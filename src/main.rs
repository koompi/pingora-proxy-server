use anyhow::Result;
use log::{error, warn};
use openssl::ssl::{NameType, SniError, SslAlert, SslContext, SslFiletype, SslMethod, SslRef};
use pingora::listeners::tls::TlsSettings;
use pingora::server::Server;
use proxy::https::HttpsProxy;
use proxy::tcp::DatabaseIpRules;
use services::cert_watcher::CertWatcherService;
use services::letsencrypt::LetsEncryptService;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tls::Certificates;
use tokio::sync::Mutex as TokioMutex;

use config::file_manager::get_config;
use config::model::{ConfigStore, MappingOrigin};

mod cert;
mod config;
mod logging;
mod metrics;
mod proxy;
mod services;
mod tls;
use crate::services::docker_swarm::SwarmDiscoveryService;
use crate::services::metrics_service::MetricsService;

const MAX_RETRIES: u32 = 3;

async fn get_config_with_retry() -> Result<ConfigStore> {
    let mut retries = 0;
    let mut last_error = None;
    while retries < MAX_RETRIES {
        match get_config().await {
            config_store => {
                // Directly return the config store
                return Ok(config_store);
            }
        }
    }

    // If we get here, all retries failed - try fallback
    match load_fallback_config().await {
        Ok(config) => {
            warn!("Using fallback configuration");
            Ok(config)
        }
        Err(_) => {
            error!("Failed to load both main and fallback configurations");
            Err(anyhow::anyhow!(
                "Configuration loading failed: {:?}",
                last_error.unwrap_or_else(|| anyhow::anyhow!("Unknown error"))
            ))
        }
    }
}

async fn load_fallback_config() -> Result<ConfigStore> {
    // Load minimal configuration that allows the proxy to start
    let mut config = ConfigStore::new();
    config.insert(
        "localhost".to_string(),
        ("127.0.0.1:8080".to_string(), MappingOrigin::Manual),
    );
    Ok(config)
}

fn main() {
    // Initialize logging
    crate::logging::setup_logging();

    // Fix the configuration file first
    config::utils::fix_config_file();

    // Create a new runtime
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Failed to create runtime: {}", e);
            std::process::exit(1);
        }
    };

    // Initialize server with runtime handle
    let mut server = match Server::new(None) {
        Ok(srv) => srv,
        Err(e) => {
            eprintln!("Failed to create server: {}", e);
            std::process::exit(1);
        }
    };

    // Initialize metrics service
    let metrics_port = std::env::var("METRICS_PORT")
        .map(|p| p.parse::<u16>().unwrap_or(9100))
        .unwrap_or(9100);

    // Add metrics service
    let metrics_service = MetricsService::new(metrics_port);
    server.add_service(metrics_service);
    println!("Metrics service configured on port {}", metrics_port);

    server.bootstrap();

    // Get configuration using blocking and wrap it in Arc<Mutex>
    let config_store = Arc::new(Mutex::new(runtime.block_on(async {
        match get_config_with_retry().await {
            Ok(config) => config,
            Err(e) => {
                eprintln!("Failed to load configuration: {}", e);
                std::process::exit(1);
            }
        }
    })));

    let disable_ssl = std::env::var("DISABLE_SSL")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(false);

    // Create HTTP proxy service (for redirects and ACME challenges)
    let mut http_service = pingora_proxy::http_proxy_service(
        &server.configuration,
        proxy::http::HttpProxy {
            servers: config_store.clone(),
            disable_ssl,
        },
    );

    // Add TCP binding - this will panic internally if it fails
    http_service.add_tcp("0.0.0.0:80");
    println!("HTTP service configured on port 80");

    // Add the HTTP and manager services to the server
    server.add_service(http_service);

    // Initialize Let's Encrypt service
    let certbot_dir = PathBuf::from("/certbot/letsencrypt");
    let email =
        std::env::var("LETSENCRYPT_EMAIL").unwrap_or_else(|_| "admin@example.com".to_string());

    // Check if the Let's Encrypt service is enabled
    let enable_letsencrypt = std::env::var("ENABLE_LETSENCRYPT")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(true); // Enable by default

    if enable_letsencrypt {
        // Create Let's Encrypt service
        let mut letsencrypt_service = LetsEncryptService::new(
            config_store.clone(),
            certbot_dir,
            email,
            // Check every 12 hours by default (configurable via env var)
            std::env::var("LETSENCRYPT_CHECK_INTERVAL")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(12 * 60 * 60),
        );

        // Add Cloudflare credentials if available
        let cloudflare_api_token = std::env::var("CLOUDFLARE_API_TOKEN").ok();
        let cloudflare_api_key = std::env::var("CLOUDFLARE_API_KEY").ok();
        let cloudflare_api_email = std::env::var("CLOUDFLARE_API_EMAIL").ok();

        letsencrypt_service = letsencrypt_service.with_cloudflare_credentials(
            cloudflare_api_token,
            cloudflare_api_key,
            cloudflare_api_email,
        );

        // Add the service to the server
        server.add_service(letsencrypt_service);
        println!("Let's Encrypt certificate service added");
    }

    if !disable_ssl {
        let https_proxy = HttpsProxy::new(config_store.clone());
        let shared_proxy = Arc::new(https_proxy.clone());

        let live_dir = PathBuf::from("/certbot/letsencrypt/live");

        // Load all available certificates
        let certificate_configs = load_certificates_from_directory("/certbot/letsencrypt/live");

        if !certificate_configs.is_empty() {
            // Initialize certificates with all found configurations
            let certificates = Arc::new(Mutex::new(
                Certificates::new(&certificate_configs).expect("Failed to initialize certificates"),
            ));

            // Create HTTPS service with SNI support
            let mut https_service =
                pingora_proxy::http_proxy_service(&server.configuration, https_proxy.clone());

            // Use the first certificate as default
            let (_, primary_cert, primary_key) = &certificate_configs[0];

            // Configure TLS settings with SNI callback
            let certificates_clone = certificates.clone();
            let mut tls_settings = TlsSettings::intermediate(primary_cert, primary_key)
                .expect("Failed to create TLS settings");

            tls_settings.enable_h2();

            // Set SNI callback
            tls_settings.set_servername_callback(move |ssl_ref, ssl_alert| {
                // We need to handle the lock here
                if let Ok(certs) = certificates_clone.lock() {
                    certs.server_name_callback(ssl_ref, ssl_alert)
                } else {
                    // Fallback if lock fails
                    Ok(())
                }
            });

            // Set ALPN callback to prefer HTTP/2
            tls_settings.set_alpn_select_callback(tls::prefer_h2);

            // Add TLS binding with settings
            https_service.add_tls_with_settings("0.0.0.0:443", None, tls_settings);

            // Add HTTPS service
            server.add_service(https_service);

            // Initialize the manager proxy with the HTTPS proxy
            let mut manager_proxy = proxy::manager::ManagerProxy::new(config_store.clone());
            manager_proxy.https_proxy = Some((*shared_proxy).clone());

            // Create manager service
            let mut manager_service =
                pingora_proxy::http_proxy_service(&server.configuration, manager_proxy);
            manager_service.add_tcp("0.0.0.0:81");

            // Add the service to the server
            server.add_service(manager_service);

            // Add certificate watcher service
            let cert_watcher = CertWatcherService::new(
                shared_proxy,
                certificates.clone(),
                15, // Check every 15 seconds
            );
            server.add_service(cert_watcher);

            println!("HTTPS service configured with SNI support");
        } else {
            println!("No valid certificates found in {}", live_dir.display());
        }
    } else {
        println!("SSL disabled by configuration");
    }

    // Set up Swarm discovery if enabled
    let docker_endpoint = std::env::var("DOCKER_ENDPOINT")
        .unwrap_or_else(|_| "unix:///var/run/docker.sock".to_string());

    let swarm_mode = std::env::var("SWARM_MODE")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(false);

    if swarm_mode {
        let networks = std::env::var("SWARM_NETWORKS")
            .map(|nets| nets.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_else(|_| vec!["ingress".to_string()]);

        match SwarmDiscoveryService::new(config_store.clone(), &docker_endpoint, networks, 30) {
            Ok(swarm_service) => {
                println!("Adding Docker Swarm discovery service");
                server.add_service(swarm_service);
            }
            Err(_) => {
                println!("Failed to initialize Docker Swarm discovery");
            }
        }
    }

    // Initialize the TCP Proxy service for databases
    let enable_tcp_proxy = std::env::var("ENABLE_TCP_PROXY")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(true); // Enable by default

    if enable_tcp_proxy {
        println!("Initializing TCP Proxy service for database connections");

        // By default, enable TLS if SSL is enabled for the main proxy
        let tcp_proxy_tls = std::env::var("TCP_PROXY_TLS")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(!disable_ssl);

        // Create database IP rules storage
        let db_ip_rules = match runtime
            .block_on(async { proxy::tcp::DatabaseIpRules::new_with_storage().await })
        {
            Ok(rules) => Arc::new(tokio::sync::Mutex::new(rules)),
            Err(e) => {
                println!("Error initializing IP rules: {}", e);
                Arc::new(tokio::sync::Mutex::new(proxy::tcp::DatabaseIpRules::new()))
            }
        };

        // Create and add the TCP proxy service
        let tokio_config_store = {
            let std_config = config_store.lock().unwrap().clone(); // Get data from std mutex
            Arc::new(tokio::sync::Mutex::new(std_config)) // Create new tokio mutex
        };
        let tcp_proxy_service = runtime
            .block_on(proxy::tcp::TcpProxyService::new(
                tokio_config_store,
                tcp_proxy_tls,
            ))
            .unwrap();

        server.add_service(tcp_proxy_service);
        println!("TCP Proxy service added for database connections");
    }

    // Add more detailed logging before server start
    println!("Starting server with the following configuration:");
    println!("- SSL Enabled: {}", !disable_ssl);
    println!("- Swarm Mode: {}", swarm_mode);

    // Start the server with run_forever
    println!("Starting server with configured services");
    server.run_forever();
}

// Function to load certificates from a directory
fn load_certificates_from_directory(base_path: &str) -> Vec<(String, String, String)> {
    let mut configs = Vec::new();

    if let Ok(entries) = fs::read_dir(base_path) {
        for entry in entries.filter_map(Result::ok) {
            if let Ok(domain) = entry.file_name().into_string() {
                let cert_path = Path::new(base_path).join(&domain).join("fullchain.pem");
                let key_path = Path::new(base_path).join(&domain).join("privkey.pem");

                if cert_path.exists() && key_path.exists() {
                    println!("Found certificate for domain: {}", domain);
                    configs.push((
                        domain,
                        cert_path.to_string_lossy().to_string(),
                        key_path.to_string_lossy().to_string(),
                    ));
                }
            }
        }
    }

    configs
}
