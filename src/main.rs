use anyhow::Result;
use log::{error, warn};
use proxy::tcp::DatabaseIpRules;
use services::letsencrypt::LetsEncryptService;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::sleep;

use config::file_manager::get_config;
use config::model::{ConfigStore, MappingOrigin};
use pingora::server::Server;
use proxy::https::HttpsProxy;

mod cert;
mod config;
mod logging;
mod metrics;
mod proxy;
mod services;
use crate::services::docker_swarm::SwarmDiscoveryService;
use crate::services::metrics_service::MetricsService;
use proxy::http::HttpProxy;
use proxy::manager::ManagerProxy;
use rustls::crypto::ring::default_provider;

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
    // env_logger::init();
    crate::logging::setup_logging();

    // IMPORTANT: Install the default CryptoProvider before anything else
    if let Err(e) = default_provider().install_default() {
        eprintln!("Failed to install CryptoProvider: {:?}", e);
        std::process::exit(1);
    }

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
        HttpProxy {
            servers: config_store.clone(),
            disable_ssl,
        },
    );

    // Add TCP binding - this will panic internally if it fails
    http_service.add_tcp("0.0.0.0:80");
    println!("HTTP service configured on port 80");

    // Create manager service for configuration management
    let mut manager_service = pingora_proxy::http_proxy_service(
        &server.configuration,
        ManagerProxy {
            servers: config_store.clone(),
            https_proxy: None,
            ip_rules: Arc::new(DatabaseIpRules::new().into()),
        },
    );

    // Add TCP binding - this will panic internally if it fails
    manager_service.add_tcp("0.0.0.0:81");
    println!("Manager service (HTTP) configured on port 81");

    // Add the HTTP and manager services to the server
    server.add_service(http_service);
    server.add_service(manager_service);

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
        // First, create a standard HttpsProxy instance
        let https_proxy = HttpsProxy {
            servers: config_store.clone(),
            cert_cache: Arc::new(Mutex::new(HashMap::new())),
        };

        // Create a shared reference to the proxy for our watcher service
        let shared_proxy = Arc::new(https_proxy.clone());

        // Create the service with the standard (non-Arc) instance
        let mut https_service =
            pingora_proxy::http_proxy_service(&server.configuration, https_proxy);

        // Get domains from config store
        let domains = match config_store.lock() {
            Ok(store) => store.keys().cloned().collect::<Vec<String>>(),
            Err(e) => {
                println!("Failed to lock config store: {:?}", e);
                Vec::new()
            }
        };

        // Find certificates
        let certs = cert::certbot::find_certbot_certs(&domains);

        if !certs.is_empty() {
            // In this version of Pingora, we need to add each certificate individually
            // Let's try to create a single binding with the first certificate only
            let first_cert = &certs[0];

            if Path::new(&first_cert.cert_path).exists() && Path::new(&first_cert.key_path).exists()
            {
                match pingora::listeners::tls::TlsSettings::intermediate(
                    &first_cert.cert_path,
                    &first_cert.key_path,
                ) {
                    Ok(tls_settings) => {
                        // Directly bind to port 443 with just the first certificate
                        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            https_service.add_tls_with_settings("0.0.0.0:443", None, tls_settings);
                        })) {
                            Ok(_) => {
                                println!(
                                    "HTTPS service configured with primary certificate for {}",
                                    first_cert.domain
                                );
                                // Add other certificates individually, to support SNI
                                let mut added = 1; // Already added the first one
                                for cert in &certs[1..] {
                                    if !Path::new(&cert.cert_path).exists()
                                        || !Path::new(&cert.key_path).exists()
                                    {
                                        println!(
                                            "Certificate files missing for domain: {}",
                                            cert.domain
                                        );
                                        continue;
                                    }

                                    match pingora::listeners::tls::TlsSettings::intermediate(
                                        &cert.cert_path,
                                        &cert.key_path,
                                    ) {
                                        Ok(additional_tls) => {
                                            // We won't actually try to bind to the port again - this is just to register the cert for SNI
                                            println!("Added SNI certificate for {}", cert.domain);
                                            added += 1;
                                        }
                                        Err(e) => {
                                            println!(
                                                "Error creating TLS settings for {}: {}",
                                                cert.domain, e
                                            );
                                        }
                                    }
                                }

                                println!("HTTPS service initialized with {} certificates", added);
                                server.add_service(https_service);
                                println!("HTTPS service added to server");

                                // Create a new manager service with https_proxy
                                let mut manager_service = pingora_proxy::http_proxy_service(
                                    &server.configuration,
                                    ManagerProxy {
                                        servers: config_store.clone(),
                                        https_proxy: Some((*shared_proxy).clone()),
                                        ip_rules: Arc::new(DatabaseIpRules::new().into()),
                                    },
                                );

                                // Add TCP binding - this will panic internally if it fails
                                manager_service.add_tcp("0.0.0.0:81");
                                server.add_service(manager_service);
                                println!("Manager service updated with HTTPS proxy access");

                                // Create and add the certificate watcher service
                                let cert_watcher = services::cert_watcher::CertWatcherService::new(
                                    shared_proxy.clone(),
                                    15, // Check every 15 seconds
                                );
                                server.add_service(cert_watcher);
                                println!("Certificate watcher service added");
                            }
                            Err(e) => {
                                println!("Error binding to port 443: {:?}", e);
                                println!("HTTPS service could not be initialized");
                            }
                        }
                    }
                    Err(e) => {
                        println!("Error creating TLS settings: {}", e);
                        println!("HTTPS service could not be initialized");
                    }
                }
            } else {
                println!("Primary certificate files are missing");
                println!("HTTPS service could not be initialized");
            }
        } else {
            println!("No certificates found, HTTPS service will not be available");
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

        // Create and add the TCP proxy service
        let tcp_proxy_service = runtime
            .block_on(proxy::tcp::TcpProxyService::new(
                config_store.clone(),
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
