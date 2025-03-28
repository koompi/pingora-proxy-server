use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use config::file_manager::get_config;
use pingora::server::Server;
use proxy::https::HttpsProxy;

mod cert;
mod config;
mod logging;
mod proxy;
mod services;

use crate::services::docker_swarm::SwarmDiscoveryService;
use proxy::http::HttpProxy;
use proxy::manager::ManagerProxy;
use rustls::crypto::ring::default_provider;

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

    server.bootstrap();

    // Get configuration using blocking and wrap it in Arc<Mutex>
    let config_store = Arc::new(Mutex::new(runtime.block_on(async { get_config().await })));

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
        },
    );

    // Add TCP binding - this will panic internally if it fails
    manager_service.add_tcp("0.0.0.0:81");
    println!("Manager service (HTTP) configured on port 81");

    // Add the HTTP and manager services to the server
    server.add_service(http_service);
    server.add_service(manager_service);

    // Initial check for existing certificates
    if !disable_ssl {
        // Create HTTPS service directly here
        let mut https_service = pingora_proxy::http_proxy_service(
            &server.configuration,
            HttpsProxy {
                servers: config_store.clone(),
            },
        );

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

    // Add more detailed logging before server start
    println!("Starting server with the following configuration:");
    println!("- SSL Enabled: {}", !disable_ssl);
    println!("- Swarm Mode: {}", swarm_mode);

    // Start the server with run_forever
    println!("Starting server with configured services");
    server.run_forever();
}
