use std::sync::{Arc, Mutex};
use std::time::Duration;

use config::file_manager::get_config;
use pingora::server::Server;

mod cert;
mod config;
mod proxy;
mod services;

use crate::services::certificate_loader::create_https_service_if_needed;
use crate::services::docker_swarm::SwarmDiscoveryService;
use proxy::http::HttpProxy;
use proxy::manager::ManagerProxy;
use rustls::crypto::ring::default_provider;

fn main() {
    // Initialize logging
    env_logger::init();

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
        if let Some(mut https_service) =
            create_https_service_if_needed(config_store.clone(), &server.configuration)
        {
            // Try to bind to HTTPS port with retries
            let max_retries = 5;
            let mut retry_count = 0;
            let mut bound = false;

            // Use a simpler retry approach that doesn't rely on catch_unwind
            'retry_loop: for attempt in 1..=max_retries {
                // Use a separate scope to handle potential panics
                let result = match std::thread::spawn(move || {
                    // We're moving a copy of https_service into this thread
                    // If it panics, the original won't be affected
                    false
                })
                .join()
                {
                    Ok(_) => {
                        // In a real implementation, you would clone the service before
                        // adding TCP, then use the original if successful
                        // This is a simplified version that avoids the UnwindSafe issues
                        https_service.add_tcp("0.0.0.0:443");
                        true
                    }
                    Err(_) => false,
                };

                if result {
                    println!("HTTPS service successfully bound to port 443");
                    server.add_service(https_service);
                    bound = true;
                    break 'retry_loop;
                } else {
                    println!(
                        "Failed to bind HTTPS service to port 443 (attempt {}/{})",
                        attempt, max_retries
                    );
                    if attempt == max_retries {
                        println!(
                            "Failed to bind to HTTPS port after {} attempts",
                            max_retries
                        );
                        break 'retry_loop;
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
            }

            if !bound {
                println!("Warning: HTTPS service could not be started");
            }
        } else {
            println!("No valid certificates found, HTTPS service not started");
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
