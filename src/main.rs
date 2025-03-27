// src/main.rs - Fixed to avoid runtime nesting
use std::path::PathBuf;
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
    default_provider()
        .install_default()
        .expect("Failed to install CryptoProvider");

    // Fix the configuration file first
    config::utils::fix_config_file();

    // Create a new runtime for our application
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("Failed to create runtime");

    // Run our async main in the runtime
    if let Err(e) = runtime.block_on(async_main()) {
        eprintln!("Error in application: {}", e);
        std::process::exit(1);
    }
}

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration
    let config_store = Arc::new(Mutex::new(get_config()));

    // Extract domain names for certificate lookup
    let domains: Vec<String> = match config_store.lock() {
        Ok(store) => store.keys().cloned().collect(),
        Err(e) => {
            println!(
                "Error locking config store when extracting domains: {:?}",
                e
            );
            Vec::new()
        }
    };
    println!("Configured domains: {:?}", domains);

    // Check if SSL is disabled
    let disable_ssl = std::env::var("DISABLE_SSL")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(false);

    if disable_ssl {
        println!("SSL handling disabled via DISABLE_SSL environment variable");
    }

    // Initialize server
    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    // Create HTTP proxy service (for redirects and ACME challenges)
    let mut http_service = pingora_proxy::http_proxy_service(
        &server.configuration,
        HttpProxy {
            servers: config_store.clone(),
            disable_ssl,
        },
    );
    http_service.add_tcp("0.0.0.0:80");

    // Create manager service for configuration management
    let mut manager_service = pingora_proxy::http_proxy_service(
        &server.configuration,
        ManagerProxy {
            servers: config_store.clone(),
        },
    );
    manager_service.add_tcp("0.0.0.0:81");
    println!("Manager service (HTTP) configured on port 81");

    // Add the HTTP and manager services to the server
    server.add_service(http_service);
    server.add_service(manager_service);

    // Initial check for existing certificates
    if !disable_ssl {
        if let Some(https_service) =
            create_https_service_if_needed(config_store.clone(), &server.configuration)
        {
            server.add_service(https_service);
            println!("Initial HTTPS service created with existing certificates");
        }
    }

    // Set up Swarm discovery if enabled
    let docker_endpoint = std::env::var("DOCKER_ENDPOINT")
        .unwrap_or_else(|_| "unix:///var/run/docker.sock".to_string());

    let swarm_mode = std::env::var("SWARM_MODE")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(false);

    if swarm_mode {
        // Default swarm networks to check
        let networks = std::env::var("SWARM_NETWORKS")
            .map(|nets| nets.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_else(|_| vec!["ingress".to_string()]);

        // Setup swarm discovery service
        match SwarmDiscoveryService::new(
            config_store.clone(),
            &docker_endpoint,
            networks,
            30, // Check every 30 seconds
        ) {
            Ok(swarm_service) => {
                println!("Adding Docker Swarm discovery service");
                server.add_service(swarm_service);
            }
            Err(e) => {
                println!("Failed to initialize Docker Swarm discovery: {}", e);
            }
        }
    }

    // Start the server with run_forever
    println!("Starting server with configured services");
    server.run_forever();

    Ok(())
}
