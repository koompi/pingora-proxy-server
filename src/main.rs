use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use config::file_manager::get_config;
use pingora::server::Server;
use std::thread;
use tokio::sync::mpsc;
use tokio::time;

mod cert;
mod config;
mod proxy;
mod services;

use crate::services::certificate_loader::{
    create_https_service_if_needed, CertificateLoaderService,
};
use crate::services::docker_swarm::SwarmDiscoveryService;
use crate::services::letsencrypt::LetsEncryptService;
use proxy::http::HttpProxy;
use proxy::manager::ManagerProxy;
use rustls::crypto::ring::default_provider;

#[tokio::main]
async fn main() {
    // Initialize logging
    env_logger::init();

    // IMPORTANT: Install the default CryptoProvider before anything else
    default_provider()
        .install_default()
        .expect("Failed to install CryptoProvider");

    // Fix the configuration file first
    config::utils::fix_config_file();

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

    // Create Let's Encrypt service with Cloudflare support (only if SSL is not disabled)
    if !disable_ssl {
        let certbot_dir = PathBuf::from("/certbot/letsencrypt");
        let email = std::env::var("LETS_ENCRYPT_EMAIL")
            .unwrap_or_else(|_| "your-email@example.com".to_string());

        // Load Cloudflare credentials from environment
        let cloudflare_api_token = std::env::var("CLOUDFLARE_API_TOKEN").ok();
        let cloudflare_api_key = std::env::var("CLOUDFLARE_API_KEY").ok();
        let cloudflare_api_email = std::env::var("CLOUDFLARE_API_EMAIL").ok();

        // Check if we have valid Cloudflare credentials
        let has_cloudflare_credentials = cloudflare_api_token.is_some()
            || (cloudflare_api_key.is_some() && cloudflare_api_email.is_some());

        // Create service with credentials if available
        let lets_encrypt_service = if has_cloudflare_credentials {
            println!(
                "Creating Let's Encrypt service with Cloudflare credentials for wildcard certificates"
            );
            LetsEncryptService::new(
                config_store.clone(),
                certbot_dir.clone(),
                email,
                3600, // Check for certificate renewals every hour
            )
            .with_cloudflare_credentials(
                cloudflare_api_token,
                cloudflare_api_key,
                cloudflare_api_email,
            )
        } else {
            println!("Creating Let's Encrypt service (wildcard certificates disabled)");
            LetsEncryptService::new(
                config_store.clone(),
                certbot_dir.clone(),
                email,
                3600, // Check for certificate renewals every hour
            )
        };

        server.add_service(lets_encrypt_service);

        // Add Certificate Loader service
        let certificate_loader = CertificateLoaderService::new(
            config_store.clone(),
            certbot_dir.clone(),
            300, // Check every 5 minutes
        );

        // Get notifier before moving the certificate loader
        let cert_change_notifier = certificate_loader.get_certificate_change_notifier();

        server.add_service(certificate_loader);
        println!("Certificate Loader service added");

        // Initial check for existing certificates
        if let Some(https_service) =
            create_https_service_if_needed(config_store.clone(), &server.configuration)
        {
            server.add_service(https_service);
            println!("Initial HTTPS service created with existing certificates");
        }

        // Create a separate thread to monitor certificate changes
        // This avoids the nested tokio runtime issue
        thread::spawn(move || {
            // Create a new runtime for this thread
            let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");

            rt.block_on(async {
                let mut interval = time::interval(Duration::from_secs(30));

                loop {
                    interval.tick().await;

                    // Check if certificate change flag is set
                    let should_reload = {
                        if let Ok(notifier) = cert_change_notifier.lock() {
                            *notifier
                        } else {
                            false
                        }
                    };

                    if should_reload {
                        println!("Certificate change detected, starting new process");

                        // Reset the flag
                        if let Ok(mut notifier) = cert_change_notifier.lock() {
                            *notifier = false;
                        }

                        // Start a new process without waiting for this one to exit
                        // This avoids runtime interactions between processes
                        match std::process::Command::new("/app/entrypoint.sh").spawn() {
                            Ok(_) => {
                                println!("New server process started, exiting current process");
                                // Give the new process time to start
                                thread::sleep(Duration::from_secs(2));
                                std::process::exit(0);
                            }
                            Err(e) => {
                                println!("Failed to start new server process: {}", e);
                            }
                        }
                    }
                }
            });
        });
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
    // This is a blocking call that will run until the server exits
    println!("Starting server with configured services");
    server.run_forever();
}
