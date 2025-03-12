use std::sync::{Arc, Mutex};

use pingora::{listeners::tls::TlsSettings, server::Server};

mod cert;
mod config;
mod proxy;

use cert::certbot::find_certbot_certs;
use config::file_manager::get_config;
use proxy::http::HttpProxy;
use proxy::https::HttpsProxy;
use proxy::manager::ManagerProxy;
use proxy::utils::clean_backend_address;

fn fix_config_file() {
    // Load the configuration
    let config_path = "config.json";
    let content = match std::fs::read_to_string(config_path) {
        Ok(content) => content,
        Err(e) => {
            println!("Error reading config file: {}", e);
            return;
        }
    };

    // Parse the configuration
    let mut config: config::model::Configuration = match serde_json::from_str(&content) {
        Ok(config) => config,
        Err(e) => {
            println!("Error parsing config file: {}", e);
            return;
        }
    };

    // Clean up the addresses
    let mut changes_made = false;
    for mapping in &mut config.servers {
        let cleaned_to = clean_backend_address(&mapping.to);
        if cleaned_to != mapping.to {
            println!("Cleaning address: {} -> {}", mapping.to, cleaned_to);
            mapping.to = cleaned_to;
            changes_made = true;
        }
    }

    // Write the configuration back if changes were made
    if changes_made {
        let data = match serde_json::to_string_pretty(&config) {
            Ok(data) => data,
            Err(e) => {
                println!("Error serializing config: {}", e);
                return;
            }
        };

        if let Err(e) = std::fs::write(config_path, data) {
            println!("Error writing config file: {}", e);
        } else {
            println!("Config file cleaned successfully");
        }
    } else {
        println!("No changes needed in config file");
    }
}
fn main() {
    // Initialize logging
    env_logger::init();

    // Fix the configuration file first
    fix_config_file();

    // Load configuration
    let config_store = Arc::new(Mutex::new(get_config()));

    // Initialize server
    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    // Extract domain names for certificate lookup
    let domains: Vec<String> = match config_store.lock() {
        Ok(store) => store.keys().cloned().collect(),
        Err(e) => {
            println!(
                "Error locking config store when extracting domains: {:?}",
                e
            );
            // Provide an empty vector as fallback
            Vec::new()
        }
    };
    println!("Configured domains: {:?}", domains);

    // Find certificates for domains
    let certs = find_certbot_certs(&domains);

    // Create HTTP proxy service
    let mut http_service = pingora_proxy::http_proxy_service(
        &server.configuration,
        HttpProxy {
            servers: config_store.clone(),
        },
    );
    http_service.add_tcp("0.0.0.0:80");

    // Create HTTPS proxy service
    let mut https_service = pingora_proxy::http_proxy_service(
        &server.configuration,
        HttpsProxy {
            servers: config_store.clone(),
        },
    );

    // Create manager service
    let mut manager_service = pingora_proxy::http_proxy_service(
        &server.configuration,
        ManagerProxy {
            servers: config_store.clone(),
        },
    );

    // Always configure the manager service on HTTP port 81
    manager_service.add_tcp("0.0.0.0:81");
    println!("Manager service (HTTP) configured on port 81");

    // Additionally, set up HTTPS on a different port if certificates are available
    if !certs.is_empty() {
        // Use the first certificate for the manager interface
        let mgr_cert = &certs[0];
        println!(
            "Also setting up TLS for manager on port 8443: {}",
            mgr_cert.domain
        );

        match TlsSettings::intermediate(&mgr_cert.cert_path, &mgr_cert.key_path) {
            Ok(tls_settings) => {
                // Use a different port (8443) for HTTPS manager access
                manager_service.add_tls_with_settings("0.0.0.0:8443", None, tls_settings);
                println!("Manager TLS configured successfully on port 8443");
            }
            Err(e) => {
                println!("Error setting up TLS for manager: {}", e);
            }
        };
    }

    // Configure HTTPS with domain-specific certificates
    if !certs.is_empty() {
        for cert in &certs {
            println!("Setting up TLS for domain: {}", cert.domain);

            // Create TLS settings
            let tls_settings = match TlsSettings::intermediate(&cert.cert_path, &cert.key_path) {
                Ok(settings) => settings,
                Err(e) => {
                    println!("Error creating TLS settings for {}: {}", cert.domain, e);
                    continue;
                }
            };

            // Add TLS endpoint
            https_service.add_tls_with_settings("0.0.0.0:443", None, tls_settings);
        }
    } else {
        println!("Warning: No TLS certificates found. HTTPS service will not be available.");
    }

    // Add all services to the server
    server.add_service(http_service);

    // Only add HTTPS service if we have certificates
    if !certs.is_empty() {
        server.add_service(https_service);
    }

    server.add_service(manager_service);

    // Start the server
    println!("Starting server with configured services");
    server.run_forever();
}
