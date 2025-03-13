use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use pingora_core::services::Service;
use pingora_core::server::configuration::ServerConf; // Add this import
use pingora::listeners::tls::TlsSettings;
use pingora_proxy;

use crate::{cert::certbot::DomainCert, config::model::Configuration};
use crate::proxy::{
    http::HttpProxy,
    https::HttpsProxy,
    manager::ManagerProxy,
};

/// Setup HTTP proxy service
pub fn setup_http_service(
    config: &Configuration,
    server_config: Arc<Mutex<HashMap<String, String>>>,
) -> Box<dyn Service> {
    // Create a ServerConf from your Configuration
    let server_conf = Arc::new(create_server_conf(config));
    
    let mut service = pingora_proxy::http_proxy_service(
        &server_conf, // Pass Arc<ServerConf> instead of Configuration
        HttpProxy {
            servers: server_config,
        },
    );

    // Add HTTP endpoint
    service.add_tcp("0.0.0.0:80");
    
    println!("HTTP service configured on port 80");
    Box::new(service)
}

/// Setup HTTPS proxy service
pub fn setup_https_service(
    config: &Configuration,
    server_config: Arc<Mutex<HashMap<String, String>>>,
    certs: &[DomainCert],
) -> Box<dyn Service> {
    // Create a ServerConf from your Configuration
    let server_conf = Arc::new(create_server_conf(config));
    
    let mut service = pingora_proxy::http_proxy_service(
        &server_conf, // Pass Arc<ServerConf> instead of Configuration
        HttpsProxy {
            servers: server_config,
        },
    );

    // Configure HTTPS with domain-specific certificates
    if !certs.is_empty() {
        for cert in certs {
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
            service.add_tls_with_settings("0.0.0.0:443", None, tls_settings);
        }
        
        println!("HTTPS service configured on port 443");
    } else {
        println!("Warning: No TLS certificates found. HTTPS service will not be available.");
    }

    Box::new(service)
}

/// Setup manager service
pub fn setup_manager_service(
    config: &Configuration,
    server_config: Arc<Mutex<HashMap<String, String>>>,
    cert: Option<&DomainCert>,
) -> Box<dyn Service> {
    // Create a ServerConf from your Configuration
    let server_conf = Arc::new(create_server_conf(config));
    
    let mut service = pingora_proxy::http_proxy_service(
        &server_conf, // Pass Arc<ServerConf> instead of Configuration
        ManagerProxy {
            servers: server_config,
        },
    );

    // Use TLS for manager if cert is available
    if let Some(mgr_cert) = cert {
        println!("Using certificate for manager: {}", mgr_cert.domain);
        
        match TlsSettings::intermediate(&mgr_cert.cert_path, &mgr_cert.key_path) {
            Ok(tls_settings) => {
                service.add_tls_with_settings("0.0.0.0:81", None, tls_settings);
                println!("Manager TLS configured successfully on port 81");
            },
            Err(e) => {
                println!("Error setting up TLS for manager: {}", e);
                service.add_tcp("0.0.0.0:81");
                println!("Manager service (HTTP) configured on port 81");
            }
        };
    } else {
        // Fallback to HTTP if no certs
        service.add_tcp("0.0.0.0:81");
        println!("Manager service (HTTP) configured on port 81");
    }

    Box::new(service)
}

/// Helper function to create ServerConf from Configuration
fn create_server_conf(config: &Configuration) -> ServerConf {
    let mut server_conf = ServerConf::default();
    
    // Map the fields from Configuration to ServerConf
    // You'll need to adjust this based on your Configuration struct's fields
    // Example:
    // server_conf.threads = config.threads;
    // server_conf.connection_timeout = config.timeout;
    
    server_conf
}