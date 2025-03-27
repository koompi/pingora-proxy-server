// src/services/certificate_loader.rs

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use pingora::{
    listeners::tls::TlsSettings,
    server::{ListenFds, ShutdownWatch},
    services::Service,
};
use tokio::time;

use crate::cert::certbot::find_certbot_certs;
use crate::config::model::{ConfigStore, Configuration};
use crate::proxy::http::HttpProxy;
use crate::proxy::https::HttpsProxy;

pub struct CertificateLoaderService {
    config_store: Arc<Mutex<ConfigStore>>,
    certbot_dir: PathBuf,
    check_interval: Duration,
    last_loaded: Arc<Mutex<HashMap<String, String>>>, // domain -> cert checksum
    https_service_added: Arc<Mutex<bool>>,
}

impl CertificateLoaderService {
    pub fn new(
        config_store: Arc<Mutex<ConfigStore>>,
        certbot_dir: PathBuf,
        check_interval_secs: u64,
    ) -> Self {
        Self {
            config_store,
            certbot_dir,
            check_interval: Duration::from_secs(check_interval_secs),
            last_loaded: Arc::new(Mutex::new(HashMap::new())),
            https_service_added: Arc::new(Mutex::new(false)),
        }
    }

    // Get checksum for a certificate file to detect changes
    fn get_cert_checksum(path: &Path) -> Result<String, std::io::Error> {
        use sha2::{Digest, Sha256};
        use std::fs;
        use std::io::Read;

        let mut file = fs::File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let mut hasher = Sha256::new();
        hasher.update(&buffer);
        let result = hasher.finalize();

        Ok(format!("{:x}", result))
    }

    // Check for new or updated certificates and return a list of valid ones
    async fn check_certificates(
        &self,
    ) -> Result<Vec<crate::cert::certbot::DomainCert>, anyhow::Error> {
        println!("Checking for new or updated certificates...");

        // Get all domains from config
        let domains = {
            let store = match self.config_store.lock() {
                Ok(store) => store,
                Err(e) => {
                    println!("Failed to lock config store: {:?}", e);
                    return Err(anyhow::anyhow!("Failed to lock config store"));
                }
            };

            store.keys().cloned().collect::<Vec<String>>()
        };

        // Find all available certificates
        let certs = find_certbot_certs(&domains);
        if certs.is_empty() {
            println!("No certificates found to load");
            return Ok(Vec::new());
        }

        // Check if any certificates are new or updated
        let mut new_or_updated = false;
        let mut new_checksums = HashMap::new();
        let mut valid_certs = Vec::new();

        {
            let mut last_loaded = match self.last_loaded.lock() {
                Ok(guard) => guard,
                Err(e) => {
                    println!("Failed to lock last_loaded: {:?}", e);
                    return Err(anyhow::anyhow!("Failed to lock last_loaded"));
                }
            };

            for cert in &certs {
                // Check if the certificate is valid
                if !Path::new(&cert.cert_path).exists() || !Path::new(&cert.key_path).exists() {
                    println!("Certificate files missing for domain: {}", cert.domain);
                    continue;
                }

                let checksum = Self::get_cert_checksum(Path::new(&cert.cert_path))?;
                new_checksums.insert(cert.domain.clone(), checksum.clone());

                if !last_loaded.contains_key(&cert.domain)
                    || last_loaded.get(&cert.domain) != Some(&checksum)
                {
                    new_or_updated = true;
                    println!("New or updated certificate detected for: {}", cert.domain);
                }

                valid_certs.push(cert.clone());
            }

            // Only update if we find new/changed certificates
            if new_or_updated {
                *last_loaded = new_checksums;
            }
        }

        // If no new or updated certificates, return empty list
        if !new_or_updated {
            println!("No certificate changes detected");
            return Ok(Vec::new());
        }

        Ok(valid_certs)
    }
}

#[async_trait]
impl Service for CertificateLoaderService {
    // The start_service method now creates and returns the HTTPS service
    // instead of trying to modify the server directly
    async fn start_service(&mut self, _fds: Option<ListenFds>, mut shutdown: ShutdownWatch) {
        println!("Starting Certificate Loader service with hot-reload capability");

        let mut interval = time::interval(self.check_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match self.check_certificates().await {
                        Ok(certs) => {
                            if !certs.is_empty() {
                                println!("Detected {} valid certificates", certs.len());

                                // Signal that we have valid certificates, main app will reload
                                if let Ok(mut added) = self.https_service_added.lock() {
                                    *added = true;
                                }

                                // This is where we would create the HTTPS service
                                // But we can't directly add it to the server here
                                // Instead, we'll use a shared flag to signal the main app
                            }
                        },
                        Err(e) => {
                            println!("Error checking certificates: {}", e);
                        }
                    }
                }
                Ok(_) = shutdown.changed() => {
                    if *shutdown.borrow() {
                        println!("Shutdown signal received, stopping Certificate Loader service");
                        break;
                    }
                }
            }
        }
    }

    fn name(&self) -> &'static str {
        "certificate_loader_service"
    }

    fn threads(&self) -> Option<usize> {
        Some(1)
    }
}

// Public function that the main app can call to check if we have certificates
// and create an HTTPS service if needed
pub fn create_https_service_if_needed(
    config_store: Arc<Mutex<ConfigStore>>,
    server_configuration: &Arc<pingora::server::configuration::ServerConf>,
) -> Option<pingora::services::listening::Service<pingora_proxy::HttpProxy<HttpsProxy>>> {
    let domains = {
        match config_store.lock() {
            Ok(store) => store.keys().cloned().collect::<Vec<String>>(),
            Err(_) => return None,
        }
    };

    let certs = find_certbot_certs(&domains);
    if certs.is_empty() {
        return None;
    }

    // Use the http_proxy_service helper function that's also used in main.rs
    let mut https_service = pingora_proxy::http_proxy_service(
        server_configuration, // This now correctly takes &Arc<ServerConf>
        HttpsProxy {
            servers: config_store.clone(),
        },
    );

    let mut successful_certs = 0;
    for cert in &certs {
        match TlsSettings::intermediate(&cert.cert_path, &cert.key_path) {
            Ok(tls_settings) => {
                https_service.add_tls_with_settings("0.0.0.0:443", None, tls_settings);
                successful_certs += 1;
                println!("Added certificate for: {}", cert.domain);
            }
            Err(e) => {
                println!("Error creating TLS settings for {}: {}", cert.domain, e);
            }
        }
    }

    if successful_certs > 0 {
        println!(
            "Created HTTPS service with {} certificates",
            successful_certs
        );
        Some(https_service)
    } else {
        None
    }
}
