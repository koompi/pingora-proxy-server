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
use crate::config::model::ConfigStore;
use crate::proxy::https::HttpsProxy;

// Simple struct to hold certificate change notification
pub struct CertChangeNotifier {
    pub changed: bool,
}

pub struct CertificateLoaderService {
    config_store: Arc<Mutex<ConfigStore>>,
    certbot_dir: PathBuf,
    check_interval: Duration,
    last_loaded: Arc<Mutex<HashMap<String, String>>>, // domain -> cert checksum
    // Use file-based notification instead of in-memory flag
    change_file_path: PathBuf,
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
            // Use a file in a shared location for notification
            change_file_path: PathBuf::from("/pingora-proxy/cert_change_flag"),
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

    // Signal certificate changes by creating a flag file
    fn signal_certificate_change(&self) -> std::io::Result<()> {
        use std::fs::File;
        use std::io::Write;

        // Create parent directory if it doesn't exist
        if let Some(parent) = self.change_file_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }

        // Write current timestamp to the file
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut file = File::create(&self.change_file_path)?;
        write!(file, "{}", timestamp)?;

        println!(
            "Created certificate change flag file at {:?}",
            self.change_file_path
        );
        Ok(())
    }
}

#[async_trait]
impl Service for CertificateLoaderService {
    async fn start_service(&mut self, _fds: Option<ListenFds>, mut shutdown: ShutdownWatch) {
        println!("Starting Certificate Loader service");

        let mut interval = time::interval(self.check_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match self.check_certificates().await {
                        Ok(certs) => {
                            if !certs.is_empty() {
                                println!("Detected {} valid certificates - signaling reload", certs.len());

                                // Signal certificate change using file
                                if let Err(e) = self.signal_certificate_change() {
                                    println!("Error creating certificate change flag file: {}", e);
                                }
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

// Check for certificate changes based on flag file
pub fn check_for_certificate_changes() -> bool {
    let flag_path = PathBuf::from("/pingora-proxy/cert_change_flag");

    if !flag_path.exists() {
        return false;
    }

    // Check if the file was created/modified recently (within last minute)
    if let Ok(metadata) = std::fs::metadata(&flag_path) {
        if let Ok(modified) = metadata.modified() {
            if let Ok(duration) = std::time::SystemTime::now().duration_since(modified) {
                // If the file is older than 60 seconds, ignore it
                if duration.as_secs() > 60 {
                    return false;
                }

                // Delete the flag file after detecting it
                let _ = std::fs::remove_file(&flag_path);
                return true;
            }
        }
    }

    false
}
