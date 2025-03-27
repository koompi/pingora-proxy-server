// src/services/letsencrypt.rs (updated with correct shutdown handling)
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use pingora::{
    server::{ListenFds, ShutdownWatch},
    services::Service,
};
use tokio::time;
use uuid::Uuid;

use crate::cert::issuer::{CertificateIssuer, CertificateRequest, Credentials};
use crate::config::model::ConfigStore;
use crate::services::lock::FileLock;

pub struct LetsEncryptService {
    config_store: Arc<std::sync::Mutex<ConfigStore>>,
    certbot_dir: PathBuf,
    lets_encrypt_email: String,
    check_interval: Duration,
    // Cloudflare credentials for wildcard certificate renewal
    cloudflare_api_token: Option<String>,
    cloudflare_api_key: Option<String>,
    cloudflare_api_email: Option<String>,
    // Unique node ID for lock ownership
    node_id: String,
}

impl LetsEncryptService {
    pub fn new(
        config_store: Arc<std::sync::Mutex<ConfigStore>>,
        certbot_dir: PathBuf,
        lets_encrypt_email: String,
        check_interval_secs: u64,
    ) -> Self {
        // Try to load Cloudflare credentials from environment variables
        let cloudflare_api_token = std::env::var("CLOUDFLARE_API_TOKEN").ok();
        let cloudflare_api_key = std::env::var("CLOUDFLARE_API_KEY").ok();
        let cloudflare_api_email = std::env::var("CLOUDFLARE_API_EMAIL").ok();

        // Generate a unique ID for this node
        let node_id = format!("node-{}", Uuid::new_v4().to_string());

        Self {
            config_store,
            certbot_dir,
            lets_encrypt_email,
            check_interval: Duration::from_secs(check_interval_secs),
            cloudflare_api_token,
            cloudflare_api_key,
            cloudflare_api_email,
            node_id,
        }
    }

    // Configure Cloudflare credentials
    pub fn with_cloudflare_credentials(
        mut self,
        api_token: Option<String>,
        api_key: Option<String>,
        api_email: Option<String>,
    ) -> Self {
        self.cloudflare_api_token = api_token;
        self.cloudflare_api_key = api_key;
        self.cloudflare_api_email = api_email;
        self
    }

    async fn issue_certificate_for_domain(
        &self,
        domain: &str,
        is_wildcard: bool,
    ) -> Result<(), anyhow::Error> {
        println!(
            "Requesting {} certificate for domain: {}",
            if is_wildcard { "wildcard" } else { "standard" },
            domain
        );

        let issuer = CertificateIssuer::new(
            self.certbot_dir.to_str().unwrap_or("/certbot/letsencrypt"),
            "certs",
        )?;

        // Create credentials for wildcard certificates
        let dns_credentials = if is_wildcard {
            Some(Credentials {
                api_token: self.cloudflare_api_token.clone(),
                api_key: self.cloudflare_api_key.clone(),
                api_email: self.cloudflare_api_email.clone(),
                api_secret: None,
                config_path: None,
            })
        } else {
            None
        };

        let request = CertificateRequest {
            domain: domain.to_string(),
            email: self.lets_encrypt_email.clone(),
            staging: Some(false),
            force_renew: Some(false),
            wildcard: Some(is_wildcard),
            dns_provider: if is_wildcard {
                Some("cloudflare".to_string())
            } else {
                None
            },
            dns_credentials,
        };

        let status = issuer.process_request(request).await;

        if status.error.is_some() {
            println!(
                "Failed to issue certificate for {}: {:?}",
                domain, status.error
            );
            return Err(anyhow::anyhow!("Certificate issuance failed"));
        }

        println!(
            "Successfully issued certificate for {}: {:?}",
            domain, status
        );
        Ok(())
    }

    // Detect if a certificate is for a wildcard domain
    fn is_wildcard_cert(&self, domain: &str) -> bool {
        // Check if the domain starts with a wildcard pattern
        if domain.starts_with("*.") {
            return true;
        }

        // Check the live certificate directory for wildcard hints
        let live_dir = self.certbot_dir.join("live").join(domain);
        if live_dir.exists() {
            // Check for README file which might mention wildcard
            let readme_path = live_dir.join("README");
            if readme_path.exists() {
                if let Ok(content) = fs::read_to_string(readme_path) {
                    if content.contains("wildcard") {
                        return true;
                    }
                }
            }

            // Look at certificate file itself - if it contains wildcard entries
            let cert_path = live_dir.join("cert.pem");
            if cert_path.exists() {
                // Use openssl to check for wildcard entries (simplified approach)
                if let Ok(output) = std::process::Command::new("openssl")
                    .args(&[
                        "x509",
                        "-in",
                        &cert_path.to_string_lossy(),
                        "-text",
                        "-noout",
                    ])
                    .output()
                {
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    if output_str.contains("*") || output_str.contains("DNS:*.") {
                        return true;
                    }
                }
            }
        }

        false
    }

    async fn check_and_issue_certificates(&self) -> Result<(), anyhow::Error> {
        // Create a lock in a shared directory
        let lock_dir = PathBuf::from("/certbot/locks");
        if !lock_dir.exists() {
            fs::create_dir_all(&lock_dir)
                .map_err(|e| anyhow::anyhow!("Failed to create lock directory: {}", e))?;
        }

        let lock = FileLock::new(
            lock_dir,
            "certman",
            &self.node_id,
            300, // 5 minute TTL
        );

        // Try to acquire the lock with retries
        let lock_acquired = lock
            .acquire(5, Duration::from_secs(5))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to acquire lock: {}", e))?;

        if !lock_acquired {
            println!("Could not acquire certificate manager lock, skipping this run");
            return Ok(());
        }

        // We now have the lock, proceed with certificate operations
        println!("Lock acquired, proceeding with certificate operations");

        // Get all domains from config - make sure to drop the MutexGuard before any .await points
        let domains = {
            // Scope the mutex guard to ensure it's dropped before any await
            let domains = {
                let store = match self.config_store.lock() {
                    Ok(store) => store,
                    Err(e) => {
                        println!("Failed to lock config store: {:?}", e);
                        // Don't await here while holding the mutex
                        return Err(anyhow::anyhow!("Failed to lock config store"));
                    }
                };
                // Clone the keys and immediately drop the guard by ending this scope
                store.keys().cloned().collect::<Vec<String>>()
            };

            domains // Return the collected domains
        };

        // Use a result variable to track overall success
        let mut result = Ok(());

        for domain in domains {
            // Skip if domain is an IP address
            if domain.parse::<std::net::IpAddr>().is_ok() {
                continue;
            }

            // Check if we have Cloudflare credentials for wildcard certs
            let has_cf_credentials = self.cloudflare_api_token.is_some()
                || (self.cloudflare_api_key.is_some() && self.cloudflare_api_email.is_some());

            // Determine if we should try to issue a wildcard certificate
            let is_wildcard = has_cf_credentials && self.should_use_wildcard(&domain);

            // For wildcard domains, we need to strip the "*." prefix if it exists
            let cert_domain = if domain.starts_with("*.") {
                domain[2..].to_string()
            } else {
                domain
            };

            // Try to issue certificate (will be skipped if valid cert exists)
            if let Err(e) = self
                .issue_certificate_for_domain(&cert_domain, is_wildcard)
                .await
            {
                println!("Error issuing certificate for {}: {}", cert_domain, e);
                // Store the error but continue with other domains
                result = Err(anyhow::anyhow!("One or more certificate operations failed"));
            }
        }

        // Release the lock when done (separate from the main operations to avoid MutexGuard issues)
        match lock.release().await {
            Ok(_) => println!("Released certificate lock successfully"),
            Err(e) => {
                println!("Error releasing certificate manager lock: {:?}", e);
                // Don't override previous errors if there were any
                if result.is_ok() {
                    result = Err(anyhow::anyhow!("Failed to release lock"));
                }
            }
        }

        result
    }

    // Determine if we should use a wildcard certificate for this domain
    fn should_use_wildcard(&self, domain: &str) -> bool {
        // If domain already starts with "*.", it's intended as wildcard
        if domain.starts_with("*.") {
            return true;
        }

        // Check if this domain already has a wildcard certificate
        if self.is_wildcard_cert(domain) {
            return true;
        }

        // Could add additional logic here, such as:
        // - Configuration flag to prefer wildcard certs
        // - Checking for multiple subdomains in config
        // - Domain naming patterns that suggest wildcard usage

        // For now, default to standard certificates
        false
    }
}

#[async_trait]
impl Service for LetsEncryptService {
    async fn start_service(&mut self, _fds: Option<ListenFds>, mut shutdown: ShutdownWatch) {
        println!("Starting Let's Encrypt certificate service with distributed locking");

        // Log Cloudflare credential status
        if self.cloudflare_api_token.is_some() {
            println!("Cloudflare API token configured for wildcard certificates");
        } else if self.cloudflare_api_key.is_some() && self.cloudflare_api_email.is_some() {
            println!("Cloudflare API key and email configured for wildcard certificates");
        } else {
            println!("Cloudflare credentials not configured - wildcard certificates disabled");
        }

        println!("Node ID for locking: {}", self.node_id);

        let mut interval = time::interval(self.check_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = self.check_and_issue_certificates().await {
                        println!("Error in certificate operations: {}", e);
                    }
                }
                // Use changed() to wait for the shutdown signal to change value
                Ok(_) = shutdown.changed() => {
                    // Check if the value is true, indicating shutdown
                    if *shutdown.borrow() {
                        println!("Shutdown signal received, stopping Let's Encrypt service");
                        break;
                    }
                }
            }
        }
    }

    fn name(&self) -> &'static str {
        "lets_encrypt_service"
    }

    fn threads(&self) -> Option<usize> {
        Some(1)
    }
}
