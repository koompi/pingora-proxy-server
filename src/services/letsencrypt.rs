// src/services/letsencrypt.rs
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

use crate::cert::issuer::{CertificateIssuer, CertificateRequest, Credentials};
use crate::config::model::ConfigStore;

pub struct LetsEncryptService {
    config_store: Arc<std::sync::Mutex<ConfigStore>>,
    certbot_dir: PathBuf,
    lets_encrypt_email: String,
    check_interval: Duration,
    // Cloudflare credentials for wildcard certificate renewal
    cloudflare_api_token: Option<String>,
    cloudflare_api_key: Option<String>,
    cloudflare_api_email: Option<String>,
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

        Self {
            config_store,
            certbot_dir,
            lets_encrypt_email,
            check_interval: Duration::from_secs(check_interval_secs),
            cloudflare_api_token,
            cloudflare_api_key,
            cloudflare_api_email,
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

    async fn check_and_issue_certificates(&self) {
        // Get all domains from config
        let domains = {
            let store = self.config_store.lock().unwrap();
            store.keys().cloned().collect::<Vec<String>>()
        };

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
            }
        }
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
    async fn start_service(&mut self, _fds: Option<ListenFds>, mut _shutdown: ShutdownWatch) {
        println!("Starting Let's Encrypt certificate service");

        // Log Cloudflare credential status
        if self.cloudflare_api_token.is_some() {
            println!("Cloudflare API token configured for wildcard certificates");
        } else if self.cloudflare_api_key.is_some() && self.cloudflare_api_email.is_some() {
            println!("Cloudflare API key and email configured for wildcard certificates");
        } else {
            println!("Cloudflare credentials not configured - wildcard certificates disabled");
        }

        let mut interval = time::interval(self.check_interval);

        loop {
            interval.tick().await;
            self.check_and_issue_certificates().await;
        }
    }

    fn name(&self) -> &'static str {
        "lets_encrypt_service"
    }

    fn threads(&self) -> Option<usize> {
        Some(1)
    }
}
