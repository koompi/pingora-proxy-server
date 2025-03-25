// src/services/letsencrypt.rs
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use pingora::{
    server::{ListenFds, ShutdownWatch},
    services::Service,
};
use tokio::time;

use crate::cert::issuer::{CertificateIssuer, CertificateRequest};
use crate::config::model::ConfigStore;

pub struct LetsEncryptService {
    config_store: Arc<std::sync::Mutex<ConfigStore>>,
    certbot_dir: PathBuf,
    lets_encrypt_email: String,
    check_interval: Duration,
}

impl LetsEncryptService {
    pub fn new(
        config_store: Arc<std::sync::Mutex<ConfigStore>>,
        certbot_dir: PathBuf,
        lets_encrypt_email: String,
        check_interval_secs: u64,
    ) -> Self {
        Self {
            config_store,
            certbot_dir,
            lets_encrypt_email,
            check_interval: Duration::from_secs(check_interval_secs),
        }
    }

    async fn issue_certificate_for_domain(&self, domain: &str) -> Result<(), anyhow::Error> {
        println!("Requesting certificate for domain: {}", domain);

        let issuer = CertificateIssuer::new(
            self.certbot_dir.to_str().unwrap_or("/certbot/letsencrypt"),
            "certs",
        )?;

        let request = CertificateRequest {
            domain: domain.to_string(),
            email: self.lets_encrypt_email.clone(),
            staging: Some(false), // Set to true for testing
            force_renew: Some(false),
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

            // Try to issue certificate (will be skipped if valid cert exists)
            if let Err(e) = self.issue_certificate_for_domain(&domain).await {
                println!("Error issuing certificate for {}: {}", domain, e);
            }
        }
    }
}

#[async_trait]
impl Service for LetsEncryptService {
    async fn start_service(&mut self, _fds: Option<ListenFds>, mut _shutdown: ShutdownWatch) {
        println!("Starting Let's Encrypt certificate service");

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
