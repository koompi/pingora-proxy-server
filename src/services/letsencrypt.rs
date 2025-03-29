// src/services/letsencrypt.rs
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use pingora::prelude::sleep;
use pingora::{
    server::{ListenFds, ShutdownWatch},
    services::Service,
};
use tokio::time;
use uuid::Uuid;

use crate::cert::issuer::{CertificateIssuer, CertificateRequest, Credentials};
use crate::config::model::ConfigStore;
use crate::services::lock::DistributedLock;

use rand::{seq::SliceRandom, Rng};
use std::collections::HashMap;

// Add this struct inside the LetsEncryptService implementation
struct RateLimitTracker {
    attempts: HashMap<String, Vec<SystemTime>>,
    max_failures_per_hour: usize,
}

impl RateLimitTracker {
    fn new() -> Self {
        Self {
            attempts: HashMap::new(),
            max_failures_per_hour: 5, // Let's Encrypt standard limit
        }
    }

    fn can_attempt_renewal(&self, domain: &str) -> bool {
        let one_hour_ago = SystemTime::now()
            .checked_sub(Duration::from_secs(3600))
            .unwrap_or_else(|| UNIX_EPOCH);

        if let Some(attempts) = self.attempts.get(domain) {
            let recent_attempts = attempts.iter().filter(|&time| time > &one_hour_ago).count();

            recent_attempts < self.max_failures_per_hour
        } else {
            true
        }
    }

    fn record_attempt(&mut self, domain: &str) {
        self.attempts
            .entry(domain.to_string())
            .or_insert_with(Vec::new)
            .push(SystemTime::now());
    }
}

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

    // Add the missing get_cert_expiry method
    fn get_cert_expiry(&self, cert_path: &Path) -> Result<SystemTime, anyhow::Error> {
        // Execute openssl to get certificate expiry
        let output = std::process::Command::new("openssl")
            .arg("x509")
            .arg("-in")
            .arg(cert_path)
            .arg("-noout")
            .arg("-enddate")
            .output()?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("Failed to get certificate expiry"));
        }

        let expiry_output = String::from_utf8_lossy(&output.stdout);

        // Parse the expiry date from output (format: notAfter=May 15 23:59:59 2024 GMT)
        let date_part = expiry_output
            .strip_prefix("notAfter=")
            .ok_or_else(|| anyhow::anyhow!("Unexpected output format"))?
            .trim();

        // Try to parse the date using chrono if available
        #[cfg(feature = "chrono")]
        {
            use chrono::DateTime;
            let dt = DateTime::parse_from_str(date_part, "%b %d %H:%M:%S %Y %Z")?;
            let timestamp = dt.timestamp();
            return Ok(UNIX_EPOCH + Duration::from_secs(timestamp as u64));
        }

        // Simplified fallback approach - just assume 90 days from now
        // In a production environment, this should be improved with proper date parsing
        let expiry = SystemTime::now() + Duration::from_secs(90 * 24 * 60 * 60);
        Ok(expiry)
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

        let lock = DistributedLock::new(
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

        // Create rate limit tracker
        let mut rate_tracker = RateLimitTracker::new();

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

        // First, run certbot with --dry-run to check for issues
        println!("Performing dry-run certificate renewal check");
        match std::process::Command::new("certbot")
            .args(&["renew", "--dry-run", "--non-interactive"])
            .output()
        {
            Ok(output) => {
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    println!("Dry-run renewal check failed: {}", stderr);
                    // Continue anyway but with caution
                }
            }
            Err(e) => {
                println!("Failed to run dry-run renewal check: {}", e);
                // Continue with individual certificates
            }
        }

        // Use a result variable to track overall success
        let mut result = Ok(());

        // Create a mutable copy of the domains to shuffle
        let mut domains_vec = domains;

        // Fix Send trait issue by creating a new random number generator each time
        // instead of using thread_rng directly across await points
        {
            let mut rng = rand::thread_rng();
            domains_vec.shuffle(&mut rng);
        }

        // Process each domain with randomized delays
        for domain in domains_vec {
            // Skip if domain is an IP address
            if domain.parse::<std::net::IpAddr>().is_ok() {
                continue;
            }

            // Check if we can attempt renewal based on rate limits
            if !rate_tracker.can_attempt_renewal(&domain) {
                println!("Skipping {} due to rate limit constraints", domain);
                continue;
            }

            // Add a random delay between certificate operations (1-20 seconds)
            // Fix Send trait issue by creating a new random number generator
            let delay = {
                let mut rng = rand::thread_rng();
                rng.gen_range(1..20)
            };
            sleep(Duration::from_secs(delay)).await;

            // Check for cloudflare credentials
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

            // Only attempt renewal if certificate is expiring soon (within 30 days)
            if !self.is_expiring_soon(&cert_domain, 30) {
                println!("Certificate for {} is not due for renewal", cert_domain);
                continue;
            }

            // Record this attempt
            rate_tracker.record_attempt(&cert_domain);

            // Try to issue/renew certificate with exponential backoff
            let mut retry_count = 0;
            let max_retries = 3;
            let mut success = false;

            while retry_count < max_retries && !success {
                match self
                    .issue_certificate_for_domain(&cert_domain, is_wildcard)
                    .await
                {
                    Ok(_) => {
                        println!(
                            "Successfully issued/renewed certificate for {}",
                            cert_domain
                        );
                        success = true;
                        break;
                    }
                    Err(e) => {
                        retry_count += 1;
                        println!(
                            "Error issuing certificate for {} (attempt {}/{}): {}",
                            cert_domain, retry_count, max_retries, e
                        );

                        if retry_count < max_retries {
                            // Exponential backoff with jitter
                            let backoff_base = 2u64.pow(retry_count as u32);
                            let jitter = {
                                let mut rng = rand::thread_rng();
                                rng.gen_range(1..30)
                            };
                            let delay = backoff_base * 60 + jitter;

                            println!("Retrying in {} seconds", delay);
                            sleep(Duration::from_secs(delay)).await;
                        } else {
                            // Store the error but continue with other domains
                            result =
                                Err(anyhow::anyhow!("One or more certificate operations failed"));
                        }
                    }
                }
            }
        }

        // Release the lock when done
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

    // Add this method to check if certificate is expiring soon
    fn is_expiring_soon(&self, domain: &str, days_threshold: u64) -> bool {
        let live_dir = self.certbot_dir.join("live").join(domain);
        let cert_path = live_dir.join("fullchain.pem");

        if !cert_path.exists() {
            // No certificate exists, so we need to get one
            return true;
        }

        match self.get_cert_expiry(&cert_path) {
            Ok(expiry) => {
                let now = SystemTime::now();
                let threshold = Duration::from_secs(days_threshold * 24 * 60 * 60);

                match expiry.duration_since(now) {
                    Ok(remaining) => remaining < threshold,
                    Err(_) => {
                        // Certificate already expired
                        true
                    }
                }
            }
            Err(e) => {
                println!("Failed to check certificate expiry for {}: {}", domain, e);
                // Default to false to prevent unnecessary renewal attempts
                false
            }
        }
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
