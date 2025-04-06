use std::fs;
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use once_cell::sync::Lazy;
use scopeguard::defer;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

static ACTIVE_CHALLENGES: Lazy<Mutex<std::collections::HashMap<String, (String, String)>>> =
    Lazy::new(|| Mutex::new(std::collections::HashMap::new()));

// Certificate request data structure with wildcard support
#[derive(Debug, Deserialize)]
pub struct CertificateRequest {
    pub domain: String,
    pub email: String,
    // Optional fields
    pub staging: Option<bool>,
    pub force_renew: Option<bool>,
    pub wildcard: Option<bool>,
    pub dns_provider: Option<String>,         // e.g., "cloudflare"
    pub dns_credentials: Option<Credentials>, // Provider-specific credentials
    #[serde(default = "default_auth_method")]
    pub auth_method: String, // Make this optional with a default value
}

// Add this function to provide a default value
fn default_auth_method() -> String {
    "http-01".to_string()
}

// DNS provider credentials
#[derive(Debug, Deserialize, Clone)]
pub struct Credentials {
    pub api_key: Option<String>,     // Used by most providers
    pub api_token: Option<String>,   // Used by Cloudflare and some others
    pub api_email: Option<String>,   // Used by Cloudflare
    pub api_secret: Option<String>,  // Used by some providers
    pub config_path: Option<String>, // Path to credentials file
}

// Certificate status response
#[derive(Debug, Serialize)]
pub struct CertificateStatus {
    pub domain: String,
    pub status: String,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub expiry: Option<String>,
    pub error: Option<String>,
    pub is_wildcard: Option<bool>,
}

// Structure to manage the certificate issuing process
pub struct CertificateIssuer {
    pub certbot_dir: PathBuf,
    pub output_dir: PathBuf,
    pub public_ip: String,
}

/// A certificate issuer that manages SSL/TLS certificates using Certbot.
///
/// This struct provides functionality to:
/// - Issue new SSL/TLS certificates
/// - Validate domains
/// - Check existing certificates
/// - Handle both standard and wildcard certificates
/// - Manage Cloudflare DNS integration for wildcard certificates
///
/// # Examples
///
/// ```
/// use your_crate::CertificateIssuer;
///
/// let issuer = CertificateIssuer::new("/etc/certbot", "/etc/certs")?;
/// let request = CertificateRequest {
///     domain: "example.com".to_string(),
///     email: "admin@example.com".to_string(),
///     wildcard: Some(false),
///     staging: Some(true),
///     force_renew: Some(false),
///     dns_provider: None,
///     dns_credentials: None,
/// };
///
/// let status = issuer.process_request(request).await;
/// ```
///
/// # Features
///
/// - HTTP-01 challenge support for standard certificates
/// - DNS-01 challenge support for wildcard certificates (Cloudflare only)
/// - Automatic certificate renewal checks
/// - Certificate expiry monitoring
/// - Public IP detection
///
/// # Security
///
/// This implementation:
/// - Uses secure file permissions for credential storage
/// - Validates domain ownership
/// - Supports staging environments for testing
/// - Handles sensitive Cloudflare credentials securely
///
/// # Requirements
///
/// - Certbot must be installed on the system
/// - OpenSSL for certificate validation
/// - curl for public IP detection
/// - Write access to specified directories
/// - Optional: Cloudflare credentials for wildcard certificates
impl CertificateIssuer {
    pub fn new(certbot_dir: &str, output_dir: &str) -> Result<Self> {
        // Ensure directories exist
        fs::create_dir_all(certbot_dir)?;
        fs::create_dir_all(output_dir)?;

        // Try to detect public IP
        let public_ip = match Self::get_public_ip() {
            Ok(ip) => ip,
            Err(_) => String::from("0.0.0.0"), // Default fallback
        };

        Ok(Self {
            certbot_dir: PathBuf::from(certbot_dir),
            output_dir: PathBuf::from(output_dir),
            public_ip,
        })
    }

    // Get public IP address
    fn get_public_ip() -> Result<String> {
        let output = Command::new("curl").arg("https://api.ipify.org").output()?;

        if output.status.success() {
            let ip = String::from_utf8(output.stdout)?;
            Ok(ip.trim().to_string())
        } else {
            Err(anyhow!("Failed to get public IP"))
        }
    }

    // Process a certificate request
    pub async fn process_request(&self, request: CertificateRequest) -> CertificateStatus {
        let is_wildcard = request.wildcard.unwrap_or(false);

        // For wildcard certificates, skip domain validation as it uses DNS challenge
        if !is_wildcard {
            // Only validate domain for non-wildcard certificates
            let validation_result = self.validate_domain(&request.domain).await;
            if let Err(e) = validation_result {
                return CertificateStatus {
                    domain: request.domain,
                    status: "failed".to_string(),
                    cert_path: None,
                    key_path: None,
                    expiry: None,
                    error: Some(format!("Domain validation failed: {}", e)),
                    is_wildcard: Some(is_wildcard),
                };
            }
        }

        // 2. Check if certificate already exists and is valid
        let force_renew = request.force_renew.unwrap_or(false);
        if !force_renew {
            if let Some(mut status) = self.check_certificate(&request.domain) {
                // Add wildcard flag to the status
                status.is_wildcard = Some(is_wildcard);
                return status;
            }
        }

        // 3. Issue certificate
        match self.issue_certificate(&request).await {
            Ok(status) => status,
            Err(e) => CertificateStatus {
                domain: request.domain,
                status: "failed".to_string(),
                cert_path: None,
                key_path: None,
                expiry: None,
                error: Some(format!("Certificate issuance failed: {}", e)),
                is_wildcard: Some(is_wildcard),
            },
        }
    }

    // Validate that the domain points to our server
    async fn validate_domain(&self, domain: &str) -> Result<()> {
        println!("Validating domain: {}", domain);

        // 1. DNS resolution check
        let addresses = match format!("{}:443", domain).to_socket_addrs() {
            Ok(addrs) => addrs.collect::<Vec<_>>(),
            Err(e) => {
                return Err(anyhow!("Failed to resolve domain {}: {}", domain, e));
            }
        };

        // Get our public IP from an environment variable if available
        let public_ip = std::env::var("PUBLIC_IP").unwrap_or_else(|_| self.public_ip.clone());

        let public_ips: Vec<String> = public_ip.split(',').map(|s| s.trim().to_string()).collect();

        let mut found_matching_ip = false;
        for addr in addresses {
            let ip = addr.ip().to_string();
            println!("Resolved IP for {}: {}", domain, ip);

            // Allow matching any of our public IPs
            if public_ips.contains(&ip) || ip == "127.0.0.1" {
                found_matching_ip = true;
                println!("IP match found for domain validation");
                break;
            }
        }

        if !found_matching_ip {
            return Err(anyhow!(
                "Domain {} does not resolve to this server's IP address ({})",
                domain,
                public_ip
            ));
        }

        // 2. Wait a moment to ensure DNS propagation
        tokio::time::sleep(Duration::from_secs(1)).await;

        Ok(())
    }

    // Check if a valid certificate already exists
    pub fn check_certificate(&self, domain: &str) -> Option<CertificateStatus> {
        // Remove any trailing commas or whitespace
        let clean_domain = domain.trim_end_matches(|c| c == ',' || c == ' ');

        let live_dir = self.certbot_dir.join("live").join(clean_domain);
        let cert_path = live_dir.join("fullchain.pem");
        let key_path = live_dir.join("privkey.pem");

        println!("Checking certificate at: {:?}", cert_path);

        if cert_path.exists() && key_path.exists() {
            // Check if files are symlinks and resolve them
            let real_cert_path = match std::fs::read_link(&cert_path) {
                Ok(link_path) => live_dir.join(link_path),
                Err(_) => cert_path.clone(),
            };

            let real_key_path = match std::fs::read_link(&key_path) {
                Ok(link_path) => live_dir.join(link_path),
                Err(_) => key_path.clone(),
            };

            println!("Real cert path: {:?}", real_cert_path);
            println!("Real key path: {:?}", real_key_path);

            // Check certificate expiry
            match std::panic::catch_unwind(|| self.get_cert_expiry(&cert_path, clean_domain)) {
                Ok(Ok(expiry)) => {
                    let now = SystemTime::now();
                    let thirty_days = Duration::from_secs(30 * 24 * 60 * 60);

                    // If certificate expires in more than 30 days, it's valid
                    if expiry > now + thirty_days {
                        return Some(CertificateStatus {
                            domain: clean_domain.to_string(),
                            status: "valid".to_string(),
                            cert_path: Some(cert_path.to_string_lossy().to_string()),
                            key_path: Some(key_path.to_string_lossy().to_string()),
                            expiry: Some(format!("{:?}", expiry)),
                            error: None,
                            is_wildcard: None, // Will be set by the caller
                        });
                    }

                    // Certificate exists but expires soon
                    return Some(CertificateStatus {
                        domain: clean_domain.to_string(),
                        status: "expiring_soon".to_string(),
                        cert_path: Some(cert_path.to_string_lossy().to_string()),
                        key_path: Some(key_path.to_string_lossy().to_string()),
                        expiry: Some(format!("{:?}", expiry)),
                        error: None,
                        is_wildcard: None, // Will be set by the caller
                    });
                }
                _ => {
                    println!("Error or timeout checking certificate expiry");
                    // Return with unknown expiry instead of hanging
                    return Some(CertificateStatus {
                        domain: clean_domain.to_string(),
                        status: "unknown_expiry".to_string(),
                        cert_path: Some(cert_path.to_string_lossy().to_string()),
                        key_path: Some(key_path.to_string_lossy().to_string()),
                        expiry: None,
                        error: Some("Could not determine certificate expiry".to_string()),
                        is_wildcard: None,
                    });
                }
            }
        }

        None
    }

    // Issue a certificate using certbot
    async fn issue_certificate(&self, request: &CertificateRequest) -> Result<CertificateStatus> {
        let domain = &request.domain;
        let email = &request.email;
        let staging = request.staging.unwrap_or(false);
        let is_wildcard = request.wildcard.unwrap_or(false);

        // // First check for any running certbot processes and kill stale ones
        // if let Ok(output) = std::process::Command::new("pgrep").arg("certbot").output() {
        //     if !output.stdout.is_empty() {
        //         // Get the PIDs of running certbot processes
        //         let stdout = String::from_utf8_lossy(&output.stdout);
        //         let pids = stdout.split_whitespace().collect::<Vec<_>>();

        //         // Check each process
        //         for pid in pids {
        //             // Check process age
        //             if let Ok(age_output) = std::process::Command::new("ps")
        //                 .args(&["-o", "etimes=", "-p", pid])
        //                 .output()
        //             {
        //                 let age = String::from_utf8_lossy(&age_output.stdout)
        //                     .trim()
        //                     .parse::<u32>()
        //                     .unwrap_or(0);

        //                 // If process is older than 1 minutes, kill it
        //                 if age > 60 {
        //                     let _ = std::process::Command::new("kill").arg(pid).output();
        //                     println!("Killed stale certbot process {}", pid);
        //                     continue;
        //                 }

        //                 // If process is fresh, abort
        //                 return Err(anyhow!("Another certbot process is already running. Please try again in a few minutes."));
        //             }
        //         }
        //     }
        // }

        // Add a small delay to ensure any killed processes are cleaned up
        std::thread::sleep(std::time::Duration::from_secs(2));

        println!("Issuing certificate for: {}", domain);

        // Build certbot command based on authentication method
        let mut cmd = Command::new("certbot");
        cmd.arg("certonly")
            .arg("--non-interactive")
            .arg("--agree-tos")
            .arg("--email")
            .arg(email)
            .arg("--config-dir")
            .arg(&self.certbot_dir);

        if staging {
            cmd.arg("--staging");
        }

        // Use appropriate authentication method
        if is_wildcard {
            if let (Some(provider), Some(credentials)) =
                (&request.dns_provider, &request.dns_credentials)
            {
                cmd.arg(format!("--dns-{}", provider));

                // Create temporary credentials file and store it in a let binding
                let creds_file = self.create_temp_credentials_file(credentials)?;

                // Create the cleanup guard with the owned path
                let _cleanup_guard = scopeguard::guard(creds_file.clone(), |f| {
                    if let Err(e) = std::fs::remove_file(&f) {
                        eprintln!("Failed to remove credentials file: {}", e);
                    }
                });

                // Use the credentials file in the command
                cmd.arg(format!("--dns-{}-credentials", provider))
                    .arg(&creds_file);

                // Add both the base domain and wildcard
                cmd.arg("-d")
                    .arg(domain)
                    .arg("-d")
                    .arg(format!("*.{}", domain));
            } else {
                return Err(anyhow!(
                    "DNS credentials required for wildcard certificates"
                ));
            }
        } else {
            cmd.arg("--webroot")
                .arg("-w")
                .arg("/var/www/html")
                .arg("-d")
                .arg(domain);
        }

        // Execute certbot command
        let output = cmd.output()?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            println!("Certbot error: {}", error);

            // Add this line to track failures
            crate::metrics::PROXY_METRICS
                .certificate_operations
                .with_label_values(&[domain, "issue", "failed"])
                .inc();

            return Err(anyhow!("Certbot failed: {}", error));
        }

        // Clean up the challenge after it's been used
        if !is_wildcard {
            let mut challenges = ACTIVE_CHALLENGES.lock().await;
            challenges.remove(domain);
        }

        // Check if certificate was created
        let live_dir = self.certbot_dir.join("live").join(domain);
        let cert_path = live_dir.join("fullchain.pem");
        let key_path = live_dir.join("privkey.pem");

        if !cert_path.exists() || !key_path.exists() {
            return Err(anyhow!("Certificate files were not created"));
        }

        // Copy certificates to output directory
        fs::create_dir_all(self.output_dir.join(domain))?;
        fs::copy(
            &cert_path,
            self.output_dir.join(domain).join("fullchain.pem"),
        )?;
        fs::copy(&key_path, self.output_dir.join(domain).join("privkey.pem"))?;

        // Get expiry information
        let expiry = match self.get_cert_expiry(&cert_path, domain) {
            Ok(expiry) => Some(format!("{:?}", expiry)),
            Err(_) => None,
        };

        // When successfully issuing a certificate, log it
        crate::metrics::PROXY_METRICS
            .certificate_operations
            .with_label_values(&[domain, "issue", "success"])
            .inc();

        Ok(CertificateStatus {
            domain: domain.to_string(),
            status: "issued".to_string(),
            cert_path: Some(cert_path.to_string_lossy().to_string()),
            key_path: Some(key_path.to_string_lossy().to_string()),
            expiry,
            error: None,
            is_wildcard: Some(is_wildcard),
        })
    }

    // Create temporary credentials file for DNS providers
    fn create_temp_credentials_file(&self, credentials: &Credentials) -> Result<String> {
        match credentials {
            // Handle Cloudflare credentials
            credentials
                if credentials.api_token.is_some()
                    || (credentials.api_key.is_some() && credentials.api_email.is_some()) =>
            {
                self.create_cloudflare_credentials(credentials)
            }
            // Add support for other DNS providers here if needed
            _ => Err(anyhow!("Unsupported DNS provider credentials format")),
        }
    }

    // Create a Cloudflare credentials file for certbot dns-cloudflare plugin
    fn create_cloudflare_credentials(&self, credentials: &Credentials) -> Result<String> {
        // Create directory for credentials if needed
        let credentials_dir = self.certbot_dir.join("cloudflare");
        fs::create_dir_all(&credentials_dir)?;

        // Create unique filename
        let credentials_file =
            credentials_dir.join(format!("cloudflare-{}.ini", uuid::Uuid::new_v4()));

        // Write credentials to file
        let mut content = String::new();

        // Prefer API token (newer API) if available
        if let Some(api_token) = &credentials.api_token {
            content.push_str(&format!("dns_cloudflare_api_token = {}\n", api_token));
        } else if let (Some(api_key), Some(api_email)) =
            (&credentials.api_key, &credentials.api_email)
        {
            // Fall back to API key (older API)
            content.push_str(&format!("dns_cloudflare_api_key = {}\n", api_key));
            content.push_str(&format!("dns_cloudflare_email = {}\n", api_email));
        } else {
            return Err(anyhow!(
                "Either API token or both API key and email are required for Cloudflare"
            ));
        }

        // Write the file with strict permissions
        fs::write(&credentials_file, content)?;

        // Set permissions to read-only for owner (600)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            fs::set_permissions(&credentials_file, perms)?;
        }

        Ok(credentials_file.to_string_lossy().to_string())
    }

    // Get certificate expiry date
    fn get_cert_expiry(&self, cert_path: &Path, domain: &str) -> Result<SystemTime, anyhow::Error> {
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
        println!(
            "Certificate expiry output for {}: {}",
            domain, expiry_output
        );

        // Parse the expiry date from output (format: notAfter=May 15 23:59:59 2024 GMT)
        let date_part = expiry_output
            .strip_prefix("notAfter=")
            .ok_or_else(|| anyhow::anyhow!("Unexpected output format"))?
            .trim();

        // Since parsing the exact date format is complex without proper libraries,
        // we'll use the openssl x509 command again to get the expiry in seconds
        let time_output = std::process::Command::new("openssl")
            .arg("x509")
            .arg("-in")
            .arg(cert_path)
            .arg("-noout")
            .arg("-enddate")
            .arg("-dateopt")
            .arg("unix")
            .output();

        match time_output {
            Ok(output) if output.status.success() => {
                let unix_time = String::from_utf8_lossy(&output.stdout);
                if let Some(time_str) = unix_time.strip_prefix("notAfter=") {
                    if let Ok(timestamp) = time_str.trim().parse::<u64>() {
                        // Update the metric
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();

                        let remaining_seconds = if timestamp > now { timestamp - now } else { 0 };

                        // Update the metric
                        crate::metrics::PROXY_METRICS
                            .certificate_expiry
                            .with_label_values(&[domain])
                            .set(remaining_seconds as f64);

                        return Ok(UNIX_EPOCH + Duration::from_secs(timestamp));
                    }
                }
            }
            _ => {
                // Failed to get precise timestamp, continue with approximation
            }
        }

        // Fallback: simplified parsing of the date string
        println!("Using simplified date parsing for: {}", date_part);

        // Simple heuristic: Extract year and estimate expiry
        // This is a very rough approximation!
        let year_str = date_part.split_whitespace().last().unwrap_or("2025");
        let current_year = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        {
            Ok(dur) => {
                // Approximating current year from Unix timestamp
                1970 + (dur.as_secs() / (365 * 24 * 60 * 60)) as u32
            }
            Err(_) => 2025, // Fallback if time is before epoch (shouldn't happen)
        };

        let cert_year = year_str.parse::<u32>().unwrap_or(current_year);
        let years_valid = if cert_year > current_year {
            cert_year - current_year
        } else {
            0
        };

        // Approximate expiry based on years valid
        let expiry =
            SystemTime::now() + Duration::from_secs(years_valid as u64 * 365 * 24 * 60 * 60);

        // Update the metric with our approximation
        if let Ok(remaining) = expiry.duration_since(SystemTime::now()) {
            crate::metrics::PROXY_METRICS
                .certificate_expiry
                .with_label_values(&[domain])
                .set(remaining.as_secs() as f64);
        }

        println!("Approximated expiry for {} set to {:?}", domain, expiry);
        Ok(expiry)
    }

    // Helper method to get active challenges - useful for the HTTP server
    pub async fn get_challenge(domain: &str) -> Option<(String, String)> {
        let challenges = ACTIVE_CHALLENGES.lock().await;
        challenges.get(domain).cloned()
    }
}
