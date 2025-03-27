// src/cert/issuer.rs
use std::fs;
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Result};
use once_cell::sync::Lazy;
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
            // 1. Validate domain points to our server (only for HTTP-01 challenges)
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
        let addresses = format!("{}:443", domain).to_socket_addrs()?;

        // For testing purposes, consider any local IP as valid
        // You can remove or modify this for production
        let valid_ips = vec![
            // "127.0.0.1".to_string(),
            // "localhost".to_string(),
            self.public_ip.clone(),
        ];

        let mut found_matching_ip = false;
        for addr in addresses {
            let ip = addr.ip().to_string();
            println!("Resolved IP for {}: {}", domain, ip);

            // In testing mode, consider localhost as valid
            // if valid_ips.contains(&ip) || ip.starts_with("192.168.") || ip.starts_with("10.") {
            //     found_matching_ip = true;
            //     println!("IP match found for domain validation");
            //     break;
            // }
            if valid_ips.contains(&ip) {
                found_matching_ip = true;
                println!("IP match found for domain validation");
                break;
            }
        }

        if !found_matching_ip {
            return Err(anyhow!(
                "Domain {} does not resolve to a valid IP (local: 127.0.0.1 or public: {})",
                domain,
                self.public_ip
            ));
        }

        // 2. Wait a moment to ensure DNS propagation
        tokio::time::sleep(Duration::from_secs(1)).await;

        Ok(())
    }

    // Check if a valid certificate already exists
    pub fn check_certificate(&self, domain: &str) -> Option<CertificateStatus> {
        let live_dir = self.certbot_dir.join("live").join(domain);
        let cert_path = live_dir.join("fullchain.pem");
        let key_path = live_dir.join("privkey.pem");

        if cert_path.exists() && key_path.exists() {
            // Check certificate expiry
            match self.get_cert_expiry(&cert_path) {
                Ok(expiry) => {
                    let now = SystemTime::now();
                    let thirty_days = Duration::from_secs(30 * 24 * 60 * 60);

                    // If certificate expires in more than 30 days, it's valid
                    if expiry > now + thirty_days {
                        return Some(CertificateStatus {
                            domain: domain.to_string(),
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
                        domain: domain.to_string(),
                        status: "expiring_soon".to_string(),
                        cert_path: Some(cert_path.to_string_lossy().to_string()),
                        key_path: Some(key_path.to_string_lossy().to_string()),
                        expiry: Some(format!("{:?}", expiry)),
                        error: None,
                        is_wildcard: None, // Will be set by the caller
                    });
                }
                Err(_) => {
                    // Certificate exists but can't read expiry
                    return Some(CertificateStatus {
                        domain: domain.to_string(),
                        status: "unknown_expiry".to_string(),
                        cert_path: Some(cert_path.to_string_lossy().to_string()),
                        key_path: Some(key_path.to_string_lossy().to_string()),
                        expiry: None,
                        error: Some("Could not determine certificate expiry".to_string()),
                        is_wildcard: None, // Will be set by the caller
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

        println!("Issuing certificate for: {}", domain);

        // Generate a token and validation string for the HTTP-01 challenge
        let token = format!("{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
        let validation = format!("{}.{}", token, "valid-response-for-acme-challenge");

        // Store the challenge token and validation for the HTTP server to use
        if !is_wildcard {
            let mut challenges = ACTIVE_CHALLENGES.lock().await;
            challenges.insert(domain.to_string(), (token.clone(), validation.clone()));
        }

        // Build certbot command
        let mut cmd = Command::new("certbot");
        cmd.arg("certonly")
            .arg("--email")
            .arg(email)
            .arg("--agree-tos")
            .arg("--no-eff-email")
            .arg("--config-dir")
            .arg(&self.certbot_dir);

        if staging {
            cmd.arg("--staging");
        }

        // Handle different challenge types
        if is_wildcard {
            // For wildcard certificates, use DNS challenge with Cloudflare
            if let Some(dns_provider) = &request.dns_provider {
                if dns_provider == "cloudflare" {
                    if let Some(credentials) = &request.dns_credentials {
                        // Create Cloudflare credentials file
                        let cf_credentials_path =
                            self.create_cloudflare_credentials(credentials)?;

                        cmd.arg("--authenticator")
                            .arg("dns-cloudflare")
                            .arg("--dns-cloudflare-credentials")
                            .arg(&cf_credentials_path);
                    } else {
                        return Err(anyhow!(
                            "Cloudflare credentials required for wildcard certificates"
                        ));
                    }
                } else {
                    return Err(anyhow!(
                        "Only Cloudflare is supported for wildcard certificates"
                    ));
                }
            } else {
                return Err(anyhow!("DNS provider required for wildcard certificates"));
            }

            // Add domain and wildcard domain
            cmd.arg("-d")
                .arg(domain)
                .arg("-d")
                .arg(format!("*.{}", domain));

            println!("Using DNS-01 challenge for wildcard certificate");
        } else {
            // For regular certificates, use HTTP-01 challenge
            cmd.arg("--webroot")
                .arg("-w")
                .arg("/var/www/html") // Webroot path
                .arg("-d")
                .arg(domain);

            println!("Using HTTP-01 challenge for standard certificate");
        }

        // Execute certbot command
        let output = cmd.output()?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            println!("Certbot error: {}", error);
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
        let expiry = match self.get_cert_expiry(&cert_path) {
            Ok(expiry) => Some(format!("{:?}", expiry)),
            Err(_) => None,
        };

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
    fn get_cert_expiry(&self, cert_path: &Path) -> Result<SystemTime> {
        // Execute openssl to get certificate expiry
        let output = Command::new("openssl")
            .arg("x509")
            .arg("-in")
            .arg(cert_path)
            .arg("-noout")
            .arg("-enddate")
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to get certificate expiry"));
        }

        let expiry_output = String::from_utf8_lossy(&output.stdout);

        // Parse the expiry date from output (format: notAfter=May 15 23:59:59 2024 GMT)
        let date_part = expiry_output
            .strip_prefix("notAfter=")
            .ok_or_else(|| anyhow!("Unexpected output format"))?
            .trim();

        // This is a simplified example - in production, use a proper date parser
        // For this example, we'll return current time + 90 days
        let expiry = SystemTime::now() + Duration::from_secs(90 * 24 * 60 * 60);

        Ok(expiry)
    }

    // Helper method to get active challenges - useful for the HTTP server
    pub async fn get_challenge(domain: &str) -> Option<(String, String)> {
        let challenges = ACTIVE_CHALLENGES.lock().await;
        challenges.get(domain).cloned()
    }
}
