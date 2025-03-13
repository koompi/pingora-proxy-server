// src/cert/issuer.rs
use std::fs;
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

// Certificate request data structure
#[derive(Debug, Deserialize)]
pub struct CertificateRequest {
    pub domain: String,
    pub email: String,
    // Optional fields
    pub staging: Option<bool>,
    pub force_renew: Option<bool>,
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
}

// Structure to manage the certificate issuing process
pub struct CertificateIssuer {
    pub certbot_dir: PathBuf,
    pub output_dir: PathBuf,
    pub public_ip: String,
}

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
        // 1. Validate domain points to our server
        let validation_result = self.validate_domain(&request.domain).await;
        if let Err(e) = validation_result {
            return CertificateStatus {
                domain: request.domain,
                status: "failed".to_string(),
                cert_path: None,
                key_path: None,
                expiry: None,
                error: Some(format!("Domain validation failed: {}", e)),
            };
        }

        // 2. Check if certificate already exists and is valid
        let force_renew = request.force_renew.unwrap_or(false);
        if !force_renew {
            if let Some(status) = self.check_certificate(&request.domain) {
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
            "127.0.0.1".to_string(),
            "localhost".to_string(),
            self.public_ip.clone()
        ];
        
        let mut found_matching_ip = false;
        for addr in addresses {
            let ip = addr.ip().to_string();
            println!("Resolved IP for {}: {}", domain, ip);
            
            // In testing mode, consider localhost as valid
            if valid_ips.contains(&ip) || ip.starts_with("192.168.") || ip.starts_with("10.") {
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

    // Check if a valid certificate already exists - make this public
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
        
        println!("Issuing certificate for: {}", domain);
        
        // For local testing, create dummy certificate files
        let dummy_testing = true; // Set to false for production
        
        if dummy_testing {
            println!("Creating dummy certificate files for testing");
            
            // Create directories
            let live_dir = self.certbot_dir.join("live").join(domain);
            fs::create_dir_all(&live_dir)?;
            
            let cert_path = live_dir.join("fullchain.pem");
            let key_path = live_dir.join("privkey.pem");
            
            // Create dummy certificate files
            fs::write(&cert_path, "DUMMY CERTIFICATE FOR TESTING\n")?;
            fs::write(&key_path, "DUMMY PRIVATE KEY FOR TESTING\n")?;
            
            // Also copy to output directory
            fs::create_dir_all(self.output_dir.join(domain))?;
            fs::copy(&cert_path, self.output_dir.join(domain).join("fullchain.pem"))?;
            fs::copy(&key_path, self.output_dir.join(domain).join("privkey.pem"))?;
            
            return Ok(CertificateStatus {
                domain: domain.to_string(),
                status: "issued".to_string(),
                cert_path: Some(cert_path.to_string_lossy().to_string()),
                key_path: Some(key_path.to_string_lossy().to_string()),
                expiry: Some("2099-12-31T23:59:59Z".to_string()),
                error: None,
            });
        }

        // Build certbot command
        let mut cmd = Command::new("certbot");
        cmd.arg("certonly")
            .arg("--webroot")
            .arg("-w")
            .arg("/var/www/html") // Webroot path - adjust to your HTTP challenge path
            .arg("--email")
            .arg(email)
            .arg("--agree-tos")
            .arg("--no-eff-email")
            .arg("-d")
            .arg(domain)
            .arg("--config-dir")
            .arg(&self.certbot_dir);

        if staging {
            cmd.arg("--staging");
        }

        // Execute certbot command
        let output = cmd.output()?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            println!("Certbot error: {}", error);
            return Err(anyhow!("Certbot failed: {}", error));
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
        })
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
}
