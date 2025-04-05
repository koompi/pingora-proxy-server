use openssl::ssl::{NameType, SniError, SslAlert, SslContext, SslFiletype, SslMethod, SslRef};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

// Define certificate information structure
#[derive(Debug)]
pub struct CertificateInfo {
    pub domain: String,
    pub cert_path: String,
    pub key_path: String,
    pub ssl_context: SslContext,
}

// Structure to manage multiple certificates
pub struct Certificates {
    certs: Vec<CertificateInfo>,
    pub default_cert_path: String,
    pub default_key_path: String,
}

impl Certificates {
    pub fn new(configs: &[(String, String, String)]) -> Result<Self, Box<dyn std::error::Error>> {
        if configs.is_empty() {
            return Err("At least one certificate configuration is required".into());
        }

        let mut certs = Vec::new();
        for (domain, cert_path, key_path) in configs {
            let ssl_context = Self::create_ssl_context(cert_path, key_path)?;
            certs.push(CertificateInfo {
                domain: domain.clone(),
                cert_path: cert_path.clone(),
                key_path: key_path.clone(),
                ssl_context,
            });
        }

        // Use the first certificate as default
        let (_, default_cert_path, default_key_path) = &configs[0];

        Ok(Self {
            certs,
            default_cert_path: default_cert_path.clone(),
            default_key_path: default_key_path.clone(),
        })
    }

    // Create SSL context for a certificate
    fn create_ssl_context(
        cert_path: &str,
        key_path: &str,
    ) -> Result<SslContext, Box<dyn std::error::Error>> {
        let mut builder = SslContext::builder(SslMethod::tls())?;
        builder.set_certificate_chain_file(cert_path)?;
        builder.set_private_key_file(key_path, SslFiletype::PEM)?;

        // Enable HTTP/2 support
        builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;

        Ok(builder.build())
    }

    // Find certificate context for a domain
    pub fn find_ssl_context(&self, server_name: &str) -> Option<&SslContext> {
        // First try exact match
        if let Some(cert) = self.certs.iter().find(|c| c.domain == server_name) {
            return Some(&cert.ssl_context);
        }

        // Then try wildcard match
        for cert in &self.certs {
            if cert.domain.starts_with("*.") {
                let wildcard_suffix = &cert.domain[1..]; // Remove the "*"
                if server_name.ends_with(wildcard_suffix) {
                    return Some(&cert.ssl_context);
                }
            }
        }

        None
    }

    // Callback for SNI handling
    pub fn server_name_callback(
        &self,
        ssl_ref: &mut SslRef,
        _ssl_alert: &mut SslAlert,
    ) -> Result<(), SniError> {
        let server_name = ssl_ref
            .servername(NameType::HOST_NAME)
            .map(|s| s.to_string());
        if let Some(server_name) = server_name {
            println!("SNI request for domain: {}", server_name);

            if let Some(ctx) = self.find_ssl_context(&server_name) {
                match ssl_ref.set_ssl_context(ctx) {
                    Ok(_) => {
                        println!("Successfully set SSL context for {}", server_name);
                        return Ok(());
                    }
                    Err(e) => {
                        println!("Failed to set SSL context: {:?}", e);
                        return Err(SniError::ALERT_FATAL);
                    }
                }
            }
            println!("No matching certificate found for {}", server_name);
        }

        // If no match found, default certificate will be used
        Ok(())
    }

    // Method to add a new certificate at runtime
    pub fn add_certificate(
        &self,
        domain: &str,
        cert_path: &str,
        key_path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let ssl_context = Self::create_ssl_context(cert_path, key_path)?;

        // Here you would add the new certificate to your certificates collection
        // This would need to be modified to handle thread-safety (e.g., using RwLock)
        // For the example, we're assuming self.certs is wrapped in a mutex or similar

        Ok(())
    }
}
