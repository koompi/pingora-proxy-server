// src/tls.rs
use log::{error, info};
use openssl::ssl::{NameType, SniError, SslAlert, SslContext, SslFiletype, SslMethod, SslRef};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

// Certificate configuration used for initialization
#[derive(Clone, Debug)]
pub struct CertificateConfig {
    pub domain: String,
    pub cert_path: String,
    pub key_path: String,
}

// Certificate information with loaded SSL context
#[derive(Debug)]
pub struct CertificateInfo {
    pub domain: String,
    pub cert_path: String,
    pub key_path: String,
    pub ssl_context: SslContext,
}

// Certificates manager for handling multiple SSL certificates
#[derive(Debug)]
pub struct Certificates {
    pub certs: Arc<Mutex<Vec<CertificateInfo>>>,
    pub default_cert_path: String,
    pub default_key_path: String,
}

impl Certificates {
    // Create a new Certificates instance from configs
    pub fn new(configs: &[(String, String, String)]) -> Result<Self, Box<dyn std::error::Error>> {
        if configs.is_empty() {
            return Err("At least one certificate configuration is required".into());
        }

        let mut certs = Vec::new();
        for (domain, cert_path, key_path) in configs {
            match Self::create_ssl_context(cert_path, key_path) {
                Ok(ssl_context) => {
                    certs.push(CertificateInfo {
                        domain: domain.clone(),
                        cert_path: cert_path.clone(),
                        key_path: key_path.clone(),
                        ssl_context,
                    });
                    info!("Loaded certificate for domain: {}", domain);
                }
                Err(e) => {
                    error!("Failed to load certificate for {}: {}", domain, e);
                }
            }
        }

        // Use the first certificate as default
        let (_, default_cert, default_key) = &configs[0];

        Ok(Self {
            certs: Arc::new(Mutex::new(certs)),
            default_cert_path: default_cert.clone(),
            default_key_path: default_key.clone(),
        })
    }

    // Create SSL context from certificate and key files
    fn create_ssl_context(
        cert_path: &str,
        key_path: &str,
    ) -> Result<SslContext, Box<dyn std::error::Error>> {
        let mut builder = SslContext::builder(SslMethod::tls())?;

        // Set the certificate and key
        builder.set_certificate_chain_file(cert_path)?;
        builder.set_private_key_file(key_path, SslFiletype::PEM)?;

        // Enable HTTP/2 support
        builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;

        // Set modern cipher suites
        builder.set_cipher_list("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384")?;

        // Set security options
        builder.set_options(
            openssl::ssl::SslOptions::NO_SSLV2
                | openssl::ssl::SslOptions::NO_SSLV3
                | openssl::ssl::SslOptions::NO_TLSV1
                | openssl::ssl::SslOptions::NO_TLSV1_1,
        );

        Ok(builder.build())
    }

    // Find certificate for a domain with wildcard support
    pub fn find_ssl_context(&self, server_name: &str) -> Option<Arc<SslContext>> {
        if let Ok(certs) = self.certs.lock() {
            // First try exact match
            if let Some(cert) = certs.iter().find(|c| c.domain == server_name) {
                info!("Found exact certificate match for {}", server_name);
                return Some(Arc::new(cert.ssl_context.clone()));
            }

            // Then try wildcard match
            for cert in certs.iter() {
                if cert.domain.starts_with("*.") {
                    let wildcard_suffix = &cert.domain[1..]; // Remove the "*"
                    if server_name.ends_with(wildcard_suffix) {
                        info!("Found wildcard certificate match for {}", server_name);
                        return Some(Arc::new(cert.ssl_context.clone()));
                    }
                }
            }

            info!("No matching certificate found for {}", server_name);
        } else {
            error!("Failed to lock certificates collection");
        }

        None
    }

    // SNI callback for TLS connections
    pub fn server_name_callback(
        &self,
        ssl_ref: &mut SslRef,
        _ssl_alert: &mut SslAlert,
    ) -> Result<(), SniError> {
        let server_name = if let Some(name) = ssl_ref.servername(NameType::HOST_NAME) {
            name.to_string()
        } else {
            return Ok(());
        };
        info!("SNI request for domain: {}", server_name);

        if let Some(ctx) = self.find_ssl_context(&server_name) {
            match ssl_ref.set_ssl_context(ctx.as_ref()) {
                Ok(_) => {
                    info!("Successfully set SSL context for {}", server_name);
                    return Ok(());
                }
                Err(e) => {
                    error!("Failed to set SSL context: {:?}", e);
                    return Err(SniError::ALERT_FATAL);
                }
            }
        }

        // If no match found or no server name provided, use default context
        Ok(())
    }

    // Method to add a new certificate at runtime
    pub fn add_certificate(
        &self,
        domain: &str,
        cert_path: &str,
        key_path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("Adding certificate for domain: {}", domain);

        // Check if files exist
        if !Path::new(cert_path).exists() || !Path::new(key_path).exists() {
            return Err(format!("Certificate files not found for {}", domain).into());
        }

        // Create SSL context
        let ssl_context = Self::create_ssl_context(cert_path, key_path)?;

        // Create certificate info
        let cert_info = CertificateInfo {
            domain: domain.to_string(),
            cert_path: cert_path.to_string(),
            key_path: key_path.to_string(),
            ssl_context,
        };

        // Add to certificates collection
        if let Ok(mut certs) = self.certs.lock() {
            // Remove existing certificate for same domain if it exists
            certs.retain(|c| c.domain != domain);

            // Add new certificate
            certs.push(cert_info);
            info!("Successfully added certificate for {}", domain);
            Ok(())
        } else {
            Err("Failed to lock certificates collection".into())
        }
    }

    // Method to remove a certificate
    pub fn remove_certificate(&self, domain: &str) -> Result<(), Box<dyn std::error::Error>> {
        info!("Removing certificate for domain: {}", domain);

        if let Ok(mut certs) = self.certs.lock() {
            let before_len = certs.len();
            certs.retain(|c| c.domain != domain);

            if certs.len() < before_len {
                info!("Successfully removed certificate for {}", domain);
                Ok(())
            } else {
                Err(format!("Certificate for domain {} not found", domain).into())
            }
        } else {
            Err("Failed to lock certificates collection".into())
        }
    }

    // Method to get all domains with certificates
    pub fn list_certificates(&self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        if let Ok(certs) = self.certs.lock() {
            Ok(certs.iter().map(|c| c.domain.clone()).collect())
        } else {
            Err("Failed to lock certificates collection".into())
        }
    }

    // Method to refresh certificates from disk
    pub fn refresh_certificates(&self, certs_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
        info!("Refreshing certificates from {}", certs_dir);

        let mut new_certs = Vec::new();

        // Read all certificate directories
        if let Ok(entries) = fs::read_dir(certs_dir) {
            for entry in entries.filter_map(Result::ok) {
                if let Ok(domain) = entry.file_name().into_string() {
                    let cert_path = Path::new(certs_dir).join(&domain).join("fullchain.pem");
                    let key_path = Path::new(certs_dir).join(&domain).join("privkey.pem");

                    if cert_path.exists() && key_path.exists() {
                        match Self::create_ssl_context(
                            &cert_path.to_string_lossy(),
                            &key_path.to_string_lossy(),
                        ) {
                            Ok(ssl_context) => {
                                new_certs.push(CertificateInfo {
                                    domain: domain.clone(),
                                    cert_path: cert_path.to_string_lossy().to_string(),
                                    key_path: key_path.to_string_lossy().to_string(),
                                    ssl_context,
                                });
                                info!("Refreshed certificate for domain: {}", domain);
                            }
                            Err(e) => {
                                error!("Failed to refresh certificate for {}: {}", domain, e);
                            }
                        }
                    }
                }
            }
        }

        // Update the certificates collection
        if let Ok(mut certs) = self.certs.lock() {
            *certs = new_certs;
            info!("Successfully refreshed {} certificates", certs.len());
            Ok(())
        } else {
            Err("Failed to lock certificates collection".into())
        }
    }
}

// ALPN callback to prefer HTTP/2
pub fn prefer_h2<'a>(
    ssl: &mut SslRef,
    server_protos: &'a [u8],
) -> Result<&'a [u8], openssl::ssl::AlpnError> {
    // Try to find HTTP/2 in both the client and server protocols
    let protos = b"\x02h2\x08http/1.1";
    for client_proto in protos.windows(2) {
        // Get the length of this protocol
        let proto_len = client_proto[0] as usize;
        if client_proto.len() < proto_len + 1 {
            break;
        }

        // Extract the protocol name
        let proto_name = &client_proto[1..1 + proto_len];

        // Check if this protocol is in the server protos
        for server_proto in server_protos.windows(2) {
            let server_proto_len = server_proto[0] as usize;
            if server_proto.len() < server_proto_len + 1 {
                break;
            }

            let server_proto_name = &server_proto[1..=server_proto_len];

            if proto_name == server_proto_name {
                return Ok(server_proto_name);
            }
        }
    }

    // No match found
    Err(openssl::ssl::AlpnError::NOACK)
}
