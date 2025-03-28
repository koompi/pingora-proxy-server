use std::path::Path;

/// Struct to represent domain certificate information
#[derive(Debug, Clone)]
pub struct DomainCert {
    pub domain: String,
    pub cert_path: String,
    pub key_path: String,
}

/// Constant for the certbot directory
const CERTBOT_LIVE_DIR: &str = "/certbot/letsencrypt/live";
const FALLBACK_LIVE_DIR: &str = "/etc/letsencrypt/live";

/// Function to check for certbot certificates for given domains
pub fn find_certbot_certs(domains: &[String]) -> Vec<DomainCert> {
    let mut certs = Vec::new();

    // Try primary path first, then fallback
    let base_paths = [CERTBOT_LIVE_DIR, FALLBACK_LIVE_DIR];

    for &base_path in &base_paths {
        println!("Looking for certificates in: {}", base_path);

        if !Path::new(base_path).exists() {
            println!("Warning: Directory {} does not exist!", base_path);
            continue;
        }

        // Check each domain for certificates
        for domain in domains {
            let domain_dir = Path::new(base_path).join(domain);
            let fullchain_path = domain_dir.join("fullchain.pem");
            let privkey_path = domain_dir.join("privkey.pem");

            println!("Checking certificates at: {}", domain_dir.display());

            if fullchain_path.exists() && privkey_path.exists() {
                println!("Found certificates for domain: {}", domain);
                certs.push(DomainCert {
                    domain: domain.clone(),
                    cert_path: fullchain_path.to_string_lossy().to_string(),
                    key_path: privkey_path.to_string_lossy().to_string(),
                });
            } else {
                println!(
                    "No certificates found for domain: {} at {}",
                    domain,
                    domain_dir.display()
                );
            }
        }

        // If we found any certificates, no need to check fallback
        if !certs.is_empty() {
            break;
        }
    }

    certs
}

pub fn check_certificate_status(domain: &str) -> Result<String, String> {
    let cert_path = Path::new(CERTBOT_LIVE_DIR)
        .join(domain)
        .join("fullchain.pem");
    let key_path = Path::new(CERTBOT_LIVE_DIR).join(domain).join("privkey.pem");

    if !cert_path.exists() || !key_path.exists() {
        return Err("Certificate files not found".to_string());
    }

    Ok("Certificate found".to_string())
}
