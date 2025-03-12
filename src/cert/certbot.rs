use std::path::Path;

/// Struct to represent domain certificate information
#[derive(Debug, Clone)]
pub struct DomainCert {
    pub domain: String,
    pub cert_path: String,
    pub key_path: String,
}

/// Constant for the certbot directory
const CERTBOT_LIVE_DIR: &str = "certbot/letsencrypt/live";

/// Function to check for certbot certificates for given domains
pub fn find_certbot_certs(domains: &[String]) -> Vec<DomainCert> {
    let mut certs = Vec::new();

    for domain in domains {
        let domain_dir = Path::new(CERTBOT_LIVE_DIR).join(domain);
        let fullchain_path = domain_dir.join("fullchain.pem");
        let privkey_path = domain_dir.join("privkey.pem");

        if fullchain_path.exists() && privkey_path.exists() {
            println!("Found certificates for domain: {}", domain);
            certs.push(DomainCert {
                domain: domain.clone(),
                cert_path: fullchain_path.to_string_lossy().to_string(),
                key_path: privkey_path.to_string_lossy().to_string(),
            });
        } else {
            println!("No certificates found for domain: {}", domain);
        }
    }

    certs
}
