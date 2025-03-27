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

/// Function to check for certbot certificates for given domains
/// Function to check for certbot certificates for given domains
pub fn find_certbot_certs(domains: &[String]) -> Vec<DomainCert> {
    let mut certs = Vec::new();

    println!("Looking for certificates in: {}", CERTBOT_LIVE_DIR);

    // Check if the base directory exists
    if !Path::new(CERTBOT_LIVE_DIR).exists() {
        println!(
            "Warning: Certificate base directory {} does not exist!",
            CERTBOT_LIVE_DIR
        );

        // Try a fallback path
        let fallback_path = "/mnt/gluster/certbot/letsencrypt/live";
        println!("Trying fallback path: {}", fallback_path);

        if Path::new(fallback_path).exists() {
            println!("Fallback path exists, will use it instead");
            for domain in domains {
                let domain_dir = Path::new(fallback_path).join(domain);
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
            return certs;
        }
    }

    // Original path logic
    for domain in domains {
        let domain_dir = Path::new(CERTBOT_LIVE_DIR).join(domain);
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

    certs
}
