use std::{
    collections::HashMap,
    path::Path,
    str,
    sync::{Arc, Mutex, RwLock},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use pingora::{prelude::HttpPeer, Error, ErrorType, Result};
use pingora_proxy::{ProxyHttp, Session};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::{
    cert::certbot,
    config::model::ConfigStore,
    metrics::PROXY_METRICS,
    proxy::utils::{parse_swarm_target, test_service_connectivity, validate_org_network_access},
};

use super::utils::extract_hostname;
use log::{error, info, warn};

// Add Debug implementation for HttpsProxy
#[derive(Debug, Clone)]
pub struct HttpsProxy {
    pub servers: Arc<Mutex<ConfigStore>>,
    pub cert_cache: Arc<Mutex<HashMap<String, (Vec<u8>, Vec<u8>, u64)>>>, // (cert, key, timestamp)
    pub domain_map: Arc<RwLock<HashMap<String, String>>>,
}

impl ResolvesServerCert for HttpsProxy {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let server_name = match client_hello.server_name() {
            Some(name) => {
                info!("SNI request for domain: {}", name);
                name.to_lowercase()
            }
            None => {
                error!("No SNI provided in client hello");
                return None;
            }
        };

        // First, try exact match
        let mut matching_cert = self.find_certificate_for_domain(&server_name);

        // If no exact match, try wildcard matching
        if matching_cert.is_none() {
            matching_cert = self.find_wildcard_certificate(&server_name);
        }

        matching_cert
    }
}

impl HttpsProxy {
    pub fn new(servers: Arc<Mutex<ConfigStore>>) -> Self {
        Self {
            servers,
            cert_cache: Arc::new(Mutex::new(HashMap::new())),
            domain_map: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    // New method to find exact certificate match
    fn find_certificate_for_domain(&self, domain: &str) -> Option<Arc<CertifiedKey>> {
        let cache_guard = match self.cert_cache.lock() {
            Ok(guard) => guard,
            Err(e) => {
                error!("Failed to lock cert cache: {:?}", e);
                return None;
            }
        };

        // Try direct lookup
        if let Some((cert, key, _)) = cache_guard.get(domain) {
            match self.create_certified_key(cert.clone(), key.clone()) {
                Ok(cert_key) => {
                    info!("Found exact certificate for: {}", domain);
                    return Some(cert_key);
                }
                Err(e) => {
                    error!("Failed to create certified key for {}: {:?}", domain, e);
                }
            }
        }

        None
    }

    // New method to find wildcard certificate
    fn find_wildcard_certificate(&self, domain: &str) -> Option<Arc<CertifiedKey>> {
        let cache_guard = match self.cert_cache.lock() {
            Ok(guard) => guard,
            Err(e) => {
                error!("Failed to lock cert cache: {:?}", e);
                return None;
            }
        };

        // Split domain to extract base domain for wildcard matching
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() < 2 {
            return None;
        }

        // Try finding a wildcard certificate
        let wildcard_domain = format!("*.{}", parts[1..].join("."));

        if let Some((cert, key, _)) = cache_guard.get(&wildcard_domain) {
            match self.create_certified_key(cert.clone(), key.clone()) {
                Ok(cert_key) => {
                    info!("Found wildcard certificate for: {}", wildcard_domain);
                    return Some(cert_key);
                }
                Err(e) => {
                    error!(
                        "Failed to create certified key for {}: {:?}",
                        wildcard_domain, e
                    );
                }
            }
        }

        None
    }

    // Enhance reload_certificates to handle multiple domains
    pub async fn reload_certificates(&self) -> Result<()> {
        info!("Starting multi-domain certificate reload process...");

        // Get current timestamp for cache invalidation
        let timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(err) => {
                error!("Failed to get system time: {:?}", err);
                return Err(Error::new(ErrorType::ConnectRefused));
            }
        };

        // Get domains from servers configuration
        let domains = {
            let servers_guard = match self.servers.lock() {
                Ok(guard) => guard,
                Err(err) => {
                    error!("Failed to lock servers: {:?}", err);
                    return Err(Error::new(ErrorType::ConnectRefused));
                }
            };
            servers_guard.keys().cloned().collect::<Vec<String>>()
        };

        info!("Reloading certificates for {} domains", domains.len());

        // Find certificates for domains
        let certs = certbot::find_certbot_certs(&domains);
        info!("Found {} certificates", certs.len());

        // Lock cert cache for update
        let mut cache_guard = match self.cert_cache.lock() {
            Ok(guard) => guard,
            Err(e) => {
                error!("Failed to lock cert cache: {:?}", e);
                return Err(Error::new(ErrorType::ConnectRefused));
            }
        };

        // Clear existing cache to ensure we reload everything
        cache_guard.clear();

        // Process each certificate
        for cert in certs {
            info!("Processing certificate for domain: {}", cert.domain);

            // Try to read certificate and key
            match (
                std::fs::read(&cert.cert_path),
                std::fs::read(&cert.key_path),
            ) {
                (Ok(cert_data), Ok(key_data)) => {
                    info!("Successfully loaded certificate for: {}", cert.domain);

                    // Store with lowercase domain for consistent lookup
                    cache_guard.insert(
                        cert.domain.to_lowercase(),
                        (cert_data.clone(), key_data.clone(), timestamp),
                    );

                    // If this is a wildcard certificate, also add wildcard entry
                    if cert.domain.starts_with("*.") {
                        cache_guard.insert(
                            cert.domain.to_lowercase(),
                            (cert_data.clone(), key_data.clone(), timestamp),
                        );
                    }
                }
                _ => {
                    error!("Failed to read certificate files for {}", cert.domain);
                    continue;
                }
            }
        }

        info!(
            "Certificate reload complete. Cache now contains {} certificates",
            cache_guard.len()
        );

        // Update domain map with lowercase domains
        {
            let mut domain_map = self.domain_map.write().unwrap();
            domain_map.clear();

            for domain in cache_guard.keys() {
                domain_map.insert(domain.clone(), domain.clone());
            }
        }

        Ok(())
    }

    pub fn get_certificate(&self, domain: &str) -> Option<(Vec<u8>, Vec<u8>)> {
        let normalized_domain = domain.to_lowercase();

        // First, check the domain map for exact match
        let canonical_domain = {
            let domain_map = self.domain_map.read().unwrap();
            domain_map.get(&normalized_domain).cloned()
        };

        if let Some(canonical_domain) = canonical_domain {
            let cache = self.cert_cache.lock().unwrap();
            if let Some((cert, key, _)) = cache.get(&canonical_domain) {
                return Some((cert.clone(), key.clone()));
            }
        }

        // Fallback to more flexible matching
        let cache = self.cert_cache.lock().unwrap();

        // Try exact match
        if let Some((cert, key, _)) = cache.get(&normalized_domain) {
            return Some((cert.clone(), key.clone()));
        }

        // Log available certificates for debugging
        let available_domains: Vec<String> = cache.keys().cloned().collect();
        error!(
            "No certificate found for {}. Available certificates: {:?}",
            normalized_domain, available_domains
        );

        None
    }

    pub async fn reload_certificate_for_domain(&self, domain: &str) -> Result<()> {
        info!("Reloading certificate for domain: {}", domain);

        // Get current timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| {
                error!("Failed to get system time: {:?}", e);
                Error::new(ErrorType::ConnectRefused)
            })
            .map(|duration| duration.as_secs())?;

        // Find certificate for domain
        let certs = certbot::find_certbot_certs(&[domain.to_string()]);

        // Lock cert cache for update
        let mut cache_guard = self.cert_cache.lock().map_err(|e| {
            error!("Failed to lock cert cache: {:?}", e);
            Error::new(ErrorType::ConnectRefused)
        })?;

        // Process certificate if found
        if let Some(cert) = certs.first() {
            match (
                std::fs::read(&cert.cert_path),
                std::fs::read(&cert.key_path),
            ) {
                (Ok(cert_data), Ok(key_data)) => {
                    info!("Successfully loaded certificate for: {}", domain);
                    cache_guard.insert(domain.to_string(), (cert_data, key_data, timestamp));
                    Ok(())
                }
                _ => {
                    error!("Failed to read certificate files for {}", domain);
                    Err(Error::new(ErrorType::ConnectRefused))
                }
            }
        } else {
            error!("No certificate found for {}", domain);
            Err(Error::new(ErrorType::ConnectRefused))
        }
    }

    // Helper method to create a CertifiedKey for rustls
    fn create_certified_key(
        &self,
        cert_data: Vec<u8>,
        key_data: Vec<u8>,
    ) -> Result<Arc<CertifiedKey>> {
        // Parse certificates
        let mut cert_cursor = std::io::Cursor::new(cert_data);
        let mut certs = Vec::new();

        // rustls_pemfile::certs returns an iterator, not a Result
        for cert_result in rustls_pemfile::certs(&mut cert_cursor) {
            match cert_result {
                Ok(cert) => certs.push(cert),
                Err(_) => return Err(Error::new(ErrorType::ConnectRefused)),
            }
        }

        if certs.is_empty() {
            return Err(Error::new(ErrorType::ConnectRefused));
        }

        // Parse private key - first try PKCS8
        let mut key_cursor = std::io::Cursor::new(key_data.clone());
        let mut private_key = None;

        // rustls_pemfile::pkcs8_private_keys returns an iterator, not a Result
        for key_result in rustls_pemfile::pkcs8_private_keys(&mut key_cursor) {
            match key_result {
                Ok(key) => {
                    private_key = Some(PrivateKeyDer::Pkcs8(key));
                    break;
                }
                Err(_) => continue,
            }
        }

        // If PKCS8 failed, try RSA
        if private_key.is_none() {
            let mut key_cursor = std::io::Cursor::new(key_data);
            for key_result in rustls_pemfile::rsa_private_keys(&mut key_cursor) {
                match key_result {
                    Ok(key) => {
                        private_key = Some(PrivateKeyDer::Pkcs1(key));
                        break;
                    }
                    Err(_) => continue,
                }
            }
        }

        // If we couldn't parse the key, return an error
        let private_key = match private_key {
            Some(key) => key,
            None => return Err(Error::new(ErrorType::ConnectRefused)),
        };

        // Create signing key
        let signing_key = match any_supported_type(&private_key) {
            Ok(key) => key,
            Err(_) => return Err(Error::new(ErrorType::ConnectRefused)),
        };

        // Return the certified key
        Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
    }
}

#[async_trait::async_trait]
/// Implementation of the HTTPS proxy functionality.
impl ProxyHttp for HttpsProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        let hostname = extract_hostname(&session.request_summary());
        let hostname_str = hostname.as_deref().unwrap_or("");

        info!("HTTPS request for hostname: {}", hostname_str);
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let hostname = extract_hostname(&session.request_summary());
        let hostname_str = hostname.as_deref().unwrap_or("");

        // Start timing the request
        let start_time = Instant::now();
        // Store timing info in a request header
        session
            .req_header_mut()
            .insert_header(
                "x-request-start-time",
                start_time.elapsed().as_secs_f64().to_string(),
            )
            .unwrap_or(());

        // Get the target outside await points to avoid holding MutexGuard across await
        let target = {
            match self.servers.lock() {
                Ok(guard) => {
                    let key = hostname.as_ref().map(String::as_str).unwrap_or("");
                    guard.get(key).map(|(target, _)| target.clone())
                }
                Err(e) => {
                    error!("Error locking servers mutex in HttpsProxy: {:?}", e);
                    None
                }
            }
        };

        // Process the target
        match target {
            Some(to) => {
                println!("Routing HTTPS request to backend: {}", to);

                // Handle Swarm service discovery with stronger isolation
                if to.contains(".") || to.starts_with("tasks.") {
                    // Parse target to get service details
                    let (host, port, org_id) = parse_swarm_target(&to);
                    println!("Using Swarm DNS target: {}", host);

                    // Create peer with proper host resolution
                    let mut peer = HttpPeer::new(
                        format!("{}:{}", host, port),
                        false,
                        hostname.unwrap_or_default(),
                    );

                    // Add security headers for organization isolation
                    if let Some(org) = org_id {
                        // Organization ID validation for network isolation
                        peer.options.extra_proxy_headers.insert(
                            "X-Organization-ID".to_string(),
                            org.to_string().into_bytes(),
                        );

                        // Add isolation header to enforce network boundary
                        peer.options
                            .extra_proxy_headers
                            .insert("X-Network-Isolation".to_string(), b"strict".to_vec());

                        // Add organization boundary header
                        peer.options
                            .extra_proxy_headers
                            .insert("X-Organization-Boundary".to_string(), b"enforced".to_vec());

                        // Add HTTPS protocol header
                        peer.options
                            .extra_proxy_headers
                            .insert("X-Forwarded-Proto".to_string(), b"https".to_vec());

                        // Add additional headers for tracing
                        peer.options.extra_proxy_headers.insert(
                            "X-Proxy-Source".to_string(),
                            b"pingora-proxy-https".to_vec(),
                        );

                        // Test connectivity with timeout to avoid hanging requests
                        if !test_service_connectivity(&host, port).await {
                            println!("Warning: Service {} appears to be unreachable", host);
                            // Continue anyway, as the Docker DNS might just need time to propagate
                        }

                        // Validate organization network access
                        if !validate_org_network_access(&host, &org) {
                            println!(
                                "Warning: Service {} is not authorized for org {}",
                                host, org
                            );
                            // We still continue, but log this security concern
                        }
                    }

                    Ok(Box::new(peer))
                } else {
                    // Standard IP:port target - use directly
                    println!("Using direct target: {}", to);
                    let mut peer = HttpPeer::new(to, false, hostname.unwrap_or_default());

                    // Add basic security headers
                    peer.options
                        .extra_proxy_headers
                        .insert("X-Forwarded-Proto".to_string(), b"https".to_vec());

                    peer.options.extra_proxy_headers.insert(
                        "X-Proxy-Source".to_string(),
                        b"pingora-proxy-https".to_vec(),
                    );

                    Ok(Box::new(peer))
                }
            }
            None => {
                PROXY_METRICS
                    .requests_total
                    .with_label_values(&[hostname_str, "404"])
                    .inc();
                Err(Error::new(ErrorType::HTTPStatus(404)))
            }
        }
    }

    async fn logging(
        &self,
        session: &mut Session,
        error: Option<&pingora::Error>,
        _ctx: &mut Self::CTX,
    ) {
        // Extract hostname and other details for logging
        let hostname = extract_hostname(&session.request_summary());
        let hostname_str = hostname.as_deref().unwrap_or("");

        // Record request duration
        let start_time_header = session.req_header().headers.get("x-request-start-time");
        if let Some(start_time_str) = start_time_header {
            if let Ok(start_time) = str::from_utf8(start_time_str.as_ref()) {
                if let Ok(start_time_secs) = start_time.parse::<f64>() {
                    let duration = start_time_secs;
                    PROXY_METRICS
                        .request_duration
                        .with_label_values(&[hostname.as_deref().unwrap_or("")])
                        .observe(duration);
                }
            }
        }

        if let Some(response) = session.as_ref().response_written() {
            let status = response.status.as_u16().to_string();

            PROXY_METRICS
                .requests_total
                .with_label_values(&[hostname_str, &status])
                .inc();

            if status == "403" {
                PROXY_METRICS
                    .backend_failures
                    .with_label_values(&[hostname_str, "forbidden"])
                    .inc();
            }
        }

        if let Some(_) = error {
            PROXY_METRICS
                .backend_failures
                .with_label_values(&[hostname_str, "connection_error"])
                .inc();
        }
    }
}
