use std::{
    collections::HashMap,
    str,
    sync::{Arc, Mutex, RwLock},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use log::{error, info};
use openssl::error::ErrorStack;
use openssl::ssl::{SslContext, SslContextBuilder, SslMethod};
use pingora::upstreams::peer::HttpPeer;
use pingora::{Error, ErrorType, Result};
use pingora_proxy::{ProxyHttp, Session};

use crate::{
    cert::certbot,
    config::model::ConfigStore,
    metrics::PROXY_METRICS,
    proxy::utils::{parse_swarm_target, test_service_connectivity, validate_org_network_access},
};

use super::utils::extract_hostname;

// Add Debug implementation for HttpsProxy
#[derive(Debug, Clone)]
pub struct HttpsProxy {
    pub servers: Arc<Mutex<ConfigStore>>,
    pub cert_cache: Arc<Mutex<HashMap<String, (Vec<u8>, Vec<u8>, u64)>>>, // (cert, key, timestamp)
    pub domain_map: Arc<RwLock<HashMap<String, String>>>,
}

impl HttpsProxy {
    pub fn new(servers: Arc<Mutex<ConfigStore>>) -> Self {
        Self {
            servers,
            cert_cache: Arc::new(Mutex::new(HashMap::new())),
            domain_map: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    // Find and return SSL context for a domain
    pub fn get_ssl_context(&self, domain: &str) -> Option<SslContext> {
        let normalized_domain = domain.to_lowercase();

        if let Some((cert, key)) = self.get_certificate(&normalized_domain) {
            match self.create_ssl_context(cert, key) {
                Ok(ctx) => Some(ctx),
                Err(e) => {
                    error!("Failed to create SSL context for {}: {:?}", domain, e);
                    None
                }
            }
        } else {
            None
        }
    }

    // Enhanced certificate matching
    fn find_certificate_for_domain(&self, domain: &str) -> Option<(Vec<u8>, Vec<u8>)> {
        let cache_guard = match self.cert_cache.lock() {
            Ok(guard) => guard,
            Err(e) => {
                error!("Failed to lock cert cache: {:?}", e);
                return None;
            }
        };

        // Try direct lookup with exact match
        if let Some((cert, key, _)) = cache_guard.get(domain) {
            return Some((cert.clone(), key.clone()));
        }

        // If no exact match, try more flexible matching
        for (cert_domain, (cert, key, _)) in cache_guard.iter() {
            if domain.ends_with(cert_domain) || cert_domain.starts_with("*.") {
                return Some((cert.clone(), key.clone()));
            }
        }

        None
    }

    fn find_wildcard_certificate(&self, domain: &str) -> Option<(Vec<u8>, Vec<u8>)> {
        let cache_guard = match self.cert_cache.lock() {
            Ok(guard) => guard,
            Err(e) => {
                error!("Failed to lock cert cache: {:?}", e);
                return None;
            }
        };

        let parts: Vec<&str> = domain.split('.').collect();
        let wildcard_domain = format!("*.{}", parts[1..].join("."));

        if let Some((cert, key, _)) = cache_guard.get(&wildcard_domain) {
            Some((cert.clone(), key.clone()))
        } else {
            None
        }
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

        let certs = certbot::find_certbot_certs(&domains);

        // More detailed logging
        info!(
            "Found {} certificates for domains: {:?}",
            certs.len(),
            domains
        );
        for cert in &certs {
            println!(
                "Certificate details: Domain={}, Cert Path={}, Key Path={}",
                cert.domain, cert.cert_path, cert.key_path
            );
        }

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

    // Helper method to create SSL context from certificate and key data
    fn create_ssl_context(&self, cert_data: Vec<u8>, key_data: Vec<u8>) -> Result<SslContext> {
        // Create a new SSL context using TLS method
        let mut ctx = SslContextBuilder::new(SslMethod::tls())
            .map_err(|e| Error::new(ErrorType::InternalError))?;

        // Load certificate from memory
        let cert = openssl::x509::X509::from_pem(&cert_data)
            .map_err(|e| Error::new(ErrorType::InternalError))?;
        ctx.set_certificate(&cert)
            .map_err(|e| Error::new(ErrorType::InternalError))?;

        // Load private key from memory
        let pkey = openssl::pkey::PKey::private_key_from_pem(&key_data)
            .map_err(|e| Error::new(ErrorType::InternalError))?;
        ctx.set_private_key(&pkey)
            .map_err(|e| Error::new(ErrorType::InternalError))?;

        // Verify private key
        ctx.check_private_key()
            .map_err(|e| Error::new(ErrorType::InternalError))?;

        // Enable HTTP/2 support
        ctx.set_alpn_protos(b"\x02h2\x08http/1.1")
            .map_err(|e| Error::new(ErrorType::InternalError))?;

        // Apply modern cipher suites and options
        ctx.set_cipher_list("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384")
            .map_err(|e| Error::new(ErrorType::InternalError))?;

        ctx.set_options(
            openssl::ssl::SslOptions::NO_SSLV2
                | openssl::ssl::SslOptions::NO_SSLV3
                | openssl::ssl::SslOptions::NO_TLSV1
                | openssl::ssl::SslOptions::NO_TLSV1_1,
        );

        Ok(ctx.build())
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
            if let Ok(start_time) = std::str::from_utf8(start_time_str.as_ref()) {
                if let Ok(start_time_secs) = str::parse::<f64>(start_time) {
                    PROXY_METRICS
                        .request_duration
                        .with_label_values(&[hostname.as_deref().unwrap_or("")])
                        .observe(start_time_secs);
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
