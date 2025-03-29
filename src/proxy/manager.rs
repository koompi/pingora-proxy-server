// src/proxy/manager.rs (Fixed for MappingOrigin support)
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use bytes::Bytes;
use pingora::{http, prelude::HttpPeer, Result};
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};
use serde::{Deserialize, Serialize};

use crate::config::model::{ConfigStore, MappingOrigin, ServerMapping};
use crate::metrics::PROXY_METRICS;
use crate::proxy::https::HttpsProxy;
use crate::{
    cert::certbot,
    config::file_manager::{create_mappings_from_store, update_config},
};
use crate::{
    cert::issuer::{CertificateIssuer, CertificateRequest, CertificateStatus},
    config::model::Configuration,
};

// Response structure for API endpoints
#[derive(Serialize)]
struct ApiResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mappings: Option<Vec<DomainMapping>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    health: Option<HealthStatus>,
}

// Domain mapping structure
#[derive(Serialize)]
struct DomainMapping {
    from: String,
    to: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin: Option<String>,
}

// Health status structure
#[derive(Serialize)]
struct HealthStatus {
    status: String,
    timestamp: String,
    components: HashMap<String, ComponentHealth>,
}

// Component health structure
#[derive(Serialize)]
struct ComponentHealth {
    status: String,
    details: HashMap<String, String>,
}

/// Manager Proxy for configuration endpoints
#[derive(Clone)]
pub struct ManagerProxy {
    pub servers: Arc<Mutex<ConfigStore>>,
    pub https_proxy: Option<HttpsProxy>,
}

/// Manager for handling proxy configuration and certificate operations.
///
/// This implementation provides methods for:
/// - Managing domain-to-backend mappings (add, update, delete, list)
/// - Handling SSL certificate requests and status checks
/// - Processing JSON responses for API endpoints
///
/// # Methods
///
/// ## Certificate Management
/// - `handle_certificate_request`: Processes certificate-related operations (POST/GET)
///   - POST: Request new certificates (including wildcard certificates)
///   - GET: Check certificate status for a domain
///
/// ## Domain Mapping Management
/// - `handle_add_update_mapping`: Adds or updates domain-to-backend mappings
/// - `handle_delete_mapping`: Removes domain mappings
/// - `handle_list_mappings`: Lists all current domain mappings
///
/// ## Helper Methods
/// - `send_json_response`: Formats and sends JSON responses
/// - `success_response`: Creates a success response object
/// - `error_response`: Creates an error response object
/// - `extract_domain_and_backend`: Parses domain and backend from URL path segments
///
/// # Features
/// - Supports both regular and wildcard SSL certificates
/// - Cloudflare DNS provider integration for wildcard certificates
/// - Persistent configuration storage
/// - Thread-safe server configuration management
/// - Support for manual and SwarmDiscovery-based mappings
///
/// # Note
/// Configuration changes are persisted to disk and managed through thread-safe
/// concurrent access using mutex locks.
impl ManagerProxy {
    // Helper method to send JSON responses
    async fn send_json_response(
        &self,
        session: &mut Session,
        status: http::StatusCode,
        response: ApiResponse,
    ) -> Result<bool> {
        let json = serde_json::to_string(&response).unwrap_or_default();

        let mut resp = ResponseHeader::build(status, None)?;
        resp.insert_header("content-type", "application/json")?;
        resp.insert_header("connection", "close")?;

        let body_bytes = json.as_bytes();
        session.write_response_header(Box::new(resp), false).await?;
        session
            .write_response_body(Some(Bytes::copy_from_slice(body_bytes)), true)
            .await?;

        session.response_written();
        session.set_keepalive(None);

        Ok(true)
    }

    // Helper to create success response
    fn success_response() -> ApiResponse {
        ApiResponse {
            status: "success".to_string(),
            error: None,
            message: None,
            mappings: None,
            health: None,
        }
    }

    // Helper to create error response
    fn error_response(message: &str) -> ApiResponse {
        ApiResponse {
            status: "error".to_string(),
            error: Some(message.to_string()),
            message: None,
            mappings: None,
            health: None,
        }
    }

    // Extract clean domain and backend from path segments
    fn extract_domain_and_backend(&self, path_segments: &[String]) -> (String, String) {
        // For paths like /test2003.koompi.cloud/192.168.1.109:3002
        // path_segments[0] will be "test2003.koompi.cloud"
        // path_segments[1] will be "192.168.1.109:3002"

        let from = path_segments.get(0).unwrap_or(&String::new()).clone();
        let to = path_segments
            .get(1)
            .unwrap_or(&String::new())
            .clone()
            .trim_end_matches(|c| c == ',' || c == ' ' || c == ';')
            .to_string();

        (from, to)
    }

    async fn handle_reload_certificates(&self, session: &mut Session) -> Result<bool> {
        println!("Received certificate reload request");

        // Actually reload the certificates using the HttpsProxy method
        if let Some(https_proxy) = &self.https_proxy {
            match https_proxy.reload_certificates().await {
                Ok(_) => println!("Certificates reloaded successfully"),
                Err(e) => println!("Error reloading certificates: {:?}", e),
            }
        }

        // Return success response
        let response = ApiResponse {
            status: "success".to_string(),
            error: None,
            message: Some("Certificate reload triggered".to_string()),
            mappings: None,
            health: None,
        };

        self.send_json_response(session, http::StatusCode::OK, response)
            .await
    }

    async fn handle_submit_certificate_request(&self, session: &mut Session) -> Result<bool> {
        // Read the request body
        let mut body = Vec::new();
        loop {
            match session.downstream_session.read_request_body().await {
                Ok(Some(chunk)) => body.extend_from_slice(&chunk),
                Ok(None) => break,
                Err(e) => {
                    return self
                        .send_json_response(
                            session,
                            http::StatusCode::BAD_REQUEST,
                            Self::error_response(&format!("Failed to read request body: {}", e)),
                        )
                        .await;
                }
            }
        }

        // Parse certificate request
        let request: CertificateRequest = match serde_json::from_slice(&body) {
            Ok(req) => req,
            Err(e) => {
                return self
                    .send_json_response(
                        session,
                        http::StatusCode::BAD_REQUEST,
                        Self::error_response(&format!("Invalid request format: {}", e)),
                    )
                    .await;
            }
        };

        // Create a request file for the external certificate manager
        let request_dir = "/pingora-proxy/cert_requests";
        std::fs::create_dir_all(request_dir).ok();

        let filename = format!(
            "{}/{}_{}.req",
            request_dir,
            request.domain.replace(".", "_"),
            chrono::Utc::now().timestamp()
        );

        let request_content = format!(
            "domain={}\nemail={}\nwildcard={}\n",
            request.domain,
            request.email,
            request.wildcard.unwrap_or(false)
        );

        match std::fs::write(&filename, request_content) {
            Ok(_) => {
                let response = ApiResponse {
                    status: "success".to_string(),
                    error: None,
                    message: Some(format!(
                        "Certificate request for {} submitted",
                        request.domain
                    )),
                    mappings: None,
                    health: None,
                };

                self.send_json_response(session, http::StatusCode::OK, response)
                    .await
            }
            Err(e) => {
                self.send_json_response(
                    session,
                    http::StatusCode::INTERNAL_SERVER_ERROR,
                    Self::error_response(&format!("Failed to submit request: {}", e)),
                )
                .await
            }
        }
    }

    // Handle certificate requests
    async fn handle_certificate_request(
        &self,
        session: &mut Session,
        method: &str,
        path_segments: &[String],
    ) -> Result<bool> {
        match method {
            // Request a new certificate
            "POST" => {
                // Check if this is a certificate reload request
                if path_segments.len() >= 2
                    && path_segments[1] == "admin"
                    && path_segments.len() >= 3
                    && path_segments[2] == "reload_certs"
                {
                    return self.handle_reload_certificates(session).await;
                }

                // Read the request body
                let mut body = Vec::new();
                loop {
                    match session.downstream_session.read_request_body().await {
                        Ok(Some(chunk)) => body.extend_from_slice(&chunk),
                        Ok(None) => break,
                        Err(e) => {
                            return self
                                .send_json_response(
                                    session,
                                    http::StatusCode::BAD_REQUEST,
                                    Self::error_response(&format!(
                                        "Failed to read request body: {}",
                                        e
                                    )),
                                )
                                .await;
                        }
                    }
                }

                // Parse certificate request
                let request: CertificateRequest = match serde_json::from_slice(&body) {
                    Ok(req) => req,
                    Err(e) => {
                        return self
                            .send_json_response(
                                session,
                                http::StatusCode::BAD_REQUEST,
                                Self::error_response(&format!("Invalid request format: {}", e)),
                            )
                            .await;
                    }
                };

                // Process the certificate request
                let issuer = match CertificateIssuer::new("/certbot/letsencrypt", "certs") {
                    Ok(issuer) => issuer,
                    Err(e) => {
                        return self
                            .send_json_response(
                                session,
                                http::StatusCode::INTERNAL_SERVER_ERROR,
                                Self::error_response(&format!(
                                    "Certificate issuer initialization failed: {}",
                                    e
                                )),
                            )
                            .await;
                    }
                };

                // Log wildcard information if applicable
                if request.wildcard.unwrap_or(false) {
                    println!(
                        "Processing WILDCARD certificate request for domain: {}",
                        request.domain
                    );

                    // Check DNS provider for wildcard certificates
                    if request.dns_provider.is_none() {
                        return self
                            .send_json_response(
                                session,
                                http::StatusCode::BAD_REQUEST,
                                Self::error_response(
                                    "Wildcard certificates require a DNS provider",
                                ),
                            )
                            .await;
                    }

                    // Verify we have credentials for the DNS provider
                    if request.dns_credentials.is_none() {
                        return self
                        .send_json_response(
                            session,
                            http::StatusCode::BAD_REQUEST,
                            Self::error_response("DNS provider credentials are required for wildcard certificates"),
                        )
                        .await;
                    }

                    // Currently we only support Cloudflare
                    if request.dns_provider.as_deref() != Some("cloudflare") {
                        return self
                        .send_json_response(
                            session,
                            http::StatusCode::BAD_REQUEST,
                            Self::error_response("Only Cloudflare is supported for wildcard certificates at this time"),
                        )
                        .await;
                    }
                } else {
                    println!(
                        "Processing certificate request for domain: {}",
                        request.domain
                    );
                }

                // Process the request
                let status = issuer.process_request(request).await;

                // Serialize the status directly
                let json = serde_json::to_string(&status).unwrap_or_else(|_| {
                    String::from(
                        "{\"status\":\"error\",\"error\":\"Failed to serialize response\"}",
                    )
                });

                // Send raw JSON for certificate status
                let mut resp = ResponseHeader::build(
                    if status.error.is_some() {
                        http::StatusCode::BAD_REQUEST
                    } else {
                        http::StatusCode::OK
                    },
                    None,
                )?;
                resp.insert_header("content-type", "application/json")?;
                resp.insert_header("connection", "close")?;

                session.write_response_header(Box::new(resp), false).await?;
                session
                    .write_response_body(Some(Bytes::copy_from_slice(json.as_bytes())), true)
                    .await?;

                session.response_written();
                session.set_keepalive(None);

                Ok(true)
            }

            // Check certificate status
            "GET" => {
                if path_segments.len() < 3 {
                    return self
                        .send_json_response(
                            session,
                            http::StatusCode::BAD_REQUEST,
                            Self::error_response("Domain parameter required"),
                        )
                        .await;
                }

                let domain = &path_segments[2];
                let issuer = match CertificateIssuer::new("/certbot/letsencrypt", "certs") {
                    Ok(issuer) => issuer,
                    Err(e) => {
                        return self
                            .send_json_response(
                                session,
                                http::StatusCode::INTERNAL_SERVER_ERROR,
                                Self::error_response(&format!(
                                    "Certificate issuer initialization failed: {}",
                                    e
                                )),
                            )
                            .await;
                    }
                };

                let mut status = match issuer.check_certificate(domain) {
                    Some(status) => status,
                    None => CertificateStatus {
                        domain: domain.clone(),
                        status: "not_found".to_string(),
                        cert_path: None,
                        key_path: None,
                        expiry: None,
                        error: None,
                        is_wildcard: None,
                    },
                };

                // Check if the domain appears to be a wildcard certificate
                // This is a heuristic since we don't store this information
                if status.cert_path.is_some()
                    && (domain.starts_with("*.") || domain.contains("wildcard"))
                {
                    status.is_wildcard = Some(true);
                }

                // Send certificate status
                let json = serde_json::to_string(&status).unwrap_or_default();
                let mut resp = ResponseHeader::build(http::StatusCode::OK, None)?;
                resp.insert_header("content-type", "application/json")?;
                resp.insert_header("connection", "close")?;

                session.write_response_header(Box::new(resp), false).await?;
                session
                    .write_response_body(Some(Bytes::copy_from_slice(json.as_bytes())), true)
                    .await?;

                session.response_written();
                session.set_keepalive(None);

                Ok(true)
            }

            // Method not supported
            _ => {
                self.send_json_response(
                    session,
                    http::StatusCode::METHOD_NOT_ALLOWED,
                    Self::error_response("Method not allowed for certificates endpoint"),
                )
                .await
            }
        }
    }

    // Handle adding or updating domain mapping
    async fn handle_add_update_mapping(
        &self,
        method: &str,
        path_segments: &[String],
    ) -> (http::StatusCode, ApiResponse) {
        // Skip if this is an admin endpoint
        if !path_segments.is_empty() && path_segments[0] == "admin" {
            return (
                http::StatusCode::BAD_REQUEST,
                Self::error_response("Invalid request path"),
            );
        }

        let (from, to) = self.extract_domain_and_backend(path_segments);

        println!("Processing {} request: mapping {} -> {}", method, from, &to);

        if from.is_empty() || to.is_empty() {
            return (
                http::StatusCode::BAD_REQUEST,
                Self::error_response("Invalid domain or backend address"),
            );
        }

        // Validate the backend address format (host:port)
        if !to.contains(':') {
            return (
                http::StatusCode::BAD_REQUEST,
                Self::error_response("Backend address must be in format host:port"),
            );
        }

        match self.servers.lock() {
            Ok(mut servers) => {
                // Mark this mapping as manually added
                servers.insert(from.clone(), (to.clone(), MappingOrigin::Manual));

                // Update config file
                let config_path =
                    std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config.json".to_string());
                let mut current_config = match std::fs::read_to_string(&config_path) {
                    Ok(content) => match serde_json::from_str::<Configuration>(&content) {
                        Ok(cfg) => cfg,
                        Err(_) => Configuration::new(),
                    },
                    Err(_) => Configuration::new(),
                };

                // Check if this domain already exists in the config
                let domain_exists = current_config.servers.iter().position(|s| s.from == from);

                if let Some(index) = domain_exists {
                    // Update existing entry
                    current_config.servers[index].to = to.clone();
                    current_config.servers[index].origin = MappingOrigin::Manual;
                } else {
                    // Add new entry
                    current_config.servers.push(ServerMapping {
                        from: from.clone(),
                        to: to.clone(),
                        origin: MappingOrigin::Manual,
                    });
                }

                // Save updated config
                match serde_json::to_string_pretty(&current_config) {
                    Ok(json) => {
                        if let Err(e) = std::fs::write(&config_path, json) {
                            println!("Error writing config file: {}", e);
                            return (
                                http::StatusCode::INTERNAL_SERVER_ERROR,
                                Self::error_response("Failed to save configuration"),
                            );
                        }
                    }
                    Err(e) => {
                        println!("Error serializing config: {}", e);
                        return (
                            http::StatusCode::INTERNAL_SERVER_ERROR,
                            Self::error_response("Failed to serialize configuration"),
                        );
                    }
                }

                (http::StatusCode::OK, Self::success_response())
            }
            Err(e) => {
                println!("Error locking servers mutex: {}", e);
                (
                    http::StatusCode::INTERNAL_SERVER_ERROR,
                    Self::error_response("Failed to acquire lock on server configuration"),
                )
            }
        }
    }

    // Handle removing domain mapping
    async fn handle_delete_mapping(
        &self,
        path_segments: &[String],
    ) -> (http::StatusCode, ApiResponse) {
        // Get the domain to delete
        if path_segments.len() < 2 {
            return (
                http::StatusCode::BAD_REQUEST,
                Self::error_response("Missing domain parameter"),
            );
        }

        let from =
            path_segments[1].trim_end_matches(|c| c == ',' || c == ' ' || c == ';' || c == '/');

        println!("Processing DELETE request for: {}", from);

        if from.is_empty() {
            return (
                http::StatusCode::BAD_REQUEST,
                Self::error_response("Invalid domain"),
            );
        }

        // Add domain to recently deleted list to prevent auto-readding by discovery
        let recently_deleted_file = PathBuf::from("/pingora-proxy/locks/recently_deleted.json");

        // Ensure the directory exists
        if let Some(parent) = recently_deleted_file.parent() {
            if !parent.exists() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    println!("Error creating recently deleted directory: {}", e);
                }
            }
        }

        // Current timestamp for expiration tracking
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Load existing recently deleted domains with timestamps
        let mut timestamp_domains: Vec<(u64, String)> = if recently_deleted_file.exists() {
            match std::fs::read_to_string(&recently_deleted_file) {
                Ok(content) => match serde_json::from_str(&content) {
                    Ok(domains) => domains,
                    Err(e) => {
                        println!("Error parsing recently deleted domains: {}", e);
                        Vec::new()
                    }
                },
                Err(e) => {
                    println!("Error reading recently deleted file: {}", e);
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        // Filter out entries older than 5 minutes (300 seconds)
        timestamp_domains.retain(|(timestamp, _)| now - *timestamp < 300);

        // Add the current domain with timestamp if not already present
        if !timestamp_domains.iter().any(|(_, domain)| domain == from) {
            timestamp_domains.push((now, from.to_string()));
        }

        // Write back the updated list
        if let Ok(json) = serde_json::to_string(&timestamp_domains) {
            if let Err(e) = std::fs::write(&recently_deleted_file, json) {
                println!("Error writing recently deleted domains: {}", e);
            } else {
                println!("Added {} to recently deleted domains list", from);
            }
        }

        // Process the actual deletion
        match self.servers.lock() {
            Ok(mut servers) => {
                // Check if domain exists
                if !servers.contains_key(from) {
                    return (
                        http::StatusCode::NOT_FOUND,
                        Self::error_response(&format!("Domain {} not found", from)),
                    );
                }

                // Remove from in-memory store
                servers.remove(from);
                println!("Removed mapping for: {} from in-memory store", from);

                // Update config file
                let updates = create_mappings_from_store(&servers);
                match update_config(updates) {
                    Ok(_) => {
                        // Verify removal using the CONFIG_PATH environment variable
                        let config_path = std::env::var("CONFIG_PATH")
                            .unwrap_or_else(|_| "config.json".to_string());
                        if let Ok(content) = std::fs::read_to_string(&config_path) {
                            if let Ok(config) = serde_json::from_str::<
                                crate::config::model::Configuration,
                            >(&content)
                            {
                                if config.servers.iter().any(|m| m.from == from) {
                                    return (
                                        http::StatusCode::INTERNAL_SERVER_ERROR,
                                        Self::error_response(
                                            "Domain was removed from memory but still exists in config file",
                                        ),
                                    );
                                }
                            }
                        }

                        (http::StatusCode::OK, Self::success_response())
                    }
                    Err(e) => {
                        println!("Error updating config file: {}", e);
                        (
                            http::StatusCode::INTERNAL_SERVER_ERROR,
                            Self::error_response(&format!(
                                "Failed to persist configuration change: {}",
                                e
                            )),
                        )
                    }
                }
            }
            Err(e) => {
                println!("Error locking servers mutex: {}", e);
                (
                    http::StatusCode::INTERNAL_SERVER_ERROR,
                    Self::error_response("Failed to acquire lock on server configuration"),
                )
            }
        }
    }

    // Handle listing all mappings
    async fn handle_list_mappings(&self) -> (http::StatusCode, ApiResponse) {
        match self.servers.lock() {
            Ok(servers) => {
                let mappings = servers
                    .iter()
                    .map(|(domain, (backend, origin))| {
                        let origin_str = match origin {
                            MappingOrigin::Manual => "Manual",
                            MappingOrigin::SwarmDiscovery => "SwarmDiscovery",
                        };

                        DomainMapping {
                            from: domain.clone(),
                            to: backend.clone(),
                            origin: Some(origin_str.to_string()),
                        }
                    })
                    .collect();

                (
                    http::StatusCode::OK,
                    ApiResponse {
                        status: "success".to_string(),
                        error: None,
                        message: None,
                        mappings: Some(mappings),
                        health: None,
                    },
                )
            }
            Err(e) => {
                println!("Error locking servers mutex: {}", e);
                (
                    http::StatusCode::INTERNAL_SERVER_ERROR,
                    Self::error_response("Failed to acquire lock on server configuration"),
                )
            }
        }
    }

    async fn handle_health_check(&self, session: &mut Session) -> Result<bool> {
        let mut health_status = HealthStatus {
            status: "healthy".to_string(),
            components: HashMap::new(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        // Check certificate status
        health_status.components.insert(
            "certificates".to_string(),
            self.check_certificate_health().await,
        );

        // Check backend connectivity
        health_status
            .components
            .insert("backends".to_string(), self.check_backend_health().await);

        // Check configuration state
        health_status.components.insert(
            "configuration".to_string(),
            self.check_config_health().await,
        );

        // Overall status determination
        let is_healthy = health_status
            .components
            .values()
            .all(|status| status.status == "healthy");

        let response = ApiResponse {
            status: if is_healthy { "healthy" } else { "unhealthy" }.to_string(),
            error: None,
            message: Some("Health check completed".to_string()),
            health: Some(health_status),
            mappings: None,
        };

        self.send_json_response(
            session,
            if is_healthy {
                http::StatusCode::OK
            } else {
                http::StatusCode::SERVICE_UNAVAILABLE
            },
            response,
        )
        .await
    }

    async fn check_certificate_health(&self) -> ComponentHealth {
        let mut health = ComponentHealth {
            status: "healthy".to_string(),
            details: HashMap::new(),
        };

        if let Ok(store) = self.servers.lock() {
            for domain in store.keys() {
                let cert_status = certbot::check_certificate_status(domain);
                health.details.insert(
                    domain.clone(),
                    match cert_status {
                        Ok(status) => status.to_string(),
                        Err(e) => {
                            health.status = "unhealthy".to_string();
                            e.to_string()
                        }
                    },
                );
            }
        }

        health
    }

    async fn check_backend_health(&self) -> ComponentHealth {
        let mut health = ComponentHealth {
            status: "healthy".to_string(),
            details: HashMap::new(),
        };

        if let Ok(store) = self.servers.lock() {
            for (domain, (backend, _origin)) in store.iter() {
                let status = self.check_backend_connectivity(backend).await;
                match status {
                    Ok(_) => {
                        health
                            .details
                            .insert(format!("{}->{}", domain, backend), "connected".to_string());
                    }
                    Err(e) => {
                        health.status = "unhealthy".to_string();
                        health
                            .details
                            .insert(format!("{}->{}", domain, backend), e.to_string());
                        PROXY_METRICS
                            .backend_failures
                            .with_label_values(&[backend, "health_check_failed"])
                            .inc();
                    }
                }
            }
        }

        health
    }

    async fn check_config_health(&self) -> ComponentHealth {
        ComponentHealth {
            status: if let Ok(_) = self.servers.lock() {
                "healthy".to_string()
            } else {
                "unhealthy".to_string()
            },
            details: HashMap::new(),
        }
    }

    async fn check_backend_connectivity(&self, backend: &str) -> Result<(), String> {
        let (service_name, port, _) = crate::proxy::utils::parse_swarm_target(backend);
        if crate::proxy::utils::test_service_connectivity(&service_name, port).await {
            Ok(())
        } else {
            Err(format!("Failed to connect to backend: {}", backend))
        }
    }
}

#[async_trait::async_trait]
impl ProxyHttp for ManagerProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        // Get request details
        let summary = session.request_summary();
        println!("Request summary: {}", summary);

        // Parse request method and path
        let segments = summary.split_whitespace().collect::<Vec<&str>>();
        let method = segments.get(0).map(|s| s.to_string()).unwrap_or_default();
        let pathname = segments.get(1).map(|s| s.to_string()).unwrap_or_default();

        // Split path into segments
        let path_segments: Vec<String> = pathname
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        // Check for certificate reload endpoint first
        if path_segments.len() >= 2
            && path_segments[0] == "admin"
            && path_segments[1] == "reload_certs"
        {
            return self.handle_reload_certificates(session).await;
        }

        // Handle standard route management endpoints
        let (status, response) = match method.as_str() {
            "PUT" | "POST" => {
                // Add or update domain mapping
                self.handle_add_update_mapping(&method, &path_segments)
                    .await
            }
            "DELETE" => {
                // Remove domain mapping
                self.handle_delete_mapping(&path_segments).await
            }
            "GET" => {
                // List all mappings
                self.handle_list_mappings().await
            }
            _ => {
                // Method not supported
                (
                    http::StatusCode::METHOD_NOT_ALLOWED,
                    Self::error_response("Method not allowed"),
                )
            }
        };

        // Send response
        self.send_json_response(session, status, response).await
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // This code will not execute because request_filter returns true
        // But we still need to provide an implementation
        let res = HttpPeer::new("127.0.0.1:80", false, "".to_string());
        Ok(Box::new(res))
    }
}
