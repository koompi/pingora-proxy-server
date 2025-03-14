// src/proxy/manager.rs
/*
This file defines a "ManagerProxy" for a web service that manages domain routing.

What it does:
- Creates, updates, and deletes mappings between domains and backend servers
- Handles certificate requests for domains
- Serves as an admin interface through HTTP endpoints

Main features:
- GET: Lists all domain mappings
- POST/PUT: Adds or updates where a domain points to
- DELETE: Removes a domain mapping
- Certificate management: Request and check status of SSL certificates

It's part of a reverse proxy system that routes traffic based on domain names,
allowing you to change where domains point without restarting the server.
*/
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use pingora::{Result, http, prelude::HttpPeer};
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};
use serde::{Deserialize, Serialize};

use crate::cert::issuer::{CertificateIssuer, CertificateRequest, CertificateStatus};
use crate::config::file_manager::{create_mappings_from_store, update_config};

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
}

// Domain mapping structure
#[derive(Serialize)]
struct DomainMapping {
    from: String,
    to: String,
}

/// Manager Proxy for configuration endpoints
#[derive(Clone)]
pub struct ManagerProxy {
    pub servers: Arc<Mutex<HashMap<String, String>>>,
}

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
        }
    }

    // Helper to create error response
    fn error_response(message: &str) -> ApiResponse {
        ApiResponse {
            status: "error".to_string(),
            error: Some(message.to_string()),
            message: None,
            mappings: None,
        }
    }

    // Extract clean domain and backend from path segments
    fn extract_domain_and_backend(&self, path_segments: &[String]) -> (String, String) {
        let from = path_segments.get(1).unwrap_or(&String::new()).clone();
        
        let to = path_segments
            .get(2)
            .unwrap_or(&String::new())
            .clone()
            .trim_end_matches(|c| c == ',' || c == ' ' || c == ';')
            .to_string();
        
        (from, to)
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
                let issuer = match CertificateIssuer::new("certbot/letsencrypt", "certs") {
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

                println!(
                    "Processing certificate request for domain: {}",
                    request.domain
                );
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
                let issuer = match CertificateIssuer::new("certbot/letsencrypt", "certs") {
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

                let status = match issuer.check_certificate(domain) {
                    Some(status) => status,
                    None => CertificateStatus {
                        domain: domain.clone(),
                        status: "not_found".to_string(),
                        cert_path: None,
                        key_path: None,
                        expiry: None,
                        error: None,
                    },
                };

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
        let (from, to) = self.extract_domain_and_backend(path_segments);

        println!("Processing {} request: mapping {} -> {}", method, from, &to);

        if from.is_empty() || to.is_empty() {
            return (
                http::StatusCode::BAD_REQUEST,
                Self::error_response("Invalid domain or backend address"),
            );
        }

        match self.servers.lock() {
            Ok(mut servers) => {
                servers.insert(from.clone(), to.clone());
                let updates = create_mappings_from_store(&servers);

                match update_config(updates) {
                    Ok(_) => {
                        println!(
                            "{} mapping: {} -> {}",
                            if method == "POST" { "Added" } else { "Updated" },
                            from,
                            &to
                        );
                        (http::StatusCode::OK, Self::success_response())
                    }
                    Err(e) => {
                        println!("Error updating config: {}", e);
                        (
                            http::StatusCode::INTERNAL_SERVER_ERROR,
                            Self::error_response(&format!(
                                "Failed to persist configuration: {}",
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
                        // Verify removal
                        if let Ok(content) = std::fs::read_to_string("config.json") {
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
                    .map(|(domain, backend)| DomainMapping {
                        from: domain.clone(),
                        to: backend.clone(),
                    })
                    .collect();

                (
                    http::StatusCode::OK,
                    ApiResponse {
                        status: "success".to_string(),
                        error: None,
                        message: None,
                        mappings: Some(mappings),
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
        let path_segments: Vec<String> = pathname.split('/').map(|seg| seg.to_string()).collect();

        // Handle certificate endpoints
        if path_segments.len() > 1 && path_segments[1].starts_with("certificates") {
            let clean_segments: Vec<String> = path_segments
                .iter()
                .map(|s| s.trim_end_matches(",").to_string())
                .collect();

            return self
                .handle_certificate_request(session, &method, &clean_segments)
                .await;
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
