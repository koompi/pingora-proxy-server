// src/proxy/manager.rs
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use pingora::{Result, http, prelude::HttpPeer};
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};

use crate::cert::issuer::{CertificateIssuer, CertificateRequest, CertificateStatus};
use crate::config::file_manager::{create_mappings_from_store, update_config};

/// Manager Proxy for configuration endpoints
#[derive(Clone)]
pub struct ManagerProxy {
    pub servers: Arc<Mutex<HashMap<String, String>>>,
}

impl ManagerProxy {
    // Helper methods for responding to requests
    async fn respond_with_json(
        &self,
        session: &mut Session,
        status: http::StatusCode,
        json: &str,
    ) -> Result<bool> {
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

    async fn respond_with_error(
        &self,
        session: &mut Session,
        status: http::StatusCode,
        message: &str,
    ) -> Result<bool> {
        let error_json = format!("{{\"status\":\"error\",\"error\":\"{}\"}}", message);
        self.respond_with_json(session, status, &error_json).await
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
                // Read the request body chunks directly
                let mut body = Vec::new();
                loop {
                    match session.downstream_session.read_request_body().await {
                        Ok(Some(chunk)) => {
                            body.extend_from_slice(&chunk);
                        }
                        Ok(None) => {
                            // End of body
                            break;
                        }
                        Err(e) => {
                            return self
                                .respond_with_error(
                                    session,
                                    http::StatusCode::BAD_REQUEST,
                                    &format!("Failed to read request body: {}", e),
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
                            .respond_with_error(
                                session,
                                http::StatusCode::BAD_REQUEST,
                                &format!("Invalid request format: {}", e),
                            )
                            .await;
                    }
                };

                // Process the certificate request
                let issuer = match CertificateIssuer::new("certbot/letsencrypt", "certs") {
                    Ok(issuer) => issuer,
                    Err(e) => {
                        return self
                            .respond_with_error(
                                session,
                                http::StatusCode::INTERNAL_SERVER_ERROR,
                                &format!("Certificate issuer initialization failed: {}", e),
                            )
                            .await;
                    }
                };

                println!(
                    "Processing certificate request for domain: {}",
                    request.domain
                );
                let status = issuer.process_request(request).await;

                // Respond with the result
                let response_json = serde_json::to_string(&status).unwrap_or_else(|_| {
                    String::from(
                        "{\"status\":\"error\",\"error\":\"Failed to serialize response\"}",
                    )
                });

                self.respond_with_json(
                    session,
                    if status.error.is_some() {
                        http::StatusCode::BAD_REQUEST
                    } else {
                        http::StatusCode::OK
                    },
                    &response_json,
                )
                .await
            }

            // Check certificate status
            "GET" => {
                if path_segments.len() < 3 {
                    return self
                        .respond_with_error(
                            session,
                            http::StatusCode::BAD_REQUEST,
                            "Domain parameter required",
                        )
                        .await;
                }

                let domain = &path_segments[2];
                let issuer = match CertificateIssuer::new("certbot/letsencrypt", "certs") {
                    Ok(issuer) => issuer,
                    Err(e) => {
                        return self
                            .respond_with_error(
                                session,
                                http::StatusCode::INTERNAL_SERVER_ERROR,
                                &format!("Certificate issuer initialization failed: {}", e),
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

                let response_json = serde_json::to_string(&status).unwrap_or_default();
                self.respond_with_json(session, http::StatusCode::OK, &response_json)
                    .await
            }

            // Method not supported
            _ => {
                self.respond_with_error(
                    session,
                    http::StatusCode::METHOD_NOT_ALLOWED,
                    "Method not allowed for certificates endpoint",
                )
                .await
            }
        }
    }
}

#[async_trait::async_trait]
impl ProxyHttp for ManagerProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        // Process admin commands
        let summary = session.request_summary();
        println!("Request summary: {}", summary);

        let segments = summary.split_whitespace().collect::<Vec<&str>>();
        let method = segments.get(0).map(|s| s.to_string()).unwrap_or_default();
        let pathname = segments.get(1).map(|s| s.to_string()).unwrap_or_default();

        let path_segments: Vec<String> = pathname.split('/').map(|seg| seg.to_string()).collect();
        println!("Request path segments: {:#?}", &path_segments);

        println!("Full request URI: {}", session.req_header().uri);

        if path_segments.len() > 1 && path_segments[1].starts_with("certificates") {
            // Remove any trailing commas from the path segment
            let segment = path_segments[1].trim_end_matches(",");

            // Create a cleaned vector
            let clean_segments: Vec<String> = path_segments
                .iter()
                .map(|s| s.trim_end_matches(",").to_string())
                .collect();

            return self
                .handle_certificate_request(session, &method, &clean_segments)
                .await;
        }

        // Handle regular route management requests
        let mut response_status = 200;
        let mut response_body = String::from("{\"status\":\"success\"}");

        // Handle PUT requests (update existing mapping)
        if method == "PUT" && path_segments.len() > 2 {
            let from = path_segments.get(1).unwrap_or(&String::new()).clone();

            // Clean the destination address by removing trailing commas or whitespace
            let to = path_segments
                .get(2)
                .unwrap_or(&String::new())
                .clone()
                .trim_end_matches(|c| c == ',' || c == ' ' || c == ';')
                .to_string();

            println!("Processing PUT request: mapping {} -> {}", from, &to);

            if !from.is_empty() && !to.is_empty() {
                // Use a block to limit the mutex lock scope
                {
                    match self.servers.lock() {
                        Ok(mut servers) => {
                            servers.insert(from.clone(), to.clone());

                            let updates = create_mappings_from_store(&servers);
                            update_config(updates);

                            println!("Updated mapping: {} -> {}", from, &to);
                        }
                        Err(e) => {
                            println!("Error locking servers mutex: {}", e);
                            response_status = 500;
                            response_body = format!(
                                "{{\"status\":\"error\",\"message\":\"Internal server error: {}\"}}",
                                "Failed to acquire lock on server configuration"
                            );
                        }
                    }
                }
            } else {
                response_status = 400;
                response_body = String::from(
                    "{\"status\":\"error\",\"message\":\"Invalid domain or backend address\"}",
                );
            }
        } else if method == "POST" && path_segments.len() > 2 {
            let from = path_segments.get(1).unwrap_or(&String::new()).clone();
            
            let to = path_segments
                .get(2)
                .unwrap_or(&String::new())
                .clone()
                .trim_end_matches(|c| c == ',' || c == ' ' || c == ';')
                .to_string();

            println!("Processing POST request: mapping {} -> {}", from, &to);

            if !from.is_empty() && !to.is_empty() {
                // Use a block to limit the mutex lock scope
                {
                    match self.servers.lock() {
                        Ok(mut servers) => {
                            servers.insert(from.clone(), to.clone());

                            let updates = create_mappings_from_store(&servers);
                            update_config(updates);

                            println!("Added mapping: {} -> {}", from, &to);
                        }
                        Err(e) => {
                            println!("Error locking servers mutex: {}", e);
                            response_status = 500;
                            response_body = format!(
                                "{{\"status\":\"error\",\"message\":\"Internal server error: {}\"}}",
                                "Failed to acquire lock on server configuration"
                            );
                        }
                    }
                }
            } else {
                response_status = 400;
                response_body = String::from(
                    "{\"status\":\"error\",\"message\":\"Invalid domain or backend address\"}",
                );
            }
        }
        // Handle DELETE requests (remove mapping)
        else if method == "DELETE" && path_segments.len() > 1 {
            let from = path_segments.get(1).unwrap_or(&String::new()).clone();

            println!("Processing DELETE request for: {}", from);

            if !from.is_empty() {
                // Use a block to limit the mutex lock scope
                {
                    match self.servers.lock() {
                        Ok(mut servers) => {
                            servers.remove(&from);

                            let updates = create_mappings_from_store(&servers);
                            update_config(updates);

                            println!("Removed mapping for: {}", from);
                        }
                        Err(e) => {
                            println!("Error locking servers mutex: {}", e);
                            response_status = 500;
                            response_body = format!(
                                "{{\"status\":\"error\",\"message\":\"Internal server error: {}\"}}",
                                "Failed to acquire lock on server configuration"
                            );
                        }
                    }
                }
            } else {
                response_status = 400;
                response_body =
                    String::from("{\"status\":\"error\",\"message\":\"Invalid domain\"}");
            }
        }
        // Handle GET request (list all mappings)
        else if method == "GET" {
            println!("Processing GET request to list mappings");

            match self.servers.lock() {
                Ok(servers) => {
                    let mut mappings_json = Vec::new();

                    for (domain, backend) in servers.iter() {
                        mappings_json.push(format!(
                            "{{\"from\":\"{}\",\"to\":\"{}\"}}",
                            domain, backend
                        ));
                    }

                    response_body = format!(
                        "{{\"status\":\"success\",\"mappings\":[{}]}}",
                        mappings_json.join(",")
                    );
                }
                Err(e) => {
                    println!("Error locking servers mutex: {}", e);
                    response_status = 500;
                    response_body = format!(
                        "{{\"status\":\"error\",\"message\":\"Internal server error: {}\"}}",
                        "Failed to acquire lock on server configuration"
                    );
                }
            }
        } else {
            response_status = 404;
            response_body = String::from("{\"status\":\"error\",\"message\":\"Not found\"}");
        }

        // Create response header with status code
        let mut resp = pingora_http::ResponseHeader::build(
            http::StatusCode::from_u16(response_status).unwrap_or(http::StatusCode::OK),
            None,
        )?;

        // Add content-type header to the response
        resp.insert_header("content-type", "application/json")?;

        // Add Connection: close header to force the connection to close after response
        resp.insert_header("connection", "close")?;

        // Write the response header - passing true for end_of_stream if there's no body
        let body_bytes = response_body.into_bytes();
        session
            .write_response_header(Box::new(resp), body_bytes.is_empty())
            .await?;

        // Only write body if there is something to write
        if !body_bytes.is_empty() {
            // Write the response body and mark it as the end of the stream (true)
            session
                .write_response_body(Some(Bytes::copy_from_slice(&body_bytes)), true)
                .await?;
        }

        // Explicitly mark the response as complete
        session.response_written();

        // Disable keepalive
        session.set_keepalive(None);

        // Log completion
        println!("Response complete, connection will be closed");

        // Return true to indicate we've handled the request and no proxying is needed
        Ok(true)
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
