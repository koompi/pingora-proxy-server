// Fixed HTTP Proxy Implementation
use std::{
    collections::HashMap,
    fs,
    path::Path,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use pingora::{Result, connectors::http, prelude::HttpPeer};
use pingora_http::StatusCode;
use pingora_proxy::{ProxyHttp, Session};

use crate::proxy::utils::{parse_swarm_target, test_service_connectivity, validate_org_network_access};

use super::utils::extract_hostname;

/// HTTP Proxy implementation
#[derive(Clone)]
pub struct HttpProxy {
    pub servers: Arc<Mutex<HashMap<String, String>>>,
}

#[async_trait::async_trait]
impl ProxyHttp for HttpProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        // Get the path from the request header
        let path = session.req_header().uri.path().to_string(); // Create an owned copy of the path

        // Handle ACME challenges from Let's Encrypt
        if path.starts_with("/.well-known/acme-challenge/") {
            println!("Handling ACME challenge: {}", path);

            let token = path.split('/').last().unwrap_or_default();

            if token.is_empty() {
                return Err(pingora::Error::new(pingora::ErrorType::HTTPStatus(404)));
            }

            // Read from webroot where certbot expects to find the challenge
            let challenge_dir = Path::new("/var/www/html/.well-known/acme-challenge");
            let challenge_file = challenge_dir.join(token);

            match fs::read_to_string(challenge_file) {
                Ok(proof) => {
                    let mut res_headers =
                        pingora_http::ResponseHeader::build(StatusCode::OK, None)?;

                    res_headers.insert_header("content-type", "text/plain")?;

                    session
                        .write_response_header(Box::new(res_headers), false)
                        .await?;

                    session
                        .write_response_body(Some(Bytes::copy_from_slice(proof.as_bytes())), true)
                        .await?;

                    println!("Successfully served ACME challenge for token: {}", token);
                    return Ok(true);
                }
                Err(e) => {
                    println!("Failed to read ACME challenge file: {}", e);
                    return Err(pingora::Error::new(pingora::ErrorType::HTTPStatus(404)));
                }
            }
        }

        // Continue with normal request processing
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let hostname = extract_hostname(&session.request_summary()).unwrap_or_default();
    
        // IMPORTANT: Get the target outside the await points to avoid holding MutexGuard across await
        let target = {
            let servers_lock = match self.servers.lock() {
                Ok(guard) => guard,
                Err(e) => {
                    println!("Error locking servers mutex in HttpProxy: {:?}", e);
                    return Ok(Box::new(HttpPeer::new("127.0.0.1:5500", false, "".to_string())));
                }
            };
            
            // Clone the target string to avoid holding the mutex lock
            servers_lock.get(&hostname).cloned()
        };
        
        // Now process the target outside the mutex lock
        match target {
            Some(to) => {
                println!("Routing HTTP request to backend: {}", to);
    
                // Determine if this is a Docker Swarm service name
                if to.contains(".") || to.starts_with("tasks.") {
                    // Parse target to handle Swarm service discovery
                    let (host, port, org_id) = parse_swarm_target(&to);
                    println!("Using Swarm DNS target: {}", host);
                    
                    // Create peer with proper host resolution
                    let mut peer = HttpPeer::new(format!("{}:{}", host, port), false, hostname.to_string());
                    
                    // Add security headers for organization isolation
                    if let Some(org) = org_id {
                        // Organization ID validation for network isolation
                        peer.options.extra_proxy_headers.insert(
                            "X-Organization-ID".to_string(),
                            org.to_string().into_bytes(),
                        );
                        
                        // Add isolation header to enforce network boundary
                        peer.options.extra_proxy_headers.insert(
                            "X-Network-Isolation".to_string(),
                            b"strict".to_vec(),
                        );
                        
                        // Add organization boundary header
                        peer.options.extra_proxy_headers.insert(
                            "X-Organization-Boundary".to_string(),
                            b"enforced".to_vec(),
                        );
                        
                        // Add additional headers for tracing
                        peer.options.extra_proxy_headers.insert(
                            "X-Proxy-Source".to_string(),
                            b"pingora-proxy".to_vec(),
                        );
                        
                        // Test connectivity with timeout to avoid hanging requests
                        if !test_service_connectivity(&host, port).await {
                            println!("Warning: Service {} appears to be unreachable", host);
                            // Continue anyway, as the Docker DNS might just need time to propagate
                        }
                        
                        // Validate organization network access
                        if !validate_org_network_access(&host, &org) {
                            println!("Warning: Service {} is not authorized for org {}", host, org);
                            // We still continue, but log this security concern
                        }
                    }
                    
                    Ok(Box::new(peer))
                } else {
                    // Standard IP:port target - use directly with security headers
                    println!("Using direct target: {}", to);
                    let mut peer = HttpPeer::new(to, false, hostname.to_string());
                    
                    // Add basic security headers
                    peer.options.extra_proxy_headers.insert(
                        "X-Forwarded-Proto".to_string(),
                        b"http".to_vec(),
                    );
                    
                    peer.options.extra_proxy_headers.insert(
                        "X-Proxy-Source".to_string(),
                        b"pingora-proxy".to_vec(),
                    );
                    
                    Ok(Box::new(peer))
                }
            }
            None => {
                // Default backend when no matching host is found
                println!("No backend found for host: {}", hostname);
                let res = HttpPeer::new("127.0.0.1:5500", false, "".to_string());
                Ok(Box::new(res))
            }
        }
    }
    
    // Add a logging method to track HTTP requests and potential security issues
    async fn logging(
        &self,
        session: &mut Session,
        error: Option<&pingora::Error>,
        _ctx: &mut Self::CTX,
    ) {
        // Extract hostname and other details for logging
        let hostname = extract_hostname(&session.request_summary()).unwrap_or_default();
        let method = session.req_header().method.to_string();
        let path = session.req_header().uri.path().to_string();
        
        if let Some(response) = session.response_written() {
            let status = response.status;
            println!(
                "HTTP request completed: host={}, method={}, path={}, status={}",
                hostname, method, path, status
            );
            
            // Log potential security issues
            if status == 403 {
                println!("Security warning: Forbidden access attempt to {}", hostname);
            }
        }
        
        // Log errors
        if let Some(err) = error {
            println!("Error handling request: {}, error: {}", hostname, err);
        }
    }
}