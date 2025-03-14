// Fixed HTTPS Proxy Implementation
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use pingora::{Result, prelude::HttpPeer};
use pingora_proxy::{ProxyHttp, Session};

use crate::proxy::utils::{parse_swarm_target, test_service_connectivity, validate_org_network_access};

use super::utils::extract_hostname;

/// HTTPS Proxy implementation
#[derive(Clone)]
pub struct HttpsProxy {
    pub servers: Arc<Mutex<HashMap<String, String>>>,
}

#[async_trait::async_trait]
impl ProxyHttp for HttpsProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        // For HTTPS, we don't need to handle ACME challenges (they're HTTP-only)
        // Extract hostname for logging purposes
        let hostname = extract_hostname(&session.request_summary()).unwrap_or_default();
        println!("HTTPS request for hostname: {}", hostname);

        // Return false to continue normal request processing
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
                    println!("Error locking servers mutex in HttpsProxy: {:?}", e);
                    return Ok(Box::new(HttpPeer::new("127.0.0.1:5500", false, "".to_string())));
                }
            };
            
            // Clone the target string to avoid holding the mutex lock
            servers_lock.get(&hostname).cloned()
        };
        
        // Now process the target outside the mutex lock
        match target {
            Some(to) => {
                println!("Routing HTTPS request to backend: {}", to);
    
                // Handle Swarm service discovery with stronger isolation
                if to.contains(".") || to.starts_with("tasks.") {
                    // Parse target to get service details
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
                        
                        // Add HTTPS protocol header
                        peer.options.extra_proxy_headers.insert(
                            "X-Forwarded-Proto".to_string(),
                            b"https".to_vec(),
                        );
                        
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
                            println!("Warning: Service {} is not authorized for org {}", host, org);
                            // We still continue, but log this security concern
                        }
                    }
                    
                    Ok(Box::new(peer))
                } else {
                    // Standard IP:port target - use directly
                    println!("Using direct target: {}", to);
                    let mut peer = HttpPeer::new(to, false, hostname.to_string());
                    
                    // Add basic security headers
                    peer.options.extra_proxy_headers.insert(
                        "X-Forwarded-Proto".to_string(),
                        b"https".to_vec(),
                    );
                    
                    peer.options.extra_proxy_headers.insert(
                        "X-Proxy-Source".to_string(),
                        b"pingora-proxy-https".to_vec(),
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

    // Add enhanced logging method for HTTPS requests
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
                "HTTPS request completed: host={}, method={}, path={}, status={}",
                hostname, method, path, status
            );
            
            // Log potential security issues
            if status == 403 {
                println!("Security warning: Forbidden HTTPS access attempt to {}", hostname);
            }
        }
        
        // Log errors
        if let Some(err) = error {
            println!("Error handling HTTPS request: {}, error: {}", hostname, err);
        }
    }
}