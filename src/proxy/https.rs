use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use pingora::{Result, prelude::HttpPeer};
use pingora_proxy::{ProxyHttp, Session};

use crate::proxy::utils::parse_swarm_target;

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
        // This is just a placeholder for any HTTPS-specific request filtering

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
    
        match self.servers.lock() {
            Ok(servers) => match servers.get(&hostname) {
                Some(to) => {
                    println!("Routing HTTP request to backend: {}", to);
    
                    // Determine if this is an IP address or a Swarm DNS name
                    if to.contains(".") && to.contains(":") && 
                       !to.chars().nth(0).unwrap_or(' ').is_digit(10) {
                        // Likely a Swarm DNS name (starts with letter, not a digit)
                        let (host, port, org_id) = parse_swarm_target(to);
                        let target = format!("{}:{}", host, port);
                        println!("Using Swarm DNS target: {}", target);
                        
                        let mut peer = HttpPeer::new(target, false, hostname.to_string());
                        
                        // Add organization header if present
                        if let Some(org) = org_id {
                            peer.options.extra_proxy_headers.insert(
                                "X-Organization-ID".to_string(),
                                org.to_string().into_bytes(),
                            );
                        }
                        
                        Ok(Box::new(peer))
                    } else {
                        // Standard IP:port target - use directly
                        println!("Using direct target: {}", to);
                        let peer = HttpPeer::new(to.to_owned(), false, hostname.to_string());
                        Ok(Box::new(peer))
                    }
                }
                None => {
                    // Default backend when no matching host is found
                    println!("No backend found for host: {}", hostname);
                    let res = HttpPeer::new("127.0.0.1:5500", false, "".to_string());
                    Ok(Box::new(res))
                }
            },
            Err(e) => {
                println!("Error locking servers mutex in HttpProxy: {:?}", e);
                // Return default backend on lock error
                let res = HttpPeer::new("127.0.0.1:5500", false, "".to_string());
                Ok(Box::new(res))
            }
        }
    }

    // Optional: Add a logging method to track HTTPS requests
    async fn logging(
        &self,
        session: &mut Session,
        _error: Option<&pingora::Error>,
        _ctx: &mut Self::CTX,
    ) {
        if let Some(response) = session.response_written() {
            let status = response.status;
            let hostname = extract_hostname(&session.request_summary()).unwrap_or_default();
            println!(
                "HTTPS request completed: host={}, status={}",
                hostname, status
            );
        }
    }
}
