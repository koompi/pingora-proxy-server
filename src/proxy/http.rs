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

use crate::proxy::utils::{parse_swarm_target, resolve_swarm_service};
use super::utils::extract_hostname;

/// HTTP Proxy implementation
#[derive(Clone)]
pub struct HttpProxy {
    pub servers: Arc<Mutex<HashMap<String, String>>>,
}

impl HttpProxy {
    // Helper method to get target safely
    fn get_server_target(&self, hostname: &str) -> Option<String> {
        self.servers.lock().ok()?.get(hostname).cloned()
    }
}

#[async_trait::async_trait]
impl ProxyHttp for HttpProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        // Get the path from the request header
        let path = session.req_header().uri.path().to_string();

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
        // Extract hostname
        let hostname = extract_hostname(&session.request_summary())
            .unwrap_or_default();
        
        // Get target safely
        let to = match self.get_server_target(&hostname) {
            Some(target) => target,
            None => {
                println!("No backend found for host: {}", hostname);
                return Ok(Box::new(HttpPeer::new("127.0.0.1:5500", false, "".to_string())));
            }
        };

        // Parse Swarm target
        let (host, port, org_id) = parse_swarm_target(&to);

        // Resolve service
        let resolved_addr = match resolve_swarm_service(&host, port).await {
            Ok(addr) => addr,
            Err(e) => {
                println!("Failed to resolve service {}: {:?}", to, e);
                return Ok(Box::new(HttpPeer::new("127.0.0.1:5500", false, "".to_string())));
            }
        };

        // Create HttpPeer
        let mut peer = HttpPeer::new(
            resolved_addr.to_string(), 
            false, 
            hostname.to_string()
        );
        
        // Add organization header if present
        if let Some(org) = org_id {
            peer.options.extra_proxy_headers.insert(
                "X-Organization-ID".to_string(),
                org.into_bytes(),
            );
        }
        
        Ok(Box::new(peer))
    }
}