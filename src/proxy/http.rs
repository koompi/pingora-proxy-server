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

use crate::proxy::utils::parse_swarm_target;

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

    // Update this section in your HTTP proxy implementation
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

                    // Parse swarm target if needed
                    let (target, use_tls, org_header) = if to.contains(".") && to.contains(":") {
                        // Likely a swarm DNS name
                        let (host, port, org_id) = parse_swarm_target(to);
                        (format!("{}:{}", host, port), false, org_id)
                    } else {
                        // Standard target
                        (to.to_owned(), false, None)
                    };

                    // Create HTTP peer
                    let mut peer = HttpPeer::new(target, use_tls, hostname.to_string());

                    // Add organization header if present
                    if let Some(org) = org_header {
                        // Access the correct location for extra headers in PeerOptions
                        peer.options.extra_proxy_headers.insert(
                            "X-Organization-ID".to_string(),
                            org.to_string().into_bytes(),
                        );
                    }

                    Ok(Box::new(peer))
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
}
