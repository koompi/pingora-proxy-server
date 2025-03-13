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

    fn upstream_peer<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        session: &'life1 mut Session,
        _ctx: &'life2 mut Self::CTX,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = Result<Box<HttpPeer>>>
                + ::core::marker::Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        let hostname = extract_hostname(&session.request_summary()).unwrap_or_default();

        match self.servers.lock() {
            Ok(servers) => match servers.get(&hostname) {
                Some(to) => {
                    let res = HttpPeer::new(to.to_owned(), false, hostname.to_string());
                    Box::pin(async move { Ok(Box::new(res)) })
                }
                None => {
                    // Default backend when no matching host is found
                    let res = HttpPeer::new("127.0.0.1:5500", false, "".to_string());
                    Box::pin(async move { Ok(Box::new(res)) })
                }
            },
            Err(e) => {
                println!("Error locking servers mutex in HttpProxy: {:?}", e);
                // Return default backend on lock error
                let res = HttpPeer::new("127.0.0.1:5500", false, "".to_string());
                Box::pin(async move { Ok(Box::new(res)) })
            }
        }
    }
}
