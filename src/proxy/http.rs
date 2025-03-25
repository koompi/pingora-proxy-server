// src/proxy/http.rs
use std::{
    collections::HashMap,
    fs,
    path::Path,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use pingora::{prelude::HttpPeer, Result};
use pingora_http::{RequestHeader, ResponseHeader, StatusCode};
use pingora_proxy::{ProxyHttp, Session};

use crate::cert::issuer::CertificateIssuer;
use crate::proxy::utils::{
    parse_swarm_target, test_service_connectivity, validate_org_network_access,
};

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

        // Get the hostname for domain verification
        let hostname = extract_hostname(&session.request_summary()).unwrap_or_default();

        // Handle ACME challenges from Let's Encrypt
        if path.starts_with("/.well-known/acme-challenge/") {
            println!("Handling ACME challenge: {}", path);

            let token = path.split('/').last().unwrap_or_default();

            if token.is_empty() {
                return Err(pingora::Error::new(pingora::ErrorType::HTTPStatus(404)));
            }

            // Check if we have an active challenge for this domain
            if let Some((challenge_token, validation)) =
                CertificateIssuer::get_challenge(&hostname).await
            {
                if token == challenge_token {
                    let mut res_headers = ResponseHeader::build(StatusCode::OK, None)?;

                    res_headers.insert_header("content-type", "text/plain")?;

                    session
                        .write_response_header(Box::new(res_headers), false)
                        .await?;

                    session
                        .write_response_body(
                            Some(Bytes::copy_from_slice(validation.as_bytes())),
                            true,
                        )
                        .await?;

                    println!("Successfully served ACME challenge for token: {}", token);
                    return Ok(true);
                }
            }

            // If we couldn't find the challenge or token doesn't match, return 404
            return Err(pingora::Error::new(pingora::ErrorType::HTTPStatus(404)));
        }

        // For all other requests, redirect to HTTPS
        let current_uri = &session.req_header().uri;
        let host = hostname;

        // Build the HTTPS URI for redirection
        // We have to manually construct the URL since we can't use http::Uri directly
        let https_uri = format!(
            "https://{}{}",
            host,
            current_uri.path_and_query().map_or("/", |pq| pq.as_str())
        );

        let mut res_headers = ResponseHeader::build(StatusCode::PERMANENT_REDIRECT, None)?;

        res_headers.insert_header("location", https_uri)?;
        res_headers.insert_header("content-type", "text/plain")?;
        res_headers.insert_header("content-length", "0")?;

        session
            .write_response_header(Box::new(res_headers), true)
            .await?;

        println!("Redirected HTTP request for {} to HTTPS", host);
        return Ok(true);
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // This should not be called because request_filter should handle everything
        Err(pingora::Error::new(pingora::ErrorType::HTTPStatus(404)))
    }
}
