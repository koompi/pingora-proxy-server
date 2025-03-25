// src/proxy/http.rs (Updated for MappingOrigin)
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

use crate::{
    cert::issuer::CertificateIssuer,
    config::model::ConfigStore,
    proxy::utils::{parse_swarm_target, test_service_connectivity, validate_org_network_access},
};

use super::utils::extract_hostname;

/// HTTP Proxy implementation
#[derive(Clone)]
pub struct HttpProxy {
    pub servers: Arc<Mutex<ConfigStore>>,
}

#[async_trait::async_trait]
/// Implementation of the `ProxyHttp` trait for `HttpProxy` that handles HTTP traffic.
///
/// This implementation serves two main purposes:
/// 1. Handles ACME challenges from Let's Encrypt for domain verification
/// 2. Redirects all other HTTP traffic to HTTPS
///
/// # Type Parameters
/// * `CTX` - Empty context type as no context is needed for this implementation
///
/// # Methods
/// * `new_ctx()` - Creates a new empty context
/// * `request_filter()` - Processes incoming HTTP requests:
///   - Handles ACME challenges by serving validation tokens
///   - Redirects all other traffic to HTTPS with a 308 Permanent Redirect
/// * `upstream_peer()` - Not used as all requests are handled by request_filter
///
/// # Error Handling
/// Returns appropriate HTTP status codes:
/// * 404 for invalid or missing ACME challenges
/// * 308 for redirecting to HTTPS
///
/// # Example
/// When receiving an HTTP request to `http://example.com/path`:
/// * If it's an ACME challenge, serves the validation token
/// * Otherwise, redirects to `https://example.com/path`
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
