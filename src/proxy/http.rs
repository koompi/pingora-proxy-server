// src/proxy/http.rs (Updated for MappingOrigin)
use std::{
    fs,
    path::Path,
    str,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use pingora::{prelude::HttpPeer, Result};
use pingora_http::{ResponseHeader, StatusCode};
use pingora_proxy::{ProxyHttp, Session};

use crate::{cert::issuer::CertificateIssuer, config::model::ConfigStore};

use super::utils::extract_hostname;
use crate::metrics::PROXY_METRICS;
use std::time::Instant;

/// HTTP Proxy implementation
#[derive(Clone)]
pub struct HttpProxy {
    pub servers: Arc<Mutex<ConfigStore>>,
    pub disable_ssl: bool,
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

        // Start timing the request - store time in request header
        let start_time = Instant::now();
        session
            .req_header_mut()
            .insert_header(
                "x-request-start-time",
                start_time.elapsed().as_secs_f64().to_string(),
            )
            .unwrap_or(());

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
            } else {
                // Fallback to filesystem if no in-memory challenge found
                let challenge_path =
                    Path::new("/var/www/html/.well-known/acme-challenge/").join(token);
                if challenge_path.exists() {
                    match fs::read_to_string(&challenge_path) {
                        Ok(content) => {
                            let mut res_headers = ResponseHeader::build(StatusCode::OK, None)?;
                            res_headers.insert_header("content-type", "text/plain")?;

                            session
                                .write_response_header(Box::new(res_headers), false)
                                .await?;
                            session
                                .write_response_body(
                                    Some(Bytes::copy_from_slice(content.as_bytes())),
                                    true,
                                )
                                .await?;

                            println!(
                                "Successfully served ACME challenge from file for token: {}",
                                token
                            );
                            return Ok(true);
                        }
                        Err(e) => {
                            println!("Error reading challenge file: {}", e);
                        }
                    }
                }
            }

            // If we couldn't find the challenge or token doesn't match, return 404
            return Err(pingora::Error::new(pingora::ErrorType::HTTPStatus(404)));
        }

        // Skip HTTPS redirect if SSL is disabled
        if self.disable_ssl {
            // Proceed with normal HTTP handling if SSL is disabled
            return Ok(false);
        }

        // Check if certificate exists for this domain before redirecting
        let cert_path = Path::new("/certbot/letsencrypt/live")
            .join(&hostname)
            .join("fullchain.pem");

        if !cert_path.exists() {
            // No certificate exists yet, allow HTTP access instead of redirecting
            println!(
                "No certificate found for {}, allowing HTTP access",
                hostname
            );
            return Ok(false);
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
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // When SSL is disabled or no certificate is found, handle HTTP forwarding here
        let hostname = extract_hostname(&session.request_summary()).unwrap_or_default();
        println!("Attempting to route HTTP request for domain: {}", hostname);

        let target = {
            let servers_lock = match self.servers.lock() {
                Ok(guard) => guard,
                Err(e) => {
                    println!("Error locking servers mutex in HttpProxy: {:?}", e);
                    return Err(pingora::Error::new(pingora::ErrorType::HTTPStatus(404)));
                }
            };

            // Debug output to see what domains are in the config store
            println!(
                "Available domains in config store: {:?}",
                servers_lock.keys().collect::<Vec<_>>()
            );

            servers_lock
                .get(&hostname)
                .map(|(target, _)| target.clone())
        };

        match target {
            Some(to) => {
                println!("Routing HTTP request to backend: {}", to);
                let peer = HttpPeer::new(to, false, hostname.clone());
                Ok(Box::new(peer))
            }
            None => {
                // Increment failed requests counter
                PROXY_METRICS
                    .requests_total
                    .with_label_values(&[&hostname, "404"])
                    .inc();
                Err(pingora::Error::new(pingora::ErrorType::HTTPStatus(404)))
            }
        }
    }

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

        // Record request duration
        let start_time_header = session.req_header().headers.get("x-request-start-time");
        if let Some(start_time_str) = start_time_header {
            if let Ok(start_time) = str::from_utf8(start_time_str.as_ref()) {
                if let Ok(start_time_secs) = start_time.parse::<f64>() {
                    let duration = start_time_secs;
                    PROXY_METRICS
                        .request_duration
                        .with_label_values(&[&hostname])
                        .observe(duration);
                }
            }
        }

        if let Some(response) = session.response_written() {
            let status = response.status.as_u16().to_string();

            // Increment total requests counter with status
            PROXY_METRICS
                .requests_total
                .with_label_values(&[&hostname, &status])
                .inc();
        }

        if let Some(err) = error {
            // Record backend failures
            PROXY_METRICS
                .backend_failures
                .with_label_values(&[&hostname, "connection_error"])
                .inc();
        }
    }
}
