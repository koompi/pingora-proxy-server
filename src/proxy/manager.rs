use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use pingora::{Result, http, prelude::HttpPeer};
use pingora_proxy::{ProxyHttp, Session};

use crate::config::file_manager::{create_mappings_from_store, update_config};

/// Manager Proxy for configuration endpoints
#[derive(Clone)]
pub struct ManagerProxy {
    pub servers: Arc<Mutex<HashMap<String, String>>>,
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
        let method = segments
            .iter()
            .nth(0)
            .map(|s| s.to_string())
            .unwrap_or_default();
        let pathname = segments
            .iter()
            .nth(1)
            .map(|s| s.to_string())
            .unwrap_or_default();

        let path_segments: Vec<String> = pathname.split('/').map(|seg| seg.to_string()).collect();
        println!("Request path segments: {:#?}", &path_segments);

        let mut response_status = 200;
        let mut response_body = String::from("{\"status\":\"success\"}");

        // Handle PUT requests (update existing mapping)
        if method == "PUT" && path_segments.len() > 2 {
            let from = path_segments.get(1).unwrap_or(&String::new()).clone();

            // Clean the destination address by removing trailing commas or whitespace
            // Create a proper owned value with let binding instead of a borrowed reference
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

            // Clean the destination address - same fix as above
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
        )
        .unwrap();

        // Add content-type header to the response
        resp.insert_header("content-type", "application/json")
            .unwrap();

        // Write the response header - passing true for end_of_stream if there's no body
        let body_bytes = response_body.into_bytes();
        session
            .write_response_header(Box::new(resp), body_bytes.is_empty())
            .await?;

        // Only write body if there is something to write
        if !body_bytes.is_empty() {
            // Write the response body and mark it as the end of the stream (true)
            // Note: Session::write_response_body expects Option<Bytes>, not Bytes directly
            session
                .write_response_body(Some(bytes::Bytes::from(body_bytes)), true)
                .await?;
        }

        // Mark that the response has been written
        session.response_written();

        // Return false to indicate we've handled the request and no proxying is needed
        Ok(false)
    }

    fn upstream_peer<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        _session: &'life1 mut Session,
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
        // This code will not execute because request_filter returns false
        // But we still need to provide an implementation
        let res = HttpPeer::new("127.0.0.1:80", false, "".to_string());
        Box::pin(async move { Ok(Box::new(res)) })
    }
}
