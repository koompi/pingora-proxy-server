use async_trait::async_trait;
use http_body_util::Full;
use hyper::{
    body::Bytes,
    http::{Request, Response, StatusCode},
};
use log::{error, info};
use prometheus::Encoder;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{watch, Mutex};

use crate::metrics::REGISTRY;
use pingora::server::{Fds, ShutdownWatch};
use pingora::services::Service;

pub struct MetricsService {
    port: u16,
}

impl MetricsService {
    pub fn new(port: u16) -> Self {
        Self { port }
    }
}

#[async_trait]
impl Service for MetricsService {
    fn name(&self) -> &'static str {
        "metrics_service"
    }

    async fn start_service(
        &mut self,
        listen_fds: Option<Arc<Mutex<Fds>>>,
        mut shutdown: ShutdownWatch,
    ) {
        let addr = SocketAddr::from(([0, 0, 0, 0], self.port));

        // Create a simple HTTP server using tokio
        let listener = match tokio::net::TcpListener::bind(&addr).await {
            Ok(listener) => listener,
            Err(e) => {
                error!("Failed to bind metrics server to port {}: {}", self.port, e);
                return;
            }
        };

        info!("Metrics server listening on {}", addr);

        // Run the server in a loop
        loop {
            // Check for shutdown signal
            if shutdown.has_changed().is_ok() && *shutdown.borrow() {
                info!("Metrics server received shutdown signal");
                break;
            }

            // Accept connections with timeout
            let accept = tokio::select! {
                result = listener.accept() => result,
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => continue,
            };

            let (stream, _) = match accept {
                Ok(conn) => conn,
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                    continue;
                }
            };

            // Handle the connection
            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);

                if let Err(err) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        io,
                        hyper::service::service_fn(|_req: Request<hyper::body::Incoming>| async {
                            let encoder = prometheus::TextEncoder::new();
                            let metric_families = REGISTRY.gather();
                            let mut buffer = Vec::new();

                            if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
                                error!("Failed to encode metrics: {}", e);
                                return Ok::<_, hyper::Error>(
                                    Response::builder()
                                        .status(500)
                                        .body(Full::new(Bytes::from("Metrics encoding failed")))
                                        .unwrap(),
                                );
                            }

                            Ok::<_, hyper::Error>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header("Content-Type", encoder.format_type())
                                    .body(Full::new(Bytes::from(buffer)))
                                    .unwrap(),
                            )
                        }),
                    )
                    .await
                {
                    error!("Error serving metrics connection: {}", err);
                }
            });
        }
    }

    fn threads(&self) -> Option<usize> {
        Some(1)
    }
}
