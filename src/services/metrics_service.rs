use async_trait::async_trait;
use hyper::http::{Request, Response, StatusCode};
use hyper::service::service_fn;
use log::{error, info};
use prometheus::Encoder;
use std::net::SocketAddr;

use pingora::server::{ListenFds, ShutdownWatch};
use pingora::services::Service;

use crate::metrics::REGISTRY;

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
    async fn start_service(&mut self, _fds: Option<ListenFds>, mut shutdown: ShutdownWatch) {
        info!("Starting metrics service on port {}", self.port);

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

                if let Err(err) = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(
                    io,
                    service_fn(|_req: Request<hyper::body::Incoming>| async {
                        // Create the metrics response
                        let encoder = prometheus::TextEncoder::new();
                        let metric_families = REGISTRY.gather();
                        let mut buffer = Vec::new();
                        encoder
                            .encode(&metric_families, &mut buffer)
                            .unwrap_or_default();

                        let response = Response::builder()
                            .status(StatusCode::OK)
                            .header("Content-Type", "text/plain")
                            .body(http_body_util::Full::new(hyper::body::Bytes::from(buffer)))
                            .unwrap_or_else(|_| {
                                Response::builder()
                                    .status(500)
                                    .body(http_body_util::Full::new(hyper::body::Bytes::from(
                                        "Internal Server Error",
                                    )))
                                    .unwrap()
                            });

                        Ok::<_, hyper::Error>(response)
                    }),
                )
                .await
                {
                    error!("Error serving metrics connection: {}", err);
                }
            });
        }
    }

    fn name(&self) -> &'static str {
        "metrics_service"
    }

    fn threads(&self) -> Option<usize> {
        Some(1)
    }
}
