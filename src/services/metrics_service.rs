use async_trait::async_trait;
use http_body_util::Full;
use hyper::{
    body::Bytes,
    http::{Request, Response, StatusCode},
};
use log::{error, info};
use prometheus::Encoder;
use std::future::Future;
use std::pin::Pin;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::{watch, Mutex};

use crate::metrics::REGISTRY;
use pingora::server::Fds;
use pingora_core::services::Service;
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
    fn name(&self) -> &str {
        "metrics_service"
    }

    async fn start_service(
        &mut self,
        listen_fds: Option<Arc<Mutex<Fds>>>,
        mut shutdown: watch::Receiver<bool>,
    ) -> () {
        let port = self.port;
        let service_future = async move {
            if let Some(fds) = listen_fds {
                let addr = SocketAddr::from(([0, 0, 0, 0], port));
                let listener = match tokio::net::TcpListener::bind(addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        error!("Failed to bind metrics service: {}", e);
                        return;
                    }
                };

                info!("Metrics service listening on port {}", port);

                loop {
                    tokio::select! {
                        Ok((stream, _)) = listener.accept() => {
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
                        }
                        _ = shutdown.changed() => {
                            info!("Metrics service shutting down");
                            break;
                        }
                    }
                }
            }
        };

        Box::pin(service_future);
    }
}
