use std::path::Path;
// src/services/cert_watcher.rs
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use log::info;
use pingora::{
    server::{ListenFds, ShutdownWatch},
    services::Service,
};
use tokio::fs;
use tokio::time;

use crate::proxy::https::HttpsProxy;
use crate::Certificates;
use crate::Mutex;
use log::error;
// Service to watch for certificate changes and reload them
pub struct CertWatcherService {
    https_proxy: Arc<HttpsProxy>,
    certificates: Arc<Mutex<Certificates>>,
    check_interval: Duration,
}

impl CertWatcherService {
    pub fn new(
        https_proxy: Arc<HttpsProxy>,
        certificates: Arc<Mutex<Certificates>>,
        check_interval_secs: u64,
    ) -> Self {
        Self {
            https_proxy,
            certificates,
            check_interval: Duration::from_secs(check_interval_secs),
        }
    }

    async fn check_for_changes(&self) -> bool {
        // Check the reload notification file
        let reload_path = std::path::Path::new("/pingora-proxy/cert-reload/last_reload");

        if let Ok(metadata) = fs::metadata(reload_path).await {
            if let Ok(modified) = metadata.modified() {
                // Check if the file was modified in the last minute
                if SystemTime::now()
                    .duration_since(modified)
                    .unwrap_or_default()
                    < Duration::from_secs(60)
                {
                    return true;
                }
            }
        }

        false
    }
}

#[async_trait::async_trait]
impl Service for CertWatcherService {
    async fn start_service(
        &mut self,
        _fds: Option<Arc<tokio::sync::Mutex<pingora::server::Fds>>>,
        mut shutdown: pingora::server::ShutdownWatch,
    ) {
        info!("Starting Certificate Watcher service");

        let mut interval = tokio::time::interval(self.check_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Check for certificate changes
                    if self.check_for_changes().await {
                        info!("Certificate change detected, reloading");

                        // Reload certificates in the HttpsProxy
                        if let Err(e) = self.https_proxy.reload_certificates().await {
                            error!("Failed to reload certificates in HttpsProxy: {}", e);
                        }

                        // Also refresh the certificates collection
                        if let Ok(certs) = self.certificates.lock() {
                            if let Err(e) = certs.refresh_certificates("/certbot/letsencrypt/live") {
                                error!("Failed to refresh certificates: {}", e);
                            }
                        }
                    }
                }

                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("Stopping Certificate Watcher service");
                        break;
                    }
                }
            }
        }
    }

    fn name(&self) -> &'static str {
        "certificate_watcher_service"
    }

    fn threads(&self) -> Option<usize> {
        Some(1)
    }
}
