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

pub struct CertWatcherService {
    https_proxy: Arc<HttpsProxy>,
    check_interval: Duration,
    certificates: Arc<Mutex<Certificates>>,
}

impl CertWatcherService {
    pub fn new(
        https_proxy: Arc<HttpsProxy>,
        check_interval: u64,
        certificates: Arc<Mutex<Certificates>>,
    ) -> Self {
        Self {
            https_proxy,
            check_interval: Duration::from_secs(check_interval),
            certificates,
        }
    }

    async fn check_for_changes(&self) -> bool {
        // Check the reload notification file
        if let Ok(metadata) = fs::metadata("/pingora-proxy/cert-reload/last_reload").await {
            if let Ok(modified) = metadata.modified() {
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

#[async_trait]
impl Service for CertWatcherService {
    async fn start_service(&mut self, _fds: Option<ListenFds>, mut shutdown: ShutdownWatch) {
        info!("Starting Certificate Watcher service...");

        let mut interval = time::interval(self.check_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if self.check_for_changes().await {
                        info!("Reloading certificates due to notification...");
                        if let Err(e) = self.https_proxy.reload_certificates().await {
                            info!("Failed to reload certificates: {}", e);
                        }
                    }
                }

                Ok(_) = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("Shutdown signal received, stopping Certificate Watcher service");
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
