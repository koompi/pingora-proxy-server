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

pub struct CertWatcherService {
    https_proxy: Arc<HttpsProxy>,
    certificates: Arc<Mutex<Certificates>>,
    check_interval: Duration,
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
        println!("Starting Certificate Watcher service...");

        let mut interval = time::interval(self.check_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Check for certificate changes
                    let reload_path = Path::new("/pingora-proxy/cert-reload/last_reload");
                    if reload_path.exists() {
                        if let Ok(metadata) = fs::metadata(reload_path).await {
                            if let Ok(modified) = metadata.modified() {
                                if SystemTime::now().duration_since(modified).unwrap_or_default() < Duration::from_secs(60) {
                                    println!("Reloading certificates...");
                                    if let Err(e) = self.https_proxy.reload_certificates().await {
                                        println!("Failed to reload certificates: {}", e);
                                    }
                                }
                            }
                        }
                    }
                }

                Ok(_) = shutdown.changed() => {
                    if *shutdown.borrow() {
                        println!("Stopping Certificate Watcher service");
                        break;
                    }
                }
            }
        }
    }

    fn name(&self) -> &'static str {
        "certificate_watcher_service"
    }
}
