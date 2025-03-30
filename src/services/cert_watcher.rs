// src/services/cert_watcher.rs
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use async_trait::async_trait;
use log::{error, info};
use pingora::{
    server::{ListenFds, ShutdownWatch},
    services::Service,
};
use tokio::time;

use crate::proxy::https::HttpsProxy;

pub struct CertWatcherService {
    https_proxy: Arc<HttpsProxy>,
    check_interval: Duration,
    watched_path: PathBuf,
    last_modified: u64,
}

impl CertWatcherService {
    pub fn new(https_proxy: Arc<HttpsProxy>, check_interval_secs: u64) -> Self {
        Self {
            https_proxy,
            check_interval: Duration::from_secs(check_interval_secs),
            watched_path: PathBuf::from("/pingora-proxy/cert-reload/last_reload"),
            last_modified: 0,
        }
    }

    async fn check_for_changes(&mut self) -> bool {
        if !self.watched_path.exists() {
            return false;
        }

        match std::fs::metadata(&self.watched_path) {
            Ok(metadata) => {
                if let Ok(modified) = metadata.modified() {
                    if let Ok(modified_secs) = modified.duration_since(UNIX_EPOCH) {
                        let modified_timestamp = modified_secs.as_secs();

                        if modified_timestamp > self.last_modified {
                            info!(
                                "Detected certificate reload notification, timestamp: {}",
                                modified_timestamp
                            );
                            self.last_modified = modified_timestamp;

                            // In addition to reloading certificates, also reload configuration
                            let config_path = std::env::var("CONFIG_PATH")
                                .unwrap_or_else(|_| "config.json".to_string());

                            info!("Reloading domain mappings from {}", config_path);
                            if let Ok(content) = std::fs::read_to_string(&config_path) {
                                if let Ok(config) = serde_json::from_str::<
                                    crate::config::model::Configuration,
                                >(&content)
                                {
                                    // Convert to hashmap and update in-memory store
                                    let store = config.to_hashmap();
                                    if let Ok(mut servers) = self.https_proxy.servers.lock() {
                                        *servers = store;
                                        info!("Successfully reloaded domain mappings from file");
                                    }
                                }
                            }

                            return true;
                        }
                    }
                }
            }
            Err(e) => {
                error!("Error checking reload file: {}", e);
            }
        }

        false
    }
}

#[async_trait]
impl Service for CertWatcherService {
    async fn start_service(&mut self, _fds: Option<ListenFds>, mut shutdown: ShutdownWatch) {
        info!("Starting Certificate Watcher service...");

        // Initial check for last modified timestamp
        if self.watched_path.exists() {
            if let Ok(metadata) = std::fs::metadata(&self.watched_path) {
                if let Ok(modified) = metadata.modified() {
                    if let Ok(modified_secs) = modified.duration_since(UNIX_EPOCH) {
                        self.last_modified = modified_secs.as_secs();
                        info!(
                            "Initial certificate reload timestamp: {}",
                            self.last_modified
                        );
                    }
                }
            }
        }

        let mut interval = time::interval(self.check_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if self.check_for_changes().await {
                        info!("Reloading certificates due to notification...");
                        match self.https_proxy.reload_certificates().await {
                            Ok(_) => info!("Certificates reloaded successfully"),
                            Err(e) => error!("Failed to reload certificates: {:?}", e),
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
