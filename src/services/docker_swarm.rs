// src/services/docker_swarm.rs
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Result;
use async_trait::async_trait;
use bollard::{API_DEFAULT_VERSION, Docker, service::ListServicesOptions};
use pingora::{
    server::{ListenFds, ShutdownWatch},
    services::Service,
};
use tokio::time;

use crate::{config::file_manager::update_config, config::model::ServerMapping};

pub struct SwarmDiscoveryService {
    pub config_store: Arc<Mutex<HashMap<String, String>>>,
    pub docker_client: Docker,
    pub networks: Vec<String>,
    pub check_interval: Duration,
}

impl SwarmDiscoveryService {
    pub fn new(
        config_store: Arc<Mutex<HashMap<String, String>>>,
        endpoint: &str,
        networks: Vec<String>,
        check_interval: u64,
    ) -> Result<Self> {
        let docker_client = if endpoint.starts_with("unix://") {
            Docker::connect_with_unix(endpoint, 120, API_DEFAULT_VERSION)?
        } else {
            Docker::connect_with_http(endpoint, 120, API_DEFAULT_VERSION)?
        };

        Ok(Self {
            config_store,
            docker_client,
            networks,
            check_interval: Duration::from_secs(check_interval),
        })
    }

    async fn discover_services(&self) -> Result<()> {
        println!("Running Docker Swarm service discovery");

        // Filter for services with a specific label for our proxy
        let mut filters = HashMap::new();
        filters.insert("label", vec!["com.koompi.proxy=true"]);

        let services = self
            .docker_client
            .list_services(Some(ListServicesOptions {
                filters: filters.clone(),
                status: true,
            }))
            .await?;

        let mut new_mappings = HashMap::new();

        for service in services {
            let service_spec = match service.spec {
                Some(spec) => spec,
                None => continue,
            };

            // Get service labels
            let labels = match service_spec.labels {
                Some(labels) => labels,
                None => continue,
            };

            // Parse required labels
            let domain = match labels.get("com.koompi.proxy.domain") {
                Some(domain) => domain.clone(),
                None => continue,
            };

            // Get port from label or use default
            let port = labels
                .get("com.koompi.proxy.port")
                .map(|p| p.parse::<u16>().unwrap_or(80))
                .unwrap_or(80);

            // Get organization ID/name for network isolation
            let org_id = labels.get("com.koompi.org.id").cloned();

            // Get service name as provided by Docker Swarm
            let service_name = service_spec.name.unwrap_or_default();

            // Create target using Docker Swarm DNS-based service discovery
            // Format: service_name.network_name:port
            let target = if let Some(org) = org_id {
                // Use organization-specific format
                format!("{}.{}.{}:{}", org, service_name, self.networks[0], port)
            } else {
                // Use standard format
                format!("{}.{}:{}", service_name, self.networks[0], port)
            };

            println!("Discovered service mapping: {} -> {}", domain, target);
            new_mappings.insert(domain, target);
        }

        // Update config store with new mappings
        if !new_mappings.is_empty() {
            if let Ok(mut store) = self.config_store.lock() {
                // Merge new mappings with existing ones
                for (domain, target) in new_mappings {
                    store.insert(domain, target);
                }

                // Update config file
                let server_mappings = store
                    .iter()
                    .map(|(from, to)| ServerMapping {
                        from: from.clone(),
                        to: to.clone(),
                    })
                    .collect();

                update_config(server_mappings);
            }
        }

        Ok(())
    }
}

#[async_trait]
impl Service for SwarmDiscoveryService {
    async fn start_service(&mut self, _fds: Option<ListenFds>, _shutdown: ShutdownWatch) {
        println!("Starting Docker Swarm discovery service");

        let mut interval = time::interval(self.check_interval);

        loop {
            interval.tick().await;

            if let Err(e) = self.discover_services().await {
                println!("Error in service discovery: {}", e);
            }
        }
    }

    fn name(&self) -> &'static str {
        "swarm_discovery_service"
    }

    fn threads(&self) -> Option<usize> {
        Some(1)
    }
}
