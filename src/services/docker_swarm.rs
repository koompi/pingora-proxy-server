// Fixed src/services/docker_swarm.rs with proper Send safety
use std::{
    collections::{HashMap, HashSet},
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
    // Track organization networks
    pub org_networks: Arc<Mutex<HashMap<String, HashSet<String>>>>,
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
            org_networks: Arc::new(Mutex::new(HashMap::new())),
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
        let mut org_services = HashMap::new();

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
            // Format depends on the context:
            let target = if let Some(org) = org_id.clone() {
                // Use just the service name - the proxy will handle the DNS resolution
                format!("tasks.{}:{}", service_name, port)
            } else {
                format!("tasks.{}:{}", service_name, port)
            };

            println!("Discovered service mapping: {} -> {}", domain, target);
            new_mappings.insert(domain, target);
        }

        // Update the organization services tracking - carefully scope the mutex lock
        {
            if let Ok(mut org_networks) = self.org_networks.lock() {
                for (org, services) in org_services {
                    org_networks.insert(org, services);
                }
            }
        }

        // Update config store with new mappings - carefully scope the mutex lock
        if !new_mappings.is_empty() {
            let server_mappings = {
                if let Ok(mut store) = self.config_store.lock() {
                    // Merge new mappings with existing ones
                    for (domain, target) in new_mappings {
                        store.insert(domain, target);
                    }
                    
                    // Create a vector of mappings while we have the lock
                    store
                        .iter()
                        .map(|(from, to)| ServerMapping {
                            from: from.clone(),
                            to: to.clone(),
                        })
                        .collect()
                } else {
                    // Failed to get lock, return empty vec
                    Vec::new()
                }
            };
            
            // Only update config if we got mappings
            if !server_mappings.is_empty() {
                update_config(server_mappings);
            }
        }

        Ok(())
    }

    // New method to ensure organization networks exist
    async fn ensure_org_networks(&self) -> Result<()> {
        // Get the orgs we need to create networks for
        let orgs = {
            let org_networks_lock = match self.org_networks.lock() {
                Ok(guard) => guard,
                Err(e) => {
                    println!("Failed to lock org_networks: {:?}", e);
                    return Ok(());
                }
            };
            
            // Clone the org IDs so we don't hold the lock
            org_networks_lock.keys().cloned().collect::<Vec<_>>()
        };
        
        // Process outside the lock to avoid Send issues
        for org_id in orgs {
            let network_name = format!("org_{}_overlay", org_id);
            
            // Check if network exists
            let networks = self.docker_client.list_networks::<String>(None).await?;
            let exists = networks.iter().any(|n| n.name.as_ref().map_or(false, |name| name == &network_name));
            
            if !exists {
                println!("Creating isolated network for organization: {}", org_id);
                
                // Network options for isolation
                let mut options = HashMap::new();
                options.insert("encrypted".to_string(), "true".to_string());
                options.insert("internal".to_string(), "true".to_string());
                
                // Create network
                self.docker_client.create_network(
                    bollard::network::CreateNetworkOptions {
                        name: network_name.clone(),
                        driver: "overlay".to_string(),
                        attachable: true,
                        internal: true,
                        options: options,
                        ..Default::default()
                    }
                ).await?;
                println!("Created network: {}", network_name);
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

            // First discover services
            if let Err(e) = self.discover_services().await {
                println!("Error in service discovery: {}", e);
            }
            
            // Then ensure networks exist
            if let Err(e) = self.ensure_org_networks().await {
                println!("Error ensuring organization networks: {}", e);
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