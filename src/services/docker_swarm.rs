// Updated src/services/docker_swarm.rs with MappingOrigin support
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Result;
use async_trait::async_trait;
use bollard::{service::ListServicesOptions, Docker, API_DEFAULT_VERSION};
use pingora::{
    server::{ListenFds, ShutdownWatch},
    services::Service,
};
use tokio::time;

use crate::{
    config::file_manager::{create_mappings_from_store, update_config},
    config::model::{ConfigStore, MappingOrigin, ServerMapping},
};

use super::lock::FileLock;

pub struct SwarmDiscoveryService {
    pub config_store: Arc<Mutex<ConfigStore>>,
    pub docker_client: Docker,
    pub networks: Vec<String>,
    pub check_interval: Duration,
    // Track organization networks
    pub org_networks: Arc<Mutex<HashMap<String, HashSet<String>>>>,
    leader_lock: FileLock,
    is_leader: Arc<Mutex<bool>>,
}

/// Service that discovers and manages Docker Swarm services for proxy configuration.
///
/// This service monitors Docker Swarm services with specific labels and updates the proxy
/// configuration accordingly. It also manages isolated networks for different organizations.
///
/// # Fields
/// - `config_store`: Thread-safe storage for service configurations
/// - `docker_client`: Client for Docker API interactions
/// - `networks`: List of networks to monitor
/// - `check_interval`: Duration between discovery checks
/// - `org_networks`: Thread-safe mapping of organization IDs to their services
///
/// # Label Requirements
/// Services must have the following labels to be discovered:
/// - `com.koompi.proxy=true`: Indicates the service should be proxied
/// - `com.koompi.proxy.domain`: The domain name to route to this service
///
/// # Optional Labels
/// - `com.koompi.proxy.port`: Port number (defaults to 80)
/// - `com.koompi.org.id`: Organization ID for network isolation
///
/// Creates a new SwarmDiscoveryService instance.
///
/// # Arguments
/// * `config_store` - Thread-safe storage for service configurations
/// * `endpoint` - Docker daemon endpoint (unix:// or http://)
/// * `networks` - List of networks to monitor
/// * `check_interval` - Interval in seconds between discovery checks
///
/// # Returns
/// * `Result<Self>` - New instance or error if connection fails
///
/// # Examples
/// ```
/// let service = SwarmDiscoveryService::new(
///     config_store,
///     "unix:///var/run/docker.sock",
///     vec!["overlay".to_string()],
///     60
/// )?;
/// ```

/// Discovers and updates service configurations from Docker Swarm.
///
/// Fetches services with required labels and updates the config store with their
/// routing information. Also tracks organization-specific services for network isolation.
///
/// # Returns
/// * `Result<()>` - Success or error during discovery
///
/// # Effects
/// - Updates config_store with new service mappings
/// - Updates org_networks with organization service mappings

/// Ensures that required overlay networks exist for each organization.
///
/// Creates isolated overlay networks for organizations if they don't already exist.
/// Networks are created with encryption and internal-only access.
///
/// # Returns
/// * `Result<()>` - Success or error during network creation
///
/// # Network Properties
/// - Name format: `org_{org_id}_overlay`
/// - Driver: overlay
/// - Encrypted: true
/// - Internal: true
/// - Attachable: true

impl SwarmDiscoveryService {
    pub fn new(
        config_store: Arc<Mutex<ConfigStore>>,
        endpoint: &str,
        networks: Vec<String>,
        check_interval: u64,
    ) -> Result<Self> {
        let docker_client = if endpoint.starts_with("unix://") {
            Docker::connect_with_unix(endpoint, 120, API_DEFAULT_VERSION)?
        } else {
            Docker::connect_with_http(endpoint, 120, API_DEFAULT_VERSION)?
        };

        // Change this path to use the shared GlusterFS volume
        let lock_dir = PathBuf::from("/pingora-proxy/locks");
        std::fs::create_dir_all(&lock_dir).ok();

        // Generate a stable node ID using hostname instead of random UUID
        let hostname = std::process::Command::new("hostname")
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
            .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());

        let node_id = hostname;
        println!("Using node ID for locking: {}", node_id);

        // Increase the TTL to 60 seconds for better stability
        let leader_lock = FileLock::new(lock_dir, "config_writer", &node_id, 60);

        Ok(Self {
            config_store,
            docker_client,
            networks,
            check_interval: Duration::from_secs(check_interval),
            org_networks: Arc::new(Mutex::new(HashMap::new())),
            leader_lock,
            is_leader: Arc::new(Mutex::new(false)),
        })
    }
    async fn check_leadership(&self) -> Result<bool> {
        // Try to refresh first with multiple attempts
        match self
            .leader_lock
            .acquire(3, Duration::from_millis(500))
            .await
        {
            Ok(true) => {
                // We are the leader
                if let Ok(mut is_leader) = self.is_leader.lock() {
                    if !*is_leader {
                        println!("Node became the configuration leader");
                    }
                    *is_leader = true;
                }
                Ok(true)
            }
            Ok(false) => {
                // We are not the leader
                if let Ok(mut is_leader) = self.is_leader.lock() {
                    if *is_leader {
                        println!("Node is no longer the configuration leader");
                    }
                    *is_leader = false;
                }
                Ok(false)
            }
            Err(e) => {
                println!("Error in leader election: {}", e);
                // Default to non-leader on error
                if let Ok(mut is_leader) = self.is_leader.lock() {
                    *is_leader = false;
                }
                Ok(false)
            }
        }
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

        // Discover and collect services
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
            let target = if let Some(org) = org_id.clone() {
                // Track services for this organization
                org_services
                    .entry(org.clone())
                    .or_insert_with(HashSet::new)
                    .insert(service_name.clone());

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
                for (org, services) in org_services.clone() {
                    org_networks.insert(org, services);
                }
            }
        }

        // Check if we're the leader before updating config file
        let is_leader = self.check_leadership().await.unwrap_or(false);

        // Always update in-memory configuration first
        let server_mappings = {
            if let Ok(mut store) = self.config_store.lock() {
                // Merge new mappings with existing ones, preserving manual mappings
                for (domain, target) in new_mappings.iter() {
                    // Only update if the mapping doesn't exist or was created by Swarm
                    if !store.contains_key(domain)
                        || store.get(domain).map_or(false, |(_, origin)| {
                            *origin == MappingOrigin::SwarmDiscovery
                        })
                    {
                        store.insert(
                            domain.clone(),
                            (target.clone(), MappingOrigin::SwarmDiscovery),
                        );
                    }
                }

                // Create a vector of mappings while we have the lock
                if is_leader {
                    create_mappings_from_store(&store)
                } else {
                    Vec::new() // Don't need mappings if not leader
                }
            } else {
                // Failed to get lock, return empty vec
                Vec::new()
            }
        };

        // Only the leader node updates the config file
        if is_leader && !server_mappings.is_empty() {
            println!("Node is the leader - updating configuration file");
            match update_config(server_mappings) {
                Ok(_) => println!("Config updated successfully"),
                Err(e) => println!("Error updating config file: {}", e),
            }
        } else if !is_leader {
            println!("Node is not the leader - skipping config file update");
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
            let exists = networks
                .iter()
                .any(|n| n.name.as_ref().map_or(false, |name| name == &network_name));

            if !exists {
                println!("Creating isolated network for organization: {}", org_id);

                // Network options for isolation
                let mut options = HashMap::new();
                options.insert("encrypted".to_string(), "true".to_string());
                options.insert("internal".to_string(), "true".to_string());

                // Create network
                self.docker_client
                    .create_network(bollard::network::CreateNetworkOptions {
                        name: network_name.clone(),
                        driver: "overlay".to_string(),
                        attachable: true,
                        internal: true,
                        options: options,
                        ..Default::default()
                    })
                    .await?;
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
