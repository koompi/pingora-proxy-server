// Updated src/services/docker_swarm.rs with MappingOrigin support
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use async_trait::async_trait;
use bollard::models::Network;
use bollard::{
    network::{CreateNetworkOptions, ListNetworksOptions},
    service::ListServicesOptions,
    Docker, API_DEFAULT_VERSION,
};
use log::{error, info, warn};
use pingora::{
    server::{ListenFds, ShutdownWatch},
    services::Service,
};
use sha256::digest;
use thiserror::Error;
use tokio::time;

#[derive(Error, Debug)]
pub enum SwarmError {
    #[error("Docker API error: {0}")]
    DockerError(#[from] bollard::errors::Error),

    #[error("Network operation failed: {0}")]
    NetworkError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("System time error: {0}")]
    TimeError(#[from] std::time::SystemTimeError),
}

use crate::{
    config::{
        file_manager::{create_mappings_from_store, update_config},
        model::{ConfigStore, MappingOrigin, ServerMapping},
    },
    proxy::tcp::DatabaseMapping,
};

use super::lock::DistributedLock;

struct ConfigVersion {
    version: u64,
    timestamp: SystemTime,
    checksum: String,
}

pub struct SwarmDiscoveryService {
    pub config_store: Arc<Mutex<ConfigStore>>,
    pub docker_client: Docker,
    pub networks: Vec<String>,
    pub check_interval: Duration,
    // Track organization networks
    pub org_networks: Arc<Mutex<HashMap<String, HashSet<String>>>>,
    distributed_lock: DistributedLock, // New distributed lock implementation
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
        info!("Using node ID for locking: {}", node_id);

        // Increase the TTL to 60 seconds for better stability
        let distributed_lock = DistributedLock::new(lock_dir, "config_writer", &node_id, 60);

        Ok(Self {
            config_store,
            docker_client,
            networks,
            check_interval: Duration::from_secs(check_interval),
            org_networks: Arc::new(Mutex::new(HashMap::new())),
            distributed_lock,
            is_leader: Arc::new(Mutex::new(false)),
        })
    }
    async fn check_leadership(&self) -> Result<bool> {
        // Try to refresh first with multiple attempts
        match self.distributed_lock.refresh_leadership().await {
            Ok(true) => {
                // We are the leader
                if let Ok(mut is_leader) = self.is_leader.lock() {
                    if !*is_leader {
                        info!("Node became the configuration leader");
                    }
                    *is_leader = true;
                }
                Ok(true)
            }
            Ok(false) => {
                // We are not the leader
                if let Ok(mut is_leader) = self.is_leader.lock() {
                    if *is_leader {
                        info!("Node is no longer the configuration leader");
                    }
                    *is_leader = false;
                }
                Ok(false)
            }
            Err(e) => {
                error!("Error in leader election: {}", e);
                // Default to non-leader on error
                if let Ok(mut is_leader) = self.is_leader.lock() {
                    *is_leader = false;
                }
                Ok(false)
            }
        }
    }
    async fn discover_services(&self) -> Result<()> {
        info!("Running Docker Swarm service discovery");

        // Try to acquire a lock with much shorter timeout for discovery operations
        let lock_acquired = self
            .distributed_lock
            .acquire(3, Duration::from_millis(500))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to acquire lock: {}", e))?;

        // Filter for services with a specific label for our proxy
        let mut filters: HashMap<String, Vec<String>> = HashMap::new();
        filters.insert(
            "label".to_string(),
            vec!["com.koompi.proxy=true".to_string()],
        );

        // Load recently deleted domains
        let recently_deleted_file = PathBuf::from("/pingora-proxy/locks/recently_deleted.json");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Create a set of recently deleted domains that are still within the cooling period
        let recently_deleted: HashSet<String> = if recently_deleted_file.exists() {
            match std::fs::read_to_string(&recently_deleted_file) {
                Ok(content) => match serde_json::from_str::<Vec<(u64, String)>>(&content) {
                    Ok(timestamp_domains) => {
                        // Only include domains deleted within the last 5 minutes
                        timestamp_domains
                            .into_iter()
                            .filter(|(timestamp, _)| now - *timestamp < 300)
                            .map(|(_, domain)| domain)
                            .collect()
                    }
                    Err(_) => HashSet::new(),
                },
                Err(_) => HashSet::new(),
            }
        } else {
            HashSet::new()
        };

        if !recently_deleted.is_empty() {
            info!(
                "Found {} recently deleted domains that will be excluded from discovery",
                recently_deleted.len()
            );
        }

        let services = self
            .docker_client
            .list_services(Some(ListServicesOptions {
                filters: filters.clone(),
                status: true,
            }))
            .await?;

        let mut new_mappings = HashMap::new();
        let mut org_services = HashMap::new();

        // Process regular HTTP/HTTPS services
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

            // Skip if this domain was recently manually deleted
            if recently_deleted.contains(&domain) {
                info!("Skipping recently deleted domain: {}", domain);
                continue;
            }

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

            info!("Discovered service mapping: {} -> {}", domain, target);
            new_mappings.insert(domain, target);
        }

        // Add MongoDB service discovery
        let mut mongo_filters: HashMap<String, Vec<String>> = HashMap::new();
        mongo_filters.insert(
            "label".to_string(),
            vec!["com.koompi.database.mongodb=true".to_string()],
        );

        let mongo_services = self
            .docker_client
            .list_services(Some(ListServicesOptions {
                filters: mongo_filters.clone(),
                status: true,
            }))
            .await?;

        // Process MongoDB services
        for service in mongo_services {
            let service_spec = match service.spec {
                Some(spec) => spec,
                None => continue,
            };

            // Get service name and domain pattern
            let service_name = service_spec.name.unwrap_or_default();
            let domain_pattern = match service_spec.labels {
                Some(labels) => labels
                    .get("com.koompi.database.name")
                    .cloned()
                    .unwrap_or_else(|| service_name.clone()),
                None => service_name.clone(),
            };

            // Create target using Docker Swarm DNS
            let target = format!("tasks.{}", service_name);

            info!(
                "Discovered MongoDB service: {} -> {}",
                domain_pattern, target
            );
            new_mappings.insert(domain_pattern.clone(), target);
        }

        // Update the organization services tracking
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
                    // Skip recently deleted domains even at this stage for extra safety
                    if recently_deleted.contains(domain) {
                        continue;
                    }

                    // Only update if the mapping doesn't exist or was created by Swarm
                    if !store.contains_key(domain)
                        || store.get(domain).map_or(false, |(_, map_origin)| {
                            *map_origin == MappingOrigin::SwarmDiscovery
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
            info!("Node is the leader - updating configuration file");
            match self.update_config_with_version(server_mappings).await {
                Ok(_) => info!("Config updated successfully"),
                Err(e) => error!("Error updating config file: {}", e),
            }
        } else if !is_leader {
            info!("Node is not the leader - skipping config file update");
        }

        // Make sure to explicitly release the lock when done
        if lock_acquired {
            if let Err(e) = self.distributed_lock.release().await {
                error!("Error releasing lock: {}", e);
            }
        }

        Ok(())
    }

    async fn network_exists(&self, network_name: &str) -> Result<bool> {
        let mut filters: HashMap<String, Vec<String>> = HashMap::new();
        filters.insert("name".to_string(), vec![network_name.to_string()]);

        let networks = self
            .docker_client
            .list_networks::<String>(Some(ListNetworksOptions { filters }))
            .await?;

        Ok(!networks.is_empty())
    }

    // New method to ensure organization networks exist
    async fn ensure_org_networks(&self) -> Result<()> {
        // Create lock directory if it doesn't exist
        let lock_dir = PathBuf::from("/pingora-proxy/locks");
        if !lock_dir.exists() {
            match std::fs::create_dir_all(&lock_dir) {
                Ok(_) => info!("Created lock directory: {:?}", lock_dir),
                Err(e) => {
                    error!("Failed to create lock directory: {:?} - {}", lock_dir, e);
                    // Continue anyway with a warning
                }
            }
        }
        // Try to acquire network setup lock
        if !self
            .distributed_lock
            .acquire(5, Duration::from_secs(1))
            .await?
        {
            info!("Another node is managing networks");
            return Ok(());
        }

        let orgs = {
            let org_networks_lock = self
                .org_networks
                .lock()
                .map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
            org_networks_lock.keys().cloned().collect::<Vec<_>>()
        };

        for org_id in orgs {
            let network_name = format!("org_{}_overlay", org_id);

            // Check network version
            let current_version = self.get_network_version(&network_name).await?;
            if !self
                .network_needs_update(&network_name, &current_version)
                .await?
            {
                continue;
            }

            // Create network if needed...
            if !self.network_exists(&network_name).await? {
                self.create_organization_network(&org_id).await?;
            }
        }

        // Release lock
        self.distributed_lock.release().await?;
        Ok(())
    }

    async fn get_network_version(&self, network_name: &str) -> Result<u64, SwarmError> {
        let mut filters: HashMap<String, Vec<String>> = HashMap::new();
        filters.insert("name".to_string(), vec![network_name.to_string()]);

        let networks = self
            .docker_client
            .list_networks::<String>(Some(ListNetworksOptions { filters }))
            .await
            .map_err(SwarmError::DockerError)?;

        let version = networks
            .first()
            .and_then(|n| n.created.as_ref())
            .and_then(|t| t.parse::<u64>().ok())
            .unwrap_or_else(|| {
                warn!(
                    "Could not determine network version for {}, using current time",
                    network_name
                );
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            });

        Ok(version)
    }

    async fn network_needs_update(
        &self,
        network_name: &str,
        version: &u64,
    ) -> Result<bool, SwarmError> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(SwarmError::TimeError)?
            .as_secs();

        Ok(current_time - version > 24 * 60 * 60)
    }

    async fn get_config_version(&self) -> Result<ConfigVersion> {
        let store = self
            .config_store
            .lock()
            .map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
        let content = serde_json::to_string(&*store)?;
        let checksum = sha256::digest(content.as_bytes());

        Ok(ConfigVersion {
            version: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            timestamp: SystemTime::now(),
            checksum,
        })
    }

    async fn update_config_with_version(
        &self,
        mappings: Vec<ServerMapping>,
    ) -> Result<(), SwarmError> {
        let version = self
            .get_config_version()
            .await
            .map_err(|e| SwarmError::ConfigError(format!("Failed to get config version: {}", e)))?;

        // Add retry logic with better error handling
        let max_retries = 5;
        let mut retry_count = 0;

        while retry_count < max_retries {
            match update_config(mappings.clone()) {
                Ok(_) => return Ok(()),
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::ResourceBusy {
                        // Device busy error - wait a bit longer
                        retry_count += 1;
                        if retry_count < max_retries {
                            let delay = std::time::Duration::from_millis(
                                250 * 2u64.pow(retry_count as u32),
                            );
                            tokio::time::sleep(delay).await;
                        }
                    } else {
                        // For other errors, fail immediately
                        return Err(SwarmError::ConfigError(format!(
                            "Failed to update config: {}",
                            e
                        )));
                    }
                }
            }
        }

        // All retries failed
        Err(SwarmError::ConfigError(format!(
            "Failed to update config after {} attempts: Device or resource busy (os error 16)",
            max_retries
        )))
    }

    async fn create_organization_network(&self, org_id: &str) -> Result<(), SwarmError> {
        let network_name = format!("org_{}_overlay", org_id);
        info!(
            "Creating network {} for organization {}",
            network_name, org_id
        );

        let mut config = HashMap::new();
        config.insert(
            "com.docker.network.driver.overlay.vxlanid_list".to_string(),
            "4096".to_string(),
        );
        config.insert(
            "com.docker.network.driver.encrypted".to_string(),
            "true".to_string(),
        );

        let ipam_config = bollard::models::IpamConfig {
            subnet: Some(format!("10.{}.0.0/16", org_id)),
            gateway: None,
            ip_range: None,
            auxiliary_addresses: None,
        };

        let create_opts = CreateNetworkOptions {
            name: network_name.clone(),
            driver: "overlay".to_string(),
            attachable: true,
            internal: true,
            labels: HashMap::new(),
            options: config,
            ipam: bollard::models::Ipam {
                driver: Some("default".to_string()),
                config: Some(vec![ipam_config]),
                options: None,
            },
            ..Default::default()
        };

        self.docker_client
            .create_network(create_opts)
            .await
            .map_err(|e| {
                SwarmError::NetworkError(format!(
                    "Failed to create network {}: {}",
                    network_name, e
                ))
            })?;

        info!("Successfully created network {}", network_name);
        Ok(())
    }

    pub async fn cleanup_old_networks(&self) -> Result<(), SwarmError> {
        let networks = self
            .docker_client
            .list_networks::<String>(None)
            .await
            .map_err(SwarmError::DockerError)?;

        for network in networks {
            if let Some(name) = network.name {
                if name.starts_with("org_") && name.ends_with("_overlay") {
                    if let Some(created) = network.created {
                        let version = created.parse::<u64>().unwrap_or_default();
                        if self.network_needs_update(&name, &version).await? {
                            info!("Removing old network: {}", name);
                            self.remove_network(&name).await?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn remove_network(&self, network_name: &str) -> Result<(), SwarmError> {
        self.docker_client
            .remove_network(network_name)
            .await
            .map_err(|e| {
                SwarmError::NetworkError(format!(
                    "Failed to remove network {}: {}",
                    network_name, e
                ))
            })?;

        info!("Successfully removed network: {}", network_name);
        Ok(())
    }
}

#[async_trait]
impl Service for SwarmDiscoveryService {
    async fn start_service(&mut self, _fds: Option<ListenFds>, mut shutdown: ShutdownWatch) {
        info!("Starting Docker Swarm discovery service");

        let mut interval = time::interval(self.check_interval);
        let mut cleanup_interval = time::interval(Duration::from_secs(300)); // Every 5 minutes

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.handle_discovery().await;
                }
                _ = cleanup_interval.tick() => {
                    self.handle_cleanup().await;
                }
                _ = shutdown.changed() => {
                    info!("Shutdown signal received, stopping service");
                    break;
                }
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

impl SwarmDiscoveryService {
    async fn handle_discovery(&self) {
        if let Err(e) = self.discover_services().await {
            error!("Error in service discovery: {}", e);
        }

        if let Err(e) = self.ensure_org_networks().await {
            error!("Error ensuring organization networks: {}", e);
        }
    }

    async fn handle_cleanup(&self) {
        let recently_deleted_file = PathBuf::from("/pingora-proxy/locks/recently_deleted.json");
        if !recently_deleted_file.exists() {
            return;
        }

        match tokio::fs::read_to_string(&recently_deleted_file).await {
            Ok(content) => {
                if let Ok(timestamp_domains) = serde_json::from_str::<Vec<(u64, String)>>(&content)
                {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    let fresh_entries: Vec<(u64, String)> = timestamp_domains
                        .into_iter()
                        .filter(|(timestamp, _)| now - timestamp < 300)
                        .collect();

                    if let Ok(json) = serde_json::to_string(&fresh_entries) {
                        if let Err(e) = tokio::fs::write(&recently_deleted_file, json).await {
                            error!("Error writing recently deleted file during cleanup: {}", e);
                        } else {
                            info!("Cleaned up recently deleted domains list");
                        }
                    }
                }
            }
            Err(e) => error!("Error reading recently deleted file: {}", e),
        }
    }
}
