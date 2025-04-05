// src/proxy/tcp.rs
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use log::{error, info};
use pingora::server::{Fds, ShutdownWatch};
use pingora::services::Service;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tokio::time::Duration;

use crate::config::model::ConfigStore;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tokio::fs;

// Database type enum
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DatabaseType {
    MongoDB,
    PostgreSQL,
    MySQL,
    Redis,
    Unknown,
}

impl DatabaseType {
    // Get the default port for a database type
    pub fn default_port(&self) -> u16 {
        match self {
            DatabaseType::MongoDB => 27017,
            DatabaseType::PostgreSQL => 5432,
            DatabaseType::MySQL => 3306,
            DatabaseType::Redis => 6379,
            DatabaseType::Unknown => 0,
        }
    }

    // Detect database type from domain pattern
    pub fn detect_from_domain(domain: &str) -> Self {
        if domain.contains(".mongodb.") {
            DatabaseType::MongoDB
        } else if domain.contains(".postgres.") || domain.contains(".postgresql.") {
            DatabaseType::PostgreSQL
        } else if domain.contains(".mysql.") || domain.contains(".sql.") {
            DatabaseType::MySQL
        } else if domain.contains(".redis.") {
            DatabaseType::Redis
        } else {
            DatabaseType::Unknown
        }
    }
}

// Connection statistics
#[derive(Debug, Default, Clone)]
struct ConnectionStats {
    active_connections: usize,
    total_connections: usize,
    bytes_in: usize,
    bytes_out: usize,
}

// Database host mapping
#[derive(Clone)]
struct DatabaseMapping {
    public_port: u16,
    target_host: String,
    target_port: u16,
    db_type: DatabaseType,
    stats: Arc<Mutex<ConnectionStats>>,
}

impl DatabaseMapping {
    pub fn new(domain: String, target: String) -> Self {
        let db_type = DatabaseType::detect_from_domain(&domain);
        let parts: Vec<&str> = target.split(':').collect();
        let (target_host, target_port) = if parts.len() > 1 {
            (
                parts[0].to_string(),
                parts[1].parse::<u16>().unwrap_or(db_type.default_port()),
            )
        } else {
            (parts[0].to_string(), db_type.default_port())
        };

        // Generate a unique port based on domain name hash
        let domain_hash = calculate_hash(&domain);
        let public_port = match db_type {
            DatabaseType::MongoDB => 27017 + (domain_hash % 1000),
            DatabaseType::PostgreSQL => 5432 + (domain_hash % 1000),
            DatabaseType::MySQL => 3306 + (domain_hash % 1000),
            DatabaseType::Redis => 6379 + (domain_hash % 1000),
            DatabaseType::Unknown => db_type.default_port(),
        };

        DatabaseMapping {
            public_port, // Use the unique port
            target_host,
            target_port,
            db_type,
            stats: Arc::new(Mutex::new(ConnectionStats::default())),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Hash, Eq, PartialEq)]
pub struct IpRule {
    pub ip: String,
    pub rule_type: IpRuleType,
    pub description: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Hash, Eq, PartialEq)]
pub enum IpRuleType {
    Whitelist,
    Blacklist,
}

// Store IP rules per database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseIpRules {
    // Key: database_name, Value: Set of IP rules
    pub rules: HashMap<String, HashSet<IpRule>>,
}

impl DatabaseIpRules {
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
        }
    }

    // Add this method for initializing with storage load
    pub async fn new_with_storage() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut rules = Self::new();
        rules.load_from_storage().await?;
        Ok(rules)
    }

    // Add rule for specific database
    pub async fn add_rule(
        &mut self,
        database: &str,
        rule: IpRule,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.rules
            .entry(database.to_string())
            .or_insert_with(HashSet::new)
            .insert(rule);

        // Save to shared storage
        self.save_to_storage().await?;

        // Notify other nodes
        let reload_path = std::path::Path::new("/pingora-proxy/locks/ip_rules_reload");
        if let Some(parent) = reload_path.parent() {
            if !parent.exists() {
                let _ = std::fs::create_dir_all(parent);
            }
        }

        // Write timestamp to trigger other nodes
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        fs::write(reload_path, now.to_string()).await?;

        Ok(())
    }

    // Remove rule for specific database
    pub async fn remove_rule(
        &mut self,
        database: &str,
        ip: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let mut changed = false;
        if let Some(db_rules) = self.rules.get_mut(database) {
            let before_len = db_rules.len();
            db_rules.retain(|rule| rule.ip != ip);
            changed = before_len != db_rules.len();

            if changed {
                self.save_to_storage().await?;

                // Notify other nodes
                let reload_path = std::path::Path::new("/pingora-proxy/locks/ip_rules_reload");
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                fs::write(reload_path, now.to_string()).await?;
            }
        }
        Ok(changed)
    }

    // Check if IP is allowed for specific database
    pub fn is_ip_allowed(&self, database: &str, ip: &str) -> bool {
        if let Some(db_rules) = self.rules.get(database) {
            // Check if IP is explicitly blacklisted for this database
            if db_rules
                .iter()
                .any(|rule| rule.rule_type == IpRuleType::Blacklist && rule.ip == ip)
            {
                return false;
            }

            // If there are any whitelist rules for this database, IP must be in whitelist
            let has_whitelist = db_rules
                .iter()
                .any(|rule| rule.rule_type == IpRuleType::Whitelist);
            if has_whitelist {
                return db_rules
                    .iter()
                    .any(|rule| rule.rule_type == IpRuleType::Whitelist && rule.ip == ip);
            }
        }

        // If no rules exist for this database or no whitelist rules, allow by default
        true
    }

    // Get all rules for specific database
    pub fn get_rules(&self, database: &str) -> Option<HashSet<IpRule>> {
        self.rules.get(database).cloned()
    }

    async fn save_to_storage(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Create storage directory if it doesn't exist
        let storage_path = std::path::Path::new("/pingora-proxy/storage");
        if let Some(parent) = storage_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }

        // Convert rules to JSON
        let json = serde_json::to_string(&self.rules)?;

        // Write to file atomically using a temporary file
        let file_path = storage_path.join("ip_rules.json");
        let temp_path = file_path.with_extension("tmp");

        // Write to temporary file first
        fs::write(&temp_path, json).await?;

        // Rename temporary file to actual file (atomic operation)
        tokio::fs::rename(&temp_path, &file_path).await?;

        Ok(())
    }

    pub async fn load_from_storage(
        &mut self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let file_path = std::path::Path::new("/pingora-proxy/storage/ip_rules.json");

        if file_path.exists() {
            let content = fs::read_to_string(file_path).await?;
            self.rules = serde_json::from_str(&content)?;
        }

        Ok(())
    }
}

// TCP Proxy Service
pub struct TcpProxyService {
    servers: Arc<Mutex<ConfigStore>>,
    db_mappings: Arc<Mutex<HashMap<String, DatabaseMapping>>>,
    enable_tls: bool,
    ip_rules: DatabaseIpRules,
}

impl TcpProxyService {
    pub async fn new(
        servers: Arc<Mutex<ConfigStore>>,
        enable_tls: bool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self {
            servers,
            db_mappings: Arc::new(Mutex::new(HashMap::new())),
            enable_tls,
            ip_rules: DatabaseIpRules::new_with_storage().await?,
        })
    }

    // Initialize database mappings from config
    async fn initialize_mappings(&self) {
        info!("Initializing database mappings");

        // Lock the mappings for update
        let mut db_mappings = self.db_mappings.lock().unwrap();
        db_mappings.clear();

        // Lock the server config store
        if let Ok(servers) = self.servers.lock() {
            for (domain, (backend, _)) in servers.iter() {
                // Check if this is a database domain pattern
                if domain.contains(".mongodb.")
                    || domain.contains(".postgres.")
                    || domain.contains(".mysql.")
                    || domain.contains(".redis.")
                    || domain.contains(".sql.")
                    || domain.contains(".postgresql.")
                    || domain.contains(".database.")
                    || domain.contains(".db.")
                {
                    let mapping = DatabaseMapping::new(domain.clone(), backend.clone());

                    info!(
                        "Adding database mapping: {} -> {}:{} (type: {:?}) - Connect to port: {}",
                        domain,
                        mapping.target_host,
                        mapping.target_port,
                        mapping.db_type,
                        mapping.public_port
                    );

                    db_mappings.insert(domain.clone(), mapping);
                }
            }
        }

        info!("Initialized {} database mappings", db_mappings.len());
    }

    // Run a TLS-enabled TCP proxy for the given mapping
    async fn run_tls_proxy(
        &self,
        domain: String,
        _public_port: u16,
        _target_host: String,
        _target_port: u16,
        _db_type: DatabaseType,
        _stats: Arc<Mutex<ConnectionStats>>,
        _shutdown_rx: mpsc::Receiver<()>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // For TLS implementation, you would need to:
        // 1. Create a TLS acceptor with the domain's certificate
        // 2. Accept TLS connections and handle them
        // This is a placeholder for the TLS implementation
        info!("TLS proxy for {} not implemented yet", domain);
        Ok(())
    }

    async fn run_tcp_proxy(
        &self,
        domain_name: String,
        public_port: u16,
        target_host: String,
        target_port: u16,
        db_type: DatabaseType,
        stats: Arc<Mutex<ConnectionStats>>,
        mut shutdown_rx: mpsc::Receiver<()>,
        db_mappings_arc: Arc<Mutex<HashMap<String, DatabaseMapping>>>,
        ip_rules: DatabaseIpRules,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listen_addr = format!("0.0.0.0:{}", public_port);

        info!(
            "TCP Proxy: Starting proxy for {} (type: {:?}) - listening on {} -> {}:{}",
            domain_name, db_type, listen_addr, target_host, target_port
        );

        let listener = TcpListener::bind(&listen_addr).await?;

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((inbound, client_addr)) => {
                            // Check IP rules using domain_name directly since we know it from the port
                            let client_ip = client_addr.ip().to_string();
                            if !ip_rules.is_ip_allowed(&domain_name, &client_ip) {
                                error!(
                                    "TCP Proxy: Connection rejected - unauthorized IP {} for database {}",
                                    client_ip, domain_name
                                );
                                continue;
                            }

                            // Update connection stats
                            {
                                let mut stats_guard = stats.lock().unwrap();
                                stats_guard.active_connections += 1;
                                stats_guard.total_connections += 1;
                            }

                            // Connect to the target
                            let backend = format!("{}:{}", target_host, target_port);
                            match TcpStream::connect(&backend).await {
                                Ok(outbound) => {
                                    let conn_stats = Arc::clone(&stats);
                                    tokio::spawn(async move {
                                        let _ = proxy_connection(inbound, outbound, conn_stats).await;
                                    });
                                }
                                Err(e) => {
                                    error!("Failed to connect to target {}: {}", backend, e);
                                    let mut stats_guard = stats.lock().unwrap();
                                    stats_guard.active_connections -= 1;
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to accept connection: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Shutting down TCP proxy for {}", domain_name);
                    break;
                }
            }
        }

        Ok(())
    }

    // Modified reload check to include file watching
    async fn check_reload_needed(&self) -> bool {
        let reload_path = std::path::Path::new("/pingora-proxy/locks/ip_rules_reload");

        if reload_path.exists() {
            if let Ok(content) = fs::read_to_string(reload_path).await {
                if let Ok(timestamp) = content.trim().parse::<u64>() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    // Reload if the file was modified in the last 5 seconds
                    if now - timestamp < 5 {
                        return true;
                    }
                }
            }
        }
        false
    }
}

// Function to handle a single proxied connection
async fn proxy_connection(
    mut inbound: TcpStream,
    mut outbound: TcpStream,
    stats: Arc<Mutex<ConnectionStats>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Log connection details at start
    let peer_addr = inbound
        .peer_addr()
        .map_or("unknown".to_string(), |addr| addr.to_string());
    let local_addr = inbound
        .local_addr()
        .map_or("unknown".to_string(), |addr| addr.to_string());
    let target_addr = outbound
        .peer_addr()
        .map_or("unknown".to_string(), |addr| addr.to_string());

    info!(
        "TCP Proxy: New connection established - Client: {} -> Proxy: {} -> Target: {}",
        peer_addr, local_addr, target_addr
    );

    // Split the streams
    let (mut ri, mut wi) = tokio::io::split(inbound);
    let (mut ro, mut wo) = tokio::io::split(outbound);

    // Create channels to communicate between tasks
    let (client_done_tx, mut client_done_rx) = mpsc::channel::<()>(1);
    let (server_done_tx, mut server_done_rx) = mpsc::channel::<()>(1);

    // Forward data from client to server with enhanced logging
    let stats_clone1 = Arc::clone(&stats);
    let client_addr = peer_addr.clone();
    let target_addr_clone = target_addr.clone();
    let client_to_server = tokio::spawn(async move {
        let mut buffer = [0; 8192];
        let mut total_bytes = 0;
        let mut last_log = std::time::Instant::now();

        loop {
            match ri.read(&mut buffer).await {
                Ok(0) => {
                    info!("TCP Proxy: Client {} disconnected", client_addr);
                    break;
                }
                Ok(n) => {
                    match wo.write_all(&buffer[0..n]).await {
                        Ok(_) => {
                            total_bytes += n;
                            // Log traffic stats every 30 seconds
                            if last_log.elapsed() >= Duration::from_secs(30) {
                                info!(
                                    "TCP Proxy: Traffic from {} to {} - {} bytes transferred",
                                    client_addr, target_addr_clone, total_bytes
                                );
                                last_log = std::time::Instant::now();
                            }
                        }
                        Err(e) => {
                            error!(
                                "TCP Proxy: Write error to target {}: {}",
                                target_addr_clone, e
                            );
                            break;
                        }
                    }
                }
                Err(e) => {
                    error!("TCP Proxy: Read error from client {}: {}", client_addr, e);
                    break;
                }
            }
        }

        // Update final stats
        if let Ok(mut stats_guard) = stats_clone1.lock() {
            stats_guard.bytes_in += total_bytes;
            stats_guard.active_connections = stats_guard.active_connections.saturating_sub(1);
        }

        let _ = client_done_tx.send(()).await;
    });

    // Forward data from server to client
    let stats_clone2 = Arc::clone(&stats);
    let server_to_client = tokio::spawn(async move {
        let mut buffer = [0; 8192];
        let mut total_bytes = 0;

        loop {
            match ro.read(&mut buffer).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    match wi.write_all(&buffer[0..n]).await {
                        Ok(_) => {
                            total_bytes += n;
                            // Optionally update stats periodically
                            if total_bytes > 1_000_000 {
                                // Update every ~1MB
                                if let Ok(mut stats_guard) = stats_clone2.lock() {
                                    stats_guard.bytes_out += total_bytes;
                                    total_bytes = 0;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                Err(_) => break,
            }
        }

        // Final stats update
        if total_bytes > 0 {
            if let Ok(mut stats_guard) = stats_clone2.lock() {
                stats_guard.bytes_out += total_bytes;
            }
        }

        // Signal that this direction is done
        let _ = server_done_tx.send(()).await;
    });

    // Wait for either direction to complete
    tokio::select! {
        _ = client_done_rx.recv() => {
            info!("TCP Proxy: Client -> Server direction completed for {}", peer_addr);
        }
        _ = server_done_rx.recv() => {
            info!("TCP Proxy: Server -> Client direction completed for {}", peer_addr);
        }
    }

    info!(
        "TCP Proxy: Connection closed - Client: {} -> Target: {}",
        peer_addr, target_addr
    );

    // Clean up tasks
    client_to_server.abort();
    server_to_client.abort();

    Ok(())
}

#[async_trait]
impl Service for TcpProxyService {
    async fn start_service(
        &mut self,
        _fds: Option<Arc<tokio::sync::Mutex<Fds>>>,
        mut shutdown: ShutdownWatch,
    ) {
        info!("Starting TCP Proxy service for database connections");

        // Initialize mappings from config
        self.initialize_mappings().await;

        // Create shutdown channels for each proxy
        let mut shutdown_channels = Vec::new();

        // Start a proxy for each database mapping
        let mut mappings = Vec::new();

        // Extract mappings from mutex to avoid holding lock during async operations
        if let Ok(db_mappings) = self.db_mappings.lock() {
            for (domain, mapping) in db_mappings.iter() {
                mappings.push((domain.clone(), mapping.clone()));
            }
        }

        // Process each mapping
        for (domain, mapping) in mappings {
            let (tx, rx) = mpsc::channel::<()>(1);
            shutdown_channels.push(tx);

            // Clone only what we need for the new task
            let domain_clone = domain.clone();
            let enable_tls = self.enable_tls;
            let servers = Arc::clone(&self.servers);
            let db_mappings = Arc::clone(&self.db_mappings);
            let ip_rules = self.ip_rules.clone();
            let db_mappings_clone = Arc::clone(&db_mappings);
            let ip_rules_clone = ip_rules.clone();

            tokio::spawn(async move {
                // Create a new service instance without holding any mutex guards
                let service = TcpProxyService {
                    servers,
                    db_mappings,
                    enable_tls,
                    ip_rules,
                };

                // Run either TLS or regular TCP proxy based on configuration
                if enable_tls {
                    if let Err(e) = service
                        .run_tls_proxy(
                            domain_clone.clone(),
                            mapping.public_port,
                            mapping.target_host.clone(),
                            mapping.target_port,
                            mapping.db_type,
                            mapping.stats.clone(),
                            rx,
                        )
                        .await
                    {
                        error!("TLS proxy for {} failed: {}", domain_clone, e);
                    }
                } else {
                    if let Err(e) = service
                        .run_tcp_proxy(
                            domain_clone.clone(),
                            mapping.public_port,
                            mapping.target_host.clone(),
                            mapping.target_port,
                            mapping.db_type,
                            mapping.stats.clone(),
                            rx,
                            db_mappings_clone, // Pass the arc
                            ip_rules_clone,    // Pass the clone
                        )
                        .await
                    {
                        error!("TCP proxy for {} failed: {}", domain_clone, e);
                    }
                }
            });
        }

        info!("Started {} TCP proxies", shutdown_channels.len());

        // Periodically check for config changes and update mappings
        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                // Check for shutdown signal
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("Shutting down TCP Proxy service");

                        // Signal all proxies to shut down
                        for tx in shutdown_channels.iter() {
                            let _ = tx.send(()).await;
                        }

                        // Wait a moment for proxies to clean up
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        break;
                    }
                }

                // Check for config changes periodically
                _ = interval.tick() => {
                    self.initialize_mappings().await;
                }
            }
        }

        info!("TCP Proxy service shutdown complete");
    }

    fn name(&self) -> &'static str {
        "tcp_proxy_service"
    }

    fn threads(&self) -> Option<usize> {
        Some(2) // Use 2 threads for this service
    }
}

// Clone trait implementation
impl Clone for TcpProxyService {
    fn clone(&self) -> Self {
        Self {
            servers: Arc::clone(&self.servers),
            db_mappings: Arc::clone(&self.db_mappings),
            enable_tls: self.enable_tls,
            ip_rules: self.ip_rules.clone(),
        }
    }
}

// Add this helper function to calculate a simple hash
fn calculate_hash(s: &str) -> u16 {
    let mut hash: u32 = 0;
    for b in s.bytes() {
        hash = hash.wrapping_mul(31).wrapping_add(b as u32);
    }
    (hash % 1000) as u16
}
