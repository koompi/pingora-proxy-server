// src/proxy/tcp.rs
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use log::{error, info, warn};
use pingora::server::{Fds, ShutdownWatch};
use pingora::services::Service;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::Duration;

use crate::config::model::ConfigStore;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
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
pub struct ConnectionStats {
    pub active_connections: usize,
    pub total_connections: usize,
    pub bytes_in: usize,
    pub bytes_out: usize,
}

// Database host mapping
#[derive(Clone)]
pub struct DatabaseMapping {
    pub domain_pattern: String, // e.g., "riverbase-mongodb"
    pub target_host: String,    // Docker service DNS name
    pub target_port: u16,       // Always 27017 for MongoDB
    pub stats: Arc<Mutex<ConnectionStats>>,
    pub active_connections: Arc<AtomicUsize>, // New field
}

impl DatabaseMapping {
    fn matches_domain(&self, domain: &str) -> bool {
        domain.contains(&self.domain_pattern)
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
    db_mappings: Arc<Mutex<Vec<DatabaseMapping>>>,
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
            db_mappings: Arc::new(Mutex::new(Vec::new())),
            enable_tls,
            ip_rules: DatabaseIpRules::new_with_storage().await?,
        })
    }

    // Initialize database mappings from config
    async fn initialize_mappings(&self) {
        info!("Initializing MongoDB database mappings");

        // Create a new vec of mappings
        let mut mappings = Vec::new();

        // Lock the server config store
        if let Ok(servers) = self.servers.lock() {
            for (domain, (backend, _)) in servers.iter() {
                // Check if this is a MongoDB domain
                if domain.contains(".mongodb.") {
                    // Extract the key part to match in connection strings
                    let domain_key = if let Some(mongo_idx) = domain.find(".mongodb.") {
                        if mongo_idx > 0 {
                            // Get the part before .mongodb. as the domain key
                            &domain[0..mongo_idx]
                        } else {
                            // Fallback to the whole domain
                            domain
                        }
                    } else {
                        domain
                    };

                    // Parse target backend (host:port)
                    let parts: Vec<&str> = backend.split(':').collect();
                    let (target_host, target_port) = if parts.len() > 1 {
                        (
                            parts[0].to_string(),
                            parts[1].parse::<u16>().unwrap_or(27017),
                        )
                    } else {
                        (parts[0].to_string(), 27017)
                    };

                    info!(
                        "Adding MongoDB mapping: domain_pattern={}, target={}:{}",
                        domain_key, target_host, target_port
                    );

                    mappings.push(DatabaseMapping {
                        domain_pattern: domain_key.to_string(),
                        target_host,
                        target_port,
                        stats: Arc::new(Mutex::new(ConnectionStats::default())),
                        active_connections: Arc::new(AtomicUsize::new(0)),
                    });
                }
            }
        }

        // Update the shared mappings
        if let Ok(mut db_mappings) = self.db_mappings.lock() {
            *db_mappings = mappings;
        }

        // Log what we found
        if let Ok(mappings) = self.db_mappings.lock() {
            info!("Initialized {} MongoDB database mappings", mappings.len());
            for (i, mapping) in mappings.iter().enumerate() {
                info!(
                    "  [{}] Pattern '{}' -> {}:{}",
                    i, mapping.domain_pattern, mapping.target_host, mapping.target_port
                );
            }
        }
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

#[async_trait]
impl Service for TcpProxyService {
    async fn start_service(
        &mut self,
        _fds: Option<Arc<tokio::sync::Mutex<Fds>>>,
        mut shutdown: ShutdownWatch,
    ) {
        info!("Starting TCP Proxy service for MongoDB connections");

        // Initialize mappings
        self.initialize_mappings().await;

        // Get a clone of the db_mappings for the accept loop
        let db_mappings = self.db_mappings.clone();

        // Create shutdown channel for the accept loop
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        // Create a single TCP listener for MongoDB
        let listener = match TcpListener::bind("0.0.0.0:27017").await {
            Ok(listener) => {
                info!("Successfully bound MongoDB proxy to 0.0.0.0:27017");
                listener
            }
            Err(e) => {
                error!("Failed to bind MongoDB proxy to 0.0.0.0:27017: {}", e);
                return;
            }
        };

        // Spawn the accept loop task
        let accept_task = tokio::spawn(mongodb_accept_loop(listener, db_mappings, shutdown_rx));

        // Wait for shutdown signal
        match shutdown.changed().await {
            Ok(_) => {
                if *shutdown.borrow() {
                    info!("Shutdown signal received, stopping MongoDB proxy");
                    let _ = shutdown_tx.send(()).await;
                    let _ = tokio::time::timeout(Duration::from_secs(5), accept_task).await;
                }
            }
            Err(e) => {
                error!("Error waiting for shutdown signal: {}", e);
            }
        }

        info!("MongoDB proxy service stopped");
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

// Main accept loop for MongoDB connections with better connection tracking
async fn mongodb_accept_loop(
    listener: TcpListener,
    db_mappings: Arc<Mutex<Vec<DatabaseMapping>>>,
    mut shutdown_rx: mpsc::Receiver<()>,
) {
    // Set up a counter for connection management
    let connection_count = Arc::new(AtomicUsize::new(0));

    // Let people know we're ready to receive MongoDB connections
    info!("MongoDB proxy is ready to accept connections on port 27017");

    // Initialize MongoDB connection mappings
    {
        let mappings = db_mappings.lock().unwrap();
        if !mappings.is_empty() {
            info!("Available MongoDB backends:");
            for (i, mapping) in mappings.iter().enumerate() {
                info!(
                    "  [{}] Pattern '{}' -> {}:{}",
                    i, mapping.domain_pattern, mapping.target_host, mapping.target_port
                );
            }
        } else {
            warn!("No MongoDB backends are configured. Connections will fail.");
        }
    }

    loop {
        // Accept new connections with timeout to check for shutdown
        let accept_future = listener.accept();
        let timeout = tokio::time::sleep(Duration::from_secs(1));

        tokio::select! {
            accept_result = accept_future => {
                match accept_result {
                    Ok((client_stream, client_addr)) => {
                        let count = connection_count.fetch_add(1, Ordering::SeqCst);
                        info!("New MongoDB connection #{} from {}", count, client_addr);

                        // Clone the mappings for this connection
                        let mappings = Arc::clone(&db_mappings);
                        let conn_count = Arc::clone(&connection_count);

                        // Spawn a new task to handle this connection
                        tokio::spawn(async move {
                            let result = handle_mongodb_connection(
                                client_stream,
                                client_addr,
                                mappings,
                            ).await;

                            if let Err(e) = result {
                                error!("Error handling MongoDB connection #{}: {}", count, e);
                            } else {
                                info!("Successfully closed MongoDB connection #{}", count);
                            }

                            // Decrement active connection count
                            conn_count.fetch_sub(1, Ordering::SeqCst);
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                        // Don't exit on accept errors, just continue
                        continue;
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                info!("Received shutdown signal, stopping MongoDB proxy accept loop");
                break;
            }
            _ = timeout => {
                // Timeout, just loop again
                continue;
            }
        }
    }

    info!(
        "MongoDB accept loop stopped. Current connections: {}",
        connection_count.load(Ordering::SeqCst)
    );
}

// Handle a MongoDB connection
async fn handle_mongodb_connection(
    mut client_stream: TcpStream,
    client_addr: SocketAddr,
    db_mappings: Arc<Mutex<Vec<DatabaseMapping>>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Read initial data from client
    let mut buffer = vec![0u8; 8192];
    let n = match client_stream.read(&mut buffer).await {
        Ok(n) if n == 0 => return Err("Client closed connection immediately".into()),
        Ok(n) => n,
        Err(e) => return Err(format!("Failed to read from client: {}", e).into()),
    };
    buffer.truncate(n);

    let data_string = String::from_utf8_lossy(&buffer);
    let preview = if data_string.len() > 200 {
        &data_string[..200]
    } else {
        &data_string
    };
    info!("Analyzing connection data (first 200 chars): {}", preview);

    // Find backend using pattern matching first, then IP-based routing
    let (backend, mapping) = {
        let mappings = db_mappings.lock().unwrap();

        if let Some(backend) = find_matching_backend(&data_string, &mappings) {
            (Some(backend), None)
        } else {
            match route_by_client_ip(&client_addr, &mappings) {
                Some((host, port, idx)) => {
                    info!(
                        "Using IP-based routing for client {} -> {}:{}",
                        client_addr, host, port
                    );

                    // Increment active connections counter
                    if let Some(mapping) = mappings.get(idx) {
                        mapping.active_connections.fetch_add(1, Ordering::SeqCst);
                        (Some((host, port)), Some(mapping.clone()))
                    } else {
                        (Some((host, port)), None)
                    }
                }
                None => (None, None),
            }
        }
    };

    match backend {
        Some((host, port)) => {
            info!(
                "Routing MongoDB connection from {} to {}:{}",
                client_addr, host, port
            );

            match TcpStream::connect(format!("{}:{}", host, port)).await {
                Ok(mut server_stream) => {
                    if let Err(e) = server_stream.write_all(&buffer).await {
                        // Decrease connection count on error
                        if let Some(m) = &mapping {
                            m.active_connections.fetch_sub(1, Ordering::SeqCst);
                        }
                        return Err(format!("Failed to write to server: {}", e).into());
                    }

                    let result = proxy_bidirectional(client_stream, server_stream).await;

                    // Decrease connection count after proxy ends
                    if let Some(m) = &mapping {
                        m.active_connections.fetch_sub(1, Ordering::SeqCst);
                    }

                    result
                }
                Err(e) => {
                    // Decrease connection count on error
                    if let Some(m) = &mapping {
                        m.active_connections.fetch_sub(1, Ordering::SeqCst);
                    }
                    error!("Failed to connect to backend {}:{}: {}", host, port, e);
                    Err(format!("Failed to connect to backend: {}", e).into())
                }
            }
        }
        None => {
            error!(
                "No backend found for MongoDB connection from {}",
                client_addr
            );
            if let Ok(mappings) = db_mappings.lock() {
                info!("Available backends ({}):", mappings.len());
                for (i, mapping) in mappings.iter().enumerate() {
                    info!(
                        "  [{}] Pattern '{}' -> {}:{} (active: {})",
                        i,
                        mapping.domain_pattern,
                        mapping.target_host,
                        mapping.target_port,
                        mapping.active_connections.load(Ordering::SeqCst)
                    );
                }
            }
            Err("No matching backend found".into())
        }
    }
}

// Helper function to proxy data bidirectionally
async fn proxy_bidirectional(
    client_stream: TcpStream,
    server_stream: TcpStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Get addresses for logging
    let client_addr = client_stream.peer_addr()?.to_string();
    let server_addr = server_stream.peer_addr()?.to_string();

    info!(
        "Established bidirectional proxy: {} <-> {}",
        client_addr, server_addr
    );

    // Split the TCP streams
    let (mut client_read, mut client_write) = tokio::io::split(client_stream);
    let (mut server_read, mut server_write) = tokio::io::split(server_stream);

    // Create channels to signal when a direction is complete
    let (client_done_tx, mut client_done_rx) = mpsc::channel::<()>(1);
    let (server_done_tx, mut server_done_rx) = mpsc::channel::<()>(1);

    // Client to server forwarding
    let client_to_server = tokio::spawn(async move {
        let mut buffer = [0u8; 8192];
        let mut bytes_copied = 0;

        loop {
            match client_read.read(&mut buffer).await {
                Ok(0) => {
                    // Client closed the connection
                    info!("Client disconnected after sending {} bytes", bytes_copied);
                    break;
                }
                Ok(n) => match server_write.write_all(&buffer[..n]).await {
                    Ok(_) => {
                        bytes_copied += n;
                    }
                    Err(e) => {
                        warn!("Error writing to server: {}", e);
                        break;
                    }
                },
                Err(e) => {
                    warn!("Error reading from client: {}", e);
                    break;
                }
            }
        }

        let _ = client_done_tx.send(()).await;
    });

    // Server to client forwarding
    let server_to_client = tokio::spawn(async move {
        let mut buffer = [0u8; 8192];
        let mut bytes_copied = 0;

        loop {
            match server_read.read(&mut buffer).await {
                Ok(0) => {
                    // Server closed the connection
                    info!("Server disconnected after sending {} bytes", bytes_copied);
                    break;
                }
                Ok(n) => match client_write.write_all(&buffer[..n]).await {
                    Ok(_) => {
                        bytes_copied += n;
                    }
                    Err(e) => {
                        warn!("Error writing to client: {}", e);
                        break;
                    }
                },
                Err(e) => {
                    warn!("Error reading from server: {}", e);
                    break;
                }
            }
        }

        let _ = server_done_tx.send(()).await;
    });

    // Wait for either stream to complete
    tokio::select! {
        _ = client_done_rx.recv() => {
            info!("Client to server transfer completed");
        }
        _ = server_done_rx.recv() => {
            info!("Server to client transfer completed");
        }
    }

    // Cancel the other task
    client_to_server.abort();
    server_to_client.abort();

    info!("Connection closed: {} <-> {}", client_addr, server_addr);
    Ok(())
}

// Find matching backend by checking all patterns against the data
fn find_matching_backend(data: &str, mappings: &[DatabaseMapping]) -> Option<(String, u16)> {
    // Domain patterns we check for
    let domain_patterns = [".mongodb.koompi.cloud", "-mongodb-", ".mongodb."];

    // For each domain pattern, look for matches
    for pattern in &domain_patterns {
        if let Some(pos) = data.find(pattern) {
            // Extract context around the match
            let start = pos.saturating_sub(100);
            let end = (pos + pattern.len() + 100).min(data.len());
            let context = &data[start..end];

            // Try each mapping against this context
            for mapping in mappings {
                if context.contains(&mapping.domain_pattern) {
                    info!(
                        "Found match for pattern '{}' in context",
                        mapping.domain_pattern
                    );
                    return Some((mapping.target_host.clone(), mapping.target_port));
                }
            }
        }
    }

    // Special case for connection strings
    if data.contains("mongodb://") {
        for mapping in mappings {
            if data.contains(&mapping.domain_pattern) {
                info!(
                    "Found match for pattern '{}' in connection string",
                    mapping.domain_pattern
                );
                return Some((mapping.target_host.clone(), mapping.target_port));
            }
        }
    }

    // No match found
    None
}

// Fixed route_by_client_ip function to correctly return the index
fn route_by_client_ip(
    client_addr: &SocketAddr,
    mappings: &[DatabaseMapping],
) -> Option<(String, u16, usize)> {
    if mappings.is_empty() {
        return None;
    }

    // Generate hash from client IP
    let hash_value = match client_addr.ip() {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            octets.iter().enumerate().fold(0u64, |acc, (i, &octet)| {
                acc.wrapping_add((octet as u64) << (i * 8))
            })
        }
        IpAddr::V6(_) => {
            // Simplified IPv6 handling - use first available backend
            return Some((mappings[0].target_host.clone(), mappings[0].target_port, 0));
        }
    };

    // Select backend using consistent hashing
    let idx = (hash_value as usize) % mappings.len();
    let mapping = &mappings[idx];

    Some((mapping.target_host.clone(), mapping.target_port, idx))
}
