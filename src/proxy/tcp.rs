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
use byteorder::{ByteOrder, LittleEndian};
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

// Add these new structs for MongoDB protocol handling
#[derive(Debug)]
struct MongoHeader {
    message_length: i32,
    request_id: i32,
    response_to: i32,
    op_code: i32,
}

impl MongoHeader {
    fn from_bytes(buffer: &[u8]) -> Option<Self> {
        if buffer.len() < 16 {
            return None;
        }

        // Ensure we're reading valid MongoDB wire protocol message
        let message_length = LittleEndian::read_i32(&buffer[0..4]);
        let request_id = LittleEndian::read_i32(&buffer[4..8]);
        let response_to = LittleEndian::read_i32(&buffer[8..12]);
        let op_code = LittleEndian::read_i32(&buffer[12..16]);

        // Validate message length and op_code
        if message_length <= 0 || message_length > 48_000_000 {
            // MongoDB max message size
            return None;
        }

        Some(MongoHeader {
            message_length,
            request_id,
            response_to,
            op_code,
        })
    }
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

    // Parse MongoDB wire protocol header
    let header = match MongoHeader::from_bytes(&buffer) {
        Some(h) => h,
        None => {
            warn!("Invalid MongoDB protocol header, falling back to IP-based routing");
            return Err("Invalid MongoDB protocol header".into());
        }
    };

    info!(
        "MongoDB message: length={}, opCode={}, reqID={}",
        header.message_length, header.op_code, header.request_id
    );

    // Extract database information and find backend
    let (backend, mapping) = {
        let mappings = db_mappings.lock().unwrap();

        // Try to extract database name from connection string or command
        if let Some(db_info) = extract_database_info(&buffer[16..], header.op_code) {
            info!("Detected database info: {}", db_info);

            // First try exact domain pattern match
            if let Some((host, port, idx)) = find_backend_for_database(&db_info, &mappings) {
                info!(
                    "Found exact match for database '{}' -> {}:{}",
                    db_info, host, port
                );
                if let Some(mapping) = mappings.get(idx) {
                    (Some((host, port)), Some(mapping.clone()))
                } else {
                    (Some((host, port)), None)
                }
            } else {
                // Fall back to default mapping if available
                if let Some((idx, mapping)) = mappings
                    .iter()
                    .enumerate()
                    .find(|(_, m)| m.domain_pattern == "default" || m.domain_pattern == "*")
                {
                    (
                        Some((mapping.target_host.clone(), mapping.target_port)),
                        Some(mapping.clone()),
                    )
                } else {
                    (None, None)
                }
            }
        } else {
            warn!("Could not extract database info, falling back to IP routing");
            match route_by_client_ip(&client_addr, &mappings) {
                Some((host, port, idx)) => {
                    if let Some(mapping) = mappings.get(idx) {
                        (Some((host, port)), Some(mapping.clone()))
                    } else {
                        (Some((host, port)), None)
                    }
                }
                None => (None, None),
            }
        }
    };

    // Handle the connection routing
    match backend {
        Some((host, port)) => {
            info!(
                "Routing MongoDB connection from {} to {}:{}",
                client_addr, host, port
            );

            // Try to resolve the backend address first
            match tokio::net::lookup_host(format!("{}:{}", host, port)).await {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        match TcpStream::connect(addr).await {
                            Ok(server_stream) => {
                                // Connection successful, proceed with proxying
                                if let Some(m) = &mapping {
                                    m.active_connections.fetch_add(1, Ordering::SeqCst);
                                }

                                let result =
                                    proxy_bidirectional(client_stream, server_stream).await;

                                if let Some(m) = &mapping {
                                    m.active_connections.fetch_sub(1, Ordering::SeqCst);
                                }

                                result
                            }
                            Err(e) => {
                                error!("Failed to connect to resolved address {}: {}", addr, e);
                                Err(format!("Connection failed: {}", e).into())
                            }
                        }
                    } else {
                        Err("No addresses resolved for backend".into())
                    }
                }
                Err(e) => {
                    error!("Failed to resolve backend host {}: {}", host, e);
                    Err(format!("DNS resolution failed: {}", e).into())
                }
            }
        }
        None => {
            error!(
                "No backend found for MongoDB connection from {}",
                client_addr
            );
            Err("No matching backend found".into())
        }
    }
}

fn extract_database_info(payload: &[u8], op_code: i32) -> Option<String> {
    match op_code {
        2004 => {
            // OP_QUERY
            if payload.len() < 8 {
                return None;
            }

            // Skip flags (4 bytes)
            let mut offset = 4;

            // Find null-terminated collection name
            let mut end = offset;
            while end < payload.len() && payload[end] != 0 {
                end += 1;
            }

            if end > offset {
                if let Ok(collection) = std::str::from_utf8(&payload[offset..end]) {
                    // Collection names are in format: dbname.collectionname
                    if let Some(dot_pos) = collection.find('.') {
                        return Some(collection[0..dot_pos].to_string());
                    }
                }
            }
        }
        2013 => {
            // OP_MSG (MongoDB 3.6+)
            if payload.len() < 4 {
                return None;
            }

            let data = String::from_utf8_lossy(payload);

            // Common patterns for database identification
            for pattern in &["\"$db\":\"", "$db: \"", "db: \"", "\"db\":\""] {
                if let Some(pos) = data.find(pattern) {
                    let start = pos + pattern.len();
                    if let Some(end) = data[start..].find('"') {
                        return Some(data[start..(start + end)].to_string());
                    }
                }
            }
        }
        _ => {}
    }

    None
}

fn find_backend_for_database(
    db_info: &str,
    mappings: &[DatabaseMapping],
) -> Option<(String, u16, usize)> {
    // First try to match based on the database name
    for (idx, mapping) in mappings.iter().enumerate() {
        // Check if the database name contains our domain pattern
        if db_info.contains(&mapping.domain_pattern) {
            return Some((mapping.target_host.clone(), mapping.target_port, idx));
        }
    }

    // If no match found based on database name, look for a default mapping
    for (idx, mapping) in mappings.iter().enumerate() {
        if mapping.domain_pattern == "default" || mapping.domain_pattern == "*" {
            return Some((mapping.target_host.clone(), mapping.target_port, idx));
        }
    }

    None
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
