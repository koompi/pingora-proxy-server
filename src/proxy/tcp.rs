// src/proxy/tcp.rs
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
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
use std::os::fd::AsRawFd;
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
    domain_pattern: String, // e.g., "riverbase-mongodb"
    target_host: String,    // Docker service DNS name
    target_port: u16,       // Always 27017 for MongoDB
    stats: Arc<Mutex<ConnectionStats>>,
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
        info!("Initializing MongoDB database mappings");

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
                    let db_type = DatabaseType::detect_from_domain(domain);
                    if db_type == DatabaseType::Unknown {
                        continue;
                    }

                    // Parse target backend (host:port)
                    let parts: Vec<&str> = backend.split(':').collect();
                    let (target_host, target_port) = if parts.len() > 1 {
                        (
                            parts[0].to_string(),
                            parts[1].parse::<u16>().unwrap_or(db_type.default_port()),
                        )
                    } else {
                        (parts[0].to_string(), db_type.default_port())
                    };

                    // For MongoDB domains, we'll use our SNI-like hostname routing
                    if db_type == DatabaseType::MongoDB {
                        info!(
                            "Adding MongoDB mapping: {} -> {}:{} (type: {:?})",
                            domain, target_host, target_port, db_type
                        );

                        db_mappings.insert(
                            domain.clone(),
                            DatabaseMapping {
                                domain_pattern: domain.clone(),
                                target_host,
                                target_port,
                                stats: Arc::new(Mutex::new(ConnectionStats::default())),
                            },
                        );
                    } else {
                        // For other database types, we'd handle them differently
                        // (outside scope of current implementation)
                    }
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
        mut _shutdown_rx: mpsc::Receiver<()>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // For TLS implementation, you would need to:
        // 1. Create a TLS acceptor with the domain's certificate
        // 2. Accept TLS connections and handle them
        // This is a placeholder for the TLS implementation
        info!("TLS proxy for {} not implemented yet", domain);
        Ok(())
    }

    // Run a regular TCP proxy for the given mapping
    async fn run_tcp_proxy(
        &self,
        domain_mappings: HashMap<String, DatabaseMapping>,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Create a single listener for all MongoDB connections
        let listen_addr = "0.0.0.0:27017";

        info!("MongoDB TCP Proxy: Starting proxy on {}", listen_addr);

        let listener = match TcpListener::bind(&listen_addr).await {
            Ok(l) => {
                info!("MongoDB TCP Proxy: Successfully bound to {}", listen_addr);
                l
            }
            Err(e) => {
                error!(
                    "MongoDB TCP Proxy: Failed to bind to {}: {}",
                    listen_addr, e
                );
                return Err(Box::new(e));
            }
        };

        let domain_mappings = Arc::new(Mutex::new(domain_mappings));

        // Process incoming connections
        loop {
            // Check for shutdown signal
            if let Ok(()) = shutdown_rx.try_recv() {
                info!("Shutting down MongoDB TCP proxy");
                break;
            }

            // Accept new connections
            let accept_future = listener.accept();
            let timeout = tokio::time::sleep(Duration::from_secs(1));

            tokio::select! {
                accept_result = accept_future => {
                    match accept_result {
                        Ok((inbound, client_addr)) => {
                            info!("MongoDB TCP Proxy: New connection from {}", client_addr);

                            // Clone the mappings for this connection
                            let mappings = Arc::clone(&domain_mappings);

                            // Spawn a new task to handle this connection
                            tokio::spawn(async move {
                                if let Err(e) = handle_mongodb_connection(inbound, client_addr, mappings, client_addr).await {
                                    error!("Error handling MongoDB connection: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Failed to accept connection: {}", e);
                        }
                    }
                }
                _ = timeout => {
                    // Timeout, check for shutdown again
                    continue;
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
        info!("Starting TCP Proxy service for MongoDB connections");

        // Initialize mappings
        self.initialize_mappings().await;

        // Get a copy of the domain mappings
        let domain_mappings = {
            let db_mappings = self.db_mappings.lock().unwrap();
            db_mappings.clone()
        };

        // Create shutdown channel for the accept loop
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);

        // Create a single TCP listener
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
        let accept_task_handle = tokio::spawn(async move {
            let shared_mappings = Arc::new(Mutex::new(domain_mappings));

            loop {
                // Accept new connections
                let accept_future = listener.accept();
                let timeout = tokio::time::sleep(Duration::from_secs(1));

                tokio::select! {
                    accept_result = accept_future => {
                        match accept_result {
                            Ok((client_stream, client_addr)) => {
                                info!("New MongoDB connection from {}", client_addr);

                                // Clone the mappings for this connection
                                let mappings = Arc::clone(&shared_mappings);

                                // Spawn a new task to handle this connection
                                tokio::spawn(async move {
                                    if let Err(e) = handle_mongodb_connection(
                                        client_stream,
                                        client_addr,
                                        mappings,
                                        client_addr
                                    ).await {
                                        error!("Error handling MongoDB connection: {}", e);
                                    }
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
                }
            }
        });

        // Wait for shutdown signal
        match shutdown.changed().await {
            Ok(_) => {
                if *shutdown.borrow() {
                    info!("Shutdown signal received, stopping MongoDB proxy");
                    let _ = shutdown_tx.send(()).await;
                    let _ = tokio::time::timeout(Duration::from_secs(5), accept_task_handle).await;
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

// Improve MongoDB protocol parsing
fn parse_mongodb_hostname(data: &[u8]) -> Option<String> {
    // MongoDB wire protocol header is 16 bytes
    if data.len() < 16 {
        return None;
    }

    // First try to parse the standard MongoDB wire protocol
    let message_length = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let op_code = u32::from_le_bytes(data[12..16].try_into().unwrap());

    // OpCode 2004 is OP_QUERY, 2013 is OP_MSG (MongoDB 3.6+)
    if (op_code == 2004 || op_code == 2013) && data.len() >= message_length {
        // Split the payload into chunks and process each separately to avoid UTF-8 boundary issues
        let payload_bytes = &data[16..message_length];

        // Convert chunks to strings safely, skipping invalid UTF-8 sequences
        let mut valid_strings = Vec::new();
        let mut current_chunk = Vec::new();

        for &byte in payload_bytes {
            current_chunk.push(byte);
            if let Ok(s) = String::from_utf8(current_chunk.clone()) {
                valid_strings.push(s);
                current_chunk.clear();
            }
        }

        // Join valid strings and search for patterns
        let payload = valid_strings.join("");

        // Look for connection string patterns
        let patterns = [
            ("isMaster", 20),   // MongoDB handshake
            ("ismaster", 20),   // Older MongoDB versions
            ("hello", 20),      // MongoDB 5.0+
            ("mongodb://", 50), // Connection string
            ("\"host\":", 100),
            ("\"hostname\":", 100),
            ("\"db\":", 50),
            ("\"database\":", 50),
            ("applicationName", 50), // MongoDB Compass and other clients
        ];

        // First try to find MongoDB Compass specific patterns
        if payload.contains("MongoDB Compass") {
            // Extract connection details from MongoDB Compass connection
            if let Some(pos) = payload.find("mongodb://") {
                let end = payload[pos..]
                    .find(char::is_whitespace)
                    .map(|p| pos + p)
                    .unwrap_or(payload.len());
                let conn_string = &payload[pos..end];

                // Try to extract hostname from connection string
                if let Some(domain) = extract_domain_from_text(conn_string) {
                    return Some(domain);
                }
            }
        }

        // Try regular pattern matching
        for (pattern, context_length) in &patterns {
            if let Some(pos) = payload.find(pattern) {
                // Get surrounding context safely
                let start = pos.saturating_sub(*context_length);
                let end = (pos + pattern.len())
                    .saturating_add(*context_length)
                    .min(payload.len());

                if let Some(context) = payload.get(start..end) {
                    if let Some(domain) = extract_domain_from_text(context) {
                        return Some(domain);
                    }
                }
            }
        }

        // Fallback: scan the entire payload for domain patterns
        if let Some(domain) = extract_domain_from_text(&payload) {
            return Some(domain);
        }
    }

    None
}

fn extract_domain_from_text(text: &str) -> Option<String> {
    // Define domain patterns to match, ordered by specificity
    let domain_patterns = [".mongodb.koompi.cloud", "-mongodb-", ".mongodb."];

    for pattern in &domain_patterns {
        if let Some(pos) = text.find(pattern) {
            // Look backwards for the start of the domain (including service names)
            let start = text[..pos]
                .rfind(|c: char| !c.is_alphanumeric() && c != '-' && c != '.')
                .map_or(0, |i| i + 1);

            // Look forward for the end of the domain
            let end = pos
                + pattern.len()
                + text[pos + pattern.len()..]
                    .find(|c: char| !c.is_alphanumeric() && c != '-' && c != '.')
                    .unwrap_or(text[pos + pattern.len()..].len());

            let domain = text[start..end].trim();
            if !domain.is_empty() {
                // Add debug logging
                info!(
                    "Found domain pattern '{}' in text, extracted domain: {}",
                    pattern, domain
                );
                return Some(domain.to_string());
            }
        }
    }

    None
}

async fn handle_mongodb_connection(
    mut client_stream: TcpStream,
    client_addr: SocketAddr,
    domain_mappings: Arc<Mutex<HashMap<String, DatabaseMapping>>>,
    _original_dst: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Read initial data
    let mut buffer = vec![0u8; 4096];
    let n = client_stream.read(&mut buffer).await?;
    buffer.truncate(n);

    // Extract hostname from connection data
    let hostname = parse_mongodb_hostname(&buffer).or_else(|| {
        // Fallback: try to find domain pattern in raw data
        let text = String::from_utf8_lossy(&buffer);
        if let Some(pos) = text.find(".mongodb.koompi.cloud") {
            let start = pos.saturating_sub(50);
            let context = &text[start..pos];
            Some(context.to_string())
        } else {
            None
        }
    });

    let backend = match hostname {
        Some(host) => {
            let mappings = domain_mappings.lock().unwrap();
            mappings.values().find(|m| m.matches_domain(&host)).cloned()
        }
        None => None,
    };

    match backend {
        Some(mapping) => {
            info!(
                "Routing MongoDB connection to backend: {}:{}",
                mapping.target_host, mapping.target_port
            );

            let server_stream =
                TcpStream::connect(format!("{}:{}", mapping.target_host, mapping.target_port))
                    .await?;

            // Send initial data
            server_stream.writable().await?;
            server_stream.try_write(&buffer)?;

            // Proxy the connection
            proxy_connection(client_stream, server_stream, mapping.stats).await
        }
        None => {
            error!("No backend found for connection");
            Err("No matching backend found".into())
        }
    }
}

async fn check_mongodb_health(target: &str) -> bool {
    match TcpStream::connect(target).await {
        Ok(_) => true,
        Err(e) => {
            error!("MongoDB health check failed for {}: {}", target, e);
            false
        }
    }
}

// Define the missing constants that aren't in the libc crate
const SOL_IP: libc::c_int = 0;
const SO_ORIGINAL_DST: libc::c_int = 80;

// Alternative implementation that handles errors more gracefully
fn get_original_dst(socket: &TcpStream) -> Option<SocketAddr> {
    // Define the constants manually
    const SOL_IP: libc::c_int = 0;
    const SO_ORIGINAL_DST: libc::c_int = 80;

    let fd = socket.as_raw_fd();
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut addrlen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    let result = unsafe {
        libc::getsockopt(
            fd,
            SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut addrlen,
        )
    };

    if result == 0 {
        let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        let port = u16::from_be(addr.sin_port);
        Some(SocketAddr::new(std::net::IpAddr::V4(ip), port))
    } else {
        // Log the error and return None
        let err = std::io::Error::last_os_error();
        warn!("Failed to get original destination: {}", err);
        None
    }
}
