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
    public_port: u16,
    target_host: String,
    target_port: u16,
    db_type: DatabaseType,
    stats: Arc<Mutex<ConnectionStats>>,
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
                                public_port: 27017, // All MongoDB instances use the same port
                                target_host,
                                target_port,
                                db_type,
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

        // Create a channel for graceful shutdown
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

        // Shared domain mappings
        let shared_mappings = Arc::new(Mutex::new(domain_mappings));

        // Spawn a task to handle accepting connections
        let accept_task_handle = tokio::spawn(async move {
            let mut shutdown_rx = shutdown_rx; // Make shutdown_rx mutable here
            loop {
                // Check for shutdown signal
                if shutdown_rx.try_recv().is_ok() {
                    info!("Shutting down MongoDB proxy listener");
                    break;
                }

                // Accept with timeout to check for shutdown periodically
                let accept_future = listener.accept();
                let timeout = tokio::time::sleep(Duration::from_secs(1));

                tokio::select! {
                    accept_result = accept_future => {
                        match accept_result {
                            Ok((client_stream, client_addr)) => {
                                info!("New MongoDB connection from {}", client_addr);

                                // Get original destination before creating the connection handler
                                let original_dst = match get_original_dst(&client_stream) {
                                    Some(addr) => {
                                        info!("Original destination was: {}", addr);
                                        addr
                                    },
                                    None => {
                                        warn!("Could not get original destination for connection");
                                        client_stream.local_addr().unwrap_or_else(|_| {
                                            SocketAddr::new(
                                                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                                                27017
                                            )
                                        })
                                    }
                                };

                                // Clone the mappings data OUTSIDE the spawned task
                                let mappings_clone = Arc::clone(&shared_mappings);
                                let mappings_data = {
                                    let guard = mappings_clone.lock().unwrap();
                                    let cloned_data = guard.clone();
                                    cloned_data
                                };

                                // Create a new Arc<Mutex<>> with the cloned data
                                let task_mappings = Arc::new(Mutex::new(mappings_data));

                                // Clone the necessary data before spawning the task
                                let task_mappings_clone = Arc::clone(&task_mappings);
                                tokio::spawn(async move {
                                    if let Err(e) = handle_mongodb_connection(
                                        client_stream,
                                        client_addr,
                                        task_mappings_clone,
                                        original_dst, // Pass the original destination
                                    ).await {
                                        error!("Error handling MongoDB connection: {}", e);
                                    }
                                });
                            }
                            Err(e) => {
                                error!("Error accepting MongoDB connection: {}", e);
                            }
                        }
                    }
                    _ = timeout => {
                        continue;
                    }
                }
            }
        });

        info!("MongoDB proxy listener stopped");

        // Wait for shutdown signal
        if let Ok(_) = shutdown.changed().await {
            if *shutdown.borrow() {
                info!("Shutdown signal received, stopping MongoDB proxy");

                // Signal the accept task to stop
                let _ = shutdown_tx.send(()).await;

                // Wait for the accept task to complete
                let _ = tokio::time::timeout(Duration::from_secs(5), accept_task_handle).await;
            }
        } else {
            // Just await the task directly if shutdown channel is closed
            let _ = accept_task_handle.await;
            info!("MongoDB proxy accept task completed unexpectedly");
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

// Helper function to parse the MongoDB wire protocol and extract the hostname
fn parse_mongodb_hostname(data: &[u8]) -> Option<String> {
    // This is a simplified parser for the MongoDB wire protocol
    // In a real implementation, you would need to follow the MongoDB wire protocol specification

    // MongoDB messages start with a header:
    // messageLength (4 bytes) + requestID (4 bytes) + responseTo (4 bytes) + opCode (4 bytes)

    // We need at least 16 bytes for the header
    if data.len() < 16 {
        return None;
    }

    // isMaster command is typically used for handshakes
    // Look for "isMaster" or "ismaster" strings in the payload
    let payload = std::str::from_utf8(&data[16..]).ok()?;

    // Look for typical database connection strings or hostnames
    // This is a simplified approach - a real implementation would properly parse BSON

    // Look for domain names that match our MongoDB patterns
    let patterns = ["mongodb.koompi.cloud", "selendra.mongodb", ".mongodb."];

    for pattern in &patterns {
        if let Some(pos) = payload.find(pattern) {
            // Find the start of the hostname (likely before the pattern)
            let start_pos = payload[..pos]
                .rfind(&[' ', '"', '\'', ':', ',', '{', '}', '[', ']'][..])
                .unwrap_or(0);

            // Find the end of the hostname (likely after the pattern)
            let end_pos = pos
                + pattern.len()
                + payload[pos + pattern.len()..]
                    .find(&[' ', '"', '\'', ':', ',', '{', '}', '[', ']'][..])
                    .unwrap_or(0);

            // Extract the hostname
            let hostname = payload[start_pos..end_pos].trim_matches(|c| " \"':,{}[]".contains(c));

            if !hostname.is_empty() {
                return Some(hostname.to_string());
            }
        }
    }

    // Alternative approach: extract anything that looks like a domain name
    let domain_regex =
        regex::Regex::new(r"[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+").ok()?;
    if let Some(captures) = domain_regex.captures(payload) {
        if let Some(domain) = captures.get(0) {
            return Some(domain.as_str().to_string());
        }
    }

    None
}

// Helper function to extract hostname from MongoDB message
fn extract_hostname_from_mongodb_message(buffer: &[u8]) -> Option<String> {
    // Try to read the message as a string
    if let Ok(payload_str) = std::str::from_utf8(&buffer[16..]) {
        // Look for MongoDB connection strings
        let connection_patterns = ["mongodb://"];

        for pattern in &connection_patterns {
            if let Some(pos) = payload_str.find(pattern) {
                // Find the auth separator (@)
                if let Some(auth_pos) = payload_str[pos..].find('@') {
                    // The hostname starts after the @ symbol
                    let hostname_start = pos + auth_pos + 1;

                    // Find the end of the hostname (next / or ? or whitespace)
                    let mut hostname_end = payload_str.len();
                    for end_char in &['/', '?', ' ', '"', '\''] {
                        if let Some(end_pos) = payload_str[hostname_start..].find(*end_char) {
                            let candidate_end = hostname_start + end_pos;
                            if candidate_end < hostname_end {
                                hostname_end = candidate_end;
                            }
                        }
                    }

                    if hostname_end > hostname_start {
                        // Extract the hostname part
                        let hostname = &payload_str[hostname_start..hostname_end];

                        // Remove port if present
                        if let Some(port_pos) = hostname.find(':') {
                            return Some(hostname[0..port_pos].to_string());
                        } else {
                            return Some(hostname.to_string());
                        }
                    }
                }
            }
        }

        // Alternatively, directly search for your specific domain patterns
        let domain_patterns = [".selendra.mongodb.koompi.cloud"];

        for pattern in &domain_patterns {
            if let Some(pos) = payload_str.find(pattern) {
                // Find the start of the hostname (look for alphanumeric/period/dash characters)
                let mut start_pos = pos;
                while start_pos > 0 {
                    let prev_char = payload_str.as_bytes()[start_pos - 1] as char;
                    if prev_char.is_alphanumeric() || prev_char == '.' || prev_char == '-' {
                        start_pos -= 1;
                    } else {
                        break;
                    }
                }

                // Extract the hostname
                let hostname = &payload_str[start_pos..(pos + pattern.len())];
                return Some(hostname.to_string());
            }
        }
    }

    None
}

// Extract hostname based on client's IP address and known mappings
async fn extract_hostname_from_client_addr(
    client_addr: &SocketAddr,
    domain_mappings: &Arc<Mutex<HashMap<String, DatabaseMapping>>>,
) -> Option<String> {
    // Get the original destination address that the client was trying to connect to
    if let Ok(sock) = TcpStream::connect(client_addr).await {
        if let Ok(orig_dst) = sock.peer_addr() {
            // Convert the original destination to a string and perform lookup
            let lookup_result = tokio::net::lookup_host(orig_dst.to_string()).await;

            if let Ok(hostnames) = lookup_result {
                // Check if any of the hostnames match our mappings
                let mappings = domain_mappings.lock().unwrap();
                for addr in hostnames {
                    let hostname = addr.to_string();
                    if mappings.contains_key(&hostname) {
                        return Some(hostname);
                    }
                }
            }
        }
    }
    None
}

// New function to handle MongoDB connections
async fn handle_mongodb_connection(
    mut client_stream: TcpStream,
    client_addr: SocketAddr,
    domain_mappings: Arc<Mutex<HashMap<String, DatabaseMapping>>>,
    original_dst: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!(
        "Handling MongoDB connection from {} (original destination: {})",
        client_addr, original_dst
    );

    // Read a small buffer just to have something to start with
    let mut length_buffer = [0u8; 4];

    // Try to read at least the initial message length
    if let Err(e) = client_stream.read_exact(&mut length_buffer).await {
        return Err(Box::new(e));
    }

    // First try to get the hostname without holding the lock
    let hostname_result = extract_hostname_from_client_addr(&client_addr, &domain_mappings).await;

    // Get all available mappings
    let available_backends = {
        // Now acquire the lock for a short scope
        let mappings = domain_mappings.lock().unwrap();

        // Log available mappings for debugging
        info!("Available MongoDB mappings:");
        for (domain, mapping) in mappings.iter() {
            info!(
                "  {} -> {}:{}",
                domain, mapping.target_host, mapping.target_port
            );
        }

        // Get the hostname the client is trying to connect to - we already got it above
        if let Some(hostname) = hostname_result {
            // Look for exact match in our mappings
            if let Some(mapping) = mappings.get(&hostname) {
                info!("Found matching backend for hostname {}", hostname);
                Ok((hostname, mapping.clone()))
            } else {
                // If no match found, log warning and fall back to default
                warn!("No matching backend found for client connection, using default");
                mappings
                    .iter()
                    .next()
                    .map(|(d, m)| (d.clone(), m.clone()))
                    .ok_or_else(|| {
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "No MongoDB backends configured",
                        ))
                    })
            }
        } else {
            // If no hostname found, fall back to default
            warn!("No hostname detected for client connection, using default");
            mappings
                .iter()
                .next()
                .map(|(d, m)| (d.clone(), m.clone()))
                .ok_or_else(|| {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "No MongoDB backends configured",
                    ))
                })
        }
    }; // Lock is dropped here at end of block

    // Default to the first available mapping if we can't determine anything else
    let (hostname, backend) = match available_backends {
        Ok((domain, mapping)) => {
            info!(
                "Using default MongoDB backend for {}: {}:{}",
                domain, mapping.target_host, mapping.target_port
            );
            (domain, mapping)
        }
        Err(e) => {
            return Err(e);
        }
    };

    // Connect to the backend
    let backend_addr = format!("{}:{}", backend.target_host, backend.target_port);
    info!("Routing MongoDB connection to backend: {}", backend_addr);

    let mut server_stream = match TcpStream::connect(&backend_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            error!("Failed to connect to backend {}: {}", backend_addr, e);
            return Err(Box::new(e));
        }
    };

    // Forward the initial message to the backend
    let mut buffer = vec![0u8; 4];
    buffer.copy_from_slice(&length_buffer);

    if let Err(e) = server_stream.write_all(&buffer).await {
        return Err(Box::new(e));
    }

    // Now set up bidirectional proxy
    info!("Setting up bidirectional proxy between client and MongoDB backend");
    proxy_connection(client_stream, server_stream, backend.stats.clone()).await
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
