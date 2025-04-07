// src/proxy/tcp.rs
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use log::{error, info, warn};
use pingora::server::{Fds, ShutdownWatch};
use pingora::services::Service;
use std::io::{Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::Duration;

use crate::config::model::ConfigStore;
use byteorder::{ByteOrder, LittleEndian};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tokio::fs;

// MongoDB header structure for protocol parsing
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

    // Convert to string for logging
    pub fn to_string(&self) -> Option<String> {
        match self {
            DatabaseType::MongoDB => Some("MongoDB".to_string()),
            DatabaseType::PostgreSQL => Some("PostgreSQL".to_string()),
            DatabaseType::MySQL => Some("MySQL".to_string()),
            DatabaseType::Redis => Some("Redis".to_string()),
            DatabaseType::Unknown => None,
        }
    }

    // Detect database type from domain pattern
    pub fn detect_from_domain(domain: &str) -> Self {
        if domain.contains(".mongodb.") || domain.contains("-mongodb-") || domain.contains("mongo")
        {
            DatabaseType::MongoDB
        } else if domain.contains(".postgres.")
            || domain.contains(".postgresql.")
            || domain.contains("postgres")
        {
            DatabaseType::PostgreSQL
        } else if domain.contains(".mysql.") || domain.contains(".sql.") || domain.contains("mysql")
        {
            DatabaseType::MySQL
        } else if domain.contains(".redis.") || domain.contains("redis") {
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
    pub target_port: u16,       // Default MongoDB port
    pub db_type: DatabaseType,  // Type of database
    pub stats: Arc<Mutex<ConnectionStats>>,
    pub active_connections: Arc<AtomicUsize>, // Connection counter
}

impl DatabaseMapping {
    fn matches_domain(&self, domain: &str) -> bool {
        // Exact match
        if domain == self.domain_pattern {
            return true;
        }

        // Or it contains the pattern
        if domain.contains(&self.domain_pattern) {
            return true;
        }

        // Check if domain matches parts of the pattern
        // This helps with matching something like "riverbase-mongodb" when the user specifies "riverbase"
        let domain_parts: Vec<&str> = domain.split(|c| c == '.' || c == '-' || c == '_').collect();
        let pattern_parts: Vec<&str> = self
            .domain_pattern
            .split(|c| c == '.' || c == '-' || c == '_')
            .collect();

        // If domain parts are a subset of pattern parts
        let mut found_all = true;
        for part in &domain_parts {
            if !pattern_parts.contains(part) && !part.is_empty() {
                found_all = false;
                break;
            }
        }

        found_all
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
    pub fn add_rule(&mut self, database: &str, rule: IpRule) {
        self.rules
            .entry(database.to_string())
            .or_insert_with(HashSet::new)
            .insert(rule);
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
        if !storage_path.exists() {
            std::fs::create_dir_all(storage_path)?;
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
    ip_rules: Arc<tokio::sync::Mutex<DatabaseIpRules>>,
    proxy_mode: String,  // "direct" or "service-discovery"
    tcp_ports: Vec<u16>, // Ports to listen on
}

impl TcpProxyService {
    pub async fn new(
        servers: Arc<Mutex<ConfigStore>>,
        enable_tls: bool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Get proxy mode from environment variable
        let proxy_mode = std::env::var("TCP_PROXY_MODE").unwrap_or_else(|_| "direct".to_string());

        // Get ports from environment variable
        let ports_str =
            std::env::var("TCP_PROXY_PORTS").unwrap_or_else(|_| "27017,5432,3306".to_string());
        let tcp_ports: Vec<u16> = ports_str
            .split(',')
            .filter_map(|p| p.trim().parse::<u16>().ok())
            .collect();

        info!(
            "TCP Proxy initialized with mode: {}, ports: {:?}",
            proxy_mode, tcp_ports
        );

        Ok(Self {
            servers,
            db_mappings: Arc::new(Mutex::new(Vec::new())),
            enable_tls,
            ip_rules: Arc::new(tokio::sync::Mutex::new(
                DatabaseIpRules::new_with_storage().await?,
            )),
            proxy_mode,
            tcp_ports,
        })
    }

    // Initialize database mappings from config
    async fn initialize_mappings(&self) {
        info!("Initializing database mappings");

        // Create a new vec of mappings
        let mut mappings = Vec::new();

        // Lock the server config store
        if let Ok(servers) = self.servers.lock() {
            for (domain, (backend, _)) in servers.iter() {
                // Detect database type
                let db_type = DatabaseType::detect_from_domain(domain);

                // Skip non-database domains
                if db_type == DatabaseType::Unknown {
                    continue;
                }

                // Parse target backend (host:port)
                let parts: Vec<&str> = backend.split(':').collect();
                let (target_host, target_port) = if parts.len() > 1 {
                    (
                        parts[0].to_string(),
                        parts[1]
                            .parse::<u16>()
                            .unwrap_or_else(|_| db_type.default_port()),
                    )
                } else {
                    (parts[0].to_string(), db_type.default_port())
                };

                info!(
                    "Adding database mapping: domain_pattern='{}', target={}:{}, type={:?}",
                    domain, target_host, target_port, db_type
                );

                mappings.push(DatabaseMapping {
                    domain_pattern: domain.to_string(),
                    target_host,
                    target_port,
                    db_type,
                    stats: Arc::new(Mutex::new(ConnectionStats::default())),
                    active_connections: Arc::new(AtomicUsize::new(0)),
                });
            }
        }

        // Update the shared mappings
        if let Ok(mut db_mappings) = self.db_mappings.lock() {
            *db_mappings = mappings;
        }

        // Log what we found
        if let Ok(mappings) = self.db_mappings.lock() {
            info!("Initialized {} database mappings", mappings.len());
            for (i, mapping) in mappings.iter().enumerate() {
                info!(
                    "  [{}] Pattern '{}' -> {}:{} (Type: {:?})",
                    i,
                    mapping.domain_pattern,
                    mapping.target_host,
                    mapping.target_port,
                    mapping.db_type
                );
            }
        }
    }
}

#[async_trait]
impl Service for TcpProxyService {
    async fn start_service(
        &mut self,
        _fds: Option<Arc<tokio::sync::Mutex<Fds>>>,
        mut shutdown: ShutdownWatch,
    ) {
        info!("Starting TCP Proxy service for database connections");

        // Initialize mappings
        self.initialize_mappings().await;

        // Create shutdown channels for each listener
        let mut shutdown_senders = Vec::new();
        let mut listener_tasks = Vec::new();

        // Get references needed for the listeners
        let db_mappings = self.db_mappings.clone();
        let ip_rules = self.ip_rules.clone();

        // Start a listener for each port
        for &port in &self.tcp_ports {
            let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
            shutdown_senders.push(shutdown_tx);

            let db_mappings_clone = db_mappings.clone();
            let ip_rules_clone = ip_rules.clone();
            let proxy_mode = self.proxy_mode.clone();

            // Start the listener task
            let task = tokio::spawn(async move {
                start_db_listener(
                    port,
                    db_mappings_clone,
                    ip_rules_clone,
                    proxy_mode,
                    shutdown_rx,
                )
                .await;
            });

            listener_tasks.push(task);
        }

        // Wait for shutdown signal
        match shutdown.changed().await {
            Ok(_) => {
                if *shutdown.borrow() {
                    info!("Shutdown signal received, stopping TCP proxy");

                    // Send shutdown signal to all listeners
                    for tx in shutdown_senders {
                        let _ = tx.send(()).await;
                    }

                    // Wait for listeners to shut down with timeout
                    for task in listener_tasks {
                        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
                    }
                }
            }
            Err(e) => {
                error!("Error waiting for shutdown signal: {}", e);
            }
        }

        info!("TCP proxy service stopped");
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
            ip_rules: Arc::clone(&self.ip_rules),
            proxy_mode: self.proxy_mode.clone(),
            tcp_ports: self.tcp_ports.clone(),
        }
    }
}

// Start a listener for a specific database port
async fn start_db_listener(
    port: u16,
    db_mappings: Arc<Mutex<Vec<DatabaseMapping>>>,
    ip_rules: Arc<tokio::sync::Mutex<DatabaseIpRules>>,
    proxy_mode: String,
    mut shutdown_rx: mpsc::Receiver<()>,
) {
    // Determine database type from port
    let db_type = match port {
        27017 => DatabaseType::MongoDB,
        5432 => DatabaseType::PostgreSQL,
        3306 => DatabaseType::MySQL,
        6379 => DatabaseType::Redis,
        _ => DatabaseType::Unknown,
    };

    info!(
        "Starting {} listener on port {}",
        db_type.to_string().unwrap_or("database".to_string()),
        port
    );

    // Create a TCP listener
    let listener = match TcpListener::bind(format!("0.0.0.0:{}", port)).await {
        Ok(listener) => {
            info!("Successfully bound to 0.0.0.0:{}", port);
            listener
        }
        Err(e) => {
            error!("Failed to bind to port {}: {}", port, e);
            return;
        }
    };

    // Connection counter for logging
    let connection_count = Arc::new(AtomicUsize::new(0));

    // Accept loop
    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((client_stream, client_addr)) => {
                        let count = connection_count.fetch_add(1, Ordering::SeqCst);
                        info!("New database connection #{} from {} on port {}", count, client_addr, port);

                        // Clone needed data for the handler
                        let mappings = Arc::clone(&db_mappings);
                        let count_ref = Arc::clone(&connection_count);
                        let ip_rules_clone = Arc::clone(&ip_rules);
                        let proxy_mode_clone = proxy_mode.clone();

                        // Spawn a handler task
                        tokio::spawn(async move {
                            let db_type_str = match db_type {
                                DatabaseType::MongoDB => "MongoDB",
                                DatabaseType::PostgreSQL => "PostgreSQL",
                                DatabaseType::MySQL => "MySQL",
                                DatabaseType::Redis => "Redis",
                                DatabaseType::Unknown => "Unknown",
                            };

                            info!("Handling {} connection #{} from {}", db_type_str, count, client_addr);

                            let result = match db_type {
                                DatabaseType::MongoDB => {
                                    handle_mongodb_connection(
                                        client_stream,
                                        client_addr,
                                        mappings,
                                        ip_rules_clone,
                                        proxy_mode_clone,
                                    ).await
                                },
                                DatabaseType::PostgreSQL => {
                                    handle_postgres_connection(
                                        client_stream,
                                        client_addr,
                                        mappings,
                                        ip_rules_clone,
                                        proxy_mode_clone,
                                    ).await
                                },
                                DatabaseType::MySQL => {
                                    handle_mysql_connection(
                                        client_stream,
                                        client_addr,
                                        mappings,
                                        ip_rules_clone,
                                        proxy_mode_clone,
                                    ).await
                                },
                                _ => {
                                    // Default generic handler
                                    handle_generic_db_connection(
                                        client_stream,
                                        client_addr,
                                        db_type,
                                        mappings,
                                        ip_rules_clone,
                                        proxy_mode_clone,
                                    ).await
                                }
                            };

                            match result {
                                Ok(()) => info!("Successfully closed connection #{}", count),
                                Err(e) => error!("Error handling connection #{}: {}", count, e),
                            }

                            // Decrement active connection count
                            count_ref.fetch_sub(1, Ordering::SeqCst);
                        });
                    },
                    Err(e) => {
                        error!("Failed to accept connection on port {}: {}", port, e);
                        // Don't exit on accept errors, just continue
                    }
                }
            },
            _ = shutdown_rx.recv() => {
                info!("Received shutdown signal, stopping listener on port {}", port);
                break;
            }
        }
    }

    info!(
        "Listener on port {} stopped. Current connections: {}",
        port,
        connection_count.load(Ordering::SeqCst)
    );
}

// Generic database connection handler
async fn handle_generic_db_connection(
    mut client_stream: tokio::net::TcpStream,
    client_addr: SocketAddr,
    db_type: DatabaseType,
    db_mappings: Arc<Mutex<Vec<DatabaseMapping>>>,
    ip_rules: Arc<tokio::sync::Mutex<DatabaseIpRules>>,
    proxy_mode: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Read initial data
    let mut buffer = vec![0u8; 8192];
    let n = match client_stream.read(&mut buffer).await {
        Ok(n) if n == 0 => return Err("Client closed connection immediately".into()),
        Ok(n) => n,
        Err(e) => return Err(format!("Failed to read from client: {}", e).into()),
    };
    buffer.truncate(n);

    // Find backend based on client IP since we don't have protocol-specific extraction
    let (backend, mapping) = {
        let mappings = match db_mappings.lock() {
            Ok(guard) => guard,
            Err(e) => {
                error!("Failed to lock db_mappings: {}", e);
                return Err("Internal server error".into());
            }
        };

        // Try to find a backend for this database type
        match route_by_client_ip(&client_addr, &mappings, db_type) {
            Some((host, port, idx)) => {
                let mapping = mappings.get(idx).cloned();
                (Some((host, port)), mapping)
            }
            None => (None, None),
        }
    };

    match backend {
        Some((host, port)) => {
            info!(
                "Routing generic database connection from {} to {}:{}",
                client_addr, host, port
            );

            // Update connection stats if mapping available
            if let Some(m) = &mapping {
                m.active_connections.fetch_add(1, Ordering::SeqCst);
            }

            // Create connection to backend
            let mut server_stream = if proxy_mode == "service-discovery" {
                match connect_to_service(&host, port).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        // Decrement connection count on failure
                        if let Some(m) = &mapping {
                            m.active_connections.fetch_sub(1, Ordering::SeqCst);
                        }
                        return Err(format!("Failed to connect to service {}: {}", host, e).into());
                    }
                }
            } else {
                match connect_to_backend(&host, port).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        // Decrement connection count on failure
                        if let Some(m) = &mapping {
                            m.active_connections.fetch_sub(1, Ordering::SeqCst);
                        }
                        return Err(format!("Failed to connect to backend {}: {}", host, e).into());
                    }
                }
            };

            // Write the initial buffer to the server
            server_stream.write_all(&buffer[0..n]).await?;

            // Start proxying
            let result = proxy_bidirectional(client_stream, server_stream).await;

            // Update connection stats when done
            if let Some(m) = &mapping {
                m.active_connections.fetch_sub(1, Ordering::SeqCst);
            }

            result
        }
        None => {
            error!(
                "No backend found for generic database connection from {}",
                client_addr
            );
            Err("No matching backend found for this database connection".into())
        }
    }
}

// MongoDB-specific connection handler
async fn handle_mongodb_connection(
    mut client_stream: tokio::net::TcpStream,
    client_addr: SocketAddr,
    db_mappings: Arc<Mutex<Vec<DatabaseMapping>>>,
    ip_rules: Arc<tokio::sync::Mutex<DatabaseIpRules>>,
    proxy_mode: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Read initial data from client to extract database info
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

    // Extract database information from the MongoDB message
    let mut db_info = String::new();
    if let Some(info) = extract_database_info(&buffer[16..], header.op_code) {
        db_info = info;
        info!("Detected database info: {}", db_info);
    } else {
        warn!("Could not extract database info from MongoDB message");
    }

    // Check IP rules
    let db_name = db_info.clone();
    let client_ip = client_addr.ip().to_string();

    let ip_allowed = {
        let ip_rules_guard = ip_rules.lock().await;
        ip_rules_guard.is_ip_allowed(&db_name, &client_ip)
    };

    if !ip_allowed {
        error!(
            "IP {} is not allowed to access database {}",
            client_ip, db_name
        );
        return Err(format!("IP {} is not allowed to access this database", client_ip).into());
    }

    // Find backend based on the database info or client IP
    let (backend, mapping) =
        find_backend_for_connection(&db_info, &client_addr, &db_mappings, DatabaseType::MongoDB)?;

    match backend {
        Some((host, port)) => {
            info!(
                "Routing MongoDB connection from {} to {}:{}",
                client_addr, host, port
            );

            // Handle different connection modes
            let mut server_stream = if proxy_mode == "service-discovery" {
                // For service discovery mode, connect using Swarm DNS
                match connect_to_service(&host, port).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        return Err(format!("Failed to connect to service {}: {}", host, e).into())
                    }
                }
            } else {
                // Direct connection mode
                match connect_to_backend(&host, port).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        return Err(format!("Failed to connect to backend {}: {}", host, e).into())
                    }
                }
            };

            // Update connection stats if mapping available
            if let Some(m) = &mapping {
                m.active_connections.fetch_add(1, Ordering::SeqCst);
            }

            // Write the initial buffer to the server
            server_stream.write_all(&buffer[0..n]).await?;

            // Start proxying in both directions
            let result = proxy_bidirectional(client_stream, server_stream).await;

            // Update connection stats when done
            if let Some(m) = &mapping {
                m.active_connections.fetch_sub(1, Ordering::SeqCst);
            }

            result
        }
        None => {
            error!(
                "No backend found for MongoDB connection from {}",
                client_addr
            );
            Err("No matching backend found for this MongoDB connection".into())
        }
    }
}

// PostgreSQL connection handler (similar structure to MongoDB)
async fn handle_postgres_connection(
    mut client_stream: tokio::net::TcpStream,
    client_addr: SocketAddr,
    db_mappings: Arc<Mutex<Vec<DatabaseMapping>>>,
    ip_rules: Arc<tokio::sync::Mutex<DatabaseIpRules>>,
    proxy_mode: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Read initial data to extract database info
    let mut buffer = vec![0u8; 8192];
    let n = match client_stream.read(&mut buffer).await {
        Ok(n) if n == 0 => return Err("Client closed connection immediately".into()),
        Ok(n) => n,
        Err(e) => return Err(format!("Failed to read from client: {}", e).into()),
    };
    buffer.truncate(n);

    // Extract PostgreSQL database name from startup message
    let db_info = match extract_postgres_database(&buffer) {
        Ok(name) => Some(name),
        Err(_) => None,
    };

    if let Some(db_name) = &db_info {
        info!("Detected PostgreSQL database: {}", db_name);
    } else {
        warn!("Could not extract database name from PostgreSQL startup message");
    }

    // Find backend based on the database info or client IP
    let (backend, mapping) = find_backend_for_connection(
        &db_info.unwrap_or_default(),
        &client_addr,
        &db_mappings,
        DatabaseType::PostgreSQL,
    )?;

    match backend {
        Some((host, port)) => {
            // Similar implementation to MongoDB handler
            info!(
                "Routing PostgreSQL connection from {} to {}:{}",
                client_addr, host, port
            );

            // Update connection stats if mapping available
            if let Some(m) = &mapping {
                m.active_connections.fetch_add(1, Ordering::SeqCst);
            }

            // Create connection to backend
            let mut server_stream = if proxy_mode == "service-discovery" {
                match connect_to_service(&host, port).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        // Decrement connection count on failure
                        if let Some(m) = &mapping {
                            m.active_connections.fetch_sub(1, Ordering::SeqCst);
                        }
                        return Err(format!("Failed to connect to service {}: {}", host, e).into());
                    }
                }
            } else {
                match connect_to_backend(&host, port).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        // Decrement connection count on failure
                        if let Some(m) = &mapping {
                            m.active_connections.fetch_sub(1, Ordering::SeqCst);
                        }
                        return Err(format!("Failed to connect to backend {}: {}", host, e).into());
                    }
                }
            };

            // Write the initial buffer to the server
            server_stream.write_all(&buffer[0..n]).await?;

            // Start proxying
            let result = proxy_bidirectional(client_stream, server_stream).await;

            // Update connection stats when done
            if let Some(m) = &mapping {
                m.active_connections.fetch_sub(1, Ordering::SeqCst);
            }

            result
        }
        None => {
            error!(
                "No backend found for PostgreSQL connection from {}",
                client_addr
            );
            Err("No matching backend found for this PostgreSQL connection".into())
        }
    }
}

// MySQL connection handler
async fn handle_mysql_connection(
    mut client_stream: tokio::net::TcpStream,
    client_addr: SocketAddr,
    db_mappings: Arc<Mutex<Vec<DatabaseMapping>>>,
    ip_rules: Arc<tokio::sync::Mutex<DatabaseIpRules>>,
    proxy_mode: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Similar structure to other handlers
    let mut buffer = vec![0u8; 8192];
    let n = match client_stream.read(&mut buffer).await {
        Ok(n) if n == 0 => return Err("Client closed connection immediately".into()),
        Ok(n) => n,
        Err(e) => return Err(format!("Failed to read from client: {}", e).into()),
    };
    buffer.truncate(n);

    // Extract MySQL database name
    let db_info = match extract_mysql_database(&buffer) {
        Ok(name) => Some(name),
        Err(_) => None,
    };

    if let Some(db_name) = &db_info {
        info!("Detected MySQL database: {}", db_name);
    } else {
        warn!("Could not extract database name from MySQL startup message");
    }

    // Find backend based on the database info or client IP
    let (backend, mapping) = find_backend_for_connection(
        &db_info.unwrap_or_default(),
        &client_addr,
        &db_mappings,
        DatabaseType::MySQL,
    )?;

    match backend {
        Some((host, port)) => {
            info!(
                "Routing MySQL connection from {} to {}:{}",
                client_addr, host, port
            );

            // Create connection to backend
            let mut server_stream = if proxy_mode == "service-discovery" {
                match connect_to_service(&host, port).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        return Err(format!("Failed to connect to service {}: {}", host, e).into())
                    }
                }
            } else {
                match connect_to_backend(&host, port).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        return Err(format!("Failed to connect to backend {}: {}", host, e).into())
                    }
                }
            };

            // Write the initial buffer to the server
            server_stream.write_all(&buffer[0..n]).await?;

            // Start proxying
            proxy_bidirectional(client_stream, server_stream).await
        }
        None => {
            error!("No backend found for MySQL connection from {}", client_addr);
            Err("No matching backend found for this MySQL connection".into())
        }
    }
}

fn route_by_client_ip(
    client_addr: &SocketAddr,
    mappings: &Vec<DatabaseMapping>,
    db_type: DatabaseType,
) -> Option<(String, u16, usize)> {
    // Filter for mappings of the requested database type
    let filtered_mappings: Vec<(usize, &DatabaseMapping)> = mappings
        .iter()
        .enumerate()
        .filter(|(_, m)| m.db_type == db_type)
        .collect();

    if filtered_mappings.is_empty() {
        // If no mappings found for specific database type, try to find a default mapping
        let default_mappings: Vec<(usize, &DatabaseMapping)> = mappings
            .iter()
            .enumerate()
            .filter(|(_, m)| m.domain_pattern == "default" || m.domain_pattern == "*")
            .collect();

        if default_mappings.is_empty() {
            return None;
        }

        // Use the first default mapping
        let (idx, mapping) = default_mappings[0];
        return Some((mapping.target_host.clone(), mapping.target_port, idx));
    }

    // Generate hash from client IP
    let hash_value = match client_addr.ip() {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            octets.iter().enumerate().fold(0u64, |acc, (i, &octet)| {
                acc.wrapping_add((octet as u64) << (i * 8))
            })
        }
        IpAddr::V6(ipv6) => {
            // Better IPv6 handling - hash the entire address
            let segments = ipv6.segments();
            segments
                .iter()
                .enumerate()
                .fold(0u64, |acc, (i, &segment)| {
                    acc.wrapping_add((segment as u64) << (i * 16))
                })
        }
    };

    // Select backend using consistent hashing
    let (idx, mapping) = filtered_mappings[(hash_value as usize) % filtered_mappings.len()];
    Some((mapping.target_host.clone(), mapping.target_port, idx))
}

fn extract_database_info(payload: &[u8], op_code: i32) -> Option<String> {
    // First try standard protocol parsing
    let from_protocol = match op_code {
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
                        Some(collection[0..dot_pos].to_string())
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
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
            None
        }
        _ => None,
    };

    if from_protocol.is_some() {
        return from_protocol;
    }

    // Fallback to string-based parsing
    if let Ok(payload_str) = std::str::from_utf8(payload) {
        // Check for connection strings
        let patterns = [
            "mongodb+srv://",
            "mongodb://",
            ".mongodb.koompi.cloud",
            "-mongodb-",
        ];

        for pattern in patterns {
            if let Some(pos) = payload_str.find(pattern) {
                let start = pos;
                let end = payload_str[start..]
                    .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                    .map(|e| start + e)
                    .unwrap_or_else(|| payload_str.len());

                let mut extracted = &payload_str[start..end];

                // Clean up connection strings
                if extracted.starts_with("mongodb") {
                    extracted = extracted
                        .trim_start_matches("mongodb+srv://")
                        .trim_start_matches("mongodb://")
                        .split(|c| c == '@' || c == '/' || c == '?')
                        .next()
                        .unwrap_or(extracted);
                }

                return Some(extracted.to_string());
            }
        }
    }

    None
}

fn find_backend_for_connection(
    db_info: &str,
    client_addr: &SocketAddr,
    db_mappings: &Arc<Mutex<Vec<DatabaseMapping>>>,
    db_type: DatabaseType,
) -> Result<
    (Option<(String, u16)>, Option<DatabaseMapping>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let mappings = match db_mappings.lock() {
        Ok(guard) => guard,
        Err(e) => {
            error!("Failed to lock db_mappings: {}", e);
            return Err("Internal server error".into());
        }
    };

    // First try matching by database info if available
    if !db_info.is_empty() {
        if let Some((idx, mapping)) = mappings
            .iter()
            .enumerate()
            .find(|(_, m)| m.matches_domain(db_info))
        {
            info!(
                "Found mapping for database '{}' -> {}:{}",
                db_info, mapping.target_host, mapping.target_port
            );

            return Ok((
                Some((mapping.target_host.clone(), mapping.target_port)),
                Some(mapping.clone()),
            ));
        }

        // Fall back to default mapping for this database type
        if let Some((idx, mapping)) = mappings.iter().enumerate().find(|(_, m)| {
            m.db_type == db_type && (m.domain_pattern == "default" || m.domain_pattern == "*")
        }) {
            let db_type_str = db_type.to_string().unwrap_or_else(|| "Unknown".to_string());
            info!(
                "Using default {} mapping -> {}:{}",
                db_type_str, mapping.target_host, mapping.target_port
            );
            return Ok((
                Some((mapping.target_host.clone(), mapping.target_port)),
                Some(mapping.clone()),
            ));
        }
    }

    // If specific routing failed or we have no database info, try IP-based routing as last resort
    match route_by_client_ip(client_addr, &mappings, db_type) {
        Some((host, port, idx)) => {
            let mapping = mappings.get(idx).cloned();
            Ok((Some((host, port)), mapping))
        }
        None => Ok((None, None)),
    }
}

async fn connect_to_service(service: &str, port: u16) -> Result<TcpStream, std::io::Error> {
    // For Docker Swarm, use the tasks.<service_name> DNS pattern
    let service_name = if service.starts_with("tasks.") {
        service.to_string()
    } else {
        format!("tasks.{}", service)
    };

    connect_to_backend(&service_name, port).await
}

async fn connect_to_backend(host: &str, port: u16) -> Result<TcpStream, std::io::Error> {
    // Try to resolve the backend address
    let addr_str = format!("{}:{}", host, port);
    let addrs = tokio::net::lookup_host(&addr_str).await?;

    // Try each address until one connects
    let mut last_error = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_error = Some(e),
        }
    }

    // Return the last error if all connections failed
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("No addresses resolved for backend {}", host),
        )
    }))
}

async fn proxy_bidirectional(
    client_stream: tokio::net::TcpStream,
    server_stream: tokio::net::TcpStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client_addr = client_stream.peer_addr()?.to_string();
    let server_addr = server_stream.peer_addr()?.to_string();

    info!(
        "Established bidirectional proxy: {} <-> {}",
        client_addr, server_addr
    );

    let (mut client_read, mut client_write) = tokio::io::split(client_stream);
    let (mut server_read, mut server_write) = tokio::io::split(server_stream);

    let (client_done_tx, mut client_done_rx) = mpsc::channel::<()>(1);
    let (server_done_tx, mut server_done_rx) = mpsc::channel::<()>(1);

    let client_to_server = tokio::spawn(async move {
        let mut buffer = [0u8; 8192];
        let mut bytes_copied = 0;

        loop {
            match client_read.read(&mut buffer).await {
                Ok(0) => {
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

    let server_to_client = tokio::spawn(async move {
        let mut buffer = [0u8; 8192];
        let mut bytes_copied = 0;

        loop {
            match server_read.read(&mut buffer).await {
                Ok(0) => {
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

    tokio::select! {
        _ = client_done_rx.recv() => {
            info!("Client to server transfer completed");
        }
        _ = server_done_rx.recv() => {
            info!("Server to client transfer completed");
        }
    }

    client_to_server.abort();
    server_to_client.abort();

    info!("Connection closed: {} <-> {}", client_addr, server_addr);
    Ok(())
}

fn extract_mysql_database(
    buffer: &[u8],
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    if buffer.len() < 36 {
        return Err("Buffer too short for MySQL protocol".into());
    }

    // Skip the initial handshake packet length and sequence number (4 bytes)
    let mut pos = 4;

    // Skip protocol version (1 byte)
    pos += 1;

    // Skip server version (null-terminated string)
    while pos < buffer.len() && buffer[pos] != 0 {
        pos += 1;
    }
    pos += 1;

    // Skip connection id (4 bytes)
    pos += 4;

    // Try to find database name in connection attributes
    if let Ok(payload_str) = std::str::from_utf8(&buffer[pos..]) {
        if let Some(db_pos) = payload_str.find("database=") {
            let start = db_pos + 9; // length of "database="
            let end = payload_str[start..]
                .find(|c: char| c.is_whitespace() || c == ';')
                .map_or(payload_str.len(), |e| start + e);
            return Ok(payload_str[start..end].to_string());
        }
    }

    Err("Could not extract database name".into())
}

fn extract_postgres_database(
    buffer: &[u8],
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    if buffer.len() < 8 {
        return Err("Buffer too short for PostgreSQL startup message".into());
    }

    // First 4 bytes are message length, next 4 bytes are protocol version
    let length = ((buffer[0] as u32) << 24)
        | ((buffer[1] as u32) << 16)
        | ((buffer[2] as u32) << 8)
        | (buffer[3] as u32);

    if length < 8 || length as usize > buffer.len() {
        return Err("Invalid PostgreSQL message length".into());
    }

    // Look for "database" parameter in startup message
    if let Ok(payload_str) = std::str::from_utf8(&buffer[8..]) {
        if let Some(db_pos) = payload_str.find("database\0") {
            let value_start = db_pos + 9; // length of "database\0"
            if let Some(value_end) = payload_str[value_start..].find('\0') {
                return Ok(payload_str[value_start..(value_start + value_end)].to_string());
            }
        }
    }

    Err("Could not extract database name".into())
}
