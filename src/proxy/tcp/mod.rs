// src/proxy/tcp.rs
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use async_trait::async_trait;
use log::{error, info};
use openssl::ssl::{NameType, SslAcceptor, SslContext, SslFiletype, SslMethod, SslVerifyMode};
use pingora::server::{Fds, ShutdownWatch};
use pingora::services::Service;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::config::model::ConfigStore;
pub use db_proxy_main::setup_db_proxies;

pub mod db_proxy_main;
pub mod sni_utils;
pub mod tls_db_proxy;

// Database type enum with serialization support
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

    // Get standard listen port (single port per database type)
    pub fn listen_port(&self) -> u16 {
        self.default_port() // Use the same standard ports
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

// Connection statistics that can be serialized
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ConnectionStats {
    pub active_connections: usize,
    pub total_connections: usize,
    pub bytes_in: usize,
    pub bytes_out: usize,
}

// Database host mapping with serializable stats
#[derive(Clone, Serialize, Deserialize)]
pub struct DatabaseMapping {
    pub target_host: String,
    pub target_port: u16,
    pub db_type: DatabaseType,
    pub tls_config: Option<TlsConfig>,
    #[serde(skip)] // Skip serialization of the stats mutex
    pub stats: Arc<Mutex<ConnectionStats>>,
}

// TLS configuration
#[derive(Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub ca_path: Option<String>,
}

impl DatabaseMapping {
    pub fn new(domain: String, target: String) -> Self {
        let db_type = DatabaseType::detect_from_domain(&domain);
        let parts: Vec<&str> = target.split(':').collect();
        let (target_host, target_port) = if parts.len() > 1 {
            (
                parts[0].to_string(),
                parts[1].parse().unwrap_or(db_type.default_port()),
            )
        } else {
            (parts[0].to_string(), db_type.default_port())
        };

        DatabaseMapping {
            target_host,
            target_port,
            db_type,
            tls_config: None,
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
        tokio::fs::write(reload_path, now.to_string()).await?;

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
                tokio::fs::write(reload_path, now.to_string()).await?;
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
        tokio::fs::write(&temp_path, json).await?;

        // Rename temporary file to actual file (atomic operation)
        tokio::fs::rename(&temp_path, &file_path).await?;

        Ok(())
    }

    pub async fn load_from_storage(
        &mut self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let file_path = std::path::Path::new("/pingora-proxy/storage/ip_rules.json");

        if file_path.exists() {
            let content = tokio::fs::read_to_string(file_path).await?;
            self.rules = serde_json::from_str(&content)?;
        }

        Ok(())
    }
}

// TCP Proxy Service with TLS SNI Support
pub struct TcpProxyService {
    servers: Arc<tokio::sync::Mutex<ConfigStore>>,
    db_mappings: Arc<Mutex<HashMap<String, DatabaseMapping>>>,
    enable_tls: bool,
    ip_rules: DatabaseIpRules,
    // Certificate store per database type
    cert_contexts: Arc<Mutex<HashMap<DatabaseType, HashMap<String, SslContext>>>>,
}

impl TcpProxyService {
    pub async fn new(
        servers: Arc<tokio::sync::Mutex<ConfigStore>>,
        enable_tls: bool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self {
            servers,
            db_mappings: Arc::new(Mutex::new(HashMap::new())),
            enable_tls,
            ip_rules: DatabaseIpRules::new_with_storage().await?,
            cert_contexts: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    // Initialize database mappings from config
    async fn initialize_mappings(&self) {
        info!("Initializing database mappings");

        // Lock the mappings for update
        let mut db_mappings = match self.db_mappings.lock().await {
            mappings => mappings,
        };
        db_mappings.clear();

        // Get access to the server config store
        if let mut servers = self.servers.lock().await {
            // Group mappings by database type to properly set up SNI routing
            let mut db_type_domains: HashMap<DatabaseType, Vec<(String, String)>> = HashMap::new();

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
                    let db_type = mapping.db_type;

                    // Group by database type
                    db_type_domains
                        .entry(db_type)
                        .or_default()
                        .push((domain.clone(), backend.clone()));

                    info!(
                        "Adding database mapping: {} -> {}:{} (type: {:?})",
                        domain, mapping.target_host, mapping.target_port, mapping.db_type
                    );

                    db_mappings.insert(domain.clone(), mapping);
                }
            }

            // Initialize TLS contexts for each database type if TLS is enabled
            if self.enable_tls {
                info!("Initializing TLS contexts for database connections");
                self.initialize_tls_contexts(&db_type_domains).await;
            }
        }

        info!("Initialized {} database mappings", db_mappings.len());
        // db_mappings is dropped here, releasing the lock
    }

    // Initialize TLS contexts for SNI routing
    async fn initialize_tls_contexts(
        &self,
        db_type_domains: &HashMap<DatabaseType, Vec<(String, String)>>,
    ) {
        // Lock the cert contexts for update
        let mut cert_contexts = match self.cert_contexts.lock().await {
            contexts => contexts,
        };

        // For each database type, initialize the contexts
        for (db_type, domains) in db_type_domains {
            let mut type_contexts = HashMap::new();

            for (domain, _) in domains {
                // Look for certificates in common locations
                let cert_path = format!("/certbot/letsencrypt/live/{}/fullchain.pem", domain);
                let key_path = format!("/certbot/letsencrypt/live/{}/privkey.pem", domain);

                if std::path::Path::new(&cert_path).exists()
                    && std::path::Path::new(&key_path).exists()
                {
                    match self.create_ssl_context(&cert_path, &key_path) {
                        Ok(context) => {
                            info!("Created TLS context for database domain: {}", domain);
                            type_contexts.insert(domain.clone(), context);
                        }
                        Err(e) => {
                            error!("Failed to create TLS context for {}: {}", domain, e);
                        }
                    }
                } else {
                    info!("No certificate found for database domain: {}", domain);
                }
            }

            // Store the contexts for this database type
            if !type_contexts.is_empty() {
                cert_contexts.insert(*db_type, type_contexts);
            }
        }
    }

    // Create SSL context from certificate and key files
    fn create_ssl_context(
        &self,
        cert_path: &str,
        key_path: &str,
    ) -> Result<SslContext, Box<dyn std::error::Error + Send + Sync>> {
        let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls())?;

        // Set up certificate and key
        builder.set_certificate_file(cert_path, SslFiletype::PEM)?;
        builder.set_private_key_file(key_path, SslFiletype::PEM)?;
        builder.check_private_key()?;

        // Set up SNI callback
        builder.set_servername_callback(|ssl_ref, _alert| {
            if let Some(servername) = ssl_ref.servername(NameType::HOST_NAME) {
                info!("SNI hostname received: {}", servername);
            }
            Ok(())
        });

        // Additional TLS settings
        builder.set_verify(SslVerifyMode::NONE); // Don't verify client certificates

        Ok(builder.build().into_context())
    }

    // Find SSL context based on SNI hostname
    async fn find_ssl_context(&self, db_type: DatabaseType, hostname: &str) -> Option<SslContext> {
        let cert_contexts = match self.cert_contexts.lock().await {
            contexts => contexts,
        };

        if let Some(type_contexts) = cert_contexts.get(&db_type) {
            // Try exact match first
            if let Some(context) = type_contexts.get(hostname) {
                return Some(context.clone());
            }

            // Try wildcard match if no exact match found
            for (domain, context) in type_contexts.iter() {
                if domain.starts_with("*.") {
                    let wildcard_suffix = &domain[1..]; // Remove the "*"
                    if hostname.ends_with(wildcard_suffix) {
                        return Some(context.clone());
                    }
                }
            }

            // If no match found, return the first context as fallback
            if let Some((_, context)) = type_contexts.iter().next() {
                return Some(context.clone());
            }
        }

        None
    }

    // Run a TLS-enabled TCP proxy for a specific database type
    async fn run_tls_proxy(
        &self,
        db_type: DatabaseType,
        listen_port: u16,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listen_addr = format!("0.0.0.0:{}", listen_port);

        info!(
            "Starting TLS Proxy for {:?} database connections on {}",
            db_type, listen_addr
        );

        let listener = TcpListener::bind(&listen_addr).await?;

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((client_stream, client_addr)) => {
                            info!("Accepted connection from {} on {:?} port", client_addr, db_type);

                            // Clone required arc references
                            let db_mappings = Arc::clone(&self.db_mappings);
                            let cert_contexts = Arc::clone(&self.cert_contexts);
                            let ip_rules = self.ip_rules.clone();
                            let self_clone = self.clone();

                            // Spawn a new task to handle the TLS connection
                            tokio::spawn(async move {
                                if let Err(e) = self_clone.handle_tls_connection(
                                    client_stream,
                                    client_addr.ip().to_string(),
                                    db_type,
                                    db_mappings,
                                    cert_contexts,
                                    ip_rules,
                                ).await {
                                    error!("Error handling TLS connection: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Error accepting connection: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Shutting down TLS proxy for {:?}", db_type);
                    break;
                }
            }
        }

        Ok(())
    }

    // Handle a TLS connection with SNI routing
    async fn handle_tls_connection(
        &self,
        client_stream: TcpStream,
        client_ip: String,
        db_type: DatabaseType,
        db_mappings: Arc<Mutex<HashMap<String, DatabaseMapping>>>,
        cert_contexts: Arc<Mutex<HashMap<DatabaseType, HashMap<String, SslContext>>>>,
        ip_rules: DatabaseIpRules,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut peek_buf = [0u8; 1024];
        let peek_size = client_stream.peek(&mut peek_buf).await?;

        // Extract SNI hostname from ClientHello
        let sni_hostname = match extract_sni_hostname(&peek_buf[..peek_size]) {
            Some(hostname) => {
                info!("SNI hostname extracted: {}", hostname);
                hostname
            }
            None => {
                // For MongoDB, use default mapping when SNI is not provided
                if db_type == DatabaseType::MongoDB {
                    let mappings = db_mappings.lock().await;
                    let default_mapping = mappings
                        .iter()
                        .find(|(k, _)| k.contains("mongodb"))
                        .map(|(k, _)| k.clone());

                    match default_mapping {
                        Some(hostname) => {
                            info!("Using default MongoDB mapping: {}", hostname);
                            hostname
                        }
                        None => {
                            error!("No default MongoDB mapping available");
                            return Err(Box::new(std::io::Error::new(
                                std::io::ErrorKind::NotFound,
                                "No default MongoDB mapping available",
                            )));
                        }
                    }
                } else {
                    error!("No SNI hostname found in TLS ClientHello");
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "No SNI hostname in TLS ClientHello",
                    )));
                }
            }
        };

        // Check IP rules for this domain
        if !ip_rules.is_ip_allowed(&sni_hostname, &client_ip) {
            error!(
                "Connection rejected - unauthorized IP {} for database {}",
                client_ip, sni_hostname
            );
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "IP not authorized for this database",
            )));
        }

        // Get mapping for this hostname
        let mapping = {
            let mappings = match db_mappings.lock().await {
                m => m,
            };

            if let Some(mapping) = mappings.get(&sni_hostname) {
                mapping.clone()
            } else {
                error!("No mapping found for hostname: {}", sni_hostname);
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "No database mapping found for hostname",
                )));
            }
        };

        // Connect to the target backend database
        let backend_addr = format!("{}:{}", mapping.target_host, mapping.target_port);
        let backend_stream = match TcpStream::connect(&backend_addr).await {
            Ok(stream) => stream,
            Err(e) => {
                error!("Failed to connect to backend {}: {}", backend_addr, e);
                return Err(Box::new(e));
            }
        };

        // Set up bidirectional proxy
        let (mut client_read, mut client_write) = tokio::io::split(client_stream);
        let (mut backend_read, mut backend_write) = tokio::io::split(backend_stream);

        // Update connection stats
        {
            let mut stats = mapping.stats.lock().await;
            stats.active_connections += 1;
            stats.total_connections += 1;
        }

        // Set up channels for signaling completion
        let (client_done_tx, mut client_done_rx) = mpsc::channel::<()>(1);
        let (backend_done_tx, mut backend_done_rx) = mpsc::channel::<()>(1);

        // Clone stats for tasks
        let stats_clone1 = mapping.stats.clone();
        let stats_clone2 = mapping.stats.clone();

        // Forward client -> backend
        let client_to_backend = tokio::spawn(async move {
            let mut buffer = [0u8; 8192];
            let mut total_bytes = 0;

            loop {
                match client_read.read(&mut buffer).await {
                    Ok(0) => break, // Connection closed
                    Ok(n) => {
                        if let Err(e) = backend_write.write_all(&buffer[..n]).await {
                            error!("Error writing to backend: {}", e);
                            break;
                        }
                        total_bytes += n;
                    }
                    Err(e) => {
                        error!("Error reading from client: {}", e);
                        break;
                    }
                }
            }

            // Update stats
            let mut stats = stats_clone1.lock().await;
            stats.bytes_in += total_bytes;
            stats.active_connections = stats.active_connections.saturating_sub(1);

            let _ = client_done_tx.send(()).await;
        });

        // Forward backend -> client
        let backend_to_client = tokio::spawn(async move {
            let mut buffer = [0u8; 8192];
            let mut total_bytes = 0;

            loop {
                match backend_read.read(&mut buffer).await {
                    Ok(0) => break, // Connection closed
                    Ok(n) => {
                        if let Err(e) = client_write.write_all(&buffer[..n]).await {
                            error!("Error writing to client: {}", e);
                            break;
                        }
                        total_bytes += n;
                    }
                    Err(e) => {
                        error!("Error reading from backend: {}", e);
                        break;
                    }
                }
            }

            // Update stats
            let mut stats = stats_clone2.lock().await;
            stats.bytes_out += total_bytes;

            let _ = backend_done_tx.send(()).await;
        });

        // Wait for either direction to complete
        tokio::select! {
            _ = client_done_rx.recv() => {
                info!("Client -> Backend completed for hostname: {}", sni_hostname);
            }
            _ = backend_done_rx.recv() => {
                info!("Backend -> Client completed for hostname: {}", sni_hostname);
            }
        }

        // Clean up tasks
        client_to_backend.abort();
        backend_to_client.abort();

        info!("Connection closed for hostname: {}", sni_hostname);
        Ok(())
    }

    // Modified reload check to include file watching
    async fn check_reload_needed(&self) -> bool {
        let reload_path = std::path::Path::new("/pingora-proxy/locks/ip_rules_reload");

        if reload_path.exists() {
            if let Ok(content) = tokio::fs::read_to_string(reload_path).await {
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

// Clone trait implementation
impl Clone for TcpProxyService {
    fn clone(&self) -> Self {
        Self {
            servers: Arc::clone(&self.servers),
            db_mappings: Arc::clone(&self.db_mappings),
            enable_tls: self.enable_tls,
            ip_rules: self.ip_rules.clone(),
            cert_contexts: Arc::clone(&self.cert_contexts),
        }
    }
}

// Extract SNI hostname from TLS ClientHello (simplified implementation)
fn extract_sni_hostname(data: &[u8]) -> Option<String> {
    // This is a simplified SNI extraction - in real code, you would use a TLS library
    // to properly parse the ClientHello packet

    // Check for valid TLS handshake
    if data.len() < 5 || data[0] != 0x16 {
        // Not a handshake
        return None;
    }

    // Basic sanity checks
    if data[1] != 0x03 || data[2] > 0x03 {
        // Not TLS 1.0-1.2
        return None;
    }

    // Skip the TLS record header (5 bytes) and handshake header (4 bytes)
    let mut pos = 9;

    // Skip client random (32 bytes)
    pos += 32;

    // Skip session ID
    if pos < data.len() {
        let session_id_len = data[pos] as usize;
        pos += 1 + session_id_len;
    }

    // Skip cipher suites
    if pos + 1 < data.len() {
        let cipher_suites_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
        pos += 2 + cipher_suites_len;
    }

    // Skip compression methods
    if pos < data.len() {
        let compression_methods_len = data[pos] as usize;
        pos += 1 + compression_methods_len;
    }

    // Check if we have extensions
    if pos + 2 > data.len() {
        return None;
    }

    // Get extensions length
    let extensions_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
    pos += 2;

    // End position of extensions
    let ext_end = pos + extensions_len;

    // Iterate through extensions
    while pos + 4 <= ext_end && pos + 4 <= data.len() {
        let ext_type = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);
        let ext_len = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
        pos += 4;

        if ext_type == 0 {
            // SNI extension
            if pos + 2 <= ext_end && pos + 2 <= data.len() {
                // Skip SNI list length
                let sni_list_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
                pos += 2;

                if pos < ext_end && pos < data.len() {
                    let name_type = data[pos];
                    pos += 1;

                    if name_type == 0 && pos + 2 <= ext_end && pos + 2 <= data.len() {
                        // Host name type
                        let name_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
                        pos += 2;

                        if pos + name_len <= ext_end && pos + name_len <= data.len() {
                            // Extract hostname
                            if let Ok(hostname) = std::str::from_utf8(&data[pos..pos + name_len]) {
                                return Some(hostname.to_string());
                            }
                        }
                    }
                }
            }
            break;
        }

        // Skip to next extension
        pos += ext_len;
    }

    None
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

        // Create shutdown channels for each database type proxy
        let mut shutdown_channels = Vec::new();

        if self.enable_tls {
            // Start a proxy for each database type
            for db_type in [
                DatabaseType::MongoDB,
                DatabaseType::PostgreSQL,
                DatabaseType::MySQL,
                DatabaseType::Redis,
            ]
            .iter()
            {
                let (tx, rx) = mpsc::channel::<()>(1);
                shutdown_channels.push(tx);

                let listen_port = db_type.listen_port();
                let self_clone = self.clone();
                let db_type_clone = *db_type;

                tokio::spawn(async move {
                    if let Err(e) = self_clone
                        .run_tls_proxy(db_type_clone, listen_port, rx)
                        .await
                    {
                        error!("TLS proxy for {:?} failed: {}", db_type_clone, e);
                    }
                });
            }

            info!("Started TLS-enabled database proxies on standard ports");
        } else {
            error!("TLS is disabled, SNI routing will not be available. Enable TCP_PROXY_TLS for SNI routing.");
        }

        // Periodically check for config changes and update mappings
        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                // Check for shutdown signal
                result = shutdown.changed() => {
                    if result.is_ok() && *shutdown.borrow() {
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
                    // Reinitialize mappings if needed
                    self.initialize_mappings().await;

                    // Check for IP rules reload
                    if self.check_reload_needed().await {
                        info!("IP rules change detected, reloading rules");
                        if let Err(e) = self.ip_rules.load_from_storage().await {
                            error!("Failed to reload IP rules: {}", e);
                        }
                    }
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
