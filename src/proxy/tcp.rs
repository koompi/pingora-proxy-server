// src/proxy/tcp.rs
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use log::{error, info};
use pingora::server::{Fds, ShutdownWatch};
use pingora::services::Service;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::Duration;

use crate::config::model::ConfigStore;

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

// TCP Proxy Service
pub struct TcpProxyService {
    servers: Arc<Mutex<ConfigStore>>,
    db_mappings: Arc<Mutex<HashMap<String, DatabaseMapping>>>,
    enable_tls: bool,
}

impl TcpProxyService {
    pub fn new(servers: Arc<Mutex<ConfigStore>>, enable_tls: bool) -> Self {
        Self {
            servers,
            db_mappings: Arc::new(Mutex::new(HashMap::new())),
            enable_tls,
        }
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

                    // Determine public port (same as target port by default)
                    let public_port = target_port;

                    info!(
                        "Adding database mapping: {} -> {}:{} (type: {:?})",
                        domain, target_host, target_port, db_type
                    );

                    db_mappings.insert(
                        domain.clone(),
                        DatabaseMapping {
                            public_port,
                            target_host,
                            target_port,
                            db_type,
                            stats: Arc::new(Mutex::new(ConnectionStats::default())),
                        },
                    );
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

    // Run a regular TCP proxy for the given mapping
    async fn run_tcp_proxy(
        &self,
        domain_name: String,
        public_port: u16,
        target_host: String,
        target_port: u16,
        db_type: DatabaseType,
        stats: Arc<Mutex<ConnectionStats>>,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listen_addr = format!("0.0.0.0:{}", public_port);
        let target_addr = format!("{}:{}", target_host, target_port);

        info!(
            "Starting TCP proxy for {} on {}, forwarding to {}",
            domain_name, listen_addr, target_addr
        );

        let listener = match TcpListener::bind(&listen_addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("Failed to bind to {}: {}", listen_addr, e);
                return Err(Box::new(e));
            }
        };

        // Update stats
        {
            let mut stats_guard = stats.lock().unwrap();
            stats_guard.active_connections = 0;
            stats_guard.total_connections = 0;
        }

        loop {
            // Check for shutdown signal
            if let Ok(()) = shutdown_rx.try_recv() {
                info!("Shutting down TCP proxy for {}", domain_name);
                break;
            }

            // Accept with timeout to allow shutdown checks
            let accept_future = listener.accept();
            let timeout = tokio::time::sleep(Duration::from_secs(1));

            tokio::select! {
                accept_result = accept_future => {
                    match accept_result {
                        Ok((inbound, client_addr)) => {
                            info!("New connection from {} to {} ({})",
                                  client_addr, domain_name, db_type as u8);

                            // Update connection stats
                            {
                                let mut stats_guard = stats.lock().unwrap();
                                stats_guard.active_connections += 1;
                                stats_guard.total_connections += 1;
                            }

                            // Connect to the target
                            match TcpStream::connect(&target_addr).await {
                                Ok(outbound) => {
                                    // Clone stats for the connection
                                    let conn_stats = Arc::clone(&stats);

                                    // Start proxying data
                                    tokio::spawn(async move {
                                        let _ = proxy_connection(inbound, outbound, conn_stats).await;
                                    });
                                },
                                Err(e) => {
                                    error!("Failed to connect to target {}: {}", target_addr, e);

                                    // Update stats on failure
                                    {
                                        let mut stats_guard = stats.lock().unwrap();
                                        stats_guard.active_connections -= 1;
                                    }
                                }
                            }
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
}

// Function to handle a single proxied connection
async fn proxy_connection(
    inbound: TcpStream,
    outbound: TcpStream,
    stats: Arc<Mutex<ConnectionStats>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Split the streams
    let (mut ri, mut wi) = tokio::io::split(inbound);
    let (mut ro, mut wo) = tokio::io::split(outbound);

    // Create channels to communicate between tasks
    let (client_done_tx, mut client_done_rx) = mpsc::channel::<()>(1);
    let (server_done_tx, mut server_done_rx) = mpsc::channel::<()>(1);

    // Forward data from client to server
    let stats_clone1 = Arc::clone(&stats);
    let client_to_server = tokio::spawn(async move {
        let mut buffer = [0; 8192]; // Larger buffer for better performance
        let mut total_bytes = 0;

        loop {
            match ri.read(&mut buffer).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    match wo.write_all(&buffer[0..n]).await {
                        Ok(_) => {
                            total_bytes += n;
                            // Optionally update stats periodically for better performance
                            if total_bytes > 1_000_000 {
                                // Update every ~1MB
                                if let Ok(mut stats_guard) = stats_clone1.lock() {
                                    stats_guard.bytes_in += total_bytes;
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
            if let Ok(mut stats_guard) = stats_clone1.lock() {
                stats_guard.bytes_in += total_bytes;
            }
        }

        // Signal that this direction is done
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
        _ = client_done_rx.recv() => {},
        _ = server_done_rx.recv() => {},
    }

    // Update connection stats
    if let Ok(mut stats_guard) = stats.lock() {
        stats_guard.active_connections = stats_guard.active_connections.saturating_sub(1);
    }

    // Clean up the remaining task
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

            let domain_clone = domain.clone();
            let enable_tls = self.enable_tls;

            // Clone the service data for the task
            let service_clone = TcpProxyService {
                servers: Arc::clone(&self.servers),
                db_mappings: Arc::clone(&self.db_mappings),
                enable_tls,
            };

            tokio::spawn(async move {
                // Run either TLS or regular TCP proxy based on configuration
                if enable_tls {
                    if let Err(e) = service_clone
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
                    if let Err(e) = service_clone
                        .run_tcp_proxy(
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
        }
    }
}
