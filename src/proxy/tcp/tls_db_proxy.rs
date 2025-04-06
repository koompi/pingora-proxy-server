// src/proxy/tls_db_proxy.rs
use foreign_types_shared::ForeignTypeRef;
use log::{debug, error, info, warn};
use openssl::ssl::{
    NameType, SslAcceptor, SslContext, SslContextBuilder, SslFiletype, SslMethod, SslVerifyMode,
};
use openssl::ssl::{SslContextRef, SslOptions};
use std::collections::HashMap;
use std::io::{Error as IoError, ErrorKind};
use std::net::SocketAddr;
use std::pin::Pin;
use std::ptr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_openssl::SslStream as TokioSslStream;

use crate::proxy::tcp::{DatabaseIpRules, DatabaseMapping, DatabaseType};

// Helper struct for SNI context selection
pub struct SniContextManager {
    default_context: SslContext,
    domain_contexts: HashMap<String, SslContext>,
    cert_dir: String,
}

impl SniContextManager {
    pub fn new(default_cert: &str, default_key: &str, cert_dir: &str) -> Result<Self, IoError> {
        // Create a default context
        let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls())
            .map_err(|e| IoError::new(ErrorKind::Other, format!("SSL builder error: {}", e)))?;

        builder
            .set_certificate_file(default_cert, SslFiletype::PEM)
            .map_err(|e| {
                IoError::new(ErrorKind::InvalidData, format!("Certificate error: {}", e))
            })?;

        builder
            .set_private_key_file(default_key, SslFiletype::PEM)
            .map_err(|e| {
                IoError::new(ErrorKind::InvalidData, format!("Private key error: {}", e))
            })?;

        builder.check_private_key().map_err(|e| {
            IoError::new(
                ErrorKind::InvalidData,
                format!("Key verification error: {}", e),
            )
        })?;

        // Enhanced MongoDB compatibility settings
        builder.set_verify(SslVerifyMode::NONE);

        // Set broader cipher list for MongoDB compatibility
        builder
            .set_cipher_list("HIGH:!aNULL:!MD5:!RC4:!3DES:@STRENGTH")
            .map_err(|e| IoError::new(ErrorKind::Other, format!("Cipher list error: {}", e)))?;

        // Additional TLS options for better compatibility
        let options =
            SslOptions::NO_COMPRESSION | SslOptions::CIPHER_SERVER_PREFERENCE | SslOptions::ALL;
        builder.set_options(options);

        // Clear restrictive options
        builder.clear_options(
            SslOptions::NO_RENEGOTIATION
                | SslOptions::NO_TLSV1
                | SslOptions::NO_TLSV1_1
                | SslOptions::NO_TICKET,
        );

        // Build the context
        let ctx = builder.build();

        Ok(Self {
            default_context: ctx.into_context(),
            domain_contexts: HashMap::new(),
            cert_dir: cert_dir.to_string(),
        })
    }

    pub fn add_domain_context(
        &mut self,
        domain: &str,
        cert_path: &str,
        key_path: &str,
    ) -> Result<(), IoError> {
        let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls())
            .map_err(|e| IoError::new(ErrorKind::Other, format!("SSL builder error: {}", e)))?;

        builder
            .set_certificate_file(cert_path, SslFiletype::PEM)
            .map_err(|e| {
                IoError::new(ErrorKind::InvalidData, format!("Certificate error: {}", e))
            })?;

        builder
            .set_private_key_file(key_path, SslFiletype::PEM)
            .map_err(|e| {
                IoError::new(ErrorKind::InvalidData, format!("Private key error: {}", e))
            })?;

        builder.check_private_key().map_err(|e| {
            IoError::new(
                ErrorKind::InvalidData,
                format!("Key verification error: {}", e),
            )
        })?;

        // Enhanced MongoDB compatibility settings
        builder.set_verify(SslVerifyMode::NONE);

        // Set broader cipher list
        builder
            .set_cipher_list("HIGH:!aNULL:!MD5:!RC4:!3DES:@STRENGTH")
            .map_err(|e| IoError::new(ErrorKind::Other, format!("Cipher list error: {}", e)))?;

        // Additional TLS options
        let options =
            SslOptions::NO_COMPRESSION | SslOptions::CIPHER_SERVER_PREFERENCE | SslOptions::ALL;
        builder.set_options(options);

        // Clear restrictive options
        builder.clear_options(
            SslOptions::NO_RENEGOTIATION
                | SslOptions::NO_TLSV1
                | SslOptions::NO_TLSV1_1
                | SslOptions::NO_TICKET,
        );

        // Set SNI callback
        builder.set_servername_callback(|ssl_ref, _alert| {
            if let Some(servername) = ssl_ref.servername(NameType::HOST_NAME) {
                info!("SNI hostname received: {}", servername);
            }
            Ok(())
        });

        let ctx = builder.build();

        self.domain_contexts
            .insert(domain.to_string(), ctx.into_context());

        Ok(())
    }

    pub fn get_context_for_domain(&self, domain: &str) -> SslContext {
        // First check for exact match
        if let Some(ctx) = self.domain_contexts.get(domain) {
            return ctx.clone();
        }

        // Then try wildcard matching
        let domain_parts: Vec<&str> = domain.split('.').collect();
        if domain_parts.len() >= 2 {
            let base_domain = domain_parts[1..].join(".");
            let wildcard_domain = format!("*.{}", base_domain);

            if let Some(ctx) = self.domain_contexts.get(&wildcard_domain) {
                return ctx.clone();
            }
        }

        // Fallback to default context
        self.default_context.clone()
    }
}

// Main TLS database proxy
pub struct TlsDatabaseProxy {
    db_type: DatabaseType,
    listen_port: u16,
    db_mappings: Arc<Mutex<HashMap<String, DatabaseMapping>>>,
    ip_rules: DatabaseIpRules,
    sni_manager: Arc<Mutex<SniContextManager>>,
}

impl TlsDatabaseProxy {
    pub async fn new(
        db_type: DatabaseType,
        cert_dir: &str,
        db_mappings: Arc<Mutex<HashMap<String, DatabaseMapping>>>,
        ip_rules: DatabaseIpRules,
    ) -> Result<Self, IoError> {
        // We need at least one default certificate for the initial TLS handshake
        let default_cert = format!("{}/default/fullchain.pem", cert_dir);
        let default_key = format!("{}/default/privkey.pem", cert_dir);

        // If no default certificate exists, try to find any certificate to use
        let (cert_path, key_path) = if std::path::Path::new(&default_cert).exists()
            && std::path::Path::new(&default_key).exists()
        {
            (default_cert, default_key)
        } else {
            // Find any available certificate in the directory
            let mut any_cert = None;
            if let Ok(entries) = std::fs::read_dir(cert_dir) {
                for entry in entries.filter_map(Result::ok) {
                    if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        let domain_dir = entry.path();
                        let cert = domain_dir.join("fullchain.pem");
                        let key = domain_dir.join("privkey.pem");

                        if cert.exists() && key.exists() {
                            any_cert = Some((
                                cert.to_string_lossy().to_string(),
                                key.to_string_lossy().to_string(),
                            ));
                            break;
                        }
                    }
                }
            }

            match any_cert {
                Some((cert, key)) => {
                    info!(
                        "Using certificate from {} as default for {:?} proxy",
                        cert, db_type
                    );
                    (cert, key)
                }
                None => {
                    return Err(IoError::new(
                        ErrorKind::NotFound,
                        format!(
                            "No certificates found for {} database proxy",
                            db_type.listen_port()
                        ),
                    ));
                }
            }
        };

        // Create SNI context manager
        let sni_manager = match SniContextManager::new(&cert_path, &key_path, cert_dir) {
            Ok(manager) => manager,
            Err(e) => return Err(e),
        };

        // Load all available certificates
        let mut manager = sni_manager;
        if let Ok(entries) = std::fs::read_dir(cert_dir) {
            for entry in entries.filter_map(Result::ok) {
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    let domain = entry.file_name().to_string_lossy().to_string();
                    if domain == "default" {
                        continue; // Skip default, already loaded
                    }

                    let cert = entry.path().join("fullchain.pem");
                    let key = entry.path().join("privkey.pem");

                    if cert.exists() && key.exists() {
                        match manager.add_domain_context(
                            &domain,
                            &cert.to_string_lossy(),
                            &key.to_string_lossy(),
                        ) {
                            Ok(_) => {
                                info!("Added certificate for domain: {}", domain);
                            }
                            Err(e) => {
                                warn!("Failed to add certificate for {}: {}", domain, e);
                            }
                        }
                    }
                }
            }
        }

        Ok(Self {
            db_type,
            listen_port: db_type.listen_port(),
            db_mappings,
            ip_rules,
            sni_manager: Arc::new(Mutex::new(manager)),
        })
    }

    pub async fn start(&self, mut shutdown_rx: mpsc::Receiver<()>) -> Result<(), IoError> {
        let addr = format!("0.0.0.0:{}", self.listen_port);
        info!(
            "Starting TLS database proxy for {:?} on {}",
            self.db_type, addr
        );

        let listener = TcpListener::bind(&addr).await?;
        self.accept_loop(listener, shutdown_rx).await
    }

    async fn accept_loop(
        &self,
        listener: TcpListener,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) -> Result<(), IoError> {
        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((socket, addr)) => {
                            let db_mappings = self.db_mappings.clone();
                            let ip_rules = self.ip_rules.clone();
                            let sni_manager = self.sni_manager.clone();
                            let db_type = self.db_type;

                            tokio::spawn(async move {
                                if let Err(e) = handle_tls_connection(socket, addr, db_type, db_mappings, ip_rules, sni_manager).await {
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
                    info!("Shutting down {:?} TLS proxy", self.db_type);
                    break;
                }
            }
        }

        Ok(())
    }
}

async fn handle_tls_connection(
    mut client: TcpStream,
    client_addr: SocketAddr,
    db_type: DatabaseType,
    db_mappings: Arc<Mutex<HashMap<String, DatabaseMapping>>>,
    ip_rules: DatabaseIpRules,
    sni_manager: Arc<Mutex<SniContextManager>>,
) -> Result<(), IoError> {
    let client_ip = client_addr.ip().to_string();
    info!(
        "New connection from {} to {:?} database port",
        client_ip, db_type
    );

    // Use our SNI extraction utility
    let mut peek_buf = [0u8; 1024];
    let peek_size = client.peek(&mut peek_buf).await?;

    // Extract SNI hostname
    let hostname = match extract_sni_hostname(&peek_buf[..peek_size]) {
        Some(hostname) => {
            info!("SNI hostname: {}", hostname);
            hostname
        }
        None => {
            // For MongoDB, use default mapping when SNI is not provided
            if db_type == DatabaseType::MongoDB {
                // Get the first MongoDB mapping as default
                let mappings = db_mappings.lock().await;
                let default_mapping = mappings
                    .iter()
                    .find(|(k, _v)| k.contains("mongodb"))
                    .map(|(k, _)| k.clone());

                if let Some(default_hostname) = default_mapping {
                    info!("Using default MongoDB mapping: {}", default_hostname);
                    default_hostname
                } else {
                    warn!("No default MongoDB mapping available");
                    return Err(IoError::new(
                        ErrorKind::InvalidData,
                        "No default MongoDB mapping available",
                    ));
                }
            } else {
                warn!("No SNI hostname provided by client");
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "No SNI hostname provided",
                ));
            }
        }
    };

    // Check IP rules
    if !ip_rules.is_ip_allowed(&hostname, &client_ip) {
        error!(
            "Connection from {} to {} rejected by IP rules",
            client_ip, hostname
        );
        return Err(IoError::new(
            ErrorKind::PermissionDenied,
            "IP not allowed for this database",
        ));
    }

    // Get database mapping
    let mapping = {
        let mappings = db_mappings.lock().await;
        match mappings.get(&hostname) {
            Some(mapping) => mapping.clone(),
            None => {
                error!("No database mapping found for hostname: {}", hostname);
                return Err(IoError::new(ErrorKind::NotFound, "Database not found"));
            }
        }
    };

    // Get SSL context for this hostname
    let ssl_ctx = {
        let manager = sni_manager.lock().await;
        manager.get_context_for_domain(&hostname)
    };

    // Create SSL acceptor
    let mut acceptor = match openssl::ssl::Ssl::new(&ssl_ctx) {
        Ok(ssl) => ssl,
        Err(e) => {
            error!("Failed to create SSL object: {}", e);
            return Err(IoError::new(ErrorKind::Other, "TLS setup failed"));
        }
    };

    // Set server name for proper certificate selection during handshake
    if let Err(e) = acceptor.set_hostname(&hostname) {
        warn!("Failed to set SSL hostname: {}", e);
    }

    // Create TLS stream
    let mut tls_stream = match TokioSslStream::new(acceptor, client) {
        Ok(stream) => stream,
        Err(e) => {
            error!("Failed to create TLS stream: {}", e);
            return Err(IoError::new(ErrorKind::Other, "TLS setup failed"));
        }
    };

    // Accept TLS connection - fixed to use Pin
    if let Err(e) = Pin::new(&mut tls_stream).accept().await {
        error!("TLS handshake failed: {}", e);
        return Err(IoError::new(
            ErrorKind::ConnectionRefused,
            "TLS handshake failed",
        ));
    }

    // Connect to target backend
    let backend_addr = format!("{}:{}", mapping.target_host, mapping.target_port);
    info!("Connecting to backend: {}", backend_addr);

    let backend = match TcpStream::connect(&backend_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            error!("Failed to connect to backend {}: {}", backend_addr, e);
            return Err(e);
        }
    };

    // Start bidirectional proxying
    let (mut client_r, mut client_w) = tokio::io::split(tls_stream);
    let (mut backend_r, mut backend_w) = tokio::io::split(backend);

    // Set up completion channels
    let (client_done_tx, mut client_done_rx) = mpsc::channel::<()>(1);
    let (backend_done_tx, mut backend_done_rx) = mpsc::channel::<()>(1);

    // Update connection stats
    {
        let mut stats = mapping.stats.lock().await;
        stats.active_connections += 1;
        stats.total_connections += 1;
    }

    // Client -> Backend
    let stats_clone = mapping.stats.clone();
    let client_to_backend = tokio::spawn(async move {
        let mut buffer = [0u8; 8192];
        let mut total_bytes = 0;

        loop {
            match client_r.read(&mut buffer).await {
                Ok(0) => break, // Connection closed
                Ok(n) => match backend_w.write_all(&buffer[..n]).await {
                    Ok(_) => {
                        total_bytes += n;
                    }
                    Err(e) => {
                        error!("Error writing to backend: {}", e);
                        break;
                    }
                },
                Err(e) => {
                    error!("Error reading from client: {}", e);
                    break;
                }
            }
        }

        // Update stats
        let mut stats = stats_clone.lock().await;
        stats.bytes_in += total_bytes;
        stats.active_connections = stats.active_connections.saturating_sub(1);

        let _ = client_done_tx.send(()).await;
    });

    // Backend -> Client
    let stats_clone = mapping.stats.clone();
    let backend_to_client = tokio::spawn(async move {
        let mut buffer = [0u8; 8192];
        let mut total_bytes = 0;

        loop {
            match backend_r.read(&mut buffer).await {
                Ok(0) => break, // Connection closed
                Ok(n) => match client_w.write_all(&buffer[..n]).await {
                    Ok(_) => {
                        total_bytes += n;
                    }
                    Err(e) => {
                        error!("Error writing to client: {}", e);
                        break;
                    }
                },
                Err(e) => {
                    error!("Error reading from backend: {}", e);
                    break;
                }
            }
        }

        // Update stats
        let mut stats = stats_clone.lock().await;
        stats.bytes_out += total_bytes;

        let _ = backend_done_tx.send(()).await;
    });

    // Wait for either side to complete
    tokio::select! {
        _ = client_done_rx.recv() => {
            debug!("Client -> Backend completed for {}", hostname);
        }
        _ = backend_done_rx.recv() => {
            debug!("Backend -> Client completed for {}", hostname);
        }
    }

    // Clean up tasks
    client_to_backend.abort();
    backend_to_client.abort();

    info!("Connection for {} completed", hostname);
    Ok(())
}

// Extract SNI hostname from TLS ClientHello data
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
                // Skip SNI list length - use underscore prefix to indicate unused variable
                let _sni_list_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
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
