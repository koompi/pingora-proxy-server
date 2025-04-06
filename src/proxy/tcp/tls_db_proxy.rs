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
use std::path::Path;
use std::pin::Pin;
use std::ptr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_openssl::SslStream as TokioSslStream;

use crate::proxy::tcp::sni_utils::extract_hostname_from_uri;
use crate::proxy::tcp::{DatabaseIpRules, DatabaseMapping, DatabaseType};

use super::sni_utils::extract_mongo_uri;

// Helper struct for SNI context selection
pub struct SniContextManager {
    default_contexts: HashMap<DatabaseType, SslContext>,
    domain_contexts: HashMap<String, (DatabaseType, SslContext)>,
    cert_dir: String,
}

impl SniContextManager {
    pub fn new(cert_dir: &str) -> Result<Self, IoError> {
        let mut default_contexts = HashMap::new();

        // Initialize default contexts for each database type
        for db_type in [
            DatabaseType::MongoDB,
            DatabaseType::PostgreSQL,
            DatabaseType::MySQL,
            DatabaseType::Redis,
        ]
        .iter()
        {
            let default_cert = format!("{}/default/{:?}/fullchain.pem", cert_dir, db_type);
            let default_key = format!("{}/default/{:?}/privkey.pem", cert_dir, db_type);

            if Path::new(&default_cert).exists() && Path::new(&default_key).exists() {
                let ctx = Self::create_ssl_context(&default_cert, &default_key)?;
                default_contexts.insert(*db_type, ctx);
            }
        }

        Ok(Self {
            default_contexts,
            domain_contexts: HashMap::new(),
            cert_dir: cert_dir.to_string(),
        })
    }

    // Add this create_ssl_context method
    fn create_ssl_context(cert_path: &str, key_path: &str) -> Result<SslContext, IoError> {
        use openssl::ssl::{SslContext, SslContextBuilder, SslFiletype, SslMethod, SslVerifyMode};

        let mut builder = SslContextBuilder::new(SslMethod::tls())
            .map_err(|e| IoError::new(std::io::ErrorKind::Other, e))?;

        // Set certificate
        builder
            .set_certificate_file(cert_path, SslFiletype::PEM)
            .map_err(|e| IoError::new(std::io::ErrorKind::Other, e))?;

        // Set private key
        builder
            .set_private_key_file(key_path, SslFiletype::PEM)
            .map_err(|e| IoError::new(std::io::ErrorKind::Other, e))?;

        // Verify private key
        builder
            .check_private_key()
            .map_err(|e| IoError::new(std::io::ErrorKind::Other, e))?;

        // Set up for MongoDB compatibility
        builder.set_verify(SslVerifyMode::NONE);

        // Set cipher for compatibility
        builder
            .set_cipher_list("HIGH:!aNULL:!MD5:!RC4:!3DES:@STRENGTH")
            .map_err(|e| IoError::new(std::io::ErrorKind::Other, e))?;

        // Enable support for multiple protocols
        let options = openssl::ssl::SslOptions::NO_COMPRESSION
            | openssl::ssl::SslOptions::CIPHER_SERVER_PREFERENCE;
        builder.set_options(options);

        Ok(builder.build())
    }

    pub fn add_domain_context(
        &mut self,
        domain: &str,
        db_type: DatabaseType,
        cert_path: &str,
        key_path: &str,
    ) -> Result<(), IoError> {
        if Path::new(cert_path).exists() && Path::new(key_path).exists() {
            let ctx = Self::create_ssl_context(cert_path, key_path)?;
            self.domain_contexts
                .insert(domain.to_string(), (db_type, ctx));
            Ok(())
        } else {
            Err(IoError::new(
                ErrorKind::NotFound,
                "Certificate files not found",
            ))
        }
    }

    pub fn get_context(&self, domain: &str, db_type: DatabaseType) -> Option<SslContext> {
        // Try exact domain match first
        if let Some((_, ctx)) = self.domain_contexts.get(domain) {
            return Some(ctx.clone());
        }

        // Try wildcard match
        let domain_parts: Vec<&str> = domain.split('.').collect();
        if domain_parts.len() >= 2 {
            let base_domain = domain_parts[1..].join(".");
            let wildcard = format!("*.{}", base_domain);
            if let Some((_, ctx)) = self.domain_contexts.get(&wildcard) {
                return Some(ctx.clone());
            }
        }

        // Fallback to default context for the database type
        self.default_contexts.get(&db_type).cloned()
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
        let sni_manager = match SniContextManager::new(cert_dir) {
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
                            db_type,
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
    use crate::proxy::tcp::sni_utils::{
        extract_hostname_from_uri, extract_mongo_uri, proxy_connection, resolve_mongodb_srv,
    };

    let client_ip = client_addr.ip().to_string();
    info!(
        "New connection from {} to {:?} database port",
        client_ip, db_type
    );

    // Peek at initial handshake data
    let mut peek_buf = [0u8; 1024];
    let peek_size = client.peek(&mut peek_buf).await?;

    // Extract SNI hostname from TLS ClientHello
    let hostname = match extract_sni_hostname(&peek_buf[..peek_size]) {
        Some(hostname) if !hostname.is_empty() => {
            info!("SNI hostname extracted: {}", hostname);
            hostname
        }
        _ => {
            // For MongoDB, use our improved mapping function
            if db_type == DatabaseType::MongoDB {
                info!("No SNI hostname provided, attempting to find default MongoDB mapping");
                match find_default_mapping(db_mappings.clone(), db_type, &mut client).await {
                    Ok(domain) => {
                        info!("Selected MongoDB mapping: {}", domain);
                        domain
                    }
                    Err(e) => {
                        error!("No MongoDB mapping available: {}", e);
                        return Err(e);
                    }
                }
            } else {
                // For non-MongoDB databases, SNI is required
                warn!("No SNI hostname provided by client");
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "No SNI hostname provided",
                ));
            }
        }
    };

    // Additional validation to prevent empty hostname
    if hostname.is_empty() {
        error!("Empty hostname after SNI extraction and fallback");
        return Err(IoError::new(
            ErrorKind::InvalidData,
            "Empty hostname after SNI extraction and fallback",
        ));
    }

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

    // Start proxying
    proxy_connection(client, backend, hostname).await
}

async fn find_default_mapping(
    db_mappings: Arc<Mutex<HashMap<String, DatabaseMapping>>>,
    db_type: DatabaseType,
    client_stream: &mut TcpStream,
) -> Result<String, IoError> {
    // For MongoDB connections, try to extract information from the protocol handshake
    if db_type == DatabaseType::MongoDB {
        let mut peek_buf = [0u8; 1024];
        let peek_size = client_stream.peek(&mut peek_buf).await?;

        // Try to extract MongoDB URI first
        if let Some(uri) = extract_mongo_uri(&peek_buf[..peek_size]) {
            info!("Found MongoDB URI in handshake: {}", uri);

            if let Ok(hostname) = extract_hostname_from_uri(&uri) {
                info!("Extracted hostname from URI: {}", hostname);

                // Check if we have a mapping for this hostname
                let mappings = db_mappings.lock().await;

                // Try exact match first
                if mappings.contains_key(&hostname) {
                    return Ok(hostname);
                }

                // If exact match fails, try to find the most specific matching domain
                let mut best_match = None;
                let mut best_match_parts = 0;

                let hostname_parts: Vec<&str> = hostname.split('.').collect();

                for domain in mappings.keys() {
                    let domain_parts: Vec<&str> = domain.split('.').collect();

                    // Check if this domain is a potential match
                    if domain_parts.len() <= hostname_parts.len() {
                        let matching = domain_parts
                            .iter()
                            .rev()
                            .zip(hostname_parts.iter().rev())
                            .take(domain_parts.len())
                            .all(|(a, b)| a == b);

                        if matching && domain_parts.len() > best_match_parts {
                            best_match = Some(domain.clone());
                            best_match_parts = domain_parts.len();
                        }
                    }
                }

                if let Some(matched_domain) = best_match {
                    info!("Found matching domain: {}", matched_domain);
                    return Ok(matched_domain);
                }

                // If we got here, we found a hostname but no matching mapping
                error!("No mapping found for MongoDB URI hostname: {}", hostname);
                return Err(IoError::new(
                    ErrorKind::NotFound,
                    format!("No mapping found for MongoDB URI hostname: {}", hostname),
                ));
            }
        }

        // If we can't extract a URI or find a match, return an error
        error!("Could not extract valid hostname from MongoDB URI");
        return Err(IoError::new(
            ErrorKind::InvalidData,
            "Could not extract valid hostname from MongoDB URI",
        ));
    }

    // For non-MongoDB databases, return an error
    Err(IoError::new(
        ErrorKind::InvalidData,
        "SNI hostname required for non-MongoDB connections",
    ))
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
