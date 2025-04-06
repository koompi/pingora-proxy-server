// src/proxy/tcp/sni_utils.rs
use log::{debug, info};
use openssl::ssl::{SslAcceptor, SslContext, SslFiletype, SslMethod, SslVerifyMode};
use std::io::{Error as IoError, ErrorKind};
use std::path::Path;
use tokio::net::TcpStream;

/// Extract SNI hostname from TLS ClientHello without consuming the data
pub async fn extract_sni_hostname(stream: &mut TcpStream) -> Result<Option<String>, IoError> {
    let mut peek_buf = [0u8; 1024];

    // Peek at the TLS handshake data without consuming it
    let peek_size = stream.peek(&mut peek_buf).await?;

    if peek_size < 5 {
        return Ok(None); // Not enough data
    }

    // Check if it's a TLS handshake
    if peek_buf[0] != 0x16 {
        // Record type: Handshake (22)
        return Ok(None);
    }

    // Check TLS version (0x0301 for TLS 1.0, 0x0302 for TLS 1.1, 0x0303 for TLS 1.2)
    if peek_buf[1] != 0x03 || peek_buf[2] < 0x01 || peek_buf[2] > 0x03 {
        return Ok(None);
    }

    // Record length
    let record_length = ((peek_buf[3] as usize) << 8) | (peek_buf[4] as usize);

    // Ensure we have enough data
    if peek_size < 5 + record_length {
        return Ok(None);
    }

    // Handshake type should be ClientHello (1)
    if peek_buf[5] != 0x01 {
        return Ok(None);
    }

    // Parse the ClientHello to find SNI extension

    // Skip to extensions section (variable length depending on session ID, cipher suites, etc.)
    // We need to navigate through:
    // - 2 bytes handshake protocol version
    // - 32 bytes client random
    // - Session ID (variable length)
    // - Cipher suites (variable length)
    // - Compression methods (variable length)
    // - Then we reach extensions

    let mut pos = 43; // Start after fixed headers

    // Skip session ID
    if pos < peek_size {
        let session_id_len = peek_buf[pos] as usize;
        pos += 1 + session_id_len;
    }

    // Skip cipher suites
    if pos + 1 < peek_size {
        let cipher_suites_len = ((peek_buf[pos] as usize) << 8) | (peek_buf[pos + 1] as usize);
        pos += 2 + cipher_suites_len;
    }

    // Skip compression methods
    if pos < peek_size {
        let compression_methods_len = peek_buf[pos] as usize;
        pos += 1 + compression_methods_len;
    }

    // Check if we have extensions
    if pos + 1 >= peek_size {
        return Ok(None);
    }

    // Extension section length
    let extensions_len = ((peek_buf[pos] as usize) << 8) | (peek_buf[pos + 1] as usize);
    pos += 2;

    // Parse extensions to find SNI
    let extensions_end = pos + extensions_len;
    while pos + 4 <= extensions_end && pos + 4 <= peek_size {
        let ext_type = ((peek_buf[pos] as u16) << 8) | (peek_buf[pos + 1] as u16);
        let ext_len = ((peek_buf[pos + 2] as usize) << 8) | (peek_buf[pos + 3] as usize);
        pos += 4;

        if ext_type == 0 {
            // ServerName extension
            if pos + 2 <= extensions_end && pos + 2 <= peek_size {
                // Skip the SNI list length
                pos += 2;

                if pos < extensions_end && pos < peek_size {
                    let name_type = peek_buf[pos];
                    pos += 1;

                    if name_type == 0 && pos + 2 <= extensions_end && pos + 2 <= peek_size {
                        // HostName
                        let hostname_len =
                            ((peek_buf[pos] as usize) << 8) | (peek_buf[pos + 1] as usize);
                        pos += 2;

                        if pos + hostname_len <= extensions_end && pos + hostname_len <= peek_size {
                            let hostname_bytes = &peek_buf[pos..pos + hostname_len];
                            if let Ok(hostname) = std::str::from_utf8(hostname_bytes) {
                                debug!("SNI hostname extracted: {}", hostname);
                                return Ok(Some(hostname.to_string()));
                            }
                        }
                    }
                }
            }
            break;
        }

        pos += ext_len;
    }

    Ok(None)
}

/// Create an SSL context for SNI-based routing
pub fn create_ssl_context(cert_path: &str, key_path: &str) -> Result<SslContext, IoError> {
    // Verify certificate and key files exist
    if !Path::new(cert_path).exists() {
        return Err(IoError::new(
            ErrorKind::NotFound,
            format!("Certificate file not found: {}", cert_path),
        ));
    }

    if !Path::new(key_path).exists() {
        return Err(IoError::new(
            ErrorKind::NotFound,
            format!("Key file not found: {}", key_path),
        ));
    }

    // Create a SSL context builder
    let mut ctx_builder = SslAcceptor::mozilla_modern(SslMethod::tls()).map_err(|e| {
        IoError::new(
            ErrorKind::Other,
            format!("Failed to create SSL context builder: {}", e),
        )
    })?;

    // Set certificate and key
    ctx_builder
        .set_certificate_file(cert_path, SslFiletype::PEM)
        .map_err(|e| {
            IoError::new(
                ErrorKind::InvalidData,
                format!("Failed to set certificate file: {}", e),
            )
        })?;

    ctx_builder
        .set_private_key_file(key_path, SslFiletype::PEM)
        .map_err(|e| {
            IoError::new(
                ErrorKind::InvalidData,
                format!("Failed to set private key file: {}", e),
            )
        })?;

    // Verify key matches certificate
    ctx_builder.check_private_key().map_err(|e| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("Private key does not match certificate: {}", e),
        )
    })?;

    // Configure SNI callback
    ctx_builder.set_servername_callback(|ssl, _| {
        // You can add custom logic here based on the server name
        if let Some(name) = ssl.servername(openssl::ssl::NameType::HOST_NAME) {
            debug!("SNI servername received: {}", name);
        }
        Ok(())
    });

    // Don't require client certificates
    ctx_builder.set_verify(SslVerifyMode::NONE);

    // Build the context
    Ok(ctx_builder.build().into_context())
}

/// Find a certificate for a given hostname in a directory
pub fn find_certificate_for_hostname(hostname: &str, cert_dir: &str) -> Option<(String, String)> {
    // Check for exact match
    let exact_cert_path = format!("{}/{}/fullchain.pem", cert_dir, hostname);
    let exact_key_path = format!("{}/{}/privkey.pem", cert_dir, hostname);

    if Path::new(&exact_cert_path).exists() && Path::new(&exact_key_path).exists() {
        info!("Found exact certificate match for {}", hostname);
        return Some((exact_cert_path, exact_key_path));
    }

    // Check for wildcard match
    let domain_parts: Vec<&str> = hostname.split('.').collect();
    if domain_parts.len() >= 2 {
        let base_domain = domain_parts[1..].join(".");
        let wildcard_hostname = format!("*.{}", base_domain);

        let wildcard_cert_path = format!("{}/{}/fullchain.pem", cert_dir, wildcard_hostname);
        let wildcard_key_path = format!("{}/{}/privkey.pem", cert_dir, wildcard_hostname);

        if Path::new(&wildcard_cert_path).exists() && Path::new(&wildcard_key_path).exists() {
            info!("Found wildcard certificate match for {}", hostname);
            return Some((wildcard_cert_path, wildcard_key_path));
        }
    }

    // No match found
    None
}

/// Extract MongoDB URI from client handshake data
pub fn extract_mongo_uri(data: &[u8]) -> Option<String> {
    // Look for the mongodb:// or mongodb+srv:// pattern in the handshake
    if data.len() < 20 {
        return None;
    }

    // Convert to string for easier searching
    if let Ok(data_str) = std::str::from_utf8(data) {
        // Look for MongoDB URI patterns
        if let Some(start_idx) = data_str.find("mongodb") {
            // Extract the URI until a space, null byte, or end of data
            let mut end_idx = start_idx;
            while end_idx < data_str.len()
                && !data_str[end_idx..].starts_with(' ')
                && !data_str[end_idx..].starts_with('\0')
            {
                end_idx += 1;
            }

            return Some(data_str[start_idx..end_idx].to_string());
        }
    }

    None
}

/// Extract hostname from MongoDB URI
pub fn extract_hostname_from_uri(uri: &str) -> Result<String, IoError> {
    // Parse URI to extract hostname
    // Format: mongodb[+srv]://[username:password@]hostname[:port][/database][?options]

    let uri_parts: Vec<&str> = uri.split("://").collect();
    if uri_parts.len() < 2 {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            "Invalid MongoDB URI format",
        ));
    }

    let address_part = uri_parts[1];

    // Handle authentication if present
    let host_part = if address_part.contains('@') {
        address_part.split('@').nth(1).unwrap_or(address_part)
    } else {
        address_part
    };

    // Remove path and query parameters
    let host_only = host_part
        .split('/')
        .next()
        .unwrap_or(host_part)
        .split('?')
        .next()
        .unwrap_or(host_part);

    // Remove port if present
    let hostname = host_only.split(':').next().unwrap_or(host_only);

    Ok(hostname.to_string())
}

/// Resolve MongoDB SRV records
pub async fn resolve_mongodb_srv(hostname: &str) -> Result<Vec<(String, u16)>, IoError> {
    use tokio::process::Command as TokioCommand;

    // Construct SRV lookup name
    let srv_record = format!("_mongodb._tcp.{}", hostname);
    info!("Looking up SRV record: {}", srv_record);

    // Try using dig for SRV lookup
    let output = TokioCommand::new("dig")
        .args(&["+short", "SRV", &srv_record])
        .output()
        .await;

    match output {
        Ok(output) if !output.stdout.is_empty() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            info!("SRV lookup result: {}", stdout);

            let mut servers = Vec::new();

            // Parse SRV records (format: priority weight port target)
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    if let Ok(port) = parts[2].parse::<u16>() {
                        let host = parts[3].trim_end_matches('.');
                        servers.push((host.to_string(), port));
                    }
                }
            }

            if !servers.is_empty() {
                info!("Found SRV records: {:?}", servers);
                return Ok(servers);
            }
        }
        _ => {
            // Fallback to assuming standard MongoDB port 27017
            info!("SRV lookup failed, using standard port 27017");
        }
    }

    // Default fallback
    info!("Using default MongoDB port for {}", hostname);
    Ok(vec![(hostname.to_string(), 27017)])
}

/// Proxy connection between client and backend
pub async fn proxy_connection(
    client: TcpStream,
    backend: TcpStream,
    hostname: String,
) -> Result<(), IoError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    info!("Starting proxy connection for hostname: {}", hostname);

    // Create owned handles to avoid ownership issues
    let (mut client_rx, mut client_tx) = tokio::io::split(client);
    let (mut backend_rx, mut backend_tx) = tokio::io::split(backend);

    // Set up completion channels
    let (client_done_tx, mut client_done_rx) = tokio::sync::mpsc::channel::<()>(1);
    let (backend_done_tx, mut backend_done_rx) = tokio::sync::mpsc::channel::<()>(1);

    // Client -> Backend (clone hostname for task)
    let hostname_c2b = hostname.clone();
    let client_to_backend = tokio::spawn(async move {
        let mut buffer = [0u8; 8192];
        let mut _total_bytes = 0;

        loop {
            match client_rx.read(&mut buffer).await {
                Ok(0) => break, // EOF from client
                Ok(n) => match backend_tx.write_all(&buffer[..n]).await {
                    Ok(_) => {
                        _total_bytes += n;
                    }
                    Err(e) => {
                        info!("Error writing to backend: {}", e);
                        break;
                    }
                },
                Err(e) => {
                    info!("Error reading from client: {}", e);
                    break;
                }
            }
        }

        info!("Client -> Backend completed for hostname: {}", hostname_c2b);
        let _ = client_done_tx.send(()).await;
    });

    // Backend -> Client (clone hostname for task)
    let hostname_b2c = hostname.clone();
    let backend_to_client = tokio::spawn(async move {
        let mut buffer = [0u8; 8192];
        let mut _total_bytes = 0;

        loop {
            match backend_rx.read(&mut buffer).await {
                Ok(0) => break, // EOF from backend
                Ok(n) => match client_tx.write_all(&buffer[..n]).await {
                    Ok(_) => {
                        _total_bytes += n;
                    }
                    Err(e) => {
                        info!("Error writing to client: {}", e);
                        break;
                    }
                },
                Err(e) => {
                    info!("Error reading from backend: {}", e);
                    break;
                }
            }
        }

        info!("Backend -> Client completed for hostname: {}", hostname_b2c);
        let _ = backend_done_tx.send(()).await;
    });

    // Wait for either side to complete
    tokio::select! {
        _ = client_done_rx.recv() => {}
        _ = backend_done_rx.recv() => {}
    }

    // Clean up tasks
    client_to_backend.abort();
    backend_to_client.abort();

    info!("Connection closed for hostname: {}", hostname);
    Ok(())
}
