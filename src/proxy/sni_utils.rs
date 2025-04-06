// src/proxy/sni_utils.rs
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
