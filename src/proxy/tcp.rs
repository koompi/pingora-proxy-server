use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use log::{debug, error, info, warn};
use pingora::{apps::ServerApp, protocols::Stream, server::ShutdownWatch};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use crate::{config::model::ConfigStore, metrics::PROXY_METRICS};

/// TCP Proxy implementation that routes based on SNI
#[derive(Clone)]
pub struct TcpSniProxy {
    pub servers: Arc<Mutex<ConfigStore>>,
}

impl TcpSniProxy {
    /// Create a new TCP SNI proxy
    pub fn new(servers: Arc<Mutex<ConfigStore>>) -> Self {
        Self { servers }
    }

    /// Extract the SNI hostname from a TLS ClientHello message
    fn extract_sni(data: &[u8]) -> Option<String> {
        // Check if it's a TLS handshake
        if data.len() < 5 || data[0] != 0x16 {
            return None;
        }

        // Skip TLS record header (5 bytes)
        let mut pos = 5;

        // Skip handshake header
        if pos + 4 > data.len() {
            return None;
        }
        pos += 4;

        // Skip client version
        if pos + 2 > data.len() {
            return None;
        }
        pos += 2;

        // Skip client random
        if pos + 32 > data.len() {
            return None;
        }
        pos += 32;

        // Skip session ID
        if pos + 1 > data.len() {
            return None;
        }
        let session_id_len = data[pos] as usize;
        pos += 1;
        if pos + session_id_len > data.len() {
            return None;
        }
        pos += session_id_len;

        // Skip cipher suites
        if pos + 2 > data.len() {
            return None;
        }
        let cipher_suites_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
        pos += 2;
        if pos + cipher_suites_len > data.len() {
            return None;
        }
        pos += cipher_suites_len;

        // Skip compression methods
        if pos + 1 > data.len() {
            return None;
        }
        let compression_methods_len = data[pos] as usize;
        pos += 1;
        if pos + compression_methods_len > data.len() {
            return None;
        }
        pos += compression_methods_len;

        // Check if we have extensions
        if pos + 2 > data.len() {
            return None;
        }
        let extensions_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
        pos += 2;
        if pos + extensions_len > data.len() {
            return None;
        }

        // Parse extensions
        let extensions_end = pos + extensions_len;
        while pos + 4 <= extensions_end {
            let ext_type = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);
            let ext_len = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
            pos += 4;

            if pos + ext_len > extensions_end {
                return None;
            }

            // SNI extension type is 0
            if ext_type == 0 {
                // Skip server name list length
                if pos + 2 > extensions_end {
                    return None;
                }
                pos += 2;

                // Parse server name
                if pos + 3 > extensions_end {
                    return None;
                }
                let name_type = data[pos];
                let name_len = ((data[pos + 1] as usize) << 8) | (data[pos + 2] as usize);
                pos += 3;

                if pos + name_len > extensions_end {
                    return None;
                }

                // Name type 0 is hostname
                if name_type == 0 {
                    return String::from_utf8(data[pos..pos + name_len].to_vec()).ok();
                }
            }

            pos += ext_len;
        }

        None
    }
}

/// TCP SNI App for handling TCP connections
pub struct TcpSniApp {
    proxy: Arc<TcpSniProxy>,
}

impl TcpSniApp {
    pub fn new(proxy: TcpSniProxy) -> Self {
        Self {
            proxy: Arc::new(proxy),
        }
    }
}

#[async_trait]
impl ServerApp for TcpSniApp {
    async fn process_new(
        self: &Arc<Self>,
        mut io: Stream,
        _shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        // Read initial data to extract SNI
        let mut buffer = [0; 4096];
        let read_timeout = Duration::from_secs(5);

        let n = match timeout(read_timeout, io.read(&mut buffer)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                error!("Failed to read from client: {}", e);
                return None;
            }
            Err(_) => {
                error!("Timeout reading from client");
                return None;
            }
        };

        if n == 0 {
            error!("Client closed connection before sending data");
            return None;
        }

        // Extract SNI from the TLS handshake
        let hostname = match TcpSniProxy::extract_sni(&buffer[..n]) {
            Some(hostname) => {
                info!("Extracted SNI hostname: {}", hostname);
                hostname
            }
            None => {
                warn!("Could not extract SNI hostname from TLS handshake");
                // If we can't extract SNI, we'll use a default route if configured
                String::new()
            }
        };

        // Get the target backend from the configuration
        let target = {
            let servers_lock = match self.proxy.servers.lock() {
                Ok(guard) => guard,
                Err(e) => {
                    error!("Error locking servers mutex in TcpSniProxy: {:?}", e);
                    return None;
                }
            };

            // Debug output to see what domains are in the config store
            debug!(
                "Available domains in config store: {:?}",
                servers_lock.keys().collect::<Vec<_>>()
            );

            servers_lock
                .get(&hostname)
                .map(|(target, _)| target.clone())
        };

        match target {
            Some(to) => {
                info!("Routing TCP request for {} to backend: {}", hostname, to);

                // Connect to the backend
                let mut backend = match TcpStream::connect(&to).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        error!("Failed to connect to backend {}: {}", to, e);
                        // Increment failed requests counter
                        PROXY_METRICS
                            .requests_total
                            .with_label_values(&[&hostname, "502"])
                            .inc();
                        return None;
                    }
                };

                // Forward the initial data to the backend
                if let Err(e) = backend.write_all(&buffer[..n]).await {
                    error!("Failed to write to backend: {}", e);
                    return None;
                }

                // Now proxy data in both directions
                // Since we can't clone streams directly, we'll use a simple loop approach
                let mut client_buffer = [0; 8192];
                let mut backend_buffer = [0; 8192];

                // Create a background task for monitoring the connection
                let (tx, mut rx) = tokio::sync::mpsc::channel(1);
                let self_clone = Arc::clone(self);

                // Spawn a background task to detect connection termination
                tokio::spawn(async move {
                    // Sleep for a reasonable timeout (e.g., 1 hour)
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    let _ = tx.send(()).await;
                });

                // Use bidirectional copy with a select! loop
                loop {
                    tokio::select! {
                        result = io.read(&mut client_buffer) => {
                            match result {
                                Ok(0) => break, // EOF
                                Ok(n) => {
                                    if let Err(e) = backend.write_all(&client_buffer[..n]).await {
                                        error!("Failed to write to backend: {}", e);
                                        break;
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to read from client: {}", e);
                                    break;
                                }
                            }
                        }
                        result = backend.read(&mut backend_buffer) => {
                            match result {
                                Ok(0) => break, // EOF
                                Ok(n) => {
                                    if let Err(e) = io.write_all(&backend_buffer[..n]).await {
                                        error!("Failed to write to client: {}", e);
                                        break;
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to read from backend: {}", e);
                                    break;
                                }
                            }
                        }
                        Some(_) = rx.recv() => {
                            debug!("Proxy connection timeout reached");
                            break;
                        }
                    }
                }

                // Increment successful requests counter
                PROXY_METRICS
                    .requests_total
                    .with_label_values(&[&hostname, "200"])
                    .inc();

                None
            }
            None => {
                error!("No backend found for hostname: {}", hostname);
                // Increment failed requests counter
                PROXY_METRICS
                    .requests_total
                    .with_label_values(&[&hostname, "404"])
                    .inc();
                None
            }
        }
    }
}
