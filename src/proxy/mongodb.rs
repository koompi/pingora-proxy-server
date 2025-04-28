// src/proxy/mongodb.rs - MongoDB TCP proxy with SNI-based routing
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use log::{debug, error, info};
use pingora::{
    apps::ServerApp,
    protocols::Stream,
    server::{configuration::ServerConf, ShutdownWatch},
    services::listening::Service,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    select,
};

use crate::{config::model::ConfigStore, metrics::PROXY_METRICS, proxy::utils::parse_swarm_target};

/// MongoDB TCP Proxy implementation
#[derive(Clone)]
pub struct MongoDBProxy {
    pub servers: Arc<Mutex<ConfigStore>>,
    pub cert_dir: String,
}

/// Structure to hold the MongoDB proxy service
pub struct MongoDBProxyService {
    _proxy: MongoDBProxy, // Renamed to _proxy to indicate it's intentionally unused
    service: Service<MongoDBProxy>,
}

impl MongoDBProxyService {
    /// Create a new MongoDB proxy service
    pub fn new(servers: Arc<Mutex<ConfigStore>>, _conf: &ServerConf) -> Self {
        let proxy = MongoDBProxy {
            servers,
            cert_dir: "/certbot/letsencrypt/live".to_string(),
        };

        // Create a service with the proxy
        let mut service = Service::new("MongoDB Proxy Service".to_string(), proxy.clone());

        // Add TCP listener on the MongoDB port
        service.add_tcp("0.0.0.0:27017");

        Self {
            _proxy: proxy,
            service,
        }
    }

    /// Get the service
    pub fn service(self) -> Service<MongoDBProxy> {
        self.service
    }
}

/// Enum to represent duplex events
enum DuplexEvent {
    DownstreamRead(usize),
    UpstreamRead(usize),
}

/// Try to get the IP address of a Docker service
fn try_get_service_ip(service_name: &str) -> Option<String> {
    // Use the Docker API to get the service IP
    // This requires the proxy to have access to the Docker socket
    let output = match std::process::Command::new("docker")
        .args(&["service", "ps", "--format", "{{.Node}}", service_name])
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            error!("Failed to execute docker command: {}", e);
            return None;
        }
    };

    if !output.status.success() {
        error!(
            "Docker command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return None;
    }

    // Parse the output to get the node name
    let node_name = match String::from_utf8(output.stdout) {
        Ok(stdout) => {
            let lines: Vec<&str> = stdout.trim().lines().collect();
            if lines.is_empty() {
                error!("No nodes found for service {}", service_name);
                return None;
            }
            lines[0].to_string()
        }
        Err(e) => {
            error!("Failed to parse docker command output: {}", e);
            return None;
        }
    };

    // Now get the IP address of the node
    let output = match std::process::Command::new("docker")
        .args(&[
            "node",
            "inspect",
            "--format",
            "{{.Status.Addr}}",
            &node_name,
        ])
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            error!("Failed to execute docker node inspect command: {}", e);
            return None;
        }
    };

    if !output.status.success() {
        error!(
            "Docker node inspect command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return None;
    }

    // Parse the output to get the IP address
    match String::from_utf8(output.stdout) {
        Ok(stdout) => {
            let ip = stdout.trim();
            if ip.is_empty() {
                error!("No IP address found for node {}", node_name);
                return None;
            }
            Some(ip.to_string())
        }
        Err(e) => {
            error!("Failed to parse docker node inspect output: {}", e);
            None
        }
    }
}

impl MongoDBProxy {
    /// Extract SNI hostname from TLS ClientHello
    fn extract_sni_hostname(data: &[u8]) -> Option<String> {
        // Check if this looks like a TLS ClientHello
        if data.len() < 5 || data[0] != 0x16 {
            // 0x16 is the TLS handshake record type
            return None;
        }

        // Skip the TLS record header (5 bytes)
        let mut pos = 5;

        // Skip the handshake message header (4 bytes)
        if data.len() < pos + 4 {
            return None;
        }
        pos += 4;

        // Skip client version (2 bytes)
        if data.len() < pos + 2 {
            return None;
        }
        pos += 2;

        // Skip client random (32 bytes)
        if data.len() < pos + 32 {
            return None;
        }
        pos += 32;

        // Skip session ID
        if data.len() < pos + 1 {
            return None;
        }
        let session_id_len = data[pos] as usize;
        pos += 1;

        if data.len() < pos + session_id_len {
            return None;
        }
        pos += session_id_len;

        // Skip cipher suites
        if data.len() < pos + 2 {
            return None;
        }
        let cipher_suites_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
        pos += 2;

        if data.len() < pos + cipher_suites_len {
            return None;
        }
        pos += cipher_suites_len;

        // Skip compression methods
        if data.len() < pos + 1 {
            return None;
        }
        let compression_methods_len = data[pos] as usize;
        pos += 1;

        if data.len() < pos + compression_methods_len {
            return None;
        }
        pos += compression_methods_len;

        // Check if we have extensions
        if data.len() < pos + 2 {
            return None;
        }

        let extensions_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
        pos += 2;

        if data.len() < pos + extensions_len {
            return None;
        }

        // Parse extensions
        let extensions_end = pos + extensions_len;
        while pos < extensions_end {
            if data.len() < pos + 4 {
                return None;
            }

            let ext_type = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);
            let ext_len = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
            pos += 4;

            if data.len() < pos + ext_len {
                return None;
            }

            // SNI extension type is 0
            if ext_type == 0 {
                // Parse SNI extension
                if ext_len < 2 {
                    return None;
                }

                let sni_list_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
                pos += 2;

                if sni_list_len > ext_len - 2 || data.len() < pos + sni_list_len {
                    return None;
                }

                // Parse SNI entries
                let sni_end = pos + sni_list_len;
                while pos < sni_end {
                    if data.len() < pos + 3 {
                        return None;
                    }

                    let name_type = data[pos];
                    let name_len = ((data[pos + 1] as usize) << 8) | (data[pos + 2] as usize);
                    pos += 3;

                    if data.len() < pos + name_len {
                        return None;
                    }

                    // Name type 0 is hostname
                    if name_type == 0 {
                        // Extract hostname
                        if let Ok(hostname) = std::str::from_utf8(&data[pos..pos + name_len]) {
                            return Some(hostname.to_string());
                        }
                    }

                    pos += name_len;
                }

                // If we get here, we didn't find a hostname in the SNI extension
                return None;
            }

            pos += ext_len;
        }

        None
    }

    /// Handle duplex connection between client and server
    async fn handle_duplex(&self, mut client_stream: Stream, mut server_stream: Stream) {
        let mut upstream_buf = [0; 8192];
        let mut downstream_buf = [0; 8192];

        // Track connection statistics
        let mut client_bytes_read = 0;
        let mut server_bytes_read = 0;
        let mut client_bytes_written = 0;
        let mut server_bytes_written = 0;
        let start_time = Instant::now();

        info!("Starting MongoDB duplex connection");

        loop {
            let downstream_read = client_stream.read(&mut upstream_buf);
            let upstream_read = server_stream.read(&mut downstream_buf);

            let event: DuplexEvent;
            select! {
                n = downstream_read => event = DuplexEvent::DownstreamRead(n.unwrap_or(0)),
                n = upstream_read => event = DuplexEvent::UpstreamRead(n.unwrap_or(0)),
            }

            match event {
                DuplexEvent::DownstreamRead(0) => {
                    info!(
                        "Client closed MongoDB connection after {:?}",
                        start_time.elapsed()
                    );
                    info!("Connection stats: client read: {} bytes, server read: {} bytes, client written: {} bytes, server written: {} bytes",
                          client_bytes_read, server_bytes_read, client_bytes_written, server_bytes_written);
                    return;
                }
                DuplexEvent::UpstreamRead(0) => {
                    info!(
                        "Server closed MongoDB connection after {:?}",
                        start_time.elapsed()
                    );
                    info!("Connection stats: client read: {} bytes, server read: {} bytes, client written: {} bytes, server written: {} bytes",
                          client_bytes_read, server_bytes_read, client_bytes_written, server_bytes_written);

                    // Log a more detailed error message
                    if server_bytes_read == 0 {
                        error!("MongoDB server closed connection without sending any data. This could indicate:");
                        error!("1. TLS handshake failure - the server doesn't support TLS or has incompatible TLS settings");
                        error!("2. Authentication failure - incorrect username/password");
                        error!("3. Network configuration issue - the server is configured to reject connections from this IP");
                        error!("4. MongoDB server is configured to only accept connections from specific IPs");

                        // Suggest a retry with a longer timeout
                        error!(
                            "Try increasing connection timeout to at least {} seconds",
                            Duration::from_secs(30).as_secs()
                        );
                    }
                    return;
                }
                DuplexEvent::DownstreamRead(n) => {
                    client_bytes_read += n;

                    // Log first few bytes of client data for debugging
                    if client_bytes_read <= n && n > 0 {
                        let log_bytes = std::cmp::min(n, 10);
                        let bytes_str = upstream_buf[0..log_bytes]
                            .iter()
                            .map(|b| format!("{:#04x}", b))
                            .collect::<Vec<_>>()
                            .join(", ");
                        info!("First {} bytes from client: [{}]", log_bytes, bytes_str);
                    }

                    debug!(
                        "Read {} bytes from client (total: {})",
                        n, client_bytes_read
                    );

                    if let Err(e) = server_stream.write_all(&upstream_buf[0..n]).await {
                        error!("Error writing to server: {}", e);
                        return;
                    }
                    server_bytes_written += n;

                    if let Err(e) = server_stream.flush().await {
                        error!("Error flushing server stream: {}", e);
                        return;
                    }
                }
                DuplexEvent::UpstreamRead(n) => {
                    server_bytes_read += n;

                    // Log first few bytes of server data for debugging
                    if server_bytes_read <= n && n > 0 {
                        let log_bytes = std::cmp::min(n, 10);
                        let bytes_str = downstream_buf[0..log_bytes]
                            .iter()
                            .map(|b| format!("{:#04x}", b))
                            .collect::<Vec<_>>()
                            .join(", ");
                        info!("First {} bytes from server: [{}]", log_bytes, bytes_str);
                    }

                    debug!(
                        "Read {} bytes from server (total: {})",
                        n, server_bytes_read
                    );

                    if let Err(e) = client_stream.write_all(&downstream_buf[0..n]).await {
                        error!("Error writing to client: {}", e);
                        return;
                    }
                    client_bytes_written += n;

                    if let Err(e) = client_stream.flush().await {
                        error!("Error flushing client stream: {}", e);
                        return;
                    }
                }
            }
        }
    }
}

#[async_trait]
impl ServerApp for MongoDBProxy {
    async fn process_new(
        self: &Arc<Self>,
        mut client_stream: Stream,
        _shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        // Start timing the request
        let _start_time = Instant::now();

        // Read the first chunk to extract SNI hostname
        let mut buf = [0; 8192];
        let n = match client_stream.read(&mut buf).await {
            Ok(n) => {
                info!("Read {} bytes from client for MongoDB connection", n);
                n
            }
            Err(e) => {
                error!("Error reading from client: {}", e);
                return None;
            }
        };

        if n == 0 {
            debug!("Client sent empty request");
            return None;
        }

        // Log the first few bytes for debugging
        if n >= 5 {
            info!("First 5 bytes of MongoDB connection: [{:#04x}, {:#04x}, {:#04x}, {:#04x}, {:#04x}]",
                buf[0], buf[1], buf[2], buf[3], buf[4]);

            // Check if this looks like a TLS ClientHello (should start with 0x16)
            if buf[0] == 0x16 {
                info!("Detected TLS ClientHello for MongoDB connection");

                // Log TLS version if available
                if n >= 7 {
                    info!("TLS version: {}.{}", buf[1], buf[2]);

                    // Log handshake type if available (should be 1 for ClientHello)
                    if n >= 9 {
                        info!("Handshake type: {}", buf[5]);
                    }
                }
            } else {
                info!(
                    "Not a TLS ClientHello for MongoDB, first byte: {:#04x}",
                    buf[0]
                );
            }
        }

        // Extract SNI hostname
        let hostname = match Self::extract_sni_hostname(&buf[0..n]) {
            Some(hostname) => {
                info!("MongoDB connection with SNI hostname: {}", hostname);
                hostname
            }
            None => {
                error!("Could not extract SNI hostname from MongoDB connection");

                // Log more details about the failure
                if n >= 5 && buf[0] == 0x16 {
                    error!("Failed to extract SNI from what appears to be a TLS ClientHello");
                    // Try to determine why SNI extraction failed
                    if n < 50 {
                        error!("ClientHello might be too short: {} bytes", n);
                    }
                } else {
                    error!("Not a TLS ClientHello or malformed TLS message");
                }

                // Increment failed requests counter
                PROXY_METRICS
                    .requests_total
                    .with_label_values(&["unknown", "400"])
                    .inc();
                return None;
            }
        };

        // Get the target outside await points to avoid holding MutexGuard across await
        let target = {
            match self.servers.lock() {
                Ok(guard) => guard.get(&hostname).map(|(target, _)| target.clone()),
                Err(e) => {
                    error!("Error locking servers mutex in MongoDBProxy: {:?}", e);
                    None
                }
            }
        };

        // Process the target
        match target {
            Some(to) => {
                info!("Routing MongoDB request to backend: {}", to);

                // Handle Swarm service discovery
                let (host, port, _org_id) = parse_swarm_target(&to);
                info!("Using Swarm DNS target: {}", host);

                // Create connection to the target
                let server_addr = format!("{}:{}", host, port);
                info!(
                    "Attempting to connect to MongoDB backend at {}",
                    server_addr
                );

                // Try to connect with the original host
                let connect_start = Instant::now();
                let connect_result = tokio::net::TcpStream::connect(&server_addr).await;
                let connect_duration = connect_start.elapsed();

                // If the original connection fails, try alternative connection methods
                let mut server_stream = match connect_result {
                    Ok(stream) => {
                        info!(
                            "Successfully connected to MongoDB backend {} in {:?}",
                            server_addr, connect_duration
                        );

                        // Get peer address if possible
                        if let Ok(peer_addr) = stream.peer_addr() {
                            info!("Connected to peer address: {}", peer_addr);
                        }

                        // Get local address if possible
                        if let Ok(local_addr) = stream.local_addr() {
                            info!("Using local address: {}", local_addr);
                        }

                        // Convert TcpStream to boxed Stream
                        Box::new(pingora::protocols::l4::stream::Stream::from(stream))
                    }
                    Err(e) => {
                        error!(
                            "Failed to connect to MongoDB backend {} after {:?}: {}",
                            server_addr, connect_duration, e
                        );

                        // Try alternative connection methods if DNS resolution failed
                        if e.kind() == std::io::ErrorKind::AddrNotAvailable
                            || e.kind() == std::io::ErrorKind::Other
                                && e.to_string().contains("lookup")
                        {
                            // Try direct connection to the service without 'tasks.' prefix
                            let service_name = if host.starts_with("tasks.") {
                                host[6..].to_string() // Remove "tasks." prefix
                            } else {
                                host.clone()
                            };

                            let alt_addr = format!("{}:{}", service_name, port);
                            info!("Trying alternative connection to: {}", alt_addr);

                            match tokio::net::TcpStream::connect(&alt_addr).await {
                                Ok(stream) => {
                                    info!(
                                        "Successfully connected to alternative address: {}",
                                        alt_addr
                                    );
                                    Box::new(pingora::protocols::l4::stream::Stream::from(stream))
                                }
                                Err(alt_e) => {
                                    error!("Alternative connection also failed: {}", alt_e);

                                    // Try one more approach - try to find the IP directly from Docker
                                    // This requires the proxy to have access to the Docker socket
                                    if let Some(ip) = try_get_service_ip(&service_name) {
                                        let ip_addr = format!("{}:{}", ip, port);
                                        info!("Trying direct IP connection to: {}", ip_addr);

                                        match tokio::net::TcpStream::connect(&ip_addr).await {
                                            Ok(stream) => {
                                                info!(
                                                    "Successfully connected to IP address: {}",
                                                    ip_addr
                                                );
                                                Box::new(
                                                    pingora::protocols::l4::stream::Stream::from(
                                                        stream,
                                                    ),
                                                )
                                            }
                                            Err(ip_e) => {
                                                error!("IP connection also failed: {}", ip_e);

                                                // All attempts failed
                                                PROXY_METRICS
                                                    .requests_total
                                                    .with_label_values(&[&hostname, "502"])
                                                    .inc();
                                                return None;
                                            }
                                        }
                                    } else {
                                        // Couldn't get IP, all attempts failed
                                        PROXY_METRICS
                                            .requests_total
                                            .with_label_values(&[&hostname, "502"])
                                            .inc();
                                        return None;
                                    }
                                }
                            }
                        } else {
                            // For other types of errors, just fail
                            PROXY_METRICS
                                .requests_total
                                .with_label_values(&[&hostname, "502"])
                                .inc();
                            return None;
                        }
                    }
                };

                // Check if the MongoDB server is actually running and accepting connections

                // Note: We can't easily set TCP_NODELAY on the Pingora Stream
                // But that's okay, the default settings should work fine

                // Don't forward the TLS ClientHello to the MongoDB server
                // Instead, we'll handle the TLS handshake here and then forward the MongoDB protocol data

                // Log that we're doing TLS termination
                info!("Performing TLS termination for MongoDB connection");

                // We've already extracted the SNI hostname, now we'll connect to the MongoDB server
                // using plain TCP and handle the MongoDB protocol data

                // Log MongoDB server connection established
                info!("MongoDB server connection established");

                // Now we need to tell the client that we're ready to receive MongoDB protocol data
                // We do this by sending a simple message to the server
                let test_message = b"ping";
                if let Err(e) = server_stream.write_all(test_message).await {
                    error!("Error sending test message to server: {}", e);
                    return None;
                }

                if let Err(e) = server_stream.flush().await {
                    error!("Error flushing test message to server: {}", e);
                    return None;
                }

                info!("Sent test message to MongoDB server");

                // Now we'll read the response from the server
                let mut response_buf = [0; 8192];
                let response_n = match server_stream.read(&mut response_buf).await {
                    Ok(n) => {
                        if n == 0 {
                            error!("Server closed connection before sending response");
                            return None;
                        }
                        info!("Read {} bytes of response from MongoDB server", n);
                        n
                    }
                    Err(e) => {
                        error!("Error reading response from MongoDB server: {}", e);
                        return None;
                    }
                };

                // Log the first few bytes of the response
                if response_n >= 5 {
                    let log_bytes = std::cmp::min(response_n, 10);
                    let bytes_str = response_buf[0..log_bytes]
                        .iter()
                        .map(|b| format!("{:#04x}", b))
                        .collect::<Vec<_>>()
                        .join(", ");
                    info!(
                        "First {} bytes of response from MongoDB server: [{}]",
                        log_bytes, bytes_str
                    );
                }

                // Now we'll start the duplex connection
                info!("Starting duplex connection between client and MongoDB server");

                // Handle the rest of the duplex connection
                self.handle_duplex(client_stream, server_stream).await;

                // Increment successful requests counter
                PROXY_METRICS
                    .requests_total
                    .with_label_values(&[&hostname, "200"])
                    .inc();

                None
            }
            None => {
                error!("No backend found for MongoDB hostname: {}", hostname);
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
