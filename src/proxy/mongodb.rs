// src/proxy/mongodb.rs - MongoDB TCP proxy with SNI-based routing
use std::{
    sync::{Arc, Mutex},
    time::Instant,
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
}

/// Structure to hold the MongoDB proxy service
pub struct MongoDBProxyService {
    _proxy: MongoDBProxy, // Renamed to _proxy to indicate it's intentionally unused
    service: Service<MongoDBProxy>,
}

impl MongoDBProxyService {
    /// Create a new MongoDB proxy service
    pub fn new(servers: Arc<Mutex<ConfigStore>>, conf: &ServerConf) -> Self {
        let proxy = MongoDBProxy { servers };

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
                    debug!("Client closed connection");
                    return;
                }
                DuplexEvent::UpstreamRead(0) => {
                    debug!("Server closed connection");
                    return;
                }
                DuplexEvent::DownstreamRead(n) => {
                    if let Err(e) = server_stream.write_all(&upstream_buf[0..n]).await {
                        error!("Error writing to server: {}", e);
                        return;
                    }
                    if let Err(e) = server_stream.flush().await {
                        error!("Error flushing server stream: {}", e);
                        return;
                    }
                }
                DuplexEvent::UpstreamRead(n) => {
                    if let Err(e) = client_stream.write_all(&downstream_buf[0..n]).await {
                        error!("Error writing to client: {}", e);
                        return;
                    }
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
            Ok(n) => n,
            Err(e) => {
                error!("Error reading from client: {}", e);
                return None;
            }
        };

        if n == 0 {
            debug!("Client sent empty request");
            return None;
        }

        // Extract SNI hostname
        let hostname = match Self::extract_sni_hostname(&buf[0..n]) {
            Some(hostname) => {
                info!("MongoDB connection with SNI hostname: {}", hostname);
                hostname
            }
            None => {
                error!("Could not extract SNI hostname from MongoDB connection");
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

                // Try to connect with the original host
                let connect_result = tokio::net::TcpStream::connect(&server_addr).await;

                // If the original connection fails, try alternative connection methods
                let server_stream = match connect_result {
                    Ok(stream) => {
                        // Convert TcpStream to boxed Stream
                        Box::new(pingora::protocols::l4::stream::Stream::from(stream))
                    }
                    Err(e) => {
                        error!(
                            "Failed to connect to MongoDB backend {}: {}",
                            server_addr, e
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

                // Handle the duplex connection
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
