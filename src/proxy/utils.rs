use regex::Regex;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::net::TcpStream;


/// Extract hostname from HTTP request header
pub fn extract_hostname(request_line: &str) -> Option<String> {
    // Regular expression to extract Host header
    let re = Regex::new(r"Host:\s*([^\s,]+)").unwrap();

    if let Some(captures) = re.captures(request_line) {
        if let Some(hostname) = captures.get(1) {
            return Some(hostname.as_str().to_string());
        }
    }

    None
}

pub fn clean_backend_address(address: &str) -> String {
    // Remove any trailing commas or whitespace
    let cleaned = address.trim_end_matches(|c| c == ',' || c == ' ' || c == ';');

    // Ensure the address has a proper port format
    if !cleaned.contains(':') {
        // If no port specified, add default port 80
        return format!("{}:80", cleaned);
    }

    cleaned.to_string()
}




/// Enum to represent different resolution strategies
enum ResolutionStrategy {
    DirectName,
    WithDefaultPort(u16),
    TasksPrefix,
    TasksPrefixWithPort(u16),
    IngressDomain(u16),
}

impl ResolutionStrategy {
    /// Attempt to resolve the service name using the specified strategy
    fn resolve(&self, service_name: &str) -> Result<SocketAddr, std::io::Error> {
        let addr_str = match self {
            ResolutionStrategy::DirectName => service_name.to_string(),
            ResolutionStrategy::WithDefaultPort(port) => 
                format!("{}:{}", service_name, port),
            ResolutionStrategy::TasksPrefix => 
                format!("tasks.{}", service_name),
            ResolutionStrategy::TasksPrefixWithPort(port) => 
                format!("tasks.{}:{}", service_name, port),
            ResolutionStrategy::IngressDomain(port) => 
                format!("{}.ingress:{}", service_name, port),
        };

        addr_str.to_socket_addrs()
            .and_then(|mut addrs| addrs.next().ok_or_else(|| std::io::Error::new(
                std::io::ErrorKind::NotFound, 
                "No addresses found"
            )))
    }
}

pub async fn resolve_swarm_service(service_name: &str, default_port: u16) -> Result<SocketAddr, std::io::Error> {
    // Log the resolution attempt
    println!("Attempting to resolve Swarm service: {}", service_name);

    // Define resolution strategies
    let resolution_strategies = [
        ResolutionStrategy::DirectName,
        ResolutionStrategy::WithDefaultPort(default_port),
        ResolutionStrategy::TasksPrefix,
        ResolutionStrategy::TasksPrefixWithPort(default_port),
        ResolutionStrategy::IngressDomain(default_port),
    ];

    // Try each resolution strategy
    for strategy in &resolution_strategies {
        match strategy.resolve(service_name) {
            Ok(addr) => {
                // Validate the address with a quick TCP connection attempt
                match validate_address(&addr).await {
                    Ok(_) => {
                        println!("Successfully resolved service {} to {:?}", service_name, addr);
                        return Ok(addr);
                    }
                    Err(e) => {
                        println!("Address validation failed for {}: {:?}", service_name, e);
                    }
                }
            }
            Err(e) => {
                println!("Resolution strategy failed: {:?}", e);
            }
        }
    }

    // If all strategies fail, return an error
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound, 
        format!("Could not resolve service: {}", service_name)
    ))
}

/// Validate the address by attempting a quick TCP connection
async fn validate_address(addr: &SocketAddr) -> Result<(), std::io::Error> {
    // Set a short timeout for connection attempt
    let timeout = Duration::from_secs(2);
    
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut, 
            "Connection attempt timed out"
        ))
    }
}



/// Utility function to parse Swarm service target
pub fn parse_swarm_target(target: &str) -> (String, u16, Option<String>) {
    // Split the target into components
    let parts: Vec<&str> = target.split(':').collect();
    
    // Default port if not specified
    let (host, port) = match parts.len() {
        1 => (parts[0], 80),
        2 => (parts[0], parts[1].parse().unwrap_or(80)),
        _ => return ("".to_string(), 80, None)
    };

    // Check for organization ID in the hostname
    let (host, org_id) = if host.contains('.') {
        let host_parts: Vec<&str> = host.split('.').collect();
        if host_parts.len() > 1 {
            (host_parts[1..].join("."), Some(host_parts[0].to_string()))
        } else {
            (host.to_string(), None)
        }
    } else {
        (host.to_string(), None)
    };

    (host, port, org_id)
}
