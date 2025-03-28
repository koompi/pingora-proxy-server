// src/proxy/utils.rs with improved Swarm service discovery handling
use regex::Regex;
// Remove unused ErrorKind
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

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

/// Parse swarm target with enhanced error handling and better organization support
pub fn parse_swarm_target(target: &str) -> (String, u16, Option<String>) {
    // Split by colon to separate host and port
    let parts: Vec<&str> = target.split(':').collect();

    // Extract port, default to 80 if not specified
    let port = if parts.len() > 1 {
        parts[1].parse::<u16>().unwrap_or(80)
    } else {
        80
    };

    // Check if the host part is an IP address
    if parts[0].split('.').count() == 4
        && parts[0].split('.').all(|part| part.parse::<u8>().is_ok())
    {
        // It's an IP address, don't try to use Swarm DNS discovery
        return (parts[0].to_string(), port, None);
    }

    // Parse the host part to extract service name and org ID
    let host_parts: Vec<&str> = parts[0].split('.').collect();

    if host_parts.len() >= 2 {
        // If format includes an org ID prefix (something.service.network)
        if host_parts[0].contains("_") || !host_parts[0].chars().next().unwrap_or('a').is_digit(10)
        {
            // Extract org ID
            let org_id = Some(host_parts[0].to_string());

            // Use the standard Docker service discovery DNS format
            let service_name = host_parts[1].to_string();
            return (format!("tasks.{}", service_name), port, org_id);
        }

        // Handle the case where it's just service.network format
        return (format!("tasks.{}", host_parts[0]), port, None);
    }

    // Default: assume it's a direct service name
    let service_name = if parts[0].starts_with("tasks.") {
        parts[0].to_string()
    } else {
        format!("tasks.{}", parts[0])
    };

    (service_name, port, None)
}

/// Function to test if a Swarm service is reachable
pub async fn test_service_connectivity(service_name: &str, port: u16) -> bool {
    // First, attempt direct DNS resolution through Docker's DNS
    let addr = format!("{}:{}", service_name, port);
    if let Ok(stream) = TcpStream::connect_timeout(
        &addr.parse().unwrap_or(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port,
        )),
        Duration::from_millis(100),
    ) {
        drop(stream);
        return true;
    }

    // Try with tasks. prefix if it doesn't already have it
    if !service_name.starts_with("tasks.") {
        let tasks_addr = format!("tasks.{}:{}", service_name, port);
        if let Ok(stream) = TcpStream::connect_timeout(
            &tasks_addr.parse().unwrap_or(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                port,
            )),
            Duration::from_millis(100),
        ) {
            drop(stream);
            return true;
        }
    }

    false
}

/// Function to validate that a service is within an organization's network
pub fn validate_org_network_access(service_name: &str, org_id: &str) -> bool {
    // In a real implementation, you would:
    // 1. Query Docker API to get service details
    // 2. Check if the service is in the org's network
    // 3. Verify the service has the right org label
    //
    // This is a simplified version for demonstration

    if service_name.contains(org_id) || service_name.starts_with("tasks.") {
        return true;
    }

    // Default to deny for security
    false
}

/// Handle response logging with minimal output - using pingora headers instead of ResponseEvent
pub fn handle_response_event<T>(event: &Option<T>, is_debug: bool) {
    if !is_debug {
        return; // Skip if not in debug mode
    }

    // Instead of trying to match on ResponseEvent which might not exist,
    // we'll just log a generic message about the response
    if event.is_some() {
        log::debug!("Response event received (details omitted to reduce log size)");
    }
}

/// Process a request summary string with reduced logging
pub fn log_request_summary(summary: &str) -> Option<String> {
    // Parse just what we need from the request summary
    let parts: Vec<&str> = summary.split_whitespace().collect();

    if parts.len() >= 2 {
        let method = parts[0];
        let path = parts[1];

        // Extract host if available
        let host = if summary.contains("Host:") {
            let host_parts: Vec<&str> = summary.split("Host:").collect();
            if host_parts.len() > 1 {
                let host_value = host_parts[1].split_whitespace().next().unwrap_or("unknown");
                format!(", host: {}", host_value)
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        // Log concise request info
        log::info!("Request: {} {}{}", method, path, host);

        // Extract just the hostname for domain routing
        if let Some(host_value) = extract_hostname(summary) {
            return Some(host_value);
        }
    }

    None
}
