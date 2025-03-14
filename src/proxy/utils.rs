use regex::Regex;

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

pub fn parse_swarm_target(target: &str) -> (String, u16, Option<String>) {
    // Split by colon to separate host and port
    let parts: Vec<&str> = target.split(':').collect();
    
    // Extract port, default to 80 if not specified
    let port = if parts.len() > 1 {
        parts[1].parse::<u16>().unwrap_or(80)
    } else {
        80
    };
    
    // Keep the full service DNS name without modification
    // This is crucial for proper DNS resolution in Docker Swarm
    (parts[0].to_string(), port, None)
}