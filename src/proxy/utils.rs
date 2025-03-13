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
    // Input format could be:
    // 1. standard: service_name.network:port
    // 2. org-specific: org_id.service_name.network:port

    let parts: Vec<&str> = target.split(':').collect();
    let port = if parts.len() > 1 {
        parts[1].parse::<u16>().unwrap_or(80)
    } else {
        80
    };

    let dns_parts: Vec<&str> = parts[0].split('.').collect();

    if dns_parts.len() >= 3 {
        // This is an org-specific format
        let org_id = dns_parts[0];
        let service_name = dns_parts[1];
        // Network name is in dns_parts[2]

        (
            format!("{}.{}", service_name, dns_parts[2]),
            port,
            Some(org_id.to_string()),
        )
    } else if dns_parts.len() == 2 {
        // Standard format
        (parts[0].to_string(), port, None)
    } else {
        // Default case
        (parts[0].to_string(), port, None)
    }
}
