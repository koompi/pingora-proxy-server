#!/bin/bash
# certbot-wrapper.sh - Standalone certificate management script

# Set up logging
LOGFILE="/var/log/certbot-wrapper.log"
exec >>"$LOGFILE" 2>&1

echo "Starting certbot wrapper at $(date)"

# Create rate limit tracking directory
RATE_LIMIT_DIR="/certbot/rate_limits"
mkdir -p "$RATE_LIMIT_DIR"

# Function to check if we're within rate limits
check_rate_limits() {
    domain="$1"
    rate_file="$RATE_LIMIT_DIR/$domain.json"
    
    # Create file if it doesn't exist
    if [ ! -f "$rate_file" ]; then
        echo '{"attempts":[],"failures":0}' > "$rate_file"
        return 0
    fi
    
    # Read current rate data
    local attempts=$(jq '.attempts' "$rate_file")
    local failures=$(jq '.failures' "$rate_file")
    
    # Filter attempts to only include the last hour
    local one_hour_ago=$(date -d '1 hour ago' +%s)
    local recent_attempts=$(echo "$attempts" | jq "[.[] | select(. > $one_hour_ago)] | length")
    
    # Check if we've hit the limit (5 failures per hour)
    if [ "$recent_attempts" -ge 5 ]; then
        echo "Rate limit reached for $domain: $recent_attempts attempts in the last hour"
        return 1
    fi
    
    return 0
}

# Function to record an attempt
record_attempt() {
    domain="$1"
    success="$2"
    rate_file="$RATE_LIMIT_DIR/$domain.json"
    
    # Get current timestamp
    now=$(date +%s)
    
    # Read current data
    if [ -f "$rate_file" ]; then
        local data=$(cat "$rate_file")
        local attempts=$(echo "$data" | jq ".attempts")
        local failures=$(echo "$data" | jq ".failures")
        
        # Add new attempt
        attempts=$(echo "$attempts" | jq ". + [$now]")
        
        # Increment failures if this was a failure
        if [ "$success" != "true" ]; then
            failures=$(echo "$failures" | jq ". + 1")
        fi
        
        # Write back
        echo "{\"attempts\":$attempts,\"failures\":$failures}" > "$rate_file"
    else
        # Create new file
        if [ "$success" = "true" ]; then
            echo "{\"attempts\":[$now],\"failures\":0}" > "$rate_file"
        else
            echo "{\"attempts\":[$now],\"failures\":1}" > "$rate_file"
        fi
    fi
}

# Function to request a standard certificate
request_standard_cert() {
    domain="$1"
    email="$2"
    
    # Check rate limits first
    if ! check_rate_limits "$domain"; then
        echo "Skipping certificate request for $domain due to rate limits"
        return 1
    fi
    
    echo "Requesting standard certificate for $domain"
    
    # First try a dry run
    certbot certonly \
        --dry-run \
        --webroot \
        -w /var/www/html \
        --email "$email" \
        --agree-tos \
        --non-interactive \
        -d "$domain"
        
    if [ $? -ne 0 ]; then
        echo "Dry run failed for $domain, aborting to prevent rate limit issues"
        record_attempt "$domain" "false"
        return 1
    fi
    
    # Actual certificate request
    certbot certonly \
        --webroot \
        -w /var/www/html \
        --email "$email" \
        --agree-tos \
        --non-interactive \
        -d "$domain"
    
    result=$?
    record_attempt "$domain" $([ $result -eq 0 ] && echo "true" || echo "false")
    return $result
}

# Function to request a wildcard certificate using Cloudflare
request_wildcard_cert() {
    domain="$1"
    email="$2"
    cf_token="$3"
    
    # Check rate limits first
    if ! check_rate_limits "$domain"; then
        echo "Skipping certificate request for $domain due to rate limits"
        return 1
    fi
    
    echo "Requesting wildcard certificate for $domain using Cloudflare DNS verification"
    
    # Create temporary credentials file
    CREDS_FILE=$(mktemp)
    echo "dns_cloudflare_api_token = $cf_token" > "$CREDS_FILE"
    chmod 600 "$CREDS_FILE"
    
    # First try a dry run
    certbot certonly \
        --dry-run \
        --dns-cloudflare \
        --dns-cloudflare-credentials "$CREDS_FILE" \
        --email "$email" \
        --agree-tos \
        --non-interactive \
        -d "$domain" \
        -d "*.$domain"
    
    if [ $? -ne 0 ]; then
        echo "Dry run failed for $domain, aborting to prevent rate limit issues"
        rm -f "$CREDS_FILE"
        record_attempt "$domain" "false"
        return 1
    fi
    
    certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials "$CREDS_FILE" \
        --email "$email" \
        --agree-tos \
        --non-interactive \
        -d "$domain" \
        -d "*.$domain"
        
    result=$?
    rm -f "$CREDS_FILE"
    record_attempt "$domain" $([ $result -eq 0 ] && echo "true" || echo "false")
    return $result
}

# Function to renew certificates with improved rate limiting
renew_certs() {
    echo "Checking for certificates that need renewal at $(date)"
    
    # First perform a dry run
    certbot renew --dry-run --non-interactive
    
    if [ $? -ne 0 ]; then
        echo "Dry run renewal failed, checking individual certificates instead"
        
        # Get list of domains with certificates
        domains=$(find /certbot/letsencrypt/live -maxdepth 1 -mindepth 1 -type d | xargs -I{} basename {})
        
        # Process each domain individually
        for domain in $domains; do
            # Check expiry
            expiry=$(openssl x509 -in "/certbot/letsencrypt/live/$domain/fullchain.pem" -noout -enddate 2>/dev/null | cut -d= -f2)
            expiry_date=$(date -d "$expiry" +%s)
            now=$(date +%s)
            days_left=$(( (expiry_date - now) / 86400 ))
            
            echo "Certificate for $domain expires in $days_left days"
            
            # Only renew if less than 30 days left
            if [ $days_left -lt 30 ]; then
                # Check rate limits
                if check_rate_limits "$domain"; then
                    echo "Attempting to renew certificate for $domain"
                    
                    # Try renewal
                    certbot renew --non-interactive --cert-name "$domain"
                    result=$?
                    
                    # Record the attempt
                    record_attempt "$domain" $([ $result -eq 0 ] && echo "true" || echo "false")
                    
                    # Add a small delay between renewals
                    sleep $((RANDOM % 10 + 5))
                else
                    echo "Skipping renewal for $domain due to rate limits"
                fi
            fi
        done
        
        return 0
    fi
    
    # If dry run succeeded, proceed with normal renewal
    echo "Dry run successful, proceeding with certificate renewal"
    certbot renew --non-interactive
    return $?
}

# Parse command line arguments
case "$1" in
    "request-standard")
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "Usage: $0 request-standard <domain> <email>"
            exit 1
        fi
        request_standard_cert "$2" "$3"
        ;;
    "request-wildcard")
        if [ -z "$2" ] || [ -z "$3" ] || [ -z "$4" ]; then
            echo "Usage: $0 request-wildcard <domain> <email> <cloudflare_token>"
            exit 1
        fi
        request_wildcard_cert "$2" "$3" "$4"
        ;;
    "renew")
        renew_certs
        ;;
    *)
        echo "Usage: $0 {request-standard|request-wildcard|renew} [options]"
        exit 1
        ;;
esac

# Check if we need to signal the server to reload certificates
if [ $? -eq 0 ]; then
    echo "Certificate operation successful, signaling reload"
    
    # Create a reload signal file
    echo "$(date +%s)" > /pingora-proxy/cert-reload/last_reload
    
    # Check if we're running in Docker Swarm
    if [ -n "$PROXY_SERVICE_NAME" ] && [ -f "/var/run/docker.sock" ]; then
        # Try to send HUP signal to the service
        echo "Signaling Docker service $PROXY_SERVICE_NAME to reload"
        docker service update --force "$PROXY_SERVICE_NAME" || true
    fi
    
    # Additionally, try to hit the reload API endpoint
    if command -v curl >/dev/null 2>&1; then
        echo "Trying to trigger reload via API"
        curl -s -X POST "http://localhost:81/admin/reload_certs" || true
    fi
    
    exit 0
else
    echo "Certificate operation failed"
    exit 1
fi