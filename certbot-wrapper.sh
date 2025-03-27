#!/bin/bash
# certbot-wrapper.sh - Standalone certificate management script

# Set up logging
LOGFILE="/var/log/certbot-wrapper.log"
exec >>"$LOGFILE" 2>&1

echo "Starting certbot wrapper at $(date)"

# Function to request a standard certificate
request_standard_cert() {
    domain="$1"
    email="$2"
    
    echo "Requesting standard certificate for $domain"
    
    certbot certonly \
        --webroot \
        -w /var/www/html \
        --email "$email" \
        --agree-tos \
        --non-interactive \
        -d "$domain"
        
    return $?
}

# Function to request a wildcard certificate using Cloudflare
request_wildcard_cert() {
    domain="$1"
    email="$2"
    cf_token="$3"
    
    echo "Requesting wildcard certificate for $domain using Cloudflare DNS verification"
    
    # Create temporary credentials file
    CREDS_FILE=$(mktemp)
    echo "dns_cloudflare_api_token = $cf_token" > "$CREDS_FILE"
    chmod 600 "$CREDS_FILE"
    
    certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials "$CREDS_FILE" \
        --email "$email" \
        --agree-tos \
        --non-interactive \
        -d "$domain" \
        -d "*.$domain"
        
    result=$?
    
    # Remove credentials file
    rm -f "$CREDS_FILE"
    
    return $result
}

# Function to renew certificates
renew_certs() {
    echo "Checking for certificates that need renewal"
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
    echo "$(date +%s)" > /pingora-proxy/cert_reload_flag
    
    # Check if we're running in Docker Swarm
    if [ -n "$PROXY_SERVICE_NAME" ] && [ -f "/var/run/docker.sock" ]; then
        # Try to send HUP signal to the service
        echo "Signaling Docker service $PROXY_SERVICE_NAME to reload"
        docker kill --signal=HUP "$PROXY_SERVICE_NAME" || true
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