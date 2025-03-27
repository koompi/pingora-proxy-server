#!/bin/bash
# cert-manager.sh - Separate certificate management process

# Set up logging
LOGFILE="/var/log/cert-manager.log"
exec >>"$LOGFILE" 2>&1

echo "Starting certificate manager process at $(date)"

# Function to check for new certificates
check_certificates() {
  # Use certbot directly to check for expiring certificates and renew them
  echo "Checking for certificates due for renewal"
  certbot renew --non-interactive

  # Create a simple reload signal if any certs were renewed
  if [ $? -eq 0 ]; then
    echo "Certificates were renewed, signaling proxy for reload"
    echo "$(date +%s)" > /pingora-proxy/cert_renewed
    # Send a reload signal to the main proxy using Docker
    if [ -n "$PROXY_SERVICE_NAME" ]; then
      # Send SIGHUP to the proxy container
      docker kill --signal=HUP "$PROXY_SERVICE_NAME" 2>/dev/null || echo "Failed to send reload signal"
    else
      # For local development, we can use curl to trigger a reload via the admin API
      curl -s -X POST "http://localhost:81/admin/reload_certs" || echo "Failed to trigger reload via API"
    fi
  else
    echo "No certificates were renewed"
  fi
}

# Function to create a new certificate
request_certificate() {
  domain=$1
  email=$2
  wildcard=$3
  
  echo "Requesting certificate for $domain (wildcard=$wildcard) at $(date)"
  
  if [ "$wildcard" = "true" ] && [ -n "$CLOUDFLARE_API_TOKEN" ]; then
    # Request wildcard certificate using Cloudflare DNS verification
    echo "Using Cloudflare DNS verification for wildcard certificate"
    
    # Create Cloudflare credentials file
    CF_CREDS_FILE=$(mktemp)
    echo "dns_cloudflare_api_token = $CLOUDFLARE_API_TOKEN" > "$CF_CREDS_FILE"
    chmod 600 "$CF_CREDS_FILE"
    
    certbot certonly \
      --dns-cloudflare \
      --dns-cloudflare-credentials "$CF_CREDS_FILE" \
      --email "$email" \
      --agree-tos \
      --non-interactive \
      -d "$domain" \
      -d "*.$domain"
    
    result=$?
    rm -f "$CF_CREDS_FILE"
  else
    # Request regular certificate using HTTP verification
    echo "Using HTTP verification for standard certificate"
    
    certbot certonly \
      --webroot \
      -w /var/www/html \
      --email "$email" \
      --agree-tos \
      --non-interactive \
      -d "$domain"
    
    result=$?
  fi
  
  if [ $result -eq 0 ]; then
    echo "Successfully obtained certificate for $domain"
    echo "$(date +%s)" > /pingora-proxy/cert_renewed
    return 0
  else
    echo "Failed to obtain certificate for $domain"
    return 1
  fi
}

# Monitor API endpoint for certificate requests
monitor_requests() {
  # Check the request directory for new requests
  REQUEST_DIR="/pingora-proxy/cert_requests"
  mkdir -p "$REQUEST_DIR"
  
  while true; do
    for request_file in "$REQUEST_DIR"/*.req; do
      if [ -f "$request_file" ]; then
        echo "Processing certificate request: $request_file"
        
        # Parse the request file
        domain=$(grep "^domain=" "$request_file" | cut -d= -f2)
        email=$(grep "^email=" "$request_file" | cut -d= -f2)
        wildcard=$(grep "^wildcard=" "$request_file" | cut -d= -f2)
        
        if [ -n "$domain" ] && [ -n "$email" ]; then
          # Create backup of the request file
          cp "$request_file" "${request_file}.processing"
          
          # Remove the original to prevent duplicate processing
          rm -f "$request_file"
          
          # Request the certificate
          if request_certificate "$domain" "$email" "$wildcard"; then
            # Success - move to processed
            mv "${request_file}.processing" "${request_file}.processed"
          else
            # Failure - move to failed
            mv "${request_file}.processing" "${request_file}.failed"
          fi
        else
          echo "Invalid request file format: $request_file"
          mv "$request_file" "${request_file}.invalid"
        fi
      fi
    done
    
    # Sleep for a bit before checking again
    sleep 30
  done
}

# Start the request monitor in the background
monitor_requests &

# Main certificate renewal loop
while true; do
  check_certificates
  
  # Sleep for an hour between checks
  echo "Sleeping for 1 hour until next certificate check"
  sleep 3600
done