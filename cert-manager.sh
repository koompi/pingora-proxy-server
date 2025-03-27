#!/bin/bash
# cert-manager.sh - Separate certificate management process

# Set up logging
LOGFILE="/var/log/cert-manager.log"
exec >>"$LOGFILE" 2>&1

echo "Starting certificate manager process at $(date)"

# Function to signal certificate reload
signal_cert_reload() {
  echo "Signaling certificate reload at $(date)"
  
  # Create the reload signal file that supervisord will detect
  echo "$(date +%s)" > /pingora-proxy/cert_renewed
  
  # Try to directly signal the pingora-proxy process if possible
  if command -v supervisorctl >/dev/null 2>&1; then
    echo "Using supervisorctl to signal reload"
    supervisorctl signal HUP pingora-proxy
  else
    echo "supervisorctl not available, relying on file-based signaling"
  fi
  
  # Alternative: Use curl to hit the admin API
  if command -v curl >/dev/null 2>&1; then
    echo "Sending reload signal via API"
    curl -s -X POST "http://localhost:81/admin/reload_certs" || echo "Failed to trigger reload via API"
  fi
}

# Function to check for new certificates
check_certificates() {
  # Use certbot directly to check for expiring certificates and renew them
  echo "Checking for certificates due for renewal at $(date)"
  certbot renew --non-interactive
  
  # Check if any certs were renewed
  if [ $? -eq 0 ]; then
    echo "Certificates were renewed"
    signal_cert_reload
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
    signal_cert_reload
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
      # Use nullglob to handle no matches
      [ -e "$request_file" ] || continue
      
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
monitor_pid=$!

# Set up signal handling
trap 'kill $monitor_pid; exit 0' SIGTERM SIGINT

# Main certificate renewal loop
while true; do
  check_certificates
  
  # Sleep for an hour between checks
  echo "Sleeping for 1 hour until next certificate check"
  sleep 3600
done