#!/bin/bash
# cert-manager.sh - Separate certificate management process

# Set up logging
LOGFILE="/var/log/cert-manager.log"
exec >>"$LOGFILE" 2>&1

echo "Starting certificate manager process at $(date)"

# Create rate limit tracking directory
RATE_LIMIT_DIR="/pingora-proxy/cert_limits"
mkdir -p "$RATE_LIMIT_DIR"

# Function to check rate limits
check_rate_limits() {
    domain="$1"
    rate_file="$RATE_LIMIT_DIR/$domain.json"
    
    # Create file if it doesn't exist
    if [ ! -f "$rate_file" ]; then
        echo '{"attempts":[],"failures":0,"last_success":0}' > "$rate_file"
        return 0
    }
    
    # Read current rate data
    attempts=$(jq -r '.attempts[]' "$rate_file" 2>/dev/null || echo "")
    failures=$(jq -r '.failures' "$rate_file" 2>/dev/null || echo "0")
    
    # Count attempts in the last hour
    now=$(date +%s)
    one_hour_ago=$((now - 3600))
    
    recent_count=0
    for timestamp in $attempts; do
        if [ "$timestamp" -gt "$one_hour_ago" ]; then
            recent_count=$((recent_count + 1))
        fi
    done
    
    # Check if we've hit the limit (5 attempts per hour)
    if [ "$recent_count" -ge 5 ]; then
        echo "Rate limit reached for $domain: $recent_count attempts in the last hour"
        return 1
    fi
    
    return 0
}

# Function to record an attempt
record_attempt() {
    domain="$1"
    success="$2"
    rate_file="$RATE_LIMIT_DIR/$domain.json"
    
    # Create directory if it doesn't exist
    mkdir -p "$RATE_LIMIT_DIR"
    
    # Get current timestamp
    now=$(date +%s)
    
    # Initialize the file if it doesn't exist
    if [ ! -f "$rate_file" ]; then
        if [ "$success" = "true" ]; then
            echo "{\"attempts\":[$now],\"failures\":0,\"last_success\":$now}" > "$rate_file"
        else
            echo "{\"attempts\":[$now],\"failures\":1,\"last_success\":0}" > "$rate_file"
        fi
        return
    fi
    
    # Update existing file
    temp_file=$(mktemp)
    
    if [ "$success" = "true" ]; then
        jq ".attempts += [$now] | .last_success = $now" "$rate_file" > "$temp_file"
    else
        jq ".attempts += [$now] | .failures += 1" "$rate_file" > "$temp_file"
    fi
    
    mv "$temp_file" "$rate_file"
}

# Function to signal certificate reload
signal_cert_reload() {
  echo "Signaling certificate reload at $(date)"
  
  # Create the reload signal file that supervisord will detect
  echo "$(date +%s)" > /pingora-proxy/cert-reload/last_reload
  
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

# Function to check if certificate is expiring soon
is_expiring_soon() {
    domain="$1"
    days_threshold="$2"
    cert_path="/certbot/letsencrypt/live/$domain/fullchain.pem"
    
    # Check if certificate exists
    if [ ! -f "$cert_path" ]; then
        echo "Certificate for $domain doesn't exist"
        return 0  # True - needs certificate
    fi
    
    # Get expiry date
    expiry=$(openssl x509 -in "$cert_path" -noout -enddate 2>/dev/null | cut -d= -f2)
    if [ -z "$expiry" ]; then
        echo "Failed to get expiry for $domain"
        return 1  # False - to avoid unnecessary renewal attempts
    fi
    
    # Convert to timestamp
    expiry_date=$(date -d "$expiry" +%s 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "Failed to parse expiry date for $domain"
        return 1  # False - to avoid unnecessary renewal attempts
    fi
    
    now=$(date +%s)
    seconds_threshold=$((days_threshold * 86400))
    time_left=$((expiry_date - now))
    
    if [ $time_left -lt $seconds_threshold ]; then
        echo "Certificate for $domain expires soon (in $((time_left / 86400)) days)"
        return 0  # True - needs renewal
    else
        echo "Certificate for $domain is still valid (expires in $((time_left / 86400)) days)"
        return 1  # False - doesn't need renewal
    fi
}

# Function to check for certificates
check_certificates() {
  # First do a dry run to see if there are any issues
  echo "Performing dry-run renewal check at $(date)"
  certbot renew --dry-run --non-interactive
  dry_run_result=$?
  
  if [ $dry_run_result -eq 0 ]; then
    echo "Dry run successful, proceeding with actual renewal check"
    
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
  else
    echo "Dry run failed, checking individual certificates instead"
    
    # Get all domains with certificates
    domains=$(find /certbot/letsencrypt/live -maxdepth 1 -mindepth 1 -type d | xargs -I{} basename {})
    
    renewed=false
    
    # Process each domain individually
    for domain in $domains; do
      # Check if certificate is expiring soon (30 days)
      if is_expiring_soon "$domain" 30; then
        # Check rate limits
        if check_rate_limits "$domain"; then
          echo "Attempting to renew certificate for $domain"
          
          # Add random delay to avoid thundering herd
          sleep $((RANDOM % 10 + 2))
          
          # Try renewal for this specific certificate
          certbot renew --non-interactive --cert-name "$domain"
          
          if [ $? -eq 0 ]; then
            echo "Successfully renewed certificate for $domain"
            record_attempt "$domain" "true"
            renewed=true
          else
            echo "Failed to renew certificate for $domain"
            record_attempt "$domain" "false"
          fi
        else
          echo "Skipping renewal for $domain due to rate limits"
        fi
      fi
    done
    
    # Signal reload if any certificates were renewed
    if [ "$renewed" = "true" ]; then
      signal_cert_reload
    fi
  fi
}

# Function to create a new certificate
request_certificate() {
  domain=$1
  email=$2
  wildcard=$3
  
  # Check rate limits first
  if ! check_rate_limits "$domain"; then
    echo "Skipping certificate request for $domain due to rate limits"
    return 1
  fi
  
  echo "Requesting certificate for $domain (wildcard=$wildcard) at $(date)"
  
  if [ "$wildcard" = "true" ] && [ -n "$CLOUDFLARE_API_TOKEN" ]; then
    # Request wildcard certificate using Cloudflare DNS verification
    echo "Using Cloudflare DNS verification for wildcard certificate"
    
    # Create Cloudflare credentials file
    CF_CREDS_FILE=$(mktemp)
    echo "dns_cloudflare_api_token = $CLOUDFLARE_API_TOKEN" > "$CF_CREDS_FILE"
    chmod 600 "$CF_CREDS_FILE"
    
    # First perform a dry run
    certbot certonly \
      --dry-run \
      --dns-cloudflare \
      --dns-cloudflare-credentials "$CF_CREDS_FILE" \
      --email "$email" \
      --agree-tos \
      --non-interactive \
      -d "$domain" \
      -d "*.$domain"
      
    dry_run_result=$?
    
    if [ $dry_run_result -ne 0 ]; then
      echo "Dry run failed for $domain, aborting to prevent rate limit issues"
      rm -f "$CF_CREDS_FILE" 
      record_attempt "$domain" "false"
      return 1
    fi
    
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
    
    # First perform a dry run
    certbot certonly \
      --dry-run \
      --webroot \
      -w /var/www/html \
      --email "$email" \
      --agree-tos \
      --non-interactive \
      -d "$domain"
      
    dry_run_result=$?
    
    if [ $dry_run_result -ne 0 ]; then
      echo "Dry run failed for $domain, aborting to prevent rate limit issues"
      record_attempt "$domain" "false"
      return 1
    fi
    
    certbot certonly \
      --webroot \
      -w /var/www/html \
      --email "$email" \
      --agree-tos \
      --non-interactive \
      -d "$domain"
    
    result=$?
  fi
  
  # Record the attempt
  record_attempt "$domain" $([ $result -eq 0 ] && echo "true" || echo "false")
  
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

# Create directory for certificate reload notifications
mkdir -p /pingora-proxy/cert-reload

# Start the request monitor in the background
monitor_requests &
monitor_pid=$!

# Set up signal handling
trap 'kill $monitor_pid; exit 0' SIGTERM SIGINT

# Main certificate renewal loop
while true; do
  check_certificates
  
  # Add randomized sleep to avoid all nodes checking at exactly the same time
  sleep_time=$((3600 + RANDOM % 600))  # 1 hour + random offset up to 10 minutes
  echo "Sleeping for $sleep_time seconds until next certificate check"
  sleep $sleep_time
done