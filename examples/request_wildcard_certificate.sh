#!/bin/bash
# Example script to request a wildcard certificate

# Set your domain and Cloudflare credentials
DOMAIN="example.com"
CLOUDFLARE_API_TOKEN="your_cloudflare_api_token"

# Or use API Key + Email
# CLOUDFLARE_API_KEY="your_cloudflare_api_key"
# CLOUDFLARE_API_EMAIL="your_cloudflare_email"

# Set the management API URL
MANAGEMENT_API="http://localhost:81"

# Create JSON payload
if [ ! -z "$CLOUDFLARE_API_TOKEN" ]; then
  # Using API Token (recommended)
  JSON_DATA=$(cat <<EOF
{
  "domain": "$DOMAIN",
  "email": "your-email@example.com",
  "wildcard": true,
  "dns_provider": "cloudflare",
  "dns_credentials": {
    "api_token": "$CLOUDFLARE_API_TOKEN"
  }
}
EOF
)
else
  # Using API Key + Email
  JSON_DATA=$(cat <<EOF
{
  "domain": "$DOMAIN",
  "email": "your-email@example.com",
  "wildcard": true,
  "dns_provider": "cloudflare",
  "dns_credentials": {
    "api_key": "$CLOUDFLARE_API_KEY",
    "api_email": "$CLOUDFLARE_API_EMAIL"
  }
}
EOF
)
fi

# Make the request
echo "Requesting wildcard certificate for *.$DOMAIN..."
curl -X POST "$MANAGEMENT_API/certificates" \
  -H "Content-Type: application/json" \
  -d "$JSON_DATA"

echo -e "\n\nTo check certificate status:"
echo "curl -X GET \"$MANAGEMENT_API/certificates/$DOMAIN\""