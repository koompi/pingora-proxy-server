curl -X POST "http://localhost:81/certificates" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "selendra.mongodb.koompi.cloud",
    "email": "admin@koompi.cloud",
    "wildcard": true,
    "dns_provider": "cloudflare",
    "dns_credentials": {
      "api_token": "your_cloudflare_api_token"
    }
  }'