# Pingora Proxy Server API Reference

## Base URL

All API endpoints are available at port 81 on the server where the proxy is running.

```
http://[proxy-server]:81/
```

## Authentication

The API does not currently implement authentication. It is recommended to secure the management port (81) using network controls.

## Endpoints

### Domain Mapping Management

#### List all domain mappings

```
GET /
```

Retrieves all configured domain mappings.

**Response**

```json
{
  "status": "success",
  "mappings": [
    {
      "from": "example.com",
      "to": "192.168.1.213:3040",
      "origin": "Manual"
    },
    {
      "from": "api.example.com",
      "to": "192.168.1.213:4444",
      "origin": "SwarmDiscovery"
    }
  ]
}
```

The `origin` field indicates how the mapping was created:

- `Manual`: Created through the API
- `SwarmDiscovery`: Automatically discovered from Docker Swarm

#### Add or Update domain mapping

```
POST /{domain}/{backend}
```

Creates or updates a domain-to-backend mapping.

**Parameters**

- `domain`: Domain name to route (e.g., example.com)
- `backend`: Backend service address (e.g., 192.168.1.213:3040 or service.network:80)

**Response**

```json
{
  "status": "success"
}
```

#### Delete domain mapping

```
DELETE /domain/{domain}
```

Removes a domain mapping from the configuration.

**Parameters**

- `domain`: Domain name to remove

**Response**

```json
{
  "status": "success"
}
```

### Certificate Management

#### Request a new certificate

```
POST /certificates
```

Requests a new SSL/TLS certificate from Let's Encrypt.

**Request Body**

```json
{
  "domain": "example.com",
  "email": "admin@example.com",
  "staging": false,
  "force_renew": false,
  "wildcard": false
}
```

**Parameters**

- `domain`: Domain name for the certificate
- `email`: Contact email for Let's Encrypt
- `staging`: (Optional) Use Let's Encrypt staging environment
- `force_renew`: (Optional) Force renewal even if a valid certificate exists
- `wildcard`: (Optional) Request a wildcard certificate

**Response**

```json
{
  "domain": "example.com",
  "status": "issued",
  "cert_path": "/certbot/letsencrypt/live/example.com/fullchain.pem",
  "key_path": "/certbot/letsencrypt/live/example.com/privkey.pem",
  "expiry": "SystemTime { tv_sec: 1719846523, tv_nsec: 0 }",
  "is_wildcard": false
}
```

#### Request a wildcard certificate

```
POST /certificates
```

Requests a wildcard certificate using Cloudflare DNS verification.

**Request Body**

```json
{
  "domain": "example.com",
  "email": "admin@example.com",
  "wildcard": true,
  "dns_provider": "cloudflare",
  "dns_credentials": {
    "api_token": "your_cloudflare_api_token"
  }
}
```

**Parameters**

- `domain`: Root domain name (without the wildcard part)
- `email`: Contact email for Let's Encrypt
- `wildcard`: Must be `true` for wildcard certificates
- `dns_provider`: DNS provider for validation (currently only `cloudflare` supported)
- `dns_credentials`: Provider-specific credentials
  - `api_token`: Cloudflare API token
  - Alternatively: `api_key` and `api_email` for Cloudflare

**Response**

```json
{
  "domain": "example.com",
  "status": "issued",
  "cert_path": "/certbot/letsencrypt/live/example.com/fullchain.pem",
  "key_path": "/certbot/letsencrypt/live/example.com/privkey.pem",
  "expiry": "SystemTime { tv_sec: 1719846523, tv_nsec: 0 }",
  "is_wildcard": true
}
```

#### Check certificate status

```
GET /certificates/status/{domain}
```

Checks the status of a certificate for a specific domain.

**Parameters**

- `domain`: Domain name to check

**Response**

```json
{
  "domain": "example.com",
  "status": "valid",
  "cert_path": "/certbot/letsencrypt/live/example.com/fullchain.pem",
  "key_path": "/certbot/letsencrypt/live/example.com/privkey.pem",
  "expiry": "SystemTime { tv_sec: 1719846523, tv_nsec: 0 }",
  "is_wildcard": false
}
```

The `status` field can be one of:

- `valid`: Certificate is valid and not expiring soon
- `expiring_soon`: Certificate exists but expires within 30 days
- `unknown_expiry`: Certificate exists but expiry couldn't be determined
- `not_found`: No certificate found for this domain
- `failed`: Error occurred while checking the certificate

#### Reload certificates

```
POST /admin/reload_certs
```

Forces the proxy to reload certificates from disk. Useful after manual certificate operations.

**Response**

```json
{
  "status": "success",
  "message": "Certificate reload completed successfully. All nodes will pick up changes within 15 seconds."
}
```

### Health Check

```
GET /health
```

Checks the health of the proxy and its components.

**Response**

```json
{
  "status": "healthy",
  "message": "Health check completed",
  "health": {
    "status": "healthy",
    "timestamp": "2025-03-29T10:15:30Z",
    "components": {
      "certificates": {
        "status": "healthy",
        "details": {
          "example.com": "valid"
        }
      },
      "backends": {
        "status": "healthy",
        "details": {
          "example.com->192.168.1.213:3040": "connected"
        }
      },
      "configuration": {
        "status": "healthy",
        "details": {}
      }
    }
  }
}
```

## Error Handling

All API endpoints return a JSON response with a `status` field indicating success or failure:

**Success Response**

```json
{
  "status": "success",
  "message": "Operation completed successfully"
}
```

**Error Response**

```json
{
  "status": "error",
  "error": "Detailed error message"
}
```

HTTP status codes are also used to indicate the result:

- `200 OK`: Request succeeded
- `400 Bad Request`: Invalid parameters or request body
- `404 Not Found`: Resource not found
- `500 Internal Server Error`: Server-side error

## Examples

### Add a domain mapping using cURL

```bash
curl -X POST "http://localhost:81/example.com/192.168.1.213:3040"
```

### Request a certificate using cURL

```bash
curl -X POST "http://localhost:81/certificates" \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com","email":"admin@example.com"}'
```

### Request a wildcard certificate using cURL

```bash
curl -X POST "http://localhost:81/certificates" \
  -H "Content-Type: application/json" \
  -d '{
    "domain":"example.com",
    "email":"admin@example.com",
    "wildcard":true,
    "dns_provider":"cloudflare",
    "dns_credentials":{
      "api_token":"your_cloudflare_api_token"
    }
  }'
```

### Check certificate status using cURL

```bash
curl -X GET "http://localhost:81/certificates/status/example.com"
```

### Delete a domain mapping using cURL

```bash
curl -X DELETE "http://localhost:81/domain/example.com"
```

### Reload certificates using cURL

```bash
curl -X POST "http://localhost:81/admin/reload_certs"
```
