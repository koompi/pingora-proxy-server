# Certificate Management with Let's Encrypt

This guide explains how Pingora Proxy Server integrates with Let's Encrypt for automated SSL/TLS certificate management.

## Overview

Pingora Proxy Server provides comprehensive SSL/TLS certificate management using Let's Encrypt and Certbot. It supports:

- Automatic certificate issuance and renewal
- Standard domain certificates (HTTP-01 challenge)
- Wildcard certificates (DNS-01 challenge with Cloudflare)
- Certificate distribution across cluster nodes
- Certificate reload without service restart

## Certificate Components

The certificate management system consists of several components:

1. **Certificate Issuer** (`CertificateIssuer`): Handles the certificate request process
2. **Certificate Watcher** (`CertWatcherService`): Monitors for certificate changes
3. **ACME Challenge Handler**: Responds to Let's Encrypt validation challenges
4. **Certificate Cache**: Stores loaded certificates in memory
5. **Distributed Notification**: Propagates certificate changes across nodes

## Certificate Storage

Certificates are stored in standard Certbot directory structure:

```
/certbot/letsencrypt/
├── accounts/                 # Let's Encrypt account information
├── live/                     # Live certificates (symlinks)
│   ├── example.com/
│   │   ├── cert.pem          # Domain certificate
│   │   ├── chain.pem         # Intermediate certificates
│   │   ├── fullchain.pem     # Combined cert + chain
│   │   └── privkey.pem       # Private key
├── archive/                  # Archive of all certificates
└── renewal/                  # Renewal configuration
```

## Certificate Types

### Standard Certificates

Standard certificates are issued for a single domain (e.g., `example.com`) and use the HTTP-01 challenge method:

1. Let's Encrypt sends a token to verify domain ownership
2. Pingora serves this token at `/.well-known/acme-challenge/{token}`
3. Let's Encrypt validates the response
4. Certificate is issued if validation is successful

**Required configuration:**

- Domain must resolve to the proxy's IP address
- Port 80 must be accessible from the internet

### Wildcard Certificates

Wildcard certificates cover a domain and all its subdomains (e.g., `*.example.com`) and use the DNS-01 challenge method with Cloudflare integration:

1. Let's Encrypt provides a challenge token
2. Pingora uses Cloudflare API to create a DNS TXT record
3. Let's Encrypt verifies the DNS record
4. Certificate is issued if validation is successful

**Required configuration:**

- Cloudflare API token with DNS edit permissions
- Domain must use Cloudflare for DNS

## Certificate Issuance

### Using the API

The easiest way to request certificates is through the API:

```bash
# Standard certificate
curl -X POST "http://localhost:81/certificates" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "email": "admin@example.com"
  }'

# Wildcard certificate
curl -X POST "http://localhost:81/certificates" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "email": "admin@example.com",
    "wildcard": true,
    "dns_provider": "cloudflare",
    "dns_credentials": {
      "api_token": "your_cloudflare_api_token"
    }
  }'
```

### Using the Certbot Wrapper

You can also use the included `certbot-wrapper.sh` script for manual certificate operations:

```bash
# Request standard certificate
./certbot-wrapper.sh request-standard example.com admin@example.com

# Request wildcard certificate
./certbot-wrapper.sh request-wildcard example.com admin@example.com your_cloudflare_token

# Renew all certificates
./certbot-wrapper.sh renew
```

## Certificate Renewal

Certificates are automatically checked for renewal based on these conditions:

1. A certificate is considered valid if it's not expiring within 30 days
2. If a certificate is expiring within 30 days, renewal is attempted
3. Renewal uses the same validation method as the original issuance

The `cert-manager.sh` script handles periodic renewal checks:

```bash
# Check for renewals every 12 hours
./cert-manager.sh
```

## Certificate Distribution

In a multi-node environment, certificates need to be synchronized across all nodes. Pingora implements this using:

1. **Shared Storage**: Certificates stored on shared volumes (e.g., GlusterFS)
2. **Change Notification**: Flag files created on certificate changes
3. **Certificate Watcher**: Service that monitors for certificate changes
4. **Atomic Reloads**: Updates certificates without dropping connections

The distribution process works as follows:

1. A certificate is issued or renewed on one node
2. The node writes a notification to `/pingora-proxy/cert-reload/last_reload`
3. Other nodes detect the change through the `CertWatcherService`
4. All nodes reload their certificate caches
5. New connections use the updated certificates

## Certificate Caching

To improve performance, certificates are cached in memory:

```rust
pub cert_cache: Arc<Mutex<HashMap<String, (Vec<u8>, Vec<u8>, u64)>>>
```

The cache stores:

- Certificate data
- Private key data
- Timestamp of the last update

## Handling ACME Challenges

The HTTP proxy component handles ACME challenges for domain validation:

1. Challenges are served from `/.well-known/acme-challenge/`
2. Active challenges are stored in `ACTIVE_CHALLENGES` in memory
3. If not found in memory, the system checks the filesystem
4. Challenge responses are prioritized over normal request routing

## Certificate Reload Process

When certificates change, the proxy implements a graceful reload process:

1. The `CertWatcherService` detects changes in the certificate filesystem
2. It signals the `HttpsProxy` to reload its certificate cache
3. New connections use the updated certificates
4. Existing connections continue with their current certificates

You can manually trigger a certificate reload:

```bash
curl -X POST "http://localhost:81/admin/reload_certs"
```

## Wildcard Certificate Configuration

To use wildcard certificates, you need Cloudflare credentials:

### Environment Variables Method

Set the Cloudflare API token as an environment variable:

```yaml
environment:
  - CLOUDFLARE_API_TOKEN=your_cloudflare_api_token
```

### API Request Method

Include credentials in the certificate request:

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

## Certificate Status Monitoring

You can check the status of certificates using the API:

```bash
curl -X GET "http://localhost:81/certificates/status/example.com"
```

This returns JSON with certificate details:

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

## Distributed Locking

To prevent conflicts when multiple nodes try to issue certificates simultaneously, the system uses distributed locking:

1. A lock file is created in `/pingora-proxy/locks/certman.lock`
2. The file contains the node ID and timestamp
3. Only the node that holds the lock can issue certificates
4. The lock expires after 5 minutes to prevent deadlocks

## Certificate Security Considerations

The system implements several security measures:

1. Private keys permissions are set to `0600` (owner read/write only)
2. Cloudflare credentials are stored in temporary files and deleted after use
3. Certificates and keys are stored in the standard Certbot directory structure
4. All certificate operations are logged for audit purposes

## Troubleshooting Certificate Issues

### Common Issues and Solutions

#### Certificate Issuance Fails

Possible causes and solutions:

1. **Domain doesn't resolve to proxy**

   - Verify DNS records point to the proxy's IP
   - Run `dig example.com` to check

2. **Port 80 not accessible**

   - Ensure port 80 is open in firewalls
   - Test with `curl http://example.com/.well-known/acme-challenge/test`

3. **Let's Encrypt rate limits**
   - Use staging environment for testing: `"staging": true`
   - Wait before retrying (rate limits reset after 7 days)

#### Wildcard Certificate Issues

1. **Cloudflare API errors**

   - Verify API token has DNS edit permissions for the domain
   - Check the zone is active in Cloudflare

2. **DNS propagation delays**
   - Increase DNS propagation wait time
   - Check if DNS changes are visible with `dig TXT _acme-challenge.example.com`

#### Certificate Renewal Problems

1. **Automatic renewal fails**
   - Check Certbot logs: `/var/log/cert-manager.log`
   - Verify certificates are accessible to the renewal service

### Debugging Commands

```bash
# Check certificate files
ls -la /certbot/letsencrypt/live/example.com/

# View certificate details
openssl x509 -in /certbot/letsencrypt/live/example.com/fullchain.pem -text -noout

# Test ACME challenge endpoint
curl http://example.com/.well-known/acme-challenge/test

# Check certificate renewal status
certbot certificates

# Manually force renewal
certbot renew --force-renewal
```

## Best Practices

1. Use wildcard certificates for domains with many subdomains
2. Set up regular certificate monitoring
3. Ensure shared storage for certificates in multi-node deployments
4. Test certificate issuance in staging environment first
5. Keep backup copies of certificates and private keys
6. Monitor certificate expiration dates
7. Plan for rate limit constraints when requesting many certificates
