# Pingora Reverse Proxy with Docker Swarm Integration

<div align="center">
  <img src="https://img.shields.io/badge/Rust-E57324?style=for-the-badge&logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/Pingora-E32929?style=for-the-badge&logo=cloudflare&logoColor=white" alt="Pingora">
  <br>
  <img src="https://img.shields.io/badge/Dynamic_Configuration-success?style=flat-square" alt="Dynamic Configuration">
  <img src="https://img.shields.io/badge/TLS_Support-success?style=flat-square" alt="TLS Support">
  <img src="https://img.shields.io/badge/Docker_Swarm_Integration-success?style=flat-square" alt="Docker Swarm">
  <img src="https://img.shields.io/badge/Let's_Encrypt-success?style=flat-square" alt="Let's Encrypt">
  <img src="https://img.shields.io/badge/Zero_Downtime_TLS_Reload-success?style=flat-square" alt="Zero Downtime TLS Reload">
</div>

## 📜 Overview

This project implements a high-performance reverse proxy built with [Pingora](https://github.com/cloudflare/pingora) - Cloudflare's Rust framework for building fast, reliable network services. The proxy comes with integrated Docker Swarm service discovery, automatic TLS certificate management via Let's Encrypt, zero-downtime SSL certificate reloading, and a flexible management API.

### Key Features

- **HTTP/HTTPS Proxying**: Route traffic to backend services based on hostname
- **Dynamic Configuration**: Update routing rules without restarting the proxy
- **Automatic TLS**: Integration with Let's Encrypt for automatic certificate issuance
- **Zero-Downtime Certificate Reloading**: Update SSL certificates without service interruption
- **Docker Swarm Integration**: Automatic service discovery for Docker Swarm deployments
- **Management API**: HTTP/HTTPS endpoints for configuration management
- **Network Isolation**: Support for organization-based traffic isolation

## 🚀 Quick Start

```bash
# Start the proxy with Docker Compose
docker-compose up -d
```

## 🔧 Configuration

The proxy is configured through a JSON file (`config.json`) that maps domains to backend services:

```json
{
  "servers": [
    {
      "from": "example.com",
      "to": "192.168.1.100:8080",
      "origin": "Manual"
    },
    {
      "from": "api.example.com",
      "to": "192.168.1.101:3000",
      "origin": "SwarmDiscovery"
    }
  ]
}
```

## 🔌 Service Discovery

When running in Docker Swarm mode, the proxy automatically discovers services with the `com.koompi.proxy=true` label.

### Docker Service Example

```bash
docker service create \
  --name my-web-app \
  --network ingress \
  --label com.koompi.proxy=true \
  --label com.koompi.proxy.domain=app.example.com \
  --label com.koompi.proxy.port=3000 \
  nginx:latest
```

## 🔐 TLS Certificates

The proxy integrates with Let's Encrypt to automatically obtain and renew TLS certificates for your domains. Certificates are stored in the `certbot/letsencrypt/live/{domain}` directory.

### Zero-Downtime Certificate Reloading

The proxy supports reloading SSL certificates without service interruption, ensuring continuous availability during certificate renewals. When a new certificate is issued or updated, it's automatically propagated to all nodes in the swarm.

## 🛠️ API Reference

The management API is available on port 81 (HTTP) and port 443 (HTTPS if certificates are available).

### Domain Mapping Management

| Endpoint                   | Method | Description                |
| -------------------------- | ------ | -------------------------- |
| `GET /`                    | GET    | List all domain mappings   |
| `PUT /{domain}/{backend}`  | PUT    | Update an existing mapping |
| `POST /{domain}/{backend}` | POST   | Add a new mapping          |
| `DELETE /{domain}`         | DELETE | Remove a mapping           |

#### Example: Add a new mapping

```bash
curl -X POST "http://localhost:81/example.com/192.168.1.100:8080"
```

### Certificate Management

| Endpoint               | Method | Description                             |
| ---------------------- | ------ | --------------------------------------- |
| `/admin/reload_certs`  | POST   | Trigger certificate reload across nodes |
| `/cert/check/{domain}` | GET    | Check certificate status for a domain   |
| `/certificates`        | POST   | Request a new certificate               |

#### Example: Reload Certificates

```bash
curl -X POST "http://localhost:81/admin/reload_certs"
```

#### Example: Check Certificate Status

```bash
curl "http://localhost:81/cert/check/example.com"
```

#### Example: Request a new certificate

```bash
curl -X POST "http://localhost:81/certificates" \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com","email":"admin@example.com"}'
```

## 🐳 Docker Swarm Integration

The proxy includes automatic service discovery for Docker Swarm deployments. It looks for services with specific labels:

- `com.koompi.proxy=true` - Marks the service for discovery
- `com.koompi.proxy.domain` - The domain to route traffic to this service
- `com.koompi.proxy.port` - The port the service listens on (defaults to 80)
- `com.koompi.org.id` - Optional organization ID for network isolation

### Example Docker Service Configuration

```yaml
version: "3.9"
services:
  web:
    image: nginx
    deploy:
      labels:
        com.koompi.proxy: "true"
        com.koompi.proxy.domain: "example.com"
        com.koompi.proxy.port: "80"
```

## 🏗️ Architecture

The proxy consists of several key components:

1. **HTTP Proxy**: Handles HTTP traffic and Let's Encrypt challenges
2. **HTTPS Proxy**: Handles HTTPS traffic with TLS termination
3. **Manager Proxy**: Provides the configuration API
4. **Certificate Watcher Service**: Monitors and reloads certificates across nodes
5. **Swarm Discovery Service**: Automatically detects services in Docker Swarm mode

## 📊 Advanced Features

### Organization Header Forwarding

For multi-tenant deployments, the proxy can extract organization information from the domain and forward it as a header:

```
# Input format
org_id.service_name.network:port

# Results in adding header
X-Organization-ID: org_id
```

### TLS Settings

TLS settings are configured using Pingora's `TlsSettings::intermediate` profile, which provides a good balance of security and compatibility.

### Zero-Downtime Certificate Reloading

The proxy implements a distributed certificate reload mechanism:

1. Certificate changes are written to a shared volume
2. Each node independently monitors for changes and reloads certificates in-memory
3. No service interruption during certificate updates
4. Certificate updates propagate across all nodes in the swarm

## 🔍 Troubleshooting

### Common Issues

- **Certificate not found**: Check the `certbot/letsencrypt/live` directory for your domain
- **Service not discovered**: Ensure services have the correct labels
- **HTTP Challenge failing**: Make sure port 80 is accessible from the internet
- **Certificate reload issues**: Check shared volumes and permissions

### Logs

The proxy outputs detailed logs that can help diagnose issues:

```bash
# View logs
docker service logs proxy_proxy

# View certificate-related logs
docker service logs proxy_proxy | grep -i "certificate"
```

## 📚 Development

### Prerequisites

- Rust 1.65 or later
- Docker 20.10 or later (for Swarm mode)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/koompi/pingora-proxy-server.git
cd pingora-proxy-server

# Build the project
cargo build --release

# Run with custom configuration
RUST_LOG=info ./target/release/pingora-proxy-server
```

### Build and push new docker image

```bash
docker buildx build --platform linux/amd64,linux/arm64 -t localhost:5000/library/pingora-proxy-server:latest --push .
```

### Environment Variables

| Variable             | Description                     | Default                       |
| -------------------- | ------------------------------- | ----------------------------- |
| `DOCKER_ENDPOINT`    | Docker API endpoint             | `unix:///var/run/docker.sock` |
| `SWARM_MODE`         | Enable Docker Swarm discovery   | `false`                       |
| `SWARM_NETWORKS`     | Networks to check for services  | `ingress`                     |
| `LOG_LEVEL`          | Logging verbosity               | `info`                        |
| `CONFIG_PATH`        | Path to configuration file      | `/app/config/config.json`     |
| `DISABLE_SSL`        | Disable SSL/TLS functionality   | `false`                       |
| `PROXY_SERVICE_NAME` | Docker service name for updates | `proxy_proxy`                 |

## 📝 License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## 🙏 Acknowledgments

- [Cloudflare Pingora](https://github.com/cloudflare/pingora) - The high-performance Rust proxy framework
- [certbot](https://certbot.eff.org/) - For Let's Encrypt integration
- [bollard](https://github.com/fussybeaver/bollard) - Rust Docker API client
