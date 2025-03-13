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
</div>

## 📜 Overview

This project implements a high-performance reverse proxy built with [Pingora](https://github.com/cloudflare/pingora) - Cloudflare's Rust framework for building fast, reliable network services. The proxy comes with integrated Docker Swarm service discovery, automatic TLS certificate management via Let's Encrypt, and a flexible management API.

### Key Features

- **HTTP/HTTPS Proxying**: Route traffic to backend services based on hostname
- **Dynamic Configuration**: Update routing rules without restarting the proxy
- **Automatic TLS**: Integration with Let's Encrypt for automatic certificate issuance
- **Docker Swarm Integration**: Automatic service discovery for Docker Swarm deployments
- **Management API**: HTTP/HTTPS endpoints for configuration management

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
      "to": "192.168.1.100:8080"
    },
    {
      "from": "api.example.com",
      "to": "192.168.1.101:3000"
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

## 🛠️ API Reference

The management API is available on port 81 (HTTP) and port 8443 (HTTPS if certificates are available).

### Domain Mapping Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /` | GET | List all domain mappings |
| `PUT /{domain}/{backend}` | PUT | Update an existing mapping |
| `POST /{domain}/{backend}` | POST | Add a new mapping |
| `DELETE /{domain}` | DELETE | Remove a mapping |

#### Example: Add a new mapping

```bash
curl -X POST "http://localhost:81/example.com/192.168.1.100:8080"
```

### Certificate Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `POST /certificates` | POST | Request a new certificate |
| `GET /certificates/{domain}` | GET | Check certificate status |

#### Example: Request a new certificate

```bash
curl -X POST "http://localhost:81/certificates" \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com","email":"admin@example.com"}'
```

#### Example: Check certificate status

```bash
curl "http://localhost:81/certificates/example.com"
```

## 🐳 Docker Swarm Integration

The proxy includes automatic service discovery for Docker Swarm deployments. It looks for services with specific labels:

- `com.koompi.proxy=true` - Marks the service for discovery
- `com.koompi.proxy.domain` - The domain to route traffic to this service
- `com.koompi.proxy.port` - The port the service listens on (defaults to 80)
- `com.koompi.org.id` - Optional organization ID for network isolation

### Example Docker Service Configuration

```yaml
version: '3.7'
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

The proxy consists of three main services:

1. **HTTP Proxy**: Handles HTTP traffic and Let's Encrypt challenges
2. **HTTPS Proxy**: Handles HTTPS traffic with TLS termination
3. **Manager Proxy**: Provides the configuration API

Additionally, a **Swarm Discovery Service** runs in the background when in Swarm mode to automatically detect services.

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

## 🔍 Troubleshooting

### Common Issues

- **Certificate not found**: Check the `certbot/letsencrypt/live` directory for your domain
- **Service not discovered**: Ensure services have the correct labels
- **HTTP Challenge failing**: Make sure port 80 is accessible from the internet

### Logs

The proxy outputs detailed logs that can help diagnose issues:

```bash
# View logs
docker-compose logs -f
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
```
docker buildx build --platform linux/amd64,linux/arm64 -t image.koompi.org/pingora-proxy-server:latest --push .
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DOCKER_ENDPOINT` | Docker API endpoint | `unix:///var/run/docker.sock` |
| `SWARM_MODE` | Enable Docker Swarm discovery | `false` |
| `SWARM_NETWORKS` | Networks to check for services | `ingress` |
| `LOG_LEVEL` | Logging verbosity | `info` |

## 📝 License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## 🙏 Acknowledgments

- [Cloudflare Pingora](https://github.com/cloudflare/pingora) - The high-performance Rust proxy framework
- [certbot](https://certbot.eff.org/) - For Let's Encrypt integration
- [bollard](https://github.com/fussybeaver/bollard) - Rust Docker API client