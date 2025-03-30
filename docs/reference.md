# Pingora Proxy Server Configuration Reference

This document details all configuration options for Pingora Proxy Server, including file formats, environment variables, and deployment configurations.

## Configuration Structure

The primary configuration is stored in a JSON file, typically located at `/app/config/config.json`. The path can be customized using the `CONFIG_PATH` environment variable.

### Basic Configuration Example

```json
{
  "servers": [
    {
      "from": "example.com",
      "to": "192.168.1.213:3040",
      "origin": "Manual"
    },
    {
      "from": "api.example.com",
      "to": "backend-api:8080",
      "origin": "SwarmDiscovery"
    }
  ]
}
```

### Configuration Fields

| Field              | Type   | Description                                                 |
| ------------------ | ------ | ----------------------------------------------------------- |
| `servers`          | Array  | List of server mappings                                     |
| `servers[].from`   | String | Domain name to match                                        |
| `servers[].to`     | String | Backend address in format `host:port`                       |
| `servers[].origin` | String | How this mapping was created (`Manual` or `SwarmDiscovery`) |

## Configuration Methods

There are three ways to configure the proxy:

1. **Configuration File**: Static configuration in JSON format
2. **API**: Dynamic configuration through the management API
3. **Service Discovery**: Automatic configuration from Docker Swarm services

## Environment Variables

The proxy is configured using the following environment variables:

| Variable               | Description                                    | Default                       |
| ---------------------- | ---------------------------------------------- | ----------------------------- |
| `CONFIG_PATH`          | Path to configuration file                     | `/app/config/config.json`     |
| `DISABLE_SSL`          | Disable HTTPS redirection and TLS              | `false`                       |
| `SWARM_MODE`           | Enable Docker Swarm integration                | `false`                       |
| `SWARM_NETWORKS`       | Comma-separated list of networks to monitor    | `ingress`                     |
| `DOCKER_ENDPOINT`      | Docker API endpoint                            | `unix:///var/run/docker.sock` |
| `LOG_LEVEL`            | Log level (trace, debug, info, warn, error)    | `info`                        |
| `RUST_LOG`             | Rust logging configuration                     | `info,pingora=debug`          |
| `RUST_BACKTRACE`       | Enable stack traces on errors                  | `0`                           |
| `CLOUDFLARE_API_TOKEN` | Cloudflare API token for wildcard certificates | -                             |
| `METRICS_PORT`         | Port for Prometheus metrics                    | `9100`                        |
| `PROXY_SERVICE_NAME`   | Service name for distributed operations        | `proxy_proxy`                 |

## Security Policy Configuration

The security policy is defined in `security-policy.json`:

```json
{
  "network_policies": {
    "default": "allow",
    "org_networks": {
      "isolation_mode": "permissive",
      "allow_internal_communication": true,
      "allow_external_communication": true,
      "exceptions": []
    }
  },
  "container_policies": {
    "memory_limit": "1024M",
    "cpu_limit": "1.0",
    "capabilities": {
      "drop_all": false,
      "allow": ["ALL"]
    },
    "security_options": {
      "no_new_privileges": false,
      "read_only_filesystem": false,
      "user_namespace_mode": "off"
    },
    "tmpfs_mounts": []
  }
}
```

### Network Policies

| Field                          | Description                                                     | Default      |
| ------------------------------ | --------------------------------------------------------------- | ------------ |
| `default`                      | Default network policy (`allow` or `deny`)                      | `allow`      |
| `isolation_mode`               | Organization network isolation level (`strict` or `permissive`) | `permissive` |
| `allow_internal_communication` | Allow services within the same org to communicate               | `true`       |
| `allow_external_communication` | Allow services to communicate with external networks            | `true`       |
| `exceptions`                   | List of network rules that override the default policy          | `[]`         |

### Container Policies

| Field              | Description                         | Default |
| ------------------ | ----------------------------------- | ------- |
| `memory_limit`     | Maximum memory limit for containers | `1024M` |
| `cpu_limit`        | CPU limit for containers            | `1.0`   |
| `capabilities`     | Docker capabilities configuration   | -       |
| `security_options` | Container security options          | -       |
| `tmpfs_mounts`     | Temporary filesystem mounts         | `[]`    |

## Docker Compose Configuration

The `docker-compose.yml` file defines services, networks, volumes, and configurations:

```yaml
version: "3.9"

services:
  proxy:
    image: image.koompi.org/library/pingora-proxy-server:latest
    dns:
      - 127.0.0.11
      - 8.8.8.8
      - 1.1.1.1
    cap_add:
      - NET_BIND_SERVICE
    ports:
      - "80:80"
      - "443:443"
      - "81:81"
    networks:
      - proxy-network
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /mnt/gluster/certbot:/certbot
      - /mnt/gluster/certbot/letsencrypt:/etc/letsencrypt
      - /mnt/gluster/acme-challenge:/var/www/html/.well-known/acme-challenge
      - /mnt/gluster/proxy-config:/app/config
      - /mnt/gluster/pingora-proxy/locks:/pingora-proxy/locks
      - /mnt/gluster/pingora-proxy/cert_requests:/pingora-proxy/cert_requests
      - cert_reload:/pingora-proxy/cert-reload:rw
    environment:
      - SWARM_MODE=true
      - SWARM_NETWORKS=proxy-network
      - LOG_LEVEL=info
      - CONFIG_PATH=/app/config/config.json
      - DISABLE_SSL=false
      - PROXY_SERVICE_NAME=proxy_proxy
      - RUST_LOG=info,pingora=debug
      - RUST_BACKTRACE=0
      - METRICS_PORT=9100
    deploy:
      mode: replicated
      replicas: 3
      update_config:
        parallelism: 1
        delay: 10s
        order: start-first
        failure_action: rollback
      restart_policy:
        condition: any
        delay: 5s
      endpoint_mode: vip
      placement:
        max_replicas_per_node: 1
    configs:
      - source: proxy-security-policy
        target: /etc/security-policy.json
        mode: 0644
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
        compress: "true"
        tag: "proxy-{{.Name}}"

  # Other services defined...

networks:
  proxy-network:
    external: true

configs:
  proxy-security-policy:
    file: ./security-policy.json

volumes:
  prometheus_data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /mnt/gluster/prometheus/data
  # Other volumes defined...
```

## Volume Configuration

The proxy uses several volumes for persistent storage:

| Volume                                     | Purpose                         |
| ------------------------------------------ | ------------------------------- |
| `/certbot`                                 | Certificate storage             |
| `/etc/letsencrypt`                         | Let's Encrypt configuration     |
| `/var/www/html/.well-known/acme-challenge` | ACME challenge files            |
| `/app/config`                              | Configuration files             |
| `/pingora-proxy/locks`                     | Distributed lock files          |
| `/pingora-proxy/cert_requests`             | Certificate request queue       |
| `/pingora-proxy/cert-reload`               | Certificate reload notification |

## Network Configuration

The Docker Compose setup creates or uses several networks:

| Network         | Purpose                             |
| --------------- | ----------------------------------- |
| `proxy-network` | Main network for proxy and backends |
| `org_*_overlay` | Isolated networks per organization  |

## Prometheus Configuration

To enable monitoring with Prometheus, configure this `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: "pingora-proxy"
    static_configs:
      - targets: ["proxy:9100"]
```

## Proxy Configuration Details

### HTTP Proxy

The HTTP proxy component:

- Handles HTTP traffic on port 80
- Redirects HTTP to HTTPS
- Serves ACME challenges for Let's Encrypt
- Falls back to HTTP routing if SSL is disabled

### HTTPS Proxy

The HTTPS proxy component:

- Handles HTTPS traffic on port 443
- Uses SNI for multiple domain certificates
- Routes requests to backends based on the `Host` header
- Adds security headers for organization isolation

### Manager Proxy

The management API component:

- Serves the REST API on port 81
- Manages domain mappings
- Handles certificate operations
- Provides health check endpoints

## Advanced Configuration Options

### Circuit Breaker Configuration

You can configure circuit breakers for backend services in the configuration:

```json
{
  "circuit_breakers": {
    "default": {
      "failure_threshold": 5,
      "reset_timeout_seconds": 60,
      "half_open_success_threshold": 2
    },
    "critical_services": {
      "failure_threshold": 10,
      "reset_timeout_seconds": 30,
      "half_open_success_threshold": 3
    }
  }
}
```

### Rate Limiting Configuration

Configure rate limits for domains:

```json
{
  "rate_limits": {
    "default": {
      "requests_per_second": 10,
      "burst": 20
    },
    "domains": {
      "api.example.com": {
        "requests_per_second": 100,
        "burst": 200
      }
    }
  }
}
```

## Organization-Based Configuration

For multi-tenant setups, you can create organization-specific configurations:

```json
{
  "organizations": [
    {
      "id": "100",
      "name": "Org A",
      "domains": ["app-a.example.com", "api-a.example.com"],
      "network_isolation": true,
      "rate_limits": {
        "requests_per_second": 50,
        "burst": 100
      }
    },
    {
      "id": "200",
      "name": "Org B",
      "domains": ["app-b.example.com", "api-b.example.com"],
      "network_isolation": true,
      "rate_limits": {
        "requests_per_second": 100,
        "burst": 200
      }
    }
  ]
}
```

## Certificate Configuration

Configure certificate settings:

```json
{
  "certificates": {
    "auto_issuance": true,
    "renewal_days_before_expiry": 30,
    "prefer_wildcard": false,
    "email": "admin@example.com",
    "staging": false,
    "dns_provider": "cloudflare"
  }
}
```

## Distributed Configuration

For multi-node setups, configure distributed operations:

```json
{
  "distributed": {
    "lock_ttl_seconds": 60,
    "leader_check_interval_seconds": 15,
    "cert_sync_interval_seconds": 30,
    "config_sync_interval_seconds": 60
  }
}
```

## Logging Configuration

Configure detailed logging options:

```json
{
  "logging": {
    "level": "info",
    "format": "json",
    "output": "file",
    "file_path": "/var/log/pingora-proxy.log",
    "rotation": {
      "max_size_mb": 10,
      "max_files": 5,
      "compress": true
    }
  }
}
```

## Example Configurations

### Basic Single Server

Minimal configuration for a single server:

```json
{
  "servers": [
    {
      "from": "example.com",
      "to": "web-server:80"
    }
  ]
}
```

### Multiple Backends

Configuration with multiple backends:

```json
{
  "servers": [
    {
      "from": "example.com",
      "to": "web-server:80"
    },
    {
      "from": "api.example.com",
      "to": "api-server:8080"
    },
    {
      "from": "admin.example.com",
      "to": "admin-portal:3000"
    }
  ]
}
```

### Production Multi-Tenant

Complex multi-tenant configuration:

```json
{
  "servers": [
    { "from": "app.tenant1.com", "to": "tenant1-app:80", "origin": "Manual" },
    { "from": "api.tenant1.com", "to": "tenant1-api:8080", "origin": "Manual" },
    { "from": "app.tenant2.com", "to": "tenant2-app:80", "origin": "Manual" },
    { "from": "api.tenant2.com", "to": "tenant2-api:8080", "origin": "Manual" }
  ],
  "organizations": [
    {
      "id": "101",
      "name": "Tenant 1",
      "domains": ["app.tenant1.com", "api.tenant1.com"],
      "network_isolation": true
    },
    {
      "id": "102",
      "name": "Tenant 2",
      "domains": ["app.tenant2.com", "api.tenant2.com"],
      "network_isolation": true
    }
  ],
  "certificates": {
    "auto_issuance": true,
    "email": "admin@example.com"
  }
}
```

## Configuration File Locations

| File                    | Default Location                                | Purpose                  |
| ----------------------- | ----------------------------------------------- | ------------------------ |
| `config.json`           | `/app/config/config.json`                       | Main configuration       |
| `security-policy.json`  | `/etc/security-policy.json`                     | Security policies        |
| `prometheus.yml`        | `/mnt/gluster/prometheus/config/prometheus.yml` | Monitoring configuration |
| `grafana/provisioning/` | `/mnt/gluster/grafana/provisioning/`            | Grafana configuration    |
