# Docker Swarm Integration & Network Isolation Guide

This guide explains how to integrate Pingora Proxy Server with Docker Swarm and implement network isolation for multi-tenant environments.

## Docker Swarm Integration

Pingora Proxy Server integrates deeply with Docker Swarm, allowing automatic discovery and routing of services based on labels.

### Enabling Swarm Integration

To enable Docker Swarm integration, set the following environment variables:

```bash
SWARM_MODE=true
SWARM_NETWORKS=ingress,proxy-network
DOCKER_ENDPOINT=unix:///var/run/docker.sock
```

### Service Discovery

The Swarm Discovery service automatically detects services with specific labels and configures the proxy to route traffic to them.

#### Required Service Labels

To expose a service through the proxy, add these labels in your service definition:

| Label                     | Description                                 | Required |
| ------------------------- | ------------------------------------------- | -------- |
| `com.koompi.proxy`        | Set to "true" to enable proxying            | Yes      |
| `com.koompi.proxy.domain` | Domain name to route to this service        | Yes      |
| `com.koompi.proxy.port`   | Container port to route to (defaults to 80) | No       |
| `com.koompi.org.id`       | Organization ID for network isolation       | No       |

#### Example Service Definition

```yaml
services:
  web-app:
    image: nginx:alpine
    deploy:
      labels:
        com.koompi.proxy: "true"
        com.koompi.proxy.domain: "app.example.com"
        com.koompi.proxy.port: "8080"
        com.koompi.org.id: "100"
```

### Network Routing

The proxy uses Docker's DNS-based service discovery to route traffic to services. For a service named "web-app", the proxy would route to:

```
tasks.web-app:8080
```

This allows services to scale horizontally while maintaining proper load balancing.

## Network Isolation

Pingora Proxy Server implements network isolation to ensure that services from different organizations cannot communicate with each other.

### Organization Networks

For each unique `com.koompi.org.id` label, the proxy creates an isolated overlay network with the following properties:

- **Name format**: `org_{org_id}_overlay`
- **Subnet**: `10.{org_id}.0.0/16`
- **Driver**: overlay
- **Internal**: true (no outbound connectivity)
- **Encrypted**: true (encrypted inter-host traffic)

### Network Setup

The `setup-network-isolation.sh` script handles network creation and configuration:

```bash
#!/bin/bash
# Run this script on a Swarm manager node
./setup-network-isolation.sh
```

### Firewall Rules

For additional security, the proxy sets up firewall rules on the Swarm manager nodes to prevent traffic between organization networks. This is implemented using a global service that runs on all manager nodes and configures iptables.

### How Traffic Routing Works

1. The proxy receives an HTTPS request for a domain
2. It looks up the backend service for that domain
3. If the service has an `org_id`, the proxy:
   - Adds security headers with organization information
   - Routes traffic through the proper isolated network
   - Enforces network boundary checks

### Example Network Topology

For a Swarm cluster with two organizations:

```
                  ┌─────────────────┐
                  │  Pingora Proxy  │
                  └─────────────────┘
                          │
          ┌───────────────┴───────────────┐
          ▼                               ▼
┌─────────────────────┐       ┌─────────────────────┐
│ org_100_overlay     │       │ org_200_overlay     │
│ (10.100.0.0/16)     │       │ (10.200.0.0/16)     │
└─────────────────────┘       └─────────────────────┘
          │                               │
          ▼                               ▼
┌─────────────────────┐       ┌─────────────────────┐
│ Service A (org 100) │       │ Service X (org 200) │
└─────────────────────┘       └─────────────────────┘
          │                               │
          ▼                               ▼
┌─────────────────────┐       ┌─────────────────────┐
│ Service B (org 100) │       │ Service Y (org 200) │
└─────────────────────┘       └─────────────────────┘
```

Services A and B can communicate with each other but not with Services X and Y, and vice versa.

## Using the Attach Networks Script

After adding new organization networks, you can attach them to the proxy service using the `attach-networks.sh` script:

```bash
#!/bin/bash
# Run this script after creating new organization networks
./attach-networks.sh
```

This script finds all networks with the `org_*` pattern and attaches them to the proxy service in a single operation.

## Security Policies

The `security-policy.json` file controls the default network and container security policies:

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

You can customize these settings to tighten security as needed.

## Network Validation

The proxy performs several validation checks on every request:

1. **Service Connectivity**: Verifies the backend service is reachable
2. **Organization Authorization**: Checks that the service belongs to the claimed organization
3. **Network Boundary**: Enforces traffic stays within organization boundaries

## Advanced Configuration

### Distributed Locking

Network operations use a distributed locking mechanism to ensure only one node performs network changes at a time. The lock files are stored in:

```
/pingora-proxy/locks/
```

### Circuit Breakers

The proxy implements circuit breakers to prevent routing traffic to failing backends:

```rust
// After multiple failures, the circuit opens
if circuit_breaker.is_open() {
    println!("Circuit open for backend: {}", backend);
    return fallback_response();
}
```

### Rate Limiting

You can configure rate limits per organization in the `security-policy.json` file:

```json
{
  "network_policies": {
    "rate_limits": {
      "requests_per_second": 100,
      "burst": 200
    }
  }
}
```

## Troubleshooting

### Network Connectivity Issues

If services cannot communicate through the proxy:

1. Check if the services are attached to the correct network:

   ```bash
   docker service inspect <service_name> --format '{{.Spec.TaskTemplate.Networks}}'
   ```

2. Verify the network exists:

   ```bash
   docker network ls | grep org_
   ```

3. Inspect iptables rules on the manager nodes:
   ```bash
   docker exec -it $(docker ps -q -f name=network-firewall) iptables -L
   ```

### Common Network Problems

| Problem                 | Cause                          | Solution                               |
| ----------------------- | ------------------------------ | -------------------------------------- |
| Service unreachable     | Service not in correct network | Attach service to organization network |
| Cross-org communication | Firewall rules not applied     | Restart network-firewall service       |
| Network creation fails  | Distributed lock issue         | Remove stale lock files                |

### Network Debugging Commands

```bash
# Check which services are on which networks
docker network inspect org_100_overlay

# Test connectivity between services
docker exec -it <container_id> ping <service_name>

# Check if proxy is attached to all networks
docker service inspect proxy_proxy --format '{{.Spec.TaskTemplate.Networks}}'

# View network firewall logs
docker service logs proxy_network-firewall
```

## Best Practices

1. Always use organization IDs for services that require isolation
2. Run the `setup-network-isolation.sh` script after adding new organizations
3. Use the `attach-networks.sh` script after creating new networks
4. Set services to use the specific network they need, rather than attaching all networks
5. Keep the security policy configured for strict isolation in production environments
