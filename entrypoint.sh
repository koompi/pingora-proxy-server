#!/bin/bash

# Create default config if not exists
CONFIG_PATH="/app/config.json"
if [ ! -f "$CONFIG_PATH" ]; then
    echo '{
    "servers": {},
    "upstream_timeout": 30,
    "upstream_keepalive_timeout": 60,
    "upstream_max_connections": 1024
}' > "$CONFIG_PATH"
    echo "Created default config file at $CONFIG_PATH"
fi

# Ensure proper DNS resolution for Docker Swarm
echo "nameserver 127.0.0.11" | tee /etc/resolv.conf
echo "nameserver 8.8.8.8" | tee -a /etc/resolv.conf
echo "nameserver 1.1.1.1" | tee -a /etc/resolv.conf

# Additional debugging for DNS
cat /etc/resolv.conf

# Execute the main application
exec /app/pingora-proxy-server