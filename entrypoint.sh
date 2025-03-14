#!/bin/sh

# Ensure proper DNS resolution for Docker Swarm
echo "nameserver 127.0.0.11" > /etc/resolv.conf
echo "nameserver 8.8.8.8" >> /etc/resolv.conf
echo "nameserver 1.1.1.1" >> /etc/resolv.conf

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

# Select and execute the correct binary based on architecture
if [ "$(uname -m)" = "x86_64" ]; then
    exec /app/pingora-proxy-server.x86_64 "$@"
elif [ "$(uname -m)" = "aarch64" ]; then
    exec /app/pingora-proxy-server.arm64 "$@"
else
    echo "Unsupported architecture: $(uname -m)"
    exit 1
fi