#!/bin/sh

# Ensure proper DNS resolution for Docker Swarm
echo "nameserver 127.0.0.11" > /etc/resolv.conf
echo "nameserver 8.8.8.8" >> /etc/resolv.conf
echo "nameserver 1.1.1.1" >> /etc/resolv.conf

# Get the configuration path from environment variable or use default
CONFIG_PATH=${CONFIG_PATH:-"/app/config.json"}
CONFIG_DIR=$(dirname "$CONFIG_PATH")

# Ensure the config directory exists
mkdir -p "$CONFIG_DIR"

# Create default config if not exists
if [ ! -f "$CONFIG_PATH" ]; then
    echo '{
    "servers": []
}' > "$CONFIG_PATH"
    echo "Created default config file at $CONFIG_PATH"
fi

# Make environment variable available to the application
export CONFIG_PATH

# Add this at the top to properly pass the variable
DISABLE_SSL=${DISABLE_SSL:-false}
export DISABLE_SSL

# Handle SIGHUP for certificate reloading
trap 'echo "Received SIGHUP, reloading certificates..."; kill -TERM $child; exit 0' SIGHUP

# Select and execute the correct binary based on architecture
if [ "$(uname -m)" = "x86_64" ]; then
    echo "Starting Pingora Proxy Server (x86_64)..."
    /app/pingora-proxy-server.x86_64 "$@" &
elif [ "$(uname -m)" = "aarch64" ]; then
    echo "Starting Pingora Proxy Server (arm64)..."
    /app/pingora-proxy-server.arm64 "$@" &
else
    echo "Unsupported architecture: $(uname -m)"
    exit 1
fi

child=$!
wait $child