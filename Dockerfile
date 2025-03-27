# Use a multi-stage build with ARG for platform detection
FROM --platform=$TARGETPLATFORM ubuntu:24.04

# Add ARG for platform detection
ARG TARGETPLATFORM

# Install dependencies with key verification fix
RUN apt-get update -y || true && \
    apt-get install -y --no-install-recommends ca-certificates gnupg curl && \
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 3B4FE6ACC0B21F32 871920D1991BC93C && \
    apt-get update -y && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    certbot \
    python3-venv \
    python3-certbot \
    openssl \
    curl \
    && python3 -m venv /opt/certbot-venv \
    && /opt/certbot-venv/bin/pip install --no-cache-dir certbot-dns-cloudflare \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Add the venv bin directory to PATH so certbot can find the plugin
ENV PATH="/opt/certbot-venv/bin:$PATH"

# Create app directory
WORKDIR /app

# Copy the appropriate binary based on architecture
COPY bin/x86_64/pingora-proxy-server /app/pingora-proxy-server.x86_64
COPY bin/arm64/pingora-proxy-server /app/pingora-proxy-server.arm64

# Copy entrypoint script and certificate wrapper
COPY entrypoint.sh /app/entrypoint.sh
COPY certbot-wrapper.sh /app/certbot-wrapper.sh
RUN chmod +x /app/entrypoint.sh /app/certbot-wrapper.sh

# Create required directories
RUN mkdir -p /pingora-proxy/locks /certbot/letsencrypt /var/www/html/.well-known/acme-challenge /app/config

# Environment for service discovery
ENV SWARM_MODE=true
ENV SWARM_NETWORKS=ingress,proxy-network
ENV CONFIG_PATH=/app/config/config.json

EXPOSE 80 443 81

# Default to using the entrypoint script
ENTRYPOINT ["/app/entrypoint.sh"]