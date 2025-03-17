# Use a multi-stage build with ARG for platform detection
FROM --platform=$TARGETPLATFORM ubuntu:24.04

# Add ARG for platform detection
ARG TARGETPLATFORM

# Install dependencies with key verification fix
RUN apt-get update -y || true && \
    apt-get install -y --no-install-recommends ca-certificates gnupg && \
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 3B4FE6ACC0B21F32 871920D1991BC93C && \
    apt-get update -y && \
    apt-get install -y --no-install-recommends ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy the appropriate binary based on architecture
COPY bin/x86_64/pingora-proxy-server /app/pingora-proxy-server.x86_64
COPY bin/arm64/pingora-proxy-server /app/pingora-proxy-server.arm64

# Use a shell script to select the correct binary at runtime
RUN echo '#!/bin/sh \n\
if [ "$(uname -m)" = "x86_64" ]; then \n\
  exec /app/pingora-proxy-server.x86_64 "$@" \n\
elif [ "$(uname -m)" = "aarch64" ]; then \n\
  exec /app/pingora-proxy-server.arm64 "$@" \n\
else \n\
  echo "Unsupported architecture: $(uname -m)" \n\
  exit 1 \n\
fi' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# Environment for service discovery
ENV SWARM_MODE=true
ENV SWARM_NETWORKS=ingress,proxy-network

EXPOSE 80 443

ENTRYPOINT ["/app/entrypoint.sh"]