# Use a multi-stage build with ARG for platform detection
FROM --platform=$TARGETPLATFORM debian:bookworm-slim

# Add ARG for platform detection
ARG TARGETPLATFORM

# Install dependencies
RUN apt-get update && apt-get install -y ca-certificates && apt-get clean

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

EXPOSE 80 443

ENTRYPOINT ["/app/entrypoint.sh"]