FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && apt-get clean

COPY target/release/pingora-proxy-server /app/pingora-proxy-server

WORKDIR /app

EXPOSE 80 443

ENTRYPOINT ["/app/pingora-proxy-server"]