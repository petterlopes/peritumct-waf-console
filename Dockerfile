# Multi-stage Rust build for peritumct-waf-console (production Linux).
# Homologated: Docker / Podman. Bind loopback only (WAF_BIND=127.0.0.1).
# Python stdlib runtime preserved under legacy/python/ for rollback only.

FROM rust:1.85-bookworm AS builder
WORKDIR /src
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*
COPY rust/Cargo.toml rust/Cargo.lock ./
COPY rust/src ./src
RUN cargo build --release && strip target/release/waf-console

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libssl3 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /src/target/release/waf-console /app/waf-console
COPY static /app/static
ENV WAF_BIND=127.0.0.1
ENV WAF_PORT=18990
ENV WAF_STATIC=/app/static
ENV WAF_APP_VERSION=2.0.0
ENV WAF_APP_PRODUCT=waf-console
ENV RUST_LOG=info
EXPOSE 18990
USER nobody
CMD ["/app/waf-console"]
