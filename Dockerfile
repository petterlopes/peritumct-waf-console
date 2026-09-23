# Multi-stage Rust build for peritumct-waf-console (production Linux).
# Homologated: Docker / Podman. Bind loopback only (WAF_BIND=127.0.0.1).
# Builder pin: rustc 1.98.1 (stable, 2026-09-03 — vtable miscompile fix).
# Python rollback: legacy/python/.

FROM rust:1.98.1-bookworm AS builder
WORKDIR /src
ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
    CARGO_TERM_COLOR=never \
    RUSTFLAGS="-C opt-level=3 -C codegen-units=1 -C strip=symbols"
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*
COPY rust/Cargo.toml rust/Cargo.lock ./
COPY rust/src ./src
# Dummy so cargo can fetch deps before full source (cache-friendly on rebuilds)
RUN cargo build --release --locked \
 && strip --strip-unneeded target/release/waf-console

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libssl3 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 65532 --home /app --shell /usr/sbin/nologin waf
WORKDIR /app
COPY --from=builder /src/target/release/waf-console /app/waf-console
COPY static /app/static
ENV WAF_BIND=127.0.0.1 \
    WAF_PORT=18990 \
    WAF_STATIC=/app/static \
    WAF_APP_VERSION=2.0.10 \
    WAF_APP_PRODUCT=waf-console \
    RUST_LOG=warn \
    RUST_BACKTRACE=0 \
    TOKIO_WORKER_THREADS=4
EXPOSE 18990
USER waf
CMD ["/app/waf-console"]
