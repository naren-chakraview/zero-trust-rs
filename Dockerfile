# syntax=docker/dockerfile:1

# --- builder ---
FROM rust:1-slim-bookworm AS builder

# ring (pulled in via jsonwebtoken) needs a C compiler to build on Linux,
# same reason the Windows build needed MSVC Build Tools installed earlier
# in this project.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --bin zt-gateway

# --- runtime ---
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/zt-gateway /usr/local/bin/zt-gateway

ENTRYPOINT ["/usr/local/bin/zt-gateway"]
