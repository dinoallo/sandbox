FROM --platform=$BUILDPLATFORM rust:1-slim AS builder
WORKDIR /usr/src/launcher

# Install system deps needed for building some crates (ssl, pkg-config)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    ca-certificates \
    pkg-config \
    libssl-dev \
    build-essential \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Copy Cargo manifests first for caching
COPY launcher/Cargo.toml launcher/Cargo.lock ./
COPY launcher/build.rs ./
COPY launcher/proto ./proto

# Copy workspace files (assumes full launcher subdir copy)
COPY launcher/src ./src

# Build release binary
RUN cargo build --release --bin launcher

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the compiled launcher binary from the builder
COPY --from=builder /usr/src/launcher/target/release/launcher /usr/local/bin/launcher

EXPOSE 50051
ENTRYPOINT ["/usr/local/bin/launcher"]
