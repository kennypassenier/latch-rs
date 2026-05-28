# ── Stage 1: Build ────────────────────────────────────────────────────────────
# Use the official Rust image pinned to the minimum required edition (2024 → 1.85).
FROM rust:1.85-slim-bookworm AS builder

WORKDIR /build

# Install OS build deps:
#   pkg-config + libssl-dev  → reqwest TLS
#   libdbus-1-dev            → keyring crate (compile-time)
#   libsecret-1-dev          → libsecret backend for keyring
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    libdbus-1-dev \
    libsecret-1-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first for layer-cached dependency compilation.
COPY Cargo.toml Cargo.lock ./

# Build a dummy main so deps compile and are cached.
RUN mkdir src && echo 'fn main(){}' > src/main.rs && \
    cargo build --release --locked && \
    rm -rf src

# Now copy the real source and build the actual binary.
COPY src ./src
# Touch main.rs so Cargo knows it changed.
RUN touch src/main.rs && \
    cargo build --release --locked

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
# Minimal Debian image. Alpine is not used because the keyring crate links
# against libsecret which requires glibc.
FROM debian:bookworm-slim

# Runtime deps:
#   ca-certificates  → HTTPS requests to the GitHub API
#   libsecret-1-0    → OS keyring support (optional in headless/CI — use LATCH_KEY env var)
#   libdbus-1-3      → required by libsecret at runtime
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    libsecret-1-0 \
    libdbus-1-3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/latch /usr/local/bin/latch

# Work inside a bind-mounted project directory.
WORKDIR /workspace

# Ensure the binary is accessible to all users.
RUN chmod 755 /usr/local/bin/latch

ENTRYPOINT ["latch"]
CMD ["--help"]
