# ============================================
# Stage 1: Build
# ============================================
# Using rust:1.88 for Rust 2024 edition and dependency support
FROM --platform=$TARGETPLATFORM rust:1.88-alpine AS builder

# Install build dependencies (Alpine uses apk)
RUN apk add --no-cache \
    pkgconfig \
    openssl-dev \
    musl-dev \
    gcc

WORKDIR /app

# Copy only Cargo manifests first — this layer is cached unless Cargo.toml/lock changes
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs, build to cache *all* dependency compilation,
# then nuke the dummy source so the real build below uses the cache
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    cargo build --release --bin auth 2>/dev/null && \
    rm -rf src

# Now copy real source — only the app code recompiles,
# dependencies reuse the cached layer above
COPY src ./src

RUN cargo build --release --bin auth

# ============================================
# Stage 2: Production
# ============================================
FROM --platform=$TARGETPLATFORM alpine:latest AS production

# Install runtime dependencies
RUN apk add --no-cache \
    libssl3 \
    ca-certificates \
    && adduser -D -s /bin/sh appuser

# Create app directory
WORKDIR /app

# Copy the built binary from builder
COPY --from=builder /app/target/release/auth /usr/local/bin/auth

# Switch to non-root user
USER appuser

# Run the application
CMD ["auth"]
