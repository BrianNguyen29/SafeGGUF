# ==============================================================================
# SafeGGUF Production Multi-Stage Container Build
# Target Image Size: < 5 MB (Ultra-Minimal Distroless / Scratch)
# ==============================================================================

# Stage 1: Build static musl binary with Zig 0.13.0
FROM debian:bookworm-slim@sha256:f3034a6ec3c1205360777c4aae76234998866ad18806ae62b63a3f84ccad782b AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget xz-utils ca-certificates git python3 && \
    rm -rf /var/lib/apt/lists/*

# Install pinned Zig 0.13.0 toolchain with cryptographic sha256 verification
RUN wget -q https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz && \
    echo "d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea  zig-linux-x86_64-0.13.0.tar.xz" | sha256sum -c - && \
    tar -xf zig-linux-x86_64-0.13.0.tar.xz && \
    mv zig-linux-x86_64-0.13.0 /usr/local/zig && \
    ln -s /usr/local/zig/zig /usr/local/bin/zig && \
    rm zig-linux-x86_64-0.13.0.tar.xz

WORKDIR /build
COPY . .

# Build fully static release binary
RUN zig build -Doptimize=ReleaseSafe -Dtarget=x86_64-linux-musl

# Stage 2: Final minimal distroless runtime container
FROM gcr.io/distroless/static-debian12:nonroot@sha256:52dcfbabb7457ea47c82f6e13af8c8a4a1d9f7b0145142b3ecab20f2b888411d

LABEL org.opencontainers.image.title="SafeGGUF"
LABEL org.opencontainers.image.description="Memory-Safe GGUF v3 Structural & Arithmetic Validator"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.version="0.3.6"

COPY --from=builder /build/zig-out/bin/safegguf /usr/local/bin/safegguf

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/safegguf"]
CMD ["--help"]
