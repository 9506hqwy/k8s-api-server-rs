FROM mcr.microsoft.com/devcontainers/rust:1-1-bullseye

RUN set -eux; \
    \
    # Install musl lib
    apt update; \
    apt install -y musl-tools; \
    \
    # Install target architecture
    rustup target add x86_64-unknown-linux-musl
