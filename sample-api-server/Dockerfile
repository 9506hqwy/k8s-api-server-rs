FROM rust:1.85.0 as build

WORKDIR /src

RUN --mount=type=bind,target=/src,Z \
    set -eux; \
    \
    apt update; \
    apt install -y musl-tools; \
    \
    rustup target add x86_64-unknown-linux-musl; \
    \
    cargo build --release --target=x86_64-unknown-linux-musl --target-dir /artifacts; \
    \
    cp /artifacts/x86_64-unknown-linux-musl/release/sample-api-server /

FROM gcr.io/distroless/static-debian12:latest

COPY --from=build /sample-api-server /

ENTRYPOINT ["/sample-api-server"]
