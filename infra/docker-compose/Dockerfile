# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS builder

ARG SERVICE
WORKDIR /workspace

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY services ./services

RUN case "$SERVICE" in \
        api-server|signal-server|relay-server) ;; \
        *) echo "unsupported SERVICE: $SERVICE" >&2; exit 1 ;; \
    esac \
    && cargo build --locked --release --package "$SERVICE" \
    && cp "target/release/$SERVICE" /tmp/service

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl netcat-openbsd \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 remote

COPY --from=builder /tmp/service /usr/local/bin/service

USER remote
ENTRYPOINT ["/usr/local/bin/service"]
