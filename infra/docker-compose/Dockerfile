# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS builder

ARG SERVICE
ARG CARGO_BUILD_JOBS=1
ARG CARGO_REGISTRY_MIRROR
WORKDIR /workspace

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY services ./services

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/workspace/target,sharing=locked \
    case "$SERVICE" in \
        api-server|signal-server|relay-server) ;; \
        *) echo "unsupported SERVICE: $SERVICE" >&2; exit 1 ;; \
    esac \
    && if [ -n "$CARGO_REGISTRY_MIRROR" ]; then \
        case "$CARGO_REGISTRY_MIRROR" in \
            sparse+https://*) ;; \
            *) echo "unsupported Cargo registry mirror: $CARGO_REGISTRY_MIRROR" >&2; exit 1 ;; \
        esac; \
        case "$CARGO_REGISTRY_MIRROR" in \
            *[!A-Za-z0-9+:/._~%-]*) echo "invalid Cargo registry mirror" >&2; exit 1 ;; \
        esac; \
        mkdir -p .cargo; \
        printf '[source.crates-io]\nreplace-with = "deployment"\n\n[source.deployment]\nregistry = "%s"\n' \
            "$CARGO_REGISTRY_MIRROR" > .cargo/config.toml; \
    fi \
    && RUSTUP_TOOLCHAIN="$RUST_VERSION" CARGO_BUILD_JOBS="$CARGO_BUILD_JOBS" \
        cargo build --locked --release --package "$SERVICE" \
    && cp "target/release/$SERVICE" /tmp/service

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl gosu netcat-openbsd \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 remote

COPY --from=builder /tmp/service /usr/local/bin/service
COPY --chmod=0755 infra/docker-compose/service-entrypoint.sh /usr/local/bin/service-entrypoint

USER remote
ENTRYPOINT ["/usr/local/bin/service-entrypoint"]
