RUST_BIN ?= /usr/lib/rust-1.93/bin
CARGO_FMT ?= $(shell command -v cargo-fmt 2>/dev/null || printf '%s/cargo-fmt' '$(RUST_BIN)')
CARGO_CLIPPY ?= $(shell command -v cargo-clippy 2>/dev/null || printf '%s/cargo-clippy' '$(RUST_BIN)')

.PHONY: fmt fmt-check lint test check run-api run-signal run-relay

fmt:
	PATH=$(RUST_BIN):$(PATH) $(CARGO_FMT) --all

fmt-check:
	PATH=$(RUST_BIN):$(PATH) $(CARGO_FMT) --all --check

lint:
	PATH=$(RUST_BIN):$(PATH) $(CARGO_CLIPPY) --workspace --all-targets -- -D warnings

test:
	cargo test --workspace

check:
	cargo check --workspace

run-api:
	cargo run -p api-server

run-signal:
	cargo run -p signal-server

run-relay:
	cargo run -p relay-server
