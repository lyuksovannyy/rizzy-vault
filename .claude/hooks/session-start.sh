#!/bin/bash
# SessionStart hook for Claude Code on the web: makes fmt, clippy, tests, the wasm32 check
# and cargo-deny work in a fresh cloud session. Idempotent; runs synchronously.
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel)}"

# Toolchain, components (rustfmt, clippy) and targets (wasm32) pinned in rust-toolchain.toml.
rustup toolchain install --no-self-update

# Supply-chain policy checker used by CI (`cargo deny check`).
if ! command -v cargo-deny >/dev/null 2>&1; then
  cargo install cargo-deny --locked
fi

# Warm the dependency and build caches so the first lint/test run in the session is fast.
cargo fetch --locked
cargo build --workspace --all-targets --locked
