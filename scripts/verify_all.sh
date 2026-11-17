#!/usr/bin/env bash
# Verify the Rust rewrite after an upstream port.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -d "$ROOT/.cargo-home" ]]; then
  export CARGO_HOME="${CARGO_HOME:-$ROOT/.cargo-home}"
fi
# The Python checks use target/debug/mio, so keep all Cargo output there.
export CARGO_TARGET_DIR="$ROOT/target"

echo "== cargo fmt =="
cargo fmt --all -- --check

echo "== cargo test =="
cargo test --locked --all-targets

echo "== cargo clippy =="
cargo clippy --locked --all-targets -- -D warnings

echo "== cargo build =="
cargo build --locked

echo "== TCP/QUIC end-to-end =="
python3 scripts/e2e_local.py

echo "== UDP camouflage relay =="
python3 scripts/udp_relay_local.py

echo "all verification checks passed"