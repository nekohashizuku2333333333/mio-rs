#!/usr/bin/env bash
# Rebuild the release binary against the vendored, pre-patched BoringSSL.
# The vendor tree provides both Chrome 156+ sigalg shape and the v0.5.8
# ClientHello X25519 key_share private-key getter.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_HOME="${CARGO_HOME:-$ROOT/.cargo-home}"
export CARGO_HOME

if ! grep -q 'SSL_get_x25519_key_share_private_key' \
  "$ROOT/vendor/boringssl/include/openssl/ssl.h"; then
  echo "vendor/boringssl is missing the X25519 key-share patch" >&2
  exit 1
fi
if ! grep -q 'Chrome 156+ prepends a GREASE' \
  "$ROOT/vendor/boringssl/ssl/extensions.cc"; then
  echo "vendor/boringssl is missing the Chrome sigalg patch" >&2
  exit 1
fi

cargo clean -p boring-sys
cargo build --release
echo "built $ROOT/target/release/mio with vendored Chrome-compatible BoringSSL"
