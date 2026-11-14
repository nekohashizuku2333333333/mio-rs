# Vendored BoringSSL

Source: `boring-sys 5.4.0` (BoringSSL submodule), pinned by `Cargo.lock`.
License: see `boringssl/LICENSE`.

This copy is intentionally pre-patched because Rust needs the client
X25519 key_share private key for mio v0.5.1 TCP authentication, which stock
BoringSSL does not expose. `.cargo/config.toml` sets
`BORING_BSSL_SOURCE_PATH` and `BORING_BSSL_ASSUME_PATCHED=1`.

Applied patches, in order:

1. `boring-sys/patches/boring-pq.patch` (Cloudflare PQ support required by
   `boring-sys`).
2. `patches/boringssl-no-sigalg-grease.patch` (Chrome 133 raw ClientHello).
3. `patches/boringssl-x25519-key-share.patch` (retains and exposes the
   initial ClientHello X25519 key_share private key).

To regenerate, start from a pristine `boring-sys 5.4.0` source tree, apply the
three patches with `git apply --whitespace=fix`, and replace this directory.
