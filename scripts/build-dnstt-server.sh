#!/usr/bin/env bash
# =============================================================================
# build-dnstt-server.sh — build the native `dnstt-server` binary for a Linux
# VPS (x86_64 or aarch64) so you can scp it up to your free VPS.
#
# Usage:
#   ./build-dnstt-server.sh [target]
# where `target` is one of x86_64-unknown-linux-gnu (default) or
# aarch64-unknown-linux-gnu (ARM / Ampere Oracle instances).
#
# Requires: cargo + rustup. Adds the target if not installed.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET="${1:-x86_64-unknown-linux-gnu}"

# Ensure the target toolchain is available.
if ! rustup target list --installed | grep -q "^${TARGET}$"; then
  echo "==> Installing target ${TARGET}"
  rustup target add "${TARGET}"
fi

echo "==> Building dnstt-server for ${TARGET}"
mkdir -p dist
cargo build --release -p dastyab-cli --bin dnstt-server --target "${TARGET}"

BIN="target/${TARGET}/release/dnstt-server"
if [ -f "$BIN" ]; then
  cp "$BIN" "dist/dnstt-server-${TARGET}"
  echo "==> Built: $(pwd)/dist/dnstt-server-${TARGET}"
  echo "    Copy it to the VPS, then run scripts/dns-tunnel-server-setup.sh there."
else
  echo "error: build did not produce $BIN" >&2
  exit 1
fi
