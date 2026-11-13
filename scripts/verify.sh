#!/usr/bin/env bash
# Canonical DastYab verification gate: fmt + build + clippy + full core
# test suite in one shot. Exit non-zero if anything fails.
#
# Usage: scripts/verify.sh
set -u
cd "$(dirname "$0")/.."
PASS=0; FAIL=0

step() {
  local name="$1"; shift
  if "$@" >/tmp/dyb-verify.log 2>&1; then
    echo "PASS $name"; PASS=$((PASS+1))
  else
    echo "FAIL $name"; FAIL=$((FAIL+1)); tail -20 /tmp/dyb-verify.log
  fi
}

step "fmt"        cargo fmt --all --check
step "core-build" cargo build -p dastyab-core
step "cli-build"  cargo build -p dastyab-cli
step "core-clippy" cargo clippy -p dastyab-core --lib
step "cli-clippy"  cargo clippy -p dastyab-cli
step "core-tests"  timeout 600 cargo test -p dastyab-core --lib

echo "======== RESULT ========"
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
