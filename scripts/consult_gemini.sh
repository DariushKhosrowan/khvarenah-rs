#!/usr/bin/env bash
# Consult Gemini through the layered aistudio SOCKS5 tunnel.
set -u
GKEY="${DYB_GEMINI_KEY:-}"
if [ -z "$GKEY" ]; then
  echo "ERR: DYB_GEMINI_KEY env var not set" >&2
  exit 2
fi
MODEL="${1:-gemini-2.5-pro}"
BODY="${2:-/tmp/gemini_body.json}"
curl -s --socks5-hostname 127.0.0.1:10850 \
  -H "x-goog-api-key: ${GKEY}" \
  -H "Content-Type: application/json" \
  "https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent" \
  -d @"${BODY}"
