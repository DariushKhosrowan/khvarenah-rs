#!/usr/bin/env bash
# ------------------------------------------------------------------
# dastyab aistudio — one-command access to Google AI Studio.
#
# Verified fact: AI Studio is reachable DIRECTLY from Iranian IPs
# (app + login + Gemini API all work). Do NOT route it through Tor
# (Google returns 403 from Tor exits). This helper checks the direct
# path, opens the studio, and points you at the API key page.
#
# Usage:
#   dastyab-aistudio.sh            # check connectivity + print guide
#   dastyab-aistudio.sh open        # open the studio in $BROWSER
#   dastyab-aistudio.sh key         # open the API-key manager page
#   dastyab-aistudio.sh api <key>   # test a Gemini API key live
# ------------------------------------------------------------------
set -euo pipefail

STUDIO="https://aistudio.google.com/"
KEYPAGE="https://aistudio.google.com/app/apikey"
API="https://generativelanguage.googleapis.com/v1beta"

BROWSER="${BROWSER:-}"

green() { printf '\033[1;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[1;33m%s\033[0m\n' "$*"; }
red() { printf '\033[1;31m%s\033[0m\n' "$*"; }

http_code() {
  curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$1" || echo 000
}

open_url() {
  local url="$1"
  if [ -n "$BROWSER" ]; then
    "$BROWSER" "$url" >/dev/null 2>&1 &
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$url" >/dev/null 2>&1 &
  else
    yellow "No browser found; open the URL manually: $url"
  fi
}

check_connectivity() {
  green "== Google AI Studio connectivity check (direct, no Tor) =="

  local s=$(http_code "$STUDIO")
  local a=$(http_code "https://accounts.google.com/")
  local g=$(http_code "$API/models")

  yellow "aistudio.google.com         -> HTTP $s  (200/302 = OK)"
  yellow "accounts.google.com          -> HTTP $a  (200/302 = OK)"
  yellow "generativelanguage API       -> HTTP $g  (400/403 = reachable, needs key)"

  # 302/200 = good; 403 = geo-blocked/Tor flagged
  if [ "$s" = "403" ]; then
    red "BLOCKED: AI Studio returns 403 from this route."
    red "If you are using Tor, STOP — Google blocks Tor exits for AI Studio."
    red "Use your direct connection (no Tor). If you're direct, try again later."
    return 1
  fi
  green "OK: AI Studio is reachable from your IP directly."
  return 0
}

case "${1:-check}" in
  open)
    open_url "$STUDIO"; green "Opened AI Studio." ;;
  key)
    open_url "$KEYPAGE"; green "Opened the API-key manager page (sign in first)." ;;
  api)
    key="${2:-}"
    if [ -z "$key" ]; then red "Usage: $0 api <API_KEY>"; exit 2; fi
    echo "== testing Gemini API key =="
    curl -s --max-time 20 "$API/models?key=$key" | head -c 600; echo ;;
  check|*)
    check_connectivity; echo
    green "Next steps:"
    echo "  1) Sign in at $STUDIO (normal Google login — works from your IP)."
    echo "  2) Get an API key: $KEYPAGE"
    echo "  3) Test it:  $0 api YOUR_KEY"
    ;;
esac
