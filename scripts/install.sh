#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
#  DastYab — one-command installer
#  ─────────────────────────────────────────────────────────────────────────────
#  Installs the latest DastYab CLI release (Rust, single static binary) in
#  one line, with automatic platform detection, SHA-256 verification, and a
#  PATH setup so `dastyab` just works afterwards.
#
#  Usage:
#      curl -fsSL https://raw.githubusercontent.com/DastYab/dastyab/main/scripts/install.sh | sh
#
#  Options (env vars):
#      INSTALL_DIR=/path      install into /path instead of ~/.local/bin
#      DASTYAB_VERSION=vX.Y.Z   install a specific version (default: latest)
#      NO_PATH=1              skip auto-adding the target dir to PATH
# ─────────────────────────────────────────────────────────────────────────────
set -eu

REPO_OWNER="DastYab"
REPO_NAME="dastyab"
GITHUB_API="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}"

# ---- colors / helpers -----------------------------------------------------
if [ -t 1 ]; then
  C_GREEN='\033[0;32m'; C_CYAN='\033[0;36m'; C_YELLOW='\033[1;33m'
  C_RED='\033[0;31m'; C_BOLD='\033[1m'; C_RESET='\033[0m'
else
  C_GREEN=''; C_CYAN=''; C_YELLOW=''; C_RED=''; C_BOLD=''; C_RESET=''
fi
say()  { printf "${C_GREEN}==>${C_RESET} %s\n" "$*"; }
info() { printf "${C_CYAN}    ${C_RESET}%s\n" "$*"; }
warn() { printf "${C_YELLOW}WARN${C_RESET} %s\n" "$*"; }
die()  { printf "${C_RED}ERROR${C_RESET} %s\n" "$*" >&2; exit 1; }

# ---- platform detection ---------------------------------------------------
detect_asset() {
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os" in
    Linux*)
      case "$arch" in
        x86_64|amd64) asset="dastyab-linux-amd64" ;;
        aarch64|arm64) asset="dastyab-linux-arm64" ;;
        *) die "Unsupported Linux arch: $arch" ;;
      esac
      ;;
    Darwin*)
      case "$arch" in
        arm64) asset="dastyab-macos-arm64" ;;
        x86_64) asset="dastyab-macos-x86_64" ;;
        *) die "Unsupported macOS arch: $arch" ;;
      esac
      ;;
    *)
      die "Unsupported OS: $os (Windows users: use the portable .zip release)."
      ;;
  esac
}

# ---- network helpers ------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

fetch() { # fetch <url> -> stdout (curl preferred, wget fallback)
  if have curl; then curl -fsSL "$1"; elif have wget; then wget -qO- "$1"; else die "Need curl or wget."; fi
}

# ---- resolve latest release + asset --------------------------------------
# Latest tag is discovered without the API (no rate limit): the public
# /releases/latest URL 302-redirects to /releases/tag/<tag>. The asset
# download URL is then deterministic on the CDN. The API is only used as a
# fallback when a GITHUB_TOKEN is available.
resolve_latest() {
  say "Resolving latest release of ${REPO_NAME}..."
  if [ -n "${DASTYAB_VERSION:-}" ]; then
    tag="$DASTYAB_VERSION"
    info "Pinned version: $tag"
  else
    if have curl; then
      tag="$(curl -fsSI -o /dev/null -w '%{redirect_url}' "https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/latest" 2>/dev/null | sed 's#.*/tag/##' | sed 's#/$##')"
    elif have wget; then
      tag="$(wget -S -O /dev/null "https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/latest" 2>&1 | grep -i '^ *Location:' | tail -1 | sed 's#.*/tag/##' | sed 's#/$##')"
    fi
    [ -n "$tag" ] || die "Could not determine the latest release tag."
    info "Latest release: $tag"
  fi

  # Deterministic CDN asset URL (no API required).
  cdn_url="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${tag}/${asset}"

  # Optional API fallback (auth'd only) for restricted networks where the CDN
  # is blocked and the anonymous API quota is exhausted.
  api_url=""
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    api_url="$(curl -fsSL \
      -H "Authorization: Bearer ${GITHUB_TOKEN}" \
      -H "Accept: application/vnd.github+json" \
      "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/tags/${tag}" 2>/dev/null \
      | python3 -c '
import json,sys
try:
    rel = json.load(sys.stdin)
except Exception:
    raise SystemExit(1)
want = sys.argv[1] if len(sys.argv) > 1 else ""
for a in rel.get("assets", []):
    if a.get("name") == want:
        print(a.get("url", ""))
        break
' "$asset")"
  fi

  [ -n "$api_url" ] || [ -n "$cdn_url" ] || die "No ${asset} asset found in ${tag}."
  url="${api_url:-$cdn_url}"
  info "Asset: ${asset}"
}

# ---- SHA-256 verification -------------------------------------------------
verify_sha() { # verify_sha <file> <expected_sha> -> true/false
  if command -v sha256sum >/dev/null 2>&1; then
    [ "$(sha256sum "$1" | awk '{print $1}')" = "$2" ]
  elif command -v shasum >/dev/null 2>&1; then
    [ "$(shasum -a 256 "$1" | awk '{print $1}')" = "$2" ]
  else
    warn "No sha256sum/shasum found; skipping checksum verification."
    true
  fi
}

# ---- install --------------------------------------------------------------
do_install() {
  # With the API endpoint the URL ends in the numeric asset id, not the real
  # filename — keep the asset name for file naming + checksum lookup.
  name="$asset"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT HUP INT TERM

  say "Downloading ${name}..."
  case "$url" in
    *api.github.com*)
      if have curl; then
        if [ -n "${GITHUB_TOKEN:-}" ]; then
          curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" -H "Accept: application/octet-stream" -o "$tmp/$name" "$url"
        else
          curl -fsSL -H "Accept: application/octet-stream" -o "$tmp/$name" "$url"
        fi
      else
        if [ -n "${GITHUB_TOKEN:-}" ]; then
          wget -q --header="Authorization: Bearer ${GITHUB_TOKEN}" --header="Accept: application/octet-stream" -O "$tmp/$name" "$url"
        else
          wget -q --header="Accept: application/octet-stream" -O "$tmp/$name" "$url"
        fi
      fi
      ;;
    *)
      if have curl; then curl -fsSL -o "$tmp/$name" "$url"; else wget -qO "$tmp/$name" "$url"; fi
      ;;
  esac
  [ -s "$tmp/$name" ] || die "Download failed or produced an empty file."

  # checksum against SHA256SUMS.txt
  sums_url="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${tag}/SHA256SUMS.txt"
  if sums="$(fetch "$sums_url" 2>/dev/null)"; then
    expected="$(printf '%s\n' "$sums" | grep -E "  ${name}$" | awk '{print $1}')"
    if [ -n "$expected" ]; then
      if verify_sha "$tmp/$name" "$expected"; then
        info "Checksum OK (sha256 $expected)."
      else
        die "Checksum mismatch for $name. Aborting."
      fi
    fi
  fi

  # target dir
  dir="${INSTALL_DIR:-}"
  if [ -z "$dir" ]; then
    dir="${HOME}/.local/bin"
  fi
  mkdir -p "$dir"

  final="$dir/dastyab"
  # atomic replace
  if command -v install >/dev/null 2>&1; then
    install -m 0755 "$tmp/$name" "$tmp/dastyab" \
      && mv -f "$tmp/dastyab" "$final"
  else
    mv -f "$tmp/$name" "$final"
    chmod 0755 "$final"
  fi

  say "Installed to ${C_BOLD}${final}${C_RESET}"

  # PATH
  case ":$PATH:" in
    *":$dir:"*) : ;;
    *)
      if [ -n "${NO_PATH:-}" ]; then
        warn "$dir is not on your PATH. Add it or run the binary as $final."
      else
        info "$dir is not on your PATH — adding it..."
        if [ -n "${SHELL:-}" ] && printf '%s' "$SHELL" | grep -q zsh; then rc="${HOME}/.zshrc"; else rc="${HOME}/.bashrc"; fi
        if [ -f "$rc" ] && ! grep -qsF "$dir" "$rc"; then
          printf '\n# added by dastyab-installer\nexport PATH="%s:$PATH"\n' "$dir" >> "$rc"
          info "Appended PATH export to $rc"
        fi
        warn "Run \`source $rc\` (or open a new terminal) before using dastyab."
      fi
      ;;
  esac
}

# ---- main -----------------------------------------------------------------
detect_asset
resolve_latest
do_install

printf "\n${C_GREEN}┌──────────────────────────────────────────────────────────┐${C_RESET}\n"
printf "${C_GREEN}│${C_RESET}  DastYab installed. Verify with:\n"
printf "${C_GREEN}│${C_RESET}     ${C_BOLD}dastyab --version${C_RESET}\n"
printf "${C_GREEN}│${C_RESET}  Then start with:\n"
printf "${C_GREEN}│${C_RESET}     ${C_BOLD}dastyab --help${C_RESET}\n"
printf "${C_GREEN}└──────────────────────────────────────────────────────────┘${C_RESET}\n"
