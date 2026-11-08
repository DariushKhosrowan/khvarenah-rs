#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
#  Khvarenah — one-command installer
#  ─────────────────────────────────────────────────────────────────────────────
#  Installs the latest Khvarenah CLI release (Rust, single static binary) in
#  one line, with automatic platform detection, SHA-256 verification, and a
#  PATH setup so `khvarenah` just works afterwards.
#
#  Usage:
#      curl -fsSL https://raw.githubusercontent.com/DariushKhosrowan/khvarenah-rs/main/scripts/install.sh | sh
#
#  Options (env vars):
#      INSTALL_DIR=/path      install into /path instead of ~/.local/bin
#      KHVARENAH_VERSION=vX.Y.Z   install a specific version (default: latest)
#      NO_PATH=1              skip auto-adding the target dir to PATH
# ─────────────────────────────────────────────────────────────────────────────
set -eu

REPO_OWNER="DariushKhosrowan"
REPO_NAME="khvarenah-rs"
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
        x86_64|amd64) asset="khvarenah-linux-amd64" ;;
        aarch64|arm64) asset="khvarenah-linux-arm64" ;;
        *) die "Unsupported Linux arch: $arch" ;;
      esac
      ;;
    Darwin*)
      case "$arch" in
        arm64) asset="khvarenah-macos-arm64" ;;
        x86_64) asset="khvarenah-macos-x86_64" ;;
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
resolve_latest() {
  say "Resolving latest release of ${REPO_NAME}..."
  if [ -n "${KHVARENAH_VERSION:-}" ]; then
    tag="$KHVARENAH_VERSION"
    info "Pinned version: $tag"
  else
    tag="$(fetch "${GITHUB_API}/releases/latest" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
    [ -n "$tag" ] || die "Could not determine the latest release tag."
    info "Latest release: $tag"
  fi

  base_url="${GITHUB_API}/releases/tags/${tag}"
  url="$(fetch "$base_url" | grep -o '"browser_download_url": *"[^"]*"' | sed 's/.*"\(.*\)"/\1/' | grep "/${asset}$" | grep -v '\.deb$' | grep -v '\.exe$' | head -n1)"
  [ -n "$url" ] || die "No ${asset} asset found in ${tag}."
  info "Asset: $(basename "$url")"
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
  name="$(basename "$url")"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT HUP INT TERM

  say "Downloading ${name}..."
  if have curl; then curl -fsSL -o "$tmp/$name" "$url"; else wget -qO "$tmp/$name" "$url"; fi
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

  final="$dir/khvarenah"
  # atomic replace
  if command -v install >/dev/null 2>&1; then
    install -m 0755 "$tmp/$name" "$tmp/khvarenah" \
      && mv -f "$tmp/khvarenah" "$final"
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
          printf '\n# added by khvarenah-installer\nexport PATH="%s:$PATH"\n' "$dir" >> "$rc"
          info "Appended PATH export to $rc"
        fi
        warn "Run \`source $rc\` (or open a new terminal) before using khvarenah."
      fi
      ;;
  esac
}

# ---- main -----------------------------------------------------------------
detect_asset
resolve_latest
do_install

printf "\n${C_GREEN}┌──────────────────────────────────────────────────────────┐${C_RESET}\n"
printf "${C_GREEN}│${C_RESET}  Khvarenah installed. Verify with:\n"
printf "${C_GREEN}│${C_RESET}     ${C_BOLD}khvarenah --version${C_RESET}\n"
printf "${C_GREEN}│${C_RESET}  Then start with:\n"
printf "${C_GREEN}│${C_RESET}     ${C_BOLD}khvarenah --help${C_RESET}\n"
printf "${C_GREEN}└──────────────────────────────────────────────────────────┘${C_RESET}\n"
