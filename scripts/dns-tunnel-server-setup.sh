#!/usr/bin/env bash
# =============================================================================
# dnstt-server-setup.sh — Turnkey DNS-tunnel server provisioner for a FREE VPS
# =============================================================================
# Target: Ubuntu 22.04 / 24.04 on a free cloud VPS (Oracle Cloud Always Free,
#         Alibaba Cloud free-tier, GCP free-tier, Hetzner, DigitalOcean, ...).
#
# What this does (idempotent, safe to re-run):
#   1. Frees UDP/TCP port 53 (disables systemd-resolved stub listener).
#   2. Opens port 53 in the OS firewall (ufw + raw iptables for Oracle's
#      image, which ships strict drop rules).
#   3. Installs the native DastYab `dnstt-server` binary (the authoritative
#      DNS-tunnel responder from this repo) as a systemd service.
#   4. Installs a Dante SOCKS5 egress backend on 127.0.0.1:1080 so decrypted
#      tunnel traffic can leave the VPS cleanly.
#   5. Generates a session key (secret) and prints the exact client config.
#
# The ONLY thing this script does NOT do is the domain delegation — you must
# create an A (glue) + NS record on your registrar/Cloudflare pointing the
# tunnel subdomain at this VPS's public IP. See the printed instructions and
# `docs/USER-GUIDE-DNS-TUNNEL.md`.
#
# Usage (run as root ON the VPS):
#   DNSTT_BIN=/path/to/dnstt-server \
#   TUNNEL_DOMAIN=t.928104.xyz \
#   ./dns-tunnel-server-setup.sh
#
# Env knobs:
#   DNSTT_BIN          path to the compiled dnstt-server binary (required).
#   TUNNEL_DOMAIN      the delegated tunnel domain, e.g. t.928104.xyz (required).
#   TUNNEL_PORT        UDP port to bind (default 53).
#   SOCKS_PORT         local SOCKS5 egress port (default 1080).
#   SESSION_KEY        32-char secret; auto-generated if empty.
#   INSTALL_DANTE      "1" (default) to set up the SOCKS5 egress backend.
# =============================================================================
set -euo pipefail

# ---- args ----------------------------------------------------------------
: "${DNSTT_BIN:?DNSTT_BIN path to the dnstt-server binary is required}"
: "${TUNNEL_DOMAIN:?TUNNEL_DOMAIN is required (e.g. t.928104.xyz)}"
TUNNEL_PORT="${TUNNEL_PORT:-53}"
SOCKS_PORT="${SOCKS_PORT:-1080}"
INSTALL_DANTE="${INSTALL_DANTE:-1}"

SESSION_KEY="${SESSION_KEY:-$(head -c 32 /dev/urandom | base64 | tr -d '=/+' | cut -c1-32)}"

if [ "$(id -u)" -ne 0 ]; then
  echo "error: run as root (sudo)" >&2
  exit 1
fi
if [ ! -x "$DNSTT_BIN" ]; then
  echo "error: dnstt-server binary not found/executable: $DNSTT_BIN" >&2
  exit 1
fi

INSTALL_DIR=/opt/dastyab-dns
mkdir -p "$INSTALL_DIR"
cp "$DNSTT_BIN" "$INSTALL_DIR/dnstt-server"
chmod +x "$INSTALL_DIR/dnstt-server"

echo "==> Session key: $SESSION_KEY"
echo "$SESSION_KEY" > "$INSTALL_DIR/session.key"
chmod 600 "$INSTALL_DIR/session.key"

# ---- 1. free port 53 (systemd-resolved stub listener) --------------------
if systemctl is-active systemd-resolved >/dev/null 2>&1; then
  echo "==> Disabling systemd-resolved stub listener on 127.0.0.53:53"
  sed -i 's/^#*DNSStubListener=.*/DNSStubListener=no/' /etc/systemd/resolved.conf
  systemctl restart systemd-resolved
  ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
fi

# Verify port 53 is free.
if ss -ulnp | grep -q ":$TUNNEL_PORT "; then
  echo "warning: port $TUNNEL_PORT still in use; resolve before starting the service" >&2
fi

# ---- 2. firewall ---------------------------------------------------------
echo "==> Opening UDP/TCP $TUNNEL_PORT in firewall"
# ufw (if present)
if command -v ufw >/dev/null 2>&1; then
  ufw allow "$TUNNEL_PORT/udp" >/dev/null 2>&1 || true
  ufw allow "$TUNNEL_PORT/tcp" >/dev/null 2>&1 || true
fi
# Raw iptables (Oracle Cloud images drop inbound by default; insert before the
# DROP chains and persist).
iptables -C INPUT -p udp --dport "$TUNNEL_PORT" -j ACCEPT 2>/dev/null || \
  iptables -I INPUT -p udp --dport "$TUNNEL_PORT" -j ACCEPT || true
iptables -C INPUT -p tcp --dport "$TUNNEL_PORT" -j ACCEPT 2>/dev/null || \
  iptables -I INPUT -p tcp --dport "$TUNNEL_PORT" -j ACCEPT || true
if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save >/dev/null 2>&1 || true
fi

# ---- 3. native dnstt-server systemd service ------------------------------
echo "==> Installing dnstt-server systemd service"
cat > /etc/systemd/system/dnstt-server.service <<EOF
[Unit]
Description=DastYab authoritative DNS-tunnel server
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/dnstt-server -d $TUNNEL_DOMAIN -k $INSTALL_DIR/session.key -u $TUNNEL_PORT
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable dnstt-server >/dev/null 2>&1
systemctl restart dnstt-server
sleep 1
systemctl --no-pager status dnstt-server | head -5 || true

# ---- 4. Dante SOCKS5 egress backend --------------------------------------
if [ "$INSTALL_DANTE" = "1" ]; then
  echo "==> Installing Dante SOCKS5 egress backend on 127.0.0.1:$SOCKS_PORT"
  apt-get update -qq >/dev/null 2>&1 || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dante-server >/dev/null 2>&1 || \
    echo "warning: could not install dante-server (install manually)" >&2

  # Detect the external interface (first non-loopback up interface).
  EXT_IF=$(ip -o -4 route show to default | awk '{print $5}' | head -1)
  EXT_IF="${EXT_IF:-eth0}"

  cat > /etc/danted.conf <<EOF
logoutput: stderr
internal: 127.0.0.1 port = $SOCKS_PORT
external: $EXT_IF

clientmethod: none
socksmethod: none

client pass {
    from: 127.0.0.0/8 to: 0.0.0.0/0
}

socks pass {
    from: 127.0.0.0/8 to: 0.0.0.0/0
}
EOF
  systemctl restart danted >/dev/null 2>&1 || true
  systemctl enable danted >/dev/null 2>&1 || true
  echo "==> SOCKS5 egress listening on 127.0.0.1:$SOCKS_PORT (interface $EXT_IF)"
fi

# ---- 5. print client instructions ----------------------------------------
IP=$(curl -4 -s --max-time 5 https://api.ipify.org || echo "<YOUR_VPS_PUBLIC_IP>")
echo
echo "================================================================================"
echo " DNS-tunnel server ready"
echo "================================================================================"
echo "  VPS public IP : $IP"
echo "  Tunnel domain  : $TUNNEL_DOMAIN"
echo "  Session key    : $SESSION_KEY"
echo
echo " You STILL need to delegate the tunnel subdomain (do this on Cloudflare /"
echo " your registrar — see docs/USER-GUIDE-DNS-TUNNEL.md):"
echo "   A record  a -> $IP        (DNS only / grey cloud — NO proxy)"
echo "   NS record t -> a.$TUNNEL_DOMAIN"
echo
echo " If using the native DastYab client, set:"
echo "   host=$IP base_domain=$TUNNEL_DOMAIN session=$SESSION_KEY"
echo
echo " If using KevinNet / MasterDnsVPN full-tunnel client:"
echo "   core=MasterDnsVPN tunnel_domain=$TUNNEL_DOMAIN key=$SESSION_KEY"
echo "   max_qname_len=101   resolvers=<domestic-resolver-pool>"
echo "================================================================================"
