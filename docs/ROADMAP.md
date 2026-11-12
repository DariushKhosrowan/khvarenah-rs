# Roadmap

Planned work, roughly in priority order. Items marked ✅ are done.

## ✅ Done (v0.1.x)

- Core Cloudflare client (accounts, scripts, subdomain, analytics).
- VLESS profile + share-link generation.
- SenPaiScanner clean-IP scanning with verification.
- Atomic per-profile storage + legacy migration.
- Client-format export (v2rayN, sing-box, Clash).
- Security audit, backup/restore, diagnostics, self-update, presets.
- CLI + TUI + GUI frontends.
- Full documentation suite + SEO-optimized README/landing.
- **Domestic-resolver discovery (blackout)** — `resolve_pool::discover_open_resolvers`
  + CLI `dns-tunnel resolvers` + GUI resolver-pool field.
- **QNAME-length clamping (≤101) + resolver round-robin** in the DNS-tunnel
  client (`encode_name_clamped`, `ResolverPool`).
- **Free-VPS server provisioning** — `scripts/dns-tunnel-server-setup.sh` +
  `scripts/build-dnstt-server.sh` (port 53 prep, firewall, dnstt-server
  systemd, Dante SOCKS5 egress).
- **Domain-selection strategy + user guide** — `docs/BLACKOUT-DNS-TUNNEL-PLAN.md`
  §6 and `docs/USER-GUIDE-DNS-TUNNEL.md`.
- **Selective-repeat windowed ARQ** (`core/src/arq.rs`) — sender window,
  receiver reorder buffer, cumulative+SACK, timing retransmission, 16-bit
  wrap-around; `cargo test -p dastyab-core arq` green.
- **Project doctrine** — `docs/PRINCIPLES.md` codifies the mission, threat
  model, resilience ladder, and engineering standards.

## ✅ Done — Doctrine gaps

- **Authenticated DNS-tunnel responses** — ChaCha20-Poly1305 `seal`/`open`,
  server-sealed replies + client verification / poisoned-resolver penalty
  (doctrine B) — `dnstunnel_auth.rs`.
- **Liveness sentinel** integrated with the racing engine (doctrine C) —
  `liveness_sentinel.rs`.
- **Interface-flap handling** (doctrine E) — `interface_monitor.rs` (sysfs
  carrier/operstate; netlink driver swap noted).
- **TUN anti-loop routing plan** (doctrine A) — `tun_route.rs` (fwmark rule
  plan generator, validated idempotent on live host).
- **MTU/MSS clamping plan** (doctrine D) — `tun_mtu.rs`.
- **DNS-tunnel entropy shaping** (doctrine §5) — `dns_shaper.rs`
  (jittered pacing + length padding + decoy queries) + `send_receive_shaped`
  integration in the tunnel client.

## 🔜 Next — Doctrine gaps (remaining)

- **Platform execution** of doctrine A/D rule plans — Linux `ip`/`iptables`
  + TUN device bring-up, WinTUN bypass, `VpnService.protect`.
- **P2P LAN mesh** — mDNS neighbor discovery + relay (Level 4).

## 🔜 Next

- **Wrangler-free deploy confirmation** — post-deploy smoke test that hits the
  worker URL and checks it responds.
- **Multi-worker management** — list/delete/update workers from one place.
- **DNS smoke test** — verify a DNS record resolves through Cloudflare.
- **GUI async/threading** — run scans in a real background task so the UI
  never blocks.
- **Keyring integration** — optional OS keychain for token storage.

## 🧭 Later

- **Telegram bot** — drive the console from chat.
- **Config presets in JSON** — let users ship custom presets via files.
- **Plugin hooks** — post-deploy / post-scan hooks.
- **Windows installer** — Inno Setup / MSI.
- **Notarized macOS app** for the GUI.

## 🧪 Always

- Keep `cargo clippy --workspace` clean.
- Keep tests green.
- Keep docs in sync.
