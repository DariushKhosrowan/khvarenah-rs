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

## 🔜 Next — Doctrine gaps

- **Authenticated DNS-tunnel responses** — ChaCha20-Poly1305 / Noise
  validation + poisoned-resolver penalty (doctrine B).
- **TUN anti-loop routing** — `SO_MARK`/fwmark policy routing (Linux),
  WinTUN bypass, `VpnService.protect` (doctrine A).
- **Liveness sentinel** integrated with the racing engine (doctrine C).
- **MTU/MSS clamping** on the TUN (doctrine D).
- **Interface-flap handling** via netlink (doctrine E).
- **P2P LAN mesh** — mDNS neighbor discovery + relay (Level 4).
- **DNS-tunnel entropy shaping** — pacing/padding + decoy queries
  (doctrine §5).

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
