# Roadmap

Planned work, roughly in priority order. Items marked ✅ are done.

## ✅ Done (v0.1.3) — multi-scheme config acquisition

- **Multi-scheme node ingestion** — the node store now accepts every supported
  share-link scheme (vless, vmess, trojan, ss/ssr, hysteria2, tuic), with
  cross-scheme dedup by host+port+id (`proxy_uri`,`,config_store`).
- **Telegram harvest upgrades** — `extract_proxy_links` recognizes all schemes;
  **archive-depth pagination** walks older posts via the `?before=<id>` cursor
  so configs long gone from the latest page are recovered (`--depth`).
- **GitHub config-source ingestion** (`dastyab sources ingest`) — discovers the
  `v2ray-configs` topic + curated repos, fetches plain & base64 subscription
  files, validates links, and imports into the store.

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
- **Platform execution** (doctrine A/D) — `platform_linux.rs` runs the
  A/D rule plans via `ip`/`iptables` (dry-run mode for CI, RAII TUN
  teardown) + `dastyab platform {plan|apply|teardown}` CLI. Builds run on
  GitHub Actions runners (not the laptop).

## 🔜 Next — Doctrine gaps (remaining)

- **WinTUN / `VpnService.protect`** platform execution (Windows/Android).
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
