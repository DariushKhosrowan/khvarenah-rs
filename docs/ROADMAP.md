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
- **Autonomous node-refill** (`core/src/node_refill.rs`) — when the node pool
  has no known-healthy config, DastYab **self-recovers**: it deep-harvests
  Telegram channel archives + GitHub config repos, probes every recovered node,
  and promotes a working one. Wired into the daemon (rate-limited to once per
  15 min) so a dead pool is topped up with zero human intervention; also
  exposed as `dastyab nodes refill`. Doctrine §5 (zero-config, never run
  out of working configs).

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

## ✅ Done — Efficiency doctrine (§6.5)

- **Pooled shared HTTP client** across harvest/GitHub ingest/probes (one TLS
  connection pool per run) — `harvest::build_client`, `gh_sources::build_client`.
- **Bounded concurrency** (`buffer_unordered`, ≤8 in flight) so wall-clock
  scales with the slowest path, not the sum.
- **Rate-limited expensive loops** — node-refill ≤ once/15 min
  (`node_refill::REFILL_COOLDOWN_SECS`), integrity sweep ≤ once/day.
- **Cheapest-first probes** — local/on-disk work runs regardless of network;
  ladder probes ordered cheapest→most expensive.
- **Minimal DNS payloads** — QNAME clamp ≤101, base32/base64url unpadded,
  EDNS0 ≤1232 bytes.

## 🔜 Next

- **Deeper autonomous recovery** — seed a rotating, verified egress-anchor set
  from more out-of-band sources (more Telegram channels + archive depth, CT
  logs, authoritative nameservers) so bootstrapping can never go circular.
- ✅ **Periodic config-health decay** — piggyback node re-probe on the daemon's
  ladder so the store always prunes to verified-live configs
  (`node_probe::probe_stale` + hourly daemon sweep).
- **Wrangler-free deploy confirmation** — post-deploy smoke test that hits the
  worker URL and checks it responds.
- **UDP-native DNS tunnel** — move the client off TCP-style framing toward the
  low-overhead ARQ over raw UDP (5–7 byte overhead target).
- **Multi-worker management** — list/delete/update workers from one place.
- **DNS smoke test** — verify a DNS record resolves through Cloudflare.
- **GUI async/threading** — run scans in a real background task so the UI
  never blocks.
- **Keyring integration** — optional OS keychain for token storage.

## 🧭 Later

- **Telegram bot** — drive the console (status, refill, failover) from chat.
- **Fuzz the codecs** (QNAME/base32/ARQ/ChaCha20 frame) + adversarial
  loss/reorder/dup simulations as a permanent CI gate.
- **Config presets in JSON** — let users ship custom presets via files.
- **Plugin hooks** — post-deploy / post-scan hooks.
- **Windows installer** — Inno Setup / MSI.
- **Notarized macOS app** for the GUI.
- **Edge-caching resolved clean IPs** so re-scans are incremental, not from
  scratch.

## 🧪 Always

- Keep `cargo clippy --workspace -- -D warnings` clean.
- Keep `cargo fmt` clean.
- Keep tests green.
- Keep docs in sync.

