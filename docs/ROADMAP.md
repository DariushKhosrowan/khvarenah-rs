# Roadmap

Planned work, roughly in priority order. Items marked ✅ are done.

## ✅ Done (v0.1.3) — multi-scheme config acquisition

- **Multi-scheme node ingestion** — the node store now accepts every supported
  share-link scheme (vless, vmess, trojan, ss/ssr, hysteria2, tuic), with
  cross-scheme dedup by host+port+id (`proxy_uri`,`,config_store`).
- **Daemon tunnel auto-detect** — autonomous probes/refill now consult
   (cheap 500ms SOCKS5 connect) and route
  through the local xray tunnel under NIN, instead of hardcoding direct
  foreign TCP. Verified: 6/6 ad-hoc checks, pool healthy set grew
  156→317/500 after a probe pass.
- **Telegram harvest: anti-bot stealth pacing** — `fetch_preview_page` now
  calls `stealth::pre_request_pause("read")` before every t.me request, so
  multi-page archive-depth walks and multi-channel harvests no longer trip
  t.me's rate-limit (previously surfaced as intermittent body-decode fetch
  errors). Respects the global `--no-stealth` toggle (doctrine §5, §6.5).
- **Telegram harvest: archive freshness-aware** — `extract_posted_links` tags
  each config with the message's publish epoch from the
  `tgme_widget_message_wrap` blocks; `published_epoch` is refreshed on
  re-harvest (never downgraded) and v2rayN export orders freshest-first.
- **Telegram harvest upgrades** — `extract_proxy_links` recognizes all schemes;
  **archive-depth pagination** walks older posts via the `?before=<id>` cursor
  so configs long gone from the latest page are recovered (`--depth`).
- **Freshness-aware harvesting & export** — the archive crawler now records the
  **per-message publish epoch** of every link (`extract_posted_links`),
  persists it on nodes as `published_epoch` (refreshed to the newest seen on
  re-harvest, never downgraded), and the v2rayN export orders **freshest-first**
  so the most recently public configs (most likely still live) are prioritized.
  Free configs rot fast; freshness makes the survivable pool last longer.
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

## ✅ Done — Doctrine gaps

- **P2P LAN mesh — discovery + relay selection + transport (Level 4)** — `lan_mesh.rs`
  broadcast-beacon discovery + neighbor table + `best_relay` candidate
  selection, exposed as `dastyab mesh {discover|listen|relay}`; plus the
  relay **transport** (`mesh_relay.rs`) that forwards traffic through a
  verified candidate and is exposed as `dastyab mesh {serve|forward}`.
  `serve --upstream` hosts a data relay over a real egress; `forward --url`
  verifies a hop (echo RTT) then fetches a URL through it. This closes the
  final ladder rung end-to-end.
- **Codec fuzz gate (doctrine §8.4)** — `codec_fuzz.rs`, a deterministic,
  dependency-free CI gate that adversarially fuzzes every wire codec every
  `cargo test` run: TunnelFrame/QNAME base32 encode→decode round-trips
  (prefix-preserving under the DPI clamp), full ARQ sessions under random
  loss/dup/reorder (exact in-order once-only delivery enforced), and
  ChaCha20-Poly1305 seal/open with bit-flip tamper rejection. Seeded PRNG
  → identical results on every machine.

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
  Partial: Telegram **systematic graph discovery** (`harvest --discover` now
  crawls cross-referenced channels from yielding seeds and probes them, so the
  net self-expands beyond hardcoded seeds). Remaining: CT logs + authoritative
  nameserver anchors.
- ✅ **Periodic config-health decay** — piggyback node re-probe on the daemon's
  ladder so the store always prunes to verified-live configs
  (`node_probe::probe_stale` + hourly daemon sweep).
- ✅ **Verified healthy nodes → v2rayN export** — `dastyab nodes
  export-v2rayn` merges the verified-healthy pool into v2rayN's ServersStore.json
  (dedup by host+port+uuid, atomic write, idempotent). Closes the loop:
  harvest → probe → export healthy → v2rayN GUI.
- ✅ **CT-log egress-anchor discovery** — `dastyab anchors discover` pulls
  candidate proxy/VPN anchor hostnames from public certificate-transparency
  logs (crt.sh), TLS-verifies them via the pooled client, and persists the
  verified-live set to `<profile>/ct_anchors.json`. An independent,
  out-of-band bootstrap source (doctrine §8.1) so recovery never goes circular.
- ✅ **Autonomous CT-anchor rotation (daemon wire-in)** — the daemon's
  self-maintenance now refreshes the CT-anchor set on a slow cadence
  (`anchors refresh` = refresh + prune; rate-limited, network-gated, run on a
  blocking thread to avoid the reqwest-blocking-under-tokio panic), prunes
  anchors that no longer complete TLS, and journals each pass. New CLI actions:
  `refresh` and `prune`. Closes the "daemon wire-in" half of §8.1.
- ✅ **Autonomous NS-anchor rotation (daemon wire-in)** — the daemon's
  self-maintenance now also refreshes the authoritative-nameserver anchor set
  (`anchors ns` = root-seed probe + high-value-zone NS discovery + prune) on
  the same cadence, giving a second independent, out-of-band DNS control-plane
  bootstrap feed (doctrine §8.1) so bootstrapping can never go circular. Live
  store verified: 13 root-server anchors populated.
- **Wrangler-free deploy confirmation** — post-deploy smoke test that hits the
  worker URL and checks it responds.
- ✅ **UDP-native DNS tunnel** — `dnstunnel_arq.rs` adds a sliding-window
  selective-repeat ARQ transport over the DNS datagram path: bridges `ArqSender`/
  `ArqReceiver` with the real `TunnelFrame` wire codec and a `Resolver`, ACK-driven
  retransmission, and in-order reassembly. `dastyab dns-tunnel selftest` drives
  it live. Verified by `cargo test -p dastyab-core dnstunnel_arq` (lossless
  window delivery + lossy-link recovery by retransmission).
- ✅ **Mesh relay transport (Level 4)** — forward traffic through the `best_relay`
  LAN neighbor discovered by `lan_mesh` (local hop forwarding) to complete the
  Level-4 ladder rung end-to-end. `mesh_relay.rs` provides the framed UDP relay
  protocol (echo probes + data forwarding); `dastyab mesh {serve|forward}` host
  the relay over a real egress and fetch URLs through a verified hop (echo RTT
  gating). Verified live end-to-end in the CLI, commit below.
- ✅ **Level-4 wired into the resilience ladder** — `Tier::MeshRelay` (rank 4,
  label `mesh-relay`) is now the final rung of `TIER_ORDER`. `probe_mesh_relay`
  runs a 2s LAN neighbor sweep off the tokio executor, picks `best_relay`
  (prefers live uplink + low RTT) and echo-probes the relay port. Wired into both
  `RealLadderProbe` / `OwnedLadderProbe` and `drill_all_tiers`, so the daemon
  auto-descends into mesh when all higher tiers fail, and `dastyab drill`
  reports all five rungs live (`3/5` in production: direct/doh/dot up,
  dns-tunnel unconfigured, mesh sees a peer but no live uplink).
- ✅ **Multi-worker management** — list/delete/update workers from one place.
  `dastyab multi-worker {status|deploy|failover|set-active|delete}`. The
  `delete` action removes the remote CF script via the API, drops it from the
  persisted set, and fails over to a healthy standby if it was the active
  worker (`delete_worker_from_set` in `multi_worker.rs`, unit-tested for
  active/non-active/unknown cases).
- ✅ **Multipath ARQ packet bonding** — `multipath_bond.rs`. Stripe or mirror
  frames across multiple lossy lanes (cellular, Wi-Fi, DNS tunnel), each lane
  running its own ARQ sender/receiver, with global bond-sequence reassembly and
  cross-lane dedup. Survives total loss of any single path (Mirror) or heavy
  loss on all (Stripe + selective-repeat retransmission). Adversarial lossy
  lane simulations test do order delivery under 40% per-lane loss.
  `dastyab bond selftest` runs a live 3-lane check.
- **DNS smoke test** — verify a DNS record resolves through Cloudflare.
- **GUI async/threading** — run scans in a real background task so the UI
  never blocks.
- **Keyring integration** — optional OS keychain for token storage.

## 🧭 Later

- **Telegram bot** — drive the console (status, refill, failover) from chat.
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

