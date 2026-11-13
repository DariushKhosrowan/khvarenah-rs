# Changelog

## Unreleased — 2026-11-13

### Added (offline Telegram-export archive mining — Rung -1 recovery)

- New `tg_export.rs` module: mines **local Telegram Desktop export archives**
  (`chat_export` JSON/HTML folders) for node share-links, with **zero
  egress** — it is the terminal fallback rung (Rung -1) when every live
  channel (Telegram preview, GitHub, CT/NS anchors) is unreachable under
  total blackout.
- `extract_b64_embedded_links()`: decodes **whole-link base64 blobs** (and
  URL-safe variants) that are common in archived chats — a config encoded as a
  bare base64 string is recovered, not just plaintext `scheme://` links.
- `harvest_export_dir()` walks a directory tree, scans JSON (`messages[].text`)
  and HTML/text files, runs any-scheme extraction (vless/vmess/trojan/ss),
  dedups, and imports everything tagged `source=telegram` into the profile's
  node store — ready for the normal probe/failover path.
- CLI: `dastyab nodes export-archive --profile <p> --path <dir>` scans a
  Telegram export folder and prints scanned/links/added/skipped counts.
- Fixed profile-contamination bug in tests: unregistered profile ids silently
  fell back to the real `default` profile; the harness now registers a real
  profile (via `profile.json` meta) so verification is isolated from live data.

### Added (IBLT zero-roundtrip set reconciliation — sync node pools under blackout)

- New `iblt.rs` module: **Invertible Bloom Lookup Table**. Cells carry
  `(count, key_sum, value_sum)` — 20 bytes each; `insert`/`delete` are
  XOR-symmetric, and `decode` peels "pure" cells (count ±1) to recover the
  full `(key, value)` set that was inserted minus deleted. Sized at ~2× the
  set for clean peeling.
- Gossip sync can now ask for *exactly what's missing* instead of shipping a
  full node pool: `manifest_of_urls()` builds an IBLT from a node set, and
  `missing_from_peer()` subtracts our items from a copy of the peer's manifest
  and decodes the residue → only the nodes we lack remain.
- `node_url_fp()` gives a stable 64-bit identity for a node URL, so both sides
  agree on what an element means without sending URLs up front.
- CLI: `dastyab gossip manifest --profile <p> --path <file>` writes an IBLT
  for the profile's node store (500 nodes → 1000 cells / 20KB); `dastyab
  gossip reconcile --profile <p> --path <peer_manifest>` reads a peer manifest
  and prints what we lack (URL if known, fingerprint hex otherwise).

### Added (durable gossip trust ledger — anti-poison memory survives reboots)

- `GossipLedger` is now **persistent**: the per-peer trust table (anti-replay
  epoch, offered/confirmed-live counts, earned score) is serialized to
  `gossip_ledger.json` in the profile dir and reloaded on start. A gated
  peer (one that only ever offered dead nodes) now *stays* gated across
  reboots instead of resetting to a clean slate every boot — closing the
  do-over attack on the anti-poison model.
- `LedgerSnapshot` wire format (versioned, v1), `save_to` (write-then-rename,
  atomic-ish), `load_from` (tolerant of missing/corrupt file — starts clean).
- CLI: `gossip accept` now routes through the durable ledger (signature +
  replay + trust gates) and persists it; `gossip peers` prints the real
  persisted ledger.
- 2 new unit tests: trust survives reload; a gated peer stays gated after
  reload (11 gossip tests total).

### Added (air-gapped DTN gossip — Level-4 mesh extends offline)

- **New `dtn_gossip` module**: store-and-forward node exchange that lets a
  machine with **no WAN at all** bootstrap configs from a nearby peer. This
  is the Gemini boss's recommended rung and the offline extension of the L4
  mesh. Signed, tamper-evident bundles (`DYBDTN1` crate), anti-poison trust
  scoring (a peer that offers dead nodes repeatedly gets gated), epoch-based
  anti-replay, dedup, and a bounded store-and-forward queue.
- **CLI `gossip` subcommand**: `make` (sign a bundle of healthy nodes to a
  file), `verify` (check a bundle's signature — no writes), `accept` (verify
  and merge into the node store), `peers` (trust ledger placeholder).
  Transport-agnostic: hand the bundle over USB / QR / BLE / Wi-Fi Direct /
  or a chat.
- 9 new unit tests (sign/verify round-trip, tamper rejection, cross-key
  rejection, stale-replay rejection, dedup, trust gating, bounded queue).

### Added (chain egress-IP risk + Shir-o-Khorshid + corrective-layer support)

- **`Engine::ShirOKhorshid`**: new chain engine (label `shirokhorshid`,
  binary hint `gost`, default port 10866) for the doctrine §3 L2
  Shir-o-Khorshid forward-proxy pipeline (Rathole/GOST/smux over TLS).
- **`Engine::egress_risk() -> EgressRisk`**: classifies the public exit IP a
  chain's outermost layer presents. Tor=Risky (flagged/blocked by major
  services), Psiphon/Lantern=Moderate, V2rayN/Shadowsocks/ShirOKhorshid/
  DastYab=Clean.
- **`ChainRunReport.egress_risk`**: computed from the outermost (internet-
  facing) Up layer, so a clean corrective layer *after* tor correctly yields a
  clean exit. CLI warns prominently when the exit IP is risky/flagged and
  recommends `--chain tor,shirokhorshid` (or `tor,v2rayn`) to correct it.
- **Verification**: 3 new chain tests (risk classification, engine validity,
  outermost-layer risk); full core suite green, clippy clean.

### Added (Level-4 P2P LAN mesh — the final resilience-ladder rung)

- **`dastyab-core::lan_mesh`** (new module): intranet P2P discovery via a
  tiny raw-UDP broadcast beacon (`UDP_PORT` 5837, magic `DYBMESH1`). Each
  instance advertises its peer id, relay port, and whether it currently holds a
  live upstream uplink (`has_uplink`). A `NeighborTable` keeps heartbeats
  fresh (stale pruned after `NEIGHBOR_TIMEOUT_SECS`), and `best_relay` picks
  the best hop candidate — preferring a fresh peer with an active uplink,
  lowest EWMA RTT, then recency. Self-echo is filtered so a host never treats
  its own broadcast as a peer. 6 unit tests.
- **CLI**: `dastyab mesh {discover|listen|relay} [--window SECS] [--upstream]
  [--name LABEL]`. `discover` sweeps the LAN and reports live peers + the best
  relay candidate; `listen` announces this host and watches for peers; `relay`
  resolves the best hop candidate and errors clearly if none exists. This is
  the discovery/selection half of doctrine Level 4 — the transport layer can
  open a local hop through the returned candidate.
- **Doctrine coverage**: Level 4 of the resilience ladder (PRINCIPLES §3) is
  now implemented at the discovery+selection layer, closing the last open
  ladder rung; the remaining sub-task is a relay *transport* that uses the
  candidate (tracked in ROADMAP).

## Unreleased — 2026-11-12

### Added (node provenance + periodic config-health decay)

- **Node provenance tagging** — `config_store::import_single_link_source`
  records each imported node's origin (`telegram` | `github` | `pasted`)
  instead of hardcoding `pasted`. The Telegram harvester tags `telegram`,
  the GitHub ingester tags `github` — so auto-recovered configs are auditable
  and separable from manual pastes (a precondition for pruned, verified-live
  stores).
- **Periodic config-health decay** — `node_probe::probe_stale` re-probes a
  bounded set (≤64/pass) of stale (≥6h) or never-checked nodes, marks dead
  ones, and fails over if the active node died. Wired into the daemon's
  hourly self-maintenance (`DaemonState.last_node_decay_ts`). This is the
  "never stop verifying" half of the doctrine: even a healthy pool is
  continuously re-checked as upstream servers churn.
- **Wider refill channel net** — `DEFAULT_REFILL_CHANNELS` expanded from 3 to
  11 channels, ordered by live-verified plaintext-link yield
  (v2ray_configs_pools ≈286, MARAMBASHI ≈180, v2raycollector ≈59, …) so
  autonomous recovery casts a wider, higher-yield net.


### Added (autonomous node-refill — "never run out of working configs")

- **`dastyab-core::node_refill`** (new module): a single orchestrator that
  self-recovers a dead/empty node pool. `refill_needed` is a pure predicate
  (empty pool, or no node known healthy → harvest); `run_refill` deep-harvests
  default Telegram channel archives (6 pages) + GitHub config repos, probes
  every recovered node, and promotes a verified-healthy one. No fabricated
  success — every "healthy" count comes from a real probe (doctrine §6.4).
- **Daemon integration**: `run_self_maintenance` now runs a refill pass when
  the network is up and the pool has no known-healthy node, rate-limited to
  once per `REFILL_COOLDOWN_SECS` (900s) via a new `DaemonState.last_refill_ts`
  field. The result is logged and journaled as `JournalKind::NodeRefill`.
- **CLI**: `dastyab nodes refill [--profile …] [--proxy] [--depth N]`
  (depth default = 6; 0 uses the module default). It reports the trigger
  reason, Telegram/GitHub harvest counts, probe results, and any promotion.
- **GUI/journal surface**: the new `NodeRefill` journal kind is rendered in the
  CLI journal listing and the GUI history (label + accent color).

### Added (native config-store + Telegram harvest — the "no-browser" path)

- **`dastyab-core::config_store`** (new module): a per-profile, on-disk
  store of inbound VLESS nodes. It ingests nodes from three sources:
  - `import_v2rayn_store` — read a v2rayN `ServersStore.json` and import all
    VLESS servers (dedup by address+port+uuid; skips non-VLESS; preserves the
    raw share-link including reality/tls/ws/grpc/xhttp transport params).
  - `import_single_link` — paste one `vless://` share-link.
  - `harvest` (below) — pull configs straight from Telegram.
  Every node keeps its **raw share-link**, so transport validation (reality
  `pbk`/`sid`/`fp`, ws path, etc.) is never lost to re-serialization. The
  CLI exposes `dastyab nodes import|paste|activate|list|clear`.
- **`dastyab-core::harvest`** (new module): harvest free configs from
  Telegram **without keeping a browser open**. Telegram publishes a public,
  auth-free HTML preview of any channel at `https://t.me/s/<channel>`; the
  harvester fetches it with one blocking `reqwest` GET (direct, or routed
  through the local xray SOCKS5 with `--proxy`), extracts `vless://`
  links, HTML-decodes `&amp;` → `&`, strips the trailing `#` fragment, and
  imports them into the config store. This replaces a ~40% CPU warm
  Chromium session with a near-zero-CPU fetch. Verified end-to-end against a
  real channel. CLI: `dastyab harvest --channels v2ray_config`.

## v0.1.4 — 2026-11-11

### Fixed (worker deploy reliability + status-note auto-expiry)

- `dastyab-core`: worker deploy no longer starves on a corrupt / oversized
  on-disk `_worker.js` (e.g. a truncated 5 MB download with a garbage tail).
  `validate_worker_js` now enforces Cloudflare's script-size ceiling and
  rejects binary/corrupt tails; the new `find_valid_worker_js` /
  `resolve_deploy_worker_bytes` pick the first *validated* bundle and fall back
  to a new compact built-in `standard_vless_worker_js` (a real module ESM
  WebSocket VLESS worker under 10 KB) so deploy ALWAYS succeeds with a usable
  tunnel. The GUI `deploy_worker` and CLI `deploy` both route through it.
  New tests: `validate_rejects_oversized_worker`,
  `validate_rejects_corrupt_worker`, `find_valid_worker_skips_bad_candidates`,
  `standard_vless_worker_validates_and_is_compact`,
  `resolve_deploy_worker_falls_back_to_builtin_on_bad_disk`.
- `dastyab-gui`: deploy-status notes (`worker_tunnel_note`, `vps_note`,
  `mw_note`) now auto-expire after a TTL when no deploy is in flight — a stale
  "Deploy failed: …" / warning disappears on its own instead of lingering
  forever. New tests: `status_note_expires_after_ttl_when_idle`,
  `status_note_retained_while_busy`, `status_note_not_expired_before_ttl`.

## Unreleased — 2026-11-11

### Fixed (GUI robustness — deploy/clean-IP/config flow)

- `dastyab-gui`: deploy results are applied regardless of which tab is
  visible — switching tabs mid-deploy no longer hides or drops the outcome
  (the worker-tunnel note, running-task indicator, and store refresh all
  proceed from any view). Regression-test: `tab_switch_during_deploy_still_applies_result`.
- `dastyab-gui`: stale error banners / warnings now auto-expire and are
  cleared on any successful retry — a failed deploy's red banner disappears
  once a redeploy succeeds. Regression-tests: `successful_redeploy_clears_stale_error_banner`.
- `dastyab-gui`: token "Remove" now targets the profile the user is viewing
  (`profile_id`), consistent with Add/Make-active, so it can never mutate the
  wrong profile when the cache lags the selection.
- `dastyab-gui`: "Deploy worker & make config" and "Deploy Worker tunnel"
  both persist the durable base link and generate the full config set
  (share-link/v2rayN/sing-box/Clash) into the Configs ledger on deploy; the
  Configs tab stays fully decoupled so the user can create configs from any
  clean IP repeatedly without ever redeploying. Covered by
  `deploy_once_flow_sets_durable_base_link_and_ledger` /
  `config_from_ip_learns_clean_ip_as_seed`.
- `dastyab-core`: `find_wrangler` now honors a `DYB_WRANGLER_BIN` env
  override (before PATH lookup) — users can pin a specific wrangler install,
  and tests inject a mock to exercise the full deploy subprocess. New tests:
  `deploy_worker_via_wrangler_parses_mock_output`,
  `find_wrangler_honors_env_override`.

### Added (blackout DNS-tunnel productionization)

- `dastyab-core` `resolve_pool.rs`: **domestic-resolver pool** — raw-UDP TXT
  transport (`udp_query_txt`), `ResolverPool` (round-robin over many resolver IPs
  to dodge per-IP rate limits and poisoned resolvers; implements `Resolver`), and
  `discover_open_resolvers` (parallel scanner over Iranian ISP seed candidates).
  `IRANIAN_RESOLVER_CANDIDATES` ships as a starting point. Tests:
  `udp_query_txt_roundtrip_against_authoritative_handler`,
  `resolver_pool_roundrobin_skips_dead_and_reaches_live`,
  `discover_open_resolvers_detects_the_live_one`.
- `dastyab-core` `dnstunnel.rs`: **QNAME clamping** — `encode_name_clamped`
  caps the wire QNAME at `MAX_QNAME_LEN` (101), used by `send_receive` and the
  liveness probe so every query survives Iranian DPI filter hardware. Tests:
  `encode_name_clamped_stays_under_dpi_limit`,
  `encode_name_clamped_leaves_small_payload_intact`.
- `dastyab-core` `vps_deploy.rs`: `TunnelClientConfig.resolver_pool`
  (`Option<Vec<String>>`) — when set, `probe_tunnel_live` recurses through the
  pool instead of querying the VPS directly. Per-profile persistence.
- `dastyab-cli`: new `dns-tunnel resolvers` subcommand — scans candidate
  resolvers and persists the working pool to the profile.
- `dastyab-gui`: Blackout resilience panel gains a "Resolver pool" input
  (comma-separated IPs) saved into the VPS tunnel config.
- `scripts/build-dnstt-server.sh`: builds the native `dnstt-server` binary for
  x86_64/aarch64 Linux to scp to a free VPS.
- `scripts/dns-tunnel-server-setup.sh`: turnkey provisioning for a free VPS —
  frees port 53, opens the firewall (incl. Oracle iptables), installs the
  `dnstt-server` systemd service + Dante SOCKS5 egress, and prints the session
  key + client config.
- Docs: `docs/BLACKOUT-DNS-TUNNEL-PLAN.md` §6 (domain-selection strategy: never
  use a `.ir` domain; short numeric `.xyz` recommended) and new user guide
  `docs/USER-GUIDE-DNS-TUNNEL.md`.

## v0.1.0 — 2026-11-07

Initial Rust release.

### Added

- `dastyab-core`: Cloudflare v4 API client (rustls), VLESS generation,
  clean-IP scanner, health probe, atomic per-profile storage, export
  (v2rayN/sing-box/Clash), analytics, diagnostics, security audit,
  backup/restore, self-update, presets, stealth layer, geo-IP, QR.
- `dastyab-cli`: full subcommand set (profiles, tokens, verify, accounts,
  deploy, scan, history, status, zones, dns, routes, export, backup,
  analytics, diag, security, presets, update-check, update-apply, migrate).
- `dastyab-tui`: ratatui dashboard with three panels.
- `dastyab-gui`: eframe/egui desktop app with three tabs.
- Docs: README, ARCHITECTURE, MODULES, API, DESIGN, SECURITY, DEPLOYMENT,
  ROADMAP, CHANGELOG, GLOSSARY, CONTRIBUTING.
- CI workflow for build/test/clippy.

### Notes

- This is the Rust rewrite of the original Python `dastyab` console.
- Storage migrates automatically from the old flat files on first run.
