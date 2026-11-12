# Module Guide

How to read the `dastyab-core` source, in dependency order. Each module is
self-contained and documented at the top of its file.

---

## 1. `error.rs` — CFError taxonomy

The foundation. Every fallible function returns `Result<_, CFError>`.

- `CFError { title, detail, fix }` — human-readable, structured errors.
- `KNOWN_CODES` — maps Cloudflare error codes to title/fix templates.
- `explain_response(status, body, action)` — builds a `CFError` from an HTTP
  response.
- `wrap(mode, err)` — wraps network/TLS/timeout errors with a friendly fix.

**Read this first.** Everything else depends on it.

---

## 2. `store/` — persistence

`store/mod.rs`:

- `atomic_write` — crash-safe file writes.
- `mem_dir()` / `profiles_dir()` — path helpers.
- Thread-local test override.

`store/profiles.rs`:

- `Profile` — the whole per-profile state (meta, tokens, accounts, history,
  clean IPs, config).
- `load_profile` / `save_profile` — read/write a profile.
- `create_profile` / `delete_profile` / `rename_profile` — lifecycle.
- `add_token` / `remove_token` — token management.
- `remember_vless` / `list` / `remember_clean_ip` — history.
- `migrate_legacy` — one-time import of pre-0.1 flat files.

---

## 3. `cf/` — Cloudflare client

`cf/mod.rs` defines `Client` and typed models (`Account`, `Script`, `Zone`,
`DnsRecord`, `WorkerRoute`). It talks to the Cloudflare v4 API over
reqwest + rustls.

Key methods:

| Method | Endpoint |
|---|---|
| `verify_token` | `GET /user/tokens/verify` |
| `list_accounts` | `GET /accounts` |
| `get_subdomain` | `GET /accounts/{id}/workers/subdomain` |
| `list_scripts` | `GET /accounts/{id}/workers/scripts` |
| `deploy_script` | `PUT /accounts/{id}/workers/scripts/{name}` |
| `set_vars` | `PATCH .../scripts/{name}/settings` |
| `delete_script` | `DELETE .../scripts/{name}` |
| `list_zones` | `GET /zones` |
| `list_dns_records` | `GET /zones/{z}/dns_records` |
| `create_dns_record` | `POST /zones/{z}/dns_records` |
| `delete_dns_record` | `DELETE /zones/{z}/dns_records/{id}` |
| `list_routes` | `GET /accounts/{id}/workers/routes` |
| `create_route` | `POST /accounts/{id}/workers/routes` |
| `delete_route` | `DELETE /accounts/{id}/workers/routes/{id}` |
| `script_analytics` | `GET .../scripts/{name}/analytics/summary` |

---

## 4. `vless.rs` — VLESS profiles

`VlessProfile` models a VLESS client config and generates:

- `share_link()` — the portable `vless://` URI.
- `xray_client_json()` — full v2rayN JSON config.
- `parse(link)` — reverse-parse a `vless://` link.
- `local_ws(ip, port)` — a local test profile.

---

## 5. `scanner.rs` — clean-IP scanning

Finds working Cloudflare IPs for a deployed worker.

- `install` / `ensure_installed` — bootstrap SenPaiScanner.
- `run_scan` — run the scanner, collect candidate endpoints.
- `scan_once` — stop at the first verified endpoint.
- `scan_many` — find N endpoints.
- `rewrite_vless_with_endpoint` — point a share link at a clean IP.

---

## 6. `health.rs` — endpoint probe

Measures TCP connect latency, TLS handshake, and download throughput for an
endpoint. Used by the scanner to verify candidates.

---

## 7. `export.rs` — client-format exporters

- `ExportFormat` — `V2rayN`, `SingBox`, `Clash`, `ShareLink`.
- `render(profile, format)` — produce the config text.
- `sing_box_json` — full sing-box config.
- `clash_entry` — Clash YAML proxy fragment.

---

## 8. `analytics.rs` — usage aggregation

Normalizes the raw analytics envelope into `UsageSummary` and renders a
human-readable report.

---

## 9. `diagnostics.rs` — endpoint diagnostics

Runs `health::check` over many endpoints, ranks them, and picks the best.

---

## 10. `security.rs` — local audit

`audit()` checks permissions, token-file mode, and scans for token leaks in
unexpected JSON files. Returns an `AuditReport`.

---

## 11. `backup.rs` — profile backup/restore

Exports a profile to a portable JSON bundle and restores it. Also lists
existing backups.

---

## 12. `selfupdate.rs` — updater

Queries GitHub for the latest release, compares versions, and downloads a
matching platform binary.

---

## 13. `presets.rs` — deploy presets

Curated deployment profiles (standard / gaming / max-compat). Each carries a
compatibility date, flags, and a default worker-name stem.

---

## 14. `stealth.rs` — anti-bot

`pre_request_pause`, `boundary_pause`, `retry_backoff` humanize API pacing.
`humanize_worker` varies deployed worker bytes per deploy. Disable with
`DASTYAB_STEALTH=0` or `--no-stealth`.

---

## 15. `geoip.rs` — country lookup

Tags IPs with an ISO country code. Ships a small built-in table; can load a
real GeoLite2 file if present.

---

## 16. `qr.rs` — QR rendering

Renders a share link as a square pixel matrix (used by UIs).

---

## 17. `arq.rs` — selective-repeat windowed ARQ (Level 3)

A self-contained, dependency-light automatic repeat-request engine for reliable
delivery over the lossy DNS transport.

- `Seqno` — 16-bit sequence number with wraparound helpers.
- `ArqSender` — send window; `send()` assigns seqnos, `retransmit()` /
  `pending_timeouts()` drive timeout-based selective retransmission,
  `on_ack(cum, sack)` advances the base and applies the SACK bitmap.
- `ArqReceiver` — reorder buffer; `recv()` returns a `RecvVerdict`
  (delivered / duplicate / buffered / reject); `take_delivered()` drains
  in-order frames; `ack()` returns cumulative ACK + SACK.
- Tested against simulated loss/reorder/duplication and 16-bit wraparound.

**Read `docs/DNS-TUNNEL-PROTOCOL.md` §3 — the protocol contract.**

---

## 18. `dnstunnel.rs` — DNS-tunnel client framing

Client-side framing and the resolver pool:

- `TunnelFrame` — the wire frame (session, seq, flags, payload).
- `encode_name` / `encode_name_clamped` — QNAME assembly with a hard
  `MAX_QNAME_LEN=101` DPI cap (base32 labels, ≤63-char chunks).
- `decode_name` — parse a reply back into a frame.
- `ResolverPool` — discovered domestic recursive resolvers, round-robin.

**Read `docs/DNS-TUNNEL-PROTOCOL.md` §2.**

---

## 19. `dnstt_server.rs` — native authoritative DNS-tunnel server

The server half:

- `TunnelHandler` — per-session authorization + command dispatch (ping,
  status, bootstrap, data echo).
- `DnsTunnelServer` — authoritative server wrapper (base domain + handler).
- `parse_question` / `build_dns_response_txt` — DNS datagram codec.
- `handle_datagram` — end-to-end request→reply pipeline.

**Read `docs/DNS-TUNNEL-PROTOCOL.md` §2.3–2.4.**

---

## 20. `dnstunnel_auth.rs` — authenticated responses (doctrine B)

Seals every server→client reply with ChaCha20-Poly1305 so poisoned/spoofed
answers are rejected:

- `DnsTunnelKey` — 32-byte shared secret + 8-hex session tag.
- `seal(key, plaintext)` — AEAD encrypt, returns nonce‖ciphertext+tag.
- `open(key, authed)` — verify + decrypt; fails on any tampering/tag mismatch.

**Read `docs/DNS-TUNNEL-PROTOCOL.md` §4.**

---

## 21. `resolve_pool.rs` — domestic resolver discovery

`discover_open_resolvers` finds working domestic recursive resolvers to build
the pool that the DNS tunnel stripes across (splitting load and surviving
resolver rate-limits).

## 22. `liveness_sentinel.rs` — liveness sentinel (doctrine C)
Per-route traffic observer that detects the half-open state (outbound flowing,
zero inbound for the stall timeout) via debounced `Stalled` verdicts. Integrated
into `FallbackLadder` as an optional component: on a confirmed stall,
`watchdog_tick` force-verifies (and descends) immediately, bypassing
`max_fails` patience. 6 unit tests + 2 ladder integration tests.

## 23. `interface_monitor.rs` — interface-flap monitoring (doctrine E)
`InterfaceMonitor` trait + `SysfsInterfaceMonitor` (reads carrier/operstate from
sysfs) + a debounced `FlapDetector` that surfaces a sustained DOWN as a single
confirmed flap with flap-count and recency. 5 unit tests.

## 24. `tun_route.rs` — TUN anti-loop routing (doctrine A)
Pure generator for the fwmark anti-loop rule plan. Parses existing
`ip rule show` fwmark rules and produces an idempotent install/uninstall plan
(`ip rule add prio 9000 fwmark 0x2024 lookup main`) that keeps tunnel-originated
(SO_MARK) packets on the main table instead of re-entering the TUN default
route. Validated against the live host (mark 0x2024 present → no-op). 6 unit
tests.

## 25. `tun_mtu.rs` — MTU/MSS clamping (doctrine D)
Pure generator for TCP MSS-clamp rules (`iptables -t mangle -A FORWARD ... -j
TCPMSS`). Supports adaptive `--clamp-mss-to-pmtu` and fixed `--set-mss <mtu-40>`
plans, both idempotent against parsed existing mangle rules. 7 unit tests.

## 26. `config_store.rs` — native node store
Per-profile, on-disk store of inbound VLESS nodes (see
`docs/NODE-STORE-HARVEST.md`). Ingests from a v2rayN `ServersStore.json`
(`import_v2rayn_store`), a single pasted link (`import_single_link`), or the
Telegram harvester. Dedup by `(address, port, uuid)`; preserves every node's
raw share-link so transport params (reality/tls/ws/grpc/xhttp) are never lost.
7 unit tests.

## 27. `harvest.rs` — browser-free Telegram config harvester
Fetches public `https://t.me/s/<channel>` HTML previews via one blocking
`reqwest` GET (direct or through the local xray SOCKS5), extracts and
HTML-decodes `vless://` share-links, and imports them into the config store.
Replaces an always-warm Telegram-web Chromium (~40% CPU) with a transient
near-zero-CPU fetch. 4 unit tests.

