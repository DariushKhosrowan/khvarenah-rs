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
