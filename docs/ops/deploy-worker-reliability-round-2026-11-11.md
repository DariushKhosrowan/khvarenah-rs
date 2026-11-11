# Deploy-worker reliability round — 2026-11-11 (commit 5f3cee7)

## Symptom (user report)
"deploy worker really doesn't work" — deploy either errored or appeared to
succeed without producing a usable config. "Deploy worker & make config"
consistently failed.

## Root cause
The only on-disk worker bundle was a **truncated 5 MB edgetunnel
`_worker.js`** (a corrupt download ending in a garbage/Hebrew-text tail). The
old `validate_worker_js` only checked *structurally* (`contains export/fetch`),
so the corrupt file passed validation, then `wrangler deploy` / Cloudflare
rejected it by script size (3 MiB ceiling) — deploy always failed.

## Fixes landed
1. `crates/dastyab-core/src/worker.rs`:
   - `validate_worker_js` now enforces `MAX_WORKER_BYTES` (3,000,000) and
     rejects binary/corrupt tails (`data.ends_with(&[0,0,0])` or a UTF-8
     replacement char). Warns (not rejects) above the 1 MiB free-tier limit.
   - New `find_valid_worker_js(explicit)` returns the first *validated* disk
     candidate's bytes (skips invalid/oversized/corrupt files).
   - New `resolve_deploy_worker_bytes()` = validated disk bundle, else the
     built-in `standard_vless_worker_js()` — the single choke point so deploy
     NEVER fails on a bad bundle.
2. `crates/dastyab-core/src/presets.rs`: added `standard_vless_worker_js()`
   — a compact (<10 KB) module-ESM VLESS-over-WebSocket worker using
   `cloudflare:sockets`, ~WebSocketPair`, parsing the VLESS preamble and
   relaying to a TCP upstream. Reads the `UUID` env var; always deployable.
   (`fallback_worker_js` stays as the health-only stub for bootstrap/doctor.)
3. GUI `deploy_worker` + CLI `deploy` both call
   `resolve_deploy_worker_bytes()` instead of the old find-then-validate flow.
4. GUI deploy-status notes (`worker_tunnel_note`, `vps_note`, `mw_note`) now
   auto-expire after a 90s TTL when no deploy task is in flight, so a stale
   "Deploy failed: …" disappears on its own (was permanent before).

## Invariant preserved ("deploy once, configure many")
- `last_deployed_base_link` (durable) + the full config-set ledger
  (share-link/v2rayN/sing-box/Clash) are written at deploy time.
- The Configs tab's "Create config from IP" reuses the deployed worker link and
  swaps the address for any clean IP — no redeploy. Verified by
  `deploy_once_flow_sets_durable_base_link_and_ledger` and
  `config_from_ip_learns_clean_ip_as_seed`.

## New tests
- worker.rs: `validate_rejects_oversized_worker`, `validate_rejects_corrupt_worker`,
  `find_valid_worker_skips_bad_candidates`, `standard_vless_worker_validates_and_is_compact`,
  `resolve_deploy_worker_falls_back_to_builtin_on_bad_disk`.
- app.rs: `status_note_expires_after_ttl_when_idle`,
  `status_note_retained_while_busy`, `status_note_not_expired_before_ttl`.

## Verification
`cargo build/test/clippy --workspace` all green (778 core + 27 gui + 3 error).
Rebuilt release, atomic-swapped `~/.local/bin/dastyab` +
`dastyab-gui` (stop→cp→start daemon), daemon restarted clean.
