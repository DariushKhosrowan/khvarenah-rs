# Changelog

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
