# Changelog

## v0.1.0 — 2026-11-07

Initial Rust release.

### Added

- `khvarenah-core`: Cloudflare v4 API client (rustls), VLESS generation,
  clean-IP scanner, health probe, atomic per-profile storage, export
  (v2rayN/sing-box/Clash), analytics, diagnostics, security audit,
  backup/restore, self-update, presets, stealth layer, geo-IP, QR.
- `khvarenah-cli`: full subcommand set (profiles, tokens, verify, accounts,
  deploy, scan, history, status, zones, dns, routes, export, backup,
  analytics, diag, security, presets, update-check, update-apply, migrate).
- `khvarenah-tui`: ratatui dashboard with three panels.
- `khvarenah-gui`: eframe/egui desktop app with three tabs.
- Docs: README, ARCHITECTURE, MODULES, API, DESIGN, SECURITY, DEPLOYMENT,
  ROADMAP, CHANGELOG, GLOSSARY, CONTRIBUTING.
- CI workflow for build/test/clippy.

### Notes

- This is the Rust rewrite of the original Python `khvarenah` console.
- Storage migrates automatically from the old flat files on first run.
