//! Khvarenah core library.
//!
//! Pure-Rust port of the Python `khvarenah` console. Everything network- or
//! filesystem-agnostic lives here: Cloudflare API client, profile store,
//! VLESS generation, anti-bot stealth, clean-IP scanner orchestration,
//! health checks, geo-IP lookup, QR helpers, client-format export, usage
//! analytics, endpoint diagnostics, a security audit, backup/restore,
//! self-update, and deploy presets.
//!
//! ## Crate layout
//! ```text
//! lib.rs       — crate root, re-exports
//! error.rs     — CFError taxonomy (title / detail / fix) — "debugging works"
//! store/       — atomic, per-profile persistent memory (update-safe)
//! vless.rs     — VLESS profile / share-link / xray client JSON
//! stealth.rs   — humanized pacing + worker byte-fingerprint humanization
//! cf/          — Cloudflare v4 API client (async, reqwest + rustls)
//! scanner.rs   — SenPaiScanner orchestration, smart stop-on-first-working
//! health.rs    — TCP/TLS health + latency probe for endpoints
//! worker.rs    — worker bundle discovery + humanization pre-upload
//! geoip.rs     — GeoLite2 country lookup (bundled .mmdb)
//! qr.rs        — QR matrix render for share links
//! export.rs    — v2rayN / sing-box / Clash client-format exporters
//! analytics.rs — request/traffic usage aggregation
//! diagnostics.rs — endpoint latency & throughput ranking
//! security.rs  — local security audit (permissions, token leaks)
//! backup.rs    — profile backup / restore
//! selfupdate.rs — GitHub release updater
//! presets.rs   — curated deploy presets
//! ```

pub mod analytics;
pub mod autopilot;
pub mod backup;
pub mod cf;
pub mod cleanip;
pub mod diagnostics;
pub mod error;
pub mod export;
pub mod geoip;
pub mod health;
pub mod presets;
pub mod qr;
pub mod scanner;
pub mod security;
pub mod selfupdate;
pub mod stealth;
pub mod store;
pub mod vless;
pub mod worker;

pub use error::CFError;
pub use store::profiles::Profile;
pub use vless::VlessProfile;

/// Global application branding used across the app.
pub const BRAND: &str = "Khvarenah";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The version of the SenPaiScanner CLI we auto-install.
pub const SENPAI_SCANNER_RELEASE: &str = "v1.1.1";
