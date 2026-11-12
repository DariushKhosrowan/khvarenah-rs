//! DastYab core library.
//!
//! Pure-Rust port of the Python `dastyab` console. Everything network- or
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

//! Local mock-worker harness (dev/testing). Feature-gated behind
//! `dev-mock` so release builds don't carry it.
#[cfg(feature = "dev-mock")]
pub mod mock_worker;

pub mod account_state;
pub mod analytics;
pub mod arq;
pub mod artifact_versions;
pub mod auto_heal;
pub mod autonomy;
pub mod autopilot;
pub mod backup;
pub mod backup_autosync;
pub mod blackout;
pub mod blackout_bridge;
pub mod bootstrap;
pub mod bootstrap_diagnose;
pub mod carrier_pool;
pub mod carrier_refresh;
pub mod cf;
pub mod cleanip;
pub mod config_mutation;
pub mod config_store;
pub mod connectivity;
pub mod cycle_guard;
pub mod daemon;
pub mod desync;
pub mod diagnose;
pub mod diagnostics;
pub mod dns_shaper;
pub mod dnstt_server;
pub mod dnstunnel;
pub mod dnstunnel_auth;
pub mod doctor;
pub mod doh;
pub mod dot;
pub mod e2e;
pub mod error;
pub mod export;
pub mod generated_configs;
pub mod geoip;
pub mod gh_sources;
pub mod harvest;
pub mod health;
pub mod health_beacon;
pub mod interface_monitor;
pub mod inventory;
pub mod journal;
pub mod lan_mesh;
pub mod ledger_guard;
pub mod liveness_sentinel;
pub mod manifest;
pub mod mesh_relay;
pub mod multi_worker;
pub mod multilayer;
pub mod node_probe;
pub mod node_refill;
pub mod platform_linux;
pub mod presets;
pub mod probe_jitter;
pub mod proxy_uri;
pub mod qr;
pub mod remote_beacon;
pub mod resolve_pool;
pub mod scanner;
pub mod security;
pub mod selfupdate;
pub mod slipscan;
pub mod sni_spoof;
pub mod status;
pub mod stealth;
pub mod store;
pub mod tls;
pub mod token_provision;
pub mod token_rotate;
pub mod tor;
pub mod tun_mtu;
pub mod tun_route;
pub mod vless;
pub mod vps_deploy;
pub mod vps_provision;
pub mod worker;
pub mod worker_tunnel;
pub mod workspace_snapshot;
pub mod workspace_snapshots;
pub mod wrangler;

pub use blackout::NetworkState;
pub use connectivity::{FallbackLadder, Probe, ProbeVerdict, RealLadderProbe, Tier, TierChange};
pub use doh::DohResolver;
pub use dot::DotEndpoint;
pub use error::CFError;
pub use store::profiles::Profile;
pub use vless::VlessProfile;

/// Global application branding used across the app.
pub const BRAND: &str = "DastYab";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The version of the SenPaiScanner CLI we auto-install.
pub const SENPAI_SCANNER_RELEASE: &str = "v1.1.1";
