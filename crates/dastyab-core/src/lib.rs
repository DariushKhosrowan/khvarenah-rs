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

// ---- root modules -------------------------------------------------------
pub mod cf;
pub mod daemon;
pub mod e2e;
pub mod error;
pub mod store;

// ---- domain layers ------------------------------------------------------
pub mod artifact;
pub mod discovery;
pub mod egress;
pub mod mesh;
pub mod net;
pub mod ops;
pub mod probe;
pub mod trust;
pub mod tunnel;

// ---- flat module aliases (stable public surface) ------------------------
// Downstream crates and existing code keep using `dastyab_core::<module>`;
// the domain grouping above is an internal organisation detail.
pub use artifact::analytics;
pub use artifact::artifact_versions;
pub use artifact::config_mutation;
pub use artifact::config_store;
pub use artifact::export;
pub use artifact::generated_configs;
pub use artifact::inventory;
pub use artifact::manifest;
pub use artifact::presets;
pub use artifact::qr;
pub use artifact::vless;
pub use artifact::workspace_snapshot;
pub use artifact::workspace_snapshots;
pub use discovery::ct_anchors;
pub use discovery::gh_sources;
pub use discovery::harvest;
pub use discovery::ns_anchors;
pub use discovery::subscription;
pub use discovery::tg_export;
pub use egress::blackout_bridge;
pub use egress::carrier_pool;
pub use egress::carrier_refresh;
pub use egress::eob_anchor;
pub use egress::vps_deploy;
pub use egress::vps_provision;
pub use egress::worker;
pub use egress::wrangler;
pub use mesh::dtn_gossip;
pub use mesh::health_beacon;
pub use mesh::journal;
pub use mesh::lan_mesh;
pub use mesh::ledger_guard;
pub use mesh::mesh_host;
pub use mesh::mesh_relay;
pub use mesh::remote_beacon;
pub use net::connectivity;
pub use net::dns_shaper;
pub use net::doh;
pub use net::dot;
pub use net::geoip;
pub use net::interface_monitor;
pub use net::proxy_uri;
pub use net::resolve_pool;
pub use net::tls;
pub use net::tun_mtu;
pub use net::tun_route;
pub use ops::backup;
pub use ops::backup_autosync;
pub use ops::i18n;
pub use ops::platform_linux;
pub use ops::selfupdate;
pub use ops::status;
pub use ops::tor;
pub use probe::auto_heal;
pub use probe::autopilot;
pub use probe::cleanip;
pub use probe::cycle_guard;
pub use probe::diagnose;
pub use probe::diagnostics;
pub use probe::doctor;
pub use probe::health;
pub use probe::liveness_sentinel;
pub use probe::multi_worker;
pub use probe::node_probe;
pub use probe::node_refill;
pub use probe::probe_jitter;
pub use probe::scanner;
pub use probe::slipscan;
pub use trust::account_state;
pub use trust::autonomy;
pub use trust::blackout;
pub use trust::bootstrap;
pub use trust::bootstrap_diagnose;
pub use trust::security;
pub use trust::stealth;
pub use trust::token_provision;
pub use trust::token_rotate;
pub use tunnel::arq;
pub use tunnel::chain_mixer;
pub use tunnel::codec_fuzz;
pub use tunnel::desync;
pub use tunnel::dnstt_server;
pub use tunnel::dnstunnel;
pub use tunnel::dnstunnel_arq;
pub use tunnel::dnstunnel_auth;
pub use tunnel::iblt;
pub use tunnel::multilayer;
pub use tunnel::multipath_bond;
pub use tunnel::tunnel_lifeline;

pub use artifact::vless::VlessProfile;
pub use egress::worker_tunnel;
pub use error::CFError;
pub use net::connectivity::{
    FallbackLadder, Probe, ProbeVerdict, RealLadderProbe, Tier, TierChange,
};
pub use net::doh::DohResolver;
pub use net::dot::DotEndpoint;
pub use store::profiles::Profile;
pub use trust::blackout::NetworkState;
pub use trust::sni_spoof;

/// Global application branding used across the app.
pub const BRAND: &str = "DastYab";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The version of the SenPaiScanner CLI we auto-install.
pub const SENPAI_SCANNER_RELEASE: &str = "v1.1.1";
