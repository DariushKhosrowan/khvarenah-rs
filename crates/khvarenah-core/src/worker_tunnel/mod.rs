//! Cloudflare-Worker-hosted DNS tunnel (no VPS) — control plane.
//!
//! This module ships the zero-credential DNS tunnel: a Cloudflare Worker is
//! the tunnel *server*, deployed via the already-present CF token, so no VPS
//! or SSH credentials are needed. The client talks to it over HTTPS (the same
//! path the app already uses for Cloudflare), which makes it reachable even
//! under censorship — and it is fully automatic after the single base token.
//!
//! # Protocol
//!
//! The wire format reuses `crate::dnstunnel::TunnelFrame` and its base32
//! label codec. The client encodes a frame as a qname string and sends it as
//! an HTTPS GET to the deployed worker:
//!
//! ```text
//! GET /?q=<encoded-qname>        header: X-Khvarenah-Session: <secret>
//! ```
//!
//! The worker authenticates via the secret (stored as the `KHV_SESSION_SECRET`
//! worker var at deploy time), decodes the frame, answers according to its
//! `flags` (1=ping, 2=status, 3=bootstrap, 0=data-plane—not yet), and returns
//! the *encoded reply qname* as a `text/plain` body. The client-side
//! `WorkerTunnelResolver` returns that string verbatim, so the existing
//! `dnstunnel::send_receive` decode path round-trips unchanged.
//!
//! # Scope
//!
//! Control plane only: flags 1/2/3. Data-plane (flags=0, actual VLESS relay)
//! is a later step.
//!
//! Files:
//! - `bundle.rs` — the embedded worker JS (`WORKER_TUNNEL_JS`).
//! - `deploy.rs` — `deploy_worker_tunnel`: mints/names the worker, deploys it,
//!   sets its secret var, and persists the `TunnelClientConfig` (mode=Worker).
//! - `resolver.rs` — `WorkerTunnelResolver`, a `dnstunnel::Resolver` that does
//!   the HTTPS call.

pub mod bundle;
pub mod deploy;
pub mod resolver;
pub mod secret;

pub use bundle::{WORKER_CRON_SCHEDULE, WORKER_TUNNEL_JS};
pub use deploy::{deploy_worker_tunnel, WorkerTunnelDeploy, WorkerTunnelDeployOpts};
pub use resolver::WorkerTunnelResolver;

/// Logical DNS base domain shared by the worker and its client. Both encode
/// frames under this suffix; it does not need to resolve — it is only a
/// framing namespace so `TunnelFrame::decode_name` round-trips.
pub const KHV_TUNNEL_BASE: &str = "tun.khvarenah.dev";
