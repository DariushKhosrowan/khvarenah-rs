//! SNI allowlist scanner — a network diagnostic that is independent of the
//! Cloudflare account (no token, no worker, no deploy).
//!
//! Iran's DPI can block specific TLS Server Name Indication values (SNI). This
//! module opens TCP connections to a public Cloudflare edge and tests which SNI
//! values pass DPI: it writes a ClientHello carrying the candidate SNI and
//! observes whether the server responds. A ServerHello (or any valid bytes back)
//! proves the SNI was allowed; a TCP reset before any response means it was
//! blocked.
//!
//! This is the only diagnostic that produces live network evidence while the CF
//! account is dead, and it directly feeds the round-13 anti-DPI decision:
//! - some SNIs pass, some blocked → DPI is SNI-based → build an SNI-spoofing
//!   injector (the allowlist becomes the fake SNI candidates),
//! - all pass → DPI is not active at the SNI layer → look at TLS fingerprint,
//! - all blocked → DPI escalated to TLS-fingerprint level → ClientHello
//!   randomization at the wire level.

pub mod candidates;
pub mod config;
pub mod scanner;
pub mod ws_probe;
