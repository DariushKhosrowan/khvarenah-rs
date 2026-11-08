//! Censorship / blackout state detection.
//!
//! Helps the fallback ladder decide *which* fight we are actually in:
//!
//! - **Normal** — system DNS resolves normally; direct paths likely work.
//! - **DnsHijacked** — the system resolver is returning 198.18.x.x synthetic
//!   answers (the Iranian DPI signature). Direct name-based connection attempts
//!   would go to black holes; we must use IP-pinned channels (DoH/DoT).
//! - **TotalBlackout** — even ICMP/TCP probing of well-known pinned IPs fails
//!   and DNS is the only channel. The app should drop to the DNS tunnel.
//!
//! These are *heuristics*, not guarantees — they guide the ladder state
//! machine, they don't replace real per-tier probes.

use crate::doh::is_hijacked_ip;
use std::net::{Ipv4Addr, ToSocketAddrs};
/// Observed network state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NetworkState {
    /// System DNS looks legitimate.
    Normal,
    /// System DNS is answering with 198.18.x.x synthetic records.
    DnsHijacked,
    /// Everything over TCP/UDP appears blocked; only DNS remains plausible.
    TotalBlackout,
}

impl NetworkState {
    pub fn label(self) -> &'static str {
        match self {
            NetworkState::Normal => "normal",
            NetworkState::DnsHijacked => "dns-hijacked",
            NetworkState::TotalBlackout => "total-blackout",
        }
    }
}

/// Probe system DNS by resolving a well-known CDN name via the OS resolver.
/// Returns true if any returned address lies in the 198.18.0.0/15 hijack
/// signature range.
pub fn system_dns_hijacked() -> bool {
    // `cloudflare.com` is a name DPI commonly targets with synthetic answers.
    for name in ["cloudflare.com", "www.cloudflare.com", "workers.dev"] {
        if let Ok(iter) = (name, 443u16).to_socket_addrs() {
            for addr in iter {
                if let std::net::IpAddr::V4(v4) = addr.ip() {
                    if is_hijacked_ip(&v4) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// A cheap, non-blocking connectivity sniff against literal IPs (no DNS
/// involved). Returns true if *any* known bootstrap IP answers a TCP connect
/// within `timeout`.
pub async fn any_bootstrap_reachable(timeout: std::time::Duration) -> bool {
    let addrs = [
        std::net::SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 443)),
        std::net::SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 443)),
        std::net::SocketAddr::from((Ipv4Addr::new(104, 16, 132, 229), 443)),
    ];
    for addr in addrs {
        if tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr))
            .await
            .is_ok_and(|r| r.is_ok())
        {
            return true;
        }
    }
    false
}

/// Combine the heuristics into a single `NetworkState`.
pub async fn detect(timeout: std::time::Duration) -> NetworkState {
    let hijacked = system_dns_hijacked();
    // If nothing is reachable over TCP and DNS is hijacked, we are almost
    // certainly in a blackout. If DNS is fine but TCP is dark, keep probing.
    let reachable = any_bootstrap_reachable(timeout).await;
    match (hijacked, reachable) {
        (true, false) => NetworkState::TotalBlackout,
        (true, true) => NetworkState::DnsHijacked,
        (false, false) => NetworkState::TotalBlackout,
        (false, true) => NetworkState::Normal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hijack_detection_checks_signature_range() {
        // We cannot control the real resolver here, but we can assert the
        // predicate logic on the helper used internally.
        assert!(is_hijacked_ip(&Ipv4Addr::new(198, 18, 3, 4)));
        assert!(!is_hijacked_ip(&Ipv4Addr::new(104, 16, 132, 229)));
    }
}
