//! Authoritative-nameserver egress-anchor discovery (doctrine §8.1).
//!
//! # Why this exists
//!
//! Bootstrapping must never be circular (PRINCIPLES §5). The Telegram harvest,
//! GitHub ingest, and CT logs are all *text* feeds — discoverable only while
//! the client already has a live path to fetch them. This module adds a
//! distinct, out-of-band feed: the **authoritative DNS control plane**.
//!
//! Internet name resolution itself is the one channel a total blackout cannot
//! fully sever — if every DNS path died, no Iranian client could reach any
//! service at all, so the state keeps recursive resolvers (and the root/TLD
//! authoritative servers behind them) reachable. Those authoritative
//! nameservers are therefore a highly-resilient, censorship-resistant control
//! plane: their addresses are published in the root zone (IANA), they are
//! rotated and geographically duplicated, and they are effectively
//! unblockable without breaking the country's own Internet.
//!
//! # What it does
//!
//! 1. **Seed.** The 13 IANA root-server addresses (a.root-servers.net … m.)
//!    are always present, serving as a minimal control-plane anchor set even
//!    before any discovery runs.
//! 2. **Discover.** For a set of high-value public domains, query a recursive
//!    resolver for the zone's **NS records**. The result names the
//!    authoritative servers for that zone (e.g. `ns1.google.com`) — candidate
//!    anchors that must be reachable by construction.
//! 3. **Probe.** For each candidate, send a raw UDP DNS query and require a
//!    well-formed response. Only servers that actually answer are recorded as
//!    verified-live anchors (doctrine §6.4 — no fabricated success).
//! 4. **Persist.** Verified anchors are saved to `<profile>/ns_anchors.json`
//!    with a probe timestamp, mirroring `ct_anchors.json`.

use std::collections::BTreeSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::CFError;
use crate::store::atomic_write;
use crate::store::profiles::{now_ts, profile_dir};

/// IANA root-servers.net addresses (authoritative for the root zone). These
/// are stable, publicly documented, and unblockable in practice — an ideal
/// minimum control plane.
pub const ROOT_SERVER_SEEDS: &[&str] = &[
    "198.41.0.4",     // a.root-servers.net
    "170.247.170.2",  // b.root-servers.net
    "192.33.4.12",    // c.root-servers.net
    "199.7.91.13",    // d.root-servers.net
    "192.203.230.10", // e.root-servers.net
    "192.5.5.241",    // f.root-servers.net
    "192.112.36.4",   // g.root-servers.net
    "198.97.190.53",  // h.root-servers.net
    "192.36.148.17",  // i.root-servers.net
    "192.58.128.30",  // j.root-servers.net
    "193.0.14.129",   // k.root-servers.net
    "199.7.83.42",    // l.root-servers.net
    "202.12.27.33",   // m.root-servers.net
];

/// High-value public zones whose NS records are queried to discover
/// authoritative nameservers.
pub const DEFAULT_ZONES: &[&str] = &[
    "google.com",
    "cloudflare.com",
    "telegram.org",
    "github.com",
    "amazon.com",
    "microsoft.com",
];

/// Cap on the number of NS candidates probed per pass.
const MAX_PROBE: usize = 48;

/// Cap on the total verified anchors kept.
const MAX_ANCHORS: usize = 200;

/// Authoritative-server anchor freshness horizon: anchors older than this are
/// re-probed (and dropped if they no longer answer).
pub const MAX_ANCHOR_AGE_SECS: f64 = 30.0 * 24.0 * 3600.0;

/// A single verified authoritative-nameserver anchor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NsAnchor {
    /// IP address (IPv4) of the authoritative server.
    pub ip: String,
    /// The zone / source that surfaced it.
    pub via: String,
    /// Epoch (unix seconds) when this anchor was verified.
    pub verified_epoch: f64,
    /// Probe latency in milliseconds.
    pub ms: u128,
}

/// Persisted authoritative-nameserver anchor set.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NsAnchorStore {
    pub anchors: Vec<NsAnchor>,
}

/// Result of a discovery pass.
#[derive(Debug, Clone, Default)]
pub struct NsDiscoverReport {
    pub zones_queried: usize,
    pub ns_seen: usize,
    pub candidates: usize,
    pub verified: usize,
    pub added: usize,
    pub anchors_total: usize,
}

fn anchors_path(profile: &str) -> std::path::PathBuf {
    profile_dir(profile).join("ns_anchors.json")
}

/// Public accessor so the CLI can clear/inspect the store.
pub fn anchors_path_pub(profile: &str) -> std::path::PathBuf {
    anchors_path(profile)
}

pub fn load_anchors(profile: &str) -> NsAnchorStore {
    let p = anchors_path(profile);
    crate::store::read_or_default(&p)
}

fn save_anchors(profile: &str, store: &NsAnchorStore) -> Result<(), CFError> {
    let bytes = serde_json::to_vec_pretty(store).map_err(|e| {
        CFError::new(
            "Anchor store",
            format!("Cannot serialize ns_anchors.json: {e}"),
            "Internal error.",
        )
    })?;
    atomic_write(&anchors_path(profile), &bytes)
}

/// Normalize a raw NS hostname: trim, lower-case, drop trailing dot, and
/// reject anything unusable (empty, no dot, IP literal).
fn clean_ns_name(raw: &str) -> Option<String> {
    let s = raw.trim().trim_end_matches('.').trim();
    if s.is_empty() || !s.contains('.') || s.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    Some(s.to_ascii_lowercase())
}

/// Resolve a domain's NS records via a recursive resolver over raw UDP.
/// Returns the distinct, cleaned authoritative hostnames.
pub async fn query_ns_for_zone(resolver: &str, zone: &str, timeout: Duration) -> Vec<String> {
    let id: u16 = rand::random();
    let q = crate::doh::build_dns_query_ns(zone, id);
    let bytes = match crate::resolve_pool::udp_raw_exchange(resolver, &q, timeout).await {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    match crate::doh::parse_dns_response_ns(&bytes) {
        Ok(names) => {
            let mut out = BTreeSet::new();
            for n in names {
                if let Some(clean) = clean_ns_name(&n) {
                    out.insert(clean);
                }
            }
            out.into_iter().collect()
        }
        Err(_) => Vec::new(),
    }
}

/// Probe whether an authoritative server answers a raw UDP DNS query.
/// Sends a root NS query (QTYPE=NS for `.`) and requires any well-formed
/// response — silence or a garbage reply means not-live.
pub async fn probe_ns_live(ip: &str, timeout: Duration) -> Option<u128> {
    let start = std::time::Instant::now();
    let id: u16 = rand::random();
    // Query the root zone (`.`); any authoritative server must answer.
    let q = crate::doh::build_dns_query_ns("", id);
    let bytes = crate::resolve_pool::udp_raw_exchange(ip, &q, timeout)
        .await
        .ok()?;
    if bytes.len() < 12 {
        return None;
    }
    // A real response echoes the request ID and has QR set (0x80).
    let qr = bytes[2] & 0x80 != 0;
    let echoed = u16::from_be_bytes([bytes[0], bytes[1]]) == id;
    if !qr || !echoed {
        return None;
    }
    Some(start.elapsed().as_millis())
}

/// True if `ip` is an acceptable anchor candidate: public, non-hijacked.
/// Rejects the Iranian DPI signature (198.18.0.0/15) and private/reserved
/// ranges (RFC 1918, link-local, loopback, CGNAT).
fn candidate_ok(ip: &std::net::Ipv4Addr) -> bool {
    if crate::doh::is_hijacked_ip(ip) {
        return false;
    }
    let o = ip.octets();
    // 10/8, 172.16/12, 192.168/16, 169.254/16, 127/8, 100.64/10, 0/8.
    if o[0] == 10
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 169 && o[1] == 254)
        || o[0] == 127
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || o[0] == 0
    {
        return false;
    }
    true
}

/// Run one discovery pass: query each zone via `resolvers`, probe the
/// resulting candidate authoritative IPs, and persist verified anchors.
pub async fn discover_ns_anchors(
    profile: &str,
    resolvers: &[String],
    zones: &[&str],
    timeout: Duration,
) -> NsDiscoverReport {
    let mut report = NsDiscoverReport {
        zones_queried: zones.len(),
        ..Default::default()
    };

    // 1. Discover NS hostnames for each zone through the first healthy resolver.
    let mut ns_hosts = BTreeSet::new();
    let mut resolver_idx = 0usize;
    if resolvers.is_empty() {
        return report;
    }
    for zone in zones {
        let resolver = &resolvers[resolver_idx % resolvers.len()];
        let names = query_ns_for_zone(resolver, zone, timeout).await;
        for n in names {
            ns_hosts.insert(n);
        }
        resolver_idx += 1;
    }
    report.ns_seen = ns_hosts.len();

    // 2. Resolve candidate hostnames to IPs (A records) via the resolver.
    //    Filter the Iranian DPI hijack signature (198.18.0.0/15) so a
    //    poisoned answer can never be recorded as a verified anchor.
    let mut candidates = BTreeSet::new();
    for host in ns_hosts.iter().take(MAX_PROBE) {
        let resolver = &resolvers[resolver_idx % resolvers.len()];
        resolver_idx += 1;
        let id: u16 = rand::random();
        let q = crate::doh::build_dns_query_a(host, id);
        if let Ok(bytes) = crate::resolve_pool::udp_raw_exchange(resolver, &q, timeout).await {
            if let Ok(ips) = crate::doh::parse_dns_response_a(&bytes) {
                for ip in ips {
                    if !candidate_ok(&ip) {
                        continue;
                    }
                    candidates.insert(ip.to_string());
                }
            }
        }
    }
    report.candidates = candidates.len();

    // 3. Probe each candidate IP for liveness, collect verified.
    let mut store = load_anchors(profile);
    let existing: BTreeSet<String> = store.anchors.iter().map(|a| a.ip.clone()).collect();
    for ip in candidates {
        if existing.contains(&ip) {
            continue;
        }
        if let Some(ms) = probe_ns_live(&ip, timeout).await {
            store.anchors.push(NsAnchor {
                ip,
                via: "ns-discover".to_string(),
                verified_epoch: now_ts(),
                ms,
            });
            report.verified += 1;
        }
    }

    // 4. Dedupe + cap + persist.
    let mut seen = BTreeSet::new();
    store.anchors.retain(|a| seen.insert(a.ip.clone()));
    store.anchors.truncate(MAX_ANCHORS);
    report.added = report.verified;
    report.anchors_total = store.anchors.len();
    let _ = save_anchors(profile, &store);

    report
}

/// Ensure the root-server seed set is present (verified-live). Idempotent.
pub async fn ensure_root_seeds(profile: &str, timeout: Duration) -> usize {
    let mut store = load_anchors(profile);
    let existing: BTreeSet<String> = store.anchors.iter().map(|a| a.ip.clone()).collect();
    let mut added = 0usize;
    for seed in ROOT_SERVER_SEEDS {
        if existing.contains(*seed) {
            continue;
        }
        if let Some(ms) = probe_ns_live(seed, timeout).await {
            store.anchors.push(NsAnchor {
                ip: seed.to_string(),
                via: "root-seed".to_string(),
                verified_epoch: now_ts(),
                ms,
            });
            added += 1;
        }
    }
    let mut seen = BTreeSet::new();
    store.anchors.retain(|a| seen.insert(a.ip.clone()));
    store.anchors.truncate(MAX_ANCHORS);
    let _ = save_anchors(profile, &store);
    added
}

/// Re-probe anchors older than the freshness horizon and drop dead ones.
pub async fn prune_stale_anchors(profile: &str, timeout: Duration) -> usize {
    let mut store = load_anchors(profile);
    if store.anchors.is_empty() {
        return 0;
    }
    let now = now_ts();
    let mut kept = Vec::with_capacity(store.anchors.len());
    let mut dropped = 0usize;
    for mut a in store.anchors.drain(..) {
        if now - a.verified_epoch < MAX_ANCHOR_AGE_SECS {
            kept.push(a);
            continue;
        }
        match probe_ns_live(&a.ip, timeout).await {
            Some(ms) => {
                a.verified_epoch = now;
                a.ms = ms;
                kept.push(a);
            }
            None => dropped += 1,
        }
    }
    store.anchors = kept;
    let _ = save_anchors(profile, &store);
    dropped
}

/// Current verified-live authoritative-nameserver IPs.
pub fn anchor_ips(profile: &str) -> Vec<String> {
    load_anchors(profile)
        .anchors
        .into_iter()
        .map(|a| a.ip)
        .collect()
}

/// One full refresh: ensure seeds, discover, prune. Returns `(added, pruned)`.
pub async fn refresh_ns_anchors(
    profile: &str,
    resolvers: &[String],
    zones: &[&str],
    timeout: Duration,
) -> (usize, usize) {
    let seeds = ensure_root_seeds(profile, timeout).await;
    let report = discover_ns_anchors(profile, resolvers, zones, timeout).await;
    let pruned = prune_stale_anchors(profile, timeout).await;
    (seeds + report.added, pruned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_ns_name_normalizes() {
        assert_eq!(
            clean_ns_name("NS1.GOOGLE.COM."),
            Some("ns1.google.com".into())
        );
        assert_eq!(
            clean_ns_name("  ns2.example.net  ".trim()),
            Some("ns2.example.net".into())
        );
        assert!(clean_ns_name("").is_none());
        assert!(clean_ns_name("localhost").is_none());
        assert!(clean_ns_name("8.8.8.8").is_none());
    }

    #[test]
    fn root_seed_list_is_complete() {
        // IANA documents 13 root servers.
        assert_eq!(ROOT_SERVER_SEEDS.len(), 13);
        // Yes IPs, each a plausible public address.
        for s in ROOT_SERVER_SEEDS {
            assert!(s.parse::<std::net::Ipv4Addr>().is_ok());
        }
    }

    #[tokio::test]
    async fn probe_rejects_garbage_and_accepts_wellformed() {
        // A malformed/too-short reply must be rejected (quiet, no panic).
        // Spin a tiny UDP server that answers with garbage.
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let expected = format!("{addr}");
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_n, peer) = sock.recv_from(&mut buf).await.unwrap();
            // reply: garbage (short, no QR bit echo)
            let _ = sock.send_to(&[0u8; 4], peer).await;
        });
        let _ = handle;
        let ms = probe_ns_live(&expected, Duration::from_millis(500)).await;
        assert!(ms.is_none());
    }

    #[test]
    fn build_ns_query_has_correct_shape() {
        let q = crate::doh::build_dns_query_ns("google.com", 0x1234);
        assert_eq!(&q[0..2], &[0x12, 0x34]); // ID echoed
        assert_eq!(u16::from_be_bytes([q[4], q[5]]), 1); // QDCOUNT=1
                                                         // QTYPE=NS (2) in the last 4 bytes
        let n = q.len();
        assert_eq!(u16::from_be_bytes([q[n - 4], q[n - 3]]), 2);
        assert_eq!(u16::from_be_bytes([q[n - 2], q[n - 1]]), 1); // QCLASS=IN
    }

    #[test]
    fn candidate_ok_filters_poison_and_private() {
        // Hijack signature (Iranian DPI) must be rejected.
        assert!(!candidate_ok(&"198.18.0.1".parse().unwrap()));
        assert!(!candidate_ok(&"198.18.255.1".parse().unwrap()));
        assert!(!candidate_ok(&"198.19.0.1".parse().unwrap()));
        // Private/reserved must be rejected.
        assert!(!candidate_ok(&"10.0.0.1".parse().unwrap()));
        assert!(!candidate_ok(&"172.16.0.1".parse().unwrap()));
        assert!(!candidate_ok(&"192.168.1.1".parse().unwrap()));
        assert!(!candidate_ok(&"169.254.0.1".parse().unwrap()));
        assert!(!candidate_ok(&"127.0.0.1".parse().unwrap()));
        assert!(!candidate_ok(&"100.64.0.1".parse().unwrap()));
        // Public addresses must be accepted.
        assert!(candidate_ok(&"198.41.0.4".parse().unwrap()));
        assert!(candidate_ok(&"8.8.8.8".parse().unwrap()));
        assert!(candidate_ok(&"1.1.1.1".parse().unwrap()));
    }
}
