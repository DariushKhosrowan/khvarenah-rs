//! Certificate-Transparency egress-anchor discovery (doctrine §8.1).
//!
//! # Why this exists
//!
//! Bootstrapping must never be circular (PRINCIPLES §5): if every egress anchor
//! is discovered through the same path that's blocked, the client starves. The
//! Telegram harvest and GitHub ingest already widen the source set; this module
//! adds an independent, out-of-band feed — **certificate transparency logs**
//! (crt.sh). Any host that has ever issued a TLS certificate is visible in CT
//! logs, and proxy/VPN operator domains routinely appear there long before they
//! are shared in Telegram channels. So even when a channel net goes quiet, the
//! client can still discover fresh candidate anchor hostnames from public CT
//! data alone.
//!
//! # What it does
//!
//! 1. **Query.** Pull recent certificates from crt.sh whose subject/issuer
//!    contains any of a set of proxy-ish keyword patterns (vless, v2ray,
//!    proxy, vpn, tunnel, node, server, ...). Retries with backoff, because
//!    crt.sh is rate-limited and returns HTML 502 under load.
//! 2. **Filter.** Extract raw hostnames (CN / SAN), dedupe, drop obvious
//!    junk (example.com, wildcard `*.` roots, IP literals), and keep only
//!    plausible anchor hostnames.
//! 3. **Probe.** For each candidate, require a real TLS handshake (`https://`
//!    GET via the pooled, verified client). Only hosts that actually complete
//!    TLS are recorded as verified-live anchors — no false confidence
//!    (doctrine §6.4).
//! 4. **Persist.** Verified anchors are saved to `<profile>/ct_anchors.json`
//!    with their probe timestamp, so the daemon/refill can consult them as a
//!    bootstrap source and they are auditable.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::CFError;
use crate::multilayer::PROXY_SOCKS_PORT;
use crate::store::atomic_write;
use crate::store::profiles::{now_ts, profile_dir};

/// crt.sh endpoint (JSON output).
const CRT_SH: &str = "https://crt.sh/?q={query}&output=json";

/// Keyword patterns against which certificate hostnames are matched. A host
/// must contain at least one of these to be considered a candidate anchor.
/// Kept deliberately *specific* — generic words (node, server, edge, cdn,
/// fast, ...) match far too many innocent domains and would drown real anchors
/// in noise. Only strong proxy/VPN signals are kept.
const KEYWORD_PATTERNS: &[&str] = &[
    "vless",
    "v2ray",
    "vmess",
    "trojan",
    "shadowsocks",
    "ss2022",
    "ss-",
    "proxy",
    "vpn",
    "tunnel",
    "relay",
    "gateway",
];

/// Hostnames/suffixes that are never useful as egress anchors.
const JUNK_SUFFIXES: &[&str] = &[
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "invalid",
    "localhost",
    "internal",
    "local",
    "cloudflare.com",
    "google.com",
    "amazon.com",
    "microsoft.com",
    "facebook.com",
    "apple.com",
];

/// Cap on the number of candidates probed per pass (bounded concurrency).
const MAX_PROBE: usize = 64;

/// Cap on the number of verified anchors kept.
const MAX_ANCHORS: usize = 200;

/// Daemon self-maintenance cadence for refreshing the CT-anchor set.
/// Rate-limited so a permanently-dead network doesn't hammer crt.sh on every
/// tick (doctrine §6.5: rate-limit the expensive).
pub const ANCHOR_REFRESH_INTERVAL_SECS: i64 = 6 * 3600;

/// Anchors older than this are considered stale and are re-probed on the next
/// refresh; those that no longer complete TLS are pruned (dropped).
pub const MAX_ANCHOR_AGE_SECS: f64 = 7.0 * 24.0 * 3600.0;

/// Recommended query terms (each yields a crt.sh call).
pub const DEFAULT_QUERIES: &[&str] = &[
    "v2ray",
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "vpn",
    "proxy",
];

/// A single verified-live CT anchor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtAnchor {
    /// The hostname (no scheme, no port).
    pub host: String,
    /// Epoch (unix seconds) when this anchor was verified.
    pub verified_epoch: f64,
    /// TLS handshake round-trip time (ms).
    pub ms: u128,
    /// Which query term surfaced it.
    pub via: String,
}

/// Persisted anchor set.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CtAnchorStore {
    pub anchors: Vec<CtAnchor>,
}

/// Result of a discovery pass.
#[derive(Debug, Clone, Default)]
pub struct CtDiscoverReport {
    pub queries: usize,
    pub hosts_seen: usize,
    pub candidates: usize,
    pub verified: usize,
    pub added: usize,
    pub anchors_total: usize,
}

fn anchors_path(profile: &str) -> std::path::PathBuf {
    profile_dir(profile).join("ct_anchors.json")
}

/// Public accessor so the CLI can write the clear-command directly.
pub fn anchors_path_pub(profile: &str) -> std::path::PathBuf {
    anchors_path(profile)
}

pub fn load_anchors(profile: &str) -> CtAnchorStore {
    let p = anchors_path(profile);
    crate::store::read_or_default(&p)
}

fn save_anchors(profile: &str, store: &CtAnchorStore) -> Result<(), CFError> {
    let bytes = serde_json::to_vec_pretty(store).map_err(|e| {
        CFError::new(
            "Anchor store",
            format!("Cannot serialize ct_anchors.json: {e}"),
            "Internal error.",
        )
    })?;
    atomic_write(&anchors_path(profile), &bytes)
}

/// Build the shared, pooled HTTP client (reused across queries + probes).
pub fn build_client(use_proxy: bool) -> Result<reqwest::blocking::Client, CFError> {
    let mut builder = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(18))
        .redirect(reqwest::redirect::Policy::limited(4))
        .user_agent("dastyab-ct-anchors/0.1");
    if use_proxy {
        builder = builder.proxy(
            reqwest::Proxy::all(format!("socks5h://127.0.0.1:{PROXY_SOCKS_PORT}")).map_err(
                |e| {
                    CFError::new(
                        "Proxy",
                        format!("Cannot build SOCKS5 proxy: {e}"),
                        "Internal error.",
                    )
                },
            )?,
        );
    }
    builder.build().map_err(|e| {
        CFError::new(
            "HTTP client",
            format!("Cannot build client: {e}"),
            "Internal error.",
        )
    })
}

/// Fetch and parse candidate hostnames for a single query term.
/// Returns the set of raw hostnames, or an empty set on a non-JSON response
/// (crt.sh returns HTML 502 under load — caller should retry).
fn query_hosts(client: &reqwest::blocking::Client, term: &str) -> Vec<String> {
    let url = CRT_SH.replace("{query}", term);
    let body = match client.get(&url).send() {
        Ok(r) => match r.text() {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        },
        Err(_) => return Vec::new(),
    };
    if !body.trim_start().starts_with('[') {
        return Vec::new(); // not JSON (502/HTML)
    }
    let arr: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut hosts = BTreeSet::new();
    if let Some(items) = arr.as_array() {
        for item in items {
            if let Some(cn) = item.get("common_name").and_then(|v| v.as_str()) {
                push_clean_host(&mut hosts, cn);
            }
            if let Some(nv) = item.get("name_value").and_then(|v| v.as_str()) {
                for line in nv.split('\n') {
                    push_clean_host(&mut hosts, line);
                }
            }
        }
    }
    hosts.into_iter().collect()
}

/// Parse a raw CT hostname, normalize it, and insert it into `out` if it is
/// a plausible anchor (non-junk, has a dot, not an IP literal, not wildcard).
fn push_clean_host(out: &mut BTreeSet<String>, raw: &str) {
    let s = raw.trim();
    let s = s.strip_prefix('*').unwrap_or(s); // strip wildcard
    let s = s.trim_matches('.').trim();
    if s.is_empty() || !s.contains('.') {
        return;
    }
    if s.parse::<std::net::IpAddr>().is_ok() {
        return;
    }
    let lower = s.to_ascii_lowercase();
    if JUNK_SUFFIXES.iter().any(|j| lower.ends_with(j)) {
        return;
    }
    out.insert(lower);
}

/// Real TLS verification: a GET to `https://host/` through the pooled client.
/// Any HTTP response (even 4xx/5xx) proves a TLS handshake completed, so a
/// silent-TCP blackhole or non-TLS server is correctly rejected. Returns RTT.
fn tls_probe_ok(client: &reqwest::blocking::Client, host: &str) -> Option<u128> {
    let start = Instant::now();
    let url = format!("https://{host}/");
    let resp = client.get(&url).send().ok()?;
    // Reaching an HTTP response at all means TLS succeeded. We accept any
    // status; 200 vs 502 doesn't matter for "does it speak TLS".
    let _ = resp.status();
    Some(start.elapsed().as_millis())
}

/// Run one discovery pass for the given query terms.
pub fn discover_ct_anchors(profile: &str, use_proxy: bool, queries: &[&str]) -> CtDiscoverReport {
    let client = match build_client(use_proxy) {
        Ok(c) => c,
        Err(_) => return CtDiscoverReport::default(),
    };

    let mut all_hosts = BTreeSet::new();
    for term in queries {
        // Retry with backoff: crt.sh returns 502/HTML under load.
        let mut got = Vec::new();
        for attempt in 0..3 {
            got = query_hosts(&client, term);
            if got.is_empty() {
                std::thread::sleep(Duration::from_millis(700 * (attempt as u64 + 1)));
            } else {
                break;
            }
        }
        for h in got {
            all_hosts.insert(h);
        }
    }

    let mut report = CtDiscoverReport {
        queries: queries.len(),
        hosts_seen: all_hosts.len(),
        ..Default::default()
    };

    let candidates: Vec<String> = all_hosts
        .into_iter()
        .filter(|h| KEYWORD_PATTERNS.iter().any(|k| h.contains(k)))
        .collect();
    report.candidates = candidates.len();

    let mut store = load_anchors(profile);
    let existing: BTreeSet<String> = store.anchors.iter().map(|a| a.host.clone()).collect();

    let mut probe_list: Vec<String> = Vec::new();
    let mut seen_probe = BTreeSet::new();
    for c in candidates.iter().take(MAX_PROBE) {
        if !existing.contains(c) && seen_probe.insert(c.clone()) {
            probe_list.push(c.clone());
        }
    }

    for host in probe_list {
        if let Some(ms) = tls_probe_ok(&client, &host) {
            let via = queries
                .iter()
                .find(|q| host.contains(**q))
                .map(|s| s.to_string())
                .unwrap_or_else(|| "misc".into());
            store.anchors.push(CtAnchor {
                host: host.clone(),
                verified_epoch: now_ts(),
                ms,
                via,
            });
            report.verified += 1;
        }
    }

    let mut seen = BTreeSet::new();
    store.anchors.retain(|a| seen.insert(a.host.clone()));
    store.anchors.truncate(MAX_ANCHORS);
    report.added = report.verified;
    report.anchors_total = store.anchors.len();
    let _ = save_anchors(profile, &store);

    report
}

/// Re-probe anchors older than [`MAX_ANCHOR_AGE_SECS`] and drop those that no
/// longer complete a real TLS handshake. Keeps the out-of-band anchor set
/// pruned toward *verified-live* hosts (doctrine §6.4 — no fabricated success)
/// and bounds unbounded growth of stale entries. Returns the number dropped.
pub fn prune_stale_anchors(profile: &str, use_proxy: bool) -> usize {
    let mut store = load_anchors(profile);
    if store.anchors.is_empty() {
        return 0;
    }
    let client = match build_client(use_proxy) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    let now = now_ts();
    let mut kept: Vec<CtAnchor> = Vec::with_capacity(store.anchors.len());
    let mut dropped = 0usize;
    for mut a in store.anchors.drain(..) {
        if now - a.verified_epoch < MAX_ANCHOR_AGE_SECS {
            kept.push(a); // still fresh — keep without re-probing
            continue;
        }
        match tls_probe_ok(&client, &a.host) {
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

/// The current set of verified-live anchor hostnames (for runtime consumers
/// such as SNI-candidate seeding / anti-DPI allowlist building).
pub fn anchor_hosts(profile: &str) -> Vec<String> {
    load_anchors(profile)
        .anchors
        .into_iter()
        .map(|a| a.host)
        .collect()
}

/// A single defer refresh pass: discover new anchors, then prune stale ones.
/// Returns `(added, pruned)` so the daemon can journal both.
pub fn refresh_and_prune(profile: &str, use_proxy: bool, queries: &[&str]) -> (usize, usize) {
    let report = discover_ct_anchors(profile, use_proxy, queries);
    let pruned = prune_stale_anchors(profile, use_proxy);
    (report.added, pruned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean_into(raw: &[&str]) -> Vec<String> {
        let mut out = BTreeSet::new();
        for r in raw {
            push_clean_host(&mut out, r);
        }
        out.into_iter().collect()
    }

    #[test]
    fn clean_host_filters_junk_wildcards_and_ips() {
        let v = clean_into(&[
            "*.proxy.example.com",        // wildcard stripped
            "1.2.3.4",                    // IP literal dropped
            "mail.example.com",           // junk suffix dropped
            "v2ray-node-01.edge.xyz",     // good
            "  vless-cdn.khadijet.net  ", // trimmed + good
        ]);
        assert!(v.contains(&"v2ray-node-01.edge.xyz".to_string()));
        assert!(v.contains(&"vless-cdn.khadijet.net".to_string()));
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn clean_host_keeps_keyword_anchors() {
        for raw in [
            "v2ray.cdn.khadijet.net",
            "vless.srv.io",
            "shadowsocks-node.fast.net",
        ] {
            let v = clean_into(&[raw]);
            assert_eq!(v.len(), 1, "{raw} should be kept");
            assert!(v[0].contains('.'));
        }
    }

    #[test]
    fn candidates_filter_by_keyword_patterns() {
        let all: Vec<String> = vec![
            "v2ray-a.khadijet.net".to_string(),
            "web-static.shop".to_string(), // no strong keyword
            "vpn-gateway.org".to_string(),
            "assets.cdn.shop".to_string(), // "cdn" is not a strong keyword
        ];
        let cand: Vec<String> = all
            .into_iter()
            .filter(|h| KEYWORD_PATTERNS.iter().any(|k| h.contains(k)))
            .collect();
        assert_eq!(cand.len(), 2);
        assert!(cand.contains(&"v2ray-a.khadijet.net".to_string()));
        assert!(cand.contains(&"vpn-gateway.org".to_string()));
    }

    #[test]
    fn json_response_parsing_extracts_cn_and_sans() {
        // Simulate the crt.sh JSON shape.
        let body = r#"[
          {"common_name":"v2ray-a.khadijet.net","name_value":"v2ray-a.khadijet.net\nv2ray-b.khadijet.net"},
          {"common_name":"web-static.shop","name_value":"web-static.shop"}
        ]"#;
        let client = build_client(false).unwrap();
        // query_hosts hits the network; instead test the shared parse side by
        // replicating the loop body logic on body.
        let arr: serde_json::Value = serde_json::from_str(body).unwrap();
        let mut hosts = BTreeSet::new();
        for item in arr.as_array().unwrap() {
            if let Some(cn) = item.get("common_name").and_then(|v| v.as_str()) {
                push_clean_host(&mut hosts, cn);
            }
            if let Some(nv) = item.get("name_value").and_then(|v| v.as_str()) {
                for line in nv.split('\n') {
                    push_clean_host(&mut hosts, line);
                }
            }
        }
        let hosts: Vec<String> = hosts.into_iter().collect();
        assert!(hosts.contains(&"v2ray-a.khadijet.net".to_string()));
        assert!(hosts.contains(&"v2ray-b.khadijet.net".to_string()));
        // push_clean_host only rejects junk/wildcard/IP — a non-keyword but
        // valid hostname passes here; keyword filtering happens separately.
        assert!(hosts.contains(&"web-static.shop".to_string()));
        // drop unused client warning-free
        let _ = client;
    }

    #[test]
    fn anchor_hosts_lists_verified_hostnames() {
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(dir.path().join("mem"));
        let profile = "anchor-hosts-test".to_string();
        let now = now_ts();
        let store = CtAnchorStore {
            anchors: vec![
                CtAnchor {
                    host: "v2ray-a.khadijet.net".to_string(),
                    verified_epoch: now,
                    ms: 12,
                    via: "v2ray".to_string(),
                },
                CtAnchor {
                    host: "tunnel.example.org".to_string(),
                    verified_epoch: now,
                    ms: 30,
                    via: "tunnel".to_string(),
                },
            ],
        };
        save_anchors(&profile, &store).unwrap();
        let hosts = anchor_hosts(&profile);
        assert_eq!(hosts.len(), 2);
        assert!(hosts.contains(&"v2ray-a.khadijet.net".to_string()));
        assert!(hosts.contains(&"tunnel.example.org".to_string()));
    }

    #[test]
    fn prune_empty_store_returns_zero() {
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(dir.path().join("mem"));
        let profile = "prune-empty-test".to_string();
        // No file → empty store → no network probe, zero dropped.
        assert_eq!(prune_stale_anchors(&profile, false), 0);
    }

    #[test]
    fn prune_keeps_fresh_anchors_unprobed() {
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(dir.path().join("mem"));
        let profile = "prune-fresh-test".to_string();
        let now = now_ts();
        let store = CtAnchorStore {
            anchors: vec![CtAnchor {
                host: "fresh-vless.edge.xyz".to_string(),
                verified_epoch: now, // fresh — must not re-probe
                ms: 20,
                via: "vless".to_string(),
            }],
        };
        save_anchors(&profile, &store).unwrap();
        // Fresh anchors are kept without any network I/O; nothing dropped.
        assert_eq!(prune_stale_anchors(&profile, false), 0);
        let after = load_anchors(&profile);
        assert_eq!(after.anchors.len(), 1);
        assert_eq!(after.anchors[0].host, "fresh-vless.edge.xyz");
    }
}
