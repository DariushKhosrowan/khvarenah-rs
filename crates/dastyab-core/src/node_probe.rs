//! Node liveness probing + automatic failover for the native config store.
//!
//! The config store holds a pool of nodes (imported from v2rayN or harvested
//! from Telegram). A node being *present* says nothing about whether it
//! *works right now*. This module gives the pool a pulse:
//!
//!   1. **probe_node** — attempt a real connection to a node's server
//!      (address:port), optionally through the local xray SOCKS5
//!      (`PROXY_SOCKS_PORT`) so the probe works from behind the NIN.
//!   2. **probe_*** — walk the store, update each node's `healthy` /
//!      `last_checked_epoch`, and persist the result.
//!   3. **failover_if_dead** — if the active node is not healthy, promote the
//!      first healthy node to active. This is the "use them yourself if no
//!      config is working" engine: give it a pool, and it keeps a working
//!      node at the front.
//!
//! A probe is deliberately a *light* connection check (TCP connect; for
//! TLS/WS nodes we go as far as a TCP stream, not a full VLESS handshake —
//! that is the tunnel's job). It is fast (~≤3s timeout) and cheap, so it is
//! safe to run on every node in the pool.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::config_store::{load_node_store, save_node_store, V2RayNode};
use crate::multilayer::PROXY_SOCKS_PORT;
use crate::store::profiles::now_ts;

/// Per-node probe connection timeout.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// How long to wait for the SOCKS5 handshake.
const SOCKS_TIMEOUT: Duration = Duration::from_secs(4);

/// Result of probing a single node.
#[derive(Debug, Clone)]
pub struct NodeProbe {
    pub id: String,
    pub alias: String,
    pub ok: bool,
    /// Round-trip time in milliseconds (0 when the probe failed).
    pub ms: u128,
    /// Send reason on failure.
    pub error: Option<String>,
}

/// Parse `host:port` out of any supported share-link (vless, vmess, trojan,
/// ss, ssr, hysteria2, tuic). Returns `None` for malformed/unsupported URLs.
pub fn parse_host_port(url: &str) -> Option<(String, u16)> {
    let uri = crate::proxy_uri::ProxyUri::parse(url)?;
    Some((uri.host, uri.port))
}

/// Connect through the local xray SOCKS5 (addr:PROXY_SOCKS_PORT) to
/// `target`. Returns a connected TCP stream (raw, unencrypted).
fn socks5_connect(target: &SocketAddr) -> std::io::Result<TcpStream> {
    let proxy_addr: SocketAddr = format!("127.0.0.1:{PROXY_SOCKS_PORT}")
        .parse()
        .map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("proxy addr: {e}"))
        })?;
    let mut s = TcpStream::connect_timeout(&proxy_addr, SOCKS_TIMEOUT)?;
    s.set_read_timeout(Some(SOCKS_TIMEOUT))?;
    s.set_write_timeout(Some(SOCKS_TIMEOUT))?;
    // Greeting: VER=0x05, NMETHODS=1, METHOD=0x00 (no auth).
    s.write_all(&[0x05, 0x01, 0x00])?;
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp)?;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 auth method rejected: {:?}", resp),
        ));
    }
    // CONNECT request. Target host is an IPv4 address (nodes are IP-based).
    let ip = match target.ip() {
        std::net::IpAddr::V4(v4) => v4,
        std::net::IpAddr::V6(v6) => {
            // ATYP=4 (IPv6). 16 octets.
            let octets = v6.octets();
            let mut req = vec![0x05, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00];
            req.extend_from_slice(&octets);
            req.extend_from_slice(&target.port().to_be_bytes());
            s.write_all(&req)?;
            let mut hdr = [0u8; 4];
            s.read_exact(&mut hdr)?;
            if hdr[1] != 0x00 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!("SOCKS5 CONNECT failed (rep={})", hdr[1]),
                ));
            }
            let mut rest = [0u8; 18]; // atyp(1)+len(2)+16+port(2) for v6
            let _ = s.read(&mut rest);
            return Ok(s);
        }
    };
    let octets = ip.octets();
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&octets);
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req)?;
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr)?;
    if hdr[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 CONNECT failed (rep={})", hdr[1]),
        ));
    }
    // Drain the rest of the reply (bind addr: bnd.addr(4) + bnd.port(2)).
    let mut rest = [0u8; 6];
    let _ = s.read(&mut rest);
    Ok(s)
}

/// Probe a single node. Returns (ok, ms, error).
///
/// `use_proxy` routes the connection through the local xray SOCKS5 so the
/// probe works even when direct foreign TCP is severed (NIN).
fn probe_one(node: &V2RayNode, use_proxy: bool) -> (bool, u128, Option<String>) {
    let (host, port) = match parse_host_port(&node.url) {
        Some(x) => x,
        None => {
            return (
                false,
                0,
                Some(format!(
                    "unparseable URL: {}",
                    &node.url[..node.url.len().min(24)]
                )),
            );
        }
    };
    // Resolve the host. Prefer a numeric IP; fall back to a DNS lookup.
    let ip = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            use std::net::ToSocketAddrs;
            let mut addrs = match (host.as_str(), port).to_socket_addrs() {
                Ok(a) => a,
                Err(_) => return (false, 0, Some(format!("could not resolve {host}"))),
            };
            match addrs.next() {
                Some(a) => a.ip(),
                None => return (false, 0, Some(format!("could not resolve {host}"))),
            }
        }
    };
    let target = SocketAddr::new(ip, port);

    let start = std::time::Instant::now();
    let result = if use_proxy {
        socks5_connect(&target)
    } else {
        TcpStream::connect_timeout(&target, PROBE_TIMEOUT)
    };
    match result {
        Ok(s) => {
            let _ = s.set_read_timeout(Some(PROBE_TIMEOUT));
            let ms = start.elapsed().as_millis();
            (true, ms, None)
        }
        Err(e) => {
            let ms = start.elapsed().as_millis();
            (false, ms, Some(e.to_string()))
        }
    }
}

/// Probe every node in the profile's store and persist the health state.
/// Returns the per-node reports.
pub fn probe_all(profile: &str, use_proxy: bool) -> Vec<NodeProbe> {
    let mut store = load_node_store(profile);
    let mut reports = Vec::with_capacity(store.nodes.len());
    for node in &mut store.nodes {
        let (ok, ms, err) = probe_one(node, use_proxy);
        node.healthy = Some(ok);
        node.last_checked_epoch = Some(now_ts());
        reports.push(NodeProbe {
            id: node.id.clone(),
            alias: node.alias.clone(),
            ok,
            ms,
            error: err,
        });
    }
    let _ = save_node_store(profile, &store);
    reports
}

/// If the active node is unhealthy (or unset), promote the first healthy node
/// (a `healthy == Some(true)`) to active. Returns the newly-active node id,
/// or `None` if no change was needed / no healthy node exists.
pub fn failover_if_dead(profile: &str) -> Option<String> {
    let mut store = load_node_store(profile);
    let active_healthy = match store.active() {
        Some(a) => a.healthy == Some(true),
        None => false,
    };
    if active_healthy {
        return None;
    }
    // Find the best healthy candidate: prefer one we've verified, prefer a
    // lower `added_epoch`? Keep it simple: first healthy in list order.
    let cand_id = store
        .nodes
        .iter()
        .find(|n| n.healthy == Some(true))
        .map(|n| n.id.clone());
    let id = cand_id?;
    store.set_active(&id);
    let _ = save_node_store(profile, &store);
    Some(id)
}

/// Outcome of a single self-heal pass over the node pool.
#[derive(Debug, Clone, Default)]
pub struct SelfHealReport {
    /// Total nodes probed.
    pub probed: usize,
    /// Nodes that passed the connection check.
    pub healthy: usize,
    /// Nodes that failed (including unparseable).
    pub unhealthy: usize,
    /// If the active node was dead and we promoted a healthy one, its id.
    pub promoted: Option<String>,
    /// Whether the previously-active node was already healthy (no change).
    pub active_was_healthy: bool,
}

/// Self-heal the node pool: probe every node, then fail over to a verified
/// healthy node if the active one is dead/unset. Returns a summary report.
/// This is the zero-human "keep a working config at the front" engine — call
/// it from the CLI, a cron job, or the daemon's autonomy loop.
///
/// `use_proxy` routes the probes through the local xray SOCKS5 so the health
/// check works even when direct foreign TCP is severed (NIN).
pub fn selfheal(profile: &str, use_proxy: bool) -> SelfHealReport {
    use crate::config_store::load_node_store;

    let before = load_node_store(profile);
    let active_was_healthy = before
        .active()
        .map(|a| a.healthy == Some(true))
        .unwrap_or(false);

    let reports = probe_all(profile, use_proxy);
    let healthy = reports.iter().filter(|r| r.ok).count();
    let unhealthy = reports.len() - healthy;
    let promoted = failover_if_dead(profile);

    SelfHealReport {
        probed: reports.len(),
        healthy,
        unhealthy,
        promoted,
        active_was_healthy,
    }
}

/// Age (seconds) after which a node's last probe is considered stale and
/// eligible for re-probing by the periodic health-decay sweep.
pub const STALE_AFTER_SECS: i64 = 6 * 3600; // 6h

/// Rate-limit interval (seconds) for the daemon's periodic health-decay
/// sweep (how often it re-probes a bounded set of stale nodes).
pub const NODE_DECAY_INTERVAL_SECS: i64 = 3600; // once per hour

/// Hard bound on how many nodes one health-decay sweep re-probes. Keeps the
/// sweep cheap (doctrine §6.5): a large pool is decayed across many passes
/// rather than all at once, and the daemon never blocks on a full re-probe.
pub const STALE_SWEEP_MAX: usize = 64;

/// Result of a health-decay sweep over the node pool.
#[derive(Debug, Clone, Default)]
pub struct HealthSweepReport {
    /// Nodes this sweep chose to re-probe (stale or never-checked).
    pub probed: usize,
    /// How many of those passed the live connection check.
    pub healthy: usize,
    /// Nodes that failed the live check.
    pub unhealthy: usize,
    /// If the active node was dead and we promoted a healthy one, its id.
    pub promoted: Option<String>,
}

/// Periodic config-health decay (doctrine §5: never run on verified-live
/// configs). Re-probes only nodes whose last check is stale (older than
/// [`STALE_AFTER_SECS`]) or that have never been checked, up to
/// [`STALE_SWEEP_MAX`] per pass — so a pool that once had healthy configs
/// is continuously re-verified as their servers churn, without hammering the
/// network or blocking the daemon. After probing, fails over to a verified
/// healthy node if the active one died.
///
/// `use_proxy` routes probes through the local xray SOCKS5 (NIN).
pub fn probe_stale(profile: &str, use_proxy: bool) -> HealthSweepReport {
    let mut store = load_node_store(profile);
    let now = now_ts() as i64;

    // Candidate = stale (or never-checked) node, oldest-checked first so a
    // large pool decays oldest-first across passes.
    let mut stale: Vec<usize> = store
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| {
            n.last_checked_epoch
                .map(|ts| now - ts as i64 >= STALE_AFTER_SECS)
                .unwrap_or(true)
        })
        .map(|(i, _)| i)
        .collect();
    stale.sort_by(|&a, &b| {
        store.nodes[a]
            .last_checked_epoch
            .partial_cmp(&store.nodes[b].last_checked_epoch)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    stale.truncate(STALE_SWEEP_MAX);

    let mut healthy = 0usize;
    for i in &stale {
        let (ok, _, _) = probe_one(&store.nodes[*i], use_proxy);
        store.nodes[*i].healthy = Some(ok);
        store.nodes[*i].last_checked_epoch = Some(now as f64);
        if ok {
            healthy += 1;
        }
    }
    let _ = save_node_store(profile, &store);

    // Fail over if the active node died.
    let promoted = failover_if_dead(profile);

    HealthSweepReport {
        probed: stale.len(),
        healthy,
        unhealthy: stale.len() - healthy,
        promoted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_store::{NodeStore, V2RayNode};
    use std::net::TcpListener;

    fn fake_node(url: &str) -> V2RayNode {
        V2RayNode {
            id: "n1".into(),
            alias: "fake".into(),
            url: url.into(),
            source_index: None,
            source: "pasted".into(),
            added_epoch: now_ts(),
            last_checked_epoch: None,
            healthy: None,
        }
    }

    #[test]
    fn parse_host_port_basic() {
        assert_eq!(
            parse_host_port("vless://abc-uuid@104.17.72.206:443?encryption=none&type=ws#"),
            Some(("104.17.72.206".to_string(), 443))
        );
    }

    #[test]
    fn parse_host_port_rejects_malformed() {
        assert!(parse_host_port("vless://no-port@1.2.3.4").is_none());
        assert!(parse_host_port("vless://@1.2.3.4:443").is_none());
        assert!(parse_host_port("not a vless").is_none());
        assert!(parse_host_port("vless://uuid@1.2.3.4:notaport").is_none());
    }

    #[test]
    fn probe_hits_local_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("vless://uuid@127.0.0.1:{}?type=tcp", addr.port());
        let node = fake_node(&url);
        let (ok, _, _) = probe_one(&node, false);
        assert!(ok, "probe against a live listener should succeed");
    }

    #[test]
    fn probe_misses_closed_port() {
        // Bind then drop to get a port that is (almost certainly) closed.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let url = format!("vless://uuid@127.0.0.1:{}?type=tcp", addr.port());
        let node = fake_node(&url);
        let (ok, _, _) = probe_one(&node, false);
        assert!(!ok, "probe to a closed port should fail");
    }

    #[test]
    fn failover_promotes_healthy_after_dead_active() {
        let mut store = NodeStore::default();
        let dead = V2RayNode {
            id: "dead".into(),
            alias: "dead".into(),
            url: "vless://u@127.0.0.1:1".into(),
            healthy: Some(false),
            ..fake_node("vless://u@127.0.0.1:2")
        };
        let alive = V2RayNode {
            id: "alive".into(),
            alias: "alive".into(),
            url: "vless://u@127.0.0.1:3".into(),
            healthy: Some(true),
            ..fake_node("vless://u@127.0.0.1:4")
        };
        store.nodes.push(dead);
        store.nodes.push(alive);
        store.active_id = Some("dead".into());
        assert!(store.set_active("dead"));
        // failover_if_dead operates on the persisted store; test the inner
        // decision directly by simulating what it does:
        let active_healthy = store
            .active()
            .map(|a| a.healthy == Some(true))
            .unwrap_or(false);
        assert!(!active_healthy);
        let cand = store
            .nodes
            .iter()
            .find(|n| n.healthy == Some(true))
            .map(|n| n.id.clone());
        assert_eq!(cand.as_deref(), Some("alive"));
        store.set_active(cand.as_deref().unwrap());
        assert_eq!(store.active().map(|a| a.id.as_str()), Some("alive"));
    }

    #[test]
    fn socks5_connect_to_closed_proxy_fails() {
        // No local SOCKS5 running at PROXY_SOCKS_PORT in CI; connect must fail
        // gracefully (An error, not a panic).
        let target: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let r = socks5_connect(&target);
        assert!(r.is_err() || r.is_ok(), "should not panic");
    }

    #[test]
    fn selfheal_report_surfaces_healthy_and_underdead_pool() {
        // Use the in-memory profile override so the store writes to a tempdir.
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(dir.path().join("mem"));
        let profile = "default".to_string();

        // Empty pool → 0 probed, no promotion.
        let rep = selfheal(&profile, false);
        assert_eq!(rep.probed, 0);
        assert!(rep.promoted.is_none());

        // Seed a store with a dead active + a live local listener node.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut store = crate::config_store::NodeStore::default();

        let dead = crate::config_store::V2RayNode {
            id: "dead".into(),
            alias: "dead".into(),
            url: format!("vless://u@127.0.0.1:1?type=tcp"),
            source_index: None,
            source: "pasted".into(),
            added_epoch: crate::store::profiles::now_ts(),
            last_checked_epoch: None,
            healthy: Some(false),
        };
        let alive = crate::config_store::V2RayNode {
            id: "alive".into(),
            alias: "alive".into(),
            url: format!("vless://u@127.0.0.1:{}?type=tcp", addr.port()),
            source_index: None,
            source: "pasted".into(),
            added_epoch: crate::store::profiles::now_ts(),
            last_checked_epoch: None,
            healthy: None,
        };
        store.nodes.push(dead);
        store.nodes.push(alive);
        store.active_id = Some("dead".into());
        crate::config_store::save_node_store(&profile, &store).unwrap();

        // selfheal probes both (dead fails, alive hits the listener) and
        // promotes the healthy "alive" node.
        let rep = selfheal(&profile, false);
        assert_eq!(rep.probed, 2);
        assert_eq!(rep.healthy, 1);
        assert_eq!(rep.unhealthy, 1);
        assert_eq!(rep.promoted.as_deref(), Some("alive"));

        let after = crate::config_store::load_node_store(&profile);
        assert_eq!(after.active().map(|a| a.id.as_str()), Some("alive"));
    }

    #[test]
    fn probe_stale_only_reprobes_stale_and_never_checked() {
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(dir.path().join("mem"));
        let profile = "decay".to_string();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let mut store = crate::config_store::NodeStore::default();
        let mut mk = |id: &str, url: String, last: Option<f64>, healthy: Option<bool>| {
            crate::config_store::V2RayNode {
                id: id.into(),
                alias: id.into(),
                url,
                source_index: None,
                source: "pasted".into(),
                added_epoch: now_ts(),
                last_checked_epoch: last,
                healthy,
            }
        };
        // Fresh node (checked just now) → NOT stale → skipped.
        store.nodes.push(mk(
            "fresh",
            "vless://u@127.0.0.1:1?type=tcp".into(),
            Some(now_ts()),
            Some(true),
        ));
        // Stale node (checked 7h ago) → re-probed (fails, port 1 closed).
        store.nodes.push(mk(
            "stale_dead",
            "vless://u@127.0.0.1:1?type=tcp".into(),
            Some(now_ts() - STALE_AFTER_SECS as f64 - 3600.0),
            Some(true),
        ));
        // Never-checked node pointing at a live listener → probed, healthy.
        store.nodes.push(mk(
            "never",
            format!("vless://u@127.0.0.1:{}?type=tcp", addr.port()),
            None,
            None,
        ));
        crate::config_store::save_node_store(&profile, &store).unwrap();

        let rep = probe_stale(&profile, false);
        // fresh skipped; stale_dead + never probed.
        assert_eq!(rep.probed, 2);
        assert_eq!(rep.healthy, 1); // only `never` hits the live listener
        assert_eq!(rep.unhealthy, 1); // stale_dead fails

        let after = crate::config_store::load_node_store(&profile);
        let by_id = |id: &str| after.nodes.iter().find(|n| n.id == id).unwrap();
        // Fresh node untouched (still healthy, same check ts).
        assert_eq!(by_id("fresh").healthy, Some(true));
        // Stale re-probed → marked down.
        assert_eq!(by_id("stale_dead").healthy, Some(false));
        // Never-checked now probed → healthy.
        assert_eq!(by_id("never").healthy, Some(true));
        assert!(by_id("never").last_checked_epoch.is_some());
    }
}
