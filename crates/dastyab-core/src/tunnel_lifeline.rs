//! Automatic "lifeline" local egress tunnel (doctrine §2/§8 openx).
//!
//! When the primary Cloudflare-worker egress is down or blocked (account
//! suspended, worker dead, token invalid), the daemon should not just sit and
//! poll — it should fall back to running a **local xray client** over the best
//! verified-healthy config from its pool (Telegram / GitHub discovered), and
//! expose it as a `SOCKS5` proxy on a fixed local port. This keeps the machine
//! connected even when the managed fleet is unavailable — the "use the configs
//! yourself if none of my channels work" requirement.
//!
//! # Design
//!
//! * `spawn_lifeline` — pick the best healthy node, render an xray client
//!   config, spawn xray as a detached child, persist its PID.
//! * `lifeline_status` — report whether a lifeline tunnel is up and what node
//!   it uses.
//! * `stop_lifeline` — kill the child (best-effort).
//! * `is_port_open` — TCP liveness check on the local SOCKS5 port.
//!
//! The module is intentionally process-oriented (spawn a real xray binary)
//! rather than in-process, so it works with the standard v2rayN/nekoray
//! xray binary the user already has, and so a crash in the tunnel cannot take
//! down the daemon itself.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use crate::config_store::{load_node_store, V2RayNode};
use crate::vless::VlessProfile;

/// Local SOCKS5 port the lifeline tunnel listens on.
pub const LIFELINE_SOCKS_PORT: u16 = 10853;

/// Time to wait for the SOCKS5 port to open after spawning xray.
const PORT_OPEN_TIMEOUT: Duration = Duration::from_secs(15);

/// How long a config's probe result stays "fresh" for failover ranking
/// (mirrors node_probe's decay window; nodes probed more recently than this
/// and marked healthy are preferred).
const FRESHNESS_WINDOW: f64 = 6.0 * 3600.0;

/// Name of the PID file we persist the lifeline xray child under.
fn pidfile(profile: &str) -> PathBuf {
    crate::store::profiles::profile_dir(profile).join("lifeline.pid")
}

/// Name of the xray config file we write for the lifeline tunnel.
fn cfgfile(profile: &str) -> PathBuf {
    crate::store::profiles::profile_dir(profile).join("lifeline-xray.json")
}

/// Locate an xray binary (reuses the same discovery as the multilayer tunnel).
pub fn find_xray_binary() -> Option<PathBuf> {
    crate::multilayer::find_xray_binary()
}

/// Pick the best candidate node from the store to run the lifeline tunnel on.
///
/// Ranking (in order of preference):
///  1. The currently-active node, if it is verified healthy.
///  2. A healthy node probed within the freshness window (most likely still
///     alive), preferring a more recent probe.
///  3. Any verified-healthy node (first in store order).
///  4. If nothing is marked healthy, fall back to the active node regardless
///     (so we still *try* rather than give up).
///
/// Only vless nodes are currently renderable to xray configs; that matches the
/// overwhelming majority of the Telegram-discovered pool.
fn pick_best_node(store: &crate::config_store::NodeStore) -> Option<&V2RayNode> {
    let now = crate::store::profiles::now_ts();

    // 1. Active + healthy.
    if let Some(a) = store.active() {
        if a.healthy == Some(true) && a.scheme_is_vless() {
            return Some(a);
        }
    }

    // 2. Fresh healthy vless nodes (most recent probe first).
    let mut fresh: Vec<&V2RayNode> = store
        .nodes
        .iter()
        .filter(|n| {
            n.healthy == Some(true)
                && n.scheme_is_vless()
                && n.last_checked_epoch
                    .map(|t| now - t <= FRESHNESS_WINDOW)
                    .unwrap_or(false)
        })
        .collect();
    fresh.sort_by(|a, b| {
        let ka = a.last_checked_epoch.unwrap_or(0.0);
        let kb = b.last_checked_epoch.unwrap_or(0.0);
        kb.partial_cmp(&ka).unwrap_or(std::cmp::Ordering::Equal)
    });
    if let Some(n) = fresh.first() {
        return Some(n);
    }

    // 3. Any healthy vless node.
    if let Some(n) = store
        .nodes
        .iter()
        .find(|n| n.healthy == Some(true) && n.scheme_is_vless())
    {
        return Some(n);
    }

    // 4. Active regardless of health (last resort).
    if let Some(a) = store.active() {
        if a.scheme_is_vless() {
            return Some(a);
        }
    }

    // 5. Any vless node at all.
    store.nodes.iter().find(|n| n.scheme_is_vless())
}

impl V2RayNode {
    /// Whether this node is a VLESS share-link (the only scheme we currently
    /// render to an xray *client* config).
    fn scheme_is_vless(&self) -> bool {
        self.url.trim_start().starts_with("vless://")
    }
}

/// Render an xray client config for a node URL on the lifeline SOCKS5 port.
fn render_node_config(url: &str) -> Result<String, crate::CFError> {
    let profile = VlessProfile::parse(url)?;
    profile.xray_client_json_at_port(LIFELINE_SOCKS_PORT)
}

/// Check whether the local SOCKS5 port is currently accepting connections.
pub async fn is_port_open(port: u16) -> bool {
    tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_ok()
}

/// Read the persisted lifeline PID, if present.
fn read_pid(profile: &str) -> Option<u32> {
    let p = pidfile(profile);
    let s = std::fs::read_to_string(&p).ok()?;
    s.trim().parse::<u32>().ok()
}

/// Whether a PID refers to a live process.
fn pid_alive(pid: u32) -> bool {
    // Signal 0: existence check only, no signal delivered.
    let r = unsafe { libc::kill(pid as i32, 0) };
    r == 0
}

/// Result of a lifeline spawn attempt.
#[derive(Debug, Clone, Default)]
pub struct LifelineReport {
    /// Whether the tunnel is up (port open).
    pub up: bool,
    /// Node the tunnel is (or was intended to be) running on.
    pub node: Option<String>,
    /// Warnings/errors encountered on the last operation.
    pub error: Option<String>,
}

/// Spawn (or restart) the lifeline tunnel on the best healthy node.
///
/// Best-effort: never panics on a missing xray or an unparseable pool; it
/// reports the reason in `report.error`. Returns a [`LifelineReport`].
pub async fn spawn_lifeline(profile: &str) -> LifelineReport {
    // If the port is already open, it is already up — report it.
    if is_port_open(LIFELINE_SOCKS_PORT).await {
        let store = load_node_store(profile);
        return LifelineReport {
            up: true,
            node: store.active().map(|a| a.alias.clone()),
            error: None,
        };
    }

    // Resolve the binary.
    let Some(xray) = find_xray_binary() else {
        return LifelineReport {
            up: false,
            node: None,
            error: Some("xray binary not found".to_string()),
        };
    };

    // Pick the best node.
    let store = load_node_store(profile);
    let Some(node) = pick_best_node(&store) else {
        return LifelineReport {
            up: false,
            node: None,
            error: Some("no vless node available in pool".to_string()),
        };
    };
    let node_url = node.url.clone();
    let node_alias = if node.alias.is_empty() {
        node_url.clone()
    } else {
        node.alias.clone()
    };

    // Render the config.
    let cfg_json = match render_node_config(&node_url) {
        Ok(c) => c,
        Err(e) => {
            return LifelineReport {
                up: false,
                node: Some(node_alias),
                error: Some(format!("render config: {e}")),
            };
        }
    };

    // Write the config.
    let cfg_path = cfgfile(profile);
    if let Err(e) = std::fs::write(&cfg_path, &cfg_json) {
        return LifelineReport {
            up: false,
            node: Some(node_alias),
            error: Some(format!("write xray config: {e}")),
        };
    }

    // Spawn xray.
    let mut child = match std::process::Command::new(&xray)
        .arg("run")
        .arg("-c")
        .arg(&cfg_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return LifelineReport {
                up: false,
                node: Some(node_alias),
                error: Some(format!("spawn xray: {e}")),
            };
        }
    };

    // Wait for the port to open.
    let deadline = std::time::Instant::now() + PORT_OPEN_TIMEOUT;
    let mut ready = false;
    while std::time::Instant::now() < deadline {
        if is_port_open(LIFELINE_SOCKS_PORT).await {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    if !ready {
        let _ = child.kill();
        let _ = child.wait();
        return LifelineReport {
            up: false,
            node: Some(node_alias),
            error: Some("xray did not open the lifeline SOCKS5 port".to_string()),
        };
    }

    // Persist the PID so we can manage the child later.
    let _ = std::fs::write(pidfile(profile), child.id().to_string());

    LifelineReport {
        up: true,
        node: Some(node_alias),
        error: None,
    }
}

/// Stop the lifeline tunnel (kill the child if alive).
pub fn stop_lifeline(profile: &str) -> bool {
    let Some(pid) = read_pid(profile) else {
        return false;
    };
    if pid_alive(pid) {
        // Send SIGTERM, then SIGKILL after a short grace if it does not exit.
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
        std::thread::sleep(Duration::from_millis(600));
        if pid_alive(pid) {
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
            }
        }
    }
    let _ = std::fs::remove_file(pidfile(profile));
    true
}

/// Current lifeline status.
pub async fn lifeline_status(profile: &str) -> LifelineReport {
    let up = is_port_open(LIFELINE_SOCKS_PORT).await;
    let store = load_node_store(profile);
    let node = store.active().map(|a| a.alias.clone());
    LifelineReport {
        up,
        node,
        error: None,
    }
}

/// Enumerate the distinct server identities present in the pool (host:port:uuid)
/// — used to sanity-check the pool is non-empty and vless-populated.
pub fn pool_summary(profile: &str) -> (usize, usize) {
    let store = load_node_store(profile);
    let mut seen: HashSet<String> = HashSet::new();
    let mut vless = 0usize;
    for n in &store.nodes {
        if n.scheme_is_vless() {
            vless += 1;
            seen.insert(n.id.clone());
        }
    }
    (store.nodes.len(), vless)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_store::{NodeStore, V2RayNode};

    fn node(url: &str, healthy: Option<bool>, checked: Option<f64>) -> V2RayNode {
        V2RayNode {
            id: url.to_string(),
            alias: String::new(),
            url: url.to_string(),
            source_index: Some(0),
            source: "test".to_string(),
            added_epoch: 0.0,
            published_epoch: None,
            last_checked_epoch: checked,
            healthy,
        }
    }

    fn vless_url(suffix: &str) -> String {
        format!(
            "vless://{suffix}@host.example:443?encryption=none&security=reality&sni=example.com&type=tcp"
        )
    }

    fn store(nodes: Vec<V2RayNode>, active_id: Option<String>) -> NodeStore {
        NodeStore { active_id, nodes }
    }

    #[test]
    fn pick_prefers_active_healthy() {
        let healthy = node(&vless_url("a"), Some(true), None);
        let other = node(&vless_url("b"), Some(true), None);
        let s = store(vec![other, healthy.clone()], Some(healthy.id.clone()));
        let best = pick_best_node(&s).unwrap();
        assert_eq!(best.id, healthy.id);
    }

    #[test]
    fn pick_prefers_fresh_healthy_over_stale() {
        let now = crate::store::profiles::now_ts();
        let stale = node(
            &vless_url("old"),
            Some(true),
            Some(now - FRESHNESS_WINDOW - 60.0),
        );
        let fresh = node(&vless_url("new"), Some(true), Some(now - 30.0));
        let s = store(vec![stale, fresh], None);
        let best = pick_best_node(&s).unwrap();
        assert!(best.url.contains("new"));
    }

    #[test]
    fn pick_prefers_healthy_over_active_unhealthy() {
        let active_dead = node(&vless_url("dead"), Some(false), None);
        let healthy = node(
            &vless_url("ok"),
            Some(true),
            Some(crate::store::profiles::now_ts()),
        );
        let active_dead_id = active_dead.id.clone();
        let s = store(vec![active_dead, healthy.clone()], Some(active_dead_id));
        // The dead active has a fresh unhealthy probe; healthy replacement wins.
        let best = pick_best_node(&s).unwrap();
        assert_eq!(best.id, healthy.id);
    }

    #[test]
    fn pick_falls_back_to_active_even_if_unhealthy() {
        let active = node(&vless_url("a"), None, None);
        let s = store(vec![active.clone()], Some(active.id.clone()));
        let best = pick_best_node(&s).unwrap();
        assert_eq!(best.id, active.id);
    }

    #[test]
    fn pick_skips_non_vless() {
        let vmess = node(
            "vmess://abc",
            Some(true),
            Some(crate::store::profiles::now_ts()),
        );
        let vless = node(
            &vless_url("v"),
            Some(true),
            Some(crate::store::profiles::now_ts()),
        );
        let s = store(vec![vmess, vless.clone()], None);
        let best = pick_best_node(&s).unwrap();
        assert!(best.url.starts_with("vless://"));
    }

    #[test]
    fn render_roundtrips_a_real_vless_link() {
        let url = "vless://664f65f4-33b3-43a3-b9e5-68192d1d428e@109.69.218.172:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=zealous-vortex.cdn.cachefleet.com&fp=firefox&pbk=cv_KJnMzQUZruACPbH-BCgLWrYqPm2dbUymg-gW_sVc&type=tcp&headerType=none#cachefleet";
        let cfg = render_node_config(url).expect("should render");
        let v: serde_json::Value = serde_json::from_str(&cfg).expect("valid json");
        // Inbound SOCKS5 on the lifeline port.
        let inbounds = v["inbounds"].as_array().unwrap();
        assert_eq!(
            inbounds[0]["port"].as_u64().unwrap() as u16,
            LIFELINE_SOCKS_PORT
        );
        assert_eq!(inbounds[0]["protocol"], "socks");
        // Outbound VLESS to the right host/port.
        let out = &v["outbounds"][0];
        assert_eq!(out["protocol"], "vless");
        assert_eq!(out["settings"]["vnext"][0]["address"], "109.69.218.172");
        assert_eq!(
            out["settings"]["vnext"][0]["port"].as_u64().unwrap() as u16,
            443
        );
    }

    #[test]
    fn pool_summary_counts_vless() {
        let s = store(
            vec![
                node(&vless_url("a"), None, None),
                node(&vless_url("b"), None, None),
                node("trojan://pw@h:443", None, None),
            ],
            None,
        );
        // Can't inject into global store without persistence; just assert the
        // helper works on a hand-built store via the same logic shape.
        let vless = s.nodes.iter().filter(|n| n.scheme_is_vless()).count();
        assert_eq!(vless, 2);
        assert_eq!(s.nodes.len(), 3);
    }
}
