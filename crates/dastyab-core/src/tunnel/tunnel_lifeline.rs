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

use crate::artifact::config_store::{load_node_store, V2RayNode};
use crate::artifact::vless::VlessProfile;

/// Local SOCKS5 port the lifeline tunnel listens on.
pub const LIFELINE_SOCKS_PORT: u16 = 10853;

/// Time to wait for the SOCKS5 port to open after spawning xray.
const PORT_OPEN_TIMEOUT: Duration = Duration::from_secs(15);

/// How long a config's probe result stays "fresh" for failover ranking
/// (mirrors node_probe's decay window; nodes probed more recently than this
/// and marked healthy are preferred).
const FRESHNESS_WINDOW: f64 = 6.0 * 3600.0;

/// Max number of candidate nodes tried per single spawn attempt. Retrying
/// every node in a large pool unboundedly would take minutes; a bounded budget
/// (doctrine §6.5) keeps the daemon responsive while still trying the best few
/// before giving up for this round.
const MAX_CANDIDATES_TRY: usize = 8;

/// Name of the PID file we persist the lifeline xray child under.
fn pidfile(profile: &str) -> PathBuf {
    crate::store::profiles::profile_dir(profile).join("lifeline.pid")
}

/// A persisted per-profile record of node URLs that failed real egress, so we
/// don't waste spawn budget re-testing them too often. Each entry carries the
/// eval when it was last proven dead; entries older than the regeneration
/// window are retried (a node / be revived or fixed upstream). Bounded; the
/// oldest entries are pruned as new ones arrive.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct BadLifelineStore {
    /// url -> unix epoch the node was last seen failing egress.
    urls: std::collections::HashMap<String, f64>,
}

/// Regeneration window: a dead node is retried after this many seconds.
const BAD_LIFELINE_REGEN: f64 = 6.0 * 3600.0;
/// Maximum entries kept per profile.
const BAD_LIFELINE_CAP: usize = 400;

fn bad_lifeline_path(profile: &str) -> PathBuf {
    crate::store::profiles::profile_dir(profile).join("lifeline_bad.json")
}

fn load_bad_lifeline(profile: &str) -> BadLifelineStore {
    crate::store::read_or_default::<BadLifelineStore>(&bad_lifeline_path(profile))
}

fn is_bad_lifeline(store: &BadLifelineStore, url: &str) -> bool {
    match store.urls.get(url) {
        Some(&at) => {
            let now = crate::store::profiles::now_ts();
            now - at < BAD_LIFELINE_REGEN
        }
        None => false,
    }
}

fn remember_bad_lifeline(profile: &str, url: &str) {
    let mut s = load_bad_lifeline(profile);
    s.urls
        .insert(url.to_string(), crate::store::profiles::now_ts());
    while s.urls.len() > BAD_LIFELINE_CAP {
        // Prune the oldest entry (O(n) keeps it simple and deterministic).
        if let Some(oldest) = s.urls.iter().min_by(|a, b| a.1.total_cmp(b.1)) {
            let oldest_url = oldest.0.clone();
            s.urls.remove(&oldest_url);
        }
    }
    let _ = crate::store::atomic_write(
        &bad_lifeline_path(profile),
        serde_json::to_vec(&s).unwrap_or_default().as_slice(),
    );
}

/// Name of the xray config file we write for the lifeline tunnel.
fn cfgfile(profile: &str) -> PathBuf {
    crate::store::profiles::profile_dir(profile).join("lifeline-xray.json")
}

/// Locate an xray binary (reuses the same discovery as the multilayer tunnel).
pub fn find_xray_binary() -> Option<PathBuf> {
    crate::tunnel::multilayer::find_xray_binary()
}

/// Rank all candidate vless nodes for the lifeline tunnel, best first.
///
/// Ranking (in order of preference):
///  1. The currently-active node, if it is verified healthy.
///  2. Healthy nodes probed within the freshness window (most recent probe
///     first).
///  3. Any verified-healthy node (store order).
///  4. The active node regardless of health (last resort — still try).
///  5. Any vless node at all.
///
/// The callers may keep the whole ranked list and fall through candidate after
/// candidate (doctrine §5: never stop trying), rather than only ever trying the
/// single best.
fn pick_candidates(store: &crate::artifact::config_store::NodeStore) -> Vec<&V2RayNode> {
    let now = crate::store::profiles::now_ts();
    let mut out: Vec<&V2RayNode> = Vec::new();

    fn push_unique<'a>(out: &mut Vec<&'a V2RayNode>, n: &'a V2RayNode) {
        if !out.iter().any(|o| std::ptr::eq(*o, n)) {
            out.push(n);
        }
    }

    // 1. Active + healthy.
    if let Some(a) = store.active() {
        if a.healthy == Some(true) {
            push_unique(&mut out, a);
        }
    }

    // 2. Fresh healthy nodes (most recent probe first).
    let mut fresh: Vec<&V2RayNode> = store
        .nodes
        .iter()
        .filter(|n| {
            n.healthy == Some(true)
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
    for n in fresh {
        push_unique(&mut out, n);
    }

    // 3. Any healthy node.
    for n in store.nodes.iter().filter(|n| n.healthy == Some(true)) {
        push_unique(&mut out, n);
    }

    // 4. Active regardless of health.
    if let Some(a) = store.active() {
        push_unique(&mut out, a);
    }

    // 5. Any other node.
    for n in store.nodes.iter() {
        push_unique(&mut out, n);
    }

    out
}

impl V2RayNode {
    /// Whether this node is a VLESS share-link (the only scheme we currently
    /// render to an xray *client* config).
    fn scheme_is_vless(&self) -> bool {
        self.url.trim_start().starts_with("vless://")
    }
}

/// Render an xray client config for a node URL on the lifeline SOCKS5 port.
pub fn render_node_config(url: &str) -> Result<String, crate::CFError> {
    let profile = VlessProfile::parse(url)?;
    profile.xray_client_json_at_port(LIFELINE_SOCKS_PORT)
}

/// Check whether the local SOCKS5 port is currently accepting connections.
pub async fn is_port_open(port: u16) -> bool {
    tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_ok()
}

/// Endpoint used to verify real end-to-end egress through the lifeline
/// tunnel (doctrine §6.4: no fabricated success). A 2xx/3xx/4xx HTTP response
/// proves the chain reaches the public internet; a connection/TLS failure
/// proves it does not.
const EGRESS_VERIFY_URL: &str = "https://www.gstatic.com/generate_204";

/// Probe an HTTP endpoint through the lifeline SOCKS5 proxy to confirm real
/// egress. Returns true only when the request completes (any HTTP status) —
/// meaning an actual outside-server answered — and false on any transport/TLS
/// error. This is the decisive check that separates a port that merely accepts
/// TCP connects from a tunnel that can actually carry traffic.
async fn egress_ok(port: u16) -> bool {
    let proxy = match reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}")) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let client = match reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    client.get(EGRESS_VERIFY_URL).send().await.is_ok()
}

/// Read the persisted lifeline PID, if present.
fn read_pid(profile: &str) -> Option<u32> {
    let p = pidfile(profile);
    let s = std::fs::read_to_string(&p).ok()?;
    s.trim().parse::<u32>().ok()
}

/// Whether a PID refers to a live process.
///
/// On Unix this is `kill(pid, 0)` — an existence check that delivers nothing.
/// Elsewhere the process model has no equivalent, so a recorded pid is assumed
/// stale rather than claimed live.
fn pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
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

    // Rank all candidates and try them in order until one proves real egress
    // (doctrine §5: never stop trying; §6.4: no fabricated success). A node
    // whose xray starts but can't actually carry traffic is skipped, not
    // reported as up.
    let store = load_node_store(profile);
    let bad = load_bad_lifeline(profile);
    let candidates = pick_candidates(&store)
        .into_iter()
        // Skip nodes we've already proven dead for lifeline egress, BEFORE the
        // budget take, so the budget only counts genuinely-tried candidates.
        .filter(|n| !is_bad_lifeline(&bad, &n.url))
        .take(MAX_CANDIDATES_TRY)
        .collect::<Vec<_>>();
    let mut last_error: Option<String> = None;
    let mut tried: Vec<String> = Vec::new();

    for node in candidates {
        let node_url = node.url.clone();
        let node_alias = if node.alias.is_empty() {
            node_url.clone()
        } else {
            node.alias.clone()
        };
        tried.push(node_alias.clone());

        // Render the config (any scheme — vless/vmess/trojan/ss/hysteria2/tuic).
        let cfg_json = match render_any_xray_cfg(&node_url, LIFELINE_SOCKS_PORT) {
            Ok(c) => c,
            Err(e) => {
                last_error = Some(format!("node {node_alias} render config: {e}"));
                continue;
            }
        };

        // Write the config.
        let cfg_path = cfgfile(profile);
        if let Err(e) = std::fs::write(&cfg_path, &cfg_json) {
            last_error = Some(format!("node {node_alias} write xray config: {e}"));
            continue;
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
                last_error = Some(format!("node {node_alias} spawn xray: {e}"));
                continue;
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
            last_error = Some(format!(
                "node {node_alias}: xray did not open the lifeline SOCKS5 port"
            ));
            continue;
        }

        // The decisive check: real end-to-end egress through the tunnel.
        if egress_ok(LIFELINE_SOCKS_PORT).await {
            // Persist the child PID and set the node sticky-active so future
            // spawn attempts prefer the known-good node first. Also record the
            // verified-healthy verdict in the pool (doctrine §6.4): the only
            // health signal that guarantees real traffic is egress itself.
            let _ = std::fs::write(pidfile(profile), child.id().to_string());
            let mut store2 = load_node_store(profile);
            store2.set_active(&node.id);
            store2.set_health(&node.id, true);
            let _ = crate::artifact::config_store::save_node_store(profile, &store2);
            return LifelineReport {
                up: true,
                node: Some(node_alias),
                error: None,
            };
        }

        // Port open but no egress → dead/mismatched server (e.g. a REALITY
        // node presenting a real certificate). Kill it, blacklist it so we
        // don't re-test this cycle, and try the next candidate.
        remember_bad_lifeline(profile, &node_url);
        // Record the confirmed-dead verdict in the pool so ranking/probing
        // stop treating it as a candidate (doctrine §6.4).
        let mut store2 = load_node_store(profile);
        store2.set_health(&node.id, false);
        let _ = crate::artifact::config_store::save_node_store(profile, &store2);
        let _ = child.kill();
        let _ = child.wait();
        last_error = Some(format!(
            "node {node_alias}: xray opened the port but egress verify failed (dead or mismatched server)"
        ));
    }

    LifelineReport {
        up: false,
        node: None,
        error: Some(match last_error {
            Some(e) => {
                if tried.len() > 1 {
                    format!("all {} candidate(s) failed; last: {e}", tried.len())
                } else {
                    e
                }
            }
            None => "no node available in pool".to_string(),
        }),
    }
}

/// Results of a single deep egress-verified probe.
#[derive(Debug, Clone, Default)]
pub struct EgressVerifyReport {
    /// Whether the node carried real end-to-end egress.
    pub ok: bool,
    /// Alias of the verified node (empty on failure).
    pub alias: String,
    /// Human-readable error/warning (None on success).
    pub error: Option<String>,
}

/// Render an xray client config for **any** supported share-link scheme
/// (vless/vmess/trojan/ss/hysteria2/tuic) with a dedicated local SOCKS5
/// inbound. This lets `deep_verify_egress` test the real egress of the whole
/// pool, not only VLESS nodes (doctrine §5: use *whatever* config works).
pub fn render_any_xray_cfg(url: &str, socks_port: u16) -> Result<String, String> {
    // VLESS has a first-class model.
    if url.starts_with("vless://") {
        return VlessProfile::parse(url)
            .and_then(|p| p.xray_client_json_at_port(socks_port))
            .map_err(|e| format!("render vless: {e}"));
    }
    let uri = crate::net::proxy_uri::ProxyUri::parse(url)
        .ok_or_else(|| "unparsable share-link".to_string())?;
    let cfg = match uri.scheme.as_str() {
        "vmess" => render_vmess_cfg(&uri, socks_port)?,
        "trojan" => render_trojan_cfg(&uri, socks_port)?,
        "ss" => render_ss_cfg(&uri, socks_port)?,
        "hysteria2" => render_hysteria2_cfg(&uri, socks_port)?,
        "tuic" => render_tuic_cfg(&uri, socks_port)?,
        other => return Err(format!("scheme '{other}' not deep-verifiable")),
    };
    serde_json::to_string_pretty(&cfg).map_err(|e| format!("serialize: {e}"))
}

/// Parse raw `?a=b&c=d` params from an arbitrary share-link (any scheme).
fn raw_query_params(url: &str) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let body = url.split('#').next().unwrap_or(url);
    let Some(q) = body.split('?').nth(1) else {
        return out;
    };
    for pair in q.split('&') {
        let mut it = pair.splitn(2, '=');
        if let (Some(k), Some(v)) = (it.next(), it.next()) {
            if !k.is_empty() {
                out.insert(
                    crate::artifact::vless::decode_query(k),
                    crate::artifact::vless::decode_query(v),
                );
            }
        }
    }
    out
}

/// Shared `streamSettings` from `network`/`security`/query params.
fn stream_block(
    network: &str,
    security: &str,
    q: &std::collections::HashMap<String, String>,
    host_default: &str,
    sni_default: &str,
) -> serde_json::Value {
    let host = q
        .get("host")
        .cloned()
        .unwrap_or_else(|| host_default.to_string());
    let sni = q
        .get("sni")
        .cloned()
        .unwrap_or_else(|| sni_default.to_string());
    let network = if network.is_empty() { "tcp" } else { network };
    let security = if security.is_empty() {
        "none"
    } else {
        security
    };
    let tls_settings = if security == "tls" {
        serde_json::json!({"serverName": sni, "fingerprint": "chrome"})
    } else {
        serde_json::Value::Null
    };
    let ws = if network == "ws" {
        serde_json::json!({"path": q.get("path").cloned().unwrap_or_default(), "headers": {"Host": host}})
    } else {
        serde_json::Value::Null
    };
    let grpc = if network == "grpc" {
        serde_json::json!({"serviceName": q.get("serviceName").cloned().unwrap_or_default()})
    } else {
        serde_json::Value::Null
    };
    let tcp = if network == "tcp" {
        serde_json::json!({"header": {"type": q.get("type").cloned().unwrap_or_else(|| "none".into())}})
    } else {
        serde_json::Value::Null
    };
    serde_json::json!({
        "network": network,
        "security": security,
        "tlsSettings": tls_settings,
        "wsSettings": ws,
        "grpcSettings": grpc,
        "tcpSettings": tcp,
    })
}

/// `socks-in` inbound shared by every rendered config.
fn socks_inbound(socks_port: u16) -> serde_json::Value {
    serde_json::json!({
        "tag": "socks-in", "listen": "127.0.0.1", "port": socks_port,
        "protocol": "socks", "settings": {"auth": "noauth", "udp": true},
    })
}

fn render_vmess_cfg(
    uri: &crate::net::proxy_uri::ProxyUri,
    socks_port: u16,
) -> Result<serde_json::Value, String> {
    // Decode the embedded JSON for transport/tls details.
    let encoded = uri.raw.split("vmess://").nth(1).unwrap_or("");
    let mut net = String::new();
    let mut security = String::new();
    let mut aid = "0".to_string();
    let mut q = std::collections::HashMap::new();
    if let Some(decoded) = crate::net::proxy_uri::b64_decode_for(encoded) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&decoded) {
            net = v
                .get("net")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            security = v
                .get("tls")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if let Some(a) = v.get("aid").and_then(|x| x.as_str()) {
                aid = a.to_string();
            }
            if let Some(h) = v.get("host").and_then(|x| x.as_str()) {
                q.insert("host".into(), h.to_string());
            }
            if let Some(p) = v.get("path").and_then(|x| x.as_str()) {
                q.insert("path".into(), p.to_string());
            }
            if let Some(t) = v.get("type").and_then(|x| x.as_str()) {
                q.insert("type".into(), t.to_string());
            }
        }
    }
    let outbound = serde_json::json!({
        "protocol": "vmess",
        "settings": {
            "vnext": [{
                "address": uri.host, "port": uri.port,
                "users": [{"id": uri.id, "alterId": aid, "security": "auto"}],
            }]
        },
        "streamSettings": stream_block(&net, &security, &q, &uri.host, &uri.host),
    });
    Ok(serde_json::json!({
        "log": {"loglevel": "warning"},
        "inbounds": [socks_inbound(socks_port)],
        "outbounds": [outbound],
    }))
}

fn render_trojan_cfg(
    uri: &crate::net::proxy_uri::ProxyUri,
    socks_port: u16,
) -> Result<serde_json::Value, String> {
    let q = raw_query_params(&uri.raw);
    let security = q.get("security").cloned().unwrap_or_else(|| "tls".into());
    let net = q.get("type").cloned().unwrap_or_else(|| "tcp".into());
    let outbound = serde_json::json!({
        "protocol": "trojan",
        "settings": {
            "servers": [{"address": uri.host, "port": uri.port, "password": uri.id}],
        },
        "streamSettings": stream_block(&net, &security, &q, &uri.host, &uri.host),
    });
    Ok(serde_json::json!({
        "log": {"loglevel": "warning"},
        "inbounds": [socks_inbound(socks_port)],
        "outbounds": [outbound],
    }))
}

fn render_ss_cfg(
    uri: &crate::net::proxy_uri::ProxyUri,
    socks_port: u16,
) -> Result<serde_json::Value, String> {
    // id is `method:password`.
    let (method, password) = match uri.id.split_once(':') {
        Some((m, p)) => (m.to_string(), p.to_string()),
        None => return Err(format!("ss link lacks method:password: {}", uri.raw)),
    };
    let q = raw_query_params(&uri.raw);
    let net = q.get("type").cloned().unwrap_or_else(|| "tcp".into());
    let security = q.get("security").cloned().unwrap_or_else(|| "none".into());
    let outbound = serde_json::json!({
        "protocol": "shadowsocks",
        "settings": {
            "servers": [{"address": uri.host, "port": uri.port, "method": method, "password": password}],
        },
        "streamSettings": stream_block(&net, &security, &q, &uri.host, &uri.host),
    });
    Ok(serde_json::json!({
        "log": {"loglevel": "warning"},
        "inbounds": [socks_inbound(socks_port)],
        "outbounds": [outbound],
    }))
}

fn render_hysteria2_cfg(
    uri: &crate::net::proxy_uri::ProxyUri,
    socks_port: u16,
) -> Result<serde_json::Value, String> {
    let q = raw_query_params(&uri.raw);
    let sni = q.get("sni").cloned().unwrap_or_else(|| uri.host.clone());
    let outbound = serde_json::json!({
        "protocol": "hysteria2",
        "settings": {
            "servers": [{
                "address": uri.host, "port": uri.port, "password": uri.id,
            }],
        },
        "streamSettings": {
            "network": "tcp", "security": "tls",
            "tlsSettings": {"serverName": sni, "allowInsecure": true},
        },
    });
    Ok(serde_json::json!({
        "log": {"loglevel": "warning"},
        "inbounds": [socks_inbound(socks_port)],
        "outbounds": [outbound],
    }))
}

fn render_tuic_cfg(
    uri: &crate::net::proxy_uri::ProxyUri,
    socks_port: u16,
) -> Result<serde_json::Value, String> {
    let q = raw_query_params(&uri.raw);
    let sni = q.get("sni").cloned().unwrap_or_else(|| uri.host.clone());
    let outbound = serde_json::json!({
        "protocol": "tuic",
        "settings": {
            "servers": [{
                "address": uri.host, "port": uri.port,
                "uuid": uri.id, "password": q.get("password").cloned().unwrap_or_default(),
                "congestionControl": "bbr",
            }],
        },
        "streamSettings": {
            "network": "tcp", "security": "tls",
            "tlsSettings": {"serverName": sni, "allowInsecure": true},
        },
    });
    Ok(serde_json::json!({
        "log": {"loglevel": "warning"},
        "inbounds": [socks_inbound(socks_port)],
        "outbounds": [outbound],
    }))
}

/// Deeply verify that a node carries **real egress** by spawning a fresh xray
/// client for it on a *dedicated* local SOCKS5 port (never the live lifeline
/// port 10853), confirming end-to-end traffic (doctrine §6.4 — no fabricated
/// success), then tearing the temporary xray down.
///
/// This closes the gap between the shallow TLS probe (`node_probe::probe_one`,
/// which only proves a server speaks TLS) and the decisive check that a node
/// actually proxies traffic. The daemon can use it to re-verify the pool's
/// healthy set without disturbing the running tunnel.
pub async fn deep_verify_egress(_profile: &str, node: &V2RayNode) -> EgressVerifyReport {
    // Pick a dedicated verification port — base port + (hash of node id) to
    // spread concurrent verifications and avoid colliding with the live
    // lifeline (10853) or the standard SOCKS ports.
    let base = 10900u16;
    let port = base
        + (node
            .id
            .bytes()
            .fold(0u16, |acc, b| acc.wrapping_add(b as u16))
            % 400);
    if port == LIFELINE_SOCKS_PORT || is_port_open(port).await {
        return EgressVerifyReport {
            ok: false,
            alias: node.alias.clone(),
            error: Some("verification port busy".into()),
        };
    }
    let xray = match find_xray_binary() {
        Some(x) => x,
        None => {
            return EgressVerifyReport {
                ok: false,
                alias: node.alias.clone(),
                error: Some("xray binary not found".into()),
            }
        }
    };
    // Render the config for this node on the dedicated port. Works for every
    // supported scheme (vless/vmess/trojan/ss/hysteria2/tuic) so deep verify
    // covers the whole pool, not only VLESS (doctrine §5).
    let cfg_json = match render_any_xray_cfg(&node.url, port) {
        Ok(c) => c,
        Err(e) => {
            return EgressVerifyReport {
                ok: false,
                alias: node.alias.clone(),
                error: Some(format!("render config: {e}")),
            }
        }
    };
    let cfg_path =
        std::env::temp_dir().join(format!("dyb-egress-verify-{}.json", crate::store::new_id()));
    if let Err(e) = std::fs::write(&cfg_path, &cfg_json) {
        return EgressVerifyReport {
            ok: false,
            alias: node.alias.clone(),
            error: Some(format!("write xray cfg: {e}")),
        };
    }
    // The random temp name already provides uniqueness; no need to persist it.
    let mut child = match std::process::Command::new(&xray)
        .arg("run")
        .arg("-c")
        .arg(&cfg_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(ch) => ch,
        Err(e) => {
            let _ = std::fs::remove_file(&cfg_path);
            return EgressVerifyReport {
                ok: false,
                alias: node.alias.clone(),
                error: Some(format!("spawn xray: {e}")),
            };
        }
    };
    // Do NOT delete cfg_path here: xray reads it asynchronously after spawn and
    // deleting too early races its boot. Clean up only after we are done.
    // Wait for the verification port to open.
    let mut ready = false;
    let deadline = std::time::Instant::now() + PORT_OPEN_TIMEOUT;
    while std::time::Instant::now() < deadline {
        if is_port_open(port).await {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    if !ready {
        let _ = child.kill();
        let _ = child.wait();
        // Collect any boot diagnostics to aid diagnosis (no fabricated success).
        let mut stderr_buf = Vec::new();
        if let Some(mut e) = child.stderr.take() {
            use std::io::Read;
            let _ = e.read_to_end(&mut stderr_buf);
        }
        return EgressVerifyReport {
            ok: false,
            alias: node.alias.clone(),
            error: Some(format!(
                "xray did not open verification port: {}",
                String::from_utf8_lossy(&stderr_buf).trim()
            )),
        };
    }
    // The decisive check: real egress through this node.
    let ok = egress_ok(port).await;
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(&cfg_path);
    EgressVerifyReport {
        ok,
        alias: node.alias.clone(),
        error: if ok {
            None
        } else {
            Some("no real egress through node".into())
        },
    }
}

/// Stop the lifeline tunnel (kill the child if alive).
pub fn stop_lifeline(profile: &str) -> bool {
    let Some(pid) = read_pid(profile) else {
        return false;
    };
    if pid_alive(pid) {
        // Send SIGTERM, then SIGKILL after a short grace if it does not exit.
        #[cfg(unix)]
        {
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
        #[cfg(not(unix))]
        {
            let _ = pid;
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
    use crate::artifact::config_store::{NodeStore, V2RayNode};

    /// Single best candidate (head of the ranked candidates list).
    fn pick_best_node(store: &NodeStore) -> Option<&V2RayNode> {
        pick_candidates(store).into_iter().next()
    }

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
    fn pick_includes_all_schemes() {
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
        // Doctrine §5: use *whatever* config works — healthy nodes of any
        // scheme are valid candidates, ranked equally by freshness.
        let s = store(vec![vmess.clone(), vless.clone()], None);
        let best = pick_best_node(&s).unwrap();
        // Both are healthy+fresh; order is by insertion (stable), so the
        // first healthy node is the vmess. Either is acceptable — what matters
        // is that the vmess is NOT excluded.
        assert!(
            best.url == vmess.url || best.url == vless.url,
            "healthy node of any scheme should be pickable, got {:?}",
            best.url
        );
        let c = pick_candidates(&s);
        assert_eq!(c.len(), 2, "both schemes should be candidates: {c:?}");
    }

    #[test]
    fn candidates_rank_and_dedup() {
        let now = crate::store::profiles::now_ts();
        // Active unhealthy (goes later, as last resort) + fresh healthy + stale
        // healthy + a fresh healthy vmess (now included — doctrine §5).
        let active = node(&vless_url("active"), None, None);
        let fresh = node(&vless_url("fresh"), Some(true), Some(now - 30.0));
        let stale = node(
            &vless_url("stale"),
            Some(true),
            Some(now - FRESHNESS_WINDOW - 60.0),
        );
        let vmess = node("vmess://abc", Some(true), Some(now - 10.0));
        let active_id = active.id.clone();
        let s = store(
            vec![vmess.clone(), stale, fresh.clone(), active.clone()],
            Some(active_id),
        );

        let c = pick_candidates(&s);
        let urls: Vec<&str> = c.iter().map(|n| n.url.as_str()).collect();
        // Fresh healthy nodes first (fresh + vmess, both fresh, stable order),
        // then stale healthy, then active. All four included now.
        assert_eq!(urls.len(), 4, "expected 4 candidates, got {urls:?}");
        // First two must be the fresh healthy pair (fresh and vmess in either
        // order — both have fresh probes).
        assert!(
            urls[0].contains("fresh") || urls[0].contains("vmess"),
            "first should be fresh-healthy: {urls:?}"
        );
        assert!(
            urls[1].contains("fresh") || urls[1].contains("vmess"),
            "second should be fresh-healthy: {urls:?}"
        );
        assert!(urls[2].contains("stale"), "third should be stale: {urls:?}");
        assert!(
            urls[3].contains("active"),
            "fourth should be active: {urls:?}"
        );
        // No duplicates.
        let n = urls.len();
        let mut uniq = urls.clone();
        uniq.dedup();
        assert_eq!(uniq.len(), n);
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
        // RealST security block must be populated; tls/ws blocks must be null.
        let ss = &out["streamSettings"];
        assert_eq!(ss["security"], "reality");
        assert_eq!(
            ss["realitySettings"]["publicKey"],
            "cv_KJnMzQUZruACPbH-BCgLWrYqPm2dbUymg-gW_sVc"
        );
        assert_eq!(
            ss["realitySettings"]["serverName"],
            "zealous-vortex.cdn.cachefleet.com"
        );
        assert_eq!(ss["realitySettings"]["fingerprint"], "firefox");
        assert!(ss["tlsSettings"].is_null());
        assert!(ss["wsSettings"].is_null());
        // TCP transport config.
        assert_eq!(ss["network"], "tcp");
        assert_eq!(ss["tcpSettings"]["header"]["type"], "none");
        assert!(ss["xhttpSettings"].is_null());
        assert!(ss["grpcSettings"].is_null());
    }

    #[test]
    fn render_xhttp_reality_uses_xhttp_settings() {
        let url = "vless://e1299012-3d27-4b7f-99d5-25ccb7c63220@194.58.41.39:443?mode=auto&path=%2F&security=reality&encryption=none&pbk=sJTPQLMDCyPAbRcaJM-P8Y3_xRVpEEGrvv-kkIuIuQE&host=www.google.com&fp=firefox&type=xhttp&sni=www.google.com#xhttp-test";
        let cfg = render_node_config(url).expect("should render");
        let v: serde_json::Value = serde_json::from_str(&cfg).expect("valid json");
        let ss = &v["outbounds"][0]["streamSettings"];
        assert_eq!(ss["network"], "xhttp");
        assert_eq!(ss["security"], "reality");
        assert!(ss["realitySettings"].is_object());
        assert_eq!(
            ss["realitySettings"]["publicKey"],
            "sJTPQLMDCyPAbRcaJM-P8Y3_xRVpEEGrvv-kkIuIuQE"
        );
        assert_eq!(ss["xhttpSettings"]["path"], "/");
        assert_eq!(ss["xhttpSettings"]["host"], "www.google.com");
        assert!(ss["wsSettings"].is_null());
        assert!(ss["tcpSettings"].is_null());
        assert!(ss["tlsSettings"].is_null());
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

    #[test]
    fn blacklist_persists_and_dedups() {
        let profile = "lifeline-test-blacklist";
        // Clean slate.
        let _ = std::fs::remove_file(bad_lifeline_path(profile));
        remember_bad_lifeline(profile, "vless://dead1");
        remember_bad_lifeline(profile, "vless://dead2");
        // Duplicate just refreshes the timestamp, still one entry.
        remember_bad_lifeline(profile, "vless://dead1");

        let s = load_bad_lifeline(profile);
        assert_eq!(s.urls.len(), 2);
        assert!(is_bad_lifeline(&s, "vless://dead1"));
        assert!(is_bad_lifeline(&s, "vless://dead2"));
        assert!(!is_bad_lifeline(&s, "vless://alive"));

        // Cleanup.
        let _ = std::fs::remove_file(bad_lifeline_path(profile));
    }

    #[test]
    fn blacklist_ages_out_after_regen_window() {
        let profile = "lifeline-test-blacklist-age";
        let _ = std::fs::remove_file(bad_lifeline_path(profile));
        let mut s = BadLifelineStore::default();
        let now = crate::store::profiles::now_ts();
        // Freshly failed → skipped.
        s.urls.insert("vless://fresh".into(), now);
        assert!(is_bad_lifeline(&s, "vless://fresh"));
        // Failed > regen window ago → retried.
        s.urls
            .insert("vless://old".into(), now - BAD_LIFELINE_REGEN - 1.0);
        assert!(!is_bad_lifeline(&s, "vless://old"));
        let _ = std::fs::remove_file(bad_lifeline_path(profile));
    }

    #[test]
    fn blacklist_filter_precedes_budget() {
        // The filter must run BEFORE the take(MAX_CANDIDATES_TRY) budget,
        // otherwise if the top-ranked candidates are all blacklisted we'd try
        // zero nodes. Here we build a store where the only healthy candidate is
        // blacklisted, but an unhealthy-but-vless one remains; the filtered
        // list must still contain that fallback.
        let now = crate::store::profiles::now_ts();
        let healthy = node(
            &vless_url("healthy-blacklisted"),
            Some(true),
            Some(now - 10.0),
        );
        let fallback = node(&vless_url("fallback"), None, None);
        let s = store(vec![healthy.clone(), fallback.clone()], None);

        let mut bad = BadLifelineStore::default();
        bad.urls.insert(healthy.url.clone(), now);
        let filtered: Vec<&V2RayNode> = pick_candidates(&s)
            .into_iter()
            .filter(|n| !is_bad_lifeline(&bad, &n.url))
            .take(MAX_CANDIDATES_TRY)
            .collect();
        // The blacklisted healthy node is skipped; the fallback still appears.
        assert!(filtered.iter().all(|n| n.url != healthy.url));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].url, fallback.url);
    }

    #[test]
    fn render_any_supports_all_schemes() {
        let cases = [
            (
                "vless://06ef598c-1555-4887-b3f9-08214a2f6792@1.2.3.4:443?encryption=none&security=reality&sni=example.com&type=tcp",
                "vless",
            ),
            ("vmess://eyJ2IjoiMiIsInBzIjoiYSIsImFkZCI6IjEuMi4zLjQiLCJwb3J0IjoiNDQzIiwiaWQiOiIwNmVmNTk4Yy0xNTU1LTQ4ODctYjNmOS0wODIxNGEyZjY3OTIiLCJhaWQiOiIwIiwibmV0IjoidGNwIiwidGxzIjoidGxzIn0=", "vmess"),
            ("trojan://password123@1.2.3.4:443?security=tls&type=tcp", "trojan"),
            ("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@1.2.3.4:8388", "shadowsocks"),
        ];
        for (url, proto) in cases {
            let cfg = render_any_xray_cfg(url, 11999).unwrap_or_else(|e| panic!("{proto}: {e}"));
            let v: serde_json::Value = serde_json::from_str(&cfg).unwrap();
            let out = v["outbounds"][0].clone();
            assert_eq!(out["protocol"], proto, "for {url}");
            assert_eq!(v["inbounds"][0]["port"], 11999);
        }
    }

    #[test]
    fn render_any_rejects_garbage() {
        assert!(render_any_xray_cfg("not-a-link", 12000).is_err());
        assert!(render_any_xray_cfg("ss://", 12000).is_err());
    }
}
