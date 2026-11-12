//! Native config store for v2rayN-derived nodes.
//!
//! v2rayN keeps its servers in a `ServersStore.json` file (a GUI-internal
//! format). Relying on that file as the long-lived source of truth is brittle:
//! v2rayN can be removed, the file moved, or the paths churn on reinstall.
//! DastYab must own its own copy of the configs it wants to route through.
//!
//! This module imports every VLESS share-link from a v2rayN store and persists
//! it into the profile's own `nodes.json` (atomic, per-profile, under
//! `~/.dastyab/profiles/<id>/nodes.json`). It keeps the **full raw share
//! link** and the alias, so nothing is lost when the pane is closed:
//! reality-only params (`pbk`, `spx`, `sid`, `fp`, `flow`, ...) survive even
//! though `VlessProfile` only models the core fields.
//!
//! ## Why a store, not a passthrough
//! - **Survives blackout**: configs are resolvable even if v2rayN is gone.
//! - **Active/fallback pool**: the autopilot can cycle nodes without re-reading
//!   v2rayN's GUI state.
//! - **Dedup + idempotency**: importing the same store twice never duplicates.
//! - **Per-profile isolation**: each named profile keeps its own node pool.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::CFError;
use crate::store::profiles::{now_ts, profile_dir};
use crate::store::{atomic_write, read_or_default};
use crate::vless::VlessProfile;

/// Maximum number of nodes kept per profile.
const MAX_NODES: usize = 500;

/// A single node imported from v2rayN (or pasted directly).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct V2RayNode {
    /// Short stable id.
    pub id: String,
    /// v2rayN's alias (or the share link fragment if none).
    pub alias: String,
    /// The full raw share link (all params preserved).
    pub url: String,
    /// Original index in the v2rayN store (for provenance).
    #[serde(default)]
    pub source_index: Option<u32>,
    /// Where this came from ("v2rayn" | "pasted" | "autopilot").
    #[serde(default = "default_source")]
    pub source: String,
    /// Epoch (unix seconds) when this node was imported.
    #[serde(default)]
    pub added_epoch: f64,
    /// Epoch of the last time a probe touched this node.
    #[serde(default)]
    pub last_checked_epoch: Option<f64>,
    /// Current health known to the autopilot (None = unprobed).
    #[serde(default)]
    pub healthy: Option<bool>,
}

fn default_source() -> String {
    "v2rayn".to_string()
}

/// Decoded core fields (from `VlessProfile`), kept for convenience/display.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CoreFields {
    pub uuid: String,
    pub address: String,
    pub port: u16,
    pub security: String,
    pub transport: String,
    pub sni: Option<String>,
    pub path: String,
}

/// The per-profile node store (persisted at `nodes.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeStore {
    /// Id of the currently-active node, if any.
    pub active_id: Option<String>,
    /// Full pool of known nodes (newest-first).
    pub nodes: Vec<V2RayNode>,
}

impl NodeStore {
    /// The active node (if one is set and still present).
    pub fn active(&self) -> Option<&V2RayNode> {
        self.active_id.as_ref().and_then(|id| self.get(id))
    }

    pub fn get(&self, id: &str) -> Option<&V2RayNode> {
        self.nodes.iter().find(|n| n.id == id)
    }

    /// Set the active node by id. Returns `Ok(false)` if unknown.
    pub fn set_active(&mut self, id: &str) -> bool {
        if self.get(id).is_some() {
            self.active_id = Some(id.to_string());
            true
        } else {
            false
        }
    }

    /// Add a node if the (address, port, uuid) triple is not already present.
    /// Returns `Ok(false)` when it was a duplicate (no change).
    pub fn upsert(&mut self, node: V2RayNode) -> bool {
        if self.nodes.iter().any(|e| same_server(&e.url, &node.url)) {
            return false;
        }
        self.nodes.insert(0, node);
        if self.nodes.len() > MAX_NODES {
            self.nodes.truncate(MAX_NODES);
            // If the active node fell off the end, unset it.
            if let Some(a) = &self.active_id {
                if self.get(a).is_none() {
                    self.active_id = None;
                }
            }
        }
        true
    }
}

/// Compare two share-links by their (address, port, uuid) identity.
fn same_server(a: &str, b: &str) -> bool {
    // Scheme-agnostic dedup: same host+port+id ⇒ same server, regardless of
    // which transport scheme the links use. When either link is unparseable,
    // fall back to exact string equality.
    if let (Some(ca), Some(cb)) = (
        crate::proxy_uri::ProxyUri::parse(a),
        crate::proxy_uri::ProxyUri::parse(b),
    ) {
        return ca.host == cb.host && ca.port == cb.port && ca.id == cb.id;
    }
    a == b
}

/// Decode the core (id/address/port/security/transport/sni/path) from any
/// supported share-link. Never fails — returns defaults for unparsable links.
///
/// For VLESS links the full `VlessProfile` model is used (security, transport,
/// sni, path). For every other scheme the security/transport columns show the
/// scheme name and the host/port/id come from the scheme-agnostic parser.
fn decode_core(url: &str) -> CoreFields {
    let mut cf = if let Some(uri) = crate::proxy_uri::ProxyUri::parse(url) {
        CoreFields {
            uuid: uri.id,
            address: uri.host,
            port: uri.port,
            security: uri.scheme,
            transport: String::new(),
            sni: None,
            path: String::new(),
        }
    } else {
        CoreFields::default()
    };
    // Enrich with the full VLESS model when this is a vless link (keeps the
    // reality/ws/tls plumbing intact for display and export).
    if let Ok(p) = VlessProfile::parse(url) {
        cf.uuid = p.uuid;
        cf.address = p.address;
        cf.port = p.port;
        cf.security = p.security;
        cf.transport = p.transport;
        cf.sni = p.sni;
        cf.path = p.path;
    }
    cf
}

/// Extract the `?`-query (and fragment) params as a raw map, preserving
/// percent-encodings as-is so reality params survive untouched. Public because
/// the GUI/CLI render the raw params as context for a node.
pub fn extract_raw_params(url: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let body = url.strip_prefix("vless://").unwrap_or(url);
    let no_frag = body.split('#').next().unwrap_or("");
    let Some(q) = no_frag.split('?').nth(1) else {
        return out;
    };
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut it = pair.splitn(2, '=');
        let k = it.next().unwrap_or("").to_string();
        let v = it.next().unwrap_or("").to_string();
        if !k.is_empty() {
            out.insert(k, v);
        }
    }
    out
}

/// The persisted path for a profile's node store.
pub fn node_store_path(profile: &str) -> std::path::PathBuf {
    profile_dir(profile).join("nodes.json")
}

/// Load the node store for a profile (empty when missing/corrupt).
pub fn load_node_store(profile: &str) -> NodeStore {
    read_or_default::<NodeStore>(&node_store_path(profile))
}

/// Persist the node store atomically.
pub fn save_node_store(profile: &str, store: &NodeStore) -> Result<(), CFError> {
    let path = node_store_path(profile);
    let bytes = serde_json::to_vec_pretty(store).map_err(|e| {
        CFError::new(
            "Storage error",
            format!("Cannot serialize node store: {e}"),
            "Internal error.",
        )
    })?;
    atomic_write(&path, &bytes)
}

/// Result of importing a v2rayN store.
#[derive(Debug, Clone, Default)]
pub struct ImportSummary {
    pub found: usize,
    pub added: usize,
    pub duplicates: usize,
    pub skipped_invalid: usize,
    pub skipped_non_vless: usize,
}

/// Load a v2rayN `ServersStore.json` and pull every VLESS share-link off it.
/// The store shape is `{"servers":[{"url":"vless://...","alias":"..."}, ...]}`.
pub fn import_v2rayn_store(profile: &str, path: &Path) -> Result<ImportSummary, CFError> {
    let bytes = std::fs::read(path).map_err(|e| {
        CFError::new(
            "Import error",
            format!("Cannot read {}: {e}", path.display()),
            "Check the path is correct and readable.",
        )
    })?;

    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
        CFError::new(
            "Import error",
            format!("{} is not valid JSON: {e}", path.display()),
            "Export a fresh ServersStore.json from v2rayN.",
        )
    })?;

    let servers = value
        .get("servers")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            CFError::new(
                "Import error",
                "No \"servers\" array found in this file.",
                "Pick the v2rayN ServersStore.json (usually in ~/.config/v2rayN/Local/).",
            )
        })?;

    let mut store = load_node_store(profile);
    let mut summary = ImportSummary {
        found: servers.len(),
        ..Default::default()
    };

    for (i, s) in servers.iter().enumerate() {
        let url = s.get("url").and_then(|v| v.as_str()).unwrap_or("");
        if url.is_empty() {
            summary.skipped_invalid += 1;
            continue;
        }
        // Any supported scheme is importable now (vless, vmess, trojan, ss,
        // ssr, hysteria2, tuic). Unrecognized schemes are counted separately.
        let parsed = match crate::proxy_uri::ProxyUri::parse(url) {
            Some(p) => p,
            None => {
                summary.skipped_non_vless += 1;
                continue;
            }
        };

        let alias = s
            .get("alias")
            .and_then(|v| v.as_str())
            .filter(|a| !a.is_empty())
            .map(|a| a.to_string())
            .or_else(|| {
                if !parsed.alias.is_empty() {
                    Some(parsed.alias.clone())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| format!("node-{}", i + 1));

        let node = V2RayNode {
            id: crate::store::new_id(),
            alias,
            url: url.to_string(),
            source_index: Some(i as u32),
            source: "v2rayn".to_string(),
            added_epoch: now_ts(),
            last_checked_epoch: None,
            healthy: None,
        };

        if store.upsert(node) {
            summary.added += 1;
        } else {
            summary.duplicates += 1;
        }
    }

    save_node_store(profile, &store)?;
    Ok(summary)
}

/// Paste a single share-link into the profile's node store. Any supported
/// scheme is accepted (vless, vmess, trojan, ss, ssr, hysteria2, tuic).
pub fn import_single_link(profile: &str, link: &str) -> Result<ImportSummary, CFError> {
    let link = link.trim();
    let uri = crate::proxy_uri::ProxyUri::parse(link).ok_or_else(|| {
        CFError::new(
            "Import error",
            "Not a supported share link.",
            "Paste a valid vless/vmess/trojan/ss/ssr/hysteria2/tuic link (or import a ServersStore.json).",
        )
    })?;

    let alias = if uri.alias.is_empty() {
        "pasted".to_string()
    } else {
        uri.alias
    };

    let node = V2RayNode {
        id: crate::store::new_id(),
        alias,
        url: link.to_string(),
        source_index: None,
        source: "pasted".to_string(),
        added_epoch: now_ts(),
        last_checked_epoch: None,
        healthy: None,
    };

    let mut store = load_node_store(profile);
    let mut summary = ImportSummary {
        found: 1,
        ..Default::default()
    };
    if store.upsert(node) {
        summary.added = 1;
    } else {
        summary.duplicates = 1;
    }
    save_node_store(profile, &store)?;
    Ok(summary)
}

/// List the node store as a human-readable table.
pub fn render_nodes(profile: &str) -> String {
    let store = load_node_store(profile);
    if store.nodes.is_empty() {
        return format!("No nodes yet in profile '{profile}'. Import a ServersStore.json or paste a vless link.");
    }
    let mut out = format!(
        "Nodes in profile '{profile}' ({} total):\n",
        store.nodes.len()
    );
    for n in &store.nodes {
        let mark = if Some(&n.id) == store.active_id.as_ref() {
            "*"
        } else {
            " "
        };
        let core = decode_core(&n.url);
        let health = match n.healthy {
            Some(true) => "healthy",
            Some(false) => "down",
            None => "unprobed",
        };
        out.push_str(&format!(
            " {mark} {}  {:<24} {:>15}:{:<5}  {:<8}  {:<9}  {}\n",
            n.id,
            n.alias.chars().take(24).collect::<String>(),
            core.address,
            core.port,
            core.security,
            health,
            core.transport,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::set_mem_dir_override;
    use base64::Engine;

    fn tmp_profile() -> (String, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mem = dir.path().join("mem");
        set_mem_dir_override(mem);
        ("default".to_string(), dir)
    }

    const SAMPLE: &str = r#"{"servers":[
      {"alias":"Telegram-1","url":"vless://413a66e9-b05b-4ae6-a9eb-6d28204a28f4@138.68.53.88:443?security=&encryption=none&headerType=none&type=tcp#@filembad"},
      {"alias":"Telegram-2","url":"vless://98a0a5cd-994d-49ca-8a64-e526afa8db28@107.189.20.41:9990?security=reality&encryption=none&pbk=rOaA_Qh474Lv7B-_1uxOBScCcRjUVlz2aZXmhbFwlFY&headerType=none&fp=chrome&spx=%2FY7vPvjIeUOpXQSq&type=tcp&flow=xtls-rprx-vision&sni=play.google.com&sid=a114#@filembad"},
      {"alias":"Clash-1","url":"clash://not-a-vless"}
    ]}"#;

    #[test]
    fn import_parses_vless_and_skips_non_vless() {
        let (profile, _d) = tmp_profile();
        let p = _d.path().join("ServersStore.json");
        std::fs::write(&p, SAMPLE).unwrap();

        let s = import_v2rayn_store(&profile, &p).unwrap();
        assert_eq!(s.found, 3);
        assert_eq!(s.added, 2);
        assert_eq!(s.skipped_non_vless, 1);
        assert_eq!(s.duplicates, 0);

        let store = load_node_store(&profile);
        assert_eq!(store.nodes.len(), 2);
        // Nodes are newest-first, so the reality node (telemed 2) is at index 0.
        // Reality params preserved in raw url.
        assert!(store.nodes[0].url.contains("pbk=rOaA_Qh474Lv7B"));
        assert!(store.nodes[0].url.contains("spx=%2FY7vPvjIeUOpXQSq"));
    }

    #[test]
    fn import_is_idempotent() {
        let (profile, _d) = tmp_profile();
        let p = _d.path().join("ServersStore.json");
        std::fs::write(&p, SAMPLE).unwrap();

        let s1 = import_v2rayn_store(&profile, &p).unwrap();
        assert_eq!(s1.added, 2);
        let s2 = import_v2rayn_store(&profile, &p).unwrap();
        assert_eq!(s2.added, 0);
        assert_eq!(s2.duplicates, 2);
        assert_eq!(load_node_store(&profile).nodes.len(), 2);
    }

    #[test]
    fn set_active_roundtrip() {
        let (profile, _d) = tmp_profile();
        let p = _d.path().join("ServersStore.json");
        std::fs::write(&p, SAMPLE).unwrap();
        import_v2rayn_store(&profile, &p).unwrap();

        let mut store = load_node_store(&profile);
        let id = store.nodes[0].id.clone();
        assert!(store.set_active(&id));
        assert!(!store.set_active("nope"));
        save_node_store(&profile, &store).unwrap();

        let reloaded = load_node_store(&profile);
        assert_eq!(reloaded.active_id.as_deref(), Some(id.as_str()));
        assert!(reloaded.active().is_some());
    }

    #[test]
    fn missing_store_is_empty_default() {
        let (profile, _d) = tmp_profile();
        let store = load_node_store(&profile);
        assert!(store.nodes.is_empty());
        assert!(store.active().is_none());
    }

    #[test]
    fn import_single_link_strips_whitespace() {
        let (profile, _d) = tmp_profile();
        import_single_link(
            &profile,
            "  vless://uuid@1.2.3.4:443?security=tls&type=ws&path=%2F#test  ",
        )
        .unwrap();
        let store = load_node_store(&profile);
        assert_eq!(store.nodes.len(), 1);
        assert_eq!(store.nodes[0].alias, "test");
    }

    #[test]
    fn import_single_link_rejects_bad() {
        let (profile, _d) = tmp_profile();
        assert!(import_single_link(&profile, "not-a-link").is_err());
        assert!(import_single_link(&profile, "vless://junk").is_err());
        assert!(import_single_link(&profile, "http://other.com").is_err());
    }

    #[test]
    fn import_multi_scheme_links() {
        let (profile, _d) = tmp_profile();
        // trojan
        import_single_link(
            &profile,
            "trojan://pw@ali.example.com:8443?security=tls&sni=ali.example.com#tr",
        )
        .unwrap();
        // hysteria2
        import_single_link(
            &profile,
            "hysteria2://tok@107.189.20.41:8443?insecure=1#hy2",
        )
        .unwrap();
        // shadowsocks (plain + base64)
        import_single_link(&profile, "ss://chacha20-ietf-poly1305:k@7.7.7.7:8388#ss1").unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:k2@38.4.5.6:10010");
        import_single_link(&profile, &format!("ss://{b64}#ss2")).unwrap();
        // vmess (base64 JSON)
        let json = r#"{"v":"2","ps":"vm","add":"198.51.100.9","port":"443","id":"7748b328-f0e8-40ab-b2e3-9a1c2c22d111","aid":"0"}"#;
        let vb64 = base64::engine::general_purpose::STANDARD.encode(json);
        import_single_link(&profile, &format!("vmess://{vb64}")).unwrap();

        let store = load_node_store(&profile);
        assert_eq!(store.nodes.len(), 5, "all five schemes must import");
        // ssr
        let ssr = "95.85.234.66:10001:auth_aes128_md5:aes-128-ctr:tls1.2_ticket_auth:Zm9vYmFy";
        let sb64 = base64::engine::general_purpose::STANDARD.encode(ssr);
        import_single_link(&profile, &format!("ssr://{sb64}")).unwrap();
        let store = load_node_store(&profile);
        assert_eq!(store.nodes.len(), 6);
        // vmess alias prefers ps over "pasted".
        let vm = store
            .nodes
            .iter()
            .find(|n| n.url.starts_with("vmess://"))
            .unwrap();
        assert_eq!(vm.alias, "vm");
    }

    #[test]
    fn dedup_cross_scheme_same_server() {
        let (profile, _d) = tmp_profile();
        // The same server identity (host+port+uuid) expressed as vless and as
        // trojan (same id string) must dedup to a single node.
        import_single_link(
            &profile,
            "vless://7748b328-f0e8-40ab-b2e3-9a1c2c22d111@1.2.3.4:443?type=tcp#v",
        )
        .unwrap();
        import_single_link(
            &profile,
            "trojan://7748b328-f0e8-40ab-b2e3-9a1c2c22d111@1.2.3.4:443?security=tls#t",
        )
        .unwrap();
        let store = load_node_store(&profile);
        assert_eq!(store.nodes.len(), 1, "cross-scheme same server must dedup");
    }

    #[test]
    fn extract_raw_params_keeps_percent_encoding() {
        let m = extract_raw_params(
            "vless://u@h:1?security=reality&spx=%2FY7vPvjIeUOpXQSq&sid=a114&flow=xtls-rprx-vision#x",
        );
        assert_eq!(m.get("security").map(String::as_str), Some("reality"));
        assert_eq!(m.get("spx").map(String::as_str), Some("%2FY7vPvjIeUOpXQSq"));
        assert_eq!(m.get("flow").map(String::as_str), Some("xtls-rprx-vision"));
        assert_eq!(m.get("sid").map(String::as_str), Some("a114"));
    }
}
