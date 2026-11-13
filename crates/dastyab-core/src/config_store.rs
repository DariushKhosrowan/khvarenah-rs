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
    /// Epoch (unix seconds) when the *source* published this config (e.g. the
    /// Telegram archive message time). `None` when unknown. Lets export
    /// prioritize the freshest (most likely still-live) free configs.
    #[serde(default)]
    pub published_epoch: Option<f64>,
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

    /// Record a verified health verdict for a node and stamp the check time.
    /// Returns `true` if the node was found and updated.
    pub fn set_health(&mut self, id: &str, healthy: bool) -> bool {
        if let Some(n) = self.nodes.iter_mut().find(|n| n.id == id) {
            n.healthy = Some(healthy);
            n.last_checked_epoch = Some(now_ts());
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
            self.retain_capacity();
        }
        true
    }

    /// Truncate to `MAX_NODES` without ever evicting the active node or a
    /// verified-healthy node (doctrine §6.4: never silently lose known-good
    /// configs). Protected nodes are kept; the rest are pruned oldest-first,
    /// so a bulk harvest never clobbers the working anchor the tunnel depends on.
    fn retain_capacity(&mut self) {
        let active = self.active_id.clone();
        let protected: Vec<String> = self
            .nodes
            .iter()
            .filter_map(|n| {
                let is_active = active.as_deref() == Some(n.id.as_str());
                let healthy = n.healthy == Some(true);
                (is_active || healthy).then(|| n.id.clone())
            })
            .collect();
        // Order: protected first (active first), then the newest remaining nodes.
        let mut ordered: Vec<V2RayNode> = Vec::with_capacity(MAX_NODES);
        for id in &protected {
            if let Some(pos) = self.nodes.iter().position(|n| &n.id == id) {
                ordered.push(self.nodes.remove(pos));
            }
        }
        if ordered.len() >= MAX_NODES {
            ordered.truncate(MAX_NODES);
            self.nodes = ordered;
            return;
        }
        // Fill the remaining slots with the newest non-protected nodes.
        let fill = MAX_NODES - ordered.len();
        let mut rest: Vec<V2RayNode> = std::mem::take(&mut self.nodes);
        rest.truncate(fill);
        ordered.extend(rest);
        self.nodes = ordered;
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
            published_epoch: None,
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

/// v2rayN server-entry `configType` label for a share-link scheme.
pub fn v2rayn_config_type(url: &str) -> &'static str {
    if url.starts_with("vless://") {
        "VLESS"
    } else if url.starts_with("vmess://") {
        "VMESS"
    } else if url.starts_with("trojan://") {
        "TROJAN"
    } else if url.starts_with("ss://") {
        "SS"
    } else if url.starts_with("ssr://") {
        "SSR"
    } else if url.starts_with("hysteria2://") {
        "HYSTERIA2"
    } else if url.starts_with("tuic://") {
        "TUIC"
    } else {
        "VLESS"
    }
}

/// Identity (host, port, id) of a share-link, mirroring [`same_server`].
fn node_identity(url: &str) -> Option<(String, String, String)> {
    let p = crate::proxy_uri::ProxyUri::parse(url)?;
    Some((p.host.clone(), p.port.to_string(), p.id.clone()))
}

/// Export nodes from this profile into a v2rayN `ServersStore.json`, merged
/// with any existing servers (dedup by host+port+uuid). When `only_healthy`
/// is true (recommended), only verified-healthy nodes are written, so the
/// v2rayN GUI ends up with a working config set. Returns (added, dups).
pub fn export_v2rayn_store(
    profile: &str,
    path: &Path,
    only_healthy: bool,
) -> Result<(usize, usize), CFError> {
    let store = load_node_store(profile);

    let mut value: serde_json::Value = if path.exists() {
        let bytes = std::fs::read(path).map_err(|e| {
            CFError::new(
                "Export error",
                format!("Cannot read {}: {e}", path.display()),
                "Check the path is valid.",
            )
        })?;
        serde_json::from_slice(&bytes).map_err(|e| {
            CFError::new(
                "Export error",
                format!("{} is not valid JSON: {e}", path.display()),
                "Export a fresh ServersStore.json from v2rayN.",
            )
        })?
    } else {
        serde_json::json!({"servers": []})
    };

    let servers = value
        .get_mut("servers")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| {
            CFError::new(
                "Export error",
                "No \"servers\" array found in the target file.",
                "Pick a valid v2rayN ServersStore.json.",
            )
        })?;

    let mut seen = std::collections::HashSet::new();
    for s in servers.iter() {
        if let Some(url) = s.get("url").and_then(|v| v.as_str()) {
            if let Some(id) = node_identity(url) {
                seen.insert(id);
            }
        }
    }

    let mut next_index = servers.len();
    let mut added = 0;
    let mut dups = 0;
    let now_ms = (now_ts() * 1000.0) as i64;

    // Export freshest-first: free configs rot fast, so the most recently
    // published are the most likely to still be live. Nodes with a known
    // publish time rank above those without; ties fall back to added_epoch.
    let mut ranked: Vec<&V2RayNode> = store.nodes.iter().collect();
    ranked.sort_by(|a, b| {
        let ka = (a.published_epoch, a.added_epoch);
        let kb = (b.published_epoch, b.added_epoch);
        kb.partial_cmp(&ka).unwrap_or(std::cmp::Ordering::Equal)
    });

    for node in ranked
        .into_iter()
        .filter(|n| !only_healthy || n.healthy == Some(true))
    {
        let id = match node_identity(&node.url) {
            Some(id) => id,
            None => continue,
        };
        if seen.contains(&id) {
            dups += 1;
            continue;
        }
        seen.insert(id);
        let clean_url = node.url.trim_end_matches('#').to_string();
        let alias = if node.alias.is_empty() {
            format!("node-{}", next_index + 1)
        } else {
            node.alias.clone()
        };
        servers.push(serde_json::json!({
            "alias": alias,
            "index": next_index,
            "lastV2rayEntryTime": now_ms,
            "subId": "",
            "url": clean_url,
            "configType": v2rayn_config_type(&clean_url),
            "serverUrl": clean_url,
        }));
        next_index += 1;
        added += 1;
    }

    let bytes = serde_json::to_vec_pretty(&value).map_err(|e| {
        CFError::new(
            "Export error",
            format!("Cannot serialize ServersStore.json: {e}"),
            "Internal error.",
        )
    })?;
    atomic_write(path, &bytes)?;
    Ok((added, dups))
}

/// Source label recorded on nodes imported from an autonomous/out-of-band
/// source (Telegram archive or GitHub config repo) — distinct from a
/// hand-pasted link so the store can track provenance and prune/audit
/// auto-discovered configs separately from manual ones.
pub const SOURCE_TELEGRAM: &str = "telegram";
pub const SOURCE_GITHUB: &str = "github";
pub const SOURCE_PASTED: &str = "pasted";

/// Paste a single share-link into the profile's node store. Any supported
/// scheme is accepted (vless, vmess, trojan, ss, ssr, hysteria2, tuic).
/// Node provenance is recorded as [`SOURCE_PASTED`].
pub fn import_single_link(profile: &str, link: &str) -> Result<ImportSummary, CFError> {
    import_single_link_source(profile, link, SOURCE_PASTED)
}

/// [`import_single_link`] with an explicit provenance `source` label (see
/// [`SOURCE_TELEGRAM`], [`SOURCE_GITHUB`]). Used by the Telegram harvester and
/// GitHub ingester so auto-recovered configs are distinguishable from manual
/// pastes in the node store.
pub fn import_single_link_source(
    profile: &str,
    link: &str,
    source: &str,
) -> Result<ImportSummary, CFError> {
    import_single_link_source_ts(profile, link, source, None)
}

/// [`import_single_link_source`] with an optional *published* epoch. When the
/// source exposes when it posted the config (e.g. the Telegram archive message
/// time), record it so the freshest, most likely still-live free configs can
/// be prioritized on export.
pub fn import_single_link_source_ts(
    profile: &str,
    link: &str,
    source: &str,
    published_epoch: Option<f64>,
) -> Result<ImportSummary, CFError> {
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
        source: source.to_string(),
        added_epoch: now_ts(),
        published_epoch,
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
        // Already-known config: refresh its published timestamp when this pass
        // carries a newer one (or the first we have seen) so age data stays
        // accurate across repeated harvest runs.
        if let Some(ts) = published_epoch {
            if let Some(existing) = store.nodes.iter_mut().find(|e| same_server(&e.url, link)) {
                if existing.published_epoch.is_none_or(|p| ts > p) {
                    existing.published_epoch = Some(ts);
                }
            }
        }
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

    #[test]
    fn import_source_tags_provenance() {
        let (profile, _d) = tmp_profile();
        // Default (pasted) provenance.
        import_single_link(
            &profile,
            "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?type=tcp#p",
        )
        .unwrap();
        // Explicit source labels.
        import_single_link_source(
            &profile,
            "vless://22222222-2222-2222-2222-222222222222@5.6.7.8:443?type=tcp#t",
            SOURCE_TELEGRAM,
        )
        .unwrap();
        import_single_link_source(
            &profile,
            "vless://33333333-3333-3333-3333-333333333333@9.10.11.12:443?type=tcp#g",
            SOURCE_GITHUB,
        )
        .unwrap();

        let store = load_node_store(&profile);
        let by_id = |id: &str| store.nodes.iter().find(|n| n.url.contains(id)).unwrap();
        assert_eq!(by_id("11111111").source, SOURCE_PASTED);
        assert_eq!(by_id("22222222").source, SOURCE_TELEGRAM);
        assert_eq!(by_id("33333333").source, SOURCE_GITHUB);
    }

    #[test]
    fn export_v2rayn_roundtrip_dedups_and_filters_unhealthy() {
        let (profile, _d) = tmp_profile();
        // Two healthy nodes + one unhealthy node.
        import_single_link(
            &profile,
            "vless://11111111-1111-1111-1111-111111111111@10.0.0.1:443?type=tcp#healthy1",
        )
        .unwrap();
        import_single_link(
            &profile,
            "trojan://22222222-2222-2222-2222-222222222222@10.0.0.2:443?security=tls#healthy2",
        )
        .unwrap();
        import_single_link(
            &profile,
            "vless://33333333-3333-3333-3333-333333333333@10.0.0.3:443?type=tcp#sick",
        )
        .unwrap();

        let mut store = load_node_store(&profile);
        for n in store.nodes.iter_mut() {
            n.healthy = Some(n.url.contains("healthy"));
        }
        save_node_store(&profile, &store).unwrap();

        // Existing v2rayN store containing one of the healthy nodes already.
        let p = _d.path().join("ServersStore.json");
        let existing = r#"{"servers":[{"alias":"prev","url":"vless://11111111-1111-1111-1111-111111111111@10.0.0.1:443?type=tcp#healthy1"}]}"#;
        std::fs::write(&p, existing).unwrap();

        let (added, dups) = export_v2rayn_store(&profile, &p, true).unwrap();
        assert_eq!(added, 1, "only the not-yet-present healthy node is added");
        assert_eq!(dups, 1, "already-present healthy node is skipped as dup");

        let out: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        let servers = out["servers"].as_array().unwrap();
        assert_eq!(servers.len(), 2);
        assert!(servers
            .iter()
            .any(|s| s["url"].as_str().unwrap().contains("22222222")));
        assert!(
            !servers
                .iter()
                .any(|s| s["url"].as_str().unwrap().contains("33333333")),
            "unhealthy node must not be exported"
        );
        assert!(servers.iter().any(|s| s["configType"] == "TROJAN"));
    }

    #[test]
    fn import_with_published_epoch_records_and_refreshes_freshness() {
        let (profile, _d) = tmp_profile();
        let link = "vless://7748b328-f0e8-40ab-b2e3-9a1c2c22d111@1.2.3.4:443?type=tcp#f";

        // First import carries a publish epoch.
        let s1 = import_single_link_source_ts(&profile, link, "telegram", Some(1000.0)).unwrap();
        assert_eq!(s1.added, 1);
        let store = load_node_store(&profile);
        assert_eq!(store.nodes[0].published_epoch, Some(1000.0));

        // Duplicate import with a NEWER publish epoch → duplicate, but the
        // recorded freshness is refreshed (no double-add).
        let s2 = import_single_link_source_ts(&profile, link, "telegram", Some(2000.0)).unwrap();
        assert_eq!(s2.added, 0);
        assert_eq!(s2.duplicates, 1);
        let store = load_node_store(&profile);
        assert_eq!(store.nodes.len(), 1);
        assert_eq!(store.nodes[0].published_epoch, Some(2000.0));

        // Duplicate import with an OLDER epoch must NOT downgrade freshness.
        import_single_link_source_ts(&profile, link, "telegram", Some(500.0)).unwrap();
        let store = load_node_store(&profile);
        assert_eq!(store.nodes[0].published_epoch, Some(2000.0));

        // No published epoch → field stays None.
        import_single_link(
            &profile,
            "vless://aaaaaaaa-0000-0000-0000-000000000000@9.9.9.9:443?type=tcp#n",
        )
        .unwrap();
        let store = load_node_store(&profile);
        let n = store
            .nodes
            .iter()
            .find(|x| x.url.contains("9.9.9.9"))
            .unwrap();
        assert_eq!(n.published_epoch, None);
    }

    fn node(id: &str, healthy: Option<bool>) -> V2RayNode {
        V2RayNode {
            id: id.to_string(),
            alias: id.to_string(),
            url: format!("vless://{}@1.2.3.4:443?type=tcp#{id}", "a".repeat(36)),
            source_index: None,
            source: "telegram".to_string(),
            added_epoch: 0.0,
            published_epoch: None,
            last_checked_epoch: None,
            healthy,
        }
    }

    #[test]
    fn set_health_records_verdict_and_timestamp() {
        let mut s = NodeStore::default();
        s.nodes = vec![node("n1", None), node("n2", Some(true))];

        // Unknown id → false, no change.
        assert!(!s.set_health("nope", true));

        // Healthy verdict recorded.
        assert!(s.set_health("n1", true));
        assert_eq!(s.nodes[0].healthy, Some(true));
        assert!(s.nodes[0].last_checked_epoch.is_some());

        // Deferiorating verdict recorded.
        assert!(s.set_health("n2", false));
        assert_eq!(s.nodes[1].healthy, Some(false));
    }

    #[test]
    fn retain_capacity_keeps_active_and_healthy() {
        let mut s = NodeStore::default();
        s.nodes = vec![
            node("dead1", Some(false)),
            node("dead2", Some(false)),
            node("healthy", Some(true)),
            node("active", None),
            node("dead3", Some(false)),
            node("unprobed", None),
        ];
        // active + healthy must be kept; the rest pruned newest-first down to
        // the fill budget (simulate a store at capacity).
        s.active_id = Some("active".to_string());
        // Fill the store well past MAX_NODES to force truncation.
        s.nodes = Vec::new();
        s.nodes.push(node("active", Some(true)));
        s.nodes.push(node("healthy", Some(true)));
        for i in 0..1200 {
            s.nodes.push(node(&format!("n{i:04}"), Some(false)));
        }
        s.nodes.push(node("active", Some(false))); // dup id — should not matter
        s.active_id = Some("active".to_string());
        s.retain_capacity();
        assert_eq!(s.nodes.len(), MAX_NODES);
        // protected pair is present
        assert!(s.nodes.iter().any(|n| n.id == "active"));
        assert!(s.nodes.iter().any(|n| n.id == "healthy"));
    }

    #[test]
    fn upsert_never_evicts_verified_healthy_or_active() {
        let (profile, _d) = tmp_profile();
        let mut store = load_node_store(&profile);
        // Establish an active, verified-healthy anchor.
        store.nodes.push(node("anchor", Some(true)));
        store.set_active("anchor");
        save_node_store(&profile, &store);

        // Bulk-import 510 fresh nodes (past MAX_NODES).
        for i in 0..510 {
            let uuid = format!("00000000-0000-0000-0000-{i:012}");
            let link = format!("vless://{uuid}@10.0.0.{ip}:443?type=tcp#t{i}", ip = i % 250);
            import_single_link(&profile, &link).unwrap();
        }
        let final_store = load_node_store(&profile);
        assert_eq!(final_store.nodes.len(), MAX_NODES);
        // The anchor must still be present and active.
        assert!(final_store.nodes.iter().any(|n| n.id == "anchor"));
        assert_eq!(final_store.active_id.as_deref(), Some("anchor"));
    }
}
