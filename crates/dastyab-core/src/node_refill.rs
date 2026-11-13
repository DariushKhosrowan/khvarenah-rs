//! Autonomous config-refill orchestrator — the "never run out of working
//! configs" engine (doctrine §5: zero-config, self-healing).
//!
//! When the per-profile node pool has **no** node known healthy (empty pool,
//! or every stored node is dead/never-probed), DastYab must be able to
//! re-provision itself entirely out-of-band: recover fresh, free share-links
//! from Telegram channel archives (deep crawl) and public GitHub config repos,
//! probe them for real end-to-end reachability, and promote a working node to
//! active — with no human intervention.
//!
//! This module is the single seam that orchestrates that recovery:
//!
//! - [`refill_needed`] — a **pure** decision predicate (pool state → *should
//!   we harvest?*). Unit-testable, no I/O.
//! - [`REFILL_COOLDOWN_SECS`] — rate-limit so a permanently-dead network
//!   doesn't hammer Telegram/GitHub on every daemon tick.
//! - [`run_refill`] — the async orchestration: deep-harvest default Telegram
//!   channels, ingest GitHub sources, then probe + fail over. Returns a
//!   structured [`RefillReport`] with no fabricated success — every "healthy"
//!   count comes from a real probe.

use crate::config_store::{load_node_store, NodeStore};

/// Minimum seconds between autonomous refill passes. The daemon checks this
/// before invoking [`run_refill`], so a dead pool is topped up at most once
/// per cooldown window (not on every 300s tick).
pub const REFILL_COOLDOWN_SECS: i64 = 900;

/// How many archive pages to walk back per Telegram channel on refill
/// (deeper than the interactive default — recovery wants *old* configs too).
pub const DEFAULT_REFILL_DEPTH: usize = 6;

/// Default Telegram channels to harvest when the pool needs refilling.
/// Best-effort seed list ordered by observed plaintext-link yield (probed
/// live 2026-11-12): high-yield config-broadcast channels first. Channel
/// failures are tolerated (a 404/empty preview just contributes zero links).
/// Users may override via `dastyab configs refill --channels …`.
pub const DEFAULT_REFILL_CHANNELS: &[&str] = &[
    "v2ray_configs_pools", // ~286 links/page (top yield)
    "MARAMBASHI",          // ~180 links/page
    "v2raycollector",      // ~59 links/page
    "v2rayann",            // ~31 links/page
    "FreeV2rayConfigs",    // ~20 links/page
    "v2ray_team",          // ~15 links/page
    "proxy_v2ray",         // ~8 links/page
    "v2rayfree",           // ~7 links/page
    "v2ray_config",        // ~2 links/page (canonical anchor)
    "V2ray_Config",
    "configs_v2ray",
];

/// Gate for the daemon's autonomous refill. Production defaults to enabled.
/// Unit tests disable it (via `daemon_home`) so a daemon tick never triggers a
/// live Telegram/GitHub harvest in a hermetic test (which would block on the
/// network and hang the suite). Tests that specifically exercise refill
/// re-enable it explicitly.
static REFILL_ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Set whether autonomous refill may run. Tests set this to `false` to keep
/// daemon unit tests offline.
pub fn set_refill_enabled(v: bool) {
    REFILL_ENABLED.store(v, std::sync::atomic::Ordering::Relaxed);
}

/// Whether autonomous refill may run (production default: true).
pub fn refill_enabled() -> bool {
    REFILL_ENABLED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Structured outcome of one refill pass.
#[derive(Debug, Clone, Default)]
pub struct RefillReport {
    /// Whether a refill was actually warranted (see [`refill_needed`]).
    pub needed: bool,
    /// Human-readable reason refill triggered (present when `needed`).
    pub reason: Option<String>,
    /// Telegram channels harvested.
    pub telegram_channels: usize,
    /// Links found across all channels (pre-dedup).
    pub telegram_found: usize,
    /// New nodes added to the store from Telegram.
    pub telegram_added: usize,
    /// GitHub repos successfully ingested.
    pub github_repos_ok: usize,
    /// New nodes added to the store from GitHub.
    pub github_added: usize,
    /// Total nodes probed after harvest.
    pub probed: usize,
    /// Nodes that passed the live probe.
    pub healthy: usize,
    /// If the active node was dead and we promoted a healthy one, its id.
    pub promoted: Option<String>,
}

/// Pure decision: does this pool state warrant a refill pass?
///
/// Returns `Some(reason)` when yes, `None` when the pool already has a node
/// marked healthy (nothing to recover). The "known healthy" bar is strict:
/// a pool of never-probed nodes (`healthy = None`) counts as needing a refill
/// — we'd rather have a surplus of configs than rely on unverified ones.
pub fn refill_needed(store: &NodeStore) -> Option<&'static str> {
    if store.nodes.is_empty() {
        return Some("node pool is empty");
    }
    if !store.nodes.iter().any(|n| n.healthy == Some(true)) {
        return Some("no node is known healthy");
    }
    None
}

/// Run one autonomous refill pass:
///
/// 1. If the pool already has a known-healthy node, return immediately
///    (`needed = false`) — nothing to do.
/// 2. Otherwise harvest default Telegram channels (deep archive) and ingest
///    GitHub sources into the profile's node store.
/// 3. Probe every node and fail over to a verified-healthy one.
///
/// `use_proxy` routes every network hop through the local xray SOCKS5, so
/// recovery works even when direct foreign TCP is severed (NIN).
pub async fn run_refill(profile: &str, use_proxy: bool) -> RefillReport {
    run_refill_depth(profile, use_proxy, DEFAULT_REFILL_DEPTH).await
}

/// [`run_refill`] with an explicit archive `depth` (mainly for tests / CLI
/// override). `depth < 1` is clamped to 1.
pub async fn run_refill_depth(profile: &str, use_proxy: bool, depth: usize) -> RefillReport {
    let mut report = RefillReport::default();

    let store = load_node_store(profile);
    match refill_needed(&store) {
        None => return report, // already have a healthy node
        Some(reason) => {
            report.needed = true;
            report.reason = Some(reason.to_string());
        }
    }

    // --- Source 1: deep Telegram channel harvest ---
    // Merge the hardcoded default net with channels discovered by previous
    // `harvest --discover` passes, so autonomous recovery keeps widening its
    // sources (never hardcoded/circular).
    let mut chan_list: Vec<String> = DEFAULT_REFILL_CHANNELS
        .iter()
        .map(|s| s.to_string())
        .collect();
    let discovered = crate::harvest::load_discovered_channels(profile);
    for ch in discovered.channels {
        if !chan_list.contains(&ch) {
            chan_list.push(ch);
        }
    }
    let concurrency = chan_list.len().min(8);
    let tg_results =
        crate::harvest::harvest_many(profile, &chan_list, use_proxy, concurrency, depth.max(1))
            .await;
    report.telegram_channels = tg_results.len();
    for (_, h) in &tg_results {
        report.telegram_found += h.summary.found;
        report.telegram_added += h.summary.added;
    }

    // --- Source 2: GitHub config repos ---
    let gh = crate::gh_sources::ingest_github(profile, use_proxy, &[]).await;
    report.github_repos_ok = gh.repos_ok.len();
    report.github_added = gh.added;

    // --- Probe everything, then fail over to a working node ---
    let healed = crate::node_probe::selfheal(profile, use_proxy);
    report.probed = healed.probed;
    report.healthy = healed.healthy;
    report.promoted = healed.promoted;

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_store::V2RayNode;
    use crate::store::profiles::now_ts;

    fn node(healthy: Option<bool>) -> V2RayNode {
        V2RayNode {
            id: crate::store::new_id(),
            alias: "t".into(),
            url: "vless://u@127.0.0.1:1?type=tcp".into(),
            source_index: None,
            source: "test".into(),
            added_epoch: now_ts(),
            published_epoch: None,
            last_checked_epoch: None,
            healthy,
        }
    }

    #[test]
    fn empty_pool_needs_refill() {
        let s = NodeStore::default();
        assert_eq!(refill_needed(&s), Some("node pool is empty"));
    }

    #[test]
    fn never_probed_pool_needs_refill() {
        let mut s = NodeStore::default();
        s.nodes.push(node(None));
        assert_eq!(refill_needed(&s), Some("no node is known healthy"));
    }

    #[test]
    fn all_dead_pool_needs_refill() {
        let mut s = NodeStore::default();
        s.nodes.push(node(Some(false)));
        s.nodes.push(node(Some(false)));
        assert_eq!(refill_needed(&s), Some("no node is known healthy"));
    }

    #[test]
    fn healthy_pool_skips_refill() {
        let mut s = NodeStore::default();
        s.nodes.push(node(Some(true)));
        s.nodes.push(node(Some(false)));
        assert_eq!(refill_needed(&s), None);
    }

    #[test]
    fn healthy_and_never_probed_skips_refill() {
        let mut s = NodeStore::default();
        s.nodes.push(node(Some(true)));
        s.nodes.push(node(None));
        assert_eq!(refill_needed(&s), None);
    }

    /// Full orchestration short-circuits (no network I/O) when the pool
    /// already has a known-healthy node.
    #[tokio::test]
    async fn run_refill_skips_network_when_pool_healthy() {
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(dir.path().join("mem"));
        let profile = "refill-ok".to_string();

        // Seed a healthy node.
        let mut store = NodeStore::default();
        store.nodes.push(node(Some(true)));
        crate::config_store::save_node_store(&profile, &store).unwrap();

        let report = run_refill(&profile, false).await;
        assert!(!report.needed, "healthy pool must skip the refill pass");
        assert!(report.reason.is_none());
        // No harvest / probe work may have run.
        assert_eq!(report.telegram_channels, 0);
        assert_eq!(report.probed, 0);
    }
}
