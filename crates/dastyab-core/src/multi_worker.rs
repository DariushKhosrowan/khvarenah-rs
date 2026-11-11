//! Multi-worker parallel redundancy (round 19 / DeepSeek plan #1).
//!
//! ## Why this exists
//!
//! The app currently deploys a single CF worker per profile. A CF worker is a
//! single point of failure at the *worker* level: if it is suspended,
//! rate-limited, or its subdomain is blocked, the whole tunnel dies until the
//! rescue chain redeploys it. The account-level failover (round 10) handles
//! the *account* being suspended, but not the individual worker.
//!
//! This module ships a `WorkerSet`: a persistent collection of N deployed
//! workers (each with its own name, UUID and path). It can:
//!
//! - deploy workers in parallel (`deploy_worker_in_parallel`),
//! - probe all workers' step-0 health concurrently and pick the healthiest
//!   (`select_healthiest`),
//! - fail over from the active worker to a healthy standby automatically
//!   (`failover_worker_set`), mirroring the account-level `decide_failover`.
//!
//! All decision logic is pure and unit-testable; the side-effecting CF calls
//! go through a `WorkerPeer` trait (same pattern as `RescuePeer` /
//! `MutationPeer`).
//!
//! ## Scope / fidelity
//!
//! Reconciled to the real repo: worker names come from
//! `crate::worker::worker_name_from_account`, deploy mechanics reuse the
//! `cf::Client` + `presets::fallback_worker_js` path, and each worker gets its
//! own UUID via `crate::worker::generate_uuid`. The set is persisted in
//! `ProfileConfig.worker_set` (serde-default -> migration-safe).

use crate::error::CFError;
use crate::store::profiles;
use crate::vless::VlessProfile;
use serde::{Deserialize, Serialize};

/// Hard cap on how many parallel workers a profile will maintain.
pub const MAX_WORKERS: usize = 3;
/// Default number of workers a profile tries to keep.
pub const DEFAULT_WORKER_COUNT: usize = 2;

/// One deployed worker in a profile's set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkerEntry {
    /// Unique slug used on the CF side.
    pub name: String,
    /// Full hostname (`<name>.<subdomain>.workers.dev`).
    pub host: String,
    /// The VLESS UUID for this worker.
    pub uuid: String,
    /// Epoch seconds deployed.
    pub deployed_ts: i64,
    /// Whether this is currently the active (selected) worker.
    #[serde(default)]
    pub active: bool,
}

impl WorkerEntry {
    /// Build the VLESS share link for this worker.
    pub fn vless_link(&self) -> String {
        let profile = VlessProfile {
            uuid: self.uuid.clone(),
            address: self.host.clone(),
            port: 443,
            security: "tls".into(),
            path: "/".into(),
            transport: "ws".into(),
            name: format!("{}-edge", self.name),
            ..Default::default()
        };
        profile.share_link()
    }
}

/// The full worker set for a profile. Persisted under config.worker_set.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkerSet {
    /// All deployed workers.
    pub workers: Vec<WorkerEntry>,
}

impl WorkerSet {
    pub fn active_worker(&self) -> Option<&WorkerEntry> {
        self.workers.iter().find(|w| w.active)
    }

    /// Clear the active flag and mark `name` as the active worker (if present).
    pub fn set_active(&mut self, name: &str) {
        for w in self.workers.iter_mut() {
            w.active = w.name == name;
        }
    }

    pub fn get(&self, name: &str) -> Option<&WorkerEntry> {
        self.workers.iter().find(|w| w.name == name)
    }

    pub fn len(&self) -> usize {
        self.workers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.workers.is_empty()
    }
}

/// Pure decision: given a `WorkerSet` and the set of healthy worker names,
/// which worker should be active next? Returns `None` if the active worker is
/// already healthy.
pub fn select_active_worker(set: &WorkerSet, healthy: &[String]) -> Option<String> {
    let cur = set.active_worker();
    if let Some(c) = cur {
        if healthy.iter().any(|h| h == &c.name) {
            // Current worker still healthy — no change.
            return None;
        }
    }
    // Pick the first healthy worker (prefer the previously active if it's
    // healthy, else first healthy).
    for h in healthy {
        if set.get(h).is_some() {
            return Some(h.clone());
        }
    }
    None
}

/// Pure decision: is failover needed? True when the active worker is not in
/// the healthy set (or the set is empty).
pub fn should_failover(set: &WorkerSet, healthy: &[String]) -> bool {
    match set.active_worker() {
        Some(a) => !healthy.iter().any(|h| h == &a.name),
        None => !set.is_empty(),
    }
}

/// Pure decision: how many workers should be deployed given the desired count
/// and what already exists. Never exceeds `MAX_WORKERS`.
pub fn workers_to_deploy(existing: usize, desired: usize) -> usize {
    let desired = desired.min(MAX_WORKERS);
    desired.saturating_sub(existing.min(desired))
}

/// Generate a deterministic-but-distinct worker name variant for index `i`.
/// Keeps the base slug readable while guaranteeing uniqueness within a set.
pub fn worker_name_variant(base: &str, i: usize) -> String {
    let base = crate::worker::safe_worker_name(base);
    let base = base.chars().take(24).collect::<String>();
    if base.is_empty() {
        format!("cf-worker-proxy-{i}")
    } else {
        format!("{base}-{i}")
    }
}

/// Abstraction over the side-effecting worker deployment/healthPro so the
/// orchestration logic is unit-testable without a live CF token / network
/// (mirrors `RescuePeer` / `MutationPeer`).
#[allow(async_fn_in_trait)]
pub trait WorkerPeer: Send + Sync {
    /// Deploy a worker named `name` under `account_id` and return its hostname.
    /// The worker gets a fresh UUID (rotated on the CF side).
    async fn deploy_worker(
        &self,
        profile_id: &str,
        account_id: &str,
        name: &str,
        uuid: &str,
    ) -> Result<String, CFError>;

    /// Probe a worker's step-0 health. Returns `true` if alive.
    async fn worker_alive(&self, host: &str) -> bool;

    /// Persist the worker set for a profile.
    fn save_set(&self, profile_id: &str, set: &WorkerSet) -> Result<(), CFError>;
}

/// Orchestrate parallel deployment of `desired` workers for a profile.
///
/// Existing workers in the set are preserved; only the missing count is
/// deployed. Each new worker gets a distinct name variant and a fresh UUID.
/// The first worker in the set becomes active if none is active yet.
pub async fn deploy_worker_in_parallel<P: WorkerPeer>(
    peer: &P,
    profile_id: &str,
    account_id: &str,
    subdomain: &str,
    desired: usize,
) -> Result<WorkerSet, CFError> {
    let mut set = profiles::load_profile(profile_id).config.worker_set;
    let _ = subdomain; // RealWorkerPeer resolves the subdomain itself.
                       // Base name derived from the account (matches bootstrap/redeploy).
    let base = crate::worker::worker_name_from_account(Some(account_id));
    let need = workers_to_deploy(set.len(), desired);

    // Pick existing name variants so we never collide.
    let mut next_index = set.len();
    let mut deployed = 0;
    // Bound the number of deploy attempts so a failing CF API can't spin
    // forever; we try at most `need` successful + a few extra name variants.
    let mut attempts = 0;
    let max_attempts = need + MAX_WORKERS;
    while deployed < need && attempts < max_attempts {
        attempts += 1;
        let name = worker_name_variant(&base, next_index);
        next_index += 1;
        let uuid = crate::worker::generate_uuid();
        let host = match peer
            .deploy_worker(profile_id, account_id, &name, &uuid)
            .await
        {
            Ok(h) => h,
            Err(_) => continue, // skip workers that fail to deploy
        };
        set.workers.push(WorkerEntry {
            name: name.clone(),
            host,
            uuid,
            deployed_ts: crate::store::now_ts() as i64,
            active: set.workers.is_empty() && set.active_worker().is_none(),
        });
        // Keep the set capped.
        if set.workers.len() > MAX_WORKERS {
            // Drop the oldest non-active worker.
            let drop_idx = set
                .workers
                .iter()
                .enumerate()
                .find(|(_, w)| !w.active)
                .map(|(i, _)| i);
            if let Some(i) = drop_idx {
                set.workers.remove(i);
            }
        }
        deployed += 1;
    }

    peer.save_set(profile_id, &set)?;
    Ok(set)
}

/// Probe every worker in the set concurrently and return the healthy names.
pub async fn probe_worker_set<P: WorkerPeer>(peer: &P, set: &WorkerSet) -> Vec<String> {
    let mut healthy = Vec::new();
    let mut futures = Vec::new();
    for w in &set.workers {
        let host = w.host.clone();
        let host_probe = host.clone();
        futures.push(async move { (host, peer.worker_alive(&host_probe).await) });
    }
    let results = futures_util::future::join_all(futures).await;
    for (host, alive) in results {
        if alive {
            healthy.push(host);
        }
    }
    // Map hosts back to names.
    healthy
        .iter()
        .filter_map(|h| {
            set.workers
                .iter()
                .find(|w| &w.host == h)
                .map(|w| w.name.clone())
        })
        .collect()
}

/// Fail over the active worker to the healthiest standby. Returns `true` if
/// the active worker changed.
pub async fn failover_worker_set<P: WorkerPeer>(
    peer: &P,
    profile_id: &str,
) -> Result<bool, CFError> {
    let mut set = profiles::load_profile(profile_id).config.worker_set;
    if set.is_empty() {
        return Ok(false);
    }
    let healthy = probe_worker_set(peer, &set).await;
    if let Some(new_active) = select_active_worker(&set, &healthy) {
        if set.active_worker().map(|w| w.name.as_str()) != Some(new_active.as_str()) {
            set.set_active(&new_active);
            peer.save_set(profile_id, &set)?;
            return Ok(true);
        }
    }
    Ok(false)
}

/// Real `WorkerPeer`: talks to the live Cloudflare API and network.
pub struct RealWorkerPeer;

impl WorkerPeer for RealWorkerPeer {
    async fn deploy_worker(
        &self,
        profile_id: &str,
        account_id: &str,
        name: &str,
        uuid: &str,
    ) -> Result<String, CFError> {
        let label = profiles::get_active_token(profile_id)?;
        let token = match label {
            Some(l) => profiles::get_token(profile_id, &l)?.ok_or_else(|| {
                CFError::new("Redeploy", "Active token not found.", "Re-add the token.")
            })?,
            None => {
                return Err(CFError::new(
                    "Redeploy",
                    "No active token for this profile.",
                    "Set an active token before enabling multi-worker deploys.",
                ))
            }
        };
        let client = crate::cf::Client::new(&token);
        let subdomain = client.get_subdomain(account_id).await?;
        if subdomain.is_empty() {
            return Err(CFError::new(
                "No subdomain",
                "The account has no Workers subdomain configured.",
                "Set a workers.dev subdomain in the CF dashboard.",
            ));
        }
        let js = crate::presets::fallback_worker_js().into_bytes();
        client
            .deploy_script(account_id, name, js, "2026-07-01", 2)
            .await?;
        client
            .set_vars(
                account_id,
                name,
                serde_json::Map::from_iter([("UUID".into(), serde_json::json!(uuid))]),
            )
            .await?;
        Ok(format!("{name}.{subdomain}.workers.dev"))
    }

    async fn worker_alive(&self, host: &str) -> bool {
        let doh = crate::doh::DohResolver::new();
        matches!(
            crate::autopilot::probe_worker_health(host, None, Some(&doh), 8).await,
            crate::autopilot::WorkerHealth::Alive
        )
    }

    fn save_set(&self, profile_id: &str, set: &WorkerSet) -> Result<(), CFError> {
        let mut p = profiles::load_profile(profile_id);
        p.config.worker_set = set.clone();
        profiles::save_profile(&p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn make_set(names: &[&str], active: Option<&str>) -> WorkerSet {
        let mut workers = Vec::new();
        for (i, n) in names.iter().enumerate() {
            workers.push(WorkerEntry {
                name: n.to_string(),
                host: format!("{n}.sub.workers.dev"),
                uuid: format!("uuid-{i}"),
                deployed_ts: 1_000_000 + i as i64,
                active: active == Some(*n),
            });
        }
        WorkerSet { workers }
    }

    #[test]
    fn select_active_worker_keeps_healthy_active() {
        let set = make_set(&["a", "b"], Some("a"));
        let healthy = vec!["a".to_string(), "b".to_string()];
        assert_eq!(select_active_worker(&set, &healthy), None);
    }

    #[test]
    fn select_active_worker_fails_over_when_active_dead() {
        let set = make_set(&["a", "b"], Some("a"));
        let healthy = vec!["b".to_string()];
        assert_eq!(select_active_worker(&set, &healthy), Some("b".to_string()));
    }

    #[test]
    fn should_failover_true_when_active_dead() {
        let set = make_set(&["a", "b"], Some("a"));
        assert!(should_failover(&set, &["b".to_string()]));
        assert!(!should_failover(&set, &["a".to_string(), "b".to_string()]));
    }

    #[test]
    fn should_failover_false_when_no_workers() {
        let set = WorkerSet::default();
        assert!(!should_failover(&set, &[]));
    }

    #[test]
    fn workers_to_deploy_clamped_to_max() {
        assert_eq!(workers_to_deploy(0, 99), MAX_WORKERS);
        assert_eq!(workers_to_deploy(1, 3), 2);
        assert_eq!(workers_to_deploy(2, 2), 0);
        assert_eq!(workers_to_deploy(0, 1), 1);
    }

    #[test]
    fn worker_name_variant_unique_and_safe() {
        let a = worker_name_variant("Hello Worker", 0);
        let b = worker_name_variant("Hello Worker", 1);
        assert_ne!(a, b);
        assert_eq!(a, "hello-worker-0");
        assert_eq!(b, "hello-worker-1");
    }

    #[test]
    fn set_active_only_marks_one() {
        let mut set = make_set(&["a", "b"], Some("a"));
        set.set_active("b");
        assert_eq!(set.active_worker().map(|w| w.name.as_str()), Some("b"));
        assert_eq!(set.workers.iter().filter(|w| w.active).count(), 1);
    }

    /// Fake `WorkerPeer` with scripted health + a captured save payload.
    struct FakeWorkerPeer {
        alive_hosts: Vec<String>,
        deploy_ok: bool,
        saved: std::sync::Mutex<Option<WorkerSet>>,
    }

    impl WorkerPeer for FakeWorkerPeer {
        async fn deploy_worker(
            &self,
            _profile_id: &str,
            _account_id: &str,
            name: &str,
            _uuid: &str,
        ) -> Result<String, CFError> {
            if self.deploy_ok {
                Ok(format!("{name}.sub.workers.dev"))
            } else {
                Err(CFError::new("deploy", "failed", "test"))
            }
        }

        async fn worker_alive(&self, host: &str) -> bool {
            self.alive_hosts.iter().any(|h| h == host)
        }

        fn save_set(&self, _profile_id: &str, set: &WorkerSet) -> Result<(), CFError> {
            *self.saved.lock().unwrap() = Some(set.clone());
            Ok(())
        }
    }

    #[tokio::test]
    async fn failover_worker_set_switches_to_healthy_standby() {
        let tmp = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(tmp.path().to_path_buf());
        let id = crate::store::profiles::create_profile("t", "").unwrap();
        let set = make_set(&["a", "b"], Some("a"));
        // Persist the set so load_profile sees it.
        let mut p = crate::store::profiles::load_profile(&id);
        p.config.worker_set = set;
        crate::store::profiles::save_profile(&p).unwrap();
        let peer = FakeWorkerPeer {
            alive_hosts: vec!["b.sub.workers.dev".to_string()],
            deploy_ok: true,
            saved: std::sync::Mutex::new(None),
        };
        let changed = failover_worker_set(&peer, &id).await.unwrap();
        assert!(changed);
        let saved = peer.saved.lock().unwrap();
        assert_eq!(
            saved
                .as_ref()
                .unwrap()
                .active_worker()
                .map(|w| w.name.as_str()),
            Some("b")
        );
    }

    #[tokio::test]
    async fn failover_worker_set_noop_when_active_healthy() {
        let tmp = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(tmp.path().to_path_buf());
        let id = crate::store::profiles::create_profile("t", "").unwrap();
        let set = make_set(&["a", "b"], Some("a"));
        let mut p = crate::store::profiles::load_profile(&id);
        p.config.worker_set = set;
        crate::store::profiles::save_profile(&p).unwrap();
        let peer = FakeWorkerPeer {
            alive_hosts: vec![
                "a.sub.workers.dev".to_string(),
                "b.sub.workers.dev".to_string(),
            ],
            deploy_ok: true,
            saved: std::sync::Mutex::new(None),
        };
        let changed = failover_worker_set(&peer, &id).await.unwrap();
        assert!(!changed);
    }

    #[tokio::test]
    async fn deploy_worker_in_parallel_adds_missing_workers() {
        let tmp = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(tmp.path().to_path_buf());
        let id = crate::store::profiles::create_profile("t", "").unwrap();
        let peer = FakeWorkerPeer {
            alive_hosts: vec![],
            deploy_ok: true,
            saved: std::sync::Mutex::new(None),
        };
        let set = deploy_worker_in_parallel(&peer, &id, "acc", "", 2)
            .await
            .unwrap();
        assert_eq!(set.len(), 2);
        // First deployed worker becomes active. Base name derives from the
        // account ("acc" -> safe name "acc"), so the variants are acc-0, acc-1.
        assert_eq!(set.active_worker().map(|w| w.name.as_str()), Some("acc-0"));
    }
}
