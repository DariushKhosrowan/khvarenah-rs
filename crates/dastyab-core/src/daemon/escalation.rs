//! Blackout escalation — the daemon tries harder the longer a blackout lasts.
//!
//! During a total blackout the survival strategy should *not* be static: hour 1
//! and hour 48 of an outage deserve different probe budgets. This module models
//! that escalation as a pure, offline, fully testable component.
//!
//! - [`EscalationPlan`] — the knobs for a given blackout duration: probe
//!   interval, parallel-probe count, whether SNI rotation is faster, and the
//!   worker-refresh interval.
//! - [`escalation_plan`] — pure tiering (0 / 1h / 6h / 24h / 72h), monotonic
//!   in parallel probes (ascending) and probe interval (descending).
//! - [`BlackoutClock`] — tracks when the blackout started so `elapsed_secs`
//!   can be fed to [`escalation_plan`].
//! - [`apply_plan_to_tick`] — writes a plan through to a [`TickTarget`] (the
//!   daemon's tick knobs), with no new I/O.
//! - [`escalated_select`] — combines the carrier pool's cooldown-aware
//!   selection with an *expiry-fill* refinement: when not enough endpoints are
//!   available (all cooling), fill the remainder from the cooling endpoints
//!   ordered by soonest cooldown expiry. This is the escalation-appropriate
//!   alternative to a blind cooldown bypass — a long blackout doesn't starve,
//!   but it still prefers endpoints most likely to be back soon.

use crate::carrier_pool::{CarrierEndpoint, CarrierKind, CarrierPool, CarrierPoolError};

/// Default (baseline, non-escalated) probe cadence, seconds.
pub const BASELINE_PROBE_INTERVAL_SECS: u64 = 60;
/// Fastest useful probe cadence across escalation tiers, seconds.
pub const MAX_ESCALATION_PROBE_INTERVAL_SECS: u64 = 15;

/// The daemon's per-tick knobs that escalation can tune.
///
/// This is intentionally a plain value struct (not tied to I/O) so
/// [`apply_plan_to_tick`] is pure and unit-testable. The daemon reads these
/// when deciding sleep/probe behavior for the tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TickTarget {
    /// Daemon poll cadence while the network is down (blackout).
    pub probe_interval_secs: u64,
    /// Number of probes to run (plumbed through; execution may remain serial).
    pub parallel_probes: u8,
    /// Whether the exclusive-SNI strategy rotation cadence should be faster.
    pub sni_rotation_faster: bool,
    /// Cadence for worker-mediated carrier refresh during a blackout.
    pub refresh_via_worker_interval_secs: u64,
}

impl Default for TickTarget {
    fn default() -> Self {
        Self {
            probe_interval_secs: BASELINE_PROBE_INTERVAL_SECS,
            parallel_probes: 1,
            sni_rotation_faster: false,
            refresh_via_worker_interval_secs: 900,
        }
    }
}

/// The knobs active at a given blackout duration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EscalationPlan {
    pub probe_interval_secs: u64,
    pub parallel_probes: u8,
    pub expiry_fill_top: u8,
    pub sni_rotation_faster: bool,
    pub refresh_via_worker_interval_secs: u64,
}

impl Default for EscalationPlan {
    fn default() -> Self {
        // Baseline tier (blackout duration 0).
        Self {
            probe_interval_secs: BASELINE_PROBE_INTERVAL_SECS,
            parallel_probes: 1,
            expiry_fill_top: 0,
            sni_rotation_faster: false,
            refresh_via_worker_interval_secs: 900,
        }
    }
}

/// Tier boundaries in seconds.
pub const TIER_1H: u64 = 3600;
pub const TIER_6H: u64 = 6 * 3600;
pub const TIER_24H: u64 = 24 * 3600;
pub const TIER_72H: u64 = 72 * 3600;

/// Pure: return the escalation plan for a blackout of `blackout_secs`.
///
/// Tiers: 0 (baseline) → 1h → 6h → 24h → 72h (capped at max). The plan is
/// monotonic: `parallel_probes` never decreases and `probe_interval_secs`
/// never increases as the blackout lengthens.
pub fn escalation_plan(blackout_secs: u64) -> EscalationPlan {
    if blackout_secs >= TIER_72H {
        EscalationPlan {
            probe_interval_secs: MAX_ESCALATION_PROBE_INTERVAL_SECS,
            parallel_probes: 5,
            expiry_fill_top: 3,
            sni_rotation_faster: true,
            refresh_via_worker_interval_secs: 120,
        }
    } else if blackout_secs >= TIER_24H {
        EscalationPlan {
            probe_interval_secs: 20,
            parallel_probes: 4,
            expiry_fill_top: 3,
            sni_rotation_faster: true,
            refresh_via_worker_interval_secs: 180,
        }
    } else if blackout_secs >= TIER_6H {
        EscalationPlan {
            probe_interval_secs: 30,
            parallel_probes: 3,
            expiry_fill_top: 2,
            sni_rotation_faster: false,
            refresh_via_worker_interval_secs: 300,
        }
    } else if blackout_secs >= TIER_1H {
        EscalationPlan {
            probe_interval_secs: 45,
            parallel_probes: 2,
            expiry_fill_top: 1,
            sni_rotation_faster: false,
            refresh_via_worker_interval_secs: 600,
        }
    } else {
        EscalationPlan::default()
    }
}

/// Tracks when the current blackout began so elapsed duration can be computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlackoutClock {
    since: Option<u64>,
}

impl BlackoutClock {
    pub fn new() -> Self {
        Self { since: None }
    }

    /// Construct from an optional "since" timestamp (used by the daemon to
    /// restore clock state across ticks without exposing the private field).
    pub(crate) fn from_since(since: Option<u64>) -> Self {
        Self { since }
    }

    /// Mark the blackout as starting at `now`.
    pub fn enter(&mut self, now: u64) {
        self.since = Some(now);
    }

    /// Clear the blackout state (call on network restore).
    pub fn exit(&mut self) {
        self.since = None;
    }

    /// Seconds since the blackout began. 0 when not in a blackout.
    pub fn elapsed_secs(&self, now: u64) -> u64 {
        match self.since {
            Some(s) if now >= s => now - s,
            _ => 0,
        }
    }

    /// Whether the clock is currently in a blackout.
    pub fn is_active(&self) -> bool {
        self.since.is_some()
    }
}

impl Default for BlackoutClock {
    fn default() -> Self {
        Self::new()
    }
}

/// Write a plan through to a [`TickTarget`]. Pure — no I/O.
pub fn apply_plan_to_tick(plan: &EscalationPlan, target: &mut TickTarget) {
    target.probe_interval_secs = plan.probe_interval_secs;
    target.parallel_probes = plan.parallel_probes;
    target.sni_rotation_faster = plan.sni_rotation_faster;
    target.refresh_via_worker_interval_secs = plan.refresh_via_worker_interval_secs;
}

/// Escalation-aware carrier selection.
///
/// Uses [`CarrierPool::select_at`] to get the available (non-cooling)
/// endpoints. If fewer than the requested count are available, fills the
/// remainder from the cooling endpoints ordered by soonest cooldown expiry
/// (the *expiry-fill* refinement) — a long blackout doesn't starve itself on
/// cooldowns, but it still prefers the endpoints most likely to be back soon.
pub fn escalated_select(
    pool: &CarrierPool,
    kind: CarrierKind,
    n: usize,
    now_unix: u64,
) -> Result<Vec<CarrierEndpoint>, CarrierPoolError> {
    let available = pool.select_at(kind, n, now_unix)?;
    if available.len() >= n {
        return Ok(available);
    }
    // Fill from cooling endpoints not already selected, soonest-expiry first.
    let snap = pool.load()?;
    let present: std::collections::HashSet<String> = available
        .iter()
        .map(CarrierPool::endpoint_id_hex)
        .collect();
    let mut cooling: Vec<(String, CarrierEndpoint)> = Vec::new();
    for e in snap.endpoints.iter().filter(|e| e.kind == kind) {
        let id = CarrierPool::endpoint_id_hex(e);
        if present.contains(&id) {
            continue;
        }
        if snap
            .penalties
            .get(&id)
            .is_some_and(|p| p.cooldown_until_unix > now_unix)
        {
            cooling.push((id, e.clone()));
        }
    }
    cooling.sort_by_key(|(id, _)| {
        snap.penalties
            .get(id)
            .map(|p| p.cooldown_until_unix)
            .unwrap_or(u64::MAX)
    });
    let mut result = available;
    for (_id, e) in cooling {
        if result.len() >= n {
            break;
        }
        result.push(e);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escalation_plan_zero_is_baseline() {
        let p = escalation_plan(0);
        assert_eq!(p, EscalationPlan::default());
        assert_eq!(p.probe_interval_secs, BASELINE_PROBE_INTERVAL_SECS);
        assert_eq!(p.parallel_probes, 1);
        assert!(!p.sni_rotation_faster);
    }

    #[test]
    fn escalation_plan_is_monotonic_across_tiers() {
        let t0 = escalation_plan(0);
        let t1 = escalation_plan(TIER_1H);
        let t6 = escalation_plan(TIER_6H);
        let t24 = escalation_plan(TIER_24H);
        let t72 = escalation_plan(TIER_72H);
        let all = [t0, t1, t6, t24, t72];
        for w in all.windows(2) {
            assert!(w[1].parallel_probes >= w[0].parallel_probes);
            assert!(w[1].probe_interval_secs <= w[0].probe_interval_secs);
        }
        assert_eq!(t72.probe_interval_secs, MAX_ESCALATION_PROBE_INTERVAL_SECS);
        assert_eq!(t72.parallel_probes, 5);
        assert!(t72.sni_rotation_faster);
    }

    #[test]
    fn escalation_plan_72h_is_max() {
        let p = escalation_plan(200 * 3600);
        assert_eq!(p.probe_interval_secs, MAX_ESCALATION_PROBE_INTERVAL_SECS);
        assert_eq!(p.parallel_probes, 5);
        // capped — a longer blackout does not escalate further
        let p2 = escalation_plan(1000 * 3600);
        assert_eq!(p, p2);
    }

    #[test]
    fn blackout_clock_elapsed_and_reset() {
        let mut c = BlackoutClock::new();
        assert_eq!(c.elapsed_secs(5000), 0);
        assert!(!c.is_active());
        c.enter(1000);
        assert!(c.is_active());
        assert_eq!(c.elapsed_secs(1050), 50);
        assert_eq!(c.elapsed_secs(2000), 1000);
        c.exit();
        assert!(!c.is_active());
        assert_eq!(c.elapsed_secs(5000), 0);
    }

    #[test]
    fn apply_plan_writes_through_to_tick_cfg() {
        let mut target = TickTarget::default();
        let plan = escalation_plan(TIER_24H);
        apply_plan_to_tick(&plan, &mut target);
        assert_eq!(target.probe_interval_secs, plan.probe_interval_secs);
        assert_eq!(target.parallel_probes, plan.parallel_probes);
        assert_eq!(target.sni_rotation_faster, plan.sni_rotation_faster);
        assert_eq!(
            target.refresh_via_worker_interval_secs,
            plan.refresh_via_worker_interval_secs
        );
    }

    fn tmp_pool_with(hosts: &[&str]) -> (tempfile::TempDir, CarrierPool) {
        use crate::carrier_pool::{CarrierProvenance, CarrierSnapshot};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("carrier_pool.json");
        let pool = CarrierPool::open(&path).unwrap();
        let mut snap = CarrierSnapshot::new_empty(1000);
        for h in hosts {
            snap.endpoints.push(CarrierEndpoint {
                kind: CarrierKind::WorkerData,
                host: h.to_string(),
                port: 443,
                sni: None,
                worker_url: Some(format!("https://{h}")),
                upstream: Some(format!("{h}:443")),
                weight: 0.8,
                last_probe_ok_unix: None,
                last_probe_rtt_ms: None,
                provenance: CarrierProvenance::Deployed,
            });
        }
        snap.sign().unwrap();
        pool.store_atomic(&snap).unwrap();
        (dir, pool)
    }

    #[test]
    fn escalated_select_returns_all_when_available() {
        let (_d, pool) = tmp_pool_with(&["a.example.com", "b.example.com"]);
        let sel = escalated_select(&pool, CarrierKind::WorkerData, 8, 1000).unwrap();
        assert_eq!(sel.len(), 2);
    }

    #[test]
    fn escalated_select_expiry_fill_picks_soonest_expiring() {
        let (_d, pool) = tmp_pool_with(&["a.example.com", "b.example.com", "c.example.com"]);
        let snap = pool.load().unwrap();
        // cooldown all three at different expiries
        pool.record_failure(&snap.endpoints[0], 1000).unwrap(); // streak1 → expires 1120
        pool.record_failure(&snap.endpoints[1], 1000).unwrap();
        pool.record_failure(&snap.endpoints[1], 1010).unwrap(); // streak2 → expires 1250
        pool.record_failure(&snap.endpoints[2], 1000).unwrap();
        // all cooling → select_at falls back to all; expiry-fill must order
        // by soonest expiry (a=1120 first)
        let sel = escalated_select(&pool, CarrierKind::WorkerData, 8, 1001).unwrap();
        assert_eq!(sel.len(), 3);
        assert_eq!(sel[0].host, "a.example.com");
    }

    #[test]
    fn escalated_select_fills_only_to_requested_count() {
        let (_d, pool) = tmp_pool_with(&["a.example.com", "b.example.com"]);
        let snap = pool.load().unwrap();
        pool.record_failure(&snap.endpoints[0], 1000).unwrap();
        pool.record_failure(&snap.endpoints[1], 1000).unwrap();
        let sel = escalated_select(&pool, CarrierKind::WorkerData, 1, 1001).unwrap();
        assert_eq!(sel.len(), 1);
        assert_eq!(sel[0].host, "a.example.com");
    }
}
