//! Explicit blackout state machine + human-free carrier reselection.
//!
//! The classic ladder descends Direct → DoH → DoT → DNS-tunnel but does not
//! *know* it is in blackout — it keeps burning cycles probing dead direct paths
//! instead of fast-failing to the worker bootstrap and rotating carriers from
//! the offline [`CarrierPool`](crate::carrier_pool::CarrierPool).
//!
//! This module is a **pure, socket-free** controller: [`BlackoutController::next`]
//! consumes [`BlackoutInputs`] (probe booleans + pool counts) and returns the one
//! [`BlackoutAction`] the daemon should take. [`resolve_action`] resolves the
//! action against the pool (the only filesystem touch). The daemon wires these
//! into its tier-decision seam — see [`decide_next_tier`].

use crate::carrier_pool::{CarrierEndpoint, CarrierKind, CarrierPool, CarrierPoolError};
use serde::{Deserialize, Serialize};

/// Where the daemon currently believes it is on the connectivity ladder.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkState {
    Direct,
    Doh,
    Dot,
    WorkerTunnel,
    Blackout,
}

/// The one action to take this tick.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum BlackoutAction {
    /// Stay put (current tier healthy, or nothing to do).
    Hold,
    /// A strictly-higher tier recovered — climb to it.
    ClimbTo(LinkState),
    /// Direct + all DNS rungs are down but the worker tunnel is up: jump
    /// straight to the worker bootstrap now (don't waste ticks probing dead
    /// tiers).
    FastFailToWorkerBootstrap,
    /// Worker liveness just recovered — refresh the carrier pool via the
    /// worker control plane (log no-op until the refresh feature lands).
    RefreshViaWorkerTunnel,
    /// Reselect `n` carriers of `kind` from the offline pool.
    ReselectCarrier { kind: CarrierKind, n: usize },
}

/// Everything `next` needs to decide — all pure, pre-probed.
#[derive(Clone, Debug)]
pub struct BlackoutInputs {
    pub now_unix: u64,
    pub direct_ok: bool,
    pub doh_ok: bool,
    pub dot_ok: bool,
    pub worker_tunnel_ok: bool,
    pub pool_worker_tunnel_count: usize,
    pub pool_worker_data_count: usize,
}

/// Hysteresis: descend only after `DESCEND_THRESHOLD` consecutive failures.
pub const DESCEND_THRESHOLD: u8 = 2;

/// The blackout controller state machine.
#[derive(Debug, Clone)]
pub struct BlackoutController {
    state: LinkState,
    /// Consecutive failures at the current state; descends only at >= 2.
    consecutive_fail: u8,
    /// Whether the worker tunnel was previously down (for the refresh edge).
    worker_was_down: bool,
}

impl Default for BlackoutController {
    fn default() -> Self {
        Self::new()
    }
}

impl BlackoutController {
    pub fn new() -> Self {
        Self {
            state: LinkState::Direct,
            consecutive_fail: 0,
            worker_was_down: false,
        }
    }

    pub fn state(&self) -> LinkState {
        self.state
    }

    /// Reset to an arbitrary state (tests / manual override).
    pub fn reset_to(&mut self, s: LinkState) {
        self.state = s;
        self.consecutive_fail = 0;
        self.worker_was_down = false;
    }

    /// Pure decision. Returns the one action to take this tick.
    ///
    /// Precedence (matches the architect's behavior contract):
    /// 1. Fast-fail: all direct/DNS rungs down but worker tunnel up, and we
    ///    are at a direct/DNS tier → jump to the worker bootstrap now; if we
    ///    are already on the worker tunnel, reselect worker-data carriers.
    /// 2. Refresh edge: worker liveness just transitioned false → true while
    ///    in worker-tunnel/blackout state → refresh the carrier pool.
    /// 3. Blackout recovery: any tier OK → climb to the highest OK tier.
    /// 4. Current tier healthy → hold (with opportunistic climb if a strictly-
    ///    higher tier recovered).
    /// 5. Otherwise increment the failure hysteresis; descend / enter blackout
    ///    only after `DESCEND_THRESHOLD` consecutive failures.
    pub fn next(&mut self, inputs: &BlackoutInputs) -> BlackoutAction {
        // 1. Fast-fail.
        if !inputs.direct_ok && !inputs.doh_ok && !inputs.dot_ok && inputs.worker_tunnel_ok {
            match self.state {
                LinkState::Direct | LinkState::Doh | LinkState::Dot => {
                    self.consecutive_fail = 0;
                    self.state = LinkState::WorkerTunnel;
                    self.worker_was_down = false;
                    return BlackoutAction::FastFailToWorkerBootstrap;
                }
                LinkState::WorkerTunnel => {
                    self.consecutive_fail = 0;
                    return BlackoutAction::ReselectCarrier {
                        kind: CarrierKind::WorkerData,
                        n: 8,
                    };
                }
                LinkState::Blackout => {}
            }
        }

        // 2. Refresh edge: worker recovered while in worker-tunnel/blackout.
        if self.worker_was_down
            && inputs.worker_tunnel_ok
            && matches!(self.state, LinkState::WorkerTunnel | LinkState::Blackout)
        {
            self.worker_was_down = false;
            self.consecutive_fail = 0;
            return BlackoutAction::RefreshViaWorkerTunnel;
        }

        // 3. Blackout recovery: climb to the highest OK tier.
        if self.state == LinkState::Blackout {
            if let Some(higher) = highest_ok(inputs) {
                self.state = higher;
                self.consecutive_fail = 0;
                self.worker_was_down = !inputs.worker_tunnel_ok;
                return BlackoutAction::ClimbTo(higher);
            }
            // Still all down → reselect from the pool (holds on empty pool).
            self.worker_was_down = !inputs.worker_tunnel_ok;
            return blackout_reselect(inputs);
        }

        // 4. Current tier healthy → hold; opportunistically climb to a
        //    strictly-higher recovered tier.
        if current_ok(self.state, inputs) {
            if let Some(higher) = highest_ok(inputs) {
                if rank(higher) > rank(self.state) {
                    self.state = higher;
                    self.consecutive_fail = 0;
                    self.worker_was_down = false;
                    return BlackoutAction::ClimbTo(higher);
                }
            }
            self.consecutive_fail = 0;
            self.worker_was_down = !inputs.worker_tunnel_ok;
            return BlackoutAction::Hold;
        }

        // 5. Failure hysteresis: descend only after >= 2 consecutive failures.
        self.consecutive_fail = self.consecutive_fail.saturating_add(1);
        if self.consecutive_fail < DESCEND_THRESHOLD {
            self.worker_was_down = !inputs.worker_tunnel_ok;
            return BlackoutAction::Hold;
        }

        // Descend.
        self.consecutive_fail = 0;
        self.worker_was_down = !inputs.worker_tunnel_ok;
        // All rungs down → blackout (reselect from pool).
        if !inputs.direct_ok && !inputs.doh_ok && !inputs.dot_ok && !inputs.worker_tunnel_ok {
            self.state = LinkState::Blackout;
            return blackout_reselect(inputs);
        }
        self.state = descend_state(self.state);
        BlackoutAction::Hold
    }
}

/// Best tier that is currently OK (highest rank), if any.
fn highest_ok(inputs: &BlackoutInputs) -> Option<LinkState> {
    if inputs.direct_ok {
        return Some(LinkState::Direct);
    }
    if inputs.doh_ok {
        return Some(LinkState::Doh);
    }
    if inputs.dot_ok {
        return Some(LinkState::Dot);
    }
    if inputs.worker_tunnel_ok {
        return Some(LinkState::WorkerTunnel);
    }
    None
}

fn current_ok(state: LinkState, inputs: &BlackoutInputs) -> bool {
    match state {
        LinkState::Direct => inputs.direct_ok,
        LinkState::Doh => inputs.doh_ok,
        LinkState::Dot => inputs.dot_ok,
        LinkState::WorkerTunnel => inputs.worker_tunnel_ok,
        LinkState::Blackout => false,
    }
}

/// One rung down the ladder (Direct → Doh → Dot → WorkerTunnel → Blackout).
fn descend_state(state: LinkState) -> LinkState {
    match state {
        LinkState::Direct => LinkState::Doh,
        LinkState::Doh => LinkState::Dot,
        LinkState::Dot => LinkState::WorkerTunnel,
        LinkState::WorkerTunnel => LinkState::Blackout,
        LinkState::Blackout => LinkState::Blackout,
    }
}

/// Reselect carriers from the pool in a blackout. Never panics on an empty pool.
fn blackout_reselect(inputs: &BlackoutInputs) -> BlackoutAction {
    if inputs.pool_worker_data_count > 0 {
        BlackoutAction::ReselectCarrier {
            kind: CarrierKind::WorkerData,
            n: 8,
        }
    } else if inputs.pool_worker_tunnel_count > 0 {
        BlackoutAction::ReselectCarrier {
            kind: CarrierKind::WorkerTunnel,
            n: 8,
        }
    } else {
        BlackoutAction::Hold
    }
}

fn rank(s: LinkState) -> u8 {
    match s {
        LinkState::Direct => 0,
        LinkState::Doh => 1,
        LinkState::Dot => 2,
        LinkState::WorkerTunnel => 3,
        LinkState::Blackout => 4,
    }
}

/// Resolve a [`BlackoutAction`] against the pool. The only filesystem touch —
/// `ReselectCarrier` selects from the pool, everything else yields an empty
/// vec. Centralizing it gives the daemon a single call site and lets tests
/// assert the returned endpoints.
pub fn resolve_action(
    action: &BlackoutAction,
    pool: &CarrierPool,
) -> Result<Vec<CarrierEndpoint>, CarrierPoolError> {
    match action {
        BlackoutAction::ReselectCarrier { kind, n } => pool.select(*kind, *n),
        _ => Ok(Vec::new()),
    }
}

/// The daemon's tier-decision seam: build inputs from current probe results +
/// pool counts, ask the controller, resolve the action. Returns the chosen
/// next tier and the endpoints to try.
///
/// Pure and socket-free — tests exercise it without opening a single socket.
pub fn decide_next_tier(
    inputs: &BlackoutInputs,
    ctl: &mut BlackoutController,
    pool: &CarrierPool,
) -> Result<(BlackoutAction, LinkState, Vec<CarrierEndpoint>), CarrierPoolError> {
    let action = ctl.next(inputs);
    let endpoints = resolve_action(&action, pool)?;
    let next_state = ctl.state();
    Ok((action, next_state, endpoints))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs(
        direct: bool,
        doh: bool,
        dot: bool,
        worker: bool,
        tun_count: usize,
        data_count: usize,
    ) -> BlackoutInputs {
        BlackoutInputs {
            now_unix: 1000,
            direct_ok: direct,
            doh_ok: doh,
            dot_ok: dot,
            worker_tunnel_ok: worker,
            pool_worker_tunnel_count: tun_count,
            pool_worker_data_count: data_count,
        }
    }

    fn tmp_pool_with_data(n: usize) -> (tempfile::TempDir, CarrierPool) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool.json");
        let pool = CarrierPool::open(&path).unwrap();
        let mut snap = crate::carrier_pool::CarrierSnapshot::new_empty(1000);
        for i in 0..n {
            snap.endpoints.push(crate::carrier_pool::CarrierEndpoint {
                kind: CarrierKind::WorkerData,
                host: format!("d{i}.example.com"),
                port: 443,
                sni: None,
                worker_url: None,
                upstream: Some(format!("d{i}.example.com:443")),
                weight: 0.9,
                last_probe_ok_unix: None,
                last_probe_rtt_ms: None,
                provenance: crate::carrier_pool::CarrierProvenance::Deployed,
                desync_strategy: None,
            });
        }
        snap.sign().unwrap();
        pool.store_atomic(&snap).unwrap();
        (dir, pool)
    }

    #[test]
    fn blackout_all_ok_holds_direct() {
        let mut ctl = BlackoutController::new();
        let act = ctl.next(&inputs(true, true, true, true, 1, 1));
        assert_eq!(act, BlackoutAction::Hold);
        assert_eq!(ctl.state(), LinkState::Direct);
    }

    #[test]
    fn blackout_single_direct_fail_does_not_descend() {
        let mut ctl = BlackoutController::new();
        // t1: direct OK
        assert_eq!(
            ctl.next(&inputs(true, true, true, true, 0, 0)),
            BlackoutAction::Hold
        );
        // t2: direct down, rest up → single blip, still Direct
        assert_eq!(
            ctl.next(&inputs(false, true, true, true, 0, 0)),
            BlackoutAction::Hold
        );
        assert_eq!(ctl.state(), LinkState::Direct);
        // t3: direct OK again → still Direct, no descend
        assert_eq!(
            ctl.next(&inputs(true, true, true, true, 0, 0)),
            BlackoutAction::Hold
        );
        assert_eq!(ctl.state(), LinkState::Direct);
    }

    #[test]
    fn blackout_direct_and_dns_down_fast_fails_to_worker() {
        let mut ctl = BlackoutController::new();
        // t1: direct/doh/dot down, worker up, state Direct → fast-fail.
        let act = ctl.next(&inputs(false, false, false, true, 1, 2));
        assert_eq!(act, BlackoutAction::FastFailToWorkerBootstrap);
        assert_eq!(ctl.state(), LinkState::WorkerTunnel);
        // t2: now at WorkerTunnel, worker still up → reselect worker-data.
        let act = ctl.next(&inputs(false, false, false, true, 1, 2));
        assert_eq!(
            act,
            BlackoutAction::ReselectCarrier {
                kind: CarrierKind::WorkerData,
                n: 8
            }
        );
    }

    #[test]
    fn blackout_all_down_with_pool_reselects_worker_data() {
        let mut ctl = BlackoutController::new();
        // First failure sets consecutive_fail=1 (Hold), second descends.
        assert_eq!(
            ctl.next(&inputs(false, false, false, false, 0, 3)),
            BlackoutAction::Hold
        );
        let act = ctl.next(&inputs(false, false, false, false, 0, 3));
        assert_eq!(
            act,
            BlackoutAction::ReselectCarrier {
                kind: CarrierKind::WorkerData,
                n: 8
            }
        );
        assert_eq!(ctl.state(), LinkState::Blackout);
    }

    #[test]
    fn blackout_all_down_empty_pool_holds() {
        let mut ctl = BlackoutController::new();
        assert_eq!(
            ctl.next(&inputs(false, false, false, false, 0, 0)),
            BlackoutAction::Hold
        );
        let act = ctl.next(&inputs(false, false, false, false, 0, 0));
        assert_eq!(act, BlackoutAction::Hold); // no panic on empty pool
        assert_eq!(ctl.state(), LinkState::Blackout);
    }

    #[test]
    fn blackout_worker_recovery_emits_refresh() {
        let mut ctl = BlackoutController::new();
        // Drive to Blackout with worker down.
        ctl.next(&inputs(false, false, false, false, 0, 1));
        ctl.next(&inputs(false, false, false, false, 0, 1));
        assert_eq!(ctl.state(), LinkState::Blackout);
        // Worker liveness recovers → refresh edge fires.
        let act = ctl.next(&inputs(false, false, false, true, 1, 1));
        assert_eq!(act, BlackoutAction::RefreshViaWorkerTunnel);
    }

    #[test]
    fn blackout_recovers_to_direct() {
        let mut ctl = BlackoutController::new();
        ctl.next(&inputs(false, false, false, false, 0, 1));
        ctl.next(&inputs(false, false, false, false, 0, 1));
        assert_eq!(ctl.state(), LinkState::Blackout);
        // Direct recovers → climb to Direct.
        let act = ctl.next(&inputs(true, false, false, false, 0, 1));
        assert_eq!(act, BlackoutAction::ClimbTo(LinkState::Direct));
        assert_eq!(ctl.state(), LinkState::Direct);
    }

    #[test]
    fn resolve_action_returns_pool_endpoints() {
        let (_dir, pool) = tmp_pool_with_data(2);
        let act = BlackoutAction::ReselectCarrier {
            kind: CarrierKind::WorkerData,
            n: 8,
        };
        let eps = resolve_action(&act, &pool).unwrap();
        assert_eq!(eps.len(), 2);
        assert!(eps.iter().all(|e| e.kind == CarrierKind::WorkerData));
        // Non-reselect action → empty.
        assert!(resolve_action(&BlackoutAction::Hold, &pool)
            .unwrap()
            .is_empty());
    }

    /// The daemon's tier-decision seam, tested end-to-end with synthetic
    /// inputs and a real (offline) pool — opens no sockets.
    #[test]
    fn decide_next_tier_fast_fails_through_seam() {
        let (_dir, pool) = tmp_pool_with_data(2);
        let mut ctl = BlackoutController::new();
        let inputs = inputs(false, false, false, true, 1, 2);

        let (action, next_state, endpoints) = decide_next_tier(&inputs, &mut ctl, &pool).unwrap();
        assert_eq!(action, BlackoutAction::FastFailToWorkerBootstrap);
        assert_eq!(next_state, LinkState::WorkerTunnel);
        assert!(endpoints.is_empty()); // fast-fail carries no endpoint list

        // Next tick on the same seam → reselect worker-data from the pool.
        let (action2, _next2, endpoints2) = decide_next_tier(&inputs, &mut ctl, &pool).unwrap();
        assert_eq!(
            action2,
            BlackoutAction::ReselectCarrier {
                kind: CarrierKind::WorkerData,
                n: 8
            }
        );
        assert_eq!(endpoints2.len(), 2);
    }
}
