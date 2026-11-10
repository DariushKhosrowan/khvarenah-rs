//! Executable reselection — the last link in the blackout-survival chain.
//!
//! The blackout state machine ([`super::blackout`]) *decides* to reselect
//! carriers ([`super::blackout::BlackoutAction::ReselectCarrier`]), but that
//! decision is only useful if the daemon actually **opens** the chosen
//! endpoints and **switches** the active tunnel to one that works. This module
//! is the pure, testable seam for that execution:
//!
//! - [`TunnelOpener`] — an abstraction over "try this endpoint now". The real
//!   opener dispatches on [`CarrierKind`] to the existing probe/connect code;
//!   tests inject a scripted opener. `open` is a *pure attempt* that returns
//!   a result; it does NOT bind the active tunnel — the caller binds the
//!   winner. This is required for parallel execution (multiple `open` calls
//!   can be in flight at once, so openers must be `Send + Sync` and free of
//!   shared mutable state).
//! - [`execute_reselection`] — serial: try each candidate in order, return the
//!   first that opens. Preserves index-order priority.
//! - [`execute_reselection_parallel`] — parallel: a bounded worker pool probes
//!   candidates concurrently and returns the first one that succeeds
//!   (fastest-wins). This is the right behavior for blackout resilience — a
//!   low-weight endpoint that responds in 2s is strictly better than a
//!   high-weight one that responds in 25s. Wall-clock to return is
//!   `winner_latency + (≤ per_probe_timeout)` (in-flight workers finish their
//!   current probe before the scope joins).
//! - [`exec_reselection_wrapper`] — dispatches on `max_concurrent`: `1` takes
//!   the serial path, otherwise parallel. All call sites go through this.
//!
//! Wiring: the daemon tick calls [`exec_reselection_wrapper`] wherever a
//! [`super::blackout::BlackoutAction::ReselectCarrier`] fires, and on success
//! binds the winning endpoint as the active tunnel.

use crate::carrier_pool::CarrierEndpoint;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;

/// A successfully opened tunnel.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenedTunnel {
    pub endpoint: CarrierEndpoint,
    pub opened_unix: u64,
}

/// Why an endpoint could not be opened.
#[derive(Debug, Clone, PartialEq)]
pub enum OpenError {
    Unreachable(String),
    Auth,
    Timeout,
    Other(String),
}

/// A tunnel opener: a *pure attempt* to use `ep` as the active tunnel.
///
/// Implementations must be cheap (a bounded probe). `open` must NOT mutate
/// shared state or bind the active tunnel — the caller binds the winner. The
/// trait is `Send + Sync` so openers can run concurrently in the bounded
/// worker pool of [`execute_reselection_parallel`].
pub trait TunnelOpener: Send + Sync {
    fn open(&self, ep: &CarrierEndpoint) -> Result<OpenedTunnel, OpenError>;
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Serial reselection: try each candidate in order, return the first that
/// opens. `opened` is the number of opener attempts (index+1 of the first
/// success, or the full list length on total failure).
pub fn execute_reselection(
    candidates: &[CarrierEndpoint],
    opener: &dyn TunnelOpener,
) -> Option<OpenedTunnel> {
    for ep in candidates {
        if let Ok(t) = opener.open(ep) {
            return Some(t);
        }
    }
    None
}

/// Parallel reselection: probe up to `max_concurrent` candidates concurrently
/// and return the first that succeeds. Endpoints are pulled from a shared
/// atomic index; a `done` flag short-circuits remaining workers on first
/// success. Fastest-wins — lower index is NOT prioritized (by design; see
/// module docs).
///
/// Returns `None` when the list is empty or every candidate fails. Wall-clock
/// to return is `winner_latency + (≤ per_probe_timeout)`: the winner is
/// received through the channel immediately, but the bounded in-flight
/// workers finish their current probe before the scope joins.
pub fn execute_reselection_parallel(
    endpoints: &[CarrierEndpoint],
    opener: &dyn TunnelOpener,
    max_concurrent: usize,
) -> Option<OpenedTunnel> {
    if endpoints.is_empty() {
        return None;
    }
    let workers = max_concurrent.min(endpoints.len()).max(1);
    let next = AtomicUsize::new(0);
    let done = AtomicBool::new(false);
    let (tx, rx) = mpsc::channel::<OpenedTunnel>();
    std::thread::scope(|s| {
        for _ in 0..workers {
            let tx = tx.clone();
            let next = &next;
            let done = &done;
            s.spawn(move || loop {
                if done.load(Ordering::Relaxed) {
                    break;
                }
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= endpoints.len() {
                    break;
                }
                if let Ok(t) = opener.open(&endpoints[i]) {
                    if !done.swap(true, Ordering::Relaxed) {
                        let _ = tx.send(t);
                    }
                    break;
                }
            });
        }
        drop(tx); // close sender in this thread; keeps rx.recv() correct on all-fail
        rx.recv().ok()
    })
}

/// Dispatch reselection: `max_concurrent == 1` → serial (preserves index
/// priority, used when not escalated); otherwise parallel. Returns the
/// winning tunnel, or `None` when nothing opens.
pub fn exec_reselection_wrapper(
    candidates: &[CarrierEndpoint],
    opener: &dyn TunnelOpener,
    max_concurrent: usize,
) -> Option<OpenedTunnel> {
    if max_concurrent <= 1 {
        execute_reselection(candidates, opener)
    } else {
        execute_reselection_parallel(candidates, opener, max_concurrent)
    }
}

/// The real opener: probes an endpoint's liveness. It is a *pure attempt* —
/// it does NOT persist or bind the active tunnel (the caller does that after
/// the winner is chosen). This is what makes it safe to run concurrently in
/// the parallel pool.
pub struct RealTunnelOpener<'a> {
    profile: &'a str,
    timeout: std::time::Duration,
}

impl<'a> RealTunnelOpener<'a> {
    pub fn new(profile: &'a str) -> Self {
        Self {
            profile,
            timeout: std::time::Duration::from_secs(3),
        }
    }

    /// Build a transient probe config for `ep` (does not write to disk).
    fn probe_config(&self, ep: &CarrierEndpoint) -> Option<crate::vps_deploy::TunnelClientConfig> {
        let url = ep.worker_url.as_ref()?;
        let upstream = ep.upstream.as_ref()?;
        // Retain the existing shared secret if we have one; otherwise a
        // placeholder is conservative (the real shared secret is set at
        // deploy time).
        let secret = crate::vps_deploy::load_tunnel_client_config(self.profile)
            .and_then(|c| c.shared_secret)
            .unwrap_or_default();
        Some(crate::vps_deploy::TunnelClientConfig {
            host: url.clone(),
            base_domain: crate::worker_tunnel::DYB_TUNNEL_BASE.to_string(),
            session: String::new(),
            resolver: "https".into(),
            mode: crate::vps_deploy::TunnelMode::Worker,
            worker_url: Some(url.clone()),
            worker_name: None,
            shared_secret: Some(secret),
            worker_vless_upstream: Some(upstream.clone()),
        })
    }
}

impl TunnelOpener for RealTunnelOpener<'_> {
    fn open(&self, ep: &CarrierEndpoint) -> Result<OpenedTunnel, OpenError> {
        let ok = match ep.kind {
            crate::carrier_pool::CarrierKind::WorkerData
            | crate::carrier_pool::CarrierKind::WorkerTunnel => {
                let Some(cfg) = self.probe_config(ep) else {
                    return Err(OpenError::Other(
                        "endpoint missing worker_url/upstream".into(),
                    ));
                };
                crate::connectivity::probe_worker_tunnel_live(&cfg, self.timeout).ok
            }
            crate::carrier_pool::CarrierKind::VpsTunnel => {
                crate::vps_deploy::probe_vps_reachable(&ep.host, ep.port)
            }
        };
        if ok {
            Ok(OpenedTunnel {
                endpoint: ep.clone(),
                opened_unix: now_unix(),
            })
        } else {
            Err(OpenError::Unreachable(ep.host.clone()))
        }
    }
}

/// Bind a winning endpoint as the profile's active tunnel. For `Worker*`
/// kinds this persists the worker URL/secret/upstream into the profile's
/// tunnel config; for `VpsTunnel` the VPS host is already probed and kept.
/// Returns `true` if a worker endpoint was bound.
pub fn bind_winner(profile: &str, ep: &CarrierEndpoint) -> bool {
    if !matches!(
        ep.kind,
        crate::carrier_pool::CarrierKind::WorkerData
            | crate::carrier_pool::CarrierKind::WorkerTunnel
    ) {
        return false;
    }
    let Some(url) = &ep.worker_url else {
        return false;
    };
    let Some(upstream) = &ep.upstream else {
        return false;
    };
    let secret = crate::vps_deploy::load_tunnel_client_config(profile)
        .and_then(|c| c.shared_secret)
        .unwrap_or_default();
    let cfg = crate::vps_deploy::TunnelClientConfig {
        host: url.clone(),
        base_domain: crate::worker_tunnel::DYB_TUNNEL_BASE.to_string(),
        session: String::new(),
        resolver: "https".into(),
        mode: crate::vps_deploy::TunnelMode::Worker,
        worker_url: Some(url.clone()),
        worker_name: None,
        shared_secret: Some(secret),
        worker_vless_upstream: Some(upstream.clone()),
    };
    crate::vps_deploy::write_tunnel_client_config(profile, &cfg).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::carrier_pool::{CarrierKind, CarrierProvenance};
    use std::sync::Mutex;

    fn ep(host: &str) -> CarrierEndpoint {
        CarrierEndpoint {
            kind: CarrierKind::WorkerData,
            host: host.to_string(),
            port: 443,
            sni: None,
            worker_url: Some(format!("https://{host}")),
            upstream: Some(format!("{host}:443")),
            weight: 0.9,
            last_probe_ok_unix: None,
            last_probe_rtt_ms: None,
            provenance: CarrierProvenance::Deployed,
        }
    }

    /// Scripted opener: a Vec<Result> of outcomes, consumed in order. Uses a
    /// Mutex so it is `Send + Sync` (open takes `&self`).
    struct ScriptOpener {
        script: Mutex<Vec<bool>>,
        calls: Mutex<usize>,
        active: Mutex<usize>,
        max_active: Mutex<usize>,
    }

    impl ScriptOpener {
        fn new(script: Vec<bool>) -> Self {
            Self {
                script: Mutex::new(script),
                calls: Mutex::new(0),
                active: Mutex::new(0),
                max_active: Mutex::new(0),
            }
        }
    }

    impl ScriptOpener {
        fn calls(&self) -> usize {
            *self.calls.lock().unwrap()
        }
        fn max_active(&self) -> usize {
            *self.max_active.lock().unwrap()
        }
    }

    impl TunnelOpener for ScriptOpener {
        fn open(&self, ep: &CarrierEndpoint) -> Result<OpenedTunnel, OpenError> {
            let mut active = self.active.lock().unwrap();
            *active += 1;
            {
                let mut ma = self.max_active.lock().unwrap();
                *ma = (*ma).max(*active);
            }
            let r = {
                let mut s = self.script.lock().unwrap();
                let hit = s.first().copied().unwrap_or(false);
                if !s.is_empty() {
                    s.remove(0);
                }
                hit
            };
            let mut c = self.calls.lock().unwrap();
            *c += 1;
            *active = active.saturating_sub(1);
            if r {
                Ok(OpenedTunnel {
                    endpoint: ep.clone(),
                    opened_unix: 1,
                })
            } else {
                Err(OpenError::Unreachable(ep.host.clone()))
            }
        }
    }

    #[test]
    fn execute_reselection_picks_first_success() {
        let eps = vec![ep("a"), ep("b"), ep("c"), ep("d")];
        let opener = ScriptOpener::new(vec![false, false, true, true]);
        let t = execute_reselection(&eps, &opener).unwrap();
        assert_eq!(t.endpoint.host, "c");
        assert_eq!(opener.calls(), 3);
    }

    #[test]
    fn execute_reselection_all_fail_returns_none() {
        let eps = vec![ep("a"), ep("b")];
        let opener = ScriptOpener::new(vec![false, false]);
        assert!(execute_reselection(&eps, &opener).is_none());
        assert_eq!(opener.calls(), 2);
    }

    #[test]
    fn execute_reselection_empty_returns_none() {
        let eps: Vec<CarrierEndpoint> = vec![];
        let opener = ScriptOpener::new(vec![]);
        assert!(execute_reselection(&eps, &opener).is_none());
        assert_eq!(opener.calls(), 0);
    }

    #[test]
    fn execute_reselection_first_is_ok_opens_once() {
        let eps = vec![ep("a"), ep("b")];
        let opener = ScriptOpener::new(vec![true, false]);
        let t = execute_reselection(&eps, &opener).unwrap();
        assert_eq!(t.endpoint.host, "a");
        assert_eq!(opener.calls(), 1);
    }

    #[test]
    fn execute_reselection_parallel_first_success_returns() {
        let eps = vec![ep("a"), ep("b"), ep("c")];
        let opener = ScriptOpener::new(vec![false, true, false]);
        let t = execute_reselection_parallel(&eps, &opener, 2).unwrap();
        let _ = t; // at least one success returned
    }

    #[test]
    fn execute_reselection_parallel_all_fail_returns_none() {
        let eps = vec![ep("a"), ep("b")];
        let opener = ScriptOpener::new(vec![false, false]);
        assert!(execute_reselection_parallel(&eps, &opener, 2).is_none());
    }

    #[test]
    fn execute_reselection_parallel_empty_returns_none() {
        let eps: Vec<CarrierEndpoint> = vec![];
        let opener = ScriptOpener::new(vec![]);
        assert!(execute_reselection_parallel(&eps, &opener, 2).is_none());
    }

    #[test]
    fn execute_reselection_parallel_bounded_concurrency() {
        // 10 endpoints, max_concurrent=2 → never more than 2 concurrent opens.
        let eps: Vec<CarrierEndpoint> = (0..10).map(|i| ep(&format!("h{i}"))).collect();
        // all fail → every candidate visited
        let opener = ScriptOpener::new(vec![false; 10]);
        assert!(execute_reselection_parallel(&eps, &opener, 2).is_none());
        assert!(
            opener.max_active() <= 2,
            "max_active={}",
            opener.max_active()
        );
    }

    /// The semantic heart of parallel reselection: fastest wins, even when it
    /// is a LATER index. A low-weight endpoint that responds in 2s is strictly
    /// better than a high-weight one that responds in 25s.
    #[test]
    fn execute_reselection_parallel_fastest_wins_over_lower_index() {
        // Delay-based opener: index 1 succeeds after 10ms, index 0 after 100ms.
        struct SlowOpener;
        impl TunnelOpener for SlowOpener {
            fn open(&self, ep: &CarrierEndpoint) -> Result<OpenedTunnel, OpenError> {
                let delay = if ep.host == "a" { 100 } else { 10 };
                std::thread::sleep(std::time::Duration::from_millis(delay));
                Ok(OpenedTunnel {
                    endpoint: ep.clone(),
                    opened_unix: 1,
                })
            }
        }
        let eps = vec![ep("a"), ep("b")];
        let t = execute_reselection_parallel(&eps, &SlowOpener, 2).unwrap();
        assert_eq!(
            t.endpoint.host, "b",
            "faster high-index endpoint must beat slower low-index one"
        );
    }

    /// After the first success is reported, workers must stop pulling new
    /// candidates (the `done` flag short-circuits). Total opens should not
    /// exceed the worker count plus the in-flight tail.
    #[test]
    fn execute_reselection_parallel_stops_pulling_after_success() {
        let eps: Vec<CarrierEndpoint> = (0..8).map(|i| ep(&format!("h{i}"))).collect();
        // Every candidate succeeds; whichever wins, the rest must not be probed.
        let opener = ScriptOpener::new(vec![true; 8]);
        let t = execute_reselection_parallel(&eps, &opener, 3).unwrap();
        let _ = t;
        let calls = opener.calls();
        assert!(
            calls <= 3 + 2,
            "expected only workers + in-flight to open, got {calls} opens"
        );
    }

    #[test]
    fn exec_reselection_wrapper_serial_for_one() {
        let eps = vec![ep("a"), ep("b")];
        let opener = ScriptOpener::new(vec![true, false]);
        let t = exec_reselection_wrapper(&eps, &opener, 1).unwrap();
        assert_eq!(t.endpoint.host, "a");
        // serial → order preserved, first success is "a"
    }

    #[test]
    fn exec_reselection_wrapper_parallel_when_escalted() {
        let eps = vec![ep("a"), ep("b"), ep("c")];
        let opener = ScriptOpener::new(vec![false, true, true]);
        let t = exec_reselection_wrapper(&eps, &opener, 3).unwrap();
        assert!(t.endpoint.host == "b" || t.endpoint.host == "c");
    }
}
