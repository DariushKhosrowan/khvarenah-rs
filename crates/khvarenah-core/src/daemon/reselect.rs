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
//!   tests inject a `Vec<bool>` script of successes/failures.
//! - [`execute_reselection`] — a pure function: given the candidate endpoints
//!   (already ordered by the pool's [`select`](crate::carrier_pool::CarrierPool::select))
//!   and an opener, try each in order and return the first that opens
//!   successfully. Returns `None` when all fail.
//!
//! Wiring: the daemon tick calls [`execute_reselection`] wherever a
//! [`super::blackout::BlackoutAction::ReselectCarrier`] fires, and on success
//! persists the winning endpoint as the active tunnel.

use crate::carrier_pool::CarrierEndpoint;

/// A tunnel opener: attempts to use `ep` as the active tunnel, returning
/// `true` on success. Implementations must be cheap (a bounded probe); the
/// function that consumes this tries candidates in order, stopping at the
/// first success.
pub trait TunnelOpener {
    fn try_open(&mut self, ep: &CarrierEndpoint) -> bool;
}

/// Try each candidate endpoint in order; return the first that opens.
/// Returns `None` when the candidate list is empty or every opener fails.
/// `opened` is the number of opener attempts (i.e. the index+1 of the first
/// success, or the full list length on total failure).
pub fn execute_reselection(
    candidates: &[CarrierEndpoint],
    opener: &mut dyn TunnelOpener,
) -> Option<(CarrierEndpoint, usize)> {
    for (i, ep) in candidates.iter().enumerate() {
        if opener.try_open(ep) {
            return Some((ep.clone(), i + 1));
        }
    }
    None
}

/// The real opener: probes an endpoint's liveness and, on success, persists it
/// as the profile's active tunnel (for `Worker*` kinds, the worker URL/secret
/// replace the tunnel config; for `VpsTunnel`, the VPS host is probed and
/// kept). It is a thin adapter over the existing probe/connect functions.
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

    fn persist_worker_endpoint(&self, ep: &CarrierEndpoint) -> bool {
        let Some(url) = &ep.worker_url else {
            return false;
        };
        let Some(upstream) = &ep.upstream else {
            return false;
        };
        // Retain the existing secret if we have one; otherwise a placeholder is
        // conservative (the real share secret is set at deploy time).
        let secret = crate::vps_deploy::load_tunnel_client_config(self.profile)
            .and_then(|c| c.shared_secret)
            .unwrap_or_default();
        let cfg = crate::vps_deploy::TunnelClientConfig {
            host: url.clone(),
            base_domain: crate::worker_tunnel::KHV_TUNNEL_BASE.to_string(),
            session: String::new(),
            resolver: "https".into(),
            mode: crate::vps_deploy::TunnelMode::Worker,
            worker_url: Some(url.clone()),
            worker_name: None,
            shared_secret: Some(secret),
            worker_vless_upstream: Some(upstream.clone()),
        };
        crate::vps_deploy::write_tunnel_client_config(self.profile, &cfg).is_ok()
    }
}

impl TunnelOpener for RealTunnelOpener<'_> {
    fn try_open(&mut self, ep: &CarrierEndpoint) -> bool {
        match ep.kind {
            crate::carrier_pool::CarrierKind::WorkerData
            | crate::carrier_pool::CarrierKind::WorkerTunnel => {
                if self.persist_worker_endpoint(ep) {
                    // Verify liveness through the freshly-persisted config.
                    let cfg =
                        crate::vps_deploy::load_tunnel_client_config(self.profile);
                    match cfg {
                        Some(c) => crate::connectivity::probe_worker_tunnel_live(&c, self.timeout)
                            .ok,
                        None => false,
                    }
                } else {
                    false
                }
            }
            crate::carrier_pool::CarrierKind::VpsTunnel => {
                crate::vps_deploy::probe_vps_reachable(&ep.host, ep.port)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::carrier_pool::{CarrierEndpoint, CarrierKind, CarrierProvenance};

    fn ep(host: &str) -> CarrierEndpoint {
        CarrierEndpoint {
            kind: CarrierKind::WorkerData,
            host: host.to_string(),
            port: 443,
            sni: None,
            worker_url: None,
            upstream: Some(format!("{host}:443")),
            weight: 0.9,
            last_probe_ok_unix: None,
            last_probe_rtt_ms: None,
            provenance: CarrierProvenance::Deployed,
        }
    }

    /// Scripted opener: a Vec<bool> of successes/failures, consumed in order.
    struct ScriptOpener {
        script: Vec<bool>,
        calls: usize,
    }

    impl TunnelOpener for ScriptOpener {
        fn try_open(&mut self, _ep: &CarrierEndpoint) -> bool {
            let r = *self.script.get(self.calls).unwrap_or(&false);
            self.calls += 1;
            r
        }
    }

    #[test]
    fn execute_reselection_picks_first_success() {
        let eps = vec![ep("a"), ep("b"), ep("c"), ep("d")];
        let mut opener = ScriptOpener {
            script: vec![false, false, true, true],
            calls: 0,
        };
        let (winner, opened) = execute_reselection(&eps, &mut opener).unwrap();
        assert_eq!(winner.host, "c");
        assert_eq!(opened, 3); // opener called 3 times
        assert_eq!(opener.calls, 3);
    }

    #[test]
    fn execute_reselection_all_fail_returns_none() {
        let eps = vec![ep("a"), ep("b")];
        let mut opener = ScriptOpener {
            script: vec![false, false],
            calls: 0,
        };
        assert!(execute_reselection(&eps, &mut opener).is_none());
        assert_eq!(opener.calls, 2);
    }

    #[test]
    fn execute_reselection_empty_returns_none() {
        let eps: Vec<CarrierEndpoint> = vec![];
        let mut opener = ScriptOpener {
            script: vec![],
            calls: 0,
        };
        assert!(execute_reselection(&eps, &mut opener).is_none());
        assert_eq!(opener.calls, 0);
    }

    #[test]
    fn execute_reselection_first_is_ok_opens_once() {
        let eps = vec![ep("a"), ep("b")];
        let mut opener = ScriptOpener {
            script: vec![true, false],
            calls: 0,
        };
        let (winner, opened) = execute_reselection(&eps, &mut opener).unwrap();
        assert_eq!(winner.host, "a");
        assert_eq!(opened, 1);
        assert_eq!(opener.calls, 1);
    }
}
