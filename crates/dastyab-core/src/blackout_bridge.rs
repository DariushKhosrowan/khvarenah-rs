//! Blackout survival decision bridge.
//!
//! `blackout::detect` tells us *what* is wrong (Normal / DnsHijacked /
//! TotalBlackout). `vps_deploy::tunnel_tier_available` tells us whether we
//! have a deployed DNS tunnel. This module combines them into one actionable
//! `SurvivalPlan` the daemon and the GUI can act on — so a configured VPS
//! tunnel actually changes what the app does during a blackout instead of just
//! being a written-down preference.
//!
//! Pure logic, fully unit-testable with no network.

use crate::blackout::NetworkState;

/// What the app should do given the observed network state + tunnel config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurvivalPlan {
    /// Full connectivity — normal operation (direct/DoH/DoT).
    Normal,
    /// System DNS is hijacked but TCP still works — stay on DoH/DoT; a
    /// DNS tunnel is unnecessary (and IM slower).
    DnsHijackedUseDoh,
    /// DNS hijacked AND no tunnel configured — we still have DoH/DoT, but
    /// flag that a tunnel would be valuable for the deeper blackout case.
    DnsHijackedNoTunnel,
    /// Everything over TCP is dark. If a tunnel is configured, descend to it.
    /// If not, the app can only report / wait — no VPN data channel exists.
    TotalBlackoutTunnelAvailable,
    /// Full blackout and no tunnel — the honest ceiling. The app should
    /// report status (e.g. via the last-known beacon) and wait for a path.
    TotalBlackoutNoTunnel,
}

impl SurvivalPlan {
    /// Compute the plan from the network state and whether a DNS tunnel is
    /// configured for the active profile.
    pub fn from_state(state: NetworkState, tunnel_configured: bool) -> Self {
        match (state, tunnel_configured) {
            (NetworkState::Normal, _) => SurvivalPlan::Normal,
            (NetworkState::DnsHijacked, true) => SurvivalPlan::DnsHijackedUseDoh,
            (NetworkState::DnsHijacked, false) => SurvivalPlan::DnsHijackedNoTunnel,
            (NetworkState::TotalBlackout, true) => SurvivalPlan::TotalBlackoutTunnelAvailable,
            (NetworkState::TotalBlackout, false) => SurvivalPlan::TotalBlackoutNoTunnel,
        }
    }

    /// One short, no-jargon label for humans.
    pub fn label(self) -> &'static str {
        match self {
            SurvivalPlan::Normal => "normal",
            SurvivalPlan::DnsHijackedUseDoh => "dns-hijacked",
            SurvivalPlan::DnsHijackedNoTunnel => "dns-hijacked",
            SurvivalPlan::TotalBlackoutTunnelAvailable => "total-blackout",
            SurvivalPlan::TotalBlackoutNoTunnel => "total-blackout",
        }
    }

    /// True when the app should descend to the DNS tunnel tier.
    pub fn uses_tunnel(self) -> bool {
        matches!(self, SurvivalPlan::TotalBlackoutTunnelAvailable)
    }

    /// A short plain-language note for the status line.
    pub fn note(self) -> &'static str {
        match self {
            SurvivalPlan::Normal => "all paths up",
            SurvivalPlan::DnsHijackedUseDoh => "system DNS hijacked — DoH/DoT still working",
            SurvivalPlan::DnsHijackedNoTunnel => {
                "system DNS hijacked — consider deploying a DNS tunnel for deep blackouts"
            }
            SurvivalPlan::TotalBlackoutTunnelAvailable => {
                "total blackout — using DNS tunnel fallback"
            }
            SurvivalPlan::TotalBlackoutNoTunnel => {
                "total blackout — no tunnel configured, waiting for a path"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_state_is_plan_normal_even_with_tunnel() {
        assert_eq!(
            SurvivalPlan::from_state(NetworkState::Normal, true),
            SurvivalPlan::Normal
        );
        assert!(!SurvivalPlan::from_state(NetworkState::Normal, true).uses_tunnel());
    }

    #[test]
    fn hijacked_with_tunnel_stays_on_doh() {
        let p = SurvivalPlan::from_state(NetworkState::DnsHijacked, true);
        assert_eq!(p, SurvivalPlan::DnsHijackedUseDoh);
        assert!(!p.uses_tunnel());
    }

    #[test]
    fn blackout_with_tunnel_uses_tunnel() {
        let p = SurvivalPlan::from_state(NetworkState::TotalBlackout, true);
        assert_eq!(p, SurvivalPlan::TotalBlackoutTunnelAvailable);
        assert!(p.uses_tunnel());
    }

    #[test]
    fn blackout_without_tunnel_is_honest_ceiling() {
        let p = SurvivalPlan::from_state(NetworkState::TotalBlackout, false);
        assert_eq!(p, SurvivalPlan::TotalBlackoutNoTunnel);
        assert!(!p.uses_tunnel());
    }
}
