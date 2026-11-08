//! Connectivity state machine + fallback ladder.
//!
//! On a heavily censored network no single path is guaranteed. This module
//! provides a small state machine that walks down a ladder of transport tiers —
//! direct clean-IP → DoH (pinned) → DoT → DNS tunnel — and climbs back up as
//! soon as a higher tier recovers. Each tier owns a probe; the app plugs in the
//! real probes (CLI/GUI), tests plug in scripted ones.

/// Ordered transport tiers, best first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Tier {
    /// Direct connection to a clean Cloudflare edge IP.
    Direct,
    /// DNS-over-HTTPS over pinned literal IPs (bypasses hijacked system DNS).
    DoH,
    /// DNS-over-TLS (TCP 853).
    DoT,
    /// DNS tunnel — text-rate emergency channel, last resort.
    DnsTunnel,
}

/// Ladder order, best first.
pub const TIER_ORDER: &[Tier] = &[Tier::Direct, Tier::DoH, Tier::DoT, Tier::DnsTunnel];

impl Tier {
    /// Index in the ladder order (0 = best).
    pub fn rank(self) -> usize {
        match self {
            Tier::Direct => 0,
            Tier::DoH => 1,
            Tier::DoT => 2,
            Tier::DnsTunnel => 3,
        }
    }

    /// Short stable label.
    pub fn label(self) -> &'static str {
        match self {
            Tier::Direct => "direct",
            Tier::DoH => "doh",
            Tier::DoT => "dot",
            Tier::DnsTunnel => "dns-tunnel",
        }
    }
}

/// A probe verdict for one tier.
#[derive(Debug, Clone)]
pub struct ProbeVerdict {
    pub ok: bool,
    /// One-way-ish RTT estimate in ms, when measurable.
    pub rtt_ms: Option<u32>,
    pub note: String,
}

impl ProbeVerdict {
    pub fn up(note: impl Into<String>) -> Self {
        Self {
            ok: true,
            rtt_ms: None,
            note: note.into(),
        }
    }
    pub fn down(note: impl Into<String>) -> Self {
        Self {
            ok: false,
            rtt_ms: None,
            note: note.into(),
        }
    }
}

/// A probe provider. Implement this in the app for real probing; tests use a
/// scripted mock.
pub trait Probe {
    fn probe(&self, tier: Tier) -> ProbeVerdict;
}

/// Default policy constants.
pub mod policy {
    /// Consecutive probe failures on a tier before we descend one step.
    pub const MAX_FAILS_BEFORE_DESCEND: u32 = 2;
    /// How often (in seconds) the watchdog re-probes the current tier.
    pub const WATCHDOG_INTERVAL_SECS: u64 = 30;
    /// Probe timeout budget per tier, ms.
    pub const PROBE_TIMEOUT_MS: u64 = 4000;
}

/// Result of a watchdog tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TierChange {
    /// Current tier still healthy.
    Stable(Tier),
    /// Current tier failed; we descended to a lower tier.
    Descended(Tier),
    /// A previously-lost higher tier came back; we climbed up.
    Recovered(Tier),
}

impl TierChange {
    pub fn tier(self) -> Tier {
        match self {
            TierChange::Stable(t) | TierChange::Descended(t) | TierChange::Recovered(t) => t,
        }
    }
}

/// The fallback-ladder state machine.
pub struct FallbackLadder<P> {
    probe: P,
    current: Tier,
    fails_in_row: u32,
    max_fails: u32,
}

impl<P: Probe> FallbackLadder<P> {
    /// Build a ladder starting at `start` (usually `Tier::Direct`).
    pub fn new(probe: P, start: Tier) -> Self {
        Self {
            probe,
            current: start,
            fails_in_row: 0,
            max_fails: policy::MAX_FAILS_BEFORE_DESCEND,
        }
    }

    /// Override how many consecutive failures trigger a descend.
    pub fn with_max_fails(mut self, n: u32) -> Self {
        self.max_fails = n.max(1);
        self
    }

    pub fn current(&self) -> Tier {
        self.current
    }

    /// Probe the current tier. Returns true if it still works; if it has
    /// failed `max_fails` times in a row, descend one step and return false.
    pub fn poll(&mut self) -> bool {
        let verdict = self.probe.probe(self.current);
        if verdict.ok {
            self.fails_in_row = 0;
            return true;
        }
        self.fails_in_row += 1;
        if self.fails_in_row >= self.max_fails {
            self.descend();
        }
        false
    }

    /// Try to climb back up: probe every strictly-higher tier, best first, and
    /// adopt the first that works. Returns Some(tier) if we improved.
    pub fn climb_back(&mut self) -> Option<Tier> {
        let cur_rank = self.current.rank();
        for tier in TIER_ORDER.iter().copied() {
            if tier.rank() >= cur_rank {
                break; // only strictly-higher tiers
            }
            if self.probe.probe(tier).ok {
                self.current = tier;
                self.fails_in_row = 0;
                return Some(tier);
            }
        }
        None
    }

    /// Full watchdog tick: poll the current tier; if it failed and we
    /// descended, opportunistically try to climb back to a recovered tier.
    pub fn watchdog_tick(&mut self) -> TierChange {
        if self.poll() {
            return TierChange::Stable(self.current);
        }
        if let Some(tier) = self.climb_back() {
            return TierChange::Recovered(tier);
        }
        TierChange::Descended(self.current)
    }

    fn descend(&mut self) {
        let rank = self.current.rank();
        if rank < TIER_ORDER.len() - 1 {
            self.current = TIER_ORDER[rank + 1];
        }
        self.fails_in_row = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct ScriptedProbe {
        results: HashMap<Tier, ProbeVerdict>,
    }

    impl Probe for ScriptedProbe {
        fn probe(&self, tier: Tier) -> ProbeVerdict {
            self.results
                .get(&tier)
                .cloned()
                .unwrap_or_else(|| ProbeVerdict::down("not scripted"))
        }
    }

    #[test]
    fn ladder_order_is_best_first() {
        assert_eq!(TIER_ORDER[0], Tier::Direct);
        assert_eq!(TIER_ORDER[3], Tier::DnsTunnel);
    }

    #[test]
    fn descends_after_repeated_failures() {
        let p = ScriptedProbe::default(); // everything down
        let mut ladder = FallbackLadder::new(p, Tier::Direct);
        assert_eq!(ladder.current(), Tier::Direct);
        ladder.poll(); // fail 1 (below threshold)
        assert_eq!(ladder.current(), Tier::Direct);
        ladder.poll(); // fail 2 -> descend
        assert_eq!(ladder.current(), Tier::DoH);
    }

    #[test]
    fn recovers_when_higher_tier_returns() {
        // Drive down to DoT with an all-down probe.
        let mut ladder = FallbackLadder::new(ScriptedProbe::default(), Tier::Direct);
        for _ in 0..4 {
            ladder.poll();
        }
        assert_eq!(ladder.current(), Tier::DoT);

        // Now DoH comes back.
        let mut results = HashMap::new();
        results.insert(Tier::DoH, ProbeVerdict::up("ok"));
        ladder.probe = ScriptedProbe { results };

        let change = ladder.watchdog_tick();
        assert_eq!(change, TierChange::Recovered(Tier::DoH));
        assert_eq!(ladder.current(), Tier::DoH);
    }

    #[test]
    fn stable_when_current_tier_healthy() {
        let mut results = HashMap::new();
        results.insert(Tier::Direct, ProbeVerdict::up("ok"));
        let mut ladder = FallbackLadder::new(ScriptedProbe { results }, Tier::Direct);
        assert_eq!(ladder.watchdog_tick(), TierChange::Stable(Tier::Direct));
    }
}
