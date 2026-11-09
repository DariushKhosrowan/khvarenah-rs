//! Connectivity state machine + fallback ladder.
//!
//! On a heavily censored network no single path is guaranteed. This module
//! provides a small state machine that walks down a ladder of transport tiers —
//! direct clean-IP → DoH (pinned) → DoT → DNS tunnel — and climbs back up as
//! soon as a higher tier recovers. Each tier owns a probe; the app plugs in the
//! real probes (CLI/GUI), tests plug in scripted ones.

use std::future::Future;
use std::pin::Pin;

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
/// scripted mock. Probes are async because every real tier does network I/O.
pub trait Probe {
    fn probe(&self, tier: Tier) -> Pin<Box<dyn Future<Output = ProbeVerdict> + Send + '_>>;
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
    pub async fn poll(&mut self) -> bool {
        let verdict = self.probe.probe(self.current).await;
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
    pub async fn climb_back(&mut self) -> Option<Tier> {
        let cur_rank = self.current.rank();
        for tier in TIER_ORDER.iter().copied() {
            if tier.rank() >= cur_rank {
                break; // only strictly-higher tiers
            }
            if self.probe.probe(tier).await.ok {
                self.current = tier;
                self.fails_in_row = 0;
                return Some(tier);
            }
        }
        None
    }

    /// Full watchdog tick: poll the current tier; if it failed and we
    /// descended, opportunistically try to climb back to a recovered tier.
    pub async fn watchdog_tick(&mut self) -> TierChange {
        if self.poll().await {
            return TierChange::Stable(self.current);
        }
        if let Some(tier) = self.climb_back().await {
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

/// Probe every tier best-first and return the first that currently works. This
/// is the one-shot "what tier is reachable right now" query the daemon uses; the
/// stateful `FallbackLadder` is for continuous watchdog operation.
pub async fn first_available<P: Probe>(probe: P) -> Option<Tier> {
    for tier in TIER_ORDER.iter().copied() {
        if probe.probe(tier).await.ok {
            return Some(tier);
        }
    }
    None
}

// ── Real tier probes (used by the daemon's `RealNetworkProbe`) ──

const DIRECT_PROBE_TIMEOUT_MS: u64 = 2000;

/// Direct tier: a raw TCP connect to well-known anycast addresses (no DNS), so
/// it is immune to both poisoned resolvers and HTTPS-DPI fingerprinting.
async fn probe_direct() -> ProbeVerdict {
    let targets: [([u8; 4], u16); 2] = [([1, 1, 1, 1], 443), ([8, 8, 8, 8], 443)];
    let dur = std::time::Duration::from_millis(DIRECT_PROBE_TIMEOUT_MS);
    for (ip, port) in targets {
        let addr = std::net::SocketAddr::from((std::net::Ipv4Addr::from(ip), port));
        if let Ok(Ok(_)) = tokio::time::timeout(dur, tokio::net::TcpStream::connect(addr)).await {
            return ProbeVerdict::up("tcp ok");
        }
    }
    ProbeVerdict::down("direct unreachable")
}

async fn probe_doh(resolver: &crate::doh::DohResolver) -> ProbeVerdict {
    if crate::doh::probe_network_liveness(resolver).await {
        ProbeVerdict::up("doh ok")
    } else {
        ProbeVerdict::down("doh failed/poisoned")
    }
}

async fn probe_dot() -> ProbeVerdict {
    match crate::dot::resolve("cloudflare-dns.com", crate::dot::DEFAULT_DOT_ENDPOINTS).await {
        Ok(ips) if !ips.is_empty() => ProbeVerdict::up(format!("dot ok ({} ip)", ips.len())),
        Ok(_) => ProbeVerdict::down("dot empty"),
        Err(e) => ProbeVerdict::down(format!("dot: {}", e.brief())),
    }
}

async fn probe_tunnel(profile: &str) -> ProbeVerdict {
    if crate::vps_deploy::is_dns_tunnel_configured(profile) {
        // Honest scope: we verify configuration presence, not a live server
        // round-trip (that would require a live authoritative responder).
        ProbeVerdict::up("dns-tunnel configured")
    } else {
        ProbeVerdict::down("no tunnel configured")
    }
}

/// Real ladder probe wiring the four tiers to their actual transports. Borrows
/// a profile id and the DoH resolver (both owned by the caller / daemon).
pub struct RealLadderProbe<'a> {
    pub profile: &'a str,
    pub resolver: &'a crate::doh::DohResolver,
}

impl Probe for RealLadderProbe<'_> {
    fn probe(&self, tier: Tier) -> Pin<Box<dyn Future<Output = ProbeVerdict> + Send + '_>> {
        match tier {
            Tier::Direct => Box::pin(async move { probe_direct().await }),
            Tier::DoH => {
                let resolver = self.resolver;
                Box::pin(async move { probe_doh(resolver).await })
            }
            Tier::DoT => Box::pin(async move { probe_dot().await }),
            Tier::DnsTunnel => {
                let profile = self.profile;
                Box::pin(async move { probe_tunnel(profile).await })
            }
        }
    }
}

/// Blackout drill: probe every rung of the fallback ladder top-down once and
/// report which ones currently survive. This is the app's self-test for
/// resilience — a user can run it to verify what would survive a partial or
/// total blackout WITHOUT disconnecting. Pure (generic over `Probe`) so tests
/// can script verdicts and the CLI can drive the real transports.
pub async fn drill_all_tiers<P: Probe>(probe: P) -> Vec<(Tier, ProbeVerdict)> {
    let order = [Tier::Direct, Tier::DoH, Tier::DoT, Tier::DnsTunnel];
    let mut out = Vec::with_capacity(order.len());
    for tier in order {
        let verdict = probe.probe(tier).await;
        out.push((tier, verdict));
    }
    out
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
        fn probe(&self, tier: Tier) -> Pin<Box<dyn Future<Output = ProbeVerdict> + Send + '_>> {
            let r = self
                .results
                .get(&tier)
                .cloned()
                .unwrap_or_else(|| ProbeVerdict::down("not scripted"));
            Box::pin(async move { r })
        }
    }

    #[test]
    fn ladder_order_is_best_first() {
        assert_eq!(TIER_ORDER[0], Tier::Direct);
        assert_eq!(TIER_ORDER[3], Tier::DnsTunnel);
    }

    #[tokio::test]
    async fn descends_after_repeated_failures() {
        let p = ScriptedProbe::default(); // everything down
        let mut ladder = FallbackLadder::new(p, Tier::Direct);
        assert_eq!(ladder.current(), Tier::Direct);
        ladder.poll().await; // fail 1 (below threshold)
        assert_eq!(ladder.current(), Tier::Direct);
        ladder.poll().await; // fail 2 -> descend
        assert_eq!(ladder.current(), Tier::DoH);
    }

    #[tokio::test]
    async fn recovers_when_higher_tier_returns() {
        // Drive down to DoT with an all-down probe.
        let mut ladder = FallbackLadder::new(ScriptedProbe::default(), Tier::Direct);
        for _ in 0..4 {
            ladder.poll().await;
        }
        assert_eq!(ladder.current(), Tier::DoT);

        // Now DoH comes back.
        let mut results = HashMap::new();
        results.insert(Tier::DoH, ProbeVerdict::up("ok"));
        ladder.probe = ScriptedProbe { results };

        let change = ladder.watchdog_tick().await;
        assert_eq!(change, TierChange::Recovered(Tier::DoH));
        assert_eq!(ladder.current(), Tier::DoH);
    }

    #[tokio::test]
    async fn stable_when_current_tier_healthy() {
        let mut results = HashMap::new();
        results.insert(Tier::Direct, ProbeVerdict::up("ok"));
        let mut ladder = FallbackLadder::new(ScriptedProbe { results }, Tier::Direct);
        assert_eq!(
            ladder.watchdog_tick().await,
            TierChange::Stable(Tier::Direct)
        );
    }

    #[tokio::test]
    async fn first_available_returns_best_working_tier() {
        // Direct down, DoH up → returns DoH (not DoT even though DoT also up).
        let mut results = HashMap::new();
        results.insert(Tier::Direct, ProbeVerdict::down("d"));
        results.insert(Tier::DoH, ProbeVerdict::up("ok"));
        results.insert(Tier::DoT, ProbeVerdict::up("ok"));
        assert_eq!(
            first_available(ScriptedProbe { results }).await,
            Some(Tier::DoH)
        );

        // All down → None.
        assert_eq!(first_available(ScriptedProbe::default()).await, None);

        // Only the tunnel works → DnsTunnel.
        let mut results = HashMap::new();
        results.insert(Tier::DnsTunnel, ProbeVerdict::up("ok"));
        assert_eq!(
            first_available(ScriptedProbe { results }).await,
            Some(Tier::DnsTunnel)
        );
    }

    #[tokio::test]
    async fn tunnel_probe_honors_configured_flag() {
        // No tunnel configured for a non-existent profile → down.
        let verdict = probe_tunnel("no-such-profile").await;
        assert!(!verdict.ok);
        assert!(verdict.note.contains("no tunnel"));
    }

    /// The blackout drill probes every tier top-down and reports each verdict,
    /// so the user sees exactly which rung would survive a blackout.
    #[tokio::test]
    async fn drill_reports_all_four_tiers_in_order() {
        let mut results = HashMap::new();
        results.insert(Tier::Direct, ProbeVerdict::down("poisoned"));
        results.insert(Tier::DoH, ProbeVerdict::up("doh ok"));
        results.insert(Tier::DoT, ProbeVerdict::down("dot tls reset"));
        results.insert(Tier::DnsTunnel, ProbeVerdict::up("tunnel configured"));
        let report = drill_all_tiers(ScriptedProbe { results }).await;
        assert_eq!(report.len(), 4);
        // Order is top-down: Direct, DoH, DoT, DnsTunnel.
        assert_eq!(report[0].0, Tier::Direct);
        assert!(!report[0].1.ok);
        assert_eq!(report[1].0, Tier::DoH);
        assert!(report[1].1.ok);
        assert_eq!(report[2].0, Tier::DoT);
        assert!(!report[2].1.ok);
        assert_eq!(report[3].0, Tier::DnsTunnel);
        assert!(report[3].1.ok);
    }
}
