//! Connectivity state machine + fallback ladder.
//!
//! On a heavily censored network no single path is guaranteed. This module
//! provides a small state machine that walks down a ladder of transport tiers —
//! direct clean-IP → DoH (pinned) → DoT → DNS tunnel — and climbs back up as
//! soon as a higher tier recovers. Each tier owns a probe; the app plugs in the
//! real probes (CLI/GUI), tests plug in scripted ones.

use std::future::Future;
use std::pin::Pin;

use crate::dnstunnel::Resolver as _;

/// Gate for the scheduled blackout drill (`drill_all_tiers`). Production
/// defaults to enabled. Hermetic daemon unit tests disable it (via
/// `daemon_home`) so a daemon tick never performs a live fallback-ladder
/// probe just because `last_drill_ts` defaulted to 0.
static DRILL_ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Returns whether the scheduled blackout drill is enabled.
pub fn drill_enabled() -> bool {
    DRILL_ENABLED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Enables/disables the scheduled blackout drill (test-only API).
pub fn set_drill_enabled(on: bool) {
    DRILL_ENABLED.store(on, std::sync::atomic::Ordering::Relaxed);
}

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
    /// Optional liveness sentinel (doctrine C). When set, the caller feeds it
    /// per-route traffic via `record_outbound`/`record_inbound`; if it flags a
    /// half-open stall, `watchdog_tick` force-verifies the route instead of
    /// waiting for `max_fails` probe failures.
    sentinel: Option<crate::liveness_sentinel::LivenessSentinel>,
}

impl<P: Probe> FallbackLadder<P> {
    /// Build a ladder starting at `start` (usually `Tier::Direct`).
    pub fn new(probe: P, start: Tier) -> Self {
        Self {
            probe,
            current: start,
            fails_in_row: 0,
            max_fails: policy::MAX_FAILS_BEFORE_DESCEND,
            sentinel: None,
        }
    }

    /// Attach a liveness sentinel to this ladder (doctrine C). Returns `self`
    /// for chaining.
    pub fn with_sentinel(mut self, s: crate::liveness_sentinel::LivenessSentinel) -> Self {
        self.sentinel = Some(s);
        self
    }

    /// Record outbound traffic on the current route (feeds the sentinel).
    pub fn record_outbound(&mut self, bytes: u64) {
        if let Some(s) = self.sentinel.as_mut() {
            s.record_outbound(bytes);
        }
    }

    /// Record inbound traffic on the current route (feeds the sentinel).
    pub fn record_inbound(&mut self, bytes: u64) {
        if let Some(s) = self.sentinel.as_mut() {
            s.record_inbound(bytes);
        }
    }

    /// True if the sentinel reports a confirmed half-open stall for the current
    /// route (should trigger a soft-break / force re-verify).
    pub fn sentinel_wants_break(&self) -> bool {
        self.sentinel
            .as_ref()
            .map(|s| s.should_break())
            .unwrap_or(false)
    }

    /// Override how many consecutive failures trigger a descend.
    pub fn with_max_fails(mut self, n: u32) -> Self {
        self.max_fails = n.max(1);
        self
    }

    pub fn current(&self) -> Tier {
        self.current
    }

    /// Probe an arbitrary tier without mutating ladder state. Used to verify a
    /// tier we just descended to (e.g. the daemon's liveness probe deciding
    /// whether the network is up after a descend).
    pub async fn probe_tier(&self, tier: Tier) -> ProbeVerdict {
        self.probe.probe(tier).await
    }

    /// Network-liveness query backed by ladder state. If the current tier is
    /// healthy, we report it and opportunistically climb back to a better tier
    /// if one has recovered. If the current tier fails, we descend rung by
    /// rung (direct → DoH → DoT → DNS tunnel) until we find one that works, or
    /// report `(false, None)` when every tier is down (total blackout). The
    /// ladder's `current` tier is updated so successive ticks remember where we
    /// landed instead of restarting from Direct every time.
    pub async fn liveness_status(&mut self) -> (bool, Option<Tier>) {
        // 1. Is the current tier still healthy?
        if self.probe_tier(self.current).await.ok {
            self.fails_in_row = 0;
            // Opportunistic climb-back: if a strictly-higher tier has
            // recovered, adopt it (we prefer the best tier).
            if let Some(higher) = self.climb_back().await {
                return (true, Some(higher));
            }
            return (true, Some(self.current));
        }
        // 2. Current tier failed — descend rung by rung until one works.
        while self.current.rank() < TIER_ORDER.len() - 1 {
            let next = TIER_ORDER[self.current.rank() + 1];
            self.current = next;
            if self.probe_tier(next).await.ok {
                self.fails_in_row = 0;
                return (true, Some(next));
            }
        }
        self.fails_in_row += 1;
        (false, None)
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
        // Doctrine C: if the liveness sentinel flags a confirmed half-open
        // stall, bypass the max_fails patience and force-verify the route now.
        if self.sentinel_wants_break() {
            if !self.probe_tier(self.current).await.ok {
                self.fails_in_row = 0;
                self.descend();
                return TierChange::Descended(self.current);
            }
            // Route actually recovered — reset sentinel counters.
            if let Some(s) = self.sentinel.as_mut() {
                s.reset();
            }
            return TierChange::Stable(self.current);
        }

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
    match crate::vps_deploy::load_tunnel_client_config(profile) {
        None => ProbeVerdict::down("no tunnel configured"),
        Some(cfg) => {
            // Worker-hosted tunnel → HTTPS liveness probe (no raw UDP).
            if cfg.is_worker_mode() {
                return probe_worker_tunnel_live(
                    &cfg,
                    std::time::Duration::from_millis(TUNNEL_PROBE_TIMEOUT_MS),
                );
            }
            // Live round-trip against the authoritative tunnel server. This
            // replaces the old "config presence only" check, so a dead /
            // unreachable VPS no longer reports a false "tunnel up" during a
            // total blackout. Timeout is short — the tunnel is a last-resort
            // tier, so a slow answer is treated as down.
            if crate::dnstunnel::probe_tunnel_live(
                &cfg,
                std::time::Duration::from_millis(TUNNEL_PROBE_TIMEOUT_MS),
            )
            .await
            {
                ProbeVerdict::up("dns-tunnel live")
            } else {
                ProbeVerdict::down("dns-tunnel unreachable")
            }
        }
    }
}

/// Probe a worker-hosted DNS tunnel: send a ping frame to the deployed worker
/// over HTTPS and require a valid pong reply within `timeout`. Returns `Up`
/// only on a successful round-trip.
pub fn probe_worker_tunnel_live(
    cfg: &crate::vps_deploy::TunnelClientConfig,
    timeout: std::time::Duration,
) -> ProbeVerdict {
    let Some(url) = &cfg.worker_url else {
        return ProbeVerdict::down("worker tunnel missing url");
    };
    let Some(secret) = &cfg.shared_secret else {
        return ProbeVerdict::down("worker tunnel missing secret");
    };
    let resolver =
        crate::worker_tunnel::resolver::WorkerTunnelResolver::with_timeout(url, secret, timeout);
    let frame = crate::dnstunnel::TunnelFrame {
        session: cfg.session.clone(),
        seq: 1,
        flags: 1, // ping
        payload: b"alive".to_vec(),
    };
    let qname = frame.encode_name(&cfg.base_domain, rand::random::<u32>() & 0xFFFF);
    match resolver.query_txt(&qname) {
        Ok(reply) => match crate::dnstunnel::TunnelFrame::decode_name(
            reply.trim_end_matches('.'),
            &cfg.base_domain,
        ) {
            Ok(r) if r.flags == 0x81 && r.payload == b"pong" => {
                ProbeVerdict::up("worker tunnel live")
            }
            Ok(_) => ProbeVerdict::down("worker tunnel bad reply"),
            Err(_) => ProbeVerdict::down("worker tunnel decode failed"),
        },
        Err(_) => ProbeVerdict::down("worker tunnel unreachable"),
    }
}

/// Timeout for the live DNS-tunnel round-trip probe.
const TUNNEL_PROBE_TIMEOUT_MS: u64 = 2500;

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

/// Owned variant of `RealLadderProbe` with no borrows — used by the daemon to
/// hold a persistent, stateful `FallbackLadder` across ticks. Owns the profile
/// id and the DoH resolver so the ladder can live as long as the daemon.
pub struct OwnedLadderProbe {
    pub profile: String,
    pub resolver: crate::doh::DohResolver,
}

impl Probe for OwnedLadderProbe {
    fn probe(&self, tier: Tier) -> Pin<Box<dyn Future<Output = ProbeVerdict> + Send + '_>> {
        match tier {
            Tier::Direct => Box::pin(async move { probe_direct().await }),
            Tier::DoH => {
                let resolver = &self.resolver;
                Box::pin(async move { probe_doh(resolver).await })
            }
            Tier::DoT => Box::pin(async move { probe_dot().await }),
            Tier::DnsTunnel => {
                let profile = self.profile.clone();
                Box::pin(async move { probe_tunnel(&profile).await })
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

    // ── worker-mode tunnel probe tests ──
    // A worker-mode tunnel with no reachable worker resolves by exercising the
    // resolve worker tunnel live probe against a mock worker. These verify the
    // dispatch (worker vs vps) and the live-probe verdict logic.

    #[test]
    fn worker_mode_config_roundtrips() {
        use crate::vps_deploy::{TunnelClientConfig, TunnelMode};
        let cfg = TunnelClientConfig {
            host: "https://w.sub.workers.dev".into(),
            base_domain: "t.un.dastyab.dev".into(),
            session: "s".into(),
            resolver: "https".into(),
            mode: TunnelMode::Worker,
            worker_url: Some("https://w.sub.workers.dev".into()),
            worker_name: Some("w".into()),
            shared_secret: Some("0123456789abcdef0123456789abcdef".into()),
            worker_vless_upstream: None,
            resolver_pool: None,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: TunnelClientConfig = serde_json::from_str(&json).unwrap();
        assert!(back.is_worker_mode());
        assert_eq!(
            back.worker_url.as_deref(),
            Some("https://w.sub.workers.dev")
        );
    }

    #[test]
    fn legacy_json_defaults_to_vps_mode() {
        use crate::vps_deploy::{TunnelClientConfig, TunnelMode};
        // Legacy config: no `mode` field → must deserialize as Vps.
        let legacy =
            r#"{"host":"1.2.3.4","base_domain":"t.example.com","session":"s","resolver":"doh"}"#;
        let cfg: TunnelClientConfig = serde_json::from_str(legacy).unwrap();
        assert_eq!(cfg.mode, TunnelMode::Vps);
        assert!(!cfg.is_worker_mode());
    }

    #[test]
    fn probe_worker_tunnel_live_down_when_url_missing() {
        use crate::vps_deploy::{TunnelClientConfig, TunnelMode};
        let cfg = TunnelClientConfig {
            host: "".into(),
            base_domain: "t.example.com".into(),
            session: "s".into(),
            resolver: "https".into(),
            mode: TunnelMode::Worker,
            worker_url: None,
            worker_name: None,
            shared_secret: None,
            worker_vless_upstream: None,
            resolver_pool: None,
        };
        let v = probe_worker_tunnel_live(&cfg, std::time::Duration::from_millis(500));
        assert!(!v.ok);
        assert!(v.note.contains("missing"));
    }

    #[tokio::test]
    async fn probe_tunnel_dispatches_worker_mode() {
        use crate::vps_deploy::{TunnelClientConfig, TunnelMode};
        // Isolate to a temp store so we never touch the real default profile.
        let base = tempfile::tempdir().unwrap().path().join(".dastyab");
        crate::store::set_mem_dir_override(base.clone());
        let id = crate::store::profiles::create_profile("kv_probe_worker", "test").unwrap();
        // A worker-mode config pointing at a dead URL (port 1 closed) → down,
        // and the note should reflect the worker path (not raw UDP).
        crate::vps_deploy::write_tunnel_client_config(
            &id,
            &TunnelClientConfig {
                host: "http://127.0.0.1:1".into(),
                base_domain: "t.example.com".into(),
                session: "s".into(),
                resolver: "https".into(),
                mode: TunnelMode::Worker,
                worker_url: Some("http://127.0.0.1:1".into()),
                worker_name: Some("w".into()),
                shared_secret: Some("a".into()),
                worker_vless_upstream: None,
                resolver_pool: None,
            },
        )
        .unwrap();
        let v = probe_tunnel(&id).await;
        assert!(!v.ok);
        assert!(v.note.contains("worker"), "note was: {}", v.note);
        let _ = std::fs::remove_dir_all(base);
    }
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

    // ── liveness_status (daemon-backed stateful probe) ──

    fn scripted(up: &[(Tier, bool)]) -> ScriptedProbe {
        let mut results = HashMap::new();
        for (t, ok) in up {
            results.insert(
                *t,
                if *ok {
                    ProbeVerdict::up("ok")
                } else {
                    ProbeVerdict::down("down")
                },
            );
        }
        ScriptedProbe { results }
    }

    /// Direct healthy → up, Direct tier reported (and the ladder stays put).
    #[tokio::test]
    async fn liveness_direct_healthy_reports_direct() {
        let mut ladder = FallbackLadder::new(scripted(&[(Tier::Direct, true)]), Tier::Direct);
        assert_eq!(ladder.liveness_status().await, (true, Some(Tier::Direct)));
        // Still Direct — no pointless descend.
        assert_eq!(ladder.current(), Tier::Direct);
    }

    /// Direct down but DoH up → the ladder descends and reports DoH.
    #[tokio::test]
    async fn liveness_descends_to_working_lower_tier() {
        let mut ladder = FallbackLadder::new(
            scripted(&[(Tier::Direct, false), (Tier::DoH, true)]),
            Tier::Direct,
        );
        assert_eq!(ladder.liveness_status().await, (true, Some(Tier::DoH)));
    }

    /// Total blackout → down, None tier, and the ladder keeps descending stepwise.
    #[tokio::test]
    async fn liveness_all_down_reports_down() {
        let all_down = scripted(&[
            (Tier::Direct, false),
            (Tier::DoH, false),
            (Tier::DoT, false),
            (Tier::DnsTunnel, false),
        ]);
        let mut ladder = FallbackLadder::new(all_down, Tier::Direct);
        assert_eq!(ladder.liveness_status().await, (false, None));
        // Descended at least one rung (Direct failed → DoH).
        assert!(ladder.current().rank() > Tier::Direct.rank());
    }

    /// A worker tier recovers → the ladder climbs back to it (stateful recovery).
    #[tokio::test]
    async fn liveness_climbs_back_when_higher_tier_recovers() {
        // Start with Direct down, DoH up → we settle on DoH.
        let mut ladder = FallbackLadder::new(
            scripted(&[(Tier::Direct, false), (Tier::DoH, true)]),
            Tier::Direct,
        );
        assert_eq!(ladder.liveness_status().await, (true, Some(Tier::DoH)));

        // Now Direct recovers: next probe should climb back to Direct.
        ladder.probe = scripted(&[(Tier::Direct, true), (Tier::DoH, true)]);
        assert_eq!(ladder.liveness_status().await, (true, Some(Tier::Direct)));
        assert_eq!(ladder.current(), Tier::Direct);
    }

    /// Direct flaky: a transient Direct failure with a healthy DoH fallback is
    /// reported as up, not down (net still reachable via DoH).
    #[tokio::test]
    async fn liveness_transient_direct_failure_still_up_via_doh() {
        let mut ladder = FallbackLadder::new(
            scripted(&[(Tier::Direct, false), (Tier::DoH, true)]),
            Tier::Direct,
        );
        assert_eq!(ladder.liveness_status().await, (true, Some(Tier::DoH)));
    }

    /// Doctrine C: a confirmed sentinel stall forces a soft-break descend even
    /// when the active probe would report the route as healthy (the probe
    /// cannot see silent blackholing of the data path).
    #[tokio::test]
    async fn sentinel_stall_forces_soft_break_descend() {
        use crate::liveness_sentinel::{LivenessSentinel, DEFAULT_STALL_TIMEOUT};
        use std::time::{Duration, Instant};

        // Probe: Direct is down, DoH is up. We set a huge max_fails so the
        // ordinary poll would need many failures to descend — but the sentinel
        // confirms a stall, so a single verified failure must break immediately.
        let p = scripted(&[(Tier::Direct, false), (Tier::DoH, true)]);
        let mut sentinel = LivenessSentinel::new("direct", DEFAULT_STALL_TIMEOUT);
        let now = Instant::now();
        sentinel.record_inbound_at(100, now); // route was alive
                                              // Feed two consecutive stalls (transmitting, inbound silent).
        sentinel.record_outbound_at(200, now + Duration::from_secs(1));
        sentinel.check_stall(now + Duration::from_secs(5));
        sentinel.record_outbound_at(50, now + Duration::from_secs(5));
        sentinel.check_stall(now + Duration::from_secs(6));
        assert!(sentinel.should_break());

        let mut ladder = FallbackLadder::new(p, Tier::Direct)
            .with_max_fails(999)
            .with_sentinel(sentinel);
        // The sentinel break must descend immediately, despite the huge
        // max_fails that would otherwise keep us on Direct for ages.
        let change = ladder.watchdog_tick().await;
        assert_eq!(change, TierChange::Descended(Tier::DoH));
        assert_eq!(ladder.current(), Tier::DoH);
    }

    /// Doctrine C: if the sentinel flags a stall but the route actually still
    /// works (e.g. a false positive), the tick verifies and stays put.
    #[tokio::test]
    async fn sentinel_stall_but_route_alive_stays() {
        use crate::liveness_sentinel::{LivenessSentinel, DEFAULT_STALL_TIMEOUT};
        use std::time::{Duration, Instant};

        // Probe: Direct up, and DoH up too (so a verify would pass).
        let p = scripted(&[(Tier::Direct, true), (Tier::DoH, true)]);
        let mut sentinel = LivenessSentinel::new("direct", DEFAULT_STALL_TIMEOUT);
        let now = Instant::now();
        sentinel.record_inbound_at(100, now);
        sentinel.record_outbound_at(200, now + Duration::from_secs(1));
        sentinel.check_stall(now + Duration::from_secs(5));
        sentinel.record_outbound_at(50, now + Duration::from_secs(5));
        sentinel.check_stall(now + Duration::from_secs(6));
        assert!(sentinel.should_break());

        let mut ladder = FallbackLadder::new(p, Tier::Direct).with_sentinel(sentinel);
        let change = ladder.watchdog_tick().await;
        // Verify passed → stay on Direct, sentinel reset.
        assert_eq!(change, TierChange::Stable(Tier::Direct));
        assert_eq!(ladder.current(), Tier::Direct);
        assert!(!ladder.sentinel_wants_break());
    }
}
