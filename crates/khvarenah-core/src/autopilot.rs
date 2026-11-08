//! Native clean-IP discovery + validation + autopilot engine (DeepSeek plan).
//!
//! This module turns a raw Cloudflare IP into a *working* VLESS frontend.
//! DeepSeek's central instruction: "the scanner is not the product — the
//! engine that keeps the endpoint alive is the product."
//!
//! Architecture (three layers, one `EndpointProvider` contract):
//!   1. **Discovery** — fetch the official Cloudflare ranges (`cf::ips`),
//!      sample a bounded candidate set, and health-probe each IP in parallel
//!      against the worker's hostname (TCP + TLS + HTTP).
//!   2. **Validation** — the candidate must actually route the worker's
//!      host. We pin the worker hostname to the candidate IP (reqwest
//!      `.resolve`) and fetch `https://<worker-host>/cdn-cgi/trace` through
//!      it. A valid Cloudflare trace body proves the edge front for that
//!      worker is alive. This kills the classic false positive where a TCP
//!      + TLS handshake succeeds against *any* Cloudflare IP.
//!   3. **Autopilot engine** — persistence (`endpoints.json` ledger), a
//!      periodic monitor loop that re-validates active endpoints and swaps
//!      in fresh ones when a front dies, plus generation of active client
//!      configs. Controlled by a single ON/OFF watch channel.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use rand::SeedableRng;

use crate::cf::ips::load_ranges;
use crate::error::CFError;
use crate::scanner::{run_scan, ScanParams, ScanResult};
use crate::store;
use crate::vless::VlessProfile;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// A validated clean endpoint (a working front for a specific worker host).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanEndpoint {
    pub ip: String,
    pub port: u16,
    /// Worker hostname used as SNI/Host (the thing we are fronting).
    pub sni: String,
    /// Composite score (higher = better). Weighted latency + throughput.
    pub score: f32,
    pub tcp_ms: f32,
    pub connect_ms: f32,
    pub download_kbps: f32,
    /// True when the endpoint passed validation (E2E front check).
    pub verified: bool,
    /// True when the last monitor check succeeded.
    #[serde(default)]
    pub alive: bool,
    #[serde(default)]
    pub last_checked: Option<String>,
    #[serde(default)]
    pub ts: String,
}

/// Parameters for one discovery/validation cycle.
#[derive(Debug, Clone)]
pub struct DiscoveryParams {
    /// How many candidate IPs to probe per cycle.
    pub sample: u32,
    /// Concurrency (parallel probes).
    pub workers: usize,
    /// Per-probe timeout in seconds.
    pub timeout_s: u32,
    /// How many validated endpoints to aim for (top_n).
    pub top_n: usize,
    /// Force a refresh of the CF range list (bypass cache).
    pub force_refresh_ranges: bool,
    /// Re-validate a candidate "dead" once after a short delay before giving
    /// up (E2E cold-start protection).
    pub retry_on_fail: bool,
    /// Known-good IP seeds (from the autopilot ledger). The scanner expands
    /// neighbourhoods around these first instead of sampling uniformly.
    /// `seed_ips` are bare IPv4 strings (no port).
    pub seed_ips: Vec<String>,
    /// Skip the step-0 worker-health gate. Used by the rescue chain, which is
    /// invoked precisely BECAUSE the worker failed the gate — re-running it
    /// would loop back into rescue forever.
    pub skip_step0: bool,
    /// Self-learning phase-2 SNI strategy for this cycle. The engine resolves
    /// the preferred persisted strategy (with rotation on repeated zero-101
    /// streaks) and pins it here so the phase-2 probe is exclusive about which
    /// SNI it tries first. `None` = WorkerOnly (the default).
    pub preferred_strategy: Option<crate::health::SniStrategy>,
}

impl Default for DiscoveryParams {
    fn default() -> Self {
        Self {
            sample: 2000,
            workers: 64,
            timeout_s: 8,
            top_n: 3,
            force_refresh_ranges: false,
            retry_on_fail: true,
            seed_ips: Vec::new(),
            skip_step0: false,
            preferred_strategy: None,
        }
    }
}

/// Rotate the self-learning phase-2 SNI strategy to the next exclusive variant.
/// Only `WorkerOnly` and `GenericCfFirst` are rotatable — they are the two
/// *exclusive* single-first strategies whose zero-101 outcome is measurable.
/// `WorkerThenGenericCf` is a blend and is never a rotation target (it is kept
/// only as a backward-compatible default for older configs).
pub fn rotate_strategy(s: crate::health::SniStrategy) -> crate::health::SniStrategy {
    match s {
        crate::health::SniStrategy::WorkerOnly => crate::health::SniStrategy::GenericCfFirst,
        crate::health::SniStrategy::GenericCfFirst => crate::health::SniStrategy::WorkerOnly,
        crate::health::SniStrategy::WorkerThenGenericCf => crate::health::SniStrategy::WorkerOnly,
    }
}

/// --- v2 rolling-window strategy (round 3) ---
///
/// Replaces the v1 consecutive-zero streak (which never rotated when a strategy
/// occasionally won — the "sticky success" bug). Tracks a rolling window of
/// discovery outcomes and adds forced exploration so the app cannot lock onto a
/// suboptimal strategy.
///
/// Rolling window length (number of recent discovery outcomes considered).
pub const STRATEGY_WINDOW: usize = 10;
/// Success rate below which the window counts as failure-driven rotation.
pub const STRATEGY_MIN_SUCCESS_RATE: f32 = 0.30;
/// Discovery cycles after which rotation is forced even if the strategy is
/// winning (exploration guarantee — can't lock onto a marginal winner).
pub const STRATEGY_FORCED_ROTATION_CYCLES: u32 = 20;
/// Consecutive zero-verified discovery cycles that trigger early rotation
/// without waiting for the full window.
pub const STRATEGY_EARLY_DEAD_CYCLES: usize = 3;

/// Roll state for the self-learning phase-2 SNI strategy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrategyState {
    /// The strategy currently in use.
    pub current: crate::health::SniStrategy,
    /// Recent discovery outcomes: true = any accepted 101 (won), false = zero.
    /// Newest is the last element. Capped at `STRATEGY_WINDOW`.
    pub recent_outcomes: Vec<bool>,
    /// Discovery cycles since the last rotation.
    pub cycles_since_rotation: u32,
}

impl Default for StrategyState {
    fn default() -> Self {
        Self {
            current: crate::health::SniStrategy::WorkerOnly,
            recent_outcomes: Vec::new(),
            cycles_since_rotation: 0,
        }
    }
}

/// Push a discovery outcome onto the window, trimming to `STRATEGY_WINDOW` and
/// incrementing the since-rotation counter.
pub fn record_cycle_outcome(state: &mut StrategyState, any_101: bool) {
    state.recent_outcomes.push(any_101);
    if state.recent_outcomes.len() > STRATEGY_WINDOW {
        let excess = state.recent_outcomes.len() - STRATEGY_WINDOW;
        let mut drain = state.recent_outcomes.drain(..excess);
        drain.next();
    }
    state.cycles_since_rotation = state.cycles_since_rotation.saturating_add(1);
}

/// Success rate over the current window (None when empty).
pub fn success_rate(state: &StrategyState) -> Option<f32> {
    if state.recent_outcomes.is_empty() {
        return None;
    }
    let wins = state.recent_outcomes.iter().filter(|&&w| w).count();
    Some(wins as f32 / state.recent_outcomes.len() as f32)
}

/// Whether the app should rotate away from the current strategy.
pub fn should_rotate(state: &StrategyState) -> bool {
    let n = state.recent_outcomes.len();
    if n >= STRATEGY_EARLY_DEAD_CYCLES && success_rate(state) == Some(0.0) {
        // (a) early dead: enough zero outcomes with zero success → rotate fast.
        return true;
    }
    if n >= STRATEGY_WINDOW && success_rate(state) < Some(STRATEGY_MIN_SUCCESS_RATE) {
        // (b) windowed failure: full window below the success floor.
        return true;
    }
    if state.cycles_since_rotation >= STRATEGY_FORCED_ROTATION_CYCLES {
        // (c) forced exploration: even a winning strategy gets rotated.
        return true;
    }
    false
}

/// Rotate to the other exclusive strategy and reset the window + counter.
pub fn rotate(mut state: StrategyState) -> StrategyState {
    state.current = rotate_strategy(state.current);
    state.recent_outcomes.clear();
    state.cycles_since_rotation = 0;
    state
}

fn strategy_from_name(name: &str) -> crate::health::SniStrategy {
    match name {
        "GenericCfFirst" => crate::health::SniStrategy::GenericCfFirst,
        "WorkerThenGenericCf" => crate::health::SniStrategy::WorkerThenGenericCf,
        _ => crate::health::SniStrategy::WorkerOnly,
    }
}

fn strategy_name(s: crate::health::SniStrategy) -> &'static str {
    match s {
        crate::health::SniStrategy::WorkerOnly => "WorkerOnly",
        crate::health::SniStrategy::GenericCfFirst => "GenericCfFirst",
        crate::health::SniStrategy::WorkerThenGenericCf => "WorkerThenGenericCf",
    }
}

/// Resolve the v2 strategy state for a cycle from the persisted profile.
pub fn resolve_strategy_v2(profile_id: &str) -> StrategyState {
    let current = crate::store::profiles::strategy_current(profile_id)
        .map(|s| strategy_from_name(&s))
        .unwrap_or(crate::health::SniStrategy::WorkerOnly);
    let outcomes = crate::store::profiles::strategy_recent_outcomes(profile_id)
        .into_iter()
        .map(|b| b != 0)
        .collect();
    let cycles = crate::store::profiles::strategy_cycles_since_rotation(profile_id);
    StrategyState {
        current,
        recent_outcomes: outcomes,
        cycles_since_rotation: cycles,
    }
}

/// Record a discovery outcome, optionally rotate, and persist. `any_101` is
/// whether this discovery cycle produced ≥1 accepted phase-2 `101` (i.e. clean
/// endpoints). Returns whether a rotation happened.
pub fn commit_strategy_v2(
    profile_id: &str,
    state: &mut StrategyState,
    any_101: bool,
) -> Result<bool, CFError> {
    record_cycle_outcome(state, any_101);
    let mut rotated = false;
    if should_rotate(state) {
        *state = rotate(state.clone());
        rotated = true;
    }
    let last_rotated = if rotated {
        crate::store::now_ts() as i64
    } else {
        crate::store::profiles::strategy_last_rotated_ts(profile_id)
    };
    crate::store::profiles::commit_strategy_state_v2(
        profile_id,
        Some(strategy_name(state.current).to_string()),
        state.recent_outcomes.iter().map(|&w| u8::from(w)).collect(),
        state.cycles_since_rotation,
        last_rotated,
    )?;
    Ok(rotated)
}

/// Build a [`crate::health_beacon::HealthBeacon`] from persisted profile state
/// plus the current cycle's contextual facts. Read-mostly plumbing: every
/// subsurface value already lives in the store or the cycle's own scope.
pub fn compose_beacon(
    profile_id: &str,
    kind: crate::health_beacon::CycleKind,
    cycle_ts: i64,
    duration_ms: u64,
    worker_health_label: Option<&str>,
    active_alive: Option<bool>,
    last_error: Option<String>,
) -> crate::health_beacon::HealthBeacon {
    let cfg = crate::store::profiles::load_profile(profile_id).config;
    let now = crate::store::now_ts() as i64;

    let mut b = crate::health_beacon::HealthBeacon::new(kind, cycle_ts);
    b.written_at = now;
    b.cycle_duration_ms = duration_ms;
    b.protection_enabled = cfg.protection_enabled;

    // Daemon owner (pid + start) if the daemon is running.
    let dstate = crate::daemon::load_daemon_state(profile_id);
    if dstate.pid > 0 {
        b.daemon_pid = Some(dstate.pid);
        b.daemon_started_at = (dstate.started_at > 0).then_some(dstate.started_at);
    }

    // Worker health label.
    b.worker_health =
        crate::health_beacon::worker_health_label(worker_health_label.unwrap_or("Skipped"));

    // Active ledger endpoint + rtt.
    if let Some(ep) = crate::cleanip::active_ledger_endpoint(profile_id) {
        b.active_endpoint = Some(ep);
        if let Some(active_alive) = active_alive {
            b.active_alive = active_alive;
        }
    }

    // Bundle condition.
    if let Ok(dir) = crate::cleanip::user_config_dir(profile_id) {
        b.bundle_dir = Some(dir.display().to_string());
        if b.active_endpoint.is_some() {
            let active = b.active_endpoint.clone().unwrap_or_default();
            b.bundle_in_sync = matches!(
                crate::cleanip::check_bundle_drift(&dir, &active),
                crate::cleanip::BundleDrift::InSync
            );
        }
    }
    b.bundle_last_checked = now;

    // Strategy v2.
    let st = resolve_strategy_v2(profile_id);
    b.strategy_current = strategy_name(st.current).to_string();
    b.strategy_window = st.recent_outcomes.iter().map(|&w| u8::from(w)).collect();
    b.strategy_rate = success_rate(&st);
    b.strategy_cycles_since_rotation = st.cycles_since_rotation;
    b.strategy_last_rotated_ts =
        (cfg.strategy_last_rotated_ts > 0).then_some(cfg.strategy_last_rotated_ts);

    // Rescue meta.
    b.last_rescue_outcome = cfg.last_rescue_outcome.clone();
    b.last_rescue_ts = (cfg.last_rescue_attempt_ts > 0).then_some(cfg.last_rescue_attempt_ts);

    b.last_error = last_error;
    b
}

/// The `EndpointProvider` contract. Two implementations ship today:
/// `NativeCfProvider` (Rust-native discovery) and `SenpaiProvider` (thin
/// wrapper around the SenPaiScanner binary, kept as a fallback/debug mode).
pub trait EndpointProvider: Send + Sync {
    /// Discover and validate up to `top_n` clean endpoints for `vless`.
    fn discover<'a>(
        &'a self,
        vless: &'a VlessProfile,
        params: &'a DiscoveryParams,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<CleanEndpoint>, CFError>> + Send + 'a>>;
}

// ---------------------------------------------------------------------------
// Native provider: discovery + validation
// ---------------------------------------------------------------------------

/// Rust-native provider: Cloudflare ranges + parallel probes + front check.
pub struct NativeCfProvider {
    profile_id: String,
}

impl Default for NativeCfProvider {
    fn default() -> Self {
        Self {
            profile_id: "default".to_string(),
        }
    }
}

impl EndpointProvider for NativeCfProvider {
    fn discover<'a>(
        &'a self,
        vless: &'a VlessProfile,
        params: &'a DiscoveryParams,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<CleanEndpoint>, CFError>> + Send + 'a>> {
        Box::pin(discover_native(vless, params, &self.profile_id))
    }
}

/// The native discovery pipeline: neighbourhood-aware candidate generation
/// (seeds + /24 expansion + weighted sample) → SlipNet-style two-phase
/// streaming scan → ranked clean endpoints. Each accepted endpoint has passed
/// the fast TCP prefilter *and* the real-client TLS+WS upgrade gate, so
/// `verified` is set at probe time.
async fn discover_native(
    vless: &VlessProfile,
    params: &DiscoveryParams,
    profile_id: &str,
) -> Result<Vec<CleanEndpoint>, CFError> {
    let target = crate::health::derive_ws_target(vless);
    let sni = target.sni.clone();
    let path = target.path.clone();
    let timeout_s = params.timeout_s.max(1);

    // Step 0 — worker-health gate (DeepSeek plan #1). If the worker is dead,
    // suspended, or path-mismatched, no scanner can find clean IPs: short-
    // circuit with a plain-language diagnosis instead of wasting a scan.
    // Skipped when `skip_step0` is set (rescue chain: we got here precisely
    // because the gate failed, so re-running it would loop forever).
    let cidrs = load_ranges(params.force_refresh_ranges).await?;
    if !params.skip_step0 {
        match crate::autopilot::step0_gate(&sni, timeout_s as u64, &cidrs).await {
            crate::autopilot::WorkerHealth::Alive => {}
            other => {
                let cause = match other {
                    crate::autopilot::WorkerHealth::Suspended { .. }
                    | crate::autopilot::WorkerHealth::NotFound => {
                        crate::diagnose::PlainCause::WorkerDead
                    }
                    crate::autopilot::WorkerHealth::PathMismatch => {
                        crate::diagnose::PlainCause::WorkerPathMismatch
                    }
                    crate::autopilot::WorkerHealth::Unreachable => {
                        crate::diagnose::PlainCause::NetworkBlocked
                    }
                    crate::autopilot::WorkerHealth::Alive => unreachable!(),
                };
                let msg = crate::diagnose::plain_message(cause, crate::diagnose::Locale::En);
                return Err(CFError::new(
                    "Worker offline",
                    msg,
                    "Check the Workers dashboard or try another network.",
                ));
            }
        }
    }

    // Candidate generation: seeds first, then /24 neighbors, then weighted
    // sampling proportional to CIDR block size (SlipNet-style).
    let seeded =
        crate::cf::ips::seeded_candidates(&params.seed_ips, &cidrs, params.sample as usize, 24);
    let mut candidate_ips = seeded;
    if candidate_ips.len() < (params.sample as usize) {
        let missing = (params.sample as usize) - candidate_ips.len();
        let mut rng = rand::rngs::StdRng::from_entropy();
        let extra = crate::cf::ips::weighted_sample_by_cidr(&cidrs, missing, &mut rng);
        let mut seen: std::collections::HashSet<String> = candidate_ips.iter().cloned().collect();
        for ip in extra {
            if seen.insert(ip.clone()) {
                candidate_ips.push(ip);
            }
        }
    }
    candidate_ips.truncate(params.sample as usize);
    if candidate_ips.is_empty() {
        return Err(CFError::new(
            "No candidates",
            "The Cloudflare range list produced no candidate IPs.",
            "Check network connectivity and retry.",
        ));
    }

    let target_n = params.top_n.max(1);
    let vless_link = vless.share_link();
    let direct_ip = crate::e2e::fetch_direct_ip(params.timeout_s.clamp(3, 20) as u64)
        .await
        .ok();

    // Local builder for one pipeline round (rebuildable per expansion round).
    // The phase-2 SNI strategy is resolved once per cycle (Copy) and captured
    // by value, so the boxed future does not borrow `params`.
    let cycle_strategy = params
        .preferred_strategy
        .unwrap_or(crate::health::SniStrategy::WorkerOnly);
    let run_round = |cands: Vec<String>| {
        let phase1: crate::slipscan::Phase1Fn = Box::new(move |ip: &str, fast_fail_ms: u64| {
            let ip = ip.to_string();
            Box::pin(async move { crate::health::probe_fast_any_port(&ip, fast_fail_ms).await })
        });
        let phase2: crate::slipscan::Phase2Fn =
            Box::new(move |ip: &str, sni: &str, path: &str, ws_timeout_ms: u64| {
                let ip = ip.to_string();
                let sni = sni.to_string();
                let path = path.to_string();
                let strategy = cycle_strategy;
                Box::pin(async move {
                    crate::health::probe_with_sni_strategy(
                        &ip,
                        &sni,
                        crate::health::GENERIC_CF_SNI,
                        &sni,
                        &path,
                        ws_timeout_ms,
                        strategy,
                    )
                    .await
                })
            });
        let e2e: crate::slipscan::E2eFn =
            Box::new(move |ip: &str, port: u16, vless: &str, timeout_s: u64| {
                let ip = ip.to_string();
                let vless = vless.to_string();
                let bin = crate::e2e::singbox_bin();
                Box::pin(async move {
                    let _ = crate::e2e::ensure_singbox("1.11.4").await;
                    crate::e2e::verify_tunnel(&ip, port, &vless, "0.0.0.0", &bin, timeout_s).await
                })
            });
        let pipeline_params = crate::slipscan::PipelineParams {
            target_n,
            phase1_workers: params.workers.max(1),
            phase2_workers: (params.workers / 4).clamp(4, 48),
            e2e_workers: 4,
            score_threshold: crate::health::ACCEPT_THRESHOLD,
            fast_fail_ms: crate::health::FAST_FAIL_MS,
            ws_timeout_ms: timeout_s as u64 * 1000,
        };
        crate::slipscan::pipeline_scan(
            cands,
            &sni,
            &path,
            &vless_link,
            direct_ip.clone(),
            pipeline_params,
            phase1,
            phase2,
            e2e,
            None,
            None,
        )
    };

    let mut examined: std::collections::HashSet<String> = candidate_ips.iter().cloned().collect();

    let first = run_round(candidate_ips).await?;
    let mut diagnostics = Some(first.diagnostics.clone());
    let mut verified = first.verified;

    // Multi-round cluster expansion (SlipNet style): when we find fewer than
    // target_n clean IPs, expand around the ones we DID find (their /24
    // siblings) and scan those next. One hit becomes a cluster. Bounded to
    // avoid runaway scans; only runs while there is still room to improve.
    let mut round = 0;
    while verified.len() < target_n && round < 3 && !verified.is_empty() {
        let expanded = crate::cf::ips::expand_around(&verified, 24, 254);
        let mut new_cands = Vec::new();
        for ip in expanded {
            if examined.insert(ip.clone()) {
                new_cands.push(ip);
            }
        }
        if new_cands.is_empty() {
            break;
        }
        let r = run_round(new_cands).await?;
        if let Some(d) = &mut diagnostics {
            d.examined_total = d
                .examined_total
                .saturating_add(r.diagnostics.examined_total);
            d.phase1_pass = d.phase1_pass.saturating_add(r.diagnostics.phase1_pass);
            d.phase2_pass = d.phase2_pass.saturating_add(r.diagnostics.phase2_pass);
            d.score_above_threshold = d
                .score_above_threshold
                .saturating_add(r.diagnostics.score_above_threshold);
            d.e2e_pass = d.e2e_pass.saturating_add(r.diagnostics.e2e_pass);
        }
        for ep in r.verified {
            if !verified.iter().any(|v| v.ip == ep.ip) {
                verified.push(ep);
            }
        }
        verified.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        verified.truncate(target_n);
        round += 1;
    }

    // Persist diagnostics so the GUI/CLI can explain a zero result.
    if let Some(d) = diagnostics {
        let _ = crate::store::profiles::save_last_diagnostics(profile_id, &d);
    }

    Ok(verified)
}

/// Health state of the worker's route, as observed by a one-shot probe.
/// Used as a step-0 gate so a scan never runs against a dead/misconfigured
/// worker (DeepSeek plan #1 — the #1 cause of "zero clean IPs").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerHealth {
    /// The worker answered a healthy probe (HTTP 200/101 or textual trace).
    Alive,
    /// The route responds, but with a status that suggests no worker there.
    NotFound,
    /// The account/worker is suspended or errored (e.g. CF 9109).
    Suspended { code: u16 },
    /// The worker responds but on a path the app didn't ask for.
    PathMismatch,
    /// No TCP/TLS/HTTP response at all (network or worker unreachable).
    Unreachable,
}

/// Step-0 worker-health probe. Does a real TLS handshake + HTTP GET against
/// the worker's hostname (its own host, not a clean-IP front), then classifies
/// the response. This is cheap (~300ms) and runs once per scan/cycle.
///
/// `connect_ip` lets the caller bypass DNS entirely: when provided, we connect
/// to that literal IP (which must front the worker) while still sending
/// `worker_host` as the SNI/Host. This is essential on censored networks
/// where system DNS is hijacked (e.g. 198.18.x.x in Iran) — the hostname
/// itself may never resolve to a real address.
pub async fn probe_worker_health(
    worker_host: &str,
    connect_ip: Option<std::net::Ipv4Addr>,
    resolver: Option<&crate::doh::DohResolver>,
    timeout_s: u64,
) -> WorkerHealth {
    let timeout_ms = timeout_s.max(1) * 1000;

    let connect_addr = match connect_ip {
        Some(ip) => ip.to_string(),
        None => {
            // Prefer the supplied DoH resolver (immune to system-DNS hijack),
            // then fall back to system DNS with hijack rejection. DoH already
            // filters 198.18.x.x.
            match resolve_worker_host(worker_host, resolver).await {
                Some(ip) => ip.to_string(),
                None => return WorkerHealth::Unreachable,
            }
        }
    };

    let stream = match crate::health::tls_connect(&connect_addr, 443, worker_host, timeout_ms).await
    {
        Ok(s) => s,
        Err(_) => return WorkerHealth::Unreachable,
    };

    classify_worker_response(stream, worker_host, timeout_ms).await
}

/// Resolve `worker_host` to a usable IPv4 address. When `doh` is provided it is
/// tried first (it is immune to system-DNS hijack); on failure we fall back to
/// `std::net::ToSocketAddrs` and reject hijacked 198.18.x.x answers.
async fn resolve_worker_host(
    worker_host: &str,
    doh: Option<&crate::doh::DohResolver>,
) -> Option<std::net::Ipv4Addr> {
    if let Some(resolver) = doh {
        if let Ok(ips) = resolver.resolve(worker_host).await {
            if let Some(ip) = ips
                .into_iter()
                .find(|ip| !crate::health::is_hijacked_ip(ip))
            {
                return Some(ip);
            }
        }
    }
    if let Ok(iter) = std::net::ToSocketAddrs::to_socket_addrs(&(worker_host.to_string(), 443u16)) {
        for a in iter {
            if let std::net::SocketAddr::V4(v4) = a {
                let ip = v4.ip();
                if !crate::health::is_hijacked_ip(ip) {
                    return Some(*ip);
                }
            }
        }
    }
    None
}

/// Perform the TLS handshake + `GET /cdn-cgi/trace` against `worker_host` via
/// an already-established TLS stream, and classify the response. Shared by the
/// hostname-gate and the DNS-free CF-sample gate.
async fn classify_worker_response(
    mut stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    worker_host: &str,
    timeout_ms: u64,
) -> WorkerHealth {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let req = format!(
        "GET /cdn-cgi/trace HTTP/1.1\r\nHost: {worker_host}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    if tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        stream.write_all(req.as_bytes()),
    )
    .await
    .is_err()
        || stream.flush().await.is_err()
    {
        return WorkerHealth::Unreachable;
    }
    let mut buf = [0u8; 8192];
    let mut head = Vec::new();
    let read_res = tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), async {
        let mut total = 0usize;
        let mut headers_done = false;
        while total < 16 * 1024 {
            match stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    head.extend_from_slice(&buf[..n]);
                    total += n;
                    if !headers_done && head.windows(4).any(|w| w == b"\r\n\r\n") {
                        headers_done = true;
                    }
                    if headers_done && total >= 512 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    })
    .await;
    if read_res.is_err() {
        return WorkerHealth::Unreachable;
    }
    let text = String::from_utf8_lossy(&head);
    classify_worker_health(&text)
}

/// Pure classification of a raw HTTP response head into a `WorkerHealth`.
/// Split out for deterministic unit testing.
pub fn classify_worker_health(text: &str) -> WorkerHealth {
    if text.contains("HTTP/1.1 200") || text.contains("HTTP/1.1 101") {
        return WorkerHealth::Alive;
    }
    // Cloudflare account/worker error codes take precedence over generic 4xx
    // path heuristics: a 403/500 with 9109 (invalid token) or a suspended/
    // disabled marker is an account-level problem, not a path mismatch.
    if text.contains("9109") || text.contains("disabled") || text.contains("suspended") {
        return WorkerHealth::Suspended { code: 9109 };
    }
    if text.contains("HTTP/1.1 404")
        || text.contains("HTTP/1.1 400")
        || text.contains("HTTP/1.1 426")
        || text.contains("HTTP/1.1 403")
    {
        // 403/404 on the trace route => likely path mismatch or wrong host.
        return WorkerHealth::PathMismatch;
    }
    if text.contains("HTTP/1.1") {
        WorkerHealth::Suspended { code: 500 }
    } else {
        WorkerHealth::Unreachable
    }
}

/// Summary of a DNS-free worker-health sweep across a sample of Cloudflare IPs.
#[derive(Debug, Clone, Default)]
pub struct WorkerHealthSample {
    pub alive: bool,
    pub responding_ip: Option<std::net::Ipv4Addr>,
    pub attempted: u32,
    pub successful: u32,
    pub path_mismatch: u32,
    pub suspended: u32,
    pub unreachable: u32,
}

/// Probe the worker's health by connecting to a sample of literal Cloudflare IPs
/// (from the known ranges) with SNI=worker_host — **no DNS anywhere in the path**.
/// On censored networks where system DNS is hijacked, this is the only reliable
/// way to establish that the worker is alive before scanning. Early-exits on the
/// first 200/101.
pub async fn probe_worker_via_cf_sample(
    worker_host: &str,
    ranges: &[crate::cf::ips::Cidr],
    sample: usize,
    timeout_s: u64,
) -> WorkerHealthSample {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let ips = crate::cf::ips::weighted_sample_by_cidr(ranges, sample.max(1), &mut rng);
    probe_worker_via_ips(worker_host, &ips, 443, timeout_s).await
}

/// The core sweep loop: probe each literal IP in `ips` with SNI=worker_host,
/// early-exiting on the first 200/101. Split out so tests can drive it with a
/// fixed IP list and a custom port (e.g. the mock worker on loopback).
pub async fn probe_worker_via_ips(
    worker_host: &str,
    ips: &[String],
    port: u16,
    timeout_s: u64,
) -> WorkerHealthSample {
    let timeout_ms = timeout_s.max(1) * 1000;
    let mut out = WorkerHealthSample::default();
    for ip_str in ips {
        out.attempted += 1;
        let stream = match crate::health::tls_connect(ip_str, port, worker_host, timeout_ms).await {
            Ok(s) => s,
            Err(_) => {
                out.unreachable += 1;
                continue;
            }
        };
        match classify_worker_response(stream, worker_host, timeout_ms).await {
            WorkerHealth::Alive => {
                out.alive = true;
                out.successful += 1;
                out.responding_ip = ip_str.parse().ok();
                break;
            }
            WorkerHealth::PathMismatch => out.path_mismatch += 1,
            WorkerHealth::Suspended { .. } => out.suspended += 1,
            WorkerHealth::Unreachable | WorkerHealth::NotFound => out.unreachable += 1,
        }
    }
    out
}

/// The step-0 gate used by discovery. First tries the fast hostname path
/// (`probe_worker_health`), which works when DNS is healthy; if that fails to
/// prove the worker is alive, falls back to the DNS-free CF-sample sweep so a
/// hijacked resolver can never block a usable scan.
pub async fn step0_gate(
    worker_host: &str,
    timeout_s: u64,
    cidrs: &[crate::cf::ips::Cidr],
) -> WorkerHealth {
    // Fast path: try DoH first, then system DNS (rejecting hijacked answers).
    let doh = crate::doh::DohResolver::new();
    if matches!(
        probe_worker_health(worker_host, None, Some(&doh), timeout_s).await,
        WorkerHealth::Alive
    ) {
        return WorkerHealth::Alive;
    }
    // Fallback: DNS-free sweep across a sample of Cloudflare IPs.
    if cidrs.is_empty() {
        return WorkerHealth::Unreachable;
    }
    let sample = probe_worker_via_cf_sample(worker_host, cidrs, 24, timeout_s).await;
    if sample.alive {
        WorkerHealth::Alive
    } else if sample.suspended > 0 {
        WorkerHealth::Suspended { code: 9109 }
    } else if sample.path_mismatch > 0 {
        WorkerHealth::PathMismatch
    } else {
        WorkerHealth::Unreachable
    }
}

/// Check whether an endpoint is still alive using the real-client WS gate:
/// TLS + RFC 6455 upgrade across the alt-port set, accepting only a 101 with
/// actual bytes. This is the monitor's "is it still tunnelling?" test.
async fn endpoint_live(ip: &str, sni: &str, path: &str, timeout_ms: u64) -> bool {
    let probes = crate::health::probe_all_alt_ports(ip, sni, path, timeout_ms).await;
    probes
        .iter()
        .any(|p| p.status == Some(101) && p.worker_bytes >= crate::health::MIN_WORKER_BYTES)
}

// ---------------------------------------------------------------------------
// SenpaiProvider: thin fallback wrapper around the existing binary
// ---------------------------------------------------------------------------

/// Thin wrapper over the existing SenPaiScanner CLI (fallback / debug mode).
#[derive(Default)]
pub struct SenpaiProvider {
    /// Show raw scanner output in the result (debug).
    pub verbose: bool,
}

impl EndpointProvider for SenpaiProvider {
    fn discover<'a>(
        &'a self,
        vless: &'a VlessProfile,
        params: &'a DiscoveryParams,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<CleanEndpoint>, CFError>> + Send + 'a>> {
        Box::pin(async move {
            // Keep a copy of the vless share link to hand to the scanner.
            let link = vless.share_link();
            let scan_params = ScanParams {
                count: params.sample,
                workers: params.workers as u32,
                timeout_s: params.timeout_s,
                top: params.top_n as u32,
                ..Default::default()
            };
            let res: ScanResult = run_scan(&link, &scan_params, params.top_n as u32).await?;
            let mut out = Vec::new();
            for ep in res.endpoints {
                let (ip, port) = split_endpoint(&ep);
                out.push(CleanEndpoint {
                    ip,
                    port,
                    sni: vless.sni.clone().unwrap_or_else(|| vless.address.clone()),
                    score: 100.0,
                    tcp_ms: 0.0,
                    connect_ms: 0.0,
                    download_kbps: 0.0,
                    verified: true,
                    alive: true,
                    last_checked: Some(store::now_iso()),
                    ts: store::now_iso(),
                });
            }
            Ok(out)
        })
    }
}

fn split_endpoint(ep: &str) -> (String, u16) {
    match ep.rsplit_once(':') {
        Some((ip, p)) => (ip.to_string(), p.parse().unwrap_or(443)),
        None => (ep.to_string(), 443),
    }
}

// ---------------------------------------------------------------------------
// Ledger persistence (machine-local)
// ---------------------------------------------------------------------------

/// Path to the autopilot ledger for a profile.
pub fn ledger_path(profile_id: &str) -> PathBuf {
    store::profiles::profile_dir(profile_id)
        .join("autopilot")
        .join("endpoints.json")
}

/// Read the current ledger.
pub fn read_ledger(profile_id: &str) -> Vec<CleanEndpoint> {
    store::read_or_default::<Vec<CleanEndpoint>>(&ledger_path(profile_id))
}

/// Persist the ledger atomically.
pub fn write_ledger(profile_id: &str, endpoints: &[CleanEndpoint]) -> Result<(), CFError> {
    store::atomic_write(
        &ledger_path(profile_id),
        &serde_json::to_vec_pretty(endpoints).map_err(|e| {
            CFError::new(
                "Storage error",
                format!("Cannot serialize ledger: {e}"),
                "Internal error.",
            )
        })?,
    )
}

/// Directory where active (fronted) configs are written.
pub fn active_configs_dir(profile_id: &str) -> PathBuf {
    store::profiles::profile_dir(profile_id)
        .join("configs")
        .join("active")
}

/// Write an active vless share link + all common client formats for an
/// endpoint that fronts a given worker profile.
pub fn write_active_configs(
    profile_id: &str,
    vless: &VlessProfile,
    ep: &CleanEndpoint,
) -> Result<(), CFError> {
    let dir = active_configs_dir(profile_id);
    std::fs::create_dir_all(&dir).map_err(|e| {
        CFError::new(
            "Storage error",
            format!("Cannot create {}: {e}", dir.display()),
            "Check permissions.",
        )
    })?;

    let mut fronted = vless.clone();
    fronted.address = ep.ip.clone();
    fronted.port = ep.port;

    let link = fronted.share_link();
    store::atomic_write(&dir.join("link.txt"), link.as_bytes())?;

    // v2rayN / xray JSON
    if let Ok(xray) = fronted.xray_client_json() {
        store::atomic_write(&dir.join("xray.json"), xray.as_bytes())?;
    }
    // sing-box JSON
    if let Ok(sb) = crate::export::sing_box_json(&fronted) {
        store::atomic_write(&dir.join("sing-box.json"), sb.as_bytes())?;
    }
    // Clash entry
    store::atomic_write(
        &dir.join("clash.yaml"),
        crate::export::clash_entry(&fronted).as_bytes(),
    )?;

    Ok(())
}

/// Find the profile's base worker (non-clean-IP) vless link.
pub fn base_vless(profile_id: &str) -> Result<VlessProfile, CFError> {
    let p = store::profiles::load_profile(profile_id);
    let rec = p
        .history
        .iter()
        .find(|r| !r.clean_ip)
        .or_else(|| p.history.first());
    match rec {
        Some(rec) if !rec.link.is_empty() => VlessProfile::parse(&rec.link),
        _ => Err(CFError::new(
            "No config",
            "No vless config to front — deploy a worker first.",
            "Deploy a worker, then enable autopilot.",
        )),
    }
}

// ---------------------------------------------------------------------------
// Autopilot engine
// ---------------------------------------------------------------------------

/// A one-line, low-volume status summary of a cycle (the only per-cycle line
/// the UI shows).
#[derive(Debug, Clone)]
pub struct CycleSummary {
    pub cycle: u64,
    pub alive: usize,
    pub replaced: usize,
    pub note: String,
}

/// A handle to the running autopilot engine. Controls stop via a watch
/// channel; progress is streamed through `tx`.
pub struct AutopilotEngine {
    profile_id: String,
    params: DiscoveryParams,
    interval: Duration,
    provider: Box<dyn EndpointProvider>,
}

impl AutopilotEngine {
    pub fn new(profile_id: impl Into<String>, params: DiscoveryParams, interval: Duration) -> Self {
        let profile_id = profile_id.into();
        Self {
            profile_id: profile_id.clone(),
            params,
            interval,
            provider: Box::new(NativeCfProvider {
                profile_id: profile_id.clone(),
            }),
        }
    }

    /// Test-only constructor: inject a scripted provider so cycles can be
    /// driven without a live network / worker.
    #[cfg(test)]
    fn with_provider(
        profile_id: impl Into<String>,
        params: DiscoveryParams,
        interval: Duration,
        provider: Box<dyn EndpointProvider>,
    ) -> Self {
        Self {
            profile_id: profile_id.into(),
            params,
            interval,
            provider,
        }
    }

    /// A discovery-param copy seeded from the ledger's last-known-good
    /// endpoints. `seed_ips` become the neighbourhood anchor points for the
    /// scanner (feature #2), so it doesn't start from zero each cycle.
    fn params_with_seeds(&self) -> DiscoveryParams {
        let mut p = self.params.clone();
        // Auto-pilot ledger's last-known-good endpoints first.
        let mut seeds: Vec<String> = crate::cf::ips::load_seed_endpoints(&self.profile_id, 6)
            .iter()
            .filter_map(|s| s.split(':').next().map(|ip| ip.to_string()))
            .collect();
        // Then the user's manually imported "known-good IPs" — these are the
        // highest-value seeds (NetworkBlocked fast path). Bare IPs only.
        for s in crate::cf::ips::load_manual_seeds(&self.profile_id) {
            if let Some(ip) = s.split(':').next() {
                if !seeds.iter().any(|e| e == ip) {
                    seeds.push(ip.to_string());
                }
            }
        }
        p.seed_ips = seeds;
        p
    }

    /// Run one full discovery+validation cycle, persist the ledger, and
    /// write active configs. Returns the validated endpoints and a summary.
    pub async fn run_cycle(&self) -> Result<(Vec<CleanEndpoint>, CycleSummary), CFError> {
        self.run_cycle_with_params(&self.params_with_seeds()).await
    }

    /// Like [`run_cycle`], but with an explicit discovery parameter set (used
    /// by the rescue chain to inject seed sources / skip the step-0 gate).
    /// Writes a health beacon on BOTH success and error paths.
    async fn run_cycle_with_params(
        &self,
        params: &DiscoveryParams,
    ) -> Result<(Vec<CleanEndpoint>, CycleSummary), CFError> {
        let cycle_ts = crate::store::now_ts() as i64;
        let started = std::time::Instant::now();
        let result = self.run_cycle_with_params_inner(params).await;
        let duration_ms = started.elapsed().as_millis() as u64;
        let last_error = result.as_ref().err().map(|e| e.brief());
        let active_alive = result.as_ref().ok().map(|(found, _)| !found.is_empty());
        let beacon = compose_beacon(
            &self.profile_id,
            crate::health_beacon::CycleKind::Discovery,
            cycle_ts,
            duration_ms,
            None,
            active_alive,
            last_error,
        );
        let _ = crate::health_beacon::write_beacon(&self.profile_id, &beacon);
        result
    }

    async fn run_cycle_with_params_inner(
        &self,
        params: &DiscoveryParams,
    ) -> Result<(Vec<CleanEndpoint>, CycleSummary), CFError> {
        // Self-heal the user-facing bundle against the ledger first (never
        // fails the cycle: discovery is still the goal).
        let _ = crate::cleanip::reconcile_bundle_if_drifted(&self.profile_id);
        // Self-learning phase-2 SNI strategy (v2 rolling-window): resolve the
        // persisted strategy state and pin its current strategy for this cycle
        // so the phase-2 probe is exclusive about which SNI it tries first.
        let mut strategy = resolve_strategy_v2(&self.profile_id);
        let mut used_params = params.clone();
        used_params.preferred_strategy = Some(strategy.current);

        let vless = base_vless(&self.profile_id)?;
        let found = self.provider.discover(&vless, &used_params).await?;

        // Learn from this discovery cycle: any verified (accepted-101)
        // endpoint means the strategy won. Record the outcome in the rolling
        // window and rotate if the window / forced-exploration says so. This is
        // the self-healing loop that makes the app pick the working SNI itself.
        let won = !found.is_empty();
        let _ = commit_strategy_v2(&self.profile_id, &mut strategy, won);

        let mut ledger = read_ledger(&self.profile_id);
        let mut replaced = 0;

        if !found.is_empty() {
            // Replace any currently-alive-but-not-in-found set? Simplest correct
            // behavior: keep the old ones that are still alive, add new ones.
            // We trust the monitor to mark dead ones.
            let mut merged = ledger.clone();
            for ep in &found {
                if !merged.iter().any(|e| e.ip == ep.ip) {
                    merged.push(ep.clone());
                } else if let Some(slot) = merged.iter_mut().find(|e| e.ip == ep.ip) {
                    *slot = ep.clone();
                }
            }
            // Trim to a sane bound (no unbounded growth).
            merged.sort_by(|a, b| {
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            merged.truncate(64);
            replaced = merged.len().saturating_sub(ledger.len());
            ledger = merged;

            // Write active configs using the top validated endpoint.
            if let Some(best) = found.iter().find(|e| e.verified) {
                write_active_configs(&self.profile_id, &vless, best)?;
            }
        }

        write_ledger(&self.profile_id, &ledger)?;

        // Refresh the user-facing bundle (~/khvarenah-configs/<profile>/).
        let live: Vec<CleanEndpoint> = ledger
            .iter()
            .filter(|e| e.verified && e.alive)
            .cloned()
            .collect();
        let _ = crate::cleanip::write_user_bundle(&self.profile_id, &vless, &live);

        let alive = ledger.iter().filter(|e| e.alive).count();
        let summary = CycleSummary {
            cycle: 0,
            alive,
            replaced,
            note: format!(
                "found {} clean endpoint(s) · {} in ledger",
                found.len(),
                ledger.len()
            ),
        };
        Ok((found, summary))
    }

    /// Run the autopilot forever. The first cycle is a full discovery; after
    /// that, the monitor loop runs on `self.interval`. Progress is streamed
    /// to `tx` (a `tokio::sync::mpsc`-style closure). Stop by cancelling the
    /// task or dropping the handle.
    pub async fn run_forever<F>(self, mut report: F) -> Result<(), CFError>
    where
        F: FnMut(CycleSummary),
    {
        // First cycle: full discovery + validation.
        match self.run_cycle().await {
            Ok((_, summary)) => report(summary),
            Err(e) => {
                report(CycleSummary {
                    cycle: 1,
                    alive: 0,
                    replaced: 0,
                    note: format!("autopilot start failed: {}", e.brief()),
                });
            }
        }

        // Then monitor on an interval.
        let mut tick = tokio::time::interval(self.interval);
        let mut cycle = 1u64;
        loop {
            tick.tick().await;
            cycle += 1;
            let mut summary = match self.monitor_cycle().await {
                Ok(s) => s,
                Err(e) => CycleSummary {
                    cycle,
                    alive: 0,
                    replaced: 0,
                    note: format!("monitor error: {}", e.brief()),
                },
            };
            summary.cycle = cycle;
            report(summary);
        }
    }

    /// The monitor loop (DeepSeek two-tier plan). Tier 1 is a cheap **light**
    /// check: the real-client WS-gate on every ledger endpoint. Two
    /// consecutive light-failures of the active endpoint *escalate* to Tier 2,
    /// a **deep** full discovery + E2E pass (also run on a 15-min schedule).
    /// A deep-check failure is what actually triggers a swap. Best-score-wins
    /// keeps the highest verified+alive endpoint as the active config.
    /// Returns a per-cycle summary. Writes a health beacon on BOTH paths.
    pub async fn monitor_cycle(&self) -> Result<CycleSummary, CFError> {
        let cycle_ts = crate::store::now_ts() as i64;
        let started = std::time::Instant::now();
        let result = self.monitor_cycle_inner().await;
        let duration_ms = started.elapsed().as_millis() as u64;
        let last_error = result.as_ref().err().map(|e| e.brief());
        let active_alive = result.as_ref().ok().map(|s| s.alive > 0);
        let beacon = compose_beacon(
            &self.profile_id,
            crate::health_beacon::CycleKind::Monitor,
            cycle_ts,
            duration_ms,
            None,
            active_alive,
            last_error,
        );
        let _ = crate::health_beacon::write_beacon(&self.profile_id, &beacon);
        result
    }

    async fn monitor_cycle_inner(&self) -> Result<CycleSummary, CFError> {
        // Self-heal the user-facing bundle against the ledger before checking
        // the network (never fails the cycle: discovery is still the goal).
        let _ = crate::cleanip::reconcile_bundle_if_drifted(&self.profile_id);
        let vless = base_vless(&self.profile_id)?;
        let path = crate::health::derive_ws_target(&vless).path;
        let timeout_ms = (self.params.timeout_s as u64) * 1000;

        let mut ledger = read_ledger(&self.profile_id);
        let mut state = crate::store::profiles::protection_state(&self.profile_id);
        let now = store::now_ts() as i64;
        let deep_interval: i64 = 900; // deep E2E check every 15 min

        // ── Tier 1: LIGHT check (WS-gate across alt ports) ──
        let mut alive = 0usize;
        for ep in ledger.iter_mut() {
            let ok = endpoint_live(&ep.ip, &ep.sni, &path, timeout_ms).await;
            ep.alive = ok;
            if ok {
                ep.last_checked = Some(store::now_iso());
                alive += 1;
            }
        }

        // The active endpoint is the best verified one (highest score).
        ledger.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let active_alive = ledger
            .iter()
            .find(|e| e.verified)
            .map(|e| e.alive)
            .unwrap_or(false);

        // Streak: 2 consecutive light failures of the active escalate to deep.
        if active_alive {
            state.failure_streak = 0;
        } else {
            state.failure_streak = state.failure_streak.saturating_add(1);
        }
        let deep_due = (now - state.last_deep_check) >= deep_interval;
        let escalated = state.failure_streak >= 2 && !active_alive;
        let do_deep = deep_due || escalated;

        let mut replaced = 0;
        let mut did_rediscover = false;

        if do_deep {
            // ── Tier 2: DEEP check — full discovery through the pipeline ──
            state.last_deep_check = now;
            let params = self.params_with_seeds();
            match self.provider.discover(&vless, &params).await {
                Ok(fresh) => {
                    for ep in fresh {
                        if let Some(slot) = ledger.iter_mut().find(|l| l.ip == ep.ip) {
                            *slot = ep.clone();
                        } else {
                            ledger.push(ep.clone());
                            replaced += 1;
                        }
                    }
                    did_rediscover = true;
                    // A successful deep pass resets the streak.
                    if ledger.iter().any(|e| e.alive) {
                        state.failure_streak = 0;
                    }
                }
                Err(_) => {
                    // Deep check failed; keep the streak so escalation retries.
                }
            }
        } else if alive == 0 {
            // Nothing alive but no escalation due yet — still chase fresh ones
            // so a dead ledger doesn't sit empty.
            let params = self.params_with_seeds();
            if let Ok(fresh) = self.provider.discover(&vless, &params).await {
                for ep in fresh {
                    if let Some(slot) = ledger.iter_mut().find(|l| l.ip == ep.ip) {
                        *slot = ep.clone();
                    } else {
                        ledger.push(ep.clone());
                        replaced += 1;
                    }
                }
                did_rediscover = true;
            }
        }

        // Best-score wins: pick the highest verified+alive endpoint as active.
        ledger.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let best_ip = ledger
            .iter()
            .find(|e| e.verified && e.alive)
            .map(|e| e.ip.clone());
        if let Some(best) = best_ip.as_ref() {
            let best_ep = ledger.iter().find(|e| e.ip == *best).unwrap();
            write_active_configs(&self.profile_id, &vless, best_ep)?;
        }

        // Trim ledger, persist state, refresh the user bundle.
        ledger.truncate(64);
        write_ledger(&self.profile_id, &ledger)?;
        crate::store::profiles::save_protection_state(&self.profile_id, &state)?;

        let live: Vec<CleanEndpoint> = ledger
            .iter()
            .filter(|e| e.verified && e.alive)
            .cloned()
            .collect();

        // Auto-rescue (Feature C): if nothing is alive, probe the worker and
        // run the rescue chain so the app *fights* the failure instead of just
        // reporting it. Only recoverable failures (NotFound/Suspended/
        // Unreachable) enter the chain — the E2E-while-tunneled false negative
        // (worker Alive) is deliberately excluded.
        let mut rescued = false;
        if live.is_empty() {
            rescued = self.rescue_if_needed().await;
        }

        let _ = crate::cleanip::write_user_bundle(&self.profile_id, &vless, &live);

        Ok(CycleSummary {
            cycle: 0,
            alive: live.len(),
            replaced,
            note: format!(
                "monitor: {alive} alive · {} clean · best {} · deep={did_rediscover} streak={}{}",
                live.len(),
                best_ip.as_deref().unwrap_or("-"),
                state.failure_streak,
                if rescued { " · auto-rescued" } else { "" }
            ),
        })
    }

    /// If every endpoint is dead, probe the worker health and, when it is a
    /// recoverable failure, run the rescue chain. Returns true if a rescue
    /// attempt ran (recovered or not). This is the automated call site that
    /// makes the monitor "fight failure" without any manual step.
    async fn rescue_if_needed(&self) -> bool {
        let vless = match base_vless(&self.profile_id) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let ws = crate::health::derive_ws_target(&vless);
        // Probe health via the worker's SNI. Passing an empty CIDR slice means
        // the gate uses its embedded/default range fallback (we only care about
        // the worker-health verdict here, not scanning).
        let cidrs: &[crate::cf::ips::Cidr] = &[];
        let health =
            crate::autopilot::step0_gate(&ws.sni, self.params.timeout_s.max(3) as u64, cidrs).await;
        if !should_rescue(&health) {
            return false;
        }
        let peer = RealRescuePeer {
            engine: self,
            profile_id: &self.profile_id,
        };
        match rescue_from_failure(&self.profile_id, &peer, health).await {
            Ok(chain) => {
                if chain.gave_up {
                    // Surface the plain-language diagnosis + recommended action.
                    let cause = match chain.initial_failure {
                        WorkerHealth::Suspended { .. } | WorkerHealth::NotFound => {
                            crate::diagnose::PlainCause::WorkerDead
                        }
                        WorkerHealth::Unreachable => crate::diagnose::PlainCause::NetworkBlocked,
                        _ => crate::diagnose::PlainCause::WorkerDead,
                    };
                    let msg = crate::diagnose::plain_message(cause, crate::diagnose::Locale::En);
                    eprintln!("[khvarenah] rescue gave up: {msg}");
                }
                true
            }
            Err(_) => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Auto-rescue chain (Feature C — "fights failure", not just "reports it")
// ---------------------------------------------------------------------------

/// The discrete recovery actions the rescue chain can attempt, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RescueAction {
    /// Cheapest: reuse a verified ledger endpoint that isn't the active one.
    TryFallbackPool,
    /// Full discovery seeded from the ledger's last-known-good endpoints.
    ReseedFromLedger,
    /// Full discovery seeded only from the user's manual seeds.
    ReseedFromManualSeeds,
    /// Nuclear: re-deploy the worker (rate-limited to 1/hour).
    RedeployWorker,
    /// Every step failed; surface the plain-language diagnosis.
    GiveUp,
}

/// Outcome of one rescue attempt.
#[derive(Debug, Clone)]
pub enum RescueOutcome {
    /// The step recovered a working endpoint.
    Success { endpoint: String, rtt_ms: u32 },
    /// The step ran but did not recover anything.
    Failed { reason: String },
    /// The step was not attempted (e.g. no manual seeds, rate-limited).
    Skipped { reason: String },
}

/// One step in a rescue chain.
#[derive(Debug, Clone)]
pub struct RescueAttempt {
    pub action: RescueAction,
    pub attempted_at: i64,
    pub outcome: RescueOutcome,
}

/// The full outcome of a rescue chain.
#[derive(Debug, Clone)]
pub struct RescueChain {
    pub attempts: Vec<RescueAttempt>,
    /// The cycle summary from whichever step recovered (if any).
    pub final_state: Option<CycleSummary>,
    pub gave_up: bool,
    pub initial_failure: WorkerHealth,
    pub completed_at: i64,
}

/// Rescue only fires on failures that a rescue can actually fix. The
/// E2E-while-tunneled false negative (`E2eIpUnchanged`) is deliberately NOT
/// rescuable — the direct-IP echo equals tunnel egress for an already-tunneled
/// user, so rescuing would spin an infinite scan loop.
pub fn should_rescue(failure: &WorkerHealth) -> bool {
    matches!(
        failure,
        WorkerHealth::NotFound | WorkerHealth::Suspended { .. } | WorkerHealth::Unreachable
    )
}

/// Plan the ordered rescue actions for a given profile state. Pure and fully
/// unit-testable. Order is strict: fallback pool → ledger reseed → manual seeds
/// → redeploy worker. Each step is only included if its precondition is met
/// (e.g. skip fallback when the ledger is empty; skip redeploy when rate-limited
/// or no token). Returns the actions to try in order.
pub fn plan_rescue(
    ledger_empty: bool,
    manual_seeds_exist: bool,
    has_token: bool,
    redeploy_rate_limited: bool,
) -> Vec<RescueAction> {
    let mut plan = Vec::new();
    if !ledger_empty {
        plan.push(RescueAction::TryFallbackPool);
        plan.push(RescueAction::ReseedFromLedger);
    }
    if manual_seeds_exist {
        plan.push(RescueAction::ReseedFromManualSeeds);
    }
    if has_token && !redeploy_rate_limited {
        plan.push(RescueAction::RedeployWorker);
    }
    plan
}

/// The future returned by a rescue `run_cycle` call.
type CycleFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(Vec<CleanEndpoint>, CycleSummary), CFError>> + Send + 'a>>;

/// Peer abstraction for the rescue chain's side-effecting operations. Splitting
/// these out makes the four-step sequencing fully unit-testable with no live
/// worker, CF token, or network (mirrors the `SingboxSpawner` pattern).
pub trait RescuePeer: Send + Sync {
    /// Probe whether one ledger endpoint is alive (fallback pool pick).
    fn endpoint_alive(
        &self,
        ip: &str,
        sni: &str,
        path: &str,
        timeout_ms: u64,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + '_>>;

    /// Run one discovery cycle with the given params (reseed steps).
    fn run_cycle(&self, params: &DiscoveryParams) -> CycleFuture<'_>;

    /// Redeploy the worker. Returns Ok(()) on success.
    fn redeploy_worker(&self) -> Pin<Box<dyn Future<Output = Result<(), CFError>> + Send + '_>>;
}

/// The production peer, backed by a real engine + CF client.
pub struct RealRescuePeer<'a> {
    pub engine: &'a AutopilotEngine,
    pub profile_id: &'a str,
}

impl<'a> RescuePeer for RealRescuePeer<'a> {
    fn endpoint_alive(
        &self,
        ip: &str,
        sni: &str,
        path: &str,
        timeout_ms: u64,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        let ip = ip.to_string();
        let sni = sni.to_string();
        let path = path.to_string();
        Box::pin(async move { endpoint_live(&ip, &sni, &path, timeout_ms).await })
    }

    fn run_cycle(
        &self,
        params: &DiscoveryParams,
    ) -> Pin<
        Box<dyn Future<Output = Result<(Vec<CleanEndpoint>, CycleSummary), CFError>> + Send + '_>,
    > {
        let params = params.clone();
        let engine = self.engine;
        Box::pin(async move { engine.run_cycle_with_params(&params).await })
    }

    fn redeploy_worker(&self) -> Pin<Box<dyn Future<Output = Result<(), CFError>> + Send + '_>> {
        let profile_id = self.profile_id.to_string();
        Box::pin(async move { redeploy_worker_core(&profile_id).await })
    }
}

/// Redeploy this profile's worker using the active token + built-in preset
/// worker JS. Rate-limiting is handled by the caller (via `last_redeploy_ts`).
async fn redeploy_worker_core(profile_id: &str) -> Result<(), CFError> {
    let label = match crate::store::profiles::get_active_token(profile_id)? {
        Some(l) => l,
        None => {
            return Err(CFError::new(
                "Redeploy",
                "No active token for this profile.",
                "Set an active token before enabling auto-redeploy.",
            ))
        }
    };
    let token = match crate::store::profiles::get_token(profile_id, &label)? {
        Some(t) => t,
        None => {
            return Err(CFError::new(
                "Redeploy",
                format!("Token '{label}' not found."),
                "Re-add the token.",
            ))
        }
    };

    let p = crate::store::profiles::load_profile(profile_id);
    let client = crate::cf::Client::new(&token);

    // Account id: active_account, else first accessible.
    let acc_id = if !p.config.active_account.is_empty() {
        p.config.active_account.clone()
    } else {
        let accs = client.list_accounts().await?;
        accs.first().map(|a| a.id.clone()).ok_or_else(|| {
            CFError::new(
                "No account",
                "No CF account accessible.",
                "Check token permissions.",
            )
        })?
    };

    let worker_name = crate::worker::worker_name_from_account(Some(&p.config.active_account));
    let js = crate::presets::fallback_worker_js().into_bytes();
    client
        .deploy_script(&acc_id, &worker_name, js, "2026-07-01", 2)
        .await?;
    Ok(())
}

/// Run the full four-step rescue chain. Returns the detailed chain; the caller
/// decides what to surface (a `final_state` means we recovered).
pub async fn rescue_from_failure(
    profile_id: &str,
    peer: &dyn RescuePeer,
    initial_failure: WorkerHealth,
) -> Result<RescueChain, CFError> {
    let now = crate::store::now_ts() as i64;
    let mut chain = RescueChain {
        attempts: Vec::new(),
        final_state: None,
        gave_up: false,
        initial_failure: initial_failure.clone(),
        completed_at: now,
    };

    // Loop guard: only recoverable failures enter the chain. In particular the
    // E2E-while-tunneled false negative (worker Alive + IpUnchanged) must never
    // rescue, or every scan for an already-tunneled user would spin forever.
    if !should_rescue(&initial_failure) {
        return Ok(chain);
    }

    // Throttle: at most one rescue chain per 5 minutes.
    let cfg = crate::store::profiles::load_profile(profile_id).config;
    if now - cfg.last_rescue_attempt_ts < 300 {
        chain.gave_up = true;
        chain.attempts.push(RescueAttempt {
            action: RescueAction::GiveUp,
            attempted_at: now,
            outcome: RescueOutcome::Skipped {
                reason: "rescues throttled (5 min window)".into(),
            },
        });
        return Ok(chain);
    }

    // Step 1 — TryFallbackPool (cheapest: no re-scan).
    let fallback_ep = pick_fallback_endpoint(profile_id, peer).await;
    if let Some((ep, rtt)) = fallback_ep {
        let ep_key = ep.clone();
        chain.attempts.push(RescueAttempt {
            action: RescueAction::TryFallbackPool,
            attempted_at: now,
            outcome: RescueOutcome::Success {
                endpoint: ep,
                rtt_ms: rtt,
            },
        });
        // Fallback is already in the ledger; write it as active.
        if let Some(best) = ledger_endpoint(profile_id, &ep_key) {
            let vless = base_vless(profile_id)?;
            write_active_configs(profile_id, &vless, &best)?;
        }
        let summary = CycleSummary {
            cycle: 0,
            alive: 1,
            replaced: 0,
            note: format!("rescued via fallback pool → {ep_key}"),
        };
        chain.final_state = Some(summary);
        crate::store::profiles::save_rescue_meta(
            profile_id,
            now,
            cfg.last_redeploy_ts,
            Some("recovered".into()),
        )?;
        return Ok(chain);
    }
    chain.attempts.push(RescueAttempt {
        action: RescueAction::TryFallbackPool,
        attempted_at: now,
        outcome: RescueOutcome::Failed {
            reason: "no live fallback".into(),
        },
    });

    // Step 2 — ReseedFromLedger (skip step-0 gate: we already know it failed).
    let mut params = peer_params(&cfg);
    params.skip_step0 = true;
    match peer.run_cycle(&params).await {
        Ok((found, summary)) if !found.is_empty() => {
            chain.attempts.push(RescueAttempt {
                action: RescueAction::ReseedFromLedger,
                attempted_at: now,
                outcome: RescueOutcome::Success {
                    endpoint: found[0].ip.clone(),
                    rtt_ms: found[0].connect_ms.max(0.0) as u32,
                },
            });
            chain.final_state = Some(summary);
            crate::store::profiles::save_rescue_meta(
                profile_id,
                now,
                cfg.last_redeploy_ts,
                Some("recovered".into()),
            )?;
            return Ok(chain);
        }
        Ok((_, summary)) => {
            chain.attempts.push(RescueAttempt {
                action: RescueAction::ReseedFromLedger,
                attempted_at: now,
                outcome: RescueOutcome::Failed {
                    reason: format!("reseed found nothing ({})", summary.note),
                },
            });
        }
        Err(e) => {
            chain.attempts.push(RescueAttempt {
                action: RescueAction::ReseedFromLedger,
                attempted_at: now,
                outcome: RescueOutcome::Failed {
                    reason: format!("reseed error: {}", e.brief()),
                },
            });
        }
    }

    // Step 3 — ReseedFromManualSeeds.
    let manual = crate::cf::ips::load_manual_seeds(profile_id);
    if manual.is_empty() {
        chain.attempts.push(RescueAttempt {
            action: RescueAction::ReseedFromManualSeeds,
            attempted_at: now,
            outcome: RescueOutcome::Skipped {
                reason: "no manual seeds imported".into(),
            },
        });
    } else {
        let mut mparams = peer_params(&cfg);
        mparams.skip_step0 = true;
        mparams.seed_ips = manual;
        match peer.run_cycle(&mparams).await {
            Ok((found, summary)) if !found.is_empty() => {
                chain.attempts.push(RescueAttempt {
                    action: RescueAction::ReseedFromManualSeeds,
                    attempted_at: now,
                    outcome: RescueOutcome::Success {
                        endpoint: found[0].ip.clone(),
                        rtt_ms: found[0].connect_ms.max(0.0) as u32,
                    },
                });
                chain.final_state = Some(summary);
                crate::store::profiles::save_rescue_meta(
                    profile_id,
                    now,
                    cfg.last_redeploy_ts,
                    Some("recovered".into()),
                )?;
                return Ok(chain);
            }
            Ok((_, summary)) => {
                chain.attempts.push(RescueAttempt {
                    action: RescueAction::ReseedFromManualSeeds,
                    attempted_at: now,
                    outcome: RescueOutcome::Failed {
                        reason: format!("manual reseed found nothing ({})", summary.note),
                    },
                });
            }
            Err(e) => {
                chain.attempts.push(RescueAttempt {
                    action: RescueAction::ReseedFromManualSeeds,
                    attempted_at: now,
                    outcome: RescueOutcome::Failed {
                        reason: format!("manual reseed error: {}", e.brief()),
                    },
                });
            }
        }
    }

    // Step 4 — RedeployWorker (nuclear; rate-limited to 1/hour).
    let redeploy_allowed = cfg.last_redeploy_ts == 0 || (now - cfg.last_redeploy_ts) >= 3600;
    if !redeploy_allowed {
        chain.attempts.push(RescueAttempt {
            action: RescueAction::RedeployWorker,
            attempted_at: now,
            outcome: RescueOutcome::Skipped {
                reason: "redeploy rate-limited (1/hour)".into(),
            },
        });
    } else {
        match peer.redeploy_worker().await {
            Ok(()) => {
                // After redeploy, run one fresh full cycle (gate re-enabled).
                let fresh = peer_params(&cfg);
                match peer.run_cycle(&fresh).await {
                    Ok((found, summary)) if !found.is_empty() => {
                        chain.attempts.push(RescueAttempt {
                            action: RescueAction::RedeployWorker,
                            attempted_at: now,
                            outcome: RescueOutcome::Success {
                                endpoint: found[0].ip.clone(),
                                rtt_ms: found[0].connect_ms.max(0.0) as u32,
                            },
                        });
                        chain.final_state = Some(summary);
                        crate::store::profiles::save_rescue_meta(
                            profile_id,
                            now,
                            now,
                            Some("recovered".into()),
                        )?;
                        return Ok(chain);
                    }
                    Ok((_, summary)) => {
                        chain.attempts.push(RescueAttempt {
                            action: RescueAction::RedeployWorker,
                            attempted_at: now,
                            outcome: RescueOutcome::Failed {
                                reason: format!(
                                    "post-redeploy cycle found nothing ({})",
                                    summary.note
                                ),
                            },
                        });
                    }
                    Err(e) => {
                        chain.attempts.push(RescueAttempt {
                            action: RescueAction::RedeployWorker,
                            attempted_at: now,
                            outcome: RescueOutcome::Failed {
                                reason: format!("post-redeploy cycle error: {}", e.brief()),
                            },
                        });
                    }
                }
            }
            Err(e) => {
                chain.attempts.push(RescueAttempt {
                    action: RescueAction::RedeployWorker,
                    attempted_at: now,
                    outcome: RescueOutcome::Failed {
                        reason: format!("redeploy error: {}", e.brief()),
                    },
                });
            }
        }
        // Record the redeploy attempt timestamp regardless of outcome.
        crate::store::profiles::save_rescue_meta(profile_id, now, now, Some("gave_up".into()))?;
    }

    // Step 5 — GiveUp.
    chain.gave_up = true;
    chain.attempts.push(RescueAttempt {
        action: RescueAction::GiveUp,
        attempted_at: now,
        outcome: RescueOutcome::Failed {
            reason: "all rescue steps exhausted".into(),
        },
    });
    crate::store::profiles::save_rescue_meta(
        profile_id,
        now,
        cfg.last_redeploy_ts,
        Some("gave_up".into()),
    )?;
    Ok(chain)
}

/// Build discovery params from the profile config (seeds come from the ledger).
fn peer_params(cfg: &crate::store::profiles::ProfileConfig) -> DiscoveryParams {
    DiscoveryParams {
        timeout_s: cfg.scan_timeout.max(3),
        sample: cfg.scan_count.max(500),
        workers: cfg.scan_workers.max(8) as usize,
        top_n: 3,
        ..Default::default()
    }
}

/// Pick the best verified-but-not-active endpoint that is currently alive.
/// Returns Some((endpoint "ip:port", rtt_ms)) from the fallback pool. This
/// mirrors the "fallback pool" idea in clean-configs.txt: ranked alternates
/// from the ledger.
async fn pick_fallback_endpoint(profile_id: &str, peer: &dyn RescuePeer) -> Option<(String, u32)> {
    let ledger = read_ledger(profile_id);
    let vless = base_vless(profile_id).ok()?;
    let ws = crate::health::derive_ws_target(&vless);
    let timeout_ms = 5000;

    // Rank by score; skip the currently-active best (we are actively failing
    // on it). Find the first verified endpoint that is alive.
    let mut ranked: Vec<&CleanEndpoint> = ledger.iter().filter(|e| e.verified).collect();
    ranked.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // The active one is the highest-scoring verified endpoint; skip it.
    let active_ip = ranked.first().map(|e| e.ip.clone());
    for ep in ranked {
        if Some(&ep.ip) == active_ip.as_ref() {
            continue;
        }
        if peer
            .endpoint_alive(&ep.ip, &ep.sni, &ws.path, timeout_ms)
            .await
        {
            let rtt = ep.connect_ms.max(0.0) as u32;
            return Some((format!("{}:{}", ep.ip, ep.port), rtt));
        }
    }
    None
}

/// Look up a full ledger endpoint by its `ip:port` string.
fn ledger_endpoint(profile_id: &str, key: &str) -> Option<CleanEndpoint> {
    let ledger = read_ledger(profile_id);
    ledger
        .into_iter()
        .find(|e| format!("{}:{}", e.ip, e.port).eq_ignore_ascii_case(key))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn sample_vless() -> VlessProfile {
        VlessProfile {
            uuid: "12345678-1234-1234-1234-123456789abc".into(),
            address: "user.workers.dev".into(),
            port: 443,
            security: "tls".into(),
            path: "/".into(),
            transport: "ws".into(),
            name: "test".into(),
            ..Default::default()
        }
    }

    #[test]
    fn split_endpoint_handles_port() {
        assert_eq!(split_endpoint("1.2.3.4:443"), ("1.2.3.4".into(), 443));
        assert_eq!(split_endpoint("1.2.3.4"), ("1.2.3.4".into(), 443));
    }

    #[test]
    fn ledger_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(dir.path().join(".khvarenah"));
        let id = "default";
        let eps = vec![CleanEndpoint {
            ip: "1.2.3.4".into(),
            port: 443,
            sni: "user.workers.dev".into(),
            score: 50.0,
            tcp_ms: 10.0,
            connect_ms: 20.0,
            download_kbps: 500.0,
            verified: true,
            alive: true,
            last_checked: None,
            ts: String::new(),
        }];
        write_ledger(id, &eps).unwrap();
        let got = read_ledger(id);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].ip, "1.2.3.4");
        assert_eq!(got[0].port, 443);
    }

    #[test]
    fn write_active_configs_produces_files() {
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(dir.path().join(".khvarenah"));
        let id = "default";
        let vless = sample_vless();
        let ep = CleanEndpoint {
            ip: "104.16.1.1".into(),
            port: 443,
            sni: "user.workers.dev".into(),
            score: 50.0,
            tcp_ms: 10.0,
            connect_ms: 20.0,
            download_kbps: 500.0,
            verified: true,
            alive: true,
            last_checked: None,
            ts: String::new(),
        };
        write_active_configs(id, &vless, &ep).unwrap();
        let dir = active_configs_dir(id);
        assert!(dir.join("link.txt").exists());
        assert!(dir.join("xray.json").exists());
        assert!(dir.join("sing-box.json").exists());
        assert!(dir.join("clash.yaml").exists());
        let link = std::fs::read_to_string(dir.join("link.txt")).unwrap();
        assert!(link.starts_with("vless://"));
        assert!(link.contains("104.16.1.1:443"));
    }

    #[test]
    fn discovery_params_defaults() {
        let p = DiscoveryParams::default();
        assert_eq!(p.sample, 2000);
        assert_eq!(p.workers, 64);
        assert_eq!(p.top_n, 3);
    }

    #[test]
    fn classify_health_alive_on_200() {
        assert!(matches!(
            classify_worker_health("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nfl=000"),
            WorkerHealth::Alive
        ));
    }

    #[test]
    fn classify_health_alive_on_101() {
        assert!(matches!(
            classify_worker_health("HTTP/1.1 101 Switching Protocols\r\n\r\n"),
            WorkerHealth::Alive
        ));
    }

    #[test]
    fn classify_health_path_mismatch_on_404() {
        assert_eq!(
            classify_worker_health("HTTP/1.1 404 Not Found\r\n\r\n"),
            WorkerHealth::PathMismatch
        );
    }

    #[test]
    fn classify_health_suspended_on_9109() {
        assert!(matches!(
            classify_worker_health("HTTP/1.1 403 Forbidden\r\n\r\n{\"code\":9109}"),
            WorkerHealth::Suspended { code: 9109 }
        ));
    }

    #[test]
    fn classify_health_unreachable_on_garbage() {
        assert_eq!(
            classify_worker_health("garbage bytes no http"),
            WorkerHealth::Unreachable
        );
    }

    #[cfg(feature = "dev-mock")]
    #[tokio::test]
    async fn probe_via_ips_marks_alive_against_mock_worker() {
        use crate::mock_worker::{run_mock_worker, MockWorkerConfig};
        let cfg = MockWorkerConfig {
            listen_addr: "127.0.0.1:18443".parse().unwrap(),
            worker_path: "/api".into(),
            ws_payload_bytes: 4096,
            trace_ip: "198.51.100.1".into(),
            cert_sni: "mock.workers.dev".into(),
        };
        let _handle = tokio::spawn(run_mock_worker(cfg));
        // Give the mock worker a moment to bind.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let ips = vec!["127.0.0.1".to_string()];
        let sample = probe_worker_via_ips("mock.workers.dev", &ips, 18443, 5).await;
        assert!(sample.alive, "mock worker should be detected alive");
        assert_eq!(sample.successful, 1);
        assert_eq!(sample.responding_ip, Some("127.0.0.1".parse().unwrap()));
    }

    #[cfg(feature = "dev-mock")]
    #[tokio::test]
    async fn probe_via_ips_reports_unreachable_when_nothing_listens() {
        let ips = vec!["127.0.0.1".to_string()];
        // Port 1 on loopback is effectively closed.
        let sample = probe_worker_via_ips("mock.workers.dev", &ips, 1, 3).await;
        assert!(!sample.alive);
        assert!(sample.unreachable >= 1);
    }

    /// When a DoH resolver is provided (cache seeded), resolution must use the
    /// DoH answer first — never the poisoned system resolver.
    #[tokio::test]
    async fn test_probe_worker_health_uses_doh_when_resolver_provided() {
        let resolver = crate::doh::DohResolver::new();
        let known = std::net::Ipv4Addr::new(104, 16, 132, 229);
        resolver.seed_cache("mock.workers.dev".to_string(), vec![known]);
        let resolved = resolve_worker_host("mock.workers.dev", Some(&resolver)).await;
        assert_eq!(resolved, Some(known), "DoH cache answer must be preferred");
    }

    #[tokio::test]
    async fn resolve_worker_host_falls_back_to_system_when_doh_fails() {
        // An empty (cacheless) resolver will attempt network; on failure we fall
        // back to system DNS. We only assert the fallback does not panic and
        // returns an Option (either Some real IP or None).
        let resolver = crate::doh::DohResolver::new();
        let _ = resolve_worker_host("example.com", Some(&resolver)).await;
    }

    // ── Auto-rescue chain (Feature C) ──

    /// Isolated profile home for store-backed tests.
    fn rescue_home() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(tmp.path().join(".khvarenah"));
        tmp
    }

    fn make_profile() -> String {
        crate::store::profiles::create_profile("rl", "").unwrap()
    }

    #[test]
    fn should_rescue_only_fires_on_recoverable_failures() {
        assert!(!should_rescue(&WorkerHealth::Alive));
        assert!(!should_rescue(&WorkerHealth::PathMismatch));
        assert!(should_rescue(&WorkerHealth::NotFound));
        assert!(should_rescue(&WorkerHealth::Unreachable));
        assert!(should_rescue(&WorkerHealth::Suspended { code: 9109 }));
    }

    /// The loop guard: a healthy worker that reports E2E IpUnchanged (the known
    /// already-tunneled false negative) must NOT trigger rescue — rescuing would
    /// spin an infinite re-scan loop.
    #[tokio::test]
    async fn test_rescue_does_not_trigger_on_e2e_ip_unchanged() {
        let _home = rescue_home();
        let id = make_profile();
        let peer = FakeRescuePeer::default();
        // Worker is Alive; E2E IpUnchanged is a *post-worker* failure stage,
        // so the worker health reaching the rescue gate is Alive.
        let chain = rescue_from_failure(&id, &peer, WorkerHealth::Alive)
            .await
            .unwrap();
        assert!(chain.attempts.is_empty(), "no rescue steps should run");
        assert!(!chain.gave_up);
        assert!(!peer.run_cycle_called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_plan_rescue_orders_steps_correctly() {
        // Fallback before reseed; manual seeds when present; redeploy last.
        let plan = plan_rescue(false, true, true, false);
        assert_eq!(plan[0], RescueAction::TryFallbackPool);
        assert_eq!(plan[1], RescueAction::ReseedFromLedger);
        assert_eq!(plan[2], RescueAction::ReseedFromManualSeeds);
        assert_eq!(plan[3], RescueAction::RedeployWorker);

        // Empty ledger skips fallback+reseed.
        let plan = plan_rescue(true, false, true, false);
        assert_eq!(plan, vec![RescueAction::RedeployWorker]);

        // No token + rate-limited redeploy → nothing to try.
        let plan = plan_rescue(true, false, false, true);
        assert!(plan.is_empty());

        // Manual seeds still attempted when ledger empty.
        let plan = plan_rescue(true, true, false, true);
        assert_eq!(plan, vec![RescueAction::ReseedFromManualSeeds]);
    }

    #[test]
    fn test_rescue_skips_fallback_when_ledger_empty() {
        let _home = rescue_home();
        let id = make_profile();
        // No ledger written → empty → fallback+reseed skipped.
        assert!(read_ledger(&id).is_empty());
        let plan = plan_rescue(read_ledger(&id).is_empty(), false, false, true);
        assert!(plan.is_empty());
    }

    #[tokio::test]
    async fn test_rescue_gives_up_after_all_steps_fail() {
        let _home = rescue_home();
        let id = make_profile();
        // Seed a ledger (so fallback+reseed are attempted), manual seeds,
        // and a token label so redeploy is tried too.
        let ep = sample_clean_endpoint("1.1.1.1", 443, true);
        write_ledger(&id, &[ep]);
        crate::cf::ips::import_manual_seeds(&id, "8.8.8.8").unwrap();
        crate::store::profiles::add_token(&id, "tok", "x").unwrap();
        crate::store::profiles::set_active_token(&id, "tok").unwrap();

        // Peer: nothing alive, no cycle results, redeploy fails.
        let peer = FakeRescuePeer {
            alive: false,
            cycle_result: None,
            redeploy_ok: false,
            ..Default::default()
        };
        let chain = rescue_from_failure(&id, &peer, WorkerHealth::NotFound)
            .await
            .unwrap();
        assert!(chain.gave_up);
        assert!(chain.final_state.is_none());
        assert!(chain
            .attempts
            .iter()
            .any(|a| a.action == RescueAction::GiveUp));
    }

    #[tokio::test]
    async fn test_rescue_returns_first_success_and_stops() {
        let _home = rescue_home();
        let id = make_profile();
        let ep = sample_clean_endpoint("1.1.1.1", 443, true);
        write_ledger(&id, &[ep]);

        // Fallback pool has no alive alternate, but the reseed cycle returns
        // verified endpoints → recovery on the 2nd step.
        let peer = FakeRescuePeer {
            alive: false,
            cycle_result: Some(vec![sample_clean_endpoint("104.16.0.1", 443, true)]),
            redeploy_ok: false,
            ..Default::default()
        };
        let chain = rescue_from_failure(&id, &peer, WorkerHealth::Unreachable)
            .await
            .unwrap();
        assert!(!chain.gave_up);
        assert!(chain.final_state.is_some());
        assert_eq!(chain.attempts.len(), 2);
        assert_eq!(chain.attempts[1].action, RescueAction::ReseedFromLedger);
        assert!(matches!(
            chain.attempts[1].outcome,
            RescueOutcome::Success { .. }
        ));
    }

    #[tokio::test]
    async fn test_rescue_uses_manual_seeds_when_fallback_and_reseed_fail() {
        let _home = rescue_home();
        let id = make_profile();
        let ep = sample_clean_endpoint("1.1.1.1", 443, true);
        write_ledger(&id, &[ep]);
        crate::cf::ips::import_manual_seeds(&id, "8.8.8.8").unwrap();

        // Fallback dead, ledger reseed empty, manual reseed succeeds.
        let peer = FakeRescuePeer {
            alive: false,
            cycle_result: None,
            manual_cycle_result: Some(vec![sample_clean_endpoint("8.8.8.8", 443, true)]),
            redeploy_ok: false,
            ..Default::default()
        };
        let chain = rescue_from_failure(&id, &peer, WorkerHealth::NotFound)
            .await
            .unwrap();
        assert!(!chain.gave_up);
        assert_eq!(chain.attempts.len(), 3);
        assert_eq!(
            chain.attempts[2].action,
            RescueAction::ReseedFromManualSeeds
        );
        assert!(matches!(
            chain.attempts[2].outcome,
            RescueOutcome::Success { .. }
        ));
    }

    #[tokio::test]
    async fn test_rescue_redeploys_when_seed_sources_exhausted() {
        let _home = rescue_home();
        let id = make_profile();
        let ep = sample_clean_endpoint("1.1.1.1", 443, true);
        write_ledger(&id, &[ep]);
        crate::cf::ips::import_manual_seeds(&id, "8.8.8.8").unwrap();
        crate::store::profiles::add_token(&id, "tok", "x").unwrap();
        crate::store::profiles::set_active_token(&id, "tok").unwrap();

        let peer = FakeRescuePeer {
            alive: false,
            cycle_result: None,
            manual_cycle_result: None,
            redeploy_ok: true,
            // After redeploy (4th call) succeed.
            post_redeploy_result: Some(vec![sample_clean_endpoint("104.16.0.9", 443, true)]),
            ..Default::default()
        };
        let chain = rescue_from_failure(&id, &peer, WorkerHealth::Suspended { code: 9109 })
            .await
            .unwrap();
        assert!(!chain.gave_up);
        assert!(chain
            .attempts
            .iter()
            .any(|a| a.action == RescueAction::RedeployWorker));
        assert!(chain
            .attempts
            .iter()
            .any(|a| matches!(a.outcome, RescueOutcome::Success { .. })));
    }

    #[tokio::test]
    async fn test_rescue_refuses_redeploy_within_one_hour() {
        let _home = rescue_home();
        let id = make_profile();
        let ep = sample_clean_endpoint("1.1.1.1", 443, true);
        write_ledger(&id, &[ep]);
        crate::store::profiles::add_token(&id, "tok", "x").unwrap();
        crate::store::profiles::set_active_token(&id, "tok").unwrap();

        // Force last_redeploy_ts to now so the rate-limit (1/hour) applies.
        let now = crate::store::now_ts() as i64;
        crate::store::profiles::save_rescue_meta(&id, 0, now, None).unwrap();

        let peer = FakeRescuePeer::default();
        let chain = rescue_from_failure(&id, &peer, WorkerHealth::NotFound)
            .await
            .unwrap();
        // Redeploy step is skipped (Skipped), not attempted.
        let redeploy = chain
            .attempts
            .iter()
            .find(|a| a.action == RescueAction::RedeployWorker);
        assert!(redeploy.is_some());
        assert!(matches!(
            redeploy.unwrap().outcome,
            RescueOutcome::Skipped { .. }
        ));
    }

    #[tokio::test]
    async fn test_profile_config_migrates_without_rescue_fields() {
        let _home = rescue_home();
        let id = make_profile();
        // Simulate an older config: write a config JSON without the new fields.
        let cfg_path = crate::store::profiles::profile_dir(&id).join("config.json");
        let old_cfg = serde_json::json!({
            "active_account": "acc-1",
            "stealth_enabled": true,
            "protection_enabled": false,
            "light_interval_secs": 300,
            "failure_streak": 0,
            "last_deep_check": 0,
        });
        crate::store::write_json(&cfg_path, &old_cfg).unwrap();

        let p = crate::store::profiles::load_profile(&id);
        // New fields default cleanly (migration-safe).
        assert_eq!(p.config.last_redeploy_ts, 0);
        assert_eq!(p.config.last_rescue_attempt_ts, 0);
        assert!(p.config.last_rescue_outcome.is_none());
    }

    /// A scripted peer for the rescue chain (no network).
    #[derive(Default)]
    struct FakeRescuePeer {
        alive: bool,
        cycle_result: Option<Vec<CleanEndpoint>>,
        manual_cycle_result: Option<Vec<CleanEndpoint>>,
        redeploy_ok: bool,
        post_redeploy_result: Option<Vec<CleanEndpoint>>,
        run_cycle_called: std::sync::atomic::AtomicBool,
        cycle_calls: std::sync::atomic::AtomicUsize,
    }

    impl FakeRescuePeer {
        fn next_cycle(&self) -> Option<Vec<CleanEndpoint>> {
            let n = self.cycle_calls.fetch_add(1, Ordering::SeqCst);
            match n {
                0 => self.cycle_result.clone(),         // ledger reseed
                1 => self.manual_cycle_result.clone(),  // manual reseed
                _ => self.post_redeploy_result.clone(), // post-redeploy
            }
        }
    }

    impl RescuePeer for FakeRescuePeer {
        fn endpoint_alive(
            &self,
            _ip: &str,
            _sni: &str,
            _path: &str,
            _timeout_ms: u64,
        ) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
            let alive = self.alive;
            Box::pin(async move { alive })
        }

        fn run_cycle(
            &self,
            _params: &DiscoveryParams,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<(Vec<CleanEndpoint>, CycleSummary), CFError>>
                    + Send
                    + '_,
            >,
        > {
            self.run_cycle_called.store(true, Ordering::SeqCst);
            let result = self.next_cycle();
            Box::pin(async move {
                match result {
                    Some(eps) => Ok((
                        eps.clone(),
                        CycleSummary {
                            cycle: 0,
                            alive: eps.len(),
                            replaced: 0,
                            note: "fake".into(),
                        },
                    )),
                    None => Err(CFError::new("Fake", "no endpoints", "")),
                }
            })
        }

        fn redeploy_worker(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<(), CFError>> + Send + '_>> {
            let ok = self.redeploy_ok;
            Box::pin(async move {
                if ok {
                    Ok(())
                } else {
                    Err(CFError::new("Fake", "redeploy failed", ""))
                }
            })
        }
    }

    fn sample_clean_endpoint(ip: &str, port: u16, verified: bool) -> CleanEndpoint {
        CleanEndpoint {
            ip: ip.into(),
            port,
            sni: "user.workers.dev".into(),
            score: 50.0,
            tcp_ms: 10.0,
            connect_ms: 20.0,
            download_kbps: 500.0,
            verified,
            alive: false,
            last_checked: None,
            ts: String::new(),
        }
    }

    // ── Self-learning phase-2 SNI strategy (autonomy) ──
    // ── Self-learning phase-2 SNI strategy v2 (rolling-window) ──

    #[test]
    fn test_record_cycle_outcome_appends_and_trims_window() {
        let mut s = StrategyState::default();
        for i in 0..STRATEGY_WINDOW + 2 {
            record_cycle_outcome(&mut s, i % 2 == 0);
        }
        assert_eq!(s.recent_outcomes.len(), STRATEGY_WINDOW);
        // Newest outcome is last; the two oldest were trimmed.
        assert_eq!(
            *s.recent_outcomes.last().unwrap(),
            (STRATEGY_WINDOW + 1) % 2 == 0
        );
        assert_eq!(s.cycles_since_rotation, (STRATEGY_WINDOW + 2) as u32);
    }

    #[test]
    fn test_success_rate_empty_returns_none() {
        let s = StrategyState::default();
        assert_eq!(success_rate(&s), None);
    }

    #[test]
    fn test_should_rotate_early_dead_on_three_zeros() {
        let mut s = StrategyState::default();
        record_cycle_outcome(&mut s, false);
        record_cycle_outcome(&mut s, false);
        assert!(!should_rotate(&s));
        record_cycle_outcome(&mut s, false);
        assert!(should_rotate(&s));
    }

    #[test]
    fn test_should_rotate_windowed_when_rate_below_threshold() {
        let mut s = StrategyState::default();
        // 2 wins / 10 = 20% < 30% floor -> rotate.
        record_cycle_outcome(&mut s, true);
        record_cycle_outcome(&mut s, true);
        for _ in 0..8 {
            record_cycle_outcome(&mut s, false);
        }
        assert_eq!(s.recent_outcomes.len(), STRATEGY_WINDOW);
        assert_eq!(success_rate(&s), Some(0.2));
        assert!(should_rotate(&s));
    }

    #[test]
    fn test_should_rotate_not_when_rate_above_threshold_and_under_forced_cycles() {
        let mut s = StrategyState::default();
        // 2 wins / 5 = 40% > 30%, and only 5 cycles < 20 -> no rotation.
        record_cycle_outcome(&mut s, true);
        record_cycle_outcome(&mut s, true);
        record_cycle_outcome(&mut s, false);
        record_cycle_outcome(&mut s, false);
        record_cycle_outcome(&mut s, false);
        assert_eq!(success_rate(&s), Some(0.4));
        assert!(!should_rotate(&s));
    }

    #[test]
    fn test_should_rotate_forced_at_twenty_cycles() {
        let mut s = StrategyState::default();
        record_cycle_outcome(&mut s, true);
        for _ in 0..STRATEGY_FORCED_ROTATION_CYCLES - 1 {
            record_cycle_outcome(&mut s, true);
        }
        assert_eq!(s.cycles_since_rotation, STRATEGY_FORCED_ROTATION_CYCLES);
        assert!(should_rotate(&s));
    }

    #[test]
    fn test_rotate_flips_strategy_and_clears_state() {
        let mut s = StrategyState::default();
        record_cycle_outcome(&mut s, false);
        record_cycle_outcome(&mut s, false);
        record_cycle_outcome(&mut s, false);
        let s = rotate(s);
        assert_eq!(s.current, crate::health::SniStrategy::GenericCfFirst);
        assert!(s.recent_outcomes.is_empty());
        assert_eq!(s.cycles_since_rotation, 0);
    }

    #[test]
    fn test_commit_strategy_v2_persists_and_reports_rotation() {
        let _home = rescue_home();
        let id = make_profile();
        let mut state = resolve_strategy_v2(&id);
        assert_eq!(state.current, crate::health::SniStrategy::WorkerOnly);
        assert!(state.recent_outcomes.is_empty());

        // Three consecutive zero-verified cycles -> early-dead rotation.
        assert!(!commit_strategy_v2(&id, &mut state, false).unwrap());
        assert!(!commit_strategy_v2(&id, &mut state, false).unwrap());
        let rotated = commit_strategy_v2(&id, &mut state, false).unwrap();
        assert!(rotated);

        // Persisted state reflects the rotation: flipped strategy, cleared window.
        let reloaded = resolve_strategy_v2(&id);
        assert_eq!(reloaded.current, crate::health::SniStrategy::GenericCfFirst);
        assert!(reloaded.recent_outcomes.is_empty());
        assert_eq!(reloaded.cycles_since_rotation, 0);
    }

    #[test]
    fn test_profile_config_migrates_to_v2_fields() {
        let _home = rescue_home();
        let id = make_profile();
        // Simulate an old config without any v2 strategy fields.
        let cfg_path = crate::store::profiles::profile_dir(&id).join("config.json");
        let old_cfg = serde_json::json!({
            "active_account": "acc-1",
            "stealth_enabled": true,
            "protection_enabled": false,
            "light_interval_secs": 300,
            "failure_streak": 0,
            "last_deep_check": 0,
        });
        crate::store::write_json(&cfg_path, &old_cfg).unwrap();

        let p = crate::store::profiles::load_profile(&id);
        assert!(p.config.strategy_current.is_none());
        assert!(p.config.strategy_recent_outcomes.is_empty());
        assert_eq!(p.config.strategy_cycles_since_rotation, 0);
        assert_eq!(p.config.strategy_last_rotated_ts, 0);

        // v2 resolve on the migrated config defaults to an empty WorkerOnly state.
        let state = resolve_strategy_v2(&id);
        assert_eq!(state.current, crate::health::SniStrategy::WorkerOnly);
        assert!(state.recent_outcomes.is_empty());
    }

    // ── Health beacon acceptance (round 4) ──

    /// Scripted provider: returns a fixed result on every discover call.
    struct ScriptedProvider {
        result: Result<Vec<CleanEndpoint>, CFError>,
    }

    impl EndpointProvider for ScriptedProvider {
        fn discover<'a>(
            &'a self,
            _vless: &'a VlessProfile,
            _params: &'a DiscoveryParams,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<CleanEndpoint>, CFError>> + Send + 'a>>
        {
            let result = self.result.clone();
            Box::pin(async move { result })
        }
    }

    fn seeded_vless_profile(id: &str) {
        let rec = crate::store::profiles::VlessRecord {
            link: "vless://8274e874-7470-43ee-8018-4bc3baa709a5@104.17.147.186:443?encryption=none&security=tls&type=ws&sni=amir.dariuskhosrowan.workers.dev&host=amir.dariuskhosrowan.workers.dev&path=%2F&fp=chrome#amir".to_string(),
            address: "104.17.147.186".to_string(),
            port: 443,
            uuid: "8274e874-7470-43ee-8018-4bc3baa709a5".to_string(),
            name: "test".to_string(),
            clean_ip: false,
            ..Default::default()
        };
        crate::store::profiles::remember_vless(id, rec).unwrap();
    }

    #[tokio::test]
    async fn test_run_cycle_writes_beacon_on_success() {
        let _home = rescue_home();
        let id = make_profile();
        seeded_vless_profile(&id);

        // Script a successful discovery: one verified endpoint.
        let provider = Box::new(ScriptedProvider {
            result: Ok(vec![CleanEndpoint {
                ip: "1.2.3.4".into(),
                port: 443,
                sni: "amir.dariuskhosrowan.workers.dev".into(),
                score: 99.0,
                tcp_ms: 5.0,
                connect_ms: 8.0,
                download_kbps: 900.0,
                verified: true,
                alive: true,
                last_checked: None,
                ts: String::new(),
            }]),
        });

        let engine = AutopilotEngine::with_provider(
            id.clone(),
            DiscoveryParams::default(),
            std::time::Duration::from_secs(300),
            provider,
        );
        let (found, _summary) = engine.run_cycle().await.expect("cycle succeeds");
        assert!(!found.is_empty());

        let beacon = crate::health_beacon::read_beacon(&id)
            .unwrap()
            .expect("beacon written on success");
        assert_eq!(
            beacon.cycle_kind,
            crate::health_beacon::CycleKind::Discovery
        );
        assert!(
            beacon.last_error.is_none(),
            "last_error={:?}",
            beacon.last_error
        );
        assert_eq!(beacon.active_endpoint.as_deref(), Some("1.2.3.4:443"));
        // A won discovery records a 1 in the strategy window.
        assert_eq!(beacon.strategy_window.last(), Some(&1u8));
        assert!(beacon.written_at > 0);
    }

    #[tokio::test]
    async fn test_run_cycle_writes_beacon_on_failure() {
        let _home = rescue_home();
        let id = make_profile();
        // No vless history set up → base_vless errors before discovery. This is
        // the case that matters most: a failure cycle must still leave a
        // readable health beacon.
        let engine = AutopilotEngine::new(
            id.clone(),
            DiscoveryParams::default(),
            std::time::Duration::from_secs(300),
        );
        assert!(engine.run_cycle().await.is_err());

        let beacon = crate::health_beacon::read_beacon(&id)
            .unwrap()
            .expect("beacon written on failure");
        assert_eq!(
            beacon.cycle_kind,
            crate::health_beacon::CycleKind::Discovery
        );
        assert!(beacon.last_error.is_some(), "last_error expected");
        assert!(beacon.written_at > 0);
    }
}
