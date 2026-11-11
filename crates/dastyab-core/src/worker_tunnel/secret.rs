//! Per-worker session-secret management and two-phase rotation.
//!
//! # Why per-worker secrets
//!
//! Originally every deployed worker shared one `DYB_SESSION_SECRET` derived
//! from the profile's session seed. A single deploy drift, partial rollout, or
//! leaked secret therefore compromised the *entire* worker tier at once — the
//! largest blast radius in the resilience stack. This module gives each worker
//! its own secret and rotates them on a schedule.
//!
//! # Two-phase (pending → current) rotation
//!
//! Naive rotation overwrites the profile secret before the worker redeploys; a
//! mid-rotation crash leaves profile and worker out of sync and the worker tier
//! unreachable until a manual fix. Instead, rotation is two-phase:
//!
//! 1. `rotate_worker_secret` writes a new `pending_secret` (the current value
//!    stays valid), calls the deploy with the pending value, then verifies via
//!    `query_self_ping` (flag 6, authenticated with the *pending* secret).
//! 2. Only on verified success does it promote `pending_secret` → `secret`,
//!    bump `rotated_unix`/`version`, and clear pending.
//!
//! On any failure the pending secret remains; the current secret stays valid
//! and the worker keeps serving traffic on it until the next rotation attempt.
//! `resolve_worker_secret` always returns the current (never pending) secret.

use std::borrow::Cow;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::error::CFError;

/// Serializes the read-modify-write on per-worker desync learning records
/// across concurrent monitor paths (daemon deep discovery + GUI light sweep).
static DESYNC_LEARN_LOCK: Mutex<()> = Mutex::new(());

/// A worker's session secret plus its two-phase rotation state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WorkerSecret {
    /// Worker URL (identity key in `ProfileConfig.worker_secrets`).
    #[serde(default)]
    pub worker_url: String,
    /// Current (active) secret.
    #[serde(default)]
    pub secret: String,
    /// Epoch-seconds the current secret was last rotated.
    #[serde(default)]
    pub rotated_unix: u64,
    /// Monotonic rotation counter (starts at 1 after first assignment).
    #[serde(default)]
    pub version: u32,
    /// Pending secret awaiting deployment + verification (two-phase rotation).
    #[serde(default)]
    pub pending_secret: Option<String>,
    /// Epoch-seconds the pending secret was written (for the in-flight guard).
    #[serde(default)]
    pub pending_since_unix: u64,
    /// Learned anti-DPI strategy that last succeeded for this worker's relay
    /// control-plane path. `None` = not yet learned (use the ladder).
    #[serde(default)]
    pub desync_strategy: Option<crate::desync::DesyncStrategy>,
    /// Strategies tried on this worker that failed (ladder skips these).
    #[serde(default)]
    pub failed_strategies: Vec<crate::desync::DesyncStrategy>,
    /// True while the worker host itself is unreachable at the transport layer
    /// (TCP connect refused/timeout — zero handshake). While set, the ladder is
    /// held: probe failures are NOT treated as strategy evidence, so we neither
    /// demote nor advance. A later success clears this and resumes at the same
    /// (held) effective strategy. Distinct from a strategy-level demotion.
    #[serde(default)]
    pub host_down: bool,
    /// Epoch-seconds the host was last marked down (0 = never/up).
    #[serde(default)]
    pub host_down_since_unix: u64,
}

/// Maximum age (seconds) of an in-flight pending rotation before it is treated
/// as stale and eligible to be retried/overwritten.
pub const MAX_PENDING_AGE_SECS: u64 = 3600; // 1h

/// Secret length in hex characters (32 hex chars = 16 bytes).
pub const SECRET_HEX_LEN: usize = 32;

/// Generate a 32-hex-char session secret via SHA-256 (the repo's already-present
/// hash), using the same `"worker-tunnel-v1"` salt as the legacy derivation so
/// per-worker secrets are distinguishable yet in-family.
pub fn generate_secret() -> String {
    use sha2::{Digest, Sha256};
    // Mix in a random nonce so two calls never collide even within the same
    // second. `std::time::SystemTime` + a per-call atomic counter is enough
    // for a session secret (not a cryptographic nonce requirement).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let c = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut hasher = Sha256::new();
    hasher.update(b"worker-tunnel-v1");
    hasher.update(now.to_le_bytes());
    hasher.update(c.to_le_bytes());
    let h = hasher.finalize();
    hex(&h[..SECRET_HEX_LEN / 2])
}

/// Resolve the effective secret for `worker_url`: the per-worker secret when
/// present, otherwise the legacy shared secret. Never returns a pending secret.
pub fn resolve_worker_secret<'a>(
    cfg: &'a crate::store::profiles::ProfileConfig,
    worker_url: &str,
    legacy_shared: &'a str,
) -> Cow<'a, str> {
    match cfg.worker_secrets.get(worker_url) {
        Some(ws) if !ws.secret.is_empty() => Cow::Borrowed(ws.secret.as_str()),
        _ => Cow::Borrowed(legacy_shared),
    }
}

/// Assign a fresh secret to a worker. If none exists, `version` starts at 1.
/// If one exists (rotation), it is written to `pending_secret` for two-phase
/// promotion — the current secret stays valid until verification succeeds.
pub fn assign_new_secret(
    cfg: &mut crate::store::profiles::ProfileConfig,
    worker_url: &str,
    now_unix: u64,
) -> Result<(), CFError> {
    let secret = generate_secret();
    let entry = cfg
        .worker_secrets
        .entry(worker_url.to_string())
        .or_default();
    entry.worker_url = worker_url.to_string();
    if entry.secret.is_empty() {
        // First assignment → promote immediately; no pending phase needed.
        entry.secret = secret;
        entry.rotated_unix = now_unix;
        entry.version = 1;
        entry.pending_secret = None;
        entry.pending_since_unix = 0;
    } else {
        // Two-phase rotation → stage as pending; worker still serves current.
        entry.pending_secret = Some(secret);
        entry.pending_since_unix = now_unix;
    }
    Ok(())
}

/// Whether rotation is due for `worker_url`: the current secret is older than
/// `max_age_secs`.
pub fn rotation_due(
    cfg: &crate::store::profiles::ProfileConfig,
    worker_url: &str,
    now_unix: u64,
    max_age_secs: u64,
) -> bool {
    let Some(ws) = cfg.worker_secrets.get(worker_url) else {
        return true; // no secret yet → due
    };
    now_unix.saturating_sub(ws.rotated_unix) >= max_age_secs
}

/// Whether a rotation may start now. Gate used by the daemon tick so rotation
/// never fires during a blackout (wasted attempt + noisy failure) and never
/// piles a second pending on top of a live one.
pub fn rotation_eligible(
    cfg: &crate::store::profiles::ProfileConfig,
    worker_url: &str,
    now_unix: u64,
    max_age_secs: u64,
    net_up: bool,
) -> bool {
    if !net_up {
        return false;
    }
    if let Some(ws) = cfg.worker_secrets.get(worker_url) {
        // An in-flight pending that is still fresh blocks a new rotation.
        if ws.pending_secret.is_some()
            && now_unix.saturating_sub(ws.pending_since_unix) < MAX_PENDING_AGE_SECS
        {
            return false;
        }
    }
    rotation_due(cfg, worker_url, now_unix, max_age_secs)
}

/// Promote a pending secret to current after verified deploy. Returns the new
/// version.
pub fn promote_pending(
    cfg: &mut crate::store::profiles::ProfileConfig,
    worker_url: &str,
    now_unix: u64,
) -> Result<u32, CFError> {
    let entry = cfg
        .worker_secrets
        .get_mut(worker_url)
        .ok_or_else(|| CFError::new("rotate", "no secret for worker", ""))?;
    let pending = entry
        .pending_secret
        .take()
        .ok_or_else(|| CFError::new("rotate", "no pending secret", ""))?;
    entry.secret = pending;
    entry.rotated_unix = now_unix;
    entry.version = entry.version.saturating_add(1);
    entry.pending_since_unix = 0;
    Ok(entry.version)
}

/// Cancel a stale/aborted pending rotation (keeps the current secret active).
pub fn clear_pending(cfg: &mut crate::store::profiles::ProfileConfig, worker_url: &str) {
    if let Some(entry) = cfg.worker_secrets.get_mut(worker_url) {
        entry.pending_secret = None;
        entry.pending_since_unix = 0;
    }
}

/// Select the anti-DPI desync strategy for a worker's relay control-plane
/// call. Mirrors the endpoint ladder: a recorded effective strategy wins when
/// it isn't in the failed-set; otherwise walk `LADDER` from `attempt`,
/// skipping failed entries. Falls back to `None` (single segment).
pub fn strategy_for_worker(
    cfg: &crate::store::profiles::ProfileConfig,
    worker_url: &str,
    attempt: u8,
) -> crate::desync::DesyncStrategy {
    let entry = cfg.worker_secrets.get(worker_url);
    // Host-down hold: the worker host itself is unreachable. The failure was
    // NOT strategy-attributable, so hold the current strategy (do not advance
    // the ladder). We still return the held effective strategy if we have one;
    // with none, fall back to the ladder start (we don't know a good shape
    // yet). When the host recovers, success clears the hold and we resume.
    if let Some(e) = entry {
        if e.host_down {
            if let Some(ef) = e.desync_strategy.as_ref() {
                return *ef;
            }
            // No learned shape yet — probe with the ladder default (None).
            return crate::desync::DesyncStrategy::None;
        }
    }
    let effective = entry.and_then(|e| e.desync_strategy.as_ref());
    let failed: &[crate::desync::DesyncStrategy] = match entry {
        Some(e) => e.failed_strategies.as_slice(),
        None => &[],
    };
    crate::desync::select_strategy(effective, failed, attempt)
}

/// Record a successful strategy for a worker relay path: set it as effective
/// and clear it from the failed-set (persisted on the profile). Other failed
/// strategies are retained — a success on one shape does not invalidate the
/// observation that a different shape failed. This makes success and failure
/// updates touch disjoint state, so concurrent/unanchored learn writes compose
/// order-independently (acceptance 'c').
pub fn record_worker_desync_success(
    cfg: &mut crate::store::profiles::ProfileConfig,
    worker_url: &str,
    strategy: crate::desync::DesyncStrategy,
) {
    let entry = cfg
        .worker_secrets
        .entry(worker_url.to_string())
        .or_default();
    entry.worker_url = worker_url.to_string();
    entry.desync_strategy = Some(strategy);
    entry.failed_strategies.retain(|s| *s != strategy);
    // A success proves the host is reachable again — clear any host-down hold
    // so the ladder resumes (at the still-held effective strategy).
    entry.host_down = false;
    entry.host_down_since_unix = 0;
}

/// Record a failed strategy for a worker relay path: push it to the failed-set
/// (capped at 4) so the ladder advances next attempt.
pub fn record_worker_desync_failure(
    cfg: &mut crate::store::profiles::ProfileConfig,
    worker_url: &str,
    strategy: crate::desync::DesyncStrategy,
) {
    let entry = cfg
        .worker_secrets
        .entry(worker_url.to_string())
        .or_default();
    entry.worker_url = worker_url.to_string();
    if !entry.failed_strategies.contains(&strategy) {
        entry.failed_strategies.push(strategy);
        const MAX_FAILED: usize = 4;
        if entry.failed_strategies.len() > MAX_FAILED {
            entry.failed_strategies.remove(0);
        }
    }
}

/// Mark a worker host as unreachable at the transport layer (TCP connect
/// refused/timeout — zero handshake). This is a HOST signal, not a strategy
/// signal: we record `host_down` so the ladder is held (no demotion/advance)
/// until a later success proves the host recovered. Returns `true` if the
/// record changed (caller persists).
pub fn record_worker_host_down(
    cfg: &mut crate::store::profiles::ProfileConfig,
    worker_url: &str,
    now_unix: u64,
) -> bool {
    let entry = cfg
        .worker_secrets
        .entry(worker_url.to_string())
        .or_default();
    entry.worker_url = worker_url.to_string();
    let changed = !entry.host_down || entry.host_down_since_unix == 0;
    entry.host_down = true;
    if entry.host_down_since_unix == 0 {
        entry.host_down_since_unix = now_unix;
    }
    changed
}

/// Classification of a per-worker probe outcome for learning purposes.
///
/// This is the deliverable column of the error-variant → classification table
/// (DeepSeek A100/A105):
///
/// | signal | meaning | learn? |
/// |--------|---------|--------|
/// | `Success` | 101 + worker bytes ≥ MIN | yes — promote effective, clear host-down |
/// | `HostDown` | TCP connect refused/timeout, zero handshake | no — hold ladder, record host-down |
/// | `StrategyFailure` | TCP connected; WS handshake/data/route failed | yes — demote the strategy used |
/// | `Unclassifiable` | unknown/ambiguous | no — safer to skip than to demote |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LearningSignal {
    Success,
    HostDown,
    StrategyFailure,
    Unclassifiable,
}

/// Classify a budgeted light-phase endpoint outcome into a [`LearningSignal`].
/// The light phase aggregates across ports, so we map the *bucket* the sweep
/// settled on. `TcpTimeoutAllPorts` = transport-level host unreachable (no
/// handshake ever started) → `HostDown`. Note: the light aggregate carries NO
/// HTTP status histogram, so the `WsUpgradeAllPorts`/`WorkerBytesAllPorts`
/// buckets are ambiguous (they could be a strategy-attributable DPI/WAF reject,
/// or an origin-unavailable worker behind a live TCP port). Per the "ambiguous
/// ⇒ no learning" rule, those map to `Unclassifiable` and hold — the deeper
/// per-probe path (which has the status) is the authority for the split.
/// `TlsResetAllPorts` is a clear TLS-layer DPI signature → `StrategyFailure`.
/// `BudgetExceeded` is ambiguous → `Unclassifiable`.
pub fn classify_endpoint_outcome(
    stage: Option<crate::health::EndpointFailureStage>,
) -> LearningSignal {
    match stage {
        None => LearningSignal::Success,
        Some(crate::health::EndpointFailureStage::TcpTimeoutAllPorts) => LearningSignal::HostDown,
        Some(crate::health::EndpointFailureStage::TlsResetAllPorts) => {
            LearningSignal::StrategyFailure
        }
        Some(crate::health::EndpointFailureStage::WsUpgradeAllPorts)
        | Some(crate::health::EndpointFailureStage::WorkerBytesAllPorts)
        | Some(crate::health::EndpointFailureStage::BudgetExceeded) => {
            LearningSignal::Unclassifiable
        }
    }
}

/// Split a failure histogram into strategy-attributable (DPI/401/403) vs
/// origin-unavailable (5xx) counts. Shared by the light sweep and the deep
/// discovery path so the two cannot disagree on the same histogram (parity).
/// `dpi` = TLS reset/timeout/write-failed (DPI signature) + 401/403 (WAF/DPI
/// fingerprint rejection). `origin` = HTTP 5xx (worker/origin unavailable).
pub fn histogram_attribution(
    hist: &std::collections::HashMap<crate::health::WsFailureReason, u32>,
) -> (u32, u32) {
    let mut dpi = 0u32;
    let mut origin = 0u32;
    for (r, n) in hist {
        match r {
            crate::health::WsFailureReason::HttpStatus(c) => {
                if *c == 401 || *c == 403 {
                    dpi += *n;
                } else if http_status_is_origin_unavailable(*c) {
                    origin += *n;
                }
            }
            crate::health::WsFailureReason::TlsAlert
            | crate::health::WsFailureReason::TlsTimeout
            | crate::health::WsFailureReason::WriteFailed => dpi += *n,
            _ => {}
        }
    }
    (dpi, origin)
}

/// Dead-fraction floor for the light sweep classifier: if the proportion of
/// non-alive endpoints is at or below this, the strategy is substantially
/// working and we hold regardless of the failure composition (a lone DPI
/// failure among mostly-alive endpoints is not a reason to demote a strategy
/// that is carrying 2/3+ of the endpoints). Above the floor, the failure
/// composition decides (DPI/401/403-dominant ⇒ demote; origin-5xx-dominant ⇒
/// hold).
pub const DEAD_FRACTION_FLOOR: f64 = 1.0 / 3.0;

/// Classify a *light sweep* aggregate outcome. Unlike
/// [`classify_endpoint_outcome`] (which works on a single status-less bucket),
/// this consumes the sweep's HTTP-status/failure histogram so light can reach
/// the same verdict deep would, including the healthy-but-muted case:
///
/// - All endpoints alive → `Success` (nothing to learn).
/// - Dead fraction ≤ [`DEAD_FRACTION_FLOOR`] → `Unclassifiable` (hold): the
///   strategy is substantially working; a minority of failures — whatever
///   their composition — is not a demotion signal (guards the false demotion
///   where 6/7 endpoints are alive and one fails with a TlsAlert).
/// - Dead fraction high (> floor) and failures DPI/401/403-dominant →
///   `StrategyFailure` (healthy-but-muted: a live fallback is masking a muted
///   worker; learn the demotion). This is the case deep never sees (it only
///   runs on NeedDeep), so light learning it closes the silent gap.
/// - Dead fraction high and failures origin-5xx-dominant or mixed →
///   `Unclassifiable` (origin-degraded → hold; don't demote on a worker outage).
/// - No histogram (status-less aggregates / empty) → fall back to legacy:
///   `Success` when all alive, `Unclassifiable` otherwise. This is the regression
///   guard for the option-(a) fix — the histogram is additive where present.
pub fn classify_light_sweep(
    alive: usize,
    total: usize,
    hist: Option<&std::collections::HashMap<crate::health::WsFailureReason, u32>>,
) -> LearningSignal {
    if total == 0 {
        return LearningSignal::Unclassifiable;
    }
    let dead = total.saturating_sub(alive);
    let Some(h) = hist else {
        return if alive == total {
            LearningSignal::Success
        } else {
            LearningSignal::Unclassifiable
        };
    };
    if h.is_empty() {
        return if alive == total {
            LearningSignal::Success
        } else {
            LearningSignal::Unclassifiable
        };
    }
    if alive == total {
        return LearningSignal::Success;
    }
    let dead_fraction = dead as f64 / total as f64;
    if dead_fraction <= DEAD_FRACTION_FLOOR {
        // Strategy substantially working — hold, do not demote.
        return LearningSignal::Unclassifiable;
    }
    let (dpi, origin) = histogram_attribution(h);
    if dpi > origin {
        LearningSignal::StrategyFailure
    } else {
        LearningSignal::Unclassifiable
    }
}

/// Whether an HTTP status from a WS-upgrade response means the *origin/worker*
/// is unavailable (as opposed to the edge/DPI rejecting the connection on our
/// wire shape). Cloudflare 5xx statuses (502/503/504/520/521/522/524/530) are
/// emitted by the edge when the worker script errors, times out, or the origin
/// is down — they are NOT a signal about our anti-DPI write shape, so they must
/// never demote a strategy.
pub fn http_status_is_origin_unavailable(code: u16) -> bool {
    (500..600).contains(&code)
}

/// Classify an HTTP status from a WS-upgrade response into a [`LearningSignal`].
/// Not all 4xx are strategy-attributable:
/// - 401/403: auth/WAF/DPI fingerprint rejections → strategy-attributable.
/// - 404: ambiguous (dead route vs config) → no learning (hold).
/// - 408: request timeout → not strategy → no learning (hold).
/// - 421: misdirected request → dead route/config → no learning (hold).
/// - 429: rate limiting / throttling → not strategy → no learning (hold).
/// - 5xx: origin unavailable → no learning (hold).
/// - anything else: treat as ambiguous → no learning (safe default).
pub fn http_status_learning_signal(code: u16) -> LearningSignal {
    match code {
        401 | 403 => LearningSignal::StrategyFailure,
        404 | 408 | 421 | 429 => LearningSignal::Unclassifiable,
        _ if http_status_is_origin_unavailable(code) => LearningSignal::Unclassifiable,
        _ => LearningSignal::Unclassifiable,
    }
}

/// Classify a single `WsProbe` failure reason (used by deeper per-probe paths)
/// into a [`LearningSignal`]. `ConnectFailed`/`ConnectTimeout` are transport-
/// level (never reached TLS) → `HostDown`. Everything after a successful TCP
/// connect is strategy-attributable EXCEPT origin-unavailable HTTP statuses
/// (5xx — the worker is down behind a live TCP port/edge, which is not the
/// desync strategy's fault). `None` (a passing probe) → `Success`.
pub fn classify_probe_failure(reason: Option<crate::health::WsFailureReason>) -> LearningSignal {
    match reason {
        None => LearningSignal::Success,
        Some(crate::health::WsFailureReason::ConnectFailed)
        | Some(crate::health::WsFailureReason::ConnectTimeout) => LearningSignal::HostDown,
        Some(crate::health::WsFailureReason::HttpStatus(code)) => http_status_learning_signal(code),
        Some(
            crate::health::WsFailureReason::TlsAlert
            | crate::health::WsFailureReason::TlsTimeout
            | crate::health::WsFailureReason::WriteFailed
            | crate::health::WsFailureReason::ResponseIncomplete
            | crate::health::WsFailureReason::DeadRoute,
        ) => LearningSignal::StrategyFailure,
    }
}

/// Classify a deep-discovery cycle's aggregate outcome into a [`LearningSignal`]
/// from the pipeline's stage counters and phase-2 failure histogram. This is
/// the deep-path counterpart to [`classify_endpoint_outcome`] (light sweep): it
/// splits host-unreachable, worker-unavailable, and strategy-attributable
/// failure so a down/offline worker never demotes a good strategy.
///
/// | phase1_pass | phase2_pass | verified | signal | meaning |
/// |---|---|---|---|---|
/// | any | any | non-empty | `Success` | strategy worked; promote + clear host-down |
/// | 0 | — | empty | `HostDown` | no TCP handshake succeeded → host unreachable, hold ladder |
/// | >0 | 0 | empty, histogram origin-5xx-dominant | `Unclassifiable` | worker unavailable behind live TCP (502/503/…), hold ladder |
/// | >0 | 0 | empty, else | `StrategyFailure` | TCP connected, WS failed → demote strategy used |
/// | >0 | >0 | empty | `Unclassifiable` | WS worked (strategy fine); E2E/score gate filtered → no learning |
pub fn classify_discovery_outcome(
    phase1_pass: u32,
    phase2_pass: u32,
    verified_nonempty: bool,
    ws_failure_histogram: Option<&std::collections::HashMap<crate::health::WsFailureReason, u32>>,
) -> LearningSignal {
    if verified_nonempty {
        return LearningSignal::Success;
    }
    if phase1_pass == 0 {
        return LearningSignal::HostDown;
    }
    if phase2_pass == 0 {
        // TCP connected but every phase-2 probe failed. Distinguish DPI /
        // strategy-attributable failure (TLS alert/reset dominant) from an
        // unavailable worker behind a live TCP port (origin 5xx dominant).
        // Per DeepSeek's gate: only the former demotes; the latter holds.
        // Parity: uses the same `histogram_attribution` split as the light
        // sweep (`classify_light_sweep`) so both paths cannot disagree.
        if let Some(h) = ws_failure_histogram {
            let (dpi, origin) = histogram_attribution(h);
            if origin > 0 && origin >= dpi {
                return LearningSignal::Unclassifiable;
            }
        }
        return LearningSignal::StrategyFailure;
    }
    LearningSignal::Unclassifiable
}

/// Decide whether a [`LearningSignal`] should feed the strategy learner at all.
/// `Success` and `StrategyFailure` are attributable; `HostDown` and
/// `Unclassifiable` must NOT demote (no signal is safer than a wrong demotion).
pub fn should_learn(sig: LearningSignal) -> bool {
    matches!(
        sig,
        LearningSignal::Success | LearningSignal::StrategyFailure
    )
}

/// Apply a classified learning signal to the per-worker record. This is the
/// single choke point the daemon and GUI both call through the persisted path:
/// - `Success` → record_worker_desync_success (promote + clear host-down).
/// - `StrategyFailure` → record_worker_desync_failure (demote, advance ladder).
/// - `HostDown` → record_worker_host_down (hold ladder, no demotion).
/// - `Unclassifiable` → no-op (no learning).
pub fn apply_learning_signal(
    cfg: &mut crate::store::profiles::ProfileConfig,
    worker_host: &str,
    strategy: crate::desync::DesyncStrategy,
    sig: LearningSignal,
    now_unix: u64,
) -> bool {
    let before = cfg.worker_secrets.clone();
    match sig {
        LearningSignal::Success => record_worker_desync_success(cfg, worker_host, strategy),
        LearningSignal::StrategyFailure => record_worker_desync_failure(cfg, worker_host, strategy),
        LearningSignal::HostDown => {
            record_worker_host_down(cfg, worker_host, now_unix);
        }
        LearningSignal::Unclassifiable => {}
    }
    cfg.worker_secrets != before
}

/// Decide the anti-DPI desync strategy for a discovery scan cycle against
/// `worker_host`. Reuses the per-worker learned store (the single
/// recorded-effective source of truth): a recorded effective strategy wins; a
/// failed-set advances the ladder; no record falls back to the ladder start.
/// This closes the discovery-path learning loop — the probe path previously
/// used only the flat global `active_config().strategy` and never learned.
pub fn strategy_for_discovery(
    cfg: &crate::store::profiles::ProfileConfig,
    worker_host: &str,
) -> crate::desync::DesyncStrategy {
    strategy_for_worker(cfg, worker_host, 0)
}

/// Record a discovery cycle's aggregate WS outcome into the per-worker desync
/// store. Success promotes `strategy` to effective (clears the failed-set);
/// failure pushes it to the failed-set so the ladder demotes. Returns `true`
/// if `cfg` changed (caller persists).
pub fn learn_from_discovery(
    cfg: &mut crate::store::profiles::ProfileConfig,
    worker_host: &str,
    strategy: crate::desync::DesyncStrategy,
    had_ws_success: bool,
) -> bool {
    let before = cfg.worker_secrets.clone();
    if had_ws_success {
        record_worker_desync_success(cfg, worker_host, strategy);
    } else {
        record_worker_desync_failure(cfg, worker_host, strategy);
    }
    cfg.worker_secrets != before
}

/// Cross-process exclusive lock on a profile's desync-learning record file.
/// The daemon and GUI are separate processes and both persist per-worker
/// desync records; a static in-process mutex alone cannot prevent a lost
/// update across that boundary. `flock` (advisory, on the same host) closes
/// the race. Returns the locked file handle, which must be kept alive (and
/// dropped) for the duration of the critical section.
///
/// Assumption: the profile store lives on a local filesystem (the default
/// `~/.dastyab`). Network/remote FS is out of scope.
fn lock_profile_desync(profile_id: &str) -> std::io::Result<std::fs::File> {
    use std::io::Write;
    let dir = crate::store::profiles::profile_dir(profile_id);
    std::fs::create_dir_all(&dir).map_err(|e| {
        std::io::Error::other(format!("cannot create profile dir {}: {e}", dir.display()))
    })?;
    let path = dir.join(".desync-learn.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)?;
    // Best-effort write a pid marker for debuggability (ignored on failure).
    let _ = writeln!(&file, "{}", std::process::id());
    let rc = unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&file), libc::LOCK_EX) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(file)
}

/// Serializes the read-modify-write on a worker's desync record across
/// concurrent monitor paths (the daemon's deep discovery and a GUI-triggered
/// light sweep can run in separate processes). Takes a cross-process exclusive
/// `flock` on a per-profile lock file, then applies `learn_from_discovery` and
/// persists only if the record changed. The in-process static mutex remains
/// as the inner guard so threads within one process never contend on flock.
pub fn learn_from_discovery_persisted(
    profile_id: &str,
    worker_host: &str,
    strategy: crate::desync::DesyncStrategy,
    had_ws_success: bool,
) -> bool {
    // Preserve the legacy boolean contract: a success promotes, a failure
    // demotes (strategy-attributable). Deep discovery keeps calling this path
    // unchanged per DeepSeek A35 ("preserve deep-discovery behavior exactly").
    let sig = if had_ws_success {
        LearningSignal::Success
    } else {
        LearningSignal::StrategyFailure
    };
    learn_from_discovery_persisted_signal(profile_id, worker_host, strategy, sig, store_now_bump())
}

/// Serialize the read-modify-write on a worker's desync record across
/// concurrent monitor paths (daemon deep discovery + GUI light sweep, possibly
/// separate processes). This is the signal-aware variant: the caller classifies
/// the probe outcome into [`LearningSignal`] before the lock, and only
/// `Success`/`StrategyFailure` actually mutate the ladder (host-up / unclassifiable
/// are held or ignored). Takes a cross-process exclusive `flock` on a per-profile
/// lock file, then persists only if the record changed.
pub fn learn_from_discovery_persisted_signal(
    profile_id: &str,
    worker_host: &str,
    strategy: crate::desync::DesyncStrategy,
    sig: LearningSignal,
    now_unix: u64,
) -> bool {
    let _inner = DESYNC_LEARN_LOCK.lock().unwrap();
    // Cross-process: hold the flock across load→mutate→persist. If flock is
    // unavailable, fall back to the in-process-only path (best-effort).
    let _file = lock_profile_desync(profile_id).ok();
    let mut p = crate::store::profiles::load_profile(profile_id);
    let changed = apply_learning_signal(&mut p.config, worker_host, strategy, sig, now_unix);
    if changed {
        let _ = crate::store::profiles::save_profile(&p);
    }
    changed
}

/// Simple now-in-seconds for the learning path (avoids threading a clock
/// through every caller). Uses the same epoch base as the rest of the store.
fn store_now_bump() -> u64 {
    crate::store::profiles::now_ts() as u64
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::profiles::ProfileConfig;

    fn cfg() -> ProfileConfig {
        ProfileConfig::default()
    }

    fn seed_worker(c: &mut ProfileConfig, url: &str, age_rot: u64) {
        let ws = WorkerSecret {
            worker_url: url.into(),
            secret: "current-secret".into(),
            rotated_unix: age_rot,
            version: 1,
            pending_secret: None,
            pending_since_unix: 0,
            desync_strategy: None,
            failed_strategies: Vec::new(),
            host_down: false,
            host_down_since_unix: 0,
        };
        c.worker_secrets.insert(url.into(), ws);
    }

    #[test]
    fn resolve_worker_secret_falls_back_to_shared_when_absent() {
        let c = cfg();
        assert_eq!(resolve_worker_secret(&c, "http://w", "shared"), "shared");
    }

    #[test]
    fn resolve_worker_secret_returns_per_worker_when_present() {
        let mut c = cfg();
        seed_worker(&mut c, "http://w", 0);
        assert_eq!(
            resolve_worker_secret(&c, "http://w", "shared"),
            "current-secret"
        );
    }

    #[test]
    fn assign_new_secret_isolates_to_target_worker() {
        let mut c = cfg();
        assign_new_secret(&mut c, "http://w", 1000).unwrap();
        assert!(c.worker_secrets.contains_key("http://w"));
        // Other worker untouched.
        assert!(!c.worker_secrets.contains_key("http://other"));
        let ws = &c.worker_secrets["http://w"];
        assert_eq!(ws.version, 1);
        assert!(ws.pending_secret.is_none());
        assert_eq!(ws.rotated_unix, 1000);
        assert_eq!(ws.secret.len(), SECRET_HEX_LEN);
    }

    #[test]
    fn rotation_due_after_max_age() {
        let mut c = cfg();
        seed_worker(&mut c, "http://w", 1000);
        assert!(!rotation_due(&c, "http://w", 1000 + 10, 100));
        assert!(rotation_due(&c, "http://w", 1000 + 200, 100));
    }

    #[test]
    fn rotation_eligible_false_when_net_down() {
        let mut c = cfg();
        seed_worker(&mut c, "http://w", 1000);
        assert!(!rotation_eligible(&c, "http://w", 1000 + 200, 100, false));
        assert!(rotation_eligible(&c, "http://w", 1000 + 200, 100, true));
    }

    #[test]
    fn rotation_eligible_false_when_pending_fresh() {
        let mut c = cfg();
        seed_worker(&mut c, "http://w", 1000);
        c.worker_secrets.get_mut("http://w").unwrap().pending_secret = Some("pending".into());
        c.worker_secrets
            .get_mut("http://w")
            .unwrap()
            .pending_since_unix = 2000;
        // now = 2100 → pending is 100s old (< 1h) → blocked.
        assert!(!rotation_eligible(&c, "http://w", 2100, 100, true));
        // now = 2000 + 2h → pending stale → eligible again.
        assert!(rotation_eligible(&c, "http://w", 2000 + 7200, 100, true));
    }

    #[test]
    fn promote_pending_promotes_and_bumps_version() {
        let mut c = cfg();
        seed_worker(&mut c, "http://w", 1000);
        c.worker_secrets.get_mut("http://w").unwrap().pending_secret = Some("pending-2".into());
        c.worker_secrets
            .get_mut("http://w")
            .unwrap()
            .pending_since_unix = 2000;
        let v = promote_pending(&mut c, "http://w", 3000).unwrap();
        assert_eq!(v, 2);
        let ws = &c.worker_secrets["http://w"];
        assert_eq!(ws.secret, "pending-2");
        assert!(ws.pending_secret.is_none());
        assert_eq!(ws.rotated_unix, 3000);
    }

    #[test]
    fn generate_secret_is_32_hex() {
        let a = generate_secret();
        let b = generate_secret();
        assert_eq!(a.len(), SECRET_HEX_LEN);
        assert_ne!(a, b);
        assert!(a.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn assign_new_secret_two_phase_keeps_current_until_pending() {
        // Rotation on an existing worker must stage a pending secret without
        // touching the current one (so traffic keeps working until verified).
        let mut c = cfg();
        seed_worker(&mut c, "http://w", 1000);
        assign_new_secret(&mut c, "http://w", 2000).unwrap();
        let ws = &c.worker_secrets["http://w"];
        assert_eq!(ws.secret, "current-secret");
        assert!(ws.pending_secret.is_some());
        assert_eq!(ws.pending_since_unix, 2000);
        // resolve still returns the current, never pending.
        assert_eq!(
            resolve_worker_secret(&c, "http://w", "shared"),
            "current-secret"
        );
    }

    #[test]
    fn clear_pending_restores_current_active() {
        let mut c = cfg();
        seed_worker(&mut c, "http://w", 1000);
        c.worker_secrets.get_mut("http://w").unwrap().pending_secret = Some("pending".into());
        clear_pending(&mut c, "http://w");
        let ws = &c.worker_secrets["http://w"];
        assert!(ws.pending_secret.is_none());
        assert_eq!(ws.secret, "current-secret");
    }

    #[test]
    fn promote_pending_errors_without_pending() {
        let mut c = cfg();
        seed_worker(&mut c, "http://w", 1000);
        assert!(promote_pending(&mut c, "http://w", 3000).is_err());
    }

    #[test]
    fn strategy_for_worker_falls_back_to_ladder_when_unset() {
        let c = cfg();
        // No worker secrets at all → ladder starts at SplitClientHello.
        assert_eq!(
            strategy_for_worker(&c, "http://w", 0),
            crate::desync::DesyncStrategy::SplitClientHello
        );
        assert_eq!(
            strategy_for_worker(&c, "http://w", 1),
            crate::desync::DesyncStrategy::SplitTwo
        );
        assert_eq!(
            strategy_for_worker(&c, "http://w", 2),
            crate::desync::DesyncStrategy::SplitAndDecoy
        );
        assert_eq!(
            strategy_for_worker(&c, "http://w", 3),
            crate::desync::DesyncStrategy::None
        );
    }

    #[test]
    fn strategy_for_worker_uses_learned_effective() {
        let mut c = cfg();
        record_worker_desync_success(&mut c, "http://w", crate::desync::DesyncStrategy::SplitTwo);
        assert_eq!(
            strategy_for_worker(&c, "http://w", 0),
            crate::desync::DesyncStrategy::SplitTwo
        );
        // High attempt still prefers the effective strategy.
        assert_eq!(
            strategy_for_worker(&c, "http://w", 7),
            crate::desync::DesyncStrategy::SplitTwo
        );
    }

    #[test]
    fn worker_learn_records_success_and_failure() {
        let mut c = cfg();
        record_worker_desync_failure(
            &mut c,
            "http://w",
            crate::desync::DesyncStrategy::SplitClientHello,
        );
        record_worker_desync_failure(&mut c, "http://w", crate::desync::DesyncStrategy::SplitTwo);
        let ws = &c.worker_secrets["http://w"];
        assert_eq!(ws.failed_strategies.len(), 2);
        assert!(ws.desync_strategy.is_none());

        record_worker_desync_success(
            &mut c,
            "http://w",
            crate::desync::DesyncStrategy::SplitAndDecoy,
        );
        let ws = &c.worker_secrets["http://w"];
        assert_eq!(
            ws.desync_strategy,
            Some(crate::desync::DesyncStrategy::SplitAndDecoy)
        );
        // Success retains other failed strategies (only the successful one is
        // removed): SplitClientHello + SplitTwo remain.
        assert_eq!(ws.failed_strategies.len(), 2);
    }

    #[test]
    fn worker_learn_skips_duplicate_failures() {
        let mut c = cfg();
        for _ in 0..3 {
            record_worker_desync_failure(
                &mut c,
                "http://w",
                crate::desync::DesyncStrategy::SplitClientHello,
            );
        }
        let ws = &c.worker_secrets["http://w"];
        assert_eq!(ws.failed_strategies.len(), 1);
    }

    #[test]
    fn strategy_for_discovery_falls_back_to_ladder_when_unlearned() {
        // No record → the ladder's first un-failed entry wins.
        let c = cfg();
        assert_eq!(
            strategy_for_discovery(&c, "host.workers.dev"),
            crate::desync::DesyncStrategy::SplitClientHello
        );
    }

    #[test]
    fn learn_from_discovery_success_promotes_effective_and_removes_only_that_failure() {
        let mut c = cfg();
        // Seed a failed strategy so the "remove only the successful one" branch
        // is exercised; a second, unrelated failure must be retained.
        record_worker_desync_failure(
            &mut c,
            "host.workers.dev",
            crate::desync::DesyncStrategy::SplitClientHello,
        );
        record_worker_desync_failure(
            &mut c,
            "host.workers.dev",
            crate::desync::DesyncStrategy::SplitAndDecoy,
        );
        let changed = learn_from_discovery(
            &mut c,
            "host.workers.dev",
            crate::desync::DesyncStrategy::SplitTwo,
            true,
        );
        assert!(changed, "a fresh success must mutate the store");
        let ws = &c.worker_secrets["host.workers.dev"];
        assert_eq!(
            ws.desync_strategy,
            Some(crate::desync::DesyncStrategy::SplitTwo)
        );
        // SplitClientHello and SplitAndDecoy are unrelated to SplitTwo and stay.
        assert_eq!(ws.failed_strategies.len(), 2);
        // The next discovery selects the learned effective strategy.
        assert_eq!(
            strategy_for_discovery(&c, "host.workers.dev"),
            crate::desync::DesyncStrategy::SplitTwo
        );
    }

    #[test]
    fn learn_from_discovery_failure_demotes_ladder() {
        let mut c = cfg();
        let changed = learn_from_discovery(
            &mut c,
            "host.workers.dev",
            crate::desync::DesyncStrategy::SplitClientHello,
            false,
        );
        assert!(changed);
        // The failed strategy is skipped → next selection advances the ladder.
        assert_eq!(
            strategy_for_discovery(&c, "host.workers.dev"),
            crate::desync::DesyncStrategy::SplitTwo
        );
        // No effective strategy is recorded on failure.
        assert!(c.worker_secrets["host.workers.dev"]
            .desync_strategy
            .is_none());
    }

    #[test]
    fn learn_from_discovery_two_endpoints_do_not_interfere() {
        let mut c = cfg();
        learn_from_discovery(
            &mut c,
            "a.workers.dev",
            crate::desync::DesyncStrategy::SplitTwo,
            true,
        );
        learn_from_discovery(
            &mut c,
            "b.workers.dev",
            crate::desync::DesyncStrategy::SplitClientHello,
            false,
        );
        // a learned SplitTwo effective; b demoted past SplitClientHello.
        assert_eq!(
            strategy_for_discovery(&c, "a.workers.dev"),
            crate::desync::DesyncStrategy::SplitTwo
        );
        assert_eq!(
            strategy_for_discovery(&c, "b.workers.dev"),
            crate::desync::DesyncStrategy::SplitTwo
        );
        // No cross-endpoint leakage: b's failure did not touch a's records.
        let a = &c.worker_secrets["a.workers.dev"];
        assert_eq!(
            a.desync_strategy,
            Some(crate::desync::DesyncStrategy::SplitTwo)
        );
        assert!(a.failed_strategies.is_empty());
    }

    #[test]
    fn learn_from_discovery_noop_when_outcome_already_recorded() {
        let mut c = cfg();
        learn_from_discovery(
            &mut c,
            "host.workers.dev",
            crate::desync::DesyncStrategy::SplitTwo,
            true,
        );
        // Same success again → store unchanged → returns false.
        let changed = learn_from_discovery(
            &mut c,
            "host.workers.dev",
            crate::desync::DesyncStrategy::SplitTwo,
            true,
        );
        assert!(!changed, "idempotent success must not mutate the store");
    }

    /// Acceptance (c): light-phase and deep-discovery outcomes for the same
    /// worker finish through the shared serialized persist path must compose
    /// order-independently with no lost update. We exercise the real persisted
    /// path (`learn_from_discovery_persisted`) — the one the GUI and daemon
    /// both call across the process boundary — against a scratch mem-dir.
    #[test]
    fn learn_from_discovery_persisted_composes_order_independently() {
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(dir.path().join(".dastyab"));
        let id = crate::store::profiles::create_profile("test", "c").unwrap();
        let host = "host.workers.dev";

        // Light = success (promote SplitClientHello), deep = failure (demote
        // SplitTwo). Apply in both orders; the final record must be identical.
        let apply_light_then_deep = |id: &str, host: &str| {
            // Start from a clean profile.
            let mut p = crate::store::profiles::load_profile(id);
            p.config.worker_secrets.clear();
            crate::store::profiles::save_profile(&p).unwrap();
            crate::worker_tunnel::secret::learn_from_discovery_persisted(
                id,
                host,
                crate::desync::DesyncStrategy::SplitClientHello,
                true,
            );
            crate::worker_tunnel::secret::learn_from_discovery_persisted(
                id,
                host,
                crate::desync::DesyncStrategy::SplitTwo,
                false,
            );
            let p = crate::store::profiles::load_profile(id);
            p.config.worker_secrets.get(host).cloned().unwrap()
        };
        let apply_deep_then_light = |id: &str, host: &str| {
            let mut p = crate::store::profiles::load_profile(id);
            p.config.worker_secrets.clear();
            crate::store::profiles::save_profile(&p).unwrap();
            crate::worker_tunnel::secret::learn_from_discovery_persisted(
                id,
                host,
                crate::desync::DesyncStrategy::SplitTwo,
                false,
            );
            crate::worker_tunnel::secret::learn_from_discovery_persisted(
                id,
                host,
                crate::desync::DesyncStrategy::SplitClientHello,
                true,
            );
            let p = crate::store::profiles::load_profile(id);
            p.config.worker_secrets.get(host).cloned().unwrap()
        };

        let a = apply_light_then_deep(&id, host);
        let b = apply_deep_then_light(&id, host);
        assert_eq!(a, b, "composed record must be order-independent");
        // The final record reflects the last-writer (success) state: effective
        // SplitClientHello. The earlier failure is retained in the failed-set
        // (success on one shape does not invalidate the observation that a
        // different shape failed) — that retained-failure semantics is what
        // makes the two orders compose to an identical record.
        assert_eq!(
            a.desync_strategy,
            Some(crate::desync::DesyncStrategy::SplitClientHello)
        );
        assert_eq!(
            a.failed_strategies,
            vec![crate::desync::DesyncStrategy::SplitTwo]
        );
        // And a subsequent discovery selects the learned effective.
        let p = crate::store::profiles::load_profile(&id);
        assert_eq!(
            strategy_for_discovery(&p.config, host),
            crate::desync::DesyncStrategy::SplitClientHello
        );
    }

    // ── DeepSeek A98–A105: transport-layer signal classification ──────────
    // Acceptance: (a) host-unreachable (connect refused) does not demote and
    // does not pollute the strategy record; (b) strategy-level WS failure still
    // demotes; (c) host-down → host-recovered resumes at the same strategy, not
    // a demoted one; (d) unclassifiable error ⇒ no learning.

    #[test]
    fn classify_endpoint_outcome_table() {
        use crate::health::EndpointFailureStage as S;
        use LearningSignal::*;
        // Success / no failure stage.
        assert_eq!(classify_endpoint_outcome(None), Success);
        // TCP transport-level → host-down.
        assert_eq!(
            classify_endpoint_outcome(Some(S::TcpTimeoutAllPorts)),
            HostDown
        );
        // Clear TLS-layer DPI signature → strategy-attributable.
        assert_eq!(
            classify_endpoint_outcome(Some(S::TlsResetAllPorts)),
            StrategyFailure
        );
        // Ambiguous without an HTTP status histogram (could be DPI/WAF OR an
        // origin-unavailable worker behind a live TCP port) → no learning.
        assert_eq!(
            classify_endpoint_outcome(Some(S::WsUpgradeAllPorts)),
            Unclassifiable
        );
        assert_eq!(
            classify_endpoint_outcome(Some(S::WorkerBytesAllPorts)),
            Unclassifiable
        );
        // Ambiguous / unknown → unclassifiable.
        assert_eq!(
            classify_endpoint_outcome(Some(S::BudgetExceeded)),
            Unclassifiable
        );
    }

    /// DeepSeek's light-path residual (A69–A71): a light sweep whose aggregate
    /// is WorkerBytes/WsUpgrade — which carries NO HTTP status histogram — must
    /// HOLD (not demote), because it could be an origin-unavailable worker
    /// behind a live TCP port, indistinguishable from a DPI/WAF reject at this
    /// aggregation level. Both are Unclassifiable ⇒ no learning.
    #[test]
    fn light_path_ambiguous_aggregates_hold_not_demote() {
        use crate::health::EndpointFailureStage as S;
        assert_eq!(
            classify_endpoint_outcome(Some(S::WorkerBytesAllPorts)),
            LearningSignal::Unclassifiable
        );
        assert_eq!(
            classify_endpoint_outcome(Some(S::WsUpgradeAllPorts)),
            LearningSignal::Unclassifiable
        );
        // Neither feeds the learner.
        assert!(!should_learn(classify_endpoint_outcome(Some(
            S::WorkerBytesAllPorts
        ))));
        assert!(!should_learn(classify_endpoint_outcome(Some(
            S::WsUpgradeAllPorts
        ))));
        // The clear TLS-layer DPI signature still demotes.
        assert_eq!(
            classify_endpoint_outcome(Some(S::TlsResetAllPorts)),
            LearningSignal::StrategyFailure
        );
        assert!(should_learn(classify_endpoint_outcome(Some(
            S::TlsResetAllPorts
        ))));
    }

    #[test]
    fn classify_probe_failure_table() {
        use crate::health::WsFailureReason as R;
        use LearningSignal::*;
        assert_eq!(classify_probe_failure(None), Success);
        assert_eq!(classify_probe_failure(Some(R::ConnectFailed)), HostDown);
        assert_eq!(classify_probe_failure(Some(R::ConnectTimeout)), HostDown);
        assert_eq!(classify_probe_failure(Some(R::TlsAlert)), StrategyFailure);
        assert_eq!(classify_probe_failure(Some(R::TlsTimeout)), StrategyFailure);
        assert_eq!(
            classify_probe_failure(Some(R::WriteFailed)),
            StrategyFailure
        );
        assert_eq!(
            classify_probe_failure(Some(R::ResponseIncomplete)),
            StrategyFailure
        );
        assert_eq!(
            classify_probe_failure(Some(R::HttpStatus(403))),
            StrategyFailure
        );
        assert_eq!(classify_probe_failure(Some(R::DeadRoute)), StrategyFailure);
        // Origin-unavailable 5xx from an upstream proxy / edge (worker down
        // behind live TCP) must NOT demote — it is not the desync strategy's
        // fault (DeepSeek's live-case gate).
        assert_eq!(
            classify_probe_failure(Some(R::HttpStatus(502))),
            Unclassifiable
        );
        assert_eq!(
            classify_probe_failure(Some(R::HttpStatus(503))),
            Unclassifiable
        );
        assert_eq!(
            classify_probe_failure(Some(R::HttpStatus(504))),
            Unclassifiable
        );
        // Non-strategy 4xx must NOT demote: 404 (ambiguous dead-route vs
        // config), 408 (timeout), 421 (misdirected), 429 (rate limit).
        assert_eq!(
            classify_probe_failure(Some(R::HttpStatus(404))),
            Unclassifiable
        );
        assert_eq!(
            classify_probe_failure(Some(R::HttpStatus(408))),
            Unclassifiable
        );
        assert_eq!(
            classify_probe_failure(Some(R::HttpStatus(421))),
            Unclassifiable
        );
        assert_eq!(
            classify_probe_failure(Some(R::HttpStatus(429))),
            Unclassifiable
        );
        // WAF/DPI 4xx stay strategy-attributable.
        assert_eq!(
            classify_probe_failure(Some(R::HttpStatus(401))),
            StrategyFailure
        );
        assert!(http_status_is_origin_unavailable(502));
        assert!(http_status_is_origin_unavailable(503));
        assert!(http_status_is_origin_unavailable(520));
        assert!(http_status_is_origin_unavailable(530));
        assert!(!http_status_is_origin_unavailable(403));
        assert!(!http_status_is_origin_unavailable(404));
        assert!(!http_status_is_origin_unavailable(421));
        // Only Success/StrategyFailure feed the learner.
        assert!(should_learn(Success));
        assert!(should_learn(StrategyFailure));
        assert!(!should_learn(HostDown));
        assert!(!should_learn(Unclassifiable));
    }

    /// Deep-discovery classification table (DeepSeek ranked #1 discriminator):
    /// phase-1 TCP success proves the host is reachable, so the signal split is
    /// host-unreachable (zero phase-1) vs strategy-attributable (phase-2 fail),
    /// further split by origin-5xx dominance (worker down behind live TCP).
    #[test]
    fn classify_discovery_outcome_table() {
        use std::collections::HashMap;
        use LearningSignal::*;
        fn hist(
            pairs: &[(crate::health::WsFailureReason, u32)],
        ) -> HashMap<crate::health::WsFailureReason, u32> {
            pairs.iter().cloned().collect()
        }
        use crate::health::WsFailureReason as R;
        // Verified → success (promote + clear host-down).
        assert_eq!(classify_discovery_outcome(0, 0, true, None), Success);
        assert_eq!(classify_discovery_outcome(100, 50, true, None), Success);
        // Zero phase-1 → never connected → host-down (hold ladder, no demote).
        assert_eq!(classify_discovery_outcome(0, 0, false, None), HostDown);
        // Phase-1 connected, phase-2 failed with DPI/strategy-dominant reasons
        // → strategy-attributable → demote.
        assert_eq!(
            classify_discovery_outcome(10, 0, false, Some(&hist(&[(R::TlsAlert, 8)]))),
            StrategyFailure
        );
        // Phase-1 connected, phase-2 failed with origin-5xx-dominant reasons
        // (worker unavailable behind live TCP/edge) → hold, do not demote.
        assert_eq!(
            classify_discovery_outcome(10, 0, false, Some(&hist(&[(R::HttpStatus(502), 8)]))),
            Unclassifiable
        );
        assert_eq!(
            classify_discovery_outcome(
                10,
                0,
                false,
                Some(&hist(&[(R::HttpStatus(503), 5), (R::HttpStatus(520), 3)]))
            ),
            Unclassifiable
        );
        // Mixed: DPI dominant over 5xx → strategy failure (demote).
        assert_eq!(
            classify_discovery_outcome(
                10,
                0,
                false,
                Some(&hist(&[(R::TlsAlert, 8), (R::HttpStatus(502), 2)]))
            ),
            StrategyFailure
        );
        // Phase-2 passed but no verified → E2E/score gate filtered, not a
        // strategy failure → unclassifiable (no learning).
        assert_eq!(
            classify_discovery_outcome(10, 5, false, None),
            Unclassifiable
        );
        assert_eq!(
            classify_discovery_outcome(1, 1, false, None),
            Unclassifiable
        );
    }

    /// Option c light-path status histogram — acceptance tests reflecting the
    /// architect's brief: the light sweep now carries an HTTP status histogram
    /// so it can classify DPI-dominant vs origin-5xx-dominant failures, matching
    /// deep's verdict, including the healthy-but-muted case and the dead-fraction
    /// gate (residual-rule-gap fix).
    #[test]
    fn light_sweep_acceptance_dpi_dominant_demotes_even_when_alive() {
        use crate::health::WsFailureReason as R;
        use std::collections::HashMap;
        use LearningSignal::*;
        let hist = |pairs: &[(R, u32)]| -> HashMap<R, u32> { pairs.iter().cloned().collect() };
        // (a) Healthy-but-muted: dead fraction is HIGH (1/7 alive = 6/7 dead >
        // 1/3 floor) AND failures are DPI-dominant → demote. Previously alive>0
        // forced Success and masked a muted worker.
        assert_eq!(
            classify_light_sweep(
                1,
                7,
                Some(&hist(&[(R::TlsAlert, 6), (R::HttpStatus(502), 1)]))
            ),
            StrategyFailure
        );
        assert_eq!(
            classify_light_sweep(0, 5, Some(&hist(&[(R::HttpStatus(403), 5)]))),
            StrategyFailure
        );
    }

    #[test]
    fn light_sweep_acceptance_origin_dominant_holds_when_alive() {
        use crate::health::WsFailureReason as R;
        use std::collections::HashMap;
        use LearningSignal::*;
        let hist = |pairs: &[(R, u32)]| -> HashMap<R, u32> { pairs.iter().cloned().collect() };
        // (b) High dead fraction but origin-5xx-dominant → hold (do not demote
        // on a worker outage).
        assert_eq!(
            classify_light_sweep(
                1,
                7,
                Some(&hist(&[(R::HttpStatus(502), 6), (R::TlsAlert, 1)]))
            ),
            Unclassifiable
        );
        // high dead fraction but mixed/inconclusive → hold.
        assert_eq!(
            classify_light_sweep(
                1,
                7,
                Some(&hist(&[(R::HttpStatus(502), 3), (R::TlsAlert, 3)]))
            ),
            Unclassifiable
        );
    }

    #[test]
    fn light_sweep_acceptance_mostly_alive_dpi_failure_holds() {
        // (e) The residual false-demotion guard: dead fraction ≤ floor (6/7
        // alive = 1/7 dead ≤ 1/3) → hold regardless of failure composition.
        // A single DPI failure among mostly-alive endpoints must NOT demote a
        // strategy that is working on 6 of 7 paths — the test that would have
        // caught the original (a) gap.
        use crate::health::WsFailureReason as R;
        use std::collections::HashMap;
        use LearningSignal::*;
        let hist = |pairs: &[(R, u32)]| -> HashMap<R, u32> { pairs.iter().cloned().collect() };
        assert_eq!(
            classify_light_sweep(6, 7, Some(&hist(&[(R::TlsAlert, 1)]))),
            Unclassifiable
        );
        // exactly at the floor (dead = 1/3) → hold too.
        assert_eq!(
            classify_light_sweep(4, 6, Some(&hist(&[(R::TlsAlert, 2)]))),
            Unclassifiable
        );
    }

    #[test]
    fn light_and_deep_share_classification_for_same_histogram() {
        // (c) Parity: light and deep must return the same verdict for the same
        // synthetic histogram (zero-alive regime). Both now route through
        // `histogram_attribution`.
        use crate::health::WsFailureReason as R;
        use std::collections::HashMap;
        use LearningSignal::*;
        let hist = |pairs: &[(R, u32)]| -> HashMap<R, u32> { pairs.iter().cloned().collect() };
        // origin-dominant → both hold
        let origin_dom = hist(&[(R::HttpStatus(502), 7), (R::TlsAlert, 1)]);
        assert_eq!(
            classify_light_sweep(0, 7, Some(&origin_dom)),
            Unclassifiable
        );
        assert_eq!(
            classify_discovery_outcome(10, 0, false, Some(&origin_dom)),
            Unclassifiable
        );
        // DPI-dominant → both demote
        let dpi_dom = hist(&[(R::TlsAlert, 7), (R::HttpStatus(502), 1)]);
        assert_eq!(classify_light_sweep(0, 7, Some(&dpi_dom)), StrategyFailure);
        assert_eq!(
            classify_discovery_outcome(10, 0, false, Some(&dpi_dom)),
            StrategyFailure
        );
        // empty histogram (aggressive) → light holds (no histogram, no learn)
        assert_eq!(classify_light_sweep(0, 5, Some(&hist(&[]))), Unclassifiable);
        assert_eq!(classify_light_sweep(1, 5, None), Unclassifiable);
    }

    #[test]
    fn light_sweep_all_alive_is_success_and_no_histogram_regression() {
        // all alive → Success (nothing to learn); no-histogram fallback keeps
        // legacy behavior (Success when all alive, Unclassifiable when not).
        use LearningSignal::*;
        assert_eq!(classify_light_sweep(5, 5, None), Success);
        assert_eq!(
            classify_light_sweep(5, 5, Some(&std::collections::HashMap::new())),
            Success
        );
        assert_eq!(classify_light_sweep(2, 5, None), Unclassifiable);
        assert_eq!(classify_light_sweep(0, 0, None), Unclassifiable);
    }

    /// (a) deep-discovery host-unreachable (zero phase-1 TCP success) does not
    /// demote and does not pollute the strategy record: the effective strategy
    /// is held and the failed-set is untouched, while host_down records.
    #[test]
    fn discovery_host_down_holds_strategy_and_does_not_demote() {
        let mut c = cfg();
        record_worker_desync_success(
            &mut c,
            "http://w",
            crate::desync::DesyncStrategy::SplitClientHello,
        );
        let before_failed = c.worker_secrets["http://w"].failed_strategies.clone();
        let before_effective = c.worker_secrets["http://w"].desync_strategy;

        let changed = apply_learning_signal(
            &mut c,
            "http://w",
            crate::desync::DesyncStrategy::SplitClientHello,
            classify_discovery_outcome(0, 0, false, None),
            1_700_000_000,
        );
        assert!(changed);
        let ws = &c.worker_secrets["http://w"];
        assert!(ws.host_down);
        assert_eq!(ws.host_down_since_unix, 1_700_000_000);
        // Not polluted: effective unchanged, failed-set unchanged.
        assert_eq!(ws.desync_strategy, before_effective);
        assert_eq!(ws.failed_strategies, before_failed);
        // Held strategy: select keeps the effective, does NOT walk the ladder.
        assert_eq!(
            strategy_for_worker(&c, "http://w", 0),
            crate::desync::DesyncStrategy::SplitClientHello
        );
    }

    /// (b) deep-discovery strategy-level WS failure (phase-1 connected, phase-2
    /// failed) still demotes — regression guard on the promote/demote behavior.
    #[test]
    fn discovery_strategy_failure_still_demotes() {
        let mut c = cfg();
        record_worker_desync_success(
            &mut c,
            "http://w",
            crate::desync::DesyncStrategy::SplitClientHello,
        );
        let changed = apply_learning_signal(
            &mut c,
            "http://w",
            crate::desync::DesyncStrategy::SplitClientHello,
            classify_discovery_outcome(10, 0, false, None),
            1_700_000_100,
        );
        assert!(changed);
        let ws = &c.worker_secrets["http://w"];
        assert!(ws
            .failed_strategies
            .contains(&crate::desync::DesyncStrategy::SplitClientHello));
        // Host not marked down — the host was reachable (phase-1 connected).
        assert!(!ws.host_down);
    }

    /// (d) deep-discovery unclassifiable (phase-2 passed but no verified — the
    /// E2E/score gate filtered them, not a strategy failure) ⇒ no learning.
    #[test]
    fn discovery_unclassifiable_produces_no_learning() {
        let mut c = cfg();
        let changed = apply_learning_signal(
            &mut c,
            "http://w",
            crate::desync::DesyncStrategy::SplitClientHello,
            classify_discovery_outcome(10, 5, false, None),
            1_700_000_300,
        );
        assert!(!changed);
        assert!(!c.worker_secrets.contains_key("http://w"));
    }

    /// (a) host-unreachable does not demote and does not pollute the strategy
    /// record: a pre-existing effective strategy is held (not advanced) and the
    /// failed-set is untouched, while host_down records.
    #[test]
    fn host_down_holds_strategy_and_does_not_demote() {
        let mut c = cfg();
        record_worker_desync_success(
            &mut c,
            "http://w",
            crate::desync::DesyncStrategy::SplitClientHello,
        );
        let before_failed = c.worker_secrets["http://w"].failed_strategies.clone();
        let before_effective = c.worker_secrets["http://w"].desync_strategy;

        let changed = record_worker_host_down(&mut c, "http://w", 1_700_000_000);
        assert!(changed);
        let ws = &c.worker_secrets["http://w"];
        assert!(ws.host_down);
        assert_eq!(ws.host_down_since_unix, 1_700_000_000);
        // Not polluted: effective unchanged, failed-set unchanged.
        assert_eq!(ws.desync_strategy, before_effective);
        assert_eq!(ws.failed_strategies, before_failed);
        // Held strategy: select keeps the effective, does NOT walk the ladder.
        assert_eq!(
            strategy_for_worker(&c, "http://w", 0),
            crate::desync::DesyncStrategy::SplitClientHello
        );
        // Idempotent re-record returns false (no churn).
        assert!(!record_worker_host_down(&mut c, "http://w", 1_700_000_001));
    }

    /// (b) strategy-level WS failure still demotes even after a host-down hold
    /// — the two signals touch disjoint state via apply_learning_signal.
    #[test]
    fn strategy_failure_demotes_independent_of_host_down() {
        let mut c = cfg();
        // Host-down hold in place.
        record_worker_host_down(&mut c, "http://w", 1_700_000_000);
        // A strategy-level failure (WS layer) must demote regardless.
        let changed = apply_learning_signal(
            &mut c,
            "http://w",
            crate::desync::DesyncStrategy::SplitClientHello,
            LearningSignal::StrategyFailure,
            1_700_000_100,
        );
        assert!(changed);
        let ws = &c.worker_secrets["http://w"];
        assert!(ws
            .failed_strategies
            .contains(&crate::desync::DesyncStrategy::SplitClientHello));
        // Host-down hold is independent — it stays until a success clears it.
        assert!(ws.host_down);
    }

    /// (c) host-down → host-recovered resumes at the SAME strategy (not a
    /// demoted one): a success clears the hold and keeps the held effective.
    #[test]
    fn host_recovered_resumes_at_same_strategy() {
        let mut c = cfg();
        record_worker_desync_success(
            &mut c,
            "http://w",
            crate::desync::DesyncStrategy::SplitClientHello,
        );
        record_worker_host_down(&mut c, "http://w", 1_700_000_000);
        assert!(c.worker_secrets["http://w"].host_down);

        let changed = apply_learning_signal(
            &mut c,
            "http://w",
            crate::desync::DesyncStrategy::SplitClientHello,
            LearningSignal::Success,
            1_700_000_200,
        );
        assert!(changed);
        let ws = &c.worker_secrets["http://w"];
        assert!(!ws.host_down, "success must clear the host-down hold");
        assert_eq!(ws.host_down_since_unix, 0);
        // Resumes at the same (held) effective — not advanced/demoted.
        assert_eq!(
            ws.desync_strategy,
            Some(crate::desync::DesyncStrategy::SplitClientHello)
        );
        assert_eq!(
            strategy_for_worker(&c, "http://w", 0),
            crate::desync::DesyncStrategy::SplitClientHello
        );
    }

    /// (d) unclassifiable ⇒ no learning: no record is created / mutated.
    #[test]
    fn unclassifiable_produces_no_learning() {
        let mut c = cfg();
        let changed = apply_learning_signal(
            &mut c,
            "http://w",
            crate::desync::DesyncStrategy::SplitClientHello,
            LearningSignal::Unclassifiable,
            1_700_000_300,
        );
        assert!(!changed);
        assert!(!c.worker_secrets.contains_key("http://w"));
    }
}
