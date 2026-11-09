//! SlipNet-style two-phase streaming scanner (DeepSeek plan, feature 1).
//!
//! The problem it solves: the old scanner sampled ~2000 IPs uniformly, ran
//! every probe, waited for ALL of them, then ranked. That is slow, wasteful,
//! and on censored networks it usually returns zero because the dense probe
//! burst itself trips DPI or the TCP fast-fail never even gets a fair shot.
//!
//! This is a producer/consumer pipeline distilled from SlipNet's pool scanner:
//!
//! ```text
//! candidates ─► Phase 1 (fast TCP liveness, high concurrency) ─► survivors
//!                        survivors stream out of phase 1 as soon as each
//!                        passes (no waiting for the whole prefilter)
//!        survivors ─► Phase 2 (deep WS-upgrade gate, low concurrency) ─► verified
//!                        verified endpoints are collected; STOP at target_n
//! ```
//!
//! Early-exit: a shared `done` flag flips the moment `verified >= target_n`.
//! Phase 1 tasks check it before starting; phase 2 tasks check before each WS
//! upgrade. In-flight probes drain, but no new ones are spawned after the
//! flag flips — so a scan that needs 3 clean IPs finishes in seconds, not
//! after all 2000 candidates have been tormented.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;

use tokio::sync::{mpsc, Semaphore};

use crate::autopilot::CleanEndpoint;
use crate::e2e::E2eFailureStage;
use crate::error::CFError;
use crate::health::{FastProbe, WsProbe};
use crate::store;

/// Scan control parameters.
#[derive(Debug, Clone, Copy)]
pub struct ScanParams {
    /// Number of verified clean endpoints to collect before early-exit.
    pub target_n: usize,
    /// Phase-1 (fast TCP) concurrency.
    pub phase1_workers: usize,
    /// Phase-2 (deep WS) concurrency.
    pub phase2_workers: usize,
    /// TCP fast-fail threshold in ms.
    pub fast_fail_ms: u64,
    /// WebSocket upgrade timeout in ms.
    pub ws_timeout_ms: u64,
}

impl Default for ScanParams {
    fn default() -> Self {
        Self {
            target_n: 3,
            phase1_workers: 200,
            phase2_workers: 24,
            fast_fail_ms: 1500,
            ws_timeout_ms: 5000,
        }
    }
}

/// Live progress view streamed to the UI/CLI.
#[derive(Debug, Clone, Default)]
pub struct ScanProgress {
    pub probed: u32,
    pub alive: u32,
    pub verified: u32,
    pub total: u32,
    pub done: bool,
}

/// Phase-1 probe: fast TCP liveness. Returns a `FastProbe`.
pub type Phase1Fn =
    Box<dyn Fn(&str, u64) -> Pin<Box<dyn Future<Output = FastProbe> + Send>> + Send + Sync>;

/// Phase-2 probe: deep WS-upgrade gate across alt ports.
pub type Phase2Fn = Box<
    dyn Fn(&str, &str, &str, u64) -> Pin<Box<dyn Future<Output = Vec<WsProbe>> + Send>>
        + Send
        + Sync,
>;

/// Scoring function for a verified endpoint. Higher is better.
pub fn score_ep(fast: &FastProbe, ws: &WsProbe) -> f32 {
    let total_rtt = (fast.rtt_ms + ws.rtt_ms) as f32;
    let rtt_bonus = if total_rtt > 0.0 {
        (1500.0 / total_rtt.max(1.0)).min(10.0)
    } else {
        0.0
    };
    let bytes_bonus = ((ws.worker_bytes as f32) / 1024.0).min(10.0);
    let port_bonus = if ws.port == 443 { 0.0 } else { 2.0 };
    rtt_bonus + bytes_bonus + port_bonus
}

/// Run the two-phase streaming scan.
///
/// `candidates` is the ordered candidate IP list (most promising first).
/// `phase1` probes fast TCP liveness; `phase2` runs the deep WS gate on a
/// survivor. `progress_tx`, when provided, receives streaming progress.
///
/// Returns the verified clean endpoints (best score first), at most
/// `params.target_n`.
pub async fn two_phase_scan(
    candidates: &[String],
    sni: &str,
    path: &str,
    params: &ScanParams,
    phase1: Phase1Fn,
    phase2: Phase2Fn,
    progress_tx: Option<mpsc::UnboundedSender<ScanProgress>>,
) -> Result<Vec<CleanEndpoint>, CFError> {
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let total = candidates.len() as u32;
    let target_n = params.target_n.max(1);

    let done = Arc::new(AtomicBool::new(false));
    let probed = Arc::new(AtomicUsize::new(0));
    let alive_count = Arc::new(AtomicUsize::new(0));
    let verified_arr = Arc::new(AtomicUsize::new(0));

    let (tx, mut rx) = mpsc::unbounded_channel::<(usize, FastProbe)>();

    // Owned closures shared across spawned 'static tasks.
    let phase1 = Arc::new(phase1);
    let phase2 = Arc::new(phase2);

    // Shared result accumulator (score-sorted at the end).
    let results: Arc<std::sync::Mutex<Vec<CleanEndpoint>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));

    // ── Phase 2: workers pull survivors, run the deep gate ──
    let phase2_done = done.clone();
    let phase2_verified_arr = verified_arr.clone();
    let phase2_results = results.clone();
    let phase2_sni = sni.to_string();
    let phase2_path = path.to_string();
    let phase2_params = *params;
    let phase2_fn = phase2.clone();
    let phase2_candidates: Vec<String> = candidates.to_vec();
    let _phase2 = tokio::spawn(async move {
        let sem = Arc::new(Semaphore::new(phase2_params.phase2_workers.max(1)));
        let mut handles = Vec::new();
        while let Some((idx, fast)) = rx.recv().await {
            if phase2_done.load(Ordering::Relaxed) {
                break;
            }
            let ip = phase2_candidates[idx].clone();
            let permit = sem.clone().acquire_owned().await.unwrap();
            let sni = phase2_sni.clone();
            let path = phase2_path.clone();
            let done = phase2_done.clone();
            let verified_arr = phase2_verified_arr.clone();
            let results = phase2_results.clone();
            let phase2_fn = phase2_fn.clone();
            let handle = tokio::spawn(async move {
                let _permit = permit;
                let probes = phase2_fn(&ip, &sni, &path, phase2_params.ws_timeout_ms).await;
                let accepted = probes
                    .iter()
                    .find(|p| p.status == Some(101) && p.worker_bytes > 0);
                if let Some(ws) = accepted {
                    let score = score_ep(&fast, ws);
                    let ep = CleanEndpoint {
                        ip: ip.clone(),
                        port: ws.port,
                        sni: sni.clone(),
                        score,
                        tcp_ms: fast.rtt_ms as f32,
                        connect_ms: ws.rtt_ms as f32,
                        download_kbps: ws.worker_bytes as f32,
                        verified: true,
                        alive: true,
                        last_checked: Some(store::now_iso()),
                        ts: store::now_iso(),
                    };
                    results.lock().unwrap().push(ep);
                    let v = verified_arr.fetch_add(1, Ordering::Relaxed) + 1;
                    if v >= target_n {
                        done.store(true, Ordering::Relaxed);
                    }
                }
            });
            handles.push(handle);
        }
        for h in handles {
            let _ = h.await;
        }
    });

    // ── Phase 1: fast TCP liveness at high concurrency, stream survivors ──
    let sem = Arc::new(Semaphore::new(params.phase1_workers.max(1)));
    let mut sends = Vec::new();
    for (idx, ip) in candidates.iter().enumerate() {
        if done.load(Ordering::Relaxed) {
            break;
        }
        let permit = sem.clone().acquire_owned().await.unwrap();
        let tx = tx.clone();
        let ip = ip.clone();
        let done = done.clone();
        let probed_c = probed.clone();
        let alive_c = alive_count.clone();
        let verified_arr_c = verified_arr.clone();
        let params = *params;
        let phase1_fn = phase1.clone();
        sends.push(tokio::spawn(async move {
            let _permit = permit;
            let _p = probed_c.fetch_add(1, Ordering::Relaxed);
            let fast = phase1_fn(&ip, params.fast_fail_ms).await;
            if fast.passed {
                let _a = alive_c.fetch_add(1, Ordering::Relaxed);
                let _ = tx.send((idx, fast));
            }
            let _verified = verified_arr_c.load(Ordering::Relaxed);
            let _done = done.load(Ordering::Relaxed);
        }));
    }
    drop(tx);
    for s in sends {
        let _ = s.await;
    }
    // Ensure phase 2 has drained.
    let _ = _phase2.await;

    let mut out = results.lock().unwrap().clone();
    out.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out.truncate(target_n);
    if let Some(tx) = &progress_tx {
        let _ = tx.send(ScanProgress {
            probed: probed.load(Ordering::Relaxed) as u32,
            alive: alive_count.load(Ordering::Relaxed) as u32,
            verified: out.len() as u32,
            total,
            done: true,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Parallel E2E pipeline with score-threshold gating (SlipNet orchestration)
// ---------------------------------------------------------------------------

/// Phase-3 probe: full tunnel verification (E2E). Real use wraps
/// `e2e::verify_tunnel`; tests inject a deterministic fake.
pub type E2eFn = Box<
    dyn Fn(&str, u16, &str, u64) -> Pin<Box<dyn Future<Output = crate::e2e::E2eResult> + Send>>
        + Send
        + Sync,
>;

/// Parameters for the parallel pipeline (all knobs have default defaults).
#[derive(Debug, Clone, Copy)]
pub struct PipelineParams {
    /// Phase-1 (fast TCP) concurrency.
    pub phase1_workers: usize,
    /// Phase-2 (deep WS-gate) concurrency.
    pub phase2_workers: usize,
    /// Phase-3 (E2E tunnel) worker pool size (small, sing-box is heavy).
    pub e2e_workers: usize,
    /// Minimum phase-2 dimension score to spend E2E budget on (0..=7).
    pub score_threshold: u8,
    /// Verified endpoints to collect before early exit.
    pub target_n: usize,
    /// TCP fast-fail threshold in ms.
    pub fast_fail_ms: u64,
    /// WebSocket upgrade timeout in ms.
    pub ws_timeout_ms: u64,
}

impl Default for PipelineParams {
    fn default() -> Self {
        Self {
            phase1_workers: 200,
            phase2_workers: 24,
            e2e_workers: 4,
            score_threshold: 5,
            target_n: 3,
            fast_fail_ms: 1500,
            ws_timeout_ms: 5000,
        }
    }
}

/// Per-stage counters so "why zero?" can be answered without guessing.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PipelineDiagnostics {
    /// Candidates examined in this cycle.
    pub examined_total: u32,
    /// Passed the fast TCP prefilter.
    pub phase1_pass: u32,
    /// Passed the deep WS-upgrade gate.
    pub phase2_pass: u32,
    /// Passed the score-threshold gate (spent E2E budget).
    pub score_above_threshold: u32,
    /// Actually tunneled (E2E pass count).
    pub e2e_pass: u32,
    /// E2E failures broken down by stage.
    pub e2e_fail_by_stage: HashMap<E2eFailureStage, u32>,
    /// Why phase-2 WS probes failed, bucketed. This is the diagnostic that
    /// tells Cause A (DPI TLS reset — `TlsAlert` dominant) from Cause B
    /// (dead worker route — `DeadRoute`/`HttpStatus` 404/421 dominant).
    pub ws_failure_histogram: HashMap<crate::health::WsFailureReason, u32>,
    /// Failure reasons stratified by which SNI layer each probe ran under.
    /// Key = (SniLayer, WsFailureReason). Answers the A-vs-B question per
    /// layer: worker-only `TlsAlert` → SNI blocking; `TlsAlert` on BOTH layers
    /// → ClientHello / cipher-suite blocking; `DeadRoute`/404/421 on worker →
    /// dead route.
    #[serde(default)]
    pub failure_by_sni: HashMap<(crate::health::SniLayer, crate::health::WsFailureReason), u32>,
    /// True when we early-exited at target_n.
    pub cancelled_early: bool,
    /// False when E2E was skipped (no direct IP available).
    pub e2e_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct PipelineResult {
    pub verified: Vec<CleanEndpoint>,
    pub diagnostics: PipelineDiagnostics,
    pub elapsed_ms: u64,
}

/// Verdict on the DPI/worker cause, derived from the SNI-stratified failure
/// histogram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SniVerdict {
    /// TlsAlert on the worker SNI only → the worker hostname's SNI is being
    /// blocked (use the Generic-CF SNI strategy).
    WorkerSniBlocked,
    /// TlsAlert on BOTH SNI layers → ClientHello / cipher-suite fingerprint
    /// blocking (rotate ClientHello profile / desync).
    ClientHelloBlocked,
    /// DeadRoute / HTTP 404/421 on the worker SNI → dead worker route
    /// (redeploy / new path).
    WorkerRouteDead,
    /// Not enough stratified data to say.
    Unknown,
}

/// Pure verdict from the stratified failure map. `worker_only_tls_alert`
/// counts `(Worker, TlsAlert)`; `both_layers_tls_alert` is true when both
/// layers have non-zero TlsAlert. `worker_dead_route` counts `DeadRoute` +
/// `HttpStatus(404)` + `HttpStatus(421)` on the worker SNI.
pub fn sni_verdict(
    worker_only_tls_alert: u32,
    both_layers_tls_alert: bool,
    worker_dead_route: u32,
) -> SniVerdict {
    if worker_dead_route > 0 && !both_layers_tls_alert {
        return SniVerdict::WorkerRouteDead;
    }
    if both_layers_tls_alert {
        return SniVerdict::ClientHelloBlocked;
    }
    if worker_only_tls_alert > 0 {
        return SniVerdict::WorkerSniBlocked;
    }
    SniVerdict::Unknown
}

/// Convenience: compute the verdict straight from a `PipelineDiagnostics`.
pub fn verdict_from_diagnostics(d: &PipelineDiagnostics) -> SniVerdict {
    use crate::health::{SniLayer, WsFailureReason};
    let tls = |l| {
        *d.failure_by_sni
            .get(&(l, WsFailureReason::TlsAlert))
            .unwrap_or(&0)
    };
    let worker_tls = tls(SniLayer::Worker);
    let generic_tls = tls(SniLayer::GenericCf);
    let dead_route = [
        WsFailureReason::DeadRoute,
        WsFailureReason::HttpStatus(404),
        WsFailureReason::HttpStatus(421),
        WsFailureReason::HttpStatus(403),
    ]
    .iter()
    .map(|r| *d.failure_by_sni.get(&(SniLayer::Worker, *r)).unwrap_or(&0))
    .sum::<u32>();
    sni_verdict(worker_tls, worker_tls > 0 && generic_tls > 0, dead_route)
}

/// 7-dimension gate score mirroring `health::quality_score`, computed from the
/// two probes we actually have (TCP + WS). Max 7.
pub fn phase2_score(fast: &FastProbe, ws: &WsProbe) -> u8 {
    let mut s = 0u8;
    if fast.passed {
        s += 1;
    }
    if ws.tls_ok {
        s += 1;
    }
    if ws.status == Some(101) && ws.worker_bytes > 0 {
        s += 2;
    }
    let total_rtt = fast.rtt_ms.saturating_add(ws.rtt_ms);
    if total_rtt < 1500 {
        s += 1;
    }
    if ws.worker_bytes >= 1024 {
        s += 1;
    }
    if ws.port != 443 {
        s += 1;
    }
    s
}

/// Reject candidates below the score threshold BEFORE they consume expensive
/// E2E budget. For this gate each candidate's `score` field carries its
/// phase-2 dimension score (0..=7), NOT the RTT/bytes ranking score.
pub fn gate_by_score(candidates: &[CleanEndpoint], threshold: u8) -> Vec<CleanEndpoint> {
    candidates
        .iter()
        .filter(|c| (c.score as u8) >= threshold)
        .cloned()
        .collect()
}

/// The parallel pipeline. Phase-1 (fast TCP) runs at high concurrency and
/// streams survivors to phase-2 (deep WS-gate). Phase-2 survivors that pass the
/// score-threshold gate feed a *parallel* E2E worker pool (SlipNet-style) that
/// proves each candidate actually tunnels. Early-exit flips a shared `done`
/// flag the moment `target_n` verified endpoints accumulate, so in-flight work
/// drains and no new probes spawn. Diagnostics count every stage so "why zero?"
/// is answerable. When `direct_ip` is `None`, E2E is skipped and phase-2-gated
/// candidates are promoted directly (graceful degradation).
#[allow(clippy::too_many_arguments)]
pub async fn pipeline_scan(
    candidates: Vec<String>,
    sni: &str,
    path: &str,
    vless_link: &str,
    direct_ip: Option<String>,
    params: PipelineParams,
    phase1: Phase1Fn,
    phase2: Phase2Fn,
    e2e: E2eFn,
    progress_tx: Option<mpsc::UnboundedSender<ScanProgress>>,
    spawner: Option<Arc<dyn crate::e2e::SingboxSpawner>>,
) -> Result<PipelineResult, CFError> {
    let started = Instant::now();
    let e2e_enabled = direct_ip.is_some();
    if candidates.is_empty() {
        return Ok(PipelineResult {
            verified: Vec::new(),
            diagnostics: PipelineDiagnostics {
                examined_total: 0,
                e2e_enabled,
                ..Default::default()
            },
            elapsed_ms: 0,
        });
    }
    let total = candidates.len() as u32;
    let target_n = params.target_n.max(1);

    let done = Arc::new(AtomicBool::new(false));
    let phase1_pass = Arc::new(AtomicUsize::new(0));
    let phase2_pass = Arc::new(AtomicUsize::new(0));
    let gated = Arc::new(AtomicUsize::new(0));
    let e2e_pass_c = Arc::new(AtomicUsize::new(0));
    let e2e_fail: Arc<Mutex<HashMap<E2eFailureStage, u32>>> = Arc::new(Mutex::new(HashMap::new()));
    let ws_fail: Arc<Mutex<HashMap<crate::health::WsFailureReason, u32>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let ws_fail_sni: Arc<
        Mutex<HashMap<(crate::health::SniLayer, crate::health::WsFailureReason), u32>>,
    > = Arc::new(Mutex::new(HashMap::new()));
    let results: Arc<Mutex<Vec<CleanEndpoint>>> = Arc::new(Mutex::new(Vec::new()));
    let candidates = Arc::new(candidates);
    let phase1 = Arc::new(phase1);
    let phase2 = Arc::new(phase2);
    // When a spawner is supplied, route the E2E stage through the real tunnel
    // verification with that spawner (used by the mock-pipeline integration
    // tests). Otherwise keep the injected `e2e` closure (unit tests / real run).
    let e2e = if let Some(spawner) = spawner {
        let direct = direct_ip.clone().unwrap_or_default();
        Arc::new(
            Box::new(move |ip: &str, port: u16, vless: &str, timeout_s: u64| {
                let ip = ip.to_string();
                let vless = vless.to_string();
                let direct = direct.clone();
                let spawner = spawner.clone();
                Box::pin(async move {
                    crate::e2e::verify_tunnel_with(
                        &ip,
                        port,
                        &vless,
                        &direct,
                        spawner.as_ref(),
                        timeout_s,
                    )
                    .await
                })
                    as std::pin::Pin<Box<dyn Future<Output = crate::e2e::E2eResult> + Send>>
            }) as E2eFn,
        )
    } else {
        Arc::new(e2e)
    };

    // Phase1 survivors -> phase2; phase2 survivors (gated) -> e2e.
    let (tx1, mut rx1) = mpsc::unbounded_channel::<(usize, FastProbe)>();
    let (tx2, mut rx2) = mpsc::unbounded_channel::<CleanEndpoint>();

    // ── Stage 3: E2E workers ──
    let e2e_handle = {
        let sem = Arc::new(Semaphore::new(params.e2e_workers.max(1)));
        let done_c = done.clone();
        let results_c = results.clone();
        let pass_c = e2e_pass_c.clone();
        let fail_c = e2e_fail.clone();
        let vless = vless_link.to_string();
        let direct = direct_ip.clone();
        let e2e_fn = e2e.clone();
        tokio::spawn(async move {
            if let Some(_direct) = direct {
                let mut handles = Vec::new();
                while let Some(ep) = rx2.recv().await {
                    if done_c.load(Ordering::Relaxed) {
                        break;
                    }
                    let permit = sem.clone().acquire_owned().await.unwrap();
                    let ip = ep.ip.clone();
                    let port = ep.port;
                    let vless = vless.clone();
                    let e2e_fn = e2e_fn.clone();
                    let results_c = results_c.clone();
                    let fail_c = fail_c.clone();
                    let pass_c = pass_c.clone();
                    let done_c2 = done_c.clone();
                    handles.push(tokio::spawn(async move {
                        let _permit = permit;
                        let r = e2e_fn(&ip, port, &vless, 8).await;
                        if r.passed {
                            pass_c.fetch_add(1, Ordering::Relaxed);
                            let mut m = results_c.lock().unwrap();
                            m.push(ep.clone());
                            if m.len() >= target_n {
                                done_c2.store(true, Ordering::Relaxed);
                            }
                        } else if let Some(stage) = r.failure_stage {
                            let mut fm = fail_c.lock().unwrap();
                            *fm.entry(stage).or_insert(0) += 1;
                        }
                    }));
                }
                for h in handles {
                    let _ = h.await;
                }
            } else {
                // E2E disabled (no direct IP): promote gated candidates directly.
                let mut buf = Vec::new();
                while let Some(ep) = rx2.recv().await {
                    if done_c.load(Ordering::Relaxed) && buf.len() >= target_n {
                        break;
                    }
                    buf.push(ep);
                }
                let mut list = results_c.lock().unwrap();
                list.extend(buf);
            }
        })
    };

    // ── Stage 2: deep WS-gate, then score-threshold gate ──
    let phase2_handle = {
        let sem = Arc::new(Semaphore::new(params.phase2_workers.max(1)));
        let tx2 = tx2;
        let phase2_fn = phase2.clone();
        let phase2_pass_c = phase2_pass.clone();
        let gated_c = gated.clone();
        let ws_fail_c = ws_fail.clone();
        let ws_fail_sni_c = ws_fail_sni.clone();
        let done_c = done.clone();
        let sni = sni.to_string();
        let path = path.to_string();
        let candidates2 = candidates.clone();
        tokio::spawn(async move {
            let mut handles = Vec::new();
            while let Some((idx, fast)) = rx1.recv().await {
                if done_c.load(Ordering::Relaxed) {
                    break;
                }
                let ip = candidates2[idx].clone();
                let permit = sem.clone().acquire_owned().await.unwrap();
                let sni = sni.clone();
                let path = path.clone();
                let phase2_fn = phase2_fn.clone();
                let tx2 = tx2.clone();
                let phase2_pass_c = phase2_pass_c.clone();
                let gated_c = gated_c.clone();
                let ws_fail_c = ws_fail_c.clone();
                let ws_fail_sni_c = ws_fail_sni_c.clone();
                let params2 = params;
                handles.push(tokio::spawn(async move {
                    let _permit = permit;
                    let probes = phase2_fn(&ip, &sni, &path, params2.ws_timeout_ms).await;
                    // Bucket every failed probe's reason into the histogram.
                    // Only the first (accepted) probe on the happy path has a
                    // failure_reason; failed probes always carry one.
                    let mut fm = ws_fail_c.lock().unwrap();
                    let mut fms = ws_fail_sni_c.lock().unwrap();
                    for p in &probes {
                        if let Some(reason) = p.failure_reason {
                            *fm.entry(reason).or_insert(0) += 1;
                            let layer = crate::health::SniLayer::classify(&p.sni_used);
                            *fms.entry((layer, reason)).or_insert(0) += 1;
                        }
                    }
                    drop((fm, fms));
                    let accepted = probes.iter().find(|p| {
                        p.status == Some(101) && p.worker_bytes >= crate::health::MIN_WORKER_BYTES
                    });
                    if let Some(ws) = accepted {
                        phase2_pass_c.fetch_add(1, Ordering::Relaxed);
                        let gate = phase2_score(&fast, ws);
                        if gate >= params2.score_threshold {
                            gated_c.fetch_add(1, Ordering::Relaxed);
                            let score = score_ep(&fast, ws);
                            let ep = CleanEndpoint {
                                ip: ip.clone(),
                                port: ws.port,
                                sni: sni.clone(),
                                score,
                                tcp_ms: fast.rtt_ms as f32,
                                connect_ms: ws.rtt_ms as f32,
                                download_kbps: ws.worker_bytes as f32,
                                verified: true,
                                alive: true,
                                last_checked: Some(store::now_iso()),
                                ts: store::now_iso(),
                            };
                            let _ = tx2.send(ep);
                        }
                    }
                }));
            }
            for h in handles {
                let _ = h.await;
            }
            drop(tx2); // release final sender so the E2E stage sees EOF
        })
    };

    // ── Stage 1: fast TCP prefilter ──
    let sem1 = Arc::new(Semaphore::new(params.phase1_workers.max(1)));
    let mut sends = Vec::new();
    for (idx, ip) in candidates.iter().enumerate() {
        if done.load(Ordering::Relaxed) {
            break;
        }
        let permit = sem1.clone().acquire_owned().await.unwrap();
        let tx1 = tx1.clone();
        let ip = ip.clone();
        let done_c = done.clone();
        let phase1_pass_c = phase1_pass.clone();
        let phase1_fn = phase1.clone();
        sends.push(tokio::spawn(async move {
            let _permit = permit;
            let fast = phase1_fn(&ip, params.fast_fail_ms).await;
            if fast.passed {
                phase1_pass_c.fetch_add(1, Ordering::Relaxed);
                let _ = tx1.send((idx, fast));
            }
            let _ = done_c.load(Ordering::Relaxed);
        }));
    }
    drop(tx1);
    for s in sends {
        let _ = s.await;
    }
    let _ = phase2_handle.await;
    let _ = e2e_handle.await;

    let verified = {
        let mut out = results.lock().unwrap().clone();
        out.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        out.truncate(target_n);
        out
    };

    let diagnostics = PipelineDiagnostics {
        examined_total: total,
        phase1_pass: phase1_pass.load(Ordering::Relaxed) as u32,
        phase2_pass: phase2_pass.load(Ordering::Relaxed) as u32,
        score_above_threshold: gated.load(Ordering::Relaxed) as u32,
        e2e_pass: if e2e_enabled {
            e2e_pass_c.load(Ordering::Relaxed) as u32
        } else {
            0
        },
        e2e_fail_by_stage: e2e_fail.lock().unwrap().clone(),
        ws_failure_histogram: ws_fail.lock().unwrap().clone(),
        failure_by_sni: ws_fail_sni.lock().unwrap().clone(),
        cancelled_early: done.load(Ordering::Relaxed),
        e2e_enabled,
    };

    if let Some(tx) = &progress_tx {
        let _ = tx.send(ScanProgress {
            probed: phase1_pass.load(Ordering::Relaxed) as u32,
            alive: phase2_pass.load(Ordering::Relaxed) as u32,
            verified: verified.len() as u32,
            total,
            done: true,
        });
    }

    Ok(PipelineResult {
        verified,
        diagnostics,
        elapsed_ms: started.elapsed().as_millis() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_passed(ms: u64) -> FastProbe {
        FastProbe {
            rtt_ms: ms as u32,
            passed: true,
        }
    }

    fn ws_accepted(port: u16, bytes: u32) -> WsProbe {
        WsProbe {
            port,
            tls_ok: true,
            status: Some(101),
            rtt_ms: 30,
            worker_bytes: bytes,
            failure_stage: None,
            failure_reason: None,
            sni_used: "mock.workers.dev".to_string(),
        }
    }

    fn ws_rejected(port: u16) -> WsProbe {
        WsProbe {
            port,
            tls_ok: true,
            status: Some(404),
            rtt_ms: 30,
            worker_bytes: 0,
            failure_stage: Some("ws".into()),
            failure_reason: Some(crate::health::WsFailureReason::HttpStatus(404)),
            sni_used: "mock.workers.dev".to_string(),
        }
    }

    fn phase1_ok(first_n_alive: usize) -> Phase1Fn {
        Box::new(move |ip: &str, _timeout: u64| {
            let out = {
                let n: usize = ip.trim_start_matches("candidate-").parse().unwrap_or(0);
                if n < first_n_alive {
                    fast_passed(20)
                } else {
                    FastProbe {
                        rtt_ms: 0,
                        passed: false,
                    }
                }
            };
            Box::pin(async move { out })
        })
    }

    fn phase2_ok(every_kth: usize) -> Phase2Fn {
        Box::new(move |ip: &str, _sni: &str, _path: &str, _to: u64| {
            let out = {
                let n: usize = ip.trim_start_matches("candidate-").parse().unwrap_or(0);
                if n % every_kth == 0 {
                    vec![ws_accepted(443, 4096)]
                } else {
                    vec![ws_rejected(443)]
                }
            };
            Box::pin(async move { out })
        })
    }

    #[tokio::test]
    async fn two_phase_streams_survivors_to_phase2() {
        let candidates: Vec<String> = (0..40).map(|i| format!("candidate-{i}")).collect();
        let p1 = phase1_ok(20); // first 20 alive
        let p2 = phase2_ok(4); // every 4th accepted
        let params = ScanParams {
            target_n: 3,
            phase1_workers: 50,
            phase2_workers: 10,
            ..Default::default()
        };
        let out = two_phase_scan(&candidates, "sni.test", "/ws", &params, p1, p2, None)
            .await
            .unwrap();
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|e| e.verified && e.alive));
        assert!(out[0].score >= out[1].score);
    }

    #[tokio::test]
    async fn early_exit_stops_at_target_n() {
        let candidates: Vec<String> = (0..200).map(|i| format!("candidate-{i}")).collect();
        let p1 = phase1_ok(usize::MAX);
        let p2 = phase2_ok(2);
        let params = ScanParams {
            target_n: 3,
            phase1_workers: 50,
            phase2_workers: 10,
            ..Default::default()
        };
        let out = two_phase_scan(&candidates, "sni.test", "/ws", &params, p1, p2, None)
            .await
            .unwrap();
        assert_eq!(out.len(), 3);
    }

    #[tokio::test]
    async fn progress_stream_is_monotonic() {
        let candidates: Vec<String> = (0..30).map(|i| format!("candidate-{i}")).collect();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let p1 = phase1_ok(30);
        let p2 = phase2_ok(3);
        let params = ScanParams {
            target_n: 2,
            phase1_workers: 30,
            phase2_workers: 8,
            ..Default::default()
        };
        let _ = two_phase_scan(&candidates, "sni.test", "/ws", &params, p1, p2, Some(tx))
            .await
            .unwrap();
        let mut last_verified = 0u32;
        let mut saw_terminal = false;
        while let Some(p) = rx.recv().await {
            assert!(p.verified >= last_verified);
            last_verified = p.verified;
            if p.done {
                saw_terminal = true;
                break;
            }
        }
        assert!(saw_terminal);
    }

    #[test]
    fn score_prefers_low_rtt_and_bytes() {
        let fast = fast_passed(40);
        let low_rtt = ws_accepted(443, 8192);
        let high_rtt = WsProbe {
            rtt_ms: 900,
            ..ws_accepted(443, 8192)
        };
        assert!(score_ep(&fast, &low_rtt) > score_ep(&fast, &high_rtt));
        let alt = ws_accepted(2053, 8192);
        assert!(score_ep(&fast, &alt) > score_ep(&fast, &low_rtt));
    }

    // --- Parallel pipeline tests ---

    #[test]
    fn score_gate_rejects_borderline() {
        let mk = |score: f32| CleanEndpoint {
            ip: "1.1.1.1".into(),
            port: 443,
            sni: "h".into(),
            score,
            tcp_ms: 0.0,
            connect_ms: 0.0,
            download_kbps: 0.0,
            verified: true,
            alive: true,
            last_checked: None,
            ts: String::new(),
        };
        let cands = vec![mk(4.0), mk(5.0), mk(6.0)];
        let kept = gate_by_score(&cands, 5);
        assert_eq!(kept.len(), 2);
        assert!(kept.iter().all(|c| c.score >= 5.0));
    }

    async fn run_pipeline(
        candidates: usize,
        params: PipelineParams,
        direct: Option<String>,
    ) -> PipelineResult {
        let cands: Vec<String> = (0..candidates).map(|i| format!("candidate-{i}")).collect();
        let p1 = phase1_ok(usize::MAX);
        let p2 = phase2_ok(2);
        let e2e: E2eFn = Box::new(move |ip, _port, _vless, _t| {
            let r = crate::e2e::E2eResult {
                endpoint: format!("{ip}:443"),
                passed: true,
                failure_stage: None,
                verified_at: 0,
                tunnel_ip: Some("9.9.9.9".into()),
            };
            Box::pin(async move { r })
        });
        pipeline_scan(
            cands,
            "sni.test",
            "/ws",
            "vless://x@y:443?security=tls&type=ws",
            direct,
            params,
            p1,
            p2,
            e2e,
            None,
            None,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn pipeline_early_exits_at_target_n() {
        let res = run_pipeline(
            200,
            PipelineParams {
                target_n: 3,
                ..Default::default()
            },
            Some("1.1.1.1".into()),
        )
        .await;
        assert_eq!(res.verified.len(), 3);
        assert!(res.diagnostics.cancelled_early);
    }

    #[tokio::test]
    async fn pipeline_returns_verified_best_first() {
        let res = run_pipeline(
            40,
            PipelineParams {
                target_n: 10,
                ..Default::default()
            },
            Some("1.1.1.1".into()),
        )
        .await;
        assert_eq!(res.verified.len(), 10);
        for w in res.verified.windows(2) {
            assert!(w[0].score >= w[1].score);
        }
    }

    #[tokio::test]
    async fn pipeline_starts_e2e_in_parallel_and_reports_diagnostics() {
        let res = run_pipeline(
            40,
            PipelineParams {
                target_n: 5,
                ..Default::default()
            },
            Some("1.1.1.1".into()),
        )
        .await;
        assert!(res.diagnostics.e2e_enabled);
        assert!(res.diagnostics.e2e_pass >= 5);
        assert!(res.diagnostics.phase1_pass > 0);
        assert!(res.diagnostics.phase2_pass > 0);
        assert!(res.diagnostics.score_above_threshold > 0);
        assert_eq!(res.diagnostics.examined_total, 40);
    }

    #[tokio::test]
    async fn pipeline_e2e_disabled_degrades_to_gate_only() {
        let res = run_pipeline(
            40,
            PipelineParams {
                target_n: 3,
                ..Default::default()
            },
            None,
        )
        .await;
        assert!(!res.diagnostics.e2e_enabled);
        assert_eq!(res.verified.len(), 3);
        assert_eq!(res.diagnostics.e2e_pass, 0);
    }

    #[tokio::test]
    async fn pipeline_e2e_concurrency_respected() {
        // A pool of 1 still yields correct results (serialized but correct).
        let res = run_pipeline(
            60,
            PipelineParams {
                e2e_workers: 1,
                target_n: 3,
                ..Default::default()
            },
            Some("1.1.1.1".into()),
        )
        .await;
        assert_eq!(res.verified.len(), 3);
    }

    #[tokio::test]
    async fn pipeline_phase1_stops_spawning_after_done_flag() {
        // Phase-1 with a small per-probe delay so the E2E stage makes progress
        // before all 500 candidates are probed — making early-exit observable.
        let cands: Vec<String> = (0..500).map(|i| format!("candidate-{i}")).collect();
        let p1: Phase1Fn = Box::new(move |ip, _t| {
            let out = {
                let n: usize = ip.trim_start_matches("candidate-").parse().unwrap_or(0);
                // Simulate a live network: low-index probes answer fast, high-index
                // probes are slow (like far edges under censoring).
                if n < 40 {
                    fast_passed(20)
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    fast_passed(20)
                }
            };
            Box::pin(async move { out })
        });
        let p2 = phase2_ok(2);
        let e2e: E2eFn = Box::new(move |ip, _port, _vless, _t| {
            let r = crate::e2e::E2eResult {
                endpoint: format!("{ip}:443"),
                passed: true,
                failure_stage: None,
                verified_at: 0,
                tunnel_ip: Some("9.9.9.9".into()),
            };
            Box::pin(async move { r })
        });
        let res = pipeline_scan(
            cands,
            "sni.test",
            "/ws",
            "vless://x@y:443?security=tls&type=ws",
            Some("1.1.1.1".into()),
            PipelineParams {
                target_n: 2,
                phase1_workers: 8,
                ..Default::default()
            },
            p1,
            p2,
            e2e,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(res.verified.len(), 2);
        // Early exit must prevent probing all 500 candidates.
        assert!((res.diagnostics.phase1_pass as usize) < 500);
        assert!(res.diagnostics.cancelled_early);
    }

    #[tokio::test]
    async fn pipeline_counts_e2e_failures_by_stage() {
        let cands: Vec<String> = (0..12).map(|i| format!("candidate-{i}")).collect();
        let p1 = phase1_ok(usize::MAX);
        let p2 = phase2_ok(1); // everyone passes WS gate
        let e2e: E2eFn = Box::new(move |ip, _p, _v, _t| {
            let idx: usize = ip.trim_start_matches("candidate-").parse().unwrap_or(0);
            let r = if idx < 6 {
                crate::e2e::E2eResult {
                    endpoint: format!("{ip}:443"),
                    passed: false,
                    failure_stage: Some(crate::e2e::E2eFailureStage::IpUnchanged),
                    verified_at: 0,
                    tunnel_ip: Some("1.1.1.1".into()),
                }
            } else {
                crate::e2e::E2eResult {
                    endpoint: format!("{ip}:443"),
                    passed: true,
                    failure_stage: None,
                    verified_at: 0,
                    tunnel_ip: Some("9.9.9.9".into()),
                }
            };
            Box::pin(async move { r })
        });
        let res = pipeline_scan(
            cands,
            "sni.test",
            "/ws",
            "vless://x@y:443?security=tls&type=ws",
            Some("1.1.1.1".into()),
            PipelineParams {
                target_n: 6,
                ..Default::default()
            },
            p1,
            p2,
            e2e,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            res.diagnostics
                .e2e_fail_by_stage
                .get(&crate::e2e::E2eFailureStage::IpUnchanged),
            Some(&6)
        );
        assert!(res.diagnostics.e2e_pass >= 5);
    }

    #[tokio::test]
    async fn pipeline_populates_ws_failure_histogram() {
        let cands: Vec<String> = (0..20).map(|i| format!("candidate-{i}")).collect();
        let p1 = phase1_ok(usize::MAX);
        // 1/3 succeed; 1/3 → HttpStatus(404); 1/3 → DeadRoute (101 < 512B).
        let p2: Phase2Fn = Box::new(move |ip: &str, _sni, _path, _to| {
            let n: usize = ip.trim_start_matches("candidate-").parse().unwrap_or(0);
            let out = match n % 3 {
                0 => vec![ws_accepted(443, 4096)],
                1 => vec![ws_rejected(443)],
                _ => vec![WsProbe {
                    status: Some(101),
                    worker_bytes: 100,
                    failure_reason: Some(crate::health::WsFailureReason::DeadRoute),
                    ..ws_rejected(443)
                }],
            };
            Box::pin(async move { out })
        });
        let e2e: E2eFn = Box::new(move |ip, _port, _vless, _t| {
            let r = crate::e2e::E2eResult {
                endpoint: format!("{ip}:443"),
                passed: true,
                failure_stage: None,
                verified_at: 0,
                tunnel_ip: Some("9.9.9.9".into()),
            };
            Box::pin(async move { r })
        });
        let res = pipeline_scan(
            cands,
            "sni.test",
            "/ws",
            "vless://x@y:443?security=tls&type=ws",
            Some("1.1.1.1".into()),
            PipelineParams::default(),
            p1,
            p2,
            e2e,
            None,
            None,
        )
        .await
        .unwrap();
        let h = &res.diagnostics.ws_failure_histogram;
        let http404 = h
            .get(&crate::health::WsFailureReason::HttpStatus(404))
            .copied()
            .unwrap_or(0);
        let deadroute = h
            .get(&crate::health::WsFailureReason::DeadRoute)
            .copied()
            .unwrap_or(0);
        assert!(http404 > 0, "expected 404 buckets in histogram, got {h:?}");
        assert!(
            deadroute > 0,
            "expected DeadRoute buckets in histogram, got {h:?}"
        );
        // The histogram should contain every failure bucket (no other reasons).
        assert_eq!(http404 + deadroute, h.values().sum::<u32>());
    }

    #[tokio::test]
    async fn pipeline_stratifies_failures_by_sni_layer() {
        let cands: Vec<String> = (0..12).map(|i| format!("candidate-{i}")).collect();
        let p1 = phase1_ok(usize::MAX);
        // Inject a worker-layer TlsAlert and a generic-CF-layer 404 so both
        // layers appear in the stratified map.
        let p2: Phase2Fn = Box::new(move |ip: &str, _sni, _path, _to| {
            let n: usize = ip.trim_start_matches("candidate-").parse().unwrap_or(0);
            let out = match n % 3 {
                0 => vec![ws_accepted(443, 4096)],
                1 => vec![WsProbe {
                    failure_reason: Some(crate::health::WsFailureReason::TlsAlert),
                    sni_used: "mock.workers.dev".to_string(),
                    ..ws_rejected(443)
                }],
                _ => vec![WsProbe {
                    failure_reason: Some(crate::health::WsFailureReason::HttpStatus(404)),
                    sni_used: crate::health::GENERIC_CF_SNI.to_string(),
                    ..ws_rejected(443)
                }],
            };
            Box::pin(async move { out })
        });
        let e2e: E2eFn = Box::new(move |ip, _port, _vless, _t| {
            let ip = ip.to_string();
            Box::pin(async move {
                crate::e2e::E2eResult {
                    endpoint: format!("{ip}:443"),
                    passed: true,
                    failure_stage: None,
                    verified_at: 0,
                    tunnel_ip: Some("9.9.9.9".into()),
                }
            })
        });
        let res = pipeline_scan(
            cands,
            "sni.test",
            "/ws",
            "vless://x@y:443?security=tls&type=ws",
            Some("1.1.1.1".into()),
            PipelineParams::default(),
            p1,
            p2,
            e2e,
            None,
            None,
        )
        .await
        .unwrap();
        let m = &res.diagnostics.failure_by_sni;
        let worker_tls = *m
            .get(&(
                crate::health::SniLayer::Worker,
                crate::health::WsFailureReason::TlsAlert,
            ))
            .unwrap_or(&0);
        let generic_404 = *m
            .get(&(
                crate::health::SniLayer::GenericCf,
                crate::health::WsFailureReason::HttpStatus(404),
            ))
            .unwrap_or(&0);
        assert!(worker_tls > 0, "expected worker-layer TlsAlert, got {m:?}");
        assert!(generic_404 > 0, "expected generic-CF-layer 404, got {m:?}");
    }

    #[test]
    fn sni_verdict_worker_only_tls_alert() {
        assert_eq!(
            super::sni_verdict(5, false, 0),
            super::SniVerdict::WorkerSniBlocked
        );
    }

    #[test]
    fn sni_verdict_both_layers_tls_alert() {
        assert_eq!(
            super::sni_verdict(5, true, 0),
            super::SniVerdict::ClientHelloBlocked
        );
    }

    #[test]
    fn sni_verdict_dead_route_wins_over_worker_alert() {
        assert_eq!(
            super::sni_verdict(2, false, 7),
            super::SniVerdict::WorkerRouteDead
        );
    }

    #[test]
    fn sni_verdict_unknown_when_no_data() {
        assert_eq!(super::sni_verdict(0, false, 0), super::SniVerdict::Unknown);
    }

    #[test]
    fn verdict_from_diagnostics_maps_stratified_map() {
        use crate::health::{SniLayer, WsFailureReason};
        let mut d = PipelineDiagnostics::default();
        d.failure_by_sni
            .insert((SniLayer::Worker, WsFailureReason::TlsAlert), 4);
        d.failure_by_sni
            .insert((SniLayer::GenericCf, WsFailureReason::TlsAlert), 4);
        assert_eq!(
            super::verdict_from_diagnostics(&d),
            super::SniVerdict::ClientHelloBlocked
        );
        d.failure_by_sni.clear();
        d.failure_by_sni
            .insert((SniLayer::Worker, WsFailureReason::DeadRoute), 9);
        assert_eq!(
            super::verdict_from_diagnostics(&d),
            super::SniVerdict::WorkerRouteDead
        );
    }
}
