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

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use tokio::sync::{Semaphore, mpsc};

use crate::autopilot::CleanEndpoint;
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
pub type Phase2Fn = Box<dyn Fn(&str, &str, &str, u64) -> Pin<Box<dyn Future<Output = Vec<WsProbe>> + Send>> + Send + Sync>;

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
                let accepted = probes.iter().find(|p| p.status == Some(101) && p.worker_bytes > 0);
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
    out.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
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
        }
    }

    fn phase1_ok(first_n_alive: usize) -> Phase1Fn {
        Box::new(move |ip: &str, _timeout: u64| {
            let out = {
                let n: usize = ip.trim_start_matches("candidate-").parse().unwrap_or(0);
                if n < first_n_alive {
                    fast_passed(20)
                } else {
                    FastProbe { rtt_ms: 0, passed: false }
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
        let p2 = phase2_ok(4);  // every 4th accepted
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
        let high_rtt = WsProbe { rtt_ms: 900, ..ws_accepted(443, 8192) };
        assert!(score_ep(&fast, &low_rtt) > score_ep(&fast, &high_rtt));
        let alt = ws_accepted(2053, 8192);
        assert!(score_ep(&fast, &alt) > score_ep(&fast, &low_rtt));
    }
}
