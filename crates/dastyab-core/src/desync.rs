//! Anti-DPI TCP desync fragmenter.
//!
//! Stateful DPI reassembles complete protocol messages (like the HTTP/1.1
//! WebSocket upgrade) by buffering TCP segments, then inspects the reassembled
//! message and drops / resets the connection when it sees the censored
//! signature. Writing the whole request as a single segment makes that
//! inspection trivial.
//!
//! This module writes the request as **irregular fragments**: small,
//! randomized-size chunks, each written then flushed so it leaves as its own
//! TLS record / TCP segment, with a tiny inter-segment pause. The receiver
//! still sees the identical byte stream (TCP is a byte stream), but the DPI
//! reassembly is defeated — it can't stitch the message before the connection
//! is established.
//!
//! This is the round-14 "desync fragmenter / obfuscation" TODO, now built.
//! It is configurable **in-app** (GUI Settings / CLI) via
//! [`DesyncConfig`] stored on `ProfileConfig`. Default is OFF so the scan hot
//! path keeps its throughput; enable it when healthy edges get connection-reset
//! on the WS upgrade (the `TlsAlert` / `WriteFailed` DPI signature).
//!
//! # Global config
//! The scanner's probe functions (`health::probe_ws_ex`, `slipscan`, …) read a
//! process-global config (mirroring `stealth.rs`). Load it from a profile with
//! [`apply_from_profile`] before probing, or set it directly with
//! [`set_config`].

use rand::Rng;
use rand::SeedableRng;
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// Process-wide desync configuration, installed once per cycle.
static CFG: Mutex<Option<DesyncConfig>> = Mutex::new(None);

/// Anti-DPI desync tuning. `enabled=false` (default) is the identical fast
/// path — every write remains a single segment.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct DesyncConfig {
    /// Master switch. When false, every write is a single segment.
    pub enabled: bool,
    /// Smallest allowed fragment size, in bytes.
    pub min_fragment: usize,
    /// Largest allowed fragment size, in bytes.
    pub max_fragment: usize,
    /// Pause between flushed fragments, in microseconds.
    pub inter_fragment_delay_us: u64,
    /// Desync strategy for the scan/probe write path. `None` (default) means
    /// the legacy randomized `fragment_plan` shape (or single segment when
    /// `enabled=false`). The connector ladder (`SplitClientHello` →
    /// `SplitTwo` → `SplitAndDecoy`) is an alternative anti-DPI shape.
    #[serde(default)]
    pub strategy: DesyncStrategy,
}

impl Default for DesyncConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_fragment: 8,
            max_fragment: 64,
            inter_fragment_delay_us: 300,
            strategy: DesyncStrategy::default(),
        }
    }
}

/// Install the active desync config (normally from a loaded profile).
pub fn set_config(cfg: DesyncConfig) {
    *CFG.lock().unwrap() = Some(cfg);
}

/// Read the active config — defaults (disabled) if never set.
pub fn active_config() -> DesyncConfig {
    CFG.lock().unwrap().clone().unwrap_or_default()
}

/// Load a profile and install its desync config. No-op if the profile can't
/// be read (tests / fresh installs fall back to the disabled default).
pub fn apply_from_profile(profile_id: &str) {
    let p = crate::store::profiles::load_profile(profile_id);
    set_config(p.config.desync);
}

/// Pure: split `len` into disjoint fragment sizes, each within `[min, max]`,
/// summing exactly to `len`. Randomized boundaries defeat deterministic DPI.
pub fn fragment_plan(len: usize, rng: &mut impl Rng, cfg: &DesyncConfig) -> Vec<usize> {
    let mut plan = Vec::new();
    let mut remaining = len;
    while remaining > 0 {
        let hi = cfg.max_fragment.min(remaining);
        let lo = cfg.min_fragment.min(hi);
        let frag = if hi == lo { hi } else { rng.gen_range(lo..=hi) };
        plan.push(frag);
        remaining -= frag;
    }
    plan
}

// ---------------------------------------------------------------------------
// Desync strategy ladder (round: anti-DPI connector)
//
// A single blanket "fragment everything" toggle is too coarse: DPI adapts to
// the exact fragmentation shape it sees. Instead the connector learns a
// per-endpoint / per-worker strategy (`DesyncStrategy`) from probe outcomes:
// on success it records the winning strategy; on failure it pushes the tried
// strategy into a failed-set so the ladder advances on the next attempt. The
// ladder is: `SplitClientHello` → `SplitTwo` → `SplitAndDecoy` → `None`
// (skip already-failed entries). This mirrors the carrier-pool penalty model
// (`EndpointPenalty`) and the worker-secret model (`WorkerSecret`).
// ---------------------------------------------------------------------------

/// A fragmentation strategy for a single connection write.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
pub enum DesyncStrategy {
    /// Split only the leading TLS record (the ClientHello + start of the
    /// upgrade) at a small randomized boundary. Minimal cost, targets the
    /// most common DPI reset point.
    SplitClientHello,
    /// Split the request into two roughly-halved irregular segments.
    SplitTwo,
    /// Prepend a decoy ClientHello record, then send the real request
    /// fragmented after it. Heaviest anti-DPI shape.
    SplitAndDecoy,
    /// Single segment (no fragmentation) — the base fallback.
    #[default]
    None,
}

impl DesyncStrategy {
    /// Short stable label for UI/CLI display.
    pub fn label(&self) -> &'static str {
        match self {
            DesyncStrategy::SplitClientHello => "split-clienthello",
            DesyncStrategy::SplitTwo => "split-two",
            DesyncStrategy::SplitAndDecoy => "split+decoy",
            DesyncStrategy::None => "none",
        }
    }

    /// Parse a strategy from a CLI arg (`split-clienthello` | `split-two` |
    /// `split+decoy` | `none`). Case-insensitive; `-`/`+` treated equally.
    pub fn parse(s: &str) -> Option<DesyncStrategy> {
        let norm = s.trim().to_lowercase().replace('-', "+");
        match norm.as_str() {
            "split+clienthello" | "splitclienthello" => Some(DesyncStrategy::SplitClientHello),
            "split+two" | "splittwo" | "split2" => Some(DesyncStrategy::SplitTwo),
            "split+decoy" | "splitdecoy" => Some(DesyncStrategy::SplitAndDecoy),
            "none" | "off" | "" => Some(DesyncStrategy::None),
            _ => None,
        }
    }
}

/// The ordered ladder tried (in order) for a fresh endpoint with no recorded
/// effective strategy: skip entries already in the failed-set.
pub const LADDER: [DesyncStrategy; 4] = [
    DesyncStrategy::SplitClientHello,
    DesyncStrategy::SplitTwo,
    DesyncStrategy::SplitAndDecoy,
    DesyncStrategy::None,
];

/// One planned write chunk of a desync plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteChunk {
    pub data: Vec<u8>,
    /// Microsecond pause after this chunk is flushed.
    pub delay_us: u64,
}

/// Build a hand-rolled, well-formed TLS 1.3 `ClientHello` record to use as a
/// decoy prefix in `DesyncStrategy::SplitAndDecoy`. The record is syntactically
/// valid (record header + handshake header + body) so a stateful DPI that
/// expects a plausible first record sees one, while the real request follows
/// as fragmented segments.
pub fn build_decoy_client_hello() -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy client_version (TLS 1.2)
    let mut random = [0u8; 32];
    rng.fill(&mut random);
    body.extend_from_slice(&random);
    body.push(0); // session_id length = 0
                  // cipher_suites: one suite (TLS_AES_128_GCM_SHA256).
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    body.extend_from_slice(&[0x01, 0x00]); // compression: null
    body.extend_from_slice(&[0x00, 0x00]); // extensions length = 0
                                           // handshake header: type ClientHello + 3-byte length
    let len = body.len();
    let mut hs = Vec::with_capacity(4 + len);
    hs.push(0x01);
    hs.push((len >> 16) as u8);
    hs.push((len >> 8) as u8);
    hs.push(len as u8);
    hs.extend_from_slice(&body);
    // record header: handshake + TLS 1.0 compatibility version + 2-byte len
    let rlen = hs.len();
    let mut rec = Vec::with_capacity(5 + rlen);
    rec.extend_from_slice(&[0x16, 0x03, 0x01]);
    rec.push((rlen >> 8) as u8);
    rec.push(rlen as u8);
    rec.extend_from_slice(&hs);
    rec
}

/// Split `data` into a single `WriteChunk` (no fragmentation).
fn single_chunk(data: &[u8]) -> Vec<WriteChunk> {
    vec![WriteChunk {
        data: data.to_vec(),
        delay_us: 0,
    }]
}

/// Split into two roughly-halved chunks.
fn split_two(data: &[u8], delay_us: u64) -> Vec<WriteChunk> {
    if data.len() <= 1 {
        return single_chunk(data);
    }
    let mid = (data.len() / 2).max(1).min(data.len() - 1);
    vec![
        WriteChunk {
            data: data[..mid].to_vec(),
            delay_us,
        },
        WriteChunk {
            data: data[mid..].to_vec(),
            delay_us: 0,
        },
    ]
}

/// Split only the leading TLS record (first `split` bytes) from the rest.
fn split_client_hello(data: &[u8], cfg: &DesyncConfig, rng: &mut impl Rng) -> Vec<WriteChunk> {
    if data.len() <= 1 {
        return single_chunk(data);
    }
    let lo = 1usize.min(data.len());
    let hi = 24usize.min(data.len());
    let split = if lo == hi { lo } else { rng.gen_range(lo..=hi) };
    vec![
        WriteChunk {
            data: data[..split].to_vec(),
            delay_us: cfg.inter_fragment_delay_us,
        },
        WriteChunk {
            data: data[split..].to_vec(),
            delay_us: 0,
        },
    ]
}

/// Fragment `data` into randomized `[min,max]`-sized chunks (each flushed
/// separately), reusing the existing `fragment_plan` boundary generator.
fn fragment_chunks(data: &[u8], cfg: &DesyncConfig, rng: &mut impl Rng) -> Vec<WriteChunk> {
    let plan = fragment_plan(data.len(), rng, cfg);
    let mut out = Vec::with_capacity(plan.len());
    let mut off = 0;
    for (i, frag) in plan.iter().enumerate() {
        let end = off + frag;
        out.push(WriteChunk {
            data: data[off..end].to_vec(),
            // no sleep after the final chunk
            delay_us: if i + 1 == plan.len() {
                0
            } else {
                cfg.inter_fragment_delay_us
            },
        });
        off = end;
    }
    out
}

/// Convert a strategy + request bytes into a concrete write plan.
pub fn plan_for_strategy(
    strategy: DesyncStrategy,
    data: &[u8],
    cfg: &DesyncConfig,
    rng: &mut impl Rng,
) -> Vec<WriteChunk> {
    match strategy {
        DesyncStrategy::None | DesyncStrategy::SplitAndDecoy if !cfg.enabled => single_chunk(data),
        DesyncStrategy::None => single_chunk(data),
        DesyncStrategy::SplitClientHello => split_client_hello(data, cfg, rng),
        DesyncStrategy::SplitTwo => split_two(data, cfg.inter_fragment_delay_us),
        DesyncStrategy::SplitAndDecoy => {
            let mut plan = Vec::new();
            plan.push(WriteChunk {
                data: build_decoy_client_hello(),
                delay_us: cfg.inter_fragment_delay_us,
            });
            plan.extend(fragment_chunks(data, cfg, rng));
            plan
        }
    }
}

/// Write `plan` through `w`, flushing after each chunk so each leaves as its
/// own TLS record / TCP segment.
pub async fn apply_plan<W>(w: &mut W, plan: &[WriteChunk]) -> Result<(), std::io::Error>
where
    W: AsyncWriteExt + Unpin,
{
    for chunk in plan {
        w.write_all(&chunk.data).await?;
        w.flush().await?;
        if chunk.delay_us > 0 {
            tokio::time::sleep(Duration::from_micros(chunk.delay_us)).await;
        }
    }
    Ok(())
}

/// Select the strategy for the next attempt on an endpoint/worker.
///
/// - If a recorded effective strategy exists and is not in the failed-set, it
///   is preferred (the last-known-good shape).
/// - Otherwise walk `LADDER` in order, skipping failed entries, starting at
///   `attempt` (so repeated failures advance the ladder).
/// - Fallback is `None` (single segment).
pub fn select_strategy(
    effective: Option<&DesyncStrategy>,
    failed: &[DesyncStrategy],
    attempt: u8,
) -> DesyncStrategy {
    if let Some(ef) = effective {
        if !failed.contains(ef) {
            return *ef;
        }
    }
    let n = LADDER.len();
    for i in 0..n {
        let cand = LADDER[(attempt as usize + i) % n];
        if !failed.contains(&cand) {
            return cand;
        }
    }
    DesyncStrategy::None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::AsyncWrite;

    /// Minimal in-memory `AsyncWrite` sink for probing byte delivery.
    struct Sink {
        buf: Vec<u8>,
        flushes: usize,
    }

    impl Sink {
        fn new() -> Self {
            Self {
                buf: Vec::new(),
                flushes: 0,
            }
        }
    }

    impl AsyncWrite for Sink {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            self.buf.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            self.flushes += 1;
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    fn cfg_on() -> DesyncConfig {
        DesyncConfig {
            enabled: true,
            min_fragment: 5,
            max_fragment: 20,
            inter_fragment_delay_us: 0, // 0 keeps tests fast
            strategy: DesyncStrategy::None,
        }
    }

    #[test]
    fn test_fragment_plan_sums_to_len() {
        let rng = &mut rand::rngs::StdRng::seed_from_u64(42);
        for len in [0usize, 1, 7, 8, 64, 400, 4096, 77777] {
            for _ in 0..50 {
                let plan = fragment_plan(len, rng, &cfg_on());
                assert_eq!(plan.iter().sum::<usize>(), len, "plan sum != len for {len}");
            }
        }
    }

    #[test]
    fn test_fragment_plan_segments_within_bounds() {
        let rng = &mut rand::rngs::StdRng::seed_from_u64(7);
        let cfg = cfg_on();
        let plan = fragment_plan(400, rng, &cfg);
        // It must actually fragment (the point of the feature).
        assert!(
            plan.len() > 1,
            "expected fragmentation for a 400-byte write"
        );
        for (i, f) in plan.iter().enumerate() {
            assert!(f >= &1, "fragment {f} empty");
            assert!(f <= &cfg.max_fragment, "fragment {f} exceeds max");
            // Every fragment except the (possibly short) tail respects the
            // lower bound — a remainder below `min` can't be padded.
            if i + 1 < plan.len() {
                assert!(f >= &cfg.min_fragment, "fragment {f} below min");
            }
        }
    }

    #[test]
    fn test_fragment_plan_single_when_len_le_max() {
        let rng = &mut rand::rngs::StdRng::seed_from_u64(1);
        assert_eq!(fragment_plan(5, rng, &cfg_on()), vec![5]);
        assert_eq!(fragment_plan(0, rng, &cfg_on()), Vec::<usize>::new());
    }

    #[tokio::test]
    async fn test_write_none_strategy_single_chunk_single_flush() {
        let mut sink = Sink::new();
        let data = vec![b'x'; 300];
        let plan = plan_for_strategy(
            DesyncStrategy::None,
            &data,
            &DesyncConfig::default(),
            &mut rand::rngs::StdRng::seed_from_u64(15),
        );
        assert_eq!(plan.len(), 1, "None strategy must produce one chunk");
        apply_plan(&mut sink, &plan).await.unwrap();
        assert_eq!(
            sink.buf, data,
            "None strategy must deliver identical bytes in one write"
        );
        assert_eq!(
            sink.flushes, 1,
            "None strategy must flush exactly once (single segment)"
        );
    }

    #[tokio::test]
    async fn test_apply_plan_fragmented_sends_exact_bytes() {
        let mut sink = Sink::new();
        let data =
            b"GET /api/abcdefghijkl HTTP/1.1\r\nHost: x.workers.dev\r\nUpgrade: websocket\r\n\r\n"
                .to_vec();
        let cfg = cfg_on();
        let plan = plan_for_strategy(
            DesyncStrategy::SplitTwo,
            &data,
            &cfg,
            &mut rand::rngs::StdRng::seed_from_u64(16),
        );
        assert!(plan.len() > 1, "SplitTwo must produce multiple chunks");
        apply_plan(&mut sink, &plan).await.unwrap();
        assert_eq!(
            sink.buf, data,
            "fragmented write must deliver the identical byte stream"
        );
        // The whole point: the request must leave as MULTIPLE segments.
        assert!(
            sink.flushes > 1,
            "desync must flush per-fragment, got {} flushes",
            sink.flushes
        );
    }

    // ---- Desync strategy ladder tests ----

    #[test]
    fn plan_writes_none_returns_single_chunk() {
        let cfg = cfg_on();
        let mut rng = rand::rngs::StdRng::seed_from_u64(11);
        let data = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let plan = plan_for_strategy(DesyncStrategy::None, data, &cfg, &mut rng);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].data, data);
        assert_eq!(plan[0].delay_us, 0);
    }

    #[test]
    fn plan_writes_split_two_boundary_correct() {
        let cfg = cfg_on();
        let mut rng = rand::rngs::StdRng::seed_from_u64(12);
        let data = b"GET /abcdefghijklmnopqrstuvwxyz HTTP/1.1\r\n";
        let plan = plan_for_strategy(DesyncStrategy::SplitTwo, data, &cfg, &mut rng);
        assert_eq!(plan.len(), 2);
        let joined: Vec<u8> = plan.iter().flat_map(|c| c.data.iter().copied()).collect();
        assert_eq!(
            joined, data,
            "SplitTwo must deliver the identical byte stream"
        );
    }

    #[test]
    fn plan_writes_split_client_hello_boundary_correct() {
        let cfg = cfg_on();
        let mut rng = rand::rngs::StdRng::seed_from_u64(13);
        let data = b"GET /abcdefghijklmnopqrstuvwxyz HTTP/1.1\r\nHost: x\r\n\r\n";
        let plan = plan_for_strategy(DesyncStrategy::SplitClientHello, data, &cfg, &mut rng);
        assert_eq!(plan.len(), 2);
        assert!(plan[0].data.len() >= 1 && plan[0].data.len() <= 24);
        let joined: Vec<u8> = plan.iter().flat_map(|c| c.data.iter().copied()).collect();
        assert_eq!(joined, data);
    }

    #[test]
    fn plan_writes_split_and_decoy_prepends_decoy() {
        let cfg = cfg_on();
        let mut rng = rand::rngs::StdRng::seed_from_u64(14);
        let data = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let plan = plan_for_strategy(DesyncStrategy::SplitAndDecoy, data, &cfg, &mut rng);
        // First chunk must be a well-formed decoy ClientHello record (random
        // bytes vary per call, so assert structure, not exact equality).
        let decoy_len = build_decoy_client_hello().len();
        assert_eq!(plan[0].data.len(), decoy_len);
        assert_eq!(plan[0].data[0], 0x16); // handshake record
        assert_eq!(plan[0].data[3], 0x00); // hi byte of 2-byte record length
        let joined: Vec<u8> = plan.iter().flat_map(|c| c.data.iter().copied()).collect();
        assert!(
            joined.windows(data.len()).any(|w| w == data),
            "real request must be present"
        );
    }

    #[test]
    fn build_decoy_client_hello_well_formed() {
        let rec = build_decoy_client_hello();
        // Record header: 0x16 (handshake), TLS 1.0 compatibility, 2-byte len.
        assert_eq!(rec[0], 0x16);
        assert_eq!(rec[1], 0x03);
        assert_eq!(rec[2], 0x01);
        let rlen = ((rec[3] as usize) << 8) | rec[4] as usize;
        assert_eq!(rlen + 5, rec.len(), "record length must match payload");
        // Handshake header: type 0x01 (ClientHello) + 3-byte len.
        assert_eq!(rec[5], 0x01);
        let hlen = ((rec[6] as usize) << 16) | ((rec[7] as usize) << 8) | rec[8] as usize;
        assert_eq!(hlen + 9, rec.len(), "handshake length must match body");
        // Body: legacy version TLS 1.2, 32-byte random, empty session id,
        // one cipher suite, null compression.
        assert_eq!(&rec[9..11], &[0x03, 0x03]);
        assert_eq!(rec[43], 0); // session_id length
        assert_eq!(&rec[44..46], &[0x00, 0x02]); // cipher list length = 2
        assert_eq!(&rec[46..48], &[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    }

    #[tokio::test]
    async fn apply_plan_writes_chunks_in_order() {
        let mut sink = Sink::new();
        let plan = vec![
            WriteChunk {
                data: b"GET ".to_vec(),
                delay_us: 0,
            },
            WriteChunk {
                data: b"/ HTTP/1.1\r\n".to_vec(),
                delay_us: 5,
            },
            WriteChunk {
                data: b"Host: x\r\n\r\n".to_vec(),
                delay_us: 0,
            },
        ];
        apply_plan(&mut sink, &plan).await.unwrap();
        assert_eq!(sink.buf, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        // Each chunk flushes → 3 flushes.
        assert_eq!(sink.flushes, 3);
    }

    #[test]
    fn select_strategy_prefers_recorded_effective() {
        let eff = DesyncStrategy::SplitTwo;
        assert_eq!(
            select_strategy(Some(&eff), &[], 0),
            DesyncStrategy::SplitTwo
        );
        // Even at a high attempt, the recorded effective wins when not failed.
        assert_eq!(
            select_strategy(Some(&eff), &[], 9),
            DesyncStrategy::SplitTwo
        );
    }

    #[test]
    fn select_strategy_skips_failed() {
        // Effective strategy is in the failed-set → must not be selected.
        let eff = DesyncStrategy::SplitTwo;
        let failed = vec![DesyncStrategy::SplitTwo];
        assert_ne!(
            select_strategy(Some(&eff), &failed, 0),
            DesyncStrategy::SplitTwo
        );
        // Skip SplitClientHello and SplitTwo → next is SplitAndDecoy.
        let failed2 = vec![DesyncStrategy::SplitClientHello, DesyncStrategy::SplitTwo];
        assert_eq!(
            select_strategy(None, &failed2, 0),
            DesyncStrategy::SplitAndDecoy
        );
    }

    #[test]
    fn desync_ladder_progresses_on_repeated_failure() {
        // attempt 0 → first non-failed ladder entry.
        assert_eq!(
            select_strategy(None, &[], 0),
            DesyncStrategy::SplitClientHello
        );
        // attempt 1 → next.
        assert_eq!(select_strategy(None, &[], 1), DesyncStrategy::SplitTwo);
        // attempt 2 → next.
        assert_eq!(select_strategy(None, &[], 2), DesyncStrategy::SplitAndDecoy);
        // attempt 3 → None (base fallback).
        assert_eq!(select_strategy(None, &[], 3), DesyncStrategy::None);
        // All attempts failed → fallback None.
        let all = vec![
            DesyncStrategy::SplitClientHello,
            DesyncStrategy::SplitTwo,
            DesyncStrategy::SplitAndDecoy,
        ];
        assert_eq!(select_strategy(None, &all, 0), DesyncStrategy::None);
    }

    // Concrete low-level blocker: the WS probe's single-segment write is the
    // vector. Lock the contract the probe relies on: flush after each fragment.
    #[test]
    fn test_fragment_plan_never_emits_empty() {
        let rng = &mut rand::rngs::StdRng::seed_from_u64(3);
        for len in 1..=200 {
            for f in fragment_plan(len, rng, &cfg_on()) {
                assert!(f >= 1, "empty fragment for len {len}");
            }
        }
    }
}
