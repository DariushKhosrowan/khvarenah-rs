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
}

impl Default for DesyncConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_fragment: 8,
            max_fragment: 64,
            inter_fragment_delay_us: 300,
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

/// Write `data` fragmented through `stream` (must be `Unpin`). Each fragment is
/// written then flushed so it leaves as its own TLS record / TCP segment.
/// When `cfg.enabled` is false, this is a single write (identical behavior).
pub async fn write_fragmented<W>(
    stream: &mut W,
    data: &[u8],
    cfg: &DesyncConfig,
) -> Result<(), std::io::Error>
where
    W: AsyncWriteExt + Unpin,
{
    if !cfg.enabled || data.is_empty() {
        stream.write_all(data).await?;
        stream.flush().await?;
        return Ok(());
    }
    let mut rng = rand::rngs::StdRng::from_entropy();
    let plan = fragment_plan(data.len(), &mut rng, cfg);
    let mut off = 0;
    for frag in plan {
        let end = off + frag;
        stream.write_all(&data[off..end]).await?;
        stream.flush().await?;
        if cfg.inter_fragment_delay_us > 0 {
            tokio::time::sleep(Duration::from_micros(cfg.inter_fragment_delay_us)).await;
        }
        off = end;
    }
    Ok(())
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
    async fn test_write_fragmented_disabled_single_write() {
        let mut sink = Sink::new();
        let data = vec![b'x'; 300];
        write_fragmented(&mut sink, &data, &DesyncConfig::default())
            .await
            .unwrap();
        assert_eq!(
            sink.buf, data,
            "disabled path must deliver identical bytes in one write"
        );
        assert_eq!(
            sink.flushes, 1,
            "disabled path must flush exactly once (single segment)"
        );
    }

    #[tokio::test]
    async fn test_write_fragmented_enabled_sends_exact_bytes() {
        let mut sink = Sink::new();
        let data =
            b"GET /api/abcdefghijkl HTTP/1.1\r\nHost: x.workers.dev\r\nUpgrade: websocket\r\n\r\n"
                .to_vec();
        let cfg = cfg_on();
        write_fragmented(&mut sink, &data, &cfg).await.unwrap();
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
