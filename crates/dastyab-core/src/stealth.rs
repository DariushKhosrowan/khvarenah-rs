//! Humanizing anti-bot-stealth layer.
//!
//! Port of the Python `stealth.py`. Everything here is configurable; set
//! `DASTYAB_STEALTH=0` to disable (used by tests/CI).

use rand::Rng;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static ENABLED: AtomicBool = AtomicBool::new(true);

/// Set whether stealth pacing is active.
pub fn set_enabled(v: bool) {
    ENABLED.store(v, Ordering::Relaxed);
}

/// Current enabled state.
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

fn rng() -> rand::rngs::ThreadRng {
    rand::thread_rng()
}

/// Human-shaped pause before an API call.
///
/// * `kind == "write"` → longer "crafting" delay (~1.5–4.5s).
/// * otherwise → short lookup delay (~0.4–2.0s).
/// * ~8% of the time add an extra "distraction" pause (1.5–6s).
pub async fn pre_request_pause(kind: &str) {
    if !enabled() {
        return;
    }
    let mut r = rng();
    let base = if kind == "write" {
        r.gen_range(1.5_f64..4.5)
    } else {
        r.gen_range(0.4_f64..2.0)
    };
    let extra = if r.gen::<f64>() < 0.08 {
        r.gen_range(1.5_f64..6.0)
    } else {
        0.0
    };
    pause((base + extra) as f32).await;
}

/// Pause between major workflow stages.
pub async fn boundary_pause() {
    if !enabled() {
        return;
    }
    let mut r = rng();
    pause(r.gen_range(0.5_f64..2.5) as f32).await;
}

/// Randomized exponential backoff between retries (attempt is 0-based).
///
/// Roughly `2^(attempt+1)` seconds scaled by a 0.75–1.25 jitter factor,
/// floored at 1.0s so the first retry is never instant.
pub async fn retry_backoff(attempt: u32) {
    if !enabled() {
        return;
    }
    let exp = 2.0_f64.powi(attempt as i32 + 1);
    let mut r = rng();
    let jitter = r.gen_range(0.75_f64..1.25);
    let secs = (exp * jitter).max(1.0);
    pause(secs as f32).await;
}

async fn pause(secs: f32) {
    if secs > 0.0 && enabled() {
        tokio::time::sleep(Duration::from_secs_f32(secs)).await;
    }
}

/// ---- Worker byte-fingerprint humanization ----
///
/// We prepend an innocuous, structurally-varying comment header so no two
/// deployments share a byte fingerprint. Roughly 1 in 5 deployments is left
/// pristine to mimic a human occasionally shipping untouched code.
const EDITORS: &[&str] = &[
    "M. K.", "A. R.", "N. T.", "S. J.", "P. M.", "D. V.", "K. B.", "E. S.", "R. A.", "Sh. N.",
    "B. H.", "G. F.", "H. Z.", "Ma. S.", "F. D.", "C. L.", "O. P.", "L. W.",
];

const NOTES: &[&str] = &[
    "minor cleanup of the upgrade path",
    "refresh deps and bump compatibility date",
    "tidy header and add a couple of comments",
    "tighten the fetch error handling branch",
    "re-format and re-verify against staging",
    "add a note about the env vars used",
    "sync with the latest template release",
    "small wording fix in the inline doc",
    "re-validate module syntax before shipping",
    "move a helper inline, drop the duplicate",
];

const PRISTINE_INVERY: u32 = 5;

fn header_comment(r: &mut impl rand::Rng) -> Vec<u8> {
    let editor = EDITORS[r.gen_range(0..EDITORS.len())];
    let note = NOTES[r.gen_range(0..NOTES.len())];
    let d1 = chrono::NaiveDate::from_ymd_opt(2025, 1, 1).unwrap()
        + chrono::Duration::days(r.gen_range(0..900) as i64);
    let d2 = d1 + chrono::Duration::days(r.gen_range(1..60) as i64);
    let _indent = ["  ", "    ", "\t", "   "][r.gen_range(0..4)];
    let spacer = ["\n", "\n\n", "\n", "\n\n\n"][r.gen_range(0..4)];
    let ci = r.gen_range(1000..10000);
    format!(
        "/*\n * {editor} — {d1} → {d2}\n * {note}.\n * last verified by CI run #{ci}\n */{spacer}"
    )
    .into_bytes()
}

/// Return a functionally-identical worker whose bytes differ per deploy.
pub fn humanize_worker(js: &[u8]) -> Vec<u8> {
    if !enabled() || js.is_empty() {
        return js.to_vec();
    }
    let mut r = rand::thread_rng();
    if r.gen_range(1..=PRISTINE_INVERY) == 1 {
        return js.to_vec();
    }
    let mut out = header_comment(&mut r);
    out.extend_from_slice(js);
    out
}
