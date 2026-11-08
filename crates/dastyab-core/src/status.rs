//! One-press simplified status helpers (DeepSeek plan, feature 3).
//!
//! A non-technical user never wants to see SNI, port, worker name, UUID, or
//! the word "endpoint". These pure helpers turn internal state into a single
//! human line: «✓ Connected — best IP 104.16.1.1, 48ms».

use crate::autopilot::{CleanEndpoint, CycleSummary};

/// Turn a `CycleSummary` into one human line that never leaks internals.
///
/// Never includes SNI, port, worker name, UUID, or "endpoint". Only IPs,
/// RTTs, and a one-word status.
pub fn simplify_status(summary: &CycleSummary) -> String {
    if summary.note.contains("error") || summary.note.contains("failed") {
        return "⚠ Last check failed, retrying".to_string();
    }
    if summary.alive == 0 {
        return "Searching for a clean IP…".to_string();
    }
    format!(
        "✓ Connected — {} clean IP{} ready",
        summary.alive,
        if summary.alive == 1 { "" } else { "s" }
    )
}

/// Pick the caption for the single best clean endpoint (highest score, alive).
/// Returns e.g. "104.16.1.1 (48ms)" — never sni/port/uuid.
pub fn pick_best_caption(endpoints: &[CleanEndpoint]) -> String {
    let best = endpoints
        .iter()
        .filter(|e| e.verified && e.alive)
        .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal));
    match best {
        Some(ep) => format!("{} ({}ms)", ep.ip, ep.tcp_ms.round() as u32),
        None => "Searching…".to_string(),
    }
}

/// Should the app auto-start a first cycle? True iff this profile has not yet
/// written any active config (first launch).
pub fn should_auto_start(profile_id: &str) -> bool {
    let dir = crate::autopilot::active_configs_dir(profile_id);
    if !dir.exists() {
        return true;
    }
    let has_link = dir.join("link.txt").exists();
    !has_link
}

/// Human-friendly one-line bundle status: where the user's configs live and
/// the current best IP, or a nudge to run autopilot.
pub fn bundle_status(profile_id: &str) -> String {
    let dir = crate::cleanip::user_config_dir(profile_id);
    let dir = match dir {
        Ok(d) => d,
        Err(_) => return "Configs not available yet.".to_string(),
    };
    let ok = dir.join("active.vless").exists();
    if ok {
        format!("Configs ready at {}", dir.display())
    } else {
        format!("No configs yet — start autopilot. ({})", dir.display())
    }
}

/// Return a short, terminal-safe summary line the CLI prints after a cycle.
pub fn cli_line(summary: &CycleSummary) -> String {
    format!("[cycle {}] {}", summary.cycle, summary.note)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(ip: &str, score: f32, alive: bool) -> CleanEndpoint {
        CleanEndpoint {
            ip: ip.into(),
            port: 443,
            sni: "worker.workers.dev".into(),
            score,
            tcp_ms: 48.0,
            connect_ms: 50.0,
            download_kbps: 800.0,
            verified: true,
            alive,
            last_checked: Some("2026-11-08T00:00:00Z".into()),
            ts: "2026-11-08T00:00:00Z".into(),
        }
    }

    #[test]
    fn simplify_status_hides_internal_fields() {
        let s = CycleSummary { cycle: 3, alive: 2, replaced: 1, note: "monitor: 2 alive".into() };
        let line = simplify_status(&s);
        assert!(line.contains("✓"));
        assert!(line.contains("2"));
        assert!(!line.contains("endpoint"));
        assert!(!line.contains("sni"));
        assert!(!line.contains("port"));
    }

    #[test]
    fn simplify_status_searching_when_zero_alive() {
        let s = CycleSummary { cycle: 1, alive: 0, replaced: 0, note: "found 0".into() };
        assert!(simplify_status(&s).contains("Searching"));
    }

    #[test]
    fn simplify_status_error_hint() {
        let s = CycleSummary { cycle: 1, alive: 0, replaced: 0, note: "monitor error: net".into() };
        assert!(simplify_status(&s).contains("retrying"));
    }

    #[test]
    fn pick_best_caption_uses_top_score() {
        let eps = vec![ep("104.16.1.1", 5.0, true), ep("104.16.2.2", 9.0, true)];
        let caption = pick_best_caption(&eps);
        assert!(caption.contains("104.16.2.2"));
        assert!(caption.contains("48ms"));
        assert!(!caption.contains("sni"));
    }

    #[test]
    fn pick_best_caption_ignores_dead() {
        let eps = vec![ep("104.16.1.1", 9.0, false), ep("104.16.2.2", 3.0, true)];
        let caption = pick_best_caption(&eps);
        assert!(caption.contains("104.16.2.2"));
    }

    #[test]
    fn should_auto_start_true_when_no_configs() {
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(dir.path().join(".dastyab"));
        crate::store::profiles::create_profile("fresh", "").unwrap();
        assert!(should_auto_start("fresh"));
    }
}
