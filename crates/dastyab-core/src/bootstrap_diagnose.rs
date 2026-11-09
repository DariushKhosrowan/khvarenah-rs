//! Fail-fast diagnosis for `dastyab up` — the "last manual step".
//!
//! The mission is zero manual steps. The honest failure mode is NOT "✓
//! Protection active" while the user's internet is still broken. So the
//! bootstrap must either produce a working bundle quickly, or exit non-zero
//! with exactly ONE plain-language sentence telling the user the specific
//! blocker and the single thing they can do about it.
//!
//! This module is the pure, human-facing translation of that contract. Every
//! `UpFailure` variant has:
//! - `plain_message` — no internal protocol jargon (asserted by the
//!   `test_diagnose_plain_message_contains_no_internal_terms` test), and
//! - `recommended_action` — one shell command / one URL / "no action".
//!
//! Exit codes (scriptable via `$?`): 0=ok, 1=no token, 2=token invalid,
//! 3=worker unavailable, 4=discovery failed, 5=bundle write, 6=daemon start.
//!
//! No I/O here — the callers feed in the outcome and the last diagnostics.

/// A failure stage of the bootstrap pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpFailure {
    /// No token found in env / file / any profile.
    NoTokenFound,
    /// A token exists but Cloudflare rejected it.
    TokenInvalid { cf_error: String },
    /// Deploying (or re-deploying) the worker failed.
    WorkerDeployFailed { cf_error: String },
    /// The worker exists but is not reachable.
    WorkerUnreachable { worker_health: String },
    /// No candidate IPs were even reachable from this network.
    DiscoveryNoCandidates { phase1_pass: u32, phase1_total: u32 },
    /// Candidates were found but none passed the real handshake. The histogram
    /// top (e.g. "TlsAlert" or "Timeout") is the diagnosis signal for the next
    /// round.
    DiscoveryCandidatesButNoWs { ws_histogram_top: String },
    /// WS-gate passed but E2E tunnel verification failed (e.g. dead worker).
    DiscoveryNoE2e {
        phase2_pass: u32,
        e2e_pass: u32,
        e2e_failure_stage: String,
    },
    /// Clean discovery succeeded but writing the user bundle failed.
    BundleWriteFailed { path: String, reason: String },
    /// The daemon/systemd unit could not be started.
    DaemonStartFailed { reason: String },
}

impl UpFailure {
    /// Human label for the pipeline stage this failure occurred at.
    pub fn stage(&self) -> &'static str {
        match self {
            UpFailure::NoTokenFound | UpFailure::TokenInvalid { .. } => "token",
            UpFailure::WorkerDeployFailed { .. } | UpFailure::WorkerUnreachable { .. } => "worker",
            UpFailure::DiscoveryNoCandidates { .. }
            | UpFailure::DiscoveryCandidatesButNoWs { .. }
            | UpFailure::DiscoveryNoE2e { .. } => "discovery",
            UpFailure::BundleWriteFailed { .. } => "bundle",
            UpFailure::DaemonStartFailed { .. } => "daemon",
        }
    }

    /// Map a failure to its scriptable exit code.
    pub fn exit_code(&self) -> i32 {
        match self {
            UpFailure::NoTokenFound => 1,
            UpFailure::TokenInvalid { .. } => 2,
            UpFailure::WorkerDeployFailed { .. } | UpFailure::WorkerUnreachable { .. } => 3,
            UpFailure::DiscoveryNoCandidates { .. }
            | UpFailure::DiscoveryCandidatesButNoWs { .. }
            | UpFailure::DiscoveryNoE2e { .. } => 4,
            UpFailure::BundleWriteFailed { .. } => 5,
            UpFailure::DaemonStartFailed { .. } => 6,
        }
    }
}

/// A rendered diagnosis: exit code + one plain message + one action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosisResult {
    pub ok: bool,
    pub stage_reached: &'static str,
    pub failure: Option<UpFailure>,
    /// No protocol jargon (asserted by test).
    pub plain_message: String,
    /// One shell command / one URL / "no action".
    pub recommended_action: String,
    pub elapsed_ms: u64,
}

impl std::fmt::Display for DiagnosisResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.ok {
            write!(
                f,
                "✓ Setup complete (stage: {}, {:.1}s). {}",
                self.stage_reached,
                self.elapsed_ms as f64 / 1000.0,
                self.recommended_action
            )
        } else {
            write!(
                f,
                "✗ Setup did not complete (stage: {}). {} Recommended: {}",
                self.stage_reached, self.plain_message, self.recommended_action
            )
        }
    }
}

/// Terms that must never appear in a plain_message.
pub const INTERNAL_TERMS: [&str; 9] = [
    "ws",
    "websocket",
    "sni",
    "tls",
    "e2e",
    "phase1",
    "phase2",
    "uuid",
    "cdn-cgi",
];

fn contains_internal_term(s: &str) -> bool {
    let lower = s.to_lowercase();
    INTERNAL_TERMS.iter().any(|t| lower.contains(t))
}

/// Render a human-facing diagnosis from a failure. Plain messages must never
/// contain internal protocol terms — `test_diagnose_plain_message_contains_no_internal_terms`
/// enforces this for every variant.
pub fn diagnose(failure: &UpFailure, elapsed_ms: u64) -> DiagnosisResult {
    let (plain_message, recommended_action, stage_reached) = match failure {
        UpFailure::NoTokenFound => (
            "No Cloudflare token was found.".to_string(),
            "Run: dastyab token add <token>".to_string(),
            "token",
        ),
        UpFailure::TokenInvalid { cf_error } => {
            let lower = cf_error.to_lowercase();
            if lower.contains("9109") || lower.contains("deactivated") {
                (
                    "Your Cloudflare account is not accessible with this token.".to_string(),
                    "Check your account status and token permissions (Account:Read) at dash.cloudflare.com"
                        .to_string(),
                    "token",
                )
            } else {
                (
                    "Your Cloudflare token was rejected.".to_string(),
                    "Create a new token at dash.cloudflare.com/profile/api-tokens".to_string(),
                    "token",
                )
            }
        }
        UpFailure::WorkerDeployFailed { .. } => (
            "Your Cloudflare worker could not be created.".to_string(),
            "Check your token permissions (Workers:Edit), then run: dastyab up".to_string(),
            "worker",
        ),
        UpFailure::WorkerUnreachable { .. } => (
            "Your worker exists but is not responding.".to_string(),
            "Run: dastyab autopilot health --verbose".to_string(),
            "worker",
        ),
        UpFailure::DiscoveryNoCandidates {
            phase1_pass: _,
            phase1_total: _,
        } => (
            "Cloudflare's IP range is unreachable from this network right now.".to_string(),
            "Try again in 15 minutes, or run: dastyab autopilot health --verbose".to_string(),
            "discovery",
        ),
        UpFailure::DiscoveryCandidatesButNoWs { ws_histogram_top } => {
            let action = match ws_histogram_top.as_str() {
                "TlsAlert" => "This network is actively blocking the connection — try again later."
                    .to_string(),
                "Timeout" => {
                    "This network is slow or throttled — try again in 15 minutes.".to_string()
                }
                _ => "Run: dastyab autopilot health --verbose".to_string(),
            };
            (
                "Candidates were found but the network is blocking their connections.".to_string(),
                action,
                "discovery",
            )
        }
        UpFailure::DiscoveryNoE2e {
            phase2_pass: _,
            e2e_pass: _,
            e2e_failure_stage,
        } => {
            let action = if e2e_failure_stage.contains("IpUnchanged") {
                "If your internet already works, just start using it.".to_string()
            } else {
                "Run: dastyab autopilot health --verbose".to_string()
            };
            (
                "Connections were found but could not be fully verified.".to_string(),
                action,
                "discovery",
            )
        }
        UpFailure::BundleWriteFailed { path, .. } => (
            "The config files could not be written.".to_string(),
            format!("Check write permissions on {path}"),
            "bundle",
        ),
        UpFailure::DaemonStartFailed { .. } => (
            "Protection activates but the background service could not start.".to_string(),
            "Run manually: systemctl --user enable --now dastyab-daemon.service".to_string(),
            "daemon",
        ),
    };

    debug_assert!(
        !contains_internal_term(&plain_message),
        "plain_message leaked an internal term: {plain_message}"
    );

    DiagnosisResult {
        ok: false,
        stage_reached,
        failure: Some(failure.clone()),
        plain_message,
        recommended_action,
        elapsed_ms,
    }
}

/// The success verdict for `dastyab up`.
pub fn success_result(elapsed_ms: u64) -> DiagnosisResult {
    DiagnosisResult {
        ok: true,
        stage_reached: "daemon",
        failure: None,
        plain_message: "✓ Protection active.".to_string(),
        recommended_action: "No action — everything is working".to_string(),
        elapsed_ms,
    }
}

/// Compute the top histogram key as a human string (e.g. "TlsAlert"). Falls
/// back to "Unknown" on an empty histogram.
pub fn ws_histogram_top(
    hist: &std::collections::HashMap<crate::health::WsFailureReason, u32>,
) -> String {
    let top = hist.iter().max_by_key(|(_, &c)| c);
    match top {
        Some((reason, _)) => format!("{reason:?}"),
        None => "Unknown".to_string(),
    }
}

/// Convenience: an empty diagnosis for a timeout (used by the cascade when the
/// guarded cycle aborts under budget).
pub fn timeout_diagnosis(elapsed_ms: u64) -> DiagnosisResult {
    diagnose(
        &UpFailure::DiscoveryCandidatesButNoWs {
            ws_histogram_top: "Timeout".to_string(),
        },
        elapsed_ms,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diagnose_no_token_found_returns_action() {
        let r = diagnose(&UpFailure::NoTokenFound, 0);
        assert_eq!(r.failure.as_ref().unwrap().exit_code(), 1);
        assert_eq!(r.stage_reached, "token");
        assert!(r.plain_message.contains("token"));
        assert!(r.recommended_action.contains("token add"));
    }

    #[test]
    fn test_diagnose_token_invalid_returns_action() {
        let r = diagnose(
            &UpFailure::TokenInvalid {
                cf_error: "x".into(),
            },
            0,
        );
        assert_eq!(r.failure.as_ref().unwrap().exit_code(), 2);
        assert!(r.recommended_action.contains("cloudflare.com"));
    }

    #[test]
    fn test_diagnose_worker_deploy_failed_returns_action() {
        let r = diagnose(
            &UpFailure::WorkerDeployFailed {
                cf_error: "x".into(),
            },
            0,
        );
        assert_eq!(r.failure.as_ref().unwrap().exit_code(), 3);
        assert!(r.plain_message.contains("worker"));
    }

    #[test]
    fn test_diagnose_token_invalid_account_deactivated_surfaces_account() {
        // CF error 9109 = "User was deactivated" → the honest message is an
        // account/permission problem, not a malformed token.
        let r = diagnose(
            &UpFailure::TokenInvalid {
                cf_error: "CF error code 9109, User was deactivated".into(),
            },
            0,
        );
        assert_eq!(r.failure.as_ref().unwrap().exit_code(), 2);
        assert!(r.plain_message.contains("account"));
        assert!(!r.plain_message.contains("rejected"));
    }

    #[test]
    fn test_diagnose_worker_unreachable_returns_action() {
        let r = diagnose(
            &UpFailure::WorkerUnreachable {
                worker_health: "x".into(),
            },
            0,
        );
        assert_eq!(r.failure.as_ref().unwrap().exit_code(), 3);
        assert!(r.recommended_action.contains("autopilot health"));
    }

    #[test]
    fn test_diagnose_discovery_no_candidates_plain_message() {
        let r = diagnose(
            &UpFailure::DiscoveryNoCandidates {
                phase1_pass: 0,
                phase1_total: 2000,
            },
            0,
        );
        assert_eq!(r.failure.as_ref().unwrap().exit_code(), 4);
        assert!(r.plain_message.contains("range"));
    }

    #[test]
    fn test_diagnose_discovery_candidates_no_ws_surfaces_histogram() {
        let r = diagnose(
            &UpFailure::DiscoveryCandidatesButNoWs {
                ws_histogram_top: "TlsAlert".into(),
            },
            0,
        );
        assert_eq!(r.failure.as_ref().unwrap().exit_code(), 4);
        assert!(r.plain_message.contains("blocking"));
    }

    #[test]
    fn test_diagnose_discovery_no_e2e_returns_action() {
        let r = diagnose(
            &UpFailure::DiscoveryNoE2e {
                phase2_pass: 5,
                e2e_pass: 0,
                e2e_failure_stage: "WorkerDead".into(),
            },
            0,
        );
        assert_eq!(r.failure.as_ref().unwrap().exit_code(), 4);
        assert!(r.plain_message.contains("verified"));
    }

    #[test]
    fn test_diagnose_bundle_write_failed() {
        let r = diagnose(
            &UpFailure::BundleWriteFailed {
                path: "/tmp".into(),
                reason: "readonly".into(),
            },
            0,
        );
        assert_eq!(r.failure.as_ref().unwrap().exit_code(), 5);
        assert_eq!(r.stage_reached, "bundle");
    }

    #[test]
    fn test_diagnose_daemon_start_failed() {
        let r = diagnose(
            &UpFailure::DaemonStartFailed {
                reason: "systemd user session unavailable".into(),
            },
            0,
        );
        assert_eq!(r.failure.as_ref().unwrap().exit_code(), 6);
        assert_eq!(r.stage_reached, "daemon");
    }

    #[test]
    fn test_diagnose_plain_message_contains_no_internal_terms() {
        // The one that matters most: a non-technical user must never see
        // protocol jargon. This forces every variant to have an honest,
        // human-facing representation.
        let variants = [
            UpFailure::NoTokenFound,
            UpFailure::TokenInvalid {
                cf_error: "x".into(),
            },
            UpFailure::WorkerDeployFailed {
                cf_error: "x".into(),
            },
            UpFailure::WorkerUnreachable {
                worker_health: "x".into(),
            },
            UpFailure::DiscoveryNoCandidates {
                phase1_pass: 0,
                phase1_total: 2000,
            },
            UpFailure::DiscoveryCandidatesButNoWs {
                ws_histogram_top: "TlsAlert".into(),
            },
            UpFailure::DiscoveryCandidatesButNoWs {
                ws_histogram_top: "Timeout".into(),
            },
            UpFailure::DiscoveryNoE2e {
                phase2_pass: 5,
                e2e_pass: 0,
                e2e_failure_stage: "WorkerDead".into(),
            },
            UpFailure::BundleWriteFailed {
                path: "/tmp".into(),
                reason: "readonly".into(),
            },
            UpFailure::DaemonStartFailed {
                reason: "systemd user session unavailable".into(),
            },
        ];
        for v in variants {
            let r = diagnose(&v, 0);
            let lower = r.plain_message.to_lowercase();
            for term in INTERNAL_TERMS {
                assert!(
                    !lower.contains(term),
                    "plain_message for {:?} leaked internal term '{term}': {:?}",
                    v,
                    r.plain_message
                );
            }
        }
    }

    #[test]
    fn test_exit_codes_are_scriptable() {
        assert_eq!(UpFailure::NoTokenFound.exit_code(), 1);
        assert_eq!(
            UpFailure::TokenInvalid {
                cf_error: "x".into()
            }
            .exit_code(),
            2
        );
        assert_eq!(
            UpFailure::WorkerDeployFailed {
                cf_error: "x".into()
            }
            .exit_code(),
            3
        );
        assert_eq!(
            UpFailure::DiscoveryCandidatesButNoWs {
                ws_histogram_top: "TlsAlert".into()
            }
            .exit_code(),
            4
        );
        assert_eq!(
            UpFailure::DiscoveryNoCandidates {
                phase1_pass: 0,
                phase1_total: 1
            }
            .exit_code(),
            4
        );
        assert_eq!(
            UpFailure::BundleWriteFailed {
                path: "/".into(),
                reason: "x".into()
            }
            .exit_code(),
            5
        );
        assert_eq!(
            UpFailure::DaemonStartFailed { reason: "x".into() }.exit_code(),
            6
        );
    }

    #[test]
    fn test_success_result() {
        let r = success_result(123);
        assert!(r.ok);
        assert!(r.failure.is_none());
        assert!(r.recommended_action.contains("No action"));
    }

    #[test]
    fn test_ws_histogram_top_returns_top_key() {
        use crate::health::WsFailureReason;
        let mut hist = std::collections::HashMap::new();
        hist.insert(WsFailureReason::TlsAlert, 42);
        hist.insert(WsFailureReason::HttpStatus(404), 3);
        assert_eq!(ws_histogram_top(&hist), "TlsAlert");
        assert_eq!(
            ws_histogram_top(&std::collections::HashMap::new()),
            "Unknown"
        );
    }

    #[test]
    fn test_locale_support_is_present() {
        // Locale is used by the caller; here we only assert the type exists and
        // both variants are constructible (guards against a future refactor).
        let _en = crate::diagnose::Locale::En;
        let _fa = crate::diagnose::Locale::Fa;
    }

    #[test]
    fn test_diagnosis_result_display_success() {
        let r = success_result(1234);
        let s = r.to_string();
        assert!(s.contains("✓ Setup complete"), "got: {s}");
        // Success path never surfaces a failure message.
        assert!(!s.contains("✗"));
        assert!(s.contains("1.2s"));
    }

    #[test]
    fn test_diagnosis_result_display_failure() {
        let r = diagnose(&UpFailure::NoTokenFound, 5000);
        let s = r.to_string();
        assert!(s.contains("✗ Setup did not complete"), "got: {s}");
        assert!(s.contains("No Cloudflare token was found"));
        assert!(s.contains("Recommended:"));
    }
}
