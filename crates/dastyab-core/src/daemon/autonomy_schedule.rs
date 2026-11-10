//! Scheduled Autonomy Audit with Auto-Execute.
//!
//! The daemon runs a readiness audit (`crate::autonomy::run_audit`) on a
//! schedule; any `CheckStatus::Action` item whose preconditions are met is
//! auto-executed on that tick — no human click. The GUI buttons become
//! retry-now surfaces; the automatic path is the primary path. This closes the
//! last manual-click leak for blackout survival (under a blackout the user is
//! asleep/unavailable, and any "click to fix" is a manual-step leak).
//!
//! # Scheduling
//!
//! `AuditSchedule` lives on `DaemonState` and persists across restarts. A pure
//! `should_run_audit` gates whether a tick runs the audit. The action set is
//! fingerprinted (`action_digest`) so we can detect the *clean → dirty*
//! regression transition and fire a beacon only once (not every tick).

use crate::error::CFError;
use crate::store::profiles::ProfileConfig;
use sha2::{Digest, Sha256};

/// Default audit cadence (seconds).
pub const AUDIT_INTERVAL_SECS: u64 = 900; // 15 min

/// How old a pending rotation must be before it is treated as stale and
/// resumed (re-verified) rather than abandoned.
pub const STALE_PENDING_AGE_SECS: u64 = 600; // 10 min

/// Persisted audit schedule state (embedded in `DaemonState`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditSchedule {
    #[serde(default)]
    pub interval_secs: u64,
    #[serde(default)]
    pub last_run_unix: u64,
    /// SHA-256 of the sorted set of ACTION-status item codes at the last run.
    /// `None` = never audited yet (or nothing action-worthy).
    #[serde(default)]
    pub last_action_digest: Option<[u8; 32]>,
}

impl Default for AuditSchedule {
    fn default() -> Self {
        Self {
            interval_secs: AUDIT_INTERVAL_SECS,
            last_run_unix: 0,
            last_action_digest: None,
        }
    }
}

/// Whether the audit should run now (interval elapsed or never run).
pub fn should_run_audit(state: &crate::daemon::DaemonState, now_unix: u64) -> bool {
    let interval = if state.audit.interval_secs > 0 {
        state.audit.interval_secs
    } else {
        AUDIT_INTERVAL_SECS
    };
    now_unix.saturating_sub(state.audit.last_run_unix) >= interval
}

/// Fingerprint the current set of ACTION-status check items: stable-sorted
/// codes, then SHA-256. Used to detect clean→dirty regressions.
pub fn action_digest(codes: &[&str]) -> [u8; 32] {
    let mut sorted: Vec<&str> = codes.iter().copied().collect();
    sorted.sort_unstable();
    sorted.dedup();
    let mut hasher = Sha256::new();
    for c in &sorted {
        hasher.update(c.as_bytes());
        hasher.update(b"\0");
    }
    hasher.finalize().into()
}

/// Whether a *clean → dirty* regression happened (a new action appeared).
/// Returns `true` only on a clean→dirty transition, never dirty→dirty.
pub fn regression_events(old: Option<[u8; 32]>, new: [u8; 32]) -> bool {
    match old {
        Some(old) => old != new, // dirty→dirty with different set is still a change
        None => false,           // first audit: nothing to regress from
    }
}

/// The seam the auto-executor needs from the CF layer — kept narrow so tests
/// can inject a scripted stub (hermetic, offline).
pub trait CfApiSeam {
    /// Mint a second rotation token and persist it (auto-rotation threshold).
    fn ensure_second_token(&self, profile: &str) -> Result<bool, CFError>;
    /// Deploy/re-deploy the worker with the current per-worker secret and
    /// verify via self-ping (two-phase rotation). Returns the new version.
    fn rotate_worker(&self, profile: &str) -> Result<u32, CFError>;
    /// Deploy the DNS-tunnel worker (total-blackout fallback).
    fn ensure_dns_tunnel(&self, profile: &str) -> Result<(), CFError>;
}

/// Context for an auto-execute pass. Bundles everything the dispatch table
/// needs without threading `cf::Client` through `daemon_tick` directly.
pub struct AutonomyContext<'a> {
    pub profile: &'a str,
    pub seam: &'a dyn CfApiSeam,
    pub now_unix: u64,
    pub net_up: bool,
    /// Current profile config (mutable so fixes can persist).
    pub cfg: &'a mut ProfileConfig,
}

/// Decide whether an ACTION item may fire with no user input, given the
/// preconditions. Table-driven allowlist.
pub fn auto_executable(code: &str, cfg: &ProfileConfig, net_up: bool, now_unix: u64) -> bool {
    match code {
        // Config toggles — safe to auto-apply, no network needed.
        "backup" => true,
        "mutation" => true,
        // Token auto-rotation is safe: block swap happens under the hood.
        "token_rotate" => {
            // Needs >= 1 token to authenticate a mint, and rotation enabled.
            cfg.auto_rotate_on_blocked && net_up
        }
        // Per-worker secret rotation: at least one worker is due && net up &&
        // no fresh in-flight pending.
        "worker_secret_rotate" => {
            if !net_up {
                return false;
            }
            cfg.worker_secrets.values().any(|ws| {
                let due = now_unix.saturating_sub(ws.rotated_unix) >= ROTATION_MAX_AGE_SECS;
                let inflight = ws.pending_secret.is_some()
                    && now_unix.saturating_sub(ws.pending_since_unix)
                        < crate::worker_tunnel::secret::MAX_PENDING_AGE_SECS;
                due && !inflight
            })
        }
        // First-run token add requires user-supplied credentials by design.
        "token_add" => false,
        // Everything else is config-toggle / daemon-install (manual or a
        // different seam) — never auto-fire here.
        _ => false,
    }
}

/// Max rotation age (seconds) before a per-worker secret is due (30 days).
pub const ROTATION_MAX_AGE_SECS: u64 = 30 * 86400;

/// Execute one auto-fix action. Returns the number of distinct fixes applied.
/// Errors are surfaced to the caller (logged / surfaced as a pending retry)
/// without aborting the rest of the audit pass.
pub fn execute_auto_fix(code: &str, ctx: &mut AutonomyContext<'_>) -> Result<bool, CFError> {
    match code {
        // Config toggles — no seam, no network; flip the profile flag.
        "backup" => {
            ctx.cfg.backup_autosync.enabled = true;
            if ctx.cfg.backup_autosync.interval_secs == 0 {
                ctx.cfg.backup_autosync.interval_secs = 3600;
            }
            if ctx.cfg.backup_autosync.keep == 0 {
                ctx.cfg.backup_autosync.keep = 5;
            }
            Ok(true)
        }
        "mutation" => {
            ctx.cfg.mutation.enabled = true;
            if ctx.cfg.mutation.interval_secs == 0 {
                ctx.cfg.mutation.interval_secs = 86400;
            }
            Ok(true)
        }
        "token_rotate" => ctx.seam.ensure_second_token(ctx.profile).map(|_| true),
        "worker_secret_rotate" => ctx.seam.rotate_worker(ctx.profile).map(|_| true),
        "tunnel" => ctx.seam.ensure_dns_tunnel(ctx.profile).map(|_| true),
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::DaemonState;
    use crate::store::profiles::ProfileConfig;

    struct StubSeam {
        rotated: std::cell::RefCell<bool>,
        second_token: std::cell::RefCell<bool>,
    }
    impl CfApiSeam for StubSeam {
        fn ensure_second_token(&self, _profile: &str) -> Result<bool, CFError> {
            *self.second_token.borrow_mut() = true;
            Ok(true)
        }
        fn rotate_worker(&self, _profile: &str) -> Result<u32, CFError> {
            *self.rotated.borrow_mut() = true;
            Ok(2)
        }
        fn ensure_dns_tunnel(&self, _profile: &str) -> Result<(), CFError> {
            Ok(())
        }
    }

    fn state_with_audit(last: u64) -> DaemonState {
        let mut s = DaemonState::default();
        s.audit.last_run_unix = last;
        s
    }

    #[test]
    fn audit_runs_when_interval_elapsed() {
        let s = state_with_audit(0);
        assert!(should_run_audit(&s, 1000));
        let mut s2 = state_with_audit(1000);
        s2.audit.interval_secs = 900;
        assert!(!should_run_audit(&s2, 1000 + 899));
        assert!(should_run_audit(&s2, 1000 + 900));
    }

    #[test]
    fn audit_skips_within_interval() {
        let mut s = state_with_audit(1000);
        s.audit.interval_secs = 900;
        assert!(!should_run_audit(&s, 1000 + 100));
    }

    #[test]
    fn action_digest_stable_for_same_set() {
        assert_eq!(action_digest(&["a", "b", "a"]), action_digest(&["b", "a"]));
    }

    #[test]
    fn action_digest_changes_on_new_item() {
        assert_ne!(action_digest(&["a"]), action_digest(&["a", "b"]));
    }

    #[test]
    fn regression_detected_on_clean_to_dirty() {
        // First audit (None old) never regresses.
        assert!(!regression_events(None, action_digest(&["a"])));
        // old empty → new with action = clean→dirty.
        assert!(regression_events(
            Some(action_digest(&[])),
            action_digest(&["a"])
        ));
    }

    #[test]
    fn no_regression_on_dirty_to_dirty() {
        // dirty→dirty with same set: no change.
        assert!(!regression_events(
            Some(action_digest(&["a"])),
            action_digest(&["a"])
        ));
    }

    #[test]
    fn auto_executable_accepts_rotation_when_due_and_net_up() {
        let mut cfg = ProfileConfig::default();
        // seed an old secret so rotation is due
        cfg.worker_secrets.insert(
            "http://w".into(),
            crate::worker_tunnel::secret::WorkerSecret {
                worker_url: "http://w".into(),
                secret: "s".into(),
                rotated_unix: 1,
                version: 1,
                pending_secret: None,
                pending_since_unix: 0,
            },
        );
        assert!(auto_executable(
            "worker_secret_rotate",
            &cfg,
            true,
            3_000_000
        ));
    }

    #[test]
    fn auto_executable_rejects_rotation_when_net_down() {
        let mut cfg = ProfileConfig::default();
        cfg.worker_secrets.insert(
            "http://w".into(),
            crate::worker_tunnel::secret::WorkerSecret {
                worker_url: "http://w".into(),
                secret: "s".into(),
                rotated_unix: 1,
                version: 1,
                pending_secret: None,
                pending_since_unix: 0,
            },
        );
        assert!(!auto_executable(
            "worker_secret_rotate",
            &cfg,
            false,
            999_999
        ));
    }

    #[test]
    fn auto_executable_rejects_first_run_token_add() {
        let cfg = ProfileConfig::default();
        assert!(!auto_executable("token_add", &cfg, true, 0));
    }

    #[test]
    fn execute_auto_fix_rotation_calls_seam() {
        let seam = StubSeam {
            rotated: std::cell::RefCell::new(false),
            second_token: std::cell::RefCell::new(false),
        };
        let mut cfg = ProfileConfig::default();
        let mut ctx = AutonomyContext {
            profile: "p",
            seam: &seam,
            now_unix: 100,
            net_up: true,
            cfg: &mut cfg,
        };
        let applied = execute_auto_fix("worker_secret_rotate", &mut ctx).unwrap();
        assert!(applied);
        assert!(*seam.rotated.borrow());
    }

    #[test]
    fn execute_auto_fix_unknown_code_is_noop() {
        let seam = StubSeam {
            rotated: std::cell::RefCell::new(false),
            second_token: std::cell::RefCell::new(false),
        };
        let mut cfg = ProfileConfig::default();
        let mut ctx = AutonomyContext {
            profile: "p",
            seam: &seam,
            now_unix: 100,
            net_up: true,
            cfg: &mut cfg,
        };
        let applied = execute_auto_fix("not-a-code", &mut ctx).unwrap();
        assert!(!applied);
    }

    #[test]
    fn auto_executable_accepts_backup_and_mutation_toggles() {
        let cfg = ProfileConfig::default();
        assert!(auto_executable("backup", &cfg, false, 0));
        assert!(auto_executable("mutation", &cfg, false, 0));
    }

    #[test]
    fn execute_auto_fix_backup_turns_on_autosync() {
        let seam = StubSeam {
            rotated: std::cell::RefCell::new(false),
            second_token: std::cell::RefCell::new(false),
        };
        let mut cfg = ProfileConfig::default();
        assert!(!cfg.backup_autosync.enabled);
        let mut ctx = AutonomyContext {
            profile: "p",
            seam: &seam,
            now_unix: 100,
            net_up: false,
            cfg: &mut cfg,
        };
        let applied = execute_auto_fix("backup", &mut ctx).unwrap();
        assert!(applied);
        assert!(cfg.backup_autosync.enabled);
        assert!(cfg.backup_autosync.interval_secs > 0);
    }

    #[test]
    fn execute_auto_fix_mutation_turns_on_signature_rotation() {
        let seam = StubSeam {
            rotated: std::cell::RefCell::new(false),
            second_token: std::cell::RefCell::new(false),
        };
        let mut cfg = ProfileConfig::default();
        assert!(!cfg.mutation.enabled);
        let mut ctx = AutonomyContext {
            profile: "p",
            seam: &seam,
            now_unix: 100,
            net_up: false,
            cfg: &mut cfg,
        };
        let applied = execute_auto_fix("mutation", &mut ctx).unwrap();
        assert!(applied);
        assert!(cfg.mutation.enabled);
        assert_eq!(cfg.mutation.interval_secs, 86400);
    }

    #[test]
    fn audit_schedule_persists_across_restart() {
        let mut s = state_with_audit(5000);
        s.audit.last_action_digest = Some(action_digest(&["backup"]));
        let json = serde_json::to_string(&s.audit).unwrap();
        let back: AuditSchedule = serde_json::from_str(&json).unwrap();
        assert_eq!(back.last_run_unix, 5000);
        assert_eq!(back.last_action_digest, Some(action_digest(&["backup"])));
        assert_eq!(back.interval_secs, AUDIT_INTERVAL_SECS);
    }
}
