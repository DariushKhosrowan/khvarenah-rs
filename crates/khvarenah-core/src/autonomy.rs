//! Hands-off readiness audit — the single source of truth for "is the app
//! fully automatic yet?".
//!
//! Both entry points report the *identical* safeguard status:
//!
//! - CLI: `khvarenah autopilot autonomy` (exit 1 when any ACTION item remains)
//! - GUI: the Autonomy panel (color-coded checklist + one-click config fixes)
//!
//! Each `CheckItem` carries a machine-readable `fix_action` for config-only
//! toggles the GUI can apply with a single click (enable scheduled auto-backup,
//! enable signature rotation). Items that need user-supplied input or
//! networking (DNS tunnel deploy, token add) surface a human-readable `fix`
//! hint instead — the app never fabricates credentials.

use serde::{Deserialize, Serialize};

use crate::daemon::{is_daemon_running, is_linger_enabled, DaemonConfig};
use crate::store::profiles::Profile;

/// Readiness of a single safeguard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckStatus {
    /// Armed and correct.
    Ok,
    /// Needs a one-time action (config toggle or setup step).
    Action,
    /// Needs human-supplied input (credentials / VPS info).
    Manual,
    /// Informational only; not a blocker.
    Info,
}

impl CheckStatus {
    pub fn label(self) -> &'static str {
        match self {
            CheckStatus::Ok => "OK",
            CheckStatus::Action => "ACTION",
            CheckStatus::Manual => "MANUAL",
            CheckStatus::Info => "INFO",
        }
    }
}

/// A config-only toggle the GUI can apply directly, with no human input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FixAction {
    /// Turn on scheduled auto-backup (`backup_autosync.enabled`).
    EnableBackupAutoSync,
    /// Turn on worker-signature rotation (`mutation.enabled`).
    EnableSignatureMutation,
}

/// One row of the autonomy checklist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckItem {
    /// Stable identifier (used as egui id salt).
    pub code: String,
    pub status: CheckStatus,
    pub title: String,
    /// What we observed / why the status is what it is.
    pub detail: String,
    /// Human-readable next step (shown by CLI and GUI alike).
    pub fix: String,
    /// Machine hint for a one-click config fix, when applicable.
    pub fix_action: Option<FixAction>,
}

/// The full readiness report for a profile.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AutonomyReport {
    pub items: Vec<CheckItem>,
}

impl AutonomyReport {
    /// Whether any safeguard still needs a one-time action.
    pub fn needs_action(&self) -> bool {
        self.items.iter().any(|i| i.status == CheckStatus::Action)
    }

    pub fn is_hands_off(&self) -> bool {
        !self.needs_action()
    }
}

/// Compute the hands-off readiness report for `profile`.
///
/// Pure beyond the two system probes (daemon pid file + loginctl linger), both
/// of which are cheap and fail closed to ACTION without panicking.
pub fn run_audit(profile: &Profile) -> AutonomyReport {
    let mut items = Vec::new();

    // 1. Daemon running (protection / self-heal).
    let cfg = DaemonConfig::new(&profile.meta.id);
    let running = is_daemon_running(&cfg.pid_file);
    items.push(CheckItem {
        code: "daemon".into(),
        status: if running {
            CheckStatus::Ok
        } else {
            CheckStatus::Action
        },
        title: "Daemon running".into(),
        detail: if running {
            "protection/self-heal loop is live".into()
        } else {
            "no protection loop running — nothing self-heals".into()
        },
        fix: "`khvarenah daemon install-systemd` + `daemon start`, or `khvarenah up`".into(),
        fix_action: None,
    });

    // 2. Boot-before-login autostart (loginctl linger) — survives blackout reboot.
    match is_linger_enabled() {
        Some(true) => items.push(CheckItem {
            code: "linger".into(),
            status: CheckStatus::Ok,
            title: "Boot autostart".into(),
            detail: "starts before login — survives a blackout reboot".into(),
            fix: String::new(),
            fix_action: None,
        }),
        Some(false) => items.push(CheckItem {
            code: "linger".into(),
            status: CheckStatus::Action,
            title: "Boot autostart".into(),
            detail: "daemon starts only at login".into(),
            fix: "`khvarenah daemon install-systemd` (enables linger)".into(),
            fix_action: None,
        }),
        None => items.push(CheckItem {
            code: "linger".into(),
            status: CheckStatus::Action,
            title: "Boot autostart".into(),
            detail: "unknown (loginctl unavailable)".into(),
            fix: "`khvarenah daemon install-systemd`".into(),
            fix_action: None,
        }),
    }

    // 3. Auto token-rotation (>=2 tokens + enabled).
    let rotate_enabled = profile.config.auto_rotate_on_blocked;
    let token_count = profile.tokens.len();
    let (rot_status, rot_detail, rot_fix) = match (rotate_enabled, token_count >= 2) {
        (true, true) => (
            CheckStatus::Ok,
            format!("{token_count} tokens stored — blocked tokens swap automatically"),
            String::new(),
        ),
        (true, false) => (
            CheckStatus::Action,
            format!("rotation ON but only {token_count} token stored"),
            "`khvarenah token add --label <name> --token <cf-token>`".into(),
        ),
        (false, _) => (
            CheckStatus::Action,
            "auto-rotation OFF — blocked token needs manual recover".into(),
            "toggle ON in GUI Settings (auto-rotation)".into(),
        ),
    };
    items.push(CheckItem {
        code: "token_rotate".into(),
        status: rot_status,
        title: "Auto token-rotation".into(),
        detail: rot_detail,
        fix: rot_fix,
        fix_action: None,
    });

    // 4. Scheduled auto-backup (crash/blackout snapshot).
    let backup_on = profile.config.backup_autosync.enabled;
    items.push(CheckItem {
        code: "backup".into(),
        status: if backup_on {
            CheckStatus::Ok
        } else {
            CheckStatus::Action
        },
        title: "Scheduled auto-backup".into(),
        detail: if backup_on {
            format!(
                "every {}s, keep {}",
                profile.config.backup_autosync.interval_secs, profile.config.backup_autosync.keep
            )
        } else {
            "no crash/blackout snapshot".into()
        },
        fix: "enable in GUI Settings (auto-backup)".into(),
        fix_action: if backup_on {
            None
        } else {
            Some(FixAction::EnableBackupAutoSync)
        },
    });

    // 5. Worker-signature rotation (moving target vs stateful DPI).
    let mutation_on = profile.config.mutation.enabled;
    items.push(CheckItem {
        code: "mutation".into(),
        status: if mutation_on {
            CheckStatus::Ok
        } else {
            CheckStatus::Action
        },
        title: "Signature rotation".into(),
        detail: if mutation_on {
            format!("every {}s", profile.config.mutation.interval_secs)
        } else {
            "not a moving target".into()
        },
        fix: "enable in GUI Settings (signature rotation)".into(),
        fix_action: if mutation_on {
            None
        } else {
            Some(FixAction::EnableSignatureMutation)
        },
    });

    // 6. DNS tunnel (total-blackout survival).
    if crate::vps_deploy::load_tunnel_client_config(&profile.meta.id).is_some() {
        items.push(CheckItem {
            code: "tunnel".into(),
            status: CheckStatus::Ok,
            title: "DNS tunnel".into(),
            detail: "total-blackout fallback configured".into(),
            fix: String::new(),
            fix_action: None,
        });
    } else {
        items.push(CheckItem {
            code: "tunnel".into(),
            status: CheckStatus::Action,
            title: "DNS tunnel".into(),
            detail: "deep blackout has no data channel".into(),
            fix: "`khvarenah dns-tunnel deploy --host <vps> --domain <dns-domain>`".into(),
            fix_action: None,
        });
    }

    // 7. Notifications — informational, not a blocker.
    match profile.config.beacon.as_ref() {
        Some(b) if b.enabled => items.push(CheckItem {
            code: "beacon".into(),
            status: CheckStatus::Ok,
            title: "Remote notifications".into(),
            detail: "Telegram/webhook enabled".into(),
            fix: String::new(),
            fix_action: None,
        }),
        _ => items.push(CheckItem {
            code: "beacon".into(),
            status: CheckStatus::Info,
            title: "Remote notifications".into(),
            detail: "off — events logged to the journal only".into(),
            fix: String::new(),
            fix_action: None,
        }),
    }

    AutonomyReport { items }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::profiles::Profile;

    fn fresh_profile() -> Profile {
        let mut p = Profile::default();
        p.meta.id = "autotest".into();
        p
    }

    #[test]
    fn default_profile_is_not_hands_off() {
        let p = fresh_profile();
        let r = run_audit(&p);
        assert!(r.needs_action());
        // default: backup off, mutation off, auto-rotation on but 0 tokens, daemon off.
        assert!(r
            .items
            .iter()
            .any(|i| i.code == "backup" && i.status == CheckStatus::Action));
        assert!(r
            .items
            .iter()
            .any(|i| i.code == "mutation" && i.status == CheckStatus::Action));
        assert!(r
            .items
            .iter()
            .any(|i| i.code == "token_rotate" && i.status == CheckStatus::Action));
        // backup + mutation are config-only fixes the GUI can apply.
        let backup = r.items.iter().find(|i| i.code == "backup").unwrap();
        assert_eq!(backup.fix_action, Some(FixAction::EnableBackupAutoSync));
        let mutation = r.items.iter().find(|i| i.code == "mutation").unwrap();
        assert_eq!(
            mutation.fix_action,
            Some(FixAction::EnableSignatureMutation)
        );
    }

    #[test]
    fn applying_config_fixes_flips_status_to_ok() {
        let mut p = fresh_profile();
        // Apply the two config-only fixes the GUI would perform.
        p.config.backup_autosync.enabled = true;
        p.config.backup_autosync.interval_secs = 3600;
        p.config.backup_autosync.keep = 5;
        p.config.mutation.enabled = true;
        p.config.mutation.interval_secs = 86400;

        let r = run_audit(&p);
        let backup = r.items.iter().find(|i| i.code == "backup").unwrap();
        assert_eq!(backup.status, CheckStatus::Ok);
        assert_eq!(backup.fix_action, None);
        let mutation = r.items.iter().find(|i| i.code == "mutation").unwrap();
        assert_eq!(mutation.status, CheckStatus::Ok);
    }

    #[test]
    fn two_tokens_and_rotation_on_is_ok() {
        let mut p = fresh_profile();
        p.config.auto_rotate_on_blocked = true;
        p.tokens.insert(
            "a".into(),
            crate::store::profiles::TokenEntry {
                token: "t1".into(),
                ts: "0".into(),
            },
        );
        p.tokens.insert(
            "b".into(),
            crate::store::profiles::TokenEntry {
                token: "t2".into(),
                ts: "0".into(),
            },
        );
        let r = run_audit(&p);
        let tok = r.items.iter().find(|i| i.code == "token_rotate").unwrap();
        assert_eq!(tok.status, CheckStatus::Ok);
    }

    #[test]
    fn report_has_expected_check_codes() {
        let r = run_audit(&fresh_profile());
        let codes: Vec<&str> = r.items.iter().map(|i| i.code.as_str()).collect();
        for expected in [
            "daemon",
            "linger",
            "token_rotate",
            "backup",
            "mutation",
            "tunnel",
        ] {
            assert!(codes.contains(&expected), "missing check {expected}");
        }
    }
}
