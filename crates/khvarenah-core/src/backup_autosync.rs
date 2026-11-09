//! Profile backup auto-sync (round 19 / DeepSeek plan #3).
//!
//! ## Why this exists
//!
//! The user wants the app to be resilient even under a total blackout. If the
//! local profile data is lost (disk failure, OS reinstall, a seized machine),
//! everything configured — worker set, tokens, seeds, bundle — is gone. This
//! module makes the daemon snapshot the profile automatically on a schedule so
//! there is always a recent, restorable copy in `~/.khvarenah/backups/`.
//!
//! It is deliberately small and safe:
//! - pure decision fn (`should_autosync`) that is unit-testable,
//! - a single `run_autosync_if_due` that exports the profile and trims the
//!   backup directory to a keep-count,
//! - wired into the daemon tick like config mutation, so it runs unattended.
//!
//! Retention avoids unbounded growth: only the newest `keep` backups survive.

use crate::error::CFError;

/// Default seconds between auto-backups (24h).
pub const AUTOSYNC_INTERVAL_SECS: u64 = 86400;
/// Default number of backups to keep.
pub const AUTOSYNC_KEEP: usize = 7;

/// Auto-sync settings persisted under `ProfileConfig.backup_autosync`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BackupAutoSyncConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_keep")]
    pub keep: usize,
}

impl Default for BackupAutoSyncConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: default_interval(),
            keep: default_keep(),
        }
    }
}

fn default_interval() -> u64 {
    AUTOSYNC_INTERVAL_SECS
}
fn default_keep() -> usize {
    AUTOSYNC_KEEP
}

/// Pure decision: is an auto-backup due now?
pub fn should_autosync(cfg: &BackupAutoSyncConfig, last_sync_ts: i64, now: i64) -> bool {
    if !cfg.enabled {
        return false;
    }
    if cfg.interval_secs == 0 {
        return false;
    }
    now - last_sync_ts >= cfg.interval_secs as i64
}

/// Trim `backup_dir()` to at most `keep` newest backups. Returns how many were
/// removed. Never removes a non-json file.
pub fn trim_backups(keep: usize) -> usize {
    let mut records = crate::backup::list_backups();
    records.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
    });
    let mut removed = 0;
    for r in records.into_iter().skip(keep.max(1)) {
        let is_json = std::path::Path::new(&r.path)
            .extension()
            .and_then(|e| e.to_str())
            == Some("json");
        if is_json && std::fs::remove_file(&r.path).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Run one auto-backup if due. Returns `Some(path)` if a backup was written,
/// `None` if not due (or disabled). Never errors on a due-but-failed export —
/// returns the error for the caller to log, and the daemon will retry next tick.
pub fn run_autosync_if_due(cfg: &BackupAutoSyncConfig, profile_id: &str, last_sync_ts: i64, now: i64) -> Result<Option<std::path::PathBuf>, CFError> {
    if !should_autosync(cfg, last_sync_ts, now) {
        return Ok(None);
    }
    let path = crate::backup::export_profile_to_file(profile_id, None)?;
    trim_backups(cfg.keep);
    Ok(Some(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_autosync_obeys_enabled_and_interval() {
        let cfg = BackupAutoSyncConfig::default(); // enabled=false
        assert!(!should_autosync(&cfg, 0, 1_000_000));
        let mut cfg = cfg;
        cfg.enabled = true;
        assert!(!should_autosync(&cfg, 0, 100)); // not yet
        assert!(should_autosync(&cfg, 0, 86400 + 1));
    }

    #[test]
    fn should_autosync_false_when_interval_zero() {
        let cfg = BackupAutoSyncConfig {
            enabled: true,
            interval_secs: 0,
            keep: 7,
        };
        assert!(!should_autosync(&cfg, 0, 1_000_000));
    }

    #[test]
    fn trim_backups_removes_oldest_beyond_keep() {
        let tmp = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(tmp.path().to_path_buf());
        // Touch 5 json files with distinct mtimes.
        for i in 0..5 {
            let p = crate::backup::backup_dir().join(format!("prof-{i}.json"));
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, "{}").unwrap();
            let t = std::time::SystemTime::UNIX_EPOCH
                + std::time::Duration::from_secs(1_000_000 + i as u64);
            let _ = filetime::set_file_mtime(&p, filetime::FileTime::from_system_time(t));
        }
        let removed = trim_backups(2);
        assert_eq!(removed, 3);
        assert_eq!(crate::backup::list_backups().len(), 2);
    }

    #[test]
    fn run_autosync_writes_and_creates_backup() {
        let tmp = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(tmp.path().to_path_buf());
        let id = crate::store::profiles::create_profile("t", "").unwrap();
        let cfg = BackupAutoSyncConfig {
            enabled: true,
            interval_secs: 1,
            keep: 3,
        };
        // Not due yet.
        assert!(run_autosync_if_due(&cfg, &id, 0, 0).unwrap().is_none());
        // Due: interval 1s, now far past.
        let path = run_autosync_if_due(&cfg, &id, 0, 100).unwrap();
        assert!(path.is_some());
        assert!(path.unwrap().exists());
    }
}
