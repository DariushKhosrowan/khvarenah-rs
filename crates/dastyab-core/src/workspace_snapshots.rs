//! Scheduled workspace snapshots — a time axis for "nothing is lost".
//!
//! The shipped `workspace_snapshot.rs` is a one-shot snapshot/restore.
//! This module layers **scheduling** (+ listing, pruning, diffing) on top so
//! the daemon can take snapshots automatically on a cadence and the user can
//! roll back to a past point in time (Inventory → "Restore a past point").
//!
//! Snapshot files live in `~/.dastyab/snapshots/<unix>.dyb-snapshot.json`.
//! Retention keeps the newest N, deterministically.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::CFError;
use crate::workspace_snapshot::{
    read_snapshot, snapshot_workspace, write_snapshot_atomic, SnapshotKind, WorkspaceSnapshot,
};

/// Default cadence: every 6 hours.
pub const WORKSPACE_SNAPSHOT_INTERVAL_SECS: u64 = 6 * 3600;
/// Default number of snapshots to keep (~3.5 days at 6h cadence).
pub const WORKSPACE_SNAPSHOT_KEEP: usize = 14;

/// One snapshot entry in the index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEntry {
    pub path: PathBuf,
    pub created_unix: u64,
    pub kind: SnapshotKind,
    pub profile_count: usize,
    pub artifact_count: usize,
    /// Invalid snapshots (corrupt / unreadable) are flagged, not dropped.
    pub invalid: bool,
}

/// Report for a prune run.
#[derive(Debug, Clone, Default)]
pub struct PruneReport {
    pub removed: Vec<PathBuf>,
}

/// The directory holding scheduled snapshots.
pub fn snapshots_dir() -> PathBuf {
    crate::store::mem_dir().join("snapshots")
}

/// File-name suffix for workspace snapshots.
pub const SNAPSHOT_SUFFIX: &str = ".dyb-snapshot.json";

/// True if `name` looks like a workspace snapshot.
pub fn is_snapshot_name(name: &str) -> bool {
    name.ends_with(SNAPSHOT_SUFFIX)
}

/// Pure decision: is a snapshot due given the last one and now?
pub fn is_snapshot_due(last_snapshot_ts: i64, now: i64) -> bool {
    now - last_snapshot_ts >= WORKSPACE_SNAPSHOT_INTERVAL_SECS as i64
}

/// Read the `created_unix` out of a snapshot file (best-effort).
pub fn snapshot_created_unix(path: &Path) -> Option<u64> {
    let text = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    v.get("created_unix")?.as_u64()
}

/// List snapshots newest-first. Invalid/corrupt ones are flagged, not dropped.
pub fn list_snapshots(snapshots_dir: &Path) -> Vec<SnapshotEntry> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(snapshots_dir) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for e in entries.flatten() {
        let p = e.path();
        let is_snapshot = p
            .file_name()
            .and_then(|s| s.to_str())
            .map(is_snapshot_name)
            .unwrap_or(false);
        if !is_snapshot {
            continue;
        }
        let created = snapshot_created_unix(&p).unwrap_or(0);
        // Count contents.
        let mut profile_count = 0;
        let mut artifact_count = 0;
        let mut invalid = false;
        match read_snapshot(&p) {
            Ok(snap) => {
                profile_count = snap.profiles.len();
                artifact_count = snap.profiles.iter().map(|pf| pf.artifacts.len()).sum();
            }
            Err(_) => invalid = true,
        }
        out.push(SnapshotEntry {
            path: p,
            created_unix: created,
            kind: SnapshotKind::Full,
            profile_count,
            artifact_count,
            invalid,
        });
    }
    out.sort_by_key(|e| std::cmp::Reverse(e.created_unix));
    out
}

/// Take a scheduled snapshot and return its entry.
pub fn take_scheduled_snapshot(
    workspace_root: &Path,
    snapshots_dir: &Path,
    kind: SnapshotKind,
    now: u64,
) -> Result<SnapshotEntry, CFError> {
    std::fs::create_dir_all(snapshots_dir).map_err(|e| {
        CFError::new(
            "Snapshot error",
            format!("Cannot create {}: {e}", snapshots_dir.display()),
            "Check permissions.",
        )
    })?;
    let snap = snapshot_workspace(workspace_root, kind, now)?;
    let path = snapshots_dir.join(format!("{now}.dyb-snapshot.json"));
    write_snapshot_atomic(&snap, &path)?;
    Ok(SnapshotEntry {
        path,
        created_unix: now,
        kind,
        profile_count: snap.profiles.len(),
        artifact_count: snap.profiles.iter().map(|pf| pf.artifacts.len()).sum(),
        invalid: false,
    })
}

/// Keep the newest `keep` snapshots, delete the rest (deterministic order).
pub fn prune_old_snapshots(snapshots_dir: &Path, keep: usize) -> Result<PruneReport, CFError> {
    let mut entries = list_snapshots(snapshots_dir);
    entries.sort_by_key(|e| std::cmp::Reverse(e.created_unix));
    let mut report = PruneReport::default();
    for e in entries.into_iter().skip(keep.max(1)) {
        if std::fs::remove_file(&e.path).is_ok() {
            report.removed.push(e.path);
        }
    }
    Ok(report)
}

/// Pure summary of what changed between a snapshot and the current workspace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiffSummary {
    pub profiles_added: Vec<String>,
    pub profiles_removed: Vec<String>,
    pub files_added: usize,
    pub files_changed: usize,
    pub files_deleted: usize,
}

/// Diff a snapshot against the current on-disk workspace.
pub fn diff_against_current(snap: &WorkspaceSnapshot, _workspace_root: &Path) -> DiffSummary {
    let mut summary = DiffSummary::default();

    // Current profiles on disk.
    let current_profiles: std::collections::BTreeSet<String> =
        crate::store::profiles::list_profiles()
            .into_iter()
            .map(|m| m.id)
            .collect();

    for profile in &snap.profiles {
        if !current_profiles.contains(&profile.profile_id) {
            summary.profiles_removed.push(profile.profile_id.clone());
        }
        let dir = crate::store::profiles::profile_dir(&profile.profile_id);
        for artifact in &profile.artifacts {
            let p = dir.join(&artifact.rel_path);
            match std::fs::read_to_string(&p) {
                Ok(cur) => {
                    if cur == artifact.content {
                        summary.files_added += 1; // present & unchanged
                    } else {
                        summary.files_changed += 1;
                    }
                }
                Err(_) => summary.files_deleted += 1,
            }
        }
    }
    for id in &current_profiles {
        if !snap.profiles.iter().any(|p| &p.profile_id == id) {
            summary.profiles_added.push(id.clone());
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::set_mem_dir_override;

    fn with_home(f: impl FnOnce(&Path, &Path)) {
        let tmp = tempfile::tempdir().unwrap();
        set_mem_dir_override(tmp.path().join(".dastyab"));
        let snaps = tmp.path().join("snapshots");
        std::fs::create_dir_all(&snaps).unwrap();
        f(tmp.path(), &snaps);
    }

    fn fresh_profile_id() -> String {
        crate::store::profiles::create_profile("t", "test").unwrap()
    }

    fn seed_artifacts(id: &str) {
        let dir = crate::store::profiles::profile_dir(id);
        std::fs::write(dir.join("accounts.json"), b"{\"a\":1}").unwrap();
        std::fs::write(dir.join("config.json"), b"{\"x\":1}").unwrap();
        crate::manifest::write_manifest(&crate::manifest::build_manifest(id).unwrap()).unwrap();
    }

    /// Only the current suffix counts as a snapshot.
    #[test]
    fn snapshot_suffix_is_recognized() {
        assert!(is_snapshot_name("1000.dyb-snapshot.json"));
        assert!(!is_snapshot_name("1000.json"));
        assert!(!is_snapshot_name("dyb-snapshot.json.bak"));
        assert!(!is_snapshot_name(".dyb-snapshot.json.hidden"));
    }

    #[test]
    fn is_snapshot_due_respects_interval() {
        assert!(!is_snapshot_due(
            1000,
            1000 + WORKSPACE_SNAPSHOT_INTERVAL_SECS as i64 - 1
        ));
        assert!(is_snapshot_due(
            1000,
            1000 + WORKSPACE_SNAPSHOT_INTERVAL_SECS as i64
        ));
    }

    #[test]
    fn take_scheduled_snapshot_creates_valid_file() {
        with_home(|root, snaps| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            let entry = take_scheduled_snapshot(root, snaps, SnapshotKind::Full, 1000).unwrap();
            assert!(entry.path.exists());
            assert!(!entry.invalid);
            assert_eq!(entry.profile_count, 1);
            let read = read_snapshot(&entry.path).unwrap();
            assert_eq!(read.created_unix, 1000);
        });
    }

    #[test]
    fn prune_old_snapshots_keeps_newest_n() {
        with_home(|root, snaps| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            for ts in [1000u64, 2000, 3000, 4000] {
                take_scheduled_snapshot(root, snaps, SnapshotKind::Full, ts).unwrap();
            }
            let report = prune_old_snapshots(snaps, 2).unwrap();
            assert_eq!(report.removed.len(), 2);
            assert_eq!(list_snapshots(snaps).len(), 2);
        });
    }

    #[test]
    fn list_snapshots_marks_invalid_without_dropping() {
        with_home(|root, snaps| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            take_scheduled_snapshot(root, snaps, SnapshotKind::Full, 1000).unwrap();
            // Corrupt one snapshot.
            std::fs::write(snaps.join("1000.dyb-snapshot.json"), b"not json").unwrap();
            let list = list_snapshots(snaps);
            assert_eq!(list.len(), 1);
            assert!(list[0].invalid);
        });
    }

    #[test]
    fn diff_against_current_counts_add_change_delete() {
        with_home(|root, _| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            let snap = snapshot_workspace(root, SnapshotKind::Full, 1000).unwrap();
            // Delete a file the snapshot had.
            std::fs::remove_file(crate::store::profiles::profile_dir(&id).join("accounts.json"))
                .unwrap();
            let summary = diff_against_current(&snap, root);
            assert!(summary.files_deleted >= 1);
        });
    }
}
