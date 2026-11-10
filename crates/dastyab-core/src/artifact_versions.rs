//! Per-artifact version history (second-by-second recovery).
//!
//! The ledger append-only guard (`ledger_guard`) detects loss but does not
//! recover it, and workspace snapshots are hours apart — a bad edit at 3h is
//! unrecoverable today. This module gives per-artifact version snapshots on the
//! files that matter (ledgers, profile.json, token.json, config.json, …): every
//! time a durable artifact is about to be rewritten, the *previous* bytes are
//! snapshotted under `<rel_path>.versions/<unix_ms>.json` and indexed in
//! `<rel_path>.versions/index.json`. A later `restore_version` can roll back to
//! any prior version — second-by-second recovery between workspace snapshots.
//!
//! ## Semantics
//! - Versions are immutable: a snapshot is never modified in place.
//! - `snapshot_before_write` snapshots the OLD bytes only when (a) a prior file
//!   exists and (b) the new bytes differ — a no-op rewrite doesn't spawn a
//!   pointless version.
//! - `restore_version` first snapshots the CURRENT file (so a restore is itself
//!   recoverable), then writes the restored bytes. For ledger paths the restore
//!   goes through the append-only guard, so it cannot shrink a ledger below its
//!   high-water mark.
//! - Version keys are unix milliseconds, so two snapshots within the same
//!   second are distinct. `VERSIONS_KEEP` bounds the retained history.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ledger_guard::{check_append_only, read_ledger_count, LedgerKind};
use crate::store::atomic_write;
use sha2::Digest;

/// How many versions to keep per artifact (newest N).
pub const VERSIONS_KEEP: usize = 20;

/// One stored version of an artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactVersion {
    /// Relative path within the profile dir, e.g. `"history.json"`.
    pub rel_path: String,
    /// Snapshot time as unix milliseconds (monotonic within a process).
    pub saved_unix: u64,
    /// SHA-256 (hex) of the stored bytes.
    pub sha256: String,
    /// Byte length of the stored content.
    pub size: u64,
}

/// Errors for the per-artifact version store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionError {
    /// I/O / serialization failure.
    Io(String),
    /// The requested version does not exist.
    NotFound { rel_path: String, unix: u64 },
    /// The stored bytes do not match their recorded hash (corruption).
    HashMismatch { expected: String, actual: String },
    /// The ledger guard refused the restore (would shrink below high-water).
    AppendOnly(String),
}

impl std::fmt::Display for VersionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VersionError::Io(msg) => write!(f, "version io: {msg}"),
            VersionError::NotFound { rel_path, unix } => {
                write!(f, "no saved version {unix} for {rel_path}")
            }
            VersionError::HashMismatch { expected, actual } => {
                write!(f, "version hash mismatch (expected {expected}, got {actual})")
            }
            VersionError::AppendOnly(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for VersionError {}

/// The directory holding all versions for one artifact.
fn versions_dir(profile_dir: &Path, rel_path: &str) -> PathBuf {
    profile_dir.join(format!("{rel_path}.versions"))
}

/// The per-artifact version index file.
fn index_path(profile_dir: &Path, rel_path: &str) -> PathBuf {
    versions_dir(profile_dir, rel_path).join("index.json")
}

/// The on-disk file for one version.
fn version_file(vdir: &Path, unix: u64) -> PathBuf {
    vdir.join(format!("{unix}.json"))
}

/// Read the version index (empty when missing/corrupt).
fn read_index(profile_dir: &Path, rel_path: &str) -> Vec<ArtifactVersion> {
    crate::store::read_opt::<Vec<ArtifactVersion>>(&index_path(profile_dir, rel_path))
        .unwrap_or_default()
}

/// Persist the version index.
fn write_index(profile_dir: &Path, rel_path: &str, versions: &[ArtifactVersion]) -> Result<(), VersionError> {
    let list: Vec<ArtifactVersion> = versions.to_vec();
    crate::store::write_json(&index_path(profile_dir, rel_path), &list)
        .map_err(|e| VersionError::Io(e.brief()))
}

/// Hex (lowercase) of a byte slice.
fn hex_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Store the given bytes as a new version of `rel_path`, appending to the index.
/// Returns the created version. Does NOT touch the live artifact file.
fn record_version(
    profile_dir: &Path,
    rel_path: &str,
    bytes: &[u8],
    now_ms: u64,
) -> Result<ArtifactVersion, VersionError> {
    let vdir = versions_dir(profile_dir, rel_path);
    std::fs::create_dir_all(&vdir).map_err(|e| VersionError::Io(format!("create {vdir:?}: {e}")))?;

    let sha256 = hex_bytes(&sha2::Sha256::digest(bytes));
    let version = ArtifactVersion {
        rel_path: rel_path.to_string(),
        saved_unix: now_ms,
        size: bytes.len() as u64,
        sha256: sha256.clone(),
    };

    // Persist the snapshot as {"sha256", "bytes_b64"} — JSON-encoded so the
    // stored byte count is unambiguous and the file is human-inspectable.
    let payload = serde_json::json!({
        "sha256": sha256,
        "bytes_b64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes),
    });
    let payload_bytes = serde_json::to_vec_pretty(&payload)
        .map_err(|e| VersionError::Io(format!("serialize snapshot: {e}")))?;
    atomic_write(&version_file(&vdir, now_ms), &payload_bytes)
        .map_err(|e| VersionError::Io(e.brief()))?;

    let mut all = read_index(profile_dir, rel_path);
    all.push(version.clone());
    write_index(profile_dir, rel_path, &all)?;

    // Bound the retained history on every version write: the atomic_write hook
    // is the hot path, and without this the per-artifact version dirs would
    // grow without limit (disk exhaustion exactly when the user needs a write
    // to succeed). prune_versions is deterministic and keeps the newest N.
    let _ = prune_versions(profile_dir, rel_path, VERSIONS_KEEP);

    Ok(version)
}

/// Snapshot the current on-disk bytes of `rel_path` *before* it is overwritten
/// with `new_bytes`. Returns `Ok(None)` when there is no prior file or when the
/// new bytes are byte-identical to the current content (a no-op rewrite).
pub fn snapshot_before_write(
    profile_dir: &Path,
    rel_path: &str,
    new_bytes: &[u8],
    now_ms: u64,
) -> Result<Option<ArtifactVersion>, VersionError> {
    let path = profile_dir.join(rel_path);
    if !path.exists() {
        return Ok(None);
    }
    let old = std::fs::read(&path).map_err(|e| VersionError::Io(format!("read {path:?}: {e}")))?;
    if old == new_bytes {
        return Ok(None);
    }
    record_version(profile_dir, rel_path, &old, now_ms).map(Some)
}

/// List all saved versions for an artifact, newest first.
pub fn list_versions(profile_dir: &Path, rel_path: &str) -> Result<Vec<ArtifactVersion>, VersionError> {
    let mut all = read_index(profile_dir, rel_path);
    all.sort_by_key(|a| std::cmp::Reverse(a.saved_unix));
    Ok(all)
}

/// Read the raw bytes of a saved version, verifying its recorded SHA-256.
pub fn read_version_bytes(
    profile_dir: &Path,
    rel_path: &str,
    unix: u64,
) -> Result<Vec<u8>, VersionError> {
    let all = read_index(profile_dir, rel_path);
    let entry = all
        .into_iter()
        .find(|v| v.saved_unix == unix)
        .ok_or(VersionError::NotFound {
            rel_path: rel_path.to_string(),
            unix,
        })?;

    let vdir = versions_dir(profile_dir, rel_path);
    let bytes = std::fs::read(version_file(&vdir, unix))
        .map_err(|e| VersionError::Io(format!("read version {unix}: {e}")))?;
    let payload: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| VersionError::Io(format!("parse version {unix}: {e}")))?;
    let b64 = payload
        .get("bytes_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| VersionError::Io(format!("version {unix} missing bytes_b64")))?;
    let data = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
        .map_err(|e| VersionError::Io(format!("decode version {unix}: {e}")))?;

    let actual = hex_bytes(&sha2::Sha256::digest(&data));
    if actual != entry.sha256 {
        return Err(VersionError::HashMismatch {
            expected: entry.sha256,
            actual,
        });
    }
    Ok(data)
}

/// Resolve the ledger kind for a profile artifact filename, if it is a ledger.
fn ledger_kind_for_filename(name: &str) -> Option<LedgerKind> {
    LedgerKind::all().iter().find(|k| k.filename() == name).copied()
}

/// Write restored bytes to the live artifact, respecting the append-only guard
/// for ledger paths.
fn write_restored(profile_dir: &Path, rel_path: &str, bytes: &[u8], now_secs: u64) -> Result<(), VersionError> {
    if let Some(kind) = ledger_kind_for_filename(rel_path) {
        let live_path = profile_dir.join(rel_path);
        let old_count = read_ledger_count(&live_path);
        let new_count = serde_json::from_slice::<serde_json::Value>(bytes)
            .ok()
            .and_then(|v| v.as_array().map(|a| a.len() as u64))
            .unwrap_or(0);
        check_append_only(kind, old_count, new_count)
            .map_err(|e| VersionError::AppendOnly(e.to_string()))?;
    }
    atomic_write(&profile_dir.join(rel_path), bytes).map_err(|e| VersionError::Io(e.brief()))?;
    // Keep the manifest in sync with the restored content.
    let _ = crate::manifest::refresh_manifest_after_write(profile_dir, now_secs);
    Ok(())
}

/// Restore an artifact to a saved version. The current live file is first
/// snapshotted as a new version (so the rollback is itself recoverable), then
/// the restored bytes are written. Ledger artifacts respect the append-only
/// guard and refuse a restore that would shrink below the high-water mark.
pub fn restore_version(
    profile_dir: &Path,
    rel_path: &str,
    unix: u64,
    now: u64,
) -> Result<(), VersionError> {
    let bytes = read_version_bytes(profile_dir, rel_path, unix)?;
    let now_ms = now.saturating_mul(1000);
    let live_path = profile_dir.join(rel_path);
    if live_path.exists() {
        let current = std::fs::read(&live_path)
            .map_err(|e| VersionError::Io(format!("read live {live_path:?}: {e}")))?;
        record_version(profile_dir, rel_path, &current, now_ms)?;
    }
    write_restored(profile_dir, rel_path, &bytes, now)
}

/// Report from pruning an artifact's version history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneReport {
    /// Versions kept (newest first).
    pub kept: u64,
    /// Versions removed.
    pub removed: u64,
}

/// Deterministically keep the newest `keep` versions of an artifact, deleting
/// older snapshot files and rewriting the index.
pub fn prune_versions(
    profile_dir: &Path,
    rel_path: &str,
    keep: usize,
) -> Result<PruneReport, VersionError> {
    let mut all = read_index(profile_dir, rel_path);
    all.sort_by_key(|a| std::cmp::Reverse(a.saved_unix));
    let vdir = versions_dir(profile_dir, rel_path);
    let removed = all.len().saturating_sub(keep);
    let keep_count = all.len().min(keep);
    let truncated: Vec<ArtifactVersion> = all.into_iter().take(keep).collect();
    // Delete the dropped snapshot files (best-effort).
    let dropped: Vec<u64> = read_index(profile_dir, rel_path)
        .into_iter()
        .map(|v| v.saved_unix)
        .collect();
    for unix in dropped.into_iter().skip(keep_count) {
        let _ = std::fs::remove_file(version_file(&vdir, unix));
    }
    write_index(profile_dir, rel_path, &truncated)?;
    Ok(PruneReport {
        kept: keep_count as u64,
        removed: removed as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run `f` with an isolated in-memory home and a fresh profile. The
    /// tempdir is kept alive for the duration of `f` so the profile dir exists.
    fn with_tmp(f: impl FnOnce(PathBuf)) {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join(".dastyab");
        crate::store::set_mem_dir_override(base);
        let id = crate::store::profiles::create_profile("v", "versions").unwrap();
        let dir = crate::store::profiles::profile_dir(&id);
        f(dir);
    }

    #[test]
    fn snapshot_before_write_creates_first_version_from_existing_file() {
        with_tmp(|dir| {
        std::fs::write(dir.join("config.json"), br#"{"x":1}"#).unwrap();
        let v = snapshot_before_write(&dir, "config.json", br#"{"x":2}"#, 1000)
            .unwrap()
            .expect("a prior file exists, so a version should be created");
        assert_eq!(v.rel_path, "config.json");
        assert_eq!(v.saved_unix, 1000);
        assert_eq!(v.size, 7); // b'{"x":1}' is 7 bytes
        // The stored bytes are the OLD content.
        assert_eq!(read_version_bytes(&dir, "config.json", 1000).unwrap(), br#"{"x":1}"#);
        });
    }

    #[test]
    fn snapshot_before_write_noops_when_file_absent() {
        with_tmp(|dir| {
        assert!(snapshot_before_write(&dir, "history.json", b"[1]", 1000)
            .unwrap()
            .is_none());
        });
    }

    #[test]
    fn snapshot_before_write_skips_when_bytes_identical() {
        with_tmp(|dir| {
        std::fs::write(dir.join("config.json"), br#"{"x":1}"#).unwrap();
        assert!(snapshot_before_write(&dir, "config.json", br#"{"x":1}"#, 1000)
            .unwrap()
            .is_none());
        });
    }

    #[test]
    fn list_versions_sorted_newest_first() {
        with_tmp(|dir| {
        std::fs::write(dir.join("config.json"), b"a").unwrap();
        snapshot_before_write(&dir, "config.json", b"b", 1000).unwrap();
        snapshot_before_write(&dir, "config.json", b"c", 2000).unwrap();
        snapshot_before_write(&dir, "config.json", b"d", 3000).unwrap();
        let all = list_versions(&dir, "config.json").unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].saved_unix, 3000);
        assert_eq!(all[1].saved_unix, 2000);
        assert_eq!(all[2].saved_unix, 1000);
        });
    }

    #[test]
    fn read_version_bytes_rejects_sha256_mismatch() {
        with_tmp(|dir| {
        std::fs::write(dir.join("config.json"), b"x").unwrap();
        snapshot_before_write(&dir, "config.json", b"y", 1000).unwrap();
        // Tamper with the stored snapshot payload. The stored version holds
        // b'x' (the OLD content before the "y" write), so encode a different
        // byte (b'z' -> "eg==") to force a hash mismatch.
        let vdir = versions_dir(&dir, "config.json");
        std::fs::write(version_file(&vdir, 1000), r#"{"sha256":"00","bytes_b64":"eg=="}"#).unwrap();
        let err = read_version_bytes(&dir, "config.json", 1000).unwrap_err();
        assert!(matches!(err, VersionError::HashMismatch { .. }));
        });
    }

    #[test]
    fn restore_version_snapshots_current_before_overwrite() {
        with_tmp(|dir| {
        std::fs::write(dir.join("config.json"), br#"{"x":1}"#).unwrap();
        snapshot_before_write(&dir, "config.json", br#"{"x":2}"#, 1000).unwrap();
        std::fs::write(dir.join("config.json"), br#"{"x":9}"#).unwrap();
        // Restore to unix=1000 (the version holding {"x":1}).
        restore_version(&dir, "config.json", 1000, 5000).unwrap();
        assert_eq!(std::fs::read(dir.join("config.json")).unwrap(), br#"{"x":1}"#);
        // The pre-restore state ({"x":9}) was itself snapshotted.
        assert!(list_versions(&dir, "config.json").unwrap().iter().any(|v| v.saved_unix == 5_000_000));
        });
    }

    #[test]
    fn restore_version_respects_ledger_append_only_guard() {
        with_tmp(|dir| {
        // Seed a history ledger with 3 records via the guarded writer.
        crate::ledger_guard::write_ledger_guarded::<u64>(&dir, LedgerKind::History, &[1, 2, 3], 100).unwrap();
        // Snapshot the 3-record state.
        snapshot_before_write(&dir, "history.json", b"[1,2,3,4]", 1000).unwrap();
        // Grow to 4, then attempt to restore the 3-record version — refused.
        std::fs::write(dir.join("history.json"), b"[1,2,3,4]").unwrap();
        let err = restore_version(&dir, "history.json", 1000, 2000).unwrap_err();
        assert!(matches!(err, VersionError::AppendOnly(_)));
        // Live file untouched.
        assert_eq!(std::fs::read(dir.join("history.json")).unwrap(), b"[1,2,3,4]");
        });
    }

    #[test]
    fn prune_versions_keeps_newest_n_deterministic() {
        with_tmp(|dir| {
        std::fs::write(dir.join("config.json"), b"a").unwrap();
        for i in 1..=5u64 {
            snapshot_before_write(&dir, "config.json", format!("v{i}").as_bytes(), i * 1000).unwrap();
        }
        let report = prune_versions(&dir, "config.json", 3).unwrap();
        assert_eq!(report.kept, 3);
        assert_eq!(report.removed, 2);
        let all = list_versions(&dir, "config.json").unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].saved_unix, 5000);
        assert_eq!(all[2].saved_unix, 3000);
        });
    }

    #[test]
    fn write_path_prunes_to_versions_keep() {
        // The atomic_write hook path (via record_version) must never grow a
        // version dir past VERSIONS_KEEP — the architect's disk-exhaustion
        // concern. Exceed the cap and assert only the newest survive.
        with_tmp(|dir| {
            std::fs::write(dir.join("config.json"), b"base").unwrap();
            let cap: u64 = VERSIONS_KEEP as u64 + 5;
            for i in 1..=cap {
                snapshot_before_write(&dir, "config.json", format!("v{i}").as_bytes(), i * 1000)
                    .unwrap();
            }
            let all = list_versions(&dir, "config.json").unwrap();
            assert_eq!(all.len(), VERSIONS_KEEP, "must cap at VERSIONS_KEEP");
            // The oldest versions are the ones pruned.
            assert_eq!(
                all.last().unwrap().saved_unix,
                (cap - VERSIONS_KEEP as u64 + 1) * 1000
            );
        });
    }
}
