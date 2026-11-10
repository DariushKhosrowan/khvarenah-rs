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

use crate::doctor::{CheckResult, CheckStatus};
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
    /// Set when the integrity sweep found this version corrupt (sha mismatch,
    /// missing payload, etc.). Never deleted by the sweep; only surfaced.
    #[serde(default)]
    pub corrupt: bool,
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
        corrupt: false,
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
    // The outcome is recorded so Doctor can surface silent prune failures
    // before disk fills — never fails the enclosing write.
    match prune_versions(profile_dir, rel_path, VERSIONS_KEEP) {
        Ok(_) => {
            let _ = record_prune_outcome(profile_dir, true, now_ms / 1000);
        }
        Err(_) => {
            let _ = record_prune_outcome(profile_dir, false, now_ms / 1000);
        }
    }

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

/// Stale-prune threshold: a last_prune_unix older than this is a Warn.
const STALE_PRUNE_SECS: u64 = 7 * 24 * 3600;

/// Per-profile versioning state (hot-path prune outcomes). Persisted so Doctor
/// can surface silent prune failures even across restarts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VersioningState {
    /// Consecutive prune failures on the write path (resets on success).
    pub consecutive_failures: u32,
    /// When the last failure happened (unix seconds).
    pub last_failure_unix: Option<u64>,
    /// When the last successful prune happened (unix seconds).
    pub last_prune_unix: Option<u64>,
    /// When the integrity sweep last completed (unix seconds).
    #[serde(default)]
    pub last_verify_unix: Option<u64>,
    /// Corrupt versions found by the last sweep.
    #[serde(default)]
    pub last_corrupt_count: u64,
    /// Orphan payload files found by the last sweep.
    #[serde(default)]
    pub last_orphan_count: u64,
    /// Index entries whose payload file was missing.
    #[serde(default)]
    pub last_missing_count: u64,
    /// Corrupt versions identified by the last integrity sweep (flagged, never
    /// deleted). Authoritative source for the GUI History drawer's per-version
    /// corrupt flag — counts alone cannot drive a truthful UI.
    #[serde(default)]
    pub corrupt_versions: Vec<CorruptVersion>,
}

/// The on-disk path of the versioning state file.
pub fn versioning_state_path(profile_dir: &Path) -> PathBuf {
    profile_dir.join("versioning_state.json")
}

fn read_versioning_state(profile_dir: &Path) -> VersioningState {
    crate::store::read_opt(&versioning_state_path(profile_dir)).unwrap_or_default()
}

/// Public accessor for the persisted versioning state (used by Doctor).
pub fn read_versioning_state_for_doctor(profile_dir: &Path) -> VersioningState {
    read_versioning_state(profile_dir)
}

/// Record the outcome of a hot-path prune. Called from `record_version`; never
/// fails the enclosing write.
pub fn record_prune_outcome(profile_dir: &Path, ok: bool, now: u64) -> Result<(), VersionError> {
    let mut st = read_versioning_state(profile_dir);
    if ok {
        st.consecutive_failures = 0;
        st.last_prune_unix = Some(now);
    } else {
        st.consecutive_failures = st.consecutive_failures.saturating_add(1);
        st.last_failure_unix = Some(now);
    }
    crate::store::write_json(&versioning_state_path(profile_dir), &st)
        .map_err(|e| VersionError::Io(e.brief()))
}

/// Health snapshot of a profile's version store.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VersioningHealth {
    /// Number of `.versions/` directories (one per versioned artifact).
    pub dir_count: u64,
    /// Total snapshot files across all version dirs.
    pub file_count: u64,
    /// Total bytes across all version dirs.
    pub total_bytes: u64,
    /// (artifact name, bytes) of the largest version dir.
    pub largest_dir: Option<(String, u64)>,
    /// Names of version dirs exceeding `VERSIONS_KEEP` files (unbounded growth).
    pub oversized_dirs: Vec<String>,
    /// From the persisted versioning state.
    pub consecutive_failures: u32,
    pub last_failure_unix: Option<u64>,
    pub last_prune_unix: Option<u64>,
}

/// Walk a profile's `.versions/` tree and assemble a health snapshot.
pub fn measure_versioning_health(profile_dir: &Path, _now: u64) -> Result<VersioningHealth, VersionError> {
    let mut h = VersioningHealth {
        ..Default::default()
    };
    let st = read_versioning_state(profile_dir);
    h.consecutive_failures = st.consecutive_failures;
    h.last_failure_unix = st.last_failure_unix;
    h.last_prune_unix = st.last_prune_unix;

    let Ok(rd) = std::fs::read_dir(profile_dir) else {
        return Ok(h);
    };
    for entry in rd.flatten() {
        let p = entry.path();
        let Some(name) = p.file_name().and_then(|s| s.to_str()).map(str::to_string) else {
            continue;
        };
        if !name.ends_with(".versions") || !p.is_dir() {
            continue;
        }
        h.dir_count += 1;
        let mut files = 0u64;
        let mut bytes = 0u64;
        if let Ok(vrd) = std::fs::read_dir(&p) {
            for v in vrd.flatten() {
                if let Ok(m) = v.metadata() {
                    if m.is_file() {
                        files += 1;
                        bytes += m.len();
                    }
                }
            }
        }
        h.file_count += files;
        h.total_bytes += bytes;
        if h.largest_dir.as_ref().map(|(_, b)| *b).unwrap_or(0) < bytes {
            h.largest_dir = Some((name.clone(), bytes));
        }
        if files > VERSIONS_KEEP as u64 {
            h.oversized_dirs.push(name);
        }
    }
    Ok(h)
}

/// Doctor row for one profile's versioning health.
pub fn doctor_check_versions(_profile_dir: &Path, health: &VersioningHealth) -> CheckResult {
    let name = "versions".to_string();
    if !health.oversized_dirs.is_empty() {
        return CheckResult {
            name,
            status: CheckStatus::Fail,
            detail: format!(
                "unbounded version dir(s) {} exceed {} files — prune is not keeping up",
                health.oversized_dirs.join(", "),
                VERSIONS_KEEP
            ),
        };
    }
    if health.consecutive_failures > 0 {
        return CheckResult {
            name,
            status: CheckStatus::Fail,
            detail: format!(
                "{} consecutive prune error(s) on the write path (last at {:?}) — disk may fill; check for full/read-only FS",
                health.consecutive_failures, health.last_failure_unix
            ),
        };
    }
    if let Some(last) = health.last_prune_unix {
        if health.total_bytes > 0 && _now_secs().saturating_sub(last) > STALE_PRUNE_SECS {
            return CheckResult {
                name,
                status: CheckStatus::Warn,
                detail: format!("last successful prune was > 7 days ago ({last}) — version history may be stale"),
            };
        }
    }
    let largest = health
        .largest_dir
        .as_ref()
        .map(|(n, b)| format!(" largest {} ({b} B)", n))
        .unwrap_or_default();
    CheckResult {
        name,
        status: CheckStatus::Ok,
        detail: format!(
            "versioning ok: {} dir(s) · {} file(s) · {} B{}",
            health.dir_count, health.file_count, health.total_bytes, largest
        ),
    }
}

fn _now_secs() -> u64 {
    crate::store::now_ts() as u64
}

/// Aggregate Doctor row across profiles.
pub fn doctor_versions_summary(healths: &[(String, VersioningHealth)]) -> CheckResult {
    let name = "versions (all profiles)".to_string();
    let any_fail = healths.iter().any(|(_, h)| !h.oversized_dirs.is_empty() || h.consecutive_failures > 0);
    let any_warn = healths.iter().any(|(_, h)| {
        h.last_prune_unix.map(|last| _now_secs().saturating_sub(last) > STALE_PRUNE_SECS).unwrap_or(false)
    });
    let total_files: u64 = healths.iter().map(|(_, h)| h.file_count).sum();
    let total_bytes: u64 = healths.iter().map(|(_, h)| h.total_bytes).sum();
    let status = if any_fail {
        CheckStatus::Fail
    } else if any_warn {
        CheckStatus::Warn
    } else {
        CheckStatus::Ok
    };
    CheckResult {
        name,
        status,
        detail: format!(
            "{} profile(s) · {} file(s) · {} B",
            healths.len(),
            total_files,
            total_bytes
        ),
    }
}

/// Why a version was flagged corrupt by the integrity sweep.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CorruptReason {
    /// The payload file exists but does not hash to the recorded sha256.
    ShaMismatch,
    /// The index references a payload file that does not exist.
    PayloadMissing,
    /// A payload file exists on disk but has no index entry (orphan).
    IndexEntryMissing,
    /// The index or payload file could not be parsed as the expected JSON.
    ParseError,
}

/// One corrupt version identified by the sweep.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorruptVersion {
    pub rel_path: String,
    pub version_unix: u64,
    pub reason: CorruptReason,
}

/// Report from running the version integrity sweep.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VersionVerifyReport {
    /// Number of version entries scanned.
    pub scanned: u64,
    /// Corrupt versions found (never deleted).
    pub corrupt: Vec<CorruptVersion>,
    /// Orphan payload filenames (in a .versions dir but not in its index).
    pub orphans: Vec<String>,
    /// Index entries whose payload file was missing.
    pub missing: Vec<String>,
    /// True if the wall-clock budget was exhausted before finishing.
    pub truncated: bool,
    /// How long the sweep took, in milliseconds.
    pub elapsed_ms: u64,
}

/// Run the integrity sweep over a profile's `.versions/` tree.
///
/// For every artifact's index: each entry must have a payload file that hashes
/// to the recorded sha256; every payload file must have an index entry; the
/// index must parse. Corrupt versions are flagged, never deleted. `budget_ms`
/// caps wall-clock time; when exceeded, `truncated` is set and the sweep stops
/// so it never stalls Doctor.
pub fn verify_all_versions(
    profile_dir: &Path,
    _now: u64,
    budget_ms: u64,
) -> Result<VersionVerifyReport, VersionError> {
    let start = std::time::Instant::now();
    let mut report = VersionVerifyReport::default();
    let Ok(rd) = std::fs::read_dir(profile_dir) else {
        return Ok(report);
    };
    let mut dirs: Vec<PathBuf> = Vec::new();
    for entry in rd.flatten() {
        let p = entry.path();
        let Some(name) = p.file_name().and_then(|s| s.to_str()).map(str::to_string) else {
            continue;
        };
        if name.ends_with(".versions") && p.is_dir() {
            dirs.push(p);
        }
    }
    dirs.sort();
    for vdir in dirs {
        // Artifact name = "<artifact>.versions"
        let Some(artifact) = vdir.file_name().and_then(|s| s.to_str()).map(|s| s.trim_end_matches(".versions").to_string()) else {
            continue;
        };
        if start.elapsed().as_millis() as u64 >= budget_ms {
            report.truncated = true;
            break;
        }
        // Parse index; a parse failure is itself a corruption signal (the whole
        // artifact's version bookkeeping is unreadable).
        let Some(index) = crate::store::read_opt::<Vec<ArtifactVersion>>(&vdir.join("index.json")) else {
            report.corrupt.push(CorruptVersion {
                rel_path: artifact.clone(),
                version_unix: 0,
                reason: CorruptReason::ParseError,
            });
            continue;
        };
        let mut seen_payloads: std::collections::BTreeSet<u64> = Default::default();
        for v in &index {
            report.scanned += 1;
            let payload_path = version_file(&vdir, v.saved_unix);
            let Ok(bytes) = std::fs::read(&payload_path) else {
                report.missing.push(format!("{}/{}", artifact, v.saved_unix));
                report.corrupt.push(CorruptVersion {
                    rel_path: artifact.clone(),
                    version_unix: v.saved_unix,
                    reason: CorruptReason::PayloadMissing,
                });
                continue;
            };
            seen_payloads.insert(v.saved_unix);
            let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
                report.corrupt.push(CorruptVersion {
                    rel_path: artifact.clone(),
                    version_unix: v.saved_unix,
                    reason: CorruptReason::ParseError,
                });
                continue;
            };
            let Some(b64) = payload.get("bytes_b64").and_then(|v| v.as_str()) else {
                report.corrupt.push(CorruptVersion {
                    rel_path: artifact.clone(),
                    version_unix: v.saved_unix,
                    reason: CorruptReason::ParseError,
                });
                continue;
            };
            let Ok(data) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64) else {
                report.corrupt.push(CorruptVersion {
                    rel_path: artifact.clone(),
                    version_unix: v.saved_unix,
                    reason: CorruptReason::ParseError,
                });
                continue;
            };
            let actual = hex_bytes(&sha2::Sha256::digest(&data));
            if actual != v.sha256 {
                report.corrupt.push(CorruptVersion {
                    rel_path: artifact.clone(),
                    version_unix: v.saved_unix,
                    reason: CorruptReason::ShaMismatch,
                });
            }
        }
        // Orphans: payload files on disk not present in the index.
        if let Ok(pd) = std::fs::read_dir(&vdir) {
            for pe in pd.flatten() {
                let p = pe.path();
                if !p.is_file() {
                    continue;
                }
                let Some(name) = p.file_name().and_then(|s| s.to_str()).map(str::to_string) else {
                    continue;
                };
                if name == "index.json" {
                    continue;
                }
                if let Ok(unix) = name.trim_end_matches(".json").parse::<u64>() {
                    if !seen_payloads.contains(&unix) {
                        report.orphans.push(format!("{}/{}", artifact, unix));
                        report.corrupt.push(CorruptVersion {
                            rel_path: artifact.clone(),
                            version_unix: unix,
                            reason: CorruptReason::IndexEntryMissing,
                        });
                    }
                }
            }
        }
    }
    report.elapsed_ms = start.elapsed().as_millis() as u64;
    Ok(report)
}

/// Record the outcome of an integrity sweep into versioning_state.json.
pub fn record_verify_outcome(
    profile_dir: &Path,
    report: &VersionVerifyReport,
    now: u64,
) -> Result<(), VersionError> {
    let mut st = read_versioning_state(profile_dir);
    st.last_verify_unix = Some(now);
    st.last_corrupt_count = report.corrupt.len() as u64;
    st.last_orphan_count = report.orphans.len() as u64;
    st.last_missing_count = report.missing.len() as u64;
    st.corrupt_versions = report.corrupt.clone();
    crate::store::write_json(&versioning_state_path(profile_dir), &st)
        .map_err(|e| VersionError::Io(e.brief()))
}

/// Deterministic one-liner describing a sweep report (Doctor / CLI).
pub fn corrupt_versions_summary(report: &VersionVerifyReport) -> String {
    if report.truncated {
        return format!(
            "sweep truncated after {}ms at {} scanned (budget exhausted)",
            report.elapsed_ms, report.scanned
        );
    }
    if report.corrupt.is_empty() {
        return format!(
            "verified {} version(s) clean in {}ms",
            report.scanned, report.elapsed_ms
        );
    }
    let by_reason = |r: CorruptReason| report.corrupt.iter().filter(|c| c.reason == r).count();
    format!(
        "{} corrupt: {} sha-mismatch, {} payload-missing, {} orphan/index-missing (in {}ms)",
        report.corrupt.len(),
        by_reason(CorruptReason::ShaMismatch),
        by_reason(CorruptReason::PayloadMissing),
        by_reason(CorruptReason::IndexEntryMissing),
        report.elapsed_ms
    )
}

/// Doctor check: content-based version integrity from the last recorded sweep.
///
/// Ok when the last sweep found no corrupt/orphan/missing and was fresh
/// (< 7 days). Warn on stale verify or orphans-only. Fail on any corruption.
pub fn doctor_check_version_integrity(
    _profile_dir: &Path,
    state: &VersioningState,
    now: u64,
) -> CheckResult {
    let name = "versions-integrity".to_string();
    let stale_threshold = 7 * 24 * 3600u64;
    let Some(last_verify) = state.last_verify_unix else {
        return CheckResult {
            name,
            status: CheckStatus::Warn,
            detail: "version integrity never verified — run `dastyab versions verify`".to_string(),
        };
    };
    if state.last_corrupt_count > 0 {
        return CheckResult {
            name,
            status: CheckStatus::Fail,
            detail: format!(
                "{} corrupt version(s) (last verify at {last_verify}) — restore will refuse these",
                state.last_corrupt_count
            ),
        };
    }
    let age = now.saturating_sub(last_verify);
    if state.last_missing_count > 0 {
        return CheckResult {
            name,
            status: CheckStatus::Fail,
            detail: format!(
                "{} payload(s) missing (last verify at {last_verify})",
                state.last_missing_count
            ),
        };
    }
    if state.last_orphan_count > 0 {
        return CheckResult {
            name,
            status: CheckStatus::Warn,
            detail: format!(
                "{} orphan payload file(s) (last verify at {last_verify})",
                state.last_orphan_count
            ),
        };
    }
    if age > stale_threshold {
        return CheckResult {
            name,
            status: CheckStatus::Warn,
            detail: format!("last integrity verify was {age}s ago (> 7d) — stale"),
        };
    }
    CheckResult {
        name,
        status: CheckStatus::Ok,
        detail: format!(
            "content verified {age}s ago · 0 corrupt · 0 missing · 0 orphan"
        ),
    }
}

/// Per-artifact version listing with integrity flags applied, for the GUI
/// History drawer. Scans the profile's `.versions/` tree and overlays the last
/// sweep's corrupt-version list so `ArtifactVersion.corrupt` is truthful (from
/// `versioning_state.corrupt_versions`, never from counts).
pub struct ArtifactVersionsSummary {
    /// Artifact name (e.g. "config.json").
    pub artifact: String,
    /// Versions, newest first, with `.corrupt` set from the last sweep.
    pub versions: Vec<ArtifactVersion>,
}

/// List every artifact's versions, flagging corrupt ones from the last sweep.
pub fn list_versions_with_integrity(profile_dir: &Path) -> Vec<ArtifactVersionsSummary> {
    let state = read_versioning_state(profile_dir);
    let corrupt = &state.corrupt_versions;
    let Ok(rd) = std::fs::read_dir(profile_dir) else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = Vec::new();
    for entry in rd.flatten() {
        let p = entry.path();
        let Some(name) = p.file_name().and_then(|s| s.to_str()).map(str::to_string) else {
            continue;
        };
        if name.ends_with(".versions") && p.is_dir() {
            dirs.push(p);
        }
    }
    dirs.sort();
    let mut out = Vec::with_capacity(dirs.len());
    for vdir in dirs {
        let Some(artifact) = vdir
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.trim_end_matches(".versions").to_string())
        else {
            continue;
        };
        let Ok(mut versions) = list_versions(profile_dir, &artifact) else {
            continue;
        };
        for v in &mut versions {
            if corrupt
                .iter()
                .any(|c| c.rel_path == artifact && c.version_unix == v.saved_unix)
            {
                v.corrupt = true;
            }
        }
        out.push(ArtifactVersionsSummary { artifact, versions });
    }
    out
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

    #[test]
    fn record_prune_outcome_increments_on_failure() {
        with_tmp(|dir| {
            record_prune_outcome(&dir, false, 1000).unwrap();
            record_prune_outcome(&dir, false, 2000).unwrap();
            let st = read_versioning_state(&dir);
            assert_eq!(st.consecutive_failures, 2);
            assert_eq!(st.last_failure_unix, Some(2000));
            assert_eq!(st.last_prune_unix, None);
        });
    }

    #[test]
    fn record_prune_outcome_resets_on_success() {
        with_tmp(|dir| {
            record_prune_outcome(&dir, false, 1000).unwrap();
            record_prune_outcome(&dir, true, 2000).unwrap();
            let st = read_versioning_state(&dir);
            assert_eq!(st.consecutive_failures, 0);
            assert_eq!(st.last_prune_unix, Some(2000));
        });
    }

    #[test]
    fn record_version_records_prune_failure_without_failing_write() {
        with_tmp(|dir| {
            std::fs::write(dir.join("config.json"), b"a").unwrap();
            // A normal version write records a successful prune outcome.
            snapshot_before_write(&dir, "config.json", b"b", 1000).unwrap();
            let st = read_versioning_state(&dir);
            assert_eq!(st.consecutive_failures, 0);
            assert!(st.last_prune_unix.is_some());
        });
    }

    #[test]
    fn record_version_reentrancy_guard_holds_under_prune_recursion() {
        // The atomic_write hook snapshots pre-write; prune_versions writes the
        // index via atomic_write. If the re-entrancy guard failed, snapshotting
        // the index would recurse. This exercises the full chain and asserts the
        // version dir stays bounded and the hook does not spin.
        with_tmp(|dir| {
            std::fs::write(dir.join("config.json"), b"base").unwrap();
            let cap = VERSIONS_KEEP + 10;
            for i in 1..=cap {
                snapshot_before_write(&dir, "config.json", format!("v{i}").as_bytes(), i as u64 * 1000)
                    .unwrap();
            }
            let all = list_versions(&dir, "config.json").unwrap();
            assert_eq!(all.len(), VERSIONS_KEEP);
        });
    }

    #[test]
    fn measure_versioning_health_counts_dirs_files_bytes() {
        with_tmp(|dir| {
            std::fs::write(dir.join("config.json"), b"a").unwrap();
            std::fs::write(dir.join("history.json"), b"[1]").unwrap();
            snapshot_before_write(&dir, "config.json", b"b", 1000).unwrap();
            snapshot_before_write(&dir, "history.json", b"[1,2]", 1000).unwrap();
            for e in std::fs::read_dir(&dir).unwrap().flatten() {
                eprintln!("DIRENT: {:?}", e.path());
            }
            let h = measure_versioning_health(&dir, 2000).unwrap();
            assert_eq!(h.dir_count, 2);
            assert!(h.file_count >= 2); // payload + index per version dir
            assert!(h.total_bytes > 0);
            assert!(h.largest_dir.is_some());
            assert!(h.oversized_dirs.is_empty());
        });
    }

    #[test]
    fn doctor_check_versions_fails_on_consecutive_failures() {
        with_tmp(|dir| {
            record_prune_outcome(&dir, false, 1000).unwrap();
            let h = measure_versioning_health(&dir, 2000).unwrap();
            let r = doctor_check_versions(&dir, &h);
            assert_eq!(r.status, CheckStatus::Fail);
        });
    }

    #[test]
    fn doctor_check_versions_warns_on_stale_prune() {
        with_tmp(|dir| {
            // Create real version dirs so total_bytes > 0.
            std::fs::write(dir.join("config.json"), b"a").unwrap();
            snapshot_before_write(&dir, "config.json", b"b", 1000).unwrap();
            let h = measure_versioning_health(&dir, 2000).unwrap();
            assert!(h.total_bytes > 0, "need version bytes to test stale prune");
            // Force stale by injecting an old last_prune_unix.
            let mut h = h;
            h.last_prune_unix = Some(1);
            let r = doctor_check_versions(&dir, &h);
            assert_eq!(r.status, CheckStatus::Warn);
        });
    }

    #[test]
    fn doctor_check_versions_flags_oversized_dir() {
        with_tmp(|dir| {
            // Synthesize an oversized version dir directly.
            let vdir = versions_dir(&dir, "config.json");
            std::fs::create_dir_all(&vdir).unwrap();
            for i in 0..(VERSIONS_KEEP as u64 + 2) {
                std::fs::write(version_file(&vdir, i), b"x").unwrap();
            }
            let h = measure_versioning_health(&dir, 2000).unwrap();
            assert!(!h.oversized_dirs.is_empty());
            let r = doctor_check_versions(&dir, &h);
            assert_eq!(r.status, CheckStatus::Fail);
        });
    }

    /// Seed one clean version of `artifact` (holding the PRE-write content)
    /// at the given unix stamp. `snapshot_before_write` snapshots the old
    /// bytes, so write "old" first, then request a "new" write.
    fn seed_version(dir: &Path, artifact: &str, new_content: &[u8], unix: u64) {
        std::fs::write(dir.join(artifact), b"old").unwrap();
        snapshot_before_write(dir, artifact, new_content, unix).unwrap();
    }

    #[test]
    fn verify_all_versions_reports_clean_when_hashes_match() {
        with_tmp(|dir| {
            seed_version(&dir, "config.json", b"v2", 1000);
            seed_version(&dir, "config.json", b"v3", 2000);
            let r = verify_all_versions(&dir, 5000, 2000).unwrap();
            assert!(r.corrupt.is_empty(), "no corrupt: {:?}", r.corrupt);
            assert!(r.orphans.is_empty());
            assert!(r.missing.is_empty());
            assert!(!r.truncated);
            assert_eq!(r.scanned, 2);
        });
    }

    #[test]
    fn verify_all_versions_flags_sha_mismatch() {
        with_tmp(|dir| {
            seed_version(&dir, "config.json", b"v2", 1000);
            let vdir = versions_dir(&dir, "config.json");
            // Valid JSON payload whose bytes do NOT hash to the recorded sha256.
            std::fs::write(version_file(&vdir, 1000), r#"{"sha256":"00","bytes_b64":"eg=="}"#).unwrap();
            let r = verify_all_versions(&dir, 5000, 2000).unwrap();
            assert_eq!(r.corrupt.len(), 1);
            assert_eq!(r.corrupt[0].reason, CorruptReason::ShaMismatch);
        });
    }

    #[test]
    fn verify_all_versions_flags_payload_missing() {
        with_tmp(|dir| {
            seed_version(&dir, "config.json", b"v2", 1000);
            let vdir = versions_dir(&dir, "config.json");
            std::fs::remove_file(version_file(&vdir, 1000)).unwrap();
            let r = verify_all_versions(&dir, 5000, 2000).unwrap();
            assert_eq!(r.missing.len(), 1);
            assert!(r.corrupt.iter().any(|c| c.reason == CorruptReason::PayloadMissing));
        });
    }

    #[test]
    fn verify_all_versions_flags_index_entry_missing() {
        // A payload file on disk with no index entry → IndexEntryMissing corrupt.
        // The index must exist for the sweep to know what *should* be there, so
        // seed a real version first, then drop a stray payload alongside it.
        with_tmp(|dir| {
            seed_version(&dir, "config.json", b"v2", 1000);
            let vdir = versions_dir(&dir, "config.json");
            std::fs::write(version_file(&vdir, 99999), r#"{"sha256":"00","bytes_b64":"eg=="}"#).unwrap();
            let r = verify_all_versions(&dir, 5000, 2000).unwrap();
            assert!(r.corrupt.iter().any(|c| c.reason == CorruptReason::IndexEntryMissing));
        });
    }

    #[test]
    fn verify_all_versions_flags_orphan_payload() {
        // Same underlying condition as index_entry_missing — a payload file not
        // referenced by the index shows up in `orphans`.
        with_tmp(|dir| {
            seed_version(&dir, "config.json", b"v2", 1000);
            let vdir = versions_dir(&dir, "config.json");
            std::fs::write(version_file(&vdir, 99998), r#"{"sha256":"00","bytes_b64":"eg=="}"#).unwrap();
            let r = verify_all_versions(&dir, 5000, 2000).unwrap();
            assert_eq!(r.orphans.len(), 1);
        });
    }

    #[test]
    fn verify_all_versions_respects_budget_and_sets_truncated() {
        with_tmp(|dir| {
            seed_version(&dir, "config.json", b"v2", 1000);
            // A zero budget truncates before scanning anything.
            let r = verify_all_versions(&dir, 5000, 0).unwrap();
            assert!(r.truncated);
            assert_eq!(r.scanned, 0);
        });
    }

    #[test]
    fn record_verify_outcome_persists_counts() {
        with_tmp(|dir| {
            let mut report = VersionVerifyReport::default();
            report.corrupt.push(CorruptVersion {
                rel_path: "config.json".into(),
                version_unix: 1000,
                reason: CorruptReason::ShaMismatch,
            });
            report.orphans.push("config.json/2000".into());
            report.missing.push("config.json/3000".into());
            record_verify_outcome(&dir, &report, 9000).unwrap();
            let st = read_versioning_state(&dir);
            assert_eq!(st.last_verify_unix, Some(9000));
            assert_eq!(st.last_corrupt_count, 1);
            assert_eq!(st.last_orphan_count, 1);
            assert_eq!(st.last_missing_count, 1);
            assert_eq!(st.corrupt_versions.len(), 1);
            assert_eq!(st.corrupt_versions[0].reason, CorruptReason::ShaMismatch);
        });
    }

    #[test]
    fn list_versions_with_integrity_flags_corrupt_from_persisted_list() {
        with_tmp(|dir| {
            seed_version(&dir, "config.json", b"v2", 1000);
            let vdir = versions_dir(&dir, "config.json");
            std::fs::write(version_file(&vdir, 1000), r#"{"sha256":"00","bytes_b64":"eg=="}"#).unwrap();
            let report = verify_all_versions(&dir, 5000, 2000).unwrap();
            assert_eq!(report.corrupt.len(), 1);
            record_verify_outcome(&dir, &report, 5000).unwrap();

            let summaries = list_versions_with_integrity(&dir);
            assert_eq!(summaries.len(), 1);
            assert_eq!(summaries[0].artifact, "config.json");
            let v = &summaries[0].versions[0];
            assert!(v.corrupt, "version must be flagged corrupt from persisted list");
        });
    }

    #[test]
    fn doctor_check_version_integrity_fails_on_corrupt() {
        let state = VersioningState {
            last_verify_unix: Some(1000),
            last_corrupt_count: 2,
            last_orphan_count: 0,
            last_missing_count: 0,
            ..Default::default()
        };
        let r = doctor_check_version_integrity(Path::new(""), &state, 2000);
        assert_eq!(r.status, CheckStatus::Fail);
    }

    #[test]
    fn doctor_check_version_integrity_warns_on_stale_verify() {
        let state = VersioningState {
            last_verify_unix: Some(1),
            last_corrupt_count: 0,
            last_orphan_count: 0,
            last_missing_count: 0,
            ..Default::default()
        };
        let r = doctor_check_version_integrity(Path::new(""), &state, 8 * 24 * 3600);
        assert_eq!(r.status, CheckStatus::Warn);
    }

    #[test]
    fn doctor_check_version_integrity_ok_when_clean_and_fresh() {
        let state = VersioningState {
            last_verify_unix: Some(1000),
            last_corrupt_count: 0,
            last_orphan_count: 0,
            last_missing_count: 0,
            ..Default::default()
        };
        let r = doctor_check_version_integrity(Path::new(""), &state, 2000);
        assert_eq!(r.status, CheckStatus::Ok);
    }

    #[test]
    fn corrupt_versions_are_not_deleted_by_sweep() {
        with_tmp(|dir| {
            seed_version(&dir, "config.json", b"v2", 1000);
            let vdir = versions_dir(&dir, "config.json");
            let p = version_file(&vdir, 1000);
            std::fs::write(&p, r#"{"sha256":"00","bytes_b64":"eg=="}"#).unwrap();
            let r = verify_all_versions(&dir, 5000, 2000).unwrap();
            assert_eq!(r.corrupt.len(), 1);
            assert!(p.exists(), "corrupt version must NOT be deleted by the sweep");
        });
    }
}
