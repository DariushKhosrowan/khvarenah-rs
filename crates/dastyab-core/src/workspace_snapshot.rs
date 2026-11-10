//! Whole-workspace snapshot & restore.
//!
//! The existing backup (`backup.rs`) is per-profile. A lost machine means
//! re-collecting N files. A workspace snapshot is a single portable
//! `.dyb-snapshot.json` containing every profile's artifacts **plus** their
//! manifests, so restore can verify every sha256 before writing. This is the
//! "nothing's gonna be lost" deliverable.
//!
//! All shipped artifacts are UTF-8 (JSON or share-link strings), so no base64
//! dependency is needed.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::CFError;
use crate::manifest::{build_manifest, profile_artifact_kinds, ProfileManifest};

/// Snapshot granularity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotKind {
    /// All per-profile artifacts.
    Full,
    /// Only the core profile state (profile/token/accounts/history).
    ProfilesOnly,
    /// Only exported VLESS outputs + tunnel-client configs.
    ConfigsOnly,
}

/// One artifact's content within a profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactPayload {
    pub rel_path: String,
    pub content: String,
}

/// A single profile's snapshot payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilePayload {
    pub profile_id: String,
    pub manifest: ProfileManifest,
    pub artifacts: Vec<ArtifactPayload>,
}

/// The whole-workspace snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceSnapshot {
    pub schema_version: u32,
    pub created_unix: u64,
    pub kind: SnapshotKind,
    pub profiles: Vec<ProfilePayload>,
}

/// Options for restore.
#[derive(Debug, Clone)]
pub struct RestoreOptions {
    pub overwrite_existing: bool,
    pub dry_run: bool,
    pub verify_after_write: bool,
}

impl Default for RestoreOptions {
    fn default() -> Self {
        Self {
            overwrite_existing: false,
            dry_run: false,
            verify_after_write: true,
        }
    }
}

/// Report of a restore run.
#[derive(Debug, Clone, Default)]
pub struct RestoreReport {
    pub profiles_restored: usize,
    pub profiles_skipped: usize,
    pub files_written: usize,
    pub verified: bool,
    pub mismatches: Vec<String>,
}

/// Which artifact kinds belong to each snapshot kind.
fn kinds_for(snapshot_kind: SnapshotKind) -> Vec<crate::manifest::ArtifactKind> {
    match snapshot_kind {
        SnapshotKind::Full => profile_artifact_kinds(),
        SnapshotKind::ProfilesOnly => vec![
            crate::manifest::ArtifactKind::ProfileMeta,
            crate::manifest::ArtifactKind::Tokens,
            crate::manifest::ArtifactKind::Accounts,
            crate::manifest::ArtifactKind::History,
        ],
        SnapshotKind::ConfigsOnly => vec![
            crate::manifest::ArtifactKind::TunnelClient,
            crate::manifest::ArtifactKind::History,
        ],
    }
}

/// Build a workspace snapshot.
pub fn snapshot_workspace(
    workspace_root: &Path,
    kind: SnapshotKind,
    now_unix: u64,
) -> Result<WorkspaceSnapshot, CFError> {
    let _ = workspace_root;
    let mut profiles = Vec::new();
    let profiles_list = crate::store::profiles::list_profiles();

    for meta in &profiles_list {
        let dir = crate::store::profiles::profile_dir(&meta.id);
        let manifest = match crate::manifest::load_manifest(&meta.id) {
            Some(m) => m,
            None => build_manifest(&meta.id)?,
        };
        let mut artifacts = Vec::new();
        for kind in kinds_for(kind) {
            let rel = kind.filename();
            let p = dir.join(rel);
            if let Ok(text) = std::fs::read_to_string(&p) {
                artifacts.push(ArtifactPayload {
                    rel_path: rel.to_string(),
                    content: text,
                });
            }
        }
        // Always include the manifest itself so restore can verify.
        if kind == SnapshotKind::Full {
            let mp = dir.join("manifest.json");
            if let Ok(text) = std::fs::read_to_string(&mp) {
                artifacts.push(ArtifactPayload {
                    rel_path: "manifest.json".to_string(),
                    content: text,
                });
            }
        }
        profiles.push(ProfilePayload {
            profile_id: meta.id.clone(),
            manifest,
            artifacts,
        });
    }

    Ok(WorkspaceSnapshot {
        schema_version: 1,
        created_unix: now_unix,
        kind,
        profiles,
    })
}

/// Write a snapshot atomically.
pub fn write_snapshot_atomic(snap: &WorkspaceSnapshot, path: &Path) -> Result<(), CFError> {
    let bytes = serde_json::to_vec_pretty(snap).map_err(|e| {
        CFError::new(
            "Snapshot error",
            format!("Cannot serialize snapshot: {e}"),
            "Internal error.",
        )
    })?;
    crate::store::atomic_write(path, &bytes)
}

/// Read a snapshot, rejecting future schema versions.
pub fn read_snapshot(path: &Path) -> Result<WorkspaceSnapshot, CFError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        CFError::new(
            "Snapshot error",
            format!("Cannot read {}: {e}", path.display()),
            "Check the file path.",
        )
    })?;
    let snap: WorkspaceSnapshot = serde_json::from_str(&text).map_err(|e| {
        CFError::new(
            "Snapshot error",
            format!("Invalid snapshot JSON: {e}"),
            "Create a snapshot first.",
        )
    })?;
    if snap.schema_version > 1 {
        return Err(CFError::new(
            "Snapshot error",
            format!(
                "Snapshot schema v{} is newer than this app supports (v1).",
                snap.schema_version
            ),
            "Update DastYab to restore this snapshot.",
        ));
    }
    Ok(snap)
}

/// Verify a single artifact's content against the embedded manifest.
fn verify_artifact(manifest: &ProfileManifest, rel: &str, content: &str) -> bool {
    use sha2::{Digest, Sha256};
    let Some(entry) = manifest.entries.get(rel) else {
        return false;
    };
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let digest = hasher.finalize();
    let mut s = String::with_capacity(64);
    use std::fmt::Write;
    for b in digest {
        let _ = write!(s, "{b:02x}");
    }
    s == entry.sha256
}

/// Restore a workspace from a snapshot. Verifies each artifact's sha256
/// against the embedded manifest before writing; mismatches are skipped and
/// reported. Never auto-overwrites unless asked.
pub fn restore_workspace(
    snap: &WorkspaceSnapshot,
    workspace_root: &Path,
    opts: &RestoreOptions,
) -> Result<RestoreReport, CFError> {
    let _ = workspace_root;
    let mut report = RestoreReport {
        verified: true,
        ..Default::default()
    };

    for profile in &snap.profiles {
        // Use the canonical profile directory directly (NOT `profile_dir`,
        // which falls back to `default` for a profile that doesn't exist yet
        // in this workspace — restore is exactly the case where we are
        // creating it fresh).
        let dir = crate::store::profiles_dir().join(&profile.profile_id);
        let exists = dir.join("profile.json").exists();
        if exists && !opts.overwrite_existing {
            report.profiles_skipped += 1;
            continue;
        }
        if !opts.dry_run {
            std::fs::create_dir_all(&dir).map_err(|e| {
                CFError::new(
                    "Restore error",
                    format!("Cannot create {}: {e}", dir.display()),
                    "Check permissions.",
                )
            })?;
        }

        for artifact in &profile.artifacts {
            if artifact.rel_path == "manifest.json" {
                continue;
            }
            if !verify_artifact(&profile.manifest, &artifact.rel_path, &artifact.content) {
                report.mismatches.push(format!(
                    "{}:{} (hash mismatch)",
                    profile.profile_id, artifact.rel_path
                ));
                report.verified = false;
                continue;
            }
            if opts.dry_run {
                report.files_written += 1;
                continue;
            }
            let dest = dir.join(&artifact.rel_path);
            crate::store::atomic_write(&dest, artifact.content.as_bytes())?;
            report.files_written += 1;
        }

        // Restore the manifest too (so future verify has a baseline). Write
        // to the explicit profile dir to avoid the store's default-fallback.
        if !opts.dry_run {
            crate::store::write_json(&dir.join("manifest.json"), &profile.manifest)?;
        }
        report.profiles_restored += 1;
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::set_mem_dir_override;

    fn with_home(f: impl FnOnce()) {
        let tmp = tempfile::tempdir().unwrap();
        set_mem_dir_override(tmp.path().join(".dastyab"));
        f();
    }

    fn fresh_profile_id() -> String {
        crate::store::profiles::create_profile("t", "test").unwrap()
    }

    fn seed_artifacts(id: &str) {
        let dir = crate::store::profiles::profile_dir(id);
        std::fs::write(dir.join("accounts.json"), b"{\"a\":1}").unwrap();
        std::fs::write(dir.join("config.json"), b"{\"x\":1}").unwrap();
        std::fs::write(dir.join("token.json"), b"{\"t\":\"abc\"}").unwrap();
        crate::manifest::write_manifest(&crate::manifest::build_manifest(id).unwrap()).unwrap();
    }

    #[test]
    fn snapshot_roundtrip_preserves_all_artifacts() {
        with_home(|| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            let snap = snapshot_workspace(Path::new("/"), SnapshotKind::Full, 1000).unwrap();
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("s.json");
            write_snapshot_atomic(&snap, &p).unwrap();
            let read = read_snapshot(&p).unwrap();
            assert_eq!(read.profiles.len(), snap.profiles.len());
            let prof = read.profiles.iter().find(|x| x.profile_id == id).unwrap();
            assert!(prof.artifacts.iter().any(|a| a.rel_path == "config.json"));
            assert!(prof.artifacts.iter().any(|a| a.rel_path == "accounts.json"));
        });
    }

    #[test]
    fn snapshot_embeds_manifest_per_profile() {
        with_home(|| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            let snap = snapshot_workspace(Path::new("/"), SnapshotKind::Full, 1000).unwrap();
            let prof = snap.profiles.iter().find(|x| x.profile_id == id).unwrap();
            assert!(!prof.manifest.entries.is_empty());
            assert!(prof.manifest.entries.contains_key("config.json"));
        });
    }

    #[test]
    fn restore_verifies_hash_before_write() {
        with_home(|| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            let mut snap = snapshot_workspace(Path::new("/"), SnapshotKind::Full, 1000).unwrap();
            // Corrupt one payload.
            let prof = snap.profiles.iter_mut().find(|x| x.profile_id == id).unwrap();
            let art = prof.artifacts.iter_mut().find(|a| a.rel_path == "config.json").unwrap();
            art.content = "{ \"tampered\": true }".to_string();

            let dir = tempfile::tempdir().unwrap();
            set_mem_dir_override(dir.path().join(".dastyab"));
            let new_id = crate::store::profiles::create_profile("t", "test").unwrap();
            let _ = new_id;
            let report = restore_workspace(&snap, Path::new("/"), &RestoreOptions::default()).unwrap();
            assert!(!report.verified);
            assert!(report.mismatches.iter().any(|m| m.contains("config.json")));
            // The tampered config.json must not have been written.
            let cfg_path = dir.path().join(".dastyab/profiles").join(&id).join("config.json");
            assert!(!cfg_path.exists() || {
                let text = std::fs::read_to_string(&cfg_path).unwrap();
                !text.contains("tampered")
            });
        });
    }

    #[test]
    fn restore_dry_run_writes_nothing() {
        with_home(|| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            let snap = snapshot_workspace(Path::new("/"), SnapshotKind::Full, 1000).unwrap();
            let dir = tempfile::tempdir().unwrap();
            set_mem_dir_override(dir.path().join(".dastyab"));
            let opts = RestoreOptions {
                dry_run: true,
                ..Default::default()
            };
            let report = restore_workspace(&snap, Path::new("/"), &opts).unwrap();
            assert_eq!(report.profiles_restored, 1);
            assert!(!dir.path().join(".dastyab/profiles").exists());
        });
    }

    #[test]
    fn restore_skips_existing_when_not_overwriting() {
        with_home(|| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            let snap = snapshot_workspace(Path::new("/"), SnapshotKind::Full, 1000).unwrap();
            let opts = RestoreOptions {
                overwrite_existing: false,
                ..Default::default()
            };
            let report = restore_workspace(&snap, Path::new("/"), &opts).unwrap();
            assert_eq!(report.profiles_skipped, 1);
            assert_eq!(report.profiles_restored, 0);
        });
    }

    #[test]
    fn restore_overwrites_when_asked() {
        with_home(|| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            let snap = snapshot_workspace(Path::new("/"), SnapshotKind::Full, 1000).unwrap();
            let opts = RestoreOptions {
                overwrite_existing: true,
                ..Default::default()
            };
            let report = restore_workspace(&snap, Path::new("/"), &opts).unwrap();
            assert_eq!(report.profiles_restored, 1);
        });
    }

    #[test]
    fn snapshot_from_empty_workspace_is_valid() {
        with_home(|| {
            let snap = snapshot_workspace(Path::new("/"), SnapshotKind::Full, 1000).unwrap();
            // Valid even when nothing is seeded (schema + empty vector round-trip).
            assert_eq!(snap.schema_version, 1);
            let p = tempfile::tempdir().unwrap().path().join("s.json");
            write_snapshot_atomic(&snap, &p).unwrap();
            assert!(read_snapshot(&p).is_ok());
        });
    }

    #[test]
    fn restore_rejects_future_schema_version() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s.json");
        let snap = WorkspaceSnapshot {
            schema_version: 99,
            created_unix: 1000,
            kind: SnapshotKind::Full,
            profiles: vec![],
        };
        write_snapshot_atomic(&snap, &p).unwrap();
        assert!(read_snapshot(&p).is_err());
    }

    #[test]
    fn configs_only_snapshot_excludes_internals() {
        with_home(|| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            let snap = snapshot_workspace(Path::new("/"), SnapshotKind::ConfigsOnly, 1000).unwrap();
            let prof = snap.profiles.iter().find(|x| x.profile_id == id).unwrap();
            assert!(!prof.artifacts.iter().any(|a| a.rel_path == "token.json"));
            for a in &prof.artifacts {
                assert!(a.rel_path == "tunnel-client.json" || a.rel_path == "history.json");
            }
        });
    }
}
