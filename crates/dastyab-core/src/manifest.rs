//! Artifact manifest + per-profile integrity verification.
//!
//! A manifest is a small JSON file written into each profile directory that
//! records the sha256 + size of every durable artifact (tokens, accounts,
//! history, clean IPs, config, worker-tunnel client config, …). `verify_profile`
//! then proves — with hashes, not just existence — that nothing was lost,
//! corrupted, or silently changed. This is the primitive the inventory and the
//! workspace snapshot both consume; it is what turns "backup" into "proof that
//! nothing's gonna be lost".
//!
//! ## Integrity semantics
//! - An entry is **Verified** when the on-disk file's sha256 matches the entry.
//! - **Missing** when a manifest entry has no on-disk file.
//! - **Changed** when the file exists but hashes differ (corruption, edit).
//! - **Extra** when a file exists under a profile dir that is not in the
//!   manifest (a `*`-matching profile store may grow files we didn't record).
//! - mtime is deliberately excluded from the hash — touching a file with no
//!   content change must still verify.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::CFError;
use crate::store::profiles::{list_profiles, profile_dir, ProfileMeta};

/// A named, durable artifact kind inside a profile (or workspace).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ArtifactKind {
    /// `profile.json` — profile metadata.
    ProfileMeta,
    /// `token.json` — API tokens (mode 600).
    Tokens,
    /// `accounts.json` — remembered Cloudflare accounts.
    Accounts,
    /// `history.json` — generated vless configs ledger.
    History,
    /// `cleanips.json` — scanned clean IPs.
    CleanIps,
    /// `config.json` — per-profile settings.
    Config,
    /// `token_history.json` — token lifecycle events.
    TokenHistory,
    /// `cleanip_meta.json` — clean-IP provenance.
    CleanIpMeta,
    /// `tunnel-client.json` — worker-tunnel client config.
    TunnelClient,
    /// `generated_configs.json` — completeness ledger of every rendered config.
    GeneratedConfigs,
    /// workspace-level: `carrier_pool.json`.
    CarrierPool,
    /// workspace-level: `active_profile` marker.
    ActiveProfileMarker,
}

impl ArtifactKind {
    /// Human label for UI/CLI output.
    pub fn label(self) -> &'static str {
        match self {
            ArtifactKind::ProfileMeta => "profile meta",
            ArtifactKind::Tokens => "tokens",
            ArtifactKind::Accounts => "accounts",
            ArtifactKind::History => "history",
            ArtifactKind::CleanIps => "clean IPs",
            ArtifactKind::Config => "config",
            ArtifactKind::TokenHistory => "token history",
            ArtifactKind::CleanIpMeta => "clean-IP meta",
            ArtifactKind::TunnelClient => "tunnel client",
            ArtifactKind::GeneratedConfigs => "generated configs",
            ArtifactKind::CarrierPool => "carrier pool",
            ArtifactKind::ActiveProfileMarker => "active profile marker",
        }
    }

    /// Relative filename within its owning dir.
    pub fn filename(self) -> &'static str {
        match self {
            ArtifactKind::ProfileMeta => "profile.json",
            ArtifactKind::Tokens => "token.json",
            ArtifactKind::Accounts => "accounts.json",
            ArtifactKind::History => "history.json",
            ArtifactKind::CleanIps => "cleanips.json",
            ArtifactKind::Config => "config.json",
            ArtifactKind::TokenHistory => "token_history.json",
            ArtifactKind::CleanIpMeta => "cleanip_meta.json",
            ArtifactKind::TunnelClient => "tunnel-client.json",
            ArtifactKind::GeneratedConfigs => "generated_configs.json",
            ArtifactKind::CarrierPool => "carrier_pool.json",
            ArtifactKind::ActiveProfileMarker => "active_profile",
        }
    }
}

/// One manifest entry: the hash + size of a single artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub sha256: String,
    pub size_bytes: u64,
}

/// The full manifest for one profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileManifest {
    pub schema_version: u32,
    pub profile_id: String,
    pub created_unix: u64,
    /// rel path (within the profile dir) → entry.
    pub entries: BTreeMap<String, ManifestEntry>,
    /// Filenames (within the profile dir) that are tracked at runtime but
    /// excluded from integrity verification (volatile state: health beacon,
    /// daemon pid/log/state, journal, temp files). Documented in the manifest
    /// so the exclusion is explicit, not hidden.
    #[serde(default)]
    pub excluded_patterns: Vec<String>,
}

/// The runtime-only filenames that are never tracked as integrity artifacts.
pub const RUNTIME_EXCLUDED_PATTERNS: [&str; 8] = [
    "manifest.json",
    "health.json",
    "daemon.pid",
    "daemon.stop",
    "daemon.log",
    "daemon-state.json",
    "journal.json",
    "versioning_state.json",
];

/// Whether a filename is a runtime-only file excluded from integrity checks.
pub fn is_runtime_excluded(name: &str) -> bool {
    RUNTIME_EXCLUDED_PATTERNS.contains(&name) || name.starts_with(".dyb_tmp_")
}

/// The on-disk verdict for one artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityStatus {
    /// File present, hash matches manifest.
    Verified,
    /// Manifest references a file that is gone.
    Missing,
    /// File present but hash differs from manifest.
    Changed,
    /// File present but not in the manifest.
    Extra,
    /// No manifest exists for this profile yet.
    NoManifest,
}

impl IntegrityStatus {
    pub fn label(self) -> &'static str {
        match self {
            IntegrityStatus::Verified => "verified",
            IntegrityStatus::Missing => "missing",
            IntegrityStatus::Changed => "changed",
            IntegrityStatus::Extra => "extra",
            IntegrityStatus::NoManifest => "no manifest",
        }
    }
}

/// Result of verifying a single profile against its manifest.
#[derive(Debug, Clone, Default)]
pub struct VerifyReport {
    pub profile_id: String,
    pub has_manifest: bool,
    pub verified: Vec<String>,
    pub missing: Vec<String>,
    pub changed: Vec<String>,
    pub extra: Vec<String>,
    /// Runtime-only files skipped during verification (documented exclusions).
    pub excluded: Vec<String>,
}

impl VerifyReport {
    pub fn is_clean(&self) -> bool {
        self.has_manifest
            && self.missing.is_empty()
            && self.changed.is_empty()
            && self.extra.is_empty()
    }
}

/// The set of per-profile artifacts we track by default.
pub fn profile_artifact_kinds() -> Vec<ArtifactKind> {
    vec![
        ArtifactKind::ProfileMeta,
        ArtifactKind::Tokens,
        ArtifactKind::Accounts,
        ArtifactKind::History,
        ArtifactKind::CleanIps,
        ArtifactKind::Config,
        ArtifactKind::TokenHistory,
        ArtifactKind::CleanIpMeta,
        ArtifactKind::TunnelClient,
        ArtifactKind::GeneratedConfigs,
    ]
}

/// Which kinds live at the workspace level (outside any profile dir).
pub fn workspace_artifact_kinds() -> Vec<ArtifactKind> {
    vec![ArtifactKind::CarrierPool, ArtifactKind::ActiveProfileMarker]
}

/// sha256 (hex) of a file. Returns a friendly error if unreadable.
pub fn sha256_file(path: &Path) -> Result<String, CFError> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).map_err(|e| {
        CFError::new(
            "Manifest error",
            format!("Cannot read {}: {e}", path.display()),
            "Check the file exists and is readable.",
        )
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex_bytes(&hasher.finalize()))
}

/// Hex (lowercase) of a byte slice — avoids pulling in the `hex` crate.
fn hex_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Compute the manifest entry for a file, if it exists.
pub fn entry_for_path(path: &Path) -> Option<ManifestEntry> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let sha256 = sha256_file(path).ok()?;
    Some(ManifestEntry {
        sha256,
        size_bytes: meta.len(),
    })
}

/// Build a manifest for a profile by hashing every tracked artifact currently
/// on disk. Files that don't exist yet are simply omitted (they are not "lost"
/// until the manifest says they should exist).
pub fn build_manifest(profile_id: &str) -> Result<ProfileManifest, CFError> {
    let dir = profile_dir(profile_id);
    let mut entries = BTreeMap::new();
    for kind in profile_artifact_kinds() {
        let rel = kind.filename().to_string();
        let p = dir.join(&rel);
        if let Some(e) = entry_for_path(&p) {
            entries.insert(rel.clone(), e);
        }
    }
    Ok(ProfileManifest {
        schema_version: 1,
        profile_id: profile_id.to_string(),
        created_unix: crate::store::now_ts() as u64,
        entries,
        excluded_patterns: RUNTIME_EXCLUDED_PATTERNS
            .iter()
            .map(|s| s.to_string())
            .collect(),
    })
}

/// Manifest file path for a profile.
pub fn manifest_path(profile_id: &str) -> PathBuf {
    profile_dir(profile_id).join("manifest.json")
}

/// Persist a manifest atomically.
pub fn write_manifest(manifest: &ProfileManifest) -> Result<(), CFError> {
    crate::store::write_json(&manifest_path(&manifest.profile_id), manifest)
}

/// Load a profile's manifest, if present.
pub fn load_manifest(profile_id: &str) -> Option<ProfileManifest> {
    crate::store::read_opt(&manifest_path(profile_id))
}

/// Rebuild a profile's manifest from what is on disk, idempotently. Cheap
/// (≤12 small files). Writes via `atomic_write` directly (not `write_json`)
/// so it never re-triggers the store's manifest-refresh hook (no recursion).
pub fn refresh_manifest_after_write(
    profile_dir: &Path,
    now_unix: u64,
) -> Result<ProfileManifest, CFError> {
    let profile_id = profile_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("default")
        .to_string();
    let mut entries = BTreeMap::new();
    for kind in profile_artifact_kinds() {
        let rel = kind.filename().to_string();
        let p = profile_dir.join(&rel);
        if let Some(e) = entry_for_path(&p) {
            entries.insert(rel, e);
        }
    }
    let manifest = ProfileManifest {
        schema_version: 1,
        profile_id,
        created_unix: now_unix,
        entries,
        excluded_patterns: RUNTIME_EXCLUDED_PATTERNS
            .iter()
            .map(|s| s.to_string())
            .collect(),
    };
    let bytes = serde_json::to_vec_pretty(&manifest).map_err(|e| {
        CFError::new(
            "Manifest error",
            format!("Cannot serialize manifest: {e}"),
            "Internal error.",
        )
    })?;
    crate::store::atomic_write(&profile_dir.join("manifest.json"), &bytes)?;
    Ok(manifest)
}

/// Ensure a profile has a manifest, creating one from disk if missing. Called
/// on the first write of a new profile.
pub fn ensure_manifest(profile_dir: &Path, now_unix: u64) -> Result<(), CFError> {
    if !profile_dir.join("manifest.json").exists() {
        refresh_manifest_after_write(profile_dir, now_unix)?;
    }
    Ok(())
}

/// Verify a profile against its manifest. When no manifest exists, returns a
/// report with `has_manifest=false` and every tracked artifact flagged as
/// `extra`-free but the whole profile `NoManifest`.
pub fn verify_profile(profile_id: &str) -> VerifyReport {
    let dir = profile_dir(profile_id);
    let mut report = VerifyReport {
        profile_id: profile_id.to_string(),
        ..Default::default()
    };

    let Some(manifest) = load_manifest(profile_id) else {
        report.has_manifest = false;
        // Still surface what exists as "extra" so the caller can render an
        // unverified-but-present inventory.
        for kind in profile_artifact_kinds() {
            let p = dir.join(kind.filename());
            if p.is_file() {
                report.extra.push(kind.filename().to_string());
            }
        }
        return report;
    };
    report.has_manifest = true;

    // Track which manifest rel paths we saw so we can detect extras.
    let mut seen = std::collections::BTreeSet::new();

    for (rel, entry) in &manifest.entries {
        match entry_for_path(&dir.join(rel)) {
            None => report.missing.push(rel.clone()),
            Some(current) if current.sha256 == entry.sha256 => {
                seen.insert(rel.clone());
                report.verified.push(rel.clone());
            }
            Some(_) => report.changed.push(rel.clone()),
        }
    }

    // Extras: files in the profile dir that are not in the manifest (and not
    // the manifest itself). Runtime state files (health beacon, daemon pid/
    // stop/log, journal, temp files) are excluded and reported separately in
    // `report.excluded` — they are volatile bookkeeping, not user data.
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            let p = e.path();
            if !p.is_file() {
                continue;
            }
            let name = p
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            if is_runtime_excluded(&name) {
                if name != "manifest.json" && !report.excluded.contains(&name) {
                    report.excluded.push(name);
                }
                continue;
            }
            if !seen.contains(&name) && !manifest.entries.contains_key(&name) {
                report.extra.push(name);
            }
        }
    }

    report.extra.sort();
    report.verified.sort();
    report.missing.sort();
    report.changed.sort();
    report
}

/// Convenience: verify every profile and return per-profile status.
pub fn verify_workspace() -> Vec<(ProfileMeta, VerifyReport)> {
    list_profiles()
        .into_iter()
        .map(|m| {
            let r = verify_profile(&m.id);
            (m, r)
        })
        .collect()
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

    /// Write a few real-looking artifacts so the manifest has something to
    /// record beyond profile.json (a fresh profile only ships profile.json).
    fn seed_artifacts(id: &str) {
        let dir = profile_dir(id);
        std::fs::write(dir.join("accounts.json"), b"{\"a\":1}").unwrap();
        std::fs::write(dir.join("config.json"), b"{\"x\":1}").unwrap();
        std::fs::write(dir.join("token.json"), b"{\"t\":\"abc\"}").unwrap();
    }

    #[test]
    fn build_manifest_hashes_existing_artifacts() {
        with_home(|| {
            let id = fresh_profile_id();
            let m = build_manifest(&id).unwrap();
            // default profile has profile.json + config.json at minimum.
            assert!(m.entries.contains_key("profile.json"));
            assert!(m.schema_version == 1);
        });
    }

    #[test]
    fn verify_ok_on_untouched_profile() {
        with_home(|| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            write_manifest(&build_manifest(&id).unwrap()).unwrap();
            let r = verify_profile(&id);
            assert!(r.has_manifest);
            assert!(
                r.is_clean(),
                "missing={:?} changed={:?} extra={:?}",
                r.missing,
                r.changed,
                r.extra
            );
            assert!(!r.verified.is_empty());
        });
    }

    #[test]
    fn verify_detects_missing_file() {
        with_home(|| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            write_manifest(&build_manifest(&id).unwrap()).unwrap();
            // Delete a tracked artifact.
            std::fs::remove_file(profile_dir(&id).join("accounts.json")).unwrap();
            let r = verify_profile(&id);
            assert!(r.missing.iter().any(|x| x == "accounts.json"));
            assert!(!r.is_clean());
        });
    }

    #[test]
    fn verify_detects_changed_file() {
        with_home(|| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            write_manifest(&build_manifest(&id).unwrap()).unwrap();
            // Tamper with config.json.
            let p = profile_dir(&id).join("config.json");
            std::fs::write(&p, b"{ \"tampered\": true }").unwrap();
            let r = verify_profile(&id);
            assert!(r.changed.iter().any(|x| x == "config.json"));
        });
    }

    #[test]
    fn verify_detects_extra_file() {
        with_home(|| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            write_manifest(&build_manifest(&id).unwrap()).unwrap();
            std::fs::write(profile_dir(&id).join("rogue.json"), b"{}").unwrap();
            let r = verify_profile(&id);
            assert!(r.extra.iter().any(|x| x == "rogue.json"));
        });
    }

    #[test]
    fn manifest_integrity_covers_artifacts_list() {
        with_home(|| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            let m = build_manifest(&id).unwrap();
            write_manifest(&m).unwrap();
            // Tamper a record by editing the manifest on disk.
            let path = manifest_path(&id);
            let mut v: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            v["entries"]["config.json"]["sha256"] = serde_json::Value::String("0".repeat(64));
            crate::store::write_json(&path, &v).unwrap();
            let r = verify_profile(&id);
            assert!(r.changed.iter().any(|x| x == "config.json"));
        });
    }

    #[test]
    fn save_profile_keeps_manifest_fresh() {
        with_home(|| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            write_manifest(&build_manifest(&id).unwrap()).unwrap();

            // A legitimate profile save (the store's normal write path, e.g.
            // set_last_deployed_base_link) must refresh the manifest so the
            // daemon's auto-heal does not misread a normal save as corruption
            // and rewind-restore an old backup.
            let mut prof = crate::store::profiles::load_profile(&id);
            prof.config.last_deployed_base_link =
                Some("vless://abc@worker.example.workers.dev:443#x".into());
            crate::store::profiles::save_profile(&prof).unwrap();

            // Manifest must now match the on-disk state -> no "changed".
            let r = verify_profile(&id);
            assert!(
                r.is_clean(),
                "expected clean after save_profile; missing={:?} changed={:?} extra={:?}",
                r.missing,
                r.changed,
                r.extra
            );
        });
    }

    #[test]
    fn manifest_excludes_mtime_from_integrity() {
        with_home(|| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            write_manifest(&build_manifest(&id).unwrap()).unwrap();
            // Touch a file (mtime changes, content doesn't) → still verifies.
            let p = profile_dir(&id).join("config.json");
            let _ = std::fs::File::options().write(true).open(&p);
            let r = verify_profile(&id);
            assert!(!r.changed.iter().any(|x| x == "config.json"));
        });
    }

    #[test]
    fn verify_marks_no_manifest_when_absent() {
        with_home(|| {
            let id = fresh_profile_id();
            let r = verify_profile(&id);
            assert!(!r.has_manifest);
        });
    }

    #[test]
    fn sha256_file_matches_known_hash() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.txt");
        std::fs::write(&p, b"hello").unwrap();
        // sha256("hello") known value.
        assert_eq!(
            sha256_file(&p).unwrap(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}
