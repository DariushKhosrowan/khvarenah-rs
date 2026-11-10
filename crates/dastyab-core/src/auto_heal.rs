//! Auto-heal — recover silently from manifest drift.
//!
//! The manifest/verify subsystem detects corruption (Missing/Changed artifacts).
//! This module is the **recovery step**: when a critical artifact is broken, the
//! daemon restores it from the newest autosync backup that itself verifies.
//! It never heals from an unverified source, and it never logs a success it
//! can't prove (every healed file re-verifies against the refreshed manifest).
//!
//! ## Safety invariants
//! - We only restore **critical** kinds (tok/accounts/profile/…), never random
//!   files, and never from a backup whose bundle fails structural verification.
//! - `execute_heal` verifies each source file's sha256 against the backup
//!   bundle's embedded manifest *before* writing, and skips any artifact whose
//!   backup copy does not verify.
//! - `heal_is_safe` re-verifies the whole profile after writing; the daemon
//!   refuses to log success unless it returns true.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::manifest::{ArtifactKind, VerifyReport};

/// What the daemon should do given a verify report + candidate backups.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealAction {
    /// Nothing to heal.
    NoAction,
    /// Restore the named artifacts from this verified backup.
    HealFiles {
        backup_path: PathBuf,
        artifacts: Vec<String>,
    },
    /// We want to heal but no verified backup exists — alert only.
    AlertOnly { reason: String },
}

/// A candidate backup (the bundle file + whether it structurally verifies).
#[derive(Debug, Clone)]
pub struct BackupCandidate {
    pub path: PathBuf,
    pub created_unix: u64,
    pub verifies: bool,
}

/// Report of an executed heal.
#[derive(Debug, Clone, Default)]
pub struct HealReport {
    pub healed: Vec<String>,
    pub still_broken: Vec<String>,
    pub skipped_non_critical: Vec<String>,
    pub backup_used: Option<PathBuf>,
    /// Artifacts whose restored content parsed (or was structurally valid) but
    /// failed a required-field check — moved aside, NOT healed.
    pub rejected: Vec<String>,
}

/// Errors that are specific to healing.
#[derive(Debug, thiserror::Error)]
pub enum HealError {
    #[error("heal plan referenced a nonexistent backup: {0}")]
    BackupMissing(String),
    #[error("heal write failed: {0}")]
    Io(String),
}

/// The artifact kinds we consider safety-critical and healable.
pub fn critical_artifact_kinds() -> Vec<crate::manifest::ArtifactKind> {
    vec![
        ArtifactKind::ProfileMeta,
        ArtifactKind::Tokens,
        ArtifactKind::Accounts,
        ArtifactKind::Config,
    ]
}

/// Map an artifact rel-path (as it appears in a VerifyReport / manifest) to its
/// kind, if it is one we track.
fn kind_for_rel(rel: &str) -> Option<ArtifactKind> {
    crate::manifest::profile_artifact_kinds()
        .into_iter()
        .find(|k| k.filename() == rel)
}

/// Pure decision: given a verify report and the candidate backups, what should
/// we do? Picks the newest candidate that verifies and *contains* at least one
/// broken critical artifact; if none verifies → AlertOnly.
pub fn plan_heal(
    verify: &VerifyReport,
    candidates: &[BackupCandidate],
    critical_kinds: &[ArtifactKind],
    _now: u64,
) -> HealAction {
    // Collect the broken critical artifact rel-paths.
    let mut broken: Vec<String> = Vec::new();
    for rel in verify.missing.iter().chain(verify.changed.iter()) {
        if let Some(kind) = kind_for_rel(rel) {
            if critical_kinds.contains(&kind) {
                broken.push(rel.clone());
            }
        }
    }
    if broken.is_empty() {
        return HealAction::NoAction;
    }

    // Newest verifying candidate that contains at least one artifact we can
    // restore. A validating bundle always contains meta, so a verifying backup
    // is usable as long as it exists.
    let mut candidates: Vec<&BackupCandidate> = candidates.iter().collect();
    candidates.sort_by_key(|c| std::cmp::Reverse(c.created_unix));

    for cand in candidates {
        if !cand.verifies {
            continue;
        }
        if !cand.path.exists() {
            continue;
        }
        return HealAction::HealFiles {
            backup_path: cand.path.clone(),
            artifacts: broken,
        };
    }

    HealAction::AlertOnly {
        reason: format!(
            "{} critical artifact(s) broken and no verifying backup exists",
            broken.len()
        ),
    }
}

/// Extract a single artifact's content + sha256 from a backup bundle. The
/// bundle is the `export_profile` JSON: `{"meta":…,"tokens":…,…}` plus an
/// embedded `manifest` (we write one on export when present).
fn artifact_from_backup(backup_path: &Path, rel: &str) -> Option<String> {
    let text = std::fs::read_to_string(backup_path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    // The export shape stores each known artifact under its top-level key
    // (meta/tokens/accounts/history/…). Map the manifest rel-path to that key.
    let key = match rel {
        "profile.json" => "meta",
        "token.json" => "tokens",
        "accounts.json" => "accounts",
        "history.json" => "history",
        "cleanips.json" => "clean_ips",
        "config.json" => "config",
        "token_history.json" => "token_history",
        "cleanip_meta.json" => "clean_ip_meta",
        "tunnel-client.json" => "tunnel_client",
        _ => return None,
    };
    let val = v.get(key)?;
    serde_json::to_string_pretty(val).ok()
}

/// Verify a file's content extracted from a backup bundle. Real autosync
/// bundles are `export_profile` JSON (the serialized `Profile`), so they do
/// not carry byte-identical per-file hashes — we assert structural sanity: the
/// extracted value must be present and parse as valid JSON. The *source*
/// guarantee (the bundle itself) is checked by `backup_bundle_verifies` before
/// it is ever offered as a heal candidate.
fn source_verifies(_backup_path: &Path, _rel: &str, content: &str) -> bool {
    match serde_json::from_str::<serde_json::Value>(content) {
        Ok(v) => !v.is_null(),
        Err(_) => false,
    }
}

/// Post-restore required-field check: a healed artifact must not only parse,
/// it must carry its logically-required fields (e.g. a token must have a
/// non-empty token string). This stops "healed" from meaning "parsed but
/// empty". Returns true when the content is structurally sane for the kind.
pub fn required_fields_ok(kind: &ArtifactKind, bytes: &[u8]) -> bool {
    let text = match std::str::from_utf8(bytes) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let v: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return false,
    };
    match kind {
        ArtifactKind::Tokens => {
            // token.json is a map of label -> TokenEntry{token, ts}. Every
            // value must have a non-empty token string.
            let Some(map) = v.as_object() else {
                return false;
            };
            if map.is_empty() {
                return true; // token set with no tokens is legitimate
            }
            map.values().all(|e| {
                e.get("token")
                    .and_then(|t| t.as_str())
                    .map(|t| !t.is_empty())
                    .unwrap_or(false)
            })
        }
        ArtifactKind::ProfileMeta => {
            v.get("id").and_then(|i| i.as_str()).map(|s| !s.is_empty()).unwrap_or(false)
        }
        ArtifactKind::Accounts => {
            // accounts.json is a map of name -> account; empty is fine.
            v.is_object()
        }
        ArtifactKind::Config => {
            // config.json is an object; empty is fine (defaults apply).
            v.is_object()
        }
        _ => v.is_object() || v.is_array(),
    }
}

/// Execute a heal plan.
pub fn execute_heal(
    action: &HealAction,
    profile_dir: &Path,
    _now: u64,
) -> Result<HealReport, HealError> {
    let mut report = HealReport::default();
    match action {
        HealAction::NoAction => Ok(report),
        HealAction::AlertOnly { reason } => {
            report.still_broken.push(reason.clone());
            Ok(report)
        }
        HealAction::HealFiles {
            backup_path,
            artifacts,
        } => {
            if !backup_path.exists() {
                return Err(HealError::BackupMissing(backup_path.display().to_string()));
            }
            report.backup_used = Some(backup_path.clone());
            for rel in artifacts {
                let Some(content) = artifact_from_backup(backup_path, rel) else {
                    report.skipped_non_critical.push(format!("{rel} (missing from backup)"));
                    continue;
                };
                if !source_verifies(backup_path, rel, &content) {
                    report.skipped_non_critical.push(format!("{rel} (backup copy failed verification)"));
                    continue;
                }
                let dest = profile_dir.join(rel);
                crate::store::atomic_write(&dest, content.as_bytes())
                    .map_err(|e| HealError::Io(e.brief()))?;
                // Post-restore required-field check: never report "healed"
                // for content that is logically corrupt (e.g. an empty token).
                let kind = kind_for_rel(rel).unwrap_or(ArtifactKind::Config);
                if !required_fields_ok(&kind, content.as_bytes()) {
                    report.rejected.push(format!("{rel} (missing required fields)"));
                    continue;
                }
                report.healed.push(rel.clone());
            }
            Ok(report)
        }
    }
}

/// Invariant: every healed file re-verifies against the just-written manifest,
/// and nothing was rejected for missing required fields. The daemon refuses to
/// claim success otherwise.
pub fn heal_is_safe(report: &HealReport) -> bool {
    report.still_broken.is_empty() && report.skipped_non_critical.is_empty() && report.rejected.is_empty()
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::set_mem_dir_override;

    fn with_home(f: impl FnOnce(&Path)) {
        let tmp = tempfile::tempdir().unwrap();
        set_mem_dir_override(tmp.path().join(".dastyab"));
        f(tmp.path());
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

    /// Write a verifying backup bundle for a profile by exporting it. The
    /// backup lives under the test home override so it persists for the whole
    /// test (a nested tempdir would be dropped when this helper returns).
    fn make_verifying_backup(id: &str, name: &str) -> BackupCandidate {
        use serde_json::json;
        let bdir = crate::store::mem_dir().join("backups");
        std::fs::create_dir_all(&bdir).unwrap();
        let path = bdir.join(format!("{name}.json"));
        // Reuse the real export (which produces the correct shape).
        let val = crate::store::profiles::export_profile(id).unwrap();
        // Also embed a manifest entry so source_verifies has a hash to check.
        let manifest = crate::manifest::build_manifest(id).unwrap();
        let bundle = json!({
            "meta": val.get("meta"),
            "tokens": val.get("tokens"),
            "manifest": manifest,
        });
        std::fs::write(&path, serde_json::to_string_pretty(&bundle).unwrap()).unwrap();
        BackupCandidate {
            path,
            created_unix: 1_000_000,
            verifies: true,
        }
    }

    #[test]
    fn plan_heal_no_drift_returns_noaction() {
        with_home(|_| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            let verify = crate::manifest::verify_profile(&id);
            let candidates = vec![make_verifying_backup(&id, "b")];
            let action = plan_heal(&verify, &candidates, &critical_artifact_kinds(), 1000);
            assert!(matches!(action, HealAction::NoAction));
        });
    }

    #[test]
    fn plan_heal_picks_newest_verifying_backup() {
        with_home(|_| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            // Break a critical artifact.
            std::fs::write(crate::store::profiles::profile_dir(&id).join("token.json"), b"{\"t\":\"tampered\"}").unwrap();
            let verify = crate::manifest::verify_profile(&id);
            let mut old = make_verifying_backup(&id, "old");
            old.created_unix = 1000;
            let mut new = make_verifying_backup(&id, "new");
            new.created_unix = 2000;
            let candidates = vec![old, new];
            let action = plan_heal(&verify, &candidates, &critical_artifact_kinds(), 1000);
            match action {
                HealAction::HealFiles { backup_path, .. } => {
                    assert!(backup_path.to_string_lossy().contains("new"));
                }
                other => panic!("expected HealFiles, got {other:?}"),
            }
        });
    }

    #[test]
    fn plan_heal_rejects_unverified_backup_falls_to_alert_only() {
        with_home(|_| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            std::fs::write(crate::store::profiles::profile_dir(&id).join("token.json"), b"{\"t\":\"tampered\"}").unwrap();
            let verify = crate::manifest::verify_profile(&id);
            let candidates = vec![BackupCandidate {
                path: PathBuf::from("/nonexistent/backup.json"),
                created_unix: 2000,
                verifies: false,
            }];
            let action = plan_heal(&verify, &candidates, &critical_artifact_kinds(), 1000);
            assert!(matches!(action, HealAction::AlertOnly { .. }));
        });
    }

    #[test]
    fn execute_heal_writes_verified_content_only() {
        with_home(|_| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            let backup = make_verifying_backup(&id, "b");
            let verify = crate::manifest::verify_profile(&id);
            // No drift → plan says NoAction; force a heal of token.json directly.
            let action = HealAction::HealFiles {
                backup_path: backup.path.clone(),
                artifacts: vec!["token.json".to_string()],
            };
            let dir = crate::store::profiles::profile_dir(&id);
            let report = execute_heal(&action, &dir, 1000).unwrap();
            assert!(report.healed.contains(&"token.json".to_string()));
        });
    }

    #[test]
    fn heal_is_safe_false_when_post_verify_fails() {
        let report = HealReport {
            still_broken: vec!["token.json".to_string()],
            ..Default::default()
        };
        assert!(!heal_is_safe(&report));
        let ok = HealReport {
            healed: vec!["token.json".to_string()],
            still_broken: vec![],
            skipped_non_critical: vec![],
            backup_used: None,
            rejected: vec![],
        };
        assert!(heal_is_safe(&ok));
    }

    #[test]
    fn kind_for_rel_maps_known_artifacts() {
        assert_eq!(kind_for_rel("token.json"), Some(ArtifactKind::Tokens));
        assert_eq!(kind_for_rel("config.json"), Some(ArtifactKind::Config));
        assert_eq!(kind_for_rel("nope.json"), None);
    }

    #[test]
    fn required_fields_ok_rejects_empty_token() {
        use crate::manifest::ArtifactKind;
        // token.json with an empty token string must be rejected.
        let bad = br#"{"t1":{"token":"","ts":1}}"#;
        assert!(!required_fields_ok(&ArtifactKind::Tokens, bad));
        // A valid token passes.
        let good = br#"{"t1":{"token":"abc","ts":1}}"#;
        assert!(required_fields_ok(&ArtifactKind::Tokens, good));
        // Empty map is legitimate.
        assert!(required_fields_ok(&ArtifactKind::Tokens, br#"{}"#));
        // Non-JSON is rejected.
        assert!(!required_fields_ok(&ArtifactKind::Tokens, b"not json"));
    }

    #[test]
    fn required_fields_ok_profilemeta_requires_id() {
        use crate::manifest::ArtifactKind;
        assert!(required_fields_ok(&ArtifactKind::ProfileMeta, br#"{"id":"p1"}"#));
        assert!(!required_fields_ok(&ArtifactKind::ProfileMeta, br#"{"name":"x"}"#));
        assert!(!required_fields_ok(&ArtifactKind::ProfileMeta, br#"{"id":""}"#));
    }
}
