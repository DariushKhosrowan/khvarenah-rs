//! Profile backup & restore.
//!
//! A profile is just a directory of small JSON files. Backing it up is a
//! matter of exporting it to a single portable JSON bundle; restoring is the
//! reverse. This gives users a safe, human-readable way to move their setup
//! between machines without ever touching raw token files.

use serde::{Deserialize, Serialize};

use crate::error::CFError;
use crate::store::profiles::{export_profile, import_profile, list_profiles, ProfileMeta};

/// A backup record pointing at a saved bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupRecord {
    pub profile_id: String,
    pub profile_name: String,
    pub path: String,
    pub created_at: String,
    pub size: u64,
}

/// Default backup directory under `~/.khvarenah/backups/`.
pub fn backup_dir() -> std::path::PathBuf {
    crate::store::mem_dir().join("backups")
}

/// Export a profile to a JSON bundle file. Returns the written path.
pub fn export_profile_to_file(
    profile_id: &str,
    path: Option<&std::path::Path>,
) -> Result<std::path::PathBuf, CFError> {
    let value = export_profile(profile_id)?;
    let dest = match path {
        Some(p) => p.to_path_buf(),
        None => {
            // Default: backups/<profile>-<ts>.json
            let dir = backup_dir();
            std::fs::create_dir_all(&dir)
                .map_err(|e| CFError::new("Backup error", format!("{e}"), "Check permissions."))?;
            let ts = crate::store::now_ts().to_string();
            dir.join(format!("{profile_id}-{ts}.json"))
        }
    };

    let json = serde_json::to_string_pretty(&value)
        .map_err(|e| CFError::new("Backup error", format!("{e}"), "Internal error."))?;
    crate::store::atomic_write(&dest, json.as_bytes())?;
    Ok(dest)
}

/// Restore a profile from a JSON bundle. Returns the restored profile id.
pub fn import_profile_from_file(path: &std::path::Path) -> Result<String, CFError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        CFError::new(
            "Backup error",
            format!("Cannot read {}: {e}", path.display()),
            "Check the file path.",
        )
    })?;
    let value: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
        CFError::new(
            "Backup error",
            format!("Invalid JSON: {e}"),
            "Export a profile first.",
        )
    })?;
    import_profile(&value)
}

/// List existing backups in the default backup directory.
pub fn list_backups() -> Vec<BackupRecord> {
    let mut out = Vec::new();
    let dir = backup_dir();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let path = e.path();
            if path.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            let created = std::fs::metadata(&path)
                .and_then(|m| m.modified())
                .ok()
                .map(|t| {
                    use std::time::SystemTime;
                    let d = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
                    d.as_secs() as f64
                })
                .unwrap_or(0.0);
            let created_at = if created > 0.0 {
                chrono::DateTime::from_timestamp(created as i64, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_default()
            } else {
                String::new()
            };
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            out.push(BackupRecord {
                profile_id: name.clone(),
                profile_name: name,
                path: path.display().to_string(),
                created_at,
                size,
            });
        }
    }
    out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    out
}

/// Human-friendly size string.
pub fn human_size(bytes: u64) -> String {
    crate::analytics::human_bytes(bytes)
}

/// Build a summary of what is backed up.
pub fn backup_summary() -> String {
    let backups = list_backups();
    let mut out = format!("Backups in {}: {}\n", backup_dir().display(), backups.len());
    for b in backups.iter().take(10) {
        out.push_str(&format!(
            "  • {} ({}) — {} at {}\n",
            b.profile_name,
            human_size(b.size),
            b.path,
            b.created_at
        ));
    }
    if backups.is_empty() {
        out.push_str("  none yet — use `khvarenah backup export`\n");
    }
    out
}

/// List recallable profile metadata (for overview screens).
pub fn profiles_overview() -> Vec<ProfileMeta> {
    list_profiles()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_size_uses_human_bytes() {
        assert!(human_size(0).contains("B"));
    }
}
