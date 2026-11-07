//! Per-profile persistence layer.
//!
//! Each named profile is a directory under `~/.khvarenah/profiles/<id>/`.
//! All tokens, generated configs, clean IPs and settings are namespaced to a
//! profile. Creating a profile is just a directory; switching is reading the
//! other directory; updating the app never touches these directories (they
//! are outside the install path), so user data can never be cleared by an
//! upgrade.
//!
//! ## Migration
//! On first run, the legacy flat files (`history.json`, `tokens.json`,
//! `accounts.json`, `config.json`) are imported into the `default` profile and
//! the originals are moved to `~/.khvarenah/legacy/`. Migration is
//! idempotent: running it twice is a no-op.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::{
    ensure_mem_dir, mem_dir, new_id, profiles_dir, read_opt, read_or_default, set_file_private,
    write_json,
};
use crate::error::CFError;

/// Metadata for a single profile.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileMeta {
    pub id: String,
    pub name: String,
    pub created_at: String,
    #[serde(default)]
    pub description: String,
}

/// A single saved vless config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlessRecord {
    pub id: String,
    pub ts: String,
    pub epoch: f64,
    pub uuid: String,
    pub address: String,
    pub port: u16,
    pub name: String,
    #[serde(default)]
    pub clean_ip: bool,
    #[serde(default)]
    pub link: String,
    #[serde(default)]
    pub note: String,
}

impl Default for VlessRecord {
    fn default() -> Self {
        Self {
            id: String::new(),
            ts: String::new(),
            epoch: 0.0,
            uuid: String::new(),
            address: String::new(),
            port: 443,
            name: String::new(),
            clean_ip: false,
            link: String::new(),
            note: String::new(),
        }
    }
}

/// A remembered Cloudflare account.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Account {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub subdomain: String,
}

/// Per-profile settings persisted separately from tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfig {
    #[serde(default)]
    pub active_account: String,
    #[serde(default)]
    pub stealth_enabled: bool,
    #[serde(default)]
    pub scan_count: u32,
    #[serde(default)]
    pub scan_workers: u32,
    #[serde(default)]
    pub scan_timeout: u32,
    #[serde(default)]
    pub scan_ports: String,
    #[serde(default)]
    pub scan_gentle: bool,
}

impl Default for ProfileConfig {
    fn default() -> Self {
        Self {
            active_account: String::new(),
            stealth_enabled: true,
            scan_count: 2000,
            scan_workers: 50,
            scan_timeout: 8,
            scan_ports: "443".to_string(),
            scan_gentle: true,
        }
    }
}

/// One token keyed by a display label.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEntry {
    pub token: String,
    pub ts: String,
}

/// The complete per-profile state.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Profile {
    pub meta: ProfileMeta,
    pub tokens: BTreeMap<String, TokenEntry>,
    pub accounts: BTreeMap<String, Account>,
    pub history: Vec<VlessRecord>,
    pub clean_ips: Vec<String>,
    pub config: ProfileConfig,
}

/// List all profiles (sorted by name). Never fails; empty on error.
pub fn list_profiles() -> Vec<ProfileMeta> {
    let dir = profiles_dir();
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(&dir) {
        for e in entries.flatten() {
            let meta_path = e.path().join("profile.json");
            if let Some(meta) = read_opt::<ProfileMeta>(&meta_path) {
                out.push(meta);
            }
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Create a profile. Returns its id.
pub fn create_profile(name: &str, description: &str) -> Result<String, CFError> {
    ensure_mem_dir()?;
    let id = new_id();
    let dir = profiles_dir().join(&id);
    fs::create_dir_all(&dir).map_err(|e| {
        CFError::new(
            "Storage error",
            format!("Cannot create profile dir: {e}"),
            "Check filesystem permissions.",
        )
    })?;
    let now = crate::store::now_iso();
    let meta = ProfileMeta {
        id: id.clone(),
        name: name.trim().to_string(),
        created_at: now.clone(),
        description: description.to_string(),
    };
    write_json(&dir.join("profile.json"), &meta)?;
    Ok(id)
}

/// Ensure the `default` profile exists (used on first run / migration).
fn ensure_default_profile() -> Result<PathBuf, CFError> {
    ensure_mem_dir()?;
    let dir = profiles_dir().join("default");
    if !dir.join("profile.json").exists() {
        let meta = ProfileMeta {
            id: "default".to_string(),
            name: "Default".to_string(),
            created_at: crate::store::now_iso(),
            description: "Default profile (migrated from the original app)".to_string(),
        };
        write_json(&dir.join("profile.json"), &meta)?;
    }
    Ok(dir)
}

/// Profile directory for a given id; missing profiles fall back to `default`.
pub fn profile_dir(id: &str) -> PathBuf {
    if id == "default" || list_profiles().iter().any(|m| m.id == id) {
        profiles_dir().join(id)
    } else {
        profiles_dir().join("default")
    }
}

/// Load a profile by id (falls back to empty defaults).
pub fn load_profile(id: &str) -> Profile {
    let dir = profile_dir(id);
    let meta = read_opt::<ProfileMeta>(&dir.join("profile.json")).unwrap_or_else(|| ProfileMeta {
        id: id.to_string(),
        name: id.to_string(),
        created_at: String::new(),
        description: String::new(),
    });
    let tokens = read_or_default::<BTreeMap<String, TokenEntry>>(&dir.join("token.json"));
    let accounts = read_or_default::<BTreeMap<String, Account>>(&dir.join("accounts.json"));
    let history = read_or_default::<Vec<VlessRecord>>(&dir.join("history.json"));
    let clean_ips = read_or_default::<Vec<String>>(&dir.join("cleanips.json"));
    let config = read_or_default::<ProfileConfig>(&dir.join("config.json"));
    Profile {
        meta,
        tokens,
        accounts,
        history,
        clean_ips,
        config,
    }
}

/// Persist an entire profile.
pub fn save_profile(p: &Profile) -> Result<(), CFError> {
    let dir = profile_dir(&p.meta.id);
    fs::create_dir_all(&dir).map_err(|e| {
        CFError::new(
            "Storage error",
            format!("Cannot create {}: {e}", dir.display()),
            "Check permissions.",
        )
    })?;
    write_json(&dir.join("profile.json"), &p.meta)?;
    write_json(&dir.join("token.json"), &p.tokens)?;
    set_file_private(&dir.join("token.json"));
    write_json(&dir.join("accounts.json"), &p.accounts)?;
    write_json(&dir.join("history.json"), &p.history)?;
    write_json(&dir.join("cleanips.json"), &p.clean_ips)?;
    write_json(&dir.join("config.json"), &p.config)?;
    Ok(())
}

/// Delete a profile directory (never the `default` profile).
pub fn delete_profile(id: &str) -> Result<(), CFError> {
    if id == "default" {
        return Err(CFError::new(
            "Storage error",
            "Cannot delete the default profile.",
            "Create a new profile, then delete the old one.",
        ));
    }
    let dir = profile_dir(id);
    if dir.exists() {
        fs::remove_dir_all(&dir).map_err(|e| {
            CFError::new(
                "Storage error",
                format!("Cannot delete profile: {e}"),
                "Check permissions.",
            )
        })?;
    }
    Ok(())
}

/// Rename a profile (updates its metadata only).
pub fn rename_profile(id: &str, new_name: &str) -> Result<(), CFError> {
    let mut p = load_profile(id);
    p.meta.name = new_name.trim().to_string();
    save_profile(&p)
}

/// Export a profile as a JSON blob (for backup / sharing).
pub fn export_profile(id: &str) -> Result<serde_json::Value, CFError> {
    let p = load_profile(id);
    serde_json::to_value(&p).map_err(|e| {
        CFError::new(
            "Export error",
            format!("Cannot serialize profile: {e}"),
            "Internal error.",
        )
    })
}

/// Import a profile from a JSON blob (from `export_profile` or hand-made).
pub fn import_profile(json: &serde_json::Value) -> Result<String, CFError> {
    let id = json
        .get("meta")
        .and_then(|m| m.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let id = if id.is_empty() { new_id() } else { id };
    let dir = profiles_dir().join(&id);
    fs::create_dir_all(&dir).map_err(|e| {
        CFError::new(
            "Storage error",
            format!("Cannot create profile dir: {e}"),
            "Check permissions.",
        )
    })?;

    // Write each known sub-file if present.
    let mut wrote_any = false;
    if let Some(meta) = json.get("meta") {
        write_json(&dir.join("profile.json"), meta)?;
        wrote_any = true;
    }
    if let Some(tokens) = json.get("tokens") {
        write_json(&dir.join("token.json"), tokens)?;
        set_file_private(&dir.join("token.json"));
        wrote_any = true;
    }
    if let Some(accounts) = json.get("accounts") {
        write_json(&dir.join("accounts.json"), accounts)?;
        wrote_any = true;
    }
    if let Some(history) = json.get("history") {
        write_json(&dir.join("history.json"), history)?;
        wrote_any = true;
    }
    if let Some(clean) = json.get("clean_ips") {
        write_json(&dir.join("cleanips.json"), clean)?;
        wrote_any = true;
    }
    if let Some(cfg) = json.get("config") {
        write_json(&dir.join("config.json"), cfg)?;
        wrote_any = true;
    }
    if !wrote_any {
        return Err(CFError::new(
            "Import error",
            "No recognizable profile data found.",
            "Export a profile first, then import that file.",
        ));
    }
    if !dir.join("profile.json").exists() {
        let meta = ProfileMeta {
            id: id.clone(),
            name: "Imported".to_string(),
            created_at: crate::store::now_iso(),
            description: String::new(),
        };
        write_json(&dir.join("profile.json"), &meta)?;
    }
    Ok(id)
}

/// Add a token to a profile (keyed by label).
pub fn add_token(id: &str, label: &str, token: &str) -> Result<(), CFError> {
    let mut p = load_profile(id);
    p.tokens.insert(
        label.to_string(),
        TokenEntry {
            token: token.trim().to_string(),
            ts: crate::store::now_iso(),
        },
    );
    save_profile(&p)
}

/// Remove a token from a profile.
pub fn remove_token(id: &str, label: &str) -> Result<(), CFError> {
    let mut p = load_profile(id);
    p.tokens.remove(label);
    save_profile(&p)
}

/// Add a remembered account.
pub fn remember_account(
    id: &str,
    account_id: &str,
    name: &str,
    subdomain: &str,
) -> Result<(), CFError> {
    let mut p = load_profile(id);
    let entry = p.accounts.entry(account_id.to_string()).or_default();
    if !name.is_empty() {
        entry.name = name.to_string();
    }
    if !subdomain.is_empty() {
        entry.subdomain = subdomain.to_string();
    }
    save_profile(&p)
}

/// Append a vless record (keeps newest-first order, capped at 500).
pub fn remember_vless(id: &str, rec: VlessRecord) -> Result<(), CFError> {
    let mut p = load_profile(id);
    p.history.insert(0, rec);
    if p.history.len() > 500 {
        p.history.truncate(500);
    }
    save_profile(&p)
}

/// Add a clean IP string (dedup, keep list ordered by insertion).
pub fn remember_clean_ip(id: &str, ip: &str) -> Result<(), CFError> {
    let mut p = load_profile(id);
    if !p.clean_ips.contains(&ip.to_string()) {
        p.clean_ips.push(ip.to_string());
    }
    save_profile(&p)
}

/// Update per-profile settings.
pub fn save_config(id: &str, cfg: &ProfileConfig) -> Result<(), CFError> {
    let mut p = load_profile(id);
    p.config = cfg.clone();
    save_profile(&p)
}

/// --- Legacy migration ---
const LEGACY_FILES: &[&str] = &[
    "history.json",
    "tokens.json",
    "accounts.json",
    "config.json",
];

/// Migrate legacy flat files into the `default` profile. Idempotent.
///
/// Returns the number of files migrated (0 = nothing to do).
pub fn migrate_legacy() -> Result<usize, CFError> {
    let mem = mem_dir();
    let legacy_dir = mem.join("legacy");
    let has_any_legacy = LEGACY_FILES.iter().any(|f| mem.join(f).exists());

    if !has_any_legacy {
        // Nothing to migrate. Still make sure a default profile exists.
        ensure_default_profile()?;
        return Ok(0);
    }

    fs::create_dir_all(&legacy_dir).map_err(|e| {
        CFError::new(
            "Storage error",
            format!("Cannot create legacy dir: {e}"),
            "Check permissions.",
        )
    })?;
    let def_dir = ensure_default_profile()?;
    let mut migrated = 0;

    let mut p = load_profile("default");

    if let Some(tok) = read_opt::<serde_json::Value>(&mem.join("tokens.json")) {
        if let Ok(values) = serde_json::from_value::<BTreeMap<String, TokenEntry>>(tok) {
            p.tokens.extend(values);
            migrated += 1;
        }
    }
    if let Some(acc) = read_opt::<serde_json::Value>(&mem.join("accounts.json")) {
        if let Ok(values) = serde_json::from_value::<BTreeMap<String, Account>>(acc) {
            p.accounts.extend(values);
            migrated += 1;
        }
    }
    if let Some(hist) = read_opt::<serde_json::Value>(&mem.join("history.json")) {
        if let Ok(values) = serde_json::from_value::<Vec<VlessRecord>>(hist) {
            p.history.extend(values);
            migrated += 1;
        }
    }
    if let Some(cfg) = read_opt::<serde_json::Value>(&mem.join("config.json")) {
        if let Ok(values) = serde_json::from_value::<ProfileConfig>(cfg) {
            p.config = values;
            migrated += 1;
        }
    }

    save_profile(&p)?;

    // Move originals into legacy/ so migration is one-shot.
    for f in LEGACY_FILES {
        let src = mem.join(f);
        if src.exists() {
            let dst = legacy_dir.join(f);
            let _ = fs::rename(&src, &dst);
        }
    }

    let _ = def_dir;
    Ok(migrated)
}

/// Rename the legacy file target.
pub fn legacy_dir() -> PathBuf {
    mem_dir().join("legacy")
}

/// The file that remembers which profile is active, so a restart reopens the
/// same profile. Kept in the memory root (not inside any profile dir).
fn active_profile_path() -> PathBuf {
    mem_dir().join("active_profile")
}

/// Return the id of the active profile. Defaults to `"default"`.
pub fn get_active_profile() -> String {
    let p = active_profile_path();
    read_opt::<String>(&p).unwrap_or_else(|| "default".to_string())
}

/// Persist the active profile id so it survives restarts. If `id` is not a
/// known profile, it falls back to `"default"`.
pub fn set_active_profile(id: &str) -> Result<(), CFError> {
    let known = list_profiles().iter().any(|m| m.id == id);
    let final_id = if known {
        id.to_string()
    } else {
        "default".to_string()
    };
    write_json(&active_profile_path(), &final_id)
}

/// Convenience: current timestamp as ISO-8601-like string.
pub fn now_iso() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Convenience: current unix epoch seconds.
pub fn now_ts() -> f64 {
    chrono::Utc::now().timestamp() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_home(f: impl FnOnce()) {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join(".khvarenah");
        crate::store::set_mem_dir_override(base);
        f();
    }

    #[test]
    fn profile_roundtrip() {
        with_home(|| {
            let id = create_profile("work", "my work profile").unwrap();
            let p = load_profile(&id);
            assert_eq!(p.meta.name, "work");
            add_token(&id, "cf-main", "secret-token").unwrap();
            let p2 = load_profile(&id);
            assert_eq!(p2.tokens.get("cf-main").unwrap().token, "secret-token");
        });
    }

    #[test]
    fn active_profile_defaults_to_default() {
        with_home(|| {
            ensure_mem_dir().unwrap();
            assert_eq!(get_active_profile(), "default");
        });
    }

    #[test]
    fn active_profile_roundtrip_and_fallback() {
        with_home(|| {
            ensure_mem_dir().unwrap();
            let id = create_profile("work", "").unwrap();

            // set to the real profile, read back
            set_active_profile(&id).unwrap();
            assert_eq!(get_active_profile(), id);

            // unknown profile falls back to default
            set_active_profile("does-not-exist").unwrap();
            assert_eq!(get_active_profile(), "default");
        });
    }

    #[test]
    fn migration_idempotent() {
        with_home(|| {
            // Simulate legacy files.
            fs::create_dir_all(mem_dir()).unwrap();
            fs::write(
                mem_dir().join("tokens.json"),
                r#"{"cf-main": {"token": "legacy-tok", "ts": "2026-01-01"}}"#,
            )
            .unwrap();
            fs::write(
                mem_dir().join("accounts.json"),
                r#"{"acc1": {"name": "Acc", "subdomain": "sd"}}"#,
            )
            .unwrap();
            fs::write(mem_dir().join("history.json"), "[]").unwrap();
            fs::write(mem_dir().join("config.json"), "{}").unwrap();

            let n1 = migrate_legacy().unwrap();
            assert!(n1 >= 1);

            // Second run must be a no-op.
            let n2 = migrate_legacy().unwrap();
            assert_eq!(n2, 0);

            let p = load_profile("default");
            assert_eq!(p.tokens.get("cf-main").unwrap().token, "legacy-tok");
            assert!(p.accounts.contains_key("acc1"));
            // original moved to legacy/
            assert!(!mem_dir().join("tokens.json").exists());
            assert!(legacy_dir().join("tokens.json").exists());
        });
    }
}
