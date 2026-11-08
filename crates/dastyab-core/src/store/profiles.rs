//! Per-profile persistence layer.
//!
//! Each named profile is a directory under `~/.dastyab/profiles/<id>/`.
//! All tokens, generated configs, clean IPs and settings are namespaced to a
//! profile. Creating a profile is just a directory; switching is reading the
//! other directory; updating the app never touches these directories (they
//! are outside the install path), so user data can never be cleared by an
//! upgrade.
//!
//! ## Migration
//! On first run, the legacy flat files (`history.json`, `tokens.json`,
//! `accounts.json`, `config.json`) are imported into the `default` profile and
//! the originals are moved to `~/.dastyab/legacy/`. Migration is
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
    /// One-button "Protection": persisted so the monitor auto-resumes after an
    /// app restart (the product's main toggle).
    #[serde(default)]
    pub protection_enabled: bool,
    /// Light-check cadence in seconds (WS-gate only; cheap ~200ms).
    #[serde(default = "default_light_interval")]
    pub light_interval_secs: u64,
    /// Consecutive light-check failures; escalates to a deep E2E check at 2.
    #[serde(default)]
    pub failure_streak: u8,
    /// UNIX epoch seconds of the last deep (E2E) check.
    #[serde(default)]
    pub last_deep_check: i64,
    /// UNIX epoch seconds of the last worker redeploy (rate-limit guard).
    #[serde(default)]
    pub last_redeploy_ts: i64,
    /// UNIX epoch seconds of the last rescue-chain attempt (throttling).
    #[serde(default)]
    pub last_rescue_attempt_ts: i64,
    /// Outcome of the most recent rescue chain: "recovered" | "gave_up".
    #[serde(default)]
    pub last_rescue_outcome: Option<String>,
    /// Self-learning phase-2 SNI strategy. `None` = not yet learned (auto →
    /// WorkerOnly). Stored as the enum's name so it survives serde and can be
    /// spawned across crate boundaries.
    #[serde(default)]
    pub preferred_phase2_strategy: Option<String>,
    /// Consecutive phase-2 cycles that yielded zero accepted `101`s under the
    /// preferred strategy (the "zero streak"). At 3 the app rotates strategy.
    #[serde(default)]
    pub strategy_zero_streak: u32,
    /// UNIX epoch seconds the strategy was last (re)learned / rotated.
    #[serde(default)]
    pub strategy_last_updated_ts: i64,
}

fn default_light_interval() -> u64 {
    300
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
            protection_enabled: false,
            light_interval_secs: 300,
            failure_streak: 0,
            last_deep_check: 0,
            last_redeploy_ts: 0,
            last_rescue_attempt_ts: 0,
            last_rescue_outcome: None,
            preferred_phase2_strategy: None,
            strategy_zero_streak: 0,
            strategy_last_updated_ts: 0,
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

/// Path of the file that records the active token label for a profile.
fn active_token_path(id: &str) -> PathBuf {
    profile_dir(id).join("active_token")
}

/// Return the label of the profile's active token.
///
/// Returns `Ok(None)` when there is no active-token file, or when the label
/// no longer exists in `tokens.json` (the token was probably deleted). It
/// never errors for a missing/stale marker — that is an expected state.
pub fn get_active_token(profile_id: &str) -> Result<Option<String>, CFError> {
    let label = match read_opt::<String>(&active_token_path(profile_id)) {
        Some(l) if !l.trim().is_empty() => l.trim().to_string(),
        _ => return Ok(None),
    };
    let p = load_profile(profile_id);
    if p.tokens.contains_key(&label) {
        Ok(Some(label))
    } else {
        // stale marker — the token was removed. Log a warning and clear it.
        eprintln!(
            "[dastyab] warn: active token '{label}' no longer exists in profile '{profile_id}'"
        );
        let _ = write_json(&active_token_path(profile_id), &String::new());
        Ok(None)
    }
}

/// Persist the active token label for a profile.
pub fn set_active_token(profile_id: &str, label: &str) -> Result<(), CFError> {
    let p = load_profile(profile_id);
    if !p.tokens.contains_key(label) {
        return Err(CFError::new(
            "Storage error",
            format!("Token '{label}' does not exist in this profile."),
            "Save the token first, then select it as active.",
        ));
    }
    write_json(&active_token_path(profile_id), &label.trim().to_string())
}

/// Clear the active token marker for a profile.
pub fn clear_active_token(profile_id: &str) -> Result<(), CFError> {
    write_json(&active_token_path(profile_id), &String::new())
}

/// Look up a token's plaintext by label (used by verify + deploy).
pub fn get_token(id: &str, label: &str) -> Result<Option<String>, CFError> {
    Ok(load_profile(id).tokens.get(label).map(|e| e.token.clone()))
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

/// Whether the one-button Protection monitor is active for this profile.
pub fn protection_enabled(id: &str) -> bool {
    load_profile(id).config.protection_enabled
}

/// Set the persisted Protection monitor flag (survives app restarts).
pub fn set_protection(id: &str, enabled: bool) -> Result<(), CFError> {
    let mut cfg = load_profile(id).config;
    cfg.protection_enabled = enabled;
    save_config(id, &cfg)
}

/// Read the persisted self-learning phase-2 SNI strategy. Returns `None`
/// before the first cycle learns one (the engine auto-defaults to WorkerOnly).
pub fn preferred_phase2_strategy(id: &str) -> Option<String> {
    load_profile(id).config.preferred_phase2_strategy.clone()
}

/// Read the consecutive zero-101 streak (rotation trigger at 3).
pub fn strategy_zero_streak(id: &str) -> u32 {
    load_profile(id).config.strategy_zero_streak
}

/// Read the epoch timestamp of the last strategy (re)learn / rotation.
pub fn strategy_last_updated_ts(id: &str) -> i64 {
    load_profile(id).config.strategy_last_updated_ts
}

/// Persist the learned strategy + zero-streak + timestamp in one atomic save.
pub fn commit_strategy_state(
    id: &str,
    preferred: Option<String>,
    zero_streak: u32,
) -> Result<(), CFError> {
    let mut cfg = load_profile(id).config;
    cfg.preferred_phase2_strategy = preferred;
    cfg.strategy_zero_streak = zero_streak;
    cfg.strategy_last_updated_ts = crate::store::now_ts() as i64;
    save_config(id, &cfg)
}

/// The monitor's two-tier escalation state (light/deep cadence). DeepSeek
/// plan: light WS-gate check every `light_interval_secs`; 2 consecutive light
/// failures escalate to a deep E2E check; a deep failure triggers a swap.
#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
pub struct ProtectionState {
    #[serde(default)]
    pub failure_streak: u8,
    #[serde(default)]
    pub last_deep_check: i64,
}

/// Read the monitor's escalation state (defaults when absent).
pub fn protection_state(id: &str) -> ProtectionState {
    let cfg = load_profile(id).config;
    ProtectionState {
        failure_streak: cfg.failure_streak,
        last_deep_check: cfg.last_deep_check,
    }
}

/// Persist the monitor's escalation state.
pub fn save_protection_state(id: &str, st: &ProtectionState) -> Result<(), CFError> {
    let mut cfg = load_profile(id).config;
    cfg.failure_streak = st.failure_streak;
    cfg.last_deep_check = st.last_deep_check;
    save_config(id, &cfg)
}

/// Persist the auto-rescue chain's bookkeeping (rate-limit + outcome).
pub fn save_rescue_meta(
    id: &str,
    last_rescue_attempt_ts: i64,
    last_redeploy_ts: i64,
    last_rescue_outcome: Option<String>,
) -> Result<(), CFError> {
    let mut cfg = load_profile(id).config;
    cfg.last_rescue_attempt_ts = last_rescue_attempt_ts;
    cfg.last_redeploy_ts = last_redeploy_ts;
    cfg.last_rescue_outcome = last_rescue_outcome;
    save_config(id, &cfg)
}

/// The last parallel-scan diagnostics (so the GUI/CLI can explain a zero
/// result in plain language). Written by the discovery pipeline each cycle.
pub fn save_last_diagnostics(
    id: &str,
    diag: &crate::slipscan::PipelineDiagnostics,
) -> Result<(), CFError> {
    let p = profile_dir(id).join("last-diagnostics.json");
    write_json(&p, diag)
}

/// Read the last saved pipeline diagnostics, if any.
pub fn load_last_diagnostics(id: &str) -> Option<crate::slipscan::PipelineDiagnostics> {
    let p = profile_dir(id).join("last-diagnostics.json");
    read_opt::<crate::slipscan::PipelineDiagnostics>(&p)
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
        let base = tmp.path().join(".dastyab");
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
    fn get_active_token_returns_none_when_file_missing() {
        with_home(|| {
            ensure_mem_dir().unwrap();
            let id = create_profile("work", "").unwrap();
            // fresh profile, no active-token file
            assert_eq!(get_active_token(&id).unwrap(), None);
        });
    }

    #[test]
    fn get_active_token_returns_none_when_label_no_longer_exists() {
        with_home(|| {
            ensure_mem_dir().unwrap();
            let id = create_profile("work", "").unwrap();
            // write a stale marker pointing at a token that doesn't exist
            fs::create_dir_all(profile_dir(&id)).unwrap();
            write_json(
                &profile_dir(&id).join("active_token"),
                &"deleted-token".to_string(),
            )
            .unwrap();
            assert_eq!(get_active_token(&id).unwrap(), None);
            // a second read also returns None (marker stays cleared/no-op)
            assert_eq!(get_active_token(&id).unwrap(), None);
        });
    }

    #[test]
    fn active_token_roundtrip_and_clear() {
        with_home(|| {
            ensure_mem_dir().unwrap();
            let id = create_profile("work", "").unwrap();
            add_token(&id, "primary", "tok1").unwrap();

            // unknown label -> error
            assert!(set_active_token(&id, "nope").is_err());

            // set + read back
            set_active_token(&id, "primary").unwrap();
            assert_eq!(get_active_token(&id).unwrap().as_deref(), Some("primary"));

            // clear
            clear_active_token(&id).unwrap();
            assert_eq!(get_active_token(&id).unwrap(), None);
        });
    }

    #[test]
    fn get_token_by_label() {
        with_home(|| {
            ensure_mem_dir().unwrap();
            let id = create_profile("work", "").unwrap();
            add_token(&id, "primary", "tok-secret").unwrap();
            assert_eq!(
                get_token(&id, "primary").unwrap().as_deref(),
                Some("tok-secret")
            );
            assert_eq!(get_token(&id, "missing").unwrap(), None);
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

    #[test]
    fn protection_state_defaults_when_absent() {
        with_home(|| {
            ensure_mem_dir().unwrap();
            let id = create_profile("work", "").unwrap();
            let st = protection_state(&id);
            assert_eq!(st.failure_streak, 0);
            assert_eq!(st.last_deep_check, 0);
        });
    }

    #[test]
    fn protection_state_roundtrip() {
        with_home(|| {
            ensure_mem_dir().unwrap();
            let id = create_profile("work", "").unwrap();
            let st = ProtectionState {
                failure_streak: 2,
                last_deep_check: 1_720_000_000,
            };
            save_protection_state(&id, &st).unwrap();
            let got = protection_state(&id);
            assert_eq!(got.failure_streak, 2);
            assert_eq!(got.last_deep_check, 1_720_000_000);
        });
    }

    #[test]
    fn old_protection_state_deserializes_with_new_fields_default() {
        with_home(|| {
            ensure_mem_dir().unwrap();
            let id = create_profile("work", "").unwrap();
            // Simulate a profile written by an older version: config has only
            // protection_enabled (no streak/deep fields). Loading must default
            // the new fields instead of failing.
            let mut cfg = load_profile(&id).config;
            cfg.protection_enabled = true;
            // Strip the new fields by serializing the old shape.
            let old_json = serde_json::json!({
                "active_account": cfg.active_account,
                "protection_enabled": true,
            });
            write_json(&profile_dir(&id).join("config.json"), &old_json).unwrap();
            let p = load_profile(&id);
            assert!(p.config.protection_enabled);
            assert_eq!(p.config.failure_streak, 0);
            assert_eq!(p.config.last_deep_check, 0);
            assert_eq!(p.config.light_interval_secs, 300);
        });
    }
}
