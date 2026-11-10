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
    /// --- v2 rolling-window strategy (round 3, replaces the streak design) ---
    /// Current strategy name ("WorkerOnly" | "GenericCfFirst"). None = unlearned.
    #[serde(default)]
    pub strategy_current: Option<String>,
    /// Rolling window of recent discovery-cycle outcomes: 0=zero-verified,
    /// 1=any-101. Newest at end, capped at STRATEGY_WINDOW (10).
    #[serde(default)]
    pub strategy_recent_outcomes: Vec<u8>,
    /// Discovery cycles since the last rotation (forced-exploration counter).
    #[serde(default)]
    pub strategy_cycles_since_rotation: u32,
    /// UNIX epoch seconds of the last rotation.
    #[serde(default)]
    pub strategy_last_rotated_ts: i64,
    /// Remote push-notification config (Telegram or webhook). `None` =
    /// disabled (default). Kept as an `Option` so old configs migrate cleanly.
    #[serde(default)]
    pub beacon: Option<crate::remote_beacon::BeaconConfig>,
    /// Scheduled config mutation settings (worker signature rotation).
    #[serde(default)]
    pub mutation: crate::config_mutation::MutationConfig,
    /// Scheduled profile auto-backup settings (crash/blackout resilience).
    #[serde(default)]
    pub backup_autosync: crate::backup_autosync::BackupAutoSyncConfig,
    /// UNIX epoch seconds of the last config mutation.
    #[serde(default)]
    pub last_mutation_ts: i64,
    /// Multi-worker parallel redundancy set (round 19).
    #[serde(default)]
    pub worker_set: crate::multi_worker::WorkerSet,
    /// Anti-DPI TCP desync fragmenter (round 21). Disabled by default.
    #[serde(default)]
    pub desync: crate::desync::DesyncConfig,
    /// Monitor LIGHT-phase budget in seconds (WS-gate sweep). 0 = system default
    /// (`cycle_guard::MONITOR_TIMEOUT_SECS`, 120). Configurable in-app so a
    /// degraded network can use a tighter budget and fail fast.
    #[serde(default)]
    pub light_timeout_secs: u64,
    /// Monitor DEEP-phase (discovery+E2E) budget in seconds. 0 = system default
    /// (`cycle_guard::DISCOVERY_TIMEOUT_SECS`, 600). On a degraded tier the
    /// daemon also auto-caps this (see `effective_deep_timeout_from_tier`).
    #[serde(default)]
    pub deep_timeout_secs: u64,
    /// Daemon backoff ceiling in seconds. 0 = system default
    /// (`daemon::DEFAULT_MAX_INTERVAL_SECS`, 21600 = 6h). Lower it to make the
    /// daemon re-rotate faster during a long blackout instead of pausing
    /// protection for hours.
    #[serde(default)]
    pub max_backoff_secs: u64,
    /// When the active Cloudflare token is blocked/invalid, automatically
    /// verify the other stored tokens and swap to the first working one —
    /// no manual `dastyab token recover` step. Default on.
    #[serde(default = "default_auto_rotate_on_blocked")]
    pub auto_rotate_on_blocked: bool,
    /// Daemon poll cadence (seconds) while the network is fully down (total
    /// blackout). 0 = system default (`daemon::NETWORK_DOWN_SLEEP_SECS`, 60).
    /// A shorter value makes the daemon re-probe for a restored path sooner
    /// after a blackout; a longer value conserves battery/CPU during a long
    /// outage. Configurable in-app (GUI Settings / CLI `config timeouts`).
    #[serde(default)]
    pub network_down_sleep_secs: u64,
    /// Scheduled blackout self-test (drill) cadence in seconds: the daemon
    /// periodically probes every fallback-ladder rung (Direct → DoH → DoT →
    /// DNS tunnel), journals how many survive, and alerts if resilience
    /// degrades. 0 = system default (`daemon::DRILL_INTERVAL_SECS`, 86400).
    #[serde(default)]
    pub drill_interval_secs: u64,
    /// Path to the durable offline carrier pool (the "which endpoints can I
    /// try with zero network" substrate). Relative to the profile store unless
    /// absolute. Defaults to `<mem_dir>/carrier_pool.json`.
    #[serde(default)]
    pub carrier_pool_path: Option<PathBuf>,
    /// Per-worker session secrets with two-phase rotation state. Keyed by
    /// worker URL. Falls back to the legacy shared secret when a worker has no
    /// entry yet (see `worker_tunnel::secret::resolve_worker_secret`).
    #[serde(default)]
    pub worker_secrets:
        std::collections::HashMap<String, crate::worker_tunnel::secret::WorkerSecret>,
}

fn default_auto_rotate_on_blocked() -> bool {
    true
}

fn default_light_interval() -> u64 {
    300
}

/// Effective monitor light-phase budget (seconds) for a profile config. A
/// zero/absent value falls back to the system default
/// (`cycle_guard::MONITOR_TIMEOUT_SECS`). Configured in-app (GUI Settings /
/// CLI `timeouts`).
pub fn effective_light_timeout_secs(c: &ProfileConfig) -> u64 {
    if c.light_timeout_secs > 0 {
        c.light_timeout_secs
    } else {
        crate::cycle_guard::MONITOR_TIMEOUT_SECS
    }
}

/// Effective monitor deep-phase budget (seconds) for a profile config. A
/// zero/absent value falls back to the system default
/// (`cycle_guard::DISCOVERY_TIMEOUT_SECS`). The daemon further auto-caps this
/// on degraded tiers (see `autopilot::effective_deep_timeout_from_tier`).
pub fn effective_deep_timeout_secs(c: &ProfileConfig) -> u64 {
    if c.deep_timeout_secs > 0 {
        c.deep_timeout_secs
    } else {
        crate::cycle_guard::DISCOVERY_TIMEOUT_SECS
    }
}

/// Effective daemon backoff ceiling (seconds) for a profile config. A
/// zero/absent value falls back to the system default
/// (`daemon::DEFAULT_MAX_INTERVAL_SECS`, 6h). Lowering this makes the daemon
/// re-rotate faster during a long blackout.
pub fn effective_max_backoff_secs(c: &ProfileConfig) -> u64 {
    if c.max_backoff_secs > 0 {
        c.max_backoff_secs
    } else {
        crate::daemon::DEFAULT_MAX_INTERVAL_SECS
    }
}

/// Effective daemon poll cadence (seconds) while the network is fully down.
/// A zero/absent value falls back to the system default
/// (`daemon::NETWORK_DOWN_SLEEP_SECS`, 60).
pub fn effective_network_down_sleep_secs(c: &ProfileConfig) -> u64 {
    if c.network_down_sleep_secs > 0 {
        c.network_down_sleep_secs
    } else {
        crate::daemon::NETWORK_DOWN_SLEEP_SECS
    }
}

/// Effective scheduled-drill cadence: per-profile override or the system
/// default. 0 means "use the default".
pub fn effective_drill_interval_secs(c: &ProfileConfig) -> u64 {
    if c.drill_interval_secs > 0 {
        c.drill_interval_secs
    } else {
        crate::daemon::DRILL_INTERVAL_SECS
    }
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
            strategy_current: None,
            strategy_recent_outcomes: Vec::new(),
            strategy_cycles_since_rotation: 0,
            strategy_last_rotated_ts: 0,
            beacon: None,
            mutation: crate::config_mutation::MutationConfig::default(),
            backup_autosync: crate::backup_autosync::BackupAutoSyncConfig::default(),
            last_mutation_ts: 0,
            worker_set: crate::multi_worker::WorkerSet::default(),
            desync: crate::desync::DesyncConfig::default(),
            light_timeout_secs: 0,
            deep_timeout_secs: 0,
            max_backoff_secs: 0,
            auto_rotate_on_blocked: true,
            network_down_sleep_secs: 0,
            drill_interval_secs: 0,
            carrier_pool_path: None,
            worker_secrets: std::collections::HashMap::new(),
        }
    }
}

/// One token keyed by a display label.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEntry {
    pub token: String,
    pub ts: String,
}

/// One recorded event in a profile's token lifecycle (added / removed /
/// made-active / verified / rotated). This is the durable "history of added
/// tokens" ledger the GUI renders on the Tokens tab.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEvent {
    pub id: String,
    pub ts: String,
    pub epoch: f64,
    pub label: String,
    /// "added" | "removed" | "made_active" | "verified" | "rotated" | "auto_rotate"
    pub kind: String,
    #[serde(default)]
    pub note: String,
}

/// Provenance metadata for one saved clean IP (source + verification times).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CleanIpMeta {
    /// "scan" | "import" | "manual"
    #[serde(default = "default_cleanip_source")]
    pub source: String,
    /// Port parsed from the endpoint string (defaults to 443).
    #[serde(default = "default_cleanip_port")]
    pub port: u16,
    /// ISO timestamp of the first time this endpoint was recorded.
    #[serde(default)]
    pub first_verified_at: String,
    /// ISO timestamp of the most recent verification / touch.
    #[serde(default)]
    pub last_verified_at: String,
}

fn default_cleanip_source() -> String {
    "scan".to_string()
}

fn default_cleanip_port() -> u16 {
    443
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
    /// Durable ledger of token-lifecycle events (added/removed/active/verify).
    #[serde(default)]
    pub token_history: Vec<TokenEvent>,
    /// Per-endpoint provenance metadata, keyed by the saved endpoint string.
    #[serde(default)]
    pub clean_ip_meta: BTreeMap<String, CleanIpMeta>,
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
    let token_history = read_or_default::<Vec<TokenEvent>>(&dir.join("token_history.json"));
    let clean_ip_meta =
        read_or_default::<BTreeMap<String, CleanIpMeta>>(&dir.join("cleanip_meta.json"));
    Profile {
        meta,
        tokens,
        accounts,
        history,
        clean_ips,
        config,
        token_history,
        clean_ip_meta,
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
    write_json(&dir.join("token_history.json"), &p.token_history)?;
    write_json(&dir.join("cleanip_meta.json"), &p.clean_ip_meta)?;
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
    if let Some(th) = json.get("token_history") {
        write_json(&dir.join("token_history.json"), th)?;
        wrote_any = true;
    }
    if let Some(cim) = json.get("clean_ip_meta") {
        write_json(&dir.join("cleanip_meta.json"), cim)?;
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
    push_token_event(&mut p, "added", label, "saved to profile");
    save_profile(&p)
}

/// Remove a token from a profile.
pub fn remove_token(id: &str, label: &str) -> Result<(), CFError> {
    let mut p = load_profile(id);
    let had = p.tokens.remove(label).is_some();
    if had {
        push_token_event(&mut p, "removed", label, "removed from profile");
    }
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
    let mut p = load_profile(profile_id);
    if !p.tokens.contains_key(label) {
        return Err(CFError::new(
            "Storage error",
            format!("Token '{label}' does not exist in this profile."),
            "Save the token first, then select it as active.",
        ));
    }
    push_token_event(&mut p, "made_active", label, "selected as the active token");
    save_profile(&p)?;
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

/// Remove a single VlessRecord by its id. Returns `Ok(false)` when no record
/// matched (a no-op). Used by the History view's per-item delete.
pub fn remove_history_record(id: &str, rec_id: &str) -> Result<bool, CFError> {
    let mut p = load_profile(id);
    let before = p.history.len();
    p.history.retain(|r| r.id != rec_id);
    let removed = p.history.len() != before;
    save_profile(&p)?;
    Ok(removed)
}

/// Clear the entire config history (deploys + clean-IP records) for a profile.
/// The journal is untouched — that is a separate stream.
pub fn clear_history(id: &str) -> Result<(), CFError> {
    let mut p = load_profile(id);
    p.history.clear();
    save_profile(&p)
}

/// Add a clean IP string (dedup, keep list ordered by insertion).
pub fn remember_clean_ip(id: &str, ip: &str) -> Result<(), CFError> {
    remember_clean_ip_with_source(id, ip, "scan")
}

/// Add a clean IP string with a provenance source ("scan" | "import" |
/// "manual"). Records first/last verified timestamps for the manager view.
pub fn remember_clean_ip_with_source(id: &str, ip: &str, source: &str) -> Result<(), CFError> {
    let mut p = load_profile(id);
    let ep = ip.trim().to_string();
    if ep.is_empty() {
        return Ok(());
    }
    let now = crate::store::now_iso();
    let port = parse_ip_port(&ep);
    if !p.clean_ips.contains(&ep) {
        p.clean_ips.push(ep.clone());
        let meta = CleanIpMeta {
            source: source.to_string(),
            port,
            first_verified_at: now.clone(),
            last_verified_at: now,
        };
        p.clean_ip_meta.insert(ep.clone(), meta);
    } else if let Some(m) = p.clean_ip_meta.get_mut(&ep) {
        m.last_verified_at = now;
        m.port = port;
        if m.source == "scan" {
            m.source = source.to_string();
        }
    }
    save_profile(&p)
}

fn parse_ip_port(ep: &str) -> u16 {
    ep.rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .unwrap_or(443)
}

/// Remove a single saved clean IP. Returns `Ok(false)` when it was not
/// present (a no-op). Used by the Clean IPs manager view.
pub fn remove_clean_ip(id: &str, ip: &str) -> Result<bool, CFError> {
    let mut p = load_profile(id);
    let before = p.clean_ips.len();
    p.clean_ips.retain(|x| x != ip);
    p.clean_ip_meta.remove(ip);
    let removed = p.clean_ips.len() != before;
    save_profile(&p)?;
    Ok(removed)
}

/// Clear all saved clean IPs for a profile. Used by the Clean IPs manager's
/// "clear all" action.
pub fn clear_clean_ips(id: &str) -> Result<(), CFError> {
    let mut p = load_profile(id);
    p.clean_ips.clear();
    p.clean_ip_meta.clear();
    save_profile(&p)
}

/// Record a token-lifecycle event on a profile (in-memory; caller saves).
fn push_token_event(p: &mut Profile, kind: &str, label: &str, note: &str) {
    let now = crate::store::now_iso();
    p.token_history.insert(
        0,
        TokenEvent {
            id: crate::store::new_id(),
            ts: now.clone(),
            epoch: crate::store::now_ts(),
            label: label.to_string(),
            kind: kind.to_string(),
            note: note.to_string(),
        },
    );
    if p.token_history.len() > 300 {
        p.token_history.truncate(300);
    }
}

/// Record a "verified" token event and persist it. Used by the GUI verify
/// flow so the history ledger reflects real checks.
pub fn record_token_verified(id: &str, label: &str, note: &str) -> Result<(), CFError> {
    let mut p = load_profile(id);
    push_token_event(&mut p, "verified", label, note);
    save_profile(&p)
}

/// The token-lifecycle ledger for a profile (newest first).
pub fn token_history(id: &str) -> Vec<TokenEvent> {
    load_profile(id).token_history
}

/// The per-endpoint provenance map for a profile.
pub fn clean_ip_meta(id: &str) -> BTreeMap<String, CleanIpMeta> {
    load_profile(id).clean_ip_meta
}

/// Clear the token-lifecycle ledger for a profile.
pub fn clear_token_history(id: &str) -> Result<(), CFError> {
    let mut p = load_profile(id);
    p.token_history.clear();
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

/// --- v2 rolling-window strategy persistence ---
///
/// Read the current v2 strategy name (None = unlearned).
pub fn strategy_current(id: &str) -> Option<String> {
    load_profile(id).config.strategy_current.clone()
}

/// Read the v2 rolling outcome window (0=zero-verified, 1=any-101).
pub fn strategy_recent_outcomes(id: &str) -> Vec<u8> {
    load_profile(id).config.strategy_recent_outcomes.clone()
}

/// Read the number of discovery cycles since the last rotation.
pub fn strategy_cycles_since_rotation(id: &str) -> u32 {
    load_profile(id).config.strategy_cycles_since_rotation
}

/// Read the last-rotation epoch timestamp.
pub fn strategy_last_rotated_ts(id: &str) -> i64 {
    load_profile(id).config.strategy_last_rotated_ts
}

/// Persist the v2 rolling-window strategy state atomically.
pub fn commit_strategy_state_v2(
    id: &str,
    current: Option<String>,
    recent_outcomes: Vec<u8>,
    cycles_since_rotation: u32,
    last_rotated_ts: i64,
) -> Result<(), CFError> {
    let mut cfg = load_profile(id).config;
    cfg.strategy_current = current;
    cfg.strategy_recent_outcomes = recent_outcomes;
    cfg.strategy_cycles_since_rotation = cycles_since_rotation;
    cfg.strategy_last_rotated_ts = last_rotated_ts;
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

// ---------------------------------------------------------------------------
// Cross-worker failover ledger + profile rotation.
//
// When a profile's worker is unrecoverable (rescue gave up, the worker is
// suspended or the path is blocked) the daemon can switch the ACTIVE profile to
// a different profile whose worker is alive. This removes the last single
// point of failure — the assumption that the active profile always has a
// working worker. The ledger below remembers which profiles recently failed so
// selection skips them, and gets cleared when a profile recovers.
// ---------------------------------------------------------------------------

/// One failure record in the failover ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverEntry {
    pub profile_id: String,
    /// UNIX seconds the profile was marked failed.
    pub marked_at: i64,
    pub reason: String,
}

/// The failover ledger: which profiles recently failed and why.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FailoverLedger {
    pub entries: Vec<FailoverEntry>,
}

/// How long a profile stays in the "failed" set before it can be tried again.
/// 24h gives the operator time to fix the worker while keeping the daemon from
/// bouncing back onto a known-broken profile every cycle.
pub const FAILOVER_FAIL_WINDOW_SECS: i64 = 86_400;

fn failover_ledger_path() -> PathBuf {
    mem_dir().join("failover.json")
}

/// Load the failover ledger (empty on error / first run).
pub fn load_failover_ledger() -> FailoverLedger {
    read_or_default::<FailoverLedger>(&failover_ledger_path())
}

/// Mark a profile as failed (e.g. its worker gave up rescue). Appends a
/// deduped entry and persists the ledger.
pub fn mark_profile_failed(profile_id: &str, reason: &str) -> Result<(), CFError> {
    let mut ledger = load_failover_ledger();
    let now = now_ts() as i64;
    ledger.entries.retain(|e| e.profile_id != profile_id);
    ledger.entries.push(FailoverEntry {
        profile_id: profile_id.to_string(),
        marked_at: now,
        reason: reason.to_string(),
    });
    write_json(&failover_ledger_path(), &ledger)
}

/// Clear a profile's failure marker (e.g. it recovered a working worker).
pub fn clear_profile_failed(profile_id: &str) -> Result<(), CFError> {
    let mut ledger = load_failover_ledger();
    ledger.entries.retain(|e| e.profile_id != profile_id);
    write_json(&failover_ledger_path(), &ledger)
}

/// Return the set of profiles marked failed within the last `window_secs`.
pub fn failed_profiles_within(window_secs: i64) -> Vec<String> {
    let now = now_ts() as i64;
    load_failover_ledger()
        .entries
        .into_iter()
        .filter(|e| now - e.marked_at <= window_secs)
        .map(|e| e.profile_id)
        .collect()
}

/// Pick the next profile to fail over to. Round-robin by name over ALL known
/// profiles, skipping the `current_id` and profiles failed within the fail
/// window. Returns `None` when there is no other eligible profile.
pub fn select_next_profile(current_id: &str) -> Option<String> {
    let failed = failed_profiles_within(FAILOVER_FAIL_WINDOW_SECS);
    list_profiles()
        .into_iter()
        .filter(|m| m.id != current_id && !failed.contains(&m.id))
        .map(|m| m.id)
        .next()
}

/// Atomically switch the active profile to `target_id`, after clearing its
/// failure marker (we are trusting it now). Returns the previous active id.
pub fn rotate_active_profile(target_id: &str) -> Result<String, CFError> {
    let prev = get_active_profile();
    if prev == target_id {
        return Ok(prev);
    }
    let _ = clear_profile_failed(target_id);
    set_active_profile(target_id)?;
    Ok(prev)
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

    /// New blackout-resilience config fields must default to 0 (= system
    /// default) and survive a save/load round-trip against an OLD config that
    /// predates them (serde-default migration).
    #[test]
    fn profile_config_migrates_new_timeout_fields() {
        with_home(|| {
            let id = create_profile("cfg", "").unwrap();
            // Simulate an old config file without the new fields.
            let dir = profile_dir(&id);
            crate::store::write_json(
                &dir.join("config.json"),
                &serde_json::json!({
                    "scan_count": 42,
                    "protection_enabled": true,
                }),
            )
            .unwrap();
            let mut p = load_profile(&id);
            assert_eq!(p.config.scan_count, 42);
            assert!(p.config.protection_enabled);
            // New fields default to 0 → effective = system default.
            assert_eq!(p.config.light_timeout_secs, 0);
            assert_eq!(p.config.deep_timeout_secs, 0);
            assert_eq!(p.config.max_backoff_secs, 0);
            assert_eq!(
                effective_light_timeout_secs(&p.config),
                crate::cycle_guard::MONITOR_TIMEOUT_SECS
            );
            assert_eq!(
                effective_deep_timeout_secs(&p.config),
                crate::cycle_guard::DISCOVERY_TIMEOUT_SECS
            );
            assert_eq!(effective_max_backoff_secs(&p.config), 21600);
            // Setting a value persists and is honored.
            p.config.deep_timeout_secs = 900;
            save_profile(&p).unwrap();
            let p2 = load_profile(&id);
            assert_eq!(p2.config.deep_timeout_secs, 900);
            assert_eq!(effective_deep_timeout_secs(&p2.config), 900);
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

    #[test]
    fn mark_and_clear_profile_failed() {
        with_home(|| {
            ensure_mem_dir().unwrap();
            let id = create_profile("work", "").unwrap();
            mark_profile_failed(&id, "worker down").unwrap();
            let failed = failed_profiles_within(FAILOVER_FAIL_WINDOW_SECS);
            assert!(failed.contains(&id));
            clear_profile_failed(&id).unwrap();
            let failed = failed_profiles_within(FAILOVER_FAIL_WINDOW_SECS);
            assert!(!failed.contains(&id));
        });
    }

    #[test]
    fn failed_profiles_expire_after_window() {
        with_home(|| {
            ensure_mem_dir().unwrap();
            let id = create_profile("work", "").unwrap();
            // Seed a ledger entry with an old marked_at (outside the fail window).
            let ledger = FailoverLedger {
                entries: vec![FailoverEntry {
                    profile_id: id.clone(),
                    marked_at: now_ts() as i64 - FAILOVER_FAIL_WINDOW_SECS - 1,
                    reason: "old".into(),
                }],
            };
            write_json(&failover_ledger_path(), &ledger).unwrap();
            let failed = failed_profiles_within(FAILOVER_FAIL_WINDOW_SECS);
            assert!(!failed.contains(&id), "expired entry must not be failed");
        });
    }

    #[test]
    fn select_next_profile_skips_failed() {
        with_home(|| {
            ensure_mem_dir().unwrap();
            let a = create_profile("a", "").unwrap();
            let b = create_profile("b", "").unwrap();
            mark_profile_failed(&b, "worker down").unwrap();
            // b is failed, so from a there is no eligible other → none.
            assert_eq!(select_next_profile(&a), None);
            // From b, a is eligible.
            assert_eq!(select_next_profile(&b), Some(a));
        });
    }

    #[test]
    fn select_next_profile_round_robin() {
        with_home(|| {
            ensure_mem_dir().unwrap();
            let a = create_profile("a", "").unwrap();
            let b = create_profile("b", "").unwrap();
            // list_profiles sorts by name → [a, b].
            // From a: skips a, picks the first other → b.
            assert_eq!(select_next_profile(&a), Some(b.clone()));
            // From b: skips b, picks the first remaining → a.
            assert_eq!(select_next_profile(&b), Some(a));
        });
    }

    #[test]
    fn select_next_profile_none_when_all_failed() {
        with_home(|| {
            ensure_mem_dir().unwrap();
            let a = create_profile("a", "").unwrap();
            let b = create_profile("b", "").unwrap();
            mark_profile_failed(&b, "worker down").unwrap();
            assert_eq!(select_next_profile(&a), None);
        });
    }

    #[test]
    fn rotate_active_profile_atomic_swap() {
        with_home(|| {
            ensure_mem_dir().unwrap();
            let a = create_profile("a", "").unwrap();
            let b = create_profile("b", "").unwrap();
            set_active_profile(&a).unwrap();
            // Mark b failed, then fail over TO b: its marker must be cleared
            // (we are trusting it now) and the active profile must become b.
            mark_profile_failed(&b, "worker down").unwrap();
            let prev = rotate_active_profile(&b).unwrap();
            assert_eq!(prev, a);
            assert_eq!(get_active_profile(), b);
            assert!(
                !failed_profiles_within(FAILOVER_FAIL_WINDOW_SECS).contains(&b),
                "rotated-to profile's failure marker must be cleared"
            );
        });
    }

    #[test]
    fn effective_network_down_sleep_defaults_to_system() {
        let cfg = ProfileConfig::default();
        assert_eq!(
            effective_network_down_sleep_secs(&cfg),
            crate::daemon::NETWORK_DOWN_SLEEP_SECS
        );
    }

    #[test]
    fn effective_network_down_sleep_uses_configured() {
        let mut cfg = ProfileConfig::default();
        cfg.network_down_sleep_secs = 15;
        assert_eq!(effective_network_down_sleep_secs(&cfg), 15);
    }

    #[test]
    fn effective_drill_interval_defaults_to_system() {
        let cfg = ProfileConfig::default();
        assert_eq!(
            effective_drill_interval_secs(&cfg),
            crate::daemon::DRILL_INTERVAL_SECS
        );
    }

    #[test]
    fn effective_drill_interval_uses_configured() {
        let mut cfg = ProfileConfig::default();
        cfg.drill_interval_secs = 3600;
        assert_eq!(effective_drill_interval_secs(&cfg), 3600);
    }

    #[test]
    fn remove_clean_ip_dedups_and_reports() {
        with_home(|| {
            let id = create_profile("work", "").unwrap();
            remember_clean_ip(&id, "104.16.1.1").unwrap();
            remember_clean_ip(&id, "104.16.1.1").unwrap(); // dedup
            remember_clean_ip(&id, "104.16.2.2").unwrap();
            assert_eq!(load_profile(&id).clean_ips.len(), 2);
            assert!(remove_clean_ip(&id, "104.16.1.1").unwrap());
            assert!(!remove_clean_ip(&id, "104.16.1.1").unwrap()); // already gone
            assert_eq!(load_profile(&id).clean_ips, vec!["104.16.2.2".to_string()]);
        });
    }

    #[test]
    fn clear_clean_ips_empties_list() {
        with_home(|| {
            let id = create_profile("work", "").unwrap();
            remember_clean_ip(&id, "104.16.1.1").unwrap();
            clear_clean_ips(&id).unwrap();
            assert!(load_profile(&id).clean_ips.is_empty());
        });
    }

    #[test]
    fn remove_and_clear_history_records() {
        with_home(|| {
            let id = create_profile("work", "").unwrap();
            let rec1 = VlessRecord {
                id: "rec-1".into(),
                address: "a.workers.dev".into(),
                port: 443,
                ..Default::default()
            };
            let rec2 = VlessRecord {
                id: "rec-2".into(),
                address: "b.workers.dev".into(),
                port: 443,
                ..Default::default()
            };
            remember_vless(&id, rec1).unwrap();
            remember_vless(&id, rec2).unwrap();
            assert_eq!(load_profile(&id).history.len(), 2);
            assert!(remove_history_record(&id, "rec-1").unwrap());
            assert!(!remove_history_record(&id, "rec-1").unwrap());
            assert_eq!(load_profile(&id).history.len(), 1);
            clear_history(&id).unwrap();
            assert!(load_profile(&id).history.is_empty());
        });
    }

    #[test]
    fn token_ledger_records_add_remove_active() {
        with_home(|| {
            let id = create_profile("work", "").unwrap();
            add_token(&id, "cf-main", "cf_live_secret_abcdefgh").unwrap();
            let th = token_history(&id);
            assert_eq!(th.len(), 1);
            assert_eq!(th[0].kind, "added");
            assert_eq!(th[0].label, "cf-main");

            set_active_token(&id, "cf-main").unwrap();
            let th = token_history(&id);
            assert_eq!(th[0].kind, "made_active");

            remove_token(&id, "cf-main").unwrap();
            let th = token_history(&id);
            assert_eq!(th[0].kind, "removed");
            assert_eq!(th.len(), 3);

            clear_token_history(&id).unwrap();
            assert!(token_history(&id).is_empty());
        });
    }

    #[test]
    fn clean_ip_provenance_tracks_source_and_port() {
        with_home(|| {
            let id = create_profile("work", "").unwrap();
            remember_clean_ip_with_source(&id, "104.16.1.1:2053", "import").unwrap();
            let p = load_profile(&id);
            let meta = p.clean_ip_meta.get("104.16.1.1:2053").unwrap();
            assert_eq!(meta.source, "import");
            assert_eq!(meta.port, 2053);
            assert!(!meta.first_verified_at.is_empty());
            assert!(!meta.last_verified_at.is_empty());

            // duplicate add is a no-op for the list, updates last_verified_at
            remember_clean_ip_with_source(&id, "104.16.1.1:2053", "scan").unwrap();
            let p = load_profile(&id);
            assert_eq!(p.clean_ips.len(), 1);
            assert_eq!(p.clean_ip_meta["104.16.1.1:2053"].source, "import");

            remove_clean_ip(&id, "104.16.1.1:2053").unwrap();
            let p = load_profile(&id);
            assert!(p.clean_ips.is_empty());
            assert!(p.clean_ip_meta.is_empty());
        });
    }

    #[test]
    fn bare_clean_ip_defaults_to_port_443() {
        with_home(|| {
            let id = create_profile("work", "").unwrap();
            remember_clean_ip_with_source(&id, "104.16.1.1", "manual").unwrap();
            let meta = load_profile(&id).clean_ip_meta["104.16.1.1"].clone();
            assert_eq!(meta.source, "manual");
            assert_eq!(meta.port, 443);
        });
    }
}
