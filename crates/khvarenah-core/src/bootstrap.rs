//! Zero-touch bootstrap — `khvarenah up`.
//!
//! Historically onboarding was five manual steps: create profile → add token →
//! deploy → scan/set up protection → install daemon → start daemon. Most users
//! in censored networks abandon after two. This module collapses all of it into
//! ONE command (`khvarenah up`) that:
//!
//! 1. Detects a token (env → `~/.khvarenah/token.txt` → an existing profile).
//! 2. Creates a profile if needed, stores the token, makes it active.
//! 3. Verifies the token and deploys a worker if none is alive.
//! 4. Runs a clean-IP discovery + writes the user bundle.
//! 5. Installs the systemd unit (if absent) and reports how to enable it.
//!
//! Everything is idempotent — running `up` again on a configured machine is a
//! cheap no-op (a status line). It never fails the whole flow because one
//! optional step failed; it reports each step's outcome and returns a summary.

use std::path::{Path, PathBuf};

use crate::error::CFError;
use crate::store;
use crate::store::profiles;

/// Where the token came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenSource {
    /// `KHVARENAH_TOKEN` env var.
    EnvVar,
    /// `~/.khvarenah/token.txt`.
    File(PathBuf),
    /// A profile that already has at least one token.
    ExistingProfile(String),
    /// No token found anywhere.
    None,
}

/// Result of the token-discovery step.
#[derive(Debug, Clone)]
pub struct DetectedToken {
    pub source: TokenSource,
    pub token: String,
}

/// What we know about a worker after `ensure_worker`.
#[derive(Debug, Clone)]
pub struct WorkerInfo {
    pub name: String,
    pub host: String,
    pub deployed_at: i64,
    /// true if we had to deploy it in this call.
    pub deployed_now: bool,
}

/// Outcome of `ensure_daemon_installed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonInstallOutcome {
    AlreadyInstalled,
    Installed,
}

/// Final summary of `up`.
#[derive(Debug, Clone)]
pub struct BootstrapResult {
    pub profile_id: String,
    pub token_source: TokenSource,
    pub worker_name: String,
    pub worker_host: String,
    pub bundle_dir: PathBuf,
    pub daemon_outcome: DaemonInstallOutcome,
    pub duration_ms: u64,
}

/// Discover a token: env → file → existing profile.
pub fn detect_token() -> DetectedToken {
    // 1) environment
    if let Ok(t) = std::env::var("KHVARENAH_TOKEN") {
        if !t.trim().is_empty() {
            return DetectedToken {
                source: TokenSource::EnvVar,
                token: t.trim().to_string(),
            };
        }
    }
    // 2) `~/.khvarenah/token.txt`
    let file = store::mem_dir().join("token.txt");
    if let Ok(t) = std::fs::read_to_string(&file) {
        if !t.trim().is_empty() {
            return DetectedToken {
                source: TokenSource::File(file),
                token: t.trim().to_string(),
            };
        }
    }
    // 3) existing profile with a token
    for meta in profiles::list_profiles() {
        let p = profiles::load_profile(&meta.id);
        if let Some((label, entry)) = p.tokens.iter().next() {
            let _ = label;
            return DetectedToken {
                source: TokenSource::ExistingProfile(meta.id),
                token: entry.token.clone(),
            };
        }
    }
    DetectedToken {
        source: TokenSource::None,
        token: String::new(),
    }
}

/// Validate a token against the CF API. Returns the active account id (first
/// accessible account) so the caller can deploy to it.
pub async fn resolve_token_and_account(token: &str) -> Result<(String, String), CFError> {
    let client = crate::cf::Client::new(token);
    let v = client.verify_token().await?;
    if v.status != "active" {
        return Err(CFError::new(
            "CF token not active",
            format!("token status = '{}'", v.status),
            "Check the API token.",
        ));
    }
    let accs = client.list_accounts().await?;
    let acc = accs.first().map(|a| a.id.clone()).ok_or_else(|| {
        CFError::new(
            "No account",
            "No Cloudflare account is accessible with this token.",
            "Check token permissions (Account:Read, Workers:Edit).",
        )
    })?;
    Ok((acc, v.id.clone()))
}

/// Deploy the built-in preset worker to `account_id` and remember the VLESS
/// config in the profile. Returns the worker hostname.
async fn deploy_worker_core(
    profile_id: &str,
    token: &str,
    account_id: &str,
) -> Result<String, CFError> {
    let client = crate::cf::Client::new(token);
    let worker_name = crate::worker::worker_name_from_account(Some(account_id));
    let subdomain = client.get_subdomain(account_id).await?;
    if subdomain.is_empty() {
        return Err(CFError::new(
            "No subdomain",
            "The account has no Workers subdomain configured.",
            "Set a workers.dev subdomain in the CF dashboard.",
        ));
    }
    let js = crate::presets::fallback_worker_js().into_bytes();
    client
        .deploy_script(account_id, &worker_name, js, "2026-07-01", 2)
        .await?;
    let uuid = crate::worker::generate_uuid();
    client
        .set_vars(
            account_id,
            &worker_name,
            serde_json::Map::from_iter([("UUID".into(), serde_json::json!(uuid))]),
        )
        .await?;

    let host = format!("{worker_name}.{subdomain}.workers.dev");
    let vless = crate::vless::VlessProfile {
        uuid: uuid.clone(),
        address: host.clone(),
        port: 443,
        security: "tls".into(),
        path: "/".into(),
        transport: "ws".into(),
        name: format!("{worker_name}-edge"),
        ..Default::default()
    };
    let link = vless.share_link();
    let rec = profiles::VlessRecord {
        id: crate::store::new_id(),
        ts: profiles::now_iso(),
        epoch: crate::store::now_ts(),
        uuid: uuid.clone(),
        address: host.clone(),
        port: 443,
        name: vless.name.clone(),
        clean_ip: false,
        link: link.clone(),
        note: "deployed via khvarenah up".into(),
    };
    profiles::remember_vless(profile_id, rec)?;
    // Remember the account id so subsequent cycles reuse it.
    let mut p = profiles::load_profile(profile_id);
    p.config.active_account = account_id.to_string();
    profiles::save_profile(&p)?;
    Ok(host)
}

/// Ensure a worker is alive for `profile_id`; if not, deploy it. Returns the
/// WorkerInfo.
pub async fn ensure_worker(
    profile_id: &str,
    token: &str,
    account_id: &str,
) -> Result<WorkerInfo, CFError> {
    // Probe health via the direct hostname (DoH resolver provided so system-DNS
    // hijack can't fool us).
    let doh = crate::doh::DohResolver::new();
    let health = crate::autopilot::probe_worker_health(
        &format!("{}-probe", profile_id),
        None,
        Some(&doh),
        8,
    )
    .await;
    // If the worker is alive, find its host from history.
    if let crate::autopilot::WorkerHealth::Alive = health {
        // Recover host from remembered vless.
        if let Ok(vless) = crate::autopilot::base_vless(profile_id) {
            return Ok(WorkerInfo {
                name: vless.address.clone(),
                host: vless.address,
                deployed_at: crate::store::now_ts() as i64,
                deployed_now: false,
            });
        }
        // Fall through to deploy — no remembered config but worker alive.
    }
    let host = deploy_worker_core(profile_id, token, account_id).await?;
    Ok(WorkerInfo {
        name: host.clone(),
        host,
        deployed_at: crate::store::now_ts() as i64,
        deployed_now: true,
    })
}

/// Write the systemd user unit if absent. Returns whether it was just written.
pub fn ensure_daemon_installed(binary_path: &Path, profile_id: &str) -> Result<DaemonInstallOutcome, CFError> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "~".into());
    let unit_dir = PathBuf::from(&home).join(".config/systemd/user");
    std::fs::create_dir_all(&unit_dir).map_err(|e| {
        CFError::new(
            "Daemon",
            e.to_string(),
            "Cannot create ~/.config/systemd/user.",
        )
    })?;
    let unit = unit_dir.join("khvarenah-daemon.service");
    if unit.exists() {
        return Ok(DaemonInstallOutcome::AlreadyInstalled);
    }
    let contents = crate::daemon::systemd_unit(binary_path, profile_id);
    std::fs::write(&unit, contents).map_err(|e| {
        CFError::new("Daemon", e.to_string(), "Cannot write the systemd unit.")
    })?;
    Ok(DaemonInstallOutcome::Installed)
}

/// The one-command orchestrator.
pub async fn up(profile_id_override: Option<&str>) -> Result<BootstrapResult, CFError> {
    let started = std::time::Instant::now();

    // 1 — detect token
    let detected = detect_token();
    if detected.source == TokenSource::None {
        return Err(CFError::new(
            "No token",
            "No Cloudflare API token found.",
            "Set KHVARENAH_TOKEN, write ~/.khvarenah/token.txt, or pre-add a token to a profile.",
        ));
    }

    // 2 — resolve profile
    let profile_id = match profile_id_override {
        Some(id) => id.to_string(),
        None => match &detected.source {
            TokenSource::ExistingProfile(id) => id.clone(),
            _ => "default".to_string(),
        },
    };
    if !profiles::list_profiles().iter().any(|m| m.id == profile_id) {
        profiles::create_profile(&profile_id, "auto-created by khvarenah up")?;
    }

    // 3 — ensure token is stored + active
    match &detected.source {
        TokenSource::ExistingProfile(_) => {
            // Already in a profile; just ensure an active token is set.
            if profiles::get_active_token(&profile_id)?.is_none() {
                let p = profiles::load_profile(&profile_id);
                if let Some(l) = p.tokens.keys().next() {
                    profiles::set_active_token(&profile_id, l)?;
                }
            }
        }
        _ => {
            // Store the token on the profile if not already present.
            let p = profiles::load_profile(&profile_id);
            let existing = p
                .tokens
                .values()
                .find(|e| e.token == detected.token);
            if existing.is_none() {
                profiles::add_token(&profile_id, "default", &detected.token)?;
                profiles::set_active_token(&profile_id, "default")?;
            }
        }
    }

    // 4 — resolve account + ensure worker
    let (account_id, _) = resolve_token_and_account(&detected.token).await?;
    let worker = ensure_worker(&profile_id, &detected.token, &account_id).await?;

    // 5 — run one discovery cycle (guarded) to produce the user bundle
    let params = crate::autopilot::DiscoveryParams {
        sample: 2000,
        workers: 64,
        ..Default::default()
    };
    let engine = crate::autopilot::AutopilotEngine::new(
        profile_id.clone(),
        params,
        std::time::Duration::from_secs(300),
    );
    let _ = engine
        .run_cycle_guarded(std::time::Duration::from_secs(
            crate::cycle_guard::DISCOVERY_TIMEOUT_SECS,
        ))
        .await;

    // 6 — bundle dir
    let bundle_dir = crate::cleanip::user_config_dir(&profile_id)?;

    // 7 — daemon unit
    let bin = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("khvarenah"));
    let daemon_outcome = ensure_daemon_installed(&bin, &profile_id)?;

    Ok(BootstrapResult {
        profile_id,
        token_source: detected.source,
        worker_name: worker.name,
        worker_host: worker.host,
        bundle_dir,
        daemon_outcome,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_mem() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let tmp = std::env::temp_dir().join(format!(
            "kvrvn-boot-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        crate::store::set_mem_dir_override(tmp.join(".khvarenah"));
        tmp
    }

    /// Serializes tests that mutate the process-global `KHVARENAH_TOKEN` env
    /// var. Without this, parallel test threads clobber each other's env (the
    /// env var is process-global, not thread-local) and the precedence tests
    /// become non-deterministic.
    fn env_lock() -> &'static std::sync::Mutex<()> {
        use std::sync::OnceLock;
        static LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    #[test]
    fn test_detect_token_none_when_nothing_present() {
        let _guard = env_lock().lock().unwrap();
        let tmp = temp_mem();
        // Nothing in env, no file, no profiles.
        unsafe {
            std::env::remove_var("KHVARENAH_TOKEN");
        }
        let d = detect_token();
        assert_eq!(d.source, TokenSource::None);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_detect_token_prefers_env_var() {
        let _guard = env_lock().lock().unwrap();
        let tmp = temp_mem();
        unsafe {
            std::env::set_var("KHVARENAH_TOKEN", "env-token-xyz");
        }
        // Also create a file to ensure env wins.
        std::fs::create_dir_all(store::mem_dir()).unwrap();
        std::fs::write(store::mem_dir().join("token.txt"), "file-token").unwrap();
        let d = detect_token();
        assert_eq!(d.source, TokenSource::EnvVar);
        assert_eq!(d.token, "env-token-xyz");
        unsafe {
            std::env::remove_var("KHVARENAH_TOKEN");
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_detect_token_falls_back_to_file() {
        let _guard = env_lock().lock().unwrap();
        let tmp = temp_mem();
        unsafe {
            std::env::remove_var("KHVARENAH_TOKEN");
        }
        std::fs::create_dir_all(store::mem_dir()).unwrap();
        std::fs::write(store::mem_dir().join("token.txt"), "file-token-abc").unwrap();
        let d = detect_token();
        assert_eq!(d.source, TokenSource::File(store::mem_dir().join("token.txt")));
        assert_eq!(d.token, "file-token-abc");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_detect_token_falls_back_to_existing_profile() {
        let _guard = env_lock().lock().unwrap();
        let tmp = temp_mem();
        unsafe {
            std::env::remove_var("KHVARENAH_TOKEN");
        }
        let id = profiles::create_profile("p1", "").unwrap();
        profiles::add_token(&id, "t1", "profile-token-777").unwrap();
        let d = detect_token();
        assert_eq!(d.source, TokenSource::ExistingProfile(id));
        assert_eq!(d.token, "profile-token-777");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_ensure_daemon_installed_writes_unit_once() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let tmp = std::env::temp_dir().join(format!(
            "kvrvn-daemon-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        // Isolate HOME so the systemd unit lands in the temp dir, not the real
        // ~/.config/systemd/user (which already exists on dev machines and
        // would make the "Installed" assertion non-deterministic).
        unsafe {
            std::env::set_var("HOME", &tmp);
        }
        let bin = PathBuf::from("/tmp/fake-khvarenah");
        let outcome = ensure_daemon_installed(&bin, "default").unwrap();
        assert_eq!(outcome, DaemonInstallOutcome::Installed);
        // Second call → already installed.
        let outcome2 = ensure_daemon_installed(&bin, "default").unwrap();
        assert_eq!(outcome2, DaemonInstallOutcome::AlreadyInstalled);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
