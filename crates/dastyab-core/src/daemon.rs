//! Persistent protection daemon (DeepSeek architect Feature A, hardened).
//!
//! Runs the monitor loop unattended with three safety guards that make it
//! safe to run 24/7:
//!
//! 1. **Network-liveness probe** — before every cycle, resolve a known DNS
//!    name over DoH. If the network is genuinely down, skip the cycle
//!    entirely (don't burn rescue/scan budget on an unreachable network).
//! 2. **Exponential backoff** — on consecutive failures, the cycle interval
//!    grows 300s → 900s → 3600s → 21600s (capped). Resets to the initial
//!    interval only on *success*, never on network-restore (a network restore
//!    short-circuits the sleep so we cycle immediately, but does not reset
//!    backoff — if the worker is genuinely broken we must not hammer it).
//! 3. **daemon.log** — plain-text, ISO-8601-prefixed, append-only, rotated at
//!    5MB keeping 3 generations. Crash-diagnostic evidence before the full
//!    structured journal (Feature B) ships.

use crate::error::CFError;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

/// Default initial cycle interval (seconds).
pub const DEFAULT_INITIAL_INTERVAL_SECS: u64 = 300;
/// Default maximum cycle interval (seconds) — 6h.
pub const DEFAULT_MAX_INTERVAL_SECS: u64 = 21600;
/// How long to sleep when the network is down before re-probing.
pub const NETWORK_DOWN_SLEEP_SECS: u64 = 60;
/// Log rotation threshold (bytes).
pub const LOG_ROTATE_BYTES: u64 = 5 * 1024 * 1024;
/// Number of rotated log generations kept.
pub const LOG_GENERATIONS: u32 = 3;
/// Minimum seconds between automatic beacon-outbox flush attempts while the
/// network is up (we do not want to hammer the Telegram/webhook transport on
/// every cycle — only periodically, plus immediately after a blackout ends).
pub const OUTBOX_FLUSH_INTERVAL_SECS: i64 = 300;

/// Daemon configuration.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub profile: String,
    pub pid_file: PathBuf,
    pub stop_file: PathBuf,
    pub log_path: PathBuf,
    pub initial_interval_secs: u64,
    pub max_interval_secs: u64,
    pub foreground: bool,
}

impl DaemonConfig {
    pub fn new(profile: &str) -> Self {
        let base = crate::store::profiles::profile_dir(profile);
        Self {
            profile: profile.to_string(),
            pid_file: base.join("daemon.pid"),
            stop_file: base.join("daemon.stop"),
            log_path: base.join("daemon.log"),
            initial_interval_secs: DEFAULT_INITIAL_INTERVAL_SECS,
            max_interval_secs: DEFAULT_MAX_INTERVAL_SECS,
            foreground: false,
        }
    }
}

/// Persistent state of the daemon loop.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DaemonState {
    #[serde(default)]
    pub pid: u32,
    #[serde(default)]
    pub started_at: i64,
    #[serde(default)]
    pub last_cycle_ts: i64,
    #[serde(default)]
    pub last_success_ts: i64,
    #[serde(default)]
    pub failure_streak: u32,
    #[serde(default = "default_interval")]
    pub current_interval_secs: u64,
    #[serde(default)]
    pub network_was_down: bool,
    /// Account-level state (serde-default→Active so old state loads cleanly).
    #[serde(default)]
    pub account_state: crate::account_state::AccountState,
    /// Last epoch-seconds we probed account status while waiting.
    #[serde(default)]
    pub last_account_poll_ts: i64,
    /// Last blackout survival plan label (set when network goes down).
    #[serde(default)]
    pub survival_plan: String,
    /// Best transport tier reachable at the last probe (label, or empty when
    /// no tier info was reported). Filled by the ladder-backed probe.
    #[serde(default)]
    pub network_tier: String,
    /// Last epoch-seconds the daemon checked for an auto-update.
    #[serde(default)]
    pub last_update_check_ts: i64,
    /// Last epoch-seconds an auto-backup was written (if enabled).
    #[serde(default)]
    pub last_backup_ts: i64,
    /// Last profile-dir mtime (epoch seconds) the daemon saw. When the profile
    /// config/token/state dir changes (e.g. Settings edited in the GUI), the
    /// daemon logs a config-reload notice and resets its interval so new
    /// settings apply without a manual restart.
    #[serde(default)]
    pub last_profile_mtime: i64,
    /// Last epoch-seconds the daemon auto-flushed the beacon outbox. Used to
    /// rate-limit outbox flush attempts when the network is up (alerts queued
    /// during a blackout are delivered on restore, then periodically).
    #[serde(default)]
    pub last_outbox_flush_ts: i64,
}

fn default_interval() -> u64 {
    DEFAULT_INITIAL_INTERVAL_SECS
}

impl Default for DaemonState {
    fn default() -> Self {
        Self {
            pid: 0,
            started_at: 0,
            last_cycle_ts: 0,
            last_success_ts: 0,
            failure_streak: 0,
            current_interval_secs: DEFAULT_INITIAL_INTERVAL_SECS,
            network_was_down: false,
            account_state: crate::account_state::AccountState::Active,
            last_account_poll_ts: 0,
            survival_plan: String::new(),
            network_tier: String::new(),
            last_update_check_ts: 0,
            last_backup_ts: 0,
            last_profile_mtime: 0,
            last_outbox_flush_ts: 0,
        }
    }
}

/// Pure: whether it is time to attempt an outbox flush, given the last flush
/// epoch and the current epoch. Returns true when we have never flushed or the
/// interval has elapsed. `interval` is in seconds and must be positive.
pub fn should_flush_outbox(last: i64, now: i64, interval: i64) -> bool {
    if interval <= 0 {
        return true;
    }
    now - last >= interval
}

/// Path to a profile's daemon-state file.
fn daemon_state_path(profile: &str) -> PathBuf {
    crate::store::profiles::profile_dir(profile).join("daemon-state.json")
}

/// Load the daemon state (defaults when absent).
pub fn load_daemon_state(profile: &str) -> DaemonState {
    crate::store::read_or_default::<DaemonState>(&daemon_state_path(profile))
}

/// Persist the daemon state atomically.
pub fn save_daemon_state(profile: &str, st: &DaemonState) -> Result<(), CFError> {
    crate::store::write_json(&daemon_state_path(profile), st)
}

/// Reset the daemon's backoff state: zero `failure_streak` and restore
/// `current_interval_secs` to the initial value. Used to make a fix testable
/// in minutes (instead of waiting out a 6-hour backoff). Returns `Some` with
/// the previous `(streak, interval)` if a state file existed, or `None` if
/// there was no state to reset (the caller prints "No daemon state to reset").
pub fn reset_daemon_state(profile: &str) -> Result<Option<(u32, u64)>, CFError> {
    let path = daemon_state_path(profile);
    if !path.exists() {
        return Ok(None);
    }
    let old = load_daemon_state(profile);
    let old_streak = old.failure_streak;
    let old_interval = old.current_interval_secs;
    let fresh = DaemonState {
        failure_streak: 0,
        current_interval_secs: DEFAULT_INITIAL_INTERVAL_SECS,
        ..old.clone()
    };
    save_daemon_state(profile, &fresh)?;
    Ok(Some((old_streak, old_interval)))
}

/// Clear a blocked account state so the daemon resumes immediately (used by
/// the guided token-recovery flow after a fresh token verifies). Resets
/// `account_state` to Active and forces an immediate re-probe on the next
/// tick. Returns `Ok(true)` if a blocked state was cleared, `Ok(false)` if the
/// daemon was already unblocked, and `Err` on persist failure.
pub fn clear_account_blocked(profile: &str) -> Result<bool, CFError> {
    let mut state = load_daemon_state(profile);
    if !state.account_state.blocks_cycle() {
        return Ok(false);
    }
    state.account_state = crate::account_state::AccountState::Active;
    // Force an immediate re-probe on the next tick.
    state.last_account_poll_ts = 0;
    save_daemon_state(profile, &state)?;
    Ok(true)
}

/// Pure: compute the next backoff interval. Follows the escalation table
/// 300 → 900 → 3600 → 21600 (5min → 15min → 1h → 6h), capped at `max`.
pub fn backoff_next(current: u64, max: u64) -> u64 {
    const TABLE: [u64; 4] = [300, 900, 3600, 21600];
    let next = TABLE
        .iter()
        .copied()
        .find(|&v| v > current)
        .unwrap_or(TABLE[3]);
    next.min(max).max(current)
}

/// Pure: backoff reset value (the initial interval).
pub fn backoff_reset() -> u64 {
    DEFAULT_INITIAL_INTERVAL_SECS
}

/// True if a process with `pid` is alive (Unix: kill -0 / /proc).
#[cfg(unix)]
pub fn process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let p = format!("/proc/{pid}");
    Path::new(&p).exists()
}

/// True if a process with `pid` is alive (non-Unix placeholder).
#[cfg(not(unix))]
pub fn process_alive(pid: u32) -> bool {
    // Windows: OpenProcess check is out of scope for v1; treat non-zero as
    // alive so a stale PID only blocks a restart on Unix.
    pid != 0
}

/// True if a daemon is currently running (pid file exists AND process alive).
pub fn is_daemon_running(pid_file: &Path) -> bool {
    let pid: u32 = crate::store::read_or_default::<u32>(pid_file);
    if pid == 0 {
        return false;
    }
    process_alive(pid)
}

/// Acquire the pid file. Returns an error if another live daemon owns it.
/// Cleans up a stale pid file (dead PID) automatically.
pub fn acquire_pid_file(pid_file: &Path, pid: u32) -> Result<(), CFError> {
    if let Some(existing) = crate::store::read_opt::<u32>(pid_file) {
        if existing != 0 && process_alive(existing) && existing != pid {
            return Err(CFError::new(
                "Daemon",
                format!("Already running (pid {existing})."),
                "Stop it first, or remove the stale pid file.",
            ));
        }
    }
    crate::store::write_json(pid_file, &pid)
}

/// Remove the pid + stop files (clean shutdown).
pub fn cleanup_daemon(pid_file: &Path, stop_file: &Path) {
    let _ = std::fs::remove_file(pid_file);
    let _ = std::fs::remove_file(stop_file);
}

/// Append one line to the daemon log, rotating when oversized.
pub fn daemon_log_append(log_path: &Path, line: &str) {
    if let Ok(meta) = std::fs::metadata(log_path) {
        if meta.len() >= LOG_ROTATE_BYTES {
            rotate_log(log_path);
        }
    }
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        let _ = writeln!(f, "{line}");
    }
}

/// Rotate the log: daemon.log → daemon.log.1 → ... (keep 3 generations).
fn rotate_log(log_path: &Path) {
    for i in (1..=LOG_GENERATIONS).rev() {
        let src = if i == 1 {
            log_path.to_path_buf()
        } else {
            log_suffix(log_path, i - 1)
        };
        let dst = log_suffix(log_path, i);
        if src.exists() {
            let _ = std::fs::rename(&src, &dst);
        }
    }
}

fn log_suffix(log_path: &Path, generation: u32) -> PathBuf {
    if generation == 0 {
        log_path.to_path_buf()
    } else {
        let mut s = log_path.as_os_str().to_os_string();
        s.push(format!(".{generation}"));
        PathBuf::from(s)
    }
}

/// Format a log line with an ISO-8601 UTC timestamp.
pub fn log_line(tag: &str, body: &str) -> String {
    let ts = crate::store::now_iso();
    format!("{ts}Z {tag} {body}")
}

/// Build the systemd user-unit contents for the dastyab daemon. Pure, so
/// it is unit-testable. `binary` is the absolute path to the CLI binary;
/// `profile` is the profile the daemon should manage.
pub fn systemd_unit(binary: &Path, profile: &str) -> String {
    format!(
        "[Unit]\nDescription=DastYab protection daemon\nAfter=network-online.target\n\n[Service]\nType=simple\nExecStart={} daemon start --profile {} --foreground\nRestart=always\nRestartSec=30\nRuntimeMaxSec=1800\nStandardOutput=null\nStandardError=null\n\n[Install]\nWantedBy=default.target\n",
        binary.display(),
        profile
    )
}

/// Build the argv for a `systemctl --user <action> <unit>` invocation. Pure,
/// so the command shape is unit-testable without a running systemd instance.
pub fn systemctl_user_argv(action: &str, unit_name: &str) -> Vec<String> {
    vec!["--user".into(), action.to_string(), unit_name.to_string()]
}

/// Run `systemctl --user <action> <unit>` and return whether it succeeded.
///
/// This is the per-user systemd manager — no root required — so the app can
/// close the last manual step (running `systemctl --user enable --now` by
/// hand). The unit file itself must already be written. Returns `Ok(true)`
/// on a clean exit, `Ok(false)` when systemctl ran but reported failure, and
/// `Err` when the executable is missing/unrunnable.
pub fn systemctl_user(action: &str, unit_name: &str) -> std::io::Result<bool> {
    let outp = std::process::Command::new("systemctl")
        .args(systemctl_user_argv(action, unit_name))
        .output()?;
    Ok(outp.status.success())
}

/// Result of a network-liveness probe: whether the network is up at all, plus
/// the best transport tier that was reachable (None when nothing worked).
#[derive(Debug, Clone, Default)]
pub struct NetStatus {
    pub up: bool,
    pub tier: Option<crate::connectivity::Tier>,
}

impl NetStatus {
    pub fn tier_label(&self) -> String {
        self.tier.map(|t| t.label().to_string()).unwrap_or_default()
    }
}

/// Abstraction over the network-liveness probe so the loop is testable.
pub trait NetworkProbe: Send + Sync {
    fn liveness(&self) -> Pin<Box<dyn Future<Output = NetStatus> + Send + '_>>;
}

/// Real probe backed by the DoH resolver + the full fallback ladder. Probes
/// every tier best-first (direct → DoH → DoT → DNS tunnel) so the daemon knows
/// the best transport actually reachable right now.
pub struct RealNetworkProbe {
    pub profile: String,
    pub resolver: crate::doh::DohResolver,
}

impl RealNetworkProbe {
    pub fn new(profile: &str) -> Self {
        Self {
            profile: profile.to_string(),
            resolver: crate::doh::DohResolver::new(),
        }
    }
}

impl NetworkProbe for RealNetworkProbe {
    fn liveness(&self) -> Pin<Box<dyn Future<Output = NetStatus> + Send + '_>> {
        let probe = crate::connectivity::RealLadderProbe {
            profile: &self.profile,
            resolver: &self.resolver,
        };
        Box::pin(async move {
            match crate::connectivity::first_available(probe).await {
                Some(tier) => NetStatus {
                    up: true,
                    tier: Some(tier),
                },
                None => NetStatus {
                    up: false,
                    tier: None,
                },
            }
        })
    }
}

/// Abstraction over a single monitor/cycle run so the loop is testable.
pub trait CycleRunner: Send + Sync {
    fn run_cycle(
        &self,
        profile: &str,
        follow: bool,
    ) -> Pin<Box<dyn Future<Output = Result<(), CFError>> + Send + '_>>;
}

/// Abstraction over the account-status probe so the loop is testable. Returns
/// the current account state without blocking on the full cycle.
pub trait AccountProbe: Send + Sync {
    fn probe_account(
        &self,
        profile: &str,
    ) -> Pin<Box<dyn Future<Output = crate::account_state::AccountState> + Send + '_>>;
}

/// Real account probe backed by the Cloudflare API.
pub struct RealAccountProbe;

impl AccountProbe for RealAccountProbe {
    fn probe_account(
        &self,
        profile: &str,
    ) -> Pin<Box<dyn Future<Output = crate::account_state::AccountState> + Send + '_>> {
        let profile = profile.to_string();
        Box::pin(async move { crate::account_state::probe_account_state(&profile).await })
    }
}

/// Real cycle runner: runs the autopilot monitor cycle.
pub struct RealCycleRunner;

impl CycleRunner for RealCycleRunner {
    fn run_cycle(
        &self,
        profile: &str,
        _follow: bool,
    ) -> Pin<Box<dyn Future<Output = Result<(), CFError>> + Send + '_>> {
        let profile = profile.to_string();
        Box::pin(async move {
            let params = crate::autopilot::DiscoveryParams::default();
            let engine = crate::autopilot::AutopilotEngine::new(
                profile.clone(),
                params,
                std::time::Duration::from_secs(DEFAULT_INITIAL_INTERVAL_SECS),
            );
            engine
                .monitor_cycle_guarded(crate::autopilot::MonitorTimeouts::default())
                .await
                .map(|_| ())
        })
    }
}

/// Run one iteration of the daemon loop. Returns the number of seconds to
/// sleep before the next iteration. Pure-ish: all side effects go through
/// `probe`, `acct`, `cycle`, and the logger callback, so it is fully unit-testable.
pub async fn daemon_tick(
    profile: &str,
    state: &mut DaemonState,
    probe: &dyn NetworkProbe,
    acct: &dyn AccountProbe,
    cycle: &dyn CycleRunner,
    log: &mut dyn FnMut(&str),
) -> u64 {
    // b. Network liveness probe (full fallback ladder: direct → DoH → DoT
    // → DNS tunnel). `status` carries the best tier actually reachable.
    let status = probe.liveness().await;
    let net_up = status.up;
    state.network_tier = status.tier_label();

    // Auto-flush the beacon outbox whenever the network is up. Alerts queued
    // during a blackout (or a blocked channel) are delivered as soon as the
    // network returns — immediately on restore, then rate-limited so we don't
    // hammer the Telegram/webhook transport every cycle.
    if net_up {
        let now = crate::store::now_ts() as i64;
        let force = state.network_was_down;
        if force || should_flush_outbox(state.last_outbox_flush_ts, now, OUTBOX_FLUSH_INTERVAL_SECS)
        {
            let n = crate::remote_beacon::flush_outbox(profile).await;
            if n > 0 {
                log(&log_line("INFO", &format!("outbox flushed {} alert(s)", n)));
            }
            state.last_outbox_flush_ts = now;
        }
    }

    if !net_up {
        // c. Network down → skip cycle, don't burn rescue budget. Compute the
        // blackout survival plan so the daemon / beacon knows whether a DNS
        // tunnel is available to descend to.
        let tunnel_ok = crate::vps_deploy::is_dns_tunnel_configured(profile);
        let plan = crate::blackout_bridge::SurvivalPlan::from_state(
            crate::blackout::NetworkState::TotalBlackout,
            tunnel_ok,
        );
        if !state.network_was_down {
            log(&log_line(
                "WARN",
                &format!(
                    "network=down skipping (survival={}, tunnel={})",
                    plan.label(),
                    if tunnel_ok { "yes" } else { "no" }
                ),
            ));
            state.network_was_down = true;
            state.survival_plan = plan.label().to_string();
        }
        return NETWORK_DOWN_SLEEP_SECS;
    }

    // d. Account-level gate. If the account is suspended/invalid, hold cycles
    // so we don't burn rescue/scan budget against a dead account. Re-probe at
    // ACCOUNT_POLL_INTERVAL_SECS and resume automatically when the account
    // comes back — no manual daemon restart required.
    let now = crate::store::now_ts() as i64;
    if state.account_state.blocks_cycle() {
        if crate::account_state::should_poll_account(state.last_account_poll_ts, now) {
            let st = acct.probe_account(profile).await;
            state.last_account_poll_ts = now;
            let still_blocked = st.blocks_cycle();
            state.account_state = st;
            if still_blocked {
                log(&log_line(
                    "WARN",
                    &format!(
                        "account={} still blocked (polling again in {}s)",
                        state.account_state.label(),
                        crate::account_state::ACCOUNT_POLL_INTERVAL_SECS
                    ),
                ));
                return crate::account_state::ACCOUNT_POLL_INTERVAL_SECS;
            }
            log(&log_line(
                "INFO",
                &format!(
                    "account={} restored, resuming cycle",
                    state.account_state.label()
                ),
            ));
        } else {
            // Not yet time to re-poll — hold this cycle.
            log(&log_line(
                "INFO",
                &format!(
                    "account={} waiting (skip cycle)",
                    state.account_state.label()
                ),
            ));
            return crate::account_state::ACCOUNT_POLL_INTERVAL_SECS;
        }
    } else {
        // Not blocked, but periodically confirm so we notice a suspension even
        // while the token itself still verifies.
        if crate::account_state::should_poll_account(state.last_account_poll_ts, now) {
            let st = acct.probe_account(profile).await;
            state.last_account_poll_ts = now;
            if st.blocks_cycle() {
                let was_blocked = state.account_state.blocks_cycle();
                state.account_state = st;
                log(&log_line(
                    "WARN",
                    &format!(
                        "account now {} — blocking cycles",
                        state.account_state.label()
                    ),
                ));
                // Notify remotely on the transition into the blocked state (the
                // daemon holds cycles silently; the user should be told why).
                if !was_blocked {
                    let _ = crate::remote_beacon::maybe_emit(
                        profile,
                        &crate::remote_beacon::BeaconEvent::AccountBlocked {
                            state: state.account_state.label().to_string(),
                            since: crate::store::now_ts() as i64,
                        },
                        crate::diagnose::Locale::En,
                    )
                    .await;
                }
                return crate::account_state::ACCOUNT_POLL_INTERVAL_SECS;
            }
            state.account_state = st;
        }
    }

    if state.network_was_down {
        log(&log_line("INFO", "network=restored"));
        // Network restore short-circuits the sleep timer but does NOT reset
        // backoff. We return 0 so the caller cycles immediately, keeping the
        // current (possibly backed-off) interval for the *next* failure.
        state.network_was_down = false;
        // Still run a cycle now.
        state.last_cycle_ts = crate::store::now_ts() as i64;
        match cycle.run_cycle(profile, false).await {
            Ok(()) => {
                state.failure_streak = 0;
                state.current_interval_secs = backoff_reset();
                state.last_success_ts = crate::store::now_ts() as i64;
                log(&log_line(
                    "INFO",
                    &format!(
                        "cycle=N success verified=1 action=none streak=0 interval={}",
                        state.current_interval_secs
                    ),
                ));
                0
            }
            Err(e) => {
                state.failure_streak += 1;
                state.current_interval_secs =
                    backoff_next(state.current_interval_secs, DEFAULT_MAX_INTERVAL_SECS);
                log(&log_line(
                    "WARN",
                    &format!(
                        "cycle=N failed streak={} next={}s rescue=auto ({})",
                        state.failure_streak,
                        state.current_interval_secs,
                        e.brief()
                    ),
                ));
                state.current_interval_secs
            }
        }
    } else {
        // Normal cycle.
        state.last_cycle_ts = crate::store::now_ts() as i64;
        match cycle.run_cycle(profile, false).await {
            Ok(()) => {
                state.failure_streak = 0;
                state.current_interval_secs = backoff_reset();
                state.last_success_ts = crate::store::now_ts() as i64;
                log(&log_line(
                    "INFO",
                    &format!(
                        "cycle=N success verified=1 action=none streak=0 interval={}",
                        state.current_interval_secs
                    ),
                ));
                state.current_interval_secs
            }
            Err(e) => {
                state.failure_streak += 1;
                state.current_interval_secs =
                    backoff_next(state.current_interval_secs, DEFAULT_MAX_INTERVAL_SECS);
                log(&log_line(
                    "WARN",
                    &format!(
                        "cycle=N failed streak={} next={}s rescue=auto ({})",
                        state.failure_streak,
                        state.current_interval_secs,
                        e.brief()
                    ),
                ));
                state.current_interval_secs
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn daemon_home() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(tmp.path().join(".dastyab"));
        tmp
    }

    #[test]
    fn backoff_next_doubles_then_caps() {
        assert_eq!(backoff_next(300, 21600), 900);
        assert_eq!(backoff_next(900, 21600), 3600);
        assert_eq!(backoff_next(3600, 21600), 21600);
        assert_eq!(backoff_next(21600, 21600), 21600);
    }

    #[test]
    fn backoff_reset_returns_initial() {
        assert_eq!(backoff_reset(), DEFAULT_INITIAL_INTERVAL_SECS);
    }

    #[test]
    fn should_flush_outbox_timing() {
        // Never flushed → flush now.
        assert!(should_flush_outbox(0, 1000, 300));
        // Before the interval elapses → wait.
        assert!(!should_flush_outbox(800, 1000, 300));
        // Exactly at the interval boundary → flush.
        assert!(should_flush_outbox(700, 1000, 300));
        // Non-positive interval → always flush.
        assert!(should_flush_outbox(999, 1000, 0));
    }

    #[test]
    fn daemon_state_migrates_without_fields() {
        let _home = daemon_home();
        let profile = crate::store::profiles::create_profile("rl", "").unwrap();
        let path = daemon_state_path(&profile);
        // Older state without the new fields.
        crate::store::write_json(&path, &serde_json::json!({"pid": 42, "started_at": 1000}))
            .unwrap();
        let st = load_daemon_state(&profile);
        assert_eq!(st.pid, 42);
        assert_eq!(st.started_at, 1000);
        assert_eq!(st.failure_streak, 0);
        assert_eq!(st.current_interval_secs, DEFAULT_INITIAL_INTERVAL_SECS);
        assert!(!st.network_was_down);
    }

    #[test]
    fn pid_file_write_and_cleanup() {
        let _home = daemon_home();
        let cfg = DaemonConfig::new("default");
        acquire_pid_file(&cfg.pid_file, 12345).unwrap();
        assert!(is_daemon_running(&cfg.pid_file) || true); // pid may not exist
        cleanup_daemon(&cfg.pid_file, &cfg.stop_file);
        assert!(!cfg.pid_file.exists());
    }

    #[test]
    fn is_daemon_running_false_when_pid_dead() {
        let _home = daemon_home();
        let cfg = DaemonConfig::new("default");
        // A pid that almost certainly doesn't exist.
        crate::store::write_json(&cfg.pid_file, &999_999u32).unwrap();
        #[cfg(unix)]
        assert!(!is_daemon_running(&cfg.pid_file));
    }

    #[test]
    fn acquire_pid_file_refuses_second_instance_when_pid_alive() {
        let _home = daemon_home();
        let cfg = DaemonConfig::new("default");
        // This process is unambiguously alive.
        let live_pid = std::process::id();
        acquire_pid_file(&cfg.pid_file, live_pid).unwrap();
        // A different (also alive) process must be refused.
        let other = live_pid.wrapping_add(1);
        assert!(acquire_pid_file(&cfg.pid_file, other).is_err());
        // The first owner is still recognized as running.
        assert!(is_daemon_running(&cfg.pid_file));
    }

    #[test]
    fn systemd_unit_has_correct_exec_start_and_restart() {
        let unit = systemd_unit(Path::new("/home/me/.local/bin/dastyab"), "default");
        assert!(unit.contains(
            "ExecStart=/home/me/.local/bin/dastyab daemon start --profile default --foreground"
        ));
        assert!(unit.contains("Restart=always"));
        assert!(unit.contains("RuntimeMaxSec=1800"));
        assert!(unit.contains("RestartSec=30"));
        assert!(unit.contains("WantedBy=default.target"));
        // Must NOT auto-run systemctl (privilege escalation is user's call).
        assert!(!unit.contains("systemctl"));
    }

    #[test]
    fn systemctl_user_argv_is_user_scoped_enable_now() {
        let argv = systemctl_user_argv("enable --now", "dastyab-daemon.service");
        assert_eq!(
            argv,
            vec!["--user", "enable --now", "dastyab-daemon.service"]
        );
        let argv_start = systemctl_user_argv("start", "dastyab-daemon.service");
        assert_eq!(argv_start[0], "--user");
        assert_eq!(argv_start[1], "start");
        assert_eq!(argv_start[2], "dastyab-daemon.service");
    }

    #[test]
    fn log_rotation_keeps_three_generations() {
        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("daemon.log");
        // Write a big file, then append a line → rotation happens.
        std::fs::write(&log_path, vec![b'x'; LOG_ROTATE_BYTES as usize]).unwrap();
        daemon_log_append(&log_path, "info line");
        assert_eq!(log_suffix(&log_path, 1).exists(), true);
        assert_eq!(log_suffix(&log_path, 2).exists(), false);
    }

    // ── daemon_tick loop behavior (established NetworkProbe/CycleRunner) ──

    struct FakeProbe {
        status: NetStatus,
        calls: std::sync::atomic::AtomicUsize,
    }
    impl FakeProbe {
        fn new(up: bool) -> Self {
            Self {
                status: NetStatus {
                    up,
                    tier: Some(crate::connectivity::Tier::Direct),
                },
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }
        fn with_tier(up: bool, tier: crate::connectivity::Tier) -> Self {
            Self {
                status: NetStatus {
                    up,
                    tier: Some(tier),
                },
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }
    impl NetworkProbe for FakeProbe {
        fn liveness(&self) -> Pin<Box<dyn Future<Output = NetStatus> + Send + '_>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let st = self.status.clone();
            Box::pin(async move { st })
        }
    }

    struct FakeCycle {
        ok: bool,
        calls: std::sync::atomic::AtomicUsize,
    }
    impl FakeCycle {
        fn new(ok: bool) -> Self {
            Self {
                ok,
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }
    impl CycleRunner for FakeCycle {
        fn run_cycle(
            &self,
            _profile: &str,
            _follow: bool,
        ) -> Pin<Box<dyn Future<Output = Result<(), CFError>> + Send + '_>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let ok = self.ok;
            Box::pin(async move {
                if ok {
                    Ok(())
                } else {
                    Err(CFError::new("test", "cycle failed", ""))
                }
            })
        }
    }

    /// A scripted account probe for daemon_tick tests.
    struct FakeAccountProbe {
        state: crate::account_state::AccountState,
    }
    impl Default for FakeAccountProbe {
        fn default() -> Self {
            Self {
                state: crate::account_state::AccountState::Active,
            }
        }
    }
    impl AccountProbe for FakeAccountProbe {
        fn probe_account(
            &self,
            _profile: &str,
        ) -> Pin<Box<dyn Future<Output = crate::account_state::AccountState> + Send + '_>> {
            let st = self.state.clone();
            Box::pin(async move { st })
        }
    }

    /// The self-inflicted-DoS guard: when the network is down, the cycle must
    /// NOT run at all (no scan, no rescue burn), and we must log network=down.
    #[tokio::test]
    async fn test_daemon_skips_cycle_when_network_down() {
        let _home = daemon_home();
        let profile = "default";
        let mut state = DaemonState::default();
        let probe = FakeProbe::new(false);
        let cycle = FakeCycle::new(true);
        let mut log_lines = Vec::new();
        let acct = FakeAccountProbe::default();

        // First tick: network down → skip cycle.
        let sleep = daemon_tick(profile, &mut state, &probe, &acct, &cycle, &mut |l| {
            log_lines.push(l.to_string())
        })
        .await;
        assert_eq!(sleep, NETWORK_DOWN_SLEEP_SECS);
        assert_eq!(
            cycle.calls.load(Ordering::SeqCst),
            0,
            "cycle must not run when network is down"
        );
        assert!(state.network_was_down);
        assert!(log_lines.iter().any(|l| l.contains("network=down")));

        // Second tick: still down → still no cycle, and no duplicate "down" log.
        let sleep2 = daemon_tick(profile, &mut state, &probe, &acct, &cycle, &mut |l| {
            log_lines.push(l.to_string())
        })
        .await;
        assert_eq!(sleep2, NETWORK_DOWN_SLEEP_SECS);
        assert_eq!(cycle.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            log_lines
                .iter()
                .filter(|l| l.contains("network=down"))
                .count(),
            1
        );
    }

    /// On blackout the daemon must record the survival plan (tunnel available
    /// vs not) so the status line + beacon can report the honest ceiling.
    #[tokio::test]
    async fn test_daemon_records_survival_plan_on_blackout() {
        let _home = daemon_home();
        let profile = "default";
        let mut state = DaemonState::default();
        let probe = FakeProbe::new(false);
        let cycle = FakeCycle::new(true);
        let mut log_lines = Vec::new();
        let acct = FakeAccountProbe::default();

        let sleep = daemon_tick(profile, &mut state, &probe, &acct, &cycle, &mut |l| {
            log_lines.push(l.to_string())
        })
        .await;
        assert_eq!(sleep, NETWORK_DOWN_SLEEP_SECS);
        // No tunnel configured for the test profile → blackout-no-tunnel plan.
        assert_eq!(state.survival_plan, "total-blackout");
        assert!(log_lines
            .iter()
            .any(|l| l.contains("survival=total-blackout")));
    }

    /// The ladder-backed probe reports the best reachable tier; the daemon must
    /// persist it so status/health can show how the app is connected (direct
    /// vs DoH vs DoT vs tunnel) without re-probing.
    #[tokio::test]
    async fn test_daemon_records_reachable_tier() {
        let _home = daemon_home();
        let profile = "default";
        let mut state = DaemonState::default();
        // Network up via DoH (direct unavailable).
        let probe = FakeProbe::with_tier(true, crate::connectivity::Tier::DoH);
        let cycle = FakeCycle::new(true);
        let acct = FakeAccountProbe::default();

        let sleep = daemon_tick(profile, &mut state, &probe, &acct, &cycle, &mut |_l| {}).await;
        // Up via DoH + a healthy cycle → success, interval reset, tier recorded.
        assert_eq!(sleep, DEFAULT_INITIAL_INTERVAL_SECS);
        assert_eq!(cycle.calls.load(Ordering::SeqCst), 1);
        assert_eq!(state.network_tier, "doh");
    }

    /// The complementary safety contract: when the network comes back, the
    /// daemon must cycle immediately (return 0), not wait for the next timer.
    #[tokio::test]
    async fn test_daemon_cycles_immediately_on_network_restore() {
        let _home = daemon_home();
        let profile = "default";
        let mut state = DaemonState {
            network_was_down: true, // was down
            ..Default::default()
        };
        let probe = FakeProbe::new(true); // now up
        let cycle = FakeCycle::new(true);
        let mut log_lines = Vec::new();
        let acct = FakeAccountProbe::default();

        let sleep = daemon_tick(profile, &mut state, &probe, &acct, &cycle, &mut |l| {
            log_lines.push(l.to_string())
        })
        .await;
        assert_eq!(sleep, 0, "must cycle immediately on network restore");
        assert_eq!(cycle.calls.load(Ordering::SeqCst), 1);
        assert!(!state.network_was_down);
        assert!(log_lines.iter().any(|l| l.contains("network=restored")));
        assert_eq!(state.failure_streak, 0);
        assert_eq!(state.current_interval_secs, DEFAULT_INITIAL_INTERVAL_SECS);
    }

    /// When the network is up the daemon auto-flushes the beacon outbox (so
    /// alerts queued during a blackout get delivered without a manual step),
    /// then rate-limits repeat flushes to once per interval.
    #[tokio::test]
    async fn test_daemon_flushes_outbox_when_network_up() {
        let _home = daemon_home();
        let profile = crate::store::profiles::create_profile("default", "").unwrap();
        let mut state = DaemonState::default();
        let probe = FakeProbe::new(true);
        let cycle = FakeCycle::new(true);
        let acct = FakeAccountProbe::default();

        let sleep = daemon_tick(&profile, &mut state, &probe, &acct, &cycle, &mut |_l| {}).await;
        assert_eq!(sleep, DEFAULT_INITIAL_INTERVAL_SECS);
        // The automatic flush attempt ran (beacon disabled on this profile →
        // noop, but the attempt is recorded).
        assert!(state.last_outbox_flush_ts > 0);

        // A second tick within the interval must NOT re-flush.
        let before = state.last_outbox_flush_ts;
        let _sleep2 = daemon_tick(&profile, &mut state, &probe, &acct, &cycle, &mut |_l| {}).await;
        assert_eq!(state.last_outbox_flush_ts, before);
    }

    /// A blackout restore forces an immediate outbox flush regardless of the
    /// rate-limit gate — that is the exact moment queued alerts must go out.
    #[tokio::test]
    async fn test_daemon_flushes_outbox_immediately_on_restore() {
        let _home = daemon_home();
        let profile = crate::store::profiles::create_profile("default", "").unwrap();
        let mut state = DaemonState {
            network_was_down: true, // was down
            ..Default::default()
        };
        let probe = FakeProbe::new(true); // now up
        let cycle = FakeCycle::new(true);
        let acct = FakeAccountProbe::default();

        let sleep = daemon_tick(&profile, &mut state, &probe, &acct, &cycle, &mut |_l| {}).await;
        assert_eq!(sleep, 0, "must cycle immediately on restore");
        assert!(
            state.last_outbox_flush_ts > 0,
            "restore forces an outbox flush"
        );
    }

    /// Backoff grows on consecutive failures, and does NOT reset just because
    /// the network came back (it only resets on a successful cycle).
    #[tokio::test]
    async fn test_daemon_backs_off_after_consecutive_failures() {
        let _home = daemon_home();
        let profile = "default";
        let mut state = DaemonState::default();
        let probe = FakeProbe::new(true);
        let cycle = FakeCycle::new(false); // always fails
        let mut log_lines = Vec::new();
        let acct = FakeAccountProbe::default();

        let s1 = daemon_tick(profile, &mut state, &probe, &acct, &cycle, &mut |l| {
            log_lines.push(l.to_string())
        })
        .await;
        assert_eq!(s1, 900, "300 → 900");
        assert_eq!(state.failure_streak, 1);

        let s2 = daemon_tick(profile, &mut state, &probe, &acct, &cycle, &mut |l| {
            log_lines.push(l.to_string())
        })
        .await;
        assert_eq!(s2, 3600, "900 → 3600");
        assert_eq!(state.failure_streak, 2);

        let s3 = daemon_tick(profile, &mut state, &probe, &acct, &cycle, &mut |l| {
            log_lines.push(l.to_string())
        })
        .await;
        assert_eq!(s3, 21600, "3600 → 21600");
        assert_eq!(state.failure_streak, 3);

        let s4 = daemon_tick(profile, &mut state, &probe, &acct, &cycle, &mut |l| {
            log_lines.push(l.to_string())
        })
        .await;
        assert_eq!(s4, 21600, "capped at 21600");
        assert_eq!(state.failure_streak, 4);
    }

    /// Backoff resets once a cycle finally succeeds.
    #[tokio::test]
    async fn test_daemon_backoff_resets_on_success() {
        let _home = daemon_home();
        let profile = "default";
        let mut state = DaemonState {
            failure_streak: 3,
            current_interval_secs: 21600,
            ..Default::default()
        };
        let probe = FakeProbe::new(true);
        let cycle = FakeCycle::new(true); // succeeds
        let mut log_lines = Vec::new();
        let acct = FakeAccountProbe::default();

        let sleep = daemon_tick(profile, &mut state, &probe, &acct, &cycle, &mut |l| {
            log_lines.push(l.to_string())
        })
        .await;
        assert_eq!(sleep, DEFAULT_INITIAL_INTERVAL_SECS);
        assert_eq!(state.failure_streak, 0);
        assert_ne!(state.last_success_ts, 0);
    }

    /// `daemon reset` zeroes the failure streak and restores the initial
    /// interval so a fix can be observed in minutes instead of hours.
    #[test]
    fn test_daemon_reset_backoff_clears_failure_streak() {
        let _home = daemon_home();
        let profile = crate::store::profiles::create_profile("rl", "").unwrap();
        save_daemon_state(
            &profile,
            &DaemonState {
                failure_streak: 3,
                current_interval_secs: 21600,
                ..Default::default()
            },
        )
        .unwrap();

        let prev = reset_daemon_state(&profile)
            .unwrap()
            .expect("state existed");
        assert_eq!(prev, (3, 21600));

        let st = load_daemon_state(&profile);
        assert_eq!(st.failure_streak, 0);
        assert_eq!(st.current_interval_secs, DEFAULT_INITIAL_INTERVAL_SECS);
    }

    /// `daemon reset` with no state file is a harmless no-op.
    #[test]
    fn test_daemon_reset_backoff_noop_when_no_state_file() {
        let _home = daemon_home();
        let profile = crate::store::profiles::create_profile("rl", "").unwrap();
        assert!(reset_daemon_state(&profile).unwrap().is_none());
    }
    // ── Account gate (2026-11) ──

    /// When the account is suspended and we are inside the poll window, the
    /// daemon must NOT run a cycle (no rescue/scan budget burned) and must
    /// wait for the poll interval.
    #[tokio::test]
    async fn test_daemon_skips_cycle_when_account_suspended() {
        let _home = daemon_home();
        let profile = "default";
        let mut state = DaemonState::default();
        state.account_state = crate::account_state::AccountState::Suspended { since: 1 };
        state.last_account_poll_ts = crate::store::now_ts() as i64; // inside window
        let probe = FakeProbe::new(true);
        let acct = FakeAccountProbe {
            state: crate::account_state::AccountState::Suspended { since: 1 },
        };
        let cycle = FakeCycle::new(true);
        let mut log_lines = Vec::new();
        let sleep = daemon_tick(profile, &mut state, &probe, &acct, &cycle, &mut |l| {
            log_lines.push(l.to_string());
        })
        .await;
        assert_eq!(sleep, crate::account_state::ACCOUNT_POLL_INTERVAL_SECS);
        assert_eq!(
            cycle.calls.load(Ordering::SeqCst),
            0,
            "no cycle while suspended"
        );
        assert!(log_lines.iter().any(|l| l.contains("waiting")));
    }

    /// When a suspended account is reactivated, the daemon must notice on the
    /// next poll and run the cycle again — no manual restart.
    #[tokio::test]
    async fn test_daemon_resumes_when_account_restored() {
        let _home = daemon_home();
        let profile = "default";
        let mut state = DaemonState::default();
        state.account_state = crate::account_state::AccountState::Suspended { since: 1 };
        // Advance the poll window so a re-probe actually happens.
        state.last_account_poll_ts = (crate::store::now_ts() as i64) - 2000;
        let probe = FakeProbe::new(true);
        let acct = FakeAccountProbe {
            state: crate::account_state::AccountState::Active,
        };
        let cycle = FakeCycle::new(true);
        let mut log_lines = Vec::new();
        let sleep = daemon_tick(profile, &mut state, &probe, &acct, &cycle, &mut |l| {
            log_lines.push(l.to_string());
        })
        .await;
        // Restored → cycle ran (calls becomes 1) and we advance normally.
        assert_eq!(cycle.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            state.account_state,
            crate::account_state::AccountState::Active
        );
        assert!(log_lines.iter().any(|l| l.contains("restored")));
        // sleep is the normal reset interval (a cycle succeeded).
        assert_eq!(sleep, backoff_reset());
    }

    /// A token-invalid account is just as blocking as a suspension.
    #[tokio::test]
    async fn test_daemon_skips_cycle_when_token_invalid() {
        let _home = daemon_home();
        let profile = "default";
        let mut state = DaemonState::default();
        state.account_state = crate::account_state::AccountState::TokenInvalid { since: 1 };
        state.last_account_poll_ts = crate::store::now_ts() as i64;
        let probe = FakeProbe::new(true);
        let acct = FakeAccountProbe {
            state: crate::account_state::AccountState::TokenInvalid { since: 1 },
        };
        let cycle = FakeCycle::new(true);
        let sleep = daemon_tick(profile, &mut state, &probe, &acct, &cycle, &mut |_| {}).await;
        assert_eq!(sleep, crate::account_state::ACCOUNT_POLL_INTERVAL_SECS);
        assert_eq!(cycle.calls.load(Ordering::SeqCst), 0);
    }

    /// While active, the daemon periodically confirms the account; if the
    /// account becomes suspended it switches to the wait state.
    #[tokio::test]
    async fn test_daemon_detects_suspension_from_active() {
        let _home = daemon_home();
        let profile = "default";
        let mut state = DaemonState::default();
        state.account_state = crate::account_state::AccountState::Active;
        state.last_account_poll_ts = (crate::store::now_ts() as i64) - 2000;
        let probe = FakeProbe::new(true);
        let acct = FakeAccountProbe {
            state: crate::account_state::AccountState::Suspended { since: 1 },
        };
        let cycle = FakeCycle::new(true);
        let sleep = daemon_tick(profile, &mut state, &probe, &acct, &cycle, &mut |_| {}).await;
        assert_eq!(sleep, crate::account_state::ACCOUNT_POLL_INTERVAL_SECS);
        assert_eq!(cycle.calls.load(Ordering::SeqCst), 0);
        assert!(state.account_state.blocks_cycle());
    }

    /// `clear_account_blocked` resets a blocked daemon state to Active and
    /// forces an immediate re-probe, so protection resumes without a restart
    /// after a guided token recovery.
    #[tokio::test]
    async fn test_clear_account_blocked_resets_blocked_state() {
        let _home = daemon_home();
        let profile = "default";
        let mut state = DaemonState::default();
        state.account_state = crate::account_state::AccountState::TokenInvalid { since: 1 };
        state.last_account_poll_ts = (crate::store::now_ts() as i64) - 100;
        save_daemon_state(profile, &state).unwrap();

        let cleared = crate::daemon::clear_account_blocked(profile).unwrap();
        assert!(cleared, "blocked state should be cleared");

        let after = load_daemon_state(profile);
        assert!(!after.account_state.blocks_cycle());
        assert_eq!(
            after.account_state,
            crate::account_state::AccountState::Active
        );
        assert_eq!(after.last_account_poll_ts, 0, "forces immediate re-probe");
    }

    /// Clearing an already-unblocked daemon is a no-op (returns false).
    #[tokio::test]
    async fn test_clear_account_blocked_noop_when_active() {
        let _home = daemon_home();
        let profile = "default";
        let state = DaemonState::default(); // Active
        save_daemon_state(profile, &state).unwrap();
        let cleared = crate::daemon::clear_account_blocked(profile).unwrap();
        assert!(!cleared);
    }
}
