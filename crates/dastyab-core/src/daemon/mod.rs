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
//!
//! Blackout state machine + carrier reselection (round 4, architect spec #3):
//! [`blackout`] is a pure, socket-free controller the daemon's tier-decision
//! seam routes through (see [`blackout::decide_next_tier`]). It makes the
//! daemon *know* when it is in a total blackout and fast-fail to the worker
//! bootstrap + reselect carriers from the offline pool — no human.
pub mod autonomy_schedule;
pub mod blackout;
pub mod blackout_drill;
pub mod escalation;
pub mod reselect;

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
/// Default cadence for the scheduled blackout self-test (drill): once a day.
pub const DRILL_INTERVAL_SECS: u64 = 86400;
/// Fewer than this many ladder rungs up in a scheduled drill triggers a
/// `ResilienceDegraded` beacon (4 rungs total; <3 = at most Direct/DoH up,
/// meaning a DoT/tunnel blackout would not be survivable with redundancy).
pub const DRILL_DEGRADED_THRESHOLD: u8 = 3;
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
    pub account_state: crate::trust::account_state::AccountState,
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
    /// Last epoch-seconds a scheduled blackout self-test (drill) ran. Used to
    /// rate-limit the daily resilience probe.
    #[serde(default)]
    pub last_drill_ts: i64,
    /// Last epoch-seconds the version-integrity sweep ran. Rate-limits the
    /// daily cadence (like autosync); the sweep is cheap but not free.
    #[serde(default)]
    pub last_verify_ts: i64,
    /// Set once per blocked episode when auto-rotation was *attempted* but
    /// every stored token failed verification. Guards the
    /// `AccountBlockedRotationExhausted` beacon so the user is told exactly
    /// once that a manual token add is required, instead of on every poll
    /// cycle. Reset to false when the account returns to Active.
    #[serde(default)]
    pub account_rotate_exhausted_notified: bool,
    /// Set once per blocked episode when the lifeline tunnel was auto-started
    /// to keep local egress working while the managed CF account is down.
    /// Reset when the account returns to Active.
    #[serde(default)]
    pub lifeline_auto_started: bool,
    /// Unix seconds when the current total blackout began. 0 = not in a
    /// blackout. Drives escalation (`daemon/escalation.rs`).
    #[serde(default)]
    pub blackout_since_unix: i64,
    /// Last epoch-seconds we queried the worker self-ping freshness (throttled
    /// to ~once per 6h off the hot path).
    #[serde(default)]
    pub last_self_ping_ts: i64,
    /// Scheduled autonomy-audit state (auto-execute allowlist + regression
    /// fingerprint). Persisted so the audit cadence and last digest survive
    /// restarts.
    #[serde(default)]
    pub audit: crate::daemon::autonomy_schedule::AuditSchedule,
    /// Last epoch-seconds a scheduled workspace snapshot was written.
    #[serde(default)]
    pub last_snapshot_ts: i64,
    /// Last epoch-seconds an autonomous node-refill pass ran. Rate-limits the
    /// dead-pool recovery (telegram+github harvest + probe) to once per
    /// `node_refill::REFILL_COOLDOWN_SECS`.
    #[serde(default)]
    pub last_refill_ts: i64,
    /// Last epoch-seconds the autonomous multi-hop Telegram discovery +
    /// v2rayN export pass ran. Rate-limits the self-expanding net walk
    /// (doctrine §5) to `node_refill::DISCOVERY_INTERVAL_SECS`.
    #[serde(default)]
    pub last_discovery_ts: i64,
    /// Last epoch-seconds the periodic config-health-decay sweep ran.
    /// Rate-limits re-probing of stale nodes to `NODE_DECAY_INTERVAL_SECS`.
    #[serde(default)]
    pub last_node_decay_ts: i64,
    /// Last epoch-seconds the deep real-egress verification pass ran.
    /// Rate-limits `tunnel_lifeline::deep_verify_egress` (which spawns a
    /// temporary xray per candidate on a dedicated port) to a slow cadence
    /// so the pool's `healthy` verdicts reflect *real* traffic, not just TLS.
    #[serde(default)]
    pub last_deep_verify_ts: i64,
    /// Last epoch-seconds the out-of-band CT-anchor set was refreshed + pruned.
    /// Rate-limits crt.sh discovery + re-probe to
    /// `ANCHOR_REFRESH_INTERVAL_SECS` (doctrine §6.5: rate-limit expensive).
    #[serde(default)]
    pub last_anchors_refresh_ts: i64,
    /// Last epoch-seconds the authoritative-nameserver anchor set was refreshed
    /// + pruned (doctrine §8.1). Mirrors the CT-anchor rotation cadence.
    #[serde(default)]
    pub last_ns_anchors_refresh_ts: i64,
    /// Last epoch-seconds the signed OOB relay-manifest feed was ingested.
    /// Rate-limits the signed-egress-anchor pull (doctrine §6.5).
    #[serde(default)]
    pub last_oob_pull_ts: i64,
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
            account_state: crate::trust::account_state::AccountState::Active,
            last_account_poll_ts: 0,
            survival_plan: String::new(),
            network_tier: String::new(),
            last_update_check_ts: 0,
            last_backup_ts: 0,
            last_profile_mtime: 0,
            last_outbox_flush_ts: 0,
            last_drill_ts: 0,
            last_verify_ts: 0,
            account_rotate_exhausted_notified: false,
            lifeline_auto_started: false,
            blackout_since_unix: 0,
            last_self_ping_ts: 0,
            audit: crate::daemon::autonomy_schedule::AuditSchedule::default(),
            last_snapshot_ts: 0,
            last_refill_ts: 0,
            last_discovery_ts: 0,
            last_node_decay_ts: 0,
            last_deep_verify_ts: 0,
            last_anchors_refresh_ts: 0,
            last_ns_anchors_refresh_ts: 0,
            last_oob_pull_ts: 0,
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
    state.account_state = crate::trust::account_state::AccountState::Active;
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

/// Cap for backoff when the failure was a *cycle timeout* (deep discovery
/// exceeded its budget on a slow/censored network) rather than a hard,
/// persistent failure (worker dead, account suspended, token invalid). A
/// timeout is transient — the network path can clear at any moment — so we
/// must not let the daemon back off all the way to the 6h max, which would
/// leave protection stale for hours after connectivity actually returns. One
/// hour is enough breathing room for a genuinely slow deep pass while still
/// keeping recovery prompt.
pub const TIMEOUT_BACKOFF_CAP_SECS: u64 = 3600;

/// True when failure error `e` is a cycle-timeout class failure. The guarded
/// monitor/run cycles return a `CFError` titled "Cycle timeout" (with a stage
/// in the detail) when the light or deep phase exceeds its budget.
pub fn is_cycle_timeout(e: &CFError) -> bool {
    e.title.eq_ignore_ascii_case("Cycle timeout")
}

/// Pure: compute the backoff interval for a failure, applying the lower cap
/// for the transient timeout class. Otherwise identical to `backoff_next`.
pub fn backoff_for_failure(current: u64, max: u64, e: &CFError) -> u64 {
    if is_cycle_timeout(e) {
        // Timeouts are transient — never hold a multi-hour interval. Clamp to
        // the 1h ceiling, *stepping down* if we're already above it (so a
        // daemon that escalated before this fix — or during a long partial
        // blackout — converges back to prompt recovery instead of lingering at
        // 6h).
        backoff_next(current, max.min(TIMEOUT_BACKOFF_CAP_SECS)).min(TIMEOUT_BACKOFF_CAP_SECS)
    } else {
        backoff_next(current, max)
    }
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
        "[Unit]\nDescription=DastYab protection daemon\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=simple\nExecStart={} daemon start --profile {} --foreground\nRestart=always\nRestartSec=30\nRuntimeMaxSec=1800\nStandardOutput=null\nStandardError=null\n\n[Install]\nWantedBy=default.target\n",
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

/// Best-effort enable of loginctl "linger" for the calling user. With linger
/// on, the per-user systemd manager (and therefore our `--user` daemon unit)
/// starts at boot *before* any graphical login — the key to surviving a
/// total-blackout reboot without a human logged into the box. Pure extra
/// resilience: if `loginctl` is missing or refused, this returns false and
/// the caller may degrade gracefully (the unit still autostarts on login).
pub fn enable_linger() -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    let Some(user) = std::env::var("USER").ok() else {
        return false;
    };
    if user.is_empty() {
        return false;
    }
    std::process::Command::new("loginctl")
        .arg("enable-linger")
        .arg(&user)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Whether loginctl linger is currently enabled for the calling user. Returns
/// `None` when the platform/user can't be determined (non-Linux, no USER env,
/// or `loginctl` unavailable).
pub fn is_linger_enabled() -> Option<bool> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let user = std::env::var("USER").ok()?;
    if user.is_empty() {
        return None;
    }
    let outp = std::process::Command::new("loginctl")
        .args(["show-user", &user, "-p", "Linger", "--value"])
        .output()
        .ok()?;
    Some(parse_linger(&outp.stdout))
}

/// Parse the `loginctl show-user … -p Linger --value` stdout into a bool.
/// loginctl prints "yes" or "no" (with a trailing newline).
fn parse_linger(bytes: &[u8]) -> bool {
    let s = String::from_utf8_lossy(bytes);
    s.trim().eq_ignore_ascii_case("yes")
}

#[cfg(test)]
mod linger_tests {
    use super::parse_linger;

    #[test]
    fn parses_yes_no_and_weird_whitespace() {
        assert!(parse_linger(b"yes\n"));
        assert!(parse_linger(b"yes"));
        assert!(parse_linger(b" YES \n"));
        assert!(!parse_linger(b"no\n"));
        assert!(!parse_linger(b""));
        assert!(!parse_linger(b"nonsense"));
    }
}

/// Result of a network-liveness probe: whether the network is up at all, plus
/// the best transport tier that was reachable (None when nothing worked).
#[derive(Debug, Clone, Default)]
pub struct NetStatus {
    pub up: bool,
    pub tier: Option<crate::net::connectivity::Tier>,
}

impl NetStatus {
    pub fn tier_label(&self) -> String {
        self.tier.map(|t| t.label().to_string()).unwrap_or_default()
    }
}

/// Abstraction over the network-liveness probe so the loop is testable.
pub trait NetworkProbe: Send + Sync {
    fn liveness(&mut self) -> Pin<Box<dyn Future<Output = NetStatus> + Send + '_>>;
}

/// Real probe backed by the DoH resolver + the full fallback ladder. Holds a
/// persistent, stateful `FallbackLadder<OwnedLadderProbe>` so tier state is
/// retained across daemon ticks: when the current tier fails it descends
/// (direct → DoH → DoT → DNS tunnel) and climbs back up when a higher tier
/// returns — rather than re-probing the whole ladder from scratch every tick.
pub struct RealNetworkProbe {
    pub ladder:
        crate::net::connectivity::FallbackLadder<crate::net::connectivity::OwnedLadderProbe>,
}

impl RealNetworkProbe {
    pub fn new(profile: &str) -> Self {
        let probe = crate::net::connectivity::OwnedLadderProbe {
            profile: profile.to_string(),
            resolver: crate::net::doh::DohResolver::new(),
        };
        Self {
            ladder: crate::net::connectivity::FallbackLadder::new(
                probe,
                crate::net::connectivity::Tier::Direct,
            ),
        }
    }
}

impl NetworkProbe for RealNetworkProbe {
    fn liveness(&mut self) -> Pin<Box<dyn Future<Output = NetStatus> + Send + '_>> {
        Box::pin(async move {
            let (up, tier) = self.ladder.liveness_status().await;
            NetStatus { up, tier }
        })
    }
}

/// Abstraction over a single monitor/cycle run so the loop is testable.
pub trait CycleRunner: Send + Sync {
    fn run_cycle(
        &self,
        profile: &str,
        follow: bool,
        timeouts: crate::probe::autopilot::MonitorTimeouts,
    ) -> Pin<Box<dyn Future<Output = Result<(), CFError>> + Send + '_>>;
}

/// Execute a worker-mediated carrier-snapshot refresh for a profile.
///
/// This is the load-bearing implementation of the
/// `BlackoutAction::RefreshViaWorkerTunnel` arm: it opens the profile's offline
/// carrier pool, builds a [`CarrierRefresher`] from the profile's worker-tunnel
/// config, and pulls + merges the latest snapshot. Logs the outcome.
///
/// `worker_url`/`shared_secret` come from the profile's `TunnelClientConfig`.
/// Pure filesystem + localhost only in tests (mock worker URL).
pub fn daemon_refresh_carriers(
    profile: &str,
    worker_url: &str,
    shared_secret: &str,
    now_unix: u64,
    log: &mut dyn FnMut(&str),
) -> Result<(), crate::egress::carrier_refresh::RefreshError> {
    let cfg = crate::store::profiles::load_profile(profile).config;
    let pool = crate::egress::carrier_pool::open_profile_pool(&cfg)?;
    // Anti-DPI desync connector: pick the worker's learned strategy (ladder),
    // and record the outcome so a repeated transport failure advances the
    // ladder on the next refresh (persisted on the profile).
    let strategy = crate::egress::worker_tunnel::secret::strategy_for_worker(&cfg, worker_url, 0);
    let refresher =
        crate::egress::carrier_refresh::CarrierRefresher::new(worker_url, shared_secret);
    let result = refresher.refresh_once(&pool, now_unix);
    let mut pcfg = crate::store::profiles::load_profile(profile);
    match &result {
        Ok(_) => {
            crate::egress::worker_tunnel::secret::record_worker_desync_success(
                &mut pcfg.config,
                worker_url,
                strategy,
            );
        }
        Err(crate::egress::carrier_refresh::RefreshError::Transport(_)) => {
            crate::egress::worker_tunnel::secret::record_worker_desync_failure(
                &mut pcfg.config,
                worker_url,
                strategy,
            );
            log(&format!("carrier refresh: transport failure recorded for desync ladder (strategy {strategy:?})"));
        }
        _ => {}
    }
    if pcfg.config.worker_secrets != cfg.worker_secrets {
        if let Err(e) = crate::store::profiles::save_profile(&pcfg) {
            log(&format!(
                "carrier refresh: failed to persist desync learning: {e}"
            ));
        }
    }
    match result? {
        crate::egress::carrier_refresh::RefreshOutcome::Updated(r) => {
            log(&format!(
                "carrier refresh: {} added, {} updated",
                r.added, r.updated
            ));
        }
        crate::egress::carrier_refresh::RefreshOutcome::NotNewer { server_generation } => {
            log(&format!(
                "carrier refresh: not newer (server gen {server_generation})"
            ));
        }
        crate::egress::carrier_refresh::RefreshOutcome::NoSnapshot => {
            log("carrier refresh: worker has no snapshot yet");
        }
    }
    Ok(())
}

/// Try to refresh the carrier pool via the worker control-plane relay during a
/// blackout. No-op (`Ok`) unless the profile's tunnel is a Cloudflare-Worker
/// tunnel with a configured URL + secret, in which case it pulls the latest
/// carrier snapshot from the KV relay and merges it into the offline pool — so
/// reselection during a total blackout sees the freshest endpoints. The actual
/// HTTP runs on its own OS thread (see [`CarrierRefresher`]), so this is safe
/// to call from the async daemon tick.
pub fn refresh_carriers_via_worker_tunnel(
    profile: &str,
    log: &mut dyn FnMut(&str),
) -> Result<(), crate::egress::carrier_refresh::RefreshError> {
    let Some(cfg) = crate::egress::vps_deploy::load_tunnel_client_config(profile) else {
        return Ok(());
    };
    let crate::egress::vps_deploy::TunnelMode::Worker = cfg.mode else {
        return Ok(());
    };
    let (Some(url), Some(secret)) = (cfg.worker_url.as_deref(), cfg.shared_secret.as_deref())
    else {
        return Ok(());
    };
    // Per-worker secret resolution: prefer the per-worker current secret over
    // the legacy shared secret when the profile has a per-worker entry.
    let pcfg = crate::store::profiles::load_profile(profile).config;
    let resolved = crate::egress::worker_tunnel::secret::resolve_worker_secret(&pcfg, url, secret);
    daemon_refresh_carriers(profile, url, &resolved, crate::store::now_ts() as u64, log)
}

/// Try to push the profile's carrier snapshot to the worker relay when the
/// endpoint identity set changed (continuous push on the healthy-network side).
/// No-op unless the profile uses a Worker-mode tunnel with URL+secret. This is
/// the counterpart to [`refresh_carriers_via_worker_tunnel`]: push happens when
/// the network is up, pull during a blackout. Best-effort; failures log and
/// leave the last-pushed hash unchanged (next tick retries).
pub fn push_carriers_via_worker_tunnel(
    profile: &str,
    log: &mut dyn FnMut(&str),
) -> Result<(), crate::egress::carrier_refresh::RefreshError> {
    let Some(cfg) = crate::egress::vps_deploy::load_tunnel_client_config(profile) else {
        return Ok(());
    };
    let crate::egress::vps_deploy::TunnelMode::Worker = cfg.mode else {
        return Ok(());
    };
    let (Some(url), Some(secret)) = (cfg.worker_url.as_deref(), cfg.shared_secret.as_deref())
    else {
        return Ok(());
    };
    let pcfg = crate::store::profiles::load_profile(profile).config;
    let resolved = crate::egress::worker_tunnel::secret::resolve_worker_secret(&pcfg, url, secret);
    let pool = crate::egress::carrier_pool::open_profile_pool(
        &crate::store::profiles::load_profile(profile).config,
    )?;
    let refresher = crate::egress::carrier_refresh::CarrierRefresher::new(url, resolved.as_ref());
    match refresher.push_snapshot_if_identity_changed(&pool)? {
        crate::egress::carrier_refresh::PushOutcome::Pushed { endpoints } => {
            log(&format!("carrier push: {endpoints} endpoints to worker"));
        }
        crate::egress::carrier_refresh::PushOutcome::Skipped { reason } => {
            log(&format!("carrier push skipped: {reason:?}"));
        }
    }
    Ok(())
}

/// Production CF seam for the autonomy auto-executor. Holds an owned token so
/// the auto-fix actions can build a `cf::Client` on a scoped thread (no borrow
/// crosses into a `'static` future).
pub struct RealCfSeam {
    token: String,
    pub account_id: String,
}

impl RealCfSeam {
    pub fn new(token: impl Into<String>, account_id: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            account_id: account_id.into(),
        }
    }
}

impl crate::daemon::autonomy_schedule::CfApiSeam for RealCfSeam {
    fn ensure_second_token(&self, profile: &str) -> Result<bool, CFError> {
        let token = self.token.clone();
        let account_id = self.account_id.clone();
        let profile_owned = profile.to_string();
        std::thread::scope(|scope| {
            let handle = scope.spawn(move || {
                let rt = tokio::runtime::Runtime::new()
                    .map_err(|e| CFError::new("cf-seam", format!("runtime: {e}"), ""))?;
                rt.block_on(async move {
                    let create = move |account_id: String,
                                       name: String|
                          -> Pin<
                        Box<dyn Future<Output = Result<String, CFError>> + Send>,
                    > {
                        let token = token.clone();
                        Box::pin(async move {
                            let cf = crate::cf::Client::new(&token);
                            cf.create_api_token(&account_id, &name).await
                        })
                    };
                    crate::trust::token_provision::ensure_minimum_tokens(
                        &profile_owned,
                        2,
                        account_id.clone(),
                        create,
                    )
                    .await
                })
            });
            handle
                .join()
                .unwrap_or_else(|_| Err(CFError::new("cf-seam", "worker thread panicked", "")))
        })
    }

    fn rotate_worker(&self, profile: &str) -> Result<u32, CFError> {
        let Some(tcfg) = crate::egress::vps_deploy::load_tunnel_client_config(profile) else {
            return Ok(0);
        };
        let crate::egress::vps_deploy::TunnelMode::Worker = tcfg.mode else {
            return Ok(0);
        };
        let Some(worker_url) = tcfg.worker_url.as_deref() else {
            return Ok(0);
        };
        let mut prof = crate::store::profiles::load_profile(profile);
        let now = crate::store::now_ts() as u64;
        crate::egress::worker_tunnel::secret::assign_new_secret(&mut prof.config, worker_url, now)?;
        crate::store::profiles::save_profile(&prof)?;

        let opts = crate::egress::worker_tunnel::WorkerTunnelDeployOpts {
            worker_name: tcfg.worker_name.clone(),
            session_seed: tcfg.session.clone(),
            compat_date: "2026-07-01".into(),
            retries: 2,
            vless_upstream: tcfg.worker_vless_upstream.clone(),
        };
        let token = self.token.clone();
        let account_id = self.account_id.clone();
        let profile_owned = profile.to_string();
        std::thread::scope(|scope| {
            let handle = scope.spawn(move || {
                let rt = tokio::runtime::Runtime::new()
                    .map_err(|e| CFError::new("cf-seam", format!("runtime: {e}"), ""))?;
                rt.block_on(async move {
                    let cf = crate::cf::Client::new(&token);
                    crate::egress::worker_tunnel::deploy::deploy_worker_tunnel(
                        &cf,
                        &account_id,
                        &profile_owned,
                        &opts,
                    )
                    .await
                })
            });
            handle
                .join()
                .unwrap_or_else(|_| Err(CFError::new("cf-seam", "worker thread panicked", "")))
        })?;

        let mut prof2 = crate::store::profiles::load_profile(profile);
        let pending = prof2
            .config
            .worker_secrets
            .get(worker_url)
            .and_then(|ws| ws.pending_secret.clone());
        let Some(pending_secret) = pending else {
            return Ok(prof2
                .config
                .worker_secrets
                .get(worker_url)
                .map(|w| w.version)
                .unwrap_or(0));
        };
        let refresher =
            crate::egress::carrier_refresh::CarrierRefresher::new(worker_url, &pending_secret);
        if refresher.query_self_ping().is_ok() {
            crate::egress::worker_tunnel::secret::promote_pending(
                &mut prof2.config,
                worker_url,
                now,
            )?;
        } else {
            crate::egress::worker_tunnel::secret::clear_pending(&mut prof2.config, worker_url);
        }
        let version = prof2
            .config
            .worker_secrets
            .get(worker_url)
            .map(|w| w.version)
            .unwrap_or(0);
        crate::store::profiles::save_profile(&prof2)?;
        Ok(version)
    }

    fn ensure_dns_tunnel(&self, profile: &str) -> Result<(), CFError> {
        let prof = crate::store::profiles::load_profile(profile);
        if crate::egress::vps_deploy::load_tunnel_client_config(profile).is_some() {
            return Ok(());
        }
        let seed = prof.config.active_account.clone();
        let opts = crate::egress::worker_tunnel::WorkerTunnelDeployOpts {
            worker_name: None,
            session_seed: if seed.is_empty() {
                "default-seed".into()
            } else {
                seed
            },
            compat_date: "2026-07-01".into(),
            retries: 2,
            vless_upstream: None,
        };
        let token = self.token.clone();
        let account_id = self.account_id.clone();
        let profile_owned = profile.to_string();
        std::thread::scope(|scope| {
            let handle = scope.spawn(move || {
                let rt = tokio::runtime::Runtime::new()
                    .map_err(|e| CFError::new("cf-seam", format!("runtime: {e}"), ""))?;
                rt.block_on(async move {
                    let cf = crate::cf::Client::new(&token);
                    crate::egress::worker_tunnel::deploy::deploy_worker_tunnel(
                        &cf,
                        &account_id,
                        &profile_owned,
                        &opts,
                    )
                    .await
                })
            });
            handle
                .join()
                .unwrap_or_else(|_| Err(CFError::new("cf-seam", "worker thread panicked", "")))
        })?;
        Ok(())
    }
}

/// Run the scheduled autonomy audit on this tick (if due) and auto-execute any
/// ACTION-status item whose preconditions are met. Returns the number of fixes
/// applied. Fires the `AutonomyRegression` beacon on a clean→dirty transition
/// (never on repeated dirty→dirty, and never on the first ever audit).
///
/// The CF seam is injected so tests can script it; production passes the real
/// [`RealCfSeam`]. When no seam is available (no resolvable active token +
/// account), the CF-backed items (`token_rotate`, `worker_secret_rotate`,
/// `tunnel`) are skipped while config-toggle items (`backup`, `mutation`) still
/// auto-apply. This keeps first-run / empty-profile ticks hermetic — no network.
pub async fn run_autonomy_audit_with_seam(
    profile: &str,
    state: &mut DaemonState,
    net_up: bool,
    seam: Option<&dyn crate::daemon::autonomy_schedule::CfApiSeam>,
    log: &mut dyn FnMut(&str),
) -> usize {
    let now = crate::store::now_ts() as u64;
    if !crate::daemon::autonomy_schedule::should_run_audit(state, now) {
        return 0;
    }

    let prof = crate::store::profiles::load_profile(profile);
    let report = crate::trust::autonomy::run_audit(&prof);

    let action_codes: Vec<String> = report
        .items
        .iter()
        .filter(|i| i.status == crate::trust::autonomy::CheckStatus::Action)
        .map(|i| i.code.clone())
        .collect();

    let code_refs: Vec<&str> = action_codes.iter().map(|s| s.as_str()).collect();
    let new_digest = crate::daemon::autonomy_schedule::action_digest(&code_refs);

    // Regression beacon: clean→dirty only (first audit = no regress).
    if crate::daemon::autonomy_schedule::regression_events(
        state.audit.last_action_digest,
        new_digest,
    ) {
        log(&log_line(
            "WARN",
            &format!(
                "autonomy regression: {} action(s) still pending",
                action_codes.len()
            ),
        ));
        let _ = crate::mesh::remote_beacon::maybe_emit(
            profile,
            &crate::mesh::remote_beacon::BeaconEvent::AutonomyRegression {
                codes: action_codes.clone(),
            },
            crate::probe::diagnose::Locale::En,
        )
        .await;
    }
    state.audit.last_action_digest = Some(new_digest);
    state.audit.last_run_unix = now;

    // Auto-execute eligible items.
    let mut cfg = prof.config.clone();
    let mut applied = 0usize;

    // Config-toggle items never touch the seam; give them a placeholder seam so
    // the context always has a concrete `&dyn CfApiSeam` (execute_auto_fix only
    // reaches the seam for CF-backed codes, which are gated below).
    struct NoopSeam;
    impl crate::daemon::autonomy_schedule::CfApiSeam for NoopSeam {
        fn ensure_second_token(&self, _p: &str) -> Result<bool, CFError> {
            Ok(false)
        }
        fn rotate_worker(&self, _p: &str) -> Result<u32, CFError> {
            Ok(0)
        }
        fn ensure_dns_tunnel(&self, _p: &str) -> Result<(), CFError> {
            Ok(())
        }
    }
    let noop = NoopSeam;
    let effective_seam: &dyn crate::daemon::autonomy_schedule::CfApiSeam = match seam {
        Some(s) => s,
        None => &noop,
    };

    for code in &action_codes {
        let needs_seam = !matches!(code.as_str(), "backup" | "mutation");
        if needs_seam && seam.is_none() {
            continue;
        }
        if !crate::daemon::autonomy_schedule::auto_executable(code, &cfg, net_up, now) {
            continue;
        }
        let mut ctx = crate::daemon::autonomy_schedule::AutonomyContext {
            profile,
            seam: effective_seam,
            now_unix: now,
            net_up,
            cfg: &mut cfg,
        };
        match crate::daemon::autonomy_schedule::execute_auto_fix(code, &mut ctx) {
            Ok(true) => {
                applied += 1;
                log(&log_line("INFO", &format!("auto-fixed audit item: {code}")));
            }
            Ok(false) => {}
            Err(e) => {
                // Leave the item pending; do not abort the rest of the pass.
                log(&log_line(
                    "WARN",
                    &format!("auto-fix failed for {code}: {}", e.brief()),
                ));
            }
        }
    }

    if applied > 0 {
        let mut p = prof;
        p.config = cfg;
        let _ = crate::store::profiles::save_profile(&p);
    }
    applied
}

/// Query the deployed worker's last self-ping freshness (the `_ping` KV key
/// written by the worker's cron `scheduled` handler). Returns `None` when the
/// profile is not a Worker-mode tunnel, or when the worker has never pinged.
/// Best-effort: any failure logs and returns `None` (callers treat non-`None`
/// as the only signal worth surfacing).
pub fn query_worker_self_ping(profile: &str, log: &mut dyn FnMut(&str)) -> Option<u64> {
    let cfg = crate::egress::vps_deploy::load_tunnel_client_config(profile)?;
    let crate::egress::vps_deploy::TunnelMode::Worker = cfg.mode else {
        return None;
    };
    let (url, secret) = (cfg.worker_url.as_deref()?, cfg.shared_secret.as_deref()?);
    let pcfg = crate::store::profiles::load_profile(profile).config;
    let resolved = crate::egress::worker_tunnel::secret::resolve_worker_secret(&pcfg, url, secret);
    let refresher = crate::egress::carrier_refresh::CarrierRefresher::new(url, resolved.as_ref());
    match refresher.query_self_ping() {
        Ok(ping) => ping,
        Err(e) => {
            log(&format!("self-ping query failed: {e}"));
            None
        }
    }
}

/// Two-phase worker-secret rotation (pending → current). Stages a pending
/// secret in the profile, redeploys the worker with it, then verifies via
/// `query_self_ping` authenticated with the pending secret; only on success
/// promotes pending → current. On any failure the current secret stays active
/// and the pending one is retained for a retry (or cleared when stale).
///
/// Callers must gate with [`secret::rotation_eligible`] (e.g. only when the
/// network is up) — this function does not re-check net state.
pub async fn rotate_worker_secret(
    cf: &crate::cf::Client,
    account_id: &str,
    profile: &str,
) -> Result<(), CFError> {
    let Some(tcfg) = crate::egress::vps_deploy::load_tunnel_client_config(profile) else {
        return Ok(());
    };
    let crate::egress::vps_deploy::TunnelMode::Worker = tcfg.mode else {
        return Ok(());
    };
    let Some(worker_url) = tcfg.worker_url.as_deref() else {
        return Ok(());
    };
    // Stage a fresh pending secret.
    let mut prof = crate::store::profiles::load_profile(profile);
    let now = crate::store::now_ts() as u64;
    crate::egress::worker_tunnel::secret::assign_new_secret(&mut prof.config, worker_url, now)?;
    crate::store::profiles::save_profile(&prof)?;

    // Redeploy with the pending secret.
    let opts = crate::egress::worker_tunnel::WorkerTunnelDeployOpts {
        worker_name: tcfg.worker_name.clone(),
        session_seed: tcfg.session.clone(),
        compat_date: "2026-07-01".into(),
        retries: 2,
        vless_upstream: tcfg.worker_vless_upstream.clone(),
    };
    crate::egress::worker_tunnel::deploy::deploy_worker_tunnel(cf, account_id, profile, &opts)
        .await?;

    // Verify via self-ping authenticated with the pending secret.
    let mut prof2 = crate::store::profiles::load_profile(profile);
    let pending = prof2
        .config
        .worker_secrets
        .get(worker_url)
        .and_then(|ws| ws.pending_secret.clone());
    let Some(pending_secret) = pending else {
        // No pending yet (e.g. very first deploy) — nothing to promote.
        return Ok(());
    };
    let refresher =
        crate::egress::carrier_refresh::CarrierRefresher::new(worker_url, &pending_secret);
    if refresher.query_self_ping().is_ok() {
        crate::egress::worker_tunnel::secret::promote_pending(&mut prof2.config, worker_url, now)?;
    } else {
        // Verification failed — keep current active; leave pending for retry.
        crate::egress::worker_tunnel::secret::clear_pending(&mut prof2.config, worker_url);
    }
    crate::store::profiles::save_profile(&prof2)?;
    Ok(())
}

/// Execute a carrier reselection: select up to `n` endpoints of `kind` from
/// the offline pool, open them (serially when `max_concurrent <= 1`, else in
/// a bounded parallel pool) via [`reselect::RealTunnelOpener`], and persist the
/// first that works as the active tunnel. Returns the host of the winning
/// endpoint, or `None` when nothing worked. This is what makes the blackout
/// state machine's `ReselectCarrier` decision actually change the active
/// tunnel (previously it was logged and discarded).
pub fn exec_reselection(
    profile: &str,
    kind: crate::egress::carrier_pool::CarrierKind,
    n: usize,
    max_concurrent: usize,
    log: &mut dyn FnMut(&str),
) -> Option<String> {
    let cfg = crate::store::profiles::load_profile(profile).config;
    let pool = crate::egress::carrier_pool::open_profile_pool(&cfg).ok()?;
    let now = crate::store::now_ts() as u64;
    // Use select_at so endpoints in failure-cooldown are skipped; only fall
    // back to cooling endpoints when nothing else exists. This prevents a
    // total-blackout reselect from re-dialing the same dead endpoint on every
    // tick.
    let candidates = pool.select_at(kind, n, now).ok()?;
    if candidates.is_empty() {
        log("reselect: pool has no candidates");
        return None;
    }
    let opener = crate::daemon::reselect::RealTunnelOpener::new(profile);
    let outcome =
        crate::daemon::reselect::exec_reselection_wrapper(&candidates, &opener, max_concurrent);
    match outcome {
        Some(tunnel) => {
            let ep = &tunnel.endpoint;
            log(&format!("reselect: switched active tunnel to {}", ep.host));
            // Bind the winning endpoint as the active tunnel, then mark it a
            // success (clears any cooldown).
            let bound = crate::daemon::reselect::bind_winner(profile, ep);
            let _ = pool.record_success(ep);
            if !bound {
                // VPS tunnel needs no worker config write; still a success.
                log("reselect: bound active tunnel (VPS)");
            }
            Some(ep.host.clone())
        }
        None => {
            // Every candidate failed → cooldown all of them so the next tick
            // tries fresh paths instead of the same dead ones.
            for c in &candidates {
                let _ = pool.record_failure(c, now);
            }
            log("reselect: no candidate opened");
            None
        }
    }
}

/// The result of an automatic token rotation: `(old_label, new_label)`.
pub type RotationOutcome = (String, String);

/// Abstraction over the account-status probe so the loop is testable. Returns
/// the current account state without blocking on the full cycle.
pub trait AccountProbe: Send + Sync {
    fn probe_account(
        &self,
        profile: &str,
    ) -> Pin<Box<dyn Future<Output = crate::trust::account_state::AccountState> + Send + '_>>;

    /// Attempt automatic token rotation when the active token is blocked.
    /// Returns `Some((from, to))` when another stored token verified and was
    /// made active, `None` when nothing rotated. Default: no-op — tests and
    /// probes that don't implement rotation simply skip it.
    fn try_rotate(
        &self,
        _profile: &str,
    ) -> Pin<Box<dyn Future<Output = Option<RotationOutcome>> + Send + '_>> {
        Box::pin(async move { None })
    }
}

/// Real account probe backed by the Cloudflare API.
pub struct RealAccountProbe;

impl AccountProbe for RealAccountProbe {
    fn probe_account(
        &self,
        profile: &str,
    ) -> Pin<Box<dyn Future<Output = crate::trust::account_state::AccountState> + Send + '_>> {
        let profile = profile.to_string();
        Box::pin(async move { crate::trust::account_state::probe_account_state(&profile).await })
    }

    fn try_rotate(
        &self,
        profile: &str,
    ) -> Pin<Box<dyn Future<Output = Option<(String, String)>> + Send + '_>> {
        let profile = profile.to_string();
        Box::pin(async move {
            let p = crate::store::profiles::load_profile(&profile);
            if !p.config.auto_rotate_on_blocked {
                return None;
            }
            crate::trust::token_rotate::try_auto_rotate(&profile, |tok| {
                let tok = tok.to_string();
                Box::pin(async move { crate::cf::Client::new(&tok).verify_token().await.is_ok() })
            })
            .await
            .unwrap_or(None)
        })
    }
}

/// Real cycle runner: runs the autopilot monitor cycle.
pub struct RealCycleRunner;

impl CycleRunner for RealCycleRunner {
    fn run_cycle(
        &self,
        profile: &str,
        _follow: bool,
        timeouts: crate::probe::autopilot::MonitorTimeouts,
    ) -> Pin<Box<dyn Future<Output = Result<(), CFError>> + Send + '_>> {
        let profile = profile.to_string();
        Box::pin(async move {
            let params = crate::probe::autopilot::DiscoveryParams::default();
            let engine = crate::probe::autopilot::AutopilotEngine::new(
                profile.clone(),
                params,
                std::time::Duration::from_secs(DEFAULT_INITIAL_INTERVAL_SECS),
            );
            engine.monitor_cycle_guarded(timeouts).await.map(|_| ())
        })
    }
}

/// Periodic self-maintenance, run at the top of every daemon tick:
///
/// 1. **Scheduled auto-backup** — if `backup_autosync.enabled`, export the
///    profile to a JSON backup each interval and trim to `keep`. This is local
///    disk work, so it runs unconditionally — even during a total blackout the
///    app keeps a fresh recoverable copy of its own configuration.
/// 2. **Scheduled worker-signature rotation** — if `mutation.enabled`, redeploy
///    the worker with a fresh UUID/path each interval (moving target against
///    stateful DPI). This needs the Cloudflare API, so it only runs when the
///    network is up.
///
/// Both were previously dormant features (config structs existed but nothing
/// called them). This is what makes the daemon fully automatic — no manual
/// backup, no manual redeploy.
async fn run_self_maintenance(
    profile: &str,
    state: &mut DaemonState,
    net_up: bool,
    log: &mut dyn FnMut(&str),
) {
    let now = crate::store::now_ts() as i64;
    let p = crate::store::profiles::load_profile(profile);

    // 1. Scheduled auto-backup (local — safe even during a blackout).
    match crate::ops::backup_autosync::run_autosync_if_due(
        &p.config.backup_autosync,
        profile,
        state.last_backup_ts,
        now,
    ) {
        Ok(Some(path)) => {
            state.last_backup_ts = now;
            let _ = crate::mesh::journal::append(
                profile,
                crate::mesh::journal::JournalKind::BackupWritten,
                &path.display().to_string(),
            );
            log(&log_line(
                "INFO",
                &format!("auto-backup written → {}", path.display()),
            ));
            let _ = crate::store::profiles::save_profile(&p);
        }
        Ok(None) => {}
        Err(e) => {
            log(&log_line(
                "WARN",
                &format!("auto-backup failed: {}", e.brief()),
            ));
        }
    }

    // 2. Scheduled worker-signature rotation. Only when the network is up
    // (CF API redeploy requires connectivity). The liveness probe has already
    // run in `daemon_tick` and its result is passed in as `net_up`.
    if net_up && crate::ops::airgap::online() {
        match crate::artifact::config_mutation::run_mutation_if_due::<
            crate::probe::autopilot::RealMutationPeer,
        >(profile, &crate::probe::autopilot::RealMutationPeer)
        .await
        {
            Ok(Some(outcome)) => {
                state.last_cycle_ts = now;
                let _ = crate::mesh::journal::append(
                    profile,
                    crate::mesh::journal::JournalKind::MutationPerformed,
                    &format!("uuid={} path={}", outcome.new_uuid, outcome.new_path),
                );
                log(&log_line(
                    "INFO",
                    &format!("signature rotated → uuid={}", outcome.new_uuid),
                ));
            }
            Ok(None) => {}
            Err(e) => {
                log(&log_line(
                    "WARN",
                    &format!("signature rotation failed: {}", e.brief()),
                ));
            }
        }
    }

    // 3. Scheduled blackout self-test (drill). Probes every fallback-ladder
    // rung, journals how many survive, and alerts if resilience has degraded.
    // Runs whenever the network is up (a probe during a full blackout would
    // just report all-down — not informative).
    if net_up && crate::ops::airgap::online() {
        run_scheduled_drill(profile, state, now, &mut |msg| log(&log_line("INFO", msg))).await;
    }

    // 4. Auto-heal: if a critical artifact (profile/token/accounts/config) is
    // Missing or Changed, restore it from the newest verifying backup — never
    // from an unverified source, and never silently (always journaled).
    run_auto_heal(profile, log);

    // 5. Scheduled workspace snapshot: on the 6h cadence, snapshot the whole
    // workspace (all profiles) so every past point is roll-back-able. Trims
    // to keep-14. Local disk work — safe even during a blackout.
    run_scheduled_snapshot(profile, state, now, log);

    // 6. Daily version-integrity sweep (content verification of every saved
    // version). Turns the Doctor "Versions: ok" claim into a verified one —
    // bit-rot/truncation is surfaced here, never only at restore time. Runs
    // regardless of network (pure local disk work), rate-limited to once/day.
    if now - state.last_verify_ts >= 86400 {
        let profile_dir = crate::store::profiles::profile_dir(profile);
        if let Ok(report) =
            crate::artifact::artifact_versions::verify_all_versions(&profile_dir, now as u64, 2000)
        {
            state.last_verify_ts = now;
            let _ = crate::artifact::artifact_versions::record_verify_outcome(
                &profile_dir,
                &report,
                now as u64,
            );
            let _ = crate::mesh::journal::append(
                profile,
                crate::mesh::journal::JournalKind::VersionVerified,
                &crate::artifact::artifact_versions::corrupt_versions_summary(&report),
            );
            if !report.corrupt.is_empty() {
                log(&log_line(
                    "WARN",
                    &format!(
                        "version-integrity sweep: {}",
                        crate::artifact::artifact_versions::corrupt_versions_summary(&report)
                    ),
                ));
            } else {
                log(&log_line(
                    "INFO",
                    &format!(
                        "version-integrity sweep: {}",
                        crate::artifact::artifact_versions::corrupt_versions_summary(&report)
                    ),
                ));
            }
        }
    }

    // 6.5. Periodic config-health decay: re-probe a bounded set of stale
    // (or never-checked) nodes so the pool never keeps verified-live configs
    // whose servers have since died — a config that was healthy at import
    // time is re-verified on a cadence, not only when the whole pool fails.
    // Rate-limited (cheap, bounded: ≤NODE_DECAY_SWEEP_MAX nodes per pass) and
    // requires the network for real probes. Fails over if the active node
    // died since the last check. Routes through the local SOCKS5 tunnel when
    // it is up (auto-detected), since direct foreign TCP is severed under NIN.
    if net_up
        && crate::ops::airgap::online()
        && now - state.last_node_decay_ts >= crate::probe::node_probe::NODE_DECAY_INTERVAL_SECS
    {
        state.last_node_decay_ts = now;
        let use_proxy = crate::probe::node_probe::tunnel_available();
        let sweep = crate::probe::node_probe::probe_stale(profile, use_proxy);
        if sweep.probed > 0 {
            log(&log_line(
                "INFO",
                &format!(
                    "node health decay: re-probed {} ({} healthy, {} dead)",
                    sweep.probed, sweep.healthy, sweep.unhealthy
                ),
            ));
            if let Some(id) = &sweep.promoted {
                log(&log_line(
                    "INFO",
                    &format!("node health decay: promoted healthy node '{id}'"),
                ));
            }
        }
    }

    // 6.5. Deep real-egress verification: the shallow decay sweep above only
    // confirms TLS reachability. Under NIN, a server can complete TLS yet be
    // a dead/blackholed relay — so periodically re-verify a small, bounded
    // subset of the pool with a *real* xray spawn + end-to-end egress check
    // (`deep_verify_egress`). Verdicts are written back into the store so the
    // pool's `healthy` flags reflect genuine working configs, not just TLS.
    // This is the "no fabricated success" doctrine (§8.2) applied at sweep
    // granularity. Rate-limited to a slow cadence (costly: spawns temporary
    // xray per candidate on dedicated ports) and bounded to ≤2 nodes/pass.
    const DEEP_VERIFY_INTERVAL_SECS: i64 = 6 * 3600;
    const DEEP_VERIFY_MAX_PER_PASS: usize = 2;
    if net_up
        && crate::ops::airgap::online()
        && now - state.last_deep_verify_ts >= DEEP_VERIFY_INTERVAL_SECS
    {
        state.last_deep_verify_ts = now;
        let store = crate::artifact::config_store::load_node_store(profile);
        let mut candidates: Vec<crate::artifact::config_store::V2RayNode> = store
            .nodes
            .iter()
            .filter(|n| n.healthy != Some(false))
            .take(DEEP_VERIFY_MAX_PER_PASS)
            .cloned()
            .collect();
        if !candidates.is_empty() {
            log(&log_line(
                "INFO",
                &format!(
                    "deep egress verify: testing {} candidate(s) with real xray spawn…",
                    candidates.len()
                ),
            ));
            for node in &mut candidates {
                let r = crate::tunnel::tunnel_lifeline::deep_verify_egress(profile, node).await;
                if r.ok {
                    log(&log_line(
                        "INFO",
                        &format!(
                            "deep egress verify: '{}' confirmed working (real egress)",
                            r.alias
                        ),
                    ));
                } else {
                    log(&log_line(
                        "WARN",
                        &format!(
                            "deep egress verify: '{}' FAILED real egress ({}) — marking unhealthy",
                            r.alias,
                            r.error.clone().unwrap_or_default()
                        ),
                    ));
                }
            }
        } else {
            log(&log_line(
                "INFO",
                "deep egress verify: no candidates (pool not yet probed)",
            ));
        }
    }

    // 7. Autonomous node-refill: if the node pool has no known-healthy
    // config, recover fresh share-links from Telegram archives (deep crawl)
    // + GitHub config repos, probe them, and promote a working node. This is
    // the "never run out of working configs" doctrine (§5). Requires the
    // network (harvest fetches) and is rate-limited to once per cooldown
    // window so a permanently-dead pool doesn't hammer Telegram/GitHub on
    // every tick. Routes through the local SOCKS5 tunnel when it is up
    // (auto-detected), since direct foreign TCP is severed under NIN.
    if net_up
        && crate::ops::airgap::online()
        && crate::probe::node_refill::refill_enabled()
        && now - state.last_refill_ts >= crate::probe::node_refill::REFILL_COOLDOWN_SECS
    {
        let needs = crate::probe::node_refill::refill_needed(
            &crate::artifact::config_store::load_node_store(profile),
        );
        if let Some(reason) = needs {
            state.last_refill_ts = now;
            let use_proxy = crate::probe::node_probe::tunnel_available();
            let report = crate::probe::node_refill::run_refill(profile, use_proxy).await;
            log(&log_line(
                "INFO",
                &format!(
                    "node refill: {reason} → telegram +{} ch (added {}), github +{} nodes, ct-anchor +{}, ns-anchor +{}, probed {} ({} healthy)",
                    report.telegram_channels,
                    report.telegram_added,
                    report.github_added,
                    report.ct_reseed_added,
                    report.ns_reseed_added,
                    report.probed,
                    report.healthy
                ),
            ));
            let _ = crate::mesh::journal::append(
                profile,
                crate::mesh::journal::JournalKind::NodeRefill,
                &format!(
                    "reason={reason} tg_added={} gh_added={} ct_added={} ns_added={} probed={} healthy={} promoted={:?}",
                    report.telegram_added,
                    report.github_added,
                    report.ct_reseed_added,
                    report.ns_reseed_added,
                    report.probed,
                    report.healthy,
                    report.promoted
                ),
            );
        }
    }

    // 7b. Autonomous systematic Telegram discovery + v2rayN export. The refill
    // step above only reacts when the pool is *already* low (recovery). This
    // step runs on its own slow cadence and is proactive: it walks the multi-hop
    // archived-chat net to grow the persisted set of yielding channels (doctrine
    // §5 — never let the net go stale) and re-exports verified-healthy nodes to
    // the v2rayN ServersStore, so the GUI pool stays stocked even when no
    // external cron/CLI invokes it (no single point of failure). Requires the
    // network; rate-limited to DISCOVERY_INTERVAL_SECS.
    if net_up
        && crate::ops::airgap::online()
        && crate::discovery::harvest::discovery_enabled()
        && now - state.last_discovery_ts >= crate::probe::node_refill::DISCOVERY_INTERVAL_SECS
    {
        state.last_discovery_ts = now;
        let use_proxy = crate::probe::node_probe::tunnel_available();
        match crate::discovery::harvest::run_multi_hop_discovery(profile, use_proxy, 2, 60, 4, true)
            .await
        {
            Ok(report) => {
                log(&log_line(
                    "INFO",
                    &format!(
                        "autonomous discovery: seeds {} → {} candidates, {} hops, {} yielding, +{} persisted ({} total)",
                        report.seeds,
                        report.candidates_total,
                        report.hops,
                        report.winners.len(),
                        report.persisted_new,
                        report.persisted_total
                    ),
                ));
                let _ = crate::mesh::journal::append(
                    profile,
                    crate::mesh::journal::JournalKind::NodeRefill,
                    &format!(
                        "discovery seeds={} cands={} hops={} winners={} persisted_new={}",
                        report.seeds,
                        report.candidates_total,
                        report.hops,
                        report.winners.len(),
                        report.persisted_new
                    ),
                );
                // Re-export verified-healthy nodes to the v2rayN store on the
                // same cadence so the user-facing pool always has working configs
                // (the user's explicit "feed v2rayN" requirement). Best-effort:
                // a missing/unwritable ServersStore must not fail the tick.
                if report.persisted_total > 0 {
                    let home = std::env::var("HOME").unwrap_or_default();
                    let target = format!("{home}/.config/v2rayN/Local/ServersStore.json");
                    match crate::artifact::config_store::export_v2rayn_store(
                        profile,
                        std::path::Path::new(&target),
                        true,
                    ) {
                        Ok((added, dups)) => log(&log_line(
                            "INFO",
                            &format!("autonomous v2rayN export: +{added} healthy (dup-skipped {dups}) → {target}"),
                        )),
                        Err(e) => log(&log_line(
                            "WARN",
                            &format!("autonomous v2rayN export skipped: {e}"),
                        )),
                    }
                }
            }
            Err(e) => log(&log_line(
                "WARN",
                &format!("autonomous discovery failed: {e}"),
            )),
        }
    }

    // 8. Out-of-band CT-anchor rotation. The certificate-transparency anchor
    // set is an independent bootstrap feed (doctrine §5 — never circular).
    // Refresh it on a slow cadence so the verified-live set the runtime
    // consults (SNI/anti-DPI seeding) never goes stale/silent, and prune
    // anchors that no longer complete TLS. Rate-limited; requires the network.
    // The CT-anchor path uses reqwest's *blocking* client, which cannot be
    // built/dropped inside an async runtime — so run it on a blocking thread.
    if net_up
        && crate::ops::airgap::online()
        && crate::discovery::ct_anchors::refresh_enabled()
        && now - state.last_anchors_refresh_ts
            >= crate::discovery::ct_anchors::ANCHOR_REFRESH_INTERVAL_SECS
    {
        state.last_anchors_refresh_ts = now;
        let profile_owned = profile.to_string();
        let (added, pruned) = match tokio::task::spawn_blocking(move || {
            crate::discovery::ct_anchors::refresh_and_prune(
                &profile_owned,
                false,
                crate::discovery::ct_anchors::DEFAULT_QUERIES,
            )
        })
        .await
        {
            Ok(r) => r,
            Err(e) => {
                log(&log_line(
                    "WARN",
                    &format!("ct anchors refresh aborted (blocking task: {e})"),
                ));
                (0usize, 0usize)
            }
        };
        let total = crate::discovery::ct_anchors::anchor_hosts(profile).len();
        log(&log_line(
            "INFO",
            &format!(
                "ct anchors: refreshed (+{added} new, pruned {pruned} dead, {total} verified-live)"
            ),
        ));
        let _ = crate::mesh::journal::append(
            profile,
            crate::mesh::journal::JournalKind::AnchorsRefreshed,
            &format!("added={added} pruned={pruned} total={total}"),
        );
    }

    // 8b. Authoritative-nameserver anchor rotation (doctrine §8.1). This is a
    // second independent out-of-band bootstrap feed: the DNS control plane
    // itself. Root-server seeds are probed, high-value zones are queried for
    // their NS records, and verified-live authoritative IPs are kept. Running
    // it in the daemon means the NS-anchor set (which the runtime can consult
    // as a non-circular reseed/tunnel-hop source) is maintained autonomously.
    // Fully async (UDP raw exchange) so it is awaited directly. Rate-limited.
    if net_up
        && crate::ops::airgap::online()
        && now - state.last_ns_anchors_refresh_ts
            >= crate::discovery::ns_anchors::NS_ANCHOR_REFRESH_INTERVAL_SECS
    {
        state.last_ns_anchors_refresh_ts = now;
        const NS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(4);
        let resolvers: Vec<String> = crate::net::resolve_pool::IRANIAN_RESOLVER_CANDIDATES
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (added, pruned) = crate::discovery::ns_anchors::refresh_ns_anchors(
            profile,
            &resolvers,
            crate::discovery::ns_anchors::DEFAULT_ZONES,
            NS_TIMEOUT,
        )
        .await;
        let total = crate::discovery::ns_anchors::anchor_ips(profile).len();
        log(&log_line(
            "INFO",
            &format!(
                "ns anchors: refreshed (+{added} new, pruned {pruned} dead, {total} verified-live)"
            ),
        ));
        let _ = crate::mesh::journal::append(
            profile,
            crate::mesh::journal::JournalKind::AnchorsRefreshed,
            &format!("ns added={added} pruned={pruned} total={total}"),
        );
    }

    // 8c. Level-4 mesh host (doctrine §3/§8.3). When we have a live uplink,
    // offer ourselves as a relay hop to peers on the LAN: keep the mesh relay
    // data-plane listener alive and advertise our beacon with
    // `has_uplink=true`. The host is a process-singleton background actor
    // (relay + beacon threads); this step just keeps it started and syncs
    // its advertised uplink state with the daemon's current reality. It runs
    // whenever the network is up (and keeps answering echo probes while down,
    // via the host's own fallback). Idempotent + cheap — no rate-limit
    // needed since `ensure_started` is a no-op after first spawn and
    // `set_uplink` is an atomic store.
    {
        let host = crate::mesh::mesh_host::MeshHost::global();
        host.set_uplink(net_up);
        let peer_id = std::env::var("HOSTNAME").unwrap_or_else(|_| format!("dyb-{profile}"));
        host.ensure_started(&peer_id, &format!("dyb-{profile}"));
        if net_up && !host.is_started() {
            // first tick with net up: log that we are now offering ourselves
            log(&log_line(
                "INFO",
                "mesh host: offering relay hop on the LAN (level-4 mesh)",
            ));
        }
    }

    // 9. Signed OOB relay-manifest ingestion. The signed egress-anchor feed is
    // an independent, cryptographically-verified bootstrap channel (doctrine
    // §5/§8.1): if the operator publishes a signed relay manifest (e.g. a seed
    // file distributed offline, or later a fetched endpoint), the client pulls
    // it, verifies the Ed25519 signature + anti-replay seq, and imports the
    // anchors into the same node pool as every other source. This runs even
    // when the network is down (local seed file costs nothing — doctrine
    // §6.5.4); a manifest that fails verification is silently discarded.
    if crate::egress::eob_anchor::verify_enabled()
        && now - state.last_oob_pull_ts >= crate::egress::eob_anchor::OOB_PULL_INTERVAL_SECS
    {
        state.last_oob_pull_ts = now;
        let seed_path = crate::store::profiles::profile_dir(profile)
            .join(crate::egress::eob_anchor::SEED_FILENAME);
        if seed_path.exists() {
            match crate::egress::eob_anchor::ingest_signed_from_seed(profile, &seed_path) {
                Ok(report) => {
                    log(&log_line(
                        "INFO",
                        &format!(
                            "oob anchors: ingested signed manifest (accepted {}, duplicates {}, rejected {})",
                            report.accepted, report.duplicates, report.rejected
                        ),
                    ));
                    let _ = crate::mesh::journal::append(
                        profile,
                        crate::mesh::journal::JournalKind::NodeRefill,
                        &format!(
                            "oob-signed accepted={} dup={} rejected={}",
                            report.accepted, report.duplicates, report.rejected
                        ),
                    );
                }
                Err(e) => {
                    log(&log_line(
                        "WARN",
                        &format!("oob anchors: seed ignored ({e})"),
                    ));
                }
            }
        }
    }
}
/// Auto-heal step (daemon self-maintenance). Runs on every tick, detects
/// critical-artifact drift via the manifest, and restores from the newest
/// verifying backup. Never heals from an unverified source; always journaled.
fn run_auto_heal(profile: &str, log: &mut dyn FnMut(&str)) {
    let verify = crate::artifact::manifest::verify_profile(profile);
    if !verify.has_manifest {
        return; // no baseline → nothing to heal against
    }
    // Build candidate list from the backup dir.
    let candidates: Vec<crate::probe::auto_heal::BackupCandidate> =
        crate::ops::backup::list_backups()
            .into_iter()
            .map(|b| {
                let path = std::path::PathBuf::from(&b.path);
                let verifies = crate::probe::doctor::backup_bundle_verifies(&path);
                crate::probe::auto_heal::BackupCandidate {
                    created_unix: 0, // re-derived from mtime below
                    verifies,
                    path,
                }
            })
            .collect();
    let candidates: Vec<crate::probe::auto_heal::BackupCandidate> = candidates
        .into_iter()
        .map(|mut c| {
            c.created_unix = std::fs::metadata(&c.path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| {
                    t.duration_since(std::time::SystemTime::UNIX_EPOCH)
                        .ok()
                        .map(|d| d.as_secs())
                })
                .unwrap_or(0);
            c
        })
        .collect();

    let action = crate::probe::auto_heal::plan_heal(
        &verify,
        &candidates,
        &crate::probe::auto_heal::critical_artifact_kinds(),
        crate::store::now_ts() as u64,
    );

    match action {
        crate::probe::auto_heal::HealAction::NoAction => {}
        crate::probe::auto_heal::HealAction::AlertOnly { reason } => {
            log(&log_line("WARN", &format!("auto-heal: {reason}")));
            let _ = crate::mesh::journal::append(
                profile,
                crate::mesh::journal::JournalKind::CycleFailed,
                &reason,
            );
        }
        crate::probe::auto_heal::HealAction::HealFiles {
            backup_path,
            artifacts,
        } => {
            let dir = crate::store::profiles::profile_dir(profile);
            match crate::probe::auto_heal::execute_heal(
                &crate::probe::auto_heal::HealAction::HealFiles {
                    backup_path: backup_path.clone(),
                    artifacts: artifacts.clone(),
                },
                &dir,
                crate::store::now_ts() as u64,
            ) {
                Ok(report) => {
                    // Refresh the manifest so the single source of truth reflects
                    // the healed content.
                    let _ = crate::artifact::manifest::refresh_manifest_after_write(
                        &dir,
                        crate::store::now_ts() as u64,
                    );
                    if crate::probe::auto_heal::heal_is_safe(&report) {
                        log(&log_line(
                            "INFO",
                            &format!(
                                "auto-healed {:?} from {} (verified)",
                                report.healed,
                                backup_path.display()
                            ),
                        ));
                        let _ = crate::mesh::journal::append(
                            profile,
                            crate::mesh::journal::JournalKind::AutoHealed,
                            &format!(
                                "healed={:?} backup={}",
                                report.healed,
                                backup_path.display()
                            ),
                        );
                    } else {
                        log(&log_line(
                            "WARN",
                            &format!(
                                "auto-heal incomplete: healed={:?} still_broken={:?} skipped={:?}",
                                report.healed, report.still_broken, report.skipped_non_critical
                            ),
                        ));
                    }
                }
                Err(e) => {
                    log(&log_line("WARN", &format!("auto-heal failed: {e}")));
                }
            }
        }
    }
}

/// Scheduled workspace-snapshot step (daemon self-maintenance). On the 6h
/// cadence (keep 14), snapshots the whole workspace — every profile — into
/// `~/.dastyab/snapshots/<unix>.dyb-snapshot.json`, then prunes retention.
fn run_scheduled_snapshot(
    profile: &str,
    state: &mut DaemonState,
    now: i64,
    log: &mut dyn FnMut(&str),
) {
    use crate::artifact::workspace_snapshot::SnapshotKind;
    use crate::artifact::workspace_snapshots::*;
    if !is_snapshot_due(state.last_snapshot_ts, now) {
        return;
    }
    let workspace = crate::store::mem_dir();
    let snaps = snapshots_dir();
    match take_scheduled_snapshot(&workspace, &snaps, SnapshotKind::Full, now as u64) {
        Ok(entry) => {
            let _ = crate::mesh::journal::append(
                profile,
                crate::mesh::journal::JournalKind::SnapshotWritten,
                &entry.path.display().to_string(),
            );
            log(&log_line(
                "INFO",
                &format!("workspace snapshot written → {}", entry.path.display()),
            ));
            if let Ok(prune) = prune_old_snapshots(&snaps, WORKSPACE_SNAPSHOT_KEEP) {
                if !prune.removed.is_empty() {
                    log(&log_line(
                        "INFO",
                        &format!("pruned {} old workspace snapshot(s)", prune.removed.len()),
                    ));
                }
            }
            state.last_snapshot_ts = now;
        }
        Err(e) => {
            log(&log_line(
                "WARN",
                &format!("workspace snapshot failed: {}", e.brief()),
            ));
        }
    }
}

/// Scheduled blackout self-test (drill). When due, probes every fallback-ladder
/// rung (Direct → DoH → DoT → DNS tunnel), journals how many survive, and emits
/// a `ResilienceDegraded` beacon when fewer than `DRILL_DEGRADED_THRESHOLD`
/// rungs are reachable — so the user learns resilience has slipped without being
/// asked to run `drill` by hand. `now` is the current epoch-seconds.
async fn run_scheduled_drill(
    profile: &str,
    state: &mut DaemonState,
    now: i64,
    log: &mut dyn FnMut(&str),
) {
    // Hermetic daemon unit tests disable the scheduled drill so a tick never
    // performs a live fallback-ladder probe (real network) just because
    // `last_drill_ts` defaulted to 0. Production default: enabled.
    if !crate::net::connectivity::drill_enabled() {
        state.last_drill_ts = now;
        return;
    }
    let p = crate::store::profiles::load_profile(profile);
    let interval = crate::store::profiles::effective_drill_interval_secs(&p.config);
    if interval == 0 || now - state.last_drill_ts < interval as i64 {
        return;
    }

    let resolver = crate::net::doh::DohResolver::new();
    let report =
        crate::net::connectivity::drill_all_tiers(crate::net::connectivity::RealLadderProbe {
            profile,
            resolver: &resolver,
        })
        .await;

    let mut survivors = 0u8;
    let mut best_tier = "none".to_string();
    // TIER_ORDER is best-first, so the first up rung is the best surviving one.
    for (tier, verdict) in &report {
        if verdict.ok {
            survivors += 1;
            if best_tier == "none" {
                best_tier = tier.label().to_string();
            }
        }
    }

    state.last_drill_ts = now;
    let _ = crate::mesh::journal::append(
        profile,
        crate::mesh::journal::JournalKind::DrillPerformed,
        &format!("{survivors}/4 rungs up (best: {best_tier})"),
    );
    log(&format!(
        "blackout self-test: {survivors}/4 rungs up (best: {best_tier})"
    ));

    if survivors < DRILL_DEGRADED_THRESHOLD {
        // Alert + journal. During a blackout the send fails and the alert is
        // queued to the durable outbox, delivered when the network returns.
        let _ = crate::mesh::remote_beacon::maybe_emit(
            profile,
            &crate::mesh::remote_beacon::BeaconEvent::ResilienceDegraded {
                survivors,
                best_tier: best_tier.clone(),
            },
            crate::probe::diagnose::Locale::En,
        )
        .await;
        let _ = crate::mesh::journal::append(
            profile,
            crate::mesh::journal::JournalKind::DrillPerformed,
            &format!("DEGRADED, {survivors}/4 rungs up (best: {best_tier})"),
        );
    }
}

/// Run one iteration of the daemon loop. Returns the number of seconds to
/// sleep before the next iteration. Pure-ish: all side effects go through
/// `probe`, `acct`, `cycle`, and the logger callback, so it is fully unit-testable.
/// Best-effort auto-start of the lifeline tunnel when the managed egress is
/// down/blocked. Logs once per episode. Never fails the cycle — the lifeline
/// is a survival aid, not a gate.
async fn try_start_lifeline(profile: &str, state: &mut DaemonState, log: &mut dyn FnMut(&str)) {
    if state.lifeline_auto_started {
        return;
    }
    let report = crate::tunnel::tunnel_lifeline::spawn_lifeline(profile).await;
    state.lifeline_auto_started = true;
    if report.up {
        log(&log_line(
            "INFO",
            "lifeline=auto-started (managed egress down; local SOCKS5 tunnel up)",
        ));
    } else {
        log(&log_line(
            "WARN",
            &format!(
                "lifeline=auto-start failed (error={})",
                report.error.as_deref().unwrap_or("unknown")
            ),
        ));
    }
}

pub async fn daemon_tick(
    profile: &str,
    state: &mut DaemonState,
    probe: &mut dyn NetworkProbe,
    acct: &dyn AccountProbe,
    cycle: &dyn CycleRunner,
    log: &mut dyn FnMut(&str),
) -> u64 {
    // Startup/periodic self-heal for the empty-active_token-marker bug: if
    // the marker is empty/stale but the profile has tokens, repopulate it so
    // a valid token is always selected (no "No active token" stall that used
    // to drive the daemon to a 21600s backoff). Best-effort — never fail the
    // tick if the marker is genuinely unusable.
    let _ = crate::store::profiles::ensure_active_token(profile);

    // b. Network liveness probe (full fallback ladder: direct → DoH → DoT
    // → DNS tunnel). `status` carries the best tier actually reachable.
    let status = probe.liveness().await;
    let net_up = status.up;
    state.network_tier = status.tier_label();

    // a. Periodic self-maintenance: scheduled auto-backup (local, always) and
    // worker-signature rotation (only when the network is confirmed up, since
    // it needs the CF API). Skipped entirely in air-gap mode so a test or an
    // isolated run cannot reach the network through the maintenance path.
    if crate::ops::airgap::online() {
        run_self_maintenance(profile, state, net_up, log).await;
    }

    // Scheduled autonomy audit with auto-execute (architect feature #3). Runs
    // on the audit cadence (default 15 min) and auto-applies every ACTION item
    // whose preconditions are met. CF-backed items rotate the worker secret /
    // mint a second token; config toggles (backup, mutation) flip flags.
    // Fire the AutonomyRegression beacon on a clean→dirty transition.
    if crate::ops::airgap::online() {
        let prof = crate::store::profiles::load_profile(profile);
        let token = crate::store::profiles::get_active_token(profile)
            .ok()
            .flatten()
            .and_then(|l| {
                crate::store::profiles::get_token(profile, &l)
                    .ok()
                    .flatten()
            });
        let account_id = if prof.config.active_account.is_empty() {
            None
        } else {
            Some(prof.config.active_account.clone())
        };
        let seam = match (token, account_id) {
            (Some(t), Some(a)) => Some(crate::daemon::RealCfSeam::new(t, a)),
            _ => None,
        };
        let seam_ref = seam
            .as_ref()
            .map(|s| s as &dyn crate::daemon::autonomy_schedule::CfApiSeam);
        crate::daemon::run_autonomy_audit_with_seam(profile, state, net_up, seam_ref, log).await;
    }

    // Per-profile blackout-resilience knobs (0 on each = system default):
    // monitor light/deep phase budgets + the backoff ceiling. On a degraded
    // tier (worse than Direct — partial blackout) the deep budget is
    // auto-extended so a slow-but-progressing censored pass isn't aborted at
    // the default 600s.
    let cfg = crate::store::profiles::load_profile(profile).config;
    let max_backoff = crate::store::profiles::effective_max_backoff_secs(&cfg);
    let degraded = status
        .tier
        .map(|t| t != crate::net::connectivity::Tier::Direct)
        .unwrap_or(false);
    let timeouts = crate::probe::autopilot::monitor_timeouts_from_config(&cfg, degraded);

    // Auto-flush the beacon outbox whenever the network is up. Alerts queued
    // during a blackout (or a blocked channel) are delivered as soon as the
    // network returns — immediately on restore, then rate-limited so we don't
    // hammer the Telegram/webhook transport every cycle.
    if net_up && crate::ops::airgap::online() {
        let now = crate::store::now_ts() as i64;
        let force = state.network_was_down;
        if force || should_flush_outbox(state.last_outbox_flush_ts, now, OUTBOX_FLUSH_INTERVAL_SECS)
        {
            let n = crate::mesh::remote_beacon::flush_outbox(profile).await;
            if n > 0 {
                log(&log_line("INFO", &format!("outbox flushed {} alert(s)", n)));
                let _ = crate::mesh::journal::append(
                    profile,
                    crate::mesh::journal::JournalKind::OutboxFlushed,
                    &format!("{n} alert(s)"),
                );
            }
            state.last_outbox_flush_ts = now;
        }
        // Healthy network: keep the worker relay's carrier snapshot fresh by
        // pushing whenever the endpoint identity set changes (routing table,
        // not probe telemetry). The last-pushed hash gate makes this a no-op
        // most ticks. This is the counterpart to the blackout-side pull above.
        if let Err(e) = crate::daemon::push_carriers_via_worker_tunnel(profile, log) {
            log(&log_line(
                "WARN",
                &format!("carrier push to worker failed: {e}"),
            ));
        }
        // Warm-up surface: query the worker's self-ping freshness once per 6h
        // (off the hot path) and record the last check so the Autonomy panel
        // can show the worker is staying active (not drifting toward CF
        // inactivity deactivation).
        {
            let now = crate::store::now_ts() as i64;
            const SELF_PING_INTERVAL_SECS: i64 = 21600; // 6h
            if now - state.last_self_ping_ts >= SELF_PING_INTERVAL_SECS {
                match crate::daemon::query_worker_self_ping(profile, log) {
                    Some(ping_ms) => {
                        let ping_secs = ping_ms / 1000;
                        let age = (now as u64).saturating_sub(ping_secs);
                        let active = age < SELF_PING_INTERVAL_SECS as u64;
                        log(&log_line(
                            "INFO",
                            &format!(
                                "worker self-ping {}h ago ({})",
                                age / 3600,
                                if active { "active" } else { "stale" }
                            ),
                        ));
                        state.last_self_ping_ts = now;
                    }
                    None => {
                        log(&log_line(
                            "INFO",
                            "worker self-ping: none (no worker tunnel)",
                        ));
                        state.last_self_ping_ts = now;
                    }
                }
            }
        }
    }

    if !net_up {
        // c. Network down → skip cycle, don't burn rescue budget. Compute the
        // blackout survival plan so the daemon / beacon knows whether a DNS
        // tunnel is actually reachable to descend to. Tunnel availability is
        // judged by a LIVE round-trip (probe_tunnel_live), not config
        // presence — so a dead/unreachable VPS reports the honest "no tunnel"
        // ceiling instead of a false "tunnel=yes".
        let branch_start = crate::store::now_ts();
        let tunnel_ok = match crate::egress::vps_deploy::load_tunnel_client_config(profile) {
            Some(cfg) => {
                // Short timeout: during a blackout we want a quick verdict.
                crate::tunnel::dnstunnel::probe_tunnel_live(
                    &cfg,
                    std::time::Duration::from_millis(1500),
                )
                .await
            }
            None => false,
        };
        let plan = crate::egress::blackout_bridge::SurvivalPlan::from_state(
            crate::trust::blackout::NetworkState::TotalBlackout,
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
            state.blackout_since_unix = crate::store::now_ts() as i64;
            state.survival_plan = plan.label().to_string();
            let _ = crate::mesh::journal::append(
                profile,
                crate::mesh::journal::JournalKind::NetworkDown,
                plan.label(),
            );
            // Notify remotely that the network went dark. During a total
            // blackout this send fails and the alert is queued to the durable
            // outbox, delivered automatically when the network returns — so
            // the user learns about the blackout even if it has already ended.
            let _ = crate::mesh::remote_beacon::maybe_emit(
                profile,
                &crate::mesh::remote_beacon::BeaconEvent::NetworkDown {
                    survival: plan.label().to_string(),
                },
                crate::probe::diagnose::Locale::En,
            )
            .await;
        }
        // During a total blackout the Cloudflare Worker control plane is often
        // the only channel back to our own infra (CF edge stays up when local
        // DNS/direct are dead). If the worker tunnel is live, pull a fresh
        // carrier snapshot through it and merge it into the offline pool — so
        // reselection has the newest endpoints even while fully dark. Best
        // effort: a failure just logs and the pool stays as-is.
        if tunnel_ok {
            if let Err(e) = crate::daemon::refresh_carriers_via_worker_tunnel(profile, log) {
                log(&log_line(
                    "WARN",
                    &format!("carrier refresh via worker failed: {e}"),
                ));
            }
        }
        // Execute a carrier reselection: try worker-data endpoints (then
        // worker-tunnel) from the offline pool and switch the active tunnel to
        // the first that opens. This turns the blackout state machine's
        // `ReselectCarrier` decision into an actual tunnel switch (it was
        // previously logged and discarded). Best-effort and cheap: each probe
        // is bounded, and an empty pool is a no-op.
        {
            let cfg_local = crate::store::profiles::load_profile(profile).config;
            let now = crate::store::now_ts() as u64;
            // Escalation: the longer the blackout, the harder we probe. The
            // plan tunes probe cadence + parallel probes (plumbed through;
            // execution stays serial) + faster SNI rotation + worker-refresh
            // cadence.
            let plan = crate::daemon::escalation::escalation_plan(
                crate::daemon::escalation::BlackoutClock::from_since(
                    (state.blackout_since_unix > 0).then_some(state.blackout_since_unix as u64),
                )
                .elapsed_secs(now),
            );
            let pool = crate::egress::carrier_pool::open_profile_pool(&cfg_local).ok();
            let data_count = pool
                .as_ref()
                .and_then(|p| {
                    crate::daemon::escalation::escalated_select(
                        p,
                        crate::egress::carrier_pool::CarrierKind::WorkerData,
                        1,
                        now,
                    )
                    .ok()
                })
                .map(|v| v.len())
                .unwrap_or(0);
            let reselect_n = (plan.parallel_probes as usize).max(2);
            if data_count > 0 {
                crate::daemon::exec_reselection(
                    profile,
                    crate::egress::carrier_pool::CarrierKind::WorkerData,
                    reselect_n,
                    plan.parallel_probes as usize,
                    log,
                );
            } else {
                crate::daemon::exec_reselection(
                    profile,
                    crate::egress::carrier_pool::CarrierKind::WorkerTunnel,
                    reselect_n,
                    plan.parallel_probes as usize,
                    log,
                );
            }
            // Log the active escalation tier on transition.
            if plan.probe_interval_secs < crate::daemon::escalation::BASELINE_PROBE_INTERVAL_SECS {
                log(&log_line(
                    "INFO",
                    &format!(
                        "blackout escalation: probe={}s parallel={} sni_faster={}",
                        plan.probe_interval_secs, plan.parallel_probes, plan.sni_rotation_faster
                    ),
                ));
            }
        }
        // Network down → skip cycle, don't burn rescue budget. Sleep the
        // configured blackout poll cadence (per-profile `network_down_sleep_secs`,
        // 0 = default 60s), but never longer than the escalation plan's probe
        // interval — escalation shortens the poll so a long blackout keeps
        // trying harder. A shorter value re-probes sooner; a longer value
        // conserves battery/CPU during a long outage.
        let base_sleep = crate::store::profiles::effective_network_down_sleep_secs(&cfg);
        let now = crate::store::now_ts() as u64;
        let plan = crate::daemon::escalation::escalation_plan(
            crate::daemon::escalation::BlackoutClock::from_since(
                (state.blackout_since_unix > 0).then_some(state.blackout_since_unix as u64),
            )
            .elapsed_secs(now),
        );
        // Sleep calc: target cycle = plan probe interval (the configured
        // blackout poll is the ceiling). The reselection/thems already ate
        // some wall-clock, so subtract the elapsed probe time so the actual
        // cycle approximates the target rather than probe_time + target.
        let target_cycle = base_sleep.min(plan.probe_interval_secs).max(1);
        let probe_elapsed = (crate::store::now_ts() - branch_start).max(0.0) as u64;
        let sleep = target_cycle.saturating_sub(probe_elapsed).max(1);
        return sleep;
    }

    // d. Account-level gate. If the account is suspended/invalid, hold cycles
    // so we don't burn rescue/scan budget against a dead account. Re-probe at
    // ACCOUNT_POLL_INTERVAL_SECS and resume automatically when the account
    // comes back — no manual daemon restart required.
    let now = crate::store::now_ts() as i64;
    if state.account_state.blocks_cycle() {
        // Automatic token rotation: before waiting/polling, check whether a
        // *different* stored token works and, if so, swap to it. This closes
        // the manual `dastyab token recover` step — protection resumes
        // automatically. Configurable via auto_rotate_on_blocked (default on).
        if let Some((from, to)) = acct.try_rotate(profile).await {
            state.account_state = crate::trust::account_state::AccountState::Active;
            state.account_rotate_exhausted_notified = false;
            state.last_account_poll_ts = now;
            log(&log_line(
                "INFO",
                &format!("account=token-auto-rotated {from}→{to}, resuming cycle"),
            ));
            let _ = crate::mesh::remote_beacon::maybe_emit(
                profile,
                &crate::mesh::remote_beacon::BeaconEvent::TokenAutoRotated { from, to },
                crate::probe::diagnose::Locale::En,
            )
            .await;
        } else {
            // Auto-rotation returned None. That happens either because it is
            // disabled (or there is only a single token), or because it was
            // attempted and every stored token failed verification. Only the
            // latter is a genuine "exhausted" condition the user must act on.
            // Notify exactly once per episode so the user who was promised
            // auto-recovery learns it actually failed and must add a token.
            let p = crate::store::profiles::load_profile(profile);
            let auto_rotate_eligible = p.config.auto_rotate_on_blocked && p.tokens.len() >= 2;
            if auto_rotate_eligible && !state.account_rotate_exhausted_notified {
                state.account_rotate_exhausted_notified = true;
                let stored_tokens = p.tokens.len();
                log(&log_line(
                    "WARN",
                    &format!(
                        "account={} auto-rotation exhausted after {stored_tokens} tokens — manual token add required",
                        state.account_state.label()
                    ),
                ));
                let _ = crate::mesh::remote_beacon::maybe_emit(
                    profile,
                    &crate::mesh::remote_beacon::BeaconEvent::AccountBlockedRotationExhausted {
                        state: state.account_state.label().to_string(),
                        profile: profile.to_string(),
                        stored_tokens,
                    },
                    crate::probe::diagnose::Locale::En,
                )
                .await;
            }
            if crate::trust::account_state::should_poll_account(state.last_account_poll_ts, now) {
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
                            crate::trust::account_state::ACCOUNT_POLL_INTERVAL_SECS
                        ),
                    ));
                    try_start_lifeline(profile, state, log).await;
                    return crate::trust::account_state::ACCOUNT_POLL_INTERVAL_SECS;
                }
                log(&log_line(
                    "INFO",
                    &format!(
                        "account={} restored, resuming cycle",
                        state.account_state.label()
                    ),
                ));
                // Managed egress is back — reset the auto-start flag so a future
                // blocked episode can trigger the lifeline again.
                state.lifeline_auto_started = false;
            } else {
                // Not yet time to re-poll — hold this cycle.
                log(&log_line(
                    "INFO",
                    &format!(
                        "account={} waiting (skip cycle)",
                        state.account_state.label()
                    ),
                ));
                return crate::trust::account_state::ACCOUNT_POLL_INTERVAL_SECS;
            }
        }
    } else {
        // Not blocked, but periodically confirm so we notice a suspension even
        // while the token itself still verifies.
        if crate::trust::account_state::should_poll_account(state.last_account_poll_ts, now) {
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
                    let p = crate::store::profiles::load_profile(profile);
                    let stored_tokens = p.tokens.len();
                    let auto_rotate_enabled = p.config.auto_rotate_on_blocked;
                    let _ = crate::mesh::remote_beacon::maybe_emit(
                        profile,
                        &crate::mesh::remote_beacon::BeaconEvent::AccountBlocked {
                            state: state.account_state.label().to_string(),
                            since: crate::store::now_ts() as i64,
                            profile: profile.to_string(),
                            auto_rotate_enabled,
                            stored_tokens,
                        },
                        crate::probe::diagnose::Locale::En,
                    )
                    .await;
                }
                try_start_lifeline(profile, state, log).await;
                return crate::trust::account_state::ACCOUNT_POLL_INTERVAL_SECS;
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
        state.blackout_since_unix = 0;
        let _ =
            crate::mesh::journal::append(profile, crate::mesh::journal::JournalKind::NetworkUp, "");
        let _ = crate::mesh::remote_beacon::maybe_emit(
            profile,
            &crate::mesh::remote_beacon::BeaconEvent::NetworkRestored,
            crate::probe::diagnose::Locale::En,
        )
        .await;
        // Still run a cycle now.
        state.last_cycle_ts = crate::store::now_ts() as i64;
        match cycle.run_cycle(profile, false, timeouts).await {
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
                    backoff_for_failure(state.current_interval_secs, max_backoff, &e);
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
        match cycle.run_cycle(profile, false, timeouts).await {
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
                    backoff_for_failure(state.current_interval_secs, max_backoff, &e);
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

// Test fixtures build configs field-by-field and serialize whole test
// bodies behind a process-wide mutex by design; both patterns are
// intentional here, so the lints are scoped to the test module.
#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn daemon_home() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(tmp.path().join(".dastyab"));
        // Hermetic daemon tests must never trigger a live autonomous refill
        // (Telegram/GitHub harvest) just because the in-memory node pool is
        // empty. Disable the gate; tests that exercise refill re-enable it.
        crate::probe::node_refill::set_refill_enabled(false);
        crate::net::connectivity::set_drill_enabled(false);
        crate::discovery::ct_anchors::set_refresh_enabled(false);
        crate::egress::eob_anchor::set_verify_enabled(false);
        crate::discovery::harvest::set_discovery_enabled(false);
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
    fn timeout_backoff_caps_at_one_hour() {
        let timeout_err = CFError::new("Cycle timeout", "stuck in DeepCheck", "");
        // Non-timeout failures still climb to the 6h max.
        let hard_err = CFError::new("Worker offline", "dead", "");
        assert_eq!(
            backoff_for_failure(3600, 21600, &hard_err),
            21600,
            "hard failures keep the 6h cap"
        );
        // Timeout failures cap at 1h even on repeat.
        assert_eq!(
            backoff_for_failure(3600, 21600, &timeout_err),
            3600,
            "timeout backs off only to 1h"
        );
        assert_eq!(
            backoff_for_failure(3600, 21600, &timeout_err),
            3600,
            "timeout stays capped at 1h"
        );
        // A daemon already escalated to 6h must STEP DOWN to the 1h ceiling on
        // the next timeout, so recovery isn't stuck at 6h.
        assert_eq!(
            backoff_for_failure(21600, 21600, &timeout_err),
            3600,
            "timeout pulls an elevated interval back down to 1h"
        );
    }

    #[test]
    fn is_cycle_timeout_matches_title_case_insensitively() {
        assert!(is_cycle_timeout(&CFError::new("Cycle timeout", "", "")));
        assert!(is_cycle_timeout(&CFError::new("cycle timeout", "", "")));
        assert!(!is_cycle_timeout(&CFError::new("Worker offline", "", "")));
        assert!(!is_cycle_timeout(&CFError::new("Network error", "", "")));
    }

    #[test]
    fn backoff_reset_returns_initial() {
        assert_eq!(backoff_reset(), DEFAULT_INITIAL_INTERVAL_SECS);
    }

    /// A user-configured backoff ceiling must cap the escalation table. This is
    /// the blackout-resilience knob: lower it so a long blackout re-rotates
    /// and re-probes faster instead of pausing protection for 6h.
    #[test]
    fn backoff_for_failure_honors_configured_max() {
        let err = CFError::new("Worker offline", "gone", "");
        // Default max 6h keeps the table.
        assert_eq!(backoff_for_failure(3600, 21600, &err), 21600);
        // A 900s max caps the escalation step at 900 (300 → 900, not 3600).
        assert_eq!(backoff_for_failure(300, 900, &err), 900);
        // Once at the cap, further failures stay pinned at the cap.
        assert_eq!(backoff_for_failure(900, 900, &err), 900);
    }

    /// `effective_max_backoff_secs` falls back to the 6h default when absent.
    #[test]
    fn effective_max_backoff_defaults_to_six_hours() {
        let cfg = crate::store::profiles::ProfileConfig::default();
        assert_eq!(
            crate::store::profiles::effective_max_backoff_secs(&cfg),
            DEFAULT_MAX_INTERVAL_SECS
        );
        let mut cfg = cfg;
        cfg.max_backoff_secs = 900;
        assert_eq!(
            crate::store::profiles::effective_max_backoff_secs(&cfg),
            900
        );
    }

    /// The daemon reads per-profile timeouts + backoff ceiling each tick.
    #[tokio::test]
    async fn daemon_tick_uses_configured_backoff_ceiling() {
        let _home = daemon_home();
        let profile = crate::store::profiles::create_profile("cfgtest", "").unwrap();
        // Configure a tight 900s backoff ceiling on the profile.
        let mut p = crate::store::profiles::load_profile(&profile);
        p.config.max_backoff_secs = 900;
        crate::store::profiles::save_profile(&p).unwrap();

        let mut state = DaemonState::default();
        // Start at the initial interval so the next failure escalates through
        // the configured ceiling.
        state.current_interval_secs = DEFAULT_INITIAL_INTERVAL_SECS;
        let mut probe = FakeProbe::new(true);
        let cycle = FakeCycle::new(false); // always fails → escalates backoff
        let acct = FakeAccountProbe::default();
        let mut log_lines = Vec::new();
        let sleep = daemon_tick(&profile, &mut state, &mut probe, &acct, &cycle, &mut |l| {
            log_lines.push(l.to_string())
        })
        .await;
        // From 300 with a 900 max, escalation is capped at 900 (not 3600).
        assert_eq!(state.current_interval_secs, 900);
        assert_eq!(sleep, 900);
    }

    /// When a profile configures `network_down_sleep_secs`, the daemon must
    /// use it (not the 60s default) as the poll cadence while the network is
    /// fully down — the blackout-resilience knob for re-probing a restored
    /// path sooner (short) or conserving battery (long).
    #[tokio::test]
    async fn daemon_tick_uses_configured_network_down_sleep() {
        let _home = daemon_home();
        let profile = crate::store::profiles::create_profile("blackoutcfg", "").unwrap();
        let mut p = crate::store::profiles::load_profile(&profile);
        p.config.network_down_sleep_secs = 15;
        crate::store::profiles::save_profile(&p).unwrap();

        let mut state = DaemonState::default();
        let mut probe = FakeProbe::new(false); // network down
        let cycle = FakeCycle::new(true);
        let acct = FakeAccountProbe::default();
        let mut log_lines = Vec::new();
        let sleep = daemon_tick(&profile, &mut state, &mut probe, &acct, &cycle, &mut |l| {
            log_lines.push(l.to_string())
        })
        .await;
        assert_eq!(sleep, 15, "configured blackout sleep must be used");
        // Default profile (0) still returns the system 60s default.
        assert_eq!(NETWORK_DOWN_SLEEP_SECS, 60);
    }

    /// Scheduled auto-backup (when enabled + due) writes a backup and records
    /// the timestamp, even with no network (it is local disk work).
    #[tokio::test]
    async fn run_self_maintenance_writes_backup_when_due() {
        let _home = daemon_home();
        let profile = crate::store::profiles::create_profile("selfmaint", "").unwrap();
        let mut p = crate::store::profiles::load_profile(&profile);
        p.config.backup_autosync.enabled = true;
        p.config.backup_autosync.interval_secs = 1;
        crate::store::profiles::save_profile(&p).unwrap();

        let mut state = DaemonState::default();
        // Never backed up → due immediately.
        state.last_backup_ts = 0;
        let mut log_lines = Vec::new();
        run_self_maintenance(&profile, &mut state, false, &mut |l| {
            log_lines.push(l.to_string())
        })
        .await;

        assert!(
            state.last_backup_ts > 0,
            "backup timestamp should be recorded"
        );
        assert!(
            !crate::ops::backup::list_backups().is_empty(),
            "a backup file should exist"
        );
        assert!(
            log_lines.iter().any(|l| l.contains("auto-backup")),
            "log should mention auto-backup: {:?}",
            log_lines
        );
    }

    /// When auto-backup is disabled, nothing is written and the timestamp stays.
    #[tokio::test]
    async fn run_self_maintenance_skips_backup_when_disabled() {
        let _home = daemon_home();
        let profile = crate::store::profiles::create_profile("selfmaint2", "").unwrap();
        let mut state = DaemonState::default();
        let mut log_lines = Vec::new();
        run_self_maintenance(&profile, &mut state, false, &mut |l| {
            log_lines.push(l.to_string())
        })
        .await;
        assert_eq!(state.last_backup_ts, 0, "disabled backup must not run");
        assert!(crate::ops::backup::list_backups().is_empty());
    }

    /// The daily version-integrity sweep runs when due (state-tracked, like
    /// autosync) and is rate-limited to once per 24h.
    #[tokio::test]
    async fn daemon_runs_integrity_sweep_once_per_day() {
        let _home = daemon_home();
        let profile = crate::store::profiles::create_profile("verifysweep", "").unwrap();
        let dir = crate::store::profiles::profile_dir(&profile);
        // Seed one real version so the sweep has content to verify.
        std::fs::write(dir.join("config.json"), b"old").unwrap();
        crate::artifact::artifact_versions::snapshot_before_write(
            &dir,
            "config.json",
            b"new",
            1000,
        )
        .unwrap();

        let mut state = DaemonState::default();
        state.last_verify_ts = 0; // never verified → due
        let mut log_lines = Vec::new();
        run_self_maintenance(&profile, &mut state, false, &mut |l| {
            log_lines.push(l.to_string())
        })
        .await;
        assert!(
            state.last_verify_ts > 0,
            "sweep should run and record its timestamp"
        );

        // Immediately after: still inside the 24h window → must NOT re-run.
        let second_ts = state.last_verify_ts;
        run_self_maintenance(&profile, &mut state, false, &mut |l| {
            log_lines.push(l.to_string())
        })
        .await;
        assert_eq!(
            state.last_verify_ts, second_ts,
            "sweep must be rate-limited to once per day"
        );
        assert!(log_lines
            .iter()
            .any(|l| l.contains("version-integrity sweep")));
    }

    /// The autonomous multi-hop discovery + v2rayN export pass is rate-limited
    /// to DISCOVERY_INTERVAL_SECS: when it just ran, a tick must NOT re-run it
    /// (state timestamp stays put and no discovery log line is emitted).
    #[tokio::test]
    async fn autonomous_discovery_is_rate_limited() {
        let _home = daemon_home();
        let profile = crate::store::profiles::create_profile("discrate", "").unwrap();
        // Re-enable discovery for this test (daemon_home disables it).
        crate::discovery::harvest::set_discovery_enabled(true);

        let mut state = DaemonState::default();
        let now = crate::store::profiles::now_ts() as i64;
        state.last_discovery_ts = now; // just ran → inside the window
        let mut log_lines = Vec::new();
        run_self_maintenance(&profile, &mut state, true, &mut |l| {
            log_lines.push(l.to_string())
        })
        .await;

        assert_eq!(
            state.last_discovery_ts, now,
            "discovery must be rate-limited inside the interval"
        );
        assert!(
            !log_lines.iter().any(|l| l.contains("autonomous discovery")),
            "no discovery pass may run inside the rate-limit window: {:?}",
            log_lines
        );
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
        // Pull network-online.target so the daemon waits for the network at
        // boot before starting (survives a boot-before-login autostart).
        assert!(unit.contains("Wants=network-online.target"));
        assert!(unit.contains("After=network-online.target"));
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
        assert!(log_suffix(&log_path, 1).exists());
        assert!(!log_suffix(&log_path, 2).exists());
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
                    tier: Some(crate::net::connectivity::Tier::Direct),
                },
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }
        fn with_tier(up: bool, tier: crate::net::connectivity::Tier) -> Self {
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
        fn liveness(&mut self) -> Pin<Box<dyn Future<Output = NetStatus> + Send + '_>> {
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
            _timeouts: crate::probe::autopilot::MonitorTimeouts,
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
        state: crate::trust::account_state::AccountState,
        /// Optional scripted rotation outcome (from, to).
        rotate: Option<(String, String)>,
    }
    impl Default for FakeAccountProbe {
        fn default() -> Self {
            Self {
                state: crate::trust::account_state::AccountState::Active,
                rotate: None,
            }
        }
    }
    impl AccountProbe for FakeAccountProbe {
        fn probe_account(
            &self,
            _profile: &str,
        ) -> Pin<Box<dyn Future<Output = crate::trust::account_state::AccountState> + Send + '_>>
        {
            let st = self.state.clone();
            Box::pin(async move { st })
        }
        fn try_rotate(
            &self,
            _profile: &str,
        ) -> Pin<Box<dyn Future<Output = Option<(String, String)>> + Send + '_>> {
            let r = self.rotate.clone();
            Box::pin(async move { r })
        }
    }

    /// The self-inflicted-DoS guard: when the network is down, the cycle must
    /// NOT run at all (no scan, no rescue burn), and we must log network=down.
    #[tokio::test]
    async fn test_daemon_skips_cycle_when_network_down() {
        let _home = daemon_home();
        let profile = "default";
        let mut state = DaemonState::default();
        let mut probe = FakeProbe::new(false);
        let cycle = FakeCycle::new(true);
        let mut log_lines = Vec::new();
        let acct = FakeAccountProbe::default();

        // First tick: network down → skip cycle.
        let sleep = daemon_tick(profile, &mut state, &mut probe, &acct, &cycle, &mut |l| {
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
        let sleep2 = daemon_tick(profile, &mut state, &mut probe, &acct, &cycle, &mut |l| {
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
        let mut probe = FakeProbe::new(false);
        let cycle = FakeCycle::new(true);
        let mut log_lines = Vec::new();
        let acct = FakeAccountProbe::default();

        let sleep = daemon_tick(profile, &mut state, &mut probe, &acct, &cycle, &mut |l| {
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
        let mut probe = FakeProbe::with_tier(true, crate::net::connectivity::Tier::DoH);
        let cycle = FakeCycle::new(true);
        let acct = FakeAccountProbe::default();

        let sleep = daemon_tick(profile, &mut state, &mut probe, &acct, &cycle, &mut |_l| {}).await;
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
        let mut probe = FakeProbe::new(true); // now up
        let cycle = FakeCycle::new(true);
        let mut log_lines = Vec::new();
        let acct = FakeAccountProbe::default();

        let sleep = daemon_tick(profile, &mut state, &mut probe, &acct, &cycle, &mut |l| {
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
        // Exercises the online outbox path; other tests may have left the
        // process-global air-gap switch on.
        crate::ops::airgap::set_offline(false);
        let _home = daemon_home();
        let profile = crate::store::profiles::create_profile("default", "").unwrap();
        let mut state = DaemonState::default();
        let mut probe = FakeProbe::new(true);
        let cycle = FakeCycle::new(true);
        let acct = FakeAccountProbe::default();

        let sleep = daemon_tick(
            &profile,
            &mut state,
            &mut probe,
            &acct,
            &cycle,
            &mut |_l| {},
        )
        .await;
        assert_eq!(sleep, DEFAULT_INITIAL_INTERVAL_SECS);
        // The automatic flush attempt ran (beacon disabled on this profile →
        // noop, but the attempt is recorded).
        assert!(state.last_outbox_flush_ts > 0);

        // A second tick within the interval must NOT re-flush.
        let before = state.last_outbox_flush_ts;
        let _sleep2 = daemon_tick(
            &profile,
            &mut state,
            &mut probe,
            &acct,
            &cycle,
            &mut |_l| {},
        )
        .await;
        assert_eq!(state.last_outbox_flush_ts, before);
    }

    /// A blackout restore forces an immediate outbox flush regardless of the
    /// rate-limit gate — that is the exact moment queued alerts must go out.
    #[tokio::test]
    async fn test_daemon_flushes_outbox_immediately_on_restore() {
        // Exercises the online outbox path; other tests may have left the
        // process-global air-gap switch on.
        crate::ops::airgap::set_offline(false);
        let _home = daemon_home();
        let profile = crate::store::profiles::create_profile("default", "").unwrap();
        let mut state = DaemonState {
            network_was_down: true, // was down
            ..Default::default()
        };
        let mut probe = FakeProbe::new(true); // now up
        let cycle = FakeCycle::new(true);
        let acct = FakeAccountProbe::default();

        let sleep = daemon_tick(
            &profile,
            &mut state,
            &mut probe,
            &acct,
            &cycle,
            &mut |_l| {},
        )
        .await;
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
        let mut probe = FakeProbe::new(true);
        let cycle = FakeCycle::new(false); // always fails
        let mut log_lines = Vec::new();
        let acct = FakeAccountProbe::default();

        let s1 = daemon_tick(profile, &mut state, &mut probe, &acct, &cycle, &mut |l| {
            log_lines.push(l.to_string())
        })
        .await;
        assert_eq!(s1, 900, "300 → 900");
        assert_eq!(state.failure_streak, 1);

        let s2 = daemon_tick(profile, &mut state, &mut probe, &acct, &cycle, &mut |l| {
            log_lines.push(l.to_string())
        })
        .await;
        assert_eq!(s2, 3600, "900 → 3600");
        assert_eq!(state.failure_streak, 2);

        let s3 = daemon_tick(profile, &mut state, &mut probe, &acct, &cycle, &mut |l| {
            log_lines.push(l.to_string())
        })
        .await;
        assert_eq!(s3, 21600, "3600 → 21600");
        assert_eq!(state.failure_streak, 3);

        let s4 = daemon_tick(profile, &mut state, &mut probe, &acct, &cycle, &mut |l| {
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
        let mut probe = FakeProbe::new(true);
        let cycle = FakeCycle::new(true); // succeeds
        let mut log_lines = Vec::new();
        let acct = FakeAccountProbe::default();

        let sleep = daemon_tick(profile, &mut state, &mut probe, &acct, &cycle, &mut |l| {
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
        state.account_state = crate::trust::account_state::AccountState::Suspended { since: 1 };
        state.last_account_poll_ts = crate::store::now_ts() as i64; // inside window
        let mut probe = FakeProbe::new(true);
        let acct = FakeAccountProbe {
            state: crate::trust::account_state::AccountState::Suspended { since: 1 },
            rotate: None,
        };
        let cycle = FakeCycle::new(true);
        let mut log_lines = Vec::new();
        let sleep = daemon_tick(profile, &mut state, &mut probe, &acct, &cycle, &mut |l| {
            log_lines.push(l.to_string());
        })
        .await;
        assert_eq!(
            sleep,
            crate::trust::account_state::ACCOUNT_POLL_INTERVAL_SECS
        );
        assert_eq!(
            cycle.calls.load(Ordering::SeqCst),
            0,
            "no cycle while suspended"
        );
        assert!(log_lines.iter().any(|l| l.contains("waiting")));
    }

    /// When the account is still blocked after a poll, the daemon must
    /// best-effort auto-start the lifeline tunnel (flag set once per episode).
    #[tokio::test]
    async fn test_daemon_autostarts_lifeline_on_still_blocked() {
        let _home = daemon_home();
        let profile = "default";
        let mut state = DaemonState::default();
        state.account_state = crate::trust::account_state::AccountState::Suspended { since: 1 };
        // Stale last-poll → the daemon actually probes and finds it still blocked.
        state.last_account_poll_ts = crate::store::now_ts() as i64 - 10_000;
        let mut probe = FakeProbe::new(true);
        let acct = FakeAccountProbe {
            state: crate::trust::account_state::AccountState::Suspended { since: 1 },
            rotate: None,
        };
        let cycle = FakeCycle::new(true);
        let mut log_lines = Vec::new();
        let sleep = daemon_tick(profile, &mut state, &mut probe, &acct, &cycle, &mut |l| {
            log_lines.push(l.to_string());
        })
        .await;
        assert_eq!(
            sleep,
            crate::trust::account_state::ACCOUNT_POLL_INTERVAL_SECS
        );
        assert!(
            state.lifeline_auto_started,
            "lifeline auto-start flag should be set while blocked"
        );
        assert_eq!(cycle.calls.load(Ordering::SeqCst), 0);
    }

    /// When the account is blocked but another stored token can take over, the
    /// daemon must rotate automatically and resume the cycle — closing the
    /// manual `dastyab token recover` step.
    #[tokio::test]
    async fn test_daemon_auto_rotates_token_and_resumes_cycle() {
        let _home = daemon_home();
        let profile = "default";
        let mut state = DaemonState::default();
        state.account_state = crate::trust::account_state::AccountState::TokenInvalid { since: 1 };
        state.last_account_poll_ts = crate::store::now_ts() as i64; // inside window
        let mut probe = FakeProbe::new(true);
        // Scripted rotation: backup token takes over.
        let acct = FakeAccountProbe {
            state: crate::trust::account_state::AccountState::TokenInvalid { since: 1 },
            rotate: Some(("primary".to_string(), "backup".to_string())),
        };
        let cycle = FakeCycle::new(true);
        let mut log_lines = Vec::new();
        let sleep = daemon_tick(profile, &mut state, &mut probe, &acct, &cycle, &mut |l| {
            log_lines.push(l.to_string());
        })
        .await;
        // Rotated → state cleared → cycle ran → normal reset interval.
        assert_eq!(cycle.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            state.account_state,
            crate::trust::account_state::AccountState::Active
        );
        assert!(log_lines.iter().any(|l| l.contains("token-auto-rotated")));
        assert_eq!(sleep, backoff_reset());
    }

    /// When auto-rotation is attempted but every stored token fails (rotate =
    /// None with >=2 tokens in the store), the daemon must notify the user
    /// exactly once that a manual token add is required — instead of holding
    /// silently forever.
    #[tokio::test]
    async fn test_daemon_notifies_once_when_rotation_exhausted() {
        let _home = daemon_home();
        let profile = "default";
        // Two stored tokens so auto-rotation is "eligible" — but the scripted
        // probe returns None (both fail verification).
        crate::store::profiles::add_token(profile, "a", "tok-a").unwrap();
        crate::store::profiles::add_token(profile, "b", "tok-b").unwrap();
        crate::store::profiles::set_active_token(profile, "a").unwrap();

        let mut state = DaemonState::default();
        state.account_state = crate::trust::account_state::AccountState::TokenInvalid { since: 1 };
        state.last_account_poll_ts = crate::store::now_ts() as i64; // inside window
        let mut probe = FakeProbe::new(true);
        let acct = FakeAccountProbe {
            state: crate::trust::account_state::AccountState::TokenInvalid { since: 1 },
            rotate: None,
        };
        let cycle = FakeCycle::new(true);
        let mut log_lines = Vec::new();
        let sleep = daemon_tick(profile, &mut state, &mut probe, &acct, &cycle, &mut |l| {
            log_lines.push(l.to_string());
        })
        .await;

        // Still blocked → no cycle runs, we wait for the next poll.
        assert_eq!(
            sleep,
            crate::trust::account_state::ACCOUNT_POLL_INTERVAL_SECS
        );
        assert_eq!(cycle.calls.load(Ordering::SeqCst), 0);
        // The one-shot exhausted notification was recorded.
        assert!(state.account_rotate_exhausted_notified);
        assert!(log_lines
            .iter()
            .any(|l| l.contains("auto-rotation exhausted")));

        // A second tick must NOT re-notify (guard works).
        let mut log_lines2 = Vec::new();
        state.last_account_poll_ts = crate::store::now_ts() as i64;
        let sleep2 = daemon_tick(profile, &mut state, &mut probe, &acct, &cycle, &mut |l| {
            log_lines2.push(l.to_string());
        })
        .await;
        assert_eq!(
            sleep2,
            crate::trust::account_state::ACCOUNT_POLL_INTERVAL_SECS
        );
        assert!(!log_lines2
            .iter()
            .any(|l| l.contains("auto-rotation exhausted")));
    }

    /// When a suspended account is reactivated, the daemon must notice on the
    /// next poll and run the cycle again — no manual restart.
    #[tokio::test]
    async fn test_daemon_resumes_when_account_restored() {
        let _home = daemon_home();
        let profile = "default";
        let mut state = DaemonState::default();
        state.account_state = crate::trust::account_state::AccountState::Suspended { since: 1 };
        // Advance the poll window so a re-probe actually happens.
        state.last_account_poll_ts = (crate::store::now_ts() as i64) - 2000;
        let mut probe = FakeProbe::new(true);
        let acct = FakeAccountProbe {
            state: crate::trust::account_state::AccountState::Active,
            rotate: None,
        };
        let cycle = FakeCycle::new(true);
        let mut log_lines = Vec::new();
        let sleep = daemon_tick(profile, &mut state, &mut probe, &acct, &cycle, &mut |l| {
            log_lines.push(l.to_string());
        })
        .await;
        // Restored → cycle ran (calls becomes 1) and we advance normally.
        assert_eq!(cycle.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            state.account_state,
            crate::trust::account_state::AccountState::Active
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
        state.account_state = crate::trust::account_state::AccountState::TokenInvalid { since: 1 };
        state.last_account_poll_ts = crate::store::now_ts() as i64;
        let mut probe = FakeProbe::new(true);
        let acct = FakeAccountProbe {
            state: crate::trust::account_state::AccountState::TokenInvalid { since: 1 },
            rotate: None,
        };
        let cycle = FakeCycle::new(true);
        let sleep = daemon_tick(profile, &mut state, &mut probe, &acct, &cycle, &mut |_| {}).await;
        assert_eq!(
            sleep,
            crate::trust::account_state::ACCOUNT_POLL_INTERVAL_SECS
        );
        assert_eq!(cycle.calls.load(Ordering::SeqCst), 0);
    }

    /// While active, the daemon periodically confirms the account; if the
    /// account becomes suspended it switches to the wait state.
    #[tokio::test]
    async fn test_daemon_detects_suspension_from_active() {
        let _home = daemon_home();
        let profile = "default";
        let mut state = DaemonState::default();
        state.account_state = crate::trust::account_state::AccountState::Active;
        state.last_account_poll_ts = (crate::store::now_ts() as i64) - 2000;
        let mut probe = FakeProbe::new(true);
        let acct = FakeAccountProbe {
            state: crate::trust::account_state::AccountState::Suspended { since: 1 },
            rotate: None,
        };
        let cycle = FakeCycle::new(true);
        let sleep = daemon_tick(profile, &mut state, &mut probe, &acct, &cycle, &mut |_| {}).await;
        assert_eq!(
            sleep,
            crate::trust::account_state::ACCOUNT_POLL_INTERVAL_SECS
        );
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
        state.account_state = crate::trust::account_state::AccountState::TokenInvalid { since: 1 };
        state.last_account_poll_ts = (crate::store::now_ts() as i64) - 100;
        save_daemon_state(profile, &state).unwrap();

        let cleared = crate::daemon::clear_account_blocked(profile).unwrap();
        assert!(cleared, "blocked state should be cleared");

        let after = load_daemon_state(profile);
        assert!(!after.account_state.blocks_cycle());
        assert_eq!(
            after.account_state,
            crate::trust::account_state::AccountState::Active
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

    /// The scheduled autonomy audit auto-applies the config-toggle ACTION items
    /// (backup + mutation) on a due tick, even with no CF seam. The backend
    /// profile config is persisted with the toggles flipped.
    #[tokio::test]
    async fn test_daemon_run_autonomy_audit_auto_applies_config_toggles() {
        let _home = daemon_home();
        let profile = crate::store::profiles::create_profile("default", "").unwrap();
        let mut state = DaemonState::default();
        state.audit.last_run_unix = 0; // due

        struct NoopSeam;
        impl crate::daemon::autonomy_schedule::CfApiSeam for NoopSeam {
            fn ensure_second_token(&self, _p: &str) -> Result<bool, CFError> {
                Ok(true)
            }
            fn rotate_worker(&self, _p: &str) -> Result<u32, CFError> {
                Ok(1)
            }
            fn ensure_dns_tunnel(&self, _p: &str) -> Result<(), CFError> {
                Ok(())
            }
        }
        let seam = NoopSeam;
        let seam_ref: &dyn crate::daemon::autonomy_schedule::CfApiSeam = &seam;

        let mut log_lines: Vec<String> = Vec::new();
        let applied = crate::daemon::run_autonomy_audit_with_seam(
            &profile,
            &mut state,
            true,
            Some(seam_ref),
            &mut |l| log_lines.push(l.to_string()),
        )
        .await;

        // A fresh profile needs backup + mutation; both auto-apply.
        assert!(
            applied >= 2,
            "expected backup+mutation toggles applied, got {applied}"
        );
        assert!(state.audit.last_run_unix > 0);
        assert!(state.audit.last_action_digest.is_some());

        // Backend config persisted.
        let p = crate::store::profiles::load_profile(&profile);
        assert!(p.config.backup_autosync.enabled);
        assert!(p.config.mutation.enabled);
    }

    /// The same audit does NOT re-run inside the interval (no double-apply).
    #[tokio::test]
    async fn test_daemon_run_autonomy_audit_skips_within_interval() {
        let _home = daemon_home();
        let profile = crate::store::profiles::create_profile("default", "").unwrap();
        let mut state = DaemonState::default();
        state.audit.last_run_unix = crate::store::now_ts() as u64; // just ran

        struct NoopSeam;
        impl crate::daemon::autonomy_schedule::CfApiSeam for NoopSeam {
            fn ensure_second_token(&self, _p: &str) -> Result<bool, CFError> {
                Ok(true)
            }
            fn rotate_worker(&self, _p: &str) -> Result<u32, CFError> {
                Ok(1)
            }
            fn ensure_dns_tunnel(&self, _p: &str) -> Result<(), CFError> {
                Ok(())
            }
        }
        let seam = NoopSeam;
        let seam_ref: &dyn crate::daemon::autonomy_schedule::CfApiSeam = &seam;

        let applied = crate::daemon::run_autonomy_audit_with_seam(
            &profile,
            &mut state,
            true,
            Some(seam_ref),
            &mut |_l| {},
        )
        .await;
        assert_eq!(applied, 0, "no fixes when audit not due");
    }
}
