//! Health beacon schema + persistence.
//!
//! A per-cycle structured snapshot written atomically at the end of every
//! autopilot cycle (discovery, monitor, rescue, or manual). It gives the user
//! a one-`cat` health check from anywhere, gives the GUI a payload to render,
//! and is the prerequisite for a future remote beacon. Crucially it is written
//! on the *error* path too, so a daemon failing silently still leaves a
//! readable diagnosis (`last_error`, `network_ok`, `worker_health`,
//! `strategy_window`) instead of only prose in `daemon.log`.

use std::path::PathBuf;

use crate::error::CFError;
use crate::store;

/// Which kind of cycle produced a beacon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CycleKind {
    /// Full discovery + validation cycle (`run_cycle_with_params`).
    Discovery,
    /// The monitor's light/deep escalation cycle (`monitor_cycle`).
    Monitor,
    /// A rescue-chain attempt.
    Rescue,
    /// A CLI / GUI manual invocation.
    Manual,
}

/// The structured health snapshot.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HealthBeacon {
    /// Schema version. Readers reject `schema_version > 1` (wrote by a newer
    /// version — do not crash, just report).
    pub schema_version: u32,
    /// UNIX seconds this file was written.
    pub written_at: i64,
    /// UNIX seconds the producing cycle started.
    pub cycle_ts: i64,
    /// Which kind of cycle wrote this.
    pub cycle_kind: CycleKind,
    /// Duration of the producing cycle in ms.
    pub cycle_duration_ms: u64,
    /// Daemon pid if written by the daemon (None = CLI/GUI).
    pub daemon_pid: Option<u32>,
    /// Daemon start time (UNIX seconds) if known.
    pub daemon_started_at: Option<i64>,
    /// Whether protection is enabled in the profile config.
    pub protection_enabled: bool,
    /// Was the network reachable at cycle top (DoH liveness probe).
    pub network_ok: bool,
    /// Worker-health verdict: "Alive" | "NotFound" | "Suspended" |
    /// "PathMismatch" | "Unreachable" | "Skipped".
    pub worker_health: String,
    /// Active ledger endpoint "ip:port" if any.
    pub active_endpoint: Option<String>,
    /// RTT of the active endpoint if known.
    pub active_rtt_ms: Option<u32>,
    /// Whether the active endpoint is presently alive.
    pub active_alive: bool,
    /// Absolute bundle directory path (if resolvable).
    pub bundle_dir: Option<String>,
    /// Whether the user-facing bundle is in sync with the ledger.
    pub bundle_in_sync: bool,
    /// UNIX seconds the bundle was last drift-checked.
    pub bundle_last_checked: i64,
    /// Current self-learning strategy ("WorkerOnly" | "GenericCfFirst").
    pub strategy_current: String,
    /// Rolling window of recent discovery outcomes (0/1, newest last).
    pub strategy_window: Vec<u8>,
    /// Success rate over the window (None when empty).
    pub strategy_rate: Option<f32>,
    /// Discovery cycles since the last rotation.
    pub strategy_cycles_since_rotation: u32,
    /// UNIX seconds of the last rotation (None = never).
    pub strategy_last_rotated_ts: Option<i64>,
    /// Last rescue outcome ("recovered" | "gave_up" | None).
    pub last_rescue_outcome: Option<String>,
    /// UNIX seconds of the last rescue attempt.
    pub last_rescue_ts: Option<i64>,
    /// Plaintext last error from the producing cycle's error path (None = ok).
    pub last_error: Option<String>,
    /// Stage the cycle was in when it aborted (timeout/panic). None = clean
    /// completion. Serde-default so older beacons load.
    #[serde(default)]
    pub last_stage: Option<String>,
}

impl HealthBeacon {
    /// A beacon with every optional field cleared, suitable as a base that
    /// callers fill in as values become known.
    pub fn new(cycle_kind: CycleKind, cycle_ts: i64) -> Self {
        Self {
            schema_version: 1,
            written_at: 0,
            cycle_ts,
            cycle_kind,
            cycle_duration_ms: 0,
            daemon_pid: None,
            daemon_started_at: None,
            protection_enabled: false,
            network_ok: false,
            worker_health: "Skipped".to_string(),
            active_endpoint: None,
            active_rtt_ms: None,
            active_alive: false,
            bundle_dir: None,
            bundle_in_sync: false,
            bundle_last_checked: 0,
            strategy_current: "WorkerOnly".to_string(),
            strategy_window: Vec::new(),
            strategy_rate: None,
            strategy_cycles_since_rotation: 0,
            strategy_last_rotated_ts: None,
            last_rescue_outcome: None,
            last_rescue_ts: None,
            last_error: None,
            last_stage: None,
        }
    }
}

impl Default for HealthBeacon {
    fn default() -> Self {
        Self::new(CycleKind::Manual, 0)
    }
}

/// The beacon path for a profile: `~/.khvarenah/profiles/<id>/health.json`.
pub fn beacon_path(profile_id: &str) -> PathBuf {
    store::profiles::profile_dir(profile_id).join("health.json")
}

/// Atomically write a beacon (tempfile + fsync + rename + parent fsync).
pub fn write_beacon(profile_id: &str, beacon: &HealthBeacon) -> Result<(), CFError> {
    store::write_json(&beacon_path(profile_id), beacon)
}

/// Write an abort beacon for a timed-out / panicked cycle. This is the
/// diagnostic left behind when the guarded wrapper kills a cycle that hung:
/// it fills `last_error` with the reason and `last_stage` with the stage the
/// cycle was last marked in (from the cycle_guard marker). Fills every other
/// field `compose_beacon` can derive (worker health, ledger endpoint, bundle
/// sync, strategy window) so the beacon stays as rich as a normal one.
/// Write an abort beacon for a cycle (`reason` = timeout/error kind). A
/// `worker_health_label` records the step-0 worker verdict so an honest
/// diagnosis survives even on abort (round 9: the beacon must never show
/// "Skipped" when we actually probed).
pub fn write_beacon_on_abort(
    profile_id: &str,
    kind: CycleKind,
    reason: &str,
) -> Result<(), CFError> {
    write_beacon_on_abort_with_verdict(profile_id, kind, reason, None)
}

/// Like [`write_beacon_on_abort`], but records the step-0 worker-health
/// verdict label (Alive / NotFound / …) instead of defaulting to "Skipped".
pub fn write_beacon_on_abort_with_verdict(
    profile_id: &str,
    kind: CycleKind,
    reason: &str,
    worker_health_label: Option<&str>,
) -> Result<(), CFError> {
    let now = crate::store::now_ts() as i64;
    let beacon = crate::autopilot::compose_beacon(
        profile_id,
        kind,
        now,
        0,
        worker_health_label,
        None,
        Some(reason.to_string()),
    );
    write_beacon(profile_id, &beacon)
}

/// Read a beacon. `Ok(None)` if the file is missing. `Err` if the schema is
/// from a newer version (never crash, just report).
pub fn read_beacon(profile_id: &str) -> Result<Option<HealthBeacon>, CFError> {
    let p = beacon_path(profile_id);
    if !p.exists() {
        return Ok(None);
    }
    let beacon: HealthBeacon = store::read_or_default(&p);
    if beacon.schema_version > 1 {
        return Err(CFError::new(
            "Health beacon schema mismatch",
            format!(
                "written by a newer version (schema {}) — upgrade the app to read it.",
                beacon.schema_version
            ),
            "Upgrade khvarenah.",
        ));
    }
    Ok(Some(beacon))
}

/// How old (in seconds) a beacon is relative to `now`. Negative = clock skew.
pub fn beacon_age_secs(beacon: &HealthBeacon, now: i64) -> i64 {
    now - beacon.written_at
}

/// True if the beacon is stale — older than `max_age_secs`.
pub fn is_stale(beacon: &HealthBeacon, now: i64, max_age_secs: i64) -> bool {
    beacon_age_secs(beacon, now) > max_age_secs
}

/// Render a `WorkerHealth`-style verdict as a plain string. Accepts a
/// &str for convenience (the autopilot `WorkerHealth` enum maps into it).
pub fn worker_health_label(v: &str) -> String {
    match v {
        "Alive" => "Alive".to_string(),
        "NotFound" => "NotFound".to_string(),
        "Suspended" => "Suspended".to_string(),
        "PathMismatch" => "PathMismatch".to_string(),
        "Unreachable" => "Unreachable".to_string(),
        _ => "Skipped".to_string(),
    }
}

/// Internal helper so tests don't have to write a full struct by hand.
#[cfg(test)]
pub(crate) fn sample_beacon() -> HealthBeacon {
    let mut b = HealthBeacon::new(CycleKind::Discovery, 1_750_000_000);
    b.written_at = 1_750_000_123;
    b.worker_health = "Alive".to_string();
    b.active_endpoint = Some("1.2.3.4:443".to_string());
    b.strategy_current = "GenericCfFirst".to_string();
    b.strategy_window = vec![1, 0, 1];
    b.strategy_rate = Some(0.66);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Isolated profile home for store-backed tests.
    fn rescue_home() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(tmp.path().join(".khvarenah"));
        tmp
    }

    fn make_profile() -> String {
        crate::store::profiles::create_profile("hl", "").unwrap()
    }

    #[test]
    fn test_beacon_roundtrip_serialization() {
        let b = sample_beacon();
        let bytes = serde_json::to_vec(&b).unwrap();
        let back: HealthBeacon = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.schema_version, 1);
        assert_eq!(back.cycle_kind, CycleKind::Discovery);
        assert_eq!(back.active_endpoint.as_deref(), Some("1.2.3.4:443"));
        assert_eq!(back.strategy_window, vec![1, 0, 1]);
        assert_eq!(back.strategy_rate, Some(0.66));
    }

    #[test]
    fn test_beacon_path_uses_profile_id() {
        let _home = rescue_home();
        let id = make_profile();
        let p = beacon_path(&id);
        assert!(p.to_string_lossy().contains(&id), "{p:?}");
        let p2 = beacon_path("default");
        assert!(p2.ends_with(Path::new("default/health.json")), "{p2:?}");
    }

    #[test]
    fn test_write_beacon_creates_file_atomically() {
        let _home = rescue_home();
        let id = make_profile();
        let b = sample_beacon();
        write_beacon(&id, &b).unwrap();
        let p = beacon_path(&id);
        assert!(p.exists());
        let read = read_beacon(&id).unwrap().expect("beacon present");
        assert_eq!(read.written_at, b.written_at);
        assert_eq!(read.strategy_current, "GenericCfFirst");
    }

    #[test]
    fn test_read_beacon_returns_none_when_missing() {
        let _home = rescue_home();
        let id = make_profile();
        assert!(read_beacon(&id).unwrap().is_none());
    }

    #[test]
    fn test_read_beacon_rejects_newer_schema_version() {
        let _home = rescue_home();
        let id = make_profile();
        let mut b = sample_beacon();
        b.schema_version = 999;
        write_beacon(&id, &b).unwrap();
        let err = read_beacon(&id).unwrap_err();
        assert!(err.brief().contains("newer"), "{}", err.brief());
    }

    #[test]
    fn test_beacon_age_secs_positive_when_written_in_past() {
        let b = sample_beacon();
        assert_eq!(beacon_age_secs(&b, 1_750_000_223), 100);
    }

    #[test]
    fn test_beacon_age_secs_negative_on_clock_skew() {
        let b = sample_beacon();
        assert_eq!(beacon_age_secs(&b, 1_750_000_023), -100);
    }
}
