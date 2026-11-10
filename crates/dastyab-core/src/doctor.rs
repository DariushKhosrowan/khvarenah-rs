//! Doctor — the "state of trust" surface.
//!
//! Runs a battery of pure, deterministic checks that make every safety
//! subsystem (manifest, backup, autosync, daemon, tunnel, workspace snapshot)
//! visible in one place. Each check is a pure function returning a
//! [`CheckResult`]; the overall report aggregates to the worst status. This
//! is what turns "is my data safe?" into a single command / GUI banner.
//!
//! ## Checks
//! 1. `check_manifest_all_profiles` — verify every profile against its
//!    manifest (nothing missing / changed / extra).
//! 2. `check_token_permissions` — token.json must be mode 600 (not world- or
//!    group-readable).
//! 3. `check_autosync_freshness` — if autosync is enabled, the last backup
//!    must be within 2× the interval.
//! 4. `check_latest_backup_verifies` — the newest backup must structurally
//!    re-import (valid export JSON with the expected fields).
//! 5. `check_disk_headroom` — free disk must exceed a floor.
//! 6. `check_daemon_heartbeat` — the health beacon must be fresh.
//! 7. `check_tunnel_recently_ok` — the tunnel-client config must be recent.
//! 8. `check_workspace_snapshot_age` — a scheduled workspace snapshot must
//!    exist and be recent.
//!
//! Every check is deterministic for a given set of fixtures, so the report's
//! Markdown/JSON rendering is stable (test `doctor_markdown_deterministic_*`).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::CFError;

/// Verdict for a single check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CheckStatus {
    /// Everything is fine.
    Ok,
    /// Something needs attention but is not fatal.
    Warn,
    /// Something safety-critical is broken.
    Fail,
}

impl CheckStatus {
    pub fn label(self) -> &'static str {
        match self {
            CheckStatus::Ok => "ok",
            CheckStatus::Warn => "warn",
            CheckStatus::Fail => "fail",
        }
    }

    /// The "worst" of two statuses (used for the overall verdict).
    fn worst(self, other: CheckStatus) -> CheckStatus {
        self.max(other)
    }
}

/// The result of running one doctor check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub name: String,
    pub status: CheckStatus,
    /// Human-readable detail (evidence, not summary).
    pub detail: String,
}

impl CheckResult {
    fn ok(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_string(),
            status: CheckStatus::Ok,
            detail: detail.into(),
        }
    }
    fn warn(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_string(),
            status: CheckStatus::Warn,
            detail: detail.into(),
        }
    }
    fn fail(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_string(),
            status: CheckStatus::Fail,
            detail: detail.into(),
        }
    }
}

/// The full doctor report.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DoctorReport {
    pub checked_at_unix: u64,
    pub results: Vec<CheckResult>,
}

impl DoctorReport {
    /// Worst status across all checks (Fail > Warn > Ok).
    pub fn overall(&self) -> CheckStatus {
        self.results
            .iter()
            .map(|r| r.status)
            .fold(CheckStatus::Ok, CheckStatus::worst)
    }

    pub fn is_all_ok(&self) -> bool {
        self.overall() == CheckStatus::Ok
    }

    pub fn get(&self, name: &str) -> Option<&CheckResult> {
        self.results.iter().find(|r| r.name == name)
    }
}

// ----------------------------------------------------------------------------
// Check helpers
// ----------------------------------------------------------------------------

/// Disk free space (kilobytes) on the filesystem containing `dir`. Best-effort
/// via a quick `df` call (no new dependency). Returns `None` when it can't be
/// determined.
pub fn free_disk_kb(dir: &Path) -> Option<u64> {
    let out = std::process::Command::new("df")
        .arg("-k")
        .arg("--output=avail")
        .arg(dir)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // df --output=avail prints a header line then one number per mount.
    for line in text.lines().skip(1) {
        let v = line.trim();
        if v.is_empty() {
            continue;
        }
        if let Ok(kb) = v.parse::<u64>() {
            return Some(kb);
        }
    }
    None
}

/// Free disk floor (kilobytes) before we warn: 512 MiB.
pub const DISK_HEADROOM_WARN_KB: u64 = 512 * 1024;
/// Hard floor before we fail: 128 MiB.
pub const DISK_HEADROOM_FAIL_KB: u64 = 128 * 1024;

/// Mtime (Unix seconds) of `path`, or `None` if it doesn't exist.
fn file_mtime_unix(path: &Path) -> Option<i64> {
    let meta = std::fs::metadata(path).ok()?;
    let m = meta.modified().ok()?;
    Some(
        m.duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
    )
}

/// Whether a file is mode 600 (or stricter / not group/world readable).
#[cfg(unix)]
fn file_is_private(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o077 == 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn file_is_private(_path: &Path) -> bool {
    true
}

/// Structural verification that a profile backup bundle re-imports cleanly.
/// A valid export is a JSON object with at least a `meta` object (and,
/// for a real backup, a `tokens` map). We don't write anything — pure parse.
pub fn backup_bundle_verifies(path: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(_v) = serde_json::from_str::<serde_json::Value>(&text) else {
        return false;
    };
    _v.is_object() && _v.get("meta").map(|m| m.is_object()).unwrap_or(false)
}

/// The newest backup file (by mtime) under the backup dir, if any.
pub fn newest_backup(backup_dir: &Path) -> Option<PathBuf> {
    let mut best: Option<(i64, PathBuf)> = None;
    let entries = std::fs::read_dir(backup_dir).ok()?;
    for e in entries.flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("json") {
            continue;
        }
        if let Some(mtime) = file_mtime_unix(&p) {
            match best {
                Some((best_m, _)) if mtime <= best_m => {}
                _ => best = Some((mtime, p)),
            }
        }
    }
    best.map(|(_, p)| p)
}

// ----------------------------------------------------------------------------
// Individual checks
// ----------------------------------------------------------------------------

/// Check 1: all profiles verify against their manifests.
pub fn check_manifest_all_profiles() -> CheckResult {
    let reports = crate::manifest::verify_workspace();
    if reports.is_empty() {
        return CheckResult::ok(
            "manifest",
            "no profiles — nothing to verify",
        );
    }
    let mut bad: Vec<String> = Vec::new();
    for (meta, r) in &reports {
        if !r.has_manifest || !r.is_clean() {
            let mut what = Vec::new();
            if !r.has_manifest {
                what.push("no manifest".to_string());
            }
            if !r.missing.is_empty() {
                what.push(format!("missing={}", r.missing.join(",")));
            }
            if !r.changed.is_empty() {
                what.push(format!("changed={}", r.changed.join(",")));
            }
            if !r.extra.is_empty() {
                what.push(format!("extra={}", r.extra.join(",")));
            }
            bad.push(format!("{} ({})", meta.name, what.join("; ")));
        }
    }
    if bad.is_empty() {
        CheckResult::ok(
            "manifest",
            format!("all {} profile(s) verified", reports.len()),
        )
    } else {
        CheckResult::fail(
            "manifest",
            format!("integrity drift in {} profile(s): {}", bad.len(), bad.join("; ")),
        )
    }
}

/// Check 2: token.json is not world/group-readable.
pub fn check_token_permissions(profile_id: &str) -> CheckResult {
    let token_path = crate::store::profiles::profile_dir(profile_id).join("token.json");
    if !token_path.exists() {
        return CheckResult::warn("token-permissions", "no token.json present in this profile");
    }
    if file_is_private(&token_path) {
        CheckResult::ok("token-permissions", "token.json is private (mode 600)")
    } else {
        CheckResult::warn(
            "token-permissions",
            "token.json is group/world readable — run chmod 600",
        )
    }
}

/// Check 3: autosync freshness. `last_backup_ts` from daemon state.
pub fn check_autosync_freshness(
    profile_id: &str,
    last_backup_ts: i64,
    now: i64,
) -> CheckResult {
    let p = crate::store::profiles::load_profile(profile_id);
    let cfg = &p.config.backup_autosync;
    if !cfg.enabled {
        return CheckResult::warn(
            "autosync",
            "scheduled auto-backup is disabled — enable with `dastyab backup autosync`",
        );
    }
    let interval = cfg.interval_secs.max(1) as i64;
    let age = now - last_backup_ts;
    if last_backup_ts <= 0 {
        return CheckResult::warn(
            "autosync",
            "enabled but no backup recorded yet (daemon has not written one)",
        );
    }
    if age <= 2 * interval {
        CheckResult::ok(
            "autosync",
            format!("last backup {age}s ago, interval {interval}s (within 2×)"),
        )
    } else {
        CheckResult::warn(
            "autosync",
            format!("last backup {age}s ago, interval {interval}s (stale)"),
        )
    }
}

/// Check 4: newest backup structurally verifies.
pub fn check_latest_backup_verifies(backup_dir: &Path) -> CheckResult {
    let Some(newest) = newest_backup(backup_dir) else {
        return CheckResult::warn("backup", "no backups exist yet — run `dastyab backup export`");
    };
    if backup_bundle_verifies(&newest) {
        CheckResult::ok(
            "backup",
            format!("newest backup verifies: {}", newest.display()),
        )
    } else {
        CheckResult::fail(
            "backup",
            format!("newest backup failed structural verification: {}", newest.display()),
        )
    }
}

/// Check 5: disk headroom.
pub fn check_disk_headroom(mem_dir: &Path) -> CheckResult {
    match free_disk_kb(mem_dir) {
        None => CheckResult::warn("disk-headroom", "could not determine free disk space"),
        Some(kb) => {
            if kb < DISK_HEADROOM_FAIL_KB {
                CheckResult::fail(
                    "disk-headroom",
                    format!("only {kb} KiB free (< {} KiB)", DISK_HEADROOM_FAIL_KB),
                )
            } else if kb < DISK_HEADROOM_WARN_KB {
                CheckResult::warn(
                    "disk-headroom",
                    format!("{kb} KiB free (< {} KiB)", DISK_HEADROOM_WARN_KB),
                )
            } else {
                CheckResult::ok("disk-headroom", format!("{kb} KiB free"))
            }
        }
    }
}

/// Check 6: daemon heartbeat (health beacon freshness).
pub fn check_daemon_heartbeat(profile_id: &str, now: i64) -> CheckResult {
    match crate::health_beacon::read_beacon(profile_id) {
        Ok(Some(beacon)) => {
            let age = crate::health_beacon::beacon_age_secs(&beacon, now);
            // A health beacon is "fresh" if it was written in the last
            // DAEMON_HEARTBEAT_MAX_AGE_SECS seconds.
            const DAEMON_HEARTBEAT_MAX_AGE_SECS: i64 = 900;
            if age > DAEMON_HEARTBEAT_MAX_AGE_SECS {
                CheckResult::fail(
                    "daemon-heartbeat",
                    format!("health beacon is {age}s old (>{DAEMON_HEARTBEAT_MAX_AGE_SECS}s)"),
                )
            } else {
                CheckResult::ok("daemon-heartbeat", format!("daemon heartbeats {age}s ago"))
            }
        }
        Ok(None) => CheckResult::fail(
            "daemon-heartbeat",
            "no health beacon — daemon has never run (start with `dastyab daemon start`)",
        ),
        Err(e) => CheckResult::fail("daemon-heartbeat", format!("beacon read error: {}", e.brief())),
    }
}

/// Check 7: tunnel-client config recency. `max_age_secs` is the freshness
/// bound — older than this means the tunnel hasn't been (re)verified recently.
pub fn check_tunnel_recently_ok(profile_id: &str, max_age_secs: i64, now: i64) -> CheckResult {
    let tunnel_path = crate::store::profiles::profile_dir(profile_id).join("tunnel-client.json");
    let Some(mtime) = file_mtime_unix(&tunnel_path) else {
        return CheckResult::warn("tunnel", "no tunnel-client.json present (tunnel not deployed)");
    };
    let age = now - mtime;
    if age <= max_age_secs {
        CheckResult::ok("tunnel", format!("tunnel-client config refreshed {age}s ago"))
    } else {
        CheckResult::warn(
            "tunnel",
            format!("tunnel-client config is {age}s old (> {max_age_secs}s)"),
        )
    }
}

/// Check 8: workspace snapshot age.
pub fn check_workspace_snapshot_age(snapshots_dir: &Path, max_age_secs: i64, now: i64) -> CheckResult {
    let Some(newest) = newest_snapshot(snapshots_dir) else {
        return CheckResult::warn(
            "workspace-snapshot",
            format!("no scheduled workspace snapshots in {}", snapshots_dir.display()),
        );
    };
    let Some(created) = snapshot_created_unix(&newest) else {
        return CheckResult::warn(
            "workspace-snapshot",
            format!("cannot read snapshot timestamp: {}", newest.display()),
        );
    };
    let age = now - created as i64;
    if age <= max_age_secs {
        CheckResult::ok(
            "workspace-snapshot",
            format!("newest snapshot {age}s ago: {}", newest.display()),
        )
    } else {
        CheckResult::warn(
            "workspace-snapshot",
            format!("newest snapshot is {age}s old (> {max_age_secs}s): {}", newest.display()),
        )
    }
}

/// Newest `.dyb-snapshot.json` under a snapshots dir (by file mtime).
pub fn newest_snapshot(snapshots_dir: &Path) -> Option<PathBuf> {
    let mut best: Option<(i64, PathBuf)> = None;
    let entries = std::fs::read_dir(snapshots_dir).ok()?;
    for e in entries.flatten() {
        let p = e.path();
        if !p.file_name().and_then(|s| s.to_str()).map(|s| s.ends_with(".dyb-snapshot.json")).unwrap_or(false) {
            continue;
        }
        if let Some(mtime) = file_mtime_unix(&p) {
            match best {
                Some((best_m, _)) if mtime <= best_m => {}
                _ => best = Some((mtime, p)),
            }
        }
    }
    best.map(|(_, p)| p)
}

/// Parse the `created_unix` field out of a snapshot file.
pub fn snapshot_created_unix(path: &Path) -> Option<u64> {
    let text = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    v.get("created_unix")?.as_u64()
}

// ----------------------------------------------------------------------------
// Orchestration + rendering
// ----------------------------------------------------------------------------

/// Options that parameterize checks that need thresholds.
#[derive(Debug, Clone)]
pub struct DoctorOptions {
    pub profile_id: String,
    pub now_unix: i64,
    pub tunnel_max_age_secs: i64,
    pub snapshot_max_age_secs: i64,
}

impl Default for DoctorOptions {
    fn default() -> Self {
        Self {
            profile_id: "default".to_string(),
            now_unix: crate::store::now_ts() as i64,
            tunnel_max_age_secs: 24 * 3600,
            snapshot_max_age_secs: 12 * 3600,
        }
    }
}

/// Run the full doctor battery.
pub fn run_doctor(opts: &DoctorOptions) -> DoctorReport {
    let mut results = Vec::new();
    let mem = crate::store::mem_dir();
    let backups = crate::backup::backup_dir();
    let snapshots = mem.join("snapshots");

    results.push(check_manifest_all_profiles());
    results.push(check_token_permissions(&opts.profile_id));

    let state = crate::daemon::load_daemon_state(&opts.profile_id);
    results.push(check_autosync_freshness(
        &opts.profile_id,
        state.last_backup_ts,
        opts.now_unix,
    ));

    results.push(check_latest_backup_verifies(&backups));
    results.push(check_disk_headroom(&mem));
    results.push(check_daemon_heartbeat(&opts.profile_id, opts.now_unix));
    results.push(check_tunnel_recently_ok(
        &opts.profile_id,
        opts.tunnel_max_age_secs,
        opts.now_unix,
    ));
    results.push(check_workspace_snapshot_age(
        &snapshots,
        opts.snapshot_max_age_secs,
        opts.now_unix,
    ));

    DoctorReport {
        checked_at_unix: opts.now_unix as u64,
        results,
    }
}

/// Render the report as a deterministic single-page card.
pub fn doctor_to_markdown(report: &DoctorReport) -> String {
    let mut out = String::new();
    let overall = report.overall();
    out.push_str(&format!(
        "# DastYab doctor — {}\n",
        overall.label()
    ));
    out.push_str(&format!("Checked at {}\n\n", report.checked_at_unix));
    out.push_str("| Check | Status | Detail |\n");
    out.push_str("|-------|--------|--------|\n");
    for r in &report.results {
        out.push_str(&format!(
            "| {} | {} | {} |\n",
            r.name,
            r.status.label(),
            r.detail.replace('|', "\\|")
        ));
    }
    out.push_str(&format!("\nOverall: {}\n", overall.label()));
    out
}

/// Serialize the report as JSON (deterministic).
pub fn doctor_to_json(report: &DoctorReport) -> Result<String, CFError> {
    serde_json::to_string_pretty(report).map_err(|e| {
        CFError::new(
            "Doctor error",
            format!("Cannot serialize doctor report: {e}"),
            "Internal error.",
        )
    })
}

/// A compact, banner-friendly summary of a doctor report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustBanner {
    /// "All systems green" | "1 warning" | "2 failures" (deterministic).
    pub text: String,
    pub severity: CheckStatus,
    /// True when there is something worth expanding (warnings/failures).
    pub expandable: bool,
}

/// Pure formatter: turn a report into a one-line banner.
pub fn summarize_doctor(report: &DoctorReport) -> TrustBanner {
    let warns = report.results.iter().filter(|r| r.status == CheckStatus::Warn).count();
    let fails = report.results.iter().filter(|r| r.status == CheckStatus::Fail).count();
    let severity = report.overall();
    let text = match severity {
        CheckStatus::Ok => "All systems green".to_string(),
        CheckStatus::Warn => {
            if warns == 1 {
                "1 warning".to_string()
            } else {
                format!("{warns} warnings")
            }
        }
        CheckStatus::Fail => {
            if fails == 1 {
                "1 failure".to_string()
            } else {
                format!("{fails} failures")
            }
        }
    };
    TrustBanner {
        text,
        severity,
        expandable: warns > 0 || fails > 0,
    }
}

#[cfg(test)]
mod summarize_tests {
    use super::*;

    fn report_with(statuses: &[CheckStatus]) -> DoctorReport {
        let results = statuses
            .iter()
            .enumerate()
            .map(|(i, st)| CheckResult {
                name: format!("check{i}"),
                status: *st,
                detail: String::new(),
            })
            .collect();
        DoctorReport {
            checked_at_unix: 0,
            results,
        }
    }

    #[test]
    fn summarize_all_green() {
        let b = summarize_doctor(&report_with(&[CheckStatus::Ok, CheckStatus::Ok]));
        assert_eq!(b.severity, CheckStatus::Ok);
        assert_eq!(b.text, "All systems green");
        assert!(!b.expandable);
    }

    #[test]
    fn summarize_singular_warning() {
        let b = summarize_doctor(&report_with(&[CheckStatus::Ok, CheckStatus::Warn]));
        assert_eq!(b.severity, CheckStatus::Warn);
        assert_eq!(b.text, "1 warning");
        assert!(b.expandable);
    }

    #[test]
    fn summarize_plural_failures() {
        let b = summarize_doctor(&report_with(&[
            CheckStatus::Fail,
            CheckStatus::Fail,
            CheckStatus::Ok,
        ]));
        assert_eq!(b.severity, CheckStatus::Fail);
        assert_eq!(b.text, "2 failures");
        assert!(b.expandable);
    }
}

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

    #[test]
    fn doctor_all_ok_reports_ok() {
        with_home(|_| {
            let id = fresh_profile_id();
            // Realistic "now" (2026-ish) so mtimes of just-written files are
            // fresh relative to it.
            let now = 1_750_000_000i64;

            // Seed durable artifacts (token/accounts/config) so the profile is
            // a realistic "healthy" one.
            let dir = crate::store::profiles::profile_dir(&id);
            std::fs::write(dir.join("token.json"), b"{\"t\":\"abc\"}").unwrap();
            std::fs::write(dir.join("accounts.json"), b"{\"a\":1}").unwrap();
            std::fs::write(dir.join("config.json"), b"{\"x\":1}").unwrap();
            std::fs::write(dir.join("tunnel-client.json"), b"{\"tunnel\":1}").unwrap();
            crate::manifest::write_manifest(&crate::manifest::build_manifest(&id).unwrap()).unwrap();

            // A fresh daemon beacon (within the 900s heartbeat window).
            let mut beacon = crate::health_beacon::HealthBeacon::new(
                crate::health_beacon::CycleKind::Monitor,
                now - 700,
            );
            beacon.written_at = now - 700;
            crate::health_beacon::write_beacon(&id, &beacon).unwrap();

            // A verifying per-profile backup.
            let bdir = crate::backup::backup_dir();
            std::fs::create_dir_all(&bdir).unwrap();
            let val = crate::store::profiles::export_profile(&id).unwrap();
            let backup_path = bdir.join("good.json");
            std::fs::write(&backup_path, serde_json::to_string_pretty(&val).unwrap()).unwrap();
            filetime::set_file_mtime(
                &backup_path,
                filetime::FileTime::from_unix_time(now - 500, 0),
            )
            .unwrap();

            // A recent workspace snapshot in the actual snapshots dir.
            let snapshots = crate::store::mem_dir().join("snapshots");
            std::fs::create_dir_all(&snapshots).unwrap();
            let snap = crate::workspace_snapshot::snapshot_workspace(
                crate::store::mem_dir().as_path(),
                crate::workspace_snapshot::SnapshotKind::Full,
                (now - 200) as u64,
            )
            .unwrap();
            let snap_path = snapshots.join(format!("{}-snapshot.dyb-snapshot.json", now - 200));
            crate::workspace_snapshot::write_snapshot_atomic(&snap, &snap_path).unwrap();
            filetime::set_file_mtime(
                &snap_path,
                filetime::FileTime::from_unix_time(now - 200, 0),
            )
            .unwrap();

            // Enable autosync and record a recent auto-backup in daemon state.
            {
                let mut p = crate::store::profiles::load_profile(&id);
                p.config.backup_autosync.enabled = true;
                p.config.backup_autosync.interval_secs = 3600;
                crate::store::profiles::save_profile(&p).unwrap();
                let mut st = crate::daemon::load_daemon_state(&id);
                st.last_backup_ts = now - 500;
                crate::daemon::save_daemon_state(&id, &st).unwrap();
            }

            // Rebuild the manifest AFTER every on-disk change (beacon, config,
            // tunnel-client) so nothing is flagged extra/changed.
            crate::manifest::write_manifest(&crate::manifest::build_manifest(&id).unwrap()).unwrap();

            let opts = DoctorOptions {
                profile_id: id,
                now_unix: now,
                tunnel_max_age_secs: 3600,
                snapshot_max_age_secs: 3600,
            };
            let report = run_doctor(&opts);
            for r in &report.results {
                assert!(
                    r.status != CheckStatus::Fail,
                    "check {:?} failed: {}",
                    r.name,
                    r.detail
                );
            }
            assert_eq!(report.overall(), CheckStatus::Ok, "{:?}", report.results);
        });
    }

    #[test]
    fn doctor_missing_manifest_fails() {
        with_home(|_| {
            let id = fresh_profile_id();
            crate::manifest::write_manifest(&crate::manifest::build_manifest(&id).unwrap()).unwrap();
            // Remove the manifest file (simulates a tamper/loss).
            std::fs::remove_file(crate::manifest::manifest_path(&id)).unwrap();
            let r = check_manifest_all_profiles();
            assert_eq!(r.status, CheckStatus::Fail);
        });
    }

    #[cfg(unix)]
    #[test]
    fn doctor_world_readable_token_warns() {
        use std::os::unix::fs::PermissionsExt;
        with_home(|_| {
            let id = fresh_profile_id();
            let tp = crate::store::profiles::profile_dir(&id).join("token.json");
            std::fs::write(&tp, b"{\"t\":\"x\"}").unwrap();
            std::fs::set_permissions(&tp, std::fs::Permissions::from_mode(0o644)).unwrap();
            let r = check_token_permissions(&id);
            assert_eq!(r.status, CheckStatus::Warn);
            std::fs::set_permissions(&tp, std::fs::Permissions::from_mode(0o600)).unwrap();
            let r2 = check_token_permissions(&id);
            assert_eq!(r2.status, CheckStatus::Ok);
        });
    }

    #[test]
    fn doctor_stale_autosync_warns() {
        with_home(|_| {
            let id = fresh_profile_id();
            {
                let mut p = crate::store::profiles::load_profile(&id);
                p.config.backup_autosync.enabled = true;
                p.config.backup_autosync.interval_secs = 10;
                crate::store::profiles::save_profile(&p).unwrap();
            }
            // Interval 10s → fresh means within 20s. last=100, now=1000 =>
            // age 900 >> 20 → stale → Warn.
            let r = check_autosync_freshness(&id, 100, 1000);
            assert_eq!(r.status, CheckStatus::Warn);
            // last=985, now=1000 => age 15 ≤ 20 → fresh → Ok.
            let r2 = check_autosync_freshness(&id, 985, 1000);
            assert_eq!(r2.status, CheckStatus::Ok);
        });
    }

    #[test]
    fn doctor_unverifiable_backup_fails() {
        with_home(|root| {
            let bdir = root.join("backups");
            std::fs::create_dir_all(&bdir).unwrap();
            std::fs::write(bdir.join("bad.json"), b"this is not json").unwrap();
            let r = check_latest_backup_verifies(&bdir);
            assert_eq!(r.status, CheckStatus::Fail);
        });
    }

    #[test]
    fn doctor_overall_is_worst_status() {
        let rep = DoctorReport {
            checked_at_unix: 0,
            results: vec![
                CheckResult::ok("a", "x"),
                CheckResult::warn("b", "y"),
                CheckResult::fail("c", "z"),
            ],
        };
        assert_eq!(rep.overall(), CheckStatus::Fail);
        let rep2 = DoctorReport {
            checked_at_unix: 0,
            results: vec![CheckResult::ok("a", "x"), CheckResult::warn("b", "y")],
        };
        assert_eq!(rep2.overall(), CheckStatus::Warn);
    }

    #[test]
    fn doctor_markdown_deterministic_for_same_input() {
        let rep = DoctorReport {
            checked_at_unix: 42,
            results: vec![
                CheckResult::ok("manifest", "all verified"),
                CheckResult::warn("tunnel", "no tunnel-client.json present"),
            ],
        };
        let a = doctor_to_markdown(&rep);
        let b = doctor_to_markdown(&rep);
        assert_eq!(a, b);
        assert!(a.contains("manifest"));
        assert!(a.contains("warn"));
    }

    #[test]
    fn doctor_backup_bundle_verifies_accepts_real_export() {
        use serde_json::json;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("good.json");
        std::fs::write(
            &p,
            serde_json::to_string_pretty(&json!({
                "meta": {"id": "default", "name": "default"},
                "tokens": {}
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(backup_bundle_verifies(&p));
        let bad = dir.path().join("bad.json");
        std::fs::write(&bad, "{}").unwrap();
        assert!(!backup_bundle_verifies(&bad));
    }
}
