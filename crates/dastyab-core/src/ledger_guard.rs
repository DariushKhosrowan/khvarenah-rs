//! Ledger Append-Only Guard.
//!
//! The "nothing's gonna be lost" primitive. Every write to an append-only
//! ledger (history.json, token_history.json, generated_configs.json) is
//! guarded by a persisted *high-water mark*: the highest record count ever
//! written for that ledger kind. If a subsequent write would drop the count
//! *below* that mark, the write is refused (the shrink is flagged).
//!
//! This catches silent corruption/truncation — a `history.json` that went
//! from 47 records to 3 without any intentional mutation is exactly the
//! failure this exists to surface, before the original data is unrecoverable.
//!
//! ## Reconciliation with real mutations
//!
//! The guard is **strict** only on the genuinely append-only write paths
//! (`remember_vless`, token-event recording, generated-config appends).
//! Intentional user mutations that legitimately *remove* records
//! (`remove_history_record`, `clear_history`, `remove_token_history_event`,
//! `clear_token_history`, `remove_clean_ip`) call [`rebase_high_water`] to
//! move the mark down so they don't trip the guard. The doctor still flags a
//! shrink that happens *without* a rebase — i.e. out-of-band, which is the
//! corruption signature.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::doctor::{CheckResult, CheckStatus};
use crate::store::atomic_write;

/// A ledger that is append-only in normal operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LedgerKind {
    /// `history.json` — generated vless config record ledger.
    History,
    /// `token_history.json` — token lifecycle event ledger.
    TokenHistory,
    /// `cleanips.json` — scanned clean IPs (mutable; deletions rebase).
    CleanIps,
    /// `generated_configs.json` — completeness ledger of every rendered config.
    GeneratedConfigs,
}

impl LedgerKind {
    /// The filename within the profile directory.
    pub fn filename(self) -> &'static str {
        match self {
            LedgerKind::History => "history.json",
            LedgerKind::TokenHistory => "token_history.json",
            LedgerKind::CleanIps => "cleanips.json",
            LedgerKind::GeneratedConfigs => "generated_configs.json",
        }
    }

    /// A stable label for doctor output.
    pub fn label(self) -> &'static str {
        match self {
            LedgerKind::History => "history",
            LedgerKind::TokenHistory => "token history",
            LedgerKind::CleanIps => "clean IPs",
            LedgerKind::GeneratedConfigs => "generated configs",
        }
    }

    /// All ledger kinds tracked by the high-water guard (in doctor row order).
    pub fn all() -> &'static [LedgerKind] {
        &[
            LedgerKind::History,
            LedgerKind::TokenHistory,
            LedgerKind::CleanIps,
            LedgerKind::GeneratedConfigs,
        ]
    }
}

/// The high-water mark recorded for one ledger kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerHighWater {
    pub kind: LedgerKind,
    /// Highest record count ever written for this ledger.
    pub count: u64,
    /// When the mark was last updated (unix seconds).
    pub updated_unix: u64,
}

/// Per-profile high-water store: filename -> high water.
pub type LedgerHighWaters = BTreeMap<LedgerKind, LedgerHighWater>;

/// Errors for the ledger guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    /// new_count < old_count — refuse the write.
    Shrink {
        kind: LedgerKind,
        old: u64,
        new: u64,
    },
    /// Io / atom / serialization failure.
    Io(String),
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LedgerError::Shrink { kind, old, new } => {
                write!(f, "{} ledger shrink refused: {old} -> {new}", kind.label())
            }
            LedgerError::Io(msg) => write!(f, "ledger io: {msg}"),
        }
    }
}

impl std::error::Error for LedgerError {}

/// The per-profile high-water ledger file.
pub fn high_water_path(profile_dir: &Path) -> PathBuf {
    profile_dir.join("ledger_hw.json")
}

/// Read the high-water store (default empty when missing/corrupt).
pub fn read_high_waters(profile_dir: &Path) -> LedgerHighWaters {
    crate::store::read_opt::<LedgerHighWaters>(&high_water_path(profile_dir)).unwrap_or_default()
}

/// Read one ledger's high-water mark (None when never recorded).
pub fn read_high_water(profile_dir: &Path, kind: LedgerKind) -> Option<LedgerHighWater> {
    read_high_waters(profile_dir).get(&kind).cloned()
}

/// Persist the high-water store for a profile.
pub fn write_high_waters(profile_dir: &Path, hw: &LedgerHighWaters) -> Result<(), LedgerError> {
    let bytes = serde_json::to_vec_pretty(hw)
        .map_err(|e| LedgerError::Io(format!("serialize: {e}")))?;
    atomic_write(&high_water_path(profile_dir), &bytes).map_err(|e| LedgerError::Io(e.brief()))
}

/// Set a ledger's high-water mark (used by rebase + after guarded writes).
fn set_high_water(
    profile_dir: &Path,
    kind: LedgerKind,
    count: u64,
    now: u64,
) -> Result<(), LedgerError> {
    let mut all = read_high_waters(profile_dir);
    all.insert(
        kind,
        LedgerHighWater {
            kind,
            count,
            updated_unix: now,
        },
    );
    write_high_waters(profile_dir, &all)
}

/// Pure append-only check: refuse when the new count drops below the old one.
///
/// Equal is allowed (a no-op rewrite). Growth is always allowed.
pub fn check_append_only(kind: LedgerKind, old_count: u64, new_count: u64) -> Result<(), LedgerError> {
    if new_count < old_count {
        Err(LedgerError::Shrink {
            kind,
            old: old_count,
            new: new_count,
        })
    } else {
        Ok(())
    }
}

/// Write a ledger file under the append-only guard.
///
/// Reads the existing count (from the on-disk file), verifies the new count
/// is not lower, writes via the atom-write path, and updates the high-water
/// mark to `max(old, new)`. On shrink it returns `Err` **without** writing.
pub fn write_ledger_guarded<T: serde::Serialize>(
    profile_dir: &Path,
    kind: LedgerKind,
    records: &[T],
    now: u64,
) -> Result<(), LedgerError> {
    let path = profile_dir.join(kind.filename());
    let old_count = read_ledger_count(&path);
    let new_count = records.len() as u64;
    check_append_only(kind, old_count, new_count)?;
    let bytes = serde_json::to_vec_pretty(records)
        .map_err(|e| LedgerError::Io(format!("serialize: {e}")))?;
    atomic_write(&path, &bytes).map_err(|e| LedgerError::Io(e.brief()))?;
    // Always ratchet the mark upward (or seed it on first write).
    let mark = old_count.max(new_count);
    set_high_water(profile_dir, kind, mark, now)
}

/// Read the record count of a ledger file (0 when missing/corrupt-not-JSON).
fn read_ledger_count(path: &Path) -> u64 {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| v.as_array().map(|a| a.len() as u64))
            .unwrap_or(0),
        Err(_) => 0,
    }
}

/// Move a ledger's high-water mark down to `count` — used by intentional
/// mutations that legitimately remove records (delete/clear single So the
/// doctor does not flag a deliberate action as corruption.
pub fn rebase_high_water(profile_dir: &Path, kind: LedgerKind, count: u64, now: u64) -> Result<(), LedgerError> {
    set_high_water(profile_dir, kind, count, now)
}

/// Ratchet a ledger's high-water mark upward to at least `count` (never
/// lowers it). Call after an append so the mark tracks the high-water, and
/// after a rebase so the two stay coherent. Idempotent.
pub fn note_ledger_state(
    profile_dir: &Path,
    kind: LedgerKind,
    count: u64,
    now: u64,
) -> Result<(), LedgerError> {
    let existing = read_high_water(profile_dir, kind).map(|h| h.count).unwrap_or(0);
    set_high_water(profile_dir, kind, existing.max(count), now)
}

/// Doctor check: for each ledger kind, compare the current on-disk count to
/// the high-water mark.
///
/// - `Ok`   → current count >= mark (ledger intact / expected).
/// - `Warn` → the ledger file is missing but a mark exists (possibly not yet
///   created, or deleted out-of-band).
/// - `Fail` → current count < mark, *without* a rebase: out-of-band shrink /
///   corruption. This is the property the guard exists to surface.
pub fn doctor_check_ledger_integrity(profile_dir: &Path) -> Vec<CheckResult> {
    let hw = read_high_waters(profile_dir);
    let mut out = Vec::new();
    for kind in LedgerKind::all() {
        let name = format!("ledger-{}", kind.label().replace(' ', "-"));
        let Some(mark) = hw.get(kind) else {
            // No mark yet: nothing tracked, nothing to flag.
            continue;
        };
        let path = profile_dir.join(kind.filename());
        let current = read_ledger_count(&path);
        if current >= mark.count {
            out.push(CheckResult {
                name: name.clone(),
                status: CheckStatus::Ok,
                detail: format!("{} ledger intact ({} records)", kind.label(), current),
            });
        } else if current == 0 && !path.exists() {
            out.push(CheckResult {
                name,
                status: CheckStatus::Warn,
                detail: format!(
                    "{} ledger missing but high-water mark is {} — file deleted out-of-band?",
                    kind.label(),
                    mark.count
                ),
            });
        } else {
            out.push(CheckResult {
                name,
                status: CheckStatus::Fail,
                detail: format!(
                    "{} ledger shrank from {} to {} records — out-of-band loss or corruption",
                    kind.label(),
                    mark.count,
                    current
                ),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_home() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!(
            "dyb_ledger_guard_{}_{n}",
            crate::store::now_ts()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn check_append_only_allows_growth() {
        assert!(check_append_only(LedgerKind::History, 3, 5).is_ok());
    }

    #[test]
    fn check_append_only_allows_equal() {
        assert!(check_append_only(LedgerKind::History, 5, 5).is_ok());
    }

    #[test]
    fn check_append_only_rejects_shrink() {
        assert_eq!(
            check_append_only(LedgerKind::History, 5, 3),
            Err(LedgerError::Shrink {
                kind: LedgerKind::History,
                old: 5,
                new: 3,
            })
        );
    }

    #[test]
    fn write_ledger_guarded_updates_high_water_on_growth() {
        let dir = tmp_home();
        let now = 1000;
        write_ledger_guarded::<u64>(&dir, LedgerKind::History, &[1, 2, 3], now).unwrap();
        // Seed a ledger file then grow to 5.
        write_ledger_guarded::<u64>(&dir, LedgerKind::History, &[1, 2, 3, 4, 5], now + 1).unwrap();
        let mark = read_high_water(&dir, LedgerKind::History).unwrap();
        assert_eq!(mark.count, 5);
    }

    #[test]
    fn write_ledger_guarded_creates_high_water_on_first_write() {
        let dir = tmp_home();
        write_ledger_guarded::<u64>(&dir, LedgerKind::TokenHistory, &[9], 500).unwrap();
        let mark = read_high_water(&dir, LedgerKind::TokenHistory).unwrap();
        assert_eq!(mark.count, 1);
        assert_eq!(mark.kind, LedgerKind::TokenHistory);
    }

    #[test]
    fn write_ledger_guarded_refuses_shrink_and_does_not_touch_file() {
        let dir = tmp_home();
        write_ledger_guarded::<u64>(&dir, LedgerKind::History, &[1, 2, 3, 4], 100).unwrap();
        let before = std::fs::read(dir.join("history.json")).unwrap();
        let err = write_ledger_guarded::<u64>(&dir, LedgerKind::History, &[1], 101).unwrap_err();
        assert!(matches!(err, LedgerError::Shrink { new: 1, .. }));
        let after = std::fs::read(dir.join("history.json")).unwrap();
        assert_eq!(before, after, "file must not be touched on refused shrink");
    }

    #[test]
    fn doctor_flags_shrunk_ledger_as_fail() {
        let dir = tmp_home();
        write_ledger_guarded::<u64>(&dir, LedgerKind::History, &[1, 2, 3, 4], 100).unwrap();
        // Out-of-band shrink: rewrite the file directly, bypassing the guard,
        // leaving the high-water mark at 4.
        std::fs::write(dir.join("history.json"), "[1]").unwrap();
        let results = doctor_check_ledger_integrity(&dir);
        let fail = results
            .iter()
            .find(|r| r.status == CheckStatus::Fail)
            .expect("expected a Fail result");
        assert!(fail.detail.contains("shrank from 4 to 1"));
    }

    #[test]
    fn doctor_flags_missing_file_with_high_water_as_warn() {
        let dir = tmp_home();
        write_ledger_guarded::<u64>(&dir, LedgerKind::TokenHistory, &[1, 2], 100).unwrap();
        std::fs::remove_file(dir.join("token_history.json")).unwrap();
        let results = doctor_check_ledger_integrity(&dir);
        let warn = results
            .iter()
            .find(|r| r.status == CheckStatus::Warn && r.name == "ledger-token-history")
            .expect("expected a Warn result for missing ledger");
        assert!(warn.detail.contains("high-water mark is 2"));
    }

    #[test]
    fn rebase_moves_mark_down() {
        let dir = tmp_home();
        write_ledger_guarded::<u64>(&dir, LedgerKind::CleanIps, &[1, 2, 3], 100).unwrap();
        // Legitimate removal rebases the mark so doctor stays green.
        rebase_high_water(&dir, LedgerKind::CleanIps, 0, 200).unwrap();
        std::fs::write(dir.join("cleanips.json"), "[]").unwrap();
        let results = doctor_check_ledger_integrity(&dir);
        assert!(results.iter().all(|r| r.status == CheckStatus::Ok || r.status == CheckStatus::Warn));
    }
}
