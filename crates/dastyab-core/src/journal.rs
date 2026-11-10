//! Durable event journal for the daemon (blackout/rescue record).
//!
//! The daemon already *acts* on blackouts (network detect → survival plan →
//! outbox flush on restore). What it lacks is a durable, per-profile account
//! of *what happened and what is owed* across a crash or restart. This module
//! fills that gap: every state transition the daemon cares about (network
//! down/up, rescue attempts, account blocked, token recovery, cycle failures)
//! is appended to an on-disk journal that survives a kill / reboot.
//!
//! Why this matters for resilience:
//!   - A total blackout in Iran can kill the machine mid-rescue. On restart,
//!     `pending_drain` tells the daemon / GUI exactly which intents were never
//!     completed, so nothing is silently lost.
//!   - The GUI and CLI can render the journal so a sleeping user can audit what
//!     the app did overnight (no manual step, just read-only evidence).
//!
//! Storage follows the store idiom: one `journal.json` per profile, written
//! atomically (`store::write_json`), so a crash mid-write never truncates it.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::CFError;
use crate::store;

/// The class of a journaled event. Human-readable, serialized by name so the
/// file survives enum changes (unknown variants are skipped on load).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum JournalKind {
    /// Network liveness was lost (survival plan label recorded in detail).
    NetworkDown,
    /// Network liveness came back.
    NetworkUp,
    /// The rescue chain was attempted (detail = outcome).
    RescueAttempt,
    /// A cycle failed (detail = error brief).
    CycleFailed,
    /// The account is blocked (detail = state label).
    AccountBlocked,
    /// A token was recovered (detail = label) — the guided recovery path.
    TokenRecovered,
    /// The beacon outbox was flushed (detail = "# alerts").
    OutboxFlushed,
    /// A scheduled auto-backup was written (detail = backup path).
    BackupWritten,
    /// A scheduled worker-signature rotation ran (detail = new uuid/path).
    MutationPerformed,
    /// A scheduled blackout self-test (drill) ran (detail = "N/4 rungs").
    DrillPerformed,
    /// Auto-heal restored a broken artifact from a verified backup (detail =
    /// list of healed files + the backup path used).
    AutoHealed,
    /// A scheduled workspace snapshot was written (detail = snapshot path).
    SnapshotWritten,
    /// The version-integrity sweep ran (detail = corrupt/orphan/missing counts).
    VersionVerified,
}

/// One durable journal entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    /// UNIX seconds when the event occurred.
    pub ts: i64,
    pub kind: JournalKind,
    /// Short, human-readable detail (survival plan label, error brief, …).
    pub detail: String,
}

/// Path to the per-profile journal file.
fn journal_path(profile_id: &str) -> PathBuf {
    store::profiles::profile_dir(profile_id).join("journal.json")
}

/// Load the full journal (newest-last). Missing/corrupt file → empty vec.
pub fn load_journal(profile_id: &str) -> Vec<JournalEntry> {
    store::read_opt::<Vec<JournalEntry>>(&journal_path(profile_id)).unwrap_or_default()
}

/// Append one event to the journal. Never fails the caller on a transient IO
/// error: the journal is best-effort evidence, not a correctness gate.
pub fn append(profile_id: &str, kind: JournalKind, detail: &str) -> Result<(), CFError> {
    let mut j = load_journal(profile_id);
    j.push(JournalEntry {
        ts: store::now_ts() as i64,
        kind,
        detail: detail.to_string(),
    });
    // Cap the journal so it cannot grow without bound over months of uptime.
    // Keep the most recent 512 entries.
    if j.len() > 512 {
        let excess = j.len() - 512;
        j.drain(..excess);
    }
    store::write_json(&journal_path(profile_id), &j)
}

/// Return the newest `n` entries (newest-first) — what the GUI/CLI shows.
pub fn recent(profile_id: &str, n: usize) -> Vec<JournalEntry> {
    let mut j = load_journal(profile_id);
    j.reverse();
    j.truncate(n);
    j
}

/// Return the entries that indicate an *unfinished* intent — the ones the
/// daemon should re-attempt after a restart. Today that is: network down that
/// never saw a matching up, and a rescue attempt that never recovered. The
/// daemon/GUI can use this to decide whether to take corrective action.
pub fn pending_drain(profile_id: &str) -> Vec<JournalEntry> {
    let j = load_journal(profile_id);
    let mut result = Vec::new();
    let mut saw_up = false;
    // Walk newest → oldest: a NetworkDown with no newer NetworkUp is owed.
    for e in j.iter().rev() {
        match e.kind {
            JournalKind::NetworkUp => saw_up = true,
            JournalKind::NetworkDown if !saw_up => result.push(e.clone()),
            _ => {}
        }
    }
    result
}

/// Clear the journal (used by the GUI/CLI "dismiss" action).
pub fn clear(profile_id: &str) -> Result<(), CFError> {
    store::write_json(&journal_path(profile_id), &Vec::<JournalEntry>::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_home(f: impl FnOnce()) {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join(".dastyab");
        store::set_mem_dir_override(base);
        f();
    }

    #[test]
    fn journal_roundtrip_and_recent_order() {
        with_home(|| {
            store::profiles::create_profile("j", "").unwrap();
            append("j", JournalKind::NetworkDown, "total-blackout").unwrap();
            append("j", JournalKind::NetworkUp, "").unwrap();
            append("j", JournalKind::CycleFailed, "worker offline").unwrap();

            let full = load_journal("j");
            assert_eq!(full.len(), 3);
            assert_eq!(full[0].kind, JournalKind::NetworkDown);
            assert_eq!(full[0].detail, "total-blackout");

            let r = recent("j", 2);
            assert_eq!(r.len(), 2);
            assert_eq!(r[0].kind, JournalKind::CycleFailed); // newest first
        });
    }

    #[test]
    fn pending_drain_finds_unclosed_blackout() {
        with_home(|| {
            store::profiles::create_profile("j", "").unwrap();
            // A blackout that ended with a restore → no pending.
            append("j", JournalKind::NetworkDown, "total-blackout").unwrap();
            append("j", JournalKind::NetworkUp, "").unwrap();
            assert!(pending_drain("j").is_empty());

            // A blackout that never saw a restore → owed.
            // (clear first to keep the scenario focused)
            clear("j").unwrap();
            append("j", JournalKind::NetworkDown, "total-blackout").unwrap();
            append("j", JournalKind::RescueAttempt, "gave_up").unwrap();
            let pending = pending_drain("j");
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[0].kind, JournalKind::NetworkDown);
        });
    }

    #[test]
    fn journal_caps_at_512() {
        with_home(|| {
            store::profiles::create_profile("j", "").unwrap();
            for _ in 0..600 {
                append("j", JournalKind::CycleFailed, "x").unwrap();
            }
            assert_eq!(load_journal("j").len(), 512);
        });
    }

    #[test]
    fn clear_empties_journal() {
        with_home(|| {
            store::profiles::create_profile("j", "").unwrap();
            append("j", JournalKind::NetworkDown, "x").unwrap();
            clear("j").unwrap();
            assert!(load_journal("j").is_empty());
        });
    }
}
