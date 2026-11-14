//! Cycle stage guards.
//!
//! A guarded autopilot cycle runs inside a tokio timeout so that a network
//! probe that blocks forever (a censored-network hang) cannot stall the daemon
//! indefinitely. The guard records which pipeline stage was last entered in a
//! marker file (via the store's `write_json` idiom, so it round-trips); when a
//! cycle times out, the abort path writes a health beacon with `last_error =
//! "CycleTimeout"` and `last_stage` = the stage the cycle was stuck in. This
//! turns an invisible hang into a diagnosable, recoverable failure.

use std::path::PathBuf;

use crate::error::CFError;
use crate::store;

/// Hard cap for a full discovery cycle (seconds). Discovery is the long pole:
/// native scan + WS-gate + E2E. If it exceeds this, the guarded wrapper aborts
/// and writes an abort beacon naming the stage it was stuck in.
pub const DISCOVERY_TIMEOUT_SECS: u64 = 600;
/// Hard cap for a monitor cycle (seconds). The light WS-gate check is fast; a
/// deep E2E pass must still fit well inside this.
pub const MONITOR_TIMEOUT_SECS: u64 = 120;

/// A named pipeline stage inside a discovery/monitor cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CycleStage {
    /// Nothing entered yet.
    None,
    /// Bundle reconciliation / pre-flight.
    Reconcile,
    /// Resolving the v2 strategy + building params.
    Prepare,
    /// Reading the base vless config.
    BaseVless,
    /// Running discovery (native scanner / slipscan pipeline).
    Phase1Scan,
    /// Phase-2 WS-gate scoring.
    Phase2Scan,
    /// E2E tunnel verification.
    E2e,
    /// Writing the ledger.
    LedgerWrite,
    /// Writing the user bundle / active configs.
    BundleWrite,
    /// Monitor tier-1 light check (per-endpoint WS-gate sweep).
    LightCheck,
    /// Monitor tier-2 deep discovery pass.
    DeepCheck,
    /// Monitor E2E verification step.
    E2eVerify,
}

impl CycleStage {
    /// The file name used for the marker.
    fn marker_path(profile_id: &str) -> PathBuf {
        store::profiles::profile_dir(profile_id).join("stage.json")
    }

    fn as_str(self) -> &'static str {
        match self {
            CycleStage::None => "none",
            CycleStage::Reconcile => "reconcile",
            CycleStage::Prepare => "prepare",
            CycleStage::BaseVless => "base_vless",
            CycleStage::Phase1Scan => "phase1_scan",
            CycleStage::Phase2Scan => "phase2_scan",
            CycleStage::E2e => "e2e",
            CycleStage::LedgerWrite => "ledger_write",
            CycleStage::BundleWrite => "bundle_write",
            CycleStage::LightCheck => "light_check",
            CycleStage::DeepCheck => "deep_check",
            CycleStage::E2eVerify => "e2e_verify",
        }
    }

    fn from_str(s: &str) -> CycleStage {
        match s {
            "reconcile" => CycleStage::Reconcile,
            "prepare" => CycleStage::Prepare,
            "base_vless" => CycleStage::BaseVless,
            "phase1_scan" => CycleStage::Phase1Scan,
            "phase2_scan" => CycleStage::Phase2Scan,
            "e2e" => CycleStage::E2e,
            "ledger_write" => CycleStage::LedgerWrite,
            "bundle_write" => CycleStage::BundleWrite,
            "light_check" => CycleStage::LightCheck,
            "deep_check" => CycleStage::DeepCheck,
            "e2e_verify" => CycleStage::E2eVerify,
            _ => CycleStage::None,
        }
    }
}

/// Mark the current stage. Called at the top of each stage-entering line.
pub fn mark_stage(profile_id: &str, stage: CycleStage) -> Result<(), CFError> {
    store::write_json(
        &CycleStage::marker_path(profile_id),
        &stage.as_str().to_string(),
    )
}

/// Read the last-written stage (None when missing).
pub fn last_stage(profile_id: &str) -> Option<CycleStage> {
    let p = CycleStage::marker_path(profile_id);
    if !p.exists() {
        return None;
    }
    let s: String = store::read_or_default(&p);
    Some(CycleStage::from_str(&s))
}

/// Clear the stage marker (called on a successful cycle).
pub fn clear_stage(profile_id: &str) -> Result<(), CFError> {
    store::write_json(
        &CycleStage::marker_path(profile_id),
        &CycleStage::None.as_str().to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rescue_home() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(tmp.path().join(".dastyab"));
        tmp
    }

    fn make_profile() -> String {
        crate::store::profiles::create_profile("cg", "").unwrap()
    }

    #[test]
    fn test_mark_stage_writes_marker() {
        let _home = rescue_home();
        let id = make_profile();
        mark_stage(&id, CycleStage::Phase2Scan).unwrap();
        assert_eq!(last_stage(&id), Some(CycleStage::Phase2Scan));
    }

    #[test]
    fn test_last_stage_reads_marker() {
        let _home = rescue_home();
        let id = make_profile();
        mark_stage(&id, CycleStage::E2e).unwrap();
        assert_eq!(last_stage(&id), Some(CycleStage::E2e));
    }

    #[test]
    fn test_last_stage_none_when_missing() {
        let _home = rescue_home();
        let id = make_profile();
        assert_eq!(last_stage(&id), None);
    }

    #[test]
    fn test_clear_stage_removes_marker() {
        let _home = rescue_home();
        let id = make_profile();
        mark_stage(&id, CycleStage::LedgerWrite).unwrap();
        clear_stage(&id).unwrap();
        assert_eq!(last_stage(&id), Some(CycleStage::None));
    }

    #[test]
    fn test_cycle_stage_roundtrips_through_json() {
        let _home = rescue_home();
        let id = make_profile();
        for stage in [
            CycleStage::Reconcile,
            CycleStage::Prepare,
            CycleStage::BaseVless,
            CycleStage::Phase1Scan,
            CycleStage::Phase2Scan,
            CycleStage::E2e,
            CycleStage::LedgerWrite,
            CycleStage::BundleWrite,
            CycleStage::LightCheck,
            CycleStage::DeepCheck,
            CycleStage::E2eVerify,
        ] {
            mark_stage(&id, stage).unwrap();
            assert_eq!(last_stage(&id), Some(stage), "roundtrip {stage:?}");
        }
    }
}
