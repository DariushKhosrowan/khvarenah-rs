//! Scheduled config mutation: periodically rotate the worker's signature
//! (UUID + deploy) so the app becomes a moving target to stateful DPI.
//!
//! ## Why this exists
//!
//! A long-lived, identical worker UUID/path is the one static signature that a
//! stateful DPI can fingerprint over time. Rotating it on a schedule (default
//! every 24h) turns the config into a moving target without requiring the user
//! to remember to redeploy. Existing active clients keep working until the next
//! time they re-read the bundle.
//!
//! ## Scope / fidelity
//!
//! This implements DeepSeek's plan #2 ("Scheduled Config Mutation") reconciled
//! to the real repo. The actual redeploy reuses the same mechanics as the
//! rescue chain's `redeploy_worker_core` (deploy the worker, then set the UUID
//! var), but additionally records a fresh UUID into the saved VLESS record so
//! downstream discovery/bundle regeneration use the new signature.

use crate::error::CFError;
use crate::vless::VlessProfile;

/// Configuration for scheduled mutation (serde-default → migration-safe).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MutationConfig {
    /// Master switch. When off, no rotation happens.
    #[serde(default)]
    pub enabled: bool,
    /// Seconds between rotations (default 24h).
    #[serde(default = "default_mutation_interval")]
    pub interval_secs: u64,
    /// Rotate the UUID every mutation (always true when enabled).
    #[serde(default = "default_true")]
    pub rotate_uuid: bool,
    /// Rotate the worker path every mutation.
    #[serde(default = "default_true")]
    pub rotate_path: bool,
}

impl Default for MutationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: default_mutation_interval(),
            rotate_uuid: true,
            rotate_path: true,
        }
    }
}

fn default_mutation_interval() -> u64 {
    86400 // 24h
}
fn default_true() -> bool {
    true
}

/// Outcome of one mutation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MutationOutcome {
    /// Previous UUID (before rotation).
    pub old_uuid: String,
    /// New UUID.
    pub new_uuid: String,
    /// Previous worker path.
    pub old_path: String,
    /// New worker path.
    pub new_path: String,
    /// Epoch seconds the mutation was applied.
    pub applied_at: i64,
}

/// Pure decision: should we mutate now?
#[allow(clippy::trivially_copy_pass_by_ref)]
pub fn should_mutate(cfg: &MutationConfig, last_mutation_ts: i64, now: i64) -> bool {
    if !cfg.enabled {
        return false;
    }
    if cfg.interval_secs == 0 {
        return false;
    }
    now - last_mutation_ts >= cfg.interval_secs as i64
}

/// Generate a random 12-char lowercase alphanumeric path segment.
pub fn generate_new_path(rng: &mut impl rand::Rng) -> String {
    const ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    (0..12)
        .map(|_| {
            let i = rng.gen_range(0..ALPHA.len());
            ALPHA[i] as char
        })
        .collect()
}

/// Abstraction over the side-effecting worker mutation so the logic is fully
/// unit-testable without a live CF token / network (mirrors `RescuePeer`).
#[allow(async_fn_in_trait)]
pub trait MutationPeer: Send + Sync {
    /// Re-deploy the worker and rotate the UUID. Returns the new UUID.
    async fn redeploy_with_new_uuid(
        &self,
        profile_id: &str,
        new_uuid: &str,
    ) -> Result<String, CFError>;
}

/// Persist the mutation metadata + rotate the saved VLESS record's UUID/path.
pub fn persist_mutation(
    profile_id: &str,
    old_path: &str,
    new_path: &str,
    new_uuid: &str,
) -> Result<MutationOutcome, CFError> {
    let now = crate::store::now_ts() as i64;

    let mut p = crate::store::profiles::load_profile(profile_id);
    // Update the non-clean-ip (deployed) VLESS record's UUID/path.
    for rec in p.history.iter_mut() {
        if !rec.clean_ip {
            let old_uuid = std::mem::replace(&mut rec.uuid, new_uuid.to_string());
            // Rebuild the share link with the new signature.
            let mut profile = VlessProfile::parse(&rec.link).unwrap_or_default();
            profile.uuid = new_uuid.to_string();
            profile.path = new_path.to_string();
            rec.link = profile.share_link();
            rec.note = format!("auto-rotated {}", crate::store::now_iso());

            let outcome = MutationOutcome {
                old_uuid,
                new_uuid: new_uuid.to_string(),
                old_path: old_path.to_string(),
                new_path: new_path.to_string(),
                applied_at: now,
            };
            p.config.last_mutation_ts = now;
            crate::store::profiles::save_profile(&p)?;
            return Ok(outcome);
        }
    }
    // No deployed record found — record the mutation timestamp anyway.
    p.config.last_mutation_ts = now;
    crate::store::profiles::save_profile(&p)?;
    Ok(MutationOutcome {
        old_uuid: String::new(),
        new_uuid: new_uuid.to_string(),
        old_path: old_path.to_string(),
        new_path: new_path.to_string(),
        applied_at: now,
    })
}

/// Run a single mutation pass. Returns `None` if not due yet / disabled.
pub async fn run_mutation_if_due<M: MutationPeer>(
    profile_id: &str,
    peer: &M,
) -> Result<Option<MutationOutcome>, CFError> {
    let cfg = crate::store::profiles::load_profile(profile_id).config;
    let now = crate::store::now_ts() as i64;
    if !should_mutate(&cfg.mutation, cfg.last_mutation_ts, now) {
        return Ok(None);
    }

    let new_uuid = crate::worker::generate_uuid();
    let new_path = if cfg.mutation.rotate_path {
        format!("/api/{}", generate_new_path(&mut rand::thread_rng()))
    } else {
        "/".to_string()
    };

    // Redeploy with the new UUID (this is the actual signature rotation).
    let deployed_uuid = peer.redeploy_with_new_uuid(profile_id, &new_uuid).await?;

    let outcome = persist_mutation(profile_id, "/", &new_path, &deployed_uuid)?;
    Ok(Some(outcome))
}

#[cfg(test)]
mod tests {
    use super::*;
    

    fn with_home() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(tmp.path().join(".dastyab"));
        crate::store::ensure_mem_dir().unwrap();
        tmp
    }

    #[test]
    fn should_mutate_at_interval() {
        let cfg = MutationConfig::default();
        // Disabled by default.
        assert!(!should_mutate(&cfg, 0, 100000));
        let mut cfg = cfg;
        cfg.enabled = true;
        cfg.interval_secs = 86400;
        assert!(!should_mutate(&cfg, 0, 86399));
        assert!(should_mutate(&cfg, 0, 86400));
        assert!(should_mutate(&cfg, 1000, 1000 + 86400));
    }

    #[test]
    fn should_mutate_disabled() {
        let cfg = MutationConfig {
            enabled: false,
            ..Default::default()
        };
        assert!(!should_mutate(&cfg, 0, i64::MAX));
    }

    #[test]
    fn generate_new_path_shape() {
        let mut rng = rand::thread_rng();
        let p = generate_new_path(&mut rng);
        assert_eq!(p.len(), 12);
        assert!(p
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    #[test]
    fn should_mutate_zero_interval_is_safe() {
        let cfg = MutationConfig {
            enabled: true,
            interval_secs: 0,
            ..Default::default()
        };
        assert!(!should_mutate(&cfg, 0, 100000));
    }

    #[test]
    fn mutation_fields_serde_default_migrate() {
        // A legacy config without mutation fields loads with defaults (off).
        let cfg: MutationConfig = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(!cfg.enabled);
        assert_eq!(cfg.interval_secs, 86400);
        assert!(cfg.rotate_uuid);
    }
}
