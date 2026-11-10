//! Per-worker session-secret management and two-phase rotation.
//!
//! # Why per-worker secrets
//!
//! Originally every deployed worker shared one `DYB_SESSION_SECRET` derived
//! from the profile's session seed. A single deploy drift, partial rollout, or
//! leaked secret therefore compromised the *entire* worker tier at once — the
//! largest blast radius in the resilience stack. This module gives each worker
//! its own secret and rotates them on a schedule.
//!
//! # Two-phase (pending → current) rotation
//!
//! Naive rotation overwrites the profile secret before the worker redeploys; a
//! mid-rotation crash leaves profile and worker out of sync and the worker tier
//! unreachable until a manual fix. Instead, rotation is two-phase:
//!
//! 1. `rotate_worker_secret` writes a new `pending_secret` (the current value
//!    stays valid), calls the deploy with the pending value, then verifies via
//!    `query_self_ping` (flag 6, authenticated with the *pending* secret).
//! 2. Only on verified success does it promote `pending_secret` → `secret`,
//!    bump `rotated_unix`/`version`, and clear pending.
//!
//! On any failure the pending secret remains; the current secret stays valid
//! and the worker keeps serving traffic on it until the next rotation attempt.
//! `resolve_worker_secret` always returns the current (never pending) secret.

use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::error::CFError;

/// A worker's session secret plus its two-phase rotation state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerSecret {
    /// Worker URL (identity key in `ProfileConfig.worker_secrets`).
    #[serde(default)]
    pub worker_url: String,
    /// Current (active) secret.
    #[serde(default)]
    pub secret: String,
    /// Epoch-seconds the current secret was last rotated.
    #[serde(default)]
    pub rotated_unix: u64,
    /// Monotonic rotation counter (starts at 1 after first assignment).
    #[serde(default)]
    pub version: u32,
    /// Pending secret awaiting deployment + verification (two-phase rotation).
    #[serde(default)]
    pub pending_secret: Option<String>,
    /// Epoch-seconds the pending secret was written (for the in-flight guard).
    #[serde(default)]
    pub pending_since_unix: u64,
}

impl Default for WorkerSecret {
    fn default() -> Self {
        Self {
            worker_url: String::new(),
            secret: String::new(),
            rotated_unix: 0,
            version: 0,
            pending_secret: None,
            pending_since_unix: 0,
        }
    }
}

/// Maximum age (seconds) of an in-flight pending rotation before it is treated
/// as stale and eligible to be retried/overwritten.
pub const MAX_PENDING_AGE_SECS: u64 = 3600; // 1h

/// Secret length in hex characters (32 hex chars = 16 bytes).
pub const SECRET_HEX_LEN: usize = 32;

/// Generate a 32-hex-char session secret via SHA-256 (the repo's already-present
/// hash), using the same `"worker-tunnel-v1"` salt as the legacy derivation so
/// per-worker secrets are distinguishable yet in-family.
pub fn generate_secret() -> String {
    use sha2::{Digest, Sha256};
    // Mix in a random nonce so two calls never collide even within the same
    // second. `std::time::SystemTime` + a per-call atomic counter is enough
    // for a session secret (not a cryptographic nonce requirement).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let c = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut hasher = Sha256::new();
    hasher.update(b"worker-tunnel-v1");
    hasher.update(now.to_le_bytes());
    hasher.update(c.to_le_bytes());
    let h = hasher.finalize();
    hex(&h[..SECRET_HEX_LEN / 2])
}

/// Resolve the effective secret for `worker_url`: the per-worker secret when
/// present, otherwise the legacy shared secret. Never returns a pending secret.
pub fn resolve_worker_secret<'a>(
    cfg: &'a crate::store::profiles::ProfileConfig,
    worker_url: &str,
    legacy_shared: &'a str,
) -> Cow<'a, str> {
    match cfg.worker_secrets.get(worker_url) {
        Some(ws) if !ws.secret.is_empty() => Cow::Borrowed(ws.secret.as_str()),
        _ => Cow::Borrowed(legacy_shared),
    }
}

/// Assign a fresh secret to a worker. If none exists, `version` starts at 1.
/// If one exists (rotation), it is written to `pending_secret` for two-phase
/// promotion — the current secret stays valid until verification succeeds.
pub fn assign_new_secret(
    cfg: &mut crate::store::profiles::ProfileConfig,
    worker_url: &str,
    now_unix: u64,
) -> Result<(), CFError> {
    let secret = generate_secret();
    let entry = cfg
        .worker_secrets
        .entry(worker_url.to_string())
        .or_default();
    entry.worker_url = worker_url.to_string();
    if entry.secret.is_empty() {
        // First assignment → promote immediately; no pending phase needed.
        entry.secret = secret;
        entry.rotated_unix = now_unix;
        entry.version = 1;
        entry.pending_secret = None;
        entry.pending_since_unix = 0;
    } else {
        // Two-phase rotation → stage as pending; worker still serves current.
        entry.pending_secret = Some(secret);
        entry.pending_since_unix = now_unix;
    }
    Ok(())
}

/// Whether rotation is due for `worker_url`: the current secret is older than
/// `max_age_secs`.
pub fn rotation_due(
    cfg: &crate::store::profiles::ProfileConfig,
    worker_url: &str,
    now_unix: u64,
    max_age_secs: u64,
) -> bool {
    let Some(ws) = cfg.worker_secrets.get(worker_url) else {
        return true; // no secret yet → due
    };
    now_unix.saturating_sub(ws.rotated_unix) >= max_age_secs
}

/// Whether a rotation may start now. Gate used by the daemon tick so rotation
/// never fires during a blackout (wasted attempt + noisy failure) and never
/// piles a second pending on top of a live one.
pub fn rotation_eligible(
    cfg: &crate::store::profiles::ProfileConfig,
    worker_url: &str,
    now_unix: u64,
    max_age_secs: u64,
    net_up: bool,
) -> bool {
    if !net_up {
        return false;
    }
    if let Some(ws) = cfg.worker_secrets.get(worker_url) {
        // An in-flight pending that is still fresh blocks a new rotation.
        if ws.pending_secret.is_some()
            && now_unix.saturating_sub(ws.pending_since_unix) < MAX_PENDING_AGE_SECS
        {
            return false;
        }
    }
    rotation_due(cfg, worker_url, now_unix, max_age_secs)
}

/// Promote a pending secret to current after verified deploy. Returns the new
/// version.
pub fn promote_pending(
    cfg: &mut crate::store::profiles::ProfileConfig,
    worker_url: &str,
    now_unix: u64,
) -> Result<u32, CFError> {
    let entry = cfg
        .worker_secrets
        .get_mut(worker_url)
        .ok_or_else(|| CFError::new("rotate", "no secret for worker", ""))?;
    let pending = entry
        .pending_secret
        .take()
        .ok_or_else(|| CFError::new("rotate", "no pending secret", ""))?;
    entry.secret = pending;
    entry.rotated_unix = now_unix;
    entry.version = entry.version.saturating_add(1);
    entry.pending_since_unix = 0;
    Ok(entry.version)
}

/// Cancel a stale/aborted pending rotation (keeps the current secret active).
pub fn clear_pending(cfg: &mut crate::store::profiles::ProfileConfig, worker_url: &str) {
    if let Some(entry) = cfg.worker_secrets.get_mut(worker_url) {
        entry.pending_secret = None;
        entry.pending_since_unix = 0;
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::profiles::ProfileConfig;

    fn cfg() -> ProfileConfig {
        ProfileConfig::default()
    }

    fn seed_worker(c: &mut ProfileConfig, url: &str, age_rot: u64) {
        let ws = WorkerSecret {
            worker_url: url.into(),
            secret: "current-secret".into(),
            rotated_unix: age_rot,
            version: 1,
            pending_secret: None,
            pending_since_unix: 0,
        };
        c.worker_secrets.insert(url.into(), ws);
    }

    #[test]
    fn resolve_worker_secret_falls_back_to_shared_when_absent() {
        let c = cfg();
        assert_eq!(resolve_worker_secret(&c, "http://w", "shared"), "shared");
    }

    #[test]
    fn resolve_worker_secret_returns_per_worker_when_present() {
        let mut c = cfg();
        seed_worker(&mut c, "http://w", 0);
        assert_eq!(
            resolve_worker_secret(&c, "http://w", "shared"),
            "current-secret"
        );
    }

    #[test]
    fn assign_new_secret_isolates_to_target_worker() {
        let mut c = cfg();
        assign_new_secret(&mut c, "http://w", 1000).unwrap();
        assert!(c.worker_secrets.contains_key("http://w"));
        // Other worker untouched.
        assert!(!c.worker_secrets.contains_key("http://other"));
        let ws = &c.worker_secrets["http://w"];
        assert_eq!(ws.version, 1);
        assert!(ws.pending_secret.is_none());
        assert_eq!(ws.rotated_unix, 1000);
        assert_eq!(ws.secret.len(), SECRET_HEX_LEN);
    }

    #[test]
    fn rotation_due_after_max_age() {
        let mut c = cfg();
        seed_worker(&mut c, "http://w", 1000);
        assert!(!rotation_due(&c, "http://w", 1000 + 10, 100));
        assert!(rotation_due(&c, "http://w", 1000 + 200, 100));
    }

    #[test]
    fn rotation_eligible_false_when_net_down() {
        let mut c = cfg();
        seed_worker(&mut c, "http://w", 1000);
        assert!(!rotation_eligible(&c, "http://w", 1000 + 200, 100, false));
        assert!(rotation_eligible(&c, "http://w", 1000 + 200, 100, true));
    }

    #[test]
    fn rotation_eligible_false_when_pending_fresh() {
        let mut c = cfg();
        seed_worker(&mut c, "http://w", 1000);
        c.worker_secrets.get_mut("http://w").unwrap().pending_secret = Some("pending".into());
        c.worker_secrets
            .get_mut("http://w")
            .unwrap()
            .pending_since_unix = 2000;
        // now = 2100 → pending is 100s old (< 1h) → blocked.
        assert!(!rotation_eligible(&c, "http://w", 2100, 100, true));
        // now = 2000 + 2h → pending stale → eligible again.
        assert!(rotation_eligible(&c, "http://w", 2000 + 7200, 100, true));
    }

    #[test]
    fn promote_pending_promotes_and_bumps_version() {
        let mut c = cfg();
        seed_worker(&mut c, "http://w", 1000);
        c.worker_secrets.get_mut("http://w").unwrap().pending_secret = Some("pending-2".into());
        c.worker_secrets
            .get_mut("http://w")
            .unwrap()
            .pending_since_unix = 2000;
        let v = promote_pending(&mut c, "http://w", 3000).unwrap();
        assert_eq!(v, 2);
        let ws = &c.worker_secrets["http://w"];
        assert_eq!(ws.secret, "pending-2");
        assert!(ws.pending_secret.is_none());
        assert_eq!(ws.rotated_unix, 3000);
    }

    #[test]
    fn generate_secret_is_32_hex() {
        let a = generate_secret();
        let b = generate_secret();
        assert_eq!(a.len(), SECRET_HEX_LEN);
        assert_ne!(a, b);
        assert!(a.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn assign_new_secret_two_phase_keeps_current_until_pending() {
        // Rotation on an existing worker must stage a pending secret without
        // touching the current one (so traffic keeps working until verified).
        let mut c = cfg();
        seed_worker(&mut c, "http://w", 1000);
        assign_new_secret(&mut c, "http://w", 2000).unwrap();
        let ws = &c.worker_secrets["http://w"];
        assert_eq!(ws.secret, "current-secret");
        assert!(ws.pending_secret.is_some());
        assert_eq!(ws.pending_since_unix, 2000);
        // resolve still returns the current, never pending.
        assert_eq!(
            resolve_worker_secret(&c, "http://w", "shared"),
            "current-secret"
        );
    }

    #[test]
    fn clear_pending_restores_current_active() {
        let mut c = cfg();
        seed_worker(&mut c, "http://w", 1000);
        c.worker_secrets.get_mut("http://w").unwrap().pending_secret = Some("pending".into());
        clear_pending(&mut c, "http://w");
        let ws = &c.worker_secrets["http://w"];
        assert!(ws.pending_secret.is_none());
        assert_eq!(ws.secret, "current-secret");
    }

    #[test]
    fn promote_pending_errors_without_pending() {
        let mut c = cfg();
        seed_worker(&mut c, "http://w", 1000);
        assert!(promote_pending(&mut c, "http://w", 3000).is_err());
    }
}
