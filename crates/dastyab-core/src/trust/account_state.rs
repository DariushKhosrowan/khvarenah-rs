//! Account-level state machine for the daemon: detect and wait out a
//! Cloudflare account suspension (CF error 9109 "User was deactivated") or a
//! token-invalid state, and automatically resume when the account is restored.
//!
//! ## Why this exists
//!
//! The daemon's cycle runner assumes the account/token is fine and just burns
//! backoff cycles when it is not. The single largest remaining *silent* manual
//! step is: the user reactivates their CF account, then must remember to
//! restart the daemon. This module lets the daemon notice the suspension on its
//! own, enter a low-cost wait state, poll at a fixed interval, and resume the
//! moment the account is back.
//!
//! ## Key distinction (verified against live evidence)
//!
//! CF error **9109 "User was deactivated"** is an *account-level* blocker
//! (`GET /accounts` fails), distinct from a token-invalid 403 from
//! `/user/tokens/verify`. We must not classify a deactivated account as a
//! malformed token, and vice-versa. See `rounds-11-13` references.
//!
//! The classifier is pure (`classify_verify_response`) so every branch is unit
//! testable without touching the network.

use crate::error::CFError;
use std::future::Future;
use std::pin::Pin;

/// Persisted account state (serde-default so old configs load cleanly).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub enum AccountState {
    /// No suspension/invalid-state detected — the daemon should run cycles.
    #[default]
    Active,
    /// Account is deactivated (CF 9109). Store when we entered the wait.
    Suspended { since: i64 },
    /// Token is invalid/rejected (403), not an account-level blocker.
    TokenInvalid { since: i64 },
    /// We could not determine the state (network error / unknown response).
    Unknown,
}

impl AccountState {
    /// Whether the daemon should skip cycles in this state.
    pub fn blocks_cycle(&self) -> bool {
        matches!(
            self,
            AccountState::Suspended { .. } | AccountState::TokenInvalid { .. }
        )
    }

    /// A short human-readable label (used by CLI/` daemon status` and GUI).
    pub fn label(&self) -> &'static str {
        match self {
            AccountState::Active => "active",
            AccountState::Suspended { .. } => "suspended",
            AccountState::TokenInvalid { .. } => "token-invalid",
            AccountState::Unknown => "unknown",
        }
    }

    /// `since` timestamp (epoch seconds) if this state carries one.
    pub fn since(&self) -> Option<i64> {
        match self {
            AccountState::Suspended { since } | AccountState::TokenInvalid { since } => {
                Some(*since)
            }
            _ => None,
        }
    }
}

/// How often the daemon re-checks account status while in a wait state.
pub const ACCOUNT_POLL_INTERVAL_SECS: u64 = 900; // 15 min

/// Pure classifier over the two clues we can get from Cloudflare.
///
/// * `verify_ok` — did `GET /user/tokens/verify` succeed (200 → token valid)?
/// * `accounts_err` — the error returned by `GET /accounts`, if any.
///
/// Returns the account state. Order of checks matters:
/// 1. If the token verify failed at the HTTP level (carries a status code) →
///    TokenInvalid. A transport/network verify failure (no status: reset,
///    timeout, TLS) → Unknown — it is NOT proof the token is bad.
/// 2. If the accounts call failed with 9109 / "deactivated" → Suspended.
/// 3. If either call failed for a network reason → Unknown.
/// 4. Otherwise → Active.
pub fn classify_verify_response(
    verify_err: Option<&CFError>,
    accounts_err: Option<&CFError>,
) -> AccountState {
    // Clue 1: token verification. Only an HTTP-level rejection — one that
    // carries a status code (a genuine 401/403/9109 from Cloudflare) —
    // proves the token is bad. A transport-level failure (no HTTP status:
    // connection reset, TLS error, timeout) is NOT proof the token is
    // invalid — it's usually a filtering/blackout blip on the path to
    // api.cloudflare.com and must not freeze the daemon for hours in a
    // TokenInvalid wait state.
    if let Some(err) = verify_err {
        if err.status.is_some() {
            return AccountState::TokenInvalid {
                since: crate::store::now_ts() as i64,
            };
        }
        // Transport-level verify failure → Unknown (not a blocker).
    }

    match accounts_err {
        None => {
            if verify_err.is_some() {
                // Verify failed for a network reason; accounts didn't report a
                // distinct error either. We can't confirm the token is good →
                // Unknown (don't block cycles).
                AccountState::Unknown
            } else {
                AccountState::Active
            }
        }
        Some(err) => {
            if err.status.is_none() {
                // Network failure reaching /accounts → Unknown.
                return AccountState::Unknown;
            }
            let msg = format!("{} {}", err.title, err.detail).to_lowercase();
            let code_is_9109 = err.code == Some(9109);
            let says_deactivated = msg.contains("9109") || msg.contains("deactivated");
            if code_is_9109 || says_deactivated {
                AccountState::Suspended {
                    since: crate::store::now_ts() as i64,
                }
            } else {
                // Some other /accounts failure — not a verdict we can trust to
                // block cycles, but it's not a clean Active either.
                AccountState::Unknown
            }
        }
    }
}

/// True when `now` is at least `ACCOUNT_POLL_INTERVAL_SECS` after `last_poll`.
pub fn should_poll_account(last_poll_ts: i64, now: i64) -> bool {
    now - last_poll_ts >= ACCOUNT_POLL_INTERVAL_SECS as i64
}

/// A pure decision returned by the account gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountGate {
    /// Account is fine — proceed with the cycle.
    Proceed,
    /// Account is suspended/invalid — skip the cycle, poll again later.
    SkipStillBlocked,
    /// We couldn't determine account state — skip rather than burn budget.
    SkipUnknown,
}

impl AccountGate {
    pub fn is_proceed(&self) -> bool {
        matches!(self, AccountGate::Proceed)
    }
}

/// Check whether a cached profile dir mtime changed since `last_mtime`.
/// Returns true when the profile dir (config/token/state) was modified.
pub fn profile_mtime_changed(profile_id: &str, last_mtime: i64) -> Result<bool, CFError> {
    let dir = crate::store::profiles::profile_dir(profile_id);
    let meta = std::fs::metadata(&dir)
        .map_err(|e| CFError::new("Storage", format!("Cannot stat {}: {e}", dir.display()), ""))?;
    let mtime = meta
        .modified()
        .map_err(|e| CFError::new("Storage", format!("mtime: {e}"), ""))?
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    Ok(mtime != last_mtime)
}

/// Probe the real account state using Cloudflare's API for the given profile
/// (uses the profile's active token). Pure classification happens in
/// [`classify_verify_response`]; this only gathers the two clues.
pub async fn probe_account_state(profile_id: &str) -> AccountState {
    // Fetch the active token label for the profile, then resolve it to the
    // actual token string. `get_active_token` returns the *label* (e.g.
    // "default"), not the secret — passing the label to `Client::new` would
    // make Cloudflare validate the literal string "default" and always fail.
    let label = match crate::store::profiles::ensure_active_token(profile_id) {
        Ok(Some(l)) => l,
        Ok(None) => {
            // No tokens at all → nothing to verify. Treat as Unknown rather
            // than blocking the daemon (a token may be added later on).
            return AccountState::Unknown;
        }
        Err(_) => return AccountState::Unknown,
    };
    let token = match crate::store::profiles::get_token(profile_id, &label) {
        Ok(Some(tok)) => tok,
        Ok(None) => return AccountState::Unknown,
        Err(_) => return AccountState::Unknown,
    };

    let client = crate::cf::Client::new(&token);

    // Clue 1: is the token itself valid? Keep the error so a *network*-level
    // failure (api.cloudflare.com unreachable mid-blackout) is not mistaken
    // for a genuinely invalid token.
    let verify_res = client.verify_token().await;
    let verify_err = match &verify_res {
        Ok(_) => None,
        Err(e) => Some(e.clone()),
    };

    // Clue 2: is the account reachable? 9109 / "deactivated" → Suspended.
    let accounts_err = client.list_accounts().await.err();

    classify_verify_response(verify_err.as_ref(), accounts_err.as_ref())
}

/// Injectable account-state probe for cycle-level gating. Mirrors the
/// `WorkerHealthProbe`/`EndpointProvider` pattern so `AutopilotEngine` cycles
/// (monitor / run_cycle) can skip scanning a suspended/invalid account without
/// burning probe budget. `RealAccountStateProbe` is the production impl; tests
/// inject a scripted state.
pub trait AccountStateProbe: Send + Sync {
    fn probe<'a>(
        &'a self,
        profile: &'a str,
    ) -> Pin<Box<dyn Future<Output = AccountState> + Send + 'a>>;
}

/// Production account probe: hits Cloudflare's API for the profile's token.
#[derive(Default)]
pub struct RealAccountStateProbe;

impl AccountStateProbe for RealAccountStateProbe {
    fn probe<'a>(
        &'a self,
        profile: &'a str,
    ) -> Pin<Box<dyn Future<Output = AccountState> + Send + 'a>> {
        let profile = profile.to_string();
        Box::pin(async move { probe_account_state(&profile).await })
    }
}

/// A pure gate helper: given the probed account state, decide whether a cycle
/// should run. Returns `Some(label)` when the cycle must be skipped (account
/// blocks cycles) and `None` when it may proceed. Kept as a tiny free fn so
/// both the monitor and run_cycle gates share one decision rule.
pub fn account_gate_verdict(state: &AccountState) -> Option<&'static str> {
    if state.blocks_cycle() {
        Some(state.label())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err_with_status(status: u16, code: Option<u32>, title: &str, detail: &str) -> CFError {
        let mut e = CFError::new(title, detail, "");
        e.status = Some(status);
        e.code = code;
        e
    }

    fn network_err() -> CFError {
        CFError::new("Network error", "connection reset", "")
    }

    #[test]
    fn classify_9109_is_suspended() {
        let err = err_with_status(403, Some(9109), "Invalid API token", "User was deactivated");
        let st = classify_verify_response(None, Some(&err));
        assert!(matches!(st, AccountState::Suspended { .. }));
        assert!(st.blocks_cycle());
    }

    #[test]
    fn classify_deactivated_string_is_suspended_even_without_code() {
        let err = err_with_status(400, None, "Error", "User was deactivated");
        let st = classify_verify_response(None, Some(&err));
        assert!(matches!(st, AccountState::Suspended { .. }));
    }

    #[test]
    fn classify_token_403_is_invalid() {
        let err = err_with_status(403, Some(403), "Forbidden", "Invalid API token");
        let st = classify_verify_response(Some(&err), None);
        assert!(matches!(st, AccountState::TokenInvalid { .. }));
        assert!(st.blocks_cycle());
    }

    #[test]
    fn classify_network_is_unknown() {
        let err = network_err();
        let st = classify_verify_response(None, Some(&err));
        assert!(matches!(st, AccountState::Unknown));
        assert!(!st.blocks_cycle());
    }

    /// Regression for the live blackout bug: a *transport*-level failure on
    /// the token verify (api.cloudflare.com unreachable mid-blackout) MUST NOT
    /// be classified as `TokenInvalid` — that froze the daemon for hours even
    /// though the stored token was valid (Cloudflare verified it active). A
    /// network blip should yield `Unknown` (non-blocking), never a hard
    /// token-invalid wait state.
    #[test]
    fn classify_verify_transport_failure_is_unknown_not_tokeninvalid() {
        let err = network_err();
        let st = classify_verify_response(Some(&err), None);
        assert!(matches!(st, AccountState::Unknown));
        assert!(!st.blocks_cycle());
    }

    #[test]
    fn classify_all_ok_is_active() {
        let st = classify_verify_response(None, None);
        assert_eq!(st, AccountState::Active);
        assert!(!st.blocks_cycle());
    }

    #[test]
    fn should_poll_at_interval() {
        let t0 = 1_000_000i64;
        assert!(!should_poll_account(t0, t0 + 899));
        assert!(should_poll_account(t0, t0 + 900));
        assert!(should_poll_account(t0, t0 + 5000));
    }

    #[test]
    fn label_and_since_are_truthful() {
        let s = AccountState::Suspended { since: 42 };
        assert_eq!(s.label(), "suspended");
        assert_eq!(s.since(), Some(42));
        assert_eq!(AccountState::Active.label(), "active");
        assert_eq!(
            AccountState::TokenInvalid { since: 1 }.label(),
            "token-invalid"
        );
        assert_eq!(AccountState::Unknown.label(), "unknown");
    }

    #[test]
    fn gate_verdict_blocks_only_suspended_and_invalid() {
        let s = AccountState::Suspended { since: 0 };
        assert_eq!(account_gate_verdict(&s), Some("suspended"));
        let t = AccountState::TokenInvalid { since: 0 };
        assert_eq!(account_gate_verdict(&t), Some("token-invalid"));
        assert_eq!(account_gate_verdict(&AccountState::Active), None);
        // Unknown is NOT a blocker — treat as proceed (the daemon surfaces a
        // real blocker via its own probe/classification).
        assert_eq!(account_gate_verdict(&AccountState::Unknown), None);
    }

    /// Regression for the round-23 bug: `probe_account_state` must resolve the
    /// active token *label* to the actual secret via `get_token`. Previously
    /// it passed the label string ("default") straight to `Client::new`, which
    /// made Cloudflare validate the literal text and report the account as
    /// token-invalid even with a valid stored token. This test pins the
    /// contract that `get_active_token` returns a label and `get_token`
    /// resolves it to the real secret.
    #[test]
    fn active_token_label_resolves_to_secret() {
        use crate::store::profiles::{add_token, get_active_token, get_token, set_active_token};
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!(
            "kvrvn-accstate-resolve-{}-{}",
            std::process::id(),
            crate::store::now_ts()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        crate::store::set_mem_dir_override(tmp.clone());

        let id = crate::store::profiles::create_profile("t", "").unwrap();
        add_token(&id, "default", "cfut_REAL_SECRET_TOKEN_1234567890abcdef").unwrap();
        set_active_token(&id, "default").unwrap();

        // get_active_token returns the LABEL, not the secret.
        let label = get_active_token(&id).unwrap().expect("label present");
        assert_eq!(label, "default");

        // get_token resolves the label to the actual secret.
        let secret = get_token(&id, &label).unwrap().expect("secret present");
        assert_eq!(secret, "cfut_REAL_SECRET_TOKEN_1234567890abcdef");
        // The secret must NEVER equal the label string.
        assert_ne!(secret, label);

        crate::store::set_mem_dir_override(std::path::PathBuf::new());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
