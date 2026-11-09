//! Automatic token rotation — closes the last manual step.
//!
//! When Cloudflare blocks/invalidates the profile's active token, the daemon
//! used to hold cycles and wait for a human to run `khvarenah token recover`.
//! This module lets the daemon verify the *other* stored tokens and swap to
//! the first working one automatically, so protection resumes with no manual
//! intervention. It is configured in-app via
//! `ProfileConfig::auto_rotate_on_blocked` (default on).
//!
//! Design notes:
//! - **Pure decision + injected verifier**: `try_auto_rotate` reads the stored
//!   tokens, walks candidates in a deterministic order (label-sorted), and
//!   asks an injected `verify` closure whether a token works. The production
//!   verifier hits Cloudflare's `verify_token`; tests inject a scripted one,
//!   so the whole flow is hermetic and offline.
//! - **Never rotates to the active token itself**; with a single stored token
//!   it returns `None` (nothing to try).
//! - The daemon owns the state transition (sets `AccountState::Active` + emits
//!   the `TokenAutoRotated` beacon); this module only swaps the active token.

use std::future::Future;
use std::pin::Pin;

/// Verify that a plaintext token works (async, injected).
pub type VerifyFn<'a> = dyn Fn(&str) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> + 'a;

/// Scan the profile's stored tokens and, if any *other* token verifies, make
/// it active. Returns `Ok(Some((from, to)))` on a successful rotation
/// (old active label → new label), `Ok(None)` when nothing could be rotated.
///
/// `verify` is injected so the call site can pick the real Cloudflare check
/// (production) or a scripted one (tests).
pub async fn try_auto_rotate<V>(
    profile: &str,
    verify: V,
) -> Result<Option<(String, String)>, crate::error::CFError>
where
    V: for<'a> Fn(
        &'a str,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>,
{
    let active = crate::store::profiles::get_active_token(profile)?;
    let p = crate::store::profiles::load_profile(profile);

    // Deterministic candidate order: labels sorted (BTreeMap key order).
    let labels: Vec<String> = p.tokens.keys().cloned().collect();
    for label in labels {
        if Some(&label) == active.as_ref() {
            continue; // never "rotate" to the very token that is blocked
        }
        let tok = match p.tokens.get(&label) {
            Some(t) => t.token.clone(),
            None => continue,
        };
        if verify(&tok).await {
            crate::store::profiles::set_active_token(profile, &label)?;
            return Ok(Some((active.unwrap_or_default(), label)));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn test_home() -> std::path::PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let tmp = std::env::temp_dir().join(format!("kvrvn-rot-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        crate::store::set_mem_dir_override(tmp.join(".khvarenah"));
        tmp
    }

    /// Fake verifier: a token is "working" iff its plaintext equals `good`.
    fn fake_verify(good: &'static str) -> impl Fn(&str) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        move |tok: &str| {
            let ok = tok == good;
            Box::pin(async move { ok })
        }
    }

    #[tokio::test]
    async fn test_rotates_to_working_candidate() {
        let tmp = test_home();
        let profile = crate::store::profiles::create_profile("rot-ok", "").unwrap();
        crate::store::profiles::add_token(&profile, "a", "tok-a").unwrap();
        crate::store::profiles::add_token(&profile, "b", "tok-b").unwrap();
        crate::store::profiles::set_active_token(&profile, "a").unwrap();

        // "a" is active; "b" verifies (its token "tok-b" == good) → rotate to b.
        let out = try_auto_rotate(&profile, fake_verify("tok-b")).await.unwrap();
        assert_eq!(out, Some(("a".to_string(), "b".to_string())));
        assert_eq!(
            crate::store::profiles::get_active_token(&profile).unwrap().unwrap(),
            "b"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn test_no_rotation_when_only_one_token() {
        let tmp = test_home();
        let profile = crate::store::profiles::create_profile("rot-single", "").unwrap();
        crate::store::profiles::add_token(&profile, "only", "tok-only").unwrap();
        crate::store::profiles::set_active_token(&profile, "only").unwrap();

        let out = try_auto_rotate(&profile, fake_verify("tok-only")).await.unwrap();
        assert_eq!(out, None);
        assert_eq!(
            crate::store::profiles::get_active_token(&profile).unwrap().unwrap(),
            "only"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn test_no_rotation_when_no_candidate_verifies() {
        let tmp = test_home();
        let profile = crate::store::profiles::create_profile("rot-none", "").unwrap();
        crate::store::profiles::add_token(&profile, "a", "tok-a").unwrap();
        crate::store::profiles::add_token(&profile, "b", "tok-b").unwrap();
        crate::store::profiles::set_active_token(&profile, "a").unwrap();

        let out = try_auto_rotate(&profile, fake_verify("tok-none")).await.unwrap();
        assert_eq!(out, None);
        assert_eq!(
            crate::store::profiles::get_active_token(&profile).unwrap().unwrap(),
            "a"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
