//! Automatic token provisioning — closes the last manual setup step.
//!
//! Auto-rotation (`token_rotate`) can only work when the profile stores at
//! least two Cloudflare tokens (it never "rotates to" the very token that is
//! blocked). Today the second token has to be created by hand in the CF
//! dashboard — a manual step. This module automates it: it creates a second
//! API token via the Cloudflare API (using the active token's credentials)
//! and persists it, so the app becomes fully hands-off.
//!
//! Design notes:
//! - **Injected creator seam**: `ensure_minimum_tokens` asks an injected
//!   `create` closure to mint a token. Production wires the real Cloudflare
//!   client (`cf::Client::create_api_token`); tests inject a scripted one,
//!   so the whole flow is hermetic and offline.
//! - **Only acts when under the threshold**: at/above the minimum it is a
//!   no-op (`Ok(false)`), so it is safe to call on every daemon tick or from
//!   `autonomy audit` — it never spams the CF API.
//! - **Never fabricates credentials**: the new token's value comes straight
//!   from the API and is written to the secure profile store via
//!   `add_token`.

use std::future::Future;
use std::pin::Pin;

/// Create a token via the Cloudflare API and return its plaintext value.
/// (account_id, name) -> Result<token_value, CFError>.
pub type CreateTokenFn<'a> = dyn Fn(String, String) -> Pin<Box<dyn Future<Output = Result<String, crate::error::CFError>> + Send + 'a>> + 'a;

/// Ensure the profile stores at least `min` tokens. Returns `Ok(true)` if a
/// new token was created and persisted, `Ok(false)` if no action was needed
/// (already at/above the threshold or no usable base token).
///
/// `create` is injected so the caller supplies the real CF client
/// (production) or a scripted stub (tests). When the profile has no token at
/// all, there is nothing to authenticate the creation with → an error.
pub async fn ensure_minimum_tokens<F>(
    profile: &str,
    min: usize,
    account_id: String,
    create: F,
) -> Result<bool, crate::error::CFError>
where
    F: Fn(String, String) -> Pin<Box<dyn Future<Output = Result<String, crate::error::CFError>> + Send>>,
{
    use crate::store::profiles::{add_token, load_profile};

    let p = load_profile(profile);
    if p.tokens.len() >= min {
        return Ok(false);
    }

    // We need at least one existing token to authenticate the create call.
    p.tokens
        .values()
        .next()
        .ok_or_else(|| {
            crate::error::CFError::new(
                "token-provision",
                "no token stored — cannot auto-create a second token",
                "Add one token first: `dastyab token add --label <name> --token <cf-token>`.",
            )
        })?;

    let name = format!("dastyab-rot-{}", crate::store::profiles::now_ts());
    let value = create(account_id, name.clone()).await?;
    if value.trim().is_empty() {
        return Err(crate::error::CFError::new(
            "token-provision",
            "created token value is empty",
            "The CF API returned an empty token; check permissions and retry.",
        ));
    }

    add_token(profile, &name, &value)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::profiles::{add_token, load_profile, create_profile};

    fn scripted_create(result: Result<String, crate::error::CFError>) -> impl Fn(String, String) -> Pin<Box<dyn Future<Output = Result<String, crate::error::CFError>> + Send>> {
        move |_acc: String, _name: String| {
            let r = result.clone();
            Box::pin(async move { r })
        }
    }

    fn base_profile() -> String {
        let id = create_profile("tokprov-test", "").unwrap();
        add_token(&id, "cf-main", "tok-1").unwrap();
        id
    }

    #[tokio::test]
    async fn creates_second_token_when_below_threshold() {
        let id = base_profile();
        assert_eq!(load_profile(&id).tokens.len(), 1);
        let made = ensure_minimum_tokens(&id, 2, "acc-1".to_string(), scripted_create(Ok("tok-2".into())))
            .await
            .unwrap();
        assert!(made);
        assert_eq!(load_profile(&id).tokens.len(), 2);
        assert!(
            load_profile(&id)
                .tokens
                .keys()
                .any(|k| k.starts_with("dastyab-rot-"))
        );
        let stored = load_profile(&id).tokens.values().any(|t| t.token == "tok-2");
        assert!(stored);
    }

    #[tokio::test]
    async fn noop_when_at_or_above_threshold() {
        let id = base_profile();
        let made = ensure_minimum_tokens(&id, 1, "acc-1".to_string(), scripted_create(Ok("unused".into())))
            .await
            .unwrap();
        assert!(!made);
        assert_eq!(load_profile(&id).tokens.len(), 1);
    }

    #[tokio::test]
    async fn errors_when_no_base_token() {
        let id = create_profile("tokprov-none", "").unwrap();
        let r = ensure_minimum_tokens(&id, 2, "acc-1".to_string(), scripted_create(Ok("x".into()))).await;
        assert!(r.is_err());
        assert!(r.unwrap_err().brief().contains("no token stored"));
    }

    #[tokio::test]
    async fn propagates_create_error() {
        let id = base_profile();
        let err = crate::error::CFError::new(
            "cf",
            "User API Tokens Write permission missing",
            "add the permission",
        );
        let r = ensure_minimum_tokens(&id, 2, "acc-1".to_string(), scripted_create(Err(err))).await;
        assert!(r.is_err());
        assert!(r.unwrap_err().brief().contains("permission"));
    }

    #[tokio::test]
    async fn rejects_empty_created_token() {
        let id = base_profile();
        let r = ensure_minimum_tokens(&id, 2, "acc-1".to_string(), scripted_create(Ok("".into()))).await;
        assert!(r.is_err());
    }
}
