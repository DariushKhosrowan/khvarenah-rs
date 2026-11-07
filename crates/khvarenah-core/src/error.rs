//! Structured error taxonomy for Khvarenah.
//!
//! Mirrors the Python app's `CFError` philosophy: every failure carries a
//! human-readable `title`, a `detail` of what happened, and a concrete `fix`
//! the user can act on. This is the backbone of "debugging that works really
//! well" — no opaque error strings leak to the user.

use serde::{Deserialize, Serialize};

/// A known Cloudflare API error code → human guidance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CFErrorTemplate {
    pub title: &'static str,
    pub fix: &'static str,
}

/// Error codes we know how to explain. (code → template)
pub const KNOWN_CODES: &[(u32, CFErrorTemplate)] = &[
    (10000, CFErrorTemplate { title: "Authentication failure", fix: "The API token was rejected. Re-enter it (or create a new one in the Cloudflare dashboard)." }),
    (9109, CFErrorTemplate { title: "Invalid API token", fix: "The token is malformed or empty. Paste a full token from Cloudflare → My Profile → API Tokens." }),
    (6003, CFErrorTemplate { title: "Insufficient permission", fix: "The token lacks a required permission. Recreate it with at least: Account-Settings-Read, Workers-Scripts-Edit, Workers-KV-Storage-Edit, Workers-Scripts-Read." }),
    (10021, CFErrorTemplate { title: "Too many requests", fix: "You hit a rate limit. Wait ~30s and retry." }),
    (10022, CFErrorTemplate { title: "Not authenticated", fix: "Token missing/expired. Re-authenticate." }),
    (9106, CFErrorTemplate { title: "Script deleted", fix: "This worker was deleted in the dashboard." }),
    (8000001, CFErrorTemplate { title: "Worker script error", fix: "The uploaded script failed to parse/validate. Check that the worker JS is the correct edgetunnel module file." }),
];

/// The full, structured error type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CFError {
    pub title: String,
    pub detail: String,
    pub fix: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

impl CFError {
    pub fn new(
        title: impl Into<String>,
        detail: impl Into<String>,
        fix: impl Into<String>,
    ) -> Self {
        Self {
            title: title.into(),
            detail: detail.into(),
            fix: fix.into(),
            status: None,
            code: None,
            action: None,
        }
    }

    /// One-line friendly form for TUI/CLI.
    pub fn brief(&self) -> String {
        format!("{}: {}", self.title, self.detail)
    }

    /// Multi-line form for the GUI / verbose logs.
    pub fn explain(&self) -> String {
        let mut out = format!("{}\n  {}", self.title, self.detail);
        if !self.fix.is_empty() {
            out.push_str(&format!("\n  Fix: {}", self.fix));
        }
        if let Some(status) = self.status {
            out.push_str(&format!("\n  HTTP {}", status));
        }
        if let Some(code) = self.code {
            out.push_str(&format!("\n  CF error code {code}"));
        }
        out
    }
}

impl std::fmt::Display for CFError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.brief())
    }
}

impl std::error::Error for CFError {}

/// Build a `CFError` from a non-2xx HTTP status and (optionally) the parsed
/// Cloudflare error envelope. This is the Rust twin of the Python
/// `explain_response`.
pub fn explain_response(status: u16, body: Option<&serde_json::Value>, action: &str) -> CFError {
    let mut code = None;
    let mut detail = String::new();

    if let Some(body) = body {
        if let Some(errors) = body.get("errors").and_then(|e| e.as_array()) {
            if let Some(first) = errors.first() {
                code = first.get("code").and_then(|c| c.as_u64()).map(|c| c as u32);
                detail = first
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("")
                    .to_string();
            }
        }
        if detail.is_empty() {
            detail = body
                .get("errors")
                .and_then(|e| e.as_str())
                .or_else(|| body.get("messages").and_then(|m| m.as_str()))
                .unwrap_or("")
                .to_string();
        }
    }

    let title: &str;
    let fix: &str;
    let known_code = code.filter(|c| KNOWN_CODES.iter().any(|(c2, _)| c2 == c));
    if let Some(c) = known_code {
        if let Some((_, tpl)) = KNOWN_CODES.iter().find(|(c2, _)| *c2 == c) {
            title = tpl.title;
            fix = tpl.fix;
        } else {
            title = "Request failed";
            fix = "Review the raw error below and adjust accordingly.";
        }
    } else {
        match status {
            400 => {
                title = "Bad request";
                fix = "One of the fields is invalid. Verify the worker name (lowercase letters, numbers, hyphens) and re-check the script.";
            }
            401 => {
                title = "Not authenticated";
                fix = "The API token is invalid or expired. Get a fresh token from Cloudflare → My Profile → API Tokens.";
            }
            403 => {
                title = "Permission denied";
                fix = "The token is missing a required permission. Recreate it with Workers-Scripts-Edit & Account-Settings-Read.";
            }
            404 => {
                title = "Not found";
                fix = "Check the Account ID and that the worker name is correct.";
            }
            409 => {
                title = "Conflict";
                fix = "A resource with this name already exists in a conflicting state. Pick another worker name or delete the existing one.";
            }
            413 => {
                title = "Script too large";
                fix = "The worker bundle is over the size limit. Use the standard edgetunnel worker file.";
            }
            429 => {
                title = "Rate limited";
                fix = "Slow down — wait a few seconds and retry. Free-tier limits apply.";
            }
            s if s >= 500 => {
                title = "Cloudflare-side error";
                fix = "This is a Cloudflare outage/5xx. Wait briefly and retry.";
            }
            _ => {
                title = "Request failed";
                fix = "Review the raw error below and adjust accordingly.";
            }
        }
    }

    CFError {
        title: title.to_string(),
        detail: if detail.is_empty() {
            format!("HTTP {status} for action '{action}'")
        } else {
            detail
        },
        fix: fix.to_string(),
        status: Some(status),
        code,
        action: Some(action.to_string()),
    }
}

/// Wrap a generic error (network / IO / parse) into a CFError with a friendly fix.
pub fn wrap(mode: &str, err: &dyn std::fmt::Display) -> CFError {
    match mode {
        "network" => CFError::new(
            "Network error",
            format!("Could not reach api.cloudflare.com: {err}"),
            "Are you offline? Cloudflare may be blocked/filtered where you are.",
        ),
        "tls" => CFError::new(
            "TLS error",
            format!("Could not establish a secure connection to Cloudflare: {err}"),
            "Check your network / proxy settings.",
        ),
        "timeout" => CFError::new(
            "Timeout",
            format!("No response from Cloudflare: {err}"),
            "Retry; if it persists, the API may be blocked on your network.",
        ),
        _ => CFError::new(
            "Unexpected error",
            format!("{err}"),
            "Review the error and try again.",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_known_code_maps_to_template() {
        for (code, tpl) in KNOWN_CODES {
            assert!(!tpl.title.is_empty());
            assert!(!tpl.fix.is_empty());
            let e = explain_response(
                400,
                Some(&serde_json::json!({"errors":[{"code": code}]})),
                "test",
            );
            assert_eq!(e.code, Some(*code));
            assert_eq!(&e.title, tpl.title);
        }
    }

    #[test]
    fn unknown_code_falls_back_to_status() {
        let e = explain_response(
            500,
            Some(&serde_json::json!({"errors":[{"code": 99999, "message": "weird"}]})),
            "deploy",
        );
        assert_eq!(e.code, Some(99999));
        assert_eq!(e.title, "Cloudflare-side error");
    }

    #[test]
    fn status_fallback_when_no_body() {
        let e = explain_response(401, None, "verify");
        assert_eq!(e.status, Some(401));
        assert_eq!(e.title, "Not authenticated");
    }

    #[test]
    fn brief_vs_explain() {
        let e = CFError::new("Title", "Detail", "Fix");
        assert!(e.brief().contains("Detail"));
        assert!(e.explain().contains("Fix"));
    }
}
