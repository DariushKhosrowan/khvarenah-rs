//! Worker bundle discovery + humanization pre-upload.

use std::path::{Path, PathBuf};

use crate::error::CFError;

/// Candidate locations for the edgetunnel `_worker.js`, searched in order.
fn candidate_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    // relative to the current crate/project
    out.push(PathBuf::from("_worker.js"));
    out.push(PathBuf::from("worker.js"));
    if let Some(home) = dirs::home_dir() {
        out.push(
            home.join("Projects")
                .join("cf-worker-proxy")
                .join("_worker.js"),
        );
        out.push(
            home.join("Projects")
                .join("cf-worker-proxy")
                .join("edgetunnel_worker.js"),
        );
    }
    out
}

/// Find a worker JS file. Returns the path if found.
pub fn find_worker_js(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        let p = p.to_path_buf();
        return if p.is_file() { Some(p) } else { None };
    }
    candidate_paths().into_iter().find(|c| c.is_file())
}
/// Cheap sanity checks: it's a worker (has fetch/WebSocket handler + export).
pub fn validate_worker_js(path: &Path) -> Result<(bool, String), CFError> {
    let data = std::fs::read(path).map_err(|e| {
        CFError::new(
            "Read error",
            format!("Cannot read worker file {}: {e}", path.display()),
            "Check the file path and permissions.",
        )
    })?;
    let blob = String::from_utf8_lossy(&data[..data.len().min(200_000)]).to_lowercase();
    if !blob.contains("websocket") && !blob.contains("upgrade") && !blob.contains("fetch") {
        return Ok((
            false,
            "Worker file does not look like a worker (no fetch/WebSocket handler).".into(),
        ));
    }
    let has_export = data.windows(13).any(|w| w == b"export default")
        || data.windows(9).any(|w| w == b"export {")
        || data.windows(15).any(|w| w == b"addEventListener");
    if has_export {
        return Ok((
            true,
            format!("OK — {} bytes, worker layout detected", data.len()),
        ));
    }
    Ok((
        false,
        "Worker file has no export/fetch handler (not a module or service worker).".into(),
    ))
}

/// Default deployment manifest.
pub fn default_manifest() -> serde_json::Value {
    serde_json::json!({
        "compatibility_date": "2026-07-01",
        "compatibility_flags": ["nodejs_compat"],
    })
}

/// Normalize a worker name to CF's slug rules.
pub fn safe_worker_name(raw: &str) -> String {
    let mut s = raw.trim().to_lowercase();
    s = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    // collapse runs of '-'
    let mut out = String::new();
    let mut prev_dash = false;
    for c in s.chars() {
        if c == '-' {
            if !prev_dash {
                out.push(c);
            }
            prev_dash = true;
        } else {
            out.push(c);
            prev_dash = false;
        }
    }
    let out = out.trim_matches('-').to_string();
    if out.is_empty() {
        return "cf-worker-proxy".to_string();
    }
    out.chars().take(64).collect()
}

/// A safe default worker name — the OS account name, never a "vpn" label.
pub fn default_worker_name() -> String {
    if let Some(home) = dirs::home_dir() {
        if let Some(user) = home.file_name().and_then(|s| s.to_str()) {
            let u = safe_worker_name(user);
            if !u.is_empty() && u != "root" && u != "admin" {
                return u.chars().take(32).collect();
            }
        }
    }
    "khosrowan".to_string()
}

/// Worker name derived from a Cloudflare account name.
pub fn worker_name_from_account(account_name: Option<&str>) -> String {
    if let Some(name) = account_name {
        let s = safe_worker_name(name);
        if !s.is_empty() {
            return s.chars().take(32).collect();
        }
    }
    default_worker_name()
}

/// Generate a v4 UUID string.
pub fn generate_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_name_slugs() {
        assert_eq!(safe_worker_name("My Worker!"), "my-worker");
        assert_eq!(safe_worker_name("   "), "cf-worker-proxy");
        assert_eq!(safe_worker_name("vpn--thing"), "vpn-thing");
    }

    #[test]
    fn default_name_not_vpn() {
        let n = default_worker_name();
        assert!(!n.to_lowercase().contains("vpn"));
    }

    #[test]
    fn uuid_is_v4_shape() {
        let u = generate_uuid();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");
    }
}
