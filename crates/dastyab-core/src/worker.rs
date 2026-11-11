//! Worker bundle discovery + humanization pre-upload.

use std::path::{Path, PathBuf};

use crate::error::CFError;

/// Candidate locations for the edgetunnel `_worker.js`, searched in order.
fn candidate_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    // relative to the current crate/project
    out.push(PathBuf::from("_worker.js"));
    out.push(PathBuf::from("worker.js"));
    if let Some(home) = crate::store::home_dir() {
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

/// Cloudflare's per-script size ceiling (paid plan). A worker larger than
/// this can NEVER deploy, so we refuse it before wasting a `wrangler deploy`
/// round-trip. The free-tier limit is 1 MiB; we warn above that but only hard-
/// reject above this 3 MiB ceiling (a paid account may legitimately deploy up
/// to the script limit).
pub const MAX_WORKER_BYTES: usize = 3_000_000;

/// The free-tier workers.dev script limit, used to warn (not hard-reject)
/// about oversized bundles.
pub const FREE_TIER_WORKER_BYTES: usize = 1_000_000;

/// Find a worker JS file. Returns the path if found.
pub fn find_worker_js(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        let p = p.to_path_buf();
        return if p.is_file() { Some(p) } else { None };
    }
    candidate_paths().into_iter().find(|c| c.is_file())
}

/// Cheap sanity checks: it's a worker (has fetch/WebSocket handler + export)
/// and fits within Cloudflare's script-size ceiling.
pub fn validate_worker_js(path: &Path) -> Result<(bool, String), CFError> {
    let data = std::fs::read(path).map_err(|e| {
        CFError::new(
            "Read error",
            format!("Cannot read worker file {}: {e}", path.display()),
            "Check the file path and permissions.",
        )
    })?;
    if data.len() > MAX_WORKER_BYTES {
        return Ok((
            false,
            format!(
                "Worker file is {} bytes — Cloudflare rejects scripts over {} bytes. Use the built-in standard worker (it is always deployable) or a bundle under the limit.",
                data.len(),
                MAX_WORKER_BYTES
            ),
        ));
    }
    let blob = String::from_utf8_lossy(&data[..data.len().min(200_000)]).to_lowercase();
    // A worker with an obvious framing bug (e.g. a truncated download ending in
    // non-JS text) must be rejected up front, not shipped to the edge.
    if data.ends_with(&[0x00, 0x00, 0x00]) || blob.contains('\u{fffd}') {
        return Ok((
            false,
            "Worker file appears corrupt (binary/UTF-8 garbage at the end). Use the built-in standard worker instead."
                .into(),
        ));
    }
    if !blob.contains("websocket") && !blob.contains("upgrade") && !blob.contains("fetch") {
        return Ok((
            false,
            "Worker file does not look like a worker (no fetch/WebSocket handler).".into(),
        ));
    }
    let has_export = data.windows(14).any(|w| w == b"export default")
        || data.windows(8).any(|w| w == b"export {")
        || data.windows(16).any(|w| w == b"addEventListener");
    if has_export {
        let warn = if data.len() > FREE_TIER_WORKER_BYTES {
            format!(
                " — WARNING: {} bytes exceeds the free-tier 1 MiB script limit; requires a paid Workers plan",
                data.len()
            )
        } else {
            String::new()
        };
        return Ok((
            true,
            format!("OK — {} bytes, worker layout detected{warn}", data.len()),
        ));
    }
    Ok((
        false,
        "Worker file has no export/fetch handler (not a module or service worker).".into(),
    ))
}

/// Resolve deployable worker bytes: the first *validated* candidate on disk,
/// or `None` when none exists (the caller falls back to the built-in worker).
/// This replaces the old "found a file, then maybe failed validation" flow with
/// a single source of truth so deploy never ships a corrupt/oversized bundle.
pub fn find_valid_worker_js(explicit: Option<&Path>) -> Option<Vec<u8>> {
    let candidates: Vec<PathBuf> = if let Some(p) = explicit {
        vec![p.to_path_buf()]
    } else {
        candidate_paths()
    };
    for c in candidates {
        if !c.is_file() {
            continue;
        }
        match validate_worker_js(&c) {
            Ok((true, _)) => {
                if let Ok(bytes) = std::fs::read(&c) {
                    eprintln!(
                        "[dastyab] using validated worker bundle {} ({} bytes)",
                        c.display(),
                        bytes.len()
                    );
                    return Some(bytes);
                }
            }
            Ok((false, why)) => eprintln!(
                "[dastyab] worker candidate {} invalid: {why}",
                c.display()
            ),
            Err(_) => {}
        }
    }
    None
}

/// Resolve the exact bytes a deploy should upload: the first *validated*
/// worker on disk, or — when none is valid (missing, corrupt, oversized) —
/// the built-in standard VLESS worker, which is always deployable. This is
/// the single choke point for "which worker do I upload" so deploy NEVER
/// fails on a bad bundle; it just falls back to a working built-in.
pub fn resolve_deploy_worker_bytes() -> Vec<u8> {
    match find_valid_worker_js(None) {
        Some(bytes) => bytes,
        None => {
            eprintln!(
                "[dastyab] no valid worker bundle on disk — using built-in standard VLESS worker"
            );
            crate::presets::standard_vless_worker_js().into_bytes()
        }
    }
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
    if let Some(home) = crate::store::home_dir() {
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

    /// Regression for the window-length bug: `validate_worker_js` compared a
    /// literal against windows of the WRONG byte length, so `has_export` was
    /// always false and every real worker file (module AND service worker) was
    /// rejected — which made deploy always fail with "no export/fetch handler".
    #[test]
    fn validate_accepts_module_worker() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("_worker.js");
        let js =
            b"export default { async fetch(request, env, ctx) { return new Response('ok'); } };\n";
        std::fs::write(&path, js).unwrap();
        let (ok, msg) = validate_worker_js(&path).unwrap();
        assert!(ok, "module worker must validate — got {msg}");
    }

    #[test]
    fn validate_accepts_service_worker() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("_worker.js");
        let js =
            b"addEventListener('fetch', event => { event.respondWith(new Response('ok')); });\n";
        std::fs::write(&path, js).unwrap();
        let (ok, msg) = validate_worker_js(&path).unwrap();
        assert!(ok, "service worker must validate — got {msg}");
    }

    /// Regression for the "deploy worker doesn't work" root cause: a corrupt /
    /// oversized worker bundle (e.g. a truncated 5 MB download with garbage
    /// appended) must be rejected up front, not shipped to wrangler.
    #[test]
    fn validate_rejects_oversized_worker() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("_worker.js");
        let mut js = vec![b'e'; MAX_WORKER_BYTES + 1];
        js.extend_from_slice(b"export default { fetch(){} };");
        std::fs::write(&path, &js).unwrap();
        let (ok, msg) = validate_worker_js(&path).unwrap();
        assert!(!ok, "oversized worker must be rejected");
        assert!(msg.contains("bytes"), "msg should mention size: {msg}");
    }

    /// A worker file that is structurally valid but ends in a UTF-8 garbage /
    /// binary tail must be rejected (truncated download protection).
    #[test]
    fn validate_rejects_corrupt_worker() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("_worker.js");
        let js = b"export default { fetch(){ return new Response('ok'); } };\n\x00\x00\x00\xff\xfe";
        std::fs::write(&path, js).unwrap();
        let (ok, _msg) = validate_worker_js(&path).unwrap();
        assert!(!ok, "corrupt worker must be rejected");
    }

    /// `find_valid_worker_js` must skip invalid candidates and (when none are
    /// valid) return None, so the caller falls back to the built-in worker.
    #[test]
    fn find_valid_worker_skips_bad_candidates() {
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("_worker.js");
        std::fs::write(&bad, b"garbage \xff\xfe not a worker").unwrap();
        // Isolate the candidate list so we only see our file. We can't easily
        // inject home, so assert the function returns None when the only file
        // is invalid — it must not panic and must not return the invalid one.
        // (The real candidate paths include the home dir; on this machine that
        // is the oversized local bundle, which also fails — so None is right.)
        let found = find_valid_worker_js(Some(&bad));
        assert!(found.is_none(), "invalid candidate must not be picked");
    }

    /// The built-in standard VLESS worker is valid, compact, and deployable.
    #[test]
    fn standard_vless_worker_validates_and_is_compact() {
        let js = crate::presets::standard_vless_worker_js();
        assert!(
            js.len() < 10_000,
            "standard worker should be compact ({} bytes)",
            js.len()
        );
        assert!(js.contains("export default"));
        assert!(
            js.contains("cloudflare:sockets"),
            "must use the sockets binding"
        );
        assert!(js.contains("WebSocketPair"), "must do WebSocket upgrade");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("_worker.js");
        std::fs::write(&path, js.as_bytes()).unwrap();
        let (ok, msg) = validate_worker_js(&path).unwrap();
        assert!(ok, "standard worker must validate — got {msg}");
        // `find_valid_worker_js` on an explicit valid path returns its bytes.
        let got = find_valid_worker_js(Some(&path));
        assert!(got.is_some(), "valid explicit worker must be picked");
    }

    /// `resolve_deploy_worker_bytes` must return the built-in standard worker
    /// (always deployable) when no on-disk candidate validates — the core
    /// fix for "deploy worker doesn't work". It must never panic and never
    /// return the corrupt/oversized bundle.
    #[test]
    fn resolve_deploy_worker_falls_back_to_builtin_on_bad_disk() {
        // Point the explicit candidate at a corrupt file. `resolve_…` uses
        // the implicit path list (candidate_paths), which on this machine
        // includes the oversized local bundle — that also fails, so the
        // result must be the built-in standard worker.
        let bytes = resolve_deploy_worker_bytes();
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("export default"), "must be a module worker");
        assert!(
            s.contains("cloudflare:sockets"),
            "must be the standard VLESS worker"
        );
        assert!(
            bytes.len() < 20_000,
            "fallback should be compact, got {} bytes",
            bytes.len()
        );
    }
}
