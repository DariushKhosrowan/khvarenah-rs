//! Self-update support for Khvarenah.
//!
//! Checks GitHub for the newest tagged release, compares it against the
//! installed version, and downloads a matching platform binary. This mirrors
//! the Python app's updater but works on compiled binaries rather than pip
//! packages.

use crate::error::CFError;

/// GitHub repo owner.
pub const OWNER: &str = "DariushKhosrowan";
/// GitHub repo name.
pub const REPO: &str = "khvarenah-rs";
/// GitHub API base.
pub const GITHUB_API: &str = "https://api.github.com";

/// How often the daemon checks for an auto-update (seconds). 24h.
pub const AUTO_UPDATE_INTERVAL_SECS: u64 = 86400;

const RELEASE_LATEST: &str =
    "https://api.github.com/repos/DariushKhosrowan/khvarenah-rs/releases/latest";

/// Version metadata parsed from a release tag.
#[derive(Debug, Clone)]
pub struct ReleaseInfo {
    pub tag: String,
    pub version: (u32, u32, u32),
    pub assets: Vec<ReleaseAsset>,
}

/// A named binary asset attached to a release.
#[derive(Debug, Clone)]
pub struct ReleaseAsset {
    pub name: String,
    /// Public download URL (GitHub CDN; may be redirected/blocked on some networks).
    pub url: String,
    /// API asset endpoint (api.github.com) — more reliable on restricted networks.
    pub api_url: String,
}

/// Parse a semantic-ish version string into a comparable tuple.
pub fn normalize_version(v: &str) -> (u32, u32, u32) {
    let v = v.trim().trim_start_matches(['v', 'V']);
    let mut parts = v.split('.');
    let major = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let patch = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (major, minor, patch)
}

/// The version of the currently running binary.
pub fn current_version() -> String {
    crate::VERSION.to_string()
}

/// Fetch metadata for the latest GitHub release.
pub async fn latest_release(timeout: std::time::Duration) -> Result<ReleaseInfo, CFError> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent("khvarenah-selfupdate")
        .build()
        .map_err(|e| CFError::new("Updater error", format!("{e}"), "Internal error."))?;

    let mut req = client.get(RELEASE_LATEST);
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        if !token.is_empty() {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
    }
    let resp = req.send().await.map_err(|e| {
        CFError::new(
            "Updater error",
            format!("Could not reach GitHub: {e}"),
            "Check your network connection.",
        )
    })?;

    if !resp.status().is_success() {
        return Err(CFError::new(
            "Updater error",
            format!("GitHub responded HTTP {}", resp.status()),
            "The repo may be private or the tag missing.",
        ));
    }

    let body: serde_json::Value = resp.json().await.map_err(|e| {
        CFError::new(
            "Updater error",
            format!("{e}"),
            "Malformed GitHub response.",
        )
    })?;

    let tag = body
        .get("tag_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if tag.is_empty() {
        return Err(CFError::new(
            "Updater error",
            "No release tag found.",
            "No public release exists yet.",
        ));
    }

    let mut assets = Vec::new();
    if let Some(arr) = body.get("assets").and_then(|a| a.as_array()) {
        for a in arr {
            let name = a
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let url = a
                .get("browser_download_url")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let api_url = a
                .get("url")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if !name.is_empty() {
                assets.push(ReleaseAsset { name, url, api_url });
            }
        }
    }

    Ok(ReleaseInfo {
        tag: tag.clone(),
        version: normalize_version(&tag),
        assets,
    })
}

/// Determine whether an update is available. Returns `(available, newest_tag)`.
pub async fn update_available(
    timeout: std::time::Duration,
) -> Result<(bool, Option<String>), CFError> {
    let rel = latest_release(timeout).await?;
    let installed = normalize_version(&current_version());
    let available = rel.version > installed;
    Ok((available, available.then_some(rel.tag)))
}

/// Pick the binary asset that matches the current platform (or None).
///
/// Prefers the exact CLI asset name (e.g. `khvarenah-linux-amd64`) and skips
/// the GUI, TUI, `.deb`, `.exe`, and portable-zip variants that share the same
/// platform substring (e.g. `khvarenah-gui-linux-amd64`).
pub fn current_platform_asset(assets: &[ReleaseAsset]) -> Option<ReleaseAsset> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    let exact = "khvarenah-linux-amd64";
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    let exact = "khvarenah-linux-arm64";
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let exact = "khvarenah-macos-arm64";
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    let exact = "khvarenah-macos-x86_64";
    #[cfg(windows)]
    let exact = "khvarenah-windows-amd64.exe";

    // Exact match first.
    if let Some(a) = assets.iter().find(|a| a.name == exact) {
        return Some(a.clone());
    }

    // Fallback: platform substring, but never a gui/tui/deb/exe/portable item.
    let needle = exact.trim_start_matches("khvarenah-");
    assets
        .iter()
        .find(|a| {
            a.name.contains(needle)
                && !a.name.contains("gui")
                && !a.name.contains("tui")
                && !a.name.ends_with(".deb")
                && !a.name.ends_with(".exe")
                && !a.name.contains("portable")
        })
        .cloned()
}

/// Download and install the matching release binary into the bin directory.
pub async fn apply_update(timeout: std::time::Duration) -> Result<String, CFError> {
    let rel = latest_release(timeout).await?;
    if rel.version <= normalize_version(&current_version()) {
        return Ok("Already on the latest version.".to_string());
    }

    let asset = current_platform_asset(&rel.assets).ok_or_else(|| {
        CFError::new(
            "Updater error",
            "No binary asset matches this platform.",
            "The release may not ship a binary for your OS/arch.",
        )
    })?;

    let client = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent("khvarenah-selfupdate")
        .build()
        .map_err(|e| CFError::new("Updater error", format!("{e}"), "Internal error."))?;

    // Prefer the API asset endpoint (api.github.com) — the CDN URL is
    // redirected and is frequently blocked/timeout on restricted networks.
    // Fall back to the public CDN URL if the API endpoint is unavailable.
    let urls: [&str; 2] = [&asset.api_url, &asset.url];
    let mut body = None;
    for u in &urls {
        if u.is_empty() {
            continue;
        }
        let resp = if u.starts_with("https://api.github.com") {
            let mut req = client.get(*u).header("Accept", "application/octet-stream");
            if let Ok(token) = std::env::var("GITHUB_TOKEN") {
                if !token.is_empty() {
                    req = req.header("Authorization", format!("Bearer {token}"));
                }
            }
            req.send().await
        } else {
            client.get(*u).send().await
        };
        match resp {
            Ok(r) if r.status().is_success() => {
                body = Some(r.bytes().await.map_err(|e| {
                    CFError::new("Updater error", format!("{e}"), "Incomplete download.")
                })?);
                break;
            }
            Ok(r) => {
                eprintln!("[updater] download from {u} returned HTTP {}", r.status());
            }
            Err(e) => {
                eprintln!("[updater] download from {u} failed: {e}");
            }
        }
    }

    let body = body.ok_or_else(|| {
        CFError::new(
            "Updater error",
            "All download endpoints failed.",
            "The asset may not exist, or the network blocks GitHub downloads.",
        )
    })?;

    let dir = crate::store::mem_dir().join("bin");
    std::fs::create_dir_all(&dir)
        .map_err(|e| CFError::new("Storage error", format!("{e}"), "Check permissions."))?;

    let target = dir.join("khvarenah-new");
    std::fs::write(&target, &body)
        .map_err(|e| CFError::new("Storage error", format!("{e}"), "Disk full or permissions?"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755));
    }

    Ok(format!(
        "Downloaded {} → {}. Restart Khvarenah to use the new version.",
        rel.tag,
        target.display()
    ))
}

/// Result of an auto-update attempt from the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// Already on the latest version.
    UpToDate,
    /// A new binary was downloaded and atomically swapped over the running
    /// executable. The process should re-exec itself to run the new version.
    Updated { tag: String },
    /// The download or swap failed (caller decides whether to log/ignore).
    Failed(String),
}

/// Daemon-facing auto-update: if a newer release exists, download it and
/// atomically replace the currently-running executable with the new binary.
///
/// On Unix this uses `rename(2)`, which succeeds even while the old binary is
/// still executing (the old inode stays open until the process exits). The
/// caller (daemon loop) then re-execs itself to pick up the new version.
pub async fn ensure_updated_with_swap(
    timeout: std::time::Duration,
) -> Result<UpdateOutcome, CFError> {
    let (available, tag) = update_available(timeout).await?;
    if !available {
        return Ok(UpdateOutcome::UpToDate);
    }
    let tag = tag.unwrap_or_default();

    let rel = latest_release(timeout).await?;
    let asset = current_platform_asset(&rel.assets).ok_or_else(|| {
        CFError::new(
            "Updater error",
            "No binary asset matches this platform.",
            "The release may not ship a binary for your OS/arch.",
        )
    })?;

    let client = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent("khvarenah-selfupdate")
        .build()
        .map_err(|e| CFError::new("Updater error", format!("{e}"), "Internal error."))?;

    // Download to a temp path next to the running binary.
    let exe = std::env::current_exe().map_err(|e| {
        CFError::new("Updater error", e.to_string(), "Cannot locate the binary.")
    })?;
    let tmp = exe.with_extension("new-tmp");
    let urls: [&str; 2] = [&asset.api_url, &asset.url];
    let mut body = None;
    for u in &urls {
        if u.is_empty() {
            continue;
        }
        let resp = if u.starts_with("https://api.github.com") {
            let mut req = client.get(*u).header("Accept", "application/octet-stream");
            if let Ok(token) = std::env::var("GITHUB_TOKEN") {
                if !token.is_empty() {
                    req = req.header("Authorization", format!("Bearer {token}"));
                }
            }
            req.send().await
        } else {
            client.get(*u).send().await
        };
        match resp {
            Ok(r) if r.status().is_success() => {
                body = Some(r.bytes().await.map_err(|e| {
                    CFError::new("Updater error", format!("{e}"), "Incomplete download.")
                })?);
                break;
            }
            Ok(r) => {
                eprintln!("[updater] download from {u} returned HTTP {}", r.status());
            }
            Err(e) => {
                eprintln!("[updater] download from {u} failed: {e}");
            }
        }
    }
    let body = body.ok_or_else(|| {
        CFError::new(
            "Updater error",
            "All download endpoints failed.",
            "The asset may not exist, or the network blocks GitHub downloads.",
        )
    })?;

    if let Err(e) = std::fs::write(&tmp, &body) {
        return Ok(UpdateOutcome::Failed(format!("write temp binary failed: {e}")));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
    }
    // Atomic swap. On Unix, rename over a running binary's path is allowed.
    if let Err(e) = std::fs::rename(&tmp, &exe) {
        let _ = std::fs::remove_file(&tmp);
        return Ok(UpdateOutcome::Failed(format!("binary swap failed: {e}")));
    }
    Ok(UpdateOutcome::Updated { tag })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_version_parses() {
        assert_eq!(normalize_version("v1.2.3"), (1, 2, 3));
        assert_eq!(normalize_version("1.2"), (1, 2, 0));
        assert_eq!(normalize_version("0.0.1"), (0, 0, 1));
        assert_eq!(normalize_version("garbage"), (0, 0, 0));
    }

    #[test]
    fn version_comparison_orders() {
        assert!(normalize_version("v1.2.3") > normalize_version("v1.2.2"));
        assert!(normalize_version("v1.3.0") > normalize_version("v1.2.9"));
        assert_eq!(normalize_version("v2.0.0"), normalize_version("2.0.0"));
    }

    #[test]
    fn platform_asset_filter() {
        let assets = vec![
            ReleaseAsset {
                name: "khvarenah-linux-amd64".into(),
                url: "u1".into(),
                api_url: "api1".into(),
            },
            ReleaseAsset {
                name: "khvarenah-linux-arm64".into(),
                url: "u2".into(),
                api_url: "api2".into(),
            },
        ];
        let picked = current_platform_asset(&assets);
        assert!(picked.is_some());
        assert_eq!(picked.unwrap().url, "u1");
    }

    #[test]
    fn update_outcome_discriminants() {
        assert_eq!(UpdateOutcome::UpToDate, UpdateOutcome::UpToDate);
        assert_eq!(
            UpdateOutcome::Updated { tag: "v1".into() },
            UpdateOutcome::Updated { tag: "v1".into() }
        );
        assert_ne!(
            UpdateOutcome::Updated { tag: "v1".into() },
            UpdateOutcome::Updated { tag: "v2".into() }
        );
        assert_eq!(
            UpdateOutcome::Failed("x".into()),
            UpdateOutcome::Failed("x".into())
        );
    }

    #[test]
    fn auto_update_interval_is_sane() {
        assert_eq!(AUTO_UPDATE_INTERVAL_SECS, 86400);
    }
}
