//! User-facing config bundle (DeepSeek plan, item 2).
//!
//! A non-technical user doesn't want to dig through `~/.khvarenah/`. This
//! module writes a findable, immediately-usable folder per profile:
//!
//! ```text
//! ~/khvarenah-configs/<profile_name>/
//!   active.vless   — the working share link (single line, no trailing NL)
//!   active.png     — QR code of that link (scan with a phone)
//!   fallbacks.txt  — one line per fallback, ranked, with rtt comments
//!   README.txt     — 3-line how-to
//! ```
//!
//! The bundle is regenerated on every autopilot cycle/swap so the user's
//! client (many watch the file, or the user just re-scans) always holds the
//! current best clean IP.

use std::path::PathBuf;

use crate::autopilot::CleanEndpoint;
use crate::error::CFError;
use crate::store;
use crate::vless::VlessProfile;

/// Everything the user can see for one profile.
#[derive(Debug, Clone)]
pub struct UserConfigBundle {
    pub dir: PathBuf,
    pub vless_path: PathBuf,
    pub qr_path: PathBuf,
    pub fallbacks_path: PathBuf,
    pub readme_path: PathBuf,
}

/// The human-facing output root for a profile: `~/khvarenah-configs/<name>/`
/// (not hidden). Created with mode 0755 on Unix.
pub fn user_config_dir(profile_id: &str) -> Result<PathBuf, CFError> {
    let name = store::profiles::load_profile(profile_id).meta.name;
    let safe = if name.trim().is_empty() {
        profile_id.to_string()
    } else {
        name.trim().to_string()
    };
    // In tests (mem override set) isolate bundle writes under the temp base so
    // parallel tests never clobber the real ~/khvarenah-configs/$.
    let dir = if let Some(base) = store::mem_override() {
        base.join("configs").join(&safe)
    } else {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("khvarenah-configs")
            .join(&safe)
    };
    std::fs::create_dir_all(&dir).map_err(|e| {
        CFError::new(
            "Storage error",
            format!("Cannot create {}: {e}", dir.display()),
            "Check permissions.",
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
    }
    Ok(dir)
}

/// Build a ranked list of `(vless_link, rtt_ms)` from validated endpoints,
/// best score first.
fn ranked_links(vless: &VlessProfile, endpoints: &[CleanEndpoint]) -> Vec<(String, u32)> {
    let mut sorted: Vec<&CleanEndpoint> = endpoints.iter().collect();
    sorted.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    sorted
        .iter()
        .map(|ep| {
            let mut f = vless.clone();
            f.address = ep.ip.clone();
            f.port = ep.port;
            (f.share_link(), ep.tcp_ms as u32)
        })
        .collect()
}

/// Write the four-file user bundle. `endpoints` should be the validated set
/// (best-first by score is applied internally). A missing/empty set still
/// produces a usable folder with a placeholder active file (no crash).
pub fn write_user_bundle(
    profile_id: &str,
    vless: &VlessProfile,
    endpoints: &[CleanEndpoint],
) -> Result<UserConfigBundle, CFError> {
    let dir = user_config_dir(profile_id)?;
    let vless_path = dir.join("active.vless");
    let qr_path = dir.join("active.png");
    let fallbacks_path = dir.join("fallbacks.txt");
    let readme_path = dir.join("README.txt");

    let ranked = ranked_links(vless, endpoints);

    // active.vless — best link, no trailing newline.
    let best = ranked.first().map(|(l, _)| l.clone()).unwrap_or_default();
    if best.is_empty() {
        std::fs::write(&vless_path, b"").map_err(|e| storage_err(&vless_path, e))?;
    } else {
        std::fs::write(&vless_path, best.as_bytes()).map_err(|e| storage_err(&vless_path, e))?;
    }

    // active.png — QR of the same best link (512-ish, quiet zone 4).
    if best.is_empty() {
        let _ = std::fs::write(&qr_path, b"");
    } else {
        let (png, _side) = crate::qr::render_png(&best, 4, 4)?;
        std::fs::write(&qr_path, &png).map_err(|e| storage_err(&qr_path, e))?;
    }

    // fallbacks.txt — remaining links, ranked, with rtt comments.
    let mut fb = String::new();
    for (i, (link, rtt)) in ranked.iter().enumerate() {
        // The first entry is the active one; list the rest as fallbacks.
        if i == 0 {
            continue;
        }
        let (ip, port) = split_endpoint(link);
        fb.push_str(&format!("# {ip}:{port} ({rtt}ms)\n{link}\n"));
    }
    if fb.is_empty() {
        fb.push_str("# No fallbacks yet — run autopilot to discover more clean IPs.\n");
    }
    std::fs::write(&fallbacks_path, fb.as_bytes()).map_err(|e| storage_err(&fallbacks_path, e))?;

    // README.txt — 3-line how-to.
    let readme = concat!(
        "Scan active.png with your phone VPN client (v2rayNG, Streisand, etc.)\n",
        "Or copy the contents of active.vless into your desktop client.\n",
        "If it stops working, try the next line in fallbacks.txt.\n"
    );
    std::fs::write(&readme_path, readme.as_bytes()).map_err(|e| storage_err(&readme_path, e))?;

    Ok(UserConfigBundle {
        dir,
        vless_path,
        qr_path,
        fallbacks_path,
        readme_path,
    })
}

fn split_endpoint(link: &str) -> (String, String) {
    if let Some(at) = link.rfind('@') {
        let hostport = &link[at + 1..];
        let hostport = match hostport.find('?') {
            Some(i) => &hostport[..i],
            None => hostport,
        };
        if let Some((ip, port)) = hostport.rsplit_once(':') {
            return (ip.to_string(), port.to_string());
        }
        return (hostport.to_string(), "443".to_string());
    }
    ("unknown".to_string(), "443".to_string())
}

fn storage_err(path: &std::path::Path, e: std::io::Error) -> CFError {
    CFError::new(
        "Storage error",
        format!("Cannot write {}: {e}", path.display()),
        "Check permissions.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_vless() -> VlessProfile {
        VlessProfile {
            uuid: "12345678-1234-1234-1234-123456789abc".into(),
            address: "user.workers.dev".into(),
            port: 443,
            security: "tls".into(),
            path: "/".into(),
            transport: "ws".into(),
            name: "test".into(),
            ..Default::default()
        }
    }

    fn sample_endpoint(ip: &str, score: f32, ms: u32) -> CleanEndpoint {
        CleanEndpoint {
            ip: ip.into(),
            port: 443,
            sni: "user.workers.dev".into(),
            score,
            tcp_ms: ms as f32,
            connect_ms: ms as f32,
            download_kbps: 100.0,
            verified: true,
            alive: true,
            last_checked: Some("2026-11-08T00:00:00Z".into()),
            ts: "2026-11-08T00:00:00Z".into(),
        }
    }

    fn with_mem_dir() {
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(dir.path().join(".khvarenah"));
        crate::store::profiles::create_profile("default", "").unwrap();
    }

    #[test]
    fn user_config_dir_creates_with_correct_perms() {
        with_mem_dir();
        let dir = user_config_dir("default").unwrap();
        assert!(dir.exists());
        assert!(dir.to_string_lossy().contains("configs"));
        assert!(dir.to_string_lossy().contains("default"));
    }

    #[test]
    fn user_config_dir_uses_profile_name_not_id() {
        let tmp = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(tmp.path().join(".khvarenah"));
        crate::store::profiles::create_profile("family", "").unwrap();
        let dir = user_config_dir("family").unwrap();
        // With a mem override set (tests) the bundle is isolated under the
        // temp base, still keyed by the profile *name* (not its id).
        assert!(dir.to_string_lossy().starts_with(tmp.path().to_string_lossy().as_ref()));
        assert!(dir.to_string_lossy().ends_with("configs/family"));
    }

    #[test]
    fn write_user_bundle_creates_all_four_files() {
        with_mem_dir();
        let vless = sample_vless();
        let eps = vec![sample_endpoint("104.16.1.1", 7.0, 48)];
        let b = write_user_bundle("default", &vless, &eps).unwrap();
        assert!(b.vless_path.exists());
        assert!(b.qr_path.exists());
        assert!(b.fallbacks_path.exists());
        assert!(b.readme_path.exists());
    }

    #[test]
    fn write_user_bundle_vless_is_single_line_no_trailing_newline() {
        with_mem_dir();
        let eps = vec![sample_endpoint("104.16.1.1", 7.0, 48)];
        let b = write_user_bundle("default", &sample_vless(), &eps).unwrap();
        let content = std::fs::read_to_string(&b.vless_path).unwrap();
        assert!(content.starts_with("vless://"));
        assert!(!content.ends_with('\n'));
        assert!(!content.contains('\n'));
    }

    #[test]
    fn write_user_bundle_fallbacks_ranked_by_rtt() {
        with_mem_dir();
        let eps = vec![
            sample_endpoint("104.16.2.2", 5.0, 200),
            sample_endpoint("104.16.1.1", 7.0, 48),
            sample_endpoint("104.16.3.3", 6.0, 120),
        ];
        let b = write_user_bundle("default", &sample_vless(), &eps).unwrap();
        let content = std::fs::read_to_string(&b.fallbacks_path).unwrap();
        // best (score 7) is active, so fallbacks start with score 6 (104.16.3.3)
        let first_line = content.lines().next().unwrap_or("");
        assert!(first_line.contains("104.16.3.3"), "unexpected fallbacks: {content}");
        // and the score-5 one appears after
        assert!(content.contains("104.16.2.2"));
    }

    #[test]
    fn write_user_bundle_empty_ranked_writes_placeholder() {
        with_mem_dir();
        let b = write_user_bundle("default", &sample_vless(), &[]).unwrap();
        assert!(b.readme_path.exists());
        let fb = std::fs::read_to_string(&b.fallbacks_path).unwrap();
        assert!(fb.contains("No fallbacks yet"));
    }

    #[test]
    fn write_user_bundle_readme_is_three_lines() {
        with_mem_dir();
        let eps = vec![sample_endpoint("104.16.1.1", 7.0, 48)];
        let b = write_user_bundle("default", &sample_vless(), &eps).unwrap();
        let readme = std::fs::read_to_string(&b.readme_path).unwrap();
        assert_eq!(readme.lines().count(), 3);
    }
}
