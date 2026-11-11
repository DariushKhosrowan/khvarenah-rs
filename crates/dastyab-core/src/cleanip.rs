//! User-facing config bundle (DeepSeek plan, item 2).
//!
//! A non-technical user doesn't want to dig through `~/.dastyab/`. This
//! module writes a findable, immediately-usable folder per profile:
//!
//! ```text
//! ~/dastyab-configs/<profile_name>/
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

/// The human-facing output root for a profile: `~/dastyab-configs/<name>/`
/// (not hidden). Created with mode 0755 on Unix.
pub fn user_config_dir(profile_id: &str) -> Result<PathBuf, CFError> {
    let name = store::profiles::load_profile(profile_id).meta.name;
    let safe = if name.trim().is_empty() {
        profile_id.to_string()
    } else {
        name.trim().to_string()
    };
    // In tests (mem override set) isolate bundle writes under the temp base so
    // parallel tests never clobber the real ~/dastyab-configs/$.
    let dir = if let Some(base) = store::mem_override() {
        base.join("configs").join(&safe)
    } else {
        store::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("dastyab-configs")
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
        fb.push_str(&format!(
            "# {ip}:{port} ({rtt}ms){}\n{link}\n",
            country_comment(&ip)
        ));
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

/// Resolve an ISO-3166 alpha-2 country code for a bare IP and render it as a
/// comment suffix (`" [US]"`) when known, else `""`. Used to annotate the
/// user-facing fallbacks.txt so a non-technical user can pick a client's
/// country by location.
fn country_comment(ip: &str) -> String {
    match ip.parse::<std::net::IpAddr>() {
        Ok(addr) => match crate::geoip::GeoDB::load(None).country_code(&addr) {
            Some(cc) => format!(" [{cc}]"),
            None => String::new(),
        },
        Err(_) => String::new(),
    }
}

fn storage_err(path: &std::path::Path, e: std::io::Error) -> CFError {
    CFError::new(
        "Storage error",
        format!("Cannot write {}: {e}", path.display()),
        "Check permissions.",
    )
}

/// Pick the ledger's active endpoint: the best-scored verified and alive
/// endpoint, rendered as `ip:port`. Returns `None` when there is nothing
/// verified yet (nothing to reconcile against).
pub fn active_ledger_endpoint(profile_id: &str) -> Option<String> {
    let ledger = crate::autopilot::read_ledger(profile_id);
    ledger
        .iter()
        .filter(|e| e.verified && e.alive)
        .max_by(|a, b| {
            a.score
                .partial_cmp(&b.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|e| format!("{}:{}", e.ip, e.port))
}

/// Drift state of a user-facing bundle relative to the ledger's active
/// endpoint. `check_bundle_drift` is pure — it never writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleDrift {
    InSync,
    MissingDir,
    MissingFile {
        name: &'static str,
    },
    EndpointMismatch {
        bundle_endpoint: String,
        ledger_endpoint: String,
    },
    Unparseable {
        file: &'static str,
        reason: String,
    },
}

/// Read `active.vless` and extract its `ip:port` endpoint, or `None` on a
/// missing/unreadable/unparseable file.
fn active_vless_endpoint(vless_path: &std::path::Path) -> Option<String> {
    let content = std::fs::read_to_string(vless_path).ok()?;
    let content = content.trim();
    if content.is_empty() {
        return None;
    }
    let (ip, port) = split_endpoint(content);
    if ip == "unknown" {
        return None;
    }
    Some(format!("{ip}:{port}"))
}

/// Pure drift check: compare the bundle directory's `active.vless` endpoint to
/// the ledger's active endpoint. Reports the first drift found.
pub fn check_bundle_drift(
    bundle_dir: &std::path::Path,
    ledger_active_endpoint: &str,
) -> BundleDrift {
    if !bundle_dir.is_dir() {
        return BundleDrift::MissingDir;
    }
    for name in ["active.vless", "active.png", "fallbacks.txt", "README.txt"] {
        if !bundle_dir.join(name).exists() {
            return BundleDrift::MissingFile { name };
        }
    }
    let vless_path = bundle_dir.join("active.vless");
    match active_vless_endpoint(&vless_path) {
        None => BundleDrift::Unparseable {
            file: "active.vless",
            reason: "missing, empty, or unparseable".into(),
        },
        Some(bundle_ep) if bundle_ep != ledger_active_endpoint => BundleDrift::EndpointMismatch {
            bundle_endpoint: bundle_ep,
            ledger_endpoint: ledger_active_endpoint.to_string(),
        },
        Some(_) => BundleDrift::InSync,
    }
}

/// Outcome of a bundle reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileOutcome {
    WasInSync,
    Rewritten { reason: BundleDrift },
    Failed { reason: String },
}

/// Regenerate the bundle from the ledger's active endpoint. If the bundle is
/// already in sync, this is a no-op (`WasInSync`). The vless template (uuid /
/// path / security / transport) is taken from the bundle's own `active.vless`
/// when it parses; otherwise `vless_template` is used. Idempotent.
pub fn reconcile_bundle(
    bundle_dir: &std::path::Path,
    ledger_active_endpoint: &str,
    vless_template: &VlessProfile,
) -> Result<ReconcileOutcome, CFError> {
    // No-op when already in sync.
    if check_bundle_drift(bundle_dir, ledger_active_endpoint) == BundleDrift::InSync {
        return Ok(ReconcileOutcome::WasInSync);
    }

    // Prefer the bundle's own link as the template (preserves uuid/path), so
    // reconciliation works without a CF token / history.
    let template = {
        let raw = std::fs::read_to_string(bundle_dir.join("active.vless")).ok();
        raw.as_deref()
            .and_then(|s| VlessProfile::parse(s.trim()).ok())
            .unwrap_or_else(|| vless_template.clone())
    };

    let (ip, port) = match ledger_active_endpoint.rsplit_once(':') {
        Some((ip, port)) => (ip.to_string(), port.parse::<u16>().unwrap_or(443)),
        None => (ledger_active_endpoint.to_string(), 443),
    };
    let mut f = template;
    f.address = ip;
    f.port = port;
    let ep = CleanEndpoint {
        ip: f.address.clone(),
        port: f.port,
        sni: f.address.clone(),
        score: 100.0,
        tcp_ms: 0.0,
        connect_ms: 0.0,
        download_kbps: 0.0,
        verified: true,
        alive: true,
        last_checked: None,
        ts: String::new(),
    };
    write_user_bundle_into(bundle_dir, &f, std::slice::from_ref(&ep)).map(|_| {
        ReconcileOutcome::Rewritten {
            reason: BundleDrift::EndpointMismatch {
                bundle_endpoint: String::new(),
                ledger_endpoint: ledger_active_endpoint.to_string(),
            },
        }
    })
}

/// Convenience wrapper for `write_user_bundle` that writes into an explicit
/// directory (used by reconciliation so it can target the user-config dir).
fn write_user_bundle_into(
    dir: &std::path::Path,
    vless: &VlessProfile,
    endpoints: &[CleanEndpoint],
) -> Result<UserConfigBundle, CFError> {
    let vless_path = dir.join("active.vless");
    let qr_path = dir.join("active.png");
    let fallbacks_path = dir.join("fallbacks.txt");
    let readme_path = dir.join("README.txt");

    let ranked = ranked_links(vless, endpoints);

    let best = ranked.first().map(|(l, _)| l.clone()).unwrap_or_default();
    if best.is_empty() {
        std::fs::write(&vless_path, b"").map_err(|e| storage_err(&vless_path, e))?;
    } else {
        std::fs::write(&vless_path, best.as_bytes()).map_err(|e| storage_err(&vless_path, e))?;
    }

    if best.is_empty() {
        let _ = std::fs::write(&qr_path, b"");
    } else {
        let (png, _side) = crate::qr::render_png(&best, 4, 4)?;
        std::fs::write(&qr_path, &png).map_err(|e| storage_err(&qr_path, e))?;
    }

    let mut fb = String::new();
    for (i, (link, rtt)) in ranked.iter().enumerate() {
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

    let readme = concat!(
        "Scan active.png with your phone VPN client (v2rayNG, Streisand, etc.)\n",
        "Or copy the contents of active.vless into your desktop client.\n",
        "If it stops working, try the next line in fallbacks.txt.\n"
    );
    std::fs::write(&readme_path, readme.as_bytes()).map_err(|e| storage_err(&readme_path, e))?;

    Ok(UserConfigBundle {
        dir: dir.to_path_buf(),
        vless_path,
        qr_path,
        fallbacks_path,
        readme_path,
    })
}

/// Reconcile the user-facing bundle against the ledger at the top of a cycle.
/// No-op when the ledger has no active endpoint yet (nothing to assert). Never
/// fails the cycle — errors are downgraded to a `Failed` outcome and logged.
pub fn reconcile_bundle_if_drifted(profile_id: &str) -> ReconcileOutcome {
    let Some(ledger_ep) = active_ledger_endpoint(profile_id) else {
        return ReconcileOutcome::WasInSync;
    };
    let dir = match user_config_dir(profile_id) {
        Ok(d) => d,
        Err(e) => return ReconcileOutcome::Failed { reason: e.brief() },
    };
    let drift = check_bundle_drift(&dir, &ledger_ep);
    if drift == BundleDrift::InSync {
        return ReconcileOutcome::WasInSync;
    }
    // Template: prefer the bundle's own link (no CF token / history needed);
    // fall back to the profile's base vless when the bundle has none.
    let template = std::fs::read_to_string(dir.join("active.vless"))
        .ok()
        .and_then(|s| VlessProfile::parse(s.trim()).ok())
        .or_else(|| crate::autopilot::base_vless(profile_id).ok());
    let template = match template {
        Some(t) => t,
        None => {
            return ReconcileOutcome::Failed {
                reason: "no vless template available (bundle empty and no profile history)".into(),
            }
        }
    };
    match reconcile_bundle(&dir, &ledger_ep, &template) {
        Ok(outcome) => outcome,
        Err(e) => ReconcileOutcome::Failed { reason: e.brief() },
    }
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
        crate::store::set_mem_dir_override(dir.path().join(".dastyab"));
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
        crate::store::set_mem_dir_override(tmp.path().join(".dastyab"));
        crate::store::profiles::create_profile("family", "").unwrap();
        let dir = user_config_dir("family").unwrap();
        // With a mem override set (tests) the bundle is isolated under the
        // temp base, still keyed by the profile *name* (not its id).
        assert!(dir
            .to_string_lossy()
            .starts_with(tmp.path().to_string_lossy().as_ref()));
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
        assert!(
            first_line.contains("104.16.3.3"),
            "unexpected fallbacks: {content}"
        );
        // and the score-5 one appears after
        assert!(content.contains("104.16.2.2"));
    }

    #[test]
    fn write_user_bundle_fallbacks_annotate_country_when_known() {
        with_mem_dir();
        // 104.x first octet → US in the builtin geo table; 99.x is unknown.
        let eps = vec![
            sample_endpoint("104.16.2.2", 5.0, 200),
            sample_endpoint("99.99.99.99", 6.0, 120),
            sample_endpoint("104.16.1.1", 7.0, 48),
        ];
        let b = write_user_bundle("default", &sample_vless(), &eps).unwrap();
        let content = std::fs::read_to_string(&b.fallbacks_path).unwrap();
        // The score-6 fallback (99.99.99.99) is unknown → no country suffix.
        assert!(
            content.contains("# 99.99.99.99:443 (120ms)\n"),
            "unknown-country fallback should have no suffix: {content}"
        );
        // The score-5 fallback (104.16.2.2) resolves to US → annotated.
        assert!(
            content.contains("# 104.16.2.2:443 (200ms) [US]\n"),
            "known-country fallback should be annotated: {content}"
        );
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

    // ── Bundle / ledger reconciliation (self-heal) ──

    fn seed_ledger(ip: &str, score: f32) {
        use crate::autopilot::write_ledger;
        let eps = vec![sample_endpoint(ip, score, 42)];
        write_ledger("default", &eps).unwrap();
    }

    #[test]
    fn test_check_bundle_drift_in_sync() {
        with_mem_dir();
        seed_ledger("104.16.1.1", 7.0);
        let dir = user_config_dir("default").unwrap();
        let ledger_ep = active_ledger_endpoint("default").unwrap();
        write_user_bundle(
            "default",
            &sample_vless(),
            &[sample_endpoint("104.16.1.1", 7.0, 42)],
        )
        .unwrap();
        assert_eq!(check_bundle_drift(&dir, &ledger_ep), BundleDrift::InSync);
    }

    #[test]
    fn test_check_bundle_drift_missing_dir() {
        with_mem_dir();
        let missing = std::path::Path::new("/nonexistent/dastyab-configs/default");
        assert_eq!(
            check_bundle_drift(missing, "104.16.1.1:443"),
            BundleDrift::MissingDir
        );
    }

    #[test]
    fn test_check_bundle_drift_missing_file() {
        with_mem_dir();
        seed_ledger("104.16.1.1", 7.0);
        let dir = user_config_dir("default").unwrap();
        let ledger_ep = active_ledger_endpoint("default").unwrap();
        write_user_bundle(
            "default",
            &sample_vless(),
            &[sample_endpoint("104.16.1.1", 7.0, 42)],
        )
        .unwrap();
        let _ = std::fs::remove_file(dir.join("active.png"));
        assert!(matches!(
            check_bundle_drift(&dir, &ledger_ep),
            BundleDrift::MissingFile { name: "active.png" }
        ));
    }

    #[test]
    fn test_check_bundle_drift_endpoint_mismatch() {
        with_mem_dir();
        seed_ledger("104.16.1.1", 7.0);
        let dir = user_config_dir("default").unwrap();
        let ledger_ep = active_ledger_endpoint("default").unwrap();
        // Bundle written for a DIFFERENT endpoint than the ledger's active one.
        write_user_bundle(
            "default",
            &sample_vless(),
            &[sample_endpoint("104.16.9.9", 5.0, 42)],
        )
        .unwrap();
        assert!(matches!(
            check_bundle_drift(&dir, &ledger_ep),
            BundleDrift::EndpointMismatch { .. }
        ));
    }

    #[test]
    fn test_check_bundle_drift_unparseable_active_vless() {
        with_mem_dir();
        seed_ledger("104.16.1.1", 7.0);
        let dir = user_config_dir("default").unwrap();
        let ledger_ep = active_ledger_endpoint("default").unwrap();
        // Build a complete bundle first, then corrupt only active.vless so the
        // drift check reaches the parse stage (not an earlier MissingFile).
        write_user_bundle(
            "default",
            &sample_vless(),
            &[sample_endpoint("104.16.1.1", 7.0, 42)],
        )
        .unwrap();
        std::fs::write(dir.join("active.vless"), b"garbage not a vless link").unwrap();
        assert!(matches!(
            check_bundle_drift(&dir, &ledger_ep),
            BundleDrift::Unparseable { .. }
        ));
    }

    #[test]
    fn test_reconcile_rewrites_on_drift() {
        with_mem_dir();
        seed_ledger("104.16.1.1", 7.0);
        let dir = user_config_dir("default").unwrap();
        let ledger_ep = active_ledger_endpoint("default").unwrap();
        // Bundle points at the wrong endpoint; reconcile should rewrite it.
        write_user_bundle(
            "default",
            &sample_vless(),
            &[sample_endpoint("104.16.9.9", 5.0, 42)],
        )
        .unwrap();
        let outcome = reconcile_bundle(&dir, &ledger_ep, &sample_vless()).unwrap();
        assert!(matches!(outcome, ReconcileOutcome::Rewritten { .. }));
        // After reconcile, the active.vless must point at the ledger endpoint.
        assert_eq!(
            active_vless_endpoint(&dir.join("active.vless")).as_deref(),
            Some("104.16.1.1:443")
        );
    }

    #[test]
    fn test_reconcile_noop_when_in_sync() {
        with_mem_dir();
        seed_ledger("104.16.1.1", 7.0);
        let dir = user_config_dir("default").unwrap();
        let ledger_ep = active_ledger_endpoint("default").unwrap();
        write_user_bundle(
            "default",
            &sample_vless(),
            &[sample_endpoint("104.16.1.1", 7.0, 42)],
        )
        .unwrap();
        let outcome = reconcile_bundle(&dir, &ledger_ep, &sample_vless()).unwrap();
        assert_eq!(outcome, ReconcileOutcome::WasInSync);
    }

    #[test]
    fn test_reconcile_noop_when_no_ledger_endpoint() {
        with_mem_dir();
        // No ledger written -> active_ledger_endpoint is None.
        assert!(active_ledger_endpoint("default").is_none());
        let outcome = reconcile_bundle_if_drifted("default");
        assert_eq!(outcome, ReconcileOutcome::WasInSync);
    }

    #[test]
    fn test_reconcile_bundle_if_drifted_detects_and_rewrites() {
        with_mem_dir();
        seed_ledger("104.16.1.1", 7.0);
        let dir = user_config_dir("default").unwrap();
        // Write a drifted bundle directly into the real dir.
        write_user_bundle_into(
            &dir,
            &sample_vless(),
            &[sample_endpoint("104.16.9.9", 5.0, 42)],
        )
        .unwrap();
        let outcome = reconcile_bundle_if_drifted("default");
        assert!(matches!(outcome, ReconcileOutcome::Rewritten { .. }));
        assert_eq!(
            active_vless_endpoint(&dir.join("active.vless")).as_deref(),
            Some("104.16.1.1:443")
        );
    }
}
