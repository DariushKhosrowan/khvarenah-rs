//! Clean-IP finding via SenPaiScanner, with smart stop-on-first behavior.
//!
//! SenPaiScanner probes Cloudflare IPs, validates them through a real vless
//! config, and exports clean endpoints. We shell out to its standalone CLI in
//! plain-text mode, collect its live-results file, then verify candidates with
//! a health probe before accepting them.
//!
//! ## Smart behavior
//! * [`scan_once`] stops as soon as ONE verified-working endpoint is found.
//! * [`scan_many`] only continues past the first when the caller explicitly
//!   asks for more configs.

use std::path::{Path, PathBuf};
use std::process::Command;

use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};

use crate::error::CFError;
use crate::health::{check, HealthOptions};
use crate::SENPAI_SCANNER_RELEASE;

/// Location for the auto-installed scanner binary.
pub fn bin_dir() -> PathBuf {
    crate::store::mem_dir().join("bin")
}

pub fn scanner_bin() -> PathBuf {
    #[cfg(windows)]
    let exe = "senpaiscanner.exe";
    #[cfg(not(windows))]
    let exe = "senpaiscanner";
    bin_dir().join(exe)
}

/// Choose the release asset name for the current platform.
pub fn platform_asset() -> &'static str {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        return "SenPaiScanner-1.1.1-cli-windows-amd64.exe";
    }
    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    {
        return "SenPaiScanner-1.1.1-cli-windows-arm64.exe";
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        return "SenPaiScanner-1.1.1-cli-macos-apple-silicon";
    }
    #[cfg(all(target_os = "macos", not(target_arch = "aarch64")))]
    {
        return "SenPaiScanner-1.1.1-cli-macos-intel";
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        return "SenPaiScanner-1.1.1-cli-linux-arm64";
    }
    #[cfg(all(target_os = "linux", target_arch = "arm"))]
    {
        return "SenPaiScanner-1.1.1-cli-linux-armv7";
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        return "SenPaiScanner-1.1.1-cli-linux-amd64";
    }
    #[allow(unreachable_code)]
    {
        "SenPaiScanner-1.1.1-cli-linux-amd64"
    }
}

/// Install the scanner binary. Returns (ok, message).
pub async fn install() -> Result<String, CFError> {
    let dir = bin_dir();
    std::fs::create_dir_all(&dir).map_err(|e| {
        CFError::new(
            "Storage error",
            format!("Cannot create {}: {e}", dir.display()),
            "Check permissions.",
        )
    })?;
    let asset = platform_asset();
    let url = format!(
        "https://github.com/MatinSenPai/SenPaiScanner/releases/download/{SENPAI_SCANNER_RELEASE}/{asset}"
    );
    let tmp = dir.join(format!("{asset}.part"));
    let resp = reqwest::get(&url).await.map_err(|e| {
        CFError::new(
            "Download error",
            format!("Failed to download SenPaiScanner: {e}"),
            "Check your network connection.",
        )
    })?;
    if !resp.status().is_success() {
        return Err(CFError::new(
            "Download error",
            format!("HTTP {} downloading SenPaiScanner", resp.status()),
            "Release may not exist for this platform.",
        ));
    }
    let body = resp
        .bytes()
        .await
        .map_err(|e| CFError::new("Download error", format!("{e}"), "Retry."))?;
    std::fs::write(&tmp, &body).map_err(|e| {
        CFError::new(
            "Storage error",
            format!("Cannot write binary: {e}"),
            "Disk full or permissions?",
        )
    })?;
    let bin = scanner_bin();
    std::fs::rename(&tmp, &bin).map_err(|e| {
        CFError::new(
            "Storage error",
            format!("Cannot finalize install: {e}"),
            "Check permissions.",
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755));
    }
    Ok(format!("Installed SenPaiScanner → {}", bin.display()))
}

/// Ensure the scanner is installed.
pub async fn ensure_installed() -> Result<PathBuf, CFError> {
    let bin = scanner_bin();
    if bin.exists() {
        return Ok(bin);
    }
    install().await?;
    Ok(bin)
}

/// A clean-IP result.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanResult {
    pub ok: bool,
    pub endpoints: Vec<String>,
    pub raw: String,
    pub message: String,
}

/// Regex-ish validator for an endpoint.
/// Immutable, canonical IPv4 octet: non-empty, ≤3 digits, no leading zero
/// (Rust's `Ipv4Addr::parse` rejects `04`), and ≤255.
fn octet_ok(o: &str) -> bool {
    !o.is_empty()
        && o.len() <= 3
        && o.chars().all(|c| c.is_ascii_digit())
        && !(o.len() > 1 && o.starts_with('0'))
        && o.parse::<u16>().map(|v| v <= 255).unwrap_or(false)
}

/// Regex-ish validator for an endpoint.
///
/// Accepts only canonical `ipv4:port` tokens (`1.2.3.4:443`). Leading-zero
/// octets (`04.18.227.124`) are rejected because they are not a canonical IPv4
/// address (and silently normalizing them would produce a bogus *different*
/// IP). A bare IP without a port is rejected — every scanner endpoint we
/// consume carries a port.
fn looks_like_endpoint(e: &str) -> bool {
    let e = e.trim();
    if e.is_empty() {
        return false;
    }
    // ipv4:port
    if let Some((ip, port)) = e.rsplit_once(':') {
        if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            let port_ok = port.parse::<u16>().map(|v| v > 0).unwrap_or(false);
            let octets: Vec<&str> = ip.split('.').collect();
            if octets.len() == 4 {
                return port_ok && octets.iter().all(|o| octet_ok(o));
            }
        }
    }
    false
}

/// Extract candidate `ip:port` endpoints from arbitrary scanner output.
///
/// The tokenizer scans **maximal runs** of `[0-9.:]` as single tokens, rather
/// than sliding one byte at a time. The old sliding-window approach started a
/// new candidate at every digit, so from `104.18.227.124:443` it also emitted
/// the suffix substrings `04.18.227.124:443` and `4.18.227.124:443` (the
/// latter a *valid-but-different* IP) — which then got persisted as "clean
/// IPs". Consuming the whole run and validating it as one token eliminates
/// those spurious suffixes and is linear in the input length.
fn extract_endpoints(text: &str) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Skip ahead to the start of a plausible token (a digit).
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        // Consume the maximal contiguous run of digits, dots, colons.
        while i < bytes.len() && (bytes[i].is_ascii_digit() || matches!(bytes[i], b'.' | b':')) {
            i += 1;
        }
        let tok = &text[start..i];
        if looks_like_endpoint(tok) {
            let low = tok.to_lowercase();
            if !seen.contains(&low) {
                seen.push(low);
            }
        }
        // Otherwise the maximal run was not a valid endpoint (e.g. a bare
        // number, or a glue like "1.2.3.4:443abc"). We have already consumed
        // the entire run, so the next iteration skips past it — this is what
        // makes the scan linear and immune to spurious suffix substrings.
    }
    seen
}

fn collect_endpoints(live_glob: &str, out_file: Option<&Path>, stdout: &str) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    let mut add = |e: &str| {
        let e = e.trim();
        if looks_like_endpoint(e) && !seen.contains(&e.to_lowercase()) {
            seen.push(e.to_lowercase());
        }
    };

    // live results file(s) — glob in the CWD and in bin dir
    for pat in [
        live_glob.to_string(),
        "SenPaiScannerResult-*.txt".to_string(),
    ] {
        if let Ok(entries) = glob_entries(&pat) {
            for f in entries {
                if let Ok(text) = std::fs::read_to_string(&f) {
                    for e in extract_endpoints(&text) {
                        add(&e);
                    }
                }
            }
        }
    }

    // explicit output file
    if let Some(of) = out_file {
        if of.exists() {
            if let Ok(text) = std::fs::read_to_string(of) {
                for e in extract_endpoints(&text) {
                    add(&e);
                }
            }
        }
    }

    // stdout fallback
    for e in extract_endpoints(stdout) {
        add(&e);
    }

    seen
}

fn glob_entries(pattern: &str) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if let Some(dir) = Path::new(pattern).parent() {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for entry in rd.flatten() {
                out.push(entry.path());
            }
        }
    }
    Ok(out)
}

/// Parameters for a scan run. Many user-tunable knobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanParams {
    pub count: u32,
    pub workers: u32,
    pub timeout_s: u32,
    pub gentle: bool,
    pub ports: String,
    pub top: u32,
    pub scan_timeout: u32,
    /// If true, verify candidate endpoints with a health probe before accepting.
    pub verify: bool,
    /// Known-good clean IPs to bias discovery toward. When non-empty, the scan
    /// targets these (and, via `-neighbors`, their /prefix_len siblings) before
    /// falling back to random sampling — the self-improving loop that reuses a
    /// found clean IP to find more near it. Bare IPv4 strings (ports stripped).
    #[serde(default)]
    pub seeds: Vec<String>,
}

impl Default for ScanParams {
    fn default() -> Self {
        Self {
            count: 2000,
            workers: 50,
            timeout_s: 8,
            gentle: true,
            ports: "443".to_string(),
            top: 25,
            scan_timeout: 600,
            verify: true,
            seeds: Vec::new(),
        }
    }
}

/// Run the scanner and collect candidate endpoints. The `desired` count is the
/// max number of endpoints to return (for smart stop-on-first, pass 1).
pub async fn run_scan(
    vless_link: &str,
    params: &ScanParams,
    desired: u32,
) -> Result<ScanResult, CFError> {
    let bin = ensure_installed().await?;
    if vless_link.is_empty() {
        return Err(CFError::new(
            "No config",
            "No vless config available — deploy first.",
            "Deploy a worker, then scan.",
        ));
    }

    let out_file = bin_dir().join("clean-ips.txt");
    let live_glob = bin_dir().join("SenPaiScannerResult-*.txt");

    let mut cmd = Command::new(&bin);
    cmd.arg("scan")
        .arg("-count")
        .arg(params.count.to_string())
        .arg("-workers")
        .arg(params.workers.to_string())
        .arg("-timeout")
        .arg(format!("{}s", params.timeout_s))
        .arg("-ports")
        .arg(&params.ports)
        .arg("-config")
        .arg(vless_link)
        .arg("-top")
        .arg(params.top.to_string())
        .arg("-no-state")
        .arg("-output")
        .arg(&out_file);
    if params.gentle {
        cmd.arg("-gentle");
    } else {
        cmd.arg("-gentle=false");
    }

    // Self-improving seeding: when we already know good clean IPs, target them
    // (and let -neighbors expand around each healthy sibling) so discovery is
    // biased toward proven-good neighborhoods instead of starting from zero.
    // If none are known this loop is a no-op and scanning stays fully random.
    if !params.seeds.is_empty() {
        let targets = params.seeds.join(" ");
        cmd.arg("-targets").arg(&targets).arg("-neighbors");
    }

    let child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| {
            CFError::new(
                "Scanner error",
                format!("Cannot start SenPaiScanner: {e}"),
                "Binary may be missing.",
            )
        })?;

    let out = tokio::task::spawn_blocking(move || child.wait_with_output())
        .await
        .map_err(|e| CFError::new("Scanner error", format!("{e}"), "Internal error."))?
        .map_err(|e| CFError::new("Scanner error", format!("{e}"), "Internal error."))?;

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let combined = format!("{stdout}\n{stderr}");

    let candidates = collect_endpoints(&live_glob.to_string_lossy(), Some(&out_file), &combined);

    // Smart behavior: verify & stop early.
    let mut verified: Vec<String> = Vec::new();
    if params.verify && !candidates.is_empty() {
        let opts = HealthOptions::default();
        for ep in &candidates {
            if let Some((ip, port)) = ep.rsplit_once(':') {
                if let Ok(port) = port.parse::<u16>() {
                    let h = check(ip, port, &opts).await;
                    if h.ok {
                        verified.push(ep.clone());
                        if verified.len() as u32 >= desired {
                            break;
                        }
                    }
                }
            }
            // a little jitter so scans read human
            if rand::rngs::StdRng::from_entropy().gen_range(0.0_f64..1.0) < 0.1 {
                tokio::time::sleep(std::time::Duration::from_millis(
                    rand::rngs::StdRng::from_entropy().gen_range(100..600),
                ))
                .await;
            }
        }
    } else {
        verified = candidates;
    }

    if verified.is_empty() {
        let mut msg =
            "No clean IPs were found. Try a larger -count, a longer timeout, or a different port."
                .to_string();
        if combined.to_lowercase().contains("no healthy")
            || combined.to_lowercase().contains("nothing to scan")
        {
            msg = "SenPaiScanner found no healthy endpoints for this config.".to_string();
        }
        return Ok(ScanResult {
            ok: false,
            endpoints: vec![],
            raw: combined,
            message: msg,
        });
    }

    verified.truncate(desired as usize);
    Ok(ScanResult {
        ok: true,
        endpoints: verified.clone(),
        raw: combined,
        message: format!("Found {} clean endpoint(s).", verified.len()),
    })
}

/// Smart scan_once: stop at the first verified-working endpoint.
pub async fn scan_once(vless_link: &str, params: &ScanParams) -> Result<Option<String>, CFError> {
    let mut p = params.clone();
    p.verify = true;
    let res = run_scan(vless_link, &p, 1).await?;
    if res.ok {
        Ok(res.endpoints.first().cloned())
    } else {
        Ok(None)
    }
}

/// scan_many: continue past the first only when the caller asks for n > 1.
pub async fn scan_many(
    vless_link: &str,
    params: &ScanParams,
    n: u32,
) -> Result<ScanResult, CFError> {
    let desired = n.max(1);
    run_scan(vless_link, params, desired).await
}

/// Point a vless link at a clean ip:port (drop any hostname/port).
pub fn rewrite_vless_with_endpoint(vless_link: &str, endpoint: &str) -> String {
    if !vless_link.starts_with("vless://") {
        return vless_link.to_string();
    }
    let body = &vless_link["vless://".len()..];
    let (body, frag) = match body.find('#') {
        Some(i) => (&body[..i], &body[i..]),
        None => (body, ""),
    };
    let (body, query) = match body.find('?') {
        Some(i) => (&body[..i], &body[i..]),
        None => (body, ""),
    };
    let (user, _hostport) = match body.rfind('@') {
        Some(i) => (&body[..i], &body[i + 1..]),
        None => ("", body),
    };
    let (ip, port) = match endpoint.rsplit_once(':') {
        Some((ip, port)) if port.chars().all(|c| c.is_ascii_digit()) => (ip, port),
        _ => (endpoint, "443"),
    };
    format!("vless://{user}@{ip}:{port}{query}{frag}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_validator() {
        assert!(looks_like_endpoint("1.2.3.4:443"));
        assert!(looks_like_endpoint("8.8.8.8:2053"));
        assert!(!looks_like_endpoint("host.name:443"));
        assert!(!looks_like_endpoint("999.999.999.999:443"));
        assert!(!looks_like_endpoint(""));
    }

    #[test]
    fn extract_from_text() {
        let text = "candidate 1.2.3.4:443 1.2.3.4:443 5.6.7.8:443";
        let eps = extract_endpoints(text);
        assert!(eps.contains(&"1.2.3.4:443".to_string()));
        assert!(eps.contains(&"5.6.7.8:443".to_string()));
        assert_eq!(eps.iter().filter(|e| *e == "1.2.3.4:443").count(), 1);
    }

    #[test]
    fn extract_does_not_emit_suffix_substrings() {
        // The old sliding-window tokenizer emitted the truncated suffix
        // substrings of a valid endpoint ("04.18.227.124:443",
        // "4.18.227.124:443") — the latter is a *valid-but-different* IP.
        // The maximal-run tokenizer must emit only the exact full endpoint.
        let text = "104.18.227.124:443 8.8.8.8:2053";
        let eps = extract_endpoints(text);
        assert_eq!(
            eps,
            vec!["104.18.227.124:443".to_string(), "8.8.8.8:2053".to_string()]
        );
        assert!(!eps.iter().any(|e| e.starts_with("04.")));
        assert!(!eps.iter().any(|e| e.starts_with("4.18.")));
    }

    #[test]
    fn looks_like_endpoint_rejects_leading_zero_octets() {
        // Rust's Ipv4Addr rejects leading-zero octets; we must too.
        assert!(!looks_like_endpoint("04.18.227.124:443"));
        assert!(!looks_like_endpoint("104.018.227.124:443"));
        assert!(looks_like_endpoint("104.18.227.124:443"));
        assert!(!looks_like_endpoint("104.18.227.124:0"));
        assert!(!looks_like_endpoint("104.18.227.124")); // no port
    }

    #[test]
    fn rewrite_drops_host_and_keeps_query_frag() {
        let link = "vless://user@old.workers.dev:443?security=tls&type=ws#name";
        let out = rewrite_vless_with_endpoint(link, "9.9.9.9:8443");
        assert!(out.contains("user@9.9.9.9:8443"));
        assert!(out.contains("security=tls"));
        assert!(out.contains("#name"));
        assert!(!out.contains("old.workers.dev"));
    }
}
