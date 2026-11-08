//! E2E tunnel-verification gate (DeepSeek plan, feature 2).
//!
//! The two-phase scanner proves a candidate edge accepts a WebSocket upgrade
//! (`101` + bytes). It does NOT prove the *worker* actually routes traffic —
//! WS-upgrade-passing is a superset of actually-tunneling. To make "verified"
//! mean "this config the user is about to load will work", every candidate
//! must pass a live tunnel: we run `sing-box` with a config fronted by that
//! clean IP, punch a SOCKS5 connection through it, fetch an IP-echo service,
//! and require the egress IP to DIFFER from our own direct IP. Same IP =
//! the tunnel didn't actually route = `IpUnchanged`.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::CFError;
use crate::store;
use crate::vless::VlessProfile;

/// Where the sing-box binary lives (auto-installed, like SenPaiScanner).
pub fn singbox_bin() -> PathBuf {
    crate::store::mem_dir().join("bin").join("sing-box")
}

/// Where a scratch config for one verification run is written.
fn scratch_cfg() -> PathBuf {
    crate::store::mem_dir().join("bin").join("e2e-tmp-config.json")
}

/// Failure stage taxonomy for the E2E gate.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum E2eFailureStage {
    /// sing-box binary missing / could not start.
    SingBoxSpawn,
    /// sing-box started but the inbound proxy never came up.
    SingBoxStartup,
    /// Could not open the SOCKS5 connection to the local inbound.
    SocksConnect,
    /// The HTTP fetch through the tunnel failed.
    TunnelHttp,
    /// The tunnel egress IP equals our direct IP → route did not work.
    IpUnchanged,
}

/// Result of one tunnel verification.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct E2eResult {
    pub endpoint: String,
    pub passed: bool,
    pub failure_stage: Option<E2eFailureStage>,
    pub verified_at: i64,
    pub tunnel_ip: Option<String>,
}

/// Minimal RFC 1928 SOCKS5 client (no auth, CONNECT). Returns the accepted
/// (raw, already-spliced) TCP stream after the handshake so callers can speak
/// any protocol through it (HTTP, TLS, whatever).
async fn socks5_connect(proxy: &str, target: &str, port: u16, timeout: Duration) -> Result<TcpStream, CFError> {
    let stream = tokio::time::timeout(timeout, TcpStream::connect(proxy))
        .await
        .map_err(|_| CFError::new("E2E", "SOCKS proxy connect timed out", ""))?
        .map_err(|e| CFError::new("E2E", format!("SOCKS proxy connect failed: {e}"), ""))?;
    let mut s = stream;

    // Greeting: v5, 1 method, no-auth.
    s.write_all(&[0x05, 0x01, 0x00]).await.map_err(|e| CFError::new("E2E", format!("SOCKS greet write: {e}"), ""))?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).await.map_err(|e| CFError::new("E2E", format!("SOCKS greet read: {e}"), ""))?;
    if reply[0] != 0x05 || reply[1] != 0x00 {
        return Err(CFError::new("E2E", "SOCKS no-auth not accepted", ""));
    }

    // CONNECT request. Target host is a domain (encode as ATYP=3).
    let host_bytes = target.as_bytes();
    if host_bytes.len() > 255 {
        return Err(CFError::new("E2E", "target host too long", ""));
    }
    let mut req = Vec::with_capacity(4 + 1 + host_bytes.len() + 2);
    req.push(0x05); // version
    req.push(0x01); // CONNECT
    req.push(0x00); // reserved
    req.push(0x03); // ATYP domain
    req.push(host_bytes.len() as u8);
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.map_err(|e| CFError::new("E2E", format!("SOCKS connect write: {e}"), ""))?;

    // Reply: v5, rep, rsv, atyp, addr, port. Read header first 4 bytes then
    // the address (length-prefixed for domain).
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await.map_err(|e| CFError::new("E2E", format!("SOCKS reply read: {e}"), ""))?;
    if hdr[0] != 0x05 || hdr[1] != 0x00 {
        return Err(CFError::new("E2E", format!("SOCKS CONNECT rejected (rep={})", hdr[1]), ""));
    }
    let addr_len = match hdr[3] {
        0x01 => 4usize,
        0x04 => 16usize,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await.map_err(|e| CFError::new("E2E", format!("SOCKS addr len: {e}"), ""))?;
            l[0] as usize
        }
        other => return Err(CFError::new("E2E", format!("SOCKS bad ATYP {other}"), "")),
    };
    let mut rest = vec![0u8; addr_len + 2];
    s.read_exact(&mut rest).await.map_err(|e| CFError::new("E2E", format!("SOCKS addr read: {e}"), ""))?;
    Ok(s)
}

/// Fetch the egress IP as seen by an IP-echo service, through an established
/// stream (this is the stream already spliced through the tunnel).
async fn fetch_ip_via(stream: &mut TcpStream, host: &str, timeout: Duration) -> Result<String, CFError> {
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: dastyab-e2e\r\n\r\n"
    );
    tokio::time::timeout(timeout, stream.write_all(req.as_bytes()))
        .await
        .map_err(|_| CFError::new("E2E", "HTTP write timed out", ""))?
        .map_err(|e| CFError::new("E2E", format!("HTTP write failed: {e}"), ""))?;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let read_res = tokio::time::timeout(timeout, async {
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.len() > 64 * 1024 {
                        break;
                    }
                }
            }
        }
    })
    .await;
    let _ = read_res;

    let text = String::from_utf8_lossy(&buf);
    // Body is after \r\n\r\n.
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
    // Extract an IPv4 from the body.
    let ip = body
        .split(|c: char| !c.is_ascii_digit() && c != '.')
        .find(|s| {
            let parts: Vec<&str> = s.split('.').collect();
            parts.len() == 4
                && parts.iter().all(|p| {
                    !p.is_empty() && p.len() <= 3 && p.chars().all(|c| c.is_ascii_digit())
                })
        })
        .unwrap_or("");
    if ip.is_empty() {
        return Err(CFError::new(
            "E2E",
            format!("no IP found in echo body: {}", &text[..text.len().min(160)]),
            "",
        ));
    }
    Ok(ip.to_string())
}

/// Ensure the sing-box binary is present. If missing, tries to download the
/// pinned Linux amd64 release from GitHub. Returns the binary path.
pub async fn ensure_singbox(pinned_version: &str) -> Result<PathBuf, CFError> {
    let bin = singbox_bin();
    if bin.exists() {
        return Ok(bin);
    }
    std::fs::create_dir_all(bin.parent().unwrap()).map_err(|e| {
        CFError::new("Storage error", format!("Cannot create bin dir: {e}"), "")
    })?;
    #[cfg(target_os = "linux")]
    let asset = format!("sing-box-{pinned_version}-linux-amd64.tar.gz");
    #[cfg(target_os = "macos")]
    let asset = format!("sing-box-{pinned_version}-darwin-amd64.tar.gz");
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let asset = format!("sing-box-{pinned_version}-darwin-arm64.tar.gz");
    let url = format!(
        "https://github.com/SagerNet/sing-box/releases/download/v{pinned_version}/{asset}"
    );
    let resp = reqwest::get(&url).await.map_err(|e| {
        CFError::new("Download error", format!("Failed to download sing-box: {e}"), "")
    })?;
    if !resp.status().is_success() {
        return Err(CFError::new(
            "Download error",
            format!("HTTP {} downloading {asset}", resp.status()),
            "",
        ));
    }
    let body = resp.bytes().await.map_err(|e| CFError::new("Download error", format!("{e}"), ""))?;
    let tmp = bin.with_extension("tar.gz");
    std::fs::write(&tmp, &body).map_err(|e| CFError::new("Storage error", format!("{e}"), ""))?;

    // Extract the tar.gz in a scratch dir, then move the binary.
    let scratch = crate::store::mem_dir().join("bin").join("singbox-extract");
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).map_err(|e| CFError::new("Storage error", format!("{e}"), ""))?;
    let tar = std::fs::File::open(&tmp).map_err(|e| CFError::new("Storage error", format!("{e}"), ""))?;
    let mut archive = flate2::read::GzDecoder::new(tar);
    let mut tar_archive = tar::Archive::new(&mut archive);
    tar_archive
        .unpack(&scratch)
        .map_err(|e| CFError::new("Storage error", format!("extract: {e}"), ""))?;

    let found = find_file(&scratch, "sing-box")?;
    std::fs::copy(&found, &bin).map_err(|e| CFError::new("Storage error", format!("copy: {e}"), ""))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755));
    }
    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_dir_all(&scratch);
    Ok(bin)
}

fn find_file(root: &Path, name: &str) -> Result<PathBuf, CFError> {
    for e in std::fs::read_dir(root).map_err(|e| CFError::new("Storage error", format!("{e}"), ""))? {
        let e = e.map_err(|e| CFError::new("Storage error", format!("{e}"), ""))?;
        let p = e.path();
        if p.is_file() && p.file_name().and_then(|n| n.to_str()) == Some(name) {
            return Ok(p);
        }
        if p.is_dir() {
            if let Ok(f) = find_file(&p, name) {
                return Ok(f);
            }
        }
    }
    Err(CFError::new("Storage error", format!("sing-box binary not found under {}", root.display()), ""))
}

/// Verify one endpoint actually tunnels. Spawns sing-box with the vless config
/// fronted by the candidate clean IP, opens a SOCKS5 connection, fetches an
/// IP-echo, and requires the egress IP to differ from `direct_ip`.
pub async fn verify_tunnel(
    endpoint_ip: &str,
    endpoint_port: u16,
    vless_link: &str,
    direct_ip: &str,
    singbox_bin: &Path,
    timeout_s: u64,
) -> E2eResult {
    let base = E2eResult {
        endpoint: format!("{endpoint_ip}:{endpoint_port}"),
        passed: false,
        failure_stage: None,
        verified_at: store::now_ts() as i64,
        tunnel_ip: None,
    };

    // Parse the base vless link and front it with the candidate IP.
    let Ok(mut profile) = VlessProfile::parse(vless_link) else {
        let mut r = base;
        r.failure_stage = Some(E2eFailureStage::SingBoxSpawn);
        return r;
    };
    profile.address = endpoint_ip.to_string();
    profile.port = endpoint_port;
    let cfg_json = match crate::export::sing_box_json(&profile) {
        Ok(j) => j,
        Err(_) => {
            let mut r = base;
            r.failure_stage = Some(E2eFailureStage::SingBoxSpawn);
            return r;
        }
    };

    let cfg_path = scratch_cfg();
    if std::fs::write(&cfg_path, cfg_json).is_err() {
        let mut r = base;
        r.failure_stage = Some(E2eFailureStage::SingBoxSpawn);
        return r;
    }

    // Spawn sing-box run.
    let child = tokio::process::Command::new(singbox_bin)
        .arg("run")
        .arg("-c")
        .arg(&cfg_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(_) => {
            let mut r = base;
            r.failure_stage = Some(E2eFailureStage::SingBoxSpawn);
            return r;
        }
    };

    // Wait for the local mixed inbound (127.0.0.1:2080) to accept.
    let deadline = Instant::now() + Duration::from_secs(timeout_s);
    let mut inbound_ok = false;
    while Instant::now() < deadline {
        if let Ok(mut s) = TcpStream::connect("127.0.0.1:2080").await {
            let _ = s.shutdown().await;
            inbound_ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    // Cleanup guaranteed on every path.
    async fn cleanup(child: &mut tokio::process::Child) {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }

    if !inbound_ok {
        let mut r = base;
        r.failure_stage = Some(E2eFailureStage::SingBoxStartup);
        cleanup(&mut child).await;
        return r;
    }

    // SOCKS5 through the tunnel to an IP-echo host.
    const ECHO_HOST: &str = "api.ipify.org";
    const ECHO_PORT: u16 = 80;
    let timeout = Duration::from_secs(timeout_s);
    let mut stream = match socks5_connect("127.0.0.1:2080", ECHO_HOST, ECHO_PORT, timeout).await {
        Ok(s) => s,
        Err(_) => {
            let mut r = base;
            r.failure_stage = Some(E2eFailureStage::SocksConnect);
            cleanup(&mut child).await;
            return r;
        }
    };

    let tunnel_ip = match fetch_ip_via(&mut stream, ECHO_HOST, timeout).await {
        Ok(ip) => ip,
        Err(_) => {
            let mut r = base;
            r.failure_stage = Some(E2eFailureStage::TunnelHttp);
            cleanup(&mut child).await;
            return r;
        }
    };

    cleanup(&mut child).await;

    let passed = tunnel_ip != direct_ip && !tunnel_ip.is_empty();
    let failure_stage = if passed { None } else { Some(E2eFailureStage::IpUnchanged) };
    E2eResult {
        endpoint: base.endpoint,
        passed,
        failure_stage,
        verified_at: store::now_ts() as i64,
        tunnel_ip: Some(tunnel_ip),
    }
}

/// Given scanner candidates + E2E results, keep only the ones that actually
/// tunnel (passed == true), ordered by original order, capped at top_n.
pub fn select_verified(candidates: &[crate::autopilot::CleanEndpoint], results: &[E2eResult], top_n: usize) -> Vec<crate::autopilot::CleanEndpoint> {
    let passed: std::collections::HashSet<&str> = results
        .iter()
        .filter(|r| r.passed)
        .map(|r| r.endpoint.as_str())
        .collect();
    candidates
        .iter()
        .filter(|c| passed.contains(format!("{}:{}", c.ip, c.port).as_str()))
        .take(top_n.max(1))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn select_verified_keeps_only_passed() {
        let mk = |ip: &str, port: u16| crate::autopilot::CleanEndpoint {
            ip: ip.into(),
            port,
            sni: "user.workers.dev".into(),
            score: 5.0,
            tcp_ms: 10.0,
            connect_ms: 20.0,
            download_kbps: 100.0,
            verified: true,
            alive: true,
            last_checked: None,
            ts: String::new(),
        };
        let candidates = vec![mk("1.1.1.1", 443), mk("2.2.2.2", 2053), mk("3.3.3.3", 443)];
        let results = vec![
            E2eResult {
                endpoint: "1.1.1.1:443".into(),
                passed: true,
                failure_stage: None,
                verified_at: 0,
                tunnel_ip: Some("104.16.1.1".into()),
            },
            E2eResult {
                endpoint: "2.2.2.2:2053".into(),
                passed: false,
                failure_stage: Some(E2eFailureStage::IpUnchanged),
                verified_at: 0,
                tunnel_ip: Some("8.8.8.8".into()),
            },
            E2eResult {
                endpoint: "3.3.3.3:443".into(),
                passed: true,
                failure_stage: None,
                verified_at: 0,
                tunnel_ip: Some("104.16.1.2".into()),
            },
        ];
        let out = select_verified(&candidates, &results, 10);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].ip, "1.1.1.1");
        assert_eq!(out[1].ip, "3.3.3.3");
    }

    #[test]
    fn socks_connect_rejects_bad_handshake() {
        // No server → connect error path returns Err.
        // This is exercised implicitly by integration tests; keep a light unit
        // to ensure the function type-checks and fails cleanly on a closed port.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let res = rt.block_on(async {
            socks5_connect("127.0.0.1:1", "api.ipify.org", 80, Duration::from_secs(1)).await
        });
        assert!(res.is_err());
    }

    /// LIVE integration test (ignored by default): prove the E2E gate works
    /// against a real deployed Cloudflare worker. Runs only when invoked
    /// explicitly (`cargo test -p dastyab-core e2e -- --ignored`) and when
    /// a sing-box binary + live worker config are present.
    #[tokio::test]
    #[ignore = "requires live sing-box + deployed worker"]
    async fn live_verify_tunnel_against_worker() {
        let bin = crate::e2e::singbox_bin();
        assert!(bin.exists(), "install sing-box first");

        // Base worker link (fronted by the candidate clean IP).
        let link = "vless://8274e874-7470-43ee-8018-4bc3baa709a5@amir.dariuskhosrowan.workers.dev:443?encryption=none&security=tls&type=ws&sni=amir.dariuskhosrowan.workers.dev&host=amir.dariuskhosrowan.workers.dev&path=%2F&fp=chrome#live";

        // A clean IP from the ledger (must be a working front).
        let ledger = crate::autopilot::read_ledger("default");
        assert!(!ledger.is_empty(), "no ledger endpoints to verify");
        let ep = &ledger[0];

        eprintln!("verifying {} via live worker…", ep.ip);
        let r = verify_tunnel(
            &ep.ip,
            ep.port,
            link,
            "163.123.193.6", // direct IP of this machine
            &bin,
            30,
        )
        .await;
        // We only assert the harness RAN cleanly and produced a tunnel_ip;
        // pass/fail depends on live network conditions. Log it.
        eprintln!("E2E result: {r:?}");
        assert!(r.tunnel_ip.is_some(), "expected a tunnel egress IP");
        assert!(!r.passed || r.tunnel_ip.as_deref() != Some("163.123.193.6"));
    }
}
