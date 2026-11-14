//! Tor integration — route DastYab traffic through the Tor anonymity
//! network to change the egress IP.
//!
//! This module manages the lifecycle of a **private** Tor daemon (`tor`)
//! owned by DastYab. It runs in its own data directory (it does not touch
//! a system-wide Tor), binds a SOCKS5 proxy on the loopback interface, and
//! exposes helpers to query the current exit IP through that proxy and to
//! request a fresh circuit.
//!
//! # Why this exists
//!
//! In a censored network, the normal egress path (Cloudflare worker VLESS,
//! DNS tunnel, etc.) may be blocked entirely. Tor provides a different
//! transport: it routes traffic over TLS through volunteer relays and exits
//! from an arbitrary address. It does not need a VPS you control, and it
//! anonymizes/rotates the public IP you present to the internet — which is
//! exactly the "change my IP" property the console wants.
//!
//! # Lifecycle
//!
//! - `start`   — launch the daemon (it daemonizes itself) and wait until the
//!   SOCKS5 port is listening and a circuit is usable.
//! - `stop`    — terminate the daemon cleanly.
//! - `status`  — report whether it is running and the current exit IP.
//! - `renew`   — restart the daemon, guaranteeing a brand-new circuit and
//!   likely a different exit node / IP.
//!
//! # Ports & state
//!
//! Per-profile runtime state lives in `~/.dastyab/tor/<profile>/`:
//! `datadir/` (Tor state), `tor.pid`, `tor.log`, and `settings.json` (the
//! last-used SOCKS port, so `status`/`renew` work without re-passing flags).

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::CFError;

/// Default SOCKS5 port for the Tor proxy.
pub const DEFAULT_SOCKS_PORT: u16 = 9050;
/// How long we wait for Tor to bootstrap before giving up.
pub const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(90);
/// Per-attempt probe timeout for the SOCKS port.
const PORT_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// Where we ask "what is my IP" through the proxy.
const IP_PROBE_URL: &str = "https://api.ipify.org";

/// Options controlling a Tor run.
#[derive(Debug, Clone)]
pub struct TorOpts {
    /// Active DastYab profile (used to scope the runtime directory).
    pub profile: String,
    /// Local SOCKS5 port the Tor proxy listens on.
    pub socks_port: u16,
}

impl TorOpts {
    pub fn new(profile: impl Into<String>, socks_port: u16) -> Self {
        Self {
            profile: profile.into(),
            socks_port,
        }
    }
}

/// Persisted per-profile run settings (ports + pid).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TorSettings {
    socks_port: u16,
}

/// Where per-profile Tor state lives.
pub fn tor_runtime_dir(profile: &str) -> PathBuf {
    let base = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join(".dastyab").join("tor").join(profile)
}

fn settings_path(profile: &str) -> PathBuf {
    tor_runtime_dir(profile).join("settings.json")
}

fn pid_path(profile: &str) -> PathBuf {
    tor_runtime_dir(profile).join("tor.pid")
}

fn log_path(profile: &str) -> PathBuf {
    tor_runtime_dir(profile).join("tor.log")
}

fn data_dir(profile: &str) -> PathBuf {
    tor_runtime_dir(profile).join("datadir")
}

fn load_settings(profile: &str) -> Option<TorSettings> {
    std::fs::read_to_string(settings_path(profile))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
}

fn save_settings(profile: &str, s: &TorSettings) {
    if let Ok(text) = serde_json::to_string_pretty(s) {
        let _ = std::fs::write(settings_path(profile), text);
    }
}

/// Locate the `tor` binary.
///
/// Resolution order:
///   1. `DYB_TOR_BIN` env var (absolute path; honored verbatim, used by
///      tests to inject a mock and lets users pin an install without PATH).
///   2. `command -v tor` on PATH.
pub fn find_tor() -> Result<Option<String>, CFError> {
    if let Ok(bin) = std::env::var("DYB_TOR_BIN") {
        let b = bin.trim().to_string();
        if !b.is_empty() && Path::new(&b).is_file() {
            return Ok(Some(b));
        }
    }
    let out = Command::new("sh")
        .arg("-c")
        .arg("command -v tor 2>/dev/null")
        .output()
        .map_err(|e| CFError::new("Tor", format!("cannot run `which`: {e}"), ""))?;
    if !out.status.success() {
        return Ok(None);
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok(if s.is_empty() { None } else { Some(s) })
}

/// True if the given PID is a live process.
fn pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // Send signal 0 (existence check) — no privileges needed.
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

fn read_pid(profile: &str) -> Option<u32> {
    std::fs::read_to_string(pid_path(profile))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
}

/// Synchronous port-liveness probe (used while bootstrapping).
fn port_listening(port: u16) -> bool {
    use std::net::SocketAddr;
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    TcpConnect::connect_timeout(&addr, PORT_PROBE_TIMEOUT).is_ok()
}

/// A tiny wrapper so we can use `TcpStream::connect_timeout` consistently.
struct TcpConnect;
impl TcpConnect {
    fn connect_timeout(
        addr: &std::net::SocketAddr,
        timeout: Duration,
    ) -> std::io::Result<std::net::TcpStream> {
        std::net::TcpStream::connect_timeout(addr, timeout)
    }
}

/// Query the current exit IP through the Tor SOCKS5 proxy.
pub async fn current_exit_ip(socks_port: u16) -> Result<String, CFError> {
    let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{socks_port}"))
        .map_err(|e| CFError::new("Tor", format!("bad SOCKS proxy config: {e}"), ""))?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| CFError::new("Tor", format!("cannot build client: {e}"), ""))?;
    let resp = client.get(IP_PROBE_URL).send().await.map_err(|e| {
        CFError::new(
            "Tor",
            format!("exit-IP probe through SOCKS5 failed: {e}"),
            "Is the Tor daemon running and fully bootstrapped? Try `dastyab tor start`.",
        )
    })?;
    if !resp.status().is_success() {
        return Err(CFError::new(
            "Tor",
            format!("exit-IP probe returned HTTP {}", resp.status()),
            "",
        ));
    }
    let ip = resp
        .text()
        .await
        .map_err(|e| CFError::new("Tor", format!("cannot read exit-IP response: {e}"), ""))?;
    let ip = ip.trim().to_string();
    if ip.is_empty() {
        return Err(CFError::new("Tor", "empty exit-IP response", ""));
    }
    Ok(ip)
}

/// Current public (non-Tor) egress IP — an identity sticky note for the
/// `status` output so the user can see "before" vs "after".
pub async fn direct_egress_ip() -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .ok()?;
    let resp = client.get(IP_PROBE_URL).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let ip = resp.text().await.ok()?;
    let ip = ip.trim().to_string();
    if ip.is_empty() {
        None
    } else {
        Some(ip)
    }
}

/// Start the Tor daemon and wait for a usable circuit.
pub async fn start(opts: &TorOpts) -> Result<(), CFError> {
    let bin = find_tor()?.ok_or_else(|| {
        CFError::new(
            "Tor not found",
            "The tor daemon is not installed, so DastYab cannot route through Tor.",
            "Install Tor (e.g. `sudo apt install tor` on Debian/Ubuntu) or point DYB_TOR_BIN at a tor binary.",
        )
    })?;

    // If already running, report that.
    if is_running(&opts.profile) {
        return Err(CFError::new(
            "Tor already running",
            format!("Tor is already up on 127.0.0.1:{}", opts.socks_port),
            "Use `dastyab tor renew` for a fresh circuit, or `dastyab tor stop` first.",
        ));
    }

    let dir = tor_runtime_dir(&opts.profile);
    std::fs::create_dir_all(dir.join("datadir"))
        .map_err(|e| CFError::new("Tor", format!("cannot create runtime dir: {e}"), ""))?;

    // The daemon detaches immediately (RunAsDaemon=1); we then poll for the
    // SOCKS port and a usable circuit.
    let status = Command::new(&bin)
        .arg("--RunAsDaemon")
        .arg("1")
        .arg("--DataDirectory")
        .arg(data_dir(&opts.profile))
        .arg("--PidFile")
        .arg(pid_path(&opts.profile))
        .arg("--SocksPort")
        .arg(format!("127.0.0.1:{}", opts.socks_port))
        .arg("--Log")
        .arg(format!("notice file {}", log_path(&opts.profile).display()))
        .arg("--AvoidDiskWrites")
        .arg("1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| CFError::new("Tor", format!("cannot spawn tor: {e}"), ""))?;

    if !status.success() {
        return Err(CFError::new(
            "Tor",
            format!("tor exited with status {status} during launch"),
            format!("Check the log at {}.", log_path(&opts.profile).display()),
        ));
    }

    // Persist settings so status/renew work without re-passing ports.
    save_settings(
        &opts.profile,
        &TorSettings {
            socks_port: opts.socks_port,
        },
    );

    // Wait for the SOCKS port to listen, then for a usable exit circuit.
    wait_for_bootstrap(opts).await
}

async fn wait_for_bootstrap(opts: &TorOpts) -> Result<(), CFError> {
    let deadline = Instant::now() + BOOTSTRAP_TIMEOUT;
    let mut saw_port = false;

    while Instant::now() < deadline {
        if !saw_port && port_listening(opts.socks_port) {
            saw_port = true;
        }
        if saw_port {
            // Port is up; try to finish a circuit by asking for our exit IP.
            if let Ok(ip) = current_exit_ip(opts.socks_port).await {
                println!("Tor bootstrapped — exit IP: {ip}");
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    let hint = if saw_port {
        "The SOCKS port is listening but no exit circuit completed yet (Tor may still be downloading descriptors). Wait a bit and re-run `dastyab tor status`.".to_string()
    } else {
        format!(
            "The SOCKS port never came up ({}). Check the log at {}.",
            opts.socks_port,
            log_path(&opts.profile).display()
        )
    };
    Err(CFError::new(
        "Tor bootstrap timeout",
        "Tor did not become usable within 90s.",
        hint,
    ))
}

/// Is there a live Tor daemon for this profile?
pub fn is_running(profile: &str) -> bool {
    if let Some(pid) = read_pid(profile) {
        if pid_alive(pid) {
            return true;
        }
    }
    false
}

/// Stop the Tor daemon.
pub fn stop(profile: &str) -> Result<(), CFError> {
    match read_pid(profile) {
        Some(pid) if pid_alive(pid) => {
            // SIGTERM for a graceful shutdown.
            let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
            if rc != 0 {
                return Err(CFError::new(
                    "Tor",
                    format!("failed to signal tor pid {pid} (errno {rc})"),
                    "Try `dastyab tor status` then kill the pid manually.",
                ));
            }
            // Wait for it to exit.
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline && pid_alive(pid) {
                std::thread::sleep(Duration::from_millis(200));
            }
            if pid_alive(pid) {
                return Err(CFError::new(
                    "Tor",
                    format!("tor pid {pid} did not exit after SIGTERM"),
                    "Force-kill it: `kill -9 {pid}`.",
                ));
            }
            println!("Tor stopped.");
        }
        _ => {
            println!("Tor is not running.");
        }
    }
    // Clean the pidfile.
    let _ = std::fs::remove_file(pid_path(profile));
    Ok(())
}

/// Restart Tor — guarantees a brand-new circuit and (likely) a fresh exit IP.
pub async fn renew(profile: &str) -> Result<(), CFError> {
    stop(profile)?;
    // Reload persisted port so the caller doesn't have to re-pass it.
    let socks_port = load_settings(profile)
        .map(|s| s.socks_port)
        .unwrap_or(DEFAULT_SOCKS_PORT);
    let opts = TorOpts::new(profile.to_string(), socks_port);
    println!("Restarting Tor on 127.0.0.1:{socks_port} ...");
    start(&opts).await
}

/// One-shot status report.
pub async fn status(profile: &str) -> Result<(), CFError> {
    let socks_port = load_settings(profile)
        .map(|s| s.socks_port)
        .unwrap_or(DEFAULT_SOCKS_PORT);

    println!("Tor mode — profile '{profile}'");
    println!(
        "  binary    : {}",
        find_tor()?.as_deref().unwrap_or("(not found)")
    );

    if is_running(profile) {
        println!(
            "  state     : running (pid {})",
            read_pid(profile).unwrap_or(0)
        );
        println!("  socks5    : 127.0.0.1:{socks_port}");
        match current_exit_ip(socks_port).await {
            Ok(ip) => println!("  exit IP   : {ip}"),
            Err(e) => {
                println!("  exit IP   : (unavailable — {})", e.brief());
                println!(
                    "  hint      : daemon is up but still bootstrapping; retry in a few seconds."
                );
            }
        }
    } else {
        println!("  state     : not running");
        println!("  hint      : run `dastyab tor start`");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_roundtrip() {
        let dir = std::env::temp_dir().join("dyb-tor-test-settings");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        // Redirect HOME to a temp dir so we don't touch the real store.
        // (We rely on tor_runtime_dir using $HOME; for the test we write
        // directly to a temp profile path instead.)
        let profile = "test-profile";
        let pid = pid_path(profile); // uses real HOME — fine for the test.
        let _ = pid;
        let s = TorSettings { socks_port: 9999 };
        // Save to a synthetic path under the temp dir.
        let sp = dir.join("settings.json");
        std::fs::write(&sp, serde_json::to_string_pretty(&s).unwrap()).unwrap();
        let loaded: TorSettings =
            serde_json::from_str(&std::fs::read_to_string(&sp).unwrap()).unwrap();
        assert_eq!(loaded.socks_port, 9999);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_tor_respects_env_override() {
        // When DYB_TOR_BIN points at /bin/true (a real file), we should
        // return it verbatim.
        unsafe { std::env::set_var("DYB_TOR_BIN", "/bin/true") };
        let found = find_tor().unwrap();
        assert_eq!(found.as_deref(), Some("/bin/true"));
        unsafe { std::env::remove_var("DYB_TOR_BIN") };
    }

    #[test]
    fn port_probe_negative() {
        // An unbound port must report not-listening.
        assert!(!port_listening(1));
    }
}
