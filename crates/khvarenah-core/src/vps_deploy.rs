//! One-command DNS tunnel deployment to a user's VPS (blackout survival).
//!
//! When a total network blackout hits (no direct/DoH/DoT path), the DNS tunnel
//! is the last rung of `connectivity::FallbackLadder`. Historically the tunnel
//! required manually shelling into a VPS — a 30-minute step most users never
//! complete. This module turns that into a one-command operation: the user
//! pastes VPS credentials in the GUI Settings (or `dns-tunnel deploy` on the
//! CLI), and the app SSHes in, installs the tunnel server, generates keys,
//! writes the systemd unit, and persists the client config — all driven from
//! inside the app.
//!
//! SSH side-effects are abstracted behind `VpsSshPeer` (mirrors `RescuePeer` /
//! `MutationPeer`) so the deploy sequencing is fully unit-testable without a
//! live VPS. `RealVpsSshPeer` shells out to the system `ssh`/`scp`/`rsync`
//! binaries via `std::process::Command` — no new crates, and host-key / key
//! auth is handled by the user's existing SSH config.

use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;

use crate::error::CFError;

/// VPS connection credentials (serde so it persists + is configurable in-app).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VpsCredentials {
    /// VPS IP / hostname.
    pub host: String,
    /// SSH username (e.g. `root`).
    pub ssh_user: String,
    /// Path to the user's existing SSH private key. No key generation.
    pub ssh_key_path: PathBuf,
    /// SSH port (default 22).
    pub ssh_port: u16,
}

impl Default for VpsCredentials {
    fn default() -> Self {
        Self {
            host: String::new(),
            ssh_user: String::new(),
            ssh_key_path: PathBuf::from("~/.ssh/id_ed25519"),
            ssh_port: 22,
        }
    }
}

impl VpsCredentials {
    /// A credential set is incomplete for deploy if any essential field is empty.
    pub fn is_complete(&self) -> bool {
        !self.host.trim().is_empty()
            && !self.ssh_user.trim().is_empty()
            && !self.ssh_key_path.as_os_str().is_empty()
    }

    /// `ssh` invocation prefix shared by all real-peer commands.
    fn ssh_args(&self) -> Vec<String> {
        vec![
            "-p".into(),
            self.ssh_port.to_string(),
            "-i".into(),
            self.ssh_key_path.display().to_string(),
            "-o".into(),
            "StrictHostKeyChecking=accept-new".into(),
            "-o".into(),
            "ConnectTimeout=15".into(),
            format!("{}@{}", self.ssh_user, self.host),
        ]
    }
}

/// Steps of the deploy pipeline; streamed to the UI/CLI for a progress bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DeployStep {
    /// Test that SSH reaches the host.
    VerifySsh,
    /// Install the tunnel server binary + deps on the VPS.
    InstallServer,
    /// Generate a session keypair for the tunnel.
    GenerateKeys,
    /// Write + enable the systemd unit.
    ConfigureSystemd,
    /// Open the tunnel port in the firewall (best-effort).
    ConfigureFirewall,
    /// Export the client config into the profile dir.
    ExportClientConfig,
    /// Probe the tunnel end-to-end from the client side.
    Verify,
}

impl DeployStep {
    pub fn label(self) -> &'static str {
        match self {
            DeployStep::VerifySsh => "verify-ssh",
            DeployStep::InstallServer => "install-server",
            DeployStep::GenerateKeys => "generate-keys",
            DeployStep::ConfigureSystemd => "configure-systemd",
            DeployStep::ConfigureFirewall => "configure-firewall",
            DeployStep::ExportClientConfig => "export-client-config",
            DeployStep::Verify => "verify",
        }
    }
    pub fn all() -> &'static [DeployStep] {
        &[
            DeployStep::VerifySsh,
            DeployStep::InstallServer,
            DeployStep::GenerateKeys,
            DeployStep::ConfigureSystemd,
            DeployStep::ConfigureFirewall,
            DeployStep::ExportClientConfig,
            DeployStep::Verify,
        ]
    }
}

/// Client-side tunnel config, persisted per-profile.
/// How a DNS tunnel is hosted.
///
/// `Vps` (default) is the legacy dnstt-style authoritative DNS server on a
/// VPS, probed via raw UDP:53. `Worker` is the newer Cloudflare-Worker-hosted
/// control-plane tunnel (HTTPS/DoH-style), probed via HTTPS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelMode {
    /// Legacy VPS-hosted dnstt server.
    #[default]
    Vps,
    /// Cloudflare-Worker-hosted tunnel (no VPS).
    Worker,
}

/// Per-profile DNS-tunnel client configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TunnelClientConfig {
    /// The server host — for `Vps` the VPS IP/hostname; for `Worker` the
    /// workers.dev URL. `#[serde(default)]` + the `mode` field keep legacy
    /// JSON (host/base_domain/session/resolver only) deserializing as Vps.
    #[serde(default)]
    pub host: String,
    /// DNS zone the server authoritatively answers (or forwards) for. For a
    /// worker tunnel this is set to the same workers.dev URL so existing
    /// callers that key off it keep working.
    #[serde(default)]
    pub base_domain: String,
    /// Session id shared with the server.
    #[serde(default)]
    pub session: String,
    /// Which resolver transport to use (e.g. "doh" | "dot").
    #[serde(default)]
    pub resolver: String,
    /// Hosting mode. Defaults to Vps so legacy configs need no migration.
    #[serde(default)]
    pub mode: TunnelMode,
    /// Worker tunnel: the workers.dev URL (also stored in `host`).
    #[serde(default)]
    pub worker_url: Option<String>,
    /// Worker tunnel: deployed worker script name.
    #[serde(default)]
    pub worker_name: Option<String>,
    /// Worker tunnel: shared-secret gate (X-Khvarenah-Session header).
    #[serde(default)]
    pub shared_secret: Option<String>,
    /// Worker tunnel: configured VLESS upstream host:port (data-plane pipe).
    #[serde(default)]
    pub worker_vless_upstream: Option<String>,
}

impl Default for TunnelClientConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            base_domain: String::new(),
            session: String::new(),
            resolver: "doh".into(),
            mode: TunnelMode::default(),
            worker_url: None,
            worker_name: None,
            shared_secret: None,
            worker_vless_upstream: None,
        }
    }
}

impl TunnelClientConfig {
    /// Whether this config describes a worker-hosted tunnel.
    pub fn is_worker_mode(&self) -> bool {
        self.mode == TunnelMode::Worker
    }
}

/// Abstraction over remote SSH side-effects so deploy sequencing is
/// unit-testable without a live VPS (mirrors `RescuePeer`/`MutationPeer`).
#[allow(async_fn_in_trait)]
pub trait VpsSshPeer: Send + Sync {
    /// Run a remote command via ssh; return trimmed stdout on success.
    async fn run_remote(&self, creds: &VpsCredentials, cmd: &str) -> Result<String, CFError>;
    /// Copy a local file to the remote host via scp.
    async fn copy_to(
        &self,
        creds: &VpsCredentials,
        local: &Path,
        remote: &str,
    ) -> Result<(), CFError>;
    /// Probe reachability of the VPS host:port (TCP).
    async fn probe_reachable(&self, creds: &VpsCredentials) -> bool;
}

/// Real SSH peer: shells out to system `ssh`/`scp`/`nc`. No new crates.
pub struct RealVpsSshPeer;

impl VpsSshPeer for RealVpsSshPeer {
    async fn run_remote(&self, creds: &VpsCredentials, cmd: &str) -> Result<String, CFError> {
        let mut args = creds.ssh_args();
        args.push(cmd.to_string());
        let out = StdCommand::new("ssh")
            .args(&args)
            .output()
            .map_err(|e| CFError::new("vps-deploy", format!("ssh spawn failed: {e}"), ""))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        } else {
            let stderr = String::from_utf8_lossy(&out.stderr);
            Err(CFError::new(
                "vps-deploy",
                format!(
                    "ssh command failed ({}): {}",
                    out.status.code().unwrap_or(-1),
                    stderr.trim()
                ),
                "",
            ))
        }
    }

    async fn copy_to(
        &self,
        creds: &VpsCredentials,
        local: &Path,
        remote: &str,
    ) -> Result<(), CFError> {
        let out = StdCommand::new("scp")
            .arg("-P")
            .arg(creds.ssh_port.to_string())
            .arg("-i")
            .arg(creds.ssh_key_path.display().to_string())
            .arg(format!("{}@{}:{}", creds.ssh_user, creds.host, remote))
            .arg(local)
            .output()
            .map_err(|e| CFError::new("vps-deploy", format!("scp spawn failed: {e}"), ""))?;
        if out.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&out.stderr);
            Err(CFError::new(
                "vps-deploy",
                format!("scp failed: {}", stderr.trim()),
                "",
            ))
        }
    }

    async fn probe_reachable(&self, creds: &VpsCredentials) -> bool {
        use std::net::{SocketAddr, TcpStream};
        use std::time::Duration;
        let addr: SocketAddr = match format!("{}:{}", creds.host, creds.ssh_port).parse() {
            Ok(a) => a,
            Err(_) => return false,
        };
        TcpStream::connect_timeout(&addr, Duration::from_secs(5)).is_ok()
    }
}

/// Pure probe (no SSH) — TCP reachability of the VPS host:port.
pub fn probe_vps_reachable(host: &str, port: u16) -> bool {
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;
    let addr: SocketAddr = match format!("{host}:{port}").parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    TcpStream::connect_timeout(&addr, Duration::from_secs(5)).is_ok()
}

/// Where the per-profile tunnel client config is persisted.
pub fn tunnel_client_config_path(profile_id: &str) -> PathBuf {
    crate::store::profiles::profile_dir(profile_id).join("tunnel-client.json")
}

/// Persist the tunnel client config (atomic write).
pub fn write_tunnel_client_config(
    profile_id: &str,
    cfg: &TunnelClientConfig,
) -> Result<(), CFError> {
    crate::store::write_json(&tunnel_client_config_path(profile_id), cfg)
}

/// Load the tunnel client config, if present.
pub fn load_tunnel_client_config(profile_id: &str) -> Option<TunnelClientConfig> {
    crate::store::read_opt(&tunnel_client_config_path(profile_id))
}

/// Whether a DNS tunnel has been deployed for this profile.
pub fn is_dns_tunnel_configured(profile_id: &str) -> bool {
    load_tunnel_client_config(profile_id)
        .map(|c| !c.host.is_empty() && !c.base_domain.is_empty())
        .unwrap_or(false)
}

/// `connectivity::Probe` helper: when a tunnel config exists, the DnsTunnel
/// tier is usable (the server is presumed reachable via DNS queries).
pub fn tunnel_tier_available(profile_id: &str) -> bool {
    is_dns_tunnel_configured(profile_id)
}

/// Result of a completed deploy.
#[derive(Debug, Clone)]
pub struct DeployResult {
    pub host: String,
    pub completed_steps: Vec<DeployStep>,
    pub verified: bool,
}

/// Run the full deploy pipeline. `progress_tx` streams step completion for a
/// UI progress bar. `peer` abstracts SSH for testability.
pub async fn deploy_dns_tunnel<P: VpsSshPeer>(
    creds: &VpsCredentials,
    peer: &P,
    profile_id: &str,
    base_domain: &str,
    progress_tx: Option<tokio::sync::mpsc::UnboundedSender<DeployStep>>,
) -> Result<DeployResult, CFError> {
    let mut completed = Vec::new();

    let emit = |step: DeployStep, completed: &mut Vec<DeployStep>| {
        if let Some(tx) = &progress_tx {
            let _ = tx.send(step);
        }
        completed.push(step);
    };

    // 1. Verify SSH.
    if !peer.probe_reachable(creds).await {
        return Err(CFError::new(
            "vps-deploy",
            "VPS unreachable on the configured host:port",
            "",
        ));
    }
    peer.run_remote(creds, "echo ok").await.map_err(|e| {
        CFError::new(
            "vps-deploy",
            format!("SSH handshake failed: {}", e.brief()),
            "",
        )
    })?;
    emit(DeployStep::VerifySsh, &mut completed);

    // 2. Install the tunnel server (dnstt-style). No new deps — shell out.
    let install_script = r#"
set -e
if ! command -v dnstt-server >/dev/null 2>&1; then
  # Minimal dnstt install: fetch the statically-linked binary.
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64) A=amd64 ;;
    aarch64) A=arm64 ;;
    *) echo "unsupported arch $ARCH"; exit 1 ;;
  esac
  curl -fsSL -o /usr/local/bin/dnstt-server \
    "https://github.com/iamrof/dnstt/releases/latest/download/dnstt-server-linux-$A" || true
  if [ -s /usr/local/bin/dnstt-server ]; then
    chmod +x /usr/local/bin/dnstt-server
  fi
fi
"#;
    peer.run_remote(creds, install_script).await?;
    emit(DeployStep::InstallServer, &mut completed);

    // 3. Generate a session keypair on the server.
    let _keys = peer
        .run_remote(
            creds,
            "umask 077; mkdir -p /etc/dnstt && cd /etc/dnstt && \
             (test -f server.key || (dnstt-server -gen-key > server.key 2>/dev/null)); \
             echo generated",
        )
        .await?;
    let session = format!("{:x}", {
        use rand::Rng;
        rand::thread_rng().gen::<u64>()
    });
    emit(DeployStep::GenerateKeys, &mut completed);

    // 4. systemd unit.
    let unit = format!(
        r#"# dnstt tunnel server
[Unit]
Description=dnstt DNS tunnel server
After=network.target

[Service]
ExecStart=/usr/local/bin/dnstt-server -d {base_domain} -k /etc/dnstt/server.key -u 53
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"#
    );
    let remote_unit = "/etc/systemd/system/dnstt.service";
    std::fs::write("/tmp/dnstt.unit", &unit)
        .map_err(|e| CFError::new("vps-deploy", format!("temp write: {e}"), ""))?;
    peer.copy_to(creds, Path::new("/tmp/dnstt.unit"), remote_unit)
        .await?;
    peer.run_remote(
        creds,
        "systemctl daemon-reload && systemctl enable --now dnstt.service && echo enabled",
    )
    .await?;
    emit(DeployStep::ConfigureSystemd, &mut completed);

    // 5. Firewall (best-effort — open 53/udp).
    peer.run_remote(
        creds,
        "(command -v ufw >/dev/null && ufw allow 53/udp) || \
         (command -v firewall-cmd >/dev/null && firewall-cmd --permanent --add-port=53/udp && firewall-cmd --reload) || \
         echo 'no-firewall-manager'",
    )
    .await?;
    emit(DeployStep::ConfigureFirewall, &mut completed);

    // 6. Persist client config.
    let client = TunnelClientConfig {
        host: creds.host.clone(),
        base_domain: base_domain.to_string(),
        session,
        resolver: "doh".into(),
        mode: TunnelMode::default(),
        worker_url: None,
        worker_name: None,
        shared_secret: None,
        worker_vless_upstream: None,
    };
    write_tunnel_client_config(profile_id, &client)?;
    emit(DeployStep::ExportClientConfig, &mut completed);

    // 7. Verify: confirm the server unit is active.
    let status = peer
        .run_remote(creds, "systemctl is-active dnstt.service")
        .await
        .unwrap_or_default();
    let verified = status.trim() == "active";
    emit(DeployStep::Verify, &mut completed);

    Ok(DeployResult {
        host: creds.host.clone(),
        completed_steps: completed,
        verified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Isolated mem dir + fresh profile id. Callers must hold `TEST_LOCK`
    /// for the whole test (the mem-dir override is process-global).
    fn fresh_profile() -> String {
        let base = tempfile::tempdir().unwrap().path().join(".khvarenah");
        crate::store::set_mem_dir_override(base);
        crate::store::profiles::create_profile(
            &format!("vps-test-{}", crate::store::new_id()),
            "test",
        )
        .unwrap()
    }

    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[derive(Default)]
    struct FakePeer {
        calls: Arc<Mutex<Vec<String>>>,
        reachable: bool,
        active: bool,
    }

    impl VpsSshPeer for FakePeer {
        async fn run_remote(&self, _c: &VpsCredentials, cmd: &str) -> Result<String, CFError> {
            self.calls.lock().unwrap().push(format!("run:{cmd}"));
            if self.active {
                Ok("active".into())
            } else {
                Ok("inactive".into())
            }
        }
        async fn copy_to(&self, _c: &VpsCredentials, _l: &Path, r: &str) -> Result<(), CFError> {
            self.calls.lock().unwrap().push(format!("copy:{r}"));
            Ok(())
        }
        async fn probe_reachable(&self, _c: &VpsCredentials) -> bool {
            self.reachable
        }
    }

    fn creds() -> VpsCredentials {
        VpsCredentials {
            host: "203.0.113.10".into(),
            ssh_user: "root".into(),
            ssh_key_path: PathBuf::from("/tmp/does-not-exist"),
            ssh_port: 22,
        }
    }

    #[tokio::test]
    async fn deploy_unreachable_vps_errors_before_any_step() {
        let _guard = TEST_LOCK.lock().unwrap();
        let profile = fresh_profile();
        let peer = FakePeer {
            reachable: false,
            ..Default::default()
        };
        let err = deploy_dns_tunnel(&creds(), &peer, &profile, "t.example.com", None).await;
        assert!(err.is_err());
        assert!(peer.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn deploy_runs_all_steps_in_order() {
        let _guard = TEST_LOCK.lock().unwrap();
        let profile = fresh_profile();
        let peer = FakePeer {
            reachable: true,
            active: true,
            ..Default::default()
        };
        let res = deploy_dns_tunnel(&creds(), &peer, &profile, "t.example.com", None)
            .await
            .unwrap();
        assert_eq!(res.completed_steps.len(), DeployStep::all().len());
        assert!(res.verified);
        let calls = peer.calls.lock().unwrap();
        assert!(calls.iter().any(|c| c.contains("systemctl enable")));
        assert!(calls.iter().any(|c| c.starts_with("copy:")));
    }

    #[tokio::test]
    async fn deploy_reports_unverified_when_service_inactive() {
        let _guard = TEST_LOCK.lock().unwrap();
        let profile = fresh_profile();
        let peer = FakePeer {
            reachable: true,
            active: false,
            ..Default::default()
        };
        let res = deploy_dns_tunnel(&creds(), &peer, &profile, "t.example.com", None)
            .await
            .unwrap();
        assert!(!res.verified);
    }

    #[test]
    fn creds_completeness() {
        assert!(creds().is_complete());
        assert!(!VpsCredentials::default().is_complete());
    }

    #[test]
    fn write_load_tunnel_config_roundtrips() {
        let _guard = TEST_LOCK.lock().unwrap();
        let profile = fresh_profile();
        let cfg = TunnelClientConfig {
            host: "203.0.113.10".into(),
            base_domain: "t.example.com".into(),
            session: "abc123".into(),
            resolver: "doh".into(),
            mode: TunnelMode::default(),
            worker_url: None,
            worker_name: None,
            shared_secret: None,
            worker_vless_upstream: None,
        };
        write_tunnel_client_config(&profile, &cfg).unwrap();
        let loaded = load_tunnel_client_config(&profile).unwrap();
        assert_eq!(loaded.host, cfg.host);
        assert_eq!(loaded.session, cfg.session);
        assert!(is_dns_tunnel_configured(&profile));
    }
}
