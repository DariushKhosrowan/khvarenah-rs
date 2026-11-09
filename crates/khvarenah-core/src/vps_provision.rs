//! Zero-touch VPS provisioning (Hetzner Cloud-first) for blackout survival.
//!
//! `vps_deploy` turns *SSHing into an existing VPS* into a one-command in-app
//! operation. The remaining manual step is owning a VPS at all: the user must
//! order one, note its IP, and hand over SSH credentials. This module removes
//! that step — the user pastes a Hetzner Cloud API token in the GUI Settings
//! (or `dns-tunnel provision` on the CLI), and the app provisions a fresh VPS
//! via the Hetzner Cloud API, waits for it to boot, installs the user's SSH
//! public key, and then hands the resulting `VpsCredentials` straight into
//! `vps_deploy::deploy_dns_tunnel`. The whole chain runs from inside the app.
//!
//! Network side-effects are abstracted behind the `HetznerApi` trait (mirrors
//! `VpsSshPeer` / `RescuePeer`), so the provisioning sequencing is fully
//! unit-testable with a fake API. `RealHetznerApi` talks to
//! `https://api.hetzner.cloud/v1` via `reqwest` — no new crates.

use std::path::PathBuf;

use crate::error::CFError;

/// Hetzner Cloud API base URL.
const HETZNER_API_BASE: &str = "https://api.hetzner.cloud/v1";

/// Hetzner Cloud API token (serde so it persists + is configurable in-app).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HetznerCredentials {
    /// Hetzner Cloud API token (read/write).
    pub api_token: String,
    /// Hetzner datacenter/location (e.g. `nbg1` or `fsn1`).
    pub location: String,
    /// Server type (e.g. `cx22` — 2 vCPU / 4GB, cheapest cloud line).
    pub server_type: String,
    /// VPS hostname/label.
    pub server_name: String,
}

impl Default for HetznerCredentials {
    fn default() -> Self {
        Self {
            api_token: String::new(),
            location: "nbg1".into(),
            server_type: "cx22".into(),
            server_name: "khvarenah-tunnel".into(),
        }
    }
}

impl HetznerCredentials {
    pub fn is_complete(&self) -> bool {
        !self.api_token.trim().is_empty()
    }
}

/// The SSH identity the provisioned VPS will accept. We generate (or reuse) a
/// keypair locally and inject the *public* half into the server; the private
/// half becomes the `VpsCredentials.ssh_key_path` used by the deploy step.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SshIdentity {
    pub private_key_path: PathBuf,
    pub public_key: String,
}

/// Steps of the provisioning pipeline; streamed for a progress bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ProvisionStep {
    /// Validate the API token against /servers.
    VerifyToken,
    /// Generate (or reuse) a local SSH keypair.
    PrepareSshKey,
    /// Upload the public key to Hetzner.
    UploadSshKey,
    /// Create the VPS server.
    CreateServer,
    /// Wait for the server to reach `running` and assign an IPv4.
    WaitReady,
}

impl ProvisionStep {
    pub fn label(self) -> &'static str {
        match self {
            ProvisionStep::VerifyToken => "verify-token",
            ProvisionStep::PrepareSshKey => "prepare-ssh-key",
            ProvisionStep::UploadSshKey => "upload-ssh-key",
            ProvisionStep::CreateServer => "create-server",
            ProvisionStep::WaitReady => "wait-ready",
        }
    }
    pub fn all() -> &'static [ProvisionStep] {
        &[
            ProvisionStep::VerifyToken,
            ProvisionStep::PrepareSshKey,
            ProvisionStep::UploadSshKey,
            ProvisionStep::CreateServer,
            ProvisionStep::WaitReady,
        ]
    }
}

/// Result of a completed provisioning run.
#[derive(Debug, Clone)]
pub struct ProvisionResult {
    pub host: String,
    pub completed_steps: Vec<ProvisionStep>,
    /// The SSH identity the deploy step should use.
    pub identity: SshIdentity,
}

/// Abstraction over Hetzner Cloud API side-effects so provisioning sequencing is
/// unit-testable without real tokens/servers (mirrors `VpsSshPeer`).
#[allow(async_fn_in_trait)]
pub trait HetznerApi: Send + Sync {
    /// Validate the API token (GET /servers). Ok when the token is valid.
    async fn verify_token(&self, creds: &HetznerCredentials) -> Result<(), CFError>;
    /// Upload an SSH public key; returns the Hetzner key id.
    async fn upload_ssh_key(
        &self,
        creds: &HetznerCredentials,
        name: &str,
        public_key: &str,
    ) -> Result<i64, CFError>;
    /// Create a server; returns its id.
    async fn create_server(
        &self,
        creds: &HetznerCredentials,
        ssh_key_id: i64,
        public_key: &str,
    ) -> Result<i64, CFError>;
    /// Poll the server until `running`; returns its IPv4 address.
    async fn wait_until_running(
        &self,
        creds: &HetznerCredentials,
        server_id: i64,
        max_attempts: u32,
    ) -> Result<String, CFError>;
}

/// Real Hetzner Cloud API client (reqwest, bearer auth, no new crates).
pub struct RealHetznerApi;

impl HetznerApi for RealHetznerApi {
    async fn verify_token(&self, creds: &HetznerCredentials) -> Result<(), CFError> {
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{HETZNER_API_BASE}/servers"))
            .bearer_auth(&creds.api_token)
            .send()
            .await
            .map_err(|e| {
                CFError::new("hetzner", format!("verify token request failed: {e}"), "")
            })?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(CFError::new(
                "hetzner",
                format!("invalid API token (HTTP {})", resp.status().as_u16()),
                "Paste a read/write Hetzner Cloud API token from console.hetzner.cloud → API Tokens.",
            ))
        }
    }

    async fn upload_ssh_key(
        &self,
        creds: &HetznerCredentials,
        name: &str,
        public_key: &str,
    ) -> Result<i64, CFError> {
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{HETZNER_API_BASE}/ssh_keys"))
            .bearer_auth(&creds.api_token)
            .json(&serde_json::json!({ "name": name, "public_key": public_key }))
            .send()
            .await
            .map_err(|e| CFError::new("hetzner", format!("upload ssh key failed: {e}"), ""))?;
        if !resp.status().is_success() {
            return Err(CFError::new(
                "hetzner",
                format!("upload ssh key failed (HTTP {})", resp.status().as_u16()),
                "Check the token has write permission.",
            ));
        }
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| CFError::new("hetzner", format!("bad ssh-key response: {e}"), ""))?;
        body["ssh_key"]["id"]
            .as_i64()
            .ok_or_else(|| CFError::new("hetzner", "missing ssh_key.id in response", ""))
    }

    async fn create_server(
        &self,
        creds: &HetznerCredentials,
        ssh_key_id: i64,
        public_key: &str,
    ) -> Result<i64, CFError> {
        let client = reqwest::Client::new();
        // cloud-init user_data: create a non-root `khvarenah` user and install
        // the SSH public key. Uses an inline heredoc-style script.
        let user_data = format!(
            "#!/bin/bash\n\
             set -e\n\
             id -u khvarenah >/dev/null 2>&1 || useradd -m -s /bin/bash khvarenah\n\
             mkdir -p /home/khvarenah/.ssh\n\
             echo '{}' > /home/khvarenah/.ssh/authorized_keys\n\
             chown -R khvarenah:khvarenah /home/khvarenah/.ssh\n\
             chmod 700 /home/khvarenah/.ssh\n\
             chmod 600 /home/khvarenah/.ssh/authorized_keys\n",
            public_key.trim()
        );
        let resp = client
            .post(format!("{HETZNER_API_BASE}/servers"))
            .bearer_auth(&creds.api_token)
            .json(&serde_json::json!({
                "name": creds.server_name,
                "server_type": creds.server_type,
                "location": creds.location,
                "ssh_keys": [ssh_key_id],
                "user_data": user_data,
            }))
            .send()
            .await
            .map_err(|e| CFError::new("hetzner", format!("create server failed: {e}"), ""))?;
        if !resp.status().is_success() {
            return Err(CFError::new(
                "hetzner",
                format!("create server failed (HTTP {})", resp.status().as_u16()),
                "Check the token has write permission and the server_type/location are valid.",
            ));
        }
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| CFError::new("hetzner", format!("bad create response: {e}"), ""))?;
        body["server"]["id"]
            .as_i64()
            .ok_or_else(|| CFError::new("hetzner", "missing server.id in response", ""))
    }

    async fn wait_until_running(
        &self,
        creds: &HetznerCredentials,
        server_id: i64,
        max_attempts: u32,
    ) -> Result<String, CFError> {
        let client = reqwest::Client::new();
        for _ in 0..max_attempts {
            let resp = client
                .get(format!("{HETZNER_API_BASE}/servers/{server_id}"))
                .bearer_auth(&creds.api_token)
                .send()
                .await
                .map_err(|e| CFError::new("hetzner", format!("get server failed: {e}"), ""))?;
            if resp.status().is_success() {
                let body: serde_json::Value = resp.json().await.map_err(|e| {
                    CFError::new("hetzner", format!("bad server response: {e}"), "")
                })?;
                let status = body["server"]["status"].as_str().unwrap_or("");
                if status == "running" {
                    let ip = body["server"]["public_net"]["ipv4"]["ip"]
                        .as_str()
                        .ok_or_else(|| CFError::new("hetzner", "missing ipv4 ip", ""))?
                        .to_string();
                    return Ok(ip);
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
        Err(CFError::new(
            "hetzner",
            "server did not reach running in time",
            "Wait a moment and check the server in the Hetzner console.",
        ))
    }
}

/// Generate a fresh Ed25519 SSH keypair on disk (if the identity lacks one)
/// and return the `SshIdentity` (private path + public key string).
///
/// Shells out to system `ssh-keygen` (no new RSA/ssh crate). Returns the
/// existing identity if `private_key_path` already exists.
pub fn ensure_ssh_identity(private_key_path: &std::path::Path) -> Result<SshIdentity, CFError> {
    if private_key_path.exists() {
        let pub_path = format!("{}.pub", private_key_path.display());
        if std::path::Path::new(&pub_path).exists() {
            let public_key = std::fs::read_to_string(&pub_path)
                .map_err(|e| CFError::new("hetzner", format!("read pubkey failed: {e}"), ""))?
                .trim()
                .to_string();
            return Ok(SshIdentity {
                private_key_path: private_key_path.to_path_buf(),
                public_key,
            });
        }
    }
    if let Some(parent) = private_key_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| CFError::new("hetzner", format!("mkdir failed: {e}"), ""))?;
    }
    let out = std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-C", "khvarenah-provision", "-f"])
        .arg(private_key_path)
        .output()
        .map_err(|e| {
            CFError::new(
                "hetzner",
                format!("ssh-keygen spawn failed: {e}"),
                "Install openssh-client.",
            )
        })?;
    if !out.status.success() {
        return Err(CFError::new(
            "hetzner",
            "ssh-keygen failed to create the keypair",
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    let public_key = std::fs::read_to_string(format!("{}.pub", private_key_path.display()))
        .map_err(|e| CFError::new("hetzner", format!("read pubkey failed: {e}"), ""))?
        .trim()
        .to_string();
    Ok(SshIdentity {
        private_key_path: private_key_path.to_path_buf(),
        public_key,
    })
}

/// Pure orchestrator: provision a fresh Hetzner VPS and return the credentials
/// the tunnel-deploy step needs. Does NOT deploy the tunnel — call
/// `vps_deploy::deploy_dns_tunnel` with the returned `VpsCredentials`.
pub async fn provision_vps<A: HetznerApi>(
    api: &A,
    creds: &HetznerCredentials,
    private_key_path: &std::path::Path,
    progress_tx: Option<tokio::sync::mpsc::UnboundedSender<ProvisionStep>>,
) -> Result<ProvisionResult, CFError> {
    let mut completed = Vec::new();
    let emit = |step: ProvisionStep, completed: &mut Vec<ProvisionStep>| {
        if let Some(tx) = &progress_tx {
            let _ = tx.send(step);
        }
        completed.push(step);
    };

    emit(ProvisionStep::VerifyToken, &mut completed);
    api.verify_token(creds).await?;

    emit(ProvisionStep::PrepareSshKey, &mut completed);
    let identity = ensure_ssh_identity(private_key_path)?;

    emit(ProvisionStep::UploadSshKey, &mut completed);
    let key_name = format!("khvarenah-{}", std::process::id());
    let ssh_key_id = api
        .upload_ssh_key(creds, &key_name, &identity.public_key)
        .await?;

    emit(ProvisionStep::CreateServer, &mut completed);
    let server_id = api
        .create_server(creds, ssh_key_id, &identity.public_key)
        .await?;

    emit(ProvisionStep::WaitReady, &mut completed);
    let host = api.wait_until_running(creds, server_id, 60).await?;

    Ok(ProvisionResult {
        host,
        completed_steps: completed,
        identity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fake Hetzner API that records calls and returns scripted results.
    struct FakeHetznerApi {
        server_ip: String,
        fail_verify: bool,
        fail_create: bool,
        never_running: bool,
    }

    impl HetznerApi for FakeHetznerApi {
        async fn verify_token(&self, _: &HetznerCredentials) -> Result<(), CFError> {
            if self.fail_verify {
                Err(CFError::new("hetzner", "bad token", ""))
            } else {
                Ok(())
            }
        }
        async fn upload_ssh_key(
            &self,
            _: &HetznerCredentials,
            _: &str,
            _: &str,
        ) -> Result<i64, CFError> {
            Ok(42)
        }
        async fn create_server(
            &self,
            _: &HetznerCredentials,
            _: i64,
            _: &str,
        ) -> Result<i64, CFError> {
            if self.fail_create {
                Err(CFError::new("hetzner", "create failed", ""))
            } else {
                Ok(7)
            }
        }
        async fn wait_until_running(
            &self,
            _: &HetznerCredentials,
            _: i64,
            _: u32,
        ) -> Result<String, CFError> {
            if self.never_running {
                Err(CFError::new("hetzner", "timeout", ""))
            } else {
                Ok(self.server_ip.clone())
            }
        }
    }

    fn test_creds() -> HetznerCredentials {
        HetznerCredentials {
            api_token: "tok".into(),
            ..Default::default()
        }
    }

    #[test]
    fn test_ensure_ssh_identity_generates_keypair() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("id_ed25519");
        let id = ensure_ssh_identity(&key).unwrap();
        assert!(key.exists());
        assert!(id.public_key.starts_with("ssh-ed25519 "));
        // second call reuses existing
        let id2 = ensure_ssh_identity(&key).unwrap();
        assert!(id2.public_key.starts_with("ssh-ed25519 "));
    }

    #[tokio::test]
    async fn test_provision_runs_all_steps_and_returns_host() {
        let api = FakeHetznerApi {
            server_ip: "1.2.3.4".into(),
            fail_verify: false,
            fail_create: false,
            never_running: false,
        };
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("id_ed25519");
        let res = provision_vps(&api, &test_creds(), &key, None)
            .await
            .unwrap();
        assert_eq!(res.host, "1.2.3.4");
        assert_eq!(res.completed_steps, ProvisionStep::all());
        assert!(key.exists());
    }

    #[tokio::test]
    async fn test_provision_aborts_on_invalid_token() {
        let api = FakeHetznerApi {
            server_ip: String::new(),
            fail_verify: true,
            fail_create: false,
            never_running: false,
        };
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("id_ed25519");
        let err = provision_vps(&api, &test_creds(), &key, None)
            .await
            .unwrap_err();
        assert!(err.brief().to_lowercase().contains("bad token"));
    }

    #[tokio::test]
    async fn test_provision_propagates_create_failure() {
        let api = FakeHetznerApi {
            server_ip: String::new(),
            fail_verify: false,
            fail_create: true,
            never_running: false,
        };
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("id_ed25519");
        let err = provision_vps(&api, &test_creds(), &key, None)
            .await
            .unwrap_err();
        assert!(err.brief().contains("create failed"));
    }

    #[tokio::test]
    async fn test_provision_propagates_wait_timeout() {
        let api = FakeHetznerApi {
            server_ip: String::new(),
            fail_verify: false,
            fail_create: false,
            never_running: true,
        };
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("id_ed25519");
        let err = provision_vps(&api, &test_creds(), &key, None)
            .await
            .unwrap_err();
        assert!(err.brief().to_lowercase().contains("timeout"));
    }
}
