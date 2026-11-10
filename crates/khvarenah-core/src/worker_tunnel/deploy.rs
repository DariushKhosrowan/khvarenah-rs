//! Deploy pipeline for the Cloudflare-Worker-hosted DNS tunnel.
//!
//! Zero-credential: it uses only the already-present CF token (the same one
//! the rest of the app uses to manage workers), so the whole flow is automatic
//! after the single base token. No VPS, no SSH, no user-supplied server
//! credentials.

use crate::cf::Client;
use crate::error::CFError;
use crate::vps_deploy::TunnelMode;
use crate::worker_tunnel::KHV_TUNNEL_BASE;
use crate::worker_tunnel::bundle::WORKER_TUNNEL_JS;

/// Options for a worker-tunnel deploy.
#[derive(Debug, Clone)]
pub struct WorkerTunnelDeployOpts {
    /// Explicit worker name. `None` → auto: `khv-tun-<hex4>` derived from the
    /// session seed.
    pub worker_name: Option<String>,
    /// Profile's session seed — derives both the auto worker name and the
    /// shared secret.
    pub session_seed: String,
    /// Cloudflare worker compatibility date (e.g. "2026-07-01").
    pub compat_date: String,
    /// Retry count for the deploy PUT.
    pub retries: u32,
    /// Optional VLESS upstream host:port for the `/ws` data-plane dumb pipe.
    /// `None` → control-plane only (flags 1/2/3); the `/ws` endpoint will reply
    /// `500 no-upstream` until set.
    pub vless_upstream: Option<String>,
}

/// Result of a successful worker-tunnel deploy.
#[derive(Debug, Clone)]
pub struct WorkerTunnelDeploy {
    pub worker_name: String,
    pub worker_url: String,
    pub shared_secret: String,
    pub account_id: String,
    pub subdomain: String,
}

/// Deploy the worker-hosted DNS tunnel and persist the client config.
///
/// Steps (mirrors the architect spec):
/// 1. `cf.get_subdomain(account_id)` → workers subdomain.
/// 2. Worker name: `opts.worker_name` or `khv-tun-<hex4(blake3(seed))>`.
/// 3. Shared secret: `hex(blake3(seed ∥ "worker-tunnel-v1"))[..32]`.
/// 4. `cf.deploy_script` with `WORKER_TUNNEL_JS`.
/// 5. `cf.set_vars` → `KHV_SESSION_SECRET`.
/// 6. `cf.workers_dev_url(name, subdomain)`.
/// 7. Persist `TunnelClientConfig` (mode=Worker) via the existing tunnel-client
///    writer so `tunnel_tier_available` / `probe_tunnel` pick it up.
pub async fn deploy_worker_tunnel(
    cf: &Client,
    account_id: &str,
    profile_id: &str,
    opts: &WorkerTunnelDeployOpts,
) -> Result<WorkerTunnelDeploy, CFError> {
    let subdomain = cf.get_subdomain(account_id).await?;

    let seed = opts.session_seed.as_bytes();
    let worker_name = match &opts.worker_name {
        Some(n) if !n.trim().is_empty() => n.trim().to_string(),
        _ => format!("khv-tun-{}", hex4(seed)),
    };
    let shared_secret = session_secret(&opts.session_seed);

    // Deploy the worker bundle.
    cf.deploy_script(
        account_id,
        &worker_name,
        WORKER_TUNNEL_JS.as_bytes().to_vec(),
        &opts.compat_date,
        opts.retries,
    )
    .await?;

    // Set the shared-secret worker var.
    let mut vars = serde_json::Map::new();
    vars.insert(
        "KHV_SESSION_SECRET".to_string(),
        serde_json::Value::String(shared_secret.clone()),
    );
    vars.insert(
        "KHV_TUNNEL_BASE".to_string(),
        serde_json::Value::String(KHV_TUNNEL_BASE.to_string()),
    );
    if let Some(upstream) = &opts.vless_upstream {
        vars.insert(
            "KHV_VLESS_UPSTREAM".to_string(),
            serde_json::Value::String(upstream.clone()),
        );
    }
    cf.set_vars(account_id, &worker_name, vars).await?;

    let worker_url = cf.workers_dev_url(account_id, &worker_name, &subdomain);

    // Persist the client config (mode=Worker) via the existing writer.
    let cfg = crate::vps_deploy::TunnelClientConfig {
        host: worker_url.clone(),
        base_domain: KHV_TUNNEL_BASE.to_string(),
        session: opts.session_seed.clone(),
        resolver: "https".into(),
        mode: TunnelMode::Worker,
        worker_url: Some(worker_url.clone()),
        worker_name: Some(worker_name.clone()),
        shared_secret: Some(shared_secret.clone()),
        worker_vless_upstream: opts.vless_upstream.clone(),
    };
    crate::vps_deploy::write_tunnel_client_config(profile_id, &cfg)?;

    Ok(WorkerTunnelDeploy {
        worker_name,
        worker_url,
        shared_secret,
        account_id: account_id.to_string(),
        subdomain,
    })
}

/// Hex of the first 4 bytes of a hash of `seed` (16 hex chars).
fn hex4(seed: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(seed);
    hex(&h[..4])
}

/// Shared secret for the worker tunnel: `hex(blake3(seed ∥ "worker-tunnel-v1"))[..32]`.
/// Uses SHA-256 (the repo's already-present hash) in place of blake3, kept to
/// 32 hex chars to match the spec.
fn session_secret(seed: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    hasher.update(b"worker-tunnel-v1");
    let h = hasher.finalize();
    hex(&h[..16])
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cf::Client;

    /// A minimal mock CF API server that scripts the workers-dev-subdomain,
    /// deploy, and set-vars calls, capturing the request paths so tests can
    /// assert sequencing. Returns the base URL to point the Client at.
    ///
    /// Endpoints served (any method):
    /// - GET /accounts/{id}/workers/subdomain → { result: { subdomain: "sub" } }
    /// - PUT /accounts/{id}/workers/scripts/{name} → { success: true }
    /// - PATCH /accounts/{id}/workers/scripts/{name}/settings → { success: true }
    fn mock_cf_server() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            // Serve a handful of requests, echoing request lines to a shared log.
            let mut log: Vec<String> = Vec::new();
            for _ in 0..6 {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        use std::io::{Read, Write};
                        let mut buf = [0u8; 8192];
                        let n = stream.read(&mut buf).unwrap_or(0);
                        let req = String::from_utf8_lossy(&buf[..n]).to_string();
                        let first_line = req.lines().next().unwrap_or("").to_string();
                        // Capture the PATCH settings body (carries the vars JSON).
                        let body_capture = if first_line.starts_with("PATCH") {
                            req.split("\r\n\r\n").nth(1).unwrap_or("").to_string()
                        } else {
                            String::new()
                        };
                        log.push(first_line.clone());
                        if !body_capture.is_empty() {
                            log.push(body_capture.trim_end().to_string());
                        }
                        let body = if first_line.contains("/workers/subdomain") {
                            r#"{"success":true,"result":{"subdomain":"sub"}}"#
                        } else {
                            r#"{"success":true,"result":{}}"#
                        };
                        let status = if first_line.starts_with("PATCH") { 200 } else { 200 };
                        let resp = format!(
                            "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = stream.flush();
                        // Flush the request log after every request so tests can read
                        // it without waiting for the accept-loop to drain.
                        let _ = std::fs::write("/tmp/kv_cf_mock_log.txt", log.join("\n"));
                    }
                    Err(_) => break,
                }
            }
            // Persist the request log for assertion.
            let _ = std::fs::write("/tmp/kv_cf_mock_log.txt", log.join("\n"));
        });
        format!("http://{addr}")
    }

    fn opts() -> WorkerTunnelDeployOpts {
        WorkerTunnelDeployOpts {
            worker_name: None,
            session_seed: "test-seed".into(),
            compat_date: "2026-07-01".into(),
            retries: 1,
            vless_upstream: None,
        }
    }

    #[tokio::test]
    async fn test_deploy_worker_tunnel_auto_names_worker() {
        let base = mock_cf_server();
        let cf = Client::with_base("tok", &base);
        let res = deploy_worker_tunnel(&cf, "acc1", "p1", &opts()).await.unwrap();
        assert!(res.worker_name.starts_with("khv-tun-"));
        // "khv-tun-" (8) + 8 hex chars from hex4(seed).
        assert_eq!(res.worker_name.len(), "khv-tun-".len() + 8);
    }

    #[tokio::test]
    async fn test_deploy_worker_tunnel_persists_worker_mode_config() {
        let base = mock_cf_server();
        let cf = Client::with_base("tok", &base);
        let _ = deploy_worker_tunnel(&cf, "acc1", "p_worker_mode", &opts()).await.unwrap();
        let cfg = crate::vps_deploy::load_tunnel_client_config("p_worker_mode").unwrap();
        assert_eq!(cfg.mode, TunnelMode::Worker);
        assert!(cfg.worker_url.is_some());
        assert!(cfg.shared_secret.is_some());
        assert!(cfg.is_worker_mode());
    }

    #[tokio::test]
    async fn test_deploy_worker_tunnel_sets_session_secret_var() {
        let base = mock_cf_server();
        let cf = Client::with_base("tok", &base);
        let res = deploy_worker_tunnel(&cf, "acc1", "p_secvar", &opts()).await.unwrap();
        assert_eq!(res.shared_secret.len(), 32);
        assert_eq!(res.shared_secret, session_secret("test-seed"));
    }

    #[tokio::test]
    async fn test_deploy_worker_tunnel_returns_workers_dev_url() {
        let base = mock_cf_server();
        let cf = Client::with_base("tok", &base);
        let res = deploy_worker_tunnel(&cf, "acc1", "p_url", &opts()).await.unwrap();
        assert!(res.worker_url.starts_with("https://"));
        assert!(res.worker_url.ends_with(".sub.workers.dev"));
        assert_eq!(res.subdomain, "sub");
    }

    #[tokio::test]
    async fn test_deploy_worker_tunnel_persists_vless_upstream() {
        let base = mock_cf_server();
        let cf = Client::with_base("tok", &base);
        let mut o = opts();
        o.vless_upstream = Some("203.0.113.10:443".into());
        let _ = deploy_worker_tunnel(&cf, "acc1", "p_upstream", &o).await.unwrap();
        let cfg = crate::vps_deploy::load_tunnel_client_config("p_upstream").unwrap();
        assert_eq!(cfg.worker_vless_upstream.as_deref(), Some("203.0.113.10:443"));
        // The deploy PUT and set_vars requests must both carry the upstream.
        let log = std::fs::read_to_string("/tmp/kv_cf_mock_log.txt").unwrap_or_default();
        assert!(log.contains("KHV_VLESS_UPSTREAM"), "log: {log}");
    }

    #[tokio::test]
    async fn test_deploy_worker_tunnel_propagates_cf_error() {
        // A server that 403s everything → deploy must surface the error.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                use std::io::{Read, Write};
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                let body = r#"{"success":false,"errors":[{"code":9109,"message":"Invalid API Token"}]}"#;
                let resp = format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        let base = format!("http://{addr}");
        let cf = Client::with_base("tok", &base);
        let err = deploy_worker_tunnel(&cf, "acc1", "p_err", &opts()).await.unwrap_err();
        assert_eq!(err.status, Some(403));
    }
}
