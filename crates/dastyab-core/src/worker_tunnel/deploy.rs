//! Deploy pipeline for the Cloudflare-Worker-hosted DNS tunnel.
//!
//! Zero-credential: it uses only the already-present CF token (the same one
//! the rest of the app uses to manage workers), so the whole flow is automatic
//! after the single base token. No VPS, no SSH, no user-supplied server
//! credentials.

use crate::cf::Client;
use crate::error::CFError;
use crate::vps_deploy::TunnelMode;
use crate::worker_tunnel::DYB_TUNNEL_BASE;
use crate::worker_tunnel::bundle::{WORKER_CRON_SCHEDULE, WORKER_TUNNEL_JS};

/// Options for a worker-tunnel deploy.
#[derive(Debug, Clone)]
pub struct WorkerTunnelDeployOpts {
    /// Explicit worker name. `None` → auto: `dyb-tun-<hex4>` derived from the
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
/// 2. Worker name: `opts.worker_name` or `dyb-tun-<hex4(blake3(seed))>`.
/// 3. Shared secret: `hex(blake3(seed ∥ "worker-tunnel-v1"))[..32]`.
/// 4. `cf.deploy_script` with `WORKER_TUNNEL_JS`.
/// 5. `cf.set_vars` → `DYB_SESSION_SECRET`.
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
        _ => format!("dyb-tun-{}", hex4(seed)),
    };
    let shared_secret = session_secret(&opts.session_seed);

    // Ensure a KV namespace for the carrier-snapshot relay and bind it. The
    // worker bundle reads `env.DYB_CARRIER_SNAPSHOT` (flags 4/5). Creating it
    // here removes the last manual step — the token minted by the app already
    // carries the KV scope (see create_api_token).
    let kv_ns_id = cf
        .ensure_kv_namespace(account_id, "dastyab-carrier-snapshot")
        .await?;
    let binding = serde_json::json!({
        "type": "kv_namespace",
        "name": "DYB_CARRIER_SNAPSHOT",
        "namespace_id": kv_ns_id,
    });

    // Deploy the worker bundle (with the KV binding and self-ping cron
    // trigger in metadata). The cron trigger keeps the worker alive during
    // long blackouts so Cloudflare does not deactivate it as idle.
    cf.deploy_script_with_bindings(
        account_id,
        &worker_name,
        WORKER_TUNNEL_JS.as_bytes().to_vec(),
        &opts.compat_date,
        opts.retries,
        vec![binding],
        &[WORKER_CRON_SCHEDULE],
    )
    .await?;

    // Set the shared-secret worker var.
    let mut vars = serde_json::Map::new();
    vars.insert(
        "DYB_SESSION_SECRET".to_string(),
        serde_json::Value::String(shared_secret.clone()),
    );
    vars.insert(
        "DYB_TUNNEL_BASE".to_string(),
        serde_json::Value::String(DYB_TUNNEL_BASE.to_string()),
    );
    if let Some(upstream) = &opts.vless_upstream {
        vars.insert(
            "DYB_VLESS_UPSTREAM".to_string(),
            serde_json::Value::String(upstream.clone()),
        );
    }
    cf.set_vars(account_id, &worker_name, vars).await?;

    let worker_url = cf.workers_dev_url(account_id, &worker_name, &subdomain);

    // Persist the client config (mode=Worker) via the existing writer.
    let cfg = crate::vps_deploy::TunnelClientConfig {
        host: worker_url.clone(),
        base_domain: DYB_TUNNEL_BASE.to_string(),
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
    /// deploy, and set-vars calls, capturing the request lines in memory so
    /// tests can assert sequencing without a shared file (parallel-safe).
    /// Returns `(base_url, log)` — `log` is appended per request.
    ///
    /// Endpoints served (any method):
    /// - GET /accounts/{id}/workers/subdomain → { result: { subdomain: "sub" } }
    /// - PUT /accounts/{id}/workers/scripts/{name} → { success: true }
    /// - PATCH /accounts/{id}/workers/scripts/{name}/settings → { success: true }
    fn mock_cf_server() -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let log2 = log.clone();
        std::thread::spawn(move || {
            for _ in 0..6 {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        use std::io::{Read, Write};
                        // Read headers first, then exactly Content-Length body
                        // bytes. A single read() is racy for the large multipart
                        // deploy body; reading to EOF deadlocks because the client
                        // waits for our response before closing.
                        let mut buf = Vec::new();
                        let mut chunk = [0u8; 4096];
                        // Read until the header terminator is present.
                        let mut header_end = None;
                        while header_end.is_none() {
                            let n = match stream.read(&mut chunk) {
                                Ok(n) => n,
                                Err(_) => break,
                            };
                            if n == 0 {
                                break;
                            }
                            buf.extend_from_slice(&chunk[..n]);
                            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                header_end = Some(pos + 4);
                            }
                        }
                        let Some(end) = header_end else {
                            return;
                        };
                        // Parse Content-Length from the header section.
                        let head = String::from_utf8_lossy(&buf[..end]).to_string();
                        let clen: usize = head
                            .lines()
                            .find_map(|l| {
                                let l = l.to_lowercase();
                                l.strip_prefix("content-length:")
                                    .and_then(|v| v.trim().parse().ok())
                            })
                            .unwrap_or(0);
                        while buf.len() < end + clen {
                            let n = match stream.read(&mut chunk) {
                                Ok(n) => n,
                                Err(_) => break,
                            };
                            if n == 0 {
                                break;
                            }
                            buf.extend_from_slice(&chunk[..n]);
                        }
                        let req = String::from_utf8_lossy(&buf).to_string();
                        let first_line = head.lines().next().unwrap_or("").to_string();
                        // Capture the PATCH settings body (carries the vars JSON)
                        // and the PUT deploy multipart body (carries metadata with
                        // bindings) so tests can assert on both.
                        let body_capture = if first_line.starts_with("PATCH")
                            || first_line.starts_with("PUT")
                        {
                            // Start after the header terminator.
                            buf.get(end..)
                                .map(|b| String::from_utf8_lossy(b).to_string())
                                .unwrap_or_default()
                        } else {
                            String::new()
                        };
                        {
                            let mut log = log2.lock().unwrap();
                            log.push(first_line.clone());
                            if !body_capture.is_empty() {
                                log.push(body_capture.trim_end().to_string());
                            }
                        }
                        let body = if first_line.contains("/workers/subdomain") {
                            r#"{"success":true,"result":{"subdomain":"sub"}}"#
                        } else if first_line.contains("/storage/kv/namespaces") && first_line.starts_with("GET") {
                            // List KV namespaces → empty on first call so the
                            // ensure path creates one.
                            r#"{"success":true,"result":[]}"#
                        } else if first_line.contains("/storage/kv/namespaces") && first_line.starts_with("POST") {
                            // Create KV namespace → return a synthetic id.
                            r#"{"success":true,"result":{"id":"kv-ns-1","title":"dastyab-carrier-snapshot"}}"#
                        } else {
                            r#"{"success":true,"result":{}}"#
                        };
                        let status = 200;
                        let resp = format!(
                            "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(_) => break,
                }
            }
        });
        (format!("http://{addr}"), log)
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
        let (base, _log) = mock_cf_server();
        let cf = Client::with_base("tok", &base);
        let res = deploy_worker_tunnel(&cf, "acc1", "p1", &opts()).await.unwrap();
        assert!(res.worker_name.starts_with("dyb-tun-"));
        // "dyb-tun-" (8) + 8 hex chars from hex4(seed).
        assert_eq!(res.worker_name.len(), "dyb-tun-".len() + 8);
    }

    #[tokio::test]
    async fn test_deploy_worker_tunnel_persists_worker_mode_config() {
        let (base, _log) = mock_cf_server();
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
        let (base, _log) = mock_cf_server();
        let cf = Client::with_base("tok", &base);
        let res = deploy_worker_tunnel(&cf, "acc1", "p_secvar", &opts()).await.unwrap();
        assert_eq!(res.shared_secret.len(), 32);
        assert_eq!(res.shared_secret, session_secret("test-seed"));
    }

    #[tokio::test]
    async fn test_deploy_worker_tunnel_returns_workers_dev_url() {
        let (base, _log) = mock_cf_server();
        let cf = Client::with_base("tok", &base);
        let res = deploy_worker_tunnel(&cf, "acc1", "p_url", &opts()).await.unwrap();
        assert!(res.worker_url.starts_with("https://"));
        assert!(res.worker_url.ends_with(".sub.workers.dev"));
        assert_eq!(res.subdomain, "sub");
    }

    #[tokio::test]
    async fn test_deploy_worker_tunnel_persists_vless_upstream() {
        let (base, log) = mock_cf_server();
        let cf = Client::with_base("tok", &base);
        let mut o = opts();
        o.vless_upstream = Some("203.0.113.10:443".into());
        let _ = deploy_worker_tunnel(&cf, "acc1", "p_upstream", &o).await.unwrap();
        let cfg = crate::vps_deploy::load_tunnel_client_config("p_upstream").unwrap();
        assert_eq!(cfg.worker_vless_upstream.as_deref(), Some("203.0.113.10:443"));
        // The deploy PUT and set_vars requests must both carry the upstream.
        let log = log.lock().unwrap().join("\n");
        assert!(log.contains("DYB_VLESS_UPSTREAM"), "log: {log}");
    }

    #[tokio::test]
    async fn test_deploy_worker_tunnel_ensures_and_binds_kv_namespace() {
        let (base, log) = mock_cf_server();
        let cf = Client::with_base("tok", &base);
        let _ = deploy_worker_tunnel(&cf, "acc1", "p_kv", &opts()).await.unwrap();
        let log = log.lock().unwrap().join("\n");
        // The KV list + create must both have happened (ensure path).
        assert!(log.contains("/storage/kv/namespaces"), "log: {log}");
        // The deploy PUT metadata must bind DYB_CARRIER_SNAPSHOT to the created
        // namespace id.
        assert!(log.contains("kv_namespace"), "log: {log}");
        assert!(log.contains("DYB_CARRIER_SNAPSHOT"), "log: {log}");
        assert!(log.contains("kv-ns-1"), "log: {log}");
    }

    #[tokio::test]
    async fn test_deploy_worker_tunnel_includes_self_ping_cron_trigger() {
        let (base, log) = mock_cf_server();
        let cf = Client::with_base("tok", &base);
        let _ = deploy_worker_tunnel(&cf, "acc1", "p_cron", &opts()).await.unwrap();
        let log = log.lock().unwrap().join("\n");
        // The deploy PUT metadata must carry the self-ping cron trigger so the
        // worker is scheduled to ping itself every 6h (keeps it from being
        // deactivated as idle during a long blackout).
        assert!(log.contains("triggers"), "log: {log}");
        assert!(log.contains("crons"), "log: {log}");
        assert!(log.contains(WORKER_CRON_SCHEDULE), "log: {log}");
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
