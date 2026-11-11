//! Deploy pipeline for the Cloudflare-Worker-hosted DNS tunnel.
//!
//! Zero-credential: it uses only the already-present CF token (the same one
//! the rest of the app uses to manage workers), so the whole flow is automatic
//! after the single base token. No VPS, no SSH, no user-supplied server
//! credentials.

use crate::cf::Client;
use crate::error::CFError;
use crate::vps_deploy::TunnelMode;
use crate::worker_tunnel::bundle::{WORKER_CRON_SCHEDULE, WORKER_TUNNEL_JS};
use crate::worker_tunnel::secret;
use crate::worker_tunnel::DYB_TUNNEL_BASE;

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
    let worker_url = cf.workers_dev_url(account_id, &worker_name, &subdomain);

    // Per-worker secret resolution (two-phase rotation aware). On first deploy
    // a fresh secret is assigned and promoted immediately; on rotation the
    // pending (new) secret is staged and used for the deploy while the client
    // keeps talking on the current secret until the caller verifies + promotes.
    let mut profile = crate::store::profiles::load_profile(profile_id);
    let now = crate::store::now_ts() as u64;
    let entry = profile
        .config
        .worker_secrets
        .entry(worker_url.clone())
        .or_default();
    entry.worker_url = worker_url.clone();
    if entry.secret.is_empty() && entry.pending_secret.is_none() {
        entry.secret = secret::generate_secret();
        entry.rotated_unix = now;
        entry.version = 1;
    }
    let deploy_secret = entry
        .pending_secret
        .clone()
        .unwrap_or_else(|| entry.secret.clone());
    // The client-facing shared_secret stays the current (never pending).
    let client_secret = entry.secret.clone();
    crate::store::profiles::save_profile(&profile)?;

    // Ensure a KV namespace for the carrier-snapshot relay and bind it. The
    // worker bundle reads `env.DYB_CARRIER_SNAPSHOT` (flags 4/5). Creating it
    // here removes the last manual step — the token minted by the app already
    // carries the KV scope (see create_api_token).
    let kv_ns_id = cf
        .ensure_kv_namespace(account_id, "dastyab-carrier-snapshot")
        .await?;

    // Worker vars (secret, base domain, optional upstream).
    let mut vars: Vec<(String, String)> = vec![
        ("DYB_SESSION_SECRET".to_string(), deploy_secret.clone()),
        ("DYB_TUNNEL_BASE".to_string(), DYB_TUNNEL_BASE.to_string()),
    ];
    if let Some(upstream) = &opts.vless_upstream {
        vars.push(("DYB_VLESS_UPSTREAM".to_string(), upstream.clone()));
    }

    // Deploy the worker bundle. The cron trigger keeps the worker alive
    // during long blackouts so Cloudflare does not deactivate it as idle.
    //
    // ESM workers CANNOT be uploaded via the raw CF Worker upload API (it only
    // accepts classic/service-worker syntax and rejects `export default` with
    // error 10021). So when we are talking to the real Cloudflare API we must
    // deploy via wrangler (which bundles ESM → classic). When the client
    // points at a local mock server (tests) we keep the HTTP path so the mock
    // can be asserted against.
    if cf.is_live() {
        let wopts = crate::wrangler::WranglerDeployOpts {
            worker_name: worker_name.clone(),
            compat_date: opts.compat_date.clone(),
            kv_binding: Some(("DYB_CARRIER_SNAPSHOT".to_string(), kv_ns_id.clone())),
            crons: vec![WORKER_CRON_SCHEDULE.to_string()],
            vars,
        };
        let deployed = crate::wrangler::deploy_worker_via_wrangler(
            cf.token(),
            account_id,
            WORKER_TUNNEL_JS.as_bytes(),
            &wopts,
        )
        .await?;
        // The deployed URL is authoritative; the constructed `worker_url` is
        // only a fallback.
        let _ = deployed;
    } else {
        let binding = serde_json::json!({
            "type": "kv_namespace",
            "name": "DYB_CARRIER_SNAPSHOT",
            "namespace_id": kv_ns_id,
        });
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
        let mut vmap = serde_json::Map::new();
        for (k, v) in vars {
            vmap.insert(k, serde_json::Value::String(v));
        }
        cf.set_vars(account_id, &worker_name, vmap).await?;
    }

    // Persist the client config (mode=Worker) via the existing writer. It
    // always carries the current secret (never pending) so in-flight traffic
    // keeps working until a verified promotion.
    let cfg = crate::vps_deploy::TunnelClientConfig {
        host: worker_url.clone(),
        base_domain: DYB_TUNNEL_BASE.to_string(),
        session: opts.session_seed.clone(),
        resolver: "https".into(),
        mode: TunnelMode::Worker,
        worker_url: Some(worker_url.clone()),
        worker_name: Some(worker_name.clone()),
        shared_secret: Some(client_secret.clone()),
        worker_vless_upstream: opts.vless_upstream.clone(),
    };
    crate::vps_deploy::write_tunnel_client_config(profile_id, &cfg)?;

    Ok(WorkerTunnelDeploy {
        worker_name,
        worker_url,
        shared_secret: client_secret,
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

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    /// Serialize all deploy tests: the mem-dir override is thread-local, so a
    /// leaked override from one test could bleed into another that reuses the
    /// same thread. Holding this lock for the whole test makes the isolation
    /// deterministic.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Isolated mem dir. Keeps the TempDir alive for the whole test (its drop
    /// would delete the dir out from under the override).

    /// Create a real profile and return its id. The store's `profile_dir`
    /// falls back to `default` for unknown ids; writing a profile with a
    /// fictional id makes `save_profile`/`load_profile` diverge (the saved
    /// meta id then resolves to its own dir), so every test must use a real
    /// profile id.
    fn fresh_profile() -> String {
        crate::store::profiles::create_profile("deploy-test", "test").unwrap()
    }

    fn isolated_home() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(d.path().to_path_buf());
        d
    }

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
                        let _req = String::from_utf8_lossy(&buf).to_string();
                        let first_line = head.lines().next().unwrap_or("").to_string();
                        // Capture the PATCH settings body (carries the vars JSON)
                        // and the PUT deploy multipart body (carries metadata with
                        // bindings) so tests can assert on both.
                        let body_capture =
                            if first_line.starts_with("PATCH") || first_line.starts_with("PUT") {
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
                        } else if first_line.contains("/storage/kv/namespaces")
                            && first_line.starts_with("GET")
                        {
                            // List KV namespaces → empty on first call so the
                            // ensure path creates one.
                            r#"{"success":true,"result":[]}"#
                        } else if first_line.contains("/storage/kv/namespaces")
                            && first_line.starts_with("POST")
                        {
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

    #[tokio::test(flavor = "current_thread")]
    async fn test_deploy_worker_tunnel_auto_names_worker() {
        let _g = TEST_LOCK.lock().unwrap();
        let _home = isolated_home();
        let pid = fresh_profile();
        let (base, _log) = mock_cf_server();
        let cf = Client::with_base("tok", &base);
        let res = deploy_worker_tunnel(&cf, "acc1", &pid, &opts())
            .await
            .unwrap();
        assert!(res.worker_name.starts_with("dyb-tun-"));
        // "dyb-tun-" (8) + 8 hex chars from hex4(seed).
        assert_eq!(res.worker_name.len(), "dyb-tun-".len() + 8);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_deploy_worker_tunnel_persists_worker_mode_config() {
        let _g = TEST_LOCK.lock().unwrap();
        let _home = isolated_home();
        let pid = fresh_profile();
        let (base, _log) = mock_cf_server();
        let cf = Client::with_base("tok", &base);
        let _ = deploy_worker_tunnel(&cf, "acc1", &pid, &opts())
            .await
            .unwrap();
        let cfg = crate::vps_deploy::load_tunnel_client_config(&pid).unwrap();
        assert_eq!(cfg.mode, TunnelMode::Worker);
        assert!(cfg.worker_url.is_some());
        assert!(cfg.shared_secret.is_some());
        assert!(cfg.is_worker_mode());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_deploy_worker_tunnel_sets_session_secret_var() {
        let _g = TEST_LOCK.lock().unwrap();
        let _home = isolated_home();
        let pid = fresh_profile();
        let (base, _log) = mock_cf_server();
        let cf = Client::with_base("tok", &base);
        let res = deploy_worker_tunnel(&cf, "acc1", &pid, &opts())
            .await
            .unwrap();
        assert_eq!(res.shared_secret.len(), 32);
        // The per-worker secret is persisted in the profile config keyed by the
        // worker URL, and versioned at 1 on first deploy.
        let prof = crate::store::profiles::load_profile(&pid);
        let ws = prof.config.worker_secrets.get(&res.worker_url).unwrap();
        assert_eq!(ws.secret, res.shared_secret);
        assert_eq!(ws.version, 1);
        assert!(ws.pending_secret.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_deploy_worker_tunnel_returns_workers_dev_url() {
        let _g = TEST_LOCK.lock().unwrap();
        let _home = isolated_home();
        let pid = fresh_profile();
        let (base, _log) = mock_cf_server();
        let cf = Client::with_base("tok", &base);
        let res = deploy_worker_tunnel(&cf, "acc1", &pid, &opts())
            .await
            .unwrap();
        assert!(res.worker_url.starts_with("https://"));
        assert!(res.worker_url.ends_with(".sub.workers.dev"));
        assert_eq!(res.subdomain, "sub");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_deploy_worker_tunnel_persists_vless_upstream() {
        let _g = TEST_LOCK.lock().unwrap();
        let _home = isolated_home();
        let pid = fresh_profile();
        let (base, log) = mock_cf_server();
        let cf = Client::with_base("tok", &base);
        let mut o = opts();
        o.vless_upstream = Some("203.0.113.10:443".into());
        let _ = deploy_worker_tunnel(&cf, "acc1", &pid, &o).await.unwrap();
        let cfg = crate::vps_deploy::load_tunnel_client_config(&pid).unwrap();
        assert_eq!(
            cfg.worker_vless_upstream.as_deref(),
            Some("203.0.113.10:443")
        );
        // The deploy PUT and set_vars requests must both carry the upstream.
        let log = log.lock().unwrap().join("\n");
        assert!(log.contains("DYB_VLESS_UPSTREAM"), "log: {log}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_deploy_worker_tunnel_ensures_and_binds_kv_namespace() {
        let _g = TEST_LOCK.lock().unwrap();
        let _home = isolated_home();
        let pid = fresh_profile();
        let (base, log) = mock_cf_server();
        let cf = Client::with_base("tok", &base);
        let _ = deploy_worker_tunnel(&cf, "acc1", &pid, &opts())
            .await
            .unwrap();
        let log = log.lock().unwrap().join("\n");
        // The KV list + create must both have happened (ensure path).
        assert!(log.contains("/storage/kv/namespaces"), "log: {log}");
        // The deploy PUT metadata must bind DYB_CARRIER_SNAPSHOT to the created
        // namespace id.
        assert!(log.contains("kv_namespace"), "log: {log}");
        assert!(log.contains("DYB_CARRIER_SNAPSHOT"), "log: {log}");
        assert!(log.contains("kv-ns-1"), "log: {log}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_deploy_worker_tunnel_includes_self_ping_cron_trigger() {
        let _g = TEST_LOCK.lock().unwrap();
        let _home = isolated_home();
        let pid = fresh_profile();
        let (base, log) = mock_cf_server();
        let cf = Client::with_base("tok", &base);
        let _ = deploy_worker_tunnel(&cf, "acc1", &pid, &opts())
            .await
            .unwrap();
        let log = log.lock().unwrap().join("\n");
        // The deploy PUT metadata must carry the self-ping cron trigger so the
        // worker is scheduled to ping itself every 6h (keeps it from being
        // deactivated as idle during a long blackout).
        assert!(log.contains("triggers"), "log: {log}");
        assert!(log.contains("crons"), "log: {log}");
        assert!(log.contains(WORKER_CRON_SCHEDULE), "log: {log}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_deploy_worker_tunnel_propagates_cf_error() {
        let _g = TEST_LOCK.lock().unwrap();
        let _home = isolated_home();
        let pid = fresh_profile();
        // A server that 403s everything → deploy must surface the error.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                use std::io::{Read, Write};
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                let body =
                    r#"{"success":false,"errors":[{"code":9109,"message":"Invalid API Token"}]}"#;
                let resp = format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        let base = format!("http://{addr}");
        let cf = Client::with_base("tok", &base);
        let err = deploy_worker_tunnel(&cf, "acc1", &pid, &opts())
            .await
            .unwrap_err();
        assert_eq!(err.status, Some(403));
    }
}
