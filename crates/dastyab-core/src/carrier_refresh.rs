//! Worker-mediated carrier-snapshot refresh — "rebuild routing from inside".
//!
//! During a total blackout the only channel back to your own infra is the
//! Cloudflare Worker control plane (CF edge is reachable when local DNS/direct
//! is dead). [`CarrierRefresher`] uses it to pull a newer carrier snapshot
//! (flag 4) or push the current one (flag 5), authenticated by the shared
//! session secret (`X-DastYab-Session`).
//!
//! The worker is a **durable relay**: it never originates or verifies carriers,
//! it stores the latest snapshot JSON blob in a KV binding
//! (`DYB_CARRIER_SNAPSHOT`) and relays it. Integrity is the client's job
//! ([`CarrierSnapshot::verify`]).
//!
//! Blocking HTTP: like [`crate::worker_tunnel::resolver::WorkerTunnelResolver`],
//! reqwest's blocking client spawns an internal tokio runtime that cannot be
//! created/dropped inside another async context. We therefore run every request
//! on a dedicated OS thread via `std::thread::scope`.

use crate::carrier_pool::{
    CarrierPool, CarrierPoolError, CarrierProvenance, CarrierSnapshot, MergeReport,
};
use serde::{Deserialize, Serialize};

/// Request body for a `flag: 4` / `flag: 5` control-plane call.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct CarrierRefreshRequest {
    /// We always send schema 1; the server ignores it for now.
    pub schema_version: u32,
    /// The pool's current generation (informational server-side).
    pub known_generation: u64,
}

/// Response body for a `flag: 4` (pull) call.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct CarrierRefreshResponse {
    /// The stored snapshot, if the worker has one yet.
    pub snapshot: Option<CarrierSnapshot>,
    /// The server's own monotonic write counter (independent of snapshot.generation).
    pub server_generation: u64,
}

/// Outcome of a successful refresh.
#[derive(Clone, Debug)]
pub enum RefreshOutcome {
    /// The pool was changed by the merge.
    Updated(MergeReport),
    /// Server has a snapshot but the merge was a no-op (already current).
    NotNewer { server_generation: u64 },
    /// The worker has no snapshot stored yet.
    NoSnapshot,
}

/// Errors from a refresh.
#[derive(Debug)]
pub enum RefreshError {
    Transport(String),
    Auth,
    Integrity(String),
    Schema(u32),
    Pool(CarrierPoolError),
}

impl From<CarrierPoolError> for RefreshError {
    fn from(e: CarrierPoolError) -> Self {
        RefreshError::Pool(e)
    }
}

impl std::fmt::Display for RefreshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RefreshError::Transport(s) => write!(f, "transport: {s}"),
            RefreshError::Auth => write!(f, "auth: session secret rejected (401)"),
            RefreshError::Integrity(s) => write!(f, "integrity: {s}"),
            RefreshError::Schema(v) => write!(f, "unsupported schema version: {v}"),
            RefreshError::Pool(e) => write!(f, "pool: {e}"),
        }
    }
}

impl std::error::Error for RefreshError {}

/// Timeout for the blocking HTTP call.
const HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// Client-side refresher for the worker-hosted carrier-snapshot relay.
#[derive(Debug, Clone)]
pub struct CarrierRefresher {
    worker_url: String,
    shared_secret: String,
}

impl CarrierRefresher {
    pub fn new(worker_url: impl Into<String>, shared_secret: impl Into<String>) -> Self {
        Self {
            worker_url: worker_url.into(),
            shared_secret: shared_secret.into(),
        }
    }

    /// Pull the latest snapshot from the worker and merge it into `pool`.
    ///
    /// Blocking. Returns [`RefreshOutcome::Updated`] when the pool changed,
    /// [`RefreshOutcome::NotNewer`] when the merge was a no-op, and
    /// [`RefreshOutcome::NoSnapshot`] when the worker has none.
    pub fn refresh_once(
        &self,
        pool: &CarrierPool,
        now_unix: u64,
    ) -> Result<RefreshOutcome, RefreshError> {
        let known_generation = pool.load()?.generation;
        let req = CarrierRefreshRequest {
            schema_version: 1,
            known_generation,
        };
        let resp: CarrierRefreshResponse = self.post_ctl(4, &req)?;

        let Some(snapshot) = resp.snapshot else {
            return Ok(RefreshOutcome::NoSnapshot);
        };
        if snapshot.schema_version != 1 {
            return Err(RefreshError::Schema(snapshot.schema_version));
        }
        snapshot.verify().map_err(|e| match e {
            CarrierPoolError::Integrity(s) => RefreshError::Integrity(s),
            CarrierPoolError::Schema(v) => RefreshError::Schema(v),
            other => RefreshError::Pool(other),
        })?;

        let report = pool.merge(snapshot, CarrierProvenance::Remote, now_unix)?;
        if report.added + report.updated > 0 {
            Ok(RefreshOutcome::Updated(report))
        } else {
            Ok(RefreshOutcome::NotNewer {
                server_generation: resp.server_generation,
            })
        }
    }

    /// Push the pool's current snapshot to the worker relay.
    ///
    /// Blocking. Skips silently (Ok) when the pool has zero endpoints.
    pub fn push_snapshot(&self, pool: &CarrierPool) -> Result<(), RefreshError> {
        let snapshot = pool.load()?;
        if snapshot.endpoints.is_empty() {
            return Ok(());
        }
        let body = serde_json::json!({
            "flag": 5,
            "snapshot": snapshot,
        });
        self.post_ctl_raw(&body).map(|_| ())
    }

    /// Query the worker's last self-ping timestamp (the `_ping` KV key that
    /// the worker's `scheduled` cron handler writes every 6h). Lets the daemon
    /// surface whether the worker tier is staying active (i.e. not drifting
    /// toward Cloudflare inactivity deactivation during a long blackout).
    pub fn query_self_ping(&self) -> Result<Option<u64>, RefreshError> {
        let body = serde_json::json!({ "flag": 6 });
        let raw: serde_json::Value = self.post_ctl_raw(&body)?;
        match raw.get("ping_ts") {
            Some(serde_json::Value::String(s)) => s
                .parse::<u64>()
                .map(Some)
                .map_err(|e| RefreshError::Transport(format!("non-numeric ping_ts: {e}"))),
            Some(serde_json::Value::Null) | None => Ok(None),
            Some(other) => Err(RefreshError::Transport(format!(
                "unexpected ping_ts type: {other}"
            ))),
        }
    }

    /// POST a control-plane request to `{worker_url}/ctl`.
    fn post_ctl<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        flag: u32,
        req: &T,
    ) -> Result<R, RefreshError> {
        let req_val =
            serde_json::to_value(req).map_err(|e| RefreshError::Transport(e.to_string()))?;
        let mut body = serde_json::Map::new();
        body.insert("flag".into(), serde_json::Value::from(flag));
        if let serde_json::Value::Object(m) = req_val {
            body.extend(m);
        }
        let raw: serde_json::Value = self.post_ctl_raw(&serde_json::Value::Object(body))?;
        serde_json::from_value(raw).map_err(|e| RefreshError::Transport(e.to_string()))
    }

    /// POST a raw JSON body and return the parsed response.
    fn post_ctl_raw(&self, body: &serde_json::Value) -> Result<serde_json::Value, RefreshError> {
        let url = format!("{}/ctl", self.worker_url.trim_end_matches('/'));
        let secret = self.shared_secret.clone();
        let body = body.clone();

        std::thread::scope(|scope| {
            let handle = scope.spawn(move || {
                let client = reqwest::blocking::Client::builder()
                    .timeout(HTTP_TIMEOUT)
                    .user_agent("dastyab-carrier-refresh")
                    .build()
                    .map_err(|e| RefreshError::Transport(format!("client: {e}")))?;
                let resp = client
                    .post(&url)
                    .header("X-DastYab-Session", &secret)
                    .json(&body)
                    .send()
                    .map_err(|e| RefreshError::Transport(format!("request: {e}")))?;
                let status = resp.status().as_u16();
                if status == 401 {
                    return Err(RefreshError::Auth);
                }
                if !(200..300).contains(&status) {
                    return Err(RefreshError::Transport(format!("http {status}")));
                }
                resp.json::<serde_json::Value>()
                    .map_err(|e| RefreshError::Transport(format!("json: {e}")))
            });
            handle
                .join()
                .unwrap_or_else(|_| Err(RefreshError::Transport("worker thread panicked".into())))
        })
    }

    /// Push the pool's snapshot to the worker relay, but only if the endpoint
    /// identity set changed since the last successful push to this worker.
    ///
    /// Identity is `(kind, host, port, sni, worker_url)` — weight/probe
    /// telemetry drift does not trigger a push (the worker carries the routing
    /// table, not the probe history). The last-pushed hash is persisted next
    /// to the pool file as `<pool_path>.push_hash`; on push failure the hash
    /// is left unchanged so the next caller retries.
    pub fn push_snapshot_if_identity_changed(
        &self,
        pool: &CarrierPool,
    ) -> Result<PushOutcome, RefreshError> {
        let snapshot = pool.load()?;
        if snapshot.endpoints.is_empty() {
            return Ok(PushOutcome::Skipped {
                reason: SkipReason::Empty,
            });
        }
        let identity = pool.identity_hash().map_err(RefreshError::Pool)?;
        let hash_path = push_hash_path(pool.path());
        if let Some(prev) = load_push_hash(&hash_path) {
            if prev.worker_url == self.worker_url && prev.hash_hex == hex_str(&identity) {
                return Ok(PushOutcome::Skipped {
                    reason: SkipReason::Unchanged,
                });
            }
        }

        let body = serde_json::json!({
            "flag": 5,
            "snapshot": snapshot,
        });
        self.post_ctl_raw(&body)?;
        // Push succeeded → record the hash for this worker.
        write_push_hash(
            &hash_path,
            PushHashRecord {
                schema_version: 1,
                worker_url: self.worker_url.clone(),
                hash_hex: hex_str(&identity),
            },
        )?;
        Ok(PushOutcome::Pushed {
            endpoints: snapshot.endpoints.len(),
        })
    }
}

/// Outcome of a [`CarrierRefresher::push_snapshot_if_identity_changed`] call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushOutcome {
    /// Pool has no endpoints (nothing to push).
    Skipped { reason: SkipReason },
    /// A snapshot was pushed to the worker.
    Pushed { endpoints: usize },
}

/// Why a push was skipped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SkipReason {
    Empty,
    Unchanged,
}

/// Persisted record of the last-pushed identity hash for a worker.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct PushHashRecord {
    schema_version: u32,
    worker_url: String,
    hash_hex: String,
}

/// `push_hash` file path: sibling of the pool file (`<pool_path>.push_hash`).
fn push_hash_path(pool_path: &std::path::Path) -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(pool_path);
    p.set_extension("push_hash");
    p
}

/// Hex of a 32-byte hash.
fn hex_str(h: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in h {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Load the stored push-hash record; `None` when missing/corrupt (treated as
/// "never pushed" → forces a push, the conservative default).
fn load_push_hash(path: &std::path::Path) -> Option<PushHashRecord> {
    let bytes = std::fs::read(path).ok()?;
    let rec: PushHashRecord = serde_json::from_slice(&bytes).ok()?;
    if rec.schema_version != 1 {
        return None;
    }
    Some(rec)
}

/// Atomically persist a push-hash record (`.tmp` → rename).
fn write_push_hash(path: &std::path::Path, rec: PushHashRecord) -> Result<(), RefreshError> {
    let tmp = {
        let p = std::path::PathBuf::from(path);
        let mut os = p.into_os_string();
        os.push(".tmp");
        std::path::PathBuf::from(os)
    };
    let bytes = serde_json::to_vec(&rec).map_err(|e| RefreshError::Transport(e.to_string()))?;
    std::fs::write(&tmp, &bytes).map_err(|e| RefreshError::Transport(e.to_string()))?;
    std::fs::rename(&tmp, path).map_err(|e| RefreshError::Transport(e.to_string()))?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::carrier_pool::{CarrierEndpoint, CarrierKind, CarrierProvenance};

    fn ep(host: &str) -> CarrierEndpoint {
        CarrierEndpoint {
            kind: CarrierKind::WorkerData,
            host: host.to_string(),
            port: 443,
            sni: None,
            worker_url: None,
            upstream: Some(format!("{host}:443")),
            weight: 0.9,
            last_probe_ok_unix: None,
            last_probe_rtt_ms: None,
            provenance: CarrierProvenance::Deployed,
            desync_strategy: None,
        }
    }

    fn snapshot_with(hosts: &[&str], generation: u64) -> CarrierSnapshot {
        let mut snap = CarrierSnapshot::new_empty(1000);
        snap.generation = generation;
        for h in hosts {
            snap.endpoints.push(ep(h));
        }
        snap.sign().unwrap();
        snap
    }

    fn tmp_pool_with(hosts: &[&str], generation: u64) -> (tempfile::TempDir, CarrierPool) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool.json");
        let pool = CarrierPool::open(&path).unwrap();
        let snap = snapshot_with(hosts, generation);
        pool.store_atomic(&snap).unwrap();
        (dir, pool)
    }

    /// A mock worker HTTP server that answers control-plane calls per a
    /// responder closure and captures request bodies. Returns `(base, log)`.
    fn mock_worker(
        responder: impl Fn(&serde_json::Value) -> (u16, serde_json::Value) + Send + 'static,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let log2 = log.clone();
        std::thread::spawn(move || {
            for _ in 0..8 {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        use std::io::{Read, Write};
                        let mut buf = [0u8; 16384];
                        let n = stream.read(&mut buf).unwrap_or(0);
                        let req = String::from_utf8_lossy(&buf[..n]).to_string();
                        let mut iter = req.split("\r\n\r\n");
                        let _head = iter.next();
                        let body = iter.next().unwrap_or("");
                        let parsed: serde_json::Value =
                            serde_json::from_str(body).unwrap_or_default();
                        log2.lock().unwrap().push(parsed.to_string());
                        let (status, payload) = responder(&parsed);
                        let out = serde_json::to_vec(&payload).unwrap();
                        let resp = format!(
                            "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            out.len()
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = stream.write_all(&out);
                        let _ = stream.flush();
                    }
                    Err(_) => break,
                }
            }
        });
        (format!("http://{addr}"), log)
    }

    fn refresher(url: &str) -> CarrierRefresher {
        CarrierRefresher::new(url, "secret")
    }

    #[test]
    fn carrier_refresh_no_snapshot_returns_no_snapshot() {
        let (url, _log) = mock_worker(|_| {
            (
                200,
                serde_json::json!({ "snapshot": null, "server_generation": 0 }),
            )
        });
        let (_dir, pool) = tmp_pool_with(&["a.example.com"], 1);
        let before = pool.load().unwrap();
        let outcome = refresher(&url).refresh_once(&pool, 2000).unwrap();
        assert!(matches!(outcome, RefreshOutcome::NoSnapshot));
        let after = pool.load().unwrap();
        assert_eq!(after.endpoints.len(), before.endpoints.len());
        assert_eq!(after.generation, before.generation);
    }

    #[test]
    fn carrier_refresh_not_newer_is_noop() {
        // Server returns a snapshot byte-identical to the pool's current one.
        let snap = snapshot_with(&["a.example.com"], 5);
        let (url, _log) = mock_worker(move |_| {
            let s = snap.clone();
            (
                200,
                serde_json::json!({ "snapshot": s, "server_generation": 7 }),
            )
        });
        let (_dir, pool) = tmp_pool_with(&["a.example.com"], 5);
        // Re-store with Remote provenance so merge is a true no-op.
        let mut snap = snapshot_with(&["a.example.com"], 5);
        for e in &mut snap.endpoints {
            e.provenance = CarrierProvenance::Remote;
        }
        snap.sign().unwrap();
        pool.store_atomic(&snap).unwrap();

        let before = pool.load().unwrap();
        let outcome = refresher(&url).refresh_once(&pool, 2000).unwrap();
        assert!(matches!(
            outcome,
            RefreshOutcome::NotNewer {
                server_generation: 7
            }
        ));
        let after = pool.load().unwrap();
        assert_eq!(after.generation, before.generation);
    }

    #[test]
    fn carrier_refresh_updates_and_merges() {
        let snap = snapshot_with(&["a.example.com", "b.example.com"], 9);
        let (url, _log) = mock_worker(move |_| {
            let s = snap.clone();
            (
                200,
                serde_json::json!({ "snapshot": s, "server_generation": 9 }),
            )
        });
        let (_dir, pool) = tmp_pool_with(&["old.example.com"], 1);
        let outcome = refresher(&url).refresh_once(&pool, 2000).unwrap();
        let RefreshOutcome::Updated(report) = outcome else {
            panic!("expected Updated");
        };
        assert_eq!(report.added, 2);
        let after = pool.load().unwrap();
        assert!(after.endpoints.iter().any(|e| e.host == "a.example.com"));
        assert!(after.endpoints.iter().any(|e| e.host == "b.example.com"));
        // The newly-added endpoints carry Remote provenance.
        assert!(after
            .endpoints
            .iter()
            .filter(|e| e.host == "a.example.com" || e.host == "b.example.com")
            .all(|e| e.provenance == CarrierProvenance::Remote));
    }

    #[test]
    fn carrier_refresh_integrity_fail_is_rejected() {
        let mut snap = snapshot_with(&["a.example.com"], 3);
        // Tamper after signing.
        snap.endpoints[0].host = "X.example.com".to_string();
        let (url, _log) = mock_worker(move |_| {
            let s = snap.clone();
            (
                200,
                serde_json::json!({ "snapshot": s, "server_generation": 3 }),
            )
        });
        let (_dir, pool) = tmp_pool_with(&["old.example.com"], 1);
        let err = refresher(&url).refresh_once(&pool, 2000).unwrap_err();
        assert!(matches!(err, RefreshError::Integrity(_)));
        // Pool untouched.
        let after = pool.load().unwrap();
        assert_eq!(after.endpoints.len(), 1);
        assert_eq!(after.endpoints[0].host, "old.example.com");
    }

    #[test]
    fn carrier_refresh_auth_required() {
        let (url, log) = mock_worker(|_| (401, serde_json::json!({ "error": "session" })));
        let (_dir, pool) = tmp_pool_with(&["a.example.com"], 1);
        let err = refresher(&url).refresh_once(&pool, 2000).unwrap_err();
        assert!(matches!(err, RefreshError::Auth));
        // The mock received exactly one request (auth failed, no retry).
        assert_eq!(log.lock().unwrap().len(), 1);
    }

    #[test]
    fn carrier_refresh_push_snapshot_roundtrip() {
        let (url, log) = mock_worker(|_| (200, serde_json::json!({ "stored_generation": 1 })));
        let (_dir, pool) = tmp_pool_with(&["a.example.com", "b.example.com", "c.example.com"], 2);
        refresher(&url).push_snapshot(&pool).unwrap();
        let bodies = log.lock().unwrap();
        assert_eq!(bodies.len(), 1);
        let b: serde_json::Value = serde_json::from_str(&bodies[0]).unwrap();
        assert_eq!(b["flag"], 5);
        assert_eq!(b["snapshot"]["schema_version"], 1);
        let hosts: Vec<_> = b["snapshot"]["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["host"].as_str().unwrap())
            .collect();
        assert!(hosts.contains(&"a.example.com"));
        assert!(hosts.contains(&"b.example.com"));
        assert!(hosts.contains(&"c.example.com"));
    }

    #[test]
    fn carrier_refresh_push_then_pull_is_idempotent() {
        // Worker stores the pushed snapshot and echoes it back on pull.
        let stored = std::sync::Arc::new(std::sync::Mutex::new(None::<CarrierSnapshot>));
        let stored2 = stored.clone();
        let (url, _log) = mock_worker(move |body: &serde_json::Value| {
            if body["flag"] == 5 {
                let snap: CarrierSnapshot =
                    serde_json::from_value(body["snapshot"].clone()).unwrap();
                *stored2.lock().unwrap() = Some(snap);
                (200, serde_json::json!({ "stored_generation": 1 }))
            } else {
                let snap = stored2.lock().unwrap().clone();
                match snap {
                    Some(s) => (
                        200,
                        serde_json::json!({ "snapshot": s, "server_generation": 1 }),
                    ),
                    None => (
                        200,
                        serde_json::json!({ "snapshot": null, "server_generation": 0 }),
                    ),
                }
            }
        });
        let (_dir, pool) = tmp_pool_with(&["a.example.com"], 1);
        refresher(&url).push_snapshot(&pool).unwrap();
        let before = pool.load().unwrap();
        let outcome = refresher(&url).refresh_once(&pool, 2000).unwrap();
        assert!(matches!(
            outcome,
            RefreshOutcome::NotNewer {
                server_generation: 1
            }
        ));
        let after = pool.load().unwrap();
        assert_eq!(after.generation, before.generation);
    }

    #[test]
    fn carrier_refresh_push_empty_pool_is_noop() {
        let (url, log) = mock_worker(|_| (200, serde_json::json!({})));
        let (_dir, pool) = tmp_pool_with(&[], 0);
        refresher(&url).push_snapshot(&pool).unwrap();
        assert_eq!(log.lock().unwrap().len(), 0);
    }

    #[test]
    fn push_if_changed_skips_when_identity_matches() {
        let (url, log) = mock_worker(|_| (200, serde_json::json!({ "stored_generation": 1 })));
        let (_dir, pool) = tmp_pool_with(&["a.example.com"], 1);
        let r = refresher(&url);
        assert!(matches!(
            r.push_snapshot_if_identity_changed(&pool).unwrap(),
            PushOutcome::Pushed { endpoints: 1 }
        ));
        assert_eq!(log.lock().unwrap().len(), 1);
        // Identical identity → skip; no new flag-5 request.
        assert!(matches!(
            r.push_snapshot_if_identity_changed(&pool).unwrap(),
            PushOutcome::Skipped {
                reason: SkipReason::Unchanged
            }
        ));
        assert_eq!(log.lock().unwrap().len(), 1);
    }

    #[test]
    fn push_if_changed_pushes_when_endpoint_added() {
        let (url, log) = mock_worker(|_| (200, serde_json::json!({ "stored_generation": 1 })));
        let (_dir, pool) = tmp_pool_with(&["a.example.com"], 1);
        let r = refresher(&url);
        r.push_snapshot_if_identity_changed(&pool).unwrap();
        assert_eq!(log.lock().unwrap().len(), 1);
        // Add an endpoint → identity changes → push.
        let mut snap = pool.load().unwrap();
        snap.endpoints.push(ep("b.example.com"));
        snap.sign().unwrap();
        pool.store_atomic(&snap).unwrap();
        assert!(matches!(
            r.push_snapshot_if_identity_changed(&pool).unwrap(),
            PushOutcome::Pushed { endpoints: 2 }
        ));
        assert_eq!(log.lock().unwrap().len(), 2);
    }

    #[test]
    fn push_if_changed_pushes_when_endpoint_removed() {
        let (url, log) = mock_worker(|_| (200, serde_json::json!({ "stored_generation": 1 })));
        let (_dir, pool) = tmp_pool_with(&["a.example.com", "b.example.com"], 1);
        let r = refresher(&url);
        r.push_snapshot_if_identity_changed(&pool).unwrap();
        assert_eq!(log.lock().unwrap().len(), 1);
        let mut snap = pool.load().unwrap();
        snap.endpoints.pop();
        snap.sign().unwrap();
        pool.store_atomic(&snap).unwrap();
        assert!(matches!(
            r.push_snapshot_if_identity_changed(&pool).unwrap(),
            PushOutcome::Pushed { endpoints: 1 }
        ));
        assert_eq!(log.lock().unwrap().len(), 2);
    }

    #[test]
    fn push_if_changed_skips_when_weight_only_changed() {
        let (url, log) = mock_worker(|_| (200, serde_json::json!({ "stored_generation": 1 })));
        let (_dir, pool) = tmp_pool_with(&["a.example.com"], 1);
        let r = refresher(&url);
        r.push_snapshot_if_identity_changed(&pool).unwrap();
        assert_eq!(log.lock().unwrap().len(), 1);
        // Same identity, different weight → skip.
        let mut snap = pool.load().unwrap();
        snap.endpoints[0].weight = 0.1;
        snap.sign().unwrap();
        pool.store_atomic(&snap).unwrap();
        assert!(matches!(
            r.push_snapshot_if_identity_changed(&pool).unwrap(),
            PushOutcome::Skipped {
                reason: SkipReason::Unchanged
            }
        ));
        assert_eq!(log.lock().unwrap().len(), 1);
    }

    #[test]
    fn push_if_changed_empty_pool_skips() {
        let (url, log) = mock_worker(|_| (200, serde_json::json!({})));
        let (_dir, pool) = tmp_pool_with(&[], 0);
        let r = refresher(&url);
        assert!(matches!(
            r.push_snapshot_if_identity_changed(&pool).unwrap(),
            PushOutcome::Skipped {
                reason: SkipReason::Empty
            }
        ));
        assert_eq!(log.lock().unwrap().len(), 0);
    }

    #[test]
    fn push_if_changed_retries_on_failure() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let attempts = std::sync::Arc::new(AtomicUsize::new(0));
        let a2 = attempts.clone();
        let (url, log) = mock_worker(move |_| {
            if a2.fetch_add(1, Ordering::SeqCst) == 0 {
                (500, serde_json::json!({}))
            } else {
                (200, serde_json::json!({ "stored_generation": 1 }))
            }
        });
        let (_dir, pool) = tmp_pool_with(&["a.example.com"], 1);
        let r = refresher(&url);
        // First push fails → Err, and the stored hash file must be untouched.
        assert!(r.push_snapshot_if_identity_changed(&pool).is_err());
        let hash_path = push_hash_path(pool.path());
        assert!(load_push_hash(&hash_path).is_none());
        // Identical identity, second push succeeds.
        assert!(matches!(
            r.push_snapshot_if_identity_changed(&pool).unwrap(),
            PushOutcome::Pushed { endpoints: 1 }
        ));
        assert!(load_push_hash(&hash_path).is_some());
        assert_eq!(log.lock().unwrap().len(), 2);
    }

    #[test]
    fn push_if_changed_worker_url_change_forces_push() {
        let (url, log) = mock_worker(|_| (200, serde_json::json!({ "stored_generation": 1 })));
        let (_dir, pool) = tmp_pool_with(&["a.example.com"], 1);
        let r = refresher(&url);
        r.push_snapshot_if_identity_changed(&pool).unwrap();
        assert_eq!(log.lock().unwrap().len(), 1);
        // Seed the hash file with a different worker_url → treat as never pushed.
        let hash_path = push_hash_path(pool.path());
        write_push_hash(
            &hash_path,
            PushHashRecord {
                schema_version: 1,
                worker_url: "http://other.example".into(),
                hash_hex: "0".repeat(64),
            },
        )
        .unwrap();
        assert!(matches!(
            r.push_snapshot_if_identity_changed(&pool).unwrap(),
            PushOutcome::Pushed { endpoints: 1 }
        ));
        assert_eq!(log.lock().unwrap().len(), 2);
    }

    #[test]
    fn query_self_ping_returns_timestamp() {
        let (url, _log) = mock_worker(|_| (200, serde_json::json!({ "ping_ts": "1700000000000" })));
        let ping = refresher(&url).query_self_ping().unwrap();
        assert_eq!(ping, Some(1700000000000u64));
    }

    #[test]
    fn query_self_ping_none_when_absent() {
        let (url, _log) = mock_worker(|_| (200, serde_json::json!({})));
        let ping = refresher(&url).query_self_ping().unwrap();
        assert_eq!(ping, None);
    }
}
