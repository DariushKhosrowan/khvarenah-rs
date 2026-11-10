//! Durable, versioned, integrity-checked offline carrier substrate.
//!
//! During a total blackout the daemon must answer "which endpoints can I try?"
//! with zero network, zero config reload, zero human. This module provides the
//! routing input the daemon consumes offline after a restart:
//!
//! - [`CarrierSnapshot`] — a versioned, signed (SHA-256) list of carrier
//!   endpoints. Canonical JSON body + integrity hex.
//! - [`CarrierPool`] — atomic on-disk store (`path + ".tmp"` → fsync → rename
//!   → fsync parent), with verified reads and a pure offline [`select`].
//!
//! Storage contract:
//! - JSON body is canonical (field order fixed by [`CarrierSnapshot::canonical_bytes`]).
//! - Read path rejects `schema_version != 1` and any integrity mismatch as `Err`;
//!   it never partially loads.
//! - Writes are atomic: write to `path + ".tmp"`, fsync file, rename to `path`,
//!   fsync parent dir.
//!
//! `select` is a pure function — no network, no probing, no async. Sort key:
//! weight desc → last_probe_ok recency desc → provenance priority
//! (Deployed > Remote > Scanned > Seed).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

/// A single routable carrier endpoint (a fallback tier rung).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CarrierEndpoint {
    pub kind: CarrierKind,
    pub host: String,
    pub port: u16,
    pub sni: Option<String>,
    /// `Some` for `Worker*` kinds (the worker URL).
    pub worker_url: Option<String>,
    /// `Some` for `WorkerData` (the VLESS upstream host:port).
    pub upstream: Option<String>,
    /// Relative preference in `0.0..=1.0`.
    pub weight: f32,
    pub last_probe_ok_unix: Option<u64>,
    pub last_probe_rtt_ms: Option<u32>,
    pub provenance: CarrierProvenance,
}

impl CarrierEndpoint {
    /// Dedup key: kind + host + port + sni.
    fn dedup_key(&self) -> (CarrierKind, String, u16, Option<String>) {
        (self.kind, self.host.clone(), self.port, self.sni.clone())
    }
}

/// Kind of a carrier endpoint.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CarrierKind {
    VpsTunnel,
    WorkerTunnel,
    WorkerData,
}

/// Where an endpoint came from — used only for tie-breaking in `select`
/// and for merge provenance upgrades.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CarrierProvenance {
    Seed,
    Scanned,
    Deployed,
    Remote,
}

impl CarrierProvenance {
    /// Priority for the `select` sort tie-break (higher = preferred).
    fn priority(self) -> u8 {
        match self {
            CarrierProvenance::Deployed => 3,
            CarrierProvenance::Remote => 2,
            CarrierProvenance::Scanned => 1,
            CarrierProvenance::Seed => 0,
        }
    }
}

/// Local failure penalty for a carrier endpoint.
///
/// This is *local-only* runtime bookkeeping — it is explicitly excluded from
/// the snapshot's integrity signature (see [`CarrierSnapshot::canonical_bytes`])
/// because it is not authoritative routing data. Remote merges never carry
/// penalties; the local failure knowledge always wins.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EndpointPenalty {
    /// Consecutive failure count used to compute the exponential backoff.
    pub failure_streak: u8,
    /// Unix seconds at which the cooldown expires; before this the endpoint is
    /// skipped by [`CarrierPool::select_at`].
    pub cooldown_until_unix: u64,
}

/// Current snapshot schema version.
pub const CARRIER_SCHEMA_VERSION: u32 = 1;

/// A signed, versioned snapshot of the carrier pool.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CarrierSnapshot {
    pub schema_version: u32,
    pub created_unix: u64,
    /// Monotonic generation counter.
    pub generation: u64,
    pub endpoints: Vec<CarrierEndpoint>,
    /// Local-only failure penalties, keyed by endpoint identity hex. Excluded
    /// from [`Self::canonical_bytes`] (not authoritative routing data), so it
    /// never affects the integrity signature. `#[serde(default)]` keeps old
    /// schema-1 pools readable.
    #[serde(default)]
    pub penalties: std::collections::HashMap<String, EndpointPenalty>,
    /// Hex SHA-256 of the canonical body (omits `integrity` itself).
    pub integrity: String,
}

impl CarrierSnapshot {
    pub fn new_empty(now_unix: u64) -> Self {
        Self {
            schema_version: CARRIER_SCHEMA_VERSION,
            created_unix: now_unix,
            generation: 0,
            endpoints: Vec::new(),
            penalties: std::collections::HashMap::new(),
            integrity: String::new(),
        }
    }

    /// Canonical body bytes: JSON of every field EXCEPT `integrity`, with a
    /// stable field order (serde's `Serialize` on the struct is stable for a
    /// fixed struct definition).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CarrierPoolError> {
        // Build the canonical body by serializing a struct that mirrors this
        // one without the integrity field, in fixed order.
        #[derive(Serialize)]
        struct Canon<'a> {
            schema_version: u32,
            created_unix: u64,
            generation: u64,
            endpoints: &'a [CarrierEndpoint],
        }
        let canon = Canon {
            schema_version: self.schema_version,
            created_unix: self.created_unix,
            generation: self.generation,
            endpoints: &self.endpoints,
        };
        serde_json::to_vec(&canon).map_err(CarrierPoolError::Serde)
    }

    /// Compute and set the integrity field.
    pub fn sign(&mut self) -> Result<(), CarrierPoolError> {
        let body = self.canonical_bytes()?;
        self.integrity = hex_sha256(&body);
        Ok(())
    }

    /// Recompute integrity over the canonical body and compare.
    pub fn verify(&self) -> Result<(), CarrierPoolError> {
        if self.schema_version != CARRIER_SCHEMA_VERSION {
            return Err(CarrierPoolError::Schema(self.schema_version));
        }
        let body = self.canonical_bytes()?;
        let expect = hex_sha256(&body);
        if self.integrity != expect {
            return Err(CarrierPoolError::Integrity(
                "integrity mismatch: snapshot tampered or malformed".into(),
            ));
        }
        Ok(())
    }
}

/// Result of a [`CarrierPool::merge`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MergeReport {
    pub added: usize,
    pub updated: usize,
    pub kept: usize,
    pub rejected: usize,
}

/// Errors from the carrier pool.
#[derive(Debug)]
pub enum CarrierPoolError {
    Io(std::io::Error),
    Integrity(String),
    Schema(u32),
    Serde(serde_json::Error),
    NotFound,
}

impl std::fmt::Display for CarrierPoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CarrierPoolError::Io(e) => write!(f, "io: {e}"),
            CarrierPoolError::Integrity(s) => write!(f, "integrity: {s}"),
            CarrierPoolError::Schema(v) => write!(f, "unsupported schema version: {v}"),
            CarrierPoolError::Serde(e) => write!(f, "serde: {e}"),
            CarrierPoolError::NotFound => write!(f, "carrier pool not found"),
        }
    }
}

impl std::error::Error for CarrierPoolError {}

/// Atomic, integrity-checked on-disk carrier pool.
///
/// The in-memory snapshot is guarded by an `RwLock`; `select` is a pure read.
pub struct CarrierPool {
    path: PathBuf,
    inner: Arc<RwLock<CarrierSnapshot>>,
}

impl CarrierPool {
    /// Open (or lazily initialize) a pool at `path`.
    ///
    /// Does not require the file to exist — [`Self::load`] returns
    /// `NotFound` until the first `store_atomic`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CarrierPoolError> {
        let path = path.as_ref().to_path_buf();
        let snap = match fs::read(&path) {
            Ok(bytes) => {
                let snap: CarrierSnapshot =
                    serde_json::from_slice(&bytes).map_err(CarrierPoolError::Serde)?;
                snap.verify()?;
                snap
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => CarrierSnapshot::new_empty(0),
            Err(e) => return Err(CarrierPoolError::Io(e)),
        };
        Ok(Self {
            path,
            inner: Arc::new(RwLock::new(snap)),
        })
    }

    /// Read the current snapshot (verifies integrity).
    pub fn load(&self) -> Result<CarrierSnapshot, CarrierPoolError> {
        let guard = self.inner.read().map_err(|_| {
            CarrierPoolError::Integrity("carrier pool lock poisoned".into())
        })?;
        Ok(guard.clone())
    }

    /// Atomically persist `snap`. Writes to `path + ".tmp"`, fsyncs the file,
    /// renames over `path`, then fsyncs the parent directory.
    pub fn store_atomic(&self, snap: &CarrierSnapshot) -> Result<(), CarrierPoolError> {
        snap.verify()?;
        let tmp = self.path.with_extension("tmp");
        {
            let mut f = fs::File::create(&tmp).map_err(CarrierPoolError::Io)?;
            let bytes = serde_json::to_vec(snap).map_err(CarrierPoolError::Serde)?;
            f.write_all(&bytes).map_err(CarrierPoolError::Io)?;
            f.sync_all().map_err(CarrierPoolError::Io)?;
        }
        fs::rename(&tmp, &self.path).map_err(CarrierPoolError::Io)?;
        // fsync parent dir (Unix).
        if let Some(parent) = self.path.parent() {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        *self
            .inner
            .write()
            .map_err(|_| CarrierPoolError::Integrity("carrier pool lock poisoned".into()))? =
            snap.clone();
        Ok(())
    }

    /// Merge `incoming` into the pool.
    ///
    /// Dedups by (kind, host, port, sni): existing endpoints are updated in
    /// place (their provenance is upgraded to `src` when `src` outranks it),
    /// new endpoints are appended. Returns a [`MergeReport`].
    pub fn merge(
        &self,
        incoming: CarrierSnapshot,
        src: CarrierProvenance,
        now_unix: u64,
    ) -> Result<MergeReport, CarrierPoolError> {
        incoming.verify()?;
        let mut guard = self
            .inner
            .write()
            .map_err(|_| CarrierPoolError::Integrity("carrier pool lock poisoned".into()))?;
        let mut report = MergeReport {
            added: 0,
            updated: 0,
            kept: 0,
            rejected: 0,
        };
        let mut by_key: std::collections::HashMap<_, usize> = std::collections::HashMap::new();
        for (i, e) in guard.endpoints.iter().enumerate() {
            by_key.insert(e.dedup_key(), i);
        }
        let mut changed = false;
        for ep in incoming.endpoints {
            if ep.weight < 0.0 || ep.weight > 1.0 {
                report.rejected += 1;
                continue;
            }
            match by_key.get(&ep.dedup_key()) {
                Some(&idx) => {
                    let cur = &mut guard.endpoints[idx];
                    let cur_prio = cur.provenance.priority();
                    let src_prio = src.priority();
                    let mut row_changed = false;
                    if src_prio > cur_prio {
                        cur.provenance = src;
                        row_changed = true;
                    }
                    if ep.weight > cur.weight {
                        cur.weight = ep.weight;
                        row_changed = true;
                    }
                    if let Some(t) = ep.last_probe_ok_unix {
                        if cur.last_probe_ok_unix.is_none_or(|c| t > c) {
                            cur.last_probe_ok_unix = Some(t);
                            row_changed = true;
                        }
                    }
                    if row_changed {
                        report.updated += 1;
                        changed = true;
                    } else {
                        report.kept += 1;
                    }
                }
                None => {
                    let mut ep = ep;
                    ep.provenance = src;
                    by_key.insert(ep.dedup_key(), guard.endpoints.len());
                    guard.endpoints.push(ep);
                    report.added += 1;
                    changed = true;
                }
            }
        }
        // No-op merge (byte-identical snapshot): don't bump generation, don't
        // rewrite the pool file — the content is already on disk.
        if !changed {
            return Ok(report);
        }
        guard.generation = guard.generation.max(incoming.generation);
        guard.created_unix = now_unix;
        report.kept = guard.endpoints.len() - report.added - report.updated - report.rejected;
        guard.sign()?;
        let snap = guard.clone();
        drop(guard);
        self.store_atomic(&snap)?;
        Ok(report)
    }

    /// The on-disk path of this pool.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Stable 32-byte hash of the endpoint identity set: sorted
    /// (kind, host, port, sni, worker_url) tuples, SHA-256. Excludes weight,
    /// last_probe_ok_unix, last_probe_rtt_ms, and provenance, so probe
    /// telemetry drift never changes the hash. Order-independent (sorts
    /// before hashing) — merging the same endpoints in a different order
    /// yields the same hash. This is what the worker relay uses to decide
    /// whether a fresh push is warranted.
    pub fn identity_hash(&self) -> Result<[u8; 32], CarrierPoolError> {
        let guard = self
            .inner
            .read()
            .map_err(|_| CarrierPoolError::Integrity("carrier pool lock poisoned".into()))?;
        let mut tuples: Vec<(CarrierKind, &str, u16, Option<&str>, Option<&str>)> = guard
            .endpoints
            .iter()
            .map(|e| {
                (
                    e.kind,
                    e.host.as_str(),
                    e.port,
                    e.sni.as_deref(),
                    e.worker_url.as_deref(),
                )
            })
            .collect();
        tuples.sort();
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        for (kind, host, port, sni, wurl) in &tuples {
            h.update(format!("{kind:?}|{host}|{port}|{sni:?}|{wurl:?}").as_bytes());
        }
        Ok(h.finalize().into())
    }

    /// Pure offline selection. No network, no probing, no async.
    ///
    /// Sort: weight desc → last_probe_ok recency desc → provenance priority
    /// (Deployed > Remote > Scanned > Seed). Returns up to `n` endpoints of
    /// kind `kind`. Empty pool → empty vec.
    pub fn select(
        &self,
        kind: CarrierKind,
        n: usize,
    ) -> Result<Vec<CarrierEndpoint>, CarrierPoolError> {
        let guard = self
            .inner
            .read()
            .map_err(|_| CarrierPoolError::Integrity("carrier pool lock poisoned".into()))?;
        let mut v: Vec<CarrierEndpoint> = guard
            .endpoints
            .iter()
            .filter(|e| e.kind == kind)
            .cloned()
            .collect();
        v.sort_by(|a, b| {
            b.weight
                .partial_cmp(&a.weight)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(
                    b.last_probe_ok_unix
                        .unwrap_or(0)
                        .cmp(&a.last_probe_ok_unix.unwrap_or(0)),
                )
                .then(b.provenance.priority().cmp(&a.provenance.priority()))
        });
        v.truncate(n);
        Ok(v)
    }

    /// Compute the stable local identity hash of an endpoint: kind + host +
    /// port + sni + worker_url. Used as the penalty map key so penalties
    /// survive snapshot re-merges (the key is stable under weight/probe drift).
    pub fn endpoint_id_hash(ep: &CarrierEndpoint) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(
            format!(
                "{:?}|{}|{}|{:?}|{:?}",
                ep.kind, ep.host, ep.port, ep.sni, ep.worker_url
            )
            .as_bytes(),
        );
        h.finalize().into()
    }

    fn endpoint_id_hex(ep: &CarrierEndpoint) -> String {
        hex_sha256(&Self::endpoint_id_hash(ep))
    }

    /// Record a failure for `ep`. Bumps the streak, sets a cooldown expiry
    /// computed from [`backoff_secs`], and persists the pool. Returns the
    /// computed backoff (seconds) for the caller's logging.
    pub fn record_failure(
        &self,
        ep: &CarrierEndpoint,
        now_unix: u64,
    ) -> Result<u64, CarrierPoolError> {
        let id = Self::endpoint_id_hex(ep);
        let mut guard = self
            .inner
            .write()
            .map_err(|_| CarrierPoolError::Integrity("carrier pool lock poisoned".into()))?;
        let mut p = guard.penalties.get(&id).copied().unwrap_or_default();
        p.failure_streak = p.failure_streak.saturating_add(1);
        let backoff = backoff_secs(p.failure_streak);
        p.cooldown_until_unix = now_unix.saturating_add(backoff);
        guard.penalties.insert(id, p);
        let snap = guard.clone();
        drop(guard);
        self.store_atomic(&snap)?;
        Ok(backoff)
    }

    /// Record a success for `ep`: clears any penalty (streak + cooldown).
    pub fn record_success(
        &self,
        ep: &CarrierEndpoint,
    ) -> Result<(), CarrierPoolError> {
        let id = Self::endpoint_id_hex(ep);
        let mut guard = self
            .inner
            .write()
            .map_err(|_| CarrierPoolError::Integrity("carrier pool lock poisoned".into()))?;
        if guard.penalties.remove(&id).is_some() {
            let snap = guard.clone();
            drop(guard);
            self.store_atomic(&snap)?;
        }
        Ok(())
    }

    /// Selection identical to [`Self::select`] but excludes endpoints currently
    /// in cooldown. If every matching endpoint is in cooldown, falls back to
    /// including them (sorted) so the caller never sees an empty candidate
    /// list while any endpoint of `kind` exists.
    pub fn select_at(
        &self,
        kind: CarrierKind,
        n: usize,
        now_unix: u64,
    ) -> Result<Vec<CarrierEndpoint>, CarrierPoolError> {
        let guard = self
            .inner
            .read()
            .map_err(|_| CarrierPoolError::Integrity("carrier pool lock poisoned".into()))?;
        let mut avail: Vec<CarrierEndpoint> = Vec::new();
        let mut cooling: Vec<CarrierEndpoint> = Vec::new();
        for e in guard.endpoints.iter().filter(|e| e.kind == kind) {
            let id = Self::endpoint_id_hex(e);
            let in_cooldown = guard
                .penalties
                .get(&id)
                .is_some_and(|p| p.cooldown_until_unix > now_unix);
            if in_cooldown {
                cooling.push(e.clone());
            } else {
                avail.push(e.clone());
            }
        }
        let mut v = if avail.is_empty() { cooling } else { avail };
        if v.is_empty() {
            return Ok(v);
        }
        v.sort_by(|a, b| {
            b.weight
                .partial_cmp(&a.weight)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(
                    b.last_probe_ok_unix
                        .unwrap_or(0)
                        .cmp(&a.last_probe_ok_unix.unwrap_or(0)),
                )
                .then(b.provenance.priority().cmp(&a.provenance.priority()))
        });
        v.truncate(n);
        Ok(v)
    }
}

/// Resolve the effective carrier-pool path for a profile.
///
/// Uses `cfg.carrier_pool_path` if set (absolute or relative to the profile
/// store dir), else `<mem_dir>/carrier_pool.json`.
pub fn profile_carrier_pool_path(cfg: &crate::store::profiles::ProfileConfig) -> PathBuf {
    if let Some(p) = &cfg.carrier_pool_path {
        if p.is_absolute() {
            return p.clone();
        }
        return crate::store::mem_dir().join(p);
    }
    crate::store::mem_dir().join("carrier_pool.json")
}

/// Open the profile's carrier pool (see [`profile_carrier_pool_path`]).
pub fn open_profile_pool(
    cfg: &crate::store::profiles::ProfileConfig,
) -> Result<CarrierPool, CarrierPoolError> {
    CarrierPool::open(profile_carrier_pool_path(cfg))
}

/// Helper: exponential backoff seconds for a failure streak.
/// `min(60 * 2^streak, 3600)` — 60s, 120s, 240s, … capped at 1 hour.
pub fn backoff_secs(streak: u8) -> u64 {
    let exp = 60u64.saturating_mul(1u64 << streak.min(6));
    exp.min(3600)
}

fn hex_sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_pool() -> (tempfile::TempDir, CarrierPool) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("carrier_pool.json");
        let pool = CarrierPool::open(&path).unwrap();
        (dir, pool)
    }

    fn ep(kind: CarrierKind, host: &str, port: u16, weight: f32) -> CarrierEndpoint {
        CarrierEndpoint {
            kind,
            host: host.to_string(),
            port,
            sni: None,
            worker_url: if matches!(kind, CarrierKind::WorkerTunnel | CarrierKind::WorkerData) {
                Some(format!("https://{host}"))
            } else {
                None
            },
            upstream: if matches!(kind, CarrierKind::WorkerData) {
                Some(format!("{host}:{port}"))
            } else {
                None
            },
            weight,
            last_probe_ok_unix: None,
            last_probe_rtt_ms: None,
            provenance: CarrierProvenance::Seed,
        }
    }

    #[test]
    fn carrier_snapshot_roundtrip() {
        let mut snap = CarrierSnapshot::new_empty(1000);
        snap.endpoints.push(ep(CarrierKind::WorkerTunnel, "w1.example.com", 443, 0.9));
        snap.sign().unwrap();
        assert!(snap.verify().is_ok());
        // Re-serialize → parse → verify still ok.
        let bytes = serde_json::to_vec(&snap).unwrap();
        let back: CarrierSnapshot = serde_json::from_slice(&bytes).unwrap();
        assert!(back.verify().is_ok());
        assert_eq!(back.integrity, snap.integrity);
    }

    #[test]
    fn carrier_snapshot_tamper_detected() {
        let mut snap = CarrierSnapshot::new_empty(1000);
        snap.endpoints.push(ep(CarrierKind::WorkerData, "w.example.com", 443, 0.8));
        snap.sign().unwrap();
        // Tamper: mutate the host string (safe, no unsafe).
        snap.endpoints[0].host = "X.example.com".to_string();
        assert!(matches!(snap.verify(), Err(CarrierPoolError::Integrity(_))));
    }

    #[test]
    fn carrier_pool_atomic_store() {
        let (_dir, pool) = tmp_pool();
        let mut snap = CarrierSnapshot::new_empty(1000);
        snap.endpoints.push(ep(CarrierKind::WorkerTunnel, "a.example.com", 443, 0.5));
        snap.sign().unwrap();
        pool.store_atomic(&snap).unwrap();
        let loaded = pool.load().unwrap();
        assert_eq!(loaded.endpoints.len(), 1);
        assert!(loaded.verify().is_ok());
        // A fresh open from the same file sees it.
        let re = CarrierPool::open(pool.path.clone()).unwrap();
        assert_eq!(re.load().unwrap().endpoints.len(), 1);
    }

    #[test]
    fn carrier_pool_merge_dedups_by_kind_host_port_sni() {
        let (_dir, pool) = tmp_pool();
        let mut snap = CarrierSnapshot::new_empty(1000);
        snap.endpoints.push(ep(CarrierKind::WorkerTunnel, "w.example.com", 443, 0.5));
        snap.sign().unwrap();
        pool.store_atomic(&snap).unwrap();

        let mut incoming = CarrierSnapshot::new_empty(2000);
        incoming.generation = 1;
        incoming.endpoints.push(ep(CarrierKind::WorkerTunnel, "w.example.com", 443, 0.7));
        incoming.sign().unwrap();
        let report = pool.merge(incoming, CarrierProvenance::Remote, 2000).unwrap();
        assert_eq!(report.added, 0);
        assert_eq!(report.updated, 1);
        let loaded = pool.load().unwrap();
        assert_eq!(loaded.endpoints.len(), 1);
        assert_eq!(loaded.endpoints[0].provenance, CarrierProvenance::Remote);
        assert_eq!(loaded.endpoints[0].weight, 0.7);
    }

    #[test]
    fn carrier_pool_merge_idempotent_noop_does_not_bump_generation() {
        let (_dir, pool) = tmp_pool();
        let mut snap = CarrierSnapshot::new_empty(1000);
        let mut e = ep(CarrierKind::WorkerTunnel, "w.example.com", 443, 0.5);
        e.provenance = CarrierProvenance::Remote; // already remote (from a prior refresh)
        snap.endpoints.push(e);
        snap.generation = 5;
        snap.sign().unwrap();
        pool.store_atomic(&snap).unwrap();

        // Merge a byte-identical snapshot (same generation, same endpoints,
        // same provenance) → true no-op.
        let report = pool
            .merge(snap.clone(), CarrierProvenance::Remote, 1000)
            .unwrap();
        assert_eq!(report.added, 0);
        assert_eq!(report.updated, 0);
        assert_eq!(report.kept, 1);
        // Generation unchanged.
        assert_eq!(pool.load().unwrap().generation, 5);
    }

    #[test]
    fn carrier_pool_select_offline_pure() {
        let (_dir, pool) = tmp_pool();
        let mut snap = CarrierSnapshot::new_empty(1000);
        snap.endpoints.push(ep(CarrierKind::WorkerData, "d1.example.com", 443, 0.3));
        snap.endpoints.push(ep(CarrierKind::WorkerData, "d2.example.com", 443, 0.9));
        snap.endpoints.push(ep(CarrierKind::WorkerData, "d3.example.com", 443, 0.6));
        snap.endpoints.push(ep(CarrierKind::WorkerTunnel, "c1.example.com", 443, 1.0));
        snap.sign().unwrap();
        pool.store_atomic(&snap).unwrap();

        let sel = pool.select(CarrierKind::WorkerData, 8).unwrap();
        assert_eq!(sel.len(), 3);
        // weight desc
        assert_eq!(sel[0].host, "d2.example.com");
        assert_eq!(sel[2].host, "d1.example.com");
        // kind filter excludes WorkerTunnel
        let tun = pool.select(CarrierKind::WorkerTunnel, 8).unwrap();
        assert_eq!(tun.len(), 1);
    }

    #[test]
    fn carrier_pool_rejects_schema_v2() {
        let _dir = tempfile::tempdir().unwrap();
        let path = _dir.path().join("bad.json");
        // Hand-craft a v2 snapshot.
        let snap = CarrierSnapshot {
            schema_version: 2,
            created_unix: 1,
            generation: 0,
            endpoints: vec![],
            penalties: std::collections::HashMap::new(),
            integrity: String::new(),
        };
        fs::write(&path, serde_json::to_vec(&snap).unwrap()).unwrap();
        // `open` verifies on read → must reject schema v2.
        assert!(matches!(CarrierPool::open(&path), Err(CarrierPoolError::Schema(2))));
    }

    fn identity_of(pool: &CarrierPool) -> [u8; 32] {
        pool.identity_hash().unwrap()
    }

    #[test]
    fn identity_hash_ignores_weight_and_probe_times() {
        // Same endpoints, different weights / probe times → same identity hash.
        let (_d1, p1) = tmp_pool();
        let (_d2, p2) = tmp_pool();
        let mut s1 = CarrierSnapshot::new_empty(1000);
        let mut s2 = CarrierSnapshot::new_empty(1000);
        s1.endpoints.push(ep(CarrierKind::WorkerData, "d.example.com", 443, 0.1));
        s1.endpoints[0].last_probe_ok_unix = Some(100);
        s1.endpoints[0].last_probe_rtt_ms = Some(5);
        s2.endpoints.push(ep(CarrierKind::WorkerData, "d.example.com", 443, 0.9));
        s2.endpoints[0].last_probe_ok_unix = Some(500);
        s2.endpoints[0].last_probe_rtt_ms = Some(200);
        s1.sign().unwrap();
        s2.sign().unwrap();
        p1.store_atomic(&s1).unwrap();
        p2.store_atomic(&s2).unwrap();
        assert_eq!(identity_of(&p1), identity_of(&p2));
    }

    #[test]
    fn identity_hash_is_order_independent() {
        // Same endpoint set in different order → same identity hash.
        let (_d1, p1) = tmp_pool();
        let (_d2, p2) = tmp_pool();
        let mut s1 = CarrierSnapshot::new_empty(1000);
        let mut s2 = CarrierSnapshot::new_empty(1000);
        for h in ["a.example.com", "b.example.com", "c.example.com"] {
            s1.endpoints.push(ep(CarrierKind::WorkerData, h, 443, 0.5));
        }
        for h in ["c.example.com", "a.example.com", "b.example.com"] {
            s2.endpoints.push(ep(CarrierKind::WorkerData, h, 443, 0.5));
        }
        s1.sign().unwrap();
        s2.sign().unwrap();
        p1.store_atomic(&s1).unwrap();
        p2.store_atomic(&s2).unwrap();
        assert_eq!(identity_of(&p1), identity_of(&p2));
    }

    #[test]
    fn identity_hash_changes_on_host_change() {
        let (_d1, p1) = tmp_pool();
        let (_d2, p2) = tmp_pool();
        let mut s1 = CarrierSnapshot::new_empty(1000);
        let mut s2 = CarrierSnapshot::new_empty(1000);
        s1.endpoints.push(ep(CarrierKind::WorkerData, "a.example.com", 443, 0.5));
        s2.endpoints.push(ep(CarrierKind::WorkerData, "b.example.com", 443, 0.5));
        s1.sign().unwrap();
        s2.sign().unwrap();
        p1.store_atomic(&s1).unwrap();
        p2.store_atomic(&s2).unwrap();
        assert_ne!(identity_of(&p1), identity_of(&p2));
    }

    #[test]
    fn backoff_secs_exponential_and_capped() {
        assert_eq!(backoff_secs(0), 60);
        assert_eq!(backoff_secs(1), 120);
        assert_eq!(backoff_secs(2), 240);
        assert_eq!(backoff_secs(6), 3600);
        assert_eq!(backoff_secs(200), 3600); // capped
    }

    #[test]
    fn record_failure_increments_streak_and_sets_cooldown() {
        let (_dir, pool) = tmp_pool();
        let mut snap = CarrierSnapshot::new_empty(1000);
        snap.endpoints.push(ep(CarrierKind::WorkerData, "a.example.com", 443, 0.9));
        snap.sign().unwrap();
        pool.store_atomic(&snap).unwrap();
        let e = &snap.endpoints[0];
        // First failure → streak 1 → backoff 60*2^1 = 120s.
        let b = pool.record_failure(e, 1000).unwrap();
        assert_eq!(b, 120);
        let loaded = pool.load().unwrap();
        let id = CarrierPool::endpoint_id_hex(e);
        let p = loaded.penalties.get(&id).unwrap();
        assert_eq!(p.failure_streak, 1);
        assert_eq!(p.cooldown_until_unix, 1120);
        // second failure → streak 2 → backoff 60*2^2 = 240s.
        let b2 = pool.record_failure(e, 1100).unwrap();
        assert_eq!(b2, 240);
    }

    #[test]
    fn record_success_clears_penalty() {
        let (_dir, pool) = tmp_pool();
        let mut snap = CarrierSnapshot::new_empty(1000);
        snap.endpoints.push(ep(CarrierKind::WorkerData, "a.example.com", 443, 0.9));
        snap.sign().unwrap();
        pool.store_atomic(&snap).unwrap();
        let e = &snap.endpoints[0];
        pool.record_failure(e, 1000).unwrap();
        assert!(!pool.load().unwrap().penalties.is_empty());
        pool.record_success(e).unwrap();
        assert!(pool.load().unwrap().penalties.is_empty());
    }

    #[test]
    fn select_at_excludes_cooldowned_endpoint() {
        let (_dir, pool) = tmp_pool();
        let mut snap = CarrierSnapshot::new_empty(1000);
        snap.endpoints.push(ep(CarrierKind::WorkerData, "a.example.com", 443, 0.9));
        snap.endpoints.push(ep(CarrierKind::WorkerData, "b.example.com", 443, 0.5));
        snap.sign().unwrap();
        pool.store_atomic(&snap).unwrap();
        // cooldown a
        pool.record_failure(&snap.endpoints[0], 1000).unwrap();
        let sel = pool.select_at(CarrierKind::WorkerData, 8, 1001).unwrap();
        assert_eq!(sel.len(), 1);
        assert_eq!(sel[0].host, "b.example.com");
    }

    #[test]
    fn select_at_reincludes_after_cooldown_expires() {
        let (_dir, pool) = tmp_pool();
        let mut snap = CarrierSnapshot::new_empty(1000);
        snap.endpoints.push(ep(CarrierKind::WorkerData, "a.example.com", 443, 0.9));
        snap.endpoints.push(ep(CarrierKind::WorkerData, "b.example.com", 443, 0.5));
        snap.sign().unwrap();
        pool.store_atomic(&snap).unwrap();
        pool.record_failure(&snap.endpoints[0], 1000).unwrap();
        // cooldown (from streak 1) expires at 1120; at now=1121 it's included again
        let sel = pool.select_at(CarrierKind::WorkerData, 8, 1121).unwrap();
        assert_eq!(sel.len(), 2);
        assert_eq!(sel[0].host, "a.example.com"); // weight desc
    }

    #[test]
    fn select_at_never_empty_when_all_cooldowned() {
        let (_dir, pool) = tmp_pool();
        let mut snap = CarrierSnapshot::new_empty(1000);
        snap.endpoints.push(ep(CarrierKind::WorkerData, "a.example.com", 443, 0.9));
        snap.endpoints.push(ep(CarrierKind::WorkerData, "b.example.com", 443, 0.5));
        snap.sign().unwrap();
        pool.store_atomic(&snap).unwrap();
        pool.record_failure(&snap.endpoints[0], 1000).unwrap();
        pool.record_failure(&snap.endpoints[1], 1000).unwrap();
        let sel = pool.select_at(CarrierKind::WorkerData, 8, 1001).unwrap();
        assert_eq!(sel.len(), 2); // fallback includes cooling ones
    }

    #[test]
    fn merge_ignores_remote_penalties_preserves_local() {
        let (_dir, pool) = tmp_pool();
        let mut snap = CarrierSnapshot::new_empty(1000);
        snap.endpoints.push(ep(CarrierKind::WorkerData, "a.example.com", 443, 0.9));
        snap.sign().unwrap();
        pool.store_atomic(&snap).unwrap();
        // local failure recorded
        pool.record_failure(&snap.endpoints[0], 1000).unwrap();
        // remote merge with the same endpoint (fresh, no penalties)
        let mut incoming = CarrierSnapshot::new_empty(2000);
        incoming.generation = 1;
        incoming.endpoints.push(ep(CarrierKind::WorkerData, "a.example.com", 443, 0.9));
        incoming.sign().unwrap();
        pool.merge(incoming, CarrierProvenance::Remote, 2000).unwrap();
        // local penalty survives (remote cannot clear it)
        let loaded = pool.load().unwrap();
        let id = CarrierPool::endpoint_id_hex(&snap.endpoints[0]);
        assert!(loaded.penalties.contains_key(&id));
    }
}
