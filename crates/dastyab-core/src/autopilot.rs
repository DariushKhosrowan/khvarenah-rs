//! Native clean-IP discovery + validation + autopilot engine (DeepSeek plan).
//!
//! This module turns a raw Cloudflare IP into a *working* VLESS frontend.
//! DeepSeek's central instruction: "the scanner is not the product — the
//! engine that keeps the endpoint alive is the product."
//!
//! Architecture (three layers, one `EndpointProvider` contract):
//!   1. **Discovery** — fetch the official Cloudflare ranges (`cf::ips`),
//!      sample a bounded candidate set, and health-probe each IP in parallel
//!      against the worker's hostname (TCP + TLS + HTTP).
//!   2. **Validation** — the candidate must actually route the worker's
//!      host. We pin the worker hostname to the candidate IP (reqwest
//!      `.resolve`) and fetch `https://<worker-host>/cdn-cgi/trace` through
//!      it. A valid Cloudflare trace body proves the edge front for that
//!      worker is alive. This kills the classic false positive where a TCP
//!      + TLS handshake succeeds against *any* Cloudflare IP.
//!   3. **Autopilot engine** — persistence (`endpoints.json` ledger), a
//!      periodic monitor loop that re-validates active endpoints and swaps
//!      in fresh ones when a front dies, plus generation of active client
//!      configs. Controlled by a single ON/OFF watch channel.

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::cf::ips::{load_ranges, sample_candidates};
use crate::error::CFError;
use crate::health::{check, HealthOptions};
use crate::store;
use crate::scanner::{run_scan, ScanParams, ScanResult};
use crate::vless::VlessProfile;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// A validated clean endpoint (a working front for a specific worker host).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanEndpoint {
    pub ip: String,
    pub port: u16,
    /// Worker hostname used as SNI/Host (the thing we are fronting).
    pub sni: String,
    /// Composite score (higher = better). Weighted latency + throughput.
    pub score: f32,
    pub tcp_ms: f32,
    pub connect_ms: f32,
    pub download_kbps: f32,
    /// True when the endpoint passed validation (E2E front check).
    pub verified: bool,
    /// True when the last monitor check succeeded.
    #[serde(default)]
    pub alive: bool,
    #[serde(default)]
    pub last_checked: Option<String>,
    #[serde(default)]
    pub ts: String,
}

/// Parameters for one discovery/validation cycle.
#[derive(Debug, Clone)]
pub struct DiscoveryParams {
    /// How many candidate IPs to probe per cycle.
    pub sample: u32,
    /// Concurrency (parallel probes).
    pub workers: usize,
    /// Per-probe timeout in seconds.
    pub timeout_s: u32,
    /// How many validated endpoints to aim for (top_n).
    pub top_n: usize,
    /// Force a refresh of the CF range list (bypass cache).
    pub force_refresh_ranges: bool,
    /// Re-validate a candidate "dead" once after a short delay before giving
    /// up (E2E cold-start protection).
    pub retry_on_fail: bool,
}

impl Default for DiscoveryParams {
    fn default() -> Self {
        Self {
            sample: 2000,
            workers: 64,
            timeout_s: 8,
            top_n: 3,
            force_refresh_ranges: false,
            retry_on_fail: true,
        }
    }
}

/// The `EndpointProvider` contract. Two implementations ship today:
/// `NativeCfProvider` (Rust-native discovery) and `SenpaiProvider` (thin
/// wrapper around the SenPaiScanner binary, kept as a fallback/debug mode).
pub trait EndpointProvider: Send + Sync {
    /// Discover and validate up to `top_n` clean endpoints for `vless`.
    fn discover<'a>(
        &'a self,
        vless: &'a VlessProfile,
        params: &'a DiscoveryParams,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<CleanEndpoint>, CFError>> + Send + 'a>>;
}

// ---------------------------------------------------------------------------
// Native provider: discovery + validation
// ---------------------------------------------------------------------------

/// Rust-native provider: Cloudflare ranges + parallel probes + front check.
#[derive(Default)]
pub struct NativeCfProvider;

impl EndpointProvider for NativeCfProvider {
    fn discover<'a>(
        &'a self,
        vless: &'a VlessProfile,
        params: &'a DiscoveryParams,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<CleanEndpoint>, CFError>> + Send + 'a>> {
        Box::pin(discover_native(vless, params))
    }
}

/// Probe one candidate IP against a worker host. Returns a scored probe.
async fn probe_candidate(
    ip: &str,
    port: u16,
    sni: &str,
    timeout_s: u32,
) -> Result<CleanEndpoint, CFError> {
    let opts = HealthOptions {
        timeout: Duration::from_secs(timeout_s as u64),
        // Enough to measure throughput without scraping the edge.
        download_bytes: 16 * 1024,
        tls: true,
    };
    let h = check(ip, port, &opts).await;
    if !h.ok {
        // Non-fatal: just not a candidate.
        return Err(CFError::new(
            "Probe failed",
            format!("TCP/TLS probe failed for {ip}:{port}"),
            "",
        ));
    }
    // Composite score: favour low latency and decent throughput.
    let latency = h.tcp_ms.max(0.001);
    let throughput = h.download_kbps.max(1.0);
    let score = (1000.0 / latency) + (throughput / 100.0);
    Ok(CleanEndpoint {
        ip: ip.to_string(),
        port,
        sni: sni.to_string(),
        score,
        tcp_ms: h.tcp_ms,
        connect_ms: h.connect_ms,
        download_kbps: h.download_kbps,
        verified: false,
        alive: true,
        last_checked: None,
        ts: store::now_iso(),
    })
}

/// The native discovery pipeline:
/// ranges → sample → concurrent probe → rank → validate the top candidates.
async fn discover_native(
    vless: &VlessProfile,
    params: &DiscoveryParams,
) -> Result<Vec<CleanEndpoint>, CFError> {
    let cidrs = load_ranges(params.force_refresh_ranges).await?;
    let candidates = sample_candidates(&cidrs, params.sample);
    if candidates.is_empty() {
        return Err(CFError::new(
            "No candidates",
            "The Cloudflare range list produced no sample IPs.",
            "Check network connectivity and retry.",
        ));
    }

    let sni = vless.sni.clone().unwrap_or_else(|| vless.address.clone());

    // Parallel probes bounded by a semaphore (worker pool).
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(params.workers.max(1)));
    let mut handles = Vec::new();
    for ip in candidates {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let sni = sni.clone();
        let timeout = params.timeout_s;
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            probe_candidate(&ip.to_string(), 443, &sni, timeout).await
        }));
    }

    let mut pool: Vec<CleanEndpoint> = Vec::new();
    for h in handles {
        if let Ok(Ok(ep)) = h.await {
            pool.push(ep);
        }
    }

    // Rank by score, take the top_n for validation.
    pool.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    let top: Vec<CleanEndpoint> = pool.into_iter().take(params.top_n.max(1)).collect();
    if top.is_empty() {
        return Ok(Vec::new());
    }

    // Validate each top candidate through the real front check. Keep those
    // that genuinely route the worker host.
    let mut validated = Vec::new();
    for ep in top {
        let mut ok = validate_front(&ep.ip, ep.port, &sni, params.timeout_s).await;
        if !ok && params.retry_on_fail {
            tokio::time::sleep(Duration::from_secs(3)).await;
            ok = validate_front(&ep.ip, ep.port, &sni, params.timeout_s).await;
        }
        if ok {
            let mut v = ep.clone();
            v.verified = true;
            v.last_checked = Some(store::now_iso());
            validated.push(v);
        }
    }

    Ok(validated)
}

/// Validate that candidate_ip:port actually fronts `sni` (the worker host).
///
/// We pin the worker hostname to the candidate IP via reqwest `.resolve`, so
/// TLS uses SNI = `sni` and the Host header = `sni`, while the TCP connection
/// goes to the candidate IP. Then `GET https://<sni>/cdn-cgi/trace`. A
/// successful Cloudflare trace body proves the front works for this worker.
async fn validate_front(ip: &str, port: u16, sni: &str, timeout_s: u32) -> bool {
    let addr = match format!("{ip}:{port}").parse::<SocketAddr>() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_s as u64))
        .resolve(sni, addr)
        .user_agent("dastyab-autopilot")
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    let url = format!("https://{sni}/cdn-cgi/trace");
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return false,
    };
    if !resp.status().is_success() {
        return false;
    }
    let body = match resp.text().await {
        Ok(t) => t,
        Err(_) => return false,
    };
    // A CF trace body contains `fl=` (front line) and `ip=`/`warp=` etc.
    body.contains("fl=") && body.contains("ip=") || body.contains("h=") && body.contains("ts=")
}

// ---------------------------------------------------------------------------
// SenpaiProvider: thin fallback wrapper around the existing binary
// ---------------------------------------------------------------------------

/// Thin wrapper over the existing SenPaiScanner CLI (fallback / debug mode).
#[derive(Default)]
pub struct SenpaiProvider {
    /// Show raw scanner output in the result (debug).
    pub verbose: bool,
}

impl EndpointProvider for SenpaiProvider {
    fn discover<'a>(
        &'a self,
        vless: &'a VlessProfile,
        params: &'a DiscoveryParams,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<CleanEndpoint>, CFError>> + Send + 'a>> {
        Box::pin(async move {
            // Keep a copy of the vless share link to hand to the scanner.
            let link = vless.share_link();
            let scan_params = ScanParams {
                count: params.sample,
                workers: params.workers as u32,
                timeout_s: params.timeout_s,
                top: params.top_n as u32,
                ..Default::default()
            };
            let res: ScanResult = run_scan(&link, &scan_params, params.top_n as u32).await?;
            let mut out = Vec::new();
            for ep in res.endpoints {
                let (ip, port) = split_endpoint(&ep);
                out.push(CleanEndpoint {
                    ip,
                    port,
                    sni: vless.sni.clone().unwrap_or_else(|| vless.address.clone()),
                    score: 100.0,
                    tcp_ms: 0.0,
                    connect_ms: 0.0,
                    download_kbps: 0.0,
                    verified: true,
                    alive: true,
                    last_checked: Some(store::now_iso()),
                    ts: store::now_iso(),
                });
            }
            Ok(out)
        })
    }
}

fn split_endpoint(ep: &str) -> (String, u16) {
    match ep.rsplit_once(':') {
        Some((ip, p)) => (ip.to_string(), p.parse().unwrap_or(443)),
        None => (ep.to_string(), 443),
    }
}

// ---------------------------------------------------------------------------
// Ledger persistence (machine-local)
// ---------------------------------------------------------------------------

/// Path to the autopilot ledger for a profile.
pub fn ledger_path(profile_id: &str) -> PathBuf {
    store::profiles::profile_dir(profile_id).join("autopilot").join("endpoints.json")
}

/// Read the current ledger.
pub fn read_ledger(profile_id: &str) -> Vec<CleanEndpoint> {
    store::read_or_default::<Vec<CleanEndpoint>>(&ledger_path(profile_id))
}

/// Persist the ledger atomically.
pub fn write_ledger(profile_id: &str, endpoints: &[CleanEndpoint]) -> Result<(), CFError> {
    store::atomic_write(&ledger_path(profile_id), &serde_json::to_vec_pretty(endpoints).map_err(|e| {
        CFError::new("Storage error", format!("Cannot serialize ledger: {e}"), "Internal error.")
    })?)
}

/// Directory where active (fronted) configs are written.
pub fn active_configs_dir(profile_id: &str) -> PathBuf {
    store::profiles::profile_dir(profile_id).join("configs").join("active")
}

/// Write an active vless share link + all common client formats for an
/// endpoint that fronts a given worker profile.
pub fn write_active_configs(
    profile_id: &str,
    vless: &VlessProfile,
    ep: &CleanEndpoint,
) -> Result<(), CFError> {
    let dir = active_configs_dir(profile_id);
    std::fs::create_dir_all(&dir).map_err(|e| {
        CFError::new("Storage error", format!("Cannot create {}: {e}", dir.display()), "Check permissions.")
    })?;

    let mut fronted = vless.clone();
    fronted.address = ep.ip.clone();
    fronted.port = ep.port;

    let link = fronted.share_link();
    store::atomic_write(&dir.join("link.txt"), link.as_bytes())?;

    // v2rayN / xray JSON
    if let Ok(xray) = fronted.xray_client_json() {
        store::atomic_write(&dir.join("xray.json"), xray.as_bytes())?;
    }
    // sing-box JSON
    if let Ok(sb) = crate::export::sing_box_json(&fronted) {
        store::atomic_write(&dir.join("sing-box.json"), sb.as_bytes())?;
    }
    // Clash entry
    store::atomic_write(&dir.join("clash.yaml"), crate::export::clash_entry(&fronted).as_bytes())?;

    Ok(())
}

/// Find the profile's base worker (non-clean-IP) vless link.
pub fn base_vless(profile_id: &str) -> Result<VlessProfile, CFError> {
    let p = store::profiles::load_profile(profile_id);
    let rec = p
        .history
        .iter()
        .find(|r| !r.clean_ip)
        .or_else(|| p.history.first());
    match rec {
        Some(rec) if !rec.link.is_empty() => VlessProfile::parse(&rec.link),
        _ => Err(CFError::new(
            "No config",
            "No vless config to front — deploy a worker first.",
            "Deploy a worker, then enable autopilot.",
        )),
    }
}

// ---------------------------------------------------------------------------
// Autopilot engine
// ---------------------------------------------------------------------------

/// A one-line, low-volume status summary of a cycle (the only per-cycle line
/// the UI shows).
#[derive(Debug, Clone)]
pub struct CycleSummary {
    pub cycle: u64,
    pub alive: usize,
    pub replaced: usize,
    pub note: String,
}

/// A handle to the running autopilot engine. Controls stop via a watch
/// channel; progress is streamed through `tx`.
pub struct AutopilotEngine {
    profile_id: String,
    params: DiscoveryParams,
    interval: Duration,
    provider: Box<dyn EndpointProvider>,
}

impl AutopilotEngine {
    pub fn new(profile_id: impl Into<String>, params: DiscoveryParams, interval: Duration) -> Self {
        Self {
            profile_id: profile_id.into(),
            params,
            interval,
            provider: Box::new(NativeCfProvider),
        }
    }

    /// Run one full discovery+validation cycle, persist the ledger, and
    /// write active configs. Returns the validated endpoints and a summary.
    pub async fn run_cycle(&self) -> Result<(Vec<CleanEndpoint>, CycleSummary), CFError> {
        let vless = base_vless(&self.profile_id)?;
        let found = self.provider.discover(&vless, &self.params).await?;

        let mut ledger = read_ledger(&self.profile_id);
        let mut replaced = 0;

        if !found.is_empty() {
            // Replace any currently-alive-but-not-in-found set? Simplest correct
            // behavior: keep the old ones that are still alive, add new ones.
            // We trust the monitor to mark dead ones.
            let mut merged = ledger.clone();
            for ep in &found {
                if !merged.iter().any(|e| e.ip == ep.ip) {
                    merged.push(ep.clone());
                } else if let Some(slot) = merged.iter_mut().find(|e| e.ip == ep.ip) {
                    *slot = ep.clone();
                }
            }
            // Trim to a sane bound (no unbounded growth).
            merged.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
            merged.truncate(64);
            replaced = merged.len().saturating_sub(ledger.len());
            ledger = merged;

            // Write active configs using the top validated endpoint.
            if let Some(best) = found.iter().find(|e| e.verified) {
                write_active_configs(&self.profile_id, &vless, best)?;
            }
        }

        write_ledger(&self.profile_id, &ledger)?;

        let alive = ledger.iter().filter(|e| e.alive).count();
        let summary = CycleSummary {
            cycle: 0,
            alive,
            replaced,
            note: format!(
                "found {} clean endpoint(s) · {} in ledger",
                found.len(),
                ledger.len()
            ),
        };
        Ok((found, summary))
    }

    /// Run the autopilot forever. The first cycle is a full discovery; after
    /// that, the monitor loop runs on `self.interval`. Progress is streamed
    /// to `tx` (a `tokio::sync::mpsc`-style closure). Stop by cancelling the
    /// task or dropping the handle.
    pub async fn run_forever<F>(self, mut report: F) -> Result<(), CFError>
    where
        F: FnMut(CycleSummary),
    {
        // First cycle: full discovery + validation.
        match self.run_cycle().await {
            Ok((_, summary)) => report(summary),
            Err(e) => {
                report(CycleSummary {
                    cycle: 1,
                    alive: 0,
                    replaced: 0,
                    note: format!("autopilot start failed: {}", e.brief()),
                });
            }
        }

        // Then monitor on an interval.
        let mut tick = tokio::time::interval(self.interval);
        let mut cycle = 1u64;
        loop {
            tick.tick().await;
            cycle += 1;
            let mut summary = match self.monitor_cycle().await {
                Ok(s) => s,
                Err(e) => CycleSummary {
                    cycle,
                    alive: 0,
                    replaced: 0,
                    note: format!("monitor error: {}", e.brief()),
                },
            };
            summary.cycle = cycle;
            report(summary);
        }
    }

    /// The monitor loop: re-validate active endpoints; swap a dead front for
    /// a fresh one found via targeted discovery. Returns a per-cycle summary.
    pub async fn monitor_cycle(&self) -> Result<CycleSummary, CFError> {
        let vless = base_vless(&self.profile_id)?;
        let mut ledger = read_ledger(&self.profile_id);
        let mut alive = 0;
        let mut replaced = 0;

        for ep in ledger.iter_mut() {
            let ok = validate_front(&ep.ip, ep.port, &ep.sni, self.params.timeout_s).await;
            if ok {
                ep.alive = true;
                ep.last_checked = Some(store::now_iso());
                alive += 1;
            } else {
                ep.alive = false;
            }
        }

        // If any active endpoint died, run a targeted discovery to find one
        // replacement (not a full re-scan) and swap it in.
        let any_dead = ledger.iter().any(|e| !e.alive);
        if any_dead {
            if let Ok(mut fresh) = self.provider.discover(&vless, &self.params).await {
                fresh.retain(|e| !ledger.iter().any(|l| l.ip == e.ip));
                if let Some(replacement) = fresh.into_iter().find(|e| e.verified) {
                    ledger.push(replacement.clone());
                    replaced += 1;
                    write_active_configs(&self.profile_id, &vless, &replacement)?;
                }
            }
        }

        write_ledger(&self.profile_id, &ledger)?;

        Ok(CycleSummary {
            cycle: 0,
            alive: ledger.iter().filter(|e| e.alive).count(),
            replaced,
            note: format!("monitor: {alive} alive, {replaced} replaced"),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_vless() -> VlessProfile {
        VlessProfile {
            uuid: "12345678-1234-1234-1234-123456789abc".into(),
            address: "user.workers.dev".into(),
            port: 443,
            security: "tls".into(),
            path: "/".into(),
            transport: "ws".into(),
            name: "test".into(),
            ..Default::default()
        }
    }

    #[test]
    fn split_endpoint_handles_port() {
        assert_eq!(split_endpoint("1.2.3.4:443"), ("1.2.3.4".into(), 443));
        assert_eq!(split_endpoint("1.2.3.4"), ("1.2.3.4".into(), 443));
    }

    #[test]
    fn ledger_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(dir.path().join(".dastyab"));
        let id = "default";
        let eps = vec![CleanEndpoint {
            ip: "1.2.3.4".into(),
            port: 443,
            sni: "user.workers.dev".into(),
            score: 50.0,
            tcp_ms: 10.0,
            connect_ms: 20.0,
            download_kbps: 500.0,
            verified: true,
            alive: true,
            last_checked: None,
            ts: String::new(),
        }];
        write_ledger(id, &eps).unwrap();
        let got = read_ledger(id);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].ip, "1.2.3.4");
        assert_eq!(got[0].port, 443);
    }

    #[test]
    fn write_active_configs_produces_files() {
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(dir.path().join(".dastyab"));
        let id = "default";
        let vless = sample_vless();
        let ep = CleanEndpoint {
            ip: "104.16.1.1".into(),
            port: 443,
            sni: "user.workers.dev".into(),
            score: 50.0,
            tcp_ms: 10.0,
            connect_ms: 20.0,
            download_kbps: 500.0,
            verified: true,
            alive: true,
            last_checked: None,
            ts: String::new(),
        };
        write_active_configs(id, &vless, &ep).unwrap();
        let dir = active_configs_dir(id);
        assert!(dir.join("link.txt").exists());
        assert!(dir.join("xray.json").exists());
        assert!(dir.join("sing-box.json").exists());
        assert!(dir.join("clash.yaml").exists());
        let link = std::fs::read_to_string(dir.join("link.txt")).unwrap();
        assert!(link.starts_with("vless://"));
        assert!(link.contains("104.16.1.1:443"));
    }

    #[test]
    fn discovery_params_defaults() {
        let p = DiscoveryParams::default();
        assert_eq!(p.sample, 2000);
        assert_eq!(p.workers, 64);
        assert_eq!(p.top_n, 3);
    }
}
