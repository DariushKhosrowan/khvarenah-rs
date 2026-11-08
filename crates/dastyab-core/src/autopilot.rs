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
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use rand::SeedableRng;

use crate::cf::ips::load_ranges;
use crate::error::CFError;
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
    /// Known-good IP seeds (from the autopilot ledger). The scanner expands
    /// neighbourhoods around these first instead of sampling uniformly.
    /// `seed_ips` are bare IPv4 strings (no port).
    pub seed_ips: Vec<String>,
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
            seed_ips: Vec::new(),
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
pub struct NativeCfProvider {
    profile_id: String,
}

impl Default for NativeCfProvider {
    fn default() -> Self {
        Self {
            profile_id: "default".to_string(),
        }
    }
}

impl EndpointProvider for NativeCfProvider {
    fn discover<'a>(
        &'a self,
        vless: &'a VlessProfile,
        params: &'a DiscoveryParams,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<CleanEndpoint>, CFError>> + Send + 'a>> {
        Box::pin(discover_native(vless, params, &self.profile_id))
    }
}

/// The native discovery pipeline: neighbourhood-aware candidate generation
/// (seeds + /24 expansion + weighted sample) → SlipNet-style two-phase
/// streaming scan → ranked clean endpoints. Each accepted endpoint has passed
/// the fast TCP prefilter *and* the real-client TLS+WS upgrade gate, so
/// `verified` is set at probe time.
async fn discover_native(
    vless: &VlessProfile,
    params: &DiscoveryParams,
    profile_id: &str,
) -> Result<Vec<CleanEndpoint>, CFError> {
    let cidrs = load_ranges(params.force_refresh_ranges).await?;

    // Candidate generation: seeds first, then /24 neighbors, then weighted
    // sampling proportional to CIDR block size (SlipNet-style).
    let seeded = crate::cf::ips::seeded_candidates(
        &params.seed_ips,
        &cidrs,
        params.sample as usize,
        24,
    );
    let mut candidate_ips = seeded;
    if candidate_ips.len() < (params.sample as usize) {
        let missing = (params.sample as usize) - candidate_ips.len();
        let mut rng = rand::rngs::StdRng::from_entropy();
        let extra = crate::cf::ips::weighted_sample_by_cidr(&cidrs, missing, &mut rng);
        let mut seen: std::collections::HashSet<String> =
            candidate_ips.iter().cloned().collect();
        for ip in extra {
            if seen.insert(ip.clone()) {
                candidate_ips.push(ip);
            }
        }
    }
    candidate_ips.truncate(params.sample as usize);
    if candidate_ips.is_empty() {
        return Err(CFError::new(
            "No candidates",
            "The Cloudflare range list produced no candidate IPs.",
            "Check network connectivity and retry.",
        ));
    }

    let target = crate::health::derive_ws_target(vless);
    let sni = target.sni.clone();
    let path = target.path.clone();
    let timeout_s = params.timeout_s.max(1);

    // Phase 1: fast TCP liveness across the alt-port set (early-exits on
    // the first reachable port — vital when 443 is throttled in Iran).
    let phase1: crate::slipscan::Phase1Fn = Box::new(move |ip: &str, fast_fail_ms: u64| {
        let ip = ip.to_string();
        Box::pin(async move { crate::health::probe_fast_any_port(&ip, fast_fail_ms).await })
    });

    // Phase 2: deep WS-upgrade gate across alt ports.
    let phase2: crate::slipscan::Phase2Fn = Box::new(move |ip: &str, sni: &str, path: &str, ws_timeout_ms: u64| {
        let ip = ip.to_string();
        let sni = sni.to_string();
        let path = path.to_string();
        Box::pin(async move {
            crate::health::probe_all_alt_ports(&ip, &sni, &path, ws_timeout_ms).await
        })
    });

    let scan_params = crate::slipscan::ScanParams {
        target_n: params.top_n.max(1),
        phase1_workers: params.workers.max(1),
        phase2_workers: (params.workers / 4).clamp(4, 48),
        fast_fail_ms: crate::health::FAST_FAIL_MS,
        ws_timeout_ms: timeout_s as u64 * 1000,
    };

    // ── Parallel pipeline (SlipNet orchestration) ──
    // Phase-1 → phase-2 → a *parallel* E2E worker pool, with score-threshold
    // gating so we only spend sing-box tunnel budget on strong candidates.
    // Diagnostics are persisted so a zero result can be explained in plain
    // language. E2E only runs when we can reach a direct-IP echo service;
    // otherwise the pipeline degrades to the WS-gate alone.
    let vless_link = vless.share_link();
    let direct_ip = crate::e2e::fetch_direct_ip(params.timeout_s.clamp(3, 20) as u64)
        .await
        .ok();

    let pipeline_params = crate::slipscan::PipelineParams {
        target_n: params.top_n.max(1),
        phase1_workers: params.workers.max(1),
        phase2_workers: (params.workers / 4).clamp(4, 48),
        e2e_workers: 4,
        score_threshold: crate::health::ACCEPT_THRESHOLD,
        fast_fail_ms: crate::health::FAST_FAIL_MS,
        ws_timeout_ms: timeout_s as u64 * 1000,
    };

    let e2e: crate::slipscan::E2eFn = Box::new(move |ip: &str, port: u16, vless: &str, timeout_s: u64| {
        let ip = ip.to_string();
        let vless = vless.to_string();
        let bin = crate::e2e::singbox_bin();
        Box::pin(async move {
            // Ensure sing-box is present; if the download fails, the E2E
            // result reports SingBoxSpawn and the pipeline falls back to the
            // gate-only path.
            let _ = crate::e2e::ensure_singbox("1.11.4").await;
            crate::e2e::verify_tunnel(&ip, port, &vless, "0.0.0.0", &bin, timeout_s).await
        })
    });

    let result = crate::slipscan::pipeline_scan(
        candidate_ips,
        &sni,
        &path,
        &vless_link,
        direct_ip,
        pipeline_params,
        phase1,
        phase2,
        e2e,
        None,
    )
    .await?;

    // Persist diagnostics so the GUI/CLI can explain a zero result.
    let _ = crate::store::profiles::save_last_diagnostics(profile_id, &result.diagnostics);
    let _ = scan_params;

    Ok(result.verified)
}

/// Check whether an endpoint is still alive using the real-client WS gate:
/// TLS + RFC 6455 upgrade across the alt-port set, accepting only a 101 with
/// actual bytes. This is the monitor's "is it still tunnelling?" test.
async fn endpoint_live(ip: &str, sni: &str, path: &str, timeout_ms: u64) -> bool {
    let probes = crate::health::probe_all_alt_ports(ip, sni, path, timeout_ms).await;
    probes
        .iter()
        .any(|p| p.status == Some(101) && p.worker_bytes > 0)
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
        let profile_id = profile_id.into();
        Self {
            profile_id: profile_id.clone(),
            params,
            interval,
            provider: Box::new(NativeCfProvider {
                profile_id: profile_id.clone(),
            }),
        }
    }

    /// A discovery-param copy seeded from the ledger's last-known-good
    /// endpoints. `seed_ips` become the neighbourhood anchor points for the
    /// scanner (feature #2), so it doesn't start from zero each cycle.
    fn params_with_seeds(&self) -> DiscoveryParams {
        let mut p = self.params.clone();
        p.seed_ips = crate::cf::ips::load_seed_endpoints(&self.profile_id, 6)
            .iter()
            .filter_map(|s| s.split(':').next().map(|ip| ip.to_string()))
            .collect();
        p
    }

    /// Run one full discovery+validation cycle, persist the ledger, and
    /// write active configs. Returns the validated endpoints and a summary.
    pub async fn run_cycle(&self) -> Result<(Vec<CleanEndpoint>, CycleSummary), CFError> {
        let vless = base_vless(&self.profile_id)?;
        let params = self.params_with_seeds();
        let found = self.provider.discover(&vless, &params).await?;

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

        // Refresh the user-facing bundle (~/dastyab-configs/<profile>/).
        let live: Vec<CleanEndpoint> = ledger
            .iter()
            .filter(|e| e.verified && e.alive)
            .cloned()
            .collect();
        let _ = crate::cleanip::write_user_bundle(&self.profile_id, &vless, &live);

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

    /// The monitor loop: re-validate active endpoints, chase better clean IPs
    /// on a cadence, and always keep the *highest-score alive* endpoint as the
    /// active config. Swap in fresh clean IPs when the current one dies.
    /// Returns a per-cycle summary.
    pub async fn monitor_cycle(&self) -> Result<CycleSummary, CFError> {
        let vless = base_vless(&self.profile_id)?;
        let mut ledger = read_ledger(&self.profile_id);
        let mut alive = 0;
        let mut replaced = 0;

        let timeout_ms = (self.params.timeout_s as u64) * 1000;
        let path = crate::health::derive_ws_target(&vless).path;

        // Re-validate every ledger endpoint's liveness.
        for ep in ledger.iter_mut() {
            let ok = endpoint_live(&ep.ip, &ep.sni, &path, timeout_ms).await;
            if ok {
                ep.alive = true;
                ep.last_checked = Some(store::now_iso());
                alive += 1;
            } else {
                ep.alive = false;
            }
        }

        // Re-discover when (a) something died, or (b) we have fewer than
        // the target number of alive endpoints — we *chase* better clean IPs
        // aggressively so the active config always has the freshest, fastest
        // front.
        let alive_count = ledger.iter().filter(|e| e.alive).count();
        let want = self.params.top_n.max(1);
        let need_more = alive_count < want;
        if need_more {
            let params = self.params_with_seeds();
            if let Ok(fresh) = self.provider.discover(&vless, &params).await {
                for ep in fresh {
                    // Record new IPs and update scores of known IPs.
                    if let Some(slot) = ledger.iter_mut().find(|l| l.ip == ep.ip) {
                        *slot = ep.clone();
                    } else {
                        ledger.push(ep.clone());
                        replaced += 1;
                    }
                }
            }
        }

        // Best-score wins: pick the highest-score *alive* endpoint as active.
        ledger.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        let best_ip = ledger
            .iter()
            .find(|e| e.verified && e.alive)
            .map(|e| e.ip.clone());
        if let Some(best) = best_ip.as_ref() {
            let best_ep = ledger.iter().find(|e| e.ip == *best).unwrap();
            write_active_configs(&self.profile_id, &vless, best_ep)?;
        }

        // Trim ledger, persist, refresh the user bundle.
        ledger.truncate(64);
        write_ledger(&self.profile_id, &ledger)?;

        let live: Vec<CleanEndpoint> = ledger
            .iter()
            .filter(|e| e.verified && e.alive)
            .cloned()
            .collect();
        let _ = crate::cleanip::write_user_bundle(&self.profile_id, &vless, &live);

        Ok(CycleSummary {
            cycle: 0,
            alive: live.len(),
            replaced,
            note: format!(
                "monitor: {alive} alive · {} clean · best {}",
                live.len(),
                best_ip.as_deref().unwrap_or("-")
            ),
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
