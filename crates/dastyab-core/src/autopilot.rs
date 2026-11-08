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
use crate::scanner::{run_scan, ScanParams, ScanResult};
use crate::store;
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
    let target = crate::health::derive_ws_target(vless);
    let sni = target.sni.clone();
    let path = target.path.clone();
    let timeout_s = params.timeout_s.max(1);

    // Step 0 — worker-health gate (DeepSeek plan #1). If the worker is dead,
    // suspended, or path-mismatched, no scanner can find clean IPs: short-
    // circuit with a plain-language diagnosis instead of wasting a scan.
    let cidrs = load_ranges(params.force_refresh_ranges).await?;
    match crate::autopilot::step0_gate(&sni, timeout_s as u64, &cidrs).await {
        crate::autopilot::WorkerHealth::Alive => {}
        other => {
            let cause = match other {
                crate::autopilot::WorkerHealth::Suspended { .. }
                | crate::autopilot::WorkerHealth::NotFound => {
                    crate::diagnose::PlainCause::WorkerDead
                }
                crate::autopilot::WorkerHealth::PathMismatch => {
                    crate::diagnose::PlainCause::WorkerPathMismatch
                }
                crate::autopilot::WorkerHealth::Unreachable => {
                    crate::diagnose::PlainCause::NetworkBlocked
                }
                crate::autopilot::WorkerHealth::Alive => unreachable!(),
            };
            let msg = crate::diagnose::plain_message(cause, crate::diagnose::Locale::En);
            return Err(CFError::new(
                "Worker offline",
                msg,
                "Check the Workers dashboard or try another network.",
            ));
        }
    }

    // Candidate generation: seeds first, then /24 neighbors, then weighted
    // sampling proportional to CIDR block size (SlipNet-style).
    let seeded =
        crate::cf::ips::seeded_candidates(&params.seed_ips, &cidrs, params.sample as usize, 24);
    let mut candidate_ips = seeded;
    if candidate_ips.len() < (params.sample as usize) {
        let missing = (params.sample as usize) - candidate_ips.len();
        let mut rng = rand::rngs::StdRng::from_entropy();
        let extra = crate::cf::ips::weighted_sample_by_cidr(&cidrs, missing, &mut rng);
        let mut seen: std::collections::HashSet<String> = candidate_ips.iter().cloned().collect();
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

    let target_n = params.top_n.max(1);
    let vless_link = vless.share_link();
    let direct_ip = crate::e2e::fetch_direct_ip(params.timeout_s.clamp(3, 20) as u64)
        .await
        .ok();

    // Local builder for one pipeline round (rebuildable per expansion round).
    let run_round = |cands: Vec<String>| {
        let phase1: crate::slipscan::Phase1Fn = Box::new(move |ip: &str, fast_fail_ms: u64| {
            let ip = ip.to_string();
            Box::pin(async move { crate::health::probe_fast_any_port(&ip, fast_fail_ms).await })
        });
        let phase2: crate::slipscan::Phase2Fn =
            Box::new(move |ip: &str, sni: &str, path: &str, ws_timeout_ms: u64| {
                let ip = ip.to_string();
                let sni = sni.to_string();
                let path = path.to_string();
                Box::pin(async move {
                    crate::health::probe_all_alt_ports(&ip, &sni, &path, ws_timeout_ms).await
                })
            });
        let e2e: crate::slipscan::E2eFn =
            Box::new(move |ip: &str, port: u16, vless: &str, timeout_s: u64| {
                let ip = ip.to_string();
                let vless = vless.to_string();
                let bin = crate::e2e::singbox_bin();
                Box::pin(async move {
                    let _ = crate::e2e::ensure_singbox("1.11.4").await;
                    crate::e2e::verify_tunnel(&ip, port, &vless, "0.0.0.0", &bin, timeout_s).await
                })
            });
        let pipeline_params = crate::slipscan::PipelineParams {
            target_n,
            phase1_workers: params.workers.max(1),
            phase2_workers: (params.workers / 4).clamp(4, 48),
            e2e_workers: 4,
            score_threshold: crate::health::ACCEPT_THRESHOLD,
            fast_fail_ms: crate::health::FAST_FAIL_MS,
            ws_timeout_ms: timeout_s as u64 * 1000,
        };
        crate::slipscan::pipeline_scan(
            cands,
            &sni,
            &path,
            &vless_link,
            direct_ip.clone(),
            pipeline_params,
            phase1,
            phase2,
            e2e,
            None,
        )
    };

    let mut examined: std::collections::HashSet<String> = candidate_ips.iter().cloned().collect();

    let first = run_round(candidate_ips).await?;
    let mut diagnostics = Some(first.diagnostics.clone());
    let mut verified = first.verified;

    // Multi-round cluster expansion (SlipNet style): when we find fewer than
    // target_n clean IPs, expand around the ones we DID find (their /24
    // siblings) and scan those next. One hit becomes a cluster. Bounded to
    // avoid runaway scans; only runs while there is still room to improve.
    let mut round = 0;
    while verified.len() < target_n && round < 3 && !verified.is_empty() {
        let expanded = crate::cf::ips::expand_around(&verified, 24, 254);
        let mut new_cands = Vec::new();
        for ip in expanded {
            if examined.insert(ip.clone()) {
                new_cands.push(ip);
            }
        }
        if new_cands.is_empty() {
            break;
        }
        let r = run_round(new_cands).await?;
        if let Some(d) = &mut diagnostics {
            d.examined_total = d
                .examined_total
                .saturating_add(r.diagnostics.examined_total);
            d.phase1_pass = d.phase1_pass.saturating_add(r.diagnostics.phase1_pass);
            d.phase2_pass = d.phase2_pass.saturating_add(r.diagnostics.phase2_pass);
            d.score_above_threshold = d
                .score_above_threshold
                .saturating_add(r.diagnostics.score_above_threshold);
            d.e2e_pass = d.e2e_pass.saturating_add(r.diagnostics.e2e_pass);
        }
        for ep in r.verified {
            if !verified.iter().any(|v| v.ip == ep.ip) {
                verified.push(ep);
            }
        }
        verified.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        verified.truncate(target_n);
        round += 1;
    }

    // Persist diagnostics so the GUI/CLI can explain a zero result.
    if let Some(d) = diagnostics {
        let _ = crate::store::profiles::save_last_diagnostics(profile_id, &d);
    }

    Ok(verified)
}

/// Health state of the worker's route, as observed by a one-shot probe.
/// Used as a step-0 gate so a scan never runs against a dead/misconfigured
/// worker (DeepSeek plan #1 — the #1 cause of "zero clean IPs").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerHealth {
    /// The worker answered a healthy probe (HTTP 200/101 or textual trace).
    Alive,
    /// The route responds, but with a status that suggests no worker there.
    NotFound,
    /// The account/worker is suspended or errored (e.g. CF 9109).
    Suspended { code: u16 },
    /// The worker responds but on a path the app didn't ask for.
    PathMismatch,
    /// No TCP/TLS/HTTP response at all (network or worker unreachable).
    Unreachable,
}

/// Step-0 worker-health probe. Does a real TLS handshake + HTTP GET against
/// the worker's hostname (its own host, not a clean-IP front), then classifies
/// the response. This is cheap (~300ms) and runs once per scan/cycle.
///
/// `connect_ip` lets the caller bypass DNS entirely: when provided, we connect
/// to that literal IP (which must front the worker) while still sending
/// `worker_host` as the SNI/Host. This is essential on censored networks
/// where system DNS is hijacked (e.g. 198.18.x.x in Iran) — the hostname
/// itself may never resolve to a real address.
pub async fn probe_worker_health(
    worker_host: &str,
    connect_ip: Option<std::net::Ipv4Addr>,
    timeout_s: u64,
) -> WorkerHealth {
    let timeout_ms = timeout_s.max(1) * 1000;

    let connect_addr = match connect_ip {
        Some(ip) => ip.to_string(),
        None => {
            // Prefer DoH (immune to system-DNS hijack), then fall back to system
            // DNS with hijack rejection. DoH already filters 198.18.x.x.
            let doh = crate::doh::DohResolver::new();
            match resolve_worker_host(worker_host, Some(&doh)).await {
                Some(ip) => ip.to_string(),
                None => return WorkerHealth::Unreachable,
            }
        }
    };

    let stream = match crate::health::tls_connect(&connect_addr, 443, worker_host, timeout_ms).await
    {
        Ok(s) => s,
        Err(_) => return WorkerHealth::Unreachable,
    };

    classify_worker_response(stream, worker_host, timeout_ms).await
}

/// Resolve `worker_host` to a usable IPv4 address. When `doh` is provided it is
/// tried first (it is immune to system-DNS hijack); on failure we fall back to
/// `std::net::ToSocketAddrs` and reject hijacked 198.18.x.x answers.
async fn resolve_worker_host(
    worker_host: &str,
    doh: Option<&crate::doh::DohResolver>,
) -> Option<std::net::Ipv4Addr> {
    if let Some(resolver) = doh {
        if let Ok(ips) = resolver.resolve(worker_host).await {
            if let Some(ip) = ips.into_iter().find(|ip| !crate::health::is_hijacked_ip(ip)) {
                return Some(ip);
            }
        }
    }
    if let Ok(iter) = std::net::ToSocketAddrs::to_socket_addrs(&(worker_host.to_string(), 443u16)) {
        for a in iter {
            if let std::net::SocketAddr::V4(v4) = a {
                let ip = v4.ip();
                if !crate::health::is_hijacked_ip(ip) {
                    return Some(*ip);
                }
            }
        }
    }
    None
}

/// Perform the TLS handshake + `GET /cdn-cgi/trace` against `worker_host` via
/// an already-established TLS stream, and classify the response. Shared by the
/// hostname-gate and the DNS-free CF-sample gate.
async fn classify_worker_response(
    mut stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    worker_host: &str,
    timeout_ms: u64,
) -> WorkerHealth {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let req = format!(
        "GET /cdn-cgi/trace HTTP/1.1\r\nHost: {worker_host}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    if tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        stream.write_all(req.as_bytes()),
    )
    .await
    .is_err()
        || stream.flush().await.is_err()
    {
        return WorkerHealth::Unreachable;
    }
    let mut buf = [0u8; 8192];
    let mut head = Vec::new();
    let read_res = tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), async {
        let mut total = 0usize;
        let mut headers_done = false;
        while total < 16 * 1024 {
            match stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    head.extend_from_slice(&buf[..n]);
                    total += n;
                    if !headers_done && head.windows(4).any(|w| w == b"\r\n\r\n") {
                        headers_done = true;
                    }
                    if headers_done && total >= 512 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    })
    .await;
    if read_res.is_err() {
        return WorkerHealth::Unreachable;
    }
    let text = String::from_utf8_lossy(&head);
    classify_worker_health(&text)
}

/// Pure classification of a raw HTTP response head into a `WorkerHealth`.
/// Split out for deterministic unit testing.
pub fn classify_worker_health(text: &str) -> WorkerHealth {
    if text.contains("HTTP/1.1 200") || text.contains("HTTP/1.1 101") {
        return WorkerHealth::Alive;
    }
    // Cloudflare account/worker error codes take precedence over generic 4xx
    // path heuristics: a 403/500 with 9109 (invalid token) or a suspended/
    // disabled marker is an account-level problem, not a path mismatch.
    if text.contains("9109") || text.contains("disabled") || text.contains("suspended") {
        return WorkerHealth::Suspended { code: 9109 };
    }
    if text.contains("HTTP/1.1 404")
        || text.contains("HTTP/1.1 400")
        || text.contains("HTTP/1.1 426")
        || text.contains("HTTP/1.1 403")
    {
        // 403/404 on the trace route => likely path mismatch or wrong host.
        return WorkerHealth::PathMismatch;
    }
    if text.contains("HTTP/1.1") {
        WorkerHealth::Suspended { code: 500 }
    } else {
        WorkerHealth::Unreachable
    }
}

/// Summary of a DNS-free worker-health sweep across a sample of Cloudflare IPs.
#[derive(Debug, Clone, Default)]
pub struct WorkerHealthSample {
    pub alive: bool,
    pub responding_ip: Option<std::net::Ipv4Addr>,
    pub attempted: u32,
    pub successful: u32,
    pub path_mismatch: u32,
    pub suspended: u32,
    pub unreachable: u32,
}

/// Probe the worker's health by connecting to a sample of literal Cloudflare IPs
/// (from the known ranges) with SNI=worker_host — **no DNS anywhere in the path**.
/// On censored networks where system DNS is hijacked, this is the only reliable
/// way to establish that the worker is alive before scanning. Early-exits on the
/// first 200/101.
pub async fn probe_worker_via_cf_sample(
    worker_host: &str,
    ranges: &[crate::cf::ips::Cidr],
    sample: usize,
    timeout_s: u64,
) -> WorkerHealthSample {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let ips = crate::cf::ips::weighted_sample_by_cidr(ranges, sample.max(1), &mut rng);
    probe_worker_via_ips(worker_host, &ips, 443, timeout_s).await
}

/// The core sweep loop: probe each literal IP in `ips` with SNI=worker_host,
/// early-exiting on the first 200/101. Split out so tests can drive it with a
/// fixed IP list and a custom port (e.g. the mock worker on loopback).
pub async fn probe_worker_via_ips(
    worker_host: &str,
    ips: &[String],
    port: u16,
    timeout_s: u64,
) -> WorkerHealthSample {
    let timeout_ms = timeout_s.max(1) * 1000;
    let mut out = WorkerHealthSample::default();
    for ip_str in ips {
        out.attempted += 1;
        let stream = match crate::health::tls_connect(ip_str, port, worker_host, timeout_ms).await {
            Ok(s) => s,
            Err(_) => {
                out.unreachable += 1;
                continue;
            }
        };
        match classify_worker_response(stream, worker_host, timeout_ms).await {
            WorkerHealth::Alive => {
                out.alive = true;
                out.successful += 1;
                out.responding_ip = ip_str.parse().ok();
                break;
            }
            WorkerHealth::PathMismatch => out.path_mismatch += 1,
            WorkerHealth::Suspended { .. } => out.suspended += 1,
            WorkerHealth::Unreachable | WorkerHealth::NotFound => out.unreachable += 1,
        }
    }
    out
}

/// The step-0 gate used by discovery. First tries the fast hostname path
/// (`probe_worker_health`), which works when DNS is healthy; if that fails to
/// prove the worker is alive, falls back to the DNS-free CF-sample sweep so a
/// hijacked resolver can never block a usable scan.
pub async fn step0_gate(
    worker_host: &str,
    timeout_s: u64,
    cidrs: &[crate::cf::ips::Cidr],
) -> WorkerHealth {
    // Fast path: try resolving through system DNS (rejecting hijacked answers).
    if matches!(
        probe_worker_health(worker_host, None, timeout_s).await,
        WorkerHealth::Alive
    ) {
        return WorkerHealth::Alive;
    }
    // Fallback: DNS-free sweep across a sample of Cloudflare IPs.
    if cidrs.is_empty() {
        return WorkerHealth::Unreachable;
    }
    let sample = probe_worker_via_cf_sample(worker_host, cidrs, 24, timeout_s).await;
    if sample.alive {
        WorkerHealth::Alive
    } else if sample.suspended > 0 {
        WorkerHealth::Suspended { code: 9109 }
    } else if sample.path_mismatch > 0 {
        WorkerHealth::PathMismatch
    } else {
        WorkerHealth::Unreachable
    }
}

/// Check whether an endpoint is still alive using the real-client WS gate:
/// TLS + RFC 6455 upgrade across the alt-port set, accepting only a 101 with
/// actual bytes. This is the monitor's "is it still tunnelling?" test.
async fn endpoint_live(ip: &str, sni: &str, path: &str, timeout_ms: u64) -> bool {
    let probes = crate::health::probe_all_alt_ports(ip, sni, path, timeout_ms).await;
    probes
        .iter()
        .any(|p| p.status == Some(101) && p.worker_bytes >= crate::health::MIN_WORKER_BYTES)
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
    store::profiles::profile_dir(profile_id)
        .join("autopilot")
        .join("endpoints.json")
}

/// Read the current ledger.
pub fn read_ledger(profile_id: &str) -> Vec<CleanEndpoint> {
    store::read_or_default::<Vec<CleanEndpoint>>(&ledger_path(profile_id))
}

/// Persist the ledger atomically.
pub fn write_ledger(profile_id: &str, endpoints: &[CleanEndpoint]) -> Result<(), CFError> {
    store::atomic_write(
        &ledger_path(profile_id),
        &serde_json::to_vec_pretty(endpoints).map_err(|e| {
            CFError::new(
                "Storage error",
                format!("Cannot serialize ledger: {e}"),
                "Internal error.",
            )
        })?,
    )
}

/// Directory where active (fronted) configs are written.
pub fn active_configs_dir(profile_id: &str) -> PathBuf {
    store::profiles::profile_dir(profile_id)
        .join("configs")
        .join("active")
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
        CFError::new(
            "Storage error",
            format!("Cannot create {}: {e}", dir.display()),
            "Check permissions.",
        )
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
    store::atomic_write(
        &dir.join("clash.yaml"),
        crate::export::clash_entry(&fronted).as_bytes(),
    )?;

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
        // Auto-pilot ledger's last-known-good endpoints first.
        let mut seeds: Vec<String> = crate::cf::ips::load_seed_endpoints(&self.profile_id, 6)
            .iter()
            .filter_map(|s| s.split(':').next().map(|ip| ip.to_string()))
            .collect();
        // Then the user's manually imported "known-good IPs" — these are the
        // highest-value seeds (NetworkBlocked fast path). Bare IPs only.
        for s in crate::cf::ips::load_manual_seeds(&self.profile_id) {
            if let Some(ip) = s.split(':').next() {
                if !seeds.iter().any(|e| e == ip) {
                    seeds.push(ip.to_string());
                }
            }
        }
        p.seed_ips = seeds;
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
            merged.sort_by(|a, b| {
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
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

    /// The monitor loop (DeepSeek two-tier plan). Tier 1 is a cheap **light**
    /// check: the real-client WS-gate on every ledger endpoint. Two
    /// consecutive light-failures of the active endpoint *escalate* to Tier 2,
    /// a **deep** full discovery + E2E pass (also run on a 15-min schedule).
    /// A deep-check failure is what actually triggers a swap. Best-score-wins
    /// keeps the highest verified+alive endpoint as the active config.
    /// Returns a per-cycle summary.
    pub async fn monitor_cycle(&self) -> Result<CycleSummary, CFError> {
        let vless = base_vless(&self.profile_id)?;
        let path = crate::health::derive_ws_target(&vless).path;
        let timeout_ms = (self.params.timeout_s as u64) * 1000;

        let mut ledger = read_ledger(&self.profile_id);
        let mut state = crate::store::profiles::protection_state(&self.profile_id);
        let now = store::now_ts() as i64;
        let deep_interval: i64 = 900; // deep E2E check every 15 min

        // ── Tier 1: LIGHT check (WS-gate across alt ports) ──
        let mut alive = 0usize;
        for ep in ledger.iter_mut() {
            let ok = endpoint_live(&ep.ip, &ep.sni, &path, timeout_ms).await;
            ep.alive = ok;
            if ok {
                ep.last_checked = Some(store::now_iso());
                alive += 1;
            }
        }

        // The active endpoint is the best verified one (highest score).
        ledger.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let active_alive = ledger
            .iter()
            .find(|e| e.verified)
            .map(|e| e.alive)
            .unwrap_or(false);

        // Streak: 2 consecutive light failures of the active escalate to deep.
        if active_alive {
            state.failure_streak = 0;
        } else {
            state.failure_streak = state.failure_streak.saturating_add(1);
        }
        let deep_due = (now - state.last_deep_check) >= deep_interval;
        let escalated = state.failure_streak >= 2 && !active_alive;
        let do_deep = deep_due || escalated;

        let mut replaced = 0;
        let mut did_rediscover = false;

        if do_deep {
            // ── Tier 2: DEEP check — full discovery through the pipeline ──
            state.last_deep_check = now;
            let params = self.params_with_seeds();
            match self.provider.discover(&vless, &params).await {
                Ok(fresh) => {
                    for ep in fresh {
                        if let Some(slot) = ledger.iter_mut().find(|l| l.ip == ep.ip) {
                            *slot = ep.clone();
                        } else {
                            ledger.push(ep.clone());
                            replaced += 1;
                        }
                    }
                    did_rediscover = true;
                    // A successful deep pass resets the streak.
                    if ledger.iter().any(|e| e.alive) {
                        state.failure_streak = 0;
                    }
                }
                Err(_) => {
                    // Deep check failed; keep the streak so escalation retries.
                }
            }
        } else if alive == 0 {
            // Nothing alive but no escalation due yet — still chase fresh ones
            // so a dead ledger doesn't sit empty.
            let params = self.params_with_seeds();
            if let Ok(fresh) = self.provider.discover(&vless, &params).await {
                for ep in fresh {
                    if let Some(slot) = ledger.iter_mut().find(|l| l.ip == ep.ip) {
                        *slot = ep.clone();
                    } else {
                        ledger.push(ep.clone());
                        replaced += 1;
                    }
                }
                did_rediscover = true;
            }
        }

        // Best-score wins: pick the highest verified+alive endpoint as active.
        ledger.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let best_ip = ledger
            .iter()
            .find(|e| e.verified && e.alive)
            .map(|e| e.ip.clone());
        if let Some(best) = best_ip.as_ref() {
            let best_ep = ledger.iter().find(|e| e.ip == *best).unwrap();
            write_active_configs(&self.profile_id, &vless, best_ep)?;
        }

        // Trim ledger, persist state, refresh the user bundle.
        ledger.truncate(64);
        write_ledger(&self.profile_id, &ledger)?;
        crate::store::profiles::save_protection_state(&self.profile_id, &state)?;

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
                "monitor: {alive} alive · {} clean · best {} · deep={did_rediscover} streak={}",
                live.len(),
                best_ip.as_deref().unwrap_or("-"),
                state.failure_streak
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

    #[test]
    fn classify_health_alive_on_200() {
        assert!(matches!(
            classify_worker_health("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nfl=000"),
            WorkerHealth::Alive
        ));
    }

    #[test]
    fn classify_health_alive_on_101() {
        assert!(matches!(
            classify_worker_health("HTTP/1.1 101 Switching Protocols\r\n\r\n"),
            WorkerHealth::Alive
        ));
    }

    #[test]
    fn classify_health_path_mismatch_on_404() {
        assert_eq!(
            classify_worker_health("HTTP/1.1 404 Not Found\r\n\r\n"),
            WorkerHealth::PathMismatch
        );
    }

    #[test]
    fn classify_health_suspended_on_9109() {
        assert!(matches!(
            classify_worker_health("HTTP/1.1 403 Forbidden\r\n\r\n{\"code\":9109}"),
            WorkerHealth::Suspended { code: 9109 }
        ));
    }

    #[test]
    fn classify_health_unreachable_on_garbage() {
        assert_eq!(
            classify_worker_health("garbage bytes no http"),
            WorkerHealth::Unreachable
        );
    }

    #[cfg(feature = "dev-mock")]
    #[tokio::test]
    async fn probe_via_ips_marks_alive_against_mock_worker() {
        use crate::mock_worker::{run_mock_worker, MockWorkerConfig};
        let cfg = MockWorkerConfig {
            listen_addr: "127.0.0.1:18443".parse().unwrap(),
            worker_path: "/api".into(),
            ws_payload_bytes: 4096,
            trace_ip: "198.51.100.1".into(),
            cert_sni: "mock.workers.dev".into(),
        };
        let _handle = tokio::spawn(run_mock_worker(cfg));
        // Give the mock worker a moment to bind.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let ips = vec!["127.0.0.1".to_string()];
        let sample = probe_worker_via_ips("mock.workers.dev", &ips, 18443, 5).await;
        assert!(sample.alive, "mock worker should be detected alive");
        assert_eq!(sample.successful, 1);
        assert_eq!(sample.responding_ip, Some("127.0.0.1".parse().unwrap()));
    }

    #[cfg(feature = "dev-mock")]
    #[tokio::test]
    async fn probe_via_ips_reports_unreachable_when_nothing_listens() {
        let ips = vec!["127.0.0.1".to_string()];
        // Port 1 on loopback is effectively closed.
        let sample = probe_worker_via_ips("mock.workers.dev", &ips, 1, 3).await;
        assert!(!sample.alive);
        assert!(sample.unreachable >= 1);
    }

    /// When a DoH resolver is provided (cache seeded), resolution must use the
    /// DoH answer first — never the poisoned system resolver.
    #[tokio::test]
    async fn test_probe_worker_health_uses_doh_when_resolver_provided() {
        let resolver = crate::doh::DohResolver::new();
        let known = std::net::Ipv4Addr::new(104, 16, 132, 229);
        resolver
            .seed_cache("mock.workers.dev".to_string(), vec![known]);
        let resolved = resolve_worker_host("mock.workers.dev", Some(&resolver)).await;
        assert_eq!(resolved, Some(known), "DoH cache answer must be preferred");
    }

    #[tokio::test]
    async fn resolve_worker_host_falls_back_to_system_when_doh_fails() {
        // An empty (cacheless) resolver will attempt network; on failure we fall
        // back to system DNS. We only assert the fallback does not panic and
        // returns an Option (either Some real IP or None).
        let resolver = crate::doh::DohResolver::new();
        let _ = resolve_worker_host("example.com", Some(&resolver)).await;
    }
}
