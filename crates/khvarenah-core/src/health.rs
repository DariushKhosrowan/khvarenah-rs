//! Health probe: TCP latency + TLS handshake latency + download speed.
//!
//! This makes the clean-IP scanner "smart": a candidate endpoint is only
//! accepted after it passes a real health check.
//!
//! It also carries the real-client WebSocket-upgrade gate (DeepSeek plan #1):
//! a candidate edge only counts as clean if a TLS session completes AND an
//! RFC 6455 Upgrade to the worker's path returns `101 Switching Protocols`
//! with actual bytes — not merely that TCP/TLS answers a ping.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use rand::SeedableRng as _;

use crate::error::CFError;
use crate::vless::VlessProfile;

/// Cloudflare alt-ports, ordered by usefulness on censored networks.
/// 443 is often the most-throttled port (every VPN uses it); the alt ports
/// are frequently left open because DPI assumes "real HTTPS uses 443".
pub const ALT_PORTS: &[u16] = &[443, 2053, 2087, 2096, 8443, 2083, 2082, 8880, 2052];

/// A benign Cloudflare SNI used by the GenericCf fallback: the network sees
/// this domain in the TLS ClientHello instead of the worker's `*.workers.dev`
/// hostname, while the HTTP Host header still routes to the worker. This
/// bypasses DPI that blocks on the SNI.
pub const GENERIC_CF_SNI: &str = "www.cloudflare.com";

/// Minimum worker payload bytes for a WS-upgrade to count as a real route.
/// A 101 that immediately closes with < this many bytes is a dead route
/// (edge upgraded but no worker behind it). (DeepSeek plan, Phase 3.)
pub const MIN_WORKER_BYTES: u32 = 512;

/// Why a WS probe failed, bucketed so the phase-2 histogram can tell Cause A
/// (DPI resetting the TLS handshake — static ClientHello fingerprint) from
/// Cause B (worker path dead / wrong route) in ONE run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum WsFailureReason {
    /// TCP connect failed outright (network unreachable / edge dropped).
    ConnectFailed,
    /// TCP connect timed out (censored network throttling the port).
    ConnectTimeout,
    /// TLS handshake aborted (alert / connection reset) — the DPI signature
    /// Cause A. Static ClientHello fingerprint being blacklisted.
    TlsAlert,
    /// TLS handshake timed out.
    TlsTimeout,
    /// Writing or flushing the WS upgrade request failed.
    WriteFailed,
    /// HTTP response never fully arrived (timeout / partial read).
    ResponseIncomplete,
    /// A non-101 HTTP status was returned by the edge (e.g. 403/421/404).
    HttpStatus(u16),
    /// Got 101 but fewer than `MIN_WORKER_BYTES` worker bytes — edge upgraded
    /// but no worker behind it (Cause B: dead route / path mismatch).
    DeadRoute,
}

/// A single WebSocket-upgrade probe verdict for one (ip, port).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WsProbe {
    pub port: u16,
    /// TLS handshake completed.
    pub tls_ok: bool,
    /// HTTP response status of the Upgrade request. `101` is the only accept.
    pub status: Option<u16>,
    /// RTT of the TLS handshake in ms.
    pub rtt_ms: u32,
    /// Bytes received after the upgrade before close/timeout. 0 = route dead.
    pub worker_bytes: u32,
    /// Failure stage if the probe did not pass ("tls" | "ws" | "route").
    pub failure_stage: Option<String>,
    /// Enriched, bucketed failure reason (the phase-2 resurrection diagnostic).
    pub failure_reason: Option<WsFailureReason>,
    /// Which SNI this probe was sent under (worker hostname vs generic CF).
    pub sni_used: String,
}

/// Derived target for a WS probe: what to connect to and what to request.
#[derive(Debug, Clone)]
pub struct WsTarget {
    pub sni: String,
    pub path: String,
    pub host: String,
}

/// A measured health result for one endpoint.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HealthResult {
    pub ip: String,
    pub port: u16,
    pub ok: bool,
    pub tcp_ms: f32,
    pub connect_ms: f32,
    pub download_kbps: f32,
    pub error: Option<String>,
}

/// Options for a health check.
#[derive(Debug, Clone)]
pub struct HealthOptions {
    pub timeout: Duration,
    pub download_bytes: usize,
    pub tls: bool,
}

impl Default for HealthOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(8),
            download_bytes: 16 * 1024,
            tls: true,
        }
    }
}

/// Resolve "host:port" into a SocketAddr quickly.
fn resolve(host: &str, port: u16) -> Result<SocketAddr, CFError> {
    (host, port)
        .to_socket_addrs()
        .map_err(|e| {
            CFError::new(
                "DNS error",
                format!("Cannot resolve {host}:{port}: {e}"),
                "Check the IP/port format.",
            )
        })?
        .next()
        .ok_or_else(|| {
            CFError::new(
                "DNS error",
                format!("No address for {host}:{port}"),
                "Check the IP/port format.",
            )
        })
}

/// Probe an endpoint: TCP connect latency + (optional) TLS + small download.
pub async fn check(ip: &str, port: u16, opts: &HealthOptions) -> HealthResult {
    let addr = match resolve(ip, port) {
        Ok(a) => a,
        Err(e) => {
            return HealthResult {
                ip: ip.to_string(),
                port,
                ok: false,
                tcp_ms: 0.0,
                connect_ms: 0.0,
                download_kbps: 0.0,
                error: Some(e.brief()),
            };
        }
    };

    let started = Instant::now();
    let res = tokio::time::timeout(opts.timeout, TcpStream::connect(addr)).await;
    let tcp_ms = started.elapsed().as_secs_f32() * 1000.0;
    match res {
        Ok(Ok(_stream)) => {}
        _ => {
            return HealthResult {
                ip: ip.to_string(),
                port,
                ok: false,
                tcp_ms,
                connect_ms: 0.0,
                download_kbps: 0.0,
                error: Some("TCP connect failed/timed out".into()),
            };
        }
    }

    // Now measure an TLS-ish GET over HTTP(S) to estimate throughput.
    let connect_started = Instant::now();
    let scheme = if opts.tls { "https" } else { "http" };
    let url = format!("{scheme}://{ip}:{port}/");

    let client = reqwest::Client::builder()
        .timeout(opts.timeout)
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| e.to_string());

    let mut download_kbps = 0.0_f32;
    let mut connect_ms = 0.0_f32;
    let mut ok = true;
    let mut error = None;

    if let Ok(client) = client {
        match client.get(&url).send().await {
            Ok(resp) => {
                let dl_started = Instant::now();
                let mut total = 0usize;
                let mut chunk = resp.bytes_stream();
                use futures_util::StreamExt;
                while let Some(item) = chunk.next().await {
                    match item {
                        Ok(bytes) => {
                            total += bytes.len();
                            if total >= opts.download_bytes {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let dl_secs = dl_started.elapsed().as_secs_f32().max(0.001);
                download_kbps = total as f32 / 1024.0 / dl_secs;
            }
            Err(e) => {
                // TLS/handshake or HTTP issue — still record connect time.
                connect_ms = connect_started.elapsed().as_secs_f32() * 1000.0;
                if !opts.tls {
                    ok = false;
                    error = Some(format!("HTTP GET failed: {e}"));
                }
            }
        }
    } else {
        ok = false;
        error = Some("Failed to build HTTP client".into());
    }

    if ok {
        connect_ms = connect_started.elapsed().as_secs_f32() * 1000.0;
    }

    HealthResult {
        ip: ip.to_string(),
        port,
        ok,
        tcp_ms,
        connect_ms,
        download_kbps,
        error,
    }
}

/// Derive the SNI / path / Host header for a WS probe from a vless link.
pub fn derive_ws_target(vless: &VlessProfile) -> WsTarget {
    let mut p = vless.clone();
    p.normalize();
    WsTarget {
        sni: p.sni.clone().unwrap_or_else(|| p.address.clone()),
        path: if p.path.is_empty() {
            "/".to_string()
        } else {
            percent_encoding::percent_decode_str(&p.path)
                .decode_utf8_lossy()
                .into_owned()
        },
        host: p.header_host.clone().unwrap_or_else(|| p.address.clone()),
    }
}

/// Lenient TLS verifier: we are fronting a Cloudflare edge and the worker
/// hostname is not the certificate owner — we intentionally skip cert-pinning.
/// This mirrors what a real v2ray/xray client does with `allowInsecure`.
#[derive(Debug)]
pub struct LenientVerifier;

impl ServerCertVerifier for LenientVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Build a lenient rustls ClientConfig for a given browser fingerprint profile.
/// The verifier is intentionally lenient because we front a Cloudflare edge and
/// the worker hostname is not the certificate owner (`allowInsecure`).
fn lenient_client_config(
    profile: crate::probe_jitter::ClientHelloProfile,
) -> Result<rustls::ClientConfig, CFError> {
    let provider = crate::probe_jitter::provider_for_profile(profile);
    Ok(
        rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| CFError::new("TLS config", format!("{e}"), ""))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(LenientVerifier))
            .with_no_client_auth(),
    )
}

/// Connect a TLS stream to `ip:port` using `sni` as the SNI hostname.
/// The ClientHello is rotated through browser fingerprint profiles (random per
/// connection) so the scanner's TLS signature is not static — the phase-2
/// resurrection fix for DPI blacklisting a fixed ClientHello.
pub async fn tls_connect(
    ip: &str,
    port: u16,
    sni: &str,
    timeout_ms: u64,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, CFError> {
    let addr: SocketAddr = format!("{ip}:{port}")
        .parse()
        .map_err(|e| CFError::new("Invalid addr", format!("{e}"), "Bad IP/port."))?;
    let tcp = tokio::time::timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr))
        .await
        .map_err(|_| CFError::new("Probe timeout", "TCP connect timed out.", ""))?
        .map_err(|e| CFError::new("Probe error", format!("TCP connect failed: {e}"), ""))?;

    let profile =
        crate::probe_jitter::pick_client_hello_profile(&mut rand::rngs::StdRng::from_entropy());
    let config = lenient_client_config(profile)?;
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(sni.to_string())
        .map_err(|_| CFError::new("Invalid SNI", "SNI must be a valid DNS name.", ""))?;
    let stream = tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        connector.connect(server_name, tcp),
    )
    .await
    .map_err(|_| CFError::new("TLS timeout", "TLS handshake timed out.", ""))?
    .map_err(|e| CFError::new("TLS error", format!("TLS handshake failed: {e}"), ""))?;
    Ok(stream)
}

/// Perform the TLS + RFC 6455 WebSocket upgrade probe.
///
/// `tls_sni` is the SNI used for the TLS handshake; `host` is the `Host`
/// header value in the WS request. Normally they are identical (the worker's
/// hostname). For the GenericCf SNI strategy they differ: the network sees a
/// benign CF-domain SNI while the Host header still routes to the worker.
pub async fn probe_ws_ex(
    ip: &str,
    port: u16,
    tls_sni: &str,
    host: &str,
    path: &str,
    timeout_ms: u64,
) -> WsProbe {
    let started = Instant::now();
    let mut probe = WsProbe {
        port,
        tls_ok: false,
        status: None,
        rtt_ms: 0,
        worker_bytes: 0,
        failure_stage: None,
        failure_reason: None,
        sni_used: tls_sni.to_string(),
    };

    let mut stream = match tls_connect(ip, port, tls_sni, timeout_ms).await {
        Ok(s) => s,
        Err(e) => {
            probe.failure_stage = Some("tls".into());
            // Bucket the failure at the catch point — this is how we tell
            // Cause A (DPI TLS reset) from a plain connect/network failure.
            probe.failure_reason = Some(match e.title.as_str() {
                "Probe timeout" => WsFailureReason::ConnectTimeout,
                "Probe error" => WsFailureReason::ConnectFailed,
                "TLS timeout" => WsFailureReason::TlsTimeout,
                _ => WsFailureReason::TlsAlert,
            });
            probe.rtt_ms = started.elapsed().as_millis() as u32;
            return probe;
        }
    };
    probe.tls_ok = true;
    probe.rtt_ms = started.elapsed().as_millis() as u32;

    // Random 16-byte Sec-WebSocket-Key (base64) per RFC 6455.
    use base64::Engine as _;
    use rand::Rng;
    use rand::SeedableRng as _;
    let mut key_bytes = [0u8; 16];
    rand::rngs::StdRng::from_entropy().fill(&mut key_bytes);
    let key = base64::engine::general_purpose::STANDARD.encode(key_bytes);

    let path = if path.is_empty() { "/" } else { path };
    let base_req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    // Anti-DPI: randomize the wire image per probe (shuffle header order +
    // random header-name casing). A fixed request gets blacklisted within
    // seconds on censored networks (SlipNet-style).
    let mut rng = rand::rngs::StdRng::from_entropy();
    let req = crate::probe_jitter::randomize_ws_request(&mut rng, base_req.as_bytes());
    if tokio::time::timeout(Duration::from_millis(timeout_ms), stream.write_all(&req))
        .await
        .is_err()
    {
        probe.failure_stage = Some("ws".into());
        probe.failure_reason = Some(WsFailureReason::WriteFailed);
        return probe;
    }
    if stream.flush().await.is_err() {
        probe.failure_stage = Some("ws".into());
        probe.failure_reason = Some(WsFailureReason::WriteFailed);
        return probe;
    }

    // Read the response, counting body bytes that arrive after the header's
    // \r\n\r\n terminator (a 101 with zero subsequent bytes = dead route).
    let mut buf = vec![0u8; 4096];
    let mut resp = Vec::new();
    let mut headers_done = false;
    let mut body_bytes = 0u32;
    let read_outcome = tokio::time::timeout(Duration::from_millis(timeout_ms), async {
        loop {
            let n = match stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            if !headers_done {
                resp.extend_from_slice(&buf[..n]);
                if let Some(pos) = resp.windows(4).position(|w| w == b"\r\n\r\n") {
                    headers_done = true;
                    body_bytes += (resp.len() - (pos + 4)) as u32;
                }
            } else {
                body_bytes += n as u32;
            }
            if body_bytes >= 1024 {
                break;
            }
        }
    })
    .await;

    if !headers_done {
        // No complete HTTP response arrived.
        probe.failure_stage = Some("ws".into());
        probe.failure_reason = Some(WsFailureReason::ResponseIncomplete);
        return probe;
    }

    let head_end = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(resp.len())
        + 4;
    let head_str = String::from_utf8_lossy(&resp[..head_end]);
    if head_str.starts_with("HTTP/1.1 101") {
        probe.status = Some(101);
        probe.worker_bytes = body_bytes;
        if probe.worker_bytes < MIN_WORKER_BYTES {
            // Edge upgraded but closed before sending a real worker payload:
            // dead route (no worker behind the edge) — Cause B.
            probe.failure_stage = Some("Ws_NoRoute".into());
            probe.failure_reason = Some(WsFailureReason::DeadRoute);
        } else {
            let _ = read_outcome;
        }
    } else {
        let status = head_str
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok());
        probe.status = status;
        probe.failure_stage = Some("ws".into());
        probe.failure_reason = Some(WsFailureReason::HttpStatus(status.unwrap_or(0)));
    }

    probe
}

/// Backward-compatible probe: single SNI used for both TLS and the Host header.
pub async fn probe_ws(ip: &str, port: u16, sni: &str, path: &str, timeout_ms: u64) -> WsProbe {
    probe_ws_ex(ip, port, sni, sni, path, timeout_ms).await
}

/// SNI strategies for the phase-2 probe: which SNI the probe offers in the
/// TLS handshake and how it falls back. This is the self-learning knob the
/// autopilot rotates when a strategy yields zero accepted `101`s for 3 cycles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SniStrategy {
    /// Use only the worker hostname for both SNI and Host.
    WorkerOnly,
    /// Try the worker hostname first, then a generic CF domain SNI.
    WorkerThenGenericCf,
    /// Try the generic CF SNI first (bypasses `*.workers.dev` SNI blocking),
    /// falling back to the worker hostname only if generic wins zero.
    GenericCfFirst,
}

/// Sweep `ports` with a fixed (tls_sni, host) pair, early-exiting on the first
/// accepted `101`. Returns per-port results up to and including the first hit.
async fn probe_ports_sni(
    ip: &str,
    tls_sni: &str,
    host: &str,
    path: &str,
    timeout_ms: u64,
    ports: &[u16],
) -> Vec<WsProbe> {
    let mut results = Vec::new();
    for &port in ports {
        let r = probe_ws_ex(ip, port, tls_sni, host, path, timeout_ms).await;
        let hit = r.status == Some(101) && r.worker_bytes >= MIN_WORKER_BYTES;
        results.push(r);
        if hit {
            break;
        }
    }
    results
}

/// Phase-2 fallback over an explicit port list: try `worker_sni` first; if
/// no edge accepts the WS gate under it, retry under `generic_cf_sni` (which
/// bypasses DPI that blocks `*.workers.dev` SNIs) while keeping `host` as the
/// Host header. Both passes' probes are returned (worker pass first) so the
/// phase-2 histogram captures the worker-pass TLS alerts too — that is the
/// whole point of the resurrection diagnosis. `probe_all_alt_ports_sni` calls
/// this with ALT_PORTS.
pub async fn probe_ports_sni_fallback(
    ip: &str,
    worker_sni: &str,
    generic_cf_sni: &str,
    host: &str,
    path: &str,
    timeout_ms: u64,
    ports: &[u16],
) -> Vec<WsProbe> {
    let worker_results = probe_ports_sni(ip, worker_sni, host, path, timeout_ms, ports).await;
    let any_hit = worker_results
        .iter()
        .any(|r| r.status == Some(101) && r.worker_bytes >= MIN_WORKER_BYTES);
    if any_hit {
        return worker_results;
    }
    let generic_results = probe_ports_sni(ip, generic_cf_sni, host, path, timeout_ms, ports).await;
    let mut combined = worker_results;
    combined.extend(generic_results);
    combined
}

/// Phase-2 probe across all alt ports with SNI-variant fallback.
pub async fn probe_all_alt_ports_sni(
    ip: &str,
    worker_sni: &str,
    generic_cf_sni: &str,
    host: &str,
    path: &str,
    timeout_ms: u64,
) -> Vec<WsProbe> {
    probe_ports_sni_fallback(
        ip,
        worker_sni,
        generic_cf_sni,
        host,
        path,
        timeout_ms,
        ALT_PORTS,
    )
    .await
}

/// Backward-compatible single-SNI sweep across all alt ports.
pub async fn probe_all_alt_ports(ip: &str, sni: &str, path: &str, timeout_ms: u64) -> Vec<WsProbe> {
    probe_all_alt_ports_sni(ip, sni, sni, sni, path, timeout_ms).await
}

/// Outcome of a budgeted parallel light-check on one endpoint.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EndpointLiveResult {
    /// True if any port returned 101 + >= MIN_WORKER_BYTES.
    pub alive: bool,
    /// The port that passed (None if not alive).
    pub responding_port: Option<u16>,
    /// TLS RTT of the winning probe (None if not alive).
    pub rtt_ms: Option<u32>,
    /// Bucketed reason when not alive.
    pub failure_stage: Option<EndpointFailureStage>,
    /// Wall-clock time the whole sweep took.
    pub elapsed_ms: u64,
    /// Number of probes launched.
    pub probes_attempted: u32,
    /// Number of probes that settled before the budget/winner ended the sweep.
    pub probes_completed: u32,
}

/// Why a budgeted endpoint check did not find a live port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EndpointFailureStage {
    /// No port responded to TCP within the budget (all connect failed/timeout).
    TcpTimeoutAllPorts,
    /// Ports responded but every TLS handshake was reset (DPI signature).
    TlsResetAllPorts,
    /// Ports passed TLS but none returned a 101 WS upgrade.
    WsUpgradeAllPorts,
    /// Got 101 but all below MIN_WORKER_BYTES (dead route).
    WorkerBytesAllPorts,
    /// The overall budget elapsed before any probe settled.
    BudgetExceeded,
}

/// Sweep `ports` **in parallel**, each probe with its own per-probe timeout,
/// wrapped in an overall `total_budget`. First 101 + MIN_WORKER_BYTES wins and
/// aborts the remaining in-flight probes (they are dropped, not awaited). If
/// `total_budget` elapses before any settles → `BudgetExceeded`. If all settle
/// without a winner, the failure mode is aggregated.
///
/// This is what the monitor's tier-1 light check uses. It prevents a single
/// stale/hanging endpoint from eating the whole monitor budget — the exact live
/// failure observed in round 6 (`CycleTimeout` at 120s, `last_stage: null`).
pub async fn probe_ports_budgeted(
    ip: &str,
    sni: &str,
    host: &str,
    path: &str,
    ports: &[u16],
    total_budget: Duration,
    per_probe_timeout: Duration,
) -> EndpointLiveResult {
    let started = Instant::now();
    let per_ms = per_probe_timeout.as_millis() as u64;
    let deadline = tokio::time::Instant::now() + total_budget;

    let mut set = tokio::task::JoinSet::new();
    for &port in ports {
        let ip = ip.to_string();
        let sni = sni.to_string();
        let host = host.to_string();
        let path = path.to_string();
        set.spawn(async move {
            probe_ws_ex(&ip, port, &sni, &host, &path, per_ms).await
        });
    }
    let attempted = ports.len() as u32;
    let mut completed = 0u32;
    let mut probes: Vec<WsProbe> = Vec::with_capacity(ports.len());

    while let Ok(Some(res)) = tokio::time::timeout_at(deadline, set.join_next()).await {
        let probe = match res {
            Ok(p) => p,
            Err(_) => continue, // a probe task panicked — ignore, keep going
        };
        completed += 1;
        if probe.status == Some(101) && probe.worker_bytes >= MIN_WORKER_BYTES {
            let elapsed_ms = started.elapsed().as_millis() as u64;
            set.abort_all();
            return EndpointLiveResult {
                alive: true,
                responding_port: Some(probe.port),
                rtt_ms: Some(probe.rtt_ms),
                failure_stage: None,
                elapsed_ms,
                probes_attempted: attempted,
                probes_completed: completed,
            };
        }
        probes.push(probe);
    }

    let elapsed_ms = started.elapsed().as_millis() as u64;
    // If the loop exited because the deadline fired, some probes are still
    // in flight → BudgetExceeded. If join_next returned None, all settled.
    let budget_exceeded = !set.is_empty();
    set.abort_all();

    if budget_exceeded {
        return EndpointLiveResult {
            alive: false,
            responding_port: None,
            rtt_ms: None,
            failure_stage: Some(EndpointFailureStage::BudgetExceeded),
            elapsed_ms,
            probes_attempted: attempted,
            probes_completed: completed,
        };
    }

    let failure_stage = aggregate_endpoint_failure(&probes);
    EndpointLiveResult {
        alive: false,
        responding_port: None,
        rtt_ms: None,
        failure_stage: Some(failure_stage),
        elapsed_ms,
        probes_attempted: attempted,
        probes_completed: completed,
    }
}

/// Aggregate the per-probe failure reasons into one `EndpointFailureStage`.
pub fn aggregate_endpoint_failure(probes: &[WsProbe]) -> EndpointFailureStage {
    if probes.is_empty() {
        return EndpointFailureStage::WsUpgradeAllPorts;
    }
    let total = probes.len();
    let tcp = probes
        .iter()
        .filter(|p| {
            matches!(
                p.failure_reason,
                Some(WsFailureReason::ConnectFailed)
                    | Some(WsFailureReason::ConnectTimeout)
                    | Some(WsFailureReason::TlsTimeout)
            )
        })
        .count();
    let tls_reset = probes
        .iter()
        .filter(|p| p.failure_reason == Some(WsFailureReason::TlsAlert))
        .count();
    let worker_bytes = probes
        .iter()
        .filter(|p| p.status == Some(101) && p.worker_bytes < MIN_WORKER_BYTES)
        .count();

    if tcp == total {
        return EndpointFailureStage::TcpTimeoutAllPorts;
    }
    // >80% of responding ports hit a TLS alert → DPI/ClientHello signature.
    if tls_reset > 0 && tls_reset * 10 >= total * 8 {
        return EndpointFailureStage::TlsResetAllPorts;
    }
    if worker_bytes == total {
        return EndpointFailureStage::WorkerBytesAllPorts;
    }
    EndpointFailureStage::WsUpgradeAllPorts
}

/// Budgeted version of `endpoint_live` — same SNI/Host semantics (worker SNI
/// and Host both = `sni`), but the alt-port sweep runs in parallel under a
/// total budget so one hanging port cannot stall the monitor. Returns a rich
/// `EndpointLiveResult` instead of a bare bool.
pub async fn endpoint_live_with_budget(
    ip: &str,
    sni: &str,
    path: &str,
    total_budget: Duration,
    per_probe_timeout: Duration,
) -> EndpointLiveResult {
    probe_ports_budgeted(
        ip,
        sni,
        sni,
        path,
        ALT_PORTS,
        total_budget,
        per_probe_timeout,
    )
    .await
}

/// Convenience: try SNI variants according to a [`SniStrategy`].
pub async fn probe_with_sni_strategy(
    ip: &str,
    worker_sni: &str,
    generic_cf_sni: &str,
    host: &str,
    path: &str,
    timeout_ms: u64,
    strategy: SniStrategy,
) -> Vec<WsProbe> {
    match strategy {
        SniStrategy::WorkerOnly => {
            probe_ports_sni(ip, worker_sni, host, path, timeout_ms, ALT_PORTS).await
        }
        SniStrategy::WorkerThenGenericCf => {
            probe_all_alt_ports_sni(ip, worker_sni, generic_cf_sni, host, path, timeout_ms).await
        }
        SniStrategy::GenericCfFirst => {
            // Generic CF SNI first (bypasses `*.workers.dev` SNI blocking);
            // only if it wins zero do we fall back to the worker hostname.
            let generic_results =
                probe_ports_sni(ip, generic_cf_sni, host, path, timeout_ms, ALT_PORTS).await;
            let any_hit = generic_results
                .iter()
                .any(|r| r.status == Some(101) && r.worker_bytes >= MIN_WORKER_BYTES);
            if any_hit {
                return generic_results;
            }
            let mut combined = generic_results;
            combined
                .extend(probe_ports_sni(ip, worker_sni, host, path, timeout_ms, ALT_PORTS).await);
            combined
        }
    }
}

/// The TCP fast-fail probe (SlipNet style). A tunnel with RTT above this
/// threshold is unusable even if it connects, so we drop it before any TLS/WS
/// work.
pub const FAST_FAIL_MS: u64 = 1500;

#[derive(Debug, Clone)]
pub struct FastProbe {
    pub rtt_ms: u32,
    pub passed: bool,
}

/// TCP-only hard-capped probe. `passed` = false if rtt > FAST_FAIL_MS or the
/// connect failed/timed out.
pub async fn probe_fast(ip: &str, port: u16, timeout_ms: u64) -> FastProbe {
    let started = Instant::now();
    let addr: SocketAddr = match format!("{ip}:{port}").parse() {
        Ok(a) => a,
        Err(_) => {
            return FastProbe {
                rtt_ms: 0,
                passed: false,
            }
        }
    };
    let res =
        tokio::time::timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await;
    let rtt_ms = started.elapsed().as_millis() as u32;
    let ok = matches!(res, Ok(Ok(_)));
    FastProbe {
        rtt_ms,
        passed: ok && rtt_ms <= (FAST_FAIL_MS as u32),
    }
}

/// TCP-only fast probe across the alt-port set, early-exiting on the first
/// port that connects. This matters on censored networks where 443 is
/// throttled but the alt ports stay open — an IP that is alive only on 2053/
/// 8443/etc. must NOT be discarded by the phase-1 prefilter.
pub async fn probe_fast_any_port(ip: &str, timeout_ms: u64) -> FastProbe {
    for &port in ALT_PORTS {
        let p = probe_fast(ip, port, timeout_ms).await;
        if p.passed {
            return p;
        }
    }
    FastProbe {
        rtt_ms: 0,
        passed: false,
    }
}

/// The full probe evidence used by the quality score.
#[derive(Debug, Clone)]
pub struct FullProbe {
    pub tcp_ms: u32,
    pub tls_ok: bool,
    pub ws_ok: bool,
    pub latency_under_1500: bool,
    pub throughput_floor: bool,
    pub alt_port_ok: bool,
}

/// 7-dimension quality score.
/// Dimensions: tcp_ok(1) + tls_ok(1) + ws_ok(2) + latency_under_1500(1) +
/// throughput_floor(1) + alt_port_ok(1) = max 7.
pub fn quality_score(p: &FullProbe) -> u8 {
    let mut s = 0u8;
    if p.tcp_ms > 0 {
        s += 1;
    }
    if p.tls_ok {
        s += 1;
    }
    if p.ws_ok {
        s += 2;
    }
    if p.latency_under_1500 {
        s += 1;
    }
    if p.throughput_floor {
        s += 1;
    }
    if p.alt_port_ok {
        s += 1;
    }
    s
}

/// Minimum accepted score. Below this the endpoint is rejected.
pub const ACCEPT_THRESHOLD: u8 = 5;

/// Signatures of DPI DNS hijack on censored networks. 198.18.0.0/15 is the
/// RFC 2544 benchmark range, which ISPs in Iran use to poison A-record answers
/// for blocked domains. If every resolved address for a hostname lands in this
/// range, the resolution is hijacked and must not be trusted.
pub fn is_hijacked_ip(ip: &std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 198 && octets[1] == 18
}

pub fn is_acceptable(p: &FullProbe) -> bool {
    quality_score(p) >= ACCEPT_THRESHOLD
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // --- mock TLS + WebSocket upgrade server ---

    fn mock_cert() -> rcgen::CertifiedKey {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["mock.test".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        rcgen::CertifiedKey {
            cert,
            key_pair: key,
        }
    }

    /// Gate the TLS handshake on the requested SNI. `None` accepts any SNI;
    /// `Some(s)` only completes the handshake when the client's SNI equals
    /// `s` (otherwise the handshake fails → the client records a TLS alert).
    #[derive(Debug)]
    struct SniGateResolver {
        required: Option<String>,
        certified_key: Arc<rustls::sign::CertifiedKey>,
    }

    impl rustls::server::ResolvesServerCert for SniGateResolver {
        fn resolve(
            &self,
            hello: rustls::server::ClientHello,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            match &self.required {
                None => Some(self.certified_key.clone()),
                Some(req) if hello.server_name() == Some(req.as_str()) => {
                    Some(self.certified_key.clone())
                }
                _ => None,
            }
        }
    }

    /// Spawn a mock TLS server on an ephemeral loopback port.
    /// `mode` controls the response: "accept" → 101 + payload,
    /// "200" → 200, "404" → 404, "403" → 403, "421" → 421,
    /// "accept_empty" → 101 without payload, "reset" → drop the socket
    /// before TLS completes (simulates a connection reset / DPI interference).
    /// `require_sni` optionally gates the handshake on a specific SNI.
    async fn start_mock_server_gated(mode: &str, require_sni: Option<&str>) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mode = mode.to_string();
        let require_sni = require_sni.map(|s| s.to_string());
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let mode = mode.clone();
                let req = require_sni.clone();
                tokio::spawn(async move {
                    handle_tls_client_gated(tcp, &mode, req.as_deref()).await;
                });
            }
        });
        port
    }

    async fn start_mock_server(mode: &str) -> u16 {
        start_mock_server_gated(mode, None).await
    }

    async fn handle_tls_client_gated(
        tcp: tokio::net::TcpStream,
        mode: &str,
        require_sni: Option<&str>,
    ) {
        let key = mock_cert();
        let cert_der = rustls::pki_types::CertificateDer::from(key.cert);
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(key.key_pair.serialize_der().into());
        let signing_key =
            rustls::crypto::aws_lc_rs::sign::any_supported_type(&key_der).expect("signing key");
        let certified_key = Arc::new(rustls::sign::CertifiedKey::new(vec![cert_der], signing_key));
        let resolver = SniGateResolver {
            required: require_sni.map(|s| s.to_string()),
            certified_key,
        };
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        // "reset" mode: drop the raw TCP socket before TLS — simulates DPI
        // resetting the handshake (connection reset).
        if mode == "reset" {
            drop(tcp);
            return;
        }
        let mut stream = match acceptor.accept(tcp).await {
            Ok(s) => s,
            Err(_) => return,
        };
        // read request head up to \r\n\r\n
        let mut buf = vec![0u8; 4096];
        let mut head = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    head.extend_from_slice(&buf[..n]);
                    if head.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                _ => return,
            }
        }
        let response = match mode {
            "accept" => {
                // Send a payload large enough to pass the MIN_WORKER_BYTES
                // gate — a real worker sends well over 512 bytes.
                let payload = "worker-payload-bytes".repeat(40); // ~760 bytes
                format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: abc123\r\n\r\n{payload}"
                )
            }
            "200" => "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_string(),
            "404" => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string(),
            "403" => "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_string(),
            "421" => "HTTP/1.1 421 Misdirected Request\r\nContent-Length: 0\r\n\r\n".to_string(),
            "accept_empty" => concat!(
                "HTTP/1.1 101 Switching Protocols\r\n",
                "Upgrade: websocket\r\n",
                "Connection: Upgrade\r\n",
                "Sec-WebSocket-Accept: abc123\r\n",
                "\r\n"
            )
            .to_string(),
            _ => "HTTP/1.1 101 Switching Protocols\r\n\r\nb".to_string(),
        };
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.flush().await;
    }

    // --- tests ---

    #[test]
    fn resolve_parses_ip_port() {
        let a = resolve("1.2.3.4", 443).unwrap();
        assert_eq!(a.to_string(), "1.2.3.4:443");
    }

    #[test]
    fn resolve_rejects_garbage() {
        assert!(resolve("not an ip", 443).is_err());
    }

    #[test]
    fn is_hijacked_detects_198_18_range() {
        use std::net::Ipv4Addr;
        assert!(is_hijacked_ip(&Ipv4Addr::new(198, 18, 0, 1)));
        assert!(is_hijacked_ip(&Ipv4Addr::new(198, 18, 7, 152)));
        assert!(is_hijacked_ip(&Ipv4Addr::new(198, 18, 255, 255)));
    }

    #[test]
    fn is_hijacked_rejects_public_ips() {
        use std::net::Ipv4Addr;
        assert!(!is_hijacked_ip(&Ipv4Addr::new(104, 16, 132, 229)));
        assert!(!is_hijacked_ip(&Ipv4Addr::new(188, 114, 96, 3)));
        assert!(!is_hijacked_ip(&Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_hijacked_ip(&Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[tokio::test]
    async fn test_probe_ws_accepts_101() {
        let port = start_mock_server("accept").await;
        let p = probe_ws("127.0.0.1", port, "mock.test", "/ws", 5000).await;
        assert!(p.tls_ok);
        assert_eq!(p.status, Some(101));
        assert!(p.worker_bytes > 0);
        assert!(p.failure_stage.is_none());
    }

    #[tokio::test]
    async fn test_probe_ws_rejects_200_without_upgrade() {
        let port = start_mock_server("200").await;
        let p = probe_ws("127.0.0.1", port, "mock.test", "/ws", 5000).await;
        assert!(p.tls_ok);
        assert_eq!(p.status, Some(200));
        assert_eq!(p.failure_stage.as_deref(), Some("ws"));
    }

    #[tokio::test]
    async fn test_probe_ws_rejects_404_worker_path() {
        let port = start_mock_server("404").await;
        let p = probe_ws("127.0.0.1", port, "mock.test", "/ws", 5000).await;
        assert_eq!(p.status, Some(404));
        assert_eq!(p.failure_stage.as_deref(), Some("ws"));
    }

    #[tokio::test]
    async fn test_probe_ws_requires_nonzero_worker_bytes() {
        let port = start_mock_server("accept_empty").await;
        let p = probe_ws("127.0.0.1", port, "mock.test", "/ws", 5000).await;
        assert_eq!(p.status, Some(101));
        assert_eq!(p.worker_bytes, 0);
        assert_eq!(p.failure_stage.as_deref(), Some("Ws_NoRoute"));
    }

    #[tokio::test]
    async fn test_probe_ws_accepts_full_payload() {
        let port = start_mock_server("accept").await;
        let p = probe_ws("127.0.0.1", port, "mock.test", "/ws", 5000).await;
        assert_eq!(p.status, Some(101));
        assert!(p.worker_bytes >= MIN_WORKER_BYTES, "got {}", p.worker_bytes);
        assert!(p.failure_stage.is_none());
    }

    #[tokio::test]
    async fn test_probe_ws_reports_tls_failure_stage() {
        // listen then drop -> nothing accepts -> TCP connect fails fast
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let p = probe_ws("127.0.0.1", port, "mock.test", "/ws", 2000).await;
        assert!(!p.tls_ok);
        assert_eq!(p.failure_stage.as_deref(), Some("tls"));
    }

    #[test]
    fn test_derive_ws_target_from_vless_link() {
        let link = "vless://8274e874-7470-43ee-8018-4bc3baa709a5@104.17.147.186:443?encryption=none&security=tls&type=ws&sni=amir.dariuskhosrowan.workers.dev&host=amir.dariuskhosrowan.workers.dev&path=%2F&fp=chrome#amir";
        let profile = VlessProfile::parse(link).unwrap();
        let t = derive_ws_target(&profile);
        assert_eq!(t.sni, "amir.dariuskhosrowan.workers.dev");
        assert_eq!(t.path, "/");
        assert_eq!(t.host, "amir.dariuskhosrowan.workers.dev");
    }

    #[tokio::test]
    async fn test_probe_ports_returns_per_port() {
        let p200 = start_mock_server("200").await;
        let p404 = start_mock_server("404").await;
        let results = probe_ports_sni(
            "127.0.0.1",
            "mock.test",
            "mock.test",
            "/ws",
            5000,
            &[p200, p404],
        )
        .await;
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].status, Some(200));
        assert_eq!(results[1].status, Some(404));
    }

    #[tokio::test]
    async fn test_probe_ports_early_exits_on_first_101() {
        let p101 = start_mock_server("accept").await;
        let p200 = start_mock_server("200").await;
        let results = probe_ports_sni(
            "127.0.0.1",
            "mock.test",
            "mock.test",
            "/ws",
            5000,
            &[p101, p200],
        )
        .await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, Some(101));
    }

    #[test]
    fn test_quality_score_all_seven_dimensions() {
        let p = FullProbe {
            tcp_ms: 100,
            tls_ok: true,
            ws_ok: true,
            latency_under_1500: true,
            throughput_floor: true,
            alt_port_ok: true,
        };
        assert_eq!(quality_score(&p), 7);
    }

    #[test]
    fn test_quality_score_ws_failure_critical() {
        let p = FullProbe {
            tcp_ms: 100,
            tls_ok: true,
            ws_ok: false,
            latency_under_1500: true,
            throughput_floor: true,
            alt_port_ok: false,
        };
        assert_eq!(quality_score(&p), 4);
        assert!(!is_acceptable(&p));
    }

    #[test]
    fn test_quality_score_rejects_below_threshold() {
        let p = FullProbe {
            tcp_ms: 100,
            tls_ok: true,
            ws_ok: false,
            latency_under_1500: true,
            throughput_floor: false,
            alt_port_ok: false,
        };
        assert_eq!(quality_score(&p), 3);
        assert!(!is_acceptable(&p));
    }

    #[test]
    fn test_quality_score_alt_port_bonus() {
        let p = FullProbe {
            tcp_ms: 100,
            tls_ok: true,
            ws_ok: true,
            latency_under_1500: true,
            throughput_floor: true,
            alt_port_ok: false,
        };
        assert_eq!(quality_score(&p), 6);
        let p2 = FullProbe {
            alt_port_ok: true,
            ..p
        };
        assert_eq!(quality_score(&p2), 7);
    }

    #[test]
    fn test_is_acceptable_at_threshold_boundary() {
        let mut p = FullProbe {
            tcp_ms: 100,
            tls_ok: true,
            ws_ok: true,
            latency_under_1500: true,
            throughput_floor: true,
            alt_port_ok: false,
        };
        assert_eq!(quality_score(&p), 6);
        assert!(is_acceptable(&p));
        p.ws_ok = false;
        p.throughput_floor = false;
        assert_eq!(quality_score(&p), 3);
        assert!(!is_acceptable(&p));
    }

    #[tokio::test]
    async fn probe_fast_any_port_finds_open_port() {
        // Open a listener on an ephemeral loopback port, then verify the
        // any-port probe finds it even though the first ALT_PORTS entries
        // are closed.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 16];
                let _ = sock.read(&mut buf).await;
            }
        });
        let p = probe_fast_any_port("127.0.0.1", 3000).await;
        // Our test port is not in ALT_PORTS, so the any-port probe won't find
        // it — this just asserts the function runs and returns a FastProbe.
        let _ = p;
        // The real test: a port in ALT_PORTS that's open.
        // Simulate by binding one of the alt ports on loopback if free.
        let alt = ALT_PORTS
            .iter()
            .find(|p| std::net::TcpListener::bind(format!("127.0.0.1:{p}")).is_ok())
            .copied();
        if let Some(alt_port) = alt {
            let l = tokio::net::TcpListener::bind(format!("127.0.0.1:{alt_port}"))
                .await
                .unwrap();
            let _ = l;
            let q = probe_fast_any_port("127.0.0.1", 3000).await;
            assert!(q.passed, "expected alt port {alt_port} to be reachable");
        }
    }

    // ── Phase-2 resurrection tests (2026-11) ──
    // Each failure at the catch point must be bucketed into a WsFailureReason
    // so the histogram can tell Cause A (DPI TLS reset) from Cause B (dead
    // worker route) in one run — DeepSeek's phase2 resurrection spec.

    #[tokio::test]
    async fn test_ws_probe_records_http_403() {
        let p = start_mock_server("403").await;
        let r = probe_ws("127.0.0.1", p, "mock.test", "/ws", 5000).await;
        assert_eq!(r.status, Some(403));
        assert_eq!(r.failure_reason, Some(WsFailureReason::HttpStatus(403)));
        assert_eq!(r.sni_used, "mock.test");
    }

    #[tokio::test]
    async fn test_ws_probe_records_http_421() {
        let p = start_mock_server("421").await;
        let r = probe_ws("127.0.0.1", p, "mock.test", "/ws", 5000).await;
        assert_eq!(r.status, Some(421));
        assert_eq!(r.failure_reason, Some(WsFailureReason::HttpStatus(421)));
    }

    #[tokio::test]
    async fn test_ws_probe_records_upgrade_missing_on_200() {
        let p = start_mock_server("200").await;
        let r = probe_ws("127.0.0.1", p, "mock.test", "/ws", 5000).await;
        assert_eq!(r.status, Some(200));
        assert_eq!(r.failure_reason, Some(WsFailureReason::HttpStatus(200)));
        assert_eq!(r.failure_stage.as_deref(), Some("ws"));
    }

    #[tokio::test]
    async fn test_ws_probe_records_tls_alert_on_connection_reset() {
        // The "reset" mock drops the socket before TLS completes — this is the
        // DPI signature (Cause A). It must bucket to TlsAlert, not a WS-stage
        // reason, so the histogram separates it from dead-route causes.
        let p = start_mock_server("reset").await;
        let r = probe_ws("127.0.0.1", p, "mock.test", "/ws", 2000).await;
        assert!(!r.tls_ok);
        assert_eq!(r.failure_reason, Some(WsFailureReason::TlsAlert));
        assert_eq!(r.failure_stage.as_deref(), Some("tls"));
    }

    #[tokio::test]
    async fn test_ws_probe_records_dead_route() {
        let p = start_mock_server("accept_empty").await;
        let r = probe_ws("127.0.0.1", p, "mock.test", "/ws", 5000).await;
        assert_eq!(r.status, Some(101));
        assert_eq!(r.failure_reason, Some(WsFailureReason::DeadRoute));
        assert_eq!(r.failure_stage.as_deref(), Some("Ws_NoRoute"));
    }

    #[tokio::test]
    async fn test_probe_ws_multi_sni_tries_worker_first() {
        // A mock that only completes the handshake when the SNI is the worker
        // hostname. Probing with the worker SNI must hit immediately, so the
        // generic-CF fallback is never reached.
        let p = start_mock_server_gated("accept", Some("worker.test")).await;
        let results =
            probe_ports_sni("127.0.0.1", "worker.test", "worker.test", "/ws", 5000, &[p]).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, Some(101));
        assert_eq!(results[0].sni_used, "worker.test");
    }

    #[tokio::test]
    async fn test_probe_ws_multi_sni_falls_back_to_generic_cf() {
        // The mock only accepts the *generic* CF SNI. The worker-SNI pass
        // fails (handshake rejected), so the fallback must retry under the
        // generic CF SNI — proving the GenericCf bypass.
        let p = start_mock_server_gated("accept", Some("generic.cloudflare.com")).await;
        let results = probe_ports_sni_fallback(
            "127.0.0.1",
            "worker.test",
            "generic.cloudflare.com",
            "worker.test",
            "/ws",
            5000,
            &[p],
        )
        .await;
        assert_eq!(results.len(), 2, "worker pass + generic fallback pass");
        // The worker pass (first) must have failed at TLS.
        assert!(!results[0].tls_ok);
        assert_eq!(results[0].failure_reason, Some(WsFailureReason::TlsAlert));
        // The fallback pass must have found the worker under the generic SNI.
        assert_eq!(results[1].status, Some(101));
        assert!(results[1].worker_bytes >= MIN_WORKER_BYTES);
        assert_eq!(results[1].sni_used, "generic.cloudflare.com");
    }

    // ── Budgeted parallel light-check (round 7) ──

    /// Bind a TCP listener that accepts connections but NEVER responds — the
    /// TLS handshake blocks forever. Simulates a censored/blackholed port.
    async fn start_hanging_server() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = listener.accept().await {
                tokio::spawn(async move {
                    // Wait for a client, then just sit on a blocked read forever
                    // (never write anything → TLS never progresses).
                    let mut buf = [0u8; 1024];
                    loop {
                        let _ = tcp.read(&mut buf).await;
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                });
            }
        });
        port
    }

    /// The core TDD test: a single hanging endpoint must NOT be able to eat the
    /// whole monitor budget. With per-probe timeout larger than the total
    /// budget, the budget MUST fire first → `BudgetExceeded`, and elapsed must
    /// stay within budget + tolerance.
    #[tokio::test]
    async fn test_endpoint_live_with_budget_respects_total_budget() {
        // Mock all 9 ports to hang.
        let mut ports = Vec::new();
        for _ in 0..ALT_PORTS.len() {
            ports.push(start_hanging_server().await);
        }
        let started = Instant::now();
        let res = probe_ports_budgeted(
            "127.0.0.1",
            "worker.test",
            "worker.test",
            "/ws",
            &ports,
            Duration::from_secs(5),
            Duration::from_secs(30),
        )
        .await;
        let elapsed_ms = started.elapsed().as_millis() as u64;
        assert!(!res.alive);
        assert_eq!(
            res.failure_stage,
            Some(EndpointFailureStage::BudgetExceeded),
            "expected BudgetExceeded, got {:?} (elapsed={elapsed_ms}ms)",
            res.failure_stage
        );
        assert!(
            elapsed_ms <= 5500,
            "elapsed {elapsed_ms}ms > 5s budget + 500ms tolerance"
        );
        assert!(res.elapsed_ms <= 5500, "report elapsed {}", res.elapsed_ms);
    }

    /// First-101 wins: a responder on one port + hang on the rest → alive with a
    /// short elapsed (we must not wait for the hanging ports).
    #[tokio::test]
    async fn test_endpoint_live_with_budget_returns_alive_on_first_101() {
        let responder = start_mock_server("accept").await;
        let mut ports = vec![responder];
        for _ in 0..2 {
            ports.push(start_hanging_server().await);
        }
        let started = Instant::now();
        let res = probe_ports_budgeted(
            "127.0.0.1",
            "worker.test",
            "worker.test",
            "/ws",
            &ports,
            Duration::from_secs(10),
            Duration::from_secs(3),
        )
        .await;
        let elapsed_ms = started.elapsed().as_millis() as u64;
        assert!(res.alive, "alive=false, stage={:?}", res.failure_stage);
        assert_eq!(res.responding_port, Some(responder));
        assert!(
            elapsed_ms < 5000,
            "should not wait for hanging ports: elapsed={elapsed_ms}ms"
        );
    }

    /// All ports respond but all TLS-reset (DPI signature) → aggregated
    /// `TlsResetAllPorts`.
    #[tokio::test]
    async fn test_endpoint_live_with_budget_aggregates_tls_reset_failures() {
        let mut ports = Vec::new();
        for _ in 0..3 {
            ports.push(start_mock_server("reset").await);
        }
        let res = probe_ports_budgeted(
            "127.0.0.1",
            "worker.test",
            "worker.test",
            "/ws",
            &ports,
            Duration::from_secs(10),
            Duration::from_secs(3),
        )
        .await;
        assert!(!res.alive);
        assert_eq!(
            res.failure_stage,
            Some(EndpointFailureStage::TlsResetAllPorts)
        );
    }

    /// All ports unreachable (connect refused) → `TcpTimeoutAllPorts`.
    #[tokio::test]
    async fn test_endpoint_live_with_budget_aggregates_tcp_timeouts() {
        // Bind listeners and close them immediately so connect is refused.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener); // port now closed → ECONNREFUSED
        let res = probe_ports_budgeted(
            "127.0.0.1",
            "worker.test",
            "worker.test",
            "/ws",
            &[port, port, port],
            Duration::from_secs(10),
            Duration::from_secs(3),
        )
        .await;
        assert!(!res.alive);
        assert_eq!(
            res.failure_stage,
            Some(EndpointFailureStage::TcpTimeoutAllPorts)
        );
    }

    /// Confirms the parallel sweep actually drops remaining probes once a winner
    /// is found (they don't delay us).
    #[tokio::test]
    async fn test_endpoint_live_with_budget_drops_remaining_probes_after_winner() {
        let responder = start_mock_server("accept").await;
        let mut ports = vec![responder];
        for _ in 0..2 {
            ports.push(start_hanging_server().await);
        }
        let res = probe_ports_budgeted(
            "127.0.0.1",
            "worker.test",
            "worker.test",
            "/ws",
            &ports,
            Duration::from_secs(10),
            Duration::from_secs(3),
        )
        .await;
        assert!(res.alive);
        assert!(res.elapsed_ms < 2000, "elapsed {}", res.elapsed_ms);
    }
}
