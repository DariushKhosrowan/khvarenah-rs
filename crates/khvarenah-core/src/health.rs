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

use crate::error::CFError;
use crate::vless::VlessProfile;

/// Cloudflare alt-ports, ordered by usefulness on censored networks.
/// 443 is often the most-throttled port (every VPN uses it); the alt ports
/// are frequently left open because DPI assumes "real HTTPS uses 443".
pub const ALT_PORTS: &[u16] = &[443, 2053, 2087, 2096, 8443, 2083, 2082, 8880, 2052];

/// Minimum worker payload bytes for a WS-upgrade to count as a real route.
/// A 101 that immediately closes with < this many bytes is a dead route
/// (edge upgraded but no worker behind it). (DeepSeek plan, Phase 3.)
pub const MIN_WORKER_BYTES: u32 = 512;

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

/// Connect a TLS stream to `ip:port` using `sni` as the SNI hostname.
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

    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| CFError::new("TLS config", format!("{e}"), ""))?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(LenientVerifier))
    .with_no_client_auth();
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
/// Sends a minimal handshake request to `sni`'s `path` at `ip:port`, asserts a
/// `101 Switching Protocols` response line, and counts the bytes received after
/// the upgrade. Returns the detailed verdict.
pub async fn probe_ws(ip: &str, port: u16, sni: &str, path: &str, timeout_ms: u64) -> WsProbe {
    let started = Instant::now();
    let mut probe = WsProbe {
        port,
        tls_ok: false,
        status: None,
        rtt_ms: 0,
        worker_bytes: 0,
        failure_stage: None,
    };

    let mut stream = match tls_connect(ip, port, sni, timeout_ms).await {
        Ok(s) => s,
        Err(e) => {
            probe.failure_stage = Some("tls".into());
            probe.rtt_ms = started.elapsed().as_millis() as u32;
            let _ = e;
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
        "GET {path} HTTP/1.1\r\nHost: {sni}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    // Anti-DPI: randomize the wire image per probe (shuffle header order +
    // random header-name casing). A fixed request gets blacklisted within
    // seconds on censored networks (SlipNet-style).
    let mut rng = rand::rngs::StdRng::from_entropy();
    let req = crate::probe_jitter::randomize_ws_request(&mut rng, base_req.as_bytes());

    if let Err(e) =
        tokio::time::timeout(Duration::from_millis(timeout_ms), stream.write_all(&req)).await
    {
        probe.failure_stage = Some("ws".into());
        let _ = e;
        return probe;
    }
    if let Err(e) = stream.flush().await {
        probe.failure_stage = Some("ws".into());
        let _ = e;
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
            // dead route (no worker behind the edge).
            probe.failure_stage = Some("Ws_NoRoute".into());
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
    }

    probe
}

/// Sweep `ports` in order, early-exiting on the first `101` hit. Returns
/// per-port results up to and including the first accepted end.
async fn probe_ports(
    ip: &str,
    sni: &str,
    path: &str,
    timeout_ms: u64,
    ports: &[u16],
) -> Vec<WsProbe> {
    let mut results = Vec::new();
    for &port in ports {
        let r = probe_ws(ip, port, sni, path, timeout_ms).await;
        let hit = r.status == Some(101) && r.worker_bytes >= MIN_WORKER_BYTES;
        results.push(r);
        if hit {
            break;
        }
    }
    results
}

/// Sweep a candidate edge across all `ALT_PORTS`, early-exiting on the first
/// `101`. Returns per-port results.
pub async fn probe_all_alt_ports(ip: &str, sni: &str, path: &str, timeout_ms: u64) -> Vec<WsProbe> {
    probe_ports(ip, sni, path, timeout_ms, ALT_PORTS).await
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

    /// Spawn a mock TLS server on an ephemeral loopback port.
    /// `mode` controls the response: "accept" → 101 + payload,
    /// "200" → 200, "404" → 404, "accept_empty" → 101 without payload.
    async fn start_mock_server(mode: &str) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mode = mode.to_string();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let mode = mode.clone();
                tokio::spawn(async move {
                    handle_tls_client(tcp, &mode).await;
                });
            }
        });
        port
    }

    async fn handle_tls_client(tcp: tokio::net::TcpStream, mode: &str) {
        let key = mock_cert();
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(key.key_pair.serialize_der().into());
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![key.cert.into()], key_der)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
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
        let results = probe_ports("127.0.0.1", "mock.test", "/ws", 5000, &[p200, p404]).await;
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].status, Some(200));
        assert_eq!(results[1].status, Some(404));
    }

    #[tokio::test]
    async fn test_probe_ports_early_exits_on_first_101() {
        let p101 = start_mock_server("accept").await;
        let p200 = start_mock_server("200").await;
        let results = probe_ports("127.0.0.1", "mock.test", "/ws", 5000, &[p101, p200]).await;
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
}
