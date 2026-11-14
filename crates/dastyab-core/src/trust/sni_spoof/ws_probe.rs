//! WS-upgrade diagnostic probe — the missing experiment between "TLS
//! handshake succeeds" (round 12 SNI scanner) and "phase2 counts a 101"
//! (pipeline goal).
//!
//! Round 12 proved all 16 SNIs pass DPI at the TLS layer. The pipeline shows
//! phase2=0 (0/2000 WS upgrades). The one untested layer is the WebSocket
//! upgrade itself. This probe sends a real WS upgrade to a Cloudflare edge and
//! classifies the response:
//!
//! - RST/timeout **after** ServerHello → DPI specifically blocks the WS
//!   upgrade (round 14 target: desync fragmenter / obfuscation).
//! - any HTTP response (400/404/200/…) → the upgrade reached the CF edge (the
//!   worker path is the issue, not DPI → round 14 target: account reactivation).
//! - reset before ServerHello → TLS-layer DPI (already ruled out by round 12).

use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Why a WS-upgrade probe failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsProbeFailure {
    /// TCP/TLS reset before any ServerHello (TLS-layer DPI).
    TlsReset,
    /// ServerHello received, then the connection reset before any HTTP
    /// response — DPI specifically targeting the WS upgrade.
    WsUpgradeReset,
    /// No bytes after the upgrade request within the budget.
    WsUpgradeTimeout,
}

/// Structured verdict of a WS-upgrade probe.
#[derive(Debug, Clone)]
pub struct WsUpgradeResult {
    /// TLS handshake completed (ServerHello seen).
    pub passed_tls: bool,
    /// We reached the HTTP layer (parsed an HTTP status line).
    pub reached_http_layer: bool,
    /// The parsed HTTP status, when reached_http_layer.
    pub http_status: Option<u16>,
    /// Failure classification when not fully successful.
    pub failure: Option<WsProbeFailure>,
    pub elapsed_ms: u64,
    /// The WS path probed.
    pub path: String,
}

impl WsUpgradeResult {
    fn tls_reset(elapsed_ms: u64, path: &str) -> Self {
        Self {
            passed_tls: false,
            reached_http_layer: false,
            http_status: None,
            failure: Some(WsProbeFailure::TlsReset),
            elapsed_ms,
            path: path.to_string(),
        }
    }

    fn upgrade_reset(elapsed_ms: u64, path: &str) -> Self {
        Self {
            passed_tls: true,
            reached_http_layer: false,
            http_status: None,
            failure: Some(WsProbeFailure::WsUpgradeReset),
            elapsed_ms,
            path: path.to_string(),
        }
    }

    fn upgrade_timeout(elapsed_ms: u64, path: &str) -> Self {
        Self {
            passed_tls: true,
            reached_http_layer: false,
            http_status: None,
            failure: Some(WsProbeFailure::WsUpgradeTimeout),
            elapsed_ms,
            path: path.to_string(),
        }
    }

    fn http(elapsed_ms: u64, status: u16, path: &str) -> Self {
        Self {
            passed_tls: true,
            reached_http_layer: true,
            http_status: Some(status),
            failure: None,
            elapsed_ms,
            path: path.to_string(),
        }
    }
}

/// RFC 4648 base64 (no padding) for the Sec-WebSocket-Key — the exact shape a
/// WS client sends. A fixed random-looking key is fine for probing.
fn ws_key() -> String {
    use rand::RngCore;
    let mut k = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut k);
    use base64::Engine;
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(k)
}

/// Build the WS-upgrade request text.
fn upgrade_request(sni: &str, path: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {sni}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36\r\n\
         \r\n",
        ws_key()
    )
}

/// Probe a WS upgrade to `sni` at `ip:port` along `path`.
///
/// We reuse `health::tls_connect` (which completes the TLS handshake and
/// returns a `TlsStream`), then write the upgrade request and read the first
/// HTTP response line. The verdict distinguishes DPI-blocking-the-upgrade from
/// a dead worker path.
pub async fn probe_ws_upgrade(
    sni: &str,
    ip: &str,
    port: u16,
    path: &str,
    timeout_ms: u64,
) -> WsUpgradeResult {
    let started = Instant::now();
    let elapsed = || started.elapsed().as_millis() as u64;

    // 1 — TLS handshake (reuses the lenient verifier + browser-profile config).
    let mut tls = match crate::probe::health::tls_connect(ip, port, sni, timeout_ms).await {
        Ok(s) => s,
        Err(_) => return WsUpgradeResult::tls_reset(elapsed(), path),
    };

    // 2 — Send the WS upgrade request.
    let req = upgrade_request(sni, path);
    if tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        tls.write_all(req.as_bytes()),
    )
    .await
    .is_err()
    {
        return WsUpgradeResult::upgrade_timeout(elapsed(), path);
    }
    let _ = tls.flush().await;

    // 3 — Read the first response bytes and classify.
    let mut buf = [0u8; 4096];
    let read = tokio::time::timeout(Duration::from_millis(timeout_ms), tls.read(&mut buf)).await;
    match read {
        Ok(Ok(0)) => WsUpgradeResult::upgrade_reset(elapsed(), path),
        Ok(Ok(n)) => {
            let head = String::from_utf8_lossy(&buf[..n]);
            // Parse "HTTP/1.1 400 ..." or "HTTP/1.1 101 ...".
            let status = head.lines().next().and_then(|line| {
                let mut parts = line.split_whitespace();
                let _http = parts.next()?;
                parts.next()?.parse::<u16>().ok()
            });
            match status {
                Some(code) => WsUpgradeResult::http(elapsed(), code, path),
                None => WsUpgradeResult::upgrade_reset(elapsed(), path),
            }
        }
        Ok(Err(_)) => WsUpgradeResult::upgrade_reset(elapsed(), path),
        Err(_) => WsUpgradeResult::upgrade_timeout(elapsed(), path),
    }
}

/// Verdict text for a scan line — the single line DeepSeek wants.
pub fn verdict_line(r: &WsUpgradeResult) -> String {
    match r.failure {
        None => format!(
            "✓ http={} reached the edge (worker path / route is reachable at the HTTP layer)",
            r.http_status.unwrap_or(0)
        ),
        Some(WsProbeFailure::TlsReset) => "✗ TLS reset before ServerHello".to_string(),
        Some(WsProbeFailure::WsUpgradeReset) => {
            "✗ TLS ok, but reset after upgrade → DPI blocks the WS upgrade".to_string()
        }
        Some(WsProbeFailure::WsUpgradeTimeout) => {
            "✗ TLS ok, but no response to upgrade (timeout)".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- mock TLS + WS server (mirrors health.rs test pattern) ---

    fn mock_cert() -> rcgen::CertifiedKey {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["mock.test".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        rcgen::CertifiedKey {
            cert,
            key_pair: key,
        }
    }

    #[derive(Clone, Debug)]
    struct CertResolver {
        certified_key: std::sync::Arc<rustls::sign::CertifiedKey>,
        required: Option<String>,
    }

    impl rustls::server::ResolvesServerCert for CertResolver {
        fn resolve(
            &self,
            hello: rustls::server::ClientHello<'_>,
        ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
            match &self.required {
                None => Some(self.certified_key.clone()),
                Some(req) if hello.server_name() == Some(req.as_str()) => {
                    Some(self.certified_key.clone())
                }
                _ => None,
            }
        }
    }

    /// Mock TLS server. Modes:
    /// - "http_400" / "http_404" / "http_200": complete TLS, respond with the
    ///   given HTTP status (upgrade reaches the HTTP layer).
    /// - "tls_then_reset": complete TLS, read the upgrade request, then drop
    ///   the socket without responding (WPI blocks the upgrade).
    /// - "reset": drop before TLS (TLS-layer DPI).
    async fn start_ws_mock(mode: &str) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mode = mode.to_string();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let mode = mode.clone();
                tokio::spawn(async move {
                    handle_ws_client(tcp, &mode).await;
                });
            }
        });
        port
    }

    async fn handle_ws_client(tcp: tokio::net::TcpStream, mode: &str) {
        let key = mock_cert();
        let cert_der = rustls::pki_types::CertificateDer::from(key.cert);
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(key.key_pair.serialize_der().into());
        let signing_key =
            rustls::crypto::aws_lc_rs::sign::any_supported_type(&key_der).expect("signing key");
        let certified_key =
            std::sync::Arc::new(rustls::sign::CertifiedKey::new(vec![cert_der], signing_key));
        let resolver = CertResolver {
            certified_key,
            required: None,
        };
        let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(std::sync::Arc::new(resolver));
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));

        if mode == "reset" {
            drop(tcp);
            return;
        }
        let mut stream = match acceptor.accept(tcp).await {
            Ok(s) => s,
            Err(_) => return,
        };

        // Read the request head.
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

        match mode {
            "tls_then_reset" => {
                // Complete TLS, read the upgrade, then drop without responding.
                let _ = head;
                drop(stream);
            }
            "http_400" => {
                let _ = stream
                    .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
            "http_404" => {
                let _ = stream
                    .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
            "http_200" => {
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
            _ => {
                let _ = stream
                    .write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\nb")
                    .await;
            }
        }
    }

    // --- tests ---

    #[tokio::test]
    async fn test_probe_ws_upgrade_fails_with_wsreset_after_serverhello() {
        let port = start_ws_mock("tls_then_reset").await;
        let r = probe_ws_upgrade("mock.test", "127.0.0.1", port, "/", 3000).await;
        assert!(r.passed_tls, "TLS must succeed before the reset: {r:?}");
        assert!(!r.reached_http_layer);
        assert_eq!(r.failure, Some(WsProbeFailure::WsUpgradeReset));
        assert!(r.elapsed_ms < 3000);
    }

    #[tokio::test]
    async fn test_probe_ws_upgrade_reached_http_when_server_returns_400() {
        let port = start_ws_mock("http_400").await;
        let r = probe_ws_upgrade("mock.test", "127.0.0.1", port, "/", 3000).await;
        assert!(r.passed_tls);
        assert!(r.reached_http_layer);
        assert_eq!(r.http_status, Some(400));
        assert!(r.failure.is_none());
    }

    #[tokio::test]
    async fn test_probe_ws_upgrade_reached_http_when_server_returns_404() {
        let port = start_ws_mock("http_404").await;
        let r = probe_ws_upgrade("mock.test", "127.0.0.1", port, "/", 3000).await;
        assert!(r.reached_http_layer);
        assert_eq!(r.http_status, Some(404));
    }

    #[tokio::test]
    async fn test_probe_ws_upgrade_reached_http_when_server_returns_200() {
        let port = start_ws_mock("http_200").await;
        let r = probe_ws_upgrade("mock.test", "127.0.0.1", port, "/", 3000).await;
        assert!(r.reached_http_layer);
        assert_eq!(r.http_status, Some(200));
    }

    #[tokio::test]
    async fn test_probe_ws_upgrade_fails_with_tlsreset() {
        let port = start_ws_mock("reset").await;
        let r = probe_ws_upgrade("mock.test", "127.0.0.1", port, "/", 3000).await;
        assert!(!r.passed_tls);
        assert_eq!(r.failure, Some(WsProbeFailure::TlsReset));
    }

    #[tokio::test]
    async fn test_probe_ws_upgrade_records_path() {
        let port = start_ws_mock("http_400").await;
        let r = probe_ws_upgrade("mock.test", "127.0.0.1", port, "/edge", 3000).await;
        assert_eq!(r.path, "/edge");
    }

    #[test]
    fn test_verdict_line_http() {
        let r = WsUpgradeResult::http(10, 400, "/");
        assert!(verdict_line(&r).contains("http=400"));
    }

    #[test]
    fn test_verdict_line_wsreset() {
        let r = WsUpgradeResult::upgrade_reset(10, "/");
        assert!(verdict_line(&r).contains("DPI"));
    }
}
