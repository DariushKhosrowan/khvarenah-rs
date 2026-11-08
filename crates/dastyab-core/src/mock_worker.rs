//! Local mock-worker harness (dev/testing).
//!
//! A self-signed HTTPS server that behaves like a Cloudflare Workers VLESS
//! front, so the real pipeline can be exercised against a *real* TCP+TLS+WS
//! server without needing a live Cloudflare account (DeepSeek plan).
//!
//! What it serves:
//! - `GET /cdn-cgi/trace`  → a valid Cloudflare-style trace body containing
//!   `ip=<trace_ip>` (a reserved RFC 5737 test IP by default).
//! - `GET <worker_path>` with a WebSocket upgrade → `101 Switching Protocols`
//!   followed by `ws_payload_bytes` bytes (default 4096, above the
//!   `MIN_WORKER_BYTES` gate).
//! - any other path → `404`.
//!
//! It uses a self-signed certificate with CN matching the host the vless
//! config's SNI expects, so the app's lenient verifier accepts it.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::error::CFError;

/// Configuration for the mock worker.
#[derive(Debug, Clone)]
pub struct MockWorkerConfig {
    /// Listen address (default `127.0.0.1:18443`).
    pub listen_addr: SocketAddr,
    /// The VLESS WebSocket path the worker "deploys" (default `/api`).
    pub worker_path: String,
    /// Bytes to emit after the 101 upgrade (default 4096). Must exceed
    /// `crate::health::MIN_WORKER_BYTES` to pass the WS-gate.
    pub ws_payload_bytes: usize,
    /// The IP reported in the `/cdn-cgi/trace` body (default a reserved
    /// RFC 5737 test IP, e.g. `198.51.100.1`).
    pub trace_ip: String,
    /// CN/SNI the self-signed certificate is issued for.
    pub cert_sni: String,
}

impl Default for MockWorkerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:18443".parse().unwrap(),
            worker_path: "/api".to_string(),
            ws_payload_bytes: 4096,
            trace_ip: "198.51.100.1".to_string(),
            cert_sni: "mock.workers.dev".to_string(),
        }
    }
}

/// Generate a self-signed cert+key for `sni`, returning DER bytes.
fn self_signed_der(sni: &str) -> Result<(Vec<u8>, Vec<u8>), CFError> {
    let cert = rcgen::generate_simple_self_signed(vec![sni.to_string()])
        .map_err(|e| CFError::new("Mock worker", format!("rcgen: {e}"), ""))?;
    let cert_der = cert.cert.der().clone();
    let key_der = cert.key_pair.serialize_der();
    Ok((cert_der.to_vec(), key_der))
}

/// Build an optimistic rustls server config (no client auth).
fn server_config(cert_der: Vec<u8>, key_der: Vec<u8>) -> Result<rustls::ServerConfig, CFError> {
    let cert = rustls::pki_types::CertificateDer::from(cert_der);
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into());
    rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| CFError::new("Mock worker", format!("tls builder: {e}"), ""))?
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .map_err(|e| CFError::new("Mock worker", format!("tls cert: {e}"), ""))
}

/// Run the mock worker forever (or until the listener errors). Each accepted
/// connection is handled on its own task and logged to stderr.
pub async fn run_mock_worker(cfg: MockWorkerConfig) -> Result<(), CFError> {
    let (cert_der, key_der) = self_signed_der(&cfg.cert_sni)?;
    let tls = server_config(cert_der, key_der)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls));

    let listener = TcpListener::bind(cfg.listen_addr)
        .await
        .map_err(|e| CFError::new("Mock worker", format!("bind: {e}"), ""))?;
    eprintln!(
        "[mock-worker] listening on {} (trace-ip={}, path={}, payload={} bytes)",
        cfg.listen_addr, cfg.trace_ip, cfg.worker_path, cfg.ws_payload_bytes
    );

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                eprintln!("[mock-worker] accept error: {e}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(acceptor, tcp, &cfg).await {
                eprintln!("[mock-worker] {peer} error: {}", e.brief());
            }
        });
    }
}

async fn handle_conn(acceptor: TlsAcceptor, tcp: TcpStream, cfg: &MockWorkerConfig) -> Result<(), CFError> {
    let mut stream = acceptor.accept(tcp).await.map_err(|e| {
        CFError::new("Mock worker", format!("tls accept: {e}"), "")
    })?;

    // Read the full HTTP request head.
    let mut buf = vec![0u8; 8192];
    let mut head = Vec::new();
    let mut n = 0usize;
    // Read until we see the header terminator or the buffer fills.
    while n < 8192 && !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let r = stream.read(&mut buf).await.map_err(|e| {
            CFError::new("Mock worker", format!("read: {e}"), "")
        })?;
        if r == 0 {
            break;
        }
        head.extend_from_slice(&buf[..r]);
        n += r;
    }

    let text = String::from_utf8_lossy(&head);
    let request_line = text.lines().next().unwrap_or("");
    let method_path = request_line.split_whitespace().collect::<Vec<_>>();
    let path = method_path.get(1).copied().unwrap_or("/");
    let is_upgrade = text.to_ascii_lowercase().contains("upgrade: websocket");

    // Cloudflare trace endpoint.
    if path == "/cdn-cgi/trace" {
        let body = format!(
            "fl=000\r\nh={}\r\nip={}\r\nloc=ZZ\r\nts=0\r\nvisit_scheme=https\r\n",
            cfg.cert_sni, cfg.trace_ip
        );
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(resp.as_bytes()).await.map_err(|e| {
            CFError::new("Mock worker", format!("write trace: {e}"), "")
        })?;
        stream.flush().await.ok();
        return Ok(());
    }

    // WebSocket upgrade on the worker path.
    if path == cfg.worker_path && is_upgrade {
        let resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: mock-accept\r\n\r\n";
        stream.write_all(resp.as_bytes()).await.map_err(|e| {
            CFError::new("Mock worker", format!("write upgrade: {e}"), "")
        })?;
        // Emit the payload (enough to clear MIN_WORKER_BYTES).
        let payload = vec![b'x'; cfg.ws_payload_bytes];
        stream.write_all(&payload).await.map_err(|e| {
            CFError::new("Mock worker", format!("write payload: {e}"), "")
        })?;
        stream.flush().await.ok();
        // Keep the connection open briefly so the client can drain it.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        return Ok(());
    }

    // Everything else → 404.
    let body = "Not Found";
    let resp = format!(
        "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes()).await.map_err(|e| {
        CFError::new("Mock worker", format!("write 404: {e}"), "")
    })?;
    stream.flush().await.ok();
    Ok(())
}

/// Convenience: run the mock worker from a CLI-provided port + path + trace-ip.
pub async fn run_mock_worker_from_args(
    port: u16,
    path: &str,
    trace_ip: &str,
    payload: usize,
) -> Result<(), CFError> {
    let cfg = MockWorkerConfig {
        listen_addr: format!("127.0.0.1:{port}").parse().map_err(|e| {
            CFError::new("Mock worker", format!("bad port: {e}"), "")
        })?,
        worker_path: if path.is_empty() { "/api".to_string() } else { path.to_string() },
        trace_ip: trace_ip.to_string(),
        ws_payload_bytes: payload,
        ..Default::default()
    };
    run_mock_worker(cfg).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncBufReadExt;

    #[test]
    fn self_signed_der_produces_cert_and_key() {
        let (cert, key) = self_signed_der("mock.workers.dev").unwrap();
        assert!(!cert.is_empty());
        assert!(!key.is_empty());
    }

    #[tokio::test]
    async fn mock_serves_trace_404_and_ws_upgrade() {
        let cfg = MockWorkerConfig::default();
        let (cert, key) = self_signed_der(&cfg.cert_sni).unwrap();
        let tls = Arc::new(server_config(cert, key).unwrap());
        let acceptor = TlsAcceptor::from(tls);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor2 = acceptor.clone();
        let cfg2 = cfg.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((tcp, _)) => {
                        let a = acceptor2.clone();
                        let c = cfg2.clone();
                        tokio::spawn(async move {
                            let _ = handle_conn(a, tcp, &c).await;
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        // TLS connect + GET /cdn-cgi/trace
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut tls_stream = acceptor
            .accept(stream)
            .await
            .expect("tls handshake");
        let (mut reader, mut writer) = tls_stream.split();
        writer
            .write_all(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: mock.workers.dev\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        reader.read_to_end(&mut resp).await.unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(text.contains("HTTP/1.1 200"));
        assert!(text.contains("ip=198.51.100.1"), "trace body: {text}");

        // WS upgrade on /api gets 101 + payload
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut tls_stream = acceptor.accept(stream).await.unwrap();
        let (mut reader, mut writer) = tls_stream.split();
        writer
            .write_all(b"GET /api HTTP/1.1\r\nHost: mock.workers.dev\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: aaaa\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        reader.read_to_end(&mut resp).await.unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(text.contains("HTTP/1.1 101"), "upgrade resp: {text}");
        assert!(resp.len() > 4096, "payload missing, len={}", resp.len());

        // unknown path → 404
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut tls_stream = acceptor.accept(stream).await.unwrap();
        let (mut reader, mut writer) = tls_stream.split();
        writer
            .write_all(b"GET /nope HTTP/1.1\r\nHost: mock.workers.dev\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        reader.read_to_end(&mut resp).await.unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(text.contains("HTTP/1.1 404"), "404 resp: {text}");
    }
}
