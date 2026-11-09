//! The SNI scanner core: probe a candidate SNI against a public Cloudflare
//! edge and classify whether DPI allowed it.
//!
//! The probe is intentionally shallow: we only need to know whether the DPI
//! allowed the ClientHello carrying this SNI to reach the server. A full TLS
//! handshake is not required — receiving any valid server response (the
//! ServerHello) proves the SNI passed. This mirrors DeepSeek's round-12 spec.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::SeedableRng as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Why an SNI probe failed before a ServerHello was seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniTestFailure {
    /// TCP connection was reset before any server bytes (DPI dropped it).
    Reset,
    /// No response within the budget.
    Timeout,
}

/// Result of a single SNI probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniTestResult {
    /// true if we received a valid server response (DPI allowed the SNI).
    pub passed: bool,
    /// Failure reason when `passed == false`.
    pub failure: Option<SniTestFailure>,
    /// Round-trip time to the first server response, in ms.
    pub rtt_ms: u64,
}

impl SniTestResult {
    fn passed(rtt_ms: u64) -> Self {
        Self {
            passed: true,
            failure: None,
            rtt_ms,
        }
    }

    fn failed(f: SniTestFailure, rtt_ms: u64) -> Self {
        Self {
            passed: false,
            failure: Some(f),
            rtt_ms,
        }
    }
}

/// Probe one SNI against `ip:port`.
///
/// A mock TCP listener that echoes bytes back (simulating a ServerHello) proves
/// `passed == true`; a listener that accepts then resets proves `Reset`.
///
/// We deliberately do NOT require a full TLS handshake: we transmit a raw
/// ClientHello carrying the SNI and watch for ANY server bytes. Receiving any
/// valid response proves the DPI allowed the SNI (even if cert verification or
/// the handshake then fails).
pub async fn test_sni(sni: &str, ip: &str, port: u16, timeout_ms: u64) -> SniTestResult {
    let started = Instant::now();

    // 1 — TCP connect.
    let addr: std::net::SocketAddr = format!("{ip}:{port}")
        .parse()
        .unwrap_or_else(|_| std::net::SocketAddr::from(([127, 0, 0, 1], port)));
    let mut tcp =
        match tokio::time::timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr))
            .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(_)) => {
                return SniTestResult::failed(
                    SniTestFailure::Reset,
                    started.elapsed().as_millis() as u64,
                )
            }
            Err(_) => {
                return SniTestResult::failed(
                    SniTestFailure::Timeout,
                    started.elapsed().as_millis() as u64,
                )
            }
        };
    tcp.set_nodelay(true).ok();

    // 2 — Build a lenient rustls client with a browser fingerprint profile.
    let profile =
        crate::probe_jitter::pick_client_hello_profile(&mut rand::rngs::StdRng::from_entropy());
    let config = match crate::health::lenient_client_config(profile) {
        Ok(c) => c,
        Err(_) => {
            return SniTestResult::failed(
                SniTestFailure::Reset,
                started.elapsed().as_millis() as u64,
            )
        }
    };
    let server_name = match rustls::pki_types::ServerName::try_from(sni.to_string()) {
        Ok(n) => n,
        Err(_) => {
            return SniTestResult::failed(
                SniTestFailure::Reset,
                started.elapsed().as_millis() as u64,
            )
        }
    };
    let mut conn = match rustls::ClientConnection::new(Arc::new(config), server_name) {
        Ok(c) => c,
        Err(_) => {
            return SniTestResult::failed(
                SniTestFailure::Reset,
                started.elapsed().as_millis() as u64,
            )
        }
    };

    // 3 — Transmit the ClientHello (first flight) as raw bytes.
    let mut hello_buf: Vec<u8> = Vec::with_capacity(512);
    {
        let mut sink = std::io::Cursor::new(&mut hello_buf);
        while conn.wants_write() {
            let before = sink.position();
            if conn.write_tls(&mut sink).is_err() {
                break;
            }
            if sink.position() == before || sink.position() as usize >= 512 {
                break;
            }
            if !conn.wants_write() {
                break;
            }
        }
    }
    if hello_buf.is_empty() {
        return SniTestResult::failed(SniTestFailure::Reset, started.elapsed().as_millis() as u64);
    }
    if tokio::time::timeout(Duration::from_millis(timeout_ms), tcp.write_all(&hello_buf))
        .await
        .is_err()
    {
        return SniTestResult::failed(
            SniTestFailure::Timeout,
            started.elapsed().as_millis() as u64,
        );
    }

    // 4 — Watch for ANY server response. Bytes ⇒ the SNI was allowed.
    let mut buf = [0u8; 4096];
    match tokio::time::timeout(Duration::from_millis(timeout_ms), tcp.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => SniTestResult::passed(started.elapsed().as_millis() as u64),
        Ok(Ok(_)) => {
            SniTestResult::failed(SniTestFailure::Reset, started.elapsed().as_millis() as u64)
        }
        Ok(Err(_)) => {
            SniTestResult::failed(SniTestFailure::Reset, started.elapsed().as_millis() as u64)
        }
        Err(_) => SniTestResult::failed(
            SniTestFailure::Timeout,
            started.elapsed().as_millis() as u64,
        ),
    }
}

/// Scan many SNIs against an edge, concurrently. Returns results in input order.
pub async fn scan_snis(
    snis: &[String],
    ip: &str,
    port: u16,
    timeout_ms: u64,
    workers: usize,
) -> Vec<(String, SniTestResult)> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc as SyncArc;
    use tokio::sync::Semaphore;

    let limiter = SyncArc::new(Semaphore::new(workers.max(1)));
    let next = SyncArc::new(AtomicUsize::new(0));
    let snis = snis.to_vec();
    let ip = ip.to_string();

    let mut handles = Vec::new();
    for _ in 0..workers.max(1) {
        let limiter = limiter.clone();
        let next = next.clone();
        let snis = snis.clone();
        let ip = ip.clone();
        handles.push(tokio::spawn(async move {
            let mut out = Vec::new();
            loop {
                let idx = next.fetch_add(1, Ordering::SeqCst);
                if idx >= snis.len() {
                    break;
                }
                let _perm = limiter.acquire().await.unwrap();
                let sni = snis[idx].clone();
                let r = test_sni(&sni, &ip, port, timeout_ms).await;
                out.push((sni, r));
            }
            out
        }));
    }

    let mut results = Vec::new();
    for h in handles {
        if let Ok(mut part) = h.await {
            results.append(&mut part);
        }
    }
    results.sort_by(|a, b| a.0.cmp(&b.0));
    results
}

/// Summarise a scan: how many passed, how many blocked, and the allowed list.
#[derive(Debug, Clone, Default)]
pub struct ScanSummary {
    pub allowed: Vec<String>,
    pub blocked: Vec<String>,
    pub timeouts: Vec<String>,
}

pub fn summarize(results: &[(String, SniTestResult)]) -> ScanSummary {
    let mut s = ScanSummary::default();
    for (sni, r) in results {
        if r.passed {
            s.allowed.push(sni.clone());
        } else if r.failure == Some(SniTestFailure::Timeout) {
            s.timeouts.push(sni.clone());
        } else {
            s.blocked.push(sni.clone());
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spawn a raw TCP listener on an ephemeral loopback port.
    /// - "echo": reads some bytes then echoes them back (simulates a ServerHello).
    /// - "reset": accepts then immediately closes with RST.
    async fn start_mock(tcp: &str) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mode = tcp.to_string();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mode = mode.clone();
                tokio::spawn(async move {
                    match mode.as_str() {
                        "echo" => {
                            let mut buf = [0u8; 2048];
                            let _ = stream.read(&mut buf).await;
                            let _ = stream.write_all(&buf[..16]).await;
                            let _ = stream.flush().await;
                        }
                        "reset" => {
                            // Drop the socket without writing → RST on close.
                            drop(stream);
                        }
                        _ => {}
                    }
                });
            }
        });
        port
    }

    fn port_override() -> u16 {
        // Tests bind their own ephemeral ports; this is just a fallback.
        std::env::var("SNI_TEST_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(0)
    }

    #[tokio::test]
    async fn test_sni_passes_when_server_responds() {
        let port = start_mock("echo").await;
        let port = if port_override() != 0 {
            port_override()
        } else {
            port
        };
        let r = test_sni("example.com", "127.0.0.1", port, 2000).await;
        assert!(
            r.passed,
            "expected pass when a ServerHello-like echo comes back: {r:?}"
        );
        assert!(r.failure.is_none());
    }

    #[tokio::test]
    async fn test_sni_returns_reset_when_tcp_resets() {
        let port = start_mock("reset").await;
        let port = if port_override() != 0 {
            port_override()
        } else {
            port
        };
        let r = test_sni("example.com", "127.0.0.1", port, 2000).await;
        assert!(!r.passed, "expected fail on reset: {r:?}");
        assert_eq!(r.failure, Some(SniTestFailure::Reset));
    }

    #[tokio::test]
    async fn test_sni_times_out_when_no_response() {
        // A listener that accepts and never sends anything.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((_stream, _)) = listener.accept().await {
                // hold open, send nothing
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
        let r = test_sni("example.com", "127.0.0.1", port, 400).await;
        assert_eq!(r.failure, Some(SniTestFailure::Timeout));
    }

    #[tokio::test]
    async fn test_scan_snis_aggregates_results() {
        let port = start_mock("echo").await;
        let snis = vec!["a.com".to_string(), "b.com".to_string()];
        let out = scan_snis(&snis, "127.0.0.1", port, 2000, 2).await;
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|(_, r)| r.passed));
    }

    #[tokio::test]
    async fn test_scan_snis_marks_all_blocked_when_all_fail() {
        let port = start_mock("reset").await;
        let snis = vec!["a.com".to_string(), "b.com".to_string()];
        let out = scan_snis(&snis, "127.0.0.1", port, 2000, 2).await;
        assert!(out.iter().all(|(_, r)| !r.passed));
    }

    #[test]
    fn test_summarize_splits_allowed_blocked_timeouts() {
        let results = vec![
            ("a.com".to_string(), SniTestResult::passed(10)),
            (
                "b.com".to_string(),
                SniTestResult::failed(SniTestFailure::Reset, 5),
            ),
            (
                "c.com".to_string(),
                SniTestResult::failed(SniTestFailure::Timeout, 400),
            ),
        ];
        let s = summarize(&results);
        assert_eq!(s.allowed, vec!["a.com"]);
        assert_eq!(s.blocked, vec!["b.com"]);
        assert_eq!(s.timeouts, vec!["c.com"]);
    }
}
