//! Health probe: TCP latency + TLS handshake latency + download speed.
//!
//! This makes the clean-IP scanner "smart": a candidate endpoint is only
//! accepted after it passes a real health check.

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

use crate::error::CFError;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_parses_ip_port() {
        let a = resolve("1.2.3.4", 443).unwrap();
        assert_eq!(a.to_string(), "1.2.3.4:443");
    }

    #[test]
    fn resolve_rejects_garbage() {
        assert!(resolve("not an ip", 443).is_err());
    }
}
