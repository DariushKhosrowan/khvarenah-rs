//! DNS-over-TLS (DoT) transport.
//!
//! DoT runs the classic DNS wire protocol over TLS on TCP 853. Because we
//! connect to *literal* IPs (never resolving the hostname via system DNS), it
//! bypasses the hijacked recursive resolver just like the DoH module — and it
//! is immune to HTTPS-specific DPI fingerprinting. It is slower to set up
//! (one TLS handshake) than a warm HTTPS connection, so it sits below DoH in
//! the fallback ladder, but above the DNS tunnel.
//!
//! We reuse the RFC 1035 wire-format helpers from `doh` (`build_dns_query_a`,
//! `parse_dns_response_a`, `is_hijacked_ip`).

use crate::doh::{build_dns_query_a, is_hijacked_ip, parse_dns_response_a};
use crate::error::CFError;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// A DoT endpoint: `sni` is the TLS server-name we present; `ip` is the
/// literal address we connect to (bypassing system DNS).
#[derive(Debug, Clone, Copy)]
pub struct DotEndpoint {
    pub sni: &'static str,
    pub ip: Ipv4Addr,
}

/// Default DoT endpoints. Cloudflare and Google, both on the well-known 853.
pub const DEFAULT_DOT_ENDPOINTS: &[DotEndpoint] = &[
    DotEndpoint {
        sni: "cloudflare-dns.com",
        ip: Ipv4Addr::new(1, 1, 1, 1),
    },
    DotEndpoint {
        sni: "cloudflare-dns.com",
        ip: Ipv4Addr::new(1, 0, 0, 1),
    },
    DotEndpoint {
        sni: "dns.google",
        ip: Ipv4Addr::new(8, 8, 8, 8),
    },
    DotEndpoint {
        sni: "dns.google",
        ip: Ipv4Addr::new(8, 8, 4, 4),
    },
];

/// Timeout for a single DoT query (connect + handshake + answer).
const DOT_TIMEOUT: Duration = Duration::from_secs(6);

/// One-shot DoT resolution of `host` → A records, trying endpoints in order.
pub async fn resolve(host: &str, endpoints: &[DotEndpoint]) -> Result<Vec<Ipv4Addr>, CFError> {
    let host = host.to_ascii_lowercase();
    let query = build_dns_query_a(&host, rand::random::<u16>());

    let mut last_err = None;
    for ep in endpoints {
        match query_endpoint(ep, &query).await {
            Ok(bytes) => match parse_dns_response_a(&bytes) {
                Ok(ips) => {
                    let real: Vec<Ipv4Addr> =
                        ips.into_iter().filter(|ip| !is_hijacked_ip(ip)).collect();
                    if !real.is_empty() {
                        return Ok(real);
                    }
                    last_err = Some(CFError::new(
                        "DoT hijacked",
                        format!("DoT answer for {host} contained only 198.18.x.x."),
                        "The resolver is poisoning answers — try another endpoint.",
                    ));
                }
                Err(e) => last_err = Some(e),
            },
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        CFError::new(
            "DoT resolution failed",
            format!("No endpoint could resolve {host}."),
            "Check connectivity.",
        )
    }))
}

/// Perform one DoT exchange against `ep`.
async fn query_endpoint(ep: &DotEndpoint, query: &[u8]) -> Result<Vec<u8>, CFError> {
    let addr = std::net::SocketAddr::from((ep.ip, 853));
    let stream = tokio::time::timeout(DOT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| CFError::new("DoT connect", "Timed out connecting to DoT server.", ""))?
        .map_err(|e| CFError::new("DoT connect", format!("{e}"), ""))?;

    // TLS with SNI = the endpoint host (cert verification against the real name).
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty()) // TODO: load webpki roots
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let sni =
        ServerName::try_from(ep.sni).map_err(|_| CFError::new("DoT TLS", "Invalid SNI.", ""))?;
    let mut tls = tokio::time::timeout(DOT_TIMEOUT, connector.connect(sni, stream))
        .await
        .map_err(|_| CFError::new("DoT TLS", "Timed out on TLS handshake.", ""))?
        .map_err(|e| CFError::new("DoT TLS", format!("{e}"), ""))?;

    // DoT frame: 2-byte length prefix + wire-format DNS message.
    let len = (query.len() as u16).to_be_bytes();
    tls.write_all(&len)
        .await
        .map_err(|e| CFError::new("DoT write", format!("{e}"), ""))?;
    tls.write_all(query)
        .await
        .map_err(|e| CFError::new("DoT write", format!("{e}"), ""))?;
    tls.flush()
        .await
        .map_err(|e| CFError::new("DoT write", format!("{e}"), ""))?;

    // Read the response frame.
    let mut lenbuf = [0u8; 2];
    tokio::time::timeout(DOT_TIMEOUT, tls.read_exact(&mut lenbuf))
        .await
        .map_err(|_| CFError::new("DoT read", "Timed out waiting for answer.", ""))?
        .map_err(|e| CFError::new("DoT read", format!("{e}"), ""))?;
    let rlen = u16::from_be_bytes(lenbuf) as usize;
    if rlen == 0 || rlen > 4096 {
        return Err(CFError::new("DoT read", "Bogus response length.", ""));
    }
    let mut body = vec![0u8; rlen];
    tokio::time::timeout(DOT_TIMEOUT, tls.read_exact(&mut body))
        .await
        .map_err(|_| CFError::new("DoT read", "Timed out reading answer body.", ""))?
        .map_err(|e| CFError::new("DoT read", format!("{e}"), ""))?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_are_not_hijacked() {
        for ep in DEFAULT_DOT_ENDPOINTS {
            assert!(!is_hijacked_ip(&ep.ip), "endpoint {} hijacked", ep.ip);
        }
    }
}
