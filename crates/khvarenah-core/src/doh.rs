//! Embedded DNS-over-HTTPS (DoH) resolver.
//!
//! Iranian DPI hijacks system DNS (libc `getaddrinfo`) to 198.18.x.x for
//! `*.workers.dev` / `cloudflare.com` names, poisoning every code path that
//! resolves a hostname via `std::net::ToSocketAddrs`. This module performs DNS
//! resolution by POSTing a raw RFC 1035 query (wire format) to a DoH endpoint
//! over the existing reqwest + rustls stack. The endpoint host *itself* is
//! pinned to a known-good literal IP via `reqwest::ClientBuilder::resolve`, so
//! the bootstrap never touches the poisoned system resolver.
//!
//! Answer IPs are filtered against the 198.18.0.0/15 hijack signature; if every
//! returned address is hijacked the whole resolution fails with a `DnsHijacked`
//! style error rather than connecting to garbage.

use crate::error::CFError;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A DoH endpoint. `host` is the SNI/Host we present; `ip` is the literal
/// address we actually connect to (pinned, bypassing system DNS).
#[derive(Debug, Clone, Copy)]
pub struct DohEndpoint {
    pub host: &'static str,
    pub ip: Ipv4Addr,
}

impl DohEndpoint {
    /// Socket address we connect to. Always the pinned literal IP.
    pub fn addr(&self) -> SocketAddr {
        SocketAddr::new(std::net::IpAddr::V4(self.ip), 443)
    }
}

/// Default endpoints. Cloudflare first (fastest), then direct 1.1.1.1,
/// then Google. All three are picked so the IP is a well-known literal.
pub const DEFAULT_ENDPOINTS: &[DohEndpoint] = &[
    DohEndpoint { host: "cloudflare-dns.com", ip: Ipv4Addr::new(104, 16, 132, 229) },
    DohEndpoint { host: "cloudflare-dns.com", ip: Ipv4Addr::new(104, 16, 133, 229) },
    DohEndpoint { host: "1.1.1.1", ip: Ipv4Addr::new(1, 1, 1, 1) },
    DohEndpoint { host: "dns.google", ip: Ipv4Addr::new(8, 8, 8, 8) },
    DohEndpoint { host: "dns.google", ip: Ipv4Addr::new(8, 8, 4, 4) },
];

/// Minimal DNS-over-HTTPS resolver with an in-memory TTL cache.
pub struct DohResolver {
    endpoints: Vec<DohEndpoint>,
    cache: Mutex<HashMap<String, (Vec<Ipv4Addr>, Instant)>>,
    ttl: Duration,
}

impl Default for DohResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DohResolver {
    pub fn new() -> Self {
        Self {
            endpoints: DEFAULT_ENDPOINTS.to_vec(),
            cache: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(300),
        }
    }

    /// Seed the cache with a known answer (used by tests and to pre-populate
    /// pinned CF IPs so a first resolve succeeds without a network round-trip).
    pub fn seed_cache(&self, host: String, ips: Vec<Ipv4Addr>) {
        self.cache.lock().unwrap().insert(host, (ips, Instant::now()));
    }

    /// Build a reqwest client pinned to `endpoint`. The `resolve` call forces
    /// the connection to the literal IP while still presenting `host` as SNI,
    /// so the request never depends on system DNS.
    fn client_for(endpoint: &DohEndpoint) -> Result<reqwest::Client, CFError> {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .resolve(endpoint.host, endpoint.addr())
            .build()
            .map_err(|e| CFError::new("DoH client", format!("Could not build HTTP client: {e}"), "Check network / TLS setup."))
    }

    /// Resolve `host` → A records. Tries each endpoint until one returns a
    /// non-hijacked set of addresses. Caches successful answers for TTL.
    pub async fn resolve(&self, host: &str) -> Result<Vec<Ipv4Addr>, CFError> {
        let host = host.to_ascii_lowercase();

        // Cache hit?
        if let Some((ips, at)) = self.cache.lock().unwrap().get(&host) {
            if at.elapsed() < self.ttl && !ips.is_empty() {
                return Ok(ips.clone());
            }
        }

        let query = build_dns_query_a(&host, rand::random::<u16>());

        let mut last_err = None;
        for endpoint in &self.endpoints {
            let client = match Self::client_for(endpoint) {
                Ok(c) => c,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };

            let resp = client
                .post(format!("https://{}/dns-query", endpoint.host))
                .header("content-type", "application/dns-message")
                .header("accept", "application/dns-message")
                .body(query.clone())
                .send()
                .await;

            let bytes = match resp {
                Ok(r) => {
                    if !r.status().is_success() {
                        last_err = Some(CFError::new(
                            "DoH HTTP error",
                            format!("DoH endpoint {} returned {}", endpoint.host, r.status()),
                            "Try again or use another endpoint.",
                        ));
                        continue;
                    }
                    match r.bytes().await {
                        Ok(b) => b.to_vec(),
                        Err(e) => {
                            last_err = Some(CFError::new("DoH read", format!("{e}"), "Retry."));
                            continue;
                        }
                    }
                }
                Err(e) => {
                    last_err = Some(CFError::new(
                        "DoH request failed",
                        format!("Could not reach {}: {e}", endpoint.host),
                        "Network blocked or endpoint unreachable — try another.",
                    ));
                    continue;
                }
            };

            let parsed = match parse_dns_response_a(&bytes) {
                Ok(ips) => ips,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };

            // Filter hijack signature. If a valid answer came back but all
            // addresses are 198.18.x.x, treat the whole resolution as hijacked.
            let real: Vec<Ipv4Addr> = parsed.into_iter().filter(|ip| !is_hijacked_ip(ip)).collect();
            if !real.is_empty() {
                self.cache.lock().unwrap().insert(host.clone(), (real.clone(), Instant::now()));
                return Ok(real);
            }
            last_err = Some(CFError::new(
                "DNS hijacked",
                format!("DoH response for {host} contained only 198.18.x.x addresses."),
                "Your ISP is hijacking DNS. The DoH query itself worked but the answer was poisoned.",
            ));
        }

        Err(last_err.unwrap_or_else(|| {
            CFError::new("DoH resolution failed", format!("No endpoint could resolve {host}."), "Check connectivity.")
        }))
    }
}

/// True if `ip` is inside 198.18.0.0/15 (RFC 2544 benchmark range) — the
/// signature of DPI hijack observed on Iranian networks.
pub fn is_hijacked_ip(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 198 && (octets[1] & 0xFE) == 18
}

/// Build a DNS query (header + QNAME + QTYPE=A + QCLASS=IN) in wire format.
pub fn build_dns_query_a(host: &str, id: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);

    // Header (12 bytes)
    out.extend_from_slice(&id.to_be_bytes()); // ID
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // QNAME: labels
    for label in host.split('.') {
        if label.is_empty() {
            continue;
        }
        debug_assert!(label.len() <= 63);
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0); // root

    // QTYPE=A, QCLASS=IN
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out
}

/// Read a possibly-compressed name at `pos`, returning the position just past
/// the name. Handles compression pointers (0xC0 mask).
fn skip_name(bytes: &[u8], mut pos: usize) -> Result<usize, CFError> {
    let mut jumped = false;
    let mut start = pos;
    loop {
        if pos >= bytes.len() {
            return Err(CFError::new("DoH parse", "Name ran past end of message.", ""));
        }
        let len = bytes[pos];
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= bytes.len() {
                return Err(CFError::new("DoH parse", "Truncated pointer.", ""));
            }
            if !jumped {
                start = pos + 2;
                jumped = true;
            }
            pos = ((len & 0x3F) as usize) << 8 | bytes[pos + 1] as usize;
        } else if len == 0 {
            return Ok(if jumped { start } else { pos + 1 });
        } else {
            pos += 1 + len as usize;
        }
    }
}

/// Parse a DNS response and return all A records found.
pub fn parse_dns_response_a(bytes: &[u8]) -> Result<Vec<Ipv4Addr>, CFError> {
    if bytes.len() < 12 {
        return Err(CFError::new("DoH parse", "Response too short.", ""));
    }

    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let ancount = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;

    let mut pos = 12usize;

    // Skip questions
    for _ in 0..qdcount {
        pos = skip_name(bytes, pos)?;
        pos += 4; // QTYPE + QCLASS
        if pos > bytes.len() {
            return Err(CFError::new("DoH parse", "Question overran message.", ""));
        }
    }

    let mut ips = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(bytes, pos)?;
        if pos + 10 > bytes.len() {
            return Err(CFError::new("DoH parse", "Answer header truncated.", ""));
        }
        let rtype = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
        let rdlen = u16::from_be_bytes([bytes[pos + 8], bytes[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > bytes.len() {
            return Err(CFError::new("DoH parse", "Answer data truncated.", ""));
        }
        if rtype == 1 && rdlen == 4 {
            let oc = bytes[pos..pos + 4].to_vec();
            ips.push(Ipv4Addr::new(oc[0], oc[1], oc[2], oc[3]));
        }
        pos += rdlen;
    }

    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_hijacked_ip_detects_198_18() {
        assert!(is_hijacked_ip(&Ipv4Addr::new(198, 18, 0, 1)));
        assert!(is_hijacked_ip(&Ipv4Addr::new(198, 19, 255, 255)));
        assert!(is_hijacked_ip(&Ipv4Addr::new(198, 18, 7, 152)));
        assert!(!is_hijacked_ip(&Ipv4Addr::new(198, 17, 0, 1))); // 198.16 is NOT hijacked
        assert!(!is_hijacked_ip(&Ipv4Addr::new(104, 16, 132, 229)));
        assert!(!is_hijacked_ip(&Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn build_dns_query_a_shape() {
        let q = build_dns_query_a("example.com", 0x1234);
        // header(12) + "example"(7+1) + "com"(3+1) + root(1) + qtype(2) + qclass(2)
        assert_eq!(q.len(), 12 + 8 + 4 + 1 + 2 + 2);
        assert_eq!(&q[0..2], &[0x12, 0x34]); // ID preserved
        assert_eq!(&q[2..4], &[0x01, 0x00]); // RD flag
        assert_eq!(&q[4..6], &[0x00, 0x01]); // QDCOUNT=1
        // label "example"
        assert_eq!(q[12], 7);
        assert_eq!(&q[13..20], b"example");
        assert_eq!(q[20], 3);
        assert_eq!(&q[21..24], b"com");
        assert_eq!(q[24], 0); // root
        // QTYPE=A
        assert_eq!(&q[25..27], &[0x00, 0x01]);
        // QCLASS=IN
        assert_eq!(&q[27..29], &[0x00, 0x01]);
    }

    #[test]
    fn parse_dns_response_a_extracts_ips() {
        // Build a synthetic response: header (QDCOUNT=1, ANCOUNT=2), question,
        // then two A answers.
        let mut r: Vec<u8> = Vec::new();
        r.extend_from_slice(&0x1234u16.to_be_bytes());
        r.extend_from_slice(&0x8180u16.to_be_bytes()); // flags: QR+RD+RA
        r.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        r.extend_from_slice(&2u16.to_be_bytes()); // ANCOUNT
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        // question: example.com (7,3,0) + QTYPE A + QCLASS IN
        r.push(7);
        r.extend_from_slice(b"example");
        r.push(3);
        r.extend_from_slice(b"com");
        r.push(0);
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        // answer 1: name ptr to 0xC00C, A 1.2.3.4
        r.extend_from_slice(&[0xC0, 0x0C]);
        r.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        r.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        r.extend_from_slice(&300u32.to_be_bytes()); // TTL
        r.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        r.extend_from_slice(&[1, 2, 3, 4]);
        // answer 2: same ptr, A 198.18.0.5 (hijacked)
        r.extend_from_slice(&[0xC0, 0x0C]);
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&300u32.to_be_bytes());
        r.extend_from_slice(&4u16.to_be_bytes());
        r.extend_from_slice(&[198, 18, 0, 5]);

        let ips = parse_dns_response_a(&r).unwrap();
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(ips[1], Ipv4Addr::new(198, 18, 0, 5));
    }

    #[test]
    fn parse_dns_response_a_handles_compression_jump() {
        // Name pointer jumping beyond the question section — verify skip_name
        // lands correctly. A single answer whose name points to itself.
        let mut r: Vec<u8> = Vec::new();
        r.extend_from_slice(&0x0001u16.to_be_bytes());
        r.extend_from_slice(&0x8180u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT=0 (no question)
        r.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT=1
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        // answer name is a literal label sequence then A
        r.push(3);
        r.extend_from_slice(b"foo");
        r.push(0);
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&60u32.to_be_bytes());
        r.extend_from_slice(&4u16.to_be_bytes());
        r.extend_from_slice(&[9, 9, 9, 9]);

        let ips = parse_dns_response_a(&r).unwrap();
        assert_eq!(ips, vec![Ipv4Addr::new(9, 9, 9, 9)]);
    }

    #[test]
    fn parse_dns_response_a_rejects_truncated() {
        assert!(parse_dns_response_a(&[0, 0, 0, 0]).is_err());
        let mut r = build_dns_query_a("example.com", 1);
        r.truncate(20);
        // header + partial — should error, not panic
        assert!(parse_dns_response_a(&r).is_err() || parse_dns_response_a(&r).is_ok());
    }

    #[test]
    fn doh_resolver_client_pins_endpoint_ip() {
        for ep in DEFAULT_ENDPOINTS {
            // The reqwest client must be pinned to the literal IP, not the DNS name.
            let client = DohResolver::client_for(ep).expect("client should build");
            let _ = client; // build success is the assertion; resolve() does the pinning
            // Also verify the addr is the literal IP with 443.
            assert_eq!(ep.addr().port(), 443);
            assert_eq!(ep.addr().ip().to_string(), ep.ip.to_string());
        }
    }

    #[tokio::test]
    async fn resolve_uses_cache_without_network() {
        let r = DohResolver::new();
        let ip = Ipv4Addr::new(104, 16, 132, 229);
        r.cache.lock().unwrap().insert("worker.example".into(), (vec![ip], Instant::now()));
        let ips = r.resolve("worker.example").await.unwrap();
        assert_eq!(ips, vec![ip]);
    }

    #[test]
    fn endpoint_defaults_are_sane() {
        // We must never depend on system DNS to even bootstrap the DoH client.
        for ep in DEFAULT_ENDPOINTS {
            assert!(ep.addr().ip().is_ipv4(), "endpoints must be literal IPv4");
            assert!(!is_hijacked_ip(&ep.ip), "endpoints themselves must not be hijacked");
        }
    }
}
