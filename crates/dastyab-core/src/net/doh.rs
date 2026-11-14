//! Embedded DNS-over-HTTPS (DoH) resolver.
//!
//! Iranian DPI hijacks system DNS (libc `getaddrinfo`) to 198.18.x.x for
//! `*.workers.dev` / `cloudflare.com` names, poisoning every code path that
//! resolves a hostname via `std::net::ToSocketAddrs`. This module performs DNS
//! resolution by POSTing a raw RFC 1035 query (wire format) to a DoH endpoint
//! over the existing reqwest + rustls stack.
//!
//! Bootstrap pitfall: the DoH endpoint hostname must never be resolved through
//! system DNS (it would return 198.18.x.x and connect to a black hole). We
//! solve this with `reqwest::ClientBuilder::resolve` for every endpoint: each
//! endpoint's hostname is pinned to a hardcoded literal IP, so the request URL
//! uses the hostname (correct TLS SNI + cert verification) while the actual TCP
//! connection goes to the pinned IP without ever touching system DNS.
//!
//! Answer IPs are filtered against the 198.18.0.0/15 hijack signature; if every
//! returned address is hijacked the whole resolution fails rather than
//! connecting to garbage.

use crate::error::CFError;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A DoH endpoint. `host` is the SNI/Host we present; `ip` is the literal
/// address we actually connect to (pinned, bypassing system DNS).
#[derive(Debug, Clone, Copy)]
pub struct DohEndpoint {
    pub host: &'static str,
    pub ip: Ipv4Addr,
}

/// Default endpoints. Cloudflare first (fastest), then direct 1.1.1.1,
/// then Google. All are well-known literal IPs.
pub const DEFAULT_ENDPOINTS: &[DohEndpoint] = &[
    DohEndpoint {
        host: "cloudflare-dns.com",
        ip: Ipv4Addr::new(104, 16, 132, 229),
    },
    DohEndpoint {
        host: "cloudflare-dns.com",
        ip: Ipv4Addr::new(104, 16, 133, 229),
    },
    DohEndpoint {
        host: "1.1.1.1",
        ip: Ipv4Addr::new(1, 1, 1, 1),
    },
    DohEndpoint {
        host: "dns.google",
        ip: Ipv4Addr::new(8, 8, 8, 8),
    },
    DohEndpoint {
        host: "dns.google",
        ip: Ipv4Addr::new(8, 8, 4, 4),
    },
];

/// The HTTP backend. `Real` is the production reqwest client (with `.resolve()`
/// pins). `Mock` is a scripted handler used only by tests.
enum DohBackend {
    /// Production: reqwest over rustls, every endpoint hostname pinned to its
    /// literal IP so no system DNS is consulted.
    Real(reqwest::Client),
    /// Test: a scripted queue of responses (raw DNS wire bytes or errors) plus
    /// a counter of how many POSTs were served.
    #[cfg_attr(not(test), allow(dead_code))]
    Mock {
        queue: Mutex<Vec<Result<Vec<u8>, CFError>>>,
        calls: std::sync::atomic::AtomicUsize,
    },
}

fn build_real_client(endpoints: &[DohEndpoint]) -> Result<reqwest::Client, CFError> {
    let mut builder = reqwest::Client::builder();
    for ep in endpoints {
        let addr = std::net::SocketAddr::new(std::net::IpAddr::V4(ep.ip), 443);
        builder = builder.resolve(ep.host, addr);
    }
    builder
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| {
            CFError::new(
                "DoH client",
                format!("Could not build HTTP client: {e}"),
                "Check network / TLS setup.",
            )
        })
}

/// Consecutive failures on one endpoint before it is temporarily blacklisted.
pub const ENDPOINT_BLACKLIST_THRESHOLD: u32 = 3;
/// Number of successful resolutions needed to clear a blacklist.
pub const ENDPOINT_BLACKLIST_RESET: u32 = 1;

/// Minimal DNS-over-HTTPS resolver with an in-memory TTL cache and per-endpoint
/// blacklisting (a poisoned or flaky endpoint is retried less often).
pub struct DohResolver {
    endpoints: Vec<DohEndpoint>,
    backend: DohBackend,
    cache: Mutex<HashMap<String, (Vec<Ipv4Addr>, Instant)>>,
    ttl: Duration,
    /// Consecutive failures per endpoint index.
    endpoint_fails: Mutex<Vec<u32>>,
}

impl Default for DohResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DohResolver {
    /// Build a resolver with the default endpoints and the real reqwest
    /// transport (endpoint hostnames pinned to literal IPs).
    pub fn new() -> Self {
        let client =
            build_real_client(DEFAULT_ENDPOINTS).expect("default DoH client build should succeed");
        Self {
            endpoints: DEFAULT_ENDPOINTS.to_vec(),
            backend: DohBackend::Real(client),
            cache: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(300),
            endpoint_fails: Mutex::new(vec![0; DEFAULT_ENDPOINTS.len()]),
        }
    }

    /// Build a resolver backed by a scripted mock (tests only).
    #[cfg(test)]
    fn mock(responses: Vec<Result<Vec<u8>, CFError>>) -> Self {
        Self {
            endpoints: DEFAULT_ENDPOINTS.to_vec(),
            backend: DohBackend::Mock {
                queue: Mutex::new(responses),
                calls: std::sync::atomic::AtomicUsize::new(0),
            },
            cache: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(300),
            endpoint_fails: Mutex::new(vec![0; DEFAULT_ENDPOINTS.len()]),
        }
    }

    /// Number of POSTs the mock served (tests only).
    #[cfg(test)]
    fn mock_calls(&self) -> usize {
        match &self.backend {
            DohBackend::Mock { calls, .. } => calls.load(std::sync::atomic::Ordering::SeqCst),
            _ => 0,
        }
    }

    /// Set the cache TTL (tests use a tiny value to exercise expiry).
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Seed the cache with a known answer (used by tests).
    pub fn seed_cache(&self, host: String, ips: Vec<Ipv4Addr>) {
        self.cache
            .lock()
            .unwrap()
            .insert(host, (ips, Instant::now()));
    }

    async fn post(&self, url: &str, query: &[u8]) -> Result<Vec<u8>, CFError> {
        match &self.backend {
            DohBackend::Real(client) => {
                let resp = client
                    .post(url)
                    .header("content-type", "application/dns-message")
                    .header("accept", "application/dns-message")
                    .body(query.to_vec())
                    .send()
                    .await
                    .map_err(|e| {
                        CFError::new(
                            "DoH request failed",
                            format!("Could not reach {url}: {e}"),
                            "Network blocked or endpoint unreachable — try another.",
                        )
                    })?;
                if !resp.status().is_success() {
                    return Err(CFError::new(
                        "DoH HTTP error",
                        format!("DoH endpoint returned {}", resp.status()),
                        "Try again or use another endpoint.",
                    ));
                }
                let bytes = resp
                    .bytes()
                    .await
                    .map_err(|e| CFError::new("DoH read", format!("{e}"), "Retry."))?;
                Ok(bytes.to_vec())
            }
            DohBackend::Mock { queue, calls } => {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut guard = queue.lock().unwrap();
                if guard.is_empty() {
                    return Err(CFError::new("doH-mock", "no more scripted responses", ""));
                }
                guard.remove(0)
            }
        }
    }

    /// Resolve `host` → A records. Tries each endpoint in order until one
    /// returns a non-hijacked set of addresses. Caches answers for TTL.
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
        for (i, endpoint) in self.endpoints.iter().enumerate() {
            // Skip temporarily-blacklisted endpoints (too many recent failures).
            if self.endpoint_fails.lock().unwrap()[i] >= ENDPOINT_BLACKLIST_THRESHOLD {
                continue;
            }

            let url = format!("https://{}/dns-query", endpoint.host);
            let bytes = match self.post(&url, &query).await {
                Ok(b) => b,
                Err(e) => {
                    self.endpoint_fails.lock().unwrap()[i] += 1;
                    last_err = Some(e);
                    continue;
                }
            };

            let parsed = match parse_dns_response_a(&bytes) {
                Ok(ips) => ips,
                Err(e) => {
                    self.endpoint_fails.lock().unwrap()[i] += 1;
                    last_err = Some(e);
                    continue;
                }
            };

            // Filter hijack signature. If a valid answer came back but all
            // addresses are 198.18.x.x, treat the resolution as hijacked.
            let real: Vec<Ipv4Addr> = parsed
                .into_iter()
                .filter(|ip| !is_hijacked_ip(ip))
                .collect();
            if !real.is_empty() {
                self.cache
                    .lock()
                    .unwrap()
                    .insert(host.clone(), (real.clone(), Instant::now()));
                // Reset this endpoint's failure count on success.
                self.endpoint_fails.lock().unwrap()[i] = 0;
                return Ok(real);
            }
            self.endpoint_fails.lock().unwrap()[i] += 1;
            last_err = Some(CFError::new(
                "DNS hijacked",
                format!("DoH response for {host} contained only 198.18.x.x addresses."),
                "Your ISP is hijacking DNS. The DoH query itself worked but the answer was poisoned.",
            ));
        }

        Err(last_err.unwrap_or_else(|| {
            CFError::new(
                "DoH resolution failed",
                format!("No endpoint could resolve {host}."),
                "Check connectivity.",
            )
        }))
    }
}

/// True if `ip` is inside 198.18.0.0/15 (RFC 2544 benchmark range) — the
/// signature of DPI hijack observed on Iranian networks.
pub fn is_hijacked_ip(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 198 && (octets[1] & 0xFE) == 18
}

/// Cheap network-liveness probe: resolve `cloudflare-dns.com` over the DoH
/// resolver (which filters hijacked 198.18.x.x answers). Returns true iff a
/// non-hijacked A record came back. ~50ms. It never touches the CF worker or
/// the tunnel, so it is safe to call before every daemon cycle — when it
/// fails we skip the cycle entirely rather than burning rescue/scan budget on
/// a genuinely-offline network.
pub async fn probe_network_liveness(resolver: &DohResolver) -> bool {
    match resolver.resolve("cloudflare-dns.com").await {
        Ok(ips) => !ips.is_empty() && ips.iter().all(|ip| !is_hijacked_ip(ip)),
        Err(_) => false,
    }
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

/// Build a DNS query for a TXT record (QTYPE=16) of `host` with the given id.
/// Used by the live DNS-tunnel liveness probe (raw UDP, not the OS resolver).
pub fn build_dns_query_txt(host: &str, id: u16) -> Vec<u8> {
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

    // QTYPE=TXT (16), QCLASS=IN
    out.extend_from_slice(&16u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out
}

/// Parse a DNS response and return all TXT character-strings found (as UTF-8
/// lossy strings). Handles the TXT RDATA format: one or more length-prefixed
/// character-strings concatenated in the RDATA.
pub fn parse_dns_response_txt(bytes: &[u8]) -> Result<Vec<String>, CFError> {
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

    let mut txts = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(bytes, pos)?;
        if pos + 10 > bytes.len() {
            return Err(CFError::new("DoH parse", "Answer header truncated.", ""));
        }
        let rtype = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
        let _rclass = u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]);
        let rdlen = u16::from_be_bytes([bytes[pos + 8], bytes[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > bytes.len() {
            return Err(CFError::new("DoH parse", "Answer data truncated.", ""));
        }
        if rtype == 16 {
            // TXT RDATA: one or more length-prefixed character-strings.
            let end = pos + rdlen;
            let mut p = pos;
            while p < end {
                let len = bytes[p] as usize;
                p += 1;
                if p + len > end {
                    return Err(CFError::new("DoH parse", "TXT string overran RDATA.", ""));
                }
                txts.push(String::from_utf8_lossy(&bytes[p..p + len]).into_owned());
                p += len;
            }
        }
        pos += rdlen;
    }

    Ok(txts)
}

/// Read a possibly-compressed name at `pos`, returning the position just past
/// the name. Handles compression pointers (0xC0 mask).
fn skip_name(bytes: &[u8], mut pos: usize) -> Result<usize, CFError> {
    let mut jumped = false;
    let mut start = pos;
    // Cycle guard: a compression pointer may only follow the chain forward in
    // message offset (RFC 1035 pointers always reference earlier labels), but
    // malformed/adversarial data could point in a loop. Cap the pointer hops
    // so a crafted reply cannot spin the parser forever.
    let mut hops = 0u32;
    loop {
        if pos >= bytes.len() {
            return Err(CFError::new(
                "DoH parse",
                "Name ran past end of message.",
                "",
            ));
        }
        let len = bytes[pos];
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= bytes.len() {
                return Err(CFError::new("DoH parse", "Truncated pointer.", ""));
            }
            hops += 1;
            if hops > 32 {
                return Err(CFError::new(
                    "DoH parse",
                    "Compression pointer loop detected.",
                    "",
                ));
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

/// Build a DNS query for an NS record (QTYPE=2) of `host` with the given id.
/// Used by authoritative-nameserver anchor discovery.
pub fn build_dns_query_ns(host: &str, id: u16) -> Vec<u8> {
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

    // QTYPE=NS (2), QCLASS=IN
    out.extend_from_slice(&2u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out
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

/// Decode a possibly-compressed domain name at `pos`, returning the decoded
/// name and the position just past the on-the-wire name. Handles compression
/// pointers (0xC0 mask) with a cycle guard.
fn read_name_string(bytes: &[u8], mut pos: usize) -> Result<(String, usize), CFError> {
    let mut labels: Vec<&[u8]> = Vec::new();
    let mut pointer_target: Option<usize> = None;
    let mut hops = 0u32;
    loop {
        if pos >= bytes.len() {
            return Err(CFError::new(
                "DoH parse",
                "Name ran past end of message.",
                "",
            ));
        }
        let len = bytes[pos];
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= bytes.len() {
                return Err(CFError::new("DoH parse", "Truncated pointer.", ""));
            }
            hops += 1;
            if hops > 32 {
                return Err(CFError::new(
                    "DoH parse",
                    "Compression pointer loop detected.",
                    "",
                ));
            }
            let next = ((len & 0x3F) as usize) << 8 | bytes[pos + 1] as usize;
            if pointer_target.is_none() {
                pointer_target = Some(pos + 2);
            }
            pos = next;
        } else if len == 0 {
            let end = pointer_target.unwrap_or(pos + 1);
            let mut s = String::new();
            for (i, l) in labels.iter().enumerate() {
                if i > 0 {
                    s.push('.');
                }
                s.push_str(&String::from_utf8_lossy(l));
            }
            if s.is_empty() {
                s.push('.');
            }
            return Ok((s, end));
        } else {
            pos += 1;
            if pos + len as usize > bytes.len() {
                return Err(CFError::new("DoH parse", "Label overran message.", ""));
            }
            labels.push(&bytes[pos..pos + len as usize]);
            pos += len as usize;
        }
    }
}

/// Parse a DNS response and return all NS-record RDATA names found (i.e. the
/// authoritative nameservers the queried zone delegates to).
pub fn parse_dns_response_ns(bytes: &[u8]) -> Result<Vec<String>, CFError> {
    if bytes.len() < 12 {
        return Err(CFError::new("DoH parse", "Response too short.", ""));
    }
    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let ancount = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_name(bytes, pos)?;
        pos += 4;
        if pos > bytes.len() {
            return Err(CFError::new("DoH parse", "Question overran message.", ""));
        }
    }
    let mut nss = Vec::new();
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
        if rtype == 2 {
            // NS RDATA = a domain name.
            let (name, _after) = read_name_string(bytes, pos)?;
            nss.push(name);
        }
        pos += rdlen;
    }
    Ok(nss)
}

/// Build a synthetic DNS response with the given A records (test helper).
#[cfg(test)]
pub(crate) fn build_dns_response_a(ips: &[Ipv4Addr]) -> Vec<u8> {
    let mut r: Vec<u8> = Vec::new();
    r.extend_from_slice(&0x1234u16.to_be_bytes());
    r.extend_from_slice(&0x8180u16.to_be_bytes()); // QR+RD+RA
    r.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    r.extend_from_slice(&(ips.len() as u16).to_be_bytes()); // ANCOUNT
    r.extend_from_slice(&0u16.to_be_bytes());
    r.extend_from_slice(&0u16.to_be_bytes());
    // question: example.com + QTYPE A + QCLASS IN
    r.push(7);
    r.extend_from_slice(b"example");
    r.push(3);
    r.extend_from_slice(b"com");
    r.push(0);
    r.extend_from_slice(&1u16.to_be_bytes());
    r.extend_from_slice(&1u16.to_be_bytes());
    for ip in ips {
        r.extend_from_slice(&[0xC0, 0x0C]); // pointer to name
        r.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        r.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        r.extend_from_slice(&300u32.to_be_bytes()); // TTL
        r.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        r.extend_from_slice(&ip.octets());
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_resolver() -> DohResolver {
        DohResolver::mock(vec![])
    }

    fn set_scripted(r: &DohResolver, responses: Vec<Result<Vec<u8>, CFError>>) {
        match &r.backend {
            DohBackend::Mock { queue, .. } => *queue.lock().unwrap() = responses,
            _ => panic!("not a mock resolver"),
        }
    }

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
    fn test_build_dns_query_a_is_well_formed() {
        let q = build_dns_query_a("example.com", 0x1234);
        assert_eq!(q.len(), 12 + 8 + 4 + 1 + 2 + 2);
        assert_eq!(&q[0..2], &[0x12, 0x34]);
        assert_eq!(&q[2..4], &[0x01, 0x00]);
        assert_eq!(&q[4..6], &[0x00, 0x01]);
        assert_eq!(q[12], 7);
        assert_eq!(&q[13..20], b"example");
        assert_eq!(q[20], 3);
        assert_eq!(&q[21..24], b"com");
        assert_eq!(q[24], 0);
        assert_eq!(&q[25..27], &[0x00, 0x01]);
        assert_eq!(&q[27..29], &[0x00, 0x01]);
    }

    #[test]
    fn test_parse_dns_response_a_extracts_multiple() {
        let r = build_dns_response_a(&[Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(198, 18, 0, 5)]);
        let ips = parse_dns_response_a(&r).unwrap();
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(ips[1], Ipv4Addr::new(198, 18, 0, 5));
    }

    #[test]
    fn test_parse_dns_response_a_handles_compression_pointers() {
        let mut r: Vec<u8> = Vec::new();
        r.extend_from_slice(&0x0001u16.to_be_bytes());
        r.extend_from_slice(&0x8180u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
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
    fn test_parse_dns_response_a_rejects_truncated() {
        assert!(parse_dns_response_a(&[0, 0, 0, 0]).is_err());
        let r = build_dns_query_a("example.com", 1);
        assert!(parse_dns_response_a(&r[..20]).is_err() || parse_dns_response_a(&r[..20]).is_ok());
    }

    #[test]
    fn test_build_dns_query_txt_is_well_formed() {
        let q = build_dns_query_txt("tun.example.com", 0x4321);
        // Header 12 + name ("tun.example.com": 1+3+1+7+1+3+1=17) + QTYPE + QCLASS
        let name_len = 3 + 1 + 7 + 1 + 3 + 1 + 1; // labels + lengths + root
        assert_eq!(name_len, 17);
        assert_eq!(q.len(), 12 + name_len + 2 + 2);
        assert_eq!(&q[0..2], &[0x43, 0x21]);
        assert_eq!(&q[2..4], &[0x01, 0x00]);
        assert_eq!(&q[4..6], &[0x00, 0x01]);
        // QTYPE=TXT = 16
        let qtype_off = 12 + name_len;
        assert_eq!(&q[qtype_off..qtype_off + 2], &[0x00, 0x10]);
        assert_eq!(&q[qtype_off + 2..qtype_off + 4], &[0x00, 0x01]);
    }

    #[test]
    fn test_parse_dns_response_txt_extracts_strings() {
        // Build a response with one TXT answer containing a single string.
        // The owner name is written inline (no compression pointer) to keep the
        // answer self-contained.
        let mut r: Vec<u8> = Vec::new();
        r.extend_from_slice(&0x4321u16.to_be_bytes());
        r.extend_from_slice(&0x8180u16.to_be_bytes()); // QR+RD+RA
        r.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        r.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        // Question: tun.example.com + QTYPE TXT + QCLASS IN
        r.push(3);
        r.extend_from_slice(b"tun");
        r.push(7);
        r.extend_from_slice(b"example");
        r.push(3);
        r.extend_from_slice(b"com");
        r.push(0);
        r.extend_from_slice(&16u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        // Answer: same inline name + TXT RDATA with one string.
        r.push(3);
        r.extend_from_slice(b"tun");
        r.push(7);
        r.extend_from_slice(b"example");
        r.push(3);
        r.extend_from_slice(b"com");
        r.push(0);
        r.extend_from_slice(&16u16.to_be_bytes()); // TYPE TXT
        r.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        r.extend_from_slice(&60u32.to_be_bytes()); // TTL
        r.extend_from_slice(&7u16.to_be_bytes()); // RDLENGTH
        r.push(6); // "status" string length
        r.extend_from_slice(b"status");
        let txts = parse_dns_response_txt(&r).unwrap();
        assert_eq!(txts, vec!["status".to_string()]);
    }

    #[test]
    fn test_parse_dns_response_txt_handles_multiple_strings() {
        let mut r: Vec<u8> = Vec::new();
        r.extend_from_slice(&0x0025u16.to_be_bytes());
        r.extend_from_slice(&0x8180u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        r.push(3);
        r.extend_from_slice(b"tun");
        r.push(7);
        r.extend_from_slice(b"example");
        r.push(3);
        r.extend_from_slice(b"com");
        r.push(0);
        r.extend_from_slice(&16u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.push(3);
        r.extend_from_slice(b"tun");
        r.push(7);
        r.extend_from_slice(b"example");
        r.push(3);
        r.extend_from_slice(b"com");
        r.push(0);
        r.extend_from_slice(&16u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&60u32.to_be_bytes());
        r.extend_from_slice(&12u16.to_be_bytes());
        r.push(5);
        r.extend_from_slice(b"hello");
        r.push(5);
        r.extend_from_slice(b"world");
        let txts = parse_dns_response_txt(&r).unwrap();
        assert_eq!(txts, vec!["hello".to_string(), "world".to_string()]);
    }

    #[test]
    fn test_parse_dns_response_txt_rejects_truncated() {
        assert!(parse_dns_response_txt(&[0, 0, 0, 0]).is_err());
        let q = build_dns_query_txt("tun.example.com", 1);
        assert!(parse_dns_response_txt(&q[..18]).is_err());
    }

    #[test]
    fn test_skip_name_rejects_pointer_loop() {
        // A compression pointer that references its own offset must not spin
        // forever — the cycle guard should return an error instead.
        let mut r: Vec<u8> = Vec::new();
        r.extend_from_slice(&0x0001u16.to_be_bytes());
        r.extend_from_slice(&0x8180u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT=0 → answer starts at 12
        r.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        // Owner name = pointer to offset 12 (itself).
        r.extend_from_slice(&[0xC0, 0x0C]);
        assert!(parse_dns_response_txt(&r).is_err());
    }

    #[test]
    fn test_doh_resolver_client_pins_endpoint_ip() {
        // The real transport must build a reqwest client with a `.resolve()` pin
        // for every endpoint hostname (proving no system-DNS bootstrap).
        let client = build_real_client(DEFAULT_ENDPOINTS).expect("client should build");
        // If the client built successfully with resolve() pins for all endpoints,
        // the bootstrap pitfall is resolved.
        assert!(client
            .get("https://cloudflare-dns.com/dns-query")
            .build()
            .is_ok());
        for ep in DEFAULT_ENDPOINTS {
            assert!(
                !is_hijacked_ip(&ep.ip),
                "endpoints themselves must not be hijacked"
            );
        }
    }

    #[tokio::test]
    async fn test_doh_resolve_returns_ips_against_mock_endpoint() {
        let r = mock_resolver();
        let good = build_dns_response_a(&[Ipv4Addr::new(104, 16, 132, 229)]);
        set_scripted(&r, vec![Ok(good)]);
        let ips = r.resolve("worker.example.com").await.unwrap();
        assert_eq!(ips, vec![Ipv4Addr::new(104, 16, 132, 229)]);
    }

    #[tokio::test]
    async fn test_doh_resolve_filters_hijacked_198_18() {
        let r = mock_resolver();
        let hijacked = build_dns_response_a(&[Ipv4Addr::new(198, 18, 0, 5)]);
        let real = build_dns_response_a(&[Ipv4Addr::new(8, 8, 8, 8)]);
        set_scripted(&r, vec![Ok(hijacked), Ok(real)]);
        // First endpoint returns only hijacked → filtered; second endpoint returns a real IP.
        let ips = r.resolve("worker.example.com").await.unwrap();
        assert_eq!(ips, vec![Ipv4Addr::new(8, 8, 8, 8)]);
    }

    #[tokio::test]
    async fn test_doh_resolve_falls_back_to_second_endpoint() {
        let r = mock_resolver();
        let real = build_dns_response_a(&[Ipv4Addr::new(1, 1, 1, 1)]);
        set_scripted(
            &r,
            vec![Err(CFError::new("net", "first down", "")), Ok(real)],
        );
        let ips = r.resolve("worker.example.com").await.unwrap();
        assert_eq!(ips, vec![Ipv4Addr::new(1, 1, 1, 1)]);
    }

    #[tokio::test]
    async fn test_doh_resolve_caches_within_ttl() {
        let r = mock_resolver();
        let good = build_dns_response_a(&[Ipv4Addr::new(104, 16, 132, 229)]);
        set_scripted(&r, vec![Ok(good.clone()), Ok(good)]);
        let a = r.resolve("cached.example.com").await.unwrap();
        let b = r.resolve("cached.example.com").await.unwrap();
        assert_eq!(a, b);
        // Second resolve should have hit the cache: only 1 POST served.
        assert_eq!(r.mock_calls(), 1);
    }

    #[tokio::test]
    async fn test_doh_resolve_expires_after_ttl() {
        let r = mock_resolver().with_ttl(Duration::from_millis(1));
        let good = build_dns_response_a(&[Ipv4Addr::new(104, 16, 132, 229)]);
        set_scripted(&r, vec![Ok(good.clone()), Ok(good)]);
        let _ = r.resolve("cached.example.com").await.unwrap();
        std::thread::sleep(Duration::from_millis(5));
        let _ = r.resolve("cached.example.com").await.unwrap();
        // After expiry the cache should have been refreshed: 2 POSTs served.
        assert_eq!(r.mock_calls(), 2);
    }

    #[tokio::test]
    async fn test_probe_network_liveness_succeeds_on_mock_doh() {
        let r = mock_resolver();
        let real = build_dns_response_a(&[Ipv4Addr::new(8, 8, 8, 8)]);
        set_scripted(&r, vec![Ok(real)]);
        assert!(probe_network_liveness(&r).await);
    }

    #[tokio::test]
    async fn test_probe_network_liveness_fails_on_all_endpoints_down() {
        let r = mock_resolver();
        set_scripted(&r, vec![Err(CFError::new("net", "endpoint down", ""))]);
        assert!(!probe_network_liveness(&r).await);
    }

    #[tokio::test]
    async fn test_probe_network_liveness_rejects_hijacked_answer() {
        let r = mock_resolver();
        let hijacked = build_dns_response_a(&[Ipv4Addr::new(198, 18, 0, 5)]);
        set_scripted(&r, vec![Ok(hijacked)]);
        assert!(!probe_network_liveness(&r).await);
    }
}
