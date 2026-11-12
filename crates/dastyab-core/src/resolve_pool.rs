//! Domestic-resolver pool + raw-UDP DNS transport for the blackout DNS tunnel.
//!
//! In a total Iranian internet blackout the client cannot talk directly to a
//! foreign IP on UDP 53 — the border drops it. What still works is the path:
//!
//! ```text
//! [ client ] --UDP 53--> [ domestic ISP recursive resolver (Irancell/MCI/…) ]
//!     --> [ foreign authoritative tunnel server (NS-delegated) ]
//! ```
//!
//! The domestic resolver is *local infrastructure* the censor must keep alive
//! (the network breaks otherwise), and it recurses across the border to the
//! authoritative nameserver we delegate the tunnel subdomain to. So the client
//! sends its encoded tunnel queries **through** a pool of working domestic
//! resolvers instead of straight to the VPS.
//!
//! This module provides:
//! - `udp_query_txt` — raw-UDP JSONT query to an arbitrary resolver IP (the
//!   transport used for both the pool and the open-resolver scanner).
//! - `ResolverPool` — a round-robin `[crate::dnstunnel::Resolver]` that fans
//!   queries across many domestic resolvers to dodge per-IP rate limits and
//!   single-point poisoning (mirrors the 50–150-resolver production pattern).
//! - `discover_open_resolvers` — a parallel scanner over candidate Iranian ISP
//!   resolver addresses that returns the pool of live, recursing resolvers.
//!
//! Seed lists are documented as seeds: real resolver IPs change, so always run
//! the scanner before a blackout and persist the resulting pool.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::dnstunnel::Resolver;
use crate::error::CFError;

/// Default per-query timeout for raw-UDP resolver exchanges.
pub const DEFAULT_RESOLVER_TIMEOUT: Duration = Duration::from_secs(3);

/// Seed candidate Iranian ISP recursive-resolver addresses, **to be verified by
/// scanning** (they are a starting point, not a live pool). Iranian ISPs rotate
/// resolver IPs; production should always run [`discover_open_resolvers`] and
/// persist its output. The list is drawn from the ISP ranges named in the
/// project's blackout plan (MCI, Irancell, Shatel, Mokhaberat, Pars Online,
/// Respina, Asratec).
pub const IRANIAN_RESOLVER_CANDIDATES: &[&str] = &[
    // Irancell
    "10.202.10.10",
    "10.202.10.11",
    "172.16.5.10",
    "78.157.42.100",
    "78.157.42.101",
    // MCI (Hamrah Aval)
    "10.10.34.36",
    "10.10.34.35",
    "194.225.62.15",
    "194.225.62.16",
    // Shatel
    "85.15.1.14",
    "85.15.1.15",
    // Mokhaberat / TCI
    "10.20.30.10",
    "10.20.30.11",
    // Pars Online
    "80.191.67.2",
    "80.191.67.3",
    // Generic domestic fallback seeds
    "5.202.100.100",
    "5.202.100.101",
];

/// Send a raw DNS query over UDP to `server` and return the raw response bytes.
///
/// `server` is an IPv4 address (port defaults to 53) or a `host:port` string.
pub async fn udp_raw_exchange(
    server: &str,
    query: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, CFError> {
    let sa = parse_resolver_addr(server)?;
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| CFError::new("resolve-pool", format!("bind: {e}"), ""))?;
    sock.send_to(query, sa)
        .await
        .map_err(|e| CFError::new("resolve-pool", format!("send {server}: {e}"), ""))?;
    let mut buf = [0u8; 1024];
    let (n, _) = tokio::time::timeout(timeout, sock.recv_from(&mut buf))
        .await
        .map_err(|_| {
            CFError::new(
                "resolve-pool",
                format!("timeout querying {server}"),
                "Resolver did not answer in time — likely closed or filtered.",
            )
        })?
        .map_err(|e| CFError::new("resolve-pool", format!("recv {server}: {e}"), ""))?;
    Ok(buf[..n].to_vec())
}

/// Resolve a resolver spec: bare IPv4 (port 53) or `host:port`.
fn parse_resolver_addr(server: &str) -> Result<SocketAddr, CFError> {
    // Explicit host:port (or already a full SocketAddr).
    if server.contains(':') {
        if let Ok(sa) = server.parse::<SocketAddr>() {
            return Ok(sa);
        }
    }
    // Bare IPv4 → port 53.
    if let Ok(ip) = server.parse::<Ipv4Addr>() {
        return Ok(SocketAddr::new(std::net::IpAddr::V4(ip), 53));
    }
    Err(CFError::new(
        "resolve-pool",
        format!("cannot parse resolver address '{server}'"),
        "Use an IPv4 address or host:port.",
    ))
}

/// Query a resolver for the TXT records of `name` over raw UDP. Returns the
/// TXT character-strings concatenated (the tunnel reply is a single TXT string).
pub async fn udp_query_txt(server: &str, name: &str, timeout: Duration) -> Result<String, CFError> {
    let id: u16 = rand::random();
    let query = crate::doh::build_dns_query_txt(name, id);
    let raw = udp_raw_exchange(server, &query, timeout).await?;
    let txts = crate::doh::parse_dns_response_txt(&raw)?;
    Ok(txts.join(""))
}

/// Simple liveness/recursion probe for a single candidate resolver: a TXT
/// query for a unique subdomain of a globally resolvable domain. Succeeds when
/// the resolver returns a well-formed DNS response (proving it recurses).
pub async fn resolver_probe(server: &str, timeout: Duration) -> bool {
    let nonce: u32 = rand::random();
    let name = format!("{nonce:x}.example.com");
    udp_query_txt(server, &name, timeout).await.is_ok()
}

/// A round-robin pool of domestic resolvers implementing `[Resolver]`.
///
/// Queries are spread across the pool to avoid per-IP query-rate alarms and to
/// survive individual poisoned/unreachable resolvers. Any resolver that errors
/// is skipped on the next round (the atomic cursor advances every call).
pub struct ResolverPool {
    resolvers: Arc<Vec<String>>,
    cursor: AtomicUsize,
    timeout: Duration,
}

impl ResolverPool {
    /// Build a pool from a list of resolver addresses.
    pub fn new(resolvers: Vec<String>, timeout: Duration) -> Self {
        Self {
            resolvers: Arc::new(resolvers),
            cursor: AtomicUsize::new(0),
            timeout,
        }
    }

    /// Number of resolvers in the pool.
    pub fn len(&self) -> usize {
        self.resolvers.len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.resolvers.is_empty()
    }

    /// Query through the pool; returns the first successful resolver's reply.
    fn query_pool(&self, name: &str) -> Result<String, CFError> {
        if self.resolvers.is_empty() {
            return Err(CFError::new("resolve-pool", "empty resolver pool", ""));
        }
        let n = self.resolvers.len();
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) % n;
        let mut last_err: Option<CFError> = None;
        for i in 0..n {
            let idx = (start + i) % n;
            let srv = self.resolvers[idx].clone();
            let timeout = self.timeout;
            // `Resolver::query_txt` is synchronous; run the async UDP exchange
            // on a dedicated OS thread with its own current-thread runtime (the
            // same pattern as WorkerTunnelResolver) so we never create/drop a
            // runtime inside another tokio context.
            let result = std::thread::scope(|scope| {
                let handle = scope.spawn(move || {
                    let rt = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(rt) => rt,
                        Err(e) => {
                            return Err(CFError::new("resolve-pool", format!("runtime: {e}"), ""));
                        }
                    };
                    rt.block_on(udp_query_txt(&srv, name, timeout))
                });
                handle.join().unwrap_or_else(|_| {
                    Err(CFError::new("resolve-pool", "query thread panicked", ""))
                })
            });
            match result {
                Ok(reply) => return Ok(reply),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| CFError::new("resolve-pool", "all resolvers failed", "")))
    }
}

impl Resolver for ResolverPool {
    fn query_txt(&self, name: &str) -> Result<String, CFError> {
        self.query_pool(name)
    }
}

/// Scan candidate resolver addresses in parallel and return the live, recursing
/// subset (the pool to persist for blackout use).
///
/// `concurrency` bounds simultaneous probes; `per_timeout` is the per-resolver
/// timeout; `probe_name` defaults to a unique `example.com` subdomain when empty.
pub async fn discover_open_resolvers(
    candidates: &[String],
    concurrency: usize,
    per_timeout: Duration,
    probe_name: &str,
) -> Vec<String> {
    if candidates.is_empty() {
        return Vec::new();
    }
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
    let mut handles = Vec::with_capacity(candidates.len());
    for c in candidates {
        let permit = match sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break,
        };
        let c = c.clone();
        let probe = if probe_name.trim().is_empty() {
            let nonce: u32 = rand::random();
            format!("{nonce:x}.example.com")
        } else {
            probe_name.to_string()
        };
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            udp_query_txt(&c, &probe, per_timeout)
                .await
                .is_ok()
                .then_some(c)
        }));
    }
    let mut out = Vec::new();
    for h in handles {
        if let Ok(Some(s)) = h.await {
            out.push(s);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnstt_server::{handle_datagram, DnsTunnelServer, TunnelHandler};
    use crate::dnstunnel::TunnelFrame;

    /// Spawn a minimal UDP DNS responder on 127.0.0.1:<ephemeral> that answers
    /// well-formed tunnel frames using the real authoritative handler, and any
    /// other TXT query with a generic answer (emulating a live recursive
    /// resolver). Returns the address the client should query.
    fn spawn_tunnel_udp(base: &str) -> std::net::SocketAddr {
        use std::net::UdpSocket;
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind responder");
        let addr = sock.local_addr().expect("local addr");
        let server = Arc::new(DnsTunnelServer::new(
            base.to_string(),
            TunnelHandler::default(),
        ));
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, src)) => {
                        let pkt = &buf[..n];
                        if let Some(resp) = handle_datagram(pkt, &server) {
                            let _ = sock.send_to(&resp, src);
                        } else {
                            // Not a tunnel frame → emulate an ordinary recursive
                            // resolver that answers the query anyway.
                            if let Ok((id, qname, _, _)) = crate::dnstt_server::parse_question(pkt)
                            {
                                let resp = crate::dnstt_server::build_dns_response_txt(
                                    id,
                                    &qname,
                                    &["ok".to_string()],
                                );
                                let _ = sock.send_to(&resp, src);
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        addr
    }

    fn addr_str(addr: std::net::SocketAddr) -> String {
        format!("{addr}")
    }

    #[tokio::test]
    async fn udp_query_txt_roundtrip_against_authoritative_handler() {
        let base = "tun.example.com";
        let addr = spawn_tunnel_udp(base);
        let frame = TunnelFrame {
            session: "sess".into(),
            seq: 7,
            flags: 1, // ping
            payload: b"alive".to_vec(),
        };
        let qname = frame.encode_name_clamped(base, 0xABCD, MAX_QNAME_LEN_C);
        let reply = udp_query_txt(&addr_str(addr), &qname, DEFAULT_RESOLVER_TIMEOUT)
            .await
            .expect("udp query should succeed against local authoritative responder");
        let decoded = TunnelFrame::decode_name(reply.trim_end_matches('.'), base).unwrap();
        assert_eq!(decoded.flags, 1);
        assert_eq!(decoded.payload, b"pong");
    }

    #[tokio::test]
    async fn resolver_pool_roundrobin_skips_dead_and_reaches_live() {
        let base = "tun.example.com";
        let live = spawn_tunnel_udp(base);
        // First two entries are dead (closed port on 127.0.0.1:1), the live
        // one is third — the pool must skip the dead ones and find it.
        let dead = "127.0.0.1:1".to_string();
        let pool = ResolverPool::new(
            vec![dead.clone(), dead.clone(), addr_str(live)],
            Duration::from_millis(800),
        );
        let frame = TunnelFrame {
            session: "s".into(),
            seq: 1,
            flags: 1,
            payload: Vec::new(),
        };
        let qname = frame.encode_name_clamped(base, 1, MAX_QNAME_LEN_C);
        let reply = pool
            .query_txt(&qname)
            .expect("pool should reach live resolver");
        let decoded = TunnelFrame::decode_name(reply.trim_end_matches('.'), base).unwrap();
        assert_eq!(decoded.flags, 1);
        assert_eq!(decoded.payload, b"pong");
    }

    #[tokio::test]
    async fn discover_open_resolvers_detects_the_live_one() {
        let base = "tun.example.com";
        let live = spawn_tunnel_udp(base);
        let candidates = vec![
            "127.0.0.1:1".to_string(),
            addr_str(live),
            "127.0.0.1:2".to_string(),
        ];
        let found = discover_open_resolvers(&candidates, 4, Duration::from_millis(800), "").await;
        assert!(
            found.contains(&addr_str(live)),
            "live resolver must be discovered: {found:?}"
        );
        assert_eq!(found.len(), 1);
    }

    use crate::dnstunnel::MAX_QNAME_LEN as MAX_QNAME_LEN_C;
}
