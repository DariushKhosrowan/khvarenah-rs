//! Level 4 — mesh relay **transport** (the other half of `lan_mesh`).
//!
//! `lan_mesh` performs discovery and relay *selection*: it builds a neighbor
//! table and returns a `best_relay` candidate — a peer that advertises a live
//! upstream uplink. But a candidate is not a usable hop until the transport
//! layer proves the peer actually listens on its advertised relay port and
//! measures the round-trip through it. This module is that transport layer.
//!
//! It provides a tiny, framed UDP relay protocol (sibling to the `Beacon`
//! wire format, with its own magic prefix so the two never collide on the
//! shared port):
//!
//! - **`EchoRequest`/`EchoReply`** — a hop-verification probe. A client sends
//!   a request carrying a nonce; the relay host answers with the same nonce.
//!   Success proves (a) a live relay listener is bound on the advertised
//!   `relay_port`, and (b) the hop is traversable. Round-trip time is measured
//!   directly and feeds back into `NeighborTable::observe_rtt`.
//! - **`Data`/`DataAck`** — a minimal framed forwarding primitive. It
//!   deliberately does NOT touch the network: it is the unit-tested skeleton
//!   the future egress-forwarding data plane hangs off (forward a payload to
//!   the neighbor's relay, which relays it toward its uplink and returns the
//!   answer). The `DataAck` gives the caller loss/timing signal without any
//!   I/O dependency.
//!
//! The protocol is blocking and off-path (a UDP ping on the private LAN), in
//! line with `lan_mesh` and doctrine §6.5 (do the cheapest useful thing
//! first).

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Magic marker that prefixes every relay frame. Distinct from `lan_mesh`'s
/// beacon magic so a beacon and a relay frame never decode as each other.
pub const RELAY_MAGIC: &str = "DYBMRELAY1";

/// Upper bound on a relay frame's wire size.
pub const MAX_RELAY_PACKET: usize = 1400;

/// Default echo time budget.
pub const ECHO_TIMEOUT_SECS: u64 = 3;

/// Default egress fetch timeout (the relay's own HTTP request budget).
pub const EGRESS_TIMEOUT_SECS: u64 = 8;

/// Largest response body a relay `DataReply` may carry in a single datagram.
/// Kept well under `MAX_RELAY_PACKET` to leave room for the JSON frame
/// overhead (magic + seq + status).
pub const MAX_DATA_BODY: usize = 1200;

/// A relay frame. Serialized on the wire as `(RELAY_MAGIC, frame)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RelayFrame {
    /// Hop-verification probe. The relay must reply `EchoReply` with the same
    /// nonce.
    EchoRequest { nonce: u64 },
    /// Reply to `EchoRequest`, echoing the nonce.
    EchoReply { nonce: u64 },
    /// A forwarding payload from the client to the relay (the relay relays it
    /// toward its uplink). `seq` is a client-side sequence for dedup/ACK
    /// correlation.
    Data { seq: u64, payload: Vec<u8> },
    /// Acknowledgement of a `Data` frame.
    DataAck { seq: u64 },
    /// Reply to a `Data` egress-forwarding frame carrying the relay's uplink
    /// fetch result (HTTP status + body). `body` is capped at `MAX_DATA_BODY`.
    DataReply {
        seq: u64,
        status: u16,
        body: Vec<u8>,
    },
    /// Failure report for a `Data` frame: malformed request, an egress
    /// transport error, or a response body too large to fit one relay
    /// datagram. The client surfaces `reason` verbatim.
    DataError { seq: u64, reason: String },
}

impl RelayFrame {
    /// Serialize to the wire form (magic-prefixed tuple).
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(&(RELAY_MAGIC.to_string(), self)).unwrap_or_default()
    }

    /// Parse a datagram as a relay frame. Returns `None` for foreign or
    /// malformed traffic.
    pub fn decode(raw: &[u8]) -> Option<Self> {
        let (magic, frame): (String, RelayFrame) = serde_json::from_slice(raw).ok()?;
        if magic != RELAY_MAGIC {
            return None;
        }
        Some(frame)
    }
}

/// A client's egress-forwarding request embedded in a `RelayFrame::Data`
/// payload. The relay executes this against its own uplink and returns the
/// result as `DataReply`/`DataError`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EgressRequest {
    /// HTTP method: `"GET"` or `"POST"`.
    pub method: String,
    /// Absolute URL to fetch through the relay's uplink.
    pub url: String,
    /// Optional request body (POST). Empty for GET.
    #[serde(default)]
    pub body: Vec<u8>,
}

/// The relay's uplink fetch result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EgressReply {
    /// HTTP status code (0 when the fetch never produced an HTTP response).
    pub status: u16,
    /// Response body (capped at `MAX_DATA_BODY`; larger bodies come back as
    /// `DataError` with a size note).
    pub body: Vec<u8>,
}

/// Outcome of forwarding one egress request through a verified relay hop.
#[derive(Debug, Clone, PartialEq)]
pub enum ForwardOutcome {
    /// The relay's uplink fetch succeeded and the response fit a datagram.
    Ok(EgressReply),
    /// The relay reported a failure (malformed request, egress error, or the
    /// response body exceeded the datagram limit).
    Error(String),
}

/// The relay-side egress executor: given a client request, fetch it over the
/// relay's own uplink connection. Abstracted so the server's forwarding logic
/// is unit-testable against a mock (the real impl uses `reqwest`).
pub trait RelayEgress: Send + Sync {
    fn fetch(&self, req: &EgressRequest) -> Result<EgressReply, String>;
}

/// Real uplink fetch via `reqwest` blocking client over the relay's own
/// network path (the peer's working egress).
pub struct RealRelayEgress {
    client: reqwest::blocking::Client,
    timeout: Duration,
}

impl RealRelayEgress {
    pub fn new(timeout: Duration) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());
        Self { client, timeout }
    }
}

impl Default for RealRelayEgress {
    fn default() -> Self {
        Self::new(Duration::from_secs(EGRESS_TIMEOUT_SECS))
    }
}

impl RelayEgress for RealRelayEgress {
    fn fetch(&self, req: &EgressRequest) -> Result<EgressReply, String> {
        let mut rb = match req.method.as_str() {
            "GET" => self.client.get(&req.url),
            "POST" => self.client.post(&req.url).body(req.body.clone()),
            other => return Err(format!("unsupported method {other:?}")),
        };
        rb = rb.timeout(self.timeout);
        let resp = rb.send().map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let body = resp.bytes().map_err(|e| e.to_string())?.to_vec();
        Ok(EgressReply { status, body })
    }
}

/// A relay that refuses data forwarding (echo only). Used by `serve_once`
/// when the host did not advertise upstream.
pub struct NoopEgress;
impl RelayEgress for NoopEgress {
    fn fetch(&self, _req: &EgressRequest) -> Result<EgressReply, String> {
        Err("this relay is not serving upstream data (no --upstream)".to_string())
    }
}

/// A monotonic-ish nonce for echo probes (time-based; no RNG dependency).
fn nonce() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or_else(|_| 0)
}

/// Send a single echo probe to `dst` and measure the round-trip time through
/// the hop. Returns `Ok(Some(rtt_ms))` when the relay replies with a matching
/// nonce, `Ok(None)` when the probe times out with no matching reply (the peer
/// is not serving a relay listener, or the hop is broken), and `Err` on a hard
/// socket failure.
///
/// This is the verification step that turns a `best_relay` *candidate* into a
/// verified, measured hop.
pub fn echo_probe(dst: SocketAddr, timeout: Duration) -> std::io::Result<Option<u64>> {
    let sock = UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))?;
    sock.set_read_timeout(Some(timeout))?;

    let n = nonce();
    let frame = RelayFrame::EchoRequest { nonce: n };
    sock.send_to(&frame.encode(), dst)?;

    let start = Instant::now();
    let deadline = start + timeout;
    let mut buf = [0u8; MAX_RELAY_PACKET];
    while Instant::now() < deadline {
        let (len, _src) = match sock.recv_from(&mut buf) {
            Ok(ok) => ok,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // read-timeout elapsed; the probe failed.
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        if let Some(RelayFrame::EchoReply { nonce: reply }) = RelayFrame::decode(&buf[..len]) {
            if reply == n {
                let rtt_ms = start.elapsed().as_millis() as u64;
                return Ok(Some(rtt_ms));
            }
        }
        // Ignore unrelated datagrams (beacons, other peers) and keep waiting.
    }
    Ok(None)
}

/// Host a relay listener on `bind` for up to `for_secs`, answering `EchoRequest`
/// frames with `EchoReply`. Returns the number of echo requests answered.
///
/// This is the server side of the hop: an instance that advertises `relay_port`
/// in its beacon must run this (or an equivalent listener) for peers' echo
/// probes to succeed. This is a blocking, off-path loop — spawn it on a helper
/// thread, as the CLI does.
pub fn serve_once(bind: SocketAddr, for_secs: u64) -> std::io::Result<usize> {
    serve_with_egress(bind, for_secs, &NoopEgress).map(|(echoed, _)| echoed)
}

/// Host a relay listener on `bind` for up to `for_secs`, answering `EchoRequest`
/// frames with `EchoReply` and forwarding `Data` frames through `egress` (the
/// relay's uplink). Returns the number of echo probes answered and the number
/// of data-forwarding frames handled.
///
/// `Data` handling: a valid `Data` frame's payload is decoded as an
/// `EgressRequest` and executed via `egress.fetch`. The reply is sent back as
/// `DataReply` (status + body) or `DataError` (malformed request / egress
/// failure / body too large). This is the data plane that completes the
/// Level-4 rung: a verified hop's `serve` is now a usable local egress.
pub fn serve_with_egress(
    bind: SocketAddr,
    for_secs: u64,
    egress: &dyn RelayEgress,
) -> std::io::Result<(usize, usize)> {
    let sock = UdpSocket::bind(bind)?;
    sock.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(for_secs);
    let mut buf = [0u8; MAX_RELAY_PACKET];
    let mut answered = 0;
    let mut forwarded = 0;
    while Instant::now() < deadline {
        match sock.recv_from(&mut buf) {
            Ok((len, src)) => {
                match RelayFrame::decode(&buf[..len]) {
                    Some(RelayFrame::EchoRequest { nonce: n }) => {
                        let reply = RelayFrame::EchoReply { nonce: n }.encode();
                        let _ = sock.send_to(&reply, src);
                        answered += 1;
                    }
                    Some(RelayFrame::Data { seq, payload }) => {
                        forwarded += 1;
                        let reply = match serde_json::from_slice::<EgressRequest>(&payload) {
                            Ok(req) => match egress.fetch(&req) {
                                Ok(EgressReply { status, body }) => {
                                    if body.len() > MAX_DATA_BODY {
                                        RelayFrame::DataError {
                                            seq,
                                            reason: format!(
                                                "uplink response body too large ({} > {})",
                                                body.len(),
                                                MAX_DATA_BODY
                                            ),
                                        }
                                    } else {
                                        RelayFrame::DataReply { seq, status, body }
                                    }
                                }
                                Err(reason) => RelayFrame::DataError { seq, reason },
                            },
                            Err(_) => RelayFrame::DataError {
                                seq,
                                reason: "malformed egress request".to_string(),
                            },
                        };
                        let _ = sock.send_to(&reply.encode(), src);
                    }
                    _ => {} // EchoReply / DataAck / DataReply / DataError: inbound-only, ignore
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(e),
        }
    }
    Ok((answered, forwarded))
}

/// Forward one egress request through a verified relay hop (`dst`) and block
/// for the relay's `DataReply`/`DataError`. Returns `ForwardOutcome::Ok` with
/// the relay's uplink fetch result, or `ForwardOutcome::Error` describing a
/// relay-side failure. Timeout is enforced by the socket read timeout and the
/// `timeout` deadline.
///
/// This is the client half of the Level-4 data plane: after `echo_probe`
/// verifies a hop, callers use this to fetch through it.
pub fn forward_data(
    dst: SocketAddr,
    req: &EgressRequest,
    timeout: Duration,
) -> std::io::Result<ForwardOutcome> {
    let sock = UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))?;
    sock.set_read_timeout(Some(timeout))?;

    let seq = nonce();
    let payload = serde_json::to_vec(req).unwrap_or_default();
    let frame = RelayFrame::Data { seq, payload };
    sock.send_to(&frame.encode(), dst)?;

    let start = Instant::now();
    let deadline = start + timeout;
    let mut buf = [0u8; MAX_RELAY_PACKET];
    while Instant::now() < deadline {
        let (len, _src) = match sock.recv_from(&mut buf) {
            Ok(ok) => ok,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return Ok(ForwardOutcome::Error(
                    "relay timed out (no reply)".to_string(),
                ));
            }
            Err(e) => return Err(e),
        };
        if let Some(frame) = RelayFrame::decode(&buf[..len]) {
            match frame {
                RelayFrame::DataReply {
                    seq: s2,
                    status,
                    body,
                } if s2 == seq => {
                    return Ok(ForwardOutcome::Ok(EgressReply { status, body }));
                }
                RelayFrame::DataError { seq: s2, reason } if s2 == seq => {
                    return Ok(ForwardOutcome::Error(reason));
                }
                _ => {} // unrelated datagram, keep waiting
            }
        }
    }
    Ok(ForwardOutcome::Error(
        "relay timed out (no matching reply)".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bind a relay listener on an ephemeral loopback port and spawn it on a
    /// helper thread for the duration of a test.
    fn spawn_echo_server() -> SocketAddr {
        let sock = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let port = sock.local_addr().unwrap().port();
        drop(sock); // release so serve_once can bind it
        let addr = SocketAddr::new("127.0.0.1".parse().unwrap(), port);
        let handle = std::thread::spawn(move || {
            let _ = serve_once(addr, 10);
        });
        // Let the thread bind before we probe. Best-effort; the probe retries
        // until the deadline either way.
        std::thread::sleep(Duration::from_millis(50));
        #[allow(unused_must_use)]
        {
            let _ = handle;
        }
        addr
    }

    #[test]
    fn frame_roundtrip() {
        for f in [
            RelayFrame::EchoRequest { nonce: 7 },
            RelayFrame::EchoReply { nonce: 7 },
            RelayFrame::Data {
                seq: 1,
                payload: b"hello".to_vec(),
            },
            RelayFrame::DataAck { seq: 1 },
            RelayFrame::DataReply {
                seq: 2,
                status: 200,
                body: b"pong".to_vec(),
            },
            RelayFrame::DataError {
                seq: 3,
                reason: "boom".to_string(),
            },
        ] {
            let dec = RelayFrame::decode(&f.encode()).unwrap();
            assert_eq!(dec, f);
        }
    }

    #[test]
    fn frame_rejects_foreign_magic() {
        // A beacon (different magic) must not decode as a relay frame.
        let raw = br#"{"magic":"DYBMESH1","peer_id":"x","relay_port":5837,"has_uplink":false,"name":"x"}"#;
        assert!(RelayFrame::decode(raw).is_none());
        assert!(RelayFrame::decode(b"not-json").is_none());
    }

    #[test]
    fn echo_probe_gets_reply_and_measures_rtt() {
        let addr = spawn_echo_server();
        let rtt = echo_probe(addr, Duration::from_secs(5)).unwrap();
        assert!(rtt.is_some(), "expected a live echo reply, got None");
        // RTT must be a sane small positive value (loopback).
        let rtt = rtt.unwrap();
        assert!(rtt < 10_000, "implausibly large RTT {rtt}ms");
    }

    #[test]
    fn echo_probe_times_out_on_silent_addr() {
        // Bind and release a socket so the port is guaranteed closed.
        let sock = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let addr = sock.local_addr().unwrap();
        drop(sock);
        let rtt = echo_probe(addr, Duration::from_millis(300)).unwrap();
        assert!(
            rtt.is_none(),
            "expected a silent port to time out, got {rtt:?}"
        );
    }

    // ---- Level-4 data plane tests ----

    /// A canned egress executor whose reply is fixed ahead of time.
    struct TestEgress {
        reply: Result<EgressReply, String>,
    }
    impl RelayEgress for TestEgress {
        fn fetch(&self, _req: &EgressRequest) -> Result<EgressReply, String> {
            self.reply.clone()
        }
    }

    fn spawn_data_server(egress: &'static dyn RelayEgress) -> SocketAddr {
        let sock = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let port = sock.local_addr().unwrap().port();
        drop(sock);
        let addr = SocketAddr::new("127.0.0.1".parse().unwrap(), port);
        std::thread::spawn(move || {
            let _ = serve_with_egress(addr, 10, egress);
        });
        std::thread::sleep(Duration::from_millis(50));
        addr
    }

    fn get_req(url: &str) -> EgressRequest {
        EgressRequest {
            method: "GET".to_string(),
            url: url.to_string(),
            body: Vec::new(),
        }
    }

    #[test]
    fn forward_data_gets_reply_via_uplink() {
        let egress: &'static dyn RelayEgress = Box::leak(Box::new(TestEgress {
            reply: Ok(EgressReply {
                status: 200,
                body: b"pong".to_vec(),
            }),
        }));
        let addr = spawn_data_server(egress);
        match forward_data(
            addr,
            &get_req("https://example.test/health"),
            Duration::from_secs(5),
        )
        .unwrap()
        {
            ForwardOutcome::Ok(reply) => {
                assert_eq!(reply.status, 200);
                assert_eq!(reply.body, b"pong");
            }
            ForwardOutcome::Error(e) => panic!("expected Ok reply, got error: {e}"),
        }
    }

    #[test]
    fn forward_data_surfaces_relay_error() {
        let egress: &'static dyn RelayEgress = Box::leak(Box::new(TestEgress {
            reply: Err("uplink unreachable".to_string()),
        }));
        let addr = spawn_data_server(egress);
        match forward_data(
            addr,
            &get_req("https://example.test/"),
            Duration::from_secs(5),
        )
        .unwrap()
        {
            ForwardOutcome::Ok(_) => panic!("expected relay error, got Ok"),
            ForwardOutcome::Error(e) => assert!(e.contains("uplink unreachable"), "got: {e}"),
        }
    }

    #[test]
    fn serve_egress_reports_oversized_body() {
        // A body over MAX_DATA_BODY must come back as an Error naming the size.
        let big = vec![0xabu8; MAX_DATA_BODY + 1];
        let egress: &'static dyn RelayEgress = Box::leak(Box::new(TestEgress {
            reply: Ok(EgressReply {
                status: 200,
                body: big,
            }),
        }));
        let addr = spawn_data_server(egress);
        match forward_data(
            addr,
            &get_req("https://example.test/big"),
            Duration::from_secs(5),
        )
        .unwrap()
        {
            ForwardOutcome::Ok(_) => panic!("expected oversized-body error, got Ok"),
            ForwardOutcome::Error(e) => assert!(e.contains("too large"), "got: {e}"),
        }
    }

    #[test]
    fn forward_data_times_out_on_silent_addr() {
        let sock = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let addr = sock.local_addr().unwrap();
        drop(sock);
        match forward_data(
            addr,
            &get_req("https://example.test/"),
            Duration::from_millis(300),
        )
        .unwrap()
        {
            ForwardOutcome::Ok(_) => panic!("expected timeout, got Ok"),
            ForwardOutcome::Error(e) => assert!(e.contains("timed out"), "got: {e}"),
        }
    }

    #[test]
    fn serve_egress_handles_echo_and_data_together() {
        // A single server must still answer echo probes while also forwarding
        // data (mixed dispatch on one socket).
        let egress: &'static dyn RelayEgress = Box::leak(Box::new(TestEgress {
            reply: Ok(EgressReply {
                status: 204,
                body: Vec::new(),
            }),
        }));
        let addr = spawn_data_server(egress);
        let rtt = echo_probe(addr, Duration::from_secs(5)).unwrap();
        assert!(
            rtt.is_some(),
            "echo should still succeed on a data-serving relay"
        );
        match forward_data(
            addr,
            &get_req("https://example.test/"),
            Duration::from_secs(5),
        )
        .unwrap()
        {
            ForwardOutcome::Ok(reply) => assert_eq!(reply.status, 204),
            ForwardOutcome::Error(e) => panic!("unexpected error: {e}"),
        }
    }
}
