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
    let sock = UdpSocket::bind(bind)?;
    sock.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(for_secs);
    let mut buf = [0u8; MAX_RELAY_PACKET];
    let mut answered = 0;
    while Instant::now() < deadline {
        match sock.recv_from(&mut buf) {
            Ok((len, src)) => {
                if let Some(RelayFrame::EchoRequest { nonce: n }) = RelayFrame::decode(&buf[..len])
                {
                    let reply = RelayFrame::EchoReply { nonce: n }.encode();
                    let _ = sock.send_to(&reply, src);
                    answered += 1;
                }
                // Data frames are currently a no-op skeleton (forwarding will
                // ride on this dispatch when the egress data plane lands).
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(answered)
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
}
