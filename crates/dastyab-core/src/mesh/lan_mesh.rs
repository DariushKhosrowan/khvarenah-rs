//! Level 4 — Intranet P2P LAN mesh relay.
//!
//! The final rung of the resilience ladder (PRINCIPLES §3 Level 4): when every
//! foreign egress path is severed, DastYab hunts for *other* running
//! DastYab instances on the local LAN that still hold an upstream uplink and
//! uses one as a local hop forwarder.
//!
//! This module implements the discovery and neighbor-maintenance half of that
//! ladder:
//!
//! - A **broadcast beacon** (raw UDP, `UDP_PORT`) announces this instance's
//!   presence, identity, and whether it currently has a working upstream
//!   uplink (`has_uplink`). Peers on the same broadcast domain hear it.
//! - A **discovery task** listens for beacons, builds a neighbor table, and
//!   keeps it fresh with same-interval heartbeats. Stale neighbors are pruned
//!   (`NEIGHBOR_TIMEOUT_SECS`).
//! - **Relay selection** picks the best relayable peer — preferring one with
//!   an active uplink, lowest RTT, and most-recent heartbeat — so the
//!   transport layer can open a local hop through it.
//!
//! Design notes:
//! - Ping on the same LAN is cheap and off-path, so this beacon always runs
//!   (it does not consume foreign bandwidth), matching doctrine §6.5
//!   (`do the cheapest useful thing first`).
//! - The beacon is tiny (< 256 bytes), one-shot per interval, and rate-limited
//!   so it cannot trip anything.
//! - This module is **pure discovery/selection** — it does not itself proxy
//!   packets (that is the transport layer's job). It returns a verified relay
//!   candidate the caller can open a hop through.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The fixed UDP port the mesh beacon listens/broadcasts on.
pub const UDP_PORT: u16 = 5837;

/// Magic marker that prefixes every beacon payload. Used to ignore foreign
/// traffic that happens to hit the port.
pub const MAGIC: &str = "DYBMESH1";

/// How often (seconds) each instance broadcasts its beacon.
pub const ANNOUNCE_INTERVAL_SECS: u64 = 8;

/// After this many seconds without a heartbeat a neighbor is considered dead.
pub const NEIGHBOR_TIMEOUT_SECS: u64 = 30;

/// Wire payload of a mesh beacon.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Beacon {
    pub magic: String,
    /// Stable per-instance id (uid). Used to dedup / self-ignore.
    pub peer_id: String,
    /// The port this instance listens on for relay hops (may be 0 if it only
    /// forwards, never hosts).
    pub relay_port: u16,
    /// Whether this instance currently has a working upstream uplink.
    pub has_uplink: bool,
    /// Short human-readable host label.
    pub name: String,
}

impl Beacon {
    pub fn new(peer_id: impl Into<String>, name: impl Into<String>, has_uplink: bool) -> Self {
        Self {
            magic: MAGIC.to_string(),
            peer_id: peer_id.into(),
            relay_port: UDP_PORT,
            has_uplink,
            name: name.into(),
        }
    }

    /// Serialize to the wire form.
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Try to parse a datagram as a beacon.
    pub fn decode(raw: &[u8]) -> Option<Self> {
        let b: Beacon = serde_json::from_slice(raw).ok()?;
        if b.magic != MAGIC {
            return None;
        }
        Some(b)
    }
}

/// A live neighbor discovered on the mesh.
#[derive(Debug, Clone, PartialEq)]
pub struct Neighbor {
    pub peer_id: String,
    /// Source socket (ip:relay_port) we can hop through.
    pub addr: SocketAddr,
    pub name: String,
    pub has_uplink: bool,
    /// Unix secs of the most recent heartbeat.
    pub last_seen_unix: u64,
    /// Smoothed RTT estimate in ms (0 = unknown).
    pub rtt_ms: u64,
}

impl Neighbor {
    pub fn is_fresh(&self, now_unix: u64) -> bool {
        now_unix.saturating_sub(self.last_seen_unix) <= NEIGHBOR_TIMEOUT_SECS
    }
}

/// A simple thread-safe neighbor table shared between the listener task and
/// the caller.
#[derive(Debug, Default)]
pub struct NeighborTable {
    map: Mutex<HashMap<String, Neighbor>>,
}

impl NeighborTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a heartbeat from `src`. Inserts or refreshes the entry. Returns
    /// the resulting neighbor.
    pub fn observe(&self, src: SocketAddr, b: &Beacon, now_unix: u64) -> Neighbor {
        let addr = if b.relay_port == 0 {
            src
        } else {
            SocketAddr::new(src.ip(), b.relay_port)
        };
        let n = Neighbor {
            peer_id: b.peer_id.clone(),
            addr,
            name: b.name.clone(),
            has_uplink: b.has_uplink,
            last_seen_unix: now_unix,
            rtt_ms: 0,
        };
        let mut guard = self.map.lock().unwrap();
        // Preserve smoothed RTT across heartbeats.
        if let Some(prev) = guard.get(&b.peer_id) {
            let mut n = n;
            n.rtt_ms = prev.rtt_ms;
            guard.insert(b.peer_id.clone(), n.clone());
            return n;
        }
        guard.insert(b.peer_id.clone(), n.clone());
        n
    }

    /// Record an RTT sample for a peer.
    pub fn observe_rtt(&self, peer_id: &str, rtt_ms: u64) {
        if let Some(g) = self.map.lock().unwrap().get_mut(peer_id) {
            // EWMA: 0.5 old + 0.5 new keeps it responsive but stable.
            g.rtt_ms = if g.rtt_ms == 0 {
                rtt_ms
            } else {
                (g.rtt_ms + rtt_ms) / 2
            };
        }
    }

    /// Remove all stale peers.
    pub fn prune_stale(&self, now_unix: u64) {
        self.map.lock().unwrap().retain(|_, n| n.is_fresh(now_unix));
    }

    /// Remove a specific peer id (used to drop our own echo/loopback).
    pub fn forget(&self, peer_id: &str) {
        self.map.lock().unwrap().remove(peer_id);
    }

    /// All live neighbors sorted by recency (most recent first).
    pub fn live(&self, now_unix: u64) -> Vec<Neighbor> {
        self.prune_stale(now_unix);
        let mut v: Vec<Neighbor> = self.map.lock().unwrap().values().cloned().collect();
        v.sort_by_key(|n| std::cmp::Reverse(n.last_seen_unix));
        v
    }

    /// The best relay candidate: prefers a fresh peer with an active uplink,
    /// and among those the lowest RTT (ties → most recent).
    pub fn best_relay(&self, now_unix: u64) -> Option<Neighbor> {
        let live = self.live(now_unix);
        live.into_iter()
            .filter(|n| n.has_uplink)
            .min_by_key(|n| (n.rtt_ms, std::cmp::Reverse(n.last_seen_unix)))
    }

    pub fn len(&self, now_unix: u64) -> usize {
        self.live(now_unix).len()
    }
}

/// Broadcast a single beacon datagram and return whether the send succeeded.
/// `src` is the local address to bind; `bcast` is the directed-broadcast
/// address (default `255.255.255.255`). This is a blocking call on the local
/// loopback — cheap, off-path, and rate-limited by the caller.
pub fn broadcast_beacon(src: SocketAddr, bcast: Ipv4Addr, beacon: &Beacon) -> std::io::Result<()> {
    let sock = UdpSocket::bind(src)?;
    sock.set_broadcast(true)?;
    let payload = beacon.encode();
    let dst = SocketAddrV4::new(bcast, UDP_PORT);
    sock.send_to(&payload, dst)?;
    Ok(())
}

/// Listen for beacons for `for_secs` and feed them into `table`. Returns once
/// the window elapses. This is the open side of a discovery sweep.
pub fn listen_once(
    bind: SocketAddr,
    table: &NeighborTable,
    for_secs: u64,
    now_unix: u64,
) -> std::io::Result<usize> {
    let sock = UdpSocket::bind(bind)?;
    sock.set_nonblocking(true)?;
    let mut buf = [0u8; 512];
    let deadline = std::time::Instant::now() + Duration::from_secs(for_secs);
    let mut heard = 0;
    while std::time::Instant::now() < deadline {
        match sock.recv_from(&mut buf) {
            Ok((n, src)) => {
                if let Some(b) = Beacon::decode(&buf[..n]) {
                    if b.peer_id.is_empty() {
                        continue;
                    }
                    table.observe(src, &b, now_unix);
                    heard += 1;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(heard)
}

/// A full one-shot discovery sweep: broadcast our own beacon (so peers hear
/// us) and listen for theirs for `for_secs`. Returns the number of distinct
/// peers heard. Uses the loopback-unique port by default.
pub fn discover_once(
    peer_id: &str,
    name: &str,
    has_uplink: bool,
    for_secs: u64,
    now_unix: u64,
) -> (NeighborTable, usize) {
    let table = NeighborTable::new();
    let self_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);
    let beacon = Beacon::new(peer_id, name, has_uplink);
    let _ = broadcast_beacon(self_addr, Ipv4Addr::new(255, 255, 255, 255), &beacon);
    let heard = listen_once(
        SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), UDP_PORT),
        &table,
        for_secs,
        now_unix,
    )
    .unwrap_or(0);
    // Drop our own loopback/broadcast echo so the table only holds real peers.
    table.forget(peer_id);
    (table, heard)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000_000;

    fn beacon(peer: &str, up: bool, name: &str) -> Beacon {
        Beacon::new(peer, name, up)
    }

    #[test]
    fn beacon_roundtrip() {
        let b = beacon("p1", true, "host-a");
        let enc = b.encode();
        let dec = Beacon::decode(&enc).unwrap();
        assert_eq!(dec, b);
    }

    #[test]
    fn beacon_rejects_foreign_magic() {
        let raw =
            br#"{"magic":"NOTMESH","peer_id":"x","relay_port":5,"has_uplink":false,"name":"x"}"#;
        assert!(Beacon::decode(raw).is_none());
        let malformed = "not-json".as_bytes();
        assert!(Beacon::decode(malformed).is_none());
    }

    #[test]
    fn table_tracks_and_prunes_stale() {
        let t = NeighborTable::new();
        let src = SocketAddr::new([192, 168, 1, 50].into(), 40000);
        let b = beacon("p1", true, "a");
        t.observe(src, &b, NOW);
        assert_eq!(t.len(NOW), 1);
        // Advance past timeout → stale, pruned.
        assert_eq!(t.len(NOW + NEIGHBOR_TIMEOUT_SECS + 1), 0);
    }

    #[test]
    fn table_forget_drops_self_echo() {
        let t = NeighborTable::new();
        let src = SocketAddr::new([192, 168, 1, 6].into(), 5837);
        t.observe(src, &beacon("myself-echo", true, "host"), NOW);
        assert_eq!(t.len(NOW), 1);
        t.forget("myself-echo");
        assert_eq!(t.len(NOW), 0);
    }

    #[test]
    fn best_relay_prefers_uplink_fresh() {
        let t = NeighborTable::new();
        let src = |ip: u8| SocketAddr::new([192, 168, 1, ip].into(), 1000);
        t.observe(src(1), &beacon("up", true, "a"), NOW);
        t.observe(src(2), &beacon("down", false, "b"), NOW);
        let best = t.best_relay(NOW).unwrap();
        assert_eq!(best.peer_id, "up");
        assert!(best.has_uplink);
    }

    #[test]
    fn best_relay_prefers_low_rtt() {
        let t = NeighborTable::new();
        let src = |ip: u8| SocketAddr::new([192, 168, 1, ip].into(), 1000);
        t.observe(src(1), &beacon("slow", true, "a"), NOW);
        t.observe(src(2), &beacon("fast", true, "b"), NOW);
        t.observe_rtt("slow", 240);
        t.observe_rtt("fast", 40);
        assert_eq!(t.best_relay(NOW).unwrap().peer_id, "fast");
    }
}
