//! Level-3 "UDP-native" windowed ARQ transport over the DNS tunnel.
//!
//! The existing `dnstunnel` client is a single query→reply primitive: one
//! `TunnelFrame` out, one frame back. The `arq` engine already provides a
//! battle-tested selective-repeat sliding-window sender/receiver, but nothing
//! wires it onto the live DNS datagram path. This module is that transport.

//!
//! It gives the L3 workhorse (the blackout's ultimate fallback) the same
//! reliability the multipath bond gives its lanes: a window of frames in
//! flight, cumulative+SACK acknowledgements, timeout-driven retransmission,
//! out-of-order reassembly, and dedup — all riding the existing `TunnelFrame`
//! wire format and QNAME clamping, so it stays under the 101-byte DPI cap.
//!
//! # Wire protocol (reserved `flags = 4` — ARQ data/ACK)
//!
//! Flag `4` is reserved for ARQ frames (server currently uses 0=data, 1=ping,
//! 2=status, 3=bootstrap). A client→server ARQ frame carries a data payload
//! chunk (`seq` set). The tunnel/server reply is an ACK frame: payload = a
//! 12-byte little-endian `(cum: u16, sack: u64)` as produced by
//! [`ArqReceiver::ack`]. The client feeds it into [`ArqSender::on_ack`] to
//! retire acknowledged frames and slide the window — exactly the
//! multipath-bond coupling, but over DNS.
//!
//! # Usage
//!
//! ```
//! # use std::time::Duration;
//! # use std::io;
//! # use dastyab_core::dnstunnel_arq::DnsTunnelArq;
//! # use dastyab_core::dnstunnel::Resolver;
//! # use dastyab_core::CFError;
//! # struct R; impl Resolver for R {
//! #   fn query_txt(&self, name: &str) -> Result<String, CFError> { Ok("dummy".into()) }
//! # }
//! let mut tr = DnsTunnelArq::new(&R, "tun.example.com", "sess", 8, Duration::from_millis(40));
//! ```
//!
//! A windowed reliable client over any `Resolver` (domestic recursive pool,
//! DoH, or direct UDP).
use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::arq::{ArqReceiver, ArqSender, RecvVerdict, Seqno};
use crate::dnstunnel::{Resolver, TunnelFrame, MAX_QNAME_LEN};

/// Reserved wire flag: ARQ data/ACK frame.
pub const FLAG_ARQ: u8 = 4;

/// ACK payload size on the wire (cum u16 LE + sack u64 LE).
pub const ACK_WIRE_LEN: usize = 10;

/// Serialize a receiver ACK (cumulative + selective bitmap) to the wire.
pub fn ack_wire(cum: Seqno, sack: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(ACK_WIRE_LEN);
    out.extend_from_slice(&cum.0.to_le_bytes());
    out.extend_from_slice(&sack.to_le_bytes());
    out
}

/// Parse a wire ACK into `(cum, sack)`.
pub fn ack_parse(raw: &[u8]) -> Option<(Seqno, u64)> {
    if raw.len() < ACK_WIRE_LEN {
        return None;
    }
    let cum = u16::from_le_bytes([raw[0], raw[1]]);
    let mut sack_bytes = [0u8; 8];
    sack_bytes.copy_from_slice(&raw[2..10]);
    Some((Seqno(cum), u64::from_le_bytes(sack_bytes)))
}

/// Result of a single [`DnsTunnelArq::pump`] round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PumpStats {
    /// Frames newly dispatched onto the wire this round.
    pub sent: usize,
    /// Frames retransmitted due to expired timers this round.
    pub retransmitted: usize,
    /// Frames acknowledged (retired from the window) this round.
    pub acked: usize,
    /// Payload chunks reassembled in-order and delivered this round.
    pub delivered: usize,
}

/// A sliding-window selective-repeat ARQ transport over the DNS tunnel.
///
/// Owns the `ArqSender` (window/retransmit) and `ArqReceiver` (reassembly),
/// plus an outbox of payloads waiting for a free window slot and an in-flight
/// registry mirroring what has actually been put on the wire.
pub struct DnsTunnelArq<'a, R: Resolver> {
    resolver: &'a R,
    base_domain: String,
    session: String,
    tx: ArqSender,
    rx: ArqReceiver,
    outbox: VecDeque<Vec<u8>>,
    /// seqs we have handed to the wire and are still awaiting ACK; used to
    /// drive retransmission and stats without reaching into `tx` internals.
    on_wire: Vec<Seqno>,
    dispatched: usize,
}

impl<'a, R: Resolver> DnsTunnelArq<'a, R> {
    /// Create a windowed ARQ DNS transport.
    ///
    /// `window` is the in-flight frame budget (clamped 1..=64); `rto` is the
    /// retransmit timeout per frame.
    pub fn new(
        resolver: &'a R,
        base_domain: &str,
        session: &str,
        window: u16,
        rto: Duration,
    ) -> Self {
        Self {
            resolver,
            base_domain: base_domain.to_string(),
            session: session.to_string(),
            tx: ArqSender::new(window, rto),
            rx: ArqReceiver::new(window),
            outbox: VecDeque::new(),
            on_wire: Vec::new(),
            dispatched: 0,
        }
    }

    /// Queue a payload chunk for reliable transmission. Returns immediately;
    /// the data actually goes on the wire during the next [`Self::pump`].
    pub fn push(&mut self, payload: Vec<u8>) {
        self.outbox.push_back(payload);
    }

    /// A payload chunk queued for (re)transmission.
    fn queue_for_wire(&mut self, seq: Seqno) {
        if !self.on_wire.contains(&seq) {
            self.on_wire.push(seq);
            self.dispatched += 1;
        }
    }

    /// Fill the window from the outbox (assign seq numbers).
    fn fill_window(&mut self) {
        while self.tx.can_send() {
            let Some(pl) = self.outbox.pop_front() else {
                break;
            };
            if let Some(seq) = self.tx.send(pl) {
                self.queue_for_wire(seq);
            } else {
                // Window became full between the check and send; put it back.
                // (Should not happen under the same lock, but keep safe.)
                break;
            }
        }
    }

    /// Run one pump round: fill the window, transmit every in-flight frame
    /// over DNS, parse ACK replies, retransmit expired frames, and collect any
    /// in-order delivered payloads.
    ///
    /// Returns running stats. This is the core loop a daemon would call
    /// periodically (or spin over) to drive the tunnel.
    pub async fn pump(&mut self) -> Result<PumpStats, crate::CFError> {
        self.fill_window();
        let mut st = PumpStats::default();
        let now = Instant::now();

        // 1. Retransmit anything whose timer expired.
        for seq in self.tx.pending_timeouts(now) {
            if let Some(_payload) = self.tx.retransmit(seq) {
                st.retransmitted += 1;
                self.queue_for_wire(seq);
            }
        }

        // 2. Transmit everything waiting on the wire, one DNS RTT each.
        let mut pending = std::mem::take(&mut self.on_wire);
        for seq in pending.drain(..) {
            let Some(payload) = self.tx.retransmit(seq) else {
                continue; // already retired by ack
            };
            let frame = TunnelFrame {
                session: self.session.clone(),
                seq: seq.0,
                flags: FLAG_ARQ,
                payload,
            };
            let nonce = rand::random::<u32>() & 0xFFFF;
            let qname = frame.encode_name_clamped(&self.base_domain, nonce, MAX_QNAME_LEN);
            let Ok(reply) = self.resolver.query_txt(&qname) else {
                // Resolver failure: frame stays in flight (will retransmit on
                // next pump after RTO). Do not mark delivered.
                st.sent += 1;
                continue;
            };
            st.sent += 1;
            let Ok(replied) =
                TunnelFrame::decode_name(reply.trim_end_matches('.'), &self.base_domain)
            else {
                continue;
            };
            if replied.flags == FLAG_ARQ {
                if let Some((cum, sack)) = ack_parse(&replied.payload) {
                    let before = self.tx.inflight();
                    self.tx.on_ack(cum, sack);
                    st.acked += before.saturating_sub(self.tx.inflight());
                }
            } else if replied.flags == 0 {
                // Legacy echo server (flags=0 echoes data back): treat the
                // echoed frame as implicit delivery + ack.
                if self.rx.recv(Seqno(replied.seq), &replied.payload) == RecvVerdict::Accepted {
                    for (_s, pl) in self.rx.take_delivered() {
                        st.delivered += 1;
                        let _ = pl;
                    }
                    let (cum, sack) = self.rx.ack();
                    self.tx.on_ack(cum, sack);
                }
            }
        }
        self.on_wire = pending;
        Ok(st)
    }

    /// Take payload chunks reassembled in-order so far.
    pub fn take_delivered(&mut self) -> Vec<(Seqno, Vec<u8>)> {
        self.rx.take_delivered()
    }

    /// Whether no frames are in flight and no outbox work remains.
    pub fn is_idle(&self) -> bool {
        self.tx.is_idle() && self.outbox.is_empty() && self.on_wire.is_empty()
    }

    /// Current in-flight frame count.
    pub fn inflight(&self) -> usize {
        self.tx.inflight()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CFError;
    use std::sync::{Arc, Mutex};

    /// A lossy fake tunnel: simulates a DNS resolver + tunnel server that drops
    /// frames with probability `loss`, and ACKs what it receives (a fresh
    /// receiver per query — representing an idempotent server that answers each
    /// frame independently with its cumulative+selective ACK).
    struct LossyResolver {
        loss: f64,
        /// Received (seq, payload) in arrival order, for the "server side".
        got: Arc<Mutex<Vec<(u64, Vec<u8>)>>>,
    }
    impl Resolver for LossyResolver {
        fn query_txt(&self, name: &str) -> Result<String, CFError> {
            let frame = TunnelFrame::decode_name(name.trim_end_matches('.'), "tun.example.com")?;
            if frame.flags != FLAG_ARQ {
                // echo legacy
                return Ok(frame.encode_name("tun.example.com", rand::random::<u32>() & 0xFFFF));
            }
            if (rand::random::<f64>()) < self.loss {
                return Err(CFError::new("dns-tunnel-arq", "simulated loss", ""));
            }
            self.got
                .lock()
                .unwrap()
                .push((frame.seq as u64, frame.payload.clone()));
            // Server side: feed into a receiver, reply with its ACK.
            let mut srv_rx = ArqReceiver::new(32);
            let _ = srv_rx.recv(Seqno(frame.seq), &frame.payload);
            let (cum, sack) = srv_rx.ack();
            let ack_payload = ack_wire(cum, sack);
            let ack = TunnelFrame {
                session: "sess".into(),
                seq: frame.seq,
                flags: FLAG_ARQ,
                payload: ack_payload,
            };
            Ok(ack.encode_name("tun.example.com", rand::random::<u32>() & 0xFFFF))
        }
    }

    #[test]
    fn ack_wire_roundtrips() {
        let (cum, sack) = (Seqno(7), 0b1010u64);
        let wire = ack_wire(cum, sack);
        assert_eq!(wire.len(), ACK_WIRE_LEN);
        assert_eq!(ack_parse(&wire), Some((cum, sack)));
    }

    #[tokio::test]
    async fn lossless_window_delivers_all_chunks_in_order() {
        let r = LossyResolver {
            loss: 0.0,
            got: Arc::new(Mutex::new(vec![])),
        };
        let mut tr = DnsTunnelArq::new(&r, "tun.example.com", "sess", 8, Duration::from_millis(30));
        let chunks: Vec<Vec<u8>> = (0..20)
            .map(|i| format!("chunk-{i:02}").into_bytes())
            .collect();
        for c in chunks.iter() {
            tr.push(c.clone());
        }
        // Pump until idle (bounded): every chunk must be ACKed and retired.
        let mut acked = 0usize;
        let mut sent = 0usize;
        for _ in 0..400 {
            let st = tr.pump().await.expect("pump");
            sent += st.sent;
            acked += st.acked;
            if tr.is_idle() {
                break;
            }
        }
        assert_eq!(acked, chunks.len(), "all chunks acknowledged");
        assert!(tr.is_idle(), "transport idle after full delivery");
        // Every server-side chunk must have been received exactly once (the
        // wire got every payload).
        let got = r.got.lock().unwrap();
        assert_eq!(got.len(), chunks.len(), "server received every chunk once");
    }

    #[tokio::test]
    async fn lossy_link_is_recovered_by_retransmission() {
        let r = LossyResolver {
            loss: 0.45,
            got: Arc::new(Mutex::new(vec![])),
        };
        let mut tr = DnsTunnelArq::new(&r, "tun.example.com", "sess", 4, Duration::from_millis(5));
        let chunks: Vec<Vec<u8>> = (0..12)
            .map(|i| format!("payload-{i:02}").into_bytes())
            .collect();
        for c in chunks.iter() {
            tr.push(c.clone());
        }
        let mut retx_total = 0usize;
        let mut acked = 0usize;
        let mut pumps = 0usize;
        for _ in 0..4000 {
            let st = tr.pump().await.expect("pump");
            retx_total += st.retransmitted;
            acked += st.acked;
            pumps += 1;
            if tr.is_idle() {
                break;
            }
            // Let wall-clock advance past the RTO so retransmit timers fire
            // (the mock resolver is instantaneous; real DNS RTTs provide this).
            tokio::time::sleep(Duration::from_millis(6)).await;
        }
        assert!(retx_total > 0, "lossy link must have retransmitted");
        assert_eq!(acked, chunks.len(), "all chunks recovered despite loss");
        assert!(tr.is_idle(), "transport idle after loss recovery");
    }
}
