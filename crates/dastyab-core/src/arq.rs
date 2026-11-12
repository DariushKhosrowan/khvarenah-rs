//! Low-overhead **selective-repeat windowed ARQ** engine for the DNS tunnel.
//!
//! # Why this exists (doctrine Level 3)
//!
//! The blackout DNS tunnel runs over domestic ISP recursive resolvers over
//! UDP. UDP has no delivery guarantees: packets are lost silently, arrive
//! out of order, or duplicate — and Iranian mobile/LTE links are lossy and
//! flappy. Without an Automatic Repeat reQuest (ARQ) layer, a single dropped
//! DNS query permanently corrupts the in-flight tunnel frame (we never get a
//! coherent reply, or we get a stale one).
//!
//! This module provides a compact, windowed, **selective-repeat** ARQ engine:
//!
//! - **Sender** assigns monotonically increasing sequence numbers to frames
//!   within a bounded in-flight window, buffers unacknowledged frames, and
//!   retransmits only the specific frames that time out (not the whole
//!   window — that is what makes it "selective-repeat" rather than go-back-N).
//! - **Receiver** accepts out-of-order frames into a small reorder buffer,
//!   delivers them in order, and returns a cumulative ACK plus a **selective
//!   ACK (SACK) bitmap** covering the window, so the sender can drop the
//!   correctly-received frames even if earlier ones are still missing.
//!
//! # Wire-budget fit for DNS labels
//!
//! Every ARQ control value is compact enough to live in the existing DNS-tunnel
//! wire format (see `dnstunnel::TunnelFrame`) without breaking the 101-byte
//! QNAME ceiling:
//!
//! | Field | Wire cost | Placement |
//! |---|---|---|
//! | sequence number | up to 5 chars (`0`–`65535`) | existing `seq` label |
//! | cumulative ACK | up to 5 chars | one label |
//! | SACK bitmap | up to 16 hex chars (u64) | one label |
//!
//! Total control overhead ≈ 1–2 DNS labels — matching the doctrine's "max 5–7
//! bytes of framing overhead" budget (a label is 1 length byte + chars).
//!
//! # Safety notes
//!
//! - Sequence-number arithmetic is **modulo 2¹⁶** with a window far smaller
//!   than the modulus, so wrap-around (seq 65535 → 0) is handled correctly.
//! - The window size is a caller-chosen constant (`MAX_WINDOW`); with the
//!   default 64 both sender and receiver tolerate 64 outstanding frames.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Sequence numbers wrap modulo 2¹⁶. The window is always much smaller than
/// this, so distance comparisons are unambiguous.
pub const MODULUS: u32 = 1 << 16;

/// Default ARQ window: max outstanding unacknowledged frames in either
/// direction. Larger tolerates more loss but costs more memory and retransmit
/// burden; 64 comfortably covers the DNS-tunnel rate ceiling.
pub const MAX_WINDOW: u16 = 64;

/// A sequence number in the tunnel's 16-bit space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Seqno(pub u16);

impl Seqno {
    #[inline]
    pub fn wrapping_add(self, rhs: u16) -> Self {
        Self(self.0.wrapping_add(rhs))
    }

    #[inline]
    pub fn wrapping_sub(self, rhs: u16) -> Self {
        Self(self.0.wrapping_sub(rhs))
    }

    /// Forward distance from `self` to `other` modulo 2¹⁶. Because the window
    /// is far smaller than the modulus, this is the number of steps you walk
    /// forward from `self` to reach `other` (0 when equal).
    #[inline]
    fn dist_to(self, other: Self) -> u32 {
        other.0.wrapping_sub(self.0) as u32
    }

    /// True if `self` is strictly "ahead" of `ref` on the sequence ring
    /// (i.e. reachable by walking forward < 32768 steps).
    #[inline]
    fn is_ahead_of(self, other: Self) -> bool {
        let d = self.0.wrapping_sub(other.0);
        d != 0 && d < 32768
    }
}

/// One in-flight (unacknowledged) frame held by the sender.
#[derive(Debug)]
struct InFlight {
    payload: Vec<u8>,
    sent_at: Instant,
}

/// Sender half of the ARQ engine.
///
/// Allocates sequence numbers within a bounded window, buffers unacked frames,
/// and reports which frames need retransmission.
#[derive(Debug)]
pub struct ArqSender {
    base: Seqno,
    next: Seqno,
    window: u16,
    in_flight: BTreeMap<Seqno, InFlight>,
    rto: Duration,
}

impl ArqSender {
    /// Create a sender with `window` slots and a retransmit timeout `rto`.
    pub fn new(window: u16, rto: Duration) -> Self {
        let window = window.clamp(1, MAX_WINDOW);
        Self {
            base: Seqno(0),
            next: Seqno(0),
            window,
            in_flight: BTreeMap::new(),
            rto,
        }
    }

    /// Whether the sender can accept another frame without exceeding the
    /// in-flight window.
    pub fn can_send(&self) -> bool {
        (self.in_flight.len() as u16) < self.window
    }

    /// Current number of unacknowledged frames in flight.
    pub fn inflight(&self) -> usize {
        self.in_flight.len()
    }

    /// Lowest unacknowledged sequence number (the window base).
    pub fn base(&self) -> Seqno {
        self.base
    }

    /// Assign the next sequence number and buffer `payload` for possible
    /// retransmission. Returns `None` if the window is full.
    pub fn send(&mut self, payload: Vec<u8>) -> Option<Seqno> {
        if !self.can_send() {
            return None;
        }
        let seq = self.next;
        self.in_flight.insert(
            seq,
            InFlight {
                payload,
                sent_at: Instant::now(),
            },
        );
        self.next = self.next.wrapping_add(1);
        Some(seq)
    }

    /// Re-send the frame with sequence `seq` (caller performs the actual
    /// network write). Touches the send timestamp so the frame is not
    /// immediately due again. Returns `None` if no such frame is in flight.
    pub fn retransmit(&mut self, seq: Seqno) -> Option<Vec<u8>> {
        let e = self.in_flight.get_mut(&seq)?;
        e.sent_at = Instant::now();
        Some(e.payload.clone())
    }

    /// Return the sequence numbers whose retransmit timer has expired relative
    /// to `now`, and restart their timers (so a single call yields each
    /// expired frame once).
    pub fn pending_timeouts(&mut self, now: Instant) -> Vec<Seqno> {
        let mut due = Vec::new();
        for (&seq, e) in &self.in_flight {
            if now.duration_since(e.sent_at) >= self.rto {
                due.push(seq);
            }
        }
        for seq in &due {
            if let Some(e) = self.in_flight.get_mut(seq) {
                e.sent_at = now;
            }
        }
        due
    }

    /// Process an ACK from the receiver.
    ///
    /// `cum` is the cumulative ACK: every sequence strictly before `cum` is
    /// acknowledged. `sack` is a selective ACK bitmap: bit *i* (LSB-first)
    /// acknowledges the frame at sequence `cum + (i+1)`.
    pub fn on_ack(&mut self, cum: Seqno, sack: u64) {
        // 1. Drop anything strictly behind the cumulative ACK (keep only the
        // cumulative seq itself and anything ahead of it on the ring).
        self.in_flight
            .retain(|&seq, _| seq == cum || seq.is_ahead_of(cum));

        // 2. Advance the base to the cumulative ACK.
        if self.base.dist_to(cum) > 0 {
            self.base = cum;
        }

        // 3. Apply the selective ACK bitmap.
        let mut drop = Vec::new();
        for &seq in self.in_flight.keys() {
            let rel = self.base.dist_to(seq);
            if (1..=64).contains(&rel) && (sack & (1u64 << (rel - 1))) != 0 {
                drop.push(seq);
            }
        }
        for seq in drop {
            self.in_flight.remove(&seq);
        }

        // 4. Slide the base over contiguous acknowledged frames.
        loop {
            if self.in_flight.is_empty() || self.in_flight.contains_key(&self.base) {
                break;
            }
            self.base = self.base.wrapping_add(1);
        }
    }

    /// True when no frames are unacknowledged.
    pub fn is_idle(&self) -> bool {
        self.in_flight.is_empty()
    }
}

/// Verdict of a received frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvVerdict {
    /// Frame accepted (delivered in-order or buffered out-of-order).
    Accepted,
    /// Duplicate of an already-received frame (ignore; do not re-ACK in a way
    /// that could confuse the sender, but harmless to re-ACK).
    Duplicate,
    /// Outside the receive window — either too old or too far ahead. Drop.
    OutOfWindow,
}

/// Receiver half of the ARQ engine.
///
/// Accepts frames possibly out of order, delivers them in order, and emits a
/// cumulative + selective ACK.
#[derive(Debug)]
pub struct ArqReceiver {
    next_expected: Seqno,
    window: u16,
    buffered: BTreeMap<Seqno, Vec<u8>>,
    delivered: Vec<(Seqno, Vec<u8>)>,
    seen: std::collections::HashSet<Seqno>,
}

impl ArqReceiver {
    /// Create a receiver with `window` reorder slots.
    pub fn new(window: u16) -> Self {
        Self {
            next_expected: Seqno(0),
            window: window.clamp(1, MAX_WINDOW),
            buffered: BTreeMap::new(),
            delivered: Vec::new(),
            seen: std::collections::HashSet::new(),
        }
    }

    /// Create a receiver whose expected sequence starts at `base` (used when
    /// the sender's sequence space does not start at zero — e.g. across a
    /// wrap-around or after a session resume).
    pub fn with_base(window: u16, base: Seqno) -> Self {
        let mut rx = Self::new(window);
        rx.next_expected = base;
        rx
    }

    /// Feed a received frame into the receiver. Returns a verdict; `Accepted`
    /// frames are delivered (in order) via [`Self::take_delivered`].
    pub fn recv(&mut self, seq: Seqno, payload: &[u8]) -> RecvVerdict {
        if self.seen.contains(&seq) {
            return RecvVerdict::Duplicate;
        }

        let dist = self.next_expected.dist_to(seq);

        if dist == 0 {
            // In-order frame: deliver immediately.
            self.seen.insert(seq);
            self.delivered.push((seq, payload.to_vec()));
            self.next_expected = self.next_expected.wrapping_add(1);
            self.flush_buffered();
            return RecvVerdict::Accepted;
        }

        if dist > self.window as u32 {
            return RecvVerdict::OutOfWindow;
        }

        // Out-of-order but inside the window: buffer it.
        self.seen.insert(seq);
        self.buffered.insert(seq, payload.to_vec());
        self.prune_seen();
        RecvVerdict::Accepted
    }

    /// Drain frames that are ready for delivery, in sequence order.
    pub fn take_delivered(&mut self) -> Vec<(Seqno, Vec<u8>)> {
        std::mem::take(&mut self.delivered)
    }

    /// Produce the ACK to send back: `(cumulative, selective_bitmap)`.
    pub fn ack(&self) -> (Seqno, u64) {
        let mut mask = 0u64;
        for &seq in self.buffered.keys() {
            let rel = self.next_expected.dist_to(seq);
            if (1..=64).contains(&rel) {
                mask |= 1u64 << (rel - 1);
            }
        }
        (self.next_expected, mask)
    }

    fn flush_buffered(&mut self) {
        while let Some(payload) = self.buffered.remove(&self.next_expected) {
            let seq = self.next_expected;
            self.delivered.push((seq, payload));
            self.next_expected = self.next_expected.wrapping_add(1);
        }
    }

    /// Keep the duplicate-detection set bounded (it only ever needs to cover
    /// the receive window worth of recent sequence numbers).
    fn prune_seen(&mut self) {
        if self.seen.len() <= 2 * self.window as usize {
            return;
        }
        let cut = self.next_expected.wrapping_sub(self.window);
        self.seen.retain(|s| s.is_ahead_of(cut) || *s == cut);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seq(n: u16) -> Seqno {
        Seqno(n)
    }

    #[test]
    fn in_order_delivery() {
        let mut tx = ArqSender::new(8, Duration::from_millis(500));
        let mut rx = ArqReceiver::new(8);

        let s0 = tx.send(b"hello".to_vec()).unwrap();
        let s1 = tx.send(b"world".to_vec()).unwrap();
        assert_eq!(s0, seq(0));
        assert_eq!(s1, seq(1));

        assert_eq!(rx.recv(s0, b"hello"), RecvVerdict::Accepted);
        assert_eq!(rx.recv(s1, b"world"), RecvVerdict::Accepted);

        let delivered = rx.take_delivered();
        assert_eq!(delivered.len(), 2);
        assert_eq!(delivered[0].1, b"hello");
        assert_eq!(delivered[1].1, b"world");

        // ACK reflects both delivered.
        let (cum, _mask) = rx.ack();
        assert_eq!(cum, seq(2));
        tx.on_ack(cum, 0);
        assert!(tx.is_idle());
    }

    #[test]
    fn out_of_order_reorder_and_ack() {
        let mut tx = ArqSender::new(8, Duration::from_millis(500));
        let mut rx = ArqReceiver::new(8);

        let _ = tx.send(b"a".to_vec()).unwrap(); // seq 0
        let s1 = tx.send(b"b".to_vec()).unwrap(); // seq 1
        let _ = tx.send(b"c".to_vec()).unwrap(); // seq 2
        let s3 = tx.send(b"d".to_vec()).unwrap(); // seq 3

        // Frame 1 arrives before frame 0 (frame 0 lost).
        assert_eq!(rx.recv(s1, b"b"), RecvVerdict::Accepted);
        assert!(rx.take_delivered().is_empty()); // nothing deliverable yet

        // Frame 3 also arrives ahead.
        assert_eq!(rx.recv(s3, b"d"), RecvVerdict::Accepted);

        // ACK should carry cumulative=0 (frame 0 still missing) + SACK bits
        // for seq 1 and 3.
        let (cum, mask) = rx.ack();
        assert_eq!(cum, seq(0));
        assert_ne!(mask & (1 << 0), 0); // seq 1 -> bit 0
        assert_ne!(mask & (1 << 2), 0); // seq 3 -> bit 2
        assert_eq!(mask & (1 << 1), 0); // seq 2 not received

        // Sender processes ACK: seq 1 and 3 should be dropped from flight.
        tx.on_ack(cum, mask);
        // seq1 removed by SACK, seq3 removed by SACK; seq0 and seq2 remain.
        assert_eq!(tx.inflight(), 2);
        assert!(!tx.is_idle());

        // Now frame 0 finally arrives → flush 0, then buffered 1, 2 missing so stop.
        assert_eq!(rx.recv(seq(0), b"a"), RecvVerdict::Accepted);
        let delivered = rx.take_delivered();
        assert_eq!(delivered.len(), 2); // 0 and 1
        assert_eq!(delivered[0].1, b"a");
        assert_eq!(delivered[1].1, b"b");
    }

    #[test]
    fn duplicate_is_rejected() {
        // Receiver expects seq 5 as its next in-order frame, so the frame is
        // deliverable immediately (not just buffered ahead of a gap).
        let mut rx = ArqReceiver::with_base(8, seq(5));
        assert_eq!(rx.recv(seq(5), b"x"), RecvVerdict::Accepted);
        // Same frame again → duplicate, not delivered twice.
        assert_eq!(rx.recv(seq(5), b"x"), RecvVerdict::Duplicate);
        assert_eq!(rx.take_delivered().len(), 1);
    }

    #[test]
    fn out_of_window_is_dropped() {
        let mut rx = ArqReceiver::new(4);
        assert_eq!(rx.recv(seq(0), b"a"), RecvVerdict::Accepted);
        // Drain the in-order seq 0 that was just delivered; the remaining
        // assertions are about the out-of-order buffering path.
        let _ = rx.take_delivered();
        // After expecting seq 1, seq 100 is wildly ahead → out of window.
        assert_eq!(rx.recv(seq(100), b"z"), RecvVerdict::OutOfWindow);
        // seq 65535 is one *behind* seq 1 on the ring (wrap) → out of window.
        assert_eq!(rx.recv(seq(65535), b"old"), RecvVerdict::OutOfWindow);
        // seq 3 is inside the window ahead → accepted (buffered).
        assert_eq!(rx.recv(seq(3), b"fwd"), RecvVerdict::Accepted);
        // Nothing in-order deliverable yet.
        assert!(rx.take_delivered().is_empty());
        // ACK: cumulative = 1, SACK acknowledges seq 3 (rel 2 → bit 1).
        let (cum, mask) = rx.ack();
        assert_eq!(cum, seq(1));
        assert_ne!(mask & (1 << 1), 0);
    }

    #[test]
    fn window_full_blocks_send() {
        let mut tx = ArqSender::new(4, Duration::from_millis(500));
        for i in 0..4 {
            assert!(tx.can_send());
            tx.send(vec![i]).unwrap();
        }
        assert!(!tx.can_send());
        assert!(tx.send(vec![9]).is_none());
    }

    #[test]
    fn selective_retransmit_only_timed_out_frames() {
        let now = Instant::now();
        let mut tx = ArqSender::new(8, Duration::from_millis(100));
        let _ = tx.send(vec![1]).unwrap(); // seq 0
        let _ = tx.send(vec![2]).unwrap(); // seq 1
        let _ = tx.send(vec![3]).unwrap(); // seq 2

        // At t=now nothing has timed out (sent just now).
        assert!(tx.pending_timeouts(now).is_empty());
        // At t=now+200ms all three are due.
        let due = tx.pending_timeouts(now + Duration::from_millis(200));
        assert_eq!(due.len(), 3);
        assert!(due.contains(&seq(0)));
        assert!(due.contains(&seq(1)));
        assert!(due.contains(&seq(2)));

        // After they are reported, their timers restart → not immediately due.
        assert!(tx
            .pending_timeouts(now + Duration::from_millis(200))
            .is_empty());

        // Frame 1 is ACKed now, so it is no longer in flight; only 0 and 2
        // remain and can time out later.
        tx.on_ack(seq(0), 1u64 << 0); // SACK bit 0 -> seq 1
        assert_eq!(tx.inflight(), 2);
    }

    #[test]
    fn wrap_around_sequence_numbers() {
        // Start near the 16-bit wrap boundary.
        let mut tx = ArqSender::new(8, Duration::from_millis(500));
        tx.base = seq(65530);
        tx.next = seq(65530);
        let s0 = tx.send(vec![0]).unwrap();
        let s1 = tx.send(vec![1]).unwrap();
        let s2 = tx.send(vec![2]).unwrap();
        assert_eq!(s0, seq(65530));
        assert_eq!(s1, seq(65531));
        assert_eq!(s2, seq(65532));

        // Receiver must start expecting seq 65530 too, otherwise the frames
        // look wildly out of window.
        let mut rx = ArqReceiver::with_base(8, seq(65530));
        // Deliver out of order across the wrap: seq 65531 before 65530.
        assert_eq!(rx.recv(s1, b"one"), RecvVerdict::Accepted);
        assert_eq!(rx.recv(s2, b"two"), RecvVerdict::Accepted);
        assert_eq!(rx.recv(s0, b"zero"), RecvVerdict::Accepted);

        let delivered = rx.take_delivered();
        assert_eq!(delivered.len(), 3);
        assert_eq!(delivered[0].0, seq(65530));
        assert_eq!(delivered[1].0, seq(65531));
        assert_eq!(delivered[2].0, seq(65532));

        let (cum, mask) = rx.ack();
        assert_eq!(cum, seq(65533));
        tx.on_ack(cum, mask);
        assert!(tx.is_idle());
    }

    #[test]
    fn end_to_end_simulated_loss_and_recovery() {
        // Simulate a lossy UDP path: frame 0 lost, frames 1-2 arrive, then
        // frame 0 retransmits. The receiver must deliver exactly 0,1,2 in
        // order, and the sender must reach idle after the full ACK.
        let mut tx = ArqSender::new(8, Duration::from_millis(50));
        let mut rx = ArqReceiver::new(8);

        let s0 = tx.send(b"frame0".to_vec()).unwrap();
        let s1 = tx.send(b"frame1".to_vec()).unwrap();
        let s2 = tx.send(b"frame2".to_vec()).unwrap();

        // frame0 is lost; frames 1 and 2 arrive.
        assert_eq!(rx.recv(s1, b"frame1"), RecvVerdict::Accepted);
        assert_eq!(rx.recv(s2, b"frame2"), RecvVerdict::Accepted);

        // Sender receives the SACK → drops 1 and 2, keeps 0.
        let (cum, mask) = rx.ack();
        tx.on_ack(cum, mask);
        assert_eq!(tx.inflight(), 1);
        assert!(tx.in_flight.contains_key(&s0));

        // Timeout fires → retransmit frame 0 only.
        let due = tx.pending_timeouts(Instant::now() + Duration::from_millis(200));
        assert_eq!(due, vec![s0]);
        let payload = tx.retransmit(s0).unwrap();
        assert_eq!(payload, b"frame0");

        // Retransmitted frame 0 arrives → flushes 0, then 1, then 2.
        assert_eq!(rx.recv(s0, &payload), RecvVerdict::Accepted);
        let delivered = rx.take_delivered();
        assert_eq!(delivered.len(), 3);
        assert_eq!(delivered[0].1, b"frame0");
        assert_eq!(delivered[1].1, b"frame1");
        assert_eq!(delivered[2].1, b"frame2");

        // Full ACK → sender idle.
        let (cum, mask) = rx.ack();
        tx.on_ack(cum, mask);
        assert!(tx.is_idle());
    }
}
