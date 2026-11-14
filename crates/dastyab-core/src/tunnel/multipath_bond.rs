//! Multipath ARQ **packet bonding** engine (doctrine §8.2 / resilience ladder).
//!
//! # Why this exists
//!
//! In a blackout, no single transport is trustworthy: the LTE link flaps, the
//! Wi-Fi cell is congested, the DNS tunnel drops queries at a high rate. A
//! single-path ARQ (see `arq.rs`) survives loss on *one* path, but the moment
//! that path blackholes, the whole session stalls.
//!
//! This module bonds **multiple lanes** — independent sub-transports, each
//! running its own `ArqSender`/`ArqReceiver` — into one reliable logical link:
//!
//! - **Outbound** — the `MultipathBonder` assigns each data frame to one or
//!   more lanes under a [`BondPolicy`]:
//!     - `Stripe`: round-robin across lanes (aggregate throughput; a frame is
//!       on exactly one lane).
//!     - `Mirror`: every frame on every lane (maximum resilience; a frame
//!       survives as long as *any* lane delivers it).
//! - **Inbound** — frames arriving on any lane carry a global **bond sequence
//!   number**. The bonder dedups across lanes (mirror redundancy) and
//!   reassembles frames in global order, so the caller sees one clean,
//!   ordered payload stream even when lanes deliver out of order or
//!   redundantly.
//!
//! # Relationship to per-lane ARQ
//!
//! Each lane owns its own `ArqSender`/`ArqReceiver`. The lane's ARQ is
//! responsible for *reliable transmission of that lane's wire frames*; the
//! bonder is responsible for *global ordering and cross-lane redundancy*.
//! Because both concerns are separated, the existing, well-tested ARQ engine
//! is reused as-is — no protocol rework.
//!
//! # Wire format (bond frame, inside a lane's ARQ payload)
//!
//! | Field | Size | Meaning |
//! |---|---|---|
//! | bond sequence | 8 bytes BE | global monotonic order across lanes |
//! | payload | rest | the caller's data bytes |
//!
//! This minimal 8-byte prefix (well under typical DNS-tunnel frame budgets)
//! is the only bonding overhead on top of per-lane ARQ.
//!
//! # Safety / correctness notes
//!
//! - Global reassembly is gap-tolerant: out-of-order frames buffer until the
//!   missing predecessors arrive or are dropped as duplicates.
//! - `LastDelivered` only advances over contiguous already-arrived frames, so
//!   a poisoned/duplicate sequence can never cause gaps to be silently
//!   skipped.
//! - All pane indexing is bounds-checked against `MAX_LANES`; an unknown lane
//!   is ignored (never panics).

use crate::tunnel::arq::{ArqReceiver, ArqSender, RecvVerdict, Seqno};
use std::collections::BTreeMap;
use std::time::Duration;

/// Hard cap on the number of bonded lanes.
pub const MAX_LANES: usize = 8;

/// Global bond-sequence type. Monotonic across all bonded lanes.
pub type BondSeq = u64;

/// Identifies one lane (sub-transport) within a bond.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LaneId(pub u8);

/// How outbound frames are assigned to lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BondPolicy {
    /// Round-robin: each frame on exactly one lane. Best aggregate throughput.
    Stripe,
    /// Every frame on every lane. Maximum resilience; a frame delivered on
    /// any lane is enough.
    Mirror,
}

/// Lightweight per-lane telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaneMetric {
    pub id: LaneId,
    pub sent_wire_frames: u64,
    pub retransmits: u64,
    pub delivered_frames: u64,
    pub inflight: usize,
}

#[derive(Debug)]
struct LaneState {
    id: LaneId,
    tx: ArqSender,
    rx: ArqReceiver,
    /// Wire frames queued for physical transmission (first send).
    outgoing: Vec<(Seqno, Vec<u8>)>,
    /// Bond frames that arrived on this lane and depend delivered in-order.
    arrived: Vec<(BondSeq, Vec<u8>)>,
    sent_wire_frames: u64,
    retransmits: u64,
    delivered_frames: u64,
}

impl LaneState {
    fn new(id: LaneId, window: u16, rto: Duration) -> Self {
        // Each lane gets its own independent ARQ window; seqno spaces are
        // lane-local, so all lanes can run concurrently without interference.
        Self {
            id,
            tx: ArqSender::new(window, rto),
            rx: ArqReceiver::new(window),
            outgoing: Vec::new(),
            arrived: Vec::new(),
            sent_wire_frames: 0,
            retransmits: 0,
            delivered_frames: 0,
        }
    }
}

/// Result of a call to [`MultipathBonder::submit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitResult {
    /// Frame accepted and assigned bond sequence `seq`.
    Accepted { seq: BondSeq },
    /// The bond is full (all lane windows saturated); retry later.
    Blocked,
}

/// The multipath bonding engine.
#[derive(Debug)]
pub struct MultipathBonder {
    lanes: Vec<LaneState>,
    policy: BondPolicy,
    next_bond: BondSeq,
    /// Global reassembly buffer: bond seq -> payload.
    reassembly: BTreeMap<BondSeq, Vec<u8>>,
    /// Highest contiguous bond frame delivered so far (next expected).
    last_delivered: BondSeq,
    delivered: Vec<(BondSeq, Vec<u8>)>,
    stripe_cursor: usize,
}

impl MultipathBonder {
    /// Create a bond over the given lane ids.
    ///
    /// `window` is the per-lane ARQ window (see `arq::MAX_WINDOW`); `rto` is
    /// the per-lane retransmit timeout. Lane ids are deduplicated; unknown or
    /// out-of-range ids are skipped.
    pub fn new(ids: &[LaneId], policy: BondPolicy, window: u16, rto: Duration) -> Self {
        let mut lanes = Vec::new();
        let mut seen = [false; MAX_LANES];
        for id in ids {
            let idx = id.0 as usize;
            if idx < MAX_LANES && !seen[idx] {
                seen[idx] = true;
                lanes.push(LaneState::new(*id, window, rto));
            }
        }
        Self {
            lanes,
            policy,
            next_bond: 0,
            reassembly: BTreeMap::new(),
            last_delivered: 0,
            delivered: Vec::new(),
            stripe_cursor: 0,
        }
    }

    /// Number of lanes currently bonded.
    pub fn lane_count(&self) -> usize {
        self.lanes.len()
    }

    /// Submit a payload ` for transmission. Assigns a global bond sequence and
    /// dispatches to lanes per the bond policy.
    ///
    /// Returns `Blocked` if every lane's window is saturated.
    pub fn submit(&mut self, payload: Vec<u8>) -> SubmitResult {
        if self.lanes.is_empty() {
            return SubmitResult::Blocked;
        }
        let seq = self.next_bond;
        // Dispatch.
        match self.policy {
            BondPolicy::Stripe => {
                // Round-robin: pick the next lane that can accept the frame.
                let mut picked = None;
                for _ in 0..self.lanes.len() {
                    let idx = self.stripe_cursor % self.lanes.len();
                    self.stripe_cursor = self.stripe_cursor.wrapping_add(1) % self.lanes.len();
                    if self.lanes[idx].tx.can_send() {
                        picked = Some(idx);
                        break;
                    }
                }
                let Some(idx) = picked else {
                    return SubmitResult::Blocked;
                };
                self.dispatch(idx, seq, payload);
            }
            BondPolicy::Mirror => {
                // Send on every lane that can currently accept the frame.
                // A dead/saturated lane is skipped (never blocks the bond) —
                // that is the whole point of mirror redundancy: deliver as
                // long as *any* lane survives. Block only if every lane is
                // saturated.
                let mut any_accept = false;
                for idx in 0..self.lanes.len() {
                    if self.lanes[idx].tx.can_send() {
                        any_accept = true;
                        let p = payload.clone();
                        self.dispatch(idx, seq, p);
                    }
                }
                if !any_accept {
                    return SubmitResult::Blocked;
                }
            }
        }
        self.next_bond = self.next_bond.wrapping_add(1);
        SubmitResult::Accepted { seq }
    }

    /// Queue `payload` (with bond seq `seq`) on lane `idx` and, if the lane's
    /// ARQ sender admits it, emit a wire frame for physical transmission.
    fn dispatch(&mut self, idx: usize, seq: BondSeq, payload: Vec<u8>) {
        let wire = encode_bond_frame(seq, &payload);
        if let Some(lseq) = self.lanes[idx].tx.send(wire.clone()) {
            self.lanes[idx].outgoing.push((lseq, wire));
            self.lanes[idx].sent_wire_frames += 1;
        } else {
            // Lane saturated despite can_send check (race within policy); drop
            // the dispatch. Under Stripe the picker checked can_send, so this
            // is only reachable in pathological interleavings; Mirror checks
            // all lanes first, so it is unreachable there.
        }
    }

    /// Drain wire frames queued for physical transmission on `lane`.
    ///
    /// Returns `(lane_seqno, bytes)` pairs the caller should write to the
    /// lane's transport.
    pub fn drain_outgoing(&mut self, lane: LaneId) -> Vec<(Seqno, Vec<u8>)> {
        let Some(l) = self.lane_mut(lane) else {
            return Vec::new();
        };
        std::mem::take(&mut l.outgoing)
    }

    /// Feed a wire frame received on `lane` with lane-local ARQ seq `seq`
    /// into the bonding engine. Returns `true` if the frame was accepted.
    pub fn on_lane_frame(&mut self, lane: LaneId, seq: Seqno, bytes: &[u8]) -> bool {
        let Some(l) = self.lane_mut(lane) else {
            return false;
        };
        let verdict = l.rx.recv(seq, bytes);
        if verdict == RecvVerdict::Accepted {
            for (bond_seq, payload) in l.rx.take_delivered() {
                if let Some((bs, pl)) = decode_bond_frame(&payload) {
                    l.arrived.push((bs, pl.to_vec()));
                    l.delivered_frames += 1;
                    // Note: bond seq comes from the *wire payload*, not the
                    // lane-local ARQ seq; the receiver implements ordering.
                    let _ = bond_seq;
                }
            }
            // Move freshly-arrived bond frames into the global reassembly.
            let arrived = std::mem::take(&mut l.arrived);
            for (bs, pl) in arrived {
                self.reassembly.insert(bs, pl);
            }
            self.pump();
            return true;
        }
        false
    }

    /// Advance global delivery over contiguous arrived frames.
    fn pump(&mut self) {
        while let Some(payload) = self.reassembly.remove(&self.last_delivered) {
            let seq = self.last_delivered;
            self.delivered.push((seq, payload));
            self.last_delivered = self.last_delivered.wrapping_add(1);
        }
    }

    /// Drain frames delivered in global order (each `(bond_seq, payload)`).
    pub fn take_delivered(&mut self) -> Vec<(BondSeq, Vec<u8>)> {
        std::mem::take(&mut self.delivered)
    }

    /// Get the ACK to send back on `lane` as `(cumulative, sack_bitmap)`.
    pub fn lane_ack(&self, lane: LaneId) -> Option<(Seqno, u64)> {
        self.lane(lane).map(|l| l.rx.ack())
    }

    /// Process an ACK received on `lane`.
    pub fn on_lane_ack(&mut self, lane: LaneId, cum: Seqno, sack: u64) {
        if let Some(l) = self.lane_mut(lane) {
            l.tx.on_ack(cum, sack);
        }
    }

    /// Return the sequence numbers on `lane` whose retransmit timer expired at
    /// `now`, restarting their timers; the caller should resend the returned
    /// frames (via [`Self::retransmit`]).
    pub fn pending_retransmits(&mut self, lane: LaneId, now: std::time::Instant) -> Vec<Seqno> {
        let Some(l) = self.lane_mut(lane) else {
            return Vec::new();
        };
        l.tx.pending_timeouts(now)
    }

    /// Re-send the frame with lane-local seq `seq` on `lane`, returning the
    /// wire bytes to transmit. Counts a retransmit.
    pub fn retransmit(&mut self, lane: LaneId, seq: Seqno) -> Option<Vec<u8>> {
        let l = self.lane_mut(lane)?;
        l.retransmits += 1;
        l.tx.retransmit(seq)
    }

    /// Current telemetry for all lanes.
    pub fn metrics(&self) -> Vec<LaneMetric> {
        self.lanes
            .iter()
            .map(|l| LaneMetric {
                id: l.id,
                sent_wire_frames: l.sent_wire_frames,
                retransmits: l.retransmits,
                delivered_frames: l.delivered_frames,
                inflight: l.tx.inflight(),
            })
            .collect()
    }

    /// Highest bond frame delivered so far (contiguous).
    pub fn last_delivered(&self) -> BondSeq {
        self.last_delivered
    }

    /// Number of frames delivered in global order since the last drain.
    pub fn delivered_pending(&self) -> usize {
        self.delivered.len()
    }

    fn lane(&self, id: LaneId) -> Option<&LaneState> {
        self.lanes.iter().find(|l| l.id == id)
    }

    fn lane_mut(&mut self, id: LaneId) -> Option<&mut LaneState> {
        self.lanes.iter_mut().find(|l| l.id == id)
    }
}

/// Encode a bond frame: 8-byte big-endian bond sequence + payload.
fn encode_bond_frame(seq: BondSeq, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Decode a bond frame into `(bond_seq, payload)`.
fn decode_bond_frame(bytes: &[u8]) -> Option<(BondSeq, &[u8])> {
    if bytes.len() < 8 {
        return None;
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes[..8]);
    let seq = u64::from_be_bytes(arr);
    Some((seq, &bytes[8..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seq(n: u16) -> Seqno {
        Seqno(n)
    }

    const RTO: Duration = Duration::from_millis(50);

    #[test]
    fn stripe_assignment_round_robins_across_lanes() {
        let mut b = MultipathBonder::new(&[LaneId(0), LaneId(1)], BondPolicy::Stripe, 8, RTO);
        b.submit(b"a".to_vec());
        b.submit(b"b".to_vec());
        b.submit(b"c".to_vec());

        // Lane 0 should carry frame 0 (seq 0) and frame 2 (seq 2).
        assert_eq!(b.drain_outgoing(LaneId(0)).len(), 2);
        // Lane 1 carries frame 1 (seq 1).
        assert_eq!(b.drain_outgoing(LaneId(1)).len(), 1);
    }

    #[test]
    fn mirror_duplicates_every_frame_on_every_lane() {
        let mut b = MultipathBonder::new(&[LaneId(0), LaneId(1)], BondPolicy::Mirror, 8, RTO);
        b.submit(b"x".to_vec());
        b.submit(b"y".to_vec());

        assert_eq!(b.drain_outgoing(LaneId(0)).len(), 2);
        assert_eq!(b.drain_outgoing(LaneId(1)).len(), 2);
    }

    #[test]
    fn reassembles_in_order_with_duplicate_dedup_across_lanes() {
        let mut b = MultipathBonder::new(&[LaneId(0), LaneId(1)], BondPolicy::Mirror, 8, RTO);
        b.submit(b"A".to_vec()); // bond 0
        b.submit(b"B".to_vec()); // bond 1

        // Drain layers.
        let lane0 = b.drain_outgoing(LaneId(0));
        let lane1 = b.drain_outgoing(LaneId(1));
        assert_eq!(lane0.len(), 2);
        assert_eq!(lane1.len(), 2);

        // Lane 1 delivers bond 1 first (out of order, its ARQ buffers it).
        b.on_lane_frame(LaneId(1), lane1[1].0, &lane1[1].1); // seq1 = bond 1
        assert_eq!(b.delivered_pending(), 0); // gap at bond 0

        // Lane 0 delivers bond 0 → bond 0 delivered; bond 1 still buffered
        // inside lane 1's ARQ (not yet in global reassembly).
        b.on_lane_frame(LaneId(0), lane0[0].0, &lane0[0].1); // seq0 = bond 0
        assert_eq!(b.delivered_pending(), 1);

        // Lane 0 delivers bond 1 → both delivered now.
        b.on_lane_frame(LaneId(0), lane0[1].0, &lane0[1].1); // seq1 = bond 1
        assert_eq!(b.delivered_pending(), 2);
        let delivered = b.take_delivered();
        assert_eq!(delivered, vec![(0, b"A".to_vec()), (1, b"B".to_vec())]);

        // Duplicates arriving from lane 1 must NOT be delivered again.
        b.on_lane_frame(LaneId(1), lane1[0].0, &lane1[0].1); // dup bond 0
        b.on_lane_frame(LaneId(1), lane1[1].0, &lane1[1].1); // dup bond 1
        assert_eq!(b.delivered_pending(), 0);

        assert!(b.take_delivered().is_empty());
    }

    #[test]
    fn out_of_order_across_lanes_reorders() {
        let mut b = MultipathBonder::new(&[LaneId(0), LaneId(1)], BondPolicy::Stripe, 8, RTO);
        for i in 0..5 {
            b.submit(vec![i]);
        }
        let l0 = b.drain_outgoing(LaneId(0));
        let l1 = b.drain_outgoing(LaneId(1));
        assert_eq!(l0.len(), 3); // bonds 0,2,4
        assert_eq!(l1.len(), 2); // bonds 1,3

        // Lane 1: receive bond 3 (buffered), then bond 1 (delivers 1 then 3).
        b.on_lane_frame(LaneId(1), l1[1].0, &l1[1].1); // seq1 = bond 3
        b.on_lane_frame(LaneId(1), l1[0].0, &l1[0].1); // seq0 = bond 1
                                                       // Global gap at bond 0 → nothing delivered yet.
        b.on_lane_frame(LaneId(0), l0[2].0, &l0[2].1); // seq2 = bond 4 (buffered in lane 0 ARQ)
        assert_eq!(b.delivered_pending(), 0); // gap at bond 0

        // Deliver bond 0 on lane 0 → pump delivers bond 0 then bond 1.
        b.on_lane_frame(LaneId(0), l0[0].0, &l0[0].1); // seq0 = bond 0
        assert_eq!(b.delivered_pending(), 2); // bonds 0 and 1
        let first = b.take_delivered();
        assert_eq!(first, vec![(0, vec![0]), (1, vec![1])]);

        // Deliver bond 2 on lane 0 → pump flushes 2,3,4 (3 and 4 were already
        // in global reassembly from lane 1 and lane 0).
        b.on_lane_frame(LaneId(0), l0[1].0, &l0[1].1); // seq1 = bond 2
        assert_eq!(b.delivered_pending(), 3); // bonds 2, 3, 4
        let rest = b.take_delivered();
        assert_eq!(rest, vec![(2, vec![2]), (3, vec![3]), (4, vec![4])]);

        // Duplicates are now out-of-window at the ARQ level → rejected.
        b.on_lane_frame(LaneId(1), l1[1].0, &l1[1].1); // dup bond 3
        b.on_lane_frame(LaneId(0), l0[2].0, &l0[2].1); // dup bond 4
        assert_eq!(b.delivered_pending(), 0);

        let delivered = b.take_delivered();
        assert!(delivered.is_empty());
    }

    #[test]
    fn unknown_lane_is_ignored() {
        let mut b = MultipathBonder::new(&[LaneId(0)], BondPolicy::Stripe, 8, RTO);
        b.submit(b"k".to_vec());
        assert!(b.drain_outgoing(LaneId(255)).is_empty());
        assert!(!b.on_lane_frame(LaneId(255), seq(0), b"x"));
        assert!(b.lane_ack(LaneId(255)).is_none());
    }

    #[test]
    fn window_full_blocks_submit() {
        let mut b = MultipathBonder::new(&[LaneId(0)], BondPolicy::Stripe, 2, RTO);
        assert!(matches!(
            b.submit(b"1".to_vec()),
            SubmitResult::Accepted { .. }
        ));
        assert!(matches!(
            b.submit(b"2".to_vec()),
            SubmitResult::Accepted { .. }
        ));
        assert_eq!(b.submit(b"3".to_vec()), SubmitResult::Blocked);
    }

    /// A tiny channel model: frames are dropped with probability `loss` and
    /// otherwise delivered in order. Rebroadcast (retransmit) frames are
    /// subjected to the same loss. The channel carries the lane-local ARQ
    /// sequence number so the receiver can feed it back into the bonder.
    /// This is the adversarial-loss simulation the doctrine (§6.4) requires —
    /// the bond must still deliver everything in order when each lane is lossy.
    struct LossyChannel {
        loss: f64,
        rng: rand::rngs::StdRng,
        delivered: Vec<(Seqno, Vec<u8>)>,
    }

    impl LossyChannel {
        fn new(loss: f64, seed: u64) -> Self {
            use rand::SeedableRng;
            Self {
                loss,
                rng: rand::rngs::StdRng::seed_from_u64(seed),
                delivered: Vec::new(),
            }
        }

        /// Returns true if this frame should be delivered (not dropped).
        fn should_deliver(&mut self) -> bool {
            use rand::Rng;
            self.rng.gen::<f64>() > self.loss
        }
    }

    #[test]
    fn adversarial_lossy_lanes_still_deliver_all_in_order() {
        // Two lanes, each dropping 40% of frames.
        let mut b = MultipathBonder::new(&[LaneId(0), LaneId(1)], BondPolicy::Stripe, 64, RTO);
        let mut ch0 = LossyChannel::new(0.40, 7);
        let mut ch1 = LossyChannel::new(0.40, 13);

        let total = 200usize;
        let frame = |i: usize| vec![b'P', (i % 256) as u8, (i >> 8) as u8];
        let mut submitted = 0usize;
        let mut next_expected = 0u64;

        // Loop until every frame is submitted AND delivered in order.
        for _ in 0..5000 {
            // Submit as many as the bond windows allow.
            while submitted < total {
                let res = b.submit(frame(submitted));
                if !matches!(res, SubmitResult::Accepted { .. }) {
                    break;
                }
                submitted += 1;
            }

            // Move queued wire frames into the channels, subject to loss.
            for (lane, ch) in [(LaneId(0), &mut ch0), (LaneId(1), &mut ch1)] {
                for (seq, bytes) in b.drain_outgoing(lane) {
                    if ch.should_deliver() {
                        ch.delivered.push((seq, bytes));
                    }
                }
            }

            // Deliver whatever the channels let through (preserving order).
            for (lane, ch) in [(LaneId(0), &mut ch0), (LaneId(1), &mut ch1)] {
                let d = std::mem::take(&mut ch.delivered);
                for (seq, bytes) in d {
                    let _ = b.on_lane_frame(lane, seq, &bytes);
                }
            }

            // Process the receiver's ACK on each lane.
            for lane in [LaneId(0), LaneId(1)] {
                if let Some((cum, sack)) = b.lane_ack(lane) {
                    b.on_lane_ack(lane, cum, sack);
                }
            }

            // Retransmit anything that timed out.
            let now = std::time::Instant::now();
            for (lane, ch) in [(LaneId(0), &mut ch0), (LaneId(1), &mut ch1)] {
                let due = b.pending_retransmits(lane, now + Duration::from_millis(200));
                for s in due {
                    if let Some(bytes) = b.retransmit(lane, s) {
                        if ch.should_deliver() {
                            ch.delivered.push((s, bytes));
                        }
                    }
                }
            }

            // Drain delivered frames and verify strict ordering.
            let delivered = b.take_delivered();
            for (seq, _) in &delivered {
                assert_eq!(*seq, next_expected);
                next_expected += 1;
            }

            if submitted == total && b.last_delivered() >= total as u64 {
                // All frames delivered in order. Nothing should remain.
                assert!(b.take_delivered().is_empty());
                return;
            }
        }

        panic!(
            "bond did not deliver all {} frames within bound (last_delivered={})",
            total,
            b.last_delivered()
        );
    }

    #[test]
    fn mirror_policy_survives_one_lane_fully_lost() {
        // Under Mirror, every frame goes to both lanes. If lane 1 is totally
        // lost, lane 0 alone must still deliver everything in order.
        let mut b = MultipathBonder::new(&[LaneId(0), LaneId(1)], BondPolicy::Mirror, 64, RTO);
        let mut ch0 = LossyChannel::new(0.0, 1); // perfect lane
        let _ch1 = LossyChannel::new(1.0, 2); // 100% loss, lane 1 never delivers

        let total = 100usize;
        let mut submitted = 0usize;

        for _ in 0..3000 {
            while submitted < total {
                if !matches!(
                    b.submit(vec![submitted as u8]),
                    SubmitResult::Accepted { .. }
                ) {
                    break;
                }
                submitted += 1;
            }
            // Only lane 0 delivers.
            for (seq, bytes) in b.drain_outgoing(LaneId(0)) {
                if ch0.should_deliver() {
                    ch0.delivered.push((seq, bytes));
                }
            }
            // Drain (and drop) lane 1.
            let _ = b.drain_outgoing(LaneId(1));

            let d = std::mem::take(&mut ch0.delivered);
            for (seq, bytes) in d {
                let _ = b.on_lane_frame(LaneId(0), seq, &bytes);
            }
            if let Some((cum, sack)) = b.lane_ack(LaneId(0)) {
                b.on_lane_ack(LaneId(0), cum, sack);
            }
            let now = std::time::Instant::now();
            for s in b.pending_retransmits(LaneId(0), now + Duration::from_millis(200)) {
                if let Some(bytes) = b.retransmit(LaneId(0), s) {
                    if ch0.should_deliver() {
                        ch0.delivered.push((s, bytes));
                    }
                }
            }
            let _ = b.take_delivered();
            if submitted == total && b.last_delivered() >= total as u64 {
                return;
            }
        }
        panic!("mirror bond did not deliver all {total} frames via lane 0");
    }
}
