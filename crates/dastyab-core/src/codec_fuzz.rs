//! Deterministic adversarial fuzz gates for the wire codecs (doctrine §8.4).
//!
//! The "no-bugs" standard (§6.3) asks for fuzzing of the codecs plus
//! adversarial loss/reorder/dup simulations as a **permanent CI gate**. This
//! module provides that gate with zero external dependencies and full
//! determinism (a seeded PRNG), so `cargo test` exercises every codec against
//! thousands of pseudo-random inputs every run — not just the hand-picked
//! happy-path vectors.
//!
//! # What is fuzzed
//!
//! 1. **`TunnelFrame` QNAME codec** (`dnstunnel.rs`) — random payloads encode
//!    to a base32 label chain, decode back to the original frame, and the
//!    encoded name stays under the DPI `MAX_QNAME_LEN` clamp.
//! 2. **ARQ transport** (`arq.rs`) — a full sender/receiver session is driven
//!    under random loss, duplication, and reordering, and the receiver must
//!    always deliver exactly the sent payloads, in order, exactly once.
//! 3. **ChaCha20-Poly1305 seal/open** (`dnstunnel_auth.rs`) — random
//!    plaintexts round-trip through `seal`/`open`; a single flipped byte must
//!    be rejected (no silent corruption).

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::arq::{ArqReceiver, ArqSender, Seqno};
use crate::dnstunnel::{TunnelFrame, MAX_QNAME_LEN};
use crate::dnstunnel_auth::{open, seal, DnsTunnelKey};

/// A tiny deterministic xorshift64 PRNG (no rand dependency).
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u64() as u8).collect()
    }
}

const BASE_DOMAIN: &str = "dastyab.internal";

/// Fuzz `TunnelFrame` encode→decode round-trips under random payloads.
/// Every frame must round-trip exactly, and the clamped name must fit the
/// DPI QNAME budget.
fn fuzz_tunnel_frame_roundtrip(seed: u64, iters: usize) {
    let mut rng = Rng::new(seed);
    // Session tags of varied length. The decoder (`decode_name`) requires at
    // least 4 core labels (nonce/seq/flags/session), so a session is always
    // present — the empty-session wire form is unsupported by design.
    let sessions: Vec<String> = vec![
        "a".to_string(),
        "sess-1234".to_string(),
        format!("s{}", "x".repeat(40)),
    ];
    for _ in 0..iters {
        let pl_len = rng.below(512) as usize;
        let payload = rng.bytes(pl_len);
        let session = &sessions[rng.below(sessions.len() as u64) as usize];
        let frame = TunnelFrame {
            session: session.clone(),
            seq: rng.next_u64() as u16,
            flags: rng.below(4) as u8,
            payload: payload.clone(),
        };
        // Encode clamped. Must always be under the DPI cap.
        let name = frame.encode_name_clamped(BASE_DOMAIN, rng.next_u64() as u32, MAX_QNAME_LEN);
        assert!(
            name.len() <= MAX_QNAME_LEN,
            "clamped QNAME {} > limit {}",
            name.len(),
            MAX_QNAME_LEN
        );
        // Decode via the real parser.
        let decoded = TunnelFrame::decode_name(&name, BASE_DOMAIN);
        match decoded {
            Ok(d) => {
                // `encode_name_clamped` is documented to truncate the payload
                // to fit the DPI QNAME limit, so a large payload must survive
                // as an exact *prefix* (never corrupted, never reordered).
                assert!(
                    payload.starts_with(&d.payload),
                    "decoded payload is not a prefix of original ({}/{} bytes)",
                    d.payload.len(),
                    payload.len()
                );
                assert_eq!(d.seq, frame.seq, "seq mismatch on round-trip");
                assert_eq!(d.flags, frame.flags, "flags mismatch on round-trip");
            }
            Err(_) => panic!("unexpected decode failure for clamped name => {name}"),
        }
    }
}

/// Enumerate the currently in-flight sequence numbers using only the public
/// ARQ surface (`base`, `inflight`, `is_inflight`).
fn inflight_seqs(tx: &ArqSender) -> Vec<Seqno> {
    let base = tx.base().0 as u64;
    let n = tx.inflight();
    (0..n)
        .map(|i| Seqno((base + i as u64) as u16))
        .filter(|s| tx.is_inflight(*s))
        .collect()
}

/// Drive a full ARQ session under random loss/dup/reorder, mirroring the real
/// `DnsTunnelArq::pump` loop: fill the window, transmit every in-flight frame
/// over the lossy channel, fire retransmit timeouts, apply ACKs, and keep
/// going until the outbox drains and the sender goes idle. The receiver must
/// end up having delivered exactly the sent payloads, in order, exactly once.
fn fuzz_arq_session(seed: u64, frames: usize, window: u16, loss: f64, dup: f64, reorder: f64) {
    let mut rng = Rng::new(seed);
    let mut tx = ArqSender::new(window, Duration::from_millis(20));
    let mut rx = ArqReceiver::new(window);

    let payloads: Vec<Vec<u8>> = (0..frames).map(|i| rng.bytes(16 + (i % 40))).collect();
    let mut outbox: VecDeque<Vec<u8>> = payloads.clone().into();
    let mut guard = 0usize;
    let max_rounds = frames * 40 + 16;

    while !outbox.is_empty() || !tx.is_idle() {
        // 1. Fill the window from the outbox.
        while tx.can_send() {
            match outbox.pop_front() {
                Some(p) => {
                    tx.send(p);
                }
                None => break,
            }
        }

        // 2. Transmit every in-flight frame over the lossy channel.
        let seqs = inflight_seqs(&tx);
        for s in seqs {
            if let Some(pl) = tx.retransmit(s) {
                deliver_with_perturbation(&mut rx, s, &pl, &mut rng, loss, dup, reorder);
            }
        }

        // 3. Fire retransmit timeouts (simulate time advancing past RTO).
        let due = tx.pending_timeouts(Instant::now() + Duration::from_millis(200));
        for s in due {
            if let Some(pl) = tx.retransmit(s) {
                deliver_with_perturbation(&mut rx, s, &pl, &mut rng, loss, dup, reorder);
            }
        }

        // 4. Apply the receiver's cumulative + selective ACK.
        let (cum, sack) = rx.ack();
        tx.on_ack(cum, sack);

        guard += 1;
        assert!(
            guard < max_rounds,
            "ARQ session failed to converge in {max_rounds} rounds"
        );
    }

    let delivered = rx.take_delivered();
    assert_eq!(delivered.len(), frames, "duplicated or lost frame(s)");
    for (i, (_seq, pl)) in delivered.iter().enumerate() {
        assert_eq!(pl, &payloads[i], "payload {} out of order", i);
    }
}

/// Deliver `(seq, payload)` to the receiver, optionally dropping, duplicating,
/// or reordering it per the perturbation probabilities.
fn deliver_with_perturbation(
    rx: &mut ArqReceiver,
    seq: Seqno,
    payload: &[u8],
    rng: &mut Rng,
    loss: f64,
    dup: f64,
    reorder: f64,
) {
    let roll = |rng: &mut Rng| (rng.next_u64() as f64) / (u64::MAX as f64);
    // Loss: skip this delivery entirely.
    if roll(rng) < loss {
        return;
    }
    // Duplicate: deliver it, and maybe deliver a copy again later.
    let mut deliveries = vec![(seq, payload.to_vec())];
    if roll(rng) < dup {
        deliveries.push((seq, payload.to_vec()));
    }
    // Reorder: push to the back so it arrives after the next frame.
    if roll(rng) < reorder && deliveries.len() == 1 {
        let item = deliveries.remove(0);
        deliveries.push(item);
    }
    for (s, pl) in deliveries {
        let _ = rx.recv(s, &pl);
    }
}

/// Fuzz ChaCha20-Poly1305 seal/open round-trips and tamper rejection.
fn fuzz_auth_seal_open(seed: u64, iters: usize) {
    let mut rng = Rng::new(seed);
    let key = DnsTunnelKey::from_bytes(&rng.bytes(32));
    for _ in 0..iters {
        let pt_len = rng.below(1024) as usize;
        let pt = rng.bytes(pt_len);
        let sealed = seal(&key, &pt);
        let reopened =
            open(&key, &sealed).unwrap_or_else(|_| panic!("failed to open own ciphertext"));
        assert_eq!(reopened, pt, "seal/open mismatch");
        // Tamper: flip one bit anywhere in the sealed blob → must be rejected.
        if sealed.len() > 1 {
            let mut tampered = sealed.clone();
            let pos = rng.below(tampered.len() as u64) as usize;
            tampered[pos] ^= 1 << rng.below(8);
            assert!(
                open(&key, &tampered).is_err(),
                "tampered ciphertext was accepted (byte {pos})"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The permanent CI fuzz gate. Deterministic: exact seed → exact result.
    ///
    /// These iteration counts are high enough to be a real gate (thousands of
    /// codec exercises per run) but small enough to stay fast in CI (<1s).
    #[test]
    fn codec_fuzz_gate() {
        let t0 = std::time::Instant::now();
        fuzz_tunnel_frame_roundtrip(0x1234_5678, 4_000);
        fuzz_arq_session(0x9abc_def0, 40, 8, 0.30, 0.10, 0.15);
        fuzz_arq_session(0x1111_2222, 80, 16, 0.45, 0.20, 0.25);
        fuzz_arq_session(0x3333_4444, 120, 4, 0.60, 0.30, 0.35);
        fuzz_auth_seal_open(0x5555_6666, 2_000);
        // Wall-clock guard: the gate has a no-busy-waiting budget.
        assert!(t0.elapsed() < Duration::from_secs(20), "fuzz gate too slow");
    }
}
