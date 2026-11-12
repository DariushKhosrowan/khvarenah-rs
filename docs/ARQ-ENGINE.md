# ARQ Engine — Selective-Repeat Windowed Automatic Repeat reQuest

`core/src/arq.rs` — the reliability layer for the DNS tunnel (Level 3).
DNS-over-UDP experiences severe packet loss, reordering, and duplication. The
ARQ engine turns the lossy, unordered DNS channel into a reliable, in-order
byte stream.

---

## 1. Why ARQ (and why this specific design)

The DNS tunnel is transported over UDP/53 through **domestic recursive
resolvers**. Real-world observations:

- Resolvers drop a fraction of queries (rate-limiting, timeouts, cache).
- Answers come back **out of order** (stripe across many resolvers).
- Queries/answers are occasionally **duplicated** (retries at the resolver,
  or the client re-asking).
- Any single dropped frame would otherwise corrupt the stream.

We need: bounded memory, low per-frame overhead, tolerance for reorder/dup,
and the ability to recover without a full re-send. **Selective-repeat windowed
ARQ** with a cumulative+SACK ACK is the sweet spot — it only retransmits what
is actually missing.

---

## 2. Sequence space

- `Seqno(pub u16)` — 16-bit sequence numbers.
- Operations are **modular** over 2¹⁶ (`wrapping_add` / `wrapping_sub`).
- `dist_to(other)` — forward distance from `self` to `other` modulo 2¹⁶
  (0 when equal).
- `is_ahead_of(other)` — strictly ahead on the ring (forward distance in
  `(0, 32768)`). This is the classic half-ring rule that disambiguates
  wraparound.

Because the window is always ≤ `MAX_WINDOW = 64` (far below 32768), the
half-ring test is unambiguous.

---

## 3. Sender — `ArqSender`

| field | role |
|---|---|
| `base` | lowest unacknowledged seq |
| `next` | next seq to allocate |
| `window` | max in-flight (clamped to 1..=64) |
| `in_flight` | `BTreeMap<Seqno, InFlight{payload, sent_at}>` |
| `rto` | retransmit timeout |

### API

| method | behavior |
|---|---|
| `new(window, rto)` | constructor; clamps window to 1..=64 |
| `can_send()` | `in_flight.len() < window` |
| `inflight()` | current unacked count |
| `is_inflight(seq)` | whether `seq` is buffered |
| `send(payload)` | assign `next`, buffer, advance `next`, return `Some(seq)`; `None` if window full |
| `retransmit(seq)` | touch `sent_at`, return the payload to re-send (caller writes it) |
| `pending_timeouts(now)` | return seqs whose timer expired, restart their timers |
| `on_ack(cum, sack)` | advance base, drop acked frames, slide base over contiguous acked |
| `is_idle()` | no frames in flight |

### ACK processing (`on_ack`)

1. Drop anything strictly behind the cumulative `cum`; keep `cum` and anything
   ahead of it on the ring.
2. Advance `base` to `cum` if it moved forward.
3. Apply the **selective ACK bitmap** `sack`: bit *i* (LSB-first) acknowledges
   seq `cum + (i+1)`; drop those frames.
4. Slide `base` forward over contiguous acknowledged frames.

### Timeout-driven retransmission (`pending_timeouts`)

The caller polls `pending_timeouts(now)` periodically; any frame whose
`sent_at` is older than `rto` is returned and its timer is reset. The caller
then calls `retransmit(seq)` (or re-reads the payload) to actually write it.
Each expired frame is emitted exactly once per call.

---

## 4. Receiver — `ArqReceiver`

| field | role |
|---|---|
| `next_expected` | next in-order seq we need |
| `window` | reorder slots (clamped 1..=64) |
| `buffered` | `BTreeMap<Seqno, Vec<u8>>` out-of-order frames |
| `delivered` | in-order frames ready to drain |
| `seen` | duplicate-detection set (bounded) |

### API

| method | behavior |
|---|---|
| `new(window)` | constructor |
| `with_base(window, base)` | start expecting `base` (wrap / resume) |
| `recv(seq, payload)` | `Accepted` / `Duplicate` / `OutOfWindow` |
| `take_delivered()` | drain in-order frames |
| `ack()` | return `(cumulative, sack_bitmap)` |

### Reception logic (`recv`)

1. Already in `seen` → `Duplicate` (ignore).
2. `dist == 0` (in-order) → deliver immediately, advance `next_expected`, then
   flush contiguous buffered frames.
3. `dist > window` → `OutOfWindow` (drop — too old or too far ahead).
4. Otherwise → buffer out-of-order inside the window.

### ACK construction (`ack`)

```
cumulative = next_expected
sack bit i (LSB-first) = 1  iff  seq = next_expected + (i+1) is buffered
```

This tells the sender exactly which gaps to fill, so it retransmits only what
is missing.

### Bounded memory

`seen` is pruned to `2 * window` entries (`prune_seen`); the buffer is bounded
by the window. No unbounded growth under long runs or wraparound.

---

## 5. Verdicts

| verdict | meaning | action |
|---|---|---|
| `Accepted` | new frame, in-window | deliver (in-order) or buffer (out-of-order) |
| `Duplicate` | already seen | ignore |
| `OutOfWindow` | too old / too far ahead | drop |

---

## 6. Wire interaction (with the DNS tunnel)

The DNS tunnel frame carries `seq` (u16). The reply echoes the request seq,
which doubles as the **cumulative ACK**; a SACK bitmap may be piggybacked in
the reply payload. The ARQ engine assigns and verifies these seq numbers but
the actual byte framing lives in `dnstunnel.rs` (see
`docs/DNS-TUNNEL-PROTOCOL.md` §2–3).

---

## 7. Determinism & testability

The engine is pure and time-triggered: `poll_timeouts` is called with an
explicit `now: Instant`, so tests inject fake clocks and simulate arbitrary
loss/reorder/dup schedules. The existing test suite covers:

- loss → timeout → selective retransmission;
- reorder → buffering → in-order delivery;
- duplication → duplicate verdict, no double-delivery;
- cumulative + SACK ACK correctness;
- 16-bit wraparound (sender & receiver);
- out-of-window rejection.
