# DNS-Tunnel Wire Protocol & Authentication

This document is the authoritative reference for the DastYab DNS-tunnel wire
protocol: how traffic is framed into DNS names, how it is carried, how the
**authenticated-response** layer (doctrine B) protects it, and how the ARQ
engine rides on top. It is written to be fully self-contained so that any
engineer can implement or audit the protocol from this document alone.

---

## 1. Transport premise

Under an Iranian blackout, client→foreign *UDP/53* is blocked, but **domestic
recursive resolvers** (MCI, Irancell, Shatel, …) retain internal peering that
lets them resolve foreign authoritative nameservers. We therefore ride on
**DNS queries** as our transport:

- Client → domestic resolver: a query whose QNAME encodes a tunnel frame.
- Domestic resolver → our authoritative nameserver: forwards the query.
- Our server answers with a **TXT record** whose RDATA (after the frame's
  QNAME is echoed) carries the reply, also encoded as labels.

The client therefore sees its own query answered by a *trusted* authoritative
server. Because the domestic resolver is in the middle and DNS is plaintext,
the answer path is exposed to **poisoning** (see §5).

---

## 2. Direction & framing

### 2.1 The frame (`TunnelFrame`)

Every message is a frame with four fields:

| Field | Type | Meaning |
|---|---|---|
| `session` | `String` | short session tag (owner/scoping) |
| `seq` | `u16` | sequence number (per-session) |
| `flags` | `u8` | 0=data, 1=ping, 2=status, 3=bootstrap |
| `payload` | `Vec<u8>` | the payload bytes |

Encode (client→server): `nonce.seq.flags.<base32 payload>.<session>.<base_domain>`
Decode (server→client): same layout, read left→right.

### 2.2 QNAME assembly (`assemble_name`)

```
<nonce:hex4>.<seq:u16>.<flags:u8>.<b32(payload) chunked ≤63>.<session>.<base_domain>
```

- The **nonce** (32-bit) is chosen per-query to defeat caching/repaint.
- The payload is Base32-encoded (RFC 4648, lowercase `a-z2-7`, no padding) so
  every byte maps to a legal DNS label character.
- Base32 bytes are chunked into ≤63-char labels (`MAX_LABEL = 63`).
- The whole QNAME is clamped to `MAX_QNAME_LEN = 101` (DPI-safe limit) via
  `encode_name_clamped` — truncating the payload monotonically if needed.

### 2.3 Decode (server)

The authoritative server parses the question (`parse_question`), discards
non-TXT queries and non-tunnel names, checks the session is authorized
(`TunnelHandler::authorized`), then dispatches on `flags`:

| flags | meaning | default server behavior |
|---|---|---|
| 1 | ping | reply payload `"pong"` |
| 2 | status | reply payload `"up:<secs>s"` |
| 3 | bootstrap | reply payload = configured bootstrap blob, or `"no-bootstrap"` |
| 0 | data | echo/text-rate payload (currently echoes) |

### 2.4 Response encoding (server→client)

The server builds a reply frame (same session, seq, reply flags/payload) and
encodes it into the **answer** TXT labels using a fresh random nonce:

```
reply_encoded = assemble_name(reply_frame, nonce=rand())
answer = build_dns_response_txt(id, qname, [reply_encoded])
```

### 2.5 Client decode

The client parses the TXT answer back into a `TunnelFrame` via
`decode_name` (reads nonce label, seq, flags, base32 payload, session),
verifying it is under the base domain.

---

## 3. Low-overhead ARQ (Level 3)

Because DNS over UDP sees severe loss/reorder/duplication, a **selective-repeat
windowed ARQ** engine (`arq.rs`) rides on the frame `seq` field.

- `ArqSender` — a send window (`window` in-flight), `send()` assigns the next
  sequence number, `retransmit()`/`pending_timeouts()` drive timeout-based
  selective retransmission, `on_ack(cum, sack)` advances the base and applies
  the SACK bitmap.
- `ArqReceiver` — a reorder buffer; `recv(seq, payload)` returns a
  `RecvVerdict` (delivered / duplicate / buffered / reject); delivered frames
  are drained by `take_delivered()`; `ack()` returns the cumulative ACK + SACK
  bitmap.
- Sequence numbers are 16-bit with wraparound (`Seqno::wrapping_add/sub`).

No ACK frames exist on the wire beyond the reply carrying the ACK (the reply
echoes `seq`, which doubles as cumulative ACK).

---

## 4. Authenticated responses (doctrine B) — `dnstunnel_auth.rs`

### 4.1 Threat

The DV resolver is a pass-through: an adversary that can forge or inject DNS
answers (DNS poisoning, spoofed `10.10.34.34` sinks, fake NXDOMAIN, replay of
stale replies) can present a *valid-looking* reply. **Naive trust of TXT
answers is the single most dangerous failure mode of a DNS tunnel.**

### 4.2 Design

Every **server → client** reply is sealed with **ChaCha20-Poly1305** AEAD. A
reply is only trusted after the client authenticates it; anything that fails
is discarded and the resolver that produced it is penalized in the health
table.

**Authenticated reply payload layout:**

```
+--------------------------+------------------------------------+------------+
| nonce (12 bytes)         | ciphertext ‖ Poly1305 tag (16B)   | session tag |
+--------------------------+------------------------------------+------------+
```

- `nonce` — 96-bit random AEAD nonce.
- ciphertext+tag — ChaCha20-Poly1305, AAD = UTF-8 session tag.
- `session` — the short,8-hex session tag (low 32 bits of the 32-byte key),
  used to look up the correct key in a multi-session pool.

### 4.3 Key provisioning

The 32-byte shared secret is provisioned **out-of-band**: pre-distributed
config or the bootstrap path. `DnsTunnelKey::from_hex` parses a 64-hex-char
secret; `from_bytes` derives the 8-hex session tag from the low 32 bits.

### 4.4 API

| function | action |
|---|---|
| `DnsTunnelKey::from_hex(hex)` | parse a 32-byte hex secret |
| `seal(key, plaintext) -> Vec<u8>` | encrypt + authenticate, returns nonce‖ct |
| `open(key, authed) -> Result<Vec<u8>, CFError>` | verify + decrypt; fails on tampering |

Verification failure returns `CFError("dns-tunnel-auth", …)` which the caller
maps to a **resolver penalty**.

### 4.5 What it defeats

- Spoofed sink answers (`10.10.34.34`) → tag mismatch → rejected.
- Injection/forgery without the key → rejected.
- Any flipped byte → rejected.
- Replay → rejected unless the same nonce is reused, which the random nonce
  makes practically impossible.

---

## 5. Integration points

- The client, after decoding a reply frame, passes the reply's payload through
  `dnstunnel_auth::open(key, …)`. If it fails, the answer is dropped and that
  resolver's health entry is decremented (poisoned-resolver penalty).
- The server seals send reply payload with `seal(key, …)` before `assemble_name`
  embeds it. Only the authenticated ciphertext ever goes inside the TXT labels.
- `TunnelHandler` gains an optional `auth_key`; when set, all replies are
  sealed, and only frames whose session matches an authorized session are
  answered.

---

## 6. Constants (single source of truth)

| constant | value | meaning |
|---|---|---|
| `MAX_LABEL` | 63 | max DNS label length |
| `MAX_QNAME_LEN` | 101 | DPI-safe QNAME cap for Iranian resolvers |
| `MAX_REPLY` | 512 | max reply size budget |
| `NONCE_LEN` | 12 | AEAD nonce length |
| `TAG_LEN` | 16 | Poly1305 tag length |
| `KEY_HEX_LEN` | 64 | hex length of 32-byte key |
| `SESSION_TAG_HEX_LEN` | 8 | hex length of session tag |

---

## 7. Tests

- `dnstunnel_auth` — roundtrip seal/open, tampered ciphertext fails, wrong key
  fails, too-short fails, hex roundtrip.
- `dnstunnel` — QNAME clamp, decode roundtrip, server handling, poison drop.
- `arq` — loss/reorder/dup simulation, 16-bit wraparound, selective retransmit.
