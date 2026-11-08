# DNS-Only Survival Engineering Report

**Scope:** How `khvarenah` (and any Rust client in Iran) can keep functioning when
the *only* working channel left is DNS — including total-blackout / heavy-DPI
scenarios where the entire network path to the outside world is severed except
for DNS resolvers.

**Audience:** engineering; assumes the reader knows the khvarenah core and can
implement Rust modules.

**Status:** research + design → **implemented in core** (see Appendix C for the concrete modules shipped in this revision).

---

## 0. Executive summary

- **DNS keeps working in blackouts for a structural reason:** the Iranian
  network (and every network) *must* keep recursive resolution alive or the
  network breaks for everyone — service discovery, CDN routing, mail retries,
  and the state's own monitoring all depend on DNS. The censor therefore
  throttles, poisons, and DPI-inspects DNS, but it almost never *fully* kills
  the channel. DoH over 443 to **pinned literal IPs** is the most resilient
  last-man-standing path, because it looks like ordinary web TLS and never
  touches the hijacked system resolver.
- **The Iran 198.18.x.x signature** is a synthetic-answer hijack: an
  `A` response whose every RR lies in `198.18.0.0/15` (RFC 2544 benchmark
  space). You must filter that range in every resolver result, and treat
  "all answers hijacked" as *poison* — not as a valid answer.
- **DNS tunneling (iodine / dnscat2) is a text-rate emergency channel**, not
  a VPN. Realistic throughput is ~1–50 kbps over many minutes, latency is
  one DNS RTT per packet (~50–300 ms), and the platform is unreliable under
  query-throttling. It should be the **last fallback**, used to bootstrap a
  real tunnel or to ferry small control messages — never for bulk traffic.
- **GoodbyeDPI / Zapret are not DNS tools**, they are *anti-DPI desync*
  tools that defeat stateful firewalls by fragmenting/reordering TCP. They
  help when the border is up but DPI is blocking you by SNI/flow signature.
  In a true total blackout (border cut), they cannot help — DNS is the only
  egress. You should implement *both* classes: an anti-DPI `desync` module
  for the "DPI but alive" state, and a DNS-tunnel module for the "only DNS"
  state.
- **Recommended fallback ladder for khvarenah:** direct/clean-IP → DoH over
  pinned 443 → DoT (TCP 853) → DNS tunnel. The app should be a **state
  machine** that walks down this ladder automatically and walks back up as
  soon as higher tiers recover.

---

## 1. Why DNS stays reachable during blockades

### 1.1 Structural indispensability

A modern network operator cannot drop DNS without degrading its own service
delivery:

- Every CDN, load balancer, and geolocation scheme depends on stub resolvers
  querying authoritative/recursive servers.
- Email (SMTP MX lookups), session reuse, and endpoint discovery still need
  DNS even in crisis.
- The censor itself uses DNS analytics and DNS-based blocking; it still wants
  to *see* queries, which means it keeps the channel open and inspects it.

Iran's repeated "internet shutdowns" have consistently left DNS resolvers
reachable (the state relies on them to keep its own services up and to
enforce domain-level blocking). The practical consequence: **what is blocked
is the *name→address* resolution for forbidden targets, and the *traffic* to
forbidden IPs — not DNS as a protocol.**

### 1.2 Why UDP/53 (plain DNS) survives but is useless

- UDP/53 is the oldest, most-cached, most-tolerated path; ISPs keep it up.
- But it is **plaintext and forgeable**: DPI injects synthetic answers (the
  198.18 hijack), and can lie about MX/NS as well. You can *read* DNS over
  53, but you cannot trust the answers, and you cannot hide what you query.
- So 53 is good for **probing** (is the border up? is DPI active?) and for
  **tunneling payloads** (see §2), not for authoritative resolution.

### 1.3 DoH over 443 to pinned IPs

DoH (RFC 8484) wraps the raw DNS wire message in HTTPS and POSTs it to a
resolver's `/dns-query` endpoint.

- **Traffic camouflage:** to DPI it is an ordinary TLS/1.3 flow to port 443 —
  indistinguishable from any web browse, unless the middleware *deeply*
  fingerprints the TLS stack.
- **Bootstrap safety:** the killer detail is that the resolver *hostname*
  must not be resolved via the hijacked system resolver. Pinning every DoH
  endpoint hostname to a **hardcoded literal IP** (via
  `reqwest::ClientBuilder::resolve`) means we connect by IP while still
  presenting the correct SNI/Host so TLS certificate validation passes.
- **TLS 1.3 + ECH (Encrypted Client Hello, formerly ESNI):** the ClientHello
  is encrypted so the middlebox only sees the *outer* public server name
  (e.g., `cloudflare-dns.com` or a routine CDN front). The resolver still
  sees the actual query inside the TLS session.

### 1.4 The 198.18.x.x DPI hijack signature

- `198.18.0.0/15` is RFC 2544's reserved benchmark range (198.18.0.0 –
  198.19.255.255). Real internet hosts never legitimately respond there.
- Iranian DPI responds to `A` queries for censored names with **synthetic
  answers entirely inside `198.18.0.0/15`**, so:
  - `getaddrinfo()` succeeds (no NXDOMAIN → the app doesn't retry),
  - connect() to the synthetic IP times out or is black-holed,
  - the censor can *track* that you asked about the forbidden name.
- **The code already implements the right signature** in `doh.rs::is_hijacked_ip`
  (`198.18/31`). The policy must be: **if every returned address is hijacked,
  treat the whole resolution as poisoned** — fail, never connect to the
  synthetic IP, and log so the watchdog can escalate.

---

## 2. DNS tunneling as a last-resort channel

### 2.1 What it is

Two cooperating ends encode arbitrary bytes into DNS query/response pairs.
The client sends *payload* in the query name (QNAME) or in a TXT/A pseudo-RR;
the server replies with the *response* bytes hidden in TXT records, CNAME
chains, or even `A` record IPs (each octet = one byte).

| Tool | Transport mode | Typical throughput | Notes |
|---|---|---|---|
| **iodine** | **IP-over-DNS** (creates a `tun0` device; full IP packets) | 10–100 kbps (best case ~1 Mbps on permissive resolvers) | TUN needs root/privileges on the client. Best for single-user rescue. |
| **dnscat2** | **application-level tunnel** (no TUN; stream protocol of its own) | 1–30 kbps | Designed for C2 smuggling; chatty; less suited to general TCP but simpler to embed. |
| NSTX / OzymanDNS | classic | very slow | historical interest |

### 2.2 Limits you must design for

- **Bandwidth:** one DNS round-trip carries ~200–500 bytes of payload after
  base64/QNAME encoding overhead. At 1 query / 100 ms that's ≈ 2–5 kB/s
  (16–40 kbps) *best case*, and an order of magnitude worse if the resolver
  throttles. Treat it as **text / rescue**, never as a general data plane.
- **Latency:** one RTT per packet. TCP-over-DNS has the full DNS RTT on
  every segment, so interactive use is painful; application-level protocols
  that do *not* assume low latency (email-style, or a one-shot command) work
  far better.
- **Reliability:**
  - Resolver caching can coalesce/reorder queries — you must make every query
    unique (random subdomain prefix) so the response is not a stale cache hit.
  - **QNAME length limits:** a label is at most 63 bytes, the whole name ≤
    255 bytes. Base64 inflates payload by ~4/3; large chunks get flagged.
  - Some middleboxes **truncate** large TXT responses, strip `ANY`/`TXT`
    types, or simply drop high-frequency query bursts. So: use **small
    frames**, keep every query ≤ ~100–120 name bytes, and add jitter.
  - **DPI heuristics** watch for unusual QNAME entropy, high query rate, and
    non-standard RDATA — so add traffic shaping (random padding, slow rates).
- **Crypto:** the whole point is preserving a *controlled* channel. Encrypt
  the inner stream (e.g., ChaCha20-Poly1305) and authenticate the peer;
  otherwise the DPI that can read your QNAMEs reads the payload too.

### 2.3 How to integrate as a fallback in khvarenah

Do **not** bolt a TUN device in by default (permissions, platform variance).
Instead ship an **application-level** tunnel (dnscat2-style) that:

1. Exposes a `tokio` `AsyncRead/AsyncWrite`-like duplex to the app,
2. Is gated behind a `dns-tunnel` feature and a watchdog-triggered fallback,
3. Carries only **small control messages** (e.g., a "hand over" command,
   a status line, a config blob) — and optionally can fetch a tiny
   "bootstrap-file" that gives the next real endpoint to try,
4. Never auto-enables on a full pipe; only enters when higher tiers fail.

A concrete, minimal vertical slice for Rust:

- `dns_tunnel::Client { server_domain, key, mode }`
- encode: `payload → (random_label).base64(server_domain)` — QNAME or TXT
- decode: parse RDATA (TXT bytes / A-octets) → frame
- a tiny **framing + reassembly** layer (sequence numbers, ACK, length prefix)
- backoff: linear + jitter, plus adaptive frame size on truncation.

---

## 3. DNS-based proxies / "crypt DNS" / GoodbyeDPI / Zapret

### 3.1 Clarify the three families — they are different problems

| Family | What it does | Works when | Verdict for Iran |
|---|---|---|---|
| **DNSCrypt** | encrypts the *DNS query itself* with a lightweight keyed protocol to a chosen resolver | border up; DNS spots | Adds confidentiality **for DNS only**, not for your traffic; good complement, not a tunnel. |
| **Anonymized DNS / ODoH** | DoH with an extra relay hop so the resolver never sees your IP | border up; DoH reachable | Privacy feature; helps against IP-based blocking of DoH endpoints. |
| **GoodbyeDPI / Zapret** | **TCP desync** — fragments/reorders the *application* flows so DPI's reassembly-based signatures miss | border up; DPI is the only blocker | The single most effective fix for "web blocked but border open"; see 3.2. |
| **DNS tunneling** | smuggling bytes inside DNS itself | **border down; only DNS open** | the last-resort channel (cf. §2). |

### 3.2 GoodbyeDPI / Zapret mechanics (and the Rust equivalent)

These run *on the client* and modify how packets leave the machine, without
any server-side cooperation:

- **Split TCP payloads** into many small segments (`--dpi-desync=split`),
  so DPI cannot reassemble the first data segment to fingerprint the
  application protocol.
- **Reorder / delay first packets** (`--dpi-desync=disorder`, `fake`, etc.)
  so the DPI's "first N packets" signature never matches.
- **Change TCP options / window sizes** and randomize MSS so the firewall's
  flow correlation is confused.
- **Mitigate SNI-based blocking** by making the *first* ClientHello segment
  appear incomplete/odd so the DPI never harvests a clean SNI.

In Rust (userspace, no kernel modules), the practical building blocks are:

- **TCP-level:** use a `socket2` / raw `TcpStream` in a custom connector that
  deliberately writes the TLS ClientHello in small, separated writes and
  randomizes the TCP option set. This is achievable for a **TLS-over-TCP**
  proxy, which is exactly what a VLESS client is.
- **IP-fragment tricks (L3):** true fragmentation needs raw sockets or
  `netfilter_queue`/`nftables` integration — heavy, platform-specific, and
  not portable to Android. Skip unless you target Linux root.
- **The practical alternative that ships everywhere:** make the *app-layer*
  un-fingerprintable:
  - randomize the TLS fingerprint (custom `rustls` config, non-default
    cipher suites, odd signatures, GREASE),
  - tunnel over **WebSocket inside TLS** (the project already does WS
    upgrades in `health.rs`) so the flow is a routine browser-ish upgrade,
  - use HTTP/2 + padding to obscure lengths,
  - rotate between **multiple CF front IPs** (anycast) so the same
    connection pattern is never pinned to one edge.

### 3.3 "crypt DNS" conclusion

Use **DNSCrypt / DoH with ECH** to protect the *resolver* leg. Use
**Zapret-style desync** to protect the *application* leg. They compose: the
first keeps your queries private, the second keeps your test secret.

---

## 4. SNI / domain-fronting techniques given ECH (Encrypted Client Hello)

### 4.1 The old trick

Domain fronting sent a valid outer SNI/Host (`www.cloudflare.com`) to a shared
CDN edge that also hosted the *censored* origin. When CDNs tightened the rules
and ECH appeared, naive "Host != SNI" fronting broke: servers now validate the
Host against the SNI's authority.

### 4.2 ECH (formerly ESNI) — what it actually changes

- **Outer ClientHello** carries a *public* server name that the middlebox can
  see — typically a routine, unblocked CDN front.
- **Inner ClientHello** (encrypted) carries the *real* SNI that the server
  decrypts.
- **Consequence for a censor:** it can't read the inner SNI, so it can't
  block by *target* name. But it **can**:
  - see the outer name, and block-by-front if the front is itself blocked,
  - detect ECH itself and block **all** ECH flows (a blunt but effective
    counter-measure seen in several censors),
  - block the SNI for the *resolver* or *front* IP.

### 4.3 Practical guidance for khvarenah

- Treat **ECH as a feature, not a religion.** Because censor behavior varies,
  the client should be able to switch between:
  1. plain TLS with a **rotating set of benign outer SNIs** (simple, stable),
  2. ECH where offered (privacy win when the censor tolerates it),
- **The most robust "fronting" in Iran today is not TLS-host fronting** — it
  is *combining* an unblocked front IP with a *plausible* SNI and a
  browser-grade TLS fingerprint. The SPI-facing "front" is `www.cloudflare.com`
  or a big CDN property; the *actual* worker is reached via the same anycast
  edge. This is exactly what the existing CF-IP scan pipeline already
  produces.
- Do **not** rely on domain fronting alone; implement it as one arm of the
  anti-DPI module (see §6, feature 4).

---

## 5. DoH vs DoT vs plain-DNS in Iran

| Transport | Port | Who sees the query | Likelihood of surviving heavy DPI | Bootstrap requirement | Verdict for Iran |
|---|---|---|---|---|---|
| **Plain DNS** | 53/UDP | network + ISP | low (forgeable, visible) | none (server IP known) | diagnostic only |
| **DoT** | 853/TCP | only endpoints (TLS) | **low–medium** — 853 is non-standard and DPI frequently drops/throttles it | need resolver IP (pin it) | secondary fallback |
| **DoH** | 443/TCP (HTTPS) | only endpoints, and it *looks like web traffic* | **high** | need resolver IP (pin it) | **primary resolver channel** |
| **DoH over a CDN front (ECH)** | 443 | only endpoints; outer front visible | high, unless ECH itself is blocked | same | best-in-class |

Why DoH wins in Iran specifically:

- 443 is the one port the censor basically cannot kill without breaking the
  *entire web* — so DoH inherits the web's immunity.
- DoT's 853 is a small, unusual port; DPIs can block *all* 853 traffic with
  no collateral damage. Many Iranian ISPs do exactly that.
- Plain DNS is too easy to poison (the 198.18 attack is trivial there).

**Trade-offs to design for:**
- DoH adds a TLS+HTTP round trip per resolution (higher latency than plain);
  mitigate with an in-memory TTL cache (already present in `doh.rs`).
- DoH endpoints per *public* (well-known) IPs can themselves be IP-blocked;
  pin several across providers (Cloudflare, Google, and one more) and rotate.
- When 443 is throttled but 853 works, DoT is a genuine rescue — hence keep
  it in the ladder after DoH, before DNS tunnel.

---

## 6. Recommended architecture for khvarenah to survive a DNS-only blackout

Add these modules to the existing `khvarenah-core` (each is small, pure-Rust,
gated, and follows the repo's `CFError` + `store/` conventions). Ranked by
impact-to-effort.

### Feature 1 — Resolver hardening (already 80% done)
**Effort:** low. **Impact:** very high.

Enhance `doh.rs`:

1. Keep the IP-pinned DoH endpoints; extend the endpoint list to also cover a
   **DoT** transport (TCP 853, TLS) using the same pinning — this is the §5
   secondary.
2. Add **rotation + blacklisting** of endpoints: on repeated failure of one
   pinned IP, park it for 60 s and move to the next; persist the blacklist in
   profile `store/`.
3. Add **coalescing**: if N resolvers share the same cache user, fan out the
   first query to all and take the first *non-hijacked* answer (this is how
   you dodge a single poisoned endpoint).
4. **Watchdog signature:** expose
   `probe::blackout_probe() -> { pct_hijacked, reachable }`. When the
   majority of answers come back hijacked *and* DoH also returns poisoned
   answers, set the blackout flag.

### Feature 2 — Connectivity state machine + fallback ladder
**Effort:** medium. **Impact:** very high.

Add `connectivity.rs`:

```
enum PathTier { DirectIp, Doh, Dot, DnsTunnel }
```

The core is a **single `resolve_and_connect(target)`** that walks:

1. `DirectIp` — the CSP pinned-IP / clean-IP scan already available
   (`health.rs` + `cf/ips.rs`). It is the fastest tier and should be tried
   first.
2. `Doh` — resolve via pinned DoH, then connect.
3. `Dot` — resolve via DoT, connect.
4. `DnsTunnel` — last resort, §2.

Each tier has a **health probe and a confidence score**; the state machine
ascends when a higher tier's probe succeeds (e.g., a successful direct TCP
handshake). **Never stay wedged at a low tier** once a better one is back.

### Feature 3 — Pinned bootstrap IPs, compiled in
**Effort:** very low. **Impact:** high.

Ship a small `const BOOTSTRAP_IPS: &[(host, ipv4, port)]` table containing
(as of this writing, verify before release):

- `cloudflare-dns.com` → `104.16.132.229`, `104.16.133.229` (DoH)
- `1.1.1.1` → `1.1.1.1` (DoH, direct)
- `dns.google` → `8.8.8.8`, `8.8.4.4` (DoH)
- `dns.google` → `8.8.8.8` 853 (DoT)
- a Cloudflare **edge** IP (e.g., `104.16.0.0/13` anycast) used only as a TCP
  probe target to test border liveness.

`120` **feature-gate** the whole DNS-tunnel crate so release builds that don't
want it stay lean.

### Feature 4 — Anti-DPI `desync` module (Zapret-style)
**Effort:** high. **Impact:** high for the "DPI alive, border up" state
(which is the *common* state; the DNS-only blackout is rarer).

Implement as a **client-side connector** (not kernel code):

- `tls_fingerprint.rs` — a `rustls` `ClientConfig` with:
  - GREASE random values (random odd cipher/extension IDs),
  - non-empty `supported_versions` go first, odd record sizes,
  - follow-up split of the handshake write into small chunks so DPI's packet
    reassembly misses the first-ClientHello signature.
- `ws_stealth.rs` — reuse the existing WebSocket upgrade logic but vary the
  upgrade path, padding, and header order per request.
- `path_spread.rs` — rotate CF-front IPs (anycast) from the clean-IP set per
  session.

### Feature 5 — DNS tunnel client
**Effort:** high. **Impact:** the *only* thing that works in a true
DNS-only blackout — and the *only* way to bootstrap the next tier.

Implement as described in §2.3. Keep it **small and textual**: one control
channel; no bulk file transfer. Expose `app_tunnel::run(addr, key, on_packet)`
with backoff and resumption.

### Feature 6 — Watchdog & incident reporting
**Effort:** low. **Impact:** medium.

Extend `diagnose.rs` to log, on blackout detection:

- *what* failed at each tier (direct/DoH/DoT),
- the *signature* observed (all-198.18 vs timeout vs connection-refused),
- the tier actually used, and the RTT/latency at that tier.

### Feature 7 — Config-free operation
Keep everything **compiled-in** (`const`/`Default`), matching the repo's
"no env-var fuss" preference. Allow override only via the profile JSON, never
a required env var.

---

## 7. The known limitation, stated plainly

**DNS tunneling is slow (kbps), text-grade, and high-latency.** It is a
*rescue/emergency messaging* channel — useful to export a status line, fetch a
small bootstrap blob, or trigger the server to stand up a real tunnel — and
**it is not a substitute for the data plane.** Any design that relies on DNS
tunneling for streaming data will fail user expectations. That's exactly why
the fallback ladder above places it at the *bottom*, with a watchdog that
climbs back to the high-bandwidth direct/DoH tiers the moment the border
recovers.

---

## Appendix A — suggested crate additions (Rust)

| Need | Crate / approach |
|---|---|
| raw DNS wire parse/encode | keep the compact handwritten parser in `doh.rs` (no dep), extend for TXT/PTR if tunneling |
| DoT | `tokio-rustls` (already in workspace) over TCP 853; reuse `reqwest::ClientBuilder::resolve` equivalently |
| TLS fingerprint variation | hand-tuned `rustls` (present) + record-layer writes |
| async worker | `tokio` (present) |
| payload framing/crypto | `bytes`, `chacha20poly1305` + `rand` |
| IP packing | a tiny const table (no dep) |
| sockets/raw | `socket2` (optional, for TCP option setting) |

## Appendix B — implementation order

1. `doh.rs` hardening (endpoint rotation, DoT, blackout signature) — small,
   unlocks everything.
2. `connectivity.rs` state machine + ladder.
3. `BOOTSTRAP_IPS` table.
4. `probe::blackout_probe`.
5. Anti-DPI desync connector.
6. DNS-tunnel client (last, but the piece that makes "survive a total
   blackout" true).

*Report prepared for the khvarenah-rs project. Verified against the actual
source: `crates/khvarenah-core/src/doh.rs` (IP-pinned DoH + 198.18 filter),
`crates/khvarenah-core/src/health.rs` (alt-ports + WS gate), and
`crates/khvarenah-core/src/cf/ips.rs` (CF range/seed engineering).*

## Appendix C — implementation shipped (this revision)

The ladder in this repo now has working Rust modules, all in
`crates/khvarenah-core/src/`:

| Module | What it does |
|---|---|
| `connectivity.rs` | `FallbackLadder` state machine; ordered tiers Direct → DoH → DoT → DnsTunnel; descends after repeated failures, climbs back when a higher tier recovers. Now `Tier: Hash`, `Probe` trait fully wired. |
| `dot.rs` | DoT transport (TLS over TCP 853) to literal pinned IPs; reuses the RFC 1035 wire helpers from `doh.rs`; filters the 198.18.x.x hijack signature. |
| `blackout.rs` | `NetworkState` detection: system-DNS 198.18 hijack probe, `any_bootstrap_reachable` TCP sniff against literal IPs, combined `detect()` heuristic. |
| `dnstunnel.rs` | dnscat2-style client framing: base32 DNS-label codec, chunking to 63-char labels, `TunnelFrame` encode/decode, and a `send_receive` primitive over a TXT-capable resolver. |
| `doh.rs` (hardened) | per-endpoint failure blacklisting (`ENDPOINT_BLACKLIST_THRESHOLD`), reset on success, plus the existing 198.18.0.0/15 filtering. |

Left for a follow-up (bookmarked in this report):
- Anti-DPI desync connector (Zapret/GoodbyeDPI-style) — the *other* half of the
  fight, for when the border is up but DPI blocks by fingerprint.
- `BOOTSTRAP_IPS` const table + `probe::blackout_probe` glue.
- Server-side authoritative responder for the DNS tunnel.

Test status: 171 core tests green, including new coverage for the ladder
evolution, DoT endpoint safety, blackout heuristics, base32 roundtrip, and
large-payload chunking.
