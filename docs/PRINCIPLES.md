# DastYab Principles — Mission, Threat Model & Engineering Doctrine

This document is the **constitution** of the DastYab project. It codifies the
mission, threat model, resilience ladder, and engineering standards that every
subsystem must serve. When a design decision is contested, it is resolved by
these principles. When a new feature is proposed, it is accepted only if it
advances them.

> **One-line mission.** DastYab must be a **perfect, flawless, self-healing
> circumvention client** — an autonomous connecting tool that still works in a
> **total internet blackout in Iran**, when every ordinary TCP/UDP path to the
> outside world has been severed.

---

## 1. Project identity & mission

DastYab is an **autonomous, ultra-resilient circumvention client** written in
pure Rust. Its primary environment is the **Iranian National Information
Network (NIN / "Halal Internet")** during a state-level nationwide blackout
orchestrated by the Telecommunication Infrastructure Company (TIC).

DastYab must function as a **zero-configuration, self-healing network
daemon**. It must:

- dynamically discover paths,
- race connection vectors in parallel,
- handle network multi-homing,
- tunnel traffic outward even when all standard TCP/UDP transit to
  international IPs is severed,
- fall back to **domestic multipath DNS tunneling** and
  **intranet mesh bridging** as last resorts.

The bar is never "good enough." The bar is **continuous self-preservation**:
if a path exists for traffic to leave through, DastYab should find it,
secure it, and keep it alive — with no human intervention.

---

## 2. Threat model & network conditions (Iran)

Design must assume the following operational realities:

1. **Intranet isolation (NIN mode).** All direct foreign BGP routes are
   severed for residential users. Outbound TCP SYN and UDP packets to foreign
   IPs are dropped with no response, or spoofed with fake TCP RSTs.
2. **Selective recursive DNS transit.** Client→foreign DNS is blocked, but
   domestic recursive resolvers (MCI, Irancell, Shatel, Mokhaberat, Respina,
   Asratec) often retain internal recursive peering to resolve foreign
   authoritative nameservers. This is the DNS tunnel's transport.
3. **DPI hardware quirks & limits.**
   - **QNAME length threshold:** DPI boxes drop DNS queries whose total QNAME
     exceeds ~101–110 bytes (well under the RFC 253 limit). We clamp to **101**.
   - **Protocol fingerprinting:** non-standard TLS handshakes (unpadded TLS,
     non-browser JA3/JA4 fingerprints) are dropped. We must mimic verified
     browser fingerprints.
   - **Silent blackholing:** firewalls often send no TCP RST; they silently
     drop after the handshake → half-open socket stalls.
   - **Resolver rate-limiting:** domestic resolvers throttle/null-route an
     authoritative domain above ~5–10 QPS from one source → we must stripe
     across many resolvers.
   - **DNS poisoning:** spoofed responses inject domestic IP sinks (e.g.
     `10.10.34.34`).
4. **Interface instability.** LTE/5G connections frequently switch cells, flap
   interfaces, and change local IPs.

---

## 3. The resilience ladder — never stop trying

DastYab must never stop trying. It executes an asynchronous, prioritized
**Parallel Racing Engine** (Happy Eyeballs on steroids). The ladder is:

### Level 1 — Stealth foreign egress (timeout 1.5s)
- **VLESS-XTLS / REALITY:** mimicking popular domestic whitelisted foreign
  domains with verified uTLS browser fingerprints (Chrome/Firefox).
- **Shadowsocks-2022 with AEAD:** direct egress with length-padding
  obfuscation.

### Level 2 — Pluggable transports & domestic relays (timeout 3.0s)
- **Tor via WebTunnel / Snowflake** (embedded via `arti-client`).
- **Shir-o-Khorshid architecture:** tunneling over intermediate domestic
  datacenter proxies running forward-proxy pipelines (Rathole / GOST / smux
  over TLS) on Iranian VPS.

### Level 3 — Native multipath DNS tunneling (the blackout workhorse)
- **Multipath query balancing:** traffic striped / round-robined across a
  dynamic pool of 50–150 discovered domestic ISP recursive resolvers.
- **Protocol overhead:** maximum 5–7 bytes framing overhead per packet. No heavy
  protocols (raw KCP-over-DNS is disallowed).
- **Low-overhead ARQ:** a selective-repeat windowed Automatic Repeat reQuest
  engine to handle severe UDP loss.
- **QNAME chunking:** hard cap of **101 bytes**; payloads Base32/Base64URL
  without padding.
- **Record types:** TXT and NULL queries; EDNS0 buffer negotiation so responses
  stay below **1232 bytes** (no IP-level fragmentation).

### Level 4 — Intranet P2P relay / mesh
- Search local LAN (mDNS / raw UDP broadcast) for other running DastYab
  instances with an active upstream uplink → local hop forwarding.

---

## 4. Critical failure modes the code must solve

### A. TUN device routing loop (deadlock)
If DastYab's TUN captures its own outbound DNS queries / proxy connections,
the stack recursively loops and freezes.

- **Linux:** mark DastYab socket packets via `SO_MARK` (e.g. `0x2a`) and
  write policy routes (`ip rule add fwmark 0x2a lookup main`).
- **Windows:** explicit destination routes bypassing the WinTUN adapter for
  ISP gateway IPs.
- **Android:** `VpnService.protect(socket)`.

### B. DNS poisoning & bogus record injection
Bogus `10.10.34.34` / fake NXDOMAIN answers must never be trusted. **All**
DNS-tunnel responses must be cryptographically authenticated (ChaCha20-Poly1305
or a Noise handshake); a failing response immediately penalizes that resolver
in the health table.

### C. Half-open TCP socket hangs
Silent drops leave sockets ESTABLISHED for minutes. A proactive **Liveness
Sentinel** must observe that an active route sees zero inbound bytes for ~4s
during outbound transmission and trigger a soft-break onto another path.

### D. MTU blackholing & IP fragmentation
PMTUD fails because ICMP Type 3 Code 4 is filtered. We clamp TCP MSS on the
TUN (≤1200 for the DNS tunnel) and never let a DNS response exceed 1232 bytes.

### E. Network interface flapping (Wi-Fi ↔ cellular)
On a netlink/OS network-change event: flush the resolver cache, background-probe
the new interface, and migrate the TUN session without restarting it.

---

## 5. Zero-config & autonomy doctrine

A user under a blackout cannot fiddle with configs. Therefore:

- **Everything is auto-discovered:** resolvers, relays, upstream tunnels,
  mesh neighbors.
- **Self-healing is a first-class loop**, not a post-hoc repair: the daemon
  continuously probes, races, and degrades/re-upgrades tiers.
- **Fails last, never first:** a tier is only abandoned after its timeout and
  its liveness sentinel both fire.
- **Bootstrapping must not be circular.** Wholly hardcoded foreign IPs fail
  the moment they are blocked. The client must keep a *rotating, verified*
  set of egress anchors and be able to re-discover them out-of-band (e.g.
  via the domestic-resolver pool, a pre-distributed config, or P2P mesh
  peers) before any direct path is attempted.
- **Traffic must look like traffic.** DNS tunnels with uniformly high-entropy
  QNAMEs are trivially ML-flagged. Queries must be paced, padded, and mixed
  with benign lookups so their statistical profile matches ordinary DNS.

---

## 6. Engineering standards

Because this tool is used under state pressure, quality is a survival property:

1. **Pure Rust, safe, production-grade.** No `unwrap()` in library code paths;
   idiomatic `thiserror`/`anyhow`; explicit zero-copy optimizations.
2. **Auditable.** Clear module boundaries, documented wire formats, and tests
   that pin every protocol assumption.
3. **The "no-bugs" standard is an engineering discipline, not a promise.**
   Perfection is the target we engineer toward — through type safety,
   exhaustive tests, fuzzing of the codecs, adversarial loss/reorder/dup
   simulations, and CI gates (`cargo clippy --workspace` warning-free,
   `cargo test --workspace` green, `cargo fmt`). Bugs will still surface in
   the field; the doctrine is that the system must **absorb** them — never
   freeze, never silently succeed on poisoned data, always degrade one rung
   and keep going.
4. **No fabricated success.** Probes must verify real end-to-end reachability
   and never report false confidence.

---

## 7. Current status vs the doctrine

Implemented and committed (see `ROADMAP.md`):

- Resilience ladder tiers (`connectivity.rs`), blackout state machine
  (`blackout.rs`, `daemon/blackout.rs`), network state detection.
- DNS-tunnel client: QNAME clamping ≤101, base32 label codec, TXT framing,
  resolver-pool discovery + round-robin (`dnstunnel.rs`, `resolve_pool.rs`).
- Native authoritative DNS-tunnel server + free-VPS provisioning scripts
  (`dnstt_server.rs`, `scripts/dns-tunnel-server-setup.sh`).
- **Selective-repeat windowed ARQ engine** (`arq.rs`) — sequence numbers,
  sender in-flight window, receiver reorder buffer, cumulative + SACK
  bitmap, timeout-driven selective retransmission; tested against simulated
  loss/reorder/duplication and 16-bit wrap-around (Level 3).
- AI Studio / Gemini reachability bridge (`dastyab aistudio`) and DeepSeek
  bridge loop for autonomous dev. The Gemini API (via the AI Studio tunnel) is
  used for design review and hard decisions.
- **Authenticated DNS-tunnel responses** (doctrine B) — ChaCha20-Poly1305
  `seal`/`open` with a session-tagged key; server seals replies, client verifies
  and penalizes poisoned/forged responses (`dnstunnel_auth.rs`).
- **Liveness sentinel** (doctrine C) — half-open stall detection (transmitting
  but zero inbound), debounced `Stalled` verdicts, integrated into the racing
  engine so a confirmed stall force-verifies/descends (`liveness_sentinel.rs`).
- **Interface-flap handling** (doctrine E) — sysfs carrier/operstate monitor +
  debounced flap detector, ready for netlink driver swap (`interface_monitor.rs`).
- **TUN anti-loop routing** (doctrine A) — fwmark anti-loop rule plan generator,
  idempotent against live rules (`tun_route.rs`).
- **MTU/MSS clamping** (doctrine D) — adaptive and fixed TCP MSS-clamp rule
  plan generator (`tun_mtu.rs`).
- **Platform execution** (doctrine A/D) — `platform_linux.rs` applies the plans
  via `ip`/`iptables` with a **dry-run** mode for CI, RAII TUN teardown, and
  a `dastyab platform {plan|apply|teardown}` CLI command. Builds run on
  GitHub Actions runners (not the local laptop) — see `.github/workflows/`.

Remaining gaps tracked as open work (see `ROADMAP.md` → **Doctrine gaps**):

- [ ] **P2P LAN mesh** — mDNS neighbor discovery + relay (Level 4).
