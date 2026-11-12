# Blackout DNS-Tunnel Survival — Engineering Plan (Iran)

**Status:** implemented → production-hardening. The client half is complete
(`dnstunnel.rs`: QNAME clamping ≤101 + `send_receive`; `resolve_pool.rs`:
domestic-resolver pool + discovery scanner + raw-UDP transport; wired into
`connectivity.rs` via the profile's `resolver_pool` and the GUI/CLI). The
server half ships as turnkey provisioning (`scripts/dns-tunnel-server-setup.sh`,
`scripts/build-dnstt-server.sh`) for any free VPS. This document remains the
authoritative "how we survive a total intranet lockdown" design reference.

---

## 0. Why this matters

During a nationwide internet blackout in Iran — when the Telecommunication
Infrastructure Company (TIC) cuts global transit and forces networks onto the
**National Information Network (NIN / Intranet)** — almost all conventional
protocols are blocked:

- WireGuard, OpenVPN, Shadowsocks, VLESS/REALITY, direct DoH/DoT.

Direct outbound connections on port 53 to foreign servers (like `8.8.8.8`) are
dropped or hijacked. **However, DNS tunneling can still work** if *domestic
recursive resolvers inside Iran* (run by local ISPs or domestic data centers)
are permitted to query authoritative nameservers outside the country for
lookups. The client never talks directly to a foreign IP — it talks to a
domestic resolver, which does the cross-border recursion for it.

---

## 1. Best free & open-source tools (current state of the art)

Traditional DNS tunnel tools (`iodine`, `dnscat2`) perform poorly under Iranian
DPI: high packet overhead, no modern encryption, and easily fingerprinted query
formats. Three modern open-source solutions are engineered for this
environment:

### 1.1 MasterDnsVPN (best overall performance for Iran)
- Built specifically for Iranian blackout conditions.
- **Protocol overhead** only ~5–7 bytes vs ~59 bytes in DNSTT → ~88% higher
  payload efficiency.
- **Multipath & ARQ**: custom low-overhead retransmission for high-loss
  networks; natively distributes queries across many domestic resolvers at once
  to dodge per-IP rate limiting.
- Sustained browsing + messaging throughput.

### 1.2 Slipstream / Slipstream-Rust (runner-up)
- Encapsulates **Multipath QUIC over DNS**.
- Adaptive congestion control, connection migration, automatic distribution
  across rate-limited resolvers.
- Slightly higher crypto/framing overhead than MasterDnsVPN under aggressive
  MTU limits.

### 1.3 VayDNS / DNSTT (solid fallback)
- DNSTT (David Fifield): KCP-over-DNS with Noise encryption.
- **VayDNS**: optimized fork of DNSTT for the Iranian network, addressing
  resolver-drop behaviors.

---

## 2. Architecture in a blackout

```
[ Client in Iran ]
       │  (Plaintext DNS query to short subdomain)
       ▼
[ Domestic ISP Recursive Resolver (Irancell / MCI / Shatel / …) ]
       │  (ISP resolver does standard recursive lookup across borders)
       ▼
[ Your Foreign Authoritative Server (MasterDns / Slipstream Server) ]
       │  (Decodes data & forwards traffic)
       ▼
[ SOCKS5 Proxy / Open Internet ]
```

---

## 3. Step-by-step implementation

### Step 1 — DNS & domain setup (critical)
DPI drops queries with long QNAMEs. Use the shortest domain possible.

1. Acquire a **short domain** (e.g. `xyz.io`, or a free/cheap 3–4 letter
   domain).
2. In the registrar's DNS manager (Cloudflare, Namecheap) add two records:
   - **A (glue) record**: name `a` (or `ns1`) → `<Foreign_VPS_IP>`,
     *proxy disabled / DNS-only (grey cloud)*.
   - **NS (delegation) record**: name `t` → `a.yourdomain.com`.
   > The glue record name (`a`) must **not** be a subdomain of the tunnel
   > delegation domain (`t`).

### Step 2 — Server-side deployment (outside Iran)
Deploy on a VPS outside Iran (Germany / Netherlands / Finland).

#### Option A: MasterDnsVPN
```
sudo ./MasterDnsVPN_Server \
  -domain t.yourdomain.com \
  -key YOUR_32_CHAR_SECRET_KEY \
  -listen 0.0.0.0:53 \
  -target 127.0.0.1:1080
```
Then run a lightweight SOCKS5 backend (Dante / sing-box) on `127.0.0.1:1080`
to egress decrypted traffic.

#### Option B: Slipstream
```
./slipstream-server --domain t.yourdomain.com --listen-port 53 \
  --target 127.0.0.1:1080
```

### Step 3 — Resolver discovery (the key to success)
**Do not** configure the client to query your VPS IP or `8.8.8.8` directly —
both fail during an intranet lockdown. The client must send queries to
**working domestic recursive resolvers**.

- Use scanner utilities: KevinNet DNS, PYDNS-Scanner, or the built-in scanner
  in SlipNet Android.
- Scan domestic ISP IP blocks (MCI, Irancell, Shatel, Mokhaberat, Asratec,
  Pars Online, Respina) for open port-53 resolvers that successfully resolve
  external NS records.
- Keep a pool of **50–150 working domestic resolvers**.

### Step 4 — Client configuration & DPI-evasion tuning
Desktop / mobile:
- **Android:** MasterDnsVPN Android client (RevocGG / Hidden-Node), or
  SlipNet.
- **Desktop:** KevinNet DNS or the CLI client.

Tuning parameters:
1. **Max QNAME length** `--max-qname-len` ≤ `101` (limit ~110). Iranian
   filtering hardware drops queries over ~110 chars.
2. **Multi-resolver load balancing**: pass the 50–100 resolver list; client
   round-robins to avoid per-IP query-rate alarms.
3. **Record type**: request TXT (or NULL if supported) for downstream.
4. **Retransmission / duplication**: under packet loss enable ARQ or duplicate
   ~1.2× to keep TCP alive over lossy radio.

---

## 4. How this maps to DastYab

DastYab already ships the **client** half of the tunnel (`dnstunnel.rs`) and
now a **native authoritative server** (`dnstt_server.rs`) plus the
`multilayer` panel that lets a user:
- configure a **final server** (their own VPS / VLESS egress),
- choose how the tunnel is applied (**device / Chrome / local SOCKS5 proxy**),
- probe **AI Studio + Gemini** reachability through the chain.

The remaining production work in this roadmap:

**Implemented in this revision:**
- **Domestic-resolver discovery scanner** — `resolve_pool::discover_open_resolvers`
  (parallel UDP 53 probe over Iranian ISP seed candidates) + CLI subcommand
  `dastyab dns-tunnel resolvers` and the GUI resolver-pool field. Persists the
  pool into the profile's `resolver_pool`.
- **QNAME-length clamping (≤101)** — `TunnelFrame::encode_name_clamped`; used by
  `send_receive` and the liveness probe so every query stays under Iranian DPI
  filter hardware limits.
- **Resolver round-robin** — `resolve_pool::ResolverPool` fans queries across the
  domestic pool to dodge per-IP rate limits and poisoned resolvers.
- **SOCKS5 egress backend** — Dante backend included in
  `scripts/dns-tunnel-server-setup.sh` (127.0.0.1:1080) so decrypted traffic can
  leave the VPS; the native `dnstt-server` authoritative responder is installed
  as a systemd service.
- **DNS tunnel as a first-class ladder tier** — already wired (Tier::DnsTunnel);
  the liveness probe now recurses through the domestic pool when configured.

**Still open:**
- Domain delegation (done manually on Cloudflare/registrar — see §6).
- Optional: full-TCP egress (working) beyond the control/status frames our native
  protocol carries (use MasterDnsVPN/KevinNet pointed at the same VPS for that).

---

## 5. Summary of practical expectations

- DNS tunneling is bandwidth-constrained: **150 Kbps–2 Mbps** (MasterDnsVPN
  at the high end). Built for Telegram/Signal text, basic web, emergency
  messaging — not 4K video.
- **Prepare infrastructure in advance.** Once a blackout hits you cannot
  register domains, buy VPSes, or download APKs. Distribute APKs, configs, and
  resolver lists beforehand.

---

## 6. Domain selection strategy (critical — do NOT use a .ir domain)

This section is the operational decision guide for the tunnel domain. It is
kept here because the domain choice determines real-world survivability.

### 6.1 Why a .ir domain is a dangerous idea

Technically, delegating an NS record from a `.ir` zone to an external foreign
VPS is possible. Practically and legally it is a serious risk:

- **Real-identity KYC.** Every `.ir` domain is registered via IRNIC and is
  strictly bound to the registrant's National ID (کد ملی), Iranian mobile number,
  and home address. DNS tunneling is noisy — tens of thousands of repetitive,
  high-frequency, high-entropy Base32/Base64 queries. Passive DNS monitoring by
  TIC and the Cyber Police (FATA) flags this pattern. If the tunnel domain is
  flagged, the registry can be queried in seconds and the traffic is associated
  with the registrant's real identity, and the domain seized.
- **IRNIC bureaucracy.** IRNIC processes nameserver/DNS changes in slow batch
  cycles (12–24 h, business hours only). If the VPS IP is blocked mid-crisis,
  glue records cannot be swapped dynamically — lockout for a full day.
- **NIN policy filtering.** During blackouts, `.ir` zones delegating to foreign
  IPs are frequently flagged, null-routed, or dropped by domestic resolvers.

**Verdict: never use a .ir domain for the tunnel.**

### 6.2 What kind of domain you need

Two hard rules:

1. **As short as possible.** Payload lives in the subdomain label:
   `[data].[session].t.yourdomain.com`. Iranian DPI drops QNAMEs longer than
   ~101–110 chars. A 32-char domain wastes 32 bytes of every packet; a 6–8-char
   domain (`x9.top`, `9281.xyz`) maximises payload room and reduces fragmentation.
2. **Full control over NS delegation + glue records.** The DNS provider must
   permit an A (glue) record pointing to the VPS IP and an NS record pointing a
   subdomain (e.g. `t`) to that glue hostname.

### 6.3 Free options

- **GitHub Student Developer Pack** (best free path): free `.me` domain for 1
  year via Namecheap + a free domain from Name.com; pair with Cloudflare.
- **Free subdomains supporting NS delegation:** DNSExit (under `publicvm.com`,
  `linkpc.net`); `nic.eu.org` (free `.eu.org` subdomains, full delegation, but
  slow manual approval). Caveat: subdomains are long (e.g. `myvpn.publicvm.com`
  = 18 chars), cutting throughput.

### 6.4 The "near-free" recommended option: short numeric .xyz

The gold standard in the Iranian circumvention community is the **1.111B Class
of .xyz** — 6–9-digit numeric `.xyz` domains are $0.99 to register and $0.99/yr
to renew indefinitely (e.g. `582910.xyz`, `830192.xyz`).

- Cost ~$0.99/yr (~60–90k Tomans); length 10 chars; renewal never jumps; full
  delegation control; works seamlessly with Cloudflare.
- **Buying from inside Iran without an international card:**
  - Crypto (direct + anonymous): Porkbun / Namecheap / Njalla accept USDT
    (TRC-20), LTC, or BTC. Buy ~$2 of crypto on domestic exchanges (Nobitex,
    Wallex) and transfer.
  - Local middlemen: Iranicard, TehranPayment, or hosting resellers order foreign
    domains for <$1.50 equivalent via Shetab cards.

### 6.5 Final setup on Cloudflare

1. Change the registrar's nameservers to Cloudflare (free tier).
2. Add the tunnel records:
   - **A record:** name `a` → `<Foreign_VPS_IP>`, Proxy = **DNS only / grey
     cloud** (Cloudflare CDN must be disabled — it blocks non-standard port-53
     tunnel traffic).
   - **NS record:** name `t` → `a.<yourdomain>`.
3. Client config: tunnel domain = `t.<yourdomain>`. For the native DastYab
   client: `host=<VPS_IP> base_domain=t.<yourdomain> session=<key>` plus the
   domestic resolver pool (scan with `dastyab dns-tunnel resolvers`).

> **Security/safety note:** the native DastYab framing base32-*encodes*
> payloads for safe DNS labels; it does **not** encrypt them. The session key
> is a server-side access gate (allow-list), not a cipher. For high-sensitivity
> data over a DNS tunnel, layer your own encryption on top of the payload (or
> use MasterDnsVPN/KevinNet, which do encrypt). Treat DNS-tunnel traffic as
> readable by passive DPI.

