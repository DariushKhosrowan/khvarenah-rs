# DastYab DNS-Tunnel — User Guide

This guide explains **what** the DNS tunnel is, **when** it activates, and the
exact steps to set it up so you still have a slow-but-working internet channel
even if the Iranian government cuts the border completely (the "blackout" /
NIN intranet scenario).

---

## 1. What is going on (the short version)

DastYab has a **fallback ladder**. In normal times it uses the fastest path:

```
Direct (clean IP) → DoH (DNS over HTTPS) → DoT (DNS over TLS) → DNS tunnel
```

When higher tiers fail, the app automatically descends to the DNS tunnel. A DNS
tunnel hides your internet traffic inside ordinary DNS queries. It is **slow**
(roughly 150 Kbps up to ~2 Mbps) — fine for messaging, email, text, and light
web; not for video. Crucially, it works even when the border is cut because it
rides on **domestic Iranian ISP resolvers**, which the government must keep
alive or its own network breaks.

```
[ your laptop ] → [ Iranian ISP resolver ] → [ your foreign VPS (authoritative) ]
                    (local, allowed)          (decodes + egresses to internet)
```

## 2. What you need (prepare BEFORE a lockdown)

| Item | Why | Recommendation |
|------|-----|----------------|
| **A free VPS outside Iran** | hosts the tunnel server (listens on UDP 53) | Oracle Cloud "Always Free", Alibaba free tier, GCP free tier, or any VPS you already have. |
| **A short international domain** | the tunnel queries hide under it | a 6–9-digit numeric `.xyz` (~$0.99/yr). **Never use a `.ir` domain** — it is tied to your national ID (see §6). |
| **Cloudflare (free)** | fast DNS delegation (A glue + NS) | or any registrar that allows NS delegation. |
| **Domestic resolver pool** | the blackout path | scan Iranian ISP resolvers with `dastyab dns-tunnel resolvers`. |

> A VPS **inside Iran won't help** — during a blackout the Iranian data-center
> routes die too. The server must be **outside** Iran.

---

## 3. Step-by-step setup

### Step 1 — Get the free VPS

Sign up for a free-tier cloud provider (Oracle Always Free is the best: 2 AMD
Micro VMs or 1 Ampere ARM VM with 4 OCPUs, 10 TB/month egress, a permanent
public IPv4, and UDP 53 open). You will need a debit/credit card for identity
verification (a refundable hold, $0 charged if you stay in the free tier).

Once the instance is up, note its **public IP** and your SSH access.

### Step 2 — Register the short international domain

Buy a numeric `.xyz` (e.g. `928104.xyz`) from Porkbun / Namecheap (crypto
acceptable) or via an Iranian reseller. Keep it short — the domain length is
subtracted from every packet's payload space.

### Step 3 — Point the domain at Cloudflare

1. In your registrar, change the domain's nameservers to Cloudflare's (free
   tier) so DNS changes propagate in seconds.
2. In Cloudflare, add **two records** for your tunnel subdomain:
   - **A record:** name `a` → `<your VPS public IP>`, Proxy = **DNS only /**
     grey cloud** (NOT proxied — Cloudflare's CDN blocks port-53 tunnel traffic).
   - **NS record:** name `t` → `a.928104.xyz`.

### Step 4 — Install the tunnel server on the VPS

Build the server binary and copy it to the VPS:

```bash
# on your machine, in the dastyab repo:
./scripts/build-dnstt-server.sh                  # → dist/dnstt-server-x86_64-unknown-linux-gnu
scp dist/dnstt-server-x86_64-unknown-linux-gnu ubuntu@<VPS_IP>:/tmp/
# (for ARM/Ampere Oracle instances, use: ./scripts/build-dnstt-server.sh aarch64-unknown-linux-gnu)
```

Then on the VPS (as root):

```bash
sudo DNSTT_BIN=/tmp/dnstt-server \
     TUNNEL_DOMAIN=t.928104.xyz \
     ./dns-tunnel-server-setup.sh
```

The script frees port 53, opens the firewall (including Oracle's iptables),
installs the `dnstt-server` systemd service, sets up a SOCKS5 egress backend,
and prints your **session key** and the final client settings. Keep the key
safe — it's the access gate to your tunnel.

### Step 5 — Configure your laptop client

In the DastYab GUI (Blackout resilience panel) set:

- **VPS host (IP):** `<VPS_IP>`
- **Base DNS domain:** `t.928104.xyz`
- **SSH user / key / port:** as used to reach the VPS (for deploy)
- **Resolver pool:** comma-separated list of domestic ISP resolver IPs (leave
  empty to query the VPS directly — but for blackout survival you want the pool).

Or, from the CLI:

```bash
dastyab dns-tunnel deploy --host <VPS_IP> --ssh-user ubuntu --ssh-key ~/.ssh/id_ed25519 --domain t.928104.xyz
dastyab dns-tunnel resolvers            # scan + persist the domestic resolver pool
dastyab dns-tunnel status               # confirm it's configured
```

### Step 6 — Verify

`dastyab dns-tunnel status` should report the tunnel configured. The **
back ladder will automatically use it when Direct/DoH/DoT fail. To test the
tunnel path specifically, trigger the blackout drill (GUI "Blackout drill" or
`dastyab drill`).

---

## 4. What each piece does

- **`dnstt-server`** — the authoritative DNS responder on your VPS. It receives
  tunnel queries (forwarded to it by the domestic resolver), decodes them, and
  answers. The native client uses it for control/status/bootstrap messaging.
- **Dante SOCKS5 backend** — sits on the VPS at `127.0.0.1:1080`; if you point
  a full-tunnel client (MasterDnsVPN / KevinNet) at the same VPS, decrypted
  traffic egresses through it.
- **Domestic resolver pool** — the list of Iranian ISP resolvers your client
  sends the tunnel queries *through*. This is what makes the tunnel survive a
  total border cut (your client never talks to a foreign IP directly; the ISP
  resolver does the cross-border recursion for you).
- **QNAME clamping ≤101** — every query is cut to ≤101 characters so Iranian DPI
  filter hardware doesn't drop it.

---

## 5. Realistic expectations & limitations

- **Speed:** ~150 Kbps – 2 Mbps. Text, messaging (Telegram/Signal), email, and
  light web browsing; not 4K video or large downloads.
- **It is a rescue channel, not your daily driver.** The ladder climbs back to
  the fast tiers the moment they recover.
- **Build it before the crisis.** You cannot register domains, provision VPSes,
  or scan resolvers during a blackout. Do all of this now, and keep your configs
  and the APK/binary on a flash drive or phone.

---

## 6. Safety notes (read this)

- **Never use a `.ir` domain for the tunnel.** It is registered to your real
  identity (National ID / phone / address) and the noisy, repetitive tunnel
  traffic can be tied back to you by IRNIC / TIC / FATA. Use a short,
  anonymised international domain instead.
- The native DastYab tunnel framing base32-**encodes** payloads but does
  **not encrypt** them. For sensitive data, add your own encryption on top (or
  use MasterDnsVPN/KevinNet, which encrypt).
- DNS tunnelling of this kind is a protected-circumvention technique. Use it in
  line with your local laws and your own risk assessment.

---

## Quick command reference

```text
dastyab dns-tunnel deploy ...        # deploy server to your VPS (SSH)
dastyab dns-tunnel resolvers          # scan + save domestic resolver pool
dastyab dns-tunnel status             # show current tunnel config
dastyab dns-tunnel test --host ...    # TCP-reachability check of the VPS
dastyab drill                          # walk the full fallback ladder
```
