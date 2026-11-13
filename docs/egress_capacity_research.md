# DastYab Egress/Relay Capacity Research — Consolidated Decision Memo

**Prepared:** 2026-11-13 · **Status:** research synthesis (live verification pending on flagged items)

This memo consolidates three parallel research passes into one actionable plan:
1. Always-free cloud VPS/VM offers (raw egress compute)
2. Usability **from Iran** (DPI/IP-burn, signup, payment, phone)
3. Free non-VPS relay/anchor/control infrastructure

---

## Bottom-line verdict

- **Best primary egress anchor = Oracle Cloud Always Free (Ampere ARM A1).** Permanent, best free
  specs, real public IPv4, ~10 TB/mo egress. Region for Iran latency: **UAE (Dubai)** or
  **Frankfurt**. Cost: a foreign card + real foreign SIM + stable foreign signup exit.
- **No mainstream provider offers always-free raw VM without a credit card.** The no-card niche
  (Serv00) is experiment-only, never load-bearing.
- **No VPS is required for the control/relay plane:** Cloudflare Workers + your own domain is the
  primary WS/L7 bridge, Deno Deploy is the independent second operator, DNS (deSEC/HE/DuckDNS)
  is the always-up anchor channel, GitHub Actions is the free cron/aggregator.
- **Raw-TCP free egress without a VM** effectively resolves to Fly.io's 3×256MB free instances
  (the nearest thing to a free VM) — treat as fallback.

---

## Part A — Free VM offers (raw egress compute)

| Provider | Spec | Permanent? | Card | SMS | Best region for IR |
|---|---|---|---|---|---|
| **Oracle Always Free** | ARM A1 4 OCPU/24GB (up to 4 inst) + 2×AMD micro (⅛ OCPU/1GB); 200GB block; ~10TB/mo out [VERIFY] | ✅ permanent | usually yes [VERIFY] | yes | Dubai / Frankfurt (no TR region) |
| **GCP e2-micro** | 2 vCPU/1GB/30GB; 1GB/mo egress | ✅ permanent | yes | yes | US-only free (us-west/central/east1) → higher latency |
| Azure B1s | 1 vCPU/1GB/64GB | ❌ 12-mo trial | yes | yes (strictest) | — |
| AWS t2/t3.micro | 750h/mo EC2 | ❌ 12-mo trial | yes | yes | — |
| Alibaba Intl free trial | trial-based (7d–3mo) | ❌ trial | foreign VISA/MC or Alipay | yes + passport | Singapore / Frankfurt |
| IBM Cloud Lite | no VSI anymore | ❌ no raw compute | n/a | — | — |
| Serv00 | shell/VPS-like, SSH, no card | ⚠️ community/unstable | **no card** | — | experiment only |

**No-card always-free: only Serv00 (niche/unstable).**

---

## Part B — Usability from Iran

- **Mechanism:** Iran does not null-route whole cloud ASNs; it uses DPI + reactive IP
  blacklisting. A **fresh, unused public IPv4** connects fine at first and gets burned by use.
  Win strategy = **fresh IP + VLESS/Reality or xtls-rprx-vision + Cloudflare-fronting** so the
  origin IP is never exposed.
- **Oracle:** best egress reachability; signup works via a **stable** foreign SOCKS5 exit, but
  all metadata (address/card/phone/exit-IP country) must match; one account per exit; never
  switch IP mid-flow. Shetab cards accepted nowhere.
- **GCP:** usable but US-region latency + more IP burn.
- **Azure:** most aggressive anti-fraud phone gate; time-limited; not recommended.
- **AWS:** Iran-origin accounts routinely rejected/suspended; IP space heavily flagged; skip.
- **Alibaba:** viable secondary (trial-limited), less-flagged egress.
- **DigitalOcean/Hetzner:** not free; Hetzner rejects many Iran/flagged users.
- **Cross-cutting rules:** one stable foreign exit IP for whole signup; match
  address=card=phone=exit-IP country; fresh IP per account; all clouds reject VoIP numbers —
  budget a real foreign SIM.

---

## Part C — Free non-VPS relay/anchor/control

| Service | Free tier | Relays raw TCP? | Works from Iran? |
|---|---|---|---|
| Cloudflare Workers | 100k req/day; WS-supported (verify plan gate) | L7 WS only | yes via **own domain** (`.workers.dev` blocked) |
| Cloudflare Pages / Turnstile / Zero Trust | unlimited static / free tokens / free tunnels | tunnel TCP but needs `cloudflared` host | partial |
| Cloudflare DNS | free authoritative | n/a | use DoH/DoT |
| GitHub Actions | public repos unlimited minutes | outbound only (aggregator/cron) | intermittent |
| deSEC / HE / DuckDNS | free DNS | n/a | reliable anchor channel |
| Tor / Onion | free | yes (via bridges obfs4/meek/snowflake) | blocked w/o bridges; control channel |
| Cloudflare WARP (wgcf) | free | yes (own egress only) | unreliable, ToS restricts reselling |
| ngrok / localhost.run | free limited | yes | domains blocked/unstable |
| Deno Deploy | ~1M req/mo, WS accept | L7 WS only | reachable (custom domain) |
| Vercel / Netlify | free | ❌ no persistent WS | reachable, unsuitable |
| Fly.io | 3× shared-cpu-1x 256MB | ✅ real TCP/UDP | not broadly blocked; card signup |

---

## Recommended redundant stack

1. **Oracle Always Free primary egress** (Dubai/Frankfurt) — VLESS/Reality, CF-fronted.
2. **GCP e2-micro backup** OR **Alibaba trial** fallback anchor.
3. **Cloudflare Workers + own domain** — primary WS/L7 bridge + config beacon (KV).
4. **Deno Deploy** — independent second WS operator.
5. **deSEC/HE/DuckDNS** — endpoint-rotation coordination (A/AAAA/TXT via DoH/DoT).
6. **GitHub Actions** — cron harvest/validate/publish fresh configs.
7. **Fly.io** — raw-TCP free fallback if a VM is acceptable.
8. **Tor/.onion + WARP** — last-resort control channel.

---

## Live-verification checklist (before deploying)

- [ ] Oracle: exact card requirement + current free egress quota + UAE/Frankfurt ARM A1 availability
- [ ] GCP: current e2-micro free region list + egress allowance
- [ ] Workers WebSocket availability on the current free plan + daily request quota
- [ ] Deno Deploy current monthly request quota
- [ ] Fly.io free-tier signup card requirement + auto-sleep behavior
- [ ] Live DPI probe from the target ISP against fresh shortlisted IPs (Oracle Jeddah/Dubai,
      Alibaba Singapore/Frankfurt) over TCP 443 with the sing-box/Reality client
