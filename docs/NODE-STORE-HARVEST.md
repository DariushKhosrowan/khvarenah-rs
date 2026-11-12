# Node Store & Telegram Harvest

Native, on-disk storage of inbound VLESS nodes plus a browser-free Telegram
config harvester. Both were built to make DastYab **autonomous and cheap**
— you never need an always-warm browser just to collect configs.

## Why this exists

Before, learning a new server meant either:

- hand-pasting a `vless://` link into a config file, or
- keeping an entire Telegram **web app** open in Chromium (~40% CPU) to read
  channels that post free configs.

The config store + harvest replace the second entirely:

- The **store** gives one command to import everything from your existing
  v2rayN `ServersStore.json`, plus paste/list/activate/clear.
- The **harvester** talks to Telegram's public preview endpoint
  (`https://t.me/s/<channel>`) with a single HTTP GET — no Chromium, no
  MTProto, no login, near-zero CPU.

## The config store

Per-profile JSON file (`<profile>/nodes.json`) of VLESS nodes.

| Source | Command |
| --- | --- |
| v2rayN ServersStore.json | `dastyab nodes import --path ~/.config/v2rayN/Local/ServersStore.json` |
| paste one link | `dastyab nodes paste --link 'vless://...'` |
| Telegram (browser-free) | `dastyab harvest --channels v2ray_config` |
| export healthy nodes → v2rayN | `dastyab nodes export-v2rayn --path ~/.config/v2rayN/Local/ServersStore.json` |

Management:

| Action | Command |
| --- | --- |
| list (with active marker) | `dastyab nodes list` |
| activate a node | `dastyab nodes activate --link <node-id-or-url>` |
| clear all | `dastyab nodes clear` |

## Autonomous refill — "never run out of working configs"

The ultimate point of the store is that DastYab **never sits dead** when the
current config stops working. The `node_refill` orchestrator makes that real:
- **Pure trigger** (`refill_needed`): the pool is empty, or no node is known
  healthy → a refill is warranted. A pool of never-probed nodes also counts
  (we'd rather have a surplus of verified configs than rely on unverified
  ones).
- **Recovery** (`run_refill`): deep-harvests the default Telegram channel
  archives (6 pages each, so old configs are recovered) and ingests GitHub
  config repos, then probes every recovered node and promotes a verified-healthy
  one. `--proxy` routes every fetch/probe through the local xray SOCKS5 for
  NIN/blackout use.
- **Daemon integration**: the persistent daemon runs a refill pass whenever the
  network is up and the pool has no known-healthy node — rate-limited to once
  per 15 minutes so a permanently-dead pool doesn't hammer Telegram/GitHub. The
  result is logged and journaled (`NodeRefill`).
- **CLI**: run it manually with `dastyab nodes refill`.

### Feeding verified configs back into v2rayN

DastYab's store is the resilient source of truth, but you may also want the
harvested, verified-healthy configs to appear in your **v2rayN GUI** so you can
use them there (or so v2rayN stays useful if the CLI/GUI isn't around):

```
$ dastyab nodes export-v2rayn [--path ~/.config/v2rayN/Local/ServersStore.json]
[configs] exported healthy nodes to ...: added=298 duplicates-skipped=0
```

- Only **verified-healthy** nodes are written by default (the two-phase TLS
  probe decides what's healthy), so v2rayN doesn't get a pile of dead configs.
- The tool **merges** — it reads the existing `ServersStore.json`, dedups by
  the same `(host, port, uuid)` identity the store uses, and appends only new
  servers. Re-running is idempotent (`added=0 duplicates-skipped=N`).
- The write is atomic (temp file + rename), so v2rayN's file is never left
  half-written, even if v2rayN is open.

This closes the loop: harvest → probe → **export healthy → v2rayN**, so the
client GUI always mirrors the verified-live pool (doctrine §5, §6.4).

### Key design points

- **Raw links are preserved.** Every node keeps the original share-link
  string (reality `pbk`/`sid`/`fp`, tls/ws/grpc/xhttp params, ws path).
  Nothing is re-serialized, so no transport detail is ever lost.
- **Dedup by identity.** A node's identity is `(address, port, uuid)`. The
  same server pasted twice is a duplicate, not a new node. Idempotent
  re-imports report `added=0`.
- **Summary is explicit.** Every import returns found / added / duplicates /
  skipped-non-VLESS / skipped-invalid so you always know what happened.
- **The store is just the collection.** "Activate" marks the node you want
  to use; the rest of DastYab can read the active node to build a tunnel.

## The Telegram harvester

`harvest::harvest_channel(profile, channel, use_proxy)`

How it works (all in `dastyab-core/src/harvest.rs`):

1. **Fetch.** One `reqwest::blocking` GET of `https://t.me/s/<channel>`.
   Direct by default; `--proxy` routes through the local xray SOCKS5
   (`PROXY_SOCKS_PORT` = 10850) when direct is blocked.
2. **Extract.** Split the HTML on `vless://`; each tail is a link up to the
   next whitespace / `"` / `<` / `>`. Index 0 (everything before the first
   delimiter) is discarded. A tail must contain `@` (a real `uuid@host`
   core) to be accepted.
3. **Decode.** `&amp;` → `&`, and strip the trailing `#` fragment Telegram
   appends. This yields an importable `vless://` link.
4. **Import.** Each link goes through `config_store::import_single_link`, so
   dedup + raw-link preservation apply automatically.

CLI: `dastyab harvest --channels v2ray_config,vlessconfigs [--proxy]`
(default channel `v2ray_config`).

### Which channels work

Only channels that post configs as **plain text** are harvestable. Many
channels post screenshots or link-posts, which the HTML preview does not
expose as text — those are not harvestable via this path (they would need a
browser / OCR). Start with channels known to post raw `vless://` text (e.g.
`v2ray_config`), and confirm with `nodes list` that nodes actually landed.

## Efficiency numbers

| Approach | Typical CPU |
| --- | --- |
| Telegram-web Chromium kept open (~2 renderers+GPU) | ~40% |
| Native harvest (one HTTP GET per channel) | <0.5% during fetch, 0% idle |

The harvester is a *transient* process: it fetches, imports, and exits. It
holds no browser, no socket, no timer — nothing to keep warm.

## Systematic Telegram channel discovery — never hardcode the net

The refill channel list is a *starting point*, not a fixed truth. Channels
come and go; a quiet one today may broadcast a flood of configs tomorrow. `dastyab harvest --discover [--save]` probes a broad candidate set
(`DISCOVER_CANDIDATE_CHANNELS`, plus any `--channels`) and ranks them by
**live** plaintext-link yield — no import, just a quick one-page probe per
channel. With `--save`, the channels that actually yielded links are persisted
to `<profile>/harvest_channels.json`, and every future refill pass merges them
into its net. This is how autonomous recovery keeps finding new sources instead
of going stale (doctrine §5: bootstrapping never goes circular/hardcoded).

```
$ dastyab harvest --discover --save
discovering 31 candidate channel(s)…
  v2ray_configs_pools: 160 links
  MARAMBASHI: 93 links
  v2raycollector: 33 links
  …
saved 11 discovered channel(s) to profile 'default'
```

## Periodic config-health decay — keep the pool verified-live

A node being *present* says nothing about whether it *still works*. The
`node_probe::probe_stale` sweep re-probes a **bounded set** of stale (≥6h
old) or never-checked nodes — ≤64 per pass — so even a healthy pool is
continuously re-verified as upstream servers churn, without hammering the
network. The daemon runs it hourly; if the active node died since its last
check, the sweep fails over to a verified-healthy one. This is the difference
between "imported a working config" (can go stale) and "keeping a working
config at the front" (the doctrine).

## Certificate-Transparency egress-anchor discovery (doctrine §8.1)

Bootstrapping must never be circular: every recovery source should be an
*independent* out-of-band path. Telegram channels and GitHub repos are two;
the third is **certificate transparency** — the public log of every domain
that has ever issued a TLS certificate. Proxy/VPN operator hostnames
(`v2ray-*`, `vless-*`, `vpn-*`, `.workers.dev`, ...) appear there, often
before they are shared in any channel, so this source stays alive even when a
channel net goes quiet.

```
$ dastyab anchors discover [--proxy] [--queries v2ray,vless,vpn]
[anchors] CT discovery pass:
  queries   : 3
  hosts seen : 420
  candidates : 97
  verified   : 29
  anchors total: 29
    v2ray-god--tel.workers.dev   978ms via=v2ray
    ...
```

How it works (all in `dastyab-core/src/ct_anchors.rs`):

1. **Query** crt.sh (`?q=<term>&output=json`) with backoff retries (it is
   rate-limited and returns HTML 502 under load). Default terms are strong
   proxy/VPN signals (`DEFAULT_QUERIES`).
2. **Filter** CN/SAN hostnames: dedupe, drop junk suffixes, wildcards, and IP
   literals, and keep only names containing a *strong* keyword (vless,
   v2ray, vmess, trojan, shadowsocks, ss2022, proxy, vpn, tunnel, relay,
   gateway) — deliberately excluding generic words (cdn, node, server, ...)
   that would drown real anchors in noise.
3. **Probe** each candidate with a real TLS handshake through the pooled
   `reqwest` client (`https://<host>/`). Only hosts that complete TLS are
   recorded — silent-TCP blackholes and non-TLS servers are rejected
   (doctrine §6.4, no fabricated success). Bounded (≤64 probes).
4. **Persist** verified-live anchors to `<profile>/ct_anchors.json` with
   probe timestamp, RTT, and provenance query; `anchors list` / `anchors
   clear` manage the set.

The daemon can consult this anchor set to reseed the node pool when channels
and repos are both unavailable — a third independent bootstrap leg.

## Tests

- `config_store` — import (server, dedup, raw-link preservation), paste,
  idempotency, invalid-link rejection. See `config_store.rs` `#[cfg(test)]`.
- `harvest` — entity decoding, fragment stripping, index-0 garbage
  rejection, `@`-core validation, empty-body handling. See `harvest.rs`
  `#[cfg(test)]`.

## Related

- `docs/MODULES.md` — full crate layout.
- `docs/PRINCIPLES.md` — why autonomy + low-cost primitives matter.
