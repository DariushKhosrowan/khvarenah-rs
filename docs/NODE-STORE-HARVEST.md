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

## Tests

- `config_store` — import (server, dedup, raw-link preservation), paste,
  idempotency, invalid-link rejection. See `config_store.rs` `#[cfg(test)]`.
- `harvest` — entity decoding, fragment stripping, index-0 garbage
  rejection, `@`-core validation, empty-body handling. See `harvest.rs`
  `#[cfg(test)]`.

## Related

- `docs/MODULES.md` — full crate layout.
- `docs/PRINCIPLES.md` — why autonomy + low-cost primitives matter.
