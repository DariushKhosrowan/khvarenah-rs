# Khvarenah Architecture

This document describes how Khvarenah is structured, how data flows through
it, and how the four crates relate to one another. It is the map you should
start from before reading any code.

---

## 1. Crate model

```
┌─────────────────────────────────────────────────────────────────┐
│                      khvarenah-rs (workspace)                   │
│                                                                 │
│   ┌─────────────────────────┐   ┌─────────────────────────────┐ │
│   │     khvarenah-core      │   │      khvarenah-cli         │ │
│   │  (library — the brain)  │◄──│  (clap CLI, binary)        │ │
│   └───────────┬─────────────┘   └─────────────────────────────┘ │
│               │                                                 │
│               │     ┌─────────────────────────────┐             │
│               ├────►│      khvarenah-tui         │             │
│               │     │  (ratatui dashboard)        │             │
│               │     └─────────────────────────────┘             │
│               │                                                 │
│               │     ┌─────────────────────────────┐             │
│               └────►│      khvarenah-gui         │             │
│                     │  (eframe/egui desktop app)  │             │
│                     └─────────────────────────────┘             │
└─────────────────────────────────────────────────────────────────┘
```

**The golden rule: all logic lives in `core`. The three frontends are thin
adapters.** Every frontend calls the same core functions; none of them
re-implement Cloudflare calls, storage, or VLESS generation. This keeps the
project maintainable and guarantees that the CLI, TUI, and GUI behave
identically.

---

## 2. Core crate layout

```
khvarenah-core/src/
├── lib.rs        # crate root: module re-exports + brand/version constants
├── error.rs      # CFError taxonomy (title / detail / fix)
├── store/        # atomic per-profile persistence (update-safe)
│   ├── mod.rs    #   atomic_write, mem_dir, profiles_dir
│   └── profiles.rs #   Profile struct, tokens, accounts, history, clean IPs
├── cf/           # Cloudflare v4 API client
│   └── mod.rs    #   Client, Account, Script, Zone, DnsRecord, WorkerRoute
├── vless.rs      # VlessProfile + share-link / xray JSON generation
├── scanner.rs    # SenPaiScanner orchestration + endpoint validation
├── health.rs     # TCP / TLS latency + throughput probe
├── export.rs     # v2rayN / sing-box / Clash exporters
├── analytics.rs  # usage aggregation across scripts
├── diagnostics.rs# endpoint diagnostics
├── security.rs   # local security audit
├── backup.rs     # profile backup / restore
├── selfupdate.rs # GitHub release updater
├── presets.rs    # curated deploy presets
├── stealth.rs    # anti-bot pacing + worker byte-fingerprint humanization
├── geoip.rs      # country lookup (built-in + GeoLite2)
└── qr.rs         # QR matrix rendering
```

---

## 3. Data flow: deploy → scan → export

The happy path is a three-stage pipeline:

```
   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
   │ token add │──►│  verify  │──►│  deploy  │──►│   scan   │
   └──────────┘    └──────────┘    └──────────┘    └──────────┘
                                         │                │
                                         ▼                ▼
                                   ┌──────────┐    ┌──────────┐
                                   │ vless:// │    │ clean IP │
                                   │   link   │    │  list    │
                                   └──────────┘    └──────────┘
                                         │                │
                                         └───────┬────────┘
                                                 ▼
                                          ┌──────────┐
                                          │  export  │
                                          │ clash/sing│
                                          │ box/v2rayN│
                                          └──────────┘
```

**Stage 1 — Deploy.** `cf::Client::deploy_script` uploads the worker via
multipart PUT, sets the `UUID` variable, and records a `VlessRecord` in the
profile history. Stealth pacing inserts human-like delays before each API
call; worker humanization varies the uploaded bytes.

**Stage 2 — Scan.** `scanner::scan_once` shells out to SenPaiScanner,
collects candidate endpoints, and runs a health probe on each. The first
*verified working* endpoint is accepted and recorded as a clean-IP config.

**Stage 3 — Export.** `export::render` turns the stored `VlessRecord` into a
v2rayN JSON, sing-box JSON, Clash YAML fragment, or a raw share link.

---

## 4. Storage & atomicity

Every write goes through `store::atomic_write`:

```
write tempfile (same dir) → fsync file → rename over target → fsync parent
```

This means a crash mid-write can never leave a truncated file. Profile data
lives in named directories under `~/.khvarenah/profiles/<id>/`; tokens are
chmod `0600`; everything else `0644` under a `0700` tree.

---

## 5. Error handling

All fallible operations return `Result<T, CFError>`.

`CFError` has three human-facing fields:

- `title` — a short headline (e.g. "Authentication failure").
- `detail` — what exactly happened.
- `fix` — a concrete next step for the user.

Every Cloudflare HTTP error is classified by status code **and** CF error
code (see `error::KNOWN_CODES`). This is the backbone of "debugging that
just works".

---

## 6. Concurrency

- `cf::Client` is `Clone` + fully `async` (tokio + reqwest/rustls).
- The TUI/GUI run core calls in a background task and block on the result so
  the UI never freezes.
- Test overrides are thread-local, so parallel tests never interfere.

---

## 7. Testing strategy

| Layer | Approach |
|---|---|
| Core unit tests | `cargo test --workspace` — pure logic (VLESS round-trips, export formats, error mapping, scanner parsing, store atomicity). |
| Static analysis | `cargo clippy --workspace` must be warning-free. |
| Formatting | `cargo fmt --all` enforced. |
| CI | GitHub Actions workflow (see `.github/workflows/`). |

---

## 8. Where to go next

- [MODULES.md](MODULES.md) — read the modules in dependency order.
- [API.md](API.md) — Cloudflare endpoint coverage.
- [DESIGN.md](DESIGN.md) — principles and conventions behind the code.
- [SECURITY.md](SECURITY.md) — threat model and hardening.
