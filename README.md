# DastYab (دستیاب) — Rust Edition

**A Cloudflare Workers VLESS VPN console: deploy, scan, and manage your entire
proxy stack from the command line, a terminal UI, or a desktop GUI — written
in Rust for speed, safety, and a single static binary.**

> **دستیاب (DastYab)** — *the Avestan royal glory; the divine fortune that
> lets the wise soar beyond every wall and veil.*

| | |
|---|---|
| **Language** | Rust (edition 2021) |
| **Workspace** | `dastyab-core` · `dastyab-cli` · `dastyab-tui` · `dastyab-gui` |
| **License** | MIT |
| **Latest release** | `v0.1.1` |
| **Rust version** | 1.99+ (stable) |
| **Zero runtime deps (CLI)** | single static binary, no Python, no Node |

---

## What is DastYab?

DastYab turns a single **Cloudflare API token** into a complete, self-hosted
***VLESS VPN control plane**. From the terminal you can:

- **Deploy** an edgetunnel VLESS worker to Cloudflare Workers (with anti-bot
  stealth pacing and per-deploy byte-fingerprint humanization).
- **Scan** for clean, fast Cloudflare IPs (via SenPaiScanner) that actually
  work with your configuration.
- **Autopilot / Protection** — one toggle: the app deploys, finds the best
  clean IP (SlipNet-style two-phase streaming scan + E2E tunnel gate), exports
  vless configs, and **periodically monitors** them, auto-replacing dead
  fronts. A **step-0 worker-health gate** checks your worker is alive before
  any scan runs — so `dastyab autopilot health` is the check to run first
  if a scan ever finds zero clean IPs (a suspended CF account, error 9109,
  or a dead route cannot be fixed by scanning).
- **Generate** client configs for **v2rayN / v2rayNG**, **sing-box**, and
  **Clash / Clash.Meta** in one command.
- **Manage** your Cloudflare account: DNS records, zones, worker routes,
  per-worker usage analytics, and per-account tokens.
- **Protect** your setup: auditable token storage (`0600`), atomic profile
  writes, and a built-in security audit.
- **Back up / restore** entire profiles as portable JSON bundles.
- **Configs manager** — a whole-workspace inventory of every generated
  artifact across all profiles, with per-artifact integrity status.
- **Nothing gets lost** — per-profile manifests (sha256) prove nothing was
  corrupted or dropped; `dastyab manifest-verify`; a whole-workspace
  snapshot/restore bundles every profile into one portable, hash-verified file.

Everything is built on a clean, pure-Rust core that is fully documented,
tested, and ready to extend.

---

## Why Rust?

| Concern | What Rust delivers |
|---|---|
| **Single binary** | `dastyab` is a static executable — no Python env, no pip, no Node. |
| **Safety** | No null pointers, no data races, no buffer overflows. Memory-safe by construction. |
| **Speed** | Clean-IP scanning and analytics are fast enough to feel instant. |
| **Correctness** | Strong types + serde models for every Cloudflare object. |
| **Distribution** | Easy cross-compile to Linux / macOS / Windows / ARM. |

---

## Quick start

### Install (one command)

The CLI ships as a single static Rust binary — no Python, no Node, no runtime
deps. Install the latest release with one line:

```bash
curl -fsSL https://raw.githubusercontent.com/DariushKhosrowan/dastyab/main/scripts/install.sh | sh
```

This detects your OS/CPU, downloads the matching binary from the latest GitHub
release, verifies its SHA-256 checksum, installs it to `~/.local/bin`, and
adds that directory to your `PATH`. Then open a new terminal and confirm:

```bash
dastyab --version
```

> **Windows?** Grab the portable `.zip` from the [releases page](https://github.com/DariushKhosrowan/dastyab/releases).
> **Prefer a package?** A `.deb` installer is published with every release too.
> **Build from source?** `cargo build --release` and run
> `target/release/dastyab` (or `cargo install dastyab-cli`).

After installing:

```bash
# 1. Add a Cloudflare token (stored 0600 in ~/.dastyab/)
dastyab token add cf-main <YOUR_CF_API_TOKEN>

# 2. Verify the token and list your accounts
dastyab verify
dastyab accounts

# 3. Create a profile (optional, defaults to "default")
dastyab profile-create work --description "my setup"

# 4. Deploy a worker & get a vless share link
dastyab deploy --preset standard

# 5. Find a clean IP (stops on the first working one)
#    Simple — for everyone:
dastyab find 1        # one working IP
dastyab find 5 ip     # five working IPs
dastyab find           # same as `find 1`
#    Advanced — when you need to tune:
#    dastyab find 10 --sample 5000 --workers 128 --timeout 12 \
#        --strategy generic-first --out ~/my-configs

# 6. Export client configs
dastyab export clash    --output clash.yaml
dastyab export singbox  --output config.json
dastyab export v2rayn  --output xray.json
```

> **Tip:** run `dastyab --help` for the full command reference.

---

## The three frontends

The same `dastyab-core` powers three interfaces, so you can pick the one
that fits how you work.

### 1. CLI — `dastyab`

The full-featured command line. Everything is scriptable and composable.

```bash
dastyab zones                              # list zones
dastyab dns list <zone_id>                 # list DNS records
dastyab dns create <zone_id> <name> A 1.2.3.4
dastyab routes list                        # list worker routes
dastyab analytics                          # per-worker request usage
dastyab security                           # run a local security audit
dastyab backup export <profile_id>         # back up a profile
dastyab inventory                          # configs inventory (the "configs manager")
dastyab manifest-verify                    # prove nothing was lost/corrupted
dastyab workspace snapshot                 # whole-workspace snapshot
dastyab workspace restore <file>           # restore from a snapshot
dastyab update-check                       # check for a newer release
```

### 2. TUI — `dastyab-tui`

A keyboard-driven terminal dashboard (ratatui). Shows profiles, token counts,
saved configs, and recent share links at a glance. Press `1`/`2`/`3` or
`Tab` to switch panels, `q` to quit.

```bash
dastyab-tui
```

### 3. GUI — `dastyab-gui`

A modern desktop app (eframe/egui) with a royal-gold-on-black theme. Three
tabs: **Deploy & Scan**, **Profiles & Tokens**, and **Tools** (security audit,
backup, config export).

```bash
dastyab-gui
```

---

## Architecture at a glance

```
dastyab/
├── crates/
│   ├── dastyab-core/        # pure logic, no UI (the brain)
│   │   └── src/
│   │       ├── cf/            # Cloudflare v4 API client (rustls)
│   │       ├── store/         # atomic per-profile JSON persistence
│   │       ├── vless.rs       # VLESS profile + share-link generation
│   │       ├── scanner.rs     # legacy clean-IP scanning wrapper (SenPaiScanner)
│   │       ├── slipscan.rs    # SlipNet-style two-phase streaming scanner + E2E pipeline
│   │       ├── autopilot.rs   # clean-IP discovery engine, worker-health gate, monitor loop
│   │       ├── health.rs      # TCP/TLS latency & real-client WS-upgrade gate (alt-port)
│   │       ├── probe_jitter.rs # anti-DPI probe pacing + randomized WS request
│   │       ├── e2e.rs        # sing-box end-to-end tunnel verification
│   │       ├── diagnose.rs    # plain-language "why zero?" cause mapping
│   │       ├── export.rs      # v2rayN / sing-box / Clash exporters
│   │       ├── analytics.rs   # usage aggregation
│   │       ├── diagnostics.rs # endpoint diagnostics
│   │       ├── security.rs    # local security audit
│   │       ├── backup.rs      # profile backup / restore
│   │       ├── manifest.rs    # per-profile integrity manifests + verify
│   │       ├── inventory.rs   # whole-workspace configs inventory
│   │       ├── workspace_snapshot.rs # hash-verified whole-workspace snap/restore
│   │       ├── selfupdate.rs  # GitHub release updater
│   │       ├── presets.rs     # curated deploy presets
│   │       ├── stealth.rs     # anti-bot pacing + worker humanization
│   │       ├── geoip.rs       # country tagging
│   │       ├── qr.rs          # QR matrix rendering
│   │       └── error.rs       # structured CFError taxonomy
│   ├── dastyab-cli/         # clap-based CLI (binary: dastyab)
│   ├── dastyab-tui/         # ratatui dashboard (binary: dastyab-tui)
│   └── dastyab-gui/         # eframe/egui desktop app (binary: dastyab-gui)
├── docs/                      # full documentation (see below)
├── .github/workflows/         # CI
└── Cargo.toml                 # workspace manifest
```

See **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** for maps and diagrams,
and **[docs/MODULES.md](docs/MODULES.md)** for a module-by-module guide.

---

## Storage layout

All state lives under `~/.dastyab/`:

```
~/.dastyab/
├── profiles/
│   └── default/
│       ├── profile.json    # metadata
│       ├── token.json      # API tokens (mode 0600)
│       ├── accounts.json   # remembered Cloudflare accounts
│       ├── history.json    # generated vless configs
│       ├── cleanips.json   # scanned clean IPs
│       └── config.json     # per-profile settings
├── backups/                # exported profile bundles
└── legacy/                 # pre-0.1 flat files (one-time migration)
```

Writes are **atomic** (tempfile + fsync + rename), so a crash or kill can
never corrupt your tokens or configs.

---

## Security

- Tokens are stored in `0600` files under `~/.dastyab/`.
- The **security audit** (`dastyab security`) checks permissions, flags
  leaked tokens in unexpected JSON files, and reports a health verdict.
- Deploys use **stealth pacing** (randomized human-like delays) and vary the
  worker's byte fingerprint per deploy so no two deployments are identical.
- The SSH-style error taxonomy (`CFError`) gives a human-readable **title →
  detail → fix** for every API failure.

See **[docs/SECURITY.md](docs/SECURITY.md)**.

---

## Documentation

The `docs/` folder is the single source of truth for the project:

| Document | What it covers |
|---|---|
| [README.md](README.md) | This file — overview, quick start, links |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System maps, data flow, component diagrams |
| [docs/MODULES.md](docs/MODULES.md) | Module-by-module guide |
| [docs/API.md](docs/API.md) | Cloudflare API coverage & client reference |
| [docs/DESIGN.md](docs/DESIGN.md) | Design principles, trade-offs, conventions |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model, hardening, audit |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Building, releasing, cross-compiling |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Planned work |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | Version history |
| [docs/GLOSSARY.md](docs/GLOSSARY.md) | Terms & concepts |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to help |

---

## Contributing

Contributions are warmly welcome — see **[CONTRIBUTING.md](CONTRIBUTING.md)**.
In short:

1. `cargo fmt --all` before every commit.
2. `cargo clippy --workspace` must be warning-free.
3. `cargo test --workspace` must pass.
4. Keep docs in sync with code.

---

## License

MIT © Dariush Khosrowan.
