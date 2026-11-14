# Contributing to DastYab

DastYab is a Rust workspace. One core crate holds all logic; the CLI, TUI and
GUI are thin front-ends over it. If a behaviour is not in `dastyab-core`, it
probably belongs there.

## Getting set up

```bash
git clone git@github.com:DastYab/dastyab.git
cd dastyab
cargo build --workspace
cargo test  -p dastyab-core --lib
```

Rust 1.99+ is required (the workspace tracks recent stable). The CLI is a
single static binary with no runtime dependencies.

## Before you open a pull request

Run the same gate CI runs:

```bash
scripts/verify.sh
```

That is `cargo fmt --all --check`, a workspace build, `cargo clippy
--workspace --all-targets -- -D warnings`, and the core test suite. A PR that
does not pass it will not be merged.

## Where things live

`crates/dastyab-core/src` is organised into nine domain layers:

| Layer | Responsibility |
|---|---|
| `net` | transport, resolvers, TLS, DNS shaping, TUN |
| `trust` | security audit, stealth, SNI, tokens, blackout, bootstrap |
| `tunnel` | DNS tunnels, ARQ, IBLT, bonding, chaining |
| `egress` | workers, wrangler, VPS deploy, carrier pool |
| `probe` | scanning, clean-IP, node health, autopilot |
| `mesh` | LAN mesh, DTN gossip, beacons, trust ledger |
| `discovery` | harvesting, GitHub/CT/NS anchors, Telegram export |
| `artifact` | VLESS, exporters, presets, inventory, snapshots |
| `ops` | backup, self-update, platform, tor, status, i18n |

`docs/MODULES.md` describes the layers in reading order.

## House rules

- **Errors are user-facing.** Return `CFError { title, detail, fix }`; the
  `fix` field is what the user actually reads when something breaks.
- **State writes are atomic.** Go through `store::atomic_write`; never write a
  config file in place.
- **No new runtime dependencies in the CLI.** The single-binary property is a
  feature, not an accident.
- **Test what you fix.** A bug fix without a test that fails before it is not
  finished.
- **Do not put network calls in unit tests.** Use the mock worker / injectable
  probes that already exist.

## Commit messages

Short imperative subject line, then a body explaining *why* rather than *what*
— the diff already shows the what. Reference the layer or crate you touched.

## Reporting a security issue

Do not open a public issue. See `SECURITY.md`.
