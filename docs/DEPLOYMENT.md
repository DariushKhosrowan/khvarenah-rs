# Build, Release & Cross-Compile

## Build (debug)

```bash
cargo build --workspace
```

Binaries land in `target/debug/`:

- `dastyab` — CLI
- `dastyab-tui` — TUI
- `dastyab-gui` — GUI

## Build (release)

```bash
cargo build --release --workspace
```

Release profile: `opt-level=3`, thin LTO, `codegen-units=1`, stripped
symbols.

## Test

```bash
cargo test --workspace
cargo clippy --workspace   # must be warning-free
cargo fmt --all
```

## Cross-compiling

The core + CLI are pure Rust with no system C dependencies (rustls for TLS),
so cross-compilation is clean. For example, on a Linux host targeting Windows:

```bash
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc -p dastyab-cli
```

ARM targets follow the same pattern.

## Releasing

1. Bump `version` in the workspace `Cargo.toml`.
2. Update `docs/CHANGELOG.md`.
3. Tag and push: `git tag vX.Y.Z && git push --tags`.
4. The CI workflow builds release binaries and attaches them to a GitHub
   release (see `.github/workflows/`).

## Self-update

The CLI can check and fetch newer binaries from GitHub releases:

```bash
dastyab update-check
dastyab update-apply
```

`selfupdate.rs` downloads the platform-matching asset. Note: the release must
actually attach a binary for the target OS/arch.

## Installing as a single binary

Copy `target/release/dastyab` to a directory on `PATH`:

```bash
install -m 0755 target/release/dastyab ~/.local/bin/dastyab
```

No other runtime is required.
