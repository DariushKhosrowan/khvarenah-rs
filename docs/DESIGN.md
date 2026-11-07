# Design Principles

How Khvarenah is designed, and why. Reading this will help you make
consistent contributions.

## 1. Pure core, thin shells

All logic lives in `khvarenah-core`. The CLI, TUI, and GUI are thin adapters.
Never add business logic to a frontend.

## 2. Everything is typed, nothing is guessed

Cloudflare objects are modeled with serde structs (`Zone`, `DnsRecord`,
`Script`, …). API responses are deserialized into these types — no loose
`Value` poking in production code.

## 3. Errors are human-first

Every error carries a `title`, `detail`, and `fix`. A user should never see a
raw stack trace or an opaque HTTP status. If you add a new fallible path, give
it a proper `CFError`.

## 4. Storage is atomic and update-safe

Profile writes go through `atomic_write` (tempfile + fsync + rename). User
data (tokens, configs) must never be lost by a crash or an upgrade.

## 5. Secrets are protected

Tokens live in `0600` files. Logs and UI must never print full tokens. The
security audit enforces this.

## 6. Anti-bot by default

Network calls are paced to look human, and deployed workers vary in bytes.
This is a deliberate, documented feature — not an accident.

## 7. Convention over configuration

Sensible defaults everywhere: `default` profile, standard preset, automatic
token discovery, derived worker names. Configuration is possible but rarely
required.

## 8. Everything is documented

Every module has a `//!` header. Every public function has doc comments.
Docs live in `docs/` and stay in sync with code.

## Conventions

- `cargo fmt --all` before committing.
- `cargo clippy --workspace` must be clean.
- New functionality ships with tests.
- Use `CFError::new(title, detail, fix)`; never `unwrap()` in library code
  that can fail gracefully.
