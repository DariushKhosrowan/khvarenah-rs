# Contributing

Thanks for helping improve DastYab!

## Getting started

1. Fork and clone the repo.
2. `cargo build --workspace`.
3. `cargo test --workspace`.

## Before you commit

```bash
cargo fmt --all
cargo clippy --workspace    # must be warning-free
cargo test --workspace       # must pass
```

## Conventions

- All logic goes in `dastyab-core`. Frontends are thin shells.
- New public functions get doc comments; new modules get a `//!` header.
- Use `CFError::new(title, detail, fix)` for errors — never `unwrap()` where
  a graceful error is possible.
- Add tests for new behavior.
- Keep `docs/` in sync.

## Testing

- Core unit tests cover pure logic (VLESS, export, parsing, storage).
- No live Cloudflare calls in tests; mock or isolate network paths.

## Code review

- Keep PRs focused and small.
- Reference the module docs in your PR description.

## Security

Do not commit real tokens or account IDs. If you find a security issue, open
a private/security issue and do not include real secrets.
