# DastYab Ops Runbook

Operational notes and manual-run gates that don't belong in unit tests.

## Live E2E acceptance gate (intentionally `#[ignore]`)

`crates/dastyab-core/src/e2e.rs:623 · live_verify_tunnel_against_worker`
is an intentional `#[ignore = "requires live sing-box + deployed worker"]` test.
It is a *live* acceptance gate, not dead code: it needs a real `sing-box`
binary and a deployed worker. Run it manually:

```bash
cargo test -p dastyab-core e2e -- --ignored
```

Preconditions:
- Install `sing-box` (see `crates/dastyab-core/src/e2e.rs::ensure_singbox`
  for the pinned version + platform asset).
- Have a deployed worker config present for the profile under test.

It is excluded from the default `cargo test --workspace` run by design; a green
CI does not imply this test passed. Gate release verification on it explicitly.

## Desync-learning cross-process lock (flock) — filesystem assumption

`worker_tunnel::secret::lock_profile_desync` takes a cross-process exclusive
`flock` on `~/.dastyab/profiles/<id>/.desync-learn.lock` to serialize the
read-modify-write of per-worker desync learning records between the daemon and
GUI processes.

**Assumption: the profile store lives on a LOCAL filesystem.** `flock` semantics
degrade on NFS/SMB (advisory locking is unreliable over network filesystems). Do
not place `~/.dastyab` on NFS/SMB. If a network filesystem is unavoidable, the
daemon and GUI must not run concurrently against the same profile (or the
in-process mutex becomes the only serialization and a lost update is possible).

## `profile_dir` / `home_dir` platform scope

The store resolves the data root via `store::home_dir()` (USERPROFILE on
Windows, `$HOME` on Unix). This is an approximation of `dirs::home_dir()`:

- **Unix (Linux/macOS):** `$HOME` is correct and is the daemon's target
  platform (systemd user service).
- **Windows:** `USERPROFILE` diverges from the shell API under service
  accounts, redirected profiles, and some domain configs. **Windows is NOT in
  the daemon service path** — the systemd daemon is Unix-only. The Windows GUI
  build is supported for interactive use; if a Windows service path is ever
  added, revisit `home_dir` to use the proper known-folder API.
