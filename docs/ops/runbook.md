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

## `active_token` marker — writer enumeration (root-cause table)

The active-token marker is `~/.dastyab/profiles/<id>/active_token` (a JSON
string holding the active token *label* — not the secret). Every writer, and
whether it can ever produce an empty/whitespace marker:

| Writer | Location | What it writes | Can it write empty? |
|---|---|---|---|---|
| `set_active_token` | `store/profiles.rs` | validated label (rejects empty/whitespace, rejects unknown label) | **No** (guarded) |
| `ensure_active_token` | `store/profiles.rs` | repopulates empty/stale marker from default or first token | **No** — writes only a real label; returns `Ok(None)` when there are no tokens (writes nothing) |
| `remove_token` | `store/profiles.rs` | promotes next token when the removed one was active | No (promotes a real remaining label) |
| `remove_token` (no remainder) | `store/profiles.rs` | writes empty string when the last token is removed | **Yes** — by design (no token left to be active) |
| `get_active_token` | `store/profiles.rs` | **pure** — never writes; reports `Ok(None)` for a stale marker | **No** (getter made pure) |
| `clear_active_token` | `store/profiles.rs` | writes empty string | **Yes** — explicit clear, `#[cfg(test)]`-only |
| `write_json` direct callers | (GUI/CLI call `set_/ensure_` — never write the marker file directly) | — | — |

Guards in place:

1. `set_active_token` rejects empty/whitespace labels, so no *validated*
   writer can blank the marker while a token is meant to be active. (`set_active_token_rejects_empty_and_whitespace_labels`)
2. `get_active_token` is **pure** — it never writes. A stale marker is
   reported as `Ok(None)` and left untouched (a read can never turn a
   transient miss into a persistent empty marker). (`get_active_token_is_pure_and_leaves_stale_marker_untouched`)
3. `ensure_active_token` is the single entry point for redeploy/account-probe;
   it repopulates an empty/stale marker from a real token when any exist, so
   the daemon never stalls on "No active token" while tokens exist.
4. `clear_active_token` is `#[cfg(test)]`-only — not reachable in production builds.