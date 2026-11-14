## What this changes

<!-- One paragraph. Say why, not just what — the diff shows the what. -->

## Layer touched

<!-- net / trust / tunnel / egress / probe / mesh / discovery / artifact / ops
     / front-end. See docs/MODULES.md. -->

## Checklist

- [ ] `scripts/verify.sh` passes (fmt, build, clippy `-D warnings`, core tests)
- [ ] New behaviour has a test that fails without the change
- [ ] No new runtime dependency in the CLI (single-static-binary property intact)
- [ ] State writes still go through `store::atomic_write`
- [ ] Errors carry a user-facing `fix` string where the user can act on them
- [ ] Docs updated if behaviour or a command changed (`docs/`, `README.md`)
- [ ] No token, UUID, hostname or share link committed in a test fixture

## Notes for the reviewer

<!-- Anything subtle: a protocol change, a migration, a deliberate tradeoff. -->
