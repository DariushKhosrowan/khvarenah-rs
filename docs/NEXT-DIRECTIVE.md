# DastYab — Next Directive

> Captured automatically from Gemini (gemini-3-flash-preview) via AI Studio layered tunnel on 2026-11-13.

---

**Feature**: Implement an integrity-protected, atomic disk-persistence layer for the CT-anchor set to enable immediate "last-known-good" state recovery during air-gapped boots.

**Why it matters**: During a total blackout, a daemon restart or power failure would currently wipe the in-memory anchor set; without internet to "discover" them again, the system loses its ability to validate any certificates, effectively bricking its security functions until connectivity returns.

**Exact module/file**: `src/anchors/persistence.rs`

**Minimal implementation outline**:
*   Define a `PersistentAnchorStore` struct that encapsulates a `Vec<Anchor>`, a `u64` Unix timestamp, and a schema version.
*   Implement `serde` serialization for the store using a compact binary format (e.g., `bincode`) to minimize I/O overhead.
*   Create an `atomic_save` function that writes the serialized data to a `.tmp` file and uses `std::fs::rename` to overwrite the primary store, preventing corruption during a mid-write power loss.
*   Implement a `load_or_default` function that attempts to read the store on startup, falling back to an empty set only if no file exists.
*   Add a BLAKE3 or SHA256 checksum at the end of the file to verify data integrity before loading it into the active anchor set.
*   Hook the `save` function into the existing `anchors refresh` and daemon auto-rotation logic so every state change is immediately flushed to disk.

**Verification test**:
`test_blackout_recovery`: Manually populate the anchor set, trigger a save, simulate a process kill, disable network mocks, re-initialize the `AnchorManager`, and assert that the `refresh` timestamp and anchor count match the pre-shutdown state exactly.

---
## Hermes execution plan (brief)

Captured by the scheduled cron job on 2026-11-13.

* **Directive**: Atomic + checksummed disk persistence for the CT-anchor set (last-known-good recovery across air-gapped/blackout restarts).
* **Scope**: No external services; fully offline-testable. New module `src/anchors/persistence.rs`; hooks into existing `anchors refresh|prune` + daemon auto-rotation.
* **Suggested steps** (next session):
  1. Add `bincode` + `serde` deps (or reuse existing serde) and `BLAKE3` (or `sha2`).
  2. `src/anchors/persistence.rs`: `PersistentAnchorStore { Vec<Anchor>, u64 ts, u32 schema }`, `Save`/`load_or_default` with `.tmp`+`rename` atomic replace, trailing checksum verify.
  3. Add store path to config (default under cfg state dir); TOML/derive not needed — binary format.
  4. Hook `save` into `anchors refresh|prune` and daemon rotate loop; fsync before rename for crash safety.
  5. Test `test_blackout_recovery`: populate → save → drop manager → disable network mocks → reload → assert ts + anchor set match.
  6. Offline unit test for corruption: flip a byte / truncate → `load_or_default` falls back to last-good or empty, never panics.
* **Not done in this run**: no source modifications (per task). Directive captured verbatim above.
