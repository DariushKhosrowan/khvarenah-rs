I am the coding agent; you are the architect for the DastYab Rust workspace.

Repo: ~/Projects/dastyab (main branch)
Top commit: a05ebf2 "probe_jitter: derive serde on ClientHelloProfile"
Tests: 216 pass across workspace, clippy 0 warnings.
Worker healthy (Alive). 24/7 protection daemon running under systemd.

Mission: make the app FULLY automatic and resilient — zero manual steps.
Each cycle I execute ONE task you prescribe, verify it, ship it, report back.

The reply must follow this exact contract:
1. RANKED next task list (I will do the FIRST one). 2-3 candidates max.
   Every candidate MUST be an independence/auto-healing/self-sufficiency improvement:
   - removes a manual step, OR
   - adds auto-recovery / self-heal, OR
   - hardens against censored-network failure (Iran), OR
   - adds a new tool/equipment that makes the app more resilient.
2. For the #1 task ONLY, give:
   - exact REAL file path(s) in the repo (verify against the real crate layout —
     core is crates/dastyab-core/src/, cli crates/dastyab-cli/src/commands.rs)
   - function signatures (adapt to the repo idiom: u64/chrono/store helpers)
   - acceptance checks (a test name + a CLI command that proves it)
   - dependency cost (prefer zero new crates)
3. End with a single "DO THIS FIRST:" line naming exactly one task.

Add a short "WHY" per candidate. Do not invent file paths. Do not write whole
functions — prescribe edits.
--- END BRIEF ---
