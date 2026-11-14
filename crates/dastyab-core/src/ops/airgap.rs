//! Air-gap switch: one place that says "this process must not open sockets".
//!
//! Two callers need this, for different reasons:
//!
//! * **Tests.** `daemon_tick` performs real maintenance work (beacon outbox,
//!   carrier push, worker self-ping) whenever the network looks up. A test that
//!   injects a scripted `NetworkProbe` still reaches those paths, so a drill
//!   that spends three ticks "healthy" can sit on a DNS timeout for minutes.
//! * **Operators.** Someone running DastYab on an isolated machine, or who
//!   wants to inspect a profile without any traffic leaving the box, should not
//!   need a firewall rule to get that guarantee.
//!
//! The switch is process-global and defaults to *online*. It is set once at
//! startup from `DASTYAB_OFFLINE` (any non-empty, non-`0` value) and can be
//! forced from code via [`set_offline`].
//!
//! This is a *cooperative* switch: it does not sandbox anything, it just
//! answers "may I make a call right now?" so call sites can skip cheaply. Any
//! new call site that ignores it simply behaves online.

use std::sync::atomic::{AtomicBool, Ordering};

/// Process-wide default, set once at startup from the environment.
static OFFLINE: AtomicBool = AtomicBool::new(false);

// Per-thread override, so a test that switches to air-gap cannot disable the
// network paths of tests running concurrently on other threads. Production
// code never sets this, so it falls through to the process default.
std::thread_local! {
    static TL_OFFLINE: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// Force offline/online mode for this process *and* this thread.
pub fn set_offline(v: bool) {
    OFFLINE.store(v, Ordering::Relaxed);
    TL_OFFLINE.with(|c| c.set(Some(v)));
}

/// Set the mode for the current thread only (tests).
pub fn set_offline_thread_local(v: bool) {
    TL_OFFLINE.with(|c| c.set(Some(v)));
}

/// Clear the current thread's override, falling back to the process default.
pub fn clear_thread_override() {
    TL_OFFLINE.with(|c| c.set(None));
}

/// True when outbound work must be skipped.
///
/// Call sites use it as an early return: `if offline() { return; }`.
pub fn offline() -> bool {
    if let Some(v) = TL_OFFLINE.with(|c| c.get()) {
        return v;
    }
    OFFLINE.load(Ordering::Relaxed)
}

/// True when outbound work is permitted. Reads better at call sites that guard
/// a block, e.g. `if online() { ... }`.
pub fn online() -> bool {
    !offline()
}

/// Apply the `DASTYAB_OFFLINE` environment variable, if present.
///
/// `DASTYAB_OFFLINE=1` (or any value other than empty/`0`/`false`) means
/// offline. Intended to be called once from `main` before any work starts.
pub fn init_from_env() {
    if let Ok(v) = std::env::var("DASTYAB_OFFLINE") {
        let v = v.trim();
        set_offline(!(v.is_empty() || v == "0" || v.eq_ignore_ascii_case("false")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_online_and_toggles() {
        // Note: process-global, so this test only asserts the transition it
        // makes itself and restores the default afterwards.
        set_offline(false);
        assert!(online());
        set_offline(true);
        assert!(offline());
        assert!(!online());
        set_offline(false);
    }
}
