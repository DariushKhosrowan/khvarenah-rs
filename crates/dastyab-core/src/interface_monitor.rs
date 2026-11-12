//! Interface-flap monitoring (doctrine E).
//!
//! Under a blackout the physical/link interface can flap (carrier drops,
//! operstate toggles). The daemon must notice this immediately — far faster
//! than waiting for a probe timeout — and re-evaluate the route ladder.
//!
//! This module provides:
//! - [`InterfaceState`]: a snapshot of one interface's link status.
//! - [`InterfaceMonitor`]: a trait so tests can inject synthetic state while
//!   production uses [`SysfsInterfaceMonitor`].
//! - [`FlapDetector`]: debounced DOWN detection with a flap counter, so a
//!   single transient sample doesn't trigger a full re-probe storm, but a
//!   sustained drop is surfaced as a flap event.

use std::time::{Duration, Instant};

/// Operational state of a network interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceState {
    Up,
    Down,
}

/// The state read from the interface at a point in time.
#[derive(Debug, Clone, Copy)]
pub struct InterfaceSample {
    pub state: InterfaceState,
    /// True when the sample changed from the previous one (raw edge).
    pub changed: bool,
}

/// Abstraction over querying a network interface's state. Production uses
/// [`SysfsInterfaceMonitor`]; tests inject synthetic samples.
pub trait InterfaceMonitor {
    /// Read the current state of the interface.
    fn sample(&mut self) -> InterfaceState;
}

/// Linux implementation reading the link state from sysfs.
/// - `carrier` (1 = carrier present) is the authoritative physical-link probe.
/// - `operstate` is a text file (`up`/`down`/`unknown`); `unknown` is
///   treated as up because carrier is authoritative for link presence.
pub struct SysfsInterfaceMonitor {
    path: std::path::PathBuf,
}

impl SysfsInterfaceMonitor {
    /// Build a monitor for a physical interface name (e.g. `wlan0`, `eth0`).
    /// `use_carrier` picks carrier (true, default) vs operstate (false).
    pub fn new(iface: &str) -> Self {
        Self {
            path: std::path::PathBuf::from(format!("/sys/class/net/{iface}")),
        }
    }

    /// Build from an explicit sysfs directory (mainly for tests, or for
    /// non-standard paths).
    pub fn from_dir(dir: impl Into<std::path::PathBuf>) -> Self {
        Self { path: dir.into() }
    }

    fn read_carrier(&self) -> InterfaceState {
        match std::fs::read_to_string(self.path.join("carrier")) {
            Ok(s) if s.trim() == "1" => InterfaceState::Up,
            Ok(_) => InterfaceState::Down,
            Err(_) => {
                // No carrier file (e.g. virtual ifaces): fall back to operstate.
                self.read_operstate()
            }
        }
    }

    fn read_operstate(&self) -> InterfaceState {
        match std::fs::read_to_string(self.path.join("operstate")) {
            Ok(s) if s.trim() == "down" => InterfaceState::Down,
            _ => InterfaceState::Up,
        }
    }
}

impl InterfaceMonitor for SysfsInterfaceMonitor {
    fn sample(&mut self) -> InterfaceState {
        self.read_carrier()
    }
}

/// Debounced flap detection over a monitor.
///
/// `sample` can be called on any cadence. To avoid flapping on a single
/// transient sample, a DOWN sample must be observed `debounce` consecutive
/// times before it is reported as a confirmed flap. Recoveries are immediate.
pub struct FlapDetector<M> {
    monitor: M,
    last: InterfaceState,
    down_streak: u32,
    debounce: u32,
    flap_count: u64,
    /// When the last confirmed flap occurred (for hysteresis / cooldown).
    last_flap_at: Option<Instant>,
}

impl<M: InterfaceMonitor> FlapDetector<M> {
    /// Create a detector with a debounce of `debounce` consecutive DOWN
    /// samples. `initial` is the assumed starting state (default Up).
    pub fn new(monitor: M, debounce: u32, initial: InterfaceState) -> Self {
        Self {
            monitor,
            last: initial,
            down_streak: 0,
            debounce: debounce.max(1),
            flap_count: 0,
            last_flap_at: None,
        }
    }

    /// Sample the interface once and return whether this sample produced a
    /// *confirmed* flap (DOWN sustained for `debounce` samples).
    pub fn sample_once(&mut self) -> bool {
        let s = self.monitor.sample();
        match s {
            InterfaceState::Up => {
                self.down_streak = 0;
                self.last = InterfaceState::Up;
                false
            }
            InterfaceState::Down => {
                self.down_streak += 1;
                if self.down_streak >= self.debounce {
                    if self.last == InterfaceState::Up || self.down_streak == self.debounce {
                        self.flap_count += 1;
                        self.last_flap_at = Some(Instant::now());
                    }
                    self.last = InterfaceState::Down;
                    // Only report the *transition* into a confirmed flap once.
                    self.down_streak == self.debounce
                } else {
                    false
                }
            }
        }
    }

    /// Number of confirmed flaps observed.
    pub fn flap_count(&self) -> u64 {
        self.flap_count
    }

    /// Time of the last confirmed flap, if any.
    pub fn last_flap_at(&self) -> Option<Instant> {
        self.last_flap_at
    }

    /// True when a flap occurred within `within` — used for cooldown /
    /// hysteresis so the daemon doesn't re-chain probes on every tick.
    pub fn recently_flapped(&self, within: Duration) -> bool {
        match self.last_flap_at {
            Some(t) => t.elapsed() <= within,
            None => false,
        }
    }

    /// Current debounced state.
    pub fn current_state(&self) -> InterfaceState {
        self.last
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ScriptedMonitor {
        states: std::cell::RefCell<std::vec::Vec<InterfaceState>>,
    }

    impl ScriptedMonitor {
        fn new(s: &[InterfaceState]) -> Self {
            Self {
                states: std::cell::RefCell::new(s.to_vec()),
            }
        }
    }

    impl InterfaceMonitor for ScriptedMonitor {
        fn sample(&mut self) -> InterfaceState {
            self.states.borrow_mut().remove(0)
        }
    }

    #[test]
    fn up_never_flaps() {
        let m = ScriptedMonitor::new(&[InterfaceState::Up; 5]);
        let mut d = FlapDetector::new(m, 2, InterfaceState::Up);
        for _ in 0..5 {
            assert!(!d.sample_once());
        }
        assert_eq!(d.flap_count(), 0);
        assert_eq!(d.current_state(), InterfaceState::Up);
    }

    #[test]
    fn single_down_sample_is_debounced_away() {
        let m =
            ScriptedMonitor::new(&[InterfaceState::Down, InterfaceState::Up, InterfaceState::Up]);
        let mut d = FlapDetector::new(m, 2, InterfaceState::Up);
        assert!(!d.sample_once()); // 1st Down: below debounce
        assert!(!d.sample_once()); // recovery
        assert!(!d.sample_once());
        assert_eq!(d.flap_count(), 0);
    }

    #[test]
    fn sustained_down_triggers_one_flap() {
        let m = ScriptedMonitor::new(&[
            InterfaceState::Down,
            InterfaceState::Down,
            InterfaceState::Down,
        ]);
        let mut d = FlapDetector::new(m, 2, InterfaceState::Up);
        assert!(!d.sample_once()); // streak=1
        assert!(d.sample_once()); // streak=2 -> confirmed flap
        assert!(!d.sample_once()); // still down, no new event
        assert_eq!(d.flap_count(), 1);
        assert_eq!(d.current_state(), InterfaceState::Down);
        assert!(d.recently_flapped(Duration::from_secs(60)));
    }

    #[test]
    fn recovery_then_down_flaps_again() {
        let m = ScriptedMonitor::new(&[
            InterfaceState::Down,
            InterfaceState::Down,
            InterfaceState::Up,
            InterfaceState::Down,
            InterfaceState::Down,
        ]);
        let mut d = FlapDetector::new(m, 2, InterfaceState::Up);
        assert!(!d.sample_once()); // Down streak=1
        assert!(d.sample_once()); // flap 1 (streak=2)
        assert!(!d.sample_once()); // recovery
        assert!(!d.sample_once()); // Down streak=1
        assert!(d.sample_once()); // flap 2
        assert_eq!(d.flap_count(), 2);
    }

    #[test]
    fn debounce_of_one_flaps_immediately() {
        let m = ScriptedMonitor::new(&[InterfaceState::Down]);
        let mut d = FlapDetector::new(m, 1, InterfaceState::Up);
        assert!(d.sample_once());
        assert_eq!(d.flap_count(), 1);
    }
}
