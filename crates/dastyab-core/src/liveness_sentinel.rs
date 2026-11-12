//! Liveness Sentinel (doctrine C).
//!
//! Silent blackholing (firewalls dropping without RST) leaves sockets
//! ESTABLISHED for minutes while the path is dead. Active probes catch this,
//! but they cost traffic and lag. The **Liveness Sentinel** observes the real
//! data path: if a route is *transmitting* — outbound bytes are flowing — but
//! sees *zero inbound bytes* for a hard threshold (~4s), the route is in a
//! half-open stall. The sentinel then emits a **soft-break** so the racing
//! engine can switch to another path without waiting for a probe timeout.
//!
//! This module is deliberately dependency-free (pure logic + `Instant`) so it
//! is trivially unit-testable and can be driven by any traffic source (the
//! TUN device read/write counters, a proxy socket's bytes, or the DNS tunnel's
//! query/reply accounting).
//!
//! Wire this into a loop:
//! ```
//! let mut sentinel = LivenessSentinel::new(ROUTE_ID, STALL_TIMEOUT);
//! // on each outbound write:
//! sentinel.record_outbound(bytes);
//! // on each inbound read:
//! sentinel.record_inbound(bytes);
//! // periodically:
//! if sentinel.check_stall(now) {
//!     soft_break(route); // switch path
//! }
//! ```

use std::time::{Duration, Instant};

/// Default half-open detection window (doctrine C: ~4s).
pub const DEFAULT_STALL_TIMEOUT: Duration = Duration::from_secs(4);

/// State of one monitored route.
#[derive(Debug, Clone)]
pub struct RouteTraffic {
    /// Bytes written outbound on this route (since the last reset).
    pub tx_bytes: u64,
    /// Bytes received inbound on this route (since the last reset).
    pub rx_bytes: u64,
    /// When outbound traffic was last observed.
    last_tx: Option<Instant>,
    /// When inbound traffic was last observed.
    last_rx: Option<Instant>,
    /// Whether the route has ever been seen alive (rx observed at least once).
    ever_seen_rx: bool,
}

impl RouteTraffic {
    fn new() -> Self {
        Self {
            tx_bytes: 0,
            rx_bytes: 0,
            last_tx: None,
            last_rx: None,
            ever_seen_rx: false,
        }
    }
}

/// Verdict of a liveness check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SentinelVerdict {
    /// Route is healthy (recent inbound traffic, or never stalled).
    Healthy,
    /// Route is in a half-open stall: transmitting but silent inbound.
    /// Caller should soft-break onto another path.
    Stalled,
    /// Route is idle (no recent outbound activity) — nothing to diagnose.
    Idle,
}

/// The liveness sentinel for a single route.
#[derive(Debug)]
pub struct LivenessSentinel {
    route_id: String,
    stall_timeout: Duration,
    traffic: RouteTraffic,
    /// Consecutive stall verdicts (used to debounce before breaking).
    stall_count: u32,
    /// Minimum consecutive stall checks before we recommend a break.
    min_stall_checks: u32,
}

impl LivenessSentinel {
    /// Create a sentinel for `route_id`.
    pub fn new(route_id: impl Into<String>, stall_timeout: Duration) -> Self {
        Self {
            route_id: route_id.into(),
            stall_timeout,
            traffic: RouteTraffic::new(),
            stall_count: 0,
            min_stall_checks: 2,
        }
    }

    /// Create with a custom debounce (stall checks before breaking).
    pub fn with_min_stall_checks(mut self, n: u32) -> Self {
        self.min_stall_checks = n.max(1);
        self
    }

    pub fn route_id(&self) -> &str {
        &self.route_id
    }

    /// Record outbound bytes.
    pub fn record_outbound(&mut self, bytes: u64) {
        self.record_outbound_at(bytes, Instant::now());
    }

    /// Record outbound bytes with an explicit timestamp (for tests / replay).
    pub fn record_outbound_at(&mut self, bytes: u64, at: Instant) {
        self.traffic.tx_bytes += bytes;
        self.traffic.last_tx = Some(at);
    }

    /// Record inbound bytes.
    pub fn record_inbound(&mut self, bytes: u64) {
        self.record_inbound_at(bytes, Instant::now());
    }

    /// Record inbound bytes with an explicit timestamp (for tests / replay).
    pub fn record_inbound_at(&mut self, bytes: u64, at: Instant) {
        self.traffic.rx_bytes += bytes;
        self.traffic.last_rx = Some(at);
        self.traffic.ever_seen_rx = true;
        // Inbound activity clears any stall accumulation.
        self.stall_count = 0;
    }

    /// Total bytes seen on the route since creation/reset.
    pub fn tx_bytes(&self) -> u64 {
        self.traffic.tx_bytes
    }
    pub fn rx_bytes(&self) -> u64 {
        self.traffic.rx_bytes
    }

    /// Reset counters (e.g. after a successful break or route reconnect).
    pub fn reset(&mut self) {
        self.traffic = RouteTraffic::new();
        self.stall_count = 0;
    }

    /// Check whether the route is stalled at `now`. Returns a verdict; when
    /// `Stalled` and the debounce threshold is reached, `should_break()` is
    /// true.
    pub fn check_stall(&mut self, now: Instant) -> SentinelVerdict {
        // If we've never seen inbound traffic yet, the route may simply be
        // establishing — do not declare a stall on a virgin route.
        if !self.traffic.ever_seen_rx {
            return SentinelVerdict::Idle;
        }

        let last_tx = match self.traffic.last_tx {
            Some(t) => t,
            None => return SentinelVerdict::Idle,
        };

        // If we're not actively transmitting right now, an idle route is not
        // a stall (nothing in flight to diagnose).
        if now.duration_since(last_tx) > self.stall_timeout {
            return SentinelVerdict::Idle;
        }

        let last_rx = self.traffic.last_rx;
        let silent_since = match last_rx {
            Some(t) => now.duration_since(t),
            None => self.stall_timeout + Duration::from_secs(1),
        };

        if silent_since >= self.stall_timeout {
            self.stall_count += 1;
            if self.stall_count >= self.min_stall_checks {
                SentinelVerdict::Stalled
            } else {
                // Still accumulating — report stalled but don't break yet.
                SentinelVerdict::Stalled
            }
        } else {
            self.stall_count = 0;
            SentinelVerdict::Healthy
        }
    }

    /// True when the route should be soft-broken (stall confirmed by enough
    /// consecutive checks).
    pub fn should_break(&self) -> bool {
        self.stall_count >= self.min_stall_checks
    }

    /// Convenience: record outbound, then check stall.
    pub fn pulse_outbound(&mut self, bytes: u64, now: Instant) -> SentinelVerdict {
        self.record_outbound(bytes);
        self.check_stall(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn healthy_route_when_receiving() {
        let mut s = LivenessSentinel::new("r1", DEFAULT_STALL_TIMEOUT);
        let now = t0();
        s.record_inbound_at(100, now);
        s.record_outbound_at(100, now);
        // Inbound is fresh (1s ago) -> healthy.
        assert_eq!(s.check_stall(now + Duration::from_secs(1)), SentinelVerdict::Healthy);
        assert!(!s.should_break());
    }

    #[test]
    fn idle_when_never_seen_inbound() {
        let mut s = LivenessSentinel::new("r2", DEFAULT_STALL_TIMEOUT);
        let now = t0();
        s.record_outbound_at(50, now);
        // Never saw inbound -> Idle (route still establishing), not stalled.
        assert_eq!(s.check_stall(now + Duration::from_secs(10)), SentinelVerdict::Idle);
        assert!(!s.should_break());
    }

    #[test]
    fn stall_detected_after_silence() {
        let mut s = LivenessSentinel::new("r3", DEFAULT_STALL_TIMEOUT);
        let now = t0();
        s.record_inbound_at(10, now); // route was alive
        s.record_outbound_at(200, now + Duration::from_secs(1)); // now transmitting
        // 5s later: still within outbound recency, inbound silent 5s -> stall.
        assert_eq!(s.check_stall(now + Duration::from_secs(5)), SentinelVerdict::Stalled);
        // Refresh transmission so it stays recent; inbound still silent -> stall again.
        s.record_outbound_at(50, now + Duration::from_secs(5));
        assert_eq!(s.check_stall(now + Duration::from_secs(6)), SentinelVerdict::Stalled);
        // Two consecutive stalls -> break.
        assert!(s.should_break());
    }

    #[test]
    fn inbound_activity_clears_stall() {
        let mut s = LivenessSentinel::new("r4", DEFAULT_STALL_TIMEOUT);
        let now = t0();
        s.record_inbound_at(10, now);
        s.record_outbound_at(200, now + Duration::from_secs(1));
        assert_eq!(s.check_stall(now + Duration::from_secs(5)), SentinelVerdict::Stalled);
        // Traffic recovers: inbound arrives -> stall cleared. Keep outbound
        // fresh (as a live transmit loop would).
        s.record_inbound_at(50, now + Duration::from_secs(5));
        s.record_outbound_at(30, now + Duration::from_secs(5));
        assert_eq!(s.check_stall(now + Duration::from_secs(6)), SentinelVerdict::Healthy);
        assert!(!s.should_break());
    }

    #[test]
    fn idle_when_not_transmitting() {
        let mut s = LivenessSentinel::new("r5", DEFAULT_STALL_TIMEOUT);
        let now = t0();
        s.record_inbound_at(10, now);
        s.record_outbound_at(100, now);
        // No outbound for a long while -> Idle (nothing in flight).
        assert_eq!(s.check_stall(now + Duration::from_secs(30)), SentinelVerdict::Idle);
        assert!(!s.should_break());
    }

    #[test]
    fn reset_clears_state() {
        let mut s = LivenessSentinel::new("r6", DEFAULT_STALL_TIMEOUT);
        let now = t0();
        s.record_inbound_at(10, now);
        s.record_outbound_at(100, now + Duration::from_secs(1));
        s.check_stall(now + Duration::from_secs(5));
        s.reset();
        assert_eq!(s.tx_bytes(), 0);
        assert_eq!(s.rx_bytes(), 0);
        assert_eq!(s.check_stall(now + Duration::from_secs(6)), SentinelVerdict::Idle);
        assert!(!s.should_break());
    }
}
