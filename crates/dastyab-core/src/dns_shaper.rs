//! DNS Traffic Shaper (doctrine §5 — entropy shaping).
//!
//! A DNS tunnel that emits a steady, fixed-size stream of QNAMEs is a perfect
//! traffic-analysis fingerprint: a DPI box sees a metronome of syntactically
//! identical queries and trivially blocks or QoS-throttles it. This module
//! makes the *outbound tunnel pattern* look like ordinary recursive-DNS
//! traffic by three levers:
//!
//! 1. **Pacing** — randomize inter-query gaps (never a fixed tick), and cap
//!    the aggregate rate so a burst never looks like a DNS flood.
//! 2. **Length padding** — snap the resulting QNAME length to discrete buckets,
//!    so the size distribution does not leak the underlying payload length
//!    (an adversary who can see "all queries are exactly 96 chars" can recover
//!    the frame length). Padding only *adds* filler up to a bucket boundary;
//!    it never lets the query exceed the DPI-safe cap.
//! 3. **Decoy queries** — intersperse plausible, real-looking lookups to
//!    unrelated domains, interleaved with tunnel frames, so the tunnel is
//!    statistically indistinguishable from ordinary browsing DNS.
//!
//! The shaper is pure and deterministic given a seeded RNG, so it is fully
//! unit-testable. It is transport-agnostic: it produces *decisions* (emit a
//! frame, emit a decoy, sleep) and the caller executes them.

use std::time::Duration;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Minimum/maximum characters a label may carry in a QNAME.
pub const MAX_LABEL: usize = 63;

/// Default DPI-safe cap for tunnel QNAMEs (Iranian ISP resolvers).
pub const MAX_QNAME_LEN: usize = 101;

/// Shaper configuration.
#[derive(Debug, Clone)]
pub struct ShaperConfig {
    /// Emit at most `max_queries_per_sec` tunnel frames (rate cap).
    pub max_queries_per_sec: u32,
    /// Lower bound of the randomized inter-query gap.
    pub min_gap: Duration,
    /// Upper bound of the randomized inter-query gap.
    pub max_gap: Duration,
    /// Probability (0.0..=1.0) that a *frame* slot is replaced by a decoy
    /// query. 0 disables decoys.
    pub decoy_prob: f64,
    /// Reference list of real, boring domains used to synthesize decoys.
    /// If empty, decoys are disabled.
    pub decoy_domains: Vec<String>,
    /// Fixed bucket sizes for QNAME-length padding. The shaper pads the query
    /// to the smallest bucket >= the natural length, capped at
    /// `MAX_QNAME_LEN`. If empty, padding is disabled.
    pub pad_buckets: Vec<usize>,
}

impl Default for ShaperConfig {
    fn default() -> Self {
        Self {
            // A slow, human-like crawl by default.
            max_queries_per_sec: 4,
            min_gap: Duration::from_millis(120),
            max_gap: Duration::from_millis(1200),
            decoy_prob: 0.25,
            decoy_domains: vec![
                "google.com".to_string(),
                "wikipedia.org".to_string(),
                "github.com".to_string(),
                "cloudflare.com".to_string(),
            ],
            pad_buckets: vec![64, 96, 101],
        }
    }
}

/// What the caller should do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShaperDecision {
    /// Send a tunnel frame whose QNAME is `padded_name`.
    EmitFrame { padded_name: String },
    /// Send a decoy query to `domain`.
    EmitDecoy { domain: String },
    /// Wait this long before the next decision.
    Sleep(Duration),
}

/// The shaper state machine. Feed it `[Shaper::step]` and execute the
/// returned decision.
pub struct DnsShaper {
    cfg: ShaperConfig,
    rng: StdRng,
}

impl DnsShaper {
    pub fn new(cfg: ShaperConfig, seed: u64) -> Self {
        Self {
            cfg,
            rng: StdRng::seed_from_u64(seed),
        }
    }

    /// Draw the next randomized inter-query gap.
    fn next_gap(&mut self) -> Duration {
        let lo = self.cfg.min_gap.as_millis() as u64;
        let hi = self.cfg.max_gap.as_millis() as u64;
        if hi <= lo {
            return self.cfg.min_gap;
        }
        let ms = self.rng.gen_range(lo..=hi);
        Duration::from_millis(ms)
    }

    /// Decide whether this slot is a decoy.
    fn is_decoy(&mut self) -> bool {
        self.cfg.decoy_prob > 0.0
            && !self.cfg.decoy_domains.is_empty()
            && self.rng.gen::<f64>() < self.cfg.decoy_prob
    }

    /// Generate a plausible decoy domain from a reference domain.
    fn decoy_domain(&mut self) -> String {
        let base = &self.cfg.decoy_domains[self.rng.gen_range(0..self.cfg.decoy_domains.len())];
        // A random subdomain of length 3-9 (alphanumeric label).
        let len = self.rng.gen_range(3..=9);
        let sub: String = (0..len)
            .map(|_| {
                const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
                CHARS[self.rng.gen_range(0..CHARS.len())] as char
            })
            .collect();
        format!("{sub}.{base}")
    }

    /// Pad a query name to the smallest bucket >= its current length, capped
    /// at `MAX_QNAME_LEN`. Returns the possible padded name. Never shortens
    /// and never exceeds the cap.
    ///
    /// Filler is inserted as a `zz`-prefixed label *immediately before* the
    /// base-domain suffix, so the result still decodes (the decoder strips
    /// `zz` filler labels).
    pub fn pad_name(&self, name: &str, base_domain: &str) -> String {
        let natural = name.len();
        if self.cfg.pad_buckets.is_empty() {
            return name.to_string();
        }
        let target = self
            .cfg
            .pad_buckets
            .iter()
            .copied()
            .filter(|&b| b >= natural)
            .min()
            .unwrap_or(MAX_QNAME_LEN)
            .min(MAX_QNAME_LEN);
        if target <= natural {
            return name.to_string();
        }
        // Split off the base-domain suffix so we can insert filler before it.
        let suffix = format!(".{base_domain}");
        let core = match name.strip_suffix(&suffix) {
            Some(c) => c,
            // If the name doesn't end with the base domain, we can't safely
            // split — return it unpadded rather than corrupt it.
            None => return name.to_string(),
        };
        // We need to add `want` characters total. A filler label costs a dot
        // plus "zz" plus its letters. So the letter count is `want - 3`.
        let want = target - natural;
        // Filler label must fit within MAX_LABEL (63) — "zz" + letters.
        let fill_chars = want.saturating_sub(3).min(MAX_LABEL.saturating_sub(2));
        if fill_chars == 0 {
            return name.to_string();
        }
        let mut filler = String::with_capacity(fill_chars + 2);
        filler.push_str("zz");
        for i in 0..fill_chars {
            filler.push((b'a' + (i % 24) as u8) as char);
        }
        format!("{core}.{filler}{suffix}")
    }

    /// Produce a decision for "we want to send a tunnel frame now".
    ///
    /// May return `Sleep` (pacing), `EmitDecoy`, or `EmitFrame`.
    pub fn step_frame(&mut self, frame_name: &str, base_domain: &str) -> ShaperDecision {
        if self.is_decoy() {
            let domain = self.decoy_domain();
            return ShaperDecision::EmitDecoy { domain };
        }
        let padded = self.pad_name(frame_name, base_domain);
        ShaperDecision::EmitFrame {
            padded_name: padded,
        }
    }

    /// Produce the next *pacing* sleep. Call this between decisions to enforce
    /// the inter-query gap.
    pub fn next_sleep(&mut self) -> Duration {
        let gap = self.next_gap();
        // Rate cap: floors the gap at 1/max_queries_per_sec.
        if self.cfg.max_queries_per_sec > 0 {
            let floor = Duration::from_secs_f64(1.0 / self.cfg.max_queries_per_sec as f64);
            if gap < floor {
                return floor;
            }
        }
        gap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_cap_floors_gap() {
        let mut cfg = ShaperConfig::default();
        cfg.max_queries_per_sec = 1000; // floor ~1ms
        cfg.min_gap = Duration::from_millis(1);
        cfg.max_gap = Duration::from_millis(2);
        let mut s = DnsShaper::new(cfg, 1);
        for _ in 0..200 {
            assert!(s.next_sleep() >= Duration::from_millis(1));
        }
    }

    #[test]
    fn pacing_gaps_fall_in_window() {
        let mut cfg = ShaperConfig::default();
        cfg.min_gap = Duration::from_millis(50);
        cfg.max_gap = Duration::from_millis(500);
        cfg.max_queries_per_sec = 0; // disable cap flooring
        let mut s = DnsShaper::new(cfg, 2);
        let mut distinct = std::collections::HashSet::new();
        for _ in 0..500 {
            let g = s.next_sleep();
            assert!(g >= Duration::from_millis(50));
            assert!(g <= Duration::from_millis(500));
            distinct.insert(g.as_millis());
        }
        assert!(distinct.len() > 1, "gaps must be jittered, not fixed");
    }

    #[test]
    fn padding_snaps_up_to_bucket_and_respects_cap() {
        let cfg = ShaperConfig::default();
        let s = DnsShaper::new(cfg, 3);
        // 60 chars -> smallest bucket >= 60 is 64. Stays under the cap.
        let name = "a".repeat(60) + ".example.com";
        assert!(
            name.len() < MAX_QNAME_LEN,
            "precondition: valid under-cap name"
        );
        let padded = s.pad_name(&name, "example.com");
        assert!(
            padded.len() >= name.len() && padded.len() <= MAX_QNAME_LEN,
            "padded len {} for natural {}",
            padded.len(),
            name.len()
        );
        // And padding to the 64 bucket must have added some filler.
        assert!(
            padded.len() > name.len(),
            "bucket padding should add filler"
        );
    }

    #[test]
    fn padding_never_shortens() {
        let cfg = ShaperConfig::default();
        let s = DnsShaper::new(cfg, 4);
        for n in [20, 50, 80, 99, 120] {
            let name = "a".repeat(n);
            let padded = s.pad_name(&name, "example.com");
            assert!(padded.len() >= n);
        }
    }

    #[test]
    fn decoy_prob_zero_disables_decoys() {
        let mut cfg = ShaperConfig::default();
        cfg.decoy_prob = 0.0;
        let mut s = DnsShaper::new(cfg, 5);
        for _ in 0..500 {
            match s.step_frame("x.example.com", "example.com") {
                ShaperDecision::EmitFrame { .. } => {}
                other => panic!("decoys must be disabled, got {other:?}"),
            }
        }
    }

    #[test]
    fn decoys_emit_plausible_domains() {
        let cfg = ShaperConfig::default();
        let mut s = DnsShaper::new(cfg, 6);
        let mut saw_decoy = false;
        for _ in 0..2000 {
            if let ShaperDecision::EmitDecoy { domain } =
                s.step_frame("f.example.com", "example.com")
            {
                saw_decoy = true;
                // Must look like sub.<ref-domain>.
                assert!(domain.contains("."), "decoy should be a FQDN: {domain}");
            }
        }
        assert!(
            saw_decoy,
            "with prob 0.25 over 2000 slots we should see a decoy"
        );
    }

    #[test]
    fn frame_decision_returns_padded_name() {
        let mut cfg = ShaperConfig::default();
        cfg.decoy_prob = 0.0;
        let mut s = DnsShaper::new(cfg, 7);
        if let ShaperDecision::EmitFrame { padded_name } = s.step_frame("short.c", "example.com") {
            assert!(!padded_name.is_empty());
        } else {
            panic!("expected frame emission");
        }
    }
}
