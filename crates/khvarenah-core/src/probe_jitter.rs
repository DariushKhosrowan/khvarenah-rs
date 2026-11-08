//! Anti-DPI probe pacing and request jitter (DeepSeek plan, feature 1).
//!
//! A high-concurrency scanner is detectable and blockable: a fixed, dense
//! burst of probes with identical fingerprints is exactly what stateful DPI
//! flags. This module turns scanning into something that looks like ordinary
//! browsing:
//!
//! 1. **Pacing** — a global rate limiter caps probes launched per second, so
//!    we never slam an ISP with a DDoS-looking wall of connections.
//! 2. **Timing jitter** — inter-probe gaps are randomized within a window, so
//!    the request pattern is not a metronome.
//! 3. **Request randomization** — the WebSocket upgrade head is randomly
//!    re-cased / re-ordered and given a randomized Sec-WebSocket-Key, so no
//!    two probes carry identical wire bytes.
//!
//! NOTE on TLS fingerprinting: true JA3/JA4 fingerprint randomization would
//! require replacing the rustls crypto provider and is out of scope for this
//! crate. What we *can* cheaply randomize is the HTTP/WS layer and the probe
//! timing — which is the dominant anti-DPI lever for a *scanner* (the client
//! tunnel itself still uses the normal rustls stack once a config is picked).

use std::time::{Duration, Instant};

use rand::{Rng, SeedableRng};

/// Pacing + jitter configuration.
#[derive(Debug, Clone, Copy)]
pub struct JitterConfig {
    /// Maximum probes to *start* per second across the whole scan.
    pub max_probes_per_sec: u32,
    /// Randomized extra wait range applied between probe starts (ms).
    pub timing_jitter_ms: (u64, u64),
}

impl Default for JitterConfig {
    fn default() -> Self {
        Self {
            max_probes_per_sec: 80,
            timing_jitter_ms: (2, 18),
        }
    }
}

/// A lightweight paced gate. Call `acquire()` before starting each probe; it
/// enforces the global rate ceiling and injects randomized inter-probe delay.
pub struct PacedGate {
    cfg: JitterConfig,
    next_allowed: Instant,
    rng: rand::rngs::StdRng,
}

impl PacedGate {
    pub fn new(cfg: JitterConfig) -> Self {
        Self {
            cfg,
            next_allowed: Instant::now(),
            rng: rand::rngs::StdRng::from_entropy(),
        }
    }

    /// Block until we are allowed to start the next probe.
    pub async fn acquire(&mut self) {
        let per_probe = Duration::from_secs_f64(1.0 / self.cfg.max_probes_per_sec.max(1) as f64);
        let now = Instant::now();
        if now < self.next_allowed {
            tokio::time::sleep(self.next_allowed - now).await;
        }
        // Advance the schedule by one slot (plus jitter).
        let (lo, hi) = self.cfg.timing_jitter_ms;
        let jitter = if hi > lo {
            self.rng.gen_range(lo..hi)
        } else {
            lo
        };
        self.next_allowed = Instant::now() + per_probe + Duration::from_millis(jitter);
    }
}

/// Random 16-byte Sec-WebSocket-Key (base64), per RFC 6455.
pub fn random_ws_key() -> String {
    use base64::Engine as _;
    let mut bytes = [0u8; 16];
    rand::rngs::StdRng::from_entropy().fill(&mut bytes);
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Randomize the (already-built) WebSocket upgrade request: re-case the
/// method/header names and shuffle the header order to vary the wire image.
/// Returns a byte vector ready to write to the socket.
pub fn randomize_ws_request(rng: &mut impl Rng, base_req: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(base_req);
    let lines: Vec<&str> = text.lines().collect();
    // Shuffle the header lines (keep the request line first).
    if lines.len() > 1 {
        let (first, rest) = lines.split_first().unwrap();
        let mut rest = rest.to_vec();
        // Fisher–Yates partial shuffle.
        for i in (1..rest.len()).rev() {
            let j = rng.gen_range(0..=i);
            rest.swap(i, j);
        }
        let mut out = Vec::new();
        out.extend_from_slice(first.as_bytes());
        out.push(b'\r');
        out.push(b'\n');
        for line in rest {
            // Randomly flip casing of the header *name* (before the colon).
            if let Some((name, value)) = line.split_once(':') {
                if rng.gen_bool(0.5) {
                    let cased: String = name
                        .chars()
                        .map(|c| {
                            if rng.gen_bool(0.5) {
                                c.to_ascii_uppercase()
                            } else {
                                c.to_ascii_lowercase()
                            }
                        })
                        .collect();
                    out.extend_from_slice(cased.as_bytes());
                } else {
                    out.extend_from_slice(name.as_bytes());
                }
                out.push(b':');
                out.extend_from_slice(value.as_bytes());
            } else {
                out.extend_from_slice(line.as_bytes());
            }
            out.push(b'\r');
            out.push(b'\n');
        }
        out.extend_from_slice(b"\r\n");
        out
    } else {
        base_req.to_vec()
    }
}

/// Browser TLS fingerprint profiles. DeepSeek's phase-2 resurrection spec:
/// the scanner's static rustls ClientHello (identical cipher order, extension
/// order, ALPN on every probe) is a fingerprintable DPI signature. Real
/// browsers differ; by rotating through these profiles the wire image of each
/// probe changes, defeating a static-JA3-style blacklist.
///
/// NOTE: rustls does not let us reorder *extensions* or inject GREASE
/// (requires uTLS-style custom ClientHello). It DOES let us choose cipher
/// suite order and key-exchange group order via a custom [`CryptoProvider`],
/// and ALPN via [`ClientConfig::alpn_protocols`]. That is the variation we
/// apply here — enough to break a static signature, without pulling in a new
/// crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ClientHelloProfile {
    Chrome120,
    Firefox121,
    Safari17,
    Edge120,
}

impl ClientHelloProfile {
    /// All supported profiles, for random selection.
    pub const ALL: [ClientHelloProfile; 4] = [
        ClientHelloProfile::Chrome120,
        ClientHelloProfile::Firefox121,
        ClientHelloProfile::Safari17,
        ClientHelloProfile::Edge120,
    ];

    /// Preferred cipher suite order (highest first). Ordering the first
    /// entries differently is what breaks the static ClientHello signature.
    pub fn cipher_order(&self) -> &'static [rustls::CipherSuite] {
        match self {
            // Chrome 120: AES-128-GCM first, then Chacha20, then AES-256.
            ClientHelloProfile::Chrome120 => &[
                rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
                rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
            ],
            // Firefox 121: AES-128, then AES-256, then Chacha20.
            ClientHelloProfile::Firefox121 => &[
                rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
                rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
                rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            ],
            // Safari 17: Chacha20 first (Apple prefers it), then AES-128.
            ClientHelloProfile::Safari17 => &[
                rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
                rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
            ],
            // Edge 120: mirrors Chrome's list but swaps the top two.
            ClientHelloProfile::Edge120 => &[
                rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
                rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
            ],
        }
    }

    /// Preferred key-exchange group order. Different first-group = different
    /// key-share the client offers, another fingerprint lever.
    pub fn kx_order(&self) -> &'static [rustls::NamedGroup] {
        match self {
            ClientHelloProfile::Chrome120
            | ClientHelloProfile::Firefox121
            | ClientHelloProfile::Edge120 => &[
                rustls::NamedGroup::X25519,
                rustls::NamedGroup::secp256r1,
                rustls::NamedGroup::X448,
            ],
            // Safari historically leads with P-256.
            ClientHelloProfile::Safari17 => &[
                rustls::NamedGroup::secp256r1,
                rustls::NamedGroup::X25519,
                rustls::NamedGroup::X448,
            ],
        }
    }
}

/// Pick a random ClientHello profile from the supported set.
pub fn pick_client_hello_profile(rng: &mut impl rand::Rng) -> ClientHelloProfile {
    ClientHelloProfile::ALL[rng.gen_range(0..ClientHelloProfile::ALL.len())]
}

/// Reorder a provider's cipher suites: preferred order first, then any
/// remaining suites (kept so the provider stays valid — every suite still has
/// its key-exchange groups present).
fn order_cipher_suites(
    mut suites: Vec<rustls::SupportedCipherSuite>,
    preferred: &'static [rustls::CipherSuite],
) -> Vec<rustls::SupportedCipherSuite> {
    let mut ordered = Vec::with_capacity(suites.len());
    for want in preferred {
        if let Some(pos) = suites.iter().position(|s| s.suite().eq(want)) {
            ordered.push(suites.remove(pos));
        }
    }
    ordered.extend(suites);
    ordered
}

/// Reorder a provider's key-exchange groups by the profile's preference.
fn order_kx_groups(
    mut groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>,
    preferred: &'static [rustls::NamedGroup],
) -> Vec<&'static dyn rustls::crypto::SupportedKxGroup> {
    let mut ordered = Vec::with_capacity(groups.len());
    for want in preferred {
        if let Some(pos) = groups.iter().position(|g| g.name().eq(want)) {
            ordered.push(groups.remove(pos));
        }
    }
    ordered.extend(groups);
    ordered
}

/// Build a custom [`rustls::CryptoProvider`] for the given browser profile.
/// Takes the default aws-lc-rs provider and reorders its cipher suites and
/// key-exchange groups to match the profile — the cheap, valid way to vary
/// the ClientHello without new crates.
pub fn provider_for_profile(profile: ClientHelloProfile) -> rustls::crypto::CryptoProvider {
    let base = rustls::crypto::aws_lc_rs::default_provider();
    rustls::crypto::CryptoProvider {
        cipher_suites: order_cipher_suites(base.cipher_suites, profile.cipher_order()),
        kx_groups: order_kx_groups(base.kx_groups, profile.kx_order()),
        ..base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_ws_key_is_16_byte_base64() {
        let k = random_ws_key();
        assert_eq!(k.len(), 24); // 16 bytes -> 24 base64 chars (no padding var)
    }

    #[tokio::test]
    async fn paced_gate_respects_rate_limit() {
        let cfg = JitterConfig {
            max_probes_per_sec: 200,
            timing_jitter_ms: (0, 1),
        };
        let mut gate = PacedGate::new(cfg);
        let start = Instant::now();
        for _ in 0..20 {
            gate.acquire().await;
        }
        let elapsed = start.elapsed();
        // 20 probes at 200/s ≈ 100ms minimum; allow slack.
        assert!(elapsed >= Duration::from_millis(80), "elapsed {elapsed:?}");
    }

    #[test]
    fn randomize_jumbles_headers_and_keeps_request_line() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let base = b"GET /ws HTTP/1.1\r\nHost: worker.workers.dev\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        let out = randomize_ws_request(&mut rng, base);
        let txt = String::from_utf8_lossy(&out);
        assert!(txt.starts_with("GET /ws HTTP/1.1"));
        assert!(txt.contains("Upgrade"));
        assert!(txt.contains("websocket"));
        // Two randomizations must differ.
        let out2 = randomize_ws_request(&mut rng, base);
        assert_ne!(out, out2);
    }

    #[test]
    fn test_chrome_profile_has_chrome_cipher_order() {
        let p = ClientHelloProfile::Chrome120;
        let order = p.cipher_order();
        assert_eq!(order[0], rustls::CipherSuite::TLS13_AES_128_GCM_SHA256);
        assert_eq!(
            order[1],
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        );
        // Provider must actually respect that order.
        let prov = provider_for_profile(p);
        let ids: Vec<_> = prov.cipher_suites.iter().map(|s| s.suite()).collect();
        assert_eq!(ids[0], rustls::CipherSuite::TLS13_AES_128_GCM_SHA256);
    }

    #[test]
    fn test_firefox_profile_has_firefox_cipher_order() {
        let p = ClientHelloProfile::Firefox121;
        let order = p.cipher_order();
        assert_eq!(order[0], rustls::CipherSuite::TLS13_AES_128_GCM_SHA256);
        assert_eq!(order[1], rustls::CipherSuite::TLS13_AES_256_GCM_SHA384);
        let prov = provider_for_profile(p);
        let ids: Vec<_> = prov.cipher_suites.iter().map(|s| s.suite()).collect();
        assert_eq!(ids[1], rustls::CipherSuite::TLS13_AES_256_GCM_SHA384);
    }

    #[test]
    fn test_random_profile_varies_across_calls() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        // Over many draws we should see >1 distinct profile.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            seen.insert(pick_client_hello_profile(&mut rng));
        }
        assert!(seen.len() > 1, "expected variation in random profile picks");
    }
}
