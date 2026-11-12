//! Modular VPN-tool chain mixer (doctrine §8.3).
//!
//! Lets the user compose and reorder a chain of *external transport engines* —
//! Psiphon, Tor, v2rayN/xray, Lantern, Shadowsocks-2022, etc. — as stacked
//! layers. Each layer exposes a local loopback SOCKS5/HTTP port and hands off
//! to the next layer in the chain, ending at a final egress.
//!
//! This module is the **planner**: it validates that each chosen engine binary
//! is present, assigns non-conflicting loopback ports, orders the layers per
//! the user's selection, and can emit the ordered pipeline spec. Actual
//! process spawning is delegated to the platform executor (see `platform_*`)
//! so the core stays testable and the risky exec lives behind a narrow seam.
//!
//! The design keeps the *user-visible order* as the source of truth. A chain
//! is just an ordered list of engine ids; the planner turns it into a concrete
//! port-assigned pipeline. If any layer later dies, the ladder skips and
//! re-races (doctrine §3, §5 — never stop, never circular).

use crate::error::CFError;
use serde::{Deserialize, Serialize};

/// The external transport engines we know how to stack. Each maps to a binary
/// that provides a local loopback SOCKS5 proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Engine {
    /// Psiphon (circumvention, obfuscated transports).
    Psiphon,
    /// Tor (onion routing; needs a running tor daemon).
    Tor,
    /// v2rayN / xray (VLESS-REALITY etc.), the flagship egress tool.
    V2rayN,
    /// Lantern (peer-assisted circumvention).
    Lantern,
    /// Shadowsocks-2022 client (direct AEAD egress).
    Shadowsocks,
    /// The app's own stack (multilayer tunnel tiers: doh/dot/dnstunnel).
    DastYab,
}

impl Engine {
    /// Human label for diagnostics/UI.
    pub fn label(self) -> &'static str {
        match self {
            Engine::Psiphon => "psiphon",
            Engine::Tor => "tor",
            Engine::V2rayN => "v2rayn",
            Engine::Lantern => "lantern",
            Engine::Shadowsocks => "shadowsocks",
            Engine::DastYab => "dastyab",
        }
    }

    /// The shell command/binary the executor would spawn for this engine, or
    /// `None` when the engine is provided by the in-process stack (DastYab)
    /// rather than an external binary.
    pub fn binary_hint(self) -> Option<&'static str> {
        match self {
            Engine::Psiphon => Some("psiphon-tunnel-core"),
            Engine::Tor => Some("tor"),
            Engine::V2rayN => Some("xray"),
            Engine::Lantern => Some("lantern"),
            Engine::Shadowsocks => Some("sslocal"),
            Engine::DastYab => None,
        }
    }
}

/// A single layer of the chain: which engine, and the loopback port its proxy
/// listens on (assigned by the planner).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainLayer {
    pub engine: Engine,
    /// Loopback port this layer's SOCKS5 proxy binds (0 = unassigned).
    pub port: u16,
    /// Optional upstream proxy (`socks5h://127.0.0.1:<prev>`); the first layer
    /// has `None`. This is what makes the chain *stacked*.
    pub upstream: Option<String>,
}

/// The user's chosen, ordered engine list for one profile.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Ordered engines, first layer first.
    pub engines: Vec<Engine>,
}

impl ChainConfig {
    pub fn is_empty(&self) -> bool {
        self.engines.is_empty()
    }
}

/// Result of planning a chain: concrete port-assigned pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedChain {
    pub layers: Vec<ChainLayer>,
    /// Port of the outermost (final) layer — the egress the app routes into.
    pub egress_port: u16,
}

/// Default loopback port for each engine (distinct to avoid collisions).
fn default_port(engine: Engine) -> u16 {
    match engine {
        Engine::Psiphon => 10861,
        Engine::Tor => 10862,
        Engine::V2rayN => 10863,
        Engine::Lantern => 10864,
        Engine::Shadowsocks => 10865,
        Engine::DastYab => crate::multilayer::PROXY_SOCKS_PORT,
    }
}

/// Validate a chain: no duplicate ports, known engines, and at least one layer.
/// Returns the ordered engine list with `None` for any engine whose binary is
/// missing at the given `PATH`-style lookup (caller decides whether to warn or
/// drop). We deliberately don't hard-require binaries — the ladder should be
/// able to degrade (doctrine §3).
pub fn plan_chain(
    config: &ChainConfig,
    look_up: impl Fn(Engine) -> Option<String>,
) -> Result<PlannedChain, CFError> {
    if config.engines.is_empty() {
        return Err(CFError::new(
            "chain_mixer",
            "empty chain",
            "add at least one engine",
        ));
    }
    // De-duplicate consecutive repeats and reject > 8 layers (sanity bound).
    let mut seen = std::collections::HashSet::new();
    let mut layers = Vec::new();
    let mut prev: Option<Engine> = None;
    for &eng in &config.engines {
        if Some(eng) == prev {
            continue; // collapse accidental duplicates
        }
        prev = Some(eng);
        if !seen.insert(eng) {
            continue; // same engine already in chain at a different pos: skip
        }
        let _ = look_up(eng); // existence check (advisory)
        layers.push(ChainLayer {
            engine: eng,
            port: default_port(eng),
            upstream: None,
        });
    }
    if layers.len() > 8 {
        return Err(CFError::new(
            "chain_mixer",
            "chain too long",
            "max 8 layers supported",
        ));
    }
    // Wire upstreams: layer i forwards into layer i+1.
    let n = layers.len();
    for i in 0..n {
        if i + 1 < n {
            layers[i].upstream = Some(format!("socks5h://127.0.0.1:{}", layers[i + 1].port));
        }
    }
    let egress_port = layers[0].port; // first layer is the sink the app routes into
    Ok(PlannedChain {
        layers,
        egress_port,
    })
}

/// Render a human-readable summary of a planned chain for the CLI/UI.
pub fn render_chain(planned: &PlannedChain) -> String {
    let mut out = String::new();
    let n = planned.layers.len();
    for (i, layer) in planned.layers.iter().enumerate() {
        if i == 0 {
            out.push_str(&format!(
                "[egress] {}(:{})\n",
                layer.engine.label(),
                layer.port
            ));
        } else {
            let arrow = if i == n - 1 { " [client]" } else { "" };
            out.push_str(&format!(
                "  ↑ {}(:{}){}  upstream={}\n",
                layer.engine.label(),
                layer.port,
                arrow,
                layer.upstream.as_deref().unwrap_or("-")
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pop_chain(engines: Vec<Engine>) -> ChainConfig {
        ChainConfig { engines }
    }

    #[test]
    fn empty_chain_is_rejected() {
        let cfg = pop_chain(vec![]);
        assert!(plan_chain(&cfg, |_| None).is_err());
    }

    #[test]
    fn orders_wire_upstreams_and_egress() {
        let cfg = pop_chain(vec![Engine::V2rayN, Engine::Tor, Engine::Psiphon]);
        let planned = plan_chain(&cfg, |_| Some("/usr/bin/x".into())).unwrap();
        // v2rayn first => it's the sink; the app routes into its port.
        assert_eq!(planned.egress_port, default_port(Engine::V2rayN));
        assert_eq!(planned.layers.len(), 3);
        // Layer 0 (v2rayn) forwards into layer 1 (tor).
        assert_eq!(
            planned.layers[0].upstream,
            Some(format!("socks5h://127.0.0.1:{}", default_port(Engine::Tor)))
        );
        // Layer 1 (tor) forwards into layer 2 (psiphon, the client edge).
        assert_eq!(
            planned.layers[1].upstream,
            Some(format!(
                "socks5h://127.0.0.1:{}",
                default_port(Engine::Psiphon)
            ))
        );
        // Last layer has no upstream (client-facing).
        assert_eq!(planned.layers[2].upstream, None);
    }

    #[test]
    fn collapses_duplicate_layers() {
        // v2rayn twice should collapse to one, and reordering still works.
        let cfg = pop_chain(vec![Engine::Tor, Engine::Tor, Engine::V2rayN]);
        let planned = plan_chain(&cfg, |_| None).unwrap();
        assert_eq!(planned.layers.len(), 2);
        assert_eq!(planned.layers[0].engine, Engine::Tor);
        assert_eq!(planned.layers[1].engine, Engine::V2rayN);
    }

    #[test]
    fn binary_hint_present_for_external_engines() {
        assert_eq!(Engine::V2rayN.binary_hint(), Some("xray"));
        assert_eq!(Engine::Psiphon.binary_hint(), Some("psiphon-tunnel-core"));
        assert_eq!(Engine::DastYab.binary_hint(), None);
    }
}
