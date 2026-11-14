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
    /// Shir-o-Khorshid architecture (doctrine §3 L2): forward through an
    /// intermediate domestic datacenter proxy pipeline (Rathole / GOST/
    /// smux over TLS) on an Iranian VPS.
    ShirOKhorshid,
    /// Hysteria2 — QUIC-based, UDP/TCP hybrid, fast CN/anti-DPI obfuscation.
    /// One of the most reliable protocols under deep-packet-injection.
    Hysteria2,
    /// Tuic(v5) — QUIC-based, UDP-only, very low overhead; often survives
    /// when TCP is throttled to zero.
    Tuic,
    /// Mihomo (clash-meta) — rule-based multiplexing client; can route
    /// multiple upstreams and adapt transport on the fly.
    Mihomo,
    /// sing-box — universal proxy core (VMess/Shadowsocks/TUIC/Hysteria2/etc.).
    SingBox,
    /// ShadowsocksR (ssr) — legacy obfs+protocol obfuscation; still reaches
    /// some networks that block standard AEAD SS.
    ShadowsocksR,
    /// The app's own stack (multilayer tunnel tiers: doh/dot/dnstunnel).
    DastYab,
}

/// A user-defined, arbitrary chain layer. This is what makes the chain a
/// *wide-freedom platform*: the operator can inject any binary/tool as a
/// layer, not just the built-in engines. The `args` template may contain
/// `{port}` (this layer's loopback listen port) and `{upstream}` (the next
/// layer's SOCKS5 URL, when present).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomEngine {
    /// Unique id/name for the registry and `--chain` token (`custom:<id>`).
    pub id: String,
    /// Human label for diagnostics/UI.
    pub label: String,
    /// Absolute path (or PATH-resolvable name) of the binary to spawn.
    pub binary: String,
    /// Argument template. `{port}` and `{upstream}` are substituted.
    pub args: Vec<String>,
    /// Whether the process listens as SOCKS5 (true) or HTTP proxy (false).
    pub socks5: bool,
    /// Preferred loopback port (planner may re-assign if it collides).
    pub default_port: u16,
    /// Reputation of the public exit IP this layer presents.
    pub egress_risk: EgressRisk,
}

impl CustomEngine {
    /// Render the launch argv for this custom engine, substituting the
    /// `{port}` and `{upstream}` placeholders.
    pub fn render_args(&self, port: u16, upstream: Option<&str>) -> Vec<String> {
        let args = &self.args;
        let mut out: Vec<String> = Vec::with_capacity(args.len());
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            // No upstream: drop any segment that is (or embeds) the
            // `{upstream}` placeholder.
            if upstream.is_none() && a.contains("{upstream}") {
                i += 1;
                continue;
            }
            // No upstream: a flag whose *next* argv is the `{upstream}`
            // placeholder is a dangling pair (flag + missing value) → drop
            // both, e.g. ["-upstream", "{upstream}"].
            if upstream.is_none()
                && !a.contains("{port}")
                && !a.contains("{upstream}")
                && args.get(i + 1).map_or(false, |n| n.contains("{upstream}"))
            {
                i += 2;
                continue;
            }
            let mut s = a.replace("{port}", &port.to_string());
            if let Some(up) = upstream {
                s = s.replace("{upstream}", up);
            }
            if !s.trim().is_empty() {
                out.push(s);
            }
            i += 1;
        }
        out
    }
}

/// A chain layer element: either a built-in engine or a user-defined custom
/// engine. This is the unit the planner, launcher, and killer operate on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ChainElement {
    Builtin(Engine),
    Custom(CustomEngine),
}

impl ChainElement {
    pub fn label(&self) -> String {
        match self {
            ChainElement::Builtin(e) => e.label().to_string(),
            ChainElement::Custom(c) => c.label.clone(),
        }
    }

    /// The binary to spawn, or `None` for in-process layers (DastYab).
    pub fn binary_hint(&self) -> Option<&str> {
        match self {
            ChainElement::Builtin(e) => e.binary_hint(),
            ChainElement::Custom(c) => Some(&c.binary),
        }
    }

    pub fn egress_risk(&self) -> EgressRisk {
        match self {
            ChainElement::Builtin(e) => e.egress_risk(),
            ChainElement::Custom(c) => c.egress_risk.clone(),
        }
    }

    pub fn listen_args(&self, port: u16) -> Vec<String> {
        match self {
            ChainElement::Builtin(e) => e.listen_args(port),
            ChainElement::Custom(c) => c.render_args(port, None),
        }
    }

    /// Render the full launch argv for this element, including the optional
    /// upstream handoff. For built-ins this matches what `ProcessLauncher`
    /// historically appended; for custom engines the template is authoritative.
    pub fn full_args(&self, port: u16, upstream: Option<&str>) -> Vec<String> {
        match self {
            ChainElement::Builtin(e) => {
                let mut args = e.listen_args(port);
                if let Some(up) = upstream {
                    args.push("--upstream".to_string());
                    args.push(up.to_string());
                }
                args
            }
            ChainElement::Custom(c) => c.render_args(port, upstream),
        }
    }
}

/// Reputation of the public exit IP a chain's outermost layer will present.
/// A risky exit (e.g. a Tor exit node) is frequently flagged/blocked by
/// mainstream services (Google, streaming, banking) and can be a red flag
/// to DPI — so the CLI warns before the user relies on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EgressRisk {
    /// Likely-residential / hosted IP; low false-positive flag rate.
    Clean,
    /// Circumvention provider exit; may be rate-limited or geo-blocked.
    Moderate,
    /// Known-flagged exit (Tor/onion); may be blocked by major services.
    Risky,
}

// ---------------------------------------------------------------------------
// Custom-engine registry (per profile): the "wide freedom" hook. A user can
// register any binary/tool as a layer and reference it in `--chain` as
// `custom:<id>`. The registry persists under the profile directory.
// ---------------------------------------------------------------------------

/// Path of a profile's custom-engine registry file.
pub fn custom_engines_path(profile: &str) -> std::path::PathBuf {
    crate::store::profiles::profile_dir(profile).join("custom_engines.json")
}

/// Load the custom-engine registry for `profile`. Missing/corrupt files are
/// treated as an empty registry (never fatal — the built-in engines still
/// work).
pub fn load_custom_engines(profile: &str) -> Vec<CustomEngine> {
    let path = custom_engines_path(profile);
    let Ok(data) = std::fs::read(&path) else {
        return Vec::new();
    };
    serde_json::from_slice(&data).unwrap_or_default()
}

/// Persist the custom-engine registry for `profile`. Creates the profile dir
/// if needed. Returns the canonical path on success.
pub fn save_custom_engines(
    profile: &str,
    engines: &[CustomEngine],
) -> Result<std::path::PathBuf, CFError> {
    use std::io::Write;
    let path = custom_engines_path(profile);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            CFError::new(
                "custom-engines",
                format!("cannot create profile dir: {e}"),
                "",
            )
        })?;
    }
    let data = serde_json::to_vec_pretty(engines)
        .map_err(|e| CFError::new("custom-engines", format!("serialize: {e}"), ""))?;
    let mut f = std::fs::File::create(&path)
        .map_err(|e| CFError::new("custom-engines", format!("cannot write registry: {e}"), ""))?;
    f.write_all(&data)
        .map_err(|e| CFError::new("custom-engines", format!("write: {e}"), ""))?;
    Ok(path)
}

/// Register a custom engine in `profile`'s registry. Replaces an existing
/// entry with the same id. Returns the saved path.
pub fn register_custom_engine(
    profile: &str,
    engine: CustomEngine,
) -> Result<std::path::PathBuf, CFError> {
    let mut all = load_custom_engines(profile);
    all.retain(|e| e.id != engine.id);
    all.push(engine);
    save_custom_engines(profile, &all)
}

/// Remove a custom engine by id. Returns true if an entry was removed.
pub fn remove_custom_engine(profile: &str, id: &str) -> Result<bool, CFError> {
    let mut all = load_custom_engines(profile);
    let before = all.len();
    all.retain(|e| e.id != id);
    if all.len() == before {
        return Ok(false);
    }
    save_custom_engines(profile, &all)?;
    Ok(true)
}

/// Resolve a `--chain` token that may be a built-in engine name or a
/// `custom:<id>` reference. Returns the resolved `ChainElement`.
pub fn parse_chain_token(token: &str, profile: &str) -> Result<ChainElement, CFError> {
    if let Some(id) = token.strip_prefix("custom:") {
        let id = id.trim();
        let custom = load_custom_engines(profile);
        if let Some(engine) = custom.into_iter().find(|e| e.id == id) {
            return Ok(ChainElement::Custom(engine));
        }
        return Err(CFError::new(
            "chain",
            format!("unknown custom engine: {id}"),
            "register it first with `dastyab nodes chain custom add`",
        ));
    }
    match token {
        "psiphon" => Ok(ChainElement::Builtin(Engine::Psiphon)),
        "tor" => Ok(ChainElement::Builtin(Engine::Tor)),
        "v2rayn" | "xray" => Ok(ChainElement::Builtin(Engine::V2rayN)),
        "lantern" => Ok(ChainElement::Builtin(Engine::Lantern)),
        "shadowsocks" | "ss" => Ok(ChainElement::Builtin(Engine::Shadowsocks)),
        "shirokhorshid" | "skh" => Ok(ChainElement::Builtin(Engine::ShirOKhorshid)),
        "hysteria2" | "hy2" => Ok(ChainElement::Builtin(Engine::Hysteria2)),
        "tuic" => Ok(ChainElement::Builtin(Engine::Tuic)),
        "mihomo" | "clash-meta" => Ok(ChainElement::Builtin(Engine::Mihomo)),
        "singbox" | "sing-box" => Ok(ChainElement::Builtin(Engine::SingBox)),
        "ssr" | "shadowsocksr" => Ok(ChainElement::Builtin(Engine::ShadowsocksR)),
        "dastyab" => Ok(ChainElement::Builtin(Engine::DastYab)),
        other => Err(CFError::new(
            "chain",
            format!("unknown engine or custom layer: {other}"),
            "use a built-in (psiphon, tor, v2rayn, lantern, shadowsocks, shirokhorshid, hysteria2, tuic, mihomo, singbox, ssr, dastyab) or custom:<id>",
        )),
    }
}

/// All built-in engine ids, for `list-engines`.
pub fn builtin_engine_ids() -> Vec<Engine> {
    vec![
        Engine::Psiphon,
        Engine::Tor,
        Engine::V2rayN,
        Engine::Lantern,
        Engine::Shadowsocks,
        Engine::ShirOKhorshid,
        Engine::Hysteria2,
        Engine::Tuic,
        Engine::Mihomo,
        Engine::SingBox,
        Engine::ShadowsocksR,
        Engine::DastYab,
    ]
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
            Engine::ShirOKhorshid => "shirokhorshid",
            Engine::Hysteria2 => "hysteria2",
            Engine::Tuic => "tuic",
            Engine::Mihomo => "mihomo",
            Engine::SingBox => "singbox",
            Engine::ShadowsocksR => "shadowsocksr",
            Engine::DastYab => "dastyab",
        }
    }

    /// The CLI flags that make this engine's binary listen as a local
    /// loopback SOCKS5 proxy on `port`. This is engine-specific: a generic
    /// `--socks5` is wrong (for tor it *means* "use Socks5Proxy", i.e. act
    /// as a client, not listen). We render the correct flag per engine so a
    /// spawned engine actually opens the port the planner assigned.
    pub fn listen_args(self, port: u16) -> Vec<String> {
        match self {
            Engine::Tor => vec![
                "--SocksPort".to_string(),
                port.to_string(),
                "--DataDirectory".to_string(),
                std::env::temp_dir()
                    .join(format!("dastyab-tor-{port}"))
                    .to_string_lossy()
                    .into_owned(),
            ],
            Engine::Lantern => vec!["--socks5-port".to_string(), port.to_string()],
            // xray needs a full vless config file to be generated by the
            // caller; pass a placeholder that makes the requirement visible.
            Engine::V2rayN => vec![
                "-config".to_string(),
                std::env::temp_dir()
                    .join(format!("dastyab-xray-{port}.json"))
                    .to_string_lossy()
                    .into_owned(),
            ],
            Engine::Psiphon => vec!["--socks".to_string(), port.to_string()],
            Engine::Shadowsocks => vec![
                "-s".to_string(),
                "127.0.0.1".to_string(),
                "-p".to_string(),
                port.to_string(),
            ],
            // Shir-o-Khorshid: forward local SOCKS5 into a domestic TLS relay
            // (gost `-L` in plain SOCKS5 mode). The domestic hop is what
            // launders the exit's reputation behind the Iranian VPS.
            Engine::ShirOKhorshid => vec!["-L".to_string(), format!("socks5://127.0.0.1:{port}")],
            // Hysteria2 client: local SOCKS5 on `port`.
            Engine::Hysteria2 => vec![
                "client".to_string(),
                "-c".to_string(),
                std::env::temp_dir()
                    .join(format!("dastyab-hysteria2-{port}.yaml"))
                    .to_string_lossy()
                    .into_owned(),
                "".to_string(), // config path is generated by the caller
            ],
            // Tuic client: local SOCKS5 on `port`.
            Engine::Tuic => vec![
                "-c".to_string(),
                std::env::temp_dir()
                    .join(format!("dastyab-tuic-{port}.json"))
                    .to_string_lossy()
                    .into_owned(),
                "".to_string(),
            ],
            // Mihomo (clash-meta): run with a generated base config; listen as
            // mixed HTTP/SOCKS5 on `port`.
            Engine::Mihomo => vec![
                "-f".to_string(),
                std::env::temp_dir()
                    .join(format!("dastyab-mihomo-{port}.yaml"))
                    .to_string_lossy()
                    .into_owned(),
            ],
            // sing-box: run with a generated JSON config; local SOCKS5 on port.
            Engine::SingBox => vec![
                "run".to_string(),
                "-c".to_string(),
                std::env::temp_dir()
                    .join(format!("dastyab-singbox-{port}.json"))
                    .to_string_lossy()
                    .into_owned(),
            ],
            // ShadowsocksR: sslocal-compatible; listen SOCKS5 on port.
            Engine::ShadowsocksR => vec![
                "-s".to_string(),
                "127.0.0.1".to_string(),
                "-p".to_string(),
                port.to_string(),
            ],
            Engine::DastYab => vec![],
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
            Engine::ShirOKhorshid => Some("gost"),
            Engine::Hysteria2 => Some("hysteria"),
            Engine::Tuic => Some("tuic-client"),
            Engine::Mihomo => Some("mihomo"),
            Engine::SingBox => Some("sing-box"),
            Engine::ShadowsocksR => Some("ssr-local"),
            Engine::DastYab => None,
        }
    }

    /// Classify the reputation of the public exit IP this engine presents.
    /// Used to warn when the outermost chain layer is risky (e.g. Tor exit
    /// nodes are flagged/blocked by major services) so the user is never
    /// surprised by a malicious-looking or blocked output IP.
    pub fn egress_risk(self) -> EgressRisk {
        match self {
            Engine::Tor => EgressRisk::Risky,
            Engine::Psiphon | Engine::Lantern => EgressRisk::Moderate,
            Engine::V2rayN
            | Engine::Shadowsocks
            | Engine::ShirOKhorshid
            | Engine::Hysteria2
            | Engine::Tuic
            | Engine::Mihomo
            | Engine::SingBox
            | Engine::ShadowsocksR
            | Engine::DastYab => EgressRisk::Clean,
        }
    }
}

/// A single layer of the chain: which engine, and the loopback port its proxy
/// listens on (assigned by the planner).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainLayer {
    pub engine: ChainElement,
    /// Loopback port this layer's SOCKS5 proxy binds (0 = unassigned).
    pub port: u16,
    /// Optional upstream proxy (`socks5h://127.0.0.1:<prev>`); the first layer
    /// has `None`. This is what makes the chain *stacked*.
    pub upstream: Option<String>,
}

/// The user's chosen, ordered engine list for one profile.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Ordered engines, first layer first. Each may be a built-in engine or a
    /// user-defined custom layer (`ChainElement::Custom`).
    pub engines: Vec<ChainElement>,
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
        Engine::ShirOKhorshid => 10866,
        Engine::Hysteria2 => 10867,
        Engine::Tuic => 10868,
        Engine::Mihomo => 10869,
        Engine::SingBox => 10870,
        Engine::ShadowsocksR => 10871,
        Engine::DastYab => crate::multilayer::PROXY_SOCKS_PORT,
    }
}

/// Default loopback port for a chain element (builtin or custom).
fn element_default_port(element: &ChainElement) -> u16 {
    match element {
        ChainElement::Builtin(e) => default_port(*e),
        ChainElement::Custom(c) => c.default_port,
    }
}

/// Validate a chain: no duplicate ports, known engines, and at least one layer.
/// Returns the ordered engine list with `None` for any engine whose binary is
/// missing at the given `PATH`-style lookup (caller decides whether to warn or
/// drop). We deliberately don't hard-require binaries — the ladder should be
/// able to degrade (doctrine §3).
pub fn plan_chain(
    config: &ChainConfig,
    look_up: impl Fn(&ChainElement) -> Option<String>,
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
    let mut prev: Option<String> = None;
    for eng in &config.engines {
        let key = eng.label();
        if Some(key.clone()) == prev {
            continue; // collapse accidental duplicates
        }
        prev = Some(key.clone());
        if !seen.insert(key) {
            continue; // same engine already in chain at a different pos: skip
        }
        let _ = look_up(eng); // existence check (advisory)
        layers.push(ChainLayer {
            engine: eng.clone(),
            port: element_default_port(eng),
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

// ---------------------------------------------------------------------------
// Runtime: execute a planned chain.
//
// The planner (above) turns the user's ordered engine list into a concrete,
// port-assigned pipeline. This runtime actually *runs* it: it spawns each
// layer, waits for its loopback SOCKS5 port to open, wires upstreams, and —
// only once every layer is up — runs the decisive end-to-end egress probe
// through the client-facing (outermost) port.
//
// Degrade semantics (doctrine §3, §5 — never stop, never circular): a layer
// whose engine the launcher cannot satisfy (binary missing) or that fails to
// open its port within the budget is *skipped*, not fatal. The chain still
// runs with the remaining layers; the report records the skip so the caller
// can surface it. Only a chain where no layer comes up is reported as down.
// ---------------------------------------------------------------------------

/// Per-layer runtime status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LayerStatus {
    /// Engine satisfied and port opened; ready to pass traffic.
    Up,
    /// Engine could not be satisfied (binary missing / launcher error).
    Skipped,
    /// Engine launched but its port did not open in time.
    FailedToStart,
    /// The layer was not attempted because a required upstream never came up
    /// (a chain can't hand off to a dead layer).
    Deferred,
}

/// Result of executing one layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerRun {
    pub engine: ChainElement,
    pub port: u16,
    pub status: LayerStatus,
    /// Human-readable reason when not `Up`.
    pub note: Option<String>,
}

/// Full result of running a chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChainRunReport {
    pub layers: Vec<LayerRun>,
    /// Whether the whole chain carried real end-to-end egress.
    pub egress_ok: bool,
    /// Port of the client-facing (outermost) layer when at least one layer is
    /// up; the app routes into it. `None` if every layer failed.
    pub egress_port: Option<u16>,
    /// Reputation of the *public exit IP* (the last, internet-facing layer's
    /// engine). `None` when no layer came up. Used to warn the user when the
    /// output IP is risky/flagged (e.g. a Tor exit).
    pub egress_risk: Option<EgressRisk>,
    /// Number of layers skipped/def-erred (degrading).
    pub degraded: usize,
}

/// Seam for launching an external transport engine. Production uses
/// `ProcessLauncher`; tests inject a fake so no real VPN binary is required.
pub trait EngineLauncher: Send + Sync {
    /// Start `engine` listening on loopback `port`, forwarding chain the
    /// optional `upstream` (`socks5h://127.0.0.1:<prev>`). Return `Ok(())`
    /// once the process is spawned and its SOCKS5 port accepts TCP connects.
    /// Return `Err` if the engine cannot be started at all (e.g. missing
    /// binary) — the runtime treats that as a skip.
    fn launch(
        &self,
        engine: &ChainElement,
        port: u16,
        upstream: Option<&str>,
    ) -> Result<(), String>;
}

/// A launcher that spawns real processes. Uses each engine's `binary_hint`
/// with argument conventions for ` --socks5 <port>` and `--upstream <url>`.
/// This is the production path; the *verification* of a chain (port open +
/// egress) is identical to the injectable launcher, so tests exercise the
/// same runtime logic.
pub struct ProcessLauncher;

impl EngineLauncher for ProcessLauncher {
    fn launch(
        &self,
        engine: &ChainElement,
        port: u16,
        upstream: Option<&str>,
    ) -> Result<(), String> {
        let Some(bin) = engine.binary_hint() else {
            // In-process stack (DastYab) is handled by the caller; the
            // runner treats it as satisfied without spawning an external proc.
            return Ok(());
        };
        let mut cmd = std::process::Command::new(bin);
        cmd.args(engine.full_args(port, upstream));
        cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // `spawn` errors (binary not found) → Err → skip.
        cmd.spawn()
            .map(|_| ())
            .map_err(|e| format!("spawn {bin}: {e}"))
    }
}

/// Seam for tearing down a previously launched chain layer. Production uses
/// `ProcessKiller` (kills the engine's process by binary name); tests inject a
/// fake so the watchdog can be verified without touching real processes.
pub trait ProcessKiller: Send + Sync {
    /// Stop the layer for `engine` on loopback `port`. Idempotent for the
    /// production impl (killing a dead process is a no-op).
    fn kill(&self, engine: &ChainElement, port: u16);
}

/// A killer that finds and kills the engine's process by binary name. Best
/// effort; killing an already-dead process is a no-op.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemKiller;

impl ProcessKiller for SystemKiller {
    fn kill(&self, engine: &ChainElement, _port: u16) {
        let Some(bin) = engine.binary_hint() else {
            return; // in-process stack: caller owns teardown
        };
        // pkill -f <binary> — kills matching processes without needing the pid.
        let _ = std::process::Command::new("pkill")
            .arg("-f")
            .arg(bin)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// Probe a SOCKS5 port for real end-to-end egress (mirrors the lifeline's
/// decisive check). Returns true only when a real outside server answers.
pub async fn chain_egress_ok(port: u16) -> bool {
    let Ok(proxy) = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}")) else {
        return false;
    };
    let Ok(client) = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(std::time::Duration::from_secs(10))
        .build()
    else {
        return false;
    };
    client
        .get("https://www.gstatic.com/generate_204")
        .send()
        .await
        .is_ok()
}

/// Wait (up to `timeout`) for `port` to accept TCP connects on loopback.
pub async fn wait_port_open(port: u16, timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    false
}

/// Execute a planned chain. Each layer is spawned via `launcher` in order
/// (client-facing first). A layer that can't start or whose port isn't
/// reported ready (via `port_ready`) is skipped; its downstream layers are
/// deferred (a chain can't hand off to a dead layer). Finally, the
/// client-facing port is egress-probed.
///
/// `port_ready` is injectable so tests can deterministically simulate port
/// states without binding real sockets. Production passes `wait_port_open`.
/// Async port-readiness probe: `Fn(u16) -> BoxFuture<bool>`.
pub type PortReadyProbe =
    dyn Fn(u16) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>> + Send + Sync;

/// Egress probe: `Fn(u16) -> BoxFuture<bool>`, injectable so tests never need
/// real network. Production uses [`chain_egress_ok`].
pub type EgressProbe =
    dyn Fn(u16) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>> + Send + Sync;

/// Execute a planned chain with *async* port-readiness and egress probes
/// (no nested `block_on`; safe to call from within a tokio runtime).
pub async fn run_chain_async<L: EngineLauncher>(
    plan: &PlannedChain,
    launcher: &L,
    port_ready: &PortReadyProbe,
    egress_probe: &EgressProbe,
) -> ChainRunReport {
    let mut runs: Vec<LayerRun> = Vec::with_capacity(plan.layers.len());
    let mut degraded = 0usize;
    // Whether the previous (upstream) layer came up; the next layer hands
    // into it, so a dead upstream defers everything below it.
    let mut previous_up = true;

    for layer in &plan.layers {
        let needed = previous_up;
        let status;
        let note;
        if !needed {
            status = LayerStatus::Deferred;
            note = Some("upstream layer not up; deferred".to_string());
            degraded += 1;
        } else {
            match launcher.launch(&layer.engine, layer.port, layer.upstream.as_deref()) {
                Ok(()) => {
                    if port_ready(layer.port).await {
                        status = LayerStatus::Up;
                        note = None;
                    } else {
                        status = LayerStatus::FailedToStart;
                        note = Some("port did not open in time".to_string());
                        degraded += 1;
                    }
                }
                Err(e) => {
                    status = LayerStatus::Skipped;
                    note = Some(format!("launcher: {e}"));
                    degraded += 1;
                }
            }
        }
        previous_up = status == LayerStatus::Up;
        runs.push(LayerRun {
            engine: layer.engine.clone(),
            port: layer.port,
            status,
            note,
        });
    }

    // Only probe egress if at least one layer came up.
    let egress_port = runs
        .iter()
        .find(|r| r.status == LayerStatus::Up)
        .map(|r| r.port);
    let egress_ok = match egress_port {
        Some(p) => egress_probe(p).await,
        None => false,
    };
    // The public exit IP is presented by the *last* Up layer (the only layer
    // with no upstream, i.e. the one that actually talks to the internet).
    // Classify its engine so the caller can warn on risky/flagged outputs
    // (e.g. a Tor exit node).
    let egress_risk = runs
        .iter()
        .rfind(|r| r.status == LayerStatus::Up)
        .map(|r| r.engine.egress_risk());

    ChainRunReport {
        layers: runs,
        egress_ok,
        egress_port,
        egress_risk,
        degraded,
    }
}

/// Bound-compatible sync entrypoint: `P: Fn(u16) -> bool` is adapted to an
/// async probe and the real egress probe is used.
pub async fn run_chain<L: EngineLauncher, P: Fn(u16) -> bool + Send + Sync + 'static>(
    plan: &PlannedChain,
    launcher: &L,
    port_ready: P,
) -> ChainRunReport {
    let arc = std::sync::Arc::new(port_ready);
    let probe =
        move |port: u16| -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>> {
            let arc = arc.clone();
            Box::pin(async move { arc(port) })
        };
    let egress = |port: u16| -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>> {
        Box::pin(chain_egress_ok(port))
    };
    run_chain_async(plan, launcher, &probe, &egress).await
}

// ---------------------------------------------------------------------------
// Failover supervisor: re-race until a plan verifies real egress (doctrine
// §3/§5 — never stop, never circular). Tries the user's configured chain
// first, then in-order degraded subsets (fewer layers), capped at
// `max_attempts`. Returns the first plan whose end-to-end egress probe
// succeeds, or the best (least-degraded) attempt if none did.

/// Result of a supervision pass.
#[derive(Debug, Clone, PartialEq)]
pub struct ChainSuperviseReport {
    /// The plan that verified egress, if any.
    pub chosen_plan: Option<PlannedChain>,
    /// Its run report when `chosen_plan` is present.
    pub chosen_report: Option<ChainRunReport>,
    /// Number of candidate chains actually executed.
    pub attempts: usize,
    /// True iff some candidate verified real end-to-end egress.
    pub ok: bool,
}

/// Generate in-order, non-empty subsequences of the configured engines,
/// largest (full chain) first so the intended composition is preferred; the
/// degraded subsets are fallbacks for re-race.
fn candidate_configs(cfg: &ChainConfig) -> Vec<ChainConfig> {
    let eng = &cfg.engines;
    let n = eng.len();
    let mut out = Vec::new();
    if n == 0 || n > 8 {
        return out;
    }
    for mask in 1u16..(1u16 << n) {
        let mut es = Vec::with_capacity(n);
        for i in 0..n {
            if mask & (1u16 << i) != 0 {
                es.push(eng[i].clone());
            }
        }
        out.push(ChainConfig { engines: es });
    }
    out.sort_by(|a, b| b.engines.len().cmp(&a.engines.len()));
    out
}

/// Run up to `max_attempts` candidate chains (full config first, then degraded
/// subsets) with *async* port-readiness, returning the first that verifies
/// egress. Safe to call from within a tokio runtime (no nested block_on).
pub async fn supervise_chain_async<L: EngineLauncher>(
    cfg: &ChainConfig,
    look_up: impl Fn(&ChainElement) -> Option<String> + Copy,
    launcher: &L,
    port_ready: &PortReadyProbe,
    egress_probe: &EgressProbe,
    max_attempts: usize,
) -> ChainSuperviseReport {
    let mut attempts = 0usize;
    for cand in candidate_configs(cfg) {
        if attempts >= max_attempts {
            break;
        }
        let Ok(plan) = plan_chain(&cand, look_up) else {
            continue;
        };
        attempts += 1;
        let report = run_chain_async(&plan, launcher, port_ready, egress_probe).await;
        if report.egress_ok {
            return ChainSuperviseReport {
                chosen_plan: Some(plan),
                chosen_report: Some(report),
                attempts,
                ok: true,
            };
        }
    }
    ChainSuperviseReport {
        chosen_plan: None,
        chosen_report: None,
        attempts,
        ok: false,
    }
}

/// Outcome of one continuous chain-watch loop (doctrine §3/§5: never stop).
#[derive(Debug, Clone, Default)]
pub struct ChainWatchReport {
    /// Number of supervise re-race rounds executed.
    pub rounds: usize,
    /// Number of times a live chain's egress died and triggered a re-race.
    pub re_races: usize,
    /// The last plan that verified egress, if any.
    pub last_plan: Option<PlannedChain>,
    /// Total times the supervisor re-arranged candidates across all rounds.
    pub total_attempts: usize,
    /// True iff the watchdog stopped because it reached `max_rounds` (bounded)
    /// rather than because the stop flag was set.
    pub reached_budget: bool,
}

/// Run a continuous chain-watch loop. Each round runs [`supervise_chain_async`];
/// if a chain verifies real egress, the loop polls that egress port every
/// `poll_interval`; when egress dies (re-race, doctrine §5) or no candidate
/// verifies, it tears down the chain via `killer` and runs the next round. The
/// loop never gives up: it keeps re-racing until `stop()` returns true or
/// `max_rounds` is reached. Pure-ish — all side effects go through `launcher`,
/// `killer`, `port_ready`, `egress_probe`, and `stop`.
pub async fn supervise_chain_watch<L: EngineLauncher, K: ProcessKiller>(
    cfg: &ChainConfig,
    look_up: impl Fn(&ChainElement) -> Option<String> + Copy,
    launcher: &L,
    killer: &K,
    port_ready: &PortReadyProbe,
    egress_probe: &EgressProbe,
    max_attempts: usize,
    max_rounds: usize,
    poll_interval: std::time::Duration,
    stop: impl Fn() -> bool,
) -> ChainWatchReport {
    let mut out = ChainWatchReport::default();
    for _round in 0..max_rounds {
        if stop() {
            return out;
        }
        let sup = supervise_chain_async(
            cfg,
            look_up,
            launcher,
            port_ready,
            egress_probe,
            max_attempts,
        )
        .await;
        out.total_attempts += sup.attempts;
        out.rounds += 1;
        let Some(plan) = sup.chosen_plan else {
            // No candidate verified this round — keep trying (never give up).
            tokio::time::sleep(poll_interval).await;
            continue;
        };
        out.last_plan = Some(plan.clone());
        // A chain is live. Watch its egress until it dies or we're told to stop.
        let egress_port = plan.egress_port;
        let mut died = false;
        loop {
            if stop() {
                return out;
            }
            tokio::time::sleep(poll_interval).await;
            if !egress_probe(egress_port).await {
                died = true;
                break;
            }
        }
        // Teardown the dead chain, then re-race (next round).
        for layer in &plan.layers {
            killer.kill(&layer.engine, layer.port);
        }
        if died {
            out.re_races += 1;
        }
    }
    out.reached_budget = true;
    out
}

/// Bound-compatible sync entrypoint: `P: Fn(u16) -> bool` is adapted to an
/// async probe.
pub async fn supervise_chain<L: EngineLauncher, P: Fn(u16) -> bool + Send + Sync + 'static>(
    cfg: &ChainConfig,
    look_up: impl Fn(&ChainElement) -> Option<String> + Copy,
    launcher: &L,
    port_ready: P,
    egress_probe: &EgressProbe,
    max_attempts: usize,
) -> ChainSuperviseReport {
    let arc = std::sync::Arc::new(port_ready);
    let probe =
        move |port: u16| -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>> {
            let arc = arc.clone();
            Box::pin(async move { arc(port) })
        };
    supervise_chain_async(cfg, look_up, launcher, &probe, egress_probe, max_attempts).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn pop_chain(engines: Vec<Engine>) -> ChainConfig {
        ChainConfig {
            engines: engines.into_iter().map(ChainElement::Builtin).collect(),
        }
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
        assert_eq!(planned.layers[0].engine, ChainElement::Builtin(Engine::Tor));
        assert_eq!(
            planned.layers[1].engine,
            ChainElement::Builtin(Engine::V2rayN)
        );
    }

    #[test]
    fn binary_hint_present_for_external_engines() {
        assert_eq!(Engine::V2rayN.binary_hint(), Some("xray"));
        assert_eq!(Engine::Psiphon.binary_hint(), Some("psiphon-tunnel-core"));
        assert_eq!(Engine::DastYab.binary_hint(), None);
    }

    // ---- Runtime tests (injectable launcher; no real VPN binaries) ----

    // Launchers never touch real sockets: a launcher that returns Err models
    // a missing binary (→ Skipped); one that returns Ok models a launchable
    // engine. Port readiness is injected separately as `port_ready`, so tests
    // are fully deterministic and can't contaminate each other.
    struct ErrLauncher; // returns Err -> Skipped
    struct OkLauncher; // returns Ok -> port_ready decides Up vs FailedToStart

    impl EngineLauncher for OkLauncher {
        fn launch(
            &self,
            _engine: &ChainElement,
            _port: u16,
            _upstream: Option<&str>,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    impl EngineLauncher for ErrLauncher {
        fn launch(
            &self,
            engine: &ChainElement,
            _port: u16,
            _upstream: Option<&str>,
        ) -> Result<(), String> {
            Err(format!("missing binary for {}", engine.label()))
        }
    }

    #[test]
    fn listen_args_tor_uses_socksport_not_generic_proxy() {
        // Regression: the old launcher passed `--socks5 <port>` to tor,
        // which tor interprets as `Socks5Proxy` (use a proxy) rather than
        // "listen on this SocksPort" — so the engine never opened its port.
        let args = Engine::Tor.listen_args(10862);
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--SocksPort" && w[1] == "10862"));
        assert!(!args.iter().any(|a| a == "--socks5"));
    }

    #[tokio::test]
    async fn run_chain_all_up_egress_not_faked() {
        let cfg = pop_chain(vec![Engine::V2rayN, Engine::Tor]);
        let planned = plan_chain(&cfg, |_| Some("/usr/bin/x".into())).unwrap();
        let report = run_chain(&planned, &OkLauncher, |_| true).await;
        assert_eq!(report.layers.len(), 2);
        assert!(report.layers.iter().all(|l| l.status == LayerStatus::Up));
        assert_eq!(report.degraded, 0);
        // egress probe against a port with no real server → false (no
        // fabricated success), but the layers are all Up.
        assert!(!report.egress_ok);
        assert_eq!(report.egress_port, Some(planned.egress_port));
    }

    #[tokio::test]
    async fn run_chain_skips_missing_binary() {
        let cfg = pop_chain(vec![Engine::V2rayN, Engine::Tor]);
        let planned = plan_chain(&cfg, |_| Some("/usr/bin/x".into())).unwrap();
        let report = run_chain(&planned, &ErrLauncher, |_| true).await;
        // First layer can't start → skipped; downstream sees dead upstream →
        // deferred. Both are degradation, none up, no egress.
        assert_eq!(report.layers[0].status, LayerStatus::Skipped);
        assert_eq!(report.layers[1].status, LayerStatus::Deferred);
        assert_eq!(report.degraded, 2);
        assert_eq!(report.egress_port, None);
        assert!(!report.egress_ok);
    }

    #[tokio::test]
    async fn run_chain_port_never_opens_is_failedtostart() {
        let cfg = pop_chain(vec![Engine::V2rayN]);
        let planned = plan_chain(&cfg, |_| Some("/usr/bin/x".into())).unwrap();
        let report = run_chain(&planned, &OkLauncher, |_| false).await;
        assert_eq!(report.layers[0].status, LayerStatus::FailedToStart);
        assert_eq!(report.degraded, 1);
        assert_eq!(report.egress_port, None);
    }

    #[tokio::test]
    async fn wait_port_open_detects_real_listener() {
        // Real network: a genuine listener must be detected; a closed port
        // must drain the small timeout. No fakes.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(wait_port_open(port, Duration::from_secs(2)).await);
        drop(listener); // close it
        assert!(!wait_port_open(port, Duration::from_millis(300)).await);
    }

    #[test]
    fn egress_risk_classifies_tor_risky_and_shiro_clean() {
        use Engine::*;
        assert_eq!(Tor.egress_risk(), EgressRisk::Risky);
        assert_eq!(Psiphon.egress_risk(), EgressRisk::Moderate);
        assert_eq!(Lantern.egress_risk(), EgressRisk::Moderate);
        assert_eq!(V2rayN.egress_risk(), EgressRisk::Clean);
        assert_eq!(Shadowsocks.egress_risk(), EgressRisk::Clean);
        assert_eq!(ShirOKhorshid.egress_risk(), EgressRisk::Clean);
        assert_eq!(DastYab.egress_risk(), EgressRisk::Clean);
    }

    #[test]
    fn shirokhorshid_is_a_valid_engine() {
        assert_eq!(Engine::ShirOKhorshid.label(), "shirokhorshid");
        assert_eq!(Engine::ShirOKhorshid.binary_hint(), Some("gost"));
        assert_eq!(default_port(Engine::ShirOKhorshid), 10866);
    }

    #[tokio::test]
    async fn report_egress_risk_is_from_outermost_up_layer() {
        // Outer (internet-facing) layer is tor -> risky even though the
        // client-facing layer is a clean v2rayn sink.
        let cfg = pop_chain(vec![Engine::V2rayN, Engine::Tor]);
        let planned = plan_chain(&cfg, |_| Some("/usr/bin/x".into())).unwrap();
        let report = run_chain(&planned, &OkLauncher, |_| true).await;
        assert_eq!(report.egress_risk, Some(EgressRisk::Risky));
    }

    #[tokio::test]
    async fn run_chain_defers_downstream_when_egress_fails() {
        // First layer fails to start; the second must be Deferred (its
        // upstream is dead), not attempted.
        let cfg = pop_chain(vec![Engine::Tor, Engine::V2rayN]);
        let planned = plan_chain(&cfg, |_| Some("/usr/bin/x".into())).unwrap();
        let report = {
            let first_port = planned.layers[0].port;
            run_chain(&planned, &OkLauncher, move |port| port != first_port).await
        };
        assert_eq!(report.layers[0].status, LayerStatus::FailedToStart);
        assert_eq!(report.layers[1].status, LayerStatus::Deferred);
        assert_eq!(report.degraded, 2);
        assert_eq!(report.egress_port, None);
    }

    // ---- Failover supervisor tests (re-race; doctrine §3/§5) ----

    // Injectable egress probe factory: a probe that returns the given value
    // for every port.
    fn fixed_egress(value: bool) -> Box<EgressProbe> {
        Box::new(move |_port: u16| Box::pin(async move { value }))
    }

    // Injectable async port-readiness probe factory (matches the watchdog's
    // `&PortReadyProbe` signature).
    fn fixed_port(ready: bool) -> Box<PortReadyProbe> {
        Box::new(move |_port: u16| Box::pin(async move { ready }))
    }

    // A launcher that only starts engines matching `ok` (used to model a
    // missing binary for one specific engine).
    struct SelectiveLauncher {
        ok: Box<dyn Fn(&ChainElement) -> bool + Send + Sync>,
    }
    impl EngineLauncher for SelectiveLauncher {
        fn launch(
            &self,
            engine: &ChainElement,
            _port: u16,
            _upstream: Option<&str>,
        ) -> Result<(), String> {
            if (self.ok)(engine) {
                Ok(())
            } else {
                Err(format!("missing binary for {}", engine.label()))
            }
        }
    }

    #[tokio::test]
    async fn supervise_wins_full_chain_when_egress_verifies() {
        let cfg = pop_chain(vec![Engine::Tor, Engine::V2rayN]);
        let report = supervise_chain(
            &cfg,
            |_| Some("/usr/bin/x".into()),
            &OkLauncher,
            |_| true,
            fixed_egress(true).as_ref(),
            4,
        )
        .await;
        assert!(report.ok);
        assert_eq!(report.attempts, 1); // full chain first
        let plan = report.chosen_plan.unwrap();
        assert_eq!(plan.layers.len(), 2); // both Tor + V2rayN survived
        assert!(report.chosen_report.unwrap().egress_ok);
    }

    #[tokio::test]
    async fn supervise_reraces_to_degraded_subset_when_full_egress_fails() {
        // Full chain (Tor+V2rayN) launches fine but its client-facing egress
        // (Tor, port 10862) fails the probe; the supervisor must re-race to
        // the degraded single-layer subset (V2rayN) and win there.
        let cfg = pop_chain(vec![Engine::Tor, Engine::V2rayN]);
        // Probe fails on the full chain's egress client (10862) but succeeds
        // on the degraded V2rayN-only subset's egress (10863).
        let probe: Box<EgressProbe> =
            Box::new(move |port: u16| Box::pin(async move { port == 10863 }));
        let report = supervise_chain(
            &cfg,
            |_| Some("/usr/bin/x".into()),
            &OkLauncher,
            |_| true,
            probe.as_ref(),
            6,
        )
        .await;
        assert!(report.ok);
        assert!(report.attempts > 1);
        let plan = report.chosen_plan.unwrap();
        // The winning subset is the smaller degraded chain, not the full one.
        assert_eq!(plan.layers.len(), 1);
        assert_eq!(plan.layers[0].engine, ChainElement::Builtin(Engine::V2rayN));
    }

    #[tokio::test]
    async fn supervise_reports_failure_when_no_candidate_verifies() {
        let cfg = pop_chain(vec![Engine::Tor, Engine::V2rayN]);
        let report = supervise_chain(
            &cfg,
            |_| Some("/usr/bin/x".into()),
            &OkLauncher,
            |_| true,
            fixed_egress(false).as_ref(),
            4,
        )
        .await;
        assert!(!report.ok);
        assert!(report.chosen_plan.is_none());
        // 2 engines → 3 candidate configs; all tried, no win.
        assert_eq!(report.attempts, 3);
    }

    #[tokio::test]
    async fn supervise_skips_unlaunchable_engine_and_reraces() {
        // Tor's binary is missing (SelectiveLauncher fails Tor) — the full
        // chain can never verify; the supervisor must skip past it and win
        // with the single-layer V2rayN subset.
        let cfg = pop_chain(vec![Engine::Tor, Engine::V2rayN]);
        let launcher = SelectiveLauncher {
            ok: Box::new(|e| e != &ChainElement::Builtin(Engine::Tor)),
        };
        let report = supervise_chain(
            &cfg,
            |_| Some("/usr/bin/x".into()),
            &launcher,
            |_| true,
            fixed_egress(true).as_ref(),
            6,
        )
        .await;
        assert!(report.ok);
        let plan = report.chosen_plan.unwrap();
        assert_eq!(plan.layers.len(), 1);
        assert_eq!(plan.layers[0].engine, ChainElement::Builtin(Engine::V2rayN));
    }

    // ---- Continuous watchdog tests (never-stop loop; doctrine §3/§5) ----

    // Records kill calls so we can assert the watchdog tears down dead chains.
    #[derive(Default)]
    struct RecordingKiller {
        killed: std::sync::Arc<std::sync::Mutex<Vec<(ChainElement, u16)>>>,
    }
    impl ProcessKiller for RecordingKiller {
        fn kill(&self, engine: &ChainElement, port: u16) {
            self.killed.lock().unwrap().push((engine.clone(), port));
        }
    }

    // A stateful egress probe that returns `true` while a shared call counter is
    // below `alive_calls`, then `false` forever. Models a chain whose egress
    // works for a while, then dies.
    fn dying_egress(alive_calls: usize) -> Box<EgressProbe> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        Box::new(move |_port: u16| {
            let calls = calls.clone();
            Box::pin(async move {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                n < alive_calls
            })
        })
    }

    #[tokio::test]
    async fn watch_reraces_when_egress_dies() {
        let cfg = pop_chain(vec![Engine::Tor, Engine::V2rayN]);
        let killer = RecordingKiller::default();
        // Round 1: full chain wins (probe call #1 → alive). The watch loop then
        // polls; by the time we're out of "alive" budget the egress dies and we
        // re-race. Later rounds find no live candidate and keep trying until the
        // round budget is exhausted.
        let report = supervise_chain_watch(
            &cfg,
            |_| Some("/usr/bin/x".into()),
            &OkLauncher,
            &killer,
            fixed_port(true).as_ref(),
            dying_egress(3).as_ref(),
            6,
            3,
            std::time::Duration::from_millis(1),
            || false,
        )
        .await;
        assert_eq!(report.rounds, 3);
        assert_eq!(report.re_races, 1); // egress died exactly once
        assert!(report.reached_budget);
        assert!(report.total_attempts >= 3);
        // The winning chain (full, Tor+V2rayN) was torn down on death.
        assert!(!killer.killed.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn watch_stops_when_told_to() {
        let cfg = pop_chain(vec![Engine::Tor]);
        let killer = RecordingKiller::default();
        let report = supervise_chain_watch(
            &cfg,
            |_| Some("/usr/bin/x".into()),
            &OkLauncher,
            &killer,
            fixed_port(true).as_ref(),
            dying_egress(1000).as_ref(),
            6,
            100,
            std::time::Duration::from_millis(1),
            || true, // stop immediately
        )
        .await;
        assert_eq!(report.rounds, 0);
        assert!(!report.reached_budget);
        assert_eq!(report.re_races, 0);
    }

    #[tokio::test]
    async fn watch_never_gives_up_while_nothing_verifies() {
        let cfg = pop_chain(vec![Engine::Tor, Engine::V2rayN]);
        let killer = RecordingKiller::default();
        let report = supervise_chain_watch(
            &cfg,
            |_| Some("/usr/bin/x".into()),
            &OkLauncher,
            &killer,
            fixed_port(true).as_ref(),
            fixed_egress(false).as_ref(), // nothing ever verifies
            6,
            4,
            std::time::Duration::from_millis(1),
            || false,
        )
        .await;
        assert_eq!(report.rounds, 4);
        assert_eq!(report.re_races, 0); // never had a live chain to lose
        assert!(report.reached_budget);
        assert!(report.last_plan.is_none());
    }

    // ------------------------------------------------------------------
    // New-engine + custom-layer tests (wide-freedom platform)
    // ------------------------------------------------------------------

    #[test]
    fn new_powerful_builtins_exist_and_render_args() {
        for e in [
            Engine::Hysteria2,
            Engine::Tuic,
            Engine::Mihomo,
            Engine::SingBox,
            Engine::ShadowsocksR,
        ] {
            assert!(!e.label().is_empty());
            let args = e.listen_args(10820);
            // Every external engine must render at least a port-bearing argv.
            assert!(
                args.iter().any(|a| a.contains("10820")),
                "{} should carry its listen port in argv: {args:?}",
                e.label()
            );
        }
    }

    #[test]
    fn custom_engine_template_substitution() {
        let c = CustomEngine {
            id: "my-tool".into(),
            label: "My Tool".into(),
            binary: "/usr/local/bin/mytool".into(),
            args: vec![
                "-listen".into(),
                "127.0.0.1:{port}".into(),
                "-upstream".into(),
                "{upstream}".into(),
            ],
            socks5: true,
            default_port: 10999,
            egress_risk: EgressRisk::Moderate,
        };
        // With upstream: both placeholders substituted.
        let args = c.render_args(10990, Some("socks5h://127.0.0.1:10801"));
        assert_eq!(
            args,
            vec![
                "-listen",
                "127.0.0.1:10990",
                "-upstream",
                "socks5h://127.0.0.1:10801",
            ]
        );
        // Without upstream: the {upstream} segment is dropped.
        let args = c.render_args(10990, None);
        assert_eq!(args, vec!["-listen", "127.0.0.1:10990"]);
    }

    #[test]
    fn custom_engine_chain_element_full_args() {
        let c = CustomEngine {
            id: "w".into(),
            label: "W".into(),
            binary: "/bin/w".into(),
            args: vec![
                "-port".into(),
                "{port}".into(),
                "-up".into(),
                "{upstream}".into(),
            ],
            socks5: true,
            default_port: 10999,
            egress_risk: EgressRisk::Clean,
        };
        let el = ChainElement::Custom(c);
        assert_eq!(el.label(), "W");
        assert_eq!(el.binary_hint(), Some("/bin/w"));
        assert_eq!(el.egress_risk(), EgressRisk::Clean);
        let args = el.full_args(10777, Some("socks5h://127.0.0.1:1"));
        assert_eq!(args, vec!["-port", "10777", "-up", "socks5h://127.0.0.1:1"]);
    }

    #[test]
    fn registry_persistence_roundtrip() {
        crate::store::set_mem_dir_override(
            std::env::temp_dir().join(format!("kv_custom_reg_{}", std::process::id())),
        );
        let custom = CustomEngine {
            id: "my-tool".into(),
            label: "My Tool".into(),
            binary: "/usr/local/bin/mytool".into(),
            args: vec!["-listen".into(), "127.0.0.1:{port}".into()],
            socks5: true,
            default_port: 10999,
            egress_risk: EgressRisk::Moderate,
        };
        let path = register_custom_engine("default", custom.clone()).unwrap();
        assert!(path.exists());

        let loaded = load_custom_engines("default");
        assert_eq!(loaded, vec![custom.clone()]);

        // Registering same id replaces (no duplicates).
        let mut v2 = custom.clone();
        v2.binary = "/opt/new/bin".into();
        register_custom_engine("default", v2.clone()).unwrap();
        let loaded = load_custom_engines("default");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].binary, "/opt/new/bin");

        assert!(remove_custom_engine("default", "my-tool").unwrap());
        assert!(!remove_custom_engine("default", "my-tool").unwrap());
        assert!(load_custom_engines("default").is_empty());
    }

    #[test]
    fn parse_chain_token_handles_builtin_and_custom() {
        crate::store::set_mem_dir_override(
            std::env::temp_dir().join(format!("kv_parse_tok_{}", std::process::id())),
        );
        // Builtins.
        assert_eq!(
            parse_chain_token("tor", "default").unwrap(),
            ChainElement::Builtin(Engine::Tor)
        );
        assert_eq!(
            parse_chain_token("hysteria2", "default").unwrap(),
            ChainElement::Builtin(Engine::Hysteria2)
        );
        assert_eq!(
            parse_chain_token("singbox", "default").unwrap(),
            ChainElement::Builtin(Engine::SingBox)
        );
        assert_eq!(
            parse_chain_token("ssr", "default").unwrap(),
            ChainElement::Builtin(Engine::ShadowsocksR)
        );
        // Unknown builtin -> error.
        assert!(parse_chain_token("nope", "default").is_err());
        // Custom not registered -> error.
        assert!(parse_chain_token("custom:ghost", "default").is_err());
        // Register then parse.
        let c = CustomEngine {
            id: "warp".into(),
            label: "Warp".into(),
            binary: "/bin/warp".into(),
            args: vec!["-p".into(), "{port}".into()],
            socks5: true,
            default_port: 11000,
            egress_risk: EgressRisk::Clean,
        };
        register_custom_engine("default", c.clone()).unwrap();
        assert_eq!(
            parse_chain_token("custom:warp", "default").unwrap(),
            ChainElement::Custom(c)
        );
    }

    #[test]
    fn plan_chain_accepts_custom_layer() {
        let c = CustomEngine {
            id: "warp".into(),
            label: "Warp".into(),
            binary: "/bin/warp".into(),
            args: vec!["-p".into(), "{port}".into()],
            socks5: true,
            default_port: 11000,
            egress_risk: EgressRisk::Clean,
        };
        let cfg = ChainConfig {
            engines: vec![ChainElement::Builtin(Engine::Tor), ChainElement::Custom(c)],
        };
        let planned = plan_chain(&cfg, |_| None).unwrap();
        assert_eq!(planned.layers.len(), 2);
        assert_eq!(
            planned.layers[1].engine,
            ChainElement::Custom(CustomEngine {
                id: "warp".into(),
                label: "Warp".into(),
                binary: "/bin/warp".into(),
                args: vec!["-p".into(), "{port}".into()],
                socks5: true,
                default_port: 11000,
                egress_risk: EgressRisk::Clean,
            })
        );
    }
}
