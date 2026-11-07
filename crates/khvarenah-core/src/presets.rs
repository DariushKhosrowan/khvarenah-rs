//! Preset deployment profiles.
//!
//! Not every user wants the same worker behavior. This module ships curated
//! presets (name + description + compatibility date + flags + a small worker
//! template) so deploy can be one command instead of a configuration puzzle.
//! Presets are data — they are easy to extend or override per-profile later.

/// A named preset describing how a worker should be deployed.
///
/// Note: intentionally not `Serialize`/`Deserialize` because it holds
/// `&'static` slices (there is no need to persist presets — they are
/// compiled-in data).
#[derive(Debug, Clone)]
pub struct Preset {
    pub name: &'static str,
    pub description: &'static str,
    pub compatibility_date: &'static str,
    pub flags: &'static [&'static str],
    /// Default worker name stem (sanitized at deploy time).
    pub default_worker_stem: &'static str,
}

/// All built-in presets.
pub fn presets() -> Vec<Preset> {
    vec![
        Preset {
            name: "standard",
            description: "Default VLESS WebSocket worker on the latest compatibility date.",
            compatibility_date: "2026-07-01",
            flags: &["nodejs_compat"],
            default_worker_stem: "edge",
        },
        Preset {
            name: "gaming",
            description: "Low-latency profile: same stack, tuned scanning defaults (fewer workers, tighter timeout).",
            compatibility_date: "2026-07-01",
            flags: &["nodejs_compat"],
            default_worker_stem: "game-edge",
        },
        Preset {
            name: "max-compat",
            description: "Maximum compatibility: broadest flag set, useful for older CF tiers.",
            compatibility_date: "2025-01-01",
            flags: &["nodejs_compat", "global_network"],
            default_worker_stem: "compat-edge",
        },
    ]
}

/// Look up a preset by name (case-insensitive).
pub fn find(name: &str) -> Option<Preset> {
    presets()
        .into_iter()
        .find(|p| p.name.eq_ignore_ascii_case(name))
}

/// List all preset names + descriptions (for CLI help / GUI combo).
pub fn describe_all() -> String {
    let mut out = String::new();
    for p in presets() {
        out.push_str(&format!("  {} — {}\n", p.name, p.description));
    }
    out
}

/// A minimal generic worker module template the presets can deploy verbatim
/// when no `_worker.js` is found. It's a valid ES module worker that returns
/// an HTTP 200, so deploys never fail on a missing bundle.
pub fn fallback_worker_js() -> String {
    r#"export default {
  async fetch(request, env, ctx) {
    return new Response(JSON.stringify({ ok: true, service: "khvarenah" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  },
};
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_exist() {
        let ps = presets();
        assert!(ps.len() >= 3);
        assert!(find("standard").is_some());
        assert!(find("STANDARD").is_some());
        assert!(find("nope").is_none());
    }

    #[test]
    fn describe_lists_all() {
        let d = describe_all();
        assert!(d.contains("standard"));
        assert!(d.contains("gaming"));
    }

    #[test]
    fn fallback_worker_is_module() {
        assert!(fallback_worker_js().contains("export default"));
        assert!(fallback_worker_js().contains("fetch"));
    }
}
