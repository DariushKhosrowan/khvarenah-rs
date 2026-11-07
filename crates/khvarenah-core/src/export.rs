//! Export VLESS profiles to the config formats used by real client apps.
//!
//! The core layer produces a portable `vless://` share link. Real users,
//! though, run v2rayN / v2rayNG, sing-box, or Clash Meta — each with its own
//! config schema. This module renders those formats from a single
//! [`crate::VlessProfile`] so the console can drop the user straight into a
//! working client.

use crate::error::CFError;
use crate::VlessProfile;

/// All supported client export formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// v2rayN / v2rayNG JSON (Xray-style outbound).
    V2rayN,
    /// sing-box JSON outbound.
    SingBox,
    /// Clash / Clash.Meta YAML proxy entry.
    Clash,
    /// The raw portable `vless://` URI.
    ShareLink,
}

impl ExportFormat {
    /// Parse a format name from a CLI/tui arg.
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "v2rayn" | "v2ray" | "xray" => Some(Self::V2rayN),
            "singbox" | "sing-box" | "sing_box" => Some(Self::SingBox),
            "clash" | "clash-meta" | "clashmeta" => Some(Self::Clash),
            "link" | "share" | "share-link" | "sharelink" => Some(Self::ShareLink),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::V2rayN => "v2rayN",
            Self::SingBox => "sing-box",
            Self::Clash => "Clash",
            Self::ShareLink => "share-link",
        }
    }
}

/// Render a profile in the requested format.
pub fn render(profile: &VlessProfile, format: ExportFormat) -> Result<String, CFError> {
    match format {
        ExportFormat::V2rayN => profile.xray_client_json(),
        ExportFormat::SingBox => sing_box_json(profile),
        ExportFormat::Clash => Ok(clash_entry(profile)),
        ExportFormat::ShareLink => Ok(profile.share_link()),
    }
}

/// Render a full sing-box JSON config (inbound + VLESS outbound).
pub fn sing_box_json(profile: &VlessProfile) -> Result<String, CFError> {
    let mut p = profile.clone();
    p.normalize();
    let sni = p.sni.clone().unwrap_or_else(|| p.address.clone());
    let host = p.header_host.clone().unwrap_or_else(|| p.address.clone());
    let tls_enabled = p.security == "tls";

    let outbound = serde_json::json!({
        "type": "vless",
        "tag": "khvarenah",
        "server": p.address,
        "server_port": p.port,
        "uuid": p.uuid,
        "packet_encoding": "xudp",
        "tls": {
            "enabled": tls_enabled,
            "server_name": sni,
            "utls": { "enabled": true, "fingerprint": "chrome" }
        },
        "transport": {
            "type": "ws",
            "path": p.path,
            "headers": { "Host": host }
        }
    });

    let cfg = serde_json::json!({
        "log": { "level": "warn" },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 2080
            }
        ],
        "outbounds": [ outbound ],
        "route": { "final": "khvarenah" }
    });

    serde_json::to_string_pretty(&cfg)
        .map_err(|e| CFError::new("Export error", format!("{e}"), "Internal error."))
}

/// Render a single Clash / Clash.Meta proxy entry (YAML fragment).
pub fn clash_entry(profile: &VlessProfile) -> String {
    let mut p = profile.clone();
    p.normalize();
    let sni = p.sni.clone().unwrap_or_else(|| p.address.clone());
    let host = p.header_host.clone().unwrap_or_else(|| p.address.clone());
    let tls_enabled = p.security == "tls";
    let name = sanitize_yaml(&p.name);

    format!(
        "- name: {name}\n  type: vless\n  server: {}\n  port: {}\n  uuid: {}\n  network: ws\n  tls: {}\n  servername: {sni}\n  ws-opts:\n    path: {}\n    headers:\n      Host: {host}\n",
        p.address,
        p.port,
        p.uuid,
        tls_enabled,
        p.path
    )
}

/// Replace YAML-problematic characters in a proxy name.
fn sanitize_yaml(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            ':' | '\n' | '\r' | '\t' | '[' | ']' | '{' | '}' | '#' => '-',
            c => c,
        })
        .collect()
}

/// Export a profile to every format and return them keyed by label.
pub fn render_all(profile: &VlessProfile) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for fmt in [
        ExportFormat::V2rayN,
        ExportFormat::SingBox,
        ExportFormat::Clash,
        ExportFormat::ShareLink,
    ] {
        if let Ok(text) = render(profile, fmt) {
            out.push((fmt.label().to_string(), text));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> VlessProfile {
        let mut p = VlessProfile::default();
        p.uuid = "12345678-1234-1234-1234-123456789abc".into();
        p.address = "edge.workers.dev".into();
        p.path = "/ws".into();
        p.name = "my-config".into();
        p.normalize();
        p
    }

    #[test]
    fn format_names_parse() {
        assert_eq!(ExportFormat::parse("clash"), Some(ExportFormat::Clash));
        assert_eq!(ExportFormat::parse("sing-box"), Some(ExportFormat::SingBox));
        assert_eq!(ExportFormat::parse("v2rayn"), Some(ExportFormat::V2rayN));
        assert_eq!(ExportFormat::parse("bogus"), None);
    }

    #[test]
    fn clash_entry_has_required_keys() {
        let e = clash_entry(&sample());
        assert!(e.contains("type: vless"));
        assert!(e.contains("server: edge.workers.dev"));
        assert!(e.contains("uuid: 12345678"));
        assert!(e.contains("network: ws"));
        assert!(e.contains("tls: true"));
    }

    #[test]
    fn singbox_json_is_valid_json() {
        let s = sing_box_json(&sample()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["outbounds"][0]["type"], "vless");
        assert_eq!(v["outbounds"][0]["server"], "edge.workers.dev");
    }

    #[test]
    fn render_all_covers_formats() {
        let all = render_all(&sample());
        assert!(all.iter().any(|(l, _)| l == "Clash"));
        assert!(all.iter().any(|(l, _)| l == "sing-box"));
        assert!(all.iter().any(|(l, _)| l == "v2rayN"));
    }
}
