//! VLESS config + share-link generation for the edgetunnel worker.

use serde::{Deserialize, Serialize};

use crate::error::CFError;

/// A VLESS client profile (port of the Python `VlessProfile`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlessProfile {
    pub uuid: String,
    pub address: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_security")]
    pub security: String,
    #[serde(default = "default_path")]
    pub path: String,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub header_host: Option<String>,
    #[serde(default = "default_transport")]
    pub transport: String,
    #[serde(default = "default_name")]
    pub name: String,
}

fn default_port() -> u16 {
    443
}
fn default_security() -> String {
    "tls".to_string()
}
fn default_path() -> String {
    "/".to_string()
}
fn default_transport() -> String {
    "ws".to_string()
}
fn default_name() -> String {
    "cf-worker-edge".to_string()
}

impl Default for VlessProfile {
    fn default() -> Self {
        Self {
            uuid: String::new(),
            address: String::new(),
            port: 443,
            security: "tls".to_string(),
            path: "/".to_string(),
            sni: None,
            header_host: None,
            transport: "ws".to_string(),
            name: "cf-worker-edge".to_string(),
        }
    }
}

/// Percent-decode a query-string value (e.g. `%2F` -> `/`). Falls back to the
/// raw string when decoding fails or is a no-op.
fn decode_query(v: &str) -> String {
    percent_encoding::percent_decode_str(v)
        .decode_utf8_lossy()
        .into_owned()
}

impl VlessProfile {
    /// Fill in default sni/header_host from address, like Python's __post_init__.
    pub fn normalize(&mut self) {
        if self.sni.as_deref().unwrap_or("").is_empty() {
            self.sni = Some(self.address.clone());
        }
        if self.header_host.as_deref().unwrap_or("").is_empty() {
            self.header_host = Some(self.address.clone());
        }
    }

    /// A copy pointing at a local wrangler-dev worker (VPN-free testing).
    pub fn local_ws(&self, lan_ip: &str, port: u16) -> Self {
        Self {
            uuid: self.uuid.clone(),
            address: lan_ip.to_string(),
            port,
            security: "none".to_string(),
            path: self.path.clone(),
            sni: None,
            header_host: Some(lan_ip.to_string()),
            transport: "ws".to_string(),
            name: "cf-worker-LOCAL (no VPN)".to_string(),
        }
    }

    /// The portable `vless://` URI used by client apps.
    pub fn share_link(&self) -> String {
        let mut p = self.clone();
        p.normalize();
        let sni = p.sni.unwrap_or_else(|| p.address.clone());
        let host = p.header_host.unwrap_or_else(|| p.address.clone());

        let mut base = format!("vless://{}@{}:{}", p.uuid, p.address, p.port);
        base.push_str("?encryption=none");
        base.push_str(&format!("&security={}", p.security));
        base.push_str(&format!("&type={}", p.transport));
        base.push_str(&format!("&sni={sni}"));
        base.push_str(&format!("&host={host}"));
        base.push_str(&format!("&path={}", p.path));
        base.push_str("&fp=chrome");
        base.push_str(&format!(
            "#{}",
            percent_encoding::utf8_percent_encode(&p.name, percent_encoding::NON_ALPHANUMERIC)
        ));
        base
    }

    /// A full xray client config (inbound socks/http + VLESS outbound).
    pub fn xray_client_json(&self) -> Result<String, CFError> {
        let mut p = self.clone();
        p.normalize();
        let sni = p.sni.clone().unwrap_or_else(|| p.address.clone());
        let host = p.header_host.clone().unwrap_or_else(|| p.address.clone());

        let cfg = serde_json::json!({
            "log": {"loglevel": "warning"},
            "inbounds": [
                {"tag": "socks-in", "listen": "127.0.0.1", "port": 10808,
                 "protocol": "socks", "settings": {"auth": "noauth", "udp": true}},
                {"tag": "http-in", "listen": "127.0.0.1", "port": 10809,
                 "protocol": "http"}
            ],
            "outbounds": [{
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": p.address,
                        "port": p.port,
                        "users": [{"id": p.uuid, "encryption": "none"}]
                    }]
                },
                "streamSettings": {
                    "network": p.transport,
                    "security": p.security,
                    "tlsSettings": (if p.security == "tls" {
                        serde_json::json!({"serverName": sni, "fingerprint": "chrome"})
                    } else {
                        serde_json::Value::Null
                    }),
                    "wsSettings": {
                        "path": p.path,
                        "headers": {"Host": host}
                    }
                }
            }]
        });
        serde_json::to_string_pretty(&cfg)
            .map_err(|e| CFError::new("Serialization error", format!("{e}"), "Internal error."))
    }

    /// Parse a `vless://` link into a VlessProfile.
    pub fn parse(link: &str) -> Result<Self, CFError> {
        let link = link.trim();
        if !link.starts_with("vless://") {
            return Err(CFError::new(
                "Invalid vless link",
                "The link does not start with vless://",
                "Export a valid vless link from the app.",
            ));
        }
        let body = &link["vless://".len()..];
        // split fragment
        let (no_frag, frag) = match body.find('#') {
            Some(i) => (&body[..i], Some(&body[i + 1..])),
            None => (body, None),
        };
        // split query
        let (userhost, query) = match no_frag.find('?') {
            Some(i) => (&no_frag[..i], Some(&no_frag[i + 1..])),
            None => (no_frag, None),
        };
        let (user, hostport) = match userhost.rfind('@') {
            Some(i) => (&userhost[..i], &userhost[i + 1..]),
            None => ("", userhost),
        };
        // split host:port
        let (address, port) = match hostport.rfind(':') {
            Some(i) => (
                &hostport[..i],
                hostport[i + 1..].parse::<u16>().unwrap_or(443),
            ),
            None => (hostport, 443),
        };

        let mut profile = VlessProfile {
            uuid: user.to_string(),
            address: address.to_string(),
            port,
            ..Default::default()
        };

        if let Some(q) = query {
            for pair in q.split('&') {
                let mut it = pair.splitn(2, '=');
                let k = it.next().unwrap_or("");
                let v = it.next().unwrap_or("");
                match k {
                    "security" => profile.security = v.to_string(),
                    "type" => profile.transport = v.to_string(),
                    // URL-decode the free-form fields. The share link encodes
                    // the ws path (and host/SNI) into the query string, so a
                    // path like "/" arrives as "%2F". Storing it verbatim makes
                    // rendered v2rayN/sing-box/Clash configs emit "path":
                    // "%2F", which v2rayN refuses to import. Decode once here
                    // so every downstream renderer gets the real path.
                    "sni" => profile.sni = Some(decode_query(v)),
                    "host" => profile.header_host = Some(decode_query(v)),
                    "path" => profile.path = decode_query(v),
                    _ => {}
                }
            }
        }
        if let Some(f) = frag {
            profile.name = percent_encoding::percent_decode_str(f)
                .decode_utf8_lossy()
                .to_string();
        }
        profile.normalize();
        Ok(profile)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_percent_decodes_path_into_slashes() {
        // The share link encodes "/" as "%2F"; parse() must decode it back to
        // "/" so rendered v2rayN/sing-box/Clash configs are importable.
        let p = VlessProfile::parse(
            "vless://uuid@1.2.3.4:443?security=tls&type=ws&path=%2F&sni=h.workers.dev#x",
        )
        .unwrap();
        assert_eq!(p.path, "/", "path must be decoded, got {:?}", p.path);
        assert_eq!(p.sni.as_deref(), Some("h.workers.dev"));
    }

    #[test]
    fn parse_decodes_encoded_path_and_host() {
        let p = VlessProfile::parse(
            "vless://uuid@1.2.3.4:443?type=ws&path=%2Fws%2Fapi&host=h.example.com#x",
        )
        .unwrap();
        assert_eq!(p.path, "/ws/api");
        assert_eq!(p.header_host.as_deref(), Some("h.example.com"));
    }

    #[test]
    fn parse_keeps_plain_path_unchanged() {
        // Un-encoded query values must still work (no double-decoding).
        let p = VlessProfile::parse(
            "vless://uuid@1.2.3.4:443?type=ws&path=/ws&host=h.example.com#x",
        )
        .unwrap();
        assert_eq!(p.path, "/ws");
        assert_eq!(p.header_host.as_deref(), Some("h.example.com"));
    }

    #[test]
    fn share_link_roundtrip() {
        let mut p = VlessProfile {
            uuid: "12345678-1234-1234-1234-123456789abc".into(),
            address: "user.workers.dev".into(),
            port: 443,
            security: "tls".into(),
            path: "/ws".into(),
            transport: "ws".into(),
            name: "my-config".into(),
            ..Default::default()
        };
        p.normalize();
        let link = p.share_link();
        let parsed = VlessProfile::parse(&link).unwrap();
        assert_eq!(parsed.uuid, p.uuid);
        assert_eq!(parsed.address, p.address);
        assert_eq!(parsed.port, p.port);
        assert_eq!(parsed.path, p.path);
        assert_eq!(parsed.name, p.name);
        assert_eq!(parsed.security, "tls");
    }

    #[test]
    fn parse_clean_endpoint_match() {
        let p = VlessProfile::parse("vless://uuid@1.2.3.4:8443?security=tls&type=ws#x").unwrap();
        assert_eq!(p.address, "1.2.3.4");
        assert_eq!(p.port, 8443);
        assert_eq!(p.name, "x");
    }

    #[test]
    fn xray_json_has_vless_outbound() {
        let mut p = VlessProfile::default();
        p.address = "example.workers.dev".into();
        p.uuid = "uuid-1".into();
        let s = p.xray_client_json().unwrap();
        assert!(s.contains("vless"));
        assert!(s.contains("socks"));
    }
}
