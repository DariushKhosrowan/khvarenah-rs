//! Scheme-agnostic proxy share-link parsing.
//!
//! Iranian Telegram config channels publish share-links in **many** schemes,
//! not just `vless://`. Under the doctrine (Level 1 wants Shadowsocks-2022;
//! every working transport is a way out of a blackout), DastYab must be
//! able to ingest them all. This module is the single, boring decoder that
//! turns any supported share-link into a normal form:
//!
//! ```text
//! (scheme, host, port, id, alias)
//! ```
//!
//! Supported schemes:
//! - `vless://UUID@host:port?params#frag`
//! - `trojan://PASSWORD@host:port?params#frag`
//! - `hysteria2://AUTH@host:port?params#frag`
//! - `tuic://UUID:TOKEN@host:port?params#frag` (id = part before first `:`)
//! - `ss://METHOD:PASSWORD@host:port#frag` or `ss://BASE64(...)`
//! - `vmess://BASE64(JSON)` (JSON carries `add`/`port`/`id`)
//! - `ssr://BASE64(server:port:protocol:method:obfs:password/)`
//!
//! The parser is deliberately **lossy-but-normalizing**: it extracts just
//! enough to deduplicate and probe a node, and preserves the raw link for
//! faithful v2rayN export. It never fabricates a field it cannot parse.

use base64::Engine;

/// Proxy URI schemes the node store / harvester understand.
pub const SUPPORTED_SCHEMES: &[&str] =
    &["vless", "vmess", "trojan", "ss", "ssr", "hysteria2", "tuic"];

/// Normalized view of a single share-link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyUri {
    /// Lowercase scheme (e.g. `vless`, `trojan`).
    pub scheme: String,
    /// Server host (IP or domain).
    pub host: String,
    /// Server port.
    pub port: u16,
    /// Identity used for dedup: uuid (vless/vmess/tuic), password
    /// (trojan), auth token (hysteria2), or `method:password` (ss/ssr).
    pub id: String,
    /// Fragment after `#` (v2rayN alias), percent-decoded.
    pub alias: String,
    /// The raw share-link as given (params preserved).
    pub raw: String,
}

impl ProxyUri {
    /// Parse any supported share-link. Returns `None` for malformed or
    /// unsupported input.
    pub fn parse(raw: &str) -> Option<ProxyUri> {
        let raw = raw.trim();
        let (scheme, rest) = split_scheme(raw)?;
        let mut out = ProxyUri {
            scheme: scheme.to_string(),
            host: String::new(),
            port: 0,
            id: String::new(),
            alias: String::new(),
            raw: raw.to_string(),
        };
        let ok = match scheme {
            "vless" | "trojan" | "hysteria2" => parse_userinfo_host(&mut out, rest, 1),
            "tuic" => parse_userinfo_host(&mut out, rest, 2),
            "ss" => parse_ss(&mut out, rest),
            "vmess" => parse_vmess(&mut out, rest),
            "ssr" => parse_ssr(&mut out, rest),
            _ => false,
        };
        if !ok {
            return None;
        }
        // Alias from the `#frag` fragment (all schemes), percent-decoded. If
        // there is no fragment, keep whatever the scheme parser set (e.g. the
        // vmess `ps` field).
        if let Some((_, frag)) = raw.rsplit_once('#') {
            out.alias = crate::vless::decode_query(frag);
        }
        Some(out)
    }
}

/// Split `scheme://...` into `(scheme, rest_after_://)`.
fn split_scheme(raw: &str) -> Option<(&str, &str)> {
    let idx = raw.find("://")?;
    let scheme = &raw[..idx];
    if scheme.is_empty() || !scheme.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some((scheme, &raw[idx + 3..]))
}

/// Strip `?query` and `#frag` from the host part. Returns the bare
/// `host:port` segment.
fn strip_query_frag(host_part: &str) -> &str {
    let host_part = host_part.split(['?', '#']).next().unwrap_or(host_part);
    host_part.split('/').next().unwrap_or(host_part)
}

/// Parse `host:port` into `out.host` / `out.port`.
fn set_host_port(out: &mut ProxyUri, host_port: &str) -> bool {
    let host_port = strip_query_frag(host_port);
    let (host, port) = match host_port.rsplit_once(':') {
        Some(x) => x,
        None => return false,
    };
    let Ok(port) = port.trim().parse::<u16>() else {
        return false;
    };
    if host.is_empty() || port == 0 {
        return false;
    }
    out.host = host.trim().to_string();
    out.port = port;
    true
}

/// For `userinfo@host:port` links. `split_at` is the index inside
/// `userinfo` to cut the id (1 keeps the whole userinfo; 2 strips a
/// trailing `:token` — used by `tuic://uuid:token@...`).
fn parse_userinfo_host(out: &mut ProxyUri, rest: &str, split_at: usize) -> bool {
    let (userinfo, host_part) = match rest.split_once('@') {
        Some(x) => x,
        None => return false,
    };
    if userinfo.is_empty() {
        return false;
    }
    let id = if split_at > 1 {
        userinfo.split(':').next().unwrap_or(userinfo).to_string()
    } else {
        crate::vless::decode_query(userinfo)
    };
    if id.is_empty() {
        return false;
    }
    if !set_host_port(out, host_part) {
        return false;
    }
    out.id = id;
    true
}

/// Shadowsocks: plain `method:password@host:port`, SIP002
/// `BASE64(method:password)@host:port`, or whole-link base64.
fn parse_ss(out: &mut ProxyUri, rest: &str) -> bool {
    if let Some((userinfo, host_part)) = rest.split_once('@') {
        // SIP002: `ss://BASE64(method:password)@host:port`. The userinfo is
        // base64 of `method:password` (the ':' is not in the base64 alphabet,
        // so if it decodes, it is unambiguous).
        if let Some(decoded) = b64_decode(userinfo) {
            if decoded.contains(':') && set_host_port(out, host_part) {
                out.id = decoded;
                return true;
            }
        }
        // Plain form: `ss://method:password@host:port`.
        if userinfo.contains(':') && set_host_port(out, host_part) {
            out.id = crate::vless::decode_query(userinfo);
            return !out.id.is_empty() && out.id.contains(':');
        }
        return false;
    }
    // Whole-link base64 form: `ss://BASE64(method:password@host:port)`.
    // Some clients also append `#frag` — strip the fragment before decoding.
    let b64_candidate = rest
        .split(['?'])
        .next()
        .unwrap_or(rest)
        .split('#')
        .next()
        .unwrap_or(rest);
    let decoded = match b64_decode(b64_candidate) {
        Some(d) => d,
        None => return false,
    };
    // Now decoded is `method:password@host:port` (or `method:password`).
    let (userinfo, host_part) = match decoded.split_once('@') {
        Some(x) => x,
        None => return false,
    };
    if !userinfo.contains(':') {
        return false;
    }
    if !set_host_port(out, host_part) {
        return false;
    }
    out.id = userinfo.to_string();
    true
}

/// Vmess: `vmess://BASE64(JSON)` where JSON has `add`, `port`, `id`, `ps`.
fn parse_vmess(out: &mut ProxyUri, rest: &str) -> bool {
    let decoded = match b64_decode(rest) {
        Some(d) => d,
        None => return false,
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&decoded) else {
        return false;
    };
    let host = match v.get("add").and_then(|x| x.as_str()) {
        Some(h) => h,
        None => return false,
    };
    let port = match v.get("port").and_then(|x| {
        x.as_str()
            .map(|s| s.to_string())
            .or_else(|| x.as_u64().map(|n| n.to_string()))
    }) {
        Some(p) => p,
        None => return false,
    };
    let id = match v.get("id").and_then(|x| x.as_str()) {
        Some(i) => i,
        None => return false,
    };
    let Ok(port) = port.parse::<u16>() else {
        return false;
    };
    if host.is_empty() || port == 0 || id.is_empty() {
        return false;
    }
    out.host = host.to_string();
    out.port = port;
    out.id = id.to_string();
    // `ps` is the friendly name — prefer it as the alias.
    if let Some(ps) = v.get("ps").and_then(|x| x.as_str()) {
        if !ps.is_empty() {
            out.alias = ps.to_string();
        }
    }
    true
}

/// SSR: `ssr://BASE64(server:port:protocol:method:obfs:password/)`.
fn parse_ssr(out: &mut ProxyUri, rest: &str) -> bool {
    let decoded = match b64_decode(rest) {
        Some(d) => d,
        None => return false,
    };
    let head = decoded.split('/').next().unwrap_or(&decoded);
    let parts: Vec<&str> = head.split(':').collect();
    if parts.len() < 2 {
        return false;
    }
    let host = parts[0];
    let Ok(port) = parts[1].parse::<u16>() else {
        return false;
    };
    if host.is_empty() || port == 0 {
        return false;
    }
    out.host = host.to_string();
    out.port = port;
    // id = `method:password` when available; else just the method.
    out.id = if parts.len() >= 6 {
        format!("{}:{}", parts[3], parts[5])
    } else {
        parts.get(3).copied().unwrap_or("").to_string()
    };
    true
}

/// Base64 decode with the usual encodings used in share-links (standard with
/// padding, and URL-safe without padding). Returns `None` on failure.
fn b64_decode(s: &str) -> Option<String> {
    let s = s.trim().trim_end_matches('#');
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    let mut buf = String::with_capacity(s.len());
    for engine in [&STANDARD, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(s) {
            if let Ok(text) = String::from_utf8(bytes) {
                buf = text;
                break;
            }
        }
    }
    if buf.is_empty() {
        None
    } else {
        Some(buf)
    }
}

/// Public wrapper for share-link base64 decoding (used by xray config
/// rendering for vmess/ssr links).
pub fn b64_decode_for(s: &str) -> Option<String> {
    b64_decode(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vless_roundtrip() {
        let u = ProxyUri::parse("vless://06ef598c-1555-4887-b3f9-08214a2f6792@104.17.72.206:443?encryption=none&type=ws#my-node").unwrap();
        assert_eq!(u.scheme, "vless");
        assert_eq!(u.host, "104.17.72.206");
        assert_eq!(u.port, 443);
        assert_eq!(u.id, "06ef598c-1555-4887-b3f9-08214a2f6792");
        assert_eq!(u.alias, "my-node");
    }

    #[test]
    fn trojan_parses() {
        let u = ProxyUri::parse("trojan://secret-password@ali.example.com:8443?security=tls&sni=ali.example.com#trojan-node").unwrap();
        assert_eq!(u.scheme, "trojan");
        assert_eq!(u.host, "ali.example.com");
        assert_eq!(u.port, 8443);
        assert_eq!(u.id, "secret-password");
        assert_eq!(u.alias, "trojan-node");
    }

    #[test]
    fn hysteria2_parses() {
        let u =
            ProxyUri::parse("hysteria2://open-token@107.189.20.41:8443?insecure=1#hy2").unwrap();
        assert_eq!(u.id, "open-token");
        assert_eq!(u.host, "107.189.20.41");
        assert_eq!(u.port, 8443);
    }

    #[test]
    fn tuic_uses_uuid_before_colon() {
        let u = ProxyUri::parse("tuic://413a66e9-b05b-4ae6-a9eb-6d28204a28f4:tok@138.68.53.88:7780?congestion_control=bbr#tuic").unwrap();
        assert_eq!(u.id, "413a66e9-b05b-4ae6-a9eb-6d28204a28f4");
        assert_eq!(u.port, 7780);
    }

    #[test]
    fn ss_plain_and_base64() {
        let plain = ProxyUri::parse("ss://chacha20-ietf-poly1305:key@1.2.3.4:8388#ss1").unwrap();
        assert_eq!(plain.id, "chacha20-ietf-poly1305:key");
        assert_eq!(plain.host, "1.2.3.4");
        assert_eq!(plain.port, 8388);

        // Base64 of `chacha20-ietf-poly1305:key@1.2.3.4:8388`.
        let b64 = base64::engine::general_purpose::STANDARD
            .encode("chacha20-ietf-poly1305:key@1.2.3.4:8388");
        let enc = ProxyUri::parse(&format!("ss://{b64}#ss2")).unwrap();
        assert_eq!(enc.id, "chacha20-ietf-poly1305:key");
        assert_eq!(enc.host, "1.2.3.4");
        assert_eq!(enc.port, 8388);
    }

    #[test]
    fn ss_sip002_base64_userinfo() {
        // Subscriptions use SIP002: only the `method:password` part is base64,
        // followed by @host:port#frag.
        let userinfo = base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:supersecret");
        let link = format!("ss://{userinfo}@198.244.201.129:19999#London");
        let u = ProxyUri::parse(&link).unwrap();
        assert_eq!(u.id, "aes-256-gcm:supersecret");
        assert_eq!(u.host, "198.244.201.129");
        assert_eq!(u.port, 19999);
        assert_eq!(u.alias, "London");
    }
    #[test]
    fn vmess_base64_json() {
        let json = r#"{"v":"2","ps":"vmess-telegram","add":"192.168.1.100","port":"443","id":"7748b328-f0e8-40ab-b2e3-9a1c2c22d111","aid":"0"}"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json);
        let u = ProxyUri::parse(&format!("vmess://{b64}")).unwrap();
        assert_eq!(u.scheme, "vmess");
        assert_eq!(u.host, "192.168.1.100");
        assert_eq!(u.port, 443);
        assert_eq!(u.id, "7748b328-f0e8-40ab-b2e3-9a1c2c22d111");
        // ps becomes the alias.
        assert_eq!(u.alias, "vmess-telegram");
    }

    #[test]
    fn ssr_parses() {
        // `server:port:protocol:method:obfs:password` (base64) — password
        // here is already the encoded form; we just need host/port.
        let plain = "95.85.234.66:10001:auth_aes128_md5:aes-128-ctr:tls1.2_ticket_auth:Zm9vYmFy";
        let b64 = base64::engine::general_purpose::STANDARD.encode(plain);
        let u = ProxyUri::parse(&format!("ssr://{b64}")).unwrap();
        assert_eq!(u.scheme, "ssr");
        assert_eq!(u.host, "95.85.234.66");
        assert_eq!(u.port, 10001);
    }

    #[test]
    fn rejects_malformed() {
        assert!(ProxyUri::parse("").is_none());
        assert!(ProxyUri::parse("http://google.com").is_none());
        assert!(ProxyUri::parse("vless://@host:443").is_none());
        assert!(ProxyUri::parse("vless://uuid@host").is_none());
        assert!(ProxyUri::parse("vless://uuid@host:0").is_none());
        assert!(ProxyUri::parse("vmess://not-base64").is_none());
    }

    #[test]
    fn supported_schemes_cover_level1() {
        // Doctrine Level 1: VLESS + Shadowsocks. Both must be ingestible.
        for s in SUPPORTED_SCHEMES {
            assert!(!s.is_empty());
        }
        assert!(SUPPORTED_SCHEMES.contains(&"vless"));
        assert!(SUPPORTED_SCHEMES.contains(&"ss"));
    }
}
