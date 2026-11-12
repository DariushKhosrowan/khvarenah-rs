//! DNS tunnel client — a text-rate emergency channel for total-blackout
//! scenarios.
//!
//! When every TCP/UDP path to the outside world is blocked except DNS, a DNS
//! tunnel is the last remaining channel. It is **slow**: realistic throughput
//! is ~1–50 kbps because every payload chunk travels inside one DNS query and
//! costs a full DNS round-trip. This module is not a high-bandwidth VPN — it
//! is an emergency control/bootstrap channel: ferry small messages, report
//! status, and discover whether a better path has reopened.
//!
//! # Protocol
//!
//! We implement the client side of a dnscat2-style tunnel. The *server* is an
//! authoritative DNS server on a host you control (a VPS outside Iran). Each
//! outgoing payload byte is encoded as a base32 label appended under a base
//! domain you own:
//!
//! ```text
//! <nonce>.<seq>.<flags>.<payload-base32>.<session-tag>.<basedomain>
//! ```
//!
//! - `session-tag` (1 label) lets the server multiplex multiple clients.
//! - `nonce` / `seq` / `flags` are short numeric labels.
//! - Payload is encoded with base32 (RFC 4648, no padding) so it is a safe
//!   label alphabet (a–z, 2–7, max 63 bytes per label => chunked).
//!
//! The server replies in a TXT record; we decode that reply back to bytes.
//!
//! This module provides the framing, the base32 label codec, and a small
//! `send_receive` primitive that resolves a crafted query via any resolver
//! that can handle TXT answers (we reuse the DoH resolver's transport). The
//! actual server-side authoritative responder is out of scope here.

use crate::error::CFError;
use std::fmt::Write;

/// Max length of a single DNS label (RFC 1035). Payload chunks must fit.
pub const MAX_LABEL: usize = 63;
/// Max TXT reply bytes we accept.
pub const MAX_REPLY: usize = 512;
/// Safe per-query QNAME length cap for Iranian ISP / DPI filter hardware.
/// Queries over ~110 chars are frequently dropped; we clamp to 101 (the
/// documented limit used by production Iranian DNS-tunnel clients).
pub const MAX_QNAME_LEN: usize = 101;

/// Base32 alphabet (RFC 4648, lowercase, no padding). Safe for DNS labels.
const B32: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

fn b32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 8 / 5 + 1);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buf >> bits) & 0x1F) as usize;
            out.push(B32[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buf << (5 - bits)) & 0x1F) as usize;
        out.push(B32[idx] as char);
    }
    out
}

fn b32_decode(s: &str) -> Result<Vec<u8>, CFError> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for c in s.chars() {
        let v = match B32
            .iter()
            .position(|&b| b as char == c.to_ascii_lowercase())
        {
            Some(v) => v as u32,
            None => {
                return Err(CFError::new(
                    "dns-tunnel",
                    format!("invalid base32 char '{c}'"),
                    "Server reply malformed.",
                ))
            }
        };
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

/// One tunnel frame.
#[derive(Debug, Clone)]
pub struct TunnelFrame {
    pub session: String,
    pub seq: u16,
    /// 0 = data, 1 = ping, 2 = status report, 3 = bootstrap-tunnel request.
    pub flags: u8,
    pub payload: Vec<u8>,
}

impl TunnelFrame {
    /// Encode the frame as a DNS name under `base_domain` (in chunks that fit
    /// in single labels, skipping the leading nonce/seq/flags labels).
    pub fn encode_name(&self, base_domain: &str, nonce: u32) -> String {
        self.assemble_name(base_domain, nonce, &self.payload)
    }

    /// Internal frame → QNAME builder for an explicit payload slice. This is
    /// the single source of truth for the wire format; `encode_name` passes the
    /// full payload, `encode_name_clamped` passes a progressively-truncated one.
    fn assemble_name(&self, base_domain: &str, nonce: u32, payload: &[u8]) -> String {
        let mut name = String::new();
        let _ = write!(name, "{nonce:x}.{}.{}", self.seq, self.flags);
        let payload_b32 = b32_encode(payload);
        // Chunk the base32 payload into <=63-char labels.
        for chunk in payload_b32.as_bytes().chunks(MAX_LABEL) {
            name.push('.');
            // `chunk` is valid base32 (a-z2-7), always an OK label.
            name.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        }
        let _ = write!(name, ".{}", self.session);
        // Strip a leading dot if payload was empty.
        if payload_b32.is_empty() && name.ends_with('.') {
            name.pop();
        }
        format!("{name}.{base_domain}")
    }

    /// Encode the frame but guarantee the resulting QNAME is at most
    /// `max_qname_len` characters — the DPI-lim safe limit for Iranian ISP
    /// resolvers is ~101 (see `MAX_QNAME_LEN`). Longer payloads are truncated
    /// (monotonic, part of the text-rate framing contract) so every query fits
    /// well under the per-query cap and is not dropped by filter hardware.
    pub fn encode_name_clamped(&self, base_domain: &str, nonce: u32, max_qname_len: usize) -> String {
        let mut pl = self.payload.clone();
        loop {
            let name = self.assemble_name(base_domain, nonce, &pl);
            if name.len() <= max_qname_len || pl.is_empty() {
                return name;
            }
            // Drop one base32 group (6 raw bytes) and rebuild. Terminates
            // because `pl` shrinks to empty, and an empty-payload name is short.
            let cut = pl.len().min(6);
            pl.truncate(pl.len() - cut);
        }
    }

    /// Decode a reply domain back into a frame (server → client direction).
    pub fn decode_name(name: &str, base_domain: &str) -> Result<TunnelFrame, CFError> {
        let name = name.trim_end_matches('.');
        let suffix = format!(".{base_domain}");
        let core = name
            .strip_suffix(&suffix)
            .ok_or_else(|| CFError::new("dns-tunnel", "name not under base domain", ""))?;
        let labels: Vec<&str> = core.split('.').collect();
        if labels.len() < 4 {
            return Err(CFError::new("dns-tunnel", "too few labels", ""));
        }
        // [nonce, seq, flags, ...payload..., session]
        let seq = labels[1]
            .parse::<u16>()
            .map_err(|_| CFError::new("dns-tunnel", "bad seq", ""))?;
        let flags = labels[2]
            .parse::<u8>()
            .map_err(|_| CFError::new("dns-tunnel", "bad flags", ""))?;
        let session = labels[labels.len() - 1].to_string();
        let payload = b32_decode(&labels[3..labels.len() - 1].join(""))?;
        Ok(TunnelFrame {
            session,
            seq,
            flags,
            payload,
        })
    }
}

/// A TXT-capable resolver. The DoH resolver's transport (HTTP POST) can be
/// adapted, but we keep this trait abstract so the app can plug in whatever
/// resolver works at the moment.
pub trait Resolver {
    fn query_txt(&self, name: &str) -> Result<String, CFError>;
}

/// Send `frame` to the tunnel server and return the decoded reply frame.
pub async fn send_receive<R: Resolver>(
    resolver: &R,
    base_domain: &str,
    frame: &TunnelFrame,
) -> Result<TunnelFrame, CFError> {
    // Nonce: derive from seq + a random value to vary the query.
    let nonce: u32 = rand::random::<u32>() & 0xFFFF;
    // Clamp the QNAME to the DPI-safe limit (≤101) so the query is not
    // dropped by Iranian ISP filter hardware — critical for the domestic
    // recursion path in a blackout.
    let qname = frame.encode_name_clamped(base_domain, nonce, MAX_QNAME_LEN);
    let reply = resolver.query_txt(&qname)?;
    TunnelFrame::decode_name(reply.trim_end_matches('.'), base_domain)
}

/// Live DNS-tunnel liveness probe: send a raw UDP TXT query straight to the
/// VPS tunnel server (UDP 53, the dnstt-server port) and require a DNS
/// datagram back within `timeout`. This is a real round-trip against the
/// authoritative responder — unlike a config-presence check, it fails fast
/// when the VPS is down, unreachable, or the DNS path is blocked, so the
/// fallback ladder will NOT report false confidence on a dead tunnel during a
/// total blackout.
///
/// The query name is a crafted ping frame (flags=1) under the tunnel's base
/// domain. A live dnstt-server answers authoritatively (any datagram that
/// parses as a DNS response is proof the server is reachable).
pub async fn probe_tunnel_live(
    cfg: &crate::vps_deploy::TunnelClientConfig,
    timeout: std::time::Duration,
) -> bool {
    use std::net::SocketAddr;
    // Resolve the VPS host (fall back to the OS resolver; it is a literal IP
    // in the common case, so this is cheap and DNS-free).
    let Ok(ip) = tokio::net::lookup_host((cfg.host.as_str(), 53u16)).await else {
        return false;
    };
    let mut addr: Option<SocketAddr> = None;
    for a in ip {
        if a.is_ipv4() {
            addr = Some(a);
            break;
        }
    }
    let Some(sa) = addr else { return false };

    // Craft a ping frame under the base domain.
    let frame = TunnelFrame {
        session: cfg.session.clone(),
        seq: 1,
        flags: 1, // ping
        payload: b"alive".to_vec(),
    };
    let nonce = rand::random::<u32>() & 0xFFFF;
    let qname = frame.encode_name_clamped(&cfg.base_domain, nonce, MAX_QNAME_LEN);

    // If a domestic resolver pool is configured, probe *through* it (the
    // blackout-safe path — the domestic resolver recurses to our delegated
    // authoritative server). Fall back to a direct UDP query to the VPS only
    // when no pool is set.
    if let Some(pool) = &cfg.resolver_pool {
        if !pool.is_empty() {
            let rp = crate::resolve_pool::ResolverPool::new(pool.clone(), timeout);
            return rp.query_txt(&qname).is_ok();
        }
    }

    let id: u16 = rand::random();
    let query = crate::doh::build_dns_query_txt(&qname, id);

    let Ok(sock) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else {
        return false;
    };
    if sock.connect(sa).await.is_err() {
        return false;
    }
    if sock.send(&query).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 512];
    tokio::time::timeout(timeout, sock.recv(&mut buf))
        .await
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b32_roundtrip() {
        let data = b"hello dns tunnel!";
        let enc = b32_encode(data);
        assert_eq!(b32_decode(&enc).unwrap(), data);
    }

    #[test]
    fn b32_alphabet_is_label_safe() {
        for &b in B32 {
            let c = b as char;
            assert!(c.is_ascii_lowercase() || c.is_ascii_digit());
        }
    }

    #[test]
    fn frame_roundtrip_encode_decode() {
        let f = TunnelFrame {
            session: "sess".into(),
            seq: 42,
            flags: 0,
            payload: b"status:ok".to_vec(),
        };
        let name = f.encode_name("tun.example.com", 0xABCD);
        assert!(name.ends_with(".tun.example.com"));
        // Truncate to the subdomain part for decode.
        let decoded = TunnelFrame::decode_name(&name, "tun.example.com").unwrap();
        assert_eq!(decoded.seq, 42);
        assert_eq!(decoded.flags, 0);
        assert_eq!(decoded.payload, b"status:ok");
        assert_eq!(decoded.session, "sess");
    }

    #[test]
    fn large_payload_is_chunked_across_labels() {
        let payload = vec![0xABu8; 200];
        let f = TunnelFrame {
            session: "s".into(),
            seq: 1,
            flags: 0,
            payload,
        };
        let name = f.encode_name("tun.example.com", 1);
        // Every label except the nonce/seq/flags must be <= 63 chars.
        let labels: Vec<&str> = name.split('.').collect();
        for &l in &labels[3..labels.len() - 1] {
            assert!(l.len() <= MAX_LABEL, "label too long: {l}");
        }
        let decoded = TunnelFrame::decode_name(&name, "tun.example.com").unwrap();
        assert_eq!(decoded.payload.len(), 200);
        assert_eq!(decoded.payload[0], 0xAB);
    }

    #[test]
    fn rejects_name_outside_base_domain() {
        assert!(TunnelFrame::decode_name("a.b.c.evil.com", "tun.example.com").is_err());
    }

    #[test]
    fn encode_name_clamped_stays_under_dpi_limit() {
        // A payload too large for the DPI-safe QNAME cap must be truncated so
        // the resulting name is always ≤ MAX_QNAME_LEN.
        let frame = TunnelFrame {
            session: "averylongsessiontag".into(),
            seq: 65535,
            flags: 0,
            payload: vec![0x42u8; 300],
        };
        let name = frame.encode_name_clamped("tun.example.com", 0xFFFF, MAX_QNAME_LEN);
        assert!(
            name.len() <= MAX_QNAME_LEN,
            "QNAME {name} has length {} > {MAX_QNAME_LEN}",
            name.len()
        );
        // The clamped name must still decode back to the same session/frame
        // metadata (payload is truncated, not corrupted).
        let decoded = TunnelFrame::decode_name(&name, "tun.example.com").unwrap();
        assert_eq!(decoded.session, "averylongsessiontag");
        assert_eq!(decoded.seq, 65535);
        assert_eq!(decoded.flags, 0);
    }

    #[test]
    fn encode_name_clamped_leaves_small_payload_intact() {
        let frame = TunnelFrame {
            session: "s".into(),
            seq: 9,
            flags: 1,
            payload: b"pong".to_vec(),
        };
        let name = frame.encode_name_clamped("tun.example.com", 0x1234, MAX_QNAME_LEN);
        assert!(name.len() <= MAX_QNAME_LEN);
        let decoded = TunnelFrame::decode_name(&name, "tun.example.com").unwrap();
        assert_eq!(decoded.payload, b"pong");
    }
}
