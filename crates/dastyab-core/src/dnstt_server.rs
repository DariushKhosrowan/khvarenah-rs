//! Server-side authoritative DNS tunnel responder.
//!
//! This is the missing other half of `dnstunnel` (the client). The client
//! encodes every payload into a DNS QNAME using the `TunnelFrame` base32
//! label scheme and expects a TXT answer in the same encoding. This module
//! implements the **server** that:
//!
//! 1. parses an incoming DNS datagram (UDP 53),
//! 2. decodes the QNAME back into a `TunnelFrame`,
//! 3. hands it to a `TunnelHandler` (built-in rescue commands),
//! 4. builds a TXT DNS response carrying the reply frame.
//!
//! It is authoritative by construction: the client talks to this server's IP
//! directly (see `dnstunnel::probe_tunnel_live` and the `Resolver` trait), so
//! no upstream forwarding or domain delegation is required. It binds UDP 53 on
//! the free-cloud VPS and answers only well-formed tunnel queries under the
//! configured base domain (everything else is ignored).
//!
//! The handler implements the rescue semantics from the survival report:
//! - flags=1 ping -> pong
//! - flags=2 status report -> uptime
//! - flags=3 bootstrap request -> next-tier endpoint blob (from a file)
//! - flags=0 data -> echo (text-rate messaging)
//!
//! An optional session allow-list gates the server, so only clients that know
//! the deployed session tag get a response.

use std::collections::HashSet;
use std::time::Instant;

use crate::dnstunnel::TunnelFrame;
use crate::error::CFError;

/// Maximum UDP datagram we accept (DNS max for classic messages).
pub const MAX_DATAGRAM: usize = 512;
/// TXT qtype.
const QTYPE_TXT: u16 = 16;
/// IN class.
const QCLASS_IN: u16 = 1;

/// Optional bootstrap blob the server serves on a flags=3 request. This is how
/// a stranded client learns the *next* tier endpoint (a better VPS, a worker
/// URL, etc.) when it only has DNS.
#[derive(Debug, Clone, Default)]
pub struct BootstrapInfo {
    pub blob: Vec<u8>,
}

/// Reply produced by the handler for a given request frame.
#[derive(Debug, Clone)]
pub struct TunnelReply {
    pub flags: u8,
    pub payload: Vec<u8>,
}

/// Server-side command handler. Kept small and self-contained; sessions are
/// authenticated via `allowed_sessions` when set.
pub struct TunnelHandler {
    /// If `Some`, only frames whose session tag is in this set are answered.
    pub allowed_sessions: Option<HashSet<String>>,
    /// Optional bootstrap blob served on flags=3.
    pub bootstrap: Option<BootstrapInfo>,
    /// When set, every reply payload is authenticated (doctrine B): sealed
    /// with ChaCha20-Poly1305 before it is embedded in the TXT answer.
    pub auth_key: Option<crate::dnstunnel_auth::DnsTunnelKey>,
    /// For uptime reporting (flags=2).
    started_at: Instant,
}

impl Default for TunnelHandler {
    fn default() -> Self {
        Self::new(None, None)
    }
}

impl TunnelHandler {
    pub fn new(
        allowed_sessions: Option<HashSet<String>>,
        bootstrap: Option<BootstrapInfo>,
    ) -> Self {
        Self {
            allowed_sessions,
            bootstrap,
            auth_key: None,
            started_at: Instant::now(),
        }
    }

    /// Builder: enable authenticated (sealed) replies (doctrine B).
    pub fn with_auth(mut self, key: crate::dnstunnel_auth::DnsTunnelKey) -> Self {
        self.auth_key = Some(key);
        self
    }

    /// Is this frame's session authorized?
    pub fn authorized(&self, frame: &TunnelFrame) -> bool {
        match &self.allowed_sessions {
            None => true,
            Some(set) => set.contains(&frame.session),
        }
    }

    /// Handle a request frame -> reply frame payload.
    pub fn handle(&self, frame: &TunnelFrame) -> TunnelReply {
        match frame.flags {
            // ping
            1 => TunnelReply {
                flags: 1,
                payload: b"pong".to_vec(),
            },
            // status report
            2 => {
                let up = self.started_at.elapsed().as_secs();
                TunnelReply {
                    flags: 2,
                    payload: format!("up:{up}s").into_bytes(),
                }
            }
            // bootstrap request
            3 => {
                let payload = match &self.bootstrap {
                    Some(b) => b.blob.clone(),
                    None => b"no-bootstrap".to_vec(),
                };
                TunnelReply { flags: 3, payload }
            }
            // data: echo (text-rate messaging)
            _ => TunnelReply {
                flags: frame.flags,
                payload: frame.payload.clone(),
            },
        }
    }
}

/// The full authoritative tunnel server configuration.
pub struct DnsTunnelServer {
    pub base_domain: String,
    pub handler: TunnelHandler,
}

impl DnsTunnelServer {
    pub fn new(base_domain: impl Into<String>, handler: TunnelHandler) -> Self {
        Self {
            base_domain: base_domain.into(),
            handler,
        }
    }
}

/// Parse the first question of a DNS datagram. Returns (id, qname, qtype,
/// qclass). Questions never use compression pointers, so a plain label walk is
/// correct.
pub fn parse_question(pkt: &[u8]) -> Result<(u16, String, u16, u16), CFError> {
    if pkt.len() < 12 {
        return Err(CFError::new(
            "dnstt-server",
            "datagram shorter than DNS header",
            "",
        ));
    }
    let id = u16::from_be_bytes([pkt[0], pkt[1]]);
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    if qdcount == 0 {
        return Err(CFError::new("dnstt-server", "no question", ""));
    }

    let mut pos = 12usize;
    let mut labels: Vec<String> = Vec::new();
    loop {
        if pos >= pkt.len() {
            return Err(CFError::new("dnstt-server", "qname overran", ""));
        }
        let len = pkt[pos];
        if len == 0 {
            pos += 1;
            break;
        }
        // No compression pointers are legal inside a question name.
        if len & 0xC0 != 0 {
            return Err(CFError::new(
                "dnstt-server",
                "unexpected pointer in question",
                "",
            ));
        }
        let l = len as usize;
        if pos + 1 + l > pkt.len() {
            return Err(CFError::new("dnstt-server", "qname label overran", ""));
        }
        labels.push(String::from_utf8_lossy(&pkt[pos + 1..pos + 1 + l]).into_owned());
        pos += 1 + l;
        // RFC 1035 whole-name cap.
        if labels.iter().map(|s| s.len()).sum::<usize>() + labels.len() > 255 {
            return Err(CFError::new("dnstt-server", "qname too long", ""));
        }
    }
    if pos + 4 > pkt.len() {
        return Err(CFError::new("dnstt-server", "question truncated", ""));
    }
    let qtype = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
    let qclass = u16::from_be_bytes([pkt[pos + 2], pkt[pos + 3]]);
    Ok((id, labels.join("."), qtype, qclass))
}

/// Build a DNS response with one or more TXT answers. `qname` is echoed back
/// in the question section and referenced by the answer RRs. TXT RDATA is a
/// single length-prefixed character-string per answer.
pub fn build_dns_response_txt(id: u16, qname: &str, txts: &[String]) -> Vec<u8> {
    let mut r = Vec::with_capacity(256 + txts.len() * 64);
    r.extend_from_slice(&id.to_be_bytes());
    r.extend_from_slice(&0x8180u16.to_be_bytes()); // QR | RD | RA
    r.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    r.extend_from_slice(&(txts.len() as u16).to_be_bytes()); // ANCOUNT
    r.extend_from_slice(&0u16.to_be_bytes());
    r.extend_from_slice(&0u16.to_be_bytes());
    // Question.
    for label in qname.split('.') {
        if label.is_empty() {
            continue;
        }
        r.push(label.len() as u8);
        r.extend_from_slice(label.as_bytes());
    }
    r.push(0);
    r.extend_from_slice(&QTYPE_TXT.to_be_bytes());
    r.extend_from_slice(&QCLASS_IN.to_be_bytes());
    // Answers.
    for txt in txts {
        r.push(0xC0);
        r.push(0x0C); // name pointer -> qname
        r.extend_from_slice(&QTYPE_TXT.to_be_bytes());
        r.extend_from_slice(&QCLASS_IN.to_be_bytes());
        r.extend_from_slice(&30u32.to_be_bytes()); // TTL
        let bytes = txt.as_bytes();
        let rdlen = 1 + bytes.len();
        r.extend_from_slice(&(rdlen as u16).to_be_bytes());
        r.push(bytes.len() as u8);
        r.extend_from_slice(bytes);
    }
    r
}

/// Handle one incoming DNS datagram. Returns `None` when the packet is not a
/// well-formed tunnel query under the configured base domain (or the session is
/// not authorized) — the caller should then simply drop it.
pub fn handle_datagram(pkt: &[u8], server: &DnsTunnelServer) -> Option<Vec<u8>> {
    let (id, qname, qtype, _qclass) = parse_question(pkt).ok()?;
    if qtype != QTYPE_TXT {
        return None;
    }
    let frame = TunnelFrame::decode_name(&qname, &server.base_domain).ok()?;
    if !server.handler.authorized(&frame) {
        return None;
    }
    let reply = server.handler.handle(&frame);
    // Doctrine B: when auth is enabled, seal the reply payload so a poisoned
    // or spoofed answer cannot impersonate the authoritative server.
    let payload = match &server.handler.auth_key {
        Some(key) => crate::dnstunnel_auth::seal(key, &reply.payload),
        None => reply.payload,
    };
    let reply_frame = TunnelFrame {
        session: frame.session.clone(),
        seq: frame.seq,
        flags: reply.flags,
        payload,
    };
    let nonce: u32 = rand::random::<u32>() & 0xFFFF;
    let reply_name = reply_frame.encode_name(&server.base_domain, nonce);
    Some(build_dns_response_txt(id, &qname, &[reply_name]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doh::{build_dns_query_txt, parse_dns_response_txt};

    fn test_server() -> DnsTunnelServer {
        DnsTunnelServer::new("tun.example.com", TunnelHandler::default())
    }

    #[test]
    fn parse_question_roundtrip() {
        let q = build_dns_query_txt("dead.beef.0.0.sess.tun.example.com", 0x4321);
        let (id, qname, qtype, qclass) = parse_question(&q).unwrap();
        assert_eq!(id, 0x4321);
        assert_eq!(qname, "dead.beef.0.0.sess.tun.example.com");
        assert_eq!(qtype, QTYPE_TXT);
        assert_eq!(qclass, QCLASS_IN);
    }

    #[test]
    fn roundtrip_client_server_status() {
        let base = "tun.example.com";
        let server = test_server();
        // Client crafts a status request (flags=2).
        let req = TunnelFrame {
            session: "sess".into(),
            seq: 7,
            flags: 2,
            payload: b"".to_vec(),
        };
        let qname = req.encode_name(base, 0xABCD);
        let query = build_dns_query_txt(&qname, 0x4321);
        let resp = handle_datagram(&query, &server).unwrap();
        let txts = parse_dns_response_txt(&resp).unwrap();
        assert_eq!(txts.len(), 1);
        let reply = TunnelFrame::decode_name(&txts[0], base).unwrap();
        assert_eq!(reply.flags, 2);
        assert!(String::from_utf8_lossy(&reply.payload).starts_with("up:"));
        assert_eq!(reply.seq, 7);
    }

    #[test]
    fn roundtrip_client_server_ping() {
        let base = "tun.example.com";
        let server = test_server();
        let req = TunnelFrame {
            session: "s".into(),
            seq: 1,
            flags: 1,
            payload: b"alive".to_vec(),
        };
        let qname = req.encode_name(base, 1);
        let query = build_dns_query_txt(&qname, 9);
        let resp = handle_datagram(&query, &server).unwrap();
        let txts = parse_dns_response_txt(&resp).unwrap();
        let reply = TunnelFrame::decode_name(&txts[0], base).unwrap();
        assert_eq!(reply.flags, 1);
        assert_eq!(reply.payload, b"pong");
    }

    #[test]
    fn bootstrap_served_on_flag_3() {
        let base = "tun.example.com";
        let server = DnsTunnelServer::new(
            base,
            TunnelHandler::new(
                None,
                Some(BootstrapInfo {
                    blob: b"worker://dyb.tunnel.workers.dev".to_vec(),
                }),
            ),
        );
        let req = TunnelFrame {
            session: "s".into(),
            seq: 3,
            flags: 3,
            payload: vec![],
        };
        let qname = req.encode_name(base, 2);
        let query = build_dns_query_txt(&qname, 10);
        let resp = handle_datagram(&query, &server).unwrap();
        let txts = parse_dns_response_txt(&resp).unwrap();
        let reply = TunnelFrame::decode_name(&txts[0], base).unwrap();
        assert_eq!(reply.payload, b"worker://dyb.tunnel.workers.dev");
    }

    #[test]
    fn data_frame_echoes() {
        let base = "tun.example.com";
        let server = test_server();
        let req = TunnelFrame {
            session: "s".into(),
            seq: 9,
            flags: 0,
            payload: b"hello".to_vec(),
        };
        let qname = req.encode_name(base, 3);
        let query = build_dns_query_txt(&qname, 11);
        let resp = handle_datagram(&query, &server).unwrap();
        let txts = parse_dns_response_txt(&resp).unwrap();
        let reply = TunnelFrame::decode_name(&txts[0], base).unwrap();
        assert_eq!(reply.payload, b"hello");
    }

    #[test]
    fn unauthorized_session_is_dropped() {
        let base = "tun.example.com";
        let mut allow = HashSet::new();
        allow.insert("good".to_string());
        let server = DnsTunnelServer::new(base, TunnelHandler::new(Some(allow), None));
        let req = TunnelFrame {
            session: "bad".into(),
            seq: 1,
            flags: 1,
            payload: vec![],
        };
        let qname = req.encode_name(base, 4);
        let query = build_dns_query_txt(&qname, 12);
        assert!(handle_datagram(&query, &server).is_none());
        // And a good session is answered.
        let ok = TunnelFrame {
            session: "good".into(),
            seq: 1,
            flags: 1,
            payload: vec![],
        };
        let qname2 = ok.encode_name(base, 5);
        let query2 = build_dns_query_txt(&qname2, 13);
        assert!(handle_datagram(&query2, &server).is_some());
    }

    #[test]
    fn non_tunnel_query_is_ignored() {
        let server = test_server();
        let query = build_dns_query_txt("plain.example.com", 14);
        assert!(handle_datagram(&query, &server).is_none());
    }

    #[test]
    fn garbage_datagram_is_ignored() {
        let server = test_server();
        assert!(handle_datagram(b"\x00\x01\x00\x00\x00", &server).is_none());
        assert!(handle_datagram(b"", &server).is_none());
    }

    #[test]
    fn response_roundtrip_with_client_parser() {
        // The full end-to-end assurance: our response must be parseable by the
        // same parser the client uses (parse_dns_response_txt).
        let base = "tun.example.com";
        let server = test_server();
        let req = TunnelFrame {
            session: "sess".into(),
            seq: 42,
            flags: 1,
            payload: vec![],
        };
        let qname = req.encode_name(base, 0xFFFF);
        let query = build_dns_query_txt(&qname, 0x1234);
        let resp = handle_datagram(&query, &server).unwrap();
        let txts = parse_dns_response_txt(&resp).unwrap();
        assert_eq!(txts.len(), 1);
        assert!(txts[0].ends_with(".tun.example.com"));
        let decoded = TunnelFrame::decode_name(&txts[0], base).unwrap();
        assert_eq!(decoded.seq, 42);
        assert_eq!(decoded.session, "sess");
    }

    #[test]
    fn authenticated_reply_is_sealed_and_opens_with_key() {
        // Doctrine B: server seals the reply; a client with the key can open
        // it, and a tampered/forged reply is rejected.
        let key_hex = crate::dnstunnel_auth::KEY_HEX_LEN;
        let key = crate::dnstunnel_auth::DnsTunnelKey::from_hex(&"a1".repeat(key_hex / 2)).unwrap();
        let base = "tun.example.com";
        let server =
            DnsTunnelServer::new(base, TunnelHandler::new(None, None).with_auth(key.clone()));

        let req = TunnelFrame {
            session: "sess".into(),
            seq: 7,
            flags: 1,
            payload: b"alive".to_vec(),
        };
        let qname = req.encode_name(base, 0xABCD);
        let query = build_dns_query_txt(&qname, 0x4321);
        let resp = handle_datagram(&query, &server).unwrap();
        let txts = parse_dns_response_txt(&resp).unwrap();
        assert_eq!(txts.len(), 1);
        let reply = TunnelFrame::decode_name(&txts[0], base).unwrap();
        assert_eq!(reply.flags, 1);
        assert_eq!(reply.seq, 7);

        // The payload must NOT be the plaintext "pong" — it is sealed.
        assert_ne!(reply.payload, b"pong");

        // Opening with the key recovers the plaintext.
        let plain = crate::dnstunnel_auth::open(&key, &reply.payload).unwrap();
        assert_eq!(plain, b"pong");

        // Tampering with the ciphertext must fail authentication.
        let mut bad = reply.payload.clone();
        let n = bad.len();
        bad[n - 2] ^= 0x01;
        assert!(crate::dnstunnel_auth::open(&key, &bad).is_err());
    }
}
