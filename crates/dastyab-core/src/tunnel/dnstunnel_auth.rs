//! Authenticated DNS-tunnel responses (doctrine B).
//!
//! A naive DNS tunnel trusts whatever TXT reply comes back from the resolver
//! pool, a domestic recursive resolver recurses to our delegated authoritative
//! server, an adversary can inject a spoofed response that looks like a real
//! one (fake `10.10.34.34` sinks, forged NXDOMAIN, or a replayed old reply).
//! Bogus answers must never be trusted.
//!
//! This module wraps every server → client reply payload in a
//! ChaCha20-Poly1305 authenticated ciphertext. The **key** is derived from a
//! per-session shared secret (pre-shared on both ends of the tunnel). On the
//! client, a reply that fails authentication is discarded — and the resolver
//! that returned it is penalized in the health table.
//!
//! # Layout
//!
//! The authenticated payload carried inside the existing DNS-tunnel reply
//! frame is:
//!
//! ```text
//! +------------------------+------------------------+-------------+
//! | nonce (12 bytes)       | ciphertext + tag (var) | session tag  |
//! +------------------------+------------------------+-------------+
//! ```
//!
//! - `nonce`: 96-bit random nonce (ChaCha20-Poly1305 standard).
//! - ciphertext+tag: AEAD output covering `nonce || plaintext`.
//! - `session`: an 8-hex-char tag (low 32 bits of the key) so the client can
//!   look up the right key on multi-session pools.
//!
//! # Threat coverage
//!
//! - **Replay/forgery** — AEAD tag fails unless the exact key is held.
//! - **Spoofed sink answers** — `10.10.34.34` etc. fail tag verification.
//! - **Tampering** — any flipped byte fails the tag.
//!
//! # Safety / zero-config
//!
//! The shared secret is provisioned out-of-band (pre-distributed config, or
//! the bootstrap blob served by `dnstt-server` under a separate one-time
//! exchange). `DnsTunnelKey::from_hex` reads a 32-byte hex secret from
//! `KV_KH.V_SECRET`.

use crate::error::CFError;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

/// Length of the AEAD nonce (standard for ChaCha20-Poly1305).
pub const NONCE_LEN: usize = 12;
/// Length of the Poly1305 authentication tag (encrypted after ciphertext).
pub const TAG_LEN: usize = 16;
/// Hex length of the full 32-byte secret key.
pub const KEY_HEX_LEN: usize = 64;
/// Hex length of the short session tag (low 32 bits of key).
pub const SESSION_TAG_HEX_LEN: usize = 8;

/// A session's shared secret, held as the raw 32-byte key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsTunnelKey {
    key: [u8; 32],
    /// Short (8-hex) session tag for multi-session key lookup.
    pub session_tag: String,
}

impl DnsTunnelKey {
    /// Build from a raw 32-byte key slice.
    pub fn from_bytes(raw: &[u8]) -> Self {
        let mut key = [0u8; 32];
        let n = raw.len().min(32);
        key[..n].copy_from_slice(&raw[..n]);
        let session_tag = format!(
            "{:08x}",
            u32::from_be_bytes([key[28], key[29], key[30], key[31]])
        );
        Self { key, session_tag }
    }

    /// Parse a 64-hex-char secret.
    pub fn from_hex(hex: &str) -> Result<Self, CFError> {
        let hex = hex.trim();
        if hex.len() != KEY_HEX_LEN {
            return Err(CFError::new(
                "dns-tunnel-auth",
                format!("secret must be {KEY_HEX_LEN} hex chars, got {}", hex.len()),
                "Re-provision the secret with a 32-byte hex value.",
            ));
        }
        let mut key = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let pair = std::str::from_utf8(chunk)
                .map_err(|_| CFError::new("dns-tunnel-auth", "non-UTF8 hex", ""))?;
            key[i] = u8::from_str_radix(pair, 16)
                .map_err(|_| CFError::new("dns-tunnel-auth", "invalid hex", ""))?;
        }
        Ok(Self::from_bytes(&key))
    }

    /// 32-byte key slice.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

/// Encrypt and authenticate a reply payload.
pub fn seal(key: &DnsTunnelKey, plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
    let nonce_bytes: [u8; NONCE_LEN] = rand::random();
    let nonce = Nonce::from(nonce_bytes);
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: key.session_tag.as_bytes(),
            },
        )
        .expect("chacha20poly1305 encrypt cannot fail for in-memory input");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    out
}

/// Decrypt and verify an authenticated reply. Returns the plaintext, or an
/// error if authentication fails (poisoned/injected/tampered answer).
pub fn open(key: &DnsTunnelKey, authed: &[u8]) -> Result<Vec<u8>, CFError> {
    if authed.len() < NONCE_LEN + TAG_LEN {
        return Err(CFError::new(
            "dns-tunnel-auth",
            "auth payload too short",
            "Drop this response; it is not a valid authenticated reply.",
        ));
    }
    let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
    let nonce_bytes: [u8; NONCE_LEN] = authed[..NONCE_LEN]
        .try_into()
        .expect("nonce length checked above");
    let nonce = Nonce::from(nonce_bytes);
    let ct = &authed[NONCE_LEN..];
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ct,
                aad: key.session_tag.as_bytes(),
            },
        )
        .map_err(|_| {
            CFError::new(
                "dns-tunnel-auth",
                "authentication failed (tag mismatch)",
                "The resolver returned a poisoned/spoofed answer; penalize it and retry elsewhere.",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> DnsTunnelKey {
        let raw: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        DnsTunnelKey::from_bytes(&raw)
    }

    #[test]
    fn roundtrip_seal_open() {
        let key = test_key();
        let msg = b"up:12345s|relay:xyz".to_vec();
        let authed = seal(&key, &msg);
        let opened = open(&key, &authed).unwrap();
        assert_eq!(opened, msg);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = test_key();
        let authed = seal(&key, b"up:1s");
        let mut bad = authed.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert!(open(&key, &bad).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let key = test_key();
        let other = DnsTunnelKey::from_bytes(&[9u8; 32]);
        let authed = seal(&key, b"up:2s");
        assert!(open(&other, &authed).is_err());
    }

    #[test]
    fn too_short_fails() {
        let key = test_key();
        assert!(open(&key, b"short").is_err());
    }

    #[test]
    fn from_hex_roundtrip() {
        let hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let key = DnsTunnelKey::from_hex(hex).unwrap();
        let msg = b"alive".to_vec();
        let authed = seal(&key, &msg);
        assert_eq!(open(&key, &authed).unwrap(), msg);
        assert_eq!(key.session_tag.len(), SESSION_TAG_HEX_LEN);
        // 8 hex chars = 4 bytes.
        assert_eq!(key.session_tag, "1d1e1f20");
    }
}
