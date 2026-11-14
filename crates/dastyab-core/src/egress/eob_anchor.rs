//! Signed out-of-band (OOB) egress-anchor ingestion (doctrine §5, §8.1).
//!
//! # Why this exists
//!
//! Bootstrapping must never be circular (PRINCIPLES §5 / §8.1): the client has
//! to be able to recover a *fresh, verified* set of egress anchors from a
//! channel that is independent of the very path that is blacked out. The
//! Telegram harvest / GitHub ingest / CT-log discovery all widen the *source*
//! set, but a censor can trivially forge a Telegram message or poison a GitHub
//! repo, and a CT log only gives hostnames (not configs).
//!
//! This module adds the *signed* out-of-band feed: an operator (or a small
//! group of operators) publishes a relay manifest containing ready-to-import
//! share links, signed with an Ed25519 key whose **public root key is embedded
//! in the binary**. The client can then pull that manifest over any degraded
//! channel (a static endpoint, a DoH/DoT TXT anchor, a local seed file shipped
//! with a past release, or a peer-to-peer mesh) and *cryptographically prove*
//! it came from the keeper of the private key — not from a censor, a MitM, or
//! a tampered cache.
//!
//! # Threat model this closes
//!
//! - **Forgery / tampering.** A poisoned channel can't produce a valid
//!   signature, so a manifest that fails verification is discarded, never
//!   trusted (mirrors the DNS-tunnel auth doctrine).
//! - **Replay / rollback.** A censor could replay an *old valid* manifest to
//!   keep the client stuck on already-burned anchors. Each manifest carries a
//!   monotonic `seq`; the client persists the highest seen seq per profile and
//!   refuses anything older (anti-replay).
//! - **Garbage ingestion.** Even a valid manifest only carries *links*; they
//!   still go through the normal node probe / import pipeline, so only
//!   verified-healthy configs reach the active pool.
//!
//! # Design
//!
//! - `VerifiedManifest` is the public verified result: the anchors (share
//!   links) that passed both the signature check and seq anti-replay.
//! - `verify_manifest` does the crypto + anti-replay pure work (no network).
//! - `ingest_signed` / `ingest_signed_from_seed` glue verification to the
//!   node store import pipeline, so verified anchors land in the same pool the
//!   daemon refill/export uses.
//! - A `#[cfg(test)]`-visible gate (`set_verify_enabled`) keeps hermetic unit
//!   tests from ever hitting the live network, matching the refill/drill/CT
//!   anchor gate pattern.
//!
//! # Key management
//!
//! The embedded root public key lives in [`ROOT_PUBKEY_HEX`]. The matching
//! private key is NOT in this repository — it is held out-of-band by the
//! operator. The seed in this file is a **test-only** keypair used by the unit
//! tests, so the crate is self-contained and fully testable without any secret
//! material; in production the operator replaces `ROOT_PUBKEY_HEX` with the
//! real public key before a release build.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::CFError;
use crate::store;
use crate::store::profiles::profile_dir;

/// Gate for live OOB-anchor ingestion. Production defaults to enabled.
/// Hermetic daemon unit tests disable it (via `daemon_home`) so a daemon tick
/// never triggers a live endpoint fetch from zeroed state.
static VERIFY_ENABLED: AtomicBool = AtomicBool::new(true);

/// Set whether live OOB-anchor ingestion may run.
pub fn set_verify_enabled(v: bool) {
    VERIFY_ENABLED.store(v, Ordering::Relaxed);
}

/// Whether live OOB-anchor ingestion may run.
pub fn verify_enabled() -> bool {
    VERIFY_ENABLED.load(Ordering::Relaxed)
}

/// Provenance label stamped on every node imported from a signed manifest.
pub const SOURCE_OOB_SIGNED: &str = "oob-signed";

/// Filename of the persisted highest-seen sequence counter (anti-replay).
const SEQ_FILE: &str = "oob_anchor_seq.json";

/// Default max anchors accepted from a single manifest (sanity bound).
pub const DEFAULT_MAX_ANCHORS: usize = 256;

/// Filename of the on-disk signed seed manifest inside a profile dir.
pub const SEED_FILENAME: &str = "oob_anchor_seed.json";

/// Daemon rate-limit interval between signed-OOB feed polls (seconds).
pub const OOB_PULL_INTERVAL_SECS: i64 = 6 * 3600;

// ---------------------------------------------------------------------------
// Crypto
// ---------------------------------------------------------------------------

/// Hex-encoded Ed25519 **public** root key used to verify manifests.
///
/// Test seed (public half of the deterministic test keypair — `[0u8;32]`
/// signing key). In a real deployment the operator replaces this with the
/// published root public key.
pub const ROOT_PUBKEY_HEX: &str =
    "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";

/// Parse the root public key.
pub fn root_verifying_key() -> Result<VerifyingKey, CFError> {
    let bytes = hex_to_bytes(ROOT_PUBKEY_HEX)
        .map_err(|e| CFError::new("oob-anchor", "bad ROOT_PUBKEY_HEX", &e))?;
    if bytes.len() != 32 {
        return Err(CFError::new(
            "oob-anchor",
            "root public key must be 32 bytes",
            format!("len={}", bytes.len()),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| CFError::new("oob-anchor", "bad root public key", e.to_string()))
}

/// Deterministic Ed25519 keypair for tests and local manifest *signing*
/// (e.g. `oob sign` for the operator / a test harness). Not for production.
fn test_signing_key() -> SigningKey {
    // 32 zero bytes -> deterministic key (fine for tests / local signing).
    SigningKey::from_bytes(&[0u8; 32])
}

/// Sign a manifest body (operator-side helper; also used by tests).
pub fn sign_body(body: &[u8]) -> Vec<u8> {
    test_signing_key().sign(body).to_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// Manifest schema
// ---------------------------------------------------------------------------

/// One anchor in a signed manifest: a ready-to-import share link plus labels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestAnchor {
    /// Share link: vless:// vmess:// trojan:// ss:// hysteria2:// tuic:// …
    pub link: String,
    /// Optional human note (e.g. "Oracle Dubai A1").
    #[serde(default)]
    pub note: String,
    /// Optional region hint (e.g. "ae", "de", "sg").
    #[serde(default)]
    pub region: String,
}

/// The signed payload: monotonic seq + anchors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestBody {
    /// Monotonic sequence; must exceed the last seen to be accepted.
    pub seq: u64,
    /// Unix epoch at creation (informational only).
    pub created_at: i64,
    /// The anchors.
    pub anchors: Vec<ManifestAnchor>,
}

/// A full signed manifest (body + signature).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedManifest {
    #[serde(flatten)]
    pub body: ManifestBody,
    /// Ed25519 signature over the canonical body bytes, hex-encoded.
    pub signature_hex: String,
}

/// Result of a successful verification.
#[derive(Debug, Clone)]
pub struct VerifiedManifest {
    pub seq: u64,
    pub anchors: Vec<ManifestAnchor>,
}

// ---------------------------------------------------------------------------
// Canonical bytes & crypto
// ---------------------------------------------------------------------------

/// Canonical bytes to sign / verify: a stable, field-ordered JSON of the body.
pub fn canonical_body_bytes(body: &ManifestBody) -> Result<Vec<u8>, CFError> {
    serde_json::to_vec(body)
        .map_err(|e| CFError::new("oob-anchor", "serialize body", e.to_string()))
}

/// Verify a signed manifest's signature against the root key.
pub fn verify_signature(manifest: &SignedManifest) -> Result<(), CFError> {
    let vk = root_verifying_key()?;
    let sig_bytes = hex_to_bytes(&manifest.signature_hex)
        .map_err(|e| CFError::new("oob-anchor", "bad signature hex", &e))?;
    if sig_bytes.len() != 64 {
        return Err(CFError::new("oob-anchor", "signature must be 64 bytes", ""));
    }
    // ed25519-dalek v3: `Signature::from_bytes` is infallible (an opaque
    // 64-byte container; verification happens against the public key below).
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);
    let body = canonical_body_bytes(&manifest.body)?;
    vk.verify(&body, &sig)
        .map_err(|e| CFError::new("oob-anchor", "signature verification failed", e.to_string()))
}

// ---------------------------------------------------------------------------
// Anti-replay sequence
// ---------------------------------------------------------------------------

fn seq_path(profile: &str) -> PathBuf {
    profile_dir(profile).join(SEQ_FILE)
}

/// Highest seq accepted so far for a profile (0 if none).
pub fn last_seen_seq(profile: &str) -> u64 {
    store::read_opt::<SerdeU64>(&seq_path(profile))
        .map(|s| s.0)
        .unwrap_or(0)
}

/// Persist the highest accepted seq.
pub fn set_last_seen_seq(profile: &str, seq: u64) -> Result<(), CFError> {
    let bytes = serde_json::to_vec(&SerdeU64(seq))
        .map_err(|e| CFError::new("oob-anchor", "serialize seq", e.to_string()))?;
    store::atomic_write(&seq_path(profile), &bytes)
}

#[derive(Serialize, Deserialize)]
struct SerdeU64(u64);

// ---------------------------------------------------------------------------
// Public verification API
// ---------------------------------------------------------------------------

/// Fully verify a manifest: signature check + anti-replay against the profile's
/// last-seen seq. Pure / network-free.
pub fn verify_manifest(
    profile: &str,
    manifest: &SignedManifest,
) -> Result<VerifiedManifest, CFError> {
    verify_signature(manifest)?;
    let last = last_seen_seq(profile);
    if manifest.body.seq <= last {
        return Err(CFError::new(
            "oob-anchor",
            "replay/rollback rejected (seq not newer)",
            format!("seq={} last_seen={}", manifest.body.seq, last),
        ));
    }
    if manifest.body.anchors.len() > DEFAULT_MAX_ANCHORS {
        return Err(CFError::new(
            "oob-anchor",
            "manifest has too many anchors",
            format!("count={}", manifest.body.anchors.len()),
        ));
    }
    set_last_seen_seq(profile, manifest.body.seq)?;
    Ok(VerifiedManifest {
        seq: manifest.body.seq,
        anchors: manifest.body.anchors.clone(),
    })
}

// ---------------------------------------------------------------------------
// Ingestion glue (verification + import into the verified-healthy pool)
// ---------------------------------------------------------------------------

/// Result of ingesting a verified manifest.
#[derive(Debug, Clone, Default)]
pub struct IngestReport {
    pub accepted: usize,
    pub duplicates: usize,
    pub rejected: usize,
}

/// Ingest a *verified* manifest's anchors into the profile's node store.
/// Each anchor is imported with provenance `oob-signed`, so it flows through
/// the same dedupe/pool logic as every other source (nothing lands in the
/// active pool simply by being signed — it must still be a valid share link).
pub fn ingest_verified(
    profile: &str,
    verified: &VerifiedManifest,
) -> Result<IngestReport, CFError> {
    let mut report = IngestReport::default();
    for a in &verified.anchors {
        match crate::artifact::config_store::import_single_link_source(
            profile,
            &a.link,
            SOURCE_OOB_SIGNED,
        ) {
            Ok(sum) => {
                if sum.added > 0 {
                    report.accepted += 1;
                } else {
                    report.duplicates += 1;
                }
            }
            Err(_) => report.rejected += 1,
        }
    }
    Ok(report)
}

/// Parse a JSON string into a signed manifest, then fully verify it.
pub fn parse_and_verify(profile: &str, json: &str) -> Result<VerifiedManifest, CFError> {
    let manifest: SignedManifest = serde_json::from_str(json)
        .map_err(|e| CFError::new("oob-anchor", "parse manifest JSON", e.to_string()))?;
    verify_manifest(profile, &manifest)
}

/// Ingest from a raw JSON manifest string (verify + import).
pub fn ingest_signed(profile: &str, json: &str) -> Result<IngestReport, CFError> {
    let verified = parse_and_verify(profile, json)?;
    ingest_verified(profile, &verified)
}

/// Ingest from a local seed file path (verify + import). This is the offline
/// bootstrap path: a manifest shipped with an old release can be re-read to
/// recover anchors even with no connectivity at all.
pub fn ingest_signed_from_seed(profile: &str, path: &Path) -> Result<IngestReport, CFError> {
    let json = std::fs::read_to_string(path)
        .map_err(|e| CFError::new("oob-anchor", "read seed file", e.to_string()))?;
    ingest_signed(profile, &json)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Hex -> bytes (lowercase).
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let h = hex.trim();
    if !h.len().is_multiple_of(2) {
        return Err("odd hex length".into());
    }
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).map_err(|e| format!("bad hex at {i}: {e}")))
        .collect()
}

/// Bytes -> lowercase hex.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Build a signed manifest from a body using the test signing key
/// (operator helper / tests).
pub fn make_signed(body: ManifestBody) -> SignedManifest {
    let sig = sign_body(&canonical_body_bytes(&body).unwrap());
    SignedManifest {
        body,
        signature_hex: bytes_to_hex(&sig),
    }
}

/// Convenience: build a verified-ready manifest body from anchor links.
pub fn build_body(seq: u64, created_at: i64, links: &[&str]) -> ManifestBody {
    ManifestBody {
        seq,
        created_at,
        anchors: links
            .iter()
            .map(|l| ManifestAnchor {
                link: l.to_string(),
                note: String::new(),
                region: String::new(),
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Run `f` with a throwaway mem-dir home (mirrors `store/profiles.rs`).
    fn with_home(f: impl FnOnce(&str)) {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join(".dastyab");
        crate::store::set_mem_dir_override(base);
        let profile = "oob-test-profile".to_string();
        f(&profile);
    }

    #[test]
    fn test_hex_roundtrip() {
        let bytes = vec![0u8, 1, 2, 0xfe, 0xff];
        assert_eq!(hex_to_bytes(&bytes_to_hex(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn test_verify_accepts_valid_signed_manifest() {
        with_home(|profile| {
            let body = build_body(1, 1_700_000_000, &["vless://x"]);
            let signed = make_signed(body);
            let verified = verify_manifest(profile, &signed).expect("should verify");
            assert_eq!(verified.seq, 1);
            assert_eq!(verified.anchors.len(), 1);
            assert_eq!(last_seen_seq(profile), 1);
        });
    }

    #[test]
    fn test_replay_rejected() {
        with_home(|profile| {
            let body = build_body(5, 1_700_000_000, &["vless://x"]);
            let signed = make_signed(body);
            verify_manifest(profile, &signed).expect("first accept");
            // Replay same seq -> must be rejected.
            assert!(verify_manifest(profile, &signed).is_err());
            // Even a valid signature with an OLDER seq must be rejected.
            let older = make_signed(build_body(3, 1_600_000_000, &["vless://x"]));
            assert!(verify_manifest(profile, &older).is_err());
        });
    }

    #[test]
    fn test_tampered_signature_rejected() {
        with_home(|profile| {
            let body = build_body(1, 1_700_000_000, &["vless://x"]);
            let mut signed = make_signed(body);
            // Flip a bit in the signature -> must fail verification.
            let mut sig = hex_to_bytes(&signed.signature_hex).unwrap();
            sig[0] ^= 0x01;
            signed.signature_hex = bytes_to_hex(&sig);
            assert!(verify_manifest(profile, &signed).is_err());
        });
    }

    #[test]
    fn test_manifest_too_many_anchors_rejected() {
        with_home(|profile| {
            let links: Vec<String> = (0..300).map(|i| format!("vless://x{i}")).collect();
            let body = ManifestBody {
                seq: 1,
                created_at: 1_700_000_000,
                anchors: links
                    .iter()
                    .map(|l| ManifestAnchor {
                        link: l.clone(),
                        note: String::new(),
                        region: String::new(),
                    })
                    .collect(),
            };
            let signed = make_signed(body);
            assert!(verify_manifest(profile, &signed).is_err());
        });
    }

    #[test]
    fn test_parse_and_verify_json_roundtrip() {
        with_home(|profile| {
            let body = build_body(1, 1_700_000_000, &["vless://aaa"]);
            let signed = make_signed(body);
            let json = serde_json::to_string(&signed).unwrap();
            let verified = parse_and_verify(profile, &json).expect("verify");
            assert_eq!(verified.anchors[0].link, "vless://aaa");
        });
    }

    #[test]
    fn test_ingest_verified_uses_source_provenance() {
        with_home(|profile| {
            // A genuinely valid share link that imports cleanly.
            let link = "vless://abc123-def@example.com:443?security=reality&sni=www.example.com#t";
            let body = build_body(1, 1_700_000_000, &[link]);
            let signed = make_signed(body);
            let verified = verify_manifest(profile, &signed).expect("verify");
            let report = ingest_verified(profile, &verified).expect("ingest");
            assert!(report.accepted == 1 || report.duplicates == 1, "{report:?}");
            // The imported node must carry the oob-signed provenance.
            let store = crate::artifact::config_store::load_node_store(profile);
            assert!(store.nodes.iter().any(|n| n.source == SOURCE_OOB_SIGNED));
        });
    }

    #[test]
    fn test_verify_enabled_gate() {
        // Self-contained: an unrelated test may have flipped the global gate,
        // so don't assume the default — drive it explicitly and restore.
        set_verify_enabled(true);
        assert!(verify_enabled());
        set_verify_enabled(false);
        assert!(!verify_enabled());
        set_verify_enabled(true);
    }
}
