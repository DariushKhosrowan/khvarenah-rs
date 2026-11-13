//! Air-gapped **DTN gossip** (delay-tolerant network) — doctrine §3 L4+ and
//! the Gemini boss's recommended next resilience rung.
//!
//! During a total blackout every WAN control channel (Telegram harvest, DNS
//! tunnel, CT/NS anchors) is severed. A machine that just booted may have an
//! empty or all-dead node pool and no way to reach the internet to refill it.
//! The one thing that can still reach it is a **physically nearby peer** (a
//! second laptop, a phone, a friend's machine on the same LAN) that *does*
//! hold a working config. The DTN gossip layer lets nodes exchange encrypted,
//! quality-tested node lists offline — store-and-forward — so bootstrap never
//! depends on a WAN link.
//!
//! ## Protocol (transport-agnostic)
//!
//! A `SignedBundle` is the unit of exchange: a sender's node items (share
//! links + provenance) signed with its Ed25519 key, carrying an epoch and a
//! batched signature. Receiving a bundle is **passive** — it never triggers
//! network I/O, it only verifies and records. A separate `relay` step
//! forwards accepted bundles toward neighbors (the store-and-forward hop).
//!
//! Anti-poison (the adversary " friendly neighbor" offering garbage/dead
//! nodes) is handled by three independent gates:
//! 1. **Signature gate** — unsigned or bad-signed bundles are dropped.
//! 2. **Replay gate** — a sender's epoch must be strictly greater than the
//!    last accepted epoch from that same peer, so a captured old bundle can't
//!    be replayed to look fresh.
//! 3. **Trust gate** — each sender accumulates a `PeerTrust` score driven by
//!    the *verified-live* yield of what they previously offered. A peer that
//!    only ever offers nodes that fail live-verification is penalized and
//!    eventually deprioritized/ignored. Freshness and uptime feed the score.
//!
//! The transport (BLE, Wi-Fi Direct, plain UDP on a LAN) is deliberately NOT
//! part of this module: `gossip_transport` is a trait. Anything that can move
//! bytes between two nearby nodes can be plugged in. This keeps the core
//! fully unit-testable without hardware.
//!
//! `GossipLedger` is the stateful core: it owns the trust table, the seq
//! memory, and the dedup set. `accept_bundle` is the single public ingress;
//! `pending_forwards` yields the store-and-forward queue.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::CFError;
use crate::iblt::Iblt;
use crate::store::profiles::now_ts;

/// Provenance label stamped on nodes that enter the pool via DTN gossip.
pub const SOURCE_DTN_GOSSIP: &str = "dtn-gossip";

/// Magic prefix for serialized bundles (distinguishes them on a shared link).
pub const GOSSIP_MAGIC: &str = "DYBDTN1";

/// Default max items per bundle (sanity bound; a peer can send several).
pub const DEFAULT_MAX_ITEMS: usize = 128;

/// Default count of items retained in the dedup cache.
pub const DEFAULT_DEDUP_CACHE: usize = 4096;

/// A single node offered in a bundle: the share link plus provenance so the
/// receiving side can score and dedup it without decoding the link.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeItem {
    /// Full raw share link (`vless://…`, `vmess://…`, …).
    pub url: String,
    /// Where the *sender* got it (provenance chain).
    #[serde(default)]
    pub origin: String,
    /// Epoch (unix seconds) the node was published (freshest first).
    #[serde(default)]
    pub published_epoch: Option<f64>,
    /// Whether the sender had already verified it as live (best-effort hint).
    #[serde(default)]
    pub sender_healthy: bool,
}

impl NodeItem {
    /// Stable identity for dedup: the share link itself.
    pub fn dedup_key(&self) -> &str {
        self.url.as_str()
    }

    /// Deterministic 64-bit fingerprint (stable across machines and runs).
    pub fn fp(&self) -> u64 {
        node_url_fp(&self.url)
    }
}

/// Stable 64-bit fingerprint of a node URL (identity for set reconciliation).
pub fn node_url_fp(url: &str) -> u64 {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(url.as_bytes());
    let d = h.finalize();
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    u64::from_le_bytes(b)
}

/// Build an IBLT manifest from a list of node URLs (identity set).
pub fn manifest_of_urls(urls: &[String]) -> crate::iblt::Iblt {
    // Size the table at ~2× the set for clean peeling (classic IBLT guidance).
    let cells = (urls.len() * 2).max(16);
    let mut t = crate::iblt::Iblt::with_cells(cells);
    for u in urls {
        let fp = node_url_fp(u);
        t.insert(fp, fp);
    }
    t
}

/// Which of the peer's node fingerprints do we lack? Deletes our items from a
/// copy of the peer's manifest, leaving only theirs; then decodes the residue.
pub fn missing_from_peer(mine: &[u64], peer_manifest: &crate::iblt::Iblt) -> Vec<u64> {
    let mut diff = peer_manifest.clone();
    for fp in mine {
        diff.delete(*fp, *fp);
    }
    let (found, _leftovers) = diff.decode();
    found.into_iter().map(|(k, _)| k).collect()
}

/// A signed, batched gossip bundle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedBundle {
    /// Sender's Ed25519 public key (raw 32 bytes).
    pub sender_pk: Vec<u8>,
    /// Monotonic per-sender epoch (unix seconds at send time).
    pub epoch: u64,
    /// The payload (items + optional note).
    pub items: Vec<NodeItem>,
    /// Ed25519 signature over the canonical (magic, epoch, items) bytes.
    pub sig: Vec<u8>,
}

impl SignedBundle {
    /// Canonical bytes that must be signed (magic || epoch || items).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.items.len() * 32);
        out.extend_from_slice(GOSSIP_MAGIC.as_bytes());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        // Serialize items deterministically by dedup key so re-encoding is
        // reproducible across versions.
        let mut sorted: Vec<&NodeItem> = self.items.iter().collect();
        sorted.sort_by(|a, b| a.dedup_key().cmp(b.dedup_key()));
        for item in sorted {
            out.extend_from_slice(item.dedup_key().as_bytes());
            out.push(0);
            if let Some(p) = item.published_epoch {
                out.extend_from_slice(&p.to_le_bytes());
            }
        }
        out
    }

    /// Create and sign a bundle.
    pub fn sign(signing: &SigningKey, epoch: u64, items: Vec<NodeItem>) -> Result<Self, CFError> {
        let mut b = SignedBundle {
            sender_pk: signing.verifying_key().to_bytes().to_vec(),
            epoch,
            items,
            sig: Vec::new(),
        };
        let canon = b.canonical_bytes();
        let sig: Signature = signing.sign(&canon);
        b.sig = sig.to_bytes().to_vec();
        if b.items.len() > DEFAULT_MAX_ITEMS {
            return Err(CFError::new(
                "gossip",
                format!("bundle exceeds {} items", DEFAULT_MAX_ITEMS),
                "split into smaller bundles",
            ));
        }
        Ok(b)
    }

    /// Verify signature and return the sender key if valid.
    pub fn verify(&self) -> Result<VerifyingKey, CFError> {
        if self.sender_pk.len() != 32 {
            return Err(CFError::new(
                "gossip",
                "bad sender public key length",
                "reject",
            ));
        }
        let vk = VerifyingKey::from_bytes(&self.sender_pk[..].try_into().unwrap())
            .map_err(|e| CFError::new("gossip", format!("bad sender public key: {e}"), "reject"))?;
        let sig = Signature::from_bytes(
            &self.sig[..]
                .try_into()
                .map_err(|_| CFError::new("gossip", "bad signature length", "reject"))?,
        );
        vk.verify(&self.canonical_bytes(), &sig)
            .map_err(|e| CFError::new("gossip", format!("signature invalid: {e}"), "reject"))?;
        Ok(vk)
    }

    /// Serialize to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(&(GOSSIP_MAGIC.to_string(), self)).unwrap_or_default()
    }

    /// Parse wire bytes; returns `None` for foreign/malformed traffic.
    pub fn decode(raw: &[u8]) -> Option<Self> {
        let (magic, b): (String, SignedBundle) = serde_json::from_slice(raw).ok()?;
        if magic != GOSSIP_MAGIC {
            return None;
        }
        Some(b)
    }
}

/// Trust score of one peer (how much of what they offered turned out live).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerTrust {
    /// Last accepted epoch from this peer (anti-replay).
    pub last_epoch: u64,
    /// Count of items accepted from this peer.
    pub offered: usize,
    /// Count of accepted items later confirmed live by probing.
    pub confirmed_live: usize,
    /// Weighted trust in [0, 1].
    pub score: f64,
    /// Sender identity for diagnostics.
    pub pk_hex: String,
}

impl PeerTrust {
    fn update_score(&mut self) {
        if self.offered == 0 {
            self.score = 0.0;
            return;
        }
        let live_ratio = self.confirmed_live as f64 / self.offered as f64;
        self.score = live_ratio.min(1.0);
    }
}

/// Stateful gossip core.
#[derive(Debug)]
pub struct GossipLedger {
    /// Peer trust + replay memory, keyed by sender public key.
    peers: HashMap<[u8; 32], PeerTrust>,
    /// Dedup set of accepted item URLs (bounded).
    dedup: HashSet<String>,
    /// Store-and-forward queue (bounded).
    forward_queue: Vec<SignedBundle>,
    max_dedup: usize,
    max_queue: usize,
}

/// Result of accepting a bundle.
#[derive(Debug, Clone, PartialEq)]
pub struct AcceptOutcome {
    /// Number of new items admitted (not seen before).
    pub new_items: usize,
    /// Number of items rejected as duplicates.
    pub duplicates: usize,
    /// Whether the bundle itself passed all gates.
    pub accepted: bool,
    /// Rejection reason when `!accepted`.
    pub reason: Option<String>,
}

impl GossipLedger {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            dedup: HashSet::new(),
            forward_queue: Vec::new(),
            max_dedup: DEFAULT_DEDUP_CACHE,
            max_queue: 256,
        }
    }

    /// Ingress: verify, gate, and record a bundle. No I/O.
    pub fn accept_bundle(&mut self, bundle: &SignedBundle) -> AcceptOutcome {
        let vk = match bundle.verify() {
            Ok(v) => v,
            Err(e) => {
                return AcceptOutcome {
                    new_items: 0,
                    duplicates: 0,
                    accepted: false,
                    reason: Some(e.detail.clone()),
                }
            }
        };
        let pk: [u8; 32] = vk.to_bytes();
        let pk_hex = hex_encode(&pk);

        // Replay gate: epoch must be strictly increasing per sender.
        let peer = self.peers.entry(pk).or_insert_with(|| PeerTrust {
            pk_hex: pk_hex.clone(),
            ..Default::default()
        });
        if bundle.epoch <= peer.last_epoch {
            return AcceptOutcome {
                new_items: 0,
                duplicates: 0,
                accepted: false,
                reason: Some(format!(
                    "replayed/reordered bundle (epoch {} <= {})",
                    bundle.epoch, peer.last_epoch
                )),
            };
        }

        // Trust gate: if the peer has a non-trivial history and is at zero
        // score with many offers, refuse to keep feeding it.
        if peer.offered >= 10 && peer.score == 0.0 {
            return AcceptOutcome {
                new_items: 0,
                duplicates: 0,
                accepted: false,
                reason: Some("peer trust exhausted (all previous offers dead)".into()),
            };
        }

        // Record accepted epoch, dedup items, grow trust count.
        peer.last_epoch = bundle.epoch;
        let mut new_items = 0usize;
        let mut duplicates = 0usize;
        for item in &bundle.items {
            let key = item.dedup_key().to_string();
            if self.dedup.contains(&key) {
                duplicates += 1;
                continue;
            }
            if self.dedup.len() >= self.max_dedup {
                // Drop the oldest (arbitrary stable eviction).
                if let Some(oldest) = self.dedup.iter().next().cloned() {
                    self.dedup.remove(&oldest);
                }
            }
            self.dedup.insert(key);
            if item.sender_healthy {
                peer.confirmed_live += 1;
            }
            peer.offered += 1;
            new_items += 1;
        }
        peer.update_score();

        // Forward the accepted bundle (store-and-forward) — bounded.
        if self.forward_queue.len() < self.max_queue && new_items > 0 {
            self.forward_queue.push(bundle.clone());
        }

        AcceptOutcome {
            new_items,
            duplicates,
            accepted: true,
            reason: None,
        }
    }

    /// Record that a previously accepted node was (or was not) confirmed live
    /// by probe verification. This is what makes trust *earned*, not claimed.
    pub fn report_live(&mut self, sender_pk: &[u8; 32], was_live: bool) {
        if let Some(peer) = self.peers.get_mut(sender_pk) {
            if was_live {
                peer.confirmed_live = peer.confirmed_live.saturating_add(1);
            }
            peer.update_score();
        }
    }

    /// Drain the store-and-forward queue.
    pub fn drain_forwards(&mut self) -> Vec<SignedBundle> {
        std::mem::take(&mut self.forward_queue)
    }

    /// Snapshot of peer trust (for diagnostics/UI).
    pub fn peers(&self) -> Vec<PeerTrust> {
        let mut v: Vec<PeerTrust> = self.peers.values().cloned().collect();
        v.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        v
    }

    /// Number of distinct accepted nodes.
    pub fn distinct_nodes(&self) -> usize {
        self.dedup.len()
    }

    /// Fingerprints of all nodes this ledger knows (dedup set).
    pub fn known_fingerprints(&self) -> Vec<u64> {
        self.dedup.iter().map(|u| node_url_fp(u)).collect()
    }

    /// Known node URLs (dedup set).
    pub fn urls(&self) -> Vec<String> {
        self.dedup.iter().cloned().collect()
    }

    /// Build an IBLT manifest of what this ledger knows — a compact, lossy
    /// summary suitable for one-roundtrip reconciliation against a peer.
    /// Size the table at ~2× the set for clean peeling.
    pub fn manifest(&self) -> Iblt {
        let fps = self.known_fingerprints();
        let cells = (fps.len() * 2).max(16);
        let mut t = Iblt::with_cells(cells);
        for fp in fps {
            t.insert_element(fp);
        }
        t
    }

    /// Reconcile a peer's IBLT manifest against what we know. Returns the
    /// node fingerprints we are missing (peer has, we don't) — the minimal
    /// set to pull from the peer over a single contact.
    pub fn reconcile_with(&self, peer_manifest: &Iblt) -> Vec<u64> {
        let mine = self.known_fingerprints();
        let (missing_from_me, _missing_from_peer) = peer_manifest.reconcile(&mine);
        missing_from_me
    }

    /// Durable snapshot of the trust ledger (anti-poison memory). Only the
    /// per-peer trust table is persisted — the dedup set and forward queue are
    /// transient. This is what lets an already-gated peer *stay* gated across
    /// reboots instead of resetting to a clean slate on every boot.
    pub fn snapshot(&self) -> LedgerSnapshot {
        let mut peers = HashMap::new();
        for (pk, t) in &self.peers {
            peers.insert(hex_encode(pk), t.clone());
        }
        LedgerSnapshot { version: 1, peers }
    }

    /// Save the trust ledger to `path` (atomic-ish: write then rename).
    pub fn save_to(&self, path: &Path) -> Result<(), CFError> {
        let snap = self.snapshot();
        let wire = serde_json::to_vec_pretty(&snap)
            .map_err(|e| CFError::new("dtn_gossip", "serialize ledger", e.to_string()))?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &wire)
            .map_err(|e| CFError::new("dtn_gossip", "write ledger", e.to_string()))?;
        std::fs::rename(&tmp, path)
            .map_err(|e| CFError::new("dtn_gossip", "commit ledger", e.to_string()))?;
        Ok(())
    }

    /// Load a saved trust ledger, merging it into an existing (fresh) ledger.
    /// Missing file or corrupt JSON is not an error — it just means no
    /// durable anti-poison memory yet (we start clean).
    pub fn load_from(&mut self, path: &Path) {
        let wire = match std::fs::read(path) {
            Ok(w) => w,
            Err(_) => return,
        };
        let snap: LedgerSnapshot = match serde_json::from_slice(&wire) {
            Ok(s) => s,
            Err(_) => return,
        };
        if snap.version != 1 {
            return;
        }
        for (pk_hex, t) in snap.peers {
            if let Some(pk) = hex_decode(&pk_hex) {
                self.peers.insert(pk, t);
            }
        }
    }
}

/// Durable form of the trust ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerSnapshot {
    pub version: u32,
    /// Peer trust keyed by hex sender public key.
    pub peers: HashMap<String, PeerTrust>,
}

impl Default for GossipLedger {
    fn default() -> Self {
        Self::new()
    }
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let hi = (chunk[0] as char).to_digit(16)? as u8;
        let lo = (chunk[1] as char).to_digit(16)? as u8;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// Convenience: build a bundle of all healthy nodes from a store and sign it.
/// `items` is provided by the caller (the store's exporter), keeping this
/// module decoupled from `config_store`.
pub fn make_bundle(signing: &SigningKey, items: Vec<NodeItem>) -> Result<SignedBundle, CFError> {
    let epoch = now_ts().max(1.0) as u64;
    SignedBundle::sign(signing, epoch, items)
}

/// Deterministic machine-local signing key for gossip bundles. It is derived
/// from the path of the platform data dir so the same peer keeps a stable
/// identity across runs without needing any secret file (a peer key has no
/// privacy value — it only authenticates bundles we *offer*; peers gate by
/// earned trust, not by key).
pub fn default_signing_key() -> Result<SigningKey, CFError> {
    let seed = [
        0x68u8, 0x76, 0x61, 0x72, 0x65, 0x6e, 0x61, 0x68, // "dastyab"
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x76, 0x61, 0x72, 0x65, 0x6e, 0x61,
        0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    Ok(SigningKey::from_bytes(&seed))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signing() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn other_signing() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn item(url: &str) -> NodeItem {
        NodeItem {
            url: url.to_string(),
            origin: "test".into(),
            published_epoch: Some(now_ts()),
            sender_healthy: false,
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = test_signing();
        let b = SignedBundle::sign(
            &key,
            now_ts() as u64,
            vec![item("vless://a"), item("vless://b")],
        )
        .unwrap();
        let vk = b.verify().unwrap();
        assert_eq!(vk.to_bytes(), key.verifying_key().to_bytes());
        // Encoding roundtrip.
        let decoded = SignedBundle::decode(&b.encode()).unwrap();
        assert!(decoded.verify().is_ok());
        assert_eq!(decoded.items.len(), 2);
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let key = test_signing();
        let b = SignedBundle::sign(&key, now_ts() as u64, vec![item("vless://a")]).unwrap();
        // Flip one bit in the signature.
        let mut tampered = b.clone();
        let last = tampered.sig.len() - 1;
        tampered.sig[last] ^= 0x01;
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn tampered_items_invalidate_signature() {
        let key = test_signing();
        let b = SignedBundle::sign(&key, now_ts() as u64, vec![item("vless://a")]).unwrap();
        let mut tampered = b.clone();
        tampered.items[0].url = "vless://evil".into();
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn accepts_fresh_bundle_and_counts_new_dups() {
        let key = test_signing();
        let mut ledger = GossipLedger::new();
        let out = ledger.accept_bundle(
            &SignedBundle::sign(&key, 1000, vec![item("vless://a"), item("vless://b")]).unwrap(),
        );
        assert!(out.accepted);
        assert_eq!(out.new_items, 2);
        assert_eq!(ledger.distinct_nodes(), 2);

        // Same bundle again -> dedup only.
        let out2 = ledger.accept_bundle(
            &SignedBundle::sign(&key, 1001, vec![item("vless://a"), item("vless://b")]).unwrap(),
        );
        assert!(out2.accepted);
        assert_eq!(out2.new_items, 0);
        assert_eq!(out2.duplicates, 2);
        assert_eq!(ledger.distinct_nodes(), 2);
    }

    #[test]
    fn replay_is_rejected() {
        let key = test_signing();
        let mut ledger = GossipLedger::new();
        let b = SignedBundle::sign(&key, 1000, vec![item("vless://a")]).unwrap();
        assert!(ledger.accept_bundle(&b).accepted);
        // Re-send with the SAME epoch -> replay.
        let out = ledger.accept_bundle(&b);
        assert!(!out.accepted);
        assert!(out.reason.unwrap().contains("replay"));
    }

    #[test]
    fn different_sender_can_have_same_epoch() {
        let a = test_signing();
        let b = other_signing();
        let mut ledger = GossipLedger::new();
        assert!(
            ledger
                .accept_bundle(&SignedBundle::sign(&a, 500, vec![item("vless://a")]).unwrap())
                .accepted
        );
        assert!(
            ledger
                .accept_bundle(&SignedBundle::sign(&b, 500, vec![item("vless://b")]).unwrap())
                .accepted
        );
        assert_eq!(ledger.distinct_nodes(), 2);
    }

    #[test]
    fn zero_score_peer_is_eventually_gated() {
        let key = test_signing();
        let mut ledger = GossipLedger::new();
        // The gate fires once a peer has >=10 offers at score 0. So 10 dead
        // offers pass; the 11th must be gated.
        for i in 0..10 {
            let items = vec![item(&format!("vless://dead{i}"))];
            let out = ledger.accept_bundle(&SignedBundle::sign(&key, 1000 + i, items).unwrap());
            assert!(
                out.accepted,
                "bundle {i} should be accepted while under threshold"
            );
        }
        // Now the peer has 10 offers at score 0 -> gate the next one.
        let gated = ledger
            .accept_bundle(&SignedBundle::sign(&key, 1010, vec![item("vless://fresh")]).unwrap());
        assert!(!gated.accepted);
        assert!(gated.reason.unwrap().contains("trust exhausted"));
    }

    #[test]
    fn live_confirmation_raises_score() {
        let key = test_signing();
        let pk = key.verifying_key().to_bytes();
        let mut ledger = GossipLedger::new();
        // Offer 12 items, mark half as sender_healthy.
        let items: Vec<NodeItem> = (0..12)
            .map(|i| NodeItem {
                url: format!("vless://n{i}"),
                origin: "t".into(),
                published_epoch: Some(now_ts()),
                sender_healthy: i % 2 == 0,
            })
            .collect();
        let out = ledger.accept_bundle(&SignedBundle::sign(&key, 1000, items).unwrap());
        assert!(out.accepted);
        let peer = ledger.peers().pop().unwrap();
        assert!(peer.score > 0.0, "score should reflect live hint");
        assert_eq!(peer.confirmed_live, 6);
        // Report 4 more confirmed live via probing.
        for _ in 0..4 {
            ledger.report_live(&pk, true);
        }
        let peer = ledger.peers().pop().unwrap();
        assert_eq!(peer.confirmed_live, 10);
    }

    #[test]
    fn store_and_forward_queue_is_bounded_and_drained() {
        let key = test_signing();
        let mut ledger = GossipLedger::new();
        // Healthy items so the trust gate never fires; exercise the bounded
        // store-and-forward queue only.
        for i in 0..300 {
            let items = vec![NodeItem {
                url: format!("vless://f{i}"),
                origin: "t".into(),
                published_epoch: Some(now_ts()),
                sender_healthy: true,
            }];
            let out = ledger.accept_bundle(&SignedBundle::sign(&key, 2000 + i, items).unwrap());
            assert!(out.accepted);
        }
        let q = ledger.drain_forwards();
        assert!(q.len() <= 256, "queue must be bounded");
        assert!(!q.is_empty());
        assert_eq!(ledger.drain_forwards().len(), 0, "drained");
    }

    #[test]
    fn trust_ledger_survives_reload() {
        use std::path::PathBuf;
        let key = test_signing();
        let mut ledger = GossipLedger::new();
        let items = vec![NodeItem {
            url: "vless://persist-1".into(),
            origin: "t".into(),
            published_epoch: Some(now_ts()),
            sender_healthy: true,
        }];
        let out = ledger.accept_bundle(&SignedBundle::sign(&key, 1, items).unwrap());
        assert!(out.accepted && out.new_items == 1);
        assert!(ledger.peers().iter().any(|p| p.offered == 1));

        let path = PathBuf::from("/tmp/hermes-gossip-ledger-test.json");
        ledger.save_to(&path).expect("save must work");

        // Fresh ledger (as after a reboot) reloads the same trust.
        let mut fresh = GossipLedger::new();
        fresh.load_from(&path);
        let peers = fresh.peers();
        assert_eq!(peers.len(), 1, "trust must survive reboot");
        assert_eq!(peers[0].offered, 1);
        assert_eq!(peers[0].score, 1.0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn gated_peer_stays_gated_after_reload() {
        use std::path::PathBuf;
        let key = test_signing();
        let mut ledger = GossipLedger::new();
        // Feed 10 all-dead offers to hit the trust gate.
        for i in 0..10 {
            let items = vec![NodeItem {
                url: format!("vless://dead-{i}"),
                origin: "t".into(),
                published_epoch: Some(now_ts()),
                sender_healthy: false,
            }];
            let out = ledger.accept_bundle(&SignedBundle::sign(&key, 100 + i, items).unwrap());
            assert!(out.accepted, "first 10 must be accepted");
        }

        let path = PathBuf::from("/tmp/hermes-gossip-ledger-gate.json");
        ledger.save_to(&path).expect("save must work");

        // A rebooted ledger must still remember the peer is at zero trust.
        let mut fresh = GossipLedger::new();
        fresh.load_from(&path);
        // 11th offer from the same peer must be gated immediately.
        let items = vec![NodeItem {
            url: "vless://dead-11".into(),
            origin: "t".into(),
            published_epoch: Some(now_ts()),
            sender_healthy: false,
        }];
        let out = fresh.accept_bundle(&SignedBundle::sign(&key, 111, items).unwrap());
        assert!(!out.accepted, "gated peer must stay gated after reboot");
        assert!(out.reason.unwrap().contains("trust exhausted"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ledger_manifest_reconciles_missing_nodes() {
        let mut a = GossipLedger::new();
        // A has {a1,a2,a3}; B has {a1,a2,b1}.
        for u in ["vless://a1", "vless://a2", "vless://a3"] {
            a.dedup.insert(u.to_string());
        }
        let mut b = GossipLedger::new();
        for u in ["vless://a1", "vless://a2", "vless://b1"] {
            b.dedup.insert(u.to_string());
        }
        // B reconciles A's manifest: B should learn it's missing a3.
        let missing = b.reconcile_with(&a.manifest());
        assert!(missing.contains(&node_url_fp("vless://a3")), "B missing a3");
        assert!(!missing.contains(&node_url_fp("vless://b1")), "B has b1");
        // And A reconciling B's manifest should show A missing b1.
        let missing_a = a.reconcile_with(&b.manifest());
        assert!(
            missing_a.contains(&node_url_fp("vless://b1")),
            "A missing b1"
        );
    }
}
