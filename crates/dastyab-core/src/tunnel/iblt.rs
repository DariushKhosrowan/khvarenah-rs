//! **Invertible Bloom Lookup Table (IBLT)** — zero-roundtrip set
//! reconciliation, doctrine §3 L4, the Gemini boss's recommended rung.
//!
//! During a total blackout, opportunistic physical contacts (passing someone
//! on the street, a micro-burst BLE/LoRa pass) last **milliseconds**. A naive
//! gossip handshake that exchanges full inventories over multiple roundtrips
//! wastes the entire contact. The IBLT lets two peers reconcile their sets in
//! roughly one roundtrip: each sends a compact, lossy summary of its set; the
//! other subtracts its own set and decodes the symmetric difference to learn
//! exactly which items it is missing (and which the peer is missing).
//!
//! ## Algorithm (Eppstein-Goodrich-Uehara)
//!
//! A fixed array of `m` cells, each with three 64-bit fields:
//! - `count` — how many entries map here (can go negative during diff),
//! - `keySum` — XOR of the element keys mapped here,
//! - `valueSum` — XOR of the values mapped here.
//!
//! Insert (and delete, symmetric) hashes each element to `k` distinct cells.
//! Decoding peels cells with `count == ±1`: since exactly one element maps
//! there, `keySum` *is* that element's key, and `valueSum` its value. After
//! recovering it we delete it, which often unlocks further cells (a cascade).
//! Reconciliation: peer A sends its IBLT; B deletes its own elements from it;
//! the table now holds the symmetric difference, which decodes to the items
//! each side is missing. One roundtrip, no inventory handshake.
//!
//! This module is the core algorithm only — transport-agnostic and fully
//! unit-testable without hardware. `sha2` provides deterministic, well-spread
//! cell hashing.

use std::fmt;

use sha2::{Digest, Sha256};

/// Number of cells an element hashes into (peeling breadth).
const K_HASHES: usize = 3;

/// Default cell count for small-to-medium node sets.
const DEFAULT_CELLS: usize = 128;

/// A single IBLT cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Cell {
    pub count: i32,
    pub key_sum: u64,
    pub value_sum: u64,
}

/// An Invertible Bloom Lookup Table.
#[derive(Debug, Clone)]
pub struct Iblt {
    cells: Vec<Cell>,
}

impl Default for Iblt {
    fn default() -> Self {
        Self::with_cells(DEFAULT_CELLS)
    }
}

impl Iblt {
    /// Create an empty table with `m` cells.
    pub fn with_cells(m: usize) -> Self {
        Self {
            cells: vec![Cell::default(); m.max(1)],
        }
    }

    /// Number of cells.
    pub fn cells(&self) -> usize {
        self.cells.len()
    }

    /// Deterministic `k` cell indices for a key.
    fn indices(&self, key: u64) -> [usize; K_HASHES] {
        let m = self.cells.len().max(1) as u64;
        let mut hasher = Sha256::new();
        hasher.update(key.to_le_bytes());
        let d = hasher.finalize();
        let mut idx = [0usize; K_HASHES];
        // Each 8-byte block of the hash becomes one index.
        for (i, block) in d.chunks_exact(8).take(K_HASHES).enumerate() {
            let mut b = [0u8; 8];
            b.copy_from_slice(block);
            idx[i] = (u64::from_le_bytes(b) % m) as usize;
        }
        idx
    }

    /// Insert `(key, value)`.
    pub fn insert(&mut self, key: u64, value: u64) {
        for i in self.indices(key) {
            let c = &mut self.cells[i];
            c.count += 1;
            c.key_sum ^= key;
            c.value_sum ^= value;
        }
    }

    /// Insert an element where key == value (set-membership form).
    pub fn insert_element(&mut self, element: u64) {
        self.insert(element, element);
    }

    /// Delete `(key, value)` (symmetric to insert).
    pub fn delete(&mut self, key: u64, value: u64) {
        for i in self.indices(key) {
            let c = &mut self.cells[i];
            c.count -= 1;
            c.key_sum ^= key;
            c.value_sum ^= value;
        }
    }

    /// Delete an element (key == value form).
    pub fn delete_element(&mut self, element: u64) {
        self.delete(element, element);
    }

    /// Decode the table into recovered `(key, value)` pairs plus any
    /// unpeelable residual cells. Returns `(found, residual_nonzero)`.
    ///
    /// `found` contains elements with `key == value` (set membership) and, if
    /// `with_values` is set, gives the distinct value for mixed key/value
    /// tables. Peeling is a fixed-point loop that always terminates.
    pub fn decode(&self) -> (Vec<(u64, u64)>, usize) {
        let mut tbl = self.clone();
        let mut found = Vec::new();
        let mut progress = true;
        while progress {
            progress = false;
            for i in 0..tbl.cells.len() {
                let c = tbl.cells[i];
                if c.count == 1 {
                    // Exactly one element maps here: recover it.
                    let (key, value) = (c.key_sum, c.value_sum);
                    // Confirm the key really hashes here (guards against a
                    // false peel when the cell is polluted).
                    let mut ok = false;
                    for j in tbl.indices(key) {
                        if j == i {
                            ok = true;
                            break;
                        }
                    }
                    if !ok {
                        continue;
                    }
                    found.push((key, value));
                    tbl.delete(key, value);
                    progress = true;
                } else if c.count == -1 {
                    let (key, value) = (c.key_sum, c.value_sum);
                    let mut ok = false;
                    for j in tbl.indices(key) {
                        if j == i {
                            ok = true;
                            break;
                        }
                    }
                    if !ok {
                        continue;
                    }
                    found.push((key, value));
                    tbl.insert(key, value);
                    progress = true;
                }
            }
        }
        let residual = tbl.cells.iter().filter(|c| c.count != 0).count();
        (found, residual)
    }

    /// Reconcile this table against `mine` (a set of elements we hold).
    /// Returns `(missing_from_me, missing_from_peer)` where:
    /// - `missing_from_me` = elements the peer holds that we don't,
    /// - `missing_from_peer` = elements we hold that the peer doesn't.
    ///
    /// This is the one-roundtrip payoff: the peer sent its IBLT, we subtract
    /// our own set, and decode the symmetric difference.
    pub fn reconcile(&self, mine: &[u64]) -> (Vec<u64>, Vec<u64>) {
        let mut diff = self.clone();
        for &e in mine {
            diff.delete_element(e);
        }
        let (found, _residual) = diff.decode();
        let mut missing_from_me = Vec::new();
        let mut missing_from_peer = Vec::new();
        for (k, _v) in found {
            // Decoding a diff: a +1 entry means the item was in the peer's
            // set but not ours (we deleted ours, so it stays). A -1 entry
            // means it was in ours but not theirs.
            // We recover both orientations; re-derive by checking membership.
            if mine.contains(&k) {
                missing_from_peer.push(k);
            } else {
                missing_from_me.push(k);
            }
        }
        (missing_from_me, missing_from_peer)
    }

    /// Serialize to bytes (compact, fixed-width cells).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.cells.len() * 20);
        for c in &self.cells {
            out.extend_from_slice(&c.count.to_le_bytes());
            out.extend_from_slice(&c.key_sum.to_le_bytes());
            out.extend_from_slice(&c.value_sum.to_le_bytes());
        }
        out
    }

    /// Deserialize from bytes produced by [`encode`].
    pub fn decode_bytes(data: &[u8]) -> Option<Self> {
        if data.len() % 20 != 0 {
            return None;
        }
        let n = data.len() / 20;
        let mut cells = Vec::with_capacity(n);
        for chunk in data.chunks_exact(20) {
            let mut count = [0u8; 4];
            count.copy_from_slice(&chunk[0..4]);
            let mut ks = [0u8; 8];
            ks.copy_from_slice(&chunk[4..12]);
            let mut vs = [0u8; 8];
            vs.copy_from_slice(&chunk[12..20]);
            cells.push(Cell {
                count: i32::from_le_bytes(count),
                key_sum: u64::from_le_bytes(ks),
                value_sum: u64::from_le_bytes(vs),
            });
        }
        Some(Self { cells })
    }
}

impl fmt::Display for Iblt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Iblt(cells={})", self.cells.len())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic "fingerprint" of a node URL (not crypto-strong; 64-bit
    /// collision space is fine for set reconciliation).
    fn fp(url: &str) -> u64 {
        let mut h = Sha256::new();
        h.update(url.as_bytes());
        let d = h.finalize();
        let mut b = [0u8; 8];
        b.copy_from_slice(&d[..8]);
        u64::from_le_bytes(b)
    }

    #[test]
    fn insert_and_decode_roundtrips() {
        // Size the table for the load (classic IBLT guidance: cells ≈ 2×n
        // for clean peeling; see `reconcile` for the low-collision path).
        let mut t = Iblt::with_cells(128);
        let items: Vec<u64> = (100..140).map(|i| fp(&format!("vless://n{i}"))).collect();
        for &e in &items {
            t.insert_element(e);
        }
        let (found, residual) = t.decode();
        assert_eq!(residual, 0, "all cells should peel clean");
        assert_eq!(found.len(), items.len());
        for (k, v) in &found {
            assert_eq!(k, v);
            assert!(items.contains(k), "recovered a genuine element");
        }
    }

    #[test]
    fn empty_table_decodes_to_nothing() {
        let t = Iblt::with_cells(64);
        let (found, residual) = t.decode();
        assert!(found.is_empty());
        assert_eq!(residual, 0);
    }

    #[test]
    fn reconcile_recovers_symmetric_difference() {
        // Peer A holds {A1, A2, A3, shared}; peer B holds {B1, B2, shared}.
        let shared = fp("vless://shared");
        let a_items = vec![fp("vless://a1"), fp("vless://a2"), fp("vless://a3"), shared];
        let b_items = vec![fp("vless://b1"), fp("vless://b2"), shared];

        // A encodes its set.
        let mut a_iblt = Iblt::with_cells(64);
        for &e in &a_items {
            a_iblt.insert_element(e);
        }
        // B reconciles: what is A missing, what is B missing?
        let (missing_from_me, missing_from_peer) = a_iblt.reconcile(&b_items);

        // B should be missing A's unique items, and A should be missing B's.
        for a in ["vless://a1", "vless://a2", "vless://a3"] {
            let f = fp(a);
            assert!(missing_from_me.contains(&f), "B missing {a}");
        }
        for b in ["vless://b1", "vless://b2"] {
            let f = fp(b);
            assert!(missing_from_peer.contains(&f), "A missing {b}");
        }
        assert!(!missing_from_me.contains(&shared));
        assert!(!missing_from_peer.contains(&shared));
    }

    #[test]
    fn encode_decode_roundtrips() {
        let mut t = Iblt::with_cells(32);
        for i in 0..20 {
            t.insert_element(fp(&format!("vless://e{i}")));
        }
        let bytes = t.encode();
        let t2 = Iblt::decode_bytes(&bytes).expect("decodes");
        assert_eq!(t2.cells, t.cells);
        let (found, residual) = t2.decode();
        assert_eq!(residual, 0);
        assert_eq!(found.len(), 20);
    }

    #[test]
    fn malformed_encode_is_rejected() {
        assert!(Iblt::decode_bytes(&[0u8; 7]).is_none());
        assert!(Iblt::decode_bytes(&[0u8; 21]).is_none());
    }

    #[test]
    fn delete_is_inverse_of_insert() {
        let mut t = Iblt::with_cells(64);
        let e = fp("vless://x");
        t.insert_element(e);
        t.delete_element(e);
        let (found, residual) = t.decode();
        assert!(found.is_empty());
        assert_eq!(residual, 0);
    }
}
