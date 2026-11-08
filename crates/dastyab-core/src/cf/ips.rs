//! Cloudflare official IP range fetching + caching (DeepSeek Task 1).
//!
//! Everything in the native clean-IP path depends on having a live, correct
//! list of Cloudflare IP ranges. We fetch from Cloudflare's official API,
//! cache for 24 h, and never hardcode the ranges (a hardcoded list silently
//! rots). If a refresh fails we fall back to the cache; if the cache is
//! stale by more than 7 days we warn loudly; if there is no cache at all we
//! abort rather than scan a stale/unknown list.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};

use crate::error::CFError;
use crate::store;

/// Official JSON endpoint (structured, authoritative).
const OFFICIAL_API_URL: &str = "https://api.cloudflare.com/client/v4/ips";
/// Plain-text IPv4 fallback (used when the JSON endpoint shape surprises us).
const TEXT_FALLBACK_URL: &str = "https://www.cloudflare.com/ips-v4";
/// Cache freshness window: refuse to re-verify within this window.
pub const CACHE_TTL: Duration = Duration::from_secs(24 * 3600);
/// If the cache is older than this, we warn loudly that it may be stale.
pub const STALE_AFTER: Duration = Duration::from_secs(7 * 24 * 3600);
/// How many candidate IPs a default scan samples across the ranges.
pub const DEFAULT_SAMPLE: u32 = 2000;

/// A single IPv4 CIDR block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cidr {
    /// Network base address.
    pub base: Ipv4Addr,
    /// Prefix length (number of leading 1 bits), e.g. `13` for `/13`.
    pub mask: u8,
}

/// A cached copy of the range list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedRanges {
    /// UNIX epoch seconds when the list was fetched/cached.
    pub fetched_at: u64,
    /// Source URL the list came from.
    pub source: String,
    /// IPv4 CIDR blocks.
    pub ipv4: Vec<Cidr>,
}

impl CachedRanges {
    fn age(&self) -> Duration {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Duration::from_secs(now.saturating_sub(self.fetched_at))
    }
}

impl Cidr {
    /// Parse `"104.16.0.0/13"` → Cidr. Accepts a bare IP (mask 32).
    pub fn parse(s: &str) -> Result<Self, CFError> {
        let s = s.trim();
        let (ip_part, mask_part) = match s.find('/') {
            Some(i) => (&s[..i], &s[i + 1..]),
            None => (s, "32"),
        };
        let base: Ipv4Addr = ip_part.parse().map_err(|e| {
            CFError::new(
                "Invalid range",
                format!("Cannot parse IP '{ip_part}': {e}"),
                "Cloudflare's IP list should contain valid IPv4 addresses.",
            )
        })?;
        let mask: u8 = mask_part.parse().map_err(|e| {
            CFError::new(
                "Invalid range",
                format!("Cannot parse prefix '/{mask_part}': {e}"),
                "Cloudflare's IP list should contain valid CIDR prefix lengths.",
            )
        })?;
        if mask > 32 {
            return Err(CFError::new(
                "Invalid range",
                format!("Prefix /{mask} out of range for IPv4 (0–32)."),
                "Cloudflare's IP list should be valid IPv4 CIDR.",
            ));
        }
        // Normalise: zero out host bits so the base is the network address.
        let base_u32 = u32::from(base);
        let host_mask = if mask == 32 {
            0u32
        } else if mask == 0 {
            u32::MAX
        } else {
            u32::MAX >> mask
        };
        let base = Ipv4Addr::from(base_u32 & !host_mask);
        Ok(Cidr { base, mask })
    }

    /// Number of addresses in this block.
    pub fn addr_count(&self) -> u64 {
        1u64 << (32 - self.mask as u32)
    }

    /// True if `ip` falls inside this block.
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        if self.mask == 0 {
            return true;
        }
        let ip_u32 = u32::from(ip);
        let base_u32 = u32::from(self.base);
        let shift = 32 - self.mask;
        (ip_u32 >> shift) == (base_u32 >> shift)
    }

    /// Samples `n` random addresses within this block (dedup via HashSet).
    /// May return fewer than `n` for very small blocks.
    pub fn sample(&self, n: usize, rng: &mut impl Rng) -> Vec<Ipv4Addr> {
        let count = self.addr_count().max(1);
        let host_bits = (32 - self.mask as u32).min(31);
        let base_u32 = u32::from(self.base);
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let want = n.min(count as usize);
        let mut attempts = 0;
        while out.len() < want && attempts < want * 40 + 64 {
            attempts += 1;
            let offset = if host_bits == 0 {
                0u32
            } else {
                rng.gen_range(0u32..(1u32 << host_bits))
            };
            let ip = Ipv4Addr::from(base_u32 | offset);
            if seen.insert(ip) {
                out.push(ip);
            }
        }
        out
    }
}

/// The cache file lives under `~/.dastyab/` (a global, ready-machine file).
pub fn cache_path() -> PathBuf {
    store::mem_dir().join("cf-ips.json")
}

/// Read the cache from disk, if present and parseable.
pub fn read_cache() -> Option<CachedRanges> {
    store::read_opt::<CachedRanges>(&cache_path())
}

/// Atomically persist a cache.
pub fn write_cache(cache: &CachedRanges) -> Result<(), CFError> {
    store::atomic_write(&cache_path(), &serde_json::to_vec_pretty(cache).map_err(|e| {
        CFError::new("Storage error", format!("Cannot serialize ranges: {e}"), "Internal error.")
    })?)
}

/// Parse the JSON API response body into IPv4 CIDR list.
fn parse_api_json(body: &str) -> Result<Vec<Cidr>, CFError> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|e| {
        CFError::new("Parse error", format!("Invalid CF IP JSON: {e}"), "CF API shape changed?")
    })?;
    let list = v
        .get("result")
        .and_then(|r| r.get("ipv4_cidrs"))
        .and_then(|r| r.as_array())
        .ok_or_else(|| {
            CFError::new("Parse error", "No ipv4_cidrs in CF response.", "CF API shape changed?")
        })?;
    let mut out = Vec::new();
    for item in list {
        if let Some(s) = item.as_str() {
            if let Ok(c) = Cidr::parse(s) {
                out.push(c);
            }
        }
    }
    if out.is_empty() {
        return Err(CFError::new(
            "Parse error",
            "Parsed zero IPv4 ranges from CF API.",
            "CF API shape changed?",
        ));
    }
    Ok(out)
}

/// Parse the plain-text fallback body into IPv4 CIDR list.
fn parse_text(body: &str) -> Vec<Cidr> {
    body.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| Cidr::parse(l).ok())
        .collect()
}

/// Fetch fresh ranges from Cloudflare, trying JSON then text fallback.
async fn fetch_fresh() -> Result<(Vec<Cidr>, String), CFError> {
    // 1) structured JSON API
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent("dastyab")
        .build()
        .map_err(|e| CFError::new("Network error", format!("{e}"), "Internal error."))?;
    match client.get(OFFICIAL_API_URL).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(text) = resp.text().await {
                match parse_api_json(&text) {
                    Ok(list) => return Ok((list, OFFICIAL_API_URL.to_string())),
                    Err(_) => { /* fall through to text fallback */ }
                }
            }
        }
        _ => { /* fall through */ }
    }
    // 2) plain-text fallback
    match client.get(TEXT_FALLBACK_URL).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(text) = resp.text().await {
                let list = parse_text(&text);
                if !list.is_empty() {
                    return Ok((list, TEXT_FALLBACK_URL.to_string()));
                }
            }
        }
        _ => {}
    }
    Err(CFError::new(
        "Network error",
        "Could not fetch Cloudflare IP ranges from either official endpoint.",
        "Check your network connection, then retry.",
    ))
}

/// Load the current best set of ranges.
///
/// Order of preference:
/// 1. A fresh cache (< 24 h old).
/// 2. A live fetch (refreshes the cache).
/// 3. A stale-but-present cache (warn loudly "CF range list may be stale").
/// 4. Nothing → hard error (never scan an empty list).
pub async fn load_ranges(force_refresh: bool) -> Result<Vec<Cidr>, CFError> {
    let cached = read_cache();
    if !force_refresh {
        if let Some(c) = &cached {
            if c.age() < CACHE_TTL {
                return Ok(c.ipv4.clone());
            }
        }
    }

    match fetch_fresh().await {
        Ok((list, source)) => {
            let cache = CachedRanges {
                fetched_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                source,
                ipv4: list.clone(),
            };
            let _ = write_cache(&cache);
            Ok(list)
        }
        Err(e) => {
            // Network died. Fall back to stale cache if we have one.
            if let Some(c) = &cached {
                if c.age() < STALE_AFTER {
                    tracing::warn!(
                        "Cloudflare range list may be stale (cache {} old) — proceeding anyway.",
                        humantime(c.age())
                    );
                    return Ok(c.ipv4.clone());
                }
            }
            Err(e)
        }
    }
}

/// Humane duration for warnings.
fn humantime(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

/// Provide a bounded sample of candidate IPs across all ranges.
/// Returns up to `count` unique addresses (uniformly across blocks).
pub fn sample_candidates(cidrs: &[Cidr], count: u32) -> Vec<Ipv4Addr> {
    if cidrs.is_empty() {
        return Vec::new();
    }
    let count = count.max(64);
    let mut rng = rand::rngs::StdRng::from_entropy();
    let per_block = (count as usize / cidrs.len()).max(1);
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for cidr in cidrs {
        let mut added = 0;
        while added < per_block {
            let ips = cidr.sample(per_block - added, &mut rng);
            if ips.is_empty() {
                break;
            }
            let mut found = false;
            for ip in ips {
                if seen.insert(ip) {
                    out.push(ip);
                    added += 1;
                    found = true;
                }
            }
            if !found {
                break; // block exhausted
            }
        }
        if out.len() >= count as usize {
            break;
        }
    }
    out.truncate(count as usize);
    out
}

/// Pretty-print the current range summary (used by CLI `ranges` diagnostic).
pub fn summarize(cidrs: &[Cidr]) -> String {
    let total: u64 = cidrs.iter().map(|c| c.addr_count()).sum();
    format!(
        "{} IPv4 block(s), ~{} addresses (source: {})",
        cidrs.len(),
        total,
        read_cache().map(|c| c.source).unwrap_or_else(|| "not cached".into())
    )
}

/// Enumerate up to `limit` sibling addresses in the same `/prefix_len` block as
/// `ip` (network and broadcast addresses excluded). Returns an empty vec for an
/// invalid IP or an out-of-range prefix. This is the clustering primitive: CF
/// anycast groups clean endpoints tightly, so a working /24 has working
/// siblings — expand around a known-good seed rather than sample the whole RFC.
pub fn neighbors_of(ip: &str, prefix_len: u8, limit: usize) -> Vec<String> {
    if prefix_len > 30 || limit == 0 {
        return Vec::new();
    }
    let addr: Ipv4Addr = match ip.trim().parse() {
        Ok(a) => a,
        Err(_) => return Vec::new(),
    };
    let base_u32 = u32::from(addr) & (u32::MAX << (32 - prefix_len as u32));
    let host_count = 1u32 << (32 - prefix_len as u32);
    if host_count <= 2 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for i in 0..host_count {
        if out.len() >= limit {
            break;
        }
        let candidate = base_u32 | i;
        // exclude network (i == 0) and broadcast (i == host_count-1)
        if i == 0 || i == host_count - 1 {
            continue;
        }
        out.push(Ipv4Addr::from(candidate).to_string());
    }
    out
}

/// Build a candidate list: seeds first, then their `/prefix_len` neighbors,
/// deduplicated, padded with a uniform sample until `n` entries. Seeds and
/// their neighborhoods come before the uniform sample so the scanner tries the
/// most promising addresses first.
pub fn seeded_candidates(
    seeds: &[String],
    ranges: &[Cidr],
    n: usize,
    prefix_len: u8,
) -> Vec<String> {
    let n = n.max(1);
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let mut add = |ip: &str, out: &mut Vec<String>| {
        if seen.insert(ip.to_string()) {
            out.push(ip.to_string());
        }
    };

    // 1) seeds that still fall inside the current ranges (from a retired range
    //    is garbage — drop it and let uniform sampling take over).
    let live: Vec<&str> = seeds
        .iter()
        .map(|s| s.as_str())
        .filter(|s| {
            s.parse::<Ipv4Addr>()
                .map(|ip| ranges.iter().any(|c| c.contains(ip)))
                .unwrap_or(false)
        })
        .collect();
    for s in live.iter() {
        add(s, &mut out);
    }

    // 2) neighbors of every live seed.
    for s in live.iter() {
        for nb in neighbors_of(s, prefix_len, 254) {
            add(&nb, &mut out);
            if out.len() >= n {
                return out;
            }
        }
    }

    // 3) pad with the uniform sample when under budget.
    if out.len() < n {
        let sample = sample_candidates(ranges, (n - out.len()) as u32);
        for ip in sample {
            add(&ip.to_string(), &mut out);
            if out.len() >= n {
                break;
            }
        }
    }

    out.truncate(n);
    out
}

/// Weighted random sampling over CIDR blocks, proportional to each block's
/// address count (SlipNet `generateFromRanges`-style cumulative distribution).
/// Returns `n` unique IPv4 strings. This beats uniform-per-block sampling when
/// blocks vary wildly in size (e.g. a /13 vs a /24).
pub fn weighted_sample_by_cidr(cidrs: &[Cidr], n: usize, rng: &mut impl Rng) -> Vec<String> {
    if cidrs.is_empty() || n == 0 {
        return Vec::new();
    }
    // Build cumulative size distribution over the address space.
    let mut cumulative: Vec<u64> = Vec::with_capacity(cidrs.len());
    let mut running: u64 = 0;
    for c in cidrs {
        running = running.saturating_add(c.addr_count());
        cumulative.push(running);
    }
    let total = running;
    if total == 0 {
        return Vec::new();
    }
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let mut attempts = 0usize;
    let max_attempts = n * 40 + 1024;
    while out.len() < n && attempts < max_attempts {
        attempts += 1;
        // Pick a random position in the flattened space.
        let pos = rng.gen_range(0u64..total);
        // Binary-search the owning block.
        let mut lo = 0usize;
        let mut hi = cidrs.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            if cumulative[mid] <= pos {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        let idx = lo.min(cidrs.len() - 1);
        let base = if idx == 0 { 0 } else { cumulative[idx - 1] };
        let offset = pos - base;
        let host_bits = (32 - cidrs[idx].mask as u32).min(31);
        let ip = if host_bits == 0 {
            cidrs[idx].base
        } else {
            let base_u32 = u32::from(cidrs[idx].base);
            let o = (offset & ((1u64 << host_bits) - 1)) as u32;
            Ipv4Addr::from(base_u32 | o)
        };
        if seen.insert(ip) {
            out.push(ip.to_string());
        }
    }
    out
}

/// Expand /prefix_len neighbourhoods around known-good clean endpoints.
/// Returns sibling IPs (network/broadcast excluded), best seeds first.
pub fn expand_around(clean: &[crate::autopilot::CleanEndpoint], prefix_len: u8, per_seed: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for ep in clean {
        for nb in neighbors_of(&ep.ip, prefix_len, per_seed.max(1)) {
            if seen.insert(nb.clone()) {
                out.push(nb);
            }
        }
    }
    out
}

/// Read prior successful endpoints from the autopilot ledger for a profile.
/// Returns the last `max` verified endpoints from the past 7 days, as
/// "ip:port" strings (the seeds for [`seeded_candidates`]).
pub fn load_seed_endpoints(profile_id: &str, max: usize) -> Vec<String> {
    let ledger = crate::store::profiles::profile_dir(profile_id)
        .join("autopilot")
        .join("endpoints.json");
    let Ok(text) = std::fs::read_to_string(&ledger) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Vec::new();
    };
    let Some(arr) = value.as_array() else {
        return Vec::new();
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let seven_days = 7 * 24 * 3600i64;
    let mut out = Vec::new();
    for entry in arr {
        let verified = entry
            .get("verified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !verified {
            continue;
        }
        // Only trust seeds added recently.
        let ts = entry.get("ts").and_then(|v| v.as_str()).unwrap_or("");
        let age = if !ts.is_empty() {
            // ts is ISO-8601; approximate by using last_checked when present,
            // else fall back to accepting it.
            match entry.get("last_checked").and_then(|v| v.as_str()) {
                Some(lc) if !lc.is_empty() => {
                    // parse "YYYY-MM-DDTHH:MM:SS..." via chrono if available
                    match chrono::DateTime::parse_from_rfc3339(lc) {
                        Ok(dt) => now.saturating_sub(dt.timestamp()),
                        Err(_) => 0,
                    }
                }
                _ => {
                    // no timestamp — accept only if the record has a recent-ish
                    // ts (best-effort: skip stale format entirely)
                    if ts.len() >= 10 {
                        0
                    } else {
                        seven_days + 1
                    }
                }
            }
        } else {
            seven_days + 1
        };
        if age <= seven_days {
            let ip = entry.get("ip").and_then(|v| v.as_str()).unwrap_or("");
            let port = entry
                .get("port")
                .and_then(|v| v.as_u64())
                .unwrap_or(443);
            if !ip.is_empty() {
                out.push(format!("{ip}:{port}"));
            }
        }
        if out.len() >= max {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn parse_simple_cidr() {
        let c = Cidr::parse("104.16.0.0/13").unwrap();
        assert_eq!(c.base, Ipv4Addr::new(104, 16, 0, 0));
        assert_eq!(c.mask, 13);
        assert_eq!(c.addr_count(), 1 << 19);
    }

    #[test]
    fn parse_bare_ip_defaults_to_32() {
        let c = Cidr::parse("1.2.3.4").unwrap();
        assert_eq!(c.mask, 32);
        assert_eq!(c.addr_count(), 1);
    }

    #[test]
    fn parse_rejects_bad_prefix() {
        assert!(Cidr::parse("104.16.0.0/33").is_err());
        assert!(Cidr::parse("not-an-ip/13").is_err());
    }

    #[test]
    fn contains_works() {
        let c = Cidr::parse("104.16.0.0/13").unwrap();
        assert!(c.contains(Ipv4Addr::new(104, 16, 1, 1)));
        assert!(c.contains(Ipv4Addr::new(104, 23, 255, 255)));
        assert!(!c.contains(Ipv4Addr::new(104, 24, 0, 0)));
    }

    #[test]
    fn sample_returns_distinct_in_block() {
        let c = Cidr::parse("104.16.0.0/13").unwrap();
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let ips = c.sample(200, &mut rng);
        assert_eq!(ips.len(), 200);
        let uniq: std::collections::HashSet<_> = ips.iter().collect();
        assert_eq!(uniq.len(), 200);
        for ip in &ips {
            assert!(c.contains(*ip));
        }
    }

    #[test]
    fn parse_api_json_extracts_ipv4() {
        let body = r#"{"success":true,"result":{"ipv4_cidrs":["104.16.0.0/13","172.64.0.0/13"],"ipv6_cidrs":[]}}"#;
        let list = parse_api_json(body).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].mask, 13);
    }

    #[test]
    fn sample_candidates_across_blocks() {
        let cidrs = vec![
            Cidr::parse("104.16.0.0/13").unwrap(),
            Cidr::parse("172.64.0.0/13").unwrap(),
        ];
        let ips = sample_candidates(&cidrs, 100);
        assert!(!ips.is_empty());
        assert!(ips.len() <= 100);
    }

    #[test]
    fn neighbors_of_254_siblings_for_slash_24() {
        let nbs = neighbors_of("104.16.1.1", 24, 254);
        assert_eq!(nbs.len(), 254);
        assert!(nbs.contains(&"104.16.1.1".to_string()));
    }

    #[test]
    fn neighbors_of_excludes_network_and_broadcast() {
        let nbs = neighbors_of("104.16.1.0", 24, 1000);
        assert!(!nbs.contains(&"104.16.1.0".to_string()));
        // /24 has 256 addresses; network .0 and broadcast .255 excluded -> 254
        assert_eq!(nbs.len(), 254);
    }

    #[test]
    fn neighbors_of_respects_limit() {
        let nbs = neighbors_of("104.16.1.1", 24, 10);
        assert_eq!(nbs.len(), 10);
    }

    #[test]
    fn neighbors_of_invalid_ip_returns_empty() {
        assert!(neighbors_of("not-an-ip", 24, 10).is_empty());
        assert!(neighbors_of("104.16.1.1", 31, 10).is_empty());
    }

    #[test]
    fn seeded_candidates_seeds_first() {
        let cidrs = vec![Cidr::parse("104.16.0.0/13").unwrap()];
        let seeds = vec!["104.16.1.1".to_string(), "104.16.2.2".to_string()];
        let out = seeded_candidates(&seeds, &cidrs, 20, 24);
        assert_eq!(out[0], "104.16.1.1");
        assert_eq!(out[1], "104.16.2.2");
    }

    #[test]
    fn seeded_candidates_deduplicates_overlap() {
        let cidrs = vec![Cidr::parse("104.16.0.0/13").unwrap()];
        let seeds = vec!["104.16.1.1".to_string(), "104.16.1.1".to_string()];
        let out = seeded_candidates(&seeds, &cidrs, 20, 24);
        let uniq: std::collections::HashSet<_> = out.iter().collect();
        assert_eq!(uniq.len(), out.len());
    }

    #[test]
    fn seeded_candidates_pads_with_uniform_when_under_budget() {
        let cidrs = vec![Cidr::parse("104.16.0.0/13").unwrap()];
        let seeds: Vec<String> = vec![];
        let out = seeded_candidates(&seeds, &cidrs, 500, 24);
        assert_eq!(out.len(), 500);
    }

    #[test]
    fn seeded_candidates_drops_retired_range_seeds() {
        // seed lies outside the only range -> should be excluded entirely
        let cidrs = vec![Cidr::parse("104.16.0.0/13").unwrap()];
        let seeds = vec!["8.8.8.8".to_string()];
        let out = seeded_candidates(&seeds, &cidrs, 200, 24);
        assert!(!out.contains(&"8.8.8.8".to_string()));
    }

    #[test]
    fn weighted_sample_by_cidr_proportional_to_block_size() {
        // Two blocks: a /24 (256 addrs) and a /30 (4 addrs) => the /24
        // should dominate the sample (~99% of draws land in it). Request far
        // fewer than the total unique count so we never run out of room.
        let cidrs = vec![
            Cidr::parse("10.0.0.0/24").unwrap(),
            Cidr::parse("10.0.1.0/30").unwrap(),
        ];
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let out = weighted_sample_by_cidr(&cidrs, 200, &mut rng);
        assert_eq!(out.len(), 200);
        let in_big = out.iter().filter(|ip| ip.starts_with("10.0.0.")).count();
        // /24 is 256/(256+4) ≈ 98.5% of the space => expect near-200.
        assert!(in_big > 190, "got only {in_big}/200 in the /24 block");
    }

    #[test]
    fn weighted_sample_by_cidr_produces_unique_ips() {
        let cidrs = vec![Cidr::parse("104.16.0.0/13").unwrap()];
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let out = weighted_sample_by_cidr(&cidrs, 500, &mut rng);
        assert_eq!(out.len(), 500);
        let uniq: std::collections::HashSet<_> = out.iter().collect();
        assert_eq!(uniq.len(), 500);
    }

    #[test]
    fn weighted_sample_by_cidr_empty_input_returns_empty() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        assert!(weighted_sample_by_cidr(&[], 10, &mut rng).is_empty());
    }
}
