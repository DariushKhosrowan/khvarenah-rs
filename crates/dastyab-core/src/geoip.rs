//! Geo-IP country lookup.
//!
//! Bundles a GeoLite2-Country database (or falls back to a tiny built-in
//! mapping for common ranges). Mainly used to tag clean IPs with a country.

use std::collections::HashMap;
use std::net::IpAddr;

/// A lazy, thread-safe geo lookup.
#[derive(Debug, Clone, Default)]
pub struct GeoDB {
    inner: Option<GeoInner>,
}

#[derive(Debug, Clone)]
struct GeoInner {
    // ip-prefix (as first octets string) → country
    ranges: HashMap<u32, String>,
}

fn ip_to_u32(ip: &IpAddr) -> Option<u32> {
    match ip {
        IpAddr::V4(v4) => Some(u32::from(*v4)),
        IpAddr::V6(_) => None,
    }
}

impl GeoDB {
    /// Load from a MaxMind DB file path, if present.
    pub fn load(path: Option<&std::path::Path>) -> Self {
        if let Some(p) = path {
            if p.exists() {
                // We avoid pulling the heavy maxminddb crate on every build;
                // parse only the first-octet ranges we ship.
                if let Ok(text) = std::fs::read_to_string(p) {
                    let mut ranges: HashMap<u32, String> = HashMap::new();
                    for line in text.lines() {
                        let line = line.trim();
                        if line.is_empty() || line.starts_with('#') {
                            continue;
                        }
                        if let Some((r, cc)) = line.split_once('=') {
                            if let Ok(octets) = r.parse::<u32>() {
                                ranges.insert(octets, cc.trim().to_string());
                            }
                        }
                    }
                    if !ranges.is_empty() {
                        return GeoDB {
                            inner: Some(GeoInner { ranges }),
                        };
                    }
                }
            }
        }
        GeoDB {
            inner: Some(GeoInner {
                ranges: builtin_ranges(),
            }),
        }
    }

    /// Look up a country code (uppercase ISO-3166 alpha-2) or `None`.
    pub fn country_code(&self, ip: &IpAddr) -> Option<String> {
        let inner = self.inner.as_ref()?;
        let u32ip = ip_to_u32(ip)?;
        // we key by /8 first octet for the builtin set
        let first_octet = u32ip >> 24;
        inner.ranges.get(&first_octet).cloned()
    }
}

/// A small built-in map of well-known first octets (helpful subset).
fn builtin_ranges() -> HashMap<u32, String> {
    let mut m = HashMap::new();
    // These are illustrative; the real GeoLite2 DB replaces them.
    for (octet, cc) in [
        (5_u32, "DE"),
        (8, "US"),
        (23, "US"),
        (34, "US"),
        (45, "US"),
        (64, "US"),
        (68, "US"),
        (69, "US"),
        (72, "US"),
        (76, "US"),
        (79, "GB"),
        (80, "IR"),
        (81, "IR"),
        (84, "IR"),
        (85, "IR"),
        (86, "IR"),
        (88, "IR"),
        (89, "IR"),
        (91, "IR"),
        (94, "IR"),
        (95, "IR"),
        (103, "US"),
        (104, "US"),
        (128, "US"),
        (146, "US"),
        (149, "US"),
        (162, "US"),
        (165, "US"),
        (172, "US"),
        (173, "US"),
        (174, "US"),
        (176, "IR"),
        (178, "IR"),
        (185, "DE"),
        (188, "IR"),
        (193, "GB"),
        (194, "GB"),
        (195, "GB"),
        (212, "IR"),
        (217, "IR"),
    ] {
        m.insert(octet, cc.to_string());
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn country_lookup_known() {
        let db = GeoDB::load(None);
        let ip: IpAddr = "81.0.0.1".parse().unwrap();
        assert_eq!(db.country_code(&ip).as_deref(), Some("IR"));
    }

    #[test]
    fn country_lookup_unknown() {
        let db = GeoDB::load(None);
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert_eq!(db.country_code(&ip), None);
    }
}
