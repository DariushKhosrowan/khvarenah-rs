//! Prioritized SNI candidates for the allowlist scanner.
//!
//! We probe SNIs that cover the realistic set of CDN/workers domains an
//! Iranian user would rely on. The list is ordered roughly by "most likely to
//! be allowed" first, so a partial scan still yields useful data.

/// Default candidate SNIs. Worker hostnames are synthesized from a profile
/// later; these are the stable, well-known CDN front domains.
pub const DEFAULT_CANDIDATES: &[&str] = &[
    "www.cloudflare.com",
    "cloudflare.com",
    "workers.dev",
    "api.cloudflare.com",
    "one.one.one.one",
    "speed.cloudflare.com",
    "dash.cloudflare.com",
    "cdnjs.cloudflare.com",
    "cloudflare-dns.com",
    "github.com",
    "www.google.com",
    "www.microsoft.com",
    "www.apple.com",
    "www.wikipedia.org",
    "www.cloudflare-dns.com",
];

/// Get the default candidate list as owned Strings.
pub fn default_candidates() -> Vec<String> {
    DEFAULT_CANDIDATES.iter().map(|s| s.to_string()).collect()
}

/// Merge a per-profile worker hostname (if known) into the candidate list,
/// de-duplicated, worker first (we care most about whether our own edge's SNI
/// passes).
pub fn candidates_with_worker(worker_host: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(w) = worker_host {
        if !w.is_empty() {
            out.push(w.to_string());
        }
    }
    for c in DEFAULT_CANDIDATES {
        let s = c.to_string();
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_candidates_non_empty() {
        assert!(!default_candidates().is_empty());
    }

    #[test]
    fn test_default_candidates_no_duplicates() {
        let c = default_candidates();
        let mut seen = std::collections::HashSet::new();
        for s in &c {
            assert!(seen.insert(s.clone()), "duplicate candidate: {s}");
        }
    }

    #[test]
    fn test_candidates_with_worker_prepends_worker_no_dup() {
        let c = candidates_with_worker(Some("edge-subdomain.workers.dev"));
        assert_eq!(c[0], "edge-subdomain.workers.dev");
        // worker not duplicated later in the defaults
        assert_eq!(
            c.iter()
                .filter(|s| s.as_str() == "edge-subdomain.workers.dev")
                .count(),
            1
        );
    }

    #[test]
    fn test_candidates_with_worker_none_returns_defaults() {
        let c = candidates_with_worker(None);
        assert_eq!(c, default_candidates());
    }
}
