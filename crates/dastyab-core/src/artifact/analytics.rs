//! Usage analytics aggregation for DastYab.
//!
//! Cloudflare's per-script analytics endpoint returns a JSON envelope whose
//! shape varies slightly by API version. This module normalizes that into a
//! typed, human-readable [`UsageSummary`] that the CLI, TUI and GUI all share.

use serde::{Deserialize, Serialize};

/// Request / traffic usage of a single script.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScriptUsage {
    pub name: String,
    pub requests: u64,
    pub bytes: u64,
}

/// Aggregated usage across a set of scripts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UsageSummary {
    pub scripts: Vec<ScriptUsage>,
    pub total_requests: u64,
    pub total_bytes: u64,
}

impl UsageSummary {
    /// Build a summary from the raw `result` value of a script-analytics call.
    pub fn from_script_result(name: &str, raw: &serde_json::Value) -> Self {
        let mut s = UsageSummary::default();
        s.push_result(name, raw);
        s
    }

    /// Fold one raw script-analytics result into this summary.
    pub fn push_result(&mut self, name: &str, raw: &serde_json::Value) {
        // The result envelope may nest under "result" or be a summary dict.
        let req = extract_u64(raw, &["requestCount", "requests", "count"]);
        let bytes = extract_u64(raw, &["respBytes", "bytes", "traffic"]);

        self.scripts.push(ScriptUsage {
            name: name.to_string(),
            requests: req,
            bytes,
        });
        self.total_requests += req;
        self.total_bytes += bytes;
    }

    /// Compact single-line summary (no per-script detail).
    pub fn summary_line(&self) -> String {
        format!(
            "{} script(s), {} requests, {} in the last 24h",
            self.scripts.len(),
            self.total_requests,
            human_bytes(self.total_bytes)
        )
    }

    /// Pretty multi-line report.
    pub fn report(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("Usage summary — {}\n", self.summary_line()));
        for s in &self.scripts {
            out.push_str(&format!(
                "  • {:<28} {:>12} requests  {}\n",
                s.name,
                s.requests,
                human_bytes(s.bytes)
            ));
        }
        out
    }
}

/// Extract the first present numeric field from a nested JSON value.
fn extract_u64(value: &serde_json::Value, keys: &[&str]) -> u64 {
    for k in keys {
        if let Some(v) = value.get(*k) {
            if let Some(n) = v.as_u64() {
                return n;
            }
            if let Some(n) = v.as_f64() {
                return n.max(0.0) as u64;
            }
            if let Some(s) = v.as_str() {
                if let Ok(n) = s.parse::<u64>() {
                    return n;
                }
            }
        }
    }
    // Recurse into a single "result" object if present.
    if value.get("result").and_then(|r| r.as_object()).is_some() {
        if let Some(r) = value.get("result") {
            return extract_u64(r, keys);
        }
    }
    0
}

/// Human-friendly byte formatting (e.g. 12.3 MB).
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if bytes == 0 {
        return "0 B".to_string();
    }
    let mut n = bytes as f64;
    let mut u = 0;
    while n >= 1024.0 && u < UNITS.len() - 1 {
        n /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{bytes} B")
    } else {
        format!("{n:.1} {}", UNITS[u])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_bytes_formats() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert!(human_bytes(2048).ends_with("KB"));
        assert!(human_bytes(1024 * 1024).ends_with("MB"));
    }

    #[test]
    fn extract_number_variants() {
        let v = serde_json::json!({ "requestCount": 1234 });
        assert_eq!(extract_u64(&v, &["requestCount", "requests"]), 1234);
        let v2 = serde_json::json!({ "requests": "567" });
        assert_eq!(extract_u64(&v2, &["requestCount", "requests"]), 567);
        let v3 = serde_json::json!({ "result": { "requests": 42 } });
        assert_eq!(extract_u64(&v3, &["requestCount", "requests"]), 42);
    }

    #[test]
    fn summary_aggregates() {
        let mut s = UsageSummary::default();
        s.push_result(
            "a",
            &serde_json::json!({ "requestCount": 10, "respBytes": 1000 }),
        );
        s.push_result(
            "b",
            &serde_json::json!({ "requestCount": 20, "respBytes": 2000 }),
        );
        assert_eq!(s.total_requests, 30);
        assert_eq!(s.total_bytes, 3000);
        assert_eq!(s.scripts.len(), 2);
        assert!(s.report().contains("30"));
    }
}
