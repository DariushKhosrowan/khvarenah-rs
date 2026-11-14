//! Network diagnostics for endpoints: latency and throughput probing.
//!
//! This builds on [`crate::probe::health`] to give the user a battery of checks over
//! a set of candidate endpoints — the kind of "is this IP actually good"
//! analysis that turns a guess into a decision.

use serde::{Deserialize, Serialize};

use crate::error::CFError;
use crate::probe::health::{check, HealthOptions, HealthResult};

/// A single measured endpoint result plus its label.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointResult {
    pub endpoint: String,
    pub result: HealthResult,
}

/// A full diagnostics run over many endpoints.
#[derive(Debug, Clone, Default)]
pub struct DiagReport {
    pub results: Vec<EndpointResult>,
    pub best: Option<EndpointResult>,
    pub total_ms: u64,
}

impl DiagReport {
    /// Sort results by latency (best first).
    pub fn ranked(&self) -> Vec<&EndpointResult> {
        let mut r: Vec<&EndpointResult> = self.results.iter().collect();
        r.sort_by(|a, b| {
            a.result
                .connect_ms
                .partial_cmp(&b.result.connect_ms)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        r
    }

    /// Render a human-readable table.
    pub fn render(&self) -> String {
        let mut out = format!(
            "Diagnostics over {} endpoint(s) in {}ms\n",
            self.results.len(),
            self.total_ms
        );
        for e in self.ranked() {
            let ok = if e.result.ok { "✓" } else { "✗" };
            let err = e.result.error.clone().unwrap_or_default();
            out.push_str(&format!(
                "  {ok} {:<22} tcp {:>6.1}ms connect {:>6.1}ms dl {:>7.1}kbps {err}\n",
                e.endpoint, e.result.tcp_ms, e.result.connect_ms, e.result.download_kbps
            ));
        }
        out
    }
}

/// Run diagnostics on a list of `ip:port` endpoints (or hostnames).
pub async fn run_diagnostics(
    endpoints: &[String],
    opts: &HealthOptions,
) -> Result<DiagReport, CFError> {
    if endpoints.is_empty() {
        return Err(CFError::new(
            "No endpoints",
            "Nothing to diagnose.",
            "Provide at least one ip:port (or hostname:port).",
        ));
    }

    let started = std::time::Instant::now();
    let mut report = DiagReport::default();
    let mut best: Option<EndpointResult> = None;

    for ep in endpoints {
        let (ip, port) = split_endpoint(ep);
        let h = check(&ip, port, opts).await;
        let er = EndpointResult {
            endpoint: ep.clone(),
            result: h,
        };
        if er.result.ok {
            let is_best = match &best {
                Some(b) => er.result.connect_ms < b.result.connect_ms,
                None => true,
            };
            if is_best {
                best = Some(er.clone());
            }
        }
        report.results.push(er);
    }

    report.total_ms = started.elapsed().as_millis() as u64;
    report.best = best;
    Ok(report)
}

/// Split `ip:port` (or `host:port`) into its parts; default port 443.
pub fn split_endpoint(ep: &str) -> (String, u16) {
    match ep.rsplit_once(':') {
        Some((ip, port)) => match port.parse::<u16>() {
            Ok(p) => (ip.to_string(), p),
            Err(_) => (ep.to_string(), 443),
        },
        None => (ep.to_string(), 443),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_endpoint_handles_forms() {
        assert_eq!(split_endpoint("1.2.3.4:443"), ("1.2.3.4".to_string(), 443));
        assert_eq!(
            split_endpoint("1.2.3.4:8443"),
            ("1.2.3.4".to_string(), 8443)
        );
        assert_eq!(
            split_endpoint("host.example"),
            ("host.example".to_string(), 443)
        );
        assert_eq!(split_endpoint("host:bad"), ("host:bad".to_string(), 443));
    }

    #[test]
    fn diag_report_ranked_orders_by_latency() {
        let mut report = DiagReport::default();
        let mut r1 = HealthResult {
            ip: "a".into(),
            port: 443,
            ok: true,
            tcp_ms: 50.0,
            connect_ms: 100.0,
            download_kbps: 100.0,
            error: None,
        };
        let mut r2 = HealthResult {
            ip: "b".into(),
            port: 443,
            ok: true,
            tcp_ms: 10.0,
            connect_ms: 20.0,
            download_kbps: 1000.0,
            error: None,
        };
        report.results.push(EndpointResult {
            endpoint: "a:443".into(),
            result: r1.clone(),
        });
        report.results.push(EndpointResult {
            endpoint: "b:443".into(),
            result: r2.clone(),
        });
        let ranked = report.ranked();
        assert_eq!(ranked[0].endpoint, "b:443");
        report.best = Some(EndpointResult {
            endpoint: "b:443".into(),
            result: r2.clone(),
        });
        assert!(report.render().contains("b:443"));
        r1.ok = false;
        r2.ok = false;
    }
}
