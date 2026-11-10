//! Client-side resolver for the Cloudflare-Worker-hosted DNS tunnel.
//!
//! `WorkerTunnelResolver` implements [`crate::dnstunnel::Resolver`] by doing an
//! HTTPS GET to the deployed worker with the encoded qname as a query param and
//! the shared secret in the `X-DastYab-Session` header. The worker replies
//! with the *encoded reply qname* as `text/plain`; that string is returned
//! verbatim so [`crate::dnstunnel::send_receive`] decodes it with the existing
//! `TunnelFrame::decode_name` path — zero protocol changes.
//!
//! The trait is synchronous, so we use a blocking HTTP client (the repo's
//! `reqwest` with the `blocking` feature). Control-plane tunnel traffic is rare
//! and low-rate, so a blocking call is acceptable. Crucially, the blocking
//! client spawns an internal tokio runtime, which cannot be created or dropped
//! while *inside* another tokio async context (tests, `probe_tunnel`, the
//! daemon cycle). We therefore run each query on a dedicated OS thread, where
//! the blocking client is built and dropped in a clean non-async context.

use crate::dnstunnel::Resolver;
use crate::error::CFError;

/// Timeout for the blocking HTTP call.
const HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// Resolver that talks to a deployed worker-hosted tunnel server over HTTPS.
pub struct WorkerTunnelResolver {
    worker_url: String,
    shared_secret: String,
    timeout: std::time::Duration,
}

impl WorkerTunnelResolver {
    /// Build a resolver for a deployed worker tunnel (default 20s timeout).
    pub fn new(worker_url: impl Into<String>, shared_secret: impl Into<String>) -> Self {
        Self::with_timeout(worker_url, shared_secret, HTTP_TIMEOUT)
    }

    /// Build a resolver with a custom HTTP timeout (used by the liveness probe).
    pub fn with_timeout(
        worker_url: impl Into<String>,
        shared_secret: impl Into<String>,
        timeout: std::time::Duration,
    ) -> Self {
        Self {
            worker_url: worker_url.into(),
            shared_secret: shared_secret.into(),
            timeout,
        }
    }

    /// The URL of the deployed worker.
    pub fn worker_url(&self) -> &str {
        &self.worker_url
    }

    fn query_txt_blocking(&self, name: &str) -> Result<String, CFError> {
        let url = format!("{}?q={}", self.worker_url.trim_end_matches('/'), name);
        let secret = self.shared_secret.clone();
        let timeout = self.timeout;

        // Run the blocking reqwest client on a dedicated thread so its internal
        // tokio runtime is created and dropped outside any async context.
        std::thread::scope(|scope| {
            let handle = scope.spawn(move || {
                let client = reqwest::blocking::Client::builder()
                    .timeout(timeout)
                    .user_agent("dastyab-worker-tunnel")
                    .build()
                    .map_err(|e| CFError::new("worker-tunnel", format!("client: {e}"), ""))?;

                let resp = client
                    .get(&url)
                    .header("X-DastYab-Session", &secret)
                    .send()
                    .map_err(|e| CFError::new("worker-tunnel", format!("request: {e}"), ""))?;

                let status = resp.status();
                if status.as_u16() == 401 {
                    let mut err = CFError::new(
                        "worker-tunnel",
                        "session secret rejected by worker (401)",
                        "Re-deploy the tunnel to refresh the shared secret.",
                    );
                    err.status = Some(401);
                    return Err(err);
                }
                if !status.is_success() {
                    return Err(CFError::new(
                        "worker-tunnel",
                        format!("worker returned HTTP {}", status.as_u16()),
                        "",
                    ));
                }
                resp.text()
                    .map_err(|e| CFError::new("worker-tunnel", format!("body: {e}"), ""))
            });

            handle
                .join()
                .unwrap_or_else(|_| Err(CFError::new("worker-tunnel", "query thread panicked", "")))
        })
    }
}

impl Resolver for WorkerTunnelResolver {
    fn query_txt(&self, name: &str) -> Result<String, CFError> {
        self.query_txt_blocking(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnstunnel::TunnelFrame;
    use crate::worker_tunnel::DYB_TUNNEL_BASE;

    /// Spawn a one-shot HTTP server that returns `body` with `status`, and
    /// captures the request line + headers into a shared log file so tests can
    /// assert the qname param and session header were sent.
    fn mock_worker(status: u16, body: String) -> (String, std::path::PathBuf) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // Per-server unique log path so parallel tests never clobber each
        // other's captured request (the old shared /tmp/ file was a race).
        let log_path = std::env::temp_dir().join(format!(
            "kv_resolver_log_{}_{}.txt",
            std::process::id(),
            addr.port()
        ));
        let log_path_clone = log_path.clone();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                use std::io::{Read, Write};
                let mut buf = [0u8; 8192];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let _ = std::fs::write(&log_path_clone, req);
                let reason = if status == 200 { "OK" } else { "Error" };
                let resp = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });
        (format!("http://{addr}"), log_path)
    }

    fn ping_qname() -> String {
        let f = TunnelFrame {
            session: "sess".into(),
            seq: 1,
            flags: 1,
            payload: b"alive".to_vec(),
        };
        f.encode_name(DYB_TUNNEL_BASE, 0x1234)
    }

    fn pong_reply() -> String {
        // Reply frame the worker would return: flags=0x81, payload "pong".
        let f = TunnelFrame {
            session: "sess".into(),
            seq: 1,
            flags: 0x81,
            payload: b"pong".to_vec(),
        };
        f.encode_name(DYB_TUNNEL_BASE, 0x1234)
    }

    #[test]
    fn test_resolver_sends_qname_as_query_param() {
        let (server, log_path) = mock_worker(200, pong_reply());
        let r = WorkerTunnelResolver::new(server, "secret");
        let replied = r.query_txt(&ping_qname()).unwrap();
        assert!(replied.ends_with(&format!(".{DYB_TUNNEL_BASE}")));
        let req = std::fs::read_to_string(&log_path).unwrap();
        assert!(
            req.contains("?q="),
            "qname must be sent as query param: {req}"
        );
        assert!(req.contains("HTTP/1.1"));
    }

    #[test]
    fn test_resolver_sends_session_header() {
        let (server, log_path) = mock_worker(200, pong_reply());
        let r = WorkerTunnelResolver::new(server, "my-secret");
        let _ = r.query_txt(&ping_qname());
        let req = std::fs::read_to_string(&log_path).unwrap();
        let lower = req.to_ascii_lowercase();
        assert!(
            lower.contains("x-dastyab-session: my-secret"),
            "session header must be sent: {req}"
        );
    }

    #[test]
    fn test_resolver_returns_body_on_200() {
        let (server, _log) = mock_worker(200, pong_reply());
        let r = WorkerTunnelResolver::new(server, "s");
        let body = r.query_txt(&ping_qname()).unwrap();
        let decoded =
            TunnelFrame::decode_name(body.trim_end_matches('.'), DYB_TUNNEL_BASE).unwrap();
        assert_eq!(decoded.flags, 0x81);
        assert_eq!(decoded.payload, b"pong");
    }

    #[test]
    fn test_resolver_errors_on_401() {
        let (server, _log) = mock_worker(401, "{}".to_string());
        let r = WorkerTunnelResolver::new(server, "wrong");
        let err = r.query_txt(&ping_qname()).unwrap_err();
        assert!(err.detail.contains("session secret rejected"));
        assert_eq!(err.status, Some(401));
    }

    #[test]
    fn test_resolver_ping_roundtrip() {
        // Full ping → pong round-trip through the resolver (sync path) + decode.
        let (server, _log) = mock_worker(200, pong_reply());
        let r = WorkerTunnelResolver::new(server, "s");
        let qname = ping_qname();
        let body = r.query_txt(&qname).unwrap();
        let reply = TunnelFrame::decode_name(body.trim_end_matches('.'), DYB_TUNNEL_BASE).unwrap();
        assert_eq!(reply.flags, 0x81);
        assert_eq!(reply.payload, b"pong");
        assert_eq!(reply.session, "sess");
    }
}
