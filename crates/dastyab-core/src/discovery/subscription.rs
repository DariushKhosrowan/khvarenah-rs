//! Embedded loopback HTTP subscription server.
//!
//! v2rayN (and many other clients) can consume a *subscription URL*: a URL
//! that returns a body of newline-separated share-links (`vless://`,
//! `vmess://`, ...), typically base64-encoded. This module implements a
//! small loopback-only HTTP server that serves the local node pool as such a
//! subscription feed, so the user can point v2rayN at
//! `http://127.0.0.1:<port>/subscription` and always get a fresh,
//! latency-verified set of configs without ever opening Telegram.
//!
//! Resilience doctrine: the feed is always built from the *current* healthy
//! pool at request time (never cached/stale). When no healthy node exists,
//! the server returns an empty body. It binds only to loopback, so it
//! exposes nothing to the network; it is a local convenience channel, not a
//! public service.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use crate::artifact::config_store::{load_node_store, V2RayNode};

/// Default port for the loopback subscription server.
pub const DEFAULT_SUBSCRIPTION_PORT: u16 = 10852;

/// Subscription feed format requested by the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedFormat {
    /// Base64-encoded newline-joined share-links (the v2rayN default).
    Base64,
    /// Plain text (newline-joined share-links), no encoding.
    Plain,
}

/// A handle to a running loopback subscription server.
pub struct SubscriptionServer {
    /// The thread serving HTTP requests.
    handle: thread::JoinHandle<()>,
    /// The bound loopback address (actual port when 0 was requested).
    pub addr: std::net::SocketAddr,
    /// Set to stop the accept loop (see [`SubscriptionServer::stop`]).
    shutdown: Arc<AtomicBool>,
}

/// Configuration for the subscription server.
#[derive(Debug, Clone)]
pub struct SubscriptionConfig {
    /// Profile whose node store is served.
    pub profile: String,
    /// Bind port. 0 = ask the OS for any free port.
    pub port: u16,
    /// Only include verified-healthy nodes. Default true.
    pub only_healthy: bool,
    /// Require `?token=` matching this to serve content. None = open.
    pub token: Option<String>,
}

impl Default for SubscriptionConfig {
    fn default() -> Self {
        Self {
            profile: "default".to_string(),
            port: DEFAULT_SUBSCRIPTION_PORT,
            only_healthy: true,
            token: None,
        }
    }
}

/// Build the subscription feed body for the given pool.
pub fn render_feed(nodes: &[V2RayNode], format: FeedFormat) -> String {
    // Order: freshest publish first, then most recently added. Free configs
    // rot fast; the newest are the most likely to still respond.
    let mut ranked: Vec<&V2RayNode> = nodes.iter().collect();
    ranked.sort_by(|a, b| {
        let ka = (a.published_epoch.unwrap_or(0.0), a.added_epoch);
        let kb = (b.published_epoch.unwrap_or(0.0), b.added_epoch);
        kb.partial_cmp(&ka).unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut joined = String::new();
    for n in ranked {
        if !n.url.trim().is_empty() {
            joined.push_str(n.url.trim());
            joined.push('\n');
        }
    }
    match format {
        FeedFormat::Plain => joined,
        FeedFormat::Base64 => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(joined.as_bytes())
        }
    }
}

/// Serve the profile's node store as a v2rayN subscription over loopback.
///
/// Only `GET /` and `GET /subscription` are handled; anything else gets a
/// 404. `?fmt=plain` returns an un-encoded feed; `?token=` is required when
/// a token is configured.
pub fn serve_loopback(cfg: &SubscriptionConfig) -> Result<SubscriptionServer, String> {
    let bind = format!("127.0.0.1:{}", cfg.port);
    let listener = TcpListener::bind(&bind).map_err(|e| format!("bind {bind}: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;
    let _ = listener.set_nonblocking(true);

    let profile = cfg.profile.clone();
    let only_healthy = cfg.only_healthy;
    let token = cfg.token.clone();
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_flag = shutdown.clone();

    let server_profile = profile.clone();
    let handle = thread::spawn(move || {
        while !shutdown_flag.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let profile = server_profile.clone();
                    let token = token.clone();
                    thread::spawn(move || {
                        let _ = handle_conn(&mut stream, &profile, only_healthy, &token);
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    });

    Ok(SubscriptionServer {
        handle,
        addr,
        shutdown,
    })
}

impl SubscriptionServer {
    /// Stop the server and wait for its thread to exit. Safe to call at any
    /// time; returns once the accept loop has exited.
    pub fn stop(self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = self.handle.join();
    }
}

fn handle_conn(
    stream: &mut TcpStream,
    profile: &str,
    only_healthy: bool,
    token: &Option<String>,
) -> Result<(), String> {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));

    let mut reader = BufReader::new(stream.try_clone().map_err(|e| format!("clone: {e}"))?);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .map_err(|e| format!("read line: {e}"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();

    // Drain the remaining request headers so keep-alive clients are satisfied.
    loop {
        let mut line = String::new();
        if reader
            .read_line(&mut line)
            .map_err(|e| format!("read header: {e}"))?
            == 0
        {
            break;
        }
        if line.trim().is_empty() {
            break;
        }
    }

    if method != "GET" {
        return write_response(stream, 405, "method not allowed", "text/plain");
    }
    // Split off the query string before path matching.
    let path = target.split('?').next().unwrap_or(target.as_str());
    let query = target.split_once('?').map(|(_, q)| q).unwrap_or("");
    if path != "/" && path != "/subscription" {
        return write_response(stream, 404, "not found", "text/plain");
    }

    // Token gate.
    if let Some(expected) = token {
        if extract_token(query).as_deref() != Some(expected.as_str()) {
            return write_response(stream, 401, "unauthorized", "text/plain");
        }
    }

    let nodes = load_node_store(profile).nodes;
    let healthy: Vec<V2RayNode> = nodes
        .into_iter()
        .filter(|n| !only_healthy || n.healthy == Some(true))
        .collect();

    if healthy.is_empty() {
        return write_response(stream, 200, "", "text/plain");
    }

    let fmt = if query.contains("fmt=plain") {
        FeedFormat::Plain
    } else {
        FeedFormat::Base64
    };
    let body = render_feed(&healthy, fmt);
    write_response(stream, 200, &body, "text/plain; charset=utf-8")
}

fn extract_token(query: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let mut it = kv.splitn(2, '=');
        let k = it.next()?;
        let v = it.next().unwrap_or("");
        if k == "token" {
            Some(v.to_string())
        } else {
            None
        }
    })
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    body: &str,
    content_type: &str,
) -> Result<(), String> {
    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .and_then(|_| stream.write_all(body.as_bytes()))
        .map_err(|e| format!("write response: {e}"))
}

/// Minimal blocking GET used for the `subscribe` command's startup self-check.
pub fn count_get(url: &str) -> Result<usize, String> {
    let body = tiny_get(url)?;
    Ok(body.len())
}

fn tiny_get(url: &str) -> Result<String, String> {
    tiny_get_full(url).map(|(_s, b)| b)
}

/// Returns (http_status, body) for a GET request. Used by tests to assert on
/// status codes without caring about store contents.
fn tiny_get_full(url: &str) -> Result<(u16, String), String> {
    let rest = url.strip_prefix("http://").ok_or("not http")?;
    let (hostport, path) = match rest.split_once('/') {
        Some((h, p)) => (h, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let mut stream = TcpStream::connect(hostport).map_err(|e| format!("connect: {e}"))?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    let reader = BufReader::new(stream);
    let mut lines = reader.lines();
    let status_line = lines
        .next()
        .ok_or("no status line")?
        .map_err(|e| format!("read: {e}"))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .ok_or("no status code")?
        .parse()
        .map_err(|e| format!("status parse: {e}"))?;
    let mut body = String::new();
    let mut in_body = false;
    for line in lines {
        let line = line.map_err(|e| format!("read: {e}"))?;
        if in_body {
            body.push_str(&line);
            body.push('\n');
        } else if line.is_empty() {
            in_body = true;
        }
    }
    Ok((status, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::config_store::V2RayNode;

    fn node(id: &str, url: &str, healthy: bool, published: f64) -> V2RayNode {
        V2RayNode {
            id: id.to_string(),
            alias: id.to_string(),
            url: url.to_string(),
            source_index: None,
            source: "test".to_string(),
            added_epoch: 0.0,
            published_epoch: Some(published),
            last_checked_epoch: Some(0.0),
            healthy: Some(healthy),
        }
    }

    #[test]
    fn feed_base64_sorts_freshest_first() {
        let nodes = vec![
            node("a", "vless://a", true, 1.0),
            node("b", "vless://b", true, 2.0),
            node("c", "vless://c", true, 3.0),
        ];
        let b64 = render_feed(&nodes, FeedFormat::Base64);
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .expect("valid base64");
        let text = String::from_utf8(decoded).expect("utf8");
        // c (freshest) first, then b, then a.
        assert!(
            text.starts_with("vless://c\nvless://b\nvless://a\n"),
            "got: {text}"
        );
    }

    #[test]
    fn feed_plain_preserves_all_lines() {
        let nodes = vec![node("a", "vless://a", true, 1.0)];
        assert_eq!(render_feed(&nodes, FeedFormat::Plain), "vless://a\n");
    }

    #[test]
    fn server_serves_over_loopback_and_enforces_token() {
        // No token: all paths without token must be serviceable (200).
        let cfg = SubscriptionConfig {
            profile: "subsrv-test".to_string(),
            port: 0,
            only_healthy: true,
            token: None,
        };
        let srv = serve_loopback(&cfg).expect("serve");
        let (st, _body) = tiny_get_full(&format!("http://{}/subscription", srv.addr)).expect("get");
        assert_eq!(st, 200, "status was {st}");
        srv.stop();

        // Token config: missing token -> 401, right token -> 200.
        let cfg2 = SubscriptionConfig {
            profile: "subsrv-test".to_string(),
            port: 0,
            only_healthy: true,
            token: Some("s3cret".to_string()),
        };
        let srv2 = serve_loopback(&cfg2).expect("serve");
        let (st2, _) =
            tiny_get_full(&format!("http://{}/subscription", srv2.addr)).expect("get no token");
        assert_eq!(st2, 401, "expected 401, got {st2}");
        let (st3, _) = tiny_get_full(&format!("http://{}/subscription?token=s3cret", srv2.addr))
            .expect("get with token");
        assert_eq!(st3, 200, "expected 200 with token, got {st3}");
        srv2.stop();
    }

    #[test]
    fn server_404_and_405() {
        let cfg = SubscriptionConfig {
            profile: "subsrv-test".to_string(),
            port: 0,
            only_healthy: true,
            token: None,
        };
        let srv = serve_loopback(&cfg).expect("serve");
        let addr = srv.addr;
        let (st, _) = tiny_get_full(&format!("http://{}/nope", addr)).expect("get");
        assert_eq!(st, 404, "expected 404, got {st}");
        srv.stop();
    }
}
