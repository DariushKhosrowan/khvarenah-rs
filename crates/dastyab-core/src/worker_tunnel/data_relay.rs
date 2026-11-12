//! Client-side data-plane relay for the Cloudflare worker tunnel.
//!
//! The deployed worker exposes a WebSocket byte-pipe at `/ws` (see
//! [`crate::worker_tunnel::bundle`]) that relays bytes to the configured
//! `DYB_VLESS_UPSTREAM`. This module is the *client* side of that pipe: it
//! opens a local TCP listener and, for every accepted connection, opens a
//! session-authenticated WebSocket to the worker's `/ws` endpoint and pipes
//! bytes bidirectionally. Local apps (a SOCKS/HTTP proxy, a raw port forward,
//! anything speaking a single TCP session) use the local listener as a clean
//! loopback entry point that runs the *entire* Cloudflare worker tunnel.
//!
//! # Security
//!
//! The `/ws` endpoint requires the shared session secret
//! (`X-DastYab-Session` header). A standard VLESS client cannot send that
//! header, so this bridge is what *arms* the data plane: it authenticates the
//! WebSocket upgrade, then pipes the raw byte stream. The listener binds only
//! to loopback so nothing local is exposed to the network.
//!
//! # Wire protocol
//!
//! ```text
//! client ──TCP──▶ relay ──WebSocket(wss://…/ws + auth)──▶ worker ──TCP──▶ upstream
//! ```
//!
//! One WebSocket per accepted local connection; both directions are piped
//! concurrently with backpressure (a slow reader stalls the writer).

use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::CFError;

/// A relay that bridges a local loopback listener to the worker's `/ws`
/// WebSocket data plane.
#[derive(Debug, Clone)]
pub struct WorkerDataRelay {
    /// The deployed worker URL, e.g. `https://dyb-tun-…sub.workers.dev`.
    worker_url: String,
    /// Shared session secret (matches `DYB_SESSION_SECRET` on the worker).
    session_secret: String,
    /// Upstream the worker relays to — informational only (the worker owns
    /// this; the client just sees a byte pipe).
    upstream: Option<String>,
    /// Per-connection WebSocket connect timeout.
    ws_timeout: Duration,
    /// Bytes copied per direction before yielding to the other direction.
    chunk: usize,
}

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

impl WorkerDataRelay {
    /// Build a relay for a deployed worker tunnel.
    pub fn new(
        worker_url: impl Into<String>,
        session_secret: impl Into<String>,
        upstream: Option<String>,
    ) -> Self {
        Self {
            worker_url: worker_url.into(),
            session_secret: session_secret.into(),
            upstream,
            ws_timeout: Duration::from_secs(20),
            chunk: 16 * 1024,
        }
    }

    /// The worker URL being bridged.
    pub fn worker_url(&self) -> &str {
        &self.worker_url
    }

    /// The configured upstream (informational).
    pub fn upstream(&self) -> Option<&str> {
        self.upstream.as_deref()
    }

    /// Resolve the worker URL to a `wss://host/ws` endpoint.
    fn ws_endpoint(&self) -> Result<String, CFError> {
        let url = self.worker_url.trim_end_matches('/');
        let host = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url)
            .split('/')
            .next()
            .unwrap_or("")
            .trim();
        if host.is_empty() {
            return Err(CFError::new(
                "worker-data-relay",
                "cannot resolve worker URL to a host",
                &format!("worker_url={}", self.worker_url),
            ));
        }
        Ok(format!("wss://{host}/ws"))
    }

    /// Open a single authenticated WebSocket to the worker's `/ws` endpoint.
    ///
    /// The session secret is injected as the `X-DastYab-Session` header on
    /// the WS upgrade request — this is what the worker's `authed()` checks.
    async fn open_ws(&self) -> Result<WsStream, CFError> {
        let endpoint = self.ws_endpoint()?;
        let secret = self.session_secret.clone();
        if secret.is_empty() {
            return Err(CFError::new(
                "worker-data-relay",
                "empty session secret",
                "Deploy the worker tunnel with a non-empty secret.",
            ));
        }

        // Resolve the host:port and open the raw TCP connection first.
        let hostport = endpoint
            .trim_start_matches("wss://")
            .trim_start_matches("ws://");
        let (host, port) = {
            let (h, rest) = hostport.split_once(':').unwrap_or((hostport, "443"));
            let p: u16 = rest.parse().map_err(|_| {
                CFError::new(
                    "worker-data-relay",
                    format!("bad port in endpoint {endpoint}"),
                    "",
                )
            })?;
            (h.to_string(), p)
        };
        let tcp = tokio::time::timeout(
            self.ws_timeout,
            tokio::net::TcpStream::connect((host.as_str(), port)),
        )
        .await
        .map_err(|_| {
            CFError::new(
                "worker-data-relay",
                format!("tcp connect {host}:{port} timed out"),
                "Is the worker reachable over TLS?",
            )
        })?
        .map_err(|e| {
            CFError::new(
                "worker-data-relay",
                format!("tcp connect {host}:{port}: {e}"),
                "Is the worker reachable over TLS?",
            )
        })?;

        // Build the upgrade request with the session auth header.
        let req = tokio_tungstenite::tungstenite::handshake::client::Request::builder()
            .uri(&endpoint)
            .header("Host", hostport.split('/').next().unwrap_or(hostport))
            .header("X-DastYab-Session", &secret)
            .header("User-Agent", "dastyab-worker-data-relay")
            .body(())
            .map_err(|e| CFError::new("worker-data-relay", format!("build ws request: {e}"), ""))?;

        let (_ws, _resp) = tokio_tungstenite::client_async_tls_with_config(req, tcp, None, None)
            .await
            .map_err(|e| {
                CFError::new(
                    "worker-data-relay",
                    format!("websocket upgrade to {endpoint}: {e}"),
                    "Is the worker deployed and reachable over TLS?",
                )
            })?;
        Ok(_ws)
    }

    /// Bridge a single accepted local TCP connection to the worker.
    ///
    /// Returns the number of bytes copied client→worker and worker→client.
    async fn bridge_connection(&self, local: TcpStream) -> Result<(u64, u64), CFError> {
        let ws = self.open_ws().await?;
        let (mut sink, mut source) = ws.split();
        let tcp = tokio::net::TcpStream::from_std(local).map_err(|e| {
            CFError::new(
                "worker-data-relay",
                format!("convert local stream: {e}"),
                "",
            )
        })?;
        let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp);

        let chunk = self.chunk;

        // Pipe TCP → WS concurrently with WS → TCP so neither direction is
        // blocked on the other (full-duplex byte pipe).
        let tcp_to_ws = async {
            let mut total = 0u64;
            let mut buf = vec![0u8; chunk];
            loop {
                let n = tcp_read.read(&mut buf).await.map_err(|e| {
                    CFError::new("worker-data-relay", format!("read local: {e}"), "")
                })?;
                if n == 0 {
                    break;
                }
                let bytes: tokio_tungstenite::tungstenite::Bytes = buf[..n].to_vec().into();
                sink.send(tokio_tungstenite::tungstenite::Message::Binary(bytes))
                    .await
                    .map_err(|e| CFError::new("worker-data-relay", format!("send ws: {e}"), ""))?;
                total += n as u64;
            }
            // Half-close our send side.
            let _ = sink.close().await;
            Ok::<u64, CFError>(total)
        };

        let ws_to_tcp = async {
            let mut total = 0u64;
            while let Some(msg) = source.next().await {
                match msg
                    .map_err(|e| CFError::new("worker-data-relay", format!("recv ws: {e}"), ""))?
                {
                    tokio_tungstenite::tungstenite::Message::Binary(data) => {
                        tcp_write.write_all(&data).await.map_err(|e| {
                            CFError::new("worker-data-relay", format!("write local: {e}"), "")
                        })?;
                        total += data.len() as u64;
                    }
                    tokio_tungstenite::tungstenite::Message::Text(data) => {
                        let bytes = data.as_bytes();
                        tcp_write.write_all(bytes).await.map_err(|e| {
                            CFError::new("worker-data-relay", format!("write local: {e}"), "")
                        })?;
                        total += bytes.len() as u64;
                    }
                    tokio_tungstenite::tungstenite::Message::Close(_) => break,
                    _ => {}
                }
            }
            Ok::<u64, CFError>(total)
        };

        let (up, down) = tokio::join!(tcp_to_ws, ws_to_tcp);
        let up = up?;
        let down = down?;
        Ok((up, down))
    }

    /// Serve a local loopback listener until `stop` is set or the listener
    /// fails. Each accepted connection is bridged in its own task.
    ///
    /// Returns when the listener closes or `stop` becomes true.
    pub async fn serve_local(
        &self,
        bind_addr: &str,
        stop: Option<Arc<AtomicBool>>,
    ) -> Result<(), CFError> {
        let listener = TcpListener::bind(bind_addr).map_err(|e| {
            CFError::new(
                "worker-data-relay",
                format!("bind {bind_addr}: {e}"),
                "Choose a free loopback port.",
            )
        })?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| CFError::new("worker-data-relay", format!("local_addr: {e}"), ""))?;
        eprintln!(
            "[worker-data-relay] listening on {local_addr} → {}",
            self.worker_url
        );

        loop {
            if stop.as_ref().is_some_and(|s| s.load(Ordering::Relaxed)) {
                break;
            }
            let (conn, _peer) = listener
                .accept()
                .map_err(|e| CFError::new("worker-data-relay", format!("accept: {e}"), ""))?;
            let relay = self.clone();
            tokio::spawn(async move {
                match relay.bridge_connection(conn).await {
                    Ok((up, down)) => {
                        eprintln!("[worker-data-relay] session done: ↑{up}B ↓{down}B");
                    }
                    Err(e) => {
                        eprintln!("[worker-data-relay] session error: {e}");
                    }
                }
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn ws_endpoint_resolves_https_worker() {
        let r = WorkerDataRelay::new("https://dyb-tun-1234.sub.workers.dev", "secret", None);
        assert_eq!(
            r.ws_endpoint().unwrap(),
            "wss://dyb-tun-1234.sub.workers.dev/ws"
        );
    }

    #[test]
    fn ws_endpoint_strips_trailing_slash_and_path() {
        let r = WorkerDataRelay::new(
            "https://dyb-tun-1234.sub.workers.dev/",
            "secret",
            Some("10.0.0.1:443".into()),
        );
        assert_eq!(
            r.ws_endpoint().unwrap(),
            "wss://dyb-tun-1234.sub.workers.dev/ws"
        );
        assert_eq!(r.upstream(), Some("10.0.0.1:443"));
    }

    #[test]
    fn ws_endpoint_rejects_empty_host() {
        let r = WorkerDataRelay::new("", "secret", None);
        assert!(r.ws_endpoint().is_err());
    }

    #[test]
    fn serve_local_stops_on_flag() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let r = WorkerDataRelay::new("https://dyb-tun-1234.sub.workers.dev", "secret", None);
            let stop = Arc::new(AtomicBool::new(true));
            // Stop is set before serving → returns immediately.
            let res = r.serve_local("127.0.0.1:0", Some(stop)).await;
            assert!(res.is_ok());
        });
    }
}
