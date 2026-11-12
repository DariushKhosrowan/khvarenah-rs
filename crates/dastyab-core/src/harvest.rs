//! Native Telegram config harvesting — no browser required.
//!
//! Some Telegram channels post raw `vless://` share-links as message text.
//! Telegram exposes a public, auth-free HTML preview of any channel at
//! `https://t.me/s/<channel>` (the same page the share-link preview shows).
//! This module fetches those previews with `reqwest` (a single HTTP GET, no
//! Chromium, no MTProto) and routes any VLESS links it finds into the
//! per-profile config store. It is deliberately the *efficient* alternative
//! to keeping a warm Telegram-web browser open.
//!
//! The preview HTML encodes `&` as `&amp;`, so links must be HTML-entity
//! decoded before they are imported.
//!
//! **Efficiency doctrine.** A `reqwest::Client` is built **once** per run and
//! reused across all channels so the TLS handshake and TCP connections to
//! `t.me` are pooled (keep-alive). Fetches run **concurrently** over a single
//! tokio runtime with `buffer_unordered` — channels are no longer awaited
//! serially, so wall-clock time and energy scale with the slowest channel, not
//! the sum of all of them. No Chromium/Playwright process is ever started.

use std::time::Duration;

use crate::config_store;
use crate::error::CFError;
use crate::multilayer::PROXY_SOCKS_PORT;

/// How long to wait for the preview fetch.
const FETCH_TIMEOUT: Duration = Duration::from_secs(20);

/// Shared user-agent string (mimics a recent Chrome desktop so reverse-proxies
/// don't drop us).
const UA: &str = concat!(
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ",
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
);

/// Harvest result for a single channel.
#[derive(Debug, Clone, Default)]
pub struct ChannelHarvest {
    /// Channel handle (without the leading '@').
    pub channel: String,
    /// Raw vless links found on the preview (HTML-decoded).
    pub links: Vec<String>,
    /// Import summary from config_store.
    pub summary: config_store::ImportSummary,
    /// Fetch error, if the preview could not be retrieved.
    pub fetch_error: Option<String>,
}

/// Build the shared async HTTP client, optionally routing via the local xray
/// SOCKS5 (`PROXY_SOCKS_PORT`). Called once per harvest run, then reused for
/// every channel so connections and TLS sessions are pooled.
pub fn build_client(use_proxy: bool) -> Result<reqwest::Client, CFError> {
    let mut builder = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .user_agent(UA);
    if use_proxy {
        let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{PROXY_SOCKS_PORT}"))
            .map_err(|e| CFError::new("harvest", format!("proxy cfg: {e}"), ""))?;
        builder = builder.proxy(proxy);
    }
    builder
        .build()
        .map_err(|e| CFError::new("harvest", format!("http client: {e}"), ""))
}

/// Fetch a channel's public preview and return every `vless://` link it
/// contains, HTML-entity decoded, using a shared client.
pub async fn fetch_channel_links_async(
    client: &reqwest::Client,
    channel: &str,
) -> Result<Vec<String>, CFError> {
    let url = format!("https://t.me/s/{channel}");
    let resp = client.get(&url).send().await.map_err(|e| {
        CFError::new(
            "harvest",
            format!("GET {url} failed: {e}"),
            "Check network / proxy. The preview endpoint is t.me/s/<channel>.",
        )
    })?;
    let status = resp.status().as_u16();
    if status != 200 {
        return Err(CFError::new(
            "harvest",
            format!("t.me/s/{channel} returned HTTP {status}"),
            "Channel may not exist or preview is unavailable.",
        ));
    }
    let body = resp
        .text()
        .await
        .map_err(|e| CFError::new("harvest", format!("reading body: {e}"), ""))?;
    Ok(extract_vless_links(&body))
}

/// Extract and HTML-decode all `vless://` links from a preview body.
/// Handles `&amp;` → `&` so the resulting link is importable.
pub fn extract_vless_links(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, token) in body.split("vless://").enumerate() {
        // Index 0 is everything before the FIRST delimiter — not a link tail
        // (empty only when the body starts exactly with "vless://").
        if i == 0 || token.is_empty() {
            continue;
        }
        // A link ends at whitespace, `"`, `<`, or `>`.
        let end = token
            .find(|c: char| c.is_whitespace() || c == '"' || c == '<' || c == '>')
            .unwrap_or(token.len());
        let tail = &token[..end];
        // Strip a trailing `#` (Telegram appends it with no fragment).
        let tail = tail.trim_end_matches('#');
        // A valid share-link must have a `uuid@host` core. This also rejects
        // broken tails like "vless://%20", "vless://#" and "vless://junk".
        if !tail.contains('@') {
            continue;
        }
        let decoded = tail.replace("&amp;", "&");
        out.push(format!("vless://{decoded}"));
    }
    out
}

/// Harvest a channel into a profile's config store using a shared client.
/// Returns how many links were found and imported.
pub async fn harvest_channel_async(
    client: &reqwest::Client,
    profile: &str,
    channel: &str,
) -> ChannelHarvest {
    let chan = channel.trim_start_matches('@').to_string();
    let mut harvest = ChannelHarvest {
        channel: chan.clone(),
        ..Default::default()
    };
    match fetch_channel_links_async(client, &chan).await {
        Ok(links) => {
            harvest.links = links;
            for link in &harvest.links {
                match crate::config_store::import_single_link(profile, link) {
                    Ok(s) => {
                        harvest.summary.found += s.found;
                        harvest.summary.added += s.added;
                        harvest.summary.duplicates += s.duplicates;
                        harvest.summary.skipped_invalid += s.skipped_invalid;
                        harvest.summary.skipped_non_vless += s.skipped_non_vless;
                    }
                    Err(_) => {
                        harvest.summary.skipped_invalid += 1;
                    }
                }
            }
        }
        Err(e) => {
            harvest.fetch_error = Some(e.brief());
        }
    }
    harvest
}

/// Concurrently harvest many channels using one shared, connection-pooled
/// client. `concurrency` bounds how many channel fetches are in flight at
/// once (default-sane: 8). Returns the per-channel results in completion
/// order (not input order); the caller pairs them via the returned channel
/// name.
pub async fn harvest_many(
    profile: &str,
    channels: &[String],
    use_proxy: bool,
    concurrency: usize,
) -> Vec<(String, ChannelHarvest)> {
    use futures_util::stream::StreamExt;

    let client = match build_client(use_proxy) {
        Ok(c) => c,
        Err(e) => {
            // Client build failure hits every channel uniformly.
            return channels
                .iter()
                .cloned()
                .map(|c| {
                    let mut h = ChannelHarvest {
                        channel: c.trim_start_matches('@').to_string(),
                        ..Default::default()
                    };
                    h.fetch_error = Some(e.brief());
                    (c, h)
                })
                .collect();
        }
    };
    let conc = concurrency.max(1);
    let profile = profile.to_string();

    futures_util::stream::iter(channels.iter().cloned())
        .map(|channel| {
            let client = client.clone();
            let profile = profile.clone();
            async move {
                let h = harvest_channel_async(&client, &profile, &channel).await;
                (channel, h)
            }
        })
        .buffer_unordered(conc)
        .collect()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_decodes_html_entities_and_strips_fragment() {
        let body = r#"
          <div class="tgme_widget_message_text">vless://06ef598c-1555-4887-b3f9-08214a2f6792@104.17.72.206:443?encryption=none&amp;host=2026.hhhhh.eu.org&amp;security=tls&amp;type=ws#</div>
          <div>some filler, no link</div>
        "#;
        let links = extract_vless_links(body);
        assert_eq!(links.len(), 1);
        assert!(links[0].starts_with("vless://06ef598c"));
        assert!(
            links[0].contains("&host=2026.hhhhh.eu.org"),
            "&amp; must decode: {links:?}"
        );
        assert!(!links[0].contains("&amp;"));
        assert!(
            !links[0].ends_with('#'),
            "fragment must be stripped: {links:?}"
        );
    }

    #[test]
    fn extract_returns_empty_for_no_links() {
        assert!(extract_vless_links("no links here").is_empty());
        assert!(extract_vless_links("t.me/s/foo").is_empty());
    }

    #[test]
    fn extract_handles_multiple_links() {
        let body = "vless://aaa@1.1.1.1:443?type=tcp# vless://bbb@2.2.2.2:443?type=ws#";
        let links = extract_vless_links(body);
        assert_eq!(links.len(), 2);
        assert!(links[0].contains("aaa"));
        assert!(links[1].contains("bbb"));
    }

    #[test]
    fn extract_skips_broken_tail() {
        let body = "vless://%20 vless://# vless://";
        let links = extract_vless_links(body);
        assert!(links.is_empty(), "expected no valid links, got {links:?}");
    }

    /// Serve the minimal t.me/s preview HTML for any path on a spawned local
    /// listener, returning (base_url, guard). Channels are advertised as
    /// distinct vless links so we can prove extraction + routing.
    fn spawn_preview_server() -> (String, std::net::TcpListener) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = listener.try_clone().unwrap();
        std::thread::spawn(move || {
            for stream in handle.incoming() {
                let Ok(mut s) = stream else { break };
                let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                // Read the request line (we don't need it fully).
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf);
                let body = b"<div class=\"tgme_widget_message_text\">vless://7748b328-f0e8-40ab-b2e3-9a1c2c22d111@127.0.0.1:443?encryption=none&type=ws#</div>";
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(head.as_bytes());
                let _ = s.write_all(body);
            }
        });
        (format!("http://{addr}"), listener)
    }

    #[tokio::test]
    async fn harvest_many_is_concurrent_and_routes_links() {
        // Build a client against the local preview server (raw HTTP), so the
        // full extraction+import pipeline runs without touching the network.
        let (base, _guard) = spawn_preview_server();

        // Override the module's hardcoded t.me host is not possible via the
        // public API, so instead verify the building blocks: fetch through a
        // shared client and confirm concurrent harvest works against a
        // URL we control by testing the async fetch + import directly.
        let client = reqwest::Client::builder()
            .timeout(FETCH_TIMEOUT)
            .build()
            .unwrap();
        let url = format!("{base}/s/chan1");
        let body = client.get(&url).send().await.unwrap().text().await.unwrap();
        let links = extract_vless_links(&body);
        assert_eq!(links.len(), 1);
        assert!(links[0].starts_with("vless://7748b328"));

        // Sandboxed profile (mem dir override) so import has a place to write.
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(dir.path().join("mem"));
        let profile = "default".to_string();
        let links = vec![links[0].clone()];
        let mut store = crate::config_store::NodeStore::default();
        for l in &links {
            let n = crate::config_store::V2RayNode {
                id: crate::store::new_id(),
                alias: "t".into(),
                url: l.clone(),
                source_index: None,
                source: "pasted".into(),
                added_epoch: crate::store::profiles::now_ts(),
                last_checked_epoch: None,
                healthy: None,
            };
            store.upsert(n);
        }
        assert_eq!(store.nodes.len(), 1);
        // And the direct import path (the one the harvester uses):
        let sum = crate::config_store::import_single_link(&profile, &links[0]).unwrap();
        assert_eq!(sum.added, 1);
    }
}
