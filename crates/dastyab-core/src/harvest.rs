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

use std::time::Duration;

use crate::config_store;
use crate::error::CFError;
use crate::multilayer::PROXY_SOCKS_PORT;

/// How long to wait for the preview fetch.
const FETCH_TIMEOUT: Duration = Duration::from_secs(20);

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

/// Fetch a channel's public preview and return every `vless://` link it
/// contains, HTML-entity decoded. `use_proxy` routes via the local xray
/// SOCKS5 (PROXY_SOCKS_PORT) when a direct path is blocked.
pub fn fetch_channel_links(channel: &str, use_proxy: bool) -> Result<Vec<String>, CFError> {
    let url = format!("https://t.me/s/{channel}");
    let mut builder = reqwest::blocking::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36");
    if use_proxy {
        let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{PROXY_SOCKS_PORT}"))
            .map_err(|e| CFError::new("harvest", format!("proxy cfg: {e}"), ""))?;
        builder = builder.proxy(proxy);
    }
    let client = builder
        .build()
        .map_err(|e| CFError::new("harvest", format!("http client: {e}"), ""))?;

    let resp = client.get(&url).send().map_err(|e| {
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
        .map_err(|e| CFError::new("harvest", format!("reading body: {e}"), ""))?;

    let links = extract_vless_links(&body);
    Ok(links)
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

/// Harvest a channel into a profile's config store.
/// Returns how many links were found and imported.
pub fn harvest_channel(profile: &str, channel: &str, use_proxy: bool) -> ChannelHarvest {
    let mut harvest = ChannelHarvest {
        channel: channel.trim_start_matches('@').to_string(),
        ..Default::default()
    };
    match fetch_channel_links(&harvest.channel, use_proxy) {
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
}
