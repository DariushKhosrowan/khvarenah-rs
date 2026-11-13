//! Local Telegram export archive miner — the *terminal* fallback rung
//! (Rung -1) for node recovery under total international blackout.
//!
//! When every live path (Telegram preview endpoints, GitHub, CT/NS anchors)
//! is unreachable, DastYab can still recover configs from **what is
//! already on disk**: the standard Telegram Desktop export archive
//! (`chat_export`), which contains every message of a channel as
//! `<chat>/messages.json` (a JSON array/map of messages) plus per-message
//! `.html` files. Mining these is offline by construction — no sockets,
//! no egress, no API keys — so it works when the daemon has *nothing*
//! else. This is doctrine §5 ("bootstrapping must not be circular": use
//! pre-distributed/out-of-band sources) taken to its local extreme.
//!
//! Design:
//! - Walk the requested directory recursively, collecting `.json` and
//!   `.html` files (`messages.json` exports, exported HTML feeds).
//! - For each file, run the same plaintext + whole-link-base64 extraction
//!   as the live `t.me/s/` harvester ([`crate::harvest::extract_proxy_links`]
//!   plus [`extract_b64_embedded_links`]).
//! - Import every found link via [`crate::config_store::import_single_link_source`]
//!   tagged `telegram` (the store dedups across schemes/pages, so re-running
//!   is idempotent).
//! - Report a structured [`TgExportHarvest`] with *real* counts (no
//!   fabricated success: every `found` link was parseable, every `added`
//!   actually entered the store).
//!
//! The keyword is **depth**: live preview only walks back ~10 pages of a
//! channel, but a full local export has the *entire* history — thousands of
//! messages including configs long gone from the public preview. That is
//! exactly the "archived chats" reservoir the user pointed at.

use crate::config_store::{import_single_link_source, SOURCE_TELEGRAM};
use crate::harvest::extract_proxy_links;
use std::path::{Path, PathBuf};

/// A `.json`/`.html` archive file that was scanned, with its landed results.
#[derive(Debug, Clone, Default)]
pub struct FileScan {
    /// Path that was scanned.
    pub path: String,
    /// Distinct valid proxy links found in this file.
    pub links_found: usize,
    /// Links that actually entered the node store (new, not dup/invalid).
    pub links_added: usize,
}

/// Structured outcome of one offline archive-mining pass.
#[derive(Debug, Clone, Default)]
pub struct TgExportHarvest {
    /// Files scanned.
    pub files_scanned: usize,
    /// Per-file details (only files that contained at least one link).
    pub files: Vec<FileScan>,
    /// Total distinct links found across all files.
    pub total_found: usize,
    /// Total links that entered the store.
    pub total_added: usize,
    /// Total duplicates / invalid that were skipped.
    pub total_skipped: usize,
}

impl TgExportHarvest {
    /// Aggregate a row of per-file results into totals.
    fn ingest_file(&mut self, scan: FileScan) {
        let added = scan.links_added;
        let found = scan.links_found;
        self.files_scanned += 1;
        if found > 0 {
            self.files.push(scan);
        }
        self.total_found += found;
        self.total_added += added;
        self.total_skipped += found.saturating_sub(added);
    }
}

/// Extract proxy links from a body that may contain **whole-link base64
/// blobs** — a full `vless://…` (or other scheme) string base64-encoded as a
/// bare token, common in archived channel messages that wrap configs to dodge
/// preview scraping. Since such a blob has no `scheme://` prefix,
/// [`extract_proxy_links`] alone misses it; this decodes the blob and re-runs
/// extraction on its plaintext.
///
/// We only treat a token as a candidate blob if it is long enough to plausibly
/// encode a config (≥ 24 chars) and its base64 decode yields text that
/// contains at least one valid proxy link. Standard and URL-safe alphabets are
/// both tried, so padding-free URL-safe blobs are handled too.
pub fn extract_b64_embedded_links(body: &str) -> Vec<String> {
    use base64::Engine;

    if body.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    // Walk the body, carving maximal base64 alphabet runs (standard + url-safe).
    let bytes = body.as_bytes();
    let is_b64 = |b: u8| -> bool {
        b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'-' || b == b'_' || b == b'='
    };

    let mut i = 0usize;
    while i < bytes.len() {
        if !is_b64(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_b64(bytes[i]) {
            i += 1;
        }
        let token = &body[start..i];
        if token.len() < 24 {
            continue;
        }
        // Normalize: base64 decode requires the length to be a multiple of 4
        // (padding may have been stripped in transport). Restore the `=` pad.
        let padded = {
            let rem = token.len() % 4;
            if rem == 0 {
                token.to_string()
            } else {
                let mut s = token.to_string();
                s.push_str(&"=".repeat(4 - rem));
                s
            }
        };
        for engine in [
            &base64::engine::general_purpose::STANDARD,
            &base64::engine::general_purpose::URL_SAFE,
        ] {
            if let Ok(decoded) = engine.decode(padded.as_str()) {
                if let Ok(text) = String::from_utf8(decoded) {
                    for link in extract_proxy_links(&text) {
                        if !out.contains(&link) {
                            out.push(link);
                        }
                    }
                }
            }
        }
    }
    out
}

/// Scan one file (`.json` or `.html`) for proxy links — both plaintext and
/// whole-link base64 blobs — and import whatever is found into the profile's
/// node store. Returns the per-file scan result.
fn scan_file(profile: &str, path: &Path) -> FileScan {
    let mut scan = FileScan {
        path: path.display().to_string(),
        ..Default::default()
    };
    if path.extension().map(|e| e.to_string_lossy().to_lowercase()) != Some("json".to_string())
        && path.extension().map(|e| e.to_string_lossy().to_lowercase()) != Some("html".to_string())
    {
        return scan;
    }
    let Ok(body) = std::fs::read_to_string(path) else {
        return scan;
    };

    let mut links = extract_proxy_links(&body);
    for l in extract_b64_embedded_links(&body) {
        if !links.contains(&l) {
            links.push(l);
        }
    }
    links.sort();
    links.dedup();

    let mut added = 0usize;
    for link in &links {
        match import_single_link_source(profile, link, SOURCE_TELEGRAM) {
            Ok(s) => {
                if s.added > 0 {
                    added += 1;
                }
            }
            Err(_) => {}
        }
    }
    scan.links_found = links.len();
    scan.links_added = added;
    scan
}

/// Recursively collect `.json`/`.html` files under `dir`.
fn collect_archive_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_archive_files(&p, out);
        } else if let Some(ext) = p.extension() {
            let ext = ext.to_string_lossy().to_lowercase();
            if ext == "json" || ext == "html" {
                out.push(p);
            }
        }
    }
}

/// Mine a local Telegram export directory (recursively) for config share-links
/// and import them into the profile's node store, tagged `telegram`.
///
/// Pure offline: never touches the network, so it works even when the daemon
/// has zero reachable egress (Rung -1). Idempotent — the store dedups, so
/// repeated runs add nothing new.
pub fn harvest_export_dir(profile: &str, dir: &Path) -> TgExportHarvest {
    let mut harvest = TgExportHarvest::default();
    let mut files = Vec::new();
    collect_archive_files(dir, &mut files);
    for f in files {
        let mut scan = scan_file(profile, &f);
        // Don't report files we couldn't read (they contribute nothing).
        // scan_file already returns counts; only record files with content.
        if scan.links_found == 0 {
            scan.links_added = 0;
        }
        harvest.ingest_file(scan);
    }
    harvest
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_profile() -> (String, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "dyb_export_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        // Register a REAL profile so profile_dir resolves to an isolated dir
        // (unregistered ids silently fall back to the live `default` profile —
        // a known contamination trap). The profile dir is removed by each test
        // when it cleans up its temp dir.
        let profile = crate::store::profiles::create_profile("export_test", "").unwrap();
        (profile, dir)
    }

    /// Remove the temp export dir and the registered profile dir.
    fn cleanup(profile: &str, dir: &std::path::Path) {
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(crate::store::profiles::profile_dir(profile));
    }

    #[test]
    fn b64_whole_link_is_decoded() {
        use base64::Engine;
        let cfg = "vless://06ef598c-1555-4887-b3f9-08214a2f6792@104.17.72.206:443?type=ws#old";
        let blob = base64::engine::general_purpose::STANDARD.encode(cfg);
        let body = format!("config: {blob}");
        let links = extract_b64_embedded_links(&body);
        assert_eq!(links.len(), 1, "whole-link b64 must decode: {links:?}");
        assert!(links[0].starts_with("vless://"));
    }

    #[test]
    fn b64_urlsafe_without_padding_is_decoded() {
        use base64::Engine;
        // A URL-safe, no-padding blob (Telegram sometimes trims `=`).
        let cfg = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNQ:x@1.2.3.4:8388#ss";
        let padded = base64::engine::general_purpose::URL_SAFE.encode(cfg);
        let unpadded = padded.trim_end_matches('=');
        let body = format!("archived: {unpadded}");
        let links = extract_b64_embedded_links(&body);
        assert_eq!(
            links.len(),
            1,
            "url-safe unpadded b64 must decode: {links:?}"
        );
        assert!(links[0].starts_with("ss://"));
    }

    #[test]
    fn b64_only_ignores_garbage() {
        assert!(extract_b64_embedded_links("no base64 here").is_empty());
        assert!(extract_b64_embedded_links("aGVsbG8= whyno").is_empty());
        // A valid b64 that decodes to plain text with no proxy link.
        use base64::Engine;
        let plain = base64::engine::general_purpose::STANDARD.encode("just some words");
        assert!(extract_b64_embedded_links(&format!("text {plain}")).is_empty());
    }

    #[test]
    fn plaintext_links_still_extracted() {
        let body = "vless://06ef598c-1555-4887-b3f9-08214a2f6792@104.17.72.206:443?type=ws#";
        let links = extract_proxy_links(body);
        assert_eq!(links.len(), 1);
    }

    #[test]
    fn harvest_imports_from_export_dir() {
        let (profile, dir) = tmp_profile();

        // Fake export layout:
        //   <dir>/chat1/messages.json        -> plaintext link + whole-link b64
        //   <dir>/chat2/messages.html        -> a second plaintext link
        //   <dir>/notes.txt                  -> ignored (not json/html)
        let chat1 = dir.join("chat1");
        let chat2 = dir.join("chat2");
        std::fs::create_dir_all(&chat1).unwrap();
        std::fs::create_dir_all(&chat2).unwrap();

        let json = r#"{ "messages": [
            { "id":1, "text": "vless://06ef598c-1555-4887-b3f9-08214a2f6792@104.17.72.206:443?type=ws#a" },
            { "id":2, "text": "vless://07ef598c-1555-4887-b3f9-08214a2f6792@104.17.72.206:443?type=ws#b" }
        ] }"#;
        std::fs::write(chat1.join("messages.json"), json).unwrap();

        let html = r#"<div class="message">trojan://pw@ali.example.com:8443#tr</div>"#;
        std::fs::write(chat2.join("messages.html"), html).unwrap();

        std::fs::write(dir.join("notes.txt"), "not a config file").unwrap();

        let harvest = harvest_export_dir(&profile, &dir);

        assert_eq!(harvest.files_scanned, 2, "json+html scanned, txt ignored");
        assert_eq!(harvest.total_found, 3, "2 vless + 1 trojan");
        assert!(
            harvest.total_added >= 3,
            "all three enter store: {:?}",
            harvest
        );
        assert!(harvest
            .files
            .iter()
            .any(|f| f.path.ends_with("messages.json")));
        assert!(harvest
            .files
            .iter()
            .any(|f| f.path.ends_with("messages.html")));

        // The store now contains them.
        let store = crate::config_store::load_node_store(&profile);
        let vless_count = store
            .nodes
            .iter()
            .filter(|n| n.url.starts_with("vless://"))
            .count();
        let trojan_count = store
            .nodes
            .iter()
            .filter(|n| n.url.starts_with("trojan://"))
            .count();
        assert_eq!(vless_count, 2);
        assert_eq!(trojan_count, 1);

        cleanup(&profile, &dir);
    }

    #[test]
    fn harvest_is_idempotent() {
        let (profile, dir) = tmp_profile();
        let chat = dir.join("chat");
        std::fs::create_dir_all(&chat).unwrap();
        let json = r#"{ "messages": [
            { "id":1, "text": "vless://06ef598c-1555-4887-b3f9-08214a2f6792@104.17.72.206:443?type=ws#c" }
        ] }"#;
        std::fs::write(chat.join("messages.json"), json).unwrap();

        let first = harvest_export_dir(&profile, &dir);
        assert_eq!(first.total_added, 1);

        let second = harvest_export_dir(&profile, &dir);
        assert_eq!(second.total_added, 0, "re-run adds nothing new");
        assert_eq!(second.total_found, 1, "still sees the link");

        cleanup(&profile, &dir);
    }
}
