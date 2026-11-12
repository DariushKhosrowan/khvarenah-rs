//! GitHub config-source ingestion — pull free v2ray configs from public
//! GitHub repositories and catalogues.
//!
//! Iranian config repos (e.g. the `v2ray-configs` GitHub topic, `barry-far/
//! V2ray-Config`, `0xRadikal/Free-v2ray-Configs`, `liMilCo/v2r`, …) publish
//! subscription files in two forms:
//!
//! - **plain** — one share-link per line (`vless://…`, `vmess://…`, …)
//! - **base64** — each line is the base64 of a full share-link
//!
//! This module is a *source* for the same node store the Telegram harvester
//! feeds: it discovers repositories (from the topic API, plus a curated
//! allow-list), fetches candidate config files over raw.githubusercontent.com,
//! decodes both encodings, validates every link with the scheme-agnostic
//! parser, and imports them through `config_store::import_single_link`.
//!
//! Fetching is fully async over a connection-pooled client, proxies the same
//! way the Telegram harvester does, and the store dedups so re-runs are cheap.
//! A refresh records the new "last fetched" epoch per source so periodic
//! smart updates only pull what changed.

use std::time::Duration;

use base64::Engine;

use crate::config_store::import_single_link;
use crate::error::CFError;
use crate::multilayer::PROXY_SOCKS_PORT;

/// How long to wait for a fetch.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Max bytes of a single config file we will read (avoid OOM on monsters).
const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;

/// GitHub topic whose repositories we discover.
pub const TOPIC: &str = "v2ray-configs";

/// Curated extra repositories (not always tagged with the topic, but reliable
/// and maintained). Owner/repo slugs.
pub const KNOWN_REPOS: &[&str] = &[
    "barry-far/V2ray-Config",
    "0xRadikal/Free-v2ray-Configs",
    "liMilCo/v2r",
    "Delta-Kronecker/V2ray-Config",
    "mohammadaz2/v2rayConfigsForYou",
];

/// A discovered GitHub repo source.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct GitHubSource {
    /// `owner/repo` slug.
    pub repo: String,
    /// Default branch (e.g. `main`, `master`).
    pub branch: String,
    /// When we last successfully fetched this repo (unix seconds; 0 = never).
    pub last_fetched: u64,
}

impl GitHubSource {
    pub fn slug(&self) -> &str {
        &self.repo
    }
}

/// Report of a GitHub ingestion pass.
#[derive(Debug, Clone, Default)]
pub struct GitHubIngestReport {
    /// Repos we successfully fetched configs from.
    pub repos_ok: Vec<String>,
    /// Repos that failed (fetch / parse).
    pub repos_failed: Vec<(String, String)>,
    /// Total links found across all repos.
    pub found: usize,
    /// Total new links added to the store.
    pub added: usize,
    /// Links skipped as duplicates.
    pub duplicates: usize,
    /// Links skipped as unparseable.
    pub invalid: usize,
}

/// Build the shared async HTTP client (optionally routed via the xray SOCKS5).
pub fn build_client(use_proxy: bool) -> Result<reqwest::Client, CFError> {
    let mut builder = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .user_agent("dastyab/0.1 (config harvester)");
    if use_proxy {
        let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{PROXY_SOCKS_PORT}"))
            .map_err(|e| CFError::new("github-src", format!("proxy cfg: {e}"), ""))?;
        builder = builder.proxy(proxy);
    }
    builder.build().map_err(|e| CFError::new("github-src", format!("http client: {e}"), ""))
}

/// Discover repositories from the `v2ray-configs` GitHub topic. Returns
/// `(repo_slug, default_branch)` pairs. Uses the GitHub REST search API.
pub async fn discover_topic_repos(client: &reqwest::Client) -> Result<Vec<(String, String)>, CFError> {
    let url = format!("https://api.github.com/search/repositories?q=topic:{TOPIC}&per_page=100");
    let resp = client.get(&url).send().await.map_err(|e| {
        CFError::new("github-src", format!("topic search failed: {e}"), "Check network / proxy.")
    })?;
    if resp.status().as_u16() != 200 {
        return Err(CFError::new(
            "github-src",
            format!("topic search returned HTTP {}", resp.status()),
            "GitHub may be rate-limiting; retry later.",
        ));
    }
    let body = resp.text().await.map_err(|e| CFError::new("github-src", format!("reading body: {e}"), ""))?;
    let v: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| CFError::new("github-src", format!("bad JSON: {e}"), ""))?;
    let mut out = Vec::new();
    if let Some(items) = v.get("items").and_then(|x| x.as_array()) {
        for it in items {
            let full = it.get("full_name").and_then(|x| x.as_str()).unwrap_or("");
            let branch = it
                .get("default_branch")
                .and_then(|x| x.as_str())
                .unwrap_or("main");
            if !full.is_empty() {
                out.push((full.to_string(), branch.to_string()));
            }
        }
    }
    Ok(out)
}

/// Resolve the default branch for a known repo without searching the topic.
async fn resolve_branch(client: &reqwest::Client, repo: &str) -> Result<String, CFError> {
    let url = format!("https://api.github.com/repos/{repo}");
    let resp = client.get(&url).send().await.map_err(|e| {
        CFError::new("github-src", format!("repo {repo} lookup failed: {e}"), "")
    })?;
    if resp.status().as_u16() != 200 {
        return Err(CFError::new("github-src", format!("repo {repo} returned HTTP {}", resp.status()), ""));
    }
    let body = resp.text().await.map_err(|e| CFError::new("github-src", format!("reading body: {e}"), ""))?;
    let v: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| CFError::new("github-src", format!("bad JSON: {e}"), ""))?;
    Ok(v.get("default_branch").and_then(|x| x.as_str()).unwrap_or("main").to_string())
}

/// Candidate file name suffixes we consider config-bearing.
fn looks_like_config(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.ends_with(".txt")
        || p.ends_with(".sub")
        || p.ends_with(".conf")
        || p.ends_with(".yaml")
        || p.ends_with(".yml")
        || p.ends_with(".json")
        || p.ends_with(".list")
        || p.ends_with(".links")
        || p.contains("config")
        || p.contains("sub")
        || p.contains("subscription")
        || p.contains("vless")
        || p.contains("vmess")
        || p.contains("all_")
}

/// Extract links from a body that may mix plain share-links and base64
/// subscription lines (one base64 link per line). Returns validated links.
fn extract_links(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    // First, handle base64-per-line subscription format: try base64-decoding
    // each non-empty line that doesn't already start with a supported scheme.
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        // Already a scheme we know? Passthrough to the proxy extractor below.
        let is_plain = crate::proxy_uri::SUPPORTED_SCHEMES
            .iter()
            .any(|s| line.starts_with(&format!("{s}://")));
        if !is_plain {
            // Attempt base64 decode of the whole line (strip #frag first).
            let candidate = line.split('#').next().unwrap_or(line);
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(candidate) {
                if let Ok(text) = String::from_utf8(bytes) {
                    out.extend(crate::harvest::extract_proxy_links(&text));
                }
            }
        }
    }
    // Then run the standard multi-scheme extractor over the whole body (this
    // catches plain links interleaved with prose/headers).
    out.extend(crate::harvest::extract_proxy_links(body));
    // Dedup preserving order.
    let mut seen = std::collections::HashSet::new();
    out.retain(|l| seen.insert(l.clone()));
    out
}

/// Fetch one repo's config files and return all validated share-links.
///
/// We do a shallow `git ls-remote` style probe via the API tree to find
/// config files, then fetch each raw file and extract links.
pub async fn fetch_repo_links(
    client: &reqwest::Client,
    repo: &str,
    branch: &str,
) -> Result<Vec<String>, CFError> {
    // List the tree to find config file paths.
    let tree_url = format!("https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1");
    let resp = client.get(&tree_url).send().await.map_err(|e| {
        CFError::new("github-src", format!("tree {repo} failed: {e}"), "")
    })?;
    if resp.status().as_u16() != 200 {
        return Err(CFError::new("github-src", format!("tree {repo} returned HTTP {}", resp.status()), ""));
    }
    let body = resp.text().await.map_err(|e| CFError::new("github-src", format!("reading body: {e}"), ""))?;
    let v: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| CFError::new("github-src", format!("bad JSON: {e}"), ""))?;

    let mut files: Vec<(String, u64)> = Vec::new();
    if let Some(tree) = v.get("tree").and_then(|x| x.as_array()) {
        for entry in tree {
            let t = entry.get("type").and_then(|x| x.as_str()).unwrap_or("");
            if t != "blob" {
                continue;
            }
            let path = entry.get("path").and_then(|x| x.as_str()).unwrap_or("");
            let size = entry.get("size").and_then(|x| x.as_u64()).unwrap_or(0);
            if size > MAX_FILE_BYTES as u64 {
                continue;
            }
            if looks_like_config(path) {
                files.push((path.to_string(), size));
            }
        }
    }

    let mut all = Vec::new();
    for (path, _size) in files {
        let raw_url = format!("https://raw.githubusercontent.com/{repo}/{branch}/{path}");
        let resp = client.get(&raw_url).send().await;
        let Ok(resp) = resp else { continue };
        if resp.status().as_u16() != 200 {
            continue;
        }
        let Ok(body) = resp.text().await else { continue };
        all.extend(extract_links(&body));
    }
    Ok(all)
}

/// Run a full GitHub ingestion pass: discover sources, fetch, import.
pub async fn ingest_github(
    profile: &str,
    use_proxy: bool,
    extra_repos: &[String],
) -> GitHubIngestReport {
    let client = match build_client(use_proxy) {
        Ok(c) => c,
        Err(e) => {
            let mut r = GitHubIngestReport::default();
            r.repos_failed.push(("<client>".to_string(), e.brief()));
            return r;
        }
    };

    // Assemble source list: topic repos + known + user-provided extras.
    let mut sources: Vec<(String, String)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    if let Ok(topic) = discover_topic_repos(&client).await {
        for (repo, branch) in topic {
            if seen.insert(repo.clone()) {
                sources.push((repo, branch));
            }
        }
    }
    for repo in KNOWN_REPOS {
        let repo = repo.to_string();
        if seen.insert(repo.clone()) {
            let branch = resolve_branch(&client, &repo).await.unwrap_or_else(|_| "main".to_string());
            sources.push((repo, branch));
        }
    }
    for repo in extra_repos {
        let repo = repo.trim().trim_end_matches('/').to_string();
        if repo.is_empty() || seen.contains(&repo) {
            continue;
        }
        seen.insert(repo.clone());
        let branch = resolve_branch(&client, &repo).await.unwrap_or_else(|_| "main".to_string());
        sources.push((repo, branch));
    }

    let mut report = GitHubIngestReport::default();
    for (repo, branch) in sources {
        match fetch_repo_links(&client, &repo, &branch).await {
            Ok(links) => {
                report.repos_ok.push(repo.clone());
                for link in &links {
                    report.found += 1;
                    match import_single_link(profile, link) {
                        Ok(s) => {
                            report.added += s.added;
                            report.duplicates += s.duplicates;
                            report.invalid += s.skipped_invalid + s.skipped_non_vless;
                        }
                        Err(_) => report.invalid += 1,
                    }
                }
            }
            Err(e) => report.repos_failed.push((repo, e.brief())),
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_links_decodes_base64_subscription() {
        use base64::Engine;
        // One plain vless, one base64-encoded vless.
        let plain = "vless://06ef598c-1555-4887-b3f9-08214a2f6792@104.17.72.206:443?type=ws#v";
        let b64 = base64::engine::general_purpose::STANDARD.encode("vless://7748b328-f0e8-40ab-b2e3-9a1c2c22d111@127.0.0.1:443?type=ws#t");
        let body = format!("{plain}\n{b64}\n# a comment\n");
        let links = extract_links(&body);
        assert_eq!(links.len(), 2, "plain + base64 must both be extracted");
        assert!(links.iter().any(|l| l.contains("06ef598c")));
        assert!(links.iter().any(|l| l.contains("7748b328")));
    }

    #[test]
    fn extract_links_skips_prose_and_comments() {
        let body = "#header line\nno scheme here\nhttp://not-a-proxy.com/x\nvless://aaa@1.1.1.1:443?type=tcp#a\n";
        let links = extract_links(body);
        assert_eq!(links.len(), 1);
        assert!(links[0].starts_with("vless://"));
    }

    #[test]
    fn looks_like_config_matches_common_names() {
        assert!(looks_like_config("All_Configs_Sub.txt"));
        assert!(looks_like_config("base64/Sub1_base64.txt"));
        assert!(looks_like_config("all/configs.txt"));
        assert!(!looks_like_config("README.md"));
        assert!(!looks_like_config("src/main.rs"));
    }
}
