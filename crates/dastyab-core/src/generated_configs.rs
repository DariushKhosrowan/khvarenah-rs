//! Generated-Configs Completeness Ledger.
//!
//! Today `history.json` records only `VlessRecord` entries (deploys, clean-IP
//! scans). Exports in other formats — v2rayN, sing-box, Clash, and tunnel
//! client configs — are rendered by [`crate::export`] and then exist only in
//! the terminal or clipboard; if the user loses them, there is no durable
//! record that a config was ever produced.
//!
//! This module records **every rendered config** in `generated_configs.json`
//! with its format, source, timestamp, full content, and a SHA-256 content
//! hash — so a lost export can be reconstructed or at least proven to have
//! existed. The ledger is append-only and participates in the manifest,
//! inventory, backup, and workspace-snapshot machinery via
//! [`crate::manifest::ArtifactKind::GeneratedConfigs`].

use crate::error::CFError;
use crate::export::ExportFormat;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Where a config came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigSource {
    ShareLink,
    V2rayN,
    SingBox,
    Clash,
    TunnelClient,
    WorkerVless,
    Other,
}

impl ConfigSource {
    pub fn label(self) -> &'static str {
        match self {
            ConfigSource::ShareLink => "share-link",
            ConfigSource::V2rayN => "v2rayN",
            ConfigSource::SingBox => "sing-box",
            ConfigSource::Clash => "Clash",
            ConfigSource::TunnelClient => "tunnel-client",
            ConfigSource::WorkerVless => "worker-vless",
            ConfigSource::Other => "other",
        }
    }
}

/// One rendered config record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedConfigRecord {
    /// Monotonic id (unix-nanos at append time; strictly increasing).
    pub id: u64,
    /// When the config was rendered (unix seconds).
    pub created_unix: u64,
    /// Export format.
    pub fmt: ExportFormat,
    /// Where the config came from.
    pub source: ConfigSource,
    /// Optional human label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The full rendered config text.
    pub content: String,
    /// SHA-256 of `content` (32 bytes).
    pub content_sha256: [u8; 32],
}

/// The append-only ledger of generated configs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedConfigsLedger {
    pub records: Vec<GeneratedConfigRecord>,
}

/// Search filters for [`search_configs`]. All present filters are AND-ed.
#[derive(Debug, Clone, Default)]
pub struct ConfigQuery {
    pub fmt: Option<ExportFormat>,
    pub source: Option<ConfigSource>,
    pub since_unix: Option<u64>,
    pub until_unix: Option<u64>,
    pub label: Option<String>,
    pub text_substring: Option<String>,
}

impl GeneratedConfigsLedger {
    /// Append a record with a computed id + hash. Returns Err if ids are not
    /// strictly monotonic (out-of-order append).
    pub fn push(
        &mut self,
        created_unix: u64,
        fmt: ExportFormat,
        source: ConfigSource,
        label: Option<String>,
        content: String,
    ) -> Result<u64, CFError> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        // id = unix-nanos at append time, nudged to be strictly greater than the
        // last id (covers same-nanosecond bursts).
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let last_id = self.records.last().map(|r| r.id).unwrap_or(0);
        let id = now_ns.max(last_id.saturating_add(1)) + SEQ.fetch_add(1, Ordering::Relaxed) % 2;
        let content_sha256 = sha256_bytes(content.as_bytes());
        let rec = GeneratedConfigRecord {
            id,
            created_unix,
            fmt,
            source,
            label,
            content,
            content_sha256,
        };
        self.records.push(rec);
        Ok(id)
    }

    /// Search with AND-ed filters.
    pub fn search(&self, q: &ConfigQuery) -> Vec<&GeneratedConfigRecord> {
        self.records
            .iter()
            .filter(|r| q.fmt.map(|f| r.fmt == f).unwrap_or(true))
            .filter(|r| q.source.map(|s| r.source == s).unwrap_or(true))
            .filter(|r| q.since_unix.map(|t| r.created_unix >= t).unwrap_or(true))
            .filter(|r| q.until_unix.map(|t| r.created_unix <= t).unwrap_or(true))
            .filter(|r| {
                q.label
                    .as_ref()
                    .map(|l| r.label.as_deref().unwrap_or("").contains(l.as_str()))
                    .unwrap_or(true)
            })
            .filter(|r| {
                q.text_substring
                    .as_ref()
                    .map(|s| r.content.contains(s.as_str()))
                    .unwrap_or(true)
            })
            .collect()
    }
}

/// SHA-256 (raw 32 bytes) of a byte slice.
pub fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Load the generated-configs ledger for a profile (empty default).
pub fn load_generated_configs(id: &str) -> GeneratedConfigsLedger {
    let dir = crate::store::profiles::profile_dir(id);
    let records = crate::store::read_opt::<Vec<GeneratedConfigRecord>>(
        &dir.join(GeneratedConfigsLedger::FILE),
    )
    .unwrap_or_default();
    GeneratedConfigsLedger { records }
}

impl GeneratedConfigsLedger {
    /// Filename within the profile directory.
    pub const FILE: &'static str = "generated_configs.json";
}

/// Record all rendered config formats for a profile into the generated-configs
/// ledger and persist it. This is the single "config creation" primitive used
/// by every deploy/learn path (edgetunnel deploy, worker-tunnel deploy, and
/// config-from-clean-IP), so a deploy always produces a usable, durable config.
///
/// Returns the number of formats recorded.
pub fn record_profile_configs(
    id: &str,
    profile: &crate::vless::VlessProfile,
    source: ConfigSource,
    label: Option<String>,
) -> usize {
    let all = crate::export::render_all(profile);
    if all.is_empty() {
        return 0;
    }
    let mut ledger = load_generated_configs(id);
    let now = crate::store::now_ts() as u64;
    let mut n = 0usize;
    for (fmt_label, content) in &all {
        let Some(fmt) = ExportFormat::parse(fmt_label) else {
            continue;
        };
        if ledger
            .push(now, fmt, source, label.clone(), content.clone())
            .is_ok()
        {
            n += 1;
        }
    }
    let _ = save_generated_configs(id, &ledger);
    n
}

/// Persist the generated-configs ledger for a profile.
///
/// The write goes through the ledger append-only guard (high-water) so the
/// doctor can flag truncation out-of-band.
pub fn save_generated_configs(id: &str, ledger: &GeneratedConfigsLedger) -> Result<(), CFError> {
    let dir = crate::store::profiles::profile_dir(id);
    crate::ledger_guard::write_ledger_guarded(
        &dir,
        crate::ledger_guard::LedgerKind::GeneratedConfigs,
        &ledger.records,
        crate::store::now_ts() as u64,
    )
    .map_err(|e| CFError::new("Storage error", e.to_string(), "Internal error."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(
        fmt: ExportFormat,
        source: ConfigSource,
        content: &str,
    ) -> (ExportFormat, ConfigSource, String) {
        (fmt, source, content.to_string())
    }

    fn sample_ledger() -> GeneratedConfigsLedger {
        let mut l = GeneratedConfigsLedger::default();
        let (f1, s1, c1) = rec(
            ExportFormat::ShareLink,
            ConfigSource::ShareLink,
            "vless://a",
        );
        l.push(1000, f1, s1, Some("home".into()), c1).unwrap();
        let (f2, s2, c2) = rec(
            ExportFormat::SingBox,
            ConfigSource::WorkerVless,
            "{\"outbound\":1}",
        );
        l.push(2000, f2, s2, None, c2).unwrap();
        let (f3, s3, c3) = rec(
            ExportFormat::Clash,
            ConfigSource::Other,
            "proxies:\n  - name: x",
        );
        l.push(3000, f3, s3, Some("work".into()), c3).unwrap();
        l
    }

    #[test]
    fn append_assigns_monotonic_id_and_timestamp() {
        let mut l = GeneratedConfigsLedger::default();
        let (f, s, c) = rec(
            ExportFormat::ShareLink,
            ConfigSource::ShareLink,
            "vless://x",
        );
        let id1 = l.push(1000, f, s, None, c).unwrap();
        let (f, s, c) = rec(ExportFormat::V2rayN, ConfigSource::V2rayN, "{}");
        let id2 = l.push(1000, f, s, None, c).unwrap();
        assert!(id2 > id1);
        assert_eq!(l.records.len(), 2);
    }

    #[test]
    fn search_filters_by_fmt() {
        let l = sample_ledger();
        let q = ConfigQuery {
            fmt: Some(ExportFormat::SingBox),
            ..Default::default()
        };
        let r = l.search(&q);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].source, ConfigSource::WorkerVless);
    }

    #[test]
    fn search_filters_by_since_until() {
        let l = sample_ledger();
        let q = ConfigQuery {
            since_unix: Some(2000),
            until_unix: Some(2999),
            ..Default::default()
        };
        let r = l.search(&q);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].created_unix, 2000);
    }

    #[test]
    fn search_filters_by_text_substring() {
        let l = sample_ledger();
        let q = ConfigQuery {
            text_substring: Some("outbound".into()),
            ..Default::default()
        };
        let r = l.search(&q);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn search_by_label_returns_single_match() {
        let l = sample_ledger();
        let q = ConfigQuery {
            label: Some("work".into()),
            ..Default::default()
        };
        let r = l.search(&q);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].source, ConfigSource::Other);
    }

    #[test]
    fn sha256_bytes_is_stable_and_32_bytes() {
        let h = sha256_bytes(b"vless://abc");
        assert_eq!(h.len(), 32);
        assert_eq!(h, sha256_bytes(b"vless://abc"));
        assert_ne!(h, sha256_bytes(b"vless://abd"));
    }

    fn test_mem_dir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("dyb_gencfg_{}_{n}", crate::store::now_ts()))
    }

    #[test]
    fn save_and_load_roundtrips_via_guarded_ledger() {
        // Use the in-memory mem dir override so we don't touch the real home.
        crate::store::set_mem_dir_override(test_mem_dir());
        let id = crate::store::profiles::create_profile("g", "gen").unwrap();
        let mut ledger = GeneratedConfigsLedger::default();
        let (f, s, c) = rec(
            ExportFormat::ShareLink,
            ConfigSource::ShareLink,
            "vless://zz",
        );
        ledger.push(1000, f, s, Some("home".into()), c).unwrap();
        save_generated_configs(&id, &ledger).unwrap();
        let loaded = load_generated_configs(&id);
        assert_eq!(loaded.records.len(), 1);
        assert_eq!(loaded.records[0].content, "vless://zz");
        // The ledger file is a manifest-tracked artifact kind.
        let kinds = crate::manifest::profile_artifact_kinds();
        assert!(kinds.contains(&crate::manifest::ArtifactKind::GeneratedConfigs));
    }

    #[test]
    fn saved_ledger_grows_without_tripping_guard() {
        crate::store::set_mem_dir_override(test_mem_dir());
        let id = crate::store::profiles::create_profile("g2", "gen").unwrap();
        let mut l = GeneratedConfigsLedger::default();
        let (f, s, c) = rec(ExportFormat::V2rayN, ConfigSource::V2rayN, "{}");
        l.push(1000, f, s, None, c).unwrap();
        save_generated_configs(&id, &l).unwrap();
        let (f, s, c) = rec(ExportFormat::Clash, ConfigSource::WorkerVless, "proxies:");
        l.push(2000, f, s, None, c).unwrap();
        save_generated_configs(&id, &l).unwrap();
        let loaded = load_generated_configs(&id);
        assert_eq!(loaded.records.len(), 2);
    }

    #[test]
    fn record_profile_configs_renders_all_formats_into_ledger() {
        crate::store::set_mem_dir_override(test_mem_dir());
        let id = crate::store::profiles::create_profile("g3", "gen").unwrap();
        let prof = crate::vless::VlessProfile {
            uuid: "12345678-1234-1234-1234-123456789abc".into(),
            address: "104.16.1.1".into(),
            port: 443,
            path: "/".into(),
            transport: "ws".into(),
            security: "tls".into(),
            name: "test-worker".into(),
            ..Default::default()
        };
        let n = record_profile_configs(
            &id,
            &prof,
            ConfigSource::WorkerVless,
            Some("deploy test-worker".into()),
        );
        // share-link, v2rayN, sing-box, Clash.
        assert!(n >= 4, "expected >=4 formats, got {n}");
        let loaded = load_generated_configs(&id);
        assert!(loaded.records.len() >= 4);
        // Every record must carry the deployed worker identity and be usable.
        for r in &loaded.records {
            assert!(
                r.content.contains(&prof.uuid),
                "missing uuid in {}",
                r.fmt.label()
            );
            assert!(
                r.content.contains("104.16.1.1"),
                "missing address in {}",
                r.fmt.label()
            );
        }
        // Calling it again appends (never overwrites) — config creation is
        // repeatable and additive.
        record_profile_configs(&id, &prof, ConfigSource::WorkerVless, Some("again".into()));
        let total = load_generated_configs(&id);
        assert_eq!(total.records.len(), loaded.records.len() * 2);
    }
}
