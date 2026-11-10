//! Cached view-model state for the GUI.
//!
//! The GUI reads the disk store through small summary structs so the render
//! loop never holds a store lock across egui calls (DeepSeek Phase 3.2/3.3
//! requirement). [`GuiState::reload`] is the one call that re-reads the
//! active profile, its tokens, and the full profile list.

use dastyab_core::store::profiles::{
    get_active_profile, get_active_token, list_profiles, load_profile,
};

/// One row in the profile sidebar.
#[derive(Debug, Clone)]
pub struct ProfileSummary {
    pub id: String,
    pub name: String,
    pub is_active: bool,
    pub token_count: u32,
    /// When the profile was created (ISO string).
    pub created_at: String,
    /// Optional user description.
    pub description: String,
}

/// One row in the token view.
#[derive(Debug, Clone)]
pub struct TokenSummary {
    pub label: String,
    /// Masked form of the token for display (never the raw secret).
    pub masked: String,
    /// Human-friendly timestamp (relative when recent, else the raw time).
    pub added_at: String,
    /// Absolute local timestamp (`YYYY-MM-DD HH:MM:SS`) of when it was added.
    pub added_at_abs: String,
    /// Whether this token is the profile's active token.
    pub is_active: bool,
}

/// One entry in the token-lifecycle ledger (adds/removes/active/verify).
#[derive(Debug, Clone)]
pub struct TokenLedgerRow {
    pub kind: String,
    pub label: String,
    pub note: String,
    pub epoch: i64,
}

/// Cached snapshot of what the sidebar + token view need to render.
#[derive(Debug, Clone, Default)]
pub struct GuiState {
    pub profiles: Vec<ProfileSummary>,
    pub active_profile_id: String,
    pub tokens: Vec<TokenSummary>,
    /// Label of the profile's active token (for deploy/scan + stroke).
    pub active_token_label: Option<String>,
    /// Saved clean IPs for the active profile (cached for fast rendering).
    pub clean_ips: Vec<String>,
    /// Per-endpoint provenance metadata for the active profile.
    pub clean_ip_meta: std::collections::BTreeMap<String, String>,
    /// Manual known-good seed endpoints (imported, not yet verified).
    pub seeds: Vec<String>,
    /// Token-lifecycle ledger (newest first).
    pub token_ledger: Vec<TokenLedgerRow>,
    /// Saved config snapshots (backup bundles) for the Saved Configs manager.
    pub backups: Vec<dastyab_core::backup::BackupRecord>,
    /// Number of undelivered beacon alerts (outbox) for the active profile.
    pub beacon_outbox: usize,
    /// Set when a background mutation completes; the next frame calls reload.
    pub reload_pending: bool,
}

impl GuiState {
    /// Re-read the active profile, its tokens, and the profile list.
    pub fn reload(&mut self) {
        self.profiles = list_profiles()
            .into_iter()
            .map(|m| ProfileSummary {
                id: m.id.clone(),
                name: m.name,
                is_active: false,
                token_count: 0,
                created_at: m.created_at,
                description: m.description,
            })
            .collect();

        self.active_profile_id = get_active_profile();

        // mark the active one and fill token counts
        let active = self.active_profile_id.clone();
        for p in &mut self.profiles {
            p.is_active = p.id == active;
            p.token_count = load_profile(&p.id).tokens.len() as u32;
        }

        let prof = load_profile(&active);
        let active_token = get_active_token(&active).unwrap_or(None);
        self.tokens = prof
            .tokens
            .iter()
            .map(|(label, e)| TokenSummary {
                label: label.clone(),
                masked: mask_token(&e.token),
                added_at: relative_time(&e.ts),
                added_at_abs: e.ts.clone(),
                is_active: active_token.as_deref() == Some(label.as_str()),
            })
            .collect();

        self.active_token_label = active_token;

        self.clean_ips = prof.clean_ips.clone();
        self.clean_ip_meta = prof
            .clean_ip_meta
            .iter()
            .map(|(k, m)| {
                let port = if m.port == 443 {
                    String::new()
                } else {
                    format!(":{}", m.port)
                };
                (k.clone(), format!("{}{port}", m.source))
            })
            .collect();

        self.seeds = dastyab_core::cf::ips::load_manual_seeds(&active);
        self.token_ledger = prof
            .token_history
            .iter()
            .map(|e| TokenLedgerRow {
                kind: e.kind.clone(),
                label: e.label.clone(),
                note: e.note.clone(),
                epoch: e.epoch as i64,
            })
            .collect();

        self.beacon_outbox = dastyab_core::remote_beacon::load_outbox(&active).len();
        self.backups = dastyab_core::backup::list_backups();

        self.reload_pending = false;
    }

    /// The count of the currently active profile (0 when none).
    pub fn _active_token_count(&self) -> u32 {
        self.profiles
            .iter()
            .find(|p| p.is_active)
            .map(|p| p.token_count)
            .unwrap_or(0)
    }
}

/// Mask a token for display: first 4 + last 4 chars, or `****` when shorter
/// than 8 characters.
pub fn mask_token(token: &str) -> String {
    let t = token.trim();
    if t.len() < 8 {
        return "****".to_string();
    }
    let prefix = &t[..4];
    let suffix = &t[t.len().saturating_sub(4)..];
    format!("{prefix}…{suffix}")
}

/// Format a `%Y-%m-%d %H:%M:%S` timestamp as a short relative string, falling
/// back to the raw string when it cannot be parsed.
pub fn relative_time(ts: &str) -> String {
    let Ok(dt) = chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S") else {
        return ts.to_string();
    };
    let now = chrono::Local::now().naive_local();
    let secs = (now - dt).num_seconds().max(0);
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else if secs < 86400 * 30 {
        format!("{}d ago", secs / 86400)
    } else {
        ts.to_string()
    }
}

/// Format a UNIX-epoch seconds value as a readable local timestamp
/// (`YYYY-MM-DD HH:MM`), falling back to the raw integer when it cannot be
/// converted.
pub fn format_ts(epoch: i64) -> String {
    match chrono::DateTime::from_timestamp(epoch, 0) {
        Some(dt) => dt
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M")
            .to_string(),
        None => format!("{epoch}"),
    }
}

/// Format a UNIX-epoch seconds value as a short relative string ("3d ago",
/// "2h ago", "just now"), falling back to [`format_ts`] for very old events.
pub fn relative_ts(epoch: i64) -> String {
    let Some(dt) = chrono::DateTime::from_timestamp(epoch, 0) else {
        return format!("{epoch}");
    };
    let now = chrono::Local::now().naive_local();
    let dt = dt.with_timezone(&chrono::Local).naive_local();
    let secs = (now - dt).num_seconds().max(0);
    match secs {
        0..=59 => "just now".to_string(),
        60..=3599 => format!("{}m ago", secs / 60),
        3600..=86399 => format!("{}h ago", secs / 3600),
        86400..=2591999 => format!("{}d ago", secs / 86400),
        _ => format_ts(epoch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_home(f: impl FnOnce()) {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join(".dastyab");
        dastyab_core::store::set_mem_dir_override(base);
        f();
    }

    #[test]
    fn mask_token_produces_prefix_and_suffix() {
        assert_eq!(mask_token("cf_live_token_abc"), "cf_l…_abc");
    }

    #[test]
    fn mask_short_token_fully() {
        assert_eq!(mask_token("ab"), "****");
        assert_eq!(mask_token("1234567"), "****"); // 7 chars < 8
    }

    #[test]
    fn mask_trimmed_input() {
        assert_eq!(mask_token("  cf_live_token_abc  "), "cf_l…_abc");
    }

    #[test]
    fn format_ts_renders_local_timestamp() {
        // 2024-01-15 12:30:00 UTC. Local rendering is timezone-dependent, so
        // just assert we get a "YYYY-MM-DD HH:MM" shape, not the raw int.
        let out = format_ts(1_705_322_600);
        assert_ne!(out, "1705322600");
        assert!(out.len() >= 13, "unexpected output: {out}");
    }

    #[test]
    fn relative_ts_recent_and_old() {
        let now = chrono::Local::now().timestamp();
        // 30s ago -> "just now"
        assert_eq!(relative_ts(now - 30), "just now");
        // 2 days ago (172800s) -> "2d ago"
        assert_eq!(relative_ts(now - 172_800), "2d ago");
        // 3 hours ago -> "3h ago"
        assert_eq!(relative_ts(now - 10_800), "3h ago");
        // far in the past -> absolute timestamp
        let ancient = relative_ts(1_000_000);
        assert_ne!(ancient, "just now");
        assert!(ancient.len() >= 13, "unexpected output: {ancient}");
    }

    #[test]
    fn reload_reflects_active_profile_and_tokens() {
        with_home(|| {
            use dastyab_core::store::ensure_mem_dir;
            use dastyab_core::store::profiles::{
                add_token, create_profile, set_active_profile, set_active_token,
            };
            ensure_mem_dir().unwrap();
            let id = create_profile("work", "").unwrap();
            // activate the profile, add token + reload
            set_active_profile(&id).unwrap();
            add_token(&id, "cf-main", "a-very-long-secret-value-here").unwrap();
            set_active_token(&id, "cf-main").unwrap();

            let mut st = GuiState::default();
            st.reload();

            assert_eq!(st.active_profile_id, id);
            assert_eq!(st.active_token_label.as_deref(), Some("cf-main"));
            assert!(st.profiles.iter().any(|p| p.is_active && p.id == id));
            let p = st.profiles.iter().find(|p| p.id == id).unwrap();
            assert_eq!(p.token_count, 1);
            assert_eq!(st.tokens.len(), 1);
            assert_eq!(st.tokens[0].label, "cf-main");
            assert!(st.tokens[0].masked.ends_with("here"));
        });
    }

    #[test]
    fn reload_pending_clears_after_reload() {
        let mut st = GuiState {
            reload_pending: true,
            ..Default::default()
        };
        st.reload();
        assert!(!st.reload_pending);
    }

    #[test]
    fn full_profile_crud_flow() {
        // Mirrors the Phase 3.2/3.3 acceptance checks:
        // create -> set active -> add token -> reload sees masked token ->
        // rename -> delete.
        with_home(|| {
            use dastyab_core::store::ensure_mem_dir;
            use dastyab_core::store::profiles::{
                create_profile, delete_profile, rename_profile, set_active_profile,
            };
            ensure_mem_dir().unwrap();

            // create
            let id = create_profile("test-profile", "").unwrap();
            assert!(!id.is_empty());

            // set active + persist
            set_active_profile(&id).unwrap();
            assert_eq!(get_active_profile(), id);

            // add token + reload
            dastyab_core::store::profiles::add_token(&id, "primary", "cf_live_token_abcdefgh")
                .unwrap();
            let mut st = GuiState::default();
            st.reload();
            assert_eq!(st.active_profile_id, id);
            assert_eq!(st.tokens.len(), 1);
            assert_eq!(st.tokens[0].masked, "cf_l…efgh");

            // rename + delete
            rename_profile(&id, "renamed-profile").unwrap();
            assert_eq!(load_profile(&id).meta.name, "renamed-profile");
            delete_profile(&id).unwrap();
            assert!(!dastyab_core::store::profiles::profile_dir(&id).exists());
        });
    }
}
