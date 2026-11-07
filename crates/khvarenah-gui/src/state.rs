//! Cached view-model state for the GUI.
//!
//! The GUI reads the disk store through small summary structs so the render
//! loop never holds a store lock across egui calls (DeepSeek Phase 3.2/3.3
//! requirement). [`GuiState::reload`] is the one call that re-reads the
//! active profile, its tokens, and the full profile list.

use khvarenah_core::store::profiles::{
    get_active_profile, list_profiles, load_profile,
};

/// One row in the profile sidebar.
#[derive(Debug, Clone)]
pub struct ProfileSummary {
    pub id: String,
    pub name: String,
    pub is_active: bool,
    pub token_count: u32,
}

/// One row in the token view.
#[derive(Debug, Clone)]
pub struct TokenSummary {
    pub label: String,
    /// Masked form of the token for display (never the raw secret).
    pub masked: String,
    /// Human-friendly timestamp (relative when recent, else the raw time).
    pub added_at: String,
}

/// Cached snapshot of what the sidebar + token view need to render.
#[derive(Debug, Clone, Default)]
pub struct GuiState {
    pub profiles: Vec<ProfileSummary>,
    pub active_profile_id: String,
    pub tokens: Vec<TokenSummary>,
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
        self.tokens = prof
            .tokens
            .iter()
            .map(|(label, e)| TokenSummary {
                label: label.clone(),
                masked: mask_token(&e.token),
                added_at: relative_time(&e.ts),
            })
            .collect();

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
    let Ok(dt) = chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S")
    else {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn with_home(f: impl FnOnce()) {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join(".khvarenah");
        khvarenah_core::store::set_mem_dir_override(base);
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
    fn reload_reflects_active_profile_and_tokens() {
        with_home(|| {
            use khvarenah_core::store::profiles::{
                add_token, create_profile, set_active_profile,
            };
            use khvarenah_core::store::ensure_mem_dir;
            ensure_mem_dir().unwrap();
            let id = create_profile("work", "").unwrap();
            set_active_profile(&id).unwrap();
            add_token(&id, "cf-main", "a-very-long-secret-value-here").unwrap();

            let mut st = GuiState::default();
            st.reload();

            assert_eq!(st.active_profile_id, id);
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
            use khvarenah_core::store::profiles::{
                delete_profile, rename_profile, create_profile, set_active_profile,
            };
            use khvarenah_core::store::ensure_mem_dir;
            ensure_mem_dir().unwrap();

            // create
            let id = create_profile("test-profile", "").unwrap();
            assert!(!id.is_empty());

            // set active + persist
            set_active_profile(&id).unwrap();
            assert_eq!(get_active_profile(), id);

            // add token + reload
            khvarenah_core::store::profiles::add_token(
                &id,
                "primary",
                "cf_live_token_abcdefgh",
            )
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
            assert!(!khvarenah_core::store::profiles::profile_dir(&id).exists());
        });
    }
}
