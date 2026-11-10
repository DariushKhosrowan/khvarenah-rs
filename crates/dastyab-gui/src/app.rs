//! DastYab GUI application state and rendering.
//!
//! Modern royal-gold-on-black design. Three tabs:
//! * Deploy — deploy worker, scan clean IPs, export share links.
//! * Profiles — list/create/switch profiles, manage tokens & settings.
//! * Tools — security audit, backup/restore, client-format export.

use eframe::egui;
use dastyab_core::scanner::{scan_many, scan_once, ScanParams};
use dastyab_core::store::profiles::{
    add_token, create_profile, delete_profile, list_profiles, load_profile, remember_clean_ip,
    remember_vless, rename_profile, save_config, set_active_profile, ProfileConfig, VlessRecord,
};
use dastyab_core::vless::VlessProfile;
use dastyab_core::worker::generate_uuid;
use dastyab_core::CFError;

use crate::bridge;
use crate::dialogs::{self, Dialog, DialogPayload, DialogResult};
use crate::state::GuiState;
use crate::views::{cleanip, configs, history, profiles, tokens};

// Royal-gold palette (dark #0a0705 bg per shell spec)
pub const GOLD: egui::Color32 = egui::Color32::from_rgb(212, 175, 55);
pub const GOLD_DIM: egui::Color32 = egui::Color32::from_rgb(150, 120, 40);
pub const DARK: egui::Color32 = egui::Color32::from_rgb(10, 7, 5); // #0a0705
pub const PANEL: egui::Color32 = egui::Color32::from_rgb(24, 20, 14);
pub const TEXT: egui::Color32 = egui::Color32::from_rgb(235, 228, 200);
/// Card surface — slightly lighter than the base panel for elevation.
pub const CARD: egui::Color32 = egui::Color32::from_rgb(30, 26, 18);
/// Subtle border used on cards.
pub const CARD_STROKE: egui::Color32 = egui::Color32::from_rgb(52, 44, 30);

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Dashboard,
    DeployScan,
    Profiles,
    Tokens,
    CleanIps,
    History,
    Configs,
    Log,
    Tools,
    Settings,
    Autonomy,
}

impl View {
    /// The eleven-item sidebar, in order.
    const ALL: [View; 11] = [
        View::Dashboard,
        View::DeployScan,
        View::Profiles,
        View::Tokens,
        View::CleanIps,
        View::History,
        View::Configs,
        View::Log,
        View::Tools,
        View::Settings,
        View::Autonomy,
    ];

    fn label(self) -> &'static str {
        match self {
            View::Dashboard => "Dashboard",
            View::DeployScan => "Deploy & Scan",
            View::Profiles => "Profiles",
            View::Tokens => "Tokens",
            View::CleanIps => "Clean IPs",
            View::History => "History",
            View::Configs => "Configs",
            View::Log => "Log",
            View::Tools => "Tools",
            View::Settings => "Settings",
            View::Autonomy => "Autonomy",
        }
    }

    /// A short glyph shown before the label in the sidebar (and in the top
    /// heading), so the navigation reads at a glance.
    fn glyph(self) -> &'static str {
        match self {
            View::Dashboard => "📊",
            View::DeployScan => "🛰",
            View::Profiles => "📁",
            View::Tokens => "🔑",
            View::CleanIps => "🌐",
            View::History => "🕘",
            View::Configs => "📄",
            View::Log => "📜",
            View::Tools => "🧰",
            View::Settings => "⚙",
            View::Autonomy => "🤖",
        }
    }
}

/// How the Saved Configs manager sorts its snapshot list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BackupSort {
    /// Newest snapshot first.
    #[default]
    Newest,
    /// Oldest snapshot first.
    Oldest,
    /// Alphabetical by profile name.
    Name,
    /// Largest bundle first.
    Size,
}

impl BackupSort {
    pub fn label(self) -> &'static str {
        match self {
            BackupSort::Newest => "newest",
            BackupSort::Oldest => "oldest",
            BackupSort::Name => "name",
            BackupSort::Size => "size",
        }
    }
}

/// Which streams the History view shows.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum HistoryFilter {
    #[default]
    All,
    Deploys,
    CleanIps,
    Journal,
    Tokens,
}

pub struct DastYabApp {
    pub profile_id: String,
    pub profiles: Vec<String>,
    pub note: String,
    /// The most recent background-task error (if any), shown as a red banner.
    error_banner: Option<String>,
    view: View,
    // async bridge
    pub tx: bridge::Tx,
    rx: bridge::Rx,
    running: Vec<String>,   // task names currently in flight
    log_lines: Vec<String>, // live log pane (capped at 5000)
    // view-model cache (Phase 3.2/3.3)
    pub state: GuiState,
    /// Which streams the History view shows.
    pub history_filter: HistoryFilter,
    /// Currently open modal dialog (if any).
    pub dialog: Option<Dialog>,
    /// The action a dialog submit should take.
    pub pending_action: Option<PendingDialogAction>,
    /// Which sidebar profile row is selected (for rename/delete).
    pub selected_profile: Option<usize>,
    /// Live search filter for the Clean IPs manager.
    pub cleanip_search: String,
    /// Sort mode for the Clean IPs list.
    pub cleanip_sort: crate::views::cleanip::CleanipSort,
    /// Live search filter for the Saved Configs manager.
    pub backups_search: String,
    /// Sort mode for the Saved Configs manager.
    pub backup_sort: BackupSort,
    /// Live search filter for the generated-configs manager.
    pub configs_search: String,
    /// Format filter for the generated-configs manager (empty = all).
    pub configs_fmt_filter: String,
    /// Sort order for the generated-configs manager.
    pub configs_sort: crate::views::configs::ConfigsSort,
    /// Kind filter for the token-history ledger (empty = all).
    pub token_history_filter: String,
    /// Auto-scroll the Log view to the newest line.
    pub log_auto_scroll: bool,
    // inputs
    pub new_profile_name: String,
    // scan params
    pub scan_count: u32,
    pub scan_workers: u32,
    pub scan_timeout: u32,
    pub scan_ports: String,
    pub scan_gentle: bool,
    pub stealth_enabled: bool,
    // results
    pub last_link: String,
    // autopilot
    pub autopilot_on: bool,
    pub autopilot_status: String,
    pub autopilot_stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    // zero-result diagnostics (plain-language explanation)
    pub last_cause: Option<String>,
    pub last_action_label: String,
    // tools
    pub audit_output: String,
    pub backup_output: String,
    pub export_output: String,
    // remote notifications config
    pub beacon_enabled: bool,
    pub beacon_channel: String,
    pub beacon_token: String,
    pub beacon_target: String,
    pub beacon_rate_limit: i64,
    pub beacon_note: String,
    // failover channel (secondary alert delivery path when primary is blocked)
    pub beacon_failover_enabled: bool,
    pub beacon_failover_channel: String,
    pub beacon_failover_token: String,
    pub beacon_failover_target: String,
    // blackout resilience / VPS DNS-tunnel config
    pub vps_host: String,
    pub vps_user: String,
    pub vps_key: String,
    pub vps_port: u16,
    pub vps_domain: String,
    pub vps_note: String,
    /// Worker-hosted DNS tunnel (no VPS) note/status line.
    pub worker_tunnel_note: String,
    // zero-touch Hetzner VPS provisioning config
    pub hz_token: String,
    pub hz_location: String,
    pub hz_server_type: String,
    // multi-worker parallel redundancy config
    pub mw_count: usize,
    pub mw_note: String,
    // anti-DPI TCP desync fragmenter config
    pub desync_enabled: bool,
    pub desync_min: usize,
    pub desync_max: usize,
    pub desync_delay_us: u64,
    pub desync_note: String,
    // blackout drill output (self-test of the fallback ladder)
    pub drill_output: String,
    // protection daemon control
    pub daemon_note: String,
    // blackout-resilience pacing (per-profile, 0 = system default)
    pub light_timeout_s: u64,
    pub deep_timeout_s: u64,
    pub max_backoff_s: u64,
    pub network_down_sleep_s: u64,
    /// Monitor light-check cadence (seconds between light WS-gate checks).
    /// 0 = system default (`default_light_interval`, 300).
    pub light_check_interval_s: u64,
    /// Scheduled blackout self-test (drill) cadence (seconds). 0 = system
    /// default (24h). The daemon runs a drill this often when the network is up.
    pub drill_interval_s: u64,
    pub timeouts_note: String,
    // automatic token rotation on account-blocked (default on)
    pub auto_rotate_enabled: bool,
    pub auto_rotate_note: String,
    // scheduled auto-backup (dormant → now wired into the daemon)
    pub backup_auto_enabled: bool,
    pub backup_auto_interval: u64,
    pub backup_auto_keep: usize,
    pub backup_auto_note: String,
    // scheduled worker-signature rotation (dormant → now wired into daemon)
    pub mutation_enabled: bool,
    pub mutation_interval: u64,
    pub mutation_rotate_path: bool,
    pub mutation_note: String,
    // live search filters (tokens / history)
    pub token_search: String,
    pub history_search: String,
    // settings section open state (true = expanded)
    pub sec_backups: bool,
    // clean-IP manager probe output + manual-add draft
    pub cleanip_test_output: String,
    pub cleanip_add_draft: String,
    // token-history ledger search filter
    pub token_history_search: String,
}

/// What to do when the open dialog submits.
#[derive(Debug, Clone)]
pub enum PendingDialogAction {
    CreateProfile,
    RenameProfile(String),
    DescribeProfile(String),
    DeleteProfile(String),
    AddToken,
    ImportSeeds,
    ClearCleanIps,
    ClearHistory,
    DeleteHistoryRecord(String),
    ClearTokenHistory,
    /// Clone a profile into a fresh one (dialog supplies the new name).
    CloneProfile(String),
    /// Overwrite the current profile from a saved bundle (destructive confirm).
    RestoreBackupIntoCurrent(String),
    /// Restore a bundle from an arbitrary path typed by the user.
    ImportBackupFromPath,
    /// Delete one token-history ledger event.
    DeleteTokenHistoryEvent(String),
    /// Reset the current profile's settings to defaults (destructive confirm).
    ResetSettings,
    /// Clear the blackout/rescue journal for the active profile.
    ClearJournal,
    /// Restore a specific saved version of an artifact (dialog confirms the
    /// destructive overwrite of the live file).
    RestoreVersion(String, u64),
    /// Point-in-time restore of the whole profile to a past unix moment.
    PitrRestore,
    /// Create fresh client configs (all formats) from a user-supplied clean
    /// IP endpoint, reusing the last deployed worker link — no redeploy.
    CreateConfigFromIp,
}

impl DastYabApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // install the theme once (Dark royal-gold)
        let mut style = (*cc.egui_ctx.style_of(egui::Theme::Dark)).clone();
        style.visuals = egui::Visuals {
            dark_mode: true,
            panel_fill: PANEL,
            window_fill: PANEL,
            extreme_bg_color: DARK,
            override_text_color: Some(TEXT),
            hyperlink_color: GOLD,
            selection: egui::style::Selection {
                bg_fill: GOLD_DIM,
                stroke: egui::Stroke::new(1.0, GOLD),
            },
            // Modern rounded window + a soft drop shadow.
            window_corner_radius: egui::CornerRadius::same(10),
            window_shadow: egui::epaint::Shadow {
                offset: [0, 4],
                blur: 18,
                spread: 0,
                color: egui::Color32::from_black_alpha(160),
            },
            ..Default::default()
        };
        // Slightly roomier spacing for a premium feel.
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(10.0, 4.0);
        cc.egui_ctx.set_style_of(egui::Theme::Dark, style);

        // touch profile data
        let _ = dastyab_core::store::profiles::migrate_legacy();
        let pids = list_profiles()
            .into_iter()
            .map(|m| m.id)
            .collect::<Vec<_>>();

        let profile = load_profile("default");
        let (tx, rx) = bridge::channel();
        let mut state = GuiState::default();
        state.reload();

        // One-button Protection auto-resume: if the user left protection on in
        // a previous session, surface that state so the toggle reflects it.
        let autopilot_on =
            dastyab_core::store::profiles::protection_enabled(&state.active_profile_id);
        let mut app = Self {
            profile_id: state.active_profile_id.clone(),
            profiles: if pids.is_empty() {
                vec!["default".to_string()]
            } else {
                pids
            },
            note: String::new(),
            error_banner: None,
            tx,
            rx,
            running: Vec::new(),
            log_lines: Vec::new(),
            state,
            dialog: None,
            pending_action: None,
            selected_profile: None,
            cleanip_search: String::new(),
            cleanip_sort: crate::views::cleanip::CleanipSort::default(),
            backups_search: String::new(),
            configs_search: String::new(),
            configs_fmt_filter: String::new(),
            configs_sort: crate::views::configs::ConfigsSort::Newest,
            new_profile_name: String::new(),
            scan_count: profile.config.scan_count.max(1),
            scan_workers: profile.config.scan_workers.max(1),
            scan_timeout: profile.config.scan_timeout.max(1),
            scan_ports: if profile.config.scan_ports.is_empty() {
                "443".to_string()
            } else {
                profile.config.scan_ports.clone()
            },
            scan_gentle: profile.config.scan_gentle,
            stealth_enabled: profile.config.stealth_enabled,
            last_link: String::new(),
            autopilot_on,
            autopilot_status: if autopilot_on {
                "Protection is on — refinding the best clean IP and keeping your configs healthy."
                    .to_string()
            } else {
                "Autopilot is off. Flip the switch to auto-find the best clean IP, export configs, and keep them healthy.".to_string()
            },
            autopilot_stop: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            last_cause: None,
            last_action_label: String::new(),
            audit_output: String::new(),
            backup_output: String::new(),
            export_output: String::new(),
            beacon_enabled: profile
                .config
                .beacon
                .as_ref()
                .map(|b| b.enabled)
                .unwrap_or(false),
            beacon_channel: profile
                .config
                .beacon
                .as_ref()
                .map(|b| match b.kind {
                    dastyab_core::remote_beacon::BeaconKind::Telegram => "Telegram".to_string(),
                    dastyab_core::remote_beacon::BeaconKind::GenericWebhook => {
                        "Webhook".to_string()
                    }
                })
                .unwrap_or_else(|| "Telegram".to_string()),
            beacon_token: profile
                .config
                .beacon
                .as_ref()
                .map(|b| b.token.clone())
                .unwrap_or_default(),
            beacon_target: profile
                .config
                .beacon
                .as_ref()
                .map(|b| b.chat_id_or_url.clone())
                .unwrap_or_default(),
            beacon_rate_limit: profile
                .config
                .beacon
                .as_ref()
                .map(|b| b.rate_limit_secs)
                .unwrap_or(900),
            beacon_note: String::new(),
            beacon_failover_enabled: profile
                .config
                .beacon
                .as_ref()
                .map(|b| b.failover_enabled)
                .unwrap_or(false),
            beacon_failover_channel: profile
                .config
                .beacon
                .as_ref()
                .map(|b| match b.failover_kind {
                    dastyab_core::remote_beacon::BeaconKind::Telegram => "Telegram".to_string(),
                    dastyab_core::remote_beacon::BeaconKind::GenericWebhook => {
                        "Webhook".to_string()
                    }
                })
                .unwrap_or_else(|| "Webhook".to_string()),
            beacon_failover_token: profile
                .config
                .beacon
                .as_ref()
                .map(|b| b.failover_token.clone())
                .unwrap_or_default(),
            beacon_failover_target: profile
                .config
                .beacon
                .as_ref()
                .map(|b| b.failover_chat_id_or_url.clone())
                .unwrap_or_default(),
            vps_host: String::new(),
            vps_user: String::new(),
            vps_key: "~/.ssh/id_ed25519".to_string(),
            vps_port: 22,
            vps_domain: String::new(),
            vps_note: String::new(),
            worker_tunnel_note: String::new(),
            desync_enabled: profile.config.desync.enabled,
            desync_min: profile.config.desync.min_fragment,
            desync_max: profile.config.desync.max_fragment,
            desync_delay_us: profile.config.desync.inter_fragment_delay_us,
            desync_note: String::new(),
            drill_output: String::new(),
            daemon_note: String::new(),
            light_timeout_s: profile.config.light_timeout_secs,
            deep_timeout_s: profile.config.deep_timeout_secs,
            max_backoff_s: profile.config.max_backoff_secs,
            network_down_sleep_s: profile.config.network_down_sleep_secs,
            light_check_interval_s: profile.config.light_interval_secs,
            drill_interval_s: profile.config.drill_interval_secs,
            timeouts_note: String::new(),
            auto_rotate_enabled: profile.config.auto_rotate_on_blocked,
            auto_rotate_note: String::new(),
            backup_auto_enabled: profile.config.backup_autosync.enabled,
            backup_auto_interval: if profile.config.backup_autosync.interval_secs > 0 {
                profile.config.backup_autosync.interval_secs
            } else {
                dastyab_core::backup_autosync::AUTOSYNC_INTERVAL_SECS
            },
            backup_auto_keep: if profile.config.backup_autosync.keep > 0 {
                profile.config.backup_autosync.keep
            } else {
                dastyab_core::backup_autosync::AUTOSYNC_KEEP
            },
            backup_auto_note: String::new(),
            mutation_enabled: profile.config.mutation.enabled,
            mutation_interval: if profile.config.mutation.interval_secs > 0 {
                profile.config.mutation.interval_secs
            } else {
                86400
            },
            mutation_rotate_path: profile.config.mutation.rotate_path,
            mutation_note: String::new(),
            hz_token: String::new(),
            hz_location: "nbg1".to_string(),
            hz_server_type: "cx22".to_string(),
            mw_count: 2,
            mw_note: String::new(),
            view: View::Dashboard,
            history_filter: HistoryFilter::default(),
            token_search: String::new(),
            history_search: String::new(),
            sec_backups: true,
            cleanip_test_output: String::new(),
            cleanip_add_draft: String::new(),
            token_history_search: String::new(),
            backup_sort: BackupSort::default(),
            token_history_filter: String::new(),
            log_auto_scroll: true,
        };
        app.refresh_diagnostics();
        app
    }

    /// Re-read the last pipeline diagnostics and derive the plain-language
    /// "why zero?" explanation for the Clean IPs view.
    fn refresh_diagnostics(&mut self) {
        use dastyab_core::diagnose::{diagnose, plain_message, Locale};
        if let Some(diag) = dastyab_core::store::profiles::load_last_diagnostics(&self.profile_id)
        {
            let probe = dastyab_core::diagnose::WorkerProbe::default();
            let cause = diagnose(&diag, probe);
            self.last_cause = Some(plain_message(cause, Locale::En));
            self.last_action_label =
                dastyab_core::diagnose::recommended_action(cause).label(Locale::En);
        }
    }

    fn reload_profiles(&mut self) {
        let pids = list_profiles()
            .into_iter()
            .map(|m| m.id)
            .collect::<Vec<_>>();
        self.profiles = if pids.is_empty() {
            vec!["default".to_string()]
        } else {
            pids
        };
    }

    /// Switch the active profile: persist the store's active marker, refresh
    /// the view-model cache, and clear transient per-profile UI state. This
    /// keeps `profile_id` and `state.active_profile_id` in lockstep so actions
    /// like "Make active" always target the profile the user is actually
    /// viewing (previously the profile dropdown only changed `profile_id`,
    /// leaving the store/state on the old profile — a real bug).
    fn switch_profile(&mut self, id: &str) {
        if self.profile_id == id {
            return;
        }
        self.profile_id = id.to_string();
        let _ = set_active_profile(id);
        self.state.reload_pending = true;
        self.selected_profile = None;
        self.dialog = None;
        self.pending_action = None;
        self.error_banner = None;
        self.note.clear();
        self.last_link.clear();
    }

    /// Collect seed IPs for a scan: manual known-good seeds plus every
    /// recently-verified clean IP from the autopilot ledger. The scanner feeds
    /// these (and expands their neighborhoods) so each successful scan teaches
    /// the next one where to look — the self-improving learning loop.
    fn scan_seed_ips(&self, pid: &str) -> Vec<String> {
        let mut seeds: Vec<String> = dastyab_core::cf::ips::load_manual_seeds(pid)
            .into_iter()
            .filter_map(|s| s.split(':').next().map(|ip| ip.trim().to_string()))
            .filter(|ip| !ip.is_empty())
            .collect();
        for ep in dastyab_core::cf::ips::load_seed_endpoints(pid, 200) {
            if let Some(ip) = ep.split(':').next() {
                let ip = ip.trim().to_string();
                if !ip.is_empty() && !seeds.contains(&ip) {
                    seeds.push(ip);
                }
            }
        }
        seeds.truncate(400);
        seeds
    }

    fn save_scan_params(&mut self) {
        let cfg = ProfileConfig {
            scan_count: self.scan_count,
            scan_workers: self.scan_workers,
            scan_timeout: self.scan_timeout,
            scan_ports: self.scan_ports.clone(),
            scan_gentle: self.scan_gentle,
            stealth_enabled: self.stealth_enabled,
            ..Default::default()
        };
        dastyab_core::stealth::set_enabled(self.stealth_enabled);
        if let Err(e) = save_config(&self.profile_id, &cfg) {
            self.note = e.brief();
        }
    }

    /// Persist blackout-resilience pacing (monitor light/deep budgets + the
    /// backoff ceiling). 0 on each field means "system default". The daemon
    /// reads these every tick, so changes apply without a restart.
    fn save_timeouts(&mut self) {
        let mut p = dastyab_core::store::profiles::load_profile(&self.profile_id);
        p.config.light_timeout_secs = self.light_timeout_s;
        p.config.deep_timeout_secs = self.deep_timeout_s;
        p.config.max_backoff_secs = self.max_backoff_s;
        p.config.network_down_sleep_secs = self.network_down_sleep_s;
        p.config.light_interval_secs = self.light_check_interval_s.max(30);
        p.config.drill_interval_secs = self.drill_interval_s.max(300);
        match dastyab_core::store::profiles::save_profile(&p) {
            Ok(()) => self.timeouts_note = "Protection pacing saved to profile.".to_string(),
            Err(e) => self.timeouts_note = e.brief(),
        }
    }

    /// Persist the automatic token-rotation toggle (account-blocked recovery).
    fn save_auto_rotate(&mut self) {
        let mut p = dastyab_core::store::profiles::load_profile(&self.profile_id);
        p.config.auto_rotate_on_blocked = self.auto_rotate_enabled;
        match dastyab_core::store::profiles::save_profile(&p) {
            Ok(()) => {
                self.auto_rotate_note = if self.auto_rotate_enabled {
                    "Auto token-rotation ON — blocked tokens swap to a backup automatically."
                        .to_string()
                } else {
                    "Auto token-rotation OFF — blocked accounts need a manual token recover."
                        .to_string()
                };
            }
            Err(e) => self.auto_rotate_note = e.brief(),
        }
    }

    /// Persist the scheduled auto-backup config. The daemon runs this every
    /// tick (local disk work — even during a blackout), so enabling it here
    /// fully removes the manual backup step.
    fn save_backup_auto(&mut self) {
        let mut p = dastyab_core::store::profiles::load_profile(&self.profile_id);
        let interval = self.backup_auto_interval.max(60);
        let keep = self.backup_auto_keep.max(1);
        p.config.backup_autosync.enabled = self.backup_auto_enabled;
        p.config.backup_autosync.interval_secs = interval;
        p.config.backup_autosync.keep = keep;
        match dastyab_core::store::profiles::save_profile(&p) {
            Ok(()) => {
                self.backup_auto_note = if self.backup_auto_enabled {
                    format!("Auto-backup ON — every {interval}s, keeping {keep} copies.")
                } else {
                    "Auto-backup OFF.".to_string()
                };
            }
            Err(e) => self.backup_auto_note = format!("Save failed: {}", e.brief()),
        }
    }

    /// Persist the scheduled worker-signature rotation config. The daemon runs
    /// this when the network is up (CF API redeploy), so enabling it here makes
    /// the app a moving target against stateful DPI with zero manual steps.
    fn save_mutation(&mut self) {
        let mut p = dastyab_core::store::profiles::load_profile(&self.profile_id);
        let interval = self.mutation_interval.max(3600);
        p.config.mutation.enabled = self.mutation_enabled;
        p.config.mutation.interval_secs = interval;
        p.config.mutation.rotate_path = self.mutation_rotate_path;
        match dastyab_core::store::profiles::save_profile(&p) {
            Ok(()) => {
                self.mutation_note = if self.mutation_enabled {
                    format!(
                        "Signature rotation ON — every {interval}s ({}).",
                        if self.mutation_rotate_path {
                            "uuid + path"
                        } else {
                            "uuid only"
                        }
                    )
                } else {
                    "Signature rotation OFF.".to_string()
                };
            }
            Err(e) => self.mutation_note = format!("Save failed: {}", e.brief()),
        }
    }

    /// Persist the anti-DPI desync fragmenter config (loads the current profile
    /// config so every other field is preserved).
    fn save_desync(&mut self) {
        let mut p = dastyab_core::store::profiles::load_profile(&self.profile_id);
        let min = self.desync_min.max(1);
        p.config.desync.enabled = self.desync_enabled;
        p.config.desync.min_fragment = min;
        p.config.desync.max_fragment = self.desync_max.max(min);
        p.config.desync.inter_fragment_delay_us = self.desync_delay_us;
        match dastyab_core::store::profiles::save_profile(&p) {
            Ok(()) => {
                dastyab_core::desync::apply_from_profile(&self.profile_id);
                self.desync_note = if self.desync_enabled {
                    "Desync fragmentation ON. Next scan will write WS upgrades as irregular segments."
                        .to_string()
                } else {
                    "Desync fragmentation OFF.".to_string()
                };
            }
            Err(e) => self.desync_note = format!("Save failed: {}", e.brief()),
        }
    }

    /// Persist the notification config. Loads the current profile config so we
    /// preserve every other field (beacon is stored on `ProfileConfig`).
    fn save_beacon(&mut self) {
        let kind = if self.beacon_channel == "Webhook" {
            dastyab_core::remote_beacon::BeaconKind::GenericWebhook
        } else {
            dastyab_core::remote_beacon::BeaconKind::Telegram
        };
        let fo_kind = if self.beacon_failover_channel == "Webhook" {
            dastyab_core::remote_beacon::BeaconKind::GenericWebhook
        } else {
            dastyab_core::remote_beacon::BeaconKind::Telegram
        };
        let mut p = dastyab_core::store::profiles::load_profile(&self.profile_id);
        p.config.beacon = Some(dastyab_core::remote_beacon::BeaconConfig {
            enabled: self.beacon_enabled,
            kind,
            token: self.beacon_token.clone(),
            chat_id_or_url: self.beacon_target.clone(),
            rate_limit_secs: self.beacon_rate_limit.max(1),
            failover_enabled: self.beacon_failover_enabled,
            failover_kind: fo_kind,
            failover_token: self.beacon_failover_token.clone(),
            failover_chat_id_or_url: self.beacon_failover_target.clone(),
        });
        match dastyab_core::store::profiles::save_profile(&p) {
            Ok(()) => self.beacon_note = "Notifications saved.".to_string(),
            Err(e) => self.beacon_note = format!("Save failed: {}", e.brief()),
        }
    }

    /// Send a test message with the current on-screen config (does not save).
    fn send_beacon_test(&mut self) {
        let kind = if self.beacon_channel == "Webhook" {
            dastyab_core::remote_beacon::BeaconKind::GenericWebhook
        } else {
            dastyab_core::remote_beacon::BeaconKind::Telegram
        };
        let cfg = dastyab_core::remote_beacon::BeaconConfig {
            enabled: true,
            kind,
            token: self.beacon_token.clone(),
            chat_id_or_url: self.beacon_target.clone(),
            rate_limit_secs: self.beacon_rate_limit.max(1),
            failover_enabled: self.beacon_failover_enabled,
            failover_kind: if self.beacon_failover_channel == "Webhook" {
                dastyab_core::remote_beacon::BeaconKind::GenericWebhook
            } else {
                dastyab_core::remote_beacon::BeaconKind::Telegram
            },
            failover_token: self.beacon_failover_token.clone(),
            failover_chat_id_or_url: self.beacon_failover_target.clone(),
        };
        if cfg.chat_id_or_url.is_empty() {
            self.beacon_note = "Set a chat ID / webhook URL first.".to_string();
            return;
        }
        let msg = "✅ DastYab test notification — protection is working.";
        let tx = self.tx.clone();
        bridge::spawn("beacon-test", tx.clone(), async move {
            match dastyab_core::remote_beacon::send_with_failover(&cfg, msg).await {
                Ok(()) => {
                    let _ = tx.send(crate::bridge::UiEvent::Log {
                        task: "beacon-test".to_string(),
                        line: "[beacon] test message sent (primary or failover)".to_string(),
                    });
                }
                Err(e) => {
                    let _ = tx.send(crate::bridge::UiEvent::TaskErr {
                        task: "beacon-test".to_string(),
                        error: CFError::new(
                            "Beacon test",
                            e.brief(),
                            "Check the primary/failover channel config.",
                        ),
                    });
                }
            }
            Ok::<String, CFError>("beacon-test done".to_string())
        });
    }

    /// Deliver any undelivered alerts in the durable outbox (queued during a
    /// blackout / blocked channel). Async over the bridge.
    fn flush_beacon_outbox(&mut self) {
        let profile = self.state.active_profile_id.clone();
        let tx = self.tx.clone();
        bridge::spawn("beacon-flush", tx.clone(), async move {
            let sent = dastyab_core::remote_beacon::flush_outbox(&profile).await;
            let remaining = dastyab_core::remote_beacon::load_outbox(&profile).len();
            let line = format!("[beacon] flushed {sent} queued alert(s); {remaining} still queued");
            let _ = tx.send(crate::bridge::UiEvent::Log {
                task: "beacon-flush".to_string(),
                line,
            });
            Ok::<String, CFError>(format!("beacon-flush sent={sent}"))
        });
    }

    /// Persist the VPS DNS-tunnel client config so the connectivity ladder can
    /// use it automatically when DoH/DoT fail.
    fn save_vps(&mut self) {
        if self.vps_host.trim().is_empty() || self.vps_domain.trim().is_empty() {
            self.vps_note = "Set at least the VPS host and the base DNS domain first.".to_string();
            return;
        }
        let cfg = dastyab_core::vps_deploy::TunnelClientConfig {
            host: self.vps_host.trim().to_string(),
            base_domain: self.vps_domain.trim().to_string(),
            session: String::new(),
            resolver: "doh".to_string(),
            mode: dastyab_core::vps_deploy::TunnelMode::default(),
            worker_url: None,
            worker_name: None,
            shared_secret: None,
            worker_vless_upstream: None,
        };
        match dastyab_core::vps_deploy::write_tunnel_client_config(&self.profile_id, &cfg) {
            Ok(()) => {
                self.vps_note =
                    "VPS config saved. The DNS tunnel will be used automatically when DoH/DoT fail."
                        .to_string()
            }
            Err(e) => self.vps_note = format!("Save failed: {}", e.brief()),
        }
    }

    /// Deploy the DNS tunnel server to the VPS via SSH (one-command, driven
    /// from inside the app). Reports progress/errors via the bridge UiEvent.
    fn deploy_vps_tunnel(&mut self) {
        if self.vps_host.trim().is_empty()
            || self.vps_user.trim().is_empty()
            || self.vps_domain.trim().is_empty()
        {
            self.vps_note = "Set VPS host, SSH user, and base DNS domain first.".to_string();
            return;
        }
        let creds = dastyab_core::vps_deploy::VpsCredentials {
            host: self.vps_host.trim().to_string(),
            ssh_user: self.vps_user.trim().to_string(),
            ssh_key_path: std::path::PathBuf::from(&self.vps_key),
            ssh_port: self.vps_port,
        };
        if !creds.is_complete() {
            self.vps_note = "Incomplete VPS credentials.".to_string();
            return;
        }
        let pid = self.profile_id.clone();
        let domain = self.vps_domain.trim().to_string();
        let tx = self.tx.clone();
        self.running.push("dns-tunnel".to_string());
        self.vps_note = "Deploying DNS tunnel on the VPS (SSH)…".to_string();
        let tx2 = tx.clone();
        bridge::spawn("dns-tunnel", tx.clone(), async move {
            let peer = dastyab_core::vps_deploy::RealVpsSshPeer;
            match dastyab_core::vps_deploy::deploy_dns_tunnel(&creds, &peer, &pid, &domain, None)
                .await
            {
                Ok(res) => {
                    let _ = tx2.send(crate::bridge::UiEvent::Log {
                        task: "dns-tunnel".to_string(),
                        line: format!(
                            "[dns-tunnel] deployed to {} (steps={}, verified={})",
                            res.host,
                            res.completed_steps.len(),
                            res.verified
                        ),
                    });
                }
                Err(e) => {
                    let _ = tx2.send(crate::bridge::UiEvent::TaskErr {
                        task: "dns-tunnel".to_string(),
                        error: CFError::new(
                            "DNS tunnel",
                            e.brief(),
                            "Check VPS connectivity / SSH key / domain.",
                        ),
                    });
                }
            }
            Ok::<String, CFError>("dns-tunnel done".to_string())
        });
    }

    /// Deploy the Worker-hosted DNS tunnel (no VPS) using the profile's active
    /// Cloudflare token. Fully automatic — no VPS/SSH credentials needed.
    fn deploy_worker_tunnel_gui(&mut self) {
        // Use the profile's ACTIVE token (not the first token added) — a
        // stale "first token" pick silently deploys with the wrong credential
        // and the worker never comes up.
        let token = match dastyab_core::store::profiles::get_active_token(&self.profile_id)
            .unwrap_or(None)
        {
            Some(label) => {
                match dastyab_core::store::profiles::get_token(&self.profile_id, &label)
                    .unwrap_or(None)
                {
                    Some(t) => t,
                    None => {
                        self.worker_tunnel_note = format!(
                        "Active token '{label}' could not be read — re-add it on the Token tab."
                    );
                        return;
                    }
                }
            }
            None => {
                self.worker_tunnel_note =
                    "No active Cloudflare token on this profile — add one and mark it active on the Token tab."
                        .to_string();
                return;
            }
        };
        let pid = self.profile_id.clone();
        let tx = self.tx.clone();
        self.running.push("dns-tunnel-worker".to_string());
        self.worker_tunnel_note = "Deploying Worker DNS tunnel (no VPS)…".to_string();
        let tx2 = tx.clone();
        bridge::spawn("dns-tunnel-worker", tx.clone(), async move {
            let client = dastyab_core::cf::Client::new(&token);
            let accs = client.list_accounts().await?;
            let acc = accs.first().cloned().ok_or_else(|| {
                dastyab_core::CFError::new(
                    "No account",
                    "No Cloudflare account accessible.",
                    "Check token permissions.",
                )
            })?;
            let opts = dastyab_core::worker_tunnel::WorkerTunnelDeployOpts {
                worker_name: None,
                session_seed: format!("dyb-gui-{}", pid),
                compat_date: "2026-07-01".into(),
                retries: 2,
                vless_upstream: None,
            };
            let res =
                dastyab_core::worker_tunnel::deploy_worker_tunnel(&client, &acc.id, &pid, &opts)
                    .await
                    .map_err(|e| {
                        dastyab_core::CFError::new(
                            "Worker tunnel",
                            e.brief(),
                            "Check the CF token.",
                        )
                    })?;
            // Record a non-clean base deploy link in history so the Configs
            // tab's "create from IP" and scanning always have a vless://
            // skeleton to build on — no redeploy needed.
            if let Some(base) = dastyab_core::worker_tunnel::resolve_deployed_base_link(&pid) {
                let rec = dastyab_core::store::profiles::VlessRecord {
                    id: dastyab_core::store::new_id(),
                    ts: dastyab_core::store::profiles::now_iso(),
                    epoch: dastyab_core::store::now_ts(),
                    uuid: String::new(),
                    address: res.worker_url.clone(),
                    port: 443,
                    name: format!("worker-{}", res.worker_name),
                    clean_ip: false,
                    link: base.clone(),
                    note: "deployed via worker tunnel".into(),
                };
                let _ = dastyab_core::store::profiles::remember_vless(&pid, rec);
            }
            let _ = tx2.send(crate::bridge::UiEvent::Log {
                task: "dns-tunnel-worker".to_string(),
                line: format!(
                    "[worker-tunnel] deployed {} — the fallback ladder can now use it",
                    res.worker_url
                ),
            });
            Ok::<String, CFError>(format!(
                "Worker tunnel deployed at {} ({}). You can now create configs from any clean IP in the Configs tab without redeploying.",
                res.worker_url, res.worker_name
            ))
        });
    }

    /// Zero-touch Hetzner provisioning: create a fresh VPS via the Hetzner
    /// Cloud API, wait for it to boot, then deploy the DNS tunnel to it —
    /// all from inside the app. Reports progress/errors via the bridge.
    fn provision_vps_tunnel(&mut self) {
        if self.hz_token.trim().is_empty() || self.vps_domain.trim().is_empty() {
            self.vps_note = "Set the Hetzner API token and base DNS domain first.".to_string();
            return;
        }
        let creds = dastyab_core::vps_provision::HetznerCredentials {
            api_token: self.hz_token.trim().to_string(),
            location: self.hz_location.trim().to_string(),
            server_type: self.hz_server_type.trim().to_string(),
            server_name: "dastyab-tunnel".to_string(),
        };
        let pid = self.profile_id.clone();
        let domain = self.vps_domain.trim().to_string();
        let ssh_user = self.vps_user.trim().to_string();
        let key_path = std::path::PathBuf::from(
            std::env::var("HOME")
                .map(|h| format!("{h}/.dastyab/key-hetzner"))
                .unwrap_or_else(|_| "~/.dastyab/key-hetzner".to_string()),
        );
        let tx = self.tx.clone();
        self.running.push("hz-provision".to_string());
        self.vps_note = "Provisioning Hetzner VPS… (this can take 1-2 min)".to_string();
        let tx2 = tx.clone();
        bridge::spawn("hz-provision", tx.clone(), async move {
            let api = dastyab_core::vps_provision::RealHetznerApi;
            match dastyab_core::vps_provision::provision_vps(&api, &creds, &key_path, None).await
            {
                Ok(prov) => {
                    let _ = tx2.send(crate::bridge::UiEvent::Log {
                        task: "hz-provision".to_string(),
                        line: format!(
                            "[hz-provision] VPS {} ready (steps={}), deploying tunnel…",
                            prov.host,
                            prov.completed_steps.len()
                        ),
                    });
                    let vps_creds = dastyab_core::vps_deploy::VpsCredentials {
                        host: prov.host.clone(),
                        ssh_user: ssh_user.clone(),
                        ssh_key_path: prov.identity.private_key_path.clone(),
                        ssh_port: 22,
                    };
                    let peer = dastyab_core::vps_deploy::RealVpsSshPeer;
                    match dastyab_core::vps_deploy::deploy_dns_tunnel(
                        &vps_creds, &peer, &pid, &domain, None,
                    )
                    .await
                    {
                        Ok(res) => {
                            let _ = tx2.send(crate::bridge::UiEvent::Log {
                                task: "hz-provision".to_string(),
                                line: format!(
                                    "[hz-provision] tunnel deployed to {} (verified={})",
                                    res.host, res.verified
                                ),
                            });
                        }
                        Err(e) => {
                            let _ = tx2.send(crate::bridge::UiEvent::TaskErr {
                                task: "hz-provision".to_string(),
                                error: CFError::new(
                                    "Hetzner",
                                    format!("VPS provisioned but tunnel deploy failed: {}", e.brief()),
                                    "Check the VPS is reachable and the tunnel server install succeeded.",
                                ),
                            });
                        }
                    }
                }
                Err(e) => {
                    let _ = tx2.send(crate::bridge::UiEvent::TaskErr {
                        task: "hz-provision".to_string(),
                        error: CFError::new(
                            "Hetzner",
                            e.brief(),
                            "Check the API token is read/write and the location/server-type are valid.",
                        ),
                    });
                }
            }
            Ok::<String, CFError>("hz-provision done".to_string())
        });
    }

    /// Deploy/maintain the multi-worker redundancy set from inside the app.
    fn deploy_multi_worker(&mut self) {
        let count = self.mw_count.clamp(1, 3);
        let pid = self.profile_id.clone();
        let tx = self.tx.clone();
        self.running.push("multi-worker".to_string());
        self.mw_note = format!("Deploying up to {count} workers…");
        let tx2 = tx.clone();
        bridge::spawn("multi-worker", tx.clone(), async move {
            let p = dastyab_core::store::profiles::load_profile(&pid);
            let acc_id = if p.config.active_account.is_empty() {
                None
            } else {
                Some(p.config.active_account.clone())
            };
            let result = match acc_id {
                Some(acc) => {
                    let peer = dastyab_core::multi_worker::RealWorkerPeer;
                    dastyab_core::multi_worker::deploy_worker_in_parallel(
                        &peer, &pid, &acc, "", count,
                    )
                    .await
                }
                None => Err(CFError::new(
                    "multi-worker",
                    "No active account for this profile.",
                    "Run `dastyab up` or set an active account first.",
                )),
            };
            match result {
                Ok(set) => {
                    let list = set
                        .workers
                        .iter()
                        .map(|w| w.name.clone())
                        .collect::<Vec<_>>()
                        .join(", ");
                    let _ = tx2.send(crate::bridge::UiEvent::Log {
                        task: "multi-worker".to_string(),
                        line: format!("[multi-worker] set now: {list}"),
                    });
                }
                Err(e) => {
                    let _ = tx2.send(crate::bridge::UiEvent::TaskErr {
                        task: "multi-worker".to_string(),
                        error: CFError::new(
                            "multi-worker",
                            e.brief(),
                            "Check the active token/account.",
                        ),
                    });
                }
            }
            Ok::<String, CFError>("multi-worker done".to_string())
        });
    }

    /// Start autopilot: spawn a background engine loop on the global tokio
    /// runtime. The loop reports progress via bridge Log events.
    fn autopilot_on(&mut self, ctx: &egui::Context) {
        let pid = self.profile_id.clone();
        let tx = self.tx.clone();
        let stop = self.autopilot_stop.clone();
        stop.store(false, std::sync::atomic::Ordering::Relaxed);

        // Persist the protection flag so the monitor auto-resumes after restart.
        let _ = dastyab_core::store::profiles::set_protection(&pid, true);

        self.running.push("autopilot".to_string());
        self.autopilot_on = true;
        self.autopilot_status = "Autopilot starting — discovering the best clean IP…".to_string();
        self.push_log("[autopilot] ON — starting discovery + monitor loop");
        ctx.request_repaint();

        bridge::spawn("autopilot", tx.clone(), async move {
            let params = dastyab_core::autopilot::DiscoveryParams::default();
            let interval = std::time::Duration::from_secs(300);
            let engine = dastyab_core::autopilot::AutopilotEngine::new(pid, params, interval);
            // Run a full cycle first (so the UI gets a quick result), then
            // monitor until `stop` is set.
            match engine.run_cycle().await {
                Ok((_, summary)) => {
                    // report via the return value; the loop below reports each cycle
                    Ok::<String, CFError>(summary.note)
                }
                Err(e) => Err(e),
            }?;
            // Monitor loop until stop is requested.
            loop {
                if stop.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                tokio::time::sleep(interval).await;
                if stop.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                match engine.monitor_cycle().await {
                    Ok(s) => {
                        // Emit a log line per cycle (quiet by default).
                        // We send a Log event so the GUI log pane updates.
                        let _ = tx.send(bridge::UiEvent::Log {
                            task: "autopilot".to_string(),
                            line: format!("[autopilot] {}", s.note),
                        });
                    }
                    Err(e) => {
                        let _ = tx.send(bridge::UiEvent::Log {
                            task: "autopilot".to_string(),
                            line: format!("[autopilot] error: {}", e.brief()),
                        });
                    }
                }
            }
            Ok::<String, CFError>("autopilot stopped".to_string())
        });
    }

    /// Stop autopilot (request the background loop to halt).
    fn autopilot_off(&mut self) {
        // Clear the persisted flag (monitor will not auto-resume).
        let _ = dastyab_core::store::profiles::set_protection(&self.profile_id, false);
        self.autopilot_stop
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.autopilot_on = false;
        self.autopilot_status =
            "Autopilot stopped. The last working clean IP stays in your active configs."
                .to_string();
        self.running.retain(|t| t != "autopilot");
        self.push_log("[autopilot] OFF");
    }

    /// Create fresh client configs (all formats) from a user-supplied clean IP
    /// endpoint, reusing this profile's most recent deployed worker link — no
    /// redeploy. `endpoint` may be a bare IP or "ip:port".
    fn create_config_from_ip(&mut self, endpoint: &str) {
        let ep = endpoint.trim();
        if ep.is_empty() {
            self.note = "Enter an IP (e.g. 104.16.1.1 or 104.16.1.1:443).".to_string();
            return;
        }
        // Reuse the profile's deployed worker base link (non-clean history
        // record, falling back to the persisted worker-tunnel config). This is
        // fully decoupled from deploying: after the one-time deploy, the user
        // can create configs from any clean IP without ever redeploying.
        let base_link = dastyab_core::worker_tunnel::resolve_deployed_base_link(&self.profile_id);
        let Some(base_link) = base_link else {
            self.note = "No deployed worker link yet — deploy once, then you can point configs at any clean IP without redeploying.".to_string();
            return;
        };

        // Parse the base worker config, then override the address with the
        // user-supplied clean IP (keeps uuid/path/security/transport).
        let mut prof = match dastyab_core::vless::VlessProfile::parse(&base_link) {
            Ok(pr) => pr,
            Err(e) => {
                self.note = format!("Could not parse deployed link: {}", e.brief());
                return;
            }
        };
        let (ip, port) = match ep.rsplit_once(':') {
            Some((ip, port)) if port.chars().all(|c| c.is_ascii_digit()) => {
                (ip.to_string(), port.parse::<u16>().unwrap_or(443))
            }
            _ => (ep.to_string(), 443),
        };
        prof.address = ip.clone();
        prof.port = port;
        prof.name = format!("clean-{ep}");

        // Render all formats and write them into the generated-configs ledger.
        let all = dastyab_core::export::render_all(&prof);
        if all.is_empty() {
            self.note = "Could not render any config for that endpoint.".to_string();
            return;
        }
        let pid = self.profile_id.clone();
        let mut ledger = dastyab_core::generated_configs::load_generated_configs(&pid);
        let now = dastyab_core::store::now_ts() as u64;
        use dastyab_core::generated_configs::ConfigSource;
        for (fmt_label, content) in &all {
            let fmt = dastyab_core::export::ExportFormat::parse(fmt_label);
            let Some(fmt) = fmt else { continue };
            let _ = ledger.push(
                now,
                fmt,
                ConfigSource::WorkerVless,
                Some(format!("clean {ep}")),
                content.clone(),
            );
        }
        let _ = dastyab_core::generated_configs::save_generated_configs(&pid, &ledger);

        // Also remember it as a saved clean IP + learn it as a seed.
        let _ = remember_clean_ip(&pid, ep);
        let _ = dastyab_core::cf::ips::learn_clean_ip(&pid, &ip);

        self.state.reload_pending = true;
        self.note = format!(
            "Created {n} config(s) from {ep} — no redeploy needed (url {base_link})",
            n = all.len()
        );
    }

    /// Drain the async bridge, applying every pending event to UI state.
    fn poll_bridge(&mut self, ctx: &egui::Context) {
        use bridge::UiEvent;
        while let Ok(ev) = self.rx.try_recv() {
            match ev {
                UiEvent::Done { task, summary } => {
                    self.running.retain(|t| t != &task);
                    if task == "dns-tunnel-worker" {
                        self.worker_tunnel_note = summary.clone();
                    } else {
                        // A task succeeding means whatever previously failed has
                        // recovered (or never applied) — clear stale error banners
                        // so errors disappear once things work again.
                        self.error_banner = None;
                    }
                    if task == "autopilot" {
                        self.autopilot_status = summary.clone();
                        self.autopilot_on = true;
                        self.refresh_diagnostics();
                    } else if task == "blackout-drill" {
                        self.drill_output = summary.clone();
                    } else if task.starts_with("probe-") || task == "probe-all" {
                        self.cleanip_test_output = summary.clone();
                        self.note = summary.clone();
                        self.state.reload_pending = true;
                    } else if task == "dns-tunnel-worker" {
                        self.state.reload_pending = true;
                        self.push_log(&format!("[done] {task}: {summary}"));
                        continue;
                    } else {
                        self.note = format!("✓ {task}: {summary}");
                    }
                    self.push_log(&format!("[done] {task}: {summary}"));
                    // mutating tasks change the store; refresh the view cache
                    self.state.reload_pending = true;
                }
                UiEvent::TaskErr { task, error } => {
                    self.running.retain(|t| t != &task);
                    if task == "dns-tunnel-worker" {
                        self.worker_tunnel_note = format!("Deploy failed: {}", error.brief());
                    }
                    if task == "autopilot" {
                        self.autopilot_on = false;
                        self.autopilot_status = format!("Autopilot error: {}", error.brief());
                    } else {
                        self.note = error.brief();
                        self.error_banner = Some(error.explain());
                    }
                    self.push_log(&format!("[err]  {task}: {}", error.explain()));
                }
                UiEvent::Log { line, .. } => {
                    self.push_log(&line);
                }
            }
        }
        if self.state.reload_pending {
            self.state.reload();
            self.profile_id = self.state.active_profile_id.clone();
        }
        // A live console must repaint every frame — not just on input — so
        // background events stream in visibly even when the user is idle.
        if !self.running.is_empty() {
            ctx.request_repaint();
        }
    }

    /// Append a log line, capping the buffer at 5000 entries to keep the
    /// runaway-scanner OOM risk bounded (report per DeepSeek pass 3.1).
    fn push_log(&mut self, line: &str) {
        self.log_lines.push(line.to_string());
        if self.log_lines.len() > 5000 {
            let excess = self.log_lines.len() - 5000;
            self.log_lines.drain(0..excess);
        }
    }

    /// Render the open dialog (if any) and apply its result.
    fn handle_dialog(&mut self, ctx: &egui::Context) {
        if self.dialog.is_none() {
            return;
        }
        let mut dlg = self.dialog.take().unwrap();
        let outcome = dialogs::show(ctx, &mut dlg);
        match outcome {
            DialogResult::Open => {
                self.dialog = Some(dlg);
            }
            DialogResult::Cancel => {
                self.pending_action = None;
            }
            DialogResult::Submit(payload) => {
                let act = self.pending_action.take();
                match act {
                    Some(PendingDialogAction::CreateProfile) => {
                        if let DialogPayload::Text(name) = payload {
                            match create_profile(&name, "") {
                                Ok(id) => {
                                    let _ = set_active_profile(&id);
                                    self.state.reload_pending = true;
                                    self.note = format!("Profile '{name}' created & activated.");
                                }
                                Err(e) => self.note = e.brief(),
                            }
                        }
                    }
                    Some(PendingDialogAction::RenameProfile(id)) => {
                        if let DialogPayload::Text(newname) = payload {
                            match rename_profile(&id, &newname) {
                                Ok(_) => {
                                    self.state.reload_pending = true;
                                    self.note = format!("Profile renamed to '{newname}'.");
                                }
                                Err(e) => self.note = e.brief(),
                            }
                        }
                    }
                    Some(PendingDialogAction::DescribeProfile(id)) => {
                        if let DialogPayload::Text(desc) = payload {
                            let mut p = dastyab_core::store::profiles::load_profile(&id);
                            p.meta.description = desc.trim().to_string();
                            match dastyab_core::store::profiles::save_profile(&p) {
                                Ok(_) => {
                                    self.state.reload_pending = true;
                                    self.note = format!("Description saved for profile '{id}'.");
                                }
                                Err(e) => self.note = e.brief(),
                            }
                        }
                    }
                    Some(PendingDialogAction::DeleteProfile(id)) => {
                        if let DialogPayload::Confirm = payload {
                            match delete_profile(&id) {
                                Ok(_) => {
                                    self.state.reload_pending = true;
                                    self.selected_profile = None;
                                    self.note = format!("Deleted profile '{id}'.");
                                }
                                Err(e) => self.note = e.brief(),
                            }
                        }
                    }
                    Some(PendingDialogAction::AddToken) => {
                        if let DialogPayload::Two(label, token) = payload {
                            match add_token(&self.profile_id, &label, &token) {
                                Ok(_) => {
                                    self.state.reload_pending = true;
                                    self.note = format!("Token '{label}' added to profile.");
                                }
                                Err(e) => self.note = e.brief(),
                            }
                        }
                    }
                    Some(PendingDialogAction::ImportSeeds) => {
                        if let DialogPayload::Text(raw) = payload {
                            match dastyab_core::cf::ips::import_manual_seeds(
                                &self.profile_id,
                                &raw,
                            ) {
                                Ok(n) => {
                                    self.note = format!(
                                        "Imported {n} known-good IP(s) — next scan will use them as seeds."
                                    );
                                }
                                Err(e) => self.note = e.brief(),
                            }
                        }
                    }
                    Some(PendingDialogAction::ClearCleanIps) => {
                        if let DialogPayload::Confirm = payload {
                            match dastyab_core::store::profiles::clear_clean_ips(&self.profile_id)
                            {
                                Ok(_) => {
                                    self.state.reload_pending = true;
                                    self.note = "All clean IPs cleared.".to_string();
                                }
                                Err(e) => self.note = e.brief(),
                            }
                        }
                    }
                    Some(PendingDialogAction::ClearHistory) => {
                        if let DialogPayload::Confirm = payload {
                            match dastyab_core::store::profiles::clear_history(&self.profile_id) {
                                Ok(_) => {
                                    self.state.reload_pending = true;
                                    self.note = "History cleared.".to_string();
                                }
                                Err(e) => self.note = e.brief(),
                            }
                        }
                    }
                    Some(PendingDialogAction::DeleteHistoryRecord(rec_id)) => {
                        if let DialogPayload::Confirm = payload {
                            match dastyab_core::store::profiles::remove_history_record(
                                &self.profile_id,
                                &rec_id,
                            ) {
                                Ok(_) => {
                                    self.state.reload_pending = true;
                                    self.note = "History entry deleted.".to_string();
                                }
                                Err(e) => self.note = e.brief(),
                            }
                        }
                    }
                    Some(PendingDialogAction::ClearTokenHistory) => {
                        if let DialogPayload::Confirm = payload {
                            match dastyab_core::store::profiles::clear_token_history(
                                &self.profile_id,
                            ) {
                                Ok(_) => {
                                    self.state.reload_pending = true;
                                    self.note = "Token history cleared.".to_string();
                                }
                                Err(e) => self.note = e.brief(),
                            }
                        }
                    }
                    Some(PendingDialogAction::CloneProfile(src_id)) => {
                        if let DialogPayload::Text(name) = payload {
                            match dastyab_core::store::profiles::clone_profile(
                                &src_id,
                                Some(&name),
                            ) {
                                Ok(id) => {
                                    self.state.reload_pending = true;
                                    self.note = format!("Cloned profile → '{id}'.");
                                }
                                Err(e) => self.note = e.brief(),
                            }
                        }
                    }
                    Some(PendingDialogAction::RestoreBackupIntoCurrent(path_str)) => {
                        if let DialogPayload::Confirm = payload {
                            if self.profile_id == "default" && path_str.contains("-default-") {
                                self.note =
                                    "Refusing to overwrite the default profile with a default-profile backup.".to_string();
                            } else {
                                match dastyab_core::store::profiles::overwrite_profile_from_bundle(
                                    &self.profile_id,
                                    std::path::Path::new(&path_str),
                                ) {
                                    Ok(_) => {
                                        self.state.reload_pending = true;
                                        self.note = format!(
                                            "Restored backup into profile '{}'.",
                                            self.profile_id
                                        );
                                    }
                                    Err(e) => self.note = e.brief(),
                                }
                            }
                        }
                    }
                    Some(PendingDialogAction::ImportBackupFromPath) => {
                        if let DialogPayload::Text(p) = payload {
                            let path = std::path::PathBuf::from(p.trim());
                            if !path.exists() {
                                self.note = format!("File not found: {}", path.display());
                            } else {
                                match dastyab_core::backup::import_profile_from_file(&path) {
                                    Ok(pid) => {
                                        self.state.reload_pending = true;
                                        self.note =
                                            format!("Imported backup → new profile '{pid}'.");
                                    }
                                    Err(e) => self.note = e.explain(),
                                }
                            }
                        }
                    }
                    Some(PendingDialogAction::DeleteTokenHistoryEvent(ev_id)) => {
                        if let DialogPayload::Confirm = payload {
                            match dastyab_core::store::profiles::remove_token_history_event(
                                &self.profile_id,
                                &ev_id,
                            ) {
                                Ok(true) => {
                                    self.state.reload_pending = true;
                                    self.note = "Token history entry deleted.".to_string();
                                }
                                Ok(false) => {
                                    self.note = "Token history entry not found.".to_string()
                                }
                                Err(e) => self.note = e.brief(),
                            }
                        }
                    }
                    Some(PendingDialogAction::ResetSettings) => {
                        if let DialogPayload::Confirm = payload {
                            let mut p =
                                dastyab_core::store::profiles::load_profile(&self.profile_id);
                            p.config = Default::default();
                            match dastyab_core::store::profiles::save_profile(&p) {
                                Ok(_) => {
                                    self.state.reload_pending = true;
                                    self.note = "Profile settings reset to defaults.".to_string();
                                }
                                Err(e) => self.note = e.brief(),
                            }
                        }
                    }
                    Some(PendingDialogAction::ClearJournal) => {
                        if let DialogPayload::Confirm = payload {
                            match dastyab_core::journal::clear(&self.profile_id) {
                                Ok(_) => {
                                    self.state.reload_pending = true;
                                    self.note = "Journal cleared.".to_string();
                                }
                                Err(e) => self.note = e.brief(),
                            }
                        }
                    }
                    Some(PendingDialogAction::RestoreVersion(rel_path, unix)) => {
                        if let DialogPayload::Confirm = payload {
                            let dir =
                                dastyab_core::store::profiles::profile_dir(&self.profile_id);
                            let now = dastyab_core::store::now_ts() as u64;
                            match dastyab_core::artifact_versions::restore_version(
                                &dir, &rel_path, unix, now,
                            ) {
                                Ok(_) => {
                                    self.state.reload_pending = true;
                                    self.note = format!("Restored {rel_path} from version {unix}.");
                                }
                                Err(e) => self.note = e.to_string(),
                            }
                        }
                    }
                    Some(PendingDialogAction::PitrRestore) => {
                        if let DialogPayload::Text(txt) = payload {
                            let target_unix: u64 = match txt.trim().parse() {
                                Ok(v) => v,
                                Err(_) => {
                                    self.note = format!(
                                        "Invalid unix moment: {:?} (expected integer seconds)",
                                        txt.trim()
                                    );
                                    return;
                                }
                            };
                            let dir =
                                dastyab_core::store::profiles::profile_dir(&self.profile_id);
                            let now = dastyab_core::store::now_ts() as u64;
                            let plan = dastyab_core::artifact_versions::build_pitr_plan(
                                &dir,
                                target_unix,
                            );
                            let preview =
                                dastyab_core::artifact_versions::pitr_preview_markdown(&plan);
                            match dastyab_core::artifact_versions::execute_pitr_plan(
                                &dir, &plan, false, now,
                            ) {
                                Ok(report) => {
                                    self.state.reload_pending = true;
                                    self.note = format!(
                                        "PITR → {target_unix}: restored={} skipped={} mismatches={}\n{preview}",
                                        report.restored,
                                        report.skipped,
                                        report.mismatches.len()
                                    );
                                }
                                Err(e) => self.note = format!("PITR error: {e:?}"),
                            }
                        }
                    }
                    Some(PendingDialogAction::CreateConfigFromIp) => {
                        if let DialogPayload::Text(ep) = payload {
                            self.create_config_from_ip(&ep);
                        }
                    }
                    None => {}
                }
            }
        }
    }
}

impl eframe::App for DastYabApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Auto-resume the one-button Protection monitor if it was left on in a
        // previous session (persisted flag) but isn't running yet.
        if self.autopilot_on && !self.running.iter().any(|t| t == "autopilot") {
            self.autopilot_on(ui.ctx());
        }

        // Drain background async work before rendering any frame.
        self.poll_bridge(ui.ctx());

        // Keyboard shortcuts (Ctrl+1..9 / Ctrl+0).
        self.handle_shortcuts(ui);

        ui.vertical_centered(|ui| {
            ui.heading(egui::RichText::new("DastYab").color(GOLD).size(28.0));
            ui.label(egui::RichText::new("Cloudflare-Workers VLESS VPN console").color(GOLD_DIM));
        });
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            egui::ComboBox::from_label("Profile")
                .selected_text(&self.profile_id)
                .show_ui(ui, |ui| {
                    let mut clicked: Option<String> = None;
                    for id in &self.profiles {
                        if ui
                            .selectable_label(self.profile_id == *id, id.as_str())
                            .clicked()
                        {
                            clicked = Some(id.clone());
                        }
                    }
                    if let Some(id) = clicked {
                        self.switch_profile(&id);
                    }
                });
            if ui.button("New profile").clicked() && !self.new_profile_name.is_empty() {
                match create_profile(&self.new_profile_name, "") {
                    Ok(id) => {
                        // Activate the fresh profile so the store marker, the
                        // view-model cache, and every action (Make active, …)
                        // all target it — otherwise `state.active_profile_id`
                        // stays on the old profile and token/config actions
                        // silently hit the wrong one.
                        let _ = set_active_profile(&id);
                        self.profile_id = id;
                        self.state.reload_pending = true;
                        self.new_profile_name.clear();
                        self.reload_profiles();
                    }
                    Err(e) => self.note = e.brief(),
                }
            }
            ui.text_edit_singleline(&mut self.new_profile_name);
        });

        ui.add_space(8.0);

        let p = load_profile(&self.profile_id);
        self.render_shell(ui, &p);
        self.handle_dialog(ui.ctx());

        if let Some(err) = self.error_banner.clone() {
            ui.add_space(8.0);
            egui::Frame::new()
                .fill(egui::Color32::from_rgb(60, 12, 12))
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(200, 60, 60)))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.add(egui::Label::new(
                            egui::RichText::new(err).color(egui::Color32::from_rgb(255, 160, 160)),
                        ));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui
                                .small_button("✕")
                                .on_hover_text("Dismiss this error")
                                .clicked()
                            {
                                self.error_banner = None;
                            }
                        });
                    });
                });
        }

        if !self.note.is_empty() {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.add(egui::Label::new(
                    egui::RichText::new(&self.note).color(GOLD_DIM),
                ));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .small_button("✕")
                        .on_hover_text("Clear message")
                        .clicked()
                    {
                        self.note.clear();
                    }
                });
            });
        }
    }
}

impl DastYabApp {
    /// Keyboard shortcuts: Ctrl+1..9 / Ctrl+0 switch views instantly.
    fn handle_shortcuts(&mut self, ui: &egui::Ui) {
        let pressed = |key: egui::Key| ui.input(|i| i.modifiers.command && i.key_pressed(key));
        let view = if pressed(egui::Key::Num1) {
            Some(View::Dashboard)
        } else if pressed(egui::Key::Num2) {
            Some(View::DeployScan)
        } else if pressed(egui::Key::Num3) {
            Some(View::Profiles)
        } else if pressed(egui::Key::Num4) {
            Some(View::Tokens)
        } else if pressed(egui::Key::Num5) {
            Some(View::CleanIps)
        } else if pressed(egui::Key::Num6) {
            Some(View::History)
        } else if pressed(egui::Key::Num7) {
            Some(View::Configs)
        } else if pressed(egui::Key::Num8) {
            Some(View::Log)
        } else if pressed(egui::Key::Num9) {
            Some(View::Settings)
        } else if pressed(egui::Key::Num0) {
            Some(View::Autonomy)
        } else {
            None
        };
        if let Some(v) = view {
            self.view = v;
        }
    }

    /// The Dashboard — a single glance at everything: protection status,
    /// active profile, key counts, daemon health, and the latest activity.
    fn dashboard_panel(&mut self, ui: &mut egui::Ui, p: &dastyab_core::store::profiles::Profile) {
        ui.heading(egui::RichText::new("Dashboard").color(GOLD));
        ui.label(
            egui::RichText::new(
                "Everything that matters at a glance — protection, profile, and recent activity.",
            )
            .color(GOLD_DIM),
        );
        ui.add_space(8.0);

        // ── Protection status card ────────────────────────────────
        crate::views::section_card(ui, "Protection", |ui| {
            ui.horizontal(|ui| {
                let (label, color) = if self.autopilot_on {
                    ("🛡 PROTECTION: ON", egui::Color32::from_rgb(90, 210, 120))
                } else {
                    ("🛡 PROTECTION: OFF", egui::Color32::from_rgb(220, 120, 90))
                };
                if ui
                    .add(egui::Button::new(
                        egui::RichText::new(label).color(color).strong().size(16.0),
                    ))
                    .clicked()
                {
                    if self.autopilot_on {
                        self.autopilot_off();
                    } else {
                        self.autopilot_on(ui.ctx());
                    }
                }
                ui.label(
                    egui::RichText::new("auto-find clean IP · export configs · keep them healthy")
                        .color(GOLD_DIM),
                );
            });
            ui.add_space(4.0);
            ui.label(egui::RichText::new(&self.autopilot_status).color(TEXT));

            // Daemon health line.
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(self.daemon_status_line())
                    .color(GOLD_DIM)
                    .small(),
            );

            // Running tasks.
            if !self.running.is_empty() {
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(format!("⏳ running: {}", self.running.join(", ")))
                        .color(GOLD),
                );
            }
        });

        // ── Active profile card ───────────────────────────────────
        crate::views::section_card(ui, "Active profile", |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("profile").color(GOLD_DIM));
                ui.label(egui::RichText::new(&self.profile_id).color(TEXT).strong());
                let dstate = dastyab_core::daemon::load_daemon_state(&self.profile_id);
                if dstate.account_state.blocks_cycle() {
                    ui.label(
                        egui::RichText::new(format!(
                            "⚠ account {} — daemon waiting",
                            dstate.account_state.label()
                        ))
                        .color(GOLD)
                        .small(),
                    );
                }
            });
            ui.add_space(4.0);
            let backups = self.state.backups.len();
            crate::views::stat_chips(
                ui,
                &[
                    ("tokens", &self.state.tokens.len().to_string()),
                    ("clean IPs", &self.state.clean_ips.len().to_string()),
                    ("seeds", &self.state.seeds.len().to_string()),
                    ("history", &p.history.len().to_string()),
                    ("snapshots", &backups.to_string()),
                ],
            );
            if self.state.beacon_outbox > 0 {
                ui.label(
                    egui::RichText::new(format!(
                        "⚠ {} alert(s) queued for delivery",
                        self.state.beacon_outbox
                    ))
                    .color(egui::Color32::from_rgb(230, 160, 60)),
                );
            }
        });

        // ── Quick actions card ────────────────────────────────────
        crate::views::section_card(ui, "Quick actions", |ui| {
            ui.horizontal_wrapped(|ui| {
                if ui.button("🛰 Scan ONE clean IP").clicked() {
                    self.view = View::DeployScan;
                    self.note = "Run a scan from Deploy & Scan (or press Ctrl+2).".to_string();
                }
                if ui.button("🚀 Deploy worker").clicked() {
                    self.view = View::DeployScan;
                }
                if ui.button("➕ Add token").clicked() {
                    self.pending_action = Some(PendingDialogAction::AddToken);
                    self.dialog = Some(dialogs::prompt_two("Add token", "Label", "Token", true));
                }
                if ui.button("💾 Snapshot config").clicked() {
                    match dastyab_core::backup::export_profile_to_file(&self.profile_id, None) {
                        Ok(path) => {
                            self.note = format!("✓ Snapshot saved → {}", path.display());
                        }
                        Err(e) => self.note = e.explain(),
                    }
                }
                if ui.button("⚙ Settings").clicked() {
                    self.view = View::Settings;
                }
            });
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(
                    "Ctrl+1…9 / Ctrl+0 switch views; profile is shown in the sidebar.",
                )
                .color(GOLD_DIM)
                .small(),
            );
        });

        // ── Recent activity ───────────────────────────────────────
        crate::views::section_card(ui, "Recent activity", |ui| {
            let mut items: Vec<(i64, &'static str, egui::Color32, String)> = Vec::new();
            for r in p.history.iter().take(12) {
                let (tag, color) = if r.clean_ip {
                    ("clean-IP", egui::Color32::from_rgb(100, 170, 220))
                } else {
                    ("workers.dev", GOLD)
                };
                let host = if r.name.is_empty() {
                    &r.address
                } else {
                    &r.name
                };
                items.push((r.epoch as i64, tag, color, host.clone()));
            }
            for e in dastyab_core::journal::recent(&self.profile_id, 8) {
                items.push((
                    e.ts,
                    "journal",
                    egui::Color32::from_rgb(140, 200, 255),
                    e.detail.clone(),
                ));
            }
            for e in self.state.token_ledger.iter().take(8) {
                items.push((
                    e.epoch,
                    "token",
                    egui::Color32::from_rgb(200, 160, 255),
                    format!("{} — {}", e.label, e.note),
                ));
            }
            items.sort_unstable_by_key(|i| std::cmp::Reverse(i.0));
            if items.is_empty() {
                ui.label(
                    egui::RichText::new(
                        "Nothing yet — deploy, scan, or let the daemon run a few cycles.",
                    )
                    .color(GOLD_DIM),
                );
            } else {
                for (epoch, tag, color, title) in items.into_iter().take(8) {
                    ui.horizontal(|ui| {
                        crate::views::tag(ui, tag, color);
                        ui.add_space(4.0);
                        ui.label(egui::RichText::new(title).color(TEXT));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(
                                egui::RichText::new(crate::state::relative_ts(epoch))
                                    .color(GOLD_DIM)
                                    .small(),
                            );
                        });
                    });
                    ui.add_space(2.0);
                }
                ui.add_space(2.0);
                if ui.button("View full history →").clicked() {
                    self.view = View::History;
                }
            }
        });
    }

    /// Dedicated Live Log view — the async bridge streams every background
    /// task's output here. Supports clear, save-to-file, and filtering.
    fn log_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading(egui::RichText::new("Live log").color(GOLD));
        ui.label(
            egui::RichText::new(
                "Deploy, scans, autopilot, and daemon tasks stream their output here.",
            )
            .color(GOLD_DIM),
        );
        ui.add_space(6.0);

        ui.horizontal(|ui| {
            ui.checkbox(&mut self.log_auto_scroll, "auto-scroll");

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("🗑 Clear").clicked() {
                    self.log_lines.clear();
                }
                if ui.button("💾 Save to file").clicked() {
                    let dir = dastyab_core::cleanip::user_config_dir(&self.profile_id);
                    let target = match dir {
                        Ok(d) => d.join("activity.log"),
                        Err(_) => std::path::PathBuf::from("activity.log"),
                    };
                    let content = self.log_lines.join(
                        "
",
                    ) + "
";
                    match std::fs::write(&target, content) {
                        Ok(_) => {
                            self.note = format!("Log saved → {}", target.display());
                        }
                        Err(e) => self.note = format!("Save failed: {e}"),
                    }
                }
                if ui.button("📋 Copy").clicked() {
                    let joined = self.log_lines.join(
                        "
",
                    );
                    if !joined.is_empty() {
                        ui.ctx().copy_text(joined);
                        self.note = "Copied log to clipboard.".to_string();
                    }
                }
            });
        });
        ui.add_space(4.0);

        if self.log_lines.is_empty() {
            ui.label(
                egui::RichText::new("Idle — run a deploy, scan, or autopilot to see live output.")
                    .color(GOLD_DIM),
            );
            return;
        }

        let mut joined = self.log_lines.join(
            "
",
        );
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(self.log_auto_scroll)
            .max_height(520.0)
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut joined)
                        .desired_rows(20)
                        .desired_width(ui.available_width())
                        .font(egui::TextStyle::Monospace)
                        .interactive(false),
                );
            });
    }

    /// The app shell: left navigation sidebar + active view, with the active
    /// view name shown in gold.
    fn render_shell(&mut self, ui: &mut egui::Ui, p: &dastyab_core::store::profiles::Profile) {
        ui.horizontal(|ui| {
            // Left sidebar with the eight views.
            ui.vertical(|ui| {
                ui.set_width(180.0);
                ui.add_space(2.0);
                ui.label(
                    egui::RichText::new("DASTYAB")
                        .color(GOLD)
                        .strong()
                        .size(17.0),
                );
                ui.add_space(4.0);
                for v in View::ALL {
                    let active = self.view == v;
                    let text = if active {
                        egui::RichText::new(format!("{}  {}", v.glyph(), v.label()))
                            .color(GOLD)
                            .strong()
                    } else {
                        egui::RichText::new(format!("{}  {}", v.glyph(), v.label())).color(TEXT)
                    };
                    let resp = ui.selectable_label(active, text);
                    if resp.clicked() {
                        self.view = v;
                    }
                }
                ui.add_space(8.0);
                ui.separator();
                // Compact status footer: active profile + pending beacon alerts.
                ui.add_space(4.0);
                ui.label(egui::RichText::new("profile").color(GOLD_DIM).small());
                let prof_label = if self.profile_id.is_empty() {
                    "default".to_string()
                } else {
                    self.profile_id.clone()
                };
                ui.label(egui::RichText::new(prof_label).color(TEXT).strong().small());
                // Compact live counts for the active profile.
                ui.add_space(2.0);
                ui.label(
                    egui::RichText::new(format!(
                        "🔑 {} · 🌐 {}",
                        self.state.tokens.len(),
                        self.state.clean_ips.len()
                    ))
                    .color(GOLD_DIM)
                    .small(),
                );
                if self.state.beacon_outbox > 0 {
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(format!(
                            "⚠ {} queued alerts",
                            self.state.beacon_outbox
                        ))
                        .color(egui::Color32::from_rgb(230, 160, 60))
                        .small(),
                    );
                }
                // Live background-task status — visible from every tab so a
                // deploy/scan in progress is never "lost" when the user
                // switches views.
                if !self.running.is_empty() {
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(format!("⏳ {}", self.running.join(", ")))
                            .color(egui::Color32::from_rgb(120, 200, 255))
                            .small(),
                    );
                }
            });

            ui.separator();

            // Main content area — wrapped in a vertical ScrollArea so every
            // view (Settings, Tools, …) stays reachable when its content is
            // taller than the window. The sidebar remains fixed.
            egui::ScrollArea::vertical()
                .id_salt("main-content-scroll")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.vertical(|ui| {
                        // active view name in gold, with glyph
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(self.view.glyph())
                                    .color(GOLD)
                                    .size(20.0),
                            );
                            ui.heading(
                                egui::RichText::new(self.view.label())
                                    .color(GOLD)
                                    .size(22.0),
                            );
                        });
                        ui.separator();
                        match self.view {
                            View::Dashboard => self.dashboard_panel(ui, p),
                            View::DeployScan => self.deploy_panel(ui, p),
                            View::Profiles => self.profile_panel(ui, p),
                            View::Tokens => self.token_panel(ui, p),
                            View::CleanIps => self.cleanip_panel(ui, p),
                            View::History => history::show(ui, self, p),
                            View::Configs => self.configs_panel(ui),
                            View::Log => self.log_panel(ui),
                            View::Tools => self.tools_panel(ui, p),
                            View::Settings => self.settings_panel(ui, p),
                            View::Autonomy => self.autonomy_panel(ui, p),
                        }
                    });
                });
        });
    }

    fn deploy_panel(&mut self, ui: &mut egui::Ui, p: &dastyab_core::store::profiles::Profile) {
        ui.heading(egui::RichText::new("Deploy & Clean-IP").color(GOLD));

        // ---- Onboarding checklist (compact "am I set up?" summary) ----
        // Mirrors `dastyab onboard status`: offline, reads local state only.
        ui.add_space(4.0);
        let steps = dastyab_core::bootstrap::onboarding_status(Some(&self.profile_id));
        let all = [
            dastyab_core::bootstrap::OnboardingStep::Token,
            dastyab_core::bootstrap::OnboardingStep::Worker,
            dastyab_core::bootstrap::OnboardingStep::Bundle,
            dastyab_core::bootstrap::OnboardingStep::DaemonInstalled,
            dastyab_core::bootstrap::OnboardingStep::DaemonRunning,
        ];
        let remaining = all.iter().filter(|s| !steps.contains(s)).count();
        let ok_green = egui::Color32::from_rgb(90, 210, 120);
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("Setup status:")
                    .color(GOLD_DIM)
                    .strong(),
            );
            if remaining == 0 {
                ui.label(egui::RichText::new("✓ complete — protection live").color(ok_green));
            } else {
                ui.label(
                    egui::RichText::new(format!(
                        "{remaining}/{} step(s) pending — run `dastyab up`",
                        all.len()
                    ))
                    .color(GOLD),
                );
            }
            if ui
                .button("⟳")
                .on_hover_text("Refresh setup status")
                .clicked()
            {
                self.state.reload_pending = true;
            }
        });
        for step in all {
            let mark = if steps.contains(&step) { "✓" } else { "·" };
            let color = if steps.contains(&step) {
                ok_green
            } else {
                GOLD_DIM
            };
            ui.label(egui::RichText::new(format!("  {mark} {}", step.label())).color(color));
        }
        ui.separator();

        // ---- Autopilot toggle (the product) ----
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let (label, color) = if self.autopilot_on {
                ("🛡 PROTECTION: ON", egui::Color32::from_rgb(90, 210, 120))
            } else {
                ("🛡 PROTECTION: OFF", egui::Color32::from_rgb(220, 120, 90))
            };
            let on = ui
                .add(egui::Button::new(
                    egui::RichText::new(label).color(color).strong().size(16.0),
                ))
                .clicked();
            if on {
                // Toggle direction depends on current state.
                if self.autopilot_on {
                    self.autopilot_off();
                } else {
                    self.autopilot_on(ui.ctx());
                }
            }
            ui.label(
                egui::RichText::new("Auto-find clean IP · export configs · keep them healthy")
                    .color(GOLD_DIM),
            );
        });
        ui.add_space(4.0);
        ui.label(egui::RichText::new(&self.autopilot_status).color(TEXT));
        // Account-level notice (daemon state): if the CF account is
        // suspended/invalid, surface it inline so the user knows the
        // daemon is waiting — not broken.
        let dstate = dastyab_core::daemon::load_daemon_state(&self.profile_id);
        if dstate.account_state.blocks_cycle() {
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(format!(
                    "⚠ Account {} — daemon is waiting (polling every 15 min). Reactivate at dash.cloudflare.com."
                    , dstate.account_state.label()
                ))
                .color(GOLD)
                .heading(),
            );
        }
        // User-facing bundle quick actions.
        if let Ok(dir) = dastyab_core::cleanip::user_config_dir(&self.profile_id) {
            ui.horizontal(|ui| {
                if ui.button("📂 Open folder").clicked() {
                    open_folder(&dir);
                }
                if ui.button("📋 Copy path").clicked() {
                    ui.ctx().copy_text(dir.to_string_lossy().into_owned());
                }
                ui.label(
                    egui::RichText::new(dir.display().to_string())
                        .small()
                        .color(GOLD_DIM),
                );
            });
        }
        ui.separator();

        ui.horizontal(|ui| {
            ui.label("Scan count:");
            ui.add(egui::DragValue::new(&mut self.scan_count).range(1..=20000));
            ui.label("Workers:");
            ui.add(egui::DragValue::new(&mut self.scan_workers).range(1..=1000));
            ui.label("Timeout (s):");
            ui.add(egui::DragValue::new(&mut self.scan_timeout).range(1..=30));
        });
        ui.horizontal(|ui| {
            ui.label("Ports:");
            ui.add(egui::TextEdit::singleline(&mut self.scan_ports).desired_width(90.0));
            ui.checkbox(&mut self.scan_gentle, "gentle");
            ui.checkbox(&mut self.stealth_enabled, "stealth pacing");
        });
        if ui.button("Save scan settings").clicked() {
            self.save_scan_params();
            self.note = "Settings saved to profile.".to_string();
        }

        ui.add_space(6.0);
        ui.separator();

        ui.horizontal(|ui| {
            if ui
                .add_enabled(!self.running.contains(&"scan".to_string()), egui::Button::new(
                    if self.running.contains(&"scan".to_string()) {
                        "Scanning…"
                    } else {
                        "Scan ONE clean IP (stops on first)"
                    },
                ))
                .clicked()
            {
                let pid = self.profile_id.clone();
                let link = p
                    .history
                    .iter()
                    .find(|r| !r.clean_ip)
                    .map(|r| r.link.clone())
                    .or_else(|| p.history.first().map(|r| r.link.clone()));
                let params = ScanParams {
                    count: self.scan_count,
                    workers: self.scan_workers,
                    timeout_s: self.scan_timeout,
                    gentle: self.scan_gentle,
                    ports: self.scan_ports.clone(),
                    // Learn from what we found: bias the scan toward previously
                    // known-good clean IPs (and their neighborhoods) so every
                    // successful scan teaches the next one where to look.
                    seeds: self.scan_seed_ips(&pid),
                    ..Default::default()
                };
                match link {
                    Some(link) => {
                        self.running.push("scan".to_string());
                        self.push_log(&format!(
                            "[scan] starting clean-IP scan (count={}, workers={})",
                            params.count, params.workers
                        ));
                        bridge::spawn("scan", self.tx.clone(), async move {
                            match scan_once(&link, &params).await {
                                Ok(Some(ep)) => {
                                    let new_link = dastyab_core::scanner::rewrite_vless_with_endpoint(&link, &ep);
                                    let _ = remember_clean_ip(&pid, &ep);
                                    // Learn the found clean IP as a seed so
                                    // future scans + autopilot bias toward its
                                    // neighbourhood (self-improving scanner).
                                    let _ =
                                        dastyab_core::cf::ips::learn_clean_ip(&pid, &ep);
                                    let rec = VlessRecord {
                                        id: dastyab_core::store::new_id(),
                                        ts: dastyab_core::store::profiles::now_iso(),
                                        epoch: dastyab_core::store::now_ts(),
                                        uuid: String::new(),
                                        address: ep.clone(),
                                        port: 443,
                                        name: format!("clean-{ep}"),
                                        clean_ip: true,
                                        link: new_link.clone(),
                                        note: "clean IP".into(),
                                    };
                                    let _ = remember_vless(&pid, rec);
                                    Ok::<String, CFError>(format!(
                                        "Found working IP: {ep} — learned as a seed; link updated in profile."
                                    ))
                                }
                                Ok(None) => Err(CFError::new(
                                    "No clean IP",
                                    "No working clean IP was found.",
                                    "Try a larger scan count, a longer timeout, or a different port.",
                                )),
                                Err(e) => Err(e),
                            }
                        });
                    }
                    None => self.note = "No deployed config to scan against — deploy first.".to_string(),
                }
            }

            if ui
                .add_enabled(!self.running.contains(&"scan5".to_string()), egui::Button::new(
                    if self.running.contains(&"scan5".to_string()) {
                        "Scanning 5…"
                    } else {
                        "Scan 5 clean IPs"
                    },
                ))
                .clicked()
            {
                let pid = self.profile_id.clone();
                let link = p
                    .history
                    .iter()
                    .find(|r| !r.clean_ip)
                    .map(|r| r.link.clone())
                    .or_else(|| p.history.first().map(|r| r.link.clone()));
                let params = ScanParams {
                    count: self.scan_count,
                    workers: self.scan_workers,
                    timeout_s: self.scan_timeout,
                    gentle: self.scan_gentle,
                    ports: self.scan_ports.clone(),
                    // Learn from what we found: bias the scan toward previously
                    // known-good clean IPs (and their neighborhoods) so every
                    // successful scan teaches the next one where to look.
                    seeds: self.scan_seed_ips(&pid),
                    ..Default::default()
                };
                match link {
                    Some(link) => {
                        self.running.push("scan5".to_string());
                        bridge::spawn("scan5", self.tx.clone(), async move {
                            match scan_many(&link, &params, 5).await {
                                Ok(res) => {
                                    for ep in &res.endpoints {
                                        let _ = remember_clean_ip(&pid, ep);
                                        // Learn each found clean IP as a seed
                                        // so future scans bias toward these
                                        // neighbourhoods (self-improving).
                                        let _ =
                                            dastyab_core::cf::ips::learn_clean_ip(&pid, ep);
                                    }
                                    Ok::<String, CFError>(format!(
                                        "{} — {} (learned as seeds)",
                                        res.message,
                                        res.endpoints.join(", ")
                                    ))
                                }
                                Err(e) => Err(e),
                            }
                        });
                    }
                    None => self.note = "No deployed config to scan against.".to_string(),
                }
            }
        });

        if !self.last_link.is_empty() {
            ui.add_space(6.0);
            ui.label(egui::RichText::new("Latest clean-IP share link").color(GOLD_DIM));
            ui.add(
                egui::TextEdit::multiline(&mut self.last_link)
                    .desired_rows(3)
                    .font(egui::TextStyle::Monospace),
            );
        }

        ui.add_space(6.0);
        ui.separator();

        if ui
            .add_enabled(
                !self.running.contains(&"deploy".to_string()),
                egui::Button::new(if self.running.contains(&"deploy".to_string()) {
                    "Deploying…"
                } else {
                    "Deploy worker & make config"
                }),
            )
            .clicked()
        {
            let pid = self.profile_id.clone();
            // Prefer the store's active token (falls back to the first one).
            let token = dastyab_core::store::profiles::get_active_token(&pid)
                .ok()
                .flatten()
                .and_then(|label| {
                    dastyab_core::store::profiles::get_token(&pid, &label)
                        .ok()
                        .flatten()
                })
                .or_else(|| p.tokens.values().next().map(|t| t.token.clone()));
            match token {
                Some(token) => {
                    self.running.push("deploy".to_string());
                    let tx = self.tx.clone();
                    bridge::spawn("deploy", tx, async move {
                        match deploy_worker(&token, &pid).await {
                            Ok((host, link)) => {
                                // persist the fresh deployment so it survives
                                // restarts and shows in profile history
                                let rec = VlessRecord {
                                    id: dastyab_core::store::new_id(),
                                    ts: dastyab_core::store::profiles::now_iso(),
                                    epoch: dastyab_core::store::now_ts(),
                                    uuid: String::new(),
                                    address: host.clone(),
                                    port: 443,
                                    name: format!("{host}-edge"),
                                    clean_ip: false,
                                    link: link.clone(),
                                    note: "workers.dev deploy".into(),
                                };
                                let _ = remember_vless(&pid, rec);
                                Ok::<String, CFError>(format!("Deployed → {host}"))
                            }
                            Err(e) => Err(e),
                        }
                    });
                }
                None => self.note = "Add a token first.".to_string(),
            }
        }

        // history
        ui.separator();
        ui.heading(egui::RichText::new("History").color(GOLD));
        for r in p.history.iter().take(8) {
            let tag = if r.clean_ip {
                "clean-IP"
            } else {
                "workers.dev"
            };
            ui.label(format!("• {} [{}] {}", r.name, tag, r.ts));
        }

        // live log pane (the async bridge streams debug lines here)
        ui.separator();
        ui.heading(egui::RichText::new("Live log").color(GOLD));
        if self.log_lines.is_empty() {
            ui.label(
                egui::RichText::new("Idle — deploy or scan to see live debug output.")
                    .color(GOLD_DIM),
            );
        } else {
            let mut joined = self.log_lines.join("\n");
            ui.add(
                egui::TextEdit::multiline(&mut joined)
                    .desired_rows(8)
                    .font(egui::TextStyle::Monospace)
                    .interactive(false),
            );
        }
    }

    fn profile_panel(&mut self, ui: &mut egui::Ui, _p: &dastyab_core::store::profiles::Profile) {
        if let Some(act) = profiles::show(ui, self, self.selected_profile) {
            if let Some(dlg) = profiles::run_action(self, act) {
                self.dialog = Some(dlg);
            }
        }
    }

    fn token_panel(&mut self, ui: &mut egui::Ui, _p: &dastyab_core::store::profiles::Profile) {
        if let Some(act) = tokens::show(ui, self) {
            if let Some(dlg) = tokens::run_action(self, act) {
                self.dialog = Some(dlg);
            }
        }
    }

    fn cleanip_panel(&mut self, ui: &mut egui::Ui, _p: &dastyab_core::store::profiles::Profile) {
        if let Some(act) = cleanip::show(ui, self) {
            match act {
                cleanip::CleanipAction::CopyAll => {
                    let all = self.state.clean_ips.join("\n");
                    if !all.is_empty() {
                        ui.ctx().copy_text(all);
                        self.note = format!("Copied {} clean IP(s).", self.state.clean_ips.len());
                    } else {
                        self.note = "No clean IPs to copy.".to_string();
                    }
                }
                cleanip::CleanipAction::Export => {
                    let all = self.state.clean_ips.join("\n");
                    if all.is_empty() {
                        self.note = "No clean IPs to export.".to_string();
                    } else {
                        ui.ctx().copy_text(all.clone());
                        self.note = format!(
                            "Exported {} clean IP(s) to clipboard.",
                            self.state.clean_ips.len()
                        );
                        self.last_link = all;
                    }
                }
                other => {
                    if let Some(dlg) = cleanip::run_action(self, other) {
                        self.dialog = Some(dlg);
                    }
                }
            }
        }

        // Zero-result diagnostics: explain "why nothing found" in plain language.
        if self.state.clean_ips.is_empty() {
            if let Some(cause) = &self.last_cause {
                ui.add_space(8.0);
                ui.separator();
                ui.heading(egui::RichText::new("Why no clean IPs?").color(GOLD));
                ui.label(egui::RichText::new(cause).color(TEXT));
                if !self.last_action_label.is_empty()
                    && ui.button(&self.last_action_label).clicked()
                {
                    // One tap to open the Cloudflare dashboard.
                    ui.ctx().open_url(egui::output::OpenUrl::new_tab(
                        "https://dash.cloudflare.com/?to=/:account/workers",
                    ));
                }
            }
        }
    }

    fn configs_panel(&mut self, ui: &mut egui::Ui) {
        if let Some(act) = configs::show(ui, self) {
            if let Some(dlg) = configs::run_action(self, act) {
                self.dialog = Some(dlg);
            }
        }
    }

    /// Install (if absent) and start the persistent protection daemon through
    /// systemd --user. This closes the last manual step: the app runs
    /// `systemctl --user enable --now` itself instead of printing the command.
    fn daemon_install_start(&mut self) {
        let pid = self.profile_id.clone();
        let current_exe = std::env::current_exe();
        let exe = match current_exe {
            Ok(p) => p,
            Err(e) => {
                self.daemon_note = format!("Cannot locate the binary: {e}");
                return;
            }
        };
        // Write the unit (idempotent) and enable+start it.
        match dastyab_core::bootstrap::ensure_daemon_installed(&exe, &pid, true) {
            Ok(_outcome) => {
                // Report whether the daemon will survive a reboot *before*
                // login (loginctl linger). This is the resilience property the
                // user cares about: a total-blackout reboot with nobody logged
                // in must still come back with protection running.
                let linger = match dastyab_core::daemon::is_linger_enabled() {
                    Some(true) => "boot autostart enabled (starts before login).",
                    Some(false) => "boot autostart not active — daemon starts at login only.",
                    None => "boot autostart unknown (loginctl unavailable).",
                };
                self.daemon_note = format!(
                    "Daemon installed and enabled (systemd --user, restarts on boot). {linger}"
                );
            }
            Err(e) => {
                self.daemon_note = format!("Daemon install failed: {}", e.brief());
            }
        }
    }

    /// Stop the daemon via the stop-file (clean, loop exits on next tick).
    fn daemon_stop(&mut self) {
        let cfg = dastyab_core::daemon::DaemonConfig::new(&self.profile_id);
        match dastyab_core::store::write_json(&cfg.stop_file, &true) {
            Ok(()) => {
                self.daemon_note =
                    "Stop requested — the daemon exits on its next tick.".to_string();
            }
            Err(e) => {
                self.daemon_note = format!("Stop failed: {e}");
            }
        }
    }

    /// Run the blackout self-test: probe each fallback-ladder rung
    /// (Direct → DoH → DoT → DNS tunnel) with the real transports and render a
    /// per-tier verdict. This is the GUI twin of `dastyab drill`.
    fn run_blackout_drill(&mut self) {
        let pid = self.profile_id.clone();
        let tx = self.tx.clone();
        let tx2 = tx.clone();
        bridge::spawn("blackout-drill", tx, async move {
            use dastyab_core::connectivity::{drill_all_tiers, RealLadderProbe};
            let resolver = dastyab_core::doh::DohResolver::new();
            let report = drill_all_tiers(RealLadderProbe {
                profile: &pid,
                resolver: &resolver,
            })
            .await;
            let mut out = String::from("Blackout drill — fallback ladder (top-down):\n");
            let mut survivors = 0;
            for (tier, verdict) in report {
                let mark = if verdict.ok { "OK" } else { "FAIL" };
                out.push_str(&format!("  {mark}  {}  {}\n", tier.label(), verdict.note));
                if verdict.ok {
                    survivors += 1;
                }
            }
            out.push_str(&format!("{survivors} of 4 tiers reachable."));
            let _ = tx2.send(crate::bridge::UiEvent::Done {
                task: "blackout-drill".to_string(),
                summary: out,
            });
            Ok::<String, CFError>("blackout-drill done".to_string())
        });
    }

    /// Refresh the daemon status line in the Blackout settings section.
    fn daemon_status_line(&self) -> String {
        let cfg = dastyab_core::daemon::DaemonConfig::new(&self.profile_id);
        let running = dastyab_core::daemon::is_daemon_running(&cfg.pid_file);
        let st = dastyab_core::daemon::load_daemon_state(&self.profile_id);
        let up = if running && st.started_at > 0 {
            let secs = (dastyab_core::store::now_ts() as i64) - st.started_at;
            format!(", uptime {secs}s")
        } else {
            String::new()
        };
        let stre = if st.failure_streak > 0 {
            format!(", failure streak {}", st.failure_streak)
        } else {
            String::new()
        };
        // Live blackout-resilience posture: the survival plan the daemon last
        // computed (normal / dns-hijacked / total-blackout) and the best
        // transport tier it reached (direct / DoH / DoT / dns-tunnel).
        let survival = if !st.survival_plan.is_empty() {
            format!(", survival={}", st.survival_plan)
        } else {
            String::new()
        };
        let tier = if !st.network_tier.is_empty() {
            format!(", tier={}", st.network_tier)
        } else {
            String::new()
        };
        // Boot autostart (loginctl linger): does the daemon come back after a
        // reboot *before* login? This is the blackout-reboot survivability bit.
        let boot = match dastyab_core::daemon::is_linger_enabled() {
            Some(true) => ", boot autostart=on".to_string(),
            Some(false) => ", boot autostart=off (login only)".to_string(),
            None => String::new(),
        };
        format!(
            "Daemon {} · last cycle {}{}{}{}{}",
            if running { "RUNNING" } else { "STOPPED" },
            up,
            stre,
            survival,
            tier,
            boot
        )
    }

    fn settings_panel(&mut self, ui: &mut egui::Ui, p: &dastyab_core::store::profiles::Profile) {
        ui.heading(egui::RichText::new("Settings").color(GOLD));
        ui.label(
            egui::RichText::new(
                "Every knob is per-profile, persisted instantly, and read live by the daemon.",
            )
            .color(GOLD_DIM),
        );
        ui.add_space(6.0);

        // Scan & behavior defaults.
        crate::views::section_card(ui, "Scan & behavior defaults", |ui| {
            ui.horizontal(|ui| {
                ui.label("Scan count:");
                ui.add(egui::DragValue::new(&mut self.scan_count).range(1..=20000));
                ui.label("Workers:");
                ui.add(egui::DragValue::new(&mut self.scan_workers).range(1..=1000));
                ui.label("Timeout (s):");
                ui.add(egui::DragValue::new(&mut self.scan_timeout).range(1..=30));
            });
            ui.horizontal(|ui| {
                ui.label("Ports:");
                ui.add(egui::TextEdit::singleline(&mut self.scan_ports).desired_width(90.0));
                ui.checkbox(&mut self.scan_gentle, "gentle scan");
                ui.checkbox(&mut self.stealth_enabled, "stealth pacing");
            });
            ui.horizontal(|ui| {
                if ui.button("Save scan defaults").clicked() {
                    self.save_scan_params();
                    self.note = "Scan defaults saved to profile.".to_string();
                }
                if ui
                    .button("Reset settings to defaults")
                    .on_hover_text("Reset every per-profile setting to its default")
                    .clicked()
                {
                    self.pending_action = Some(PendingDialogAction::ResetSettings);
                    self.dialog = Some(dialogs::confirm(
                        "Reset settings to defaults",
                        "Reset ALL profile settings (scan, protection pacing, notifications, desync, scheduled maintenance) to defaults? This does not touch tokens or clean IPs.",
                        true,
                    ));
                }
                ui.label(
                    egui::RichText::new("Used by Deploy & Scan and the automatic monitor.")
                        .color(GOLD_DIM)
                        .small(),
                );
            });
        });

        // Active profile / account summary.
        crate::views::section_card(ui, "Profile & account", |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Active profile:").color(GOLD_DIM));
                ui.label(egui::RichText::new(&self.profile_id).color(TEXT).strong());
            });
            let active_account = &p.config.active_account;
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Cloudflare account:").color(GOLD_DIM));
                if active_account.is_empty() {
                    ui.label(
                        egui::RichText::new("none saved yet — deploy once to remember it")
                            .color(GOLD_DIM),
                    );
                } else {
                    ui.label(egui::RichText::new(active_account).color(TEXT).monospace());
                }
            });
            let worker_count = p.config.worker_set.workers.len();
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Workers in set:").color(GOLD_DIM));
                ui.label(
                    egui::RichText::new(format!("{worker_count}"))
                        .color(TEXT)
                        .strong(),
                );
            });
        });

        ui.add_space(10.0);
        ui.separator();
        ui.heading(egui::RichText::new("Backup / restore").color(GOLD));
        ui.horizontal(|ui| {
            if ui.button("Backup this profile").clicked() {
                match dastyab_core::backup::export_profile_to_file(&self.profile_id, None) {
                    Ok(path) => self.backup_output = format!("✓ Backed up → {}", path.display()),
                    Err(e) => self.backup_output = e.explain(),
                }
            }
            if ui.button("List backups").clicked() {
                self.backup_output = dastyab_core::backup::backup_summary();
            }
        });
        if !self.backup_output.is_empty() {
            ui.add(
                egui::TextEdit::multiline(&mut self.backup_output)
                    .desired_rows(4)
                    .font(egui::TextStyle::Monospace),
            );
        }

        // ── Saved Configs manager ─────────────────────────────────────
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let caret = if self.sec_backups { "▾" } else { "▸" };
            if ui
                .button(
                    egui::RichText::new(format!("{caret} Saved Configs"))
                        .color(GOLD)
                        .strong(),
                )
                .on_hover_text("Toggle the saved-configs manager")
                .clicked()
            {
                self.sec_backups = !self.sec_backups;
            }
            ui.label(
                egui::RichText::new("everything per-profile, snapshot as a JSON bundle")
                    .color(GOLD_DIM)
                    .small(),
            );
            if ui
                .button("➕ Snapshot now")
                .on_hover_text("Back up the current profile to the backup folder")
                .clicked()
            {
                match dastyab_core::backup::export_profile_to_file(&self.profile_id, None) {
                    Ok(path) => {
                        self.backup_output = format!("✓ Snapshot saved → {}", path.display())
                    }
                    Err(e) => self.backup_output = e.explain(),
                }
            }
        });
        if self.sec_backups {
            ui.separator();

            // Search + refresh row.
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Search:").color(GOLD_DIM));
                ui.add(
                    egui::TextEdit::singleline(&mut self.backups_search)
                        .hint_text("filter saved configs…")
                        .desired_width(180.0),
                );
                egui::ComboBox::from_id_salt("backup_sort")
                    .selected_text(format!("sort: {}", self.backup_sort.label()))
                    .show_ui(ui, |ui| {
                        for s in [
                            BackupSort::Newest,
                            BackupSort::Oldest,
                            BackupSort::Name,
                            BackupSort::Size,
                        ] {
                            ui.selectable_value(&mut self.backup_sort, s, s.label());
                        }
                    });
                if ui
                    .button("⟳")
                    .on_hover_text("Refresh the saved-configs list")
                    .clicked()
                {
                    self.state.reload_pending = true;
                }
                if ui
                    .button("📂 Open folder")
                    .on_hover_text("Open the backup folder in your file manager")
                    .clicked()
                {
                    open_folder(&dastyab_core::backup::backup_dir());
                }
                if ui
                    .button("📥 Import from path")
                    .on_hover_text("Restore a bundle from an arbitrary file path")
                    .clicked()
                {
                    self.pending_action = Some(PendingDialogAction::ImportBackupFromPath);
                    self.dialog = Some(dialogs::prompt_text(
                        "Import backup from file",
                        "Full path to a .json bundle",
                    ));
                }
                ui.label(
                    egui::RichText::new(format!("{} saved config(s)", self.state.backups.len()))
                        .color(GOLD_DIM)
                        .small(),
                );
            });

            let query = self.backups_search.trim().to_lowercase();
            let mut backups: Vec<_> = self
                .state
                .backups
                .iter()
                .filter(|b| {
                    query.is_empty()
                        || b.profile_name.to_lowercase().contains(&query)
                        || b.profile_id.to_lowercase().contains(&query)
                })
                .collect();
            match self.backup_sort {
                BackupSort::Newest => {
                    backups.sort_by(|a, b| b.created_at.cmp(&a.created_at));
                }
                BackupSort::Oldest => {
                    backups.sort_by(|a, b| a.created_at.cmp(&b.created_at));
                }
                BackupSort::Name => {
                    backups.sort_by(|a, b| a.profile_name.cmp(&b.profile_name));
                }
                BackupSort::Size => {
                    backups.sort_by_key(|a| std::cmp::Reverse(a.size));
                }
            }

            if backups.is_empty() {
                ui.label(
                    egui::RichText::new(if query.is_empty() {
                        "No saved configs yet — take a snapshot above."
                    } else {
                        "No saved config matches that search."
                    })
                    .color(GOLD_DIM),
                );
            } else {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .max_height(220.0)
                    .show(ui, |ui| {
                        for b in backups {
                            egui::Frame::new()
                                .fill(PANEL)
                                .inner_margin(egui::Margin::symmetric(8, 6))
                                .corner_radius(6.0)
                                .stroke(egui::Stroke::new(1.0, crate::views::CARD_STROKE))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.vertical(|ui| {
                                            ui.label(
                                                egui::RichText::new(&b.profile_name)
                                                    .color(TEXT)
                                                    .strong(),
                                            );
                                            ui.label(
                                                egui::RichText::new(format!(
                                                    "{} · {} · {}",
                                                    dastyab_core::backup::human_size(b.size),
                                                    crate::state::relative_ts(
                                                        chrono::NaiveDateTime::parse_from_str(
                                                            &b.created_at,
                                                            "%Y-%m-%d %H:%M:%S"
                                                        )
                                                        .ok()
                                                        .map(|d| d.and_utc().timestamp())
                                                        .unwrap_or(0)
                                                    ),
                                                    b.created_at
                                                ))
                                                .color(GOLD_DIM)
                                                .small(),
                                            );
                                        });
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                if ui
                                                    .button("🗑")
                                                    .on_hover_text("Delete this snapshot")
                                                    .clicked()
                                                {
                                                    match dastyab_core::backup::delete_backup(
                                                        std::path::Path::new(&b.path),
                                                    ) {
                                                        Ok(_) => {
                                                            self.backup_output = format!(
                                                                "Deleted snapshot {}.",
                                                                b.path
                                                            );
                                                            self.state.reload_pending = true;
                                                        }
                                                        Err(e) => {
                                                            self.backup_output = e.explain()
                                                        }
                                                    }
                                                }
                                                if ui
                                                    .button("📄")
                                                    .on_hover_text("Preview this snapshot (read the JSON)")
                                                    .clicked()
                                                {
                                                    match std::fs::read_to_string(&b.path) {
                                                        Ok(text) => {
                                                            self.backup_output = text;
                                                        }
                                                        Err(e) => {
                                                            self.backup_output = format!(
                                                                "Read failed: {e}"
                                                            )
                                                        }
                                                    }
                                                }
                                                if ui
                                                    .button("📋")
                                                    .on_hover_text("Copy this snapshot's path")
                                                    .clicked()
                                                {
                                                    ui.ctx().copy_text(b.path.clone());
                                                    self.note =
                                                        format!("Copied path: {}", b.path);
                                                }
                                                if ui
                                                    .button("Restore → new")
                                                    .on_hover_text("Restore this snapshot into a new profile")
                                                    .clicked()
                                                {
                                                    match dastyab_core::backup::import_profile_from_file(
                                                        std::path::Path::new(&b.path),
                                                    ) {
                                                        Ok(pid) => {
                                                            self.backup_output = format!(
                                                                "✓ Restored into new profile '{pid}'."
                                                            );
                                                            self.state.reload_pending = true;
                                                        }
                                                        Err(e) => {
                                                            self.backup_output = e.explain()
                                                        }
                                                    }
                                                }
                                                if ui
                                                    .button("Restore → here")
                                                    .on_hover_text("Overwrite THIS profile from this snapshot")
                                                    .clicked()
                                                {
                                                    self.pending_action = Some(
                                                        PendingDialogAction::RestoreBackupIntoCurrent(
                                                            b.path.clone(),
                                                        ),
                                                    );
                                                    self.dialog = Some(dialogs::confirm(
                                                        "Restore into current profile",
                                                        format!(
                                                            "Overwrite profile '{}' with this snapshot? Tokens, config, clean IPs and history will be replaced. This cannot be undone.",
                                                            self.profile_id
                                                        ),
                                                        true,
                                                    ));
                                                }
                                            },
                                        );
                                    });
                                });
                            ui.add_space(4.0);
                        }
                    });
            }
        } // if self.sec_backups

        ui.add_space(10.0);
        ui.separator();
        ui.heading(egui::RichText::new("Notifications").color(GOLD));
        ui.checkbox(
            &mut self.beacon_enabled,
            "Enable push notifications (Telegram / webhook)",
        );
        ui.horizontal(|ui| {
            egui::ComboBox::from_id_salt("beacon_ch")
                .selected_text(&self.beacon_channel)
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut self.beacon_channel,
                        "Telegram".to_string(),
                        "Telegram",
                    );
                    ui.selectable_value(&mut self.beacon_channel, "Webhook".to_string(), "Webhook");
                });
            ui.label("channel");
        });
        if self.beacon_channel == "Telegram" {
            ui.label("Bot token:");
            ui.add(
                egui::TextEdit::singleline(&mut self.beacon_token)
                    .password(true)
                    .desired_width(260.0),
            );
            ui.label("Chat ID:");
            ui.add(egui::TextEdit::singleline(&mut self.beacon_target).desired_width(260.0));
        } else {
            ui.label("Webhook URL:");
            ui.add(egui::TextEdit::singleline(&mut self.beacon_target).desired_width(260.0));
        }
        ui.horizontal(|ui| {
            ui.label("Rate limit (s/event):");
            ui.add(egui::DragValue::new(&mut self.beacon_rate_limit).range(1..=86400));
        });
        ui.add_space(6.0);
        ui.separator();
        ui.colored_label(GOLD, "Failover channel (used when the primary is blocked)");
        ui.label("Telegram is sometimes blocked in Iran — if the primary channel");
        ui.label("fails, alerts auto-route to this backup. Configure it once here.");
        ui.checkbox(&mut self.beacon_failover_enabled, "Enable failover channel");
        if self.beacon_failover_enabled {
            ui.horizontal(|ui| {
                egui::ComboBox::from_id_salt("beacon_fo_ch")
                    .selected_text(&self.beacon_failover_channel)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.beacon_failover_channel,
                            "Telegram".to_string(),
                            "Telegram",
                        );
                        ui.selectable_value(
                            &mut self.beacon_failover_channel,
                            "Webhook".to_string(),
                            "Webhook",
                        );
                    });
                ui.label("failover channel");
            });
            if self.beacon_failover_channel == "Telegram" {
                ui.label("Failover bot token:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.beacon_failover_token)
                        .password(true)
                        .desired_width(260.0),
                );
                ui.label("Failover Chat ID:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.beacon_failover_target)
                        .desired_width(260.0),
                );
            } else {
                ui.label("Failover webhook URL:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.beacon_failover_target)
                        .desired_width(260.0),
                );
            }
        }
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui.button("Save notifications").clicked() {
                self.save_beacon();
            }
            if ui.button("Send test").clicked() {
                self.send_beacon_test();
            }
        });
        // Durable outbox: alerts queued during a blackout / blocked channel.
        let queued = self.state.beacon_outbox;
        if queued > 0 {
            ui.horizontal(|ui| {
                ui.colored_label(
                    egui::Color32::from_rgb(212, 175, 55),
                    format!("⚠ {queued} alert(s) queued during blackout — awaiting delivery"),
                );
                if ui.button("Flush now").clicked() {
                    self.state.reload_pending = true;
                    self.flush_beacon_outbox();
                }
            });
        } else {
            ui.label("No queued alerts (outbox empty).");
        }
        if !self.beacon_note.is_empty() {
            ui.colored_label(GOLD, &self.beacon_note);
        }

        ui.add_space(10.0);
        ui.separator();
        ui.heading(egui::RichText::new("Blackout resilience").color(GOLD));
        ui.label("Total-blackout fallback: when direct/DoH/DoT all fail, the app");
        ui.label("uses a DNS tunnel hosted on your own VPS. Configure it here once.");
        ui.horizontal(|ui| {
            ui.label("VPS host (IP):");
            ui.add(egui::TextEdit::singleline(&mut self.vps_host).desired_width(220.0));
        });
        ui.horizontal(|ui| {
            ui.label("SSH user:");
            ui.add(egui::TextEdit::singleline(&mut self.vps_user).desired_width(120.0));
            ui.label("SSH port:");
            ui.add(egui::DragValue::new(&mut self.vps_port).range(1..=65535));
        });
        ui.horizontal(|ui| {
            ui.label("SSH key path:");
            ui.add(egui::TextEdit::singleline(&mut self.vps_key).desired_width(240.0));
        });
        ui.horizontal(|ui| {
            ui.label("Base DNS domain:");
            ui.add(egui::TextEdit::singleline(&mut self.vps_domain).desired_width(200.0));
        });
        ui.horizontal(|ui| {
            if ui.button("Save VPS config").clicked() {
                self.save_vps();
            }
            if ui.button("Deploy DNS tunnel (VPS)").clicked() {
                self.deploy_vps_tunnel();
            }
        });
        ui.horizontal(|ui| {
            if ui.button("⚡ Deploy Worker tunnel (no VPS)").clicked() {
                self.deploy_worker_tunnel_gui();
            }
        });
        if !self.vps_note.is_empty() {
            ui.horizontal(|ui| {
                ui.colored_label(GOLD, &self.vps_note);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("✕").on_hover_text("Dismiss").clicked() {
                        self.vps_note.clear();
                    }
                });
            });
        }
        if !self.worker_tunnel_note.is_empty() {
            ui.horizontal(|ui| {
                ui.colored_label(GOLD, &self.worker_tunnel_note);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("✕").on_hover_text("Dismiss").clicked() {
                        self.worker_tunnel_note.clear();
                    }
                });
            });
        }

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui.button("🏥 Blackout self-test").clicked() {
                self.run_blackout_drill();
            }
        });
        if !self.drill_output.is_empty() {
            ui.add(
                egui::TextEdit::multiline(&mut self.drill_output)
                    .desired_rows(6)
                    .desired_width(420.0)
                    .font(egui::TextStyle::Monospace)
                    .interactive(false),
            );
        }

        ui.add_space(10.0);
        ui.separator();
        ui.heading(egui::RichText::new("Daemon").color(GOLD));
        ui.label("Persistent protection daemon: safe to run 24/7. It scans,");
        ui.label("resurfaces, fails-over, and reports — no manual care needed.");
        ui.label(self.daemon_status_line());
        ui.horizontal(|ui| {
            if ui.button("Install + start (systemd)").clicked() {
                self.daemon_install_start();
            }
            if ui.button("Stop").clicked() {
                self.daemon_stop();
            }
        });
        if !self.daemon_note.is_empty() {
            ui.colored_label(GOLD, &self.daemon_note);
        }

        ui.add_space(10.0);
        ui.separator();
        ui.heading(egui::RichText::new("Protection pacing / blackout").color(GOLD));
        ui.label("Tune how the daemon behaves on a slow or partially-blocked network.");
        ui.label("0 = system default. The daemon reads these every tick — no restart.");
        ui.horizontal(|ui| {
            ui.label("Light check (s):");
            ui.add(egui::DragValue::new(&mut self.light_timeout_s).range(0..=3600));
            ui.label("Deep check (s):");
            ui.add(egui::DragValue::new(&mut self.deep_timeout_s).range(0..=3600));
        });
        ui.horizontal(|ui| {
            ui.label("Max backoff (s):");
            ui.add(egui::DragValue::new(&mut self.max_backoff_s).range(0..=86400));
            ui.label("Blackout poll (s):");
            ui.add(egui::DragValue::new(&mut self.network_down_sleep_s).range(0..=3600));
            ui.label("Light check cadence (s):");
            ui.add(egui::DragValue::new(&mut self.light_check_interval_s).range(30..=3600));
            if ui.button("Save pacing").clicked() {
                self.save_timeouts();
            }
        });
        ui.horizontal(|ui| {
            ui.label("Scheduled self-test cadence (s):");
            ui.add(egui::DragValue::new(&mut self.drill_interval_s).range(300..=604800));
        });
        ui.label("On a degraded tier the deep budget is auto-extended 2× (capped at");
        ui.label("1800s). Lower 'Max backoff' so a long blackout re-rotates faster.");
        if !self.timeouts_note.is_empty() {
            ui.colored_label(GOLD, &self.timeouts_note);
        }

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.checkbox(
                &mut self.auto_rotate_enabled,
                "auto-rotate to a backup token when the active one is blocked",
            );
            if ui.button("Save auto-rotate").clicked() {
                self.save_auto_rotate();
            }
        });
        ui.label("When Cloudflare blocks/invalidates the active token, the app verifies your");
        ui.label("other saved tokens and swaps to the first working one automatically — no manual");
        ui.label("`dastyab token recover` step. The daemon holds cycles until it can rotate.");
        if !self.auto_rotate_note.is_empty() {
            ui.colored_label(GOLD, &self.auto_rotate_note);
        }

        ui.add_space(10.0);
        ui.separator();
        ui.heading(egui::RichText::new("Anti-DPI desync").color(GOLD));
        ui.label("Stateful DPI can reassemble the WS-upgrade request and reset the");
        ui.label("connection. Writing it as irregular segments makes that impossible.");
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.desync_enabled, "fragment WS-upgrade writes");
        });
        ui.horizontal(|ui| {
            ui.label("Min fragment (B):");
            ui.add(egui::DragValue::new(&mut self.desync_min).range(1..=512));
            ui.label("Max fragment (B):");
            ui.add(egui::DragValue::new(&mut self.desync_max).range(1..=1024));
        });
        ui.horizontal(|ui| {
            ui.label("Inter-fragment delay (us):");
            ui.add(egui::DragValue::new(&mut self.desync_delay_us).range(0..=100000));
            if ui.button("Save desync config").clicked() {
                self.save_desync();
            }
        });
        if !self.desync_note.is_empty() {
            ui.colored_label(GOLD, &self.desync_note);
        }

        ui.add_space(10.0);
        ui.separator();
        ui.heading(egui::RichText::new("Scheduled self-maintenance").color(GOLD));
        ui.label("These run automatically in the daemon — no manual steps. Set them");
        ui.label("once here and the app keeps itself backed up and hard to fingerprint.");
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.backup_auto_enabled, "auto-backup");
            ui.label("every");
            ui.add(egui::DragValue::new(&mut self.backup_auto_interval).range(60..=604800));
            ui.label("s, keep");
            ui.add(egui::DragValue::new(&mut self.backup_auto_keep).range(1..=100));
            ui.label("copies");
            if ui.button("Save backup").clicked() {
                self.save_backup_auto();
            }
        });
        if !self.backup_auto_note.is_empty() {
            ui.colored_label(GOLD, &self.backup_auto_note);
        }
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.mutation_enabled, "rotate worker signature");
            ui.label("every");
            ui.add(egui::DragValue::new(&mut self.mutation_interval).range(3600..=604800));
            ui.label("s");
            ui.checkbox(&mut self.mutation_rotate_path, "path too");
            if ui.button("Save rotation").clicked() {
                self.save_mutation();
            }
        });
        if !self.mutation_note.is_empty() {
            ui.colored_label(GOLD, &self.mutation_note);
        }

        ui.add_space(10.0);
        ui.separator();
        ui.heading(egui::RichText::new("Zero-touch Hetzner VPS").color(GOLD));
        ui.label("No VPS yet? Paste a Hetzner Cloud API token and the app provisions");
        ui.label("a server, then deploys the DNS tunnel to it. (Read/write token.)");
        ui.horizontal(|ui| {
            ui.label("Hetzner API token:");
            ui.add(egui::TextEdit::singleline(&mut self.hz_token).desired_width(280.0));
        });
        ui.horizontal(|ui| {
            ui.label("Location:");
            ui.add(egui::TextEdit::singleline(&mut self.hz_location).desired_width(90.0));
            ui.label("Server type:");
            ui.add(egui::TextEdit::singleline(&mut self.hz_server_type).desired_width(90.0));
        });
        if ui.button("Provision VPS + deploy tunnel").clicked() {
            self.provision_vps_tunnel();
        }

        ui.add_space(10.0);
        ui.separator();
        ui.heading(egui::RichText::new("Multi-worker redundancy").color(GOLD));
        ui.label("Deploy several workers in parallel so one worker dying doesn't");
        ui.label("kill your tunnel. The daemon auto-fails-over to a healthy standby.");
        ui.horizontal(|ui| {
            ui.label("Workers to keep:");
            ui.add(egui::DragValue::new(&mut self.mw_count).range(1..=3));
            if ui.button("Deploy / maintain worker set").clicked() {
                self.deploy_multi_worker();
            }
        });
        if !self.mw_note.is_empty() {
            ui.colored_label(GOLD, &self.mw_note);
        }
    }

    fn tools_panel(&mut self, ui: &mut egui::Ui, p: &dastyab_core::store::profiles::Profile) {
        ui.heading(egui::RichText::new("Security audit").color(GOLD));
        if ui.button("Run security audit").clicked() {
            self.audit_output = dastyab_core::security::audit().render();
        }
        if !self.audit_output.is_empty() {
            ui.add(
                egui::TextEdit::multiline(&mut self.audit_output)
                    .desired_rows(8)
                    .font(egui::TextStyle::Monospace),
            );
        }

        ui.add_space(10.0);
        ui.separator();
        ui.heading(egui::RichText::new("Backup / restore").color(GOLD));
        ui.horizontal(|ui| {
            if ui.button("Backup this profile").clicked() {
                match dastyab_core::backup::export_profile_to_file(&self.profile_id, None) {
                    Ok(path) => self.backup_output = format!("✓ Backed up → {}", path.display()),
                    Err(e) => self.backup_output = e.explain(),
                }
            }
            if ui.button("List backups").clicked() {
                self.backup_output = dastyab_core::backup::backup_summary();
            }
        });
        if !self.backup_output.is_empty() {
            ui.add(
                egui::TextEdit::multiline(&mut self.backup_output)
                    .desired_rows(4)
                    .font(egui::TextStyle::Monospace),
            );
        }

        ui.add_space(10.0);
        ui.separator();
        ui.heading(egui::RichText::new("Export client config").color(GOLD));
        let mut chosen = "clash".to_string();
        ui.horizontal(|ui| {
            egui::ComboBox::from_id_salt("fmt")
                .selected_text(&chosen)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut chosen, "clash".to_string(), "Clash");
                    ui.selectable_value(&mut chosen, "singbox".to_string(), "sing-box");
                    ui.selectable_value(&mut chosen, "v2rayn".to_string(), "v2rayN");
                    ui.selectable_value(&mut chosen, "link".to_string(), "share-link");
                });
            if ui.button("Render").clicked() {
                if let Some(rec) = p.history.first() {
                    let mut vless = VlessProfile {
                        uuid: rec.uuid.clone(),
                        address: rec.address.clone(),
                        port: rec.port,
                        name: rec.name.clone(),
                        ..Default::default()
                    };
                    vless.normalize();
                    if let Some(fmt) = dastyab_core::export::ExportFormat::parse(&chosen) {
                        match dastyab_core::export::render(&vless, fmt) {
                            Ok(text) => self.export_output = text,
                            Err(e) => self.export_output = e.explain(),
                        }
                    }
                } else {
                    self.export_output =
                        "No saved config to export — deploy or scan first.".to_string();
                }
            }
        });
        if !self.export_output.is_empty() {
            ui.add(
                egui::TextEdit::multiline(&mut self.export_output)
                    .desired_rows(10)
                    .font(egui::TextStyle::Monospace),
            );
        }

        // ── Blackout resilience journal ──────────────────────────────
        ui.add_space(10.0);
        ui.separator();
        ui.heading(egui::RichText::new("Blackout / rescue journal").color(GOLD));
        let pending = dastyab_core::journal::pending_drain(&self.profile_id);
        if !pending.is_empty() {
            ui.label(
                egui::RichText::new(format!(
                    "⚠ {} unresolved intent(s) — see CLI `dastyab journal pending`",
                    pending.len()
                ))
                .color(egui::Color32::from_rgb(220, 140, 60)),
            );
        } else {
            ui.label("No unresolved intents.");
        }
        ui.horizontal(|ui| {
            if ui.button("Clear journal").clicked()
                && dastyab_core::journal::clear(&self.profile_id).is_ok()
            {
                ui.label("Cleared.");
            }
        });
        let show = dastyab_core::journal::recent(&self.profile_id, 10);
        if show.is_empty() {
            ui.label("Journal is empty — events appear after the daemon records blackout/rescue transitions.");
        } else {
            egui::ScrollArea::vertical()
                .max_height(160.0)
                .show(ui, |ui| {
                    for e in &show {
                        let label = match e.kind {
                            dastyab_core::journal::JournalKind::NetworkDown => "⬇ network-down",
                            dastyab_core::journal::JournalKind::NetworkUp => "⬆ network-up",
                            dastyab_core::journal::JournalKind::RescueAttempt => "🔧 rescue",
                            dastyab_core::journal::JournalKind::CycleFailed => "❌ cycle-failed",
                            dastyab_core::journal::JournalKind::AccountBlocked => {
                                "⛔ account-blocked"
                            }
                            dastyab_core::journal::JournalKind::TokenRecovered => {
                                "🔑 token-recovered"
                            }
                            dastyab_core::journal::JournalKind::OutboxFlushed => {
                                "📤 outbox-flushed"
                            }
                            dastyab_core::journal::JournalKind::BackupWritten => {
                                "💾 backup-written"
                            }
                            dastyab_core::journal::JournalKind::MutationPerformed => {
                                "🔁 signature-rotated"
                            }
                            dastyab_core::journal::JournalKind::DrillPerformed => {
                                "🩺 blackout-self-test"
                            }
                            dastyab_core::journal::JournalKind::AutoHealed => "🛠 auto-healed",
                            dastyab_core::journal::JournalKind::SnapshotWritten => {
                                "📸 workspace-snapshot"
                            }
                            dastyab_core::journal::JournalKind::VersionVerified => {
                                "✅ versions-verified"
                            }
                        };
                        ui.label(format!("{label} — {} (t={})", e.detail, e.ts));
                    }
                });
        }
    }

    /// The hands-off readiness panel. Lists the same safeguards as the CLI
    /// `dastyab autopilot autonomy` audit, color-coded, with one-click config
    /// fixes for the toggles the app can apply itself (auto-backup, signature
    /// rotation). Items that need user-supplied input (DNS tunnel deploy, a
    /// second token) show the exact command instead — the app never fabricates
    /// credentials.
    fn autonomy_panel(&mut self, ui: &mut egui::Ui, p: &dastyab_core::store::profiles::Profile) {
        use dastyab_core::autonomy::{CheckStatus, FixAction};

        ui.heading(egui::RichText::new("Autonomy").color(GOLD));
        ui.label("Hands-off readiness — what still needs you, and what the app can fix itself.");

        // Live daemon health snapshot (real evidence from the loop's persisted
        // state — not just "is the process up").
        if let Some(st) = load_daemon_state_opt(&self.profile_id) {
            ui.add_space(4.0);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let mut health = format!(
                "daemon state — failures: {} · interval: {}s · tier: {}{}",
                st.failure_streak,
                st.current_interval_secs,
                if st.network_tier.is_empty() {
                    "?"
                } else {
                    &st.network_tier
                },
                if st.network_was_down {
                    " · network-down"
                } else {
                    ""
                },
            );
            if st.last_success_ts > 0 {
                let age = (now - st.last_success_ts).max(0);
                health.push_str(&format!(" · last-ok {age}s ago"));
            } else {
                health.push_str(" · no-ok-yet");
            }
            if !st.survival_plan.is_empty() {
                health.push_str(&format!(" · plan:{}", st.survival_plan));
            }
            ui.colored_label(egui::Color32::from_rgb(170, 170, 190), health);
        }

        let report = dastyab_core::autonomy::run_audit(p);

        // One-click config fixes the app can apply directly. The audit is
        // re-run at the top of this panel every frame, so the status line
        // below automatically reflects any fix applied this frame.
        for item in &report.items {
            if let Some(fix) = item.fix_action {
                ui.horizontal(|ui| {
                    let color = match item.status {
                        CheckStatus::Ok => egui::Color32::from_rgb(90, 200, 120),
                        CheckStatus::Action => egui::Color32::from_rgb(230, 160, 60),
                        CheckStatus::Manual => egui::Color32::from_rgb(220, 120, 120),
                        CheckStatus::Info => egui::Color32::from_rgb(160, 160, 170),
                    };
                    ui.colored_label(color, format!("[{}] {}", item.status.label(), item.title));
                    ui.label(&item.detail);
                    if ui.button("Enable").clicked() {
                        match fix {
                            FixAction::EnableBackupAutoSync => {
                                self.backup_auto_enabled = true;
                                if self.backup_auto_interval == 0 {
                                    self.backup_auto_interval = 3600;
                                }
                                if self.backup_auto_keep == 0 {
                                    self.backup_auto_keep = 5;
                                }
                                self.save_backup_auto();
                            }
                            FixAction::EnableSignatureMutation => {
                                self.mutation_enabled = true;
                                if self.mutation_interval == 0 {
                                    self.mutation_interval = 86400;
                                }
                                self.save_mutation();
                            }
                            FixAction::EnableDaemon => {
                                // One-click install+start of the systemd
                                // daemon with boot-before-login linger.
                                let exe = std::env::current_exe()
                                    .unwrap_or_else(|_| "/home/amir/.local/bin/dastyab".into());
                                match dastyab_core::bootstrap::ensure_daemon_installed(
                                    &exe,
                                    &self.profile_id,
                                    true,
                                ) {
                                    Ok(outcome) => {
                                        let status_txt = match outcome {
                                            dastyab_core::bootstrap::DaemonInstallOutcome::Installed => {
                                                "installed and started"
                                            }
                                            dastyab_core::bootstrap::DaemonInstallOutcome::AlreadyInstalled => {
                                                "started (already installed)"
                                            }
                                        };
                                        self.daemon_note =
                                            format!("Daemon {status_txt} — boot autostart armed.");
                                    }
                                    Err(e) => {
                                        self.daemon_note = format!("Daemon install failed: {}", e.brief());
                                    }
                                }
                            }
                        }
                    }
                });
            } else {
                let color = match item.status {
                    CheckStatus::Ok => egui::Color32::from_rgb(90, 200, 120),
                    CheckStatus::Action => egui::Color32::from_rgb(230, 160, 60),
                    CheckStatus::Manual => egui::Color32::from_rgb(220, 120, 120),
                    CheckStatus::Info => egui::Color32::from_rgb(160, 160, 170),
                };
                ui.horizontal(|ui| {
                    ui.colored_label(color, format!("[{}] {}", item.status.label(), item.title));
                    ui.label(&item.detail);
                });
                if !item.fix.is_empty() {
                    ui.label(
                        egui::RichText::new(format!("    → {}", item.fix))
                            .color(egui::Color32::from_rgb(120, 140, 180)),
                    );
                }
                // In-app actions for the two safeguards that need user-supplied
                // input — open the *same* dialogs/panels the dedicated views
                // use, so no safeguard forces a terminal step.
                match item.code.as_str() {
                    "token_rotate" if item.status == CheckStatus::Action => {
                        if ui.button("➕ Add token in app").clicked() {
                            self.pending_action = Some(PendingDialogAction::AddToken);
                            self.dialog = Some(dialogs::prompt_two(
                                "Add token",
                                "Label (e.g. cf-main)",
                                "Cloudflare API token",
                                true,
                            ));
                        }
                    }
                    "tunnel"
                        if item.status == CheckStatus::Action
                            && ui.button("⚙ Configure DNS tunnel in app").clicked() =>
                    {
                        self.view = View::Settings;
                    }
                    _ => {}
                }
            }
        }

        // Status line.
        ui.add_space(8.0);
        ui.separator();
        if report.needs_action() {
            ui.colored_label(
                egui::Color32::from_rgb(230, 160, 60),
                "⚠ Not fully hands-off yet — complete the ACTION items above. Each is a one-time step.",
            );
        } else {
            ui.colored_label(
                egui::Color32::from_rgb(90, 200, 120),
                "✓ All autonomous safeguards armed — the app runs hands-off.",
            );
        }
    }
}

/// Load the daemon state for a profile, returning None when absent/unreadable.
fn load_daemon_state_opt(profile: &str) -> Option<dastyab_core::daemon::DaemonState> {
    Some(dastyab_core::daemon::load_daemon_state(profile))
}

/// Deploy the VLESS worker and persist the fresh share link + all client
/// config formats into the generated-configs ledger. Returns (host, link).
async fn deploy_worker(token: &str, pid: &str) -> Result<(String, String), CFError> {
    let client = dastyab_core::cf::Client::new(token);
    let accs = client.list_accounts().await?;
    let acc = accs.first().ok_or_else(|| {
        CFError::new(
            "No account",
            "No CF account accessible.",
            "Check token permissions.",
        )
    })?;
    let subdomain = client.get_subdomain(&acc.id).await?;
    let worker_name = dastyab_core::worker::default_worker_name();
    let uuid = generate_uuid();

    // Use the real VLESS worker JS. Require an actual worker file — the
    // fallback constant is only a health-check stub that cannot proxy VLESS
    // traffic, so deploying it would "succeed" while producing a useless
    // worker. Refuse loudly instead of shipping a dead deploy.
    let worker_path = dastyab_core::worker::find_worker_js(None).ok_or_else(|| {
        CFError::new(
            "No worker file",
            "No functional VLESS worker JS was found to deploy.",
            "Place an edgetunnel worker at ~/Projects/cf-worker-proxy/edgetunnel_worker.js (or run `dastyab setup`) and retry.",
        )
    })?;
    let (ok, msg) = dastyab_core::worker::validate_worker_js(&worker_path)?;
    if !ok {
        return Err(CFError::new(
            "Invalid worker file",
            msg,
            "Use the correct edgetunnel module worker.",
        ));
    }
    let js: Vec<u8> = std::fs::read(&worker_path)
        .map_err(|e| CFError::new("Read error", format!("{e}"), "Check the file path."))?;

    client
        .deploy_script(&acc.id, &worker_name, js, "2026-07-01", 2)
        .await?;
    client
        .set_vars(
            &acc.id,
            &worker_name,
            serde_json::Map::from_iter([("UUID".into(), serde_json::json!(uuid))]),
        )
        .await?;
    let host = format!("{worker_name}.{subdomain}.workers.dev");
    let vless = VlessProfile {
        uuid: uuid.clone(),
        address: host.clone(),
        port: 443,
        security: "tls".into(),
        path: "/".into(),
        transport: "ws".into(),
        name: format!("{worker_name}-edge"),
        ..Default::default()
    };
    let link = vless.share_link();

    // Record every rendered config format (share-link, v2rayN, sing-box,
    // Clash) into the generated-configs ledger so the Configs tab reflects
    // the fresh deployment without a separate export step.
    let mut ledger = dastyab_core::generated_configs::load_generated_configs(pid);
    let now = dastyab_core::store::now_ts() as u64;
    use dastyab_core::export::{render, ExportFormat};
    use dastyab_core::generated_configs::ConfigSource;
    for fmt in [
        ExportFormat::ShareLink,
        ExportFormat::V2rayN,
        ExportFormat::SingBox,
        ExportFormat::Clash,
    ] {
        if let Ok(content) = render(&vless, fmt) {
            let _ = ledger.push(
                now,
                fmt,
                ConfigSource::WorkerVless,
                Some(format!("deploy {worker_name}")),
                content,
            );
        }
    }
    let _ = dastyab_core::generated_configs::save_generated_configs(pid, &ledger);

    Ok((host, link))
}

/// Open a folder in the platform file manager.
fn open_folder(dir: &std::path::Path) {
    let dir = dir.to_string_lossy().into_owned();
    let (prog, arg) = match std::env::consts::OS {
        "macos" => ("open", dir),
        "windows" => ("explorer", dir),
        _ => ("xdg-open", dir),
    };
    let _ = std::process::Command::new(prog).arg(arg).spawn();
}
