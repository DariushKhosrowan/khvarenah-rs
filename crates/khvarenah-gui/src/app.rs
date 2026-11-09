//! Khvarenah GUI application state and rendering.
//!
//! Modern royal-gold-on-black design. Three tabs:
//! * Deploy — deploy worker, scan clean IPs, export share links.
//! * Profiles — list/create/switch profiles, manage tokens & settings.
//! * Tools — security audit, backup/restore, client-format export.

use eframe::egui;
use khvarenah_core::scanner::{scan_many, scan_once, ScanParams};
use khvarenah_core::store::profiles::{
    add_token, create_profile, delete_profile, list_profiles, load_profile, remember_clean_ip,
    remember_vless, rename_profile, save_config, set_active_profile, ProfileConfig, VlessRecord,
};
use khvarenah_core::vless::VlessProfile;
use khvarenah_core::worker::generate_uuid;
use khvarenah_core::CFError;

use crate::bridge;
use crate::dialogs::{self, Dialog, DialogPayload, DialogResult};
use crate::state::GuiState;
use crate::views::{profiles, tokens};

// Royal-gold palette (dark #0a0705 bg per shell spec)
pub const GOLD: egui::Color32 = egui::Color32::from_rgb(212, 175, 55);
pub const GOLD_DIM: egui::Color32 = egui::Color32::from_rgb(150, 120, 40);
pub const DARK: egui::Color32 = egui::Color32::from_rgb(10, 7, 5); // #0a0705
pub const PANEL: egui::Color32 = egui::Color32::from_rgb(24, 20, 14);
pub const TEXT: egui::Color32 = egui::Color32::from_rgb(235, 228, 200);

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    DeployScan,
    Profiles,
    Tokens,
    CleanIps,
    Tools,
    Settings,
}

impl View {
    /// The six-item sidebar, in order.
    const ALL: [View; 6] = [
        View::DeployScan,
        View::Profiles,
        View::Tokens,
        View::CleanIps,
        View::Tools,
        View::Settings,
    ];

    fn label(self) -> &'static str {
        match self {
            View::DeployScan => "Deploy & Scan",
            View::Profiles => "Profiles",
            View::Tokens => "Tokens",
            View::CleanIps => "Clean IPs",
            View::Tools => "Tools",
            View::Settings => "Settings",
        }
    }
}

pub struct KhvarenahApp {
    pub profile_id: String,
    pub profiles: Vec<String>,
    pub note: String,
    /// The most recent background-task error (if any), shown as a red banner.
    error_banner: Option<String>,
    view: View,
    // async bridge
    tx: bridge::Tx,
    rx: bridge::Rx,
    running: Vec<String>,   // task names currently in flight
    log_lines: Vec<String>, // live log pane (capped at 5000)
    // view-model cache (Phase 3.2/3.3)
    pub state: GuiState,
    /// Currently open modal dialog (if any).
    pub dialog: Option<Dialog>,
    /// The action a dialog submit should take.
    pub pending_action: Option<PendingDialogAction>,
    /// Which sidebar profile row is selected (for rename/delete).
    pub selected_profile: Option<usize>,
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
}

/// What to do when the open dialog submits.
#[derive(Debug, Clone)]
pub enum PendingDialogAction {
    CreateProfile,
    RenameProfile(String),
    DeleteProfile(String),
    AddToken,
    ImportSeeds,
}

impl KhvarenahApp {
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
            ..Default::default()
        };
        cc.egui_ctx.set_style_of(egui::Theme::Dark, style);

        // touch profile data
        let _ = khvarenah_core::store::profiles::migrate_legacy();
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
            khvarenah_core::store::profiles::protection_enabled(&state.active_profile_id);
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
            beacon_enabled: profile.config.beacon.as_ref().map(|b| b.enabled).unwrap_or(false),
            beacon_channel: profile
                .config
                .beacon
                .as_ref()
                .map(|b| match b.kind {
                    khvarenah_core::remote_beacon::BeaconKind::Telegram => {
                        "Telegram".to_string()
                    }
                    khvarenah_core::remote_beacon::BeaconKind::GenericWebhook => {
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
            view: View::DeployScan,
        };
        app.refresh_diagnostics();
        app
    }

    /// Re-read the last pipeline diagnostics and derive the plain-language
    /// "why zero?" explanation for the Clean IPs view.
    fn refresh_diagnostics(&mut self) {
        use khvarenah_core::diagnose::{diagnose, plain_message, Locale};
        if let Some(diag) = khvarenah_core::store::profiles::load_last_diagnostics(&self.profile_id)
        {
            let probe = khvarenah_core::diagnose::WorkerProbe::default();
            let cause = diagnose(&diag, probe);
            self.last_cause = Some(plain_message(cause, Locale::En));
            self.last_action_label =
                khvarenah_core::diagnose::recommended_action(cause).label(Locale::En);
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
        khvarenah_core::stealth::set_enabled(self.stealth_enabled);
        if let Err(e) = save_config(&self.profile_id, &cfg) {
            self.note = e.brief();
        }
    }

    /// Persist the notification config. Loads the current profile config so we
    /// preserve every other field (beacon is stored on `ProfileConfig`).
    fn save_beacon(&mut self) {
        let kind = if self.beacon_channel == "Webhook" {
            khvarenah_core::remote_beacon::BeaconKind::GenericWebhook
        } else {
            khvarenah_core::remote_beacon::BeaconKind::Telegram
        };
        let mut p = khvarenah_core::store::profiles::load_profile(&self.profile_id);
        p.config.beacon = Some(khvarenah_core::remote_beacon::BeaconConfig {
            enabled: self.beacon_enabled,
            kind,
            token: self.beacon_token.clone(),
            chat_id_or_url: self.beacon_target.clone(),
            rate_limit_secs: self.beacon_rate_limit.max(1),
        });
        match khvarenah_core::store::profiles::save_profile(&p) {
            Ok(()) => self.beacon_note = "Notifications saved.".to_string(),
            Err(e) => self.beacon_note = format!("Save failed: {}", e.brief()),
        }
    }

    /// Send a test message with the current on-screen config (does not save).
    fn send_beacon_test(&mut self) {
        let kind = if self.beacon_channel == "Webhook" {
            khvarenah_core::remote_beacon::BeaconKind::GenericWebhook
        } else {
            khvarenah_core::remote_beacon::BeaconKind::Telegram
        };
        let cfg = khvarenah_core::remote_beacon::BeaconConfig {
            enabled: true,
            kind,
            token: self.beacon_token.clone(),
            chat_id_or_url: self.beacon_target.clone(),
            rate_limit_secs: self.beacon_rate_limit.max(1),
        };
        if cfg.chat_id_or_url.is_empty() {
            self.beacon_note = "Set a chat ID / webhook URL first.".to_string();
            return;
        }
        let msg = "✅ Khvarenah test notification — protection is working.";
        let tx = self.tx.clone();
        bridge::spawn("beacon-test", tx.clone(), async move {
            match khvarenah_core::remote_beacon::send(&cfg, msg).await {
                Ok(()) => {
                    let _ = tx.send(crate::bridge::UiEvent::Log {
                        task: "beacon-test".to_string(),
                        line: "[beacon] test message sent".to_string(),
                    });
                }
                Err(e) => {
                    let _ = tx.send(crate::bridge::UiEvent::TaskErr {
                        task: "beacon-test".to_string(),
                        error: CFError::new(
                            "Beacon test",
                            e.brief(),
                            "Check the channel config.",
                        ),
                    });
                }
            }
            Ok::<String, CFError>("beacon-test done".to_string())
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
        let _ = khvarenah_core::store::profiles::set_protection(&pid, true);

        self.running.push("autopilot".to_string());
        self.autopilot_on = true;
        self.autopilot_status = "Autopilot starting — discovering the best clean IP…".to_string();
        self.push_log("[autopilot] ON — starting discovery + monitor loop");
        ctx.request_repaint();

        bridge::spawn("autopilot", tx.clone(), async move {
            let params = khvarenah_core::autopilot::DiscoveryParams::default();
            let interval = std::time::Duration::from_secs(300);
            let engine = khvarenah_core::autopilot::AutopilotEngine::new(pid, params, interval);
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
        let _ = khvarenah_core::store::profiles::set_protection(&self.profile_id, false);
        self.autopilot_stop
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.autopilot_on = false;
        self.autopilot_status =
            "Autopilot stopped. The last working clean IP stays in your active configs."
                .to_string();
        self.running.retain(|t| t != "autopilot");
        self.push_log("[autopilot] OFF");
    }

    /// Drain the async bridge, applying every pending event to UI state.
    fn poll_bridge(&mut self, ctx: &egui::Context) {
        use bridge::UiEvent;
        while let Ok(ev) = self.rx.try_recv() {
            match ev {
                UiEvent::Done { task, summary } => {
                    self.running.retain(|t| t != &task);
                    if task == "autopilot" {
                        self.autopilot_status = summary.clone();
                        self.autopilot_on = true;
                        self.refresh_diagnostics();
                    } else {
                        self.note = format!("✓ {task}: {summary}");
                    }
                    self.push_log(&format!("[done] {task}: {summary}"));
                    // mutating tasks change the store; refresh the view cache
                    self.state.reload_pending = true;
                }
                UiEvent::TaskErr { task, error } => {
                    self.running.retain(|t| t != &task);
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
                            match khvarenah_core::cf::ips::import_manual_seeds(
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
                    None => {}
                }
            }
        }
    }
}

impl eframe::App for KhvarenahApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Auto-resume the one-button Protection monitor if it was left on in a
        // previous session (persisted flag) but isn't running yet.
        if self.autopilot_on && !self.running.iter().any(|t| t == "autopilot") {
            self.autopilot_on(ui.ctx());
        }

        // Drain background async work before rendering any frame.
        self.poll_bridge(ui.ctx());

        ui.vertical_centered(|ui| {
            ui.heading(egui::RichText::new("Khvarenah").color(GOLD).size(28.0));
            ui.label(egui::RichText::new("Cloudflare-Workers VLESS VPN console").color(GOLD_DIM));
        });
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            egui::ComboBox::from_label("Profile")
                .selected_text(&self.profile_id)
                .show_ui(ui, |ui| {
                    for id in &self.profiles {
                        ui.selectable_value(&mut self.profile_id, id.clone(), id.as_str());
                    }
                });
            if ui.button("New profile").clicked() && !self.new_profile_name.is_empty() {
                match create_profile(&self.new_profile_name, "") {
                    Ok(id) => {
                        self.profile_id = id;
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

        if let Some(err) = &self.error_banner {
            ui.add_space(8.0);
            egui::Frame::new()
                .fill(egui::Color32::from_rgb(60, 12, 12))
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(200, 60, 60)))
                .show(ui, |ui| {
                    ui.label(
                        egui::RichText::new(err).color(egui::Color32::from_rgb(255, 160, 160)),
                    );
                });
        }

        if !self.note.is_empty() {
            ui.add_space(6.0);
            ui.label(egui::RichText::new(&self.note).color(GOLD_DIM));
        }
    }
}

impl KhvarenahApp {
    /// The app shell: left navigation sidebar + active view, with the active
    /// view name shown in gold.
    fn render_shell(&mut self, ui: &mut egui::Ui, p: &khvarenah_core::store::profiles::Profile) {
        ui.horizontal(|ui| {
            // Left sidebar with the six views.
            ui.vertical(|ui| {
                ui.set_width(170.0);
                ui.label(
                    egui::RichText::new("KHVARENAH")
                        .color(GOLD)
                        .strong()
                        .size(16.0),
                );
                ui.add_space(4.0);
                for v in View::ALL {
                    let active = self.view == v;
                    let text = if active {
                        egui::RichText::new(v.label()).color(GOLD).strong()
                    } else {
                        egui::RichText::new(v.label()).color(TEXT)
                    };
                    let resp = ui.selectable_label(active, text);
                    if resp.clicked() {
                        self.view = v;
                    }
                }
            });

            ui.separator();

            // Main content area.
            ui.vertical(|ui| {
                // active view name in gold
                ui.heading(
                    egui::RichText::new(self.view.label())
                        .color(GOLD)
                        .size(22.0),
                );
                ui.separator();
                match self.view {
                    View::DeployScan => self.deploy_panel(ui, p),
                    View::Profiles => self.profile_panel(ui, p),
                    View::Tokens => self.token_panel(ui, p),
                    View::CleanIps => self.cleanip_panel(ui, p),
                    View::Tools => self.tools_panel(ui, p),
                    View::Settings => self.settings_panel(ui, p),
                }
            });
        });
    }

    fn deploy_panel(&mut self, ui: &mut egui::Ui, p: &khvarenah_core::store::profiles::Profile) {
        ui.heading(egui::RichText::new("Deploy & Clean-IP").color(GOLD));

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
        let dstate = khvarenah_core::daemon::load_daemon_state(&self.profile_id);
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
        if let Ok(dir) = khvarenah_core::cleanip::user_config_dir(&self.profile_id) {
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
                                    let new_link = khvarenah_core::scanner::rewrite_vless_with_endpoint(&link, &ep);
                                    let _ = remember_clean_ip(&pid, &ep);
                                    let rec = VlessRecord {
                                        id: khvarenah_core::store::new_id(),
                                        ts: khvarenah_core::store::profiles::now_iso(),
                                        epoch: khvarenah_core::store::now_ts(),
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
                                        "Found working IP: {ep} — link updated in profile."
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
                                    }
                                    Ok::<String, CFError>(format!(
                                        "{} — {}",
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
            let token = p.tokens.values().next().map(|t| t.token.clone());
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
                                    id: khvarenah_core::store::new_id(),
                                    ts: khvarenah_core::store::profiles::now_iso(),
                                    epoch: khvarenah_core::store::now_ts(),
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

    fn profile_panel(&mut self, ui: &mut egui::Ui, _p: &khvarenah_core::store::profiles::Profile) {
        if let Some(act) = profiles::show(ui, self, self.selected_profile) {
            if let Some(dlg) = profiles::run_action(self, act) {
                self.dialog = Some(dlg);
            }
        }
    }

    fn token_panel(&mut self, ui: &mut egui::Ui, _p: &khvarenah_core::store::profiles::Profile) {
        if let Some(act) = tokens::show(ui, self) {
            if let Some(dlg) = tokens::run_action(self, act) {
                self.dialog = Some(dlg);
            }
        }
    }

    fn cleanip_panel(&mut self, ui: &mut egui::Ui, _p: &khvarenah_core::store::profiles::Profile) {
        ui.heading(egui::RichText::new("Clean IPs").color(GOLD));
        ui.label(
            egui::RichText::new("Verified endpoints saved per profile (smart stop-on-first).")
                .color(GOLD_DIM),
        );
        ui.add_space(6.0);
        let p = load_profile(&self.profile_id);
        if p.clean_ips.is_empty() {
            ui.label(
                egui::RichText::new("No clean IPs found yet — scan from Deploy & Scan.")
                    .color(GOLD_DIM),
            );
        }
        for ip in &p.clean_ips {
            ui.label(format!("• {ip}"));
        }

        // Zero-result diagnostics: explain "why nothing found" in plain language.
        if p.clean_ips.is_empty() {
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
            // Import known-good IPs (the NetworkBlocked fast path).
            ui.add_space(8.0);
            if ui.button("📥 Import known-good IPs").clicked() {
                self.pending_action = Some(PendingDialogAction::ImportSeeds);
                self.dialog = Some(dialogs::prompt_text_area(
                    "Import known-good IPs",
                    "One IP per line — e.g.\n104.16.1.1\n104.16.2.1:2053  # fast",
                ));
            }
        }
    }

    fn settings_panel(&mut self, ui: &mut egui::Ui, _p: &khvarenah_core::store::profiles::Profile) {
        ui.heading(egui::RichText::new("Settings").color(GOLD));
        ui.checkbox(&mut self.scan_gentle, "gentle scan");
        ui.checkbox(&mut self.stealth_enabled, "stealth pacing");
        ui.add_space(6.0);
        if ui.button("Save settings").clicked() {
            self.save_scan_params();
            self.note = "Settings saved to profile.".to_string();
        }
        ui.add_space(10.0);
        ui.separator();
        ui.heading(egui::RichText::new("Backup / restore").color(GOLD));
        ui.horizontal(|ui| {
            if ui.button("Backup this profile").clicked() {
                match khvarenah_core::backup::export_profile_to_file(&self.profile_id, None) {
                    Ok(path) => self.backup_output = format!("✓ Backed up → {}", path.display()),
                    Err(e) => self.backup_output = e.explain(),
                }
            }
            if ui.button("List backups").clicked() {
                self.backup_output = khvarenah_core::backup::backup_summary();
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
        ui.heading(egui::RichText::new("Notifications").color(GOLD));
        ui.checkbox(&mut self.beacon_enabled, "Enable push notifications (Telegram / webhook)");
        ui.horizontal(|ui| {
            egui::ComboBox::from_id_salt("beacon_ch")
                .selected_text(&self.beacon_channel)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.beacon_channel, "Telegram".to_string(), "Telegram");
                    ui.selectable_value(&mut self.beacon_channel, "Webhook".to_string(), "Webhook");
                });
            ui.label("channel");
        });
        if self.beacon_channel == "Telegram" {
            ui.label("Bot token:");
            ui.add(egui::TextEdit::singleline(&mut self.beacon_token).password(true).desired_width(260.0));
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
        ui.horizontal(|ui| {
            if ui.button("Save notifications").clicked() {
                self.save_beacon();
            }
            if ui.button("Send test").clicked() {
                self.send_beacon_test();
            }
        });
        if !self.beacon_note.is_empty() {
            ui.colored_label(GOLD, &self.beacon_note);
        }
    }

    fn tools_panel(&mut self, ui: &mut egui::Ui, p: &khvarenah_core::store::profiles::Profile) {
        ui.heading(egui::RichText::new("Security audit").color(GOLD));
        if ui.button("Run security audit").clicked() {
            self.audit_output = khvarenah_core::security::audit().render();
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
                match khvarenah_core::backup::export_profile_to_file(&self.profile_id, None) {
                    Ok(path) => self.backup_output = format!("✓ Backed up → {}", path.display()),
                    Err(e) => self.backup_output = e.explain(),
                }
            }
            if ui.button("List backups").clicked() {
                self.backup_output = khvarenah_core::backup::backup_summary();
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
                    if let Some(fmt) = khvarenah_core::export::ExportFormat::parse(&chosen) {
                        match khvarenah_core::export::render(&vless, fmt) {
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
    }
}

async fn deploy_worker(token: &str, _pid: &str) -> Result<(String, String), CFError> {
    let client = khvarenah_core::cf::Client::new(token);
    let accs = client.list_accounts().await?;
    let acc = accs.first().ok_or_else(|| {
        CFError::new(
            "No account",
            "No CF account accessible.",
            "Check token permissions.",
        )
    })?;
    let subdomain = client.get_subdomain(&acc.id).await?;
    let worker_name = khvarenah_core::worker::default_worker_name();
    let uuid = generate_uuid();
    let js = khvarenah_core::worker::find_worker_js(None)
        .map(std::fs::read)
        .transpose()
        .map_err(|e| CFError::new("Read error", format!("{e}"), "Check file."))?
        .unwrap_or_else(|| {
            b"export default { async fetch(){ return new Response('ok'); } }".to_vec()
        });
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
