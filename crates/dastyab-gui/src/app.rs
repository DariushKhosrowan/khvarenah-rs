//! DastYab GUI application state and rendering.
//!
//! Modern royal-gold-on-black design. Three tabs:
//! * Deploy — deploy worker, scan clean IPs, export share links.
//! * Profiles — list/create/switch profiles, manage tokens & settings.
//! * Tools — security audit, backup/restore, client-format export.

use eframe::egui;
use dastyab_core::scanner::{scan_many, scan_once, ScanParams};
use dastyab_core::store::profiles::{
    add_token, create_profile, list_profiles, load_profile, remember_clean_ip, remember_vless,
    save_config, ProfileConfig, VlessRecord,
};
use dastyab_core::vless::VlessProfile;
use dastyab_core::worker::generate_uuid;
use dastyab_core::CFError;

// Royal-gold palette
const GOLD: egui::Color32 = egui::Color32::from_rgb(212, 175, 55);
const GOLD_DIM: egui::Color32 = egui::Color32::from_rgb(150, 120, 40);
const DARK: egui::Color32 = egui::Color32::from_rgb(10, 8, 6);
const PANEL: egui::Color32 = egui::Color32::from_rgb(24, 20, 14);
const TEXT: egui::Color32 = egui::Color32::from_rgb(235, 228, 200);

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Deploy,
    Profiles,
    Tools,
}

pub struct DastYabApp {
    pub profile_id: String,
    pub profiles: Vec<String>,
    pub note: String,
    tab: Tab,
    // inputs
    pub new_profile_name: String,
    pub token_label: String,
    pub token_value: String,
    // scan params
    pub scan_count: u32,
    pub scan_workers: u32,
    pub scan_timeout: u32,
    pub scan_ports: String,
    pub scan_gentle: bool,
    pub stealth_enabled: bool,
    // results
    pub last_link: String,
    pub last_scan: String,
    // tools
    pub audit_output: String,
    pub backup_output: String,
    pub export_output: String,
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
            ..Default::default()
        };
        cc.egui_ctx.set_style_of(egui::Theme::Dark, style);

        // touch profile data
        let _ = dastyab_core::store::profiles::migrate_legacy();
        let pids = list_profiles()
            .into_iter()
            .map(|m| m.id)
            .collect::<Vec<_>>();

        let profile = load_profile("default");
        Self {
            profile_id: "default".to_string(),
            profiles: if pids.is_empty() {
                vec!["default".to_string()]
            } else {
                pids
            },
            note: String::new(),
            new_profile_name: String::new(),
            token_label: "cf-main".to_string(),
            token_value: String::new(),
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
            last_scan: String::new(),
            audit_output: String::new(),
            backup_output: String::new(),
            export_output: String::new(),
            tab: Tab::Deploy,
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
        dastyab_core::stealth::set_enabled(self.stealth_enabled);
        if let Err(e) = save_config(&self.profile_id, &cfg) {
            self.note = e.brief();
        }
    }
}

impl eframe::App for DastYabApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        ui.vertical_centered(|ui| {
            ui.heading(egui::RichText::new("DastYab").color(GOLD).size(28.0));
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

        // Tabs
        ui.horizontal(|ui| {
            if ui
                .selectable_label(self.tab == Tab::Deploy, "Deploy & Scan")
                .clicked()
            {
                self.tab = Tab::Deploy;
            }
            if ui
                .selectable_label(self.tab == Tab::Profiles, "Profiles & Tokens")
                .clicked()
            {
                self.tab = Tab::Profiles;
            }
            if ui
                .selectable_label(self.tab == Tab::Tools, "Tools")
                .clicked()
            {
                self.tab = Tab::Tools;
            }
        });

        ui.separator();

        let p = load_profile(&self.profile_id);
        match self.tab {
            Tab::Deploy => self.deploy_panel(ui, &p),
            Tab::Profiles => self.profile_panel(ui, &p),
            Tab::Tools => self.tools_panel(ui, &p),
        }

        if !self.note.is_empty() {
            ui.add_space(6.0);
            ui.label(egui::RichText::new(&self.note).color(GOLD_DIM));
        }
    }
}

impl DastYabApp {
    fn deploy_panel(&mut self, ui: &mut egui::Ui, p: &dastyab_core::store::profiles::Profile) {
        ui.heading(egui::RichText::new("Deploy & Clean-IP").color(GOLD));

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
            if ui.button("Scan ONE clean IP (stops on first)").clicked() {
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
                let (note, last_scan) = match link {
                    Some(link) => match block_on(scan_once(&link, &params)) {
                        Ok(Some(ep)) => {
                            let _ = remember_clean_ip(&pid, &ep);
                            let new_link =
                                dastyab_core::scanner::rewrite_vless_with_endpoint(&link, &ep);
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
                            self.last_link = new_link;
                            (format!("✓ Found working IP: {ep}"), "done".to_string())
                        }
                        Ok(None) => ("No working clean IP found.".to_string(), "none".to_string()),
                        Err(e) => (e.brief(), "error".to_string()),
                    },
                    None => (
                        "No deployed config to scan against — deploy first.".to_string(),
                        "none".to_string(),
                    ),
                };
                self.note = note;
                self.last_scan = last_scan;
            }

            if ui.button("Scan 5 clean IPs").clicked() {
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
                self.note = match link {
                    Some(link) => match block_on(scan_many(&link, &params, 5)) {
                        Ok(res) => {
                            for ep in &res.endpoints {
                                let _ = remember_clean_ip(&pid, ep);
                            }
                            format!("{} — {}", res.message, res.endpoints.join(", "))
                        }
                        Err(e) => e.brief(),
                    },
                    None => "No deployed config to scan against.".to_string(),
                };
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

        if ui.button("Deploy worker & make config").clicked() {
            let pid = self.profile_id.clone();
            let token = p.tokens.values().next().map(|t| t.token.clone());
            match token {
                Some(token) => match block_on(deploy_worker(&token, &pid)) {
                    Ok((host, link)) => {
                        self.last_link = link.clone();
                        self.note = format!("✓ Deployed → {host}");
                    }
                    Err(e) => self.note = e.brief(),
                },
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
    }

    fn profile_panel(&mut self, ui: &mut egui::Ui, p: &dastyab_core::store::profiles::Profile) {
        ui.heading(egui::RichText::new("Tokens").color(GOLD));
        ui.horizontal(|ui| {
            ui.label("Label:");
            ui.add(egui::TextEdit::singleline(&mut self.token_label).desired_width(100.0));
            ui.label("Token:");
            ui.add(
                egui::TextEdit::singleline(&mut self.token_value)
                    .desired_width(200.0)
                    .password(true),
            );
            if ui.button("Save token").clicked() {
                if let Err(e) = add_token(&self.profile_id, &self.token_label, &self.token_value) {
                    self.note = e.brief();
                } else {
                    self.token_value.clear();
                    self.note = format!(
                        "Token '{}' saved to profile '{}'.",
                        self.token_label, self.profile_id
                    );
                }
            }
        });

        ui.add_space(6.0);
        for (label, entry) in &p.tokens {
            let masked = format!(
                "{}…{}",
                &entry.token[..entry.token.len().min(4)],
                &entry.token[entry.token.len().saturating_sub(4)..]
            );
            ui.label(format!("• {label}: {masked}"));
        }

        ui.add_space(8.0);
        ui.heading(egui::RichText::new("Accounts").color(GOLD));
        for (id, acc) in &p.accounts {
            ui.label(format!("• {id} — {}", acc.name));
        }

        ui.add_space(8.0);
        ui.heading(egui::RichText::new("Clean IPs").color(GOLD));
        for ip in p.clean_ips.iter().take(10) {
            ui.label(format!("• {ip}"));
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
    }
}

async fn deploy_worker(token: &str, _pid: &str) -> Result<(String, String), CFError> {
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
    let js = dastyab_core::worker::find_worker_js(None)
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

/// Block on a future using a fresh tokio runtime (GUI has no ambient runtime).
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Runtime::new()
        .expect("failed to create tokio runtime")
        .block_on(fut)
}
