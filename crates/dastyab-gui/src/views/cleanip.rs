//! Clean IPs view — a fast, searchable manager for the profile's saved
//! clean-IP endpoints. Includes per-entry provenance (source + port), copy /
//! delete, search, stats, copy-all, clear-all, manual add, import of
//! known-good seeds, and a live per-entry reachability probe.

use eframe::egui;
use dastyab_core::store::profiles::{remember_clean_ip_with_source, remove_clean_ip};

use crate::app::DastYabApp;
use crate::views::{
    mono_copy_row, section_card, stat_chips, tag, CARD, CARD_STROKE, GOLD, GOLD_DIM, SUCCESS,
};
use dastyab_core::CFError;

/// Actions the Clean IPs view can request.
#[derive(Debug)]
pub enum CleanipAction {
    /// Remove one saved clean IP.
    Remove(String),
    /// Remove every saved clean IP (opens a confirm dialog).
    ClearAll,
    /// Open the import-seeds text-area dialog.
    Import,
    /// Copy every endpoint (newline-joined) into the clipboard.
    CopyAll,
    /// Export all endpoints as text (handled inline).
    Export,
    /// Add one endpoint manually.
    AddManual(String),
    /// Probe one saved clean IP for reachability (spawns a bridge task).
    Probe(String),
    /// Probe every saved clean IP in sequence.
    ProbeAll,
    /// Promote every imported seed to a saved clean IP.
    PromoteAllSeeds,
    /// Write all saved clean IPs to a text file in the profile config dir.
    ExportToFile,
}

/// How the Clean IPs list is sorted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CleanipSort {
    /// Original save order (newest last).
    #[default]
    Added,
    /// Numerically by port (lowest first).
    Port,
    /// Grouped by source (manual → imported → scanned).
    Source,
}

impl CleanipSort {
    pub fn label(self) -> &'static str {
        match self {
            CleanipSort::Added => "added",
            CleanipSort::Port => "port",
            CleanipSort::Source => "source",
        }
    }
}

/// Accent for a clean-IP source.
fn source_color(source: &str) -> egui::Color32 {
    match source {
        "manual" => GOLD,
        "import" => egui::Color32::from_rgb(140, 200, 255),
        _ => SUCCESS,
    }
}

fn source_label(source: &str) -> &'static str {
    match source {
        "manual" => "manual",
        "import" => "seeded",
        _ => "scanned",
    }
}

pub fn show(ui: &mut egui::Ui, app: &mut DastYabApp) -> Option<CleanipAction> {
    let mut action = None;

    ui.heading(egui::RichText::new("Clean IPs").color(GOLD));
    ui.label(
        egui::RichText::new(
            "Verified endpoints saved per profile — search, copy, probe, or prune.",
        )
        .color(GOLD_DIM),
    );
    ui.add_space(6.0);

    let ips = &app.state.clean_ips;

    // Stats chip row (always visible, even when empty).
    let mut ports: std::collections::BTreeSet<u16> = Default::default();
    for ip in ips {
        if let Some((_, p)) = ip.rsplit_once(':') {
            if let Ok(p) = p.parse::<u16>() {
                ports.insert(p);
            }
        }
    }
    let seeds = app.state.seeds.len();
    stat_chips(
        ui,
        &[
            ("saved", &ips.len().to_string()),
            ("ports", &ports.len().to_string()),
            ("seeds", &seeds.to_string()),
        ],
    );

    // Search + bulk action row (only when there is anything to search).
    if !ips.is_empty() {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Search:").color(GOLD_DIM));
            ui.add(
                egui::TextEdit::singleline(&mut app.cleanip_search)
                    .hint_text("filter IPs…")
                    .desired_width(160.0),
            );
            // Sort selector.
            egui::ComboBox::from_id_salt("cleanip_sort")
                .selected_text(format!("sort: {}", app.cleanip_sort.label()))
                .show_ui(ui, |ui| {
                    for mode in [CleanipSort::Added, CleanipSort::Port, CleanipSort::Source] {
                        ui.selectable_value(&mut app.cleanip_sort, mode, mode.label());
                    }
                });
            if ui
                .button("📋 Copy all")
                .on_hover_text("Copy every saved IP")
                .clicked()
            {
                action = Some(CleanipAction::CopyAll);
            }
            if ui
                .button("💾 Export")
                .on_hover_text("Export all IPs as text")
                .clicked()
            {
                action = Some(CleanipAction::Export);
            }
            if ui
                .button("⚡ Probe all")
                .on_hover_text("Reachability-test every saved IP")
                .clicked()
            {
                action = Some(CleanipAction::ProbeAll);
            }
        });
        ui.add_space(4.0);
    }

    if ips.is_empty() {
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new(
                "No clean IPs found yet — scan from Deploy & Scan, add one below, or import known-good seeds.",
            )
            .color(GOLD_DIM),
        );
    } else {
        let query = app.cleanip_search.trim().to_lowercase();
        let mut matched: Vec<&String> = ips
            .iter()
            .filter(|ip| query.is_empty() || ip.to_lowercase().contains(&query))
            .collect();

        // Apply the selected sort (stable — preserves save order within a key).
        match app.cleanip_sort {
            CleanipSort::Added => {}
            CleanipSort::Port => matched.sort_by_key(|ip| {
                ip.rsplit_once(':')
                    .and_then(|(_, p)| p.parse::<u16>().ok())
                    .unwrap_or(443)
            }),
            CleanipSort::Source => matched.sort_by_key(|ip| {
                let meta = app.state.clean_ip_meta.get(ip.as_str());
                let src = meta.and_then(|m| m.split(':').next()).unwrap_or("scan");
                match src {
                    "manual" => 0,
                    "import" => 1,
                    _ => 2,
                }
            }),
        }

        if matched.is_empty() {
            ui.label(egui::RichText::new("No saved IP matches that search.").color(GOLD_DIM));
        } else {
            ui.label(
                egui::RichText::new(format!("{} of {} saved IP(s)", matched.len(), ips.len()))
                    .color(GOLD_DIM)
                    .small(),
            );
            ui.add_space(2.0);
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .max_height(380.0)
                .show(ui, |ui| {
                    for ip in matched {
                        let meta = app.state.clean_ip_meta.get(ip.as_str());
                        let (src_label, src_color) = match meta {
                            Some(m) => {
                                let s = m.split(':').next().unwrap_or("scan");
                                (source_label(s), source_color(s))
                            }
                            None => ("scanned", source_color("scan")),
                        };
                        egui::Frame::new()
                            .fill(CARD)
                            .inner_margin(egui::Margin::symmetric(10, 8))
                            .corner_radius(6.0)
                            .stroke(egui::Stroke::new(1.0, CARD_STROKE))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.vertical(|ui| {
                                        mono_copy_row(ui, ip);
                                        ui.horizontal(|ui| {
                                            tag(ui, src_label, src_color);
                                            if let Some(m) = meta {
                                                if let Some((_, p)) = m.rsplit_once(':') {
                                                    if let Ok(p) = p.parse::<u16>() {
                                                        tag(ui, &format!(":{p}"), GOLD_DIM);
                                                    }
                                                }
                                            }
                                        });
                                    });
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui
                                                .button("⚡")
                                                .on_hover_text("Probe reachability")
                                                .clicked()
                                            {
                                                action = Some(CleanipAction::Probe(ip.clone()));
                                            }
                                            if ui
                                                .button("🗑")
                                                .on_hover_text("Remove this clean IP")
                                                .clicked()
                                            {
                                                action = Some(CleanipAction::Remove(ip.clone()));
                                            }
                                        },
                                    );
                                });
                            });
                        ui.add_space(4.0);
                    }
                });
        }
    }

    ui.add_space(8.0);
    ui.separator();

    // Manual add box.
    ui.horizontal(|ui| {
        let mut add_text = String::new();
        add_text.push_str(&app.cleanip_add_draft);
        let resp = ui.add(
            egui::TextEdit::singleline(&mut add_text)
                .hint_text("Add one endpoint manually, e.g. 104.16.1.1:443")
                .desired_width(300.0),
        );
        if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            let v = add_text.trim().to_string();
            if !v.is_empty() {
                action = Some(CleanipAction::AddManual(v));
            }
        }
        if ui.button("➕ Add").clicked() {
            let v = add_text.trim().to_string();
            if !v.is_empty() {
                action = Some(CleanipAction::AddManual(v));
            }
        }
    });

    // Probe output line (from a background probe task).
    if !app.cleanip_test_output.is_empty() {
        ui.add_space(4.0);
        ui.label(
            egui::RichText::new(&app.cleanip_test_output)
                .color(GOLD)
                .small(),
        );
    }
    ui.add_space(4.0);

    // Action row.
    ui.horizontal(|ui| {
        if ui.button("📥 Import known-good IPs").clicked() {
            action = Some(CleanipAction::Import);
        }
        let export_btn = ui
            .add_enabled(!ips.is_empty(), egui::Button::new("💾 Export to file"))
            .on_hover_text("Save all clean IPs to a text file in the profile config folder");
        if export_btn.clicked() {
            action = Some(CleanipAction::ExportToFile);
        }
        let clear_btn = ui
            .add_enabled(!ips.is_empty(), egui::Button::new("🗑 Clear all"))
            .on_hover_text("Remove every saved clean IP");
        if clear_btn.clicked() {
            action = Some(CleanipAction::ClearAll);
        }
    });

    ui.add_space(6.0);

    // Seeds sub-list (imported known-good endpoints, not yet verified).
    if !app.state.seeds.is_empty() {
        section_card(ui, "Known-good seeds (imported)", |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Saved as scan seeds — promote to verified clean IPs.")
                        .color(GOLD_DIM)
                        .small(),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .button("🌟 Promote all")
                        .on_hover_text("Save every seed as a clean IP")
                        .clicked()
                    {
                        action = Some(CleanipAction::PromoteAllSeeds);
                    }
                });
            });
            ui.add_space(4.0);
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .max_height(140.0)
                .show(ui, |ui| {
                    for s in app.state.seeds.clone() {
                        ui.horizontal(|ui| {
                            mono_copy_row(ui, &s);
                            if ui
                                .button("★ Save as IP")
                                .on_hover_text("Promote this seed to a saved clean IP")
                                .clicked()
                            {
                                action = Some(CleanipAction::AddManual(s));
                            }
                        });
                        ui.add_space(2.0);
                    }
                });
        });
    }

    action
}

/// Run a clean-IP action. Returns a dialog to open, if any.
pub fn run_action(app: &mut DastYabApp, action: CleanipAction) -> Option<crate::dialogs::Dialog> {
    use crate::app::PendingDialogAction;
    match action {
        CleanipAction::Remove(ip) => {
            match remove_clean_ip(&app.profile_id, &ip) {
                Ok(_) => {
                    app.state.reload_pending = true;
                    app.note = format!("Removed clean IP {ip}.");
                }
                Err(e) => app.note = e.brief(),
            }
            None
        }
        CleanipAction::AddManual(ip) => {
            match remember_clean_ip_with_source(&app.profile_id, &ip, "manual") {
                Ok(_) => {
                    // Learn as a persistent seed too, so future scans bias
                    // toward this known-good IP (and its /24 neighbourhood).
                    let _ = remember_clean_ip_with_source(&app.profile_id, &ip, "manual");
                    if let Some(bare) = ip.split(':').next() {
                        let _ = dastyab_core::cf::ips::learn_clean_ip(&app.profile_id, bare);
                    }
                    app.state.reload_pending = true;
                    app.note = format!("Saved clean IP {ip}.");
                }
                Err(e) => app.note = e.brief(),
            }
            None
        }
        CleanipAction::Probe(ip) => {
            let pid = app.profile_id.clone();
            let tx = app.tx.clone();
            bridge_probe(pid, ip.clone(), tx);
            app.cleanip_test_output = format!("Probing {ip}…");
            None
        }
        CleanipAction::ProbeAll => {
            let ips = app.state.clean_ips.clone();
            let pid = app.profile_id.clone();
            let tx = app.tx.clone();
            let total = ips.len();
            crate::bridge::spawn("probe-all", tx, async move {
                let mut ok = 0usize;
                let mut out = String::new();
                for ip in &ips {
                    let reachable = probe_endpoint(ip).await;
                    out.push_str(&format!(
                        "  {ip} -> {}\n",
                        if reachable { "OK" } else { "FAIL" }
                    ));
                    if reachable {
                        ok += 1;
                        let _ = remember_clean_ip_with_source(&pid, ip, "scan");
                        if let Some(bare) = ip.split(':').next() {
                            let _ = dastyab_core::cf::ips::learn_clean_ip(&pid, bare);
                        }
                    }
                }
                out.push_str(&format!("{ok}/{} reachable", ips.len()));
                Ok::<String, CFError>(out)
            });
            app.cleanip_test_output = format!("Probing {total} endpoint(s)…");
            None
        }
        CleanipAction::CopyAll => {
            let all = app.state.clean_ips.join("\n");
            if all.is_empty() {
                app.note = "No clean IPs to copy.".to_string();
            } else {
                app.note = format!("Copied {} clean IP(s).", app.state.clean_ips.len());
            }
            None
        }
        CleanipAction::Export => {
            let all = app.state.clean_ips.join("\n");
            if all.is_empty() {
                app.note = "No clean IPs to export.".to_string();
            }
            None
        }
        CleanipAction::PromoteAllSeeds => {
            let seeds: Vec<String> = app.state.seeds.clone();
            let pid = app.profile_id.clone();
            let mut added = 0usize;
            for s in seeds {
                if remember_clean_ip_with_source(&pid, &s, "import").is_ok() {
                    added += 1;
                    if let Some(bare) = s.split(':').next() {
                        let _ = dastyab_core::cf::ips::learn_clean_ip(&pid, bare);
                    }
                }
            }
            app.state.reload_pending = true;
            app.note = format!("Promoted {added} seed(s) to clean IPs.");
            None
        }
        CleanipAction::ExportToFile => {
            let target = dastyab_core::cleanip::user_config_dir(&app.profile_id)
                .map(|d| d.join("cleanips.txt"))
                .unwrap_or_else(|_| std::path::PathBuf::from("cleanips.txt"));
            let content = app.state.clean_ips.join(
                "
",
            ) + "
";
            match std::fs::write(&target, content) {
                Ok(_) => {
                    app.note = format!(
                        "Exported {} clean IP(s) → {}",
                        app.state.clean_ips.len(),
                        target.display()
                    );
                }
                Err(e) => app.note = format!("Export failed: {e}"),
            }
            None
        }
        CleanipAction::ClearAll => {
            app.pending_action = Some(PendingDialogAction::ClearCleanIps);
            Some(crate::dialogs::confirm(
                "Clear all clean IPs",
                "Remove every saved clean IP for this profile? This cannot be undone.",
                true,
            ))
        }
        CleanipAction::Import => {
            app.pending_action = Some(PendingDialogAction::ImportSeeds);
            Some(crate::dialogs::prompt_text_area(
                "Import known-good IPs",
                "One IP per line — e.g.\n104.16.1.1\n104.16.2.1:2053  # fast",
            ))
        }
    }
}

/// Spawn a single-endpoint reachability probe (bridge task).
fn bridge_probe(pid: String, ip: String, tx: crate::bridge::Tx) {
    let ip2 = ip.clone();
    crate::bridge::spawn(&format!("probe-{ip2}"), tx, async move {
        let ok = probe_endpoint(&ip).await;
        if ok {
            let _ = remember_clean_ip_with_source(&pid, &ip, "scan");
            if let Some(bare) = ip.split(':').next() {
                let _ = dastyab_core::cf::ips::learn_clean_ip(&pid, bare);
            }
            Ok::<String, CFError>(format!("{ip} reachable ✓"))
        } else {
            Err(CFError::new(
                "Probe failed",
                format!("{ip} did not respond on the given port."),
                "It may be blocked from this network, or the port is wrong.",
            ))
        }
    });
}

/// Best-effort TCP reachability probe for an `ip[:port]` endpoint.
async fn probe_endpoint(ep: &str) -> bool {
    let (host, port) = match ep.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(443)),
        None => (ep.to_string(), 443),
    };
    use std::time::Duration;
    use tokio::net::TcpStream;
    let addr = match tokio::net::lookup_host((host.as_str(), port)).await {
        Ok(mut it) => match it.next() {
            Some(a) => a,
            None => return false,
        },
        Err(_) => return false,
    };
    tokio::time::timeout(Duration::from_secs(4), TcpStream::connect(&addr))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}
