//! Clean IPs view — a fast, searchable manager for the profile's saved
//! clean-IP endpoints. Includes copy/delete per entry, search, stats,
//! copy-all, clear-all, and import of known-good seeds.

use eframe::egui;
use khvarenah_core::store::profiles::remove_clean_ip;

use crate::app::KhvarenahApp;
use crate::views::{mono_copy_row, stat_chips, CARD, CARD_STROKE, GOLD, GOLD_DIM};

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
}

pub fn show(ui: &mut egui::Ui, app: &mut KhvarenahApp) -> Option<CleanipAction> {
    let mut action = None;

    ui.heading(egui::RichText::new("Clean IPs").color(GOLD));
    ui.label(
        egui::RichText::new("Verified endpoints saved per profile — search, copy, or prune.")
            .color(GOLD_DIM),
    );
    ui.add_space(6.0);

    let ips = &app.state.clean_ips;

    // Stats chip row (always visible, even when empty).
    stat_chips(ui, &[("saved", &ips.len().to_string())]);

    // Search box (only when there is anything to search).
    if !ips.is_empty() {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Search:").color(GOLD_DIM));
            ui.add(
                egui::TextEdit::singleline(&mut app.cleanip_search)
                    .hint_text("filter IPs…")
                    .desired_width(220.0),
            );
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
        });
        ui.add_space(4.0);
    }

    if ips.is_empty() {
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new(
                "No clean IPs found yet — scan from Deploy & Scan, or import known-good seeds below.",
            )
            .color(GOLD_DIM),
        );
    } else {
        let query = app.cleanip_search.trim().to_lowercase();
        let matched: Vec<&String> = ips
            .iter()
            .filter(|ip| query.is_empty() || ip.to_lowercase().contains(&query))
            .collect();

        if matched.is_empty() {
            ui.label(egui::RichText::new("No saved IP matches that search.").color(GOLD_DIM));
        } else {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .max_height(420.0)
                .show(ui, |ui| {
                    for ip in matched {
                        egui::Frame::new()
                            .fill(CARD)
                            .inner_margin(egui::Margin::symmetric(10, 8))
                            .corner_radius(6.0)
                            .stroke(egui::Stroke::new(1.0, CARD_STROKE))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.vertical(|ui| {
                                        mono_copy_row(ui, ip);
                                        ui.label(
                                            egui::RichText::new("verified clean-IP")
                                                .color(GOLD_DIM)
                                                .small(),
                                        );
                                    });
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
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

    // Action row.
    ui.horizontal(|ui| {
        if ui.button("📥 Import known-good IPs").clicked() {
            action = Some(CleanipAction::Import);
        }
        let clear_btn = ui
            .add_enabled(!ips.is_empty(), egui::Button::new("🗑 Clear all"))
            .on_hover_text("Remove every saved clean IP");
        if clear_btn.clicked() {
            action = Some(CleanipAction::ClearAll);
        }
    });

    action
}

/// Run a clean-IP action. Returns a dialog to open, if any.
pub fn run_action(app: &mut KhvarenahApp, action: CleanipAction) -> Option<crate::dialogs::Dialog> {
    use crate::app::PendingDialogAction;
    match action {
        CleanipAction::Remove(ip) => {
            match remove_clean_ip(&app.state.active_profile_id, &ip) {
                Ok(_) => {
                    app.state.reload_pending = true;
                    app.note = format!("Removed clean IP {ip}.");
                }
                Err(e) => app.note = e.brief(),
            }
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
