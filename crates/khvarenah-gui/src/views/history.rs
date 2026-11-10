//! History view — a full, filterable timeline that merges the profile's
//! persistent VlessRecord history (deploys + clean-IP scans) with the
//! blackout/rescue journal. Each entry shows its type, a readable local
//! timestamp, the resolved host/endpoint, and (for VlessRecords that carry a
//! share link) a one-click copy button.

use eframe::egui;
use khvarenah_core::journal::JournalKind;

use crate::app::{HistoryFilter, KhvarenahApp};
use crate::state::format_ts;
use crate::views::{GOLD, GOLD_DIM, PANEL, TEXT};

/// Short label for a journal entry kind.
fn journal_kind_label(kind: &JournalKind) -> &'static str {
    match kind {
        JournalKind::NetworkDown => "network-down",
        JournalKind::NetworkUp => "network-up",
        JournalKind::RescueAttempt => "rescue",
        JournalKind::CycleFailed => "cycle-failed",
        JournalKind::AccountBlocked => "account-blocked",
        JournalKind::TokenRecovered => "token-recovered",
        JournalKind::OutboxFlushed => "outbox-flushed",
        JournalKind::BackupWritten => "backup-written",
        JournalKind::MutationPerformed => "signature-rotated",
        JournalKind::DrillPerformed => "blackout-self-test",
    }
}

/// Accent color for a journal entry kind.
fn journal_kind_color(kind: &JournalKind) -> egui::Color32 {
    match kind {
        JournalKind::NetworkDown => egui::Color32::from_rgb(220, 120, 120),
        JournalKind::NetworkUp => egui::Color32::from_rgb(90, 210, 120),
        JournalKind::RescueAttempt => egui::Color32::from_rgb(230, 160, 60),
        JournalKind::CycleFailed => egui::Color32::from_rgb(220, 120, 120),
        JournalKind::AccountBlocked => egui::Color32::from_rgb(255, 90, 90),
        JournalKind::TokenRecovered => egui::Color32::from_rgb(140, 200, 255),
        JournalKind::OutboxFlushed => egui::Color32::from_rgb(170, 170, 220),
        JournalKind::BackupWritten => egui::Color32::from_rgb(150, 190, 255),
        JournalKind::MutationPerformed => egui::Color32::from_rgb(200, 160, 255),
        JournalKind::DrillPerformed => egui::Color32::from_rgb(120, 200, 180),
    }
}

/// One unified timeline row.
struct Item {
    epoch: i64,
    tag: &'static str,
    tag_color: egui::Color32,
    title: String,
    detail: String,
    link: Option<String>,
}

/// Render the history view for the active profile.
pub fn show(
    ui: &mut egui::Ui,
    app: &mut KhvarenahApp,
    p: &khvarenah_core::store::profiles::Profile,
) {
    ui.heading(egui::RichText::new("History").color(GOLD));

    // Filter tabs.
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Show:").color(GOLD_DIM));
        for (f, label) in [
            (HistoryFilter::All, "All"),
            (HistoryFilter::Deploys, "Deploys"),
            (HistoryFilter::CleanIps, "Clean IPs"),
            (HistoryFilter::Journal, "Journal"),
        ] {
            if ui
                .selectable_label(app.history_filter == f, label)
                .clicked()
            {
                app.history_filter = f;
            }
        }
    });
    ui.separator();

    let want_deploys = matches!(
        app.history_filter,
        HistoryFilter::All | HistoryFilter::Deploys
    );
    let want_clean = matches!(
        app.history_filter,
        HistoryFilter::All | HistoryFilter::CleanIps
    );
    let want_journal = matches!(
        app.history_filter,
        HistoryFilter::All | HistoryFilter::Journal
    );

    let mut items: Vec<Item> = Vec::new();

    // VlessRecord history (deploys + clean-IP scans).
    for r in &p.history {
        let is_clean = r.clean_ip;
        let wanted = if is_clean { want_clean } else { want_deploys };
        if !wanted {
            continue;
        }
        let (tag, tag_color) = if is_clean {
            ("clean-IP", egui::Color32::from_rgb(100, 170, 220))
        } else {
            ("workers.dev", GOLD)
        };
        let host = if r.name.is_empty() {
            &r.address
        } else {
            &r.name
        };
        items.push(Item {
            epoch: r.epoch as i64,
            tag,
            tag_color,
            title: host.clone(),
            detail: format!("{}:{} — {}", r.address, r.port, r.ts),
            link: if r.link.is_empty() {
                None
            } else {
                Some(r.link.clone())
            },
        });
    }

    // Blackout/rescue journal.
    if want_journal {
        let entries = khvarenah_core::journal::recent(&app.profile_id, 300);
        for e in &entries {
            items.push(Item {
                epoch: e.ts,
                tag: journal_kind_label(&e.kind),
                tag_color: journal_kind_color(&e.kind),
                title: e.detail.clone(),
                detail: String::new(),
                link: None,
            });
        }
    }

    items.sort_unstable_by_key(|it| std::cmp::Reverse(it.epoch));

    if items.is_empty() {
        ui.label(
            egui::RichText::new(
                "Nothing here yet — deploy, scan, or let the daemon run a few cycles.",
            )
            .color(GOLD_DIM),
        );
        return;
    }

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .max_height(500.0)
        .show(ui, |ui| {
            for it in &items {
                egui::Frame::new()
                    .fill(PANEL)
                    .inner_margin(egui::Margin::symmetric(10, 7))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(it.tag)
                                    .color(it.tag_color)
                                    .strong()
                                    .small(),
                            );
                            ui.add_space(6.0);
                            ui.label(egui::RichText::new(&it.title).color(TEXT));
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if let Some(link) = &it.link {
                                        if ui
                                            .button("📋")
                                            .on_hover_text("Copy share link")
                                            .clicked()
                                        {
                                            ui.ctx().copy_text(link.clone());
                                        }
                                    }
                                },
                            );
                        });
                        if !it.detail.is_empty() {
                            ui.label(egui::RichText::new(&it.detail).color(GOLD_DIM).small());
                        }
                        ui.label(
                            egui::RichText::new(format_ts(it.epoch))
                                .color(GOLD_DIM)
                                .small(),
                        );
                    });
                ui.add_space(4.0);
            }
        });
}
