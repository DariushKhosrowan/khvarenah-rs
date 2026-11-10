//! History view — a full, filterable timeline that merges the profile's
//! persistent VlessRecord history (deploys + clean-IP scans) with the
//! blackout/rescue journal. Each entry shows its type, a readable local
//! timestamp, the resolved host/endpoint, and (for VlessRecords that carry a
//! share link) a one-click copy button. Entries can be deleted individually
//! or the whole VlessRecord stream cleared. Stats, search, and export
//! round out the view.

use eframe::egui;
use dastyab_core::journal::JournalKind;

use crate::app::{HistoryFilter, DastYabApp, PendingDialogAction};
use crate::dialogs;
use crate::state::{format_ts, relative_ts};
use crate::views::{section_card, stat_chips, tag, CARD, CARD_STROKE, GOLD, GOLD_DIM, TEXT};
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

/// Label + accent for a token-ledger event kind.
fn token_kind(kind: &str) -> (&'static str, egui::Color32) {
    match kind {
        "added" => ("token added", egui::Color32::from_rgb(90, 210, 120)),
        "removed" => ("token removed", egui::Color32::from_rgb(220, 120, 120)),
        "made_active" => ("made active", GOLD),
        "verified" => ("verified", egui::Color32::from_rgb(140, 200, 255)),
        "rotated" => ("rotated", egui::Color32::from_rgb(200, 160, 255)),
        "auto_rotate" => ("auto-rotate", egui::Color32::from_rgb(255, 170, 90)),
        _ => ("token event", GOLD_DIM),
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
    /// Stable rec id for per-item delete (None for journal entries).
    rec_id: Option<String>,
}

/// Render the history view for the active profile.
pub fn show(
    ui: &mut egui::Ui,
    app: &mut DastYabApp,
    p: &dastyab_core::store::profiles::Profile,
) {
    ui.heading(egui::RichText::new("History").color(GOLD));

    // Filter tabs + clear actions.
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Show:").color(GOLD_DIM));
        for (f, label) in [
            (HistoryFilter::All, "All"),
            (HistoryFilter::Deploys, "Deploys"),
            (HistoryFilter::CleanIps, "Clean IPs"),
            (HistoryFilter::Tokens, "Tokens"),
            (HistoryFilter::Journal, "Journal"),
        ] {
            if ui
                .selectable_label(app.history_filter == f, label)
                .clicked()
            {
                app.history_filter = f;
            }
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let clear = ui
                .add_enabled(!p.history.is_empty(), egui::Button::new("🗑 Clear config history"))
                .on_hover_text("Delete all deploy + clean-IP records (journal is kept)");
            if clear.clicked() {
                app.pending_action = Some(PendingDialogAction::ClearHistory);
                app.dialog = Some(dialogs::confirm(
                    "Clear history",
                    "Delete all saved deploy + clean-IP records for this profile? The journal is kept.",
                    true,
                ));
            }
        });
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
    let want_tokens = matches!(
        app.history_filter,
        HistoryFilter::All | HistoryFilter::Tokens
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
            rec_id: Some(r.id.clone()),
        });
    }

    // Blackout/rescue journal.
    if want_journal {
        let entries = dastyab_core::journal::recent(&app.profile_id, 300);
        for e in &entries {
            items.push(Item {
                epoch: e.ts,
                tag: journal_kind_label(&e.kind),
                tag_color: journal_kind_color(&e.kind),
                title: e.detail.clone(),
                detail: String::new(),
                link: None,
                rec_id: None,
            });
        }
    }

    // Token-lifecycle ledger (adds/removes/active/verify/rotate).
    if want_tokens {
        for e in &app.state.token_ledger {
            let (label, color) = token_kind(&e.kind);
            let mut title = e.label.clone();
            if !e.note.is_empty() {
                title.push_str(&format!(" — {}", e.note));
            }
            items.push(Item {
                epoch: e.epoch,
                tag: label,
                tag_color: color,
                title,
                detail: String::new(),
                link: None,
                rec_id: None,
            });
        }
    }

    items.sort_unstable_by_key(|it| std::cmp::Reverse(it.epoch));

    // Stats chips.
    {
        let deploys = items.iter().filter(|it| it.tag == "workers.dev").count();
        let clean = items.iter().filter(|it| it.tag == "clean-IP").count();
        let tokens = items
            .iter()
            .filter(|it| {
                matches!(
                    it.tag,
                    "token added"
                        | "token removed"
                        | "made active"
                        | "verified"
                        | "rotated"
                        | "auto-rotate"
                        | "token event"
                )
            })
            .count();
        let journal = items.len().saturating_sub(deploys + clean + tokens);
        stat_chips(
            ui,
            &[
                ("entries", &items.len().to_string()),
                ("deploys", &deploys.to_string()),
                ("clean-IP", &clean.to_string()),
                ("tokens", &tokens.to_string()),
                ("journal", &journal.to_string()),
            ],
        );
    }

    if items.is_empty() {
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new(
                "Nothing here yet — deploy, scan, or let the daemon run a few cycles.",
            )
            .color(GOLD_DIM),
        );
        return;
    }

    // Live search filter.
    let query = {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Search:").color(GOLD_DIM));
            ui.add(
                egui::TextEdit::singleline(&mut app.history_search)
                    .hint_text("filter entries…")
                    .desired_width(220.0),
            );
            if ui
                .button("📋 Export")
                .on_hover_text("Copy all entries to clipboard")
                .clicked()
            {
                let mut buf = String::new();
                for it in &items {
                    buf.push_str(&format!(
                        "[{}] {} — {}\n",
                        it.tag,
                        it.title,
                        format_ts(it.epoch)
                    ));
                    if !it.detail.is_empty() {
                        buf.push_str(&format!("    {}\n", it.detail));
                    }
                }
                ui.ctx().copy_text(buf.clone());
                app.note = format!("Exported {} history entries to clipboard.", items.len());
            }
        });
        app.history_search.trim().to_lowercase()
    };
    ui.add_space(4.0);

    let shown = items
        .iter()
        .filter(|it| {
            query.is_empty()
                || it.title.to_lowercase().contains(&query)
                || it.tag.to_lowercase().contains(&query)
                || it.detail.to_lowercase().contains(&query)
        })
        .count();

    if shown == 0 {
        ui.label(egui::RichText::new("No entries match that search.").color(GOLD_DIM));
        return;
    }

    ui.label(
        egui::RichText::new(format!("{shown} entries"))
            .color(GOLD_DIM)
            .small(),
    );
    ui.add_space(4.0);

    section_card(ui, "Timeline", |ui| {
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .max_height(520.0)
            .show(ui, |ui| {
                for it in items.iter().filter(|it| {
                    query.is_empty()
                        || it.title.to_lowercase().contains(&query)
                        || it.tag.to_lowercase().contains(&query)
                        || it.detail.to_lowercase().contains(&query)
                }) {
                    egui::Frame::new()
                        .fill(CARD)
                        .inner_margin(egui::Margin::symmetric(10, 7))
                        .corner_radius(6.0)
                        .stroke(egui::Stroke::new(1.0, CARD_STROKE))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                tag(ui, it.tag, it.tag_color);
                                ui.add_space(4.0);
                                ui.label(egui::RichText::new(&it.title).color(TEXT));
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if let Some(rec_id) = &it.rec_id {
                                            if ui
                                                .button("🗑")
                                                .on_hover_text("Delete this entry")
                                                .clicked()
                                            {
                                                app.pending_action =
                                                    Some(PendingDialogAction::DeleteHistoryRecord(
                                                        rec_id.clone(),
                                                    ));
                                                app.dialog = Some(dialogs::confirm(
                                                    "Delete history entry",
                                                    "Delete this history entry?",
                                                    true,
                                                ));
                                            }
                                        }
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
                                ui.add_space(2.0);
                                ui.label(egui::RichText::new(&it.detail).color(GOLD_DIM).small());
                            }
                            ui.label(
                                egui::RichText::new(format!(
                                    "{} · {}",
                                    relative_ts(it.epoch),
                                    format_ts(it.epoch)
                                ))
                                .color(GOLD_DIM)
                                .small(),
                            );
                        });
                    ui.add_space(4.0);
                }
            });
    });
}
