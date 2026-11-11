//! Tokens view — a per-profile list of API tokens with add / remove /
//! verify, an active-token marker, live search, and one-click "make active".
//!
//! Below the token list sits the **token-history ledger**: a durable timeline
//! of every lifecycle event (added / removed / made-active / verified) so
//! the user always knows who/what happened to their keys.
//!
//! Design: a gold-rule header, a stats chip row, a live filter box, then a
//! scrollable card list. Active tokens get a gold stroke and a "● ACTIVE"
//! badge; secondary tokens offer Make-active / Verify / Remove actions.

use eframe::egui;
use dastyab_core::store::profiles::{
    get_token, record_token_verified, remove_token, set_active_token,
};

use crate::app::DastYabApp;
use crate::bridge;
use crate::dialogs;
use crate::views::{
    section_card, stat_chips, tag, CARD, CARD_STROKE, GOLD, GOLD_DIM, SUCCESS, TEXT,
};
use dastyab_core::CFError;

/// Render the tokens panel. Returns an action the app should handle.
#[derive(Debug)]
pub enum TokensAction {
    /// Open the add-token (label + token) dialog.
    Add,
    /// Remove the token at this label.
    Remove(String),
    /// Verify the token at this label (spawns a bridge task).
    Verify(String),
    /// Mark this token as the profile's active token.
    MakeActive(String),
}

/// Label + accent for a token-ledger event kind.
fn ledger_kind(kind: &str) -> (&str, egui::Color32) {
    match kind {
        "added" => ("added", egui::Color32::from_rgb(90, 210, 120)),
        "removed" => ("removed", egui::Color32::from_rgb(220, 120, 120)),
        "made_active" => ("made active", GOLD),
        "verified" => ("verified", egui::Color32::from_rgb(140, 200, 255)),
        "rotated" => ("rotated", egui::Color32::from_rgb(200, 160, 255)),
        "auto_rotate" => ("auto-rotate", egui::Color32::from_rgb(255, 170, 90)),
        other => (other, GOLD_DIM),
    }
}

pub fn show(ui: &mut egui::Ui, app: &mut DastYabApp) -> Option<TokensAction> {
    let mut action = None;

    ui.heading(egui::RichText::new("Tokens").color(GOLD));
    ui.label(
        egui::RichText::new("API tokens for this profile — mark one active for deploy/scan.")
            .color(GOLD_DIM),
    );
    ui.add_space(6.0);

    // Stats chips.
    {
        let total = app.state.tokens.len();
        let active = app
            .state
            .active_token_label
            .clone()
            .unwrap_or_else(|| "—".to_string());
        let events = app.state.token_ledger.len();
        stat_chips(
            ui,
            &[
                ("tokens", &total.to_string()),
                ("active", &active),
                ("events", &events.to_string()),
            ],
        );
    }

    if app.state.tokens.is_empty() {
        ui.add_space(8.0);
        ui.label(egui::RichText::new("No tokens yet — add one.").color(GOLD_DIM));
    } else {
        // Live search filter.
        let query = {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Search:").color(GOLD_DIM));
                ui.add(
                    egui::TextEdit::singleline(&mut app.token_search)
                        .hint_text("filter by label…")
                        .desired_width(220.0),
                );
                ui.label(
                    egui::RichText::new(format!("{} token(s)", app.state.tokens.len()))
                        .color(GOLD_DIM)
                        .small(),
                );
            });
            app.token_search.trim().to_lowercase()
        };
        ui.add_space(4.0);

        let matched: Vec<&crate::state::TokenSummary> = app
            .state
            .tokens
            .iter()
            .filter(|t| query.is_empty() || t.label.to_lowercase().contains(&query))
            .collect();

        if matched.is_empty() {
            ui.label(egui::RichText::new("No token matches that search.").color(GOLD_DIM));
            ui.add_space(8.0);
        } else {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .max_height(340.0)
                .show(ui, |ui| {
                    for t in matched {
                        let is_active = t.is_active;
                        let frame = egui::Frame::new()
                            .fill(CARD)
                            .inner_margin(egui::Margin::symmetric(10, 8))
                            .corner_radius(6.0)
                            .stroke(if is_active {
                                egui::Stroke::new(1.5, GOLD)
                            } else {
                                egui::Stroke::new(1.0, CARD_STROKE)
                            });
                        frame.show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    ui.horizontal(|ui| {
                                        if is_active {
                                            ui.label(egui::RichText::new("●").color(GOLD).strong());
                                        }
                                        ui.label(
                                            egui::RichText::new(&t.label)
                                                .color(if is_active { GOLD } else { TEXT })
                                                .strong(),
                                        );
                                        ui.label(
                                            egui::RichText::new(&t.masked).color(TEXT).monospace(),
                                        );
                                    });
                                    ui.label(
                                        egui::RichText::new(format!(
                                            "added {} ({})",
                                            t.added_at, t.added_at_abs
                                        ))
                                        .color(GOLD_DIM)
                                        .small(),
                                    );
                                });
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if is_active {
                                            tag(ui, "ACTIVE", SUCCESS);
                                            ui.add_space(6.0);
                                        }
                                        if ui.button("🗑").on_hover_text("Remove token").clicked()
                                        {
                                            action = Some(TokensAction::Remove(t.label.clone()));
                                        }
                                        if !is_active && ui.button("Make active").clicked() {
                                            action =
                                                Some(TokensAction::MakeActive(t.label.clone()));
                                        }
                                        if ui
                                            .button("Verify")
                                            .on_hover_text("Check this token against Cloudflare")
                                            .clicked()
                                        {
                                            action = Some(TokensAction::Verify(t.label.clone()));
                                        }
                                    },
                                );
                            });
                        });
                        ui.add_space(6.0);
                    }
                });
        }
    }

    ui.add_space(8.0);
    ui.separator();
    if ui.button("➕ Add Token").clicked() {
        action = Some(TokensAction::Add);
    }

    // ── Token-history ledger ───────────────────────────────────────
    ui.add_space(10.0);
    section_card(ui, "Token history", |ui| {
        if app.state.token_ledger.is_empty() {
            ui.label(
                egui::RichText::new(
                    "No token events recorded yet — add, remove, or verify a token to build the ledger.",
                )
                .color(GOLD_DIM),
            );
            return;
        }
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Search:").color(GOLD_DIM));
            ui.add(
                egui::TextEdit::singleline(&mut app.token_history_search)
                    .hint_text("filter events…")
                    .desired_width(160.0),
            );
            egui::ComboBox::from_id_salt("tokled_filter")
                .selected_text(if app.token_history_filter.is_empty() {
                    "kind: all".to_string()
                } else {
                    format!("kind: {}", app.token_history_filter)
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut app.token_history_filter,
                        String::new(),
                        "all",
                    );
                    for k in ["added", "removed", "made_active", "verified", "rotated", "auto_rotate"]
                    {
                        ui.selectable_value(
                            &mut app.token_history_filter,
                            k.to_string(),
                            k,
                        );
                    }
                });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .button("📋 Export")
                    .on_hover_text("Copy the whole token-history ledger to clipboard")
                    .clicked()
                {
                    let mut buf = String::new();
                    for e in &app.state.token_ledger {
                        buf.push_str(&format!(
                            "[{}] {} — {} ({})\n",
                            e.kind,
                            e.label,
                            e.note,
                            crate::state::format_ts(e.epoch)
                        ));
                    }
                    ui.ctx().copy_text(buf.clone());
                    app.note =
                        format!("Exported {} token-history events to clipboard.", app.state.token_ledger.len());
                }
                if ui
                    .button("🗑 Clear ledger")
                    .on_hover_text("Delete the whole token-history ledger")
                    .clicked()
                {
                    app.pending_action = Some(crate::app::PendingDialogAction::ClearTokenHistory);
                    app.dialog = Some(dialogs::confirm(
                        "Clear token history",
                        "Delete the entire token-history ledger for this profile? Tokens themselves are not touched.",
                        true,
                    ));
                }
            });
        });
        ui.add_space(4.0);
        let q = app.token_history_search.trim().to_lowercase();
        let kf = app.token_history_filter.trim().to_lowercase();
        let shown = app
            .state
            .token_ledger
            .iter()
            .filter(|e| {
                (kf.is_empty() || e.kind.to_lowercase() == kf)
                    && (q.is_empty()
                        || e.label.to_lowercase().contains(&q)
                        || e.kind.to_lowercase().contains(&q)
                        || e.note.to_lowercase().contains(&q))
            })
            .collect::<Vec<_>>();
        if shown.is_empty() {
            ui.label(egui::RichText::new("No events match that search.").color(GOLD_DIM));
            return;
        }
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .max_height(220.0)
            .show(ui, |ui| {
                for e in shown {
                    let (label, color) = ledger_kind(&e.kind);
                    egui::Frame::new()
                        .fill(PANEL_ROW)
                        .inner_margin(egui::Margin::symmetric(8, 6))
                        .corner_radius(6.0)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                tag(ui, label, color);
                                ui.add_space(4.0);
                                ui.label(egui::RichText::new(&e.label).color(TEXT).strong());
                                ui.label(egui::RichText::new(&e.note).color(GOLD_DIM).small());
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.label(
                                            egui::RichText::new(format!(
                                                "{} · {}",
                                                crate::state::relative_ts(e.epoch),
                                                crate::state::format_ts(e.epoch)
                                            ))
                                            .color(GOLD_DIM)
                                            .small(),
                                        );
                                        if ui
                                            .button("🗑")
                                            .on_hover_text("Delete this token-history event")
                                            .clicked()
                                        {
                                            app.pending_action = Some(
                                                crate::app::PendingDialogAction::DeleteTokenHistoryEvent(
                                                    e.id.clone(),
                                                ),
                                            );
                                            app.dialog = Some(dialogs::confirm(
                                                "Delete token-history event",
                                                "Delete this ledger event? Tokens themselves are not touched.",
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
    });

    action
}

/// Row surface for ledger entries (slightly darker than card).
const PANEL_ROW: egui::Color32 = egui::Color32::from_rgb(20, 17, 12);

/// Run a token action. Returns the dialog to open, if any.
pub fn run_action(app: &mut DastYabApp, action: TokensAction) -> Option<crate::dialogs::Dialog> {
    use crate::app::PendingDialogAction;
    match action {
        TokensAction::Add => {
            app.pending_action = Some(PendingDialogAction::AddToken);
            Some(crate::dialogs::prompt_two(
                "Add token",
                "Label",
                "Token",
                true,
            ))
        }
        TokensAction::Remove(label) => {
            // Target the profile the user is actually viewing (`profile_id`),
            // mirroring Add/MakeActive. Using the possibly-stale cached
            // `state.active_profile_id` here could remove from the wrong
            // profile if the cache lags the selection.
            let _ = remove_token(&app.profile_id, &label);
            app.state.reload_pending = true;
            app.note = format!("Removed token '{label}'.");
            None
        }
        TokensAction::Verify(label) => {
            // Real verification: read the token from the store by label and
            // run it through the CF verify_token endpoint on the bridge.
            // Target the profile the user is actually viewing (`profile_id`),
            // not the possibly-stale cached `state.active_profile_id` (same
            // rule as MakeActive/Add/Remove) so a stale cache can never verify
            // against the wrong profile.
            let pid = app.profile_id.clone();
            let token = get_token(&pid, &label).ok().flatten();
            match token {
                Some(token) => {
                    let tx = app.tx.clone();
                    let run_label = label.clone();
                    let pid2 = pid.clone();
                    bridge::spawn(&format!("verify-{label}"), tx, async move {
                        let client = dastyab_core::cf::Client::new(&token);
                        let res = client.verify_token().await?;
                        let status = if res.status.is_empty() {
                            "active".to_string()
                        } else {
                            res.status
                        };
                        if status == "active" {
                            let _ = record_token_verified(
                                &pid2,
                                &run_label,
                                "verified active on Cloudflare",
                            );
                            Ok::<String, CFError>(format!(
                                "✓ token '{run_label}' verified (active)."
                            ))
                        } else {
                            Err(CFError::new(
                                "Token invalid",
                                format!(
                                    "Token '{run_label}' is {status} — Cloudflare rejected it."
                                ),
                                "Check the token is still active and has the right permissions.",
                            ))
                        }
                    });
                    None
                }
                None => {
                    app.note = format!("No stored value for token '{label}'.");
                    None
                }
            }
        }
        TokensAction::MakeActive(label) => {
            // Target the profile the user is actually viewing (`profile_id`),
            // not the possibly-stale cached `state.active_profile_id` — a
            // mismatch here silently no-ops ("nothing happens"). We also guard
            // against a stale token list by re-reading the target profile's
            // active token from the store before mutating in-memory state.
            if app.profile_id.is_empty() {
                app.note = "No profile selected — pick a profile first.".to_string();
                return None;
            }
            // Only record an activation if this is not already the active token
            // (avoids a confusing no-op that looks like a failure).
            let already = dastyab_core::store::profiles::get_active_token(&app.profile_id)
                .ok()
                .flatten();
            match set_active_token(&app.profile_id, &label) {
                Ok(_) => {
                    // Reflect the change immediately (not just after the next
                    // reload) so the click has visible feedback.
                    app.state.active_token_label = Some(label.clone());
                    for t in &mut app.state.tokens {
                        t.is_active = t.label == label;
                    }
                    app.note = if already.as_deref() == Some(label.as_str()) {
                        format!("'{label}' is already the active token.")
                    } else {
                        format!("'{label}' is now the active token.")
                    };
                    // Force a reload next frame so the store-driven view and the
                    // in-memory view stay consistent.
                    app.state.reload_pending = true;
                }
                Err(e) => app.note = e.brief(),
            }
            None
        }
    }
}
