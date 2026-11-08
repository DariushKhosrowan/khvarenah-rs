//! Tokens view — a list of per-profile API tokens with add / remove / verify.

use eframe::egui;
use khvarenah_core::store::profiles::remove_token;

use crate::app::KhvarenahApp;
use crate::views::{GOLD, GOLD_DIM, PANEL, TEXT};

/// Render the tokens panel. Returns an action the app should handle.
#[derive(Debug)]
pub enum TokensAction {
    /// Open the add-token (label + token) dialog.
    Add,
    /// Remove the token at this label.
    Remove(String),
    /// Verify the token at this label (spawns a bridge task).
    Verify(String),
}

pub fn show(ui: &mut egui::Ui, app: &KhvarenahApp) -> Option<TokensAction> {
    let mut action = None;

    ui.heading(egui::RichText::new("Tokens").color(GOLD));

    if app.state.tokens.is_empty() {
        ui.label(egui::RichText::new("No tokens yet — add one.").color(GOLD_DIM));
    } else {
        egui::ScrollArea::vertical()
            .max_height(320.0)
            .show(ui, |ui| {
                for t in &app.state.tokens {
                    egui::Frame::new()
                        .fill(PANEL)
                        .inner_margin(egui::Margin::symmetric(8, 6))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new(&t.label).strong());
                                ui.label(egui::RichText::new(&t.masked).color(TEXT).monospace());
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui.button("Verify").clicked() {
                                            action = Some(TokensAction::Verify(t.label.clone()));
                                        }
                                        if ui.button("Remove").clicked() {
                                            action = Some(TokensAction::Remove(t.label.clone()));
                                        }
                                    },
                                );
                            });
                            ui.label(
                                egui::RichText::new(format!("added {}", t.added_at))
                                    .color(GOLD_DIM),
                            );
                        });
                }
            });
    }

    ui.add_space(6.0);
    if ui.button("Add Token").clicked() {
        action = Some(TokensAction::Add);
    }

    action
}

/// Run a token action. Returns the dialog to open, if any.
pub fn run_action(app: &mut KhvarenahApp, action: TokensAction) -> Option<crate::dialogs::Dialog> {
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
            let _ = remove_token(&app.state.active_profile_id, &label);
            app.state.reload_pending = true;
            app.note = format!("Removed token '{label}'.");
            None
        }
        TokensAction::Verify(_label) => {
            // Verification requires the real token; the bridge task reads it
            // from the store by label. Spawn through the bridge.
            app.note = "Verify not yet wired to worker call — Phase 3.6.".to_string();
            None
        }
    }
}
