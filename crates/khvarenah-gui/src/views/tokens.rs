//! Tokens view — a per-profile list of API tokens with add / remove /
//! verify, an active-token marker, and one-click "make active".

use eframe::egui;
use khvarenah_core::store::profiles::{get_token, remove_token, set_active_token};

use crate::app::KhvarenahApp;
use crate::bridge;
use crate::views::{GOLD, GOLD_DIM, PANEL, TEXT};
use khvarenah_core::CFError;

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

pub fn show(ui: &mut egui::Ui, app: &KhvarenahApp) -> Option<TokensAction> {
    let mut action = None;

    ui.heading(egui::RichText::new("Tokens").color(GOLD));
    ui.label(
        egui::RichText::new("API tokens for this profile — mark one active for deploy/scan.")
            .color(GOLD_DIM),
    );
    ui.add_space(6.0);

    if app.state.tokens.is_empty() {
        ui.add_space(8.0);
        ui.label(egui::RichText::new("No tokens yet — add one.").color(GOLD_DIM));
    } else {
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .max_height(400.0)
            .show(ui, |ui| {
                for t in &app.state.tokens {
                    let is_active = t.is_active;
                    let frame = egui::Frame::new()
                        .fill(if is_active { PANEL } else { PANEL })
                        .inner_margin(egui::Margin::symmetric(10, 6))
                        .stroke(if is_active {
                            egui::Stroke::new(1.5, GOLD)
                        } else {
                            egui::Stroke::new(0.0, egui::Color32::TRANSPARENT)
                        });
                    frame.show(ui, |ui| {
                        ui.horizontal(|ui| {
                            if is_active {
                                ui.label(egui::RichText::new("●").color(GOLD).strong());
                            }
                            ui.label(
                                egui::RichText::new(&t.label)
                                    .color(if is_active { GOLD } else { TEXT })
                                    .strong(),
                            );
                            ui.label(egui::RichText::new(&t.masked).color(TEXT).monospace());
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui.button("🗑").on_hover_text("Remove token").clicked() {
                                        action = Some(TokensAction::Remove(t.label.clone()));
                                    }
                                    if is_active {
                                        ui.label(
                                            egui::RichText::new("ACTIVE")
                                                .color(GOLD)
                                                .small()
                                                .strong(),
                                        );
                                    } else if ui.button("Make active").clicked() {
                                        action = Some(TokensAction::MakeActive(t.label.clone()));
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
                        ui.label(
                            egui::RichText::new(format!(
                                "added {} ({})",
                                t.added_at, t.added_at_abs
                            ))
                            .color(GOLD_DIM)
                            .small(),
                        );
                    });
                    ui.add_space(5.0);
                }
            });
    }

    ui.add_space(8.0);
    ui.separator();
    if ui.button("➕ Add Token").clicked() {
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
        TokensAction::Verify(label) => {
            // Real verification: read the token from the store by label and
            // run it through the CF verify_token endpoint on the bridge.
            let pid = app.state.active_profile_id.clone();
            let token = get_token(&pid, &label).ok().flatten();
            match token {
                Some(token) => {
                    let tx = app.tx.clone();
                    let run_label = label.clone();
                    bridge::spawn(&format!("verify-{label}"), tx, async move {
                        let client = khvarenah_core::cf::Client::new(&token);
                        let res = client.verify_token().await?;
                        let status = if res.status.is_empty() {
                            "active".to_string()
                        } else {
                            res.status
                        };
                        if status == "active" {
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
            match set_active_token(&app.state.active_profile_id, &label) {
                Ok(_) => {
                    app.state.reload_pending = true;
                    app.note = format!("'{label}' is now the active token.");
                }
                Err(e) => app.note = e.brief(),
            }
            None
        }
    }
}
