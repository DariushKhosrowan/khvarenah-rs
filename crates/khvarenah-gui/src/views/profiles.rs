//! Profiles view — a scrollable list of profiles with create / switch /
//! rename / delete actions, plus Import/Export stubs (Phase 3.7).

use eframe::egui;
use khvarenah_core::store::profiles::set_active_profile;

use crate::app::KhvarenahApp;
use crate::state::ProfileSummary;
use crate::views::{GOLD, GOLD_DIM, PANEL, TEXT};

/// One row of the profile list, rendered with the gold-` stroke when active.
fn profile_row(ui: &mut egui::Ui, p: &ProfileSummary) {
    let name = if p.is_active {
        egui::RichText::new(&p.name).color(GOLD).strong()
    } else {
        egui::RichText::new(&p.name).color(TEXT)
    };

    // left-edge stroke for the active row
    let frame = egui::Frame::new()
        .fill(PANEL)
        .inner_margin(egui::Margin::symmetric(8, 6))
        .stroke(if p.is_active {
            egui::Stroke::new(2.0, GOLD)
        } else {
            egui::Stroke::new(0.0, egui::Color32::TRANSPARENT)
        });

    frame.show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(name);
            if p.token_count > 0 {
                ui.label(egui::RichText::new(format!("[{}]", p.token_count)).color(GOLD_DIM));
            }
        });
    });
}

/// Render the profiles panel and return an optional action the app should run.
#[derive(Debug)]
pub enum ProfilesAction {
    /// Switch the active profile.
    Switch(String),
    /// Request the "new profile" text dialog.
    New,
    /// Request the "rename" text dialog for this profile.
    Rename(String),
    /// Request the "delete" confirmation dialog for this profile.
    Delete(String),
}

pub fn show(
    ui: &mut egui::Ui,
    app: &KhvarenahApp,
    selected: Option<usize>,
) -> Option<ProfilesAction> {
    let mut action = None;

    ui.heading(egui::RichText::new("Profiles").color(GOLD));

    // the list
    egui::ScrollArea::vertical()
        .max_height(300.0)
        .show(ui, |ui| {
            for (i, p) in app.state.profiles.iter().enumerate() {
                if selected == Some(i) {
                    profile_row(ui, p);
                } else {
                    ui.push_id(i, |ui| {
                        let resp = ui.add_sized(
                            egui::vec2(ui.available_width(), 0.0),
                            egui::Label::new(p.name.as_str()),
                        );
                        if resp.clicked() {
                            action = Some(ProfilesAction::Switch(p.id.clone()));
                        }
                    });
                }
            }
        });

    ui.add_space(6.0);

    // action buttons
    ui.horizontal(|ui| {
        if ui.button("New Profile").clicked() {
            action = Some(ProfilesAction::New);
        }
        if let Some(i) = selected {
            if let Some(p) = app.state.profiles.get(i) {
                if ui.button("Rename").clicked() {
                    action = Some(ProfilesAction::Rename(p.id.clone()));
                }
                if ui.button("Delete").clicked() {
                    action = Some(ProfilesAction::Delete(p.id.clone()));
                }
            }
        }
    });

    ui.horizontal(|ui| {
        let imp = ui.add_enabled(false, egui::Button::new("Import"));
        imp.on_hover_text("Phase 3.7");
        let exp = ui.add_enabled(false, egui::Button::new("Export"));
        exp.on_hover_text("Phase 3.7");
    });

    ui.add_space(4.0);
    ui.label(
        egui::RichText::new(
            "Select a profile to manage it. Tokens, configs and clean IPs live per-profile.",
        )
        .color(GOLD_DIM),
    );

    action
}

/// Run an action that requires a dialog. Returns the dialog to open, if any.
pub fn run_action(
    app: &mut KhvarenahApp,
    action: ProfilesAction,
) -> Option<crate::dialogs::Dialog> {
    use crate::app::PendingDialogAction;
    match action {
        ProfilesAction::Switch(id) => {
            let id_ = id.clone();
            // persist active profile; the store helper validates the id
            let _ = set_active_profile(&id_);
            app.state.active_profile_id = id;
            app.state.reload_pending = true;
            app.note = format!("Switched to profile '{}'.", app.state.active_profile_id);
            None
        }
        ProfilesAction::New => {
            app.pending_action = Some(PendingDialogAction::CreateProfile);
            Some(crate::dialogs::prompt_text("New profile", "Profile name"))
        }
        ProfilesAction::Rename(id) => {
            app.pending_action = Some(PendingDialogAction::RenameProfile(id));
            Some(crate::dialogs::prompt_text("Rename profile", "New name"))
        }
        ProfilesAction::Delete(id) => {
            app.pending_action = Some(PendingDialogAction::DeleteProfile(id.clone()));
            Some(crate::dialogs::confirm(
                "Delete profile",
                format!("Delete profile '{id}'? This cannot be undone."),
                true,
            ))
        }
    }
}
