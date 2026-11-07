//! Reusable modal dialog helpers.
//!
//! egui has no native modal; we implement a small state machine on an
//! `Option<Dialog>` field. Each dialog returns a value (or `None` when still
//! open) and never blocks the UI thread — the caller polls it every frame.

use eframe::egui;

/// What a dialog is currently waiting for.
#[derive(Debug, Clone)]
pub enum Dialog {
    /// Yes/No confirmation. `destructive` tints the confirm button red.
    Confirm {
        title: String,
        body: String,
        destructive: bool,
    },
    /// One text input (e.g. new profile name, rename target).
    Text {
        title: String,
        placeholder: String,
        draft: String,
    },
    /// Two text inputs (e.g. label + token). `mask_b` makes field B a
    /// password field.
    Two {
        title: String,
        label_a: String,
        label_b: String,
        draft_a: String,
        draft_b: String,
        mask_b: bool,
    },
}

/// The outcome of a dialog after one frame of rendering.
pub enum DialogResult {
    /// Dialog still open; draw nothing else.
    Open,
    /// User submitted; carry the payload.
    Submit(DialogPayload),
    /// User cancelled / dismissed.
    Cancel,
}

/// A submitted value from a dialog.
#[derive(Debug, Clone)]
pub enum DialogPayload {
    Confirm,
    Text(String),
    Two(String, String),
}

/// Render the currently-open dialog (if any) into `ctx`.
///
/// Returns the dialog result for the frame. The caller owns the `Dialog`
/// value and updates it based on the result.
pub fn show(ctx: &egui::Context, dlg: &mut Dialog) -> DialogResult {
    let (title, _body) = match dlg {
        Dialog::Confirm { title, body, .. } => (title.clone(), body.clone()),
        Dialog::Text { title, .. } => (title.clone(), String::new()),
        Dialog::Two { title, .. } => (title.clone(), String::new()),
    };

    let mut result = DialogResult::Open;
    let mut cancel = false;

    let window = egui::Window::new(title)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO);

    window.show(ctx, |ui| {
        match dlg {
            Dialog::Confirm { body, destructive, .. } => {
                ui.label(body.clone());
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let confirm_label = if *destructive { "Yes, delete" } else { "Confirm" };
                    let mut btn = egui::Button::new(confirm_label);
                    if *destructive {
                        btn = btn.fill(egui::Color32::from_rgb(120, 20, 20));
                    }
                    if ui.add(btn).clicked() {
                        result = DialogResult::Submit(DialogPayload::Confirm);
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            }
            Dialog::Text { placeholder, draft, .. } => {
                ui.add(
                    egui::TextEdit::singleline(draft)
                        .hint_text(placeholder.as_str())
                        .desired_width(240.0),
                );
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("OK").clicked() {
                        let value = draft.clone();
                        result = DialogResult::Submit(DialogPayload::Text(value));
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            }
            Dialog::Two {
                label_a,
                label_b,
                draft_a,
                draft_b,
                mask_b,
                ..
            } => {
                ui.horizontal(|ui| {
                    ui.label(label_a.clone());
                    ui.add(egui::TextEdit::singleline(draft_a).desired_width(200.0));
                });
                ui.horizontal(|ui| {
                    ui.label(label_b.clone());
                    let mut edit =
                        egui::TextEdit::singleline(draft_b).desired_width(220.0);
                    if *mask_b {
                        edit = edit.password(true);
                    }
                    ui.add(edit);
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("OK").clicked() {
                        let a = draft_a.clone();
                        let b = draft_b.clone();
                        result = DialogResult::Submit(DialogPayload::Two(a, b));
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            }
        }
    });

    if cancel {
        DialogResult::Cancel
    } else {
        result
    }
}

/// A convenience constructor for a confirm dialog.
pub fn confirm(title: impl Into<String>, body: impl Into<String>, destructive: bool) -> Dialog {
    Dialog::Confirm {
        title: title.into(),
        body: body.into(),
        destructive,
    }
}

/// A convenience constructor for a one-field text prompt.
pub fn prompt_text(title: impl Into<String>, placeholder: impl Into<String>) -> Dialog {
    Dialog::Text {
        title: title.into(),
        placeholder: placeholder.into(),
        draft: String::new(),
    }
}

/// A convenience constructor for a two-field prompt.
pub fn prompt_two(
    title: impl Into<String>,
    label_a: impl Into<String>,
    label_b: impl Into<String>,
    mask_b: bool,
) -> Dialog {
    Dialog::Two {
        title: title.into(),
        label_a: label_a.into(),
        label_b: label_b.into(),
        draft_a: String::new(),
        draft_b: String::new(),
        mask_b,
    }
}
