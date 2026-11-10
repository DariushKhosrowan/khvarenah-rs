//! View implementations for the DastYab GUI.
//!
//! Each view is a panel rendered by the app shell. They read from the app's
//! [`GuiState`] cache and drive store mutations through the async bridge,
//! reusing the dialog helpers.
//!
//! This module also hosts the shared palette constants and the small,
//! reusable "design system" helpers (`section_card`, `stat_chip`,
//! `mono_row`, …) so every view reads from one place and looks consistent.

use eframe::egui;

pub mod cleanip;
pub mod history;
pub mod profiles;
pub mod tokens;

pub use crate::app::{CARD, CARD_STROKE, GOLD, GOLD_DIM, TEXT};

// Extended palette (used across all views).
pub const SUCCESS: egui::Color32 = egui::Color32::from_rgb(90, 200, 120);

/// Render a titled card: a rounded frame with a gold accent rule, a header,
/// a separator, then the content closure.
pub fn section_card(ui: &mut egui::Ui, title: &str, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(CARD)
        .inner_margin(egui::Margin::symmetric(12, 10))
        .stroke(egui::Stroke::new(1.0, CARD_STROKE))
        .corner_radius(8.0)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("▎").color(GOLD).size(18.0));
                ui.label(egui::RichText::new(title).color(GOLD).strong().size(15.0));
            });
            ui.add_space(4.0);
            ui.separator();
            ui.add_space(4.0);
            add(ui);
        });
    ui.add_space(8.0);
}

/// A row of several stat chips, wrapped.
pub fn stat_chips(ui: &mut egui::Ui, chips: &[(&str, &str)]) {
    ui.horizontal_wrapped(|ui| {
        for (label, value) in chips {
            egui::Frame::new()
                .fill(egui::Color32::from_rgb(20, 17, 12))
                .inner_margin(egui::Margin::symmetric(8, 4))
                .corner_radius(6.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(*label).color(GOLD_DIM).small());
                        ui.label(egui::RichText::new(*value).color(TEXT).small().strong());
                    });
                });
            ui.add_space(6.0);
        }
    });
    ui.add_space(4.0);
}

/// Render a value in monospace with a one-click copy button.
pub fn mono_copy_row(ui: &mut egui::Ui, value: &str) {
    ui.horizontal(|ui| {
        ui.add(
            egui::TextEdit::singleline(&mut value.to_owned())
                .font(egui::TextStyle::Monospace)
                .desired_width(ui.available_width() - 40.0)
                .interactive(false),
        );
        if ui.button("📋").on_hover_text("Copy").clicked() {
            ui.ctx().copy_text(value.to_string());
        }
    });
}

/// A small inline tag (e.g. a type or status badge) with a background fill.
pub fn tag(ui: &mut egui::Ui, text: &str, color: egui::Color32) {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.16))
        .inner_margin(egui::Margin::symmetric(6, 2))
        .corner_radius(4.0)
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text).color(color).small().strong());
        });
}
