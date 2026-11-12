//! Multi-Layer Tunnel view.
//!
//! One panel that ties the whole rescue chain together for a normal user:
//!   1. Paste your **final server** (your own VPN / VLESS link).
//!   2. Choose HOW the tunnel is applied — whole device, DastYab's
//!      dedicated Chrome (AI Studio), or a local SOCKS5 proxy for any app.
//!   3. Test access to AI Studio + Gemini (and even call Gemini) through the
//!      chain.
//!
//! The final-server config is persisted per profile; the Gemini API key is
//! stored in the profile dir (out of git). All network work runs on the
//! async bridge so the UI never blocks.

use eframe::egui;

use crate::app::DastYabApp;
use crate::views::{section_card, stat_chips, tag, CARD, GOLD, GOLD_DIM, SUCCESS, TEXT};

/// Actions the view asks the app to run.
#[derive(Debug)]
pub enum MultilayerAction {
    /// Save the final-server config (from the current input fields).
    Save,
    /// Edit the final-server config.
    Clear,
    /// Store the Gemini API key.
    SaveGeminiKey,
    /// Spawn a probe of AI Studio + Gemini through the chain.
    ProbeAi,
    /// Spawn a real Gemini generateContent call through the chain.
    Gemini,
    /// Start the tunnel in the selected mode.
    Start,
}

pub fn show(ui: &mut egui::Ui, app: &mut DastYabApp) -> Option<MultilayerAction> {
    let mut action = None;

    ui.heading(egui::RichText::new("Multi-Layer Tunnel").color(GOLD));
    ui.label(
        egui::RichText::new(
            "Your rescue chain ends at your own server. Paste a vless:// link, \
             choose how to apply the tunnel, and test AI Studio / Gemini access.",
        )
        .color(GOLD_DIM),
    );
    ui.add_space(6.0);

    // --- Step 1: final server ---------------------------------------------
    section_card(ui, "1 · Final server (your VPN / VLESS egress)", |ui| {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Label").color(GOLD_DIM));
            ui.add(
                egui::TextEdit::singleline(&mut app.ml_name)
                    .hint_text("e.g. my-vps")
                    .desired_width(140.0),
            );
            ui.label(egui::RichText::new("Country hint").color(GOLD_DIM));
            ui.add(
                egui::TextEdit::singleline(&mut app.ml_country)
                    .hint_text("e.g. DE")
                    .desired_width(60.0),
            );
        });
        ui.add_space(4.0);
        ui.label(egui::RichText::new("vless:// link").color(GOLD_DIM));
        ui.add(
            egui::TextEdit::singleline(&mut app.ml_link)
                .hint_text("vless://uuid@host:443?security=tls&type=ws&path=%2F#name")
                .desired_width(ui.available_width()),
        );
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui.button("💾 Save server").clicked() {
                action = Some(MultilayerAction::Save);
            }
            if ui.button("🗑 Clear").clicked() {
                action = Some(MultilayerAction::Clear);
            }
            let has = dastyab_core::multilayer::load_final_server(&app.state.active_profile_id)
                .is_some();
            if has {
                tag(ui, "configured", SUCCESS);
            } else {
                tag(ui, "not set", GOLD_DIM);
            }
        });
    });

    // --- Step 2: tunnel mode ----------------------------------------------
    section_card(ui, "2 · How to apply the tunnel", |ui| {
        ui.label(egui::RichText::new("Where should the tunnel route traffic?").color(GOLD_DIM));
        ui.add_space(4.0);
        egui::Grid::new("ml-mode-grid").num_columns(3).spacing([12.0, 4.0]).show(ui, |ui| {
            let modes = [
                ("chrome", "Chrome (AI Studio)", "Use the tunnel only for DastYab's dedicated Chrome. Your login session is persisted between runs."),
                ("proxy", "Local proxy", "Expose a SOCKS5 proxy on 127.0.0.1 — any app can point at it."),
                ("device", "Whole device", "Route the whole device via the environment proxy (best-effort system-wide)."),
            ];
            for (id, label, desc) in modes {
                let selected = app.ml_mode == id;
                if ui.selectable_label(selected, label.to_string()).clicked() {
                    app.ml_mode = id.to_string();
                }
                ui.add_space(4.0);
                ui.label(egui::RichText::new(desc).small().color(GOLD_DIM));
                ui.end_row();
            }
        });
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Proxy port").color(GOLD_DIM));
            ui.add(egui::DragValue::new(&mut app.ml_proxy_port).range(1024..=65535));
            ui.checkbox(
                &mut app.ml_chrome_persist,
                "Keep Chrome session (login persists)",
            );
        });
        ui.add_space(6.0);
        if ui.button("▶ Start tunnel").clicked() {
            action = Some(MultilayerAction::Start);
        }
    });

    // --- Step 3: access testing -------------------------------------------
    section_card(ui, "3 · Test access (AI Studio / Gemini)", |ui| {
        ui.label(
            egui::RichText::new(
                "Probe whether AI Studio and Gemini are reachable through the chain — \
                 then optionally make a real Gemini call.",
            )
            .color(GOLD_DIM),
        );
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Gemini API key").color(GOLD_DIM));
            ui.add(
                egui::TextEdit::singleline(&mut app.ml_gemini_key)
                    .password(true)
                    .hint_text("AIza…")
                    .desired_width(220.0),
            );
            ui.button("💾 Save key").clicked().then(|| {
                action = Some(MultilayerAction::SaveGeminiKey);
            });
        });
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui.button("🛰 Probe AI Studio + Gemini").clicked() {
                action = Some(MultilayerAction::ProbeAi);
            }
            ui.label(egui::RichText::new("Prompt").color(GOLD_DIM));
            ui.add(
                egui::TextEdit::singleline(&mut app.ml_prompt)
                    .desired_width(280.0)
                    .hint_text("Ask Gemini through the tunnel…"),
            );
            if ui.button("🪐 Call Gemini").clicked() {
                action = Some(MultilayerAction::Gemini);
            }
        });
    });

    // --- Status / output ----------------------------------------------------
    if !app.ml_note.is_empty() {
        ui.add_space(6.0);
        ui.label(egui::RichText::new(&app.ml_note).color(GOLD));
    }
    if !app.ml_output.is_empty() {
        ui.add_space(6.0);
        ui.label(egui::RichText::new(&app.ml_output).color(TEXT));
    }

    // Status chips.
    ui.add_space(8.0);
    let configured =
        dastyab_core::multilayer::load_final_server(&app.state.active_profile_id).is_some();
    let has_key =
        dastyab_core::multilayer::load_gemini_key(&app.state.active_profile_id).is_some();
    stat_chips(
        ui,
        &[
            ("final server", if configured { "✓" } else { "—" }),
            ("gemini key", if has_key { "✓" } else { "—" }),
            ("mode", &app.ml_mode),
            ("port", &app.ml_proxy_port.to_string()),
        ],
    );

    ui.add_space(4.0);
    let _ = CARD;
    action
}
