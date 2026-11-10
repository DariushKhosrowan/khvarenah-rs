//! Configs view — the **generated-configs manager**.
//!
//! Every config the console renders (vless:// share link, v2rayN / sing-box
//! / Clash, tunnel-client) is durably recorded in the per-profile
//! `generated_configs.json` ledger with its format, source, label, full
//! content, and a SHA-256 content hash. This view is the human interface to
//! that ledger: browse, search, filter by format, expand to inspect content,
//! copy any single config, or export the whole ledger to disk — so a lost
//! export can always be reconstructed or proven to have existed.
//!
//! The ledger is append-only and participates in the manifest / inventory /
//! backup / workspace-snapshot machinery, so these records survive the same
//! safety layer as history and token history.

use eframe::egui;

use crate::state::GeneratedConfigRow;
use crate::views::{section_card, stat_chips, tag, CARD, CARD_STROKE, GOLD, GOLD_DIM, TEXT};

/// How the configs ledger sorts its rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConfigsSort {
    /// Newest first (default).
    #[default]
    Newest,
    /// Oldest first.
    Oldest,
}

/// Actions the configs view can request of the app shell.
#[derive(Debug)]
pub enum ConfigsAction {
    /// Write every matching generated config to disk under the export folder.
    ExportAll,
}

pub fn show(ui: &mut egui::Ui, app: &mut crate::app::DastYabApp) -> Option<ConfigsAction> {
    let mut action = None;
    let rows = &app.state.generated_configs;

    ui.heading(egui::RichText::new("Generated Configs").color(GOLD));
    ui.label(
        egui::RichText::new(
            "Every config this console rendered — kept, hash-verified, and never lost.",
        )
        .color(GOLD_DIM),
    );
    ui.add_space(6.0);

    // Stats chips.
    {
        let share = rows.iter().filter(|r| r.fmt == "share-link").count();
        let v2 = rows.iter().filter(|r| r.fmt == "v2rayN").count();
        let sb = rows.iter().filter(|r| r.fmt == "sing-box").count();
        let clash = rows.iter().filter(|r| r.fmt == "Clash").count();
        stat_chips(
            ui,
            &[
                ("total", &rows.len().to_string()),
                ("share-link", &share.to_string()),
                ("v2rayN", &v2.to_string()),
                ("sing-box", &sb.to_string()),
                ("Clash", &clash.to_string()),
            ],
        );
    }
    ui.add_space(4.0);

    if rows.is_empty() {
        let empty_card = egui::Frame::new()
            .fill(CARD)
            .inner_margin(egui::Margin::symmetric(12, 14))
            .corner_radius(8.0)
            .stroke(egui::Stroke::new(1.0, CARD_STROKE));
        empty_card.show(ui, |ui| {
            ui.label(
                egui::RichText::new("No generated configs recorded yet.")
                    .color(TEXT)
                    .strong(),
            );
            ui.label(
                egui::RichText::new(
                    "Deploy a worker or run autopilot — every config it renders (share link, \
                     v2rayN, sing-box, Clash, tunnel client) will be recorded here with its \
                     content hash.",
                )
                .color(GOLD_DIM),
            );
        });
        ui.add_space(8.0);
        return None;
    }

    // Filter + sort toolbar.
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Search:").color(GOLD_DIM));
        ui.add(
            egui::TextEdit::singleline(&mut app.configs_search)
                .hint_text("filter by label or content…")
                .desired_width(200.0),
        );
        egui::ComboBox::from_id_salt("cfgfmt_filter")
            .selected_text(if app.configs_fmt_filter.is_empty() {
                "format: all".to_string()
            } else {
                format!("format: {}", app.configs_fmt_filter)
            })
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut app.configs_fmt_filter, String::new(), "all");
                for f in ["share-link", "v2rayN", "sing-box", "Clash"] {
                    ui.selectable_value(
                        &mut app.configs_fmt_filter,
                        f.to_string(),
                        f,
                    );
                }
            });
        egui::ComboBox::from_id_salt("cfgsort")
            .selected_text(match app.configs_sort {
                ConfigsSort::Newest => "newest first",
                ConfigsSort::Oldest => "oldest first",
            })
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut app.configs_sort, ConfigsSort::Newest, "newest first");
                ui.selectable_value(&mut app.configs_sort, ConfigsSort::Oldest, "oldest first");
            });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .button("💾 Export all")
                .on_hover_text("Write every generated config to disk under ~/.dastyab/exported_configs/<profile>/")
                .clicked()
            {
                action = Some(ConfigsAction::ExportAll);
            }
        });
    });
    ui.add_space(4.0);

    let q = app.configs_search.trim().to_lowercase();
    let ff = app.configs_fmt_filter.trim().to_lowercase();

    // Filter + sort into a display vector.
    let mut shown: Vec<&GeneratedConfigRow> = rows
        .iter()
        .filter(|r| {
            (ff.is_empty() || r.fmt.to_lowercase() == ff)
                && (q.is_empty()
                    || r.label.to_lowercase().contains(&q)
                    || r.fmt.to_lowercase().contains(&q)
                    || r.source.to_lowercase().contains(&q)
                    || r.content.to_lowercase().contains(&q))
        })
        .collect();
    match app.configs_sort {
        ConfigsSort::Newest => shown.sort_unstable_by_key(|r| std::cmp::Reverse(r.id)),
        ConfigsSort::Oldest => shown.sort_unstable_by_key(|r| r.id),
    }

    if shown.is_empty() {
        ui.label(egui::RichText::new("No configs match that search.").color(GOLD_DIM));
        return action;
    }

    ui.label(
        egui::RichText::new(format!("{} config(s)", shown.len()))
            .color(GOLD_DIM)
            .small(),
    );
    ui.add_space(4.0);

    section_card(ui, "Ledger", |ui| {
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .max_height(560.0)
            .show(ui, |ui| {
                for row in shown {
                    let fmt_color = match row.fmt.as_str() {
                        "share-link" => egui::Color32::from_rgb(120, 200, 255),
                        "v2rayN" => egui::Color32::from_rgb(200, 160, 255),
                        "sing-box" => egui::Color32::from_rgb(90, 210, 120),
                        _ => egui::Color32::from_rgb(255, 185, 90),
                    };
                    let frame = egui::Frame::new()
                        .fill(CARD)
                        .inner_margin(egui::Margin::symmetric(10, 7))
                        .corner_radius(6.0)
                        .stroke(egui::Stroke::new(1.0, CARD_STROKE));
                    frame.show(ui, |ui| {
                        ui.horizontal(|ui| {
                            tag(ui, &row.fmt, fmt_color);
                            ui.add_space(4.0);
                            ui.label(egui::RichText::new(&row.label).color(TEXT));
                            ui.label(
                                egui::RichText::new(format!("· {}", row.source))
                                    .color(GOLD_DIM)
                                    .small(),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    ui.label(
                                        egui::RichText::new(format!(
                                            "{} · {}",
                                            crate::state::relative_ts(row.created_unix as i64),
                                            crate::state::format_ts(row.created_unix as i64)
                                        ))
                                        .color(GOLD_DIM)
                                        .small(),
                                    );
                                    if ui
                                        .button("📋")
                                        .on_hover_text("Copy this config to clipboard")
                                        .clicked()
                                    {
                                        ui.ctx().copy_text(row.content.clone());
                                        app.note = format!(
                                            "Copied {} config (#{}) to clipboard.",
                                            row.fmt, row.id
                                        );
                                    }
                                },
                            );
                        });
                        ui.add_space(2.0);
                        ui.label(
                            egui::RichText::new(format!("sha256 {}", hex(&row.content_sha256)))
                                .color(GOLD_DIM)
                                .small()
                                .monospace(),
                        );
                        ui.add_space(2.0);
                        egui::CollapsingHeader::new("show content")
                            .default_open(false)
                            .show(ui, |ui| {
                                let mut content = row.content.clone();
                                ui.add(
                                    egui::TextEdit::multiline(&mut content)
                                        .desired_rows(6)
                                        .desired_width(ui.available_width() - 8.0)
                                        .font(egui::TextStyle::Monospace)
                                        .interactive(false),
                                );
                            });
                    });
                    ui.add_space(4.0);
                }
            });
    });

    action
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Run a configs action (surfaces a note on the app).
pub fn run_action(app: &mut crate::app::DastYabApp, act: ConfigsAction) {
    match act {
        ConfigsAction::ExportAll => {
            let pid = app.state.active_profile_id.clone();
            match export_all(&pid, &app.state.generated_configs) {
                Ok(path) => {
                    app.note = format!(
                        "Exported {} config(s) → {}",
                        app.state.generated_configs.len(),
                        path.display()
                    );
                }
                Err(e) => {
                    app.note = format!("Export failed: {e}");
                }
            }
        }
    }
}

/// Write every generated config in the ledger to disk under
/// `~/.dastyab/exported_configs/<profile>/`.
fn export_all(profile: &str, rows: &[GeneratedConfigRow]) -> Result<std::path::PathBuf, String> {
    let base = dastyab_core::store::mem_dir()
        .join("exported_configs")
        .join(profile);
    std::fs::create_dir_all(&base).map_err(|e| e.to_string())?;
    let now = crate::state::format_ts(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
    )
    .replace([' ', ':'], "-");
    for row in rows {
        let fname = format!("{now}_{}_{}.conf", row.fmt, row.id);
        let path = base.join(fname);
        std::fs::write(&path, &row.content).map_err(|e| e.to_string())?;
    }
    Ok(base)
}
