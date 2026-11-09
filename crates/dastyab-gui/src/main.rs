//! DastYab desktop GUI (eframe/egui).
//!
//! Full GUI with a royal-gold-on-black theme. This is a substantial app; it
//! is built in a separate module so the file stays navigable.

mod app;
pub mod bridge;
mod dialogs;
mod state;
mod views;

fn main() -> eframe::Result {
    // Install the process-level rustls provider before any network/TLS work.
    dastyab_core::tls::install_tls_provider();

    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "DastYab",
        native_options,
        Box::new(|cc| Ok(Box::new(app::DastYabApp::new(cc)))),
    )
}
