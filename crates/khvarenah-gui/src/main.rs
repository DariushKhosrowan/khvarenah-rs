//! Khvarenah desktop GUI (eframe/egui).
//!
//! Full GUI with a royal-gold-on-black theme. This is a substantial app; it
//! is built in a separate module so the file stays navigable.

mod app;

fn main() -> eframe::Result {
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "Khvarenah",
        native_options,
        Box::new(|cc| Ok(Box::new(app::KhvarenahApp::new(cc)))),
    )
}
