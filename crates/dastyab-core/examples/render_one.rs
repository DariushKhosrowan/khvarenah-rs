//! Throwaway helper: render a single vless share-link to an xray client config.
//! Usage: cargo run --example render_one -- '<vless://...>'
use dastyab_core::tunnel_lifeline::render_node_config;

fn main() {
    let url = std::env::args()
        .nth(1)
        .expect("usage: render_one <vless-url>");
    match render_node_config(&url) {
        Ok(cfg) => print!("{cfg}"),
        Err(e) => {
            eprintln!("render failed: {e}");
            std::process::exit(2);
        }
    }
}
