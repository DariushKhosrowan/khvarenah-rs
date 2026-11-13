//! Throwaway helper: render any supported share-link (vless/vmess/trojan/ss/
//! hysteria2/tuic) to an xray client config.
//! Usage: cargo run --example render_one -- '<share-link>'
use dastyab_core::tunnel_lifeline::render_any_xray_cfg;

fn main() {
    let url = std::env::args()
        .nth(1)
        .expect("usage: render_one <share-link>");
    match render_any_xray_cfg(&url, 10853) {
        Ok(cfg) => print!("{cfg}"),
        Err(e) => {
            eprintln!("render failed: {e}");
            std::process::exit(2);
        }
    }
}
