//! Throwaway helper: deep-verify one config (any scheme) by spawning xray and
//! checking the local SOCKS5 port opens. Usage:
//!   cargo run --example verify_live -- '<share-link>'
use dastyab_core::tunnel_lifeline::render_any_xray_cfg;
use std::time::{Duration, Instant};

fn main() {
    let url = std::env::args()
        .nth(1)
        .expect("usage: verify_live <share-link>");
    let port: u16 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(12099);

    let cfg = match render_any_xray_cfg(&url, port) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("render failed: {e}");
            std::process::exit(2);
        }
    };
    eprintln!("[render] ok, cfg {} bytes", cfg.len());

    let xray = match dastyab_core::tunnel_lifeline::find_xray_binary() {
        Some(x) => x,
        None => {
            eprintln!("no xray binary found");
            std::process::exit(3);
        }
    };

    let cfg_path =
        std::env::temp_dir().join(format!("dyb-verify-live-{}.json", std::process::id()));
    std::fs::write(&cfg_path, &cfg).expect("write cfg");

    let mut child = match std::process::Command::new(&xray)
        .arg("run")
        .arg("-c")
        .arg(&cfg_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(ch) => ch,
        Err(e) => {
            let _ = std::fs::remove_file(&cfg_path);
            eprintln!("spawn failed: {e}");
            std::process::exit(4);
        }
    };

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut ready = false;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let mut stderr = String::new();
    let _ = child.kill();
    let _ = child.wait();
    if let Some(mut e) = child.stderr.take() {
        let _ = std::io::Read::read_to_string(&mut e, &mut stderr);
    }
    let _ = std::fs::remove_file(&cfg_path);

    if ready {
        println!("READY port={port}");
    } else {
        eprintln!("port never opened. stderr dump:\n{stderr}");
        std::process::exit(5);
    }
}
