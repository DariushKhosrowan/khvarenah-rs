//! dnstt-server — authoritative DNS tunnel server for DastYab.
//!
//! This is the server half of the DastYab DNS tunnel. It is CLI-compatible
//! with the historical `dnstt-server` binary the deploy flow installs, but it
//! speaks the **native DastYab protocol** (the `dnstunnel::TunnelFrame`
//! base32-label framing implemented by the client), so a blackout-ladder
//! client can actually talk to it.
//!
//! Usage:
//! ```text
//! dnstt-server -gen-key                        # print a fresh session token
//! dnstt-server -d <base_domain> -k <keyfile> -u <port> [-b <bootstrap>]
//! ```
//!
//! - `-gen-key` prints a random session token to stdout. Write it into the
//!   file given by `-k` to authorize exactly that session (one token per line).
//! - `-d` is the base domain the tunnel queries appear under (the client's
//!   `base_domain`). The server answers only frames ending in this domain.
//! - `-u` binds UDP on this port (default 53; requires root or CAP_NET_BIND_SERVICE).
//! - `-b` optionally points to a file whose raw bytes are served as the
//!   bootstrap blob for a flags=3 "give me the next tier endpoint" request.
//!
//! Anonymous mode: if `-k` is omitted (or the key file does not exist), the
//! server accepts any session (useful for first boot / open rescue nets).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use dastyab_core::dnstt_server::{
    handle_datagram, BootstrapInfo, DnsTunnelServer, TunnelHandler,
};

const DEFAULT_PORT: u16 = 53;
const MAX_DATAGRAM: usize = 512;

struct Args {
    gen_key: bool,
    domain: Option<String>,
    key_file: Option<PathBuf>,
    port: u16,
    bootstrap: Option<PathBuf>,
}

fn print_usage() -> ! {
    eprintln!(
        "usage: dnstt-server -gen-key | -d <base_domain> -k <keyfile> [-u <port>] [-b <bootstrap>]"
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut args = std::env::args().skip(1);
    let mut gen_key = false;
    let mut domain: Option<String> = None;
    let mut key_file: Option<PathBuf> = None;
    let mut port: u16 = DEFAULT_PORT;
    let mut bootstrap: Option<PathBuf> = None;

    while let Some(a) = args.next() {
        match a.as_str() {
            "-gen-key" => gen_key = true,
            "-d" => {
                domain = Some(match args.next() {
                    Some(v) if !v.is_empty() => v,
                    _ => print_usage(),
                })
            }
            "-k" => {
                key_file = Some(PathBuf::from(match args.next() {
                    Some(v) if !v.is_empty() => v,
                    _ => print_usage(),
                }))
            }
            "-u" => {
                port = match args.next().and_then(|v| v.parse().ok()) {
                    Some(p) => p,
                    None => print_usage(),
                }
            }
            "-b" => {
                bootstrap = Some(PathBuf::from(match args.next() {
                    Some(v) if !v.is_empty() => v,
                    _ => print_usage(),
                }))
            }
            _ => print_usage(),
        }
    }

    Args {
        gen_key,
        domain,
        key_file,
        port,
        bootstrap,
    }
}

fn random_session() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let n: u64 = rng.gen();
    format!("{n:x}")
}

/// Load authorized sessions from the key file (one token per line).
fn load_sessions(key_file: &Path) -> Option<HashSet<String>> {
    let Ok(content) = std::fs::read_to_string(key_file) else {
        // Key file absent => anonymous mode.
        return None;
    };
    let set: HashSet<String> = content
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if set.is_empty() {
        None
    } else {
        Some(set)
    }
}

fn load_bootstrap(path: &Path) -> Option<BootstrapInfo> {
    std::fs::read(path).ok().map(|blob| BootstrapInfo { blob })
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = parse_args();

    // -gen-key: print a session token and exit.
    if args.gen_key {
        println!("{}", random_session());
        return ExitCode::SUCCESS;
    }

    let domain = match args.domain {
        Some(d) => d,
        None => print_usage(),
    };

    let allowed_sessions = args.key_file.as_deref().and_then(load_sessions);
    let bootstrap = args.bootstrap.as_deref().and_then(load_bootstrap);

    let handler = TunnelHandler::new(allowed_sessions, bootstrap);
    let server = Arc::new(DnsTunnelServer::new(domain, handler));

    let bind = format!("0.0.0.0:{}", args.port);
    let socket = match tokio::net::UdpSocket::bind(&bind).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "dnstt-server: failed to bind UDP {bind}: {e} (port 53 needs root or CAP_NET_BIND_SERVICE)"
            );
            return ExitCode::FAILURE;
        }
    };
    eprintln!("dnstt-server: authoritative DNS tunnel listening on udp {bind}");

    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, src)) => {
                let pkt = &buf[..n];
                if let Some(resp) = handle_datagram(pkt, &server) {
                    let _ = socket.send_to(&resp, src).await;
                }
                buf = vec![0u8; MAX_DATAGRAM];
            }
            Err(e) => {
                eprintln!("dnstt-server: recv error: {e}");
            }
        }
    }
}
