//! Cloudflare-Worker-hosted DNS tunnel (no VPS) — control plane.
//!
//! This module ships the zero-credential DNS tunnel: a Cloudflare Worker is
//! the tunnel *server*, deployed via the already-present CF token, so no VPS
//! or SSH credentials are needed. The client talks to it over HTTPS (the same
//! path the app already uses for Cloudflare), which makes it reachable even
//! under censorship — and it is fully automatic after the single base token.
//!
//! # Protocol
//!
//! The wire format reuses `crate::dnstunnel::TunnelFrame` and its base32
//! label codec. The client encodes a frame as a qname string and sends it as
//! an HTTPS GET to the deployed worker:
//!
//! ```text
//! GET /?q=<encoded-qname>        header: X-DastYab-Session: <secret>
//! ```
//!
//! The worker authenticates via the secret (stored as the `DYB_SESSION_SECRET`
//! worker var at deploy time), decodes the frame, answers according to its
//! `flags` (1=ping, 2=status, 3=bootstrap, 0=data-plane—not yet), and returns
//! the *encoded reply qname* as a `text/plain` body. The client-side
//! `WorkerTunnelResolver` returns that string verbatim, so the existing
//! `dnstunnel::send_receive` decode path round-trips unchanged.
//!
//! # Scope
//!
//! Control plane only: flags 1/2/3. Data-plane (flags=0, actual VLESS relay)
//! is a later step.
//!
//! Files:
//! - `bundle.rs` — the embedded worker JS (`WORKER_TUNNEL_JS`).
//! - `deploy.rs` — `deploy_worker_tunnel`: mints/names the worker, deploys it,
//!   sets its secret var, and persists the `TunnelClientConfig` (mode=Worker).
//! - `resolver.rs` — `WorkerTunnelResolver`, a `dnstunnel::Resolver` that does
//!   the HTTPS call.

pub mod bundle;
pub mod deploy;
pub mod resolver;
pub mod secret;

pub use bundle::{WORKER_CRON_SCHEDULE, WORKER_TUNNEL_JS};
pub use deploy::{deploy_worker_tunnel, WorkerTunnelDeploy, WorkerTunnelDeployOpts};
pub use resolver::WorkerTunnelResolver;

/// Logical DNS base domain shared by the worker and its client. Both encode
/// frames under this suffix; it does not need to resolve — it is only a
/// framing namespace so `TunnelFrame::decode_name` round-trips.
pub const DYB_TUNNEL_BASE: &str = "tun.dastyab.dev";

/// Build the canonical `vless://` share link for a deployed worker's HTTP(S)
/// endpoint. The uuid is derived deterministically from the profile + host so
/// redeploys of the same worker keep a stable client identity, and so config
/// generated from a clean IP can always reproduce the same worker path/uuid
/// without a redeploy.
pub fn vless_link_for_worker(profile_id: &str, worker_url: &str) -> Option<String> {
    let host = worker_url
        .strip_prefix("https://")
        .unwrap_or(worker_url)
        .split('/')
        .next()?
        .trim()
        .to_string();
    if host.is_empty() {
        return None;
    }
    let uuid = derive_vless_uuid(&format!("{profile_id}|{host}"));
    let prof = crate::vless::VlessProfile {
        uuid: uuid.clone(),
        address: host.clone(),
        port: 443,
        security: "tls".into(),
        path: "/".into(),
        transport: "ws".into(),
        sni: Some(host.clone()),
        header_host: Some(host),
        name: format!("worker-{}", &uuid[..8]),
    };
    Some(prof.share_link())
}

/// Resolve the profile's deployed worker base link — the `vless://` skeleton
/// (worker uuid/path/transport) that config-from-IP and scanning reuse, with
/// the address swapped for a clean IP.
///
/// Preference:
/// 1. The durable persisted base link (`last_deployed_base_link`), written at
///    deploy time — survives history clears/trims and always carries the
///    actually-deployed identity (including a random-UUID edgetunnel deploy).
/// 2. The most recent non-clean deploy record in profile history (a full base
///    link recorded at deploy time).
/// 3. Fallback from the persisted worker-tunnel client config: if a worker has
///    been deployed at any point, synthesize a canonical base link from its
///    workers.dev URL. This makes the Configs tab work right after a single
///    deploy even before a scan has written history.
pub fn resolve_deployed_base_link(profile_id: &str) -> Option<String> {
    let p = crate::store::profiles::load_profile(profile_id);
    // A base link is only usable if it parses to a worker with a non-empty,
    // well-formed host. A malformed legacy record (empty host, e.g.
    // "vless://uuid@:443?" — seen in the wild from a pre-Rust deploy) must
    // never be returned, otherwise every later config-from-IP renders against
    // an empty server and silently produces broken configs.
    let usable = |link: &str| -> bool {
        if !link.starts_with("vless://") {
            return false;
        }
        match crate::vless::VlessProfile::parse(link) {
            Ok(prof) => {
                let h = prof.address.trim();
                !h.is_empty() && !h.contains("..") && !h.starts_with('.')
            }
            Err(_) => false,
        }
    };
    if let Some(link) = &p.config.last_deployed_base_link {
        if usable(link) {
            return Some(link.clone());
        }
    }
    if let Some(r) = p.history.iter().find(|r| !r.clean_ip && usable(&r.link)) {
        return Some(r.link.clone());
    }
    let cfg = crate::vps_deploy::load_tunnel_client_config(profile_id)?;
    let url = match cfg.mode {
        crate::vps_deploy::TunnelMode::Worker => cfg.worker_url.as_deref()?,
        _ => return None,
    };
    vless_link_for_worker(profile_id, url)
}

/// Derive a stable UUID (v4-shaped string) from a seed.
fn derive_vless_uuid(seed: &str) -> String {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(seed.as_bytes());
    let b = &h[..16];
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12],
        b[13], b[14], b[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn isolated_home() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(d.path().to_path_buf());
        d
    }

    #[test]
    fn vless_link_for_worker_builds_parseable_vless() {
        let link = vless_link_for_worker("p1", "https://dyb-tun-1234.sub.workers.dev").unwrap();
        assert!(link.starts_with("vless://"), "link: {link}");
        let p = crate::vless::VlessProfile::parse(&link).unwrap();
        assert_eq!(p.address, "dyb-tun-1234.sub.workers.dev");
        assert_eq!(p.port, 443);
        assert_eq!(p.transport, "ws");
        // stable per (profile, host)
        let link2 = vless_link_for_worker("p1", "https://dyb-tun-1234.sub.workers.dev").unwrap();
        assert_eq!(link, link2);
        // different profile → different uuid
        let link3 = vless_link_for_worker("p2", "https://dyb-tun-1234.sub.workers.dev").unwrap();
        assert_ne!(link, link3);
    }

    #[test]
    fn resolve_deployed_base_link_falls_back_to_tunnel_config() {
        let _home = isolated_home();
        let pid = crate::store::profiles::create_profile("resolve-test", "test").unwrap();
        // No history, but a worker tunnel config exists → base link synthesized.
        let cfg = crate::vps_deploy::TunnelClientConfig {
            host: "https://dyb-tun-aaaa.sub.workers.dev".into(),
            base_domain: DYB_TUNNEL_BASE.into(),
            session: "s".into(),
            resolver: "https".into(),
            mode: crate::vps_deploy::TunnelMode::Worker,
            worker_url: Some("https://dyb-tun-aaaa.sub.workers.dev".into()),
            worker_name: Some("dyb-tun-aaaa".into()),
            shared_secret: Some("x".into()),
            worker_vless_upstream: None,
            resolver_pool: None,
        };
        crate::vps_deploy::write_tunnel_client_config(&pid, &cfg).unwrap();
        let link = resolve_deployed_base_link(&pid).expect("resolved from tunnel config");
        assert!(link.starts_with("vless://"));
        assert!(link.contains("dyb-tun-aaaa.sub.workers.dev"));
    }

    #[test]
    fn resolve_deployed_base_link_prefers_non_clean_history() {
        let _home = isolated_home();
        let pid = crate::store::profiles::create_profile("resolve-test2", "test").unwrap();
        let rec = crate::store::profiles::VlessRecord {
            id: crate::store::new_id(),
            ts: crate::store::profiles::now_iso(),
            epoch: crate::store::now_ts(),
            uuid: String::new(),
            address: "104.16.9.9".into(),
            port: 443,
            name: "worker-x".into(),
            clean_ip: false,
            link: "vless://abc123@104.16.9.9:443?security=tls&type=ws#worker-x".into(),
            note: "deployed".into(),
        };
        crate::store::profiles::remember_vless(&pid, rec).unwrap();
        let link = resolve_deployed_base_link(&pid).unwrap();
        assert!(link.contains("104.16.9.9"));
        assert!(link.contains("abc123"));
    }

    #[test]
    fn deploy_once_then_config_from_clean_ip_repeatedly() {
        let _home = isolated_home();
        let pid = crate::store::profiles::create_profile("cfg-flow", "test").unwrap();
        // 1) "deploy once": write a worker tunnel config (simulates a deploy).
        let worker_url = "https://dyb-tun-cccc.sub.workers.dev".to_string();
        let cfg = crate::vps_deploy::TunnelClientConfig {
            host: worker_url.clone(),
            base_domain: DYB_TUNNEL_BASE.into(),
            session: "s".into(),
            resolver: "https".into(),
            mode: crate::vps_deploy::TunnelMode::Worker,
            worker_url: Some(worker_url.clone()),
            worker_name: Some("dyb-tun-cccc".into()),
            shared_secret: Some("x".into()),
            worker_vless_upstream: None,
            resolver_pool: None,
        };
        crate::vps_deploy::write_tunnel_client_config(&pid, &cfg).unwrap();

        // 2) The Configs tab can build a base link WITHOUT redeploying.
        let base = resolve_deployed_base_link(&pid).expect("base link after deploy");
        let prof = crate::vless::VlessProfile::parse(&base).unwrap();
        // The worker's uuid/path/transport are preserved across configs.
        let worker_uuid = prof.uuid.clone();
        let worker_path = prof.path.clone();

        // 3) Create configs from several clean IPs — repeated, no redeploy.
        for clean_ip in ["104.16.1.1", "104.16.2.2:2053", "104.17.3.3"] {
            let (ip, port) = match clean_ip.rsplit_once(':') {
                Some((ip, p)) if p.chars().all(|c| c.is_ascii_digit()) => {
                    (ip.to_string(), p.parse::<u16>().unwrap())
                }
                _ => (clean_ip.to_string(), 443),
            };
            let mut p = prof.clone();
            p.address = ip.clone();
            p.port = port;
            let all = crate::export::render_all(&p);
            assert!(!all.is_empty(), "no formats rendered for {clean_ip}");
            // Every format still targets the deployed worker uuid/path.
            for (_fmt, content) in &all {
                assert!(
                    content.contains(worker_uuid.as_str()),
                    "content missing uuid: {content}"
                );
                assert!(
                    content.contains(worker_path.as_str()),
                    "content missing path: {content}"
                );
            }
            // Remember + learn the clean IP as a seed.
            crate::store::profiles::remember_clean_ip(&pid, clean_ip).unwrap();
            crate::cf::ips::learn_clean_ip(&pid, &ip).unwrap();
        }

        // 4) Learned clean IPs feed future scans as seeds.
        let seeds = crate::cf::ips::load_manual_seeds(&pid);
        assert!(seeds.iter().any(|s| s.contains("104.16.1.1")));
        assert!(seeds.iter().any(|s| s.contains("104.17.3.3")));
    }

    #[test]
    fn durable_base_link_survives_history_clear() {
        let _home = isolated_home();
        let pid = crate::store::profiles::create_profile("durable", "test").unwrap();

        // Simulate a deploy that persisted a *specific* base link (a random
        // UUID edgetunnel deploy, say). This is what `deploy_worker` writes.
        let deployed_link = "vless://11111111-2222-3333-4444-555555555555@host1.sub.workers.dev:443?security=tls&type=ws&path=%2F#worker-11111111";
        crate::store::profiles::set_last_deployed_base_link(&pid, deployed_link).unwrap();

        // Resolve before any history exists → the durable link wins.
        let resolved = resolve_deployed_base_link(&pid).unwrap();
        assert!(
            resolved.contains("11111111-2222-3333-4444-555555555555"),
            "resolved: {resolved}"
        );

        // Add some unrelated (clean) history then clear it — the durable link
        // must still resolve. This is the core regression: previously, once
        // history was cleared, resolution fell back to a *synthesized* UUID
        // that never matched the actually-deployed (random) one, silently
        // generating broken configs.
        crate::store::profiles::remember_clean_ip(&pid, "104.16.1.1").unwrap();
        crate::store::profiles::clear_history(&pid).unwrap();
        assert!(crate::store::profiles::load_profile(&pid)
            .history
            .is_empty());

        let after = resolve_deployed_base_link(&pid).expect("base link after history clear");
        assert_eq!(
            after, deployed_link,
            "durable base link must be unchanged by history clear"
        );
    }
    #[test]
    fn resolve_deployed_base_link_skips_empty_host_records() {
        // A legacy malformed record (empty host, e.g. the one observed in the
        // wild: "vless://uuid@:443?…") must NEVER be returned as the base link.
        // If it were, config-from-IP would render broken configs against an
        // empty server and the Configs tab would falsely report "deployed".
        let _home = isolated_home();
        let pid = crate::store::profiles::create_profile("resolve-emptyhost", "test").unwrap();

        // Valid deploy first (should be preferred if it comes first).
        let good = crate::store::profiles::VlessRecord {
            id: crate::store::new_id(),
            ts: crate::store::profiles::now_iso(),
            epoch: crate::store::now_ts(),
            uuid: String::new(),
            address: "104.16.9.9".into(),
            port: 443,
            name: "worker-good".into(),
            clean_ip: false,
            link: "vless://good111@104.16.9.9:443?security=tls&type=ws#worker-good".into(),
            note: "deployed".into(),
        };
        // Malformed empty-host record placed BEFORE the good one — the resolver
        // must skip it, not return it.
        let bad = crate::store::profiles::VlessRecord {
            id: crate::store::new_id(),
            ts: crate::store::profiles::now_iso(),
            epoch: crate::store::now_ts(),
            uuid: String::new(),
            address: String::new(),
            port: 443,
            name: String::new(),
            clean_ip: false,
            link: "vless://81c2913f-5d08-4f80-a8ee-bda46fc0b65b@:443?encryption=none&security=tls&type=ws&sni=&host=&path=%2F&fp=chrome#".into(),
            note: String::new(),
        };
        crate::store::profiles::remember_vless(&pid, bad).unwrap();
        crate::store::profiles::remember_vless(&pid, good).unwrap();

        let link = resolve_deployed_base_link(&pid).expect("should resolve to the valid record");
        assert!(link.contains("104.16.9.9"), "got: {link}");
        assert!(link.contains("good111"), "got: {link}");
        assert!(
            !link.contains("@:"),
            "must not be the empty-host record: {link}"
        );
    }

    #[test]
    fn resolve_deployed_base_link_none_when_only_empty_host_records() {
        let _home = isolated_home();
        let pid = crate::store::profiles::create_profile("resolve-allempty", "test").unwrap();
        let bad = crate::store::profiles::VlessRecord {
            id: crate::store::new_id(),
            ts: crate::store::profiles::now_iso(),
            epoch: crate::store::now_ts(),
            uuid: String::new(),
            address: String::new(),
            port: 443,
            name: String::new(),
            clean_ip: false,
            link: "vless://81c2913f-5d08-4f80-a8ee-bda46fc0b65b@:443?encryption=none&security=tls&type=ws&sni=&host=&path=%2F&fp=chrome#".into(),
            note: String::new(),
        };
        crate::store::profiles::remember_vless(&pid, bad).unwrap();
        assert!(
            resolve_deployed_base_link(&pid).is_none(),
            "all records empty-host ⇒ None"
        );
    }
}
