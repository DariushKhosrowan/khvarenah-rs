//! CLI command implementations.

use khvarenah_core::cf::{Client, DnsRecord};
use khvarenah_core::diagnostics::{run_diagnostics, split_endpoint};
use khvarenah_core::export::{render, ExportFormat};
use khvarenah_core::scanner::{scan_many, scan_once, ScanParams};
use khvarenah_core::store::profiles::{
    add_token, create_profile, delete_profile, export_profile, import_profile, list_profiles,
    load_profile, migrate_legacy, remember_clean_ip, remember_vless, rename_profile, VlessRecord,
};
use khvarenah_core::vless::VlessProfile;
use khvarenah_core::worker::{
    find_worker_js, generate_uuid, safe_worker_name, validate_worker_js, worker_name_from_account,
};
use khvarenah_core::{CFError, BRAND, VERSION};

use crate::{BackupAction, Command, DnsAction, RoutesAction};

/// Run a command. `profile` is the active profile id.
pub async fn run(profile: String, cmd: Command) -> Result<(), CFError> {
    match cmd {
        Command::Profiles => cmd_profiles(),
        Command::ProfileCreate { name, description } => {
            let id = create_profile(&name, &description)?;
            println!("Created profile '{name}' (id: {id})");
            Ok(())
        }
        Command::ProfileDelete { id } => {
            delete_profile(&id)?;
            println!("Deleted profile '{id}'");
            Ok(())
        }
        Command::ProfileRename { id, name } => {
            rename_profile(&id, &name)?;
            println!("Renamed profile → '{name}'");
            Ok(())
        }
        Command::ProfileExport { id } => {
            let v = export_profile(&id)?;
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
            Ok(())
        }
        Command::ProfileImport { path } => {
            let text = std::fs::read_to_string(&path).map_err(|e| {
                CFError::new(
                    "Read error",
                    format!("Cannot read {path}: {e}"),
                    "Check the file path.",
                )
            })?;
            let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
                CFError::new(
                    "Parse error",
                    format!("Invalid JSON: {e}"),
                    "Export a profile first.",
                )
            })?;
            let id = import_profile(&v)?;
            println!("Imported profile (id: {id})");
            Ok(())
        }
        Command::TokenAdd { label, token } => {
            add_token(&profile, &label, &token)?;
            println!("Token '{label}' saved to profile '{profile}'");
            Ok(())
        }
        Command::TokenList => {
            let p = load_profile(&profile);
            if p.tokens.is_empty() {
                println!("No tokens in profile '{profile}'.");
            } else {
                for (label, entry) in &p.tokens {
                    let masked = mask(&entry.token);
                    println!("{label}: {masked}");
                }
            }
            Ok(())
        }
        Command::TokenRemove { label } => {
            khvarenah_core::store::profiles::remove_token(&profile, &label)?;
            println!("Removed token '{label}'");
            Ok(())
        }
        Command::Verify => verify(profile).await,
        Command::Accounts => accounts(profile).await,
        Command::Deploy {
            account,
            worker,
            preset,
        } => deploy(&profile, account, worker, preset).await,
        Command::Scan => scan(&profile, 1).await,
        Command::ScanMany { count } => scan(&profile, count).await,
        Command::History => history(&profile),
        Command::Status => status(&profile),
        Command::Migrate => {
            let n = migrate_legacy()?;
            println!("Migration complete ({n} legacy file group(s) imported).");
            Ok(())
        }

        // ---- new tooling ----
        Command::Zones => zones(profile).await,
        Command::Dns { action } => dns(profile, action).await,
        Command::Routes { action } => routes(profile, action).await,
        Command::Export { format, output } => export_cmd(profile, &format, output).await,
        Command::Backup { action } => backup(profile, action),
        Command::Analytics => analytics(profile).await,
        Command::Diag { endpoints } => diag(&endpoints).await,
        Command::Security => security_audit(),
        Command::Presets => presets_cmd(),
        Command::UpdateCheck => update_check().await,
        Command::UpdateApply => update_apply().await,

        // ---- native clean-IP + autopilot ----
        Command::Ranges => cmd_ranges(),
        Command::Discover {
            sample,
            workers,
            refresh,
        } => cmd_discover(&profile, sample, workers, refresh).await,
        Command::Autopilot { action } => cmd_autopilot(&profile, action).await,
    }
}

fn cmd_profiles() -> Result<(), CFError> {
    let list = list_profiles();
    if list.is_empty() {
        println!("No profiles yet. Create one with `profile-create`.");
    } else {
        for m in list {
            println!("• {} ({}) — {}", m.name, m.id, m.description);
        }
    }
    Ok(())
}

fn mask(tok: &str) -> String {
    if tok.len() <= 8 {
        return "••••••••".to_string();
    }
    format!("{}…{}", &tok[..4], &tok[tok.len() - 4..])
}

fn first_token(p: &khvarenah_core::store::profiles::Profile) -> Result<String, CFError> {
    p.tokens
        .values()
        .next()
        .map(|t| t.token.clone())
        .ok_or_else(|| {
            CFError::new(
                "No token",
                "No token in this profile.",
                "Add a token with `khvarenah token add`.",
            )
        })
}

async fn verify(profile: String) -> Result<(), CFError> {
    let token = first_token(&load_profile(&profile))?;
    let client = Client::new(&token);
    match client.verify_token().await {
        Ok(res) => {
            println!("Token is valid. status={} id={}", res.status, res.id);
            Ok(())
        }
        Err(e) => Err(e),
    }
}

async fn accounts(profile: String) -> Result<(), CFError> {
    let token = first_token(&load_profile(&profile))?;
    let client = Client::new(&token);
    let accs = client.list_accounts().await?;
    if accs.is_empty() {
        println!("No accounts accessible with this token.");
    } else {
        for a in accs {
            println!("{} ({})", a.name, a.id);
        }
    }
    Ok(())
}

fn resolve_account_id(
    p: &khvarenah_core::store::profiles::Profile,
    client: &Client,
    account: Option<&str>,
) -> Result<String, CFError> {
    if let Some(a) = account {
        return Ok(a.to_string());
    }
    // Use the active account if remembered, else first accessible.
    if !p.config.active_account.is_empty() {
        return Ok(p.config.active_account.clone());
    }
    let accs = block_on(client.list_accounts())?;
    accs.first().map(|a| a.id.clone()).ok_or_else(|| {
        CFError::new(
            "No account",
            "No CF account accessible.",
            "Check token permissions.",
        )
    })
}

async fn deploy(
    profile: &str,
    account: Option<String>,
    worker: Option<String>,
    preset: Option<String>,
) -> Result<(), CFError> {
    let p = load_profile(profile);
    let token = first_token(&p)?;

    // worker name: explicit > account-derived > preset stem > default
    let worker_name = if let Some(w) = worker {
        safe_worker_name(&w)
    } else if let Some(acc) = account.as_deref() {
        worker_name_from_account(Some(acc))
    } else if let Some(pn) = preset.as_deref() {
        if let Some(preset) = khvarenah_core::presets::find(pn) {
            safe_worker_name(preset.default_worker_stem)
        } else {
            return Err(CFError::new(
                "Unknown preset",
                format!("No preset named '{pn}'."),
                khvarenah_core::presets::describe_all(),
            ));
        }
    } else if let Some(first_acc) = p.accounts.iter().next() {
        worker_name_from_account(Some(&first_acc.1.name))
    } else {
        khvarenah_core::worker::default_worker_name()
    };

    // find worker js (or fall back to the preset's built-in worker)
    let worker_bytes = match find_worker_js(None) {
        Some(path) => {
            let (ok, msg) = validate_worker_js(&path)?;
            if !ok {
                return Err(CFError::new(
                    "Invalid worker file",
                    msg,
                    "Use the correct edgetunnel module worker.",
                ));
            }
            std::fs::read(&path)
                .map_err(|e| CFError::new("Read error", format!("{e}"), "Check file."))?
        }
        None => {
            println!("⚠ No _worker.js found — using the built-in preset worker.");
            khvarenah_core::presets::fallback_worker_js().into_bytes()
        }
    };

    let client = Client::new(&token);
    let acc_id = resolve_account_id(&p, &client, account.as_deref())?;
    let subdomain = client.get_subdomain(&acc_id).await?;
    let uuid = generate_uuid();

    println!("Deploying worker '{worker_name}' to account {acc_id} …");
    client
        .deploy_script(&acc_id, &worker_name, worker_bytes, "2026-07-01", 2)
        .await?;
    client
        .set_vars(
            &acc_id,
            &worker_name,
            serde_json::Map::from_iter([("UUID".into(), serde_json::json!(uuid))]),
        )
        .await?;

    let host = format!("{worker_name}.{subdomain}.workers.dev");
    let vless = VlessProfile {
        uuid: uuid.clone(),
        address: host.clone(),
        port: 443,
        security: "tls".into(),
        path: "/".into(),
        transport: "ws".into(),
        name: format!("{worker_name}-edge"),
        ..Default::default()
    };
    let link = vless.share_link();
    let rec = VlessRecord {
        id: khvarenah_core::store::new_id(),
        ts: khvarenah_core::store::profiles::now_iso(),
        epoch: khvarenah_core::store::now_ts(),
        uuid: uuid.clone(),
        address: host.clone(),
        port: 443,
        name: vless.name.clone(),
        clean_ip: false,
        link: link.clone(),
        note: "deployed via rust CLI".into(),
    };
    remember_vless(profile, rec)?;
    println!("✓ Deployed → {host}");
    println!("VLESS share link:\n{link}");
    Ok(())
}

async fn scan(profile: &str, n: u32) -> Result<(), CFError> {
    let p = load_profile(profile);
    let link = p
        .history
        .iter()
        .find(|r| !r.clean_ip)
        .map(|r| r.link.clone())
        .or_else(|| p.history.first().map(|r| r.link.clone()));
    let Some(link) = link else {
        return Err(CFError::new(
            "No config",
            "No vless config to scan against.",
            "Deploy a worker first.",
        ));
    };

    let params = ScanParams {
        count: p.config.scan_count.max(1),
        workers: p.config.scan_workers.max(1),
        timeout_s: p.config.scan_timeout.max(1),
        gentle: p.config.scan_gentle,
        ports: if p.config.scan_ports.is_empty() {
            "443".into()
        } else {
            p.config.scan_ports.clone()
        },
        ..Default::default()
    };

    if n <= 1 {
        println!("Scanning for one working IP … (stops at the first verified endpoint)");
        match scan_once(&link, &params).await? {
            Some(ep) => {
                println!("✓ Found working IP: {ep}");
                remember_clean_ip(profile, &ep)?;
                let new_link = khvarenah_core::scanner::rewrite_vless_with_endpoint(&link, &ep);
                let rec = VlessRecord {
                    id: khvarenah_core::store::new_id(),
                    ts: khvarenah_core::store::profiles::now_iso(),
                    epoch: khvarenah_core::store::now_ts(),
                    uuid: String::new(),
                    address: ep.clone(),
                    port: 443,
                    name: format!("clean-{ep}"),
                    clean_ip: true,
                    link: new_link.clone(),
                    note: "clean IP".into(),
                };
                remember_vless(profile, rec)?;
                println!("Updated vless config to use {ep}");
                println!("Link:\n{new_link}");
                Ok(())
            }
            None => Err(CFError::new(
                "No clean IP",
                "No working clean IP was found.",
                "Try a larger count or a different port.",
            )),
        }
    } else {
        println!("Scanning for up to {n} working IPs …");
        let res = scan_many(&link, &params, n).await?;
        for ep in &res.endpoints {
            remember_clean_ip(profile, ep)?;
        }
        println!("✓ {}", res.message);
        for ep in &res.endpoints {
            println!("  • {ep}");
        }
        Ok(())
    }
}

fn history(profile: &str) -> Result<(), CFError> {
    let p = load_profile(profile);
    if p.history.is_empty() {
        println!("No saved configs in profile '{profile}'.");
        return Ok(());
    }
    for r in p.history.iter().take(20) {
        let tag = if r.clean_ip {
            "clean-IP"
        } else {
            "workers.dev"
        };
        println!(
            "[{}] {} ({tag})",
            r.ts,
            if r.name.is_empty() {
                &r.address
            } else {
                &r.name
            }
        );
    }
    Ok(())
}

fn status(profile: &str) -> Result<(), CFError> {
    let p = load_profile(profile);
    println!("{BRAND} v{VERSION}");
    println!("Profile: {} ({})", p.meta.name, p.meta.id);
    println!("Tokens: {}", p.tokens.len());
    println!("Accounts: {}", p.accounts.len());
    println!("Configs: {}", p.history.len());
    println!("Clean IPs: {}", p.clean_ips.len());
    Ok(())
}

// ---- new tooling ----

async fn zones(profile: String) -> Result<(), CFError> {
    let token = first_token(&load_profile(&profile))?;
    let client = Client::new(&token);
    let zones = client.list_zones().await?;
    if zones.is_empty() {
        println!("No zones accessible with this token.");
    } else {
        println!("Zones ({}):", zones.len());
        for z in zones {
            println!("  {} ({}) — {}", z.name, z.id, z.status);
        }
    }
    Ok(())
}

async fn dns(profile: String, action: DnsAction) -> Result<(), CFError> {
    let token = first_token(&load_profile(&profile))?;
    let client = Client::new(&token);
    match action {
        DnsAction::List { zone } => {
            let recs = client.list_dns_records(&zone).await?;
            if recs.is_empty() {
                println!("No DNS records in zone {zone}");
            } else {
                println!("DNS records in {zone}:");
                for r in recs {
                    println!(
                        "  {} ({}) → {} [ttl={} proxy={}]",
                        r.name, r.record_type, r.content, r.ttl, r.proxied
                    );
                }
            }
        }
        DnsAction::Create {
            zone,
            name,
            record_type,
            content,
            ttl,
            no_proxy,
        } => {
            let rec = DnsRecord {
                name,
                record_type,
                content,
                ttl,
                proxied: !no_proxy,
                ..Default::default()
            };
            let created = client.create_dns_record(&zone, &rec).await?;
            println!(
                "✓ Created {} {} → {} (id {})",
                created.record_type, created.name, created.content, created.id
            );
        }
        DnsAction::Delete { zone, record_id } => {
            client.delete_dns_record(&zone, &record_id).await?;
            println!("✓ Deleted DNS record {record_id}");
        }
    }
    Ok(())
}

async fn routes(profile: String, action: RoutesAction) -> Result<(), CFError> {
    let p = load_profile(&profile);
    let token = first_token(&p)?;
    let client = Client::new(&token);
    let acc_id = resolve_account_id(&p, &client, None)?;
    match action {
        RoutesAction::List => {
            let routes = client.list_routes(&acc_id).await?;
            if routes.is_empty() {
                println!("No custom routes.");
            } else {
                println!("Routes (account {acc_id}):");
                for r in routes {
                    println!(
                        "  {} → {} ({})",
                        r.pattern,
                        if r.script.is_empty() {
                            "(no script)"
                        } else {
                            &r.script
                        },
                        r.id
                    );
                }
            }
        }
        RoutesAction::Create { pattern, script } => {
            client.create_route(&acc_id, &pattern, &script).await?;
            println!("✓ Route '{pattern}' → {script}");
        }
        RoutesAction::Delete { route_id } => {
            client.delete_route(&acc_id, &route_id).await?;
            println!("✓ Deleted route {route_id}");
        }
    }
    Ok(())
}

async fn export_cmd(
    profile: String,
    format_name: &str,
    output: Option<String>,
) -> Result<(), CFError> {
    let fmt = ExportFormat::parse(format_name).ok_or_else(|| {
        CFError::new(
            "Unknown format",
            format!("No export format '{format_name}'."),
            "Use one of: v2rayn, singbox, clash, link.",
        )
    })?;
    let p = load_profile(&profile);
    let rec = p.history.first().ok_or_else(|| {
        CFError::new(
            "No config",
            "No saved config to export.",
            "Deploy or scan first.",
        )
    })?;
    // Reconstruct a profile from the saved record.
    let mut vless = VlessProfile {
        uuid: rec.uuid.clone(),
        address: rec.address.clone(),
        port: rec.port,
        name: rec.name.clone(),
        ..Default::default()
    };
    vless.normalize();

    let text = render(&vless, fmt)?;
    match output {
        Some(path) => {
            std::fs::write(&path, &text)
                .map_err(|e| CFError::new("Write error", format!("{e}"), "Check the path."))?;
            println!("✓ Exported {} → {path}", fmt.label());
        }
        None => println!("{text}"),
    }
    Ok(())
}

fn backup(_profile: String, action: BackupAction) -> Result<(), CFError> {
    use khvarenah_core::backup::*;
    match action {
        BackupAction::Export { profile_id } => {
            let path = export_profile_to_file(&profile_id, None)?;
            println!("✓ Backed up profile '{profile_id}' → {}", path.display());
        }
        BackupAction::Import { path } => {
            let id = import_profile_from_file(std::path::Path::new(&path))?;
            println!("✓ Restored profile (id {id}) from {path}");
        }
        BackupAction::List => {
            print!("{}", backup_summary());
        }
    }
    Ok(())
}

async fn analytics(profile: String) -> Result<(), CFError> {
    use khvarenah_core::analytics::UsageSummary;
    let p = load_profile(&profile);
    let token = first_token(&p)?;
    let client = Client::new(&token);
    let acc_id = resolve_account_id(&p, &client, None)?;
    let scripts = client.list_scripts(&acc_id).await?;
    if scripts.is_empty() {
        println!("No worker scripts in account {acc_id}.");
        return Ok(());
    }
    let mut summary = UsageSummary::default();
    for s in scripts.iter().take(20) {
        let since = "2026-01-01T00:00:00Z";
        let until = "2026-12-31T23:59:59Z";
        let raw = client
            .script_analytics(&acc_id, &s.name, since, until)
            .await?;
        summary.push_result(&s.name, &raw);
    }
    print!("{}", summary.report());
    Ok(())
}

async fn diag(endpoints: &str) -> Result<(), CFError> {
    let eps: Vec<String> = endpoints
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let opts = khvarenah_core::health::HealthOptions::default();
    let report = run_diagnostics(&eps, &opts).await?;
    print!("{}", report.render());
    if let Some(best) = &report.best {
        let (ip, port) = split_endpoint(&best.endpoint);
        println!(
            "Best endpoint: {} ({} ms, {:.1} kbps)",
            best.endpoint, best.result.connect_ms, best.result.download_kbps
        );
        let _ = (ip, port);
    }
    Ok(())
}

fn security_audit() -> Result<(), CFError> {
    let report = khvarenah_core::security::audit();
    print!("{}", report.render());
    Ok(())
}

fn presets_cmd() -> Result<(), CFError> {
    println!("Deployment presets:");
    println!("{}", khvarenah_core::presets::describe_all().trim());
    Ok(())
}

async fn update_check() -> Result<(), CFError> {
    match khvarenah_core::selfupdate::update_available(std::time::Duration::from_secs(12)).await? {
        (true, Some(tag)) => {
            println!("An update is available: {tag} (current {VERSION}).");
            println!("Run `khvarenah update-apply` to download it.");
        }
        _ => println!("You are on the latest version ({VERSION})."),
    }
    Ok(())
}

async fn update_apply() -> Result<(), CFError> {
    let msg = khvarenah_core::selfupdate::apply_update(std::time::Duration::from_secs(120)).await?;
    println!("{msg}");
    Ok(())
}

/// Block on a future using a fresh tokio runtime.
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Runtime::new()
        .expect("failed to create tokio runtime")
        .block_on(fut)
}

// ---------------------------------------------------------------------------
// Native clean-IP + autopilot CLI
// ---------------------------------------------------------------------------

fn cmd_ranges() -> Result<(), CFError> {
    let cidrs = khvarenah_core::cf::ips::read_cache();
    match cidrs {
        Some(c) => {
            println!("Cached Cloudflare IPv4 ranges (fetched {}):", c.source);
            println!("{}", khvarenah_core::cf::ips::summarize(&c.ipv4));
        }
        None => {
            println!("No cached Cloudflare ranges yet. Run `khvarenah discover` to fetch.");
        }
    }
    Ok(())
}

async fn cmd_discover(profile: &str, sample: u32, workers: u32, refresh: bool) -> Result<(), CFError> {
    let params = khvarenah_core::autopilot::DiscoveryParams {
        sample: sample.max(1),
        workers: workers.max(1) as usize,
        force_refresh_ranges: refresh,
        ..Default::default()
    };
    // First make sure we have a base worker config to front.
    let _ = khvarenah_core::autopilot::base_vless(profile)?;
    println!("Discovery: {} candidate IPs, {} workers, targeting {} clean endpoint(s)…",
        params.sample, params.workers, params.top_n);

    let engine = khvarenah_core::autopilot::AutopilotEngine::new(
        profile,
        params.clone(),
        std::time::Duration::from_secs(300),
    );
    let (found, summary) = engine.run_cycle().await?;
    if found.is_empty() {
        println!("No clean IP found in this cycle. Try a larger --sample, --refresh, or re-deploy a worker.");
        return Ok(());
    }
    for ep in &found {
        println!(
            "✓ {}:{} (score {:.1}, tcp {:.0}ms, {:.0} kbps)",
            ep.ip, ep.port, ep.score, ep.tcp_ms, ep.download_kbps
        );
    }
    println!("{}", summary.note);
    // Surface the user-facing bundle (QR + one-line active config).
    if let Ok(bundle) = khvarenah_core::cleanip::write_user_bundle(profile, &base_vless_for(profile), &found) {
        println!();
        println!("✓ Protection active. Config: {}", bundle.dir.display());
        println!("  → active.png   (scan with your phone)");
        println!("  → active.vless (paste into your desktop client)");
        println!("  → 3 fallbacks saved in fallbacks.txt");
        if let Some(best) = found.first() {
            println!("  Best endpoint: {}:{} ({:.0}ms)", best.ip, best.port, best.tcp_ms);
        }
    }
    Ok(())
}

fn base_vless_for(profile: &str) -> khvarenah_core::VlessProfile {
    khvarenah_core::autopilot::base_vless(profile).unwrap_or_default()
}

async fn cmd_autopilot(profile: &str, action: crate::AutopilotAction) -> Result<(), CFError> {
    match action {
        crate::AutopilotAction::Status => {
            let ledger = khvarenah_core::autopilot::read_ledger(profile);
            if ledger.is_empty() {
                println!("Autopilot ledger is empty — run `.khvarenah autopilot on` to start.");
                return Ok(());
            }
            let alive = ledger.iter().filter(|e| e.alive).count();
            println!("Autopilot status (profile '{profile}'): {} endpoint(s) in ledger, {alive} alive.", ledger.len());
            for ep in ledger.iter().take(10) {
                println!(
                    "  {}:{}  sni={}  score={:.1}  alive={}",
                    ep.ip, ep.port, ep.sni, ep.score, ep.alive
                );
            }
            Ok(())
        }
        crate::AutopilotAction::Check => {
            let engine = khvarenah_core::autopilot::AutopilotEngine::new(
                profile,
                khvarenah_core::autopilot::DiscoveryParams::default(),
                std::time::Duration::from_secs(300),
            );
            let summary = engine.monitor_cycle().await?;
            println!("{}", summary.note);
            Ok(())
        }
        crate::AutopilotAction::On {
            interval_s,
            sample,
            workers,
        } => {
            let params = khvarenah_core::autopilot::DiscoveryParams {
                sample: sample.max(1),
                workers: workers.max(1) as usize,
                ..Default::default()
            };
            let interval = std::time::Duration::from_secs(interval_s.max(60));
            println!("Autopilot ON (profile '{profile}'): discovery every {}s, {} candidates, {} workers.",
                interval.as_secs(), params.sample, params.workers);
            println!("First cycle: discovering the best clean IP…");
            let engine = khvarenah_core::autopilot::AutopilotEngine::new(profile, params, interval);
            engine.run_forever(|summary| {
                println!(
                    "[cycle {}] {} (alive: {}, replaced: {})",
                    summary.cycle, summary.note, summary.alive, summary.replaced
                );
            }).await?;
            Ok(())
        }
        crate::AutopilotAction::Off => {
            println!("Autopilot has no persistent loop in the CLI (it runs per-invocation). Use the GUI toggle for a background loop.");
            Ok(())
        }
    }
}
