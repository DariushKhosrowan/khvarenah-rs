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

use crate::{BackupAction, Command, DaemonAction, DnsAction, ProtectionAction, RoutesAction};
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
        Command::Protection { action } => cmd_protection(&profile, action).await,
        Command::Daemon { action } => cmd_daemon(&profile, action).await,
        Command::Health { json } => cmd_health(&profile, json),
        Command::E2e {
            skip_worker_deploy,
            worker,
        } => cmd_e2e(&profile, skip_worker_deploy, worker).await,
        Command::VerifyTunnel {
            direct_ip,
            tunnel_ip,
        } => cmd_verify(&direct_ip, &tunnel_ip),
        Command::Bundle { action } => cmd_bundle(&profile, action),
    }
}

fn cmd_bundle(profile: &str, action: crate::BundleAction) -> Result<(), CFError> {
    match action {
        crate::BundleAction::Verify => {
            let ledger_ep = khvarenah_core::cleanip::active_ledger_endpoint(profile);
            match ledger_ep {
                None => {
                    println!(
                        "No verified active endpoint in the ledger yet — nothing to reconcile."
                    );
                }
                Some(ledger_ep) => {
                    let dir = khvarenah_core::cleanip::user_config_dir(profile)?;
                    let drift = khvarenah_core::cleanip::check_bundle_drift(&dir, &ledger_ep);
                    match drift {
                        khvarenah_core::cleanip::BundleDrift::InSync => {
                            println!(
                                "Bundle in-sync with ledger (endpoint={ledger_ep}, files=4/4)"
                            );
                        }
                        khvarenah_core::cleanip::BundleDrift::MissingDir => {
                            println!("Bundle drift: directory missing ({}). Next cycle will recreate it.", dir.display());
                        }
                        khvarenah_core::cleanip::BundleDrift::MissingFile { name } => {
                            println!(
                                "Bundle drift: missing file {name}. Next cycle will recreate it."
                            );
                        }
                        khvarenah_core::cleanip::BundleDrift::EndpointMismatch {
                            bundle_endpoint,
                            ledger_endpoint,
                        } => {
                            println!(
                                "Bundle drift: active.vless points to {bundle_endpoint} but ledger says {ledger_endpoint}"
                            );
                            println!("Next cycle will reconcile automatically, or run `khvarenah bundle reconcile`.");
                        }
                        khvarenah_core::cleanip::BundleDrift::Unparseable { file, reason } => {
                            println!("Bundle drift: {file} unparseable ({reason}). Next cycle will recreate it.");
                        }
                    }
                }
            }
            Ok(())
        }
        crate::BundleAction::Reconcile => {
            let outcome = khvarenah_core::cleanip::reconcile_bundle_if_drifted(profile);
            match outcome {
                khvarenah_core::cleanip::ReconcileOutcome::WasInSync => {
                    println!("Bundle already in-sync with ledger — no action needed.");
                }
                khvarenah_core::cleanip::ReconcileOutcome::Rewritten { reason } => {
                    println!("Bundle rewritten from ledger (reason={reason:?}).");
                }
                khvarenah_core::cleanip::ReconcileOutcome::Failed { reason } => {
                    return Err(CFError::new(
                        "Bundle reconcile",
                        reason,
                        "Check permissions and profile config.",
                    ));
                }
            }
            Ok(())
        }
    }
}

/// Read and render the per-cycle health beacon. `--json` emits the raw
/// snapshot; otherwise a human-readable table. Exit code 0 (fresh) / 1
/// (stale / missing) makes this scriptable for the user's remote check.
fn cmd_health(profile: &str, json: bool) -> Result<(), CFError> {
    let beacon = match khvarenah_core::health_beacon::read_beacon(profile)? {
        Some(b) => b,
        None => {
            println!("No health beacon yet for profile '{profile}' — no cycle has run.");
            println!("Run `khvarenah autopilot` or start the daemon, then re-check.");
            std::process::exit(1);
        }
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&beacon).unwrap());
        return Ok(());
    }

    let now = khvarenah_core::store::now_ts() as i64;
    let age = khvarenah_core::health_beacon::beacon_age_secs(&beacon, now);
    // Staleness threshold: 3× the light-monitor interval from the profile
    // config.
    let cfg = khvarenah_core::store::profiles::load_profile(profile).config;
    let interval = cfg.light_interval_secs.max(60) as i64;
    let stale = khvarenah_core::health_beacon::is_stale(&beacon, now, 3 * interval);

    let kind = match beacon.cycle_kind {
        khvarenah_core::health_beacon::CycleKind::Discovery => "Discovery",
        khvarenah_core::health_beacon::CycleKind::Monitor => "Monitor",
        khvarenah_core::health_beacon::CycleKind::Rescue => "Rescue",
        khvarenah_core::health_beacon::CycleKind::Manual => "Manual",
    };

    println!("Health beacon — profile {profile}");
    println!(
        "  cycle:        {kind} ts={} dur={}ms",
        beacon.cycle_ts, beacon.cycle_duration_ms
    );
    println!(
        "  written:      {}s ago ({})",
        age,
        if stale { "STALE" } else { "fresh" }
    );
    println!(
        "  protection:   {}",
        if beacon.protection_enabled {
            "on"
        } else {
            "off"
        }
    );
    println!("  worker:       {}", beacon.worker_health);
    println!(
        "  active:       {}",
        beacon.active_endpoint.as_deref().unwrap_or("-")
    );
    println!(
        "  alive:        {}",
        if beacon.active_alive { "yes" } else { "no" }
    );
    println!(
        "  bundle:       {}/sync",
        if beacon.bundle_in_sync { "in" } else { "NOT" }
    );
    println!(
        "  strategy:     {} window={:?} rate={:?} cycles_since_rot={}",
        beacon.strategy_current,
        beacon.strategy_window,
        beacon.strategy_rate,
        beacon.strategy_cycles_since_rotation
    );
    if let Some(outcome) = &beacon.last_rescue_outcome {
        println!("  last rescue:  {outcome}");
    }
    if let Some(err) = &beacon.last_error {
        println!("  last error:   {err}");
    }

    if stale {
        std::process::exit(1);
    }
    Ok(())
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

async fn cmd_discover(
    profile: &str,
    sample: u32,
    workers: u32,
    refresh: bool,
) -> Result<(), CFError> {
    let params = khvarenah_core::autopilot::DiscoveryParams {
        sample: sample.max(1),
        workers: workers.max(1) as usize,
        force_refresh_ranges: refresh,
        ..Default::default()
    };
    // First make sure we have a base worker config to front.
    let _ = khvarenah_core::autopilot::base_vless(profile)?;
    println!(
        "Discovery: {} candidate IPs, {} workers, targeting {} clean endpoint(s)…",
        params.sample, params.workers, params.top_n
    );

    let engine = khvarenah_core::autopilot::AutopilotEngine::new(
        profile,
        params.clone(),
        std::time::Duration::from_secs(300),
    );
    let (found, summary) = engine
        .run_cycle_guarded(std::time::Duration::from_secs(
            khvarenah_core::cycle_guard::DISCOVERY_TIMEOUT_SECS,
        ))
        .await?;
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
    if let Ok(bundle) =
        khvarenah_core::cleanip::write_user_bundle(profile, &base_vless_for(profile), &found)
    {
        println!();
        println!("✓ Protection active. Config: {}", bundle.dir.display());
        println!("  → active.png   (scan with your phone)");
        println!("  → active.vless (paste into your desktop client)");
        println!("  → 3 fallbacks saved in fallbacks.txt");
        if let Some(best) = found.first() {
            println!(
                "  Best endpoint: {}:{} ({:.0}ms)",
                best.ip, best.port, best.tcp_ms
            );
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
                println!("Autopilot ledger is empty — run `khvarenah autopilot on` to start.");
                return Ok(());
            }
            let alive: Vec<_> = ledger.iter().filter(|e| e.alive).cloned().collect();
            let summary = khvarenah_core::autopilot::CycleSummary {
                cycle: 0,
                alive: alive.len(),
                replaced: 0,
                note: format!("monitor: {} alive", alive.len()),
            };
            println!("{}", khvarenah_core::status::simplify_status(&summary));
            println!(
                "  Best IP: {}",
                khvarenah_core::status::pick_best_caption(&alive)
            );
            println!("{}", khvarenah_core::status::bundle_status(profile));
            // Collapsible technical detail (only when the user asks).
            println!("  (detail: {} endpoint(s) in ledger)", ledger.len());
            Ok(())
        }
        crate::AutopilotAction::Check => {
            let engine = khvarenah_core::autopilot::AutopilotEngine::new(
                profile,
                khvarenah_core::autopilot::DiscoveryParams::default(),
                std::time::Duration::from_secs(300),
            );
            let summary = engine
                .monitor_cycle_guarded(khvarenah_core::autopilot::MonitorTimeouts::default())
                .await?;
            println!("{}", summary.note);
            Ok(())
        }
        crate::AutopilotAction::Health {
            connect_ip,
            verbose,
        } => {
            let vless = khvarenah_core::autopilot::base_vless(profile)?;
            let target = khvarenah_core::health::derive_ws_target(&vless);
            let host = target.sni.clone();
            if let Some(ip) = connect_ip {
                println!("Probing worker {host} via connect-ip {ip} (SNI={host}) …");
            } else {
                println!("Probing worker {host} …");
            }
            let doh = khvarenah_core::doh::DohResolver::new();
            match khvarenah_core::autopilot::probe_worker_health(&host, connect_ip, Some(&doh), 10)
                .await
            {
                khvarenah_core::autopilot::WorkerHealth::Alive => {
                    println!("Worker HEALTHY (Alive). Scanning will proceed.");
                }
                other => {
                    let cause = match other {
                        khvarenah_core::autopilot::WorkerHealth::Suspended { .. }
                        | khvarenah_core::autopilot::WorkerHealth::NotFound => {
                            khvarenah_core::diagnose::PlainCause::WorkerDead
                        }
                        khvarenah_core::autopilot::WorkerHealth::PathMismatch => {
                            khvarenah_core::diagnose::PlainCause::WorkerPathMismatch
                        }
                        khvarenah_core::autopilot::WorkerHealth::Unreachable => {
                            khvarenah_core::diagnose::PlainCause::NetworkBlocked
                        }
                        khvarenah_core::autopilot::WorkerHealth::Alive => unreachable!(),
                    };
                    println!(
                        "Worker NOT healthy: {}",
                        khvarenah_core::diagnose::plain_message(
                            cause,
                            khvarenah_core::diagnose::Locale::En
                        )
                    );
                    println!(
                        "  Recommended: {}",
                        khvarenah_core::diagnose::recommended_action(cause)
                            .label(khvarenah_core::diagnose::Locale::En)
                    );
                }
            }
            // `--verbose`: dump the last scan's phase-2 failure histogram so
            // the A-vs-B question is answerable in one command. TlsAlert
            // dominant → DPI resetting the static ClientHello (Cause A);
            // DeadRoute/HttpStatus(404,421) dominant → worker route dead
            // (Cause B, rescue territory).
            if verbose {
                println!("\n--- phase-2 WS-failure histogram (last scan) ---");
                if let Some(diag) = khvarenah_core::store::profiles::load_last_diagnostics(profile)
                {
                    if diag.ws_failure_histogram.is_empty() {
                        println!("  (empty — no phase-2 probes recorded yet; run a discovery cycle first)");
                    } else {
                        let mut rows: Vec<_> = diag.ws_failure_histogram.iter().collect();
                        rows.sort_by(|a, b| b.1.cmp(a.1));
                        for (reason, count) in rows {
                            println!("  {reason:?}: {count}");
                        }
                        let tls_alerts = *diag
                            .ws_failure_histogram
                            .get(&khvarenah_core::health::WsFailureReason::TlsAlert)
                            .unwrap_or(&0);
                        let all: u32 = diag.ws_failure_histogram.values().sum();
                        if all > 0 {
                            let pct = tls_alerts as f64 * 100.0 / all as f64;
                            println!("\n  TlsAlert share: {pct:.0}% of {} phase-2 failures", all);
                            println!(
                                "  Verdict: {}",
                                if pct > 50.0 {
                                    "DPI is resetting the TLS handshake (static ClientHello fingerprint) — TLS-layer profile variation is the lever."
                                } else {
                                    "The worker route is dead (path/404/421) — rescue/redeploy territory, not a network problem."
                                }
                            );
                        }
                    }
                } else {
                    println!("  (no last-diagnostics file for profile {profile})");
                }
            }
            // Self-learning phase-2 SNI strategy status (the autonomy knob, v2
            // rolling-window).
            if verbose {
                // Health beacon line (round 4): age + kind, so `autopilot
                // health --verbose` doubles as a one-line liveness check.
                if let Ok(Some(beacon)) = khvarenah_core::health_beacon::read_beacon(profile) {
                    let now = khvarenah_core::store::now_ts() as i64;
                    let age = khvarenah_core::health_beacon::beacon_age_secs(&beacon, now);
                    let kind = match beacon.cycle_kind {
                        khvarenah_core::health_beacon::CycleKind::Discovery => "Discovery",
                        khvarenah_core::health_beacon::CycleKind::Monitor => "Monitor",
                        khvarenah_core::health_beacon::CycleKind::Rescue => "Rescue",
                        khvarenah_core::health_beacon::CycleKind::Manual => "Manual",
                    };
                    println!(
                        "  Beacon: age={age}s cycle_ts={} cycle_kind={kind}",
                        beacon.cycle_ts
                    );
                    let last_error = beacon.last_error.as_deref().unwrap_or("none");
                    let last_stage = beacon.last_stage.as_deref().unwrap_or("<cleared>");
                    let active = beacon.active_endpoint.as_deref().unwrap_or("-");
                    let elapsed = beacon.cycle_duration_ms;
                    println!(
                        "  Last monitor cycle: stage={last_stage} error={last_error} elapsed={elapsed}ms endpoint={active}"
                    );
                }
                let state = khvarenah_core::autopilot::resolve_strategy_v2(profile);
                let name = match state.current {
                    khvarenah_core::health::SniStrategy::WorkerOnly => "WorkerOnly",
                    khvarenah_core::health::SniStrategy::GenericCfFirst => "GenericCfFirst",
                    khvarenah_core::health::SniStrategy::WorkerThenGenericCf => {
                        "WorkerThenGenericCf"
                    }
                };
                let window: Vec<u8> = state.recent_outcomes.iter().map(|&w| u8::from(w)).collect();
                let rate = khvarenah_core::autopilot::success_rate(&state);
                let should_rotate = khvarenah_core::autopilot::should_rotate(&state);
                let cycles_left = khvarenah_core::autopilot::STRATEGY_FORCED_ROTATION_CYCLES
                    .saturating_sub(state.cycles_since_rotation);
                let rotated_ts = khvarenah_core::store::profiles::strategy_last_rotated_ts(profile);
                if should_rotate {
                    println!("  Strategy: {name} (rotating next cycle, window={window:?})");
                } else if let Some(r) = rate {
                    println!(
                        "  Strategy: {name} (window={window:?}, rate={:.0}%, next rotation in {cycles_left} cycles)",
                        r * 100.0
                    );
                } else if rotated_ts > 0 {
                    println!("  Strategy: {name} (rotated {rotated_ts}s epoch, window empty)");
                } else {
                    println!("  Strategy: {name} (not yet learned; auto)");
                }
                // Bundle sync state (the user's actual handoff).
                if let Some(ledger_ep) = khvarenah_core::cleanip::active_ledger_endpoint(profile) {
                    let dir = khvarenah_core::cleanip::user_config_dir(profile).ok();
                    let drift = dir
                        .as_ref()
                        .map(|d| khvarenah_core::cleanip::check_bundle_drift(d, &ledger_ep));
                    match drift {
                        Some(khvarenah_core::cleanip::BundleDrift::InSync) => {
                            println!("  Bundle: in-sync (endpoint={ledger_ep})");
                        }
                        Some(khvarenah_core::cleanip::BundleDrift::EndpointMismatch { .. })
                        | Some(khvarenah_core::cleanip::BundleDrift::MissingDir)
                        | Some(khvarenah_core::cleanip::BundleDrift::MissingFile { .. })
                        | Some(khvarenah_core::cleanip::BundleDrift::Unparseable { .. }) => {
                            println!("  Bundle: drifted — next cycle will reconcile automatically");
                        }
                        None => {
                            println!("  Bundle: (unreadable)");
                        }
                    }
                }
            }
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
            engine
                .run_forever(|summary| {
                    println!(
                        "[cycle {}] {} (alive: {}, replaced: {})",
                        summary.cycle, summary.note, summary.alive, summary.replaced
                    );
                })
                .await?;
            Ok(())
        }
        crate::AutopilotAction::Off => {
            println!("Autopilot has no persistent loop in the CLI (it runs per-invocation). Use the GUI toggle for a background loop.");
            Ok(())
        }
    }
}

/// One-button Protection: the "simple for a normal user" path. Persists the
/// monitor flag (auto-resume after restart), runs a full discovery cycle with
/// the parallel pipeline, writes the user bundle, and optionally keeps a
/// foreground monitor loop until Ctrl+C.
async fn cmd_protection(profile: &str, action: ProtectionAction) -> Result<(), CFError> {
    match action {
        ProtectionAction::Status => {
            let enabled = khvarenah_core::store::profiles::protection_enabled(profile);
            println!("Protection: {}", if enabled { "ON" } else { "OFF" });
            // Surface the last plain-language explanation of a zero result, if any.
            if let Some(diag) = khvarenah_core::store::profiles::load_last_diagnostics(profile) {
                let probe = khvarenah_core::diagnose::WorkerProbe::default();
                let cause = khvarenah_core::diagnose::diagnose(&diag, probe);
                println!(
                    "  Last scan: {}",
                    khvarenah_core::diagnose::plain_message(
                        cause,
                        khvarenah_core::diagnose::Locale::En
                    )
                );
                println!(
                    "  Recommended: {}",
                    khvarenah_core::diagnose::recommended_action(cause)
                        .label(khvarenah_core::diagnose::Locale::En)
                );
            }
            Ok(())
        }
        ProtectionAction::SeedsImport { raw, stdin } => {
            let input = if stdin {
                use std::io::Read;
                let mut s = String::new();
                std::io::stdin()
                    .read_to_string(&mut s)
                    .map_err(|e| CFError::new("Seeds", format!("stdin read: {e}"), ""))?;
                s
            } else {
                raw.clone().unwrap_or_default()
            };
            let n = khvarenah_core::cf::ips::import_manual_seeds(profile, &input)?;
            println!("Imported {n} known-good IP(s). Next scan will use them as seeds.");
            Ok(())
        }
        ProtectionAction::Off => {
            khvarenah_core::store::profiles::set_protection(profile, false)?;
            println!("Protection OFF (monitor will not auto-resume).");
            Ok(())
        }
        ProtectionAction::On {
            persist,
            monitor,
            interval_s,
            sample,
            workers,
        } => {
            if persist {
                khvarenah_core::store::profiles::set_protection(profile, true)?;
                println!("Protection ON (persisted — will auto-resume after restart).");
            } else {
                println!("Protection ON (not persisted).");
            }

            let params = khvarenah_core::autopilot::DiscoveryParams {
                sample: sample.max(1),
                workers: workers.max(1) as usize,
                ..Default::default()
            };
            let interval = std::time::Duration::from_secs(interval_s.max(60));
            println!("First cycle: discovering the best clean IP…");
            let engine = khvarenah_core::autopilot::AutopilotEngine::new(profile, params, interval);

            if monitor {
                engine
                    .run_forever(|summary| {
                        println!(
                            "[cycle {}] {} (alive: {}, replaced: {})",
                            summary.cycle, summary.note, summary.alive, summary.replaced
                        );
                    })
                    .await?;
            } else {
                let (_, summary) = engine
                    .run_cycle_guarded(std::time::Duration::from_secs(
                        khvarenah_core::cycle_guard::DISCOVERY_TIMEOUT_SECS,
                    ))
                    .await?;
                println!("{}", summary.note);
            }
            Ok(())
        }
    }
}

/// Run the daemon loop forever (or until the stop file appears).
async fn daemon_loop(cfg: khvarenah_core::daemon::DaemonConfig) -> Result<(), CFError> {
    use khvarenah_core::daemon::*;
    use std::time::Duration;

    let pid = std::process::id();
    acquire_pid_file(&cfg.pid_file, pid)?;
    daemon_log_append(
        &cfg.log_path,
        &log_line(
            "INFO",
            &format!(
                "daemon start profile={} pid={pid} interval={}",
                cfg.profile, cfg.initial_interval_secs
            ),
        ),
    );

    let mut state = load_daemon_state(&cfg.profile);
    state.pid = pid;
    state.started_at = khvarenah_core::store::now_ts() as i64;
    save_daemon_state(&cfg.profile, &state)?;

    let probe = RealNetworkProbe(khvarenah_core::doh::DohResolver::new());
    let cycle = RealCycleRunner;
    let mut interval = cfg.initial_interval_secs;

    loop {
        // Stop request?
        if cfg.stop_file.exists() {
            daemon_log_append(&cfg.log_path, &log_line("INFO", "daemon stop requested"));
            cleanup_daemon(&cfg.pid_file, &cfg.stop_file);
            return Ok(());
        }

        let sleep = daemon_tick(&cfg.profile, &mut state, &probe, &cycle, &mut |line| {
            daemon_log_append(&cfg.log_path, line)
        })
        .await;
        save_daemon_state(&cfg.profile, &state)?;
        // Persist the current backoff interval into state.
        if sleep != 0 && sleep != interval {
            interval = sleep;
        }
        tokio::time::sleep(Duration::from_secs(sleep)).await;
    }
}

/// CLI handler for the persistent daemon.
async fn cmd_daemon(profile: &str, action: DaemonAction) -> Result<(), CFError> {
    use khvarenah_core::daemon::*;
    match action {
        DaemonAction::Start {
            foreground,
            interval_s,
        } => {
            let mut cfg = DaemonConfig::new(profile);
            cfg.initial_interval_secs = interval_s.max(60);
            cfg.foreground = foreground;
            cfg.max_interval_secs = DEFAULT_MAX_INTERVAL_SECS;

            if !foreground && is_daemon_running(&cfg.pid_file) {
                return Err(CFError::new(
                    "Daemon",
                    "Already running.",
                    "Use `daemon status` or `daemon stop` first.",
                ));
            }

            if foreground {
                // Run in the foreground (recommended under systemd).
                return daemon_loop(cfg).await;
            }

            // Daemonize: re-exec ourselves in the background with --foreground
            // and return immediately (the parent must not block on the
            // long-running daemon). stdio is detached so the daemon survives
            // the shell/terminal closing.
            let exe = std::env::current_exe()
                .map_err(|e| CFError::new("Daemon", e.to_string(), "Cannot locate the binary."))?;
            std::process::Command::new(exe)
                .arg("daemon")
                .arg("start")
                .arg("--profile")
                .arg(profile)
                .arg("--foreground")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .map_err(|e| {
                    CFError::new(
                        "Daemon",
                        e.to_string(),
                        "Cannot spawn the background daemon.",
                    )
                })?;
            // The child holds the pid file; once it has written "daemon start"
            // to its own log it is live. Give it a moment to acquire the pid
            // file so a tight `start && status` sequence sees it running.
            std::thread::sleep(std::time::Duration::from_millis(300));
            Ok(())
        }
        DaemonAction::Stop => {
            let cfg = DaemonConfig::new(profile);
            // Write stop file; the loop cleans up on next tick.
            khvarenah_core::store::write_json(&cfg.stop_file, &true)?;
            println!("Stop requested. The daemon will exit on its next tick.");
            Ok(())
        }
        DaemonAction::Status => {
            let cfg = DaemonConfig::new(profile);
            let state = load_daemon_state(profile);
            let running = is_daemon_running(&cfg.pid_file);
            println!("Daemon (profile '{profile}'):");
            println!("  running: {}", if running { "yes" } else { "no" });
            println!("  pid: {}", state.pid);
            if state.started_at > 0 {
                let up = (khvarenah_core::store::now_ts() as i64) - state.started_at;
                println!("  uptime: {up}s");
            }
            println!("  last cycle ts: {}", state.last_cycle_ts);
            println!("  last success ts: {}", state.last_success_ts);
            println!("  failure streak: {}", state.failure_streak);
            println!("  current interval: {}s", state.current_interval_secs);
            println!("  network was down: {}", state.network_was_down);
            Ok(())
        }
        DaemonAction::InstallSystemd => {
            let home = std::env::var("HOME").unwrap_or_else(|_| "~".into());
            let unit_dir = std::path::PathBuf::from(&home).join(".config/systemd/user");
            std::fs::create_dir_all(&unit_dir).map_err(|e| {
                CFError::new(
                    "Daemon",
                    e.to_string(),
                    "Cannot create ~/.config/systemd/user.",
                )
            })?;
            let unit = unit_dir.join("khvarenah-daemon.service");
            let bin = std::env::current_exe()
                .map_err(|e| CFError::new("Daemon", e.to_string(), "Cannot locate the binary."))?;
            let contents = khvarenah_core::daemon::systemd_unit(&bin, profile);
            std::fs::write(&unit, contents).map_err(|e| {
                CFError::new("Daemon", e.to_string(), "Cannot write the systemd unit.")
            })?;
            println!("Wrote {}.", unit.display());
            println!("Enable with: systemctl --user enable --now khvarenah-daemon.service");
            Ok(())
        }
        DaemonAction::Reset => {
            match reset_daemon_state(profile) {
                Ok(Some((old_streak, old_interval))) => {
                    println!(
                        "Daemon backoff reset: next cycle in {}s (was {}s, streak {})",
                        DEFAULT_INITIAL_INTERVAL_SECS, old_interval, old_streak
                    );
                }
                Ok(None) => {
                    println!("No daemon state to reset");
                }
                Err(e) => return Err(e),
            }
            Ok(())
        }
    }
}

/// End-to-end harness: verify the token → (optionally) deploy the worker →
/// discover clean IPs → write the user bundle → print the manual-verification
/// block. Does NOT claim success itself; the only proof is the two `ip=`
/// lines differing after the human runs `verify`.
async fn cmd_e2e(
    profile: &str,
    skip_worker_deploy: bool,
    worker: Option<String>,
) -> Result<(), CFError> {
    // 1) Token must be live.
    let p = load_profile(profile);
    let token = first_token(&p)?;
    let client = khvarenah_core::cf::Client::new(&token);
    let v = client.verify_token().await?;
    if v.status != "active" {
        return Err(CFError::new(
            "CF token not active",
            format!("token status = '{}'", v.status),
            "Check the API token in the profile.",
        ));
    }
    println!("✓ CF token active.");

    // 2) Deploy the worker unless skipped.
    if !skip_worker_deploy {
        deploy(profile, None, worker.clone(), None).await?;
    }

    // 3) Worker must exist.
    let worker_name = worker
        .map(|w| safe_worker_name(&w))
        .unwrap_or_else(|| default_worker_name_for(&p));
    let acc_id = if p.config.active_account.is_empty() {
        client
            .list_accounts()
            .await?
            .first()
            .map(|a| a.id.clone())
            .ok_or_else(|| {
                CFError::new(
                    "No account",
                    "No CF account accessible.",
                    "Check token permissions.",
                )
            })?
    } else {
        p.config.active_account.clone()
    };
    let scripts = client.list_scripts(&acc_id).await?;
    if !scripts.iter().any(|s| s.name == worker_name) {
        return Err(CFError::new(
            "Worker missing",
            format!("Worker '{worker_name}' not found on account {acc_id}."),
            "Deploy the worker first (or omit --skip-worker-deploy).",
        ));
    }
    let host = format!(
        "{worker_name}.{}.workers.dev",
        client.get_subdomain(&acc_id).await?
    );
    println!("✓ Worker '{worker_name}' exists → {host}");

    // 4) Run native discovery.
    let params = khvarenah_core::autopilot::DiscoveryParams::default();
    let engine = khvarenah_core::autopilot::AutopilotEngine::new(
        profile,
        params,
        std::time::Duration::from_secs(300),
    );
    let (found, summary) = engine
        .run_cycle_guarded(std::time::Duration::from_secs(
            khvarenah_core::cycle_guard::DISCOVERY_TIMEOUT_SECS,
        ))
        .await?;
    if found.is_empty() {
        return Err(CFError::new(
            "No clean IP",
            "Discovery found no clean IP for this worker.",
            "Run with a larger sample or re-deploy the worker.",
        ));
    }
    for ep in &found {
        println!(
            "✓ {}:{} (score {:.1}, tcp {:.0}ms)",
            ep.ip, ep.port, ep.score, ep.tcp_ms
        );
    }
    println!("{}", summary.note);

    // 5) Write the user bundle.
    let bundle = khvarenah_core::cleanip::write_user_bundle(
        profile,
        &khvarenah_core::autopilot::base_vless(profile)?,
        &found,
    )?;
    println!();
    println!("✓ User config bundle: {}", bundle.dir.display());
    println!("  → active.png (scan with phone) · active.vless (paste into client)");

    // 6) Manual verification block.
    println!();
    println!("══════════════════ MANUAL VERIFICATION ══════════════════");
    println!("1. Direct (no VPN) — run:   curl -s https://ifconfig.me");
    println!("   (or https://api.ipify.org) → note the IP as DIRECT_IP");
    println!("2. Connect with the client using active.vless / active.png");
    println!("3. Through the tunnel — run: curl -s https://ifconfig.me");
    println!("   → note the IP as TUNNEL_IP");
    println!("4. Compare:  khvarenah verify --direct-ip DIRECT_IP --tunnel-ip TUNNEL_IP");
    println!("   PASS = the two IPs differ → the tunnel routes through the Worker.");
    println!("════════════════════════════════════════════════════════════");
    Ok(())
}

fn default_worker_name_for(p: &khvarenah_core::store::profiles::Profile) -> String {
    // Mirror deploy()'s fallback: first account name, else preset stem.
    if let Some(first) = p.accounts.iter().next() {
        worker_name_from_account(Some(&first.1.name))
    } else {
        khvarenah_core::worker::default_worker_name()
    }
}

/// Compare direct vs tunnel IP. This is the E2E gate.
fn cmd_verify(direct_ip: &str, tunnel_ip: &str) -> Result<(), CFError> {
    let d = direct_ip.trim();
    let t = tunnel_ip.trim();
    if d.is_empty() || t.is_empty() {
        return Err(CFError::new(
            "Missing IP",
            "Both --direct-ip and --tunnel-ip are required.",
            "Run the manual verification steps in `khvarenah e2e`.",
        ));
    }
    if d == t {
        return Err(CFError::new(
            "E2E FAIL",
            "direct IP == tunnel IP — the tunnel is NOT routing through the Worker.",
            "Check the worker route, UUID, and clean-IP config, then retry.",
        ));
    }
    println!("✓ E2E PASS — direct {d} ≠ tunnel {t}. Tunnel routes through the Worker.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_passes_when_ips_differ() {
        assert!(cmd_verify("1.2.3.4", "5.6.7.8").is_ok());
    }

    #[test]
    fn test_verify_fails_when_ips_match() {
        assert!(cmd_verify("1.2.3.4", "1.2.3.4").is_err());
    }

    #[test]
    fn test_verify_fails_on_empty_ip() {
        assert!(cmd_verify("", "1.2.3.4").is_err());
        assert!(cmd_verify("1.2.3.4", "").is_err());
        assert!(cmd_verify("", "").is_err());
    }
}
