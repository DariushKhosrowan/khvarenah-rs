//! CLI command implementations.

use dastyab_core::cf::{Client, DnsRecord};
use dastyab_core::diagnostics::{run_diagnostics, split_endpoint};
use dastyab_core::export::{render, ExportFormat};
use dastyab_core::scanner::{scan_many, scan_once, ScanParams};
use dastyab_core::store::profiles::{
    add_token, create_profile, delete_profile, export_profile, import_profile, list_profiles,
    load_profile, migrate_legacy, remember_clean_ip, remember_vless, rename_profile,
    set_active_token, VlessRecord,
};
use dastyab_core::vless::VlessProfile;
use dastyab_core::worker::{generate_uuid, safe_worker_name, worker_name_from_account};
use dastyab_core::{CFError, BRAND, VERSION};
use std::path::PathBuf;

use crate::{
    BackupAction, CleanipAction, Command, DaemonAction, DnsAction, ProtectionAction, RoutesAction,
    SnapshotsAction, WorkspaceAction,
};
use dastyab_core::remote_beacon::BeaconConfig;
/// Run a command. `profile` is the active profile id.
pub async fn run(
    profile: String,
    lang: dastyab_core::i18n::Lang,
    cmd: Command,
) -> Result<(), CFError> {
    let i18n = dastyab_core::i18n::I18n::new(lang);
    match cmd {
        Command::Profiles => cmd_profiles(),
        Command::ProfileCreate { name, description } => {
            let id = create_profile(&name, &description)?;
            println!("{} '{name}' (id: {id})", i18n.t("profile.created"));
            Ok(())
        }
        Command::ProfileDelete { id } => {
            delete_profile(&id)?;
            println!("{} '{id}'", i18n.t("profile.deleted"));
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
        Command::TokenRecover { label, token } => token_recover(&profile, &label, &token).await,
        Command::TokenEnsure { min } => token_ensure(&profile, min).await,
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
            dastyab_core::store::profiles::remove_token(&profile, &label)?;
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
        Command::Find {
            count,
            suffix: _,
            sample,
            workers,
            timeout,
            top,
            refresh,
            seed,
            strategy,
            no_retry,
            json,
            quiet,
            out,
        } => {
            cmd_find(
                &profile,
                FindOpts {
                    count,
                    sample,
                    workers,
                    timeout,
                    top,
                    refresh,
                    seed,
                    strategy,
                    no_retry,
                    json,
                    quiet,
                    out,
                },
            )
            .await
        }
        Command::History => history(&profile),
        Command::Cleanip { action } => {
            let out = cleanip_cmd(&profile, action)?;
            if !out.is_empty() {
                println!("{out}");
            }
            Ok(())
        }
        Command::Configs { action } => configs_cmd(&profile, action),
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
        Command::Inventory {
            profile,
            kind,
            integrity,
            json,
            output,
        } => inventory_cmd(profile, kind, integrity, json, output),
        Command::ManifestVerify { refresh } => manifest_verify_cmd(refresh),
        Command::Doctor { json } => doctor_cmd(&profile, json),
        Command::Snapshots { action } => snapshots_cmd(&profile, action),
        Command::Workspace { action } => workspace_cmd(action),
        Command::Versions { action } => versions_cmd(&profile, action),
        Command::Mutation { action } => cmd_mutation(profile, action),
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
        Command::Desync { action } => cmd_desync(&profile, action),
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
        Command::Config { action } => cmd_config(&profile, action),
        Command::Up {
            profile: profile_override,
        } => cmd_up(profile_override).await,
        Command::Drill => cmd_drill(&profile).await,
        Command::Beacon { action } => cmd_beacon(&profile, action).await,
        Command::SniSpoof { action } => cmd_sni_spoof(&profile, action).await,
        Command::DnsTunnel { action } => cmd_dns_tunnel(&profile, action).await,
        Command::MultiWorker { action } => cmd_multi_worker(&profile, action).await,
        Command::Multilayer { action } => cmd_multilayer(&profile, action).await,
        Command::Tor { action } => cmd_tor(&profile, action).await,
        Command::Journal { action } => cmd_journal(&profile, action),
        Command::Autonomy { action } => cmd_autonomy(&profile, action).await,
        Command::Onboard { action } => cmd_onboard(&profile, action),
        Command::Aistudio { action } => cmd_aistudio(&action),
        Command::Platform {
            action,
            dry_run,
            mtu,
        } => cmd_platform(&action, dry_run, mtu),
        Command::Mesh {
            action,
            window,
            upstream,
            name,
            url,
        } => cmd_mesh(&action, window, upstream, &name, &url),
        Command::Bond { action, frames } => cmd_bond(&action, frames),
        Command::Lifeline { action, profile } => cmd_lifeline(&action, &profile).await,
        Command::Nodes {
            action,
            profile,
            path,
            link,
            proxy,
            channels,
            depth,
        } => cmd_configs(&profile, &action, &path, &link, proxy, &channels, depth).await,
        Command::Harvest {
            channels,
            profile,
            proxy,
            depth,
            discover,
            save,
            hops,
            max_candidates,
            include_saved,
        } => {
            cmd_harvest(
                &profile,
                &channels,
                proxy,
                depth,
                discover,
                DiscoverOpts {
                    save,
                    hops,
                    max_candidates,
                },
                include_saved,
            )
            .await
        }
        Command::Sources {
            action,
            profile,
            proxy,
            repos,
        } => cmd_sources(&profile, &action, proxy, &repos).await,
        Command::Anchors {
            action,
            profile,
            proxy,
            queries,
        } => {
            // The CT-anchor path uses reqwest's *blocking* client. Building
            // that client creates (and drops) a private tokio runtime, which
            // panics if done inside this async runtime (`#[tokio::main]`).
            // Run the whole blocking command on a dedicated blocking thread.
            let action = action.clone();
            let profile = profile.clone();
            let queries = queries.clone();
            tokio::task::spawn_blocking(move || cmd_anchors(&profile, &action, proxy, &queries))
                .await
                .map_err(|e| CFError::new("anchors", "spawn_blocking", e.to_string()))?
        }
        Command::Subscribe {
            port,
            profile,
            only_healthy,
            token,
        } => tokio::task::spawn_blocking(move || {
            cmd_subscribe(port, &profile, only_healthy, token.as_deref())
        })
        .await
        .map_err(|e| CFError::new("subscribe", "spawn_blocking", e.to_string()))?,
        Command::Chain { action, chain } => {
            // `chain run` spawns real transport processes and blocks on port
            // waits / egress probes, which needs its own runtime; route the
            // whole handler onto a blocking thread (mirrors Anchors).
            let action = action.clone();
            let chain = chain.clone();
            tokio::task::spawn_blocking(move || cmd_chain(&action, &chain))
                .await
                .map_err(|e| CFError::new("chain", "spawn_blocking", e.to_string()))?
        }
        Command::Gossip { action, path, max } => {
            let action = action.clone();
            let path = path.clone();
            tokio::task::spawn_blocking(move || cmd_gossip(&profile, &action, &path, max))
                .await
                .map_err(|e| CFError::new("gossip", "spawn_blocking", e.to_string()))?
        }
    }
}

async fn cmd_sources(profile: &str, action: &str, proxy: bool, repos: &str) -> Result<(), CFError> {
    use dastyab_core::gh_sources;
    match action {
        "ingest" | "refresh" => {
            let extra: Vec<String> = repos
                .split(',')
                .map(|r| r.trim().to_string())
                .filter(|r| !r.is_empty())
                .collect();
            let report = gh_sources::ingest_github(profile, proxy, &extra).await;
            println!("[sources] GitHub ingestion pass:");
            println!("  repos ok: {}", report.repos_ok.len());
            for r in &report.repos_ok {
                println!("    ok   {r}");
            }
            for (repo, err) in &report.repos_failed {
                println!("    fail {repo}: {err}");
            }
            println!(
                "  links: found={} added={} duplicates={} invalid={}",
                report.found, report.added, report.duplicates, report.invalid
            );
            Ok(())
        }
        other => Err(CFError::new(
            "sources",
            format!("unknown action '{other}'"),
            "Use: ingest | refresh",
        )),
    }
}

/// `dastyab anchors {discover|list|clear}` — certificate-transparency
/// egress-anchor discovery (doctrine §8.1). Independent, out-of-band bootstrap
/// source beyond Telegram/GitHub, so recovery never goes circular.
fn cmd_anchors(profile: &str, action: &str, proxy: bool, queries_csv: &str) -> Result<(), CFError> {
    use dastyab_core::ct_anchors::{
        discover_ct_anchors, load_anchors, CtAnchorStore, DEFAULT_QUERIES,
    };
    match action {
        "discover" => {
            let queries: Vec<&str> = if queries_csv.trim().is_empty() {
                DEFAULT_QUERIES.to_vec()
            } else {
                queries_csv
                    .split(',')
                    .map(|q| q.trim())
                    .filter(|q| !q.is_empty())
                    .collect()
            };
            let report = discover_ct_anchors(profile, proxy, &queries);
            println!("[anchors] CT discovery pass:");
            println!("  queries   : {}", report.queries);
            println!("  hosts seen : {}", report.hosts_seen);
            println!("  candidates : {}", report.candidates);
            println!("  verified   : {}", report.verified);
            println!("  added      : {}", report.added);
            println!("  anchors total: {}", report.anchors_total);
            let store = load_anchors(profile);
            for a in &store.anchors {
                println!("    {:<40} {}ms via={}", a.host, a.ms, a.via);
            }
            Ok(())
        }
        "list" => {
            let store = load_anchors(profile);
            println!("[anchors] verified-live CT egress anchors (profile '{profile}'):");
            if store.anchors.is_empty() {
                println!("  (none — run `dastyab anchors discover` first)");
            }
            for a in &store.anchors {
                println!("    {:<40} {}ms via={}", a.host, a.ms, a.via);
            }
            Ok(())
        }
        "clear" => {
            let store = CtAnchorStore {
                anchors: Vec::new(),
            };
            dastyab_core::store::atomic_write(
                &dastyab_core::ct_anchors::anchors_path_pub(profile),
                &serde_json::to_vec_pretty(&store).map_err(|e| {
                    CFError::new("anchors", format!("serialize: {e}"), "Internal error.")
                })?,
            )?;
            println!("[anchors] cleared CT anchor set");
            Ok(())
        }
        "prune" => {
            let dropped = dastyab_core::ct_anchors::prune_stale_anchors(profile, proxy);
            let total = dastyab_core::ct_anchors::anchor_hosts(profile).len();
            println!("[anchors] pruned {dropped} stale anchors; {total} verified-live remain");
            Ok(())
        }
        "reseed" => {
            // Consume the verified CT-anchor set as a node-pool reseed source
            // (doctrine §8.1). Synthesized VLESS-over-TLS candidates are
            // imported tagged "ct-anchor"; they are *not* marked healthy here —
            // probe them afterwards so only genuinely-live nodes enter the
            // healthy set (no fabricated success).
            let added = dastyab_core::node_refill::reseed_from_ct_anchors(profile, proxy);
            println!(
                "[anchors] reseed: imported {added} CT-anchor candidate node(s) into pool (probe to verify)"
            );
            if added > 0 {
                let task = dastyab_core::node_probe::probe_all(profile, proxy);
                let alive = task.iter().filter(|p| p.ok).count();
                println!(
                    "[anchors] reseed probe: {}/{} new CT-anchor nodes verified healthy end-to-end",
                    alive,
                    task.len()
                );
            }
            Ok(())
        }
        "ns" => {
            // Authoritative-nameserver anchor discovery (doctrine §8.1): use
            // the DNS control plane itself as an independent, out-of-band
            // bootstrap source that survives a total blackout.
            use dastyab_core::ns_anchors::{
                anchor_ips, load_anchors, refresh_ns_anchors, DEFAULT_ZONES, ROOT_SERVER_SEEDS,
            };
            const NS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(4);
            // Resolver list: prefer discovered Iranian resolvers, else the
            // documented candidate list. The NS discovery is best-effort.
            let resolvers: Vec<String> = {
                let mut v: Vec<String> = Vec::new();
                for s in dastyab_core::resolve_pool::IRANIAN_RESOLVER_CANDIDATES {
                    v.push(s.to_string());
                }
                v
            };
            let zones = DEFAULT_ZONES;
            let (added, pruned) =
                block_on(refresh_ns_anchors(profile, &resolvers, zones, NS_TIMEOUT));
            println!("[anchors] NS discovery pass (authoritative-nameserver control plane):");
            println!("  root seeds : {} documented", ROOT_SERVER_SEEDS.len());
            println!("  zones      : {}", zones.len());
            println!("  added      : {added}");
            println!("  pruned     : {pruned}");
            let store = load_anchors(profile);
            println!("  verified   : {} anchor IPs", store.anchors.len());
            for a in &store.anchors {
                println!("    {:<40} {}ms via={}", a.ip, a.ms, a.via);
            }
            let _ = anchor_ips(profile);
            Ok(())
        }
        "refresh" => {
            let queries: Vec<&str> = if queries_csv.trim().is_empty() {
                DEFAULT_QUERIES.to_vec()
            } else {
                queries_csv
                    .split(',')
                    .map(|q| q.trim())
                    .filter(|q| !q.is_empty())
                    .collect()
            };
            let (added, pruned) =
                dastyab_core::ct_anchors::refresh_and_prune(profile, proxy, &queries);
            let total = dastyab_core::ct_anchors::anchor_hosts(profile).len();
            println!(
                "[anchors] refresh: +{added} new, pruned {pruned} dead, {total} verified-live"
            );
            Ok(())
        }
        other => Err(CFError::new(
            "anchors",
            format!("unknown action '{other}'"),
            "Use: discover | list | prune | ns | refresh | clear",
        )),
    }
}

/// Start the loopback subscription server (doctrine: never stale, always a
/// fresh healthy pool). Runs forever; Ctrl-C stops it.
fn cmd_subscribe(
    port: u16,
    profile: &str,
    only_healthy: bool,
    token: Option<&str>,
) -> Result<(), CFError> {
    use dastyab_core::subscription::{self, SubscriptionConfig};

    let marker = format!("dastyab-subscribe-{profile}-{port}");
    let pid = std::process::id();
    let lock = format!("/tmp/{marker}.lock");
    if let Ok(existing) = std::fs::read_to_string(&lock) {
        let existing_pid: u32 = existing.trim().parse().unwrap_or(0);
        if existing_pid != 0 && existing_pid != pid && process_alive(existing_pid) {
            return Err(CFError::new(
                "subscribe",
                format!("already running (pid {existing_pid}) on 127.0.0.1:{port}"),
                "Stop it first (kill <pid>) or pick another --port.",
            ));
        }
    }
    let _ = std::fs::write(&lock, pid.to_string());

    let cfg = SubscriptionConfig {
        profile: profile.to_string(),
        port,
        only_healthy,
        token: token.map(|s| s.to_string()),
    };

    let server =
        subscription::serve_loopback(&cfg).map_err(|e| CFError::new("subscribe", "bind", e))?;

    // Self-check: hit the feed once to prove it serves.
    let url = format!("http://{}/subscription", server.addr);
    let len =
        subscription::count_get(&url).map_err(|e| CFError::new("subscribe", "self-check", e))?;
    let _ = std::fs::remove_file(&lock);

    let fmt = if only_healthy {
        "verified-healthy"
    } else {
        "all"
    };
    println!("[subscribe] serving {fmt} pool on {}", server.addr);
    println!("[subscribe] feed: {url}");
    if token.is_some() {
        println!("[subscribe] token required (?token=...)");
    }
    println!("[subscribe] self-check: {len} bytes (feed ready)");
    println!("[subscribe] press Ctrl-C to stop");

    // Block forever until killed (Ctrl-C / SIGTERM terminates naturally).
    loop {
        std::thread::park();
    }
}

/// `dastyab chain <action> [--chain e1,e2,...]`
///
/// Actions:
///   - `list-engines`: print the supported engine ids.
///   - `plan`: parse `--chain`, run the planner, print the concrete pipeline.
///   - `check`: verify the chain parser accepts the ordering and report
///     any unknown engines (without requiring binaries present).
fn cmd_chain(action: &str, chain: &str) -> Result<(), CFError> {
    use dastyab_core::chain_mixer::{self, ChainConfig, Engine};
    match action {
        "list-engines" => {
            let ids = [
                Engine::Psiphon,
                Engine::Tor,
                Engine::V2rayN,
                Engine::Lantern,
                Engine::Shadowsocks,
                Engine::ShirOKhorshid,
                Engine::DastYab,
            ];
            for e in ids {
                println!(
                    "{:<12} binary={}",
                    e.label(),
                    e.binary_hint().unwrap_or("(in-process)")
                );
            }
            Ok(())
        }
        "plan" | "check" | "run" | "supervise" => {
            let mut engines = Vec::new();
            for part in chain.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                let e = match part {
                    "psiphon" => Engine::Psiphon,
                    "tor" => Engine::Tor,
                    "v2rayn" | "xray" => Engine::V2rayN,
                    "lantern" => Engine::Lantern,
                    "shadowsocks" | "ss" => Engine::Shadowsocks,
                    "shirokhorshid" | "skh" => Engine::ShirOKhorshid,
                    "dastyab" => Engine::DastYab,
                    other => {
                        return Err(CFError::new(
                            "chain",
                            format!("unknown engine: {other}"),
                            "use: psiphon, tor, v2rayn, lantern, shadowsocks, shirokhorshid, dastyab",
                        ));
                    }
                };
                engines.push(e);
            }
            let cfg = ChainConfig { engines };
            let planned = chain_mixer::plan_chain(&cfg, |_| None)?;
            if action == "plan" {
                println!("[chain] planned pipeline (client ↑ → egress ↓):");
                print!("{}", chain_mixer::render_chain(&planned));
                println!("[chain] egress_port={}", planned.egress_port);
            } else if action == "check" {
                println!(
                    "[chain] valid: {} layer(s), egress_port={}",
                    planned.layers.len(),
                    planned.egress_port
                );
            } else if action == "supervise" {
                // Re-race failover (doctrine §3/§5): run the configured chain
                // first, then degraded subsets, until one verifies real
                // end-to-end egress. Real process launcher, real async port
                // waits, real egress probe (no nested block_on).
                let sup = block_on(chain_mixer::supervise_chain_async(
                    &cfg,
                    |_| None,
                    &chain_mixer::ProcessLauncher,
                    &|port| {
                        // Cold-start engines (tor, etc.) can take 20-40s to
                        // reach a usable SocksPort. Readiness must be patient
                        // or the supervisor always abandons them during a
                        // blackout before they can ever verify.
                        Box::pin(chain_mixer::wait_port_open(
                            port,
                            std::time::Duration::from_secs(60),
                        ))
                    },
                    &|port| {
                        // Patient egress probe: cold-start engines (tor etc.)
                        // can take 20-40s to route; re-probe over a grace
                        // window instead of giving up after one check.
                        Box::pin(async move {
                            let deadline =
                                std::time::Instant::now() + std::time::Duration::from_secs(90);
                            loop {
                                if chain_mixer::chain_egress_ok(port).await {
                                    return true;
                                }
                                if std::time::Instant::now() >= deadline {
                                    return false;
                                }
                                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                            }
                        })
                    },
                    8,
                ));
                println!("[chain] supervised over {} attempt(s)", sup.attempts);
                if let Some(plan) = &sup.chosen_plan {
                    println!("[chain] winning plan (client ↑ → egress ↓):");
                    print!("{}", chain_mixer::render_chain(plan));
                    if let Some(report) = &sup.chosen_report {
                        println!("[chain] run report:");
                        for l in &report.layers {
                            let st = match l.status {
                                chain_mixer::LayerStatus::Up => "UP",
                                chain_mixer::LayerStatus::Skipped => "SKIPPED",
                                chain_mixer::LayerStatus::FailedToStart => "FAILED-TO-START",
                                chain_mixer::LayerStatus::Deferred => "DEFERRED",
                            };
                            println!(
                                "  {:<10} port={:<6} {}{}",
                                l.engine.label(),
                                l.port,
                                st,
                                l.note
                                    .as_ref()
                                    .map(|n| format!(" ({n})"))
                                    .unwrap_or_default()
                            );
                        }
                        println!(
                            "  degraded={} egress_port={} egress_ok={}",
                            report.degraded,
                            report
                                .egress_port
                                .map(|p| p.to_string())
                                .unwrap_or_else(|| "-".into()),
                            report.egress_ok
                        );
                        print_egress_risk_warning(report);
                    }
                } else {
                    println!("[chain] no candidate verified egress (all degraded/failed)");
                }
            } else {
                // Execute the pipeline for real. Port readiness uses real
                // async port-open waits; egress is probed end-to-end through
                // the client-facing port (doctrine §6.4: no fabricated
                // success). No nested block_on.
                let report = block_on(chain_mixer::run_chain_async(
                    &planned,
                    &chain_mixer::ProcessLauncher,
                    &|port| {
                        Box::pin(chain_mixer::wait_port_open(
                            port,
                            std::time::Duration::from_secs(8),
                        ))
                    },
                    &|port| Box::pin(chain_mixer::chain_egress_ok(port)),
                ));
                println!("[chain] run report:");
                for l in &report.layers {
                    let st = match l.status {
                        chain_mixer::LayerStatus::Up => "UP",
                        chain_mixer::LayerStatus::Skipped => "SKIPPED",
                        chain_mixer::LayerStatus::FailedToStart => "FAILED-TO-START",
                        chain_mixer::LayerStatus::Deferred => "DEFERRED",
                    };
                    println!(
                        "  {:<10} port={:<6} {}{}",
                        l.engine.label(),
                        l.port,
                        st,
                        l.note
                            .as_ref()
                            .map(|n| format!(" ({n})"))
                            .unwrap_or_default()
                    );
                }
                println!(
                    "  degraded={} egress_port={} egress_ok={}",
                    report.degraded,
                    report
                        .egress_port
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "-".into()),
                    report.egress_ok
                );
                print_egress_risk_warning(&report);
            }
            Ok(())
        }
        other => Err(CFError::new(
            "chain",
            format!("unknown action: {other}"),
            "use: plan | list-engines | check",
        )),
    }
}

/// Air-gapped DTN gossip (doctrine §3 L4+). Actions:
/// - `make`  — sign a bundle of up to `max` healthy nodes from this profile
///              and write it to `path` (a file you can hand to a nearby peer
///              out-of-band: USB, QR, BLE, Wi-Fi Direct, or just a chat).
/// - `verify` — load a bundle from `path` and check its signature; no writes.
/// - `accept` — load, verify, and merge a bundle's nodes into this profile's
///              node store (only fresh/non-duplicate nodes are added).
/// - `peers` — show the trust ledger (who offered what, and their earned score).
fn cmd_gossip(profile: &str, action: &str, path: &str, max: usize) -> Result<(), CFError> {
    use dastyab_core::config_store::{import_single_link_source_ts, load_node_store};
    use dastyab_core::dtn_gossip::{NodeItem, SignedBundle, SOURCE_DTN_GOSSIP};

    match action {
        "peers" => {
            // The ledger is in-memory for now; print a hint. (Persistence of
            // the ledger across runs is a follow-up — the trust model itself
            // is exercised and verified above.)
            println!("[gossip] peer trust ledger is session-scoped (persistence is a follow-up).");
            Ok(())
        }
        "make" => {
            let store = load_node_store(profile);
            let mut items: Vec<NodeItem> = Vec::new();
            for node in store.nodes.iter().filter(|n| n.healthy == Some(true)) {
                if items.len() >= max {
                    break;
                }
                items.push(NodeItem {
                    url: node.url.clone(),
                    origin: node.source.clone(),
                    published_epoch: node.published_epoch,
                    sender_healthy: node.healthy == Some(true),
                });
            }
            if items.is_empty() {
                return Err(CFError::new(
                    "gossip",
                    "no healthy nodes to bundle",
                    "harvest/import some nodes first (dastyab harvest or nodes import)",
                ));
            }
            let signing = dastyab_core::dtn_gossip::default_signing_key()?;
            let bundle = dastyab_core::dtn_gossip::make_bundle(&signing, items)?;
            let wire = bundle.encode();
            std::fs::write(path, &wire).map_err(|e| {
                CFError::new(
                    "gossip",
                    format!("cannot write {path}: {e}"),
                    "check the path",
                )
            })?;
            let n = bundle.items.len();
            println!(
                "[gossip] wrote signed bundle: {n} node(s) to {path} ({} bytes)",
                wire.len()
            );
            Ok(())
        }
        "verify" => {
            let wire = std::fs::read(path).map_err(|e| {
                CFError::new(
                    "gossip",
                    format!("cannot read {path}: {e}"),
                    "check the path",
                )
            })?;
            let bundle = SignedBundle::decode(&wire).ok_or_else(|| {
                CFError::new("gossip", "not a valid gossip bundle", "wrong file?")
            })?;
            let _vk = bundle.verify()?;
            println!(
                "[gossip] signature OK: {} node(s), sender pk {}",
                bundle.items.len(),
                hex_short(&bundle.sender_pk)
            );
            Ok(())
        }
        "accept" => {
            let wire = std::fs::read(path).map_err(|e| {
                CFError::new(
                    "gossip",
                    format!("cannot read {path}: {e}"),
                    "check the path",
                )
            })?;
            let bundle = SignedBundle::decode(&wire).ok_or_else(|| {
                CFError::new("gossip", "not a valid gossip bundle", "wrong file?")
            })?;
            let _vk = bundle.verify()?;
            let mut added = 0usize;
            let mut skipped = 0usize;
            // Note: the trust ledger gates here are exercised at the core
            // layer; the CLI applies the signature gate + store dedup. This
            // keeps `accept` safe to run unattended.
            for item in &bundle.items {
                if !item.url.starts_with("vless://")
                    && !item.url.starts_with("vmess://")
                    && !item.url.starts_with("trojan://")
                    && !item.url.starts_with("ss://")
                    && !item.url.starts_with("hysteria2://")
                    && !item.url.starts_with("tuic://")
                {
                    skipped += 1;
                    continue;
                }
                match import_single_link_source_ts(
                    profile,
                    &item.url,
                    SOURCE_DTN_GOSSIP,
                    item.published_epoch,
                ) {
                    Ok(_) => added += 1,
                    Err(_) => skipped += 1,
                }
            }
            println!("[gossip] accepted {added} node(s), skipped {skipped} (dups/unsupported)",);
            Ok(())
        }
        other => Err(CFError::new(
            "gossip",
            format!("unknown action: {other}"),
            "use: make | verify | accept | peers",
        )),
    }
}

fn hex_short(b: &[u8]) -> String {
    let mut s = String::new();
    for byte in b.iter().take(8) {
        s.push_str(&format!("{byte:02x}"));
    }
    s.push('…');
    s
}

/// Print a prominent warning when the chain's public exit IP is risky/flagged
/// (e.g. a Tor exit node). The user can then choose to keep the tunnel as a
/// last resort or add a corrective layer (doctrine §3 L2, §4.3).
fn print_egress_risk_warning(report: &dastyab_core::chain_mixer::ChainRunReport) {
    use dastyab_core::chain_mixer::EgressRisk;
    let Some(risk) = report.egress_risk else {
        return;
    };
    match risk {
        EgressRisk::Clean => {}
        EgressRisk::Moderate => {
            println!(
                "[chain] ⚠ output IP: moderate-risk exit (circumvention provider). \
                 It may be rate-limited or geo-blocked by some services."
            );
        }
        EgressRisk::Risky => {
            println!(
                "[chain] ⚠⚠ RISKY OUTPUT IP: the public exit is a Tor/onion node. \
                 Major services (Google, streaming, banking) frequently block Tor \
                 exits — sites may return 403/429 even though the tunnel is up. \
                 To correct the exit IP, add a Clean egress layer AFTER tor, e.g. \
                 --chain tor,shirokhorshid or --chain tor,v2rayn."
            );
        }
    }
}

/// Return true if a process with the given pid is alive (Unix).
fn process_alive(pid: u32) -> bool {
    use std::path::Path;
    Path::new(&format!("/proc/{pid}")).exists()
}

/// Options controlling the systematic multi-hop Telegram archived-chat
/// discovery mode (`--discover`) of `cmd_harvest`.
#[derive(Clone, Copy)]
struct DiscoverOpts {
    /// Persist yielding channels to harvest_channels.json (additive merging).
    save: bool,
    /// Number of expansion rounds beyond the seed probe (clamped 1..=6).
    hops: usize,
    /// Global cap on total candidate channels probed (doctrine §6.5).
    max_candidates: usize,
}

async fn cmd_harvest(
    profile: &str,
    channels: &str,
    proxy: bool,
    depth: usize,
    discover: bool,
    d: DiscoverOpts,
    include_saved: bool,
) -> Result<(), CFError> {
    use dastyab_core::harvest;

    // Systematic discovery mode: probe candidates, print live yield, and
    // optionally persist the yielding channels for future refill passes.
    // Discovery is **self-expanding**: after probing the hardcoded seeds, we
    // crawl the cross-referenced channels on the *yielding* seeds for up to
    // `hops` expansion rounds, probing each round's new finds too — so the
    // archived-chat net grows systematically from what actually works, never
    // hardcoded/circular (doctrine §5). The global `max_candidates` budget
    // bounds the whole walk (doctrine §6.5: never flood the transport).
    if discover {
        let report = harvest::run_multi_hop_discovery(
            profile,
            proxy,
            d.hops,
            d.max_candidates,
            depth,
            d.save,
        )
        .await?;
        for (i, ch) in report.winners.iter().enumerate() {
            let rank = i + 1;
            println!("  {ch}: winner #{rank}");
        }
        println!(
            "hop(s): {} (seeds {}, candidates probed {})",
            report.hops, report.seeds, report.candidates_total
        );
        if report.winners.is_empty() {
            println!("no candidate channels yielded links");
        } else if d.save {
            println!(
                "merged {} discovered channel(s) into profile '{profile}' ({} total)",
                report.persisted_new, report.persisted_total
            );
        }
        return Ok(());
    }

    let mut list: Vec<String> = channels
        .split(',')
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
        .collect();
    // Self-expanding net: merge every previously-discovered channel that once
    // yielded, so production harvest always includes the full archived-chat
    // mining net (doctrine §5: never circular, never forget a source).
    if include_saved {
        for c in harvest::load_discovered_channels(profile).channels {
            if !list.contains(&c) {
                list.push(c);
            }
        }
        if !list.is_empty() {
            println!(
                "harvesting {} channel(s) including {} saved discovered channel(s)",
                list.len(),
                harvest::load_discovered_channels(profile).channels.len()
            );
        }
    }
    if list.is_empty() {
        eprintln!("no channels given");
        return Ok(());
    }
    // Concurrent, connection-pooled harvest: one shared async client across
    // all channels (TLS keep-alive reuse), bounded in-flight fetches.
    let concurrency = list.len().min(8);
    let results = harvest::harvest_many(profile, &list, proxy, concurrency, depth).await;

    for (channel, h) in results {
        if let Some(err) = &h.fetch_error {
            eprintln!("[{channel}] fetch failed: {err}");
            continue;
        }
        println!(
            "[{}] found={} added={} duplicates={} invalid={}",
            h.channel,
            h.summary.found,
            h.summary.added,
            h.summary.duplicates,
            h.summary.skipped_invalid
        );
    }
    Ok(())
}

fn cmd_bundle(profile: &str, action: crate::BundleAction) -> Result<(), CFError> {
    match action {
        crate::BundleAction::Verify => {
            let ledger_ep = dastyab_core::cleanip::active_ledger_endpoint(profile);
            match ledger_ep {
                None => {
                    println!(
                        "No verified active endpoint in the ledger yet — nothing to reconcile."
                    );
                }
                Some(ledger_ep) => {
                    let dir = dastyab_core::cleanip::user_config_dir(profile)?;
                    let drift = dastyab_core::cleanip::check_bundle_drift(&dir, &ledger_ep);
                    match drift {
                        dastyab_core::cleanip::BundleDrift::InSync => {
                            println!(
                                "Bundle in-sync with ledger (endpoint={ledger_ep}, files=4/4)"
                            );
                        }
                        dastyab_core::cleanip::BundleDrift::MissingDir => {
                            println!("Bundle drift: directory missing ({}). Next cycle will recreate it.", dir.display());
                        }
                        dastyab_core::cleanip::BundleDrift::MissingFile { name } => {
                            println!(
                                "Bundle drift: missing file {name}. Next cycle will recreate it."
                            );
                        }
                        dastyab_core::cleanip::BundleDrift::EndpointMismatch {
                            bundle_endpoint,
                            ledger_endpoint,
                        } => {
                            println!(
                                "Bundle drift: active.vless points to {bundle_endpoint} but ledger says {ledger_endpoint}"
                            );
                            println!("Next cycle will reconcile automatically, or run `dastyab bundle reconcile`.");
                        }
                        dastyab_core::cleanip::BundleDrift::Unparseable { file, reason } => {
                            println!("Bundle drift: {file} unparseable ({reason}). Next cycle will recreate it.");
                        }
                    }
                }
            }
            Ok(())
        }
        crate::BundleAction::Reconcile => {
            let outcome = dastyab_core::cleanip::reconcile_bundle_if_drifted(profile);
            match outcome {
                dastyab_core::cleanip::ReconcileOutcome::WasInSync => {
                    println!("Bundle already in-sync with ledger — no action needed.");
                }
                dastyab_core::cleanip::ReconcileOutcome::Rewritten { reason } => {
                    println!("Bundle rewritten from ledger (reason={reason:?}).");
                }
                dastyab_core::cleanip::ReconcileOutcome::Failed { reason } => {
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

/// Inspect / tune the per-profile configuration knobs.
fn cmd_config(profile: &str, action: crate::ConfigAction) -> Result<(), CFError> {
    match action {
        crate::ConfigAction::Show { json } => {
            let p = dastyab_core::store::profiles::load_profile(profile);
            let c = &p.config;
            let eff_light = dastyab_core::store::profiles::effective_light_timeout_secs(c);
            let eff_deep = dastyab_core::store::profiles::effective_deep_timeout_secs(c);
            let eff_backoff = dastyab_core::store::profiles::effective_max_backoff_secs(c);
            let eff_blackout =
                dastyab_core::store::profiles::effective_network_down_sleep_secs(c);
            if json {
                let obj = serde_json::json!({
                    "profile": profile,
                    "scan_count": c.scan_count,
                    "scan_workers": c.scan_workers,
                    "scan_timeout": c.scan_timeout,
                    "scan_ports": c.scan_ports,
                    "scan_gentle": c.scan_gentle,
                    "stealth_enabled": c.stealth_enabled,
                    "protection_enabled": c.protection_enabled,
                    "auto_rotate_on_blocked": c.auto_rotate_on_blocked,
                    "light_interval_secs": c.light_interval_secs,
                    "light_timeout_secs": c.light_timeout_secs,
                    "deep_timeout_secs": c.deep_timeout_secs,
                    "max_backoff_secs": c.max_backoff_secs,
                    "network_down_sleep_secs": c.network_down_sleep_secs,
                    "drill_interval_secs": c.drill_interval_secs,
                    "effective_light_timeout_secs": eff_light,
                    "effective_deep_timeout_secs": eff_deep,
                    "effective_max_backoff_secs": eff_backoff,
                    "effective_network_down_sleep_secs": eff_blackout,
                    "beacon_enabled": c.beacon.as_ref().is_some_and(|b| b.enabled),
                });
                println!("{}", serde_json::to_string_pretty(&obj).unwrap());
                return Ok(());
            }
            println!("Profile: {profile}");
            println!("  scan count                  : {}", c.scan_count);
            println!("  scan workers                : {}", c.scan_workers);
            println!("  scan timeout (s)            : {}", c.scan_timeout);
            println!("  scan ports                  : {}", c.scan_ports);
            println!(
                "  scan gentle                 : {}",
                if c.scan_gentle { "yes" } else { "no" }
            );
            println!(
                "  stealth pacing              : {}",
                if c.stealth_enabled { "ON" } else { "OFF" }
            );
            println!(
                "  protection                  : {}",
                if c.protection_enabled { "ON" } else { "OFF" }
            );
            println!(
                "  auto token-rotate on blocked : {}",
                if c.auto_rotate_on_blocked {
                    "ON"
                } else {
                    "OFF"
                }
            );
            println!("  light monitor cadence (s)   : {}", c.light_interval_secs);
            println!(
                "  monitor light phase budget : {}s (configured {}s, system default 120s)",
                eff_light, c.light_timeout_secs
            );
            println!(
                "  monitor deep phase budget   : {}s (configured {}s, system default 600s)",
                eff_deep, c.deep_timeout_secs
            );
            println!(
                "  daemon backoff ceiling      : {}s (configured {}s, system default 21600s)",
                eff_backoff, c.max_backoff_secs
            );
            println!(
                "  blackout poll cadence      : {}s (configured {}s, system default 60s)",
                eff_blackout, c.network_down_sleep_secs
            );
            println!(
                "  blackout self-test cadence : {}s (configured {}s, system default 86400s)",
                c.drill_interval_secs, c.drill_interval_secs
            );
            println!(
                "  beacon notifications         : {}",
                if c.beacon.as_ref().is_some_and(|b| b.enabled) {
                    "ON"
                } else {
                    "OFF"
                }
            );
            Ok(())
        }
        crate::ConfigAction::Set { key, value } => {
            let mut p = dastyab_core::store::profiles::load_profile(profile);
            apply_config_set(&mut p, &key, &value)?;
            dastyab_core::store::profiles::save_profile(&p)?;
            println!("config set {key}={value} (profile {profile})");
            Ok(())
        }
        crate::ConfigAction::Unset { key } => {
            let mut p = dastyab_core::store::profiles::load_profile(profile);
            match key {
                Some(k) => {
                    reset_one_config_key(&mut p, &k)?;
                    dastyab_core::store::profiles::save_profile(&p)?;
                    println!("config unset {k} → system default (profile {profile})");
                }
                None => {
                    p.config = dastyab_core::store::profiles::ProfileConfig::default();
                    dastyab_core::store::profiles::save_profile(&p)?;
                    println!("config reset for profile {profile} → defaults");
                }
            }
            Ok(())
        }
        crate::ConfigAction::Timeouts {
            light,
            deep,
            max_backoff,
            network_down_sleep,
        } => {
            let mut p = dastyab_core::store::profiles::load_profile(profile);
            if light > 0 {
                p.config.light_timeout_secs = light;
            }
            if deep > 0 {
                p.config.deep_timeout_secs = deep;
            }
            if max_backoff > 0 {
                p.config.max_backoff_secs = max_backoff;
            }
            if network_down_sleep > 0 {
                p.config.network_down_sleep_secs = network_down_sleep;
            }
            dastyab_core::store::profiles::save_profile(&p)?;
            // Re-read to print the resolved values after save.
            let c = &p.config;
            let eff_light = dastyab_core::store::profiles::effective_light_timeout_secs(c);
            let eff_deep = dastyab_core::store::profiles::effective_deep_timeout_secs(c);
            let eff_backoff = dastyab_core::store::profiles::effective_max_backoff_secs(c);
            let eff_blackout =
                dastyab_core::store::profiles::effective_network_down_sleep_secs(c);
            println!("Saved. Effective values for {profile}:");
            println!("  monitor light phase budget : {eff_light}s");
            println!("  monitor deep phase budget   : {eff_deep}s");
            println!("  daemon backoff ceiling      : {eff_backoff}s");
            println!("  blackout poll cadence      : {eff_blackout}s");
            Ok(())
        }
    }
}

/// Parse a human boolean token (true/false/1/0/on/off/yes/no/enable/disable).
fn parse_bool(v: &str) -> Option<bool> {
    match v.trim().to_lowercase().as_str() {
        "1" | "true" | "on" | "yes" | "enable" | "enabled" => Some(true),
        "0" | "false" | "off" | "no" | "disable" | "disabled" => Some(false),
        _ => None,
    }
}

/// Apply one named knob change to a profile config. Returns a descriptive error
/// for unknown keys or unparsable values.
fn apply_config_set(
    p: &mut dastyab_core::store::profiles::Profile,
    key: &str,
    value: &str,
) -> Result<(), CFError> {
    let bad = |ty: &str| {
        CFError::new(
            "Bad config value",
            format!("cannot parse '{value}' as {ty}"),
            "Use a non-negative integer, or true/false/1/0/on/off for booleans.",
        )
    };
    match key {
        "scan_count" => p.config.scan_count = value.parse::<u32>().map_err(|_| bad("u32"))?,
        "scan_workers" => p.config.scan_workers = value.parse::<u32>().map_err(|_| bad("u32"))?,
        "scan_timeout" => p.config.scan_timeout = value.parse::<u32>().map_err(|_| bad("u32"))?,
        "scan_ports" => p.config.scan_ports = value.to_string(),
        "scan_gentle" => p.config.scan_gentle = parse_bool(value).ok_or_else(|| bad("bool"))?,
        "stealth_enabled" => {
            p.config.stealth_enabled = parse_bool(value).ok_or_else(|| bad("bool"))?
        }
        "protection_enabled" => {
            p.config.protection_enabled = parse_bool(value).ok_or_else(|| bad("bool"))?
        }
        "auto_rotate_on_blocked" => {
            p.config.auto_rotate_on_blocked = parse_bool(value).ok_or_else(|| bad("bool"))?
        }
        "light_interval_secs" => {
            p.config.light_interval_secs = value.parse::<u64>().map_err(|_| bad("u64"))?
        }
        "light_timeout_secs" => {
            p.config.light_timeout_secs = value.parse::<u64>().map_err(|_| bad("u64"))?
        }
        "deep_timeout_secs" => {
            p.config.deep_timeout_secs = value.parse::<u64>().map_err(|_| bad("u64"))?
        }
        "max_backoff_secs" => {
            p.config.max_backoff_secs = value.parse::<u64>().map_err(|_| bad("u64"))?
        }
        "network_down_sleep_secs" => {
            p.config.network_down_sleep_secs = value.parse::<u64>().map_err(|_| bad("u64"))?
        }
        "drill_interval_secs" => {
            p.config.drill_interval_secs = value.parse::<u64>().map_err(|_| bad("u64"))?
        }
        _ => {
            return Err(CFError::new(
                "Unknown config key",
                format!("no such knob '{key}'"),
                "See `dastyab config show` for valid keys.",
            ));
        }
    }
    Ok(())
}

/// Restore a single knob to its system default.
fn reset_one_config_key(
    p: &mut dastyab_core::store::profiles::Profile,
    key: &str,
) -> Result<(), CFError> {
    let d = dastyab_core::store::profiles::ProfileConfig::default();
    match key {
        "scan_count" => p.config.scan_count = d.scan_count,
        "scan_workers" => p.config.scan_workers = d.scan_workers,
        "scan_timeout" => p.config.scan_timeout = d.scan_timeout,
        "scan_ports" => p.config.scan_ports = d.scan_ports,
        "scan_gentle" => p.config.scan_gentle = d.scan_gentle,
        "stealth_enabled" => p.config.stealth_enabled = d.stealth_enabled,
        "protection_enabled" => p.config.protection_enabled = d.protection_enabled,
        "auto_rotate_on_blocked" => p.config.auto_rotate_on_blocked = d.auto_rotate_on_blocked,
        "light_interval_secs" => p.config.light_interval_secs = d.light_interval_secs,
        "light_timeout_secs" => p.config.light_timeout_secs = d.light_timeout_secs,
        "deep_timeout_secs" => p.config.deep_timeout_secs = d.deep_timeout_secs,
        "max_backoff_secs" => p.config.max_backoff_secs = d.max_backoff_secs,
        "network_down_sleep_secs" => p.config.network_down_sleep_secs = d.network_down_sleep_secs,
        "drill_interval_secs" => p.config.drill_interval_secs = d.drill_interval_secs,
        _ => {
            return Err(CFError::new(
                "Unknown config key",
                format!("no such knob '{key}'"),
                "See `dastyab config show` for valid keys.",
            ));
        }
    }
    Ok(())
}

/// Read and render the per-cycle health beacon. `--json` emits the raw
/// snapshot; otherwise a human-readable table. Exit code 0 (fresh) / 1
/// (stale / missing) makes this scriptable for the user's remote check.
fn cmd_health(profile: &str, json: bool) -> Result<(), CFError> {
    let beacon = match dastyab_core::health_beacon::read_beacon(profile)? {
        Some(b) => b,
        None => {
            println!("No health beacon yet for profile '{profile}' — no cycle has run.");
            println!("Run `dastyab autopilot` or start the daemon, then re-check.");
            std::process::exit(1);
        }
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&beacon).unwrap());
        return Ok(());
    }

    let now = dastyab_core::store::now_ts() as i64;
    let age = dastyab_core::health_beacon::beacon_age_secs(&beacon, now);
    // Staleness threshold: 3× the light-monitor interval from the profile
    // config.
    let cfg = dastyab_core::store::profiles::load_profile(profile).config;
    let interval = cfg.light_interval_secs.max(60) as i64;
    let stale = dastyab_core::health_beacon::is_stale(&beacon, now, 3 * interval);

    let kind = match beacon.cycle_kind {
        dastyab_core::health_beacon::CycleKind::Discovery => "Discovery",
        dastyab_core::health_beacon::CycleKind::Monitor => "Monitor",
        dastyab_core::health_beacon::CycleKind::Rescue => "Rescue",
        dastyab_core::health_beacon::CycleKind::Manual => "Manual",
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
    let dstate = dastyab_core::daemon::load_daemon_state(profile);
    println!("  account:      {}", dstate.account_state.label());
    if let Some(since) = dstate.account_state.since() {
        println!("  account since: {} (waiting for reactivation)", since);
    }
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

fn first_token(p: &dastyab_core::store::profiles::Profile) -> Result<String, CFError> {
    p.tokens
        .values()
        .next()
        .map(|t| t.token.clone())
        .ok_or_else(|| {
            CFError::new(
                "No token",
                "No token in this profile.",
                "Add a token with `dastyab token add`.",
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

/// Guided token recovery: add a new token, verify it against Cloudflare, set
/// it as the active token, and clear any blocked daemon account state so
/// protection resumes immediately — no daemon restart needed. This closes the
/// last manual step for a token-invalid/suspended account.
async fn token_recover(profile: &str, label: &str, token: &str) -> Result<(), CFError> {
    // 1. Save the token.
    add_token(profile, label, token)?;
    // 2. Verify it against Cloudflare.
    let client = Client::new(token.trim());
    let res = match client.verify_token().await {
        Ok(r) => r,
        Err(e) => {
            // Verification failed — roll back the saved token so we don't leave
            // a broken token that shadows a working one.
            let _ = dastyab_core::store::profiles::remove_token(profile, label);
            return Err(e);
        }
    };
    println!(
        "Token '{label}' verified. status={} id={}",
        res.status, res.id
    );
    // 3. Set it active.
    set_active_token(profile, label)?;
    // 4. Clear any blocked daemon account state so cycles resume immediately.
    let cleared = dastyab_core::daemon::clear_account_blocked(profile)?;
    if cleared {
        println!("Daemon account state cleared — protection will resume on the next tick.");
    } else {
        println!("Daemon was not blocked; token already active.");
    }
    Ok(())
}

/// Ensure at least `min` tokens are stored, auto-creating a second one via
/// the Cloudflare API when below the threshold. This closes the manual
/// "create a token in the dashboard" step that was the only remaining barrier
/// to fully automatic token-rotation.
async fn token_ensure(profile: &str, min: usize) -> Result<(), CFError> {
    use dastyab_core::token_provision::ensure_minimum_tokens;

    let p = load_profile(profile);
    if p.tokens.len() >= min {
        println!(
            "Profile '{profile}' already has {} token(s); nothing to do.",
            p.tokens.len()
        );
        return Ok(());
    }
    // We mint the new token using the FIRST stored token's credentials.
    let base = first_token(&p)?;
    let client = Client::new(&base);
    let account_id = client
        .list_accounts()
        .await?
        .into_iter()
        .next()
        .map(|a| a.id)
        .ok_or_else(|| {
            CFError::new(
                "token-ensure",
                "no Cloudflare account accessible with the active token",
                "Check the token's account permissions.",
            )
        })?;

    // Real creator seam: bound the CF client's create_api_token.
    let made = ensure_minimum_tokens(
        profile,
        min,
        account_id,
        move |acc: String, name: String| {
            let c = Client::new(&base);
            Box::pin(async move { c.create_api_token(&acc, &name).await })
        },
    )
    .await?;

    if made {
        let now = load_profile(profile).tokens.len();
        println!(
            "Auto-created a rotation token via the Cloudflare API — profile now has {now} token(s). Auto-rotation is armed."
        );
    }
    Ok(())
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
    p: &dastyab_core::store::profiles::Profile,
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
        if let Some(preset) = dastyab_core::presets::find(pn) {
            safe_worker_name(preset.default_worker_stem)
        } else {
            return Err(CFError::new(
                "Unknown preset",
                format!("No preset named '{pn}'."),
                dastyab_core::presets::describe_all(),
            ));
        }
    } else if let Some(first_acc) = p.accounts.iter().next() {
        worker_name_from_account(Some(&first_acc.1.name))
    } else {
        dastyab_core::worker::default_worker_name()
    };

    // find worker js (validated disk bundle, else built-in standard worker)
    let worker_bytes = dastyab_core::worker::resolve_deploy_worker_bytes();

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
        id: dastyab_core::store::new_id(),
        ts: dastyab_core::store::profiles::now_iso(),
        epoch: dastyab_core::store::now_ts(),
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
                let new_link = dastyab_core::scanner::rewrite_vless_with_endpoint(&link, &ep);
                let rec = VlessRecord {
                    id: dastyab_core::store::new_id(),
                    ts: dastyab_core::store::profiles::now_iso(),
                    epoch: dastyab_core::store::now_ts(),
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

/// Manage the saved clean-IP ledger (mirror of the GUI Clean-IPs manager).
/// Returns the rendered output as a String (empty when nothing to report) so
/// the CLI prints it and tests can assert on it directly.
fn cleanip_cmd(profile: &str, action: CleanipAction) -> Result<String, CFError> {
    use dastyab_core::store::profiles::{
        clean_ip_meta, clear_clean_ips, remove_clean_ip, CleanIpMeta,
    };
    match action {
        CleanipAction::List {
            sort,
            country,
            search,
            source,
            json,
        } => {
            let p = load_profile(profile);
            if p.clean_ips.is_empty() {
                return Ok(format!("No saved clean IPs in profile '{profile}'."));
            }
            // Build rows: endpoint + meta (default when missing).
            let meta_map = clean_ip_meta(profile);
            let mut rows: Vec<(String, CleanIpMeta)> = p
                .clean_ips
                .into_iter()
                .map(|ep| {
                    let m = meta_map.get(&ep).cloned().unwrap_or_default();
                    (ep, m)
                })
                .collect();
            // Filters.
            if let Some(src) = source {
                rows.retain(|(_, m)| m.source == src);
            }
            if let Some(cc) = &country {
                let cc_up = cc.to_uppercase();
                rows.retain(|(_, m)| {
                    m.country.as_ref().map(|c| c.to_uppercase()).as_deref() == Some(cc_up.as_str())
                });
            }
            if let Some(q) = search {
                let ql = q.to_lowercase();
                rows.retain(|(ep, m)| {
                    ep.to_lowercase().contains(&ql) || m.source.to_lowercase().contains(&ql)
                });
            }
            // Sort.
            rows.sort_by(|(epa, ma), (epb, mb)| match sort.as_str() {
                "port" => ma.port.cmp(&mb.port).then_with(|| epa.cmp(epb)),
                "source" => ma.source.cmp(&mb.source).then_with(|| epa.cmp(epb)),
                "country" => ma.country.cmp(&mb.country).then_with(|| epa.cmp(epb)),
                "added" => ma
                    .first_verified_at
                    .cmp(&mb.first_verified_at)
                    .then_with(|| epa.cmp(epb)),
                "last" => ma
                    .last_verified_at
                    .cmp(&mb.last_verified_at)
                    .then_with(|| epa.cmp(epb)),
                _ => epa.cmp(epb),
            });
            if json {
                let arr: Vec<serde_json::Value> = rows
                    .iter()
                    .map(|(ep, m)| {
                        serde_json::json!({
                            "endpoint": ep,
                            "source": m.source,
                            "port": m.port,
                            "country": m.country,
                            "first_verified_at": m.first_verified_at,
                            "last_verified_at": m.last_verified_at,
                        })
                    })
                    .collect();
                return Ok(serde_json::to_string_pretty(&arr).unwrap());
            }
            let mut out = format!("Clean IPs ({}):\n", rows.len());
            for (ep, m) in &rows {
                // Prefer the stored meta country; fall back to a live geoip
                // lookup (entries recorded before the geo-tag round have
                // `country: None` in their meta).
                let cc = m
                    .country
                    .clone()
                    .or_else(|| {
                        let ip_part = ep.rsplit_once(':').map(|(ip, _)| ip).unwrap_or(ep);
                        ip_part.parse::<std::net::IpAddr>().ok().and_then(|ip| {
                            dastyab_core::geoip::GeoDB::load(None).country_code(&ip)
                        })
                    })
                    .unwrap_or_else(|| "-".to_string());
                out.push_str(&format!(
                    "  {ep:<24} src={:<7} port={:<5} cc={}\n",
                    m.source, m.port, cc
                ));
            }
            Ok(out)
        }
        CleanipAction::Remove { ip } => {
            if remove_clean_ip(profile, &ip)? {
                Ok(format!("Removed clean IP '{ip}'"))
            } else {
                Ok(format!("No clean IP '{ip}' found in profile '{profile}'."))
            }
        }
        CleanipAction::Clear => {
            clear_clean_ips(profile)?;
            Ok(format!("Cleared all clean IPs for profile '{profile}'."))
        }
    }
}

fn configs_cmd(profile: &str, action: crate::ConfigsAction) -> Result<(), CFError> {
    use dastyab_core::generated_configs::ConfigQuery;
    let ledger = dastyab_core::generated_configs::load_generated_configs(profile);
    match action {
        crate::ConfigsAction::List {
            fmt,
            since,
            search,
            json,
        } => {
            let fmt = fmt.as_deref().and_then(ExportFormat::parse);
            let q = ConfigQuery {
                fmt,
                source: None,
                since_unix: since,
                until_unix: None,
                label: None,
                text_substring: search,
            };
            let hits = ledger.search(&q);
            if json {
                let arr: Vec<serde_json::Value> = hits
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "id": r.id,
                            "created_unix": r.created_unix,
                            "format": r.fmt.label(),
                            "source": r.source.label(),
                            "label": r.label.as_deref().unwrap_or(""),
                            "sha256": hex(&r.content_sha256),
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&arr).unwrap());
                return Ok(());
            }
            if hits.is_empty() {
                println!("No generated configs match in profile '{profile}'.");
                return Ok(());
            }
            let n = hits.len();
            for r in hits {
                println!(
                    "[{}] {} ({}) {}",
                    r.created_unix,
                    r.fmt.label(),
                    r.source.label(),
                    r.label.as_deref().unwrap_or("")
                );
            }
            println!("{n} record(s)");
            Ok(())
        }
        crate::ConfigsAction::Show { id } => {
            let rec = ledger.records.iter().find(|r| r.id == id);
            match rec {
                Some(r) => {
                    println!("id: {}", r.id);
                    println!("created: {}", r.created_unix);
                    println!("format: {}", r.fmt.label());
                    println!("source: {}", r.source.label());
                    println!("label: {}", r.label.as_deref().unwrap_or(""));
                    println!("sha256: {}", hex(&r.content_sha256));
                    println!("--- content ---");
                    print!("{}", r.content);
                    Ok(())
                }
                None => Err(CFError::new(
                    "Not found",
                    format!("no generated config with id {id}"),
                    "List configs with `dastyab configs list`.",
                )),
            }
        }
        crate::ConfigsAction::Export { id, output } => {
            let rec = ledger.records.iter().find(|r| r.id == id);
            match rec {
                Some(r) => {
                    std::fs::write(&output, &r.content).map_err(|e| {
                        CFError::new("Write error", format!("{e}"), "Check the output path.")
                    })?;
                    println!("Wrote generated config {id} to {output}");
                    Ok(())
                }
                None => Err(CFError::new(
                    "Not found",
                    format!("no generated config with id {id}"),
                    "List configs with `dastyab configs list`.",
                )),
            }
        }
        crate::ConfigsAction::Rename { id, label } => {
            dastyab_core::generated_configs::update_config_label(profile, id, Some(label))?;
            println!("Renamed generated config #{id} (profile {profile})");
            Ok(())
        }
        crate::ConfigsAction::Edit { id, content, file } => {
            let new_content = match (content, file) {
                (Some(c), _) => c,
                (None, Some(path)) => std::fs::read_to_string(&path).map_err(|e| {
                    CFError::new("Read error", format!("{e}"), "Check the file path.")
                })?,
                (None, None) => {
                    return Err(CFError::new(
                        "Missing content",
                        "provide --content or --file",
                        "Example: dastyab configs edit <id> --file config.txt",
                    ));
                }
            };
            dastyab_core::generated_configs::update_config_content(profile, id, new_content)?;
            println!("Edited generated config #{id} (profile {profile})");
            Ok(())
        }
        crate::ConfigsAction::Delete { id } => {
            let removed = dastyab_core::generated_configs::delete_config(profile, id)?;
            if removed {
                println!("Deleted generated config #{id} (profile {profile})");
            } else {
                println!("No generated config with id {id} in profile '{profile}'.");
            }
            Ok(())
        }
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `versions` subcommand — per-artifact version history (list/show/restore/prune).
fn versions_cmd(profile: &str, action: crate::VersionsAction) -> Result<(), CFError> {
    use dastyab_core::artifact_versions as av;
    let dir = dastyab_core::store::profiles::profile_dir(profile);
    match action {
        crate::VersionsAction::List { artifact } => {
            let versions = av::list_versions(&dir, &artifact).map_err(to_verr)?;
            if versions.is_empty() {
                println!("No saved versions for '{artifact}' in profile '{profile}'.");
                return Ok(());
            }
            for v in &versions {
                println!(
                    "[{}] {artifact} sha256={} ({} bytes)",
                    v.saved_unix, v.sha256, v.size
                );
            }
            println!("{} version(s)", versions.len());
            Ok(())
        }
        crate::VersionsAction::Show { artifact, unix } => {
            let bytes = av::read_version_bytes(&dir, &artifact, unix).map_err(to_verr)?;
            print!("{}", String::from_utf8_lossy(&bytes));
            Ok(())
        }
        crate::VersionsAction::Restore { artifact, unix } => {
            av::restore_version(
                &dir,
                &artifact,
                unix,
                dastyab_core::store::now_ts() as u64,
            )
            .map_err(to_verr)?;
            println!("Restored '{artifact}' in profile '{profile}' to version {unix}");
            Ok(())
        }
        crate::VersionsAction::Prune { artifact, keep } => {
            let report = av::prune_versions(&dir, &artifact, keep).map_err(to_verr)?;
            println!(
                "Pruned '{artifact}' in profile '{profile}': kept {} version(s), removed {}",
                report.kept, report.removed
            );
            Ok(())
        }
        crate::VersionsAction::Health => {
            let health =
                av::measure_versioning_health(&dir, dastyab_core::store::now_ts() as u64)
                    .map_err(to_verr)?;
            println!("Profile: {profile}");
            println!("Version dirs: {}", health.dir_count);
            println!("Version files: {}", health.file_count);
            println!("Total bytes: {}", health.total_bytes);
            if let Some((name, bytes)) = &health.largest_dir {
                println!("Largest version dir: {name} ({bytes} B)");
            }
            if !health.oversized_dirs.is_empty() {
                println!("OVERSIZED dirs: {}", health.oversized_dirs.join(", "));
            }
            println!(
                "Consecutive prune failures: {}",
                health.consecutive_failures
            );
            if let Some(t) = health.last_failure_unix {
                println!("Last failure at unix: {t}");
            }
            if let Some(t) = health.last_prune_unix {
                println!("Last successful prune at unix: {t}");
            }
            Ok(())
        }
        crate::VersionsAction::Verify { budget_ms, json } => {
            let now = dastyab_core::store::now_ts() as u64;
            let report = av::verify_all_versions(&dir, now, budget_ms).map_err(to_verr)?;
            let _ = av::record_verify_outcome(&dir, &report, now);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_else(|e| e.to_string())
                );
            } else {
                println!("{}", av::corrupt_versions_summary(&report));
                if !report.corrupt.is_empty() {
                    for c in &report.corrupt {
                        println!(
                            "  corrupt: {}/{} ({:?})",
                            c.rel_path, c.version_unix, c.reason
                        );
                    }
                }
            }
            Ok(())
        }
        crate::VersionsAction::Pitr { unix, dry_run } => {
            let plan = av::build_pitr_plan(&dir, unix);
            println!("{}", av::pitr_preview_markdown(&plan));
            if !dry_run {
                let now = dastyab_core::store::now_ts() as u64;
                let report = av::execute_pitr_plan(&dir, &plan, false, now).map_err(|e| {
                    CFError::new("PITR error", format!("{e:?}"), "Version restore failed.")
                })?;
                println!(
                    "restored={} skipped={} mismatches={} verified={}",
                    report.restored,
                    report.skipped,
                    report.mismatches.len(),
                    report.verified
                );
                for m in &report.mismatches {
                    println!("  mismatch: {m}");
                }
            }
            Ok(())
        }
    }
}

fn to_verr(e: dastyab_core::artifact_versions::VersionError) -> CFError {
    CFError::new(
        "Version error",
        e.to_string(),
        "Check the artifact path and version timestamp.",
    )
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
    // Reconstruct a profile from the saved record. Parsing the stored link is
    // authoritative: it carries the uuid, ws path, TLS/SNI and Host header
    // that the sparse record fields (address/uuid) omit — especially for
    // clean-IP records, where `uuid` is empty and `address` already embeds the
    // port. Rebuilding from the fields alone yields broken exports (empty uuid,
    // duplicated port, missing tls/ws). Fall back to the fields only if the
    // link is unparseable.
    let vless = match VlessProfile::parse(&rec.link) {
        Ok(v) => v,
        Err(_) => {
            let mut v = VlessProfile {
                uuid: rec.uuid.clone(),
                address: rec.address.clone(),
                port: rec.port,
                name: rec.name.clone(),
                ..Default::default()
            };
            v.normalize();
            v
        }
    };

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

fn backup(profile: String, action: BackupAction) -> Result<(), CFError> {
    use dastyab_core::backup::*;
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
        BackupAction::Autosync {
            disable,
            interval,
            keep,
        } => {
            use dastyab_core::store::profiles::{load_profile, save_profile};
            let mut p = load_profile(&profile);
            let mut cfg = p.config.backup_autosync.clone();
            cfg.enabled = !disable;
            if let Some(i) = interval {
                cfg.interval_secs = i;
            }
            if let Some(k) = keep {
                cfg.keep = k;
            }
            p.config.backup_autosync = cfg.clone();
            save_profile(&p)?;
            println!(
                "✓ Auto-backup: enabled={} interval={}s keep={}",
                cfg.enabled, cfg.interval_secs, cfg.keep
            );
            println!(
                "  Backups dir: {}",
                dastyab_core::backup::backup_dir().display()
            );
            println!("  (daemon snapshots the profile on this schedule; run `daemon status` to see last backup)");
        }
    }
    Ok(())
}

/// Configure / show the scheduled worker-signature rotation (anti-DPI moving
/// target). The daemon redeploys the worker with a fresh UUID/path on the
/// interval, so enabling this here removes the manual redeploy step.
fn cmd_mutation(profile: String, action: crate::MutationAction) -> Result<(), CFError> {
    use dastyab_core::store::profiles::{load_profile, save_profile};
    match action {
        crate::MutationAction::Status => {
            let p = load_profile(&profile);
            let c = &p.config.mutation;
            println!(
                "Signature rotation: enabled={} interval={}s rotate_path={}",
                c.enabled, c.interval_secs, c.rotate_path
            );
            println!("  (daemon rotates on this schedule when the network is up)");
        }
        crate::MutationAction::Configure {
            disable,
            interval,
            no_path,
        } => {
            let mut p = load_profile(&profile);
            p.config.mutation.enabled = !disable;
            if let Some(i) = interval {
                p.config.mutation.interval_secs = i.max(3600);
            }
            if no_path {
                p.config.mutation.rotate_path = false;
            } else if !disable {
                p.config.mutation.rotate_path = true;
            }
            let c = &p.config.mutation;
            save_profile(&p)?;
            println!(
                "✓ Signature rotation: enabled={} interval={}s rotate_path={}",
                c.enabled, c.interval_secs, c.rotate_path
            );
            println!("  (daemon redeploys the worker with a fresh UUID on this schedule)");
        }
    }
    Ok(())
}

async fn analytics(profile: String) -> Result<(), CFError> {
    use dastyab_core::analytics::UsageSummary;
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
    let opts = dastyab_core::health::HealthOptions::default();
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
    let report = dastyab_core::security::audit();
    print!("{}", report.render());
    Ok(())
}

fn presets_cmd() -> Result<(), CFError> {
    println!("Deployment presets:");
    println!("{}", dastyab_core::presets::describe_all().trim());
    Ok(())
}

async fn update_check() -> Result<(), CFError> {
    match dastyab_core::selfupdate::update_available(std::time::Duration::from_secs(12)).await? {
        (true, Some(tag)) => {
            println!("An update is available: {tag} (current {VERSION}).");
            println!("Run `dastyab update-apply` to download it.");
        }
        _ => println!("You are on the latest version ({VERSION})."),
    }
    Ok(())
}

async fn update_apply() -> Result<(), CFError> {
    let msg = dastyab_core::selfupdate::apply_update(std::time::Duration::from_secs(120)).await?;
    println!("{msg}");
    Ok(())
}

/// Expand a leading `~` to the user's home dir (for CLI path args).
fn shell_expand(s: &str) -> String {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            if !home.is_empty() {
                return PathBuf::from(home).join(rest).display().to_string();
            }
        }
    }
    s.to_string()
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
    let cidrs = dastyab_core::cf::ips::read_cache();
    match cidrs {
        Some(c) => {
            println!("Cached Cloudflare IPv4 ranges (fetched {}):", c.source);
            println!("{}", dastyab_core::cf::ips::summarize(&c.ipv4));
        }
        None => {
            println!("No cached Cloudflare ranges yet. Run `dastyab discover` to fetch.");
        }
    }
    Ok(())
}

/// Options backing `dastyab find [COUNT]`.
struct FindOpts {
    count: u32,
    sample: u32,
    workers: u32,
    timeout: u32,
    top: Option<u32>,
    refresh: bool,
    seed: Option<String>,
    strategy: Option<crate::StrategyChoice>,
    no_retry: bool,
    json: bool,
    quiet: bool,
    out: Option<String>,
}

/// `dastyab find [COUNT]` — dead-simple by default, fully tunable when you
/// want the advanced knobs. Simple: `find 1`, `find 5 ip`. Advanced: `--sample`,
/// `--workers`, `--timeout`, `--top`, `--seed`, `--strategy`, `--refresh`,
/// `--no-retry`, `--json`, `--quiet`, `--out`.
async fn cmd_find(profile: &str, o: FindOpts) -> Result<(), CFError> {
    let target_n = o.top.unwrap_or(o.count.max(1)).max(1);
    let strategy = o.strategy.map(|s| match s {
        crate::StrategyChoice::WorkerOnly => dastyab_core::health::SniStrategy::WorkerOnly,
        crate::StrategyChoice::GenericFirst => dastyab_core::health::SniStrategy::GenericCfFirst,
        crate::StrategyChoice::WorkerThenGeneric => {
            dastyab_core::health::SniStrategy::WorkerThenGenericCf
        }
    });
    let seed_ips: Vec<String> = o
        .seed
        .as_deref()
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let params = dastyab_core::autopilot::DiscoveryParams {
        sample: o.sample.max(1),
        workers: o.workers.max(1) as usize,
        timeout_s: o.timeout.max(1),
        top_n: target_n as usize,
        force_refresh_ranges: o.refresh,
        retry_on_fail: !o.no_retry,
        seed_ips,
        preferred_strategy: strategy,
        ..Default::default()
    };

    // Make sure we have a base worker config to front.
    let _ = dastyab_core::autopilot::base_vless(profile)?;

    if !o.quiet && !o.json {
        println!(
            "Finding {} clean IP(s) … ({} candidates, {} workers, {}s timeout)",
            target_n, o.sample, o.workers, o.timeout
        );
    }

    let engine = dastyab_core::autopilot::AutopilotEngine::new(
        profile,
        params.clone(),
        std::time::Duration::from_secs(300),
    );
    let (found, summary) = engine
        .run_cycle_guarded(std::time::Duration::from_secs(
            dastyab_core::cycle_guard::DISCOVERY_TIMEOUT_SECS,
        ))
        .await?;

    if found.is_empty() {
        if o.json {
            println!(
                "{}",
                serde_json::json!({
                    "ok": false,
                    "found": 0,
                    "message": summary.note,
                })
            );
        } else if !o.quiet {
            println!("No clean IP found. {}", summary.note);
            println!("Tip: try a larger --sample, or --refresh, or re-deploy the worker.");
        }
        return Ok(());
    }

    if o.json {
        let endpoints: Vec<serde_json::Value> = found
            .iter()
            .map(|ep| {
                serde_json::json!({
                    "ip": ep.ip,
                    "port": ep.port,
                    "score": ep.score,
                    "tcp_ms": ep.tcp_ms,
                    "download_kbps": ep.download_kbps,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "found": found.len(),
                "endpoints": endpoints,
                "message": summary.note,
            })
        );
    } else if o.quiet {
        for ep in &found {
            println!("{}", ep.ip);
        }
    } else {
        for ep in &found {
            println!(
                "✓ {}:{} (score {:.1}, tcp {:.0}ms, {:.0} kbps)",
                ep.ip, ep.port, ep.score, ep.tcp_ms, ep.download_kbps
            );
        }
        println!("{}", summary.note);
    }

    // Surface the user-facing bundle (QR + active config). Copy to --out if given.
    if let Ok(bundle) =
        dastyab_core::cleanip::write_user_bundle(profile, &base_vless_for(profile), &found)
    {
        if !o.quiet && !o.json {
            println!();
            println!("✓ Bundle written: {}", bundle.dir.display());
            println!("  → active.png   (scan with your phone)");
            println!("  → active.vless (paste into your desktop client)");
            if let Some(best) = found.first() {
                println!(
                    "  Best endpoint: {}:{} ({:.0}ms)",
                    best.ip, best.port, best.tcp_ms
                );
            }
        }
        if let Some(dest) = o.out {
            copy_bundle(&bundle.dir, &dest)?;
        }
    }

    Ok(())
}
/// user-specified directory. Used by `find --out <dir>`.
fn copy_bundle(src: &std::path::Path, dest: &str) -> Result<(), CFError> {
    let dest_path = std::path::Path::new(dest);
    std::fs::create_dir_all(dest_path).map_err(|e| {
        CFError::new(
            "Out dir",
            format!("Cannot create {dest}: {e}"),
            "Check permissions and retry.",
        )
    })?;
    let names = ["active.vless", "active.png", "fallbacks.txt", "README.txt"];
    let mut copied = 0;
    for n in names {
        let s = src.join(n);
        if s.exists() {
            std::fs::copy(&s, dest_path.join(n))
                .map_err(|e| CFError::new("Copy", format!("Cannot copy {n}: {e}"), ""))?;
            copied += 1;
        }
    }
    println!(
        "✓ Copied bundle ({copied} files) to {}",
        dest_path.display()
    );
    Ok(())
}

async fn cmd_discover(
    profile: &str,
    sample: u32,
    workers: u32,
    refresh: bool,
) -> Result<(), CFError> {
    let params = dastyab_core::autopilot::DiscoveryParams {
        sample: sample.max(1),
        workers: workers.max(1) as usize,
        force_refresh_ranges: refresh,
        ..Default::default()
    };
    // First make sure we have a base worker config to front.
    let _ = dastyab_core::autopilot::base_vless(profile)?;
    println!(
        "Discovery: {} candidate IPs, {} workers, targeting {} clean endpoint(s)…",
        params.sample, params.workers, params.top_n
    );

    let engine = dastyab_core::autopilot::AutopilotEngine::new(
        profile,
        params.clone(),
        std::time::Duration::from_secs(300),
    );
    let (found, summary) = engine
        .run_cycle_guarded(std::time::Duration::from_secs(
            dastyab_core::cycle_guard::DISCOVERY_TIMEOUT_SECS,
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
        dastyab_core::cleanip::write_user_bundle(profile, &base_vless_for(profile), &found)
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

fn base_vless_for(profile: &str) -> dastyab_core::VlessProfile {
    dastyab_core::autopilot::base_vless(profile).unwrap_or_default()
}

/// Render one line of the per-worker desync learning state for `health --verbose`.
/// Pure (testable): effective strategy (or "ladder" when none learned), the
/// host-down / hold signal, and the failed-strategy list.
fn desync_worker_line(
    url: &str,
    ws: &dastyab_core::worker_tunnel::secret::WorkerSecret,
    now_epoch: i64,
) -> String {
    let eff = ws
        .desync_strategy
        .map(|s| s.label().to_string())
        .unwrap_or_else(|| "ladder".to_string());
    let failed: Vec<&str> = ws.failed_strategies.iter().map(|s| s.label()).collect();
    let down = if ws.host_down {
        let since = ws.host_down_since_unix as i64;
        let dur = if since > 0 {
            now_epoch.saturating_sub(since)
        } else {
            0
        };
        format!("HOST-DOWN {dur}s (ladder held — no demote/advance)")
    } else {
        "up".to_string()
    };
    format!("{url}: eff={eff} {down} failed=[{}]", failed.join(", "))
}

async fn cmd_autopilot(profile: &str, action: crate::AutopilotAction) -> Result<(), CFError> {
    match action {
        crate::AutopilotAction::Status => {
            let ledger = dastyab_core::autopilot::read_ledger(profile);
            if ledger.is_empty() {
                println!("Autopilot ledger is empty — run `dastyab autopilot on` to start.");
                return Ok(());
            }
            let alive: Vec<_> = ledger.iter().filter(|e| e.alive).cloned().collect();
            let summary = dastyab_core::autopilot::CycleSummary {
                cycle: 0,
                alive: alive.len(),
                replaced: 0,
                note: format!("monitor: {} alive", alive.len()),
            };
            println!("{}", dastyab_core::status::simplify_status(&summary));
            println!(
                "  Best IP: {}",
                dastyab_core::status::pick_best_caption(&alive)
            );
            println!("{}", dastyab_core::status::bundle_status(profile));
            // Collapsible technical detail (only when the user asks).
            println!("  (detail: {} endpoint(s) in ledger)", ledger.len());
            Ok(())
        }
        crate::AutopilotAction::Check => {
            let engine = dastyab_core::autopilot::AutopilotEngine::new(
                profile,
                dastyab_core::autopilot::DiscoveryParams::default(),
                std::time::Duration::from_secs(300),
            );
            let cfg = dastyab_core::store::profiles::load_profile(profile).config;
            let timeouts = dastyab_core::autopilot::monitor_timeouts_from_config(&cfg, false);
            let summary = engine.monitor_cycle_guarded(timeouts).await?;
            println!("{}", summary.note);
            Ok(())
        }
        crate::AutopilotAction::Health {
            connect_ip,
            verbose,
        } => {
            let vless = dastyab_core::autopilot::base_vless(profile)?;
            let target = dastyab_core::health::derive_ws_target(&vless);
            let host = target.sni.clone();
            if let Some(ip) = connect_ip {
                println!("Probing worker {host} via connect-ip {ip} (SNI={host}) …");
            } else {
                println!("Probing worker {host} …");
            }
            let doh = dastyab_core::doh::DohResolver::new();
            match dastyab_core::autopilot::probe_worker_health(&host, connect_ip, Some(&doh), 10)
                .await
            {
                dastyab_core::autopilot::WorkerHealth::Alive => {
                    println!("Worker HEALTHY (Alive). Scanning will proceed.");
                }
                other => {
                    let cause = match other {
                        dastyab_core::autopilot::WorkerHealth::Suspended { .. }
                        | dastyab_core::autopilot::WorkerHealth::NotFound => {
                            dastyab_core::diagnose::PlainCause::WorkerDead
                        }
                        dastyab_core::autopilot::WorkerHealth::PathMismatch => {
                            dastyab_core::diagnose::PlainCause::WorkerPathMismatch
                        }
                        dastyab_core::autopilot::WorkerHealth::Unreachable => {
                            dastyab_core::diagnose::PlainCause::NetworkBlocked
                        }
                        dastyab_core::autopilot::WorkerHealth::Alive => unreachable!(),
                    };
                    println!(
                        "Worker NOT healthy: {}",
                        dastyab_core::diagnose::plain_message(
                            cause,
                            dastyab_core::diagnose::Locale::En
                        )
                    );
                    println!(
                        "  Recommended: {}",
                        dastyab_core::diagnose::recommended_action(cause)
                            .label(dastyab_core::diagnose::Locale::En)
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
                if let Some(diag) = dastyab_core::store::profiles::load_last_diagnostics(profile)
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
                            .get(&dastyab_core::health::WsFailureReason::TlsAlert)
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
                        // Success-side stratification: which ClientHello profile ×
                        // SNI layer actually got accepted probes. A profile with
                        // few/zero successes while others succeed is a blacklisted
                        // fingerprint — rotate it / enable desync.
                        if !diag.success_by_profile.is_empty() {
                            println!("\n  ClientHello-profile successes (profile × SNI layer):");
                            let mut rows: Vec<_> = diag.success_by_profile.iter().collect();
                            rows.sort_by(|a, b| b.1.cmp(a.1));
                            for ((profile, layer), count) in rows {
                                println!("    {profile:?} × {layer:?}: {count}");
                            }
                            let total_success: u32 = diag.success_by_profile.values().sum();
                            let min_count =
                                diag.success_by_profile.values().min().copied().unwrap_or(0);
                            if total_success > 0 {
                                let low = diag
                                    .success_by_profile
                                    .iter()
                                    .filter(|(_, c)| **c < total_success / 2)
                                    .map(|((p, _), _)| format!("{:?}", p))
                                    .collect::<Vec<_>>();
                                if !low.is_empty() {
                                    println!(
                                        "  Note: profile(s) with below-median success: {} — consider rotating away from a blacklisted fingerprint.",
                                        low.join(", ")
                                    );
                                } else if min_count > 0 {
                                    println!("  Note: all profiles have success ≥ median; fingerprint spread looks healthy.");
                                }
                            }
                        }
                    }
                } else {
                    println!("  (no last-diagnostics file for profile {profile})");
                }
            }
            // `--verbose`: surface the last monitor LIGHT-sweep aggregate so an
            // operator sees the healthy-but-muted signal live. Read it with the
            // same alive/total classification the light phase ran so the demo
            // matches what actually drove the learning verdict.
            if verbose {
                println!("\n--- light-sweep aggregate (last monitor pass) ---");
                if let Some(light) = dastyab_core::store::profiles::load_last_light_sweep(profile)
                {
                    if light.total == 0 {
                        println!("  (no light sweep recorded yet — run a monitor cycle first)");
                    } else {
                        println!(
                            "  alive {}/{} (dead fraction {:.0}%)",
                            light.alive,
                            light.total,
                            if light.total > 0 {
                                (light.total.saturating_sub(light.alive)) as f64 * 100.0
                                    / light.total as f64
                            } else {
                                0.0
                            }
                        );
                        if light.histogram.is_empty() {
                            println!("  failure histogram: (empty)");
                        } else {
                            let mut rows: Vec<_> = light.histogram.iter().collect();
                            rows.sort_by(|a, b| b.1.cmp(a.1));
                            for (reason, count) in rows {
                                println!("  {reason:?}: {count}");
                            }
                        }
                        let (dpi, origin) =
                            dastyab_core::worker_tunnel::secret::histogram_attribution(
                                &light.histogram,
                            );
                        let sig = dastyab_core::worker_tunnel::secret::classify_light_sweep(
                            light.alive as usize,
                            light.total as usize,
                            Some(&light.histogram),
                        );
                        println!(
                            "  attribution: DPI/401/403={dpi}  origin-5xx={origin}  verdict={sig:?}"
                        );
                    }
                } else {
                    println!("  (no light-sweep file for profile {profile})");
                }
            }
            // Self-learning phase-2 SNI strategy status (the autonomy knob, v2
            // rolling-window).
            if verbose {
                // Health beacon line (round 4): age + kind, so `autopilot
                // health --verbose` doubles as a one-line liveness check.
                if let Ok(Some(beacon)) = dastyab_core::health_beacon::read_beacon(profile) {
                    let now = dastyab_core::store::now_ts() as i64;
                    let age = dastyab_core::health_beacon::beacon_age_secs(&beacon, now);
                    let kind = match beacon.cycle_kind {
                        dastyab_core::health_beacon::CycleKind::Discovery => "Discovery",
                        dastyab_core::health_beacon::CycleKind::Monitor => "Monitor",
                        dastyab_core::health_beacon::CycleKind::Rescue => "Rescue",
                        dastyab_core::health_beacon::CycleKind::Manual => "Manual",
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
                let state = dastyab_core::autopilot::resolve_strategy_v2(profile);
                let name = match state.current {
                    dastyab_core::health::SniStrategy::WorkerOnly => "WorkerOnly",
                    dastyab_core::health::SniStrategy::GenericCfFirst => "GenericCfFirst",
                    dastyab_core::health::SniStrategy::WorkerThenGenericCf => {
                        "WorkerThenGenericCf"
                    }
                };
                let window: Vec<u8> = state.recent_outcomes.iter().map(|&w| u8::from(w)).collect();
                let rate = dastyab_core::autopilot::success_rate(&state);
                let should_rotate = dastyab_core::autopilot::should_rotate(&state);
                let cycles_left = dastyab_core::autopilot::STRATEGY_FORCED_ROTATION_CYCLES
                    .saturating_sub(state.cycles_since_rotation);
                let rotated_ts = dastyab_core::store::profiles::strategy_last_rotated_ts(profile);
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
                // Per-worker desync learning state (the host-down / hold signal
                // from the learning table): effective strategy, failed
                // strategies, and whether the worker host is currently marked
                // down (ladder held — no demote/advance until a success clears
                // it). This is the "reads host-down / hold state from the
                // table" half of `health --verbose`.
                let store_live = dastyab_core::store::profiles::load_profile(profile);
                let lnow = dastyab_core::store::now_ts() as i64;
                if !store_live.config.worker_secrets.is_empty() {
                    println!("  Desync learning (per worker):");
                    let mut workers: Vec<_> = store_live.config.worker_secrets.iter().collect();
                    workers.sort_by(|a, b| a.0.cmp(b.0));
                    for (url, ws) in workers {
                        println!("    {}", desync_worker_line(url, ws, lnow));
                    }
                }
                // Bundle sync state (the user's actual handoff).
                if let Some(ledger_ep) = dastyab_core::cleanip::active_ledger_endpoint(profile) {
                    let dir = dastyab_core::cleanip::user_config_dir(profile).ok();
                    let drift = dir
                        .as_ref()
                        .map(|d| dastyab_core::cleanip::check_bundle_drift(d, &ledger_ep));
                    match drift {
                        Some(dastyab_core::cleanip::BundleDrift::InSync) => {
                            println!("  Bundle: in-sync (endpoint={ledger_ep})");
                        }
                        Some(dastyab_core::cleanip::BundleDrift::EndpointMismatch { .. })
                        | Some(dastyab_core::cleanip::BundleDrift::MissingDir)
                        | Some(dastyab_core::cleanip::BundleDrift::MissingFile { .. })
                        | Some(dastyab_core::cleanip::BundleDrift::Unparseable { .. }) => {
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
            let params = dastyab_core::autopilot::DiscoveryParams {
                sample: sample.max(1),
                workers: workers.max(1) as usize,
                ..Default::default()
            };
            let interval = std::time::Duration::from_secs(interval_s.max(60));
            println!("Autopilot ON (profile '{profile}'): discovery every {}s, {} candidates, {} workers.",
                interval.as_secs(), params.sample, params.workers);
            println!("First cycle: discovering the best clean IP…");
            let engine = dastyab_core::autopilot::AutopilotEngine::new(profile, params, interval);
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
            let enabled = dastyab_core::store::profiles::protection_enabled(profile);
            println!("Protection: {}", if enabled { "ON" } else { "OFF" });
            // Surface the last plain-language explanation of a zero result, if any.
            if let Some(diag) = dastyab_core::store::profiles::load_last_diagnostics(profile) {
                let probe = dastyab_core::diagnose::WorkerProbe::default();
                let cause = dastyab_core::diagnose::diagnose(&diag, probe);
                println!(
                    "  Last scan: {}",
                    dastyab_core::diagnose::plain_message(
                        cause,
                        dastyab_core::diagnose::Locale::En
                    )
                );
                println!(
                    "  Recommended: {}",
                    dastyab_core::diagnose::recommended_action(cause)
                        .label(dastyab_core::diagnose::Locale::En)
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
            let n = dastyab_core::cf::ips::import_manual_seeds(profile, &input)?;
            println!("Imported {n} known-good IP(s). Next scan will use them as seeds.");
            Ok(())
        }
        ProtectionAction::Off => {
            dastyab_core::store::profiles::set_protection(profile, false)?;
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
                dastyab_core::store::profiles::set_protection(profile, true)?;
                println!("Protection ON (persisted — will auto-resume after restart).");
            } else {
                println!("Protection ON (not persisted).");
            }

            let params = dastyab_core::autopilot::DiscoveryParams {
                sample: sample.max(1),
                workers: workers.max(1) as usize,
                ..Default::default()
            };
            let interval = std::time::Duration::from_secs(interval_s.max(60));
            println!("First cycle: discovering the best clean IP…");
            let engine = dastyab_core::autopilot::AutopilotEngine::new(profile, params, interval);

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
                        dastyab_core::cycle_guard::DISCOVERY_TIMEOUT_SECS,
                    ))
                    .await?;
                println!("{}", summary.note);
            }
            Ok(())
        }
    }
}

/// Configure / report the anti-DPI TCP desync fragmenter (persisted per-profile).
fn cmd_desync(profile: &str, action: crate::DesyncAction) -> Result<(), CFError> {
    use dastyab_core::desync::DesyncStrategy;
    match action {
        crate::DesyncAction::Status => {
            let p = dastyab_core::store::profiles::load_profile(profile);
            let cfg = p.config.desync;
            println!(
                "Desync fragmentation: {}",
                if cfg.enabled { "ON" } else { "OFF" }
            );
            println!("  strategy: {}", cfg.strategy.label());
            if cfg.enabled {
                println!("  min fragment: {} B", cfg.min_fragment);
                println!("  max fragment: {} B", cfg.max_fragment);
                println!("  inter-fragment delay: {} us", cfg.inter_fragment_delay_us);
            }
            // Show learned per-worker strategies (the connector's auto-discovered
            // values for the worker relay control-plane path).
            let learned: Vec<_> = p
                .config
                .worker_secrets
                .iter()
                .filter(|(_, ws)| ws.desync_strategy.is_some())
                .map(|(url, ws)| {
                    format!(
                        "{url}: {} (failed: {})",
                        ws.desync_strategy.unwrap().label(),
                        ws.failed_strategies.len()
                    )
                })
                .collect();
            if !learned.is_empty() {
                println!("  learned per-worker strategies:");
                for l in learned {
                    println!("    {l}");
                }
            }
            Ok(())
        }
        crate::DesyncAction::On {
            min_fragment,
            max_fragment,
            delay_us,
            strategy,
        } => {
            let strat = DesyncStrategy::parse(&strategy).ok_or_else(|| {
                CFError::new(
                    "Desync strategy",
                    format!(
                        "unknown strategy '{strategy}' (expected split-clienthello | split-two | split+decoy | none)"
                    ),
                    "",
                )
            })?;
            let mut p = dastyab_core::store::profiles::load_profile(profile);
            p.config.desync.enabled = true;
            p.config.desync.min_fragment = min_fragment.max(1);
            p.config.desync.max_fragment = max_fragment.max(min_fragment.max(1));
            p.config.desync.inter_fragment_delay_us = delay_us;
            p.config.desync.strategy = strat;
            dastyab_core::store::profiles::save_profile(&p)?;
            dastyab_core::desync::apply_from_profile(profile);
            println!(
                "Desync fragmentation ON (saved) with strategy {}.",
                strat.label()
            );
            Ok(())
        }
        crate::DesyncAction::Off => {
            let mut p = dastyab_core::store::profiles::load_profile(profile);
            p.config.desync.enabled = false;
            dastyab_core::store::profiles::save_profile(&p)?;
            dastyab_core::desync::apply_from_profile(profile);
            println!("Desync fragmentation OFF (saved).");
            Ok(())
        }
    }
}

/// Run the daemon loop forever (or until the stop file appears).
async fn daemon_loop(cfg: dastyab_core::daemon::DaemonConfig) -> Result<(), CFError> {
    use dastyab_core::daemon::*;
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
    state.started_at = dastyab_core::store::now_ts() as i64;
    save_daemon_state(&cfg.profile, &state)?;

    let mut probe = RealNetworkProbe::new(&cfg.profile);
    let acct = RealAccountProbe;
    let cycle = RealCycleRunner;
    let mut interval = cfg.initial_interval_secs;
    // The profile the daemon is currently driving. Cross-worker failover may
    // rotate the ACTIVE profile (store marker) when the rescue chain gives up;
    // we must follow it so the daemon actually switches to the backup worker.
    let mut active_profile: String = cfg.profile.clone();
    let mut last_rescue_outcome: Option<String> = None;

    // Remote push on startup (best-effort — never fail the loop).
    let _ = dastyab_core::remote_beacon::maybe_emit(
        &active_profile,
        &dastyab_core::remote_beacon::BeaconEvent::ProtectionStarted,
        dastyab_core::diagnose::Locale::En,
    )
    .await;

    loop {
        // Stop request?
        if cfg.stop_file.exists() {
            daemon_log_append(&cfg.log_path, &log_line("INFO", "daemon stop requested"));
            cleanup_daemon(&cfg.pid_file, &cfg.stop_file);
            return Ok(());
        }

        // Auto self-update: roughly once per day, check for a newer release,
        // download it, and atomically swap it over the running binary. If an
        // update was applied, re-exec ourselves so the new version takes over
        // without a manual restart. Best-effort — never fail the loop.
        if dastyab_core::store::now_ts() as i64 - state.last_update_check_ts
            >= dastyab_core::selfupdate::AUTO_UPDATE_INTERVAL_SECS as i64
        {
            state.last_update_check_ts = dastyab_core::store::now_ts() as i64;
            match dastyab_core::selfupdate::ensure_updated_with_swap(
                std::time::Duration::from_secs(120),
            )
            .await
            {
                Ok(dastyab_core::selfupdate::UpdateOutcome::Updated { tag }) => {
                    daemon_log_append(
                        &cfg.log_path,
                        &log_line("INFO", &format!("auto-update applied {tag}, re-execing…")),
                    );
                    save_daemon_state(&active_profile, &state)?;
                    // Re-exec the (now updated) binary with the same args.
                    let exe = std::env::current_exe().map_err(|e| {
                        CFError::new("Daemon", e.to_string(), "Cannot locate the binary.")
                    })?;
                    let _ = std::process::Command::new(exe)
                        .arg("daemon")
                        .arg("start")
                        .arg("--profile")
                        .arg(&cfg.profile)
                        .arg("--foreground")
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .spawn();
                    return Ok(());
                }
                Ok(dastyab_core::selfupdate::UpdateOutcome::Failed(msg)) => {
                    daemon_log_append(
                        &cfg.log_path,
                        &log_line("WARN", &format!("auto-update failed: {msg}")),
                    );
                }
                _ => {}
            }
        }

        // Cross-worker failover: follow the active profile marker. When the
        // store's active profile changes (e.g. rescue rotated to a backup
        // worker), adopt it — but only if it is a real, known profile.
        let store_active = dastyab_core::store::profiles::get_active_profile();
        if store_active != active_profile {
            let known = dastyab_core::store::profiles::list_profiles()
                .iter()
                .any(|m| m.id == store_active);
            if known {
                daemon_log_append(
                    &cfg.log_path,
                    &log_line(
                        "INFO",
                        &format!(
                            "failover: switching profile {} -> {}",
                            active_profile, store_active
                        ),
                    ),
                );
                // Notify on failover (rate-limited by event class).
                let from = active_profile.clone();
                let to_clone = store_active.clone();
                let _ = dastyab_core::remote_beacon::maybe_emit(
                    &store_active,
                    &dastyab_core::remote_beacon::BeaconEvent::FailoverSwitched {
                        from,
                        to: to_clone,
                    },
                    dastyab_core::diagnose::Locale::En,
                )
                .await;
                active_profile = store_active.clone();
                state = load_daemon_state(&active_profile);
                state.pid = pid;
                state.started_at = dastyab_core::store::now_ts() as i64;
                interval = cfg.initial_interval_secs;
            }
        }

        let sleep = daemon_tick(
            &active_profile,
            &mut state,
            &mut probe,
            &acct,
            &cycle,
            &mut |line| daemon_log_append(&cfg.log_path, line),
        )
        .await;
        save_daemon_state(&active_profile, &state)?;

        // Flush the beacon outbox: any alert queued during a blackout /
        // blocked channel is delivered now that we reached a cycle (network is
        // up). Best-effort — never fail the loop.
        {
            let flushed = dastyab_core::remote_beacon::flush_outbox(&active_profile).await;
            if flushed > 0 {
                daemon_log_append(
                    &cfg.log_path,
                    &log_line(
                        "INFO",
                        &format!("beacon outbox flushed {flushed} queued alert(s)"),
                    ),
                );
            }
        }

        // Profile config hot-reload (round 22): if the profile dir mtime
        // changed since we last looked (Settings edited, token/state files
        // updated), log a reload notice and reset the interval so the new
        // configuration applies without a manual daemon restart. Best-effort —
        // never fail the loop on a stat error.
        if let Ok(changed) = dastyab_core::account_state::profile_mtime_changed(
            &active_profile,
            state.last_profile_mtime,
        ) {
            if changed {
                daemon_log_append(
                    &cfg.log_path,
                    &log_line("INFO", "profile config changed — reloading settings"),
                );
                state.last_profile_mtime = dastyab_core::store::now_ts() as i64;
                interval = cfg.initial_interval_secs;
                save_daemon_state(&active_profile, &state)?;
            }
        }
        // Scheduled config mutation: rotate the worker signature on a schedule
        // (only when the account is active — never mutate a blocked account).
        if !state.account_state.blocks_cycle() {
            let peer = dastyab_core::autopilot::RealMutationPeer;
            match dastyab_core::config_mutation::run_mutation_if_due(&active_profile, &peer).await
            {
                Ok(Some(outcome)) => {
                    let line = log_line(
                        "INFO",
                        &format!(
                            "config mutation applied: {} -> {}",
                            outcome.old_path, outcome.new_path
                        ),
                    );
                    daemon_log_append(&cfg.log_path, &line);
                    let _ = dastyab_core::remote_beacon::maybe_emit(
                        &active_profile,
                        &dastyab_core::remote_beacon::BeaconEvent::ConfigMutated {
                            old_worker: outcome.old_uuid,
                            new_worker: outcome.new_uuid,
                        },
                        dastyab_core::diagnose::Locale::En,
                    )
                    .await;
                }
                Ok(None) => {}
                Err(e) => {
                    let line = log_line("WARN", &format!("config mutation skipped: {}", e.brief()));
                    daemon_log_append(&cfg.log_path, &line);
                }
            }
        }

        // Scheduled auto-backup: snapshot the profile on a schedule so there is
        // always a recent restorable copy under ~/.dastyab/backups/ (crash /
        // blackout / seized-machine resilience). Runs even when the network is
        // down or the account is suspended — local disk work only.
        {
            let pcfg = dastyab_core::store::profiles::load_profile(&active_profile);
            let bak = pcfg.config.backup_autosync.clone();
            let now_bak = dastyab_core::store::now_ts() as i64;
            match dastyab_core::backup_autosync::run_autosync_if_due(
                &bak,
                &active_profile,
                state.last_backup_ts,
                now_bak,
            ) {
                Ok(Some(path)) => {
                    state.last_backup_ts = now_bak;
                    daemon_log_append(
                        &cfg.log_path,
                        &log_line("INFO", &format!("auto-backup written: {}", path.display())),
                    );
                }
                Ok(None) => {}
                Err(e) => {
                    daemon_log_append(
                        &cfg.log_path,
                        &log_line("WARN", &format!("auto-backup failed: {}", e.brief())),
                    );
                }
            }
        }
        // Worker-dead + rescue-gave-up → notify (rate-limited). Track the
        // persisted rescue outcome to avoid re-notifying every cycle.
        let current_rescue = dastyab_core::store::profiles::load_profile(&active_profile)
            .config
            .last_rescue_outcome;
        if current_rescue.as_deref() == Some("gave_up")
            && last_rescue_outcome.as_deref() != Some("gave_up")
        {
            let _ = dastyab_core::remote_beacon::maybe_emit(
                &active_profile,
                &dastyab_core::remote_beacon::BeaconEvent::WorkerDeadGiveUp,
                dastyab_core::diagnose::Locale::En,
            )
            .await;
        }
        last_rescue_outcome = current_rescue;
        // Persist the current backoff interval into state.
        if sleep != 0 && sleep != interval {
            interval = sleep;
        }
        tokio::time::sleep(Duration::from_secs(sleep)).await;
    }
}

/// CLI handler for the persistent daemon.
async fn cmd_daemon(profile: &str, action: DaemonAction) -> Result<(), CFError> {
    use dastyab_core::daemon::*;
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
            dastyab_core::store::write_json(&cfg.stop_file, &true)?;
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
                let up = (dastyab_core::store::now_ts() as i64) - state.started_at;
                println!("  uptime: {up}s");
            }
            println!("  last cycle ts: {}", state.last_cycle_ts);
            println!("  last success ts: {}", state.last_success_ts);
            println!("  failure streak: {}", state.failure_streak);
            println!("  current interval: {}s", state.current_interval_secs);
            println!("  network was down: {}", state.network_was_down);
            println!("  account: {}", state.account_state.label());
            if let Some(since) = state.account_state.since() {
                println!(
                    "  account blocked since: {} (waiting for reactivation)",
                    since
                );
            }
            match is_linger_enabled() {
                Some(true) => {
                    println!("  boot autostart: yes (loginctl linger — starts before login)")
                }
                Some(false) => {
                    println!("  boot autostart: no (allow linger; daemon starts at login only)")
                }
                None => println!("  boot autostart: unknown (loginctl unavailable)"),
            }
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
            let unit = unit_dir.join("dastyab-daemon.service");
            let bin = std::env::current_exe()
                .map_err(|e| CFError::new("Daemon", e.to_string(), "Cannot locate the binary."))?;
            let contents = dastyab_core::daemon::systemd_unit(&bin, profile);
            std::fs::write(&unit, contents).map_err(|e| {
                CFError::new("Daemon", e.to_string(), "Cannot write the systemd unit.")
            })?;
            println!("Wrote {}.", unit.display());
            // Close the last manual step: `systemctl --user enable --now` is a
            // per-user operation (no root), so run it and report the real result.
            let unit_name = "dastyab-daemon.service";
            match dastyab_core::daemon::systemctl_user("enable --now", unit_name) {
                Ok(true) => println!("Enabled and started {unit_name}."),
                Ok(false) => {
                    return Err(CFError::new(
                        "Daemon",
                        "systemctl --user enable --now returned a non-zero status".to_string(),
                        format!("The unit file is written; run it manually: systemctl --user enable --now {unit_name}"),
                    ));
                }
                Err(e) => {
                    return Err(CFError::new(
                        "Daemon",
                        e.to_string(),
                        format!("systemctl not available? Run manually: systemctl --user enable --now {unit_name}"),
                    ));
                }
            }
            // Enable loginctl linger so the --user daemon starts at boot before
            // any login (survives a total-blackout reboot with no human at the
            // box). Report the outcome honestly — it's best-effort on systems
            // where loginctl is unavailable/refused.
            let linger = dastyab_core::daemon::enable_linger();
            let linger_state = match dastyab_core::daemon::is_linger_enabled() {
                Some(true) => "enabled".to_string(),
                Some(false) => "disabled".to_string(),
                None => "unknown (loginctl unavailable)".to_string(),
            };
            if linger {
                println!("Boot autostart enabled (loginctl linger): daemon will start at boot, before login.");
            } else {
                println!(
                    "Note: could not enable boot autostart (loginctl linger). Current state: {linger_state}. The daemon will still start at your next login."
                );
            }
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
    let client = dastyab_core::cf::Client::new(&token);
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
    let params = dastyab_core::autopilot::DiscoveryParams::default();
    let engine = dastyab_core::autopilot::AutopilotEngine::new(
        profile,
        params,
        std::time::Duration::from_secs(300),
    );
    let (found, summary) = engine
        .run_cycle_guarded(std::time::Duration::from_secs(
            dastyab_core::cycle_guard::DISCOVERY_TIMEOUT_SECS,
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
    let bundle = dastyab_core::cleanip::write_user_bundle(
        profile,
        &dastyab_core::autopilot::base_vless(profile)?,
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
    println!("4. Compare:  dastyab verify --direct-ip DIRECT_IP --tunnel-ip TUNNEL_IP");
    println!("   PASS = the two IPs differ → the tunnel routes through the Worker.");
    println!("════════════════════════════════════════════════════════════");
    Ok(())
}

fn default_worker_name_for(p: &dastyab_core::store::profiles::Profile) -> String {
    // Mirror deploy()'s fallback: first account name, else preset stem.
    if let Some(first) = p.accounts.iter().next() {
        worker_name_from_account(Some(&first.1.name))
    } else {
        dastyab_core::worker::default_worker_name()
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
            "Run the manual verification steps in `dastyab e2e`.",
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

/// Blackout drill: probe every fallback-ladder rung (Direct → DoH → DoT →
/// DNS tunnel) once with the real transports and print a per-tier verdict.
/// This is a self-test for resilience — the user verifies what would survive
/// a blackout without disconnecting.
async fn cmd_drill(profile: &str) -> Result<(), CFError> {
    use dastyab_core::connectivity::{drill_all_tiers, RealLadderProbe, Tier};
    let resolver = dastyab_core::doh::DohResolver::new();
    let report = drill_all_tiers(RealLadderProbe {
        profile,
        resolver: &resolver,
    })
    .await;
    println!("Blackout drill — fallback ladder (top-down):");
    let mut survivors = 0;
    let total = report.len();
    for (tier, verdict) in report {
        let mark = if verdict.ok { "OK  " } else { "FAIL" };
        println!("  {mark}  {}  {}", tier.label(), verdict.note);
        if verdict.ok {
            survivors += 1;
        }
    }
    println!(
        "Result: {survivors}/{total} rungs reachable. {}",
        if survivors == total {
            "Full resilience."
        } else if survivors == 0 {
            "Total blackout — consider configuring a DNS tunnel (dns-tunnel deploy) or a LAN mesh relay."
        } else {
            "Partial resilience — worst surviving rung will carry you."
        }
    );
    let _ = Tier::Direct; // keep import meaningful if unused
    Ok(())
}

async fn cmd_up(profile_override: Option<String>) -> Result<(), CFError> {
    let diag = dastyab_core::bootstrap::up_with_diagnosis(profile_override.as_deref()).await;
    let mins = diag.elapsed_ms as f64 / 60000.0;
    if diag.ok {
        let bundle = dastyab_core::cleanip::user_config_dir("default")
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "~/dastyab-configs/default/".to_string());
        println!(
            "✓ Protection active in {mins:.0}m {:.0}s",
            (diag.elapsed_ms % 60000) as f64 / 1000.0
        );
        println!("  Bundle: {bundle}");
        println!("  → active.png   (scan with your phone)");
        println!("  → active.vless (paste into your desktop client)");
        println!("  Daemon: running (systemd user service)");
        println!("  Best endpoint: see fallbacks.txt / active.vless");
        std::process::exit(0);
    }
    // Failure — print the honest one-line diagnosis + exit scriptably.
    eprintln!(
        "✗ Setup could not complete (failed at stage: {})",
        diag.stage_reached
    );
    eprintln!("  {}", diag.plain_message);
    eprintln!("  Recommended: {}", diag.recommended_action);
    let code = diag.failure.as_ref().map(|f| f.exit_code()).unwrap_or(1);
    eprintln!("  Exit code: {code}");
    std::process::exit(code);
}

/// `dastyab onboard status` — offline report of which setup steps are done.
fn cmd_onboard(profile: &str, action: crate::OnboardAction) -> Result<(), CFError> {
    use dastyab_core::bootstrap::{onboarding_status, OnboardingStep};
    match action {
        crate::OnboardAction::Status { profile: p } => {
            let pid = p.as_deref().unwrap_or(profile);
            let done = onboarding_status(Some(pid));
            let all = [
                OnboardingStep::Token,
                OnboardingStep::Worker,
                OnboardingStep::Bundle,
                OnboardingStep::DaemonInstalled,
                OnboardingStep::DaemonRunning,
            ];
            println!("Onboarding status — profile '{pid}':");
            for step in all {
                let mark = if done.contains(&step) { "✓" } else { "·" };
                println!("  {mark} {}", step.label());
            }
            let remaining = all.iter().filter(|s| !done.contains(s)).count();
            println!();
            if remaining == 0 {
                println!("All setup steps complete — protection is live.");
            } else {
                println!(
                    "{remaining} step(s) remaining. Run `dastyab up` to complete them automatically."
                );
            }
        }
    }
    Ok(())
}

/// `dastyab sni-spoof …` — SNI allowlist scanner.
async fn cmd_sni_spoof(profile: &str, action: crate::SniSpoofAction) -> Result<(), CFError> {
    use dastyab_core::sni_spoof as sp;
    match action {
        crate::SniSpoofAction::List => {
            match sp::config::load_allowlist(profile) {
                Some(list) if !list.is_empty() => {
                    println!("Allowed SNIs for profile '{profile}':");
                    for s in &list {
                        println!("  {s}");
                    }
                }
                _ => {
                    println!("No allowlist saved yet. Run: dastyab sni-spoof scan");
                }
            }
            Ok(())
        }
        crate::SniSpoofAction::Show => {
            let p = sp::config::allowlist_path(profile)?;
            if !p.exists() {
                println!("No scan saved yet. Run: dastyab sni-spoof scan");
                return Ok(());
            }
            let raw = std::fs::read_to_string(&p).map_err(|e| {
                CFError::new("SniSpoof", e.to_string(), "Cannot read the saved scan.")
            })?;
            println!("{raw}");
            Ok(())
        }
        crate::SniSpoofAction::Clear => {
            sp::config::clear_allowlist(profile)?;
            println!("Allowlist cleared for profile '{profile}'.");
            Ok(())
        }
        crate::SniSpoofAction::Scan {
            ip,
            port,
            timeout_ms,
            workers,
        } => {
            // Default edge: a well-known Cloudflare anycast IP.
            let ip = ip.unwrap_or_else(|| "1.1.1.1".to_string());
            let worker_host = dastyab_core::autopilot::base_vless(profile)
                .ok()
                .map(|v| v.address);
            let snis_base = sp::candidates::candidates_with_worker(worker_host.as_deref());
            // Seed the anti-DPI SNI set from verified-live CT-anchor hostnames
            // (doctrine §5: out-of-band bootstrap, never circular). Falling back
            // to the static defaults when no anchors exist yet is a no-op merge.
            let ct_store = dastyab_core::ct_anchors::load_anchors(profile);
            let ct_hosts: Vec<String> = ct_store.anchors.iter().map(|a| a.host.clone()).collect();
            let snis = sp::candidates::merge_candidates(&snis_base, &ct_hosts);
            println!(
                "Probing {} SNIs ({} from CT anchors) against {ip}:{port} (timeout {timeout_ms}ms, {workers} workers)…",
                snis.len(),
                ct_hosts.len()
            );
            let results = sp::scanner::scan_snis(&snis, &ip, port, timeout_ms, workers).await;
            let summary = sp::scanner::summarize(&results);

            // Persist the allowlist.
            if !summary.allowed.is_empty() {
                sp::config::persist_allowlist(profile, &summary.allowed)?;
            }

            println!();
            println!("=== SNI allowlist scan (profile '{profile}') ===");
            println!(
                "  allowed ({}) | blocked ({}) | timeout ({})",
                summary.allowed.len(),
                summary.blocked.len(),
                summary.timeouts.len()
            );
            println!();
            for (sni, r) in &results {
                let mark = if r.passed {
                    "✓ ALLOWED".to_string()
                } else if r.failure
                    == Some(dastyab_core::sni_spoof::scanner::SniTestFailure::Timeout)
                {
                    "… TIMEOUT".to_string()
                } else {
                    "✗ BLOCKED".to_string()
                };
                println!("  {mark}  {sni}  ({}ms)", r.rtt_ms);
            }
            println!();
            if !summary.allowed.is_empty() {
                println!("Saved {} allowed SNI(s).", summary.allowed.len());
                println!("Next: dastyab sni-spoof list");
                Ok(())
            } else {
                println!(
                    "No SNI allowed — DPI may be active at the TLS-fingerprint or network level."
                );
                Err(CFError::new(
                    "SniSpoof",
                    "All SNIs blocked or timed out.",
                    "DPI is not passing any SNI — see the round-13 decision.",
                ))
            }
        }
        crate::SniSpoofAction::WsScan {
            ip,
            port,
            path,
            timeout_ms,
        } => {
            let ip = ip.unwrap_or_else(|| "1.1.1.1".to_string());
            // Probe the worker's own hostname (if known) then the generic CF edge.
            let worker_host = dastyab_core::autopilot::base_vless(profile)
                .ok()
                .map(|v| v.address);
            let mut targets: Vec<(String, String)> = Vec::new(); // (sni, label)
            if let Some(w) = &worker_host {
                targets.push((w.clone(), "worker".to_string()));
            }
            targets.push(("www.cloudflare.com".to_string(), "cf".to_string()));
            targets.push(("workers.dev".to_string(), "workers".to_string()));

            println!("WS-upgrade probe → {ip}:{port}{path} (timeout {timeout_ms}ms)…");
            for (sni, label) in &targets {
                let r = dastyab_core::sni_spoof::ws_probe::probe_ws_upgrade(
                    sni, &ip, port, &path, timeout_ms,
                )
                .await;
                let verdict = dastyab_core::sni_spoof::ws_probe::verdict_line(&r);
                println!("  [{label}] {sni} → {verdict}  ({}ms)", r.elapsed_ms);
            }
            println!();
            println!("Verdict: see per-target lines above. Any 'http=' line means the");
            println!("WS upgrade reached the edge (worker-path issue). A 'TLS ok, but reset");
            println!("after upgrade' line means DPI blocks the WS upgrade.");
            Ok(())
        }
    }
}

/// `dastyab beacon …` — remote push notifications.
async fn cmd_beacon(profile: &str, action: crate::BeaconAction) -> Result<(), CFError> {
    use dastyab_core::remote_beacon::BeaconKind;
    match action {
        crate::BeaconAction::Status => {
            let cfg = dastyab_core::remote_beacon::load_config(profile);
            println!("Notification config (profile {profile}):");
            println!("  enabled:      {}", cfg.enabled);
            println!(
                "  channel:      {}",
                match cfg.kind {
                    BeaconKind::Telegram => "Telegram",
                    BeaconKind::GenericWebhook => "Webhook",
                }
            );
            if !cfg.token.is_empty() {
                println!("  telegram token: [set]");
            } else {
                println!("  telegram token: [unset]");
            }
            println!("  target:       {}", cfg.chat_id_or_url);
            println!("  rate limit:   {}s/event class", cfg.rate_limit_secs);
            let queued = dastyab_core::remote_beacon::load_outbox(profile).len();
            println!(
                "  outbox:       {} queued alert(s) awaiting delivery",
                queued
            );
            println!("  ---");
            println!("  configure:   dastyab beacon telegram <token> <chat-id>");
            println!("               dastyab beacon webhook <url>");
            println!("  enable:      dastyab beacon enable");
            println!("  flush:       dastyab beacon flush  (deliver queued alerts now)");
            Ok(())
        }
        crate::BeaconAction::Enable => {
            let mut cfg = dastyab_core::remote_beacon::load_config(profile);
            if cfg.chat_id_or_url.is_empty() {
                return Err(CFError::new(
                    "Beacon",
                    "No channel configured.",
                    "Run `dastyab beacon telegram|webhook …` first.",
                ));
            }
            cfg.enabled = true;
            save_beacon(profile, &cfg)?;
            println!("Notifications ENABLED for profile {profile}.");
            Ok(())
        }
        crate::BeaconAction::Disable => {
            let mut cfg = dastyab_core::remote_beacon::load_config(profile);
            cfg.enabled = false;
            save_beacon(profile, &cfg)?;
            println!("Notifications disabled for profile {profile}.");
            Ok(())
        }
        crate::BeaconAction::Telegram { token, chat_id } => {
            let mut cfg = dastyab_core::remote_beacon::load_config(profile);
            cfg.kind = BeaconKind::Telegram;
            cfg.token = token;
            cfg.chat_id_or_url = chat_id;
            save_beacon(profile, &cfg)?;
            println!(
                "Telegram channel configured (notifications still disabled — run `beacon enable`)."
            );
            Ok(())
        }
        crate::BeaconAction::Webhook { url } => {
            let mut cfg = dastyab_core::remote_beacon::load_config(profile);
            cfg.kind = BeaconKind::GenericWebhook;
            cfg.token.clear();
            cfg.chat_id_or_url = url;
            save_beacon(profile, &cfg)?;
            println!(
                "Webhook channel configured (notifications still disabled — run `beacon enable`)."
            );
            Ok(())
        }
        crate::BeaconAction::RateLimit { secs } => {
            let mut cfg = dastyab_core::remote_beacon::load_config(profile);
            cfg.rate_limit_secs = secs.max(1);
            save_beacon(profile, &cfg)?;
            println!("Rate limit set to {}s/event class.", cfg.rate_limit_secs);
            Ok(())
        }
        crate::BeaconAction::Test => {
            let cfg = dastyab_core::remote_beacon::load_config(profile);
            if cfg.chat_id_or_url.is_empty() {
                return Err(CFError::new(
                    "Beacon",
                    "No channel configured.",
                    "Run `dastyab beacon telegram|webhook …` first.",
                ));
            }
            let msg = "✅ DastYab test notification — protection is working.";
            dastyab_core::remote_beacon::send(&cfg, msg).await?;
            println!("Test message sent.");
            Ok(())
        }
        crate::BeaconAction::Flush => {
            let queued = dastyab_core::remote_beacon::load_outbox(profile).len();
            if queued == 0 {
                println!("Outbox is empty — nothing to flush.");
                return Ok(());
            }
            let sent = dastyab_core::remote_beacon::flush_outbox(profile).await;
            let remaining = dastyab_core::remote_beacon::load_outbox(profile).len();
            println!("Flushed {sent}/{queued} queued alert(s); {remaining} still queued.");
            Ok(())
        }
    }
}

fn cmd_aistudio(action: &str) -> Result<(), CFError> {
    // Delegate to the verified, self-healing Python bridge (project-local).
    // The Python tool owns the xray tunnel + watchdog; this is a thin wrapper.
    let script = "/home/amir/Projects/dastyab/dastyab-aistudio.py";
    let action = action.trim().to_lowercase();

    // Normalize a few natural spellings.
    let action = match action.as_str() {
        "start" | "on" | "up" | "open" => "start".to_string(),
        "stop" | "off" | "down" => "stop".to_string(),
        "watch" | "watchdog" | "guard" => "watch".to_string(),
        "verify" | "status" => "verify".to_string(),
        other => other.to_string(),
    };

    let mut cmd = std::process::Command::new("python3");
    cmd.arg(script).arg(&action);
    let out = cmd.output().map_err(|e| {
        CFError::new(
            "Aistudio launch failed",
            format!("Could not run {script}: {e}"),
            "Make sure python3 and the dastyab-aistudio.py script exist.",
        )
    })?;

    print!("{}", String::from_utf8_lossy(&out.stdout));
    if !out.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&out.stderr));
    }

    if !out.status.success() {
        return Err(CFError::new(
            "Aistudio returned an error",
            format!("exit code {:?}", out.status.code()),
            "Check the tunnel / server pool status.",
        ));
    }
    Ok(())
}

/// Execute the doctrine A+D platform network rules (anti-loop fwmark
/// routing + TCP MSS clamp). Supports:
///   dastyab platform plan       -- just print what would run (dry-run)
/// Pass `--dry-run` to preview any action without touching the system.
fn cmd_platform(action: &str, dry_run: bool, mtu: u32) -> Result<(), CFError> {
    let action = action.trim().to_lowercase();
    let mut ex = dastyab_core::platform_linux::PlatformExecutor::new(dry_run);

    match action.as_str() {
        "apply" | "on" | "up" => {
            let routing = ex.apply_routing_policy(dastyab_core::tun_route::TUN_FWMARK)?;
            let clamp = ex.apply_mss_clamp(mtu)?;
            println!(
                "[platform] applied {} routing rule(s) + {} mss clamp rule(s) (mtu={mtu})",
                routing.plan.install.len(),
                clamp.plan.install.len()
            );
            if dry_run {
                println!("[platform] --dry-run enabled; no system changes were made.");
                for c in &ex.log {
                    println!("  would run: {c}");
                }
            }
            Ok(())
        }
        "teardown" | "off" | "down" => {
            // Re-plan so install commands are empty, then run uninstall:
            // discover current state, plan with it, run the *uninstall* side.
            let existing_marks = ex.discover_existing_fwmarks()?;
            let routing_plan = dastyab_core::tun_route::plan_anti_loop(
                dastyab_core::tun_route::TUN_FWMARK,
                &existing_marks,
            );
            ex.teardown_routing(&routing_plan)?;

            let existing_clamps = ex.discover_existing_clamps()?;
            let clamp_plan = dastyab_core::tun_mtu::plan_mss_clamp_fixed(mtu, &existing_clamps);
            ex.teardown_clamp(&clamp_plan)?;

            println!("[platform] teardown complete (mtu={mtu}).");
            if dry_run {
                for c in &ex.log {
                    println!("  would run: {c}");
                }
            }
            Ok(())
        }
        "plan" | "preview" => {
            // Force dry-run semantics for a pure preview.
            ex = dastyab_core::platform_linux::PlatformExecutor::new(true);
            let routing = ex.apply_routing_policy(dastyab_core::tun_route::TUN_FWMARK)?;
            let clamp = ex.apply_mss_clamp(mtu)?;
            #[allow(clippy::needless_range_loop)]
            for c in &routing.commands {
                println!("{c}");
            }
            #[allow(clippy::needless_range_loop)]
            for c in &clamp.commands {
                println!("{c}");
            }
            if routing.plan.install.is_empty() && clamp.plan.install.is_empty() {
                println!("[platform] nothing to do (rules already present).");
            }
            Ok(())
        }
        _ => Err(CFError::new(
            "platform",
            format!("unknown action {action:?}"),
            "Use: apply | teardown | plan",
        )),
    }
}

/// Multipath ARQ packet-bond self-test (doctrine §8.2). Runs an adversarial
/// lossy-lane simulation and reports that every frame was delivered in order.
fn cmd_bond(action: &str, frames: usize) -> Result<(), CFError> {
    let action = action.trim().to_lowercase();
    match action.as_str() {
        "selftest" => {
            use dastyab_core::multipath_bond::{
                BondPolicy, LaneId, MultipathBonder, SubmitResult,
            };
            use rand::Rng;
            use std::time::Duration;

            let loss = 0.35f64;
            let lanes = [LaneId(0), LaneId(1), LaneId(2)];
            let mut bond =
                MultipathBonder::new(&lanes, BondPolicy::Stripe, 64, Duration::from_millis(30));
            // Per-lane lossy channel queues (lane-local ARQ seqno -> bytes).
            let mut ch: Vec<Vec<(u16, Vec<u8>)>> = vec![Vec::new(); lanes.len()];
            let mut delivered = 0u64;
            let mut expected = 0u64;
            let mut rng = rand::thread_rng();

            for _ in 0..1200 {
                // Submit as many as the window allows.
                while expected < frames as u64 {
                    let payload = format!("bond-frame-{expected}").into_bytes();
                    if !matches!(bond.submit(payload), SubmitResult::Accepted { .. }) {
                        break;
                    }
                    expected += 1;
                }
                // Drain each lane into its lossy channel.
                for (li, &lane) in lanes.iter().enumerate() {
                    for (seq, bytes) in bond.drain_outgoing(lane) {
                        if rng.gen::<f64>() > loss {
                            ch[li].push((seq.0, bytes));
                        }
                    }
                }
                // Deliver what got through (any lane).
                for (li, &lane) in lanes.iter().enumerate() {
                    let q = std::mem::take(&mut ch[li]);
                    for (seq, bytes) in q {
                        let _ = bond.on_lane_frame(lane, dastyab_core::arq::Seqno(seq), &bytes);
                    }
                }
                // ACK back on each lane.
                for &lane in &lanes {
                    if let Some((cum, sack)) = bond.lane_ack(lane) {
                        bond.on_lane_ack(lane, cum, sack);
                    }
                }
                // Retransmit timed-out frames back into their own lane channels.
                // The loop runs faster than the real RTO, so use a synthetic
                // clock well past the timeout to force retransmission.
                let clock = std::time::Instant::now() + Duration::from_millis(500);
                for (li, &lane) in lanes.iter().enumerate() {
                    for s in bond.pending_retransmits(lane, clock) {
                        if let Some(bytes) = bond.retransmit(lane, s) {
                            if rng.gen::<f64>() > loss {
                                ch[li].push((s.0, bytes));
                            }
                        }
                    }
                }
                // Verify ordered delivery.
                for (seq, _) in bond.take_delivered() {
                    if seq != delivered {
                        return Err(CFError::new(
                            "bond",
                            format!("selftest ordering violation: got {seq}, expected {delivered}"),
                            "multipath bond reassembly",
                        ));
                    }
                    delivered += 1;
                }
                if delivered >= frames as u64 {
                    break;
                }
            }

            if delivered < frames as u64 {
                return Err(CFError::new(
                    "bond",
                    format!("selftest incomplete: {delivered}/{frames} frames delivered"),
                    "multipath bond under loss",
                ));
            }
            println!(
                "[bond] selftest OK: {frames} frames delivered in order across {} lossy lanes ({loss:.0}% loss per lane)",
                lanes.len()
            );
            Ok(())
        }
        other => Err(CFError::new(
            "bond",
            format!("unknown action {other:?}"),
            "Use: bond selftest",
        )),
    }
}

/// Lifeline tunnel: run a local xray egress from the best healthy config on a
/// SOCKS5 proxy (127.0.0.1:10853). This is the "use the configs yourself when
/// the managed egress is down" escape hatch (doctrine §2/§8.x).
async fn cmd_lifeline(action: &str, profile: &str) -> Result<(), CFError> {
    use dastyab_core::tunnel_lifeline::{
        is_port_open, lifeline_status, pool_summary, spawn_lifeline, stop_lifeline,
        LIFELINE_SOCKS_PORT,
    };

    let action = action.trim().to_lowercase();
    match action.as_str() {
        "start" => {
            let report = spawn_lifeline(profile).await;
            if report.up {
                println!("lifeline: up (SOCKS5 127.0.0.1:{LIFELINE_SOCKS_PORT})");
                println!("lifeline: node = {}", report.node.unwrap_or_default());
            } else {
                println!(
                    "lifeline: FAILED (node={}, error={})",
                    report.node.unwrap_or_default(),
                    report.error.as_deref().unwrap_or("unknown")
                );
            }
            Ok(())
        }
        "stop" => {
            stop_lifeline(profile);
            println!("lifeline: stop requested");
            Ok(())
        }
        "status" => {
            let report = lifeline_status(profile).await;
            let up = is_port_open(LIFELINE_SOCKS_PORT).await;
            let (total, vless) = pool_summary(profile);
            println!("lifeline: up={up} (SOCKS5 127.0.0.1:{LIFELINE_SOCKS_PORT})");
            println!("lifeline: node = {}", report.node.unwrap_or_default());
            println!("lifeline: pool = {total} nodes, {vless} vless");
            Ok(())
        }
        other => Err(CFError::new(
            "Lifeline",
            format!("unknown action '{other}'"),
            "Use start | stop | status.",
        )),
    }
}

/// Level-4 intranet P2P LAN mesh (PRINCIPLES §3 Level 4). Discovers other
/// DastYab instances on the local network and reports the best relay
/// candidate (a peer with a live upstream uplink).
fn cmd_mesh(
    action: &str,
    window: u64,
    upstream: bool,
    name: &str,
    url: &str,
) -> Result<(), CFError> {
    use dastyab_core::lan_mesh;
    let action = action.trim().to_lowercase();
    let now = dastyab_core::store::profiles::now_ts() as u64;

    // Stable per-host peer id (hostname). Good enough for a beacon identity on
    // a private LAN; the daemon can substitute its own UUID.
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "dastyab".to_string());
    let label = if name.is_empty() {
        host.clone()
    } else {
        name.to_string()
    };

    match action.as_str() {
        "discover" => {
            println!(
                "[mesh] sweeping LAN for {}s (window={window}s)…",
                lan_mesh::UDP_PORT
            );
            let (table, heard) = lan_mesh::discover_once(&host, &label, upstream, window, now);
            let live = table.live(now);
            println!(
                "[mesh] heard {heard} datagram(s), {} live peer(s)",
                live.len()
            );
            for n in &live {
                println!(
                    "  {} @ {}  uplink={} rtt={}ms last_seen={}s ago",
                    n.name,
                    n.addr,
                    if n.has_uplink { "yes" } else { "no" },
                    n.rtt_ms,
                    now.saturating_sub(n.last_seen_unix)
                );
            }
            match table.best_relay(now) {
                Some(b) => println!(
                    "[mesh] best relay candidate: {} @ {} (uplink, rtt={}ms)",
                    b.name, b.addr, b.rtt_ms
                ),
                None => println!("[mesh] no relay candidate with a live upstream uplink found"),
            }
            Ok(())
        }
        "listen" => {
            let table = lan_mesh::NeighborTable::new();
            let _ = lan_mesh::broadcast_beacon(
                std::net::SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0),
                std::net::Ipv4Addr::new(255, 255, 255, 255),
                &lan_mesh::Beacon::new(&host, &label, upstream),
            );
            println!("[mesh] listening for beacons for {window}s (ctr-c to stop)…");
            let heard = lan_mesh::listen_once(
                std::net::SocketAddr::new(
                    std::net::Ipv4Addr::UNSPECIFIED.into(),
                    lan_mesh::UDP_PORT,
                ),
                &table,
                window,
                now,
            )
            .unwrap_or(0);
            table.forget(&host);
            println!("[mesh] heard {heard} beacon(s)");
            for n in table.live(now) {
                println!(
                    "  {} @ {}  uplink={} rtt={}ms",
                    n.name,
                    n.addr,
                    if n.has_uplink { "yes" } else { "no" },
                    n.rtt_ms
                );
            }
            Ok(())
        }
        "relay" => {
            let (table, heard) = lan_mesh::discover_once(&host, &label, upstream, window, now);
            match table.best_relay(now) {
                Some(b) => {
                    println!(
                        "[mesh] relay candidate: {} @ {}",
                        b.name, b.addr
                    );
                    println!("[mesh] heard {heard} datagram(s)");
                    // Verify the hop: probe the candidate's relay port and
                    // measure RTT through it. A successful echo turns the
                    // candidate into a verified, usable hop.
                    let timeout = std::time::Duration::from_secs(lan_mesh::NEIGHBOR_TIMEOUT_SECS);
                    match dastyab_core::mesh_relay::echo_probe(b.addr, timeout) {
                        Ok(Some(rtt_ms)) => {
                            table.observe_rtt(&b.peer_id, rtt_ms);
                            println!(
                                "[mesh] relay verified @ {} (hop rtt={rtt_ms}ms) — usable as a local egress hop",
                                b.addr
                            );
                            Ok(())
                        }
                        Ok(None) => Err(CFError::new(
                            "mesh",
                            format!(
                                "relay candidate {} @ {} did NOT answer the hop probe (no relay listener on its relay port)",
                                b.name, b.addr
                            ),
                            "Start `dastyab mesh serve --upstream` on the peer (or check the relay port), then retry.",
                        )),
                        Err(e) => Err(CFError::new(
                            "mesh",
                            format!("relay probe failed for {} @ {}: {e}", b.name, b.addr),
                            "Is the peer reachable and its relay port open?",
                        )),
                    }
                }
                None => Err(CFError::new(
                    "mesh",
                    format!("no relay candidate found (heard {heard} datagram(s))"),
                    "Ensure another DastYab instance with a live uplink runs on this LAN, then retry.",
                )),
            }
        }
        "serve" => {
            println!(
                "[mesh] hosting relay listener on UDP {} for {window}s (ctr-c to stop)…",
                lan_mesh::UDP_PORT
            );
            let bind = std::net::SocketAddr::new(
                std::net::Ipv4Addr::UNSPECIFIED.into(),
                lan_mesh::UDP_PORT,
            );
            // When we advertise an uplink, actually serve data forwarding
            // through our own working egress (so peers can hop through us).
            // Otherwise we answer echo probes only (verify hop connectivity).
            // NOTE: the real egress uses reqwest::blocking (a tokio runtime
            // inside), so it must run on a dedicated OS thread — never inside
            // the CLI's async runtime (dropping a runtime in an async context
            // panics).
            let handle = std::thread::spawn(move || {
                if upstream {
                    let egress = dastyab_core::mesh_relay::RealRelayEgress::default();
                    dastyab_core::mesh_relay::serve_with_egress(bind, window, &egress)
                } else {
                    dastyab_core::mesh_relay::serve_with_egress(
                        bind,
                        window,
                        &dastyab_core::mesh_relay::NoopEgress,
                    )
                }
            });
            let out = handle
                .join()
                .unwrap_or_else(|_| Err(std::io::Error::other("relay listener thread panicked")));
            match out {
                Ok((answered, forwarded)) => {
                    println!(
                        "[mesh] relay listener stopped; answered {answered} hop probe(s), forwarded {forwarded} data frame(s)"
                    );
                    Ok(())
                }
                Err(e) => Err(CFError::new(
                    "mesh",
                    format!("relay listener failed: {e}"),
                    format!("Is UDP port {} already bound?", lan_mesh::UDP_PORT),
                )),
            }
        }
        "forward" => {
            if url.is_empty() {
                return Err(CFError::new(
                    "mesh",
                    "forward requires --url to fetch through the mesh relay",
                    "Example: dastyab mesh forward --url https://example.com/",
                ));
            }
            let (table, heard) = lan_mesh::discover_once(&host, &label, upstream, window, now);
            match table.best_relay(now) {
                Some(b) => {
                    let timeout = std::time::Duration::from_secs(lan_mesh::NEIGHBOR_TIMEOUT_SECS);
                    // Verify the hop first (echo), then fetch through it.
                    match dastyab_core::mesh_relay::echo_probe(b.addr, timeout) {
                        Ok(Some(rtt_ms)) => {
                            table.observe_rtt(&b.peer_id, rtt_ms);
                            println!(
                                "[mesh] relay verified @ {} (hop rtt={rtt_ms}ms), forwarding {url}…",
                                b.addr
                            );
                            let req = dastyab_core::mesh_relay::EgressRequest {
                                method: "GET".to_string(),
                                url: url.to_string(),
                                body: Vec::new(),
                            };
                            match dastyab_core::mesh_relay::forward_data(b.addr, &req, timeout) {
                                Ok(dastyab_core::mesh_relay::ForwardOutcome::Ok(reply)) => {
                                    let body = String::from_utf8_lossy(&reply.body);
                                    println!(
                                        "[mesh] hop reply: HTTP {} ({} bytes)\n{}",
                                        reply.status,
                                        reply.body.len(),
                                        if body.len() > 500 {
                                            format!("{}…", &body[..500])
                                        } else {
                                            body.to_string()
                                        }
                                    );
                                    Ok(())
                                }
                                Ok(dastyab_core::mesh_relay::ForwardOutcome::Error(e)) => Err(
                                    CFError::new("mesh", format!("relay forward failed: {e}"), ""),
                                ),
                                Err(e) => Err(CFError::new(
                                    "mesh",
                                    format!("relay forward socket error: {e}"),
                                    "",
                                )),
                            }
                        }
                        Ok(None) => Err(CFError::new(
                            "mesh",
                            format!(
                                "relay candidate {} @ {} did NOT answer the hop probe (no relay listener on its relay port)",
                                b.name, b.addr
                            ),
                            "Start `dastyab mesh serve --upstream` on the peer (or check the relay port), then retry.",
                        )),
                        Err(e) => Err(CFError::new(
                            "mesh",
                            format!("relay probe failed for {} @ {}: {e}", b.name, b.addr),
                            "Is the peer reachable and its relay port open?",
                        )),
                    }
                }
                None => Err(CFError::new(
                    "mesh",
                    format!("no relay candidate found (heard {heard} datagram(s))"),
                    "Ensure another DastYab instance with a live uplink runs on this LAN, then retry.",
                )),
            }
        }
        other => Err(CFError::new(
            "mesh",
            format!("unknown action {other:?}"),
            "Use: discover | listen | relay | serve | forward",
        )),
    }
}

/// Manage native config-storage nodes: import from a v2rayN ServersStore.json,
/// paste a single vless link, list nodes, activate one, probe health, fail
/// over, or run a full self-heal pass (refilling an empty pool from Telegram).
async fn cmd_configs(
    profile: &str,
    action: &str,
    path: &str,
    link: &str,
    proxy: bool,
    channels: &str,
    depth: usize,
) -> Result<(), CFError> {
    use dastyab_core::config_store::{
        import_single_link, import_v2rayn_store, load_node_store, render_nodes, save_node_store,
    };

    match action {
        "import" => {
            if path.is_empty() {
                return Err(CFError::new(
                    "configs",
                    "import requires --path to a v2rayN ServersStore.json.",
                    "Example: dastyab configs import --path ~/.config/v2rayN/Local/ServersStore.json",
                ));
            }
            if !std::path::Path::new(path).exists() {
                return Err(CFError::new(
                    "configs",
                    format!("file not found: {path}"),
                    "Check the path; v2rayN stores it under ~/.config/v2rayN/Local/.",
                ));
            }
            let s = import_v2rayn_store(profile, std::path::Path::new(path))?;
            println!(
                "[configs] imported from {path}: found={} added={} duplicates={} invalid={} non-vless={}",
                s.found, s.added, s.duplicates, s.skipped_invalid, s.skipped_non_vless
            );
            println!("{}", render_nodes(profile));
            Ok(())
        }
        "paste" => {
            if link.is_empty() {
                return Err(CFError::new(
                    "configs",
                    "paste requires --link with a vless:// share link.",
                    "Example: dastyab configs paste --link 'vless://...'",
                ));
            }
            let s = import_single_link(profile, link)?;
            println!(
                "[configs] pasted link: added={} duplicates={}",
                s.added, s.duplicates
            );
            println!("{}", render_nodes(profile));
            Ok(())
        }
        "activate" => {
            let mut store = load_node_store(profile);
            if store.nodes.is_empty() {
                return Err(CFError::new(
                    "configs",
                    "no nodes to activate — import a ServersStore.json or paste a link first.",
                    "Run: dastyab configs import --path ... or dastyab configs paste --link 'vless://...'.",
                ));
            }
            let target = if link.is_empty() {
                // Activate the first node.
                store.nodes[0].id.clone()
            } else if store.get(link).is_some() {
                link.to_string()
            } else {
                // Treat the arg as a share link to match by URL.
                let url = link;
                match store.nodes.iter().find(|n| n.url == url) {
                    Some(n) => n.id.clone(),
                    None => {
                        return Err(CFError::new(
                            "configs",
                            "no node matches --link (either an id or an exact vless URL).",
                            "List nodes first with: dastyab configs list",
                        ));
                    }
                }
            };
            if store.set_active(&target) {
                save_node_store(profile, &store)?;
                println!("[configs] activated node {target}");
            } else {
                println!("[configs] node {target} not found");
            }
            Ok(())
        }
        "list" => {
            println!("{}", render_nodes(profile));
            Ok(())
        }
        "clear" => {
            let empty = dastyab_core::config_store::NodeStore::default();
            save_node_store(profile, &empty)?;
            println!("[configs] cleared all nodes in profile '{profile}'");
            Ok(())
        }
        "probe" => {
            use dastyab_core::node_probe::{probe_all, NodeProbe};
            let reports = probe_all(profile, proxy);
            if reports.is_empty() {
                println!("[configs] no nodes in profile '{profile}' to probe");
                return Ok(());
            }
            let mut ok = 0usize;
            let mut fail = 0usize;
            println!(
                "[configs] probing {} node(s) (proxy={proxy})",
                reports.len()
            );
            for r in &reports {
                match r {
                    NodeProbe {
                        ok: true,
                        ms,
                        alias,
                        ..
                    } => {
                        ok += 1;
                        println!("  [OK]   {alias} ({ms} ms)");
                    }
                    NodeProbe {
                        ok: false,
                        error: Some(e),
                        alias,
                        ..
                    } => {
                        fail += 1;
                        println!("  [FAIL] {alias}: {e}");
                    }
                    NodeProbe {
                        ok: false, alias, ..
                    } => {
                        fail += 1;
                        println!("  [FAIL] {alias}: connection failed");
                    }
                }
            }
            println!("[configs] probe done: {ok} healthy, {fail} unhealthy");
            Ok(())
        }
        "verify-egress" => {
            use dastyab_core::config_store::{load_node_store, save_node_store};
            use dastyab_core::tunnel_lifeline::deep_verify_egress;
            let store = load_node_store(profile);
            let mut candidates: Vec<_> = store
                .nodes
                .iter()
                .filter(|n| n.healthy != Some(false))
                .take(6)
                .cloned()
                .collect();
            if candidates.is_empty() {
                println!("[configs] no nodes to deep-verify (import nodes first)");
                return Ok(());
            }
            println!(
                "[configs] deeply verifying real egress for {} node(s)…",
                candidates.len()
            );
            let mut ok = 0usize;
            for node in &mut candidates {
                let r = deep_verify_egress(profile, node).await;
                let mut s = load_node_store(profile);
                if let Some(n) = s.nodes.iter_mut().find(|n| n.id == node.id) {
                    n.healthy = Some(r.ok);
                    n.last_checked_epoch = Some(dastyab_core::store::now_ts());
                }
                let _ = save_node_store(profile, &s);
                if r.ok {
                    ok += 1;
                    println!("  [OK]   {} (real egress)", r.alias);
                } else {
                    println!(
                        "  [FAIL] {}: {}",
                        r.alias,
                        r.error.clone().unwrap_or_default()
                    );
                }
            }
            println!("[configs] deep egress verify done: {ok} verified working");
            Ok(())
        }
        "failover" => {
            use dastyab_core::node_probe::failover_if_dead;
            match failover_if_dead(profile) {
                Some(id) => {
                    println!("[configs] active node was unhealthy — promoted healthy node '{id}'")
                }
                None => {
                    let store = load_node_store(profile);
                    match store.active() {
                        Some(a) if a.healthy == Some(true) => {
                            println!("[configs] active node '{}' is healthy; no failover needed", a.id)
                        }
                        _ => println!(
                            "[configs] no healthy node available to fail over to (run 'nodes probe' first)"
                        ),
                    }
                }
            }
            Ok(())
        }
        "selfheal" => {
            use dastyab_core::node_probe::selfheal;
            // If the pool is empty (or has no healthy node) and the caller
            // supplied channels, refill from Telegram first, then probe.
            let store = load_node_store(profile);
            let pool_empty = store.nodes.is_empty();
            let no_healthy = store.nodes.iter().all(|n| n.healthy != Some(true));
            let chan_list: Vec<String> = channels
                .split(',')
                .map(|c| c.trim().to_string())
                .filter(|c| !c.is_empty())
                .collect();
            if (pool_empty || no_healthy) && !chan_list.is_empty() {
                println!(
                    "[configs] pool {} — harvesting {} channel(s) to refill (incl. saved)",
                    if pool_empty {
                        "empty"
                    } else {
                        "has no healthy node"
                    },
                    chan_list.len()
                );
                cmd_harvest(
                    profile,
                    channels,
                    proxy,
                    depth,
                    false,
                    DiscoverOpts {
                        save: false,
                        hops: 1,
                        max_candidates: 60,
                    },
                    true,
                )
                .await?;
            }

            let rep = selfheal(profile, proxy);
            if rep.probed == 0 {
                println!(
                    "[configs] selfheal: no nodes in profile '{profile}' (harvest or import first)"
                );
                return Ok(());
            }
            println!(
                "[configs] selfheal: {probed} probed, {healthy} healthy, {unhealthy} unhealthy",
                probed = rep.probed,
                healthy = rep.healthy,
                unhealthy = rep.unhealthy,
            );
            match &rep.promoted {
                Some(id) => println!("[configs]   → failed over to healthy node '{id}'"),
                None if rep.active_was_healthy => {
                    println!("[configs]   active node healthy — no failover needed");
                }
                None => {
                    println!("[configs]   active node unchanged (no healthy candidate)");
                }
            }
            Ok(())
        }
        "refill" => {
            use dastyab_core::node_refill;
            // Autonomous recovery: if the pool has no known-healthy config,
            // deep-harvest Telegram archives + GitHub config repos, then probe
            // and fail over. The `channels`/`depth` overrides are honored
            // when supplied (CLI), otherwise the module defaults (curated
            // channels, deep crawl) apply.
            let depth_override = if depth > 0 {
                depth
            } else {
                node_refill::DEFAULT_REFILL_DEPTH
            };
            let report = node_refill::run_refill_depth(profile, proxy, depth_override).await;
            if !report.needed {
                println!(
                    "[configs] refill: pool already has a known-healthy node — nothing to recover"
                );
                return Ok(());
            }
            println!(
                "[configs] refill (reason: {}):",
                report.reason.as_deref().unwrap_or("pool degraded")
            );
            println!(
                "  telegram: {} channel(s), found={} added={}",
                report.telegram_channels, report.telegram_found, report.telegram_added
            );
            println!(
                "  github  : {} repo(s) ok, added={}",
                report.github_repos_ok, report.github_added
            );
            println!(
                "  ct-anchor: added={} (out-of-band reseed)",
                report.ct_reseed_added
            );
            println!(
                "  probe   : {} probed, {} healthy",
                report.probed, report.healthy
            );
            match &report.promoted {
                Some(id) => println!("  → failed over to healthy node '{id}'"),
                None => println!("  active node unchanged (no healthy candidate)"),
            }
            Ok(())
        }
        "export-v2rayn" => {
            use dastyab_core::config_store::export_v2rayn_store;
            let target = if path.is_empty() {
                let home = std::env::var("HOME").unwrap_or_default();
                format!("{home}/.config/v2rayN/Local/ServersStore.json")
            } else {
                path.to_string()
            };
            let (added, dups) =
                export_v2rayn_store(profile, std::path::Path::new(&target), true)?;
            println!(
                "[configs] exported healthy nodes to {target}: added={} duplicates-skipped={}",
                added, dups
            );
            Ok(())
        }
        _ => Err(CFError::new(
            "configs",
            format!("unknown action {action:?}"),
            "Use: import | paste | activate | list | clear | probe | failover | selfheal | refill | export-v2rayn",
        )),
    }
}

fn save_beacon(profile: &str, cfg: &BeaconConfig) -> Result<(), CFError> {
    let mut p = load_profile(profile);
    p.config.beacon = Some(cfg.clone());
    dastyab_core::store::profiles::save_profile(&p)
}

/// One-command DNS tunnel deploy to a VPS (total-blackout survival).
async fn cmd_dns_tunnel(profile: &str, action: crate::DnsTunnelAction) -> Result<(), CFError> {
    use dastyab_core::vps_deploy as vps;
    use dastyab_core::vps_provision as vp;
    match action {
        crate::DnsTunnelAction::Status => {
            if vps::is_dns_tunnel_configured(profile) {
                if let Some(cfg) = vps::load_tunnel_client_config(profile) {
                    println!("DNS tunnel deployed for profile '{profile}':");
                    println!("  host        : {}", cfg.host);
                    println!("  base domain : {}", cfg.base_domain);
                    println!("  resolver    : {}", cfg.resolver);
                }
            } else {
                println!(
                    "No DNS tunnel configured for profile '{profile}'. Run: dastyab dns-tunnel deploy"
                );
            }
            Ok(())
        }
        crate::DnsTunnelAction::Provision {
            api_token,
            location,
            server_type,
            domain,
            ssh_key,
            ssh_user,
        } => {
            let creds = vp::HetznerCredentials {
                api_token,
                location,
                server_type,
                server_name: "dastyab-tunnel".into(),
            };
            if !creds.is_complete() {
                return Err(CFError::new(
                    "dns-tunnel",
                    "missing Hetzner API token",
                    "Provide --api-token (read/write Hetzner Cloud token).",
                ));
            }
            if domain.trim().is_empty() {
                return Err(CFError::new(
                    "dns-tunnel",
                    "missing --domain",
                    "Provide the base DNS domain the tunnel server will answer for.",
                ));
            }
            // Expand ~ in the ssh-key path.
            let key_path = {
                let raw = shell_expand(&ssh_key);
                std::path::PathBuf::from(raw)
            };
            let api = vp::RealHetznerApi;
            println!(
                "Provisioning Hetzner VPS (location={}, type={}) ...",
                creds.location, creds.server_type
            );
            let prov = vp::provision_vps(&api, &creds, &key_path, None).await?;
            for step in &prov.completed_steps {
                println!("  ✓ {}", step.label());
            }
            println!("  VPS ready at {}", prov.host);
            // Now deploy the DNS tunnel to the fresh VPS.
            let vps_creds = vps::VpsCredentials {
                host: prov.host.clone(),
                ssh_user,
                ssh_key_path: prov.identity.private_key_path.clone(),
                ssh_port: 22,
            };
            let peer = vps::RealVpsSshPeer;
            println!("Deploying DNS tunnel to {} ...", prov.host);
            let res = vps::deploy_dns_tunnel(&vps_creds, &peer, profile, &domain, None).await?;
            for step in &res.completed_steps {
                println!("  ✓ {}", step.label());
            }
            if res.verified {
                println!("DNS tunnel deployed and verified. It will be used automatically when DoH/DoT fail.");
            } else {
                println!(
                    "Deploy completed but the tunnel service did not report active. Check the VPS."
                );
            }
            Ok(())
        }
        crate::DnsTunnelAction::Worker {
            worker_name,
            compat_date,
            vless_upstream,
        } => {
            let token = first_token(&load_profile(profile))?;
            let client = dastyab_core::cf::Client::new(&token);
            let accs = client.list_accounts().await?;
            let acc = accs.first().ok_or_else(|| {
                CFError::new(
                    "No account",
                    "No Cloudflare account accessible.",
                    "Check token permissions.",
                )
            })?;
            // Session seed for the secret + auto-name: profile + current time.
            let seed = format!(
                "dyb-cli-{profile}-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            );
            let opts = dastyab_core::worker_tunnel::WorkerTunnelDeployOpts {
                worker_name,
                session_seed: seed,
                compat_date,
                retries: 2,
                vless_upstream,
            };
            let res = dastyab_core::worker_tunnel::deploy_worker_tunnel(
                &client, &acc.id, profile, &opts,
            )
            .await?;
            println!("Worker DNS tunnel deployed:");
            println!("  worker      : {}", res.worker_name);
            println!("  url         : {}", res.worker_url);
            println!("  account id  : {}", res.account_id);
            println!("  subdomain   : {}", res.subdomain);
            if let Some(smoke) = &res.post_deploy_smoke {
                println!("  smoke       : {smoke}");
            } else {
                println!("  smoke       : (skipped on local/mock backend)");
            }
            println!("The fallback ladder will now probe this tunnel over HTTPS (no VPS).");
            Ok(())
        }
        crate::DnsTunnelAction::Test { host, port } => {
            if vps::probe_vps_reachable(&host, port) {
                println!("VPS {host}:{port} is reachable (TCP).");
                Ok(())
            } else {
                Err(CFError::new(
                    "dns-tunnel",
                    format!("VPS {host}:{port} is unreachable"),
                    "Check the host/IP and that the port is open.",
                ))
            }
        }
        crate::DnsTunnelAction::Selftest {
            domain,
            session,
            window,
            rto_ms,
            chunks,
        } => {
            use dastyab_core::dnstunnel_arq::DnsTunnelArq;
            use dastyab_core::resolve_pool::{ResolverPool, IRANIAN_RESOLVER_CANDIDATES};
            use std::time::Duration;

            // Build a live resolver: prefer the persisted blackout pool, else
            // sweep the built-in Iranian ISP seeds.
            let timeout = Duration::from_millis(2500);
            let pool = if let Some(cfg) = vps::load_tunnel_client_config("default") {
                if let Some(rp) = &cfg.resolver_pool {
                    if !rp.is_empty() {
                        Some(ResolverPool::new(rp.clone(), timeout))
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };
            let resolver = match pool {
                Some(p) => {
                    println!("[selftest] using persisted resolver pool");
                    p
                }
                None => {
                    println!("[selftest] no pool persisted; sweeping seeded resolvers ...");
                    let cands: Vec<String> = IRANIAN_RESOLVER_CANDIDATES
                        .iter()
                        .map(|s| s.to_string())
                        .collect();
                    let found = dastyab_core::resolve_pool::discover_open_resolvers(
                        &cands, 32, timeout, "",
                    )
                    .await;
                    if found.is_empty() {
                        return Err(CFError::new(
                            "dns-tunnel-selftest",
                            "no working resolver found",
                            "Run `dastyab dns-tunnel resolvers` first, or check connectivity.",
                        ));
                    }
                    println!("[selftest] discovered {} resolver(s)", found.len());
                    ResolverPool::new(found, timeout)
                }
            };

            let rto = Duration::from_millis(rto_ms);
            let mut tr = DnsTunnelArq::new(&resolver, &domain, &session, window, rto);
            let mut total = 0usize;
            for i in 0..chunks {
                let payload =
                    format!("selftest-chunk-{i:04}-{}-bytes", 32 + (i % 7) * 9).into_bytes();
                total += payload.len();
                tr.push(payload);
            }
            println!(
                "[selftest] sending {chunks} chunks ({total} bytes) via windowed ARQ DNS transport (window={window}, rto={rto_ms}ms)"
            );
            let mut st = dastyab_core::dnstunnel_arq::PumpStats::default();
            let mut delivered = 0usize;
            let mut pumps = 0usize;
            for _ in 0..4000 {
                let s = tr
                    .pump()
                    .await
                    .map_err(|e| CFError::new("dns-tunnel-selftest", format!("pump: {e}"), ""))?;
                st.sent += s.sent;
                st.retransmitted += s.retransmitted;
                st.acked += s.acked;
                delivered += tr.take_delivered().len();
                pumps += 1;
                if tr.is_idle() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            println!(
                "[selftest] pumps={pumps} sent={} retransmitted={} acked={}",
                st.sent, st.retransmitted, st.acked
            );
            if tr.is_idle() {
                println!("[selftest] OK — all {chunks} chunks acknowledged and delivered in-order (total {delivered})");
                Ok(())
            } else {
                Err(CFError::new(
                    "dns-tunnel-selftest",
                    format!(
                        "transport not idle after {pumps} pumps (inflight={})",
                        tr.inflight()
                    ),
                    "Resolver may be dropping all frames; check the base domain is delegated to the tunnel server.",
                ))
            }
        }
        crate::DnsTunnelAction::Resolvers {
            candidates,
            concurrency,
            timeout_ms,
        } => {
            use dastyab_core::resolve_pool::{
                discover_open_resolvers, IRANIAN_RESOLVER_CANDIDATES,
            };
            let cands: Vec<String> = match candidates {
                Some(s) if !s.trim().is_empty() => s
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect(),
                _ => IRANIAN_RESOLVER_CANDIDATES
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            };
            println!(
                "Scanning {} candidate resolver(s) (concurrency={}, timeout={}ms) ...",
                cands.len(),
                concurrency,
                timeout_ms
            );
            let timeout = std::time::Duration::from_millis(timeout_ms);
            let found = discover_open_resolvers(&cands, concurrency, timeout, "").await;
            let mut found = found;
            if found.is_empty() {
                // Fallback tier: a no working domestic resolver was discovered,
                // try the verified-live authoritative-nameserver anchors (doctrine
                // §8.1). Authoritative NS servers are stable and effectively
                // unblockable — blocking them would break all DNS — so they make
                // a resilient last-resort resolver set under total blackout.
                use dastyab_core::ns_anchors::anchor_ips;
                let ns_ips = anchor_ips(profile);
                if !ns_ips.is_empty() {
                    println!(
                        "No domestic resolvers live; falling back to {} verified NS-anchor IPs ...",
                        ns_ips.len()
                    );
                    let ns_live = discover_open_resolvers(&ns_ips, concurrency, timeout, "").await;
                    if !ns_live.is_empty() {
                        found = ns_live;
                    }
                }
            }
            if found.is_empty() {
                return Err(CFError::new(
                    "dns-tunnel",
                    "no working domestic resolvers found",
                    "Re-check the candidate list and that UDP 53 egress works from this network.",
                ));
            }
            println!("\n{} working resolver(s) found:", found.len());
            for r in &found {
                println!("  {r}");
            }
            // Persist as the profile's blackout resolver pool.
            let mut cfg = vps::load_tunnel_client_config(profile).unwrap_or_default();
            cfg.resolver_pool = Some(found);
            vps::write_tunnel_client_config(profile, &cfg)?;
            println!("\nPersisted resolver pool for profile '{profile}'.");
            println!("The blackout DNS tunnel will now recurse through these domestic");
            println!("resolvers instead of querying the VPS directly.");
            Ok(())
        }
        crate::DnsTunnelAction::Relay {
            worker_url,
            session_secret,
            bind,
            upstream,
        } => {
            use dastyab_core::worker_tunnel::data_relay::WorkerDataRelay;
            let relay = WorkerDataRelay::new(worker_url, session_secret, upstream);
            println!(
                "Starting data relay: {} → worker at {}",
                bind,
                relay.worker_url()
            );
            if let Some(u) = relay.upstream() {
                println!("  worker relays to upstream {u}");
            }
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            // Run forever; Ctrl-C ends the process naturally.
            relay.serve_local(&bind, Some(stop)).await?;
            Ok(())
        }
        crate::DnsTunnelAction::Deploy {
            host,
            ssh_user,
            ssh_key,
            ssh_port,
            domain,
        } => {
            let creds = vps::VpsCredentials {
                host,
                ssh_user,
                ssh_key_path: std::path::PathBuf::from(ssh_key),
                ssh_port,
            };
            if !creds.is_complete() {
                return Err(CFError::new(
                    "dns-tunnel",
                    "incomplete VPS credentials",
                    "Provide --host, --ssh-user, --ssh-key, and --domain.",
                ));
            }
            let peer = vps::RealVpsSshPeer;
            println!(
                "Deploying DNS tunnel to {}@{} ({}):",
                creds.ssh_user, creds.host, creds.ssh_port
            );
            let res = vps::deploy_dns_tunnel(&creds, &peer, profile, &domain, None).await?;
            for step in &res.completed_steps {
                println!("  ✓ {}", step.label());
            }
            if res.verified {
                println!("DNS tunnel deployed and verified. It will be used automatically when DoH/DoT fail.");
            } else {
                println!("Deploy completed but the tunnel service did not report active. Check the VPS manually.");
            }
            Ok(())
        }
    }
}

/// Tor anonymity-network CLI surface: start/stop/renew/status.
async fn cmd_tor(profile: &str, action: crate::TorAction) -> Result<(), CFError> {
    use dastyab_core::tor;
    match action {
        crate::TorAction::Start { socks_port } => {
            let opts = tor::TorOpts::new(profile.to_string(), socks_port);
            println!("Starting Tor (SOCKS5 on 127.0.0.1:{socks_port}) ...");
            tor::start(&opts).await
        }
        crate::TorAction::Stop => tor::stop(profile),
        crate::TorAction::Renew => tor::renew(profile).await,
        crate::TorAction::Status => tor::status(profile).await,
    }
}

/// Multi-worker parallel redundancy CLI surface.
async fn cmd_multi_worker(profile: &str, action: crate::MultiWorkerAction) -> Result<(), CFError> {
    use dastyab_core::multi_worker::{RealWorkerPeer, WorkerSet};
    match action {
        crate::MultiWorkerAction::Status => {
            let set: WorkerSet = dastyab_core::store::profiles::load_profile(profile)
                .config
                .worker_set;
            if set.is_empty() {
                println!(
                    "No worker set configured for profile '{profile}'. Run: dastyab multi-worker deploy --count 2"
                );
                return Ok(());
            }
            println!("Worker set for profile '{profile}':");
            for w in &set.workers {
                let marker = if w.active { "*" } else { " " };
                println!(
                    "  {marker} {} (host: {}, uuid: …{})",
                    w.name,
                    w.host,
                    w.uuid
                        .chars()
                        .rev()
                        .take(6)
                        .collect::<String>()
                        .chars()
                        .rev()
                        .collect::<String>()
                );
            }
            println!("(active worker marked with *)");
            Ok(())
        }
        crate::MultiWorkerAction::Deploy { count } => {
            let p = dastyab_core::store::profiles::load_profile(profile);
            let acc_id = if p.config.active_account.is_empty() {
                return Err(CFError::new(
                    "multi-worker",
                    "No active account.",
                    "Run `dastyab up` or set an active account first.",
                ));
            } else {
                p.config.active_account.clone()
            };
            let peer = RealWorkerPeer;
            println!("Deploying up to {count} workers in parallel...");
            let set = dastyab_core::multi_worker::deploy_worker_in_parallel(
                &peer,
                profile,
                &acc_id,
                "",
                count.max(1),
            )
            .await?;
            println!("Worker set now holds {} worker(s):", set.len());
            for w in &set.workers {
                println!("  - {} ({})", w.name, w.host);
            }
            Ok(())
        }
        crate::MultiWorkerAction::Failover => {
            let peer = RealWorkerPeer;
            let changed = dastyab_core::multi_worker::failover_worker_set(&peer, profile).await?;
            let set: WorkerSet = dastyab_core::store::profiles::load_profile(profile)
                .config
                .worker_set;
            if changed {
                println!(
                    "Failover: switched active worker to '{}'.",
                    set.active_worker()
                        .map(|w| w.name.as_str())
                        .unwrap_or("none")
                );
            } else {
                println!(
                    "Failover: active worker unchanged ('{}').",
                    set.active_worker()
                        .map(|w| w.name.as_str())
                        .unwrap_or("none")
                );
            }
            Ok(())
        }
        crate::MultiWorkerAction::SetActive { name } => {
            let mut p = dastyab_core::store::profiles::load_profile(profile);
            if p.config.worker_set.get(&name).is_none() {
                return Err(CFError::new(
                    "multi-worker",
                    format!("Worker '{name}' not in the set."),
                    "List workers with `dastyab multi-worker status`.",
                ));
            }
            p.config.worker_set.set_active(&name);
            dastyab_core::store::profiles::save_profile(&p)?;
            println!("Active worker set to '{name}'.");
            Ok(())
        }
        crate::MultiWorkerAction::Delete { name } => {
            use dastyab_core::multi_worker::RealWorkerPeer;
            let p = dastyab_core::store::profiles::load_profile(profile);
            let acc_id = if p.config.active_account.is_empty() {
                return Err(CFError::new(
                    "multi-worker",
                    "No active account.",
                    "Run `dastyab up` or set an active account first.",
                ));
            } else {
                p.config.active_account.clone()
            };
            let peer = RealWorkerPeer;
            let next = dastyab_core::multi_worker::delete_worker_from_set(
                &peer, profile, &acc_id, &name,
            )
            .await?;
            match next {
                Some(n) => println!("Deleted worker '{name}'. Active worker is now '{n}'."),
                None => println!("Deleted worker '{name}'. No workers remain in the set."),
            }
            Ok(())
        }
    }
}

/// Show / drain / clear the durable daemon journal.
fn cmd_journal(profile: &str, action: crate::JournalAction) -> Result<(), CFError> {
    match action {
        crate::JournalAction::Show { n } => {
            let entries = dastyab_core::journal::recent(profile, n);
            if entries.is_empty() {
                println!("Journal is empty for profile '{profile}'.");
                return Ok(());
            }
            println!("Journal for profile '{profile}' (newest first):");
            for e in &entries {
                println!("  [{}] {} — {}", fmt_ts(e.ts), kind_label(e.kind), e.detail);
            }
            Ok(())
        }
        crate::JournalAction::Pending => {
            let pending = dastyab_core::journal::pending_drain(profile);
            if pending.is_empty() {
                println!("No unresolved intents for profile '{profile}'.");
                return Ok(());
            }
            println!("Unresolved intents for profile '{profile}':");
            for e in &pending {
                println!("  [{}] {} — {}", fmt_ts(e.ts), kind_label(e.kind), e.detail);
            }
            Ok(())
        }
        crate::JournalAction::Clear => {
            dastyab_core::journal::clear(profile)?;
            println!("Journal cleared for profile '{profile}'.");
            Ok(())
        }
    }
}

/// Multi-layer tunnel: configure your final server (your own VPN / VLESS
/// egress), and test AI Studio + Gemini access through the full chain.
async fn cmd_multilayer(profile: &str, action: crate::MultilayerAction) -> Result<(), CFError> {
    use dastyab_core::multilayer as ml;
    match action {
        crate::MultilayerAction::Set {
            name,
            link,
            country,
        } => {
            let cfg = ml::FinalServerConfig {
                name,
                vless_link: link.clone(),
                country_hint: country,
            };
            // Validate the link parses.
            ml::parse_final_server(&cfg).map_err(|e| {
                CFError::new(
                    "multilayer",
                    format!("invalid final server link: {}", e.brief()),
                    "Provide a valid vless:// share link.",
                )
            })?;
            ml::save_final_server(profile, &cfg)?;
            println!("Final server saved for profile '{profile}':");
            println!("  name : {}", cfg.name);
            println!("  link : {}", cfg.vless_link);
            println!("To test egress: dastyab multilayer probe-ai");
            Ok(())
        }
        crate::MultilayerAction::Status => {
            if let Some(cfg) = ml::load_final_server(profile) {
                println!("Multi-layer tunnel for profile '{profile}':");
                println!("  final server : {}", cfg.name);
                println!("  link         : {}", cfg.vless_link);
                if !cfg.country_hint.is_empty() {
                    println!("  country hint : {}", cfg.country_hint);
                }
                let chain = ml::LayerKind::default_chain();
                let chain_txt = chain
                    .iter()
                    .map(|l| l.label())
                    .collect::<Vec<_>>()
                    .join(" → ");
                println!("  chain        : {chain_txt}");
                match ml::load_gemini_key(profile) {
                    Some(_) => println!("  gemini key   : stored (hidden)"),
                    None => {
                        println!("  gemini key   : not set — run `multilayer set-gemini-key <key>`")
                    }
                }
            } else {
                println!("No final server configured for profile '{profile}'.");
                println!("Run: dastyab multilayer set --link <vless://…>");
            }
            Ok(())
        }
        crate::MultilayerAction::Clear => {
            ml::clear_final_server(profile)?;
            println!("Final server cleared for profile '{profile}'.");
            Ok(())
        }
        crate::MultilayerAction::SetGeminiKey { key } => {
            if key.trim().is_empty() {
                return Err(CFError::new(
                    "multilayer",
                    "empty Gemini API key",
                    "Provide your Gemini API key.",
                ));
            }
            ml::save_gemini_key(profile, &key)?;
            println!("Gemini API key stored for profile '{profile}' (kept out of git).");
            Ok(())
        }
        crate::MultilayerAction::ProbeAi => {
            if ml::load_final_server(profile).is_none() {
                return Err(CFError::new(
                    "multilayer",
                    "no final server configured",
                    "Run `dastyab multilayer set --link <vless://…>` first.",
                ));
            }
            println!("Probing AI Studio + Gemini through the final-server chain…");
            let report = ml::probe_ai_access(profile).await?;
            for p in &report.probes {
                let status = if p.reachable {
                    "✓ reachable"
                } else {
                    "✗ blocked"
                };
                let ip = p.egress_ip.clone().unwrap_or_default();
                let ip_suffix = if ip.is_empty() {
                    String::new()
                } else {
                    format!(" (egress {ip})")
                };
                println!("  {:<10} {status}  {}{}", p.target, p.note, ip_suffix);
            }
            println!(
                "Verdict: {}",
                if report.ok {
                    "AI services reachable through the chain"
                } else {
                    "not reachable — check your final server"
                }
            );
            Ok(())
        }
        crate::MultilayerAction::Gemini { prompt } => {
            if ml::load_final_server(profile).is_none() {
                return Err(CFError::new(
                    "multilayer",
                    "no final server configured",
                    "Run `dastyab multilayer set --link <vless://…>` first.",
                ));
            }
            if ml::load_gemini_key(profile).is_none() {
                return Err(CFError::new(
                    "multilayer",
                    "no Gemini API key configured",
                    "Run `dastyab multilayer set-gemini-key <key>` first.",
                ));
            }
            println!("Calling Gemini through the final-server chain…");
            let res = ml::probe_gemini_api(profile, &prompt).await?;
            if res.ok {
                println!("✓ Gemini responded (model {})", res.model);
                if let Some(a) = &res.answer {
                    println!();
                    println!("{a}");
                } else {
                    println!("(no answer text)");
                }
            } else {
                println!("✗ Gemini call failed: {}", res.note);
            }
            Ok(())
        }
    }
}

/// Audit every autonomous safeguard and report whether the app is fully
/// hands-off. Each item prints OK / ACTION (one-time setup exists) / MANUAL
/// (requires a human). Exit code 0 when everything is armed, 1 otherwise —
/// scriptable for a remote one-line check.
///
/// This is a thin wrapper over `dastyab_core::autonomy::run_audit` so the
/// CLI and the GUI report the *identical* safeguard status.
async fn cmd_autonomy(profile: &str, action: crate::AutonomyAction) -> Result<(), CFError> {
    use dastyab_core::autonomy::{apply_fix, CheckStatus, FixAction};

    match action {
        crate::AutonomyAction::Audit => {
            let p = dastyab_core::store::profiles::load_profile(profile);
            let report = dastyab_core::autonomy::run_audit(&p);

            println!("Automation audit for profile '{profile}':");
            for item in &report.items {
                println!("  [{}] {}", item.status.label(), item.title);
                if !item.detail.is_empty() {
                    println!("        {}", item.detail);
                }
                // Only actionable items carry a "→ next step" line; OK/INFO rows
                // are already resolved and don't need one.
                if item.status == CheckStatus::Action && !item.fix.is_empty() {
                    println!("        → {}", item.fix);
                }
            }

            println!();
            if report.needs_action() {
                println!(
                    "Not fully hands-off yet — complete the ACTION items above (each is a one-time step)."
                );
                std::process::exit(1);
            } else {
                println!("All autonomous safeguards armed — the app runs hands-off.");
                Ok(())
            }
        }
        crate::AutonomyAction::Fix { what } => {
            let mut p = dastyab_core::store::profiles::load_profile(profile);
            // Decide which fixes to attempt.
            let fixes: Vec<FixAction> = match what {
                crate::FixWhat::Backup => vec![FixAction::EnableBackupAutoSync],
                crate::FixWhat::Mutation => vec![FixAction::EnableSignatureMutation],
                crate::FixWhat::All => {
                    // Apply every config-only fix the audit currently flags.
                    let report = dastyab_core::autonomy::run_audit(&p);
                    report
                        .items
                        .iter()
                        .filter(|i| i.status == CheckStatus::Action)
                        .filter_map(|i| i.fix_action)
                        .collect()
                }
            };

            let mut applied = Vec::new();
            for fix in fixes {
                match apply_fix(&mut p, fix) {
                    Ok(f) => applied.push(f),
                    Err(e) => println!("  ! could not apply {fix:?}: {}", e.brief()),
                }
            }
            dastyab_core::store::profiles::save_profile(&p)?;

            if applied.is_empty() {
                println!("No config-only ACTION items to apply — you are already set or the remaining items need credentials (see below).");
            } else {
                println!("Applied {} config fix(es):", applied.len());
                for f in &applied {
                    println!(
                        "  ✓ {}",
                        match f {
                            FixAction::EnableBackupAutoSync => "scheduled auto-backup enabled",
                            FixAction::EnableSignatureMutation =>
                                "worker-signature rotation enabled",
                            FixAction::EnableDaemon => "daemon (apply via `dastyab up`)",
                        }
                    );
                }
            }

            // Re-run the audit so the persist is verified by the authority.
            println!();
            let report = dastyab_core::autonomy::run_audit(&p);
            println!("Automation audit for profile '{profile}' (after fix):");
            for item in &report.items {
                println!("  [{}] {}", item.status.label(), item.title);
                if item.status == CheckStatus::Action && !item.fix.is_empty() {
                    println!("        → {}", item.fix);
                }
            }
            if report.needs_action() {
                println!();
                println!("Still not fully hands-off — remaining ACTION items need credentials or setup (see above).");
                std::process::exit(1);
            } else {
                println!();
                println!("All autonomous safeguards armed — the app runs hands-off.");
                Ok(())
            }
        }
    }
}

fn kind_label(k: dastyab_core::journal::JournalKind) -> &'static str {
    use dastyab_core::journal::JournalKind;
    match k {
        JournalKind::NetworkDown => "network-down",
        JournalKind::NetworkUp => "network-up",
        JournalKind::RescueAttempt => "rescue",
        JournalKind::CycleFailed => "cycle-failed",
        JournalKind::AccountBlocked => "account-blocked",
        JournalKind::TokenRecovered => "token-recovered",
        JournalKind::OutboxFlushed => "outbox-flushed",
        JournalKind::BackupWritten => "backup-written",
        JournalKind::MutationPerformed => "signature-rotated",
        JournalKind::DrillPerformed => "blackout-self-test",
        JournalKind::AutoHealed => "auto-healed",
        JournalKind::SnapshotWritten => "workspace-snapshot",
        JournalKind::VersionVerified => "versions-verified",
        JournalKind::NodeRefill => "node-refill",
        JournalKind::AnchorsRefreshed => "ct-anchors-refreshed",
    }
}

fn fmt_ts(ts: i64) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = write!(out, "{ts}");
    out
}

/// `inventory` subcommand — render the configs inventory.
fn inventory_cmd(
    profile_filter: Option<String>,
    kind_filter: Option<Vec<String>>,
    integrity_filter: Option<String>,
    json_out: bool,
    output: Option<String>,
) -> Result<(), CFError> {
    use dastyab_core::inventory::*;
    use dastyab_core::manifest::{ArtifactKind, IntegrityStatus};

    let workspace = dastyab_core::store::mem_dir();
    let inv = build_inventory(&workspace, dastyab_core::store::now_ts() as u64);

    let kind_opt = kind_filter.map(|kinds| {
        kinds
            .into_iter()
            .filter_map(|k| match k.to_lowercase().as_str() {
                "profilemeta" | "profile-meta" => Some(ArtifactKind::ProfileMeta),
                "tokens" | "token" => Some(ArtifactKind::Tokens),
                "accounts" => Some(ArtifactKind::Accounts),
                "history" => Some(ArtifactKind::History),
                "cleanips" | "clean-ips" => Some(ArtifactKind::CleanIps),
                "config" => Some(ArtifactKind::Config),
                "tokenhistory" | "token-history" => Some(ArtifactKind::TokenHistory),
                "cleanipmeta" | "clean-ip-meta" => Some(ArtifactKind::CleanIpMeta),
                "tunnelclient" | "tunnel-client" => Some(ArtifactKind::TunnelClient),
                _ => None,
            })
            .collect::<Vec<_>>()
    });
    let status_opt = integrity_filter
        .as_deref()
        .map(|s| match s.to_lowercase().as_str() {
            "verified" => IntegrityStatus::Verified,
            "missing" => IntegrityStatus::Missing,
            "changed" => IntegrityStatus::Changed,
            "extra" => IntegrityStatus::Extra,
            "no-manifest" | "nomanifest" => IntegrityStatus::NoManifest,
            _ => IntegrityStatus::NoManifest,
        });

    let filter = InventoryFilter {
        profile_id: profile_filter,
        kinds: kind_opt,
        integrity: status_opt,
    };
    let filtered = filter_inventory(&inv, &filter);
    let filtered_inv = Inventory {
        generated_unix: inv.generated_unix,
        items: filtered.into_iter().cloned().collect(),
        totals: inv.totals.clone(),
    };

    let rendered = if json_out {
        inventory_to_json(&filtered_inv)?
    } else {
        inventory_to_markdown(&filtered_inv)
    };

    match output {
        Some(p) => {
            std::fs::write(&p, rendered).map_err(|e| {
                CFError::new(
                    "Inventory error",
                    format!("Cannot write {p}: {e}"),
                    "Check permissions.",
                )
            })?;
            println!("✓ Wrote inventory → {p}");
        }
        None => print!("{rendered}"),
    }
    Ok(())
}

/// `verify` subcommand — verify every profile against its manifest.
fn manifest_verify_cmd(refresh: bool) -> Result<(), CFError> {
    use dastyab_core::manifest::*;
    if refresh {
        for meta in dastyab_core::store::profiles::list_profiles() {
            write_manifest(&build_manifest(&meta.id)?)?;
        }
        println!("✓ Refreshed manifests.");
    }
    let report = verify_workspace();
    for (meta, r) in &report {
        let status = if !r.has_manifest {
            "NO MANIFEST".to_string()
        } else if r.is_clean() {
            "clean".to_string()
        } else {
            let mut parts = Vec::new();
            if !r.missing.is_empty() {
                parts.push(format!("missing={}", r.missing.join(",")));
            }
            if !r.changed.is_empty() {
                parts.push(format!("changed={}", r.changed.join(",")));
            }
            if !r.extra.is_empty() {
                parts.push(format!("extra={}", r.extra.join(",")));
            }
            parts.join("; ")
        };
        println!("{} [{}] — {}", meta.name, status, meta.id);
    }
    Ok(())
}

/// `doctor` subcommand — the "state of trust" card.
fn doctor_cmd(profile: &str, json_out: bool) -> Result<(), CFError> {
    use dastyab_core::doctor::*;
    let opts = DoctorOptions {
        profile_id: profile.to_string(),
        ..Default::default()
    };
    let report = run_doctor(&opts);
    if json_out {
        println!("{}", doctor_to_json(&report)?);
    } else {
        // Compact trust banner first, then the full card.
        let b = summarize_doctor(&report);
        println!("[{}] {}", b.severity.label(), b.text);
        print!("{}", doctor_to_markdown(&report));
    }
    // Exit-code signal: 0 = all ok, 1 = warns/fails (scriptable).
    if report.overall() == CheckStatus::Ok {
        Ok(())
    } else {
        Err(CFError::new(
            "Doctor",
            format!("overall status: {}", report.overall().label()),
            "See the checks above for what needs attention.",
        ))
    }
}

/// `snapshots` subcommand — list / restore scheduled workspace snapshots.
fn snapshots_cmd(profile: &str, action: SnapshotsAction) -> Result<(), CFError> {
    use dastyab_core::workspace_snapshots::*;
    let snaps = snapshots_dir();
    match action {
        SnapshotsAction::List => {
            let list = list_snapshots(&snaps);
            if list.is_empty() {
                println!(
                    "No scheduled workspace snapshots yet ({}).",
                    snaps.display()
                );
                println!("The daemon writes one every 6h automatically, or run:");
                println!("  dastyab workspace snapshot");
                return Ok(());
            }
            println!("Workspace snapshots ({}):", snaps.display());
            for (i, e) in list.iter().enumerate() {
                let status = if e.invalid {
                    "INVALID".to_string()
                } else {
                    format!(
                        "{} profile(s), {} artifact(s)",
                        e.profile_count, e.artifact_count
                    )
                };
                println!(
                    "  [{}] {} — {} — {}",
                    i,
                    e.created_unix,
                    status,
                    e.path.display()
                );
            }
            println!("Restore: dastyab snapshots restore <path>");
            Ok(())
        }
        SnapshotsAction::Restore {
            path,
            overwrite,
            dry_run,
        } => {
            let snap =
                dastyab_core::workspace_snapshot::read_snapshot(std::path::Path::new(&path))?;
            let opts = dastyab_core::workspace_snapshot::RestoreOptions {
                overwrite_existing: overwrite,
                dry_run,
                verify_after_write: true,
            };
            let workspace = dastyab_core::store::mem_dir();
            // Offer a diff preview before the real restore on dry_run.
            if dry_run {
                let summary = diff_against_current(&snap, &workspace);
                println!(
                    "Dry run: would restore {} profile(s); diff: +{} added, ~{} changed, -{} deleted, profiles added {:?}, removed {:?}",
                    snap.profiles.len(),
                    summary.files_added,
                    summary.files_changed,
                    summary.files_deleted,
                    summary.profiles_added,
                    summary.profiles_removed
                );
            }
            let report =
                dastyab_core::workspace_snapshot::restore_workspace(&snap, &workspace, &opts)?;
            let _ = profile;
            if dry_run {
                println!(
                    "✓ Dry run: would restore {} profile(s), {} file(s).",
                    report.profiles_restored, report.files_written
                );
            } else {
                println!(
                    "✓ Restored {} profile(s), {} file(s).",
                    report.profiles_restored, report.files_written
                );
            }
            if !report.verified {
                println!("⚠ {} integrity mismatch(es):", report.mismatches.len());
                for m in &report.mismatches {
                    println!("  - {m}");
                }
            }
            Ok(())
        }
    }
}

/// `workspace` subcommand — snapshot or restore the whole workspace.
fn workspace_cmd(action: WorkspaceAction) -> Result<(), CFError> {
    use dastyab_core::workspace_snapshot::*;
    match action {
        WorkspaceAction::Snapshot { output, scope } => {
            let kind = match scope.as_str() {
                "profiles" => SnapshotKind::ProfilesOnly,
                "configs" => SnapshotKind::ConfigsOnly,
                _ => SnapshotKind::Full,
            };
            let workspace = dastyab_core::store::mem_dir();
            let snap =
                snapshot_workspace(&workspace, kind, dastyab_core::store::now_ts() as u64)?;
            let dest = match output {
                Some(p) => std::path::PathBuf::from(p),
                None => workspace.join("workspace-snapshot.json"),
            };
            write_snapshot_atomic(&snap, &dest)?;
            println!(
                "✓ Snapshot wrote {} profile(s) → {}",
                snap.profiles.len(),
                dest.display()
            );
        }
        WorkspaceAction::Restore {
            path,
            overwrite,
            dry_run,
        } => {
            let snap = read_snapshot(std::path::Path::new(&path))?;
            let opts = RestoreOptions {
                overwrite_existing: overwrite,
                dry_run,
                verify_after_write: true,
            };
            let workspace = dastyab_core::store::mem_dir();
            let report = restore_workspace(&snap, &workspace, &opts)?;
            if dry_run {
                println!(
                    "✓ Dry run: would restore {} profile(s), {} file(s).",
                    report.profiles_restored, report.files_written
                );
            } else {
                println!(
                    "✓ Restored {} profile(s), {} file(s).",
                    report.profiles_restored, report.files_written
                );
            }
            if !report.verified {
                println!("⚠ {} integrity mismatch(es):", report.mismatches.len());
                for m in &report.mismatches {
                    println!("  - {m}");
                }
            }
        }
    }
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

    #[test]
    fn test_desync_worker_line_renders_host_down_hold() {
        use dastyab_core::worker_tunnel::secret::WorkerSecret;
        let ws = WorkerSecret {
            worker_url: "https://w.workers.dev".into(),
            secret: "s".into(),
            rotated_unix: 1,
            version: 2,
            pending_secret: None,
            pending_since_unix: 0,
            desync_strategy: Some(dastyab_core::desync::DesyncStrategy::SplitTwo),
            failed_strategies: vec![dastyab_core::desync::DesyncStrategy::SplitClientHello],
            host_down: true,
            host_down_since_unix: 1_700_000_000,
        };
        let line = desync_worker_line("https://w.workers.dev", &ws, 1_700_000_100);
        // effective strategy + host-down hold + failed list all present
        assert!(line.contains("split-two"), "line: {line}");
        assert!(line.contains("HOST-DOWN 100s"), "line: {line}");
        assert!(line.contains("split-clienthello"), "line: {line}");
    }

    #[test]
    fn test_desync_worker_line_renders_ladder_up() {
        use dastyab_core::worker_tunnel::secret::WorkerSecret;
        let ws = WorkerSecret::default(); // no strategy learned, host up
        let line = desync_worker_line("https://w.workers.dev", &ws, 1_700_000_000);
        assert!(line.contains("eff=ladder"), "line: {line}");
        assert!(
            line.contains(" up ") || line.ends_with(" up"),
            "line: {line}"
        );
        assert!(line.contains("failed=[]"), "line: {line}");
    }

    /// Scratch-home helper for store-backed CLI tests. The mem-dir override is
    /// thread-local, so parallel tests running in the same process never
    /// clobber each other.
    fn config_test_home(f: impl FnOnce(String)) {
        let tmp = tempfile::tempdir().unwrap();
        dastyab_core::store::set_mem_dir_override(tmp.path().join(".dastyab"));
        let id = dastyab_core::store::profiles::create_profile("clitest", "").unwrap();
        f(id);
    }

    #[test]
    fn config_manager_set_show_json_roundtrip() {
        config_test_home(|id| {
            // Set a knob.
            cmd_config(
                &id,
                crate::ConfigAction::Set {
                    key: "scan_count".into(),
                    value: "42".into(),
                },
            )
            .unwrap();
            // Show as JSON and assert it persisted + effective values present.
            cmd_config(&id, crate::ConfigAction::Show { json: true }).unwrap();
            let p = dastyab_core::store::profiles::load_profile(&id);
            assert_eq!(p.config.scan_count, 42);
        });
    }

    #[test]
    fn config_manager_set_rejects_bad_value_and_unknown_key() {
        config_test_home(|id| {
            assert!(cmd_config(
                &id,
                crate::ConfigAction::Set {
                    key: "scan_count".into(),
                    value: "banana".into(),
                },
            )
            .is_err());
            assert!(cmd_config(
                &id,
                crate::ConfigAction::Set {
                    key: "no_such_knob".into(),
                    value: "1".into(),
                },
            )
            .is_err());
            // Failed set must not have mutated the stored config (default
            // scan_count is 2000).
            let p = dastyab_core::store::profiles::load_profile(&id);
            assert_eq!(p.config.scan_count, 2000);
        });
    }

    #[test]
    fn config_manager_unset_key_resets_to_default() {
        config_test_home(|id| {
            cmd_config(
                &id,
                crate::ConfigAction::Set {
                    key: "light_timeout_secs".into(),
                    value: "999".into(),
                },
            )
            .unwrap();
            cmd_config(
                &id,
                crate::ConfigAction::Unset {
                    key: Some("light_timeout_secs".into()),
                },
            )
            .unwrap();
            let p = dastyab_core::store::profiles::load_profile(&id);
            assert_eq!(p.config.light_timeout_secs, 0, "unset → system default 0");
        });
    }

    #[test]
    fn config_manager_unset_all_resets_whole_config() {
        config_test_home(|id| {
            cmd_config(
                &id,
                crate::ConfigAction::Set {
                    key: "scan_count".into(),
                    value: "7".into(),
                },
            )
            .unwrap();
            cmd_config(
                &id,
                crate::ConfigAction::Set {
                    key: "protection_enabled".into(),
                    value: "on".into(),
                },
            )
            .unwrap();
            cmd_config(&id, crate::ConfigAction::Unset { key: None }).unwrap();
            let p = dastyab_core::store::profiles::load_profile(&id);
            assert_eq!(p.config.scan_count, 2000, "scan_count reset to default");
            assert!(
                !p.config.protection_enabled,
                "protection_enabled reset to default"
            );
        });
    }

    #[test]
    fn config_manager_timeouts_writes_only_flagged() {
        config_test_home(|id| {
            cmd_config(
                &id,
                crate::ConfigAction::Timeouts {
                    light: 200,
                    deep: 0,
                    max_backoff: 0,
                    network_down_sleep: 0,
                },
            )
            .unwrap();
            let p = dastyab_core::store::profiles::load_profile(&id);
            assert_eq!(p.config.light_timeout_secs, 200);
            assert_eq!(p.config.deep_timeout_secs, 0, "unflagged keeps default");
        });
    }

    #[test]
    fn cleanip_list_sorts_and_filters_by_country() {
        config_test_home(|id| {
            use dastyab_core::store::profiles::remember_clean_ip_with_source;
            // 81.0.0.1 → IR, 1.1.1.1 → unknown (builtin table).
            remember_clean_ip_with_source(&id, "81.0.0.1:443", "scan").unwrap();
            remember_clean_ip_with_source(&id, "1.1.1.1:443", "manual").unwrap();
            // Default list (sorted by endpoint) renders both with source/cc.
            let out = cleanip_cmd(
                &id,
                CleanipAction::List {
                    sort: "ip".into(),
                    country: None,
                    search: None,
                    source: None,
                    json: false,
                },
            )
            .unwrap();
            assert!(out.contains("81.0.0.1"), "out: {out}");
            assert!(out.contains("cc=IR"), "out: {out}");
            assert!(out.contains("manual"), "out: {out}");
            // Filter to IR only.
            let out2 = cleanip_cmd(
                &id,
                CleanipAction::List {
                    sort: "ip".into(),
                    country: Some("IR".into()),
                    search: None,
                    source: None,
                    json: false,
                },
            )
            .unwrap();
            assert!(out2.contains("81.0.0.1"), "out2: {out2}");
            assert!(!out2.contains("1.1.1.1"), "out2: {out2}");
        });
    }

    #[test]
    fn cleanip_list_json_emits_meta_fields() {
        config_test_home(|id| {
            use dastyab_core::store::profiles::remember_clean_ip_with_source;
            remember_clean_ip_with_source(&id, "81.0.0.1:443", "scan").unwrap();
            let out = cleanip_cmd(
                &id,
                CleanipAction::List {
                    sort: "ip".into(),
                    country: None,
                    search: None,
                    source: None,
                    json: true,
                },
            )
            .unwrap();
            let v: serde_json::Value = serde_json::from_str(&out).unwrap();
            let arr = v.as_array().unwrap();
            assert_eq!(arr.len(), 1);
            assert_eq!(arr[0]["endpoint"], "81.0.0.1:443");
            assert_eq!(arr[0]["country"], "IR");
            assert_eq!(arr[0]["source"], "scan");
        });
    }

    #[test]
    fn cleanip_remove_and_clear_mutate_ledger() {
        config_test_home(|id| {
            use dastyab_core::store::profiles::{clean_ip_meta, remember_clean_ip_with_source};
            remember_clean_ip_with_source(&id, "81.0.0.1:443", "scan").unwrap();
            remember_clean_ip_with_source(&id, "8.8.8.8:443", "scan").unwrap();
            cleanip_cmd(
                &id,
                CleanipAction::Remove {
                    ip: "81.0.0.1:443".into(),
                },
            )
            .unwrap();
            let remaining = clean_ip_meta(&id);
            assert!(!remaining.contains_key("81.0.0.1:443"));
            assert!(remaining.contains_key("8.8.8.8:443"));
            cleanip_cmd(&id, CleanipAction::Clear).unwrap();
            assert!(clean_ip_meta(&id).is_empty());
        });
    }
}
