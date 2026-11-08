//! Khvarenah CLI.
//!
//! Proves the core crate end-to-end: profiles, tokens, deploy, scan, export,
//! DNS/zones, routes, analytics, diagnostics, backup, security audit, presets,
//! and self-update.

mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "khvarenah",
    version,
    about = "Khvarenah — Cloudflare-Workers VLESS VPN console (Rust)",
    long_about = "Khvarenah (خوَرنه) is a Cloudflare-Workers VLESS VPN console: \
                  deploy workers, scan clean IPs, generate client configs \
                  (v2rayN / sing-box / Clash), and manage DNS, zones, routes \
                  and usage — all from the shell. Built in Rust for speed and safety."
)]
struct Cli {
    /// The profile to act on (defaults to `default`).
    #[arg(long, global = true, default_value = "default")]
    profile: String,

    /// Disable anti-bot stealth pacing for this run.
    #[arg(long, global = true)]
    no_stealth: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List profiles.
    Profiles,
    /// Create a new profile.
    ProfileCreate {
        #[arg()]
        name: String,
        #[arg(long, default_value = "")]
        description: String,
    },
    /// Delete a profile.
    ProfileDelete {
        #[arg()]
        id: String,
    },
    /// Rename a profile.
    ProfileRename {
        #[arg()]
        id: String,
        #[arg()]
        name: String,
    },
    /// Export a profile as JSON.
    ProfileExport {
        #[arg()]
        id: String,
    },
    /// Import a profile from a JSON file.
    ProfileImport {
        #[arg()]
        path: String,
    },
    /// Add a token.
    TokenAdd {
        #[arg()]
        label: String,
        #[arg()]
        token: String,
    },
    /// List tokens (masked).
    TokenList,
    /// Remove a token.
    TokenRemove {
        #[arg()]
        label: String,
    },
    /// Verify the active token.
    Verify,
    /// List Cloudflare accounts.
    Accounts,
    /// Deploy the worker.
    Deploy {
        #[arg(long)]
        account: Option<String>,
        #[arg(long)]
        worker: Option<String>,
        /// Preset to apply (standard | gaming | max-compat).
        #[arg(long)]
        preset: Option<String>,
    },
    /// Find a clean IP (stops on the first working one).
    Scan,
    /// Find N clean IPs (only when you explicitly want more).
    ScanMany {
        #[arg(long, default_value_t = 5)]
        count: u32,
    },
    /// Show history.
    History,
    /// Show usage summary.
    Status,
    /// Migrate old flat-file memory into profiles.
    Migrate,

    // ---- new tooling ----
    /// List zones accessible to the token.
    Zones,
    /// Manage DNS records for a zone.
    Dns {
        #[command(subcommand)]
        action: DnsAction,
    },
    /// Manage worker custom routes.
    Routes {
        #[command(subcommand)]
        action: RoutesAction,
    },
    /// Export the latest config as a client format.
    Export {
        /// Format: v2rayn | singbox | clash | link.
        #[arg()]
        format: String,
        /// Optional output file (else printed to stdout).
        #[arg(long)]
        output: Option<String>,
    },
    /// Backup a profile to a JSON bundle.
    Backup {
        #[command(subcommand)]
        action: BackupAction,
    },
    /// Show usage analytics for the active account's workers.
    Analytics,
    /// Run network diagnostics against endpoints.
    Diag {
        /// ip:port endpoints (comma-separated) to test.
        #[arg(long, required = true)]
        endpoints: String,
    },
    /// Run a local security audit.
    Security,
    /// List deployment presets.
    Presets,
    /// Check for a newer release.
    UpdateCheck,
    /// Download & install a newer release (requires GitHub asset).
    UpdateApply,

    // ---- native clean-IP + autopilot ----
    /// Show cached Cloudflare IP-range summary (diagnostic).
    Ranges,
    /// Run a single native clean-IP discovery cycle (no autopilot).
    Discover {
        /// Number of candidate IPs to probe per cycle.
        #[arg(long, default_value_t = 2000)]
        sample: u32,
        /// Worker concurrency.
        #[arg(long, default_value_t = 64)]
        workers: u32,
        /// Force refresh of the CF range list.
        #[arg(long)]
        refresh: bool,
    },
    /// Autopilot: find the best clean IP, export vless configs, and
    /// continuously monitor + auto-replace dead fronts.
    Autopilot {
        #[command(subcommand)]
        action: AutopilotAction,
    },
    /// One-button Protection: persist the monitor flag, run a full discovery
    /// cycle, export the user bundle, then optionally keep a monitor loop.
    Protection {
        #[command(subcommand)]
        action: ProtectionAction,
    },
    /// Persistent protection daemon (unattended monitor with network-liveness
    /// probe, exponential backoff, and daemon.log).
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
    /// Read the per-cycle health beacon (one-`cat` health check). Exit code
    /// 0 = fresh, 1 = stale (scriptable for remote checks).
    Health {
        /// Emit raw beacon JSON instead of the human-readable table.
        #[arg(long)]
        json: bool,
    },
    /// End-to-end harness: verify token → deploy worker → discover clean IPs
    /// → write the user bundle, then print the manual verification block.
    E2e {
        /// Skip the worker-deploy step (assume a worker already exists).
        #[arg(long)]
        skip_worker_deploy: bool,
        /// Worker name to use/deploy (optional).
        #[arg(long)]
        worker: Option<String>,
    },
    /// Compare the direct (non-tunnel) IP with the tunnel IP to prove the
    /// VLESS tunnel actually routes through the Worker.
    VerifyTunnel {
        /// IP the machine reports without the tunnel.
        #[arg(long)]
        direct_ip: String,
        /// IP the machine reports through the tunnel.
        #[arg(long)]
        tunnel_ip: String,
    },
    /// Inspect / reconcile the user-facing bundle against the ledger.
    Bundle {
        #[command(subcommand)]
        action: BundleAction,
    },
    /// Zero-touch bootstrap: detect a token, create/use a profile, deploy a
    /// worker if needed, discover clean IPs, write the user bundle, and
    /// install the systemd unit — all in one command.
    Up {
        /// Profile id to use (default: `default`, or the existing profile that
        /// supplied the token).
        #[arg(long)]
        profile: Option<String>,
    },
    /// Remote push notifications (Telegram or webhook).
    Beacon {
        #[command(subcommand)]
        action: BeaconAction,
    },
    /// SNI allowlist scanner — tests which SNIs DPI allows on this network,
    /// independent of the Cloudflare account.
    SniSpoof {
        #[command(subcommand)]
        action: SniSpoofAction,
    },
}

#[derive(Subcommand)]
pub enum SniSpoofAction {
    /// Probe each candidate SNI against a public CF edge and print the allowlist.
    Scan {
        /// Edge IP to target (default: use a known Cloudflare anycast edge).
        #[arg(long)]
        ip: Option<String>,
        /// TCP port (default 443).
        #[arg(long, default_value_t = 443)]
        port: u16,
        /// Per-probe timeout ms (default 3000).
        #[arg(long, default_value_t = 3000)]
        timeout_ms: u64,
        /// Concurrency (default 4).
        #[arg(long, default_value_t = 4)]
        workers: usize,
    },
    /// Show the persisted allowlist.
    List,
    /// Pretty-print the last scan JSON.
    Show,
    /// Remove the persisted allowlist (forces a re-scan).
    Clear,
    /// WS-upgrade diagnostic: does a WS upgrade reach the CF edge, or is it
    /// intercepted by DPI? Distinguishes DPI-blocks-upgrade from dead worker.
    WsScan {
        /// Edge IP to target (default: a known Cloudflare anycast edge).
        #[arg(long)]
        ip: Option<String>,
        /// TCP port (default 443).
        #[arg(long, default_value_t = 443)]
        port: u16,
        /// WS path to probe (default /).
        #[arg(long, default_value = "/")]
        path: String,
        /// Per-probe timeout ms (default 5000).
        #[arg(long, default_value_t = 5000)]
        timeout_ms: u64,
    },
}

#[derive(Subcommand)]
pub enum BeaconAction {
    /// Send a test message with the current config (verifies the channel).
    Test,
    /// Show current notification config.
    Status,
    /// Enable notifications (requires a configured channel).
    Enable,
    /// Disable notifications.
    Disable,
    /// Configure the Telegram channel.
    Telegram {
        #[arg()]
        token: String,
        #[arg()]
        chat_id: String,
    },
    /// Configure a generic webhook channel.
    Webhook {
        #[arg()]
        url: String,
    },
    /// Set the per-event-class rate limit in seconds (default 900).
    RateLimit {
        #[arg()]
        secs: i64,
    },
}

#[derive(Subcommand)]
enum BundleAction {
    /// Verify the bundle is in sync with the ledger's active endpoint.
    Verify,
    /// Reconcile a drifted bundle now (one-shot manual fix).
    Reconcile,
}

#[derive(Subcommand)]
enum DnsAction {
    /// List DNS records for a zone.
    List {
        #[arg()]
        zone: String,
    },
    /// Create a DNS record.
    Create {
        #[arg()]
        zone: String,
        #[arg()]
        name: String,
        #[arg()]
        record_type: String,
        #[arg()]
        content: String,
        #[arg(long, default_value_t = 120)]
        ttl: u32,
        #[arg(long)]
        no_proxy: bool,
    },
    /// Delete a DNS record.
    Delete {
        #[arg()]
        zone: String,
        #[arg()]
        record_id: String,
    },
}

#[derive(Subcommand)]
enum RoutesAction {
    /// List custom routes.
    List,
    /// Create a route (pattern -> script).
    Create {
        #[arg()]
        pattern: String,
        #[arg()]
        script: String,
    },
    /// Delete a route.
    Delete {
        #[arg()]
        route_id: String,
    },
}

#[derive(Subcommand)]
enum BackupAction {
    /// Export a profile to a JSON bundle.
    Export {
        #[arg()]
        profile_id: String,
    },
    /// Restore a profile from a JSON bundle.
    Import {
        #[arg()]
        path: String,
    },
    /// List existing backups.
    List,
}

#[derive(Subcommand)]
enum AutopilotAction {
    /// Turn autopilot on: discover best clean IP, export configs, then
    /// monitor and auto-replace dead fronts on an interval.
    On {
        /// Monitor interval in seconds (default 300 = 5 min).
        #[arg(long, default_value_t = 300)]
        interval_s: u64,
        /// Candidate IPs per discovery cycle.
        #[arg(long, default_value_t = 2000)]
        sample: u32,
        /// Worker concurrency.
        #[arg(long, default_value_t = 64)]
        workers: u32,
    },
    /// Run one monitor pass (without enabling the loop).
    Check,
    /// Probe the worker's health directly (step-0 gate): a real TLS+HTTP
    /// check against the deployed worker's hostname, before any scanning.
    /// Optionally connect via a specific fronting IP (bypasses DNS, which is
    /// often hijacked on censored networks) while still probing the worker's
    /// hostname as SNI/Host.
    Health {
        /// A Cloudflare IP that fronts the worker; connect to this IP while
        /// using the worker hostname as SNI/Host (skips DNS entirely).
        #[arg(long)]
        connect_ip: Option<std::net::Ipv4Addr>,
        /// Dump the last scan's phase-2 WS-failure histogram (answers "why
        /// zero clean IPs?": DPI TLS reset vs dead worker route).
        #[arg(long)]
        verbose: bool,
    },
    /// Show autopilot status + current ledger.
    Status,
    /// Turn autopilot off (stop the loop). No-op for CLI (loop is per-run);
    /// provided for parity with the GUI toggle.
    Off,
}

/// One-button Protection subcommands (the "simple for a normal user" path).
#[derive(Subcommand)]
pub enum ProtectionAction {
    /// Turn protection on: persist the flag, deploy-if-needed, run a full
    /// discovery cycle, export the user bundle, then optionally keep a
    /// monitor loop running (bg).
    On {
        /// Persist the protection flag (auto-resume after restart).
        #[arg(long)]
        persist: bool,
        /// Keep monitoring in a background loop after the first cycle
        /// (default true). The loop runs in the foreground until Ctrl+C.
        #[arg(long, default_value_t = true)]
        monitor: bool,
        /// Monitor interval in seconds (default 300 = 5 min).
        #[arg(long, default_value_t = 300)]
        interval_s: u64,
        /// Candidate IPs per discovery cycle.
        #[arg(long, default_value_t = 2000)]
        sample: u32,
        /// Worker concurrency.
        #[arg(long, default_value_t = 64)]
        workers: u32,
    },
    /// Turn protection off (clear the persisted flag).
    Off,
    /// Show whether protection is enabled + the latest explanation of a zero
    /// result (if any).
    Status,
    /// Import "known-good IPs" (one per line, `ip` or `ip:port`, `#` comments
    /// allowed) so the next scan seeds from them — the NetworkBlocked fast path.
    SeedsImport {
        /// Raw text/IPs to import (argument or stdin).
        #[arg()]
        raw: Option<String>,
        /// Read from stdin instead of the argument.
        #[arg(long)]
        stdin: bool,
    },
}

/// Persistent daemon subcommands (unattended protection monitor).
#[derive(Subcommand)]
pub enum DaemonAction {
    /// Start the daemon process (foreground or daemonized).
    Start {
        /// Run in the foreground (recommended under systemd).
        #[arg(long)]
        foreground: bool,
        /// Initial cycle interval in seconds (default 300).
        #[arg(long, default_value_t = 300)]
        interval_s: u64,
    },
    /// Stop the daemon (writes the stop file; the loop exits on next tick).
    Stop,
    /// Show daemon status: PID, uptime, last cycle, streak, interval, network.
    Status,
    /// Write the systemd user unit and print the enable --now command.
    InstallSystemd,
    /// Reset backoff state: zero failure streak and restore the initial interval.
    /// Use after fixing a network/worker issue so the daemon retries now.
    Reset,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if cli.no_stealth {
        khvarenah_core::stealth::set_enabled(false);
    }

    if let Err(e) = commands::run(cli.profile, cli.command).await {
        eprintln!("\u{1b}[31m✗ {}\u{1b}[0m", e.explain());
        std::process::exit(1);
    }
}
