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
