//! DastYab CLI.
//!
//! Proves the core crate end-to-end: profiles, tokens, deploy, scan, export,
//! DNS/zones, routes, analytics, diagnostics, backup, security audit, presets,
//! and self-update.

mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "dastyab",
    version,
    about = "DastYab — Cloudflare-Workers VLESS VPN console (Rust)",
    long_about = "DastYab (دستیاب) is a Cloudflare-Workers VLESS VPN console: \
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
    /// Add a token, verify it against Cloudflare, set it active, and clear a
    /// blocked daemon account state so protection resumes immediately (guided
    /// token recovery — no restart).
    TokenRecover {
        #[arg()]
        label: String,
        #[arg()]
        token: String,
    },
    /// Ensure at least MIN tokens are stored, auto-creating a second one via
    /// the Cloudflare API when below the threshold (removes the manual
    /// "create a token in the dashboard" step that blocks auto-rotation).
    TokenEnsure {
        #[arg(long, default_value_t = 2)]
        min: usize,
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
    /// Find clean IPs — dead-simple or fully tuned.
    ///
    /// Simple (for everyone):
    ///   dastyab find 1      # one working IP
    ///   dastyab find 5 ip   # five working IPs
    ///   dastyab find        # default: one working IP
    ///
    /// Advanced knobs: --sample, --workers, --timeout, --top, --seed,
    /// --strategy, --refresh, --no-retry, --json, --quiet, --out.
    Find {
        /// How many clean IPs you want (default 1).
        #[arg(default_value_t = 1)]
        count: u32,

        /// Optional decorative word so "find 5 ip" reads naturally.
        #[arg()]
        suffix: Option<String>,

        /// Candidate IPs to probe per cycle (advanced).
        #[arg(long, default_value_t = 2000)]
        sample: u32,

        /// Probe concurrency (advanced).
        #[arg(long, default_value_t = 64)]
        workers: u32,

        /// Per-probe timeout in seconds.
        #[arg(long, default_value_t = 8)]
        timeout: u32,

        /// How many validated endpoints to aim for (defaults to count).
        #[arg(long)]
        top: Option<u32>,

        /// Force refresh of the Cloudflare range list.
        #[arg(long)]
        refresh: bool,

        /// Known-good IP seeds (comma-separated) to expand neighbourhoods around.
        #[arg(long)]
        seed: Option<String>,

        /// Phase-2 SNI strategy for this cycle.
        #[arg(long, value_enum)]
        strategy: Option<StrategyChoice>,

        /// Disable retry-on-fail for cold-start validation.
        #[arg(long)]
        no_retry: bool,

        /// Emit JSON instead of human text.
        #[arg(long, conflicts_with = "quiet")]
        json: bool,

        /// Print only the IPs (one per line), nothing else.
        #[arg(long, conflicts_with = "json")]
        quiet: bool,

        /// Write the client bundle (active.vless / QR / fallbacks) to a dir.
        #[arg(long)]
        out: Option<String>,
    },
    /// Show history.
    History,
    /// Manage the saved clean-IP ledger (list / remove / clear).
    Cleanip {
        #[command(subcommand)]
        action: CleanipAction,
    },
    /// List / show / export generated configs (the completeness ledger).
    Configs {
        #[command(subcommand)]
        action: ConfigsAction,
    },
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
    /// Show the configs inventory across all profiles (the "configs manager").
    /// Exports deterministic Markdown or JSON.
    Inventory {
        /// Filter output by profile id.
        #[arg(long)]
        profile: Option<String>,
        /// Filter output by artifact kind label.
        #[arg(long, value_delimiter = ',')]
        kind: Option<Vec<String>>,
        /// Filter output by integrity status (verified|missing|changed|extra|no-manifest).
        #[arg(long)]
        integrity: Option<String>,
        /// Emit JSON instead of Markdown.
        #[arg(long)]
        json: bool,
        /// Output file (default: print to stdout).
        #[arg(long)]
        output: Option<String>,
    },
    /// Verify all profiles against their manifests (proof nothing is lost).
    ManifestVerify {
        /// Refresh manifests first (re-hash current artifacts).
        #[arg(long)]
        refresh: bool,
    },
    /// Doctor — the "state of trust" card. Runs a battery of checks over every
    /// safety subsystem (manifest, backup, autosync, daemon, tunnel, workspace
    /// snapshot) and reports the overall verdict.
    Doctor {
        /// Emit the report as JSON instead of Markdown.
        #[arg(long)]
        json: bool,
    },
    /// Scheduled workspace snapshots (the "Restore a past point" timeline).
    Snapshots {
        #[command(subcommand)]
        action: SnapshotsAction,
    },
    /// Whole-workspace snapshot (all profiles in one portable bundle).
    Workspace {
        #[command(subcommand)]
        action: WorkspaceAction,
    },
    /// Per-artifact version history (second-by-second recovery).
    Versions {
        #[command(subcommand)]
        action: VersionsAction,
    },
    /// Configure scheduled worker-signature rotation (anti-DPI moving target).
    /// The daemon redeploys the worker with a fresh UUID/path on the interval.
    Mutation {
        #[command(subcommand)]
        action: MutationAction,
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
    /// Anti-DPI TCP desync fragmenter: configure and report it. When enabled,
    /// the WS-gate writes the upgrade request as irregular segments so DPI
    /// can't reassemble it (helps when healthy edges get reset on upgrade).
    Desync {
        #[command(subcommand)]
        action: DesyncAction,
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
    /// Inspect / tune the per-profile blackout-resilience knobs (monitor
    /// light/deep phase budgets and the daemon backoff ceiling). Everything
    /// the daemon uses to pace its fight against censorship lives here, so it
    /// can be tuned from the app rather than compiled in.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
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
    /// Blackout drill: probe every rung of the fallback ladder (Direct → DoH
    /// → DoT → DNS tunnel) once and report which would survive a blackout.
    /// A self-test that verifies resilience without disconnecting.
    Drill,
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
    /// One-command DNS tunnel deploy to a VPS (total-blackout survival).
    DnsTunnel {
        #[command(subcommand)]
        action: DnsTunnelAction,
    },
    /// Multi-worker parallel redundancy (deploy/probe/failover a worker set).
    MultiWorker {
        #[command(subcommand)]
        action: MultiWorkerAction,
    },
    /// Multi-layer tunnel: configure your final server and test AI
    /// Studio + Gemini access through the full chain.
    Multilayer {
        #[command(subcommand)]
        action: MultilayerAction,
    },
    /// Route traffic through the Tor anonymity network to change the egress
    /// IP (private daemon + SOCKS5 proxy on the loopback interface).
    Tor {
        #[command(subcommand)]
        action: TorAction,
    },
    /// Durable daemon journal: blackout/rescue/outbox events recorded across
    /// crashes and restarts. The blackout-resilience audit trail.
    Journal {
        #[command(subcommand)]
        action: JournalAction,
    },
    /// Automation self-audit: verify every autonomous safeguard is armed
    /// (daemon running, boot-before-login autostart, auto token-rotation with
    /// ≥2 tokens, scheduled auto-backup, signature rotation, DNS tunnel).
    /// One command tells you whether the app is fully hands-off or which
    /// single step still needs a human.
    Autonomy {
        #[command(subcommand)]
        action: AutonomyAction,
    },
    /// Onboarding status: report which setup steps (token, worker, bundle,
    /// daemon installed/running) are already complete. Offline — reads local
    /// state only, never the network.
    Onboard {
        #[command(subcommand)]
        action: OnboardAction,
    },

    /// Launch/stop the self-healing clean-IP tunnel to Google AI Studio.
    /// Routes your browser through a working foreign server pool and keeps it
    /// alive with a watchdog (auto-rotates when a server dies).
    ///
    /// Simple usage:
    ///   dastyab aistudio start     # tunnel + open AI Studio in Chrome
    ///   dastyab aistudio watch     # self-healing watchdog (background)
    ///   dastyab aistudio stop      # stop the tunnel
    ///   dastyab aistudio verify    # show pool + live egress IP
    Aistudio {
        #[arg()]
        action: String,
    },
    /// Apply / teardown the doctrine A+D platform network rules (anti-loop
    /// fwmark routing + TCP MSS clamp). Use `--dry-run` to preview commands.
    Platform {
        /// Action: apply | teardown | plan.
        #[arg()]
        action: String,
        /// Only print the commands that would run; require root.
        #[arg(long)]
        dry_run: bool,
        /// Tunnel MTU for the MSS clamp (default 1290).
        #[arg(long, default_value_t = 1290)]
        mtu: u32,
    },
    /// Manage native config-storage nodes (imported from v2rayN or pasted).
    Nodes {
        /// Sub-command: import | paste | activate | list | clear.
        #[arg()]
        action: String,
        /// Profile to operate on (default "default").
        #[arg(long, default_value = "default")]
        profile: String,
        /// Path to a v2rayN ServersStore.json (for import).
        #[arg(long, default_value = "")]
        path: String,
        /// A vless:// share-link (for paste/activate).
        #[arg(long, default_value = "")]
        link: String,
        /// Route the probe through the local xray SOCKS5 (for NIN/blackout).
        #[arg(long, default_value_t = false)]
        proxy: bool,
    },
    /// Harvest free vless configs from Telegram channels (public previews,
    /// no browser needed) into a profile's node store.
    Harvest {
        /// Comma-separated channel handles (with or without leading '@').
        #[arg(long, default_value = "v2ray_config")]
        channels: String,
        /// Profile to import into (default "default").
        #[arg(long, default_value = "default")]
        profile: String,
        /// Route through the local xray SOCKS5 proxy (use when direct is blocked).
        #[arg(long)]
        proxy: bool,
    },
}

#[derive(Subcommand)]
pub enum CleanipAction {
    /// List saved clean IPs with provenance (source, port, country, verified times).
    /// Mirrors the GUI Clean-IPs manager. Default: human table sorted by endpoint.
    List {
        /// Sort field: ip | port | source | country | added | last.
        #[arg(long, default_value = "ip")]
        sort: String,
        /// Only show endpoints whose country begins with this (e.g. --country IR).
        #[arg(long)]
        country: Option<String>,
        /// Only show endpoints matching this text substring (endpoint / source).
        #[arg(long)]
        search: Option<String>,
        /// Only show endpoints from a given source (scan | import | manual).
        #[arg(long)]
        source: Option<String>,
        /// Emit JSON instead of a human table.
        #[arg(long)]
        json: bool,
    },
    /// Remove one saved clean IP by its endpoint string.
    Remove {
        #[arg()]
        ip: String,
    },
    /// Remove all saved clean IPs.
    Clear,
}

#[derive(Subcommand)]
pub enum ConfigsAction {
    /// List generated configs (optionally filtered). `--json` emits the
    /// matching records as a machine-readable array.
    List {
        /// Filter by export format (v2rayn | singbox | clash | link).
        #[arg(long)]
        fmt: Option<String>,
        /// Only records at or after this unix timestamp.
        #[arg(long)]
        since: Option<u64>,
        /// Text substring to search for in the config content.
        #[arg(long)]
        search: Option<String>,
        /// Emit the matching records as JSON instead of a human table.
        #[arg(long)]
        json: bool,
    },
    /// Show one generated config by id.
    Show {
        #[arg()]
        id: u64,
    },
    /// Write one generated config to a file.
    Export {
        #[arg()]
        id: u64,
        #[arg(long)]
        output: String,
    },
    /// Rename a generated config's label (display name).
    Rename {
        #[arg()]
        id: u64,
        /// New label text. Use "" to clear the label.
        #[arg(long)]
        label: String,
    },
    /// Edit a generated config's content in place (re-hashes it). Provide the
    /// new content inline with `--content` or read it from a file with
    /// `--file` (at most one).
    Edit {
        #[arg()]
        id: u64,
        /// New config content, inline.
        #[arg(long, conflicts_with = "file")]
        content: Option<String>,
        /// Read the new config content from this file path.
        #[arg(long, conflicts_with = "content")]
        file: Option<String>,
    },
    /// Delete a generated config from the ledger (destructive).
    Delete {
        #[arg()]
        id: u64,
    },
}

#[derive(Subcommand)]
pub enum VersionsAction {
    /// List saved versions of a profile artifact (newest first).
    List {
        /// Relative artifact filename within the profile dir (e.g. history.json).
        #[arg()]
        artifact: String,
    },
    /// Show one saved version's stored bytes.
    Show {
        /// Relative artifact filename.
        #[arg()]
        artifact: String,
        /// The saved version's unix-millisecond timestamp.
        #[arg()]
        unix: u64,
    },
    /// Restore an artifact to a saved version (snapshots the current state first).
    Restore {
        /// Relative artifact filename.
        #[arg()]
        artifact: String,
        /// The saved version's unix-millisecond timestamp.
        #[arg()]
        unix: u64,
    },
    /// Prune an artifact's version history down to the newest N.
    Prune {
        /// Relative artifact filename.
        #[arg()]
        artifact: String,
        /// How many newest versions to keep.
        #[arg(long, default_value_t = 20)]
        keep: usize,
    },
    /// Show per-artifact versioning health (dirs, files, bytes, prune state).
    Health,
    /// Run the version-integrity sweep (content verification of all versions).
    Verify {
        /// Wall-clock budget in milliseconds (default 2000).
        #[arg(long, default_value_t = 2000)]
        budget_ms: u64,
        /// Emit the report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Point-in-time restore: preview or execute a whole-profile restore to a
    /// past moment (unix seconds).
    Pitr {
        /// Target moment as unix seconds.
        unix: u64,
        /// Only preview the plan; write nothing.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
pub enum OnboardAction {
    /// Show which onboarding steps are done and which remain.
    Status {
        /// Profile id to inspect (default: active profile).
        #[arg(long)]
        profile: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum DnsTunnelAction {
    /// Deploy the DNS tunnel server to a VPS and persist the client config.
    Deploy {
        /// VPS host / IP.
        #[arg(long)]
        host: String,
        /// SSH user.
        #[arg(long)]
        ssh_user: String,
        /// Path to the SSH private key.
        #[arg(long, default_value = "~/.ssh/id_ed25519")]
        ssh_key: String,
        /// SSH port.
        #[arg(long, default_value_t = 22)]
        ssh_port: u16,
        /// Base DNS domain the tunnel server answers for.
        #[arg(long)]
        domain: String,
    },
    /// Show whether a DNS tunnel is deployed for the active profile.
    Status,
    /// Deploy the Worker-hosted DNS tunnel (no VPS) with the profile's token.
    Worker {
        /// Explicit worker name (default: auto dyb-tun-<hex>).
        #[arg(long)]
        worker_name: Option<String>,
        /// Cloudflare worker compatibility date.
        #[arg(long, default_value = "2026-07-01")]
        compat_date: String,
    },
    /// Provision a fresh Hetzner Cloud VPS, then deploy the DNS tunnel to it.
    Provision {
        /// Hetzner Cloud API token.
        #[arg(long)]
        api_token: String,
        /// Hetzner datacenter/location (nbg1 | fsn1 | hel1 | ash | hil).
        #[arg(long, default_value = "nbg1")]
        location: String,
        /// Hetzner server type (default cx22).
        #[arg(long, default_value = "cx22")]
        server_type: String,
        /// Base DNS domain the tunnel server answers for.
        #[arg(long)]
        domain: String,
        /// Path to write the generated SSH private key (default ~/.dastyab/key-hetzner).
        #[arg(long, default_value = "~/.dastyab/key-hetzner")]
        ssh_key: String,
        /// SSH user to use on the provisioned VPS.
        #[arg(long, default_value = "dastyab")]
        ssh_user: String,
    },
    /// Probe the VPS reachability (pure TCP check, no SSH).
    Test {
        /// VPS host / IP.
        #[arg(long)]
        host: String,
        /// VPS TCP port (SSH).
        #[arg(long, default_value_t = 22)]
        port: u16,
    },
    /// Scan for working domestic (Iranian ISP) recursive resolvers and persist
    /// them as the blackout resolver pool. Run this BEFORE a lockdown.
    Resolvers {
        /// Candidate resolver list (comma-separated); defaults to the built-in
        /// Iranian ISP seed list.
        #[arg(long)]
        candidates: Option<String>,
        /// Max concurrent probes.
        #[arg(long, default_value_t = 32)]
        concurrency: usize,
        /// Per-resolver timeout ms.
        #[arg(long, default_value_t = 2500)]
        timeout_ms: u64,
    },
}

/// Tor anonymity-network actions (egress-IP change).
#[derive(Subcommand)]
pub enum TorAction {
    /// Start the private Tor daemon and wait for a usable circuit.
    Start {
        /// Local SOCKS5 port for the Tor proxy (default 9050).
        #[arg(long, default_value_t = 9050)]
        socks_port: u16,
    },
    /// Stop the Tor daemon.
    Stop,
    /// Restart Tor — guaranteed fresh circuit, new exit IP.
    Renew,
    /// Show whether Tor is running and the current exit IP.
    Status,
}

/// Multi-worker parallel redundancy actions.
#[derive(Subcommand)]
pub enum MultiWorkerAction {
    /// Ensure the profile has `count` deployed workers (parallel deploy).
    Deploy {
        /// Number of workers to maintain (default 2, max 3).
        #[arg(long, default_value_t = 2)]
        count: usize,
    },
    /// List the worker set with their health.
    Status,
    /// Probe all workers and fail over to the healthiest alive one.
    Failover,
    /// Force the active worker selection to a specific worker name.
    SetActive {
        /// Worker name to make active.
        #[arg()]
        name: String,
    },
}

/// Multi-layer tunnel actions.
#[derive(Subcommand)]
pub enum MultilayerAction {
    /// Set the final server config (your own VPN / VLESS egress).
    Set {
        /// Human label for this server.
        #[arg(long, default_value = "my final server")]
        name: String,
        /// A vless:// share link for the final server.
        #[arg(long)]
        link: String,
        /// Optional expected egress-country hint.
        #[arg(long, default_value = "")]
        country: String,
    },
    /// Show the configured final server + status.
    Status,
    /// Remove the final-server config.
    Clear,
    /// Store the Gemini API key (used only through the multi-layer tunnel).
    SetGeminiKey {
        /// Your Gemini API key.
        #[arg()]
        key: String,
    },
    /// Probe AI Studio + Gemini reachability through the final-server chain.
    ProbeAi,
    /// Make one real Gemini generateContent call through the chain.
    Gemini {
        /// The prompt to send.
        #[arg(default_value = "Explain how AI works in a few words")]
        prompt: String,
    },
}

/// Durable daemon journal actions.
#[derive(Subcommand)]
pub enum JournalAction {
    /// Show the most recent journal entries (newest first).
    Show {
        /// Number of entries to print (default 20).
        #[arg(long, default_value_t = 20)]
        n: usize,
    },
    /// Show only unresolved intents (e.g. a blackout that never saw a restore).
    Pending,
    /// Clear the journal.
    Clear,
}

/// Per-profile blackout-resilience knob actions.
#[derive(Subcommand)]
pub enum ConfigAction {
    /// Show the effective (resolved) per-profile configuration: monitor
    /// budgets, backoff ceiling, scan defaults, toggles, cadences — plus the
    /// raw configured values and the system defaults behind them. `--json`
    /// emits the whole resolved profile as a machine-readable object.
    Show {
        /// Emit the resolved configuration as JSON (instead of a human table).
        #[arg(long)]
        json: bool,
    },
    /// Set one named knob to a value. Keys are the snake_case field names:
    /// scan_count, scan_workers, scan_timeout, scan_ports, scan_gentle,
    /// stealth_enabled, protection_enabled, auto_rotate_on_blocked,
    /// light_interval_secs, light_timeout_secs, deep_timeout_secs,
    /// max_backoff_secs, network_down_sleep_secs, drill_interval_secs.
    /// Booleans accept true/false/1/0/on/off/yes/no.
    Set {
        /// Knob name (snake_case, see help text).
        #[arg()]
        key: String,
        /// Value to assign (boolean or unsigned integer).
        #[arg()]
        value: String,
    },
    /// Restore a single knob to its system default. With no key, reset the
    /// whole profile config to defaults (equivalent to the GUI's "Reset
    /// settings to defaults"). Never touches tokens or clean IPs.
    Unset {
        /// Knob name to reset. Omit to reset the entire config.
        #[arg()]
        key: Option<String>,
    },
    /// Set the monitor phase budgets and the daemon backoff ceiling. Only the
    /// flags you pass are changed; 0 / omitted keeps the system default.
    Timeouts {
        /// Monitor LIGHT-phase budget in seconds (WS-gate sweep). 0 = default 120.
        #[arg(long, default_value_t = 0)]
        light: u64,
        /// Monitor DEEP-phase (discovery+E2E) budget in seconds. 0 = default 600.
        #[arg(long, default_value_t = 0)]
        deep: u64,
        /// Daemon backoff ceiling in seconds. 0 = default 21600 (6h).
        #[arg(long, default_value_t = 0)]
        max_backoff: u64,
        /// Daemon poll cadence (seconds) while the network is fully down
        /// (total blackout). 0 = default 60. Lower = re-probe for a restored
        /// path sooner; higher = conserve battery/CPU during a long outage.
        #[arg(long, default_value_t = 0)]
        network_down_sleep: u64,
    },
}

/// Automation self-audit actions.
#[derive(Subcommand)]
pub enum AutonomyAction {
    /// Audit all autonomous safeguards and report, per item, whether it is
    /// armed (OK), needs a one-time setup (ACTION), or is a manual requirement
    /// (MANUAL). Exit code 0 when everything is hands-off, 1 otherwise — so
    /// it is scriptable for a remote check.
    Audit,
    /// Apply a config-only safeguard fix directly (no human input needed):
    /// `backup` enables scheduled auto-backup, `mutation` enables worker-
    /// signature rotation. Prints the re-run audit afterwards and exits 0
    /// when all config ACTION items are cleared.
    Fix {
        /// Which config-only fix to apply.
        #[arg()]
        what: FixWhat,
    },
}

#[derive(clap::ValueEnum, Clone)]
pub enum FixWhat {
    /// Enable scheduled auto-backup (daily snapshots, keep 5).
    Backup,
    /// Enable worker-signature rotation (anti-DPI moving target, daily).
    Mutation,
    /// Apply every config-only fix that resolves an ACTION item.
    All,
}

/// Phase-2 SNI strategy for the `find` command's advanced mode.
#[derive(clap::ValueEnum, Clone, Copy)]
pub enum StrategyChoice {
    /// Use only the worker hostname as SNI (`*.workers.dev`).
    WorkerOnly,
    /// Try a generic Cloudflare SNI first (bypasses `*.workers.dev` blocking).
    GenericFirst,
    /// Try the worker hostname first, then a generic CF SNI.
    WorkerThenGeneric,
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
    /// Deliver any alerts queued in the durable outbox (e.g. during a
    /// blackout) right now. Returns how many were delivered.
    Flush,
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
    /// Configure scheduled auto-backup (daemon snapshots the profile to
    /// ~/.dastyab/backups/ on an interval, trimming to a keep-count).
    Autosync {
        /// Enable (default) or disable scheduled auto-backup.
        #[arg(long)]
        disable: bool,
        /// Interval between auto-backups in seconds (default 86400 = 24h).
        #[arg(long)]
        interval: Option<u64>,
        /// How many newest backups to keep (default 7).
        #[arg(long)]
        keep: Option<usize>,
    },
}

#[derive(Subcommand)]
pub enum WorkspaceAction {
    /// Snapshot the whole workspace to a portable .dyb-snapshot.json.
    Snapshot {
        /// Output path (default: ~/.dastyab/workspace-snapshot.json).
        #[arg(long)]
        output: Option<String>,
        /// Snapshot scope: full|profiles|configs (default full).
        #[arg(long, default_value = "full")]
        scope: String,
    },
    /// Restore the whole workspace from a snapshot.
    Restore {
        /// Snapshot file to restore from.
        #[arg()]
        path: String,
        /// Overwrite existing profiles.
        #[arg(long)]
        overwrite: bool,
        /// Dry run: verify + report, write nothing.
        #[arg(long)]
        dry_run: bool,
    },
}

/// Scheduled workspace-snapshot subcommands.
#[derive(Subcommand)]
pub enum SnapshotsAction {
    /// List scheduled snapshots newest-first.
    List,
    /// Restore a past point (by index from `list`, newest = 0).
    Restore {
        /// Snapshot file to restore from.
        #[arg()]
        path: String,
        /// Overwrite existing profiles.
        #[arg(long)]
        overwrite: bool,
        /// Dry run: verify + report, write nothing.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum MutationAction {
    /// Show current scheduled-rotation config.
    Status,
    /// Configure scheduled worker-signature rotation.
    Configure {
        /// Disable rotation (default enables).
        #[arg(long)]
        disable: bool,
        /// Interval between rotations in seconds (default 86400 = 24h).
        #[arg(long)]
        interval: Option<u64>,
        /// Also rotate the worker URL path (default true).
        #[arg(long)]
        no_path: bool,
    },
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

/// Anti-DPI TCP desync fragmenter subcommands.
#[derive(Subcommand)]
pub enum DesyncAction {
    /// Show whether desync fragmentation is enabled (and its tuning/strategy).
    Status,
    /// Enable desync fragmentation (persisted on the profile).
    On {
        /// Smallest fragment size in bytes.
        #[arg(long, default_value_t = 8)]
        min_fragment: usize,
        /// Largest fragment size in bytes.
        #[arg(long, default_value_t = 64)]
        max_fragment: usize,
        /// Pause between flushed fragments, microseconds.
        #[arg(long, default_value_t = 300)]
        delay_us: u64,
        /// Desync strategy (split-clienthello | split-two | split+decoy | none).
        #[arg(long, default_value = "none")]
        strategy: String,
    },
    /// Disable desync fragmentation (persisted).
    Off,
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
    // Install the process-level rustls provider before any network/TLS work
    // (core uses aws-lc-rs; reqwest pulls ring too — explicit install avoids
    // the "could not determine CryptoProvider" panic, e.g. on `drill`).
    dastyab_core::tls::install_tls_provider();

    let cli = Cli::parse();

    if cli.no_stealth {
        dastyab_core::stealth::set_enabled(false);
    }

    if let Err(e) = commands::run(cli.profile, cli.command).await {
        eprintln!("\u{1b}[31m✗ {}\u{1b}[0m", e.explain());
        std::process::exit(1);
    }
}
