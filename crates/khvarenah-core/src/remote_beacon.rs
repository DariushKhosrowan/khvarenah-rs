//! Remote health beacon — push notifications to the user's phone.
//!
//! The daemon writes a local `health.json` beacon and `daemon.log`, but when the
//! worker dies the user is asleep and never sees them. This module turns
//! "silently broken until I check" into "I know in 10 seconds" by pushing a
//! short message to Telegram (or a generic webhook) on state transitions.
//!
//! Design notes:
//! - **Rate-limited by event class**: at most one push per event class per
//!   `rate_limit_secs` (default 15 min). `should_send` is pure and unit-testable.
//! - **Never called from the hot loop**: the daemon wires `maybe_emit` at
//!   *state transitions* only (protection start/stop, worker-dead+giveup,
//!   failover switch, daily summary). Sending is async with a 10s timeout.
//! - **Optional**: all config lives in the profile store (GUI/CLI settable),
//!   so a user who doesn't want push notifications is untouched.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::error::CFError;
use crate::store;

/// The kinds of events that can be pushed. Each maps to its own rate-limit
/// class (state is tracked keyed by this).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum BeaconEventKind {
    ProtectionStarted,
    ProtectionStopped,
    WorkerDeadGiveUp,
    FailoverSwitched,
    RescueRecovered,
    DailySummary,
    ConfigMutated,
    AccountBlocked,
    /// Auto-rotation was attempted but every stored token failed verification
    /// — a fresh token must be added. Rate-limited as its own class so it is
    /// distinct from the initial `AccountBlocked` transition.
    AccountBlockedRotationExhausted,
    /// The daemon automatically rotated to another stored token because the
    /// active one was blocked/invalid (no manual `token recover` needed).
    TokenAutoRotated,
    NetworkDown,
    NetworkRestored,
    /// Scheduled blackout self-test found fewer ladder rungs up than before
    /// — resilience degraded and the user should know without being asked.
    ResilienceDegraded,
    /// The scheduled autonomy audit flipped from clean to dirty — a new
    /// safeguard needs attention (auto-execute did not clear it).
    AutonomyRegression,
}

/// A concrete event ready to be formatted + sent.
#[derive(Debug, Clone, PartialEq)]
pub enum BeaconEvent {
    ProtectionStarted,
    ProtectionStopped,
    WorkerDeadGiveUp,
    FailoverSwitched {
        from: String,
        to: String,
    },
    RescueRecovered,
    DailySummary {
        cycles: u32,
        uptime_pct: f32,
    },
    ConfigMutated {
        old_worker: String,
        new_worker: String,
    },
    AccountBlocked {
        state: String,
        since: i64,
        /// The profile the blocked account belongs to. Drives the exact
        /// recovery command: a non-default profile needs `--profile`, so the
        /// beacon can hand the user a copy-paste-ready, profile-specific
        /// recovery action rather than a generic one.
        profile: String,
        /// Whether auto-rotation across the profile's stored tokens is enabled
        /// (default on). When true, the daemon will try to self-heal before
        /// any manual step is needed.
        auto_rotate_enabled: bool,
        /// Number of tokens recorded in the profile at emission time. Drives
        /// whether the beacon message promises auto-recovery (>=2 tokens) or
        /// demands a manual token add (single token / rotation off).
        stored_tokens: usize,
    },
    /// Auto-rotation was attempted but every stored token failed verification.
    /// Emitted once per blocked episode, so a user who was promised
    /// auto-recovery learns it actually failed and must add a fresh token.
    AccountBlockedRotationExhausted {
        state: String,
        /// The profile whose stored tokens were exhausted (see `AccountBlocked`).
        profile: String,
        /// Number of stored tokens that were tried and failed.
        stored_tokens: usize,
    },
    /// The daemon automatically rotated to another stored token (the active
    /// one was blocked/invalid). Carries the old and new token labels.
    TokenAutoRotated {
        from: String,
        to: String,
    },
    NetworkDown {
        survival: String,
    },
    NetworkRestored,
    /// Scheduled blackout self-test found degraded resilience.
    ResilienceDegraded {
        /// "N/4" ladder rungs up.
        survivors: u8,
        /// Best rung name (Direct/DoH/DoT/DnsTunnel).
        best_tier: String,
    },
    /// The scheduled autonomy audit flipped from clean to dirty — auto-execute
    /// did not clear every action item. Carries the remaining action codes.
    AutonomyRegression {
        /// Codes of the action items still pending (e.g. "daemon", "token").
        codes: Vec<String>,
    },
}

impl BeaconEvent {
    pub fn kind(&self) -> BeaconEventKind {
        match self {
            BeaconEvent::ProtectionStarted => BeaconEventKind::ProtectionStarted,
            BeaconEvent::ProtectionStopped => BeaconEventKind::ProtectionStopped,
            BeaconEvent::WorkerDeadGiveUp => BeaconEventKind::WorkerDeadGiveUp,
            BeaconEvent::FailoverSwitched { .. } => BeaconEventKind::FailoverSwitched,
            BeaconEvent::RescueRecovered => BeaconEventKind::RescueRecovered,
            BeaconEvent::DailySummary { .. } => BeaconEventKind::DailySummary,
            BeaconEvent::ConfigMutated { .. } => BeaconEventKind::ConfigMutated,
            BeaconEvent::AccountBlocked { .. } => BeaconEventKind::AccountBlocked,
            BeaconEvent::AccountBlockedRotationExhausted { .. } => {
                BeaconEventKind::AccountBlockedRotationExhausted
            }
            BeaconEvent::TokenAutoRotated { .. } => BeaconEventKind::TokenAutoRotated,
            BeaconEvent::NetworkDown { .. } => BeaconEventKind::NetworkDown,
            BeaconEvent::NetworkRestored => BeaconEventKind::NetworkRestored,
            BeaconEvent::ResilienceDegraded { .. } => BeaconEventKind::ResilienceDegraded,
            BeaconEvent::AutonomyRegression { .. } => BeaconEventKind::AutonomyRegression,
        }
    }
}

/// The delivery channel.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub enum BeaconKind {
    #[default]
    Telegram,
    GenericWebhook,
}

/// Persisted (in the profile store) notification config.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BeaconConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub kind: BeaconKind,
    /// Telegram bot token (when kind == Telegram) — otherwise unused.
    #[serde(default)]
    pub token: String,
    /// Telegram chat id (when kind == Telegram) OR the generic webhook URL.
    #[serde(default)]
    pub chat_id_or_url: String,
    /// Rate-limit seconds per event class.
    #[serde(default = "default_rate_limit_secs")]
    pub rate_limit_secs: i64,
    /// Failover channel: when the primary channel fails (Telegram blocked in
    /// Iran, webhook down), the beacon automatically retries on this secondary
    /// channel before queueing to the outbox. This makes alerts resilient to
    /// any single channel being censored/blocked.
    #[serde(default)]
    pub failover_enabled: bool,
    #[serde(default)]
    pub failover_kind: BeaconKind,
    /// Secondary Telegram bot token (when failover_kind == Telegram).
    #[serde(default)]
    pub failover_token: String,
    /// Secondary Telegram chat id OR webhook URL.
    #[serde(default)]
    pub failover_chat_id_or_url: String,
}

fn default_rate_limit_secs() -> i64 {
    900
}

impl Default for BeaconConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            kind: BeaconKind::Telegram,
            token: String::new(),
            chat_id_or_url: String::new(),
            rate_limit_secs: 900,
            failover_enabled: false,
            failover_kind: BeaconKind::Telegram,
            failover_token: String::new(),
            failover_chat_id_or_url: String::new(),
        }
    }
}

/// Path to the per-profile beacon state (last-sent timestamps).
fn beacon_state_path(profile_id: &str) -> PathBuf {
    store::profiles::profile_dir(profile_id).join("beacon-state.json")
}

/// One queued alert that could not be delivered (e.g. network blackout,
/// Telegram blocked) and is waiting to be flushed when the network returns.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OutboxEntry {
    /// UNIX seconds when the alert was first queued.
    pub ts: i64,
    /// The formatted alert text (already localized).
    pub text: String,
}

/// Path to the durable beacon outbox for a profile.
fn outbox_path(profile_id: &str) -> PathBuf {
    store::profiles::profile_dir(profile_id).join("beacon-outbox.json")
}

/// Load the queued (undelivered) alerts for a profile.
pub fn load_outbox(profile_id: &str) -> Vec<OutboxEntry> {
    let p = outbox_path(profile_id);
    store::read_opt::<Vec<OutboxEntry>>(&p).unwrap_or_default()
}

/// Persist the outbox. Empty slice removes the file's contents (keeps the
/// file but trims it to `[]`).
pub fn save_outbox(profile_id: &str, entries: &[OutboxEntry]) -> Result<(), CFError> {
    store::write_json(&outbox_path(profile_id), &entries)
}

/// Durable-queue an alert text. Called when a send fails — during a total
/// blackout or when the deliver channel is blocked, the alert is persisted so
/// it can be flushed once the network returns. Never loses an alert.
pub fn queue_for_retry(profile_id: &str, text: &str) -> Result<(), CFError> {
    let mut ob = load_outbox(profile_id);
    ob.push(OutboxEntry {
        ts: store::now_ts() as i64,
        text: text.to_string(),
    });
    save_outbox(profile_id, &ob)
}

/// Load the last-sent map (per event class → UNIX seconds).
pub fn load_last_sent(profile_id: &str) -> HashMap<BeaconEventKind, i64> {
    let path = beacon_state_path(profile_id);
    store::read_opt::<HashMap<BeaconEventKind, i64>>(&path).unwrap_or_default()
}

/// Persist last-sent timestamps.
pub fn record_sent(profile_id: &str, kind: BeaconEventKind, now: i64) -> Result<(), CFError> {
    let mut map = load_last_sent(profile_id);
    map.insert(kind, now);
    store::write_json(&beacon_state_path(profile_id), &map)
}

/// Pure rate-limit check: true iff `kind` was not sent within `rate_limit_secs`
/// of `now`. Unit-testable with a scripted map.
pub fn should_send(
    kind: BeaconEventKind,
    last_sent: &HashMap<BeaconEventKind, i64>,
    now: i64,
    rate_limit_secs: i64,
) -> bool {
    match last_sent.get(&kind) {
        None => true,
        Some(last) => now - last >= rate_limit_secs,
    }
}

/// Build the recovery command for a blocked account, qualified with the actual
/// profile. A non-default profile needs `--profile` so the command is directly
/// copy-pasteable for the right profile instead of silently targeting `default`.
fn recovery_cmd(profile: &str) -> String {
    if profile.is_empty() || profile == "default" {
        "khvarenah token recover <label> <token>".to_string()
    } else {
        format!("khvarenah --profile {profile} token recover <label> <token>")
    }
}

/// Build the message text for a given event + language. Pure.
pub fn format_message(event: &BeaconEvent, lang: crate::diagnose::Locale) -> String {
    match (event, lang) {
        (BeaconEvent::ProtectionStarted, crate::diagnose::Locale::Fa) => {
            "🛡 حفاظت شروع شد".to_string()
        }
        (BeaconEvent::ProtectionStarted, _) => "🛡 Protection started".to_string(),
        (BeaconEvent::ProtectionStopped, crate::diagnose::Locale::Fa) => {
            "⏹ حفاظت متوقف شد".to_string()
        }
        (BeaconEvent::ProtectionStopped, _) => "⏹ Protection stopped".to_string(),
        (BeaconEvent::WorkerDeadGiveUp, crate::diagnose::Locale::Fa) => {
            "⚠️ کارگر از کار افتاد و همه تلاش‌ها ناموفق بود".to_string()
        }
        (BeaconEvent::WorkerDeadGiveUp, _) => {
            "⚠️ Worker dead: all rescue attempts failed".to_string()
        }
        (BeaconEvent::FailoverSwitched { from, to }, crate::diagnose::Locale::Fa) => {
            format!("🔁 سوئیچ به پروفایل {to} (از {from})")
        }
        (BeaconEvent::FailoverSwitched { from, to }, _) => {
            format!("🔁 Failover switched to profile {to} (from {from})")
        }
        (BeaconEvent::RescueRecovered, crate::diagnose::Locale::Fa) => {
            "✅ اتصال بازیابی شد".to_string()
        }
        (BeaconEvent::RescueRecovered, _) => "✅ Connection recovered".to_string(),
        (BeaconEvent::DailySummary { cycles, uptime_pct }, crate::diagnose::Locale::Fa) => {
            format!("📊 خلاصه روزانه: {cycles} چرخه، {uptime_pct:.0}٪ آپ‌تایم")
        }
        (BeaconEvent::DailySummary { cycles, uptime_pct }, _) => {
            format!("📊 Daily summary: {cycles} cycles, {uptime_pct:.0}% uptime")
        }
        (
            BeaconEvent::ConfigMutated {
                old_worker,
                new_worker,
            },
            crate::diagnose::Locale::Fa,
        ) => {
            format!("🔄 امضای کارگر چرخید: {old_worker} ← {new_worker}")
        }
        (
            BeaconEvent::ConfigMutated {
                old_worker,
                new_worker,
            },
            _,
        ) => {
            format!("🔄 Worker signature rotated: {old_worker} → {new_worker}")
        }
        (
            BeaconEvent::AccountBlocked {
                state,
                profile,
                auto_rotate_enabled,
                stored_tokens,
                ..
            },
            crate::diagnose::Locale::Fa,
        ) => {
            if *auto_rotate_enabled && *stored_tokens >= 2 {
                format!(
                    "⛔ حساب مسدود شد ({state}) — {stored_tokens} توکن ذخیره‌شده است؛ چرخش خودکار فعال است و در چند لحظه تلاش می‌کند توکن سالم جایگزین کند"
                )
            } else if *auto_rotate_enabled {
                let cmd = recovery_cmd(profile);
                format!(
                    "⛔ حساب مسدود شد ({state}) — فقط ۱ توکن ذخیره شده است؛ با «{cmd}» توکن دوم اضافه کنید تا چرخش خودکار فعال شود"
                )
            } else {
                let cmd = recovery_cmd(profile);
                format!("⛔ حساب مسدود شد ({state}) — چرخش خودکار خاموش است؛ «{cmd}» را اجرا کنید")
            }
        }
        (
            BeaconEvent::AccountBlockedRotationExhausted {
                state,
                profile,
                stored_tokens,
            },
            crate::diagnose::Locale::Fa,
        ) => {
            let cmd = recovery_cmd(profile);
            format!(
                "⛔ حساب مسدود شد ({state}) — چرخش خودکار هر {stored_tokens} توکن ذخیره‌شده را آزمایش کرد و هیچ‌کدام تأیید نشد؛ با «{cmd}» توکن جدید اضافه کنید"
            )
        }
        (
            BeaconEvent::AccountBlocked {
                state,
                profile,
                auto_rotate_enabled,
                stored_tokens,
                ..
            },
            _,
        ) => {
            if *auto_rotate_enabled && *stored_tokens >= 2 {
                format!(
                    "⛔ Account blocked ({state}) — {stored_tokens} tokens stored; auto-rotation is ON and will try to swap to a working token in moments"
                )
            } else if *auto_rotate_enabled {
                let cmd = recovery_cmd(profile);
                format!(
                    "⛔ Account blocked ({state}) — only 1 token stored; run `{cmd}` to add a second so auto-rotation can engage"
                )
            } else {
                let cmd = recovery_cmd(profile);
                format!(
                    "⛔ Account blocked ({state}) — auto-rotation is OFF; run `{cmd}` to replace the token and auto-resume protection"
                )
            }
        }
        (
            BeaconEvent::AccountBlockedRotationExhausted {
                state,
                profile,
                stored_tokens,
            },
            _,
        ) => {
            let cmd = recovery_cmd(profile);
            format!(
                "⛔ Account blocked ({state}) — auto-rotation tried all {stored_tokens} stored tokens and none verified; run `{cmd}` to add a fresh token and auto-resume"
            )
        }
        (BeaconEvent::TokenAutoRotated { from, to }, crate::diagnose::Locale::Fa) => {
            format!("🔁 توکن به‌طور خودکار چرخید: {from} ← {to} — حفاظت بدون دخالت ادامه می‌یابد")
        }
        (BeaconEvent::TokenAutoRotated { from, to }, _) => {
            format!("🔁 Token auto-rotated: {from} → {to} — protection resumed with no manual step")
        }
        (BeaconEvent::NetworkDown { survival }, crate::diagnose::Locale::Fa) => {
            format!("🌑 شبکه قطع شد ({survival}) — حفاظت صبر می‌کند و هنگام بازگشت شبکه به‌طور خودکار ادامه می‌یابد")
        }
        (BeaconEvent::NetworkDown { survival }, _) => {
            format!("🌑 Network down ({survival}) — protection holding; will auto-resume when the network returns")
        }
        (BeaconEvent::NetworkRestored, crate::diagnose::Locale::Fa) => {
            "✅ شبکه بازگشت — حفاظت خودکار از سر گرفته شد".to_string()
        }
        (BeaconEvent::NetworkRestored, _) => {
            "✅ Network restored — protection auto-resumed".to_string()
        }
        (
            BeaconEvent::ResilienceDegraded {
                survivors,
                best_tier,
            },
            crate::diagnose::Locale::Fa,
        ) => {
            format!(
                "⚠️ تست خودکار تاب‌آوری: فقط {survivors}/4 مسیر زنده‌اند (بهترین: {best_tier}) — کانال داده در قطعی کامل ممکن است در دسترس نباشد"
            )
        }
        (
            BeaconEvent::ResilienceDegraded {
                survivors,
                best_tier,
            },
            _,
        ) => {
            format!(
                "⚠️ Blackout self-test: only {survivors}/4 ladder rungs up (best: {best_tier}) — the data channel may not survive a total blackout"
            )
        }
        (BeaconEvent::AutonomyRegression { codes }, crate::diagnose::Locale::Fa) => {
            let list = codes.join("، ");
            format!("🛠 ممیزی خودکار رگرسیون یافت: اقدامات معلق — {list}")
        }
        (BeaconEvent::AutonomyRegression { codes }, _) => {
            let list = codes.join(", ");
            format!("🛠 Autonomy audit regression: action items still pending — {list}")
        }
    }
}

/// Send a message over the configured channel. Telegram uses the
/// `sendMessage` bot API; a generic webhook is a raw JSON POST. 10s timeout.
pub async fn send(config: &BeaconConfig, message: &str) -> Result<(), CFError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| CFError::new("Beacon", e.to_string(), "Cannot build HTTP client."))?;

    match config.kind {
        BeaconKind::Telegram => {
            if config.token.is_empty() || config.chat_id_or_url.is_empty() {
                return Err(CFError::new(
                    "Beacon",
                    "Telegram config incomplete.",
                    "Set both bot token and chat id.",
                ));
            }
            let url = format!("https://api.telegram.org/bot{}/sendMessage", config.token);
            let body = serde_json::json!({
                "chat_id": config.chat_id_or_url,
                "text": message,
                "disable_web_page_preview": true,
            });
            let resp = client
                .post(&url)
                .json(&body)
                .send()
                .await
                .map_err(|e| CFError::new("Beacon", e.to_string(), "Telegram unreachable."))?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                return Err(CFError::new(
                    "Beacon",
                    format!("Telegram returned HTTP {status}"),
                    "Check the bot token and chat id.",
                ));
            }
            Ok(())
        }
        BeaconKind::GenericWebhook => {
            if config.chat_id_or_url.is_empty() {
                return Err(CFError::new(
                    "Beacon",
                    "Webhook URL empty.",
                    "Set a webhook URL.",
                ));
            }
            let resp = client
                .post(&config.chat_id_or_url)
                .json(&serde_json::json!({ "text": message }))
                .send()
                .await
                .map_err(|e| CFError::new("Beacon", e.to_string(), "Webhook unreachable."))?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                return Err(CFError::new(
                    "Beacon",
                    format!("Webhook returned HTTP {status}"),
                    "Check the webhook URL.",
                ));
            }
            Ok(())
        }
    }
}

/// Build the failover channel config from a beacon config, when failover is
/// enabled and the secondary channel is complete for its kind. Pure.
fn failover_config(config: &BeaconConfig) -> Option<BeaconConfig> {
    if !config.failover_enabled {
        return None;
    }
    let fc = BeaconConfig {
        enabled: true,
        kind: config.failover_kind.clone(),
        token: config.failover_token.clone(),
        chat_id_or_url: config.failover_chat_id_or_url.clone(),
        rate_limit_secs: config.rate_limit_secs,
        failover_enabled: false,
        failover_kind: BeaconKind::Telegram,
        failover_token: String::new(),
        failover_chat_id_or_url: String::new(),
    };
    match fc.kind {
        BeaconKind::Telegram => {
            if fc.token.is_empty() || fc.chat_id_or_url.is_empty() {
                None
            } else {
                Some(fc)
            }
        }
        BeaconKind::GenericWebhook => {
            if fc.chat_id_or_url.is_empty() {
                None
            } else {
                Some(fc)
            }
        }
    }
}

/// The ordered list of channels to try, primary first, then failover. Pure.
fn delivery_order(config: &BeaconConfig) -> Vec<BeaconConfig> {
    let mut v = vec![config.clone()];
    if let Some(fc) = failover_config(config) {
        v.push(fc);
    }
    v
}

/// Deliver a message trying every configured channel (primary, then failover)
/// in order. Returns Ok as soon as any channel delivers; the caller only sees
/// an error when every channel failed — at which point the alert is queued to
/// the outbox for later delivery.
pub async fn send_with_failover(config: &BeaconConfig, message: &str) -> Result<(), CFError> {
    let chain = delivery_order(config);
    let mut last_err = None;
    for c in chain {
        match send(&c, message).await {
            Ok(()) => return Ok(()),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        CFError::new(
            "Beacon",
            "no channel configured",
            "Enable notifications first.",
        )
    }))
}

/// Load the stored config for a profile (defaults when absent).
pub fn load_config(profile_id: &str) -> BeaconConfig {
    let p = store::profiles::load_profile(profile_id);
    p.config.beacon.clone().unwrap_or_default()
}

/// Full emit path: rate-limit check → format → send → record. Returns `Ok`
/// when suppressed or sent, `Err` only on a genuine send failure after the
/// rate limit cleared (so callers can log it).
pub async fn maybe_emit(
    profile_id: &str,
    event: &BeaconEvent,
    lang: crate::diagnose::Locale,
) -> Result<bool, CFError> {
    let cfg = load_config(profile_id);
    if !cfg.enabled {
        return Ok(false);
    }
    let now = store::now_ts() as i64;
    let last = load_last_sent(profile_id);
    if !should_send(event.kind(), &last, now, cfg.rate_limit_secs) {
        return Ok(false);
    }
    let text = format_message(event, lang);
    match send_with_failover(&cfg, &text).await {
        Ok(()) => {
            record_sent(profile_id, event.kind(), now)?;
            Ok(true)
        }
        Err(_) => {
            // Durable queue: never lose an alert during a blackout or a
            // blocked channel. Persist it, and it will be flushed once the
            // network returns (see `flush_outbox`).
            queue_for_retry(profile_id, &text)?;
            Ok(false)
        }
    }
}

/// Attempt to deliver every queued alert (outbox). Returns the number of
/// alerts successfully delivered. Failed deliveries stay queued for the next
/// flush. Best-effort — never fails the caller. No-op when notifications are
/// disabled or the outbox is empty.
pub async fn flush_outbox(profile_id: &str) -> usize {
    let cfg = load_config(profile_id);
    flush_outbox_with_profile(profile_id, &cfg, |text, cfg| {
        Box::pin(send_with_failover(cfg, text))
    })
    .await
}

/// Hermetic core of `flush_outbox`. `deliver` is injected so tests can script
/// success/failure per alert without network access.
async fn flush_outbox_with_profile<F>(profile_id: &str, cfg: &BeaconConfig, deliver: F) -> usize
where
    F: for<'a> Fn(
        &'a str,
        &'a BeaconConfig,
    ) -> futures_util::future::BoxFuture<'a, Result<(), CFError>>,
{
    if !cfg.enabled {
        return 0;
    }
    let mut ob = load_outbox(profile_id);
    if ob.is_empty() {
        return 0;
    }
    let mut remaining = Vec::with_capacity(ob.len());
    let mut sent = 0usize;
    for entry in ob.drain(..) {
        match deliver(&entry.text, cfg).await {
            Ok(()) => sent += 1,
            Err(_) => remaining.push(entry),
        }
    }
    let _ = save_outbox(profile_id, &remaining);
    sent
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> HashMap<BeaconEventKind, i64> {
        HashMap::new()
    }

    #[test]
    fn test_should_send_true_for_new_event() {
        assert!(should_send(
            BeaconEventKind::ProtectionStarted,
            &map(),
            1000,
            900
        ));
    }

    #[test]
    fn test_should_send_false_within_rate_limit() {
        let mut m = map();
        m.insert(BeaconEventKind::ProtectionStarted, 500);
        assert!(!should_send(
            BeaconEventKind::ProtectionStarted,
            &m,
            1000,
            900
        ));
    }

    #[test]
    fn test_should_send_true_after_rate_limit_expires() {
        let mut m = map();
        m.insert(BeaconEventKind::ProtectionStarted, 500);
        // 1000 - 500 = 500 < 900 → still limited.
        assert!(!should_send(
            BeaconEventKind::ProtectionStarted,
            &m,
            1000,
            900
        ));
        // 1400 - 500 = 900 → exactly at limit → allowed.
        assert!(should_send(
            BeaconEventKind::ProtectionStarted,
            &m,
            1400,
            900
        ));
    }

    #[test]
    fn test_format_message_telegram_protection_started() {
        let msg = format_message(&BeaconEvent::ProtectionStarted, crate::diagnose::Locale::En);
        assert!(msg.contains("Protection started"));
    }

    #[test]
    fn test_format_message_telegram_worker_dead() {
        let msg = format_message(&BeaconEvent::WorkerDeadGiveUp, crate::diagnose::Locale::En);
        assert!(msg.contains("rescue"));
    }

    #[test]
    fn test_format_message_failover_contains_profiles() {
        let msg = format_message(
            &BeaconEvent::FailoverSwitched {
                from: "a".into(),
                to: "b".into(),
            },
            crate::diagnose::Locale::En,
        );
        assert!(msg.contains("a"));
        assert!(msg.contains("b"));
    }

    #[test]
    fn test_format_message_webhook_contains_event_kind() {
        let msg = format_message(
            &BeaconEvent::DailySummary {
                cycles: 42,
                uptime_pct: 99.5,
            },
            crate::diagnose::Locale::En,
        );
        assert!(msg.contains("42"));
        // 99.5 formats with `:.0` → rounds to "100".
        assert!(msg.contains("100"));
    }

    #[test]
    fn test_format_message_account_blocked_en_and_fa() {
        let ev = BeaconEvent::AccountBlocked {
            state: "token-invalid".into(),
            since: 1234,
            profile: "default".into(),
            auto_rotate_enabled: false,
            stored_tokens: 1,
        };
        let en = format_message(&ev, crate::diagnose::Locale::En);
        assert!(en.contains("token-invalid"), "en={en}");
        assert!(en.contains("Account blocked"));
        assert!(
            en.contains("token recover"),
            "en should carry the recovery action: {en}"
        );
        let fa = format_message(&ev, crate::diagnose::Locale::Fa);
        assert!(fa.contains("token-invalid"), "fa={fa}");
        assert!(fa.contains("حساب"));
        assert!(
            fa.contains("token recover"),
            "fa should carry the recovery action: {fa}"
        );
    }

    #[test]
    fn test_format_message_account_blocked_auto_rotate_promises_selfheal() {
        // Auto-rotation on with >=2 stored tokens → the message promises the
        // daemon will self-heal, not demand a manual command.
        let ev = BeaconEvent::AccountBlocked {
            state: "suspended".into(),
            since: 1234,
            profile: "default".into(),
            auto_rotate_enabled: true,
            stored_tokens: 3,
        };
        let en = format_message(&ev, crate::diagnose::Locale::En);
        assert!(en.contains("auto-rotation is ON"), "en={en}");
        assert!(en.contains("3 tokens stored"), "en={en}");
        // The manual step should NOT be the headline when auto-rotation engages.
        assert!(!en.contains("run `khvarenah token recover"), "en={en}");
        let fa = format_message(&ev, crate::diagnose::Locale::Fa);
        assert!(fa.contains("چرخش خودکار فعال"), "fa={fa}");
        assert!(!fa.contains("token recover"), "fa={fa}");
    }

    #[test]
    fn test_format_message_account_blocked_auto_rotate_single_token_asks_for_second() {
        // Auto-rotation on but only ONE token stored → cannot rotate; the
        // message must tell the user to add a second token.
        let ev = BeaconEvent::AccountBlocked {
            state: "token-invalid".into(),
            since: 1234,
            profile: "default".into(),
            auto_rotate_enabled: true,
            stored_tokens: 1,
        };
        let en = format_message(&ev, crate::diagnose::Locale::En);
        assert!(en.contains("only 1 token"), "en={en}");
        assert!(en.contains("token recover"), "en={en}");
        assert!(en.contains("add a second"), "en={en}");
    }

    #[test]
    fn test_format_message_account_blocked_nondefault_profile_qualifies_recovery() {
        // A non-default profile must yield a profile-qualified recovery command
        // so the user's copy-paste doesn't silently target `default`.
        let ev = BeaconEvent::AccountBlocked {
            state: "suspended".into(),
            since: 1234,
            profile: "backup".into(),
            auto_rotate_enabled: false,
            stored_tokens: 1,
        };
        let en = format_message(&ev, crate::diagnose::Locale::En);
        assert!(en.contains("--profile backup"), "en={en}");
        assert!(en.contains("token recover"), "en={en}");
        // The bare default-profile command must NOT appear.
        assert!(!en.contains("token recover <label> <token> `"), "en={en}");
        let fa = format_message(&ev, crate::diagnose::Locale::Fa);
        assert!(fa.contains("--profile backup"), "fa={fa}");
    }

    #[test]
    fn test_format_message_token_auto_rotated_en_and_fa() {
        let ev = BeaconEvent::TokenAutoRotated {
            from: "primary".into(),
            to: "backup".into(),
        };
        let en = format_message(&ev, crate::diagnose::Locale::En);
        assert!(en.contains("primary"), "en={en}");
        assert!(en.contains("backup"), "en={en}");
        assert!(en.contains("auto-rotated"));
        let fa = format_message(&ev, crate::diagnose::Locale::Fa);
        assert!(fa.contains("primary"), "fa={fa}");
        assert!(fa.contains("backup"), "fa={fa}");
        assert!(fa.contains("خودکار"));
    }

    #[test]
    fn test_record_sent_persists_timestamp() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let tmp = std::env::temp_dir().join(format!("kvrvn-beacon-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        crate::store::set_mem_dir_override(tmp.join(".khvarenah"));
        let profile = "beacon-test";
        std::fs::create_dir_all(store::profiles::profile_dir(profile)).unwrap();
        record_sent(profile, BeaconEventKind::ProtectionStarted, 1234).unwrap();
        let loaded = load_last_sent(profile);
        assert_eq!(loaded.get(&BeaconEventKind::ProtectionStarted), Some(&1234));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_default_config_disabled() {
        let cfg = BeaconConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.rate_limit_secs >= 900);
    }

    #[test]
    fn test_queue_for_retry_persists_and_loads() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let tmp = std::env::temp_dir().join(format!("kvrvn-outbox-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        crate::store::set_mem_dir_override(tmp.join(".khvarenah"));
        let profile = "outbox-test";
        std::fs::create_dir_all(store::profiles::profile_dir(profile)).unwrap();

        assert!(load_outbox(profile).is_empty());
        queue_for_retry(profile, "alert one").unwrap();
        queue_for_retry(profile, "alert two").unwrap();
        let ob = load_outbox(profile);
        assert_eq!(ob.len(), 2);
        assert_eq!(ob[0].text, "alert one");
        assert_eq!(ob[1].text, "alert two");
        // ts is a UNIX epoch (positive for any realistic clock).
        assert!(ob[0].ts > 0);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_outbox_roundtrip_trim_when_empty() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let tmp = std::env::temp_dir().join(format!("kvrvn-outbox2-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        crate::store::set_mem_dir_override(tmp.join(".khvarenah"));
        let profile = "outbox2-test";
        std::fs::create_dir_all(store::profiles::profile_dir(profile)).unwrap();

        queue_for_retry(profile, "x").unwrap();
        assert_eq!(load_outbox(profile).len(), 1);
        save_outbox(profile, &[]).unwrap();
        assert!(load_outbox(profile).is_empty());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn test_flush_outbox_delivers_and_drains() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let tmp = std::env::temp_dir().join(format!("kvrvn-flush-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        crate::store::set_mem_dir_override(tmp.join(".khvarenah"));
        let profile = "flush-test";
        std::fs::create_dir_all(store::profiles::profile_dir(profile)).unwrap();

        // Configure + enable the beacon.
        let cfg = BeaconConfig {
            enabled: true,
            chat_id_or_url: "https://hook.test".into(),
            ..Default::default()
        };
        let mut p = store::profiles::load_profile(profile);
        p.config.beacon = Some(cfg.clone());
        store::profiles::save_profile(&p).unwrap();

        // Queue two alerts.
        queue_for_retry(profile, "a").unwrap();
        queue_for_retry(profile, "b").unwrap();

        // Hermetic flush: both deliver → 2 sent, outbox empty.
        let sent = flush_outbox_with_profile(profile, &cfg, |text, _cfg| {
            let text = text.to_string();
            Box::pin(async move {
                assert!(text == "a" || text == "b");
                Ok(())
            })
        })
        .await;
        assert_eq!(sent, 2);
        assert!(load_outbox(profile).is_empty());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn test_flush_outbox_keeps_failures() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let tmp = std::env::temp_dir().join(format!("kvrvn-flush2-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        crate::store::set_mem_dir_override(tmp.join(".khvarenah"));
        let profile = "flush2-test";
        std::fs::create_dir_all(store::profiles::profile_dir(profile)).unwrap();

        let cfg = BeaconConfig {
            enabled: true,
            chat_id_or_url: "https://hook.test".into(),
            ..Default::default()
        };
        let mut p = store::profiles::load_profile(profile);
        p.config.beacon = Some(cfg.clone());
        store::profiles::save_profile(&p).unwrap();

        queue_for_retry(profile, "fail").unwrap();

        // Deliver always fails → 0 sent, alert stays queued.
        let sent = flush_outbox_with_profile(profile, &cfg, |_text, _cfg| {
            Box::pin(async move { Err(CFError::new("Test", "channel blocked", "blackout")) })
        })
        .await;
        assert_eq!(sent, 0);
        let ob = load_outbox(profile);
        assert_eq!(ob.len(), 1);
        assert_eq!(ob[0].text, "fail");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn test_flush_outbox_disabled_is_noop() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let tmp = std::env::temp_dir().join(format!("kvrvn-flush3-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        crate::store::set_mem_dir_override(tmp.join(".khvarenah"));
        let profile = "flush3-test";
        std::fs::create_dir_all(store::profiles::profile_dir(profile)).unwrap();

        let cfg = BeaconConfig::default(); // enabled = false
        queue_for_retry(profile, "a").unwrap();

        let sent =
            flush_outbox_with_profile(profile, &cfg, |_text, _cfg| Box::pin(async move { Ok(()) }))
                .await;
        assert_eq!(sent, 0);
        // Outbox untouched.
        assert_eq!(load_outbox(profile).len(), 1);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ---- failover channel logic (pure) ----

    fn base_cfg() -> BeaconConfig {
        BeaconConfig {
            enabled: true,
            kind: BeaconKind::Telegram,
            token: "primary-token".into(),
            chat_id_or_url: "111".into(),
            rate_limit_secs: 900,
            failover_enabled: false,
            failover_kind: BeaconKind::GenericWebhook,
            failover_token: String::new(),
            failover_chat_id_or_url: String::new(),
        }
    }

    #[test]
    fn failover_disabled_means_no_failover_chain() {
        let cfg = base_cfg(); // failover_enabled = false
        assert!(failover_config(&cfg).is_none());
        assert_eq!(
            delivery_order(&cfg).len(),
            1,
            "primary only when failover off"
        );
    }

    #[test]
    fn failover_requires_complete_secondary() {
        // Enabled but empty secondary webhook → no failover (can't send).
        let mut cfg = base_cfg();
        cfg.failover_enabled = true;
        cfg.failover_kind = BeaconKind::GenericWebhook;
        cfg.failover_chat_id_or_url.clear();
        assert!(failover_config(&cfg).is_none());
        assert_eq!(delivery_order(&cfg).len(), 1);

        // Complete secondary webhook is appended after primary.
        cfg.failover_chat_id_or_url = "https://hooks.example.com/x".into();
        let fc = failover_config(&cfg).expect("complete failover present");
        assert_eq!(fc.kind, BeaconKind::GenericWebhook);
        assert_eq!(fc.chat_id_or_url, "https://hooks.example.com/x");
        let order = delivery_order(&cfg);
        assert_eq!(order.len(), 2);
        assert_eq!(order[0].kind, BeaconKind::Telegram);
        assert_eq!(order[1].kind, BeaconKind::GenericWebhook);
    }

    #[test]
    fn failover_secondary_telegram_needs_token_and_chat() {
        let mut cfg = base_cfg();
        cfg.failover_enabled = true;
        cfg.failover_kind = BeaconKind::Telegram;
        cfg.failover_token = "backup-token".into();
        cfg.failover_chat_id_or_url = "222".into();
        assert!(failover_config(&cfg).is_some());
        let order = delivery_order(&cfg);
        assert_eq!(order.len(), 2);
        assert_eq!(order[1].token, "backup-token");
        assert_eq!(order[1].chat_id_or_url, "222");

        // Missing token → no failover.
        cfg.failover_token.clear();
        assert!(failover_config(&cfg).is_none());
    }

    #[test]
    fn failover_self_recursion_is_disabled_in_secondary() {
        let mut cfg = base_cfg();
        cfg.failover_enabled = true;
        cfg.failover_kind = BeaconKind::GenericWebhook;
        cfg.failover_chat_id_or_url = "https://hooks.example.com/x".into();
        let fc = failover_config(&cfg).unwrap();
        // The secondary must never again try to fail over (no infinite loop).
        assert!(!fc.failover_enabled);
        assert_eq!(delivery_order(&fc).len(), 1);
    }

    #[test]
    fn network_down_event_formats_survival_plan() {
        let en = format_message(
            &BeaconEvent::NetworkDown {
                survival: "total-blackout".into(),
            },
            crate::diagnose::Locale::En,
        );
        assert!(en.contains("Network down"));
        assert!(en.contains("total-blackout"));
        let fa = format_message(
            &BeaconEvent::NetworkDown {
                survival: "dns-hijacked".into(),
            },
            crate::diagnose::Locale::Fa,
        );
        assert!(fa.contains("شبکه"));
    }

    #[test]
    fn network_restored_event_formats() {
        let en = format_message(&BeaconEvent::NetworkRestored, crate::diagnose::Locale::En);
        assert!(en.contains("Network restored"));
        let fa = format_message(&BeaconEvent::NetworkRestored, crate::diagnose::Locale::Fa);
        assert!(fa.contains("شبکه"));
    }

    #[test]
    fn network_event_kinds_map_to_own_rate_limit_class() {
        assert_eq!(
            BeaconEvent::NetworkDown {
                survival: "x".into()
            }
            .kind(),
            BeaconEventKind::NetworkDown
        );
        assert_eq!(
            BeaconEvent::NetworkRestored.kind(),
            BeaconEventKind::NetworkRestored
        );
        assert_ne!(
            BeaconEventKind::NetworkDown,
            BeaconEventKind::NetworkRestored
        );
    }

    #[test]
    fn resilience_degraded_event_formats_and_kind() {
        let ev = BeaconEvent::ResilienceDegraded {
            survivors: 2,
            best_tier: "DoH".into(),
        };
        assert_eq!(ev.kind(), BeaconEventKind::ResilienceDegraded);
        assert_ne!(ev.kind(), BeaconEventKind::NetworkDown);
        let en = format_message(&ev, crate::diagnose::Locale::En);
        assert!(en.contains("Blackout self-test"));
        assert!(en.contains("2/4"));
        let fa = format_message(&ev, crate::diagnose::Locale::Fa);
        assert!(fa.contains("تاب‌آوری"));
    }
}
