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
}

/// A concrete event ready to be formatted + sent.
#[derive(Debug, Clone, PartialEq)]
pub enum BeaconEvent {
    ProtectionStarted,
    ProtectionStopped,
    WorkerDeadGiveUp,
    FailoverSwitched { from: String, to: String },
    RescueRecovered,
    DailySummary { cycles: u32, uptime_pct: f32 },
    ConfigMutated { old_worker: String, new_worker: String },
    AccountBlocked { state: String, since: i64 },
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
        (
            BeaconEvent::FailoverSwitched { from, to },
            crate::diagnose::Locale::Fa,
        ) => format!("🔁 سوئیچ به پروفایل {to} (از {from})"),
        (BeaconEvent::FailoverSwitched { from, to }, _) => {
            format!("🔁 Failover switched to profile {to} (from {from})")
        }
        (BeaconEvent::RescueRecovered, crate::diagnose::Locale::Fa) => {
            "✅ اتصال بازیابی شد".to_string()
        }
        (BeaconEvent::RescueRecovered, _) => "✅ Connection recovered".to_string(),
        (
            BeaconEvent::DailySummary { cycles, uptime_pct },
            crate::diagnose::Locale::Fa,
        ) => format!("📊 خلاصه روزانه: {cycles} چرخه، {uptime_pct:.0}٪ آپ‌تایم"),
        (BeaconEvent::DailySummary { cycles, uptime_pct }, _) => {
            format!("📊 Daily summary: {cycles} cycles, {uptime_pct:.0}% uptime")
        }
        (BeaconEvent::ConfigMutated { old_worker, new_worker }, crate::diagnose::Locale::Fa) => {
            format!("🔄 امضای کارگر چرخید: {old_worker} ← {new_worker}")
        }
        (BeaconEvent::ConfigMutated { old_worker, new_worker }, _) => {
            format!("🔄 Worker signature rotated: {old_worker} → {new_worker}")
        }
        (BeaconEvent::AccountBlocked { state, .. }, crate::diagnose::Locale::Fa) => {
            format!(
                "⛔ حساب مسدود شد ({state}) — دستور «dastyab token recover <label> <token>» را اجرا کنید تا توکن جدید جایگزین و حفاظت خودکار دوباره شروع شود"
            )
        }
        (BeaconEvent::AccountBlocked { state, .. }, _) => {
            format!(
                "⛔ Account blocked ({state}) — run `dastyab token recover <label> <token>` to replace the token and auto-resume protection"
            )
        }
    }
}

/// Send a message over the configured channel. Telegram uses the
/// `sendMessage` bot API; a generic webhook is a raw JSON POST. 10s timeout.
pub async fn send(config: &BeaconConfig, message: &str) -> Result<(), CFError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| {
            CFError::new("Beacon", e.to_string(), "Cannot build HTTP client.")
        })?;

    match config.kind {
        BeaconKind::Telegram => {
            if config.token.is_empty() || config.chat_id_or_url.is_empty() {
                return Err(CFError::new(
                    "Beacon",
                    "Telegram config incomplete.",
                    "Set both bot token and chat id.",
                ));
            }
            let url = format!(
                "https://api.telegram.org/bot{}/sendMessage",
                config.token
            );
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
    match send(&cfg, &text).await {
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
        Box::pin(send(cfg, text))
    })
    .await
}

/// Hermetic core of `flush_outbox`. `deliver` is injected so tests can script
/// success/failure per alert without network access.
async fn flush_outbox_with_profile<F>(
    profile_id: &str,
    cfg: &BeaconConfig,
    deliver: F,
) -> usize
where
    F: for<'a> Fn(&'a str, &'a BeaconConfig) -> futures_util::future::BoxFuture<'a, Result<(), CFError>>,
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
        };
        let en = format_message(&ev, crate::diagnose::Locale::En);
        assert!(en.contains("token-invalid"), "en={en}");
        assert!(en.contains("Account blocked"));
        assert!(en.contains("token recover"), "en should carry the recovery action: {en}");
        let fa = format_message(&ev, crate::diagnose::Locale::Fa);
        assert!(fa.contains("token-invalid"), "fa={fa}");
        assert!(fa.contains("حساب"));
        assert!(fa.contains("token recover"), "fa should carry the recovery action: {fa}");
    }

    #[test]
    fn test_record_sent_persists_timestamp() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let tmp = std::env::temp_dir().join(format!(
            "kvrvn-beacon-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        crate::store::set_mem_dir_override(tmp.join(".dastyab"));
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
        let tmp = std::env::temp_dir().join(format!(
            "kvrvn-outbox-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        crate::store::set_mem_dir_override(tmp.join(".dastyab"));
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
        let tmp = std::env::temp_dir().join(format!(
            "kvrvn-outbox2-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        crate::store::set_mem_dir_override(tmp.join(".dastyab"));
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
        let tmp = std::env::temp_dir().join(format!(
            "kvrvn-flush-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        crate::store::set_mem_dir_override(tmp.join(".dastyab"));
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
        let tmp = std::env::temp_dir().join(format!(
            "kvrvn-flush2-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        crate::store::set_mem_dir_override(tmp.join(".dastyab"));
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
        let sent =
            flush_outbox_with_profile(profile, &cfg, |_text, _cfg| {
                Box::pin(async move {
                    Err(CFError::new(
                        "Test",
                        "channel blocked",
                        "blackout",
                    ))
                })
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
        let tmp = std::env::temp_dir().join(format!(
            "kvrvn-flush3-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        crate::store::set_mem_dir_override(tmp.join(".dastyab"));
        let profile = "flush3-test";
        std::fs::create_dir_all(store::profiles::profile_dir(profile)).unwrap();

        let cfg = BeaconConfig::default(); // enabled = false
        queue_for_retry(profile, "a").unwrap();

        let sent = flush_outbox_with_profile(profile, &cfg, |_text, _cfg| {
            Box::pin(async move { Ok(()) })
        })
        .await;
        assert_eq!(sent, 0);
        // Outbox untouched.
        assert_eq!(load_outbox(profile).len(), 1);

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
