//! Zero-result diagnostics — explain "why zero clean IPs?" in plain language.
//!
//! The parallel pipeline already counts every stage (`PipelineDiagnostics`), so
//! when a scan comes back empty we can say exactly which layer ate the results
//! instead of showing a bare "0 verified". `PlainCause` is a pure value; the
//! human-facing sentence and the recommended action are derived from it. The
//! message language deliberately never mentions SNI, ports, UUIDs, phase-2,
//! WebSocket, or E2E — a normal user should get "your worker's route is
//! missing, check the dashboard", not a protocol dump.

use crate::e2e::E2eFailureStage;
use crate::slipscan::PipelineDiagnostics;

/// The single most likely reason a scan found nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlainCause {
    /// The Worker is not deployed / the account is suspended (probe of the
    /// worker route failed outright, e.g. a 9109 API error).
    WorkerDead,
    /// The worker exists but responds on a different WS path than we probe
    /// (400/426 during the upgrade).
    WorkerPathMismatch,
    /// Every candidate edge failed the TCP probe (censored network / no
    /// route to Cloudflare at all).
    NetworkBlocked,
    /// Edges answered, workers responded, but the tunnels always egress from
    /// our own IP — the worker is not actually routing traffic.
    E2eIpUnchanged,
    /// Candidates passed the deep gate and tunneled, but too few were scanned
    /// for us to trust the empty result.
    InsufficientCandidates,
}

/// One recommended action for the user, phrased as a single verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecommendedAction {
    OpenCloudflareDashboard,
    Reauthenticate,
    ImportSeeds,
    RetryWithMoreSamples,
    CheckNetwork,
}

/// Which language to render `plain_message` in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locale {
    En,
    Fa,
}

/// A tiny snapshot of what a one-shot worker probe observed. Constructed by
/// the caller (CLI/GUI) from a real `GET` against the worker route.
#[derive(Debug, Clone, Copy, Default)]
pub struct WorkerProbe {
    /// Did the worker respond at all (any HTTP status)?
    pub responding: bool,
    /// The HTTP status observed (0 = not responding). 200/101 is healthy.
    pub status: u16,
    /// True when the status suggests the path is wrong (400/404/426).
    pub path_mismatch: bool,
}

/// Decide the cause from pipeline diagnostics + a worker probe. The check
/// order encodes "fix the cheapest, most foundational thing first":
/// account/worker state → network reachability → path → tunnel routing →
/// coverage.
pub fn diagnose(diag: &PipelineDiagnostics, probe: WorkerProbe) -> PlainCause {
    if !probe.responding {
        return PlainCause::WorkerDead;
    }
    if probe.path_mismatch {
        return PlainCause::WorkerPathMismatch;
    }

    // Diagnostics are all-zero when the pipeline never got a candidate list
    // (nothing was examined) — treat that as "not enough coverage".
    if diag.examined_total == 0 {
        return PlainCause::InsufficientCandidates;
    }

    // All TCP probes failed → the network is blocking Cloudflare edges.
    if diag.phase1_pass == 0 {
        return PlainCause::NetworkBlocked;
    }

    // Some edges passed TCP but none passed the deep gate → could be network
    // or worker; if the worker responds at all, the likely cause is path.
    if diag.phase2_pass == 0 {
        if probe.status != 0 {
            return PlainCause::WorkerPathMismatch;
        }
        return PlainCause::NetworkBlocked;
    }

    // Edges passed the deep gate but every E2E tunnel failed.
    if diag.score_above_threshold > 0 {
        let ip_unchanged = diag
            .e2e_fail_by_stage
            .get(&E2eFailureStage::IpUnchanged)
            .copied()
            .unwrap_or(0);
        if diag.e2e_enabled && diag.e2e_pass == 0 && ip_unchanged > 0 {
            return PlainCause::E2eIpUnchanged;
        }
        if diag.e2e_enabled && diag.e2e_pass == 0 {
            return PlainCause::WorkerDead;
        }
    }

    if diag.phase1_pass < 50 {
        return PlainCause::InsufficientCandidates;
    }

    // Everything looked healthy but we still scored zero — the most useful
    // next step is to scan more.
    PlainCause::InsufficientCandidates
}

/// One plain-language sentence for a normal user (never protocol jargon).
pub fn plain_message(cause: PlainCause, locale: Locale) -> String {
    let en = match cause {
        PlainCause::WorkerDead => {
            "Cloudflare isn't answering on your Worker's route. Open the Workers dashboard and check the Worker is deployed and enabled."
        }
        PlainCause::WorkerPathMismatch => {
            "Your Worker is up, but it's not answering where this app looks. Mostly the path is wrong — verify your Worker's path in the dashboard."
        }
        PlainCause::NetworkBlocked => {
            "None of the server addresses answered on this network — your connection is probably blocking them. Try another network, or import addresses you already know work."
        }
        PlainCause::E2eIpUnchanged => {
            "The addresses connect, but the tunnel is not actually carrying your traffic — the Worker route looks broken. Check the Workers dashboard for errors."
        }
        PlainCause::InsufficientCandidates => {
            "Not enough addresses were tested to find a working one. Run the scan again with a larger sample."
        }
    };
    match locale {
        Locale::En => en.to_string(),
        Locale::Fa => {
            let fa = match cause {
                PlainCause::WorkerDead => {
                    "کلودفلر در مسیر Worker شما پاسخ نمی‌دهد. داشبورد Workers را باز کرده و بررسی کنید که Worker فعال و مستقر باشد."
                }
                PlainCause::WorkerPathMismatch => {
                    "Worker شما فعال است، اما در مسیری که این برنامه جستجو می‌کند پاسخ نمی‌دهد — بیشتر اوقات مسیر اشتباه است؛ آن را در داشبورد بررسی کنید."
                }
                PlainCause::NetworkBlocked => {
                    "هیچ‌کدام از آدرس‌های سرور در این شبکه پاسخ ندادند — احتمالاً شبکه شما آن‌ها را مسدود کرده است. شبکه دیگری را امتحان کنید یا آدرس‌های کارکرده وارد کنید."
                }
                PlainCause::E2eIpUnchanged => {
                    "آدرس‌ها متصل می‌شوند اما تونل واقعاً ترافیک شما را منتقل نمی‌کند — مسیر Worker خراب به نظر می‌رسد. خطاهای داشبورد Workers را بررسی کنید."
                }
                PlainCause::InsufficientCandidates => {
                    "تعداد کافی آدرس برای یافتن یک آدرس کارکرده آزمایش نشد. دوباره با نمونه بزرگ‌تر اسکن کنید."
                }
            };
            fa.to_string()
        }
    }
}

/// One recommended action (never a menu).
pub fn recommended_action(cause: PlainCause) -> RecommendedAction {
    match cause {
        PlainCause::WorkerDead => RecommendedAction::OpenCloudflareDashboard,
        PlainCause::WorkerPathMismatch => RecommendedAction::OpenCloudflareDashboard,
        PlainCause::NetworkBlocked => RecommendedAction::CheckNetwork,
        PlainCause::E2eIpUnchanged => RecommendedAction::OpenCloudflareDashboard,
        PlainCause::InsufficientCandidates => RecommendedAction::RetryWithMoreSamples,
    }
}

impl RecommendedAction {
    /// A short human label for the action button.
    pub fn label(&self, locale: Locale) -> String {
        let en = match self {
            RecommendedAction::OpenCloudflareDashboard => "Open Workers dashboard",
            RecommendedAction::Reauthenticate => "Reconnect Cloudflare account",
            RecommendedAction::ImportSeeds => "Import working addresses",
            RecommendedAction::RetryWithMoreSamples => "Scan again with more",
            RecommendedAction::CheckNetwork => "Check network / switch network",
        };
        match locale {
            Locale::En => en.to_string(),
            Locale::Fa => {
                let fa = match self {
                    RecommendedAction::OpenCloudflareDashboard => "باز کردن داشبورد Workers",
                    RecommendedAction::Reauthenticate => "اتصال مجدد حساب کلودفلر",
                    RecommendedAction::ImportSeeds => "وارد کردن آدرس‌های کارکرده",
                    RecommendedAction::RetryWithMoreSamples => "اسکن دوباره با نمونه بیشتر",
                    RecommendedAction::CheckNetwork => "بررسی شبکه / تعویض شبکه",
                };
                fa.to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn diag_with() -> PipelineDiagnostics {
        PipelineDiagnostics {
            examined_total: 2000,
            phase1_pass: 500,
            phase2_pass: 40,
            score_above_threshold: 20,
            e2e_pass: 0,
            e2e_fail_by_stage: HashMap::new(),
            ws_failure_histogram: HashMap::new(),
            failure_by_sni: HashMap::new(),
            success_by_profile: HashMap::new(),
            cancelled_early: false,
            e2e_enabled: true,
        }
    }

    #[test]
    fn dead_worker_is_first_check() {
        let d = diag_with();
        let probe = WorkerProbe {
            responding: false,
            status: 0,
            path_mismatch: false,
        };
        assert_eq!(diagnose(&d, probe), PlainCause::WorkerDead);
    }

    #[test]
    fn path_mismatch_ranked_before_network() {
        let d = diag_with();
        let probe = WorkerProbe {
            responding: true,
            status: 404,
            path_mismatch: true,
        };
        assert_eq!(diagnose(&d, probe), PlainCause::WorkerPathMismatch);
    }

    #[test]
    fn all_tcp_failed_is_network_blocked() {
        let mut d = diag_with();
        d.phase1_pass = 0;
        d.phase2_pass = 0;
        d.score_above_threshold = 0;
        let probe = WorkerProbe {
            responding: true,
            status: 200,
            path_mismatch: false,
        };
        assert_eq!(diagnose(&d, probe), PlainCause::NetworkBlocked);
    }

    #[test]
    fn zero_examined_is_insufficient_coverage() {
        let d = PipelineDiagnostics::default();
        let probe = WorkerProbe {
            responding: true,
            status: 200,
            path_mismatch: false,
        };
        assert_eq!(diagnose(&d, probe), PlainCause::InsufficientCandidates);
    }

    #[test]
    fn ip_unchanged_ranked_over_generic_worker() {
        let mut d = diag_with();
        d.e2e_fail_by_stage.insert(E2eFailureStage::IpUnchanged, 20);
        d.score_above_threshold = 20;
        let probe = WorkerProbe {
            responding: true,
            status: 200,
            path_mismatch: false,
        };
        assert_eq!(diagnose(&d, probe), PlainCause::E2eIpUnchanged);
    }

    #[test]
    fn e2e_disabled_zero_pass_falls_back() {
        let mut d = diag_with();
        d.e2e_enabled = false;
        d.e2e_pass = 0;
        d.phase1_pass = 60;
        let probe = WorkerProbe {
            responding: true,
            status: 200,
            path_mismatch: false,
        };
        // Above threshold, E2E disabled → not IP-unchanged; phase1 >= 50 so
        // the fall-through is InsufficientCandidates.
        assert_eq!(diagnose(&d, probe), PlainCause::InsufficientCandidates);
    }

    #[test]
    fn message_never_leaks_fuzz() {
        for cause in [
            PlainCause::WorkerDead,
            PlainCause::WorkerPathMismatch,
            PlainCause::NetworkBlocked,
            PlainCause::E2eIpUnchanged,
            PlainCause::InsufficientCandidates,
        ] {
            let m = plain_message(cause, Locale::En);
            for forbidden in [
                "SNI",
                "sni",
                "uuid",
                "UUID",
                "phase",
                "WebSocket",
                "E2E",
                "101",
                "WS",
            ] {
                assert!(
                    !m.contains(forbidden),
                    "message for {cause:?} leaked '{forbidden}': {m}"
                );
            }
            // "port" is checked word-bounded so "import" doesn't trip it.
            for word in m.split_whitespace() {
                assert_ne!(
                    word.trim_matches(|c: char| !c.is_alphanumeric()),
                    "port",
                    "message for {cause:?} leaked 'port': {m}"
                );
            }
        }
    }

    #[test]
    fn fa_messages_render() {
        assert!(!plain_message(PlainCause::WorkerDead, Locale::Fa).is_empty());
        assert!(!recommended_action(PlainCause::WorkerDead)
            .label(Locale::Fa)
            .is_empty());
    }

    #[test]
    fn recommended_action_is_single() {
        assert_eq!(
            recommended_action(PlainCause::WorkerDead),
            RecommendedAction::OpenCloudflareDashboard
        );
        assert_eq!(
            recommended_action(PlainCause::NetworkBlocked),
            RecommendedAction::CheckNetwork
        );
        assert_eq!(
            recommended_action(PlainCause::InsufficientCandidates),
            RecommendedAction::RetryWithMoreSamples
        );
    }
}
