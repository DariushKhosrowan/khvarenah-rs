//! TUN anti-loop routing (doctrine A).
//!
//! When a TUN interface is the default route, every outbound packet is routed
//! into the tunnel. But the tunnel process itself must *also* emit packets to
//! the real Internet — those must NOT re-enter the TUN, or the traffic loops
//! forever. The standard Linux answer is firewalling-by-mark:
//!
//! 1. The tunnel application marks its own sockets with `SO_MARK` = `mark`.
//! 2. An `ip rule` at a priority *higher* (lower number) than the TUN default
//!    route sends any packet carrying that mark straight to the `main` table
//!    (which routes via the physical interface).
//! 3. Everything else keeps falling through to the TUN's default route.
//!
//! This module generates the *plan* of commands to install (and uninstall)
//! that routing. It is pure and deterministic so it can be unit-tested
//! exhaustively; execution uses the standard `ip` tool.
//!
//! The plan is also written to be idempotent: it detects pre-existing rules
//! (e.g. from xray/v2rayN) that already cover the mark and avoids adding a
//! duplicate.

use std::collections::HashSet;

/// The firewall mark used to tag tunnel-originated sockets. Matches the
/// conventional value used by proxy stacks on this host.
pub const TUN_FWMARK: u32 = 0x2024;

/// The routing table `ip` uses for the main table.
pub const TABLE_MAIN: &str = "main";

/// Default priority for the anti-loop rule. Must be numerically smaller
/// (higher priority) than the TUN's default-route rule so marked packets win.
pub const ANTI_LOOP_PRIO: u32 = 9000;

/// Parse `ip rule show` output into a set of `(priority, fwmark)` pairs.
/// Rules that don't reference a fwmark are ignored (they select on all).
pub fn parse_existing_fwmark_rules(ip_rule_show: &str) -> HashSet<u32> {
    let mut marks = HashSet::new();
    for line in ip_rule_show.lines() {
        // format: "<prio>:\tfrom all fwmark 0x2024 lookup 2022"
        let prio = line.split(':').next().and_then(|p| p.trim().parse::<u32>().ok());
        let Some(prio) = prio else { continue };
        // Only consider rules at or above our target priority (the anti-loop
        // slice of the table). Lower-numbered = higher precedence.
        if prio > ANTI_LOOP_PRIO + 100 {
            continue;
        }
        // find "fwmark 0xXXXX"
        let toks: Vec<&str> = line.split_whitespace().collect();
        for i in 0..toks.len().saturating_sub(1) {
            if toks[i] == "fwmark" {
                if let Some(hex) = toks.get(i + 1) {
                    if let Some(v) = u32::from_str_radix(hex.trim_start_matches("0x"), 16).ok() {
                        marks.insert(v);
                    }
                }
            }
        }
    }
    marks
}

/// The generated command plan for installing/removing anti-loop routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingPlan {
    /// The fwmark we assign to tunnel-originated sockets.
    pub mark: u32,
    /// The priority of the anti-loop rule.
    pub prio: u32,
    /// Commands that add the anti-loop routing (idempotent given `existing`).
    pub install: Vec<String>,
    /// Commands that remove the anti-loop routing we added.
    pub uninstall: Vec<String>,
}

/// Build the install/uninstall plan.
///
/// `existing` is the set of fwmark values already covered by a rule at a
/// priority <= `ANTI_LOOP_PRIO + 100`. If `mark` is already covered we don't
/// re-add it (idempotence).
pub fn plan_anti_loop(mark: u32, existing: &HashSet<u32>) -> RoutingPlan {
    let prio = ANTI_LOOP_PRIO;
    let mut install = Vec::new();
    let mut uninstall = Vec::new();

    if !existing.contains(&mark) {
        install.push(format!(
            "ip rule add prio {prio} fwmark {mark:#x} lookup {TABLE_MAIN}"
        ));
        uninstall.push(format!("ip rule del prio {prio} fwmark {mark:#x}"));
    }

    RoutingPlan {
        mark,
        prio,
        install,
        uninstall,
    }
}

/// Convenience wrapper planning with the default mark.
pub fn plan_default_anti_loop(existing: &HashSet<u32>) -> RoutingPlan {
    plan_anti_loop(TUN_FWMARK, existing)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_finds_fwmark_rules() {
        let out = "\
0:\tfrom all lookup local
1:\tfrom all lookup 2926784985
9000:\tfrom all fwmark 0x2024 goto 9002
9001:\tfrom all fwmark 0x2023 lookup 2022
9002:\tfrom all nop
";
        let marks = parse_existing_fwmark_rules(out);
        assert!(marks.contains(&0x2024));
        assert!(marks.contains(&0x2023));
        assert_eq!(marks.len(), 2);
    }

    #[test]
    fn parse_ignores_unmarked_and_far_priorities() {
        let out = "\
0:\tfrom all lookup local
1:\tfrom all lookup 2926784985
9500:\tfrom all fwmark 0x1111 lookup 100
";
        let marks = parse_existing_fwmark_rules(out);
        assert!(marks.is_empty(), "unmarked/far rules must be ignored");
    }

    #[test]
    fn plan_adds_rule_when_mark_not_present() {
        let existing: HashSet<u32> = HashSet::new();
        let p = plan_default_anti_loop(&existing);
        assert_eq!(p.mark, TUN_FWMARK);
        assert_eq!(p.install.len(), 1);
        assert!(p.install[0].contains("prio 9000"));
        assert!(p.install[0].contains("fwmark 0x2024"));
        assert!(p.install[0].contains("lookup main"));
        assert_eq!(p.uninstall.len(), 1);
        assert!(p.uninstall[0].contains("ip rule del"));
    }

    #[test]
    fn plan_is_idempotent_when_mark_already_covered() {
        let mut existing = HashSet::new();
        existing.insert(TUN_FWMARK);
        let p = plan_default_anti_loop(&existing);
        assert!(p.install.is_empty(), "must not duplicate an existing rule");
        assert!(p.uninstall.is_empty());
    }

    #[test]
    fn plan_respects_custom_mark() {
        let existing: HashSet<u32> = HashSet::new();
        let p = plan_anti_loop(0xabcd, &existing);
        assert_eq!(p.mark, 0xabcd);
        assert!(p.install[0].contains("fwmark 0xabcd"));
    }

    #[test]
    fn install_and_uninstall_are_inverse() {
        let existing: HashSet<u32> = HashSet::new();
        let p = plan_default_anti_loop(&existing);
        // The delete command should reference the same prio + mark.
        assert!(p.uninstall[0].contains(&p.prio.to_string()));
        assert!(p.uninstall[0].contains(&format!("{:#x}", p.mark)));
    }
}
