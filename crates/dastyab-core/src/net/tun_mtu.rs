//! MTU/MSS clamping for tunnel paths (doctrine D).
//!
//! DNS tunnels and other low-MTU carriers fragment or drop oversized TCP
//! segments. The standard fix is to clamp the TCP Maximum Segment Size (MSS)
//! at the firewall so each side advertises a segment size that fits inside the
//! tunnel's effective MTU. This is done with `iptables`/`nft` mangle rules on
//! the `FORWARD`/`OUTPUT` chains.
//!
//! This module generates the deterministic command plan (install + uninstall)
//! for MSS clamping, mirroring the approach of [`crate::net::tun_route`] so it is
//! pure, idempotent and fully unit-testable. Execution is left to the caller
//! (Linux `iptables`/`nft`), matching the conventions of the rest of the code.

use std::collections::HashSet;

/// The default clamp target. `clamp-mss-to-pmtu` is the modern, adaptive form
/// (it clamps to the path MTU rather than a fixed number), so we prefer it.
/// A fixed clamp value is available via [`plan_mss_clamp_fixed`].
pub const PMTU_CLAMP: &str = "--clamp-mss-to-pmtu";

/// The TCP MSS overhead (IPv4 20 + TCP 20 = 40). Subtracting this from the
/// tunnel MTU gives the maximum safe MSS.
const IP_TCP_OVERHEAD: u32 = 40;

/// The iptables chain we attach the clamp rule to.
const CHAIN: &str = "FORWARD";

/// The table used by the rule.
const TABLE: &str = "mangle";

/// Parse `iptables -t mangle -L FORWARD -n -v --line-numbers` output into the
/// set of MSS-clamp targets already present. We only key on the clamp target
/// string so an existing adaptive clamp suppresses a duplicate.
pub fn parse_existing_mss_clamps(iptables_nv: &str) -> HashSet<String> {
    let mut clamps = HashSet::new();
    for line in iptables_nv.lines() {
        let line = line.trim();
        // A clamp rule mentions "clamp-mss" in its comment or target.
        // e.g. "0 0 TCPMSS tcp -- 0.0.0.0/0 0.0.0.0/0 tcpflags:0x06/0x06
        //        TCPMSS clamp to PMTU"
        if line.contains("clamp-mss") || line.contains("PMTU") {
            clamps.insert(PMTU_CLAMP.to_string());
        } else if line.contains("TCPMSS") {
            if let Some(idx) = line.find("set mss") {
                let value = line[idx..].split_whitespace().nth(2).unwrap_or("");
                if !value.is_empty() {
                    clamps.insert(format!("--set-mss {value}"));
                }
            }
        }
    }
    clamps
}

/// The plan for installing/removing MSS clamping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MssClampPlan {
    /// The clamp argument, e.g. `--clamp-mss-to-pmtu`.
    pub clamp: String,
    /// The chain we attach to.
    pub chain: String,
    /// The table.
    pub table: String,
    /// Install commands (idempotent given `existing`).
    pub install: Vec<String>,
    /// Uninstall commands.
    pub uninstall: Vec<String>,
}

/// Plan adaptive PMTU clamping.
pub fn plan_pmtu_clamp(existing: &HashSet<String>) -> MssClampPlan {
    let clamp = PMTU_CLAMP.to_string();
    let mut install = Vec::new();
    let mut uninstall = Vec::new();

    if !existing.contains(&clamp) {
        install.push(format!(
            "iptables -t {TABLE} -A {CHAIN} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS {clamp}"
        ));
        uninstall.push(format!(
            "iptables -t {TABLE} -D {CHAIN} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS {clamp}"
        ));
    }

    MssClampPlan {
        clamp,
        chain: CHAIN.to_string(),
        table: TABLE.to_string(),
        install,
        uninstall,
    }
}

/// Plan fixed MSS clamping given a tunnel MTU. The MSS is the MTU minus the
/// IPv4+TCP overhead.
pub fn plan_mss_clamp_fixed(mtu: u32, existing: &HashSet<String>) -> MssClampPlan {
    let mss = mtu.saturating_sub(IP_TCP_OVERHEAD);
    let clamp = format!("--set-mss {mss}");
    let mut install = Vec::new();
    let mut uninstall = Vec::new();

    if !existing.contains(&clamp) {
        install.push(format!(
            "iptables -t {TABLE} -A {CHAIN} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS {clamp}"
        ));
        uninstall.push(format!(
            "iptables -t {TABLE} -D {CHAIN} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS {clamp}"
        ));
    }

    MssClampPlan {
        clamp,
        chain: CHAIN.to_string(),
        table: TABLE.to_string(),
        install,
        uninstall,
    }
}

/// The default tunnel MTU used by the DNS tunnel path (DNS over UDP rarely
/// carries payloads over ~1290 bytes).
pub const DEFAULT_TUNNEL_MTU: u32 = 1290;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pmtu_plan_adds_rule_when_absent() {
        let existing: HashSet<String> = HashSet::new();
        let p = plan_pmtu_clamp(&existing);
        assert_eq!(p.clamp, "--clamp-mss-to-pmtu");
        assert_eq!(p.install.len(), 1);
        assert!(p.install[0].contains("mangle"));
        assert!(p.install[0].contains("FORWARD"));
        assert!(p.install[0].contains("TCPMSS --clamp-mss-to-pmtu"));
        assert_eq!(p.uninstall.len(), 1);
        assert!(p.uninstall[0].contains("iptables -t mangle -D"));
    }

    #[test]
    fn pmtu_plan_is_idempotent_when_already_present() {
        let mut existing = HashSet::new();
        existing.insert("--clamp-mss-to-pmtu".to_string());
        let p = plan_pmtu_clamp(&existing);
        assert!(p.install.is_empty());
        assert!(p.uninstall.is_empty());
    }

    #[test]
    fn fixed_mss_computes_overhead() {
        let existing: HashSet<String> = HashSet::new();
        // MTU 1290 -> MSS 1250.
        let p = plan_mss_clamp_fixed(1290, &existing);
        assert!(p.install[0].contains("--set-mss 1250"));
    }

    #[test]
    fn fixed_mss_saturates_at_zero() {
        let existing: HashSet<String> = HashSet::new();
        let p = plan_mss_clamp_fixed(0, &existing);
        assert!(p.install[0].contains("--set-mss 0"));
    }

    #[test]
    fn parse_detects_pmtu_clamp() {
        let out = "\
Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
num pkts bytes target prot opt in out source destination
1 0 0 TCPMSS tcp -- * * 0.0.0.0/0 0.0.0.0/0 tcpflags:0x06/0x06 TCPMSS clamp to PMTU
";
        let clamps = parse_existing_mss_clamps(out);
        assert!(clamps.contains("--clamp-mss-to-pmtu"));
    }

    #[test]
    fn parse_detects_fixed_mss() {
        let out =
            "1 0 0 TCPMSS tcp -- * * 0.0.0.0/0 0.0.0.0/0 tcpflags:0x06/0x06 TCPMSS set mss 1250\n";
        let clamps = parse_existing_mss_clamps(out);
        assert!(clamps.contains("--set-mss 1250"));
    }

    #[test]
    fn parse_handles_empty() {
        let clamps = parse_existing_mss_clamps("");
        assert!(clamps.is_empty());
    }
}
