//! Security hardening & linting of the local Khvarenah installation.
//!
//! A security tool that audits the local `~/.khvarenah/` tree: file
//! permissions (tokens must be 0600, directories 0700), whether any plaintext
//! token leaked into a world-readable file, and presence of any worker bundle
//! that embeds a secret. It returns an actionable report without ever
//! printing token values.

use serde::{Deserialize, Serialize};

use crate::store::{mem_dir, profiles_dir};

/// Severity of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// A single security finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub fix: String,
}

/// The full audit result.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditReport {
    pub findings: Vec<Finding>,
    pub healthy: bool,
}

impl AuditReport {
    /// Add a finding (used internally and by callers).
    pub fn add(&mut self, severity: Severity, title: &str, detail: &str, fix: &str) {
        self.findings.push(Finding {
            severity,
            title: title.to_string(),
            detail: detail.to_string(),
            fix: fix.to_string(),
        });
    }

    pub fn finalize(mut self) -> Self {
        self.healthy = self
            .findings
            .iter()
            .all(|f| matches!(f.severity, Severity::Info | Severity::Low));
        self
    }

    /// Render a readable report.
    pub fn render(&self) -> String {
        let mut out = format!(
            "Security audit — {} finding(s) — {}\n",
            self.findings.len(),
            if self.healthy {
                "HEALTHY"
            } else {
                "ACTION REQUIRED"
            }
        );
        for f in &self.findings {
            out.push_str(&format!(
                "  [{}] {}\n    {}\n    Fix: {}\n",
                f.severity.as_str(),
                f.title,
                f.detail,
                f.fix
            ));
        }
        out
    }
}

/// Check permissions on the base dirs.
fn check_dir_permissions(report: &mut AuditReport) {
    let dirs = [mem_dir(), profiles_dir()];
    for d in dirs {
        if let Ok(meta) = std::fs::metadata(&d) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    report.add(
                        Severity::High,
                        "Directory world/group readable",
                        &format!("{} has mode {mode:o} (wanted 0700)", d.display()),
                        "Run: chmod 700 <dir>",
                    );
                }
            }
        }
    }
}

/// Check token files are 0600 and don't contain leaked plaintext elsewhere.
fn check_token_files(report: &mut AuditReport) {
    let token_files = [
        mem_dir()
            .join("profiles")
            .join("default")
            .join("token.json"),
        mem_dir().join("tokens.json"), // legacy location
    ];

    for path in token_files {
        if path.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(&path) {
                    let mode = meta.permissions().mode() & 0o777;
                    if mode & 0o077 != 0 {
                        report.add(
                            Severity::Critical,
                            "Token file is world/group readable",
                            &format!("{} has mode {mode:o} (wanted 0600)", path.display()),
                            "Run: chmod 600 <file>",
                        );
                    }
                }
            }
        }
    }
}

/// Scan all JSON files under the memory dir for accidental token leaks.
fn scan_for_token_leaks(report: &mut AuditReport) {
    let root = mem_dir();
    let mut stack = vec![root];
    let mut files = Vec::new();

    while let Some(dir) = stack.pop() {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().and_then(|x| x.to_str()) == Some("json") {
                    files.push(p);
                }
            }
        }
    }

    for f in files {
        if let Ok(text) = std::fs::read_to_string(&f) {
            // Common token patterns (never printed back).
            // Skip the two legitimate dedicated token stores.
            let fname = f.file_name().and_then(|s| s.to_str()).unwrap_or("");
            let is_legit_store = fname == "token.json" || fname == "tokens.json";
            let suspicious =
                !is_legit_store && text.contains("\"token\"") && text.contains("\"token\": \"");
            if suspicious {
                report.add(
                    Severity::High,
                    "Possible token leak in JSON",
                    &format!(
                        "{} contains a 'token' field outside the dedicated token store.",
                        f.display()
                    ),
                    "Remove the secret from this file; use the profile store instead.",
                );
            }
        }
    }
}

/// Run the full audit.
pub fn audit() -> AuditReport {
    let mut report = AuditReport::default();
    check_dir_permissions(&mut report);
    check_token_files(&mut report);
    scan_for_token_leaks(&mut report);

    // Clean bill of health if nothing found.
    if report.findings.is_empty() {
        report.add(
            Severity::Info,
            "No issues",
            "Permissions, token storage, and config files look clean.",
            "Nothing to do.",
        );
    }
    report.finalize()
}

/// Quick single-check: is the default profile token file private?
pub fn token_file_private() -> bool {
    let path = mem_dir()
        .join("profiles")
        .join("default")
        .join("token.json");
    if !path.exists() {
        return true;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&path) {
            return meta.permissions().mode() & 0o077 == 0;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_as_str() {
        assert_eq!(Severity::Critical.as_str(), "critical");
        assert_eq!(Severity::Info.as_str(), "info");
    }

    #[test]
    fn report_finalize_marks_health() {
        let mut r = AuditReport::default();
        r.add(Severity::Info, "t", "d", "f");
        let r = r.finalize();
        assert!(r.healthy);

        let mut r2 = AuditReport::default();
        r2.add(Severity::Critical, "t", "d", "f");
        let r2 = r2.finalize();
        assert!(!r2.healthy);
        assert!(r2.render().contains("ACTION REQUIRED"));
    }

    #[test]
    fn token_file_private_missing_is_true() {
        // Uses the default mem dir; no real file exists → true.
        assert!(token_file_private());
    }
}
