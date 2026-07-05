//! Replay: re-run the current ruleset over a historical audit log and diff verdicts.
//!
//! This is the regression oracle for rule changes. Given the live audit JSONL,
//! it reconstructs each decision's input, re-evaluates it against the *current*
//! engine, and reports what changed:
//!
//!   - `newly_allowed` (was BLOCKED, now allowed) — safety-sensitive: every entry
//!     must be a deliberate false-positive fix, never a real regression.
//!   - `newly_blocked` (was ALLOWED, now denied) — new false-positive risk.
//!
//! Fidelity caveat: v1 stored a *truncated* (100-char) command in `input_summary`,
//! so Bash entries whose command was cut off cannot be faithfully re-evaluated and
//! are counted under `skipped_truncated` rather than guessed at.

use serde::Deserialize;
use std::path::Path;

use crate::engine::SecurityEngine;

/// One verdict change surfaced by replay.
#[derive(Debug, Clone)]
pub struct Change {
    pub tool: String,
    pub subject: String,
    pub old_rule: Option<String>,
    pub new_rule: Option<String>,
}

/// Aggregate result of a replay run.
#[derive(Debug, Default)]
pub struct ReplayReport {
    pub total: usize,
    pub evaluated: usize,
    pub skipped_truncated: usize,
    pub skipped_other: usize,
    pub unchanged_allow: usize,
    pub unchanged_deny: usize,
    /// was ALLOWED, now denied — new false-positive risk
    pub newly_blocked: Vec<Change>,
    /// was BLOCKED, now allowed — must all be intentional FP fixes
    pub newly_allowed: Vec<Change>,
}

/// A single audit-log line (subset of fields we need).
#[derive(Deserialize)]
struct AuditLine {
    level: String,
    tool: String,
    input_summary: String,
    /// Full untruncated Bash command (audit-log v2). Preferred over the summary.
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    rule_id: Option<String>,
}

/// Strip the `"<Tool>: "` prefix that `HookInput::summary()` prepends.
fn strip_prefix(summary: &str) -> &str {
    summary
        .split_once(": ")
        .map(|(_, rest)| rest)
        .unwrap_or(summary)
}

/// Re-evaluate one audit line against the current engine. Returns whether the new
/// verdict is a deny, or `None` if the entry can't be faithfully replayed.
fn new_is_deny(engine: &SecurityEngine, line: &AuditLine, subject: &str) -> Option<bool> {
    let decision = match line.tool.as_str() {
        "Bash" => engine.check_bash(subject),
        "Read" | "Edit" | "Write" => engine.check_file(&line.tool, subject),
        _ => return None,
    };
    Some(decision.is_deny())
}

/// Replay a JSONL audit log at `path` against the current engine.
pub fn run(path: &Path, engine: &SecurityEngine) -> std::io::Result<ReplayReport> {
    let content = std::fs::read_to_string(path)?;
    let mut report = ReplayReport::default();

    for raw in content.lines() {
        if raw.trim().is_empty() {
            continue;
        }
        report.total += 1;

        let line: AuditLine = match serde_json::from_str(raw) {
            Ok(l) => l,
            Err(_) => {
                report.skipped_other += 1;
                continue;
            }
        };

        // Old verdict from the recorded level.
        let old_deny = match line.level.as_str() {
            "BLOCKED" | "WARN" => true,
            "ALLOWED" => false,
            // DISABLED / ERROR / anything else: not a rule decision to compare.
            _ => {
                report.skipped_other += 1;
                continue;
            }
        };

        // Prefer the full command (audit-log v2); fall back to the summary.
        let (subject, from_full) = match &line.command {
            Some(cmd) => (cmd.clone(), true),
            None => (strip_prefix(&line.input_summary).to_string(), false),
        };

        // A truncated Bash summary (no full command) can't be faithfully replayed.
        if !from_full && line.tool == "Bash" && subject.ends_with("...") {
            report.skipped_truncated += 1;
            continue;
        }

        let new_deny = match new_is_deny(engine, &line, &subject) {
            Some(d) => d,
            None => {
                report.skipped_other += 1;
                continue;
            }
        };

        report.evaluated += 1;
        match (old_deny, new_deny) {
            (false, false) => report.unchanged_allow += 1,
            (true, true) => report.unchanged_deny += 1,
            (false, true) => report.newly_blocked.push(Change {
                tool: line.tool.clone(),
                subject,
                old_rule: None,
                new_rule: None,
            }),
            (true, false) => report.newly_allowed.push(Change {
                tool: line.tool.clone(),
                subject,
                old_rule: line.rule_id.clone(),
                new_rule: None,
            }),
        }
    }

    Ok(report)
}

/// Render a human-readable report to stdout.
pub fn print_report(report: &ReplayReport, limit: usize) {
    println!("Replay over {} audit entries", report.total);
    println!(
        "  evaluated {} · skipped {} truncated · {} other",
        report.evaluated, report.skipped_truncated, report.skipped_other
    );
    println!(
        "  unchanged: {} allow · {} deny",
        report.unchanged_allow, report.unchanged_deny
    );
    println!(
        "  CHANGED: {} newly-allowed (was blocked) · {} newly-blocked (was allowed)",
        report.newly_allowed.len(),
        report.newly_blocked.len()
    );

    if !report.newly_allowed.is_empty() {
        println!(
            "\n  ⚠ NEWLY ALLOWED (verify each is an intentional false-positive fix, not a regression):"
        );
        for c in report.newly_allowed.iter().take(limit) {
            let was = c.old_rule.as_deref().unwrap_or("?");
            println!("    - [{}] (was {}) {}", c.tool, was, c.subject);
        }
        if report.newly_allowed.len() > limit {
            println!("    … {} more", report.newly_allowed.len() - limit);
        }
    }

    if !report.newly_blocked.is_empty() {
        println!("\n  NEWLY BLOCKED (new potential false positives):");
        for c in report.newly_blocked.iter().take(limit) {
            println!("    - [{}] {}", c.tool, c.subject);
        }
        if report.newly_blocked.len() > limit {
            println!("    … {} more", report.newly_blocked.len() - limit);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn engine() -> SecurityEngine {
        SecurityEngine::new(Config::default())
    }

    fn write_log(lines: &[&str]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        for l in lines {
            writeln!(f, "{}", l).unwrap();
        }
        f
    }

    #[test]
    fn test_strip_prefix() {
        assert_eq!(strip_prefix("Bash: rm -rf /"), "rm -rf /");
        assert_eq!(strip_prefix("Read: /etc/passwd"), "/etc/passwd");
        assert_eq!(strip_prefix("no-prefix"), "no-prefix");
    }

    #[test]
    fn test_unchanged_deny() {
        // rm -rf / was blocked and is still blocked → unchanged_deny.
        let log = write_log(&[
            r#"{"level":"BLOCKED","tool":"Bash","input_summary":"Bash: rm -rf /","rule_id":"rm-root"}"#,
        ]);
        let r = run(log.path(), &engine()).unwrap();
        assert_eq!(r.unchanged_deny, 1);
        assert!(r.newly_allowed.is_empty());
    }

    #[test]
    fn test_newly_allowed_p1_fix() {
        // The P1 false positives: v1 BLOCKED these, v2 allows them → newly_allowed.
        let log = write_log(&[
            r#"{"level":"BLOCKED","tool":"Bash","input_summary":"Bash: eval \"$(fleetops session-stamp cic)\"","rule_id":"eval-variable"}"#,
            r#"{"level":"BLOCKED","tool":"Bash","input_summary":"Bash: git status","rule_id":"x"}"#,
        ]);
        let r = run(log.path(), &engine()).unwrap();
        assert_eq!(r.newly_allowed.len(), 2);
        assert_eq!(
            r.newly_allowed[0].old_rule.as_deref(),
            Some("eval-variable")
        );
    }

    #[test]
    fn test_skips_truncated() {
        let long = "Bash: ".to_string() + &"a".repeat(100) + "...";
        let line = format!(
            r#"{{"level":"ALLOWED","tool":"Bash","input_summary":{}}}"#,
            serde_json::to_string(&long).unwrap()
        );
        let r = run(write_log(&[&line]).path(), &engine()).unwrap();
        assert_eq!(r.skipped_truncated, 1);
        assert_eq!(r.evaluated, 0);
    }

    #[test]
    fn test_full_command_preferred_over_truncated_summary() {
        // A long command that was truncated in the summary but has a full
        // `command` field must be re-evaluated, not skipped.
        let cmd = "eval \"$(fleetops session-stamp cic)\" && echo ".to_string() + &"x".repeat(120);
        let line = format!(
            r#"{{"level":"BLOCKED","tool":"Bash","input_summary":"Bash: {}...","command":{},"rule_id":"eval-variable"}}"#,
            "x".repeat(100),
            serde_json::to_string(&cmd).unwrap()
        );
        let r = run(write_log(&[&line]).path(), &engine()).unwrap();
        assert_eq!(r.skipped_truncated, 0, "full command should not be skipped");
        assert_eq!(r.newly_allowed.len(), 1, "trusted eval now allowed");
    }

    #[test]
    fn test_skips_disabled_and_unparseable() {
        let log = write_log(&[
            r#"{"level":"DISABLED","tool":"Bash","input_summary":"Bash: whatever"}"#,
            r#"not json"#,
        ]);
        let r = run(log.path(), &engine()).unwrap();
        assert_eq!(r.skipped_other, 2);
        assert_eq!(r.total, 2);
    }
}
