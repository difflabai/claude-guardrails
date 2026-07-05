//! `doctor`: operational health checks for a deployed guardrail.
//!
//! Answers the questions you actually care about after a deploy: is the hook
//! still registered, is anything disabling the guard, is the log rotating. This
//! is what turns self-protection from "blocks tampering" into "blocks tampering
//! AND tells you if the hook ever went missing."

use std::path::PathBuf;

use crate::allowonce::AllowOnceStore;
use crate::config::Config;

/// Health status of a single check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    Ok,
    Warn,
    Fail,
}

impl Health {
    fn label(&self) -> &'static str {
        match self {
            Health::Ok => "OK  ",
            Health::Warn => "WARN",
            Health::Fail => "FAIL",
        }
    }
}

/// One diagnostic result.
#[derive(Debug)]
pub struct Check {
    pub name: String,
    pub status: Health,
    pub detail: String,
}

fn check(name: &str, status: Health, detail: impl Into<String>) -> Check {
    Check {
        name: name.to_string(),
        status,
        detail: detail.into(),
    }
}

fn settings_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".claude/settings.json"))
}

/// Run all health checks.
pub fn run(config: &Config) -> Vec<Check> {
    let mut checks = Vec::new();

    // 1. Hook still registered in settings.json.
    checks.push(match settings_path() {
        Some(p) => match std::fs::read_to_string(&p) {
            Ok(body) if body.contains("guardrails") && body.contains("PreToolUse") => check(
                "hook registered",
                Health::Ok,
                "guardrails PreToolUse hook present",
            ),
            Ok(_) => check(
                "hook registered",
                Health::Fail,
                format!(
                    "no guardrails hook found in {} — the guard is not active",
                    p.display()
                ),
            ),
            Err(_) => check(
                "hook registered",
                Health::Warn,
                format!("could not read {}", p.display()),
            ),
        },
        None => check("hook registered", Health::Warn, "no home directory"),
    });

    // 2. Installed binary present.
    let bin = dirs::home_dir().map(|h| h.join(".claude/guardrails/claude-guardrails"));
    checks.push(match bin {
        Some(p) if p.exists() => check("binary installed", Health::Ok, p.display().to_string()),
        Some(p) => check(
            "binary installed",
            Health::Warn,
            format!("{} not found (running from elsewhere?)", p.display()),
        ),
        None => check("binary installed", Health::Warn, "no home directory"),
    });

    // 3. Disable / warn-only flags.
    let disabled = std::env::var("GUARDRAILS_DISABLED").is_ok();
    let warn_only = std::env::var("GUARDRAILS_WARN_ONLY").is_ok();
    checks.push(if disabled {
        check(
            "guard active",
            Health::Warn,
            "GUARDRAILS_DISABLED is set — all checks bypassed",
        )
    } else if warn_only {
        check(
            "guard active",
            Health::Warn,
            "GUARDRAILS_WARN_ONLY is set — denies become warnings",
        )
    } else {
        check("guard active", Health::Ok, "enforcing")
    });

    // 4. Audit log health / rotation.
    checks.push(match config.audit_path() {
        Some(p) => match std::fs::metadata(&p) {
            Ok(m) => {
                let mb = m.len() as f64 / (1024.0 * 1024.0);
                let cap = config.general.audit_max_bytes;
                if cap > 0 && m.len() > cap {
                    check(
                        "audit log",
                        Health::Warn,
                        format!(
                            "{:.1} MB exceeds cap — rotation should fire on next write",
                            mb
                        ),
                    )
                } else {
                    check("audit log", Health::Ok, format!("{:.1} MB", mb))
                }
            }
            Err(_) => check(
                "audit log",
                Health::Warn,
                format!("{} not present yet", p.display()),
            ),
        },
        None => check("audit log", Health::Warn, "audit logging disabled"),
    });

    // 5. Active allow-once grants.
    let store = AllowOnceStore::new(AllowOnceStore::default_path());
    let active = store.prune().unwrap_or(0);
    checks.push(check(
        "allow-once grants",
        Health::Ok,
        format!("{} active", active),
    ));

    // 6. Safety level (informational).
    checks.push(check(
        "safety level",
        Health::Ok,
        format!("{:?}", config.general.safety_level),
    ));

    checks
}

/// Render checks to stdout. Returns the process exit code (1 if any check failed).
pub fn print_and_code(checks: &[Check]) -> i32 {
    let mut worst_failed = false;
    for c in checks {
        println!("[{}] {:<18} {}", c.status.label(), c.name, c.detail);
        if c.status == Health::Fail {
            worst_failed = true;
        }
    }
    if worst_failed {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_produces_all_checks() {
        let checks = run(&Config::default());
        let names: Vec<&str> = checks.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"hook registered"));
        assert!(names.contains(&"guard active"));
        assert!(names.contains(&"audit log"));
        assert!(names.contains(&"safety level"));
    }

    #[test]
    fn test_exit_code_ok_when_no_fail() {
        let checks = vec![
            check("x", Health::Ok, "fine"),
            check("y", Health::Warn, "meh"),
        ];
        assert_eq!(print_and_code(&checks), 0);
    }

    #[test]
    fn test_exit_code_fail() {
        let checks = vec![check("x", Health::Fail, "broken")];
        assert_eq!(print_and_code(&checks), 1);
    }
}
