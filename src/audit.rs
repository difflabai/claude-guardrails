//! JSONL audit logging for claude-guardrails
//!
//! Records all security decisions to a JSONL file for later analysis.

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;

use crate::input::HookInput;
use crate::output::Decision;

/// Log level for audit entries
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogLevel {
    Allowed,
    Blocked,
    Warn,
    Disabled,
    Error,
}

/// An audit log entry
#[derive(Debug, Serialize)]
pub struct AuditEntry {
    /// Timestamp of the decision
    pub timestamp: DateTime<Utc>,

    /// Log level (ALLOWED, BLOCKED, WARN, DISABLED)
    pub level: LogLevel,

    /// Tool that was invoked
    pub tool: String,

    /// Rule ID that matched (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,

    /// Summary of the input (truncated, human-readable)
    pub input_summary: String,

    /// Full untruncated Bash command, when applicable — for faithful replay.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,

    /// Reason for the decision
    pub reason: String,

    /// Session ID (if provided)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

impl AuditEntry {
    /// Create a new audit entry from input and decision
    pub fn new(input: &HookInput, decision: &Decision, disabled: bool) -> Self {
        let (level, rule_id, reason) = if disabled {
            (LogLevel::Disabled, None, "GUARDRAILS_DISABLED".to_string())
        } else {
            match decision {
                Decision::Allow { reason } => (LogLevel::Allowed, None, reason.clone()),
                Decision::Deny { rule_id, reason } => {
                    (LogLevel::Blocked, Some(rule_id.clone()), reason.clone())
                }
                Decision::Warn { rule_id, reason } => {
                    (LogLevel::Warn, Some(rule_id.clone()), reason.clone())
                }
            }
        };

        Self {
            timestamp: Utc::now(),
            level,
            tool: input.tool_name.clone(),
            rule_id,
            input_summary: input.summary(),
            command: input.full_command().map(str::to_string),
            reason,
            session_id: input.session_id.clone(),
        }
    }
}

/// Audit logger
pub struct AuditLogger {
    writer: Option<BufWriter<File>>,
}

impl AuditLogger {
    /// Create a new audit logger with default rotation (25 MB, keep 5).
    pub fn new(path: Option<&Path>) -> Self {
        Self::with_rotation(path, 25 * 1024 * 1024, 5)
    }

    /// Create a logger that rotates the log when it exceeds `max_bytes`, keeping
    /// `keep` rotated generations (`audit.jsonl.1` … `audit.jsonl.{keep}`).
    pub fn with_rotation(path: Option<&Path>, max_bytes: u64, keep: usize) -> Self {
        let writer = path.and_then(|p| {
            if let Some(parent) = p.parent() {
                let _ = std::fs::create_dir_all(parent);
            }

            // Rotate before opening if the current log is over the cap.
            if max_bytes > 0 {
                if let Ok(meta) = std::fs::metadata(p) {
                    if meta.len() > max_bytes {
                        rotate(p, keep);
                    }
                }
            }

            OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .ok()
                .map(BufWriter::new)
        });

        Self { writer }
    }

    /// Log an audit entry
    pub fn log(&mut self, entry: &AuditEntry) -> Result<(), std::io::Error> {
        if let Some(ref mut writer) = self.writer {
            let json = serde_json::to_string(entry)?;
            writeln!(writer, "{}", json)?;
            writer.flush()?;
        }
        Ok(())
    }

    /// Log a decision
    pub fn log_decision(
        &mut self,
        input: &HookInput,
        decision: &Decision,
        disabled: bool,
    ) -> Result<(), std::io::Error> {
        let entry = AuditEntry::new(input, decision, disabled);
        self.log(&entry)
    }

    /// Check if logging is enabled
    pub fn is_enabled(&self) -> bool {
        self.writer.is_some()
    }
}

/// Rotate `path` → `path.1` → … → `path.{keep}`, dropping the oldest.
fn rotate(path: &Path, keep: usize) {
    if keep == 0 {
        // No generations kept: just truncate by removing the current log.
        let _ = std::fs::remove_file(path);
        return;
    }
    let gen = |i: usize| path.with_extension(format!("jsonl.{}", i));
    // Drop the oldest generation.
    let _ = std::fs::remove_file(gen(keep));
    // Shift .{i} → .{i+1} from oldest-but-one down to 1.
    for i in (1..keep).rev() {
        if gen(i).exists() {
            let _ = std::fs::rename(gen(i), gen(i + 1));
        }
    }
    // Current log → .1
    let _ = std::fs::rename(path, gen(1));
}

/// Create a disabled logger (for when audit logging is off)
impl Default for AuditLogger {
    fn default() -> Self {
        Self { writer: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::ToolInput;
    use tempfile::NamedTempFile;

    fn test_input() -> HookInput {
        HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput::Bash {
                command: "rm -rf /".to_string(),
                description: None,
                timeout: None,
            },
            session_id: Some("test-session".to_string()),
            hook_event_name: Some("PreToolUse".to_string()),
        }
    }

    #[test]
    fn test_audit_entry_allow() {
        let input = test_input();
        let decision = Decision::allow("passed checks");
        let entry = AuditEntry::new(&input, &decision, false);

        assert!(matches!(entry.level, LogLevel::Allowed));
        assert!(entry.rule_id.is_none());
    }

    #[test]
    fn test_audit_entry_deny() {
        let input = test_input();
        let decision = Decision::deny("rm-root", "Attempting to delete root");
        let entry = AuditEntry::new(&input, &decision, false);

        assert!(matches!(entry.level, LogLevel::Blocked));
        assert_eq!(entry.rule_id, Some("rm-root".to_string()));
    }

    #[test]
    fn test_audit_entry_disabled() {
        let input = test_input();
        let decision = Decision::allow("disabled");
        let entry = AuditEntry::new(&input, &decision, true);

        assert!(matches!(entry.level, LogLevel::Disabled));
    }

    #[test]
    fn test_audit_logger_write() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let mut logger = AuditLogger::new(Some(path));
        assert!(logger.is_enabled());

        let input = test_input();
        let decision = Decision::deny("test-rule", "test reason");
        logger.log_decision(&input, &decision, false).unwrap();

        // Read back and verify
        let content = std::fs::read_to_string(path).unwrap();
        assert!(content.contains("test-rule"));
        assert!(content.contains("BLOCKED"));
    }

    #[test]
    fn test_audit_logger_disabled() {
        let mut logger = AuditLogger::default();
        assert!(!logger.is_enabled());

        let input = test_input();
        let decision = Decision::allow("test");
        // Should not error even when disabled
        logger.log_decision(&input, &decision, false).unwrap();
    }

    #[test]
    fn test_audit_entry_carries_full_command() {
        let input = test_input(); // Bash: rm -rf /
        let entry = AuditEntry::new(&input, &Decision::allow("x"), false);
        assert_eq!(entry.command.as_deref(), Some("rm -rf /"));
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"command\":\"rm -rf /\""));
    }

    #[test]
    fn test_rotation_shifts_generations() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        // Write an oversized log, then open with a tiny cap to force rotation.
        std::fs::write(&path, "x".repeat(2048)).unwrap();
        let mut logger = AuditLogger::with_rotation(Some(&path), 1024, 3);
        logger
            .log_decision(&test_input(), &Decision::allow("fresh"), false)
            .unwrap();

        // Old content moved to .1; current log is the fresh (small) one.
        let rotated = path.with_extension("jsonl.1");
        assert!(rotated.exists(), "generation .1 should exist");
        assert_eq!(std::fs::read_to_string(&rotated).unwrap().len(), 2048);
        assert!(std::fs::read_to_string(&path).unwrap().contains("fresh"));
    }

    #[test]
    fn test_rotation_drops_oldest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        // Seed the max generation, which must be dropped on rotate.
        std::fs::write(path.with_extension("jsonl.2"), "oldest").unwrap();
        std::fs::write(&path, "y".repeat(2048)).unwrap();

        let _ = AuditLogger::with_rotation(Some(&path), 1024, 2);
        // keep=2: .2 dropped, old current → .1
        assert_eq!(
            std::fs::read_to_string(path.with_extension("jsonl.1"))
                .unwrap()
                .len(),
            2048
        );
    }
}
