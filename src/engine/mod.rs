//! Security engine for claude-guardrails
//!
//! Coordinates security checks across all tool types.

pub mod bash;
pub mod common;
pub mod file;
pub mod selfprotect;

use crate::allowonce::AllowOnceStore;
use crate::config::{Config, SafetyLevel};
use crate::input::{HookInput, ToolInput};
use crate::output::Decision;
use crate::rules::allowlist::CompiledAllowlist;

use regex::RegexSet;
use std::env;

/// Packs whose denials an allow-once grant MAY override. Allow-once is a UX escape
/// hatch for over-blocking *operational* commands, not a security bypass — and the
/// agent runs both the grant and the command, so anything security-critical must be
/// unreachable this way. Only non-catastrophic operational packs are overridable;
/// everything else (catastrophic filesystem, RCE, interpreter exec, secret reads,
/// exfiltration, self-protection, and any engine-level/unmapped rule) is NOT.
/// Deriving this from the pack (rather than a hand-maintained rule-id list) means it
/// can't drift as rules are added.
const OVERRIDABLE_PACKS: &[&str] = &[
    "core.git",
    "core.perms",
    "containers.docker",
    "system",
    "database",
];

/// Whether an allow-once grant may override a deny with this rule id.
pub fn is_overridable(rule_id: &str) -> bool {
    OVERRIDABLE_PACKS.contains(&crate::rules::packs::pack_of(rule_id))
}

/// True if an env var is set to a truthy value (not empty / "0" / "false" / "no").
fn env_truthy(key: &str) -> bool {
    match env::var(key) {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "" | "0" | "false" | "no"
        ),
        Err(_) => false,
    }
}

/// The string an allow-once code is keyed on for a given input: the command for
/// Bash, the file path for file tools. Must match what the CLI shows on denial.
pub fn allow_once_subject(input: &HookInput) -> Option<String> {
    match &input.tool_input {
        ToolInput::Bash { command, .. } => Some(command.clone()),
        ToolInput::Read { file_path }
        | ToolInput::Edit { file_path, .. }
        | ToolInput::Write { file_path, .. } => Some(format!("{}:{}", input.tool_name, file_path)),
        ToolInput::Unknown { .. } => None,
    }
}

/// The main security engine
pub struct SecurityEngine {
    config: Config,
    safety_level: SafetyLevel,
    bash_rules: RegexSet,
    file_rules: RegexSet,
    exfil_rules: RegexSet,
    allowlist: CompiledAllowlist,
}

impl SecurityEngine {
    /// Create a new security engine with the given configuration
    pub fn new(config: Config) -> Self {
        let safety_level = config.general.safety_level;
        let disabled = &config.packs.disabled;

        // Compile bash rules (pack-filtered; order preserved for index alignment)
        let bash_patterns: Vec<&str> =
            crate::rules::dangerous::active_rules_for_level(safety_level, disabled)
                .iter()
                .map(|r| r.pattern)
                .collect();
        let bash_rules = RegexSet::new(&bash_patterns).unwrap_or_else(|_| RegexSet::empty());

        // Compile file rules
        let file_patterns: Vec<&str> =
            crate::rules::secrets::active_patterns_for_level(safety_level, disabled)
                .iter()
                .map(|r| r.pattern)
                .collect();
        let file_rules = RegexSet::new(&file_patterns).unwrap_or_else(|_| RegexSet::empty());

        // Compile exfiltration rules
        let exfil_patterns: Vec<&str> =
            crate::rules::exfiltration::active_rules_for_level(safety_level, disabled)
                .iter()
                .map(|r| r.pattern)
                .collect();
        let exfil_rules = RegexSet::new(&exfil_patterns).unwrap_or_else(|_| RegexSet::empty());

        // Load allowlist if configured
        let allowlist = config
            .allowlist_path()
            .and_then(|path| {
                if path.exists() {
                    CompiledAllowlist::from_file(&path).ok()
                } else {
                    None
                }
            })
            .unwrap_or_else(CompiledAllowlist::empty);

        Self {
            config,
            safety_level,
            bash_rules,
            file_rules,
            exfil_rules,
            allowlist,
        }
    }

    /// Check if guardrails are disabled via environment (truthy value required).
    pub fn is_disabled(&self) -> bool {
        env_truthy("GUARDRAILS_DISABLED")
    }

    /// Check if warn-only mode is enabled (truthy value required).
    pub fn is_warn_only(&self) -> bool {
        env_truthy("GUARDRAILS_WARN_ONLY")
    }

    /// Main entry point: check an input and return a decision
    pub fn check(&self, input: &HookInput) -> Decision {
        // Check if disabled via environment
        if self.is_disabled() {
            return Decision::allow("disabled via GUARDRAILS_DISABLED");
        }

        // Route to appropriate checker based on tool type
        let decision = match &input.tool_input {
            ToolInput::Bash { command, .. } => self.check_bash(command),
            ToolInput::Read { file_path } => self.check_file(&input.tool_name, file_path),
            ToolInput::Edit {
                file_path,
                old_string,
                new_string,
            } => {
                if let Some(d) =
                    selfprotect::check_settings(file_path, Some((old_string, new_string)), None)
                {
                    d
                } else {
                    let decision = self.check_file(&input.tool_name, file_path);
                    if decision.is_deny() {
                        decision
                    } else {
                        // Scan the inserted text for live credentials, same as Write.
                        self.check_content(new_string)
                    }
                }
            }
            ToolInput::Write { file_path, content } => {
                if let Some(d) = selfprotect::check_settings(file_path, None, Some(content)) {
                    d
                } else {
                    let decision = self.check_file(&input.tool_name, file_path);
                    if decision.is_deny() {
                        decision
                    } else {
                        self.check_content(content)
                    }
                }
            }
            ToolInput::Unknown { .. } => Decision::allow("unknown tool type - passing through"),
        };

        // Allow-once escape hatch: a granted one-shot exception overrides an
        // overridable deny (never self-protection or catastrophic rules).
        let decision = self.apply_allow_once(input, decision);

        // If warn-only mode, convert denies to warnings
        if self.is_warn_only() {
            if let Decision::Deny { rule_id, reason } = decision {
                return Decision::warn(rule_id, reason);
            }
        }

        decision
    }

    /// Check a bash command
    pub fn check_bash(&self, command: &str) -> Decision {
        // Self-protection runs first and is not allowlist-overridable: tampering
        // with the guardrail's own settings or binary is always denied.
        if let Some(decision) = selfprotect::check_bash(command) {
            return decision;
        }

        // Check allowlist first
        if let Some(reason) = self.allowlist.matches("Bash", command) {
            return Decision::allow(format!("allowlisted: {}", reason));
        }

        // Use the bash-specific checker
        bash::check_command(
            command,
            &self.config,
            self.safety_level,
            &self.bash_rules,
            &self.exfil_rules,
        )
    }

    /// Check a file operation
    pub fn check_file(&self, tool: &str, file_path: &str) -> Decision {
        // Self-protection of the install runs first and is not allowlist-overridable.
        if let Some(decision) = selfprotect::check_install(tool, file_path) {
            return decision;
        }

        // Check allowlist first
        if let Some(reason) = self.allowlist.matches(tool, file_path) {
            return Decision::allow(format!("allowlisted: {}", reason));
        }

        // Use the file-specific checker
        file::check_path(
            file_path,
            self.safety_level,
            &self.file_rules,
            &self.config.packs.disabled,
        )
    }

    /// Apply an allow-once grant, if one covers this input and the deny is
    /// overridable. Consumes the grant on match.
    fn apply_allow_once(&self, input: &HookInput, decision: Decision) -> Decision {
        let Decision::Deny { rule_id, .. } = &decision else {
            return decision;
        };
        if !is_overridable(rule_id) {
            return decision;
        }
        let Some(subject) = allow_once_subject(input) else {
            return decision;
        };
        let store = AllowOnceStore::new(AllowOnceStore::default_path());
        if store.check_and_consume(&subject) {
            return Decision::allow("allow-once grant consumed");
        }
        decision
    }

    /// Check file content being written for embedded live credentials.
    pub fn check_content(&self, content: &str) -> Decision {
        if common::contains_secret(content) {
            return Decision::deny(
                "secret-in-content",
                "Writing a live credential (API key or private key) into file content is blocked",
            );
        }
        Decision::allow("content passed all checks")
    }

    /// Get the current safety level
    pub fn safety_level(&self) -> SafetyLevel {
        self.safety_level
    }

    /// Get the configuration
    pub fn config(&self) -> &Config {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> SecurityEngine {
        SecurityEngine::new(Config::default())
    }

    #[test]
    fn test_basic_allow() {
        let engine = test_engine();
        let decision = engine.check_bash("ls -la");
        assert!(decision.is_allow());
    }

    #[test]
    fn test_rm_rf_root_blocked() {
        let engine = test_engine();
        let decision = engine.check_bash("rm -rf /");
        assert!(decision.is_deny());
    }

    #[test]
    fn test_file_env_blocked() {
        let engine = test_engine();
        let decision = engine.check_file("Read", "/path/to/.env");
        assert!(decision.is_deny());
    }

    #[test]
    fn test_file_normal_allowed() {
        let engine = test_engine();
        let decision = engine.check_file("Read", "/path/to/README.md");
        assert!(decision.is_allow());
    }

    #[test]
    fn test_write_content_with_secret_blocked() {
        let engine = test_engine();
        let decision =
            engine.check_content("client = Anthropic(api_key='sk-ant-api03-AbCdEf0123456789xyz')");
        assert!(decision.is_deny());
        assert_eq!(decision.rule_id(), Some("secret-in-content"));
    }

    #[test]
    fn test_write_content_clean_allowed() {
        let engine = test_engine();
        let decision = engine.check_content("fn main() { println!(\"hello\"); }");
        assert!(decision.is_allow());
    }

    #[test]
    fn test_self_protection_bash() {
        let engine = test_engine();
        assert!(engine
            .check_bash("rm ~/.claude/guardrails/claude-guardrails")
            .is_deny());
    }

    #[test]
    fn test_allow_once_scope_security() {
        // C1/H2: allow-once may override operational packs only — never
        // security-critical denials.
        assert!(is_overridable("git-reset-hard")); // core.git
        assert!(is_overridable("chmod-777")); // core.perms
        assert!(is_overridable("docker-system-prune")); // containers.docker
        assert!(is_overridable("drop-database")); // database
        for id in [
            "rm-root",
            "rm-boot",
            "rm-kernel",
            "rm-rf-star", // H2: previously missing
            "curl-pipe-sh",
            "reverse-shell-nc",
            "python-c-os-system",
            "eval-variable",
            "cat-env-file",
            "env-file",
            "ssh-private-key",
            "curl-upload-env",
            "dev-tcp-write",
            "self-protect-install",
            "self-protect-hook",
            "pipe-remote-to-interpreter",
            "dynamic-command",
        ] {
            assert!(
                !is_overridable(id),
                "{id} must not be allow-once-overridable"
            );
        }
    }
}
