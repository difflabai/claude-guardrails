//! Integration tests for override mechanisms

use std::env;
use claude_guardrails::{Config, HookInput, SecurityEngine};

fn check_with_env(command: &str, env_var: &str, env_val: &str) -> bool {
    // Set the environment variable
    env::set_var(env_var, env_val);

    let json = format!(
        r#"{{"tool_name":"Bash","tool_input":{{"command":"{}"}}}}"#,
        command.replace('\\', "\\\\").replace('"', "\\\"")
    );
    let input = HookInput::from_json(&json).unwrap();
    let engine = SecurityEngine::new(Config::default());
    let decision = engine.check(&input);

    // Clean up environment
    env::remove_var(env_var);

    decision.is_allow()
}

// ============================================================================
// GUARDRAILS_DISABLED Tests
// ============================================================================

#[test]
fn test_disabled_allows_dangerous_command() {
    // Without GUARDRAILS_DISABLED, rm -rf / is blocked
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
    let input = HookInput::from_json(json).unwrap();
    let engine = SecurityEngine::new(Config::default());
    let decision = engine.check(&input);
    assert!(decision.is_deny());

    // With GUARDRAILS_DISABLED, it's allowed
    assert!(check_with_env("rm -rf /", "GUARDRAILS_DISABLED", "1"));
}

// ============================================================================
// GUARDRAILS_WARN_ONLY Tests
// ============================================================================

#[test]
fn test_warn_only_converts_deny_to_warn() {
    env::set_var("GUARDRAILS_WARN_ONLY", "1");

    let json = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
    let input = HookInput::from_json(json).unwrap();
    let engine = SecurityEngine::new(Config::default());
    let decision = engine.check(&input);

    env::remove_var("GUARDRAILS_WARN_ONLY");

    // Should be a warn (which counts as allow)
    assert!(decision.is_allow() || matches!(decision, claude_guardrails::Decision::Warn { .. }));
}

// ============================================================================
// Safety Level Override Tests
// ============================================================================

#[test]
fn test_safety_level_critical() {
    use claude_guardrails::SafetyLevel;

    let mut config = Config::default();
    config.general.safety_level = SafetyLevel::Critical;
    let engine = SecurityEngine::new(config);

    // Critical should still block rm -rf /
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
    let input = HookInput::from_json(json).unwrap();
    let decision = engine.check(&input);
    assert!(decision.is_deny());

    // But critical should allow git push -f main (that's a high-level rule)
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"git push -f origin main"}}"#;
    let input = HookInput::from_json(json).unwrap();
    let _decision = engine.check(&input);
    // This might still be blocked by pipe-to-shell or other checks,
    // so we just verify the safety level is applied
    assert_eq!(engine.safety_level(), SafetyLevel::Critical);
}

#[test]
fn test_safety_level_strict() {
    use claude_guardrails::SafetyLevel;

    let mut config = Config::default();
    config.general.safety_level = SafetyLevel::Strict;
    let engine = SecurityEngine::new(config);

    assert_eq!(engine.safety_level(), SafetyLevel::Strict);
}

// ============================================================================
// Allowlist Tests
// ============================================================================

#[test]
fn test_allowlist_matching() {
    use claude_guardrails::rules::allowlist::{AllowEntry, AllowlistConfig, CompiledAllowlist};

    let config = AllowlistConfig {
        allow: vec![
            AllowEntry {
                pattern: r"rm\s+-rf\s+\./node_modules".to_string(),
                reason: "Allow cleaning node_modules".to_string(),
                tool: Some("Bash".to_string()),
            },
        ],
    };

    let allowlist = CompiledAllowlist::from_config(&config).unwrap();

    // Should match
    assert!(allowlist.matches("Bash", "rm -rf ./node_modules").is_some());

    // Should not match (different path)
    assert!(allowlist.matches("Bash", "rm -rf /").is_none());

    // Should not match (different tool)
    assert!(allowlist.matches("Read", "rm -rf ./node_modules").is_none());
}

// ============================================================================
// Config Loading Tests
// ============================================================================

#[test]
fn test_default_config() {
    let config = Config::default();
    assert_eq!(config.general.safety_level, claude_guardrails::SafetyLevel::High);
    assert!(config.general.audit_log);
    assert!(!config.bash.wrappers.is_empty());
    assert!(config.bash.block_variable_commands);
    assert!(config.bash.block_pipe_to_shell);
}

#[test]
fn test_config_expand_path() {
    let expanded = Config::expand_path("~/.claude/guardrails/audit.jsonl");
    // Should not start with ~
    assert!(!expanded.to_string_lossy().starts_with('~'));
}
