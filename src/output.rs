//! Output formatting for Claude Code hook responses
//!
//! Produces the JSON output format expected by Claude Code hooks.

use serde::Serialize;

/// Main output structure for Claude Code hooks
#[derive(Debug, Serialize)]
pub struct HookOutput {
    /// Hook-specific output containing the permission decision
    #[serde(rename = "hookSpecificOutput", skip_serializing_if = "Option::is_none")]
    pub hook_specific_output: Option<HookSpecificOutput>,

    /// Optional system message to show the user
    #[serde(rename = "systemMessage", skip_serializing_if = "Option::is_none")]
    pub system_message: Option<String>,
}

/// Hook-specific output with permission decision
#[derive(Debug, Serialize)]
pub struct HookSpecificOutput {
    /// The hook event name (typically "PreToolUse")
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,

    /// Permission decision: "allow" or "deny"
    #[serde(rename = "permissionDecision")]
    pub permission_decision: String,

    /// Why the call was denied. On a deny, Claude Code shows this text to the
    /// model; `systemMessage` goes to the user only. Without it the model sees
    /// a bare "Blocked by hook" and cannot tell which rule fired.
    #[serde(
        rename = "permissionDecisionReason",
        skip_serializing_if = "Option::is_none"
    )]
    pub permission_decision_reason: Option<String>,
}

/// Decision result from the security engine
#[derive(Debug, Clone)]
pub enum Decision {
    /// Allow the operation
    Allow { reason: String },

    /// Deny the operation
    Deny { rule_id: String, reason: String },

    /// Warn but allow (audit mode)
    Warn { rule_id: String, reason: String },
}

impl Decision {
    /// Create an allow decision
    pub fn allow(reason: impl Into<String>) -> Self {
        Decision::Allow {
            reason: reason.into(),
        }
    }

    /// Create a deny decision
    pub fn deny(rule_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Decision::Deny {
            rule_id: rule_id.into(),
            reason: reason.into(),
        }
    }

    /// Create a warn decision
    pub fn warn(rule_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Decision::Warn {
            rule_id: rule_id.into(),
            reason: reason.into(),
        }
    }

    /// Check if this is an allow decision
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow { .. })
    }

    /// Check if this is a deny decision
    pub fn is_deny(&self) -> bool {
        matches!(self, Decision::Deny { .. })
    }

    /// Get the rule ID if applicable
    pub fn rule_id(&self) -> Option<&str> {
        match self {
            Decision::Allow { .. } => None,
            Decision::Deny { rule_id, .. } => Some(rule_id),
            Decision::Warn { rule_id, .. } => Some(rule_id),
        }
    }

    /// Get the reason
    pub fn reason(&self) -> &str {
        match self {
            Decision::Allow { reason } => reason,
            Decision::Deny { reason, .. } => reason,
            Decision::Warn { reason, .. } => reason,
        }
    }
}

impl HookOutput {
    /// Create an allow response (empty output = allow)
    pub fn allow() -> Self {
        HookOutput {
            hook_specific_output: None,
            system_message: None,
        }
    }

    /// Create a deny response with reason
    pub fn deny(reason: &str) -> Self {
        let message = format!("[guardrails] Blocked: {}", reason);
        HookOutput {
            hook_specific_output: Some(HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "deny".to_string(),
                permission_decision_reason: Some(message.clone()),
            }),
            system_message: Some(message),
        }
    }

    /// Create a deny response with rule ID and reason
    pub fn deny_with_rule(rule_id: &str, reason: &str) -> Self {
        let message = format!("[guardrails:{}] Blocked: {}", rule_id, reason);
        HookOutput {
            hook_specific_output: Some(HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "deny".to_string(),
                permission_decision_reason: Some(message.clone()),
            }),
            system_message: Some(message),
        }
    }

    /// Create a warn response (allows but shows warning)
    pub fn warn(message: &str) -> Self {
        HookOutput {
            hook_specific_output: None,
            system_message: Some(format!("[guardrails] Warning: {}", message)),
        }
    }

    /// Create output from a Decision
    pub fn from_decision(decision: &Decision) -> Self {
        match decision {
            Decision::Allow { .. } => HookOutput::allow(),
            Decision::Deny { rule_id, reason } => HookOutput::deny_with_rule(rule_id, reason),
            Decision::Warn { reason, .. } => HookOutput::warn(reason),
        }
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow_output() {
        let output = HookOutput::allow();
        let json = output.to_json();
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_deny_output() {
        let output = HookOutput::deny("Dangerous command");
        let json = output.to_json();
        assert!(json.contains("deny"));
        assert!(json.contains("Blocked"));
    }

    #[test]
    fn test_deny_with_rule() {
        let output = HookOutput::deny_with_rule("rm-root", "Attempting to delete root");
        let json = output.to_json();
        assert!(json.contains("deny"));
        assert!(json.contains("rm-root"));
    }

    #[test]
    fn test_deny_reason_reaches_the_model() {
        let output = HookOutput::deny_with_rule("env-dump", "Dumping all environment variables");
        let v: serde_json::Value = serde_json::from_str(&output.to_json()).unwrap();
        let hso = &v["hookSpecificOutput"];
        assert_eq!(hso["permissionDecision"], "deny");
        assert_eq!(
            hso["permissionDecisionReason"],
            "[guardrails:env-dump] Blocked: Dumping all environment variables"
        );
        assert_eq!(v["systemMessage"], hso["permissionDecisionReason"]);

        let plain: serde_json::Value =
            serde_json::from_str(&HookOutput::deny("Dangerous command").to_json()).unwrap();
        assert_eq!(
            plain["hookSpecificOutput"]["permissionDecisionReason"],
            "[guardrails] Blocked: Dangerous command"
        );
    }

    #[test]
    fn test_allow_and_warn_carry_no_decision_reason() {
        assert!(!HookOutput::allow()
            .to_json()
            .contains("permissionDecisionReason"));
        assert!(!HookOutput::warn("risky")
            .to_json()
            .contains("permissionDecisionReason"));
    }

    #[test]
    fn test_warn_output() {
        let output = HookOutput::warn("This might be risky");
        let json = output.to_json();
        // Warn allows (no hookSpecificOutput) but has message
        assert!(json.contains("Warning"));
        assert!(!json.contains("deny"));
    }

    #[test]
    fn test_from_decision_allow() {
        let decision = Decision::allow("passed checks");
        let output = HookOutput::from_decision(&decision);
        assert!(output.hook_specific_output.is_none());
    }

    #[test]
    fn test_from_decision_deny() {
        let decision = Decision::deny("test-rule", "test reason");
        let output = HookOutput::from_decision(&decision);
        assert!(output.hook_specific_output.is_some());
        assert_eq!(
            output.hook_specific_output.unwrap().permission_decision,
            "deny"
        );
    }
}
