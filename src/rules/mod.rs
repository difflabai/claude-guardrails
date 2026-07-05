//! Security rules for claude-guardrails
//!
//! Defines dangerous command patterns, secrets patterns, and exfiltration detection.

pub mod allowlist;
pub mod dangerous;
pub mod exfiltration;
pub mod packs;
pub mod secrets;

use crate::config::SafetyLevel;

/// A security rule definition
#[derive(Debug, Clone)]
pub struct Rule {
    /// Unique identifier for this rule
    pub id: &'static str,

    /// Safety level at which this rule is active
    pub level: SafetyLevel,

    /// Regex pattern to match
    pub pattern: &'static str,

    /// Human-readable reason for blocking
    pub reason: &'static str,
}

impl Rule {
    /// Create a new rule
    pub const fn new(
        id: &'static str,
        level: SafetyLevel,
        pattern: &'static str,
        reason: &'static str,
    ) -> Self {
        Self {
            id,
            level,
            pattern,
            reason,
        }
    }
}
