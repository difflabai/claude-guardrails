//! claude-guardrails - Security guardrails for Claude Code YOLO mode
//!
//! This library provides security checks for Claude Code hooks, blocking
//! dangerous commands and protecting sensitive files.
//!
//! # Features
//!
//! - **Bash command analysis**: Detects dangerous shell commands
//! - **File protection**: Blocks access to sensitive files (.env, SSH keys, etc.)
//! - **Wrapper detection**: Unwraps sudo, timeout, env, etc. to analyze the real command
//! - **Safety levels**: Configurable strictness (critical, high, strict)
//! - **Allowlist support**: User-defined exceptions for specific patterns
//! - **Audit logging**: JSONL log of all decisions
//!
//! # Example
//!
//! ```
//! use claude_guardrails::{Config, SecurityEngine, HookInput};
//!
//! let config = Config::default();
//! let engine = SecurityEngine::new(config);
//!
//! let input = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
//! let hook_input = HookInput::from_json(input).unwrap();
//!
//! let decision = engine.check(&hook_input);
//! assert!(decision.is_deny());
//! ```

pub mod allowonce;
pub mod audit;
pub mod config;
pub mod doctor;
pub mod engine;
pub mod explain;
pub mod input;
pub mod output;
pub mod parser;
pub mod replay;
pub mod rules;

// Re-exports for convenience
pub use config::{Config, SafetyLevel};
pub use engine::SecurityEngine;
pub use input::{HookInput, ToolInput};
pub use output::{Decision, HookOutput};
