//! Shell parsing utilities for claude-guardrails
//!
//! Provides shell tokenization, wrapper command detection, and AST-based analysis.

pub mod ast;
mod inline_python;
pub mod shell;
pub mod wrapper;
