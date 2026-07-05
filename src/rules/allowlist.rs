//! Allowlist handling for bypassing security checks
//!
//! Supports user-defined patterns that should bypass security checks.

use regex::Regex;
use serde::Deserialize;
use std::path::Path;

/// An allowlist entry
#[derive(Debug, Clone, Deserialize)]
pub struct AllowEntry {
    /// Regex pattern to match
    pub pattern: String,

    /// Human-readable reason for allowing
    pub reason: String,

    /// Optional tool restriction (if not set, applies to all tools)
    #[serde(default)]
    pub tool: Option<String>,
}

/// The allowlist configuration file structure
#[derive(Debug, Clone, Deserialize, Default)]
pub struct AllowlistConfig {
    /// List of allowed patterns
    #[serde(default)]
    pub allow: Vec<AllowEntry>,
}

/// Compiled allowlist for efficient matching
pub struct CompiledAllowlist {
    /// General patterns (apply to all tools)
    general: Vec<(Regex, String)>,

    /// Bash-specific patterns
    bash: Vec<(Regex, String)>,

    /// Read-specific patterns
    read: Vec<(Regex, String)>,

    /// Edit-specific patterns
    edit: Vec<(Regex, String)>,

    /// Write-specific patterns
    write: Vec<(Regex, String)>,
}

impl CompiledAllowlist {
    /// Create an empty allowlist
    pub fn empty() -> Self {
        Self {
            general: Vec::new(),
            bash: Vec::new(),
            read: Vec::new(),
            edit: Vec::new(),
            write: Vec::new(),
        }
    }

    /// Load and compile allowlist from file
    pub fn from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: AllowlistConfig = toml::from_str(&content)?;
        Self::from_config(&config)
    }

    /// Compile from config
    pub fn from_config(config: &AllowlistConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let mut allowlist = Self::empty();

        for entry in &config.allow {
            let regex = Regex::new(&entry.pattern)?;
            let item = (regex, entry.reason.clone());

            match entry.tool.as_deref() {
                Some("Bash") | Some("bash") => allowlist.bash.push(item),
                Some("Read") | Some("read") => allowlist.read.push(item),
                Some("Edit") | Some("edit") => allowlist.edit.push(item),
                Some("Write") | Some("write") => allowlist.write.push(item),
                None | Some("*") => allowlist.general.push(item),
                Some(other) => {
                    eprintln!("Warning: Unknown tool type in allowlist: {}", other);
                    allowlist.general.push(item);
                }
            }
        }

        Ok(allowlist)
    }

    /// Check if a command/path matches the allowlist for the given tool
    pub fn matches(&self, tool: &str, input: &str) -> Option<&str> {
        // Check tool-specific patterns first
        let tool_patterns: &[(Regex, String)] = match tool.to_lowercase().as_str() {
            "bash" => &self.bash,
            "read" => &self.read,
            "edit" => &self.edit,
            "write" => &self.write,
            _ => &[],
        };

        for (regex, reason) in tool_patterns {
            if regex.is_match(input) {
                return Some(reason);
            }
        }

        // Then check general patterns
        for (regex, reason) in &self.general {
            if regex.is_match(input) {
                return Some(reason);
            }
        }

        None
    }

    /// Check if the allowlist is empty
    pub fn is_empty(&self) -> bool {
        self.general.is_empty()
            && self.bash.is_empty()
            && self.read.is_empty()
            && self.edit.is_empty()
            && self.write.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allowlist_parsing() {
        let toml = r#"
            [[allow]]
            pattern = "rm\\s+-rf\\s+\\./node_modules"
            reason = "Allow cleaning node_modules"

            [[allow]]
            pattern = "\\.env\\.example$"
            reason = "Allow reading .env examples"
            tool = "Read"
        "#;

        let config: AllowlistConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.allow.len(), 2);
        assert_eq!(config.allow[0].reason, "Allow cleaning node_modules");
        assert_eq!(config.allow[1].tool, Some("Read".to_string()));
    }

    #[test]
    fn test_compiled_allowlist() {
        let config = AllowlistConfig {
            allow: vec![
                AllowEntry {
                    pattern: r"rm\s+-rf\s+\./node_modules".to_string(),
                    reason: "Allow cleaning node_modules".to_string(),
                    tool: Some("Bash".to_string()),
                },
                AllowEntry {
                    pattern: r"\.env\.example$".to_string(),
                    reason: "Allow reading .env examples".to_string(),
                    tool: Some("Read".to_string()),
                },
            ],
        };

        let allowlist = CompiledAllowlist::from_config(&config).unwrap();

        // Should match bash command
        assert!(allowlist.matches("Bash", "rm -rf ./node_modules").is_some());

        // Should not match read for bash pattern
        assert!(allowlist.matches("Read", "rm -rf ./node_modules").is_none());

        // Should match read pattern
        assert!(allowlist.matches("Read", ".env.example").is_some());
        assert!(allowlist.matches("Read", "/path/to/.env.example").is_some());

        // Should not match .env (not .env.example)
        assert!(allowlist.matches("Read", ".env").is_none());
    }

    #[test]
    fn test_general_patterns() {
        let config = AllowlistConfig {
            allow: vec![AllowEntry {
                pattern: r"test-pattern".to_string(),
                reason: "General allow".to_string(),
                tool: None,
            }],
        };

        let allowlist = CompiledAllowlist::from_config(&config).unwrap();

        // Should match for any tool
        assert!(allowlist.matches("Bash", "test-pattern").is_some());
        assert!(allowlist.matches("Read", "test-pattern").is_some());
        assert!(allowlist.matches("Write", "test-pattern").is_some());
    }
}
