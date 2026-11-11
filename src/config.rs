//! Configuration loading for claude-guardrails
//!
//! Supports TOML configuration with embedded defaults.

use serde::Deserialize;
use std::path::PathBuf;

/// Safety level determines which rules are active
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SafetyLevel {
    /// Only block catastrophic operations (rm -rf /, fork bombs)
    Critical,

    /// Block critical + risky operations (force push main, secrets exposure)
    #[default]
    High,

    /// Block all above + cautionary (any force push, sudo rm)
    Strict,
}

impl SafetyLevel {
    /// Check if a rule level is active under this safety level
    pub fn includes(&self, rule_level: SafetyLevel) -> bool {
        match self {
            SafetyLevel::Critical => rule_level == SafetyLevel::Critical,
            SafetyLevel::High => {
                rule_level == SafetyLevel::Critical || rule_level == SafetyLevel::High
            }
            SafetyLevel::Strict => true,
        }
    }

    /// Parse from string
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "critical" => Some(SafetyLevel::Critical),
            "high" => Some(SafetyLevel::High),
            "strict" => Some(SafetyLevel::Strict),
            _ => None,
        }
    }
}

/// General configuration section
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    /// Safety level for rule filtering
    pub safety_level: SafetyLevel,

    /// Enable audit logging
    pub audit_log: bool,

    /// Path to audit log file
    pub audit_path: Option<String>,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            safety_level: SafetyLevel::High,
            audit_log: true,
            audit_path: Some("~/.claude/guardrails/audit.jsonl".to_string()),
        }
    }
}

/// Override configuration section
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct OverrideConfig {
    /// Path to allowlist file
    pub allowlist_file: Option<String>,
}

/// Bash-specific configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct BashConfig {
    /// Commands that wrap other commands (to scan recursively)
    pub wrappers: Vec<String>,

    /// Block variable-based command execution ($cmd, $(cmd), `cmd`)
    pub block_variable_commands: bool,

    /// Block dangerous pipe targets (| sh, | bash)
    pub block_pipe_to_shell: bool,
}

impl Default for BashConfig {
    fn default() -> Self {
        Self {
            wrappers: vec![
                "sudo".to_string(),
                "timeout".to_string(),
                "xargs".to_string(),
                "env".to_string(),
                "nice".to_string(),
                "nohup".to_string(),
                "ionice".to_string(),
                "strace".to_string(),
                "time".to_string(),
                "unbuffer".to_string(),
            ],
            block_variable_commands: true,
            block_pipe_to_shell: true,
        }
    }
}

/// File operation configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FilesConfig {
    /// Patterns to protect from Read/Edit/Write
    pub protected_patterns: Vec<String>,
}

impl Default for FilesConfig {
    fn default() -> Self {
        Self {
            protected_patterns: vec![
                r"\.env$".to_string(),
                r"\.env\.local$".to_string(),
                r"\.env\.production$".to_string(),
                r"\.ssh/".to_string(),
                r"\.aws/credentials".to_string(),
                r"\.kube/config".to_string(),
                r"\.pem$".to_string(),
                r"credentials\.json$".to_string(),
                r"secrets?\.(json|ya?ml)$".to_string(),
                r"\.docker/config\.json".to_string(),
                r"\.netrc$".to_string(),
                r"\.npmrc$".to_string(),
                r"\.pypirc$".to_string(),
            ],
        }
    }
}

/// Main configuration structure
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub general: GeneralConfig,
    pub overrides: OverrideConfig,
    pub bash: BashConfig,
    pub files: FilesConfig,
}

impl Config {
    /// Load configuration from file or use defaults
    pub fn load() -> Self {
        // Try to load from standard locations
        let config_paths = [
            // User-specific config
            dirs::home_dir().map(|p| p.join(".claude/guardrails/config.toml")),
            // System-wide config
            Some(PathBuf::from("/etc/claude-guardrails/config.toml")),
        ];

        for path in config_paths.into_iter().flatten() {
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    match toml::from_str(&content) {
                        Ok(config) => return config,
                        Err(e) => {
                            eprintln!("Warning: Failed to parse {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }

        // Return defaults
        Config::default()
    }

    /// Load from a specific path
    pub fn load_from(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Expand ~ in path strings
    pub fn expand_path(path: &str) -> PathBuf {
        if let Some(rest) = path.strip_prefix("~/") {
            if let Some(home) = dirs::home_dir() {
                return home.join(rest);
            }
        }
        PathBuf::from(path)
    }

    /// Get the audit log path (expanded)
    pub fn audit_path(&self) -> Option<PathBuf> {
        self.general.audit_path.as_ref().map(|p| Self::expand_path(p))
    }

    /// Get the allowlist file path (expanded)
    pub fn allowlist_path(&self) -> Option<PathBuf> {
        self.overrides
            .allowlist_file
            .as_ref()
            .map(|p| Self::expand_path(p))
    }
}

/// Embedded default configuration
pub const DEFAULT_CONFIG_TOML: &str = r#"
[general]
safety_level = "high"
audit_log = true
audit_path = "~/.claude/guardrails/audit.jsonl"

[overrides]
allowlist_file = "~/.claude/guardrails/allow.toml"

[bash]
wrappers = ["sudo", "timeout", "xargs", "env", "nice", "nohup", "ionice", "strace", "time"]
block_variable_commands = true
block_pipe_to_shell = true

[files]
protected_patterns = [
    "\\.env$",
    "\\.env\\.local$",
    "\\.env\\.production$",
    "\\.ssh/",
    "\\.aws/credentials",
    "\\.kube/config",
    "\\.pem$",
    "credentials\\.json$",
    "secrets?\\.(json|ya?ml)$",
    "\\.docker/config\\.json",
    "\\.netrc$",
    "\\.npmrc$",
    "\\.pypirc$",
]
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safety_level_includes() {
        assert!(SafetyLevel::Critical.includes(SafetyLevel::Critical));
        assert!(!SafetyLevel::Critical.includes(SafetyLevel::High));

        assert!(SafetyLevel::High.includes(SafetyLevel::Critical));
        assert!(SafetyLevel::High.includes(SafetyLevel::High));
        assert!(!SafetyLevel::High.includes(SafetyLevel::Strict));

        assert!(SafetyLevel::Strict.includes(SafetyLevel::Critical));
        assert!(SafetyLevel::Strict.includes(SafetyLevel::High));
        assert!(SafetyLevel::Strict.includes(SafetyLevel::Strict));
    }

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.general.safety_level, SafetyLevel::High);
        assert!(config.general.audit_log);
        assert!(!config.bash.wrappers.is_empty());
    }

    #[test]
    fn test_parse_embedded_config() {
        let config: Config = toml::from_str(DEFAULT_CONFIG_TOML).unwrap();
        assert_eq!(config.general.safety_level, SafetyLevel::High);
    }

    #[test]
    fn test_expand_path() {
        let expanded = Config::expand_path("~/.claude/guardrails/audit.jsonl");
        assert!(!expanded.to_string_lossy().starts_with("~"));
    }
}
