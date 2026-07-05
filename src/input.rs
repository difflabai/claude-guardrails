//! Input parsing for Claude Code hook JSON format
//!
//! Parses the JSON input from stdin that Claude Code sends to hooks.

use serde::Deserialize;

/// Main input structure from Claude Code hooks
#[derive(Debug, Deserialize)]
pub struct HookInput {
    /// Name of the tool being invoked (e.g., "Bash", "Read", "Edit", "Write")
    pub tool_name: String,

    /// Tool-specific input parameters
    pub tool_input: ToolInput,

    /// Optional session identifier
    #[serde(default)]
    pub session_id: Option<String>,

    /// Hook event name (e.g., "PreToolUse")
    #[serde(default)]
    pub hook_event_name: Option<String>,
}

/// Tool-specific input variants
#[derive(Debug, Clone)]
pub enum ToolInput {
    /// Bash command execution
    Bash {
        command: String,
        #[allow(dead_code)]
        description: Option<String>,
        #[allow(dead_code)]
        timeout: Option<u64>,
    },

    /// File read operation
    Read { file_path: String },

    /// File edit operation
    Edit {
        file_path: String,
        old_string: String,
        new_string: String,
    },

    /// File write operation
    Write { file_path: String, content: String },

    /// Unknown tool - pass through
    Unknown { raw: serde_json::Value },
}

impl<'de> Deserialize<'de> for ToolInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialize as raw JSON value first
        let value = serde_json::Value::deserialize(deserializer)?;

        // Try to determine the type based on available fields
        if let Some(obj) = value.as_object() {
            // Check for Bash (has "command")
            if let Some(command) = obj.get("command").and_then(|v| v.as_str()) {
                return Ok(ToolInput::Bash {
                    command: command.to_string(),
                    description: obj
                        .get("description")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    timeout: obj.get("timeout").and_then(|v| v.as_u64()),
                });
            }

            // Check for file operations (has "file_path")
            if let Some(file_path) = obj.get("file_path").and_then(|v| v.as_str()) {
                // Edit has old_string and new_string
                if let (Some(old_string), Some(new_string)) = (
                    obj.get("old_string").and_then(|v| v.as_str()),
                    obj.get("new_string").and_then(|v| v.as_str()),
                ) {
                    return Ok(ToolInput::Edit {
                        file_path: file_path.to_string(),
                        old_string: old_string.to_string(),
                        new_string: new_string.to_string(),
                    });
                }

                // Write has content
                if let Some(content) = obj.get("content").and_then(|v| v.as_str()) {
                    return Ok(ToolInput::Write {
                        file_path: file_path.to_string(),
                        content: content.to_string(),
                    });
                }

                // Read only has file_path
                return Ok(ToolInput::Read {
                    file_path: file_path.to_string(),
                });
            }
        }

        // Unknown tool format - preserve raw data
        Ok(ToolInput::Unknown { raw: value })
    }
}

impl HookInput {
    /// Parse input from JSON string
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Get a short, human-readable summary of the input for logging.
    /// Bash commands are truncated on a UTF-8 char boundary (never mid-codepoint).
    pub fn summary(&self) -> String {
        match &self.tool_input {
            ToolInput::Bash { command, .. } => {
                format!("Bash: {}", truncate_chars(command, 100))
            }
            ToolInput::Read { file_path } => format!("Read: {}", file_path),
            ToolInput::Edit { file_path, .. } => format!("Edit: {}", file_path),
            ToolInput::Write { file_path, .. } => format!("Write: {}", file_path),
            ToolInput::Unknown { .. } => format!("Unknown tool: {}", self.tool_name),
        }
    }

    /// The full, untruncated Bash command, if this is a Bash invocation. Logged
    /// so `replay` can faithfully re-evaluate long commands that `summary()` cuts.
    pub fn full_command(&self) -> Option<&str> {
        match &self.tool_input {
            ToolInput::Bash { command, .. } => Some(command),
            _ => None,
        }
    }
}

/// Truncate to at most `max` characters (not bytes), appending `...` if cut.
fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        let head: String = s.chars().take(max).collect();
        format!("{}...", head)
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bash_input() {
        let json = r#"{"tool_name":"Bash","tool_input":{"command":"ls -la"}}"#;
        let input = HookInput::from_json(json).unwrap();
        assert_eq!(input.tool_name, "Bash");
        match input.tool_input {
            ToolInput::Bash { command, .. } => assert_eq!(command, "ls -la"),
            _ => panic!("Expected Bash input"),
        }
    }

    #[test]
    fn test_parse_read_input() {
        let json = r#"{"tool_name":"Read","tool_input":{"file_path":"/etc/passwd"}}"#;
        let input = HookInput::from_json(json).unwrap();
        assert_eq!(input.tool_name, "Read");
        match input.tool_input {
            ToolInput::Read { file_path } => assert_eq!(file_path, "/etc/passwd"),
            _ => panic!("Expected Read input"),
        }
    }

    #[test]
    fn test_parse_edit_input() {
        let json = r#"{"tool_name":"Edit","tool_input":{"file_path":"test.txt","old_string":"foo","new_string":"bar"}}"#;
        let input = HookInput::from_json(json).unwrap();
        assert_eq!(input.tool_name, "Edit");
        match input.tool_input {
            ToolInput::Edit {
                file_path,
                old_string,
                new_string,
            } => {
                assert_eq!(file_path, "test.txt");
                assert_eq!(old_string, "foo");
                assert_eq!(new_string, "bar");
            }
            _ => panic!("Expected Edit input"),
        }
    }

    #[test]
    fn test_parse_write_input() {
        let json = r#"{"tool_name":"Write","tool_input":{"file_path":"test.txt","content":"hello world"}}"#;
        let input = HookInput::from_json(json).unwrap();
        assert_eq!(input.tool_name, "Write");
        match input.tool_input {
            ToolInput::Write { file_path, content } => {
                assert_eq!(file_path, "test.txt");
                assert_eq!(content, "hello world");
            }
            _ => panic!("Expected Write input"),
        }
    }

    #[test]
    fn test_parse_with_session_id() {
        let json = r#"{"tool_name":"Bash","tool_input":{"command":"ls"},"session_id":"abc123"}"#;
        let input = HookInput::from_json(json).unwrap();
        assert_eq!(input.session_id, Some("abc123".to_string()));
    }
}
