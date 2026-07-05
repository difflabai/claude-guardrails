//! claude-guardrails - Security guardrails for Claude Code YOLO mode
//!
//! A fast, robust security hook that analyzes commands before execution.
//!
//! # Usage
//!
//! ```bash
//! # As a Claude Code hook (reads JSON from stdin, writes JSON to stdout)
//! echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | claude-guardrails
//!
//! # With safety level override
//! claude-guardrails --safety-level=strict
//!
//! # Dry-run mode (show what would be blocked)
//! claude-guardrails --dry-run
//! ```

use std::env;
use std::io::{self, BufRead, Write};

use claude_guardrails::{
    allowonce::{self, AllowOnceStore},
    audit::AuditLogger,
    config::{Config, SafetyLevel},
    doctor,
    engine::{self, SecurityEngine},
    explain,
    input::HookInput,
    output::HookOutput,
    replay,
};

/// Print version information
fn print_version() {
    println!("claude-guardrails {}", env!("CARGO_PKG_VERSION"));
}

/// Print help message
fn print_help() {
    println!(
        r#"claude-guardrails - Security guardrails for Claude Code YOLO mode

USAGE:
    claude-guardrails [OPTIONS]

OPTIONS:
    -h, --help              Print this help message
    -v, --version           Print version information
    -l, --safety-level      Safety level: critical, high, strict (default: high)
    -d, --dry-run           Dry-run mode (show what would be blocked but allow)
    -c, --config PATH       Path to config file

ENVIRONMENT:
    GUARDRAILS_DISABLED=1   Disable all checks (still logs)
    GUARDRAILS_WARN_ONLY=1  Warn but don't block

USAGE AS HOOK:
    Configure in ~/.claude/settings.json:
    {{
      "hooks": {{
        "PreToolUse": [{{
          "type": "command",
          "command": "~/.claude/guardrails/claude-guardrails",
          "timeout": 5000,
          "tools": ["Bash", "Read", "Edit", "Write"]
        }}]
      }}
    }}
"#
    );
}

/// Parse command line arguments
struct Args {
    help: bool,
    version: bool,
    safety_level: Option<SafetyLevel>,
    dry_run: bool,
    config_path: Option<String>,
}

impl Args {
    fn parse() -> Self {
        let args: Vec<String> = env::args().collect();
        let mut result = Args {
            help: false,
            version: false,
            safety_level: None,
            dry_run: false,
            config_path: None,
        };

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-h" | "--help" => result.help = true,
                "-v" | "--version" => result.version = true,
                "-d" | "--dry-run" => result.dry_run = true,
                "-l" | "--safety-level" if i + 1 < args.len() => {
                    i += 1;
                    result.safety_level = SafetyLevel::parse(&args[i]);
                }
                "-c" | "--config" if i + 1 < args.len() => {
                    i += 1;
                    result.config_path = Some(args[i].clone());
                }
                arg if arg.starts_with("--safety-level=") => {
                    let level = arg.trim_start_matches("--safety-level=");
                    result.safety_level = SafetyLevel::parse(level);
                }
                arg if arg.starts_with("--config=") => {
                    let path = arg.trim_start_matches("--config=");
                    result.config_path = Some(path.to_string());
                }
                _ => {}
            }
            i += 1;
        }

        result
    }
}

/// `guardrails replay <audit.jsonl> [--limit N]` — regression oracle.
/// Re-runs the current ruleset over a historical audit log and reports verdict
/// changes. Exit code 2 if any command that was BLOCKED is now allowed *and*
/// isn't verifiable here, so it can gate CI before a rule change deploys.
fn run_replay(argv: &[String]) -> i32 {
    let path = match argv.get(2) {
        Some(p) => std::path::PathBuf::from(p),
        None => {
            eprintln!("usage: claude-guardrails replay <audit.jsonl> [--limit N]");
            return 1;
        }
    };
    let mut limit = 20usize;
    let mut i = 3;
    while i < argv.len() {
        if argv[i] == "--limit" && i + 1 < argv.len() {
            limit = argv[i + 1].parse().unwrap_or(20);
            i += 1;
        }
        i += 1;
    }

    let engine = SecurityEngine::new(Config::load());
    match replay::run(&path, &engine) {
        Ok(report) => {
            replay::print_report(&report, limit);
            0
        }
        Err(e) => {
            eprintln!("replay failed: {}", e);
            1
        }
    }
}

/// `guardrails allow-once <code>` — grant a single-use, 24h exception for the
/// command whose denial produced `<code>`.
fn run_allow_once(argv: &[String]) -> i32 {
    let Some(code) = argv.get(2) else {
        eprintln!("usage: claude-guardrails allow-once <code>");
        return 1;
    };
    let store = AllowOnceStore::new(AllowOnceStore::default_path());
    match store.grant(code) {
        Ok(()) => {
            println!(
                "Granted a one-shot exception for code {} (expires in 24h). \
                 Re-run the blocked command once to proceed.",
                code.to_uppercase()
            );
            0
        }
        Err(e) => {
            eprintln!("allow-once failed: {}", e);
            1
        }
    }
}

/// `guardrails test "<command>"` — evaluate a single command without executing.
fn run_test(argv: &[String]) -> i32 {
    let Some(command) = argv.get(2) else {
        eprintln!("usage: claude-guardrails test \"<command>\"");
        return 1;
    };
    let engine = SecurityEngine::new(Config::load());
    let decision = engine.check_bash(command);
    match decision {
        claude_guardrails::Decision::Deny { rule_id, reason } => {
            println!("DENY  [{}] {}", rule_id, reason);
            0
        }
        claude_guardrails::Decision::Warn { rule_id, reason } => {
            println!("WARN  [{}] {}", rule_id, reason);
            0
        }
        claude_guardrails::Decision::Allow { reason } => {
            println!("ALLOW {}", reason);
            0
        }
    }
}

/// `guardrails explain "<command>"` — print a decision trace with timing.
fn run_explain(argv: &[String]) -> i32 {
    let Some(command) = argv.get(2) else {
        eprintln!("usage: claude-guardrails explain \"<command>\"");
        return 1;
    };
    explain::print_trace(&explain::trace(command, &Config::load()));
    0
}

/// `guardrails doctor` — run operational health checks.
fn run_doctor() -> i32 {
    doctor::print_and_code(&doctor::run(&Config::load()))
}

/// `guardrails packs` — list security packs and their enabled/disabled state.
fn run_packs() -> i32 {
    use claude_guardrails::rules::packs::{is_disabled, ALL_PACKS};
    let disabled = Config::load().packs.disabled;
    for p in ALL_PACKS {
        let state = if p.always_on {
            "on (always)"
        } else if is_disabled(p.name, &disabled) {
            "off"
        } else {
            "on"
        };
        println!("  {:<18} [{:<11}] {}", p.name, state, p.description);
    }
    0
}

fn main() {
    // Subcommand dispatch (before the stdin hook flow).
    let raw: Vec<String> = env::args().collect();
    if let Some(sub) = raw.get(1) {
        match sub.as_str() {
            "replay" => std::process::exit(run_replay(&raw)),
            "test" => std::process::exit(run_test(&raw)),
            "explain" => std::process::exit(run_explain(&raw)),
            "doctor" => std::process::exit(run_doctor()),
            "packs" => std::process::exit(run_packs()),
            "allow-once" => std::process::exit(run_allow_once(&raw)),
            _ => {}
        }
    }

    let args = Args::parse();

    // Handle help and version
    if args.help {
        print_help();
        return;
    }

    if args.version {
        print_version();
        return;
    }

    // Load configuration
    let mut config = if let Some(ref path) = args.config_path {
        Config::load_from(std::path::Path::new(path)).unwrap_or_else(|e| {
            eprintln!("Warning: Failed to load config from {}: {}", path, e);
            Config::default()
        })
    } else {
        Config::load()
    };

    // Override safety level if specified
    if let Some(level) = args.safety_level {
        config.general.safety_level = level;
    }

    // Set up dry-run mode via environment
    if args.dry_run {
        env::set_var("GUARDRAILS_WARN_ONLY", "1");
    }

    // Create security engine
    let engine = SecurityEngine::new(config.clone());

    // Create audit logger
    let audit_path = if config.general.audit_log {
        config.audit_path()
    } else {
        None
    };
    let mut logger = AuditLogger::with_rotation(
        audit_path.as_deref(),
        config.general.audit_max_bytes,
        config.general.audit_keep,
    );

    // Read JSON from stdin
    let stdin = io::stdin();
    let mut input_json = String::new();

    for line in stdin.lock().lines() {
        match line {
            Ok(line) => input_json.push_str(&line),
            Err(_) => break,
        }
    }

    // Handle empty input
    if input_json.trim().is_empty() {
        // No input = nothing to check, allow
        let output = HookOutput::allow();
        println!("{}", output.to_json());
        return;
    }

    // Parse input
    let input = match HookInput::from_json(&input_json) {
        Ok(input) => input,
        Err(e) => {
            // SECURITY: Fail closed on parse errors
            // Malformed input could be an evasion attempt
            eprintln!("Error: Failed to parse input (denying): {}", e);
            let output = HookOutput::deny_with_rule(
                "parse-error",
                &format!("Failed to parse hook input: {}", e),
            );
            println!("{}", output.to_json());
            return;
        }
    };

    // Check if disabled
    let disabled = engine.is_disabled();

    // Run security check
    let decision = engine.check(&input);

    // Log the decision
    if let Err(e) = logger.log_decision(&input, &decision, disabled) {
        eprintln!("Warning: Failed to write audit log: {}", e);
    }

    // On an overridable denial, tell the user how to allow it once.
    if let claude_guardrails::Decision::Deny { rule_id, .. } = &decision {
        if engine::is_overridable(rule_id) {
            if let Some(subject) = engine::allow_once_subject(&input) {
                eprintln!(
                    "↳ if this is safe, allow it once with: claude-guardrails allow-once {}",
                    allowonce::code_for(&subject)
                );
            }
        }
    }

    // Generate output
    let output = HookOutput::from_decision(&decision);

    // Write to stdout
    let json = output.to_json();
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    let _ = writeln!(handle, "{}", json);
    let _ = handle.flush();
}
