//! steward-l8b3, round 3: rm-home and bash-c-rm-home are main's regexes, unchanged,
//! with an AST check OR'd on top. The PR may only ADD denials.
//!
//! * `main_regexes_are_main_text`: the two patterns are byte-for-byte main's.
//! * `every_command_main_denies_is_still_denied`: a corpus of commands that main
//!   denies, recorded from main's own engine at three safety levels, is denied at head
//!   by the same rule at the same level.
//! * the rest: commands that delete the home directory and that main (or round 1 or
//!   round 2 of this PR) let through, each through every wrapper.
//!
//! All tests go through `SecurityEngine::check_bash`, the entry the hook binary uses,
//! with the real tree-sitter-bash parser and the real rule set.

use claude_guardrails::rules::dangerous;
use claude_guardrails::{Config, Decision, SafetyLevel, SecurityEngine};

fn engine_at(level: SafetyLevel) -> SecurityEngine {
    let mut config = Config::default();
    config.general.safety_level = level;
    SecurityEngine::new(config)
}

const LEVELS: [SafetyLevel; 3] = [
    SafetyLevel::Critical,
    SafetyLevel::High,
    SafetyLevel::Strict,
];

fn verdict(command: &str) -> Decision {
    engine_at(SafetyLevel::High).check_bash(command)
}

/// Denied at every safety level: rm-home is a Critical rule.
#[track_caller]
fn assert_denied_everywhere(command: &str) {
    for level in LEVELS {
        let d = engine_at(level).check_bash(command);
        assert!(
            d.is_deny(),
            "expected DENY at {level:?} for {command:?}, got {d:?}"
        );
    }
}

#[track_caller]
fn assert_allowed(command: &str) {
    let d = verdict(command);
    assert!(d.is_allow(), "expected ALLOW for {command:?}, got {d:?}");
}

// ---------------------------------------------------------------------------
// The union: main's text, and everything main denies.
// ---------------------------------------------------------------------------

fn pattern_of(rule_id: &str) -> &'static str {
    dangerous::get_rules_for_level(SafetyLevel::Strict)
        .iter()
        .find(|r| r.id == rule_id)
        .unwrap_or_else(|| panic!("no rule {rule_id}"))
        .pattern
}

#[test]
fn main_regexes_are_main_text() {
    // Recorded from `git show origin/main:src/rules/dangerous.rs`.
    let main: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/main_rm_home_patterns.json")).unwrap();
    for id in ["rm-home", "bash-c-rm-home"] {
        assert_eq!(
            pattern_of(id),
            main[id].as_str().unwrap(),
            "{id} must be main's text; the AST check is the addition"
        );
    }
}

#[test]
fn every_command_main_denies_is_still_denied() {
    // One JSON object per line: the command and main's verdict at Critical, High and
    // Strict (the rule id, or null for allow). The corpus crosses about 250 targets
    // (home spellings, subpaths, look-alikes, hidden operands) with 8 flag spellings
    // and 36 wrappers and keeps every fourth command main denies.
    let engines: Vec<SecurityEngine> = LEVELS.iter().map(|l| engine_at(*l)).collect();
    let mut checked = 0;
    for line in include_str!("../fixtures/main_denied.jsonl").lines() {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        let cmd = row["cmd"].as_str().unwrap();
        for (i, level) in LEVELS.iter().enumerate() {
            let Some(main_rule) = row["v"][i].as_str() else {
                continue;
            };
            let d = engines[i].check_bash(cmd);
            assert_eq!(
                d.rule_id(),
                Some(main_rule),
                "{level:?}: main denies {cmd:?} by {main_rule}, head says {d:?}"
            );
            checked += 1;
        }
    }
    assert!(checked > 5000, "fixture shrank: {checked} verdicts");
}

#[test]
fn main_denied_subpaths_stay_denied() {
    // Rounds 1 and 2 allowed these. Main denies them, so they stay denied: an
    // add-only change does not decide which subpaths are safe to delete.
    for cmd in [
        "rm -rf $HOME/proj",
        "rm -rf $HOME/proj/build",
        "rm -rf \"$HOME/proj/build\"",
        "rm -rf \"$HOME\"/proj/build",
        "rm -rf /home/alice/proj",
        "rm -rf /home/alice/proj/build",
        "rm -rf ~alice/proj",
        "rm -rf $HOME-old",
        "bash -c 'rm -rf $HOME/proj/build'",
        "bash -c 'rm -rf ~user/proj'",
        "echo \"rm $HOME\"",
    ] {
        assert_denied_everywhere(cmd);
    }
    // `bash-c-rm-home` is a High rule: denied at High and Strict, as on main.
    for cmd in ["bash -c 'rm -rf ~/build'", "bash -c 'rm -rf $HOMEDIR'"] {
        for level in [SafetyLevel::High, SafetyLevel::Strict] {
            let d = engine_at(level).check_bash(cmd);
            assert_eq!(
                d.rule_id(),
                Some("bash-c-rm-home"),
                "{level:?} {cmd:?}: {d:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Must deny: the home directory, in every spelling, through every wrapper.
// ---------------------------------------------------------------------------

const HOME_FORMS: &[&str] = &[
    "~",
    "~/",
    "~//",
    "~/.",
    "~/*",
    "~/.*",
    "$HOME",
    "$HOME/",
    "\"$HOME\"",
    "\"$HOME/\"",
    "${HOME}",
    "${HOME}/",
    "\"${HOME}\"",
    "/Users/alice",
    "/Users/alice/",
    "'/Users/alice'",
    "/home/alice",
    "/home/alice/",
    "$HOME/..",
    "~/..",
    "/Users/alice/..",
    "$HOME/{,}",
    "~/{build,}",
    "~/*(D)",
    "$HOME/./*",
];

const FLAGS: &[&str] = &[
    "",
    "-rf ",
    "-fr ",
    "-r -f ",
    "--recursive --force ",
    "-Rf ",
    "-rf -- ",
];

/// `{}` is the rm command line.
const WRAPPERS: &[&str] = &[
    "{}",
    "\\{}",
    "/bin/{}",
    "/usr/bin/{}",
    "command {}",
    "command -p {}",
    "builtin {}",
    "exec {}",
    "sudo {}",
    "sudo -u root {}",
    "env {}",
    "env X=1 {}",
    "nohup {}",
    "noglob {}",
    "time {}",
    "timeout 30 {}",
    "cd /tmp && {}",
    "echo `{}`",
    "echo $({})",
    "x=`{}`",
    "echo \"`{}`\"",
    "echo \"$({})\"",
    "bash -c '{}'",
    "sh -c '{}'",
    "zsh -c '{}'",
    "bash -lc '{}'",
    "bash -c -- '{}'",
    "eval '{}'",
    "{ {}; }",
    "({})",
    "if true; then {}; fi",
    "{} >/dev/null",
    "{}>/dev/null",
    "{} 2>&1",
    "{}; echo ok",
    "{} && echo ok",
    "{} | cat",
    "{} &",
    "{} # c",
];

#[test]
fn home_is_denied_through_every_wrapper() {
    let engines: Vec<SecurityEngine> = LEVELS.iter().map(|l| engine_at(*l)).collect();
    let mut checked = 0;
    for form in HOME_FORMS {
        for flags in FLAGS {
            for wrapper in WRAPPERS {
                let rm = format!("rm {flags}{form}");
                let cmd = wrapper.replace("{}", &rm);
                for (i, level) in LEVELS.iter().enumerate() {
                    let d = engines[i].check_bash(&cmd);
                    assert!(
                        d.is_deny(),
                        "{level:?}: expected DENY for {cmd:?}, got {d:?}"
                    );
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 10_000);
}

#[test]
fn the_brief_forms_through_the_brief_wrappers() {
    for target in [
        "~",
        "~/",
        "$HOME",
        "\"$HOME\"",
        "${HOME}/",
        "/Users/someone",
    ] {
        for cmd in [
            format!("rm -rf {target}"),
            format!("\\rm -rf {target}"),
            format!("/bin/rm -rf {target}"),
            format!("command rm -rf {target}"),
            format!("builtin rm -rf {target}"),
            format!("exec rm -rf {target}"),
            format!("bash -c 'rm -rf {target}'"),
            format!("sh -c 'rm -rf {target}'"),
            format!("zsh -c 'rm -rf {target}'"),
            format!("bash -lc 'rm -rf {target}'"),
            format!("echo `rm -rf {target}`"),
            format!("echo $(rm -rf {target})"),
        ] {
            assert_denied_everywhere(&cmd);
        }
    }
}

#[test]
fn quoted_and_escaped_spellings_of_the_command_and_target_are_decoded() {
    for cmd in [
        "\"rm\" -rf ~",
        "'rm' -rf ~",
        "r\\m -rf ~",
        "r\"\"m -rf ~",
        "$'rm' -rf ~",
        "bash -c '\"rm\" -rf ~'",
        "bash -c 'r\\m -rf $HOME'",
        "eval '\"rm\" -rf ~'",
        "rm -rf $'/home/alice/'",
        "rm -rf $'\\x2fUsers/alice/'",
        "rm -rf $HOME/$'..'/*",
        "rm -rf $HOME/$'\\x2e\\x2e'/*",
        "rm -rf ~/$'..'",
        "rm -rf \"$HOME\"/'..'/*",
        "rm -rf $HOME\"\"",
        "rm -rf $HOME\\/",
        "rm -rf \"\"$HOME",
        "rm -rf \"$HOME\"''/",
        "rm -rf ~/\"..\"",
        "rm -rf ~/'..'",
        "rm -rf ~/\\.\\.",
    ] {
        assert_denied_everywhere(cmd);
    }
}

#[test]
fn literal_tilde_in_the_wrong_quotes_is_not_the_home() {
    // `$'~'` and `'~'` are the literal text, a relative file name.
    for cmd in ["rm -rf '~'", "rm -rf $'~'", "rm -rf \"~\"", "rm -rf \\~"] {
        assert_allowed(cmd);
    }
}

// ---------------------------------------------------------------------------
// Round 1 of PR #2 (qa-gate-ruff2 and Codex), all denied.
// ---------------------------------------------------------------------------

#[test]
fn round1_rows_stay_denied() {
    for cmd in [
        // P1-1 backticks
        "echo `rm -rf $HOME`",
        "echo `rm -rf \"$HOME\"`",
        "echo `rm -rf ~`",
        "echo `rm -rf ~/`",
        "echo `rm -rf ${HOME}`",
        "echo `rm -rf /Users/someone`",
        "bash -c 'echo `rm -rf ~`'",
        // P1-2 dot-dot
        "rm -rf $HOME/..",
        "rm -rf /home/x/..",
        "rm -rf $HOME/build/..",
        "rm -rf $HOME/build/../..",
        "rm -rf ~/..",
        "rm -rf ~/build/..",
        "rm -rf /Users/lee/..",
        "rm -rf /Users/lee/../lee",
        "bash -c 'rm -rf ~/..'",
        // P1-3 quoted earlier operand
        "rm -rf 'old|backup' ~",
        "rm -rf 'old|backup' ~/",
        "rm -rf 'old|backup' ~/*",
        "rm -rf 'old|backup' $HOME",
        "rm -rf 'old|backup' ${HOME}",
        "rm -rf 'old|backup' /home/alice",
        "rm -rf 'old|backup' /Users/alice",
        "rm -rf 'a;b' ~",
        "rm -rf \"a&b\" ~",
        "rm -rf 'a)b' ~",
        "rm -rf a\\;b ~",
        "rm -rf a\\|b ~",
        "bash -c 'rm -rf \"a|b\" ~'",
        // P2-1 braces and dot globs
        "rm -rf $HOME/{*,.*}",
        "rm -rf ~/{*,.*}",
        "rm -rf ~/.[!.]*",
        "rm -rf ~/.[^.]*",
        "rm -rf ~/..?*",
        "rm -rf ~/.??*",
    ] {
        assert_denied_everywhere(cmd);
    }
}

// ---------------------------------------------------------------------------
// Round 2 of PR #2: ruff3's classes and Codex's round-2 list.
// ---------------------------------------------------------------------------

/// ruff3 P1-A: an earlier substitution hides the home operand.
#[test]
fn round2_earlier_substitution_operand() {
    for cmd in [
        "rm -rf `printf old` $HOME",
        "rm -rf `mktemp` ~",
        "rm -rf `mktemp -d` ~",
        "rm -rf x`printf old` /Users/alice",
        "bash -c 'rm -rf `printf old` $HOME'",
        "bash -c 'rm -rf `printf old` ~'",
        "rm -rf $(printf old) ${HOME}",
        "rm -rf $(mktemp -d) ~",
        "rm -rf $(printf old)x ~",
        "rm -rf <(true) ~",
        "bash -c 'rm -rf $(printf old) ${HOME}'",
    ] {
        assert_denied_everywhere(cmd);
    }
}

/// ruff3 P1-B: a brace with an empty arm gives back the home itself.
#[test]
fn round2_brace_with_an_empty_arm() {
    for cmd in [
        "rm -rf $HOME/{,}",
        "rm -rf $HOME{,}",
        "rm -rf $HOME/{build,}",
        "rm -rf $HOME/{build,dist,}",
        "rm -rf $HOME/{,build}",
        "rm -rf \"$HOME\"/{,}",
        "rm -rf \"$HOME\"{,/}",
        "rm -rf \"$HOME/\"{,}",
        "bash -c 'rm -rf $HOME/{,}'",
        "rm -rf ~/{,}",
        "rm -rf ~{,}",
        "rm -rf ~/{build,}",
        "rm -rf ~/{build,dist,}",
        "rm -rf ~/{.,}",
        "rm -rf /Users/lee/{build,}",
        "rm -rf /home/x{,}",
        "rm -rf ~/{a,{b,}}",
    ] {
        assert_denied_everywhere(cmd);
    }
}

/// ruff3 P1-C: a redirection with no space before it, top level and inside `-c`.
#[test]
fn round2_redirection_without_a_space() {
    for cmd in [
        "bash -c 'rm -rf $HOME>/dev/null'",
        "bash -c 'rm -rf $HOME>/dev/null 2>&1'",
        "eval 'rm -rf /home/x>/dev/null'",
        "bash -c 'rm -rf ~/>/dev/null'",
        "bash -c 'rm -rf ~/*>/dev/null'",
        "rm -rf $HOME>/dev/null",
        "rm -rf ~>/dev/null",
        "rm -rf ~/>/dev/null",
        "rm -rf ~<in",
        "rm -rf ~>>log",
        "rm -rf /Users/lee>/dev/null",
        "rm -rf ${HOME}/</dev/null",
        "rm -rf /Users/alice/<<EOF\nEOF",
    ] {
        assert_denied_everywhere(cmd);
    }
}

/// ruff3 P2-a: other globs for all of the contents.
#[test]
fn round2_other_content_globs() {
    for cmd in [
        "rm -rf $HOME/./*",
        "rm -rf $HOME/?*",
        "rm -rf $HOME/**/*",
        "rm -rf $HOME/*(D)",
        "bash -c 'rm -rf $HOME/./*'",
        "bash -c 'rm -rf $HOME/?*'",
        "rm -rf ~/./*",
        "rm -rf ${HOME}/././*",
        "rm -rf ~/?*",
        "rm -rf ~/[!.]*",
        "rm -rf ~/[^.]*",
        "rm -rf ~/*(D)",
        "rm -rf ~/*(D)/",
        "rm -rf ~/*(N)",
        "rm -rf ~/**(D)",
        "rm -rf ~/{*,{.[!.]*,..?*}}",
        "rm -rf ~/**/*",
    ] {
        assert_denied_everywhere(cmd);
    }
}

/// ruff3 P2-b: an escaped quote in an earlier operand.
#[test]
fn round2_escaped_quote_in_an_earlier_operand() {
    for cmd in [
        "rm -rf \"a\\\"b\" $HOME",
        "rm -rf \"a\\\"b\" ~",
        "rm -rf $'a\\'b' ${HOME}",
        "bash -c 'rm -rf \"a\\\"b\" $HOME'",
        "rm -rf \"a\\\"|b\" ~",
        "rm -rf \"a\\\"b;c\" ~",
        "rm -rf \"a\\\"|b\" $HOME",
        "rm -rf $'a\\'|b' ~",
    ] {
        assert_denied_everywhere(cmd);
    }
}

/// ruff3 P2-c: a suffix joined to the home name, ANSI-C parts, `""` inside `-c`.
#[test]
fn round2_suffix_ansi_c_and_empty_quotes() {
    for cmd in [
        "rm -rf $HOME$(true)",
        "rm -rf $HOME$x",
        "rm -rf $HOME${x}",
        "bash -c 'rm -rf $HOME$(true)'",
        "rm -rf $HOME`true`",
        "rm -rf $HOME/$'..'/*",
        "rm -rf $HOME/$'\\x2e\\x2e'/*",
        "rm -rf $'/home/alice/'",
        "rm -rf $'\\x2fUsers/alice/'",
        "rm -rf ~/$'..'",
        "bash -c 'rm -rf $HOME\"\"'",
        "bash -c 'rm -rf $HOME\"/\"'",
        "eval 'rm -rf $HOME\"\"'",
        "zsh -c 'rm -rf $HOME\"\"'",
        "bash -c -- 'rm -rf $HOME\"\"'",
        "rm -rf $HOME\"\"",
        "rm -rf $HOME\\/",
        "rm -rf \"$HOME\"/'..'/*",
        "rm -rf \"\"$HOME",
        "rm -rf \"$HOME\"''/",
    ] {
        assert_denied_everywhere(cmd);
    }
}

/// ruff3 P2-d: a quoted segment with a space, then `..`.
#[test]
fn round2_quoted_segment_with_a_space() {
    for cmd in [
        "rm -rf \"$HOME/a b/../\"*",
        "rm -rf \"$HOME/a;b/../\"*",
        "rm -rf ~/\"a b\"/..",
        "bash -c 'rm -rf \"$HOME/a b/../\"*'",
        "rm -rf \"/Users/Alice Smith/\"",
        "rm -rf \"/Users/Alice Smith\"",
        "rm -rf /Users/Alice\\ Smith",
        "rm -rf '/home/alice;smith/'",
    ] {
        assert_denied_everywhere(cmd);
    }
}

/// ruff3 P2-e and Codex class 7: heredoc bodies, outer quoting layers, a substitution.
#[test]
fn round2_heredoc_and_outer_quoting_layers() {
    for cmd in [
        "sh <<EOF\nrm -rf 'a|b' ~\nEOF",
        "sh <<EOF\nrm -rf ~\nEOF",
        "bash <<'EOF'\nrm -rf $HOME\nEOF",
        "bash <<< 'rm -rf ~'",
        "sh <<EOF\nrm -rf \\\"\\$HOME\\\"\nEOF",
        "bash -c \"rm -rf \\\"\\$HOME\\\"\"",
        "bash -c \"rm -rf \\\"\\$HOME\\\"/\"",
        "rm -rf \"$(echo ~)\"",
        "rm -rf $(echo $HOME)",
        "bash -c 'echo ready\nrm -rf ~'",
        "bash -c 'echo ready; rm -rf ~'",
        "ssh host 'x' ; rm -rf ~",
    ] {
        assert_denied_everywhere(cmd);
    }
}

#[test]
fn find_exec_xargs_and_other_wrappers_of_rm() {
    for cmd in [
        "find /tmp -exec rm -rf ~ {} \\;",
        "find /tmp -execdir rm -rf $HOME {} +",
        "xargs rm -rf ~",
        "xargs -n1 rm -rf $HOME",
        "nice -n 5 rm -rf ~",
        "nice rm -rf ~",
        "ionice -c3 rm -rf ~",
        "doas rm -rf ~",
        "stdbuf -oL rm -rf ~",
        "env -u X rm -rf ~",
        "env -S 'rm -rf ~'",
        "repeat 2 rm -rf ~",
        "nocorrect rm -rf ~",
        "- rm -rf ~",
        "su -c 'rm -rf ~'",
        "sudo -- rm -rf ~",
        "grm -rf ~",
    ] {
        assert_denied_everywhere(cmd);
    }
}

// ---------------------------------------------------------------------------
// Not a deny: what is neither the home folder nor above it.
// ---------------------------------------------------------------------------

#[test]
fn plain_paths_below_home_and_harmless_text_stay_allowed() {
    // Main allows each of these. They are not home, so the AST check adds nothing.
    for cmd in [
        "rm -rf ./node_modules",
        "rm file.txt",
        "rm -rf ~/proj/build",
        "rm -rf ~/proj",
        "rm -rf ~/.cache/x",
        "rm -rf ~/*.txt",
        "rm -rf ~/.*rc",
        "rm -rf ~/..foo",
        "rm -rf ~/.../x",
        "rm ~/old.txt",
        "rm -rf /Users/alice/proj/build",
        "rm -rf /Users/alice/proj/*",
        "rm -rf /tmp/x",
        "rm -rf ~/{a,b}",
        "rm -rf ~/{*.txt,*.log}",
        "rm -rf ~/build/{*,.*}",
        "rm -rf ~/.[!.]*rc",
        "rm -rf ~+",
        "echo \"never rm ~\"",
        "git commit -m \"docs: warn about rm -rf ~\"",
        "echo 'rm -rf ~'",
        "echo `ls ~/proj`",
        "bash -c 'echo ok'",
        "ls ~",
        "cd ~ && ls",
    ] {
        assert_allowed(cmd);
    }
}

#[test]
fn rm_home_is_a_critical_rule() {
    // The AST check applies at every level, as the regexes do.
    let engine = engine_at(SafetyLevel::Critical);
    for cmd in [
        "rm -rf ~",
        "rm -rf ~/",
        "rm -rf $HOME",
        "rm -rf /Users/someone",
        "bash -c 'rm -rf ~'",
    ] {
        let d = engine.check_bash(cmd);
        assert!(d.is_deny(), "{cmd:?}: {d:?}");
    }
    assert!(engine.check_bash("rm -rf ~/proj/build").is_allow());
}

#[test]
fn deny_reason_names_the_rule() {
    let d = verdict("rm -rf ~");
    assert_eq!(d.rule_id(), Some("rm-home"), "{d:?}");
    let d = verdict("rm -rf ~/{,}");
    assert_eq!(d.rule_id(), Some("rm-home"), "{d:?}");
}

// ---------------------------------------------------------------------------
// dd-disk-device: the nvme fix stays.
// ---------------------------------------------------------------------------

#[test]
fn dd_nvme_devices_are_denied_and_images_are_not() {
    for cmd in [
        "dd if=/dev/zero of=/dev/nvme0n1",
        "dd if=/dev/zero of=/dev/nvme10n2p3",
        "dd if=/dev/zero of=/dev/sda",
    ] {
        assert_denied_everywhere(cmd);
    }
    assert_allowed("dd if=/dev/zero of=/tmp/image");
    assert_allowed("dd if=/dev/zero of=/dev/null");
}
