//! steward-l8b3: rm-home and bash-c-rm-home.
//!
//! `rm-home` is a Critical rule: it must match the home directory itself and all its
//! contents, in every spelling, and must not match a real subpath such as
//! `~/proj/build` (a false Critical block costs more than it saves).
//!
//! Each form is tested both ways: the rule fires, and it does not fire on the
//! neighbouring subpath or look-alike name.

use claude_guardrails::{Config, Decision, SafetyLevel, SecurityEngine};

fn engine_at(level: SafetyLevel) -> SecurityEngine {
    let mut config = Config::default();
    config.general.safety_level = level;
    SecurityEngine::new(config)
}

fn verdict(command: &str) -> Decision {
    engine_at(SafetyLevel::High).check_bash(command)
}

#[track_caller]
fn assert_rule(command: &str, rule_id: &str) {
    let d = verdict(command);
    assert!(d.is_deny(), "expected DENY by {rule_id} for {command:?}, got {d:?}");
    assert_eq!(d.rule_id(), Some(rule_id), "wrong rule for {command:?}: {d:?}");
}

/// Not denied by `rm-home` or `bash-c-rm-home`. Other rules are not the subject here.
#[track_caller]
fn assert_not_home_rule(command: &str) {
    let d = verdict(command);
    assert!(
        !matches!(d.rule_id(), Some("rm-home") | Some("bash-c-rm-home")),
        "{command:?} must not be a home-directory deny, got {d:?}"
    );
}

#[track_caller]
fn assert_allowed(command: &str) {
    let d = verdict(command);
    assert!(d.is_allow(), "expected ALLOW for {command:?}, got {d:?}");
}

// ---------------------------------------------------------------------------
// rm-home: the home directory and all its contents
// ---------------------------------------------------------------------------

#[test]
fn tilde_forms_match() {
    for cmd in [
        "rm -rf ~",
        "rm -rf ~/",
        "rm -rf ~/*",
        "rm -r ~",
        "rm -fr ~/",
        "rm ~",
        "rm -rf ~root",
    ] {
        assert_rule(cmd, "rm-home");
    }
}

#[test]
fn home_variable_forms_match() {
    for cmd in [
        "rm -rf $HOME",
        "rm -rf $HOME/",
        "rm -rf $HOME/*",
        "rm -rf ${HOME}",
        "rm -rf ${HOME}/",
        "rm -rf ${HOME}/*",
        "rm -rf \"$HOME\"",
        "rm -rf \"$HOME/\"",
        "rm -rf \"$HOME/*\"",
        "rm -rf \"$HOME\"/",
        "rm -rf \"$HOME\"/*",
        "rm -rf \"${HOME}\"",
        "rm -rf \"${HOME}/\"",
    ] {
        assert_rule(cmd, "rm-home");
    }
}

#[test]
fn absolute_home_forms_match() {
    for cmd in [
        "rm -rf /home/someone",
        "rm -rf /home/someone/",
        "rm -rf /home/someone/*",
        "rm -rf /Users/someone",
        "rm -rf /Users/someone/",
        "rm -rf /Users/someone/*",
        "rm -rf \"/Users/someone\"",
        "rm -rf '/Users/someone/'",
        "rm -rf \"/home/someone/\"",
    ] {
        assert_rule(cmd, "rm-home");
    }
}

#[test]
fn each_form_is_followed_by_a_terminator() {
    // End of line, whitespace, ; & | or ).
    for cmd in [
        "rm -rf ~\n",
        "rm -rf ~ ",
        "rm -rf ~ other",
        "rm -rf ~; ls",
        "rm -rf ~;",
        "rm -rf ~ && ls",
        "rm -rf ~&& ls",
        "rm -rf ~ & ls",
        "rm -rf ~ | cat",
        "rm -rf ~| cat",
        "(rm -rf ~)",
        "rm -rf $HOME;ls",
        "rm -rf $HOME)",
        "rm -rf ${HOME}|cat",
        "rm -rf /Users/someone&ls",
    ] {
        assert_rule(cmd, "rm-home");
    }
}

#[test]
fn flag_spellings_and_wrappers_match() {
    for cmd in [
        "rm -Rf ~",
        "rm -rfv ~/",
        "rm -r -f ~",
        "rm --recursive --force ~",
        "rm -rf -- ~",
        "rm -rf --no-preserve-root ~",
        "sudo rm -rf ~",
        "/bin/rm -rf ~",
        "timeout 30 rm -rf ~",
        "cd /tmp && rm -rf ~",
    ] {
        assert_rule(cmd, "rm-home");
    }
}

#[test]
fn home_as_a_later_operand_matches() {
    // The home directory is deleted whichever operand names it.
    assert_rule("rm -rf build ~", "rm-home");
    assert_rule("rm -rf ./a ./b $HOME/", "rm-home");
    assert_rule("rm -rf ~/proj ~", "rm-home");
}

#[test]
fn real_subpaths_do_not_match() {
    for cmd in [
        "rm -rf ~/proj/build",
        "rm -rf ~/proj",
        "rm -rf ~/proj/",
        "rm -rf ~/.cache/x",
        "rm -rf ~/proj/*",
        "rm -rf ~user/proj",
        "rm -rf $HOME/proj/build",
        "rm -rf $HOME/proj/*",
        "rm -rf ${HOME}/proj/build",
        "rm -rf \"$HOME/proj/build\"",
        "rm -rf \"$HOME\"/proj/build",
        "rm -rf /Users/someone/proj/build",
        "rm -rf /home/someone/proj/build",
        "rm -rf /Users/someone/proj/*",
        "rm ~/old.txt",
        "rm ~/proj/a.txt ~/proj/b.txt",
    ] {
        assert_not_home_rule(cmd);
    }
}

#[test]
fn look_alike_names_do_not_match() {
    for cmd in [
        "rm -rf $HOME_BACKUP",
        "rm -rf $HOMEDIR",
        "rm -rf ${HOME}_old",
        "rm -rf ~~",
        "rm -rf /Users",
        "rm -rf /home",
        "rm -rf /Users/",
        "rm -rf /homework/x",
        "rm -rf $HOMES",
    ] {
        assert_not_home_rule(cmd);
    }
}

#[test]
fn quoted_tilde_and_single_quoted_variable_are_literal_names() {
    // The shell does not expand these, so they do not name the home directory.
    for cmd in ["rm -rf \"~\"", "rm -rf '~'", "rm -rf '$HOME'", "rm -rf \"~/\""] {
        assert_not_home_rule(cmd);
    }
}

#[test]
fn prose_mentioning_rm_and_home_in_quotes_does_not_match() {
    // The word after the name is a quote, not a terminator.
    for cmd in [
        "echo \"never rm $HOME\"",
        "echo \"never rm ~\"",
        "git commit -m \"docs: warn about rm ~\"",
    ] {
        assert_not_home_rule(cmd);
    }
}

#[test]
fn safe_rm_still_allowed() {
    assert_allowed("rm -rf ./node_modules");
    assert_allowed("rm file.txt");
    assert_allowed("rm -rf ~/proj/build");
    assert_allowed("rm -rf $HOME/proj/build");
}

#[test]
fn rm_home_is_a_critical_rule() {
    // Active at every level, including Critical.
    let engine = engine_at(SafetyLevel::Critical);
    for cmd in ["rm -rf ~", "rm -rf ~/", "rm -rf $HOME", "rm -rf /Users/someone"] {
        let d = engine.check_bash(cmd);
        assert_eq!(d.rule_id(), Some("rm-home"), "{cmd:?}: {d:?}");
    }
    assert!(engine.check_bash("rm -rf ~/proj/build").is_allow());
}

// ---------------------------------------------------------------------------
// bash-c-rm-home: the same rule inside `sh -c '...'`
// ---------------------------------------------------------------------------

#[test]
fn bash_c_home_forms_match() {
    for cmd in [
        "bash -c 'rm -rf ~'",
        "bash -c 'rm -rf ~/'",
        "bash -c 'rm -rf ~/*'",
        "sh -c \"rm -rf $HOME\"",
        "sh -c 'rm -rf $HOME/'",
        "bash -c 'rm -rf ${HOME}'",
        "bash -c 'rm -rf ${HOME}/*'",
        "bash -c 'cd /tmp && rm -rf ~'",
        "bash -c 'echo hi; rm -rf ~; echo done'",
        "bash -c 'rm -rf /Users/someone'",
        "bash -c 'rm -rf /home/someone/'",
        "bash -c 'rm -Rf ~'",
    ] {
        let d = verdict(cmd);
        assert!(d.is_deny(), "expected DENY for {cmd:?}, got {d:?}");
        assert_eq!(d.rule_id(), Some("bash-c-rm-home"), "{cmd:?}: {d:?}");
    }
}

#[test]
fn bash_c_subpaths_and_look_alikes_do_not_match() {
    for cmd in [
        "bash -c 'rm -rf ~/proj/build'",
        "bash -c 'rm -rf $HOME/proj/build'",
        "bash -c 'rm -rf ${HOME}/proj'",
        "bash -c 'rm -rf $HOME_BACKUP'",
        "bash -c 'rm -rf ~user/proj'",
        "bash -c 'rm ~/old.txt'",
        "bash -c 'rm -rf ./build'",
        "sh -c \"rm -rf /Users/someone/proj\"",
    ] {
        assert_not_home_rule(cmd);
    }
}

#[test]
fn bash_c_harmless_text_does_not_match() {
    // The old rule had no end anchor: any text after `rm ~` or `rm $HOME` matched.
    for cmd in [
        "bash -c 'echo \"see rm -rf ~/docs for details\"'",
        "bash -c 'echo rm $HOMEDIR'",
        "bash -c 'grep -n \"rm $HOME_X\" notes.txt'",
        "bash -c 'echo ok'",
        "bash -c 'printf \"%s\" \"rm ~/x\"'",
    ] {
        assert_not_home_rule(cmd);
    }
}

#[test]
fn bash_c_rm_home_at_critical_level_follows_the_rule_level() {
    // bash-c-rm-home is a High rule: Critical does not run it.
    let engine = engine_at(SafetyLevel::Critical);
    assert!(engine.check_bash("bash -c 'rm -rf ~'").is_allow());
    let engine = engine_at(SafetyLevel::High);
    assert_eq!(
        engine.check_bash("bash -c 'rm -rf ~'").rule_id(),
        Some("bash-c-rm-home")
    );
}
