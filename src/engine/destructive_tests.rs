//! Destructive git and recursive deletes, end to end through `SecurityEngine::check_bash`.
//!
//! Each `blocks_*` list was red before `rules::destructive` existed; the `passes_*` lists
//! are everyday commands that must stay allowed.

use super::SecurityEngine;
use crate::config::Config;
use crate::output::Decision;

fn decide(command: &str) -> Decision {
    SecurityEngine::new(Config::default()).check_bash(command)
}

fn assert_blocked(cases: &[&str], rule: &str) {
    for c in cases {
        match decide(c) {
            Decision::Deny { rule_id, .. } => {
                assert_eq!(rule_id, rule, "{c}: denied by {rule_id}, expected {rule}")
            }
            other => panic!("{c}: expected deny by {rule}, got {other:?}"),
        }
    }
}

fn assert_passes(cases: &[&str]) {
    for c in cases {
        let d = decide(c);
        assert!(d.is_allow(), "{c}: expected allow, got {d:?}");
    }
}

#[test]
fn blocks_git_reset_hard_behind_global_options() {
    assert_blocked(
        &[
            "git -C /some/repo reset --hard origin/main",
            "git -c color.ui=never reset --hard",
        ],
        "git-reset-hard",
    );
}

#[test]
fn blocks_git_clean_force_in_every_spelling() {
    assert_blocked(
        &[
            "git clean -xf",
            "git clean --force",
            "git -C repo clean -f -d",
        ],
        "git-clean-force",
    );
}

#[test]
fn blocks_git_discarding_uncommitted_work() {
    assert_blocked(
        &[
            "git checkout -- .",
            "git checkout -- src/main.rs",
            "git checkout HEAD -- .",
            "git checkout .",
            "git checkout -f main",
            "git checkout feature/x -- docs/plan.md",
            "git restore .",
            "git restore src/main.rs",
            "git restore --worktree --staged .",
            "git restore -SW .",
            "git switch --discard-changes main",
            "git switch -f main",
            "git stash drop",
            "git stash drop stash@{1}",
            "git stash clear",
            "git branch -D feature/x",
            "git branch --delete --force feature/x",
            "git branch -df feature/x",
            "git worktree remove --force .worktrees/x",
            "git worktree remove -f .worktrees/x",
            "true && git checkout -- .",
        ],
        "git-discard",
    );
}

#[test]
fn blocks_every_force_push() {
    assert_blocked(
        &[
            "git push --force origin feature/x",
            "git push -f",
            "git push -fu origin feature/x",
            "git push origin +main",
            "git push origin +HEAD:feature/x",
            "git push --force-with-lease origin feature/x",
            "git push --force-with-lease=feature/x:abc123 origin feature/x",
            "git push --force-with-lease",
            "git push --force-if-includes origin feature/x",
            "git push --mirror",
        ],
        "git-force-push",
    );
}

#[test]
fn blocks_history_rewrite() {
    assert_blocked(
        &[
            "git filter-branch --tree-filter 'rm -f secrets.txt' HEAD",
            "git filter-repo --path secrets.txt --invert-paths",
            "git reflog expire --expire=now --all",
            "git reflog delete HEAD@{1}",
            "git update-ref -d refs/heads/main",
            "git rebase -i HEAD~3",
            "git rebase --interactive main",
        ],
        "git-history-rewrite",
    );
}

#[test]
fn blocks_turning_hooks_off() {
    assert_blocked(
        &[
            "git commit --no-verify -m wip",
            "git commit -nm wip",
            "git commit -a -n -m wip",
            "git push --no-verify",
            "git merge --no-verify feature/x",
            "git -c core.hooksPath=/dev/null commit -m wip",
            "git -c core.hookspath=/tmp/none commit -m wip",
            "git config core.hooksPath /dev/null",
            "git config --global core.hooksPath /dev/null",
            "git config set core.hooksPath /dev/null",
            "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null git commit -m x",
        ],
        "git-hooks-off",
    );
}

#[test]
fn blocks_recursive_delete_outside_temp_and_build_output() {
    assert_blocked(
        &[
            "rm -rf ~/Projects/foo",
            "rm -rf ../other-repo",
            "rm -rf .",
            "rm -rf *",
            "rm -rf .git",
            "rm -rf src",
            "rm -fr src",
            "rm -r -f src",
            "rm -r src",
            "rm -R src",
            "rm --recursive --force src",
            "rm -rf -- src",
            "/bin/rm -rf src",
            "rm -rf /Users/someone/Projects",
            "rm -rf build/../src",
            "rm -rf .worktrees/x",
            "rm -rf dist/*",
            "rm -rf /tmp/*",
            "rm -rf ~",
            "rm -rf $TMPDIR",
            "find . -type d -exec rm -rf {} +",
            "ls -d */ | xargs rm -rf",
        ],
        "rm-recursive",
    );
}

#[test]
fn blocks_destructive_commands_inside_wrappers_and_shells() {
    assert_blocked(&["bash -c 'git checkout -- .'"], "git-discard");
    assert_blocked(&["sh -lc 'rm -rf src'"], "rm-recursive");
    assert_blocked(&["eval 'git stash clear'"], "git-discard");
    assert_blocked(
        &["sudo -u lee git push --force origin feature/x"],
        "git-force-push",
    );
    assert_blocked(&["env GIT_DIR=/x/.git git checkout -- ."], "git-discard");
    assert_blocked(&["(cd repo && rm -rf src)"], "rm-recursive");
    assert_blocked(&["timeout 5 git restore ."], "git-discard");
    assert_blocked(&["command rm -rf src", "\\rm -rf src"], "rm-recursive");
    assert_blocked(&["git status\ngit stash clear"], "git-discard");
}

#[test]
fn passes_everyday_git() {
    assert_passes(&[
        "git status",
        "git diff --stat",
        "git log --oneline -5",
        "git add src/main.rs",
        "git commit -m \"fix: handle empty input\"",
        "git commit -am 'wip on the parser'",
        "git push -u origin HEAD",
        "git push origin feature/x",
        "git push -n origin feature/x",
        "git pull --rebase",
        "git fetch origin pull/108/head",
        "git checkout main",
        "git checkout -b feat/x origin/main",
        "git checkout --theirs -- conflicted.txt",
        "git switch -c feat/x",
        "git restore --staged src/main.rs",
        "git restore --staged --source=HEAD~1 src/main.rs",
        "git stash",
        "git stash push -m 'drop this later'",
        "git stash pop",
        "git stash list",
        "git branch -d merged-branch",
        "git branch -m old new",
        "git rebase main",
        "git worktree add .worktrees/x -b feat/x",
        "git worktree remove .worktrees/x",
        "git worktree prune",
        "git -C /some/repo worktree remove --force /private/tmp/claude-501/s/wt",
        "git merge --ff-only origin/main",
        "git cherry-pick abc123",
        "git revert abc123",
        "git reset HEAD~1",
        "git reset --soft HEAD~1",
        "git clean -n",
        "git tag v1.0",
        "git show HEAD",
        "git config --get core.hooksPath",
        "git config core.hooksPath",
        "git config --unset core.hooksPath",
        "git config user.name t",
        "git log --grep='checkout -- .'",
        "gh pr merge 5 --squash --match-head-commit abc123",
    ]);
}

#[test]
fn passes_destructive_words_as_data() {
    assert_passes(&[
        "git commit -m \"docs: say why git checkout -- . is blocked\"",
        "git commit -m 'note: rm -rf src would be blocked'",
        "fleetmail send --to Adama --subject 'git push --force-with-lease is blocked now' --body-file m.md",
        "gh pr create --title 'Block git stash clear' --body-file body.md",
        "grep -rn 'checkout -- .' docs/",
        "rg 'rm -rf src' .",
        "echo 'never run git branch -D main'",
    ]);
}

#[test]
fn passes_everyday_deletes() {
    assert_passes(&[
        "rm file.txt",
        "rm -f file.txt",
        "rm -rf node_modules",
        "rm -rf frontend/node_modules",
        "rm -rf ./dist/",
        "rm -rf target",
        "rm -rf build",
        "rm -rf .venv __pycache__ .pytest_cache",
        "rm -rf /tmp/scratch-dir",
        "rm -r /tmp/x",
        "rm -rf /private/tmp/claude-501/session/scratchpad/x",
        "rm -rf \"$TMPDIR/ccc-test.abc\"",
        "rm -rf ${TMPDIR}/build.abc",
        "find . -name '*.orig' -delete",
        "find . -type f -exec rm {} +",
        "cargo clean",
        "mkdir -p build && cd build",
    ]);
}

#[test]
fn passes_temp_targets_named_through_variables() {
    assert_passes(&[
        "S=/private/tmp/claude-501/x/scratchpad; rm -rf $S/sol389 && mkdir -p $S/sol389",
        "T=/private/tmp/claude-501/x366 && rm -rf $T && mkdir -p $T/main",
        "S=/tmp/s; H=$S/fakehome; rm -rf $H; mkdir -p $H/.claude",
        "export B=/tmp/b; rm -rf \"$B\"",
        "S=/tmp/s; rm -rf \"${S}/out\"",
        "S=/tmp/s; git -C $S/clone checkout -q -- .",
        "git -C /private/tmp/s/clone checkout -- src/cli.rs",
        "C=/tmp/s/clone; git -C $C -c core.hooksPath=/dev/null fetch -q origin",
    ]);
}

#[test]
fn blocks_what_variables_and_temp_clones_do_not_excuse() {
    assert_blocked(
        &[
            "S=/Users/someone; rm -rf $S/x",
            "VAR=/tmp/x rm -rf $VAR",
            "S=/tmp/s; bash -c 'rm -rf $S/y'",
            "rm -rf $UNSET/y",
        ],
        "rm-recursive",
    );
    assert_blocked(
        &[
            "git -C /tmp/clone push --force origin feature/x",
            "S=/tmp/s; git -C $S push -f",
        ],
        "git-force-push",
    );
    assert_blocked(
        &["git -C /tmp/clone -c core.hooksPath=/dev/null push origin x"],
        "git-hooks-off",
    );
    assert_blocked(
        &[
            "git -C /tmp/../Users/x/repo checkout -- .",
            "git -C /Users/x/repo checkout -- .",
        ],
        "git-discard",
    );
}

#[test]
fn long_command_lists_stay_linear() {
    // Rescanning the whole command once per AST command was quadratic: 5000 statements ran past
    // the hook's 5 s timeout in a release build, and a hook that times out lets the command run.
    let cmd = vec!["S=/tmp/x; ls $S/y"; 3000].join("; ");
    let t = std::time::Instant::now();
    assert!(decide(&cmd).is_allow());
    let took = t.elapsed();
    assert!(took < std::time::Duration::from_secs(3), "took {took:?}");
}
