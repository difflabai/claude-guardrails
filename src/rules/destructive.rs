//! Destructive git commands and recursive deletes
//!
//! Like `secret_read`, this works on TOKENS, not text: a command is a violation when its own
//! program and arguments ask for the destructive action. `git -C repo checkout -- .` is one;
//! `git commit -m "explain git checkout -- ."` is not, because there the words are one
//! message argument of `git commit`.
//!
//! Covers: git commands that throw away uncommitted work (reset --hard, clean -f, checkout or
//! restore of paths, switch --discard-changes, stash drop/clear, branch -D, worktree remove
//! --force), every kind of force push, history rewrites, turning git hooks off, and recursive
//! `rm` of anything but a temp dir or regenerable build output. The regex rules in
//! `dangerous.rs` still run as well.
//!
//! Limits (not covered): git aliases, `git checkout <path>` without `--` (a path and a branch
//! name look the same as tokens), commands inside a script file or a substitution the AST does
//! not hand over, `ssh host <command>`, shells nested deeper than 3, and variables set where
//! the text does not show it (a sourced file, a function defined earlier, `eval "$x"`, the
//! environment the command starts with).

use std::collections::{HashMap, HashSet};

use crate::rules::secret_read::{
    basename, is_duration, split_unquoted_ends, wrapper_valued_options, PartEnd, SEPARATORS, SHELLS,
};

/// A matched rule: its id (for packs, audit and allow-once) and the reason shown to the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hit {
    pub id: &'static str,
    pub reason: &'static str,
}

const RESET_HARD: Hit = Hit {
    id: "git-reset-hard",
    reason: "git reset --hard throws away uncommitted changes. Commit or stash first; \
             git reset --soft or --mixed keeps the work.",
};
const CLEAN_FORCE: Hit = Hit {
    id: "git-clean-force",
    reason: "git clean -f deletes untracked files. Run git clean -n to list them, \
             then delete the named files.",
};
const CHECKOUT_PATHS: Hit = Hit {
    id: "git-discard",
    reason: "git checkout of paths (-- <path>, ., -f) overwrites uncommitted changes. \
             Commit or stash first. In a scratch clone under a temp dir, use git -C <clone>.",
};
const RESTORE_WORKTREE: Hit = Hit {
    id: "git-discard",
    reason: "git restore of the working tree throws away uncommitted changes. \
             git restore --staged <path> only unstages. In a scratch clone under a temp dir, \
             use git -C <clone>.",
};
const SWITCH_DISCARD: Hit = Hit {
    id: "git-discard",
    reason: "git switch --discard-changes or -f throws away uncommitted changes. \
             Commit or stash first.",
};
const STASH_DELETE: Hit = Hit {
    id: "git-discard",
    reason: "git stash drop or clear deletes stashed work. Keep the stash, or ask a human.",
};
const BRANCH_FORCE_DELETE: Hit = Hit {
    id: "git-discard",
    reason: "git branch -D deletes a branch even when it is not merged. \
             Use git branch -d, which refuses to delete unmerged work.",
};
const WORKTREE_FORCE_REMOVE: Hit = Hit {
    id: "git-discard",
    reason: "git worktree remove --force deletes a worktree with uncommitted changes. \
             Commit there first, then remove it without --force.",
};
const FORCE_PUSH: Hit = Hit {
    id: "git-force-push",
    reason: "Force push (-f, --force, --force-with-lease, --force-if-includes, +refspec, \
             --mirror) rewrites history on the remote. Push to a new branch instead.",
};
const HISTORY_REWRITE: Hit = Hit {
    id: "git-history-rewrite",
    reason: "Rewrites or deletes history (filter-branch, filter-repo, rebase -i, \
             reflog expire/delete, update-ref -d). Ask a human first.",
};
const HOOKS_OFF: Hit = Hit {
    id: "git-hooks-off",
    reason: "Turns git hooks off (--no-verify, commit -n, core.hooksPath). \
             Fix what the hook reports instead. A scratch clone under a temp dir may run \
             without hooks when named with git -C <clone>, except for push.",
};
const RM_RECURSIVE: Hit = Hit {
    id: "rm-recursive",
    reason: "Recursive delete outside a temp dir or build output. Write the temp path out \
             (rm -rf /tmp/x, or S=/tmp/s; rm -rf $S/x), delete named files, or use \
             git worktree remove or cargo clean.",
};

/// Temp roots under which a recursive delete is allowed (with at least one name below).
const TEMP_ROOTS: &[&str] = &[
    "/tmp/",
    "/private/tmp/",
    "/var/folders/",
    "/private/var/folders/",
    "$TMPDIR/",
    "${TMPDIR}/",
    "${TMPDIR%/}/",
];

/// Build output and caches a build or install recreates; a relative path ending in one of
/// these may be deleted recursively.
const REGENERABLE: &[&str] = &[
    "node_modules",
    "target",
    "build",
    "dist",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    "coverage",
    "htmlcov",
    ".next",
    ".turbo",
];

const MAX_DEPTH: u8 = 3;

/// Shell variables set earlier in the same command (`S=/tmp/x; rm -rf $S/y`), so a target
/// written through a variable can be judged. Only plain `NAME=value` statements and
/// `export NAME=value` count; `NAME=value cmd` sets the variable for `cmd` alone.
///
/// An assignment counts only where it surely runs in this shell: a statement of its own, at
/// the top level, not after `&&` or `||`, not in a pipeline, a background job, a subshell, a
/// `{ }` group, an `if`/`case`/loop body, or a heredoc a child shell runs. Anywhere else, and
/// wherever the name is handed to a command (`for S`, `read S`, `unset S`, `local S=…`), the
/// variable becomes unknown until a sure assignment sets it again, and a target written
/// through it is never judged safe, not even as `$TMPDIR/…`.
#[derive(Default)]
struct Ctx<'a> {
    vars: HashMap<String, String>,
    unknown: HashSet<String>,
    /// Variables of the whole command, when this one was cut out of it.
    base: Option<&'a Vars>,
}

/// The variables a whole command sets (last value wins), and the ones it may set to a value
/// it cannot know. Build it once per command check and pass it to [`command_reason_in`] for
/// each command the AST cuts out of it.
#[derive(Default)]
pub struct Vars {
    vars: HashMap<String, String>,
    unknown: HashSet<String>,
}

impl Vars {
    pub fn of(command: &str) -> Vars {
        let mut ctx = Ctx::default();
        let _ = command_reason_depth(command, 0, &|_| false, &mut ctx, true);
        Vars {
            vars: ctx.vars,
            unknown: ctx.unknown,
        }
    }
}

impl Ctx<'_> {
    /// True when `name` was assigned where its value cannot be known, and no sure assignment
    /// in this command has set it since.
    fn is_unknown(&self, name: &str) -> bool {
        !self.vars.contains_key(name)
            && (self.unknown.contains(name) || self.base.is_some_and(|b| b.unknown.contains(name)))
    }

    fn get(&self, name: &str) -> Option<&String> {
        if let Some(value) = self.vars.get(name) {
            return Some(value);
        }
        if self.is_unknown(name) {
            return None;
        }
        self.base.and_then(|b| b.vars.get(name))
    }

    /// Record `NAME=value`. When `sure` is false the assignment may not reach this shell, so
    /// the name becomes unknown until a sure assignment sets it again.
    fn set(&mut self, assignment: &str, sure: bool) {
        if let Some((name, value)) = assignment.split_once('=') {
            if sure {
                let value = self.expand(value);
                self.unknown.remove(name);
                self.vars.insert(name.to_string(), value);
            } else {
                self.forget(name);
            }
        }
    }

    fn forget(&mut self, name: &str) {
        self.vars.remove(name);
        self.unknown.insert(name.to_string());
    }

    /// True when the git directory or worktree that variable `name` names (if any) is under a
    /// temp root.
    fn tree_is_temp(&self, name: &str) -> bool {
        match self.get(name) {
            Some(v) => is_temp_path(v),
            None => !self.is_unknown(name),
        }
    }

    /// Replace `$NAME` and `${NAME}` with known values; leave anything else as written.
    fn expand(&self, s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut rest = s;
        while let Some(pos) = rest.find('$') {
            out.push_str(&rest[..pos]);
            let after = &rest[pos + 1..];
            let (name, used) = match after.strip_prefix('{') {
                Some(inner) => match inner.find('}') {
                    Some(end) => (&inner[..end], end + 2),
                    None => ("", 0),
                },
                None => {
                    let end = after
                        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                        .unwrap_or(after.len());
                    (&after[..end], end)
                }
            };
            // `${TMPDIR%/}` is TMPDIR with an operator: judge it by the name.
            let ident = name
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .map_or(name, |end| &name[..end]);
            match self.get(name) {
                Some(value) if is_assignment(&format!("{name}=")) => {
                    out.push_str(value);
                    rest = &after[used..];
                }
                // Assigned in this command, but its value here cannot be known (an unknown
                // assignment, or `${NAME%…}` of a known one): never a temp path, so the
                // literal `$TMPDIR/` exemption cannot apply to it.
                _ if used > 0
                    && is_assignment(&format!("{ident}="))
                    && (self.is_unknown(ident) || self.get(ident).is_some()) =>
                {
                    out.push_str(UNKNOWN_VALUE);
                    rest = &after[used..];
                }
                _ => {
                    out.push('$');
                    rest = after;
                }
            }
        }
        out.push_str(rest);
        out
    }
}

/// The first destructive action in `command` whose rule `enabled` accepts.
pub fn command_reason(command: &str, enabled: &dyn Fn(&str) -> bool) -> Option<Hit> {
    command_reason_depth(command, 0, enabled, &mut Ctx::default(), true)
}

/// Like [`command_reason`] for one command cut out of a whole command (the AST hands commands
/// over one by one): the variables the whole command sets count as known. The ordered pass
/// over the whole command still runs, so a target used before its variable is set is judged
/// there.
pub fn command_reason_in(
    command: &str,
    whole: &Vars,
    enabled: &dyn Fn(&str) -> bool,
) -> Option<Hit> {
    let mut ctx = Ctx {
        base: Some(whole),
        ..Ctx::default()
    };
    command_reason_depth(command, 0, enabled, &mut ctx, true)
}

/// `sure` is false when `command` itself may not run in this shell (an `eval` after `&&`):
/// then no assignment in it counts.
fn command_reason_depth(
    command: &str,
    depth: u8,
    enabled: &dyn Fn(&str) -> bool,
    ctx: &mut Ctx<'_>,
    sure: bool,
) -> Option<Hit> {
    let parts = split_unquoted_ends(command);
    let sure = sure && !has_case(&parts);
    // Open subshells, `{ }` groups and if/case/loop bodies before the current part.
    let mut nest: i64 = 0;
    for (k, (part, end)) in parts.iter().enumerate() {
        // An unbalanced quote makes shlex give up; check the bare words instead of nothing.
        let tokens = shlex::split(part).unwrap_or_else(|| {
            part.split_whitespace()
                .map(|t| t.trim_matches(['\'', '"']).to_string())
                .collect()
        });
        let (opens, closes) = nesting(part, &tokens);
        let part_sure = sure
            && nest == 0
            && opens == 0
            && closes == 0
            && starts_a_statement(&parts, k)
            && ends_a_statement(&parts, k, *end);
        for seg in tokens.split(|t| SEPARATORS.contains(&t.as_str())) {
            if let Some(hit) = segment_reason(seg, depth, enabled, ctx, part_sure) {
                return Some(hit);
            }
        }
        nest = (nest + opens - closes).max(0);
    }
    None
}

/// True when part `k` runs whatever the part before it did: it opens the text, or follows
/// `;`, a newline, a background `&`, or a heredoc body. Not after `&&`, `||` or a pipe.
fn starts_a_statement(parts: &[(String, PartEnd)], k: usize) -> bool {
    let Some(prev) = k.checked_sub(1).map(|p| &parts[p]) else {
        return true;
    };
    match prev.1 {
        PartEnd::Op(';' | '\n') | PartEnd::ShellHeredoc | PartEnd::End => true,
        // `a & b`: `a` runs in the background, `b` runs anyway. In `a && b` the part
        // between the two `&` is empty.
        PartEnd::Op('&') => !prev.0.trim().is_empty(),
        PartEnd::Op(_) => false,
    }
}

/// True when part `k` (ended by `end`) runs in this shell: it is followed by `;`, a newline,
/// `&&`, `||`, or the end. Not before a pipe or a background `&`, and not a heredoc body that
/// a child shell runs.
fn ends_a_statement(parts: &[(String, PartEnd)], k: usize, end: PartEnd) -> bool {
    match end {
        PartEnd::Op(';' | '\n') | PartEnd::End => true,
        PartEnd::Op(c @ ('&' | '|')) => parts
            .get(k + 1)
            .is_some_and(|(p, e)| p.is_empty() && *e == PartEnd::Op(c)),
        PartEnd::Op(_) | PartEnd::ShellHeredoc => false,
    }
}

const OPENERS: &[&str] = &["if", "case", "while", "until", "for", "select"];
const CLOSERS: &[&str] = &["fi", "esac", "done"];

/// How many subshells, groups and compound commands `part` opens and closes. Opens are
/// counted generously (every `(` outside single quotes, quoted or not) and closes strictly
/// (a `)` outside all quotes), so a miscount only makes later assignments count less.
fn nesting(part: &str, tokens: &[String]) -> (i64, i64) {
    let (mut opens, mut closes) = (0i64, 0i64);
    let (mut single, mut double, mut escaped) = (false, false, false);
    for c in part.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if !single => escaped = true,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '(' | '`' if !single => opens += 1,
            ')' if !single && !double => closes += 1,
            _ => {}
        }
    }
    for (i, t) in tokens.iter().enumerate() {
        // A closing word counts only where a command starts; an opening one counts anywhere.
        let at_start = i == 0 || SEPARATORS.contains(&tokens[i - 1].as_str());
        if t == "{" || OPENERS.contains(&t.trim_start_matches(['(', '{'])) {
            opens += 1;
        } else if at_start && (t == "}" || CLOSERS.contains(&t.trim_end_matches([')', '}']))) {
            closes += 1;
        }
    }
    (opens, closes)
}

/// `case` patterns end in a bare `)` that closes nothing, so with a `case` anywhere the
/// nesting count cannot be trusted.
fn has_case(parts: &[(String, PartEnd)]) -> bool {
    parts.iter().any(|(p, _)| {
        p.split_whitespace()
            .any(|w| w.trim_start_matches(['(', '{']) == "case")
    })
}

/// `NAME=value` with a shell variable name.
fn is_assignment(t: &str) -> bool {
    match t.split_once('=') {
        Some((name, _)) => {
            let mut chars = name.chars();
            matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
}

fn names_hooks_path(s: &str) -> bool {
    s.to_ascii_lowercase().contains("core.hookspath")
}

/// Commands that set the shell variables named in their arguments (`printf -v` is handled on
/// its own; `export` is handled as an assignment).
const SETS_NAMES: &[&str] = &[
    "for",
    "select",
    "read",
    "unset",
    "local",
    "declare",
    "typeset",
    "readonly",
    "let",
    "getopts",
    "mapfile",
    "readarray",
];

/// What `$NAME` expands to when NAME was assigned where its value cannot be known: an
/// absolute path that is under no temp root and names nothing real.
const UNKNOWN_VALUE: &str = "/\u{0}unknown-variable";

/// Keywords that can come before a command's program name.
const KEYWORDS: &[&str] = &[
    "if", "then", "elif", "else", "while", "until", "do", "!", "time",
];

/// `sure` is false when this segment may not run in this shell; see [`Ctx`].
fn segment_reason(
    raw: &[String],
    depth: u8,
    enabled: &dyn Fn(&str) -> bool,
    ctx: &mut Ctx<'_>,
    sure: bool,
) -> Option<Hit> {
    // A subshell's parentheses stay glued to the words beside them: `(cd x`, `--hard)`.
    let mut seg: Vec<String> = raw.to_vec();
    if let Some(first) = seg.first_mut() {
        *first = first.trim_start_matches(['(', '{']).to_string();
    }
    if let Some(last) = seg.last_mut() {
        if last != "{}" {
            *last = last.trim_end_matches([')', '}']).to_string();
        }
    }
    seg.retain(|t| !t.is_empty());

    // Skip leading keywords (`if git reset --hard; then`), VAR=val assignments and wrapper
    // programs (with their options). An assignment after a keyword is inside a compound
    // command, which the nesting count already marks as not sure.
    let mut i = 0;
    while i < seg.len() && KEYWORDS.contains(&seg[i].as_str()) {
        i += 1;
    }
    let seg = seg.split_off(i);
    let mut i = 0;
    let mut via_xargs = false;
    // GIT_DIR / GIT_WORK_TREE / core.worktree given on this command line: the git dir or
    // worktree they name, as written.
    let mut trees: Vec<String> = Vec::new();
    while i < seg.len() {
        let t = seg[i].trim_start_matches('\\');
        if is_assignment(t) {
            // GIT_CONFIG_KEY_0=core.hooksPath, GIT_CONFIG_PARAMETERS='core.hooksPath=…'
            if t.starts_with("GIT_CONFIG") && names_hooks_path(t) && enabled(HOOKS_OFF.id) {
                return Some(HOOKS_OFF);
            }
            if let Some(v) = t
                .strip_prefix("GIT_DIR=")
                .or_else(|| t.strip_prefix("GIT_WORK_TREE="))
            {
                trees.push(ctx.expand(v));
            }
            if t.starts_with("GIT_CONFIG") && names_worktree(t) {
                trees.push(String::new());
            }
            i += 1;
            continue;
        }
        let prog = basename(t);
        if prog == "xargs" {
            via_xargs = true;
            i += 1;
            while i < seg.len() && seg[i].starts_with('-') && seg[i] != "-" {
                let opt = seg[i].as_str();
                i += 1;
                if matches!(opt, "-I" | "-n" | "-P" | "-L" | "-s" | "-d" | "-E" | "-a")
                    && i < seg.len()
                {
                    i += 1;
                }
            }
            continue;
        }
        if let Some(valued) = wrapper_valued_options(prog) {
            let is_timeout = prog == "timeout";
            i += 1;
            while i < seg.len() && seg[i].starts_with('-') && seg[i] != "-" {
                let opt = seg[i].as_str();
                i += 1;
                if valued.contains(&opt) && i < seg.len() {
                    i += 1;
                }
            }
            if is_timeout && i < seg.len() && is_duration(&seg[i]) {
                i += 1;
            }
            continue;
        }
        break;
    }
    if i == seg.len() && seg.iter().all(|t| is_assignment(t)) {
        seg.iter().for_each(|t| ctx.set(t, sure));
        return None;
    }
    let prog_tok = seg.get(i)?.trim_start_matches('\\');
    let prog = basename(prog_tok);
    let args = &seg[i + 1..];
    if prog == "export" {
        args.iter()
            .filter(|a| is_assignment(a))
            .for_each(|a| ctx.set(a, sure));
        return None;
    }
    // A command that sets the variables it is handed (`for S in`, `read S`, `unset S`,
    // `local S=…`, `printf -v S`): their values are unknown from here on. Any other command's
    // arguments (`echo S`) leave variables alone.
    let handed: Vec<&str> = if SETS_NAMES.contains(&prog) {
        args.iter().map(String::as_str).collect()
    } else if prog == "printf" {
        args.iter()
            .enumerate()
            .filter_map(|(k, a)| match a.as_str() {
                "-v" => args.get(k + 1).map(String::as_str),
                _ => a.strip_prefix("-v").filter(|n| !n.is_empty()),
            })
            .collect()
    } else {
        Vec::new()
    };
    for a in handed {
        let name = a.split_once('=').map_or(a, |(n, _)| n);
        if is_assignment(&format!("{name}=")) {
            ctx.forget(name);
        }
    }

    if depth < MAX_DEPTH {
        // bash -c "script", sh -lc "script": look inside the script text.
        if SHELLS.contains(&prog) {
            let pos = args
                .iter()
                .position(|a| a.starts_with('-') && !a.starts_with("--") && a.contains('c'))?;
            // A child shell sees no unexported variables: start it with none.
            return command_reason_depth(
                args.get(pos + 1)?,
                depth + 1,
                enabled,
                &mut Ctx::default(),
                true,
            );
        }
        if prog == "eval" {
            return command_reason_depth(&args.join(" "), depth + 1, enabled, ctx, sure);
        }
        // find … -exec rm -rf {} +
        if prog == "find" {
            let mut k = 0;
            while k < args.len() {
                if matches!(args[k].as_str(), "-exec" | "-execdir" | "-ok" | "-okdir") {
                    let end = args[k + 1..]
                        .iter()
                        .position(|a| a == ";" || a == "+")
                        .map_or(args.len(), |p| k + 1 + p);
                    let exec = &args[k + 1..end];
                    if let Some(hit) = segment_reason(exec, depth + 1, enabled, ctx, false) {
                        return Some(hit);
                    }
                    k = end;
                }
                k += 1;
            }
            return None;
        }
    }

    let hit = match prog {
        "git" => git_reason(args, ctx, &trees),
        "rm" => rm_reason(args, via_xargs, ctx),
        _ => None,
    }?;
    enabled(hit.id).then_some(hit)
}

/// Options, operands and `--` of one command line.
#[derive(Default)]
struct Parsed<'a> {
    /// Short option letters, up to the first letter that takes a value.
    shorts: String,
    /// Long options, without any `=value`.
    longs: Vec<&'a str>,
    /// Operands before `--`.
    operands: Vec<&'a str>,
    /// Whether `--` appeared, and what followed it.
    dashdash: bool,
    after_dashdash: Vec<&'a str>,
}

impl Parsed<'_> {
    fn short(&self, c: char) -> bool {
        self.shorts.contains(c)
    }
    fn long(&self, name: &str) -> bool {
        self.longs.contains(&name)
    }
}

/// Parse `args`. Short letters in `valued` take a value (attached or the next token); letters
/// in `attached` take only an attached value. Long options in `valued_long` take the next token
/// as their value unless written `--name=value`.
fn parse<'a>(args: &'a [String], valued: &str, attached: &str, valued_long: &[&str]) -> Parsed<'a> {
    let mut p = Parsed::default();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        i += 1;
        if p.dashdash {
            p.after_dashdash.push(a);
        } else if a == "--" {
            p.dashdash = true;
        } else if let Some(long) = a.strip_prefix("--") {
            let (name, has_value) = match long.split_once('=') {
                Some((n, _)) => (n, true),
                None => (long, false),
            };
            let full = &a[..name.len() + 2];
            p.longs.push(full);
            if !has_value && valued_long.contains(&full) {
                i += 1;
            }
        } else if a.len() > 1 && a.starts_with('-') {
            for (pos, c) in a.char_indices().skip(1) {
                if valued.contains(c) {
                    if pos + c.len_utf8() == a.len() {
                        i += 1;
                    }
                    break;
                }
                if attached.contains(c) {
                    break;
                }
                p.shorts.push(c);
            }
        } else {
            p.operands.push(a);
        }
    }
    p
}

const COMMIT_LONG: &[&str] = &[
    "--message",
    "--file",
    "--reuse-message",
    "--reedit-message",
    "--fixup",
    "--squash",
    "--author",
    "--date",
    "--template",
    "--trailer",
    "--cleanup",
    "--pathspec-from-file",
];

fn names_worktree(s: &str) -> bool {
    s.to_ascii_lowercase().contains("core.worktree")
}

/// `trees`: the git dirs and worktrees that `GIT_DIR`, `GIT_WORK_TREE` or a `core.worktree`
/// config name on this command line (empty when the value is not known).
fn git_reason(args: &[String], ctx: &Ctx<'_>, trees: &[String]) -> Option<Hit> {
    // Global options before the subcommand: -C <dir>, -c <key=value>, --git-dir <dir>, …
    let mut i = 0;
    let mut dir: Option<String> = None;
    let mut hooks_off = false;
    let mut trees: Vec<String> = trees.to_vec();
    while i < args.len() && args[i].starts_with('-') {
        let a = args[i].as_str();
        i += 1;
        let value = match a {
            "-c" | "--config-env" => args.get(i).map(String::as_str),
            _ => a
                .strip_prefix("--config-env=")
                .or_else(|| a.strip_prefix("-c").filter(|v| !v.is_empty())),
        };
        hooks_off |= value.is_some_and(names_hooks_path);
        if value.is_some_and(names_worktree) {
            trees.push(String::new());
        }
        match a {
            "-C" => dir = args.get(i).map(|d| ctx.expand(d)),
            "--git-dir" | "--work-tree" => {
                trees.push(args.get(i).map_or(String::new(), |t| ctx.expand(t)))
            }
            _ => {
                if let Some(t) = a
                    .strip_prefix("--git-dir=")
                    .or_else(|| a.strip_prefix("--work-tree="))
                {
                    trees.push(ctx.expand(t));
                }
            }
        }
        if matches!(
            a,
            "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace" | "--config-env"
        ) {
            i += 1;
        }
    }
    let sub = args.get(i)?.as_str();
    let rest = &args[i + 1..];
    let (hit, sub_hooks_off) = git_subcommand_reason(sub, rest);
    let hooks_off = hooks_off || sub_hooks_off;
    // Work in a scratch clone under a temp dir is disposable: discarding it, or running it with
    // hooks off, is allowed when the clone is named with -C and no git dir or worktree outside
    // a temp dir is named another way. Anything that reaches a remote is not.
    let scratch = dir.as_deref().is_some_and(is_temp_path)
        && trees.iter().all(|t| is_temp_path(t))
        && ctx.tree_is_temp("GIT_DIR")
        && ctx.tree_is_temp("GIT_WORK_TREE");
    // Judge the destructive action first: hooks off is excused in a scratch clone, and must
    // not hide a `reset --hard` or `rebase -i` next to it.
    if let Some(hit) = hit {
        if !(scratch && hit.id == "git-discard") {
            return Some(hit);
        }
    }
    (hooks_off && !(scratch && sub != "push")).then_some(HOOKS_OFF)
}

/// The destructive action of `git <sub> <rest>`, if any, and whether it turns hooks off.
fn git_subcommand_reason(sub: &str, rest: &[String]) -> (Option<Hit>, bool) {
    let p = match sub {
        "commit" => parse(rest, "mFCct", "Su", COMMIT_LONG),
        "push" => parse(
            rest,
            "o",
            "",
            &["--push-option", "--repo", "--receive-pack", "--exec"],
        ),
        "clean" => parse(rest, "e", "", &["--exclude"]),
        "checkout" => parse(rest, "bB", "", &["--orphan", "--pathspec-from-file"]),
        "restore" => parse(rest, "s", "", &["--source", "--pathspec-from-file"]),
        "switch" => parse(rest, "cC", "", &["--create", "--force-create", "--orphan"]),
        "stash" => parse(rest, "m", "", &["--message", "--pathspec-from-file"]),
        "branch" => parse(rest, "u", "", &["--set-upstream-to"]),
        "rebase" => parse(
            rest,
            "xsX",
            "C",
            &["--exec", "--strategy", "--strategy-option", "--onto"],
        ),
        "config" => parse(
            rest,
            "f",
            "",
            &["--file", "--blob", "--type", "--default", "--comment"],
        ),
        "merge" => parse(
            rest,
            "msX",
            "S",
            &["--message", "--file", "--strategy", "--strategy-option"],
        ),
        _ => parse(rest, "", "", &[]),
    };
    let no_verify = p.long("--no-verify");
    let force = p.short('f') || p.long("--force");
    let first = p.operands.first().copied();
    let hit = match sub {
        "reset" if p.long("--hard") => RESET_HARD,
        "clean" if force && !(p.short('n') || p.long("--dry-run")) => CLEAN_FORCE,
        "checkout" if p.long("--ours") || p.long("--theirs") => return (None, no_verify),
        // `git checkout <path>` without `--` is not denied: as tokens a path and a branch name
        // look the same, and denying every `git checkout <name>` would block switching
        // branches. A known gap, listed under Limits at the top of this file.
        "checkout"
            if force
                || (p.dashdash && !p.after_dashdash.is_empty())
                || p.long("--pathspec-from-file")
                || p.operands.iter().any(|o| matches!(*o, "." | ":/" | "*")) =>
        {
            CHECKOUT_PATHS
        }
        "restore" if p.long("--ours") || p.long("--theirs") => return (None, no_verify),
        "restore"
            if p.short('W') || p.long("--worktree") || !(p.short('S') || p.long("--staged")) =>
        {
            RESTORE_WORKTREE
        }
        "switch" if force || p.long("--discard-changes") => SWITCH_DISCARD,
        "stash" if matches!(first, Some("drop" | "clear")) => STASH_DELETE,
        "branch" if p.short('D') || ((p.short('d') || p.long("--delete")) && force) => {
            BRANCH_FORCE_DELETE
        }
        "worktree"
            if first == Some("remove")
                && force
                && !p.operands.get(1).is_some_and(|w| is_temp_path(w)) =>
        {
            WORKTREE_FORCE_REMOVE
        }
        "push"
            if force
                || p.long("--force-with-lease")
                || p.long("--force-if-includes")
                || p.long("--mirror")
                || p.operands
                    .iter()
                    .chain(p.after_dashdash.iter())
                    .any(|o| o.starts_with('+')) =>
        {
            FORCE_PUSH
        }
        "filter-branch" | "filter-repo" => HISTORY_REWRITE,
        "rebase" if p.short('i') || p.long("--interactive") => HISTORY_REWRITE,
        "reflog" if matches!(first, Some("expire" | "delete")) => HISTORY_REWRITE,
        "update-ref" if p.short('d') || p.long("--delete") => HISTORY_REWRITE,
        "commit" if p.short('n') => return (None, true),
        "config" => {
            let reads = [
                "--get",
                "--get-all",
                "--get-regexp",
                "--unset",
                "--unset-all",
                "--list",
            ];
            if reads.iter().any(|r| p.long(r)) || p.short('l') {
                return (None, no_verify);
            }
            // `git config core.hooksPath` reads; a value after the key sets it.
            let sets = p
                .operands
                .iter()
                .position(|o| names_hooks_path(o))
                .is_some_and(|key| key + 1 < p.operands.len());
            return (None, no_verify || sets);
        }
        _ => return (None, no_verify),
    };
    (Some(hit), no_verify)
}

fn rm_reason(args: &[String], via_xargs: bool, ctx: &Ctx<'_>) -> Option<Hit> {
    let p = parse(args, "", "", &[]);
    if !(p.short('r') || p.short('R') || p.long("--recursive")) {
        return None;
    }
    // Under xargs the targets come from stdin, so none of them can be judged.
    if via_xargs {
        return Some(RM_RECURSIVE);
    }
    let mut targets = p.operands.iter().chain(p.after_dashdash.iter());
    targets
        .any(|t| !safe_target(&ctx.expand(t)))
        .then_some(RM_RECURSIVE)
}

/// True for a path with at least one name below a temp root, and no `..`.
fn is_temp_path(path: &str) -> bool {
    let t = path.trim_end_matches('/');
    if t.split('/').any(|c| c == "..") {
        return false;
    }
    TEMP_ROOTS
        .iter()
        .find_map(|r| t.strip_prefix(r))
        .map(|below| below.split('/').next().unwrap_or(""))
        .is_some_and(|top| !top.is_empty() && top != "*")
}

/// True for a path under a temp root, or a relative path to regenerable build output.
fn safe_target(target: &str) -> bool {
    let t = target.trim_end_matches('/');
    if t.is_empty() || t.split('/').any(|c| c == "..") {
        return false;
    }
    if TEMP_ROOTS.iter().any(|r| t.starts_with(r)) {
        return is_temp_path(t);
    }
    if t.starts_with(['/', '~', '$']) || t.contains(['*', '?', '[']) {
        return false;
    }
    let last = t.rsplit('/').next().unwrap_or(t);
    REGENERABLE.contains(&last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_targets() {
        for t in [
            "node_modules",
            "./dist/",
            "a/b/target",
            "/tmp/x",
            "$TMPDIR/x.1",
        ] {
            assert!(safe_target(t), "{t}");
        }
        for t in [
            "src",
            ".",
            "..",
            "/tmp",
            "/tmp/*",
            "$TMPDIR",
            "build/../src",
            "dist/*",
            "~",
        ] {
            assert!(!safe_target(t), "{t}");
        }
    }

    #[test]
    fn parse_skips_option_values() {
        let args: Vec<String> = ["-m", "-n is text", "-a"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let p = parse(&args, "mFCct", "Su", COMMIT_LONG);
        assert_eq!(p.shorts, "a");
        let args: Vec<String> = ["-mfix -n"].iter().map(|s| s.to_string()).collect();
        assert_eq!(parse(&args, "mFCct", "Su", COMMIT_LONG).shorts, "");
    }

    #[test]
    fn disabled_rule_is_skipped_for_a_later_one() {
        let only_rm = |id: &str| id == "rm-recursive";
        assert_eq!(
            command_reason("git stash clear; rm -rf src", &only_rm).map(|h| h.id),
            Some("rm-recursive")
        );
    }

    #[test]
    fn subshell_parentheses_do_not_hide_the_last_word() {
        // The engine's AST pass splits subshells cleanly; this whole-text pass (and the no-AST
        // fallback) sees `(cd repo` and `clear)` as words.
        assert!(command_reason("(cd repo && git stash clear)", &|_| true).is_some());
        assert!(command_reason("{ git stash clear; }", &|_| true).is_some());
    }

    #[test]
    fn multibyte_options_do_not_panic() {
        for c in [
            "git commit -é",
            "rm -é src",
            "git push -日本",
            "git -cé reset",
        ] {
            let _ = command_reason(c, &|_| true);
        }
    }
}
