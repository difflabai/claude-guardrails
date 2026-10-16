//! Reader commands pointed at protected secret paths
//!
//! The regex rules only ever caught `cat .env` / `cat ~/.ssh/id_rsa`; `grep -r`, `head`,
//! `tail`, `rg`, `less`, `awk`, `sed` … and `cat` of `*.pem` / `secrets.json` went
//! through. This works on TOKENS, not text: a command is a violation when its program
//! is a reader and one of its own arguments (or an input redirect) names a protected
//! path. The same filenames inside the quoted argument of some other command, such as
//! a mail `--body`, are not that command's file operands and pass.
//!
//! Limits (not covered): `cd dir && cat relative` with a protected name only after the cd, partial
//! globs, dd/tee/source/git show/curl file://, substitution reads, and shells nested deeper than 3.

/// Programs that print or search file contents.
const READERS: &[&str] = &[
    "cat", "tac", "nl", "less", "more", "most", "head", "tail", "grep", "egrep", "fgrep", "rg",
    "ag", "ack", "awk", "gawk", "mawk", "sed", "cut", "sort", "uniq", "tr", "xxd", "od", "hexdump",
    "strings", "base64", "bat", "batcat", "jq", "yq", "diff", "cmp", "paste", "fold", "fmt",
    "column", "wc", "rev", "cp", "scp", "rsync", "zcat", "open", "pbcopy",
];

const SHELLS: &[&str] = &["bash", "sh", "zsh", "dash", "ksh"];

const SEPARATORS: &[&str] = &["|", "||", "&&", ";", "&", "|&", "(", ")", "{", "}"];

const REASON: &str =
    "Reading a protected secret file (dotenv, SSH key, .pem/.key, credentials, secrets.*)";

fn basename(s: &str) -> &str {
    s.rsplit('/').next().unwrap_or(s)
}

/// True when `token` names a protected secret file. Example/template dotenv files,
/// and public keys, are not protected.
pub fn is_protected_path(token: &str) -> bool {
    // `0<.env`: drop the fd number in front of the redirect operator
    let token = match token.find('<') {
        Some(idx) if idx > 0 && token[..idx].chars().all(|c| c.is_ascii_digit()) => &token[idx..],
        _ => token,
    };
    let t = token
        .trim_start_matches('<')
        .trim_matches(|c| c == '"' || c == '\'');
    // `--file=.env`, `of=.env`: look at the value too.
    if let Some((_, v)) = t.split_once('=') {
        if !v.is_empty() && is_protected_path(v) {
            return true;
        }
    }
    let base = basename(t);
    if base.is_empty() {
        return false;
    }
    let lower = base.to_ascii_lowercase();

    // dotenv: .env, .env.local, .env.production, .env*, prod.env — not .env.example & friends
    if lower == ".env" || (lower.ends_with(".env") && lower.len() > 4) {
        return true;
    }
    if let Some(rest) = lower.strip_prefix(".env") {
        if rest.starts_with('.') || rest.contains(['*', '?', '[']) {
            let ext = rest.trim_start_matches('.');
            let benign = matches!(
                ext,
                "example" | "sample" | "template" | "dist" | "defaults" | "schema" | "tpl"
            );
            return !benign;
        }
        return false; // .envrc, .environment …
    }
    // SSH private keys: id_rsa, id_ed25519_work … but not the .pub half
    if lower.starts_with("id_") && !lower.ends_with(".pub") && t.contains("id_") {
        return true;
    }
    // certificates / keys
    if lower.ends_with(".pem") || lower.ends_with(".key") || lower.ends_with(".p12") {
        return true;
    }
    // credentials: ~/.aws/credentials, credentials.json — a bare word "credentials" is prose
    if lower == "credentials" && t.contains('/') {
        return true;
    }
    if lower == "credentials.json" {
        return true;
    }
    // secrets.json / secret.yaml / secrets.env …
    if let Some(rest) = lower
        .strip_prefix("secrets.")
        .or_else(|| lower.strip_prefix("secret."))
    {
        return !rest.is_empty();
    }
    false
}

/// Deny reason when the command in `tokens` is a reader of a protected path.
/// `tokens` is one shell-split command line, possibly with pipes / `&&` / `;`.
pub fn secret_read_reason(tokens: &[String]) -> Option<&'static str> {
    secret_read_reason_depth(tokens, 0)
}

fn secret_read_reason_depth(tokens: &[String], depth: u8) -> Option<&'static str> {
    for seg in tokens.split(|t| SEPARATORS.contains(&t.as_str())) {
        if let Some(r) = segment_reason(seg, depth) {
            return Some(r);
        }
    }
    None
}

/// Wrapper programs that run the next command, with the options that take a value.
/// `timeout` also takes one duration operand before the command.
fn wrapper_valued_options(prog: &str) -> Option<&'static [&'static str]> {
    match prog {
        "command" | "builtin" | "exec" | "nohup" | "time" | "setsid" => Some(&[]),
        "sudo" => Some(&["-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U"]),
        "env" => Some(&["-u", "-C", "-S", "-P"]),
        "nice" => Some(&["-n"]),
        "ionice" => Some(&["-c", "-n", "-p", "-P", "-u"]),
        "stdbuf" => Some(&["-i", "-o", "-e"]),
        "timeout" => Some(&["-k", "-s"]),
        _ => None,
    }
}

fn is_duration(t: &str) -> bool {
    let t = t.trim_end_matches(['s', 'm', 'h', 'd']);
    !t.is_empty() && t.chars().all(|c| c.is_ascii_digit() || c == '.')
}

fn segment_reason(seg: &[String], depth: u8) -> Option<&'static str> {
    // Skip leading VAR=val assignments and wrapper programs (with their options).
    let mut i = 0;
    while i < seg.len() {
        let t = seg[i].trim_start_matches('\\');
        let assignment = t.contains('=') && !t.starts_with('-') && !t.contains('/');
        if assignment {
            i += 1;
            continue;
        }
        if let Some(valued) = wrapper_valued_options(basename(t)) {
            let is_timeout = basename(t) == "timeout";
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
    let prog_tok = seg.get(i)?.trim_start_matches('\\');
    let prog = basename(prog_tok);
    let args = &seg[i + 1..];

    // bash -c "cat .env": look inside the script text.
    if SHELLS.contains(&prog) && depth < 3 {
        if let Some(pos) = args.iter().position(|a| a == "-c") {
            if let Some(script) = args.get(pos + 1) {
                if let Some(r) = command_reason_depth(script, depth + 1) {
                    return Some(r);
                }
            }
        }
        return None;
    }

    if !READERS.contains(&prog) {
        return None;
    }
    if file_operands(prog, args)
        .iter()
        .any(|a| is_protected_path(a))
    {
        return Some(REASON);
    }
    None
}

/// rsync `--filter` / `-f` RULE: an exclude/include pattern (`- x`, `+ x`) is a glob and is
/// skipped. ANY other rule (merge, dir-merge, `.`, `:`, `:-`, unknown) may name a rules FILE, so
/// its last word is path-checked. Allowlist the safe shape, never list the merge words.
fn rsync_rule_file(rule: &str) -> Option<&str> {
    let r = rule.trim_start();
    if r.starts_with('-') || r.starts_with('+') {
        return None;
    }
    r.split_whitespace().last()
}

/// The arguments of reader `prog` that are FILES: option values that are patterns,
/// scripts, variable names or here-strings are data, not files, and are left out.
fn file_operands<'a>(prog: &str, args: &'a [String]) -> Vec<&'a str> {
    // tr takes no file operands (its words are character sets); it reads only stdin, so only an
    // input redirect (`< .env`, `<.env`) can name a file.
    if prog == "tr" {
        let mut out = Vec::new();
        for (i, a) in args.iter().enumerate() {
            // an fd number may precede the operator: `0< .env`, `0<.env`
            let t = a.trim_start_matches(|c: char| c.is_ascii_digit());
            if t == "<" {
                if let Some(v) = args.get(i + 1) {
                    out.push(v.as_str());
                }
            } else if t.starts_with('<') && !t.starts_with("<<") {
                out.push(t);
            }
        }
        return out;
    }
    // Options that take a value, by program. RULE: a flag is listed in `skip_value` only when
    // it certainly takes a NON-file value; skipping a token we should have checked is the
    // unsafe direction, so any doubt means "not listed" (the token is then treated as an
    // operand, which can only over-block). `file_value` flags take one FILE value;
    // `name_file` flags take NAME then FILE (jq --rawfile NAME FILE); `name_value` take NAME
    // then a non-file VALUE (jq --arg NAME VALUE).
    let (skip_value, file_value): (&[&str], &[&str]) = match prog {
        "grep" | "egrep" | "fgrep" => (
            &[
                "-e",
                "--regexp",
                "-m",
                "--max-count",
                "-A",
                "-B",
                "-C",
                "--context",
                "--include",
                "--exclude",
                "--exclude-dir",
                "--label",
                "--binary-files",
            ],
            &["-f", "--file"],
        ),
        "rg" | "ag" | "ack" => (
            &[
                "-e",
                "--regexp",
                "-m",
                "--max-count",
                "-A",
                "-B",
                "-C",
                "--context",
                "-g",
                "--glob",
                "--type",
                "--type-not",
            ],
            &["-f", "--file"],
        ),
        "sed" => (
            &["-e", "--expression", "-l", "--line-length"],
            &["-f", "--file"],
        ),
        "awk" | "gawk" | "mawk" => (
            &[
                "-v",
                "-F",
                "--assign",
                "--field-separator",
                "-e",
                "--source",
            ],
            &["-f", "--file"],
        ),
        // jq: -e is `--exit-status` (NO value). --arg/--argjson are NAME VALUE.
        "jq" | "yq" => (&["--indent"], &["-f", "--from-file"]),
        "head" | "tail" => (&["-n", "-c", "--lines", "--bytes"], &[]),
        "cut" => (&["-d", "-f", "-c", "-b"], &[]),
        "uniq" => (&["-f", "-s", "-w"], &[]),
        "paste" => (&["-d"], &[]),
        "fold" | "fmt" => (&["-w"], &[]),
        "od" => (&["-N", "-j", "-w", "-A", "-t"], &[]),
        "xxd" => (&["-l", "-s", "-c", "-g", "-o"], &[]),
        _ => (&[], &[]),
    };
    // More flags whose value is a FILE (spaced form). Attached and `=` values are checked for
    // every program and flag regardless of this list.
    let extra_file: &[&str] = match prog {
        "grep" | "egrep" | "fgrep" => &["--exclude-from"],
        "rg" => &["--ignore-file"],
        "ag" => &["-p", "--path-to-ignore"],
        "awk" | "gawk" | "mawk" => &["-i", "--include", "-E", "--exec"],
        "diff" => &["--from-file", "--to-file"],
        "sort" => &["--files0-from", "--random-source"],
        "wc" => &["--files0-from"],
        "rsync" | "cp" | "scp" => &["--exclude-from", "--include-from", "--files-from"],
        _ => &[],
    };
    // Flags whose value is a GLOB or a DELIMITER, never a file: attached, `=` and spaced values
    // are all skipped. `--exclude-from` and friends are NOT here: those values are files.
    let ignore_value: &[&str] = match prog {
        "rsync" => &["--exclude", "--include"],
        "grep" | "egrep" | "fgrep" => &["--exclude", "--include", "--exclude-dir"],
        "diff" => &["-x", "--exclude"],
        "rg" => &["-g", "--glob", "--iglob", "--type-add"],
        "ack" => &["--ignore-file", "--ignore-dir"],
        "cut" | "paste" => &["-d"],
        "sort" => &["-t", "--field-separator"],
        "awk" | "gawk" | "mawk" => &["-v", "-F", "--assign", "--field-separator"],
        _ => &[],
    };
    // awk: these flags SUPPLY the program, so the first positional is a file
    let is_awk = matches!(prog, "awk" | "gawk" | "mawk");
    let prog_flag = |n: &str| {
        is_awk
            && matches!(
                n,
                "-f" | "--file" | "-E" | "--exec" | "-e" | "--source" | "-i" | "--include"
            )
    };
    // combined short flags ending in `f` (-if, -vf, -nf): the next token is that flag's FILE
    let combined_f = matches!(
        prog,
        "grep" | "egrep" | "fgrep" | "rg" | "sed" | "awk" | "gawk" | "mawk"
    );
    let name_value: &[&str] = if matches!(prog, "jq" | "yq") {
        &["--arg", "--argjson"]
    } else {
        &[]
    };
    let name_file: &[&str] = if matches!(prog, "jq" | "yq") {
        &["--slurpfile", "--rawfile"]
    } else {
        &[]
    };
    // grep family, sed and awk take a first POSITIONAL that is the pattern/script/program,
    // unless it was supplied by -e / -f.
    let positional_is_pattern = matches!(
        prog,
        "grep"
            | "egrep"
            | "fgrep"
            | "rg"
            | "ag"
            | "ack"
            | "sed"
            | "awk"
            | "gawk"
            | "mawk"
            | "jq"
            | "yq"
    );
    let mut have_pattern_opt = false;
    let mut out = Vec::new();
    let mut i = 0;
    let mut pattern_pending = positional_is_pattern;
    while i < args.len() {
        let a = args[i].as_str();
        // here-string: the operand is data, never a file
        if a == "<<<" {
            i += 2;
            continue;
        }
        if a.starts_with("<<<") {
            i += 1;
            continue;
        }
        if a == "--" {
            out.extend(args[i + 1..].iter().map(|s| s.as_str()));
            break;
        }
        if a.starts_with('-') && a.len() > 1 && prog == "rsync" {
            let rule = if a == "--filter" || a == "-f" {
                i += 1;
                args.get(i).map(String::as_str)
            } else if let Some(v) = a.strip_prefix("--filter=") {
                Some(v)
            } else if !a.starts_with("--") && a.starts_with("-f") {
                Some(&a[2..])
            } else {
                None
            };
            if let Some(rule) = rule {
                if let Some(f) = rsync_rule_file(rule) {
                    out.push(f);
                }
                i += 1;
                continue;
            }
        }
        if a.starts_with('-') && a.len() > 1 {
            // --opt=value form: the value is ALWAYS checked, whatever the program and flag.
            if let Some((name, value)) = a.split_once('=') {
                let short_attached = !name.starts_with("--") && name.len() > 2;
                let pre = name.get(..2).unwrap_or("");
                if ignore_value.contains(&name) || (short_attached && ignore_value.contains(&pre)) {
                    i += 1;
                    continue;
                }
                out.push(value);
                if name_file.contains(&name) {
                    // not valid jq, but if a version accepts it, check the next token too
                    // rather than guess which is the file
                    if let Some(v) = args.get(i + 1) {
                        out.push(v.as_str());
                    }
                }
                if matches!(
                    name,
                    "-e" | "--regexp" | "--expression" | "-f" | "--file" | "--from-file"
                ) || prog_flag(name)
                    || (short_attached && prog_flag(pre))
                {
                    have_pattern_opt = true;
                }
                i += 1;
                continue;
            }
            if ignore_value.contains(&a) {
                i += 2;
                continue;
            }
            if name_file.contains(&a) {
                // --rawfile NAME FILE: the FILE is the third token
                if let Some(v) = args.get(i + 2) {
                    out.push(v.as_str());
                }
                i += 3;
                continue;
            }
            if name_value.contains(&a) {
                i += 3; // --arg NAME VALUE
                continue;
            }
            if file_value.contains(&a) || extra_file.contains(&a) {
                have_pattern_opt = have_pattern_opt
                    || matches!(a, "-f" | "--file" | "--from-file")
                    || prog_flag(a);
                if let Some(v) = args.get(i + 1) {
                    out.push(v.as_str());
                }
                i += 2;
                continue;
            }
            if skip_value.contains(&a) {
                if matches!(a, "-e" | "--regexp" | "--expression") || prog_flag(a) {
                    have_pattern_opt = true;
                }
                i += 2;
                continue;
            }
            // Unlisted flag. A short flag with an attached value (-Xvalue, e.g. sed -f.env) is
            // checked as a path; a bare flag skips nothing, so the next token stays an operand.
            if !a.starts_with("--") && a.len() > 2 {
                let pre = a.get(..2).unwrap_or("");
                if ignore_value.contains(&pre) {
                    i += 1;
                    continue;
                }
                if combined_f
                    && a.ends_with('f')
                    && a[1..].chars().all(|c| c.is_ascii_alphabetic())
                {
                    have_pattern_opt = true;
                    if let Some(v) = args.get(i + 1) {
                        out.push(v.as_str());
                    }
                    i += 2;
                    continue;
                }
                out.push(&a[2..]);
                if a.starts_with("-e") || a.starts_with("-f") || prog_flag(pre) {
                    have_pattern_opt = true; // -ePATTERN / -fFILE supplied the pattern
                }
            }
            i += 1;
            continue;
        }
        // positional
        if pattern_pending && !have_pattern_opt {
            pattern_pending = false; // this one is the pattern / script / filter
        } else {
            out.push(a);
        }
        i += 1;
    }
    out
}

/// Split `text` at `;`, `&`, `|` and newlines that are outside quotes. Heredoc bodies are
/// cut out: they are data for the command they feed, except for a shell, whose body is a
/// script and is returned as a part of its own.
fn split_unquoted(text: &str) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut cur = String::new();
    let (mut single, mut double, mut escaped) = (false, false, false);
    let mut pending: Vec<String> = Vec::new(); // heredoc delimiters seen on this line
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    let mut line_parts_start = 0usize;
    while i < chars.len() {
        let ch = chars[i];
        if escaped {
            cur.push(ch);
            escaped = false;
            i += 1;
            continue;
        }
        match ch {
            '\\' if !single => {
                cur.push(ch);
                escaped = true;
            }
            '\'' if !double => {
                single = !single;
                cur.push(ch);
            }
            '"' if !single => {
                double = !double;
                cur.push(ch);
            }
            '<' if !single
                && !double
                && chars.get(i + 1) == Some(&'<')
                && chars.get(i + 2) != Some(&'<')
                && !(i > 0 && chars[i - 1] == '<') =>
            {
                // heredoc operator: read the delimiter word
                let mut j = i + 2;
                if chars.get(j) == Some(&'-') {
                    j += 1;
                }
                while chars.get(j) == Some(&' ') {
                    j += 1;
                }
                let mut delim = String::new();
                while let Some(&c) = chars.get(j) {
                    if c.is_whitespace() || matches!(c, ';' | '&' | '|' | '<' | '>') {
                        break;
                    }
                    if !matches!(c, '\'' | '"' | '\\') {
                        delim.push(c);
                    }
                    j += 1;
                }
                if !delim.is_empty() {
                    pending.push(delim);
                }
                cur.push_str("<<");
                i += 2;
                continue;
            }
            '\n' if !single && !double => {
                let first_word = cur.split_whitespace().next().unwrap_or("").to_string();
                let feeds_shell = SHELLS.contains(&basename(&first_word));
                parts.push(std::mem::take(&mut cur));
                // consume heredoc bodies that begin on the next line
                let mut k = i + 1;
                for delim in pending.drain(..) {
                    let mut body = String::new();
                    loop {
                        let end = chars[k..].iter().position(|&c| c == '\n').map(|p| k + p);
                        let line: String = chars[k..end.unwrap_or(chars.len())].iter().collect();
                        k = end.map_or(chars.len(), |e| e + 1);
                        if line.trim_start_matches('\t').trim_end() == delim || k >= chars.len() {
                            if line.trim_start_matches('\t').trim_end() != delim {
                                body.push_str(&line);
                            }
                            break;
                        }
                        body.push_str(&line);
                        body.push('\n');
                    }
                    if feeds_shell {
                        parts.push(body);
                    }
                }
                let _ = line_parts_start;
                line_parts_start = parts.len();
                i = k;
                continue;
            }
            ';' | '&' | '|' if !single && !double => {
                parts.push(std::mem::take(&mut cur));
            }
            _ => cur.push(ch),
        }
        i += 1;
    }
    parts.push(cur);
    parts
}

/// Convenience: split `command` at unquoted operators, shell-split each part, check it.
pub fn command_reason(command: &str) -> Option<&'static str> {
    command_reason_depth(command, 0)
}

fn command_reason_depth(command: &str, depth: u8) -> Option<&'static str> {
    for part in split_unquoted(command) {
        if let Some(tokens) = shlex::split(&part) {
            if let Some(r) = secret_read_reason_depth(&tokens, depth) {
                return Some(r);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocked(c: &str) -> bool {
        command_reason(c).is_some()
    }

    #[test]
    fn readers_of_protected_paths_block() {
        for c in [
            "cat .env",
            "cat /app/.env.local",
            "grep -r KEY .env",
            "grep -rn TOKEN ~/work/.env.production",
            "grep -e KEY -f .env",
            "head -5 ~/.ssh/id_rsa",
            "tail -n 3 ~/.ssh/id_ed25519",
            "rg secret ~/.aws/credentials",
            "less certs/server.pem",
            "cat server.key",
            "cat config/secrets.json",
            "awk '{print}' secrets.yaml",
            "sed -n 1p .env",
            "sed -e 's/a/b/' .env",
            "jq . secrets.json",
            "jq --arg k v . .env",
            "sed -f.env x.txt",
            "grep -eKEY .env",
            "grep -fpats.txt .env",
            "sed -escript .env",
            "sed -f .env x.txt",
            "sed --file=.env x.txt",
            "diff --from-file=.env x",
            "diff --from-file .env x",
            "diff --to-file=.env x",
            "sort --files0-from=.env",
            "sort --files0-from .env",
            "sort --random-source=.env x",
            "wc --files0-from=.env",
            "awk -i .env 1 x",
            "awk --include .env 1 x",
            "awk --include=.env 1 x",
            "awk -f.env x",
            "grep -f.env KEY",
            "grep --file=.env KEY README.md",
            "grep --exclude-from=.env KEY README.md",
            "grep --exclude-from .env KEY README.md",
            "grep -ef.env README.md",
            "rg --ignore-file .env KEY .",
            "rg --ignore-file=.env KEY .",
            "ag -p .env KEY",
            "ag --path-to-ignore .env KEY",
            "ag -p.env KEY",
            "rsync --exclude-from=.env . /tmp/b",
            "rsync --exclude-from .env . /tmp/b",
            "cp --files-from=.env a b",
            "head -n5 --foo=~/.ssh/id_rsa",
            "cat -Xserver.pem",
            "tail -q.env",
            "jq --rawfile x .env .",
            "jq --slurpfile x secrets.json .",
            "jq --rawfile x ~/.ssh/id_rsa .",
            "jq -e . .env",
            "jq -n --rawfile k server.pem '$k'",
            "jq --rawfile=x .env .",
            "jq . --rawfile x .env",
            "jq --arg a b --rawfile c .env .",
            "grep --color KEY .env",
            "grep -T KEY .env",
            "rg -t py KEY .env",
            "sort -s .env",
            "sort -o /tmp/x .env",
            "paste -s .env",
            "tr a b < .env",
            "uniq -c .env",
            "column -t .env",
            "cat *.pem",
            "cat .env*",
            "cat prod.env",
            "xxd ~/.ssh/id_rsa",
            "cat < .env",
            "cat <.env",
            "cp ~/.ssh/id_rsa /tmp/x",
        ] {
            assert!(blocked(c), "should block: {c}");
        }
    }

    #[test]
    fn compound_pipe_wrapper_and_bash_c_block() {
        for c in [
            "true && cat .env",
            "echo hi; head ~/.ssh/id_rsa",
            "ls | grep foo; tail .env",
            "bash -c 'cat .env'",
            "sh -c \"grep -r K ~/.aws/credentials\"",
            "env FOO=1 cat .env",
            "env -i FOO=1 cat .env",
            "sudo cat ~/.ssh/id_rsa",
            "sudo -u root cat ~/.ssh/id_rsa",
            "nice head .env",
            "nice -n 5 head .env",
            "timeout 5 head .env",
            "timeout -k 2 5 head .env",
            "stdbuf -oL tail .env",
            "ionice -c 3 head .env",
            "nohup cat .env",
            "\\cat .env",
            "/bin/cat .env",
            "bash <<EOF\ncat .env\nEOF",
            "rsync --filter='merge .env' . /tmp/b",
            "rsync --filter='. .env' . /tmp/b",
            "rsync --filter=':- .env' . /tmp/b",
            "rsync --filter ':- .env' . /tmp/b",
            "rsync --filter='dir-merge .env' . /tmp/b",
            "rsync -f'. .env' . /tmp/b",
            "rsync -f '. .env' . /tmp/b",
            "tr a b 0< .env",
            "tr a b 0<.env",
            "cat 0< .env",
            "cat 0<.env",
            "grep KEY 0< .env",
            "awk --source=1 .env",
            "awk -E prog .env",
            "awk -Eprog .env",
            "awk -e 1 .env",
            "awk --source 1 .env",
            "gawk --exec=p .env",
            "awk -i inc.awk .env",
            "awk -f prog.awk .env",
            "awk -f.env 1",
            "rsync --exclude-from=.env . /tmp/b",
            "rsync --include-from=.env . /tmp/b",
            "grep --exclude-from=.env KEY .",
            "grep -if .env KEY",
            "grep -vf .env KEY",
            "grep -rf .env KEY",
            "sed -nf .env x.txt",
            "sed -n -f .env x.txt",
        ] {
            assert!(blocked(c), "should block: {c}");
        }
    }

    #[test]
    fn data_arguments_and_examples_pass() {
        for c in [
            "fleetmail send --to X --subject s --body 'we read .env and id_rsa and server.pem'",
            "echo \"cat .env\"",
            "echo 'a; head .env'",
            "git commit -m 'note; head .env; more'",
            "git commit -m \"rotate secrets.json && cat server.key\"",
            "grep -F '.env' README.md",
            "grep -e '.env' README.md",
            "grep '.env' README.md",
            "rg id_rsa src/",
            "sed -n '/server.pem/p' notes.txt",
            "awk '/secrets.json/' notes.txt",
            "jq --arg note server.pem . data.json",
            "jq '.[] | select(.f == \"server.pem\")' data.json",
            "head <<< '.env'",
            "head <<<'.env'",
            "cat <<EOF\nsee .env and head .env\nEOF",
            "fleetmail send --to X --body-stdin <<'EOF'\nhead .env\ncat server.pem\nEOF",
            "printf 'grep -r K ~/.aws/credentials\\n'",
            "cat .env.example",
            "cat .env.sample",
            "cat README.md",
            "head ~/.ssh/id_rsa.pub",
            "grep credentials README.md",
            "grep --color=auto KEY README.md",
            "grep -A 2 KEY README.md",
            "grep -B2 -A2 KEY README.md",
            "grep -ePAT README.md",
            "rg -g '*.rs' KEY",
            "rg -C 3 KEY src/",
            "rg -t rust KEY src/",
            "sort -t= -k2 notes.txt",
            "sort -o out.txt notes.txt",
            "sed -i.bak 's/a/b/' notes.txt",
            "sed -n 1,5p notes.txt",
            "cut -d= -f1 notes.txt",
            "xxd -l 16 notes.bin",
            "od -An -tx1 notes.bin",
            "jq --arg env prod . data.json",
            "jq --arg a .env . data.json",
            "jq --argjson a 1 . data.json",
            "jq -r .name data.json",
            "tail -f app.log",
            "head -c 100 notes.txt",
            "cut -f1 notes.txt",
            "cat .envrc",
            "ls -la .env",
            "cat notes.txt",
            "rsync --exclude=.env . /tmp/b",
            "rsync -av --exclude='.env*' a b",
            "rsync --exclude .env . /tmp/b",
            "rsync --filter='- .env' . /tmp/b",
            "grep -r --exclude=.env KEY .",
            "grep -r --exclude-dir=.env KEY .",
            "grep -r --include=.env KEY .",
            "diff -x .env a b",
            "diff -x.env a b",
            "diff --exclude=.env a b",
            "rg -g.env KEY",
            "rg --glob=.env KEY",
            "rg -g .env KEY",
            "rg --iglob=.env KEY",
            "rg --type-add=x:.env KEY",
            "cut -d.env -f1 notes.txt",
            "awk -vx=.env 1 notes.txt",
            "awk --assign=x=.env 1 notes.txt",
            "sort -t.env notes.txt",
            "paste -d.env a.txt b.txt",
            "tr a b",
            "tr -d .env",
            "tr a-z A-Z < notes.txt",
            "rsync --filter='- .env' . /tmp/b",
            "rsync --filter='+ .env' . /tmp/b",
            "rsync -f'- .env' . /tmp/b",
            "rsync --filter '- .env' . /tmp/b",
        ] {
            assert!(!blocked(c), "should pass: {c}");
        }
    }

    #[test]
    fn heredoc_body_of_a_non_shell_is_data_but_a_shell_body_is_code() {
        assert!(!blocked("cat <<EOF\nhead .env\nEOF"));
        assert!(blocked("sh <<EOF\nhead .env\nEOF"));
        assert!(blocked("cat <<EOF\nx\nEOF\nhead .env"));
    }
}
