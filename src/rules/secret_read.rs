//! Reader commands pointed at protected secret paths (servitor-w8ys)
//!
//! The regex rules only ever caught `cat .env` / `cat ~/.ssh/id_rsa`; `grep -r`, `head`,
//! `tail`, `rg`, `less`, `awk`, `sed` … and `cat` of `*.pem` / `secrets.json` went
//! through. This works on TOKENS, not text: a command is a violation when its program
//! is a reader and one of its own arguments (or an input redirect) names a protected
//! path. The same filenames inside the quoted argument of some other command, such as
//! a mail `--body`, are not that command's file operands and pass.

/// Programs that print or search file contents.
const READERS: &[&str] = &[
    "cat", "tac", "nl", "less", "more", "most", "head", "tail", "grep", "egrep", "fgrep", "rg",
    "ag", "ack", "awk", "gawk", "mawk", "sed", "cut", "sort", "uniq", "tr", "xxd", "od", "hexdump",
    "strings", "base64", "bat", "batcat", "jq", "yq", "diff", "cmp", "paste", "fold", "fmt",
    "column", "rev", "cp", "scp", "rsync", "zcat", "open", "pbcopy",
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

fn segment_reason(seg: &[String], depth: u8) -> Option<&'static str> {
    // Skip leading VAR=val assignments and a few transparent prefixes.
    let mut i = 0;
    while i < seg.len() {
        let t = seg[i].as_str();
        let assignment = t.contains('=') && !t.starts_with('-') && !t.contains('/');
        if assignment
            || matches!(
                t,
                "command" | "builtin" | "exec" | "nohup" | "time" | "sudo" | "env"
            )
        {
            i += 1;
        } else {
            break;
        }
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
        // `< .env cat` style: input redirect on any program that is itself a reader is
        // handled above; a redirect into a non-reader is not a read of the file by it.
        return None;
    }
    if args.iter().any(|a| is_protected_path(a)) {
        return Some(REASON);
    }
    None
}

/// Split `text` at `;`, `&`, `|` and newlines that are outside quotes.
fn split_unquoted(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let (mut single, mut double, mut escaped) = (false, false, false);
    for ch in text.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
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
            ';' | '&' | '|' | '\n' if !single && !double => {
                parts.push(std::mem::take(&mut cur));
            }
            _ => cur.push(ch),
        }
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
            "head -5 ~/.ssh/id_rsa",
            "tail -n 3 ~/.ssh/id_ed25519",
            "rg secret ~/.aws/credentials",
            "less certs/server.pem",
            "cat server.key",
            "cat config/secrets.json",
            "awk '{print}' secrets.yaml",
            "sed -n 1p .env",
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
    fn compound_pipe_and_bash_c_block() {
        for c in [
            "true && cat .env",
            "echo hi; head ~/.ssh/id_rsa",
            "ls | grep foo; tail .env",
            "bash -c 'cat .env'",
            "sh -c \"grep -r K ~/.aws/credentials\"",
            "env FOO=1 cat .env",
            "sudo cat ~/.ssh/id_rsa",
            "\\cat .env",
            "/bin/cat .env",
        ] {
            assert!(blocked(c), "should block: {c}");
        }
    }

    #[test]
    fn data_arguments_and_examples_pass() {
        for c in [
            "fleetmail send --to X --subject s --body 'we read .env and id_rsa and server.pem'",
            "echo \"cat .env\"",
            "printf 'grep -r K ~/.aws/credentials\\n'",
            "git commit -m 'rotate secrets.json and .env'",
            "cat .env.example",
            "cat .env.sample",
            "cat README.md",
            "head ~/.ssh/id_rsa.pub",
            "grep credentials README.md",
            "cat .envrc",
            "ls -la .env",
            "cat notes.txt",
        ] {
            assert!(!blocked(c), "should pass: {c}");
        }
    }
}
