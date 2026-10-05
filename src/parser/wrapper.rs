//! Wrapper command detection and unwrapping
//!
//! Handles commands like sudo, timeout, env, etc. that wrap other commands.

use std::collections::HashSet;

/// Default wrapper commands to detect
pub const DEFAULT_WRAPPERS: &[&str] = &[
    "sudo",
    "timeout",
    "xargs",
    "env",
    "nice",
    "nohup",
    "ionice",
    "strace",
    "time",
    "unbuffer",
    "watch",
    "caffeinate", // macOS
    "doas",       // BSD sudo alternative
];

/// Maximum number of nested executable wrappers.
pub(crate) const MAX_WRAPPER_DEPTH: usize = 128;

/// Extract the actual command without recursion or copying each suffix.
pub fn unwrap_command(command: &str, wrappers: &[String]) -> Result<Vec<String>, &'static str> {
    let wrapper_set: HashSet<&str> = wrappers.iter().map(String::as_str).collect();
    let Some(tokens) = shlex::split(command) else {
        return Ok(vec![command.to_string()]);
    };
    let tokens: Vec<_> = tokens.into_iter().map(Some).collect();
    let mut start = 0;
    let mut depth = 0;
    while let Some(Some(name)) = tokens.get(start) {
        if !wrapper_set.contains(name.as_str()) {
            break;
        }
        depth += 1;
        if depth > MAX_WRAPPER_DEPTH {
            return Err("wrapper depth");
        }
        // The regex backstop keeps uncertain syntax intact. Pipeline policy
        // separately treats unknown wrapper options/names as possible code.
        match wrapped_command_index(name, &tokens[start + 1..]) {
            Ok(Some(index)) => start += index + 1,
            _ => break,
        }
    }
    if start == 0 || start >= tokens.len() {
        Ok(vec![command.to_string()])
    } else {
        Ok(vec![tokens[start..]
            .iter()
            .map(|t| t.as_deref().unwrap_or(""))
            .collect::<Vec<_>>()
            .join(" ")])
    }
}

/// Locate just the wrapped executable. Option operands are data, never commands.
/// None tokens are undecodable shell words. Unknown syntax fails closed.
/// env split-string reparses argv and is deliberately always uncertain.
pub(crate) fn wrapped_command_index(
    wrapper: &str,
    args: &[Option<String>],
) -> Result<Option<usize>, &'static str> {
    let base = wrapper.rsplit('/').next().unwrap_or(wrapper);
    let (no_value, with_value): (&[&str], &[&str]) = match base {
        "env" => (
            &["i", "ignore-environment", "0", "null", "v", "debug"],
            &["u", "unset", "C", "chdir"],
        ),
        "xargs" => (
            &[
                "0",
                "null",
                "r",
                "no-run-if-empty",
                "t",
                "verbose",
                "p",
                "interactive",
                "x",
                "exit",
            ],
            &[
                "n",
                "max-args",
                "L",
                "max-lines",
                "I",
                "replace",
                "E",
                "eof",
                "s",
                "max-chars",
                "P",
                "max-procs",
                "d",
                "delimiter",
                "a",
                "arg-file",
            ],
        ),
        "sudo" | "doas" => (
            &[
                "E",
                "H",
                "P",
                "S",
                "n",
                "b",
                "k",
                "K",
                "preserve-env",
                "non-interactive",
            ],
            &[
                "u",
                "user",
                "g",
                "group",
                "C",
                "close-from",
                "h",
                "host",
                "p",
                "prompt",
            ],
        ),
        "timeout" => (
            &["foreground", "preserve-status", "v", "verbose"],
            &["s", "signal", "k", "kill-after"],
        ),
        "nice" => (&[], &["n", "adjustment"]),
        "ionice" => (
            &["t", "ignore"],
            &[
                "c",
                "class",
                "n",
                "classdata",
                "p",
                "pid",
                "P",
                "pgid",
                "u",
                "uid",
            ],
        ),
        "strace" => (
            &[
                "f", "ff", "t", "tt", "T", "q", "qq", "v", "x", "xx", "y", "yy",
            ],
            &["o", "output", "e", "s", "p", "u"],
        ),
        "time" => (
            &["p", "v", "verbose", "a", "append"],
            &["o", "output", "f", "format"],
        ),
        "watch" => (
            &[
                "x",
                "exec",
                "t",
                "no-title",
                "d",
                "differences",
                "g",
                "chgexit",
                "e",
                "errexit",
                "b",
                "beep",
                "c",
                "color",
                "p",
                "precise",
            ],
            &["n", "interval"],
        ),
        "caffeinate" => (&["d", "i", "m", "s", "u"], &["t", "w"]),
        "nohup" | "unbuffer" => (&[], &[]),
        _ => return Err("unknown wrapper"),
    };
    let mut i = 0;
    while i < args.len() {
        let value = args[i].as_deref().ok_or("dynamic wrapper argument")?;
        if value == "--" {
            i += 1;
            break;
        }
        if base == "env" && value.contains('=') && !value.starts_with('-') {
            i += 1;
            continue;
        }
        if !value.starts_with('-') || value == "-" {
            break;
        }
        if let Some(long) = value.strip_prefix("--") {
            let (flag, attached) = long
                .split_once('=')
                .map_or((long, false), |(f, _)| (f, true));
            if with_value.contains(&flag) {
                if !attached {
                    i += 1;
                    if i >= args.len() {
                        return Err("missing option operand");
                    }
                }
            } else if !no_value.contains(&flag) || attached {
                return Err("unknown wrapper option");
            }
        } else {
            let flags = value[1..].char_indices();
            for (offset, ch) in flags {
                let flag = ch.to_string();
                if with_value.contains(&flag.as_str()) {
                    if offset + ch.len_utf8() == value.len() - 1 {
                        i += 1;
                        if i >= args.len() {
                            return Err("missing option operand");
                        }
                    }
                    break;
                }
                if !no_value.contains(&flag.as_str()) {
                    return Err("unknown wrapper option");
                }
            }
        }
        i += 1;
    }
    if base == "timeout" {
        // The duration is an operand, not the executable.
        if i >= args.len() || args[i].is_none() {
            return Err("missing duration");
        }
        i += 1;
    }
    if base == "timeout" && i >= args.len() {
        return Err("missing executable");
    }
    Ok((i < args.len()).then_some(i))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_wrappers() -> Vec<String> {
        DEFAULT_WRAPPERS.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_unwrap_sudo() {
        let wrappers = default_wrappers();

        let result = unwrap_command("sudo rm -rf /", &wrappers).unwrap();
        assert_eq!(result, vec!["rm -rf /"]);

        let result = unwrap_command("sudo -u root rm -rf /", &wrappers).unwrap();
        assert_eq!(result, vec!["rm -rf /"]);

        let result = unwrap_command("sudo -E -H ls -la", &wrappers).unwrap();
        assert_eq!(result, vec!["ls -la"]);
    }

    #[test]
    fn test_unwrap_timeout() {
        let wrappers = default_wrappers();

        let result = unwrap_command("timeout 30 rm -rf /", &wrappers).unwrap();
        assert_eq!(result, vec!["rm -rf /"]);

        let result = unwrap_command("timeout -s KILL 60 command arg", &wrappers).unwrap();
        assert_eq!(result, vec!["command arg"]);
    }

    #[test]
    fn test_unwrap_env() {
        let wrappers = default_wrappers();

        let result = unwrap_command("env VAR=val command arg", &wrappers).unwrap();
        assert_eq!(result, vec!["command arg"]);

        let result = unwrap_command("env -i PATH=/bin command", &wrappers).unwrap();
        assert_eq!(result, vec!["command"]);
    }

    #[test]
    fn test_unwrap_nested() {
        let wrappers = default_wrappers();

        let result = unwrap_command("sudo timeout 30 rm -rf /", &wrappers).unwrap();
        assert_eq!(result, vec!["rm -rf /"]);

        let result = unwrap_command("sudo nice -n 10 nohup command arg", &wrappers).unwrap();
        assert_eq!(result, vec!["command arg"]);
    }

    #[test]
    fn test_unwrap_no_wrapper() {
        let wrappers = default_wrappers();

        let result = unwrap_command("rm -rf /", &wrappers).unwrap();
        assert_eq!(result, vec!["rm -rf /"]);

        let result = unwrap_command("git status", &wrappers).unwrap();
        assert_eq!(result, vec!["git status"]);
    }

    #[test]
    fn test_unwrap_nohup() {
        let wrappers = default_wrappers();

        let result = unwrap_command("nohup command arg &", &wrappers).unwrap();
        assert_eq!(result, vec!["command arg &"]);
    }

    #[test]
    fn test_unwrap_xargs() {
        let wrappers = default_wrappers();

        let result = unwrap_command("xargs rm -f", &wrappers).unwrap();
        assert_eq!(result, vec!["rm -f"]);

        let result = unwrap_command("xargs -n 1 echo", &wrappers).unwrap();
        assert_eq!(result, vec!["echo"]);
    }
}
