//! Self-protection: the guardrail guards itself.
//!
//! A YOLO-mode agent that can edit the hook registration or overwrite/delete the
//! guardrail binary can disable every other check. v1 had no defense here. These
//! checks are always-on (independent of safety level) and fail-closed.
//!
//! Two tiers:
//!   - **Install** (`~/.claude/guardrails/**`, `/etc/claude-guardrails/**`): any
//!     Edit/Write is denied outright — there's no legitimate reason for an agent
//!     to rewrite the guardrail's own binary or config.
//!   - **Settings** (`~/.claude/settings*.json`): *content-aware*. Only edits that
//!     touch the guardrail's hook registration (the string `guardrails`) are
//!     denied; all other config edits pass. This is what lets normal settings work
//!     through while still blocking hook removal — the replay found 24 legitimate
//!     settings edits that a blanket block would have broken.
//!
//! Reading any of these paths stays allowed — inspection is fine, tampering is not.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::output::Decision;

/// The guardrail's own install locations — mutation is denied unconditionally.
const INSTALL_PATHS: &[&str] = &[r"\.claude/guardrails/", r"/etc/claude-guardrails/"];

/// Marker that a settings edit touches the guardrail's hook. The hook command is
/// `~/.claude/guardrails/claude-guardrails`, so any line registering, altering, or
/// removing it contains this substring.
const HOOK_MARKER: &str = "guardrails";

/// Matches a Claude Code settings file path.
static SETTINGS_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\.claude/settings[^/]*\.json$").unwrap());

/// Mutating shell verbs that, applied to a self path, tamper with the guardrail.
static BASH_TAMPER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?x)
        \b(rm|unlink|shred|mv|cp|install|truncate|chmod|chown|dd|tee|sed\s+-i|ln)\b
        [^|;&]*
        (\.claude/(settings[^/]*\.json|guardrails/)|/etc/claude-guardrails/)
        ",
    )
    .unwrap()
});

/// Redirection (`>`, `>>`) onto a self path — overwrites settings or the binary.
static BASH_REDIRECT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r">>?\s*\S*(\.claude/(settings[^/]*\.json|guardrails/)|/etc/claude-guardrails/)")
        .unwrap()
});

/// Attempt to set the disable/bypass env var — a tampering signal.
static DISABLE_ENV: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bGUARDRAILS_(DISABLED|WARN_ONLY)\s*=").unwrap());

/// Guardrail install paths, precompiled.
static INSTALL_RES: Lazy<Vec<Regex>> = Lazy::new(|| {
    INSTALL_PATHS
        .iter()
        .map(|p| Regex::new(p).unwrap())
        .collect()
});

/// Check a bash command for guardrail self-tampering. Always-on, fail-closed.
pub fn check_bash(command: &str) -> Option<Decision> {
    if BASH_TAMPER.is_match(command) || BASH_REDIRECT.is_match(command) {
        return Some(Decision::deny(
            "self-protect-mutate",
            "Modifying the guardrail's hook settings or binary is blocked",
        ));
    }
    if DISABLE_ENV.is_match(command) {
        return Some(Decision::deny(
            "self-protect-disable",
            "Setting GUARDRAILS_DISABLED/WARN_ONLY to bypass the guardrail is blocked",
        ));
    }
    None
}

/// Check a file operation against the guardrail *install* paths. Only mutating
/// tools (Edit/Write) are blocked; Read is allowed. This is the unconditional
/// tier — no content-aware exception for the binary or its config.
pub fn check_install(tool: &str, file_path: &str) -> Option<Decision> {
    let mutating = matches!(tool, "Edit" | "Write" | "NotebookEdit");
    if !mutating {
        return None;
    }
    let normalized = expand_home(file_path);
    if INSTALL_RES.iter().any(|re| re.is_match(&normalized)) {
        return Some(Decision::deny(
            "self-protect-install",
            "Editing the guardrail's own binary or config is blocked",
        ));
    }
    None
}

/// Content-aware check for `settings*.json`. Returns a deny only when the edit
/// touches the guardrail hook registration; other settings edits pass through.
///
/// - `edit`: `(old_string, new_string)` for the Edit tool.
/// - `content`: full new file content for the Write tool.
pub fn check_settings(
    file_path: &str,
    edit: Option<(&str, &str)>,
    content: Option<&str>,
) -> Option<Decision> {
    let normalized = expand_home(file_path);
    if !SETTINGS_RE.is_match(&normalized) {
        return None;
    }

    let touches_hook = match (edit, content) {
        // Edit: block if either side of the change mentions the hook.
        (Some((old, new)), _) => old.contains(HOOK_MARKER) || new.contains(HOOK_MARKER),
        // Write: block only if the current file registers the hook and the new
        // content drops it (i.e. this write removes the guardrail).
        (None, Some(new_content)) => {
            let current = std::fs::read_to_string(&normalized).unwrap_or_default();
            current.contains(HOOK_MARKER) && !new_content.contains(HOOK_MARKER)
        }
        (None, None) => false,
    };

    if touches_hook {
        return Some(Decision::deny(
            "self-protect-hook",
            "This settings edit removes or alters the guardrail's own hook registration",
        ));
    }
    None
}

fn expand_home(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return format!("{}/{}", home.display(), rest);
        }
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rm_binary_blocked() {
        assert!(check_bash("rm ~/.claude/guardrails/claude-guardrails").is_some());
        assert!(check_bash("rm -f /etc/claude-guardrails/config.toml").is_some());
    }

    #[test]
    fn test_redirect_settings_blocked() {
        assert!(check_bash("echo '{}' > ~/.claude/settings.json").is_some());
        assert!(check_bash("cat x >> ~/.claude/settings.local.json").is_some());
    }

    #[test]
    fn test_sed_settings_blocked() {
        assert!(check_bash("sed -i 's/hook//' ~/.claude/settings.json").is_some());
    }

    #[test]
    fn test_disable_env_blocked() {
        assert!(check_bash("export GUARDRAILS_DISABLED=1").is_some());
        assert!(check_bash("GUARDRAILS_WARN_ONLY=1 something").is_some());
    }

    #[test]
    fn test_reading_settings_allowed() {
        assert!(check_bash("cat ~/.claude/settings.json").is_none());
        assert!(check_bash("grep hooks ~/.claude/settings.json").is_none());
    }

    #[test]
    fn test_unrelated_command_allowed() {
        assert!(check_bash("rm -rf ./node_modules").is_none());
        assert!(check_bash("git commit -m x").is_none());
    }

    #[test]
    fn test_install_edit_blocked() {
        assert!(check_install("Write", "~/.claude/guardrails/config.toml").is_some());
        assert!(check_install("Edit", "/etc/claude-guardrails/config.toml").is_some());
    }

    #[test]
    fn test_install_read_allowed() {
        assert!(check_install("Read", "~/.claude/guardrails/config.toml").is_none());
    }

    #[test]
    fn test_install_normal_file_allowed() {
        assert!(check_install("Edit", "/home/user/project/src/main.rs").is_none());
        assert!(check_install("Write", "README.md").is_none());
    }

    #[test]
    fn test_settings_edit_touching_hook_blocked() {
        // Editing the guardrails hook line out of settings → blocked.
        let d = check_settings(
            "~/.claude/settings.json",
            Some((
                "\"command\": \"~/.claude/guardrails/claude-guardrails\"",
                "",
            )),
            None,
        );
        assert!(d.is_some());
        assert_eq!(d.unwrap().rule_id(), Some("self-protect-hook"));
    }

    #[test]
    fn test_settings_edit_unrelated_allowed() {
        // A normal settings edit that doesn't touch the hook → allowed.
        let d = check_settings(
            "~/.claude/settings.json",
            Some(("\"theme\": \"dark\"", "\"theme\": \"light\"")),
            None,
        );
        assert!(d.is_none(), "unrelated settings edit must pass");
    }

    #[test]
    fn test_settings_write_removing_hook_blocked() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join(".claude");
        std::fs::create_dir_all(&sub).unwrap();
        let path = sub.join("settings.json");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(f, "{{\"hooks\": {{\"cmd\": \"guardrails\"}}}}").unwrap();

        let p = path.to_string_lossy().to_string();
        // New content drops the guardrails hook → blocked.
        assert!(check_settings(&p, None, Some("{\"hooks\": {}}")).is_some());
        // New content keeps it → allowed.
        assert!(check_settings(
            &p,
            None,
            Some("{\"hooks\": {\"cmd\": \"guardrails\"}, \"x\": 1}")
        )
        .is_none());
    }

    #[test]
    fn test_non_settings_file_ignored() {
        assert!(check_settings("~/project/config.json", Some(("guardrails", "")), None).is_none());
    }
}
