//! Security packs: namespaced groupings of rules that can be toggled as a unit.
//!
//! Every rule belongs to exactly one pack (via [`pack_of`]). Packs give the user
//! coarse, per-project control (disable `containers.docker` if you don't use
//! Docker) without touching Rust. Catastrophic-protection packs are `always_on`
//! and ignore the disable list — you can't foot-gun away `rm -rf /` protection.
//!
//! This is purely organizational: with nothing disabled, the active rule set is
//! byte-identical to the pre-pack behavior (verified by replay over the corpus).

/// Metadata for one pack, surfaced by `guardrails packs`.
pub struct PackInfo {
    pub name: &'static str,
    pub description: &'static str,
    /// Cannot be disabled (catastrophic / core protection).
    pub always_on: bool,
}

/// The full pack registry.
pub const ALL_PACKS: &[PackInfo] = &[
    PackInfo {
        name: "core.filesystem",
        description: "Catastrophic filesystem/disk destruction (rm -rf /, dd, mkfs, fork bombs)",
        always_on: true,
    },
    PackInfo {
        name: "core.rce",
        description: "Remote code execution (curl|sh, reverse shells)",
        always_on: true,
    },
    PackInfo {
        name: "core.exec",
        description: "Dynamic/interpreter code execution (eval, python -c, sh -c)",
        always_on: true,
    },
    PackInfo {
        name: "core.git",
        description: "Destructive git (reset --hard, force push, clean -fd)",
        always_on: false,
    },
    PackInfo {
        name: "core.secrets",
        description: "Secret exposure in commands (echo $API_KEY, env dump, cat .env)",
        always_on: false,
    },
    PackInfo {
        name: "core.perms",
        description: "Dangerous permissions (chmod 777)",
        always_on: false,
    },
    PackInfo {
        name: "containers.docker",
        description: "Docker (privileged, host mount, system prune)",
        always_on: false,
    },
    PackInfo {
        name: "system",
        description: "System ops (sudo rm, killall, history -c, npm cache clean)",
        always_on: false,
    },
    PackInfo {
        name: "database",
        description: "Database destruction (DROP DATABASE, TRUNCATE TABLE)",
        always_on: false,
    },
    PackInfo {
        name: "secrets.files",
        description: "Protected credential file paths (.env, SSH keys, .pem)",
        always_on: true,
    },
    PackInfo {
        name: "exfil",
        description: "Exfiltration of secrets (curl upload, scp .env, /dev/tcp)",
        always_on: true,
    },
];

/// Map a rule id to its pack. Unknown ids fall back to `core.misc` (always active).
pub fn pack_of(id: &str) -> &'static str {
    match id {
        // core.filesystem — catastrophic destruction
        "rm-root" | "rm-home" | "rm-system-dirs" | "rm-wildcard-root" | "rm-boot" | "rm-kernel"
        | "rm-rf-star" | "dd-disk-device" | "mkfs-device" | "fdisk-write" | "fork-bomb"
        | "fork-bomb-alt" => "core.filesystem",

        // core.rce — remote code execution
        "curl-pipe-sh" | "curl-pipe-bash" | "curl-pipe-zsh" | "curl-pipe-python"
        | "bash-c-curl-pipe" | "reverse-shell-bash" | "reverse-shell-nc" => "core.rce",

        // core.exec — dynamic / interpreter execution
        "bash-c-dangerous" | "bash-c-rm-home" | "python-c-os-system" | "node-e-exec"
        | "perl-e-system" | "ruby-e-system" | "eval-variable" | "eval-command-sub"
        | "sudo-bash-c" => "core.exec",

        // core.git
        "git-force-main" | "git-force-main-alt" | "git-reset-hard" | "git-clean-force"
        | "git-force-any" => "core.git",

        // core.secrets — secret exposure in commands
        "echo-secret-env" | "printenv-all" | "env-dump" | "cat-env-file" | "cat-ssh-key" => {
            "core.secrets"
        }

        // core.perms
        "chmod-777" | "chmod-recursive-permissive" => "core.perms",

        // containers.docker
        "docker-privileged"
        | "docker-host-mount"
        | "docker-system-prune"
        | "docker-image-prune" => "containers.docker",

        // system
        "sudo-rm" | "killall" | "pkill-all" | "history-clear" | "npm-cache-clean" => "system",

        // database
        "drop-database" | "truncate-table" => "database",

        // secrets.files — file-path secret rules
        "env-file" | "env-local" | "env-production" | "ssh-private-key" | "aws-credentials"
        | "kube-config" | "pem-file" | "p12-file" | "key-file" | "credentials-json"
        | "secrets-file" | "docker-config" | "netrc" | "npmrc" | "pypirc" | "pgpass" | "my-cnf"
        | "gcp-credentials" | "azure-profile" | "github-token" | "gnupg-keyring"
        | "config-with-auth" | "htpasswd" | "shadow" | "passwd" => "secrets.files",

        // exfil — everything in exfiltration.rs is prefixed distinctively
        id if is_exfil(id) => "exfil",

        _ => "core.misc",
    }
}

/// Exfiltration rule ids (from exfiltration.rs).
fn is_exfil(id: &str) -> bool {
    id.starts_with("curl-upload")
        || id.starts_with("scp-")
        || id.starts_with("rsync-")
        || id.starts_with("nc-exfil")
        || id.starts_with("base64-")
        || id.starts_with("wget-")
        || id.starts_with("dev-tcp")
        || id.starts_with("dev-udp")
        || id.starts_with("dns-exfil")
        || id.starts_with("dig-exfil")
        || id.starts_with("tar-")
        || id == "curl-data-binary"
        || id.starts_with("aws-s3-cp")
}

/// Whether `pack` is disabled given the config's disable list. Always-on packs
/// are never disabled. A disable entry matches the exact pack or its namespace
/// prefix (`containers` disables `containers.docker`).
pub fn is_disabled(pack: &str, disabled: &[String]) -> bool {
    // The unmapped-rule fallback is never disableable, so a future dangerous rule
    // whose id isn't yet in `pack_of` can't be silently turned off via `["core"]`.
    if pack == "core.misc" {
        return false;
    }
    if ALL_PACKS.iter().any(|p| p.name == pack && p.always_on) {
        return false;
    }
    disabled
        .iter()
        .any(|d| pack == d || pack.starts_with(&format!("{}.", d)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_ids_mapped() {
        assert_eq!(pack_of("rm-root"), "core.filesystem");
        assert_eq!(pack_of("git-reset-hard"), "core.git");
        assert_eq!(pack_of("docker-privileged"), "containers.docker");
        assert_eq!(pack_of("drop-database"), "database");
        assert_eq!(pack_of("env-file"), "secrets.files");
        assert_eq!(pack_of("dev-tcp-write"), "exfil");
        assert_eq!(pack_of("curl-upload-env"), "exfil");
    }

    #[test]
    fn test_unknown_id_is_misc() {
        assert_eq!(pack_of("totally-new-rule"), "core.misc");
    }

    #[test]
    fn test_always_on_cannot_be_disabled() {
        assert!(!is_disabled(
            "core.filesystem",
            &["core.filesystem".to_string()]
        ));
        assert!(!is_disabled("exfil", &["exfil".to_string()]));
    }

    #[test]
    fn test_disable_exact_and_namespace() {
        assert!(is_disabled(
            "containers.docker",
            &["containers.docker".to_string()]
        ));
        assert!(is_disabled(
            "containers.docker",
            &["containers".to_string()]
        ));
        assert!(is_disabled("database", &["database".to_string()]));
        assert!(!is_disabled("core.git", &["database".to_string()]));
    }

    #[test]
    fn test_nothing_disabled_by_default() {
        for p in ALL_PACKS {
            assert!(
                !is_disabled(p.name, &[]),
                "{} disabled with empty list",
                p.name
            );
        }
    }
}
