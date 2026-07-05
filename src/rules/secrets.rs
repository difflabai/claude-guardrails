//! Secrets detection rules for file operations
//!
//! Defines patterns for files that commonly contain secrets.

use crate::config::SafetyLevel;
use crate::rules::Rule;

/// Critical secrets - direct credential files
pub const CRITICAL_SECRET_PATTERNS: &[Rule] = &[
    Rule::new(
        "env-file",
        SafetyLevel::Critical,
        r"\.env$",
        "Environment file may contain secrets",
    ),
    Rule::new(
        "env-local",
        SafetyLevel::Critical,
        r"\.env\.local$",
        "Local environment file may contain secrets",
    ),
    Rule::new(
        "env-production",
        SafetyLevel::Critical,
        r"\.env\.production$",
        "Production environment file contains secrets",
    ),
    Rule::new(
        "ssh-private-key",
        SafetyLevel::Critical,
        r"\.ssh/id_(rsa|ed25519|ecdsa|dsa)$",
        "SSH private key file",
    ),
    Rule::new(
        "aws-credentials",
        SafetyLevel::Critical,
        r"\.aws/credentials$",
        "AWS credentials file",
    ),
    Rule::new(
        "kube-config",
        SafetyLevel::Critical,
        r"\.kube/config$",
        "Kubernetes config with credentials",
    ),
    Rule::new(
        "pem-file",
        SafetyLevel::Critical,
        r"\.pem$",
        "PEM certificate/key file",
    ),
    Rule::new(
        "p12-file",
        SafetyLevel::Critical,
        r"\.p12$",
        "PKCS#12 certificate file",
    ),
    Rule::new(
        "key-file",
        SafetyLevel::Critical,
        r"\.key$",
        "Private key file",
    ),
];

/// High level secrets - config files that may contain credentials
pub const HIGH_SECRET_PATTERNS: &[Rule] = &[
    Rule::new(
        "credentials-json",
        SafetyLevel::High,
        r"credentials\.json$",
        "Credentials configuration file",
    ),
    Rule::new(
        "secrets-file",
        SafetyLevel::High,
        r"secrets?\.(json|ya?ml|toml)$",
        "Secrets configuration file",
    ),
    Rule::new(
        "docker-config",
        SafetyLevel::High,
        r"\.docker/config\.json$",
        "Docker registry credentials",
    ),
    Rule::new(
        "netrc",
        SafetyLevel::High,
        r"\.netrc$",
        "Network credentials file",
    ),
    Rule::new(
        "npmrc",
        SafetyLevel::High,
        r"\.npmrc$",
        "npm authentication tokens",
    ),
    Rule::new(
        "pypirc",
        SafetyLevel::High,
        r"\.pypirc$",
        "PyPI authentication file",
    ),
    Rule::new(
        "pgpass",
        SafetyLevel::High,
        r"\.pgpass$",
        "PostgreSQL password file",
    ),
    Rule::new(
        "my-cnf",
        SafetyLevel::High,
        r"\.my\.cnf$",
        "MySQL credentials file",
    ),
    Rule::new(
        "gcp-credentials",
        SafetyLevel::High,
        r"gcloud/credentials\.db$",
        "GCP credentials database",
    ),
    Rule::new(
        "azure-profile",
        SafetyLevel::High,
        r"\.azure/accessTokens\.json$",
        "Azure access tokens",
    ),
    Rule::new(
        "github-token",
        SafetyLevel::High,
        r"\.github/token$",
        "GitHub token file",
    ),
    Rule::new(
        "gnupg-keyring",
        SafetyLevel::High,
        r"\.gnupg/(secring|private-keys)",
        "GPG private keyring",
    ),
];

/// Strict level secrets - files that might contain secrets
pub const STRICT_SECRET_PATTERNS: &[Rule] = &[
    Rule::new(
        "config-with-auth",
        SafetyLevel::Strict,
        r"(config|settings)\.(json|ya?ml|toml)$",
        "Configuration file may contain credentials",
    ),
    Rule::new(
        "htpasswd",
        SafetyLevel::Strict,
        r"\.htpasswd$",
        "Apache password file",
    ),
    Rule::new(
        "shadow",
        SafetyLevel::Strict,
        r"/etc/shadow$",
        "System password hashes",
    ),
    Rule::new(
        "passwd",
        SafetyLevel::Strict,
        r"/etc/passwd$",
        "System user database",
    ),
];

/// Get all secret patterns up to and including the specified safety level
pub fn get_secret_patterns_for_level(level: SafetyLevel) -> Vec<&'static Rule> {
    let mut rules = Vec::new();

    rules.extend(CRITICAL_SECRET_PATTERNS.iter());

    if level.includes(SafetyLevel::High) {
        rules.extend(HIGH_SECRET_PATTERNS.iter());
    }

    if level.includes(SafetyLevel::Strict) {
        rules.extend(STRICT_SECRET_PATTERNS.iter());
    }

    rules
}

/// Secret patterns active for `level` after removing disabled packs. Order-
/// preserving vs `get_secret_patterns_for_level`; equals it when `disabled` is
/// empty. (The `secrets.files` pack is always-on, so this only changes if a
/// future secrets pack is made toggleable.)
pub fn active_patterns_for_level(level: SafetyLevel, disabled: &[String]) -> Vec<&'static Rule> {
    get_secret_patterns_for_level(level)
        .into_iter()
        .filter(|r| !crate::rules::packs::is_disabled(crate::rules::packs::pack_of(r.id), disabled))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    #[test]
    fn test_all_patterns_compile() {
        for rule in CRITICAL_SECRET_PATTERNS
            .iter()
            .chain(HIGH_SECRET_PATTERNS.iter())
            .chain(STRICT_SECRET_PATTERNS.iter())
        {
            let result = Regex::new(rule.pattern);
            assert!(
                result.is_ok(),
                "Rule {} has invalid pattern: {}",
                rule.id,
                rule.pattern
            );
        }
    }

    #[test]
    fn test_env_file_matches() {
        let re = Regex::new(r"\.env$").unwrap();
        assert!(re.is_match(".env"));
        assert!(re.is_match("/path/to/.env"));
        assert!(!re.is_match(".env.example"));
        assert!(!re.is_match(".envrc"));
    }

    #[test]
    fn test_ssh_key_matches() {
        let re = Regex::new(r"\.ssh/id_(rsa|ed25519|ecdsa|dsa)$").unwrap();
        assert!(re.is_match("/home/user/.ssh/id_rsa"));
        assert!(re.is_match("~/.ssh/id_ed25519"));
        assert!(!re.is_match("~/.ssh/id_rsa.pub"));
    }

    #[test]
    fn test_pem_file_matches() {
        let re = Regex::new(r"\.pem$").unwrap();
        assert!(re.is_match("server.pem"));
        assert!(re.is_match("/path/to/cert.pem"));
    }
}
