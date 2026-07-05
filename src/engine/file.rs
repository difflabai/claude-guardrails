//! File operation security checking
//!
//! Checks Read/Edit/Write operations for access to sensitive files.

use crate::config::SafetyLevel;
use crate::output::Decision;
use crate::rules::secrets;

use regex::RegexSet;

/// Check a file path for security issues. `disabled` must match the pack-filter
/// used to compile `rules`, so match indices map to the correct rule.
pub fn check_path(
    file_path: &str,
    safety_level: SafetyLevel,
    rules: &RegexSet,
    disabled: &[String],
) -> Decision {
    // Normalize the path for matching
    let normalized = normalize_path(file_path);

    // Check against secret patterns
    let matches: Vec<usize> = rules.matches(&normalized).iter().collect();

    if matches.is_empty() {
        return Decision::allow("file path passed all checks");
    }

    // Get the matching rules (same pack-filtered list used to build `rules`)
    let all_rules = secrets::active_patterns_for_level(safety_level, disabled);

    for idx in matches {
        if idx < all_rules.len() {
            let rule = all_rules[idx];
            return Decision::deny(rule.id, rule.reason);
        }
    }

    Decision::allow("no matching rule found")
}

/// Normalize a file path for pattern matching
fn normalize_path(path: &str) -> String {
    // Expand ~ to home directory representation
    if path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            return format!("{}{}", home.display(), &path[1..]);
        }
    }

    path.to_string()
}

/// Check if a file path matches any of the protected patterns
pub fn is_protected_path(file_path: &str, patterns: &[String]) -> Option<String> {
    let normalized = normalize_path(file_path);

    for pattern in patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if re.is_match(&normalized) {
                return Some(pattern.clone());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile_rules(safety_level: SafetyLevel) -> RegexSet {
        let patterns: Vec<&str> = secrets::get_secret_patterns_for_level(safety_level)
            .iter()
            .map(|r| r.pattern)
            .collect();
        RegexSet::new(&patterns).unwrap()
    }

    #[test]
    fn test_env_file_blocked() {
        let rules = compile_rules(SafetyLevel::High);
        let decision = check_path(".env", SafetyLevel::High, &rules, &[]);
        assert!(decision.is_deny());
    }

    #[test]
    fn test_env_file_with_path_blocked() {
        let rules = compile_rules(SafetyLevel::High);
        let decision = check_path("/path/to/project/.env", SafetyLevel::High, &rules, &[]);
        assert!(decision.is_deny());
    }

    #[test]
    fn test_env_example_allowed() {
        let rules = compile_rules(SafetyLevel::High);
        let decision = check_path(".env.example", SafetyLevel::High, &rules, &[]);
        // .env.example should be allowed (doesn't match .env$)
        assert!(decision.is_allow());
    }

    #[test]
    fn test_ssh_key_blocked() {
        let rules = compile_rules(SafetyLevel::High);
        let decision = check_path("/home/user/.ssh/id_rsa", SafetyLevel::High, &rules, &[]);
        assert!(decision.is_deny());
    }

    #[test]
    fn test_ssh_pub_key_allowed() {
        let rules = compile_rules(SafetyLevel::High);
        let decision = check_path("/home/user/.ssh/id_rsa.pub", SafetyLevel::High, &rules, &[]);
        // Public keys should be allowed (pattern is for private keys)
        assert!(decision.is_allow());
    }

    #[test]
    fn test_aws_credentials_blocked() {
        let rules = compile_rules(SafetyLevel::High);
        let decision = check_path(
            "/home/user/.aws/credentials",
            SafetyLevel::High,
            &rules,
            &[],
        );
        assert!(decision.is_deny());
    }

    #[test]
    fn test_normal_file_allowed() {
        let rules = compile_rules(SafetyLevel::High);

        let decision = check_path("README.md", SafetyLevel::High, &rules, &[]);
        assert!(decision.is_allow());

        let decision = check_path(
            "/path/to/project/src/main.rs",
            SafetyLevel::High,
            &rules,
            &[],
        );
        assert!(decision.is_allow());

        let decision = check_path("package.json", SafetyLevel::High, &rules, &[]);
        assert!(decision.is_allow());
    }

    #[test]
    fn test_pem_file_blocked() {
        let rules = compile_rules(SafetyLevel::High);
        let decision = check_path("/path/to/server.pem", SafetyLevel::High, &rules, &[]);
        assert!(decision.is_deny());
    }

    #[test]
    fn test_kube_config_blocked() {
        let rules = compile_rules(SafetyLevel::High);
        let decision = check_path("/home/user/.kube/config", SafetyLevel::High, &rules, &[]);
        assert!(decision.is_deny());
    }

    #[test]
    fn test_docker_config_blocked() {
        let rules = compile_rules(SafetyLevel::High);
        let decision = check_path(
            "/home/user/.docker/config.json",
            SafetyLevel::High,
            &rules,
            &[],
        );
        assert!(decision.is_deny());
    }

    #[test]
    fn test_normalize_path() {
        // Without home dir expansion, just verify basic behavior
        let normalized = normalize_path("/path/to/file");
        assert_eq!(normalized, "/path/to/file");
    }
}
