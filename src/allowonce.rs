//! Allow-once: single-use, time-limited exceptions via short codes.
//!
//! When a command is blocked but the user knows it's safe, they get a short code
//! and run `guardrails allow-once <code>` to grant a one-shot, 24h exception —
//! instead of the nuclear option of disabling the guardrail entirely. The code is
//! derived deterministically from the command (HMAC-SHA256 when a secret is set,
//! plain SHA-256 otherwise), so the grant re-links to the exact command on its
//! next evaluation without the store ever holding the command text.
//!
//! Clean-room implementation. The short-code/pending-grant *concept* is a common
//! pattern; none of this code is copied from any other project.

use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Env var holding an optional secret. When set, codes can't be forged.
const SECRET_ENV: &str = "GUARDRAILS_ALLOW_ONCE_SECRET";
const STORE_FILE: &str = "allow_once.jsonl";
const TTL_HOURS: i64 = 24;

/// A granted one-shot exception (one JSONL line).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    /// Short code = derived from the command being excepted.
    pub code: String,
    /// RFC 3339 expiry timestamp.
    pub expires_at: String,
    /// Whether this grant has already been used.
    #[serde(default)]
    pub consumed: bool,
}

/// Derive the 6-hex-char short code for a command.
pub fn code_for(command: &str) -> String {
    let full = match std::env::var(SECRET_ENV) {
        Ok(secret) if !secret.is_empty() => {
            let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
                .expect("HMAC accepts any key length");
            mac.update(command.as_bytes());
            hex(&mac.finalize().into_bytes())
        }
        _ => {
            let mut hasher = Sha256::new();
            hasher.update(command.as_bytes());
            hex(&hasher.finalize())
        }
    };
    full[..8].to_uppercase()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// The on-disk grant store (JSONL).
pub struct AllowOnceStore {
    path: PathBuf,
}

impl AllowOnceStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Default store path: `$GUARDRAILS_ALLOW_ONCE_FILE` if set (isolation/tests),
    /// else alongside the audit log.
    pub fn default_path() -> PathBuf {
        if let Ok(p) = std::env::var("GUARDRAILS_ALLOW_ONCE_FILE") {
            if !p.is_empty() {
                return PathBuf::from(p);
            }
        }
        dirs::home_dir()
            .map(|h| h.join(".claude/guardrails").join(STORE_FILE))
            .unwrap_or_else(|| PathBuf::from(STORE_FILE))
    }

    /// Grant a one-shot exception for `code`. Idempotent-ish: appends a fresh
    /// grant (the newest active one wins on lookup).
    pub fn grant(&self, code: &str) -> std::io::Result<()> {
        self.grant_at(code, Utc::now())
    }

    fn grant_at(&self, code: &str, now: DateTime<Utc>) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let grant = Grant {
            code: code.to_uppercase(),
            expires_at: (now + Duration::hours(TTL_HOURS)).to_rfc3339(),
            consumed: false,
        };
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{}", serde_json::to_string(&grant)?)?;
        Ok(())
    }

    /// If an active, unconsumed, unexpired grant exists for `command`, consume it
    /// and return true. Rewrites the store to mark the grant consumed.
    pub fn check_and_consume(&self, command: &str) -> bool {
        self.check_and_consume_at(command, Utc::now())
    }

    fn check_and_consume_at(&self, command: &str, now: DateTime<Utc>) -> bool {
        let want = code_for(command);
        let Ok(content) = std::fs::read_to_string(&self.path) else {
            return false;
        };

        let mut grants: Vec<Grant> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str::<Grant>(l).ok())
            .filter(|g| !is_expired(g, now)) // prune expired while we're here
            .collect();

        // Find the newest matching active grant.
        let idx = grants.iter().rposition(|g| g.code == want && !g.consumed);
        let Some(idx) = idx else {
            // Nothing matched; still rewrite to persist the expiry prune.
            let _ = self.rewrite(&grants);
            return false;
        };

        grants[idx].consumed = true;
        let _ = self.rewrite(&grants);
        true
    }

    /// Remove expired and consumed grants. Returns how many remain.
    pub fn prune(&self) -> std::io::Result<usize> {
        let now = Utc::now();
        let content = std::fs::read_to_string(&self.path).unwrap_or_default();
        let kept: Vec<Grant> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str::<Grant>(l).ok())
            .filter(|g| !g.consumed && !is_expired(g, now))
            .collect();
        self.rewrite(&kept)?;
        Ok(kept.len())
    }

    fn rewrite(&self, grants: &[Grant]) -> std::io::Result<()> {
        let body: String = grants
            .iter()
            .filter_map(|g| serde_json::to_string(g).ok())
            .map(|s| s + "\n")
            .collect();
        // Atomic replace (temp + rename) so a concurrent reader never sees a
        // truncated store. (A read-modify-write lock would additionally close the
        // lost-update race, but allow-once now only covers low-stakes operational
        // commands — see OVERRIDABLE_PACKS — so a torn write is the real hazard.)
        let tmp = self.path.with_extension("jsonl.tmp");
        std::fs::write(&tmp, body)?;
        std::fs::rename(&tmp, &self.path)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn is_expired(g: &Grant, now: DateTime<Utc>) -> bool {
    match DateTime::parse_from_rfc3339(&g.expires_at) {
        Ok(exp) => now >= exp.with_timezone(&Utc),
        Err(_) => true, // unparseable expiry = treat as expired (fail closed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn store() -> (AllowOnceStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("allow_once.jsonl");
        (AllowOnceStore::new(path), dir)
    }

    #[test]
    fn test_code_deterministic_and_short() {
        let a = code_for("rm -rf /tmp/x");
        let b = code_for("rm -rf /tmp/x");
        assert_eq!(a, b);
        assert_eq!(a.len(), 8);
        assert_ne!(a, code_for("rm -rf /tmp/y"));
    }

    #[test]
    fn test_grant_then_consume_once() {
        let (s, _d) = store();
        let cmd = "git reset --hard HEAD~3";
        assert!(!s.check_and_consume(cmd), "no grant yet");

        s.grant(&code_for(cmd)).unwrap();
        assert!(s.check_and_consume(cmd), "granted → allowed once");
        assert!(!s.check_and_consume(cmd), "single-use → gone after one use");
    }

    #[test]
    fn test_grant_does_not_leak_to_other_commands() {
        let (s, _d) = store();
        s.grant(&code_for("git reset --hard")).unwrap();
        assert!(
            !s.check_and_consume("rm -rf /"),
            "grant is command-specific"
        );
    }

    #[test]
    fn test_expired_grant_not_honored() {
        let (s, _d) = store();
        let cmd = "git push --force";
        // Grant in the far past so it's already expired.
        let past = Utc::now() - Duration::hours(48);
        s.grant_at(&code_for(cmd), past).unwrap();
        assert!(!s.check_and_consume(cmd), "expired grant must not allow");
    }

    #[test]
    fn test_prune_removes_consumed_and_expired() {
        let (s, _d) = store();
        let cmd = "rm -rf ./build";
        s.grant(&code_for(cmd)).unwrap();
        assert!(s.check_and_consume(cmd)); // now consumed
        assert_eq!(s.prune().unwrap(), 0);
    }
}
