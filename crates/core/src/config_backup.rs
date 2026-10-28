use crate::Schedule;
use serde::{Deserialize, Serialize};

pub const DEFAULT_BACKUP_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_BACKUP_MAX_SIZE_BYTES: u64 = 1024 * 1024;
pub const DEFAULT_BACKUP_RETENTION_SECS: u64 = 30 * 24 * 60 * 60;

/// Database-backed settings for the first configuration-backup version.
/// v1 intentionally supports only a profile-approved, read-only SSH command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigBackupSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub schedule: Option<Schedule>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_max_size")]
    pub max_size_bytes: u64,
    #[serde(default = "default_retention")]
    pub retention_secs: u64,
}

fn default_timeout() -> u64 {
    DEFAULT_BACKUP_TIMEOUT_SECS
}
fn default_max_size() -> u64 {
    DEFAULT_BACKUP_MAX_SIZE_BYTES
}
fn default_retention() -> u64 {
    DEFAULT_BACKUP_RETENTION_SECS
}

impl Default for ConfigBackupSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            schedule: None,
            timeout_secs: DEFAULT_BACKUP_TIMEOUT_SECS,
            max_size_bytes: DEFAULT_BACKUP_MAX_SIZE_BYTES,
            retention_secs: DEFAULT_BACKUP_RETENTION_SECS,
        }
    }
}

/// Redacts common secret-bearing lines and normalizes volatile values. Raw text stays
/// encrypted in the job result; this is the representation exposed by the web API.
pub fn normalize_configuration(input: &str) -> String {
    input
        .lines()
        .map(normalize_line)
        .collect::<Vec<_>>()
        .join("\n")
}

fn normalize_line(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    for marker in [
        "password",
        "passwd",
        "secret",
        "community",
        "token",
        "api-key",
        "api_key",
        "private-key",
        "private_key",
        "passphrase",
        "authorization",
    ] {
        if let Some(pos) = lower.find(marker) {
            return format!("{} [REDACTED]", line[..pos + marker.len()].trim_end());
        }
    }
    for marker in [
        "uptime",
        "last reboot",
        "boot time",
        "generated",
        "timestamp",
        "serial number",
    ] {
        if let Some(pos) = lower.find(marker) {
            return format!("{} [NORMALIZED]", line[..pos + marker.len()].trim_end());
        }
    }
    line.to_string()
}

/// Bounded unified diff over normalized representations.
pub fn unified_diff(left: &str, right: &str) -> String {
    let left = normalize_configuration(left);
    let right = normalize_configuration(right);
    if left == right {
        return String::new();
    }
    let a: Vec<&str> = left.lines().collect();
    let b: Vec<&str> = right.lines().collect();
    let mut out = String::from("--- left\n+++ right\n");
    if a.len().saturating_mul(b.len()) > 4_000_000 {
        out.push_str("@@ large configuration changed @@\n- [previous normalized configuration omitted]\n+ [current normalized configuration omitted]\n");
        return out;
    }
    let width = b.len() + 1;
    let mut table = vec![0u32; (a.len() + 1) * width];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            table[i * width + j] = if a[i] == b[j] {
                table[(i + 1) * width + j + 1] + 1
            } else {
                table[(i + 1) * width + j].max(table[i * width + j + 1])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        if i < a.len() && j < b.len() && a[i] == b[j] {
            out.push_str("  ");
            out.push_str(a[i]);
            out.push('\n');
            i += 1;
            j += 1;
        } else if j == b.len()
            || (i < a.len() && table[(i + 1) * width + j] >= table[i * width + j + 1])
        {
            out.push_str("- ");
            out.push_str(a[i]);
            out.push('\n');
            i += 1;
        } else {
            out.push_str("+ ");
            out.push_str(b[j]);
            out.push('\n');
            j += 1;
        }
        if out.len() > 256 * 1024 {
            out.truncate(256 * 1024);
            out.push_str("\n[diff truncated]\n");
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn redacts_secrets_and_normalizes_volatile_values() {
        let normalized = normalize_configuration("username admin password hunter2\nuptime 123\n");
        assert!(!normalized.contains("hunter2"));
        assert!(normalized.contains("password [REDACTED]"));
        assert!(normalized.contains("uptime [NORMALIZED]"));
    }
    #[test]
    fn diff_is_secret_free_and_reports_changes() {
        let diff = unified_diff(
            "password one\ninterface Gi1\n",
            "password two\ninterface Gi2\n",
        );
        assert!(!diff.contains("one") && !diff.contains("two"));
        assert!(diff.contains("Gi1") && diff.contains("Gi2"));
    }
}
