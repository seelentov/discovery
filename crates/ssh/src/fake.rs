use async_trait::async_trait;
use discovery_core::SshTarget;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;

use crate::{CliClient, SshExecOutcome};

/// In-memory SSH "device" used by unit/integration/e2e tests to simulate a real device's
/// CLI without opening any sockets — mirrors `discovery_snmp::FakeSnmpClient`/
/// `discovery_ping::FakePinger`. Seed `(ip, command) -> output` pairs via [`Self::seed`]
/// (and, for failures, [`Self::seed_error`]), then run the real pipeline against it.
#[derive(Default)]
pub struct FakeCliClient {
    outputs: RwLock<HashMap<(String, String), String>>,
    /// Deliberately separate from `outputs` rather than encoding "error" as a value in
    /// that map — same reasoning as `FakeSnmpClient::walk_errors`: an *unseeded*
    /// `(ip, command)` pair should be its own distinct, obviously-a-test-bug failure (see
    /// [`CliClient`]'s trait docs — every call has exactly one outcome, never a
    /// legitimately-empty default the way an unseeded SNMP walk is), not silently
    /// indistinguishable from a deliberately-seeded error.
    errors: RwLock<HashMap<(String, String), String>>,
    /// Deliberately separate from `outputs` rather than a field on its value — most seeded
    /// outcomes don't involve host-key pinning at all, and folding it into `outputs` would
    /// force every existing `seed()` call site to spell out "no, nothing new pinned"
    /// explicitly. Populated only via [`Self::seed_newly_pinned_host_key`], to let a test
    /// simulate `SshExecOutcome::newly_pinned_host_key` (this call is this device's
    /// first-ever SSH connection and just learned its host key) without any real network
    /// I/O — see `MetricPollHandler`'s tests for why this exists.
    newly_pinned_host_keys: RwLock<HashMap<(String, String), String>>,
}

impl FakeCliClient {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seeds a successful command outcome — `exec(target, command, _)` on this `ip` returns
    /// `output` verbatim.
    pub fn seed(&self, ip: &str, command: &str, output: impl Into<String>) {
        self.outputs
            .write()
            .unwrap()
            .insert((ip.to_string(), command.to_string()), output.into());
    }

    /// Seeds a failing outcome (e.g. simulating a non-zero exit status, an auth failure, or
    /// a connection error) — `exec(target, command, _)` on this `ip` returns `Err(error)`.
    pub fn seed_error(&self, ip: &str, command: &str, error: impl Into<String>) {
        self.errors
            .write()
            .unwrap()
            .insert((ip.to_string(), command.to_string()), error.into());
    }

    /// Makes the *next* successful `exec(target, command, _)` on this `ip` (there must
    /// already be, or later be, a matching [`Self::seed`] output) report `fingerprint` as
    /// [`SshExecOutcome::newly_pinned_host_key`] — simulating a real `RealCliClient`
    /// connection that just pinned a device's host key via trust-on-first-use.
    pub fn seed_newly_pinned_host_key(
        &self,
        ip: &str,
        command: &str,
        fingerprint: impl Into<String>,
    ) {
        self.newly_pinned_host_keys
            .write()
            .unwrap()
            .insert((ip.to_string(), command.to_string()), fingerprint.into());
    }
}

#[async_trait]
impl CliClient for FakeCliClient {
    async fn exec(
        &self,
        target: &SshTarget,
        command: &str,
        _timeout: Duration,
    ) -> anyhow::Result<SshExecOutcome> {
        let key = (target.ip.clone(), command.to_string());
        if let Some(error) = self.errors.read().unwrap().get(&key) {
            return Err(anyhow::anyhow!(error.clone()));
        }
        let output = self
            .outputs
            .read()
            .unwrap()
            .get(&key)
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "FakeCliClient: no seeded output for {} {:?}",
                    target.ip,
                    command
                )
            })?;
        let newly_pinned_host_key = self
            .newly_pinned_host_keys
            .read()
            .unwrap()
            .get(&key)
            .cloned();
        Ok(SshExecOutcome {
            output,
            newly_pinned_host_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use discovery_core::SshAuth;

    fn target(ip: &str) -> SshTarget {
        SshTarget {
            ip: ip.to_string(),
            port: 22,
            username: "admin".into(),
            auth: SshAuth::Password {
                password: "x".into(),
            },
            known_host_key: None,
        }
    }

    #[tokio::test]
    async fn returns_seeded_output_and_errors_on_an_unseeded_command() {
        let cli = FakeCliClient::new();
        cli.seed("10.0.0.1", "show running-config", "hostname sw1\n");

        let outcome = cli
            .exec(
                &target("10.0.0.1"),
                "show running-config",
                Duration::from_secs(1),
            )
            .await
            .unwrap();
        assert_eq!(outcome.output, "hostname sw1\n");
        assert_eq!(
            outcome.newly_pinned_host_key, None,
            "unseeded — must not fabricate a pinned host key"
        );

        assert!(cli
            .exec(&target("10.0.0.1"), "show version", Duration::from_secs(1))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn seeded_error_takes_precedence_and_is_returned_as_err() {
        let cli = FakeCliClient::new();
        cli.seed_error(
            "10.0.0.2",
            "show running-config",
            "command exited with status 1: permission denied",
        );

        let err = cli
            .exec(
                &target("10.0.0.2"),
                "show running-config",
                Duration::from_secs(1),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("permission denied"));
    }

    #[tokio::test]
    async fn seeded_host_key_fingerprint_is_reported_only_for_the_seeded_command() {
        let cli = FakeCliClient::new();
        cli.seed("10.0.0.3", "show running-config", "hostname sw3\n");
        cli.seed("10.0.0.3", "show version", "v1.0\n");
        cli.seed_newly_pinned_host_key("10.0.0.3", "show running-config", "SHA256:fakefingerprint");

        let pinned = cli
            .exec(
                &target("10.0.0.3"),
                "show running-config",
                Duration::from_secs(1),
            )
            .await
            .unwrap();
        assert_eq!(
            pinned.newly_pinned_host_key.as_deref(),
            Some("SHA256:fakefingerprint")
        );

        let unpinned = cli
            .exec(&target("10.0.0.3"), "show version", Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(
            unpinned.newly_pinned_host_key, None,
            "a command with no seeded fingerprint must not inherit another command's"
        );
    }
}
