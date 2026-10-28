use async_trait::async_trait;
use discovery_core::{SshAuth, SshTarget};
use russh::client;
use russh::keys::{decode_secret_key, HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::warn;

/// Abstraction over "run this one CLI command on this device over SSH and capture its
/// output" — the SSH counterpart of `discovery_snmp::SnmpClient`/`discovery_ping::Pinger`.
/// Kept trait-based, same reasoning as those two: the pipeline (`MetricPollHandler`) runs
/// against [`crate::FakeCliClient`] in tests without any real network I/O or SSH server.
///
/// **One call = one full connect/authenticate/exec/disconnect cycle — no persistent
/// session held across calls.** See [`RealCliClient`]'s docs for why this is the
/// deliberate choice for v1, not an oversight.
#[async_trait]
pub trait CliClient: Send + Sync {
    /// Runs `command` on `target` and returns its captured stdout, trimmed of nothing (the
    /// caller/profile author decides whether trailing whitespace matters to their
    /// `AlertRule` expression). `timeout` bounds the **entire** operation — connect,
    /// authenticate, open the channel, run the command, read its output — not just one
    /// sub-step, mirroring `discovery_ping::Pinger::ping`'s caller-supplied-per-call
    /// convention rather than baking a timeout into the target/client itself.
    ///
    /// Fails (never panics) on: connection refused/unreachable, **the server's host key
    /// not matching `target.known_host_key`** (see [`SshExecOutcome`]'s docs — a mismatch
    /// here means either a legitimate host key rotation or a MITM presenting a different
    /// key, and this project has no way to tell those apart, so it always fails closed),
    /// authentication failure, a malformed private key, the command exiting with a
    /// non-zero status (the stderr text, if any, is folded into the error message), or the
    /// whole operation not finishing within `timeout`. There is no "partial success" shape
    /// the way `discovery_snmp::SnmpClient::get_multi` has for a batch — one command, one
    /// outcome.
    async fn exec(
        &self,
        target: &SshTarget,
        command: &str,
        timeout: Duration,
    ) -> anyhow::Result<SshExecOutcome>;
}

/// Successful outcome of one [`CliClient::exec`] call — command output plus, on the one
/// call that pinned a previously-unpinned host key, that key's fingerprint so the caller
/// can persist it for every future call against this target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshExecOutcome {
    pub output: String,
    /// `Some(fingerprint)` only when `target.known_host_key` was `None` going into this
    /// call and the connection succeeded — trust-on-first-use just learned this target's
    /// host key (see `discovery_core::SshCredentials::known_host_key`'s docs). The caller
    /// (`MetricPollHandler`) is expected to persist it via `DeviceStore::pin_ssh_host_key`
    /// so every subsequent call passes a `target.known_host_key` that pins it. `None` on
    /// every other successful call (already pinned, nothing new to persist).
    pub newly_pinned_host_key: Option<String>,
}

/// `russh::client::Handler` implementation used for every [`RealCliClient`] connection.
/// Deliberately minimal — this project only ever needs "connect, auth, exec one command,
/// disconnect", never an interactive session, so every other `Handler` callback keeps its
/// default (no-op) behavior.
struct Handler {
    /// `target.known_host_key`, if this connection's target already has one pinned —
    /// `None` means trust-on-first-use for this connection (see [`SshExecOutcome`]'s
    /// docs).
    expected_fingerprint: Option<String>,
    /// Filled in by [`Self::check_server_key`] with whatever fingerprint the server
    /// actually presented, then read back by `RealCliClient::exec_inner` after
    /// `client::connect` returns — on success *and* on failure alike, so a host-key
    /// mismatch can be reported with a clear "expected X, got Y" message instead of
    /// `russh`'s own generic `UnknownKey` error. A plain `std::sync::Mutex`, not an async
    /// one: it's written from one synchronous line inside `check_server_key`'s body and
    /// never held across an `.await`, so there's no contention to worry about.
    observed_fingerprint: Arc<Mutex<Option<String>>>,
}

impl client::Handler for Handler {
    type Error = russh::Error;

    /// **Host-key pinning, closing a CWE-295 finding** (this used to accept every server
    /// key unconditionally — see git history for the original scope-cut docs this
    /// replaced). Always records the presented key's SHA256 fingerprint into
    /// `observed_fingerprint` first, *then* decides whether to accept it:
    /// [`SshExecOutcome`]'s docs describe the resulting trust-on-first-use/pin-and-verify
    /// contract in full — no pinned key yet accepts unconditionally (the caller pins
    /// whatever was observed after a successful connection), a pinned key must match
    /// exactly or the connection is refused before authentication is ever attempted.
    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let fingerprint = server_public_key
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string();
        *self.observed_fingerprint.lock().expect("observed_fingerprint mutex is never held across an .await and this callback never panics while holding it") = Some(fingerprint.clone());
        Ok(match &self.expected_fingerprint {
            Some(expected) => &fingerprint == expected,
            None => true,
        })
    }
}

/// Real SSH client backed by the `russh` crate (pure-Rust SSH implementation — no
/// system `ssh`/OpenSSL dependency, same "no external process/library dependency" property
/// `discovery-snmp`'s `async-snmp`/`discovery-ping`'s `surge-ping` already have).
///
/// **Connection lifecycle: reconnect-per-`exec()`, no persistent session pool.** The
/// project's convention for a comparatively expensive per-call cost (see
/// `discovery/CLAUDE.md`'s "Батч вместо цикла на hot path" principle) is to batch or cache
/// across a *hot path* — something exercised on every tick across a large number of
/// entities, the way `MetricPollHandler`'s scalar SNMP batch is. SSH-command metrics are
/// deliberately not that: they exist for comparatively low-frequency use cases (config
/// backup/compliance checks — see `docs/Roadmap.md`'s decision), so a profile author is
/// expected to set a coarser `schedule` (minutes to once-daily, often `Schedule::Calendar`)
/// precisely because of this cost, not the default per-metric interval every SNMP scalar
/// gets. Given that, holding a persistent per-device SSH session (with its own keepalive,
/// health-check-before-reuse, and reconnect-on-broken-pipe logic, layered on top of the
/// existing per-device generation-guard/`ActiveChains` machinery `MetricPollHandler`
/// already manages) was judged disproportionate complexity for what this actually needs:
/// full reconnect (TCP handshake + SSH key exchange + auth) on every `exec()` call is
/// simple, always correct (no stale-session edge cases), and its latency cost is
/// negligible next to the coarse cadence this metric source is meant to run at. Revisit
/// with a real per-device session cache only if live/profiling data shows connection
/// overhead actually dominates for a real deployment — not a preemptive optimization.
///
/// **No retry loop**, unlike `discovery_snmp::RealSnmpClient`'s UDP-packet-loss retries —
/// see [`SshTarget`]'s docs for why a failed SSH attempt doesn't get the same "maybe it was
/// just one dropped packet" benefit of the doubt a UDP-based SNMP `get` does.
#[derive(Default)]
pub struct RealCliClient;

impl RealCliClient {
    pub fn new() -> Self {
        Self
    }

    async fn exec_inner(
        &self,
        target: &SshTarget,
        command: &str,
    ) -> anyhow::Result<SshExecOutcome> {
        // Decode/validate a private key (if that's this target's auth mode) *before*
        // opening any connection — fails fast on a malformed key without wasting a network
        // round trip against a device the key was never going to work against anyway.
        let key_pair = match &target.auth {
            SshAuth::PrivateKey {
                private_key,
                passphrase,
            } => Some(
                decode_secret_key(private_key, passphrase.as_deref())
                    .map_err(|e| anyhow::anyhow!("failed to parse SSH private key: {e}"))?,
            ),
            SshAuth::Password { .. } => None,
        };

        let observed_fingerprint = Arc::new(Mutex::new(None));
        let handler = Handler {
            expected_fingerprint: target.known_host_key.clone(),
            observed_fingerprint: observed_fingerprint.clone(),
        };

        let config = Arc::new(client::Config::default());
        let addr = (target.ip.as_str(), target.port);
        let mut session = client::connect(config, addr, handler).await.map_err(|e| {
            // A pinned target whose presented key doesn't match `e`'s generic
            // `UnknownKey` gets a specific, actionable message instead — see
            // `Handler::check_server_key`'s docs for why `observed_fingerprint` is always
            // populated by this point even on failure.
            match (&target.known_host_key, observed_fingerprint.lock().expect("observed_fingerprint mutex is never held across an .await").clone()) {
                (Some(expected), Some(observed)) if &observed != expected => {
                    anyhow::anyhow!(
                        "SSH host key verification failed for {}:{}: expected {expected}, server presented {observed} — possible MITM attack, or the device's host key legitimately rotated (an operator must explicitly re-pin it, e.g. by resetting this device's SSH credentials)",
                        target.ip,
                        target.port
                    )
                }
                _ => anyhow::anyhow!("SSH connect to {}:{} failed: {e}", target.ip, target.port),
            }
        })?;

        let auth_result = if let Some(key_pair) = key_pair {
            // Only matters for RSA keys (picks the signature hash the server advertises
            // support for via the `server-sig-algs` extension); `None` for every other key
            // type, exactly matching upstream's own reference client example.
            let hash_alg = session.best_supported_rsa_hash().await?.flatten();
            session
                .authenticate_publickey(
                    target.username.clone(),
                    PrivateKeyWithHashAlg::new(Arc::new(key_pair), hash_alg),
                )
                .await?
        } else {
            let SshAuth::Password { password } = &target.auth else {
                unreachable!("key_pair is None only when target.auth is Password")
            };
            session
                .authenticate_password(target.username.clone(), password.clone())
                .await?
        };
        if !auth_result.success() {
            anyhow::bail!(
                "SSH authentication failed for {}@{}",
                target.username,
                target.ip
            );
        }

        let mut channel = session.channel_open_session().await?;
        channel.exec(true, command).await?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_status: Option<u32> = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status: code } => exit_status = Some(code),
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => {}
            }
        }

        // Best-effort — a command that already ran to completion (we have its output
        // either way) shouldn't fail the whole call just because a clean disconnect
        // handshake didn't complete.
        let _ = session
            .disconnect(Disconnect::ByApplication, "", "en")
            .await;

        // Only reported when this connection is what pinned the key (`target` came in
        // with no pin yet) — see `SshExecOutcome::newly_pinned_host_key`'s docs. A target
        // that already had a pinned fingerprint has nothing new to report even though
        // `observed_fingerprint` was populated too: it's already persisted, and it's
        // guaranteed equal to `target.known_host_key` here (a mismatch would have failed
        // the `client::connect` call above, well before this point).
        let newly_pinned_host_key = if target.known_host_key.is_none() {
            observed_fingerprint
                .lock()
                .expect("observed_fingerprint mutex is never held across an .await")
                .clone()
        } else {
            None
        };

        match exit_status {
            Some(0) => Ok(SshExecOutcome {
                output: String::from_utf8_lossy(&stdout).into_owned(),
                newly_pinned_host_key,
            }),
            Some(code) => {
                let stderr_text = String::from_utf8_lossy(&stderr);
                anyhow::bail!(
                    "command exited with status {code}{}",
                    if stderr_text.trim().is_empty() {
                        String::new()
                    } else {
                        format!(": {}", stderr_text.trim())
                    }
                )
            }
            // The channel closed without ever sending an ExitStatus message — protocol-legal
            // (e.g. the connection dropped mid-command) but unusual for a well-behaved
            // server. Treated as success with whatever output was captured rather than a
            // hard failure, since we may well have the command's full real output already;
            // logged so it's visible without being fatal.
            None => {
                warn!(ip = %target.ip, "SSH channel closed without an exit status — returning captured output anyway");
                Ok(SshExecOutcome {
                    output: String::from_utf8_lossy(&stdout).into_owned(),
                    newly_pinned_host_key,
                })
            }
        }
    }
}

#[async_trait]
impl CliClient for RealCliClient {
    async fn exec(
        &self,
        target: &SshTarget,
        command: &str,
        timeout: Duration,
    ) -> anyhow::Result<SshExecOutcome> {
        match tokio::time::timeout(timeout, self.exec_inner(target, command)).await {
            Ok(result) => result,
            Err(_) => anyhow::bail!("SSH command timed out after {timeout:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use discovery_core::SshAuth;

    fn dead_target() -> SshTarget {
        SshTarget {
            ip: "127.0.0.1".into(),
            port: 39998, // an obscure high port essentially guaranteed unbound in test environments
            username: "admin".into(),
            auth: SshAuth::Password {
                password: "irrelevant".into(),
            },
            known_host_key: None,
        }
    }

    /// Same "must not hang forever" guarantee `discovery_snmp::RealSnmpClient`'s tests
    /// establish for SNMP — the outer `tokio::time::timeout` here is the proof.
    #[tokio::test]
    async fn exec_against_an_unresponsive_target_fails_within_the_configured_timeout_not_forever() {
        let client = RealCliClient::new();
        let target = dead_target();

        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            client.exec(&target, "show version", Duration::from_millis(300)),
        )
        .await;
        let result = outcome.expect(
            "exec() must return within the configured timeout, not hang past the outer bound",
        );
        assert!(
            result.is_err(),
            "nothing is listening on that port — the SSH exec must fail, not succeed"
        );
    }

    #[tokio::test]
    async fn exec_fails_fast_with_a_malformed_private_key() {
        let client = RealCliClient::new();
        // Loopback but a port nothing listens on — irrelevant here since key parsing fails
        // before any network I/O happens.
        let target = SshTarget {
            auth: SshAuth::PrivateKey {
                private_key: "not a real key".into(),
                passphrase: None,
            },
            ..dead_target()
        };
        let result = client
            .exec(&target, "show version", Duration::from_secs(2))
            .await;
        assert!(result.is_err());
    }

    /// A tiny in-process `russh::server` fixture — unlike everything above (which only
    /// ever exercises `RealCliClient` against an unresponsive/nonexistent target), this
    /// gives it a genuinely live, running SSH server to speak the real protocol against:
    /// real TCP handshake, real SSH key exchange, real password auth, a real exec channel.
    /// `FakeCliClient` (see `crate::fake`) never proves any of that actually works — only
    /// this does. Accepts `admin`/`testpass` and understands exactly two commands,
    /// `"uname -a"` (succeeds) and `"exit 1"` (fails), nothing more — this exists purely to
    /// pin down `RealCliClient::exec`'s real-protocol behavior, not to be a general-purpose
    /// SSH server.
    mod test_server {
        use russh::keys::{Algorithm, PrivateKey};
        use russh::server::{self, Auth, Msg, Server as _, Session};
        use russh::{Channel, ChannelId};
        use std::sync::Arc;

        #[derive(Clone)]
        pub struct TestServer;

        impl server::Server for TestServer {
            type Handler = TestServer;
            fn new_client(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
                self.clone()
            }
        }

        impl server::Handler for TestServer {
            type Error = russh::Error;

            async fn auth_password(
                &mut self,
                user: &str,
                password: &str,
            ) -> Result<Auth, Self::Error> {
                Ok(if user == "admin" && password == "testpass" {
                    Auth::Accept
                } else {
                    Auth::reject()
                })
            }

            async fn channel_open_session(
                &mut self,
                _channel: Channel<Msg>,
                reply: server::ChannelOpenHandle,
                _session: &mut Session,
            ) -> Result<(), Self::Error> {
                reply.accept().await;
                Ok(())
            }

            async fn exec_request(
                &mut self,
                channel: ChannelId,
                data: &[u8],
                session: &mut Session,
            ) -> Result<(), Self::Error> {
                match String::from_utf8_lossy(data).as_ref() {
                    "uname -a" => {
                        session.data(channel, b"Linux sw-live-test 5.10.0\n".to_vec())?;
                        session.exit_status_request(channel, 0)?;
                    }
                    "exit 1" => {
                        session.exit_status_request(channel, 1)?;
                    }
                    _ => {
                        session.exit_status_request(channel, 127)?;
                    }
                }
                session.channel_success(channel)?;
                session.eof(channel)?;
                session.close(channel)?;
                Ok(())
            }
        }

        /// Binds an ephemeral port, spawns the server loop in the background, and returns
        /// its address plus its host key's SHA256 fingerprint (computed the exact same
        /// way `Handler::check_server_key` does — `PublicKey::fingerprint`) so host-key
        /// pinning tests can assert against a known-correct value without duplicating
        /// key-generation logic. The spawned task is intentionally never joined/aborted:
        /// it's dropped along with the `#[tokio::test]`'s single-threaded runtime when the
        /// test ends, which is all the cleanup an isolated, single-test-lifetime fixture
        /// needs.
        pub async fn spawn() -> (std::net::SocketAddr, String) {
            let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
                .expect("generating an ephemeral Ed25519 test host key must not fail");
            let fingerprint = key
                .public_key()
                .fingerprint(russh::keys::HashAlg::Sha256)
                .to_string();
            let config = Arc::new(server::Config {
                keys: vec![key],
                ..Default::default()
            });
            let socket = tokio::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .expect("binding an ephemeral loopback port must not fail");
            let addr = socket
                .local_addr()
                .expect("a just-bound socket must have a local address");
            let mut server = TestServer;
            tokio::spawn(async move {
                let _ = server.run_on_socket(config, &socket).await;
            });
            (addr, fingerprint)
        }
    }

    fn test_server_target(
        addr: std::net::SocketAddr,
        password: &str,
        known_host_key: Option<String>,
    ) -> SshTarget {
        SshTarget {
            ip: addr.ip().to_string(),
            port: addr.port(),
            username: "admin".into(),
            auth: SshAuth::Password {
                password: password.into(),
            },
            known_host_key,
        }
    }

    #[tokio::test]
    async fn exec_round_trips_the_real_command_output_against_a_real_ssh_server() {
        let (addr, fingerprint) = test_server::spawn().await;
        let client = RealCliClient::new();
        let outcome = client
            .exec(&test_server_target(addr, "testpass", Some(fingerprint)), "uname -a", Duration::from_secs(5))
            .await
            .expect("exec against a real, running SSH server with correct credentials and a correctly-pinned host key must succeed");
        assert_eq!(outcome.output, "Linux sw-live-test 5.10.0\n");
    }

    #[tokio::test]
    async fn exec_surfaces_a_real_non_zero_exit_status_from_a_real_ssh_server() {
        let (addr, fingerprint) = test_server::spawn().await;
        let client = RealCliClient::new();
        let err = client
            .exec(
                &test_server_target(addr, "testpass", Some(fingerprint)),
                "exit 1",
                Duration::from_secs(5),
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("status 1"),
            "unexpected error message: {err}"
        );
    }

    #[tokio::test]
    async fn exec_fails_with_a_real_auth_rejection_from_a_real_ssh_server() {
        let (addr, fingerprint) = test_server::spawn().await;
        let client = RealCliClient::new();
        let err = client
            .exec(
                &test_server_target(addr, "wrong-password", Some(fingerprint)),
                "uname -a",
                Duration::from_secs(5),
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("auth"),
            "unexpected error message: {err}"
        );
    }

    // ---- Host-key pinning (CWE-295 fix) ----

    /// The core trust-on-first-use contract: a target with no pinned host key yet
    /// (`known_host_key: None`) connects successfully against a real server, and the
    /// fingerprint `exec` reports back is exactly that server's real host key fingerprint
    /// — not a placeholder, not empty, the genuine value a caller would go on to pin.
    #[tokio::test]
    async fn exec_against_an_unpinned_target_succeeds_and_reports_the_real_host_key_fingerprint() {
        let (addr, fingerprint) = test_server::spawn().await;
        let client = RealCliClient::new();
        let outcome = client
            .exec(
                &test_server_target(addr, "testpass", None),
                "uname -a",
                Duration::from_secs(5),
            )
            .await
            .expect("trust-on-first-use must accept an unpinned target's host key");
        assert_eq!(
            outcome.newly_pinned_host_key.as_deref(),
            Some(fingerprint.as_str())
        );
    }

    /// Once a target's host key is pinned and the server presents that exact key, `exec`
    /// must succeed and must **not** report a `newly_pinned_host_key` — there's nothing
    /// new to persist, it was already pinned coming in.
    #[tokio::test]
    async fn exec_against_a_correctly_pinned_target_succeeds_with_nothing_new_to_pin() {
        let (addr, fingerprint) = test_server::spawn().await;
        let client = RealCliClient::new();
        let outcome = client
            .exec(&test_server_target(addr, "testpass", Some(fingerprint)), "uname -a", Duration::from_secs(5))
            .await
            .expect("exec against a target whose pinned fingerprint matches the server's real key must succeed");
        assert_eq!(
            outcome.newly_pinned_host_key, None,
            "a target that was already pinned coming in has nothing new to report"
        );
    }

    /// **The actual CWE-295 regression test.** A target is pinned to one server's real
    /// fingerprint, but the connection actually lands on a *different* server presenting a
    /// *different* host key — exactly what a MITM (or a legitimate but unannounced host
    /// key rotation) looks like from the client's point of view. Before this fix,
    /// `Handler::check_server_key` accepted this unconditionally; the fix must refuse the
    /// connection outright, before authentication is ever attempted (proven by asserting
    /// on the specific mismatch error, not just "some error").
    #[tokio::test]
    async fn exec_rejects_a_connection_whose_host_key_does_not_match_the_pinned_fingerprint() {
        let (_legitimate_addr, legitimate_fingerprint) = test_server::spawn().await;
        let (impostor_addr, _impostor_fingerprint) = test_server::spawn().await;
        let client = RealCliClient::new();

        // Pin the legitimate server's fingerprint, but connect to the impostor's address —
        // simulates the impostor's key being presented where the legitimate one was
        // expected, without needing to actually redirect traffic in this test.
        let target = test_server_target(
            impostor_addr,
            "testpass",
            Some(legitimate_fingerprint.clone()),
        );
        let err = client
            .exec(&target, "uname -a", Duration::from_secs(5))
            .await
            .unwrap_err();

        let message = err.to_string();
        assert!(
            message.contains("host key verification failed"),
            "unexpected error message: {message}"
        );
        assert!(
            message.contains(&legitimate_fingerprint),
            "error must name the expected fingerprint: {message}"
        );
    }

    /// A pinned target rejects a mismatched key *before* authentication is ever attempted
    /// — proven by pinning a fingerprint that doesn't match a server that would otherwise
    /// happily accept these exact credentials (`test_server`'s `auth_password` only checks
    /// `admin`/`testpass`, both supplied here). If the mismatch were only cosmetic (logged
    /// but not enforced), this would succeed; it must not.
    #[tokio::test]
    async fn exec_rejects_a_host_key_mismatch_even_with_otherwise_valid_credentials() {
        let (addr, _fingerprint) = test_server::spawn().await;
        let client = RealCliClient::new();
        let target = test_server_target(
            addr,
            "testpass",
            Some("SHA256:0000000000000000000000000000000000000000000000000".to_string()),
        );
        let err = client
            .exec(&target, "uname -a", Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("host key verification failed"),
            "unexpected error message: {err}"
        );
    }
}
