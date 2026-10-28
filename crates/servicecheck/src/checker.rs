use async_trait::async_trait;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tracing::warn;

/// Which L4/L7 probe to run — mirrors `discovery_dsl::ServiceCheckProtocol` one level down
/// (this crate deliberately doesn't depend on `discovery-dsl`, same "network probe crate
/// knows nothing about profiles" separation `discovery-ping`/`discovery-snmp` already keep
/// — `discovery-agent::handlers::ServiceCheckPollHandler` is what bridges the two).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckProtocol {
    Tcp,
    Http,
    Https,
    Ssh,
}

/// One resolved check to actually run — everything [`ServiceChecker::check`] needs, already
/// defaulted/resolved by the caller (e.g. `path` defaulting to `"/"`, `host` defaulting to
/// the device's own IP when a profile's `ServiceCheckSpec::target` is unset).
#[derive(Debug, Clone)]
pub struct CheckTarget {
    pub protocol: CheckProtocol,
    pub host: String,
    pub port: u16,
    /// HTTP(S) only — ignored by `Tcp`/`Ssh`.
    pub path: String,
    /// HTTP(S) only. `None` = any 2xx status counts as ok.
    pub expected_status: Option<u16>,
    /// HTTP(S) only. `None` = body is not even fetched (see [`RealServiceChecker::check`]'s
    /// docs for why that matters, not just "not checked").
    pub body_contains: Option<String>,
    pub timeout: Duration,
}

/// The outcome of one probe attempt — deliberately richer than `discovery_ping::Pinger`'s
/// plain `bool`: unlike "is the device alive at all" (which only ever needs *whether*, per
/// that trait's own docs), a service check's whole point is surfacing enough detail
/// (`latency_ms`, `error`) to become a useful table-metric row an operator can actually read
/// (`metrics.service_checks` — see `discovery_dsl::ServiceChecksSection`'s docs), not just a
/// pass/fail dot.
#[derive(Debug, Clone, PartialEq)]
pub struct CheckOutcome {
    pub ok: bool,
    /// `None` if the attempt never got far enough to measure a meaningful duration (e.g. a
    /// DNS/parse failure before any I/O started) — present on both success *and* failure
    /// otherwise (a TCP refusal is fast but still a measured duration).
    pub latency_ms: Option<u64>,
    /// `None` on success. Human-readable, not structured — same convention
    /// `MetricPollOutcome::Err` and `discovery_snmp::SnmpClient::get`'s error type use.
    pub error: Option<String>,
}

impl CheckOutcome {
    fn ok(latency: Duration) -> Self {
        Self {
            ok: true,
            latency_ms: Some(latency.as_millis() as u64),
            error: None,
        }
    }

    fn err(latency: Option<Duration>, error: impl Into<String>) -> Self {
        Self {
            ok: false,
            latency_ms: latency.map(|d| d.as_millis() as u64),
            error: Some(error.into()),
        }
    }
}

/// Abstraction over "does this L4/L7 endpoint answer right now" — mirrors
/// `discovery_ping::Pinger`'s real/fake split exactly, so
/// `discovery-agent::handlers::ServiceCheckPollHandler` can run against
/// [`crate::FakeServiceChecker`] in tests without any real sockets, same as every other
/// pipeline stage in this project.
#[async_trait]
pub trait ServiceChecker: Send + Sync {
    async fn check(&self, target: &CheckTarget) -> CheckOutcome;
}

/// Real prober — plain TCP connect for `Tcp`, an HTTP(S) GET via `reqwest` for
/// `Http`/`Https`, and a raw banner read for `Ssh` (see [`Self::check_ssh`]'s docs — it
/// deliberately never attempts authentication).
///
/// Holds one shared `reqwest::Client` (built once in `discovery-agent::main`, not per-call)
/// — same "own the connection machinery once, reuse it every probe" reasoning
/// `discovery_ping::IcmpPinger` gives for its shared `surge_ping::Client`.
pub struct RealServiceChecker {
    http: reqwest::Client,
}

impl RealServiceChecker {
    /// Fails only if `reqwest` can't build a client at all (e.g. the TLS backend can't
    /// initialize) — a startup-time failure, same treatment as `IcmpPinger::new`.
    ///
    /// **`danger_accept_invalid_certs(true)`** — deliberate, not an oversight: this probe
    /// answers "does something respond on this HTTPS port", not "is its certificate valid
    /// and trusted". Self-signed/expired certificates are the norm, not the exception, on
    /// internal network-device admin UIs (switches, OLTs, routers) — the exact devices this
    /// project monitors — and treating every one of them as "down" because of a cert issue
    /// would make the `https` protocol option useless for its actual purpose here. A
    /// profile author who genuinely wants "and the cert must be valid" as part of the check
    /// has no way to express that yet — not requested, and would be a separate, explicit
    /// opt-in field if it ever is.
    pub fn new() -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()?;
        Ok(Self { http })
    }

    async fn check_tcp(&self, target: &CheckTarget) -> CheckOutcome {
        let start = Instant::now();
        match tokio::time::timeout(
            target.timeout,
            tokio::net::TcpStream::connect((target.host.as_str(), target.port)),
        )
        .await
        {
            Ok(Ok(_stream)) => CheckOutcome::ok(start.elapsed()),
            Ok(Err(e)) => CheckOutcome::err(Some(start.elapsed()), e.to_string()),
            Err(_) => CheckOutcome::err(Some(start.elapsed()), "timed out"),
        }
    }

    /// SSH reachability — deliberately **not** an SSH client (no `russh`/`thrussh`
    /// dependency, no handshake, definitely no authentication attempt): a real SSH server
    /// sends its identification banner (`SSH-2.0-...`, RFC 4253 §4.2) unprompted, immediately
    /// after the TCP handshake completes — reading it and checking the `"SSH-"` prefix is
    /// enough to confirm "something SSH-shaped is listening" without any credentials, which
    /// is all this feature was asked to confirm ("doesn't need to authenticate, just confirm
    /// something SSH-shaped answers").
    async fn check_ssh(&self, target: &CheckTarget) -> CheckOutcome {
        use tokio::io::AsyncReadExt;

        let start = Instant::now();
        let mut stream = match tokio::time::timeout(
            target.timeout,
            tokio::net::TcpStream::connect((target.host.as_str(), target.port)),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return CheckOutcome::err(Some(start.elapsed()), e.to_string()),
            Err(_) => return CheckOutcome::err(Some(start.elapsed()), "timed out connecting"),
        };

        let remaining = target.timeout.saturating_sub(start.elapsed());
        let mut buf = [0u8; 8];
        match tokio::time::timeout(remaining, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 && buf[..n].starts_with(b"SSH-") => {
                CheckOutcome::ok(start.elapsed())
            }
            Ok(Ok(0)) => CheckOutcome::err(
                Some(start.elapsed()),
                "connection closed before sending a banner",
            ),
            Ok(Ok(_)) => CheckOutcome::err(
                Some(start.elapsed()),
                "connected, but no SSH banner (\"SSH-\" prefix) in the response",
            ),
            Ok(Err(e)) => CheckOutcome::err(Some(start.elapsed()), e.to_string()),
            Err(_) => CheckOutcome::err(
                Some(start.elapsed()),
                "timed out waiting for the SSH banner",
            ),
        }
    }

    async fn check_http(&self, target: &CheckTarget, https: bool) -> CheckOutcome {
        let scheme = if https { "https" } else { "http" };
        let path = if target.path.starts_with('/') {
            target.path.clone()
        } else {
            format!("/{}", target.path)
        };
        let url = format!("{scheme}://{}:{}{path}", target.host, target.port);

        let start = Instant::now();
        let request = self.http.get(&url).timeout(target.timeout);
        let response = match request.send().await {
            Ok(r) => r,
            Err(e) => return CheckOutcome::err(Some(start.elapsed()), e.to_string()),
        };

        let status = response.status();
        let status_ok = match target.expected_status {
            Some(expected) => status.as_u16() == expected,
            None => status.is_success(),
        };

        // Only fetches the body when a `body_contains` check was actually declared — an
        // ordinary status-only check (the common case) never pays for downloading a
        // response body it isn't going to look at.
        if let Some(needle) = &target.body_contains {
            let body = match response.text().await {
                Ok(b) => b,
                Err(e) => {
                    return CheckOutcome::err(
                        Some(start.elapsed()),
                        format!("reading response body: {e}"),
                    )
                }
            };
            let body_ok = body.contains(needle.as_str());
            if status_ok && body_ok {
                CheckOutcome::ok(start.elapsed())
            } else if !status_ok {
                CheckOutcome::err(Some(start.elapsed()), format!("unexpected status {status}"))
            } else {
                CheckOutcome::err(
                    Some(start.elapsed()),
                    "response body did not contain the expected substring",
                )
            }
        } else if status_ok {
            CheckOutcome::ok(start.elapsed())
        } else {
            CheckOutcome::err(Some(start.elapsed()), format!("unexpected status {status}"))
        }
    }
}

#[async_trait]
impl ServiceChecker for RealServiceChecker {
    async fn check(&self, target: &CheckTarget) -> CheckOutcome {
        // The profile/agent boundary additionally requires an override to equal the
        // device's literal management IP.  Keep this lower-level guard too: callers of
        // this crate must not be able to turn a hostname into an implicit DNS/SSRF probe.
        if target.host.parse::<IpAddr>().is_err() {
            return CheckOutcome::err(None, "service-check target must be a literal IP address");
        }
        match target.protocol {
            CheckProtocol::Tcp => self.check_tcp(target).await,
            CheckProtocol::Ssh => self.check_ssh(target).await,
            CheckProtocol::Http => self.check_http(target, false).await,
            CheckProtocol::Https => self.check_http(target, true).await,
        }
    }
}

/// Logged once at process startup if [`RealServiceChecker::new`] fails — kept as a free
/// function (not inlined at the one call site) purely so the reasoning is documented next to
/// the behavior it explains, same pattern as this crate's other doc comments.
pub fn log_checker_build_failure(e: &anyhow::Error) {
    warn!(error = %e, "failed to build the HTTP(S) client for service checks — service_checks polling will not run");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(protocol: CheckProtocol, host: &str, port: u16) -> CheckTarget {
        CheckTarget {
            protocol,
            host: host.to_string(),
            port,
            path: "/".to_string(),
            expected_status: None,
            body_contains: None,
            timeout: Duration::from_millis(300),
        }
    }

    #[tokio::test]
    async fn tcp_connect_succeeds_against_a_real_local_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((_socket, _)) = listener.accept().await else {
                    break;
                };
            }
        });

        let checker = RealServiceChecker::new().unwrap();
        let outcome = checker
            .check(&target(CheckProtocol::Tcp, "127.0.0.1", port))
            .await;
        assert!(outcome.ok, "a real listener must be reachable: {outcome:?}");
        assert!(outcome.latency_ms.is_some());
        assert!(outcome.error.is_none());
    }

    #[tokio::test]
    async fn tcp_connect_fails_against_a_closed_port() {
        // Bind-then-drop to get a port that is guaranteed nothing is listening on right now.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let checker = RealServiceChecker::new().unwrap();
        let outcome = checker
            .check(&target(CheckProtocol::Tcp, "127.0.0.1", port))
            .await;
        assert!(
            !outcome.ok,
            "nothing is listening — must be reported as not ok"
        );
        assert!(outcome.error.is_some());
    }

    #[tokio::test]
    async fn tcp_connect_times_out_against_a_non_routable_address() {
        let checker = RealServiceChecker::new().unwrap();
        // TEST-NET-1 (RFC 5737, 192.0.2.0/24) — reserved for documentation, guaranteed
        // never to have anything answering, so a connection attempt will hang until our own
        // timeout fires rather than getting an immediate refusal like a closed local port.
        let mut t = target(CheckProtocol::Tcp, "192.0.2.1", 81);
        t.timeout = Duration::from_millis(200);
        let outcome = checker.check(&t).await;
        assert!(!outcome.ok);
        assert_eq!(outcome.error.as_deref(), Some("timed out"));
    }

    #[tokio::test]
    async fn service_check_rejects_hostnames_before_network_io() {
        let checker = RealServiceChecker::new().unwrap();
        let outcome = checker
            .check(&target(CheckProtocol::Tcp, "localhost", 80))
            .await;
        assert!(!outcome.ok);
        assert_eq!(outcome.latency_ms, None);
        assert_eq!(
            outcome.error.as_deref(),
            Some("service-check target must be a literal IP address")
        );
    }

    #[tokio::test]
    async fn ssh_banner_detected_from_a_fake_ssh_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                use tokio::io::AsyncWriteExt;
                let _ = socket.write_all(b"SSH-2.0-OpenSSH_9.0\r\n").await;
                // Keep the socket alive briefly so the reader on the other end isn't racing
                // a close before it gets to read.
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });

        let checker = RealServiceChecker::new().unwrap();
        let outcome = checker
            .check(&target(CheckProtocol::Ssh, "127.0.0.1", port))
            .await;
        assert!(
            outcome.ok,
            "a real SSH-shaped banner must be recognized: {outcome:?}"
        );
    }

    #[tokio::test]
    async fn ssh_check_fails_when_the_banner_does_not_start_with_ssh_dash() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                use tokio::io::AsyncWriteExt;
                let _ = socket.write_all(b"220 not an ssh server\r\n").await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });

        let checker = RealServiceChecker::new().unwrap();
        let outcome = checker
            .check(&target(CheckProtocol::Ssh, "127.0.0.1", port))
            .await;
        assert!(!outcome.ok);
        assert!(outcome.error.unwrap().contains("SSH-"));
    }

    #[tokio::test]
    async fn http_status_matches_default_2xx_expectation() {
        let server = tiny_http_server(200, "ok").await;
        let checker = RealServiceChecker::new().unwrap();
        let outcome = checker
            .check(&target(CheckProtocol::Http, "127.0.0.1", server))
            .await;
        assert!(outcome.ok, "{outcome:?}");
    }

    #[tokio::test]
    async fn http_status_mismatch_against_expected_status_fails() {
        let server = tiny_http_server(200, "ok").await;
        let checker = RealServiceChecker::new().unwrap();
        let mut t = target(CheckProtocol::Http, "127.0.0.1", server);
        t.expected_status = Some(204);
        let outcome = checker.check(&t).await;
        assert!(!outcome.ok);
        assert!(outcome.error.unwrap().contains("200"));
    }

    #[tokio::test]
    async fn http_body_contains_check_passes_and_fails_correctly() {
        let server = tiny_http_server(200, "hello world").await;
        let checker = RealServiceChecker::new().unwrap();

        let mut ok_target = target(CheckProtocol::Http, "127.0.0.1", server);
        ok_target.body_contains = Some("world".to_string());
        assert!(checker.check(&ok_target).await.ok);

        let mut bad_target = target(CheckProtocol::Http, "127.0.0.1", server);
        bad_target.body_contains = Some("goodbye".to_string());
        let outcome = checker.check(&bad_target).await;
        assert!(!outcome.ok);
        assert!(outcome.error.unwrap().contains("substring"));
    }

    /// Minimal one-shot HTTP/1.1 server over a raw TCP listener — good enough to drive
    /// `RealServiceChecker::check_http` end to end without pulling in a whole test-server
    /// crate. Returns the port; accepts exactly one connection then serves a fixed
    /// response, looping to keep accepting for the handful of requests a single test file
    /// might make against it.
    async fn tiny_http_server(status: u16, body: &'static str) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 1024];
                // Drain (and discard) the request line/headers — we don't need to parse
                // them for this fixed-response fake.
                let _ = socket.read(&mut buf).await;
                let reason = if status == 200 { "OK" } else { "No Content" };
                let response = format!("HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });
        port
    }
}
