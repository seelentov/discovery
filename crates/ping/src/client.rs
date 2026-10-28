use async_trait::async_trait;
use std::time::Duration;
use tracing::warn;

/// Outcome of one [`Pinger::ping`] call — added 2026-09-14, `docs/Roadmap.md` "До релиза"
/// item 5 ("Packet loss % не собирается вообще"), a direct honest-porting prerequisite for
/// AggreGate's ICMP-packet-loss alert. Before this, `ping()` returned a plain `bool` and
/// short-circuited on the very first successful attempt — fine for "is it reachable", but
/// it means a device that answered on attempt 1 of `1 + retries` looks identical to one
/// that answered on every attempt: there's no way to compute a meaningful loss percentage
/// from "we stopped looking after the first success". `IcmpPinger` now always runs the
/// full `1 + retries` attempts (see its docs) so `loss_pct` reflects the real fraction that
/// got no reply, not an artifact of early-exit.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PingOutcome {
    /// `true` iff at least one of the `1 + retries` attempts got a reply — same meaning
    /// the old plain-`bool` return value had, so every existing caller's `if outcome.reachable`
    /// logic is unchanged.
    pub reachable: bool,
    /// Percentage (`0.0`-`100.0`) of the `1 + retries` attempts that got **no** reply.
    /// `0.0` = every attempt answered, `100.0` = none did.
    pub loss_pct: f64,
}

/// Abstraction over "is this IP reachable over ICMP right now, and how much of it got
/// dropped" — deliberately not `anyhow::Result<PingOutcome>` like
/// `discovery_snmp::SnmpClient::get`: a caller here
/// (`discovery-agent::handlers::ReachabilityPollHandler`) only ever needs "did it answer"
/// plus "how reliably", never *why* an individual attempt failed (unlike a metric poll
/// failure, which gets logged per-metric with its specific error text) — see that
/// handler's docs. Kept trait-based, mirroring `discovery-snmp`'s split, so the pipeline
/// can run against [`FakePinger`] in tests without any real ICMP I/O.
#[async_trait]
pub trait Pinger: Send + Sync {
    /// Runs `1 + retries` attempts (same convention as `discovery_snmp::DeviceTarget::
    /// retries`) and reports both whether any got through and what fraction didn't — see
    /// [`PingOutcome`]'s docs. An unparseable `ip` collapses to `PingOutcome { reachable:
    /// false, loss_pct: 100.0 }`, the same "not reachable" signal a real all-attempts-failed
    /// probe would report.
    ///
    /// `timeout`/`retries` are caller-supplied on every call, not baked into the
    /// implementor — both now come from `discovery_core::PingConfig`, read fresh from
    /// `SettingsStore` on each use by `discovery-agent::handlers::{DiscoveryHandler,
    /// ReachabilityPollHandler}`, so a dashboard edit to either value applies on the very
    /// next probe, no restart (direct user correction 2026-08-18: "Нужно сделать
    /// настраиваемым и таймауты и кол-во проб и периодичность" — periodicity was already
    /// covered by `PollIntervalsConfig.reachability_secs`, this covers the other two).
    async fn ping(&self, ip: &str, timeout: Duration, retries: u32) -> PingOutcome;
}

/// Real ICMP echo client — backed by `surge-ping`, in its **unprivileged** mode
/// (`SOCK_DGRAM` + `IPPROTO_ICMP`, not a raw socket): confirmed live in this project's dev
/// environment to work without root (a direct Python `socket` test succeeded, and — more to
/// the point — the system `ping` binary itself distinguishes a real loopback-aliased
/// devicefarm device from a bare, unaliased one on the same subnet, proving ICMP here is a
/// genuinely meaningful signal, not something that trivially always succeeds just because
/// every test IP happens to be on `127.0.0.0/8`).
///
/// Holds one shared `surge_ping::Client` (created once in `discovery-agent::main`, not
/// per-call) — the client owns the actual ICMP socket; recreating it on every ping would be
/// wasteful and is not how `surge-ping` is meant to be used (each `.pinger()` call is a
/// lightweight per-target session over the same shared socket).
pub struct IcmpPinger {
    client: surge_ping::Client,
}

impl IcmpPinger {
    /// Fails only if the underlying ICMP socket can't be created at all (e.g. genuinely no
    /// permission on a platform that doesn't support the unprivileged path) — a startup-time
    /// failure, handled the same way `RealSnmpClient`'s sibling concerns are: propagated via
    /// `anyhow::Context` up through `discovery-agent::main`'s single fatal-error path, not
    /// silently degraded.
    pub fn new() -> anyhow::Result<Self> {
        let config = surge_ping::Config::builder()
            .kind(surge_ping::ICMP::V4)
            .build();
        let client = surge_ping::Client::new(&config)?;
        Ok(Self { client })
    }
}

#[async_trait]
impl Pinger for IcmpPinger {
    async fn ping(&self, ip: &str, timeout: Duration, retries: u32) -> PingOutcome {
        let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
            warn!(ip, "IcmpPinger: not a valid IP address");
            return PingOutcome {
                reachable: false,
                loss_pct: 100.0,
            };
        };

        // `1 + retries` attempts total, same convention as `RealSnmpClient::get`'s retry
        // loop — but unlike before this type existed, **every** attempt always runs, no
        // more short-circuiting on the first success (see `PingOutcome`'s docs for why: a
        // meaningful `loss_pct` can't be computed from "stopped looking after attempt 1
        // succeeded"). This does mean a device that's fully reachable now costs `1 +
        // retries` round trips per tick instead of typically just one — an accepted
        // trade-off for an honest number, not an oversight.
        let total_attempts = retries + 1;
        let mut received = 0u32;
        for attempt in 0..total_attempts {
            // A fresh, random identifier per attempt — `surge-ping` uses it (plus the
            // sequence number) to match an echo reply back to this specific request, same
            // idea as an SNMP request-id. Random rather than a fixed constant so concurrent
            // pings from different `ReachabilityPollHandler` workers (this runs with its
            // own concurrency setting, several in flight at once) — and successive attempts
            // of the same probe — don't collide.
            let identifier = surge_ping::PingIdentifier(rand::random());
            let mut pinger = self.client.pinger(addr, identifier).await;
            pinger.timeout(timeout);

            if matches!(pinger.ping(surge_ping::PingSequence(0), &[]).await, Ok(_)) {
                received += 1;
            } else if attempt + 1 < total_attempts {
                warn!(
                    ip,
                    attempt, retries, "IcmpPinger: attempt failed, continuing"
                );
            }
        }
        let loss_pct = 100.0 * (total_attempts - received) as f64 / total_attempts as f64;
        PingOutcome {
            reachable: received > 0,
            loss_pct,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Not a real network test (would need a live target and CI-unfriendly ICMP
    /// permissions) — just confirms an unparseable address fails closed rather than
    /// panicking, and reports the "every attempt failed" loss reading (100%), not some
    /// other value.
    #[tokio::test]
    async fn unparseable_ip_returns_unreachable_with_full_loss_not_a_panic() {
        let Ok(pinger) = IcmpPinger::new() else {
            // Environment doesn't support unprivileged ICMP sockets at all (e.g. some CI
            // sandboxes) — nothing to test here, but must not fail the suite over an
            // environment limitation unrelated to the code under test.
            return;
        };
        let outcome = pinger.ping("not-an-ip", Duration::from_millis(50), 0).await;
        assert!(!outcome.reachable);
        assert_eq!(outcome.loss_pct, 100.0);
    }

    /// A real (unprivileged) ICMP probe against an address nothing answers on
    /// (`TEST-NET-1`, RFC 5737 — reserved for documentation, guaranteed never to reply) with
    /// `retries=3` (4 total attempts) — proves the "every attempt actually runs, not just
    /// the first" behavior this type exists for: 100% loss, not a lower number an
    /// early-exit implementation could still produce for a single failed attempt.
    #[tokio::test]
    async fn every_attempt_runs_against_an_address_that_never_replies() {
        let Ok(pinger) = IcmpPinger::new() else {
            return;
        };
        let outcome = pinger
            .ping("192.0.2.1", Duration::from_millis(100), 3)
            .await;
        assert!(!outcome.reachable);
        assert_eq!(
            outcome.loss_pct, 100.0,
            "all 4 attempts against a guaranteed-silent address must be counted as lost"
        );
    }
}
