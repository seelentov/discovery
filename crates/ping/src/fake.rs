use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;

use crate::{PingOutcome, Pinger};

/// In-memory ping "responder" for tests — mirrors `discovery_snmp::FakeSnmpClient`. Seed
/// `(ip -> bool)` pairs via [`Self::seed`] for the common case (fully up or fully down —
/// maps to `loss_pct` `0.0`/`100.0`), or a full [`PingOutcome`] via [`Self::seed_outcome`]
/// when a test needs a specific partial-loss value (e.g. proving `ReachabilityPollHandler`
/// actually threads `loss_pct` through to `DeviceStore::set_reachability` unchanged, not
/// just `reachable`). An un-seeded IP defaults to fully unreachable — the safe default: a
/// test that forgets to seed a device should see it as down, not silently up.
#[derive(Default)]
pub struct FakePinger {
    replies: RwLock<HashMap<String, PingOutcome>>,
}

impl FakePinger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Convenience for the common all-or-nothing case — `reachable=true` seeds `loss_pct:
    /// 0.0`, `reachable=false` seeds `loss_pct: 100.0`. Use [`Self::seed_outcome`] directly
    /// for a partial-loss value.
    pub fn seed(&self, ip: &str, reachable: bool) {
        self.seed_outcome(
            ip,
            PingOutcome {
                reachable,
                loss_pct: if reachable { 0.0 } else { 100.0 },
            },
        );
    }

    pub fn seed_outcome(&self, ip: &str, outcome: PingOutcome) {
        self.replies
            .write()
            .unwrap()
            .insert(ip.to_string(), outcome);
    }
}

#[async_trait]
impl Pinger for FakePinger {
    async fn ping(&self, ip: &str, _timeout: Duration, _retries: u32) -> PingOutcome {
        // A seeded reply is deterministic (a test fixture, not a flaky network) — retrying
        // it would just return the same answer `retries` more times for no benefit, so
        // `retries` is intentionally accepted-and-ignored here, unlike `IcmpPinger` where
        // it drives real repeated I/O.
        self.replies
            .read()
            .unwrap()
            .get(ip)
            .copied()
            .unwrap_or(PingOutcome {
                reachable: false,
                loss_pct: 100.0,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn returns_seeded_value_and_defaults_to_unreachable() {
        let pinger = FakePinger::new();
        pinger.seed("10.0.0.1", true);
        pinger.seed("10.0.0.2", false);

        assert_eq!(
            pinger.ping("10.0.0.1", Duration::from_millis(100), 0).await,
            PingOutcome {
                reachable: true,
                loss_pct: 0.0
            }
        );
        assert_eq!(
            pinger.ping("10.0.0.2", Duration::from_millis(100), 0).await,
            PingOutcome {
                reachable: false,
                loss_pct: 100.0
            }
        );
        let unseeded = pinger.ping("10.0.0.3", Duration::from_millis(100), 0).await;
        assert!(
            !unseeded.reachable,
            "unseeded IP must default to unreachable"
        );
        assert_eq!(unseeded.loss_pct, 100.0);
    }

    #[tokio::test]
    async fn seed_outcome_carries_a_partial_loss_value_through_unchanged() {
        let pinger = FakePinger::new();
        pinger.seed_outcome(
            "10.0.0.1",
            PingOutcome {
                reachable: true,
                loss_pct: 25.0,
            },
        );
        assert_eq!(
            pinger.ping("10.0.0.1", Duration::from_millis(100), 0).await,
            PingOutcome {
                reachable: true,
                loss_pct: 25.0
            }
        );
    }
}
