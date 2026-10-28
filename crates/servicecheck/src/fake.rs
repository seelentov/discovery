use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;

use crate::{CheckOutcome, CheckTarget, ServiceChecker};

/// In-memory check "responder" for tests — mirrors `discovery_ping::FakePinger`. Seed
/// `((host, port) -> CheckOutcome)` pairs via [`Self::seed`], then run the pipeline against
/// it. An un-seeded `(host, port)` defaults to a failed outcome — same "the safe default is
/// down, not silently up" reasoning as `FakePinger`'s un-seeded IP.
#[derive(Default)]
pub struct FakeServiceChecker {
    replies: RwLock<HashMap<(String, u16), CheckOutcome>>,
}

impl FakeServiceChecker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seed(&self, host: &str, port: u16, outcome: CheckOutcome) {
        self.replies
            .write()
            .unwrap()
            .insert((host.to_string(), port), outcome);
    }

    pub fn seed_ok(&self, host: &str, port: u16, latency_ms: u64) {
        self.seed(
            host,
            port,
            CheckOutcome {
                ok: true,
                latency_ms: Some(latency_ms),
                error: None,
            },
        );
    }

    pub fn seed_err(&self, host: &str, port: u16, error: impl Into<String>) {
        self.seed(
            host,
            port,
            CheckOutcome {
                ok: false,
                latency_ms: None,
                error: Some(error.into()),
            },
        );
    }
}

#[async_trait]
impl ServiceChecker for FakeServiceChecker {
    async fn check(&self, target: &CheckTarget) -> CheckOutcome {
        self.replies
            .read()
            .unwrap()
            .get(&(target.host.clone(), target.port))
            .cloned()
            .unwrap_or(CheckOutcome {
                ok: false,
                latency_ms: None,
                error: Some("not seeded".to_string()),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CheckProtocol;
    use std::time::Duration;

    fn target(host: &str, port: u16) -> CheckTarget {
        CheckTarget {
            protocol: CheckProtocol::Tcp,
            host: host.to_string(),
            port,
            path: "/".to_string(),
            expected_status: None,
            body_contains: None,
            timeout: Duration::from_millis(100),
        }
    }

    #[tokio::test]
    async fn returns_seeded_value_and_defaults_to_a_failed_outcome() {
        let checker = FakeServiceChecker::new();
        checker.seed_ok("10.0.0.1", 22, 5);
        checker.seed_err("10.0.0.2", 22, "refused");

        let ok = checker.check(&target("10.0.0.1", 22)).await;
        assert!(ok.ok);
        assert_eq!(ok.latency_ms, Some(5));

        let err = checker.check(&target("10.0.0.2", 22)).await;
        assert!(!err.ok);
        assert_eq!(err.error.as_deref(), Some("refused"));

        let unseeded = checker.check(&target("10.0.0.3", 22)).await;
        assert!(
            !unseeded.ok,
            "unseeded target must default to a failed outcome"
        );
    }
}
