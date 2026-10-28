use async_trait::async_trait;
use discovery_core::DeviceTarget;
use std::collections::HashMap;
use std::sync::RwLock;

use crate::{SnmpClient, SnmpValue};

/// In-memory SNMP "agent" used by unit/integration/e2e tests (and the demo binary) to
/// simulate real devices without opening any sockets. Seed it with `(ip, oid) -> value`
/// pairs via [`Self::seed_get`] (and, for walks, [`Self::seed_walk`]), then run the real
/// pipeline against it — this is the "виртуальные тестовые устройства" the pipeline's
/// e2e tests exercise.
#[derive(Default)]
pub struct FakeSnmpClient {
    gets: RwLock<HashMap<(String, String), SnmpValue>>,
    walks: RwLock<HashMap<(String, String), Vec<(String, SnmpValue)>>>,
    /// Deliberately separate from `walks` rather than encoding "error" as a value in that
    /// map — an *unseeded* walk means "this OID has no data" (a legitimately empty table,
    /// e.g. `LAG` on a device with no aggregation), which must stay `Ok(vec![])`, the
    /// existing default below. Only an OID explicitly seeded here via
    /// [`Self::seed_walk_error`] simulates a genuine transport failure (timeout/unreachable)
    /// — see `discovery_snmp::poll_table_metric`'s docs for why callers need to be able to
    /// distinguish the two in tests.
    walk_errors: RwLock<HashMap<(String, String), String>>,
}

impl FakeSnmpClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seed_get(&self, ip: &str, oid: &str, value: SnmpValue) {
        self.gets
            .write()
            .unwrap()
            .insert((ip.to_string(), oid.to_string()), value);
    }

    pub fn seed_walk(&self, ip: &str, oid_prefix: &str, values: Vec<(String, SnmpValue)>) {
        self.walks
            .write()
            .unwrap()
            .insert((ip.to_string(), oid_prefix.to_string()), values);
    }

    /// Makes `walk(ip, oid_prefix)` return `Err` instead of the usual "unseeded = empty
    /// table" default — simulates a real network/timeout failure on one specific walk, for
    /// tests that need to prove a caller handles that distinctly from a legitimately empty
    /// table (e.g. `poll_table_metric`'s whole-metric-fails-if-any-column-fails contract).
    pub fn seed_walk_error(&self, ip: &str, oid_prefix: &str, error: impl Into<String>) {
        self.walk_errors
            .write()
            .unwrap()
            .insert((ip.to_string(), oid_prefix.to_string()), error.into());
    }
}

#[async_trait]
impl SnmpClient for FakeSnmpClient {
    async fn get(&self, target: &DeviceTarget, oid: &str) -> anyhow::Result<SnmpValue> {
        self.gets
            .read()
            .unwrap()
            .get(&(target.ip.clone(), oid.to_string()))
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!("FakeSnmpClient: no seeded value for {} {}", target.ip, oid)
            })
    }

    async fn walk(
        &self,
        target: &DeviceTarget,
        oid: &str,
    ) -> anyhow::Result<Vec<(String, SnmpValue)>> {
        let key = (target.ip.clone(), oid.to_string());
        if let Some(error) = self.walk_errors.read().unwrap().get(&key) {
            return Err(anyhow::anyhow!(error.clone()));
        }
        Ok(self
            .walks
            .read()
            .unwrap()
            .get(&key)
            .cloned()
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn returns_seeded_value_and_errors_on_unseeded_oid() {
        let snmp = FakeSnmpClient::new();
        snmp.seed_get(
            "10.0.0.1",
            "1.3.6.1.2.1.1.5.0",
            SnmpValue::OctetString("sw1".into()),
        );

        let target = DeviceTarget {
            ip: "10.0.0.1".into(),
            ..Default::default()
        };
        let value = snmp.get(&target, "1.3.6.1.2.1.1.5.0").await.unwrap();
        assert_eq!(value.as_str(), Some("sw1"));

        assert!(snmp.get(&target, "1.3.6.1.2.1.1.1.0").await.is_err());
    }
}
