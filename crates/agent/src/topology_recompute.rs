//! `TopologyRecomputeHandler` — the `QueueKind::TopologyRecompute` worker. Recomputes one
//! device's `my_key`/claimed-neighbors under every enabled
//! `discovery_config_store::TopologyRule`, reacting to a fresh metric poll
//! (`crate::handlers::MetricPollHandler`'s enqueue, right after `record_metric_polls` —
//! see that call site's docs) rather than running on its own timer. See
//! `discovery_topology`'s module docs for why recomputing this one device never needs to
//! touch any other device — the other side of an edge resolves at *read* time.

use std::sync::Arc;

use async_trait::async_trait;
use discovery_core::payload::TopologyRecomputePayload;
use discovery_core::Job;
use discovery_devices::{DeviceMetricsStore, DeviceStore};
use discovery_dsl::topology::TopologyEvaluator;
use discovery_queue::JobHandler;
use discovery_topology::TopologyStore;
use tracing::warn;

pub struct TopologyRecomputeHandler {
    /// Loaded fresh on every `handle()` call, not cached — same "small config table, read
    /// it live" convention `AlertEvalHandler.maintenance_windows` already documents (a
    /// rule can be edited/enabled/disabled between ticks and must take effect
    /// immediately, not after some cache TTL).
    pub rules: Arc<dyn discovery_config_store::TopologyRuleStore>,
    pub topology: Arc<dyn TopologyStore>,
    pub devices: Arc<dyn DeviceStore>,
    pub device_metrics: Arc<dyn DeviceMetricsStore>,
    pub evaluator: Arc<TopologyEvaluator>,
}

#[async_trait]
impl JobHandler for TopologyRecomputeHandler {
    async fn handle(&self, job: Job) -> anyhow::Result<()> {
        let payload: TopologyRecomputePayload = serde_json::from_value(job.payload)?;

        // Same "stale target, quietly done" contract every other handler in this crate
        // uses when the device was deleted between enqueue and this job actually running.
        let Some((device, metrics)) = discovery_devices::get(
            self.devices.as_ref(),
            self.device_metrics.as_ref(),
            payload.device_id,
        )
        .await?
        else {
            return Ok(());
        };

        for rule in self
            .rules
            .list_all()
            .await?
            .into_iter()
            .filter(|r| r.enabled)
        {
            // A malformed expression in *this* rule must not block every other enabled
            // rule from recomputing for this device — same "warn and move on" posture
            // `AlertEvalHandler::eval_row_scoped_rule` already takes for a broken
            // `row_key_expression`. A genuine storage failure below (`apply_recompute`)
            // is a different matter — that still propagates via `?`, so the queue retries
            // the whole job.
            let my_key = match self.evaluator.evaluate_my_key(
                &rule.my_key_expression,
                &device.facts,
                &metrics,
            ) {
                Ok(key) => key,
                Err(e) => {
                    warn!(ip = %device.facts.ip, rule = %rule.name, error = %e, "my_key_expression failed to evaluate — skipping this rule this tick");
                    continue;
                }
            };
            let claimed_neighbors = match self.evaluator.evaluate_claimed_neighbors(
                rule.claimed_neighbors_expression.as_deref(),
                &device.facts,
                &metrics,
            ) {
                Ok(claimed) => claimed,
                Err(e) => {
                    warn!(ip = %device.facts.ip, rule = %rule.name, error = %e, "claimed_neighbors_expression failed to evaluate — skipping this rule this tick");
                    continue;
                }
            };
            let rank = match self.evaluator.evaluate_rank(
                rule.rank_expression.as_deref(),
                &device.facts,
                &metrics,
            ) {
                Ok(rank) => rank,
                Err(e) => {
                    warn!(ip = %device.facts.ip, rule = %rule.name, error = %e, "rank_expression failed to evaluate — skipping this rule this tick");
                    continue;
                }
            };

            self.topology
                .apply_recompute(&rule.name, device.id, my_key, claimed_neighbors, rank)
                .await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use discovery_config_store::{SeaOrmTopologyRuleStore, TopologyRule, TopologyRuleStore};
    use discovery_core::{DeviceFacts, MetricPollOutcome, MetricValue, QueueKind};
    use discovery_devices::{SeaOrmDeviceMetricsStore, SeaOrmDeviceStore};
    use discovery_topology::SeaOrmTopologyStore;
    use std::collections::BTreeMap;
    use uuid::Uuid;

    fn job(device_id: Uuid) -> Job {
        Job {
            id: 1,
            queue: QueueKind::TopologyRecompute,
            payload: serde_json::to_value(TopologyRecomputePayload { device_id }).unwrap(),
            dedupe_key: None,
            state: discovery_core::JobState::InProgress,
            attempts: 1,
            max_attempts: 5,
            locked_by: None,
            locked_at: None,
            last_error: None,
            result: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            paused: false,
        }
    }

    async fn setup() -> (
        TopologyRecomputeHandler,
        Arc<dyn DeviceStore>,
        Arc<dyn DeviceMetricsStore>,
        Arc<dyn TopologyRuleStore>,
        Arc<dyn TopologyStore>,
    ) {
        let db = discovery_migration::connect_in_memory_for_tests().await;
        let device_metrics: Arc<dyn DeviceMetricsStore> =
            Arc::new(SeaOrmDeviceMetricsStore::new(db.clone()));
        let alerts: Arc<dyn discovery_alerts::AlertStore> =
            Arc::new(discovery_alerts::SeaOrmAlertStore::new(db.clone()));
        let devices: Arc<dyn DeviceStore> = Arc::new(SeaOrmDeviceStore::new(
            db.clone(),
            device_metrics.clone(),
            alerts,
        ));
        let rules: Arc<dyn TopologyRuleStore> = Arc::new(SeaOrmTopologyRuleStore::new(db.clone()));
        let topology: Arc<dyn TopologyStore> = Arc::new(SeaOrmTopologyStore::new(db));
        let handler = TopologyRecomputeHandler {
            rules: rules.clone(),
            topology: topology.clone(),
            devices: devices.clone(),
            device_metrics: device_metrics.clone(),
            evaluator: Arc::new(TopologyEvaluator::new()),
        };
        (handler, devices, device_metrics, rules, topology)
    }

    async fn new_device(devices: &Arc<dyn DeviceStore>, ip: &str) -> Uuid {
        devices
            .resolve(DeviceFacts { ip: ip.to_string() })
            .await
            .unwrap()
            .0
    }

    fn lldp_rule() -> TopologyRule {
        TopologyRule {
            id: Uuid::new_v4(),
            name: "lldp".to_string(),
            enabled: true,
            my_key_expression: "metrics.lldp_chassis_id".to_string(),
            claimed_neighbors_expression: Some(
                "metrics.lldp_rem_table.map(|row| row.chassis_id)".to_string(),
            ),
            rank_expression: None,
            watched_metrics: None,
        }
    }

    /// The scenario from the design discussion, now end to end through the real handler
    /// and real storage: device A's tick claims B before B has ever polled — nothing
    /// resolves. Device B's tick (**A is never re-enqueued or re-handled**) makes A's
    /// original claim resolve, purely because `neighbors_of` reads current state at call
    /// time.
    #[tokio::test]
    async fn recomputing_only_the_second_device_makes_the_first_devices_claim_resolve() {
        let (handler, devices, device_metrics, rules, topology) = setup().await;
        rules.upsert(&lldp_rule()).await.unwrap();

        let a = new_device(&devices, "10.0.0.1").await;
        let b = new_device(&devices, "10.0.0.2").await;

        let mut a_metrics = BTreeMap::new();
        a_metrics.insert(
            "lldp_chassis_id".to_string(),
            MetricPollOutcome::Ok(MetricValue::Str("key-a".to_string())),
        );
        a_metrics.insert(
            "lldp_rem_table".to_string(),
            MetricPollOutcome::Ok(MetricValue::Table(vec![discovery_core::MetricTableRow {
                index: "0.1.1".to_string(),
                fields: BTreeMap::from([(
                    "chassis_id".to_string(),
                    MetricValue::Str("key-b".to_string()),
                )]),
            }])),
        );
        device_metrics
            .record_metric_polls(a, &a_metrics)
            .await
            .unwrap();

        handler.handle(job(a)).await.unwrap();
        assert!(
            topology.neighbors_of("lldp", a).await.unwrap().is_empty(),
            "B hasn't polled yet — nothing to resolve to"
        );

        let mut b_metrics = BTreeMap::new();
        b_metrics.insert(
            "lldp_chassis_id".to_string(),
            MetricPollOutcome::Ok(MetricValue::Str("key-b".to_string())),
        );
        b_metrics.insert(
            "lldp_rem_table".to_string(),
            MetricPollOutcome::Ok(MetricValue::Table(vec![discovery_core::MetricTableRow {
                index: "0.1.1".to_string(),
                fields: BTreeMap::from([(
                    "chassis_id".to_string(),
                    MetricValue::Str("key-a".to_string()),
                )]),
            }])),
        );
        device_metrics
            .record_metric_polls(b, &b_metrics)
            .await
            .unwrap();

        handler.handle(job(b)).await.unwrap();

        let neighbors_a = topology.neighbors_of("lldp", a).await.unwrap();
        assert_eq!(neighbors_a.len(), 1);
        assert_eq!(neighbors_a[0].neighbor_device_id, b);
        assert!(neighbors_a[0].confirmed, "both sides now claim each other");
    }

    /// Same reactive property as the test above, for direction: A's `rank` is written on
    /// A's own tick, B's on B's own tick — neither recompute ever re-touches the other
    /// device, yet direction resolves correctly the moment both sides are known, exactly
    /// like adjacency already does.
    #[tokio::test]
    async fn rank_flows_through_end_to_end_and_resolves_direction_reactively() {
        let (handler, devices, device_metrics, rules, topology) = setup().await;
        let mut rule = lldp_rule();
        rule.rank_expression = Some("metrics.role_value".to_string());
        rules.upsert(&rule).await.unwrap();

        let a = new_device(&devices, "10.0.0.1").await;
        let b = new_device(&devices, "10.0.0.2").await;

        let mut a_metrics = BTreeMap::new();
        a_metrics.insert(
            "lldp_chassis_id".to_string(),
            MetricPollOutcome::Ok(MetricValue::Str("key-a".to_string())),
        );
        a_metrics.insert(
            "role_value".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(0)),
        );
        a_metrics.insert(
            "lldp_rem_table".to_string(),
            MetricPollOutcome::Ok(MetricValue::Table(vec![discovery_core::MetricTableRow {
                index: "0.1.1".to_string(),
                fields: BTreeMap::from([(
                    "chassis_id".to_string(),
                    MetricValue::Str("key-b".to_string()),
                )]),
            }])),
        );
        device_metrics
            .record_metric_polls(a, &a_metrics)
            .await
            .unwrap();
        handler.handle(job(a)).await.unwrap();

        let mut b_metrics = BTreeMap::new();
        b_metrics.insert(
            "lldp_chassis_id".to_string(),
            MetricPollOutcome::Ok(MetricValue::Str("key-b".to_string())),
        );
        b_metrics.insert(
            "role_value".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(1)),
        );
        b_metrics.insert(
            "lldp_rem_table".to_string(),
            MetricPollOutcome::Ok(MetricValue::Table(vec![discovery_core::MetricTableRow {
                index: "0.1.1".to_string(),
                fields: BTreeMap::from([(
                    "chassis_id".to_string(),
                    MetricValue::Str("key-a".to_string()),
                )]),
            }])),
        );
        device_metrics
            .record_metric_polls(b, &b_metrics)
            .await
            .unwrap();
        handler.handle(job(b)).await.unwrap();

        let neighbors_a = topology.neighbors_of("lldp", a).await.unwrap();
        assert_eq!(
            neighbors_a[0].upstream_device_id,
            Some(a),
            "a's lower rank must resolve as upstream, without a ever being re-handled"
        );
    }

    #[tokio::test]
    async fn disabled_rules_are_never_evaluated() {
        let (handler, devices, device_metrics, rules, topology) = setup().await;
        let mut rule = lldp_rule();
        rule.enabled = false;
        rules.upsert(&rule).await.unwrap();

        let a = new_device(&devices, "10.0.0.1").await;
        let mut metrics = BTreeMap::new();
        metrics.insert(
            "lldp_chassis_id".to_string(),
            MetricPollOutcome::Ok(MetricValue::Str("key-a".to_string())),
        );
        device_metrics
            .record_metric_polls(a, &metrics)
            .await
            .unwrap();

        handler.handle(job(a)).await.unwrap();
        assert!(topology.resolved_edges("lldp").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_deleted_device_is_a_quiet_no_op_not_an_error() {
        let (handler, ..) = setup().await;
        handler.handle(job(Uuid::new_v4())).await.unwrap();
    }

    #[tokio::test]
    async fn a_device_with_no_lldp_data_participates_in_no_edges() {
        let (handler, devices, device_metrics, rules, topology) = setup().await;
        rules.upsert(&lldp_rule()).await.unwrap();

        // A CPE profile that never polls LLDP at all — `metrics.lldp_chassis_id` is simply
        // absent, not present-but-empty.
        let a = new_device(&devices, "10.0.0.1").await;
        let mut metrics = BTreeMap::new();
        metrics.insert(
            "uptime".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(12345)),
        );
        device_metrics
            .record_metric_polls(a, &metrics)
            .await
            .unwrap();

        handler.handle(job(a)).await.unwrap();
        assert!(topology.resolved_edges("lldp").await.unwrap().is_empty());
    }
}
