use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use discovery_config_store::SettingsStore;
use discovery_core::payload::{OperatorAction, OperatorActionPayload};
use discovery_core::secret::{encrypt_secret, SecretKey};
use discovery_core::{Job, QueueKind, SshTarget};
use discovery_devices::DeviceStore;
use discovery_dsl::{ProfileMatcher, ServiceCheckProtocol};
use discovery_journal::{JournalEntry, JournalStore};
use discovery_ping::Pinger;
use discovery_queue::{JobHandler, JobQueueStore};
use discovery_servicecheck::{CheckProtocol, CheckTarget, ServiceChecker};
use discovery_ssh::CliClient;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::handlers::{resolve_service_check_host, MetricPollHandler, SnmpPollHandler};

/// A single worker serializes explicit operations, while the queue dedupe key prevents
/// more than one pending/running operator action for the same device.
pub struct OperatorActionHandler {
    pub queue: Arc<dyn JobQueueStore>,
    pub devices: Arc<dyn DeviceStore>,
    pub matcher: Arc<ProfileMatcher>,
    pub settings: Arc<dyn SettingsStore>,
    pub pinger: Arc<dyn Pinger>,
    pub checker: Arc<dyn ServiceChecker>,
    pub cli: Arc<dyn CliClient>,
    pub snmp_poll: Arc<SnmpPollHandler>,
    pub metric_poll: Arc<MetricPollHandler>,
    pub journal: Arc<dyn JournalStore>,
    pub secret_key: Option<Arc<SecretKey>>,
}

impl OperatorActionHandler {
    async fn run(&self, job: &Job, payload: &OperatorActionPayload) -> anyhow::Result<Value> {
        let device = self
            .devices
            .get_device(payload.device_id)
            .await
            .map_err(|_| anyhow::anyhow!("device_lookup_failed"))?
            .ok_or_else(|| anyhow::anyhow!("device_not_found"))?;
        if !device.enabled {
            anyhow::bail!("device_disabled");
        }

        match payload.action {
            OperatorAction::Test => {
                let ping = self.settings.ping_config().await;
                let outcome = self
                    .pinger
                    .ping(
                        &device.facts.ip,
                        Duration::from_millis(ping.timeout_ms),
                        ping.retries,
                    )
                    .await;
                let mut checks = Vec::new();
                if let Some(name) = &device.profile {
                    if let Some(profile) = self.matcher.profile_by_name(name).await {
                        for check in &profile.service_checks.checks {
                            if !check.enabled {
                                continue;
                            }
                            let host = resolve_service_check_host(
                                check.target.as_deref(),
                                &device.facts.ip,
                            )
                            .map_err(|_| anyhow::anyhow!("service_target_not_allowed"))?;
                            let protocol = match check.protocol {
                                ServiceCheckProtocol::Tcp => CheckProtocol::Tcp,
                                ServiceCheckProtocol::Http => CheckProtocol::Http,
                                ServiceCheckProtocol::Https => CheckProtocol::Https,
                                ServiceCheckProtocol::Ssh => CheckProtocol::Ssh,
                            };
                            let result = self
                                .checker
                                .check(&CheckTarget {
                                    protocol,
                                    host,
                                    port: check.port,
                                    path: check.path_or_default().to_string(),
                                    expected_status: check.expected_status,
                                    body_contains: check.body_contains.clone(),
                                    timeout: Duration::from_millis(
                                        check.timeout_ms.unwrap_or(2000),
                                    ),
                                })
                                .await;
                            checks.push(json!({"name": check.name, "ok": result.ok,
                                "reason": if result.ok { None } else { Some("service_check_failed") }}));
                        }
                    }
                }
                Ok(
                    json!({"ping_ok": outcome.reachable, "ping_loss_pct": outcome.loss_pct,
                    "reason": if outcome.reachable { None } else { Some("device_unreachable") },
                    "services": checks, "ok": outcome.reachable && checks.iter().all(|c| c["ok"] == true)}),
                )
            }
            OperatorAction::PollNow => {
                let generation = self
                    .devices
                    .current_poll_generation(device.id)
                    .await
                    .map_err(|_| anyhow::anyhow!("device_lookup_failed"))?
                    .ok_or_else(|| anyhow::anyhow!("poll_generation_missing"))?;
                let Some(name) = &device.profile else {
                    anyhow::bail!("profile_missing");
                };
                let Some(profile) = self.matcher.profile_by_name(name).await else {
                    anyhow::bail!("profile_missing");
                };
                let metric_count = profile
                    .metrics
                    .poll
                    .values()
                    .filter(|spec| spec.enabled() && !spec.is_ssh_command())
                    .count();
                if metric_count == 0 {
                    anyhow::bail!("no_poll_metrics");
                }
                let mut sub_job = job.clone();
                sub_job.queue = QueueKind::MetricPoll;
                sub_job.payload =
                    json!({"device_id": device.id, "generation": generation, "manual": true});
                self.metric_poll
                    .handle(sub_job)
                    .await
                    .map_err(|_| anyhow::anyhow!("poll_failed"))?;
                let records = self
                    .metric_poll
                    .device_metrics
                    .get_metric_records(device.id)
                    .await
                    .map_err(|_| anyhow::anyhow!("poll_result_unavailable"))?;
                let failed_metrics: Vec<_> = records
                    .iter()
                    .filter(|record| {
                        profile
                            .metrics
                            .poll
                            .get(&record.name)
                            .is_some_and(|spec| !spec.is_ssh_command())
                            && record.error.is_some()
                    })
                    .map(|record| record.name.clone())
                    .collect();
                Ok(
                    json!({"message": "poll_completed", "metric_count": metric_count,
                    "failed_metrics": failed_metrics}),
                )
            }
            OperatorAction::Rediscover => {
                let mut sub_job = job.clone();
                sub_job.queue = QueueKind::SnmpPoll;
                sub_job.payload =
                    json!({"ip": device.facts.ip, "recurring": false, "manual": true});
                self.snmp_poll
                    .handle(sub_job)
                    .await
                    .map_err(|_| anyhow::anyhow!("rediscovery_failed"))?;
                Ok(json!({"message": "identity_check_queued"}))
            }
            OperatorAction::Backup => {
                let backup_settings = self.settings.config_backup().await;
                let Some(key) = &self.secret_key else {
                    anyhow::bail!("backup_key_unavailable");
                };
                let Some(credentials) = &device.ssh_credentials else {
                    anyhow::bail!("ssh_credentials_missing");
                };
                if credentials.known_host_key.is_none() {
                    anyhow::bail!("ssh_host_key_not_pinned");
                }
                let Some(name) = &device.profile else {
                    anyhow::bail!("profile_missing");
                };
                let Some(profile) = self.matcher.profile_by_name(name).await else {
                    anyhow::bail!("profile_missing");
                };
                // The operator cannot supply a command. Only a profile-approved, read-only
                // configuration command from this exact allowlist can be executed.
                let command = profile
                    .metrics
                    .poll
                    .values()
                    .filter(|spec| spec.enabled())
                    .filter_map(|spec| spec.command())
                    .find(|command| {
                        matches!(*command, "show running-config" | "show configuration")
                    })
                    .ok_or_else(|| anyhow::anyhow!("backup_command_not_configured"))?;
                let result = self
                    .cli
                    .exec(
                        &SshTarget {
                            ip: device.facts.ip.clone(),
                            port: credentials.port,
                            username: credentials.username.clone(),
                            auth: credentials.auth.clone(),
                            known_host_key: credentials.known_host_key.clone(),
                        },
                        command,
                        Duration::from_secs(backup_settings.timeout_secs.max(1)),
                    )
                    .await
                    .map_err(|_| anyhow::anyhow!("backup_connection_failed"))?;
                if result.output.len() as u64 > backup_settings.max_size_bytes {
                    anyhow::bail!("backup_too_large");
                }
                Ok(
                    json!({"configuration_encrypted": encrypt_secret(key, &result.output),
                    "bytes": result.output.len()}),
                )
            }
        }
    }

    async fn audit(
        &self,
        payload: &OperatorActionPayload,
        job_id: i64,
        status: &str,
        reason: Option<&str>,
    ) {
        let entry = JournalEntry {
            id: Uuid::new_v4(),
            ts: chrono::Utc::now(),
            username: payload.username.clone(),
            domain: "devices".to_string(),
            action: format!("Действие оператора: {:?}: {status}", payload.action),
            method: "WORKER".to_string(),
            path: "/api/devices/:id/actions/:action".to_string(),
            object: Some(payload.device_id.to_string()),
            details: Some(
                json!({"job_id": job_id, "action": payload.action, "status": status, "reason": reason}),
            ),
        };
        if let Err(error) = self.journal.append(&entry).await {
            tracing::warn!(job_id, %error, "operator action audit failed");
        }
    }
}

#[async_trait]
impl JobHandler for OperatorActionHandler {
    async fn handle(&self, job: Job) -> anyhow::Result<()> {
        let payload: OperatorActionPayload = serde_json::from_value(job.payload.clone())
            .map_err(|_| anyhow::anyhow!("invalid_action_payload"))?;
        let result = self.run(&job, &payload).await;
        match result {
            Ok(value) => {
                let reason = value
                    .get("reason")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .or_else(|| {
                        value
                            .get("failed_metrics")
                            .and_then(Value::as_array)
                            .filter(|items| !items.is_empty())
                            .map(|_| "metric_failures".to_string())
                    });
                if self.queue.set_result(job.id, value).await.is_err() {
                    self.audit(
                        &payload,
                        job.id,
                        "failed",
                        Some("action_result_store_failed"),
                    )
                    .await;
                    anyhow::bail!("action_result_store_failed");
                }
                self.audit(&payload, job.id, "done", reason.as_deref())
                    .await;
                Ok(())
            }
            Err(error) => {
                self.audit(&payload, job.id, "failed", Some(&error.to_string()))
                    .await;
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashmap::DashMap;
    use discovery_alerts::SeaOrmAlertStore;
    use discovery_config_store::{
        SeaOrmDiscoveryConfigStore, SeaOrmSettingsStore, SeaOrmTopologyRuleStore,
    };
    use discovery_core::DeviceFacts;
    use discovery_devices::{SeaOrmDeviceMetricsStore, SeaOrmDeviceStore};
    use discovery_journal::{JournalListQuery, SeaOrmJournalStore};
    use discovery_ping::FakePinger;
    use discovery_queue::SeaOrmJobQueueStore;
    use discovery_servicecheck::FakeServiceChecker;
    use discovery_snmp::FakeSnmpClient;
    use discovery_ssh::FakeCliClient;

    #[tokio::test]
    async fn test_action_runs_with_fake_device_and_persists_safe_result_and_audit() {
        let db = discovery_migration::connect_in_memory_for_tests().await;
        let metrics = Arc::new(SeaOrmDeviceMetricsStore::new(db.clone()));
        let alerts = Arc::new(SeaOrmAlertStore::new(db.clone()));
        let devices: Arc<dyn DeviceStore> =
            Arc::new(SeaOrmDeviceStore::new(db.clone(), metrics.clone(), alerts));
        let queue: Arc<dyn JobQueueStore> = Arc::new(SeaOrmJobQueueStore::new(db.clone()));
        let settings: Arc<dyn SettingsStore> = Arc::new(SeaOrmSettingsStore::new(db.clone()));
        let configs = Arc::new(SeaOrmDiscoveryConfigStore::new(db.clone()));
        let matcher = Arc::new(ProfileMatcher::new(vec![]));
        let snmp = Arc::new(FakeSnmpClient::new());
        let cli = Arc::new(FakeCliClient::new());
        let pinger = Arc::new(FakePinger::new());
        pinger.seed("192.0.2.81", true);
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "192.0.2.81".to_string(),
            })
            .await
            .unwrap();
        let snmp_poll = Arc::new(SnmpPollHandler {
            store: queue.clone(),
            snmp: snmp.clone(),
            devices: devices.clone(),
            discovery_configs: configs.clone(),
            settings: settings.clone(),
        });
        let metric_poll = Arc::new(MetricPollHandler {
            store: queue.clone(),
            snmp,
            cli: cli.clone(),
            devices: devices.clone(),
            device_metrics: metrics,
            matcher: matcher.clone(),
            settings: settings.clone(),
            last_polled: Arc::new(DashMap::new()),
            last_polled_date: Arc::new(DashMap::new()),
            discovery_configs: configs,
            pruned_generations: Arc::new(DashMap::new()),
            topology_rules: Arc::new(SeaOrmTopologyRuleStore::new(db.clone())),
        });
        let journal = Arc::new(SeaOrmJournalStore::new(db));
        let handler = OperatorActionHandler {
            queue: queue.clone(),
            devices,
            matcher,
            settings,
            pinger,
            checker: Arc::new(FakeServiceChecker::new()),
            cli,
            snmp_poll,
            metric_poll,
            journal: journal.clone(),
            secret_key: None,
        };
        let id = queue
            .enqueue(
                QueueKind::OperatorAction,
                json!(OperatorActionPayload {
                    alert_id: None,
                    device_id,
                    action: OperatorAction::Test,
                    username: "operator".to_string(),
                }),
                Some(&device_id.to_string()),
            )
            .await
            .unwrap();
        let job = queue
            .claim(QueueKind::OperatorAction, "worker", 1)
            .await
            .unwrap()
            .remove(0);
        handler.handle(job).await.unwrap();
        queue.complete(id).await.unwrap();
        let stored = queue.get_job(id).await.unwrap().unwrap();
        assert_eq!(stored.result.unwrap()["ping_ok"], true);
        let entries = journal.list(&JournalListQuery::default()).await.unwrap();
        assert_eq!(entries.total, 1);
        assert_eq!(entries.items[0].username, "operator");
        assert!(!serde_json::to_string(&entries.items)
            .unwrap()
            .contains("secret"));
    }
}
