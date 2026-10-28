//! End-to-end test for the full pipeline: discovery -> SNMP identification -> identity
//! resolution (per-IP for now, see `discovery_devices::DeviceStore::resolve`'s docs) ->
//! profile matching (DSL) -> parallel profile apply -> metric poll -> alert evaluation
//! (with anti-flap debounce). Uses an in-memory job queue and virtual SNMP devices
//! (`FakeSnmpClient`, no real sockets) — this is the "e2e тесты с использованием
//! inmemory db с поднятием виртуальных тестовых устройств" requirement.
//!
//! Not covered here: the Postgres-backed stores' real-database semantics (`FOR UPDATE
//! SKIP LOCKED`, the identity-resolve advisory lock, ...) — those are exercised separately
//! against a live Postgres, see `crates/devices/tests/postgres.rs` and
//! `discovery/CLAUDE.md`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use discovery_agent::demo;
use discovery_agent::handlers::{
    AlertEvalHandler, DedupHandler, DiscoveryHandler, MetricPollHandler, ProfileApplyHandler,
    SnmpPollHandler,
};
use discovery_alerts::{AlertListQuery, AlertSortBy, AlertStore};
use discovery_config_store::{
    DiscoveryConfig, DiscoveryConfigStore, DiscoveryOidSpec, Schedule, SeaOrmDiscoveryConfigStore,
    SeaOrmMaintenanceWindowStore, SeaOrmNotificationChannelStore, SeaOrmNotificationRuleStore,
    SubnetSpec,
};
use discovery_core::payload::DiscoveryPayload;
use discovery_core::ActiveChains;
use discovery_core::{
    AlertStateTracker, QueueKind, SnmpAuth, SnmpVersion, SortDir, WorkerRegistry,
};
use discovery_devices::{
    DeviceMetricsStore, DeviceStore, SeaOrmDeviceMetricsStore, SeaOrmDeviceStore,
};
use discovery_dsl::{
    AlertEvaluator, AlertRule, MatchSection, MetricSpec, MetricsSection, ProfileFile,
    ProfileMatcher, ProfileMeta,
};
use discovery_queue::{
    run_worker_pool, JobHandler, JobQueueStore, SeaOrmJobQueueStore, WorkerPoolConfig,
};

/// Shared by the trap and syslog push-ingestion e2e tests below — drains every pending
/// `AlertEval` job by hand, since `AlertEvalHandler::handle()` itself never
/// completes/fails the job (that's `run_worker_pool`'s job in production); doing it
/// explicitly here avoids a claimed-but-never-completed job staying `InProgress` forever
/// and permanently blocking a device's `dedupe_key` from ever enqueueing another one.
async fn drain_alert_evals(queue: &Arc<dyn JobQueueStore>, handler: &Arc<AlertEvalHandler>) {
    loop {
        let jobs = queue
            .claim(QueueKind::AlertEval, "test-worker", 10)
            .await
            .unwrap();
        if jobs.is_empty() {
            break;
        }
        for job in jobs {
            let job_id = job.id;
            handler.handle(job).await.unwrap();
            queue.complete(job_id).await.unwrap();
        }
    }
}

/// Shared by the trap and syslog push-ingestion e2e tests below.
async fn alert_for(
    alert_store: &Arc<dyn AlertStore>,
    device_id: uuid::Uuid,
    row_key: &str,
) -> discovery_core::Alert {
    let page = alert_store
        .list(&AlertListQuery {
            response_pending: false,
            screen_only: false,
            search: None,
            level: None,
            state: None,
            device_id: Some(device_id),
            since: None,
            until: None,
            sort_by: AlertSortBy::LastSeen,
            sort_dir: SortDir::Desc,
            limit: 100,
            offset: 0,
        })
        .await
        .unwrap();
    page.items
        .into_iter()
        .find(|a| a.row_key.as_deref() == Some(row_key))
        .unwrap_or_else(|| panic!("no alert found for row_key {row_key}"))
}

/// Built as literals, not loaded from `profiles/*.toml` — file-based profile loading was
/// removed 2026-08-16 (direct user request: no more file-based seeding anywhere in this
/// project). Mirrors the old `profiles/generic_switch.toml`/`generic_host.toml` content
/// exactly (see `demo::seed_demo_devices`'s docs for the OIDs these must match).
fn demo_profiles() -> Vec<ProfileFile> {
    vec![
        ProfileFile { traps: Default::default(), syslog: Default::default(), service_checks: Default::default(),
            profile: ProfileMeta { name: "generic_switch".into(), priority: 10 },
            match_expr: MatchSection {
                expression: r#"metrics.sys_descr.contains("Switch") || metrics.sys_object_id.starts_with("1.3.6.1.4.1.9.1")"#.into(),
            },
            metrics: MetricsSection {
                poll: BTreeMap::from([
                    ("cpu".to_string(), MetricSpec::Oid("1.3.6.1.4.1.9.9.109.1.1.1.1.3.1".to_string())),
                    ("uptime".to_string(), MetricSpec::Oid("1.3.6.1.2.1.1.3.0".to_string())),
                    ("serial_number".to_string(), MetricSpec::Oid("1.3.6.1.2.1.47.1.1.1.1.11.1".to_string())),
                    ("mac_address".to_string(), MetricSpec::Oid("1.3.6.1.2.1.2.2.1.6.1".to_string())),
                ]),
            },
            alerts: vec![AlertRule {
                policy: Default::default(),
                name: "high_cpu".into(),
                level: "warning".into(),
                row_metric: None,
                row_key_expression: None,
                expression: "metrics.cpu > 85".into(),
                deactivation_expression: None,
                facts_expression: None,
                message: "CPU load {metrics.cpu}% выше порога 85%".into(),
                clear_after_seconds: Some(60),
                activate_after_seconds: None,
                flap_window_seconds: None,
                flap_threshold: None,
                enabled: true,
            }],
            version: "test".into(),
        },
        ProfileFile { traps: Default::default(), syslog: Default::default(), service_checks: Default::default(),
            profile: ProfileMeta { name: "generic_host".into(), priority: 0 },
            match_expr: MatchSection { expression: "true".into() },
            metrics: MetricsSection {
                poll: BTreeMap::from([
                    ("uptime".to_string(), MetricSpec::Oid("1.3.6.1.2.1.1.3.0".to_string())),
                    ("serial_number".to_string(), MetricSpec::Oid("1.3.6.1.2.1.47.1.1.1.1.11.1".to_string())),
                    ("mac_address".to_string(), MetricSpec::Oid("1.3.6.1.2.1.2.2.1.6.1".to_string())),
                ]),
            },
            alerts: vec![AlertRule {
                policy: Default::default(),
                name: "device_unreachable".into(),
                level: "critical".into(),
                row_metric: None,
                row_key_expression: None,
                expression: "metrics.uptime == 0".into(),
                deactivation_expression: None,
                facts_expression: None,
                message: "Устройство недоступно (uptime = 0)".into(),
                clear_after_seconds: Some(60),
                activate_after_seconds: None,
                flap_window_seconds: None,
                flap_threshold: None,
                enabled: true,
            }],
            version: "test".into(),
        },
    ]
}

#[tokio::test]
async fn full_pipeline_matches_profiles_and_raises_expected_alerts() {
    let matcher = Arc::new(ProfileMatcher::new(demo_profiles()));
    let alert_engine = Arc::new(AlertEvaluator::new());

    let store: Arc<dyn JobQueueStore> =
        Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
    let registry = Arc::new(WorkerRegistry::new());
    let alerts = Arc::new(AlertStateTracker::new());
    // devices/device_metrics/alert_store share one connection — the 2026-08-18 domain
    // split means `DeviceStore::delete` etc. need a real `DeviceMetricsStore`/`AlertStore`
    // to cascade into (see `discovery_devices::SeaOrmDeviceStore`'s docs); sharing one
    // connection here mirrors production's common case (every domain routed to the
    // default database) and lets `alert_store` below observe the same data either way.
    let e2e_db = discovery_migration::connect_in_memory_for_tests().await;
    let device_metrics: Arc<dyn DeviceMetricsStore> =
        Arc::new(SeaOrmDeviceMetricsStore::new(e2e_db.clone()));
    let alert_store: Arc<dyn discovery_alerts::AlertStore> =
        Arc::new(discovery_alerts::SeaOrmAlertStore::new(e2e_db.clone()));
    let devices: Arc<dyn DeviceStore> = Arc::new(SeaOrmDeviceStore::new(
        e2e_db,
        device_metrics.clone(),
        alert_store.clone(),
    ));
    let snmp: Arc<dyn discovery_snmp::SnmpClient> = Arc::new(demo::seed_demo_devices());
    // A subnet covering the demo IPs, declaring the standard identity OIDs in `oids` —
    // needed since 2026-08-16: `SnmpPollHandler` no longer fetches sys_descr/sys_object_id/
    // sys_name unconditionally (direct user request, see `discovery_core::DeviceFacts`'s
    // docs), so without this the demo devices would carry no identity data at all and every
    // one would fall through to `generic_host`. `demo::seed_demo_devices()`'s
    // `seed_identity` already seeds `FakeSnmpClient` under these exact OIDs.
    let discovery_config_store = SeaOrmDiscoveryConfigStore::new_in_memory_for_tests().await;
    discovery_config_store
        .upsert(&DiscoveryConfig {
            name: "e2e-demo".into(),
            enabled: true,
            schedule: Schedule::Calendar {
                months: vec![],
                days_of_month: vec![],
                time: chrono::NaiveTime::from_hms_opt(3, 0, 0).unwrap(),
            },
            subnets: vec![SubnetSpec {
                ip: "10.0.0.0".into(),
                mask: "255.255.255.0".into(),
                port: 161,
                credentials: vec![SnmpAuth::Community {
                    version: SnmpVersion::V2c,
                    community: "public".into(),
                }],
                oids: [
                    (
                        "sys_object_id".to_string(),
                        DiscoveryOidSpec::Oid("1.3.6.1.2.1.1.2.0".to_string()),
                    ),
                    (
                        "sys_descr".to_string(),
                        DiscoveryOidSpec::Oid("1.3.6.1.2.1.1.1.0".to_string()),
                    ),
                    (
                        "sys_name".to_string(),
                        DiscoveryOidSpec::Oid("1.3.6.1.2.1.1.5.0".to_string()),
                    ),
                ]
                .into_iter()
                .collect(),
                labels: Default::default(),
                snmp_timeout_ms: None,
                snmp_retries: None,
                create_dead_devices: true,
            }],
        })
        .await
        .unwrap();
    let discovery_configs: Arc<dyn DiscoveryConfigStore> = Arc::new(discovery_config_store);

    // High concurrency, fast polling — this is a test, not a real deployment, so we just
    // want the pipeline to settle quickly.
    let concurrency = 4usize;
    let poll_interval = Duration::from_millis(20);

    // Long identity/metric intervals — not the fast `poll_interval` above (that's the
    // worker *pool's* claim-loop cadence, unrelated) — long enough that the recurring
    // identity re-check / metric poll chain don't fire again mid-test and confuse the
    // assertions below.
    let settings: Arc<dyn discovery_config_store::SettingsStore> =
        Arc::new(discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests().await);
    settings
        .set_poll_intervals(&discovery_core::PollIntervalsConfig {
            identity_secs: 3600,
            metric_secs: 3600,
            ..Default::default()
        })
        .await
        .unwrap();

    tokio::spawn(run_worker_pool(
        store.clone(),
        registry.clone(),
        WorkerPoolConfig {
            queue: QueueKind::Discovery,
            concurrency,
            poll_interval,
        },
        Arc::new(DiscoveryHandler {
            store: store.clone(),
            identity_chains: Arc::new(ActiveChains::new()),
            discovery_configs: discovery_configs.clone(),
            // Never actually called — every subnet fixture in this file sets
            // `create_dead_devices: true`, which bypasses the ping gate entirely.
            pinger: Arc::new(discovery_ping::FakePinger::new()),
            settings: settings.clone(),
        }),
    ));
    tokio::spawn(run_worker_pool(
        store.clone(),
        registry.clone(),
        WorkerPoolConfig {
            queue: QueueKind::SnmpPoll,
            concurrency,
            poll_interval,
        },
        Arc::new(SnmpPollHandler {
            store: store.clone(),
            snmp: snmp.clone(),
            devices: devices.clone(),
            discovery_configs: discovery_configs.clone(),
            settings: settings.clone(),
        }),
    ));
    tokio::spawn(run_worker_pool(
        store.clone(),
        registry.clone(),
        WorkerPoolConfig {
            queue: QueueKind::Dedup,
            concurrency,
            poll_interval,
        },
        Arc::new(DedupHandler {
            store: store.clone(),
            devices: devices.clone(),
            device_metrics: device_metrics.clone(),
            matcher: matcher.clone(),
            reachability_chains: Arc::new(ActiveChains::new()),
        }),
    ));
    // Shared with MetricPollHandler below — ProfileApplyHandler clears entries here on a
    // real profile change, so both handlers must see the same map.
    let metric_last_polled = Arc::new(dashmap::DashMap::new());
    let metric_last_polled_date = Arc::new(dashmap::DashMap::new());
    tokio::spawn(run_worker_pool(
        store.clone(),
        registry.clone(),
        WorkerPoolConfig {
            queue: QueueKind::ProfileApply,
            concurrency,
            poll_interval,
        },
        Arc::new(ProfileApplyHandler {
            store: store.clone(),
            devices: devices.clone(),
            active_chains: Arc::new(ActiveChains::new()),
            last_polled: metric_last_polled.clone(),
            last_polled_date: metric_last_polled_date.clone(),
            service_check_last_polled: Arc::new(dashmap::DashMap::new()),
            service_check_last_polled_date: Arc::new(dashmap::DashMap::new()),
        }),
    ));
    tokio::spawn(run_worker_pool(
        store.clone(),
        registry.clone(),
        WorkerPoolConfig {
            queue: QueueKind::MetricPoll,
            concurrency,
            poll_interval,
        },
        Arc::new(MetricPollHandler {
            store: store.clone(),
            snmp: snmp.clone(),
            cli: Arc::new(discovery_ssh::FakeCliClient::new()),
            devices: devices.clone(),
            device_metrics: device_metrics.clone(),
            matcher: matcher.clone(),
            settings: settings.clone(),
            last_polled: metric_last_polled.clone(),
            last_polled_date: metric_last_polled_date.clone(),
            discovery_configs: discovery_configs.clone(),
            pruned_generations: Arc::new(dashmap::DashMap::new()),
            topology_rules: Arc::new(
                discovery_config_store::SeaOrmTopologyRuleStore::new_in_memory_for_tests().await,
            ),
        }),
    ));
    tokio::spawn(run_worker_pool(
        store.clone(),
        registry.clone(),
        WorkerPoolConfig {
            queue: QueueKind::AlertEval,
            concurrency,
            poll_interval,
        },
        Arc::new(AlertEvalHandler {
            evaluation_locks: Default::default(),
            alert_engine: alert_engine.clone(),
            alerts: alerts.clone(),
            alert_store: alert_store.clone(),
            devices: devices.clone(),
            device_metrics: device_metrics.clone(),
            matcher: matcher.clone(),
            maintenance_windows: Arc::new(
                SeaOrmMaintenanceWindowStore::new_in_memory_for_tests().await,
            ),
            notification_rules: Arc::new(
                SeaOrmNotificationRuleStore::new_in_memory_for_tests().await,
            ),
            notification_channels: Arc::new(
                SeaOrmNotificationChannelStore::new_in_memory_for_tests().await,
            ),
            auth: Arc::new(discovery_auth::SeaOrmAuthStore::new(
                discovery_migration::connect_in_memory_for_tests().await,
            )),
            queue: store.clone(),
            still_active_last_persisted: Arc::new(dashmap::DashMap::new()),
            correlator: Arc::new(discovery_agent::group_alert::GroupAlertCorrelator::new()),
        }),
    ));

    for ip in demo::demo_device_ips() {
        store
            .enqueue(
                QueueKind::Discovery,
                serde_json::to_value(DiscoveryPayload { ip: ip.clone() }).unwrap(),
                Some(&ip),
            )
            .await
            .unwrap();
    }

    // Let the pipeline settle: discovery -> snmp -> dedup -> profile -> apply -> metrics -> alerts.
    // Wait for both expected alerts specifically, not just "some alert exists" — with more
    // queues/worker pools now in the pipeline (service checks, SSH), device 11's high_cpu
    // alert can land well before device 13's device_unreachable one, and breaking early on
    // just the former made this test flaky.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if devices.id_by_ip("10.0.0.13").await.unwrap().is_some() {
            let active = alerts.active_alerts();
            let has_high_cpu = active
                .iter()
                .any(|a| a.device_ip == "10.0.0.11" && a.name == "high_cpu");
            let has_unreachable = active
                .iter()
                .any(|a| a.device_ip == "10.0.0.13" && a.name == "device_unreachable");
            if has_high_cpu && has_unreachable {
                break;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Three distinct IPs must resolve to three distinct devices.
    assert_eq!(
        devices.all().await.unwrap().len(),
        3,
        "the three demo devices must remain distinct"
    );

    let device_11 = devices
        .id_by_ip("10.0.0.11")
        .await
        .unwrap()
        .expect("device 10.0.0.11 should have been discovered");
    let (device11, _) =
        discovery_devices::get(devices.as_ref(), device_metrics.as_ref(), device_11)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        device11.profile.as_deref(),
        Some("generic_switch"),
        "overloaded switch should match the switch profile"
    );

    let device_13 = devices
        .id_by_ip("10.0.0.13")
        .await
        .unwrap()
        .expect("device 10.0.0.13 should have been discovered");
    let (device13, _) =
        discovery_devices::get(devices.as_ref(), device_metrics.as_ref(), device_13)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        device13.profile.as_deref(),
        Some("generic_host"),
        "non-switch device should fall through to the catch-all profile"
    );

    let active = alerts.active_alerts();
    let names: Vec<(&str, &str)> = active
        .iter()
        .map(|a| (a.device_ip.as_str(), a.name.as_str()))
        .collect();

    assert!(
        names.contains(&("10.0.0.11", "high_cpu")),
        "expected high_cpu alert on the overloaded switch, active alerts: {:?}",
        names
    );
    assert!(
        !names.contains(&("10.0.0.12", "high_cpu")),
        "healthy switch (cpu=14) should not have an alert, active alerts: {:?}",
        names
    );
    assert!(
        names.contains(&("10.0.0.13", "device_unreachable")),
        "expected device_unreachable alert on the unreachable host, active alerts: {:?}",
        names
    );
}

/// End-to-end for SNMP Trap ingestion (2026-08-30): a trap -> `trap_ingest::ingest_one` ->
/// `metrics.trap_port_link_state` row -> `AlertEval` -> a real `Alert` — exercising the
/// property the whole design discussion centered on: a *confirmed* close (a real `linkUp`
/// trap arrives) must clear the alert normally, while a *ttl-timeout* close (no closer ever
/// arrives) must clear it tagged `RowMissing`/"Утеряна" — same distinction the codebase
/// already draws for an ordinary polled table's row disappearing, just reached by a
/// different path for trap-derived data (see `discovery-agent::trap_ingest::sweep_ttl_once`'s
/// docs for why nothing but the ttl-sweep can ever produce that tag here).
///
/// Deliberately doesn't touch a real UDP socket — `discovery-snmp::trap`'s own tests
/// already prove real wire decode end-to-end; this test's job is the *agent-side* pipeline
/// from an already-decoded `DecodedTrap` through to a persisted `Alert`.
#[tokio::test]
async fn trap_ingestion_confirmed_close_clears_normally_ttl_timeout_clears_as_row_missing() {
    use discovery_alerts::SeaOrmAlertStore;
    use discovery_core::{AutoClearReason, SnmpCredentials};
    use discovery_dsl::{TrapEventSpec, TrapSpec, TrapsSection};
    use discovery_queue::SeaOrmJobQueueStore;
    use discovery_snmp::{DecodedTrap, TrapAuth};
    use std::net::{IpAddr, SocketAddr};

    let db = discovery_migration::connect_in_memory_for_tests().await;
    let device_metrics: Arc<dyn DeviceMetricsStore> =
        Arc::new(SeaOrmDeviceMetricsStore::new(db.clone()));
    let alert_store: Arc<dyn AlertStore> = Arc::new(SeaOrmAlertStore::new(db.clone()));
    let devices: Arc<dyn DeviceStore> = Arc::new(SeaOrmDeviceStore::new(
        db,
        device_metrics.clone(),
        alert_store.clone(),
    ));
    let queue: Arc<dyn JobQueueStore> =
        Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);

    let if_index_oid = "1.3.6.1.2.1.2.2.1.1";
    let if_oper_status_oid = "1.3.6.1.2.1.2.2.1.8";
    let mut varbinds_spec = BTreeMap::new();
    varbinds_spec.insert("if_index".to_string(), if_index_oid.to_string());
    varbinds_spec.insert("if_oper_status".to_string(), if_oper_status_oid.to_string());

    let mut traps = TrapsSection::default();
    traps.bindings.insert(
        "port_link_state".to_string(),
        TrapSpec {
            variants: vec![
                TrapEventSpec {
                    trap_oid: "1.3.6.1.6.3.1.1.5.3".to_string(),
                    varbinds: varbinds_spec.clone(),
                    key_expression: Some("varbinds.if_index".to_string()),
                },
                TrapEventSpec {
                    trap_oid: "1.3.6.1.6.3.1.1.5.4".to_string(),
                    varbinds: varbinds_spec,
                    key_expression: Some("varbinds.if_index".to_string()),
                },
            ],
            ttl_secs: Some(0), // deliberately immediate — see the ttl-timeout half of this test
            history_retention_secs: None,
        },
    );
    let profile = ProfileFile {
        profile: ProfileMeta {
            name: "trap_switch".into(),
            priority: 0,
        },
        match_expr: MatchSection {
            expression: "true".into(),
        },
        metrics: MetricsSection::default(),
        traps,
        syslog: Default::default(),
        service_checks: Default::default(),
        alerts: vec![AlertRule {
            policy: Default::default(),
            name: "port_link_down_trap".into(),
            level: "warning".into(),
            row_metric: Some("trap_port_link_state".into()),
            row_key_expression: None,
            expression: "row.if_oper_status == 2".into(),
            deactivation_expression: None,
            facts_expression: None,
            message: "Порт ifIndex={row.if_index} down (trap)".into(),
            clear_after_seconds: Some(0),
            activate_after_seconds: None,
            flap_window_seconds: None,
            flap_threshold: None,
            enabled: true,
        }],
        version: "test".into(),
    };
    let matcher = Arc::new(ProfileMatcher::new(vec![profile]));
    let alert_engine = Arc::new(AlertEvaluator::new());

    let (device_id, _) = devices
        .resolve(discovery_core::DeviceFacts {
            ip: "10.9.9.9".into(),
        })
        .await
        .unwrap();
    devices
        .set_snmp_credentials(
            device_id,
            SnmpCredentials {
                auth: SnmpAuth::Community {
                    version: SnmpVersion::V2c,
                    community: "public".into(),
                },
                port: 161,
            },
        )
        .await
        .unwrap();
    devices
        .apply_profile_if_changed(device_id, "trap_switch", "v1")
        .await
        .unwrap();

    let ingest_state = Arc::new(discovery_agent::trap_ingest::TrapIngestState::new(
        devices.clone(),
        device_metrics.clone(),
        matcher.clone(),
        alert_engine.clone(),
        queue.clone(),
        100,
    ));

    let alert_eval = Arc::new(AlertEvalHandler {
        evaluation_locks: Default::default(),
        alert_engine: alert_engine.clone(),
        alerts: Arc::new(AlertStateTracker::new()),
        alert_store: alert_store.clone(),
        devices: devices.clone(),
        device_metrics: device_metrics.clone(),
        matcher: matcher.clone(),
        maintenance_windows: Arc::new(
            SeaOrmMaintenanceWindowStore::new_in_memory_for_tests().await,
        ),
        notification_rules: Arc::new(SeaOrmNotificationRuleStore::new_in_memory_for_tests().await),
        notification_channels: Arc::new(
            SeaOrmNotificationChannelStore::new_in_memory_for_tests().await,
        ),
        auth: Arc::new(discovery_auth::SeaOrmAuthStore::new(
            discovery_migration::connect_in_memory_for_tests().await,
        )),
        queue: queue.clone(),
        still_active_last_persisted: Arc::new(dashmap::DashMap::new()),
        correlator: Arc::new(discovery_agent::group_alert::GroupAlertCorrelator::new()),
    });

    fn trap(source_ip: &str, trap_oid: &str, if_index: i64, if_oper_status: i64) -> DecodedTrap {
        let mut varbinds = BTreeMap::new();
        varbinds.insert(
            "1.3.6.1.2.1.2.2.1.1".to_string(),
            discovery_core::MetricValue::Int(if_index),
        );
        varbinds.insert(
            "1.3.6.1.2.1.2.2.1.8".to_string(),
            discovery_core::MetricValue::Int(if_oper_status),
        );
        DecodedTrap {
            source: SocketAddr::new(source_ip.parse::<IpAddr>().unwrap(), 1162),
            trap_oid: trap_oid.to_string(),
            uptime_centis: 0,
            varbinds,
            auth: TrapAuth::Community("public".to_string()),
        }
    }

    // --- Confirmed close: linkDown then a real linkUp for the same port ---
    discovery_agent::trap_ingest::ingest_one(
        &ingest_state,
        trap("10.9.9.9", "1.3.6.1.6.3.1.1.5.3", 3, 2),
    )
    .await
    .unwrap();
    drain_alert_evals(&queue, &alert_eval).await;
    let opened = alert_for(&alert_store, device_id, "3").await;
    assert_eq!(opened.state, discovery_core::AlertState::Active);
    assert_eq!(opened.level, discovery_core::AlertLevel::Warning);
    assert!(
        opened.message.contains("ifIndex=3"),
        "message: {}",
        opened.message
    );

    discovery_agent::trap_ingest::ingest_one(
        &ingest_state,
        trap("10.9.9.9", "1.3.6.1.6.3.1.1.5.4", 3, 1),
    )
    .await
    .unwrap();
    drain_alert_evals(&queue, &alert_eval).await;
    let closed = alert_for(&alert_store, device_id, "3").await;
    assert_eq!(
        closed.state,
        discovery_core::AlertState::Cleared,
        "a real linkUp trap must clear the alert"
    );
    assert_eq!(closed.auto_clear_reason, None, "a confirmed close must NOT be tagged RowMissing/\"Утеряна\" — we positively know it recovered");

    // --- ttl-timeout close: linkDown on a different port, no linkUp ever sent ---
    discovery_agent::trap_ingest::ingest_one(
        &ingest_state,
        trap("10.9.9.9", "1.3.6.1.6.3.1.1.5.3", 5, 2),
    )
    .await
    .unwrap();
    drain_alert_evals(&queue, &alert_eval).await;
    let opened5 = alert_for(&alert_store, device_id, "5").await;
    assert_eq!(opened5.state, discovery_core::AlertState::Active);

    // ttl_secs = 0 — any elapsed time makes the row stale; sleep past the second boundary
    // so `is_stale`'s second-granularity comparison is unambiguous, not a race.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    discovery_agent::trap_ingest::sweep_ttl_once(&ingest_state)
        .await
        .unwrap();
    drain_alert_evals(&queue, &alert_eval).await;
    let timed_out = alert_for(&alert_store, device_id, "5").await;
    assert_eq!(
        timed_out.state,
        discovery_core::AlertState::Cleared,
        "ttl-sweep must have evicted the row and thereby cleared the alert"
    );
    assert_eq!(timed_out.auto_clear_reason, Some(AutoClearReason::RowMissing), "a ttl-timeout close (no closer ever arrived) must be tagged RowMissing/\"Утеряна\" — we never confirmed recovery, we just gave up waiting");
}

/// End-to-end for Syslog ingestion (2026-09-06): a message -> `syslog_ingest::ingest_one`
/// -> `metrics.syslog_iface_down` row -> `AlertEval` -> a real `Alert` — the direct sibling
/// of `trap_ingestion_confirmed_close_clears_normally_ttl_timeout_clears_as_row_missing`
/// above, proving the same confirmed-close-vs-ttl-timeout distinction holds for
/// regex-derived data exactly as it does for varbind-derived data, via the identical
/// `AlertStateTracker`/`AutoClearReason` mechanics (see `syslog_ingest::sweep_ttl_once`'s
/// docs for why nothing but the ttl-sweep can ever produce `RowMissing` here).
///
/// Deliberately doesn't touch a real UDP socket — `syslog_decode`'s own tests already
/// prove real wire decode end-to-end; this test's job is the *agent-side* pipeline from an
/// already-decoded `DecodedSyslogMessage` through to a persisted `Alert`. No SNMP
/// credentials are configured on the device — syslog has no auth step at all, see
/// `syslog_ingest`'s module docs.
#[tokio::test]
async fn syslog_ingestion_confirmed_close_clears_normally_ttl_timeout_clears_as_row_missing() {
    use discovery_alerts::SeaOrmAlertStore;
    use discovery_core::AutoClearReason;
    use discovery_dsl::{SyslogEventSpec, SyslogSection, SyslogSpec};
    use discovery_queue::SeaOrmJobQueueStore;
    use std::net::{IpAddr, SocketAddr};

    let db = discovery_migration::connect_in_memory_for_tests().await;
    let device_metrics: Arc<dyn DeviceMetricsStore> =
        Arc::new(SeaOrmDeviceMetricsStore::new(db.clone()));
    let alert_store: Arc<dyn AlertStore> = Arc::new(SeaOrmAlertStore::new(db.clone()));
    let devices: Arc<dyn DeviceStore> = Arc::new(SeaOrmDeviceStore::new(
        db,
        device_metrics.clone(),
        alert_store.clone(),
    ));
    let queue: Arc<dyn JobQueueStore> =
        Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);

    let mut syslog = SyslogSection::default();
    syslog.bindings.insert(
        "iface_down".to_string(),
        SyslogSpec {
            variants: vec![
                SyslogEventSpec {
                    pattern: r"ifIndex=(?P<ifIndex>\d+) link (?P<state>down)".to_string(),
                    max_severity: None,
                    facility: None,
                    key_expression: Some("fields.ifIndex".to_string()),
                },
                SyslogEventSpec {
                    pattern: r"ifIndex=(?P<ifIndex>\d+) link (?P<state>up)".to_string(),
                    max_severity: None,
                    facility: None,
                    key_expression: Some("fields.ifIndex".to_string()),
                },
            ],
            ttl_secs: Some(0), // deliberately immediate — see the ttl-timeout half of this test
            history_retention_secs: None,
        },
    );
    let profile = ProfileFile {
        profile: ProfileMeta {
            name: "syslog_switch".into(),
            priority: 0,
        },
        match_expr: MatchSection {
            expression: "true".into(),
        },
        metrics: MetricsSection::default(),
        traps: Default::default(),
        syslog,
        service_checks: Default::default(),
        alerts: vec![AlertRule {
            policy: Default::default(),
            name: "port_link_down_syslog".into(),
            level: "warning".into(),
            row_metric: Some("syslog_iface_down".into()),
            row_key_expression: None,
            expression: r#"row.state == "down""#.into(),
            deactivation_expression: Some(r#"row.state == "up""#.into()),
            facts_expression: None,
            message: "Порт ifIndex={row.ifIndex} down (syslog)".into(),
            clear_after_seconds: Some(0),
            activate_after_seconds: None,
            flap_window_seconds: None,
            flap_threshold: None,
            enabled: true,
        }],
        version: "test".into(),
    };
    let matcher = Arc::new(ProfileMatcher::new(vec![profile]));
    let alert_engine = Arc::new(AlertEvaluator::new());

    // No `set_snmp_credentials` call — syslog has no auth step, unlike the trap test above.
    let (device_id, _) = devices
        .resolve(discovery_core::DeviceFacts {
            ip: "10.9.9.10".into(),
        })
        .await
        .unwrap();
    devices
        .apply_profile_if_changed(device_id, "syslog_switch", "v1")
        .await
        .unwrap();

    let ingest_state = Arc::new(discovery_agent::syslog_ingest::SyslogIngestState::new(
        devices.clone(),
        device_metrics.clone(),
        matcher.clone(),
        alert_engine.clone(),
        queue.clone(),
        100,
    ));

    let alert_eval = Arc::new(AlertEvalHandler {
        evaluation_locks: Default::default(),
        alert_engine: alert_engine.clone(),
        alerts: Arc::new(AlertStateTracker::new()),
        alert_store: alert_store.clone(),
        devices: devices.clone(),
        device_metrics: device_metrics.clone(),
        matcher: matcher.clone(),
        maintenance_windows: Arc::new(
            SeaOrmMaintenanceWindowStore::new_in_memory_for_tests().await,
        ),
        notification_rules: Arc::new(SeaOrmNotificationRuleStore::new_in_memory_for_tests().await),
        notification_channels: Arc::new(
            SeaOrmNotificationChannelStore::new_in_memory_for_tests().await,
        ),
        auth: Arc::new(discovery_auth::SeaOrmAuthStore::new(
            discovery_migration::connect_in_memory_for_tests().await,
        )),
        queue: queue.clone(),
        still_active_last_persisted: Arc::new(dashmap::DashMap::new()),
        correlator: Arc::new(discovery_agent::group_alert::GroupAlertCorrelator::new()),
    });

    fn syslog_message(
        source_ip: &str,
        if_index: i64,
        state: &str,
    ) -> discovery_agent::syslog_decode::DecodedSyslogMessage {
        discovery_agent::syslog_decode::DecodedSyslogMessage {
            source: SocketAddr::new(source_ip.parse::<IpAddr>().unwrap(), 514),
            severity: 4,
            facility: 23,
            hostname: "sw-vrn-01".to_string(),
            message: format!("ifIndex={if_index} link {state}"),
        }
    }

    // --- Confirmed close: "link down" then a real "link up" for the same port ---
    discovery_agent::syslog_ingest::ingest_one(
        &ingest_state,
        syslog_message("10.9.9.10", 3, "down"),
    )
    .await
    .unwrap();
    drain_alert_evals(&queue, &alert_eval).await;
    let opened = alert_for(&alert_store, device_id, "3").await;
    assert_eq!(opened.state, discovery_core::AlertState::Active);
    assert_eq!(opened.level, discovery_core::AlertLevel::Warning);
    assert!(
        opened.message.contains("ifIndex=3"),
        "message: {}",
        opened.message
    );

    discovery_agent::syslog_ingest::ingest_one(&ingest_state, syslog_message("10.9.9.10", 3, "up"))
        .await
        .unwrap();
    drain_alert_evals(&queue, &alert_eval).await;
    let closed = alert_for(&alert_store, device_id, "3").await;
    assert_eq!(
        closed.state,
        discovery_core::AlertState::Cleared,
        "a real 'link up' message must clear the alert"
    );
    assert_eq!(closed.auto_clear_reason, None, "a confirmed close must NOT be tagged RowMissing/\"Утеряна\" — we positively know it recovered");

    // --- ttl-timeout close: "link down" on a different port, no "link up" ever sent ---
    discovery_agent::syslog_ingest::ingest_one(
        &ingest_state,
        syslog_message("10.9.9.10", 5, "down"),
    )
    .await
    .unwrap();
    drain_alert_evals(&queue, &alert_eval).await;
    let opened5 = alert_for(&alert_store, device_id, "5").await;
    assert_eq!(opened5.state, discovery_core::AlertState::Active);

    // ttl_secs = 0 — any elapsed time makes the row stale; sleep past the second boundary
    // so `is_stale`'s second-granularity comparison is unambiguous, not a race.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    discovery_agent::syslog_ingest::sweep_ttl_once(&ingest_state)
        .await
        .unwrap();
    drain_alert_evals(&queue, &alert_eval).await;
    let timed_out = alert_for(&alert_store, device_id, "5").await;
    assert_eq!(
        timed_out.state,
        discovery_core::AlertState::Cleared,
        "ttl-sweep must have evicted the row and thereby cleared the alert"
    );
    assert_eq!(timed_out.auto_clear_reason, Some(AutoClearReason::RowMissing), "a ttl-timeout close (no closer ever arrived) must be tagged RowMissing/\"Утеряна\" — we never confirmed recovery, we just gave up waiting");
}

/// End-to-end for L4/L7 service checks (2026-09-07): a real `discovery_servicecheck::
/// RealServiceChecker` — not `FakeServiceChecker`, this is deliberately the un-mocked path —
/// probes a genuine local TCP listener, a genuine tiny HTTP server, and a genuine closed
/// port, all three declared on one profile's `service_checks.checks`, through
/// `ServiceCheckPollHandler::handle()` exactly as `run_worker_pool` would call it in
/// production. Proves the whole chain end to end: real socket I/O -> `metrics.
/// service_checks` (one row per check, correct `ok`/fields) -> `AlertEval` -> a real,
/// persisted `Alert` for the one failing check and *no* alert for the two healthy ones —
/// the row-scoped `AlertRule` mechanism (`row_metric = "service_checks"`) needed zero new
/// alert-engine code to support this, per this feature's design.
#[tokio::test]
async fn service_checks_poll_against_real_tcp_and_http_listeners_and_raises_a_row_scoped_alert() {
    use discovery_agent::handlers::ServiceCheckPollHandler;
    use discovery_alerts::SeaOrmAlertStore;
    use discovery_core::payload::ServiceCheckPollPayload;
    use discovery_devices::{ProfileDecision, SeaOrmDeviceMetricsStore};
    use discovery_dsl::{ServiceCheckProtocol, ServiceCheckSpec, ServiceChecksSection};
    use discovery_queue::SeaOrmJobQueueStore;
    use discovery_servicecheck::{RealServiceChecker, ServiceChecker};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // A real TCP listener that just accepts and holds the connection open — enough for a
    // plain `tcp` check.
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_port = tcp_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((_socket, _)) = tcp_listener.accept().await else {
                break;
            };
        }
    });

    // A real, tiny HTTP/1.1 server — enough to drive the `http` protocol's status+body
    // check end to end without a whole test-server dependency.
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = http_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = http_listener.accept().await else {
                break;
            };
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let body = "healthy";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.shutdown().await;
        }
    });

    // A genuinely closed port — bind then drop, guaranteeing nothing answers there.
    let closed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_port = closed_listener.local_addr().unwrap().port();
    drop(closed_listener);

    let db = discovery_migration::connect_in_memory_for_tests().await;
    let device_metrics: Arc<dyn DeviceMetricsStore> =
        Arc::new(SeaOrmDeviceMetricsStore::new(db.clone()));
    let alert_store: Arc<dyn AlertStore> = Arc::new(SeaOrmAlertStore::new(db.clone()));
    let devices: Arc<dyn DeviceStore> = Arc::new(SeaOrmDeviceStore::new(
        db,
        device_metrics.clone(),
        alert_store.clone(),
    ));
    let store: Arc<dyn JobQueueStore> =
        Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);

    let checks = vec![
        ServiceCheckSpec {
            name: "tcp_ok".into(),
            protocol: ServiceCheckProtocol::Tcp,
            target: None,
            port: tcp_port,
            path: None,
            expected_status: None,
            body_contains: None,
            timeout_ms: Some(500),
            enabled: true,
        },
        ServiceCheckSpec {
            name: "http_ok".into(),
            protocol: ServiceCheckProtocol::Http,
            target: None,
            port: http_port,
            path: Some("/healthz".into()),
            expected_status: Some(200),
            body_contains: Some("healthy".into()),
            timeout_ms: Some(500),
            enabled: true,
        },
        ServiceCheckSpec {
            name: "tcp_fail".into(),
            protocol: ServiceCheckProtocol::Tcp,
            target: None,
            port: closed_port,
            path: None,
            expected_status: None,
            body_contains: None,
            timeout_ms: Some(300),
            enabled: true,
        },
    ];
    let profile = ProfileFile {
        profile: ProfileMeta {
            name: "svc_e2e".into(),
            priority: 0,
        },
        match_expr: MatchSection {
            expression: "true".into(),
        },
        metrics: MetricsSection::default(),
        traps: Default::default(),
        syslog: Default::default(),
        service_checks: ServiceChecksSection {
            checks,
            schedule: None,
            history_retention_secs: None,
        },
        alerts: vec![AlertRule {
            policy: Default::default(),
            name: "service_check_failed".into(),
            level: "warning".into(),
            row_metric: Some("service_checks".into()),
            row_key_expression: None,
            expression: "row.ok == false".into(),
            deactivation_expression: Some("row.ok == true".into()),
            facts_expression: None,
            message: "Сервис-чек {row.name} недоступен: {row.error}".into(),
            clear_after_seconds: Some(0),
            activate_after_seconds: None,
            flap_window_seconds: None,
            flap_threshold: None,
            enabled: true,
        }],
        version: "test".into(),
    };
    // One matcher, shared by both handlers below — `ServiceCheckPollHandler` (to know what
    // to poll) and `AlertEvalHandler` (to know what to evaluate) must agree on the exact
    // same profile, same as production wiring (`discovery-agent::main` builds one
    // `ProfileMatcher` and hands the same `Arc` to every handler).
    let matcher = Arc::new(ProfileMatcher::new(vec![profile]));
    let alert_engine = Arc::new(AlertEvaluator::new());

    let (device_id, _) = devices
        .resolve(discovery_core::DeviceFacts {
            ip: "127.0.0.1".into(),
        })
        .await
        .unwrap();
    let generation = match devices
        .apply_profile_if_changed(device_id, "svc_e2e", "v1")
        .await
        .unwrap()
        .unwrap()
    {
        ProfileDecision::Changed { generation } => generation,
        ProfileDecision::Unchanged { generation } => generation,
    };

    let checker: Arc<dyn ServiceChecker> = Arc::new(RealServiceChecker::new().unwrap());
    let handler = ServiceCheckPollHandler {
        store: store.clone(),
        devices: devices.clone(),
        device_metrics: device_metrics.clone(),
        matcher: matcher.clone(),
        checker,
        settings: Arc::new(
            discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests().await,
        ),
        last_polled: Arc::new(dashmap::DashMap::new()),
        last_polled_date: Arc::new(dashmap::DashMap::new()),
    };

    store
        .enqueue(
            QueueKind::ServiceCheckPoll,
            serde_json::to_value(ServiceCheckPollPayload {
                device_id,
                generation,
            })
            .unwrap(),
            None,
        )
        .await
        .unwrap();
    let job = store
        .claim(QueueKind::ServiceCheckPoll, "test-worker", 1)
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    handler.handle(job).await.unwrap();

    // --- Real socket I/O actually landed in stored metrics ---
    let (_, metrics) = discovery_devices::get(devices.as_ref(), device_metrics.as_ref(), device_id)
        .await
        .unwrap()
        .unwrap();
    let discovery_core::MetricValue::Table(rows) = metrics
        .get("service_checks")
        .expect("service_checks metric must be recorded")
    else {
        panic!("service_checks must be table-shaped");
    };
    assert_eq!(rows.len(), 3);
    let row = |name: &str| {
        rows.iter()
            .find(|r| r.index == name)
            .unwrap_or_else(|| panic!("no row for {name}"))
    };
    assert_eq!(
        row("tcp_ok").fields.get("ok"),
        Some(&discovery_core::MetricValue::Bool(true)),
        "a real open TCP port must be reported reachable"
    );
    assert_eq!(
        row("http_ok").fields.get("ok"),
        Some(&discovery_core::MetricValue::Bool(true)),
        "a real HTTP 200 + matching body must be reported ok"
    );
    assert_eq!(
        row("tcp_fail").fields.get("ok"),
        Some(&discovery_core::MetricValue::Bool(false)),
        "a genuinely closed port must be reported not ok"
    );
    assert!(
        row("tcp_fail").fields.get("error").is_some(),
        "a failed check must carry a human-readable error"
    );

    // --- The row-scoped AlertRule fires for the one failing check, zero new engine code ---
    let alert_eval = Arc::new(AlertEvalHandler {
        evaluation_locks: Default::default(),
        alert_engine: alert_engine.clone(),
        alerts: Arc::new(AlertStateTracker::new()),
        alert_store: alert_store.clone(),
        devices: devices.clone(),
        device_metrics: device_metrics.clone(),
        matcher: matcher.clone(),
        maintenance_windows: Arc::new(
            SeaOrmMaintenanceWindowStore::new_in_memory_for_tests().await,
        ),
        notification_rules: Arc::new(SeaOrmNotificationRuleStore::new_in_memory_for_tests().await),
        notification_channels: Arc::new(
            SeaOrmNotificationChannelStore::new_in_memory_for_tests().await,
        ),
        auth: Arc::new(discovery_auth::SeaOrmAuthStore::new(
            discovery_migration::connect_in_memory_for_tests().await,
        )),
        queue: store.clone(),
        still_active_last_persisted: Arc::new(dashmap::DashMap::new()),
        correlator: Arc::new(discovery_agent::group_alert::GroupAlertCorrelator::new()),
    });

    drain_alert_evals(&store, &alert_eval).await;

    let failing = alert_for(&alert_store, device_id, "tcp_fail").await;
    assert_eq!(failing.state, discovery_core::AlertState::Active);
    assert!(
        failing.message.contains("tcp_fail"),
        "message: {}",
        failing.message
    );

    let page = alert_store
        .list(&AlertListQuery {
            response_pending: false,
            screen_only: false,
            search: None,
            level: None,
            state: None,
            device_id: Some(device_id),
            since: None,
            until: None,
            sort_by: AlertSortBy::LastSeen,
            sort_dir: SortDir::Desc,
            limit: 100,
            offset: 0,
        })
        .await
        .unwrap();
    assert_eq!(
        page.items.len(),
        1,
        "only the failing check must produce an alert — the two healthy checks must not"
    );
}

/// `docs/Roadmap.md` "До релиза" item 5 (2026-09-14, ICMP packet loss %) — proves the real
/// `ReachabilityPollHandler::handle` actually threads `PingOutcome::loss_pct` all the way
/// through to `DeviceStore::set_reachability`'s persisted `Device::ping_loss_pct`, not just
/// `reachable`/`ping_ok`. `FakePinger::seed_outcome` (not the plain `seed`) is what makes
/// this observable — a real ICMP loss reading is separately proven against real sockets in
/// `crates/ping/src/client.rs`'s own live test.
#[tokio::test]
async fn reachability_poll_persists_a_partial_packet_loss_reading_onto_the_device() {
    use discovery_agent::handlers::ReachabilityPollHandler;
    use discovery_config_store::SettingsStore;
    use discovery_core::payload::ReachabilityPollPayload;
    use discovery_core::{DeviceFacts, PingConfig};
    use discovery_ping::PingOutcome;

    let db = discovery_migration::connect_in_memory_for_tests().await;
    let device_metrics: Arc<dyn DeviceMetricsStore> =
        Arc::new(SeaOrmDeviceMetricsStore::new(db.clone()));
    let alert_store: Arc<dyn AlertStore> =
        Arc::new(discovery_alerts::SeaOrmAlertStore::new(db.clone()));
    let devices: Arc<dyn DeviceStore> = Arc::new(SeaOrmDeviceStore::new(
        db,
        device_metrics,
        alert_store.clone(),
    ));
    let (device_id, _) = devices
        .resolve(DeviceFacts {
            ip: "10.50.1.1".to_string(),
        })
        .await
        .unwrap();

    let pinger = Arc::new(discovery_ping::FakePinger::new());
    pinger.seed_outcome(
        "10.50.1.1",
        PingOutcome {
            reachable: true,
            loss_pct: 25.0,
        },
    );
    let settings =
        Arc::new(discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests().await);
    settings
        .set_ping_config(&PingConfig {
            timeout_ms: 100,
            retries: 0,
        })
        .await
        .unwrap();
    let queue: Arc<dyn JobQueueStore> =
        Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
    let handler = ReachabilityPollHandler {
        store: queue.clone(),
        devices: devices.clone(),
        snmp: Arc::new(discovery_snmp::FakeSnmpClient::new()),
        pinger: pinger.clone(),
        discovery_configs: Arc::new(
            discovery_config_store::SeaOrmDiscoveryConfigStore::new_in_memory_for_tests().await,
        ),
        settings: settings.clone(),
    };

    queue
        .enqueue(
            QueueKind::ReachabilityPoll,
            serde_json::to_value(ReachabilityPollPayload { device_id }).unwrap(),
            None,
        )
        .await
        .unwrap();
    let job = queue
        .claim(QueueKind::ReachabilityPoll, "test-worker", 1)
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    handler.handle(job).await.unwrap();

    let device = devices.get_device(device_id).await.unwrap().unwrap();
    assert_eq!(
        device.ping_ok,
        Some(true),
        "reachable, per the seeded outcome"
    );
    assert_eq!(device.ping_loss_pct, Some(25.0), "the partial loss reading must survive the full handler -> DeviceStore round trip unchanged, not just the boolean");
}

/// `docs/Roadmap.md` "Находки ручного теста демо-парка" item 6 (2026-09-18) — a
/// `DeviceStore` decorator that fails the *first* call to [`DeviceStore::set_reachability`]
/// with a simulated transient DB error (the shape of a real `SQLITE_BUSY`/"database is
/// locked" failure under the concurrent discoverer/worker load that found this bug live),
/// then delegates every subsequent call — including every other method — straight through
/// to a real, fully-working `SeaOrmDeviceStore`. Every method below is a plain
/// pass-through except [`Self::set_reachability`]; the point of the decorator is to
/// isolate exactly one call in exactly one tick as the failure, not to fake the whole
/// store.
struct FlakyOnFirstReachabilityWrite {
    inner: Arc<dyn DeviceStore>,
    fail_next: std::sync::atomic::AtomicBool,
}

impl FlakyOnFirstReachabilityWrite {
    fn new(inner: Arc<dyn DeviceStore>) -> Self {
        Self {
            inner,
            fail_next: std::sync::atomic::AtomicBool::new(true),
        }
    }
}

#[async_trait::async_trait]
impl DeviceStore for FlakyOnFirstReachabilityWrite {
    async fn resolve(
        &self,
        facts: discovery_core::DeviceFacts,
    ) -> anyhow::Result<(uuid::Uuid, bool)> {
        self.inner.resolve(facts).await
    }
    async fn apply_profile_if_changed(
        &self,
        id: uuid::Uuid,
        new_profile: &str,
        new_profile_version: &str,
    ) -> anyhow::Result<Option<discovery_devices::ProfileDecision>> {
        self.inner
            .apply_profile_if_changed(id, new_profile, new_profile_version)
            .await
    }
    async fn current_poll_generation(&self, id: uuid::Uuid) -> anyhow::Result<Option<u64>> {
        self.inner.current_poll_generation(id).await
    }
    async fn set_snmp_credentials(
        &self,
        id: uuid::Uuid,
        credentials: discovery_core::SnmpCredentials,
    ) -> anyhow::Result<()> {
        self.inner.set_snmp_credentials(id, credentials).await
    }
    async fn set_ssh_credentials(
        &self,
        id: uuid::Uuid,
        credentials: discovery_core::SshCredentials,
    ) -> anyhow::Result<()> {
        self.inner.set_ssh_credentials(id, credentials).await
    }
    async fn pin_ssh_host_key(&self, id: uuid::Uuid, fingerprint: String) -> anyhow::Result<()> {
        self.inner.pin_ssh_host_key(id, fingerprint).await
    }
    // The one method this decorator actually overrides — see the struct's docs.
    async fn set_reachability(
        &self,
        id: uuid::Uuid,
        ping_ok: bool,
        ping_loss_pct: f64,
        snmp_ok: bool,
    ) -> anyhow::Result<()> {
        if self
            .fail_next
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            anyhow::bail!("simulated SQLITE_BUSY: database is locked");
        }
        self.inner
            .set_reachability(id, ping_ok, ping_loss_pct, snmp_ok)
            .await
    }
    async fn delete_unreachable_since(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<Vec<(uuid::Uuid, String)>> {
        self.inner.delete_unreachable_since(cutoff).await
    }
    async fn set_enabled(&self, id: uuid::Uuid, enabled: bool) -> anyhow::Result<()> {
        self.inner.set_enabled(id, enabled).await
    }
    async fn set_enabled_all(&self, enabled: bool) -> anyhow::Result<u64> {
        self.inner.set_enabled_all(enabled).await
    }
    async fn set_enabled_for_ids(&self, ids: &[uuid::Uuid], enabled: bool) -> anyhow::Result<u64> {
        self.inner.set_enabled_for_ids(ids, enabled).await
    }
    async fn get_metric_overrides(&self, id: uuid::Uuid) -> anyhow::Result<BTreeMap<String, bool>> {
        self.inner.get_metric_overrides(id).await
    }
    async fn get_metric_overrides_for_many(
        &self,
        ids: &[uuid::Uuid],
    ) -> anyhow::Result<BTreeMap<uuid::Uuid, BTreeMap<String, bool>>> {
        self.inner.get_metric_overrides_for_many(ids).await
    }
    async fn set_metric_override(
        &self,
        id: uuid::Uuid,
        name: &str,
        enabled: bool,
    ) -> anyhow::Result<()> {
        self.inner.set_metric_override(id, name, enabled).await
    }
    async fn clear_metric_override(&self, id: uuid::Uuid, name: &str) -> anyhow::Result<()> {
        self.inner.clear_metric_override(id, name).await
    }
    async fn clear_metric_overrides(&self, id: uuid::Uuid, names: &[String]) -> anyhow::Result<()> {
        self.inner.clear_metric_overrides(id, names).await
    }
    async fn clear_metric_overrides_for_devices(
        &self,
        ids: &[uuid::Uuid],
        names: &[String],
    ) -> anyhow::Result<()> {
        self.inner
            .clear_metric_overrides_for_devices(ids, names)
            .await
    }
    async fn prune_metric_overrides(&self, id: uuid::Uuid, keep: &[String]) -> anyhow::Result<()> {
        self.inner.prune_metric_overrides(id, keep).await
    }
    async fn delete(&self, id: uuid::Uuid) -> anyhow::Result<()> {
        self.inner.delete(id).await
    }
    async fn get_device(&self, id: uuid::Uuid) -> anyhow::Result<Option<discovery_core::Device>> {
        self.inner.get_device(id).await
    }
    async fn id_by_ip(&self, ip: &str) -> anyhow::Result<Option<uuid::Uuid>> {
        self.inner.id_by_ip(ip).await
    }
    async fn all(&self) -> anyhow::Result<Vec<discovery_core::Device>> {
        self.inner.all().await
    }
    async fn list_devices(
        &self,
        query: &discovery_devices::DeviceListQuery,
    ) -> anyhow::Result<discovery_devices::DeviceListPage> {
        self.inner.list_devices(query).await
    }
    async fn device_ids_by_profile(&self, profile_name: &str) -> anyhow::Result<Vec<uuid::Uuid>> {
        self.inner.device_ids_by_profile(profile_name).await
    }
    async fn count(&self) -> anyhow::Result<u64> {
        self.inner.count().await
    }
}

/// `docs/Roadmap.md` "Находки ручного теста демо-парка" item 6 — proves the actual fix:
/// `ReachabilityPollHandler::handle` must survive a transient DB error on
/// `DeviceStore::set_reachability` (e.g. `SQLITE_BUSY` under the concurrent discoverer/
/// worker load that found this live, 2026-09-18) by catching it around just that one call,
/// not letting it propagate via `?` out of the whole handler — see
/// `docs/Changelog/2026-09-18 - Fix ReachabilityPollHandler умирает после SQLITE_BUSY.md`.
/// Before the fix, `handle()` would return `Err` on the first (failing) tick and —
/// critically — never reach the `tokio::spawn` self-reenqueue at the bottom, so no second
/// `ReachabilityPoll` job would ever be enqueued for this device: the chain dies forever,
/// not just this one tick. This test proves both halves of the fix: (1) `handle()` itself
/// returns `Ok(())` even though the DB write failed, and (2) the chain actually reached its
/// self-reenqueue and produced a real follow-up job, which — on a later tick, once the
/// simulated outage has cleared — successfully persists `ping_ok`/`snmp_ok`.
#[tokio::test]
async fn reachability_poll_survives_a_transient_db_error_and_keeps_the_chain_alive() {
    use discovery_agent::handlers::ReachabilityPollHandler;
    use discovery_config_store::SettingsStore;
    use discovery_core::payload::ReachabilityPollPayload;
    use discovery_core::{DeviceFacts, PingConfig};
    use discovery_ping::PingOutcome;

    let db = discovery_migration::connect_in_memory_for_tests().await;
    let device_metrics: Arc<dyn DeviceMetricsStore> =
        Arc::new(SeaOrmDeviceMetricsStore::new(db.clone()));
    let alert_store: Arc<dyn AlertStore> =
        Arc::new(discovery_alerts::SeaOrmAlertStore::new(db.clone()));
    let real_devices: Arc<dyn DeviceStore> = Arc::new(SeaOrmDeviceStore::new(
        db,
        device_metrics,
        alert_store.clone(),
    ));
    let (device_id, _) = real_devices
        .resolve(DeviceFacts {
            ip: "10.50.2.2".to_string(),
        })
        .await
        .unwrap();

    // Wraps the real store, failing only the very next `set_reachability` call —
    // simulates exactly one transient `SQLITE_BUSY` on one tick, not a permanently broken
    // store (a permanently broken store would legitimately never recover, which isn't
    // what this bug was about).
    let devices: Arc<dyn DeviceStore> =
        Arc::new(FlakyOnFirstReachabilityWrite::new(real_devices.clone()));

    let pinger = Arc::new(discovery_ping::FakePinger::new());
    pinger.seed_outcome(
        "10.50.2.2",
        PingOutcome {
            reachable: true,
            loss_pct: 0.0,
        },
    );
    let settings =
        Arc::new(discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests().await);
    settings
        .set_ping_config(&PingConfig {
            timeout_ms: 100,
            retries: 0,
        })
        .await
        .unwrap();
    // Short poll interval so the self-reenqueue's `tokio::spawn` (`sleep(jittered(...))`)
    // resolves almost immediately — real wall-clock time, not `tokio::time::pause`, since
    // the reenqueue closure itself awaits `SettingsStore::poll_intervals()` (real async
    // I/O against the in-memory DB), which a paused clock wouldn't advance past anyway.
    settings
        .set_poll_intervals(&discovery_core::PollIntervalsConfig {
            reachability_secs: 0,
            ..Default::default()
        })
        .await
        .unwrap();
    let queue: Arc<dyn JobQueueStore> =
        Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
    let handler = ReachabilityPollHandler {
        store: queue.clone(),
        devices: devices.clone(),
        snmp: Arc::new(discovery_snmp::FakeSnmpClient::new()),
        pinger: pinger.clone(),
        discovery_configs: Arc::new(
            discovery_config_store::SeaOrmDiscoveryConfigStore::new_in_memory_for_tests().await,
        ),
        settings: settings.clone(),
    };

    // --- Tick 1: the simulated DB write fails ---
    queue
        .enqueue(
            QueueKind::ReachabilityPoll,
            serde_json::to_value(ReachabilityPollPayload { device_id }).unwrap(),
            None,
        )
        .await
        .unwrap();
    let job1 = queue
        .claim(QueueKind::ReachabilityPoll, "test-worker", 1)
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let result1 = handler.handle(job1).await;
    assert!(result1.is_ok(), "handle() must not propagate a transient DB error out of the whole handler — the DB write is caught internally, not the fix: {result1:?}");

    let device_after_tick1 = real_devices.get_device(device_id).await.unwrap().unwrap();
    assert_eq!(
        device_after_tick1.ping_ok, None,
        "the failed write must not have silently persisted anything — still untouched after tick 1"
    );

    // --- The chain must have reached its self-reenqueue despite the failed write above ---
    // Real wall-clock wait for the `tokio::spawn`'d reschedule (interval 0 + up to 1ms
    // jitter, see `jittered`'s docs) to actually run and enqueue the next job.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let job2 = queue
        .claim(QueueKind::ReachabilityPoll, "test-worker", 1)
        .await
        .unwrap()
        .into_iter()
        .next();
    assert!(job2.is_some(), "the chain must have self-reenqueued a follow-up ReachabilityPoll job even though tick 1's DB write failed — this is exactly the bug: before the fix, a failed write propagates out of handle() via `?` and the tokio::spawn reschedule below it never runs");

    // --- Tick 2: the simulated outage has cleared (FlakyOnFirstReachabilityWrite only
    // fails once) — the chain must actually recover, not just survive ---
    let result2 = handler.handle(job2.unwrap()).await;
    assert!(result2.is_ok());
    let device_after_tick2 = real_devices.get_device(device_id).await.unwrap().unwrap();
    assert_eq!(device_after_tick2.ping_ok, Some(true), "once the transient error clears, the very next tick must successfully persist reachability — the chain healed itself, no process restart needed");
}
