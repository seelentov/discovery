//! End-to-end proof of group-alert suppression (2026-09-16, item 3 of `docs/Roadmap.md`'s
//! "Топология → групповые тревоги → RADIUS" chain) against **real** `discovery-devicefarm`
//! instances — real SNMP wire traffic through `discovery_snmp::RealSnmpClient`, real
//! `MetricPollHandler`/`TopologyRecomputeHandler`/`AlertEvalHandler` production handlers
//! (not injected metrics/alerts), exactly like `live_topology.rs`'s own docs describe for
//! the topology half this feature builds on.
//!
//! The one piece this test drives directly rather than through a handler is the group-alert
//! sweep's own per-tick body (`discovery_agent::group_alert::{merge_upstream_map,
//! compute_suppression}`, both `pub` for exactly this reason) — `run_group_alert_loop`
//! itself is just `loop { sleep; <this body>; }`, no different from how every other
//! recurring-loop live test in this crate drives the handler/logic directly rather than the
//! outer timer wrapper.
//!
//! **Live-only, `#[ignore]`d — not run by normal `cargo test`.**
//!
//! ## Setup (once, before running `cargo test -p discovery-agent --test live_group_alert -- --ignored`)
//!
//! ```bash
//! sudo ifconfig lo0 alias 127.0.0.2 up   # second virtual device's IP — see discovery-live-verification skill
//! cargo run -p discovery-devicefarm -- serve --root /tmp/devicefarm-group-alert-test \
//!   --bind 127.0.0.1:8098 \
//!   --snmpsim-binary ~/Library/Python/3.9/bin/snmpsim-command-responder &
//! ```

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use discovery_agent::group_alert::{compute_suppression, merge_upstream_map};
use discovery_agent::handlers::{AlertEvalHandler, MetricPollHandler};
use discovery_agent::topology_recompute::TopologyRecomputeHandler;
use discovery_alerts::{AlertListQuery, AlertSortBy, AlertStore};
use discovery_config_store::{
    GroupAlertRule, GroupAlertRuleStore, SeaOrmGroupAlertRuleStore, SeaOrmTopologyRuleStore,
    TopologyRule, TopologyRuleStore,
};
use discovery_core::payload::MetricPollPayload;
use discovery_core::{AlertState, DeviceFacts, QueueKind, SnmpAuth, SnmpVersion, SortDir};
use discovery_devices::{
    DeviceMetricsStore, DeviceStore, SeaOrmDeviceMetricsStore, SeaOrmDeviceStore,
};
use discovery_dsl::topology::TopologyEvaluator;
use discovery_dsl::{
    AlertRule, MatchSection, MetricSpec, MetricsSection, ProfileFile, ProfileMatcher, ProfileMeta,
};
use discovery_queue::{JobHandler, JobQueueStore, SeaOrmJobQueueStore};
use discovery_snmp::{RealSnmpClient, SnmpClient};
use discovery_topology::{SeaOrmTopologyStore, TopologyStore};

const DEVICEFARM_BASE: &str = "http://127.0.0.1:8098";
const DEVICE_A_PORT: u16 = 18821;
const DEVICE_B_PORT: u16 = 18822;
const CHASSIS_ID_OID: &str = "1.3.6.1.4.1.99998.1.0";
const REM_TABLE_ENTRY_OID: &str = "1.3.6.1.4.1.99998.2";
const REM_TABLE_CHASSIS_COL: &str = "5";
const ROLE_VALUE_OID: &str = "1.3.6.1.4.1.99998.3.0";
/// `1` = simulates "this device just went unreachable" (drives `device_unreachable`'s
/// activation expression) — a stand-in for real ping loss, same reasoning `live_topology.rs`
/// gives for `role_value` standing in for a real role/profile field: this test only needs
/// *some* controllable signal, not real ICMP loss.
const UNREACHABLE_FLAG_OID: &str = "1.3.6.1.4.1.99998.4.0";
const PROFILE_NAME: &str = "group_alert_live_test";
const ALERT_NAME: &str = "device_unreachable";

fn devicefarm_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

async fn create_device(
    http: &reqwest::Client,
    ip: &str,
    port: u16,
    my_chassis_id: &str,
    claimed_neighbor_chassis_id: &str,
    role_value: i64,
    unreachable_flag: i64,
) {
    let resp = http
        .post(format!("{DEVICEFARM_BASE}/api/devices"))
        .json(&serde_json::json!({
            "ip": ip,
            "port": port,
            "community": "public",
            "snmp_version": "v2c",
            "oids": [
                {"label": "lldp_chassis_id", "oid": CHASSIS_ID_OID, "tag": "OctetString", "value": my_chassis_id},
                {"label": "lldp_rem_chassis_id", "oid": format!("{REM_TABLE_ENTRY_OID}.{REM_TABLE_CHASSIS_COL}.1"), "tag": "OctetString", "value": claimed_neighbor_chassis_id},
                {"label": "role_value", "oid": ROLE_VALUE_OID, "tag": "Integer32", "value": role_value.to_string()},
                {"label": "unreachable_flag", "oid": UNREACHABLE_FLAG_OID, "tag": "Integer32", "value": unreachable_flag.to_string()},
            ]
        }))
        .send()
        .await
        .expect("POST /api/devices — is discovery-devicefarm actually running on 127.0.0.1:8098? See this file's module docs for the setup command.");
    assert!(
        resp.status().is_success(),
        "unexpected status creating/updating device {ip}:{port}: {}",
        resp.status()
    );
}

async fn wait_until_device_answers(
    snmp: &RealSnmpClient,
    target: &discovery_core::DeviceTarget,
    deadline: std::time::Instant,
) {
    loop {
        if snmp.get(target, CHASSIS_ID_OID).await.is_ok() {
            return;
        }
        if std::time::Instant::now() >= deadline {
            panic!("device at {}:{} never answered SNMP within the deadline — is discovery-devicefarm running (see this file's module docs)?", target.ip, target.port);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Unlike [`wait_until_device_answers`] (any answer at all), this waits for
/// `UNREACHABLE_FLAG_OID` to actually report `expected` — needed after re-`create_device`-ing
/// an already-running device to change its simulated value: devicefarm's snmpsim child
/// restart is debounced (~1s, undocumented exact bound), so a plain "does it answer" check
/// can observe the *old* still-shutting-down child's stale value as a false "ready" signal.
async fn wait_until_flag_is(
    snmp: &RealSnmpClient,
    target: &discovery_core::DeviceTarget,
    expected: i64,
    deadline: std::time::Instant,
) {
    loop {
        if let Ok(v) = snmp.get(target, UNREACHABLE_FLAG_OID).await {
            if v.as_i64() == Some(expected) {
                return;
            }
        }
        if std::time::Instant::now() >= deadline {
            panic!("device at {}:{} never reported unreachable_flag={expected} within the deadline — is discovery-devicefarm's snmpsim child restart just slower than this test's wait, or is create_device's restart-on-repost behavior not what this test assumes?", target.ip, target.port);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn detailed_metric(oid: &str, columns: Option<BTreeMap<String, String>>) -> MetricSpec {
    MetricSpec::Detailed {
        oid: oid.to_string(),
        columns,
        schedule: None,
        history_retention_secs: None,
        enabled: true,
        history_keep_last_success: true,
        history_keep_last_attempt: true,
        derive: None,
    }
}

fn profile() -> ProfileFile {
    let mut poll = BTreeMap::new();
    poll.insert(
        "lldp_chassis_id".to_string(),
        detailed_metric(CHASSIS_ID_OID, None),
    );
    poll.insert(
        "lldp_rem_table".to_string(),
        detailed_metric(
            REM_TABLE_ENTRY_OID,
            Some(BTreeMap::from([(
                "chassis_id".to_string(),
                REM_TABLE_CHASSIS_COL.to_string(),
            )])),
        ),
    );
    poll.insert(
        "role_value".to_string(),
        detailed_metric(ROLE_VALUE_OID, None),
    );
    poll.insert(
        "unreachable_flag".to_string(),
        detailed_metric(UNREACHABLE_FLAG_OID, None),
    );
    ProfileFile {
        profile: ProfileMeta {
            name: PROFILE_NAME.into(),
            priority: 0,
        },
        match_expr: MatchSection {
            expression: "true".into(),
        },
        metrics: MetricsSection { poll },
        traps: Default::default(),
        syslog: Default::default(),
        service_checks: Default::default(),
        alerts: vec![AlertRule {
            policy: Default::default(),
            name: ALERT_NAME.to_string(),
            level: "critical".to_string(),
            row_metric: None,
            row_key_expression: None,
            expression: "metrics.unreachable_flag == 1".to_string(),
            // `None` = negation of `expression` — clears the moment a re-poll observes
            // `unreachable_flag != 1`, no separate hysteresis expression needed for this test.
            deactivation_expression: None,
            facts_expression: None,
            message: "device unreachable (simulated)".to_string(),
            // Clear immediately once the deactivation condition holds — this test's
            // recovery step re-polls once and expects the clear on that same tick, not
            // after a grace period.
            clear_after_seconds: None,
            activate_after_seconds: None,
            flap_window_seconds: None,
            flap_threshold: None,
            enabled: true,
        }],
        version: "test".into(),
    }
}

/// One real `MetricPoll` tick, followed by draining whatever `TopologyRecompute`/`AlertEval`
/// jobs it enqueued — `MetricPollHandler::handle` enqueues both unconditionally every tick
/// (see `discovery_agent::handlers`' docs), so this mirrors exactly what the three
/// independent worker pools in `main.rs` would do, just sequentially.
async fn tick_and_drain(
    store: &Arc<dyn JobQueueStore>,
    metric_poll_handler: &MetricPollHandler,
    topology_recompute_handler: &TopologyRecomputeHandler,
    alert_eval_handler: &AlertEvalHandler,
    device_id: uuid::Uuid,
) {
    store
        .enqueue(
            QueueKind::MetricPoll,
            serde_json::to_value(MetricPollPayload {
                device_id,
                generation: 1,
            })
            .unwrap(),
            None,
        )
        .await
        .unwrap();
    let job = store
        .claim(QueueKind::MetricPoll, "test-worker", 1)
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    metric_poll_handler.handle(job).await.unwrap();

    while let Some(job) = store
        .claim(QueueKind::TopologyRecompute, "test-worker", 1)
        .await
        .unwrap()
        .into_iter()
        .next()
    {
        topology_recompute_handler.handle(job).await.unwrap();
    }
    while let Some(job) = store
        .claim(QueueKind::AlertEval, "test-worker", 1)
        .await
        .unwrap()
        .into_iter()
        .next()
    {
        alert_eval_handler.handle(job).await.unwrap();
    }
}

/// One real group-alert sweep tick's body — `discovery_agent::group_alert::
/// run_group_alert_loop` minus the outer `loop { sleep; ... }` (same "drive the logic, not
/// the timer wrapper" posture every recurring-loop live test in this crate already takes),
/// calling the exact same `pub` functions that loop calls.
async fn run_one_group_alert_tick(
    alert_store: &Arc<dyn AlertStore>,
    topology_rules: &Arc<dyn TopologyRuleStore>,
    topology: &Arc<dyn TopologyStore>,
    group_alert_rules: &Arc<dyn GroupAlertRuleStore>,
) {
    let evaluator = discovery_dsl::group_alerts::GroupAlertEvaluator::new();
    let active = alert_store
        .list(&AlertListQuery {
            response_pending: false,
            screen_only: false,
            search: None,
            level: None,
            state: Some(AlertState::Active),
            device_id: None,
            since: None,
            until: None,
            sort_by: AlertSortBy::FirstSeen,
            sort_dir: SortDir::Asc,
            limit: 10_000,
            offset: 0,
        })
        .await
        .unwrap()
        .items;

    let mut rule_edges = Vec::new();
    for rule in topology_rules
        .list_all()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.enabled)
    {
        rule_edges.push(topology.resolved_edges(&rule.name).await.unwrap());
    }
    let upstream_of = merge_upstream_map(rule_edges);
    let group_rules: Vec<GroupAlertRule> = group_alert_rules
        .list_all()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.enabled)
        .collect();

    let assignments = compute_suppression(&active, &upstream_of, &group_rules, &evaluator);
    for alert in active {
        let new_value = assignments.get(&alert.id).copied().flatten();
        if alert.suppressed_by_alert_id != new_value {
            // `set_suppression`, not `upsert(&alert)` — matches
            // `discovery_agent::group_alert::run_group_alert_loop`'s real write path
            // (2026-09-17 fix, see `AlertStore::set_suppression`'s docs): a full `upsert`
            // here would be indistinguishable from the bug this file's other test step
            // exists to catch.
            alert_store
                .set_suppression(alert.id, new_value)
                .await
                .unwrap();
        }
    }
}

/// The real proof, end to end: two real devices, both genuinely unreachable (simulated via
/// `unreachable_flag`), topologically linked with device A resolved as upstream (lower
/// `role_value`, same real-SNMP-driven direction proof `live_topology.rs` establishes).
/// Real `AlertEvalHandler` activates a real `device_unreachable` alert on each device from
/// real polled metrics. A real group-alert sweep tick must then suppress B's alert,
/// pointing it at A's — and un-suppress it again once A's alert genuinely clears from a
/// second real poll showing recovery.
#[tokio::test]
#[ignore]
async fn a_real_poll_cycle_suppresses_the_downstream_alert_and_un_suppresses_it_on_recovery() {
    let http = devicefarm_client();
    // A's role_value (0) < B's (1) -> A resolves as upstream, same as live_topology.rs.
    // Both start "unreachable" (flag=1) so both real-poll their way into an active alert.
    create_device(&http, "127.0.0.1", DEVICE_A_PORT, "key-a", "key-b", 0, 1).await;
    create_device(&http, "127.0.0.2", DEVICE_B_PORT, "key-b", "key-a", 1, 1).await;

    let snmp = Arc::new(RealSnmpClient::new());
    let target_a = discovery_core::DeviceTarget {
        ip: "127.0.0.1".into(),
        port: DEVICE_A_PORT,
        auth: SnmpAuth::Community {
            version: SnmpVersion::V2c,
            community: "public".into(),
        },
        timeout_ms: 1000,
        retries: 2,
    };
    let target_b = discovery_core::DeviceTarget {
        ip: "127.0.0.2".into(),
        port: DEVICE_B_PORT,
        auth: SnmpAuth::Community {
            version: SnmpVersion::V2c,
            community: "public".into(),
        },
        timeout_ms: 1000,
        retries: 2,
    };
    wait_until_device_answers(
        &snmp,
        &target_a,
        std::time::Instant::now() + Duration::from_secs(10),
    )
    .await;
    wait_until_device_answers(
        &snmp,
        &target_b,
        std::time::Instant::now() + Duration::from_secs(10),
    )
    .await;

    // ---- Wire the real production handlers, in-memory sqlite for everything else ----
    let db = discovery_migration::connect_in_memory_for_tests().await;
    let device_metrics: Arc<dyn DeviceMetricsStore> =
        Arc::new(SeaOrmDeviceMetricsStore::new(db.clone()));
    let alert_store: Arc<dyn AlertStore> =
        Arc::new(discovery_alerts::SeaOrmAlertStore::new(db.clone()));
    let devices: Arc<dyn DeviceStore> = Arc::new(SeaOrmDeviceStore::new(
        db,
        device_metrics.clone(),
        alert_store.clone(),
    ));
    let store: Arc<dyn JobQueueStore> =
        Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
    let matcher = Arc::new(ProfileMatcher::new(vec![profile()]));

    // `topology_rules`/`topology` share one connection — real FK, same reasoning
    // `live_topology.rs` documents.
    let topology_db = discovery_migration::connect_in_memory_for_tests().await;
    let topology_rules: Arc<dyn TopologyRuleStore> =
        Arc::new(SeaOrmTopologyRuleStore::new(topology_db.clone()));
    let topology: Arc<dyn TopologyStore> = Arc::new(SeaOrmTopologyStore::new(topology_db));
    topology_rules
        .upsert(&TopologyRule {
            id: uuid::Uuid::new_v4(),
            name: "lldp".to_string(),
            enabled: true,
            my_key_expression: "metrics.lldp_chassis_id".to_string(),
            claimed_neighbors_expression: Some(
                "metrics.lldp_rem_table.map(|row| row.chassis_id)".to_string(),
            ),
            rank_expression: Some("metrics.role_value".to_string()),
            watched_metrics: None,
        })
        .await
        .unwrap();

    let group_alert_rules: Arc<dyn GroupAlertRuleStore> =
        Arc::new(SeaOrmGroupAlertRuleStore::new_in_memory_for_tests().await);
    group_alert_rules
        .upsert(&GroupAlertRule {
            id: uuid::Uuid::new_v4(),
            name: "unreachable-cascade".to_string(),
            enabled: true,
            cause_expression: format!(r#"name == "{ALERT_NAME}""#),
            effect_expression: format!(r#"name == "{ALERT_NAME}""#),
        })
        .await
        .unwrap();

    let (device_a, _) = devices
        .resolve(DeviceFacts {
            ip: "127.0.0.1".into(),
        })
        .await
        .unwrap();
    devices
        .set_snmp_credentials(
            device_a,
            discovery_core::SnmpCredentials {
                auth: target_a.auth.clone(),
                port: DEVICE_A_PORT,
            },
        )
        .await
        .unwrap();
    devices
        .apply_profile_if_changed(device_a, PROFILE_NAME, "test")
        .await
        .unwrap();
    let (device_b, _) = devices
        .resolve(DeviceFacts {
            ip: "127.0.0.2".into(),
        })
        .await
        .unwrap();
    devices
        .set_snmp_credentials(
            device_b,
            discovery_core::SnmpCredentials {
                auth: target_b.auth.clone(),
                port: DEVICE_B_PORT,
            },
        )
        .await
        .unwrap();
    devices
        .apply_profile_if_changed(device_b, PROFILE_NAME, "test")
        .await
        .unwrap();

    let metric_poll_handler = MetricPollHandler {
        store: store.clone(),
        snmp: snmp.clone(),
        cli: Arc::new(discovery_ssh::FakeCliClient::new()),
        devices: devices.clone(),
        device_metrics: device_metrics.clone(),
        matcher: matcher.clone(),
        settings: Arc::new(
            discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests().await,
        ),
        last_polled: Arc::new(DashMap::new()),
        last_polled_date: Arc::new(DashMap::new()),
        discovery_configs: Arc::new(
            discovery_config_store::SeaOrmDiscoveryConfigStore::new_in_memory_for_tests().await,
        ),
        pruned_generations: Arc::new(DashMap::new()),
        topology_rules: topology_rules.clone(),
    };
    let topology_recompute_handler = TopologyRecomputeHandler {
        rules: topology_rules.clone(),
        topology: topology.clone(),
        devices: devices.clone(),
        device_metrics: device_metrics.clone(),
        evaluator: Arc::new(TopologyEvaluator::new()),
    };
    let alert_eval_handler = AlertEvalHandler {
        evaluation_locks: Default::default(),
        alert_engine: Arc::new(discovery_dsl::AlertEvaluator::new()),
        alerts: Arc::new(discovery_core::AlertStateTracker::new()),
        alert_store: alert_store.clone(),
        devices: devices.clone(),
        device_metrics: device_metrics.clone(),
        matcher,
        maintenance_windows: Arc::new(
            discovery_config_store::SeaOrmMaintenanceWindowStore::new_in_memory_for_tests().await,
        ),
        notification_rules: Arc::new(
            discovery_config_store::SeaOrmNotificationRuleStore::new_in_memory_for_tests().await,
        ),
        notification_channels: Arc::new(
            discovery_config_store::SeaOrmNotificationChannelStore::new_in_memory_for_tests().await,
        ),
        auth: Arc::new(discovery_auth::SeaOrmAuthStore::new(
            discovery_migration::connect_in_memory_for_tests().await,
        )),
        queue: store.clone(),
        still_active_last_persisted: Arc::new(DashMap::new()),
        correlator: Arc::new(discovery_agent::group_alert::GroupAlertCorrelator::new()),
    };

    // ---- Tick A: real SNMP poll activates A's real alert; B unpolled, topology unresolved ----
    tick_and_drain(
        &store,
        &metric_poll_handler,
        &topology_recompute_handler,
        &alert_eval_handler,
        device_a,
    )
    .await;
    let alert_a_first = alert_store
        .list(&AlertListQuery {
            response_pending: false,
            screen_only: false,
            search: None,
            level: None,
            state: Some(AlertState::Active),
            device_id: Some(device_a),
            since: None,
            until: None,
            sort_by: AlertSortBy::FirstSeen,
            sort_dir: SortDir::Asc,
            limit: 10,
            offset: 0,
        })
        .await
        .unwrap();
    assert_eq!(
        alert_a_first.items.len(),
        1,
        "A's real poll must have activated a real device_unreachable alert"
    );
    let alert_a_id = alert_a_first.items[0].id;

    // ---- Tick B: real SNMP poll activates B's real alert; topology resolves, A upstream ----
    tick_and_drain(
        &store,
        &metric_poll_handler,
        &topology_recompute_handler,
        &alert_eval_handler,
        device_b,
    )
    .await;
    let edges = topology.resolved_edges("lldp").await.unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(
        edges[0].upstream_device_id,
        Some(device_a),
        "device A's lower real-polled role_value must resolve it as upstream"
    );

    // ---- Real group-alert sweep tick ----
    run_one_group_alert_tick(&alert_store, &topology_rules, &topology, &group_alert_rules).await;

    let alert_b_page = alert_store
        .list(&AlertListQuery {
            response_pending: false,
            screen_only: false,
            search: None,
            level: None,
            state: Some(AlertState::Active),
            device_id: Some(device_b),
            since: None,
            until: None,
            sort_by: AlertSortBy::FirstSeen,
            sort_dir: SortDir::Asc,
            limit: 10,
            offset: 0,
        })
        .await
        .unwrap();
    assert_eq!(alert_b_page.items.len(), 1);
    let alert_b_id = alert_b_page.items[0].id;
    assert_eq!(
        alert_b_page.items[0].suppressed_by_alert_id,
        Some(alert_a_id),
        "B's alert must be suppressed by A's real alert after a real group-alert sweep tick"
    );

    let alert_a_after = alert_store.get(alert_a_id).await.unwrap().unwrap();
    assert_eq!(
        alert_a_after.suppressed_by_alert_id, None,
        "the upstream root cause must never suppress itself"
    );

    // ---- Regression proof for the 2026-09-17 audit finding #1: a `StillActive` persist
    // for B (same real handler, same condition still holding — nothing about B changed)
    // must not clobber the suppression the sweep just wrote. `still_active_last_persisted`
    // throttles this to once per `STILL_ACTIVE_PERSIST_INTERVAL` (60s) in production; the
    // entry is force-cleared here instead of sleeping 60s real-time so this stays a fast
    // test while still exercising the exact write (`AlertEvalHandler::persist_transition`
    // -> `AlertStore::upsert`) that used to race with the sweep over the same column.
    alert_eval_handler.still_active_last_persisted.remove(&(
        device_b,
        ALERT_NAME.to_string(),
        None,
    ));
    tick_and_drain(
        &store,
        &metric_poll_handler,
        &topology_recompute_handler,
        &alert_eval_handler,
        device_b,
    )
    .await;
    let alert_b_after_still_active = alert_store.get(alert_b_id).await.unwrap().unwrap();
    assert_eq!(
        alert_b_after_still_active.suppressed_by_alert_id,
        Some(alert_a_id),
        "a StillActive persist for B must never clobber suppressed_by_alert_id — AlertStore::upsert must leave that column alone, only AlertStore::set_suppression may write it"
    );

    // ---- Recovery: A genuinely recovers (a second real poll observes unreachable_flag=0) ----
    create_device(&http, "127.0.0.1", DEVICE_A_PORT, "key-a", "key-b", 0, 0).await;
    wait_until_flag_is(
        &snmp,
        &target_a,
        0,
        std::time::Instant::now() + Duration::from_secs(15),
    )
    .await;
    // Force every metric due again for A — same reset `ProfileApplyHandler` performs on a
    // real reconfigure (see its docs); without it `MetricPollHandler`'s own `last_polled`
    // elapsed-time gate would skip re-fetching `unreachable_flag` this soon after the first
    // poll (well under the profile's `metric_secs` interval), observing the stale value.
    metric_poll_handler
        .last_polled
        .retain(|(id, _), _| *id != device_a);
    tick_and_drain(
        &store,
        &metric_poll_handler,
        &topology_recompute_handler,
        &alert_eval_handler,
        device_a,
    )
    .await;
    let alert_a_recovered = alert_store.get(alert_a_id).await.unwrap().unwrap();
    assert_eq!(
        alert_a_recovered.state,
        discovery_core::AlertState::Cleared,
        "A's real re-poll observing recovery must clear its alert"
    );

    // ---- Real group-alert sweep tick, again: A's cleared alert must drop out of the active set ----
    run_one_group_alert_tick(&alert_store, &topology_rules, &topology, &group_alert_rules).await;
    let alert_b_recovered = alert_store.get(alert_b_id).await.unwrap().unwrap();
    assert_eq!(alert_b_recovered.suppressed_by_alert_id, None, "must un-suppress once the claimed root cause is no longer active — no separate code path needed for this, see compute_suppression's docs");

    // ---- Cleanup ----
    let _ = http
        .delete(format!("{DEVICEFARM_BASE}/api/devices/127.0.0.1"))
        .send()
        .await;
    let _ = http
        .delete(format!("{DEVICEFARM_BASE}/api/devices/127.0.0.2"))
        .send()
        .await;
}
