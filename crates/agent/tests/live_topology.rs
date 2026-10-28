//! End-to-end proof of the rule-based topology mechanism (2026-09-16) against **real**
//! `discovery-devicefarm` instances (real `snmpsim-command-responder` child processes,
//! real UDP SNMP wire traffic, real `discovery_snmp::RealSnmpClient`) — not
//! `FakeSnmpClient`, and not metrics injected directly into storage. Drives the real
//! `MetricPollHandler`/`TopologyRecomputeHandler` production handlers directly (same
//! handlers the binary's worker pools run), exactly like `live_derived_metrics.rs`'s own
//! docs describe for that feature.
//!
//! This is the one thing the in-memory integration test in
//! `crates/agent/src/topology_recompute.rs` (`recomputing_only_the_second_device_makes_
//! the_first_devices_claim_resolve`) can't cover on its own: that test injects
//! `MetricValue`s directly via `record_metric_polls`, bypassing `MetricPollHandler`
//! entirely — it proves the resolution logic and the reactive-trigger *code*, but not
//! that a genuine SNMP poll cycle through the real production handler actually reaches
//! that trigger. This test proves exactly that link, with two distinct virtual devices
//! (needs a second loopback alias — `discovery-live-verification`'s docs on why one IP,
//! two ports, would collapse into a single `discovery_core::Device` via `DeviceStore::
//! resolve`'s IP-only identity).
//!
//! **Live-only, `#[ignore]`d — not run by normal `cargo test`.**
//!
//! ## Setup (once, before running `cargo test -p discovery-agent --test live_topology -- --ignored`)
//!
//! ```bash
//! sudo ifconfig lo0 alias 127.0.0.2 up   # second virtual device's IP — see module docs
//! cargo run -p discovery-devicefarm -- serve --root /tmp/devicefarm-topology-test \
//!   --bind 127.0.0.1:8097 \
//!   --snmpsim-binary ~/Library/Python/3.9/bin/snmpsim-command-responder &
//! ```
//!
//! The test creates and deletes its own two virtual devices against that running
//! instance — no manual per-device setup needed beyond the `serve` above.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use discovery_agent::handlers::MetricPollHandler;
use discovery_agent::topology_recompute::TopologyRecomputeHandler;
use discovery_config_store::{SeaOrmTopologyRuleStore, TopologyRule, TopologyRuleStore};
use discovery_core::payload::MetricPollPayload;
use discovery_core::{DeviceFacts, MetricValue, QueueKind, SnmpAuth, SnmpVersion};
use discovery_devices::{
    DeviceMetricsStore, DeviceStore, SeaOrmDeviceMetricsStore, SeaOrmDeviceStore,
};
use discovery_dsl::topology::TopologyEvaluator;
use discovery_dsl::{
    MatchSection, MetricSpec, MetricsSection, ProfileFile, ProfileMatcher, ProfileMeta,
};
use discovery_queue::{JobHandler, JobQueueStore, SeaOrmJobQueueStore};
use discovery_snmp::{RealSnmpClient, SnmpClient};
use discovery_topology::{SeaOrmTopologyStore, TopologyStore};

const DEVICEFARM_BASE: &str = "http://127.0.0.1:8097";
const DEVICE_A_PORT: u16 = 18811;
const DEVICE_B_PORT: u16 = 18812;
const CHASSIS_ID_OID: &str = "1.3.6.1.4.1.99999.1.0";
const REM_TABLE_ENTRY_OID: &str = "1.3.6.1.4.1.99999.2";
const REM_TABLE_CHASSIS_COL: &str = "5";
/// A scalar "role" OID standing in for whatever real signal a provider's
/// `rank_expression` would actually reference (a device role/profile field) — this test
/// only needs *some* numeric metric, not a specific real-world semantic.
const ROLE_VALUE_OID: &str = "1.3.6.1.4.1.99999.3.0";
const PROFILE_NAME: &str = "topology_live_test";

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
            ]
        }))
        .send()
        .await
        .expect("POST /api/devices — is discovery-devicefarm actually running on 127.0.0.1:8097? See this file's module docs for the setup command.");
    assert!(
        resp.status().is_success(),
        "unexpected status creating device {ip}:{port}: {}",
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

fn lldp_profile() -> ProfileFile {
    let mut poll = BTreeMap::new();
    poll.insert(
        "lldp_chassis_id".to_string(),
        MetricSpec::Detailed {
            oid: CHASSIS_ID_OID.to_string(),
            columns: None,
            schedule: None,
            history_retention_secs: None,
            enabled: true,
            history_keep_last_success: true,
            history_keep_last_attempt: true,
            derive: None,
        },
    );
    poll.insert(
        "lldp_rem_table".to_string(),
        MetricSpec::Detailed {
            oid: REM_TABLE_ENTRY_OID.to_string(),
            columns: Some(BTreeMap::from([(
                "chassis_id".to_string(),
                REM_TABLE_CHASSIS_COL.to_string(),
            )])),
            schedule: None,
            history_retention_secs: None,
            enabled: true,
            history_keep_last_success: true,
            history_keep_last_attempt: true,
            derive: None,
        },
    );
    poll.insert(
        "role_value".to_string(),
        MetricSpec::Detailed {
            oid: ROLE_VALUE_OID.to_string(),
            columns: None,
            schedule: None,
            history_retention_secs: None,
            enabled: true,
            history_keep_last_success: true,
            history_keep_last_attempt: true,
            derive: None,
        },
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
        alerts: vec![],
        version: "test".into(),
    }
}

/// The real proof, end to end: device A's real SNMP poll claims B before B has ever been
/// polled — the topology recompute this triggers finds nothing to resolve to yet. Device
/// B's real SNMP poll (**A is never re-polled or re-handled**) makes A's original claim
/// resolve, purely because `neighbors_of` reads current state at call time — the exact
/// design property this whole feature was built around, now proven with real wire
/// traffic instead of directly-injected metrics.
#[tokio::test]
#[ignore]
async fn a_real_lldp_style_poll_cycle_reactively_resolves_a_confirmed_edge() {
    let http = devicefarm_client();
    // Device A's role_value (0) is lower than B's (1) — A must resolve as upstream once
    // both sides have polled, proving `rank_expression` flows through a real SNMP poll
    // cycle, not just injected metrics.
    create_device(&http, "127.0.0.1", DEVICE_A_PORT, "key-a", "key-b", 0).await;
    create_device(&http, "127.0.0.2", DEVICE_B_PORT, "key-b", "key-a", 1).await;

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

    // `create_device` restarts the real snmpsim child (debounced ~1s) per device.
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
    let alert_store: Arc<dyn discovery_alerts::AlertStore> =
        Arc::new(discovery_alerts::SeaOrmAlertStore::new(db.clone()));
    let devices: Arc<dyn DeviceStore> = Arc::new(SeaOrmDeviceStore::new(
        db,
        device_metrics.clone(),
        alert_store,
    ));
    let store: Arc<dyn JobQueueStore> =
        Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
    let matcher = Arc::new(ProfileMatcher::new(vec![lldp_profile()]));

    // `topology_rules`/`topology` share one connection — real `FOREIGN KEY
    // (topology_device_keys/topology_claims).rule_name -> topology_rules.name`, see
    // `discovery_entities::topology_device_keys`'s docs.
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
        matcher,
        settings: Arc::new(
            discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests().await,
        ),
        last_polled: Arc::new(dashmap::DashMap::new()),
        last_polled_date: Arc::new(dashmap::DashMap::new()),
        discovery_configs: Arc::new(
            discovery_config_store::SeaOrmDiscoveryConfigStore::new_in_memory_for_tests().await,
        ),
        pruned_generations: Arc::new(dashmap::DashMap::new()),
        topology_rules: topology_rules.clone(),
    };
    let topology_recompute_handler = TopologyRecomputeHandler {
        rules: topology_rules.clone(),
        topology: topology.clone(),
        devices: devices.clone(),
        device_metrics: device_metrics.clone(),
        evaluator: Arc::new(TopologyEvaluator::new()),
    };

    /// One real `MetricPoll` tick, followed by draining whatever `TopologyRecompute` job
    /// (if any) it enqueued — mirrors exactly what the two independent worker pools in
    /// `main.rs` would do, just sequentially instead of concurrently.
    async fn tick_and_drain_topology(
        store: &Arc<dyn JobQueueStore>,
        metric_poll_handler: &MetricPollHandler,
        topology_recompute_handler: &TopologyRecomputeHandler,
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
    }

    // ---- Tick A: real SNMP poll claims B, but B hasn't been polled/registered yet ----
    tick_and_drain_topology(
        &store,
        &metric_poll_handler,
        &topology_recompute_handler,
        device_a,
    )
    .await;
    let metrics_a = device_metrics.get_metrics(device_a).await.unwrap();
    assert_eq!(
        metrics_a.get("lldp_chassis_id"),
        Some(&MetricValue::Str("key-a".to_string())),
        "raw chassis id must have polled for real over the wire"
    );
    assert!(
        topology
            .neighbors_of("lldp", device_a)
            .await
            .unwrap()
            .is_empty(),
        "B hasn't been polled yet — A's claim can't resolve to anything"
    );

    // ---- Tick B: real SNMP poll — A is never touched again from here on ----
    tick_and_drain_topology(
        &store,
        &metric_poll_handler,
        &topology_recompute_handler,
        device_b,
    )
    .await;

    let neighbors_a = topology.neighbors_of("lldp", device_a).await.unwrap();
    assert_eq!(
        neighbors_a.len(),
        1,
        "A's original claim to B must now resolve, without A ever being re-polled"
    );
    assert_eq!(neighbors_a[0].neighbor_device_id, device_b);
    assert!(
        neighbors_a[0].confirmed,
        "both real devices' polls claimed each other — must resolve as confirmed"
    );

    let edges = topology.resolved_edges("lldp").await.unwrap();
    assert_eq!(edges.len(), 1);
    assert!(edges[0].confirmed);
    assert_eq!(
        edges[0].upstream_device_id,
        Some(device_a),
        "device A's lower real-polled role_value must resolve it as upstream"
    );

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
