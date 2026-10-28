//! End-to-end proof of derived rate/delta metrics (2026-09-07) against a **real**
//! `discovery-devicefarm` instance (real `snmpsim-command-responder` child process, real
//! UDP SNMP wire traffic, real `discovery_snmp::RealSnmpClient`) — not `FakeSnmpClient`.
//! Drives the real `MetricPollHandler` production handler directly (same handler the
//! binary's worker pool runs), exactly like `crates/agent/tests/e2e.rs`'s in-memory tests
//! do, just with a real SNMP transport underneath instead of a mock.
//!
//! **Live-only, `#[ignore]`d — not run by normal `cargo test`** (`cargo test -- --ignored`),
//! same convention as `discovery-snmp`'s `live_get_multi_batches_when_everything_is_supported...`/
//! `live_v3_auth_priv_get_succeeds_against_devicefarm`. `discovery-devicefarm` is
//! deliberately bin-only (no library target — zero path-dependency on any discovery-*
//! crate, see its own `Cargo.toml` docstring), so this talks to it exclusively over its
//! HTTP control API (`reqwest`) — the same integration surface any external operator has.
//!
//! ## Setup (once, before running `cargo test -p discovery-agent --test live_derived_metrics -- --ignored`)
//!
//! ```bash
//! # snmpsim-command-responder must be on PATH, or pass --snmpsim-binary pointing at it —
//! # on macOS via pip --user it commonly lands at
//! # ~/Library/Python/3.9/bin/snmpsim-command-responder, not on PATH by default. There is
//! # no env var for this (verified against discovery-devicefarm's `Serve` CLI args) — the
//! # flag is the only way to override the default `snmpsim-command-responder` lookup.
//! cargo run -p discovery-devicefarm -- serve --root /tmp/devicefarm-derived-metrics-test \
//!   --bind 127.0.0.1:8097 \
//!   --snmpsim-binary ~/Library/Python/3.9/bin/snmpsim-command-responder &
//! ```
//!
//! The test creates and deletes its own virtual device (`127.0.0.1:<DEVICE_PORT>`) against
//! that running instance — no manual per-device setup needed beyond the `serve` above.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use discovery_agent::handlers::MetricPollHandler;
use discovery_core::payload::MetricPollPayload;
use discovery_core::{DeviceFacts, MetricValue, QueueKind, SnmpAuth, SnmpVersion};
use discovery_devices::{
    DeviceMetricsStore, DeviceStore, SeaOrmDeviceMetricsStore, SeaOrmDeviceStore,
};
use discovery_dsl::{
    DeriveKind, MatchSection, MetricSpec, MetricsSection, ProfileFile, ProfileMatcher, ProfileMeta,
};
use discovery_queue::{JobHandler, JobQueueStore, SeaOrmJobQueueStore};
use discovery_snmp::{RealSnmpClient, SnmpClient};

const DEVICEFARM_BASE: &str = "http://127.0.0.1:8097";
const DEVICE_PORT: u16 = 12699;
const COUNTER_OID: &str = "1.3.6.1.4.1.99999.1.0";
const METRIC_NAME: &str = "traffic_counter";

fn devicefarm_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

/// `PUT /api/devices/:ip/oids/:oid` — the exact live-edit endpoint the devicefarm UI uses,
/// see `discovery_devicefarm`'s (unreachable from here — bin-only) `web::update_oid` docs:
/// restart-free, picked up by `snmpsim` on the very next request via its own mtime-check
/// reload, no signal/restart involved.
async fn put_counter_value(http: &reqwest::Client, value: &str) {
    let resp = http
        .put(format!("{DEVICEFARM_BASE}/api/devices/127.0.0.1/oids/{COUNTER_OID}"))
        .json(&serde_json::json!({"label": METRIC_NAME, "tag": "Counter32", "value": value}))
        .send()
        .await
        .expect("PUT .../oids/:oid — is discovery-devicefarm actually running on 127.0.0.1:8097? See this file's module docs for the setup command.");
    assert!(
        resp.status().is_success(),
        "unexpected status updating counter: {}",
        resp.status()
    );
}

/// Retries `client.get` against the real device until it succeeds or `deadline` passes —
/// needed because `create_device` below triggers `ProcessSupervisor`'s ~1s-debounced
/// restart of the real `snmpsim-command-responder` child; the very first request right
/// after creating the device can land before that child has actually finished starting up
/// and bound its UDP socket.
async fn wait_until_device_answers(
    snmp: &RealSnmpClient,
    target: &discovery_core::DeviceTarget,
    deadline: std::time::Instant,
) {
    loop {
        if snmp.get(target, COUNTER_OID).await.is_ok() {
            return;
        }
        if std::time::Instant::now() >= deadline {
            panic!("device at {}:{} never answered SNMP within the deadline — is discovery-devicefarm running (see this file's module docs)?", target.ip, target.port);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Retries a real SNMP `get` until it reflects `expected` or `deadline` passes, without
/// re-sending anything — used only for the post-creation readiness check below, where
/// `create_device`'s own full process restart (not a live in-place edit) is the mechanism
/// bringing the value up to date, so there's nothing productive to re-nudge if it's slow.
/// See `set_counter_value_and_wait`'s docs for why a live *edit* needs a stronger retry.
async fn wait_until_value_matches(
    snmp: &RealSnmpClient,
    target: &discovery_core::DeviceTarget,
    expected: i64,
    deadline: std::time::Instant,
) {
    loop {
        if let Ok(v) = snmp.get(target, COUNTER_OID).await {
            if v.as_i64() == Some(expected) {
                return;
            }
        }
        if std::time::Instant::now() >= deadline {
            panic!("device at {}:{} never reported the created counter value ({expected}) within the deadline", target.ip, target.port);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Sets the counter to `value` and doesn't return until a real SNMP `get` actually reflects
/// it (or `deadline` passes) — a real bug in the *test harness's dependency*, found live
/// 2026-09-07 and root-caused, not just papered over with a longer sleep: `discovery-
/// devicefarm`'s write path (`update_one_oid`/`write_snmprec`) writes-then-atomically-
/// renames the `.snmprec` file every time, confirmed correct on disk (checked with `stat`
/// mid-failure: fresh nanosecond-precision mtime, right content) — but `snmpsim-command-
/// responder`'s *own* mtime-based reload occasionally misses that change and keeps serving
/// the previous value **indefinitely** (confirmed against a plain `snmpget` CLI too, ruling
/// out anything in this project's `async-snmp`-based client: it's snmpsim itself, wedged).
/// Confirmed empirically that a second, identical PUT — forcing another write+rename, i.e.
/// another fresh mtime for snmpsim to notice — reliably un-wedges it. So: poll for the
/// expected value, and if it hasn't shown up after `nudge_after`, re-issue the PUT (any
/// number of times, until `deadline`) rather than trusting the first one blindly.
async fn set_counter_value_and_wait(
    http: &reqwest::Client,
    snmp: &RealSnmpClient,
    target: &discovery_core::DeviceTarget,
    value: &str,
    expected: i64,
    deadline: std::time::Instant,
) {
    const NUDGE_AFTER: Duration = Duration::from_millis(800);
    put_counter_value(http, value).await;
    let mut next_nudge = std::time::Instant::now() + NUDGE_AFTER;
    loop {
        if let Ok(v) = snmp.get(target, COUNTER_OID).await {
            if v.as_i64() == Some(expected) {
                return;
            }
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            panic!("device at {}:{} never reported the updated counter value ({expected}) within the deadline, even after re-nudging snmpsim with repeated PUTs — is it wedged for real this time?", target.ip, target.port);
        }
        if now >= next_nudge {
            put_counter_value(http, value).await;
            next_nudge = now + NUDGE_AFTER;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn derive_profile() -> ProfileFile {
    let mut poll = BTreeMap::new();
    poll.insert(
        METRIC_NAME.to_string(),
        MetricSpec::Detailed {
            oid: COUNTER_OID.to_string(),
            columns: None,
            schedule: None,
            history_retention_secs: None,
            enabled: true,
            history_keep_last_success: true,
            history_keep_last_attempt: true,
            derive: Some(DeriveKind::Rate),
        },
    );
    ProfileFile {
        profile: ProfileMeta {
            name: "derived_metrics_live_test".into(),
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

/// The real proof, end to end: a raw `Counter32` genuinely increasing across two real SNMP
/// polls (real wire traffic, real `snmpsim`) produces a real, positive `traffic_counter_rate`
/// — and a subsequent genuine *decrease* (simulating a device reboot resetting the counter)
/// produces none, leaving the last good rate frozen rather than a nonsensical negative one.
#[tokio::test]
#[ignore]
async fn a_real_increasing_counter_produces_a_real_rate_and_a_reset_is_skipped_not_guessed() {
    let http = devicefarm_client();

    // ---- Create the virtual device: one Counter32 OID, starting at 1000 ----
    let create_resp = http
        .post(format!("{DEVICEFARM_BASE}/api/devices"))
        .json(&serde_json::json!({
            "ip": "127.0.0.1",
            "port": DEVICE_PORT,
            "community": "public",
            "snmp_version": "v2c",
            "oids": [
                {"label": METRIC_NAME, "oid": COUNTER_OID, "tag": "Counter32", "value": "1000"}
            ]
        }))
        .send()
        .await
        .expect("POST /api/devices — is discovery-devicefarm actually running on 127.0.0.1:8097? See this file's module docs for the setup command.");
    assert!(
        create_resp.status().is_success(),
        "unexpected status creating device: {}",
        create_resp.status()
    );

    // Shared (not a second independent instance) with the handler below — found live
    // (2026-09-07) that having this test's own readiness-check client and the handler's
    // polling client as two separate `RealSnmpClient`s hitting the same simulated device
    // in close succession made the second counter transition (1500 -> 200) hang forever
    // waiting for propagation, well past any reload latency `snmpsim` should ever need;
    // one real poller (as any real deployment actually has) doesn't hit this.
    let snmp = Arc::new(RealSnmpClient::new());
    let target = discovery_core::DeviceTarget {
        ip: "127.0.0.1".into(),
        port: DEVICE_PORT,
        auth: SnmpAuth::Community {
            version: SnmpVersion::V2c,
            community: "public".into(),
        },
        timeout_ms: 1000,
        retries: 2,
    };

    // `create_device` restarts the real snmpsim child (debounced ~1s) — give it up to 10s
    // total to actually come up and start answering before we start timing poll ticks.
    wait_until_device_answers(
        &snmp,
        &target,
        std::time::Instant::now() + Duration::from_secs(10),
    )
    .await;
    // "Answers" alone isn't enough: a *stale* child from a leftover device on the same
    // IP:port (e.g. an earlier run's device that didn't get cleaned up) can still be
    // serving right up until the debounced restart above actually lands, and it answers
    // SNMP requests just fine while doing so — found live (2026-09-07) as an intermittent
    // "raw counter must have polled for real over the wire" failure on tick 1, expected
    // 1000 got 200 (the *previous* run's final value). Wait for the value this device was
    // actually created with, not just for any response.
    wait_until_value_matches(
        &snmp,
        &target,
        1000,
        std::time::Instant::now() + Duration::from_secs(10),
    )
    .await;

    // ---- Wire the real production MetricPollHandler, in-memory sqlite for everything else ----
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
    let matcher = Arc::new(ProfileMatcher::new(vec![derive_profile()]));

    let (device_id, _) = devices
        .resolve(DeviceFacts {
            ip: "127.0.0.1".into(),
        })
        .await
        .unwrap();
    devices
        .set_snmp_credentials(
            device_id,
            discovery_core::SnmpCredentials {
                auth: target.auth.clone(),
                port: DEVICE_PORT,
            },
        )
        .await
        .unwrap();
    devices
        .apply_profile_if_changed(device_id, "derived_metrics_live_test", "test")
        .await
        .unwrap();

    let last_polled = Arc::new(dashmap::DashMap::new());
    let last_polled_date = Arc::new(dashmap::DashMap::new());
    let handler = MetricPollHandler {
        store: store.clone(),
        snmp: snmp.clone(),
        cli: Arc::new(discovery_ssh::FakeCliClient::new()),
        devices: devices.clone(),
        device_metrics: device_metrics.clone(),
        matcher,
        settings: Arc::new(
            discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests().await,
        ),
        last_polled: last_polled.clone(),
        last_polled_date: last_polled_date.clone(),
        discovery_configs: Arc::new(
            discovery_config_store::SeaOrmDiscoveryConfigStore::new_in_memory_for_tests().await,
        ),
        pruned_generations: Arc::new(dashmap::DashMap::new()),
        topology_rules: Arc::new(
            discovery_config_store::SeaOrmTopologyRuleStore::new_in_memory_for_tests().await,
        ),
    };

    async fn tick(
        store: &Arc<dyn JobQueueStore>,
        handler: &MetricPollHandler,
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
        handler.handle(job).await.unwrap();
    }

    // Forces the metric "due" again right now, bypassing the default poll interval —
    // same backdating technique `handlers.rs`'s own
    // `editing_a_metrics_schedule_in_the_profile_changes_the_actual_poll_cadence` test uses,
    // see its docs for why this is preferred over a real multi-minute sleep.
    fn force_due_now(
        last_polled: &dashmap::DashMap<(uuid::Uuid, String), tokio::time::Instant>,
        device_id: uuid::Uuid,
    ) {
        last_polled.insert(
            (device_id, METRIC_NAME.to_string()),
            tokio::time::Instant::now() - Duration::from_secs(3600),
        );
    }

    // ---- Tick 1: first-ever sample — real counter = 1000, no derived value yet ----
    tick(&store, &handler, device_id).await;
    let metrics = device_metrics.get_metrics(device_id).await.unwrap();
    assert_eq!(
        metrics.get(METRIC_NAME),
        Some(&MetricValue::Int(1000)),
        "raw counter must have polled for real over the wire"
    );
    assert_eq!(
        metrics.get("traffic_counter_rate"),
        None,
        "first-ever sample must not produce a derived value"
    );

    // ---- Real counter genuinely increases (real device edit, real elapsed wall-clock time) ----
    set_counter_value_and_wait(
        &http,
        &snmp,
        &target,
        "1500",
        1500,
        std::time::Instant::now() + Duration::from_secs(15),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    force_due_now(&last_polled, device_id);
    tick(&store, &handler, device_id).await;

    let metrics = device_metrics.get_metrics(device_id).await.unwrap();
    assert_eq!(
        metrics.get(METRIC_NAME),
        Some(&MetricValue::Int(1500)),
        "raw counter must reflect the real updated value"
    );
    let rate_after_increase = match metrics.get("traffic_counter_rate") {
        Some(MetricValue::Float(v)) => *v,
        other => {
            panic!("expected a real computed Float rate after a genuine increase, got {other:?}")
        }
    };
    assert!(rate_after_increase > 0.0, "counter genuinely increased by 500 over real elapsed time — rate must be positive, got {rate_after_increase}");
    // Loose sanity bound, not a pinned exact value — real wall-clock elapsed time varies
    // run to run (scheduling jitter, CI load); the exact-arithmetic case is already pinned
    // deterministically by discovery_dsl::derive_metric's unit tests. ~500/0.6s ballpark is
    // ~833/s; anything wildly outside a generous envelope would indicate broken math, not
    // just timing noise.
    assert!(
        rate_after_increase < 100_000.0,
        "rate is implausibly large for a real ~500-unit increase over ~0.6s: {rate_after_increase}"
    );

    // ---- Real counter genuinely decreases (simulates a device reboot resetting to ~0) ----
    set_counter_value_and_wait(
        &http,
        &snmp,
        &target,
        "200",
        200,
        std::time::Instant::now() + Duration::from_secs(15),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    force_due_now(&last_polled, device_id);
    tick(&store, &handler, device_id).await;

    let metrics = device_metrics.get_metrics(device_id).await.unwrap();
    assert_eq!(
        metrics.get(METRIC_NAME),
        Some(&MetricValue::Int(200)),
        "raw counter must still reflect the real (decreased) value — only the derived metric skips"
    );
    let rate_after_reset = match metrics.get("traffic_counter_rate") {
        Some(MetricValue::Float(v)) => *v,
        other => {
            panic!("expected the derived metric to still be present, unchanged, not {other:?}")
        }
    };
    assert_eq!(rate_after_reset, rate_after_increase, "a genuine decrease (wrap/reset) must be skipped entirely, not guessed — the derived value stays frozen at its last real computation, never goes negative");

    // ---- Cleanup ----
    let _ = http
        .delete(format!("{DEVICEFARM_BASE}/api/devices/127.0.0.1"))
        .send()
        .await;
}
