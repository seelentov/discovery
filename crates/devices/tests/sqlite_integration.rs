//! Integration tests for `SeaOrmDeviceStore`/`SeaOrmDeviceMetricsStore` against a real,
//! in-process SQLite database — proves the sea-orm query-builder path (the `set_reachability`
//! `ping_failing_since` three-way transition, `delete_unreachable_since`'s bulk condition,
//! `record_metric_polls`'s "state run" dedup, the cross-store cascade delete added by the
//! 2026-08-18 `DeviceStore`/`DeviceMetricsStore` domain split) actually runs correctly
//! through `sqlx`'s SQLite driver, not just against each crate's own `#[cfg(test)]` module.
//!
//! **`discovery_migration::connect_in_memory_for_tests` is shared across all three stores
//! here (devices/device_metrics/alerts)** — in this fixture there's only one database, so
//! "which physical connection" is moot; production wiring (`main.rs`'s `build_stores`, via
//! `discovery-db::ConnectionRegistry`) passes whichever connection each domain actually
//! resolved to, possibly three different ones. `SeaOrmDeviceStore::new_in_memory_for_tests`
//! already does exactly this same wiring — used directly wherever a test doesn't also need
//! its own handle on the `device_metrics`/`alerts` stores.

use chrono::Utc;
use discovery_alerts::{AlertStore, SeaOrmAlertStore};
use discovery_core::{
    Alert, AlertLevel, AlertState, Device, DeviceFacts, MetricPollOutcome, MetricValue, SshAuth,
    SshCredentials,
};
use discovery_devices::{
    self as devices_crate, DeviceMetricsStore, DeviceStore, ProfileDecision,
    SeaOrmDeviceMetricsStore, SeaOrmDeviceStore,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use uuid::Uuid;

fn generation_of(decision: ProfileDecision) -> u64 {
    match decision {
        ProfileDecision::Unchanged { generation } | ProfileDecision::Changed { generation } => {
            generation
        }
    }
}

fn facts(ip: &str) -> DeviceFacts {
    DeviceFacts { ip: ip.to_string() }
}

/// Every test that only exercises `DeviceStore` methods uses this — the same wiring
/// `SeaOrmDeviceStore::new_in_memory_for_tests` does internally.
async fn device_store() -> SeaOrmDeviceStore {
    SeaOrmDeviceStore::new_in_memory_for_tests().await
}

/// Tests that also need direct `DeviceMetricsStore`/`AlertStore` calls build all three by
/// hand, sharing one connection, so they can reach into all of them.
async fn all_stores() -> (
    SeaOrmDeviceStore,
    Arc<dyn DeviceMetricsStore>,
    Arc<dyn AlertStore>,
) {
    let db = discovery_migration::connect_in_memory_for_tests().await;
    let device_metrics: Arc<dyn DeviceMetricsStore> =
        Arc::new(SeaOrmDeviceMetricsStore::new(db.clone()));
    let alerts: Arc<dyn AlertStore> = Arc::new(SeaOrmAlertStore::new(db.clone()));
    let devices = SeaOrmDeviceStore::new(db, device_metrics.clone(), alerts.clone());
    (devices, device_metrics, alerts)
}

/// Like [`device_store`], but with an at-rest encryption key configured — `set_ssh_credentials`
/// (like `SnmpAuth::UsmV3`) requires one, see `discovery_core::secret::SecretKey`'s docs.
async fn device_store_with_secret_key() -> SeaOrmDeviceStore {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use discovery_core::secret::SecretKey;

    let db = discovery_migration::connect_in_memory_for_tests().await;
    let device_metrics: Arc<dyn DeviceMetricsStore> =
        Arc::new(SeaOrmDeviceMetricsStore::new(db.clone()));
    let alerts: Arc<dyn AlertStore> = Arc::new(SeaOrmAlertStore::new(db.clone()));
    let key = Arc::new(SecretKey::from_base64(&STANDARD.encode([9u8; 32])).unwrap());
    SeaOrmDeviceStore::new(db, device_metrics, alerts).with_secret_key(key)
}

#[tokio::test]
async fn resolve_is_idempotent_per_ip_and_survives_a_reconnect() {
    let store = device_store().await;
    let (id1, is_new1) = store.resolve(facts("10.0.0.1")).await.unwrap();
    assert!(is_new1);
    let (id2, is_new2) = store.resolve(facts("10.0.0.1")).await.unwrap();
    assert_eq!(id1, id2, "the same IP must resolve to the same device id");
    assert!(
        !is_new2,
        "the second resolve of the same IP is not a new device"
    );

    let (id3, is_new3) = store.resolve(facts("10.0.0.2")).await.unwrap();
    assert!(is_new3);
    assert_ne!(id1, id3, "a different IP must be a different device");
}

#[tokio::test]
async fn apply_profile_if_changed_bumps_generation_only_on_a_real_change() {
    let store = device_store().await;
    let (id, _) = store.resolve(facts("10.0.0.1")).await.unwrap();

    let first = store
        .apply_profile_if_changed(id, "generic_switch", "v1")
        .await
        .unwrap()
        .unwrap();
    let gen1 = generation_of(first);

    let unchanged = store
        .apply_profile_if_changed(id, "generic_switch", "v1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        generation_of(unchanged),
        gen1,
        "same (name, version) must not bump the generation"
    );

    let changed = store
        .apply_profile_if_changed(id, "generic_switch", "v2")
        .await
        .unwrap()
        .unwrap();
    assert!(
        generation_of(changed) > gen1,
        "a version-only change (same name) must still bump the generation"
    );

    let device = store.get_device(id).await.unwrap().unwrap();
    assert_eq!(device.profile.as_deref(), Some("generic_switch"));
}

#[tokio::test]
async fn record_metric_polls_merges_without_wiping_other_metrics_and_history_dedupes_repeats() {
    let (devices, device_metrics, _alerts) = all_stores().await;
    let (id, _) = devices.resolve(facts("10.0.0.1")).await.unwrap();

    let mut first: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
    first.insert(
        "sys_descr".into(),
        MetricPollOutcome::Ok(MetricValue::Str("Cisco Switch".into())),
    );
    device_metrics
        .record_metric_polls(id, &first)
        .await
        .unwrap();

    // A second, disjoint metric name must not wipe the first — `record_metric_polls` is a
    // merge, not a replace.
    let mut second: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
    second.insert(
        "uptime".into(),
        MetricPollOutcome::Ok(MetricValue::Int(12345)),
    );
    device_metrics
        .record_metric_polls(id, &second)
        .await
        .unwrap();

    let metrics = device_metrics.get_metrics(id).await.unwrap();
    assert!(
        metrics.0.contains_key("sys_descr"),
        "an unrelated later write must not remove an earlier metric"
    );
    assert!(metrics.0.contains_key("uptime"));

    // Repeating the exact same value must not grow history — one run, `last_observed_at`
    // advances in place (the "state run" model this table is built on).
    for _ in 0..3 {
        device_metrics
            .record_metric_polls(id, &second)
            .await
            .unwrap();
    }
    let history = device_metrics
        .metric_history(id, "uptime", 50, 0, None, None)
        .await
        .unwrap();
    assert_eq!(
        history.total, 1,
        "repeating an identical value must collapse into a single history run, not grow it"
    );

    // A genuinely different value opens a new run.
    let mut third: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
    third.insert(
        "uptime".into(),
        MetricPollOutcome::Ok(MetricValue::Int(99999)),
    );
    device_metrics
        .record_metric_polls(id, &third)
        .await
        .unwrap();
    let history = device_metrics
        .metric_history(id, "uptime", 50, 0, None, None)
        .await
        .unwrap();
    assert_eq!(
        history.total, 2,
        "a real value change must start a second history run"
    );
}

/// Direct user request 2026-08-28: date-range inputs on the dashboard's metric-history
/// chart. `since`/`until` filter on `last_observed_at`, so a window that starts after the
/// only run's timestamp (or ends before it) must exclude it, and a window that brackets it
/// must include it.
#[tokio::test]
async fn metric_history_since_until_filters_by_last_observed_at() {
    let (devices, device_metrics, _alerts) = all_stores().await;
    let (id, _) = devices.resolve(facts("10.0.0.1")).await.unwrap();

    let before = Utc::now();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let mut m: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
    m.insert("uptime".into(), MetricPollOutcome::Ok(MetricValue::Int(1)));
    device_metrics.record_metric_polls(id, &m).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let after = Utc::now();

    let bracketing = device_metrics
        .metric_history(id, "uptime", 50, 0, Some(before), Some(after))
        .await
        .unwrap();
    assert_eq!(
        bracketing.total, 1,
        "a window bracketing the run's timestamp must include it"
    );

    let too_early = device_metrics
        .metric_history(id, "uptime", 50, 0, None, Some(before))
        .await
        .unwrap();
    assert_eq!(
        too_early.total, 0,
        "an `until` before the run's timestamp must exclude it"
    );

    let too_late = device_metrics
        .metric_history(id, "uptime", 50, 0, Some(after), None)
        .await
        .unwrap();
    assert_eq!(
        too_late.total, 0,
        "a `since` after the run's timestamp must exclude it"
    );
}

/// Regression test for the 2026-08-18 batching rewrite of `record_metric_polls` (see that
/// method's docs) — every existing test up to this point only ever passed a single-entry
/// `BTreeMap`, which happened to exercise the exact same code path whether the old
/// per-metric loop or the new batched implementation ran it. A *multi*-metric call is the
/// one that actually stresses the new batched read (`GROUP BY` + `(name, last_observed_at)`
/// pair lookup) and batched write (`update_many`/`insert_many`) logic — in particular,
/// whether it correctly tells apart, *within the same call*, metrics whose state didn't
/// change from ones that did or are brand new.
#[tokio::test]
async fn record_metric_polls_correctly_batches_a_mix_of_unchanged_changed_and_new_metrics_in_one_call(
) {
    let (devices, device_metrics, _alerts) = all_stores().await;
    let (id, _) = devices.resolve(facts("10.0.0.1")).await.unwrap();

    let mut seed: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
    seed.insert("cpu".into(), MetricPollOutcome::Ok(MetricValue::Int(10)));
    seed.insert(
        "temperature".into(),
        MetricPollOutcome::Ok(MetricValue::Int(40)),
    );
    device_metrics.record_metric_polls(id, &seed).await.unwrap();

    // One call, three metrics with three different fates: "cpu" repeats its exact prior
    // value (must collapse into the same run), "temperature" changes (must open a new
    // run), "fan_speed" has never been seen before (must insert a first run).
    let mut mixed: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
    mixed.insert("cpu".into(), MetricPollOutcome::Ok(MetricValue::Int(10)));
    mixed.insert(
        "temperature".into(),
        MetricPollOutcome::Ok(MetricValue::Int(55)),
    );
    mixed.insert(
        "fan_speed".into(),
        MetricPollOutcome::Ok(MetricValue::Int(3000)),
    );
    device_metrics
        .record_metric_polls(id, &mixed)
        .await
        .unwrap();

    let cpu_history = device_metrics
        .metric_history(id, "cpu", 50, 0, None, None)
        .await
        .unwrap();
    assert_eq!(
        cpu_history.total, 1,
        "an unchanged value in a multi-metric batch must not open a second run"
    );

    let temp_history = device_metrics
        .metric_history(id, "temperature", 50, 0, None, None)
        .await
        .unwrap();
    assert_eq!(
        temp_history.total, 2,
        "a changed value in a multi-metric batch must open a second run"
    );

    let fan_history = device_metrics
        .metric_history(id, "fan_speed", 50, 0, None, None)
        .await
        .unwrap();
    assert_eq!(
        fan_history.total, 1,
        "a brand-new metric in a multi-metric batch must be inserted"
    );

    let metrics = device_metrics.get_metrics(id).await.unwrap();
    assert_eq!(metrics.0.get("cpu"), Some(&MetricValue::Int(10)));
    assert_eq!(metrics.0.get("temperature"), Some(&MetricValue::Int(55)));
    assert_eq!(metrics.0.get("fan_speed"), Some(&MetricValue::Int(3000)));

    // And a failure mixed in with successes in the same call: the cache's last known good
    // value/time must survive untouched, only error/last_attempt_at advance.
    let mut with_failure: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
    with_failure.insert("cpu".into(), MetricPollOutcome::Err("timeout".into()));
    with_failure.insert(
        "fan_speed".into(),
        MetricPollOutcome::Ok(MetricValue::Int(3100)),
    );
    device_metrics
        .record_metric_polls(id, &with_failure)
        .await
        .unwrap();

    let records = device_metrics.get_metric_records(id).await.unwrap();
    let cpu_record = records.iter().find(|r| r.name == "cpu").unwrap();
    assert_eq!(
        cpu_record.value,
        Some(MetricValue::Int(10)),
        "a failed poll must not blank out the last known good value"
    );
    assert_eq!(cpu_record.error.as_deref(), Some("timeout"));
    let fan_record = records.iter().find(|r| r.name == "fan_speed").unwrap();
    assert_eq!(fan_record.value, Some(MetricValue::Int(3100)));
    assert_eq!(fan_record.error, None);
}

#[tokio::test]
async fn prune_metrics_removes_only_keys_not_in_keep() {
    let (devices, device_metrics, _alerts) = all_stores().await;
    let (id, _) = devices.resolve(facts("10.0.0.1")).await.unwrap();

    let mut outcomes: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
    outcomes.insert("keep_me".into(), MetricPollOutcome::Ok(MetricValue::Int(1)));
    outcomes.insert("drop_me".into(), MetricPollOutcome::Ok(MetricValue::Int(2)));
    device_metrics
        .record_metric_polls(id, &outcomes)
        .await
        .unwrap();

    device_metrics
        .prune_metrics(id, &["keep_me".to_string()])
        .await
        .unwrap();

    let metrics = device_metrics.get_metrics(id).await.unwrap();
    assert!(metrics.0.contains_key("keep_me"));
    assert!(
        !metrics.0.contains_key("drop_me"),
        "a metric not in the keep list must actually be deleted from the SQL-backed cache"
    );
}

#[tokio::test]
async fn prune_metric_history_older_than_respects_keep_last_attempt_and_keep_last_success() {
    let (devices, device_metrics, _alerts) = all_stores().await;
    let (id, _) = devices.resolve(facts("10.0.0.1")).await.unwrap();

    let mut ok: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
    ok.insert("x".into(), MetricPollOutcome::Ok(MetricValue::Int(1)));
    device_metrics.record_metric_polls(id, &ok).await.unwrap();

    // A later error opens a second run — now the metric's *latest* row is a failure, its
    // most recent *success* is the older run.
    let mut err: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
    err.insert("x".into(), MetricPollOutcome::Err("timeout".into()));
    device_metrics.record_metric_polls(id, &err).await.unwrap();

    let future_cutoff = Utc::now() + chrono::Duration::days(1);
    let deleted = device_metrics
        .prune_metric_history_older_than("x", future_cutoff, true, true)
        .await
        .unwrap();
    assert_eq!(deleted, 0, "both runs are exempted (latest-attempt and latest-success respectively), even though both are past the cutoff");

    let history = device_metrics
        .metric_history(id, "x", 50, 0, None, None)
        .await
        .unwrap();
    assert_eq!(
        history.total, 2,
        "neither protected run was actually deleted"
    );
}

/// The riskiest, least-previously-verified SQL in this store — the three-way
/// `ping_failing_since` transition. See `discovery_core::Device::ping_failing_since`'s docs
/// for the contract this pins down: starts on the first `false`, survives repeats, clears
/// on a `true`.
#[tokio::test]
async fn set_reachability_maintains_ping_failing_since_through_the_three_way_transition() {
    let store = device_store().await;
    let (id, _) = store.resolve(facts("10.0.0.1")).await.unwrap();

    let fresh = store.get_device(id).await.unwrap().unwrap();
    assert_eq!(fresh.ping_failing_since, None);

    store
        .set_reachability(id, false, 100.0, false)
        .await
        .unwrap();
    let first_failure = store
        .get_device(id)
        .await
        .unwrap()
        .unwrap()
        .ping_failing_since;
    assert!(
        first_failure.is_some(),
        "the first observed false must start the streak"
    );

    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    store
        .set_reachability(id, false, 100.0, false)
        .await
        .unwrap();
    let second_failure = store
        .get_device(id)
        .await
        .unwrap()
        .unwrap()
        .ping_failing_since;
    assert_eq!(
        second_failure, first_failure,
        "a repeated false must not slide the streak's start forward"
    );

    store.set_reachability(id, true, 0.0, false).await.unwrap();
    assert_eq!(
        store
            .get_device(id)
            .await
            .unwrap()
            .unwrap()
            .ping_failing_since,
        None,
        "a success must clear the streak"
    );
    assert_eq!(
        store.get_device(id).await.unwrap().unwrap().ping_ok,
        Some(true)
    );
}

#[tokio::test]
async fn delete_unreachable_since_respects_enabled_and_the_cutoff() {
    let store = device_store().await;
    let (stale_id, _) = store.resolve(facts("10.0.0.1")).await.unwrap();
    let (fresh_id, _) = store.resolve(facts("10.0.0.2")).await.unwrap();
    let (parked_id, _) = store.resolve(facts("10.0.0.3")).await.unwrap();

    store
        .set_reachability(stale_id, false, 100.0, false)
        .await
        .unwrap();
    store
        .set_reachability(parked_id, false, 100.0, false)
        .await
        .unwrap();
    store.set_enabled(parked_id, false).await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let cutoff = Utc::now();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    store
        .set_reachability(fresh_id, false, 100.0, false)
        .await
        .unwrap();

    let deleted = store.delete_unreachable_since(cutoff).await.unwrap();
    assert_eq!(deleted, vec![(stale_id, "10.0.0.1".to_string())], "only the enabled device whose streak started before the cutoff must be deleted, and its id+ip must be returned");

    assert!(store.get_device(stale_id).await.unwrap().is_none());
    assert!(
        store.get_device(fresh_id).await.unwrap().is_some(),
        "streak started after the cutoff — must survive"
    );
    assert!(
        store.get_device(parked_id).await.unwrap().is_some(),
        "disabled — must survive regardless of how long it's been failing"
    );
}

#[tokio::test]
async fn set_enabled_and_bulk_set_enabled_all() {
    let store = device_store().await;
    let (id_a, _) = store.resolve(facts("10.0.0.1")).await.unwrap();
    let (id_b, _) = store.resolve(facts("10.0.0.2")).await.unwrap();
    assert!(
        store.get_device(id_a).await.unwrap().unwrap().enabled,
        "a freshly resolved device starts enabled"
    );

    store.set_enabled(id_a, false).await.unwrap();
    assert!(!store.get_device(id_a).await.unwrap().unwrap().enabled);
    assert!(
        store.get_device(id_b).await.unwrap().unwrap().enabled,
        "set_enabled must only touch the named device"
    );

    let touched = store.set_enabled_all(false).await.unwrap();
    assert_eq!(touched, 2);
    assert!(!store.get_device(id_a).await.unwrap().unwrap().enabled);
    assert!(!store.get_device(id_b).await.unwrap().unwrap().enabled);
}

#[tokio::test]
async fn metric_override_set_get_clear_round_trip() {
    let store = device_store().await;
    let (id, _) = store.resolve(facts("10.0.0.1")).await.unwrap();

    assert!(store.get_metric_overrides(id).await.unwrap().is_empty());
    store.set_metric_override(id, "cpu", false).await.unwrap();
    let overrides = store.get_metric_overrides(id).await.unwrap();
    assert_eq!(overrides.get("cpu"), Some(&false));

    store.clear_metric_override(id, "cpu").await.unwrap();
    assert!(store.get_metric_overrides(id).await.unwrap().is_empty());
}

/// **New coverage for the 2026-08-18 domain split**: `delete` used to rely on a single
/// `ON DELETE CASCADE` off `devices` for metrics/history *and* alerts. Now two of those
/// three cascades are explicit application-code calls (`DeviceMetricsStore::delete_for_device`,
/// `AlertStore::delete_for_device`) — this proves all three actually still happen, not just
/// the one (`device_metric_settings`) that's still a real DB-enforced FK.
#[tokio::test]
async fn delete_cascades_to_metrics_history_and_alerts_and_leaves_other_devices_alone() {
    let (devices, device_metrics, alerts) = all_stores().await;
    let (target, _) = devices.resolve(facts("10.0.0.1")).await.unwrap();
    let (other, _) = devices.resolve(facts("10.0.0.2")).await.unwrap();

    let mut outcomes: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
    outcomes.insert("uptime".into(), MetricPollOutcome::Ok(MetricValue::Int(1)));
    device_metrics
        .record_metric_polls(target, &outcomes)
        .await
        .unwrap();
    device_metrics
        .record_metric_polls(other, &outcomes)
        .await
        .unwrap();

    devices
        .set_metric_override(target, "uptime", false)
        .await
        .unwrap();

    let now = Utc::now();
    let target_alert = Alert {
        details: Default::default(),
        id: Uuid::new_v4(),
        device_id: target,
        device_ip: "10.0.0.1".into(),
        name: "high_cpu".into(),
        row_key: None,
        level: AlertLevel::Warning,
        message: "test".into(),
        state: AlertState::Active,
        facts: None,
        first_seen: now,
        last_seen: now,
        cleared_at: None,
        closed_by: None,
        acknowledged_by: None,
        acknowledged_at: None,
        snoozed_until: None,
        snoozed_by: None,
        auto_clear_reason: None,
        repeat_count: 0,
        escalation_level: 0,
        repeated_at: None,
        escalation_reason: None,
        flapping: false,
        suppression_reason: None,
        comment_count: 0,
        suppressed_by_alert_id: None,
        reopened_from_alert_id: None,
    };
    let mut other_alert = target_alert.clone();
    other_alert.id = Uuid::new_v4();
    other_alert.device_id = other;
    other_alert.device_ip = "10.0.0.2".into();
    alerts.upsert(&target_alert).await.unwrap();
    alerts.upsert(&other_alert).await.unwrap();

    devices.delete(target).await.unwrap();

    assert!(devices.get_device(target).await.unwrap().is_none());
    assert_eq!(
        device_metrics
            .metric_history(target, "uptime", 50, 0, None, None)
            .await
            .unwrap()
            .total,
        0,
        "history for the deleted device must be gone too"
    );
    assert!(
        devices
            .get_metric_overrides(target)
            .await
            .unwrap()
            .is_empty(),
        "overrides for the deleted device must be gone too (real FK cascade)"
    );
    assert!(
        alerts.get(target_alert.id).await.unwrap().is_none(),
        "alerts for the deleted device must be gone too (explicit cascade)"
    );

    assert!(
        devices.get_device(other).await.unwrap().is_some(),
        "deleting one device must not touch another"
    );
    assert_eq!(
        device_metrics
            .metric_history(other, "uptime", 50, 0, None, None)
            .await
            .unwrap()
            .total,
        1,
        "the other device's history must survive"
    );
    assert!(
        alerts.get(other_alert.id).await.unwrap().is_some(),
        "the other device's alerts must survive"
    );

    // Deleting an already-gone id is a documented no-op, not an error.
    devices.delete(target).await.unwrap();
}

/// **New coverage for 2026-09-16's topology mechanism**: unlike `device_metrics`/`alerts`,
/// the `topology` cascade is opt-in (`SeaOrmDeviceStore::with_topology`) — a store that
/// never calls it (every other test in this file) must keep working unchanged, and one
/// that does must actually clean up `topology_device_keys`/`topology_claims` on delete.
#[tokio::test]
async fn delete_cascades_to_topology_when_with_topology_is_configured() {
    use discovery_topology::{SeaOrmTopologyStore, TopologyStore};

    let db = discovery_migration::connect_in_memory_for_tests().await;
    let device_metrics: Arc<dyn DeviceMetricsStore> =
        Arc::new(SeaOrmDeviceMetricsStore::new(db.clone()));
    let alerts: Arc<dyn AlertStore> = Arc::new(SeaOrmAlertStore::new(db.clone()));
    let topology: Arc<dyn TopologyStore> = Arc::new(SeaOrmTopologyStore::new(db.clone()));
    let devices = SeaOrmDeviceStore::new(db.clone(), device_metrics.clone(), alerts.clone())
        .with_topology(topology.clone());

    // A bare `topology_rules` row, written directly via the entity — mirrors
    // `discovery-topology`'s own test support, avoiding a `discovery-config-store`
    // dependency in this crate just for one FK target row.
    {
        use sea_orm::{ActiveValue::Set, EntityTrait};
        let now = Utc::now();
        let am = discovery_entities::topology_rules::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set("lldp".to_string()),
            enabled: Set(true),
            my_key_expression: Set("metrics.key".to_string()),
            claimed_neighbors_expression: Set(None),
            rank_expression: Set(None),
            watched_metrics: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        };
        discovery_entities::topology_rules::Entity::insert(am)
            .exec(&db)
            .await
            .unwrap();
    }

    let (target, _) = devices.resolve(facts("10.0.0.3")).await.unwrap();
    let (other, _) = devices.resolve(facts("10.0.0.4")).await.unwrap();
    topology
        .apply_recompute(
            "lldp",
            target,
            Some("key-target".to_string()),
            vec!["key-other".to_string()],
            None,
        )
        .await
        .unwrap();
    topology
        .apply_recompute(
            "lldp",
            other,
            Some("key-other".to_string()),
            vec!["key-target".to_string()],
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        topology.neighbors_of("lldp", target).await.unwrap().len(),
        1
    );

    devices.delete(target).await.unwrap();

    assert!(
        topology
            .neighbors_of("lldp", target)
            .await
            .unwrap()
            .is_empty(),
        "the deleted device's own key/claims must be gone"
    );
    assert!(
        topology
            .neighbors_of("lldp", other)
            .await
            .unwrap()
            .is_empty(),
        "the survivor's claim to the deleted device must no longer resolve to anything"
    );
}

/// `Device` isn't `Clone`-inspectable field-by-field from outside this crate in a way
/// that would catch a forgotten field in `model_to_device` (a new column silently reading
/// back as its type default instead of erroring) — this asserts the full round trip for
/// every reachability-related field at once, the exact shape a future column addition
/// would need to keep intact.
#[tokio::test]
async fn full_device_round_trip_after_reachability_writes() {
    let store = device_store().await;
    let (id, _) = store.resolve(facts("10.0.0.1")).await.unwrap();
    store.set_reachability(id, true, 0.0, true).await.unwrap();

    let device: Device = store.get_device(id).await.unwrap().unwrap();
    assert_eq!(device.facts.ip, "10.0.0.1");
    assert_eq!(device.ping_ok, Some(true));
    assert_eq!(device.snmp_ok, Some(true));
    assert!(device.ping_checked_at.is_some());
    assert!(device.snmp_checked_at.is_some());
    assert_eq!(device.ping_failing_since, None);
    assert!(device.enabled);
}

/// A freshly-resolved device has no SSH credentials at all (mirrors `snmp_credentials`'
/// `None`-until-negotiated default, except SSH's `None` persists until a manual
/// `set_ssh_credentials` call — see `discovery_core::SshCredentials`'s docs for why there's
/// no automatic negotiation to fill this in the way there is for SNMP).
#[tokio::test]
async fn ssh_credentials_default_to_none_and_round_trip_once_set() {
    let store = device_store_with_secret_key().await;
    let (id, _) = store.resolve(facts("10.0.0.5")).await.unwrap();

    let device = store.get_device(id).await.unwrap().unwrap();
    assert!(
        device.ssh_credentials.is_none(),
        "a freshly-resolved device must have no SSH credentials until manually configured"
    );

    let creds = SshCredentials {
        username: "admin".to_string(),
        auth: SshAuth::Password {
            password: "hunter2".to_string(),
        },
        port: 2222,
        known_host_key: None,
    };
    store.set_ssh_credentials(id, creds.clone()).await.unwrap();

    let device = store.get_device(id).await.unwrap().unwrap();
    let stored = device
        .ssh_credentials
        .expect("set_ssh_credentials must persist a retrievable credential");
    assert_eq!(stored.username, "admin");
    assert_eq!(stored.port, 2222);
    assert_eq!(
        stored.auth,
        SshAuth::Password {
            password: "hunter2".to_string()
        }
    );
    assert_eq!(stored.known_host_key, None, "a freshly-set credential has no pinned host key yet — trust-on-first-use pins it on the next successful connection");
}

/// `pin_ssh_host_key` — CWE-295 fix, trust-on-first-use pinning: the first fingerprint
/// offered for a device with no pin yet must be written and readable back.
#[tokio::test]
async fn pin_ssh_host_key_writes_the_first_fingerprint_for_a_device() {
    let store = device_store_with_secret_key().await;
    let (id, _) = store.resolve(facts("10.0.0.8")).await.unwrap();
    store
        .set_ssh_credentials(
            id,
            SshCredentials {
                username: "admin".to_string(),
                auth: SshAuth::Password {
                    password: "hunter2".to_string(),
                },
                port: 22,
                known_host_key: None,
            },
        )
        .await
        .unwrap();

    store
        .pin_ssh_host_key(id, "SHA256:first".to_string())
        .await
        .unwrap();

    let device = store.get_device(id).await.unwrap().unwrap();
    assert_eq!(
        device.ssh_credentials.unwrap().known_host_key.as_deref(),
        Some("SHA256:first")
    );
}

/// **The other half of the CWE-295 fix's persistence contract**: once a fingerprint is
/// pinned, `pin_ssh_host_key` must never silently overwrite it with a different one — a
/// mismatch is `discovery_ssh::CliClient::exec`'s job to refuse outright, not this
/// method's job to quietly paper over by re-pinning. This is what makes a genuine host-key
/// rotation (or a MITM) a hard, visible failure instead of a silent drift.
#[tokio::test]
async fn pin_ssh_host_key_does_not_overwrite_an_already_pinned_fingerprint() {
    let store = device_store_with_secret_key().await;
    let (id, _) = store.resolve(facts("10.0.0.9")).await.unwrap();
    store
        .set_ssh_credentials(
            id,
            SshCredentials {
                username: "admin".to_string(),
                auth: SshAuth::Password {
                    password: "hunter2".to_string(),
                },
                port: 22,
                known_host_key: None,
            },
        )
        .await
        .unwrap();

    store
        .pin_ssh_host_key(id, "SHA256:first".to_string())
        .await
        .unwrap();
    store
        .pin_ssh_host_key(id, "SHA256:different".to_string())
        .await
        .unwrap();

    let device = store.get_device(id).await.unwrap().unwrap();
    assert_eq!(
        device.ssh_credentials.unwrap().known_host_key.as_deref(),
        Some("SHA256:first"),
        "an already-pinned fingerprint must never be silently replaced"
    );
}

/// Rotating a device's SSH credentials via `set_ssh_credentials` resets any previously
/// pinned host key back to unpinned — see `discovery_core::SshCredentials::known_host_key`'s
/// docs for why: an operator who legitimately rotates a device's host key alongside its
/// credentials gets a fresh trust-on-first-use pin on the next connection instead of a
/// permanent lockout from the old fingerprint.
#[tokio::test]
async fn set_ssh_credentials_resets_a_previously_pinned_host_key() {
    let store = device_store_with_secret_key().await;
    let (id, _) = store.resolve(facts("10.0.0.10")).await.unwrap();
    store
        .set_ssh_credentials(
            id,
            SshCredentials {
                username: "admin".to_string(),
                auth: SshAuth::Password {
                    password: "hunter2".to_string(),
                },
                port: 22,
                known_host_key: None,
            },
        )
        .await
        .unwrap();
    store
        .pin_ssh_host_key(id, "SHA256:old".to_string())
        .await
        .unwrap();

    store
        .set_ssh_credentials(
            id,
            SshCredentials {
                username: "admin".to_string(),
                auth: SshAuth::Password {
                    password: "new-password".to_string(),
                },
                port: 22,
                known_host_key: None,
            },
        )
        .await
        .unwrap();

    let device = store.get_device(id).await.unwrap().unwrap();
    assert_eq!(device.ssh_credentials.unwrap().known_host_key, None, "rotating credentials must reset the pin, not leave the old fingerprint attached to new credentials");
}

/// `set_ssh_credentials` on an id that doesn't exist must be a harmless no-op, same
/// contract `set_snmp_credentials`/`set_reachability` already document.
#[tokio::test]
async fn set_ssh_credentials_on_an_unknown_device_is_a_noop() {
    let store = device_store_with_secret_key().await;
    let creds = SshCredentials {
        username: "admin".to_string(),
        auth: SshAuth::Password {
            password: "x".to_string(),
        },
        port: 22,
        known_host_key: None,
    };
    store
        .set_ssh_credentials(Uuid::new_v4(), creds)
        .await
        .unwrap();
}

/// Unlike `SnmpAuth::Community`, SSH has no plaintext-ok branch — `set_ssh_credentials`
/// must fail loudly, not silently write plaintext, when no `DISCOVERY_SECRET_KEY`-equivalent
/// is configured on the store.
#[tokio::test]
async fn set_ssh_credentials_without_a_secret_key_fails_instead_of_writing_plaintext() {
    let store = device_store().await;
    let (id, _) = store.resolve(facts("10.0.0.6")).await.unwrap();
    let creds = SshCredentials {
        username: "admin".to_string(),
        auth: SshAuth::Password {
            password: "hunter2".to_string(),
        },
        port: 22,
        known_host_key: None,
    };
    assert!(store.set_ssh_credentials(id, creds).await.is_err());
}

/// The point of `discovery_core::secret`'s encrypt-at-rest boundary, SSH edition: a
/// password must round-trip correctly through a store configured with a key **and** the
/// actual row sitting in the DB must not contain that plaintext anywhere — checked by
/// reading the raw `devices.ssh_auth` JSON directly, not just trusting the store's own
/// decrypt path to prove itself. Mirrors `discovery_config_store`'s
/// `usm_v3_passphrases_are_ciphertext_in_the_db_and_round_trip_through_the_store`.
#[tokio::test]
async fn ssh_password_is_ciphertext_in_the_db_and_round_trips_through_the_store() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use discovery_core::secret::SecretKey;
    use sea_orm::EntityTrait;

    let db = discovery_migration::connect_in_memory_for_tests().await;
    let device_metrics: Arc<dyn DeviceMetricsStore> =
        Arc::new(SeaOrmDeviceMetricsStore::new(db.clone()));
    let alerts: Arc<dyn AlertStore> = Arc::new(SeaOrmAlertStore::new(db.clone()));
    let key = Arc::new(SecretKey::from_base64(&STANDARD.encode([9u8; 32])).unwrap());
    let store = SeaOrmDeviceStore::new(db.clone(), device_metrics, alerts).with_secret_key(key);

    let (id, _) = store.resolve(facts("10.0.0.7")).await.unwrap();
    let creds = SshCredentials {
        username: "admin".to_string(),
        auth: SshAuth::Password {
            password: "hunter2".to_string(),
        },
        port: 22,
        known_host_key: None,
    };
    store.set_ssh_credentials(id, creds).await.unwrap();

    let device = store.get_device(id).await.unwrap().unwrap();
    assert_eq!(
        device.ssh_credentials.unwrap().auth,
        SshAuth::Password {
            password: "hunter2".to_string()
        },
        "the store's own decrypt path must return the original plaintext"
    );

    // Raw row, bypassing the store's own decrypt path entirely.
    let raw_row = discovery_entities::devices::Entity::find_by_id(id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    let raw_json = raw_row.ssh_auth.unwrap().to_string();
    assert!(
        !raw_json.contains("hunter2"),
        "the SSH password must not be readable in the raw DB row: {raw_json}"
    );
}

/// The free composition function `discovery_devices::all_with_metrics` replaces what used
/// to be a single-store SQL `JOIN` — this proves the two-round-trip composition actually
/// zips devices, their metric records, *and* their overrides back together correctly.
#[tokio::test]
async fn all_with_metrics_composes_devices_records_and_overrides_across_both_stores() {
    let (devices, device_metrics, _alerts) = all_stores().await;
    let (id_a, _) = devices.resolve(facts("10.0.0.1")).await.unwrap();
    devices.resolve(facts("10.0.0.2")).await.unwrap();

    let mut outcomes: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
    outcomes.insert("uptime".into(), MetricPollOutcome::Ok(MetricValue::Int(42)));
    device_metrics
        .record_metric_polls(id_a, &outcomes)
        .await
        .unwrap();
    devices
        .set_metric_override(id_a, "uptime", false)
        .await
        .unwrap();
    // `id_b` gets no metrics at all — must still show up with an empty record list, not be
    // dropped from the result.

    let mut result = devices_crate::all_with_metrics(&devices, device_metrics.as_ref())
        .await
        .unwrap();
    result.sort_by(|(a, _), (b, _)| a.facts.ip.cmp(&b.facts.ip));
    assert_eq!(result.len(), 2);

    let (device_a, records_a) = &result[0];
    assert_eq!(device_a.facts.ip, "10.0.0.1");
    assert_eq!(records_a.len(), 1);
    assert_eq!(records_a[0].name, "uptime");
    assert_eq!(records_a[0].enabled_override, Some(false), "the override from DeviceStore's domain must be merged onto the record from DeviceMetricsStore's domain");

    let (device_b, records_b) = &result[1];
    assert_eq!(device_b.facts.ip, "10.0.0.2");
    assert!(records_b.is_empty());
}

#[tokio::test]
async fn get_composes_device_identity_and_metrics_bag() {
    let (devices, device_metrics, _alerts) = all_stores().await;
    let (id, _) = devices.resolve(facts("10.0.0.1")).await.unwrap();
    let mut outcomes: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
    outcomes.insert("uptime".into(), MetricPollOutcome::Ok(MetricValue::Int(7)));
    device_metrics
        .record_metric_polls(id, &outcomes)
        .await
        .unwrap();

    let (device, metrics) = devices_crate::get(&devices, device_metrics.as_ref(), id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(device.facts.ip, "10.0.0.1");
    assert_eq!(metrics.0.get("uptime"), Some(&MetricValue::Int(7)));

    assert!(
        devices_crate::get(&devices, device_metrics.as_ref(), Uuid::new_v4())
            .await
            .unwrap()
            .is_none()
    );
}

fn list_query(
    overrides: impl FnOnce(&mut devices_crate::DeviceListQuery),
) -> devices_crate::DeviceListQuery {
    let mut q = devices_crate::DeviceListQuery::default();
    overrides(&mut q);
    q
}

/// Added 2026-08-21, scale audit — `list_devices` must sort `ip` *numerically* via the
/// precomputed `ip_sort_key`, not lexicographically as a plain string would ("10.0.0.10"
/// before "10.0.0.2").
#[tokio::test]
async fn list_devices_sorts_ip_numerically_not_lexicographically() {
    let devices = device_store().await;
    devices.resolve(facts("10.0.0.10")).await.unwrap();
    devices.resolve(facts("10.0.0.2")).await.unwrap();
    devices.resolve(facts("10.0.0.1")).await.unwrap();

    let page = devices.list_devices(&list_query(|_| {})).await.unwrap();
    let ips: Vec<&str> = page.items.iter().map(|d| d.facts.ip.as_str()).collect();
    assert_eq!(ips, vec!["10.0.0.1", "10.0.0.2", "10.0.0.10"]);
    assert_eq!(page.total, 3);
}

#[tokio::test]
async fn list_devices_search_matches_ip_or_profile_case_insensitively() {
    let devices = device_store().await;
    let (id_a, _) = devices.resolve(facts("10.0.0.1")).await.unwrap();
    devices.resolve(facts("192.168.1.1")).await.unwrap();
    devices
        .apply_profile_if_changed(id_a, "Generic_Switch", "v1")
        .await
        .unwrap();

    let by_ip = devices
        .list_devices(&list_query(|q| q.search = Some("192.168".to_string())))
        .await
        .unwrap();
    assert_eq!(by_ip.items.len(), 1);
    assert_eq!(by_ip.items[0].facts.ip, "192.168.1.1");

    let by_profile = devices
        .list_devices(&list_query(|q| {
            q.search = Some("generic_switch".to_string())
        }))
        .await
        .unwrap();
    assert_eq!(
        by_profile.items.len(),
        1,
        "search must be case-insensitive and match the profile name too"
    );
    assert_eq!(by_profile.items[0].facts.ip, "10.0.0.1");
}

#[tokio::test]
async fn list_devices_filters_by_exact_profile_and_paginates() {
    let devices = device_store().await;
    let (id_a, _) = devices.resolve(facts("10.0.0.1")).await.unwrap();
    let (id_b, _) = devices.resolve(facts("10.0.0.2")).await.unwrap();
    devices.resolve(facts("10.0.0.3")).await.unwrap();
    devices
        .apply_profile_if_changed(id_a, "switch", "v1")
        .await
        .unwrap();
    devices
        .apply_profile_if_changed(id_b, "switch", "v1")
        .await
        .unwrap();

    let filtered = devices
        .list_devices(&list_query(|q| q.profile = Some("switch".to_string())))
        .await
        .unwrap();
    assert_eq!(
        filtered.total, 2,
        "must not match the third, unprofiled device"
    );

    let page1 = devices
        .list_devices(&list_query(|q| q.limit = 1))
        .await
        .unwrap();
    assert_eq!(page1.items.len(), 1, "limit must be respected");
    assert_eq!(
        page1.total, 3,
        "total must reflect the full match count, not just this page"
    );
    let page2 = devices
        .list_devices(&list_query(|q| {
            q.limit = 1;
            q.offset = 1;
        }))
        .await
        .unwrap();
    assert_ne!(
        page1.items[0].id, page2.items[0].id,
        "offset must actually move to the next row"
    );
}

/// SNMP Trap ingestion (2026-08-30) — `discovery-agent`'s ttl-sweep needs to find every
/// trap-derived metric across every device by name prefix, without touching unrelated
/// metrics (`cpu`, `if_table`, ...) or unrelated devices.
#[tokio::test]
async fn list_metrics_by_name_prefix_finds_matching_metrics_across_devices_and_skips_others() {
    let (devices, device_metrics, _alerts) = all_stores().await;
    let (id_a, _) = devices.resolve(facts("10.0.0.1")).await.unwrap();
    let (id_b, _) = devices.resolve(facts("10.0.0.2")).await.unwrap();

    let mut a_metrics = BTreeMap::new();
    a_metrics.insert(
        "cpu".to_string(),
        MetricPollOutcome::Ok(MetricValue::Int(42)),
    );
    a_metrics.insert(
        "trap_port_link_state".to_string(),
        MetricPollOutcome::Ok(MetricValue::Table(vec![])),
    );
    device_metrics
        .record_metric_polls(id_a, &a_metrics)
        .await
        .unwrap();

    let mut b_metrics = BTreeMap::new();
    b_metrics.insert(
        "trap_cold_start".to_string(),
        MetricPollOutcome::Ok(MetricValue::Table(vec![])),
    );
    device_metrics
        .record_metric_polls(id_b, &b_metrics)
        .await
        .unwrap();

    let found = device_metrics
        .list_metrics_by_name_prefix("trap_")
        .await
        .unwrap();
    let mut names: Vec<(Uuid, String)> =
        found.into_iter().map(|(id, name, _)| (id, name)).collect();
    names.sort();
    let mut expected = vec![
        (id_a, "trap_port_link_state".to_string()),
        (id_b, "trap_cold_start".to_string()),
    ];
    expected.sort();
    assert_eq!(
        names, expected,
        "must find both trap-prefixed metrics, from both devices, and nothing else (cpu excluded)"
    );
}

#[tokio::test]
async fn count_reflects_inserts_and_does_not_double_count_a_re_resolved_ip() {
    let store = device_store().await;
    assert_eq!(store.count().await.unwrap(), 0);

    store.resolve(facts("10.0.0.1")).await.unwrap();
    assert_eq!(store.count().await.unwrap(), 1);

    store.resolve(facts("10.0.0.2")).await.unwrap();
    assert_eq!(store.count().await.unwrap(), 2);

    // Re-resolving an already-known IP must not be counted as a second device.
    store.resolve(facts("10.0.0.1")).await.unwrap();
    assert_eq!(store.count().await.unwrap(), 2);
}
