//! Live verification of `CassandraDeviceMetricsStore` against a real Cassandra server —
//! same `#[ignore]`d convention as `discovery-migration`'s `tests/live_multi_backend.rs`
//! (needs a real server reachable, not run by plain `cargo test --workspace`). Run
//! explicitly with `cargo test -p discovery-devices --test live_cassandra -- --ignored`.
//!
//! Mirrors the coverage `sqlite_integration.rs`'s sea-orm tests give
//! `SeaOrmDeviceMetricsStore` — every device id is a fresh random `Uuid`, so tests don't
//! interfere with each other even sharing one keyspace across runs.

use chrono::Utc;
use discovery_core::{MetricPollOutcome, MetricValue};
use discovery_devices::{CassandraDeviceMetricsStore, DeviceMetricsStore};
use scylla::SessionBuilder;
use std::collections::BTreeMap;
use std::sync::Arc;
use uuid::Uuid;

const KEYSPACE: &str = "discovery_devices_live_test";

async fn store() -> CassandraDeviceMetricsStore {
    let session = SessionBuilder::new()
        .known_node("127.0.0.1:9042")
        .build()
        .await
        .expect("connect to the local Cassandra");
    CassandraDeviceMetricsStore::ensure_schema(&session, KEYSPACE)
        .await
        .expect("ensure_schema");
    CassandraDeviceMetricsStore::new(Arc::new(session))
}

#[tokio::test]
#[ignore]
async fn record_metric_polls_merges_without_wiping_other_metrics_and_history_dedupes_repeats() {
    let store = store().await;
    let id = Uuid::new_v4();

    let mut first: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
    first.insert(
        "sys_descr".into(),
        MetricPollOutcome::Ok(MetricValue::Str("Cisco Switch".into())),
    );
    store.record_metric_polls(id, &first).await.unwrap();

    let mut second: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
    second.insert(
        "uptime".into(),
        MetricPollOutcome::Ok(MetricValue::Int(12345)),
    );
    store.record_metric_polls(id, &second).await.unwrap();

    let metrics = store.get_metrics(id).await.unwrap();
    assert!(
        metrics.0.contains_key("sys_descr"),
        "an unrelated later write must not remove an earlier metric"
    );
    assert!(metrics.0.contains_key("uptime"));

    for _ in 0..3 {
        store.record_metric_polls(id, &second).await.unwrap();
    }
    let history = store
        .metric_history(id, "uptime", 50, 0, None, None)
        .await
        .unwrap();
    assert_eq!(
        history.total, 1,
        "repeating an identical value must collapse into a single history run, not grow it"
    );

    let mut third: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
    third.insert(
        "uptime".into(),
        MetricPollOutcome::Ok(MetricValue::Int(99999)),
    );
    store.record_metric_polls(id, &third).await.unwrap();
    let history = store
        .metric_history(id, "uptime", 50, 0, None, None)
        .await
        .unwrap();
    assert_eq!(
        history.total, 2,
        "a real value change must start a second history run"
    );
}

/// See `sqlite_integration.rs`'s twin test — same coverage against the Cassandra backend.
#[tokio::test]
#[ignore]
async fn metric_history_since_until_filters_by_last_observed_at() {
    let store = store().await;
    let id = Uuid::new_v4();

    let before = Utc::now();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let mut m: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
    m.insert("uptime".into(), MetricPollOutcome::Ok(MetricValue::Int(1)));
    store.record_metric_polls(id, &m).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let after = Utc::now();

    let bracketing = store
        .metric_history(id, "uptime", 50, 0, Some(before), Some(after))
        .await
        .unwrap();
    assert_eq!(
        bracketing.total, 1,
        "a window bracketing the run's timestamp must include it"
    );

    let too_early = store
        .metric_history(id, "uptime", 50, 0, None, Some(before))
        .await
        .unwrap();
    assert_eq!(
        too_early.total, 0,
        "an `until` before the run's timestamp must exclude it"
    );

    let too_late = store
        .metric_history(id, "uptime", 50, 0, Some(after), None)
        .await
        .unwrap();
    assert_eq!(
        too_late.total, 0,
        "a `since` after the run's timestamp must exclude it"
    );
}

#[tokio::test]
#[ignore]
async fn record_metric_polls_correctly_batches_a_mix_of_unchanged_changed_and_new_metrics_in_one_call(
) {
    let store = store().await;
    let id = Uuid::new_v4();

    let mut seed: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
    seed.insert("cpu".into(), MetricPollOutcome::Ok(MetricValue::Int(10)));
    seed.insert(
        "temperature".into(),
        MetricPollOutcome::Ok(MetricValue::Int(40)),
    );
    store.record_metric_polls(id, &seed).await.unwrap();

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
    store.record_metric_polls(id, &mixed).await.unwrap();

    assert_eq!(
        store
            .metric_history(id, "cpu", 50, 0, None, None)
            .await
            .unwrap()
            .total,
        1,
        "unchanged in a multi-metric batch must not open a second run"
    );
    assert_eq!(
        store
            .metric_history(id, "temperature", 50, 0, None, None)
            .await
            .unwrap()
            .total,
        2,
        "changed in a multi-metric batch must open a second run"
    );
    assert_eq!(
        store
            .metric_history(id, "fan_speed", 50, 0, None, None)
            .await
            .unwrap()
            .total,
        1,
        "brand-new in a multi-metric batch must be inserted"
    );

    let metrics = store.get_metrics(id).await.unwrap();
    assert_eq!(metrics.0.get("cpu"), Some(&MetricValue::Int(10)));
    assert_eq!(metrics.0.get("temperature"), Some(&MetricValue::Int(55)));
    assert_eq!(metrics.0.get("fan_speed"), Some(&MetricValue::Int(3000)));

    // A failure mixed with a success in the same call: the last known good value/time
    // must survive untouched (no read-before-write needed, CQL only writes columns
    // actually mentioned — see `CassandraDeviceMetricsStore`'s docs).
    let mut with_failure: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
    with_failure.insert("cpu".into(), MetricPollOutcome::Err("timeout".into()));
    with_failure.insert(
        "fan_speed".into(),
        MetricPollOutcome::Ok(MetricValue::Int(3100)),
    );
    store.record_metric_polls(id, &with_failure).await.unwrap();

    let records = store.get_metric_records(id).await.unwrap();
    let cpu = records.iter().find(|r| r.name == "cpu").unwrap();
    assert_eq!(
        cpu.value,
        Some(MetricValue::Int(10)),
        "a failed poll must not blank out the last known good value"
    );
    assert_eq!(cpu.error.as_deref(), Some("timeout"));
    let fan = records.iter().find(|r| r.name == "fan_speed").unwrap();
    assert_eq!(fan.value, Some(MetricValue::Int(3100)));
    assert_eq!(fan.error, None);
}

#[tokio::test]
#[ignore]
async fn prune_metrics_removes_only_keys_not_in_keep() {
    let store = store().await;
    let id = Uuid::new_v4();

    let mut outcomes: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
    outcomes.insert("keep_me".into(), MetricPollOutcome::Ok(MetricValue::Int(1)));
    outcomes.insert("drop_me".into(), MetricPollOutcome::Ok(MetricValue::Int(2)));
    store.record_metric_polls(id, &outcomes).await.unwrap();

    store
        .prune_metrics(id, &["keep_me".to_string()])
        .await
        .unwrap();

    let metrics = store.get_metrics(id).await.unwrap();
    assert!(metrics.0.contains_key("keep_me"));
    assert!(!metrics.0.contains_key("drop_me"));

    // History is untouched by prune_metrics — an archival record, per the trait's docs.
    let history = store
        .metric_history(id, "drop_me", 50, 0, None, None)
        .await
        .unwrap();
    assert_eq!(
        history.total, 1,
        "prune_metrics must not touch device_metric_history"
    );
}

#[tokio::test]
#[ignore]
async fn prune_metric_history_older_than_respects_keep_last_attempt_and_keep_last_success() {
    let store = store().await;
    let id = Uuid::new_v4();
    let metric_name = format!("cross_partition_prune_{}", Uuid::new_v4());

    // A successful run, then (much) later a failing run — both old enough to be
    // candidates for a cutoff in between doesn't apply here; we cut off *after* both.
    let mut ok: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
    ok.insert(
        metric_name.clone(),
        MetricPollOutcome::Ok(MetricValue::Int(1)),
    );
    store.record_metric_polls(id, &ok).await.unwrap();

    let mut err: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
    err.insert(metric_name.clone(), MetricPollOutcome::Err("boom".into()));
    store.record_metric_polls(id, &err).await.unwrap();

    let cutoff = chrono::Utc::now() + chrono::Duration::seconds(60);

    let deleted = store
        .prune_metric_history_older_than(&metric_name, cutoff, true, true)
        .await
        .unwrap();
    // The latest row (the error) is exempt by keep_last_attempt; the success row is the
    // latest *success* and exempt by keep_last_success — both survive, nothing deleted.
    assert_eq!(
        deleted, 0,
        "both rows are exempt (latest attempt = the error, latest success = the ok)"
    );

    let history = store
        .metric_history(id, &metric_name, 50, 0, None, None)
        .await
        .unwrap();
    assert_eq!(history.total, 2);

    let deleted = store
        .prune_metric_history_older_than(&metric_name, cutoff, false, false)
        .await
        .unwrap();
    assert_eq!(
        deleted, 2,
        "with no exemptions, both past-cutoff rows are deleted"
    );
    let history = store
        .metric_history(id, &metric_name, 50, 0, None, None)
        .await
        .unwrap();
    assert_eq!(history.total, 0);
}

#[tokio::test]
#[ignore]
async fn delete_for_device_removes_both_tables_and_is_a_noop_for_an_unknown_id() {
    let store = store().await;
    let id = Uuid::new_v4();

    let mut outcomes: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
    outcomes.insert("cpu".into(), MetricPollOutcome::Ok(MetricValue::Int(1)));
    store.record_metric_polls(id, &outcomes).await.unwrap();
    assert!(!store.get_metrics(id).await.unwrap().0.is_empty());

    store.delete_for_device(id).await.unwrap();
    assert!(store.get_metrics(id).await.unwrap().0.is_empty());
    assert_eq!(
        store
            .metric_history(id, "cpu", 50, 0, None, None)
            .await
            .unwrap()
            .total,
        0
    );

    // Unknown id — must not error.
    store.delete_for_device(Uuid::new_v4()).await.unwrap();
}

#[tokio::test]
#[ignore]
async fn get_metric_records_for_many_fans_out_across_partitions() {
    let store = store().await;
    let id_a = Uuid::new_v4();
    let id_b = Uuid::new_v4();

    let mut a: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
    a.insert("cpu".into(), MetricPollOutcome::Ok(MetricValue::Int(1)));
    store.record_metric_polls(id_a, &a).await.unwrap();
    let mut b: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
    b.insert("cpu".into(), MetricPollOutcome::Ok(MetricValue::Int(2)));
    store.record_metric_polls(id_b, &b).await.unwrap();

    let result = store
        .get_metric_records_for_many(&[id_a, id_b, Uuid::new_v4()])
        .await
        .unwrap();
    assert_eq!(
        result.len(),
        2,
        "a device with no metrics must be absent, not an empty entry"
    );
    assert_eq!(result[&id_a][0].value, Some(MetricValue::Int(1)));
    assert_eq!(result[&id_b][0].value, Some(MetricValue::Int(2)));
}
