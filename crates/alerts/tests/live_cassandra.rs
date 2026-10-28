//! Live verification of `CassandraAlertStore` against a real Cassandra server — same
//! `#[ignore]`d convention as `discovery-devices`'s `tests/live_cassandra.rs`/`discovery-
//! migration`'s `tests/live_multi_backend.rs` (needs a real server reachable, not run by
//! plain `cargo test --workspace`). Run explicitly with `cargo test -p discovery-alerts
//! --test live_cassandra -- --ignored`.
//!
//! Mirrors `sea_orm_store.rs`'s own test coverage — every test uses a fresh random `Uuid`
//! id/device_id, so tests don't interfere with each other even sharing one keyspace across
//! runs.

use discovery_alerts::{AlertListQuery, AlertSortBy, AlertStore, CassandraAlertStore};
use discovery_core::{Alert, AlertLevel, AlertState, NewAttachment, SortDir};
use scylla::SessionBuilder;
use std::sync::Arc;
use uuid::Uuid;

const KEYSPACE: &str = "discovery_alerts_live_test";

async fn store() -> CassandraAlertStore {
    let session = SessionBuilder::new()
        .known_node("127.0.0.1:9042")
        .build()
        .await
        .expect("connect to the local Cassandra");
    CassandraAlertStore::ensure_schema(&session, KEYSPACE)
        .await
        .expect("ensure_schema");
    CassandraAlertStore::new(Arc::new(session))
}

fn alert(
    id: Uuid,
    device_id: Uuid,
    device_ip: &str,
    name: &str,
    state: AlertState,
    level: AlertLevel,
) -> Alert {
    let now = chrono::Utc::now();
    Alert {
        details: Default::default(),
        id,
        device_id,
        device_ip: device_ip.to_string(),
        name: name.to_string(),
        row_key: None,
        level,
        message: format!("{name} on {device_ip}"),
        state: state.clone(),
        facts: Some(serde_json::json!({"ip": device_ip, "value": 42})),
        first_seen: now,
        last_seen: now,
        cleared_at: if state == AlertState::Cleared {
            Some(now)
        } else {
            None
        },
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
    }
}

#[tokio::test]
#[ignore]
async fn upsert_is_insert_or_update_by_id_and_facts_json_round_trips() {
    let store = store().await;
    let id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    store
        .upsert(&alert(
            id,
            device_id,
            "10.9.0.1",
            "high_cpu",
            AlertState::Active,
            AlertLevel::Warning,
        ))
        .await
        .unwrap();

    let fetched = store.get(id).await.unwrap().unwrap();
    assert_eq!(
        fetched.facts,
        Some(serde_json::json!({"ip": "10.9.0.1", "value": 42}))
    );

    let mut updated = alert(
        id,
        device_id,
        "10.9.0.1",
        "high_cpu",
        AlertState::Cleared,
        AlertLevel::Warning,
    );
    updated.message = "resolved".into();
    store.upsert(&updated).await.unwrap();

    let fetched = store.get(id).await.unwrap().unwrap();
    assert_eq!(
        fetched.message, "resolved",
        "same id must update in place, not create a second row"
    );
    assert_eq!(fetched.state, AlertState::Cleared);
}

/// Mirrors `sea_orm_store::tests::row_key_and_auto_clear_reason_round_trip` — direct
/// user request 2026-08-29 ("тревога по порту"), same coverage on both `AlertStore`
/// backends per this project's "new implementation mirrors the existing one 1:1"
/// discipline.
#[tokio::test]
#[ignore]
async fn row_key_and_auto_clear_reason_round_trip() {
    let store = store().await;
    let id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let mut a = alert(
        id,
        device_id,
        "10.9.0.2",
        "port_down",
        AlertState::Active,
        AlertLevel::Warning,
    );
    a.row_key = Some("Gi0/3".to_string());
    store.upsert(&a).await.unwrap();

    let fetched = store.get(id).await.unwrap().unwrap();
    assert_eq!(fetched.row_key.as_deref(), Some("Gi0/3"));
    assert_eq!(fetched.auto_clear_reason, None);

    let mut cleared = fetched;
    cleared.state = AlertState::Cleared;
    cleared.cleared_at = Some(chrono::Utc::now());
    cleared.auto_clear_reason = Some(discovery_core::AutoClearReason::RowMissing);
    store.upsert(&cleared).await.unwrap();

    let refetched = store.get(id).await.unwrap().unwrap();
    assert_eq!(
        refetched.row_key.as_deref(),
        Some("Gi0/3"),
        "row_key must survive the update, frozen from activation"
    );
    assert_eq!(
        refetched.auto_clear_reason,
        Some(discovery_core::AutoClearReason::RowMissing)
    );
}

#[tokio::test]
#[ignore]
async fn search_matches_ip_name_and_message_case_insensitively() {
    let store = store().await;
    let ip_marker = format!("marker-{}", Uuid::new_v4());
    store
        .upsert(&alert(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &ip_marker,
            "high_cpu",
            AlertState::Active,
            AlertLevel::Warning,
        ))
        .await
        .unwrap();
    let name_marker = format!("LOW_DISK_{}", Uuid::new_v4().simple());
    store
        .upsert(&alert(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "10.9.0.2",
            &name_marker,
            AlertState::Active,
            AlertLevel::Critical,
        ))
        .await
        .unwrap();

    let by_ip = store
        .list(&AlertListQuery {
            search: Some(ip_marker.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(by_ip.total, 1);

    let by_name = store
        .list(&AlertListQuery {
            search: Some(name_marker.to_lowercase()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(by_name.total, 1);
    assert_eq!(by_name.items[0].device_ip, "10.9.0.2");
}

#[tokio::test]
#[ignore]
async fn filters_by_level_state_and_device_id() {
    let store = store().await;
    let device_a = Uuid::new_v4();
    let device_b = Uuid::new_v4();
    let a = alert(
        Uuid::new_v4(),
        device_a,
        "10.9.1.1",
        &format!("a-{}", Uuid::new_v4()),
        AlertState::Active,
        AlertLevel::Warning,
    );
    let b = alert(
        Uuid::new_v4(),
        device_b,
        "10.9.1.2",
        &format!("b-{}", Uuid::new_v4()),
        AlertState::Cleared,
        AlertLevel::Critical,
    );
    store.upsert(&a).await.unwrap();
    store.upsert(&b).await.unwrap();

    let by_device = store
        .list(&AlertListQuery {
            device_id: Some(device_a),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(by_device.total, 1);
    assert_eq!(by_device.items[0].id, a.id);

    let by_device_and_level = store
        .list(&AlertListQuery {
            device_id: Some(device_a),
            level: Some(AlertLevel::Warning),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(by_device_and_level.total, 1);

    let by_device_wrong_level = store
        .list(&AlertListQuery {
            device_id: Some(device_a),
            level: Some(AlertLevel::Critical),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        by_device_wrong_level.total, 0,
        "combined SAI predicates must be AND'd, not OR'd"
    );

    let by_state = store
        .list(&AlertListQuery {
            device_id: Some(device_b),
            state: Some(AlertState::Cleared),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(by_state.total, 1);
    assert_eq!(by_state.items[0].id, b.id);
}

#[tokio::test]
#[ignore]
async fn sort_and_pagination() {
    let store = store().await;
    let device_id = Uuid::new_v4();
    let marker = format!("sortmarker-{}", Uuid::new_v4());
    for ip in ["10.9.2.3", "10.9.2.1", "10.9.2.2"] {
        store
            .upsert(&alert(
                Uuid::new_v4(),
                device_id,
                ip,
                &marker,
                AlertState::Active,
                AlertLevel::Info,
            ))
            .await
            .unwrap();
    }

    let page = store
        .list(&AlertListQuery {
            device_id: Some(device_id),
            sort_by: AlertSortBy::DeviceIp,
            sort_dir: SortDir::Asc,
            limit: 2,
            offset: 0,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        page.total, 3,
        "total must reflect all matches, not just this page"
    );
    assert_eq!(page.items.len(), 2);
    assert_eq!(page.items[0].device_ip, "10.9.2.1");
    assert_eq!(page.items[1].device_ip, "10.9.2.2");
}

#[tokio::test]
#[ignore]
async fn prune_cleared_older_than_leaves_active_alerts_and_recent_cleared_ones_alone() {
    let store = store().await;
    let old_id = Uuid::new_v4();
    let mut old_cleared = alert(
        old_id,
        Uuid::new_v4(),
        "10.9.3.1",
        "a",
        AlertState::Cleared,
        AlertLevel::Info,
    );
    old_cleared.cleared_at = Some(chrono::Utc::now() - chrono::Duration::days(30));
    store.upsert(&old_cleared).await.unwrap();

    let recent_id = Uuid::new_v4();
    store
        .upsert(&alert(
            recent_id,
            Uuid::new_v4(),
            "10.9.3.2",
            "b",
            AlertState::Cleared,
            AlertLevel::Info,
        ))
        .await
        .unwrap();

    let active_id = Uuid::new_v4();
    store
        .upsert(&alert(
            active_id,
            Uuid::new_v4(),
            "10.9.3.3",
            "c",
            AlertState::Active,
            AlertLevel::Info,
        ))
        .await
        .unwrap();

    let cutoff = chrono::Utc::now() - chrono::Duration::days(7);
    let deleted = store.prune_cleared_older_than(cutoff).await.unwrap();
    assert!(
        deleted >= 1,
        "at least the old cleared alert must be pruned"
    );

    assert!(
        store.get(old_id).await.unwrap().is_none(),
        "the old cleared alert must be gone"
    );
    assert!(
        store.get(recent_id).await.unwrap().is_some(),
        "a recently-cleared alert must survive"
    );
    assert!(
        store.get(active_id).await.unwrap().is_some(),
        "an active alert must never be pruned regardless of age"
    );
}

#[tokio::test]
#[ignore]
async fn get_returns_none_for_an_unknown_id_and_some_after_upsert() {
    let store = store().await;
    let id = Uuid::new_v4();
    assert!(store.get(id).await.unwrap().is_none());
    store
        .upsert(&alert(
            id,
            Uuid::new_v4(),
            "10.9.4.1",
            "high_cpu",
            AlertState::Active,
            AlertLevel::Warning,
        ))
        .await
        .unwrap();
    assert_eq!(store.get(id).await.unwrap().unwrap().id, id);
}

#[tokio::test]
#[ignore]
async fn delete_removes_the_row_and_is_a_noop_for_an_unknown_id() {
    let store = store().await;
    let id = Uuid::new_v4();
    store
        .upsert(&alert(
            id,
            Uuid::new_v4(),
            "10.9.4.2",
            "high_cpu",
            AlertState::Active,
            AlertLevel::Warning,
        ))
        .await
        .unwrap();
    store.delete(id).await.unwrap();
    assert!(store.get(id).await.unwrap().is_none());
    store.delete(Uuid::new_v4()).await.unwrap(); // no such id — must not error
}

#[tokio::test]
#[ignore]
async fn add_comment_appends_to_the_thread_and_bumps_comment_count() {
    let store = store().await;
    let id = Uuid::new_v4();
    let original = alert(
        id,
        Uuid::new_v4(),
        "10.9.4.3",
        "high_cpu",
        AlertState::Active,
        AlertLevel::Warning,
    );
    store.upsert(&original).await.unwrap();

    let comment = store
        .add_comment(
            id,
            "alice",
            "looked into it, waiting on vendor",
            vec![NewAttachment {
                filename: "screenshot.png".to_string(),
                content_type: "image/png".to_string(),
                data: vec![1, 2, 3, 4],
            }],
        )
        .await
        .unwrap();
    assert_eq!(comment.attachments.len(), 1);
    let fetched = store.get(id).await.unwrap().unwrap();
    assert_eq!(fetched.comment_count, 1);
    assert_eq!(
        fetched.message, original.message,
        "add_comment must not touch other fields"
    );

    let thread = store.list_comments(id).await.unwrap();
    assert_eq!(thread.len(), 1);
    assert_eq!(thread[0].author, "alice");
    assert_eq!(thread[0].attachments.len(), 1);
    assert_eq!(thread[0].attachments[0].filename, "screenshot.png");

    let (meta, data) = store
        .get_attachment(comment.attachments[0].id)
        .await
        .unwrap()
        .expect("attachment must exist");
    assert_eq!(meta.content_type, "image/png");
    assert_eq!(data, vec![1, 2, 3, 4]);

    assert!(store
        .add_comment(Uuid::new_v4(), "bob", "x", vec![])
        .await
        .is_err()); // no such alert — must error
}

#[tokio::test]
#[ignore]
async fn delete_for_device_removes_only_that_devices_alerts() {
    let store = store().await;
    let device_a = Uuid::new_v4();
    let device_b = Uuid::new_v4();
    let a = alert(
        Uuid::new_v4(),
        device_a,
        "10.9.5.1",
        "high_cpu",
        AlertState::Active,
        AlertLevel::Warning,
    );
    let b = alert(
        Uuid::new_v4(),
        device_b,
        "10.9.5.2",
        "high_cpu",
        AlertState::Active,
        AlertLevel::Warning,
    );
    store.upsert(&a).await.unwrap();
    store.upsert(&b).await.unwrap();

    let deleted = store.delete_for_device(device_a).await.unwrap();
    assert_eq!(deleted, 1);
    assert!(store.get(a.id).await.unwrap().is_none());
    assert!(
        store.get(b.id).await.unwrap().is_some(),
        "an unrelated device's alerts must survive"
    );

    assert_eq!(store.delete_for_device(Uuid::new_v4()).await.unwrap(), 0); // no such device
}

/// See `sea_orm_store.rs`'s twin test — same coverage against the Cassandra backend.
#[tokio::test]
#[ignore]
async fn active_counts_by_device_counts_only_active_and_only_the_requested_devices() {
    let store = store().await;
    let device_a = Uuid::new_v4();
    let device_b = Uuid::new_v4();
    let device_c = Uuid::new_v4(); // never included in the query below

    let a1 = alert(
        Uuid::new_v4(),
        device_a,
        "10.9.6.1",
        "high_cpu",
        AlertState::Active,
        AlertLevel::Warning,
    );
    let a2 = alert(
        Uuid::new_v4(),
        device_a,
        "10.9.6.1",
        "high_memory",
        AlertState::Active,
        AlertLevel::Critical,
    );
    let a3 = alert(
        Uuid::new_v4(),
        device_a,
        "10.9.6.1",
        "flapping",
        AlertState::Cleared,
        AlertLevel::Warning,
    );
    let b1 = alert(
        Uuid::new_v4(),
        device_b,
        "10.9.6.2",
        "high_cpu",
        AlertState::Active,
        AlertLevel::Warning,
    );
    let c1 = alert(
        Uuid::new_v4(),
        device_c,
        "10.9.6.3",
        "high_cpu",
        AlertState::Active,
        AlertLevel::Warning,
    );

    for a in [&a1, &a2, &a3, &b1, &c1] {
        store.upsert(a).await.unwrap();
    }

    let counts = store
        .active_counts_by_device(&[device_a, device_b])
        .await
        .unwrap();
    assert_eq!(
        counts.get(&device_a),
        Some(&2),
        "two active alerts, cleared one excluded"
    );
    assert_eq!(counts.get(&device_b), Some(&1));
    assert_eq!(
        counts.get(&device_c),
        None,
        "not in the requested id list, even though it has an active alert"
    );

    assert!(store.active_counts_by_device(&[]).await.unwrap().is_empty());
}
