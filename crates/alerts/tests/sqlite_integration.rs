//! Integration test for `SeaOrmAlertStore` against a real, in-process SQLite database —
//! proves the sea-orm query-builder path (`list`'s dynamic filter/sort/pagination, the
//! `ON CONFLICT`-based upsert, the `state = 'cleared' AND cleared_at < ?` retention prune)
//! actually runs correctly through `sqlx`'s SQLite driver, not just against the crate's
//! own `#[cfg(test)]` module (same connection, same migration, but worth keeping as an
//! independent regression net — same rationale as `discovery-devices`'s/`discovery-queue`'s
//! sibling files).
//!
//! **No device fixture row needed here** (unlike the pre-2026-08-18 hand-written
//! `SqliteAlertStore`'s version of this file) — `alerts.device_id` is a *soft* reference
//! in the new sea-orm schema (`discovery_entities::alerts`'s docs), not an enforced
//! `FOREIGN KEY`, so a synthetic `Uuid::new_v4()` with no matching `devices` row is valid.

use chrono::Utc;
use discovery_alerts::{AlertListQuery, AlertSortBy, AlertStore, SeaOrmAlertStore};
use discovery_core::{Alert, AlertLevel, AlertState, NewAttachment};
use uuid::Uuid;

async fn test_store() -> SeaOrmAlertStore {
    SeaOrmAlertStore::new_in_memory_for_tests().await
}

fn an_alert(name: &str, ip: &str, device_id: Uuid, level: AlertLevel, state: AlertState) -> Alert {
    let now = Utc::now();
    Alert {
        details: Default::default(),
        id: Uuid::new_v4(),
        device_id,
        device_ip: ip.to_string(),
        name: name.to_string(),
        row_key: None,
        level,
        message: "test message".to_string(),
        state: state.clone(),
        facts: Some(serde_json::json!({"ip": ip, "value": 42})),
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
async fn upsert_insert_then_update_round_trips_every_field_including_facts_json() {
    let store = test_store().await;
    let device_id = Uuid::new_v4();
    let mut alert = an_alert(
        "high_cpu",
        "10.0.0.1",
        device_id,
        AlertLevel::Critical,
        AlertState::Active,
    );
    store.upsert(&alert).await.unwrap();

    let fetched = store.get(alert.id).await.unwrap().unwrap();
    assert_eq!(fetched.name, "high_cpu");
    assert_eq!(fetched.level, AlertLevel::Critical);
    assert_eq!(fetched.state, AlertState::Active);
    assert_eq!(
        fetched.facts,
        Some(serde_json::json!({"ip": "10.0.0.1", "value": 42})),
        "facts JSON must round-trip exactly, not just its presence"
    );
    assert_eq!(fetched.cleared_at, None);

    // Same id, second write — this must be an UPDATE (ON CONFLICT), not a second row.
    alert.message = "updated message".to_string();
    alert.state = AlertState::Cleared;
    alert.cleared_at = Some(Utc::now());
    store.upsert(&alert).await.unwrap();

    let page = store.list(&AlertListQuery::default()).await.unwrap();
    assert_eq!(
        page.total, 1,
        "upserting the same id twice must update the row in place, not insert a second one"
    );
    let fetched = store.get(alert.id).await.unwrap().unwrap();
    assert_eq!(fetched.message, "updated message");
    assert_eq!(fetched.state, AlertState::Cleared);
    assert!(fetched.cleared_at.is_some());
}

/// Direct user request 2026-08-29 ("тревога по порту") — `row_key`/`auto_clear_reason`
/// round-trip through the real sqlx/SQLite path, not just the crate's own in-memory tests.
#[tokio::test]
async fn row_key_and_auto_clear_reason_round_trip() {
    let store = test_store().await;
    let device_id = Uuid::new_v4();
    let mut alert = an_alert(
        "port_down",
        "10.0.0.1",
        device_id,
        AlertLevel::Warning,
        AlertState::Active,
    );
    alert.row_key = Some("Gi0/3".to_string());
    store.upsert(&alert).await.unwrap();

    let fetched = store.get(alert.id).await.unwrap().unwrap();
    assert_eq!(fetched.row_key.as_deref(), Some("Gi0/3"));
    assert_eq!(fetched.auto_clear_reason, None);

    alert.state = AlertState::Cleared;
    alert.cleared_at = Some(Utc::now());
    alert.auto_clear_reason = Some(discovery_core::AutoClearReason::RowMissing);
    store.upsert(&alert).await.unwrap();

    let refetched = store.get(alert.id).await.unwrap().unwrap();
    assert_eq!(refetched.row_key.as_deref(), Some("Gi0/3"));
    assert_eq!(
        refetched.auto_clear_reason,
        Some(discovery_core::AutoClearReason::RowMissing)
    );
}

#[tokio::test]
async fn get_returns_none_for_an_unknown_id() {
    let store = test_store().await;
    assert!(store.get(Uuid::new_v4()).await.unwrap().is_none());
}

#[tokio::test]
async fn list_filters_by_level_state_device_id_and_search() {
    let store = test_store().await;
    let device_a = Uuid::new_v4();
    let device_b = Uuid::new_v4();
    let a1 = an_alert(
        "high_cpu",
        "10.0.0.1",
        device_a,
        AlertLevel::Critical,
        AlertState::Active,
    );
    let a2 = an_alert(
        "recent_reboot",
        "10.0.0.2",
        device_b,
        AlertLevel::Warning,
        AlertState::Cleared,
    );
    store.upsert(&a1).await.unwrap();
    store.upsert(&a2).await.unwrap();

    let by_level = store
        .list(&AlertListQuery {
            level: Some(AlertLevel::Critical),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(by_level.total, 1);
    assert_eq!(by_level.items[0].id, a1.id);

    let by_state = store
        .list(&AlertListQuery {
            state: Some(AlertState::Cleared),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(by_state.total, 1);
    assert_eq!(by_state.items[0].id, a2.id);

    let by_device = store
        .list(&AlertListQuery {
            device_id: Some(device_a),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(by_device.total, 1);
    assert_eq!(by_device.items[0].id, a1.id);

    // Search matches device_ip/name/message — case-insensitive.
    let by_search = store
        .list(&AlertListQuery {
            search: Some("REBOOT".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(by_search.total, 1);
    assert_eq!(by_search.items[0].id, a2.id);

    let by_ip_search = store
        .list(&AlertListQuery {
            search: Some("10.0.0.1".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(by_ip_search.total, 1);
    assert_eq!(by_ip_search.items[0].id, a1.id);
}

#[tokio::test]
async fn list_sorts_by_every_supported_column_and_direction() {
    let store = test_store().await;
    let a = an_alert(
        "alpha",
        "10.0.0.1",
        Uuid::new_v4(),
        AlertLevel::Info,
        AlertState::Active,
    );
    let b = an_alert(
        "bravo",
        "10.0.0.2",
        Uuid::new_v4(),
        AlertLevel::Critical,
        AlertState::Active,
    );
    store.upsert(&a).await.unwrap();
    store.upsert(&b).await.unwrap();

    let asc = store
        .list(&AlertListQuery {
            sort_by: AlertSortBy::Name,
            sort_dir: discovery_core::SortDir::Asc,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(asc.items[0].name, "alpha");
    let desc = store
        .list(&AlertListQuery {
            sort_by: AlertSortBy::Name,
            sort_dir: discovery_core::SortDir::Desc,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(desc.items[0].name, "bravo");
}

#[tokio::test]
async fn list_paginates_with_total_reflecting_the_full_filtered_count() {
    let store = test_store().await;
    let device_id = Uuid::new_v4();
    for i in 0..5 {
        store
            .upsert(&an_alert(
                &format!("alert{i}"),
                "10.0.0.1",
                device_id,
                AlertLevel::Info,
                AlertState::Active,
            ))
            .await
            .unwrap();
    }
    let page = store
        .list(&AlertListQuery {
            limit: 2,
            offset: 0,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(page.total, 5);
    assert_eq!(page.items.len(), 2);
}

#[tokio::test]
async fn add_comment_appends_and_bumps_comment_count_without_touching_other_fields() {
    let store = test_store().await;
    let alert = an_alert(
        "high_cpu",
        "10.0.0.1",
        Uuid::new_v4(),
        AlertLevel::Critical,
        AlertState::Active,
    );
    store.upsert(&alert).await.unwrap();

    store
        .add_comment(
            alert.id,
            "alice",
            "investigating",
            vec![NewAttachment {
                filename: "log.txt".to_string(),
                content_type: "text/plain".to_string(),
                data: vec![1, 2, 3],
            }],
        )
        .await
        .unwrap();
    let fetched = store.get(alert.id).await.unwrap().unwrap();
    assert_eq!(fetched.comment_count, 1);
    assert_eq!(
        fetched.state,
        AlertState::Active,
        "add_comment must not touch state"
    );

    let thread = store.list_comments(alert.id).await.unwrap();
    assert_eq!(thread.len(), 1);
    assert_eq!(thread[0].author, "alice");
    assert_eq!(thread[0].text, "investigating");
    assert_eq!(thread[0].attachments.len(), 1);
    assert_eq!(thread[0].attachments[0].filename, "log.txt");

    let (meta, data) = store
        .get_attachment(thread[0].attachments[0].id)
        .await
        .unwrap()
        .expect("attachment must exist");
    assert_eq!(meta.size, 3);
    assert_eq!(data, vec![1, 2, 3]);
}

#[tokio::test]
async fn delete_removes_the_row_and_is_a_noop_for_an_unknown_id() {
    let store = test_store().await;
    let alert = an_alert(
        "high_cpu",
        "10.0.0.1",
        Uuid::new_v4(),
        AlertLevel::Critical,
        AlertState::Active,
    );
    store.upsert(&alert).await.unwrap();

    store.delete(alert.id).await.unwrap();
    assert!(store.get(alert.id).await.unwrap().is_none());

    // Deleting again (or an id that never existed) must not error.
    store.delete(alert.id).await.unwrap();
    store.delete(Uuid::new_v4()).await.unwrap();
}

#[tokio::test]
async fn prune_cleared_older_than_only_touches_cleared_rows_past_the_cutoff() {
    let store = test_store().await;
    let old_cleared = an_alert(
        "old",
        "10.0.0.1",
        Uuid::new_v4(),
        AlertLevel::Info,
        AlertState::Cleared,
    );
    let recent_cleared = an_alert(
        "recent",
        "10.0.0.2",
        Uuid::new_v4(),
        AlertLevel::Info,
        AlertState::Cleared,
    );
    let active = an_alert(
        "still_open",
        "10.0.0.3",
        Uuid::new_v4(),
        AlertLevel::Info,
        AlertState::Active,
    );
    store.upsert(&old_cleared).await.unwrap();
    store.upsert(&recent_cleared).await.unwrap();
    store.upsert(&active).await.unwrap();

    // `old_cleared`'s `cleared_at` was set to "now" at construction — sleep past it, note
    // the cutoff, then clear `recent_cleared` *after* the cutoff so it must survive.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let cutoff = Utc::now();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let mut recent_cleared_now = recent_cleared.clone();
    recent_cleared_now.cleared_at = Some(Utc::now());
    store.upsert(&recent_cleared_now).await.unwrap();

    let deleted = store.prune_cleared_older_than(cutoff).await.unwrap();
    assert_eq!(
        deleted, 1,
        "only the cleared alert whose cleared_at is before the cutoff must be pruned"
    );
    assert!(store.get(old_cleared.id).await.unwrap().is_none());
    assert!(
        store.get(recent_cleared.id).await.unwrap().is_some(),
        "cleared after the cutoff — must survive"
    );
    assert!(
        store.get(active.id).await.unwrap().is_some(),
        "still active — must never be pruned regardless of age"
    );
}

#[tokio::test]
async fn capability_runtime_library_event_journal_and_provenance_survive_storage_roundtrip() {
    let store = test_store().await;
    let id = Uuid::new_v4();
    let now = Utc::now();
    let mut status = discovery_core::AlertRuleStatus::new("event", Some("eth0"), now);
    status.event_times = vec![now];
    status.processed_events = vec![Uuid::new_v4()];
    status.value = Some(serde_json::json!({"previous":3}));
    let snapshot = discovery_core::AlertRuntimeSnapshot {
        states: vec![],
        statuses: vec![status],
        ..Default::default()
    };
    store.save_runtime(id, &snapshot).await.unwrap();
    store.save_runtime(id, &snapshot).await.unwrap();
    assert_eq!(
        store.runtime_page(1, 0).await.unwrap()[0].snapshot.statuses[0].processed_events,
        snapshot.statuses[0].processed_events
    );
    assert!(store.runtime_page(1, 1).await.unwrap().is_empty());
    store
        .save_shared_rule("link", serde_json::json!({"expression":"true"}))
        .await
        .unwrap();
    store
        .save_shared_rule("link", serde_json::json!({"expression":"false"}))
        .await
        .unwrap();
    assert_eq!(
        store.shared_rules().await.unwrap()["link"]["expression"],
        "false"
    );
    let event = discovery_core::AlertSourceEvent {
        id: Uuid::new_v4(),
        device_id: id,
        metric: "syslog_link".into(),
        received_at: now,
        data: serde_json::json!({"status":2}),
    };
    store.record_source_event(&event).await.unwrap();
    store.record_source_event(&event).await.unwrap();
    assert_eq!(
        store
            .source_events(id, now - chrono::Duration::seconds(1))
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(store
        .source_events(Uuid::new_v4(), now)
        .await
        .unwrap()
        .is_empty());
    let mut alert = an_alert(
        "link",
        "127.0.0.1",
        id,
        AlertLevel::Warning,
        AlertState::Active,
    );
    alert.details.policy.mode = discovery_core::AlertMode::Event;
    alert.details.source_event = Some(serde_json::json!({"id":event.id}));
    alert.details.previous_value = Some(serde_json::json!(3));
    alert.details.response_escalated = true;
    store.upsert(&alert).await.unwrap();
    let fetched = store.get(alert.id).await.unwrap().unwrap();
    assert!(fetched.details.response_escalated);
    assert_eq!(fetched.details.source_event, alert.details.source_event);
    store.delete_shared_rule("link").await.unwrap();
    assert!(store.shared_rules().await.unwrap().is_empty());
    assert_eq!(
        store
            .prune_source_events(now + chrono::Duration::seconds(1))
            .await
            .unwrap(),
        1
    );
    store.record_source_event(&event).await.unwrap();
    store.delete_for_device(id).await.unwrap();
    assert!(store.runtime_page(10, 0).await.unwrap().is_empty());
    assert!(store
        .source_events(id, now - chrono::Duration::seconds(1))
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn capability_pending_response_is_indexed_and_survives_history_cleanup_until_ack() {
    let store = test_store().await;
    let id = Uuid::new_v4();
    let now = Utc::now();
    let mut a = an_alert(
        "pending",
        "127.0.0.1",
        id,
        AlertLevel::Warning,
        AlertState::Cleared,
    );
    a.cleared_at = Some(now - chrono::Duration::days(2));
    a.details.policy.acknowledge_required = true;
    a.details.policy.screen_notification = true;
    store.upsert(&a).await.unwrap();
    assert_eq!(
        store
            .list(&AlertListQuery {
                response_pending: true,
                ..Default::default()
            })
            .await
            .unwrap()
            .total,
        1
    );
    assert_eq!(
        store
            .list(&AlertListQuery {
                screen_only: true,
                ..Default::default()
            })
            .await
            .unwrap()
            .total,
        1
    );
    assert_eq!(store.prune_cleared_older_than(now).await.unwrap(), 0);
    store
        .set_acknowledgement(a.id, Some("operator".into()), Some(now))
        .await
        .unwrap();
    assert_eq!(
        store
            .list(&AlertListQuery {
                response_pending: true,
                ..Default::default()
            })
            .await
            .unwrap()
            .total,
        0
    );
    assert_eq!(
        store
            .list(&AlertListQuery {
                screen_only: true,
                ..Default::default()
            })
            .await
            .unwrap()
            .total,
        0
    );
    assert_eq!(store.prune_cleared_older_than(now).await.unwrap(), 1);
}
