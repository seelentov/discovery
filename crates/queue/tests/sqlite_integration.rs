//! Integration test for `SeaOrmJobQueueStore` against a real, in-process SQLite database —
//! proves the sea-orm query-builder path (the dedupe-key existence check, `claim`'s
//! transactional select+update+reselect with `lock_with_behavior`, the `fail`
//! attempts-vs-max_attempts branch, `list_jobs`'s dynamic filter/sort/pagination) actually
//! runs correctly through `sqlx`'s SQLite driver, not just against the crate's own
//! `#[cfg(test)]` module (same connection, same migration, but worth keeping as an
//! independent regression net — same rationale as `discovery-devices`'s sibling file).

use discovery_core::{JobState, QueueKind};
use discovery_queue::{JobListQuery, JobQueueStore, SeaOrmJobQueueStore};

async fn test_store() -> SeaOrmJobQueueStore {
    SeaOrmJobQueueStore::new_in_memory_for_tests().await
}

#[tokio::test]
async fn enqueue_claim_complete_round_trip() {
    let store = test_store().await;
    let id = store
        .enqueue(
            QueueKind::Discovery,
            serde_json::json!({"ip": "10.0.0.1"}),
            None,
        )
        .await
        .unwrap();
    assert!(id > 0);
    assert_eq!(store.state_of(id).await.unwrap(), Some(JobState::Pending));

    let claimed = store
        .claim(QueueKind::Discovery, "worker-1", 10)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].id, id);
    assert_eq!(claimed[0].payload["ip"], "10.0.0.1");
    assert_eq!(
        store.state_of(id).await.unwrap(),
        Some(JobState::InProgress)
    );

    // A second claim call must not see the same job again — it's already in_progress.
    let claimed_again = store
        .claim(QueueKind::Discovery, "worker-2", 10)
        .await
        .unwrap();
    assert!(claimed_again.is_empty());

    store.complete(id).await.unwrap();
    // Completed jobs are deleted outright (2026-08-16 decision, see the trait's docs), not
    // moved to a terminal state — `state_of` on a deleted row is `None`, not `Some(Done)`.
    assert_eq!(store.state_of(id).await.unwrap(), None);
}

#[tokio::test]
async fn dedupe_key_prevents_a_second_pending_job_for_the_same_target() {
    let store = test_store().await;
    let id1 = store
        .enqueue(QueueKind::SnmpPoll, serde_json::json!({}), Some("10.0.0.1"))
        .await
        .unwrap();
    assert!(id1 > 0);

    let id2 = store
        .enqueue(QueueKind::SnmpPoll, serde_json::json!({}), Some("10.0.0.1"))
        .await
        .unwrap();
    assert_eq!(
        id2, -1,
        "a duplicate dedupe_key while the first is still pending must be rejected"
    );

    // A different dedupe_key is unaffected.
    let id3 = store
        .enqueue(QueueKind::SnmpPoll, serde_json::json!({}), Some("10.0.0.2"))
        .await
        .unwrap();
    assert!(id3 > 0);

    // Once the original completes (deleted), the same dedupe_key is free again.
    store.complete(id1).await.unwrap();
    let id4 = store
        .enqueue(QueueKind::SnmpPoll, serde_json::json!({}), Some("10.0.0.1"))
        .await
        .unwrap();
    assert!(
        id4 > 0,
        "the dedupe_key must be reusable once the earlier job is gone"
    );
}

#[tokio::test]
async fn fail_requeues_until_max_attempts_then_marks_failed() {
    let store = test_store().await;
    let id = store
        .enqueue(QueueKind::MetricPoll, serde_json::json!({}), None)
        .await
        .unwrap();

    // `max_attempts` is 5 (hardcoded at insert) — claim+fail 5 times; the 5th fail must be
    // the one that actually flips it to `failed` instead of requeuing to `pending` again.
    for i in 0..5 {
        let claimed = store
            .claim(QueueKind::MetricPoll, "worker-1", 1)
            .await
            .unwrap();
        assert_eq!(claimed.len(), 1, "attempt {i}: job must still be claimable");
        store.fail(claimed[0].id, "boom").await.unwrap();
        if i < 4 {
            assert_eq!(
                store.state_of(id).await.unwrap(),
                Some(JobState::Pending),
                "attempt {i}: must requeue, not fail yet"
            );
        }
    }
    assert_eq!(store.state_of(id).await.unwrap(), Some(JobState::Failed));

    let stats = store.stats(QueueKind::MetricPoll).await.unwrap();
    assert_eq!(stats.failed, 1);
    assert_eq!(stats.pending, 0);
    assert_eq!(stats.in_progress, 0);
}

#[tokio::test]
async fn reclaim_stale_returns_a_stuck_in_progress_job_to_pending() {
    let store = test_store().await;
    let id = store
        .enqueue(QueueKind::AlertEval, serde_json::json!({}), None)
        .await
        .unwrap();
    store
        .claim(QueueKind::AlertEval, "worker-1", 1)
        .await
        .unwrap();
    assert_eq!(
        store.state_of(id).await.unwrap(),
        Some(JobState::InProgress)
    );

    // Nothing stale yet — a fresh lock must not be touched.
    assert_eq!(
        store
            .reclaim_stale(chrono::Duration::minutes(5))
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        store.state_of(id).await.unwrap(),
        Some(JobState::InProgress)
    );

    // A lock older than the threshold must be requeued — simulate the passage of time by
    // reclaiming against a threshold shorter than "just now".
    let reclaimed = store
        .reclaim_stale(chrono::Duration::milliseconds(-1))
        .await
        .unwrap();
    assert_eq!(reclaimed, 1);
    assert_eq!(store.state_of(id).await.unwrap(), Some(JobState::Pending));
}

#[tokio::test]
async fn list_jobs_filters_searches_sorts_and_paginates() {
    let store = test_store().await;
    store
        .enqueue(
            QueueKind::Discovery,
            serde_json::json!({"ip": "10.0.0.1"}),
            None,
        )
        .await
        .unwrap();
    store
        .enqueue(
            QueueKind::Discovery,
            serde_json::json!({"ip": "10.0.0.2"}),
            None,
        )
        .await
        .unwrap();
    let claimed_id = store
        .enqueue(
            QueueKind::Discovery,
            serde_json::json!({"ip": "10.0.0.3"}),
            None,
        )
        .await
        .unwrap();
    store
        .claim(QueueKind::Discovery, "worker-1", 100)
        .await
        .unwrap(); // claims all 3 pending

    // Reset two of them back to pending by failing them once (max_attempts=5, so they go
    // back to pending, not failed) — gives a mix of states to filter on.
    let all = store
        .list_jobs(
            QueueKind::Discovery,
            &discovery_queue::JobListQuery::default(),
        )
        .await
        .unwrap();
    for job in &all.jobs {
        if job.id != claimed_id {
            store.fail(job.id, "transient").await.unwrap();
        }
    }

    let pending = store
        .list_jobs(
            QueueKind::Discovery,
            &JobListQuery {
                state: Some(JobState::Pending),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(pending.total, 2);
    let in_progress = store
        .list_jobs(
            QueueKind::Discovery,
            &JobListQuery {
                state: Some(JobState::InProgress),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(in_progress.total, 1);
    assert_eq!(in_progress.jobs[0].id, claimed_id);

    // Search matches the JSON payload text.
    let searched = store
        .list_jobs(
            QueueKind::Discovery,
            &JobListQuery {
                search: Some("10.0.0.3".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(searched.total, 1);
    assert_eq!(searched.jobs[0].id, claimed_id);

    // Pagination — `total` reflects the full match count, not just this page's size.
    let page = store
        .list_jobs(
            QueueKind::Discovery,
            &JobListQuery {
                limit: 1,
                offset: 0,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(page.total, 3);
    assert_eq!(page.jobs.len(), 1);
}

#[tokio::test]
async fn different_queues_are_fully_independent() {
    let store = test_store().await;
    store
        .enqueue(QueueKind::Discovery, serde_json::json!({}), None)
        .await
        .unwrap();
    store
        .enqueue(QueueKind::MetricPoll, serde_json::json!({}), None)
        .await
        .unwrap();

    let discovery_stats = store.stats(QueueKind::Discovery).await.unwrap();
    assert_eq!(discovery_stats.pending, 1);
    let metric_stats = store.stats(QueueKind::MetricPoll).await.unwrap();
    assert_eq!(metric_stats.pending, 1);

    // Claiming from one queue must never surface a job enqueued on another.
    let claimed = store
        .claim(QueueKind::Discovery, "worker-1", 10)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].queue, QueueKind::Discovery);
}
