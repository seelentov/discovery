use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use discovery_core::{Job, QueueKind, WorkerRegistry};
use discovery_queue::{
    run_worker_pool, JobHandler, JobListQuery, JobQueueStore, SeaOrmJobQueueStore, WorkerPoolConfig,
};

struct TrackingHandler {
    current: Arc<AtomicUsize>,
    max_seen: Arc<AtomicUsize>,
}

#[async_trait]
impl JobHandler for TrackingHandler {
    async fn handle(&self, _job: Job) -> anyhow::Result<()> {
        let now = self.current.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_seen.fetch_max(now, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(50)).await;
        self.current.fetch_sub(1, Ordering::SeqCst);
        Ok(())
    }
}

/// This is the load-bearing test for "ограничение на кол-во одновременных потоков для
/// каждого процесса": with `concurrency = 3` and 20 jobs queued, the handler must never
/// observe more than 3 concurrently in flight, but must observe more than 1 (otherwise
/// the pool would just be accidentally serial).
#[tokio::test]
async fn worker_pool_never_exceeds_configured_concurrency() {
    let store: Arc<dyn JobQueueStore> =
        Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
    for _ in 0..20 {
        store
            .enqueue(QueueKind::MetricPoll, serde_json::json!({}), None)
            .await
            .unwrap();
    }

    let current = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));
    let handler = Arc::new(TrackingHandler {
        current: current.clone(),
        max_seen: max_seen.clone(),
    });
    let registry = Arc::new(WorkerRegistry::new());

    let concurrency = 3;
    let pool = tokio::spawn(run_worker_pool(
        store.clone(),
        registry,
        WorkerPoolConfig {
            queue: QueueKind::MetricPoll,
            concurrency,
            poll_interval: Duration::from_millis(10),
        },
        handler,
    ));

    tokio::time::sleep(Duration::from_millis(600)).await;
    pool.abort();

    let observed = max_seen.load(Ordering::SeqCst);
    assert!(
        observed <= concurrency,
        "observed {} concurrent jobs, configured limit was {}",
        observed,
        concurrency
    );
    assert!(
        observed >= 2,
        "expected the pool to actually run jobs concurrently, not serially (observed {})",
        observed
    );
}

#[tokio::test]
async fn stats_reflect_progress_through_the_queue() {
    let store: Arc<dyn JobQueueStore> =
        Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
    for _ in 0..5 {
        store
            .enqueue(QueueKind::Discovery, serde_json::json!({}), None)
            .await
            .unwrap();
    }

    struct AlwaysOk;
    #[async_trait]
    impl JobHandler for AlwaysOk {
        async fn handle(&self, _job: Job) -> anyhow::Result<()> {
            Ok(())
        }
    }

    let registry = Arc::new(WorkerRegistry::new());
    let pool = tokio::spawn(run_worker_pool(
        store.clone(),
        registry,
        WorkerPoolConfig {
            queue: QueueKind::Discovery,
            concurrency: 2,
            poll_interval: Duration::from_millis(10),
        },
        Arc::new(AlwaysOk),
    ));

    tokio::time::sleep(Duration::from_millis(300)).await;
    pool.abort();

    // Completed jobs are deleted outright (2026-08-16, direct user request — see
    // discovery-queue::JobQueueStore::complete's docs), not archived in a `done` state —
    // so "all 5 finished" shows up as the queue being entirely empty, not as a done count.
    let stats = store.stats(QueueKind::Discovery).await.unwrap();
    assert_eq!(stats.pending, 0);
    assert_eq!(stats.in_progress, 0);
    assert_eq!(stats.failed, 0);
    let remaining = store
        .list_jobs(QueueKind::Discovery, &JobListQuery::default())
        .await
        .unwrap()
        .jobs;
    assert!(
        remaining.is_empty(),
        "successfully completed jobs must not linger in storage"
    );
}
