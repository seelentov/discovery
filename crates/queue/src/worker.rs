use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use discovery_core::{Job, QueueKind, WorkerRegistry};
use tracing::{error, info, warn};

use crate::JobQueueStore;

#[async_trait]
pub trait JobHandler: Send + Sync {
    async fn handle(&self, job: Job) -> anyhow::Result<()>;
}

pub struct WorkerPoolConfig {
    pub queue: QueueKind,
    /// Hard concurrency limit for this queue — this is the whole answer to "ограничение
    /// на кол-во одновременных потоков для каждого процесса": each pipeline stage gets
    /// its own pool with its own number here, independent of every other stage's.
    pub concurrency: usize,
    /// How long an idle worker sleeps between empty claims.
    pub poll_interval: Duration,
}

/// How many jobs one worker claims per `claim()` call — added 2026-08-21, scale audit
/// finding: `claim()` is itself several round trips (`BEGIN` + `SELECT ... FOR UPDATE
/// SKIP LOCKED` + `UPDATE` + a re-`SELECT` for the updated rows + `COMMIT` — see
/// `SeaOrmJobQueueStore::claim`'s docs), and paying that fixed cost per *single* job (the
/// old `limit=1`) doesn't hold up once a queue is genuinely busy (tens of thousands of
/// jobs/sec at the scale this project is meant to be ready for). Claimed jobs are still
/// handled **sequentially within this one worker**, not spawned concurrently — batching
/// only amortizes `claim()`'s own overhead, it deliberately does not raise how many jobs
/// one worker pool can have in flight at once (that's still exactly `concurrency`, see
/// this function's own docs on why that structural guarantee matters for the dashboard).
/// The real tradeoff this introduces: one slow/hung job (e.g. a device timing out) now
/// head-of-line-blocks up to `CLAIM_BATCH_SIZE - 1` other already-claimed jobs on the same
/// worker for the length of that stall, which couldn't happen when every claim was
/// exactly one job. 8 is a deliberately modest size — enough to cut the per-job
/// `claim()` overhead roughly 8x under load, without letting one stuck job stall more
/// than a handful of others behind it.
const CLAIM_BATCH_SIZE: i64 = 8;

/// Runs `config.concurrency` independent worker loops for one queue kind, each claiming a
/// batch of up to [`CLAIM_BATCH_SIZE`] jobs and handling them one at a time. Concurrency
/// is enforced structurally — there are only ever `concurrency` loops, not a shared
/// semaphore over an unbounded pool — which makes "how many X are running right now"
/// trivially answerable for the dashboard.
pub async fn run_worker_pool<H>(
    store: Arc<dyn JobQueueStore>,
    registry: Arc<WorkerRegistry>,
    config: WorkerPoolConfig,
    handler: Arc<H>,
) where
    H: JobHandler + 'static,
{
    let mut tasks = Vec::with_capacity(config.concurrency);
    for worker_idx in 0..config.concurrency {
        let store = store.clone();
        let registry = registry.clone();
        let handler = handler.clone();
        let queue = config.queue;
        let poll_interval = config.poll_interval;
        let worker_id = format!("{}-{}", queue.as_str(), worker_idx);

        registry.set_idle(&worker_id, queue);

        tasks.push(tokio::spawn(async move {
            loop {
                match store.claim(queue, &worker_id, CLAIM_BATCH_SIZE).await {
                    Ok(jobs) if !jobs.is_empty() => {
                        for job in jobs {
                            let job_id = job.id;
                            registry.set_busy(&worker_id, queue, format!("job#{}", job_id));

                            match handler.handle(job).await {
                                Ok(()) => {
                                    if let Err(e) = store.complete(job_id).await {
                                        error!(worker = %worker_id, job_id, error = %e, "failed to mark job complete");
                                    }
                                }
                                Err(e) => {
                                    warn!(worker = %worker_id, job_id, error = %e, "job failed");
                                    if let Err(e2) = store.fail(job_id, &e.to_string()).await {
                                        error!(worker = %worker_id, job_id, error = %e2, "failed to mark job failed");
                                    }
                                }
                            }

                            registry.set_idle(&worker_id, queue);
                        }
                    }
                    Ok(_) => tokio::time::sleep(poll_interval).await,
                    Err(e) => {
                        error!(worker = %worker_id, error = %e, "claim failed");
                        tokio::time::sleep(poll_interval).await;
                    }
                }
            }
        }));
    }

    info!(
        queue = config.queue.as_str(),
        concurrency = config.concurrency,
        "worker pool started"
    );
    for task in tasks {
        let _ = task.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use discovery_core::{JobState, QueueStats};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Spy store — only `claim` is ever meaningfully called by `run_worker_pool`; every
    /// other method is `unimplemented!()` since a test that hit one would be testing the
    /// wrong thing. Counts calls rather than returning jobs, so a test can assert the loop
    /// keeps polling an empty queue.
    struct CountingStore {
        claim_calls: AtomicUsize,
    }

    #[async_trait]
    impl JobQueueStore for CountingStore {
        async fn enqueue(
            &self,
            _queue: QueueKind,
            _payload: serde_json::Value,
            _dedupe_key: Option<&str>,
        ) -> anyhow::Result<i64> {
            unimplemented!()
        }
        async fn claim(
            &self,
            _queue: QueueKind,
            _worker_id: &str,
            _limit: i64,
        ) -> anyhow::Result<Vec<Job>> {
            self.claim_calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![])
        }
        async fn complete(&self, _job_id: i64) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn fail(&self, _job_id: i64, _error: &str) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn reclaim_stale(&self, _older_than: chrono::Duration) -> anyhow::Result<u64> {
            unimplemented!()
        }
        async fn stats(&self, _queue: QueueKind) -> anyhow::Result<QueueStats> {
            unimplemented!()
        }
        async fn state_of(&self, _job_id: i64) -> anyhow::Result<Option<JobState>> {
            unimplemented!()
        }
        async fn delete_job(&self, _job_id: i64) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn pause_job(&self, _job_id: i64) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn resume_job(&self, _job_id: i64) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn clear_queue(
            &self,
            _queue: QueueKind,
            _state: Option<JobState>,
        ) -> anyhow::Result<u64> {
            unimplemented!()
        }
        async fn is_queue_paused(&self, _queue: QueueKind) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn set_queue_paused(&self, _queue: QueueKind, _paused: bool) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn list_jobs(
            &self,
            _queue: QueueKind,
            _query: &crate::JobListQuery,
        ) -> anyhow::Result<crate::JobListPage> {
            unimplemented!()
        }
    }

    struct NoopHandler;

    #[async_trait]
    impl JobHandler for NoopHandler {
        async fn handle(&self, _job: Job) -> anyhow::Result<()> {
            unimplemented!("no job is ever claimed in these tests")
        }
    }

    #[tokio::test(start_paused = true)]
    async fn idle_workers_keep_polling_an_empty_queue() {
        let store = Arc::new(CountingStore {
            claim_calls: AtomicUsize::new(0),
        });
        let registry = Arc::new(WorkerRegistry::default());
        let config = WorkerPoolConfig {
            queue: QueueKind::Discovery,
            concurrency: 1,
            poll_interval: Duration::from_millis(10),
        };

        tokio::spawn(run_worker_pool(
            store.clone(),
            registry,
            config,
            Arc::new(NoopHandler),
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(35)).await;
        tokio::task::yield_now().await;

        assert!(
            store.claim_calls.load(Ordering::SeqCst) > 1,
            "an idle worker must keep claiming after each poll interval"
        );
    }
}

/// The other half of crash-safety: periodically requeues jobs whose lock has gone stale
/// (a worker claimed them and then the process died before completing/failing them).
/// Without this, a crash mid-job would leave that job stuck `in_progress` forever.
pub fn spawn_reclaim_loop(
    store: Arc<dyn JobQueueStore>,
    older_than: chrono::Duration,
    interval: Duration,
) {
    tokio::spawn(async move {
        loop {
            match store.reclaim_stale(older_than).await {
                Ok(count) if count > 0 => info!(count, "reclaimed stale jobs"),
                Ok(_) => {}
                Err(e) => error!(error = %e, "reclaim_stale failed"),
            }
            tokio::time::sleep(interval).await;
        }
    });
}
