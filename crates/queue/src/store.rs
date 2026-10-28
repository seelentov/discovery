use async_trait::async_trait;
use discovery_core::{Job, JobState, QueueKind, QueueStats};
use serde::Serialize;

/// `SortDir` moved to `discovery_core` 2026-08-17, once `discovery-alerts` needed the
/// exact same type — re-exported here so existing call sites
/// (`use discovery_queue::SortDir`) don't need to change their import path.
pub use discovery_core::SortDir;

/// Which column to sort job records by — see [`JobListQuery`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobSortBy {
    Id,
    CreatedAt,
    UpdatedAt,
    Attempts,
}

/// Search + sort + paginate parameters for [`JobQueueStore::list_jobs`] — the dashboard's
/// per-queue job records view (added 2026-08-17, direct user request: "не отображай
/// последние 100 записей а все не done с пагинацией фильтрацией сортировкой и поиском").
/// Recurring queues contain only actionable jobs; the operator-action queue also keeps
/// bounded terminal history for the action status screen.
#[derive(Debug, Clone)]
pub struct JobListQuery {
    /// `None` means every state, not just one.
    pub state: Option<JobState>,
    /// Free-text, case-insensitive, matched against the job id, its JSON payload (as
    /// text), and its last error — "what does this job concern" in one box, since a
    /// payload usually carries the IP/device/subnet a job is about.
    pub search: Option<String>,
    pub sort_by: JobSortBy,
    pub sort_dir: SortDir,
    pub limit: i64,
    pub offset: i64,
}

impl Default for JobListQuery {
    fn default() -> Self {
        Self {
            state: None,
            search: None,
            sort_by: JobSortBy::UpdatedAt,
            sort_dir: SortDir::Desc,
            limit: 50,
            offset: 0,
        }
    }
}

/// One page of job records plus the total count matching the filter (ignoring
/// `limit`/`offset`) — what the dashboard needs to render "page N of M, K total"
/// pagination controls without a second round-trip.
#[derive(Debug, Clone, Serialize)]
pub struct JobListPage {
    pub jobs: Vec<Job>,
    pub total: i64,
}

/// Storage for the job queue. One implementation — [`crate::SeaOrmJobQueueStore`], works
/// against Postgres/MySQL/SQLite (and, for tests/zero-config, `sqlite::memory:`) through
/// the same sea-orm entity/query code path (2026-08-18 multi-DB rewrite, replacing the old
/// `PostgresJobQueueStore`/`SqliteJobQueueStore`/`InMemoryJobQueueStore` trio — see
/// `discovery_config_store::SeaOrmSettingsStore`'s docs for the full rationale). Jobs are
/// rows in a table; a worker process dying mid-job just leaves a stale `locked_at`, which
/// [`JobQueueStore::reclaim_stale`] periodically notices and requeues. Nothing needs to be
/// "resumed" manually — a fresh process just starts claiming `pending` rows again, and
/// stale `in_progress` rows become `pending` again on their own.
#[async_trait]
pub trait JobQueueStore: Send + Sync {
    /// Adds a new job. `dedupe_key`, if given, prevents queuing duplicate pending/in-flight
    /// work for the same logical target (e.g. don't queue two `SnmpPoll` jobs for the same
    /// IP while one is already outstanding). Returns `-1` instead of a new id when the
    /// dedupe key was already active.
    async fn enqueue(
        &self,
        queue: QueueKind,
        payload: serde_json::Value,
        dedupe_key: Option<&str>,
    ) -> anyhow::Result<i64>;

    /// Atomically claims up to `limit` pending jobs for `worker_id` and marks them
    /// in-progress. Must be safe under concurrent callers — no two callers may ever claim
    /// the same job (the Postgres implementation relies on `FOR UPDATE SKIP LOCKED` for
    /// this; the in-memory one relies on a single mutex).
    async fn claim(
        &self,
        queue: QueueKind,
        worker_id: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<Job>>;

    /// Deletes successful recurring pipeline jobs. Operator actions alone are retained
    /// as `done` with their result for a bounded history period.
    async fn complete(&self, job_id: i64) -> anyhow::Result<()>;

    /// Marks a job's attempt as failed. Requeues it (back to `pending`) unless it has hit
    /// `max_attempts`, in which case it's marked `failed` for good.
    async fn fail(&self, job_id: i64, error: &str) -> anyhow::Result<()>;

    /// Requeues jobs that have been `in_progress` for longer than `older_than` — the
    /// crash-recovery path. Called periodically by [`crate::spawn_reclaim_loop`].
    async fn reclaim_stale(&self, older_than: chrono::Duration) -> anyhow::Result<u64>;

    async fn stats(&self, queue: QueueKind) -> anyhow::Result<QueueStats>;

    async fn state_of(&self, job_id: i64) -> anyhow::Result<Option<JobState>>;

    /// Full record for an operator action, including its terminal result.
    async fn get_job(&self, _job_id: i64) -> anyhow::Result<Option<Job>> {
        anyhow::bail!("get_job is not supported by this store")
    }

    /// Save a safe action result before the worker marks the job done.
    async fn set_result(&self, _job_id: i64, _result: serde_json::Value) -> anyhow::Result<()> {
        anyhow::bail!("set_result is not supported by this store")
    }

    /// Deletes one job outright, regardless of its current `state`/`paused` flag. Returns
    /// `false` if no job with that id existed (already completed/deleted/never existed) —
    /// same "not found is not an error" convention as `fail`, since a worker racing this
    /// call (finishing the same job right as an operator deletes it) is a normal,
    /// harmless outcome, not a bug: `complete`/`fail` on an already-deleted id are already
    /// no-ops.
    async fn delete_job(&self, job_id: i64) -> anyhow::Result<bool>;

    /// Cancel only a pending operator action. A claimed job cannot be interrupted safely.
    async fn cancel_pending_action(&self, _job_id: i64) -> anyhow::Result<bool> {
        anyhow::bail!("cancel_pending_action is not supported by this store")
    }

    /// Marks one job paused: it stays exactly where it is (same `state`, same row) but
    /// `claim` will never return it until [`Self::resume_job`] clears the flag. Returns
    /// `false` if no job with that id existed. Pausing an already-`in_progress` job is
    /// allowed (not an error) — it simply has no effect on the attempt already underway,
    /// only on whether it's claimable again afterwards (a retry via `fail`, or after
    /// `reclaim_stale` requeues it).
    async fn pause_job(&self, job_id: i64) -> anyhow::Result<bool>;

    /// Clears a job's pause flag, making it claimable again (once its `state` is
    /// `pending`). Returns `false` if no job with that id existed.
    async fn resume_job(&self, job_id: i64) -> anyhow::Result<bool>;

    /// Bulk-deletes every job in `queue`, optionally narrowed to one `state` (`None` =
    /// every state, including `in_progress` — deleting a job a worker currently holds is
    /// safe, see [`Self::delete_job`]'s docs on why that's a harmless race, not a bug).
    /// Returns the number of rows deleted. This is "очищать очередь целиком" — the bulk
    /// counterpart to `delete_job`, reusing the same state-scoping idea `list_jobs`/
    /// `JobListQuery::state` already established (e.g. "clear only the failed ones").
    async fn clear_queue(&self, queue: QueueKind, state: Option<JobState>) -> anyhow::Result<u64>;

    /// Whether `queue` as a whole is paused (`JobQueueStore::set_queue_paused`) — checked
    /// by [`Self::claim`] before it looks at any individual job, so a paused queue returns
    /// no work regardless of what's pending or which jobs have their own `paused` flag
    /// set. Defaults to `false` for a queue that has never been explicitly paused (no
    /// `queue_control` row needs to exist up front for every `QueueKind`).
    async fn is_queue_paused(&self, queue: QueueKind) -> anyhow::Result<bool>;

    /// Pauses or resumes an entire queue's worker claiming — "приостанавливать... очередь
    /// целиком" (as opposed to [`Self::pause_job`], which targets one job). Jobs already
    /// `in_progress` when a queue is paused are left running; only future `claim` calls
    /// are affected.
    async fn set_queue_paused(&self, queue: QueueKind, paused: bool) -> anyhow::Result<()>;

    /// Search + sort + paginate individual job records for `queue` — the dashboard's
    /// queue-records view: aggregate `stats()` counts alone don't say *which*
    /// device/subnet/IP each pending/in-progress/failed job actually concerns (that's in
    /// `payload`, whose shape depends on `queue` — see `discovery_core::payload`). See
    /// [`JobListQuery`]'s docs for the filter/sort/page parameters and [`JobListPage`] for
    /// the shape returned (rows plus a total count for pagination controls).
    ///
    /// **Changed 2026-08-17 (direct user request — dashboard pagination/search/sort/filter
    /// pass):** used to be `(queue, state: Option<JobState>, limit: i64) ->
    /// Vec<Job>` — a flat cap with no way to search, sort, or page past the first `limit`
    /// rows. Real SQL-level pagination here (not "fetch everything, slice in the web
    /// layer", the simpler approach used for devices/logs) because a queue's `pending`
    /// count can transiently spike into the thousands during a large discovery run — a
    /// real case observed in this exact project — where loading the whole set into memory
    /// on every dashboard poll would be wasteful.
    async fn list_jobs(
        &self,
        queue: QueueKind,
        query: &JobListQuery,
    ) -> anyhow::Result<JobListPage>;
}
