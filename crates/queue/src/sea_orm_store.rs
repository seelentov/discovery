use async_trait::async_trait;
use chrono::{DateTime, Utc};
use discovery_core::{Job, JobState, QueueKind, QueueStats, SortDir};
use discovery_entities::jobs::{ActiveModel, Column, Entity, Model};
use sea_orm::sea_query::{Expr, Func, LockBehavior, LockType, SimpleExpr};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, Condition, ConnectionTrait, DatabaseBackend,
    DatabaseConnection, EntityTrait, Order, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect,
    TransactionTrait,
};

use crate::{JobListPage, JobListQuery, JobQueueStore, JobSortBy};

fn state_from_str(s: &str) -> JobState {
    match s {
        "in_progress" => JobState::InProgress,
        "failed" => JobState::Failed,
        "done" => JobState::Done,
        "cancelled" => JobState::Cancelled,
        _ => JobState::Pending,
    }
}

fn state_to_str(state: JobState) -> &'static str {
    match state {
        JobState::Pending => "pending",
        JobState::InProgress => "in_progress",
        JobState::Failed => "failed",
        JobState::Done => "done",
        JobState::Cancelled => "cancelled",
    }
}

fn model_to_job(m: Model) -> anyhow::Result<Job> {
    Ok(Job {
        id: m.id,
        queue: QueueKind::from_str(&m.queue_type)
            .ok_or_else(|| anyhow::anyhow!("unknown queue_type '{}' in DB row", m.queue_type))?,
        payload: m.payload,
        dedupe_key: m.dedupe_key,
        state: state_from_str(&m.state),
        attempts: m.attempts,
        max_attempts: m.max_attempts,
        locked_by: m.locked_by,
        locked_at: m.locked_at,
        last_error: m.last_error,
        result: m.result,
        created_at: m.created_at,
        updated_at: m.updated_at,
        paused: m.paused,
    })
}

fn sort_column(sort_by: JobSortBy) -> Column {
    match sort_by {
        JobSortBy::Id => Column::Id,
        JobSortBy::CreatedAt => Column::CreatedAt,
        JobSortBy::UpdatedAt => Column::UpdatedAt,
        JobSortBy::Attempts => Column::Attempts,
    }
}

/// `CAST(col AS TEXT)` on every backend except MySQL, whose `CAST` has no `TEXT` target
/// (`CHAR` is its equivalent) — the one dialect difference [`SeaOrmJobQueueStore::list_jobs`]'s
/// free-text search (over `id`/`payload`/`last_error`) can't avoid, since it needs to
/// compare a JSON column and an integer column against a plain string pattern.
///
/// **`cust_with_expr`'s template marker isn't `$1` on every backend** (found live, not
/// guessed — the first version of this function hardcoded `$1` and every search silently
/// matched nothing on SQLite): `sea_query`'s `QueryBuilder::placeholder()` is `("$", true)`
/// only for Postgres; MySQL and SQLite both use the default `("?", false)`, so `$1` in a
/// `cust_with_expr` string against those backends isn't recognized as a substitution marker
/// at all — it's tokenized and written out *literally* as the four characters `$1`, and the
/// column reference never gets inlined, so the generated `WHERE` clause silently compares
/// against the literal text `"$1"` instead of the column. Branching the marker text by
/// backend (`$1` vs plain `?`) is what actually makes this portable, not just the `CAST`
/// target name.
fn cast_to_text(backend: DatabaseBackend, column: Column) -> SimpleExpr {
    let target = if backend == DatabaseBackend::MySql {
        "CHAR"
    } else {
        "TEXT"
    };
    let marker = if backend == DatabaseBackend::Postgres {
        "$1"
    } else {
        "?"
    };
    Expr::cust_with_expr(format!("CAST({marker} AS {target})"), Expr::col(column))
}

/// The sea-orm-backed implementation, replacing the old `PostgresJobQueueStore`/
/// `SqliteJobQueueStore`/`InMemoryJobQueueStore` trio (2026-08-18 multi-DB rewrite — see
/// `discovery_config_store::SeaOrmSettingsStore`'s docs for the full rationale).
///
/// **[`Self::claim`]'s `FOR UPDATE SKIP LOCKED` turned out not to need a raw-SQL escape
/// hatch after all** — the original plan assumed one would be necessary (sea-orm's query
/// *builder*, as opposed to hand-written SQL, seemed unlikely to expose row-locking
/// clauses portably). In fact `QuerySelect::lock_with_behavior(LockType::Update,
/// LockBehavior::SkipLocked)` does exactly this, and `sea-query`'s SQLite backend simply
/// overrides its `prepare_select_lock` to emit nothing at all (verified by reading
/// `sea-query`'s own backend source, not assumed) — so the same builder call works on
/// Postgres and MySQL (which both support the clause) and silently degrades to a plain
/// `SELECT` on SQLite (which doesn't need it: SQLite already serializes writers at the
/// file-lock level, the same reasoning the pre-rewrite hand-written `SqliteJobQueueStore`
/// documented). One code path, no backend branch, for the one operation in this project
/// most likely to have needed one.
pub struct SeaOrmJobQueueStore {
    db: DatabaseConnection,
}

impl SeaOrmJobQueueStore {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Convenience for tests — see `discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests`'s
    /// docs for why this exists and why it's async.
    pub async fn new_in_memory_for_tests() -> Self {
        Self::new(discovery_migration::connect_in_memory_for_tests().await)
    }
}

#[async_trait]
impl JobQueueStore for SeaOrmJobQueueStore {
    async fn enqueue(
        &self,
        queue: QueueKind,
        payload: serde_json::Value,
        dedupe_key: Option<&str>,
    ) -> anyhow::Result<i64> {
        if let Some(key) = dedupe_key {
            let base = Entity::find()
                .filter(Column::QueueType.eq(queue.as_str()))
                .filter(Column::DedupeKey.eq(key));
            let active = Condition::any()
                .add(Column::State.eq(state_to_str(JobState::Pending)))
                .add(Column::State.eq(state_to_str(JobState::InProgress)));
            if queue == QueueKind::OperatorAction {
                let recent = base
                    .filter(
                        Condition::any()
                            .add(active)
                            .add(Column::CreatedAt.gte(Utc::now() - chrono::Duration::seconds(30))),
                    )
                    .all(&self.db)
                    .await?;
                if recent.iter().any(|existing| {
                    matches!(
                        state_from_str(&existing.state),
                        JobState::Pending | JobState::InProgress
                    ) || (state_from_str(&existing.state) != JobState::Cancelled
                        && existing.payload.get("action") == payload.get("action"))
                }) {
                    return Ok(-1);
                }
            } else if base.filter(active).one(&self.db).await?.is_some() {
                return Ok(-1);
            }
        }

        let now = Utc::now();
        let am = ActiveModel {
            id: sea_orm::ActiveValue::NotSet,
            queue_type: Set(queue.as_str().to_string()),
            payload: Set(payload),
            dedupe_key: Set(dedupe_key.map(|s| s.to_string())),
            state: Set(state_to_str(JobState::Pending).to_string()),
            attempts: Set(0),
            max_attempts: Set(if queue == QueueKind::OperatorAction {
                1
            } else {
                5
            }),
            locked_by: Set(None),
            locked_at: Set(None),
            last_error: Set(None),
            result: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
            paused: Set(false),
        };
        let inserted = am.insert(&self.db).await?;
        Ok(inserted.id)
    }

    async fn claim(
        &self,
        queue: QueueKind,
        worker_id: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<Job>> {
        // Whole-queue pause short-circuits before touching `jobs` at all — see
        // `JobQueueStore::set_queue_paused`'s docs. Checked outside the transaction below
        // on purpose: this is a cheap, separate table, and a pause flipping mid-claim just
        // means the operator's toggle takes effect on this call or the very next one, not
        // a correctness issue worth serializing against.
        if self.is_queue_paused(queue).await? {
            return Ok(vec![]);
        }

        let txn = self.db.begin().await?;

        let candidates = Entity::find()
            .filter(Column::QueueType.eq(queue.as_str()))
            .filter(Column::State.eq(state_to_str(JobState::Pending)))
            .filter(Column::Paused.eq(false))
            .order_by_asc(Column::Id)
            .limit(limit.max(0) as u64)
            .lock_with_behavior(LockType::Update, LockBehavior::SkipLocked)
            .all(&txn)
            .await?;

        if candidates.is_empty() {
            txn.commit().await?;
            return Ok(vec![]);
        }

        let ids: Vec<i64> = candidates.iter().map(|c| c.id).collect();
        let now = Utc::now();
        Entity::update_many()
            .filter(Column::Id.is_in(ids.clone()))
            .col_expr(
                Column::State,
                Expr::value(state_to_str(JobState::InProgress)),
            )
            .col_expr(Column::LockedBy, Expr::value(worker_id))
            .col_expr(Column::LockedAt, Expr::value(now))
            .col_expr(Column::Attempts, Expr::col(Column::Attempts).add(1))
            .col_expr(Column::UpdatedAt, Expr::value(now))
            .exec(&txn)
            .await?;

        let updated = Entity::find()
            .filter(Column::Id.is_in(ids))
            .order_by_asc(Column::Id)
            .all(&txn)
            .await?;
        txn.commit().await?;

        updated.into_iter().map(model_to_job).collect()
    }

    async fn complete(&self, job_id: i64) -> anyhow::Result<()> {
        if let Some(model) = Entity::find_by_id(job_id).one(&self.db).await? {
            if model.queue_type == QueueKind::OperatorAction.as_str() {
                let mut active: ActiveModel = model.into();
                active.state = Set(state_to_str(JobState::Done).to_string());
                active.updated_at = Set(Utc::now());
                active.update(&self.db).await?;
                // Operator jobs are human-scale history, retained for 30 days only.
                Entity::delete_many()
                    .filter(Column::QueueType.eq(QueueKind::OperatorAction.as_str()))
                    .filter(
                        Condition::any()
                            .add(Column::State.eq(state_to_str(JobState::Done)))
                            .add(Column::State.eq(state_to_str(JobState::Cancelled)))
                            .add(Column::State.eq(state_to_str(JobState::Failed))),
                    )
                    .filter(Column::UpdatedAt.lt(Utc::now() - chrono::Duration::days(30)))
                    .exec(&self.db)
                    .await?;
                return Ok(());
            }
        }
        Entity::delete_by_id(job_id).exec(&self.db).await?;
        Ok(())
    }

    async fn fail(&self, job_id: i64, error: &str) -> anyhow::Result<()> {
        let Some(model) = Entity::find_by_id(job_id).one(&self.db).await? else {
            return Ok(());
        };
        let exhausted = model.attempts >= model.max_attempts;
        let mut am: ActiveModel = model.into();
        am.last_error = Set(Some(error.to_string()));
        am.updated_at = Set(Utc::now());
        am.state = Set(state_to_str(if exhausted {
            JobState::Failed
        } else {
            JobState::Pending
        })
        .to_string());
        if !exhausted {
            am.locked_by = Set(None);
            am.locked_at = Set(None);
        }
        am.update(&self.db).await?;
        Ok(())
    }

    async fn reclaim_stale(&self, older_than: chrono::Duration) -> anyhow::Result<u64> {
        let cutoff = Utc::now() - older_than;
        let result = Entity::update_many()
            .filter(Column::State.eq(state_to_str(JobState::InProgress)))
            .filter(Column::LockedAt.lt(cutoff))
            .col_expr(Column::State, Expr::value(state_to_str(JobState::Pending)))
            .col_expr(Column::LockedBy, Expr::value(Option::<String>::None))
            .col_expr(Column::LockedAt, Expr::value(Option::<DateTime<Utc>>::None))
            .col_expr(Column::UpdatedAt, Expr::value(Utc::now()))
            .exec(&self.db)
            .await?;
        Ok(result.rows_affected)
    }

    async fn stats(&self, queue: QueueKind) -> anyhow::Result<QueueStats> {
        let base = Entity::find().filter(Column::QueueType.eq(queue.as_str()));
        let pending = base
            .clone()
            .filter(Column::State.eq(state_to_str(JobState::Pending)))
            .count(&self.db)
            .await?;
        let in_progress = base
            .clone()
            .filter(Column::State.eq(state_to_str(JobState::InProgress)))
            .count(&self.db)
            .await?;
        let failed = base
            .clone()
            .filter(Column::State.eq(state_to_str(JobState::Failed)))
            .count(&self.db)
            .await?;
        let paused = base.filter(Column::Paused.eq(true)).count(&self.db).await?;
        let queue_paused = self.is_queue_paused(queue).await?;
        Ok(QueueStats {
            pending: pending as i64,
            in_progress: in_progress as i64,
            failed: failed as i64,
            paused: paused as i64,
            queue_paused,
        })
    }

    async fn delete_job(&self, job_id: i64) -> anyhow::Result<bool> {
        let result = Entity::delete_by_id(job_id).exec(&self.db).await?;
        Ok(result.rows_affected > 0)
    }

    async fn cancel_pending_action(&self, job_id: i64) -> anyhow::Result<bool> {
        Ok(Entity::update_many()
            .filter(Column::Id.eq(job_id))
            .filter(Column::QueueType.eq(QueueKind::OperatorAction.as_str()))
            .filter(Column::State.eq(state_to_str(JobState::Pending)))
            .col_expr(
                Column::State,
                Expr::value(state_to_str(JobState::Cancelled)),
            )
            .col_expr(Column::UpdatedAt, Expr::value(Utc::now()))
            .exec(&self.db)
            .await?
            .rows_affected
            > 0)
    }

    async fn pause_job(&self, job_id: i64) -> anyhow::Result<bool> {
        let result = Entity::update_many()
            .filter(Column::Id.eq(job_id))
            .col_expr(Column::Paused, Expr::value(true))
            .col_expr(Column::UpdatedAt, Expr::value(Utc::now()))
            .exec(&self.db)
            .await?;
        Ok(result.rows_affected > 0)
    }

    async fn resume_job(&self, job_id: i64) -> anyhow::Result<bool> {
        let result = Entity::update_many()
            .filter(Column::Id.eq(job_id))
            .col_expr(Column::Paused, Expr::value(false))
            .col_expr(Column::UpdatedAt, Expr::value(Utc::now()))
            .exec(&self.db)
            .await?;
        Ok(result.rows_affected > 0)
    }

    async fn clear_queue(&self, queue: QueueKind, state: Option<JobState>) -> anyhow::Result<u64> {
        let mut cond = Condition::all().add(Column::QueueType.eq(queue.as_str()));
        if let Some(state) = state {
            cond = cond.add(Column::State.eq(state_to_str(state)));
        }
        let result = Entity::delete_many().filter(cond).exec(&self.db).await?;
        Ok(result.rows_affected)
    }

    async fn is_queue_paused(&self, queue: QueueKind) -> anyhow::Result<bool> {
        use discovery_entities::queue_control::{Column as QcColumn, Entity as QcEntity};
        let row = QcEntity::find()
            .filter(QcColumn::QueueType.eq(queue.as_str()))
            .one(&self.db)
            .await?;
        Ok(row.map(|r| r.paused).unwrap_or(false))
    }

    async fn set_queue_paused(&self, queue: QueueKind, paused: bool) -> anyhow::Result<()> {
        use discovery_entities::queue_control::{
            ActiveModel as QcActiveModel, Column as QcColumn, Entity as QcEntity,
        };
        let existing = QcEntity::find()
            .filter(QcColumn::QueueType.eq(queue.as_str()))
            .one(&self.db)
            .await?;
        match existing {
            Some(model) => {
                let mut am: QcActiveModel = model.into();
                am.paused = Set(paused);
                am.update(&self.db).await?;
            }
            None => {
                let am = QcActiveModel {
                    queue_type: Set(queue.as_str().to_string()),
                    paused: Set(paused),
                };
                am.insert(&self.db).await?;
            }
        }
        Ok(())
    }

    async fn state_of(&self, job_id: i64) -> anyhow::Result<Option<JobState>> {
        Ok(Entity::find_by_id(job_id)
            .one(&self.db)
            .await?
            .map(|m| state_from_str(&m.state)))
    }

    async fn get_job(&self, job_id: i64) -> anyhow::Result<Option<Job>> {
        Entity::find_by_id(job_id)
            .one(&self.db)
            .await?
            .map(model_to_job)
            .transpose()
    }

    async fn set_result(&self, job_id: i64, result: serde_json::Value) -> anyhow::Result<()> {
        if let Some(model) = Entity::find_by_id(job_id).one(&self.db).await? {
            if model.queue_type != QueueKind::OperatorAction.as_str() {
                anyhow::bail!("result is only supported for operator actions");
            }
            let mut active: ActiveModel = model.into();
            active.result = Set(Some(result));
            active.updated_at = Set(Utc::now());
            active.update(&self.db).await?;
        }
        Ok(())
    }

    async fn list_jobs(
        &self,
        queue: QueueKind,
        query: &JobListQuery,
    ) -> anyhow::Result<JobListPage> {
        let backend = self.db.get_database_backend();
        let mut cond = Condition::all().add(Column::QueueType.eq(queue.as_str()));
        if let Some(state) = query.state {
            cond = cond.add(Column::State.eq(state_to_str(state)));
        }
        // Not escaping literal `%`/`_` in `search` on purpose — same call as the old
        // hand-written backends made, see their docs: a dashboard search box for a
        // testing tool, not a security boundary.
        if let Some(search) = query
            .search
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let needle = format!("%{}%", search.to_lowercase());
            cond = cond.add(
                Condition::any()
                    .add(
                        Expr::expr(Func::lower(cast_to_text(backend, Column::Id)))
                            .like(needle.clone()),
                    )
                    .add(
                        Expr::expr(Func::lower(cast_to_text(backend, Column::Payload)))
                            .like(needle.clone()),
                    )
                    .add(
                        Expr::expr(Func::lower(Func::coalesce([
                            Expr::col(Column::LastError).into(),
                            Expr::val("").into(),
                        ])))
                        .like(needle),
                    ),
            );
        }

        let total = Entity::find().filter(cond.clone()).count(&self.db).await? as i64;

        let order = if query.sort_dir == SortDir::Asc {
            Order::Asc
        } else {
            Order::Desc
        };
        let models = Entity::find()
            .filter(cond)
            .order_by(sort_column(query.sort_by), order)
            .order_by(Column::Id, Order::Asc) // stable tiebreaker, same convention as every other list() in this project
            .limit(query.limit.max(0) as u64)
            .offset(query.offset.max(0) as u64)
            .all(&self.db)
            .await?;

        Ok(JobListPage {
            jobs: models
                .into_iter()
                .map(model_to_job)
                .collect::<anyhow::Result<_>>()?,
            total,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_store() -> SeaOrmJobQueueStore {
        SeaOrmJobQueueStore::new_in_memory_for_tests().await
    }

    #[tokio::test]
    async fn operator_action_keeps_result_and_cancellation_without_blocking_next_request() {
        let store = test_store().await;
        let id = store
            .enqueue(
                QueueKind::OperatorAction,
                serde_json::json!({"action": "test"}),
                Some("device-1"),
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .enqueue(
                    QueueKind::OperatorAction,
                    serde_json::json!({}),
                    Some("device-1")
                )
                .await
                .unwrap(),
            -1
        );
        let claimed = store
            .claim(QueueKind::OperatorAction, "operator", 1)
            .await
            .unwrap();
        assert_eq!(claimed[0].id, id);
        assert!(!store.cancel_pending_action(id).await.unwrap());
        store
            .set_result(id, serde_json::json!({"ok": true}))
            .await
            .unwrap();
        store.complete(id).await.unwrap();
        let done = store.get_job(id).await.unwrap().unwrap();
        assert_eq!(done.state, JobState::Done);
        assert_eq!(done.result.unwrap()["ok"], true);
        let next = store
            .enqueue(
                QueueKind::OperatorAction,
                serde_json::json!({}),
                Some("device-1"),
            )
            .await
            .unwrap();
        assert!(next > id);
        assert!(store.cancel_pending_action(next).await.unwrap());
        assert_eq!(
            store.get_job(next).await.unwrap().unwrap().state,
            JobState::Cancelled
        );
    }

    #[tokio::test]
    async fn claim_marks_in_progress_and_hides_from_further_claims() {
        let store = test_store().await;
        let id = store
            .enqueue(
                QueueKind::Discovery,
                serde_json::json!({"ip": "1.2.3.4"}),
                None,
            )
            .await
            .unwrap();
        assert!(id > 0);

        let claimed = store
            .claim(QueueKind::Discovery, "worker-1", 10)
            .await
            .unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].id, id);
        assert_eq!(claimed[0].payload["ip"], "1.2.3.4");

        let claimed_again = store
            .claim(QueueKind::Discovery, "worker-2", 10)
            .await
            .unwrap();
        assert!(
            claimed_again.is_empty(),
            "job already claimed must not be claimable twice"
        );
    }

    #[tokio::test]
    async fn dedupe_key_prevents_duplicate_pending_jobs() {
        let store = test_store().await;
        let first = store
            .enqueue(QueueKind::SnmpPoll, serde_json::json!({}), Some("10.0.0.1"))
            .await
            .unwrap();
        let second = store
            .enqueue(QueueKind::SnmpPoll, serde_json::json!({}), Some("10.0.0.1"))
            .await
            .unwrap();
        assert!(first > 0);
        assert_eq!(
            second, -1,
            "duplicate dedupe key while first job still pending must be rejected"
        );

        // Once the first job finishes, the same key must be enqueueable again.
        store
            .claim(QueueKind::SnmpPoll, "worker-1", 1)
            .await
            .unwrap();
        store.complete(first).await.unwrap();
        let third = store
            .enqueue(QueueKind::SnmpPoll, serde_json::json!({}), Some("10.0.0.1"))
            .await
            .unwrap();
        assert!(third > 0);
    }

    #[tokio::test]
    async fn failed_job_is_retried_until_max_attempts_then_marked_failed() {
        let store = test_store().await;
        store
            .enqueue(QueueKind::MetricPoll, serde_json::json!({}), None)
            .await
            .unwrap();

        for _ in 0..5 {
            let claimed = store
                .claim(QueueKind::MetricPoll, "worker-1", 1)
                .await
                .unwrap();
            let job = claimed.into_iter().next().unwrap();
            store.fail(job.id, "boom").await.unwrap();
        }

        let stats = store.stats(QueueKind::MetricPoll).await.unwrap();
        assert_eq!(stats.failed, 1);
        assert_eq!(stats.pending, 0);
    }

    #[tokio::test]
    async fn reclaim_stale_returns_jobs_to_pending() {
        let store = test_store().await;
        let id = store
            .enqueue(QueueKind::AlertEval, serde_json::json!({}), None)
            .await
            .unwrap();
        store
            .claim(QueueKind::AlertEval, "worker-1", 1)
            .await
            .unwrap();

        // Nothing stale yet.
        let reclaimed = store
            .reclaim_stale(chrono::Duration::minutes(5))
            .await
            .unwrap();
        assert_eq!(reclaimed, 0);

        // A lock older than the threshold must be requeued — simulate the passage of time
        // by reclaiming against a threshold shorter than "just now" instead of mutating the
        // row directly (no direct field access into a private in-memory `Vec` the way the
        // old `InMemoryJobQueueStore` test could — this is the store's own public API,
        // exactly what production code sees too).
        let reclaimed = store
            .reclaim_stale(chrono::Duration::milliseconds(-1))
            .await
            .unwrap();
        assert_eq!(reclaimed, 1);
        assert_eq!(store.state_of(id).await.unwrap(), Some(JobState::Pending));
    }

    fn job_query(state: Option<JobState>) -> JobListQuery {
        JobListQuery {
            state,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn list_jobs_filters_by_queue_and_state_and_carries_the_payload() {
        let store = test_store().await;
        // `claim` claims the oldest matching pending job first (insertion order), so this
        // first-enqueued Discovery job is the one that ends up in_progress below.
        let first_id = store
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
        store
            .enqueue(
                QueueKind::SnmpPoll,
                serde_json::json!({"ip": "10.0.0.3"}),
                None,
            )
            .await
            .unwrap();
        store
            .claim(QueueKind::Discovery, "worker-1", 1)
            .await
            .unwrap();

        let discovery_page = store
            .list_jobs(QueueKind::Discovery, &job_query(None))
            .await
            .unwrap();
        assert_eq!(
            discovery_page.jobs.len(),
            2,
            "must not include the SnmpPoll job"
        );
        assert_eq!(discovery_page.total, 2);

        let pending_only = store
            .list_jobs(QueueKind::Discovery, &job_query(Some(JobState::Pending)))
            .await
            .unwrap();
        assert_eq!(pending_only.jobs.len(), 1);
        assert_eq!(pending_only.jobs[0].payload["ip"], "10.0.0.2");

        let in_progress_only = store
            .list_jobs(QueueKind::Discovery, &job_query(Some(JobState::InProgress)))
            .await
            .unwrap();
        assert_eq!(in_progress_only.jobs.len(), 1);
        assert_eq!(in_progress_only.jobs[0].id, first_id);
        assert_eq!(in_progress_only.jobs[0].payload["ip"], "10.0.0.1");

        let capped = store
            .list_jobs(
                QueueKind::Discovery,
                &JobListQuery {
                    limit: 1,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(capped.jobs.len(), 1, "limit must be respected");
        assert_eq!(
            capped.total, 2,
            "total must reflect the full match count, not just this page"
        );
    }

    #[tokio::test]
    async fn list_jobs_supports_search_sort_and_pagination() {
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
        store
            .enqueue(
                QueueKind::Discovery,
                serde_json::json!({"ip": "192.168.1.1"}),
                None,
            )
            .await
            .unwrap();

        // Search matches the payload text, case-insensitively.
        let searched = store
            .list_jobs(
                QueueKind::Discovery,
                &JobListQuery {
                    search: Some("192.168".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(searched.jobs.len(), 1);
        assert_eq!(searched.jobs[0].payload["ip"], "192.168.1.1");

        // Sort by id ascending — insertion order, since ids are assigned sequentially.
        let sorted_asc = store
            .list_jobs(
                QueueKind::Discovery,
                &JobListQuery {
                    sort_by: JobSortBy::Id,
                    sort_dir: SortDir::Asc,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let ips: Vec<&str> = sorted_asc
            .jobs
            .iter()
            .map(|j| j.payload["ip"].as_str().unwrap())
            .collect();
        assert_eq!(ips, vec!["10.0.0.1", "10.0.0.2", "192.168.1.1"]);

        // Pagination: page 2 of size 1, sorted by id ascending, must be the second job.
        let page2 = store
            .list_jobs(
                QueueKind::Discovery,
                &JobListQuery {
                    sort_by: JobSortBy::Id,
                    sort_dir: SortDir::Asc,
                    limit: 1,
                    offset: 1,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(page2.jobs.len(), 1);
        assert_eq!(page2.jobs[0].payload["ip"], "10.0.0.2");
        assert_eq!(
            page2.total, 3,
            "total must reflect all matching rows, not just this page's size"
        );
    }

    #[tokio::test]
    async fn delete_job_removes_it_and_is_idempotent_on_missing_id() {
        let store = test_store().await;
        let id = store
            .enqueue(QueueKind::Discovery, serde_json::json!({}), None)
            .await
            .unwrap();

        assert!(
            store.delete_job(id).await.unwrap(),
            "must report it actually deleted a row"
        );
        assert_eq!(store.state_of(id).await.unwrap(), None, "job must be gone");
        assert!(
            !store.delete_job(id).await.unwrap(),
            "deleting an already-gone id must not error, just report false"
        );
        assert!(
            !store.delete_job(999_999).await.unwrap(),
            "deleting a never-existed id must not error either"
        );
    }

    #[tokio::test]
    async fn paused_job_stays_pending_but_is_never_claimed_until_resumed() {
        let store = test_store().await;
        let id = store
            .enqueue(QueueKind::Discovery, serde_json::json!({}), None)
            .await
            .unwrap();

        assert!(store.pause_job(id).await.unwrap());
        assert_eq!(
            store.state_of(id).await.unwrap(),
            Some(JobState::Pending),
            "pause must not change state — it stays wherever it was"
        );

        let claimed = store
            .claim(QueueKind::Discovery, "worker-1", 10)
            .await
            .unwrap();
        assert!(claimed.is_empty(), "a paused job must never be claimed");

        assert!(store.resume_job(id).await.unwrap());
        let claimed = store
            .claim(QueueKind::Discovery, "worker-1", 10)
            .await
            .unwrap();
        assert_eq!(claimed.len(), 1, "resuming must make it claimable again");
        assert_eq!(claimed[0].id, id);
    }

    #[tokio::test]
    async fn pause_and_resume_report_false_for_unknown_job() {
        let store = test_store().await;
        assert!(!store.pause_job(424_242).await.unwrap());
        assert!(!store.resume_job(424_242).await.unwrap());
    }

    #[tokio::test]
    async fn whole_queue_pause_blocks_claim_regardless_of_individual_job_pause_state() {
        let store = test_store().await;
        store
            .enqueue(
                QueueKind::Discovery,
                serde_json::json!({"ip": "1.1.1.1"}),
                None,
            )
            .await
            .unwrap();
        store
            .enqueue(
                QueueKind::Discovery,
                serde_json::json!({"ip": "2.2.2.2"}),
                None,
            )
            .await
            .unwrap();
        // A different queue must stay unaffected — pausing is per-QueueKind, not global.
        store
            .enqueue(QueueKind::MetricPoll, serde_json::json!({}), None)
            .await
            .unwrap();

        assert!(
            !store.is_queue_paused(QueueKind::Discovery).await.unwrap(),
            "a queue must start unpaused with no row seeded up front"
        );

        store
            .set_queue_paused(QueueKind::Discovery, true)
            .await
            .unwrap();
        assert!(store.is_queue_paused(QueueKind::Discovery).await.unwrap());

        let claimed = store
            .claim(QueueKind::Discovery, "worker-1", 10)
            .await
            .unwrap();
        assert!(claimed.is_empty(), "claim must return nothing while the queue is paused, even though jobs are pending and individually unpaused");

        let other = store
            .claim(QueueKind::MetricPoll, "worker-1", 10)
            .await
            .unwrap();
        assert_eq!(
            other.len(),
            1,
            "pausing Discovery must not affect MetricPoll's claim"
        );

        store
            .set_queue_paused(QueueKind::Discovery, false)
            .await
            .unwrap();
        let claimed = store
            .claim(QueueKind::Discovery, "worker-1", 10)
            .await
            .unwrap();
        assert_eq!(claimed.len(), 2, "unpausing must restore normal claiming");
    }

    #[tokio::test]
    async fn stats_reports_paused_job_count_and_queue_paused_flag() {
        let store = test_store().await;
        let id1 = store
            .enqueue(QueueKind::Discovery, serde_json::json!({}), None)
            .await
            .unwrap();
        store
            .enqueue(QueueKind::Discovery, serde_json::json!({}), None)
            .await
            .unwrap();
        store.pause_job(id1).await.unwrap();

        let stats = store.stats(QueueKind::Discovery).await.unwrap();
        assert_eq!(
            stats.pending, 2,
            "paused jobs are still pending — pause is orthogonal to state"
        );
        assert_eq!(stats.paused, 1);
        assert!(!stats.queue_paused);

        store
            .set_queue_paused(QueueKind::Discovery, true)
            .await
            .unwrap();
        let stats = store.stats(QueueKind::Discovery).await.unwrap();
        assert!(stats.queue_paused);
    }

    #[tokio::test]
    async fn clear_queue_deletes_everything_by_default_and_only_matching_state_when_scoped() {
        let store = test_store().await;
        // Enqueued first (smaller id) so `claim`'s oldest-first ordering always hands this
        // one back first, for as long as it stays `pending` — keeping `pending_id` (below)
        // untouched until this one is terminal (`Failed`).
        let to_fail_id = store
            .enqueue(
                QueueKind::Discovery,
                serde_json::json!({"ip": "2.2.2.2"}),
                None,
            )
            .await
            .unwrap();
        let pending_id = store
            .enqueue(
                QueueKind::Discovery,
                serde_json::json!({"ip": "1.1.1.1"}),
                None,
            )
            .await
            .unwrap();
        store
            .enqueue(QueueKind::MetricPoll, serde_json::json!({}), None)
            .await
            .unwrap();

        // Drive `to_fail_id` to `failed` (exactly `max_attempts` = 5 claim+fail cycles —
        // each `fail` below `max_attempts` requeues it to `pending`, so it's still the
        // oldest pending job on every one of these 5 iterations).
        for _ in 0..5 {
            let claimed = store
                .claim(QueueKind::Discovery, "worker-1", 1)
                .await
                .unwrap();
            assert_eq!(
                claimed[0].id, to_fail_id,
                "must always reclaim the still-pending to_fail_id, never touching pending_id"
            );
            store.fail(claimed[0].id, "boom").await.unwrap();
        }
        assert_eq!(
            store.state_of(to_fail_id).await.unwrap(),
            Some(JobState::Failed)
        );

        // Scoped clear: only failed jobs go, pending survives.
        let deleted = store
            .clear_queue(QueueKind::Discovery, Some(JobState::Failed))
            .await
            .unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(
            store.state_of(pending_id).await.unwrap(),
            Some(JobState::Pending)
        );
        assert_eq!(store.state_of(to_fail_id).await.unwrap(), None);

        // Full clear: everything left in Discovery goes, MetricPoll is untouched.
        let deleted = store.clear_queue(QueueKind::Discovery, None).await.unwrap();
        assert_eq!(deleted, 1);
        let discovery_stats = store.stats(QueueKind::Discovery).await.unwrap();
        assert_eq!(
            discovery_stats.pending + discovery_stats.in_progress + discovery_stats.failed,
            0
        );
        let metric_stats = store.stats(QueueKind::MetricPoll).await.unwrap();
        assert_eq!(
            metric_stats.pending, 1,
            "clearing Discovery must not touch MetricPoll"
        );
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

        let claimed = store
            .claim(QueueKind::Discovery, "worker-1", 10)
            .await
            .unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].queue, QueueKind::Discovery);
    }
}
