//! `jobs` — the crash-safe job queue (`migrations/0001_jobs.sql`'s final shape). See
//! `discovery_queue::JobQueueStore`'s docs for the domain-level contract this table
//! backs; this is purely the sea-orm mapping onto it, shared by every backend
//! (`DbKind::Postgres`/`MySql`/`Sqlite`/`Memory`) — one query-building code path instead
//! of the three hand-written dialects that existed before 2026-08-18's multi-DB rewrite.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "jobs")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub queue_type: String,
    #[sea_orm(column_type = "Json")]
    pub payload: Json,
    pub dedupe_key: Option<String>,
    /// "pending" | "in_progress" | "failed" — no "done", see
    /// `discovery_queue::JobQueueStore::complete`'s docs (a finished job's row is deleted
    /// outright, never archived in a terminal state).
    pub state: String,
    pub attempts: i32,
    pub max_attempts: i32,
    pub locked_by: Option<String>,
    pub locked_at: Option<DateTimeUtc>,
    pub last_error: Option<String>,
    #[sea_orm(column_type = "Json")]
    pub result: Option<Json>,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
    /// Per-job pause (2026-08-21) — orthogonal to `state`: a paused job stays wherever it
    /// currently is (usually `pending`) but `JobQueueStore::claim`'s query excludes it, so
    /// it's visible/searchable but never picked up by a worker until resumed. See
    /// `discovery_queue::JobQueueStore::pause_job`'s docs.
    pub paused: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
