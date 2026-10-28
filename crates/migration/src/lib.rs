//! `discovery-migration` — the schema for every table `discovery-entities` maps onto,
//! defined once via `sea_orm_migration`'s backend-agnostic `SchemaManager` DSL instead of
//! the old hand-written `migrations/*.sql` (Postgres dialect) + `migrations_sqlite/*.sql`
//! (SQLite dialect) pair — direct user request 2026-08-18: "discovery должен уметь
//! подключаться к разным СУБД... тебе нужно будет подключить orm для этой задачи". The
//! same `up()` below runs correctly against Postgres, MySQL, or SQLite — whichever
//! `DatabaseConnection` `discovery-db::ConnectionRegistry` hands it — without a third
//! hand-written MySQL dialect ever needing to exist.
//!
//! **One migration for the initial schema, not 23** — this project already had a "no
//! backward-compat needed, schema recreated from scratch" discipline before this (see
//! `discovery/CLAUDE.md`'s "Нормализация схемы БД" section: "проект в активной разработке,
//! обратная совместимость БД не нужна"); replaying 23 increments of `ALTER TABLE` history
//! through `sea_orm_migration` would just be more code for the same end state
//! `migrations/*.sql`'s *final* shape already describes. `m20260818_000001_initial_schema`
//! is written directly in its current, final form (column list cross-checked against every
//! `migrations/*.sql` file, including every later `ALTER` folded in) — see
//! `discovery-entities`'s per-module docs for exactly which `.sql` file each table traces
//! back to.
//!
//! **A schema change to an already-shipped table is a *new* migration, though — not
//! another edit to that same file.** Found live, 2026-09-18, the hard way: every "add a
//! column to an existing table" retrofit up to that point (`jobs.paused`,
//! `devices.snmp_auth`/`ssh_*`/`ping_loss_pct`/`ip_sort_key`, `profile_metrics.*`,
//! `profile_alerts.*`, `discovery_subnets.credentials`, `discovery_subnet_oids.columns`,
//! `alerts.*`) had been added as a `has_column`-guarded block appended directly into
//! `m20260818_000001_initial_schema`'s own `up()` — correct for avoiding a duplicate-
//! column crash on a *fresh* install (where the column already exists via that same
//! migration's own `CREATE TABLE`, in the same `up()` call), but silently **inert** for
//! the case the guard's own comments claimed to handle: `MigratorTrait::up()` only calls
//! `up()` on migrations not yet recorded in `seaql_migrations` (this crate's
//! `sea-orm-migration` dependency's own `get_pending_migrations`) — editing an
//! already-applied migration's body has zero effect on a database that already ran it.
//! `m20260918_000002_column_retrofit_for_already_migrated_installs` fixes this — every one
//! of those guarded blocks duplicated verbatim into a migration `sea-orm-migration` will
//! actually re-evaluate against an install that ran the first migration before any of them
//! existed. See that file's own docs for the live reproduction. Any future "add a column
//! to a table this project has already released" change follows that same pattern — a new
//! migration file, registered below — never a further edit to either of these two.
//!
//! **`.if_not_exists()` on every table** — same idempotency the old `CREATE TABLE IF NOT
//! EXISTS` migrations had, load-bearing for the already-running Postgres dev stand: table/
//! column names are unchanged, so this migration must be safe to run against a database
//! that already has all fifteen tables from the pre-2026-08-18 code, not just a fresh one.
//!
//! **JSON, not Postgres-specific JSONB** — `ColumnDef::json()`, not `.json_binary()`: the
//! whole point of one migration for three backends is portability, and JSONB has no MySQL/
//! SQLite equivalent. Deliberate tradeoff (loses Postgres's binary-JSON storage/indexing
//! upside) in exchange for a single real schema definition instead of three.
//!
//! **No `FOREIGN KEY` on `device_metrics.device_id`/`device_metric_history.device_id`/
//! `alerts.device_id`** — see `discovery-entities`'s `device_metrics`/`alerts` module docs
//! for why: those tables' routing domains ("Метрики устройств"/"Тревоги") can resolve to a
//! *different* physical database than `devices` ("Устройства"), where a cross-database FK
//! is not physically possible. `DeviceStore::delete`/`delete_unreachable_since` clean up
//! the matching rows explicitly in application code instead — see that crate's docs.
//! Every *same-domain* reference (`profile_metrics`/`profile_alerts` -> `profiles`,
//! `discovery_subnets` -> `discovery_configs`, `discovery_subnet_oids`/`labels` ->
//! `discovery_subnets`, `device_metric_settings` -> `devices`) keeps a real, DB-enforced
//! `ON DELETE CASCADE` FK, because both sides of each of those always share one connection
//! by construction.

use sea_orm_migration::prelude::*;

mod m20260818_000001_initial_schema;
mod m20260918_000002_column_retrofit_for_already_migrated_installs;
mod m20260925_000003_alert_operator_states;
mod m20260925_000004_alert_escalation;
mod m20260925_000005_operator_action_result;
mod m20260925_000006_alert_hysteresis_and_flapping;

mod m20261003_000007_alert_capabilities;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260818_000001_initial_schema::Migration),
            Box::new(m20260918_000002_column_retrofit_for_already_migrated_installs::Migration),
            Box::new(m20260925_000003_alert_operator_states::Migration),
            Box::new(m20260925_000004_alert_escalation::Migration),
            Box::new(m20260925_000005_operator_action_result::Migration),
            Box::new(m20260925_000006_alert_hysteresis_and_flapping::Migration),
            Box::new(m20261003_000007_alert_capabilities::Migration),
        ]
    }
}

/// Opens a fresh, isolated `sqlite::memory:` connection with every migration already
/// applied — the exact fixture every sea-orm store crate's own `new_in_memory_for_tests()`
/// needs, centralized here instead of duplicated per crate (which is how the first few
/// sea-orm store rewrites — `SeaOrmSettingsStore`/`SeaOrmAlertStore`/`SeaOrmLogStore`/
/// `SeaOrmJobQueueStore` — originally did it).
///
/// **Also sets `PRAGMA foreign_keys = ON`** — a real gap found while writing the next store
/// after those four: `sea_orm::Database::connect` does **not** enable SQLite foreign-key
/// enforcement by default (unlike this project's pre-2026-08-18 hand-written
/// `SqliteConnectOptions::foreign_keys(true)`, which every `main.rs` storage branch set
/// explicitly). Without it, every same-domain `ON DELETE CASCADE` this migration declares
/// (`profile_metrics`/`profile_alerts` -> `profiles`, `discovery_subnets` ->
/// `discovery_configs`, `discovery_subnet_oids`/`labels` -> `discovery_subnets`,
/// `device_metric_settings` -> `devices` — see this crate's module docs) silently never
/// fires against a SQLite connection, so a parent-row delete leaves orphaned child rows
/// instead of cascading. `discovery-db::ConnectionRegistry`'s SQLite/Memory connections
/// need the identical fix for the same reason in production, not just here for tests.
pub async fn connect_in_memory_for_tests() -> sea_orm::DatabaseConnection {
    use sea_orm::ConnectionTrait;

    // See `discovery-db::connect_memory`'s docs for why `idle_timeout`/`max_lifetime` are
    // pinned to an effectively-never duration, not left at sea-orm's default (which lets
    // sqlx's own 10-minute `idle_timeout` default apply) — the same "connection gets
    // reaped, replacement is a brand-new empty `sqlite::memory:` database" failure mode
    // applies here too, just less likely to actually trigger given how short-lived tests
    // are.
    const EFFECTIVELY_NEVER: std::time::Duration =
        std::time::Duration::from_secs(60 * 60 * 24 * 365 * 10); // 10 years
    let mut opt = sea_orm::ConnectOptions::new("sqlite::memory:");
    opt.max_connections(1)
        .idle_timeout(EFFECTIVELY_NEVER)
        .max_lifetime(EFFECTIVELY_NEVER);
    let db = sea_orm::Database::connect(opt)
        .await
        .expect("connect in-memory sqlite");
    db.execute_unprepared("PRAGMA foreign_keys = ON;")
        .await
        .expect("enable sqlite foreign key enforcement");
    Migrator::up(&db, None).await.expect("run migrations");
    db
}
