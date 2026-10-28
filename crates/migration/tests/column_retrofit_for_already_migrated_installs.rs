//! Regression test for the bug `m20260918_000002_column_retrofit_for_already_migrated_installs`
//! fixes — found live 2026-09-18 (see that migration's own docs and
//! `crate`'s module docs): a `has_column`-guarded `ADD COLUMN` living *inside* an
//! already-applied migration's `up()` body never runs again, because
//! `sea_orm_migration::MigratorTrait::up()` only calls `up()` on migrations not yet
//! recorded in `seaql_migrations`. `ip_sort_key_backfill.rs` (this crate's older sibling
//! test) doesn't actually cover this — it hand-creates a pre-existing table via raw SQL
//! and then calls `Migrator::up` for the very *first* time against that database, so the
//! migration itself was never "already applied" going in. This test reproduces the real
//! failure mode instead: a database that has genuinely already run
//! `m20260818_000001_initial_schema` to completion (a real `seaql_migrations` row for it),
//! simulating an install that upgraded its binary *before*
//! `m20260918_000002_column_retrofit_for_already_migrated_installs` existed.

use discovery_migration::Migrator;
use sea_orm::{ConnectionTrait, Database, EntityTrait, Statement};
use sea_orm_migration::MigratorTrait;
use uuid::Uuid;

#[tokio::test]
async fn an_already_migrated_database_missing_a_later_retrofitted_column_gets_it_without_erroring()
{
    let db = Database::connect("sqlite::memory:").await.expect("connect");
    db.execute_unprepared("PRAGMA foreign_keys = ON;")
        .await
        .unwrap();

    // A genuinely fresh install — both migrations run, `seaql_migrations` records both by
    // name, `assistant_conversations` has every current column.
    Migrator::up(&db, None)
        .await
        .expect("first run must succeed");

    let owner_id = Uuid::new_v4();
    let conversation_id = Uuid::new_v4();
    let now = chrono::Utc::now().to_rfc3339();
    db.execute(Statement::from_sql_and_values(
        db.get_database_backend(),
        "INSERT INTO assistant_conversations (id, owner_user_id, title, created_at, updated_at, auto_approve_writes) VALUES ($1, $2, $3, $4, $4, $5)",
        [conversation_id.as_bytes().to_vec().into(), owner_id.as_bytes().to_vec().into(), "pre-existing chat".into(), now.into(), true.into()],
    ))
    .await
    .unwrap();

    // Simulate "this install's binary predates `m20260918_000002_...`": that migration
    // never ran, so its column was never added — and reverse the one thing it would have
    // done, without touching `m20260818_000001_initial_schema`'s own (still correctly
    // applied) record.
    db.execute_unprepared("DELETE FROM seaql_migrations WHERE version = 'm20260918_000002_column_retrofit_for_already_migrated_installs'").await.unwrap();
    db.execute_unprepared("ALTER TABLE assistant_conversations DROP COLUMN auto_approve_writes")
        .await
        .unwrap();

    // Without the fix, this reproduces the live failure verbatim: a plain `SELECT *`
    // through the current entity (which declares `auto_approve_writes`) errors with
    // "no such column" — proving the simulated "before the fix" state is faithful, not a
    // trivially-already-working setup.
    let broken = discovery_entities::assistant_conversations::Entity::find_by_id(conversation_id)
        .one(&db)
        .await;
    assert!(
        broken.is_err(),
        "sanity check: the simulated pre-upgrade database must actually be missing the column"
    );

    // The real fix: `m20260818_000001_initial_schema` is already applied and correctly
    // skipped again; `m20260918_000002_column_retrofit_for_already_migrated_installs` is
    // still pending (just deleted above) and actually runs this time, retrofitting the
    // column via its own `has_column` guard.
    Migrator::up(&db, None).await.expect("retrofit migration must succeed against an already-migrated database missing one of its columns");

    let row = discovery_entities::assistant_conversations::Entity::find_by_id(conversation_id)
        .one(&db)
        .await
        .unwrap()
        .expect("the pre-existing conversation must survive the retrofit");
    assert!(!row.auto_approve_writes, "a row that predates the column gets the column's schema default (false) — the true prior value can't be recovered, same as every other has_column retrofit in this project");
    assert_eq!(
        row.title, "pre-existing chat",
        "unrelated columns must be untouched by the retrofit"
    );

    // Idempotency — a third run (both migrations now genuinely applied) must be a clean no-op.
    Migrator::up(&db, None)
        .await
        .expect("third run must be a no-op, not an error");
}
