//! Proves `devices.ip_sort_key`'s backfill (added 2026-08-21, scale audit — see
//! `m20260818_000001_initial_schema`'s `up()` docs) actually computes real values for rows
//! that predate the column, not just for brand-new inserts. Simulates an "already-running
//! installation" by hand-creating the `devices` table in its pre-`ip_sort_key` shape and
//! inserting a raw row *before* running the real migration — `Migrator::up`'s
//! `create_table(...).if_not_exists()` then no-ops on the table itself (it already
//! exists), so this genuinely exercises the `has_column` -> `false` -> `ALTER` + backfill
//! branch, not the fresh-install path every other test in this workspace goes through.

use discovery_migration::Migrator;
use sea_orm::{ConnectionTrait, Database, EntityTrait, Statement};
use sea_orm_migration::MigratorTrait;
use uuid::Uuid;

#[tokio::test]
async fn preexisting_rows_get_a_real_ip_sort_key_not_the_schema_default() {
    let db = Database::connect("sqlite::memory:").await.expect("connect");
    db.execute_unprepared("PRAGMA foreign_keys = ON;")
        .await
        .unwrap();

    // The pre-2026-08-21 shape: every column `m20260818_000001_initial_schema` declares
    // for `devices` except `ip_sort_key`. Minimal but real DDL, not a mock — this is what
    // an already-running installation's `devices` table actually looked like.
    db.execute_unprepared(
        "CREATE TABLE devices (
            device_id TEXT PRIMARY KEY,
            ip TEXT NOT NULL,
            profile TEXT,
            profile_version TEXT,
            poll_generation BIGINT NOT NULL DEFAULT 0,
            snmp_version TEXT,
            snmp_community TEXT,
            snmp_port INTEGER NOT NULL DEFAULT 161,
            discovered_at TIMESTAMP NOT NULL,
            updated_at TIMESTAMP NOT NULL,
            ping_ok BOOLEAN,
            ping_checked_at TIMESTAMP,
            snmp_ok BOOLEAN,
            snmp_checked_at TIMESTAMP,
            enabled BOOLEAN NOT NULL DEFAULT 1,
            ping_failing_since TIMESTAMP
        )",
    )
    .await
    .unwrap();

    let preexisting_id = Uuid::new_v4();
    let now = chrono::Utc::now().to_rfc3339();
    // `device_id` is bound as its raw 16-byte form, not the 36-character hyphenated
    // string — sea-orm's sqlx `Uuid` decode for SQLite (`with-uuid`) expects the binary
    // encoding regardless of the column's declared SQL type name (SQLite's dynamic typing
    // makes the declared type mostly decorative); binding the string form here made the
    // migration's own typed backfill query fail to decode this row with a real (if
    // SQLite-specific) `ColumnDecode`/`ParseByteLength` error the first time this test
    // was written — found live, not guessed.
    db.execute(Statement::from_sql_and_values(
        db.get_database_backend(),
        "INSERT INTO devices (device_id, ip, discovered_at, updated_at) VALUES ($1, $2, $3, $3)",
        [
            preexisting_id.as_bytes().to_vec().into(),
            "10.0.0.9".into(),
            now.into(),
        ],
    ))
    .await
    .unwrap();

    // The real migration — `devices` already exists (this table's own `create_table`
    // no-ops), so this must hit the `has_column("devices", "ip_sort_key")` -> `false`
    // branch: add the column, then backfill every existing row.
    Migrator::up(&db, None)
        .await
        .expect("migration must succeed against a pre-existing devices table");

    let row = discovery_entities::devices::Entity::find_by_id(preexisting_id)
        .one(&db)
        .await
        .unwrap()
        .expect("the pre-existing row must survive the migration");
    assert_eq!(row.ip_sort_key, discovery_core::ipv4_to_sort_key("10.0.0.9"), "a row that predates ip_sort_key must be backfilled with a real computed value, not left at the column's schema default (0)");

    // Idempotency — the same "no-op if it already exists" guarantee this migration has
    // always promised (`has_column` correctly reports `true` the second time), and a
    // second run must not somehow re-corrupt or re-zero an already-backfilled value.
    Migrator::up(&db, None)
        .await
        .expect("second run must be a no-op, not an error");
    let row_again = discovery_entities::devices::Entity::find_by_id(preexisting_id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row_again.ip_sort_key,
        discovery_core::ipv4_to_sort_key("10.0.0.9")
    );
}
