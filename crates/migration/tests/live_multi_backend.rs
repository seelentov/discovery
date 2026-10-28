//! Live verification that one migration definition genuinely produces a correct schema
//! against all three backends — direct user request 2026-08-18: "discovery должен уметь
//! подключаться к разным СУБД". `#[ignore]`d (needs real servers reachable, not run by
//! plain `cargo test --workspace`) — run explicitly with `cargo test -p discovery-migration
//! --test live_multi_backend -- --ignored`.
//!
//! Each backend: connect → run the migration → assert all 15 tables exist → run the
//! migration **again** (the `.if_not_exists()` idempotency this crate's docs promise,
//! load-bearing for an already-running Postgres deployment) → assert still fine.

use discovery_migration::Migrator;
use sea_orm::{ConnectionTrait, Database, Statement};
use sea_orm_migration::MigratorTrait;

const EXPECTED_TABLES: &[&str] = &[
    "jobs",
    "devices",
    "device_metric_settings",
    "device_metrics",
    "device_metric_history",
    "profiles",
    "profile_metrics",
    "profile_alerts",
    "profile_service_checks",
    "discovery_configs",
    "discovery_subnets",
    "discovery_subnet_oids",
    "discovery_subnet_labels",
    "logs",
    "settings",
    "alerts",
];

#[tokio::test]
#[ignore]
async fn postgres_migration_creates_every_table_and_is_idempotent() {
    let db = Database::connect("postgres://vladislav@127.0.0.1:5432/discovery_migration_test")
        .await
        .expect("connect to Postgres");
    Migrator::up(&db, None).await.expect("first run");
    Migrator::up(&db, None)
        .await
        .expect("second run must be a no-op, not an error");

    let rows = db
        .query_all(Statement::from_string(
            db.get_database_backend(),
            "SELECT table_name FROM information_schema.tables WHERE table_schema='public'",
        ))
        .await
        .unwrap();
    let found: Vec<String> = rows
        .iter()
        .map(|r| r.try_get::<String>("", "table_name").unwrap())
        .collect();
    for table in EXPECTED_TABLES {
        assert!(
            found.contains(&table.to_string()),
            "Postgres: missing table {table}, found {found:?}"
        );
    }
}

#[tokio::test]
#[ignore]
async fn sqlite_migration_creates_every_table_and_is_idempotent() {
    let path = std::env::temp_dir().join(format!(
        "discovery-migration-test-{}.sqlite3",
        std::process::id()
    ));
    let url = format!("sqlite://{}?mode=rwc", path.display());
    let db = Database::connect(&url).await.expect("connect to SQLite");
    Migrator::up(&db, None).await.expect("first run");
    Migrator::up(&db, None)
        .await
        .expect("second run must be a no-op, not an error");

    let rows = db
        .query_all(Statement::from_string(
            db.get_database_backend(),
            "SELECT name FROM sqlite_master WHERE type='table'",
        ))
        .await
        .unwrap();
    let found: Vec<String> = rows
        .iter()
        .map(|r| r.try_get::<String>("", "name").unwrap())
        .collect();
    for table in EXPECTED_TABLES {
        assert!(
            found.contains(&table.to_string()),
            "SQLite: missing table {table}, found {found:?}"
        );
    }
    std::fs::remove_file(&path).ok();
}

#[tokio::test]
#[ignore]
async fn mysql_migration_creates_every_table_and_is_idempotent() {
    let db = Database::connect("mysql://root@127.0.0.1:3306/discovery_migration_test")
        .await
        .expect("connect to MySQL");
    Migrator::up(&db, None).await.expect("first run");
    Migrator::up(&db, None)
        .await
        .expect("second run must be a no-op, not an error");

    // Aliased to a lowercase name explicitly — MySQL's `information_schema.tables`
    // returns `TABLE_NAME` (uppercase) on this install, which `try_get`'s exact-name
    // lookup doesn't match; a plain `SELECT table_name` alone isn't enough (found live,
    // not guessed — the migration itself succeeded, only this verification query didn't).
    let rows = db
        .query_all(Statement::from_string(
            db.get_database_backend(),
            "SELECT table_name AS tbl FROM information_schema.tables WHERE table_schema='discovery_migration_test'",
        ))
        .await
        .unwrap();
    let found: Vec<String> = rows
        .iter()
        .map(|r| r.try_get::<String>("", "tbl").unwrap())
        .collect();
    for table in EXPECTED_TABLES {
        assert!(
            found.contains(&table.to_string()),
            "MySQL: missing table {table}, found {found:?}"
        );
    }
}
