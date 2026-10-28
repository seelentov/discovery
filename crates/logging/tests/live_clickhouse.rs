//! Live verification of `ClickHouseLogStore` against a real ClickHouse server — same
//! `#[ignore]`d convention as `discovery-migration`'s `tests/live_multi_backend.rs` (needs
//! a real server reachable, not run by plain `cargo test --workspace`). Run explicitly
//! with `cargo test -p discovery-logging --test live_clickhouse -- --ignored`.

use discovery_logging::{ClickHouseLogStore, LogEntry, LogStore};
use std::collections::BTreeMap;

const TEST_DATABASE: &str = "discovery_logs_test";

#[tokio::test]
#[ignore]
async fn append_persists_a_row_queryable_back_from_a_real_clickhouse_server() {
    // ClickHouse doesn't auto-create a database named in `with_database` — create it
    // first via a client pointed at the always-present `default` database.
    let admin = clickhouse::Client::default().with_url("http://127.0.0.1:8123");
    admin
        .query(&format!("CREATE DATABASE IF NOT EXISTS {TEST_DATABASE}"))
        .execute()
        .await
        .expect("create test database");

    let client = clickhouse::Client::default()
        .with_url("http://127.0.0.1:8123")
        .with_database(TEST_DATABASE);
    ClickHouseLogStore::ensure_schema(&client)
        .await
        .expect("ensure_schema");
    let store = ClickHouseLogStore::new(client.clone());

    let mut fields = BTreeMap::new();
    fields.insert("device_id".to_string(), "abc-123".to_string());
    // Unique per run so repeated executions of this test against the same persistent
    // table don't accumulate false-positive matches from earlier runs.
    let unique_message = format!(
        "live-clickhouse-test-{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap()
    );
    let entry = LogEntry {
        timestamp: chrono::Utc::now(),
        level: "INFO".to_string(),
        target: "discovery_agent".to_string(),
        message: unique_message.clone(),
        fields,
    };
    store.append(&entry).await.expect("append");

    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Found {
        level: String,
        target: String,
        message: String,
        fields: String,
    }
    let rows: Vec<Found> = client
        .query("SELECT level, target, message, fields FROM logs WHERE message = ?")
        .bind(&unique_message)
        .fetch_all()
        .await
        .expect("select back the row just inserted");

    assert_eq!(
        rows.len(),
        1,
        "expected exactly one row for this run's unique message, got {}",
        rows.len()
    );
    assert_eq!(rows[0].level, "INFO");
    assert_eq!(rows[0].target, "discovery_agent");
    assert_eq!(rows[0].message, unique_message);
    assert_eq!(rows[0].fields, "{\"device_id\":\"abc-123\"}");
}

#[tokio::test]
#[ignore]
async fn ensure_schema_is_idempotent() {
    let admin = clickhouse::Client::default().with_url("http://127.0.0.1:8123");
    admin
        .query(&format!("CREATE DATABASE IF NOT EXISTS {TEST_DATABASE}"))
        .execute()
        .await
        .expect("create test database");
    let client = clickhouse::Client::default()
        .with_url("http://127.0.0.1:8123")
        .with_database(TEST_DATABASE);
    ClickHouseLogStore::ensure_schema(&client)
        .await
        .expect("first call");
    ClickHouseLogStore::ensure_schema(&client)
        .await
        .expect("second call must be a no-op, not an error");
}
