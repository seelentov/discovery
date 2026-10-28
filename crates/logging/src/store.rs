use async_trait::async_trait;
use discovery_entities::logs::ActiveModel;
use sea_orm::{ActiveValue::Set, DatabaseConnection, EntityTrait};

use crate::LogEntry;

/// Durable log storage — the "logs" part of "мы просто устанавливаем одну бд для
/// хранения всего: данных устройств, логов, конфигурации". Deliberately minimal
/// (`append` only, no query/list method yet): there's no dashboard/API for browsing
/// historical logs built on top of this yet, only the live in-memory tail
/// ([`crate::LogBuffer`], via `/api/logs`) — but the data itself is genuinely persisted
/// per the selected storage backend, not silently dropped, which is the actual point.
#[async_trait]
pub trait LogStore: Send + Sync {
    async fn append(&self, entry: &LogEntry) -> anyhow::Result<()>;

    /// Deletes every row older than `cutoff` — added 2026-08-21, scale audit finding: this
    /// table had no retention/pruning mechanism at all, unlike `device_metric_history`/
    /// `alerts`, so it grew without bound under normal operation (every `info!`+ tracing
    /// event from every recurring poll cycle across the whole fleet gets one row). Returns
    /// how many rows were deleted, purely for the cleanup loop's own logging — same
    /// contract as `discovery_alerts::AlertStore::prune_cleared_older_than`.
    async fn prune_older_than(&self, cutoff: chrono::DateTime<chrono::Utc>) -> anyhow::Result<u64>;
}

/// The sea-orm-backed implementation, replacing the old `PostgresLogStore`/
/// `SqliteLogStore`/`MemoryLogStore` trio (2026-08-18 multi-DB rewrite, same rationale as
/// `discovery_config_store::SeaOrmSettingsStore`'s docs). Rows in `logs`
/// (`discovery_entities::logs`, `crates/migration`).
///
/// **No more true no-op "memory" backend.** The old `MemoryLogStore` skipped persistence
/// entirely on the reasoning that an in-process backend's data is thrown away on restart
/// anyway, so writing it first was wasted work. That reasoning was specific to "memory"
/// being its own storage *kind*; in the per-domain-routing model every domain — including
/// one that resolves to the zero-config implicit connection, or to a named config whose
/// `kind = "memory"` — is just another `sea_orm::DatabaseConnection`
/// (`discovery-db::ConnectionRegistry`'s docs), and `SeaOrmLogStore` doesn't special-case
/// any of them: an in-memory SQLite `INSERT` per log line is real SQL-engine work (not
/// free), but still no disk I/O, and it keeps this crate down to one code path instead of
/// three — the explicit goal of this rewrite.
pub struct SeaOrmLogStore {
    db: DatabaseConnection,
}

impl SeaOrmLogStore {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Convenience for tests — see `discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests`'s
    /// docs for why this exists and why it's async. Not currently used outside this
    /// crate's own tests (`LogStore` isn't wired into `DashboardState`/handler test
    /// fixtures — only `discovery-agent::main`'s `spawn_log_persister` uses it), kept for
    /// symmetry with every other store crate and for whatever calls this gains once
    /// `main.rs` is rewired onto `ConnectionRegistry` (task tracking this rewrite).
    #[allow(dead_code)]
    pub async fn new_in_memory_for_tests() -> Self {
        Self::new(discovery_migration::connect_in_memory_for_tests().await)
    }
}

#[async_trait]
impl LogStore for SeaOrmLogStore {
    async fn append(&self, entry: &LogEntry) -> anyhow::Result<()> {
        let am = ActiveModel {
            id: sea_orm::ActiveValue::NotSet,
            ts: Set(entry.timestamp),
            level: Set(entry.level.clone()),
            target: Set(entry.target.clone()),
            message: Set(entry.message.clone()),
            fields: Set(serde_json::to_value(&entry.fields)?),
        };
        discovery_entities::logs::Entity::insert(am)
            .exec(&self.db)
            .await?;
        Ok(())
    }

    async fn prune_older_than(&self, cutoff: chrono::DateTime<chrono::Utc>) -> anyhow::Result<u64> {
        use sea_orm::{ColumnTrait, QueryFilter};
        let result = discovery_entities::logs::Entity::delete_many()
            .filter(discovery_entities::logs::Column::Ts.lt(cutoff))
            .exec(&self.db)
            .await?;
        Ok(result.rows_affected)
    }
}

/// The ClickHouse-backed implementation (2026-08-18) — direct user request "Может сразу
/// добавить поддержку timescale и clickhouse?", following the multi-DB architecture
/// discussion. `logs` is the *only* domain `discovery_bootstrap::Config::validate` allows
/// to route to a ClickHouse-kind database (see that type's docs and
/// `discovery_db::DomainConnection`'s docs for the full reasoning) — this trait's single
/// `append` method is pure insert, never updates or deletes a row, which is exactly what
/// ClickHouse is good at and exactly what every *other* domain's store structurally isn't
/// (`device_metrics`/`device_metric_history` upsert in place every poll,
/// `alerts` updates in place on `StillActive`, both explicitly delete a device's rows on
/// removal — none of that is a fast, synchronous operation on ClickHouse).
///
/// Owns its own schema (unlike `SeaOrmLogStore`, whose `logs` table comes from the shared
/// `discovery-migration` crate that every sea-orm-backed store draws from) — there's no
/// equivalent shared "ClickHouse schema" crate today, since this is the only domain that
/// uses one, so [`Self::ensure_schema`] is called directly by `discovery-agent::main`
/// right after construction, mirroring where `discovery_migration::Migrator::up` gets
/// called for the sea-orm path (see `discovery_db::ConnectionRegistry::build`'s docs).
pub struct ClickHouseLogStore {
    client: clickhouse::Client,
}

/// One-to-one with `logs`' sea-orm shape (`discovery_entities::logs`) except `fields`,
/// which is stored as a JSON-encoded `String` rather than a native JSON column — ClickHouse
/// does have a `JSON`/`Map` type, but a plain string keeps this row exactly as simple to
/// read back (the dashboard only ever displays `fields` as text) without pulling in
/// ClickHouse's own JSON-column ecosystem for a write-mostly column nothing queries into.
#[derive(Debug, Clone, clickhouse::Row, serde::Serialize)]
struct ClickHouseLogRow {
    #[serde(with = "clickhouse::serde::chrono::datetime64::micros")]
    ts: chrono::DateTime<chrono::Utc>,
    level: String,
    target: String,
    message: String,
    fields: String,
}

impl ClickHouseLogStore {
    pub fn new(client: clickhouse::Client) -> Self {
        Self { client }
    }

    /// Creates the `logs` table if it doesn't already exist — `MergeTree` ordered by `ts`,
    /// the only access pattern this domain has (append, optionally range-scanned by time;
    /// `LogStore` has no read method today, see this module's docs on why that's fine).
    /// Idempotent (`IF NOT EXISTS`), safe to call on every startup.
    pub async fn ensure_schema(client: &clickhouse::Client) -> anyhow::Result<()> {
        client
            .query(
                "CREATE TABLE IF NOT EXISTS logs (
                    ts DateTime64(6),
                    level LowCardinality(String),
                    target String,
                    message String,
                    fields String
                ) ENGINE = MergeTree
                ORDER BY (ts)",
            )
            .execute()
            .await?;
        Ok(())
    }
}

#[async_trait]
impl LogStore for ClickHouseLogStore {
    async fn append(&self, entry: &LogEntry) -> anyhow::Result<()> {
        let row = ClickHouseLogRow {
            ts: entry.timestamp,
            level: entry.level.clone(),
            target: entry.target.clone(),
            message: entry.message.clone(),
            fields: serde_json::to_string(&entry.fields)?,
        };
        let mut insert = self.client.insert::<ClickHouseLogRow>("logs")?;
        insert.write(&row).await?;
        insert.end().await?;
        Ok(())
    }

    /// `ALTER TABLE ... DELETE WHERE` — ClickHouse's mutation mechanism, not a classic
    /// synchronous `DELETE`: it's applied asynchronously in the background by later
    /// `MergeTree` merges, same as any other ClickHouse mutation. Acceptable for a
    /// once-an-hour retention sweep (this isn't a latency-sensitive path); the idiomatic
    /// alternative — a table-level `TTL` clause — would need to be re-issued via `ALTER
    /// TABLE ... MODIFY TTL` every time `LogRetentionConfig::retention_secs` changes at
    /// runtime, which is real extra complexity for a domain that's an opt-in choice, not
    /// the default backend. Row count isn't reported back by this command (ClickHouse
    /// mutations are fire-and-forget), so this returns `0` always — same "can't count,
    /// don't pretend to" honesty `AlertStore`/`LogStore` docs already use elsewhere for
    /// backend-specific gaps.
    async fn prune_older_than(&self, cutoff: chrono::DateTime<chrono::Utc>) -> anyhow::Result<u64> {
        let formatted = cutoff.format("%Y-%m-%d %H:%M:%S%.6f");
        self.client
            .query(&format!("ALTER TABLE logs DELETE WHERE ts < '{formatted}'"))
            .execute()
            .await?;
        Ok(0)
    }
}

/// Drains a channel of [`LogEntry`] fed by [`crate::PersistingLayer`] and writes each one
/// to `store`. Runs for the lifetime of the process (spawned once in
/// `discovery-agent::main`); a failed `append` is reported to stderr directly, not via
/// `tracing`, to avoid a feedback loop (a broken log store logging its own failure through
/// the very pipeline that's broken).
pub fn spawn_log_persister(
    mut receiver: tokio::sync::mpsc::Receiver<LogEntry>,
    store: std::sync::Arc<dyn LogStore>,
) {
    tokio::spawn(async move {
        while let Some(entry) = receiver.recv().await {
            if let Err(e) = store.append(&entry).await {
                eprintln!("log persister: failed to append entry: {e}");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn append_persists_a_row_including_structured_fields_as_json() {
        let store = SeaOrmLogStore::new_in_memory_for_tests().await;
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("device_id".to_string(), "abc-123".to_string());
        let entry = LogEntry {
            timestamp: chrono::Utc::now(),
            level: "INFO".to_string(),
            target: "discovery_agent".to_string(),
            message: "hello".to_string(),
            fields,
        };
        store.append(&entry).await.unwrap();

        use sea_orm::EntityTrait;
        let rows = discovery_entities::logs::Entity::find()
            .all(&store.db)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].message, "hello");
        assert_eq!(rows[0].fields, serde_json::json!({"device_id": "abc-123"}));
    }

    #[tokio::test]
    async fn append_twice_creates_two_independent_rows_not_an_upsert() {
        let store = SeaOrmLogStore::new_in_memory_for_tests().await;
        let entry = |msg: &str| LogEntry {
            timestamp: chrono::Utc::now(),
            level: "INFO".to_string(),
            target: "t".to_string(),
            message: msg.to_string(),
            fields: Default::default(),
        };
        store.append(&entry("first")).await.unwrap();
        store.append(&entry("second")).await.unwrap();

        use sea_orm::EntityTrait;
        let rows = discovery_entities::logs::Entity::find()
            .all(&store.db)
            .await
            .unwrap();
        assert_eq!(rows.len(), 2, "append is a log — every call is a new row, unlike upsert-by-key stores elsewhere in this project");
    }

    #[tokio::test]
    async fn prune_older_than_deletes_only_rows_before_the_cutoff() {
        let store = SeaOrmLogStore::new_in_memory_for_tests().await;
        let entry_at = |ts: chrono::DateTime<chrono::Utc>| LogEntry {
            timestamp: ts,
            level: "INFO".to_string(),
            target: "t".to_string(),
            message: "m".to_string(),
            fields: Default::default(),
        };
        let now = chrono::Utc::now();
        store
            .append(&entry_at(now - chrono::Duration::hours(2)))
            .await
            .unwrap();
        store
            .append(&entry_at(now - chrono::Duration::minutes(1)))
            .await
            .unwrap();

        let deleted = store
            .prune_older_than(now - chrono::Duration::hours(1))
            .await
            .unwrap();
        assert_eq!(deleted, 1);

        use sea_orm::EntityTrait;
        let rows = discovery_entities::logs::Entity::find()
            .all(&store.db)
            .await
            .unwrap();
        assert_eq!(
            rows.len(),
            1,
            "only the row older than the cutoff must be gone"
        );
    }
}
