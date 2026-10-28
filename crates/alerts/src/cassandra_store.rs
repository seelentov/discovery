//! `CassandraAlertStore` — the second [`AlertStore`] backend (2026-08-18, fourth pass,
//! direct user request: "Сделай для alerts cassandra"). Domain chosen after asking which
//! of the remaining 7 domains fits — `alerts`, unlike `devices`/`jobs`/`profiles`/etc.,
//! shares `device_metrics`'s partition-by-`device_id` shape (see
//! `discovery_bootstrap::DbKind::Cassandra`'s docs) for its `delete_for_device` path, and
//! Cassandra's `INSERT`/`UPDATE`/`DELETE` (all fast, synchronous upserts/point-deletes)
//! tolerate this trait's `upsert`-by-id and per-device-delete patterns fine — the same
//! reasoning that already ruled ClickHouse out for this domain.
//!
//! **Important asymmetry vs. `CassandraDeviceMetricsStore`, disclosed up front:**
//! `device_metrics`'s every read (`get_metrics`/`get_metric_records`/`metric_history`) is
//! scoped to one device — a clean partition-by-`device_id` fit throughout. `alerts`'
//! *primary* read (`list`, the dashboard's Тревоги page) is the opposite: a **global**
//! query across every device, filtered by any combination of level/state/device_id/free-text
//! search, sorted by any of 5 columns, paginated. That access pattern has no natural
//! Cassandra partition key at all — verified live against this project's own Cassandra 5.0.9
//! install before committing to a design (not guessed): `ORDER BY` is rejected outright on
//! any secondary-indexed column ("ORDER BY with 2ndary indexes is not supported, except for
//! ANN queries"), and free-text substring search (`LIKE`) needs SAI analyzer configuration
//! this project doesn't set up. What **is** confirmed to work, live: SAI (`CREATE CUSTOM
//! INDEX ... USING 'sai'`) equality and range predicates — including combined
//! (`state = ? AND cleared_at < ?`) — with no `ALLOW FILTERING` needed.
//!
//! **The honest design this leads to**, not a guessed one: `id` is the partition key (a
//! plain one-row-per-partition table) — this makes `upsert`/`get`/`delete`,
//! the *actual* hot path (called on every `AlertStateTracker` transition), trivially
//! efficient single-partition operations, matching how the sea-orm version's `upsert`
//! (`OnConflict::column(Column::Id)`) already works. `list`'s `level`/`state`/`device_id`
//! filters are pushed down to Cassandra via SAI equality (each optional, AND'd together
//! when present); **free-text search and sorting happen in Rust**, over whatever SAI
//! already narrowed down (or the full table, if no equality filter was given at all) —
//! `ORDER BY`/`LIKE` genuinely aren't available server-side here, not a corner cut for
//! convenience. Bounded in practice by `prune_cleared_older_than`'s retention policy
//! keeping the cleared-alert working set small — same reasoning `CassandraDeviceMetricsStore`
//! already applies to its own disclosed compromises (see that module's docs).
//!
//! **`prune_cleared_older_than`/`delete_for_device` — read-then-delete, not a single
//! statement.** Verified live: CQL `DELETE` always requires the partition key in its
//! `WHERE` clause, even when the row-selecting predicate is a SAI-indexed column
//! (`DELETE FROM alerts WHERE state = 'cleared'` fails with "Some partition key parts are
//! missing: id") — so both methods first `SELECT id FROM alerts WHERE <SAI predicate>`,
//! then delete each matching `id` individually.
use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use discovery_core::{
    Alert, AlertComment, AlertCommentAttachment, AlertLevel, AlertState, AutoClearReason,
    NewAttachment, SortDir,
};
use scylla::{DeserializeRow, SerializeRow, Session};
use uuid::Uuid;

use crate::{AlertListPage, AlertListQuery, AlertSortBy, AlertStore};

fn level_to_str(level: AlertLevel) -> &'static str {
    match level {
        AlertLevel::Info => "info",
        AlertLevel::Warning => "warning",
        AlertLevel::Critical => "critical",
    }
}

fn level_from_str(s: &str) -> AlertLevel {
    match s {
        "critical" => AlertLevel::Critical,
        "warning" => AlertLevel::Warning,
        _ => AlertLevel::Info,
    }
}

fn state_to_str(state: &AlertState) -> &'static str {
    match state {
        AlertState::Active => "active",
        AlertState::Cleared => "cleared",
    }
}

fn state_from_str(s: &str) -> AlertState {
    match s {
        "cleared" => AlertState::Cleared,
        _ => AlertState::Active,
    }
}

fn auto_clear_reason_to_str(reason: AutoClearReason) -> &'static str {
    match reason {
        AutoClearReason::RowMissing => "row_missing",
    }
}

fn auto_clear_reason_from_str(s: &str) -> Option<AutoClearReason> {
    match s {
        "row_missing" => Some(AutoClearReason::RowMissing),
        _ => None,
    }
}

#[derive(DeserializeRow)]
#[scylla(crate = "scylla")]
struct AlertRow {
    details: Option<String>,
    id: Uuid,
    device_id: Uuid,
    device_ip: String,
    name: String,
    row_key: Option<String>,
    level: String,
    message: String,
    state: String,
    facts: Option<String>,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    cleared_at: Option<DateTime<Utc>>,
    closed_by: Option<String>,
    auto_clear_reason: Option<String>,
    flapping: Option<bool>,
    suppression_reason: Option<String>,
    suppressed_by_alert_id: Option<Uuid>,
    reopened_from_alert_id: Option<Uuid>,
}

#[derive(SerializeRow)]
#[scylla(crate = "scylla")]
struct AlertInsert<'a> {
    details: Option<&'a str>,
    id: Uuid,
    device_id: Uuid,
    device_ip: &'a str,
    name: &'a str,
    row_key: Option<&'a str>,
    level: &'static str,
    message: &'a str,
    state: &'static str,
    facts: Option<&'a str>,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    cleared_at: Option<DateTime<Utc>>,
    closed_by: Option<&'a str>,
    auto_clear_reason: Option<&'static str>,
    flapping: bool,
    suppression_reason: Option<&'a str>,
    reopened_from_alert_id: Option<Uuid>,
}

fn row_to_alert(row: AlertRow, comment_count: i64) -> anyhow::Result<Alert> {
    let AlertRow {
        details,
        id,
        device_id,
        device_ip,
        name,
        row_key,
        level,
        message,
        state,
        facts,
        first_seen,
        last_seen,
        cleared_at,
        closed_by,
        auto_clear_reason,
        flapping,
        suppression_reason,
        suppressed_by_alert_id,
        reopened_from_alert_id,
    } = row;
    Ok(Alert {
        details: details
            .as_deref()
            .map(serde_json::from_str)
            .transpose()?
            .unwrap_or_default(),
        id,
        device_id,
        device_ip,
        name,
        row_key,
        level: level_from_str(&level),
        message,
        state: state_from_str(&state),
        facts: facts.as_deref().map(serde_json::from_str).transpose()?,
        first_seen,
        last_seen,
        cleared_at,
        closed_by,
        acknowledged_by: None,
        acknowledged_at: None,
        snoozed_until: None,
        snoozed_by: None,
        auto_clear_reason: auto_clear_reason
            .as_deref()
            .and_then(auto_clear_reason_from_str),
        flapping: flapping.unwrap_or(false),
        suppression_reason,
        comment_count,
        suppressed_by_alert_id,
        reopened_from_alert_id,
        repeat_count: 0,
        escalation_level: 0,
        repeated_at: None,
        escalation_reason: None,
    })
}

type CommentRow = (Uuid, Uuid, DateTime<Utc>, String, String);

fn row_to_comment(row: CommentRow, attachments: Vec<AlertCommentAttachment>) -> AlertComment {
    let (alert_id, id, created_at, author, text) = row;
    AlertComment {
        id,
        alert_id,
        author,
        created_at,
        text,
        attachments,
    }
}

/// Metadata-only projection of `alert_comment_attachments` (no `data`) — same "never
/// pull attachment bytes into memory just to list a thread" reasoning the sea-orm
/// backend's `AttachmentMetaRow` docs explain.
type AttachmentMetaRow = (Uuid, Uuid, String, String, i64);

fn attachment_meta_row_to_meta(row: AttachmentMetaRow) -> AlertCommentAttachment {
    let (id, comment_id, filename, content_type, size) = row;
    AlertCommentAttachment {
        id,
        comment_id,
        filename,
        content_type,
        size,
    }
}

pub struct CassandraAlertStore {
    session: Arc<Session>,
}

impl CassandraAlertStore {
    pub fn new(session: Arc<Session>) -> Self {
        Self { session }
    }

    /// Creates the keyspace (if missing — `SimpleStrategy`, replication factor 1, same
    /// "just works" local/dev default as `CassandraDeviceMetricsStore::ensure_schema`'s
    /// docs explain), the table, and the four SAI indexes `list`/`prune_cleared_older_than`/
    /// `delete_for_device` rely on. Idempotent, safe on every startup.
    pub async fn ensure_schema(session: &Session, keyspace: &str) -> anyhow::Result<()> {
        session
            .query_unpaged(format!("CREATE KEYSPACE IF NOT EXISTS {keyspace} WITH replication = {{'class': 'SimpleStrategy', 'replication_factor': 1}}"), &[])
            .await?;
        session.use_keyspace(keyspace, false).await?;

        session
            .query_unpaged(
                "CREATE TABLE IF NOT EXISTS alerts (
                    id uuid PRIMARY KEY,
                    details text,
                    device_id uuid,
                    device_ip text,
                    name text,
                    row_key text,
                    level text,
                    message text,
                    state text,
                    facts text,
                    first_seen timestamp,
                    last_seen timestamp,
                    cleared_at timestamp,
                    closed_by text,
                    auto_clear_reason text,
                    flapping boolean,
                    suppression_reason text,
                    suppressed_by_alert_id uuid,
                    reopened_from_alert_id uuid
                )",
                &[],
            )
            .await?;

        session
            .query_unpaged("ALTER TABLE alerts ADD IF NOT EXISTS flapping boolean", &[])
            .await?;
        session
            .query_unpaged(
                "ALTER TABLE alerts ADD IF NOT EXISTS suppression_reason text",
                &[],
            )
            .await?;

        for (index_name, column) in [
            ("alerts_device_id_idx", "device_id"),
            ("alerts_level_idx", "level"),
            ("alerts_state_idx", "state"),
            ("alerts_cleared_at_idx", "cleared_at"),
        ] {
            session.query_unpaged(format!("CREATE CUSTOM INDEX IF NOT EXISTS {index_name} ON alerts ({column}) USING 'sai'"), &[]).await?;
        }

        // Partitioned by `alert_id` — unlike `alerts` itself (see this module's top docs
        // on why that table has no natural partition key), a comment thread's *only*
        // real access pattern is "every comment for one alert, oldest first", which maps
        // onto Cassandra's strengths exactly the way `device_metrics` does for
        // `device_id` (2026-08-28, direct user request — threaded multi-author
        // comments, superseding the earlier single free-form `comment` column dropped
        // from `alerts` above).
        session
            .query_unpaged(
                "CREATE TABLE IF NOT EXISTS alert_comments (
                    alert_id uuid,
                    created_at timestamp,
                    id uuid,
                    author text,
                    text text,
                    PRIMARY KEY (alert_id, created_at, id)
                ) WITH CLUSTERING ORDER BY (created_at ASC, id ASC)",
                &[],
            )
            .await?;

        session
            .query_unpaged(
                "CREATE TABLE IF NOT EXISTS alert_operator_states (
                    alert_id uuid PRIMARY KEY,
                    acknowledged_by text,
                    acknowledged_at timestamp,
                    snoozed_until timestamp,
                    snoozed_by text
                )",
                &[],
            )
            .await?;

        let columns = session.query_unpaged("SELECT column_name FROM system_schema.columns WHERE keyspace_name = ? AND table_name = 'alerts'", (keyspace,)).await?;
        if !columns
            .into_rows_result()?
            .rows::<(String,)>()?
            .any(|r| r.is_ok_and(|r| r.0 == "details"))
        {
            session
                .query_unpaged("ALTER TABLE alerts ADD details text", &[])
                .await?;
        }
        session.query_unpaged("CREATE TABLE IF NOT EXISTS alert_runtime (device_id uuid PRIMARY KEY, snapshot text)", &[]).await?;
        session.query_unpaged("CREATE TABLE IF NOT EXISTS alert_rule_definitions (name text PRIMARY KEY, definition text)", &[]).await?;
        session.query_unpaged("CREATE TABLE IF NOT EXISTS alert_source_events (device_id uuid, received_at timestamp, id uuid, metric text, data text, PRIMARY KEY (device_id, received_at, id)) WITH default_time_to_live = 172800", &[]).await?;

        // Partitioned by `comment_id` — same "every X for one Y" fit `alert_comments`
        // itself already uses for `alert_id` (2026-08-29, direct user request: "вложения
        // к комментариям тревог: файл/изображение/видео"). No FK/`ON DELETE CASCADE` in
        // Cassandra — see `delete`/`prune_cleared_older_than`/`delete_for_device`'s docs
        // for how attachment cleanup is done by hand here, one level deeper than the
        // comment cleanup they already perform.
        session
            .query_unpaged(
                "CREATE TABLE IF NOT EXISTS alert_comment_attachments (
                    comment_id uuid,
                    id uuid,
                    filename text,
                    content_type text,
                    size bigint,
                    data blob,
                    PRIMARY KEY (comment_id, id)
                )",
                &[],
            )
            .await?;

        Ok(())
    }

    /// Deletes every attachment row for the given comment ids — the one-level-deeper
    /// cleanup `alert_comment_attachments`'s lack of `ON DELETE CASCADE` requires
    /// whenever a comment thread is torn down (see `ensure_schema`'s docs).
    async fn delete_attachments_for_comments(&self, comment_ids: &[Uuid]) -> anyhow::Result<()> {
        for comment_id in comment_ids {
            self.session
                .query_unpaged(
                    "DELETE FROM alert_comment_attachments WHERE comment_id = ?",
                    (comment_id,),
                )
                .await?;
        }
        Ok(())
    }

    /// The comment ids for one alert — used only to cascade attachment deletion by hand
    /// (see `delete_attachments_for_comments`'s docs); `alert_comments` itself is still
    /// deleted as a single-partition `DELETE ... WHERE alert_id = ?`.
    async fn comment_ids_for_alert(&self, alert_id: Uuid) -> anyhow::Result<Vec<Uuid>> {
        let rows: Vec<(Uuid,)> = self
            .session
            .query_unpaged(
                "SELECT id FROM alert_comments WHERE alert_id = ?",
                (alert_id,),
            )
            .await?
            .into_rows_result()?
            .rows::<(Uuid,)>()?
            .collect::<Result<_, _>>()?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// Fetches every row matching `level`/`state`/`device_id` (each an optional SAI
    /// equality predicate, AND'd together when more than one is present) — see this
    /// module's docs for why free-text `search` and sorting aren't pushed down here.
    /// Bound values are `CqlValue` (`scylla`'s own dynamically-typed value enum, which
    /// implements `SerializeValue` directly) rather than boxed trait objects — a much
    /// simpler way to build a variable-length, variable-type parameter list than `dyn
    /// SerializeValue`, which this driver's query API doesn't need at all here.
    async fn fetch_candidates(
        &self,
        level: Option<AlertLevel>,
        state: Option<&AlertState>,
        device_id: Option<Uuid>,
    ) -> anyhow::Result<Vec<Alert>> {
        let mut clauses: Vec<&str> = Vec::new();
        let mut values: Vec<scylla::frame::response::result::CqlValue> = Vec::new();

        if let Some(l) = level {
            clauses.push("level = ?");
            values.push(scylla::frame::response::result::CqlValue::Text(
                level_to_str(l).to_string(),
            ));
        }
        if let Some(s) = state {
            clauses.push("state = ?");
            values.push(scylla::frame::response::result::CqlValue::Text(
                state_to_str(s).to_string(),
            ));
        }
        if let Some(d) = device_id {
            clauses.push("device_id = ?");
            values.push(scylla::frame::response::result::CqlValue::Uuid(d));
        }

        let query = if clauses.is_empty() {
            "SELECT details, id, device_id, device_ip, name, row_key, level, message, state, facts, first_seen, last_seen, cleared_at, closed_by, auto_clear_reason, flapping, suppression_reason, suppressed_by_alert_id, reopened_from_alert_id FROM alerts".to_string()
        } else {
            format!("SELECT details, id, device_id, device_ip, name, row_key, level, message, state, facts, first_seen, last_seen, cleared_at, closed_by, auto_clear_reason, flapping, suppression_reason, suppressed_by_alert_id, reopened_from_alert_id FROM alerts WHERE {}", clauses.join(" AND "))
        };

        let rows: Vec<AlertRow> = self
            .session
            .query_unpaged(query, values)
            .await?
            .into_rows_result()?
            .rows::<AlertRow>()?
            .collect::<Result<_, _>>()?;
        let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
        let counts = self.comment_counts(&ids).await?;
        let mut alerts: Vec<Alert> = rows
            .into_iter()
            .map(|r| {
                let id = r.id;
                let count = *counts.get(&id).unwrap_or(&0);
                row_to_alert(r, count)
            })
            .collect::<anyhow::Result<_>>()?;
        self.apply_operator_states(&mut alerts).await?;
        Ok(alerts)
    }

    /// One `alert_id IN ?` fan-out query (same pattern `CassandraDeviceMetricsStore`
    /// already uses for `device_id IN ?`) plus client-side grouping — Cassandra has no
    /// server-side `COUNT ... GROUP BY` across partitions, but this is still a single
    /// round trip, bounded by however many alerts are actually being returned (page size
    /// for `list`, one for `get`), not the full candidate set.
    async fn comment_counts(&self, alert_ids: &[Uuid]) -> anyhow::Result<HashMap<Uuid, i64>> {
        if alert_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let rows: Vec<(Uuid,)> = self
            .session
            .query_unpaged(
                "SELECT alert_id FROM alert_comments WHERE alert_id IN ?",
                (alert_ids.to_vec(),),
            )
            .await?
            .into_rows_result()?
            .rows::<(Uuid,)>()?
            .collect::<Result<_, _>>()?;
        let mut counts = HashMap::new();
        for (id,) in rows {
            *counts.entry(id).or_insert(0i64) += 1;
        }
        Ok(counts)
    }

    async fn apply_operator_states(&self, alerts: &mut [Alert]) -> anyhow::Result<()> {
        if alerts.is_empty() {
            return Ok(());
        }
        let ids: Vec<_> = alerts.iter().map(|a| a.id).collect();
        let rows: Vec<(Uuid, Option<String>, Option<DateTime<Utc>>, Option<DateTime<Utc>>, Option<String>)> = self
            .session
            .query_unpaged(
                "SELECT alert_id, acknowledged_by, acknowledged_at, snoozed_until, snoozed_by FROM alert_operator_states WHERE alert_id IN ?",
                (ids,),
            )
            .await?
            .into_rows_result()?
            .rows::<(Uuid, Option<String>, Option<DateTime<Utc>>, Option<DateTime<Utc>>, Option<String>)>()?
            .collect::<Result<_, _>>()?;
        for (id, acknowledged_by, acknowledged_at, snoozed_until, snoozed_by) in rows {
            if let Some(alert) = alerts.iter_mut().find(|a| a.id == id) {
                alert.acknowledged_by = acknowledged_by;
                alert.acknowledged_at = acknowledged_at;
                alert.snoozed_until = snoozed_until;
                alert.snoozed_by = snoozed_by;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl AlertStore for CassandraAlertStore {
    async fn save_runtime(
        &self,
        device_id: Uuid,
        snapshot: &discovery_core::AlertRuntimeSnapshot,
    ) -> anyhow::Result<()> {
        self.session
            .query_unpaged(
                "INSERT INTO alert_runtime (device_id, snapshot) VALUES (?, ?)",
                (device_id, serde_json::to_string(snapshot)?),
            )
            .await?;
        Ok(())
    }
    async fn runtime_page(
        &self,
        limit: u32,
        offset: u64,
    ) -> anyhow::Result<Vec<discovery_core::DeviceAlertRuntime>> {
        let rows = self
            .session
            .query_unpaged("SELECT device_id, snapshot FROM alert_runtime", &[])
            .await?
            .into_rows_result()?;
        let mut rows = rows
            .rows::<(Uuid, String)>()?
            .collect::<Result<Vec<_>, _>>()?;
        rows.sort_by_key(|r| r.0);
        rows.into_iter()
            .skip(offset as usize)
            .take(limit.min(500) as usize)
            .map(|(device_id, snapshot)| {
                Ok(discovery_core::DeviceAlertRuntime {
                    device_id,
                    snapshot: serde_json::from_str(&snapshot)?,
                })
            })
            .collect()
    }
    async fn shared_rules(
        &self,
    ) -> anyhow::Result<std::collections::BTreeMap<String, serde_json::Value>> {
        self.session
            .query_unpaged("SELECT name, definition FROM alert_rule_definitions", &[])
            .await?
            .into_rows_result()?
            .rows::<(String, String)>()?
            .map(|row| {
                let (name, value) = row?;
                Ok((name, serde_json::from_str(&value)?))
            })
            .collect()
    }
    async fn save_shared_rule(
        &self,
        name: &str,
        definition: serde_json::Value,
    ) -> anyhow::Result<()> {
        self.session
            .query_unpaged(
                "INSERT INTO alert_rule_definitions (name, definition) VALUES (?, ?)",
                (name, serde_json::to_string(&definition)?),
            )
            .await?;
        Ok(())
    }
    async fn delete_shared_rule(&self, name: &str) -> anyhow::Result<()> {
        self.session
            .query_unpaged("DELETE FROM alert_rule_definitions WHERE name = ?", (name,))
            .await?;
        Ok(())
    }
    async fn record_source_event(
        &self,
        event: &discovery_core::AlertSourceEvent,
    ) -> anyhow::Result<()> {
        self.session.query_unpaged("INSERT INTO alert_source_events (device_id, received_at, id, metric, data) VALUES (?, ?, ?, ?, ?)", (event.device_id, event.received_at, event.id, &event.metric, serde_json::to_string(event)?)).await?;
        Ok(())
    }
    async fn prune_source_events(&self, _before: DateTime<Utc>) -> anyhow::Result<u64> {
        // Cassandra expires source rows through the table TTL, avoiding a full scan.
        Ok(0)
    }
    async fn source_events(
        &self,
        device_id: Uuid,
        since: DateTime<Utc>,
    ) -> anyhow::Result<Vec<discovery_core::AlertSourceEvent>> {
        let rows = self.session.query_unpaged(
            "SELECT received_at, id, metric, data FROM alert_source_events WHERE device_id = ? AND received_at >= ? LIMIT 10001",
            (device_id, since)).await?.into_rows_result()?;
        let mut events = Vec::new();
        for row in rows.rows::<(DateTime<Utc>, Uuid, String, String)>()? {
            let (_, _, _, data) = row?;
            // CQL timestamps truncate to milliseconds; the envelope preserves packet
            // order at the original precision for a down/up burst in one millisecond.
            let event: discovery_core::AlertSourceEvent = serde_json::from_str(&data)?;
            if event.received_at >= since {
                events.push(event);
            }
        }
        events.sort_by_key(|event| (event.received_at, event.id));
        Ok(events)
    }

    async fn upsert(&self, alert: &Alert) -> anyhow::Result<()> {
        let details_json = serde_json::to_string(&alert.details)?;
        let facts_json = alert
            .facts
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let auto_clear_reason_str = alert.auto_clear_reason.map(auto_clear_reason_to_str);
        let suppression_reason = alert.suppression_reason.as_deref();
        // `suppressed_by_alert_id` deliberately absent from this column list — see
        // `AlertStore::set_suppression`'s docs. Cassandra's `INSERT` only ever touches the
        // columns named here (unlike a full-row RDBMS upsert), so simply omitting it means
        // this call leaves whatever the sweep last wrote untouched, same effect as the
        // sea-orm backend excluding it from `on_conflict.update_columns`.
        self.session
            .query_unpaged(
                "INSERT INTO alerts (details, id, device_id, device_ip, name, row_key, level, message, state, facts, first_seen, last_seen, cleared_at, closed_by, auto_clear_reason, flapping, suppression_reason, reopened_from_alert_id) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                AlertInsert {
                    details: Some(&details_json),
                    id: alert.id,
                    device_id: alert.device_id,
                    device_ip: alert.device_ip.as_str(),
                    name: alert.name.as_str(),
                    row_key: alert.row_key.as_deref(),
                    level: level_to_str(alert.level),
                    message: alert.message.as_str(),
                    state: state_to_str(&alert.state),
                    facts: facts_json.as_deref(),
                    first_seen: alert.first_seen,
                    last_seen: alert.last_seen,
                    cleared_at: alert.cleared_at,
                    closed_by: alert.closed_by.as_deref(),
                    auto_clear_reason: auto_clear_reason_str,
                    flapping: alert.flapping,
                    suppression_reason,
                    // Frozen at insert, same as `row_key` above — see
                    // `Alert::reopened_from_alert_id`'s docs. Re-writing the same value on
                    // every subsequent `upsert` for this id is harmless (the in-memory
                    // `AlertStateTracker` copy never changes it after the initial
                    // `Activated` persist), unlike `suppressed_by_alert_id`'s exclusion
                    // above — there's no second, independent writer racing on this column.
                    reopened_from_alert_id: alert.reopened_from_alert_id,
                },
            )
            .await?;
        Ok(())
    }

    async fn set_suppression(
        &self,
        alert_id: Uuid,
        suppressed_by_alert_id: Option<Uuid>,
    ) -> anyhow::Result<()> {
        self.session
            .query_unpaged(
                "UPDATE alerts SET suppressed_by_alert_id = ? WHERE id = ?",
                (suppressed_by_alert_id, alert_id),
            )
            .await?;
        Ok(())
    }

    async fn set_acknowledgement(
        &self,
        alert_id: Uuid,
        acknowledged_by: Option<String>,
        acknowledged_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> anyhow::Result<()> {
        self.session
            .query_unpaged(
                "UPDATE alert_operator_states SET acknowledged_by = ?, acknowledged_at = ? WHERE alert_id = ?",
                (acknowledged_by, acknowledged_at, alert_id),
            )
            .await?;
        Ok(())
    }

    async fn set_snooze(
        &self,
        alert_id: Uuid,
        snoozed_until: Option<chrono::DateTime<chrono::Utc>>,
        snoozed_by: Option<String>,
    ) -> anyhow::Result<()> {
        self.session
            .query_unpaged(
                "UPDATE alert_operator_states SET snoozed_until = ?, snoozed_by = ? WHERE alert_id = ?",
                (snoozed_until, snoozed_by, alert_id),
            )
            .await?;
        Ok(())
    }

    async fn find_recent_manual_close(
        &self,
        device_id: Uuid,
        name: &str,
        row_key: Option<&str>,
        since: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<Option<Alert>> {
        // `device_id` is the only SAI-indexed predicate available here — `name`/`row_key`/
        // `closed_by`/`cleared_at` are filtered in Rust over that narrowed candidate set,
        // same "push down what's indexed, filter the rest in Rust" split `list` already
        // uses (see this module's top docs).
        let candidates = self
            .fetch_candidates(None, Some(&AlertState::Cleared), Some(device_id))
            .await?;
        Ok(candidates
            .into_iter()
            .filter(|a| {
                a.name == name
                    && a.row_key.as_deref() == row_key
                    && a.closed_by.is_some()
                    && a.cleared_at.is_some_and(|c| c >= since)
            })
            .max_by_key(|a| a.cleared_at))
    }

    async fn list(&self, query: &AlertListQuery) -> anyhow::Result<AlertListPage> {
        let mut candidates = self
            .fetch_candidates(query.level, query.state.as_ref(), query.device_id)
            .await?;

        if query.response_pending {
            candidates.retain(|a| {
                (a.details.policy.acknowledge_required && a.acknowledged_at.is_none())
                    || a.details.response_escalated
            });
        }
        if query.screen_only {
            candidates.retain(|a| {
                a.details.policy.screen_notification
                    && a.acknowledged_at.is_none()
                    && (a.state == AlertState::Active || a.details.policy.acknowledge_required)
            });
        }
        if let Some(search) = query.search.as_deref() {
            let needle = search.to_lowercase();
            candidates.retain(|a| {
                a.device_ip.to_lowercase().contains(&needle)
                    || a.name.to_lowercase().contains(&needle)
                    || a.message.to_lowercase().contains(&needle)
                    // Row-scoped alerts (2026-08-29) — same "let a port's own key be
                    // searchable" parity as `SeaOrmAlertStore::list`'s SQL equivalent.
                    || a.row_key.as_deref().is_some_and(|k| k.to_lowercase().contains(&needle))
            });
        }
        if let Some(since) = query.since {
            candidates.retain(|a| a.first_seen >= since);
        }
        if let Some(until) = query.until {
            candidates.retain(|a| a.first_seen <= until);
        }

        candidates.sort_by(|a, b| {
            let ordering = match query.sort_by {
                AlertSortBy::FirstSeen => a.first_seen.cmp(&b.first_seen),
                AlertSortBy::LastSeen => a.last_seen.cmp(&b.last_seen),
                AlertSortBy::Level => a.level.cmp(&b.level),
                AlertSortBy::Name => a.name.cmp(&b.name),
                AlertSortBy::DeviceIp => a.device_ip.cmp(&b.device_ip),
            };
            // Stable tiebreaker on `id`, same convention `SeaOrmAlertStore::list` uses.
            let ordering = ordering.then_with(|| a.id.cmp(&b.id));
            if query.sort_dir == SortDir::Desc {
                ordering.reverse()
            } else {
                ordering
            }
        });

        let total = candidates.len() as i64;
        let items = candidates
            .into_iter()
            .skip(query.offset.max(0) as usize)
            .take(query.limit.max(0) as usize)
            .collect();
        Ok(AlertListPage { items, total })
    }

    async fn get(&self, id: Uuid) -> anyhow::Result<Option<Alert>> {
        let row: Option<AlertRow> = self
            .session
            .query_unpaged("SELECT details, id, device_id, device_ip, name, row_key, level, message, state, facts, first_seen, last_seen, cleared_at, closed_by, auto_clear_reason, flapping, suppression_reason, suppressed_by_alert_id, reopened_from_alert_id FROM alerts WHERE id = ?", (id,))
            .await?
            .into_rows_result()?
            .rows::<AlertRow>()?
            .next()
            .transpose()?;
        let Some(row) = row else { return Ok(None) };
        let counts = self.comment_counts(&[id]).await?;
        let count = *counts.get(&id).unwrap_or(&0);
        let mut alert = row_to_alert(row, count)?;
        self.apply_operator_states(std::slice::from_mut(&mut alert))
            .await?;
        Ok(Some(alert))
    }

    async fn prune_cleared_older_than(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<u64> {
        // SAI range query — verified live to work with no ALLOW FILTERING, combined with
        // the equality predicate on `state`. `cleared_at < cutoff` naturally excludes every
        // active alert, whose `cleared_at` is `NULL` (a `NULL` never satisfies `<`) — same
        // reasoning as the sea-orm version's docs.
        let ids: Vec<(Uuid,)> = self
            .session
            .query_unpaged(
                "SELECT id FROM alerts WHERE state = ? AND cleared_at < ?",
                (state_to_str(&AlertState::Cleared), cutoff),
            )
            .await?
            .into_rows_result()?
            .rows::<(Uuid,)>()?
            .collect::<Result<_, _>>()?;

        let mut deleted = 0u64;
        for (id,) in ids {
            if self.get(id).await?.is_some_and(|a| {
                a.details.policy.acknowledge_required && a.acknowledged_at.is_none()
            }) {
                continue;
            }
            let comment_ids = self.comment_ids_for_alert(id).await?;
            self.session
                .query_unpaged("DELETE FROM alerts WHERE id = ?", (id,))
                .await?;
            self.session
                .query_unpaged("DELETE FROM alert_comments WHERE alert_id = ?", (id,))
                .await?;
            self.delete_attachments_for_comments(&comment_ids).await?;
            self.session
                .query_unpaged(
                    "DELETE FROM alert_operator_states WHERE alert_id = ?",
                    (id,),
                )
                .await?;
            deleted += 1;
        }
        Ok(deleted)
    }

    async fn delete(&self, id: Uuid) -> anyhow::Result<()> {
        let comment_ids = self.comment_ids_for_alert(id).await?;
        self.session
            .query_unpaged("DELETE FROM alerts WHERE id = ?", (id,))
            .await?;
        // No `ON DELETE CASCADE` in Cassandra — `alert_comments` is partitioned by
        // `alert_id`, so this is a single-partition delete, not a fan-out.
        self.session
            .query_unpaged("DELETE FROM alert_comments WHERE alert_id = ?", (id,))
            .await?;
        self.delete_attachments_for_comments(&comment_ids).await?;
        self.session
            .query_unpaged(
                "DELETE FROM alert_operator_states WHERE alert_id = ?",
                (id,),
            )
            .await?;
        Ok(())
    }

    async fn add_comment(
        &self,
        alert_id: Uuid,
        author: &str,
        text: &str,
        attachments: Vec<NewAttachment>,
    ) -> anyhow::Result<AlertComment> {
        if self.get(alert_id).await?.is_none() {
            anyhow::bail!("no such alert '{alert_id}'");
        }
        let comment = AlertComment {
            id: Uuid::new_v4(),
            alert_id,
            author: author.to_string(),
            created_at: Utc::now(),
            text: text.to_string(),
            attachments: Vec::new(),
        };
        self.session
            .query_unpaged(
                "INSERT INTO alert_comments (alert_id, created_at, id, author, text) VALUES (?, ?, ?, ?, ?)",
                (comment.alert_id, comment.created_at, comment.id, comment.author.as_str(), comment.text.as_str()),
            )
            .await?;

        let mut meta = Vec::with_capacity(attachments.len());
        for a in attachments {
            let attachment_id = Uuid::new_v4();
            let size = a.data.len() as i64;
            self.session
                .query_unpaged(
                    "INSERT INTO alert_comment_attachments (comment_id, id, filename, content_type, size, data) VALUES (?, ?, ?, ?, ?, ?)",
                    (comment.id, attachment_id, a.filename.as_str(), a.content_type.as_str(), size, a.data.as_slice()),
                )
                .await?;
            meta.push(AlertCommentAttachment {
                id: attachment_id,
                comment_id: comment.id,
                filename: a.filename,
                content_type: a.content_type,
                size,
            });
        }

        Ok(AlertComment {
            attachments: meta,
            ..comment
        })
    }

    async fn list_comments(&self, alert_id: Uuid) -> anyhow::Result<Vec<AlertComment>> {
        // Clustered by `created_at ASC` — already in reading order, no `ORDER BY` needed
        // (and CQL wouldn't reorder a single-partition query differently anyway).
        let rows: Vec<CommentRow> = self
            .session
            .query_unpaged("SELECT alert_id, id, created_at, author, text FROM alert_comments WHERE alert_id = ?", (alert_id,))
            .await?
            .into_rows_result()?
            .rows::<CommentRow>()?
            .collect::<Result<_, _>>()?;

        let mut comments = Vec::with_capacity(rows.len());
        for row in rows {
            let comment_id = row.1;
            let attachment_rows: Vec<AttachmentMetaRow> = self
                .session
                .query_unpaged(
                    "SELECT id, comment_id, filename, content_type, size FROM alert_comment_attachments WHERE comment_id = ?",
                    (comment_id,),
                )
                .await?
                .into_rows_result()?
                .rows::<AttachmentMetaRow>()?
                .collect::<Result<_, _>>()?;
            let attachments = attachment_rows
                .into_iter()
                .map(attachment_meta_row_to_meta)
                .collect();
            comments.push(row_to_comment(row, attachments));
        }
        Ok(comments)
    }

    async fn get_attachment(
        &self,
        attachment_id: Uuid,
    ) -> anyhow::Result<Option<(AlertCommentAttachment, Vec<u8>)>> {
        // `id` isn't the partition key here (`comment_id` is) — a global lookup by
        // attachment id alone needs `ALLOW FILTERING`. Acceptable: this only runs once
        // per download click, never in a hot/bulk path the way `list`/`list_comments` do.
        let rows: Vec<(Uuid, Uuid, String, String, i64, Vec<u8>)> = self
            .session
            .query_unpaged(
                "SELECT id, comment_id, filename, content_type, size, data FROM alert_comment_attachments WHERE id = ? ALLOW FILTERING",
                (attachment_id,),
            )
            .await?
            .into_rows_result()?
            .rows::<(Uuid, Uuid, String, String, i64, Vec<u8>)>()?
            .collect::<Result<_, _>>()?;
        Ok(rows
            .into_iter()
            .next()
            .map(|(id, comment_id, filename, content_type, size, data)| {
                (
                    AlertCommentAttachment {
                        id,
                        comment_id,
                        filename,
                        content_type,
                        size,
                    },
                    data,
                )
            }))
    }

    async fn delete_for_device(&self, device_id: Uuid) -> anyhow::Result<u64> {
        self.session
            .query_unpaged(
                "DELETE FROM alert_runtime WHERE device_id = ?",
                (device_id,),
            )
            .await?;
        self.session
            .query_unpaged(
                "DELETE FROM alert_source_events WHERE device_id = ?",
                (device_id,),
            )
            .await?;
        let ids: Vec<(Uuid,)> = self
            .session
            .query_unpaged("SELECT id FROM alerts WHERE device_id = ?", (device_id,))
            .await?
            .into_rows_result()?
            .rows::<(Uuid,)>()?
            .collect::<Result<_, _>>()?;

        let mut deleted = 0u64;
        for (id,) in ids {
            let comment_ids = self.comment_ids_for_alert(id).await?;
            self.session
                .query_unpaged("DELETE FROM alerts WHERE id = ?", (id,))
                .await?;
            self.session
                .query_unpaged("DELETE FROM alert_comments WHERE alert_id = ?", (id,))
                .await?;
            self.delete_attachments_for_comments(&comment_ids).await?;
            deleted += 1;
        }
        Ok(deleted)
    }

    /// `device_id IN ?` (SAI) AND'd with `state = ?` (SAI) — same "multiple SAI equality
    /// predicates ANDed together, no `ALLOW FILTERING`" shape `fetch_candidates` already
    /// relies on, just with an `IN` list on the first predicate instead of a single
    /// equality.
    async fn active_counts_by_device(
        &self,
        device_ids: &[Uuid],
    ) -> anyhow::Result<HashMap<Uuid, i64>> {
        if device_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let rows: Vec<(Uuid,)> = self
            .session
            .query_unpaged(
                "SELECT device_id FROM alerts WHERE device_id IN ? AND state = ?",
                (device_ids.to_vec(), state_to_str(&AlertState::Active)),
            )
            .await?
            .into_rows_result()?
            .rows::<(Uuid,)>()?
            .collect::<Result<_, _>>()?;
        let mut counts = HashMap::new();
        for (id,) in rows {
            *counts.entry(id).or_insert(0i64) += 1;
        }
        Ok(counts)
    }
}
