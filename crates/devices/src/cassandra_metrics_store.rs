//! `CassandraDeviceMetricsStore` — the second [`DeviceMetricsStore`] backend (2026-08-18,
//! third pass, direct user request: "переходи на реализацию подключения к cassandra.
//! Пускай этот вариант тоже будет"). Domain chosen by the user, asked explicitly:
//! "device_metrics/device_metric_history" — Cassandra's partition-by-key/cluster-by-range
//! model is a canonical fit for exactly this domain's shape (`device_id` partition, metric
//! name + time clustering), and unlike ClickHouse (see that store's docs), Cassandra's
//! `INSERT`/`UPDATE` are literally the same fast, synchronous upsert operation — it
//! tolerates the "update-in-place on an unchanged poll" and "delete a device's rows on
//! removal" patterns this trait relies on just fine.
//!
//! **Schema, CQL-shaped rather than a straight port of the sea-orm tables:**
//!
//! ```cql
//! CREATE TABLE device_metrics (
//!     device_id uuid,
//!     name text,
//!     value text,             -- JSON-encoded MetricValue, same convention as
//!     error text,             -- discovery_logging::ClickHouseLogStore's `fields` column
//!     polled_at timestamp,
//!     last_attempt_at timestamp,
//!     PRIMARY KEY (device_id, name)
//! );
//!
//! CREATE TABLE device_metric_history (
//!     device_id uuid,
//!     name text,
//!     first_observed_at timestamp,
//!     last_observed_at timestamp,
//!     value text,
//!     error text,
//!     PRIMARY KEY (device_id, name, first_observed_at)
//! ) WITH CLUSTERING ORDER BY (name ASC, first_observed_at DESC);
//! ```
//!
//! **Why `first_observed_at`, not `last_observed_at`, is the clustering column that
//! identifies a "run".** The sea-orm design (see `SeaOrmDeviceMetricsStore::record_metric_polls`'s
//! docs) updates a run's `last_observed_at` *in place* every time the same state repeats.
//! In CQL, clustering columns are part of a row's primary key — they can never be updated,
//! only replaced (delete + insert a differently-keyed row). `first_observed_at` (when a run
//! *started*) is genuinely immutable once set, so it's the right primary-key column;
//! `last_observed_at` (when it was *last* seen) is ordinary row data, freely `UPDATE`-able.
//! Runs for a given `(device_id, name)` are strictly chronological — a run can't start
//! before an earlier run's `last_observed_at` — so ordering by `first_observed_at DESC`
//! (the declared clustering order) produces the exact same row order `metric_history`'s
//! contract (newest run first) promises, without needing `last_observed_at` in the key at
//! all.
//!
//! **`prune_metric_history_older_than`'s one honest compromise.** It's global by metric
//! *name* across every device (per the trait's contract) — but this table is partitioned
//! by `device_id`, not `name`, so that query doesn't have a device_id to route by. A
//! secondary index on `name` (`CREATE INDEX ... ON device_metric_history (name)`) plus
//! `ALLOW FILTERING` makes it possible, but Cassandra secondary indexes scan every node
//! rather than routing to one partition — genuinely worse than the sea-orm path's plain
//! indexed `WHERE name = ?`. Acceptable here specifically because this method only runs
//! from a background hourly cleanup job (`discovery-agent::metric_history_cleanup`), never
//! on a request's hot path — not a compromise this store would make for `record_metric_polls`
//! or any per-request read.
use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use discovery_core::{
    MetricHistoryPage, MetricHistoryRecord, MetricPollOutcome, MetricRecord, MetricValue, Metrics,
};
use scylla::Session;
use uuid::Uuid;

use crate::DeviceMetricsStore;

fn value_to_json(v: &MetricValue) -> anyhow::Result<String> {
    Ok(serde_json::to_string(v)?)
}

fn json_to_value(s: &str) -> anyhow::Result<MetricValue> {
    Ok(serde_json::from_str(s)?)
}

pub struct CassandraDeviceMetricsStore {
    session: Arc<Session>,
}

impl CassandraDeviceMetricsStore {
    pub fn new(session: Arc<Session>) -> Self {
        Self { session }
    }

    /// Creates the keyspace (if it doesn't already exist — `SimpleStrategy`, replication
    /// factor 1, the right default for a single local/dev node; a real multi-node
    /// deployment is expected to pre-create the keyspace with its own replication
    /// strategy, this is a "just works" default, not a production topology decision this
    /// store should be making) and the two tables, then switches the shared `Session` into
    /// it. Idempotent (`IF NOT EXISTS` throughout), safe to call on every startup — same
    /// contract as `discovery_logging::ClickHouseLogStore::ensure_schema`.
    pub async fn ensure_schema(session: &Session, keyspace: &str) -> anyhow::Result<()> {
        session
            .query_unpaged(format!("CREATE KEYSPACE IF NOT EXISTS {keyspace} WITH replication = {{'class': 'SimpleStrategy', 'replication_factor': 1}}"), &[])
            .await?;
        session.use_keyspace(keyspace, false).await?;

        session
            .query_unpaged(
                "CREATE TABLE IF NOT EXISTS device_metrics (
                    device_id uuid,
                    name text,
                    value text,
                    error text,
                    polled_at timestamp,
                    last_attempt_at timestamp,
                    PRIMARY KEY (device_id, name)
                )",
                &[],
            )
            .await?;

        session
            .query_unpaged(
                "CREATE TABLE IF NOT EXISTS device_metric_history (
                    device_id uuid,
                    name text,
                    first_observed_at timestamp,
                    last_observed_at timestamp,
                    value text,
                    error text,
                    PRIMARY KEY (device_id, name, first_observed_at)
                ) WITH CLUSTERING ORDER BY (name ASC, first_observed_at DESC)",
                &[],
            )
            .await?;

        // Only ever queried by `prune_metric_history_older_than` — see this module's docs
        // on why that method is the one place this store accepts a cross-partition scan.
        session
            .query_unpaged(
                "CREATE INDEX IF NOT EXISTS ON device_metric_history (name)",
                &[],
            )
            .await?;

        Ok(())
    }
}

#[async_trait]
impl DeviceMetricsStore for CassandraDeviceMetricsStore {
    async fn record_metric_polls(
        &self,
        id: Uuid,
        results: &BTreeMap<String, MetricPollOutcome>,
    ) -> anyhow::Result<()> {
        if results.is_empty() {
            return Ok(());
        }
        let now = Utc::now();

        for (name, outcome) in results {
            let (value_param, error_param): (Option<String>, Option<String>) = match outcome {
                MetricPollOutcome::Ok(v) => (Some(value_to_json(v)?), None),
                MetricPollOutcome::Err(e) => (None, Some(e.clone())),
            };

            // Latest run for this (device, name) — clustering order is `first_observed_at
            // DESC` within the `name` partition-prefix, so `LIMIT 1` is genuinely "the
            // latest run", not an arbitrary row.
            let existing = self
                .session
                .query_unpaged(
                    "SELECT first_observed_at, value, error FROM device_metric_history WHERE device_id = ? AND name = ? LIMIT 1",
                    (id, name.as_str()),
                )
                .await?
                .into_rows_result()?
                .rows::<(DateTime<Utc>, Option<String>, Option<String>)>()?
                .next()
                .transpose()?;

            let same_state = existing
                .as_ref()
                .is_some_and(|(_, v, e)| *v == value_param && *e == error_param);

            match (same_state, existing) {
                (true, Some((first_observed_at, _, _))) => {
                    // Extend the existing run — `first_observed_at` is the primary key,
                    // untouched; only the ordinary `last_observed_at` column changes.
                    self.session
                        .query_unpaged(
                            "UPDATE device_metric_history SET last_observed_at = ? WHERE device_id = ? AND name = ? AND first_observed_at = ?",
                            (now, id, name.as_str(), first_observed_at),
                        )
                        .await?;
                }
                _ => {
                    self.session
                        .query_unpaged(
                            "INSERT INTO device_metric_history (device_id, name, first_observed_at, last_observed_at, value, error) VALUES (?, ?, ?, ?, ?, ?)",
                            (id, name.as_str(), now, now, value_param.as_deref(), error_param.as_deref()),
                        )
                        .await?;
                }
            }

            // Cache upsert. Unlike the sea-orm path (which must read the existing cache row
            // first to preserve `value`/`polled_at` on a failed attempt — see
            // `SeaOrmDeviceMetricsStore::record_metric_polls`'s docs), CQL's per-column
            // `INSERT`/`UPDATE` only ever touches the columns actually listed — a failed
            // attempt simply never mentions `value`/`polled_at`, so whatever was already
            // there (or nothing, if this metric has never once succeeded) is left alone by
            // construction, no read-before-write needed.
            match outcome {
                MetricPollOutcome::Ok(_) => {
                    self.session
                        .query_unpaged(
                            "UPDATE device_metrics SET value = ?, error = ?, polled_at = ?, last_attempt_at = ? WHERE device_id = ? AND name = ?",
                            (value_param.as_deref(), None::<&str>, now, now, id, name.as_str()),
                        )
                        .await?;
                }
                MetricPollOutcome::Err(_) => {
                    self.session
                        .query_unpaged(
                            "UPDATE device_metrics SET error = ?, last_attempt_at = ? WHERE device_id = ? AND name = ?",
                            (error_param.as_deref(), now, id, name.as_str()),
                        )
                        .await?;
                }
            }
        }

        Ok(())
    }

    async fn prune_metrics(&self, id: Uuid, keep: &[String]) -> anyhow::Result<()> {
        let existing: Vec<String> = self
            .session
            .query_unpaged("SELECT name FROM device_metrics WHERE device_id = ?", (id,))
            .await?
            .into_rows_result()?
            .rows::<(String,)>()?
            .map(|r| r.map(|(n,)| n))
            .collect::<Result<_, _>>()?;

        let to_delete: Vec<String> = existing.into_iter().filter(|n| !keep.contains(n)).collect();
        if to_delete.is_empty() {
            return Ok(());
        }
        self.session
            .query_unpaged(
                "DELETE FROM device_metrics WHERE device_id = ? AND name IN ?",
                (id, to_delete),
            )
            .await?;
        Ok(())
    }

    async fn prune_metric_history_older_than(
        &self,
        name: &str,
        cutoff: chrono::DateTime<chrono::Utc>,
        keep_last_attempt: bool,
        keep_last_success: bool,
    ) -> anyhow::Result<u64> {
        // Cross-partition scan via the secondary index on `name` — see this module's docs
        // on why this is the one method that accepts one. `ALLOW FILTERING` is required
        // because the range condition is on `first_observed_at` (a clustering column, not
        // the indexed one).
        let candidates: Vec<(Uuid, DateTime<Utc>, Option<String>)> = self
            .session
            .query_unpaged(
                "SELECT device_id, first_observed_at, value FROM device_metric_history WHERE name = ? AND first_observed_at < ? ALLOW FILTERING",
                (name, cutoff),
            )
            .await?
            .into_rows_result()?
            .rows::<(Uuid, DateTime<Utc>, Option<String>)>()?
            .collect::<Result<_, _>>()?;
        if candidates.is_empty() {
            return Ok(0);
        }

        // Ranking (latest-attempt / latest-success per device) needs every row for `name`,
        // not just the past-cutoff candidates — same reasoning as
        // `SeaOrmDeviceMetricsStore::prune_metric_history_older_than`'s docs: an old row is
        // only exempt if it's genuinely the device's single latest, which might not itself
        // be past the cutoff.
        let all_rows: Vec<(Uuid, DateTime<Utc>, Option<String>)> = self
            .session
            .query_unpaged("SELECT device_id, first_observed_at, value FROM device_metric_history WHERE name = ? ALLOW FILTERING", (name,))
            .await?
            .into_rows_result()?
            .rows::<(Uuid, DateTime<Utc>, Option<String>)>()?
            .collect::<Result<_, _>>()?;

        let mut latest_attempt: BTreeMap<Uuid, DateTime<Utc>> = BTreeMap::new();
        let mut latest_success: BTreeMap<Uuid, DateTime<Utc>> = BTreeMap::new();
        for (device_id, first_observed_at, value) in &all_rows {
            let entry = latest_attempt
                .entry(*device_id)
                .or_insert(*first_observed_at);
            if first_observed_at > entry {
                *entry = *first_observed_at;
            }
            if value.is_some() {
                let entry = latest_success
                    .entry(*device_id)
                    .or_insert(*first_observed_at);
                if first_observed_at > entry {
                    *entry = *first_observed_at;
                }
            }
        }

        let mut deleted = 0u64;
        for (device_id, first_observed_at, _) in candidates {
            let is_latest_attempt = latest_attempt.get(&device_id) == Some(&first_observed_at);
            let is_latest_success = latest_success.get(&device_id) == Some(&first_observed_at);
            if (keep_last_attempt && is_latest_attempt) || (keep_last_success && is_latest_success)
            {
                continue;
            }
            self.session
                .query_unpaged("DELETE FROM device_metric_history WHERE device_id = ? AND name = ? AND first_observed_at = ?", (device_id, name, first_observed_at))
                .await?;
            deleted += 1;
        }
        Ok(deleted)
    }

    async fn metric_history(
        &self,
        id: Uuid,
        name: &str,
        limit: i64,
        offset: i64,
        since: Option<DateTime<Utc>>,
        until: Option<DateTime<Utc>>,
    ) -> anyhow::Result<MetricHistoryPage> {
        // No secondary index on `last_observed_at` — same "fetch everything for this
        // partition, filter client-side" tradeoff already disclosed for `offset` below,
        // just extended to `since`/`until` too. Fine at dashboard-scale history sizes.
        let rows: Vec<(Option<String>, Option<String>, DateTime<Utc>, DateTime<Utc>)> = self
            .session
            .query_unpaged("SELECT value, error, first_observed_at, last_observed_at FROM device_metric_history WHERE device_id = ? AND name = ?", (id, name))
            .await?
            .into_rows_result()?
            .rows::<(Option<String>, Option<String>, DateTime<Utc>, DateTime<Utc>)>()?
            .collect::<Result<_, _>>()?;

        let mut filtered: Vec<_> = rows
            .into_iter()
            .filter(|(_, _, _, last_observed_at)| {
                since.map(|s| *last_observed_at >= s).unwrap_or(true)
                    && until.map(|u| *last_observed_at <= u).unwrap_or(true)
            })
            .collect();
        // Rows arrive newest-first already (declared clustering order), but the filter
        // above preserves order so this is a no-op unless that assumption ever changes.
        filtered.sort_by(|a, b| b.3.cmp(&a.3));

        let total = filtered.len() as i64;
        let records = filtered
            .into_iter()
            .skip(offset.max(0) as usize)
            .take(limit.max(0) as usize)
            .map(|(value, error, first_observed_at, last_observed_at)| {
                Ok(MetricHistoryRecord {
                    value: value.as_deref().map(json_to_value).transpose()?,
                    error,
                    first_observed_at,
                    last_observed_at,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(MetricHistoryPage { records, total })
    }

    async fn get_metrics(&self, id: Uuid) -> anyhow::Result<Metrics> {
        let rows: Vec<(String, Option<String>)> = self
            .session
            .query_unpaged(
                "SELECT name, value FROM device_metrics WHERE device_id = ?",
                (id,),
            )
            .await?
            .into_rows_result()?
            .rows::<(String, Option<String>)>()?
            .collect::<Result<_, _>>()?;

        let mut metrics = Metrics::default();
        for (name, value) in rows {
            if let Some(value) = value {
                metrics.0.insert(name, json_to_value(&value)?);
            }
        }
        Ok(metrics)
    }

    /// **Full, unrestricted table scan** — `name` isn't part of the partition key
    /// (`PRIMARY KEY (device_id, name)`, see this module's docs), and this needs a prefix
    /// match, not equality, so even `ALLOW FILTERING` (used elsewhere in this store for
    /// equality-on-clustering-column lookups, e.g. `device_metric_history`'s `name = ?`
    /// queries) doesn't help — deliberately no `WHERE` at all, filtering by prefix in Rust
    /// after fetching, rather than relying on unverified CQL range-filtering semantics.
    /// Acceptable here specifically because the caller runs on a coarse cadence, not a hot
    /// path: `discovery-agent::trap_ttl_sweep` (`poll_intervals.trap_ttl_sweep_secs`,
    /// default 60s). Would need a secondary index (or a denormalized lookup table) before
    /// this could be called any more often than that.
    async fn list_metrics_by_name_prefix(
        &self,
        prefix: &str,
    ) -> anyhow::Result<Vec<(Uuid, String, MetricValue)>> {
        let rows: Vec<(Uuid, String, Option<String>)> = self
            .session
            .query_unpaged("SELECT device_id, name, value FROM device_metrics", ())
            .await?
            .into_rows_result()?
            .rows::<(Uuid, String, Option<String>)>()?
            .collect::<Result<_, _>>()?;

        rows.into_iter()
            .filter(|(_, name, _)| name.starts_with(prefix))
            .filter_map(|(id, name, value)| value.map(|v| (id, name, v)))
            .map(|(id, name, v)| Ok((id, name, json_to_value(&v)?)))
            .collect()
    }

    async fn get_metric_records(&self, id: Uuid) -> anyhow::Result<Vec<MetricRecord>> {
        let rows: Vec<(String, Option<String>, Option<String>, Option<DateTime<Utc>>, DateTime<Utc>)> = self
            .session
            .query_unpaged("SELECT name, value, error, polled_at, last_attempt_at FROM device_metrics WHERE device_id = ?", (id,))
            .await?
            .into_rows_result()?
            .rows::<(String, Option<String>, Option<String>, Option<DateTime<Utc>>, DateTime<Utc>)>()?
            .collect::<Result<_, _>>()?;

        rows.into_iter()
            .map(|(name, value, error, polled_at, last_attempt_at)| {
                Ok(MetricRecord {
                    name,
                    value: value.as_deref().map(json_to_value).transpose()?,
                    error,
                    polled_at,
                    last_attempt_at,
                    enabled_override: None,
                })
            })
            .collect()
    }

    async fn get_metric_records_for_many(
        &self,
        ids: &[Uuid],
    ) -> anyhow::Result<BTreeMap<Uuid, Vec<MetricRecord>>> {
        if ids.is_empty() {
            return Ok(BTreeMap::new());
        }
        // `IN` on the full partition key fans out to exactly those partitions — a
        // well-supported, efficient CQL pattern (unlike `IN`/range on a non-partition-key
        // column, which is what forces `ALLOW FILTERING` elsewhere in this store).
        let rows: Vec<(Uuid, String, Option<String>, Option<String>, Option<DateTime<Utc>>, DateTime<Utc>)> = self
            .session
            .query_unpaged(
                "SELECT device_id, name, value, error, polled_at, last_attempt_at FROM device_metrics WHERE device_id IN ?",
                (ids.to_vec(),),
            )
            .await?
            .into_rows_result()?
            .rows::<(Uuid, String, Option<String>, Option<String>, Option<DateTime<Utc>>, DateTime<Utc>)>()?
            .collect::<Result<_, _>>()?;

        let mut out: BTreeMap<Uuid, Vec<MetricRecord>> = BTreeMap::new();
        for (device_id, name, value, error, polled_at, last_attempt_at) in rows {
            let record = MetricRecord {
                name,
                value: value.as_deref().map(json_to_value).transpose()?,
                error,
                polled_at,
                last_attempt_at,
                enabled_override: None,
            };
            out.entry(device_id).or_default().push(record);
        }
        Ok(out)
    }

    async fn delete_for_device(&self, id: Uuid) -> anyhow::Result<()> {
        self.session
            .query_unpaged("DELETE FROM device_metrics WHERE device_id = ?", (id,))
            .await?;
        self.session
            .query_unpaged(
                "DELETE FROM device_metric_history WHERE device_id = ?",
                (id,),
            )
            .await?;
        Ok(())
    }
}
