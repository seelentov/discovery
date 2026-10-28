use async_trait::async_trait;
use discovery_core::{
    MetricHistoryPage, MetricHistoryRecord, MetricPollOutcome, MetricRecord, MetricValue, Metrics,
};
use discovery_entities::{device_metric_history, device_metrics};
use sea_orm::sea_query::{Condition, Expr, OnConflict};
use sea_orm::{
    ActiveValue::NotSet, ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait,
    QueryFilter, QueryOrder, QuerySelect, TransactionTrait,
};
use std::collections::{BTreeMap, HashMap};
use uuid::Uuid;

use crate::DeviceMetricsStore;

fn value_to_metric(v: &serde_json::Value) -> anyhow::Result<MetricValue> {
    Ok(serde_json::from_value(v.clone())?)
}

fn record_from_model(m: device_metrics::Model) -> anyhow::Result<MetricRecord> {
    Ok(MetricRecord {
        name: m.name,
        value: m.value.as_ref().map(value_to_metric).transpose()?,
        error: m.error,
        polled_at: m.polled_at,
        last_attempt_at: m.last_attempt_at,
        enabled_override: None, // filled in by `crate::all_with_metrics` from DeviceStore's domain
    })
}

/// The sea-orm-backed implementation of [`DeviceMetricsStore`] — see that trait's docs.
pub struct SeaOrmDeviceMetricsStore {
    db: DatabaseConnection,
}

impl SeaOrmDeviceMetricsStore {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Convenience for tests — see `discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests`'s
    /// docs for why this exists and why it's async.
    pub async fn new_in_memory_for_tests() -> Self {
        Self::new(discovery_migration::connect_in_memory_for_tests().await)
    }

    /// One row per device in `device_ids` with its `MAX(last_observed_at)` for metric
    /// `name` — `only_successful = true` restricts to rows with a non-null `value` (the
    /// "latest success" half of [`DeviceMetricsStore::prune_metric_history_older_than`]'s
    /// two exemptions). A device absent from the result simply has no matching row at all
    /// (e.g. every attempt for it failed, when `only_successful = true`) — see that
    /// method's docs for why this replaced loading every row for these devices.
    async fn max_observed_at_per_device(
        db: &DatabaseConnection,
        name: &str,
        device_ids: &[Uuid],
        only_successful: bool,
    ) -> anyhow::Result<BTreeMap<Uuid, chrono::DateTime<chrono::Utc>>> {
        use sea_orm::sea_query::Func;
        use sea_orm::FromQueryResult;

        #[derive(FromQueryResult)]
        struct MaxRow {
            device_id: Uuid,
            max_ts: Option<chrono::DateTime<chrono::Utc>>,
        }

        let mut q = device_metric_history::Entity::find()
            .filter(device_metric_history::Column::Name.eq(name))
            .filter(device_metric_history::Column::DeviceId.is_in(device_ids.to_vec()));
        if only_successful {
            q = q.filter(device_metric_history::Column::Value.is_not_null());
        }

        let rows = q
            .select_only()
            .column(device_metric_history::Column::DeviceId)
            .column_as(
                Expr::expr(Func::max(Expr::col(
                    device_metric_history::Column::LastObservedAt,
                ))),
                "max_ts",
            )
            .group_by(device_metric_history::Column::DeviceId)
            .into_model::<MaxRow>()
            .all(db)
            .await?;

        Ok(rows
            .into_iter()
            .filter_map(|r| Some((r.device_id, r.max_ts?)))
            .collect())
    }
}

#[async_trait]
impl DeviceMetricsStore for SeaOrmDeviceMetricsStore {
    /// **Batched 2026-08-18** (direct user request — write throughput at a 500k-1M device
    /// target, see `discovery/CLAUDE.md`'s "Мульти-БД поддержка" section for the scale
    /// context). The original shape of this method did one `SELECT ... LIMIT 1 FOR UPDATE`
    /// + one `INSERT`-or-`UPDATE` **per metric in `results`, per table** — for a 20-metric
    /// profile that's up to ~80 sequential round trips for a single device's single poll
    /// tick. At the device counts this project is now explicitly targeting, that scales
    /// linearly with `results.len()` and dominates the whole pipeline's latency. This
    /// version does the same two tables in a small, `results.len()`-independent number of
    /// round trips (2 reads + up to 2 writes for `device_metric_history`, 1 read + 1 write
    /// for `device_metrics`) by batch-fetching what already exists and using set-based
    /// `UPDATE ... WHERE id IN (...)` / multi-row `INSERT` / `INSERT ... ON CONFLICT`
    /// instead of one statement per metric.
    ///
    /// **Traded away for this: the per-row `FOR UPDATE` lock on `device_metric_history`.**
    /// It was already documented as "shouldn't happen structurally today, but cheap to
    /// guard" — a device only ever has one active `MetricPoll` chain at a time (the
    /// generation guard / `ActiveChains`, see `discovery-agent::handlers`'s docs), so two
    /// concurrent writers racing to decide "is this a new state or the same one" for the
    /// same `(device_id, name)` isn't a scenario that can currently arise. It was also
    /// already a silent no-op on SQLite (see `discovery_queue::SeaOrmJobQueueStore::claim`'s
    /// docs for the same `lock`/SQLite interaction). Without the lock, the worst case if
    /// that assumption is ever violated is a duplicate history row for one transition — a
    /// minor data-quality blemish, not corruption — the same failure mode SQLite already
    /// tolerated unconditionally before this change.
    async fn record_metric_polls(
        &self,
        id: Uuid,
        results: &BTreeMap<String, MetricPollOutcome>,
    ) -> anyhow::Result<()> {
        if results.is_empty() {
            return Ok(());
        }

        let txn = self.db.begin().await?;
        let now = chrono::Utc::now();
        let names: Vec<String> = results.keys().cloned().collect();

        // ---- device_metric_history: find each name's latest row in 2 round trips, not N ----
        // Step 1: per-name `MAX(last_observed_at)` — a plain `GROUP BY`, portable across
        // Postgres/MySQL/SQLite without window functions (same reasoning as
        // `prune_metric_history_older_than`'s docs on avoiding per-dialect SQL).
        let maxes: Vec<(String, chrono::DateTime<chrono::Utc>)> =
            device_metric_history::Entity::find()
                .filter(device_metric_history::Column::DeviceId.eq(id))
                .filter(device_metric_history::Column::Name.is_in(names.clone()))
                .select_only()
                .column(device_metric_history::Column::Name)
                .column_as(
                    device_metric_history::Column::LastObservedAt.max(),
                    "last_observed_at",
                )
                .group_by(device_metric_history::Column::Name)
                .into_tuple()
                .all(&txn)
                .await?;

        // Step 2: fetch those exact rows by `(name, last_observed_at)` pairs, built as an
        // OR-of-ANDs rather than a tuple-IN — SQLite's tuple-IN support is version-
        // dependent, OR-of-ANDs is standard SQL everywhere. A tie (two rows for the same
        // name sharing the exact same microsecond timestamp) is astronomically unlikely
        // and, worst case, just picks one of them below — no worse than the pre-batching
        // behavior under the same theoretical race.
        let latest_by_name: HashMap<String, device_metric_history::Model> = if maxes.is_empty() {
            HashMap::new()
        } else {
            let mut cond = Condition::any();
            for (name, last_observed_at) in &maxes {
                cond = cond.add(
                    Condition::all()
                        .add(device_metric_history::Column::Name.eq(name.clone()))
                        .add(device_metric_history::Column::LastObservedAt.eq(*last_observed_at)),
                );
            }
            device_metric_history::Entity::find()
                .filter(device_metric_history::Column::DeviceId.eq(id))
                .filter(cond)
                .all(&txn)
                .await?
                .into_iter()
                .map(|row| (row.name.clone(), row))
                .collect()
        };

        // ---- device_metrics cache: batch-fetch existing rows in 1 round trip, not N ----
        let existing_cache: HashMap<String, device_metrics::Model> = device_metrics::Entity::find()
            .filter(device_metrics::Column::DeviceId.eq(id))
            .filter(device_metrics::Column::Name.is_in(names))
            .all(&txn)
            .await?
            .into_iter()
            .map(|row| (row.name.clone(), row))
            .collect();

        let mut history_unchanged_ids: Vec<i64> = Vec::new();
        let mut history_new_rows: Vec<device_metric_history::ActiveModel> = Vec::new();
        let mut cache_models: Vec<device_metrics::ActiveModel> = Vec::with_capacity(results.len());

        for (name, outcome) in results {
            let (value_param, error_param): (Option<serde_json::Value>, Option<String>) =
                match outcome {
                    MetricPollOutcome::Ok(v) => (Some(serde_json::to_value(v)?), None),
                    MetricPollOutcome::Err(e) => (None, Some(e.clone())),
                };
            let is_success = matches!(outcome, MetricPollOutcome::Ok(_));

            match latest_by_name.get(name) {
                Some(row) if row.value == value_param && row.error == error_param => {
                    history_unchanged_ids.push(row.id);
                }
                _ => {
                    history_new_rows.push(device_metric_history::ActiveModel {
                        id: NotSet,
                        device_id: Set(id),
                        name: Set(name.clone()),
                        value: Set(value_param.clone()),
                        error: Set(error_param.clone()),
                        first_observed_at: Set(now),
                        last_observed_at: Set(now),
                    });
                }
            }

            // Cache upsert — `value`/`polled_at` move to the new value/now only on
            // success; on failure they're carried forward from whatever was already on
            // record (last known good value survives), only `error`/`last_attempt_at`
            // advance. Computed here (in Rust, against the batch-fetched `existing_cache`)
            // rather than as a per-dialect conditional SQL expression inside the upsert
            // below — keeps the upsert itself a plain unconditional column overwrite.
            let existing = existing_cache.get(name);
            let (final_value, final_polled_at) = if is_success {
                (value_param.clone(), Some(now))
            } else {
                (
                    existing.and_then(|r| r.value.clone()),
                    existing.and_then(|r| r.polled_at),
                )
            };
            cache_models.push(device_metrics::ActiveModel {
                device_id: Set(id),
                name: Set(name.clone()),
                value: Set(final_value),
                error: Set(error_param),
                polled_at: Set(final_polled_at),
                last_attempt_at: Set(now),
            });
        }

        if !history_unchanged_ids.is_empty() {
            device_metric_history::Entity::update_many()
                .filter(device_metric_history::Column::Id.is_in(history_unchanged_ids))
                .col_expr(
                    device_metric_history::Column::LastObservedAt,
                    Expr::value(now),
                )
                .exec(&txn)
                .await?;
        }
        if !history_new_rows.is_empty() {
            device_metric_history::Entity::insert_many(history_new_rows)
                .exec(&txn)
                .await?;
        }

        // `device_metrics`'s composite `(device_id, name)` primary key makes this a genuine
        // single-statement multi-row upsert (`INSERT ... ON CONFLICT DO UPDATE` / MySQL's
        // `ON DUPLICATE KEY UPDATE`, sea-query picks the right one per backend) — no
        // per-dialect branching needed here, unlike `device_metric_history` above (which
        // has no natural conflict target, since it's append-only history, not a
        // one-row-per-key cache).
        device_metrics::Entity::insert_many(cache_models)
            .on_conflict(
                OnConflict::columns([
                    device_metrics::Column::DeviceId,
                    device_metrics::Column::Name,
                ])
                .update_columns([
                    device_metrics::Column::Value,
                    device_metrics::Column::Error,
                    device_metrics::Column::PolledAt,
                    device_metrics::Column::LastAttemptAt,
                ])
                .to_owned(),
            )
            .exec(&txn)
            .await?;

        txn.commit().await?;
        Ok(())
    }

    async fn prune_metrics(&self, id: Uuid, keep: &[String]) -> anyhow::Result<()> {
        let mut query =
            device_metrics::Entity::delete_many().filter(device_metrics::Column::DeviceId.eq(id));
        // Empty `keep` -> delete every metric for this device (nothing declared anymore);
        // special-cased in Rust rather than relying on how each backend's query builder
        // renders `NOT (name IN ())`, which isn't guaranteed identical across Postgres/
        // MySQL/SQLite.
        if !keep.is_empty() {
            query = query.filter(device_metrics::Column::Name.is_not_in(keep.to_vec()));
        }
        query.exec(&self.db).await?;
        Ok(())
    }

    async fn prune_metric_history_older_than(
        &self,
        name: &str,
        cutoff: chrono::DateTime<chrono::Utc>,
        keep_last_attempt: bool,
        keep_last_success: bool,
    ) -> anyhow::Result<u64> {
        // Portable equivalent of the old single Postgres-dialect `WITH ranked AS (...
        // ROW_NUMBER() OVER (PARTITION BY device_id ...))` CTE: window functions render
        // differently enough across backends (and SQLite's support is version-dependent)
        // that computing the per-device "is this the latest / latest-success row" rank in
        // Rust is more robust here than one hand-tuned SQL statement per dialect. Only
        // rows for `name` past `cutoff` are even candidates, so this stays cheap
        // regardless of total history size.
        let candidates = device_metric_history::Entity::find()
            .filter(device_metric_history::Column::Name.eq(name))
            .filter(device_metric_history::Column::LastObservedAt.lt(cutoff))
            .all(&self.db)
            .await?;

        if candidates.is_empty() {
            return Ok(0);
        }

        // Latest-attempt / latest-success *timestamps* must be computed against *every*
        // row for the device, not just the past-cutoff candidates — an old row can only be
        // exempt if it's genuinely at the device's single latest timestamp overall, which
        // might not even be in `candidates` (a device is protected by its truly-latest row
        // regardless of whether that row happens to also be past the cutoff).
        //
        // **Changed 2026-08-21, scale audit finding**: this used to load *every* history
        // row for these devices into memory (`all_rows_for_devices`) just to fold it down
        // to two per-device timestamps — at 1M devices with an unretained/noisy metric,
        // that could be millions of rows materialized on a single cleanup tick. Two
        // `GROUP BY ... MAX(last_observed_at)` aggregate queries return exactly one row
        // per device instead — the database does the folding, not this process's memory.
        // Semantic difference from the old row-by-row scan: this protects *every* row tied
        // for a device's max timestamp (not one arbitrarily "first found" id) — strictly
        // safer (never prunes fewer protected rows than before), and ties on a
        // microsecond-precision timestamp are vanishingly rare in practice anyway.
        let device_ids: Vec<Uuid> = candidates.iter().map(|r| r.device_id).collect();
        let latest_attempt =
            Self::max_observed_at_per_device(&self.db, name, &device_ids, false).await?;
        let latest_success =
            Self::max_observed_at_per_device(&self.db, name, &device_ids, true).await?;

        let to_delete: Vec<i64> = candidates
            .into_iter()
            .filter(|row| {
                let is_latest_attempt =
                    latest_attempt.get(&row.device_id) == Some(&row.last_observed_at);
                let is_latest_success =
                    latest_success.get(&row.device_id) == Some(&row.last_observed_at);
                !(keep_last_attempt && is_latest_attempt)
                    && !(keep_last_success && is_latest_success)
            })
            .map(|row| row.id)
            .collect();

        if to_delete.is_empty() {
            return Ok(0);
        }
        let result = device_metric_history::Entity::delete_many()
            .filter(device_metric_history::Column::Id.is_in(to_delete))
            .exec(&self.db)
            .await?;
        Ok(result.rows_affected)
    }

    async fn metric_history(
        &self,
        id: Uuid,
        name: &str,
        limit: i64,
        offset: i64,
        since: Option<chrono::DateTime<chrono::Utc>>,
        until: Option<chrono::DateTime<chrono::Utc>>,
    ) -> anyhow::Result<MetricHistoryPage> {
        use sea_orm::PaginatorTrait;

        let mut base = device_metric_history::Entity::find()
            .filter(device_metric_history::Column::DeviceId.eq(id))
            .filter(device_metric_history::Column::Name.eq(name));
        if let Some(since) = since {
            base = base.filter(device_metric_history::Column::LastObservedAt.gte(since));
        }
        if let Some(until) = until {
            base = base.filter(device_metric_history::Column::LastObservedAt.lte(until));
        }
        let total = base.clone().count(&self.db).await? as i64;
        let rows = base
            .order_by_desc(device_metric_history::Column::LastObservedAt)
            .limit(limit.max(0) as u64)
            .offset(offset.max(0) as u64)
            .all(&self.db)
            .await?;

        let records = rows
            .into_iter()
            .map(|row| {
                Ok(MetricHistoryRecord {
                    value: row.value.as_ref().map(value_to_metric).transpose()?,
                    error: row.error,
                    first_observed_at: row.first_observed_at,
                    last_observed_at: row.last_observed_at,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(MetricHistoryPage { records, total })
    }

    async fn get_metrics(&self, id: Uuid) -> anyhow::Result<Metrics> {
        let rows = device_metrics::Entity::find()
            .filter(device_metrics::Column::DeviceId.eq(id))
            .filter(device_metrics::Column::Value.is_not_null())
            .all(&self.db)
            .await?;
        let mut metrics = Metrics::default();
        for row in rows {
            if let Some(value) = row.value {
                metrics.0.insert(row.name, value_to_metric(&value)?);
            }
        }
        Ok(metrics)
    }

    async fn list_metrics_by_name_prefix(
        &self,
        prefix: &str,
    ) -> anyhow::Result<Vec<(Uuid, String, MetricValue)>> {
        let rows = device_metrics::Entity::find()
            .filter(device_metrics::Column::Name.starts_with(prefix))
            .filter(device_metrics::Column::Value.is_not_null())
            .all(&self.db)
            .await?;
        rows.into_iter()
            .filter_map(|row| row.value.map(|v| (row.device_id, row.name, v)))
            .map(|(id, name, v)| Ok((id, name, value_to_metric(&v)?)))
            .collect()
    }

    async fn get_metric_records(&self, id: Uuid) -> anyhow::Result<Vec<MetricRecord>> {
        let rows = device_metrics::Entity::find()
            .filter(device_metrics::Column::DeviceId.eq(id))
            .all(&self.db)
            .await?;
        rows.into_iter().map(record_from_model).collect()
    }

    async fn get_metric_records_for_many(
        &self,
        ids: &[Uuid],
    ) -> anyhow::Result<BTreeMap<Uuid, Vec<MetricRecord>>> {
        if ids.is_empty() {
            return Ok(BTreeMap::new());
        }
        let rows = device_metrics::Entity::find()
            .filter(device_metrics::Column::DeviceId.is_in(ids.to_vec()))
            .all(&self.db)
            .await?;
        let mut out: BTreeMap<Uuid, Vec<MetricRecord>> = BTreeMap::new();
        for row in rows {
            let device_id = row.device_id;
            out.entry(device_id)
                .or_default()
                .push(record_from_model(row)?);
        }
        Ok(out)
    }

    async fn delete_for_device(&self, id: Uuid) -> anyhow::Result<()> {
        device_metrics::Entity::delete_many()
            .filter(device_metrics::Column::DeviceId.eq(id))
            .exec(&self.db)
            .await?;
        device_metric_history::Entity::delete_many()
            .filter(device_metric_history::Column::DeviceId.eq(id))
            .exec(&self.db)
            .await?;
        Ok(())
    }
}
