use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A single polled value. `untagged` so it serializes as a plain JSON number/string/bool,
/// not `{"Int": 5}` — the dashboard and any future export format want plain values.
/// `Table` is the exception — it serializes as a plain JSON array of `MetricTableRow`
/// objects, which never collides with the scalar shapes (array vs. bare
/// number/string/bool), so `#[serde(untagged)]` still resolves unambiguously.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum MetricValue {
    Int(i64),
    Float(f64),
    Str(String),
    Bool(bool),
    /// A table-shaped SNMP metric (an OID that's a MIB table entry, not a scalar) — see
    /// `MetricSpec::Detailed::columns`'s docs in `discovery-dsl` for how a metric ends up
    /// here vs. one of the scalar variants above, and `discovery-snmp`'s `build_metric_table`/
    /// `build_metric_table_auto` for how a raw SNMP walk becomes this shape. A cell inside
    /// a row (`MetricTableRow::fields`) is itself typed `MetricValue` for convenience (no
    /// separate cell-only enum) but will never actually be `Table` — SNMP's own MIB syntax
    /// (SMIv2 `Entry ::= SEQUENCE { ... }`) forbids a table column from being another table,
    /// so nothing in this codebase constructs a nested `Table` and nothing needs to guard
    /// against one; see the design discussion this came out of for the full reasoning.
    Table(Vec<MetricTableRow>),
}

impl MetricValue {
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            MetricValue::Int(v) => Some(*v as f64),
            MetricValue::Float(v) => Some(*v),
            MetricValue::Bool(v) => Some(if *v { 1.0 } else { 0.0 }),
            MetricValue::Str(_) | MetricValue::Table(_) => None,
        }
    }
}

/// One row of a table-shaped SNMP metric — see [`MetricValue::Table`]'s docs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MetricTableRow {
    /// The raw SNMP row index (the OID suffix after the column subid) — e.g. `"1"`, `"24"`
    /// for a simple single-integer-indexed table like `ifTable`, or a dotted composite for
    /// a multi-part index (e.g. an IP-address- or VLAN-keyed table). Kept as an opaque
    /// string, not decomposed into typed parts, for the same "v1, extend later if needed"
    /// reasoning documented on the design discussion — most tables this project targets
    /// (`ifTable`-alikes) have a single-integer index anyway.
    pub index: String,
    /// column name (from `MetricSpec::Detailed::columns`, or the raw subid string in
    /// "collect everything" auto mode) -> that column's value for this row. Not every
    /// declared column is guaranteed present in every row — a column a device didn't
    /// return for this particular index is simply absent here, not an error (see
    /// `build_metric_table`'s docs).
    pub fields: BTreeMap<String, MetricValue>,
}

/// The set of metrics collected for one device on one poll cycle, keyed by the metric
/// name declared in the device's profile (`[metrics.poll]` in the profile TOML) or a
/// subnet's one-shot discovery-time `oids`/`labels`.
///
/// This is the shape the DSL layer (Rhai `facts`/`metrics` scope — see
/// `discovery-dsl::matcher`/`dedup`/`alerts`) and the pipeline handlers deal in — an
/// in-memory bag with no notion of "when was this last polled". Durable storage
/// (`discovery-devices::DeviceStore`) keeps that timestamp per metric as of 2026-08-16
/// (direct user request: metrics moved from one JSONB blob on `devices` to their own
/// `device_metrics` table, one row per metric, with a `polled_at` column — see
/// `migrations/0003_device_metrics.sql`) — see [`MetricRecord`] for the row shape that
/// carries it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Metrics(pub BTreeMap<String, MetricValue>);

impl Metrics {
    pub fn get(&self, name: &str) -> Option<&MetricValue> {
        self.0.get(name)
    }

    pub fn insert(&mut self, name: impl Into<String>, value: MetricValue) {
        self.0.insert(name.into(), value);
    }
}

/// The outcome of one poll attempt for one metric — direct user request 2026-08-16: errors
/// used to be logged and dropped (`warn!` in `MetricPollHandler`, nothing persisted); now
/// every attempt, success or failure, is recorded (`DeviceStore::record_metric_polls`, see
/// `migrations/0012_device_metric_history.sql`'s docs for the storage model). Deliberately
/// **not** part of [`Metrics`]/[`MetricValue`] — the DSL layer (`DedupResolver`/
/// `ProfileMatcher`/`AlertEvaluator`) only ever needs the plain successful-value bag, never
/// error/attempt bookkeeping; that split keeps this change entirely contained to the
/// storage layer and the handlers that call it.
///
/// `PartialEq` (not `Eq` — `MetricValue::Float` rules that out) is mainly for tests; the
/// storage backends' own same-state comparisons work one level down, on the
/// `(Option<MetricValue>, Option<String>)` pair, not on this enum directly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MetricPollOutcome {
    Ok(MetricValue),
    Err(String),
}

/// One row of `device_metrics`: a metric's current cached state plus when it was last
/// touched. `DeviceStore::all_with_metrics`/dashboard `GET /api/devices` return these (not
/// bare [`Metrics`]) specifically so the dashboard can show staleness/errors per metric,
/// not just per device — a metric a profile stopped polling (edited out of
/// `[metrics.poll]`) is pruned from storage entirely (`DeviceStore::prune_metrics`), so
/// every row here is something currently declared as relevant.
///
/// **Changed 2026-08-16 (direct user request — metric change history):** `device_metrics`
/// is no longer the source of truth for a metric's value — it's a derived cache of the
/// latest row in `device_metric_history` (`migrations/0012_device_metric_history.sql`),
/// written in the same transaction as that table by the single writer
/// `DeviceStore::record_metric_polls`. `value`/`polled_at` now describe the **last
/// success** specifically (both `None` if the metric has never once succeeded); `error`/
/// `last_attempt_at` describe the **most recent attempt**, which may be more recent than
/// the last success if the metric is currently failing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricRecord {
    pub name: String,
    /// The last successfully polled value — `None` if this metric has never once
    /// succeeded (only errors so far).
    pub value: Option<MetricValue>,
    /// The error from the most recent poll attempt — `None` if that attempt succeeded.
    pub error: Option<String>,
    /// When `value` was obtained — `None` if it's never been obtained at all.
    pub polled_at: Option<chrono::DateTime<chrono::Utc>>,
    /// When the most recent poll was *attempted*, success or failure — this is the
    /// reliable "are we still actually checking this" signal (see the discussion this
    /// feature came out of: `devices.updated_at` is **not** reliable for that, since
    /// identity resolution touches it even when nothing was actually re-verified;
    /// `last_attempt_at` here only advances when a real poll attempt happened).
    pub last_attempt_at: chrono::DateTime<chrono::Utc>,
    /// A manual per-device override on this metric's on/off state, if one exists — direct
    /// user request 2026-08-16: "за определенными устройствами выключать временно
    /// метрики". `None` = no override, this device follows the profile's own per-metric
    /// default (`MetricSpec::Detailed::enabled`); `Some(true)`/`Some(false)` = explicitly
    /// forced on/off for this device specifically, regardless of what the profile says.
    /// **Never written by automatic profile (re)application** — only by an explicit
    /// per-metric toggle or "sync with profile" action (which *clears* this, it doesn't
    /// set it) — see `discovery_devices::DeviceStore`'s docs for the full contract this
    /// guarantees. The dashboard resolves the *effective* on/off state by combining this
    /// with the current profile's default (`discovery-web`'s `MetricView`), since
    /// `MetricRecord` alone doesn't know which profile a device is on.
    #[serde(default)]
    pub enabled_override: Option<bool>,
}

/// One row of `device_metric_history` — a past "state run" for one device+metric. See
/// `migrations/0012_device_metric_history.sql`'s docs for the run model: a row covers a
/// maximal stretch of consecutive polls that all produced the identical state (same value,
/// or the same error text); `last_observed_at` advances in place while the state repeats,
/// a new row only appears when the state actually changes. Added 2026-08-17, direct user
/// request (dashboard: "при нажатии в таблице на метрику увидеть её историю") — the first
/// read path over this table; until now it was write-only from the dashboard's
/// perspective, `MetricRecord`/`device_metrics` only ever expose the *current* state.
///
/// Deliberately doesn't carry `device_id`/`name` — the caller already knows both, they're
/// what it queried `DeviceStore::metric_history` by; repeating them on every row would be
/// pure noise for a per-device-per-metric history view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricHistoryRecord {
    /// `None` if this run's state was an error, not a value.
    pub value: Option<MetricValue>,
    /// `None` if this run's state was a successful value, not an error.
    pub error: Option<String>,
    pub first_observed_at: chrono::DateTime<chrono::Utc>,
    pub last_observed_at: chrono::DateTime<chrono::Utc>,
}

/// A page of `metric_history` results plus the total number of runs on record for that
/// device+metric (ignoring `limit`/`offset`) — same "page N of M, K total" shape as
/// `discovery_queue::JobListPage`, for the same reason (dashboard pagination controls
/// without a second round-trip).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricHistoryPage {
    pub records: Vec<MetricHistoryRecord>,
    pub total: i64,
}
