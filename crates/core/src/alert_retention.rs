use serde::{Deserialize, Serialize};

/// Global alert-history retention — direct user request 2026-08-17: "добавь конфигурацию
/// на время хранения тревог". Unlike per-metric `history_retention_secs`
/// (`discovery_dsl::MetricSpec`, one value per metric *name*), this is a single
/// process-wide setting — the user asked for one retention knob for alert history, not
/// per-rule granularity. DB-backed via `discovery_config_store::SettingsStore`
/// (`get_alert_retention`/`set_alert_retention`), same "lives in the DB, editable from the
/// dashboard, applies on the cleanup loop's next tick" treatment as
/// `discovery_core::PollIntervalsConfig`.
///
/// Only **cleared** alerts are ever subject to this — an alert still `Active` is current
/// state, not history, and is never pruned regardless of age (see
/// `discovery_alerts::AlertStore::prune_cleared_older_than`'s docs). No per-alert
/// "keep the last one" exemption is needed here the way `device_metric_history` needed
/// two — an alert already carries an explicit `Active`/`Cleared` state, so "is this the
/// current one" is a plain SQL condition, not something that has to be inferred from
/// recency the way a plain value/error blob would.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AlertRetentionConfig {
    /// How long a **cleared** alert is kept before the cleanup sweep deletes it. `None`
    /// (the default) means keep forever.
    pub retention_secs: Option<u64>,
}
