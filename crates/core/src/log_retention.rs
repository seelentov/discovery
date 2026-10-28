use serde::{Deserialize, Serialize};

/// Global log retention — added 2026-08-21, scale audit finding: `logs` had no retention
/// mechanism at all, unlike `device_metric_history` (`history_retention_secs` per metric)
/// and `alerts` (`AlertRetentionConfig`). Same shape as `AlertRetentionConfig`: one
/// process-wide knob, DB-backed via `discovery_config_store::SettingsStore`
/// (`get_log_retention`/`set_log_retention`), applies on `discovery-agent::log_cleanup`'s
/// next tick, no restart needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct LogRetentionConfig {
    /// How long a log row is kept before the cleanup sweep deletes it. `None` (the
    /// default) means keep forever — same "explicit opt-in to bound growth" default as
    /// `AlertRetentionConfig::retention_secs`.
    pub retention_secs: Option<u64>,
}
