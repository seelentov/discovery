use serde::{Deserialize, Serialize};

fn default_identity_secs() -> u64 {
    300
}
fn default_metric_secs() -> u64 {
    15
}
fn default_profiles_reload_secs() -> u64 {
    5
}
fn default_discovery_schedule_check_secs() -> u64 {
    30
}
fn default_metric_history_cleanup_secs() -> u64 {
    3600
}
fn default_reachability_secs() -> u64 {
    60
}
fn default_alert_cleanup_secs() -> u64 {
    3600
}
fn default_dead_device_cleanup_secs() -> u64 {
    3600
}
fn default_group_alert_sweep_secs() -> u64 {
    30
}
fn default_logs_cleanup_secs() -> u64 {
    3600
}
fn default_journal_cleanup_secs() -> u64 {
    3600
}
fn default_trap_ttl_sweep_secs() -> u64 {
    60
}
fn default_syslog_ttl_sweep_secs() -> u64 {
    60
}
// Same cost class/default as `reachability_secs` — an L4/L7 check is one more per-device
// network round trip per tick, same "не нужно чаще минуты для большинства случаев" default
// as ping/SNMP reachability.
fn default_service_check_secs() -> u64 {
    60
}

/// Process-wide poll cadences — how often each recurring background activity runs.
///
/// **Moved here from `discovery-bootstrap` 2026-08-16** (direct user request: "конфигурацию
/// мы храним в БД! И должна быть возможность для webui для изменения настроек + они должны
/// сразу применяться"). Until then this lived in `config.toml` only, read once at process
/// startup and never revisited — exactly the "нельзя-в-бд" bootstrap category
/// `discovery-bootstrap`'s docs describe. That framing stops being true for *this*
/// particular settings group the moment there's a web UI to edit it and an expectation that
/// an edit takes effect without a restart: there's no chicken-and-egg problem here (unlike
/// `storage.kind`/`database_url`, which really must be known before any database can be
/// reached at all) — `poll_intervals` only ever gets read *after* the process already has a
/// working store.
///
/// `discovery_bootstrap::Config::poll_intervals` (loaded from `config.toml`, if present)
/// still exists — but now purely as the **first-run seed default**, written into
/// `discovery_config_store::SettingsStore` once if the store has nothing yet (see
/// `discovery-agent::main::build_stores`'s docs). After that first write, `config.toml`'s
/// `[poll_intervals]` section is inert — the database is the live source of truth, read
/// fresh by every consumer (`SnmpPollHandler`, `MetricPollHandler`,
/// `ReachabilityPollHandler`, and the three background loops) rather than captured once at
/// construction time, which is what actually makes a dashboard edit apply immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PollIntervalsConfig {
    #[serde(default = "default_identity_secs")]
    pub identity_secs: u64,
    #[serde(default = "default_metric_secs")]
    pub metric_secs: u64,
    #[serde(default = "default_profiles_reload_secs")]
    pub profiles_reload_secs: u64,
    /// Must stay comfortably under 60s to reliably catch every scheduled discovery
    /// minute — see `discovery-agent::discovery_scan::run_discovery_schedule_loop`.
    #[serde(default = "default_discovery_schedule_check_secs")]
    pub discovery_schedule_check_secs: u64,
    /// How often `discovery-agent::metric_history_cleanup` sweeps `device_metric_history`
    /// for rows past their metric's configured `history_retention_secs`. Defaults to once
    /// an hour: this is pure housekeeping, not something that needs to react quickly — a
    /// retention window measured in days/weeks doesn't need enforcing to the minute.
    #[serde(default = "default_metric_history_cleanup_secs")]
    pub metric_history_cleanup_secs: u64,
    /// How often each device's ping+SNMP reachability status refreshes — see
    /// `discovery_core::Device`'s `ping_ok`/`snmp_ok` docs.
    #[serde(default = "default_reachability_secs")]
    pub reachability_secs: u64,
    /// How often `discovery-agent::alert_history_cleanup` sweeps the `alerts` table for
    /// cleared alerts past `AlertRetentionConfig::retention_secs` — direct user request
    /// 2026-08-17, same pure-housekeeping reasoning as `metric_history_cleanup_secs`.
    #[serde(default = "default_alert_cleanup_secs")]
    pub alert_cleanup_secs: u64,
    /// How often `discovery-agent::dead_device_cleanup` sweeps `devices` for rows past
    /// `DeadDeviceRetentionConfig::unreachable_for_secs` — direct user request
    /// 2026-08-18, same pure-housekeeping reasoning as `alert_cleanup_secs`/
    /// `metric_history_cleanup_secs`. Idles harmlessly (0 rows deleted, no query even run)
    /// when the retention setting is `0` (the default — auto-delete disabled).
    #[serde(default = "default_dead_device_cleanup_secs")]
    pub dead_device_cleanup_secs: u64,
    /// How often `discovery-agent::group_alert` re-correlates active alerts against the
    /// topology graph to (re)compute `Alert::suppressed_by_alert_id` — 2026-09-16. Short
    /// default (matching `reachability_secs`/`trap_ttl_sweep_secs`, not the hour-scale
    /// `*_cleanup_secs` housekeeping fields): unlike those, a slow cadence here directly
    /// delays the thing this feature exists for — collapsing a topology-caused alert storm
    /// down to one root cause — so it needs to run often, not just eventually.
    #[serde(default = "default_group_alert_sweep_secs")]
    pub group_alert_sweep_secs: u64,
    /// How often `discovery-agent::log_cleanup` sweeps the `logs` table for rows past
    /// `LogRetentionConfig::retention_secs` — added 2026-08-21, scale audit finding: unlike
    /// `device_metric_history`/`alerts`, `logs` had no retention mechanism at all before
    /// this, so it grew without bound. Same pure-housekeeping reasoning/default as the
    /// other `*_cleanup_secs` fields.
    #[serde(default = "default_logs_cleanup_secs")]
    pub logs_cleanup_secs: u64,
    /// How often `discovery-agent::journal_cleanup` sweeps the `journal_entries` table for
    /// rows past `JournalRetentionConfig::retention_secs`. Same pure-housekeeping
    /// reasoning/default as `logs_cleanup_secs`, which this mirrors.
    #[serde(default = "default_journal_cleanup_secs")]
    pub journal_cleanup_secs: u64,
    /// How often `discovery-agent::trap_ttl_sweep` evicts trap-derived rows/singleton
    /// facts (`metrics.trap_<binding name>`) untouched by any `TrapEventSpec` variant for
    /// longer than that binding's own `TrapSpec::ttl_secs` — SNMP Trap ingestion,
    /// 2026-08-30. Deliberately a short default (matching `reachability_secs`, not the
    /// hour-scale `*_cleanup_secs` housekeeping fields above): unlike those, this sweep is
    /// what actually produces `AutoClearReason::RowMissing`/"Утеряна" for trap-derived
    /// alerts — see `docs/Changelog/2026-08-30 - SNMP Trap.md` for why nothing else could
    /// ever detect that on its own, since trap-derived tables aren't rebuilt on a polling
    /// cadence the way a walked SNMP table is.
    #[serde(default = "default_trap_ttl_sweep_secs")]
    pub trap_ttl_sweep_secs: u64,
    /// How often `discovery-agent::syslog_ttl_sweep` evicts syslog-derived rows/singleton
    /// facts (`metrics.syslog_<binding name>`) untouched by any `SyslogEventSpec` variant
    /// for longer than that binding's own `SyslogSpec::ttl_secs` — Syslog ingestion,
    /// 2026-09-06. Direct sibling of `trap_ttl_sweep_secs`, same reasoning and default.
    #[serde(default = "default_syslog_ttl_sweep_secs")]
    pub syslog_ttl_sweep_secs: u64,
    /// Fallback cadence for a profile's `service_checks` section (L4/L7 TCP/HTTP/SSH
    /// reachability, 2026-09-07) when it declares no `schedule` of its own — same role
    /// `metric_secs` plays for a `[metrics.poll]` entry with no per-metric schedule. See
    /// `discovery_agent::handlers::ServiceCheckPollHandler`'s docs.
    #[serde(default = "default_service_check_secs")]
    pub service_check_secs: u64,
}

impl Default for PollIntervalsConfig {
    fn default() -> Self {
        Self {
            identity_secs: default_identity_secs(),
            metric_secs: default_metric_secs(),
            profiles_reload_secs: default_profiles_reload_secs(),
            discovery_schedule_check_secs: default_discovery_schedule_check_secs(),
            metric_history_cleanup_secs: default_metric_history_cleanup_secs(),
            reachability_secs: default_reachability_secs(),
            alert_cleanup_secs: default_alert_cleanup_secs(),
            dead_device_cleanup_secs: default_dead_device_cleanup_secs(),
            group_alert_sweep_secs: default_group_alert_sweep_secs(),
            logs_cleanup_secs: default_logs_cleanup_secs(),
            journal_cleanup_secs: default_journal_cleanup_secs(),
            trap_ttl_sweep_secs: default_trap_ttl_sweep_secs(),
            syslog_ttl_sweep_secs: default_syslog_ttl_sweep_secs(),
            service_check_secs: default_service_check_secs(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_the_documented_values() {
        let d = PollIntervalsConfig::default();
        assert_eq!(d.identity_secs, 300);
        assert_eq!(d.metric_secs, 15);
        assert_eq!(d.reachability_secs, 60);
        assert_eq!(d.service_check_secs, 60);
    }

    #[test]
    fn partial_json_keeps_defaults_for_the_rest() {
        let parsed: PollIntervalsConfig =
            serde_json::from_str(r#"{"reachability_secs": 10}"#).unwrap();
        assert_eq!(parsed.reachability_secs, 10);
        assert_eq!(
            parsed.metric_secs, 15,
            "untouched field must keep its default"
        );
    }

    #[test]
    fn round_trips_through_json() {
        let original = PollIntervalsConfig {
            reachability_secs: 42,
            ..Default::default()
        };
        let json = serde_json::to_string(&original).unwrap();
        let back: PollIntervalsConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(original, back);
    }
}
