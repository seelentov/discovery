use serde::{Deserialize, Serialize};

fn default_timeout_ms() -> u64 {
    2000
}

fn default_retries() -> u32 {
    1
}

/// Global ICMP ping probe behavior — direct user request 2026-08-18. Corrects an earlier
/// decision (see `discovery_agent::handlers`'s history) that only the *interval between*
/// reachability checks (`poll_intervals.reachability_secs`) should be configurable, not
/// the per-probe timeout: "'настраивать периодичность, не таймаут пробы' не правда. Нужно
/// сделать настраиваемым и таймауты и кол-во проб и периодичность." Periodicity stays
/// exactly where it already was (`PollIntervalsConfig.reachability_secs`) — this covers
/// the other two, mirroring the `snmp_timeout_ms`/`snmp_retries` pattern already used for
/// SNMP (`discovery_core::default_snmp_timeout_ms`/`default_snmp_retries`,
/// `discovery-config-store::SubnetSpec`), just without per-subnet overrides — nothing
/// asked for ping to vary by subnet, only one global value.
///
/// One value each, not per-subnet — `discovery_agent::handlers::DiscoveryHandler`'s
/// dead-device gate and `ReachabilityPollHandler`'s recurring check both read this fresh
/// (not cached) via `SettingsStore::ping_config`, same live-DB-editable/no-restart
/// treatment as `AlertRetentionConfig`/`PollIntervalsConfig`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PingConfig {
    /// How long to wait for a single echo reply before giving up on that attempt.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Additional attempts after the first failure (total attempts = `1 + retries`) —
    /// same convention as `SnmpClient`'s `target.retries`.
    #[serde(default = "default_retries")]
    pub retries: u32,
}

impl Default for PingConfig {
    fn default() -> Self {
        Self {
            timeout_ms: default_timeout_ms(),
            retries: default_retries(),
        }
    }
}
