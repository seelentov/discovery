use serde::{Deserialize, Serialize};

/// Audit journal retention — added alongside the "Журнал" feature (who did what, in which
/// domain, when — see `discovery_journal::JournalStore`'s docs). Same shape/convention as
/// `LogRetentionConfig`: one process-wide knob, DB-backed via
/// `discovery_config_store::SettingsStore` (`get_journal_retention`/`set_journal_retention`),
/// applies on `discovery-agent::journal_cleanup`'s next tick, no restart needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct JournalRetentionConfig {
    /// How long a journal entry is kept before the cleanup sweep deletes it. `None` (the
    /// default) means keep forever — an audit trail is exactly the kind of data an
    /// operator is more likely to want to bound deliberately than to have silently
    /// expire, same "explicit opt-in to bound growth" default as
    /// `LogRetentionConfig::retention_secs`/`AlertRetentionConfig::retention_secs`.
    pub retention_secs: Option<u64>,
}
