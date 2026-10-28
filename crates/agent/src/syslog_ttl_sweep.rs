use std::sync::Arc;
use std::time::Duration;

use discovery_config_store::SettingsStore;
use tracing::warn;

use crate::syslog_ingest::{sweep_ttl_once, SyslogIngestState};

/// Periodically evicts syslog-derived rows/singletons untouched by any `SyslogEventSpec`
/// variant for longer than their binding's own `SyslogSpec::ttl_secs` — the only path that
/// can produce `AutoClearReason::RowMissing`/"Утеряна" for syslog-derived data, see
/// `syslog_ingest::sweep_ttl_once`'s docs. Direct sibling of
/// `trap_ttl_sweep::run_trap_ttl_sweep_loop`, own cadence
/// (`poll_intervals.syslog_ttl_sweep_secs`), read fresh from `settings` every iteration.
pub async fn run_syslog_ttl_sweep_loop(
    state: Arc<SyslogIngestState>,
    settings: Arc<dyn SettingsStore>,
) {
    loop {
        tokio::time::sleep(Duration::from_secs(
            settings.poll_intervals().await.syslog_ttl_sweep_secs,
        ))
        .await;

        if let Err(e) = sweep_ttl_once(&state).await {
            warn!(error = %e, "syslog ttl sweep: failed this tick");
        }
    }
}
