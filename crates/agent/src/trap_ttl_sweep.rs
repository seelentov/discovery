use std::sync::Arc;
use std::time::Duration;

use discovery_config_store::SettingsStore;
use tracing::warn;

use crate::trap_ingest::{sweep_ttl_once, TrapIngestState};

/// Periodically evicts trap-derived rows/singletons untouched by any `TrapEventSpec`
/// variant for longer than their binding's own `TrapSpec::ttl_secs` — the only path that
/// can produce `AutoClearReason::RowMissing`/"Утеряна" for trap-derived data, see
/// [`sweep_ttl_once`]'s docs. Idles harmlessly if `[snmp_trap].enabled = false` (no traps
/// ever ingested, `list_metrics_by_name_prefix("trap_")` finds nothing) or if no binding
/// sets a `ttl_secs`. Cadence — `poll_intervals.trap_ttl_sweep_secs`, read fresh from
/// `settings` every iteration, same live-editable convention as every other pure-
/// housekeeping loop here (`metric_history_cleanup`, `alert_history_cleanup`, ...).
pub async fn run_trap_ttl_sweep_loop(
    state: Arc<TrapIngestState>,
    settings: Arc<dyn SettingsStore>,
) {
    loop {
        tokio::time::sleep(Duration::from_secs(
            settings.poll_intervals().await.trap_ttl_sweep_secs,
        ))
        .await;

        if let Err(e) = sweep_ttl_once(&state).await {
            warn!(error = %e, "trap ttl sweep: failed this tick");
        }
    }
}
