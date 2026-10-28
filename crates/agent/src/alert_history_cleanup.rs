use std::sync::Arc;
use std::time::Duration;

use discovery_alerts::AlertStore;
use discovery_config_store::SettingsStore;
use tracing::{info, warn};

/// Periodically enforces `AlertRetentionConfig.retention_secs` — direct user request
/// 2026-08-17: "добавь конфигурацию на время хранения тревог". Cadence is
/// `poll_intervals.alert_cleanup_secs` (default: once an hour, see
/// `discovery_core::PollIntervalsConfig`'s docs) — read fresh from `settings` every
/// iteration, same as `metric_history_cleanup`'s loop.
///
/// Much simpler than `metric_history_cleanup` — one global value, not one per metric name
/// (direct user request's singular phrasing: "конфигурациб" — one setting, not per-rule),
/// and no per-name collapsing pass is needed. `retention_secs = None` (the default — "keep
/// forever") means this loop simply never deletes anything, ever.
pub async fn run_alert_history_cleanup_loop(
    alert_store: Arc<dyn AlertStore>,
    settings: Arc<dyn SettingsStore>,
) {
    loop {
        let intervals = settings.poll_intervals().await;
        tokio::time::sleep(Duration::from_secs(intervals.alert_cleanup_secs)).await;

        if let Err(error) = alert_store
            .prune_source_events(chrono::Utc::now() - chrono::Duration::days(2))
            .await
        {
            warn!(%error, "alert source cleanup failed");
        }
        let Some(retention_secs) = settings.alert_retention().await.retention_secs else {
            continue; // "keep forever" — nothing to prune this tick
        };

        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(retention_secs as i64);
        match alert_store.prune_cleared_older_than(cutoff).await {
            Ok(deleted) if deleted > 0 => info!(
                deleted,
                retention_secs, "alert history cleanup: pruned expired cleared alerts"
            ),
            Ok(_) => {} // nothing to delete this tick — the common case, not worth logging
            Err(e) => warn!(error = %e, "alert history cleanup: prune failed"),
        }
    }
}
