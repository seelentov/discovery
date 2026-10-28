use std::sync::Arc;
use std::time::Duration;

use discovery_config_store::SettingsStore;
use discovery_logging::LogStore;
use tracing::{info, warn};

/// Periodically enforces `LogRetentionConfig.retention_secs` — added 2026-08-21, scale
/// audit finding: `logs` had no retention mechanism at all, unlike `device_metric_history`/
/// `alerts`. Cadence is `poll_intervals.logs_cleanup_secs` (default: once an hour) — read
/// fresh from `settings` every iteration, same pattern as `alert_history_cleanup`'s loop.
/// `retention_secs = None` (the default — "keep forever") means this loop simply never
/// prunes anything, ever, same shape as `AlertRetentionConfig`.
pub async fn run_log_cleanup_loop(log_store: Arc<dyn LogStore>, settings: Arc<dyn SettingsStore>) {
    loop {
        let intervals = settings.poll_intervals().await;
        tokio::time::sleep(Duration::from_secs(intervals.logs_cleanup_secs)).await;

        let Some(retention_secs) = settings.log_retention().await.retention_secs else {
            continue; // "keep forever" — nothing to prune this tick
        };

        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(retention_secs as i64);
        match log_store.prune_older_than(cutoff).await {
            Ok(deleted) if deleted > 0 => info!(
                deleted,
                retention_secs, "log cleanup: pruned expired log rows"
            ),
            Ok(_) => {} // nothing to delete this tick (or a backend that can't report a count, e.g. ClickHouse) — not worth logging
            Err(e) => warn!(error = %e, "log cleanup: prune failed"),
        }
    }
}
