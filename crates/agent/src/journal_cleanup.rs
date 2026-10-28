use std::sync::Arc;
use std::time::Duration;

use discovery_config_store::SettingsStore;
use discovery_journal::JournalStore;
use tracing::{info, warn};

/// Periodically enforces `JournalRetentionConfig.retention_secs` — same shape as
/// `discovery-agent::log_cleanup`'s loop, which this mirrors. Cadence is
/// `poll_intervals.journal_cleanup_secs` (default: once an hour), read fresh from
/// `settings` every iteration. `retention_secs = None` (the default — "keep forever")
/// means this loop simply never prunes anything, ever, same shape as `LogRetentionConfig`.
pub async fn run_journal_cleanup_loop(
    journal_store: Arc<dyn JournalStore>,
    settings: Arc<dyn SettingsStore>,
) {
    loop {
        let intervals = settings.poll_intervals().await;
        tokio::time::sleep(Duration::from_secs(intervals.journal_cleanup_secs)).await;

        let Some(retention_secs) = settings.journal_retention().await.retention_secs else {
            continue; // "keep forever" — nothing to prune this tick
        };

        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(retention_secs as i64);
        match journal_store.prune_older_than(cutoff).await {
            Ok(deleted) if deleted > 0 => info!(
                deleted,
                retention_secs, "journal cleanup: pruned expired journal entries"
            ),
            Ok(_) => {} // nothing to delete this tick — not worth logging
            Err(e) => warn!(error = %e, "journal cleanup: prune failed"),
        }
    }
}
