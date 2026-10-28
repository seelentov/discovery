use std::sync::Arc;
use std::time::Duration;

use discovery_auth::AuthStore;
use tracing::{info, warn};

/// Sweeps expired login sessions — added 2026-08-21, scale audit finding:
/// `AuthStore::delete_expired_sessions` existed since the auth feature shipped but was
/// never actually called anywhere, so the `sessions` table only ever grew. Not
/// device-count-critical (it grows with login activity, not fleet size) but a real,
/// easy-to-fix gap — `authenticate_session` already independently re-checks `expires_at`
/// on every request regardless of whether this sweep has run, so this loop is purely
/// housekeeping, same relationship `alert_history_cleanup`/`metric_history_cleanup` have
/// to their own stores.
///
/// Fixed hourly cadence, not a `poll_intervals` field — session hygiene doesn't need
/// per-installation tuning the way device-count-driven cleanups do; a config knob nobody
/// asked for is exactly the kind of thing this project's own discipline says not to add.
pub async fn run_session_cleanup_loop(auth: Arc<dyn AuthStore>) {
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        match auth.delete_expired_sessions().await {
            Ok(deleted) if deleted > 0 => {
                info!(deleted, "session cleanup: swept expired login sessions")
            }
            Ok(_) => {} // nothing to delete this tick — the common case, not worth logging
            Err(e) => warn!(error = %e, "session cleanup: sweep failed"),
        }
    }
}
