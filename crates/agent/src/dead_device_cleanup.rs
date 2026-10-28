use std::sync::Arc;
use std::time::Duration;

use discovery_config_store::SettingsStore;
use discovery_core::{ActiveChains, AlertStateTracker};
use discovery_devices::DeviceStore;
use tracing::{info, warn};

/// Periodically enforces `DeadDeviceRetentionConfig.unreachable_for_secs` — direct user
/// request 2026-08-18, a follow-up to manual per-device deletion already existing in the
/// UI: "Сделай настраиваемый через конфиг период времени после которого устройство с
/// ping=false удаляется. По умолчанию сделай 0 - если 0 никогда не удалять." Cadence is
/// `poll_intervals.dead_device_cleanup_secs` (default: once an hour) — read fresh from
/// `settings` every iteration, same pattern as `alert_history_cleanup`'s loop.
///
/// `unreachable_for_secs = 0` (the default — "never delete") means this loop simply never
/// prunes anything, ever, same "0/None disables the sweep entirely" shape as
/// `alert_history_cleanup` has for `AlertRetentionConfig::retention_secs`. See
/// `discovery_devices::DeviceStore::delete_unreachable_since`'s docs for exactly which
/// devices qualify (continuously unreachable for the threshold, and still `enabled`).
/// `identity_chains`/`active_chains`/`reachability_chains` — the *same* instances
/// `discovery-agent::handlers`'s recurring chains check, not private copies (added
/// 2026-08-21, scale/correctness audit): every device this sweep deletes must also be
/// forgotten from all three, or its ip/id stays permanently blocked from ever starting a
/// fresh chain again in this process — see `discovery_core::ActiveChains::remove`'s docs.
pub async fn run_dead_device_cleanup_loop(
    devices: Arc<dyn DeviceStore>,
    settings: Arc<dyn SettingsStore>,
    identity_chains: Arc<ActiveChains<String>>,
    active_chains: Arc<ActiveChains<uuid::Uuid>>,
    reachability_chains: Arc<ActiveChains<uuid::Uuid>>,
    alerts: Arc<AlertStateTracker>,
) {
    loop {
        let intervals = settings.poll_intervals().await;
        tokio::time::sleep(Duration::from_secs(intervals.dead_device_cleanup_secs)).await;

        let unreachable_for_secs = settings.dead_device_retention().await.unreachable_for_secs;
        if unreachable_for_secs == 0 {
            continue; // disabled — nothing to prune this tick
        }

        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(unreachable_for_secs as i64);
        match devices.delete_unreachable_since(cutoff).await {
            Ok(deleted) if !deleted.is_empty() => {
                for (id, ip) in &deleted {
                    alerts.remove_for_device(*id);
                    identity_chains.remove(ip);
                    active_chains.remove(id);
                    reachability_chains.remove(id);
                }
                info!(deleted = deleted.len(), unreachable_for_secs, "dead device cleanup: deleted devices unreachable past the configured threshold");
            }
            Ok(_) => {} // nothing to delete this tick — the common case, not worth logging
            Err(e) => warn!(error = %e, "dead device cleanup: delete failed"),
        }
    }
}
