use std::sync::Arc;
use std::time::Duration;

use discovery_config_store::{ProfileStore, SettingsStore};
use discovery_devices::DeviceStore;
use discovery_dsl::ProfileMatcher;
use discovery_queue::JobQueueStore;
use discovery_web::reload_matcher_and_nudge_devices;
use tracing::warn;

/// Periodically re-reads the active profile set from `profile_store` and, if it actually
/// changed (by content, not just presence — see `ProfileFile::version`), hot-swaps it into
/// `matcher` (`ProfileMatcher::reload`) and proactively nudges every already-known device
/// back through the pipeline (re-enqueuing `SnmpPoll`) so the change takes effect within
/// one reload cycle instead of waiting up to `IDENTITY_POLL_INTERVAL_SECS` for each
/// device's next scheduled identity re-check.
///
/// **The actual "reload + nudge" logic lives in `discovery_web::reload_matcher_and_nudge_devices`
/// now (2026-08-18, direct user request), shared with that crate's `upsert_profile`/
/// `delete_profile` HTTP handlers** — this loop is the *fallback* path: it catches changes
/// made directly against `profile_store` that never go through the API at all (a
/// `FileProfileStore` edit, or `UPDATE profiles ... ` straight in psql — both documented,
/// real ways this project's profiles get edited). The API path no longer waits for this
/// loop's own tick; this loop still runs unconditionally so the direct-edit case keeps
/// working exactly as before.
///
/// `profile_store` is a [`ProfileStore`] — `FileProfileStore` (re-reads `profiles/*.toml`)
/// in the default/demo build, `PostgresProfileStore` (polls the `profiles` table) with
/// `--features postgres`. Either way this loop is what makes "change a profile while the
/// agent is running" actually reconfigure affected devices live — no restart required.
///
/// **`interval` read fresh from `settings` every iteration (2026-08-16), not fixed at
/// spawn time** — same "конфигурацию мы храним в БД... они должны сразу применяться"
/// requirement as everything else in `discovery_core::PollIntervalsConfig`'s docs. An edit
/// to `profiles_reload_secs` itself takes effect on this loop's very next tick — the one
/// poll interval that governs how quickly *every other* poll-interval edit is noticed at
/// all (`run()` re-reads `poll_intervals` at every iteration, this is just the outermost
/// one of the bunch).
pub async fn run_profile_reload_loop(
    profile_store: Arc<dyn ProfileStore>,
    matcher: Arc<ProfileMatcher>,
    devices: Arc<dyn DeviceStore>,
    store: Arc<dyn JobQueueStore>,
    settings: Arc<dyn SettingsStore>,
) {
    loop {
        tokio::time::sleep(Duration::from_secs(
            settings.poll_intervals().await.profiles_reload_secs,
        ))
        .await;

        if let Err(e) =
            reload_matcher_and_nudge_devices(&profile_store, &matcher, &devices, &store).await
        {
            warn!(error = %e, "failed to reload profiles — keeping the active set");
        }
    }
}
