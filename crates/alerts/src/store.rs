use async_trait::async_trait;
use discovery_core::{
    Alert, AlertComment, AlertCommentAttachment, AlertLevel, AlertState, NewAttachment, SortDir,
};
use serde::Serialize;
use uuid::Uuid;

/// Which column to sort alert records by — see [`AlertListQuery`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertSortBy {
    FirstSeen,
    LastSeen,
    Level,
    Name,
    DeviceIp,
}

/// Search + filter + sort + paginate parameters for [`AlertStore::list`] — the dashboard's
/// Тревоги page (added 2026-08-17, direct user request: "добавь на ui раздел с тревогами,
/// фильтрацией, пагинацией, сортировкой, поиском"). Same shape/conventions as
/// `discovery_queue::JobListQuery`/`discovery-web`'s `DevicesQuery`.
#[derive(Debug, Clone)]
pub struct AlertListQuery {
    /// Internal indexed queues for unresolved operator response and NOC notices.
    pub response_pending: bool,
    pub screen_only: bool,
    /// Free-text, case-insensitive, matched against the device IP, alert name, and
    /// message.
    pub search: Option<String>,
    /// `None` means every level, not just one.
    pub level: Option<AlertLevel>,
    /// `None` means every state (active and cleared both).
    pub state: Option<AlertState>,
    /// Scope to one device — used by a future device-detail view; `None` for the
    /// dashboard's own top-level Тревоги page, which shows every device's alerts.
    pub device_id: Option<Uuid>,
    /// Inclusive lower/upper bound on `Alert::first_seen` — added 2026-08-27,
    /// design-artifact parity pass (round 3's date-range filter). `None` on either side
    /// means unbounded on that side.
    pub since: Option<chrono::DateTime<chrono::Utc>>,
    pub until: Option<chrono::DateTime<chrono::Utc>>,
    pub sort_by: AlertSortBy,
    pub sort_dir: SortDir,
    pub limit: i64,
    pub offset: i64,
}

impl Default for AlertListQuery {
    fn default() -> Self {
        Self {
            response_pending: false,
            screen_only: false,
            search: None,
            level: None,
            state: None,
            device_id: None,
            since: None,
            until: None,
            sort_by: AlertSortBy::LastSeen,
            sort_dir: SortDir::Desc,
            limit: 50,
            offset: 0,
        }
    }
}

/// One page of alert records plus the total count matching the filter (ignoring
/// `limit`/`offset`) — same "page N of M, K total" shape as `discovery_queue::JobListPage`.
#[derive(Debug, Clone, Serialize)]
pub struct AlertListPage {
    pub items: Vec<Alert>,
    pub total: i64,
}

/// Durable alert (incident) history — direct user request 2026-08-17: "сделай хранение
/// тревог в БД". Persists what `discovery_core::AlertStateTracker` decides (activation
/// debounce/anti-flap logic stays purely in-memory there, unchanged) so the dashboard can
/// show a full, paginated/filterable/sortable incident history, not just "what's active
/// right now".
///
/// **[`Self::upsert`] is the single write path** — called by
/// `discovery_agent::handlers::AlertEvalHandler` after *every* non-`None`
/// `AlertStateTracker::observe` transition (`Activated`/`StillActive`/`Cleared` all
/// persist; `Alert.id` is stable across a `StillActive` sequence's repeated calls, so this
/// is an insert-or-update by id, not an append-only log — mirrors
/// `discovery_devices::DeviceStore::record_metric_polls`'s "bump the current row in place"
/// discipline for a repeated identical state, just keyed on `id` instead of
/// `(device_id, name)` directly). A `StillActive` write is a plain field update
/// (`last_seen`/`message`), not a new row — same reasoning as `device_metric_history`
/// choosing not to grow one row per poll for an unchanged state.
///
/// One implementation — [`SeaOrmAlertStore`], works against Postgres/MySQL/SQLite (and, for
/// tests/zero-config, `sqlite::memory:`) through the same sea-orm entity/query code path,
/// replacing the old `PostgresAlertStore`/`SqliteAlertStore`/`InMemoryAlertStore` trio
/// (2026-08-18 multi-DB rewrite, direct user request — see `discovery_config_store::SeaOrmSettingsStore`'s
/// docs for the full rationale). `device_id` is a **soft** reference to `devices.device_id`
/// (no enforced `FOREIGN KEY`) — "Тревоги" and "Устройства" can independently route to
/// different physical databases now, so cascade-on-device-delete is application code's job
/// (`DeviceStore::delete`), not the database's.
#[async_trait]
pub trait AlertStore: Send + Sync {
    async fn save_runtime(
        &self,
        device_id: Uuid,
        snapshot: &discovery_core::AlertRuntimeSnapshot,
    ) -> anyhow::Result<()>;
    async fn runtime_page(
        &self,
        limit: u32,
        offset: u64,
    ) -> anyhow::Result<Vec<discovery_core::DeviceAlertRuntime>>;
    async fn shared_rules(
        &self,
    ) -> anyhow::Result<std::collections::BTreeMap<String, serde_json::Value>>;
    async fn save_shared_rule(
        &self,
        name: &str,
        definition: serde_json::Value,
    ) -> anyhow::Result<()>;
    async fn delete_shared_rule(&self, name: &str) -> anyhow::Result<()>;
    async fn record_source_event(
        &self,
        event: &discovery_core::AlertSourceEvent,
    ) -> anyhow::Result<()>;
    async fn prune_source_events(
        &self,
        before: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<u64>;
    async fn source_events(
        &self,
        device_id: Uuid,
        since: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<Vec<discovery_core::AlertSourceEvent>>;

    /// **Never touches `suppressed_by_alert_id`** — see [`Self::set_suppression`]'s docs
    /// for why that column has its own dedicated write path, excluded here on purpose.
    async fn upsert(&self, alert: &Alert) -> anyhow::Result<()>;

    /// Targeted single-column write for `suppressed_by_alert_id` — the *only* way this
    /// column is ever changed. Added 2026-09-17 fixing a real production bug: before this
    /// existed, `discovery_agent::group_alert`'s sweep loop set the column by mutating a
    /// full [`Alert`] and calling [`Self::upsert`], but `AlertEvalHandler::persist_transition`
    /// calls `upsert` too (on every throttled `StillActive` tick) with its own in-memory
    /// `AlertStateTracker` copy of the alert — created at activation time with
    /// `suppressed_by_alert_id: None` and never resynced with what the sweep writes out of
    /// band. Because the old `upsert` unconditionally overwrote every column including this
    /// one, the tracker's stale `None` silently clobbered the sweep's write on the very next
    /// `StillActive` persist (throttled to `STILL_ACTIVE_PERSIST_INTERVAL` ≈ 60s) — the
    /// suppression badge would flash on and immediately get erased again, so it never
    /// stayed visible on any alert that lived past one tick. `upsert` no longer touches this
    /// column at all (see its own docs); only this method does, and only the sweep loop
    /// calls it — the two writers no longer race over the same column.
    async fn set_suppression(
        &self,
        alert_id: Uuid,
        suppressed_by_alert_id: Option<Uuid>,
    ) -> anyhow::Result<()>;

    /// Updates operator acknowledgement without allowing the automatic alert pipeline
    /// to overwrite it with a stale in-memory snapshot.
    async fn set_acknowledgement(
        &self,
        alert_id: Uuid,
        acknowledged_by: Option<String>,
        acknowledged_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> anyhow::Result<()>;

    /// Updates the independent notification-snooze state.
    async fn set_snooze(
        &self,
        alert_id: Uuid,
        snoozed_until: Option<chrono::DateTime<chrono::Utc>>,
        snoozed_by: Option<String>,
    ) -> anyhow::Result<()>;

    /// The most recently *manually* closed alert (`closed_by.is_some()`) for the same
    /// `(device_id, name, row_key)`, cleared at or after `since` — `None` if there isn't
    /// one. Added 2026-09-17 fixing audit finding #4 (see
    /// `docs/Changelog/2026-09-17 - Аудит глазами оператора...md`): "Закрыть тревогу"
    /// creates a brand-new incident whenever the underlying condition is still true (see
    /// `discovery_core::Alert::closed_by`'s docs), which used to leave the closed alert's
    /// comment thread stranded with nothing pointing forward to the new one. Called by
    /// `discovery_agent::handlers::persist_alert_transition` right before persisting a
    /// fresh `Activated` alert, to decide `Alert::reopened_from_alert_id` — see that
    /// field's docs. Deliberately ignores an *automatically* cleared alert as a candidate:
    /// a condition clearing on its own and genuinely recurring later is normal incident
    /// behavior, not the "operator closed it while it was still true" scenario this exists
    /// to soften.
    async fn find_recent_manual_close(
        &self,
        device_id: Uuid,
        name: &str,
        row_key: Option<&str>,
        since: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<Option<Alert>>;

    async fn list(&self, query: &AlertListQuery) -> anyhow::Result<AlertListPage>;

    /// Single-row lookup by id — added 2026-08-18 for manual close/delete
    /// (`discovery-web`'s `close_alert`/`delete_alert` handlers need the current row,
    /// specifically `device_id`/`name`, to sever live tracking in `AlertStateTracker`
    /// before touching the durable record — see that type's `remove`'s docs for why).
    /// `None` if no such id exists.
    async fn get(&self, id: Uuid) -> anyhow::Result<Option<Alert>>;

    /// Deletes **cleared** alerts (`state = Cleared`) whose `cleared_at` is older than
    /// `cutoff` — direct user request: "добавь конфигурацию на время хранения тревог"
    /// (`discovery_core::AlertRetentionConfig`). Active alerts are never touched
    /// regardless of age — see that type's docs for why no extra "keep the latest"
    /// exemption is needed here the way `device_metric_history` needed one. Returns the
    /// number of rows deleted, purely for logging by the caller
    /// (`discovery-agent::alert_history_cleanup`).
    async fn prune_cleared_older_than(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<u64>;

    /// Unconditionally removes one alert by id, active or cleared — direct user request
    /// 2026-08-18: "нужна возможность вручную закрыть тревогу и отдельно — удалить
    /// тревогу (это две разные операции)". A no-op (not an error) if `id` doesn't exist.
    /// Callers are responsible for severing live tracking first if the alert might still
    /// be active (`AlertStateTracker::remove`) — this method only ever touches the
    /// durable row.
    async fn delete(&self, id: Uuid) -> anyhow::Result<()>;

    /// Appends one comment to an alert's thread — 2026-08-28, direct user request,
    /// supersedes the earlier single free-form `set_comment` (see `AlertComment`'s docs).
    /// The *only* place this table is ever written — never touched by `upsert` (the
    /// automatic-pipeline write path). Errors if `alert_id` doesn't exist (unlike the old
    /// `set_comment`'s silent no-op — appending *to* a specific thread makes "there is no
    /// such thread" a real error condition, not a harmless no-op the way "clear a comment
    /// that was already clear" was).
    ///
    /// `attachments` (2026-08-29, direct user request) are stored alongside the comment
    /// in the same call — there is no separate "attach a file to an existing comment"
    /// operation, matching the thread's own append-only, no-edit shape. Empty for the
    /// overwhelming majority of calls.
    async fn add_comment(
        &self,
        alert_id: Uuid,
        author: &str,
        text: &str,
        attachments: Vec<NewAttachment>,
    ) -> anyhow::Result<AlertComment>;

    /// The full thread for one alert, oldest first (reading order) — empty if none.
    /// Each comment's `attachments` field is populated with metadata only (no bytes —
    /// see `AlertCommentAttachment`'s docs), so this stays cheap regardless of how large
    /// any individual attachment's stored blob is.
    async fn list_comments(&self, alert_id: Uuid) -> anyhow::Result<Vec<AlertComment>>;

    /// One attachment's metadata plus its raw bytes, for the download endpoint
    /// (`GET /api/alerts/:id/comments/:comment_id/attachments/:attachment_id`). `None`
    /// if no such attachment exists.
    async fn get_attachment(
        &self,
        attachment_id: Uuid,
    ) -> anyhow::Result<Option<(AlertCommentAttachment, Vec<u8>)>>;

    /// Batched count of **active** alerts per device — direct user request 2026-08-28: an
    /// "active alerts" column on the Devices table. One query for a whole page of device
    /// ids (typically ≤500, `DevicesQuery::page_size`'s cap), not one query per device —
    /// same "resolve once per request" discipline `SeaOrmAlertStore::comment_counts` and
    /// `discovery-web::build_device_views`'s `profiles_by_name` map already use;
    /// `discovery-web`'s
    /// `devices` handler is polled every 1.5s while the Devices page is open (see that
    /// handler's docs on the 2026-08-21 scale rewrite), so this must scale with the page
    /// size, not the fleet. Device ids absent from the returned map have zero active
    /// alerts (not an error) — same "missing means zero" contract as `comment_counts`.
    async fn active_counts_by_device(
        &self,
        device_ids: &[Uuid],
    ) -> anyhow::Result<std::collections::HashMap<Uuid, i64>>;

    /// Deletes every alert (active or cleared) for one device — the cascade target
    /// `discovery_devices::DeviceStore::delete`/`delete_unreachable_since` call explicitly,
    /// added 2026-08-18's multi-DB rewrite: `alerts.device_id` is a **soft** reference (see
    /// `discovery_entities::alerts`'s docs), not an enforced `FOREIGN KEY`, since "Тревоги"
    /// and "Устройства" can independently route to different physical databases — a device
    /// delete can no longer rely on `ON DELETE CASCADE` to clean these up, so the device
    /// store calls this directly instead. Returns the number of rows deleted, purely for
    /// logging by the caller.
    async fn delete_for_device(&self, device_id: Uuid) -> anyhow::Result<u64>;
}
