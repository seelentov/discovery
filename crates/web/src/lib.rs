use axum::extract::{ConnectInfo, Path, Query};
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::{
    extract::State,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, put},
    Json, Router,
};
use dashmap::DashMap;
use discovery_alerts::{AlertListPage, AlertListQuery, AlertSortBy, AlertStore};
use discovery_auth::{validate_password, AccessLevel, AuthStore, AuthenticatedUser};
use discovery_config_store::{
    enqueue_scan, DiscoveryConfig, DiscoveryConfigStore, MaintenanceWindow, MaintenanceWindowStore,
    NotificationChannelStore, NotificationRule, NotificationRuleStore, ProfileStore, SettingsStore,
    SubnetTarget,
};
use discovery_core::payload::{
    OperatorAction, OperatorActionPayload, SnmpPollPayload, TopologyRecomputePayload,
};
use discovery_core::{
    ActiveChains, AiAssistantProviderConfig, Alert, AlertComment, AlertLevel, AlertRetentionConfig,
    AlertState, AlertStateTracker, ConfigBackupSettings, DeadDeviceRetentionConfig, Device, Domain, JobState,
    JournalRetentionConfig, MetricHistoryPage, MetricRecord, NewAttachment, NotificationChannel,
    NotificationChannelKind, NotificationProviderConfig, PingConfig, PollIntervalsConfig,
    QueueKind, SnmpAuth, SortDir, TokenBucket, WorkerActivity, WorkerRegistry,
};
use discovery_devices::{DeviceMetricsStore, DeviceStore};
use discovery_dsl::{profiles_signature, ProfileFile, ProfileMatcher};
use discovery_journal::{
    JournalEntry, JournalListPage, JournalListQuery, JournalSortBy, JournalStore,
};
use discovery_logging::{LogBuffer, LogEntry};
use discovery_queue::{JobListPage, JobListQuery, JobQueueStore, JobSortBy};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

// AI assistant (2026-09-18) — tool registry (`assistant_tools`) + chat orchestration
// (`assistant`, the REST handlers registered in `api_router` below). Split into their own
// modules rather than grown inline here — the first submodule split in this crate, made
// because the orchestration loop + tool registry is a self-contained enough unit of new
// logic to warrant it, not a change to how the rest of this (very large) file is organized.
mod alert_rules;
mod assistant;
mod assistant_tools;
mod service_discovery;

#[derive(Clone)]
pub struct DashboardState {
    pub store: Arc<dyn JobQueueStore>,
    pub alerts: Arc<AlertStateTracker>,
    pub alert_store: Arc<dyn AlertStore>,
    pub workers: Arc<WorkerRegistry>,
    pub logs: Arc<LogBuffer>,
    pub profiles: Arc<dyn ProfileStore>,
    /// Needed (added 2026-08-18, direct user request — "изменить профиль за устройством
    /// сразу") so `upsert_profile`/`delete_profile` can hot-swap the active set and nudge
    /// known devices immediately, not wait for `discovery-agent::profile_reload`'s own
    /// polling cycle (up to `profiles_reload_secs`, default 5s) to notice. That loop still
    /// exists and still runs — it's the fallback for edits made directly against the store
    /// (e.g. `UPDATE profiles ...` straight in psql) that never go through this API at
    /// all — but the common case (edit via dashboard/API) no longer waits on it.
    pub matcher: Arc<ProfileMatcher>,
    pub discovery_configs: Arc<dyn DiscoveryConfigStore>,
    pub devices: Arc<dyn DeviceStore>,
    /// Added 2026-08-18's `DeviceStore`/`DeviceMetricsStore` domain split — see
    /// `discovery_agent::handlers::DedupHandler::device_metrics`'s docs. Every endpoint
    /// that used to call a single-store `DeviceStore::all_with_metrics`/`get`/
    /// `metric_history` now composes `devices` with this via `discovery_devices::all_with_metrics`/`get`,
    /// or calls this directly for metric-history reads.
    pub device_metrics: Arc<dyn DeviceMetricsStore>,
    pub settings: Arc<dyn SettingsStore>,
    /// Local accounts, sessions, per-domain permissions (2026-08-21) — see
    /// `discovery_auth::AuthStore`'s docs. Every `/api/*` route except `/api/auth/login`
    /// requires a valid session; most additionally require a specific
    /// `discovery_core::Domain` permission (`guard`/`require_login` below build the
    /// `route_layer` middleware `router()` attaches per route).
    pub auth: Arc<dyn AuthStore>,
    /// The "Журнал" audit trail — who did what, in which functional area, when. Not one
    /// of the 8 routed domains (same treatment as `auth` above — see
    /// `discovery_entities::journal_entries`'s docs); written by
    /// `require_domain_permission`/`require_admin` after every successful mutating
    /// request, read via `GET /api/journal`.
    pub journal: Arc<dyn JournalStore>,
    /// Maintenance windows (2026-09-07) — see `discovery_core::Domain::MaintenanceWindows`'s
    /// docs. Read here for full CRUD (`/api/maintenance-windows*`) and to compute the
    /// "под ТО" indicator on device REST responses (`attach_maintenance_status`); the
    /// actual alert-suppression enforcement lives in
    /// `discovery_agent::handlers::AlertEvalHandler`, which holds its own independent
    /// handle on the same underlying store.
    pub maintenance_windows: Arc<dyn MaintenanceWindowStore>,
    /// Notification matrix (2026-09-10) — `discovery_core::Domain::Notifications`-gated
    /// CRUD (`/api/notifications/rules*`), see that domain variant's docs.
    pub notification_rules: Arc<dyn NotificationRuleStore>,
    /// Per-user notification channels — self-service (`/api/notifications/channels*`, no
    /// domain gate) plus admin-on-behalf-of (`/api/users/:id/notification-channels*`,
    /// `admin_guard!`), see `discovery_core::NotificationChannel`'s docs.
    pub notification_channels: Arc<dyn NotificationChannelStore>,
    /// Topology rules (2026-09-16) — `discovery_core::Domain::Topology`-gated CRUD
    /// (`/api/topology/rules*`) plus read-only resolved-graph endpoints
    /// (`/api/topology/rules/:name/neighbors/:device_id`, `/api/topology/rules/:name/edges`),
    /// see that domain variant's docs.
    pub topology_rules: Arc<dyn discovery_config_store::TopologyRuleStore>,
    pub topology: Arc<dyn discovery_topology::TopologyStore>,
    /// Group-alert suppression rules (2026-09-16) — `discovery_core::Domain::GroupAlerts`-
    /// gated CRUD (`/api/group-alerts/rules*`), see that domain variant's docs. The
    /// correlation result itself (`Alert::suppressed_by_alert_id`) is computed by
    /// `discovery_agent::group_alert`'s sweep loop, not this crate — this field only
    /// backs the rule editor.
    pub group_alert_rules: Arc<dyn discovery_config_store::GroupAlertRuleStore>,
    /// AI-assistant conversation/message history (2026-09-18) — self-service, no
    /// `discovery_core::Domain` gate (see `discovery_assistant::AssistantStore`'s docs);
    /// what the assistant is actually allowed to *do* within a conversation is bounded
    /// entirely by the calling user's own domain permissions, enforced fresh at each tool
    /// call's internal REST sub-request (`crate::assistant::execute_tool_call`), not by
    /// anything gating this store or the `/api/assistant/*` routes themselves.
    pub assistant: Arc<dyn discovery_assistant::AssistantStore>,
    /// Same process-local, in-memory "chain already running" trackers
    /// `discovery-agent::handlers` uses — shared (not a separate instance) so
    /// `delete_device` can call [`discovery_core::ActiveChains::remove`] and actually
    /// affect the same sets the recurring `SnmpPoll`/`MetricPoll`/`ReachabilityPoll`
    /// chains check, instead of clearing a `DashboardState`-local copy nothing else reads.
    /// Added 2026-08-21, scale/correctness audit — see that method's docs for the bug
    /// this fixes (a deleted device's IP could never be re-discovered again in this
    /// process's lifetime otherwise).
    pub identity_chains: Arc<ActiveChains<String>>,
    pub active_chains: Arc<ActiveChains<uuid::Uuid>>,
    pub reachability_chains: Arc<ActiveChains<uuid::Uuid>>,
    /// Per-(username, source-IP) login throttle (2026-09-12, commercial-readiness/security
    /// audit finding — `/api/auth/login` had zero brute-force protection). See
    /// [`LoginRateLimiter`]'s docs.
    pub login_rate_limiter: Arc<LoginRateLimiter>,
    pub action_enqueue_lock: Arc<tokio::sync::Mutex<()>>,
}

/// Re-reads `profile_store`, and if the set actually changed (by content — see
/// `ProfileFile::version` — not just presence), hot-swaps it into `matcher` and nudges
/// every already-known device back through `SnmpPoll` so the change is picked up on that
/// device's very next identity cycle instead of its regularly-scheduled one (which could
/// be `identity_secs` away, several minutes by default).
///
/// Shared by two callers, both of which need the exact same "did anything change, and if
/// so who needs to know" logic:
/// - `discovery-agent::profile_reload::run_profile_reload_loop` — the periodic fallback,
///   catches edits made directly against the store (`FileProfileStore`/direct DB writes)
///   that never go through this crate's HTTP API at all.
/// - This crate's `upsert_profile`/`delete_profile` handlers — call this immediately after
///   a successful write, so the API/dashboard path doesn't wait out the periodic loop's
///   own interval for something the caller already knows just changed.
///
/// Returns whether a reload actually happened (`false` = signature was already up to
/// date — the common case when the periodic loop calls this and nothing changed since its
/// last tick).
pub async fn reload_matcher_and_nudge_devices(
    profile_store: &Arc<dyn ProfileStore>,
    matcher: &Arc<ProfileMatcher>,
    devices: &Arc<dyn DeviceStore>,
    store: &Arc<dyn JobQueueStore>,
) -> anyhow::Result<bool> {
    let fresh = profile_store.load_all().await?;
    if profiles_signature(&fresh) == matcher.signature().await {
        return Ok(false); // nothing changed
    }

    info!("profile set changed — hot-reloading and re-checking known devices");
    matcher.reload(fresh).await;

    let known_devices = match devices.all().await {
        Ok(devices) => devices,
        Err(e) => {
            warn!(error = %e, "profiles reloaded, but failed to list known devices to re-check — they'll pick it up on their next scheduled identity poll instead");
            return Ok(true);
        }
    };
    for device in known_devices {
        // `recurring: false` — a one-off "re-check sooner than your next scheduled tick"
        // nudge, not a new chain. See `SnmpPollPayload`'s docs.
        let Ok(payload) = serde_json::to_value(SnmpPollPayload {
            ip: device.facts.ip.clone(),
            recurring: false,
        }) else {
            continue;
        };
        let _ = store
            .enqueue(QueueKind::SnmpPoll, payload, Some(&device.facts.ip))
            .await;
    }
    Ok(true)
}

/// Every route below is wrapped in `.route_layer(domain_guard!(state, Domain::X))`
/// mapping it to one of the 8 business domains — see `discovery_core::Domain`'s docs and
/// `discovery/CLAUDE.md`'s auth section for the full path -> domain table. `route_layer`
/// (not `layer`) on purpose: it only wraps routes actually registered on this
/// `MethodRouter`, so a 405 (wrong method, no matching handler at all) is still returned
/// as a 405, not swallowed into a 401/403 by middleware running before routing even
/// resolves — same distinction `axum`'s own docs draw between `route_layer`/`layer`.
/// `Domain::Alerts`/`Devices`/etc. cover `GET` (read) and every other method (write) alike
/// — `require_domain_permission` derives which level a given request needs from its HTTP
/// method, not from which domain it targets, so one layer per route covers both.
/// Builds the `route_layer` for one route's `Domain` check (`require_domain_permission`,
/// defined further down alongside the rest of the auth machinery). A `macro_rules!`
/// instead of a plain function on purpose: `axum::middleware::from_fn_with_state`'s return
/// type is an unnameable `impl Handler`-bound opaque type, which a helper *function*
/// cannot name in its return position without either fighting the trait bounds or boxing —
/// a macro just inlines the call at each of `router()`'s ~30 route registrations, so
/// nothing ever needs to name the type at all. Clones `state` itself so every call site
/// below reads `domain_guard!(state, Domain::X)`, not `domain_guard!(state.clone(), ...)`.
macro_rules! domain_guard {
    ($state:expr, $domain:expr) => {
        axum::middleware::from_fn_with_state(($state.clone(), $domain), require_domain_permission)
    };
}

/// Same reasoning as [`domain_guard`] above, for `/api/users*`'s `is_admin`-only routes.
macro_rules! admin_guard {
    ($state:expr) => {
        axum::middleware::from_fn_with_state($state.clone(), require_admin)
    };
}

/// Routes that are authenticated but intentionally outside a domain/admin guard
/// (personal notification channels and assistant conversations) still must not be
/// usable by an account whose bootstrap/temporary password has not been replaced.
macro_rules! password_guard {
    ($state:expr) => {
        axum::middleware::from_fn_with_state($state.clone(), require_password_change_completed)
    };
}

/// Everything this crate exposes over `/api/*` — no static-asset fallback. Split out from
/// `router()` (2026-08-29, direct user request: config.toml's `[server].enable_rest`/
/// `enable_webui` toggles, see `discovery/CLAUDE.md`'s REST-completeness audit note) so the
/// REST surface and the bundled webui's static assets can be turned off independently —
/// `router()`/`router_with_flags()` below are the only two ways any caller assembles a
/// route table; every route this crate will ever serve is registered exactly once, here.
fn api_router(state: DashboardState) -> Router {
    Router::new()
        .route("/api/auth/login", axum::routing::post(login))
        .route("/api/auth/logout", axum::routing::post(logout))
        .route("/api/auth/me", get(me))
        .route(
            "/api/auth/password",
            axum::routing::put(change_own_password),
        )
        .route(
            "/api/users",
            get(list_users)
                .post(create_user)
                .route_layer(admin_guard!(state)),
        )
        .route(
            "/api/users/:id",
            axum::routing::delete(delete_user).route_layer(admin_guard!(state)),
        )
        .route(
            "/api/users/:id/password",
            axum::routing::put(set_user_password).route_layer(admin_guard!(state)),
        )
        .route(
            "/api/users/:id/admin",
            axum::routing::put(set_user_admin).route_layer(admin_guard!(state)),
        )
        .route(
            "/api/users/:id/role",
            axum::routing::put(set_user_role).route_layer(admin_guard!(state)),
        )
        .route(
            "/api/roles",
            get(list_roles)
                .post(create_role)
                .route_layer(admin_guard!(state)),
        )
        .route(
            "/api/roles/:id",
            get(get_role)
                .put(update_role)
                .delete(delete_role)
                .route_layer(admin_guard!(state)),
        )
        // AI assistant provider credentials (2026-09-18) — admin-only like user/role
        // management, not a `discovery_core::Domain`, see `AiAssistantProviderConfig`'s docs.
        .route(
            "/api/settings/ai-assistant",
            get(get_ai_assistant_provider_settings)
                .put(put_ai_assistant_provider_settings)
                .route_layer(admin_guard!(state)),
        )
        .route(
            "/api/incidents",
            get(incidents).route_layer(domain_guard!(state, Domain::Alerts)),
        )
        .route(
            "/api/alert-rules/shared",
            get(alert_rules::shared_rules)
                .post(alert_rules::save_shared_rule)
                .route_layer(domain_guard!(state, Domain::Alerts)),
        )
        .route(
            "/api/alert-rules/shared/:name",
            axum::routing::delete(alert_rules::delete_shared_rule)
                .route_layer(domain_guard!(state, Domain::Alerts)),
        )
        .route(
            "/api/devices/:id/alert-rules",
            get(alert_rules::rule_statuses).route_layer(domain_guard!(state, Domain::Alerts)),
        )
        .route(
            "/api/alerts/:id/actions/:action",
            axum::routing::post(alert_rules::enqueue_interactive_action)
                .route_layer(domain_guard!(state, Domain::Alerts)),
        )
        .route(
            "/api/alerts/screen",
            get(alert_rules::screen_alerts).route_layer(domain_guard!(state, Domain::Alerts)),
        )
        .route(
            "/api/alerts",
            get(list_alerts).route_layer(domain_guard!(state, Domain::Alerts)),
        )
        .route(
            "/api/alerts/:id",
            get(get_alert)
                .delete(delete_alert)
                .route_layer(domain_guard!(state, Domain::Alerts)),
        )
        .route(
            "/api/alerts/:id/close",
            axum::routing::post(close_alert).route_layer(domain_guard!(state, Domain::Alerts)),
        )
        .route(
            "/api/alerts/:id/acknowledge",
            axum::routing::post(acknowledge_alert)
                .route_layer(domain_guard!(state, Domain::Alerts)),
        )
        .route(
            "/api/alerts/:id/unacknowledge",
            axum::routing::post(unacknowledge_alert)
                .route_layer(domain_guard!(state, Domain::Alerts)),
        )
        .route(
            "/api/alerts/:id/snooze",
            axum::routing::post(snooze_alert).route_layer(domain_guard!(state, Domain::Alerts)),
        )
        .route(
            "/api/alerts/:id/unsnooze",
            axum::routing::post(unsnooze_alert).route_layer(domain_guard!(state, Domain::Alerts)),
        )
        .route(
            "/api/alerts/:id/comments",
            get(list_alert_comments)
                .post(add_alert_comment)
                .route_layer(domain_guard!(state, Domain::Alerts)),
        )
        .route(
            "/api/alerts/:id/comments/:comment_id/attachments/:attachment_id",
            get(download_alert_attachment).route_layer(domain_guard!(state, Domain::Alerts)),
        )
        .route(
            "/api/queues",
            get(queues).route_layer(domain_guard!(state, Domain::Jobs)),
        )
        .route(
            "/api/queues/:kind/paused",
            axum::routing::put(set_queue_paused).route_layer(domain_guard!(state, Domain::Jobs)),
        )
        .route(
            "/api/queues/:kind/jobs",
            get(queue_jobs)
                .delete(clear_queue)
                .route_layer(domain_guard!(state, Domain::Jobs)),
        )
        .route(
            "/api/queues/:kind/jobs/:id",
            axum::routing::delete(delete_job).route_layer(domain_guard!(state, Domain::Jobs)),
        )
        .route(
            "/api/queues/:kind/jobs/:id/pause",
            axum::routing::post(pause_job).route_layer(domain_guard!(state, Domain::Jobs)),
        )
        .route(
            "/api/queues/:kind/jobs/:id/resume",
            axum::routing::post(resume_job).route_layer(domain_guard!(state, Domain::Jobs)),
        )
        .route(
            "/api/workers",
            get(workers).route_layer(domain_guard!(state, Domain::Jobs)),
        )
        .route(
            "/api/logs",
            get(logs).route_layer(domain_guard!(state, Domain::Logs)),
        )
        .route(
            "/api/devices",
            get(devices)
                .post(create_device)
                .route_layer(domain_guard!(state, Domain::Devices)),
        )
        .route(
            "/api/service-discovery",
            axum::routing::post(run_service_discovery)
                .route_layer(domain_guard!(state, Domain::Devices)),
        )
        .route(
            "/api/devices/enabled",
            axum::routing::put(set_all_devices_enabled)
                .route_layer(domain_guard!(state, Domain::Devices)),
        )
        .route(
            "/api/devices/:id",
            get(get_device_by_id)
                .delete(delete_device)
                .route_layer(domain_guard!(state, Domain::Devices)),
        )
        .route(
            "/api/devices/:id/enabled",
            axum::routing::put(set_device_enabled)
                .route_layer(domain_guard!(state, Domain::Devices)),
        )
        .route(
            "/api/devices/:id/actions",
            get(list_device_actions).route_layer(domain_guard!(state, Domain::Devices)),
        )
        .route(
            "/api/devices/:id/actions/:action",
            axum::routing::post(run_device_action)
                .route_layer(domain_guard!(state, Domain::Devices)),
        )
        .route(
            "/api/devices/:id/actions/jobs/:job_id",
            get(get_device_action)
                .delete(cancel_device_action)
                .route_layer(domain_guard!(state, Domain::Devices)),
        )
        .route(
            "/api/devices/:id/backups",
            get(list_device_backups).route_layer(domain_guard!(state, Domain::Devices)),
        )
        .route(
            "/api/devices/:id/backups/:job_id",
            get(download_device_backup).route_layer(domain_guard!(state, Domain::Devices)),
        )
        .route(
            "/api/devices/:id/backups/:left/diff/:right",
            get(diff_device_backups).route_layer(domain_guard!(state, Domain::Devices)),
        )
        .route(
            "/api/devices/:id/ssh_credentials",
            axum::routing::put(set_ssh_credentials)
                .route_layer(domain_guard!(state, Domain::Devices)),
        )
        .route(
            "/api/devices/:id/sync-profile",
            axum::routing::post(sync_device_metrics_with_profile)
                .route_layer(domain_guard!(state, Domain::Devices)),
        )
        .route(
            "/api/devices/:id/metrics/:name/history",
            get(metric_history).route_layer(domain_guard!(state, Domain::DeviceMetrics)),
        )
        .route(
            "/api/devices/:id/metrics/:name/enabled",
            axum::routing::put(set_metric_override)
                .delete(clear_metric_override)
                .route_layer(domain_guard!(state, Domain::DeviceMetrics)),
        )
        .route(
            "/api/profiles",
            get(list_profiles)
                .post(upsert_profile)
                .route_layer(domain_guard!(state, Domain::Profiles)),
        )
        .route(
            "/api/profiles/:name",
            get(get_profile)
                .delete(delete_profile)
                .route_layer(domain_guard!(state, Domain::Profiles)),
        )
        .route(
            "/api/profiles/:name/sync-devices",
            axum::routing::post(sync_profile_devices_metrics)
                .route_layer(domain_guard!(state, Domain::Profiles)),
        )
        .route(
            "/api/discovery-configs",
            get(list_discovery_configs)
                .post(upsert_discovery_config)
                .route_layer(domain_guard!(state, Domain::DiscoveryConfigs)),
        )
        .route(
            "/api/discovery-configs/:name",
            get(get_discovery_config)
                .delete(delete_discovery_config)
                .route_layer(domain_guard!(state, Domain::DiscoveryConfigs)),
        )
        .route(
            "/api/discovery-configs/:name/run",
            axum::routing::post(run_discovery_config_now)
                .route_layer(domain_guard!(state, Domain::DiscoveryConfigs)),
        )
        .route(
            "/api/settings/poll-intervals",
            get(get_poll_intervals)
                .put(put_poll_intervals)
                .route_layer(domain_guard!(state, Domain::Settings)),
        )
        .route(
            "/api/settings/alert-retention",
            get(get_alert_retention)
                .put(put_alert_retention)
                .route_layer(domain_guard!(state, Domain::Settings)),
        )
        .route(
            "/api/settings/log-retention",
            get(get_log_retention)
                .put(put_log_retention)
                .route_layer(domain_guard!(state, Domain::Settings)),
        )
        .route(
            "/api/settings/ping",
            get(get_ping_config)
                .put(put_ping_config)
                .route_layer(domain_guard!(state, Domain::Settings)),
        )
        .route(
            "/api/settings/dead-device-retention",
            get(get_dead_device_retention)
                .put(put_dead_device_retention)
                .route_layer(domain_guard!(state, Domain::Settings)),
        )
        .route(
            "/api/settings/config-backup",
            get(get_config_backup_settings)
                .put(put_config_backup_settings)
                .route_layer(domain_guard!(state, Domain::Settings)),
        )
        .route(
            "/api/settings/databases",
            get(get_storage_databases)
                .put(put_storage_databases)
                .route_layer(domain_guard!(state, Domain::Settings)),
        )
        .route(
            "/api/settings/routing",
            get(get_storage_routing)
                .put(put_storage_routing)
                .route_layer(domain_guard!(state, Domain::Settings)),
        )
        .route(
            "/api/settings/journal-retention",
            get(get_journal_retention)
                .put(put_journal_retention)
                .route_layer(domain_guard!(state, Domain::Settings)),
        )
        .route(
            "/api/system/restart",
            axum::routing::post(restart_process)
                .route_layer(domain_guard!(state, Domain::Settings)),
        )
        .route(
            "/api/maintenance-windows",
            get(list_maintenance_windows)
                .post(upsert_maintenance_window)
                .route_layer(domain_guard!(state, Domain::MaintenanceWindows)),
        )
        .route(
            "/api/maintenance-windows/:id",
            get(get_maintenance_window)
                .delete(delete_maintenance_window)
                .route_layer(domain_guard!(state, Domain::MaintenanceWindows)),
        )
        // Self-service — no domain gate, same tier as `/api/auth/password`: a user manages
        // only their own contact points (`authenticate_request` inside each handler is the
        // only check). See `discovery_core::NotificationChannel`'s docs.
        .route(
            "/api/notifications/channels",
            get(list_my_notification_channels)
                .post(upsert_my_notification_channel)
                .route_layer(password_guard!(state)),
        )
        .route(
            "/api/notifications/channels/:id",
            axum::routing::delete(delete_my_notification_channel)
                .route_layer(password_guard!(state)),
        )
        // AI assistant chat (2026-09-18) — self-service, same tier as
        // `/api/notifications/channels*` above: any authenticated user may open and use
        // their own conversations, no `discovery_core::Domain` gate at all. See
        // `crate::assistant`'s module docs for why — what the assistant can *do* is bounded
        // by the calling user's own domain permissions at tool-execution time instead.
        .route(
            "/api/assistant/conversations",
            get(assistant::list_conversations)
                .post(assistant::create_conversation)
                .route_layer(password_guard!(state)),
        )
        .route(
            "/api/assistant/conversations/:id",
            axum::routing::put(assistant::update_conversation_settings)
                .route_layer(password_guard!(state)),
        )
        .route(
            "/api/assistant/conversations/:id/messages",
            get(assistant::list_messages)
                .post(assistant::send_message)
                .route_layer(password_guard!(state)),
        )
        .route(
            "/api/assistant/conversations/:id/messages/:message_id/confirm",
            axum::routing::post(assistant::confirm_action).route_layer(password_guard!(state)),
        )
        .route(
            "/api/assistant/conversations/:id/messages/:message_id/reject",
            axum::routing::post(assistant::reject_action).route_layer(password_guard!(state)),
        )
        // Admin-on-behalf-of — support/troubleshooting access to another user's channels,
        // same tier as `/api/users/:id/password`.
        .route(
            "/api/users/:id/notification-channels",
            get(list_user_notification_channels)
                .post(upsert_user_notification_channel)
                .route_layer(admin_guard!(state)),
        )
        .route(
            "/api/users/:id/notification-channels/:channel_id",
            axum::routing::delete(delete_user_notification_channel)
                .route_layer(admin_guard!(state)),
        )
        // The notification matrix + its provider credentials — one domain for both, see
        // `discovery_core::Domain::Notifications`'s docs on why the provider config
        // (SMTP/Telegram) sits under this domain rather than `Settings`.
        .route(
            "/api/notifications/rules",
            get(list_notification_rules)
                .post(upsert_notification_rule)
                .route_layer(domain_guard!(state, Domain::Notifications)),
        )
        .route(
            "/api/notifications/rules/:id",
            get(get_notification_rule)
                .delete(delete_notification_rule)
                .route_layer(domain_guard!(state, Domain::Notifications)),
        )
        .route(
            "/api/notifications/recipients",
            get(list_notification_recipients)
                .route_layer(domain_guard!(state, Domain::Notifications)),
        )
        .route(
            "/api/notifications/recipient-roles",
            get(list_notification_recipient_roles)
                .route_layer(domain_guard!(state, Domain::Notifications)),
        )
        .route(
            "/api/settings/notifications",
            get(get_notification_provider_settings)
                .put(put_notification_provider_settings)
                .route_layer(domain_guard!(state, Domain::Notifications)),
        )
        // Topology rules (2026-09-16) — provider-authored Rhai extraction rules, see
        // `discovery_core::Domain::Topology`'s docs. `neighbors`/`edges` are read-only
        // resolved-graph views over `discovery_topology::TopologyStore`, gated by the same
        // domain as the rule CRUD itself (topology data has no self-service tier).
        .route(
            "/api/topology/rules",
            get(list_topology_rules)
                .post(upsert_topology_rule)
                .route_layer(domain_guard!(state, Domain::Topology)),
        )
        .route(
            "/api/topology/rules/:id",
            get(get_topology_rule)
                .delete(delete_topology_rule)
                .route_layer(domain_guard!(state, Domain::Topology)),
        )
        .route(
            "/api/topology/rules/:name/neighbors/:device_id",
            get(get_topology_neighbors).route_layer(domain_guard!(state, Domain::Topology)),
        )
        .route(
            "/api/topology/rules/:name/edges",
            get(get_topology_edges).route_layer(domain_guard!(state, Domain::Topology)),
        )
        .route(
            "/api/topology/rules/:name/hierarchy/:device_a/:device_b",
            put(set_topology_hierarchy_override)
                .delete(clear_topology_hierarchy_override)
                .route_layer(domain_guard!(state, Domain::Topology)),
        )
        // Group-alert suppression rules (2026-09-16) — provider-authored Rhai cause/effect
        // rules, see `discovery_core::Domain::GroupAlerts`'s docs. The correlation itself
        // runs as a background sweep (`discovery_agent::group_alert`), not through this API.
        .route(
            "/api/group-alerts/rules",
            get(list_group_alert_rules)
                .post(upsert_group_alert_rule)
                .route_layer(domain_guard!(state, Domain::GroupAlerts)),
        )
        .route(
            "/api/group-alerts/rules/:id",
            get(get_group_alert_rule)
                .delete(delete_group_alert_rule)
                .route_layer(domain_guard!(state, Domain::GroupAlerts)),
        )
        // Admin-only, not `domain_guard!` — an audit trail spans every domain at once
        // (every user's actions everywhere), so "which domain's Read permission gates
        // this" has no single right answer; same reasoning `/api/users*`/`/api/roles*`
        // already use for a cross-cutting administrative capability. See `router()`'s
        // top-level docs and `list_journal`'s own docs.
        .route(
            "/api/journal",
            get(list_journal).route_layer(admin_guard!(state)),
        )
        .with_state(state)
}

/// The REST API plus the bundled webui — what `main.rs` has served since before either
/// toggle existed, and what every test/call site in this crate that just wants "everything
/// on" still gets verbatim. Everything that isn't `/api/*` is the React app — one
/// static-file handler covers both the SPA's own entry point ("/") and every hashed asset
/// path Vite produces, unlike the old single `include_str!`'d HTML file this replaced (see
/// `serve_embedded`'s docs for the embedding/fallback contract).
pub fn router(state: DashboardState) -> Router {
    secure_http_router(api_router(state).fallback(serve_embedded))
}

/// `router()`, minus whichever half `config.toml`'s `[server].enable_rest`/`enable_webui`
/// says to leave out — direct user request 2026-08-29: "возможность через config.toml
/// выключить rest и/или webui". Preceded by an audit of whether the webui does anything the
/// REST API can't: it doesn't — `crates/web/frontend`'s only network calls are the `fetch`
/// wrapper in `api/http.ts`, every one of them against `/api/*` (no WebSocket/SSE/other
/// channel), so the webui is strictly a REST client with a bundled UI on top, never a
/// capability of its own. Turning `enable_rest` off therefore also makes the webui
/// non-functional (its own requests 404), which is expected, not a bug — the two toggles
/// are independent on purpose (e.g. `enable_webui = false` for a headless/REST-only
/// deployment that doesn't want to expose the dashboard's static assets at all), not a
/// promise that every combination is *useful*.
///
/// `enable_rest = false` unmounts every `/api/*` route entirely (a real 404 from axum's own
/// default fallback, not an auth rejection or a "REST disabled" body — nothing here needs
/// to distinguish the two, since a route that was never registered and one that's gone both
/// read as "not found" to a client). `enable_webui = false` skips `.fallback(serve_embedded)`,
/// so any non-`/api/*` path also falls through to that same default 404 instead of serving
/// the dashboard's static assets. Both `false` leaves nothing registered at all — every
/// request 404s; `discovery-agent::main::run` logs a `warn!` at startup for that
/// combination (there is then no way to interact with the running process at all), but
/// still starts it — this function itself makes no judgment call about whether the
/// resulting config is sensible, only builds the router the flags describe.
pub fn router_with_flags(state: DashboardState, enable_rest: bool, enable_webui: bool) -> Router {
    let router = if enable_rest {
        api_router(state)
    } else {
        // A real registered route, not just "nothing here, fall through to whatever
        // `.fallback` ends up being below" — `enable_webui` can be `true` at the same
        // time, and a single `Router` only has one `.fallback` for its entire tree, so
        // without this an unmounted `/api/*` would silently match `serve_embedded`
        // instead: a 200 `text/html` (the SPA's `index.html`) rather than a 404, for
        // every `/api/*` path once nothing is registered under it. `*rest` is axum's
        // wildcard segment syntax — matches any path under `/api/`, and (being an actual
        // route, not the fallback) takes priority over `.fallback(serve_embedded)`
        // regardless of registration order below.
        Router::new().route("/api/*rest", axum::routing::any(rest_disabled))
    };
    let router = if enable_webui {
        router.fallback(serve_embedded)
    } else {
        router
    };
    secure_http_router(router)
}

fn secure_http_router(router: Router) -> Router {
    router
        .layer(axum::middleware::from_fn(csrf_protection))
        .layer(axum::middleware::from_fn(security_headers))
}

async fn security_headers(req: Request<axum::body::Body>, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_SECURITY_POLICY, "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'".parse().unwrap());
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    headers.insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        "max-age=31536000; includeSubDomains".parse().unwrap(),
    );
    response
}

fn same_origin(origin: &str, host: &str) -> bool {
    origin == format!("http://{host}") || origin == format!("https://{host}")
}

fn csrf_is_allowed(method: &axum::http::Method, path: &str, headers: &HeaderMap) -> bool {
    if method == axum::http::Method::GET
        || method == axum::http::Method::HEAD
        || method == axum::http::Method::OPTIONS
    {
        return true;
    }
    if path == "/api/auth/login" || !headers.contains_key(header::COOKIE) {
        return true;
    }
    let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let Some(host) = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    same_origin(origin, host)
}

async fn csrf_protection(req: Request<axum::body::Body>, next: Next) -> Response {
    if req.uri().path().starts_with("/api/")
        && !csrf_is_allowed(req.method(), req.uri().path(), req.headers())
    {
        return (StatusCode::FORBIDDEN, "cross-site request rejected").into_response();
    }
    next.run(req).await
}

/// See [`router_with_flags`]'s docs for why this exists as an explicit route rather than
/// being left to fall through to the SPA fallback.
async fn rest_disabled() -> StatusCode {
    StatusCode::NOT_FOUND
}

// -----------------------------------------------------------------------------------------
// Аутентификация/permissions (2026-08-21) — direct user request: "логика авторизации и
// аутентификации. Как и rest, так и для webui... permissions. Классический вид доступа -
// чтение, запись, для различных доменов". Local password auth only — external providers
// (LDAP/Kerberos/OAuth/Tibbo cloud) explicitly deferred, see `discovery/CLAUDE.md`'s
// AggreGate auth survey. Session token travels either as `Authorization: Bearer <token>`
// (REST/API clients) or an `HttpOnly` cookie (browser dashboard) — `login` sets both by
// returning the token in the JSON body *and* a `Set-Cookie` header, so either style of
// caller can use it. No `axum-extra`/cookie crate: exactly one cookie name to read and
// write, not worth a new dependency for.
// -----------------------------------------------------------------------------------------

const SESSION_COOKIE: &str = "discovery_session";
const SESSION_TTL_DAYS: i64 = 7;

fn session_cookie(token: &str, max_age_seconds: i64) -> String {
    format!("{SESSION_COOKIE}={token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age_seconds}")
}

fn extract_token(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Some(token) = value.to_str().ok().and_then(|s| s.strip_prefix("Bearer ")) {
            return Some(token.to_string());
        }
    }
    let cookie_header = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    cookie_header.split(';').map(str::trim).find_map(|part| {
        part.strip_prefix(&format!("{SESSION_COOKIE}="))
            .map(str::to_string)
    })
}

async fn authenticate_request(
    state: &DashboardState,
    headers: &HeaderMap,
) -> Result<AuthenticatedUser, ApiError> {
    let token =
        extract_token(headers).ok_or((StatusCode::UNAUTHORIZED, "not logged in".to_string()))?;
    state
        .auth
        .authenticate_session(&token)
        .await
        .map_err(internal_error)?
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "invalid or expired session".to_string(),
        ))
}

/// A handler-populated response extension — direct user follow-up request: the Журнал
/// entry itself should say *which* object was touched and, for an edit, roughly *what*
/// changed, not just "who did what kind of action" (`action`/`domain` alone). A handler
/// that has something worth recording beyond the generic `describe_action` text builds
/// this and inserts it into its own response's extensions (`with_journal_details`
/// below); `require_domain_permission`/`require_admin` read it back out *after*
/// `next.run` (a handler's own return value is the only place this data naturally exists
/// — the enclosing middleware has no independent way to know "which profile" a
/// `POST /api/profiles` touched) and fold it into the recorded entry. Absent for a
/// handler that doesn't call `with_journal_details` — same as `object`/`details` being
/// `None` on the [`JournalEntry`] itself.
#[derive(Clone)]
struct JournalDetails {
    object: Option<String>,
    details: Option<serde_json::Value>,
}

/// Wraps `resp` so `require_domain_permission`/`require_admin` can find `object`/
/// `details` after the fact — see [`JournalDetails`]'s docs. A no-op (just converts to a
/// `Response`) when both are `None`, so call sites can pass through whatever they
/// computed without a separate "was there anything to record" branch.
fn with_journal_details(
    resp: impl axum::response::IntoResponse,
    object: Option<String>,
    details: Option<serde_json::Value>,
) -> axum::response::Response {
    let mut resp = resp.into_response();
    if object.is_some() || details.is_some() {
        resp.extensions_mut()
            .insert(JournalDetails { object, details });
    }
    resp
}

/// Field names that must never end up in a Журнал `details` diff even indirectly via the
/// generic [`json_diff`] below — plaintext DB passwords (`DatabaseConnConfig::password`),
/// SNMP community strings, and (2026-08-29) SNMPv3 USM auth/priv passphrases
/// (`SnmpV3AuthCreds::passphrase`/`SnmpV3PrivCreds::passphrase`, inside `SnmpAuth::UsmV3`
/// on `SubnetSpec::credentials`/`SnmpCredentials::auth`/`Device::snmp_credentials`) are
/// real secrets that happen to live on structs this project otherwise freely diffs whole
/// — the v3 passphrases doubly so, since they're the one thing this project actually
/// encrypts at rest (`discovery_core::secret`); this redaction is what stops that same
/// plaintext from leaking right back out through the audit trail on every config edit.
/// `read_communities`/`snmp_community`/`community` predate `SnmpAuth` (2026-08-16) and no
/// longer match anything real, kept for stray legacy-shaped data. Matched by exact JSON
/// key name, recursively, regardless of which struct they came from — defense in depth
/// against a future field with one of these names silently starting to leak into the
/// audit trail, not just today's known call sites.
/// `private_key` (2026-09-07) covers `SshAuth::PrivateKey::private_key` — the key body
/// itself, not just its `passphrase` (already covered above): a device's SSH private key
/// is just as sensitive as a password and must never reach the Журнал diff in plaintext
/// either, see `discovery_core::secret::encrypt_ssh_auth_secrets`'s docs for why this
/// project always encrypts both at rest.
/// `secret`/`smtp_password`/`telegram_bot_token` (2026-09-10) cover the notification
/// channels + matrix feature's own encrypted-at-rest fields
/// (`NotificationChannel::secret`, `NotificationProviderConfig::smtp_password`/
/// `telegram_bot_token`) — same reasoning as `private_key` above.
/// `client_secret`/`openrouter_api_key` (2026-09-18) — `AiAssistantProviderConfig`'s own
/// encrypted-at-rest fields (GigaChat/OpenRouter). Found live during OpenRouter's own
/// live verification (2026-09-18): the bare `"secret"` entry above does **not** match the
/// literal key `"client_secret"` (`REDACTED_DIFF_KEYS.contains` is an exact-string check,
/// not a substring one) — a real edit (not the first-ever create, which short-circuits
/// before a diff is computed at all — see `diff_details`) put the *actual* GigaChat
/// client secret and OpenRouter API key, in full, into a real Журнал entry's `details`,
/// pre-existing since the GigaChat feature shipped, not just a risk in the new field. No
/// existing test caught this — `NotificationProviderConfig`'s own redaction test only
/// happens to pass because `smtp_password`/`telegram_bot_token` are themselves already
/// exact entries in this list, not because the mechanism generalizes.
const REDACTED_DIFF_KEYS: &[&str] = &[
    "password",
    "read_communities",
    "snmp_community",
    "community",
    "passphrase",
    "password_hash",
    "private_key",
    "secret",
    "smtp_password",
    "telegram_bot_token",
    "client_secret",
    "openrouter_api_key",
    "self_hosted_api_key",
];

/// Recursively replaces every value under a [`REDACTED_DIFF_KEYS`] key with a fixed
/// placeholder, in place — always run on both `before`/`after` before they reach
/// [`json_diff`] (see that function's docs and every call site below).
fn redact_sensitive(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, v) in map.iter_mut() {
                if REDACTED_DIFF_KEYS.contains(&key.as_str()) {
                    *v = serde_json::Value::String("<скрыто>".to_string());
                } else {
                    redact_sensitive(v);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                redact_sensitive(item);
            }
        }
        _ => {}
    }
}

/// A single before/after diff value collapses to a short summary once it's "too big" to
/// usefully embed — direct user request: "не населяй журнал большим количеством данных"
/// (don't bloat the journal with lots of data). The diff records *that* something changed
/// and roughly what, not a full copy of a large nested value (a discovery config's
/// `subnets`, a profile's `metrics` map, ...).
const DIFF_VALUE_MAX_CHARS: usize = 200;

fn summarize_diff_value(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Array(items) if items.len() > 5 => {
            serde_json::json!(format!("[{} элементов]", items.len()))
        }
        serde_json::Value::Object(map) if map.len() > 8 => {
            serde_json::json!(format!("{{{} полей}}", map.len()))
        }
        // Matched separately from the fallback below so the reported length is the
        // string's own content, not its JSON-quoted (and possibly escape-inflated) form.
        serde_json::Value::String(s) if s.chars().count() > DIFF_VALUE_MAX_CHARS => {
            let truncated: String = s.chars().take(DIFF_VALUE_MAX_CHARS).collect();
            serde_json::json!(format!("{truncated}… ({} симв.)", s.chars().count()))
        }
        other => {
            let text = other.to_string();
            if text.chars().count() > DIFF_VALUE_MAX_CHARS {
                serde_json::json!(format!("(изменено, {} симв.)", text.chars().count()))
            } else {
                other.clone()
            }
        }
    }
}

/// Shallow top-level diff between two JSON objects for the Журнал `details` column —
/// every top-level key whose value differs gets `{"old": ..., "new": ...}` in the result;
/// unchanged keys are omitted entirely (this is a diff, not a copy of either object), and
/// individual before/after values that are themselves large get collapsed by
/// [`summarize_diff_value`] — both in service of the same "не населяй журнал большим
/// количеством данных" request `with_journal_details`'s docs cite. Returns `None` if
/// there is no top-level difference at all (including when `before`/`after` aren't JSON
/// objects and are equal). Callers pass already-[`redact_sensitive`]d values — this
/// function itself does no redaction, so a call site that forgets to redact first would
/// leak a secret; every call site in this file redacts immediately before calling this.
fn json_diff(before: &serde_json::Value, after: &serde_json::Value) -> Option<serde_json::Value> {
    let (Some(before_map), Some(after_map)) = (before.as_object(), after.as_object()) else {
        return if before == after {
            None
        } else {
            let (old_val, new_val) = summarize_diff_pair(before, after);
            Some(serde_json::json!({"old": old_val, "new": new_val}))
        };
    };
    let mut keys: Vec<&String> = before_map.keys().chain(after_map.keys()).collect();
    keys.sort();
    keys.dedup();
    let mut changes = serde_json::Map::new();
    let null = serde_json::Value::Null;
    for key in keys {
        let b = before_map.get(key).unwrap_or(&null);
        let a = after_map.get(key).unwrap_or(&null);
        if b != a {
            let (old_val, new_val) = summarize_diff_pair(b, a);
            changes.insert(
                key.clone(),
                serde_json::json!({"old": old_val, "new": new_val}),
            );
        }
    }
    if changes.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(changes))
    }
}

/// Summarizes `before`/`after` *together*, not independently — found live (a discovery
/// config's `subnets` diff): a small `old` array and a `new` array that just crosses
/// [`summarize_diff_value`]'s size cap used to render as full nested JSON on one side and
/// an opaque "(изменено, N симв.)" placeholder on the other for the *same* field — a
/// structural-vs-opaque shape mismatch that reads as broken, not just terse. Scoped to
/// array/object values specifically (where the shape mismatch actually looks wrong); a
/// short string paired with a long, ellipsis-truncated one is normal, legible diff
/// behavior on its own and doesn't need this — see the two-sided asymmetry this exists to
/// avoid vs. the "one side is genuinely just a longer sentence" case it deliberately
/// leaves alone.
fn summarize_diff_pair(
    before: &serde_json::Value,
    after: &serde_json::Value,
) -> (serde_json::Value, serde_json::Value) {
    let is_structural = |v: &serde_json::Value| {
        matches!(
            v,
            serde_json::Value::Array(_) | serde_json::Value::Object(_)
        )
    };
    let needs_summary = |v: &serde_json::Value| &summarize_diff_value(v) != v;
    if (is_structural(before) || is_structural(after))
        && (needs_summary(before) || needs_summary(after))
    {
        (force_collapse(before), force_collapse(after))
    } else {
        (summarize_diff_value(before), summarize_diff_value(after))
    }
}

/// Unconditionally collapses an array/object to its `summarize_diff_value` size-cap form
/// regardless of whether it individually crosses the cap — the "make this side match its
/// sibling's collapsed shape" half of [`summarize_diff_pair`]. Non-array/object values
/// fall back to the ordinary (threshold-gated) [`summarize_diff_value`].
fn force_collapse(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Array(items) => {
            serde_json::json!(format!("[{} элементов]", items.len()))
        }
        serde_json::Value::Object(map) => serde_json::json!(format!("{{{} полей}}", map.len())),
        other => summarize_diff_value(other),
    }
}

/// Redact-then-diff two `Serialize`ables for a Журнал entry — the composition every write
/// handler that records an edit actually calls, so no call site can accidentally skip
/// [`redact_sensitive`]. `before: None` (a create, or a delete where fetching the prior
/// state isn't worth it) always yields `None` — there's nothing to diff *against*, and a
/// one-sided dump of the new/old state alone is exactly the "не населяй журнал большим
/// количеством данных" case `with_journal_details`'s docs warn about; the row's `object`
/// field already identifies *what* was created/deleted.
fn diff_details<T: Serialize>(before: Option<&T>, after: &T) -> Option<serde_json::Value> {
    let before = before?;
    let mut before_v = serde_json::to_value(before).ok()?;
    let mut after_v = serde_json::to_value(after).ok()?;
    redact_sensitive(&mut before_v);
    redact_sensitive(&mut after_v);
    json_diff(&before_v, &after_v)
}

#[cfg(test)]
mod journal_diff_tests {
    use super::*;

    #[test]
    fn json_diff_is_none_for_identical_objects() {
        let v = serde_json::json!({"a": 1, "b": "x"});
        assert_eq!(json_diff(&v, &v), None);
    }

    #[test]
    fn json_diff_only_includes_changed_keys() {
        let before = serde_json::json!({"a": 1, "b": "x", "c": true});
        let after = serde_json::json!({"a": 1, "b": "y", "c": true});
        let diff = json_diff(&before, &after).unwrap();
        assert_eq!(
            diff,
            serde_json::json!({"b": {"old": "x", "new": "y"}}),
            "unchanged keys a/c must be entirely absent, not present-and-equal"
        );
    }

    #[test]
    fn json_diff_handles_a_key_appearing_or_disappearing() {
        let before = serde_json::json!({"a": 1});
        let after = serde_json::json!({"a": 1, "b": 2});
        let diff = json_diff(&before, &after).unwrap();
        assert_eq!(diff, serde_json::json!({"b": {"old": null, "new": 2}}));
    }

    #[test]
    fn summarize_diff_value_collapses_long_strings_and_big_collections() {
        let long = serde_json::json!("x".repeat(500));
        let summarized = summarize_diff_value(&long);
        let text = summarized.as_str().unwrap();
        assert!(
            text.len() < 500,
            "a long value must be shortened, not embedded whole"
        );
        assert!(
            text.contains("500"),
            "the summary should still say how big the original was"
        );

        let big_array = serde_json::json!([1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(
            summarize_diff_value(&big_array),
            serde_json::json!("[7 элементов]")
        );

        let small_array = serde_json::json!([1, 2]);
        assert_eq!(
            summarize_diff_value(&small_array),
            small_array,
            "a small array is embedded as-is, not summarized"
        );
    }

    #[test]
    fn json_diff_summarizes_large_changed_values_instead_of_embedding_them() {
        let before = serde_json::json!({"subnets": []});
        let after = serde_json::json!({"subnets": [1, 2, 3, 4, 5, 6]});
        let diff = json_diff(&before, &after).unwrap();
        assert_eq!(diff["subnets"]["new"], serde_json::json!("[6 элементов]"));
    }

    /// Found live (a real discovery-config `subnets` edit): a small `old` array and a
    /// `new` array that just barely crosses `DIFF_VALUE_MAX_CHARS` used to render as full
    /// nested JSON on one side and a "(изменено, N симв.)" placeholder on the other —
    /// same field, wildly different fidelity. Both sides must collapse together.
    #[test]
    fn json_diff_summarizes_both_sides_together_when_only_one_needs_it() {
        let long_string = "x".repeat(300);
        let before = serde_json::json!({"items": [{"a": 1}]});
        let after = serde_json::json!({"items": [{"a": 1, "b": long_string}]});
        let diff = json_diff(&before, &after).unwrap();
        // `before["items"]` alone serializes short enough to embed whole, but since
        // `after`'s (same array shape, 1 element) needs summarizing, `before` collapses
        // to the same "[N элементов]" form too, not left as full nested JSON.
        assert_eq!(diff["items"]["old"], serde_json::json!("[1 элементов]"));
        assert_eq!(diff["items"]["new"], serde_json::json!("[1 элементов]"));
    }

    /// The asymmetry fix is scoped to array/object values — a short string next to a
    /// long, truncated one is normal diff behavior and must NOT be forced into a
    /// same-shape collapse (there'd be nothing meaningfully "structural" to collapse to).
    #[test]
    fn json_diff_leaves_asymmetric_scalar_strings_alone() {
        let long_string = "y".repeat(300);
        let before = serde_json::json!({"message": "short"});
        let after = serde_json::json!({"message": long_string});
        let diff = json_diff(&before, &after).unwrap();
        assert_eq!(
            diff["message"]["old"],
            serde_json::json!("short"),
            "a short string that doesn't need summarizing must stay as-is"
        );
        assert!(
            diff["message"]["new"]
                .as_str()
                .unwrap()
                .contains("… (300 симв.)"),
            "the long side still gets its own ordinary truncation"
        );
    }

    #[test]
    fn redact_sensitive_replaces_password_and_community_fields_by_name_anywhere_in_the_tree() {
        let mut v = serde_json::json!({
            "name": "main",
            "password": "hunter2",
            "nested": {"read_communities": ["public", "private"], "keep": "me"},
            "list": [{"snmp_community": "public"}, {"community": "also-secret"}],
        });
        redact_sensitive(&mut v);
        assert_eq!(v["password"], "<скрыто>");
        assert_eq!(v["nested"]["read_communities"], "<скрыто>");
        assert_eq!(
            v["nested"]["keep"], "me",
            "an unrelated sibling field must survive redaction untouched"
        );
        assert_eq!(v["list"][0]["snmp_community"], "<скрыто>");
        assert_eq!(v["list"][1]["community"], "<скрыто>");
    }

    /// A `SnmpAuth::UsmV3` credential's auth/priv passphrase must never reach the Журнал
    /// diff in plaintext — this is the one secret this project actually encrypts at rest
    /// (`discovery_core::secret`); redaction here is what keeps the audit trail from
    /// handing the same plaintext right back out on every config edit.
    #[test]
    fn redact_sensitive_replaces_snmp_v3_passphrases() {
        let mut v = serde_json::json!({
            "credentials": [{
                "kind": "usm_v3",
                "user": "monitor",
                "auth": {"protocol": "sha1", "passphrase": "authpass123"},
                "priv_": {"protocol": "aes128", "passphrase": "privpass123"},
            }],
        });
        redact_sensitive(&mut v);
        assert_eq!(v["credentials"][0]["auth"]["passphrase"], "<скрыто>");
        assert_eq!(v["credentials"][0]["priv_"]["passphrase"], "<скрыто>");
        assert_eq!(
            v["credentials"][0]["user"], "monitor",
            "the username isn't a secret and must survive redaction untouched"
        );
    }

    #[test]
    fn redact_sensitive_replaces_an_ssh_private_key_body_not_just_its_passphrase() {
        let mut v = serde_json::json!({
            "ssh_credentials": {
                "username": "admin",
                "auth": {"kind": "private_key", "private_key": "-----BEGIN KEY-----\nabc\n-----END KEY-----", "passphrase": "keypass123"},
                "port": 22,
            },
        });
        redact_sensitive(&mut v);
        assert_eq!(v["ssh_credentials"]["auth"]["private_key"], "<скрыто>");
        assert_eq!(v["ssh_credentials"]["auth"]["passphrase"], "<скрыто>");
        assert_eq!(
            v["ssh_credentials"]["username"], "admin",
            "the username isn't a secret and must survive redaction untouched"
        );
    }

    #[test]
    fn diff_details_redacts_before_diffing_so_a_changed_password_never_appears() {
        #[derive(serde::Serialize)]
        struct WithPassword {
            name: String,
            password: Option<String>,
        }
        // `name` also changes so there's a real diff to assert on — a password-only
        // change redacting to the same placeholder on both sides would correctly produce
        // *no* diff at all (nothing left that actually differs post-redaction), which is
        // covered separately below.
        let before = WithPassword {
            name: "main".to_string(),
            password: Some("old-secret".to_string()),
        };
        let after = WithPassword {
            name: "renamed".to_string(),
            password: Some("new-secret".to_string()),
        };
        let diff = diff_details(Some(&before), &after).unwrap();
        let dump = diff.to_string();
        assert!(
            !dump.contains("old-secret") && !dump.contains("new-secret"),
            "a changed password must never reach the diff, redacted or not: {dump}"
        );
        assert_eq!(diff["name"]["old"], "main");
        assert_eq!(diff["name"]["new"], "renamed");
        // Redacted to the same placeholder on both sides, so the password field itself
        // produces no diff entry at all — not `{"old": "<скрыто>", "new": "<скрыто>"}`
        // (technically still safe, but reads as "this changed" when it didn't visibly).
        assert!(diff.get("password").is_none());
    }

    #[test]
    fn diff_details_is_none_when_only_a_redacted_field_changed() {
        #[derive(serde::Serialize)]
        struct WithPassword {
            name: String,
            password: Option<String>,
        }
        let before = WithPassword {
            name: "main".to_string(),
            password: Some("old-secret".to_string()),
        };
        let after = WithPassword {
            name: "main".to_string(),
            password: Some("new-secret".to_string()),
        };
        assert_eq!(
            diff_details(Some(&before), &after),
            None,
            "a password-only change must produce no visible diff, not an empty-looking one"
        );
    }

    #[test]
    fn diff_details_is_none_when_before_is_none() {
        let after = serde_json::json!({"a": 1});
        assert_eq!(
            diff_details::<serde_json::Value>(None, &after),
            None,
            "a create has nothing to diff against — object alone identifies what was created"
        );
    }
}

/// Header a tool-call's internal sub-request (`crate::assistant::execute_tool_call`) sets
/// on itself before running it through the real router — lets the Журнал distinguish an
/// AI-driven action from the same user's own manual click, without a separate audit
/// mechanism (see [`record_journal_entry`]'s use of it below).
const INTERNAL_CALLER_HEADER: &str = "x-discovery-internal-caller";

/// Maps [`INTERNAL_CALLER_HEADER`]'s value to the Журнал action suffix, distinguishing a
/// manually-confirmed AI action from one that executed because the conversation has
/// `auto_approve_writes` on (2026-09-18, direct user request — Claude-Code-style bypass
/// toggle, see `discovery_assistant::Conversation`'s docs) — same audit mechanism as
/// before, just a second value it recognizes, not a new one.
fn assistant_journal_suffix(headers: &HeaderMap) -> Option<&'static str> {
    match headers
        .get(INTERNAL_CALLER_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        Some("assistant") => Some(" (через ИИ-ассистента)"),
        Some("assistant-auto") => Some(" (через ИИ-ассистента, авто-подтверждено)"),
        _ => None,
    }
}

/// Appends one Журнал entry — shared by `require_domain_permission`/`require_admin` after
/// they've already decided (2xx response to a non-GET/HEAD request) that something worth
/// recording actually happened. A failure here is logged and swallowed, never surfaced to
/// the caller: the underlying action already succeeded and its response has already been
/// decided by the time this runs (see both call sites) — a broken audit log must not turn
/// into a broken API.
async fn record_journal_entry(
    state: &DashboardState,
    username: &str,
    domain: &str,
    method: &axum::http::Method,
    path: &str,
    extra: Option<JournalDetails>,
    assistant_suffix: Option<&str>,
) {
    let (object, details) = match extra {
        Some(JournalDetails { object, details }) => (object, details),
        None => (None, None),
    };
    let mut action = describe_action(method, path);
    if let Some(suffix) = assistant_suffix {
        action.push_str(suffix);
    }
    let entry = JournalEntry {
        id: Uuid::new_v4(),
        ts: chrono::Utc::now(),
        username: username.to_string(),
        domain: domain.to_string(),
        action,
        method: method.to_string(),
        path: path.to_string(),
        object,
        details,
    };
    if let Err(e) = state.journal.append(&entry).await {
        warn!(error = %e, username, domain, action = %entry.action, "journal: failed to record action");
    }
}

/// Per-route middleware requiring `domain` at `Read` (GET/HEAD) or `Write` (every other
/// method) — see `router()`'s docs for why one layer covers both levels for a given
/// route. `admin_guard` below is the same shape but checks `is_admin` instead of a domain.
///
/// Also the write path for the Журнал audit trail (added alongside `discovery-journal`) —
/// after a `Write`-level request completes with a 2xx status, records who did what via
/// [`record_journal_entry`]. `MatchedPath` (the route *template*, e.g.
/// `/api/devices/:id/enabled`, not the concrete request path) must be read before
/// `next.run` consumes `req`; whether logging happens at all is decided after, from the
/// response's actual status — a permission-denied 403 never reaches `next.run` in the
/// first place (see the early `return Err` above), and a request that reaches `next.run`
/// but still fails downstream (e.g. a 404/422/500 handler result) isn't a real completed
/// action either.
async fn require_domain_permission(
    State((state, domain)): State<(DashboardState, Domain)>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, axum::response::Response> {
    use axum::response::IntoResponse;
    let user = match authenticate_request(&state, req.headers()).await {
        Ok(u) => u,
        Err(e) => return Err(e.into_response()),
    };
    if user.must_change_password {
        return Err((
            StatusCode::FORBIDDEN,
            "password change required — PUT /api/auth/password".to_string(),
        )
            .into_response());
    }
    let method = req.method().clone();
    let level = if matches!(
        &method,
        &axum::http::Method::GET | &axum::http::Method::HEAD
    ) {
        AccessLevel::Read
    } else {
        AccessLevel::Write
    };
    if !user.can(domain, level) {
        return Err((
            StatusCode::FORBIDDEN,
            format!("requires {} access to {}", level.as_str(), domain.as_str()),
        )
            .into_response());
    }
    let matched_path = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|p| p.as_str().to_string());
    let assistant_suffix = assistant_journal_suffix(req.headers());
    let mut response = next.run(req).await;
    if level == AccessLevel::Write && response.status().is_success() {
        if let Some(path) = matched_path {
            let extra = response.extensions_mut().remove::<JournalDetails>();
            record_journal_entry(
                &state,
                &user.username,
                domain.as_str(),
                &method,
                &path,
                extra,
                assistant_suffix,
            )
            .await;
        }
    }
    Ok(response)
}

async fn require_admin(
    State(state): State<DashboardState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, axum::response::Response> {
    use axum::response::IntoResponse;
    let user = match authenticate_request(&state, req.headers()).await {
        Ok(u) => u,
        Err(e) => return Err(e.into_response()),
    };
    if user.must_change_password {
        return Err((
            StatusCode::FORBIDDEN,
            "password change required — PUT /api/auth/password".to_string(),
        )
            .into_response());
    }
    if !user.is_admin {
        return Err((StatusCode::FORBIDDEN, "requires admin".to_string()).into_response());
    }
    let method = req.method().clone();
    let matched_path = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|p| p.as_str().to_string());
    // Never actually `Some` in practice — no assistant tool targets an admin-only route —
    // but computed the same way `require_domain_permission` does, for consistency rather
    // than hardcoding `None` below.
    let assistant_suffix = assistant_journal_suffix(req.headers());
    let mut response = next.run(req).await;
    // `/api/journal` itself is GET-only, so it never reaches here; every other
    // `admin_guard!`-gated route is `/api/users*`, `/api/roles*`, or (2026-09-18)
    // `/api/settings/ai-assistant` — see `router()`.
    if !matches!(
        &method,
        &axum::http::Method::GET | &axum::http::Method::HEAD
    ) && response.status().is_success()
    {
        if let Some(path) = matched_path {
            let domain_label = if path.starts_with("/api/roles") {
                "roles"
            } else if path.starts_with("/api/settings/ai-assistant") {
                "ai_assistant"
            } else {
                "users"
            };
            let extra = response.extensions_mut().remove::<JournalDetails>();
            record_journal_entry(
                &state,
                &user.username,
                domain_label,
                &method,
                &path,
                extra,
                assistant_suffix,
            )
            .await;
        }
    }
    Ok(response)
}

/// Authenticated self-service routes use this guard because they do not carry a
/// domain/admin middleware. They remain unavailable until a bootstrap or temporary
/// password is replaced; `/api/auth/me`, `/api/auth/password` and logout remain the
/// deliberate exceptions needed to complete that flow.
async fn require_password_change_completed(
    State(state): State<DashboardState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, axum::response::Response> {
    use axum::response::IntoResponse;
    let user = match authenticate_request(&state, req.headers()).await {
        Ok(u) => u,
        Err(e) => return Err(e.into_response()),
    };
    if user.must_change_password {
        return Err((
            StatusCode::FORBIDDEN,
            "password change required — PUT /api/auth/password".to_string(),
        )
            .into_response());
    }
    Ok(next.run(req).await)
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct UserView {
    id: uuid::Uuid,
    username: String,
    is_admin: bool,
    /// See `discovery_auth::User::must_change_password`'s docs — the dashboard's `Root`
    /// component gates on this directly (blocking `ChangePasswordPage`, no sidebar/
    /// navigation) before ever rendering anything that would hit a domain-gated route,
    /// which the server enforces independently anyway (see `require_domain_permission`/
    /// `require_admin`'s docs) — this field is what lets the client *anticipate* that
    /// block instead of just failing into it.
    must_change_password: bool,
    /// See `discovery_auth::User::role_id`'s docs. `None` = no role, no domain access.
    role_id: Option<uuid::Uuid>,
    /// Denormalized alongside `role_id` purely for display — the dashboard shouldn't need
    /// a second `GET /api/roles` round trip just to show which role a user has. `None`
    /// whenever `role_id` is `None`, or (rare) if `role_id` points at a role that's since
    /// been deleted.
    role_name: Option<String>,
    /// Denormalized effective domain permissions used by the dashboard to hide write
    /// controls before a request can predictably receive a 403. The server guards remain
    /// authoritative; this is a UX hint and is refreshed with `/api/auth/me`.
    permissions: std::collections::HashMap<String, String>,
}

fn user_view(
    id: uuid::Uuid,
    username: String,
    is_admin: bool,
    must_change_password: bool,
    role_id: Option<uuid::Uuid>,
    role_name: Option<String>,
    permissions: HashMap<Domain, AccessLevel>,
) -> UserView {
    UserView {
        id,
        username,
        is_admin,
        must_change_password,
        role_id,
        role_name,
        permissions: permissions
            .into_iter()
            .map(|(domain, level)| (domain.as_str().to_string(), level.as_str().to_string()))
            .collect(),
    }
}

#[derive(Serialize)]
struct LoginResponse {
    /// Also set as an `HttpOnly` cookie on this same response — present in the body too
    /// so non-browser callers (curl, scripts) can grab it without parsing `Set-Cookie`.
    token: String,
    user: UserView,
}

/// Per-(username, source-IP) login throttle — reuses `discovery_core::TokenBucket` (added
/// 2026-09-12, direct follow-up from the security audit: `/api/auth/login`
/// had zero brute-force protection, unlike the trap/syslog ingestion endpoints which already
/// had this same limiter). Burst of `config.burst_capacity` immediate attempts, then a slow
/// trickle at `config.refill_per_sec` (`discovery_bootstrap::LoginRateLimitConfig` —
/// `[login_rate_limit]` in `config.toml`, defaults match this paragraph's numbers) —
/// deliberately not a hard timed lockout with its own state: the response when throttled is
/// byte-for-byte the same "invalid username or password" a wrong password gets (see `login`
/// below), so there's no separate "you're locked out" signal for an attacker to use to
/// distinguish a throttle from a bad guess, or to fingerprint which usernames exist.
/// Tradeoff, stated plainly: a legitimate user who mistypes their password
/// `burst_capacity` times in a row has to wait out the same trickle an attacker would, with
/// no differentiated error telling them why.
///
/// Keyed by the *raw* submitted username, not case-folded — matches
/// `SeaOrmAuthStore::verify_password`'s exact-match `Username.eq(username)` lookup, so the
/// throttle key always describes the same account identity the query does.
///
/// Grows one entry per distinct (username, ip) pair ever attempted — **evicted** by a
/// periodic sweep (`run_login_rate_limiter_sweep_loop`), unlike the still-accepted
/// never-evicts tradeoff `TrapIngestState`/`SyslogIngestState`'s per-*IP*-only maps make
/// (see their docs in `discovery-agent`). The difference that justifies treating this one
/// differently: `username` here is attacker-controlled free text, not IP-bounded, so a
/// remote attacker rotating usernames could otherwise grow this map roughly without limit
/// — found in the 2026-09-11 audit, fixed 2026-09-12.
pub struct LoginRateLimiter {
    account_buckets: DashMap<(String, IpAddr), TokenBucket>,
    ip_buckets: DashMap<IpAddr, TokenBucket>,
    config: discovery_bootstrap::LoginRateLimitConfig,
}

impl LoginRateLimiter {
    pub fn new(config: discovery_bootstrap::LoginRateLimitConfig) -> Self {
        Self {
            account_buckets: DashMap::new(),
            ip_buckets: DashMap::new(),
            config,
        }
    }

    /// `false` means "throttled — reject without even checking the password."
    fn check_and_consume(&self, username: &str, ip: IpAddr) -> bool {
        let ip_allowed = self
            .ip_buckets
            .entry(ip)
            .or_insert_with(|| TokenBucket::new(self.config.burst_capacity))
            .try_consume(self.config.refill_per_sec);
        let account_allowed = self
            .account_buckets
            .entry((username.to_string(), ip))
            .or_insert_with(|| TokenBucket::new(self.config.burst_capacity))
            .try_consume(self.config.refill_per_sec);
        ip_allowed && account_allowed
    }

    /// Clears this (username, ip) pair's throttle state entirely on a successful login, so a
    /// user who fumbled a few attempts before getting it right isn't left sitting on a
    /// partially-spent bucket for their next normal session refresh.
    fn record_success(&self, username: &str, ip: IpAddr) {
        self.account_buckets.remove(&(username.to_string(), ip));
    }

    /// Resolves the client address only when the direct peer is explicitly trusted. The
    /// rightmost forwarded address is accepted first, then the chain is walked left while
    /// every proxy hop remains in the configured allowlist; otherwise the transport peer
    /// is used and attacker-controlled headers have no effect.
    fn source_ip(&self, peer: IpAddr, forwarded_for: Option<&str>) -> IpAddr {
        if !self.config.trusted_proxy_ips.contains(&peer) {
            return peer;
        }
        let mut current = peer;
        for candidate in forwarded_for
            .unwrap_or_default()
            .split(',')
            .rev()
            .filter_map(|value| value.trim().parse::<IpAddr>().ok())
        {
            if !self.config.trusted_proxy_ips.contains(&current) {
                break;
            }
            current = candidate;
        }
        current
    }

    /// Removes every bucket whose `TokenBucket::last_refill` is older than
    /// `stale_after`. Safe by construction, not just "probably fine": continuous refill
    /// means a bucket idle this long is already back at full capacity, so evicting it and
    /// letting the next attempt recreate it fresh is behaviorally identical to leaving it in
    /// place — this only reclaims memory, it never changes what a caller observes. Public
    /// (not just `pub(crate)`) so `discovery_agent`'s recurring sweep loop can call it —
    /// see that crate's docs for why the loop itself lives there, not here.
    pub fn sweep_stale(&self, stale_after: std::time::Duration) {
        let now = std::time::Instant::now();
        self.account_buckets
            .retain(|_, bucket| now.duration_since(bucket.last_refill()) < stale_after);
        self.ip_buckets
            .retain(|_, bucket| now.duration_since(bucket.last_refill()) < stale_after);
    }
}

impl Default for LoginRateLimiter {
    fn default() -> Self {
        Self::new(discovery_bootstrap::LoginRateLimitConfig::default())
    }
}

async fn login(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<LoginRequest>,
) -> Result<axum::response::Response, ApiError> {
    use axum::response::IntoResponse;
    // Trimmed — not `body.password` (see audit finding 5, `docs/Changelog/2026-09-20 -
    // Аудит перед релизом...md`): a stray copy-pasted newline/space around a *username*
    // should never turn an otherwise-correct login into "invalid username or password",
    // but the password itself must stay byte-exact — trimming it would silently accept a
    // wrong password that happens to differ only in surrounding whitespace.
    let username = body.username.trim();
    let source_ip = state.login_rate_limiter.source_ip(
        addr.ip(),
        headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok()),
    );
    if !state
        .login_rate_limiter
        .check_and_consume(username, source_ip)
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            "invalid username or password".to_string(),
        ));
    }
    let Some(user) = state
        .auth
        .verify_password(username, &body.password)
        .await
        .map_err(internal_error)?
    else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "invalid username or password".to_string(),
        ));
    };
    state.login_rate_limiter.record_success(username, source_ip);
    let token = state
        .auth
        .create_session(user.id, chrono::Duration::days(SESSION_TTL_DAYS))
        .await
        .map_err(internal_error)?;
    let (role_name, permissions) = match user.role_id {
        Some(role_id) => state
            .auth
            .get_role(role_id)
            .await
            .map_err(internal_error)?
            .map(|r| (Some(r.name), r.permissions))
            .unwrap_or_else(|| (None, HashMap::new())),
        None => (None, HashMap::new()),
    };
    let mut response = Json(LoginResponse {
        token: token.clone(),
        user: user_view(
            user.id,
            user.username,
            user.is_admin,
            user.must_change_password,
            user.role_id,
            role_name,
            permissions,
        ),
    })
    .into_response();
    let cookie = session_cookie(&token, SESSION_TTL_DAYS * 86400);
    if let Ok(value) = cookie.parse() {
        response
            .headers_mut()
            .insert(axum::http::header::SET_COOKIE, value);
    }
    Ok(response)
}

/// No auth-required middleware on this route on purpose — logging out with an
/// already-invalid/missing token is a no-op, not an error (same idempotent-delete
/// discipline as `discovery_queue::JobQueueStore::delete_session`), so there's nothing a
/// pre-check would protect that the handler doesn't already handle itself.
async fn logout(
    State(state): State<DashboardState>,
    headers: HeaderMap,
) -> Result<axum::response::Response, ApiError> {
    use axum::response::IntoResponse;
    if let Some(token) = extract_token(&headers) {
        state
            .auth
            .delete_session(&token)
            .await
            .map_err(internal_error)?;
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    let cookie = session_cookie("", 0);
    if let Ok(value) = cookie.parse() {
        response
            .headers_mut()
            .insert(axum::http::header::SET_COOKIE, value);
    }
    Ok(response)
}

/// What the dashboard's JS calls on load to decide "show the login form" (401) vs. "show
/// the dashboard, and which nav items/edit controls this user's permissions allow" (200).
async fn me(
    State(state): State<DashboardState>,
    headers: HeaderMap,
) -> Result<Json<UserView>, ApiError> {
    let user = authenticate_request(&state, &headers).await?;
    let role_name = match user.role_id {
        Some(role_id) => state
            .auth
            .get_role(role_id)
            .await
            .map_err(internal_error)?
            .map(|r| r.name),
        None => None,
    };
    Ok(Json(user_view(
        user.id,
        user.username,
        user.is_admin,
        user.must_change_password,
        user.role_id,
        role_name,
        user.permissions,
    )))
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

/// Self-service password change — added 2026-08-26 alongside `must_change_password`
/// (direct user request: the fixed `admin`/`admin` bootstrap login must force a real
/// password on first use). Deliberately **not** behind `domain_guard!`/`admin_guard!` —
/// those two middlewares are exactly what reject every *other* request while
/// `must_change_password` is set (see their docs), so this has to stay reachable through
/// that same window or the account could never satisfy it. Any logged-in user can change
/// their own password this way regardless of the flag — not just accounts stuck in the
/// forced-change state — this is simply "the" self-service change-password endpoint, the
/// forced flow is just its most important caller.
///
/// Requires `current_password` (not just a valid session) before accepting `new_password`
/// — standard defense-in-depth for a change-password action: confirms whoever is at the
/// keyboard right now actually knows the password, not just that a session cookie/token
/// happens to still be valid (e.g. a browser left open). Re-uses `AuthStore::verify_password`
/// rather than a separate "check this user's password" method — same function `login`
/// itself calls, just keyed by the already-authenticated user's own username instead of
/// one supplied by an unauthenticated caller.
async fn change_own_password(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<StatusCode, ApiError> {
    let user = authenticate_request(&state, &headers).await?;
    if state
        .auth
        .verify_password(&user.username, &body.current_password)
        .await
        .map_err(internal_error)?
        .is_none()
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            "current password is incorrect".to_string(),
        ));
    }
    validate_password(&body.new_password).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    state
        .auth
        .set_password(user.id, &body.new_password)
        .await
        .map_err(internal_error)?;
    state
        .auth
        .delete_sessions_for_user(user.id)
        .await
        .map_err(internal_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct UserListItem {
    id: uuid::Uuid,
    username: String,
    is_admin: bool,
    /// Surfaced to admins mainly so a fixed-credential bootstrap account (`admin`/`admin`)
    /// left unchanged is visible in the list, not just enforced silently — see
    /// `discovery_auth::User::must_change_password`'s docs.
    must_change_password: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    role_id: Option<uuid::Uuid>,
    role_name: Option<String>,
}

async fn list_users(
    State(state): State<DashboardState>,
) -> Result<Json<Vec<UserListItem>>, ApiError> {
    let users = state.auth.list_users().await.map_err(internal_error)?;
    // Loaded once, not per user — same "resolve names once per request" shape
    // `build_device_views`'s `profiles_by_name` uses for the devices list.
    let roles_by_id: HashMap<uuid::Uuid, String> = state
        .auth
        .list_roles()
        .await
        .map_err(internal_error)?
        .into_iter()
        .map(|r| (r.id, r.name))
        .collect();
    let out = users
        .into_iter()
        .map(|u| UserListItem {
            id: u.id,
            username: u.username,
            is_admin: u.is_admin,
            must_change_password: u.must_change_password,
            created_at: u.created_at,
            role_id: u.role_id,
            role_name: u.role_id.and_then(|id| roles_by_id.get(&id).cloned()),
        })
        .collect();
    Ok(Json(out))
}

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
    #[serde(default)]
    is_admin: bool,
    /// Opt an admin-created account into the same forced-change-on-first-login flow the
    /// bootstrap account uses (see `discovery_auth::User::must_change_password`'s docs) —
    /// e.g. for handing out a temporary password. Defaults to `false`: an admin creating
    /// an account for someone typically already knows the password they're setting is
    /// meant to be the real one, unlike the bootstrap case.
    #[serde(default)]
    must_change_password: bool,
    /// Which role (if any) to assign at creation time — same dropdown a user's edit view
    /// uses for `PUT /api/users/:id/role`, just settable up front instead of requiring a
    /// second call right after creation.
    #[serde(default)]
    role_id: Option<uuid::Uuid>,
}

async fn create_user(
    State(state): State<DashboardState>,
    Json(body): Json<CreateUserRequest>,
) -> Result<axum::response::Response, ApiError> {
    // `details` deliberately omits `body.password` (raw plaintext at this point) and
    // stays limited to fields safe to record — never a generic dump of the request body,
    // unlike `diff_details`'s reuse elsewhere in this file, precisely because this one
    // body shape carries a secret. `is_admin`/`must_change_password`/`role_id` mirror
    // what `CreateUserRequest` itself already exposes as non-secret flags.
    let details = serde_json::json!({"is_admin": body.is_admin, "must_change_password": body.must_change_password, "role_id": body.role_id});
    validate_password(&body.password).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let user = state
        .auth
        .create_user(
            body.username.trim(),
            &body.password,
            body.is_admin,
            body.must_change_password,
            body.role_id,
        )
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let username = user.username.clone();
    Ok(with_journal_details(
        Json(user),
        Some(username),
        Some(details),
    ))
}

async fn delete_user(
    State(state): State<DashboardState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<axum::response::Response, ApiError> {
    // Fetched *before* deleting purely for the Журнал entry's `object` — the account (and
    // its username) is gone once `delete_user` returns.
    let username = state
        .auth
        .get_user_by_id(id)
        .await
        .map_err(internal_error)?
        .map(|u| u.username);
    if !state.auth.delete_user(id).await.map_err(internal_error)? {
        return Err((StatusCode::NOT_FOUND, "no such user".to_string()));
    }
    Ok(with_journal_details(StatusCode::NO_CONTENT, username, None))
}

#[derive(Deserialize)]
struct SetPasswordRequest {
    password: String,
}

/// `details` deliberately `None` — the new password must never appear in the audit
/// trail, plaintext or otherwise; `object` (username) is enough to say *who* had their
/// password reset.
async fn set_user_password(
    State(state): State<DashboardState>,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<SetPasswordRequest>,
) -> Result<axum::response::Response, ApiError> {
    validate_password(&body.password).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let username = state
        .auth
        .get_user_by_id(id)
        .await
        .map_err(internal_error)?
        .map(|u| u.username);
    if !state
        .auth
        .set_password(id, &body.password)
        .await
        .map_err(internal_error)?
    {
        return Err((StatusCode::NOT_FOUND, "no such user".to_string()));
    }
    state
        .auth
        .delete_sessions_for_user(id)
        .await
        .map_err(internal_error)?;
    Ok(with_journal_details(StatusCode::NO_CONTENT, username, None))
}

#[derive(Deserialize)]
struct SetAdminRequest {
    is_admin: bool,
}

async fn set_user_admin(
    State(state): State<DashboardState>,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<SetAdminRequest>,
) -> Result<axum::response::Response, ApiError> {
    let before = state
        .auth
        .get_user_by_id(id)
        .await
        .map_err(internal_error)?;
    if !state
        .auth
        .set_admin(id, body.is_admin)
        .await
        .map_err(internal_error)?
    {
        return Err((StatusCode::NOT_FOUND, "no such user".to_string()));
    }
    let object = before.as_ref().map(|u| u.username.clone());
    let details =
        before.map(|u| serde_json::json!({"is_admin": {"old": u.is_admin, "new": body.is_admin}}));
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        object,
        details,
    ))
}

#[derive(Deserialize)]
struct SetUserRoleRequest {
    /// `None` (or the key omitted, defaulting to `None`) clears the role entirely — back
    /// to no domain access, see `discovery_auth::User::role_id`'s docs.
    role_id: Option<uuid::Uuid>,
}

async fn set_user_role(
    State(state): State<DashboardState>,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<SetUserRoleRequest>,
) -> Result<axum::response::Response, ApiError> {
    let before = state
        .auth
        .get_user_by_id(id)
        .await
        .map_err(internal_error)?;
    if !state
        .auth
        .set_user_role(id, body.role_id)
        .await
        .map_err(internal_error)?
    {
        return Err((StatusCode::NOT_FOUND, "no such user".to_string()));
    }
    let object = before.as_ref().map(|u| u.username.clone());
    // Role names, not bare ids — an id alone in an audit trail forces a second lookup to
    // mean anything; `None` reads as "нет" (no role), matching the dashboard's own
    // "role_name: null" convention (`UserView`'s docs).
    let old_role_name = match before.and_then(|u| u.role_id) {
        Some(rid) => state
            .auth
            .get_role(rid)
            .await
            .ok()
            .flatten()
            .map(|r| r.name),
        None => None,
    };
    let new_role_name = match body.role_id {
        Some(rid) => state
            .auth
            .get_role(rid)
            .await
            .ok()
            .flatten()
            .map(|r| r.name),
        None => None,
    };
    let details = serde_json::json!({"role": {"old": old_role_name, "new": new_role_name}});
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        object,
        Some(details),
    ))
}

/// `Domain`/`AccessLevel` as their `as_str()` names ("devices"/"write", ...) on the wire —
/// same convention the old per-user `permissions` map used, just keyed by role now, see
/// `discovery_auth::Role`'s docs.
#[derive(Serialize)]
struct RoleView {
    id: uuid::Uuid,
    name: String,
    permissions: std::collections::HashMap<String, String>,
}

fn role_view(role: discovery_auth::Role) -> RoleView {
    RoleView {
        id: role.id,
        name: role.name,
        permissions: role
            .permissions
            .iter()
            .map(|(d, l)| (d.as_str().to_string(), l.as_str().to_string()))
            .collect(),
    }
}

fn parse_permissions_body(
    body: &std::collections::HashMap<String, String>,
) -> Result<HashMap<Domain, AccessLevel>, ApiError> {
    body.iter()
        .map(|(d, l)| {
            let domain = Domain::from_str(d)
                .ok_or((StatusCode::BAD_REQUEST, format!("unknown domain '{d}'")))?;
            let level = AccessLevel::from_str(l)
                .ok_or((StatusCode::BAD_REQUEST, format!("unknown level '{l}'")))?;
            Ok((domain, level))
        })
        .collect()
}

async fn list_roles(State(state): State<DashboardState>) -> Result<Json<Vec<RoleView>>, ApiError> {
    let roles = state.auth.list_roles().await.map_err(internal_error)?;
    Ok(Json(roles.into_iter().map(role_view).collect()))
}

#[derive(Deserialize)]
struct RoleRequest {
    name: String,
    #[serde(default)]
    permissions: std::collections::HashMap<String, String>,
}

async fn create_role(
    State(state): State<DashboardState>,
    Json(mut body): Json<RoleRequest>,
) -> Result<axum::response::Response, ApiError> {
    body.name = body.name.trim().to_string();
    let permissions = parse_permissions_body(&body.permissions)?;
    let role = state
        .auth
        .create_role(&body.name, permissions)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let view = role_view(role);
    let name = view.name.clone();
    Ok(with_journal_details(Json(view), Some(name), None))
}

async fn get_role(
    State(state): State<DashboardState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<RoleView>, ApiError> {
    match state.auth.get_role(id).await.map_err(internal_error)? {
        Some(role) => Ok(Json(role_view(role))),
        None => Err((StatusCode::NOT_FOUND, "no such role".to_string())),
    }
}

async fn update_role(
    State(state): State<DashboardState>,
    Path(id): Path<uuid::Uuid>,
    Json(mut body): Json<RoleRequest>,
) -> Result<axum::response::Response, ApiError> {
    body.name = body.name.trim().to_string();
    let permissions = parse_permissions_body(&body.permissions)?;
    // `update_role` is a full-replace (see its own docs) — the diff below is what makes
    // "which permissions actually changed" legible from the journal instead of just
    // "role X was edited"; no secrets on this struct (see `Role`'s docs), so a plain
    // `diff_details` (no `redact_sensitive` beyond what it already does) is safe here.
    let before = state
        .auth
        .get_role(id)
        .await
        .map_err(internal_error)?
        .map(role_view);
    let updated = state
        .auth
        .update_role(id, &body.name, permissions)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    if !updated {
        return Err((StatusCode::NOT_FOUND, "no such role".to_string()));
    }
    let after = RoleView {
        id,
        name: body.name.clone(),
        permissions: body.permissions.clone(),
    };
    let details = diff_details(before.as_ref(), &after);
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        Some(body.name.clone()),
        details,
    ))
}

async fn delete_role(
    State(state): State<DashboardState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<axum::response::Response, ApiError> {
    let name = state
        .auth
        .get_role(id)
        .await
        .map_err(internal_error)?
        .map(|r| r.name);
    if !state.auth.delete_role(id).await.map_err(internal_error)? {
        return Err((StatusCode::NOT_FOUND, "no such role".to_string()));
    }
    Ok(with_journal_details(StatusCode::NO_CONTENT, name, None))
}

/// Every write endpoint below goes straight through to whichever `ProfileStore`/
/// `DiscoveryConfigStore` `main.rs` picked for the configured storage backend
/// (memory/file/database — see `discovery-bootstrap`) — this is what makes the dashboard
/// an actual config editor and not just a read-only view: "не вижу где в webui
/// настраивать, должна быть возможность настройки через webui".
///
/// **`/api/dedup-config` removed 2026-08-16** (direct user request, same change that
/// pulled the custom dedup-key mechanism out entirely — see
/// `discovery_devices::DeviceStore::resolve`'s docs). Will come back, redesigned,
/// alongside whatever replaces it.
type ApiError = (StatusCode, String);

fn internal_error(e: anyhow::Error) -> ApiError {
    let correlation_id = Uuid::new_v4();
    error!(error = %e, %correlation_id, "internal request failure");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("internal server error (correlation id: {correlation_id})"),
    )
}

fn validate_optional_retention(name: &str, retention_secs: Option<u64>) -> Result<(), ApiError> {
    if retention_secs == Some(0) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{name} must be greater than zero or null"),
        ));
    }
    Ok(())
}

/// One row in the dashboard's device list. `metrics` is the device's unified data bag —
/// one-shot discovery-time `subnet.oids`/`subnet.labels` values and profile-polled
/// `[metrics.poll]` values share it (direct user request 2026-08-16 — see
/// `discovery_core::DeviceFacts`'s docs; no more artificial split between "data from
/// discovery" and "data from a profile poll"). Each entry is a full [`MetricRecord`], not
/// a bare value, as of the `device_metrics` table split (2026-08-16, direct user request —
/// see `migrations/0003_device_metrics.sql`'s docs) — this is what lets the dashboard show
/// per-metric staleness.
///
/// **Extended same day (metric change history):** `MetricRecord` now also carries `error`
/// (the most recent poll attempt's failure, if any) and `last_attempt_at` (when that
/// attempt happened, success or failure) alongside `value`/`polled_at` (the last
/// *success*) — no change needed here, `#[derive(Serialize)]` on `MetricRecord` picks up
/// the new fields automatically.
#[derive(Serialize)]
struct DeviceView {
    #[serde(flatten)]
    device: Device,
    metrics: Vec<MetricView>,
    /// Count of currently-**active** alerts for this device — direct user request
    /// 2026-08-28, mirrors Alerts' own IP→Devices deep link but in reverse (click the
    /// count here, land on Alerts pre-filtered to this device). Computed here (batched,
    /// once per page via `AlertStore::active_counts_by_device`), not stored anywhere —
    /// same "resolved fresh per request" treatment as `MetricView::effective_enabled`.
    active_alert_count: i64,
    /// Is this device currently under an active maintenance window? **Computed on every
    /// read, never stored** — same reasoning as `active_alert_count`: caching this would
    /// go stale exactly at a window's `starts_at`/`ends_at` boundary, the one moment this
    /// field's accuracy matters most. See `attach_maintenance_status`'s docs.
    under_maintenance: bool,
    /// `Some(true)`/`Some(false)` only from [`create_device`]'s response — whether this
    /// POST actually created a new row or resolved to an already-existing one by ip (see
    /// that handler's docs, TASK-20260921-019). `None`/omitted everywhere else
    /// ([`build_device_views`] always leaves it `None`): list/get responses have no
    /// "was this just created" question to answer.
    #[serde(skip_serializing_if = "Option::is_none")]
    created: Option<bool>,
}

/// A [`MetricRecord`] plus the *resolved* on/off state — direct user request 2026-08-16:
/// "за определенными устройствами выключать временно метрики" / "настраивать это за
/// самими профилями". `MetricRecord.enabled_override` alone only tells you whether *this
/// device* has an explicit override; it doesn't know the profile's own default, so it
/// can't say whether the metric is actually being polled right now. This wrapper combines
/// both, computed here (not stored anywhere) since `DeviceStore` deliberately doesn't know
/// about profiles at all — see `discovery_devices::DeviceStore`'s docs for why that
/// separation matters (it's what keeps the override table's write path free of any
/// profile-driven code).
#[derive(Serialize)]
struct MetricView {
    #[serde(flatten)]
    record: MetricRecord,
    /// `record.enabled_override` if one exists, otherwise the current profile's own
    /// default for this metric name (`MetricSpec::enabled()`) — `true` if the device has
    /// no profile right now, or that profile no longer exists, or the profile doesn't
    /// even declare this metric name (all "nothing to disable against" cases).
    effective_enabled: bool,
}

#[derive(Deserialize)]
struct DevicesQuery {
    /// Free-text, case-insensitive. Matched against the device's IP and profile name via
    /// the fast SQL path; also matched against every metric's current value when this
    /// triggers the full-fleet-then-filter-in-Rust path (see [`devices`]'s docs on why a
    /// non-empty search always does, unlike an idle poll with no filters at all).
    search: Option<String>,
    /// Exact profile-name filter — a dropdown on the dashboard, populated from
    /// `GET /api/profiles`, not free text (avoids "generic_switch" vs "Generic_Switch"
    /// typo-mismatches a search box would risk).
    profile: Option<String>,
    /// `true` keeps only devices with at least one metric currently in an error state
    /// (`MetricRecord.error.is_some()`) — a "show me what's broken" toggle.
    has_error: Option<bool>,
    /// Dotted-quad CIDR, e.g. `"10.121.0.0/16"` — kept only devices whose IP falls inside
    /// it. No generic cross-backend SQL expression for this (Postgres/MySQL/SQLite/memory
    /// all differ), so — like `has_error` — it's applied in Rust after a full fetch, not
    /// pushed into `DeviceListQuery`. See [`ip_in_cidr`].
    cidr: Option<String>,
    /// "ip" (default) | "profile" | "discovered_at".
    sort_by: Option<String>,
    /// "asc" (default) | "desc".
    sort_dir: Option<String>,
    page: Option<u32>,
    page_size: Option<u32>,
}

#[derive(Serialize)]
struct DevicesPage {
    items: Vec<DeviceView>,
    total: usize,
}

/// Parses a dotted-quad IPv4 address into an octet tuple for a *numeric* sort key — plain
/// string comparison would put `"10.0.0.10"` before `"10.0.0.2"` (lexicographic: `'1' <
/// '2'`), which looks obviously wrong on a dashboard. Anything that doesn't parse as four
/// dotted octets (shouldn't happen in this project — `DeviceFacts.ip` is always IPv4 today
/// — but cheap to guard) sorts after every valid address rather than panicking or silently
/// misplacing it.
fn ip_sort_key(ip: &str) -> (u8, [u8; 4]) {
    let mut octets = [0u8; 4];
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 {
        if let Some(parsed) = parts
            .iter()
            .map(|p| p.parse::<u8>().ok())
            .collect::<Option<Vec<u8>>>()
        {
            octets.copy_from_slice(&parsed);
            return (0, octets);
        }
    }
    (1, octets) // unparseable — sorts after every valid IPv4 address
}

/// `true` if `value` (a metric's current value, scalar or table) contains `needle`
/// (already lowercased) anywhere — the dashboard search box's "search also matches metric
/// values" behavior (2026-08-27). For `MetricValue::Table`, searches every cell of every
/// row: a device search for a hostname/status string should find it whether it lives in a
/// scalar metric or inside a table-shaped one (e.g. a down port's `ifDescr` in `if_table`),
/// not just the former. Recurses rather than a flat loop purely so a future nested shape
/// (there isn't one today — see `MetricValue::Table`'s docs on why a cell is never itself a
/// table) wouldn't silently stop being searched.
fn metric_value_matches_search(value: &discovery_core::MetricValue, needle: &str) -> bool {
    match value {
        discovery_core::MetricValue::Str(s) => s.to_lowercase().contains(needle),
        discovery_core::MetricValue::Int(n) => n.to_string().contains(needle),
        discovery_core::MetricValue::Float(f) => f.to_string().contains(needle),
        discovery_core::MetricValue::Bool(b) => b.to_string().contains(needle),
        discovery_core::MetricValue::Table(rows) => rows.iter().any(|row| {
            row.fields
                .values()
                .any(|cell| metric_value_matches_search(cell, needle))
        }),
    }
}

/// `true` if `ip` (dotted-quad IPv4) falls inside `cidr` (`"a.b.c.d/prefix"`). Malformed
/// input on either side — bad dotted-quad, missing `/prefix`, prefix out of `0..=32` — is
/// treated as "doesn't match" rather than an error: this feeds a dashboard filter field a
/// human is actively typing into, where a half-typed CIDR should just show nothing yet,
/// not 400 the whole request.
fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    fn parse_ipv4(s: &str) -> Option<u32> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return None;
        }
        let octets: Vec<u8> = parts
            .iter()
            .map(|p| p.parse::<u8>().ok())
            .collect::<Option<Vec<u8>>>()?;
        Some(u32::from_be_bytes([
            octets[0], octets[1], octets[2], octets[3],
        ]))
    }

    let Some((network_str, prefix_str)) = cidr.split_once('/') else {
        return false;
    };
    let Some(network) = parse_ipv4(network_str.trim()) else {
        return false;
    };
    let Ok(prefix) = prefix_str.trim().parse::<u32>() else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    let Some(addr) = parse_ipv4(ip) else {
        return false;
    };

    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (addr & mask) == (network & mask)
}

/// Search + filter + sort + paginate the device list — added 2026-08-17, direct user
/// request (dashboard pagination/search/sort/filter pass). Done entirely in this handler
/// over `DeviceStore::all_with_metrics()`'s full result, not pushed down into per-backend
/// SQL: device counts in this project don't approach the scale `JobQueueStore::list_jobs`
/// has to worry about (a stable device inventory, not a bursty work queue — see that
/// method's docs for the contrast), so filtering/sorting/paging an already-fetched `Vec`
/// in Rust is simpler and just as fast in practice.
/// Strips the actual secret out of `SshAuth::Password`/`SshAuth::PrivateKey` before a
/// `Device` ever reaches a GET response — fixes a real bug found in the 2026-09-17 audit
/// (finding #5, see `docs/Changelog/2026-09-17 - Аудит глазами оператора...md`): the "SSH-
/// креды" modal's own text claims "Пароль/приватный ключ никогда не приходят обратно с
/// сервера", but before this existed `Device` (flattened straight into [`DeviceView`]) was
/// serialized as-is — the modal simply never *populated* the field from the response, which
/// only hid the leak from that one screen. `GET /api/devices`/`GET /api/devices/:id`
/// (`build_device_views`'s only two callers that reach an HTTP response — see this
/// function's own docs) genuinely returned the decrypted password/private key/passphrase in
/// plaintext to any caller with read access to "Устройства", visible in the Network tab
/// regardless of what the modal did or didn't show.
///
/// Keeps `username`/`port`/`auth`'s `kind` tag intact (the SSH-креды modal legitimately
/// reads these back — see `DevicesPage.tsx`'s `openSshModal`) and blanks only the secret
/// payload itself, to an empty string rather than dropping the field/enum variant entirely
/// — this is the one place `SshAuth` deserializes leniently either way, and an empty
/// string is indistinguishable from what the modal already always showed for these fields.
///
/// Purely a response-shaping concern — never applied to what `DeviceStore` itself
/// reads/writes (SSH polling needs the *real* decrypted credential to ever connect), so this
/// must only ever be called from a GET-response path, never before a write.
fn redact_ssh_credentials(
    creds: Option<discovery_core::SshCredentials>,
) -> Option<discovery_core::SshCredentials> {
    creds.map(|mut c| {
        c.auth = match c.auth {
            discovery_core::SshAuth::Password { .. } => discovery_core::SshAuth::Password {
                password: String::new(),
            },
            discovery_core::SshAuth::PrivateKey { passphrase, .. } => {
                discovery_core::SshAuth::PrivateKey {
                    private_key: String::new(),
                    passphrase: passphrase.map(|_| String::new()),
                }
            }
        };
        c
    })
}

/// SNMP credentials are operational secrets too: v2c community strings and both USM v3
/// passphrases must never be included in ordinary device reads.  Unlike SSH, there is no
/// non-secret metadata the dashboard needs from this field, so the response removes it
/// completely while the store retains the real credentials for polling and trap auth.
fn redact_snmp_credentials(device: &mut Device) {
    device.snmp_credentials = None;
}

/// Shared by [`devices`] and [`get_device_by_id`] — resolves every metric's *effective*
/// enabled state (override-or-profile-default, see [`MetricView`]'s docs) against a
/// pre-loaded `name -> ProfileFile` map, once per request rather than once per device.
fn build_device_views(
    rows: Vec<(Device, Vec<MetricRecord>)>,
    profiles_by_name: &HashMap<String, ProfileFile>,
) -> Vec<DeviceView> {
    rows.into_iter()
        .map(|(mut device, metrics)| {
            device.ssh_credentials = redact_ssh_credentials(device.ssh_credentials);
            redact_snmp_credentials(&mut device);
            let profile = device
                .profile
                .as_deref()
                .and_then(|name| profiles_by_name.get(name));
            let metrics = metrics
                .into_iter()
                .map(|record| {
                    let profile_default = profile
                        .and_then(|p| p.metrics.poll.get(&record.name))
                        .map(|spec| spec.enabled())
                        .unwrap_or(true);
                    let effective_enabled = record.enabled_override.unwrap_or(profile_default);
                    MetricView {
                        record,
                        effective_enabled,
                    }
                })
                .collect();
            // Placeholders — [`attach_active_alert_counts`]/[`attach_maintenance_status`]
            // fill these in for real, but only once for whichever page of devices
            // actually ends up being returned (after filter/sort/pagination), not for
            // every row this function is ever called with (the full-fleet
            // `has_error`/`cidr`/`search` path above builds views for the *whole* fleet
            // before slicing a page out of them — batching either query against all of
            // those would defeat the point).
            DeviceView {
                device,
                metrics,
                active_alert_count: 0,
                under_maintenance: false,
                created: None,
            }
        })
        .collect()
}

/// Batched `AlertStore::active_counts_by_device` lookup for exactly `items` (typically one
/// page, ≤500 — `DevicesQuery::page_size`'s cap) — mutates each `DeviceView` in place. Split
/// out from [`build_device_views`] so every caller can defer this until *after* whichever
/// filter/sort/paginate path it takes has settled on the final page, see that function's
/// docs on why.
async fn attach_active_alert_counts(
    items: &mut [DeviceView],
    alerts: &dyn discovery_alerts::AlertStore,
) -> anyhow::Result<()> {
    let ids: Vec<Uuid> = items.iter().map(|v| v.device.id).collect();
    let counts = alerts.active_counts_by_device(&ids).await?;
    for item in items {
        item.active_alert_count = counts.get(&item.device.id).copied().unwrap_or(0);
    }
    Ok(())
}

/// The "под ТО" indicator — `MaintenanceWindowStore::list_all()` is loaded **once for the
/// whole page** (batch-not-loop, same discipline `attach_active_alert_counts` and
/// `AlertEvalHandler`'s own per-tick check already follow), then
/// `discovery_config_store::is_device_under_maintenance` is evaluated per device in
/// memory — matching isn't a predicate any of Postgres/MySQL/SQLite can share, so pushing
/// it into SQL isn't an option the way `active_counts_by_device` can. Computed fresh on
/// every call, never cached — see [`DeviceView::under_maintenance`]'s docs on why.
async fn attach_maintenance_status(
    items: &mut [DeviceView],
    maintenance_windows: &dyn MaintenanceWindowStore,
    now: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<()> {
    let windows = maintenance_windows.list_all().await?;
    for item in items {
        item.under_maintenance = discovery_config_store::is_device_under_maintenance(
            &windows,
            &item.device.facts.ip,
            item.device.profile.as_deref(),
            item.device.id,
            now,
        );
    }
    Ok(())
}

/// Search + filter + sort + paginate the device list — added 2026-08-17, direct user
/// request (dashboard pagination/search/sort/filter pass).
///
/// **Rewritten 2026-08-21, scale audit finding.** Used to call `all_with_metrics()`
/// unconditionally (every device, every column, every metric) and filter/sort/paginate the
/// resulting `Vec` in Rust — on the explicit (and, once this project was asked to be ready
/// for 500k-1M devices, no longer true) reasoning that "device counts in this project don't
/// approach the scale `JobQueueStore::list_jobs` has to worry about". The dashboard polls
/// this endpoint every 1.5s while the devices page is open, so that cost was paid
/// continuously, not just occasionally.
///
/// Now pushes search/profile-filter/sort/pagination down to
/// `DeviceStore::list_devices` (SQL-level, same shape as `list_jobs`/`AlertStore::list`)
/// and only fetches metrics for the one *page* of devices actually being returned — except
/// for `has_error`, which can't be pushed into that same query (it depends on
/// `device_metrics`, a domain that can route to a different physical database than
/// `devices` — see `DeviceListQuery`'s docs) and falls back to the old full-fleet-then-
/// filter-in-Rust path. That fallback is a known, deliberate scope limit: `has_error` is an
/// occasional "show me what's broken" toggle a human clicks, not something the dashboard's
/// idle 1.5s poll exercises by default.
async fn devices(
    State(state): State<DashboardState>,
    Query(params): Query<DevicesQuery>,
) -> Result<Json<DevicesPage>, ApiError> {
    // Loaded once per request, not per device — needed purely to resolve each metric's
    // *effective* enabled state (override-or-profile-default), see `MetricView`'s docs.
    let profiles_by_name: HashMap<String, ProfileFile> = state
        .profiles
        .load_all()
        .await
        .map_err(internal_error)?
        .into_iter()
        .map(|p| (p.profile.name.clone(), p))
        .collect();

    let search_trimmed = params
        .search
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let cidr_trimmed = params
        .cidr
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    // `has_error`/`cidr` can't be expressed as a generic cross-backend SQL predicate (see
    // their own docs on `DevicesQuery`) and always require the full-fleet path below. A
    // non-empty `search` joins them here too — 2026-08-27 addition, direct user request to
    // match the design artifact's "search also matches metric values" behavior — which
    // needs every device's metrics loaded to check, the same data this path already loads
    // for `has_error`. Deliberately **not** applied when `search` is empty: that's the
    // dashboard's continuous idle-poll shape (no filters at all), which is exactly what the
    // 2026-08-21 scale rewrite optimized onto the fast `DeviceListQuery` path below — a
    // human typing into the search box (debounced 300ms) is a bounded, occasional cost by
    // comparison, not something paid on every poll tick.
    if params.has_error == Some(true) || cidr_trimmed.is_some() || search_trimmed.is_some() {
        let rows = discovery_devices::all_with_metrics(
            state.devices.as_ref(),
            state.device_metrics.as_ref(),
        )
        .await
        .map_err(internal_error)?;
        let mut views: Vec<DeviceView> = build_device_views(rows, &profiles_by_name);

        if let Some(needle) = search_trimmed.map(str::to_lowercase) {
            views.retain(|v| {
                v.device.facts.ip.to_lowercase().contains(&needle)
                    || v.device
                        .profile
                        .as_deref()
                        .map(|p| p.to_lowercase().contains(&needle))
                        .unwrap_or(false)
                    || v.metrics.iter().any(|m| {
                        m.record
                            .value
                            .as_ref()
                            .is_some_and(|value| metric_value_matches_search(value, &needle))
                    })
            });
        }
        if let Some(profile) = params.profile.as_deref().filter(|s| !s.is_empty()) {
            views.retain(|v| v.device.profile.as_deref() == Some(profile));
        }
        if let Some(cidr) = cidr_trimmed {
            views.retain(|v| ip_in_cidr(&v.device.facts.ip, cidr));
        }
        if params.has_error == Some(true) {
            views.retain(|v| v.metrics.iter().any(|m| m.record.error.is_some()));
        }

        let desc = params.sort_dir.as_deref() == Some("desc");
        match params.sort_by.as_deref() {
            Some("profile") => views.sort_by(|a, b| a.device.profile.cmp(&b.device.profile)),
            Some("discovered_at") => {
                views.sort_by(|a, b| a.device.discovered_at.cmp(&b.device.discovered_at))
            }
            _ => views.sort_by(|a, b| {
                ip_sort_key(&a.device.facts.ip).cmp(&ip_sort_key(&b.device.facts.ip))
            }),
        }
        if desc {
            views.reverse();
        }

        let total = views.len();
        let page_size = params.page_size.unwrap_or(25).clamp(1, 500) as usize;
        let page = params.page.unwrap_or(1).max(1) as usize;
        let mut items: Vec<DeviceView> = views
            .into_iter()
            .skip((page - 1) * page_size)
            .take(page_size)
            .collect();
        attach_active_alert_counts(&mut items, state.alert_store.as_ref())
            .await
            .map_err(internal_error)?;
        attach_maintenance_status(
            &mut items,
            state.maintenance_windows.as_ref(),
            chrono::Utc::now(),
        )
        .await
        .map_err(internal_error)?;
        return Ok(Json(DevicesPage { items, total }));
    }

    let sort_by = match params.sort_by.as_deref() {
        Some("profile") => discovery_devices::DeviceSortBy::Profile,
        Some("discovered_at") => discovery_devices::DeviceSortBy::DiscoveredAt,
        _ => discovery_devices::DeviceSortBy::Ip,
    };
    let sort_dir = if params.sort_dir.as_deref() == Some("desc") {
        SortDir::Desc
    } else {
        SortDir::Asc
    };
    let page_size = params.page_size.unwrap_or(25).clamp(1, 500) as i64;
    let page = params.page.unwrap_or(1).max(1) as i64;
    let list_query = discovery_devices::DeviceListQuery {
        search: params.search.clone(),
        profile: params.profile.clone(),
        sort_by: Some(sort_by),
        sort_dir: Some(sort_dir),
        limit: page_size,
        offset: (page - 1) * page_size,
    };
    let list_page = state
        .devices
        .list_devices(&list_query)
        .await
        .map_err(internal_error)?;
    let total = list_page.total as usize;
    let rows = discovery_devices::with_metrics(
        list_page.items,
        state.devices.as_ref(),
        state.device_metrics.as_ref(),
    )
    .await
    .map_err(internal_error)?;
    let mut items = build_device_views(rows, &profiles_by_name);
    attach_active_alert_counts(&mut items, state.alert_store.as_ref())
        .await
        .map_err(internal_error)?;
    attach_maintenance_status(
        &mut items,
        state.maintenance_windows.as_ref(),
        chrono::Utc::now(),
    )
    .await
    .map_err(internal_error)?;

    Ok(Json(DevicesPage { items, total }))
}

/// Single-device read — added 2026-08-18 during a REST-completeness pass (direct user
/// request: "REST должен полностью позволять работать с приложением, без UI").
///
/// **Rewritten 2026-08-21, scale audit finding** — used to call `all_with_metrics()` (every
/// device in the fleet) just to find one by id in Rust; the doc comment even said so
/// explicitly ("not worth a dedicated single-row store method just for this"), which
/// stopped being true the moment this project needed to be ready for a 500k-1M-device
/// fleet. Now a targeted `DeviceStore::get_device` (single-row, already existed and was
/// already used by `delete_device`) plus metrics for just that one device.
#[derive(Deserialize)]
struct CreateDeviceBody {
    ip: String,
    /// Existing profile name to force-assign, bypassing `match_expr` — direct user
    /// request 2026-08-28: "ручное создание устройств - указание ip, профиля". Optional;
    /// omitted/blank leaves the device profile-less, same as a freshly-discovered device
    /// that hasn't matched anything yet.
    #[serde(default)]
    profile: Option<String>,
    /// Initial metric name -> value bag, written the same way discovery subnets' own
    /// one-shot `labels` are (a constant string, no SNMP round trip) — direct user
    /// request: "ручное добавление метрик (по типу area_name и прочих)". String-only,
    /// matching `SubnetSpec::labels`' shape; a later real profile poll overwriting one of
    /// these is expected and fine (explicitly confirmed by the user), not guarded against.
    #[serde(default)]
    metrics: std::collections::BTreeMap<String, String>,
    /// SNMP auth to record as this device's negotiated credentials — added 2026-08-30
    /// alongside SNMP Trap ingestion: a manually-created device otherwise has
    /// `snmp_credentials: None` forever (only `SnmpPollHandler`'s real negotiation sets
    /// it), which the trap listener requires to validate an incoming trap's claimed auth
    /// against (see `discovery-agent::trap_ingest::auth_matches`'s docs) — without this, a
    /// manually-created device could never receive traps at all. Optional; omitted leaves
    /// the device exactly as before (`None`, same as a fresh discovery-pipeline device
    /// before its first successful `SnmpPoll`). `port` defaults to 161, same as
    /// `SnmpCredentials::port`'s own default.
    #[serde(default)]
    snmp_auth: Option<discovery_core::SnmpAuth>,
    #[serde(default)]
    snmp_port: Option<u16>,
}

/// Manual device creation — direct user request 2026-08-28: "ручное создание устройств -
/// указание ip, профиля, ручное добавление метрик... потом профиль может переопросить
/// метрику - это ок". Every other device in this system arrives through the discovery
/// pipeline (`DiscoveryHandler` -> `SnmpPoll` -> `Dedup` -> `ProfileApply`); this is the one
/// bypass, for a device an operator wants to track without waiting for (or without being
/// able to run) a real SNMP discovery pass against it.
///
/// `profile`, if given, is force-assigned via the same `DeviceStore::apply_profile_if_changed`
/// the real `ProfileApplyHandler` uses (not a bespoke setter) — this keeps the device's
/// profile/profile_version pair internally consistent with what that pipeline expects to
/// find, so a later automatic re-evaluation doesn't see a nonsensical state. It does
/// **not** itself start a `MetricPoll` chain (that's an in-process, per-agent-instance
/// concern — `ActiveChains`, private to `discovery-agent`, not reachable from
/// `discovery-web`) — the device's metrics simply start getting polled on this profile's
/// normal schedule once `discovery-agent`'s own periodic reconciliation notices it, same
/// as it would for any other already-known device after a process restart.
///
/// **`ip` already in use by another device: returns that device untouched, applying none
/// of `snmp_auth`/`profile`/`metrics` from this request** (TASK-20260921-019, 2026-09-22).
/// `DeviceStore::resolve` itself has get-or-create semantics (an already-known ip is not a
/// new device — needed so the *automatic* discovery pipeline's repeated resolves of the
/// same live device stay idempotent), but blindly reapplying every optional field on that
/// path here would let a POST that collides with an existing IP silently overwrite a real
/// device's SNMP credentials or profile assignment — this endpoint's name and the
/// frontend's "device created" messaging both promise a *creation*, not an edit. A caller
/// that actually wants to change an existing device's profile/credentials/metrics has
/// dedicated endpoints for exactly that (`PUT /api/devices/:id/profile`, `/snmp-credentials`,
/// `/ssh-credentials`, `POST /api/devices/:id/metrics`) — this one only ever populates a
/// genuinely new row. Status/response shape stay `200`/`DeviceView` either way (matching
/// every other upsert-style POST in this file — no endpoint here uses `201`), since the
/// "existing, unchanged" case was already relied on as idempotent-by-IP before this fix.
async fn create_device(
    State(state): State<DashboardState>,
    Json(mut body): Json<CreateDeviceBody>,
) -> Result<axum::response::Response, ApiError> {
    let ip = body.ip.trim();
    if ip.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "ip must not be empty".to_string()));
    }
    // IPv4-only, same as everything downstream that polls/matches this address (SNMP,
    // subnet selectors — see `discovery_config_store::scan`'s `Ipv4Addr`-only math): an
    // arbitrary accepted string used to save fine and then just never resolve to a
    // working device (TASK-20260921-018). No address-class restriction beyond "is it a
    // real IPv4 address" — unlike the SSRF allowlists elsewhere in this file (webhook/
    // service-check targets), loopback/private ranges are the *expected* common case
    // here: real deployments monitor RFC1918 devices, and manual creation against a
    // `discovery-devicefarm` instance on `127.0.0.x` is a legitimate, exercised workflow.
    // Re-serialized through `Ipv4Addr` (not the raw trimmed string) so a non-canonical
    // form (`Ipv4Addr::from_str` already rejects octal-ambiguous leading zeros, but not
    // e.g. surrounding formatting quirks) can't slip through as a distinct device.
    let parsed: std::net::Ipv4Addr = ip.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            format!("ip '{ip}' is not a valid IPv4 address (IPv6 is not currently supported)"),
        )
    })?;
    let ip_owned = parsed.to_string();
    let profile_name = body
        .profile
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    // Validate the profile *before* touching the device-creation lock below — a pure read,
    // independent of the device count, so an unknown profile name fails fast without making
    // other concurrent creations wait on it. Also rejects the whole request cleanly rather
    // than leaving a profile-less device behind that the caller never actually asked for.
    let profile = if let Some(profile_name) = profile_name {
        let profiles = state.profiles.load_all().await.map_err(internal_error)?;
        let Some(profile) = profiles
            .into_iter()
            .find(|p| p.profile.name == profile_name)
        else {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("no such profile '{profile_name}'"),
            ));
        };
        Some(profile)
    } else {
        None
    };

    let (device_id, is_new) = state
        .devices
        .resolve(discovery_core::DeviceFacts {
            ip: ip_owned.clone(),
        })
        .await
        .map_err(internal_error)?;

    // TASK-20260921-019 — none of these run for an already-existing device (see this
    // handler's docs): applying them unconditionally would let a POST that happens to
    // collide with a real device's IP silently overwrite its credentials/profile.
    if is_new {
        if let Some(mut auth) = body.snmp_auth.take() {
            // Audit finding 5 (2026-09-20) — see `SnmpAuth::trim_identifiers`'s docs.
            auth.trim_identifiers();
            state
                .devices
                .set_snmp_credentials(
                    device_id,
                    discovery_core::SnmpCredentials {
                        auth,
                        port: body.snmp_port.unwrap_or(161),
                    },
                )
                .await
                .map_err(internal_error)?;
        }

        if let Some(profile) = profile {
            state
                .devices
                .apply_profile_if_changed(device_id, &profile.profile.name, &profile.version)
                .await
                .map_err(internal_error)?;
        }

        if !body.metrics.is_empty() {
            let outcomes: std::collections::BTreeMap<String, discovery_core::MetricPollOutcome> =
                body.metrics
                    .into_iter()
                    .map(|(name, value)| {
                        (
                            name,
                            discovery_core::MetricPollOutcome::Ok(
                                discovery_core::MetricValue::Str(value),
                            ),
                        )
                    })
                    .collect();
            state
                .device_metrics
                .record_metric_polls(device_id, &outcomes)
                .await
                .map_err(internal_error)?;
        }
    }

    let profiles_by_name: HashMap<String, ProfileFile> = state
        .profiles
        .load_all()
        .await
        .map_err(internal_error)?
        .into_iter()
        .map(|p| (p.profile.name.clone(), p))
        .collect();
    let Some(device) = state
        .devices
        .get_device(device_id)
        .await
        .map_err(internal_error)?
    else {
        return Err(internal_error(anyhow::anyhow!(
            "device vanished immediately after creation"
        )));
    };
    let rows = discovery_devices::with_metrics(
        vec![device],
        state.devices.as_ref(),
        state.device_metrics.as_ref(),
    )
    .await
    .map_err(internal_error)?;
    state
        .store
        .enqueue(
            QueueKind::AlertEval,
            serde_json::json!({"device_id": device_id}),
            Some(&device_id.to_string()),
        )
        .await
        .map_err(internal_error)?;
    let mut items = build_device_views(rows, &profiles_by_name);
    attach_active_alert_counts(&mut items, state.alert_store.as_ref())
        .await
        .map_err(internal_error)?;
    attach_maintenance_status(
        &mut items,
        state.maintenance_windows.as_ref(),
        chrono::Utc::now(),
    )
    .await
    .map_err(internal_error)?;
    let mut view = items
        .into_iter()
        .next()
        .expect("exactly one device was composed above");
    view.created = Some(is_new);
    // Journal `details` says which case this was too (TASK-20260921-019) — the shared
    // `describe_action`/`record_journal_entry` machinery has no per-call opt-out to
    // suppress the "Создано устройство" line entirely for the no-op path, but the entry
    // itself doesn't have to lie about what happened.
    Ok(with_journal_details(
        Json(view),
        Some(ip_owned),
        Some(serde_json::json!({"created": is_new})),
    ))
}

/// Bounded multi-protocol discovery for one explicitly requested IPv4 address.
/// Failed probes never create a device; successful repeated requests resolve the same IP.
async fn run_service_discovery(
    State(state): State<DashboardState>,
    Json(mut request): Json<service_discovery::ServiceDiscoveryRequest>,
) -> Result<Json<service_discovery::ServiceDiscoveryResponse>, ApiError> {
    let ip = service_discovery::validate_request(&request)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    request.ip = ip.to_string();

    let profiles = state.profiles.load_all().await.map_err(internal_error)?;
    let checker = service_discovery::real_checker().map_err(internal_error)?;
    let snmp: Arc<dyn discovery_snmp::SnmpClient> = Arc::new(discovery_snmp::RealSnmpClient::new());
    let (results, winner) =
        service_discovery::discover(&request, &profiles, checker.as_ref(), snmp.as_ref()).await;

    let Some(profile) = winner else {
        return Ok(Json(service_discovery::ServiceDiscoveryResponse {
            ip: request.ip,
            device_id: None,
            profile: None,
            created: false,
            results,
        }));
    };

    let (device_id, created) = state
        .devices
        .resolve(discovery_core::DeviceFacts {
            ip: request.ip.clone(),
        })
        .await
        .map_err(internal_error)?;

    if created {
        if let Some(mut auth) = request.snmp_auth.take() {
            auth.trim_identifiers();
            state
                .devices
                .set_snmp_credentials(
                    device_id,
                    discovery_core::SnmpCredentials {
                        auth,
                        port: request.snmp_port.unwrap_or(161),
                    },
                )
                .await
                .map_err(internal_error)?;
        }
    }
    state
        .devices
        .apply_profile_if_changed(device_id, &profile.name, &profile.version)
        .await
        .map_err(internal_error)?;

    Ok(Json(service_discovery::ServiceDiscoveryResponse {
        ip: request.ip,
        device_id: Some(device_id),
        profile: Some(profile.name),
        created,
        results,
    }))
}

async fn get_device_by_id(
    State(state): State<DashboardState>,
    Path(id): Path<Uuid>,
) -> Result<Json<DeviceView>, ApiError> {
    let profiles_by_name: HashMap<String, ProfileFile> = state
        .profiles
        .load_all()
        .await
        .map_err(internal_error)?
        .into_iter()
        .map(|p| (p.profile.name.clone(), p))
        .collect();
    let Some(device) = state.devices.get_device(id).await.map_err(internal_error)? else {
        return Err((StatusCode::NOT_FOUND, "no such device".to_string()));
    };
    let rows = discovery_devices::with_metrics(
        vec![device],
        state.devices.as_ref(),
        state.device_metrics.as_ref(),
    )
    .await
    .map_err(internal_error)?;
    let mut items = build_device_views(rows, &profiles_by_name);
    attach_active_alert_counts(&mut items, state.alert_store.as_ref())
        .await
        .map_err(internal_error)?;
    attach_maintenance_status(
        &mut items,
        state.maintenance_windows.as_ref(),
        chrono::Utc::now(),
    )
    .await
    .map_err(internal_error)?;
    Ok(Json(
        items
            .into_iter()
            .next()
            .expect("exactly one device was composed above"),
    ))
}

#[derive(Serialize)]
struct OperatorActionView {
    job_id: i64,
    alert_id: Option<Uuid>,
    device_id: Uuid,
    action: OperatorAction,
    status: &'static str,
    result: Option<serde_json::Value>,
    error: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

fn operator_action_view(job: discovery_core::Job) -> Result<OperatorActionView, ApiError> {
    let payload: OperatorActionPayload =
        serde_json::from_value(job.payload).map_err(|e| internal_error(e.into()))?;
    Ok(OperatorActionView {
        job_id: job.id,
        alert_id: payload.alert_id,
        device_id: payload.device_id,
        action: payload.action,
        status: match job.state {
            JobState::Pending => "pending",
            JobState::InProgress => "in_progress",
            JobState::Failed => "failed",
            JobState::Done => "done",
            JobState::Cancelled => "cancelled",
        },
        result: job.result,
        error: job.last_error,
        created_at: job.created_at,
        updated_at: job.updated_at,
    })
}

async fn run_device_action(
    State(state): State<DashboardState>,
    Path((id, action)): Path<(Uuid, String)>,
    headers: HeaderMap,
) -> Result<axum::response::Response, ApiError> {
    let action = OperatorAction::from_str(&action)
        .ok_or((StatusCode::NOT_FOUND, "unknown action".to_string()))?;
    let user = authenticate_request(&state, &headers).await?;
    enqueue_checked_device_action(&state, id, action, user.username, None).await
}

async fn enqueue_checked_device_action(
    state: &DashboardState,
    id: Uuid,
    action: OperatorAction,
    username: String,
    alert_id: Option<Uuid>,
) -> Result<axum::response::Response, ApiError> {
    let _guard = state.action_enqueue_lock.lock().await;
    let device = state
        .devices
        .get_device(id)
        .await
        .map_err(internal_error)?
        .ok_or((StatusCode::NOT_FOUND, "no such device".to_string()))?;
    if !device.enabled {
        return Err((StatusCode::CONFLICT, "device is disabled".to_string()));
    }
    if matches!(action, OperatorAction::PollNow | OperatorAction::Backup)
        && device.profile.is_none()
    {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "device has no profile".to_string(),
        ));
    }
    if action == OperatorAction::Backup && device.ssh_credentials.is_none() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "device has no SSH credentials".to_string(),
        ));
    }
    if state
        .store
        .is_queue_paused(QueueKind::OperatorAction)
        .await
        .map_err(internal_error)?
    {
        return Err((
            StatusCode::CONFLICT,
            "operator action queue is paused".to_string(),
        ));
    }
    let recent = state
        .store
        .list_jobs(
            QueueKind::OperatorAction,
            &JobListQuery {
                search: Some(id.to_string()),
                limit: 20,
                ..JobListQuery::default()
            },
        )
        .await
        .map_err(internal_error)?;
    for previous in recent.jobs {
        if previous.state == JobState::Cancelled {
            continue;
        }
        if let Ok(p) = serde_json::from_value::<OperatorActionPayload>(previous.payload) {
            if p.device_id == id
                && p.action == action
                && previous.created_at > chrono::Utc::now() - chrono::Duration::seconds(30)
                && !matches!(previous.state, JobState::Pending | JobState::InProgress)
            {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    "this action was run recently; wait 30 seconds".to_string(),
                ));
            }
        }
    }
    let payload = OperatorActionPayload {
        alert_id,
        device_id: id,
        action,
        username,
    };
    let dedupe_key = id.to_string();
    let job_id = state
        .store
        .enqueue(
            QueueKind::OperatorAction,
            serde_json::to_value(payload).map_err(|e| internal_error(e.into()))?,
            Some(&dedupe_key),
        )
        .await
        .map_err(internal_error)?;
    if job_id == -1 {
        return Err((
            StatusCode::CONFLICT,
            "device already has a pending or running action".to_string(),
        ));
    }
    let job = state
        .store
        .get_job(job_id)
        .await
        .map_err(internal_error)?
        .ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "queued action not found".to_string(),
        ))?;
    let view = operator_action_view(job)?;
    Ok(with_journal_details(
        (StatusCode::ACCEPTED, Json(view)),
        Some(device.facts.ip),
        Some(serde_json::json!({"job_id": job_id, "action": action})),
    ))
}

async fn list_device_actions(
    State(state): State<DashboardState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Vec<OperatorActionView>>, ApiError> {
    let user = authenticate_request(&state, &headers).await?;
    if !user.can(Domain::Devices, AccessLevel::Write) {
        return Err((
            StatusCode::FORBIDDEN,
            "requires write access to devices".to_string(),
        ));
    }
    if state
        .devices
        .get_device(id)
        .await
        .map_err(internal_error)?
        .is_none()
    {
        return Err((StatusCode::NOT_FOUND, "no such device".to_string()));
    }
    let page = state
        .store
        .list_jobs(
            QueueKind::OperatorAction,
            &JobListQuery {
                search: Some(id.to_string()),
                limit: 20,
                ..JobListQuery::default()
            },
        )
        .await
        .map_err(internal_error)?;
    let mut views = Vec::new();
    for job in page.jobs {
        let mut view = operator_action_view(job)?;
        if view.device_id == id {
            // The history list is metadata only. Backup content is available through
            // the dedicated GET endpoint after its separate write-permission check.
            view.result = None;
            views.push(view);
        }
    }
    Ok(Json(views))
}

async fn get_device_action(
    State(state): State<DashboardState>,
    Path((id, job_id)): Path<(Uuid, i64)>,
    headers: HeaderMap,
) -> Result<axum::response::Response, ApiError> {
    let job = state
        .store
        .get_job(job_id)
        .await
        .map_err(internal_error)?
        .filter(|j| j.queue == QueueKind::OperatorAction)
        .ok_or((StatusCode::NOT_FOUND, "no such action".to_string()))?;
    let mut view = operator_action_view(job)?;
    if view.device_id != id {
        return Err((StatusCode::NOT_FOUND, "no such action".to_string()));
    }
    if view.action == OperatorAction::Backup {
        let user = authenticate_request(&state, &headers).await?;
        if !user.can(Domain::Devices, AccessLevel::Write) {
            return Err((
                StatusCode::FORBIDDEN,
                "requires write access to devices".to_string(),
            ));
        }
        if let Some(result) = &mut view.result {
            if let Some(encrypted) = result
                .get("configuration_encrypted")
                .and_then(|v| v.as_str())
            {
                let key = discovery_core::secret::SecretKey::from_env()
                    .map_err(|e| internal_error(e.into()))?;
                let plaintext = discovery_core::secret::decrypt_secret(&key, encrypted)
                    .map_err(|e| internal_error(e.into()))?;
                let bytes = plaintext.len();
                *result = serde_json::json!({"configuration": discovery_core::normalize_configuration(&plaintext), "bytes": bytes});
            }
        }
    }
    let mut response = Json(view).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}

#[derive(Serialize)]
struct BackupMetadata {
    job_id: i64,
    device_id: Uuid,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    bytes: u64,
}

fn backup_metadata(job: &discovery_core::Job, device_id: Uuid) -> Option<BackupMetadata> {
    let payload: OperatorActionPayload = serde_json::from_value(job.payload.clone()).ok()?;
    if payload.device_id != device_id || payload.action != OperatorAction::Backup || job.state != JobState::Done { return None; }
    let bytes = job.result.as_ref()?.get("bytes")?.as_u64()?;
    Some(BackupMetadata { job_id: job.id, device_id, created_at: job.created_at, updated_at: job.updated_at, bytes })
}

async fn load_backup_text(state: &DashboardState, device_id: Uuid, job_id: i64) -> Result<(BackupMetadata, String), ApiError> {
    let job = state.store.get_job(job_id).await.map_err(internal_error)?
        .filter(|job| job.queue == QueueKind::OperatorAction)
        .ok_or((StatusCode::NOT_FOUND, "no such backup".to_string()))?;
    let metadata = backup_metadata(&job, device_id)
        .ok_or((StatusCode::NOT_FOUND, "no such backup".to_string()))?;
    let encrypted = job.result.as_ref().and_then(|r| r.get("configuration_encrypted")).and_then(|v| v.as_str())
        .ok_or((StatusCode::NOT_FOUND, "backup content is unavailable".to_string()))?;
    let key = discovery_core::secret::SecretKey::from_env().map_err(|e| internal_error(e.into()))?;
    let plaintext = discovery_core::secret::decrypt_secret(&key, encrypted).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "backup content is unavailable".to_string()))?;
    Ok((metadata, plaintext))
}

async fn list_device_backups(State(state): State<DashboardState>, Path(device_id): Path<Uuid>, headers: HeaderMap) -> Result<Json<Vec<BackupMetadata>>, ApiError> {
    let user = authenticate_request(&state, &headers).await?;
    if !user.can(Domain::Devices, AccessLevel::Write) { return Err((StatusCode::FORBIDDEN, "requires write access to devices".to_string())); }
    if state.devices.get_device(device_id).await.map_err(internal_error)?.is_none() { return Err((StatusCode::NOT_FOUND, "no such device".to_string())); }
    let page = state.store.list_jobs(QueueKind::OperatorAction, &JobListQuery { search: Some(device_id.to_string()), limit: 500, ..Default::default() }).await.map_err(internal_error)?;
    Ok(Json(page.jobs.iter().filter_map(|job| backup_metadata(job, device_id)).collect()))
}

async fn download_device_backup(State(state): State<DashboardState>, Path((device_id, job_id)): Path<(Uuid, i64)>, headers: HeaderMap) -> Result<axum::response::Response, ApiError> {
    let user = authenticate_request(&state, &headers).await?;
    if !user.can(Domain::Devices, AccessLevel::Write) { return Err((StatusCode::FORBIDDEN, "requires write access to devices".to_string())); }
    let (metadata, plaintext) = load_backup_text(&state, device_id, job_id).await?;
    let body = serde_json::json!({"job_id": metadata.job_id, "device_id": metadata.device_id, "created_at": metadata.created_at, "bytes": plaintext.len(), "configuration": discovery_core::normalize_configuration(&plaintext)});
    let mut response = Json(body).into_response();
    response.headers_mut().insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
    response.headers_mut().insert(header::CONTENT_DISPOSITION, header::HeaderValue::from_static("attachment; filename=configuration.txt"));
    Ok(response)
}

async fn diff_device_backups(State(state): State<DashboardState>, Path((device_id, left, right)): Path<(Uuid, i64, i64)>, headers: HeaderMap) -> Result<Json<serde_json::Value>, ApiError> {
    let user = authenticate_request(&state, &headers).await?;
    if !user.can(Domain::Devices, AccessLevel::Write) { return Err((StatusCode::FORBIDDEN, "requires write access to devices".to_string())); }
    let (left_meta, left_text) = load_backup_text(&state, device_id, left).await?;
    let (right_meta, right_text) = load_backup_text(&state, device_id, right).await?;
    Ok(Json(serde_json::json!({"left": left_meta, "right": right_meta, "diff": discovery_core::unified_diff(&left_text, &right_text)})))
}

async fn cancel_device_action(
    State(state): State<DashboardState>,
    Path((id, job_id)): Path<(Uuid, i64)>,
) -> Result<axum::response::Response, ApiError> {
    let job = state
        .store
        .get_job(job_id)
        .await
        .map_err(internal_error)?
        .filter(|j| j.queue == QueueKind::OperatorAction)
        .ok_or((StatusCode::NOT_FOUND, "no such action".to_string()))?;
    let view = operator_action_view(job)?;
    if view.device_id != id {
        return Err((StatusCode::NOT_FOUND, "no such action".to_string()));
    }
    if !state
        .store
        .cancel_pending_action(job_id)
        .await
        .map_err(internal_error)?
    {
        return Err((
            StatusCode::CONFLICT,
            "only a pending action can be cancelled".to_string(),
        ));
    }
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        Some(id.to_string()),
        Some(serde_json::json!({"job_id": job_id, "action": view.action, "status": "cancelled"})),
    ))
}

/// Direct user request 2026-08-16: "возможность удаления устройства вовсе с каскадным
/// удалением истории и прочего связанного". `DeviceStore::delete` relies on
/// `ON DELETE CASCADE` for `device_metrics`/`device_metric_history`/
/// `device_metric_settings` — see its docs.
async fn delete_device(
    State(state): State<DashboardState>,
    Path(id): Path<Uuid>,
) -> Result<axum::response::Response, ApiError> {
    // Fetched *before* deleting purely to get the IP for `identity_chains.remove` below —
    // `active_chains`/`reachability_chains` are already keyed by `id`, which the path
    // param already gives us. See `ActiveChains::remove`'s docs for why this must happen:
    // without it, this IP could never start a fresh `SnmpPoll` identity chain again in
    // this process's lifetime, even after a different physical device takes it over. Also
    // doubles as the Журнал entry's `object` — the device is gone once `delete` returns,
    // so this is the only chance to record which IP was removed.
    let ip = state
        .devices
        .get_device(id)
        .await
        .map_err(internal_error)?
        .map(|d| d.facts.ip);
    state.alerts.remove_for_device(id);
    state.devices.delete(id).await.map_err(internal_error)?;
    if let Some(ip) = &ip {
        state.identity_chains.remove(ip);
    }
    state.active_chains.remove(&id);
    state.reachability_chains.remove(&id);
    Ok(with_journal_details(StatusCode::NO_CONTENT, ip, None))
}

#[derive(Deserialize)]
struct EnabledBody {
    enabled: bool,
}

/// Device-level master on/off switch — direct user request 2026-08-16: "мне нужна
/// возможность выключать устройства". Applies on the device's very next poll tick, no
/// restart — see `MetricPollHandler`/`ReachabilityPollHandler`'s `Device::enabled` docs.
async fn set_device_enabled(
    State(state): State<DashboardState>,
    Path(id): Path<Uuid>,
    Json(body): Json<EnabledBody>,
) -> Result<axum::response::Response, ApiError> {
    // Fetched *before* the write purely for the Журнал entry's `object`/old value — a
    // no-op toggle (already at `body.enabled`) still writes through `set_enabled`, but
    // `details` correctly shows `old == new` (well-formed, not misleadingly omitted).
    // TASK-20260921-020 (2026-09-22) — also now the existence check: `set_enabled`'s
    // `UPDATE ... WHERE device_id = ?` silently affects zero rows for an unknown id and
    // still returns `Ok(())`, so without this the endpoint reported `204` (success) for a
    // device that was never touched because it doesn't exist.
    let Some(before) = state.devices.get_device(id).await.map_err(internal_error)? else {
        return Err((StatusCode::NOT_FOUND, "no such device".to_string()));
    };
    state
        .devices
        .set_enabled(id, body.enabled)
        .await
        .map_err(internal_error)?;
    let details = serde_json::json!({"enabled": {"old": before.enabled, "new": body.enabled}});
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        Some(before.facts.ip),
        Some(details),
    ))
}

#[derive(Serialize)]
struct SetEnabledAllResponse {
    touched: u64,
}

/// "Выключить все" / "включить все" — the bulk companion of [`set_device_enabled`]. The
/// query filters select the same scope as the dashboard list; the final update is one
/// statement over the selected ids, not a loop of per-device calls.
async fn set_all_devices_enabled(
    State(state): State<DashboardState>,
    Query(params): Query<DevicesQuery>,
    Json(body): Json<EnabledBody>,
) -> Result<axum::response::Response, ApiError> {
    let profiles_by_name: HashMap<String, ProfileFile> = state
        .profiles
        .load_all()
        .await
        .map_err(internal_error)?
        .into_iter()
        .map(|p| (p.profile.name.clone(), p))
        .collect();
    let rows =
        discovery_devices::all_with_metrics(state.devices.as_ref(), state.device_metrics.as_ref())
            .await
            .map_err(internal_error)?;
    let mut views = build_device_views(rows, &profiles_by_name);
    let search = params
        .search
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase);
    let cidr = params
        .cidr
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    views.retain(|v| {
        let search_matches = search.as_deref().is_none_or(|needle| {
            v.device.facts.ip.to_lowercase().contains(needle)
                || v.device
                    .profile
                    .as_deref()
                    .map(|p| p.to_lowercase().contains(needle))
                    .unwrap_or(false)
                || v.metrics.iter().any(|m| {
                    m.record
                        .value
                        .as_ref()
                        .is_some_and(|value| metric_value_matches_search(value, needle))
                })
        });
        let profile_matches = params
            .profile
            .as_deref()
            .filter(|s| !s.is_empty())
            .is_none_or(|profile| v.device.profile.as_deref() == Some(profile));
        let cidr_matches = cidr.is_none_or(|network| ip_in_cidr(&v.device.facts.ip, network));
        let error_matches =
            params.has_error != Some(true) || v.metrics.iter().any(|m| m.record.error.is_some());
        search_matches && profile_matches && cidr_matches && error_matches
    });
    let ids: Vec<Uuid> = views.into_iter().map(|v| v.device.id).collect();
    let touched = state
        .devices
        .set_enabled_for_ids(&ids, body.enabled)
        .await
        .map_err(internal_error)?;
    let details = serde_json::json!({"enabled": body.enabled, "touched": touched});
    Ok(with_journal_details(
        Json(SetEnabledAllResponse { touched }),
        None,
        Some(details),
    ))
}

#[derive(Deserialize)]
struct SetSshCredentialsBody {
    username: String,
    auth: discovery_core::SshAuth,
    #[serde(default = "discovery_core::default_ssh_port")]
    port: u16,
}

/// Sets/replaces this device's SSH credentials — the dedicated `PUT` endpoint
/// `discovery_core::SshCredentials`'s docs call for (manual-entry-only: see there for why
/// there's no auto-negotiation path the way `snmp_auth` gets at `POST /api/devices`).
/// Unlike `snmp_auth`, which only exists on the manual-device-creation body, this works on
/// *any* existing device — the common case is a device that already arrived through the
/// normal discovery pipeline, which needs SSH credentials attached after the fact before
/// any `discovery_dsl::MetricSpec::SshCommand` metric its profile declares (config
/// backup/compliance, see `docs/Roadmap.md`) can ever be polled.
async fn set_ssh_credentials(
    State(state): State<DashboardState>,
    Path(id): Path<Uuid>,
    Json(body): Json<SetSshCredentialsBody>,
) -> Result<axum::response::Response, ApiError> {
    let before = state.devices.get_device(id).await.map_err(internal_error)?;
    if before.is_none() {
        return Err((StatusCode::NOT_FOUND, "no such device".to_string()));
    }
    // `known_host_key: None` — this endpoint never accepts a caller-supplied fingerprint
    // (see `discovery_core::SshCredentials::known_host_key`'s docs: manual pinning isn't
    // a thing this project does), so every credentials update resets the pin and the next
    // successful connection re-learns it via trust-on-first-use.
    // `username` trimmed, `auth` (password/private key) deliberately left byte-exact —
    // same asymmetry as `login`'s username/password split above.
    let credentials = discovery_core::SshCredentials {
        username: body.username.trim().to_string(),
        auth: body.auth,
        port: body.port,
        known_host_key: None,
    };
    state
        .devices
        .set_ssh_credentials(id, credentials)
        .await
        .map_err(internal_error)?;
    let Some(after) = state.devices.get_device(id).await.map_err(internal_error)? else {
        return Err(internal_error(anyhow::anyhow!(
            "device vanished immediately after updating SSH credentials"
        )));
    };
    let details = diff_details(before.as_ref(), &after);
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        Some(after.facts.ip.clone()),
        details,
    ))
}

#[derive(Deserialize)]
struct MetricNameParams {
    id: Uuid,
    name: String,
}

/// Sets an explicit per-device metric override — direct user request 2026-08-16: "за
/// определенными устройствами выключать временно метрики". The *only* place this ever
/// gets written outside an explicit sync action — see `DeviceStore::set_metric_override`'s
/// docs for the guarantee this preserves (never touched by automatic profile
/// (re)application).
async fn set_metric_override(
    State(state): State<DashboardState>,
    Path(params): Path<MetricNameParams>,
    Json(body): Json<EnabledBody>,
) -> Result<axum::response::Response, ApiError> {
    state
        .devices
        .set_metric_override(params.id, &params.name, body.enabled)
        .await
        .map_err(internal_error)?;
    let object = metric_override_object(&state, params.id, &params.name).await;
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        object,
        Some(serde_json::json!({"enabled": body.enabled})),
    ))
}

/// Clears one metric's override, reverting it to follow the profile's own default again.
async fn clear_metric_override(
    State(state): State<DashboardState>,
    Path(params): Path<MetricNameParams>,
) -> Result<axum::response::Response, ApiError> {
    state
        .devices
        .clear_metric_override(params.id, &params.name)
        .await
        .map_err(internal_error)?;
    let object = metric_override_object(&state, params.id, &params.name).await;
    Ok(with_journal_details(StatusCode::NO_CONTENT, object, None))
}

/// Journal `object` for a per-device metric override — "<ip> / <metric name>", e.g.
/// "10.1.2.3 / cpu_load". A best-effort lookup (device may already be gone in a race with
/// a concurrent delete) — `None` here just means the Журнал entry falls back to no
/// `object`, never a hard failure for what's otherwise already a successful write.
async fn metric_override_object(
    state: &DashboardState,
    device_id: Uuid,
    metric_name: &str,
) -> Option<String> {
    let ip = state
        .devices
        .get_device(device_id)
        .await
        .ok()
        .flatten()?
        .facts
        .ip;
    Some(format!("{ip} / {metric_name}"))
}

/// Device-scoped "sync with profile" — direct user request 2026-08-16: "на устройстве —
/// синхронизироваться с профилем ... включил или выключит опрос метрики". Clears (not
/// overwrites, see `DeviceStore::clear_metric_overrides`'s docs for why) every override
/// for metric names the device's *current* profile actually declares — a no-op if the
/// device has no profile right now.
async fn sync_device_metrics_with_profile(
    State(state): State<DashboardState>,
    Path(id): Path<Uuid>,
) -> Result<axum::response::Response, ApiError> {
    let Some(device) = state.devices.get_device(id).await.map_err(internal_error)? else {
        return Err((StatusCode::NOT_FOUND, "device not found".to_string()));
    };
    let ip = device.facts.ip.clone();
    let Some(profile_name) = device.profile else {
        return Ok(with_journal_details(StatusCode::NO_CONTENT, Some(ip), None));
        // no profile — nothing to sync against
    };
    let names = metric_names_of_profile(&state, &profile_name).await?;
    state
        .devices
        .clear_metric_overrides(id, &names)
        .await
        .map_err(internal_error)?;
    Ok(with_journal_details(StatusCode::NO_CONTENT, Some(ip), None))
}

#[derive(Serialize)]
struct SyncProfileDevicesResponse {
    devices_synced: usize,
}

/// Profile-scoped "sync devices" — direct user request 2026-08-16: "кнопка синхронизации
/// устройств с профилем в профиле — включить или выключить метрики согласно профилю".
/// Same underlying operation as [`sync_device_metrics_with_profile`], applied to every
/// device currently on this profile in one request.
async fn sync_profile_devices_metrics(
    State(state): State<DashboardState>,
    Path(name): Path<String>,
) -> Result<axum::response::Response, ApiError> {
    let names = metric_names_of_profile(&state, &name).await?;
    // Was `devices.all()` (whole fleet, every column) filtered by profile in Rust, then a
    // sequential per-device `clear_metric_overrides` loop — found on the 2026-08-21 scale
    // audit as an N+1 that would time out a single HTTP request at a large device count. Now
    // a DB-level filtered id projection plus one batched clear.
    let ids = state
        .devices
        .device_ids_by_profile(&name)
        .await
        .map_err(internal_error)?;
    let devices_synced = ids.len();
    state
        .devices
        .clear_metric_overrides_for_devices(&ids, &names)
        .await
        .map_err(internal_error)?;
    Ok(with_journal_details(
        Json(SyncProfileDevicesResponse { devices_synced }),
        Some(name),
        Some(serde_json::json!({"devices_synced": devices_synced})),
    ))
}

async fn metric_names_of_profile(
    state: &DashboardState,
    profile_name: &str,
) -> Result<Vec<String>, ApiError> {
    let profiles = state.profiles.load_all().await.map_err(internal_error)?;
    Ok(profiles
        .into_iter()
        .find(|p| p.profile.name == profile_name)
        .map(|p| p.metrics.poll.into_keys().collect())
        .unwrap_or_default())
}

#[derive(Deserialize)]
struct MetricHistoryParams {
    id: Uuid,
    name: String,
}

#[derive(Deserialize)]
struct MetricHistoryQuery {
    page: Option<u32>,
    page_size: Option<u32>,
    /// See `DeviceStore::metric_history`'s docs — filters on `last_observed_at`, same
    /// one-sided-optional-bounds contract as `AlertListQuery::since`/`until`.
    since: Option<chrono::DateTime<chrono::Utc>>,
    until: Option<chrono::DateTime<chrono::Utc>>,
}

/// The dashboard's metric-history view — added 2026-08-17, direct user request: click a
/// metric in the devices table's metrics sub-table, see its change history. Thin wrapper
/// over `DeviceStore::metric_history`; see its docs for the "state run" model and pagination
/// contract.
async fn metric_history(
    State(state): State<DashboardState>,
    Path(params): Path<MetricHistoryParams>,
    Query(query): Query<MetricHistoryQuery>,
) -> Result<Json<MetricHistoryPage>, ApiError> {
    let page_size = query.page_size.unwrap_or(50).clamp(1, 500) as i64;
    let page_num = query.page.unwrap_or(1).max(1) as i64;
    let offset = (page_num - 1) * page_size;
    let result = state
        .device_metrics
        .metric_history(
            params.id,
            &params.name,
            page_size,
            offset,
            query.since,
            query.until,
        )
        .await
        .map_err(internal_error)?;
    Ok(Json(result))
}

#[derive(Deserialize)]
struct ProfilesQuery {
    /// Free-text, case-insensitive, matched against the profile's name or any of its
    /// declared metric names (`metrics.poll` keys) — e.g. searching "cpu_load" finds every
    /// profile that polls a metric by that name, not just one literally named that.
    search: Option<String>,
    /// "name" (default) | "priority".
    sort_by: Option<String>,
    /// "asc" (default) | "desc".
    sort_dir: Option<String>,
    page: Option<u32>,
    page_size: Option<u32>,
}

#[derive(Serialize)]
struct ProfilesPage {
    items: Vec<ProfileFile>,
    total: usize,
}

/// Search/sort/paginate the profile list — added 2026-08-18 during a REST-completeness
/// pass (direct user request: "REST должен полностью позволять работать с приложением,
/// без UI... Изменение - добавление, удаление, чтение (включая пагинацию, фильтрацию,
/// сортировку, поиск). Все это должно быть."). Before this, `GET /api/profiles` was a
/// bare unfiltered `Vec` — every *other* list endpoint in this API (devices/alerts/
/// queue-jobs/logs) already had this pass, profiles and discovery-configs were the two
/// left over. Filtered/sorted/paged in Rust over `load_all()`'s full result, not pushed
/// into SQL — same "small, bounded collection" reasoning `devices()` documents, applies
/// even more so here (a profile set numbers in the tens, not the thousands).
///
/// **Response shape changed from a bare `Vec<ProfileFile>` to `{items, total}`** to match
/// every other paginated endpoint's contract — the dashboard's own `loadProfiles()` was
/// updated to read `.items` (and requests a page size large enough to always get
/// everything, since the profiles page still renders all of them as cards, not paged UI).
async fn list_profiles(
    State(state): State<DashboardState>,
    Query(params): Query<ProfilesQuery>,
) -> Result<Json<ProfilesPage>, ApiError> {
    let mut items = state.profiles.load_all().await.map_err(internal_error)?;

    if let Some(needle) = params
        .search
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase)
    {
        items.retain(|p| {
            p.profile.name.to_lowercase().contains(&needle)
                || p.metrics
                    .poll
                    .keys()
                    .any(|name| name.to_lowercase().contains(&needle))
        });
    }

    let desc = params.sort_dir.as_deref() == Some("desc");
    match params.sort_by.as_deref() {
        Some("priority") => items.sort_by(|a, b| a.profile.priority.cmp(&b.profile.priority)),
        _ => items.sort_by(|a, b| a.profile.name.cmp(&b.profile.name)),
    }
    if desc {
        items.reverse();
    }

    let total = items.len();
    let page_size = params.page_size.unwrap_or(50).clamp(1, 500) as usize;
    let page = params.page.unwrap_or(1).max(1) as usize;
    let items = items
        .into_iter()
        .skip((page - 1) * page_size)
        .take(page_size)
        .collect();

    Ok(Json(ProfilesPage { items, total }))
}

/// Single-profile read — added 2026-08-18, same REST-completeness pass as [`list_profiles`]
/// above. `ProfileStore` has no dedicated single-name fetch method (only `load_all`); same
/// "fetch-all, filter in Rust" precedent as [`get_device_by_id`] — a bounded profile set
/// makes a dedicated store method not worth it just for this.
async fn get_profile(
    State(state): State<DashboardState>,
    Path(name): Path<String>,
) -> Result<Json<ProfileFile>, ApiError> {
    match state
        .profiles
        .load_all()
        .await
        .map_err(internal_error)?
        .into_iter()
        .find(|p| p.profile.name == name)
    {
        Some(profile) => Ok(Json(profile)),
        None => Err((StatusCode::NOT_FOUND, "no such profile".to_string())),
    }
}

fn validate_ssh_profile_access(
    profile: &ProfileFile,
    user: &AuthenticatedUser,
) -> Result<(), ApiError> {
    let ssh_metrics: Vec<(&str, &str)> = profile
        .metrics
        .poll
        .iter()
        .filter_map(|(name, metric)| metric.command().map(|command| (name.as_str(), command)))
        .collect();
    if ssh_metrics.is_empty() {
        return Ok(());
    }
    if !user.can(Domain::Devices, AccessLevel::Write) {
        return Err((StatusCode::FORBIDDEN, "Profiles: Write is insufficient for SSH metric execution; Devices: Write is also required".to_string()));
    }
    for (name, command) in ssh_metrics {
        let trimmed = command.trim();
        let first_word = trimmed
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if trimmed.is_empty()
            || trimmed.len() > 256
            || trimmed.chars().any(|c| {
                matches!(
                    c,
                    '\0' | '\n' | '\r' | ';' | '|' | '&' | '$' | '`' | '>' | '<'
                )
            })
        {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("metrics.poll.{name}: SSH command contains disallowed shell syntax"),
            ));
        }
        if !matches!(
            first_word.as_str(),
            "show" | "display" | "get" | "list" | "status" | "ip" | "interface"
        ) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "metrics.poll.{name}: SSH command must start with a read-only allowlisted verb"
                ),
            ));
        }
    }
    Ok(())
}

/// Direct user request 2026-08-18: "изменить профиль за устройством сразу и при этом
/// сразу оно начнёт опрашиваться по новым правилам" — reconfiguration no longer waits on
/// `profile_reload`'s own polling interval (up to `profiles_reload_secs`). Safety of an
/// immediate switch (a device's already-in-flight `MetricPoll` chain under the *old*
/// profile can't accidentally poll a metric the new version removed) comes from the
/// existing `poll_generation` guard, not from anything added here — see
/// `discovery_agent::handlers::MetricPollHandler`'s docs: a stale-generation job bails
/// before it ever looks at what profile is current, so it structurally cannot happen.
/// `before` fetched purely for the Журнал `details` diff — same reasoning as
/// `upsert_discovery_config`'s docs.
async fn upsert_profile(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Json(mut profile): Json<ProfileFile>,
) -> Result<axum::response::Response, ApiError> {
    let user = authenticate_request(&state, &headers).await?;
    // Audit finding 5 (2026-09-20): trimmed before the uniqueness lookup below — an
    // accidental trailing space/newline from copy-paste would otherwise silently create a
    // second, visually-identical profile instead of editing the intended one.
    profile.profile.name = profile.profile.name.trim().to_string();
    // Catches trap-binding authoring mistakes at save time — see `TrapsSection::validate`'s
    // docs — rather than letting them fail silently once live traffic hits the ingestion
    // layer.
    profile
        .traps
        .validate()
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    // Same reasoning for syslog bindings — see `SyslogSection::validate`'s docs.
    profile
        .syslog
        .validate()
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    // Same reasoning for a `derive`d metric colliding with another declared metric's name
    // — see `MetricsSection::validate`'s docs.
    profile
        .metrics
        .validate()
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    validate_ssh_profile_access(&profile, &user)?;
    // Rhai syntax-validated at save time (2026-09-17, audit finding #3 — see
    // `ProfileMatcher::validate_expression`'s docs) — `match.expression` is the one piece
    // of Rhai every profile has, and until this existed a typo here saved with a green
    // "Профиль сохранён" toast and only ever surfaced later as an opaque, unrelated-looking
    // `WARN "job failed"` on the `dedup` queue.
    state
        .matcher
        .validate_expression(&profile.match_expr.expression)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("match.expression: {e}")))?;
    // Same treatment for every alert rule's own Rhai expressions — see
    // `AlertEvaluator::validate_expression`'s docs.
    let existing = state.profiles.load_all().await.map_err(internal_error)?;
    let before = existing
        .iter()
        .find(|p| p.profile.name == profile.profile.name)
        .cloned();
    if let Some(profile) = &before {
        alert_rules::require_profile_rule_access(&state, profile, &user)?;
    }
    let alert_evaluator = discovery_dsl::AlertEvaluator::new();
    for rule in &profile.alerts {
        alert_rules::validate_authoring(rule, &user)?;
        let before_policy = before
            .as_ref()
            .and_then(|p| p.alerts.iter().find(|r| r.name == rule.name))
            .map(|r| &r.policy);
        if !user.is_admin
            && (before_policy.is_none_or(|p| {
                p.viewer_roles != rule.policy.viewer_roles
                    || p.operator_roles != rule.policy.operator_roles
            }) && (!rule.policy.viewer_roles.is_empty()
                || !rule.policy.operator_roles.is_empty()
                || before_policy
                    .is_some_and(|p| !p.viewer_roles.is_empty() || !p.operator_roles.is_empty())))
        {
            return Err((
                StatusCode::FORBIDDEN,
                "rule permissions require an administrator".into(),
            ));
        }
        if let Some(policy) = before_policy {
            if !alert_rules::permits(policy, &user, true) {
                return Err((StatusCode::FORBIDDEN, "alert rule access denied".into()));
            }
        }
        if let Some(name) = &rule.policy.shared_rule {
            let shared: discovery_dsl::AlertRule =
                serde_json::from_value(state.alerts.shared_rule(name).ok_or((
                    StatusCode::BAD_REQUEST,
                    format!("shared rule '{name}' does not exist"),
                ))?)
                .map_err(|e| internal_error(e.into()))?;
            if !alert_rules::permits(&shared.policy, &user, true) {
                return Err((StatusCode::FORBIDDEN, "shared rule access denied".into()));
            }
            alert_rules::validate_authoring(&shared, &user)?;
        }
        alert_evaluator
            .validate_expression(&rule.expression)
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("alerts[\"{}\"].expression: {e}", rule.name),
                )
            })?;
        if let Some(expr) = &rule.deactivation_expression {
            alert_evaluator.validate_expression(expr).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("alerts[\"{}\"].deactivation_expression: {e}", rule.name),
                )
            })?;
        }
        if let Some(expr) = &rule.facts_expression {
            alert_evaluator.validate_expression(expr).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("alerts[\"{}\"].facts_expression: {e}", rule.name),
                )
            })?;
        }
        if let Some(expr) = &rule.row_key_expression {
            alert_evaluator.validate_expression(expr).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("alerts[\"{}\"].row_key_expression: {e}", rule.name),
                )
            })?;
        }
    }
    state
        .profiles
        .upsert(&profile)
        .await
        .map_err(internal_error)?;
    if let Err(e) = reload_matcher_and_nudge_devices(
        &state.profiles,
        &state.matcher,
        &state.devices,
        &state.store,
    )
    .await
    {
        warn!(error = %e, "profile saved, but immediate reload/nudge failed — the periodic profile_reload loop will still pick it up");
    }
    let details = diff_details(before.as_ref(), &profile);
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        Some(profile.profile.name.clone()),
        details,
    ))
}

async fn delete_profile(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<axum::response::Response, ApiError> {
    let user = authenticate_request(&state, &headers).await?;
    if let Some(profile) = state.matcher.profile_by_name(&name).await {
        alert_rules::require_profile_rule_access(&state, &profile, &user)?;
    }
    state.profiles.delete(&name).await.map_err(internal_error)?;
    if let Err(e) = reload_matcher_and_nudge_devices(
        &state.profiles,
        &state.matcher,
        &state.devices,
        &state.store,
    )
    .await
    {
        warn!(error = %e, "profile deleted, but immediate reload/nudge failed — the periodic profile_reload loop will still pick it up");
    }
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        Some(name),
        None,
    ))
}

#[derive(Deserialize)]
struct DiscoveryConfigsQuery {
    /// Free-text, case-insensitive, matched against the config's name and its subnets'
    /// `ip`/`mask`/label values — direct user request 2026-08-28: "Поиск читает подсети и
    /// название и ищет по ним."
    search: Option<String>,
    /// Exact match on `enabled` — "true" | "false".
    enabled: Option<bool>,
    /// "name" (default) | "enabled".
    sort_by: Option<String>,
    /// "asc" (default) | "desc".
    sort_dir: Option<String>,
    page: Option<u32>,
    page_size: Option<u32>,
}

#[derive(Serialize)]
struct DiscoveryConfigsPage {
    items: Vec<DiscoveryConfig>,
    total: usize,
}

/// Search/filter/sort/paginate the discovery-config list — same REST-completeness pass
/// and reasoning as [`list_profiles`] above (this was the other bare-`Vec` list endpoint
/// left over). Response shape likewise changed to `{items, total}` — the dashboard's
/// `loadDiscoveryConfigs()` was updated to match.
async fn list_discovery_configs(
    State(state): State<DashboardState>,
    Query(params): Query<DiscoveryConfigsQuery>,
) -> Result<Json<DiscoveryConfigsPage>, ApiError> {
    let mut items = state
        .discovery_configs
        .load_all()
        .await
        .map_err(internal_error)?;

    if let Some(needle) = params
        .search
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase)
    {
        items.retain(|c| {
            c.name.to_lowercase().contains(&needle)
                || c.subnets.iter().any(|s| {
                    s.ip.to_lowercase().contains(&needle)
                        || s.mask.to_lowercase().contains(&needle)
                        || s.labels
                            .values()
                            .any(|v| v.to_lowercase().contains(&needle))
                })
        });
    }
    if let Some(enabled) = params.enabled {
        items.retain(|c| c.enabled == enabled);
    }

    let desc = params.sort_dir.as_deref() == Some("desc");
    match params.sort_by.as_deref() {
        Some("enabled") => items.sort_by(|a, b| a.enabled.cmp(&b.enabled)),
        _ => items.sort_by(|a, b| a.name.cmp(&b.name)),
    }
    if desc {
        items.reverse();
    }

    let total = items.len();
    let page_size = params.page_size.unwrap_or(50).clamp(1, 500) as usize;
    let page = params.page.unwrap_or(1).max(1) as usize;
    let items = items
        .into_iter()
        .skip((page - 1) * page_size)
        .take(page_size)
        .collect();

    Ok(Json(DiscoveryConfigsPage { items, total }))
}

/// Single-config read — added 2026-08-18, same REST-completeness pass as [`get_profile`].
async fn get_discovery_config(
    State(state): State<DashboardState>,
    Path(name): Path<String>,
) -> Result<Json<DiscoveryConfig>, ApiError> {
    match state
        .discovery_configs
        .load_all()
        .await
        .map_err(internal_error)?
        .into_iter()
        .find(|c| c.name == name)
    {
        Some(config) => Ok(Json(config)),
        None => Err((
            StatusCode::NOT_FOUND,
            "no such discovery config".to_string(),
        )),
    }
}

/// RFC 3414's minimum USM passphrase length — `async-snmp`'s `UsmConfig::auth`/`auth_priv`
/// enforce this too (rejected at connect time), but the REST boundary is where an operator
/// actually finds out, not a background poll's error log.
const MIN_SNMP_V3_PASSPHRASE_LEN: usize = 8;

/// Rejects an invalid `SnmpAuth::UsmV3` before it ever reaches a store: a passphrase
/// shorter than RFC 3414's 8-octet minimum, or `priv_` set without `auth` (privNoAuth,
/// not a real SNMPv3 security level — see `discovery_core::SnmpV3Credentials`'s docs).
/// `Community` entries have nothing to validate here (a blank community string is a
/// config-time choice, not a protocol violation).
fn validate_subnet_credentials(
    subnets: &[discovery_config_store::SubnetSpec],
) -> Result<(), ApiError> {
    for subnet in subnets {
        for auth in &subnet.credentials {
            let SnmpAuth::UsmV3(creds) = auth else {
                continue;
            };
            if creds.priv_.is_some() && creds.auth.is_none() {
                return Err((StatusCode::BAD_REQUEST, format!("SNMPv3 user '{}': privacy without authentication (privNoAuth) is not a valid security level", creds.user)));
            }
            if let Some(a) = &creds.auth {
                if a.passphrase.len() < MIN_SNMP_V3_PASSPHRASE_LEN {
                    return Err((StatusCode::BAD_REQUEST, format!("SNMPv3 user '{}': auth passphrase must be at least {MIN_SNMP_V3_PASSPHRASE_LEN} characters", creds.user)));
                }
            }
            if let Some(p) = &creds.priv_ {
                if p.passphrase.len() < MIN_SNMP_V3_PASSPHRASE_LEN {
                    return Err((StatusCode::BAD_REQUEST, format!("SNMPv3 user '{}': priv passphrase must be at least {MIN_SNMP_V3_PASSPHRASE_LEN} characters", creds.user)));
                }
            }
        }
    }
    Ok(())
}

/// `before` is fetched *before* the write purely for the Журнал entry's `details` diff
/// (direct user follow-up request: "при создании и редактировании дискаверинга показывать
/// что за дискаверинг и что было отредактировано... сравнить с до изменений и после") —
/// `None` on a genuine create (no config with this name existed yet), so
/// [`diff_details`] naturally yields no diff for that case, only `object` (the name).
async fn upsert_discovery_config(
    State(state): State<DashboardState>,
    Json(mut config): Json<DiscoveryConfig>,
) -> Result<axum::response::Response, ApiError> {
    // Audit finding 5 (2026-09-20) — same reasoning as `upsert_profile`'s name trim above,
    // plus SNMP community strings/USM usernames (`SnmpAuth::trim_identifiers`'s docs).
    config.name = config.name.trim().to_string();
    for subnet in &mut config.subnets {
        for cred in &mut subnet.credentials {
            cred.trim_identifiers();
        }
    }
    validate_subnet_credentials(&config.subnets)?;
    let existing = state
        .discovery_configs
        .load_all()
        .await
        .map_err(internal_error)?;
    let before = existing.iter().find(|c| c.name == config.name).cloned();
    state
        .discovery_configs
        .upsert(&config)
        .await
        .map_err(internal_error)?;
    let details = diff_details(before.as_ref(), &config);
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        Some(config.name.clone()),
        details,
    ))
}

async fn delete_discovery_config(
    State(state): State<DashboardState>,
    Path(name): Path<String>,
) -> Result<axum::response::Response, ApiError> {
    state
        .discovery_configs
        .delete(&name)
        .await
        .map_err(internal_error)?;
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        Some(name),
        None,
    ))
}

// ---- Maintenance windows (2026-09-07) ----
//
// Full CRUD, gated by `Domain::MaintenanceWindows` — see
// `discovery_config_store::MaintenanceWindow`'s docs for the selector semantics and
// `discovery_agent::handlers::AlertEvalHandler` for the actual suppression enforcement
// this store feeds (this crate only manages/reads the config, it never evaluates it).

async fn list_maintenance_windows(
    State(state): State<DashboardState>,
) -> Result<Json<Vec<MaintenanceWindow>>, ApiError> {
    Ok(Json(
        state
            .maintenance_windows
            .list_all()
            .await
            .map_err(internal_error)?,
    ))
}

async fn get_maintenance_window(
    State(state): State<DashboardState>,
    Path(id): Path<Uuid>,
) -> Result<Json<MaintenanceWindow>, ApiError> {
    match state
        .maintenance_windows
        .get(id)
        .await
        .map_err(internal_error)?
    {
        Some(window) => Ok(Json(window)),
        None => Err((
            StatusCode::NOT_FOUND,
            "no such maintenance window".to_string(),
        )),
    }
}

/// `id: None` on create (a fresh id is generated server-side, same "server owns identity
/// generation" convention `create_device`/`resolve` already follow) — `Some(id)` edits
/// that window in place, same "id decides create vs edit" contract
/// `MaintenanceWindowStore::upsert` itself documents.
#[derive(Deserialize)]
struct MaintenanceWindowBody {
    #[serde(default)]
    id: Option<Uuid>,
    name: String,
    enabled: bool,
    starts_at: chrono::DateTime<chrono::Utc>,
    ends_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    subnets: Vec<SubnetTarget>,
    #[serde(default)]
    profiles: Vec<String>,
    #[serde(default)]
    device_ids: Vec<Uuid>,
}

/// Create-or-edit — see [`MaintenanceWindowBody::id`]'s docs. `before` is fetched *before*
/// the write purely for the Журнал entry's `details` diff, same convention
/// `upsert_discovery_config` uses right above.
async fn upsert_maintenance_window(
    State(state): State<DashboardState>,
    Json(body): Json<MaintenanceWindowBody>,
) -> Result<axum::response::Response, ApiError> {
    let name_trimmed = body.name.trim();
    if name_trimmed.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "name must not be empty".to_string(),
        ));
    }
    if body.ends_at < body.starts_at {
        return Err((
            StatusCode::BAD_REQUEST,
            "ends_at must not be before starts_at".to_string(),
        ));
    }
    if let Some((i, e)) = body
        .subnets
        .iter()
        .enumerate()
        .find_map(|(i, s)| s.validate().err().map(|e| (i, e)))
    {
        return Err((StatusCode::BAD_REQUEST, format!("subnets[{i}]: {e}")));
    }

    let id = body.id.unwrap_or_else(Uuid::new_v4);
    let before = state
        .maintenance_windows
        .get(id)
        .await
        .map_err(internal_error)?;
    let window = MaintenanceWindow {
        id,
        name: name_trimmed.to_string(),
        enabled: body.enabled,
        starts_at: body.starts_at,
        ends_at: body.ends_at,
        subnets: body.subnets,
        profiles: body.profiles,
        device_ids: body.device_ids,
    };
    state
        .maintenance_windows
        .upsert(&window)
        .await
        .map_err(internal_error)?;
    let details = diff_details(before.as_ref(), &window);
    Ok(with_journal_details(
        Json(window),
        Some(id.to_string()),
        details,
    ))
}

async fn delete_maintenance_window(
    State(state): State<DashboardState>,
    Path(id): Path<Uuid>,
) -> Result<axum::response::Response, ApiError> {
    state
        .maintenance_windows
        .delete(id)
        .await
        .map_err(internal_error)?;
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        Some(id.to_string()),
        None,
    ))
}

// -----------------------------------------------------------------------------------------
// Notification channels + matrix (2026-09-10) — direct user request "Реализуй каналы
// нотификации + матрицу нотификации". See `discovery_core::NotificationChannel`/
// `discovery_config_store::NotificationRule`'s docs for the model.
// -----------------------------------------------------------------------------------------

/// `id: None` on create, same "server owns identity generation" convention as
/// `MaintenanceWindowBody`. `secret` is webhook-only (see `NotificationChannel::secret`'s
/// docs) but accepted regardless of `kind` without complaint — a value set on an
/// `Email`/`Telegram` channel is simply never read by `discovery-notify`, not worth a
/// validation error over.
#[derive(Deserialize)]
struct NotificationChannelBody {
    #[serde(default)]
    id: Option<Uuid>,
    kind: NotificationChannelKind,
    target: String,
    #[serde(default)]
    secret: Option<String>,
    enabled: bool,
}

/// Blanks a webhook channel's signing `secret` value before it reaches a GET response,
/// preserving only *whether* one is configured (`Some("")` vs `None`) — same audit finding
/// #5 leak class as `redact_ssh_credentials` (2026-09-17, see that function's docs and
/// `docs/Changelog/2026-09-17 - Аудит глазами оператора...md`): before this,
/// `list_my_notification_channels`/`list_user_notification_channels` returned
/// `NotificationChannelStore::list_for_user`'s already-decrypted `NotificationChannel` as-is
/// — the real webhook signing secret was visible in plaintext on every ordinary channel-list
/// fetch. Never applied to `upsert_notification_channel_for`'s own response (echoing back
/// exactly what the caller just submitted in the same request isn't a new disclosure).
///
/// Because this makes the value genuinely unrecoverable from a GET, saving an edited
/// channel with a blank `secret` field no longer means "clear it" the way it used to —
/// see `upsert_notification_channel_for`'s docs for the matching write-side change that
/// keeps a channel's existing secret when the field comes back blank, rather than silently
/// wiping it on every unrelated edit (e.g. toggling `enabled`).
fn redact_notification_channel(mut c: NotificationChannel) -> NotificationChannel {
    if c.secret.is_some() {
        c.secret = Some(String::new());
    }
    c
}

async fn list_my_notification_channels(
    State(state): State<DashboardState>,
    headers: HeaderMap,
) -> Result<Json<Vec<NotificationChannel>>, ApiError> {
    let user = authenticate_request(&state, &headers).await?;
    let channels = state
        .notification_channels
        .list_for_user(user.id)
        .await
        .map_err(internal_error)?;
    Ok(Json(
        channels
            .into_iter()
            .map(redact_notification_channel)
            .collect(),
    ))
}

async fn upsert_my_notification_channel(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Json(body): Json<NotificationChannelBody>,
) -> Result<axum::response::Response, ApiError> {
    let user = authenticate_request(&state, &headers).await?;
    upsert_notification_channel_for(&state, user.id, body).await
}

async fn delete_my_notification_channel(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<axum::response::Response, ApiError> {
    let user = authenticate_request(&state, &headers).await?;
    delete_notification_channel_owned_by(&state, user.id, id).await
}

/// Admin-on-behalf-of variants of the three handlers above — `user_id` comes from the path,
/// not the caller's own session, so an admin can manage another user's channels for
/// support purposes. Both sides funnel through the same two shared functions below, so
/// "who owns this channel" is enforced identically either way.
async fn list_user_notification_channels(
    State(state): State<DashboardState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<Vec<NotificationChannel>>, ApiError> {
    let channels = state
        .notification_channels
        .list_for_user(user_id)
        .await
        .map_err(internal_error)?;
    Ok(Json(
        channels
            .into_iter()
            .map(redact_notification_channel)
            .collect(),
    ))
}

async fn upsert_user_notification_channel(
    State(state): State<DashboardState>,
    Path(user_id): Path<Uuid>,
    Json(body): Json<NotificationChannelBody>,
) -> Result<axum::response::Response, ApiError> {
    upsert_notification_channel_for(&state, user_id, body).await
}

async fn delete_user_notification_channel(
    State(state): State<DashboardState>,
    Path((user_id, id)): Path<(Uuid, Uuid)>,
) -> Result<axum::response::Response, ApiError> {
    delete_notification_channel_owned_by(&state, user_id, id).await
}

/// SSRF guard (CWE-918, 2026-09-17 audit finding #2) for a webhook channel's `target`.
/// Self-service notification channels are deliberately **not** behind `domain_guard!` (see
/// `upsert_my_notification_channel`'s docs above — same tier as `PUT /api/auth/password`),
/// so any logged-in user, regardless of domain grants, can create one and add themselves as
/// a recipient of some notification rule. Before this check, `target` was validated only for
/// non-emptiness: pointing a webhook channel at `http://169.254.169.254/latest/meta-data/...`
/// (cloud metadata) or any other loopback/private-range/link-local service was accepted
/// as-is, and `discovery-notify`'s `RealNotifier::send_webhook` would then issue a real HTTP
/// request there — on the agent's network position, not the attacker's — every time a rule
/// they're a recipient of fires. Fixing this with `domain_guard!` instead was the other
/// option the finding named, but would silently break the intentional self-service design
/// this whole module already documents in several places, so `target` validation is the
/// right layer.
///
/// Deliberately does **not** resolve DNS names — only rejects a literal IP-address host (or
/// the well-known `localhost` name) that falls in a forbidden range, plus any non-`http(s)`
/// scheme. A domain name that itself resolves to a private address at delivery time (DNS
/// rebinding) is a separate, TOCTOU-shaped problem that would require re-validating at
/// connect time inside `discovery-notify`, not at this write-time check — out of scope for
/// this fix, same boundary the roadmap entry itself draws, and it keeps this check (and the
/// tests around it) free of any real network access, matching this crate's existing
/// `tower::ServiceExt::oneshot`-only router tests.
fn validate_webhook_target(target: &str) -> Result<(), ApiError> {
    let bad_target = |msg: String| (StatusCode::BAD_REQUEST, msg);
    let url = url::Url::parse(target)
        .map_err(|e| bad_target(format!("webhook target must be a valid URL: {e}")))?;
    match url.scheme() {
        "http" | "https" => {}
        other => {
            return Err(bad_target(format!(
                "webhook target must use http or https, not '{other}'"
            )))
        }
    }
    match url.host() {
        // `localhost.` (trailing dot — valid FQDN syntax every resolver treats as identical
        // to the bare name, no DNS lookup involved) would otherwise slip past as an ordinary
        // `Domain` host.
        Some(url::Host::Domain(domain)) if domain.trim_end_matches('.').eq_ignore_ascii_case("localhost") => {
            Err(bad_target("webhook target must not point at localhost".to_string()))
        }
        Some(url::Host::Ipv4(ip)) if is_forbidden_webhook_ip(IpAddr::V4(ip)) => {
            Err(bad_target(format!("webhook target must not point at a private, loopback, or link-local address ({ip})")))
        }
        Some(url::Host::Ipv6(ip)) if is_forbidden_webhook_ip(IpAddr::V6(ip)) => {
            Err(bad_target(format!("webhook target must not point at a private, loopback, or link-local address ({ip})")))
        }
        Some(_) => Ok(()),
        None => Err(bad_target("webhook target must have a host".to_string())),
    }
}

/// IPv4-embedded IPv6 addresses are checked as their IPv4 form too, in addition to (not
/// instead of) the native IPv6 checks below — `to_ipv4()` unwraps both the modern
/// IPv4-mapped notation (`::ffff:a.b.c.d`) and the legacy IPv4-compatible one (`::a.b.c.d`,
/// still accepted by `url::Url::parse`), so e.g. `http://[::169.254.169.254]/` (cloud
/// metadata via the legacy form — `to_ipv4_mapped()` alone misses it, only handles the
/// `::ffff:` prefix) is caught the same as the `::ffff:`-prefixed form. Kept alongside the
/// native checks, not as a replacement for them, because `to_ipv4()` maps `::1` to
/// `0.0.0.1` (not `127.0.0.1`) — relying on it alone would let IPv6 loopback slip through.
fn is_forbidden_webhook_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_forbidden_webhook_ipv4(v4),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 — unique local (RFC 4193)
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 — link-local
                || v6.to_ipv4().is_some_and(is_forbidden_webhook_ipv4)
        }
    }
}

fn is_forbidden_webhook_ipv4(v4: std::net::Ipv4Addr) -> bool {
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_multicast()
        || v4.is_broadcast()
        || is_cgnat_shared_address_space(v4)
}

/// `100.64.0.0/10` (RFC 6598) — carrier-grade NAT shared address space, notably where cloud
/// providers other than AWS/GCP/Azure (e.g. Alibaba Cloud's `100.100.100.200`) put their
/// instance-metadata endpoint. `Ipv4Addr::is_shared()` already covers this exact range but
/// is nightly-only (the unstable `ip` feature), so checked by hand instead.
fn is_cgnat_shared_address_space(v4: std::net::Ipv4Addr) -> bool {
    let [a, b, ..] = v4.octets();
    a == 100 && (64..=127).contains(&b)
}

/// Shared by both the self-service and admin-on-behalf-of upsert handlers. Rejects editing
/// (not creating) a channel that belongs to a *different* user than `owner_id` — for the
/// self-service caller this is the real security boundary ("can I touch someone else's
/// channel"); for the admin path it catches a `user_id`/`id` mismatch in the URL instead of
/// silently reassigning the channel to a different owner.
async fn upsert_notification_channel_for(
    state: &DashboardState,
    owner_id: Uuid,
    body: NotificationChannelBody,
) -> Result<axum::response::Response, ApiError> {
    let target_trimmed = body.target.trim();
    if target_trimmed.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "target must not be empty".to_string(),
        ));
    }
    if body.kind == NotificationChannelKind::Webhook {
        validate_webhook_target(target_trimmed)?;
    }
    let id = body.id.unwrap_or_else(Uuid::new_v4);
    let before = state
        .notification_channels
        .get(id)
        .await
        .map_err(internal_error)?;
    if let Some(existing) = &before {
        if existing.user_id != owner_id {
            return Err((
                StatusCode::FORBIDDEN,
                "this notification channel belongs to a different user".to_string(),
            ));
        }
    }
    let channel = NotificationChannel {
        id,
        user_id: owner_id,
        kind: body.kind,
        target: target_trimmed.to_string(),
        // A blank `secret` means "unchanged" on an edit, not "clear it" — see
        // `redact_notification_channel`'s docs for why: since a GET can no longer return
        // the real value, the edit form's field always comes back blank regardless of
        // whether a secret is actually configured, so treating blank-on-edit as "wipe it"
        // would silently drop the signing secret on every unrelated save (e.g. toggling
        // `enabled`). A brand-new channel (`before.is_none()`) has nothing to fall back to,
        // so blank there still means "no secret", same as before this existed.
        // Audit finding 5 (2026-09-20) — trimmed before the blank check, same reasoning as
        // `put_ai_assistant_provider_settings`.
        secret: body
            .secret
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| before.as_ref().and_then(|b| b.secret.clone())),
        enabled: body.enabled,
        created_at: before
            .as_ref()
            .map(|b| b.created_at)
            .unwrap_or_else(chrono::Utc::now),
    };
    state
        .notification_channels
        .upsert(&channel)
        .await
        .map_err(internal_error)?;
    let details = diff_details(before.as_ref(), &channel);
    Ok(with_journal_details(
        Json(channel),
        Some(id.to_string()),
        details,
    ))
}

async fn delete_notification_channel_owned_by(
    state: &DashboardState,
    owner_id: Uuid,
    id: Uuid,
) -> Result<axum::response::Response, ApiError> {
    if let Some(existing) = state
        .notification_channels
        .get(id)
        .await
        .map_err(internal_error)?
    {
        if existing.user_id != owner_id {
            return Err((
                StatusCode::FORBIDDEN,
                "this notification channel belongs to a different user".to_string(),
            ));
        }
    }
    state
        .notification_channels
        .delete(id)
        .await
        .map_err(internal_error)?;
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        Some(id.to_string()),
        None,
    ))
}

async fn list_notification_rules(
    State(state): State<DashboardState>,
) -> Result<Json<Vec<NotificationRule>>, ApiError> {
    Ok(Json(
        state
            .notification_rules
            .list_all()
            .await
            .map_err(internal_error)?,
    ))
}

async fn get_notification_rule(
    State(state): State<DashboardState>,
    Path(id): Path<Uuid>,
) -> Result<Json<NotificationRule>, ApiError> {
    match state
        .notification_rules
        .get(id)
        .await
        .map_err(internal_error)?
    {
        Some(rule) => Ok(Json(rule)),
        None => Err((
            StatusCode::NOT_FOUND,
            "no such notification rule".to_string(),
        )),
    }
}

#[derive(Deserialize)]
struct NotificationRuleBody {
    #[serde(default)]
    selection: discovery_config_store::NotificationSelection,
    #[serde(default)]
    id: Option<Uuid>,
    name: String,
    enabled: bool,
    min_level: AlertLevel,
    #[serde(default)]
    subnets: Vec<SubnetTarget>,
    #[serde(default)]
    profiles: Vec<String>,
    #[serde(default)]
    device_ids: Vec<Uuid>,
    #[serde(default)]
    active_from: Option<chrono::NaiveTime>,
    #[serde(default)]
    active_to: Option<chrono::NaiveTime>,
    #[serde(default)]
    days_of_week: Vec<String>,
    notify_on_activate: bool,
    notify_on_clear: bool,
    #[serde(default)]
    recipients: Vec<discovery_config_store::RecipientRef>,
    #[serde(default)]
    repeat_after_seconds: u64,
    #[serde(default)]
    repeat_interval_seconds: u64,
    #[serde(default)]
    max_repeats: u32,
    #[serde(default)]
    escalation_levels: Vec<discovery_config_store::EscalationLevel>,
}

const VALID_WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

/// Create-or-edit — see [`NotificationChannelBody`]'s sibling docs above for the same
/// `id: None`-on-create convention. `active_from`/`active_to` must be set together or not
/// at all (`NotificationRule::matches_time`'s docs on why a mixed pair is a state this type
/// itself has no clean interpretation for) — checked here, not left to silently fall back
/// to "no restriction" the way the pure function does for defense-in-depth against a
/// malformed stored row.
async fn upsert_notification_rule(
    State(state): State<DashboardState>,
    Json(body): Json<NotificationRuleBody>,
) -> Result<axum::response::Response, ApiError> {
    let name_trimmed = body.name.trim();
    if name_trimmed.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "name must not be empty".to_string(),
        ));
    }
    if body.active_from.is_some() != body.active_to.is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "active_from and active_to must be set together, or both left unset".to_string(),
        ));
    }
    if let Some(bad) = body
        .days_of_week
        .iter()
        .find(|d| !VALID_WEEKDAYS.contains(&d.as_str()))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "invalid days_of_week entry '{bad}' — must be one of Mon/Tue/Wed/Thu/Fri/Sat/Sun"
            ),
        ));
    }
    if let Some((i, e)) = body
        .subnets
        .iter()
        .enumerate()
        .find_map(|(i, s)| s.validate().err().map(|e| (i, e)))
    {
        return Err((StatusCode::BAD_REQUEST, format!("subnets[{i}]: {e}")));
    }

    if let Some(expr) = &body.selection.recipient_expression {
        discovery_dsl::AlertEvaluator::new()
            .validate_expression(expr)
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("recipient_expression: {e}"),
                )
            })?;
    }
    let id = body.id.unwrap_or_else(Uuid::new_v4);
    let before = state
        .notification_rules
        .get(id)
        .await
        .map_err(internal_error)?;
    let rule = NotificationRule {
        selection: body.selection,
        id,
        name: name_trimmed.to_string(),
        enabled: body.enabled,
        min_level: body.min_level,
        subnets: body.subnets,
        profiles: body.profiles,
        device_ids: body.device_ids,
        active_from: body.active_from,
        active_to: body.active_to,
        days_of_week: body.days_of_week,
        notify_on_activate: body.notify_on_activate,
        notify_on_clear: body.notify_on_clear,
        recipients: body.recipients,
        repeat_after_seconds: body.repeat_after_seconds,
        repeat_interval_seconds: body.repeat_interval_seconds,
        max_repeats: body.max_repeats,
        escalation_levels: body.escalation_levels,
    };
    state
        .notification_rules
        .upsert(&rule)
        .await
        .map_err(internal_error)?;
    let details = diff_details(before.as_ref(), &rule);
    Ok(with_journal_details(
        Json(rule),
        Some(id.to_string()),
        details,
    ))
}

async fn delete_notification_rule(
    State(state): State<DashboardState>,
    Path(id): Path<Uuid>,
) -> Result<axum::response::Response, ApiError> {
    state
        .notification_rules
        .delete(id)
        .await
        .map_err(internal_error)?;
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        Some(id.to_string()),
        None,
    ))
}

async fn list_topology_rules(
    State(state): State<DashboardState>,
) -> Result<Json<Vec<discovery_config_store::TopologyRule>>, ApiError> {
    Ok(Json(
        state
            .topology_rules
            .list_all()
            .await
            .map_err(internal_error)?,
    ))
}

async fn get_topology_rule(
    State(state): State<DashboardState>,
    Path(id): Path<Uuid>,
) -> Result<Json<discovery_config_store::TopologyRule>, ApiError> {
    match state.topology_rules.get(id).await.map_err(internal_error)? {
        Some(rule) => Ok(Json(rule)),
        None => Err((StatusCode::NOT_FOUND, "no such topology rule".to_string())),
    }
}

async fn enqueue_topology_recompute_for_all_devices(state: &DashboardState) -> anyhow::Result<()> {
    for device in state.devices.all().await? {
        state
            .store
            .enqueue(
                QueueKind::TopologyRecompute,
                serde_json::to_value(TopologyRecomputePayload {
                    device_id: device.id,
                })?,
                None,
            )
            .await?;
    }
    Ok(())
}

#[derive(Deserialize)]
struct TopologyRuleBody {
    #[serde(default)]
    id: Option<Uuid>,
    name: String,
    enabled: bool,
    my_key_expression: String,
    #[serde(default)]
    claimed_neighbors_expression: Option<String>,
    #[serde(default)]
    rank_expression: Option<String>,
    #[serde(default)]
    watched_metrics: Option<Vec<String>>,
}

/// Create-or-edit — same `id: None`-on-create convention as
/// [`upsert_notification_rule`]'s sibling docs. Both expressions are syntax-validated
/// here (`TopologyEvaluator::validate_expression`) before ever reaching storage — a typo
/// would otherwise only ever surface as a `warn!` log line from
/// `discovery_agent::topology_recompute::TopologyRecomputeHandler`, silently skipped
/// forever rather than rejected up front where whoever's authoring the rule can see it.
/// A `name` collision with a different rule surfaces as the underlying unique-constraint
/// error (`idx_topology_rules_name`) via `internal_error` — see
/// `TopologyRuleStore::upsert`'s docs on why there's no separate pre-check.
async fn upsert_topology_rule(
    State(state): State<DashboardState>,
    Json(body): Json<TopologyRuleBody>,
) -> Result<axum::response::Response, ApiError> {
    let name_trimmed = body.name.trim();
    if name_trimmed.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "name must not be empty".to_string(),
        ));
    }

    let evaluator = discovery_dsl::topology::TopologyEvaluator::new();
    evaluator
        .validate_expression(&body.my_key_expression)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("my_key_expression: {e}")))?;
    if let Some(expr) = &body.claimed_neighbors_expression {
        evaluator.validate_expression(expr).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("claimed_neighbors_expression: {e}"),
            )
        })?;
    }
    if let Some(expr) = &body.rank_expression {
        evaluator
            .validate_expression(expr)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("rank_expression: {e}")))?;
    }

    let id = body.id.unwrap_or_else(Uuid::new_v4);
    let before = state.topology_rules.get(id).await.map_err(internal_error)?;
    let rule = discovery_config_store::TopologyRule {
        id,
        name: name_trimmed.to_string(),
        enabled: body.enabled,
        my_key_expression: body.my_key_expression,
        claimed_neighbors_expression: body.claimed_neighbors_expression,
        rank_expression: body.rank_expression,
        watched_metrics: body.watched_metrics,
    };
    if let Some(previous) = before.as_ref() {
        if previous.name != rule.name {
            // The topology tables reference rule.name. Clear the old rows before
            // changing that key so databases without ON UPDATE CASCADE accept the edit.
            state
                .topology
                .delete_for_rule(&previous.name)
                .await
                .map_err(internal_error)?;
        }
    }
    state
        .topology_rules
        .upsert(&rule)
        .await
        .map_err(internal_error)?;
    state
        .topology
        .delete_for_rule(&rule.name)
        .await
        .map_err(internal_error)?;
    if rule.enabled {
        enqueue_topology_recompute_for_all_devices(&state)
            .await
            .map_err(internal_error)?;
    }
    let details = diff_details(before.as_ref(), &rule);
    Ok(with_journal_details(
        Json(rule),
        Some(id.to_string()),
        details,
    ))
}

async fn delete_topology_rule(
    State(state): State<DashboardState>,
    Path(id): Path<Uuid>,
) -> Result<axum::response::Response, ApiError> {
    let rule = state.topology_rules.get(id).await.map_err(internal_error)?;
    state
        .topology_rules
        .delete(id)
        .await
        .map_err(internal_error)?;
    if let Some(rule) = rule {
        state
            .topology
            .delete_for_rule(&rule.name)
            .await
            .map_err(internal_error)?;
    }
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        Some(id.to_string()),
        None,
    ))
}

/// This device's resolved neighbors under one rule — `rule_name` is the rule's `name`
/// (the join key `discovery_topology::TopologyStore` actually uses), not its `id`.
async fn get_topology_neighbors(
    State(state): State<DashboardState>,
    Path((rule_name, device_id)): Path<(String, Uuid)>,
) -> Result<Json<Vec<discovery_topology::ResolvedNeighbor>>, ApiError> {
    Ok(Json(
        state
            .topology
            .neighbors_of(&rule_name, device_id)
            .await
            .map_err(internal_error)?,
    ))
}

#[derive(Deserialize)]
struct TopologyEdgesQuery {
    /// Free-text, case-insensitive — matched against both devices' IP addresses (the only
    /// human-readable identifier an edge has; `device_a`/`device_b` are raw device ids).
    /// Same "app-level filter over a full fetch" posture `DevicesQuery::cidr`/`has_error`
    /// already document — `ResolvedEdge` carries no IP itself (`resolve_edges` is DB-free,
    /// see its own docs), and Devices/Topology can route to different physical databases
    /// (see `discovery_devices::DeviceListQuery`'s docs), so a SQL-level JOIN isn't
    /// generically possible here either.
    search: Option<String>,
    /// "confirmed" | "unconfirmed" — omitted means both.
    status: Option<String>,
    /// "determined" | "undetermined" — whether `upstream_device_id` is known at all.
    /// Omitted means both.
    direction: Option<String>,
    /// "device_a" (default) | "device_b" | "status" | "direction". The first two sort by
    /// that side's IP.
    sort_by: Option<String>,
    sort_dir: Option<String>,
    page: Option<u32>,
    page_size: Option<u32>,
}

/// One [`discovery_topology::ResolvedEdge`] enriched with both devices' IPs, so the
/// frontend no longer needs its own separate `devicesApi.list({ page_size: 1000 })` call
/// just to render a readable label — see [`get_topology_edges`]'s docs.
#[derive(Serialize)]
struct TopologyEdgeView {
    device_a: Uuid,
    device_b: Uuid,
    /// `None` if the device has since been deleted from `devices` — an edge can briefly
    /// outlive the device it's about until the next recompute/`delete_for_device` cleans it
    /// up. The frontend falls back to the raw id in that case, same as before this endpoint
    /// started resolving IPs itself.
    device_a_ip: Option<String>,
    device_b_ip: Option<String>,
    confirmed: bool,
    upstream_device_id: Option<Uuid>,
    direction_overridden: bool,
}

#[derive(Serialize)]
struct TopologyEdgesPage {
    items: Vec<TopologyEdgeView>,
    total: i64,
}

/// The whole resolved graph for one rule — what the topology page's edge list renders.
/// Search/filter/sort/pagination (2026-09-18, manual-test-audit finding #5: this page had
/// no controls at all beyond the rule selector) applied in Rust over the full result, same
/// posture as `DevicesQuery`'s `cidr`/`has_error` filters: the underlying computation
/// (`TopologyStore::resolved_edges`) is already one fleet-wide O(devices+claims) pass, not
/// a per-request SQL query with a `WHERE` clause to push filters into, and joining in each
/// device's IP for search/display can't be expressed as SQL either (`DeviceStore` can be a
/// different physical database — see `DeviceListQuery`'s docs). `state.devices.all()` below
/// is one batch call, not a per-edge round trip
/// (`.claude/rules/engineering-patterns.md`'s "батч вместо цикла на hot path") — the same
/// call the frontend used to make itself to build this same id→IP map, just centralized
/// here now instead of silently truncating past its old hardcoded `page_size: 1000` cap.
async fn get_topology_edges(
    State(state): State<DashboardState>,
    Path(rule_name): Path<String>,
    Query(params): Query<TopologyEdgesQuery>,
) -> Result<Json<TopologyEdgesPage>, ApiError> {
    let edges = state
        .topology
        .resolved_edges(&rule_name)
        .await
        .map_err(internal_error)?;
    let devices = state.devices.all().await.map_err(internal_error)?;
    let ip_by_id: HashMap<Uuid, String> = devices.into_iter().map(|d| (d.id, d.facts.ip)).collect();

    let mut views: Vec<TopologyEdgeView> = edges
        .into_iter()
        .map(|e| TopologyEdgeView {
            device_a_ip: ip_by_id.get(&e.device_a).cloned(),
            device_b_ip: ip_by_id.get(&e.device_b).cloned(),
            device_a: e.device_a,
            device_b: e.device_b,
            confirmed: e.confirmed,
            upstream_device_id: e.upstream_device_id,
            direction_overridden: e.direction_overridden,
        })
        .collect();

    if let Some(search) = params
        .search
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let needle = search.to_lowercase();
        views.retain(|v| {
            v.device_a_ip
                .as_deref()
                .is_some_and(|ip| ip.to_lowercase().contains(&needle))
                || v.device_b_ip
                    .as_deref()
                    .is_some_and(|ip| ip.to_lowercase().contains(&needle))
        });
    }
    match params.status.as_deref() {
        Some("confirmed") => views.retain(|v| v.confirmed),
        Some("unconfirmed") => views.retain(|v| !v.confirmed),
        _ => {}
    }
    match params.direction.as_deref() {
        Some("determined") => views.retain(|v| v.upstream_device_id.is_some()),
        Some("undetermined") => views.retain(|v| v.upstream_device_id.is_none()),
        _ => {}
    }

    match params.sort_by.as_deref() {
        Some("device_b") => {
            views.sort_by_key(|v| ip_sort_key(v.device_b_ip.as_deref().unwrap_or("")))
        }
        Some("status") => views.sort_by_key(|v| !v.confirmed),
        Some("direction") => views.sort_by_key(|v| v.upstream_device_id.is_none()),
        _ => views.sort_by_key(|v| ip_sort_key(v.device_a_ip.as_deref().unwrap_or(""))),
    }
    if params.sort_dir.as_deref() == Some("desc") {
        views.reverse();
    }

    let total = views.len() as i64;
    let page_size = params.page_size.unwrap_or(50).clamp(1, 500) as usize;
    let page = params.page.unwrap_or(1).max(1) as usize;
    let offset = (page - 1) * page_size;
    let items = views.into_iter().skip(offset).take(page_size).collect();

    Ok(Json(TopologyEdgesPage { items, total }))
}

#[derive(Deserialize)]
struct HierarchyOverrideBody {
    upstream_device_id: Uuid,
}

/// Manually pins which side of the `device_a`/`device_b` edge (under one rule) is
/// upstream — the escape hatch for when `rank_expression` alone can't determine direction
/// (a tie, or no rank expression configured at all). Rejects an `upstream_device_id` that
/// isn't one of the two devices before ever reaching the store — same immediate-feedback
/// posture `upsert_topology_rule` already takes for a broken expression, even though
/// `TopologyStore::set_hierarchy_override` also validates this itself as the actual
/// persistence boundary.
async fn set_topology_hierarchy_override(
    State(state): State<DashboardState>,
    Path((rule_name, device_a, device_b)): Path<(String, Uuid, Uuid)>,
    Json(body): Json<HierarchyOverrideBody>,
) -> Result<axum::response::Response, ApiError> {
    if body.upstream_device_id != device_a && body.upstream_device_id != device_b {
        return Err((
            StatusCode::BAD_REQUEST,
            "upstream_device_id must be one of the two devices in the edge".to_string(),
        ));
    }
    state
        .topology
        .set_hierarchy_override(&rule_name, device_a, device_b, body.upstream_device_id)
        .await
        .map_err(internal_error)?;
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        Some(format!("{rule_name}:{device_a}:{device_b}")),
        None,
    ))
}

async fn clear_topology_hierarchy_override(
    State(state): State<DashboardState>,
    Path((rule_name, device_a, device_b)): Path<(String, Uuid, Uuid)>,
) -> Result<axum::response::Response, ApiError> {
    state
        .topology
        .clear_hierarchy_override(&rule_name, device_a, device_b)
        .await
        .map_err(internal_error)?;
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        Some(format!("{rule_name}:{device_a}:{device_b}")),
        None,
    ))
}

async fn list_group_alert_rules(
    State(state): State<DashboardState>,
) -> Result<Json<Vec<discovery_config_store::GroupAlertRule>>, ApiError> {
    Ok(Json(
        state
            .group_alert_rules
            .list_all()
            .await
            .map_err(internal_error)?,
    ))
}

async fn get_group_alert_rule(
    State(state): State<DashboardState>,
    Path(id): Path<Uuid>,
) -> Result<Json<discovery_config_store::GroupAlertRule>, ApiError> {
    match state
        .group_alert_rules
        .get(id)
        .await
        .map_err(internal_error)?
    {
        Some(rule) => Ok(Json(rule)),
        None => Err((
            StatusCode::NOT_FOUND,
            "no such group-alert rule".to_string(),
        )),
    }
}

#[derive(Deserialize)]
struct GroupAlertRuleBody {
    #[serde(default)]
    id: Option<Uuid>,
    name: String,
    enabled: bool,
    cause_expression: String,
    effect_expression: String,
}

/// Create-or-edit — same `id: None`-on-create convention as [`upsert_topology_rule`]'s
/// sibling docs. Both expressions are syntax-validated here
/// (`GroupAlertEvaluator::validate_expression`) before ever reaching storage, same
/// "catch a typo at save time, not as a silent per-tick `warn!` forever" reasoning
/// `upsert_topology_rule` already documents. Unlike `TopologyRule::name`, no uniqueness
/// check — `name` here is a display label only (see `GroupAlertRuleStore`'s docs).
async fn upsert_group_alert_rule(
    State(state): State<DashboardState>,
    Json(body): Json<GroupAlertRuleBody>,
) -> Result<axum::response::Response, ApiError> {
    let name_trimmed = body.name.trim();
    if name_trimmed.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "name must not be empty".to_string(),
        ));
    }

    let evaluator = discovery_dsl::group_alerts::GroupAlertEvaluator::new();
    evaluator
        .validate_expression(&body.cause_expression)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("cause_expression: {e}")))?;
    evaluator
        .validate_expression(&body.effect_expression)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("effect_expression: {e}")))?;

    let id = body.id.unwrap_or_else(Uuid::new_v4);
    let before = state
        .group_alert_rules
        .get(id)
        .await
        .map_err(internal_error)?;
    let rule = discovery_config_store::GroupAlertRule {
        id,
        name: name_trimmed.to_string(),
        enabled: body.enabled,
        cause_expression: body.cause_expression,
        effect_expression: body.effect_expression,
    };
    state
        .group_alert_rules
        .upsert(&rule)
        .await
        .map_err(internal_error)?;
    let details = diff_details(before.as_ref(), &rule);
    Ok(with_journal_details(
        Json(rule),
        Some(id.to_string()),
        details,
    ))
}

async fn delete_group_alert_rule(
    State(state): State<DashboardState>,
    Path(id): Path<Uuid>,
) -> Result<axum::response::Response, ApiError> {
    state
        .group_alert_rules
        .delete(id)
        .await
        .map_err(internal_error)?;
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        Some(id.to_string()),
        None,
    ))
}

/// Minimal projection for the matrix editor's recipient picker — `{id, username}` only, not
/// the full admin-only `/api/users` payload (role/admin-flag/must_change_password): a
/// `Domain::Notifications` holder who isn't an admin still needs to pick recipients without
/// gaining visibility into user administration.
#[derive(Serialize)]
struct NotificationRecipient {
    id: Uuid,
    username: String,
}

async fn list_notification_recipients(
    State(state): State<DashboardState>,
) -> Result<Json<Vec<NotificationRecipient>>, ApiError> {
    let users = state.auth.list_users().await.map_err(internal_error)?;
    Ok(Json(
        users
            .into_iter()
            .map(|u| NotificationRecipient {
                id: u.id,
                username: u.username,
            })
            .collect(),
    ))
}

/// Sibling of [`NotificationRecipient`]/[`list_notification_recipients`] for the matrix
/// editor's role-as-proxy-group recipient option (2026-09-18, `RecipientRef::Role`) — same
/// "minimal projection, not the admin-only shape" reasoning: `{id, name}` only, not
/// `/api/roles`'s full permission-set payload, and gated by `Domain::Notifications` rather
/// than `admin_guard!` so the same non-admin notification-rule editor who can already pick
/// individual users can pick a role too.
#[derive(Serialize)]
struct NotificationRecipientRole {
    id: Uuid,
    name: String,
}

async fn list_notification_recipient_roles(
    State(state): State<DashboardState>,
) -> Result<Json<Vec<NotificationRecipientRole>>, ApiError> {
    let roles = state.auth.list_roles().await.map_err(internal_error)?;
    Ok(Json(
        roles
            .into_iter()
            .map(|r| NotificationRecipientRole {
                id: r.id,
                name: r.name,
            })
            .collect(),
    ))
}

/// System-wide SMTP/Telegram provider credentials — same `SettingsStore`-category shape as
/// `get_poll_intervals`/`put_poll_intervals` above, gated by `Domain::Notifications` rather
/// than `Domain::Settings` (see that domain variant's docs).
///
/// **`smtp_password`/`telegram_bot_token` are redacted to a blank placeholder in the GET
/// response** — fixed 2026-09-17 (audit finding #5's side-check, same leak class as
/// `redact_ssh_credentials`/`redact_notification_channel`: see
/// `docs/Changelog/2026-09-17 - Аудит глазами оператора...md`). This endpoint used to
/// return both in plaintext to any `Domain::Notifications` reader — the doc comment here
/// used to call that an intentional "same precedent as `Device.snmp_credentials`/
/// `ssh_credentials`", but that precedent itself only became true for *those* once this
/// same audit fixed it; nothing about it was ever a reason for *this* endpoint to also
/// leak. See `put_notification_provider_settings`'s docs for the matching write-side
/// "blank means unchanged" change this requires.
async fn get_notification_provider_settings(
    State(state): State<DashboardState>,
) -> Json<NotificationProviderConfig> {
    let mut config = state.settings.notification_provider().await;
    if config.smtp_password.is_some() {
        config.smtp_password = Some(String::new());
    }
    if config.telegram_bot_token.is_some() {
        config.telegram_bot_token = Some(String::new());
    }
    Json(config)
}

/// A blank `smtp_password`/`telegram_bot_token` means "leave the existing one unchanged",
/// not "clear it" — same reasoning, same fix session, as
/// `upsert_notification_channel_for`'s matching change for a webhook channel's `secret`
/// (see that function's docs): once `get_notification_provider_settings` no longer returns
/// the real value, the settings form's fields always come back blank regardless of whether
/// a credential is actually configured, so treating blank-on-save as "wipe it" would
/// silently drop working SMTP/Telegram credentials on every unrelated field's edit (e.g.
/// changing `smtp_host`).
async fn put_notification_provider_settings(
    State(state): State<DashboardState>,
    Json(mut config): Json<NotificationProviderConfig>,
) -> Result<axum::response::Response, ApiError> {
    // Audit finding 5 (2026-09-20) — same "trim before the blank-means-unchanged check"
    // reasoning as `put_ai_assistant_provider_settings`, applied to the sibling provider
    // settings endpoint.
    config.smtp_host = config.smtp_host.map(|s| s.trim().to_string());
    config.smtp_username = config.smtp_username.map(|s| s.trim().to_string());
    config.smtp_password = config.smtp_password.map(|s| s.trim().to_string());
    config.smtp_from_address = config.smtp_from_address.map(|s| s.trim().to_string());
    config.telegram_bot_token = config.telegram_bot_token.map(|s| s.trim().to_string());

    let before = state
        .settings
        .get_notification_provider()
        .await
        .map_err(internal_error)?;
    if config.smtp_password.as_deref().is_none_or(str::is_empty) {
        config.smtp_password = before.as_ref().and_then(|b| b.smtp_password.clone());
    }
    if config
        .telegram_bot_token
        .as_deref()
        .is_none_or(str::is_empty)
    {
        config.telegram_bot_token = before.as_ref().and_then(|b| b.telegram_bot_token.clone());
    }
    state
        .settings
        .set_notification_provider(&config)
        .await
        .map_err(internal_error)?;
    let details = diff_details(before.as_ref(), &config);
    Ok(with_journal_details(StatusCode::NO_CONTENT, None, details))
}

/// Admin-only (`admin_guard!`, not `domain_guard!` — see `discovery_core::AiAssistantProviderConfig`'s
/// docs for why) — same redact-on-GET contract as `get_notification_provider_settings`:
/// `client_secret` never round-trips to the browser once it's set.
async fn get_ai_assistant_provider_settings(
    State(state): State<DashboardState>,
) -> Json<AiAssistantProviderConfig> {
    let mut config = state.settings.ai_assistant_provider().await;
    if config.client_secret.is_some() {
        config.client_secret = Some(String::new());
    }
    // `openrouter_api_key` (2026-09-18, second provider) — same redact-on-read contract
    // as `client_secret` above; found missing live (2026-09-18, this provider's own live
    // verification pass) — without this, `GET` handed the real key straight back in the
    // response.
    if config.openrouter_api_key.is_some() {
        config.openrouter_api_key = Some(String::new());
    }
    // `self_hosted_api_key` (2026-09-19, third provider) — same redact-on-read contract,
    // applied proactively this time (not found live again) given the lesson from
    // `openrouter_api_key` just above. `Option<String>` here (not `Some(String::new())`
    // unconditionally) — a self-hosted config genuinely has no key configured in the
    // common "no auth" case, and that absence itself isn't sensitive, only a real value
    // would be.
    if config.self_hosted_api_key.is_some() {
        config.self_hosted_api_key = Some(String::new());
    }
    Json(config)
}

/// Same "blank means unchanged" write contract as `put_notification_provider_settings` —
/// see that function's docs. Applies independently to `client_secret`, `openrouter_api_key`
/// (2026-09-18), and `self_hosted_api_key` (2026-09-19) — same bug class as
/// `get_ai_assistant_provider_settings` above would have hit for each of them (a blank
/// field on save would have silently wiped an already-configured key) had this not been
/// added alongside it.
async fn put_ai_assistant_provider_settings(
    State(state): State<DashboardState>,
    Json(mut config): Json<AiAssistantProviderConfig>,
) -> Result<axum::response::Response, ApiError> {
    // Audit finding 5 (2026-09-20): none of these text fields were trimmed — a stray
    // copy-pasted space/newline (from GigaChat Studio/OpenRouter's dashboard, both common
    // sources for these values) silently corrupted the credential with no validation error
    // anywhere, which is exactly what broke the audit's own first GigaChat setup attempt.
    // Trimmed *before* the "blank means keep existing" checks below, so an all-whitespace
    // paste is correctly treated as "unchanged" too, not saved as a whitespace secret.
    config.client_id = config.client_id.trim().to_string();
    config.client_scope = config.client_scope.trim().to_string();
    config.client_secret = config.client_secret.map(|s| s.trim().to_string());
    config.openrouter_api_key = config.openrouter_api_key.map(|s| s.trim().to_string());
    config.openrouter_model = config.openrouter_model.trim().to_string();
    config.self_hosted_base_url = config.self_hosted_base_url.trim().to_string();
    config.self_hosted_api_key = config.self_hosted_api_key.map(|s| s.trim().to_string());
    config.self_hosted_model = config.self_hosted_model.trim().to_string();

    let before = state
        .settings
        .get_ai_assistant_provider()
        .await
        .map_err(internal_error)?;
    if config.client_secret.as_deref().is_none_or(str::is_empty) {
        config.client_secret = before.as_ref().and_then(|b| b.client_secret.clone());
    }
    if config
        .openrouter_api_key
        .as_deref()
        .is_none_or(str::is_empty)
    {
        config.openrouter_api_key = before.as_ref().and_then(|b| b.openrouter_api_key.clone());
    }
    if config
        .self_hosted_api_key
        .as_deref()
        .is_none_or(str::is_empty)
    {
        config.self_hosted_api_key = before.as_ref().and_then(|b| b.self_hosted_api_key.clone());
    }
    state
        .settings
        .set_ai_assistant_provider(&config)
        .await
        .map_err(internal_error)?;
    let details = diff_details(before.as_ref(), &config);
    Ok(with_journal_details(StatusCode::NO_CONTENT, None, details))
}

/// Direct user request 2026-08-16: "конфигурацию мы храним в БД! И должна быть возможность
/// для webui для изменения настроек + они должны сразу применяться" — the first (so far
/// only) settings category moved out of `config.toml`, see
/// `discovery_core::PollIntervalsConfig`'s docs. `Some` default via
/// `SettingsStore::poll_intervals()` (not the raw `get_poll_intervals`) — the dashboard
/// should always have *something* sensible to show/edit, even on a fresh store that
/// hasn't been seeded yet for some reason (`main.rs` seeds it from `config.toml` at
/// startup in the normal case, but this endpoint doesn't depend on that having happened).
async fn get_poll_intervals(State(state): State<DashboardState>) -> Json<PollIntervalsConfig> {
    Json(state.settings.poll_intervals().await)
}

/// Every consumer (`SnmpPollHandler`/`MetricPollHandler`/`ReachabilityPollHandler`, and
/// the three background loops) reads `SettingsStore` fresh on its own next tick — a save
/// here takes effect within one cycle of whichever poll interval was actually changed, no
/// restart, see each consumer's `settings` field docs.
async fn put_poll_intervals(
    State(state): State<DashboardState>,
    Json(intervals): Json<PollIntervalsConfig>,
) -> Result<axum::response::Response, ApiError> {
    let before = state
        .settings
        .get_poll_intervals()
        .await
        .map_err(internal_error)?;
    state
        .settings
        .set_poll_intervals(&intervals)
        .await
        .map_err(internal_error)?;
    let details = diff_details(before.as_ref(), &intervals);
    Ok(with_journal_details(StatusCode::NO_CONTENT, None, details))
}

#[derive(Serialize)]
struct StorageDatabasesView {
    databases: Vec<StorageDatabaseView>,
    default_database: Option<String>,
}

/// Public database settings deliberately have a write-only password field.  The empty
/// placeholder is accepted by the update endpoint as "keep the value already on disk";
/// a read-only Settings user therefore cannot recover a database credential through REST.
#[derive(Serialize)]
struct StorageDatabaseView {
    name: String,
    kind: discovery_bootstrap::DbKind,
    host: Option<String>,
    port: Option<u16>,
    database: Option<String>,
    username: Option<String>,
    password: Option<String>,
    file_path: Option<std::path::PathBuf>,
    pool_max_connections: Option<u32>,
    sqlite_busy_timeout_secs: u64,
}

fn storage_database_view(config: discovery_bootstrap::DatabaseConnConfig) -> StorageDatabaseView {
    StorageDatabaseView {
        name: config.name,
        kind: config.kind,
        host: config.host,
        port: config.port,
        database: config.database,
        username: config.username,
        password: config.password.map(|_| String::new()),
        file_path: config.file_path,
        pool_max_connections: config.pool_max_connections,
        sqlite_busy_timeout_secs: config.sqlite_busy_timeout_secs,
    }
}

#[derive(Deserialize)]
struct StorageDatabasesUpdate {
    databases: Vec<discovery_bootstrap::DatabaseConnConfig>,
    default_database: Option<String>,
}

/// Every write below always answers `{needs_restart: true}` — a database-config change
/// can never take effect without one (see `discovery_bootstrap::StorageConfig`'s docs) —
/// but never *forces* one itself: direct user request 2026-08-18, "переключение будет
/// требовать перезапуска всегда, но можно будет отказаться, пользователь сам
/// перезапустит как закончит конфигурировать". The dashboard shows this as a banner with
/// "restart now" (calls [`restart_process`]) / "later" buttons, so several edits can be
/// batched into one restart.
#[derive(Serialize)]
struct StorageWriteResponse {
    needs_restart: bool,
}

/// `config.toml`'s `[storage]` table is the only thing these two endpoint pairs edit —
/// it's still config-file-only, never DB-backed (chicken-and-egg: `build_stores` needs
/// this before any database connection exists at all, see `discovery_bootstrap::Config`'s
/// docs) — the dashboard's "Настройки — БД" section is a structured editor for this one
/// file, not a separate source of truth. Read fresh (not from `DashboardState`, which
/// holds no `Config`) on every call, same "always reflect what's actually on disk right
/// now" discipline every other settings read in this file follows.
async fn get_storage_databases() -> Result<Json<StorageDatabasesView>, ApiError> {
    let config = discovery_bootstrap::Config::load().map_err(internal_error)?;
    Ok(Json(StorageDatabasesView {
        databases: config
            .storage
            .databases
            .into_iter()
            .map(storage_database_view)
            .collect(),
        default_database: config.storage.default_database,
    }))
}

/// Replaces `databases`/`default_database` wholesale, leaving `routing` (and every other
/// `config.toml` section) untouched — see `discovery_bootstrap::Config::write_storage`'s
/// docs for the format-preserving merge this relies on. Validated before anything is
/// written (`400` on failure, e.g. a `postgres` entry with no `url`, or `default_database`
/// naming a database that isn't in `databases`) — see `Config::validate`'s docs for the
/// full rule set.
/// **No Журнал `details` diff on purpose.** `DatabaseConnConfig` carries a plaintext
/// `password` field — real DB credentials. `redact_sensitive` *would* strip it by name
/// before a diff, same as it does for `update_role`/`put_poll_intervals`'s calls, but this
/// is the one endpoint in the whole file where a genuine secret lives on the diffed
/// struct — deliberately not leaning on that generic, name-based redaction being
/// complete here (a future field rename/typo silently reintroducing a leak) rather than
/// structurally cheap to avoid altogether. Practically moot anyway: multiple DB entries'
/// worth of fields serialized together routinely exceeds `DIFF_VALUE_MAX_CHARS`, so a real
/// diff would mostly collapse to a vague "changed, N symbols" placeholder, not a legible
/// field-by-field diff. The generic middleware still records the action itself (who/when/
/// "Изменён список подключений к БД") via `describe_action`, just with `object`/`details`
/// both `None`.
async fn put_storage_databases(
    Json(update): Json<StorageDatabasesUpdate>,
) -> Result<Json<StorageWriteResponse>, ApiError> {
    let path = discovery_bootstrap::Config::config_file_path();
    let mut config = discovery_bootstrap::Config::load_from_path(&path).unwrap_or_default();
    let old_passwords: HashMap<String, Option<String>> = config
        .storage
        .databases
        .into_iter()
        .map(|db| (db.name, db.password))
        .collect();
    let mut databases = update.databases;
    for database in &mut databases {
        if database.password.as_deref().is_none_or(str::is_empty) {
            database.password = old_passwords.get(&database.name).cloned().flatten();
        }
    }
    config.storage.databases = databases;
    config.storage.default_database = update.default_database;
    discovery_bootstrap::Config::write_storage(&path, &config.storage)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(Json(StorageWriteResponse {
        needs_restart: true,
    }))
}

async fn get_storage_routing() -> Result<Json<discovery_bootstrap::DomainRouting>, ApiError> {
    let config = discovery_bootstrap::Config::load().map_err(internal_error)?;
    Ok(Json(config.storage.routing))
}

/// Replaces `routing` wholesale, leaving `databases`/`default_database` untouched — see
/// [`put_storage_databases`]'s docs for the shared contract (format-preserving write,
/// validated first, `needs_restart: true` always, never a forced restart).
async fn put_storage_routing(
    Json(routing): Json<discovery_bootstrap::DomainRouting>,
) -> Result<axum::response::Response, ApiError> {
    let path = discovery_bootstrap::Config::config_file_path();
    let mut config = discovery_bootstrap::Config::load_from_path(&path).unwrap_or_default();
    // No secrets on `DomainRouting` (just 8 database-name strings) — safe to diff whole,
    // unlike `put_storage_databases` next to it, which is why that one deliberately
    // stays without a `details` diff (see its docs).
    let before = config.storage.routing.clone();
    config.storage.routing = routing;
    discovery_bootstrap::Config::write_storage(&path, &config.storage)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let details = diff_details(Some(&before), &config.storage.routing);
    Ok(with_journal_details(
        Json(StorageWriteResponse {
            needs_restart: true,
        }),
        None,
        details,
    ))
}

/// The explicit, user-triggered "restart now" action — direct user request 2026-08-18: a
/// database-config change never restarts automatically on save (see
/// [`StorageWriteResponse`]'s docs), only when the user actually clicks this. Implementation
/// is deliberately just `exit(0)`: this process has no supervisor of its own to ask for a
/// clean respawn, so restarting is whatever wraps it (`systemd`, a container orchestrator,
/// or — on the current dev stand, which has neither — a human re-running `cargo run`/the
/// binary by hand, same as every other manual relaunch already done during this project's
/// development). Responds `202` *before* exiting (via a short delayed spawn) so the
/// triggering HTTP request actually gets a response instead of a reset connection.
async fn restart_process() -> StatusCode {
    tracing::warn!("restart requested via POST /api/system/restart — exiting now (no in-process supervisor; something outside this process must relaunch it)");
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        std::process::exit(0);
    });
    StatusCode::ACCEPTED
}

#[derive(Serialize)]
struct RunDiscoveryConfigResponse {
    enqueued: usize,
}

/// Manual "run now" — enqueues `config`'s subnets immediately via the same
/// `discovery_config_store::enqueue_scan` the scheduled loop uses
/// (`discovery-agent::discovery_scan::run_discovery_schedule_loop`), bypassing its
/// schedule and `last_fired` bookkeeping entirely (a one-off action, doesn't suppress or
/// get suppressed by the schedule — see that loop's docs). Deliberately does **not**
/// require `config.enabled` — a manual click is explicit intent, unlike the schedule which
/// must respect the enabled flag to avoid surprise scans.
async fn run_discovery_config_now(
    State(state): State<DashboardState>,
    Path(name): Path<String>,
) -> Result<axum::response::Response, ApiError> {
    let configs = state
        .discovery_configs
        .load_all()
        .await
        .map_err(internal_error)?;
    let config = configs.into_iter().find(|c| c.name == name).ok_or((
        StatusCode::NOT_FOUND,
        format!("no discovery config named '{name}'"),
    ))?;
    let enqueued = enqueue_scan(&config, &state.store).await;
    Ok(with_journal_details(
        Json(RunDiscoveryConfigResponse { enqueued }),
        Some(name),
        Some(serde_json::json!({"enqueued": enqueued})),
    ))
}

/// The built React app (`crates/web/frontend/dist`, produced by `npm run build` — **must**
/// exist at compile time, see `frontend/README.md`). Replaces the old single
/// `include_str!("../static/index.html")` dashboard (`crates/web/static/index.html`,
/// deleted 2026-08-25 once every page had a React equivalent — see
/// `docs/Changelog/2026-08-25 - React Frontend — все страницы.md`): that worked for one
/// hand-written file with zero external assets; a real Vite build emits a variable set of
/// hashed `assets/*.js`/`*.css` files that a single `Html<&'static str>` handler can't
/// serve at all.
#[derive(rust_embed::RustEmbed)]
#[folder = "frontend/dist"]
struct Assets;

/// Catch-all for anything under `/` that isn't `/api/*` (see `router`'s `.fallback`).
/// Serves the exact embedded file for a matching path (e.g. `/assets/index-abc123.js`);
/// falls back to `index.html` for anything else — the standard SPA pattern, needed even
/// though this app doesn't do client-side URL routing yet (round 15 design note:
/// navigation is in-memory `useState`, not the URL) because it also covers the plain "/"
/// request and any trailing-slash/typo path without a dedicated route each.
async fn serve_embedded(uri: axum::http::Uri) -> axum::response::Response {
    use axum::response::IntoResponse;
    let path = uri.path().trim_start_matches('/');
    let (path, body, is_index_fallback) = match Assets::get(path) {
        Some(file) => (path, file, false),
        None => match Assets::get("index.html") {
            Some(file) => ("index.html", file, true),
            None => return (StatusCode::INTERNAL_SERVER_ERROR, "frontend/dist is missing or empty — run `npm run build` in crates/web/frontend before starting this binary (see frontend/README.md)").into_response(),
        },
    };
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    // `index.html` references `assets/*.js`/`*.css` by content-hashed filename — a
    // rebuild changes both the hash *and* what's embedded in this binary, so a browser
    // caching an old `index.html` would keep pointing at a JS bundle this process no
    // longer has (a real 404, seen live: a hard refresh was needed to recover). The
    // hashed assets themselves are the opposite case — a genuinely different build always
    // gets a genuinely different filename, so caching them aggressively is safe.
    let cache_control = if is_index_fallback || path == "index.html" {
        "no-cache"
    } else {
        "public, max-age=31536000, immutable"
    };
    (
        [
            (axum::http::header::CONTENT_TYPE, mime.as_ref()),
            (axum::http::header::CACHE_CONTROL, cache_control),
        ],
        body.data,
    )
        .into_response()
}

/// Backs the Обзор page's active-incidents tile. Reads `state.alerts` (`AlertStateTracker`)
/// directly — the exact same `Arc` `AlertEvalHandler` mutates synchronously as part of
/// every `Activated`/`Cleared` transition, *before* that transition's own DB write (see
/// `discovery_agent::handlers::persist_alert_transition`) — so this is never actually
/// behind `AlertStore` (which backs `GET /api/alerts`/`active_alert_count`), only ever
/// equal-or-ahead of it. The 2026-09-17 audit's finding #9 ("Обзор может на несколько
/// секунд не показывать только что активировавшуюся тревогу") traced to the *frontend*
/// polling this route on a much slower cadence than the pages it appeared to lag behind
/// (Обзор's own fixed 5s vs Тревоги's 1s default) — fixed there (`OverviewPage.tsx`), not
/// here; this handler itself was never the source of the staleness.
async fn incidents(
    State(state): State<DashboardState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Alert>>, ApiError> {
    let user = authenticate_request(&state, &headers).await?;
    let mut visible = Vec::new();
    for alert in state.alerts.active_alerts() {
        if alert_rules::permits(
            &alert_rules::current_policy(&state, &alert).await?,
            &user,
            false,
        ) {
            visible.push(alert);
        }
    }
    Ok(Json(visible))
}

#[derive(Deserialize)]
struct AlertsQuery {
    /// Free-text, case-insensitive — see `AlertListQuery::search`'s docs.
    search: Option<String>,
    /// "info" | "warning" | "critical" — omitted means every level.
    level: Option<String>,
    /// "active" | "cleared" — omitted means both.
    state: Option<String>,
    device_id: Option<Uuid>,
    /// Inclusive lower/upper bound on `Alert::first_seen`, ISO-8601 — see
    /// `AlertListQuery::since`'s docs.
    since: Option<chrono::DateTime<chrono::Utc>>,
    until: Option<chrono::DateTime<chrono::Utc>>,
    /// "first_seen" | "last_seen" (default) | "level" | "name" | "device_ip".
    sort_by: Option<String>,
    /// "asc" | "desc" (default).
    sort_dir: Option<String>,
    page: Option<u32>,
    page_size: Option<u32>,
}

fn parse_alert_level(s: &str) -> Option<AlertLevel> {
    match s {
        "info" => Some(AlertLevel::Info),
        "warning" => Some(AlertLevel::Warning),
        "critical" => Some(AlertLevel::Critical),
        _ => None,
    }
}

fn parse_alert_state(s: &str) -> Option<AlertState> {
    match s {
        "active" => Some(AlertState::Active),
        "cleared" => Some(AlertState::Cleared),
        _ => None,
    }
}

fn parse_alert_sort_by(s: Option<&str>) -> AlertSortBy {
    match s {
        Some("first_seen") => AlertSortBy::FirstSeen,
        Some("level") => AlertSortBy::Level,
        Some("name") => AlertSortBy::Name,
        Some("device_ip") => AlertSortBy::DeviceIp,
        _ => AlertSortBy::LastSeen,
    }
}

/// The dashboard's Тревоги page — direct user request 2026-08-17: "добавь на ui раздел с
/// тревогами, фильтрацией, пагинацией, сортировкой, поиском". Durable history from
/// `AlertStore` (every activation/still-active/clear transition — see its docs), not the
/// in-memory-only `incidents()`/`AlertStateTracker::active_alerts()` above (kept as-is,
/// still the cheap "what's open right now" view with no DB round-trip).
async fn list_alerts(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(params): Query<AlertsQuery>,
) -> Result<Json<AlertListPage>, ApiError> {
    let level = match params.level.as_deref() {
        Some(s) => Some(parse_alert_level(s).ok_or((
            StatusCode::BAD_REQUEST,
            format!("unknown alert level '{s}'"),
        ))?),
        None => None,
    };
    let alert_state = match params.state.as_deref() {
        Some(s) => Some(parse_alert_state(s).ok_or((
            StatusCode::BAD_REQUEST,
            format!("unknown alert state '{s}'"),
        ))?),
        None => None,
    };
    let page_size = params.page_size.unwrap_or(50).clamp(1, 500) as i64;
    let page = params.page.unwrap_or(1).max(1) as i64;
    let query = AlertListQuery {
        response_pending: false,
        screen_only: false,
        search: params.search.filter(|s| !s.trim().is_empty()),
        level,
        state: alert_state,
        device_id: params.device_id,
        since: params.since,
        until: params.until,
        sort_by: parse_alert_sort_by(params.sort_by.as_deref()),
        sort_dir: if params.sort_dir.as_deref() == Some("asc") {
            SortDir::Asc
        } else {
            SortDir::Desc
        },
        limit: page_size,
        offset: (page - 1) * page_size,
    };
    let user = authenticate_request(&state, &headers).await?;
    let result = alert_rules::visible_page(&state, &query, &user).await?;
    Ok(Json(result))
}

/// Single-alert read — added 2026-08-18 during a REST-completeness pass (direct user
/// request: "REST должен полностью позволять работать с приложением, без UI... чтение
/// (включая пагинацию, фильтрацию, сортировку, поиск)"). `list_alerts` above already
/// covers the paginated/filterable collection view; this is the plain "fetch one by id"
/// counterpart every other resource in this API has, which alerts was missing despite the
/// store already exposing `AlertStore::get` (used internally by `close_alert`/
/// `delete_alert`, just never routed for direct external use).
async fn get_alert(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Alert>, ApiError> {
    match state.alert_store.get(id).await.map_err(internal_error)? {
        Some(alert) => {
            let user = authenticate_request(&state, &headers).await?;
            alert_rules::require_alert_access(&state, &alert, &user, false).await?;
            Ok(Json(alert))
        }
        None => Err((StatusCode::NOT_FOUND, "no such alert".to_string())),
    }
}

/// Direct user request 2026-08-18: "нужна возможность вручную закрыть тревогу" — separate
/// from [`delete_alert`] below (explicitly asked for as two different operations: closing
/// keeps the row as history with `cleared_at` set, deleting removes it outright).
///
/// Reads the current row first (not just trusting the id blindly) for two reasons: to
/// 404 on a genuinely unknown id, and to get `device_id`/`name` — needed to sever live
/// tracking in `AlertStateTracker` *before* writing `Cleared`, or the very next
/// `AlertEvalHandler` tick would silently flip it back to `Active` if the underlying
/// condition is still true (see `AlertStateTracker::remove`'s docs). `state.alerts.remove`
/// is a harmless no-op if this alert had already fallen out of live tracking — which is
/// exactly the case for an alert that's been `Active` in the DB ever since a process
/// restart wiped the (purely in-memory) tracker; closing it here works either way, reading
/// the *durable* row as the source of truth rather than assuming the tracker still has it.
///
/// Sets `closed_by` to the authenticated caller's own username — direct user request
/// 2026-08-28: "указывать кто закрыл тревогу, если пользователь закрыл руками". This is
/// the *only* place that ever sets it — the automatic pipeline's own `Cleared` transition
/// (`AlertEvalHandler`, condition became false on its own) calls `upsert` directly with an
/// `Alert` that never touches this field, so it stays `None` for an automatic clear.
async fn close_alert(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<axum::response::Response, ApiError> {
    let user = authenticate_request(&state, &headers).await?;
    let Some(mut alert) = state.alert_store.get(id).await.map_err(internal_error)? else {
        return Err((StatusCode::NOT_FOUND, "no such alert".to_string()));
    };
    alert_rules::require_alert_access(&state, &alert, &user, true).await?;
    let object = Some(format!("{} — {}", alert.device_ip, alert.name));
    if alert.state == AlertState::Cleared {
        return Ok(with_journal_details(StatusCode::NO_CONTENT, object, None)); // already closed — idempotent no-op
    }
    state
        .alerts
        .remove(alert.device_id, &alert.name, alert.row_key.as_deref());
    let now = chrono::Utc::now();
    alert.state = AlertState::Cleared;
    alert.cleared_at = Some(now);
    alert.last_seen = now;
    alert.closed_by = Some(user.username.clone());
    state
        .alert_store
        .upsert(&alert)
        .await
        .map_err(internal_error)?;
    alert_rules::lifecycle_actions(
        &state,
        &alert,
        discovery_core::AlertLifecycle::Cleared,
        &user.username,
    )
    .await?;
    state
        .alert_store
        .save_runtime(
            alert.device_id,
            &state.alerts.snapshot_for_device(alert.device_id),
        )
        .await
        .map_err(internal_error)?;
    Ok(with_journal_details(StatusCode::NO_CONTENT, object, None))
}

#[derive(Debug, Deserialize)]
struct SnoozeAlertBody {
    until: chrono::DateTime<chrono::Utc>,
}

/// Acknowledgement is an operator annotation, deliberately independent from closing:
/// the incident remains active and the evaluator keeps tracking it.
async fn acknowledge_alert(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Alert>, ApiError> {
    let user = authenticate_request(&state, &headers).await?;
    let Some(mut alert) = state.alert_store.get(id).await.map_err(internal_error)? else {
        return Err((StatusCode::NOT_FOUND, "no such alert".to_string()));
    };
    alert_rules::require_alert_access(&state, &alert, &user, true).await?;
    if alert.acknowledged_at.is_some() {
        return Ok(Json(alert));
    }
    if alert.state != AlertState::Active && !alert.details.policy.acknowledge_required {
        return Err((
            StatusCode::CONFLICT,
            "only active alerts can be acknowledged".to_string(),
        ));
    }
    let now = chrono::Utc::now();
    state
        .alert_store
        .set_acknowledgement(id, Some(user.username.clone()), Some(now))
        .await
        .map_err(internal_error)?;
    alert.acknowledged_by = Some(user.username.clone());
    alert.acknowledged_at = Some(now);
    alert_rules::lifecycle_actions(
        &state,
        &alert,
        discovery_core::AlertLifecycle::Acknowledged,
        &user.username,
    )
    .await?;
    if alert.details.policy.mode == discovery_core::AlertMode::Change
        || (alert.details.policy.mode == discovery_core::AlertMode::Event
            && alert
                .details
                .policy
                .event
                .as_ref()
                .is_some_and(|e| e.recovery_expression.is_none()))
    {
        alert.state = AlertState::Cleared;
        alert.cleared_at = Some(now);
        state
            .alerts
            .remove(alert.device_id, &alert.name, alert.row_key.as_deref());
    } else {
        state.alerts.set_details(
            alert.device_id,
            &alert.name,
            alert.row_key.as_deref(),
            alert.details.clone(),
        );
    }
    state
        .alert_store
        .upsert(&alert)
        .await
        .map_err(internal_error)?;
    state
        .alert_store
        .save_runtime(
            alert.device_id,
            &state.alerts.snapshot_for_device(alert.device_id),
        )
        .await
        .map_err(internal_error)?;
    state.alerts.update_operator_state(&alert);
    if let Ok(payload) = serde_json::to_value(discovery_core::payload::AlertEvalPayload {
        device_id: alert.device_id,
        event: None,
    }) {
        let _ = state
            .store
            .enqueue(
                QueueKind::AlertEval,
                payload,
                Some(&alert.device_id.to_string()),
            )
            .await;
    }
    Ok(Json(alert))
}

async fn unacknowledge_alert(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Alert>, ApiError> {
    let user = authenticate_request(&state, &headers).await?;
    let Some(mut alert) = state.alert_store.get(id).await.map_err(internal_error)? else {
        return Err((StatusCode::NOT_FOUND, "no such alert".to_string()));
    };
    alert_rules::require_alert_access(&state, &alert, &user, true).await?;
    state
        .alert_store
        .set_acknowledgement(id, None, None)
        .await
        .map_err(internal_error)?;
    alert.acknowledged_by = None;
    alert.acknowledged_at = None;
    state.alerts.update_operator_state(&alert);
    if let Ok(payload) = serde_json::to_value(discovery_core::payload::AlertEvalPayload {
        device_id: alert.device_id,
        event: None,
    }) {
        let _ = state
            .store
            .enqueue(
                QueueKind::AlertEval,
                payload,
                Some(&alert.device_id.to_string()),
            )
            .await;
    }
    Ok(Json(alert))
}

async fn snooze_alert(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<SnoozeAlertBody>,
) -> Result<Json<Alert>, ApiError> {
    let user = authenticate_request(&state, &headers).await?;
    let Some(mut alert) = state.alert_store.get(id).await.map_err(internal_error)? else {
        return Err((StatusCode::NOT_FOUND, "no such alert".to_string()));
    };
    alert_rules::require_alert_access(&state, &alert, &user, true).await?;
    if alert.state != AlertState::Active {
        return Err((
            StatusCode::CONFLICT,
            "only active alerts can be snoozed".to_string(),
        ));
    }
    let now = chrono::Utc::now();
    if body.until <= now {
        return Err((
            StatusCode::BAD_REQUEST,
            "snooze deadline must be in the future".to_string(),
        ));
    }
    state
        .alert_store
        .set_snooze(id, Some(body.until), Some(user.username.clone()))
        .await
        .map_err(internal_error)?;
    alert.snoozed_until = Some(body.until);
    alert.snoozed_by = Some(user.username);
    state.alerts.update_operator_state(&alert);
    if let Ok(payload) = serde_json::to_value(discovery_core::payload::AlertEvalPayload {
        device_id: alert.device_id,
        event: None,
    }) {
        let _ = state
            .store
            .enqueue(
                QueueKind::AlertEval,
                payload,
                Some(&alert.device_id.to_string()),
            )
            .await;
    }
    Ok(Json(alert))
}

async fn unsnooze_alert(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Alert>, ApiError> {
    let user = authenticate_request(&state, &headers).await?;
    let Some(mut alert) = state.alert_store.get(id).await.map_err(internal_error)? else {
        return Err((StatusCode::NOT_FOUND, "no such alert".to_string()));
    };
    alert_rules::require_alert_access(&state, &alert, &user, true).await?;
    state
        .alert_store
        .set_snooze(id, None, None)
        .await
        .map_err(internal_error)?;
    alert.snoozed_until = None;
    alert.snoozed_by = None;
    state.alerts.update_operator_state(&alert);
    if let Ok(payload) = serde_json::to_value(discovery_core::payload::AlertEvalPayload {
        device_id: alert.device_id,
        event: None,
    }) {
        let _ = state
            .store
            .enqueue(
                QueueKind::AlertEval,
                payload,
                Some(&alert.device_id.to_string()),
            )
            .await;
    }
    Ok(Json(alert))
}

/// Direct user request 2026-08-18: "отдельно — удалить тревогу". Unlike [`close_alert`],
/// removes the row outright (no history left behind) — works on an active or already-
/// cleared alert alike. Same "sever live tracking first" reasoning as `close_alert` (a
/// no-op if it wasn't tracked), otherwise a still-genuinely-active alert would just get
/// silently recreated (same id, via the normal `upsert` path) on the next `AlertEval` tick
/// right after being deleted.
async fn delete_alert(
    State(state): State<DashboardState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<axum::response::Response, ApiError> {
    let user = authenticate_request(&state, &headers).await?;
    let object = if let Some(alert) = state.alert_store.get(id).await.map_err(internal_error)? {
        alert_rules::require_alert_access(&state, &alert, &user, true).await?;
        state
            .alerts
            .remove(alert.device_id, &alert.name, alert.row_key.as_deref());
        Some(format!("{} — {}", alert.device_ip, alert.name))
    } else {
        None
    };
    state.alert_store.delete(id).await.map_err(internal_error)?;
    Ok(with_journal_details(StatusCode::NO_CONTENT, object, None))
}

/// One attachment as it travels over the wire — bytes as base64 inside the same JSON
/// body as `text`, no multipart/form-data extractor needed for a feature this small
/// (2026-08-29, direct user request: "вложения к комментариям тревог: файл/изображение/
/// видео").
#[derive(Deserialize)]
struct AttachmentUploadBody {
    filename: String,
    content_type: String,
    data_base64: String,
}

#[derive(Deserialize)]
struct AddAlertCommentBody {
    text: String,
    #[serde(default)]
    attachments: Vec<AttachmentUploadBody>,
}

/// Threaded, multi-author comments (2026-08-28, direct user request — supersedes the
/// earlier 2026-08-18 single free-form textarea: "Мы в дизайне делали комментариями от
/// пользователей", the design artifact's original round-4 intent, reinstated). `author`
/// is the *authenticated caller's own username* — not a client-supplied field, so a
/// comment can never be posted under someone else's name.
async fn add_alert_comment(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<AddAlertCommentBody>,
) -> Result<axum::response::Response, ApiError> {
    let access_user = authenticate_request(&state, &headers).await?;
    let access_alert = state
        .alert_store
        .get(id)
        .await
        .map_err(internal_error)?
        .ok_or((StatusCode::NOT_FOUND, "no such alert".into()))?;
    alert_rules::require_alert_access(&state, &access_alert, &access_user, true).await?;
    use base64::Engine;

    let user = authenticate_request(&state, &headers).await?;
    let text = body.text.trim();
    if text.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "comment text must not be empty".to_string(),
        ));
    }
    let mut attachments = Vec::with_capacity(body.attachments.len());
    for a in body.attachments {
        let data = base64::engine::general_purpose::STANDARD
            .decode(a.data_base64.as_bytes())
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("attachment '{}': invalid base64: {e}", a.filename),
                )
            })?;
        attachments.push(NewAttachment {
            filename: a.filename,
            content_type: a.content_type,
            data,
        });
    }
    // `object` only — the comment thread itself (`alert_comments`, already durable) is
    // where the actual text/attachments live; the Журнал entry doesn't duplicate content,
    // per the same "не населяй журнал большим количеством данных" discipline every other
    // `details` in this file follows.
    let object = state
        .alert_store
        .get(id)
        .await
        .ok()
        .flatten()
        .map(|a| format!("{} — {}", a.device_ip, a.name));
    let comment = state
        .alert_store
        .add_comment(id, &user.username, text, attachments)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(with_journal_details(Json(comment), object, None))
}

async fn list_alert_comments(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<AlertComment>>, ApiError> {
    let access_user = authenticate_request(&state, &headers).await?;
    let access_alert = state
        .alert_store
        .get(id)
        .await
        .map_err(internal_error)?
        .ok_or((StatusCode::NOT_FOUND, "no such alert".into()))?;
    alert_rules::require_alert_access(&state, &access_alert, &access_user, false).await?;
    let comments = state
        .alert_store
        .list_comments(id)
        .await
        .map_err(internal_error)?;
    Ok(Json(comments))
}

/// Serves one attachment's raw bytes for download — `:id`/`:comment_id` in the path are
/// for URL readability/REST nesting only, not used to scope the lookup (an attachment id
/// is already globally unique — see `AlertStore::get_attachment`'s docs).
async fn download_alert_attachment(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path((id, comment_id, attachment_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<axum::response::Response, ApiError> {
    use axum::response::IntoResponse;
    let user = authenticate_request(&state, &headers).await?;
    let alert = state
        .alert_store
        .get(id)
        .await
        .map_err(internal_error)?
        .ok_or((StatusCode::NOT_FOUND, "no such alert".into()))?;
    alert_rules::require_alert_access(&state, &alert, &user, false).await?;
    let comments = state
        .alert_store
        .list_comments(id)
        .await
        .map_err(internal_error)?;
    if !comments
        .iter()
        .any(|c| c.id == comment_id && c.attachments.iter().any(|a| a.id == attachment_id))
    {
        return Err((
            StatusCode::NOT_FOUND,
            "no such attachment in this alert".into(),
        ));
    }

    let Some((meta, data)) = state
        .alert_store
        .get_attachment(attachment_id)
        .await
        .map_err(internal_error)?
    else {
        return Err((StatusCode::NOT_FOUND, "no such attachment".to_string()));
    };
    let mut response = data.into_response();
    if let Ok(value) = meta.content_type.parse() {
        response
            .headers_mut()
            .insert(axum::http::header::CONTENT_TYPE, value);
    }
    if let Ok(value) = format!(
        "attachment; filename=\"{}\"",
        meta.filename.replace('"', "")
    )
    .parse()
    {
        response
            .headers_mut()
            .insert(axum::http::header::CONTENT_DISPOSITION, value);
    }
    Ok(response)
}

/// Direct user request 2026-08-17: "добавь конфигурацию на время хранения тревог" — same
/// `Some`-default-via-the-convenience-method contract as `get_poll_intervals`.
async fn get_alert_retention(State(state): State<DashboardState>) -> Json<AlertRetentionConfig> {
    Json(state.settings.alert_retention().await)
}

/// Read fresh every tick by `discovery_agent::alert_history_cleanup`'s loop — a save here
/// takes effect within one cleanup cycle, no restart.
async fn put_alert_retention(
    State(state): State<DashboardState>,
    Json(retention): Json<AlertRetentionConfig>,
) -> Result<axum::response::Response, ApiError> {
    validate_optional_retention("retention_secs", retention.retention_secs)?;
    let before = state
        .settings
        .get_alert_retention()
        .await
        .map_err(internal_error)?;
    state
        .settings
        .set_alert_retention(&retention)
        .await
        .map_err(internal_error)?;
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        None,
        diff_details(before.as_ref(), &retention),
    ))
}

/// Sixth settings category — added 2026-08-21, scale audit finding: `logs` had no
/// retention control at all, unlike `device_metric_history`/`alerts`. Same shape as
/// `get_alert_retention`/`put_alert_retention`.
async fn get_log_retention(
    State(state): State<DashboardState>,
) -> Json<discovery_core::LogRetentionConfig> {
    Json(state.settings.log_retention().await)
}

/// Read fresh every tick by `discovery_agent::log_cleanup`'s loop — a save here takes
/// effect within one cleanup cycle, no restart.
async fn put_log_retention(
    State(state): State<DashboardState>,
    Json(retention): Json<discovery_core::LogRetentionConfig>,
) -> Result<axum::response::Response, ApiError> {
    validate_optional_retention("retention_secs", retention.retention_secs)?;
    let before = state
        .settings
        .get_log_retention()
        .await
        .map_err(internal_error)?;
    state
        .settings
        .set_log_retention(&retention)
        .await
        .map_err(internal_error)?;
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        None,
        diff_details(before.as_ref(), &retention),
    ))
}

async fn get_journal_retention(
    State(state): State<DashboardState>,
) -> Json<JournalRetentionConfig> {
    Json(state.settings.journal_retention().await)
}

/// Read fresh every tick by `discovery_agent::journal_cleanup`'s loop — a save here takes
/// effect within one cleanup cycle, no restart.
async fn put_journal_retention(
    State(state): State<DashboardState>,
    Json(retention): Json<JournalRetentionConfig>,
) -> Result<axum::response::Response, ApiError> {
    validate_optional_retention("retention_secs", retention.retention_secs)?;
    let before = state
        .settings
        .get_journal_retention()
        .await
        .map_err(internal_error)?;
    state
        .settings
        .set_journal_retention(&retention)
        .await
        .map_err(internal_error)?;
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        None,
        diff_details(before.as_ref(), &retention),
    ))
}

/// Direct user correction 2026-08-18: "Нужно сделать настраиваемым и таймауты и кол-во
/// проб и периодичность" — periodicity was already covered by
/// `poll_intervals.reachability_secs`; this is the timeout/retries half.
async fn get_ping_config(State(state): State<DashboardState>) -> Json<PingConfig> {
    Json(state.settings.ping_config().await)
}

/// Read fresh on every use by `DiscoveryHandler`'s dead-device gate and by
/// `ReachabilityPollHandler` — a save here applies to the very next probe, no restart.
async fn put_ping_config(
    State(state): State<DashboardState>,
    Json(config): Json<PingConfig>,
) -> Result<axum::response::Response, ApiError> {
    let before = state
        .settings
        .get_ping_config()
        .await
        .map_err(internal_error)?;
    state
        .settings
        .set_ping_config(&config)
        .await
        .map_err(internal_error)?;
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        None,
        diff_details(before.as_ref(), &config),
    ))
}

/// Direct user request 2026-08-18: "настраиваемый через конфиг период времени после
/// которого устройство с ping=false удаляется. По умолчанию 0 - если 0 никогда не
/// удалять."
async fn get_dead_device_retention(
    State(state): State<DashboardState>,
) -> Json<DeadDeviceRetentionConfig> {
    Json(state.settings.dead_device_retention().await)
}

/// Read fresh every tick by `discovery_agent::dead_device_cleanup`'s loop — a save here
/// applies within one cleanup cycle, no restart.
async fn put_dead_device_retention(
    State(state): State<DashboardState>,
    Json(retention): Json<DeadDeviceRetentionConfig>,
) -> Result<axum::response::Response, ApiError> {
    let before = state
        .settings
        .get_dead_device_retention()
        .await
        .map_err(internal_error)?;
    state
        .settings
        .set_dead_device_retention(&retention)
        .await
        .map_err(internal_error)?;
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        None,
        diff_details(before.as_ref(), &retention),
    ))
}

async fn get_config_backup_settings(State(state): State<DashboardState>) -> Json<ConfigBackupSettings> {
    Json(state.settings.config_backup().await)
}

async fn put_config_backup_settings(
    State(state): State<DashboardState>,
    Json(config): Json<ConfigBackupSettings>,
) -> Result<axum::response::Response, ApiError> {
    if !(1..=600).contains(&config.timeout_secs) || !(1..=(16 * 1024 * 1024)).contains(&config.max_size_bytes) || !(60..=(365 * 24 * 60 * 60)).contains(&config.retention_secs) {
        return Err((StatusCode::BAD_REQUEST, "invalid backup limits".to_string()));
    }
    if let Some(discovery_core::Schedule::Periodic { interval_secs }) = &config.schedule {
        if *interval_secs < 60 { return Err((StatusCode::BAD_REQUEST, "periodic backup interval must be at least 60 seconds".to_string())); }
    }
    let before = state.settings.get_config_backup().await.map_err(internal_error)?;
    state.settings.set_config_backup(&config).await.map_err(internal_error)?;
    Ok(with_journal_details(StatusCode::NO_CONTENT, None, diff_details(before.as_ref(), &config)))
}

#[derive(Serialize)]
struct QueueStatsView {
    queue: &'static str,
    stats: discovery_core::QueueStats,
}

/// TASK-20260921-021 (2026-09-22) — used to swallow a storage error into
/// `QueueStats::default()` (all zeros) per queue, so a genuine backend outage looked
/// identical to "every queue is empty and healthy" to both an operator and any monitoring
/// scraping this endpoint. A stats read failing is itself signal (the same class of
/// problem `internal_error` already reports consistently for every other store failure in
/// this file — correlation-id-bearing 500, no internal details leaked) — it must never be
/// silently downgraded to a fake zero.
async fn queues(
    State(state): State<DashboardState>,
) -> Result<Json<Vec<QueueStatsView>>, ApiError> {
    let mut out = Vec::with_capacity(QueueKind::ALL.len());
    for queue in QueueKind::ALL {
        let stats = state.store.stats(queue).await.map_err(internal_error)?;
        out.push(QueueStatsView {
            queue: queue.as_str(),
            stats,
        });
    }
    Ok(Json(out))
}

async fn workers(State(state): State<DashboardState>) -> Json<Vec<WorkerActivity>> {
    Json(state.workers.snapshot())
}

#[derive(Deserialize)]
struct QueueJobsQuery {
    /// "pending" | "in_progress" | "failed" — omitted means every state. Values
    /// mirror `QueueStatsView`'s field names (see `queues` above), not `Debug`-formatted
    /// Rust variant names, so the same string the dashboard shows for a count is also what
    /// it sends back to filter by.
    state: Option<String>,
    /// Free-text, case-insensitive — see `discovery_queue::JobListQuery::search`'s docs.
    search: Option<String>,
    /// "id" | "created_at" | "updated_at" (default) | "attempts".
    sort_by: Option<String>,
    /// "asc" | "desc" (default).
    sort_dir: Option<String>,
    page: Option<u32>,
    page_size: Option<u32>,
}

fn parse_job_state(s: &str) -> Option<JobState> {
    match s {
        "pending" => Some(JobState::Pending),
        "in_progress" => Some(JobState::InProgress),
        "failed" => Some(JobState::Failed),
        "done" => Some(JobState::Done),
        "cancelled" => Some(JobState::Cancelled),
        _ => None,
    }
}

fn parse_job_sort_by(s: Option<&str>) -> JobSortBy {
    match s {
        Some("id") => JobSortBy::Id,
        Some("created_at") => JobSortBy::CreatedAt,
        Some("attempts") => JobSortBy::Attempts,
        _ => JobSortBy::UpdatedAt,
    }
}

/// Individual job records for one queue — the counterpart to `queues()`'s aggregate
/// stats. Each `Job.payload` is a JSON blob whose shape depends on the queue
/// (`discovery_core::payload`) but always carries what the job actually concerns — an IP,
/// a device context, etc. — which is exactly what aggregate counts can't show.
///
/// **Changed 2026-08-17 (direct user request — dashboard pagination/search/sort/filter
/// pass, "не отображай последние 100 записей а все не done с пагинацией фильтрацией
/// сортировкой и поиском"):** used to be a flat `?state=&limit=` cap on the most-recently-
/// updated rows. Now real search/sort/pagination — see `JobListQuery`'s docs for why this
/// is pushed down to SQL rather than done in this handler the way `devices()`/`logs()` do
/// it.
async fn queue_jobs(
    State(state): State<DashboardState>,
    Path(kind): Path<String>,
    Query(params): Query<QueueJobsQuery>,
) -> Result<Json<JobListPage>, ApiError> {
    let queue = QueueKind::from_str(&kind)
        .ok_or((StatusCode::NOT_FOUND, format!("unknown queue '{kind}'")))?;
    let job_state = match params.state.as_deref() {
        Some(s) => Some(
            parse_job_state(s)
                .ok_or((StatusCode::BAD_REQUEST, format!("unknown job state '{s}'")))?,
        ),
        None => None,
    };
    let page_size = params.page_size.unwrap_or(50).clamp(1, 500) as i64;
    let page = params.page.unwrap_or(1).max(1) as i64;
    let query = JobListQuery {
        state: job_state,
        search: params.search.filter(|s| !s.trim().is_empty()),
        sort_by: parse_job_sort_by(params.sort_by.as_deref()),
        sort_dir: if params.sort_dir.as_deref() == Some("asc") {
            SortDir::Asc
        } else {
            SortDir::Desc
        },
        limit: page_size,
        offset: (page - 1) * page_size,
    };
    let result = state
        .store
        .list_jobs(queue, &query)
        .await
        .map_err(internal_error)?;
    Ok(Json(result))
}

#[derive(Deserialize)]
struct QueuePausedBody {
    paused: bool,
}

/// Whole-queue pause — "приостанавливать... очередь целиком" — same `{"paused": bool}`
/// PUT-a-boolean shape as `set_device_enabled`/`set_all_devices_enabled` use for their
/// on/off switches. A paused queue stops `JobQueueStore::claim` from returning any work
/// for it; jobs already `in_progress` keep running to completion. See
/// `JobQueueStore::set_queue_paused`'s docs.
async fn set_queue_paused(
    State(state): State<DashboardState>,
    Path(kind): Path<String>,
    Json(body): Json<QueuePausedBody>,
) -> Result<axum::response::Response, ApiError> {
    let queue = QueueKind::from_str(&kind)
        .ok_or((StatusCode::NOT_FOUND, format!("unknown queue '{kind}'")))?;
    state
        .store
        .set_queue_paused(queue, body.paused)
        .await
        .map_err(internal_error)?;
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        Some(kind),
        Some(serde_json::json!({"paused": body.paused})),
    ))
}

#[derive(Deserialize)]
struct JobIdPath {
    kind: String,
    id: i64,
}

async fn reject_operator_job(state: &DashboardState, id: i64) -> Result<(), ApiError> {
    if state
        .store
        .get_job(id)
        .await
        .map_err(internal_error)?
        .is_some_and(|job| job.queue == QueueKind::OperatorAction)
    {
        return Err((
            StatusCode::FORBIDDEN,
            "use device action endpoints for operator jobs".to_string(),
        ));
    }
    Ok(())
}

/// Deletes one job from its queue outright — "возможность удалять задачи в очереди".
/// `kind` is only used to give a clean 404 for an unknown queue name; the delete itself is
/// by job id alone (ids are unique across every queue).
async fn delete_job(
    State(state): State<DashboardState>,
    Path(params): Path<JobIdPath>,
) -> Result<axum::response::Response, ApiError> {
    QueueKind::from_str(&params.kind).ok_or((
        StatusCode::NOT_FOUND,
        format!("unknown queue '{}'", params.kind),
    ))?;
    reject_operator_job(&state, params.id).await?;
    let deleted = state
        .store
        .delete_job(params.id)
        .await
        .map_err(internal_error)?;
    if !deleted {
        return Err((StatusCode::NOT_FOUND, "no such job".to_string()));
    }
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        Some(format!("{} #{}", params.kind, params.id)),
        None,
    ))
}

/// Pauses one job — "приостанавливать их (остается в очереди но не выполняется)". See
/// `JobQueueStore::pause_job`'s docs.
async fn pause_job(
    State(state): State<DashboardState>,
    Path(params): Path<JobIdPath>,
) -> Result<axum::response::Response, ApiError> {
    QueueKind::from_str(&params.kind).ok_or((
        StatusCode::NOT_FOUND,
        format!("unknown queue '{}'", params.kind),
    ))?;
    reject_operator_job(&state, params.id).await?;
    let found = state
        .store
        .pause_job(params.id)
        .await
        .map_err(internal_error)?;
    if !found {
        return Err((StatusCode::NOT_FOUND, "no such job".to_string()));
    }
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        Some(format!("{} #{}", params.kind, params.id)),
        None,
    ))
}

async fn resume_job(
    State(state): State<DashboardState>,
    Path(params): Path<JobIdPath>,
) -> Result<axum::response::Response, ApiError> {
    QueueKind::from_str(&params.kind).ok_or((
        StatusCode::NOT_FOUND,
        format!("unknown queue '{}'", params.kind),
    ))?;
    reject_operator_job(&state, params.id).await?;
    let found = state
        .store
        .resume_job(params.id)
        .await
        .map_err(internal_error)?;
    if !found {
        return Err((StatusCode::NOT_FOUND, "no such job".to_string()));
    }
    Ok(with_journal_details(
        StatusCode::NO_CONTENT,
        Some(format!("{} #{}", params.kind, params.id)),
        None,
    ))
}

#[derive(Deserialize)]
struct ClearQueueQuery {
    /// Same "pending" | "in_progress" | "failed" strings as `QueueJobsQuery::state` —
    /// omitted clears every job in the queue, not just one state.
    state: Option<String>,
}

#[derive(Serialize)]
struct ClearQueueResponse {
    deleted: u64,
}

/// Bulk-clears a queue — "очищать очередь целиком" — optionally scoped to one state (e.g.
/// `?state=failed` to sweep out only dead jobs, leaving pending/in-progress work alone).
async fn clear_queue(
    State(state): State<DashboardState>,
    Path(kind): Path<String>,
    Query(params): Query<ClearQueueQuery>,
) -> Result<axum::response::Response, ApiError> {
    let queue = QueueKind::from_str(&kind)
        .ok_or((StatusCode::NOT_FOUND, format!("unknown queue '{kind}'")))?;
    if queue == QueueKind::OperatorAction {
        return Err((
            StatusCode::FORBIDDEN,
            "use device action endpoints for operator jobs".to_string(),
        ));
    }
    let job_state = match params.state.as_deref() {
        Some(s) => Some(
            parse_job_state(s)
                .ok_or((StatusCode::BAD_REQUEST, format!("unknown job state '{s}'")))?,
        ),
        None => None,
    };
    let deleted = state
        .store
        .clear_queue(queue, job_state)
        .await
        .map_err(internal_error)?;
    let mut details = serde_json::json!({"deleted": deleted});
    if let Some(s) = &params.state {
        details["state"] = serde_json::json!(s);
    }
    Ok(with_journal_details(
        Json(ClearQueueResponse { deleted }),
        Some(kind),
        Some(details),
    ))
}

#[derive(Deserialize)]
struct LogsQuery {
    /// Minimum severity to show ("error" | "warn" | "info" | "debug" | "trace") — that
    /// level and worse. Omitted/unrecognized = show everything (see `LogBuffer::snapshot`).
    level: Option<String>,
    /// Only entries whose tracing target starts with this (e.g. `discovery_agent`).
    target: Option<String>,
    /// Free-text, case-insensitive — matches `message` or `target` (see
    /// `LogBuffer::snapshot`'s docs).
    search: Option<String>,
    /// Inclusive lower/upper bound on `LogEntry.timestamp`, ISO-8601 — added 2026-08-27,
    /// design-artifact parity pass (round 13's Logs date-range widget). `None` = unbounded
    /// on that side, matching the artifact's own "bounded-default for query views" default
    /// being a *frontend* choice (pre-filled to last 24h), not a backend requirement.
    since: Option<chrono::DateTime<chrono::Utc>>,
    until: Option<chrono::DateTime<chrono::Utc>>,
    /// "desc" (default, newest first) | "asc" (oldest first).
    sort_dir: Option<String>,
    page: Option<u32>,
    page_size: Option<u32>,
}

#[derive(Serialize)]
struct LogsPage {
    items: Vec<LogEntry>,
    total: usize,
}

/// **Changed 2026-08-17 (direct user request — dashboard pagination/search/sort/filter
/// pass):** used to be a flat `?limit=` cap on the newest matching entries. Now adds
/// `search`/`sort_dir`/pagination — done here, over `LogBuffer::snapshot`'s full (already
/// level/target-filtered) result, not inside the buffer itself (see its docs for why: the
/// buffer's own capacity already bounds this to a small, cheap-to-slice `Vec`).
async fn logs(
    State(state): State<DashboardState>,
    Query(params): Query<LogsQuery>,
) -> Json<LogsPage> {
    let mut entries = state.logs.snapshot(
        params.level.as_deref(),
        params.target.as_deref(),
        params.search.as_deref(),
        params.since,
        params.until,
    );
    if params.sort_dir.as_deref() == Some("asc") {
        entries.reverse();
    }
    let total = entries.len();
    let page_size = params.page_size.unwrap_or(50).clamp(1, 500) as usize;
    let page = params.page.unwrap_or(1).max(1) as usize;
    let items = entries
        .into_iter()
        .skip((page - 1) * page_size)
        .take(page_size)
        .collect();
    Json(LogsPage { items, total })
}

#[derive(Deserialize)]
struct JournalQuery {
    /// Free-text, case-insensitive — see `JournalListQuery::search`'s docs.
    search: Option<String>,
    /// Exact match — see `JournalListQuery::domain`'s docs. One of
    /// `discovery_core::Domain::as_str()`'s 8 values, or `"users"`/`"roles"`.
    domain: Option<String>,
    /// Exact match on username.
    username: Option<String>,
    /// Inclusive lower/upper bound on `JournalEntry.ts`, ISO-8601.
    since: Option<chrono::DateTime<chrono::Utc>>,
    until: Option<chrono::DateTime<chrono::Utc>>,
    /// "ts" (default) | "username" | "domain" | "action".
    sort_by: Option<String>,
    /// "asc" | "desc" (default).
    sort_dir: Option<String>,
    page: Option<u32>,
    page_size: Option<u32>,
}

fn parse_journal_sort_by(s: Option<&str>) -> JournalSortBy {
    match s {
        Some("username") => JournalSortBy::Username,
        Some("domain") => JournalSortBy::Domain,
        Some("action") => JournalSortBy::Action,
        _ => JournalSortBy::Ts,
    }
}

/// The dashboard's Журнал page — direct user request: "журнал... хранить в себе все
/// действия пользователей: что за пользователь, в каком домене и что за действие", with
/// "фильтрацией, пагинацией, просмотр по определенному времени, сортировкой, поиском,
/// аналогично другим страницам (тревоги, устройства, метрики)". Admin-only (see
/// `router()`'s docs on this route) — reads `state.journal`, the durable trail
/// `require_domain_permission`/`require_admin` write to on every successful mutating
/// request (see `describe_action`'s docs), same paginated/filterable/sortable shape as
/// `list_alerts`.
async fn list_journal(
    State(state): State<DashboardState>,
    Query(params): Query<JournalQuery>,
) -> Result<Json<JournalListPage>, ApiError> {
    let page_size = params.page_size.unwrap_or(50).clamp(1, 500) as i64;
    let page = params.page.unwrap_or(1).max(1) as i64;
    let query = JournalListQuery {
        search: params.search.filter(|s| !s.trim().is_empty()),
        domain: params.domain.filter(|s| !s.trim().is_empty()),
        username: params.username.filter(|s| !s.trim().is_empty()),
        since: params.since,
        until: params.until,
        sort_by: parse_journal_sort_by(params.sort_by.as_deref()),
        sort_dir: if params.sort_dir.as_deref() == Some("asc") {
            SortDir::Asc
        } else {
            SortDir::Desc
        },
        limit: page_size,
        offset: (page - 1) * page_size,
    };
    let result = state.journal.list(&query).await.map_err(internal_error)?;
    Ok(Json(result))
}

/// Maps a mutating request's method + matched route template to a human-readable (Russian)
/// action description for the Журнал audit trail — called from `require_domain_permission`/
/// `require_admin` after a successful (2xx) response, never for GET/HEAD (those aren't
/// "actions"). `path` is the **matched route pattern** (`axum::extract::MatchedPath`, e.g.
/// `/api/devices/:id/enabled`), not the concrete request path with real ids substituted —
/// so this is a small, closed match over `router()`'s own route table, not a regex/parser.
/// Falls back to `"{method} {path}"` for any route added later without a matching update
/// here — every write is still recorded, just with a less friendly label, rather than
/// silently going unlogged (same "REST-first, never code-only" discipline `discovery/
/// AGENTS.md` documents for every other management operation in this project).
fn describe_action(method: &axum::http::Method, path: &str) -> String {
    use axum::http::Method as M;
    let action = match (method, path) {
        (&M::POST, "/api/users") => "Создан пользователь",
        (&M::DELETE, "/api/users/:id") => "Удалён пользователь",
        (&M::PUT, "/api/users/:id/password") => "Сброшен пароль пользователя",
        (&M::PUT, "/api/users/:id/admin") => "Изменён admin-флаг пользователя",
        (&M::PUT, "/api/users/:id/role") => "Изменена роль пользователя",
        (&M::POST, "/api/roles") => "Создана роль",
        (&M::PUT, "/api/roles/:id") => "Изменены права роли",
        (&M::DELETE, "/api/roles/:id") => "Удалена роль",
        (&M::DELETE, "/api/alerts/:id") => "Удалена тревога",
        (&M::POST, "/api/alerts/:id/close") => "Закрыта тревога",
        (&M::POST, "/api/alerts/:id/comments") => "Добавлен комментарий к тревоге",
        (&M::PUT, "/api/queues/:kind/paused") => "Изменена пауза очереди",
        (&M::DELETE, "/api/queues/:kind/jobs") => "Очищена очередь",
        (&M::DELETE, "/api/queues/:kind/jobs/:id") => "Удалена задача очереди",
        (&M::POST, "/api/queues/:kind/jobs/:id/pause") => "Приостановлена задача",
        (&M::POST, "/api/queues/:kind/jobs/:id/resume") => "Возобновлена задача",
        (&M::POST, "/api/devices") => "Создано устройство",
        (&M::POST, "/api/devices/:id/actions/:action") => "Запущено действие оператора",
        (&M::DELETE, "/api/devices/:id/actions/jobs/:job_id") => "Отменено действие оператора",
        (&M::PUT, "/api/devices/enabled") => "Массово изменена активность устройств",
        (&M::DELETE, "/api/devices/:id") => "Удалено устройство",
        (&M::PUT, "/api/devices/:id/enabled") => "Изменена активность устройства",
        (&M::POST, "/api/devices/:id/sync-profile") => {
            "Синхронизированы метрики устройства с профилем"
        }
        (&M::PUT, "/api/devices/:id/metrics/:name/enabled") => {
            "Включена метрика устройства (override)"
        }
        (&M::DELETE, "/api/devices/:id/metrics/:name/enabled") => {
            "Сброшен override метрики устройства"
        }
        (&M::POST, "/api/profiles") => "Сохранён профиль",
        (&M::DELETE, "/api/profiles/:name") => "Удалён профиль",
        (&M::POST, "/api/profiles/:name/sync-devices") => "Синхронизированы устройства профиля",
        (&M::POST, "/api/discovery-configs") => "Сохранён конфиг дискаверинга",
        (&M::DELETE, "/api/discovery-configs/:name") => "Удалён конфиг дискаверинга",
        (&M::POST, "/api/discovery-configs/:name/run") => "Запущен дискаверинг вручную",
        (&M::PUT, "/api/settings/poll-intervals") => "Изменены каденсы фоновых циклов",
        (&M::PUT, "/api/settings/alert-retention") => "Изменён срок хранения тревог",
        (&M::PUT, "/api/settings/log-retention") => "Изменён срок хранения логов",
        (&M::PUT, "/api/settings/journal-retention") => "Изменён срок хранения журнала",
        (&M::PUT, "/api/settings/ping") => "Изменены настройки ping",
        (&M::PUT, "/api/settings/dead-device-retention") => {
            "Изменена авто-очистка недоступных устройств"
        }
        (&M::PUT, "/api/settings/config-backup") => {
            "Изменены настройки резервного копирования конфигураций"
        }
        (&M::PUT, "/api/settings/databases") => "Изменён список подключений к БД",
        (&M::PUT, "/api/settings/routing") => "Изменена маршрутизация доменов по БД",
        (&M::POST, "/api/system/restart") => "Инициирован перезапуск процесса",
        // Found while writing customer docs, 2026-09-13 — these two fell through to the
        // generic fallback, unlike every sibling domain's create/delete routes.
        (&M::POST, "/api/maintenance-windows") => "Сохранено окно обслуживания",
        (&M::DELETE, "/api/maintenance-windows/:id") => "Удалено окно обслуживания",
        // No entries for `/api/notifications/channels*` (self-service) — like
        // `/api/auth/password`, that route has neither `domain_guard!` nor `admin_guard!`,
        // so `require_domain_permission`/`require_admin` (the only two places that write a
        // Журнал entry at all) never run for it; a user's own contact-point edits are
        // deliberately not audit-logged, same as their own password changes.
        (&M::POST, "/api/users/:id/notification-channels") => {
            "Сохранён канал нотификации пользователя"
        }
        (&M::DELETE, "/api/users/:id/notification-channels/:channel_id") => {
            "Удалён канал нотификации пользователя"
        }
        (&M::POST, "/api/notifications/rules") => "Сохранено правило матрицы нотификации",
        (&M::DELETE, "/api/notifications/rules/:id") => "Удалено правило матрицы нотификации",
        (&M::PUT, "/api/settings/notifications") => "Изменена конфигурация провайдера нотификаций",
        (&M::PUT, "/api/settings/ai-assistant") => "Изменена конфигурация провайдера ИИ-ассистента",
        (&M::POST, "/api/topology/rules") => "Сохранено правило топологии",
        (&M::DELETE, "/api/topology/rules/:id") => "Удалено правило топологии",
        (&M::PUT, "/api/topology/rules/:name/hierarchy/:device_a/:device_b") => {
            "Установлено ручное направление иерархии топологии"
        }
        (&M::DELETE, "/api/topology/rules/:name/hierarchy/:device_a/:device_b") => {
            "Сброшено ручное направление иерархии топологии"
        }
        (&M::POST, "/api/group-alerts/rules") => "Сохранено правило группового подавления тревог",
        (&M::DELETE, "/api/group-alerts/rules/:id") => {
            "Удалено правило группового подавления тревог"
        }
        _ => return format!("{method} {path}"),
    };
    action.to_string()
}

/// Router-level HTTP tests — added 2026-08-18, direct user question "Тесты покрывают все
/// операции?" whose honest answer, before this, was "no": this crate had **zero**
/// automated tests despite every write/read endpoint in it, verified until now only by
/// live `curl` against the running dev stand (real, but not repeatable by `cargo test`,
/// not part of CI, and silent about regressions the next time someone touches this file).
///
/// Drives the real `router()` — the same one `main.rs` serves — through
/// `tower::ServiceExt::oneshot`, against `DashboardState` built entirely from `InMemory*`
/// stores (every trait object field already has one, used the same way demo/test fixtures
/// do elsewhere in this project). No real socket, no real database; still exercises the
/// actual routing table, extractors, and handler bodies — not a hand-rolled call into the
/// handler functions directly, which would silently stop catching a route-registration
/// mistake (wrong path, wrong method, wrong param name) the way a real HTTP request does.
///
/// Covers, for every resource this crate exposes: list (empty + populated,
/// search/filter/sort/pagination where the endpoint has it), single-item read (200 +
/// 404), create/update, delete, and any resource-specific action endpoint
/// (close/comment/enable/run/sync) — the same add/delete/read(+pagination/filter/sort/
/// search) checklist the REST-completeness pass itself was asked to satisfy, now pinned
/// down as regression tests instead of one-off `curl` checks.
#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use discovery_config_store::{
        Schedule, SeaOrmDiscoveryConfigStore, SeaOrmMaintenanceWindowStore, SeaOrmProfileStore,
        SeaOrmSettingsStore, SubnetSpec,
    };
    use discovery_core::{SnmpAuth, SnmpVersion};
    use discovery_devices::{SeaOrmDeviceMetricsStore, SeaOrmDeviceStore};
    use discovery_dsl::{MatchSection, MetricsSection, ProfileMeta};
    use discovery_queue::SeaOrmJobQueueStore;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// Returns the router, the state (so tests can reach into stores directly), and a
    /// bearer token for a freshly-created **admin** user — every route this crate exposes
    /// requires a logged-in session as of 2026-08-21 (see this module's auth section), and
    /// this suite is about exercising each endpoint's own logic, not re-proving the
    /// permission-guard middleware works on every single one of the ~70 call sites below
    /// (that's covered once, directly, by `auth_tests` further down: login, a
    /// permission-denied 403, and an admin bypass).
    async fn test_app() -> (Router, DashboardState, String) {
        // Devices/device_metrics/alert_store share one connection here — the common case
        // (all domains routed to the default database), and what lets a test that deletes
        // a device via `state.devices` observe the cascade through `state.device_metrics`/
        // `state.alert_store` too, not just through `devices`'s own internal references
        // (which `SeaOrmDeviceStore::new_in_memory_for_tests` would otherwise wire up on a
        // *separate* connection nothing else in this fixture could see).
        let db = discovery_migration::connect_in_memory_for_tests().await;
        let device_metrics: Arc<dyn DeviceMetricsStore> =
            Arc::new(SeaOrmDeviceMetricsStore::new(db.clone()));
        let alert_store: Arc<dyn AlertStore> =
            Arc::new(discovery_alerts::SeaOrmAlertStore::new(db.clone()));
        let devices: Arc<dyn DeviceStore> = Arc::new(SeaOrmDeviceStore::new(
            db.clone(),
            device_metrics.clone(),
            alert_store.clone(),
        ));
        let auth: Arc<dyn AuthStore> = Arc::new(discovery_auth::SeaOrmAuthStore::new(db));
        // Own connection — `topology_rules`/`topology` need to share *a* connection with
        // each other (see the `DashboardState` field docs below), but not with `devices`
        // above; `device_id` inside `topology_device_keys`/`topology_claims` is
        // deliberately not an FK (cross-domain), so there's no constraint forcing it onto
        // the same database `devices` uses.
        let topology_db = discovery_migration::connect_in_memory_for_tests().await;

        let admin = auth
            .create_user("test-admin", "test-password", true, false, None)
            .await
            .unwrap();
        let token = auth
            .create_session(admin.id, chrono::Duration::hours(1))
            .await
            .unwrap();

        let state = DashboardState {
            store: Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await),
            alerts: Arc::new(AlertStateTracker::new()),
            alert_store,
            workers: Arc::new(WorkerRegistry::new()),
            logs: Arc::new(LogBuffer::new(1000)),
            profiles: Arc::new(SeaOrmProfileStore::new_in_memory_for_tests().await),
            matcher: Arc::new(ProfileMatcher::new(vec![])),
            discovery_configs: Arc::new(
                SeaOrmDiscoveryConfigStore::new_in_memory_for_tests().await,
            ),
            devices,
            device_metrics,
            settings: Arc::new(SeaOrmSettingsStore::new_in_memory_for_tests().await),
            auth,
            journal: Arc::new(
                discovery_journal::SeaOrmJournalStore::new_in_memory_for_tests().await,
            ),
            maintenance_windows: Arc::new(
                SeaOrmMaintenanceWindowStore::new_in_memory_for_tests().await,
            ),
            notification_rules: Arc::new(
                discovery_config_store::SeaOrmNotificationRuleStore::new_in_memory_for_tests()
                    .await,
            ),
            notification_channels: Arc::new(
                discovery_config_store::SeaOrmNotificationChannelStore::new_in_memory_for_tests()
                    .await,
            ),
            // Unlike `notification_rules`/`notification_channels` (unrelated domains, no
            // FK between them), `topology_rules` and `topology` **must** share one
            // connection here — `topology_device_keys`/`topology_claims.rule_name` is a
            // real `FOREIGN KEY` against `topology_rules.name` (same physical database by
            // construction, see `discovery_entities::topology_device_keys`'s docs), so two
            // independent in-memory databases would make every `apply_recompute` for a
            // rule created through this fixture's REST layer fail that constraint.
            topology_rules: Arc::new(discovery_config_store::SeaOrmTopologyRuleStore::new(
                topology_db.clone(),
            )),
            topology: Arc::new(discovery_topology::SeaOrmTopologyStore::new(topology_db)),
            group_alert_rules: Arc::new(
                discovery_config_store::SeaOrmGroupAlertRuleStore::new_in_memory_for_tests().await,
            ),
            assistant: Arc::new(
                discovery_assistant::SeaOrmAssistantStore::new_in_memory_for_tests().await,
            ),
            identity_chains: Arc::new(ActiveChains::new()),
            active_chains: Arc::new(ActiveChains::new()),
            reachability_chains: Arc::new(ActiveChains::new()),
            login_rate_limiter: Arc::new(LoginRateLimiter::default()),
            action_enqueue_lock: Arc::new(tokio::sync::Mutex::new(())),
        };
        (router(state.clone()), state, token)
    }

    /// Issues one request through the router and parses the body as JSON — `Value::Null`
    /// for an empty body (every `204 No Content` response in this crate), so callers can
    /// still match on it without a separate empty-body special case.
    /// Fake peer address every test request carries via a manually-inserted `ConnectInfo`
    /// extension — real serving (`main.rs`) gets this from `into_make_service_with_connect_info`,
    /// but these tests drive the bare `Router` through `oneshot`, which never populates it,
    /// so `login`'s `ConnectInfo<SocketAddr>` extractor would otherwise fail on every request.
    /// One fixed address for the whole suite is fine — only the dedicated rate-limit tests
    /// below care about distinguishing source IPs, and they build their own requests via
    /// [`login_req_from`] instead of this helper.
    fn test_peer_addr() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 12345))
    }

    async fn req(
        app: &Router,
        token: &str,
        method: &str,
        uri: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .extension(ConnectInfo(test_peer_addr()));
        let body = match &body {
            Some(v) => {
                builder = builder.header("content-type", "application/json");
                Body::from(serde_json::to_vec(v).unwrap())
            }
            None => Body::empty(),
        };
        let response = app
            .clone()
            .oneshot(builder.body(body).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        // Most bodies are JSON, but an `ApiError` (`(StatusCode, String)`) renders as
        // plain text via axum's blanket `IntoResponse` — fall back to wrapping it as a
        // JSON string rather than panicking, so a 404's error message is still inspectable.
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or_else(|_| {
                serde_json::Value::String(String::from_utf8_lossy(&bytes).into_owned())
            })
        };
        (status, json)
    }

    fn a_profile(name: &str, priority: i32, expression: &str) -> serde_json::Value {
        serde_json::json!({
            "profile": {"name": name, "priority": priority},
            "match": {"expression": expression},
            "metrics": {"poll": {}},
            "alerts": [],
        })
    }

    #[tokio::test]
    async fn profiles_full_crud_plus_list_pagination_search_sort() {
        let (app, _, token) = test_app().await;

        // Empty collection — {items: [], total: 0}, not a bare [] or an error.
        let (status, body) = req(&app, &token, "GET", "/api/profiles", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["total"], 0);
        assert_eq!(body["items"].as_array().unwrap().len(), 0);

        // Create (POST is upsert — no separate "create" verb in this API).
        let (status, _) = req(
            &app,
            &token,
            "POST",
            "/api/profiles",
            Some(a_profile("zebra", 5, "true")),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = req(
            &app,
            &token,
            "POST",
            "/api/profiles",
            Some(a_profile("apple", 10, "true")),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Read (list) — both present, total reflects the unfiltered count.
        let (_, body) = req(&app, &token, "GET", "/api/profiles", None).await;
        assert_eq!(body["total"], 2);

        // Read (single) — 200 for a known name, 404 for an unknown one.
        let (status, body) = req(&app, &token, "GET", "/api/profiles/apple", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["profile"]["priority"], 10);
        let (status, _) = req(&app, &token, "GET", "/api/profiles/does-not-exist", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Search — case-insensitive substring on name.
        let (_, body) = req(&app, &token, "GET", "/api/profiles?search=ZEB", None).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["profile"]["name"], "zebra");

        // Sort — default (name, asc) puts "apple" before "zebra"; reversed with sort_dir=desc.
        let (_, body) = req(&app, &token, "GET", "/api/profiles", None).await;
        assert_eq!(body["items"][0]["profile"]["name"], "apple");
        let (_, body) = req(
            &app,
            &token,
            "GET",
            "/api/profiles?sort_by=priority&sort_dir=desc",
            None,
        )
        .await;
        assert_eq!(body["items"][0]["profile"]["name"], "apple"); // priority 10, highest first

        // Pagination — page_size=1 slices to one item per page without changing `total`.
        let (_, body) = req(
            &app,
            &token,
            "GET",
            "/api/profiles?page_size=1&page=2",
            None,
        )
        .await;
        assert_eq!(body["total"], 2);
        assert_eq!(body["items"].as_array().unwrap().len(), 1);
        assert_eq!(body["items"][0]["profile"]["name"], "zebra");

        // Update (POST upsert again, same name) — priority actually changes.
        let (status, _) = req(
            &app,
            &token,
            "POST",
            "/api/profiles",
            Some(a_profile("apple", 99, "true")),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, body) = req(&app, &token, "GET", "/api/profiles/apple", None).await;
        assert_eq!(body["profile"]["priority"], 99);

        // Delete — gone from both single-read and the list.
        let (status, _) = req(&app, &token, "DELETE", "/api/profiles/apple", None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = req(&app, &token, "GET", "/api/profiles/apple", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (_, body) = req(&app, &token, "GET", "/api/profiles", None).await;
        assert_eq!(body["total"], 1);
    }

    /// 2026-09-17 audit finding #3: before `ProfileMatcher::validate_expression`/
    /// `AlertEvaluator::validate_expression` were wired into this handler, a profile with a
    /// syntactically broken `match.expression` (or a broken alert-rule expression) saved
    /// with a plain `204`, exactly like a well-formed one — the only symptom was a much
    /// later, disconnected-looking `WARN "job failed"` on the `dedup` queue. Both must now
    /// be rejected with `400` and a message naming the offending field, at save time, and
    /// the broken profile must never actually reach storage.
    #[tokio::test]
    async fn upsert_profile_rejects_a_broken_match_expression_and_a_broken_alert_expression() {
        let (app, _, token) = test_app().await;

        let mut broken_match = a_profile(
            "broken-match",
            0,
            "metrics.sys_object_id == ((( broken rhai",
        );
        let (status, body) = req(
            &app,
            &token,
            "POST",
            "/api/profiles",
            Some(broken_match.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.as_str()
                .unwrap_or_default()
                .contains("match.expression"),
            "error must name the field: {body}"
        );

        // Never actually persisted — the earlier 400 must have stopped it before storage.
        let (status, _) = req(&app, &token, "GET", "/api/profiles/broken-match", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // A well-formed match.expression but a broken alert-rule expression must be
        // rejected too, naming that alert rule specifically.
        broken_match["match"]["expression"] = serde_json::json!("true");
        broken_match["alerts"] = serde_json::json!([{
            "name": "bad_alert",
            "level": "warning",
            "expression": "metrics.cpu > ((( broken rhai",
            "message": "cpu high",
        }]);
        let (status, body) = req(&app, &token, "POST", "/api/profiles", Some(broken_match)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.as_str().unwrap_or_default().contains("bad_alert"),
            "error must name the offending alert rule: {body}"
        );
        let (status, _) = req(&app, &token, "GET", "/api/profiles/broken-match", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn ssh_profile_requires_device_write_and_a_read_only_command() {
        let mut profile: ProfileFile = serde_json::from_value(a_profile("ssh", 0, "true")).unwrap();
        profile.metrics.poll.insert(
            "running_config".to_string(),
            discovery_dsl::MetricSpec::SshCommand {
                command: "show running-config".to_string(),
                schedule: None,
                history_retention_secs: None,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
                enabled: true,
            },
        );
        let read_only = AuthenticatedUser {
            id: Uuid::new_v4(),
            username: "reader".into(),
            is_admin: false,
            must_change_password: false,
            role_id: None,
            permissions: HashMap::from([(Domain::Profiles, AccessLevel::Write)]),
        };
        assert_eq!(
            validate_ssh_profile_access(&profile, &read_only)
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );

        let device_writer = AuthenticatedUser {
            permissions: HashMap::from([
                (Domain::Profiles, AccessLevel::Write),
                (Domain::Devices, AccessLevel::Write),
            ]),
            ..read_only.clone()
        };
        assert!(validate_ssh_profile_access(&profile, &device_writer).is_ok());

        if let Some(discovery_dsl::MetricSpec::SshCommand { command, .. }) =
            profile.metrics.poll.get_mut("running_config")
        {
            *command = "show running-config; reload".to_string();
        }
        assert_eq!(
            validate_ssh_profile_access(&profile, &device_writer)
                .unwrap_err()
                .0,
            StatusCode::BAD_REQUEST
        );
    }

    fn a_discovery_config(name: &str, enabled: bool) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "enabled": enabled,
            "schedule": {"type": "calendar", "months": [], "days_of_month": [], "time": "03:00:00"},
            "subnets": [],
        })
    }

    #[tokio::test]
    async fn discovery_configs_full_crud_plus_list_filter_search_sort() {
        let (app, _, token) = test_app().await;

        let (_, body) = req(&app, &token, "GET", "/api/discovery-configs", None).await;
        assert_eq!(body["total"], 0);

        let (status, _) = req(
            &app,
            &token,
            "POST",
            "/api/discovery-configs",
            Some(a_discovery_config("office", true)),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = req(
            &app,
            &token,
            "POST",
            "/api/discovery-configs",
            Some(a_discovery_config("warehouse", false)),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let (_, body) = req(&app, &token, "GET", "/api/discovery-configs", None).await;
        assert_eq!(body["total"], 2);

        let (status, body) = req(&app, &token, "GET", "/api/discovery-configs/office", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["enabled"], true);
        let (status, _) = req(
            &app,
            &token,
            "GET",
            "/api/discovery-configs/does-not-exist",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Search by name.
        let (_, body) = req(
            &app,
            &token,
            "GET",
            "/api/discovery-configs?search=ware",
            None,
        )
        .await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["name"], "warehouse");

        // Filter by enabled.
        let (_, body) = req(
            &app,
            &token,
            "GET",
            "/api/discovery-configs?enabled=false",
            None,
        )
        .await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["name"], "warehouse");

        // Update — flip enabled on an existing name via the same upsert route.
        let (status, _) = req(
            &app,
            &token,
            "POST",
            "/api/discovery-configs",
            Some(a_discovery_config("warehouse", true)),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, body) = req(
            &app,
            &token,
            "GET",
            "/api/discovery-configs/warehouse",
            None,
        )
        .await;
        assert_eq!(body["enabled"], true);

        // Manual "run now" — deliberately does not require `enabled` (see the handler's
        // docs); 0 subnets means 0 candidates enqueued, but the endpoint itself must work.
        let (status, body) = req(
            &app,
            &token,
            "POST",
            "/api/discovery-configs/office/run",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["enqueued"], 0);
        let (status, _) = req(
            &app,
            &token,
            "POST",
            "/api/discovery-configs/does-not-exist/run",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Delete.
        let (status, _) = req(
            &app,
            &token,
            "DELETE",
            "/api/discovery-configs/office",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, body) = req(&app, &token, "GET", "/api/discovery-configs", None).await;
        assert_eq!(body["total"], 1);
    }

    /// Devices have no REST "create" — in this app's model they only ever come from the
    /// discovery pipeline (see `get_device_by_id`'s docs) — so this seeds one straight
    /// through `DeviceStore::resolve`, the same entry point `DedupHandler` uses, and
    /// exercises everything else: read (list + single, search/filter/sort/pagination),
    /// update (enable toggle, bulk enable, metric override), delete.
    #[tokio::test]
    async fn devices_read_update_delete_plus_list_search_filter_sort_pagination() {
        let (app, state, token) = test_app().await;

        let (id_a, _) = state
            .devices
            .resolve(discovery_core::DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        let (id_b, _) = state
            .devices
            .resolve(discovery_core::DeviceFacts {
                ip: "10.0.0.2".into(),
            })
            .await
            .unwrap();

        let (_, body) = req(&app, &token, "GET", "/api/devices", None).await;
        assert_eq!(body["total"], 2);

        // Single read — 200 for a known id, 404 for a random unknown one.
        let (status, body) = req(&app, &token, "GET", &format!("/api/devices/{id_a}"), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["facts"]["ip"], "10.0.0.1");
        let (status, _) = req(
            &app,
            &token,
            "GET",
            &format!("/api/devices/{}", Uuid::new_v4()),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Search — matches IP.
        let (_, body) = req(&app, &token, "GET", "/api/devices?search=10.0.0.2", None).await;
        assert_eq!(body["total"], 1);

        // Sort — numeric IP order (not lexicographic), asc by default.
        let (_, body) = req(
            &app,
            &token,
            "GET",
            "/api/devices?sort_by=ip&sort_dir=asc",
            None,
        )
        .await;
        assert_eq!(body["items"][0]["facts"]["ip"], "10.0.0.1");

        // Pagination.
        let (_, body) = req(&app, &token, "GET", "/api/devices?page_size=1&page=1", None).await;
        assert_eq!(body["total"], 2);
        assert_eq!(body["items"].as_array().unwrap().len(), 1);

        // Update — per-device enable, then bulk-disable-all.
        let (status, _) = req(
            &app,
            &token,
            "PUT",
            &format!("/api/devices/{id_a}/enabled"),
            Some(serde_json::json!({"enabled": false})),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(
            !state
                .devices
                .get_device(id_a)
                .await
                .unwrap()
                .unwrap()
                .enabled
        );
        let (status, body) = req(
            &app,
            &token,
            "PUT",
            "/api/devices/enabled",
            Some(serde_json::json!({"enabled": true})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["touched"], 2);
        assert!(
            state
                .devices
                .get_device(id_a)
                .await
                .unwrap()
                .unwrap()
                .enabled
        );
        assert!(
            state
                .devices
                .get_device(id_b)
                .await
                .unwrap()
                .unwrap()
                .enabled
        );

        // A filtered bulk action must not touch devices outside its current selection.
        let (status, body) = req(
            &app,
            &token,
            "PUT",
            "/api/devices/enabled?search=10.0.0.1",
            Some(serde_json::json!({"enabled": false})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["touched"], 1);
        assert!(
            !state
                .devices
                .get_device(id_a)
                .await
                .unwrap()
                .unwrap()
                .enabled
        );
        assert!(
            state
                .devices
                .get_device(id_b)
                .await
                .unwrap()
                .unwrap()
                .enabled
        );

        let (status, body) = req(
            &app,
            &token,
            "PUT",
            "/api/devices/enabled?cidr=192.0.2.0%2F24",
            Some(serde_json::json!({"enabled": false})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["touched"], 0);
        assert!(
            state
                .devices
                .get_device(id_b)
                .await
                .unwrap()
                .unwrap()
                .enabled
        );

        // TASK-20260921-020 — an unknown device id used to still report 204 (the store's
        // `UPDATE ... WHERE device_id = ?` silently affects zero rows and returns Ok either
        // way), falsely implying the toggle took effect on something.
        let (status, _) = req(
            &app,
            &token,
            "PUT",
            &format!("/api/devices/{}/enabled", Uuid::new_v4()),
            Some(serde_json::json!({"enabled": false})),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        // A malformed id in the path is rejected by axum's own `Path<Uuid>` extraction
        // before the handler ever runs — 400, not 404 (it's not "a UUID that doesn't
        // exist", it's not a UUID at all).
        let (status, _) = req(
            &app,
            &token,
            "PUT",
            "/api/devices/not-a-uuid/enabled",
            Some(serde_json::json!({"enabled": false})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Device deletion cascades durable alerts too; the process-local tracker must
        // forget the same device or the in-memory incidents view keeps a ghost alert.
        let now = chrono::Utc::now();
        assert!(matches!(
            state.alerts.observe(
                id_a,
                "10.0.0.1",
                "device_deleted",
                None,
                AlertLevel::Critical,
                "test".to_string(),
                None,
                true,
                false,
                None,
                chrono::Duration::zero(),
                now,
            ),
            discovery_core::AlertTransition::Activated(_)
        ));
        assert_eq!(state.alerts.active_alerts_for_device(id_a).len(), 1);

        // Delete.
        let (status, _) = req(
            &app,
            &token,
            "DELETE",
            &format!("/api/devices/{id_a}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(state.alerts.active_alerts_for_device(id_a).is_empty());
        let (_, body) = req(&app, &token, "GET", "/api/devices", None).await;
        assert_eq!(body["total"], 1);
    }

    #[tokio::test]
    async fn operator_action_routes_enforce_rbac_dedupe_state_and_cancellation() {
        let (app, state, admin_token) = test_app().await;
        let (device_id, _) = state
            .devices
            .resolve(discovery_core::DeviceFacts {
                ip: "192.0.2.44".to_string(),
            })
            .await
            .unwrap();
        let role = state
            .auth
            .create_role(
                "device-readers",
                HashMap::from([(Domain::Devices, AccessLevel::Read)]),
            )
            .await
            .unwrap();
        let reader = state
            .auth
            .create_user(
                "reader-action",
                "test-password",
                false,
                false,
                Some(role.id),
            )
            .await
            .unwrap();
        let reader_token = state
            .auth
            .create_session(reader.id, chrono::Duration::hours(1))
            .await
            .unwrap();
        let path = format!("/api/devices/{device_id}/actions/test");

        let (status, _) = req(&app, &reader_token, "POST", &path, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, started) = req(&app, &admin_token, "POST", &path, None).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let job_id = started["job_id"].as_i64().unwrap();
        assert_eq!(started["status"], "pending");
        let (status, _) = req(&app, &admin_token, "POST", &path, None).await;
        assert_eq!(status, StatusCode::CONFLICT);
        let status_path = format!("/api/devices/{device_id}/actions/jobs/{job_id}");
        let (status, visible) = req(&app, &reader_token, "GET", &status_path, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(visible["status"], "pending");
        let (status, _) = req(&app, &reader_token, "DELETE", &status_path, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = req(&app, &admin_token, "DELETE", &status_path, None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, cancelled) = req(&app, &admin_token, "GET", &status_path, None).await;
        assert_eq!(cancelled["status"], "cancelled");
        let (status, _) = req(
            &app,
            &admin_token,
            "POST",
            &format!("/api/devices/{device_id}/actions/rediscover"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let (backup_device_id, _) = state
            .devices
            .resolve(discovery_core::DeviceFacts {
                ip: "192.0.2.45".to_string(),
            })
            .await
            .unwrap();
        let backup_id = state
            .store
            .enqueue(
                QueueKind::OperatorAction,
                serde_json::json!(OperatorActionPayload {
                    alert_id: None,
                    device_id: backup_device_id,
                    action: OperatorAction::Backup,
                    username: "admin".to_string(),
                }),
                Some(&backup_device_id.to_string()),
            )
            .await
            .unwrap();
        let backup_path = format!("/api/devices/{backup_device_id}/actions/jobs/{backup_id}");
        let (status, _) = req(&app, &reader_token, "GET", &backup_path, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = req(&app, &admin_token, "GET", &backup_path, None).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = req(
            &app,
            &admin_token,
            "DELETE",
            &format!("/api/queues/operator_action/jobs/{backup_id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        state.devices.set_enabled(device_id, false).await.unwrap();
        let (status, _) = req(&app, &admin_token, "POST", &path, None).await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    /// Direct user request 2026-08-28: "ручное создание устройств - указание ip,
    /// профиля, ручное добавление метрик". The one bypass of the discovery pipeline —
    /// every other device arrives through Discovery -> SnmpPoll -> Dedup -> ProfileApply.
    #[tokio::test]
    async fn create_device_manually_with_profile_and_seed_metrics() {
        let (app, state, token) = test_app().await;
        let (status, _) = req(
            &app,
            &token,
            "POST",
            "/api/profiles",
            Some(a_profile("manual-profile", 10, "true")),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let (status, body) = req(
            &app,
            &token,
            "POST",
            "/api/devices",
            Some(serde_json::json!({"ip": "10.5.0.9", "profile": "manual-profile", "metrics": {"area_name": "Воронеж"}})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["facts"]["ip"], "10.5.0.9");
        assert_eq!(body["profile"], "manual-profile");
        assert_eq!(
            body["created"], true,
            "TASK-20260921-019: a genuinely new device must report created: true"
        );
        let metrics = body["metrics"].as_array().unwrap();
        let area = metrics
            .iter()
            .find(|m| m["name"] == "area_name")
            .expect("seeded metric must be present");
        assert_eq!(area["value"], "Воронеж");
        let device_id = body["id"].as_str().unwrap().to_string();

        // Idempotent by IP — posting the same IP again resolves to the same device, not a
        // second one, same contract `DeviceStore::resolve` already guarantees.
        let (status, body2) = req(
            &app,
            &token,
            "POST",
            "/api/devices",
            Some(serde_json::json!({"ip": "10.5.0.9"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body2["id"], device_id);
        assert_eq!(body2["created"], false, "TASK-20260921-019: re-resolving an existing ip must report created: false, not look identical to a fresh create");
        let (_, list) = req(&app, &token, "GET", "/api/devices", None).await;
        assert_eq!(list["total"], 1);
        assert!(list["items"][0].get("created").is_none(), "created is create_device-only — list/get views must not carry a stale/misleading value");

        // Blank ip and an unknown profile are both rejected.
        let (status, _) = req(
            &app,
            &token,
            "POST",
            "/api/devices",
            Some(serde_json::json!({"ip": "  "})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = req(
            &app,
            &token,
            "POST",
            "/api/devices",
            Some(serde_json::json!({"ip": "10.5.0.10", "profile": "does-not-exist"})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            state.devices.id_by_ip("10.5.0.10").await.unwrap().is_none(),
            "a rejected profile must not leave a half-created device behind either"
        );
    }

    /// TASK-20260921-018 — `POST /api/devices` only checked for a non-empty string; any
    /// garbage saved fine as a "device" that polling could then never actually reach.
    #[tokio::test]
    async fn create_device_rejects_malformed_and_ipv6_but_accepts_loopback_and_private() {
        let (app, state, token) = test_app().await;

        for bad_ip in [
            "not-an-ip",
            "10.0.0.999",
            "10.0.0",
            "10.0.0.1.5",
            "::1",
            "2001:db8::1",
            "10.0.0.01",
        ] {
            let (status, body) = req(
                &app,
                &token,
                "POST",
                "/api/devices",
                Some(serde_json::json!({"ip": bad_ip})),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "'{bad_ip}' must be rejected: {body}"
            );
            assert!(
                state.devices.id_by_ip(bad_ip).await.unwrap().is_none(),
                "a rejected ip must not leave a device row behind: {bad_ip}"
            );
        }
        // IPv6 specifically must get a clear, distinguishable message (not just a generic
        // parse failure) — this project has no IPv6 support anywhere downstream (SNMP
        // polling, subnet-selector matching are all Ipv4Addr-only).
        let (_, body) = req(
            &app,
            &token,
            "POST",
            "/api/devices",
            Some(serde_json::json!({"ip": "::1"})),
        )
        .await;
        assert!(
            body.as_str()
                .unwrap_or_default()
                .to_lowercase()
                .contains("ipv6"),
            "IPv6 rejection must say so explicitly: {body}"
        );

        // No address-class restriction: loopback and private ranges are the expected
        // common case here (real deployments monitor RFC1918 devices; manually adding a
        // discovery-devicefarm instance on 127.0.0.x is a legitimate workflow), unlike the
        // SSRF-motivated forbidden-range checks elsewhere in this file for webhook/service-
        // check targets.
        for good_ip in ["127.0.0.1", "10.0.0.5", "192.168.1.1"] {
            let (status, body) = req(
                &app,
                &token,
                "POST",
                "/api/devices",
                Some(serde_json::json!({"ip": good_ip})),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "'{good_ip}' must be accepted: {body}"
            );
            assert_eq!(body["facts"]["ip"], good_ip);
        }
    }

    /// SNMP Trap ingestion (2026-08-30) — a manually-created device needs
    /// `snmp_credentials` set for the trap listener to ever validate an incoming trap
    /// against it (see `discovery-agent::trap_ingest::auth_matches`'s docs); without
    /// `snmp_auth` in the request body there'd be no way to give one a working trap setup
    /// short of routing it through real `SnmpPoll` negotiation first.
    #[tokio::test]
    async fn create_device_manually_with_snmp_auth_sets_credentials() {
        let (app, state, token) = test_app().await;
        let (status, body) = req(
            &app,
            &token,
            "POST",
            "/api/devices",
            Some(serde_json::json!({"ip": "10.5.0.20", "snmp_auth": {"kind": "community", "version": "v2c", "community": "public"}, "snmp_port": 1161})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let device_id = state.devices.id_by_ip("10.5.0.20").await.unwrap().unwrap();
        let device = state.devices.get_device(device_id).await.unwrap().unwrap();
        let credentials = device
            .snmp_credentials
            .expect("snmp_auth in the request must set snmp_credentials");
        assert_eq!(credentials.port, 1161);
        assert_eq!(
            credentials.auth,
            discovery_core::SnmpAuth::Community {
                version: discovery_core::SnmpVersion::V2c,
                community: "public".to_string()
            }
        );
        let _ = body;
    }

    /// TASK-20260921-019 — `resolve()` has get-or-create semantics (needed for the
    /// automatic discovery pipeline's own idempotent re-resolves), but `create_device`
    /// used to blindly reapply `snmp_auth`/`profile`/`metrics` regardless, so a POST that
    /// happened to collide with an already-known IP silently overwrote a real device's
    /// credentials/profile with whatever the new request carried — no error, no signal,
    /// identical-looking 200 either way. Confirms none of those three fields touch an
    /// already-existing device anymore.
    #[tokio::test]
    async fn create_device_on_an_existing_ip_does_not_overwrite_credentials_profile_or_metrics() {
        let (app, state, token) = test_app().await;
        let (status, _) = req(
            &app,
            &token,
            "POST",
            "/api/profiles",
            Some(a_profile("original-profile", 10, "true")),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = req(
            &app,
            &token,
            "POST",
            "/api/profiles",
            Some(a_profile("attacker-profile", 10, "true")),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let (status, body) = req(
            &app,
            &token,
            "POST",
            "/api/devices",
            Some(serde_json::json!({
                "ip": "10.5.0.40",
                "profile": "original-profile",
                "snmp_auth": {"kind": "community", "version": "v2c", "community": "original-secret"},
                "metrics": {"note": "original"},
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["created"], true);
        let device_id = body["id"].as_str().unwrap().to_string();

        // Re-POST the same IP with entirely different profile/credentials/metrics.
        let (status, body2) = req(
            &app,
            &token,
            "POST",
            "/api/devices",
            Some(serde_json::json!({
                "ip": "10.5.0.40",
                "profile": "attacker-profile",
                "snmp_auth": {"kind": "community", "version": "v2c", "community": "clobbered-secret"},
                "metrics": {"note": "clobbered"},
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body2["id"], device_id,
            "same ip must still resolve to the same device"
        );
        assert_eq!(body2["created"], false, "the second POST must explicitly report that it resolved to an existing device, not a new one");
        assert_eq!(
            body2["profile"], "original-profile",
            "the second POST's profile must not have been applied"
        );

        let device = state
            .devices
            .get_device(Uuid::parse_str(&device_id).unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            device.snmp_credentials.unwrap().auth,
            discovery_core::SnmpAuth::Community {
                version: discovery_core::SnmpVersion::V2c,
                community: "original-secret".to_string()
            },
            "the second POST's snmp_auth must not have overwritten the original credentials"
        );
        let note = body2["metrics"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["name"] == "note")
            .expect("original metric must still be present");
        assert_eq!(
            note["value"], "original",
            "the second POST's metrics must not have overwritten the original value"
        );

        // The Журнал entry for the no-op re-POST still says "Создано устройство" (no
        // per-call opt-out exists in the shared journal middleware — out of scope here),
        // but its `details` must at least be honest about what actually happened.
        let (_, journal) = req(&app, &token, "GET", "/api/journal?domain=devices", None).await;
        let entries: Vec<_> = journal["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["object"] == "10.5.0.40")
            .collect();
        assert_eq!(entries.len(), 2, "one entry per POST");
        assert_eq!(
            entries[0]["details"]["created"], false,
            "the second (most recent) POST's entry must record that nothing was created"
        );
        assert_eq!(
            entries[1]["details"]["created"], true,
            "the first POST's entry must record that it actually created the device"
        );
    }

    /// `set_ssh_credentials` (the store method) always encrypts, unconditionally requiring
    /// a configured secret key — see `discovery_core::secret::encrypt_ssh_auth_secrets`'s
    /// docs for why SSH has no plaintext-ok branch the way `SnmpAuth::Community` does.
    /// `test_app()`'s `DeviceStore` never has one configured, so this is the SSH-side
    /// mirror of `discovery_config_with_a_v3_credential_fails_loudly_without_a_secret_key_
    /// configured` above: without a key, the endpoint must fail loudly (500), not silently
    /// store an unencrypted credential or panic.
    #[tokio::test]
    async fn put_ssh_credentials_without_a_secret_key_configured_fails_loudly() {
        let (app, state, token) = test_app().await;
        let (device_id, _) = state
            .devices
            .resolve(discovery_core::DeviceFacts {
                ip: "10.5.0.30".to_string(),
            })
            .await
            .unwrap();

        let (status, body) = req(
            &app,
            &token,
            "PUT",
            &format!("/api/devices/{device_id}/ssh_credentials"),
            Some(serde_json::json!({"username": "admin", "auth": {"kind": "password", "password": "hunter2"}, "port": 2222})),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {body}");
    }

    /// Same request as above, but through a store that *does* have a key configured —
    /// proves the dedicated `PUT /api/devices/:id/ssh_credentials` endpoint (see
    /// `set_ssh_credentials`'s docs) actually round-trips credentials onto an *existing*
    /// device once a deployment opts in, not just that the no-key case fails correctly.
    /// Unlike `snmp_auth`, which only ever gets set through `POST /api/devices` at
    /// creation time, this must work on a device that already exists — the common case:
    /// one that arrived through the normal discovery pipeline and now needs SSH
    /// credentials attached for a `MetricSpec::SshCommand` metric.
    #[tokio::test]
    async fn put_ssh_credentials_with_a_secret_key_configured_round_trips_onto_an_existing_device()
    {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        let (_, state, token) = test_app().await;
        let db = discovery_migration::connect_in_memory_for_tests().await;
        let device_metrics: Arc<dyn DeviceMetricsStore> =
            Arc::new(SeaOrmDeviceMetricsStore::new(db.clone()));
        let alert_store: Arc<dyn AlertStore> =
            Arc::new(discovery_alerts::SeaOrmAlertStore::new(db.clone()));
        let key = Arc::new(
            discovery_core::secret::SecretKey::from_base64(&STANDARD.encode([5u8; 32])).unwrap(),
        );
        let devices: Arc<dyn DeviceStore> = Arc::new(
            SeaOrmDeviceStore::new(db, device_metrics.clone(), alert_store).with_secret_key(key),
        );
        let (device_id, _) = devices
            .resolve(discovery_core::DeviceFacts {
                ip: "10.5.0.30".to_string(),
            })
            .await
            .unwrap();
        let app = router(DashboardState {
            devices: devices.clone(),
            device_metrics,
            ..state
        });

        let (status, body) = req(
            &app,
            &token,
            "PUT",
            &format!("/api/devices/{device_id}/ssh_credentials"),
            Some(serde_json::json!({"username": "admin", "auth": {"kind": "password", "password": "hunter2"}, "port": 2222})),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "body: {body}");

        let device = devices.get_device(device_id).await.unwrap().unwrap();
        let credentials = device
            .ssh_credentials
            .expect("PUT must set ssh_credentials");
        assert_eq!(credentials.username, "admin");
        assert_eq!(credentials.port, 2222);
        assert_eq!(
            credentials.auth,
            discovery_core::SshAuth::Password {
                password: "hunter2".to_string()
            }
        );
        assert_eq!(credentials.known_host_key, None, "this endpoint never accepts a caller-supplied host key fingerprint — it's always learned via trust-on-first-use");
    }

    /// CWE-295 fix — unlike the password/private-key secret payload, a pinned SSH host
    /// key fingerprint is not sensitive (it's the public key the device already broadcasts
    /// to anyone who connects) and must come back from `GET` untouched, not blanked the
    /// way `redact_ssh_credentials` blanks `auth`'s secret fields.
    #[tokio::test]
    async fn get_device_reflects_a_pinned_ssh_host_key_fingerprint_unredacted() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        let (_, state, token) = test_app().await;
        let db = discovery_migration::connect_in_memory_for_tests().await;
        let device_metrics: Arc<dyn DeviceMetricsStore> =
            Arc::new(SeaOrmDeviceMetricsStore::new(db.clone()));
        let alert_store: Arc<dyn AlertStore> =
            Arc::new(discovery_alerts::SeaOrmAlertStore::new(db.clone()));
        let key = Arc::new(
            discovery_core::secret::SecretKey::from_base64(&STANDARD.encode([11u8; 32])).unwrap(),
        );
        let devices: Arc<dyn DeviceStore> = Arc::new(
            SeaOrmDeviceStore::new(db, device_metrics.clone(), alert_store).with_secret_key(key),
        );
        let app = router(DashboardState {
            devices: devices.clone(),
            device_metrics,
            ..state
        });

        let (device_id, _) = devices
            .resolve(discovery_core::DeviceFacts {
                ip: "10.5.0.33".to_string(),
            })
            .await
            .unwrap();
        req(&app, &token, "PUT", &format!("/api/devices/{device_id}/ssh_credentials"), Some(serde_json::json!({"username": "admin", "auth": {"kind": "password", "password": "hunter2"}, "port": 22}))).await;

        let (_, before) = req(
            &app,
            &token,
            "GET",
            &format!("/api/devices/{device_id}"),
            None,
        )
        .await;
        assert_eq!(
            before["ssh_credentials"]["known_host_key"],
            serde_json::Value::Null,
            "a freshly-set credential has no pinned host key yet"
        );

        devices
            .pin_ssh_host_key(device_id, "SHA256:testfingerprint".to_string())
            .await
            .unwrap();

        let (_, after) = req(
            &app,
            &token,
            "GET",
            &format!("/api/devices/{device_id}"),
            None,
        )
        .await;
        assert_eq!(
            after["ssh_credentials"]["known_host_key"],
            "SHA256:testfingerprint"
        );
    }

    /// 2026-09-17 audit finding #5: the "SSH-креды" modal's text claims the password never
    /// comes back from the server, but `GET /api/devices`/`GET /api/devices/:id` used to
    /// serialize the real, decrypted `Device.ssh_credentials` straight through — the
    /// plaintext password was visible in every ordinary device-list fetch's response body,
    /// not just some special endpoint. Covers both a password credential and a
    /// passphrase-protected private key, and both GET routes, and confirms the
    /// non-secret fields (`username`/`port`/`auth.kind`) the modal legitimately reads back
    /// still survive untouched — see `redact_ssh_credentials`'s docs.
    #[tokio::test]
    async fn get_devices_never_returns_the_real_ssh_secret() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        let (_, state, token) = test_app().await;
        let db = discovery_migration::connect_in_memory_for_tests().await;
        let device_metrics: Arc<dyn DeviceMetricsStore> =
            Arc::new(SeaOrmDeviceMetricsStore::new(db.clone()));
        let alert_store: Arc<dyn AlertStore> =
            Arc::new(discovery_alerts::SeaOrmAlertStore::new(db.clone()));
        let key = Arc::new(
            discovery_core::secret::SecretKey::from_base64(&STANDARD.encode([7u8; 32])).unwrap(),
        );
        let devices: Arc<dyn DeviceStore> = Arc::new(
            SeaOrmDeviceStore::new(db, device_metrics.clone(), alert_store).with_secret_key(key),
        );
        let app = router(DashboardState {
            devices: devices.clone(),
            device_metrics,
            ..state
        });

        let (device_a, _) = devices
            .resolve(discovery_core::DeviceFacts {
                ip: "10.5.0.31".to_string(),
            })
            .await
            .unwrap();
        req(&app, &token, "PUT", &format!("/api/devices/{device_a}/ssh_credentials"), Some(serde_json::json!({"username": "admin", "auth": {"kind": "password", "password": "hunter2"}, "port": 2222}))).await;

        let (device_b, _) = devices
            .resolve(discovery_core::DeviceFacts {
                ip: "10.5.0.32".to_string(),
            })
            .await
            .unwrap();
        req(
            &app,
            &token,
            "PUT",
            &format!("/api/devices/{device_b}/ssh_credentials"),
            Some(serde_json::json!({"username": "root", "auth": {"kind": "private_key", "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----", "passphrase": "hunter3"}, "port": 22})),
        )
        .await;

        devices
            .set_snmp_credentials(
                device_a,
                discovery_core::SnmpCredentials {
                    auth: discovery_core::SnmpAuth::Community {
                        version: discovery_core::SnmpVersion::V2c,
                        community: "private-v2c-secret".into(),
                    },
                    port: 161,
                },
            )
            .await
            .unwrap();
        devices
            .set_snmp_credentials(
                device_b,
                discovery_core::SnmpCredentials {
                    auth: discovery_core::SnmpAuth::UsmV3(discovery_core::SnmpV3Credentials {
                        user: "snmp-user".into(),
                        auth: Some(discovery_core::SnmpV3AuthCreds {
                            protocol: discovery_core::SnmpAuthProtocol::Sha256,
                            passphrase: "auth-pass-secret".into(),
                        }),
                        priv_: Some(discovery_core::SnmpV3PrivCreds {
                            protocol: discovery_core::SnmpPrivProtocol::Aes128,
                            passphrase: "priv-pass-secret".into(),
                        }),
                    }),
                    port: 161,
                },
            )
            .await
            .unwrap();

        // The list endpoint — the audit's own reproduction: "используемый для списка
        // устройств".
        let (status, body) = req(&app, &token, "GET", "/api/devices?page_size=50", None).await;
        assert_eq!(status, StatusCode::OK);
        let dump = body.to_string();
        assert!(
            !dump.contains("hunter2"),
            "the password must never appear anywhere in the list response: {dump}"
        );
        assert!(
            !dump.contains("hunter3"),
            "the passphrase must never appear anywhere in the list response: {dump}"
        );
        assert!(
            !dump.contains("BEGIN OPENSSH PRIVATE KEY"),
            "the private key body must never appear anywhere in the list response: {dump}"
        );
        assert!(
            !dump.contains("private-v2c-secret"),
            "v2c community must never appear in the list response: {dump}"
        );
        assert!(
            !dump.contains("auth-pass-secret"),
            "v3 auth passphrase must never appear in the list response: {dump}"
        );
        assert!(
            !dump.contains("priv-pass-secret"),
            "v3 privacy passphrase must never appear in the list response: {dump}"
        );

        // The single-device endpoint too, for both credential shapes — and confirm the
        // legitimately-shown fields (username/port/auth kind) survive.
        let (_, a) = req(
            &app,
            &token,
            "GET",
            &format!("/api/devices/{device_a}"),
            None,
        )
        .await;
        assert_eq!(a["ssh_credentials"]["username"], "admin");
        assert_eq!(a["ssh_credentials"]["port"], 2222);
        assert_eq!(a["ssh_credentials"]["auth"]["kind"], "password");
        assert_eq!(
            a["ssh_credentials"]["auth"]["password"], "",
            "must be blanked, not the real secret"
        );

        let (_, b) = req(
            &app,
            &token,
            "GET",
            &format!("/api/devices/{device_b}"),
            None,
        )
        .await;
        assert_eq!(b["ssh_credentials"]["username"], "root");
        assert_eq!(b["ssh_credentials"]["auth"]["kind"], "private_key");
        assert_eq!(
            b["ssh_credentials"]["auth"]["private_key"], "",
            "must be blanked, not the real secret"
        );
        assert_eq!(
            b["ssh_credentials"]["auth"]["passphrase"], "",
            "must be blanked, not the real secret"
        );
        assert!(
            a["snmp_credentials"].is_null(),
            "v2c credentials must be omitted from device reads"
        );
        assert!(
            b["snmp_credentials"].is_null(),
            "v3 credentials must be omitted from device reads"
        );
    }

    #[tokio::test]
    async fn put_ssh_credentials_on_an_unknown_device_returns_not_found() {
        let (app, state, token) = test_app().await;
        let _ = &state;
        let (status, _) = req(
            &app,
            &token,
            "PUT",
            &format!("/api/devices/{}/ssh_credentials", Uuid::new_v4()),
            Some(serde_json::json!({"username": "admin", "auth": {"kind": "password", "password": "hunter2"}})),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    fn an_alert(
        name: &str,
        ip: &str,
        device_id: Uuid,
        level: AlertLevel,
        state: AlertState,
    ) -> Alert {
        let now = chrono::Utc::now();
        Alert {
            details: Default::default(),
            id: Uuid::new_v4(),
            device_id,
            device_ip: ip.to_string(),
            name: name.to_string(),
            row_key: None,
            level,
            message: "test alert".to_string(),
            state: state.clone(),
            facts: None,
            first_seen: now,
            last_seen: now,
            cleared_at: if state == AlertState::Cleared {
                Some(now)
            } else {
                None
            },
            closed_by: None,
            acknowledged_by: None,
            acknowledged_at: None,
            snoozed_until: None,
            snoozed_by: None,
            auto_clear_reason: None,
            repeat_count: 0,
            escalation_level: 0,
            repeated_at: None,
            escalation_reason: None,
            flapping: false,
            suppression_reason: None,
            comment_count: 0,
            suppressed_by_alert_id: None,
            reopened_from_alert_id: None,
        }
    }

    /// Alerts have no REST "create" either — they're only ever produced by
    /// `AlertEvalHandler`/`AlertStateTracker` — so this seeds directly through
    /// `AlertStore::upsert`, the same write path that handler uses, and exercises read
    /// (list + single, filter/sort/pagination), the comment thread, and the two distinct
    /// "close" vs "delete" actions (direct user request 2026-08-18: "это две разные
    /// операции").
    #[tokio::test]
    async fn alerts_read_close_comment_delete_plus_list_filter_sort_pagination() {
        let (app, state, token) = test_app().await;
        let device_id = Uuid::new_v4();
        let active = an_alert(
            "high_cpu",
            "10.0.0.1",
            device_id,
            AlertLevel::Critical,
            AlertState::Active,
        );
        let cleared = an_alert(
            "recent_reboot",
            "10.0.0.2",
            device_id,
            AlertLevel::Warning,
            AlertState::Cleared,
        );
        state.alert_store.upsert(&active).await.unwrap();
        state.alert_store.upsert(&cleared).await.unwrap();

        let (_, body) = req(&app, &token, "GET", "/api/alerts", None).await;
        assert_eq!(body["total"], 2);

        // Single read — 200/404.
        let (status, body) = req(
            &app,
            &token,
            "GET",
            &format!("/api/alerts/{}", active.id),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["name"], "high_cpu");
        let (status, _) = req(
            &app,
            &token,
            "GET",
            &format!("/api/alerts/{}", Uuid::new_v4()),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Filter by state and by level.
        let (_, body) = req(&app, &token, "GET", "/api/alerts?state=active", None).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["id"], active.id.to_string());
        let (_, body) = req(&app, &token, "GET", "/api/alerts?level=warning", None).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["id"], cleared.id.to_string());

        // Search — matches device_ip/name/message.
        let (_, body) = req(&app, &token, "GET", "/api/alerts?search=high_cpu", None).await;
        assert_eq!(body["total"], 1);

        // Pagination.
        let (_, body) = req(&app, &token, "GET", "/api/alerts?page_size=1&page=1", None).await;
        assert_eq!(body["total"], 2);
        assert_eq!(body["items"].as_array().unwrap().len(), 1);

        // Comment thread — multi-author, append-only (2026-08-28, supersedes the earlier
        // single free-form field). `author` comes from the authenticated caller, not the
        // request body.
        let (status, _) = req(
            &app,
            &token,
            "GET",
            &format!("/api/alerts/{}/comments", active.id),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = req(
            &app,
            &token,
            "POST",
            &format!("/api/alerts/{}/comments", active.id),
            Some(serde_json::json!({"text": "investigating"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["text"], "investigating");
        assert_eq!(body["author"], "test-admin");
        let (status, _) = req(
            &app,
            &token,
            "POST",
            &format!("/api/alerts/{}/comments", active.id),
            Some(serde_json::json!({"text": "  "})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "blank comment text must be rejected"
        );

        // Attachments — bytes travel as base64 in the same JSON body (2026-08-29, direct
        // user request: "вложения к комментариям тревог: файл/изображение/видео").
        let (status, body) = req(
            &app,
            &token,
            "POST",
            &format!("/api/alerts/{}/comments", active.id),
            Some(serde_json::json!({
                "text": "see attached",
                "attachments": [{"filename": "shot.png", "content_type": "image/png", "data_base64": "AQIDBA=="}],
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["attachments"].as_array().unwrap().len(), 1);
        assert_eq!(body["attachments"][0]["filename"], "shot.png");
        assert_eq!(body["attachments"][0]["size"], 4);
        let attachment_id = body["attachments"][0]["id"].as_str().unwrap();
        let comment_id = body["id"].as_str().unwrap();

        let (status, _) = req(
            &app,
            &token,
            "POST",
            &format!("/api/alerts/{}/comments", active.id),
            Some(serde_json::json!({"text": "bad b64", "attachments": [{"filename": "x", "content_type": "x", "data_base64": "not-base64!!"}]})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "invalid base64 must be rejected"
        );

        let download_path = format!(
            "/api/alerts/{}/comments/{comment_id}/attachments/{attachment_id}",
            active.id
        );
        let download_req = axum::http::Request::builder()
            .method("GET")
            .uri(&download_path)
            .header("Authorization", format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let download_res = app.clone().oneshot(download_req).await.unwrap();
        assert_eq!(download_res.status(), StatusCode::OK);
        assert_eq!(
            download_res
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "image/png"
        );
        let download_bytes = download_res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(download_bytes.as_ref(), &[1u8, 2, 3, 4]);

        let missing_download = format!(
            "/api/alerts/{}/comments/{comment_id}/attachments/{}",
            active.id,
            Uuid::new_v4()
        );
        let (status, _) = req(&app, &token, "GET", &missing_download, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (_, body) = req(
            &app,
            &token,
            "GET",
            &format!("/api/alerts/{}/comments", active.id),
            None,
        )
        .await;
        assert_eq!(body.as_array().unwrap().len(), 2);
        let (_, body) = req(
            &app,
            &token,
            "GET",
            &format!("/api/alerts/{}", active.id),
            None,
        )
        .await;
        assert_eq!(body["comment_count"], 2);

        // Close — a distinct action from delete: the row survives, state flips to Cleared.
        // `closed_by` records the authenticated caller — direct user request 2026-08-28.
        let (status, _) = req(
            &app,
            &token,
            "POST",
            &format!("/api/alerts/{}/close", active.id),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, body) = req(
            &app,
            &token,
            "GET",
            &format!("/api/alerts/{}", active.id),
            None,
        )
        .await;
        assert_eq!(body["state"], "Cleared");
        assert!(body["cleared_at"].is_string());
        assert_eq!(body["closed_by"], "test-admin");

        // Delete — the row is actually gone, not just marked.
        let (status, _) = req(
            &app,
            &token,
            "DELETE",
            &format!("/api/alerts/{}", active.id),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = req(
            &app,
            &token,
            "GET",
            &format!("/api/alerts/{}", active.id),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (_, body) = req(&app, &token, "GET", "/api/alerts", None).await;
        assert_eq!(body["total"], 1);
    }

    /// Every settings category follows the identical GET/PUT shape — one thorough
    /// round-trip (`poll-intervals`) plus a spot-check per remaining category is enough
    /// to catch a route/serialization mistake without four near-identical essays.
    #[tokio::test]
    async fn settings_get_defaults_and_put_round_trips() {
        let (app, _, token) = test_app().await;

        let (status, body) = req(&app, &token, "GET", "/api/settings/poll-intervals", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["identity_secs"], 300); // built-in default, nothing written yet

        let mut edited = body.clone();
        edited["identity_secs"] = serde_json::json!(42);
        let (status, _) = req(
            &app,
            &token,
            "PUT",
            "/api/settings/poll-intervals",
            Some(edited),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, body) = req(&app, &token, "GET", "/api/settings/poll-intervals", None).await;
        assert_eq!(body["identity_secs"], 42);

        let (status, _) = req(
            &app,
            &token,
            "PUT",
            "/api/settings/ping",
            Some(serde_json::json!({"timeout_ms": 500, "retries": 2})),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, body) = req(&app, &token, "GET", "/api/settings/ping", None).await;
        assert_eq!(body["timeout_ms"], 500);
        assert_eq!(body["retries"], 2);

        let (status, _) = req(
            &app,
            &token,
            "PUT",
            "/api/settings/alert-retention",
            Some(serde_json::json!({"retention_secs": 86400})),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, body) = req(&app, &token, "GET", "/api/settings/alert-retention", None).await;
        assert_eq!(body["retention_secs"], 86400);

        let (status, _) = req(
            &app,
            &token,
            "PUT",
            "/api/settings/dead-device-retention",
            Some(serde_json::json!({"unreachable_for_secs": 3600})),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, body) = req(
            &app,
            &token,
            "GET",
            "/api/settings/dead-device-retention",
            None,
        )
        .await;
        assert_eq!(body["unreachable_for_secs"], 3600);

        let (_, body) = req(&app, &token, "GET", "/api/settings/journal-retention", None).await;
        assert_eq!(body["retention_secs"], serde_json::Value::Null); // built-in default — keep forever
        let (status, _) = req(
            &app,
            &token,
            "PUT",
            "/api/settings/journal-retention",
            Some(serde_json::json!({"retention_secs": 2_592_000})),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, body) = req(&app, &token, "GET", "/api/settings/journal-retention", None).await;
        assert_eq!(body["retention_secs"], 2_592_000);

        let (status, body) = req(&app, &token, "GET", "/api/settings/config-backup", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["enabled"], false);
        let (status, _) = req(&app, &token, "PUT", "/api/settings/config-backup", Some(serde_json::json!({
            "enabled": true, "schedule": {"interval_secs": 3600}, "timeout_secs": 20,
            "max_size_bytes": 524288, "retention_secs": 604800
        }))).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, body) = req(&app, &token, "GET", "/api/settings/config-backup", None).await;
        assert_eq!(body["schedule"]["interval_secs"], 3600);
        assert_eq!(body["max_size_bytes"], 524288);
        let (status, _) = req(&app, &token, "PUT", "/api/settings/config-backup", Some(serde_json::json!({
            "enabled": true, "timeout_secs": 0, "max_size_bytes": 1, "retention_secs": 60
        }))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn nullable_retention_rejects_non_positive_values_but_accepts_forever_and_positive() {
        let (app, _, token) = test_app().await;
        for path in [
            "/api/settings/alert-retention",
            "/api/settings/log-retention",
            "/api/settings/journal-retention",
        ] {
            for value in [
                serde_json::json!(0),
                serde_json::json!(""),
                serde_json::json!(-1),
                serde_json::json!(1.5),
            ] {
                let (status, _) = req(
                    &app,
                    &token,
                    "PUT",
                    path,
                    Some(serde_json::json!({"retention_secs": value})),
                )
                .await;
                assert!(
                    matches!(
                        status,
                        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
                    ),
                    "{path} accepted {value} with {status}"
                );
            }

            let (status, _) = req(
                &app,
                &token,
                "PUT",
                path,
                Some(serde_json::json!({"retention_secs": null})),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::NO_CONTENT,
                "{path} must accept null as forever"
            );
            let (status, _) = req(
                &app,
                &token,
                "PUT",
                path,
                Some(serde_json::json!({"retention_secs": 3600})),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::NO_CONTENT,
                "{path} must accept positive seconds"
            );
        }
    }

    /// `CONFIG_FILE` is process-wide, and `cargo test` runs every `#[tokio::test]` in this
    /// binary in parallel on the same process — a plain `std::env::set_var` here would race
    /// every other test in this file that happens to read it concurrently. This mutex
    /// serializes only the handful of tests below that actually need to point `CONFIG_FILE`
    /// at a scratch file; every other test in this file is unaffected (they never touch the
    /// env var at all).
    static CONFIG_FILE_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn temp_config_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "discovery-web-test-config-{label}-{}.toml",
            std::process::id()
        ))
    }

    /// Direct user request 2026-08-18: a database-config edit is a structured editor over
    /// `config.toml`'s `[storage]` table, not a separate source of truth — round-trips
    /// through the real file on disk, not a mock. Covers both endpoint pairs
    /// (`databases`+`default_database`, and `routing`) plus the "always needs_restart,
    /// never forced" contract.
    #[tokio::test]
    async fn storage_databases_and_routing_round_trip_through_the_real_config_file() {
        let _env_guard = CONFIG_FILE_ENV_LOCK.lock().unwrap();
        let path = temp_config_path("databases-routing");
        std::fs::write(
            &path,
            "# a comment that must survive every write below\n[server]\naddr = \"0.0.0.0:9000\"\n",
        )
        .unwrap();
        unsafe { std::env::set_var("CONFIG_FILE", &path) };

        let (app, _, token) = test_app().await;

        // Starts empty — nothing configured yet.
        let (status, body) = req(&app, &token, "GET", "/api/settings/databases", None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["databases"].as_array().unwrap().is_empty());
        assert!(body["default_database"].is_null());

        let update = serde_json::json!({
            "databases": [{"name": "main", "kind": "sqlite", "file_path": "main.sqlite3", "sqlite_busy_timeout_secs": 5}],
            "default_database": "main",
        });
        let (status, body) =
            req(&app, &token, "PUT", "/api/settings/databases", Some(update)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["needs_restart"], true);

        let (_, body) = req(&app, &token, "GET", "/api/settings/databases", None).await;
        assert_eq!(body["databases"][0]["name"], "main");
        assert_eq!(body["default_database"], "main");

        // Routing starts all-unset (every domain falls back to the default).
        let (_, body) = req(&app, &token, "GET", "/api/settings/routing", None).await;
        assert!(body["alerts"].is_null());

        let (status, body) = req(
            &app,
            &token,
            "PUT",
            "/api/settings/routing",
            Some(serde_json::json!({"alerts": "main"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["needs_restart"], true);

        let (_, body) = req(&app, &token, "GET", "/api/settings/routing", None).await;
        assert_eq!(body["alerts"], "main");
        assert!(
            body["devices"].is_null(),
            "an untouched domain must stay unset, not silently pick up the routed value"
        );

        // Neither write above must have disturbed the unrelated [server] section or its
        // comment — same format-preserving contract `Config::write_storage` guarantees.
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("a comment that must survive every write below"));
        assert!(on_disk.contains("0.0.0.0:9000"));

        unsafe { std::env::remove_var("CONFIG_FILE") };
        std::fs::remove_file(&path).ok();
    }

    /// A `PUT` that would produce an invalid config (here: a database name referenced by
    /// `default_database` that doesn't actually exist in `databases`) must be rejected with
    /// `400`, and — since [`put_storage_databases`] validates before
    /// `Config::write_storage` ever touches the file — must leave the file on disk exactly
    /// as it was.
    #[tokio::test]
    async fn put_storage_databases_rejects_an_invalid_update_and_leaves_the_file_untouched() {
        let _env_guard = CONFIG_FILE_ENV_LOCK.lock().unwrap();
        let path = temp_config_path("invalid-update");
        std::fs::write(&path, "[server]\naddr = \"0.0.0.0:9000\"\n").unwrap();
        unsafe { std::env::set_var("CONFIG_FILE", &path) };
        let before = std::fs::read_to_string(&path).unwrap();

        let (app, _, token) = test_app().await;
        let invalid = serde_json::json!({"databases": [], "default_database": "does-not-exist"});
        let (status, _) = req(
            &app,
            &token,
            "PUT",
            "/api/settings/databases",
            Some(invalid),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            before, after,
            "a rejected update must never touch the file on disk"
        );

        unsafe { std::env::remove_var("CONFIG_FILE") };
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn settings_read_role_sees_only_a_blank_database_password() {
        let _env_guard = CONFIG_FILE_ENV_LOCK.lock().unwrap();
        let path = temp_config_path("database-secret-redaction");
        std::fs::write(
            &path,
            "[storage]\ndefault_database = \"main\"\n[[storage.databases]]\nname = \"main\"\nkind = \"postgres\"\nhost = \"db.internal\"\ndatabase = \"discovery\"\nusername = \"app\"\npassword = \"db-secret-not-for-rest\"\n",
        )
        .unwrap();
        unsafe { std::env::set_var("CONFIG_FILE", &path) };

        let (app, state, _) = test_app().await;
        let role = state
            .auth
            .create_role(
                "settings-reader",
                HashMap::from([(Domain::Settings, AccessLevel::Read)]),
            )
            .await
            .unwrap();
        state
            .auth
            .create_user(
                "settings-reader",
                "reader-password",
                false,
                false,
                Some(role.id),
            )
            .await
            .unwrap();
        let (_, login) = login_req(&app, "settings-reader", "reader-password").await;
        let token = login["token"].as_str().unwrap();

        let (status, body) = req(&app, token, "GET", "/api/settings/databases", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["databases"][0]["password"], "");
        assert!(!body.to_string().contains("db-secret-not-for-rest"));

        unsafe { std::env::remove_var("CONFIG_FILE") };
        std::fs::remove_file(&path).ok();
    }

    /// `/api/queues`/`/api/queues/:kind/jobs`/`/api/workers`/`/api/logs`/`/api/incidents`
    /// are the read-only, no-CRUD-needed endpoints (see the REST-completeness pass's
    /// docs for why: aggregate stats, a live registry snapshot, and append-only
    /// telemetry — none of them a collection a caller adds to or deletes from). One
    /// smoke check each confirms the routes actually respond, not that they have logic
    /// worth a dedicated test — that logic already has coverage where it's implemented
    /// (`discovery-queue`/`discovery-logging`).
    #[tokio::test]
    async fn read_only_endpoints_respond() {
        let (app, _, token) = test_app().await;
        for (method, uri) in [
            ("GET", "/api/queues"),
            ("GET", "/api/queues/discovery/jobs"),
            ("GET", "/api/workers"),
            ("GET", "/api/logs"),
            ("GET", "/api/incidents"),
        ] {
            let (status, _) = req(&app, &token, method, uri, None).await;
            assert_eq!(status, StatusCode::OK, "{method} {uri}");
        }
    }

    /// Delegates every `JobQueueStore` method to a real store except `stats`, which
    /// always fails — the only way to exercise TASK-20260921-021's fix (a storage error
    /// must surface as a real error, not `QueueStats::default()`) without a live database
    /// to actually take down.
    struct FailingStatsStore(Arc<dyn JobQueueStore>);

    #[async_trait::async_trait]
    impl JobQueueStore for FailingStatsStore {
        async fn enqueue(
            &self,
            queue: QueueKind,
            payload: serde_json::Value,
            dedupe_key: Option<&str>,
        ) -> anyhow::Result<i64> {
            self.0.enqueue(queue, payload, dedupe_key).await
        }
        async fn claim(
            &self,
            queue: QueueKind,
            worker_id: &str,
            limit: i64,
        ) -> anyhow::Result<Vec<discovery_core::Job>> {
            self.0.claim(queue, worker_id, limit).await
        }
        async fn complete(&self, job_id: i64) -> anyhow::Result<()> {
            self.0.complete(job_id).await
        }
        async fn fail(&self, job_id: i64, error: &str) -> anyhow::Result<()> {
            self.0.fail(job_id, error).await
        }
        async fn reclaim_stale(&self, older_than: chrono::Duration) -> anyhow::Result<u64> {
            self.0.reclaim_stale(older_than).await
        }
        async fn stats(&self, _queue: QueueKind) -> anyhow::Result<discovery_core::QueueStats> {
            anyhow::bail!("simulated storage failure — must never surface to the client")
        }
        async fn state_of(&self, job_id: i64) -> anyhow::Result<Option<discovery_core::JobState>> {
            self.0.state_of(job_id).await
        }
        async fn delete_job(&self, job_id: i64) -> anyhow::Result<bool> {
            self.0.delete_job(job_id).await
        }
        async fn pause_job(&self, job_id: i64) -> anyhow::Result<bool> {
            self.0.pause_job(job_id).await
        }
        async fn resume_job(&self, job_id: i64) -> anyhow::Result<bool> {
            self.0.resume_job(job_id).await
        }
        async fn clear_queue(
            &self,
            queue: QueueKind,
            state: Option<discovery_core::JobState>,
        ) -> anyhow::Result<u64> {
            self.0.clear_queue(queue, state).await
        }
        async fn is_queue_paused(&self, queue: QueueKind) -> anyhow::Result<bool> {
            self.0.is_queue_paused(queue).await
        }
        async fn set_queue_paused(&self, queue: QueueKind, paused: bool) -> anyhow::Result<()> {
            self.0.set_queue_paused(queue, paused).await
        }
        async fn list_jobs(
            &self,
            queue: QueueKind,
            query: &JobListQuery,
        ) -> anyhow::Result<JobListPage> {
            self.0.list_jobs(queue, query).await
        }
    }

    /// TASK-20260921-021 — `GET /api/queues` used to swallow a per-queue `stats()` error
    /// into `QueueStats::default()` (all zeros), so a genuine storage outage looked
    /// identical to "every queue is empty and healthy" to an operator or monitoring
    /// scraping this endpoint.
    #[tokio::test]
    async fn queue_stats_storage_error_returns_500_not_fake_empty_stats() {
        let (_app, state, token) = test_app().await;
        let mut failing_state = state.clone();
        failing_state.store = Arc::new(FailingStatsStore(state.store.clone()));
        let app = router(failing_state);

        let (status, body) = req(&app, &token, "GET", "/api/queues", None).await;
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "a storage error must not be reported as 200 with fake-empty stats: {body}"
        );
        let message = body.as_str().unwrap_or_default();
        assert!(
            !message.to_lowercase().contains("simulated storage failure"),
            "internal error details must not leak to the client: {message}"
        );
    }

    /// The React app's `dist/` is embedded at compile time (`serve_embedded`) — pins the
    /// SPA fallback contract: an unmatched path (including bare "/") falls back to
    /// `index.html` rather than 404ing, since the SPA needs to boot from any path once
    /// client routing exists. `/legacy` (the pre-React dashboard) was removed 2026-08-25
    /// once every page had a React equivalent — see
    /// `docs/Changelog/2026-08-25 - React Frontend — все страницы.md`.
    #[tokio::test]
    async fn embedded_frontend_falls_back_to_index_html_for_any_unmatched_path() {
        let (app, _, token) = test_app().await;
        for uri in ["/", "/some/unmatched/path"] {
            let (status, body) = req(&app, &token, "GET", uri, None).await;
            assert_eq!(status, StatusCode::OK, "{uri}");
            assert!(
                body.as_str()
                    .unwrap_or_default()
                    .contains("<div id=\"root\">"),
                "{uri} did not fall back to the React app's index.html: {body}"
            );
        }
    }

    /// `router_with_flags` — config.toml's `[server].enable_rest`/`enable_webui` toggles
    /// (2026-08-29). Three cases pinned down: REST off leaves `/api/*` 404ing while the
    /// webui still serves `index.html`; webui off leaves `/api/*` working while an
    /// unmatched path 404s instead of falling back to the SPA; both off means literally
    /// everything 404s (the "no way to interact with the system" case `discovery-agent::
    /// main::run` warns about, but does not prevent). The "both on" case is exactly
    /// `router()`, already covered by every other test in this module using `test_app()`.
    #[tokio::test]
    async fn router_with_flags_toggles_rest_and_webui_independently() {
        let (_, state, token) = test_app().await;

        let rest_only = router_with_flags(state.clone(), true, false);
        let (status, _) = req(&rest_only, &token, "GET", "/api/devices", None).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "REST must still work with webui disabled"
        );
        let (status, _) = req(&rest_only, &token, "GET", "/some/unmatched/path", None).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "no SPA fallback once webui is disabled"
        );

        let webui_only = router_with_flags(state.clone(), false, true);
        let (status, _) = req(&webui_only, &token, "GET", "/api/devices", None).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "/api/* must be entirely unmounted, not just auth-rejected, once REST is disabled"
        );
        let (status, body) = req(&webui_only, &token, "GET", "/some/unmatched/path", None).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the webui's own SPA fallback must be unaffected by REST being disabled"
        );
        assert!(body
            .as_str()
            .unwrap_or_default()
            .contains("<div id=\"root\">"));

        let neither = router_with_flags(state.clone(), false, false);
        for uri in ["/api/devices", "/", "/some/unmatched/path"] {
            let (status, _) = req(&neither, &token, "GET", uri, None).await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "{uri} — nothing is reachable once both are disabled"
            );
        }
    }

    /// `reload_matcher_and_nudge_devices` had zero direct test coverage until now (same
    /// project-wide coverage audit as the router tests above, direct user request
    /// 2026-08-18) — it's called from two places (`upsert_profile`/`delete_profile` here,
    /// and `discovery_agent::profile_reload`'s periodic loop), but the function itself,
    /// including its most important property — *not* re-enqueueing every known device's
    /// identity poll on every single call, only on an actual content change — was never
    /// pinned down anywhere.
    #[tokio::test]
    async fn reload_matcher_and_nudge_devices_is_a_noop_when_nothing_changed() {
        let (_, state, _) = test_app().await;
        let profile = ProfileFile {
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            profile: ProfileMeta {
                name: "p".into(),
                priority: 0,
            },
            match_expr: MatchSection {
                expression: "true".into(),
            },
            metrics: MetricsSection::default(),
            alerts: vec![],
            version: String::new(),
        };
        state.profiles.upsert(&profile).await.unwrap();
        // Matcher already holds the exact same set (constructed fresh from the store, same
        // way `main.rs` does at startup) — signatures must already agree.
        let same = Arc::new(ProfileMatcher::new(
            state.profiles.load_all().await.unwrap(),
        ));

        let changed =
            reload_matcher_and_nudge_devices(&state.profiles, &same, &state.devices, &state.store)
                .await
                .unwrap();
        assert!(
            !changed,
            "signature already matched — must report no reload happened"
        );

        let stats = state.store.stats(QueueKind::SnmpPoll).await.unwrap();
        assert_eq!(stats.pending, 0, "a no-op reload must not nudge anything");
    }

    #[tokio::test]
    async fn reload_matcher_and_nudge_devices_reloads_and_nudges_every_known_device() {
        let (_, state, _) = test_app().await;
        let profile = ProfileFile {
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            profile: ProfileMeta {
                name: "p".into(),
                priority: 0,
            },
            match_expr: MatchSection {
                expression: "true".into(),
            },
            metrics: MetricsSection::default(),
            alerts: vec![],
            version: String::new(),
        };
        state.profiles.upsert(&profile).await.unwrap();
        // Matcher starts from an empty set — deliberately stale, so a reload is due.
        state
            .devices
            .resolve(discovery_core::DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        state
            .devices
            .resolve(discovery_core::DeviceFacts {
                ip: "10.0.0.2".into(),
            })
            .await
            .unwrap();

        let changed = reload_matcher_and_nudge_devices(
            &state.profiles,
            &state.matcher,
            &state.devices,
            &state.store,
        )
        .await
        .unwrap();
        assert!(
            changed,
            "matcher started empty, store has a profile — a reload is due"
        );

        // The matcher itself now agrees with the store — a second call right after is a
        // true no-op, not just coincidentally reporting one.
        let changed_again = reload_matcher_and_nudge_devices(
            &state.profiles,
            &state.matcher,
            &state.devices,
            &state.store,
        )
        .await
        .unwrap();
        assert!(
            !changed_again,
            "immediately calling again with nothing new changed must be a no-op"
        );

        // Exactly one SnmpPoll nudge per known device, not the whole queue re-run twice.
        let stats = state.store.stats(QueueKind::SnmpPoll).await.unwrap();
        assert_eq!(
            stats.pending, 2,
            "one nudge per known device, from the single reload that actually happened"
        );

        let jobs = state
            .store
            .list_jobs(QueueKind::SnmpPoll, &JobListQuery::default())
            .await
            .unwrap();
        for job in &jobs.jobs {
            assert_eq!(
                job.payload["recurring"], false,
                "a reload nudge must be one-off, not start a second permanent chain"
            );
        }
    }

    /// Sanity check that the test fixtures above (`ProfileMeta`/`MatchSection`/
    /// `MetricsSection`/`Schedule`/`SubnetSpec`/`SnmpVersion`) are real, used types, not
    /// dead imports — a device created through a discovery-config-shaped subnet spec
    /// round-trips through the same JSON shape `POST /api/discovery-configs` accepts.
    #[tokio::test]
    async fn discovery_config_with_a_real_subnet_round_trips() {
        let (app, _, token) = test_app().await;
        let config = discovery_config_store::DiscoveryConfig {
            name: "full".into(),
            enabled: true,
            schedule: Schedule::Periodic {
                interval_secs: 3600,
            },
            subnets: vec![SubnetSpec {
                ip: "10.0.0.0".into(),
                mask: "255.255.255.0".into(),
                port: 161,
                credentials: vec![SnmpAuth::Community {
                    version: SnmpVersion::V2c,
                    community: "public".into(),
                }],
                oids: Default::default(),
                labels: Default::default(),
                snmp_timeout_ms: None,
                snmp_retries: None,
                create_dead_devices: false,
            }],
        };
        let (status, _) = req(
            &app,
            &token,
            "POST",
            "/api/discovery-configs",
            Some(serde_json::to_value(&config).unwrap()),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, body) = req(&app, &token, "GET", "/api/discovery-configs/full", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["subnets"][0]["create_dead_devices"], false);

        // Same round-trip for a fully-specified profile, using the DSL types directly
        // instead of a raw `serde_json::json!` literal.
        let profile = ProfileFile {
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            profile: ProfileMeta {
                name: "full".into(),
                priority: 1,
            },
            match_expr: MatchSection {
                expression: "true".into(),
            },
            metrics: MetricsSection::default(),
            alerts: vec![],
            version: String::new(),
        };
        let (status, _) = req(
            &app,
            &token,
            "POST",
            "/api/profiles",
            Some(serde_json::to_value(&profile).unwrap()),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = req(&app, &token, "GET", "/api/profiles/full", None).await;
        assert_eq!(status, StatusCode::OK);
    }

    fn usm_v3_config(
        name: &str,
        auth: Option<discovery_core::SnmpV3AuthCreds>,
        priv_: Option<discovery_core::SnmpV3PrivCreds>,
    ) -> discovery_config_store::DiscoveryConfig {
        discovery_config_store::DiscoveryConfig {
            name: name.into(),
            enabled: true,
            schedule: Schedule::Periodic {
                interval_secs: 3600,
            },
            subnets: vec![SubnetSpec {
                ip: "10.0.0.0".into(),
                mask: "255.255.255.0".into(),
                port: 161,
                credentials: vec![SnmpAuth::UsmV3(discovery_core::SnmpV3Credentials {
                    user: "monitor".into(),
                    auth,
                    priv_,
                })],
                oids: Default::default(),
                labels: Default::default(),
                snmp_timeout_ms: None,
                snmp_retries: None,
                create_dead_devices: false,
            }],
        }
    }

    fn valid_v3_config(name: &str) -> discovery_config_store::DiscoveryConfig {
        usm_v3_config(
            name,
            Some(discovery_core::SnmpV3AuthCreds {
                protocol: discovery_core::SnmpAuthProtocol::Sha1,
                passphrase: "authpass123".into(),
            }),
            Some(discovery_core::SnmpV3PrivCreds {
                protocol: discovery_core::SnmpPrivProtocol::Aes128,
                passphrase: "privpass123".into(),
            }),
        )
    }

    /// `test_app()`'s `discovery_configs` store has no secret key configured (the common
    /// case for every other test in this file, none of which touch v3) — a `UsmV3`
    /// credential must fail loudly at write time instead of silently landing as plaintext.
    /// See `discovery_core::secret::SecretError::KeyRequired`'s docs.
    #[tokio::test]
    async fn discovery_config_with_a_v3_credential_fails_loudly_without_a_secret_key_configured() {
        let (app, _, token) = test_app().await;
        let (status, body) = req(
            &app,
            &token,
            "POST",
            "/api/discovery-configs",
            Some(serde_json::to_value(&valid_v3_config("v3-no-key")).unwrap()),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {body}");
    }

    /// Same config as above, but through a store that *does* have a key configured —
    /// proves the actual round trip works once a deployment opts in, not just that the
    /// no-key case fails correctly.
    #[tokio::test]
    async fn discovery_config_with_a_secret_key_configured_round_trips_a_v3_credential() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        let (_, state, token) = test_app().await;
        let db = discovery_migration::connect_in_memory_for_tests().await;
        let key = Arc::new(
            discovery_core::secret::SecretKey::from_base64(&STANDARD.encode([3u8; 32])).unwrap(),
        );
        let discovery_configs: Arc<dyn discovery_config_store::DiscoveryConfigStore> = Arc::new(
            discovery_config_store::SeaOrmDiscoveryConfigStore::new(db).with_secret_key(key),
        );
        let app = router(DashboardState {
            discovery_configs,
            ..state
        });

        let (status, _) = req(
            &app,
            &token,
            "POST",
            "/api/discovery-configs",
            Some(serde_json::to_value(&valid_v3_config("v3-full")).unwrap()),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, body) = req(&app, &token, "GET", "/api/discovery-configs/v3-full", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["subnets"][0]["credentials"][0]["user"], "monitor");
        assert_eq!(
            body["subnets"][0]["credentials"][0]["auth"]["passphrase"], "authpass123",
            "the store must hand back the original plaintext, not ciphertext"
        );
    }

    #[tokio::test]
    async fn discovery_config_rejects_priv_without_auth() {
        let (app, _, token) = test_app().await;
        let config = usm_v3_config(
            "v3-priv-no-auth",
            None,
            Some(discovery_core::SnmpV3PrivCreds {
                protocol: discovery_core::SnmpPrivProtocol::Aes128,
                passphrase: "privpass123".into(),
            }),
        );
        let (status, body) = req(
            &app,
            &token,
            "POST",
            "/api/discovery-configs",
            Some(serde_json::to_value(&config).unwrap()),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    }

    #[tokio::test]
    async fn discovery_config_rejects_a_too_short_v3_passphrase() {
        let (app, _, token) = test_app().await;
        let config = usm_v3_config(
            "v3-short-pass",
            Some(discovery_core::SnmpV3AuthCreds {
                protocol: discovery_core::SnmpAuthProtocol::Sha1,
                passphrase: "short".into(),
            }),
            None,
        );
        let (status, body) = req(
            &app,
            &token,
            "POST",
            "/api/discovery-configs",
            Some(serde_json::to_value(&config).unwrap()),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    }

    /// Direct user request 2026-08-28: "Поиск читает подсети и название и ищет по ним" —
    /// `search` must match a config's subnets (`ip`/`mask`/label values), not just its own
    /// `name` (already covered by `discovery_configs_full_crud_plus_list_filter_search_sort`).
    #[tokio::test]
    async fn discovery_configs_search_also_matches_subnet_ip_mask_and_labels() {
        let (app, _, token) = test_app().await;
        let with_subnet = discovery_config_store::DiscoveryConfig {
            name: "branch-a".into(),
            enabled: true,
            schedule: Schedule::Periodic {
                interval_secs: 3600,
            },
            subnets: vec![SubnetSpec {
                ip: "10.77.0.0".into(),
                mask: "255.255.0.0".into(),
                port: 161,
                credentials: vec![SnmpAuth::Community {
                    version: SnmpVersion::V2c,
                    community: "public".into(),
                }],
                oids: Default::default(),
                labels: [("area_name".to_string(), "Воронеж".to_string())]
                    .into_iter()
                    .collect(),
                snmp_timeout_ms: None,
                snmp_retries: None,
                create_dead_devices: false,
            }],
        };
        let (status, _) = req(
            &app,
            &token,
            "POST",
            "/api/discovery-configs",
            Some(serde_json::to_value(&with_subnet).unwrap()),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = req(
            &app,
            &token,
            "POST",
            "/api/discovery-configs",
            Some(a_discovery_config("branch-b", true)),
        )
        .await; // no matching subnet, no matching name
        assert_eq!(status, StatusCode::NO_CONTENT);

        let (_, body) = req(
            &app,
            &token,
            "GET",
            "/api/discovery-configs?search=10.77",
            None,
        )
        .await;
        assert_eq!(body["total"], 1, "must match by subnet ip");
        assert_eq!(body["items"][0]["name"], "branch-a");

        let (_, body) = req(
            &app,
            &token,
            "GET",
            "/api/discovery-configs?search=255.255.0.0",
            None,
        )
        .await;
        assert_eq!(body["total"], 1, "must match by subnet mask");

        let (_, body) = req(
            &app,
            &token,
            "GET",
            "/api/discovery-configs?search=воронеж",
            None,
        )
        .await;
        assert_eq!(
            body["total"], 1,
            "must match by a label value, case-insensitively"
        );

        let (_, body) = req(
            &app,
            &token,
            "GET",
            "/api/discovery-configs?search=does-not-exist-anywhere",
            None,
        )
        .await;
        assert_eq!(body["total"], 0);
    }

    // -------------------------------------------------------------------------------
    // Auth (2026-08-21) — every other test in this file goes through `test_app()`'s
    // admin token, which is exactly what makes it *not* prove the permission-guard
    // middleware itself works (an admin bypasses every domain check — see
    // `AuthenticatedUser::can`'s docs). These tests are the ones that actually exercise
    // login, missing/invalid sessions, and a non-admin's per-domain read/write split.
    // -------------------------------------------------------------------------------

    #[tokio::test]
    async fn requests_without_a_session_are_rejected() {
        let (app, _, _) = test_app().await;
        let (status, _) = req(&app, "not-a-real-token", "GET", "/api/devices", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // No `Authorization` header at all — same outcome, checked separately since it's a
        // different code path through `extract_token` (no header found vs. header present
        // but the token doesn't resolve to a session).
        let request = Request::builder()
            .method("GET")
            .uri("/api/devices")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_rejects_wrong_credentials_and_succeeds_with_the_right_ones() {
        let (app, state, _) = test_app().await;
        state
            .auth
            .create_user("alice", "correct-password", false, false, None)
            .await
            .unwrap();

        let (status, _) = login_req(&app, "alice", "wrong-password").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = login_req(&app, "nobody", "correct-password").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "unknown username must fail the same way as a wrong password, not leak which one was wrong");

        let (status, body) = login_req(&app, "alice", "correct-password").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["user"]["username"], "alice");
        assert!(body["token"].as_str().is_some_and(|t| !t.is_empty()));
    }

    #[tokio::test]
    async fn account_management_rejects_short_passwords() {
        let (app, _, token) = test_app().await;
        let (status, body) = req(
            &app,
            &token,
            "POST",
            "/api/users",
            Some(serde_json::json!({"username": "too-short", "password": "short"})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.as_str().unwrap_or_default().contains("at least 8"));
    }

    #[test]
    fn session_cookie_is_secure_and_http_only() {
        let cookie = session_cookie("token", 60);
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Max-Age=60"));
    }

    #[test]
    fn cookie_mutations_require_same_origin() {
        let method = axum::http::Method::POST;
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, "discovery_session=token".parse().unwrap());
        headers.insert(header::HOST, "dashboard.example".parse().unwrap());
        assert!(!csrf_is_allowed(&method, "/api/devices", &headers));
        headers.insert(header::ORIGIN, "https://dashboard.example".parse().unwrap());
        assert!(csrf_is_allowed(&method, "/api/devices", &headers));
        headers.insert(header::ORIGIN, "https://evil.example".parse().unwrap());
        assert!(!csrf_is_allowed(&method, "/api/devices", &headers));
        assert!(csrf_is_allowed(&method, "/api/auth/login", &headers));
    }

    #[test]
    fn internal_errors_hide_details_and_return_a_correlation_id() {
        let (status, body) = internal_error(anyhow::anyhow!("database password leaked"));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!body.contains("database password leaked"));
        assert!(body.starts_with("internal server error (correlation id: "));
        assert!(body.ends_with(')'));
    }

    #[tokio::test]
    async fn responses_include_security_headers() {
        let (app, _, token) = test_app().await;
        let mut request = Request::builder()
            .method("GET")
            .uri("/api/devices")
            .header("authorization", format!("Bearer {token}"));
        request = request.extension(ConnectInfo(test_peer_addr()));
        let response = app
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
        assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
        assert!(response.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'"));
        assert!(response.headers()[header::STRICT_TRANSPORT_SECURITY]
            .to_str()
            .unwrap()
            .contains("max-age=31536000"));
    }

    async fn login_req(
        app: &Router,
        username: &str,
        password: &str,
    ) -> (StatusCode, serde_json::Value) {
        req(
            app,
            "",
            "POST",
            "/api/auth/login",
            Some(serde_json::json!({"username": username, "password": password})),
        )
        .await
    }

    /// Same as [`login_req`], but with an explicit source IP instead of [`test_peer_addr`] —
    /// used only by the rate-limit tests below, which need to distinguish source IPs.
    async fn login_req_from(
        app: &Router,
        username: &str,
        password: &str,
        ip: IpAddr,
    ) -> (StatusCode, serde_json::Value) {
        let request = Request::builder()
            .method("POST")
            .uri("/api/auth/login")
            .header("content-type", "application/json")
            .extension(ConnectInfo(SocketAddr::new(ip, 0)))
            .body(Body::from(
                serde_json::to_vec(
                    &serde_json::json!({"username": username, "password": password}),
                )
                .unwrap(),
            ))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or_else(|_| {
                serde_json::Value::String(String::from_utf8_lossy(&bytes).into_owned())
            })
        };
        (status, json)
    }

    #[tokio::test]
    async fn login_throttled_response_is_indistinguishable_from_a_wrong_password() {
        let (app, state, _) = test_app().await;
        state
            .auth
            .create_user("throttle-target", "correct-horse", false, false, None)
            .await
            .unwrap();
        let ip = IpAddr::from([203, 0, 113, 8]);

        let (wrong_status, wrong_body) =
            login_req_from(&app, "throttle-target", "wrong-password", ip).await;
        assert_eq!(wrong_status, StatusCode::UNAUTHORIZED);

        // Spend the rest of the burst (LOGIN_BURST_CAPACITY = 5; one attempt already spent
        // above) with more wrong guesses from the same (username, ip).
        for _ in 0..4 {
            login_req_from(&app, "throttle-target", "wrong-password", ip).await;
        }

        // Burst is now exhausted. The *correct* password is still rejected — proving the
        // limiter fires before credentials are even checked — and with a response
        // byte-for-byte identical to the plain wrong-password case above, so an attacker
        // gets no separate "locked out" signal to distinguish throttling from a bad guess.
        let (throttled_status, throttled_body) =
            login_req_from(&app, "throttle-target", "correct-horse", ip).await;
        assert_eq!(throttled_status, wrong_status);
        assert_eq!(throttled_body, wrong_body);
    }

    #[tokio::test]
    async fn login_throttle_is_scoped_per_ip_not_globally_per_username() {
        let (app, state, _) = test_app().await;
        state
            .auth
            .create_user("shared-target", "correct-horse", false, false, None)
            .await
            .unwrap();
        let attacker_ip = IpAddr::from([203, 0, 113, 6]);
        let innocent_ip = IpAddr::from([203, 0, 113, 7]);

        for _ in 0..5 {
            login_req_from(&app, "shared-target", "wrong-password", attacker_ip).await;
        }
        let (status, _) =
            login_req_from(&app, "shared-target", "wrong-password", attacker_ip).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "attacker_ip's burst should be exhausted by now"
        );

        // A different IP logging into the same account is unaffected by the attacker's burst.
        let (status, body) =
            login_req_from(&app, "shared-target", "correct-horse", innocent_ip).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["user"]["username"], "shared-target");
    }

    /// Regression test (2026-09-12 audit follow-up): `username` in the `(username, ip)`
    /// throttle key is attacker-controlled free text, unlike the trap/syslog per-IP maps
    /// this project accepts as never-evicting — `sweep_stale` is what keeps this map
    /// bounded against a remote attacker rotating usernames.
    #[test]
    fn sweep_stale_evicts_only_buckets_idle_longer_than_the_threshold() {
        let limiter = LoginRateLimiter::default();
        let ip = IpAddr::from([203, 0, 113, 9]);
        // Touch two distinct buckets "now".
        assert!(limiter.check_and_consume("still-fresh", ip));
        assert!(limiter.check_and_consume("also-fresh", ip));
        assert_eq!(limiter.account_buckets.len(), 2);
        assert_eq!(limiter.ip_buckets.len(), 1);

        // A threshold longer than any real elapsed time here must evict nothing.
        limiter.sweep_stale(std::time::Duration::from_secs(3600));
        assert_eq!(
            limiter.account_buckets.len(),
            2,
            "nothing has gone idle yet -- sweep must be a no-op"
        );
        assert_eq!(limiter.ip_buckets.len(), 1);

        // A threshold of zero means "anything not touched in this exact instant" -- a real
        // sweep interval is always far larger than this, but it proves the eviction
        // predicate itself actually removes entries, not just leaves them untouched.
        limiter.sweep_stale(std::time::Duration::from_nanos(0));
        assert_eq!(
            limiter.account_buckets.len(),
            0,
            "a zero threshold must evict every account bucket regardless of age"
        );
        assert_eq!(
            limiter.ip_buckets.len(),
            0,
            "a zero threshold must evict every IP bucket regardless of age"
        );
    }

    #[test]
    fn login_rate_limiter_uses_the_configured_burst_and_refill_not_hardcoded_values() {
        let config = discovery_bootstrap::LoginRateLimitConfig {
            burst_capacity: 2,
            ..Default::default()
        };
        let limiter = LoginRateLimiter::new(config);
        let ip = IpAddr::from([203, 0, 113, 10]);
        assert!(limiter.check_and_consume("cfg-test", ip));
        assert!(limiter.check_and_consume("cfg-test", ip));
        assert!(!limiter.check_and_consume("cfg-test", ip), "a burst_capacity of 2 must throttle on the third immediate attempt, not the default's fifth");
    }

    #[test]
    fn login_rate_limiter_has_a_global_per_ip_cap_and_trusts_only_configured_proxies() {
        let config = discovery_bootstrap::LoginRateLimitConfig {
            burst_capacity: 2,
            trusted_proxy_ips: vec![IpAddr::from([192, 0, 2, 10])],
            ..Default::default()
        };
        let limiter = LoginRateLimiter::new(config);
        let proxy = IpAddr::from([192, 0, 2, 10]);
        let client_a = IpAddr::from([198, 51, 100, 1]);
        let client_b = IpAddr::from([198, 51, 100, 2]);
        assert_eq!(limiter.source_ip(proxy, Some("198.51.100.1")), client_a);
        assert_eq!(
            limiter.source_ip(IpAddr::from([203, 0, 113, 9]), Some("198.51.100.1")),
            IpAddr::from([203, 0, 113, 9])
        );
        assert!(limiter.check_and_consume("one", client_a));
        assert!(limiter.check_and_consume("two", client_a));
        assert!(
            !limiter.check_and_consume("three", client_a),
            "rotating usernames must not bypass the IP-wide cap"
        );
        assert!(
            limiter.check_and_consume("one", client_b),
            "a separate client IP has its own global bucket"
        );
    }

    #[tokio::test]
    async fn me_reflects_the_logged_in_user_and_logout_invalidates_the_session() {
        let (app, state, _) = test_app().await;

        // The SPA's first request has no cookie. Keep this protected 401 distinct
        // from the invalid/expired-session 401 below; the frontend uses the body
        // only to classify the expected auth state, never to expose user data.
        let request = Request::builder()
            .method("GET")
            .uri("/api/auth/me")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"not logged in");

        let role = state
            .auth
            .create_role(
                "readers",
                HashMap::from([(Domain::Devices, AccessLevel::Read)]),
            )
            .await
            .unwrap();
        state
            .auth
            .create_user("alice", "hunter2", false, false, Some(role.id))
            .await
            .unwrap();
        let (_, login_body) = login_req(&app, "alice", "hunter2").await;
        let token = login_body["token"].as_str().unwrap().to_string();

        let (status, body) = req(&app, &token, "GET", "/api/auth/me", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["username"], "alice");
        assert_eq!(body["role_name"], "readers");

        let (status, _) = req(&app, &token, "POST", "/api/auth/logout", None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, body) = req(&app, &token, "GET", "/api/auth/me", None).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "session must be dead immediately after logout"
        );
        assert_eq!(body, "invalid or expired session");
    }

    /// Direct user request 2026-08-26: the first-run bootstrap account ships with a
    /// fixed, publicly-known `admin`/`admin` login (see `discovery-agent::main`'s docs) —
    /// `must_change_password` is what makes that safe, and this pins the *server-side*
    /// half of it: `GET /api/auth/me` and `PUT /api/auth/password` must stay reachable
    /// throughout (the dashboard needs the former to know to show the forced-change
    /// screen at all, and the latter *is* the escape hatch), while every domain-gated
    /// and admin-gated route rejects with 403 regardless of what permissions the account
    /// actually holds (here, `is_admin: true` — proves this check runs before, not
    /// instead of, the normal permission check, since an admin would otherwise sail
    /// through `/api/users`).
    #[tokio::test]
    async fn must_change_password_blocks_every_domain_and_admin_route_until_changed() {
        let (app, state, _) = test_app().await;
        state
            .auth
            .create_user("temp-admin", "admin", true, true, None)
            .await
            .unwrap();
        let (_, login_body) = login_req(&app, "temp-admin", "admin").await;
        assert_eq!(login_body["user"]["must_change_password"], true);
        let token = login_body["token"].as_str().unwrap().to_string();

        // Escape hatch and self-check both stay reachable.
        let (status, body) = req(&app, &token, "GET", "/api/auth/me", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["must_change_password"], true);

        // Everything else — including admin-only routes, despite `is_admin: true` — is
        // blocked while the flag is set.
        let (status, _) = req(&app, &token, "GET", "/api/devices", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = req(&app, &token, "GET", "/api/users", None).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "must_change_password must be checked before the admin check, not bypassed by is_admin"
        );
        let (status, _) = req(&app, &token, "GET", "/api/notifications/channels", None).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "temporary-password users must not use self-service notification routes"
        );
        let (status, _) = req(&app, &token, "GET", "/api/assistant/conversations", None).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "temporary-password users must not use assistant routes"
        );

        // Wrong current password on the escape hatch itself must not clear the flag.
        let (status, _) = req(
            &app,
            &token,
            "PUT",
            "/api/auth/password",
            Some(
                serde_json::json!({"current_password": "wrong", "new_password": "a-real-password"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = req(&app, &token, "GET", "/api/devices", None).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a failed change attempt must not have cleared the flag"
        );

        // The real change clears it and revokes the old session.  Re-authenticate before
        // checking the post-change account state; keeping the old token valid would let a
        // stolen seven-day session survive a password reset.
        let (status, _) = req(
            &app,
            &token,
            "PUT",
            "/api/auth/password",
            Some(
                serde_json::json!({"current_password": "admin", "new_password": "a-real-password"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = req(&app, &token, "GET", "/api/auth/me", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, login_body) = login_req(&app, "temp-admin", "a-real-password").await;
        assert_eq!(status, StatusCode::OK);
        let fresh_token = login_body["token"].as_str().unwrap();
        let (status, body) = req(&app, fresh_token, "GET", "/api/auth/me", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["must_change_password"], false);
        let (status, _) = req(&app, fresh_token, "GET", "/api/users", None).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "admin routes must open back up once the password is changed"
        );

        // The old password no longer works — confirms this really was a change, not just
        // a flag flip.
        let (status, _) = login_req(&app, "temp-admin", "admin").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn read_permission_allows_get_but_not_write_write_allows_both() {
        let (app, state, _) = test_app().await;
        let role = state
            .auth
            .create_role(
                "device-readers",
                HashMap::from([(Domain::Devices, AccessLevel::Read)]),
            )
            .await
            .unwrap();
        state
            .auth
            .create_user("bob", "pw", false, false, Some(role.id))
            .await
            .unwrap();
        let (_, login_body) = login_req(&app, "bob", "pw").await;
        let token = login_body["token"].as_str().unwrap().to_string();

        let (status, _) = req(&app, &token, "GET", "/api/devices", None).await;
        assert_eq!(status, StatusCode::OK, "Read must satisfy a GET");
        let (status, _) = req(
            &app,
            &token,
            "PUT",
            "/api/devices/enabled",
            Some(serde_json::json!({"enabled": true})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "Read must not satisfy a write method"
        );

        // A domain never granted at all — not just under-permissioned, absent entirely.
        let (status, _) = req(&app, &token, "GET", "/api/alerts", None).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a domain missing from the permission map must deny access, not default-allow"
        );

        // Updating the role's own permissions takes effect immediately on the *same*
        // already-issued token — no re-login needed, since `authenticate_session` resolves
        // a role's permissions fresh on every request, not once at login time.
        assert!(state
            .auth
            .update_role(
                role.id,
                "device-readers",
                HashMap::from([(Domain::Devices, AccessLevel::Write)])
            )
            .await
            .unwrap());
        let (status, _) = req(
            &app,
            &token,
            "PUT",
            "/api/devices/enabled",
            Some(serde_json::json!({"enabled": true})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "Write must satisfy a write method");
        let (status, _) = req(&app, &token, "GET", "/api/devices", None).await;
        assert_eq!(status, StatusCode::OK, "Write must still satisfy a GET too");
    }

    #[tokio::test]
    async fn non_admin_cannot_manage_users_admin_can() {
        let (app, state, admin_token) = test_app().await;
        let user = state
            .auth
            .create_user("bob", "pw", false, false, None)
            .await
            .unwrap();
        let (_, login_body) = login_req(&app, "bob", "pw").await;
        let bob_token = login_body["token"].as_str().unwrap().to_string();

        let (status, _) = req(&app, &bob_token, "GET", "/api/users", None).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a regular user must not be able to list accounts"
        );

        let (status, body) = req(&app, &admin_token, "GET", "/api/users", None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body
            .as_array()
            .unwrap()
            .iter()
            .any(|u| u["username"] == "bob"));

        let role = state
            .auth
            .create_role(
                "device-writers",
                HashMap::from([(Domain::Devices, AccessLevel::Write)]),
            )
            .await
            .unwrap();
        let (status, _) = req(
            &app,
            &admin_token,
            "PUT",
            &format!("/api/users/{}/role", user.id),
            Some(serde_json::json!({"role_id": role.id})),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(
            state
                .auth
                .get_user_by_id(user.id)
                .await
                .unwrap()
                .unwrap()
                .role_id,
            Some(role.id)
        );
    }

    /// Full REST surface for the Roles model (2026-08-27, design-artifact parity pass) —
    /// same "create/read/update/delete + list" checklist every other resource in this
    /// suite gets, plus the two behaviors specific to roles: deleting one unassigns (not
    /// deletes) its users, and assigning/reassigning a user's role via `PUT /api/users/
    /// :id/role` actually changes what that user can do.
    #[tokio::test]
    async fn roles_full_crud_plus_user_assignment_and_role_deletion_unassigns_users() {
        let (app, state, admin_token) = test_app().await;

        let (status, _) = req(&app, &admin_token, "GET", "/api/roles", None).await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = req(
            &app,
            &admin_token,
            "POST",
            "/api/roles",
            Some(serde_json::json!({"name": "ops", "permissions": {"devices": "read", "alerts": "write"}})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let role_id = body["id"].as_str().unwrap().to_string();
        assert_eq!(body["name"], "ops");
        assert_eq!(body["permissions"]["devices"], "read");
        assert_eq!(body["permissions"]["alerts"], "write");

        let (status, body) = req(&app, &admin_token, "GET", "/api/roles", None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.as_array().unwrap().iter().any(|r| r["name"] == "ops"));

        let (status, body) = req(
            &app,
            &admin_token,
            "GET",
            &format!("/api/roles/{role_id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["name"], "ops");

        // Full-replace update — `alerts` left out of the new set must disappear, not merge.
        let (status, _) = req(
            &app,
            &admin_token,
            "PUT",
            &format!("/api/roles/{role_id}"),
            Some(serde_json::json!({"name": "ops-renamed", "permissions": {"devices": "write"}})),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, body) = req(
            &app,
            &admin_token,
            "GET",
            &format!("/api/roles/{role_id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["name"], "ops-renamed");
        assert_eq!(body["permissions"]["devices"], "write");
        assert!(
            body["permissions"].get("alerts").is_none(),
            "a domain left out of the update must be gone, not merged"
        );

        // Assign the role to a user, confirm it actually gates access, then delete the
        // role and confirm the user survives, unassigned.
        let (_, user_body) = req(
            &app,
            &admin_token,
            "POST",
            "/api/users",
            Some(serde_json::json!({"username": "carol", "password": "carol-pw"})),
        )
        .await;
        let user_id = user_body["id"].as_str().unwrap().to_string();
        let (status, _) = req(
            &app,
            &admin_token,
            "PUT",
            &format!("/api/users/{user_id}/role"),
            Some(serde_json::json!({"role_id": role_id})),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let (_, login_body) = login_req(&app, "carol", "carol-pw").await;
        let carol_token = login_body["token"].as_str().unwrap().to_string();
        assert_eq!(login_body["user"]["role_name"], "ops-renamed");
        let (status, _) = req(
            &app,
            &carol_token,
            "PUT",
            "/api/devices/enabled",
            Some(serde_json::json!({"enabled": true})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the assigned role's write grant on devices must actually work"
        );

        let (status, _) = req(
            &app,
            &admin_token,
            "DELETE",
            &format!("/api/roles/{role_id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = req(
            &app,
            &admin_token,
            "GET",
            &format!("/api/roles/{role_id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let user_uuid = Uuid::parse_str(&user_id).unwrap();
        assert_eq!(
            state
                .auth
                .get_user_by_id(user_uuid)
                .await
                .unwrap()
                .unwrap()
                .role_id,
            None,
            "the user must survive the role's deletion, unassigned"
        );

        let (status, _) = req(
            &app,
            &admin_token,
            "DELETE",
            &format!("/api/roles/{role_id}"),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "deleting an already-gone role must 404, not 204"
        );
    }

    /// The "Журнал" audit trail — direct user request: record "что за пользователь, в
    /// каком домене и что за действие" for every write, with the same filter/pagination/
    /// sort/search UI other list pages get, admin-only to read. Exercises the actual
    /// recording path (`require_domain_permission`/`require_admin` calling
    /// `record_journal_entry`) end to end through real HTTP requests, not by calling
    /// `state.journal` directly — same "drive it through the router" discipline this whole
    /// test module documents at its top.
    #[tokio::test]
    async fn journal_records_every_successful_write_admin_only_filter_sort_search_paginate() {
        let (app, state, admin_token) = test_app().await;
        let bob = state
            .auth
            .create_user("bob", "pw", false, false, None)
            .await
            .unwrap();
        let role = state
            .auth
            .create_role(
                "device-writers",
                HashMap::from([(Domain::Devices, AccessLevel::Write)]),
            )
            .await
            .unwrap();
        req(
            &app,
            &admin_token,
            "PUT",
            &format!("/api/users/{}/role", bob.id),
            Some(serde_json::json!({"role_id": role.id})),
        )
        .await;
        let (_, login_body) = login_req(&app, "bob", "pw").await;
        let bob_token = login_body["token"].as_str().unwrap().to_string();

        // Non-admin — even one with full write access to a business domain — cannot read
        // the audit trail: it's an admin-only cross-cutting capability (see `router()`'s
        // docs on this route), not gated by any single `Domain`.
        let (status, _) = req(&app, &bob_token, "GET", "/api/journal", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // A plain GET (read) is never an "action" — nothing recorded for it.
        req(&app, &admin_token, "GET", "/api/devices", None).await;
        // A write that never happens (bad session on a route that still requires it) also
        // records nothing — checked implicitly: only the two real writes below appear.
        let (status, _) = req(
            &app,
            &bob_token,
            "PUT",
            "/api/devices/enabled",
            Some(serde_json::json!({"enabled": true})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = req(
            &app,
            &admin_token,
            "POST",
            "/api/profiles",
            Some(a_profile("zebra", 5, "true")),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body:?}");

        let (status, body) = req(&app, &admin_token, "GET", "/api/journal", None).await;
        assert_eq!(status, StatusCode::OK);
        // The setup above already recorded one entry of its own (the admin's own
        // `PUT /api/users/:id/role` assigning "device-writers" to bob) — a real write, so
        // it's expected to show up too. Total: that role assignment + the two writes below
        // (bob's device toggle, the admin's profile save); the earlier plain GET recorded
        // nothing.
        assert_eq!(body["total"], 3);
        let items = body["items"].as_array().unwrap();
        // Default sort is newest first.
        assert_eq!(items[0]["username"], "test-admin");
        assert_eq!(items[0]["domain"], "profiles");
        assert_eq!(items[0]["action"], "Сохранён профиль");
        assert_eq!(items[1]["username"], "bob");
        assert_eq!(items[1]["domain"], "devices");
        assert_eq!(items[1]["action"], "Массово изменена активность устройств");
        assert_eq!(items[2]["username"], "test-admin");
        assert_eq!(items[2]["domain"], "users");
        assert_eq!(items[2]["action"], "Изменена роль пользователя");

        // Filter by domain — exact match.
        let (_, body) = req(
            &app,
            &admin_token,
            "GET",
            "/api/journal?domain=profiles",
            None,
        )
        .await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["username"], "test-admin");

        // Filter by username — exact match, only bob's own action.
        let (_, body) = req(&app, &admin_token, "GET", "/api/journal?username=bob", None).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["domain"], "devices");

        // Free-text search matches the action text too.
        let (_, body) = req(
            &app,
            &admin_token,
            "GET",
            "/api/journal?search=профиль",
            None,
        )
        .await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["username"], "test-admin");

        // Sort ascending by username — "bob" before "test-admin".
        let (_, body) = req(
            &app,
            &admin_token,
            "GET",
            "/api/journal?sort_by=username&sort_dir=asc",
            None,
        )
        .await;
        let items = body["items"].as_array().unwrap();
        assert_eq!(items[0]["username"], "bob");

        // Pagination.
        let (_, body) = req(
            &app,
            &admin_token,
            "GET",
            "/api/journal?page=1&page_size=1",
            None,
        )
        .await;
        assert_eq!(body["total"], 3);
        assert_eq!(body["items"].as_array().unwrap().len(), 1);
        let (_, body) = req(
            &app,
            &admin_token,
            "GET",
            "/api/journal?page=2&page_size=1",
            None,
        )
        .await;
        assert_eq!(
            body["items"].as_array().unwrap().len(),
            1,
            "second page must still return a row, not come back empty"
        );
    }

    /// Direct user follow-up request: the Журнал entry itself should say *which* object
    /// was touched and, for an edit, *what* changed (before -> after), not just "who did
    /// what kind of action" — "например при создании и редактировании дискаверинга
    /// показывать что за дискаверинг и что было отредактировано". A create has `object`
    /// but no `details` (nothing to diff against); an edit has both. Also checks the
    /// no-op case (PUT the exact same enabled value a device already has) still records a
    /// well-formed `old == new` diff rather than nothing at all.
    #[tokio::test]
    async fn journal_details_show_object_and_before_after_diff_on_edit_not_on_create() {
        let (app, _, token) = test_app().await;

        // Create — object present, no details (nothing existed before to diff against).
        let (status, _) = req(
            &app,
            &token,
            "POST",
            "/api/profiles",
            Some(a_profile("zebra", 5, "true")),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, body) = req(&app, &token, "GET", "/api/journal?domain=profiles", None).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["object"], "zebra");
        assert_eq!(body["items"][0]["details"], serde_json::Value::Null);

        // Edit — same name, different priority and match expression. `metrics`/`alerts`
        // are untouched (both calls pass `{"poll": {}}`/`[]`) and must be entirely absent
        // from the diff, not just unchanged-but-present.
        let (status, _) = req(
            &app,
            &token,
            "POST",
            "/api/profiles",
            Some(a_profile("zebra", 9, "false")),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, body) = req(
            &app,
            &token,
            "GET",
            "/api/journal?domain=profiles&sort_dir=asc",
            None,
        )
        .await;
        assert_eq!(body["total"], 2);
        let edit_entry = &body["items"][1];
        assert_eq!(edit_entry["object"], "zebra");
        let details = &edit_entry["details"];
        assert_eq!(details["profile"]["old"]["priority"], 5);
        assert_eq!(details["profile"]["new"]["priority"], 9);
        assert_eq!(details["match"]["old"]["expression"], "true");
        assert_eq!(details["match"]["new"]["expression"], "false");
        assert!(details.get("metrics").is_none(), "an untouched top-level field must be absent from the diff entirely, not present-and-unchanged");
        assert!(details.get("alerts").is_none());

        // Device enable/disable toggle — object is the IP, details is a small old->new
        // pair, not the whole `Device` struct.
        let (_, dev_body) = req(
            &app,
            &token,
            "POST",
            "/api/devices",
            Some(serde_json::json!({"ip": "10.9.9.9"})),
        )
        .await;
        let device_id = dev_body["id"].as_str().unwrap();
        let (status, _) = req(
            &app,
            &token,
            "PUT",
            &format!("/api/devices/{device_id}/enabled"),
            Some(serde_json::json!({"enabled": false})),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, body) = req(
            &app,
            &token,
            "GET",
            "/api/journal?domain=devices&search=10.9.9.9",
            None,
        )
        .await;
        let toggle_entry = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["action"] == "Изменена активность устройства")
            .unwrap();
        assert_eq!(toggle_entry["object"], "10.9.9.9");
        assert_eq!(toggle_entry["details"]["enabled"]["old"], true);
        assert_eq!(toggle_entry["details"]["enabled"]["new"], false);
    }

    /// `put_storage_databases` deliberately records no `details` at all (see its own
    /// docs) — this test's job is to prove that holds even when a password is present
    /// and actually changes, not just that the endpoint itself works.
    #[tokio::test]
    async fn journal_never_leaks_a_database_password_into_a_diff() {
        let _env_guard = CONFIG_FILE_ENV_LOCK.lock().unwrap();
        let path = temp_config_path("journal-db-password");
        std::fs::write(&path, "[server]\naddr = \"0.0.0.0:9000\"\n").unwrap();
        unsafe { std::env::set_var("CONFIG_FILE", &path) };

        let (app, _, token) = test_app().await;
        let body = serde_json::json!({
            "databases": [{"name": "main", "kind": "postgres", "host": "localhost", "port": 5432, "database": "discovery", "username": "app", "password": "s3cr3t-password", "sqlite_busy_timeout_secs": 5}],
            "default_database": "main",
        });
        let (status, _) = req(&app, &token, "PUT", "/api/settings/databases", Some(body)).await;
        assert_eq!(status, StatusCode::OK);
        let (_, journal_body) =
            req(&app, &token, "GET", "/api/journal?domain=settings", None).await;
        let entry = journal_body["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["action"] == "Изменён список подключений к БД")
            .unwrap();
        assert_eq!(
            entry["details"],
            serde_json::Value::Null,
            "must never attempt a details diff on the one endpoint where a real DB password lives"
        );
        let dump = serde_json::to_string(&journal_body).unwrap();
        assert!(
            !dump.contains("s3cr3t-password"),
            "the password must not appear anywhere in the journal response, in any form"
        );

        unsafe { std::env::remove_var("CONFIG_FILE") };
        std::fs::remove_file(&path).ok();
    }

    // ---- notification channels + matrix (2026-09-10) ----

    #[tokio::test]
    async fn notification_channels_self_service_crud_and_ownership_guard() {
        let (app, state, _admin_token) = test_app().await;
        state
            .auth
            .create_user("bob", "pw", false, false, None)
            .await
            .unwrap();
        state
            .auth
            .create_user("alice", "pw", false, false, None)
            .await
            .unwrap();
        let (_, bob_login) = login_req(&app, "bob", "pw").await;
        let bob_token = bob_login["token"].as_str().unwrap().to_string();
        let (_, alice_login) = login_req(&app, "alice", "pw").await;
        let alice_token = alice_login["token"].as_str().unwrap().to_string();

        // No domain grant of any kind needed — self-service, like PUT /api/auth/password.
        let (status, body) = req(
            &app,
            &bob_token,
            "POST",
            "/api/notifications/channels",
            Some(serde_json::json!({"kind": "telegram", "target": "123456", "enabled": true})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let channel_id = body["id"].as_str().unwrap().to_string();
        assert_eq!(
            body["user_id"],
            serde_json::json!(
                state
                    .auth
                    .list_users()
                    .await
                    .unwrap()
                    .iter()
                    .find(|u| u.username == "bob")
                    .unwrap()
                    .id
            )
        );

        let (status, list_body) =
            req(&app, &bob_token, "GET", "/api/notifications/channels", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(list_body.as_array().unwrap().len(), 1);

        // Alice sees none of bob's channels through her own self-service list.
        let (_, alice_list) = req(
            &app,
            &alice_token,
            "GET",
            "/api/notifications/channels",
            None,
        )
        .await;
        assert!(alice_list.as_array().unwrap().is_empty());

        // Alice cannot edit or delete bob's channel by guessing its id.
        let (status, _) = req(
            &app,
            &alice_token,
            "POST",
            "/api/notifications/channels",
            Some(serde_json::json!({"id": channel_id, "kind": "telegram", "target": "999999", "enabled": true})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "editing another user's channel via self-service must be forbidden"
        );
        let (status, _) = req(
            &app,
            &alice_token,
            "DELETE",
            &format!("/api/notifications/channels/{channel_id}"),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "deleting another user's channel via self-service must be forbidden"
        );

        // Bob can edit and delete his own.
        let (status, _) = req(
            &app,
            &bob_token,
            "POST",
            "/api/notifications/channels",
            Some(serde_json::json!({"id": channel_id, "kind": "telegram", "target": "654321", "enabled": false})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = req(
            &app,
            &bob_token,
            "DELETE",
            &format!("/api/notifications/channels/{channel_id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, list_after) =
            req(&app, &bob_token, "GET", "/api/notifications/channels", None).await;
        assert!(list_after.as_array().unwrap().is_empty());
    }

    /// 2026-09-17 audit finding #2 (CWE-918, SSRF) — self-service webhook channels have no
    /// domain grant requirement (confirmed by the test right above), so this is the only
    /// thing standing between any logged-in user and pointing `discovery-agent`'s outbound
    /// webhook call at cloud metadata or an internal service. Router-level, not just a unit
    /// test on `validate_webhook_target`, to confirm the check is actually wired into the
    /// self-service endpoint's request path — not merely defined.
    #[tokio::test]
    async fn webhook_channel_rejects_ssrf_targets_but_accepts_a_public_url() {
        let (app, _state, token) = test_app().await;

        for (target, why) in [
            (
                "http://169.254.169.254/latest/meta-data/",
                "cloud metadata address",
            ),
            ("http://127.0.0.1:8080/admin", "IPv4 loopback"),
            ("http://localhost/hook", "well-known loopback name"),
            ("http://10.0.0.5/hook", "RFC1918 private range"),
            ("http://[::1]/hook", "IPv6 loopback"),
            (
                "http://[::ffff:169.254.169.254]/",
                "IPv4-mapped IPv6 metadata address",
            ),
            ("ftp://example.com/hook", "non-http(s) scheme"),
            ("not a url", "unparseable target"),
        ] {
            let (status, body) = req(
                &app,
                &token,
                "POST",
                "/api/notifications/channels",
                Some(serde_json::json!({"kind": "webhook", "target": target, "enabled": true})),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{why} ('{target}') must be rejected, got {body:?}"
            );
        }

        let (status, _) = req(&app, &token, "POST", "/api/notifications/channels", Some(serde_json::json!({"kind": "webhook", "target": "https://example.com/hook", "enabled": true}))).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a normal public https URL must still be accepted"
        );
    }

    #[test]
    fn validate_webhook_target_rejects_forbidden_hosts_and_schemes() {
        for target in [
            "http://169.254.169.254/",
            "http://127.0.0.1/",
            "http://localhost/",
            "http://LOCALHOST/",
            "http://10.1.2.3/",
            "http://172.16.0.1/",
            "http://192.168.1.1/",
            "http://0.0.0.0/",
            "http://[::1]/",
            "http://[fe80::1]/",
            "http://[fc00::1]/",
            "http://[::ffff:127.0.0.1]/",
            // Legacy "IPv4-compatible" IPv6 notation (`::a.b.c.d`, distinct from the
            // IPv4-mapped `::ffff:a.b.c.d` form above) — `to_ipv4_mapped()` alone misses
            // this, must go through `to_ipv4()` instead.
            "http://[::169.254.169.254]/",
            "http://[::127.0.0.1]/",
            // Trailing-dot FQDN — `localhost.` is the exact same host as `localhost` to
            // every resolver, no DNS lookup needed to know that.
            "http://localhost./",
            "http://LOCALHOST./admin",
            // RFC 6598 carrier-grade NAT shared space — e.g. Alibaba Cloud's metadata
            // endpoint (100.100.100.200) lives here; not covered by `Ipv4Addr::is_private()`.
            "http://100.100.100.200/",
            "http://100.64.0.1/",
            "ftp://example.com/",
            "not-a-url",
            "//example.com/no-scheme",
        ] {
            assert!(
                validate_webhook_target(target).is_err(),
                "expected '{target}' to be rejected"
            );
        }
    }

    #[test]
    fn validate_webhook_target_accepts_ordinary_public_urls() {
        for target in [
            "https://example.com/hook",
            "http://example.com:8080/hook?x=1",
            "https://8.8.8.8/hook",
        ] {
            assert!(
                validate_webhook_target(target).is_ok(),
                "expected '{target}' to be accepted"
            );
        }
    }

    /// 2026-09-17 audit finding #5's side-check ("стоит перепроверить тем же способом" —
    /// see that finding's write-up) confirmed a real, separate leak: `GET
    /// /api/notifications/channels` returned a webhook channel's real, decrypted signing
    /// `secret` in plaintext, same bug class as the SSH password. Covers the fix's two
    /// halves together, since they depend on each other: the GET response must never
    /// carry the real value, *and* saving an edited channel with that now-always-blank
    /// field must preserve the existing secret rather than silently wiping it (see
    /// `redact_notification_channel`'s docs for why the two are linked).
    #[tokio::test]
    async fn notification_channel_secret_is_redacted_on_read_and_preserved_across_an_unrelated_edit(
    ) {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        let (_, state, token) = test_app().await;
        let db = discovery_migration::connect_in_memory_for_tests().await;
        let key = Arc::new(
            discovery_core::secret::SecretKey::from_base64(&STANDARD.encode([9u8; 32])).unwrap(),
        );
        let notification_channels: Arc<dyn discovery_config_store::NotificationChannelStore> =
            Arc::new(
                discovery_config_store::SeaOrmNotificationChannelStore::new(db)
                    .with_secret_key(key),
            );
        let app = router(DashboardState {
            notification_channels: notification_channels.clone(),
            ..state
        });

        let (status, created) = req(
            &app,
            &token,
            "POST",
            "/api/notifications/channels",
            Some(serde_json::json!({"kind": "webhook", "target": "https://example.com/hook", "secret": "top-secret-hmac-key", "enabled": true})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let channel_id = created["id"].as_str().unwrap().to_string();

        // The leak itself: a plain list-read must never carry the real value.
        let (_, list_body) = req(&app, &token, "GET", "/api/notifications/channels", None).await;
        let dump = list_body.to_string();
        assert!(
            !dump.contains("top-secret-hmac-key"),
            "the webhook secret must never appear in a GET response: {dump}"
        );
        let listed = &list_body.as_array().unwrap()[0];
        assert_eq!(listed["secret"], "", "redacted to a blank placeholder, not null — a configured secret must still read as \"something is set\"");

        // An unrelated edit (just toggling `enabled`) submitted with that now-always-blank
        // field must not wipe the real secret server-side.
        let (status, _) = req(
            &app,
            &token,
            "POST",
            "/api/notifications/channels",
            Some(serde_json::json!({"id": channel_id, "kind": "webhook", "target": "https://example.com/hook", "secret": "", "enabled": false})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let stored = notification_channels
            .get(Uuid::parse_str(&channel_id).unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.secret.as_deref(),
            Some("top-secret-hmac-key"),
            "an edit with a blank secret field must preserve the existing one, not clear it"
        );
        assert!(
            !stored.enabled,
            "the actual intended change must still take effect"
        );
    }

    #[tokio::test]
    async fn admin_can_manage_another_users_notification_channels_non_admin_cannot() {
        let (app, state, admin_token) = test_app().await;
        let bob = state
            .auth
            .create_user("bob", "pw", false, false, None)
            .await
            .unwrap();
        state
            .auth
            .create_user("carol", "pw", false, false, None)
            .await
            .unwrap();
        let (_, carol_login) = login_req(&app, "carol", "pw").await;
        let carol_token = carol_login["token"].as_str().unwrap().to_string();

        let (status, _) = req(
            &app,
            &carol_token,
            "GET",
            &format!("/api/users/{}/notification-channels", bob.id),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a non-admin must not manage another user's channels"
        );

        let (status, body) = req(
            &app,
            &admin_token,
            "POST",
            &format!("/api/users/{}/notification-channels", bob.id),
            Some(
                serde_json::json!({"kind": "email", "target": "bob@example.com", "enabled": true}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["user_id"], serde_json::json!(bob.id));

        let (_, list_body) = req(
            &app,
            &admin_token,
            "GET",
            &format!("/api/users/{}/notification-channels", bob.id),
            None,
        )
        .await;
        assert_eq!(list_body.as_array().unwrap().len(), 1);

        // The admin write must be journaled (unlike the self-service path — see
        // `describe_action`'s docs).
        let (_, journal_body) = req(&app, &admin_token, "GET", "/api/journal", None).await;
        assert!(journal_body["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["action"] == "Сохранён канал нотификации пользователя"));
    }

    #[tokio::test]
    async fn notification_rules_full_crud_plus_validation_requires_notifications_domain() {
        let (app, state, _admin_token) = test_app().await;
        let role = state
            .auth
            .create_role(
                "notifiers",
                HashMap::from([(Domain::Notifications, AccessLevel::Write)]),
            )
            .await
            .unwrap();
        state
            .auth
            .create_user("dan", "pw", false, false, Some(role.id))
            .await
            .unwrap();
        let (_, dan_login) = login_req(&app, "dan", "pw").await;
        let dan_token = dan_login["token"].as_str().unwrap().to_string();

        // No domain at all — forbidden.
        state
            .auth
            .create_user("eve", "pw", false, false, None)
            .await
            .unwrap();
        let (_, eve_login) = login_req(&app, "eve", "pw").await;
        let eve_token = eve_login["token"].as_str().unwrap().to_string();
        let (status, _) = req(&app, &eve_token, "GET", "/api/notifications/rules", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let recipient = Uuid::new_v4();
        let (status, body) = req(
            &app,
            &dan_token,
            "POST",
            "/api/notifications/rules",
            Some(serde_json::json!({
                "name": "page on critical",
                "enabled": true,
                "min_level": "Critical",
                "notify_on_activate": true,
                "notify_on_clear": true,
                "recipients": [recipient],
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected body: {body}");
        let rule_id = body["id"].as_str().unwrap().to_string();
        assert_eq!(body["recipients"], serde_json::json!([recipient]));

        let (status, _) = req(
            &app,
            &dan_token,
            "GET",
            &format!("/api/notifications/rules/{rule_id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Validation: empty name.
        let (status, _) = req(
            &app,
            &dan_token,
            "POST",
            "/api/notifications/rules",
            Some(serde_json::json!({"name": "  ", "enabled": true, "min_level": "Info", "notify_on_activate": true, "notify_on_clear": true})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Validation: active_from without active_to.
        let (status, _) = req(
            &app,
            &dan_token,
            "POST",
            "/api/notifications/rules",
            Some(serde_json::json!({"name": "partial window", "enabled": true, "min_level": "Info", "notify_on_activate": true, "notify_on_clear": true, "active_from": "09:00:00"})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Validation: bad weekday name.
        let (status, _) = req(
            &app,
            &dan_token,
            "POST",
            "/api/notifications/rules",
            Some(serde_json::json!({"name": "bad day", "enabled": true, "min_level": "Info", "notify_on_activate": true, "notify_on_clear": true, "days_of_week": ["Funday"]})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // TASK-20260921-017 — a malformed subnet selector used to save with 2xx and just
        // silently never match anything at runtime (`ipv4_in_subnet(...).unwrap_or(false)`
        // treats a parse error the same as "not in this subnet"). Bad IP.
        let (status, body) = req(
            &app,
            &dan_token,
            "POST",
            "/api/notifications/rules",
            Some(serde_json::json!({"name": "bad ip", "enabled": true, "min_level": "Info", "notify_on_activate": true, "notify_on_clear": true, "subnets": [{"ip": "not-an-ip", "mask": "255.255.255.0"}]})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.as_str().unwrap_or_default().contains("subnets[0]"),
            "error must name the offending array index: {body}"
        );

        // Bad (non-contiguous) mask.
        let (status, body) = req(
            &app,
            &dan_token,
            "POST",
            "/api/notifications/rules",
            Some(serde_json::json!({"name": "bad mask", "enabled": true, "min_level": "Info", "notify_on_activate": true, "notify_on_clear": true, "subnets": [{"ip": "10.0.0.0", "mask": "255.0.255.0"}]})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.as_str().unwrap_or_default().contains("subnets[0]"),
            "error must name the offending array index: {body}"
        );

        // A second, valid entry after a bad first one must still be named by its own
        // index, not the first bad one found overall.
        let (status, body) = req(
            &app,
            &dan_token,
            "POST",
            "/api/notifications/rules",
            Some(serde_json::json!({"name": "second bad", "enabled": true, "min_level": "Info", "notify_on_activate": true, "notify_on_clear": true, "subnets": [{"ip": "10.0.0.0", "mask": "255.255.255.0"}, {"ip": "bad", "mask": "255.255.255.0"}]})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.as_str().unwrap_or_default().contains("subnets[1]"),
            "error must name index 1, not 0: {body}"
        );

        // A correct subnet, and an explicitly empty list (both must save fine — empty
        // means "no subnet restriction", the same as never setting the field at all).
        let (status, _) = req(
            &app,
            &dan_token,
            "POST",
            "/api/notifications/rules",
            Some(serde_json::json!({"name": "good subnet", "enabled": true, "min_level": "Info", "notify_on_activate": true, "notify_on_clear": true, "subnets": [{"ip": "10.0.0.0", "mask": "255.255.255.0"}]})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = req(
            &app,
            &dan_token,
            "POST",
            "/api/notifications/rules",
            Some(serde_json::json!({"name": "empty subnets", "enabled": true, "min_level": "Info", "notify_on_activate": true, "notify_on_clear": true, "subnets": []})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _) = req(
            &app,
            &dan_token,
            "DELETE",
            &format!("/api/notifications/rules/{rule_id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = req(
            &app,
            &dan_token,
            "GET",
            &format!("/api/notifications/rules/{rule_id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// TASK-20260921-017 — same fix, same silent-runtime-no-match failure mode as
    /// `notification_rules_full_crud_plus_validation_requires_notifications_domain`'s
    /// subnet cases above, for maintenance windows' independent copy of `subnets:
    /// Vec<SubnetTarget>`.
    #[tokio::test]
    async fn maintenance_window_rejects_malformed_subnet_selectors() {
        let (app, _state, token) = test_app().await;
        let starts = chrono::Utc::now();
        let ends = starts + chrono::Duration::hours(1);

        let (status, body) = req(
            &app,
            &token,
            "POST",
            "/api/maintenance-windows",
            Some(serde_json::json!({"name": "bad ip", "enabled": true, "starts_at": starts, "ends_at": ends, "subnets": [{"ip": "not-an-ip", "mask": "255.255.255.0"}]})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.as_str().unwrap_or_default().contains("subnets[0]"),
            "error must name the offending array index: {body}"
        );

        let (status, body) = req(
            &app,
            &token,
            "POST",
            "/api/maintenance-windows",
            Some(serde_json::json!({"name": "bad mask", "enabled": true, "starts_at": starts, "ends_at": ends, "subnets": [{"ip": "10.0.0.0", "mask": "255.0.255.0"}]})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.as_str().unwrap_or_default().contains("subnets[0]"),
            "error must name the offending array index: {body}"
        );

        // Valid subnet and empty list both still save fine.
        let (status, _) = req(
            &app,
            &token,
            "POST",
            "/api/maintenance-windows",
            Some(serde_json::json!({"name": "good subnet", "enabled": true, "starts_at": starts, "ends_at": ends, "subnets": [{"ip": "10.0.0.0", "mask": "255.255.255.0"}]})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = req(
            &app,
            &token,
            "POST",
            "/api/maintenance-windows",
            Some(serde_json::json!({"name": "empty subnets", "enabled": true, "starts_at": starts, "ends_at": ends, "subnets": []})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn notification_recipients_is_a_minimal_projection_available_without_full_user_admin_access(
    ) {
        let (app, state, _admin_token) = test_app().await;
        let role = state
            .auth
            .create_role(
                "notifiers",
                HashMap::from([(Domain::Notifications, AccessLevel::Read)]),
            )
            .await
            .unwrap();
        state
            .auth
            .create_user("frank", "pw", false, false, Some(role.id))
            .await
            .unwrap();
        let (_, frank_login) = login_req(&app, "frank", "pw").await;
        let frank_token = frank_login["token"].as_str().unwrap().to_string();

        // Full user admin surface stays forbidden...
        let (status, _) = req(&app, &frank_token, "GET", "/api/users", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // ...but the minimal recipient picker is available under the Notifications domain.
        let (status, body) = req(
            &app,
            &frank_token,
            "GET",
            "/api/notifications/recipients",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let names: Vec<&str> = body
            .as_array()
            .unwrap()
            .iter()
            .map(|u| u["username"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"frank"));
        // Only {id, username} — no role/admin-flag/password fields leak through.
        assert!(body[0].get("is_admin").is_none());
        assert!(body[0].get("role_id").is_none());
    }

    #[tokio::test]
    async fn topology_rules_full_crud_plus_validation_requires_topology_domain() {
        let (app, state, _admin_token) = test_app().await;
        let role = state
            .auth
            .create_role(
                "topologists",
                HashMap::from([(Domain::Topology, AccessLevel::Write)]),
            )
            .await
            .unwrap();
        state
            .auth
            .create_user("tara", "pw", false, false, Some(role.id))
            .await
            .unwrap();
        let (_, tara_login) = login_req(&app, "tara", "pw").await;
        let tara_token = tara_login["token"].as_str().unwrap().to_string();

        // No domain at all — forbidden.
        state
            .auth
            .create_user("eve2", "pw", false, false, None)
            .await
            .unwrap();
        let (_, eve_login) = login_req(&app, "eve2", "pw").await;
        let eve_token = eve_login["token"].as_str().unwrap().to_string();
        let (status, _) = req(&app, &eve_token, "GET", "/api/topology/rules", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Validation: empty name.
        let (status, _) = req(
            &app,
            &tara_token,
            "POST",
            "/api/topology/rules",
            Some(serde_json::json!({"name": "  ", "enabled": true, "my_key_expression": "metrics.key"})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Validation: broken Rhai syntax is rejected at save time, not silently accepted.
        let (status, _) = req(
            &app,
            &tara_token,
            "POST",
            "/api/topology/rules",
            Some(serde_json::json!({"name": "broken", "enabled": true, "my_key_expression": "metrics.((("})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Same validation for `rank_expression` specifically — it's not just the other two
        // expressions that get checked at save time.
        let (status, _) = req(
            &app,
            &tara_token,
            "POST",
            "/api/topology/rules",
            Some(serde_json::json!({"name": "broken-rank", "enabled": true, "my_key_expression": "metrics.key", "rank_expression": "metrics.((("})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, body) = req(
            &app,
            &tara_token,
            "POST",
            "/api/topology/rules",
            Some(serde_json::json!({
                "name": "lldp",
                "enabled": true,
                "my_key_expression": "metrics.lldp_chassis_id",
                "claimed_neighbors_expression": "metrics.lldp_rem_table.map(|row| row.chassis_id)",
                "rank_expression": "metrics.role_value",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected body: {body}");
        assert_eq!(body["rank_expression"], "metrics.role_value");
        let rule_id = body["id"].as_str().unwrap().to_string();

        let (status, _) = req(
            &app,
            &tara_token,
            "GET",
            &format!("/api/topology/rules/{rule_id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Two devices, resolved through the real storage the handler shares with topology —
        // proves the read-side REST endpoints (not just the rule CRUD) work end to end.
        let (a, _) = state
            .devices
            .resolve(discovery_core::DeviceFacts {
                ip: "10.0.0.11".into(),
            })
            .await
            .unwrap();
        let (b, _) = state
            .devices
            .resolve(discovery_core::DeviceFacts {
                ip: "10.0.0.12".into(),
            })
            .await
            .unwrap();
        state
            .topology
            .apply_recompute(
                "lldp",
                a,
                Some("key-a".into()),
                vec!["key-b".into()],
                Some(0.0),
            )
            .await
            .unwrap();
        state
            .topology
            .apply_recompute(
                "lldp",
                b,
                Some("key-b".into()),
                vec!["key-a".into()],
                Some(1.0),
            )
            .await
            .unwrap();

        // A rule edit must invalidate already-cached topology immediately, not wait for
        // another watched-metric poll. Disabling it clears the old graph; enabling it queues
        // one recompute per already-known device.
        let (status, _) = req(
            &app,
            &tara_token,
            "POST",
            "/api/topology/rules",
            Some(serde_json::json!({
                "id": rule_id.clone(),
                "name": "lldp",
                "enabled": false,
                "my_key_expression": "metrics.lldp_chassis_id",
                "claimed_neighbors_expression": "metrics.lldp_neighbors",
                "rank_expression": "metrics.role_value"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(state
            .topology
            .resolved_edges("lldp")
            .await
            .unwrap()
            .is_empty());

        let (status, _) = req(
            &app,
            &tara_token,
            "POST",
            "/api/topology/rules",
            Some(serde_json::json!({
                "id": rule_id.clone(),
                "name": "lldp",
                "enabled": true,
                "my_key_expression": "metrics.lldp_chassis_id",
                "claimed_neighbors_expression": "metrics.lldp_neighbors",
                "rank_expression": "metrics.role_value"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            state
                .store
                .stats(QueueKind::TopologyRecompute)
                .await
                .unwrap()
                .pending,
            2
        );

        // This router-level test has no agent worker consuming the queue. The REST handler's
        // contract is only to enqueue one recompute per known device; execute the equivalent
        // worker result here before asserting the read-side graph, so the test does not confuse
        // an intentionally pending job with a broken topology resolver.
        state
            .topology
            .apply_recompute(
                "lldp",
                a,
                Some("key-a".into()),
                vec!["key-b".into()],
                Some(0.0),
            )
            .await
            .unwrap();
        state
            .topology
            .apply_recompute(
                "lldp",
                b,
                Some("key-b".into()),
                vec!["key-a".into()],
                Some(1.0),
            )
            .await
            .unwrap();

        let (status, body) = req(
            &app,
            &tara_token,
            "GET",
            &format!("/api/topology/rules/lldp/neighbors/{a}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body[0]["neighbor_device_id"], b.to_string());
        assert_eq!(body[0]["confirmed"], true);
        assert_eq!(
            body[0]["upstream_device_id"],
            a.to_string(),
            "a's lower rank must resolve it as upstream"
        );
        assert_eq!(body[0]["direction_overridden"], false);

        let (status, body) = req(
            &app,
            &tara_token,
            "GET",
            "/api/topology/rules/lldp/edges",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"].as_array().unwrap().len(), 1);
        // The API canonically orders edge endpoints by UUID, not creation order. Verify the
        // UUID/IP correspondence directly so random UUIDs cannot make this test flaky while
        // still proving that both endpoints are enriched with their device IPs.
        let (expected_a, expected_a_ip, expected_b, expected_b_ip) = if a < b {
            (a, "10.0.0.11", b, "10.0.0.12")
        } else {
            (b, "10.0.0.12", a, "10.0.0.11")
        };
        assert_eq!(body["items"][0]["device_a"], expected_a.to_string());
        assert_eq!(body["items"][0]["device_a_ip"], expected_a_ip);
        assert_eq!(body["items"][0]["device_b"], expected_b.to_string());
        assert_eq!(body["items"][0]["device_b_ip"], expected_b_ip);

        // Manual override flips direction despite rank disagreeing, then clearing it falls
        // back to rank again.
        let (status, _) = req(
            &app,
            &tara_token,
            "PUT",
            &format!("/api/topology/rules/lldp/hierarchy/{a}/{b}"),
            Some(serde_json::json!({"upstream_device_id": b.to_string()})),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, body) = req(
            &app,
            &tara_token,
            "GET",
            "/api/topology/rules/lldp/edges",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["items"][0]["upstream_device_id"], b.to_string());
        assert_eq!(body["items"][0]["direction_overridden"], true);

        // Rejects an upstream_device_id that isn't one of the two devices in the edge.
        let other = Uuid::new_v4();
        let (status, _) = req(
            &app,
            &tara_token,
            "PUT",
            &format!("/api/topology/rules/lldp/hierarchy/{a}/{b}"),
            Some(serde_json::json!({"upstream_device_id": other.to_string()})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _) = req(
            &app,
            &tara_token,
            "DELETE",
            &format!("/api/topology/rules/lldp/hierarchy/{a}/{b}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, body) = req(
            &app,
            &tara_token,
            "GET",
            "/api/topology/rules/lldp/edges",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["items"][0]["upstream_device_id"],
            a.to_string(),
            "clearing the override falls back to rank"
        );
        assert_eq!(body["items"][0]["direction_overridden"], false);

        // Search/filter/status/direction/pagination (2026-09-18 — manual-test-audit finding
        // #5, same server-side pattern `AlertsQuery`/`DevicesQuery` already use).
        let (status, body) = req(
            &app,
            &tara_token,
            "GET",
            "/api/topology/rules/lldp/edges?search=10.0.0.11",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["total"], 1);
        let (status, body) = req(
            &app,
            &tara_token,
            "GET",
            "/api/topology/rules/lldp/edges?search=nomatch",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["total"], 0);
        let (status, body) = req(
            &app,
            &tara_token,
            "GET",
            "/api/topology/rules/lldp/edges?status=confirmed",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["total"], 1);
        let (status, body) = req(
            &app,
            &tara_token,
            "GET",
            "/api/topology/rules/lldp/edges?status=unconfirmed",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["total"], 0);
        let (status, body) = req(
            &app,
            &tara_token,
            "GET",
            "/api/topology/rules/lldp/edges?direction=undetermined",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["total"], 0,
            "direction was just restored to determined (rank-based) above"
        );
        let (status, body) = req(
            &app,
            &tara_token,
            "GET",
            "/api/topology/rules/lldp/edges?page=2&page_size=1",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["total"], 1,
            "total still reflects the whole filtered set, not just this page"
        );
        assert_eq!(
            body["items"].as_array().unwrap().len(),
            0,
            "page 2 of a 1-row result is empty"
        );

        let (status, _) = req(
            &app,
            &tara_token,
            "DELETE",
            &format!("/api/topology/rules/{rule_id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = req(
            &app,
            &tara_token,
            "GET",
            &format!("/api/topology/rules/{rule_id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn notification_provider_settings_get_defaults_before_anything_is_configured() {
        let (app, _, token) = test_app().await;
        let (status, body) = req(&app, &token, "GET", "/api/settings/notifications", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["smtp_port"], 587,
            "default port must come through even before anything is configured"
        );
        assert_eq!(body["smtp_host"], serde_json::Value::Null);
    }

    /// Same "no passthrough" contract as SSH credentials — see
    /// `put_ssh_credentials_without_a_secret_key_configured_fails_loudly`, which this
    /// mirrors: a non-empty `smtp_password`/`telegram_bot_token` with no
    /// `DISCOVERY_SECRET_KEY` configured on the settings store must fail loudly, not
    /// silently write plaintext.
    #[tokio::test]
    async fn notification_provider_settings_secrets_require_a_key_configured_to_persist() {
        let (app, _, token) = test_app().await; // test_app's settings store has no secret key
        let (status, body) = req(
            &app,
            &token,
            "PUT",
            "/api/settings/notifications",
            Some(serde_json::json!({"smtp_password": "hunter2", "smtp_port": 587})),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {body}");
    }

    /// 2026-09-17 audit finding #5's side-check confirmed a real, separate leak here too:
    /// `GET /api/settings/notifications` returned `smtp_password`/`telegram_bot_token` in
    /// plaintext — same bug class as the SSH password and the webhook channel secret. This
    /// test used to assert that leak as an intentional "precedent" (see the old comment
    /// this replaced); now covers the fix's two linked halves instead: the GET response
    /// must never carry the real values, and saving with those now-always-blank fields
    /// must preserve the existing credentials rather than silently wiping them.
    #[tokio::test]
    async fn notification_provider_secrets_are_redacted_on_read_preserved_across_edit_and_never_reach_the_journal(
    ) {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        let (_, state, token) = test_app().await;
        let db = discovery_migration::connect_in_memory_for_tests().await;
        let key = Arc::new(
            discovery_core::secret::SecretKey::from_base64(&STANDARD.encode([4u8; 32])).unwrap(),
        );
        let settings: Arc<dyn SettingsStore> =
            Arc::new(discovery_config_store::SeaOrmSettingsStore::new(db).with_secret_key(key));
        let app = router(DashboardState {
            settings: settings.clone(),
            ..state
        });

        let (status, _) = req(
            &app,
            &token,
            "PUT",
            "/api/settings/notifications",
            Some(serde_json::json!({
                "smtp_host": "mail.example.com",
                "smtp_port": 587,
                "smtp_username": "alerts",
                "smtp_password": "hunter2",
                "smtp_from_address": "alerts@example.com",
                "telegram_bot_token": "123:ABC",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // The leak itself: a plain read must never carry the real values.
        let (_, after) = req(&app, &token, "GET", "/api/settings/notifications", None).await;
        assert_eq!(after["smtp_host"], "mail.example.com");
        assert_eq!(
            after["smtp_password"], "",
            "redacted to a blank placeholder, not the real secret"
        );
        assert_eq!(
            after["telegram_bot_token"], "",
            "redacted to a blank placeholder, not the real secret"
        );

        // An unrelated edit (just changing smtp_host) submitted with those now-always-blank
        // fields must not wipe the real credentials server-side.
        let (status, _) = req(
            &app,
            &token,
            "PUT",
            "/api/settings/notifications",
            Some(serde_json::json!({
                "smtp_host": "mail2.example.com",
                "smtp_port": 587,
                "smtp_username": "alerts",
                "smtp_password": "",
                "smtp_from_address": "alerts@example.com",
                "telegram_bot_token": "",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let stored = settings.get_notification_provider().await.unwrap().unwrap();
        assert_eq!(
            stored.smtp_host.as_deref(),
            Some("mail2.example.com"),
            "the actual intended change must still take effect"
        );
        assert_eq!(
            stored.smtp_password.as_deref(),
            Some("hunter2"),
            "a blank smtp_password on edit must preserve the existing one, not clear it"
        );
        assert_eq!(
            stored.telegram_bot_token.as_deref(),
            Some("123:ABC"),
            "a blank telegram_bot_token on edit must preserve the existing one, not clear it"
        );

        let (_, journal_body) = req(
            &app,
            &token,
            "GET",
            "/api/journal?domain=notifications",
            None,
        )
        .await;
        let dump = serde_json::to_string(&journal_body).unwrap();
        assert!(
            !dump.contains("hunter2"),
            "smtp_password must never reach the journal diff"
        );
        assert!(
            !dump.contains("123:ABC"),
            "telegram_bot_token must never reach the journal diff"
        );
    }

    /// Regression test for a real bug found live 2026-09-18 (OpenRouter provider's own
    /// live verification pass, see `REDACTED_DIFF_KEYS`'s docs): `client_secret`/
    /// `openrouter_api_key` were never covered by the bare `"secret"` entry in that list
    /// (exact-string match, not substring) — a real edit put both plaintext secrets into
    /// the Журнал. Same shape as `notification_provider_secrets_are_redacted_on_read_preserved_across_edit_and_never_reach_the_journal`
    /// above, extended to cover both providers' secret fields in one config.
    #[tokio::test]
    async fn ai_assistant_provider_secrets_are_redacted_on_read_preserved_across_edit_and_never_reach_the_journal(
    ) {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        let (_, state, token) = test_app().await;
        let db = discovery_migration::connect_in_memory_for_tests().await;
        let key = Arc::new(
            discovery_core::secret::SecretKey::from_base64(&STANDARD.encode([5u8; 32])).unwrap(),
        );
        let settings: Arc<dyn SettingsStore> =
            Arc::new(discovery_config_store::SeaOrmSettingsStore::new(db).with_secret_key(key));
        let app = router(DashboardState {
            settings: settings.clone(),
            ..state
        });

        let (status, _) = req(
            &app,
            &token,
            "PUT",
            "/api/settings/ai-assistant",
            Some(serde_json::json!({
                "enabled": true,
                "provider": "openrouter",
                "client_id": "gigachat-client",
                "client_secret": "hunter2",
                "openrouter_api_key": "sk-or-v1-hunter2",
                "openrouter_model": "openai/gpt-4o-mini",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // The leak itself: a plain read must never carry the real values.
        let (_, after) = req(&app, &token, "GET", "/api/settings/ai-assistant", None).await;
        assert_eq!(after["client_id"], "gigachat-client");
        assert_eq!(
            after["client_secret"], "",
            "redacted to a blank placeholder, not the real secret"
        );
        assert_eq!(
            after["openrouter_api_key"], "",
            "redacted to a blank placeholder, not the real secret"
        );

        // An unrelated edit (just changing the model) submitted with those now-always-blank
        // fields must not wipe the real credentials server-side.
        let (status, _) = req(
            &app,
            &token,
            "PUT",
            "/api/settings/ai-assistant",
            Some(serde_json::json!({
                "enabled": true,
                "provider": "openrouter",
                "client_id": "gigachat-client",
                "client_secret": "",
                "openrouter_api_key": "",
                "openrouter_model": "openai/gpt-4o",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let stored = settings.get_ai_assistant_provider().await.unwrap().unwrap();
        assert_eq!(
            stored.openrouter_model, "openai/gpt-4o",
            "the actual intended change must still take effect"
        );
        assert_eq!(
            stored.client_secret.as_deref(),
            Some("hunter2"),
            "a blank client_secret on edit must preserve the existing one, not clear it"
        );
        assert_eq!(
            stored.openrouter_api_key.as_deref(),
            Some("sk-or-v1-hunter2"),
            "a blank openrouter_api_key on edit must preserve the existing one, not clear it"
        );

        let (_, journal_body) = req(
            &app,
            &token,
            "GET",
            "/api/journal?domain=ai_assistant",
            None,
        )
        .await;
        let dump = serde_json::to_string(&journal_body).unwrap();
        assert!(
            !dump.contains("hunter2"),
            "client_secret must never reach the journal diff"
        );
        assert!(
            !dump.contains("sk-or-v1-hunter2"),
            "openrouter_api_key must never reach the journal diff"
        );
    }

    /// Same shape as `ai_assistant_provider_secrets_are_redacted_on_read_preserved_across_edit_and_never_reach_the_journal`
    /// above, for `self_hosted_api_key` (2026-09-19, third provider) — applied proactively
    /// this time given the lesson from the OpenRouter one, not found live again.
    #[tokio::test]
    async fn ai_assistant_provider_self_hosted_api_key_is_redacted_on_read_preserved_across_edit_and_never_reaches_the_journal(
    ) {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        let (_, state, token) = test_app().await;
        let db = discovery_migration::connect_in_memory_for_tests().await;
        let key = Arc::new(
            discovery_core::secret::SecretKey::from_base64(&STANDARD.encode([8u8; 32])).unwrap(),
        );
        let settings: Arc<dyn SettingsStore> =
            Arc::new(discovery_config_store::SeaOrmSettingsStore::new(db).with_secret_key(key));
        let app = router(DashboardState {
            settings: settings.clone(),
            ..state
        });

        let (status, _) = req(
            &app,
            &token,
            "PUT",
            "/api/settings/ai-assistant",
            Some(serde_json::json!({
                "enabled": true,
                "provider": "self_hosted",
                "self_hosted_base_url": "http://vllm-host:8000/v1/chat/completions",
                "self_hosted_api_key": "hunter2",
                "self_hosted_model": "llama3",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let (_, after) = req(&app, &token, "GET", "/api/settings/ai-assistant", None).await;
        assert_eq!(
            after["self_hosted_base_url"],
            "http://vllm-host:8000/v1/chat/completions"
        );
        assert_eq!(
            after["self_hosted_api_key"], "",
            "redacted to a blank placeholder, not the real secret"
        );

        let (status, _) = req(
            &app,
            &token,
            "PUT",
            "/api/settings/ai-assistant",
            Some(serde_json::json!({
                "enabled": true,
                "provider": "self_hosted",
                "self_hosted_base_url": "http://vllm-host:8000/v1/chat/completions",
                "self_hosted_api_key": "",
                "self_hosted_model": "llama3.1",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let stored = settings.get_ai_assistant_provider().await.unwrap().unwrap();
        assert_eq!(
            stored.self_hosted_model, "llama3.1",
            "the actual intended change must still take effect"
        );
        assert_eq!(
            stored.self_hosted_api_key.as_deref(),
            Some("hunter2"),
            "a blank self_hosted_api_key on edit must preserve the existing one, not clear it"
        );

        let (_, journal_body) = req(
            &app,
            &token,
            "GET",
            "/api/journal?domain=ai_assistant",
            None,
        )
        .await;
        let dump = serde_json::to_string(&journal_body).unwrap();
        assert!(
            !dump.contains("hunter2"),
            "self_hosted_api_key must never reach the journal diff"
        );
    }

    /// `docs/Roadmap.md` "До релиза" item 13 (2026-09-14) — RBAC под нагрузкой реального
    /// многопользовательского сценария. Existing coverage
    /// (`read_permission_allows_get_but_not_write_write_allows_both` etc.) proves the
    /// permission *logic* is correct one request at a time, sequentially — this proves it
    /// stays correctly scoped to the right user's own session/role even when several
    /// different users' requests are genuinely in flight *concurrently* against the same
    /// shared `Router`/`DashboardState`, real multi-user load, not a request-per-turn
    /// simulation. The class of bug this specifically guards against — a session/role
    /// lookup that's supposed to be scoped per-request accidentally resolving against a
    /// *different*, concurrently-in-flight user's identity (e.g. a shared/global cache or
    /// a request-scoped value threaded incorrectly) — can only ever show up under genuine
    /// concurrency; a sequential test, however thorough, structurally cannot exercise it.
    #[tokio::test]
    async fn rbac_stays_correctly_scoped_per_user_under_real_concurrent_multi_user_load() {
        let (app, state, admin_token) = test_app().await;

        let reader_role = state
            .auth
            .create_role(
                "reader",
                HashMap::from([(Domain::Devices, AccessLevel::Read)]),
            )
            .await
            .unwrap();
        state
            .auth
            .create_user("reader", "pw", false, false, Some(reader_role.id))
            .await
            .unwrap();
        let writer_role = state
            .auth
            .create_role(
                "writer",
                HashMap::from([(Domain::Devices, AccessLevel::Write)]),
            )
            .await
            .unwrap();
        state
            .auth
            .create_user("writer", "pw", false, false, Some(writer_role.id))
            .await
            .unwrap();
        state
            .auth
            .create_user("noperm", "pw", false, false, None)
            .await
            .unwrap();

        let (_, reader_login) = login_req(&app, "reader", "pw").await;
        let reader_token = reader_login["token"].as_str().unwrap().to_string();
        let (_, writer_login) = login_req(&app, "writer", "pw").await;
        let writer_token = writer_login["token"].as_str().unwrap().to_string();
        let (_, noperm_login) = login_req(&app, "noperm", "pw").await;
        let noperm_token = noperm_login["token"].as_str().unwrap().to_string();

        // Each of the four users probed against both a read and a write endpoint on the
        // same domain, so a cross-request scoping bug (this user's request resolved
        // against a *different* concurrently-in-flight user's session/role) would surface
        // as an unexpected status for *someone* specific, not just a vague failure.
        #[derive(Clone)]
        struct Probe {
            token: String,
            method: &'static str,
            uri: &'static str,
            expected: StatusCode,
        }
        let probes = vec![
            Probe {
                token: admin_token.clone(),
                method: "GET",
                uri: "/api/devices",
                expected: StatusCode::OK,
            },
            Probe {
                token: admin_token.clone(),
                method: "PUT",
                uri: "/api/devices/enabled",
                expected: StatusCode::OK,
            },
            Probe {
                token: reader_token.clone(),
                method: "GET",
                uri: "/api/devices",
                expected: StatusCode::OK,
            },
            Probe {
                token: reader_token.clone(),
                method: "PUT",
                uri: "/api/devices/enabled",
                expected: StatusCode::FORBIDDEN,
            },
            Probe {
                token: writer_token.clone(),
                method: "GET",
                uri: "/api/devices",
                expected: StatusCode::OK,
            },
            Probe {
                token: writer_token.clone(),
                method: "PUT",
                uri: "/api/devices/enabled",
                expected: StatusCode::OK,
            },
            Probe {
                token: noperm_token.clone(),
                method: "GET",
                uri: "/api/devices",
                expected: StatusCode::FORBIDDEN,
            },
            Probe {
                token: noperm_token.clone(),
                method: "PUT",
                uri: "/api/devices/enabled",
                expected: StatusCode::FORBIDDEN,
            },
        ];

        // A large, round-robin-interleaved batch of the 8 probes above, all spawned before
        // any of them is awaited — genuinely concurrent, real multi-user load against the
        // one shared router, not requests dispatched one at a time.
        let mut tasks = Vec::new();
        for i in 0..200usize {
            let probe = probes[i % probes.len()].clone();
            let app = app.clone();
            tasks.push(tokio::spawn(async move {
                let body = if probe.method == "PUT" {
                    Some(serde_json::json!({"enabled": true}))
                } else {
                    None
                };
                let (status, resp_body) =
                    req(&app, &probe.token, probe.method, probe.uri, body).await;
                (probe.expected, status, resp_body)
            }));
        }
        for t in tasks {
            let (expected, actual, body) = t.await.unwrap();
            assert_eq!(actual, expected, "a concurrent request got the wrong status for its own user's role -- possible cross-request auth state leak: body={body}");
        }
    }

    // -------------------------------------------------------------------- AI assistant
    //
    // `send_message_with_provider`/`confirm_action_with_provider`/
    // `reject_action_with_provider` (not the `send_message`/`confirm_action`/
    // `reject_action` REST handlers directly) — the REST handlers always build a real
    // `GigaChatProvider` from `state.settings.ai_assistant_provider()`, which needs real
    // network-reachable credentials; the `_with_provider` split exists specifically so
    // these tests can inject `discovery_llm::FakeLlmProvider` while still exercising real
    // permission enforcement (`execute_tool_call` still runs the tool through the real
    // in-process router either way). Ownership isolation is tested through the real REST
    // routes instead, since it never reaches provider construction.

    fn authed_headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        headers
    }

    #[tokio::test]
    async fn assistant_read_tool_executes_automatically_and_loop_continues_to_final_text() {
        let (_app, state, token) = test_app().await;
        let admin = state
            .auth
            .authenticate_session(&token)
            .await
            .unwrap()
            .unwrap();
        let conversation = state
            .assistant
            .create_conversation(admin.id, "test")
            .await
            .unwrap();
        let headers = authed_headers(&token);

        let fake = discovery_llm::FakeLlmProvider::with_responses(vec![
            discovery_llm::LlmTurn {
                text: None,
                tool_call: Some(discovery_llm::ToolCall {
                    name: "list_alerts".to_string(),
                    arguments: serde_json::json!({}),
                    id: None,
                }),
            },
            discovery_llm::LlmTurn {
                text: Some("Активных тревог нет".to_string()),
                tool_call: None,
            },
        ]);

        let response = assistant::send_message_with_provider(
            &state,
            &headers,
            conversation.id,
            "покажи тревоги".to_string(),
            &fake,
        )
        .await
        .unwrap();
        assert_eq!(response.status, "final");
        assert_eq!(
            response.message.content.as_deref(),
            Some("Активных тревог нет")
        );
        assert_eq!(
            fake.call_count().await,
            2,
            "the loop must call the model again after the read tool executed"
        );

        let messages = state
            .assistant
            .list_messages(conversation.id)
            .await
            .unwrap();
        assert_eq!(
            messages.len(),
            4,
            "user, assistant(tool_call, executed), tool(result), assistant(final text)"
        );
        assert_eq!(
            messages[1].tool_call_status,
            discovery_assistant::ToolCallStatus::Executed
        );
    }

    /// SEC-21 (2026-09-22) — every call to the model must lead with a `System`-role
    /// message instructing it to treat tool-returned data (device/alert data pulled from
    /// the monitored network) as untrusted, not as instructions to follow. Not persisted
    /// in the conversation's own `Message` history (see `assistant::ASSISTANT_SYSTEM_PROMPT`'s
    /// docs) — it only shows up in what actually gets sent to the provider, which is why
    /// this asserts against `fake.calls`, not `state.assistant.list_messages`.
    #[tokio::test]
    async fn assistant_turn_prepends_a_system_prompt_on_every_call() {
        let (_app, state, token) = test_app().await;
        let admin = state
            .auth
            .authenticate_session(&token)
            .await
            .unwrap()
            .unwrap();
        let conversation = state
            .assistant
            .create_conversation(admin.id, "test")
            .await
            .unwrap();
        let headers = authed_headers(&token);

        let fake = discovery_llm::FakeLlmProvider::with_responses(vec![
            discovery_llm::LlmTurn {
                text: None,
                tool_call: Some(discovery_llm::ToolCall {
                    name: "list_alerts".to_string(),
                    arguments: serde_json::json!({}),
                    id: None,
                }),
            },
            discovery_llm::LlmTurn {
                text: Some("Активных тревог нет".to_string()),
                tool_call: None,
            },
        ]);
        assistant::send_message_with_provider(
            &state,
            &headers,
            conversation.id,
            "покажи тревоги".to_string(),
            &fake,
        )
        .await
        .unwrap();

        let calls = fake.calls.lock().await;
        assert_eq!(calls.len(), 2, "one call per loop iteration");
        for (history, _) in calls.iter() {
            assert_eq!(
                history[0].role,
                discovery_llm::LlmRole::System,
                "the system prompt must be first on every call, not just the first one"
            );
            let content = history[0].content.as_deref().unwrap_or_default();
            assert!(
                content.contains("ВНЕШНИЕ ДАННЫЕ")
                    || content.to_lowercase().contains("не инструкции")
                    || content.to_lowercase().contains("untrusted"),
                "system prompt must explicitly frame tool results as untrusted data: {content}"
            );
        }
    }

    #[tokio::test]
    async fn assistant_write_tool_call_stops_for_confirmation_without_executing() {
        let (_app, state, token) = test_app().await;
        let admin = state
            .auth
            .authenticate_session(&token)
            .await
            .unwrap()
            .unwrap();
        let conversation = state
            .assistant
            .create_conversation(admin.id, "test")
            .await
            .unwrap();
        let headers = authed_headers(&token);

        let alert = an_alert(
            "high_cpu",
            "10.0.0.5",
            Uuid::new_v4(),
            AlertLevel::Critical,
            AlertState::Active,
        );
        state.alert_store.upsert(&alert).await.unwrap();

        let fake = discovery_llm::FakeLlmProvider::with_responses(vec![discovery_llm::LlmTurn {
            text: None,
            tool_call: Some(discovery_llm::ToolCall {
                name: "close_alert".to_string(),
                arguments: serde_json::json!({"id": alert.id.to_string()}),
                id: None,
            }),
        }]);

        let response = assistant::send_message_with_provider(
            &state,
            &headers,
            conversation.id,
            "закрой тревогу".to_string(),
            &fake,
        )
        .await
        .unwrap();
        assert_eq!(response.status, "awaiting_confirmation");
        assert_eq!(
            response.message.tool_call_status,
            discovery_assistant::ToolCallStatus::PendingConfirmation
        );
        assert_eq!(
            fake.call_count().await,
            1,
            "the loop must stop, not call the model again, once a write tool call is pending"
        );

        let still_active = state.alert_store.get(alert.id).await.unwrap().unwrap();
        assert_eq!(
            still_active.state,
            AlertState::Active,
            "must not execute before confirmation"
        );
    }

    #[tokio::test]
    async fn assistant_confirming_pending_action_executes_and_changes_real_state() {
        let (_app, state, token) = test_app().await;
        let admin = state
            .auth
            .authenticate_session(&token)
            .await
            .unwrap()
            .unwrap();
        let conversation = state
            .assistant
            .create_conversation(admin.id, "test")
            .await
            .unwrap();
        let headers = authed_headers(&token);

        let alert = an_alert(
            "high_cpu",
            "10.0.0.5",
            Uuid::new_v4(),
            AlertLevel::Critical,
            AlertState::Active,
        );
        state.alert_store.upsert(&alert).await.unwrap();

        let fake1 = discovery_llm::FakeLlmProvider::with_responses(vec![discovery_llm::LlmTurn {
            text: None,
            tool_call: Some(discovery_llm::ToolCall {
                name: "close_alert".to_string(),
                arguments: serde_json::json!({"id": alert.id.to_string()}),
                id: None,
            }),
        }]);
        let pending = assistant::send_message_with_provider(
            &state,
            &headers,
            conversation.id,
            "закрой тревогу".to_string(),
            &fake1,
        )
        .await
        .unwrap();
        assert_eq!(pending.status, "awaiting_confirmation");

        let fake2 = discovery_llm::FakeLlmProvider::with_responses(vec![discovery_llm::LlmTurn {
            text: Some("Готово, тревога закрыта".to_string()),
            tool_call: None,
        }]);
        let confirmed = assistant::confirm_action_with_provider(
            &state,
            &headers,
            conversation.id,
            pending.message.id,
            &fake2,
        )
        .await
        .unwrap();
        assert_eq!(confirmed.status, "final");

        let closed = state.alert_store.get(alert.id).await.unwrap().unwrap();
        assert_eq!(
            closed.state,
            AlertState::Cleared,
            "confirming must actually execute the write"
        );
        assert_eq!(closed.closed_by.as_deref(), Some("test-admin"));
    }

    /// TASK-20260922-001 — `comment_alert`'s `ToolDef` pointed at `PUT
    /// /api/alerts/{id}/comment` (singular), which no route ever matched; every call
    /// unconditionally 404'd. Fixed to `POST /api/alerts/{id}/comments` (plural, the real
    /// `add_alert_comment` route) — this pins the fix down with an assertion that the
    /// comment actually lands, not just that the tool call stops for confirmation.
    #[tokio::test]
    async fn assistant_comment_alert_write_tool_actually_adds_a_comment() {
        let (app, state, token) = test_app().await;
        let admin = state
            .auth
            .authenticate_session(&token)
            .await
            .unwrap()
            .unwrap();
        let conversation = state
            .assistant
            .create_conversation(admin.id, "test")
            .await
            .unwrap();
        let headers = authed_headers(&token);

        let alert = an_alert(
            "high_cpu",
            "10.0.0.7",
            Uuid::new_v4(),
            AlertLevel::Critical,
            AlertState::Active,
        );
        state.alert_store.upsert(&alert).await.unwrap();

        let fake1 = discovery_llm::FakeLlmProvider::with_responses(vec![discovery_llm::LlmTurn {
            text: None,
            tool_call: Some(discovery_llm::ToolCall {
                name: "comment_alert".to_string(),
                arguments: serde_json::json!({"id": alert.id.to_string(), "text": "investigating via assistant"}),
                id: None,
            }),
        }]);
        let pending = assistant::send_message_with_provider(
            &state,
            &headers,
            conversation.id,
            "прокомментируй тревогу".to_string(),
            &fake1,
        )
        .await
        .unwrap();
        assert_eq!(pending.status, "awaiting_confirmation");

        let fake2 = discovery_llm::FakeLlmProvider::with_responses(vec![discovery_llm::LlmTurn {
            text: Some("Готово, комментарий добавлен".to_string()),
            tool_call: None,
        }]);
        let confirmed = assistant::confirm_action_with_provider(
            &state,
            &headers,
            conversation.id,
            pending.message.id,
            &fake2,
        )
        .await
        .unwrap();
        assert_eq!(confirmed.status, "final");

        let (status, body) = req(
            &app,
            &token,
            "GET",
            &format!("/api/alerts/{}/comments", alert.id),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let comments = body.as_array().unwrap();
        assert_eq!(comments.len(), 1, "the tool call must have actually reached add_alert_comment, not 404'd against a nonexistent route");
        assert_eq!(comments[0]["text"], "investigating via assistant");
    }

    #[tokio::test]
    async fn assistant_rejecting_pending_action_does_not_change_state() {
        let (_app, state, token) = test_app().await;
        let admin = state
            .auth
            .authenticate_session(&token)
            .await
            .unwrap()
            .unwrap();
        let conversation = state
            .assistant
            .create_conversation(admin.id, "test")
            .await
            .unwrap();
        let headers = authed_headers(&token);

        let alert = an_alert(
            "high_cpu",
            "10.0.0.5",
            Uuid::new_v4(),
            AlertLevel::Critical,
            AlertState::Active,
        );
        state.alert_store.upsert(&alert).await.unwrap();

        let fake1 = discovery_llm::FakeLlmProvider::with_responses(vec![discovery_llm::LlmTurn {
            text: None,
            tool_call: Some(discovery_llm::ToolCall {
                name: "close_alert".to_string(),
                arguments: serde_json::json!({"id": alert.id.to_string()}),
                id: None,
            }),
        }]);
        let pending = assistant::send_message_with_provider(
            &state,
            &headers,
            conversation.id,
            "закрой тревогу".to_string(),
            &fake1,
        )
        .await
        .unwrap();

        let fake2 = discovery_llm::FakeLlmProvider::with_responses(vec![discovery_llm::LlmTurn {
            text: Some("Хорошо, не буду закрывать".to_string()),
            tool_call: None,
        }]);
        let rejected = assistant::reject_action_with_provider(
            &state,
            &headers,
            conversation.id,
            pending.message.id,
            &fake2,
        )
        .await
        .unwrap();
        assert_eq!(rejected.status, "final");

        let still_active = state.alert_store.get(alert.id).await.unwrap().unwrap();
        assert_eq!(still_active.state, AlertState::Active);

        let messages = state
            .assistant
            .list_messages(conversation.id)
            .await
            .unwrap();
        let decline_result = messages.iter().find_map(|m| {
            m.tool_result
                .as_ref()
                .filter(|r| r.get("declined_by_user").is_some())
        });
        let decline_result =
            decline_result.expect("a synthetic declined_by_user tool result must be recorded");
        // Regression test for a real bug caught during live verification against the real
        // GigaChat model (2026-09-18): with only `{"declined_by_user": true}`, the model
        // reliably narrated the rejected action back to the user as successfully completed
        // anyway — it has no special-cased understanding of that field name and apparently
        // defaults to assuming success from any function-role result. `executed: false`
        // plus a plain-language `message` fixed it live; assert both are actually present
        // on every reject, not just the structural `declined_by_user` marker.
        assert_eq!(
            decline_result.get("executed"),
            Some(&serde_json::json!(false)),
            "must explicitly tell the model the action did not execute"
        );
        assert!(
            decline_result
                .get("message")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty()),
            "must carry a plain-language explanation the model can narrate correctly"
        );
    }

    #[tokio::test]
    async fn assistant_confirm_without_write_permission_surfaces_403_not_panic() {
        let (app, state, _admin_token) = test_app().await;
        let reader_role = state
            .auth
            .create_role(
                "alerts-reader",
                HashMap::from([(Domain::Alerts, AccessLevel::Read)]),
            )
            .await
            .unwrap();
        state
            .auth
            .create_user(
                "alerts-reader-user",
                "pw",
                false,
                false,
                Some(reader_role.id),
            )
            .await
            .unwrap();
        let (_, login) = login_req(&app, "alerts-reader-user", "pw").await;
        let reader_token = login["token"].as_str().unwrap().to_string();
        let reader = state
            .auth
            .authenticate_session(&reader_token)
            .await
            .unwrap()
            .unwrap();

        let conversation = state
            .assistant
            .create_conversation(reader.id, "test")
            .await
            .unwrap();
        let headers = authed_headers(&reader_token);

        let alert = an_alert(
            "high_cpu",
            "10.0.0.5",
            Uuid::new_v4(),
            AlertLevel::Critical,
            AlertState::Active,
        );
        state.alert_store.upsert(&alert).await.unwrap();

        let fake1 = discovery_llm::FakeLlmProvider::with_responses(vec![discovery_llm::LlmTurn {
            text: None,
            tool_call: Some(discovery_llm::ToolCall {
                name: "close_alert".to_string(),
                arguments: serde_json::json!({"id": alert.id.to_string()}),
                id: None,
            }),
        }]);
        let pending = assistant::send_message_with_provider(
            &state,
            &headers,
            conversation.id,
            "закрой тревогу".to_string(),
            &fake1,
        )
        .await
        .unwrap();

        let fake2 = discovery_llm::FakeLlmProvider::with_responses(vec![discovery_llm::LlmTurn {
            text: Some("Не получилось".to_string()),
            tool_call: None,
        }]);
        let confirmed = assistant::confirm_action_with_provider(
            &state,
            &headers,
            conversation.id,
            pending.message.id,
            &fake2,
        )
        .await
        .unwrap();
        assert_eq!(
            confirmed.status, "final",
            "must not panic — the 403 is surfaced as a tool result, not an error return"
        );

        let still_active = state.alert_store.get(alert.id).await.unwrap().unwrap();
        assert_eq!(
            still_active.state,
            AlertState::Active,
            "a read-only user's confirm must not actually close the alert"
        );

        let messages = state
            .assistant
            .list_messages(conversation.id)
            .await
            .unwrap();
        let tool_result_msg = messages
            .iter()
            .rev()
            .find(|m| m.role == discovery_assistant::MessageRole::Tool && m.tool_result.is_some())
            .unwrap();
        let status_code = tool_result_msg
            .tool_result
            .as_ref()
            .unwrap()
            .get("status_code")
            .and_then(|v| v.as_u64())
            .unwrap();
        assert_eq!(status_code, 403);
    }

    #[tokio::test]
    async fn assistant_turn_loop_terminates_at_iteration_cap() {
        let (_app, state, token) = test_app().await;
        let admin = state
            .auth
            .authenticate_session(&token)
            .await
            .unwrap()
            .unwrap();
        let conversation = state
            .assistant
            .create_conversation(admin.id, "test")
            .await
            .unwrap();
        let headers = authed_headers(&token);

        // Scripted to always request the same read-only tool — never converges to a final
        // text reply on its own; the loop's own iteration cap must be what stops it.
        let responses: Vec<_> = (0..20)
            .map(|_| discovery_llm::LlmTurn {
                text: None,
                tool_call: Some(discovery_llm::ToolCall {
                    name: "list_alerts".to_string(),
                    arguments: serde_json::json!({}),
                    id: None,
                }),
            })
            .collect();
        let fake = discovery_llm::FakeLlmProvider::with_responses(responses);

        let response = assistant::send_message_with_provider(
            &state,
            &headers,
            conversation.id,
            "покажи тревоги".to_string(),
            &fake,
        )
        .await
        .unwrap();
        assert_eq!(
            response.status, "final",
            "must terminate with a synthetic final message, not loop forever"
        );
        assert_eq!(
            fake.call_count().await,
            8,
            "must stop exactly at the iteration cap"
        );
    }

    #[tokio::test]
    async fn assistant_conversation_ownership_is_isolated_between_users() {
        let (app, state, _admin_token) = test_app().await;
        state
            .auth
            .create_user("alice", "pw", false, false, None)
            .await
            .unwrap();
        state
            .auth
            .create_user("bob", "pw", false, false, None)
            .await
            .unwrap();
        let (_, alice_login) = login_req(&app, "alice", "pw").await;
        let alice_token = alice_login["token"].as_str().unwrap().to_string();
        let (_, bob_login) = login_req(&app, "bob", "pw").await;
        let bob_token = bob_login["token"].as_str().unwrap().to_string();

        let (status, body) = req(
            &app,
            &alice_token,
            "POST",
            "/api/assistant/conversations",
            Some(serde_json::json!({"title": "alice chat"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let conversation_id = body["id"].as_str().unwrap();

        let (status, _) = req(
            &app,
            &bob_token,
            "GET",
            &format!("/api/assistant/conversations/{conversation_id}/messages"),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "bob must not be able to read alice's conversation"
        );

        let (status, _) = req(
            &app,
            &bob_token,
            "POST",
            &format!("/api/assistant/conversations/{conversation_id}/messages"),
            Some(serde_json::json!({"content": "hi"})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "bob must not be able to message into alice's conversation"
        );
    }

    // ---------------------------------------------------------- new domains (2026-09-18)
    //
    // One read-tool + one write-tool-pending-confirmation pair per newly-added "operational"
    // domain — same minimal shape as the Alerts pair above, not exhaustive per-tool
    // coverage (the generic `assistant_tools::tests` already prove every tool's schema/path
    // template is well-formed; these prove the domain actually wires through the real
    // in-process router end to end).

    #[tokio::test]
    async fn assistant_get_metric_history_read_tool_executes_automatically() {
        let (app, state, token) = test_app().await;
        let admin = state
            .auth
            .authenticate_session(&token)
            .await
            .unwrap()
            .unwrap();
        let conversation = state
            .assistant
            .create_conversation(admin.id, "test")
            .await
            .unwrap();
        let headers = authed_headers(&token);
        let (_, dev_body) = req(
            &app,
            &token,
            "POST",
            "/api/devices",
            Some(serde_json::json!({"ip": "10.9.10.1"})),
        )
        .await;
        let device_id = dev_body["id"].as_str().unwrap().to_string();

        let fake = discovery_llm::FakeLlmProvider::with_responses(vec![
            discovery_llm::LlmTurn {
                text: None,
                tool_call: Some(discovery_llm::ToolCall {
                    name: "get_metric_history".to_string(),
                    arguments: serde_json::json!({"id": device_id, "name": "cpu"}),
                    id: None,
                }),
            },
            discovery_llm::LlmTurn {
                text: Some("История пуста".to_string()),
                tool_call: None,
            },
        ]);
        let response = assistant::send_message_with_provider(
            &state,
            &headers,
            conversation.id,
            "история cpu".to_string(),
            &fake,
        )
        .await
        .unwrap();
        assert_eq!(response.status, "final");
    }

    #[tokio::test]
    async fn assistant_set_metric_override_write_tool_stops_for_confirmation() {
        let (app, state, token) = test_app().await;
        let admin = state
            .auth
            .authenticate_session(&token)
            .await
            .unwrap()
            .unwrap();
        let conversation = state
            .assistant
            .create_conversation(admin.id, "test")
            .await
            .unwrap();
        let headers = authed_headers(&token);
        let (_, dev_body) = req(
            &app,
            &token,
            "POST",
            "/api/devices",
            Some(serde_json::json!({"ip": "10.9.10.2"})),
        )
        .await;
        let device_id = dev_body["id"].as_str().unwrap().to_string();

        let fake = discovery_llm::FakeLlmProvider::with_responses(vec![discovery_llm::LlmTurn {
            text: None,
            tool_call: Some(discovery_llm::ToolCall {
                name: "set_metric_override".to_string(),
                arguments: serde_json::json!({"id": device_id, "name": "cpu", "enabled": false}),
                id: None,
            }),
        }]);
        let response = assistant::send_message_with_provider(
            &state,
            &headers,
            conversation.id,
            "выключи метрику cpu".to_string(),
            &fake,
        )
        .await
        .unwrap();
        assert_eq!(response.status, "awaiting_confirmation");

        let overrides = state
            .devices
            .get_metric_overrides(Uuid::parse_str(&device_id).unwrap())
            .await
            .unwrap();
        assert!(overrides.is_empty(), "must not execute before confirmation");
    }

    fn an_assistant_test_profile(name: &str) -> discovery_dsl::ProfileFile {
        discovery_dsl::ProfileFile {
            profile: discovery_dsl::ProfileMeta {
                name: name.to_string(),
                priority: 0,
            },
            match_expr: discovery_dsl::MatchSection {
                expression: "true".to_string(),
            },
            metrics: Default::default(),
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            alerts: vec![],
            version: String::new(),
        }
    }

    #[tokio::test]
    async fn assistant_list_profiles_read_tool_executes_automatically() {
        let (_app, state, token) = test_app().await;
        let admin = state
            .auth
            .authenticate_session(&token)
            .await
            .unwrap()
            .unwrap();
        let conversation = state
            .assistant
            .create_conversation(admin.id, "test")
            .await
            .unwrap();
        let headers = authed_headers(&token);
        state
            .profiles
            .upsert(&an_assistant_test_profile("asw-test"))
            .await
            .unwrap();

        let fake = discovery_llm::FakeLlmProvider::with_responses(vec![
            discovery_llm::LlmTurn {
                text: None,
                tool_call: Some(discovery_llm::ToolCall {
                    name: "list_profiles".to_string(),
                    arguments: serde_json::json!({}),
                    id: None,
                }),
            },
            discovery_llm::LlmTurn {
                text: Some("Один профиль".to_string()),
                tool_call: None,
            },
        ]);
        let response = assistant::send_message_with_provider(
            &state,
            &headers,
            conversation.id,
            "покажи профили".to_string(),
            &fake,
        )
        .await
        .unwrap();
        assert_eq!(response.status, "final");
    }

    #[tokio::test]
    async fn assistant_delete_profile_write_tool_stops_for_confirmation() {
        let (_app, state, token) = test_app().await;
        let admin = state
            .auth
            .authenticate_session(&token)
            .await
            .unwrap()
            .unwrap();
        let conversation = state
            .assistant
            .create_conversation(admin.id, "test")
            .await
            .unwrap();
        let headers = authed_headers(&token);
        state
            .profiles
            .upsert(&an_assistant_test_profile("asw-test"))
            .await
            .unwrap();

        let fake = discovery_llm::FakeLlmProvider::with_responses(vec![discovery_llm::LlmTurn {
            text: None,
            tool_call: Some(discovery_llm::ToolCall {
                name: "delete_profile".to_string(),
                arguments: serde_json::json!({"name": "asw-test"}),
                id: None,
            }),
        }]);
        let response = assistant::send_message_with_provider(
            &state,
            &headers,
            conversation.id,
            "удали профиль asw-test".to_string(),
            &fake,
        )
        .await
        .unwrap();
        assert_eq!(response.status, "awaiting_confirmation");

        let still_there = state.profiles.load_all().await.unwrap();
        assert!(
            still_there.iter().any(|p| p.profile.name == "asw-test"),
            "must not execute before confirmation"
        );
    }

    #[tokio::test]
    async fn assistant_get_logs_read_tool_executes_automatically() {
        let (_app, state, token) = test_app().await;
        let admin = state
            .auth
            .authenticate_session(&token)
            .await
            .unwrap()
            .unwrap();
        let conversation = state
            .assistant
            .create_conversation(admin.id, "test")
            .await
            .unwrap();
        let headers = authed_headers(&token);
        state.logs.push(discovery_logging::LogEntry {
            timestamp: chrono::Utc::now(),
            level: "INFO".to_string(),
            target: "discovery_agent".to_string(),
            message: "test log line".to_string(),
            fields: Default::default(),
        });

        let fake = discovery_llm::FakeLlmProvider::with_responses(vec![
            discovery_llm::LlmTurn {
                text: None,
                tool_call: Some(discovery_llm::ToolCall {
                    name: "get_logs".to_string(),
                    arguments: serde_json::json!({"search": "test log line"}),
                    id: None,
                }),
            },
            discovery_llm::LlmTurn {
                text: Some("Нашёл строку".to_string()),
                tool_call: None,
            },
        ]);
        let response = assistant::send_message_with_provider(
            &state,
            &headers,
            conversation.id,
            "найди в логах test log line".to_string(),
            &fake,
        )
        .await
        .unwrap();
        assert_eq!(response.status, "final");
    }

    fn a_notification_rule(name: &str) -> discovery_config_store::NotificationRule {
        discovery_config_store::NotificationRule {
            selection: Default::default(),
            id: Uuid::new_v4(),
            name: name.to_string(),
            enabled: true,
            min_level: AlertLevel::Critical,
            subnets: vec![],
            profiles: vec![],
            device_ids: vec![],
            active_from: None,
            active_to: None,
            days_of_week: vec![],
            notify_on_activate: true,
            notify_on_clear: true,
            recipients: vec![],
            repeat_after_seconds: 0,
            repeat_interval_seconds: 0,
            max_repeats: 0,
            escalation_levels: vec![],
        }
    }

    #[tokio::test]
    async fn assistant_list_notification_rules_read_tool_executes_automatically() {
        let (_app, state, token) = test_app().await;
        let admin = state
            .auth
            .authenticate_session(&token)
            .await
            .unwrap()
            .unwrap();
        let conversation = state
            .assistant
            .create_conversation(admin.id, "test")
            .await
            .unwrap();
        let headers = authed_headers(&token);
        state
            .notification_rules
            .upsert(&a_notification_rule("critical-pages"))
            .await
            .unwrap();

        let fake = discovery_llm::FakeLlmProvider::with_responses(vec![
            discovery_llm::LlmTurn {
                text: None,
                tool_call: Some(discovery_llm::ToolCall {
                    name: "list_notification_rules".to_string(),
                    arguments: serde_json::json!({}),
                    id: None,
                }),
            },
            discovery_llm::LlmTurn {
                text: Some("Одно правило".to_string()),
                tool_call: None,
            },
        ]);
        let response = assistant::send_message_with_provider(
            &state,
            &headers,
            conversation.id,
            "покажи правила нотификации".to_string(),
            &fake,
        )
        .await
        .unwrap();
        assert_eq!(response.status, "final");
    }

    /// TASK-20260921-016 — `upsert_notification_rule`'s tool schema declared `min_level`
    /// as lowercase (`"info"|"warning"|"critical"`), but the REST body it targets
    /// deserializes straight into `AlertLevel`, which has no `#[serde(rename_all)]` and
    /// so only accepts `"Info"|"Warning"|"Critical"` — a model *following its own tool
    /// schema* got a 400 on every call. `FakeLlmProvider`-driven tests can't catch this
    /// class of bug by scripting a tool call (the fake ignores the schema entirely and
    /// just returns whatever arguments the test hardcodes — a real model would consult
    /// the schema's declared `enum` before generating a value, the fake ignores it
    /// completely), so this instead checks the actual contract: every value the schema
    /// *advertises* as valid must round-trip through `AlertLevel`'s real `Deserialize`
    /// impl the REST body uses.
    #[test]
    fn upsert_notification_rule_schema_min_level_values_are_valid_alert_levels() {
        let tools = crate::assistant_tools::v1_tools();
        let tool = tools
            .iter()
            .find(|t| t.name == "upsert_notification_rule")
            .unwrap();
        let schema = (tool.parameters_schema)();
        let declared: Vec<&str> = schema["properties"]["min_level"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(
            declared.len(),
            3,
            "must advertise exactly the three real AlertLevel variants"
        );
        for value in declared {
            let parsed: Result<AlertLevel, _> = serde_json::from_value(serde_json::json!(value));
            assert!(parsed.is_ok(), "schema advertises min_level = \"{value}\" as valid, but AlertLevel's real Deserialize impl (what NotificationRuleBody actually uses) rejects it — a model following this schema would get a 400");
        }
    }

    #[tokio::test]
    async fn assistant_delete_notification_rule_write_tool_stops_for_confirmation() {
        let (_app, state, token) = test_app().await;
        let admin = state
            .auth
            .authenticate_session(&token)
            .await
            .unwrap()
            .unwrap();
        let conversation = state
            .assistant
            .create_conversation(admin.id, "test")
            .await
            .unwrap();
        let headers = authed_headers(&token);
        let rule = a_notification_rule("critical-pages");
        state.notification_rules.upsert(&rule).await.unwrap();

        let fake = discovery_llm::FakeLlmProvider::with_responses(vec![discovery_llm::LlmTurn {
            text: None,
            tool_call: Some(discovery_llm::ToolCall {
                name: "delete_notification_rule".to_string(),
                arguments: serde_json::json!({"id": rule.id.to_string()}),
                id: None,
            }),
        }]);
        let response = assistant::send_message_with_provider(
            &state,
            &headers,
            conversation.id,
            "удали правило critical-pages".to_string(),
            &fake,
        )
        .await
        .unwrap();
        assert_eq!(response.status, "awaiting_confirmation");
        assert!(
            state
                .notification_rules
                .get(rule.id)
                .await
                .unwrap()
                .is_some(),
            "must not execute before confirmation"
        );
    }

    fn a_topology_rule(name: &str) -> discovery_config_store::TopologyRule {
        discovery_config_store::TopologyRule {
            id: Uuid::new_v4(),
            name: name.to_string(),
            enabled: true,
            my_key_expression: "metrics.lldp_chassis_id".to_string(),
            claimed_neighbors_expression: None,
            rank_expression: None,
            watched_metrics: None,
        }
    }

    #[tokio::test]
    async fn assistant_list_topology_rules_read_tool_executes_automatically() {
        let (_app, state, token) = test_app().await;
        let admin = state
            .auth
            .authenticate_session(&token)
            .await
            .unwrap()
            .unwrap();
        let conversation = state
            .assistant
            .create_conversation(admin.id, "test")
            .await
            .unwrap();
        let headers = authed_headers(&token);
        state
            .topology_rules
            .upsert(&a_topology_rule("lldp"))
            .await
            .unwrap();

        let fake = discovery_llm::FakeLlmProvider::with_responses(vec![
            discovery_llm::LlmTurn {
                text: None,
                tool_call: Some(discovery_llm::ToolCall {
                    name: "list_topology_rules".to_string(),
                    arguments: serde_json::json!({}),
                    id: None,
                }),
            },
            discovery_llm::LlmTurn {
                text: Some("Одно правило".to_string()),
                tool_call: None,
            },
        ]);
        let response = assistant::send_message_with_provider(
            &state,
            &headers,
            conversation.id,
            "покажи правила топологии".to_string(),
            &fake,
        )
        .await
        .unwrap();
        assert_eq!(response.status, "final");
    }

    #[tokio::test]
    async fn assistant_delete_topology_rule_write_tool_stops_for_confirmation() {
        let (_app, state, token) = test_app().await;
        let admin = state
            .auth
            .authenticate_session(&token)
            .await
            .unwrap()
            .unwrap();
        let conversation = state
            .assistant
            .create_conversation(admin.id, "test")
            .await
            .unwrap();
        let headers = authed_headers(&token);
        let rule = a_topology_rule("lldp");
        state.topology_rules.upsert(&rule).await.unwrap();

        let fake = discovery_llm::FakeLlmProvider::with_responses(vec![discovery_llm::LlmTurn {
            text: None,
            tool_call: Some(discovery_llm::ToolCall {
                name: "delete_topology_rule".to_string(),
                arguments: serde_json::json!({"id": rule.id.to_string()}),
                id: None,
            }),
        }]);
        let response = assistant::send_message_with_provider(
            &state,
            &headers,
            conversation.id,
            "удали правило топологии lldp".to_string(),
            &fake,
        )
        .await
        .unwrap();
        assert_eq!(response.status, "awaiting_confirmation");
        assert!(
            state.topology_rules.get(rule.id).await.unwrap().is_some(),
            "must not execute before confirmation"
        );
    }

    fn a_group_alert_rule(name: &str) -> discovery_config_store::GroupAlertRule {
        discovery_config_store::GroupAlertRule {
            id: Uuid::new_v4(),
            name: name.to_string(),
            enabled: true,
            cause_expression: "true".to_string(),
            effect_expression: "true".to_string(),
        }
    }

    #[tokio::test]
    async fn assistant_list_group_alert_rules_read_tool_executes_automatically() {
        let (_app, state, token) = test_app().await;
        let admin = state
            .auth
            .authenticate_session(&token)
            .await
            .unwrap()
            .unwrap();
        let conversation = state
            .assistant
            .create_conversation(admin.id, "test")
            .await
            .unwrap();
        let headers = authed_headers(&token);
        state
            .group_alert_rules
            .upsert(&a_group_alert_rule("upstream-port-down"))
            .await
            .unwrap();

        let fake = discovery_llm::FakeLlmProvider::with_responses(vec![
            discovery_llm::LlmTurn {
                text: None,
                tool_call: Some(discovery_llm::ToolCall {
                    name: "list_group_alert_rules".to_string(),
                    arguments: serde_json::json!({}),
                    id: None,
                }),
            },
            discovery_llm::LlmTurn {
                text: Some("Одно правило".to_string()),
                tool_call: None,
            },
        ]);
        let response = assistant::send_message_with_provider(
            &state,
            &headers,
            conversation.id,
            "покажи правила группировки тревог".to_string(),
            &fake,
        )
        .await
        .unwrap();
        assert_eq!(response.status, "final");
    }

    #[tokio::test]
    async fn assistant_delete_group_alert_rule_write_tool_stops_for_confirmation() {
        let (_app, state, token) = test_app().await;
        let admin = state
            .auth
            .authenticate_session(&token)
            .await
            .unwrap()
            .unwrap();
        let conversation = state
            .assistant
            .create_conversation(admin.id, "test")
            .await
            .unwrap();
        let headers = authed_headers(&token);
        let rule = a_group_alert_rule("upstream-port-down");
        state.group_alert_rules.upsert(&rule).await.unwrap();

        let fake = discovery_llm::FakeLlmProvider::with_responses(vec![discovery_llm::LlmTurn {
            text: None,
            tool_call: Some(discovery_llm::ToolCall {
                name: "delete_group_alert_rule".to_string(),
                arguments: serde_json::json!({"id": rule.id.to_string()}),
                id: None,
            }),
        }]);
        let response = assistant::send_message_with_provider(
            &state,
            &headers,
            conversation.id,
            "удали правило группировки upstream-port-down".to_string(),
            &fake,
        )
        .await
        .unwrap();
        assert_eq!(response.status, "awaiting_confirmation");
        assert!(
            state
                .group_alert_rules
                .get(rule.id)
                .await
                .unwrap()
                .is_some(),
            "must not execute before confirmation"
        );
    }

    // ---------------------------------------------------------- DiscoveryConfigs carve-out

    fn an_assistant_test_discovery_config(name: &str) -> discovery_config_store::DiscoveryConfig {
        discovery_config_store::DiscoveryConfig {
            name: name.to_string(),
            enabled: true,
            schedule: discovery_core::Schedule::Periodic {
                interval_secs: 3600,
            },
            subnets: vec![],
        }
    }

    #[tokio::test]
    async fn assistant_create_discovery_config_succeeds_for_a_new_name() {
        let (_app, state, token) = test_app().await;
        let admin = state
            .auth
            .authenticate_session(&token)
            .await
            .unwrap()
            .unwrap();
        let conversation = state
            .assistant
            .create_conversation(admin.id, "test")
            .await
            .unwrap();
        let headers = authed_headers(&token);

        let fake1 = discovery_llm::FakeLlmProvider::with_responses(vec![discovery_llm::LlmTurn {
            text: None,
            tool_call: Some(discovery_llm::ToolCall {
                name: "create_discovery_config".to_string(),
                arguments: serde_json::json!({"name": "new-branch", "schedule": {"interval_secs": 3600}}),
                id: None,
            }),
        }]);
        let pending = assistant::send_message_with_provider(
            &state,
            &headers,
            conversation.id,
            "создай конфиг дискаверинга new-branch".to_string(),
            &fake1,
        )
        .await
        .unwrap();
        assert_eq!(pending.status, "awaiting_confirmation");

        let fake2 = discovery_llm::FakeLlmProvider::with_responses(vec![discovery_llm::LlmTurn {
            text: Some("Готово".to_string()),
            tool_call: None,
        }]);
        let confirmed = assistant::confirm_action_with_provider(
            &state,
            &headers,
            conversation.id,
            pending.message.id,
            &fake2,
        )
        .await
        .unwrap();
        assert_eq!(confirmed.status, "final");

        let configs = state.discovery_configs.load_all().await.unwrap();
        assert!(configs.iter().any(|c| c.name == "new-branch"));
    }

    #[tokio::test]
    async fn assistant_create_discovery_config_rejects_an_existing_name_without_touching_it() {
        let (_app, state, token) = test_app().await;
        let admin = state
            .auth
            .authenticate_session(&token)
            .await
            .unwrap()
            .unwrap();
        let conversation = state
            .assistant
            .create_conversation(admin.id, "test")
            .await
            .unwrap();
        let headers = authed_headers(&token);
        state
            .discovery_configs
            .upsert(&an_assistant_test_discovery_config("existing-branch"))
            .await
            .unwrap();

        let fake1 = discovery_llm::FakeLlmProvider::with_responses(vec![discovery_llm::LlmTurn {
            text: None,
            tool_call: Some(discovery_llm::ToolCall {
                name: "create_discovery_config".to_string(),
                arguments: serde_json::json!({"name": "existing-branch", "schedule": {"interval_secs": 60}}),
                id: None,
            }),
        }]);
        let pending = assistant::send_message_with_provider(
            &state,
            &headers,
            conversation.id,
            "создай конфиг existing-branch".to_string(),
            &fake1,
        )
        .await
        .unwrap();
        assert_eq!(pending.status, "awaiting_confirmation");

        let fake2 = discovery_llm::FakeLlmProvider::with_responses(vec![discovery_llm::LlmTurn {
            text: Some("Не получилось".to_string()),
            tool_call: None,
        }]);
        let confirmed = assistant::confirm_action_with_provider(
            &state,
            &headers,
            conversation.id,
            pending.message.id,
            &fake2,
        )
        .await
        .unwrap();
        assert_eq!(confirmed.status, "final");

        let configs = state.discovery_configs.load_all().await.unwrap();
        let existing = configs
            .iter()
            .find(|c| c.name == "existing-branch")
            .unwrap();
        assert!(matches!(existing.schedule, discovery_core::Schedule::Periodic { interval_secs: 3600 }), "the original config must be untouched, not overwritten by the rejected attempt's interval_secs: 60");

        let messages = state
            .assistant
            .list_messages(conversation.id)
            .await
            .unwrap();
        let tool_result_msg = messages
            .iter()
            .rev()
            .find(|m| m.role == discovery_assistant::MessageRole::Tool && m.tool_result.is_some())
            .unwrap();
        let status_code = tool_result_msg
            .tool_result
            .as_ref()
            .unwrap()
            .get("status_code")
            .and_then(|v| v.as_u64())
            .unwrap();
        assert_eq!(
            status_code, 409,
            "must reject with 409, never fall through to a real upsert"
        );
    }

    #[tokio::test]
    async fn assistant_list_and_get_discovery_config_redact_credentials() {
        let (_app, state, token) = test_app().await;
        let admin = state
            .auth
            .authenticate_session(&token)
            .await
            .unwrap()
            .unwrap();
        let conversation = state
            .assistant
            .create_conversation(admin.id, "test")
            .await
            .unwrap();
        let headers = authed_headers(&token);
        let mut config = an_assistant_test_discovery_config("with-creds");
        config.subnets = vec![discovery_config_store::SubnetSpec {
            ip: "10.9.0.0".to_string(),
            mask: "255.255.255.0".to_string(),
            port: 161,
            credentials: vec![SnmpAuth::Community {
                version: SnmpVersion::V2c,
                community: "s3cr3t-community".to_string(),
            }],
            oids: Default::default(),
            labels: Default::default(),
            snmp_timeout_ms: None,
            snmp_retries: None,
            create_dead_devices: false,
        }];
        state.discovery_configs.upsert(&config).await.unwrap();

        let list_fake = discovery_llm::FakeLlmProvider::with_responses(vec![
            discovery_llm::LlmTurn {
                text: None,
                tool_call: Some(discovery_llm::ToolCall {
                    name: "list_discovery_configs".to_string(),
                    arguments: serde_json::json!({}),
                    id: None,
                }),
            },
            discovery_llm::LlmTurn {
                text: Some("Один конфиг".to_string()),
                tool_call: None,
            },
        ]);
        assistant::send_message_with_provider(
            &state,
            &headers,
            conversation.id,
            "покажи конфиги дискаверинга".to_string(),
            &list_fake,
        )
        .await
        .unwrap();
        let list_messages = state
            .assistant
            .list_messages(conversation.id)
            .await
            .unwrap();
        let list_result = list_messages
            .iter()
            .rev()
            .find_map(|m| m.tool_result.as_ref())
            .unwrap();
        let list_json = list_result.to_string();
        assert!(
            !list_json.contains("s3cr3t-community"),
            "list_discovery_configs must never leak SNMP credentials to the model: {list_json}"
        );

        let conversation2 = state
            .assistant
            .create_conversation(admin.id, "test2")
            .await
            .unwrap();
        let get_fake = discovery_llm::FakeLlmProvider::with_responses(vec![
            discovery_llm::LlmTurn {
                text: None,
                tool_call: Some(discovery_llm::ToolCall {
                    name: "get_discovery_config".to_string(),
                    arguments: serde_json::json!({"name": "with-creds"}),
                    id: None,
                }),
            },
            discovery_llm::LlmTurn {
                text: Some("Конфиг найден".to_string()),
                tool_call: None,
            },
        ]);
        assistant::send_message_with_provider(
            &state,
            &headers,
            conversation2.id,
            "покажи конфиг with-creds".to_string(),
            &get_fake,
        )
        .await
        .unwrap();
        let get_messages = state
            .assistant
            .list_messages(conversation2.id)
            .await
            .unwrap();
        let get_result = get_messages
            .iter()
            .rev()
            .find_map(|m| m.tool_result.as_ref())
            .unwrap();
        let get_json = get_result.to_string();
        assert!(
            !get_json.contains("s3cr3t-community"),
            "get_discovery_config must never leak SNMP credentials to the model: {get_json}"
        );

        // The real, unredacted value must still be intact in storage — this is a
        // presentation-layer redaction for the model, not data loss.
        let stored = state.discovery_configs.load_all().await.unwrap();
        let stored = stored.iter().find(|c| c.name == "with-creds").unwrap();
        assert_eq!(
            stored.subnets[0].credentials,
            vec![SnmpAuth::Community {
                version: SnmpVersion::V2c,
                community: "s3cr3t-community".to_string()
            }]
        );
    }

    // ---------------------------------------------------------- bypass (auto_approve_writes)

    #[tokio::test]
    async fn assistant_auto_approve_writes_executes_immediately_without_confirmation() {
        let (app, state, token) = test_app().await;
        let admin = state
            .auth
            .authenticate_session(&token)
            .await
            .unwrap()
            .unwrap();
        let conversation = state
            .assistant
            .create_conversation(admin.id, "test")
            .await
            .unwrap();
        state
            .assistant
            .set_auto_approve_writes(conversation.id, true)
            .await
            .unwrap();
        let headers = authed_headers(&token);

        let (_, dev_body) = req(
            &app,
            &token,
            "POST",
            "/api/devices",
            Some(serde_json::json!({"ip": "10.0.0.5"})),
        )
        .await;
        let device_id = dev_body["id"].as_str().unwrap().to_string();
        req(
            &app,
            &token,
            "PUT",
            &format!("/api/devices/{device_id}/enabled"),
            Some(serde_json::json!({"enabled": false})),
        )
        .await;

        // `set_device_enabled(enabled: true)` — re-enabling, not disabling — is the
        // reversible half of this tool: `is_dangerous_tool_call` only routes the
        // *disabling* call to confirmation regardless of this bypass (see the dedicated
        // `assistant_auto_approve_writes_still_confirms_dangerous_tool_calls` test below),
        // precisely because silencing monitoring is the kind of write a prompt-injected
        // instruction hidden in tool-returned data would aim for.
        let fake = discovery_llm::FakeLlmProvider::with_responses(vec![
            discovery_llm::LlmTurn {
                text: None,
                tool_call: Some(discovery_llm::ToolCall {
                    name: "set_device_enabled".to_string(),
                    arguments: serde_json::json!({"id": device_id, "enabled": true}),
                    id: None,
                }),
            },
            discovery_llm::LlmTurn {
                text: Some("Готово, устройство снова включено".to_string()),
                tool_call: None,
            },
        ]);
        let response = assistant::send_message_with_provider(
            &state,
            &headers,
            conversation.id,
            "включи устройство обратно".to_string(),
            &fake,
        )
        .await
        .unwrap();
        assert_eq!(response.status, "final", "bypass must execute the write and keep going in the same turn, never stop at awaiting_confirmation");
        assert_eq!(fake.call_count().await, 2, "the loop must call the model again after the auto-approved write executed, same as a read tool");

        let (_, body) = req(
            &app,
            &token,
            "GET",
            &format!("/api/devices/{device_id}"),
            None,
        )
        .await;
        assert_eq!(
            body["enabled"], true,
            "bypass must actually execute the write, not just skip the confirmation UI"
        );

        let (_, body) = req(&app, &token, "GET", "/api/journal?domain=devices", None).await;
        let entry = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| {
                i["object"] == "10.0.0.5" && i["action"].as_str().unwrap().contains("активность")
            })
            .expect("set_device_enabled must have written a Журнал entry");
        assert!(
            entry["action"]
                .as_str()
                .unwrap()
                .contains("авто-подтверждено"),
            "Журнал must distinguish a bypassed write from a manually-confirmed one: {entry}"
        );
    }

    /// SEC-21 (2026-09-22) — a curated set of tool calls always stops for confirmation
    /// even with `auto_approve_writes` on: destructive/irreversible actions (`delete_*`)
    /// and actions that suppress monitoring/security signal (closing an alert, disabling
    /// a device). See [`assistant::is_dangerous_tool_call`]'s docs for the rationale.
    #[tokio::test]
    async fn assistant_auto_approve_writes_still_confirms_dangerous_tool_calls() {
        let (app, state, token) = test_app().await;
        let admin = state
            .auth
            .authenticate_session(&token)
            .await
            .unwrap()
            .unwrap();
        let conversation = state
            .assistant
            .create_conversation(admin.id, "test")
            .await
            .unwrap();
        state
            .assistant
            .set_auto_approve_writes(conversation.id, true)
            .await
            .unwrap();
        let headers = authed_headers(&token);

        let alert = an_alert(
            "high_cpu",
            "10.0.0.6",
            Uuid::new_v4(),
            AlertLevel::Critical,
            AlertState::Active,
        );
        state.alert_store.upsert(&alert).await.unwrap();

        let fake = discovery_llm::FakeLlmProvider::with_responses(vec![discovery_llm::LlmTurn {
            text: None,
            tool_call: Some(discovery_llm::ToolCall {
                name: "close_alert".to_string(),
                arguments: serde_json::json!({"id": alert.id.to_string()}),
                id: None,
            }),
        }]);
        let response = assistant::send_message_with_provider(
            &state,
            &headers,
            conversation.id,
            "закрой тревогу".to_string(),
            &fake,
        )
        .await
        .unwrap();
        assert_eq!(
            response.status, "awaiting_confirmation",
            "close_alert must stop for confirmation even with auto_approve_writes on"
        );
        assert_eq!(
            fake.call_count().await,
            1,
            "the model must not be called again until the user explicitly confirms or rejects"
        );

        let still_active = state.alert_store.get(alert.id).await.unwrap().unwrap();
        assert_eq!(
            still_active.state,
            AlertState::Active,
            "the dangerous write must not have executed"
        );

        let (_, body) = req(&app, &token, "GET", "/api/journal?domain=alerts", None).await;
        let expected_object = format!("{} — {}", alert.device_ip, alert.name);
        assert!(
            body["items"]
                .as_array()
                .unwrap()
                .iter()
                .all(|i| i["object"] != expected_object),
            "nothing should have been journaled — the write never ran"
        );
    }

    #[tokio::test]
    async fn update_conversation_settings_is_owner_scoped() {
        let (app, state, _admin_token) = test_app().await;
        state
            .auth
            .create_user("alice", "pw", false, false, None)
            .await
            .unwrap();
        state
            .auth
            .create_user("bob", "pw", false, false, None)
            .await
            .unwrap();
        let (_, alice_login) = login_req(&app, "alice", "pw").await;
        let alice_token = alice_login["token"].as_str().unwrap().to_string();
        let (_, bob_login) = login_req(&app, "bob", "pw").await;
        let bob_token = bob_login["token"].as_str().unwrap().to_string();

        let (status, body) = req(
            &app,
            &alice_token,
            "POST",
            "/api/assistant/conversations",
            Some(serde_json::json!({"title": "alice chat"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let conversation_id = body["id"].as_str().unwrap();
        assert_eq!(body["auto_approve_writes"], false);

        let (status, _) = req(
            &app,
            &bob_token,
            "PUT",
            &format!("/api/assistant/conversations/{conversation_id}"),
            Some(serde_json::json!({"auto_approve_writes": true})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "bob must not be able to toggle alice's conversation"
        );

        let (status, body) = req(
            &app,
            &alice_token,
            "PUT",
            &format!("/api/assistant/conversations/{conversation_id}"),
            Some(serde_json::json!({"auto_approve_writes": true})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["auto_approve_writes"], true);
    }

    // ---------------------------------------------------------- build_provider dispatch

    #[test]
    fn build_provider_rejects_an_unknown_provider_name() {
        let config = discovery_core::AiAssistantProviderConfig {
            enabled: true,
            provider: "not-a-real-provider".to_string(),
            ..Default::default()
        };
        let err = assistant::build_provider(&config).err().expect("must fail");
        assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            err.1.contains("not-a-real-provider"),
            "error should name the unrecognized provider: {}",
            err.1
        );
    }

    #[test]
    fn build_provider_rejects_disabled_regardless_of_provider() {
        let config = discovery_core::AiAssistantProviderConfig {
            enabled: false,
            provider: "gigachat".to_string(),
            ..Default::default()
        };
        let err = assistant::build_provider(&config).err().expect("must fail");
        assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn build_provider_rejects_openrouter_without_an_api_key() {
        let config = discovery_core::AiAssistantProviderConfig {
            enabled: true,
            provider: "openrouter".to_string(),
            openrouter_model: "openai/gpt-4o-mini".to_string(),
            ..Default::default()
        };
        let err = assistant::build_provider(&config).err().expect("must fail");
        assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn build_provider_rejects_openrouter_without_a_model() {
        let config = discovery_core::AiAssistantProviderConfig {
            enabled: true,
            provider: "openrouter".to_string(),
            openrouter_api_key: Some("sk-or-test".to_string()),
            ..Default::default()
        };
        let err = assistant::build_provider(&config).err().expect("must fail");
        assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn build_provider_succeeds_for_a_fully_configured_openrouter() {
        let config = discovery_core::AiAssistantProviderConfig {
            enabled: true,
            provider: "openrouter".to_string(),
            openrouter_api_key: Some("sk-or-test".to_string()),
            openrouter_model: "openai/gpt-4o-mini".to_string(),
            ..Default::default()
        };
        assert!(assistant::build_provider(&config).is_ok());
    }

    #[test]
    fn build_provider_rejects_self_hosted_without_a_base_url() {
        let config = discovery_core::AiAssistantProviderConfig {
            enabled: true,
            provider: "self_hosted".to_string(),
            self_hosted_model: "llama3".to_string(),
            ..Default::default()
        };
        let err = assistant::build_provider(&config).err().expect("must fail");
        assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn build_provider_rejects_self_hosted_without_a_model() {
        let config = discovery_core::AiAssistantProviderConfig {
            enabled: true,
            provider: "self_hosted".to_string(),
            self_hosted_base_url: "http://localhost:11434/v1/chat/completions".to_string(),
            ..Default::default()
        };
        let err = assistant::build_provider(&config).err().expect("must fail");
        assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Unlike OpenRouter/GigaChat — a self-hosted config with **no** api key at all must
    /// still succeed (a self-hosted server with no auth is a real, common setup, not a
    /// degraded one — see `discovery_llm::SelfHostedProvider`'s docs).
    #[test]
    fn build_provider_succeeds_for_self_hosted_with_no_api_key_configured() {
        let config = discovery_core::AiAssistantProviderConfig {
            enabled: true,
            provider: "self_hosted".to_string(),
            self_hosted_base_url: "http://localhost:11434/v1/chat/completions".to_string(),
            self_hosted_model: "llama3".to_string(),
            ..Default::default()
        };
        assert!(assistant::build_provider(&config).is_ok());
    }

    #[test]
    fn build_provider_succeeds_for_a_fully_configured_self_hosted() {
        let config = discovery_core::AiAssistantProviderConfig {
            enabled: true,
            provider: "self_hosted".to_string(),
            self_hosted_base_url: "http://vllm-host:8000/v1/chat/completions".to_string(),
            self_hosted_api_key: Some("dummy-key".to_string()),
            self_hosted_model: "llama3".to_string(),
            ..Default::default()
        };
        assert!(assistant::build_provider(&config).is_ok());
    }
    #[tokio::test]
    async fn capability_rule_permissions_cover_list_read_mutation_comments_diagnostics_and_screen()
    {
        let (app, state, admin) = test_app().await;
        let allowed = state
            .auth
            .create_role(
                "alert-visible",
                HashMap::from([
                    (Domain::Alerts, AccessLevel::Write),
                    (Domain::Devices, AccessLevel::Write),
                ]),
            )
            .await
            .unwrap();
        let hidden = state
            .auth
            .create_role(
                "alert-hidden",
                HashMap::from([
                    (Domain::Alerts, AccessLevel::Write),
                    (Domain::Devices, AccessLevel::Write),
                ]),
            )
            .await
            .unwrap();
        let u = state
            .auth
            .create_user("hidden", "test-password", false, false, Some(hidden.id))
            .await
            .unwrap();
        let token = state
            .auth
            .create_session(u.id, chrono::Duration::hours(1))
            .await
            .unwrap();
        let mut a = an_alert(
            "protected",
            "127.0.0.1",
            Uuid::new_v4(),
            AlertLevel::Warning,
            AlertState::Active,
        );
        a.details.policy.viewer_roles = vec![allowed.id];
        a.details.policy.operator_roles = vec![allowed.id];
        a.details.policy.screen_notification = true;
        state.alert_store.upsert(&a).await.unwrap();
        state.alerts.restore_active(a.clone());
        let mut protected_profile: ProfileFile =
            serde_json::from_value(a_profile("protected-profile", 0, "false")).unwrap();
        protected_profile.alerts.push(serde_json::from_value(serde_json::json!({"name":"protected","expression":"true","level":"warning","message":"test","enabled":true,"policy":a.details.policy})).unwrap());
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        let user = authenticate_request(&state, &headers).await.unwrap();
        assert!(
            alert_rules::require_profile_rule_access(&state, &protected_profile, &user).is_err()
        );
        for (method, path) in [
            ("GET", format!("/api/alerts/{}", a.id)),
            ("POST", format!("/api/alerts/{}/close", a.id)),
            ("POST", format!("/api/alerts/{}/acknowledge", a.id)),
            ("GET", format!("/api/alerts/{}/comments", a.id)),
            ("DELETE", format!("/api/alerts/{}", a.id)),
        ] {
            assert_eq!(
                req(&app, &token, method, &path, None).await.0,
                StatusCode::FORBIDDEN
            );
        }
        let (_, list) = req(&app, &token, "GET", "/api/alerts", None).await;
        assert_eq!(list["total"], 0);
        for path in ["/api/incidents", "/api/alerts/screen"] {
            assert!(req(&app, &token, "GET", path, None)
                .await
                .1
                .as_array()
                .unwrap()
                .is_empty());
        }
        assert_eq!(
            req(&app, &admin, "GET", &format!("/api/alerts/{}", a.id), None)
                .await
                .0,
            StatusCode::OK
        );
        state
            .auth
            .set_user_role(u.id, Some(allowed.id))
            .await
            .unwrap();
        assert_eq!(
            req(&app, &token, "GET", &format!("/api/alerts/{}", a.id), None)
                .await
                .0,
            StatusCode::OK
        );
    }
    #[tokio::test]
    async fn capability_shared_authoring_rejects_invalid_modes_and_referenced_deletion() {
        let (app, state, token) = test_app().await;
        let base = serde_json::json!({"name":"shared","level":"warning","expression":"true","message":"test","enabled":true,"policy":{"mode":"event"}});
        assert_eq!(
            req(&app, &token, "POST", "/api/alert-rules/shared", Some(base))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let rule = serde_json::json!({"name":"shared","level":"warning","expression":"true","message":"test","enabled":true});
        assert_eq!(
            req(&app, &token, "POST", "/api/alert-rules/shared", Some(rule))
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        assert!(state.alerts.shared_rule("shared").is_some());
        let profile = serde_json::json!({"profile":{"name":"linked","priority":0},"match":{"expression":"false"},"metrics":{"poll":{}},"alerts":[{"name":"alias","level":"warning","expression":"false","message":"unused","enabled":true,"policy":{"shared_rule":"shared"}}]});
        assert_eq!(
            req(&app, &token, "POST", "/api/profiles", Some(profile))
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            req(
                &app,
                &token,
                "DELETE",
                "/api/alert-rules/shared/shared",
                None
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        let (_, rules) = req(&app, &token, "GET", "/api/alert-rules/shared", None).await;
        assert_eq!(rules[0]["name"], "shared");
    }
    #[tokio::test]
    async fn capability_required_ack_survives_recovery_and_pulse_ack_is_terminal() {
        let (app, state, token) = test_app().await;
        let mut a = an_alert(
            "pulse",
            "127.0.0.1",
            Uuid::new_v4(),
            AlertLevel::Warning,
            AlertState::Active,
        );
        a.details.policy.mode = discovery_core::AlertMode::Change;
        a.details.policy.acknowledge_required = true;
        a.details.policy.screen_notification = true;
        state.alert_store.upsert(&a).await.unwrap();
        state.alerts.restore_active(a.clone());
        let path = format!("/api/alerts/{}/acknowledge", a.id);
        let (status, body) = req(&app, &token, "POST", &path, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["state"], "Cleared");
        assert!(body["acknowledged_at"].is_string());
        assert!(state.alerts.active_alerts().is_empty());
        assert!(req(&app, &token, "GET", "/api/alerts/screen", None)
            .await
            .1
            .as_array()
            .unwrap()
            .is_empty());
        let mut recovered = an_alert(
            "recovered",
            "127.0.0.1",
            Uuid::new_v4(),
            AlertLevel::Warning,
            AlertState::Cleared,
        );
        recovered.details.policy.acknowledge_required = true;
        recovered.details.policy.screen_notification = true;
        recovered.details.policy.notification_lifetime_seconds = Some(1);
        recovered.first_seen -= chrono::Duration::days(1);
        state.alert_store.upsert(&recovered).await.unwrap();
        assert_eq!(
            req(&app, &token, "GET", "/api/alerts/screen", None)
                .await
                .1
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            req(
                &app,
                &token,
                "POST",
                &format!("/api/alerts/{}/acknowledge", recovered.id),
                None
            )
            .await
            .0,
            StatusCode::OK
        );
    }
}
