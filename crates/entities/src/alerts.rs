//! `alerts` — durable incident history. Domain "Тревоги". `device_id` is a **soft** reference to
//! `devices.device_id`, not an enforced `FOREIGN KEY` — same cross-domain reasoning as
//! `device_metrics.rs`'s docs: "Тревоги" and "Устройства" can resolve to different
//! physical databases, so `DeviceStore::delete` must explicitly delete this table's
//! matching rows in application code instead of relying on `ON DELETE CASCADE`.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "alerts")]
pub struct Model {
    pub details: Option<Json>,
    pub response_required: bool,
    pub response_escalated: bool,
    pub screen_notification: bool,
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub device_id: Uuid,
    pub device_ip: String,
    pub name: String,
    /// `Some(key)` for a row-scoped alert (`discovery_dsl::AlertRule::row_metric`) —
    /// see `discovery_core::Alert::row_key`'s docs. `None` for an ordinary device-level
    /// alert.
    pub row_key: Option<String>,
    pub level: String,
    pub message: String,
    /// "active" | "cleared".
    pub state: String,
    #[sea_orm(column_type = "Json", nullable)]
    pub facts: Option<Json>,
    pub first_seen: DateTimeUtc,
    pub last_seen: DateTimeUtc,
    pub cleared_at: Option<DateTimeUtc>,
    /// Username of whoever manually closed this alert — `None` if still active or cleared
    /// automatically. See `discovery_core::Alert::closed_by`'s docs.
    pub closed_by: Option<String>,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<DateTimeUtc>,
    pub snoozed_until: Option<DateTimeUtc>,
    pub snoozed_by: Option<String>,
    /// "row_missing" (currently the only value) or `NULL` — see
    /// `discovery_core::AutoClearReason`'s docs.
    pub auto_clear_reason: Option<String>,
    pub flapping: bool,
    pub suppression_reason: Option<String>,
    /// Soft reference to another row's `id` in this same table — `NULL` = this alert is
    /// its own root cause (or group-alert suppression hasn't run/found nothing yet). See
    /// `discovery_core::Alert::suppressed_by_alert_id`'s docs.
    pub suppressed_by_alert_id: Option<Uuid>,
    /// Soft reference to another row's `id` in this same table — `NULL` unless this alert
    /// re-activated shortly after being manually closed while its condition was still
    /// true. See `discovery_core::Alert::reopened_from_alert_id`'s docs.
    pub reopened_from_alert_id: Option<Uuid>,
    pub repeat_count: i32,
    pub escalation_level: i32,
    pub repeated_at: Option<DateTimeUtc>,
    pub escalation_reason: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
