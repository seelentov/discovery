//! `notification_rules` — the notification matrix: one row per "who gets notified for
//! which alert" rule (`discovery_config_store::NotificationRule`/`NotificationRuleStore`).
//! Domain `discovery_core::Domain::Notifications`, added 2026-09-10.
//!
//! Same "selector dimensions as whole-column JSON, not child tables" precedent as
//! `maintenance_windows.subnets`/`profiles`/`device_ids` (see that entity's docs) —
//! `subnets`/`profiles`/`device_ids`/`days_of_week`/`recipients` are always read/written as
//! a single unit (matching happens in application code against the small in-memory rule
//! list, never "find every rule targeting subnet X" as a query), so a child table would
//! only add join/cascade ceremony with no querying benefit.
//!
//! No FK to `devices`/`users` for the ids inside `device_ids`/`recipients` — same
//! cross-domain reasoning as `maintenance_windows.device_ids`: this table, `aggregate.devices`'s
//! analog, and `users` can all independently route to different physical databases.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "notification_rules")]
pub struct Model {
    pub selection: Option<Json>,
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    /// `discovery_core::AlertLevel::as_str()` — notify when the alert's level is this or
    /// higher (`AlertLevel`'s derived `Ord`: Info < Warning < Critical).
    pub min_level: String,
    /// `Vec<discovery_config_store::SubnetTarget>` as JSON — empty means "don't filter by
    /// subnet". **Unlike `maintenance_windows.subnets`, zero populated dimensions across
    /// `subnets`/`profiles`/`device_ids` here means "matches every device", not "matches
    /// none"** — see `NotificationRule::matches_device`'s docs for why the two types
    /// deliberately made opposite calls on this.
    #[sea_orm(column_type = "Json")]
    pub subnets: Json,
    /// `Vec<String>` (profile names) as JSON.
    #[sea_orm(column_type = "Json")]
    pub profiles: Json,
    /// `Vec<Uuid>` (explicit device allow-list) as JSON.
    #[sea_orm(column_type = "Json")]
    pub device_ids: Json,
    /// Time-of-day window, UTC (the project has no timezone handling anywhere else either —
    /// every other `DateTime` in this codebase is already UTC). `None`/`None` (both, always
    /// together — enforced at the REST layer, not here) means "all day". Stored as
    /// `"HH:MM:SS"` text (`chrono::NaiveTime::parse_from_str`/`.format()` at the
    /// `discovery-config-store` boundary), not a native TIME column — sidesteps the
    /// cross-backend inconsistency a native temporal-without-date type would risk between
    /// Postgres/MySQL/SQLite (SQLite has no native TIME type at all), same "text/JSON over
    /// a DB-native type when in doubt" caution this project already applies elsewhere
    /// (`discovery-db-patterns` skill).
    pub active_from: Option<String>,
    pub active_to: Option<String>,
    /// `Vec<String>` (`chrono::Weekday::to_string()`-shaped short names, e.g. "Mon") as
    /// JSON — empty means "every day of the week", same "empty = don't filter" convention
    /// as `subnets`/`profiles`.
    #[sea_orm(column_type = "Json")]
    pub days_of_week: Json,
    pub notify_on_activate: bool,
    pub notify_on_clear: bool,
    /// `Vec<discovery_config_store::RecipientRef>` as JSON — a mix of individual `users.id`
    /// entries and/or `discovery_auth::Role.id` proxy-groups (2026-09-18). Every `enabled`
    /// `notification_channels` row belonging to each resolved user (an explicit `User`, or
    /// a *current* member of a `Role`) is notified when this rule matches — see
    /// `RecipientRef`'s docs for why a role reference is stored as a bare id here rather
    /// than this crate depending on `discovery-auth`. `#[serde(untagged)]` on that type
    /// means the pre-2026-09-18 bare-`Vec<Uuid>` shape already in this column for existing
    /// rows keeps deserializing unchanged (as `User` entries) — no migration/backfill was
    /// needed for this change.
    #[sea_orm(column_type = "Json")]
    pub recipients: Json,
    pub repeat_after_seconds: i64,
    pub repeat_interval_seconds: i64,
    pub max_repeats: i32,
    #[sea_orm(column_type = "Json", nullable)]
    pub escalation_levels: Option<Json>,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
