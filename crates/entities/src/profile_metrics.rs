//! `profile_metrics` — one row per metric a profile's `[metrics.poll]` declares
//! (`migrations/0006_profile_metrics.sql` plus 0014/0017/0019's additions folded into
//! final shape). Same routing domain as `profiles` ("Профили") — `profile_name` stays a
//! real, DB-enforced `FOREIGN KEY ... ON DELETE CASCADE` (unlike the device-related
//! cross-domain references) because both tables always live in the same physical
//! database by construction (one domain, one connection).
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "profile_metrics")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub profile_name: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub name: String,
    pub oid: String,
    /// See `migrations`'s `ProfileMetrics::Columns` docs — `NULL` = scalar, `{}` = table
    /// "collect everything", `{"name": "subid", ...}` = table with curated columns.
    #[sea_orm(column_type = "Json", nullable)]
    pub columns: Option<Json>,
    /// See `migrations`'s `ProfileMetrics::Command` docs — `NULL` = an SNMP-sourced row
    /// (`oid` holds the real value), `Some(cmd)` = a `discovery_dsl::MetricSpec::SshCommand`
    /// row (`oid` is unused, always `""`).
    pub command: Option<String>,
    pub history_retention_secs: Option<i64>,
    /// Serialized `discovery_core::Schedule` — `None` means "use the process-wide default
    /// periodic interval" (see `migrations/0014_profile_metric_schedule.sql`'s docs).
    #[sea_orm(column_type = "Json", nullable)]
    pub schedule: Option<Json>,
    pub enabled: bool,
    pub history_keep_last_success: bool,
    pub history_keep_last_attempt: bool,
    /// Serialized `discovery_dsl::DeriveKind` (`"rate"`/`"delta"`) — `NULL` = no derived
    /// rate/delta metric for this one (`migrations`'s `ProfileMetrics::Derive` docs).
    #[sea_orm(column_type = "Json", nullable)]
    pub derive: Option<Json>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::profiles::Entity",
        from = "Column::ProfileName",
        to = "super::profiles::Column::Name",
        on_delete = "Cascade"
    )]
    Profile,
}

impl ActiveModelBehavior for ActiveModel {}
