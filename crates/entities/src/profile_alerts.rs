//! `profile_alerts` — one row per alert rule a profile declares
//! (`migrations/0020_profile_alerts.sql`). Same routing domain as `profiles`
//! ("Профили") — real, DB-enforced FK, see `profile_metrics.rs`'s docs for why that's
//! safe here but not for the device-related tables.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "profile_alerts")]
pub struct Model {
    pub policy: Option<Json>,
    #[sea_orm(primary_key, auto_increment = false)]
    pub profile_name: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub name: String,
    pub level: String,
    /// See `discovery_dsl::AlertRule::row_metric`/`row_key_expression`'s docs — both
    /// `None` (the default) means an ordinary device-level rule, unchanged from before
    /// this pair of fields existed.
    pub row_metric: Option<String>,
    pub row_key_expression: Option<String>,
    pub expression: String,
    pub deactivation_expression: Option<String>,
    pub facts_expression: Option<String>,
    pub message: String,
    pub clear_after_seconds: Option<i64>,
    pub activate_after_seconds: Option<i64>,
    pub flap_window_seconds: Option<i64>,
    pub flap_threshold: Option<i64>,
    pub enabled: bool,
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
