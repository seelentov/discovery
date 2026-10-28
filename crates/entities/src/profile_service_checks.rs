//! `profile_service_checks` — the L4/L7 service-check list a profile's `service_checks`
//! section declares (`crates/migration`'s single schema migration). Same routing domain as
//! `profiles` ("Профили") — real, DB-enforced FK, same reasoning as `profile_traps.rs`/
//! `profile_syslog.rs`.
//!
//! Unlike those two (one row per named binding), this is **one row per profile**: a
//! profile's `service_checks.checks` is a single flat `Vec<discovery_dsl::ServiceCheckSpec>`
//! (not a `BTreeMap<String, T>` keyed by binding name), and `schedule`/
//! `history_retention_secs` are section-level, not per-entry — there is nothing to key
//! multiple rows off, so this table mirrors `profile_service_checks.profile_name` as its
//! whole primary key, storing the entire list as one JSON column, same "small, always
//! read/written as a unit" precedent `profile_traps.variants`/`profile_syslog.variants`
//! already set for nested structured data.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "profile_service_checks")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub profile_name: String,
    /// `Vec<discovery_dsl::ServiceCheckSpec>` as JSON.
    #[sea_orm(column_type = "Json")]
    pub checks: Json,
    /// `discovery_core::Schedule` as JSON — `NULL` = use the process-wide default
    /// (`poll_intervals.service_check_secs`).
    #[sea_orm(column_type = "Json", nullable)]
    pub schedule: Option<Json>,
    pub history_retention_secs: Option<i64>,
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
