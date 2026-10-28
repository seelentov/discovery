//! `profile_traps` — one row per trap binding a profile's `traps.bindings` declares
//! (`crates/migration`'s single schema migration). Same routing domain as `profiles`
//! ("Профили") — real, DB-enforced FK, see `profile_metrics.rs`'s docs for why that's
//! safe here but not for the device-related tables.
//!
//! `variants` is the whole `Vec<discovery_dsl::TrapEventSpec>` as JSON, not further
//! normalized into its own child table — same precedent as `profile_metrics.columns`/
//! `schedule`: nested structured data too small and always read/written as a unit gets a
//! JSON column, only genuine one-row-per-X collections (metrics, alerts, and this table
//! itself relative to `profiles`) get real child tables.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "profile_traps")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub profile_name: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub name: String,
    #[sea_orm(column_type = "Json")]
    pub variants: Json,
    pub ttl_secs: Option<i64>,
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
