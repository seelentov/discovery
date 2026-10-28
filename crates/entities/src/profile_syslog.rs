//! `profile_syslog` — one row per syslog binding a profile's `syslog.bindings` declares
//! (`crates/migration`'s single schema migration). Direct sibling of `profile_traps.rs`,
//! same routing domain as `profiles` ("Профили") — real, DB-enforced FK.
//!
//! `variants` is the whole `Vec<discovery_dsl::SyslogEventSpec>` as JSON, not further
//! normalized into its own child table — same precedent as `profile_traps.variants`.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "profile_syslog")]
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
