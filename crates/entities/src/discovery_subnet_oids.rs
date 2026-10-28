//! `discovery_subnet_oids` — named OIDs fetched once during a subnet's identity probe
//! (`migrations/0009_discovery_subnet_oids.sql`). Same routing domain as
//! `discovery_subnets`/`discovery_configs` — real, DB-enforced FK.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "discovery_subnet_oids")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub subnet_id: i64,
    #[sea_orm(primary_key, auto_increment = false)]
    pub name: String,
    pub oid: String,
    /// See `discovery-config-store::DiscoveryOidSpec`'s docs — `NULL` = scalar, `{}` =
    /// table "collect everything", `{"name": "subid", ...}` = table with curated
    /// columns. Same three-state encoding as `profile_metrics.columns`.
    #[sea_orm(column_type = "Json", nullable)]
    pub columns: Option<Json>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::discovery_subnets::Entity",
        from = "Column::SubnetId",
        to = "super::discovery_subnets::Column::SubnetId",
        on_delete = "Cascade"
    )]
    Subnet,
}

impl ActiveModelBehavior for ActiveModel {}
