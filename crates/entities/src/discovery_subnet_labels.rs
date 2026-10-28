//! `discovery_subnet_labels` — constant name -> value labels written once during a
//! subnet's identity probe, no SNMP round trip (`migrations/0010_discovery_subnet_labels.sql`).
//! Same routing domain as `discovery_subnets`/`discovery_configs` — real, DB-enforced FK.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "discovery_subnet_labels")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub subnet_id: i64,
    #[sea_orm(primary_key, auto_increment = false)]
    pub name: String,
    pub value: String,
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
