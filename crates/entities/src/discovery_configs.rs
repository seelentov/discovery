//! `discovery_configs` — named, independently schedulable discovery configurations
//! (`migrations/0007_discovery_configs.sql`). Domain "Подсети / конфиги дискаверинга".
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "discovery_configs")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub name: String,
    pub enabled: bool,
    /// Serialized `discovery_core::Schedule`.
    #[sea_orm(column_type = "Json")]
    pub schedule: Json,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
