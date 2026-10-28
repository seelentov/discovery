//! `logs` — durable copy of every tracing event (`migrations/0011_logs.sql`). Domain
//! "Логи".
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "logs")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub ts: DateTimeUtc,
    pub level: String,
    pub target: String,
    pub message: String,
    #[sea_orm(column_type = "Json")]
    pub fields: Json,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
