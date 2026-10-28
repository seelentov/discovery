//! `roles` — named, reusable per-domain permission bundles (2026-08-27, design-artifact
//! parity pass). See `discovery_migration`'s `up()` docs for why this replaced the old
//! flat `user_permissions` table entirely rather than sitting alongside it.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "roles")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub name: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
