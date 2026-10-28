//! `role_permissions` — flat `(role, domain) -> level` classic read/write ACL (2026-08-27),
//! the direct successor of the old `user_permissions` table (see `roles`/
//! `discovery_migration`'s `up()` docs). `domain` stores `discovery_core::Domain::as_str()`;
//! `level` stores `discovery_auth::AccessLevel::as_str()` — both plain strings, validated
//! at the Rust layer, not a DB-level `CHECK`, same discipline `user_permissions` used.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "role_permissions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub role_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub domain: String,
    pub level: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::roles::Entity",
        from = "Column::RoleId",
        to = "super::roles::Column::Id",
        on_delete = "Cascade"
    )]
    Role,
}

impl ActiveModelBehavior for ActiveModel {}
