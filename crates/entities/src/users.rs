//! `users` — local AggreGate-style accounts for `discovery`'s own auth (2026-08-21). See
//! `discovery_auth::AuthStore`'s docs for the domain-level contract; this is purely the
//! sea-orm mapping. `is_admin` bypasses per-domain `role_permissions` entirely (user
//! management itself needs its own elevated right, distinct from the 8 business domains —
//! see `discovery/CLAUDE.md`'s auth survey on why AggreGate keeps role/permission
//! management separate from object-level ACL too).
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
    pub is_admin: bool,
    /// See `discovery_auth::User::must_change_password`'s docs.
    pub must_change_password: bool,
    /// `None` = no role assigned, i.e. no domain access at all (same "absence = no
    /// access" convention `role_permissions` itself uses one level down) — see
    /// `discovery_auth::User::role_id`'s docs.
    pub role_id: Option<Uuid>,
    pub created_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::roles::Entity",
        from = "Column::RoleId",
        to = "super::roles::Column::Id",
        on_delete = "SetNull"
    )]
    Role,
}

impl ActiveModelBehavior for ActiveModel {}
