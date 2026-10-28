//! `sessions` — opaque bearer/cookie session tokens (2026-08-21). Primary key is
//! `token_hash` (SHA-256 of the raw token the client holds), never the raw token itself —
//! see `discovery_migration`'s `up()` docs for why. Domain "Настройки" is not quite right
//! and not quite wrong either — auth doesn't route like the other 8 business domains at
//! all (see `discovery_auth::AuthStore`'s docs); it always lives on the same connection as
//! `users`/`user_permissions` by construction, never independently routed.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sessions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub token_hash: String,
    pub user_id: Uuid,
    pub created_at: DateTimeUtc,
    pub expires_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::users::Entity",
        from = "Column::UserId",
        to = "super::users::Column::Id",
        on_delete = "Cascade"
    )]
    User,
}

impl ActiveModelBehavior for ActiveModel {}
