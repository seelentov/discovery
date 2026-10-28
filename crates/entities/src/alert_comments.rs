//! `alert_comments` — threaded, multi-author comments on an alert (2026-08-28, direct
//! user request — supersedes the earlier single free-form `alerts.comment` field: "Мы в
//! дизайне делали комментариями от пользователей", the design artifact's original
//! round-4 intent). Same-domain FK to `alerts` (both "Тревоги"), so a real
//! `ON DELETE CASCADE` applies here, unlike `alerts.device_id`'s cross-domain soft
//! reference to "Устройства".
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "alert_comments")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub alert_id: Uuid,
    /// Username at the time of posting — a text snapshot, not a `users.id` FK. Comments
    /// are an append-only audit trail; if the author account is later renamed or
    /// deleted, past comments should keep reading as who actually wrote them, the same
    /// "snapshot, not a live join" reasoning `Alert::facts` already uses.
    pub author: String,
    pub created_at: DateTimeUtc,
    pub text: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::alerts::Entity",
        from = "Column::AlertId",
        to = "super::alerts::Column::Id",
        on_delete = "Cascade"
    )]
    Alert,
}

impl ActiveModelBehavior for ActiveModel {}
