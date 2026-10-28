//! `alert_comment_attachments` — one row per file attached to an `alert_comments` row
//! (2026-08-29, direct user request: "вложения к комментариям тревог: файл/изображение/
//! видео"). Same-domain FK to `alert_comments` (both "Тревоги"), so a real
//! `ON DELETE CASCADE` applies here, same reasoning `alert_comments`'s own FK to `alerts`
//! already uses. `data` holds the raw bytes — chosen over a filesystem path (2026-08-29,
//! direct user request: "Blob в БД") so an attachment lives in whatever database the
//! `alerts` domain is already routed to, with no extra filesystem/storage dependency to
//! configure or back up separately.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "alert_comment_attachments")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub comment_id: Uuid,
    pub filename: String,
    pub content_type: String,
    pub size: i64,
    pub data: Vec<u8>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::alert_comments::Entity",
        from = "Column::CommentId",
        to = "super::alert_comments::Column::Id",
        on_delete = "Cascade"
    )]
    Comment,
}

impl ActiveModelBehavior for ActiveModel {}
