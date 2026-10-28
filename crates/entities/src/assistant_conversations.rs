//! `assistant_conversations` — one row per AI-assistant chat conversation
//! (`discovery_assistant::Conversation`/`AssistantStore`), scoped to its owning user.
//! Not one of the 12 routed `discovery_core::Domain`s — self-service, gated only by
//! `owner_user_id == current user` (same tier as `notification_channels`), see
//! `discovery_assistant::AssistantStore`'s docs. Added 2026-09-18.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "assistant_conversations")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// No FK — `discovery_auth::AuthStore`'s `users` table lives outside the
    /// independently-routable `Domain` set, same "no FK across domains" convention
    /// `maintenance_windows.device_ids` (a JSON list, not a real FK either) already
    /// follows.
    pub owner_user_id: Uuid,
    pub title: String,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
    /// Per-conversation opt-in bypass of confirm-before-write (2026-09-18, direct user
    /// request — "bypass permission... как в Claude Code"): when `true`,
    /// `discovery_web::assistant::run_assistant_turn` executes a write-level tool call
    /// immediately instead of stopping at `ToolCallStatus::PendingConfirmation`. Does
    /// **not** change what the assistant is allowed to do — `require_domain_permission`
    /// still runs fresh on every tool-call sub-request either way; this only skips the
    /// human's manual confirm click for that one conversation. Default `false`.
    pub auto_approve_writes: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
