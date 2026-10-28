//! `assistant_messages` — one row per turn in an AI-assistant conversation
//! (`discovery_assistant::Message`/`AssistantStore`), ordered by `sequence` within its
//! `conversation_id` (not by `created_at` — several rows can be created within the same
//! millisecond during an automatic read-tool-call loop). `tool_call`/`tool_result` are
//! whole-value JSON blobs (name+arguments / status+body), not normalized columns — same
//! "read/written as one unit" reasoning `maintenance_windows.subnets`/`.profiles`/
//! `.device_ids` already use for their own JSON columns. Added 2026-09-18.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "assistant_messages")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// No FK, same reasoning as `assistant_conversations.owner_user_id` — kept an app-
    /// level reference rather than a DB constraint.
    pub conversation_id: Uuid,
    pub sequence: i32,
    /// `discovery_assistant::MessageRole::as_str()` — `"user"`/`"assistant"`/`"tool"`.
    pub role: String,
    pub content: Option<String>,
    /// `{name, arguments}` — set on an assistant message that requested a tool call.
    #[sea_orm(column_type = "Json", nullable)]
    pub tool_call: Option<Json>,
    /// `discovery_assistant::ToolCallStatus::as_str()` — `"none"` for a plain text
    /// message with no tool call at all.
    pub tool_call_status: String,
    /// `{status_code, body}` — the internal REST sub-request's outcome once a tool call
    /// actually executed.
    #[sea_orm(column_type = "Json", nullable)]
    pub tool_result: Option<Json>,
    pub created_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
