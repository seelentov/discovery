use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One AI-assistant chat conversation, scoped to its owning user — see
/// [`AssistantStore`]'s docs. `Serialize`/`Deserialize` (added for `discovery-web`'s REST
/// handlers, which return this as-is — same "domain type doubles as its own REST DTO"
/// convention `discovery_core::{NotificationChannel, MaintenanceWindow}` already follow;
/// only the sea-orm entity `Model` this is mapped from/to deliberately lacks these).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Conversation {
    pub id: Uuid,
    pub owner_user_id: Uuid,
    pub title: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// See `discovery_entities::assistant_conversations::Model::auto_approve_writes`'s
    /// docs — per-conversation opt-in bypass of confirm-before-write. Default `false`.
    pub auto_approve_writes: bool,
}

/// Who authored a [`Message`] — same three-way split as
/// `discovery_llm::LlmRole`, just persisted as a string (`as_str`/`from_str`, same
/// convention as `discovery_core::NotificationChannelKind`) rather than kept as that
/// crate's in-memory type, so this crate doesn't need to depend on `discovery-llm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageRole {
    User,
    Assistant,
    Tool,
}

impl MessageRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageRole::User => "user",
            MessageRole::Assistant => "assistant",
            MessageRole::Tool => "tool",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "user" => MessageRole::User,
            "assistant" => MessageRole::Assistant,
            "tool" => MessageRole::Tool,
            _ => return None,
        })
    }
}

/// Lifecycle of a tool call an assistant message proposed — `None` for a plain text
/// message with no tool call at all. `PendingConfirmation` is the confirm-before-write
/// gate: a write-level tool call stops here until a human calls `.../confirm` or
/// `.../reject` (see the AI Assistant architecture doc for the full orchestration loop).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCallStatus {
    None,
    PendingConfirmation,
    Confirmed,
    Rejected,
    Executed,
    Failed,
}

impl ToolCallStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ToolCallStatus::None => "none",
            ToolCallStatus::PendingConfirmation => "pending_confirmation",
            ToolCallStatus::Confirmed => "confirmed",
            ToolCallStatus::Rejected => "rejected",
            ToolCallStatus::Executed => "executed",
            ToolCallStatus::Failed => "failed",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "none" => ToolCallStatus::None,
            "pending_confirmation" => ToolCallStatus::PendingConfirmation,
            "confirmed" => ToolCallStatus::Confirmed,
            "rejected" => ToolCallStatus::Rejected,
            "executed" => ToolCallStatus::Executed,
            "failed" => ToolCallStatus::Failed,
            _ => return None,
        })
    }
}

/// One turn in a conversation — see [`AssistantStore`]'s docs. `sequence` (not
/// `created_at`) is the stable ordering key within a `conversation_id`: several rows can
/// be created within the same millisecond during an automatic read-tool-call loop.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub id: Uuid,
    pub conversation_id: Uuid,
    pub sequence: i32,
    pub role: MessageRole,
    pub content: Option<String>,
    /// `{name, arguments}` — set on an assistant message that requested a tool call.
    pub tool_call: Option<serde_json::Value>,
    pub tool_call_status: ToolCallStatus,
    /// `{status_code, body}` — the internal REST sub-request's outcome once a tool call
    /// actually executed (or a synthetic `{"declined_by_user": true}` on reject).
    pub tool_result: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

/// AI-assistant conversation/message history — self-service, scoped by `owner_user_id`
/// (same tier as `discovery_config_store::NotificationChannelStore`, no
/// `discovery_core::Domain` gate at all: any authenticated user can have their own
/// conversations, what the *assistant* is allowed to do within one is governed entirely
/// by the calling user's own domain permissions at tool-execution time, not by a
/// permission on this store). One implementation — [`crate::SeaOrmAssistantStore`].
#[async_trait]
pub trait AssistantStore: Send + Sync {
    async fn create_conversation(
        &self,
        owner_user_id: Uuid,
        title: &str,
    ) -> anyhow::Result<Conversation>;

    async fn list_conversations(&self, owner_user_id: Uuid) -> anyhow::Result<Vec<Conversation>>;

    async fn get_conversation(&self, id: Uuid) -> anyhow::Result<Option<Conversation>>;

    /// Ordered by `sequence` ascending — the full transcript, oldest first.
    async fn list_messages(&self, conversation_id: Uuid) -> anyhow::Result<Vec<Message>>;

    /// `msg.sequence` is ignored on input — the store assigns the next sequence number
    /// for `msg.conversation_id` itself (max existing + 1, starting at 0), so callers
    /// never race each other over picking one.
    async fn append_message(&self, msg: &Message) -> anyhow::Result<()>;

    async fn update_message_tool_status(
        &self,
        id: Uuid,
        status: ToolCallStatus,
        tool_result: Option<serde_json::Value>,
    ) -> anyhow::Result<()>;

    /// Atomically claims a pending confirmation. Exactly one concurrent confirmer can
    /// move the row to `Confirmed`; all later confirm/reject attempts observe `false`.
    async fn claim_pending_tool_call(&self, id: Uuid) -> anyhow::Result<bool>;

    /// Toggles [`Conversation::auto_approve_writes`] — self-service, the REST layer gates
    /// this the same way as every other conversation operation (`owner_user_id ==
    /// current user`, see `discovery_web::assistant::owned_conversation`).
    async fn set_auto_approve_writes(&self, id: Uuid, enabled: bool) -> anyhow::Result<()>;
}
