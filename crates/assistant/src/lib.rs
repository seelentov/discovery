//! `discovery-assistant` — AI-assistant conversation/message history. See
//! [`AssistantStore`]'s docs.

mod sea_orm_store;
mod store;

pub use sea_orm_store::SeaOrmAssistantStore;
pub use store::{AssistantStore, Conversation, Message, MessageRole, ToolCallStatus};
