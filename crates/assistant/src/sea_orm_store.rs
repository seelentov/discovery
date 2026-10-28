use async_trait::async_trait;
use discovery_entities::{assistant_conversations, assistant_messages};
use sea_orm::{
    sea_query::Expr, ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseConnection,
    EntityTrait, Order, QueryFilter, QueryOrder,
};
use uuid::Uuid;

use crate::{AssistantStore, Conversation, Message, MessageRole, ToolCallStatus};

fn model_to_conversation(m: assistant_conversations::Model) -> Conversation {
    Conversation {
        id: m.id,
        owner_user_id: m.owner_user_id,
        title: m.title,
        created_at: m.created_at,
        updated_at: m.updated_at,
        auto_approve_writes: m.auto_approve_writes,
    }
}

fn model_to_message(m: assistant_messages::Model) -> anyhow::Result<Message> {
    let role = MessageRole::from_str(&m.role)
        .ok_or_else(|| anyhow::anyhow!("unknown assistant message role '{}'", m.role))?;
    let tool_call_status = ToolCallStatus::from_str(&m.tool_call_status).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown assistant tool_call_status '{}'",
            m.tool_call_status
        )
    })?;
    Ok(Message {
        id: m.id,
        conversation_id: m.conversation_id,
        sequence: m.sequence,
        role,
        content: m.content,
        tool_call: m.tool_call,
        tool_call_status,
        tool_result: m.tool_result,
        created_at: m.created_at,
    })
}

/// The sea-orm-backed implementation — see [`crate::AssistantStore`]'s docs.
pub struct SeaOrmAssistantStore {
    db: DatabaseConnection,
}

impl SeaOrmAssistantStore {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Convenience for tests — see `discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests`'s
    /// docs for why this exists and why it's async.
    pub async fn new_in_memory_for_tests() -> Self {
        Self::new(discovery_migration::connect_in_memory_for_tests().await)
    }
}

#[async_trait]
impl AssistantStore for SeaOrmAssistantStore {
    async fn create_conversation(
        &self,
        owner_user_id: Uuid,
        title: &str,
    ) -> anyhow::Result<Conversation> {
        use assistant_conversations::ActiveModel;
        let now = chrono::Utc::now();
        let conversation = Conversation {
            id: Uuid::new_v4(),
            owner_user_id,
            title: title.to_string(),
            created_at: now,
            updated_at: now,
            auto_approve_writes: false,
        };
        let am = ActiveModel {
            id: Set(conversation.id),
            owner_user_id: Set(conversation.owner_user_id),
            title: Set(conversation.title.clone()),
            created_at: Set(conversation.created_at),
            updated_at: Set(conversation.updated_at),
            auto_approve_writes: Set(conversation.auto_approve_writes),
        };
        assistant_conversations::Entity::insert(am)
            .exec(&self.db)
            .await?;
        Ok(conversation)
    }

    async fn list_conversations(&self, owner_user_id: Uuid) -> anyhow::Result<Vec<Conversation>> {
        use assistant_conversations::{Column, Entity};
        let models = Entity::find()
            .filter(Column::OwnerUserId.eq(owner_user_id))
            .order_by(Column::UpdatedAt, Order::Desc)
            .all(&self.db)
            .await?;
        Ok(models.into_iter().map(model_to_conversation).collect())
    }

    async fn get_conversation(&self, id: Uuid) -> anyhow::Result<Option<Conversation>> {
        use assistant_conversations::Entity;
        Ok(Entity::find_by_id(id)
            .one(&self.db)
            .await?
            .map(model_to_conversation))
    }

    async fn list_messages(&self, conversation_id: Uuid) -> anyhow::Result<Vec<Message>> {
        use assistant_messages::{Column, Entity};
        let models = Entity::find()
            .filter(Column::ConversationId.eq(conversation_id))
            .order_by(Column::Sequence, Order::Asc)
            .all(&self.db)
            .await?;
        models.into_iter().map(model_to_message).collect()
    }

    async fn append_message(&self, msg: &Message) -> anyhow::Result<()> {
        use assistant_messages::{ActiveModel, Column, Entity};

        // Next sequence for this conversation — a single extra query is fine, appending a
        // message is not a hot path (bounded by human typing speed / one LLM round trip).
        let last = Entity::find()
            .filter(Column::ConversationId.eq(msg.conversation_id))
            .order_by(Column::Sequence, Order::Desc)
            .one(&self.db)
            .await?;
        let sequence = last.map(|m| m.sequence + 1).unwrap_or(0);

        let am = ActiveModel {
            id: Set(msg.id),
            conversation_id: Set(msg.conversation_id),
            sequence: Set(sequence),
            role: Set(msg.role.as_str().to_string()),
            content: Set(msg.content.clone()),
            tool_call: Set(msg.tool_call.clone()),
            tool_call_status: Set(msg.tool_call_status.as_str().to_string()),
            tool_result: Set(msg.tool_result.clone()),
            created_at: Set(msg.created_at),
        };
        Entity::insert(am).exec(&self.db).await?;
        Ok(())
    }

    async fn update_message_tool_status(
        &self,
        id: Uuid,
        status: ToolCallStatus,
        tool_result: Option<serde_json::Value>,
    ) -> anyhow::Result<()> {
        use assistant_messages::{ActiveModel, Entity};
        let existing = Entity::find_by_id(id)
            .one(&self.db)
            .await?
            .ok_or_else(|| anyhow::anyhow!("assistant message {id} not found"))?;
        let mut am: ActiveModel = existing.into();
        am.tool_call_status = Set(status.as_str().to_string());
        am.tool_result = Set(tool_result);
        am.update(&self.db).await?;
        Ok(())
    }

    async fn claim_pending_tool_call(&self, id: Uuid) -> anyhow::Result<bool> {
        use assistant_messages::{Column, Entity};
        let result = Entity::update_many()
            .col_expr(
                Column::ToolCallStatus,
                Expr::value(ToolCallStatus::Confirmed.as_str()),
            )
            .filter(Column::Id.eq(id))
            .filter(Column::ToolCallStatus.eq(ToolCallStatus::PendingConfirmation.as_str()))
            .exec(&self.db)
            .await?;
        Ok(result.rows_affected == 1)
    }

    async fn set_auto_approve_writes(&self, id: Uuid, enabled: bool) -> anyhow::Result<()> {
        use assistant_conversations::{ActiveModel, Entity};
        let existing = Entity::find_by_id(id)
            .one(&self.db)
            .await?
            .ok_or_else(|| anyhow::anyhow!("conversation {id} not found"))?;
        let mut am: ActiveModel = existing.into();
        am.auto_approve_writes = Set(enabled);
        am.update(&self.db).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(conversation_id: Uuid, role: MessageRole, content: &str) -> Message {
        Message {
            id: Uuid::new_v4(),
            conversation_id,
            sequence: 0,
            role,
            content: Some(content.to_string()),
            tool_call: None,
            tool_call_status: ToolCallStatus::None,
            tool_result: None,
            created_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn create_and_get_conversation_round_trips() {
        let store = SeaOrmAssistantStore::new_in_memory_for_tests().await;
        let owner = Uuid::new_v4();
        let created = store.create_conversation(owner, "Новый чат").await.unwrap();

        let fetched = store
            .get_conversation(created.id)
            .await
            .unwrap()
            .expect("just created");
        assert_eq!(fetched.owner_user_id, owner);
        assert_eq!(fetched.title, "Новый чат");
    }

    #[tokio::test]
    async fn create_conversation_defaults_auto_approve_writes_to_false() {
        let store = SeaOrmAssistantStore::new_in_memory_for_tests().await;
        let created = store
            .create_conversation(Uuid::new_v4(), "chat")
            .await
            .unwrap();
        assert!(!created.auto_approve_writes);

        let fetched = store
            .get_conversation(created.id)
            .await
            .unwrap()
            .expect("just created");
        assert!(!fetched.auto_approve_writes);
    }

    #[tokio::test]
    async fn set_auto_approve_writes_round_trips_and_survives_a_reload() {
        let store = SeaOrmAssistantStore::new_in_memory_for_tests().await;
        let created = store
            .create_conversation(Uuid::new_v4(), "chat")
            .await
            .unwrap();

        store
            .set_auto_approve_writes(created.id, true)
            .await
            .unwrap();
        let enabled = store
            .get_conversation(created.id)
            .await
            .unwrap()
            .expect("still exists");
        assert!(enabled.auto_approve_writes);
        assert_eq!(
            enabled.title, "chat",
            "unrelated fields must survive the update untouched"
        );

        store
            .set_auto_approve_writes(created.id, false)
            .await
            .unwrap();
        let disabled = store
            .get_conversation(created.id)
            .await
            .unwrap()
            .expect("still exists");
        assert!(!disabled.auto_approve_writes);
    }

    #[tokio::test]
    async fn set_auto_approve_writes_on_an_unknown_id_is_an_error() {
        let store = SeaOrmAssistantStore::new_in_memory_for_tests().await;
        assert!(store
            .set_auto_approve_writes(Uuid::new_v4(), true)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn get_conversation_returns_none_for_an_unknown_id() {
        let store = SeaOrmAssistantStore::new_in_memory_for_tests().await;
        assert!(store
            .get_conversation(Uuid::new_v4())
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn list_conversations_is_scoped_per_owner() {
        let store = SeaOrmAssistantStore::new_in_memory_for_tests().await;
        let alice = Uuid::new_v4();
        let bob = Uuid::new_v4();
        store
            .create_conversation(alice, "alice's chat")
            .await
            .unwrap();
        store.create_conversation(bob, "bob's chat").await.unwrap();

        let alice_conversations = store.list_conversations(alice).await.unwrap();
        assert_eq!(alice_conversations.len(), 1);
        assert_eq!(alice_conversations[0].title, "alice's chat");
    }

    #[tokio::test]
    async fn messages_are_appended_in_stable_sequence_order() {
        let store = SeaOrmAssistantStore::new_in_memory_for_tests().await;
        let conversation = store
            .create_conversation(Uuid::new_v4(), "chat")
            .await
            .unwrap();

        store
            .append_message(&message(conversation.id, MessageRole::User, "первое"))
            .await
            .unwrap();
        store
            .append_message(&message(conversation.id, MessageRole::Assistant, "второе"))
            .await
            .unwrap();
        store
            .append_message(&message(conversation.id, MessageRole::User, "третье"))
            .await
            .unwrap();

        let messages = store.list_messages(conversation.id).await.unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0].content.as_deref(), Some("первое"));
        assert_eq!(messages[0].sequence, 0);
        assert_eq!(messages[1].content.as_deref(), Some("второе"));
        assert_eq!(messages[1].sequence, 1);
        assert_eq!(messages[2].content.as_deref(), Some("третье"));
        assert_eq!(messages[2].sequence, 2);
    }

    #[tokio::test]
    async fn sequences_are_independent_per_conversation() {
        let store = SeaOrmAssistantStore::new_in_memory_for_tests().await;
        let c1 = store
            .create_conversation(Uuid::new_v4(), "c1")
            .await
            .unwrap();
        let c2 = store
            .create_conversation(Uuid::new_v4(), "c2")
            .await
            .unwrap();

        store
            .append_message(&message(c1.id, MessageRole::User, "a"))
            .await
            .unwrap();
        store
            .append_message(&message(c2.id, MessageRole::User, "b"))
            .await
            .unwrap();
        store
            .append_message(&message(c1.id, MessageRole::User, "c"))
            .await
            .unwrap();

        let c1_messages = store.list_messages(c1.id).await.unwrap();
        assert_eq!(c1_messages.len(), 2);
        assert_eq!(c1_messages[0].sequence, 0);
        assert_eq!(c1_messages[1].sequence, 1);

        let c2_messages = store.list_messages(c2.id).await.unwrap();
        assert_eq!(c2_messages.len(), 1);
        assert_eq!(c2_messages[0].sequence, 0);
    }

    #[tokio::test]
    async fn update_message_tool_status_round_trips() {
        let store = SeaOrmAssistantStore::new_in_memory_for_tests().await;
        let conversation = store
            .create_conversation(Uuid::new_v4(), "chat")
            .await
            .unwrap();
        let mut msg = message(conversation.id, MessageRole::Assistant, "");
        msg.tool_call = Some(serde_json::json!({"name": "list_alerts", "arguments": {}}));
        msg.tool_call_status = ToolCallStatus::PendingConfirmation;
        store.append_message(&msg).await.unwrap();

        let appended = &store.list_messages(conversation.id).await.unwrap()[0];
        assert_eq!(
            appended.tool_call_status,
            ToolCallStatus::PendingConfirmation
        );

        let result = serde_json::json!({"status_code": 204, "body": ""});
        store
            .update_message_tool_status(appended.id, ToolCallStatus::Executed, Some(result.clone()))
            .await
            .unwrap();

        let updated = &store.list_messages(conversation.id).await.unwrap()[0];
        assert_eq!(updated.tool_call_status, ToolCallStatus::Executed);
        assert_eq!(updated.tool_result, Some(result));
        assert_eq!(
            updated.tool_call, msg.tool_call,
            "unrelated fields must survive the update untouched"
        );
    }

    #[tokio::test]
    async fn pending_tool_call_can_be_claimed_only_once() {
        let store = SeaOrmAssistantStore::new_in_memory_for_tests().await;
        let conversation = store
            .create_conversation(Uuid::new_v4(), "chat")
            .await
            .unwrap();
        let mut msg = message(conversation.id, MessageRole::Assistant, "");
        msg.tool_call = Some(serde_json::json!({"name": "set_device_enabled", "arguments": {}}));
        msg.tool_call_status = ToolCallStatus::PendingConfirmation;
        store.append_message(&msg).await.unwrap();

        let first = store.claim_pending_tool_call(msg.id).await.unwrap();
        let second = store.claim_pending_tool_call(msg.id).await.unwrap();
        assert!(first);
        assert!(!second);
        assert_eq!(
            store.list_messages(conversation.id).await.unwrap()[0].tool_call_status,
            ToolCallStatus::Confirmed
        );
    }
}
