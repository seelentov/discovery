//! Per-user notification channels — direct user request 2026-09-10: "Реализуй каналы
//! нотификации + матрицу нотификации", elaborating `docs/Roadmap.md`'s "каналы нотификации
//! за юзерами" ("у каждого пользователя свои настроенные способы связи... не один
//! глобальный webhook на всю систему"). See `discovery_core::NotificationChannel`'s docs
//! for why the type itself lives one crate down (needed by the dependency-free
//! `discovery-notify`), and `crate::notification_rule` for the matrix (the other half of
//! this feature — "кого извещать по какой тревоге").

use async_trait::async_trait;
use discovery_core::secret::{decrypt_secret, encrypt_secret, SecretError, SecretKey};
use discovery_core::{NotificationChannel, NotificationChannelKind};
use std::sync::Arc;
use tracing::warn;
use uuid::Uuid;

/// Where per-user notification channels live. One implementation —
/// [`SeaOrmNotificationChannelStore`] — same "one trait, one sea-orm implementation" shape
/// as [`crate::MaintenanceWindowStore`].
#[async_trait]
pub trait NotificationChannelStore: Send + Sync {
    /// Self-service read — `discovery-web`'s `GET /api/notifications/channels` calls this
    /// with the requesting user's own id.
    async fn list_for_user(&self, user_id: Uuid) -> anyhow::Result<Vec<NotificationChannel>>;

    /// Batch read for the notification dispatcher (`AlertEvalHandler::dispatch_notifications`)
    /// — one query for every recipient a matched rule names, **not** a loop of
    /// [`Self::list_for_user`] calls per recipient (batch-not-loop discipline, see
    /// `.claude/rules/engineering-patterns.md`). Empty `user_ids` returns an empty `Vec`
    /// without touching the DB.
    async fn list_for_users(&self, user_ids: &[Uuid]) -> anyhow::Result<Vec<NotificationChannel>>;

    async fn get(&self, id: Uuid) -> anyhow::Result<Option<NotificationChannel>>;

    /// Every channel, across every user. Not meant for a hot path — a plain full read.
    async fn list_all(&self) -> anyhow::Result<Vec<NotificationChannel>>;

    /// Insert-or-replace-by-id — same "id decides create vs edit" contract as
    /// `discovery_alerts::AlertStore::upsert`/`crate::MaintenanceWindowStore::upsert`.
    async fn upsert(&self, channel: &NotificationChannel) -> anyhow::Result<()>;

    /// No-op (not an error) if `id` doesn't exist — same convention as
    /// `crate::MaintenanceWindowStore::delete`.
    async fn delete(&self, id: Uuid) -> anyhow::Result<()>;
}

/// The sea-orm-backed implementation — see [`NotificationChannelStore`]'s docs.
pub struct SeaOrmNotificationChannelStore {
    db: sea_orm::DatabaseConnection,
    /// `None` unless [`Self::with_secret_key`] was called — mirrors
    /// `discovery_devices::SeaOrmDeviceStore::secret_key`'s docs exactly: without a key,
    /// writing a channel with a non-empty `secret` fails loudly
    /// (`SecretError::KeyRequired`), it never falls back to plaintext.
    secret_key: Option<Arc<SecretKey>>,
}

impl SeaOrmNotificationChannelStore {
    pub fn new(db: sea_orm::DatabaseConnection) -> Self {
        Self {
            db,
            secret_key: None,
        }
    }

    pub fn with_secret_key(mut self, key: Arc<SecretKey>) -> Self {
        self.secret_key = Some(key);
        self
    }

    pub async fn new_in_memory_for_tests() -> Self {
        Self::new(discovery_migration::connect_in_memory_for_tests().await)
    }
}

/// `None`/empty stay `None` — an empty webhook secret is the same as "no secret configured",
/// not worth encrypting and storing as a zero-length ciphertext. A genuinely non-empty
/// secret with no key configured is [`SecretError::KeyRequired`] — same "no passthrough"
/// contract as `encrypt_ssh_auth_secrets` (see that function's docs): a webhook signing
/// secret is meaningfully sensitive, there's no "not really a secret" branch the way an SNMP
/// community string gets.
pub(crate) fn encrypt_optional_secret(
    secret: Option<String>,
    key: Option<&SecretKey>,
) -> Result<Option<String>, SecretError> {
    match secret {
        None => Ok(None),
        Some(s) if s.is_empty() => Ok(None),
        Some(s) => Ok(Some(encrypt_secret(
            key.ok_or(SecretError::KeyRequired)?,
            &s,
        ))),
    }
}

/// Reverses [`encrypt_optional_secret`] for the settings store's optional provider secrets.
/// Notification channels use [`decrypt_optional_secret_strict`] below: a webhook signing
/// secret must never degrade to an unsigned delivery when the key is missing or wrong.
pub(crate) fn decrypt_optional_secret(
    secret: Option<String>,
    key: Option<&SecretKey>,
) -> Option<String> {
    let ciphertext = secret?;
    match key {
        None => {
            warn!("an encrypted notification secret is stored but no DISCOVERY_SECRET_KEY is configured — treating it as absent");
            None
        }
        Some(key) => match decrypt_secret(key, &ciphertext) {
            Ok(plain) => Some(plain),
            Err(e) => {
                warn!(error = %e, "failed to decrypt a notification secret — treating it as absent");
                None
            }
        },
    }
}

fn decrypt_optional_secret_strict(
    secret: Option<String>,
    key: Option<&SecretKey>,
) -> Result<Option<String>, SecretError> {
    match secret {
        None => Ok(None),
        Some(s) if s.is_empty() => Ok(None),
        Some(s) => Ok(Some(decrypt_secret(
            key.ok_or(SecretError::KeyRequired)?,
            &s,
        )?)),
    }
}

fn model_to_channel(
    m: discovery_entities::notification_channels::Model,
    key: Option<&SecretKey>,
) -> anyhow::Result<NotificationChannel> {
    let kind = NotificationChannelKind::from_str(&m.kind)
        .ok_or_else(|| anyhow::anyhow!("unknown notification channel kind '{}'", m.kind))?;
    Ok(NotificationChannel {
        id: m.id,
        user_id: m.user_id,
        kind,
        target: m.target,
        secret: decrypt_optional_secret_strict(m.secret, key)?,
        enabled: m.enabled,
        created_at: m.created_at,
    })
}

#[async_trait]
impl NotificationChannelStore for SeaOrmNotificationChannelStore {
    async fn list_for_user(&self, user_id: Uuid) -> anyhow::Result<Vec<NotificationChannel>> {
        use discovery_entities::notification_channels::{Column, Entity};
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        Entity::find()
            .filter(Column::UserId.eq(user_id))
            .all(&self.db)
            .await?
            .into_iter()
            .map(|m| model_to_channel(m, self.secret_key.as_deref()))
            .collect()
    }

    async fn list_for_users(&self, user_ids: &[Uuid]) -> anyhow::Result<Vec<NotificationChannel>> {
        if user_ids.is_empty() {
            return Ok(Vec::new());
        }
        use discovery_entities::notification_channels::{Column, Entity};
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        Entity::find()
            .filter(Column::UserId.is_in(user_ids.iter().copied()))
            .all(&self.db)
            .await?
            .into_iter()
            .map(|m| model_to_channel(m, self.secret_key.as_deref()))
            .collect()
    }

    async fn list_all(&self) -> anyhow::Result<Vec<NotificationChannel>> {
        use discovery_entities::notification_channels::Entity;
        use sea_orm::EntityTrait;
        Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(|m| model_to_channel(m, self.secret_key.as_deref()))
            .collect()
    }

    async fn get(&self, id: Uuid) -> anyhow::Result<Option<NotificationChannel>> {
        use discovery_entities::notification_channels::Entity;
        use sea_orm::EntityTrait;
        Entity::find_by_id(id)
            .one(&self.db)
            .await?
            .map(|m| model_to_channel(m, self.secret_key.as_deref()))
            .transpose()
    }

    async fn upsert(&self, channel: &NotificationChannel) -> anyhow::Result<()> {
        use discovery_entities::notification_channels::{ActiveModel, Column, Entity};
        use sea_orm::sea_query::OnConflict;
        use sea_orm::{ActiveValue::Set, EntityTrait};

        let secret = encrypt_optional_secret(channel.secret.clone(), self.secret_key.as_deref())?;
        let now = chrono::Utc::now();
        let am = ActiveModel {
            id: Set(channel.id),
            user_id: Set(channel.user_id),
            kind: Set(channel.kind.as_str().to_string()),
            target: Set(channel.target.clone()),
            secret: Set(secret),
            enabled: Set(channel.enabled),
            created_at: Set(now),
            updated_at: Set(now),
        };
        Entity::insert(am)
            .on_conflict(
                OnConflict::column(Column::Id)
                    .update_columns([
                        Column::UserId,
                        Column::Kind,
                        Column::Target,
                        Column::Secret,
                        Column::Enabled,
                        Column::UpdatedAt,
                    ])
                    .to_owned(),
            )
            .exec(&self.db)
            .await?;
        Ok(())
    }

    async fn delete(&self, id: Uuid) -> anyhow::Result<()> {
        use discovery_entities::notification_channels::Entity;
        use sea_orm::EntityTrait;
        Entity::delete_by_id(id).exec(&self.db).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    fn channel(
        user_id: Uuid,
        kind: NotificationChannelKind,
        target: &str,
        secret: Option<&str>,
    ) -> NotificationChannel {
        NotificationChannel {
            id: Uuid::new_v4(),
            user_id,
            kind,
            target: target.to_string(),
            secret: secret.map(|s| s.to_string()),
            enabled: true,
            created_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn store_round_trips_create_edit_and_delete() {
        let store = SeaOrmNotificationChannelStore::new_in_memory_for_tests().await;
        let user_id = Uuid::new_v4();
        let c = channel(user_id, NotificationChannelKind::Telegram, "123456", None);
        store.upsert(&c).await.unwrap();

        let all = store.list_for_user(user_id).await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].target, "123456");
        assert_eq!(all[0].kind, NotificationChannelKind::Telegram);

        let mut edited = c.clone();
        edited.target = "654321".to_string();
        edited.enabled = false;
        store.upsert(&edited).await.unwrap();
        let all = store.list_for_user(user_id).await.unwrap();
        assert_eq!(
            all.len(),
            1,
            "same id — must update in place, not create a second row"
        );
        assert_eq!(all[0].target, "654321");
        assert!(!all[0].enabled);

        store.delete(c.id).await.unwrap();
        assert!(store.list_for_user(user_id).await.unwrap().is_empty());
        store.delete(Uuid::new_v4()).await.unwrap(); // no-op, not an error
    }

    #[tokio::test]
    async fn list_for_users_batches_across_several_owners_and_ignores_others() {
        let store = SeaOrmNotificationChannelStore::new_in_memory_for_tests().await;
        let alice = Uuid::new_v4();
        let bob = Uuid::new_v4();
        let carol = Uuid::new_v4();
        store
            .upsert(&channel(
                alice,
                NotificationChannelKind::Email,
                "alice@x.com",
                None,
            ))
            .await
            .unwrap();
        store
            .upsert(&channel(
                bob,
                NotificationChannelKind::Email,
                "bob@x.com",
                None,
            ))
            .await
            .unwrap();
        store
            .upsert(&channel(
                carol,
                NotificationChannelKind::Email,
                "carol@x.com",
                None,
            ))
            .await
            .unwrap();

        let batch = store.list_for_users(&[alice, bob]).await.unwrap();
        assert_eq!(batch.len(), 2);
        assert!(batch.iter().all(|c| c.user_id == alice || c.user_id == bob));
    }

    #[tokio::test]
    async fn list_for_users_with_empty_input_returns_empty_without_erroring() {
        let store = SeaOrmNotificationChannelStore::new_in_memory_for_tests().await;
        assert!(store.list_for_users(&[]).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn get_returns_none_for_an_unknown_id() {
        let store = SeaOrmNotificationChannelStore::new_in_memory_for_tests().await;
        assert!(store.get(Uuid::new_v4()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn webhook_secret_requires_a_key_to_persist() {
        let store = SeaOrmNotificationChannelStore::new_in_memory_for_tests().await; // no secret key configured
        let c = channel(
            Uuid::new_v4(),
            NotificationChannelKind::Webhook,
            "https://example.com/hook",
            Some("sekrit"),
        );
        let err = store.upsert(&c).await.unwrap_err();
        assert!(
            err.to_string().contains("DISCOVERY_SECRET_KEY")
                || format!("{err:?}").contains("KeyRequired"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn webhook_secret_round_trips_through_encrypt_then_decrypt_with_a_key() {
        let db = discovery_migration::connect_in_memory_for_tests().await;
        let key = Arc::new(SecretKey::from_base64(&STANDARD.encode([3u8; 32])).unwrap());
        let store = SeaOrmNotificationChannelStore::new(db).with_secret_key(key);
        let c = channel(
            Uuid::new_v4(),
            NotificationChannelKind::Webhook,
            "https://example.com/hook",
            Some("sekrit"),
        );
        store.upsert(&c).await.unwrap();

        let fetched = store.get(c.id).await.unwrap().expect("just inserted");
        assert_eq!(fetched.secret.as_deref(), Some("sekrit"));
    }

    #[tokio::test]
    async fn encrypted_webhook_secret_read_fails_without_the_key() {
        let db = discovery_migration::connect_in_memory_for_tests().await;
        let key = Arc::new(SecretKey::from_base64(&STANDARD.encode([4u8; 32])).unwrap());
        let writer = SeaOrmNotificationChannelStore::new(db.clone()).with_secret_key(key);
        let c = channel(
            Uuid::new_v4(),
            NotificationChannelKind::Webhook,
            "https://example.com/hook",
            Some("sekrit"),
        );
        writer.upsert(&c).await.unwrap();

        let reader = SeaOrmNotificationChannelStore::new(db);
        let err = reader.get(c.id).await.unwrap_err();
        assert!(
            err.to_string().contains("DISCOVERY_SECRET_KEY"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn encrypted_webhook_secret_read_fails_with_the_wrong_key() {
        let db = discovery_migration::connect_in_memory_for_tests().await;
        let writer_key = Arc::new(SecretKey::from_base64(&STANDARD.encode([5u8; 32])).unwrap());
        let writer = SeaOrmNotificationChannelStore::new(db.clone()).with_secret_key(writer_key);
        let c = channel(
            Uuid::new_v4(),
            NotificationChannelKind::Webhook,
            "https://example.com/hook",
            Some("sekrit"),
        );
        writer.upsert(&c).await.unwrap();

        let reader_key = Arc::new(SecretKey::from_base64(&STANDARD.encode([6u8; 32])).unwrap());
        let reader = SeaOrmNotificationChannelStore::new(db).with_secret_key(reader_key);
        let err = reader.get(c.id).await.unwrap_err();
        assert!(
            err.to_string().contains("decryption failed"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn empty_secret_string_is_stored_as_none_not_an_empty_ciphertext() {
        let store = SeaOrmNotificationChannelStore::new_in_memory_for_tests().await; // no key needed
        let c = channel(
            Uuid::new_v4(),
            NotificationChannelKind::Webhook,
            "https://example.com/hook",
            Some(""),
        );
        store.upsert(&c).await.unwrap();
        let fetched = store.get(c.id).await.unwrap().expect("just inserted");
        assert_eq!(fetched.secret, None);
    }
}
