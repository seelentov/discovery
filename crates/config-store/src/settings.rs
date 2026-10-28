use async_trait::async_trait;
use discovery_core::secret::SecretKey;
use discovery_core::{
    AiAssistantProviderConfig, AlertRetentionConfig, ConfigBackupSettings, DeadDeviceRetentionConfig,
    JournalRetentionConfig, LogRetentionConfig, NotificationProviderConfig, PingConfig,
    PollIntervalsConfig, TrapEngineState,
};
use std::sync::Arc;

use crate::notification_channel::{decrypt_optional_secret, encrypt_optional_secret};

/// Process-wide, dashboard-editable runtime settings — currently just
/// [`PollIntervalsConfig`], the first (and so far only) settings category moved out of
/// `config.toml` into the database (direct user request 2026-08-16: "конфигурацию мы
/// храним в БД! И должна быть возможность для webui для изменения настроек + они должны
/// сразу применяться" — see `discovery_core::PollIntervalsConfig`'s docs for the full
/// rationale). A typed method per category, same shape as `ProfileStore`/
/// `DiscoveryConfigStore` — not a generic "get/set any key" API, so each category keeps
/// its own validation/shape guarantees at the Rust type level rather than deserializing
/// untyped JSON at every call site.
///
/// Backed by a single generic `settings(key, value, updated_at)` table under the hood
/// (see each implementation's docs) — deliberately generic at the *storage* layer even
/// though the trait above it is typed, so a second settings category later (concurrency?
/// logging levels?) is a new row and a new typed method, not a new table/migration.
#[async_trait]
pub trait SettingsStore: Send + Sync {
    /// `None` if nothing has ever been written — callers (`discovery-agent::main`) treat
    /// this as "first run" and seed it from `config.toml`'s `[poll_intervals]` (or that
    /// section's own built-in defaults if `config.toml` doesn't set it either).
    async fn get_poll_intervals(&self) -> anyhow::Result<Option<PollIntervalsConfig>>;

    async fn set_poll_intervals(&self, intervals: &PollIntervalsConfig) -> anyhow::Result<()>;

    /// Convenience wrapper for the common case — most callers (recurring background
    /// loops/chains) just want "the current settings, or built-in defaults if nothing's
    /// been written yet or this particular read hiccuped" rather than plumbing an
    /// `Option`/`Result` through every single poll tick for a setting that isn't
    /// safety-critical to get perfectly. Read fresh on every call (no caching) — that's
    /// what makes a dashboard edit apply on the *next* tick of whichever loop/chain calls
    /// this, not just at process startup. A default `#[async_trait]` method, not
    /// reimplemented per backend.
    async fn poll_intervals(&self) -> PollIntervalsConfig {
        self.get_poll_intervals()
            .await
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    /// Second settings category, added 2026-08-17 — direct user request "добавь
    /// конфигурацию на время хранения тревог" (alert history retention). Same
    /// `Option`-on-read / seed-on-first-run contract as `get_poll_intervals`.
    async fn get_alert_retention(&self) -> anyhow::Result<Option<AlertRetentionConfig>>;

    async fn set_alert_retention(&self, retention: &AlertRetentionConfig) -> anyhow::Result<()>;

    /// Same "just give me *something* usable" convenience as `poll_intervals()`.
    async fn alert_retention(&self) -> AlertRetentionConfig {
        self.get_alert_retention()
            .await
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    /// Third settings category, added 2026-08-18 — direct user request correcting an
    /// earlier decision: "'настраивать периодичность, не таймаут пробы' не правда. Нужно
    /// сделать настраиваемым и таймауты и кол-во проб и периодичность." Periodicity was
    /// already covered (`PollIntervalsConfig.reachability_secs`); this is the other two.
    /// Same `Option`-on-read / seed-on-first-run contract as `get_poll_intervals`.
    async fn get_ping_config(&self) -> anyhow::Result<Option<PingConfig>>;

    async fn set_ping_config(&self, config: &PingConfig) -> anyhow::Result<()>;

    /// Same "just give me *something* usable" convenience as `poll_intervals()`.
    async fn ping_config(&self) -> PingConfig {
        self.get_ping_config()
            .await
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    /// Fourth settings category, added 2026-08-18 — direct user request following up on
    /// manual device deletion already existing in the UI: "Сделай настраиваемый через
    /// конфиг период времени после которого устройство с ping=false удаляется. По
    /// умолчанию сделай 0 - если 0 никогда не удалять." Same `Option`-on-read /
    /// seed-on-first-run contract as `get_poll_intervals`.
    async fn get_dead_device_retention(&self) -> anyhow::Result<Option<DeadDeviceRetentionConfig>>;

    async fn set_dead_device_retention(
        &self,
        retention: &DeadDeviceRetentionConfig,
    ) -> anyhow::Result<()>;

    /// Same "just give me *something* usable" convenience as `poll_intervals()` — and,
    /// since [`DeadDeviceRetentionConfig::default`] is `unreachable_for_secs: 0`
    /// ("disabled"), a read failure here fails safe: nothing gets auto-deleted, same as an
    /// explicit `0`.
    async fn dead_device_retention(&self) -> DeadDeviceRetentionConfig {
        self.get_dead_device_retention()
            .await
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    /// Fifth settings category, added 2026-08-21 — scale audit finding: `logs` had no
    /// retention mechanism at all, unlike `device_metric_history`/`alerts`. Same
    /// `Option`-on-read / seed-on-first-run contract as `get_poll_intervals`.
    async fn get_log_retention(&self) -> anyhow::Result<Option<LogRetentionConfig>>;

    async fn set_log_retention(&self, retention: &LogRetentionConfig) -> anyhow::Result<()>;

    /// Same "just give me *something* usable" convenience as `poll_intervals()`.
    async fn log_retention(&self) -> LogRetentionConfig {
        self.get_log_retention()
            .await
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    /// Sixth settings category — audit journal retention (`discovery_journal::JournalStore`),
    /// added alongside the "Журнал" feature. Same `Option`-on-read / seed-on-first-run
    /// contract as `get_poll_intervals`.
    async fn get_journal_retention(&self) -> anyhow::Result<Option<JournalRetentionConfig>>;

    async fn set_journal_retention(&self, retention: &JournalRetentionConfig)
        -> anyhow::Result<()>;

    /// Same "just give me *something* usable" convenience as `poll_intervals()`.
    async fn journal_retention(&self) -> JournalRetentionConfig {
        self.get_journal_retention()
            .await
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    /// Seventh settings category — SNMP Trap ingestion, 2026-08-30. No convenience
    /// `trap_engine_state()` method (unlike every category above): unwrapping a read
    /// failure to a *fabricated* default here would silently start handing out a random
    /// fresh `engine_id`/`engine_boots` on every hiccup, which is exactly the identity
    /// churn `discovery-agent`'s trap listener startup is supposed to prevent — see
    /// `discovery_core::TrapEngineState`'s docs. Callers must handle `Ok(None)`
    /// (first-run — `AuthoritativeEngine::install`) and `Ok(Some(_))` (`::restart`)
    /// explicitly, and treat `Err` as fatal to trap listener startup, not as "use a
    /// default".
    async fn get_trap_engine_state(&self) -> anyhow::Result<Option<TrapEngineState>>;

    async fn set_trap_engine_state(&self, state: &TrapEngineState) -> anyhow::Result<()>;

    /// Eighth settings category — notification channel provider credentials (SMTP relay +
    /// Telegram bot token), added 2026-09-10 alongside notification channels/matrix. Same
    /// `Option`-on-read / seed-on-first-run contract as `get_poll_intervals`, but with an
    /// extra encrypt/decrypt step at this boundary for `smtp_password`/`telegram_bot_token`
    /// — see [`SeaOrmSettingsStore::with_secret_key`]'s docs. Unlike every category above,
    /// this one can fail for a reason other than "the DB hiccuped": a `Some` value with a
    /// non-empty secret and no `DISCOVERY_SECRET_KEY` configured on `set_notification_provider`
    /// is `Err` (the same "no passthrough" contract `discovery_core::secret::
    /// encrypt_ssh_auth_secrets` already has for SSH credentials).
    async fn get_notification_provider(&self)
        -> anyhow::Result<Option<NotificationProviderConfig>>;

    async fn set_notification_provider(
        &self,
        config: &NotificationProviderConfig,
    ) -> anyhow::Result<()>;

    /// Same "just give me *something* usable" convenience as `poll_intervals()` — a read
    /// failure (or nothing configured yet) reads as "no provider configured", which is
    /// exactly what `discovery-notify`'s email/Telegram senders should fail on with a clear
    /// "provider not configured" error rather than silently using stale credentials.
    async fn notification_provider(&self) -> NotificationProviderConfig {
        self.get_notification_provider()
            .await
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    /// Eleventh settings category — AI assistant provider credentials (GigaChat client
    /// id/secret), added 2026-09-18 alongside the AI assistant feature. Same
    /// `Option`-on-read / seed-on-first-run contract as `get_poll_intervals`, but with an
    /// extra encrypt/decrypt step for `client_secret` — see
    /// [`SeaOrmSettingsStore::get_ai_assistant_provider`]'s docs. Same "no passthrough"
    /// contract as `set_notification_provider`: a `Some` value with a non-empty
    /// `client_secret` and no `DISCOVERY_SECRET_KEY` configured is `Err`.
    async fn get_ai_assistant_provider(&self) -> anyhow::Result<Option<AiAssistantProviderConfig>>;

    async fn set_ai_assistant_provider(
        &self,
        config: &AiAssistantProviderConfig,
    ) -> anyhow::Result<()>;

    /// Same "just give me *something* usable" convenience as `poll_intervals()` — a read
    /// failure (or nothing configured yet) reads as "assistant not configured", which is
    /// exactly what the assistant chat orchestration should fail on with a clear error
    /// rather than silently using stale credentials.
    async fn ai_assistant_provider(&self) -> AiAssistantProviderConfig {
        self.get_ai_assistant_provider()
            .await
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    async fn get_config_backup(&self) -> anyhow::Result<Option<ConfigBackupSettings>>;
    async fn set_config_backup(&self, config: &ConfigBackupSettings) -> anyhow::Result<()>;

    async fn config_backup(&self) -> ConfigBackupSettings {
        self.get_config_backup().await.ok().flatten().unwrap_or_default()
    }
}

const POLL_INTERVALS_KEY: &str = "poll_intervals";
const ALERT_RETENTION_KEY: &str = "alert_retention";
const PING_CONFIG_KEY: &str = "ping_config";
const DEAD_DEVICE_RETENTION_KEY: &str = "dead_device_retention";
const LOG_RETENTION_KEY: &str = "log_retention";
const JOURNAL_RETENTION_KEY: &str = "journal_retention";
const TRAP_ENGINE_STATE_KEY: &str = "trap_engine_state";
const NOTIFICATION_PROVIDER_KEY: &str = "notification_provider";
const AI_ASSISTANT_PROVIDER_KEY: &str = "ai_assistant_provider";
const CONFIG_BACKUP_KEY: &str = "config_backup";

/// The single sea-orm-backed implementation, replacing the old `PostgresSettingsStore`/
/// `SqliteSettingsStore`/`InMemorySettingsStore` trio (2026-08-18, direct user request —
/// discovery must connect to "разные СУБД": Postgres/MySQL/SQLite, and the in-process
/// "memory" mode is now just another `sea_orm::DatabaseConnection` over
/// `sqlite::memory:`, not a bespoke fourth code path — see `discovery-db::ConnectionRegistry`'s
/// docs). One row per settings category in `settings` (`discovery_entities::settings`,
/// `crates/migration`), `value` as JSON — works identically against any backend `sea_orm`
/// supports, which is the entire point of this rewrite: one query-building code path
/// instead of three hand-written dialects.
pub struct SeaOrmSettingsStore {
    db: sea_orm::DatabaseConnection,
    /// `None` unless [`Self::with_secret_key`] was called — mirrors
    /// `discovery_devices::SeaOrmDeviceStore::secret_key`/`crate::SeaOrmNotificationChannelStore::secret_key`
    /// exactly: without it, `set_notification_provider` with a non-empty `smtp_password`/
    /// `telegram_bot_token` fails loudly (`SecretError::KeyRequired`) rather than writing
    /// plaintext.
    secret_key: Option<Arc<SecretKey>>,
}

impl SeaOrmSettingsStore {
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

    /// Convenience for tests across the workspace — the direct successor of the old
    /// `InMemorySettingsStore::new()` (removed along with `PostgresSettingsStore`/
    /// `SqliteSettingsStore`, see this struct's docs). Unlike the old zero-cost struct
    /// literal, opening any sea-orm connection is inherently async — every call site that
    /// used to say `InMemorySettingsStore::new()` becomes `SeaOrmSettingsStore::new_in_memory_for_tests().await`.
    /// Always compiled (not `#[cfg(test)]`) because callers live in other crates' own test
    /// modules, which need it as an ordinary public item, not a `dev-dependencies`-only one.
    pub async fn new_in_memory_for_tests() -> Self {
        Self::new(discovery_migration::connect_in_memory_for_tests().await)
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, key: &str) -> anyhow::Result<Option<T>> {
        use sea_orm::EntityTrait;
        let row = discovery_entities::settings::Entity::find_by_id(key.to_string())
            .one(&self.db)
            .await?;
        match row {
            Some(model) => Ok(Some(serde_json::from_value(model.value)?)),
            None => Ok(None),
        }
    }

    /// `INSERT ... ON CONFLICT (key) DO UPDATE` (Postgres/SQLite) / `ON DUPLICATE KEY
    /// UPDATE` (MySQL) — sea-query's `OnConflict` translates to whichever the connected
    /// backend actually speaks, same upsert-in-one-round-trip the old hand-written
    /// per-dialect queries did, now written once.
    async fn set<T: serde::Serialize + Sync>(&self, key: &str, value: &T) -> anyhow::Result<()> {
        use discovery_entities::settings::{ActiveModel, Column, Entity};
        use sea_orm::sea_query::OnConflict;
        use sea_orm::{ActiveValue::Set, EntityTrait};

        let json = serde_json::to_value(value)?;
        let am = ActiveModel {
            key: Set(key.to_string()),
            value: Set(json),
            updated_at: Set(chrono::Utc::now()),
        };
        Entity::insert(am)
            .on_conflict(
                OnConflict::column(Column::Key)
                    .update_columns([Column::Value, Column::UpdatedAt])
                    .to_owned(),
            )
            .exec(&self.db)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl SettingsStore for SeaOrmSettingsStore {
    async fn get_poll_intervals(&self) -> anyhow::Result<Option<PollIntervalsConfig>> {
        self.get(POLL_INTERVALS_KEY).await
    }

    async fn set_poll_intervals(&self, intervals: &PollIntervalsConfig) -> anyhow::Result<()> {
        self.set(POLL_INTERVALS_KEY, intervals).await
    }

    async fn get_alert_retention(&self) -> anyhow::Result<Option<AlertRetentionConfig>> {
        self.get(ALERT_RETENTION_KEY).await
    }

    async fn set_alert_retention(&self, retention: &AlertRetentionConfig) -> anyhow::Result<()> {
        self.set(ALERT_RETENTION_KEY, retention).await
    }

    async fn get_ping_config(&self) -> anyhow::Result<Option<PingConfig>> {
        self.get(PING_CONFIG_KEY).await
    }

    async fn set_ping_config(&self, config: &PingConfig) -> anyhow::Result<()> {
        self.set(PING_CONFIG_KEY, config).await
    }

    async fn get_dead_device_retention(&self) -> anyhow::Result<Option<DeadDeviceRetentionConfig>> {
        self.get(DEAD_DEVICE_RETENTION_KEY).await
    }

    async fn set_dead_device_retention(
        &self,
        retention: &DeadDeviceRetentionConfig,
    ) -> anyhow::Result<()> {
        self.set(DEAD_DEVICE_RETENTION_KEY, retention).await
    }

    async fn get_log_retention(&self) -> anyhow::Result<Option<LogRetentionConfig>> {
        self.get(LOG_RETENTION_KEY).await
    }

    async fn set_log_retention(&self, retention: &LogRetentionConfig) -> anyhow::Result<()> {
        self.set(LOG_RETENTION_KEY, retention).await
    }

    async fn get_journal_retention(&self) -> anyhow::Result<Option<JournalRetentionConfig>> {
        self.get(JOURNAL_RETENTION_KEY).await
    }

    async fn set_journal_retention(
        &self,
        retention: &JournalRetentionConfig,
    ) -> anyhow::Result<()> {
        self.set(JOURNAL_RETENTION_KEY, retention).await
    }

    async fn get_trap_engine_state(&self) -> anyhow::Result<Option<TrapEngineState>> {
        self.get(TRAP_ENGINE_STATE_KEY).await
    }

    async fn set_trap_engine_state(&self, state: &TrapEngineState) -> anyhow::Result<()> {
        self.set(TRAP_ENGINE_STATE_KEY, state).await
    }

    async fn get_notification_provider(
        &self,
    ) -> anyhow::Result<Option<NotificationProviderConfig>> {
        let stored: Option<NotificationProviderConfig> =
            self.get(NOTIFICATION_PROVIDER_KEY).await?;
        Ok(stored.map(|mut cfg| {
            // Graceful degradation on decrypt failure (wrong/missing key) — see
            // `decrypt_optional_secret`'s docs. The rest of the config (host/port/
            // username/from address) is still perfectly usable even if the secret isn't.
            cfg.smtp_password =
                decrypt_optional_secret(cfg.smtp_password, self.secret_key.as_deref());
            cfg.telegram_bot_token =
                decrypt_optional_secret(cfg.telegram_bot_token, self.secret_key.as_deref());
            cfg
        }))
    }

    async fn set_notification_provider(
        &self,
        config: &NotificationProviderConfig,
    ) -> anyhow::Result<()> {
        let mut to_store = config.clone();
        to_store.smtp_password =
            encrypt_optional_secret(to_store.smtp_password, self.secret_key.as_deref())?;
        to_store.telegram_bot_token =
            encrypt_optional_secret(to_store.telegram_bot_token, self.secret_key.as_deref())?;
        self.set(NOTIFICATION_PROVIDER_KEY, &to_store).await
    }

    /// Same graceful-degrade-on-decrypt-failure contract as `get_notification_provider`
    /// — `client_id`/`enabled`/`provider` are still perfectly usable even if
    /// `client_secret`/`openrouter_api_key`/`self_hosted_api_key` can't be decrypted
    /// (wrong/missing `DISCOVERY_SECRET_KEY`).
    async fn get_ai_assistant_provider(&self) -> anyhow::Result<Option<AiAssistantProviderConfig>> {
        let stored: Option<AiAssistantProviderConfig> = self.get(AI_ASSISTANT_PROVIDER_KEY).await?;
        Ok(stored.map(|mut cfg| {
            cfg.client_secret =
                decrypt_optional_secret(cfg.client_secret, self.secret_key.as_deref());
            cfg.openrouter_api_key =
                decrypt_optional_secret(cfg.openrouter_api_key, self.secret_key.as_deref());
            cfg.self_hosted_api_key =
                decrypt_optional_secret(cfg.self_hosted_api_key, self.secret_key.as_deref());
            cfg
        }))
    }

    async fn set_ai_assistant_provider(
        &self,
        config: &AiAssistantProviderConfig,
    ) -> anyhow::Result<()> {
        let mut to_store = config.clone();
        to_store.client_secret =
            encrypt_optional_secret(to_store.client_secret, self.secret_key.as_deref())?;
        to_store.openrouter_api_key =
            encrypt_optional_secret(to_store.openrouter_api_key, self.secret_key.as_deref())?;
        to_store.self_hosted_api_key =
            encrypt_optional_secret(to_store.self_hosted_api_key, self.secret_key.as_deref())?;
        self.set(AI_ASSISTANT_PROVIDER_KEY, &to_store).await
    }

    async fn get_config_backup(&self) -> anyhow::Result<Option<ConfigBackupSettings>> {
        self.get(CONFIG_BACKUP_KEY).await
    }

    async fn set_config_backup(&self, config: &ConfigBackupSettings) -> anyhow::Result<()> {
        self.set(CONFIG_BACKUP_KEY, config).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn store_starts_empty_and_round_trips_a_write() {
        let store = SeaOrmSettingsStore::new_in_memory_for_tests().await;
        assert_eq!(
            store.get_poll_intervals().await.unwrap(),
            None,
            "nothing written yet — first-run seeding must detect this"
        );

        let intervals = PollIntervalsConfig {
            reachability_secs: 42,
            ..Default::default()
        };
        store.set_poll_intervals(&intervals).await.unwrap();
        assert_eq!(store.get_poll_intervals().await.unwrap(), Some(intervals));
    }

    #[tokio::test]
    async fn a_second_write_overwrites_the_first_not_a_duplicate_row() {
        let store = SeaOrmSettingsStore::new_in_memory_for_tests().await;
        store
            .set_poll_intervals(&PollIntervalsConfig {
                reachability_secs: 10,
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .set_poll_intervals(&PollIntervalsConfig {
                reachability_secs: 20,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            store
                .get_poll_intervals()
                .await
                .unwrap()
                .unwrap()
                .reachability_secs,
            20
        );
    }

    #[tokio::test]
    async fn all_six_categories_round_trip_independently() {
        let store = SeaOrmSettingsStore::new_in_memory_for_tests().await;
        store
            .set_config_backup(&ConfigBackupSettings {
                enabled: true,
                schedule: Some(discovery_core::Schedule::Periodic { interval_secs: 3600 }),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .set_alert_retention(&AlertRetentionConfig {
                retention_secs: Some(123),
            })
            .await
            .unwrap();
        store
            .set_ping_config(&PingConfig {
                timeout_ms: 500,
                retries: 2,
            })
            .await
            .unwrap();
        store
            .set_dead_device_retention(&DeadDeviceRetentionConfig {
                unreachable_for_secs: 3600,
            })
            .await
            .unwrap();
        store
            .set_log_retention(&LogRetentionConfig {
                retention_secs: Some(456),
            })
            .await
            .unwrap();
        store
            .set_journal_retention(&JournalRetentionConfig {
                retention_secs: Some(789),
            })
            .await
            .unwrap();

        assert_eq!(store.alert_retention().await.retention_secs, Some(123));
        assert_eq!(store.ping_config().await.timeout_ms, 500);
        assert_eq!(
            store.dead_device_retention().await.unreachable_for_secs,
            3600
        );
        assert_eq!(store.log_retention().await.retention_secs, Some(456));
        assert_eq!(store.journal_retention().await.retention_secs, Some(789));
        // Untouched category must still read as the built-in default via the convenience
        // method, not error or bleed values from a sibling category.
        assert_eq!(store.poll_intervals().await, PollIntervalsConfig::default());
        assert_eq!(store.config_backup().await.schedule, Some(discovery_core::Schedule::Periodic { interval_secs: 3600 }));
    }

    #[tokio::test]
    async fn trap_engine_state_round_trips_and_starts_absent() {
        let store = SeaOrmSettingsStore::new_in_memory_for_tests().await;
        assert_eq!(
            store.get_trap_engine_state().await.unwrap(),
            None,
            "first run — the caller must call AuthoritativeEngine::install, not ::restart"
        );

        let state = discovery_core::TrapEngineState {
            engine_id: vec![0xde, 0xad, 0xbe, 0xef],
            engine_boots: 3,
        };
        store.set_trap_engine_state(&state).await.unwrap();
        assert_eq!(store.get_trap_engine_state().await.unwrap(), Some(state));
    }

    #[tokio::test]
    async fn notification_provider_without_secrets_needs_no_key() {
        let store = SeaOrmSettingsStore::new_in_memory_for_tests().await;
        assert_eq!(
            store.notification_provider().await,
            NotificationProviderConfig::default(),
            "nothing configured yet — must read as the built-in default, not error"
        );

        let config = NotificationProviderConfig {
            smtp_host: Some("mail.example.com".into()),
            smtp_from_address: Some("alerts@example.com".into()),
            ..Default::default()
        };
        store.set_notification_provider(&config).await.unwrap();
        assert_eq!(
            store.get_notification_provider().await.unwrap(),
            Some(config)
        );
    }

    #[tokio::test]
    async fn notification_provider_secrets_require_a_key_to_persist() {
        let store = SeaOrmSettingsStore::new_in_memory_for_tests().await; // no secret key configured
        let config = NotificationProviderConfig {
            smtp_password: Some("hunter2".into()),
            ..Default::default()
        };
        let err = store.set_notification_provider(&config).await.unwrap_err();
        assert!(
            format!("{err:?}").contains("KeyRequired")
                || err.to_string().contains("DISCOVERY_SECRET_KEY"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn notification_provider_secrets_round_trip_through_encrypt_then_decrypt_with_a_key() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        let db = discovery_migration::connect_in_memory_for_tests().await;
        let key = Arc::new(SecretKey::from_base64(&STANDARD.encode([5u8; 32])).unwrap());
        let store = SeaOrmSettingsStore::new(db).with_secret_key(key);
        let config = NotificationProviderConfig {
            smtp_host: Some("mail.example.com".into()),
            smtp_username: Some("alerts".into()),
            smtp_password: Some("hunter2".into()),
            telegram_bot_token: Some("123:ABC".into()),
            ..Default::default()
        };
        store.set_notification_provider(&config).await.unwrap();

        let fetched = store
            .get_notification_provider()
            .await
            .unwrap()
            .expect("just written");
        assert_eq!(
            fetched, config,
            "decrypted read must equal the plaintext originally written"
        );
    }

    #[tokio::test]
    async fn ai_assistant_provider_without_a_secret_needs_no_key() {
        let store = SeaOrmSettingsStore::new_in_memory_for_tests().await;
        assert_eq!(
            store.ai_assistant_provider().await,
            AiAssistantProviderConfig::default(),
            "nothing configured yet — must read as the built-in default, not error"
        );

        let config = AiAssistantProviderConfig {
            enabled: true,
            provider: "gigachat".to_string(),
            client_id: "test-client".to_string(),
            client_secret: None,
            ..Default::default()
        };
        store.set_ai_assistant_provider(&config).await.unwrap();
        assert_eq!(
            store.get_ai_assistant_provider().await.unwrap(),
            Some(config)
        );
    }

    #[tokio::test]
    async fn ai_assistant_provider_secret_requires_a_key_to_persist() {
        let store = SeaOrmSettingsStore::new_in_memory_for_tests().await; // no secret key configured
        let config = AiAssistantProviderConfig {
            client_secret: Some("hunter2".into()),
            ..Default::default()
        };
        let err = store.set_ai_assistant_provider(&config).await.unwrap_err();
        assert!(
            format!("{err:?}").contains("KeyRequired")
                || err.to_string().contains("DISCOVERY_SECRET_KEY"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn ai_assistant_provider_secret_round_trips_through_encrypt_then_decrypt_with_a_key() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        let db = discovery_migration::connect_in_memory_for_tests().await;
        let key = Arc::new(SecretKey::from_base64(&STANDARD.encode([6u8; 32])).unwrap());
        let store = SeaOrmSettingsStore::new(db).with_secret_key(key);
        let config = AiAssistantProviderConfig {
            enabled: true,
            provider: "gigachat".to_string(),
            client_id: "test-client".to_string(),
            client_secret: Some("hunter2".into()),
            ..Default::default()
        };
        store.set_ai_assistant_provider(&config).await.unwrap();

        let fetched = store
            .get_ai_assistant_provider()
            .await
            .unwrap()
            .expect("just written");
        assert_eq!(
            fetched, config,
            "decrypted read must equal the plaintext originally written"
        );
    }

    #[tokio::test]
    async fn ai_assistant_provider_openrouter_api_key_requires_a_key_to_persist() {
        let store = SeaOrmSettingsStore::new_in_memory_for_tests().await; // no secret key configured
        let config = AiAssistantProviderConfig {
            provider: "openrouter".to_string(),
            openrouter_api_key: Some("sk-or-hunter2".into()),
            ..Default::default()
        };
        let err = store.set_ai_assistant_provider(&config).await.unwrap_err();
        assert!(
            format!("{err:?}").contains("KeyRequired")
                || err.to_string().contains("DISCOVERY_SECRET_KEY"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn ai_assistant_provider_openrouter_api_key_round_trips_through_encrypt_then_decrypt_with_a_key(
    ) {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        let db = discovery_migration::connect_in_memory_for_tests().await;
        let key = Arc::new(SecretKey::from_base64(&STANDARD.encode([6u8; 32])).unwrap());
        let store = SeaOrmSettingsStore::new(db).with_secret_key(key);
        let config = AiAssistantProviderConfig {
            enabled: true,
            provider: "openrouter".to_string(),
            openrouter_api_key: Some("sk-or-hunter2".into()),
            openrouter_model: "openai/gpt-4o-mini".to_string(),
            ..Default::default()
        };
        store.set_ai_assistant_provider(&config).await.unwrap();

        let fetched = store
            .get_ai_assistant_provider()
            .await
            .unwrap()
            .expect("just written");
        assert_eq!(
            fetched, config,
            "decrypted read must equal the plaintext originally written"
        );
        assert!(
            fetched.client_secret.is_none(),
            "unrelated GigaChat secret field must stay untouched"
        );
    }

    #[tokio::test]
    async fn ai_assistant_provider_self_hosted_api_key_requires_a_key_to_persist() {
        let store = SeaOrmSettingsStore::new_in_memory_for_tests().await; // no secret key configured
        let config = AiAssistantProviderConfig {
            provider: "self_hosted".to_string(),
            self_hosted_api_key: Some("hunter2".into()),
            ..Default::default()
        };
        let err = store.set_ai_assistant_provider(&config).await.unwrap_err();
        assert!(
            format!("{err:?}").contains("KeyRequired")
                || err.to_string().contains("DISCOVERY_SECRET_KEY"),
            "unexpected error: {err}"
        );
    }

    /// Unlike GigaChat/OpenRouter, a self-hosted config with **no** `self_hosted_api_key`
    /// at all is a real, common setup (a self-hosted server with no auth) — must persist
    /// with no `DISCOVERY_SECRET_KEY` configured at all, not fail the way a real secret
    /// value would.
    #[tokio::test]
    async fn ai_assistant_provider_self_hosted_without_an_api_key_needs_no_secret_key() {
        let store = SeaOrmSettingsStore::new_in_memory_for_tests().await; // no secret key configured
        let config = AiAssistantProviderConfig {
            enabled: true,
            provider: "self_hosted".to_string(),
            self_hosted_base_url: "http://localhost:11434/v1/chat/completions".to_string(),
            self_hosted_model: "llama3".to_string(),
            ..Default::default()
        };
        store.set_ai_assistant_provider(&config).await.unwrap();
        assert_eq!(
            store.get_ai_assistant_provider().await.unwrap(),
            Some(config)
        );
    }

    #[tokio::test]
    async fn ai_assistant_provider_self_hosted_api_key_round_trips_through_encrypt_then_decrypt_with_a_key(
    ) {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        let db = discovery_migration::connect_in_memory_for_tests().await;
        let key = Arc::new(SecretKey::from_base64(&STANDARD.encode([7u8; 32])).unwrap());
        let store = SeaOrmSettingsStore::new(db).with_secret_key(key);
        let config = AiAssistantProviderConfig {
            enabled: true,
            provider: "self_hosted".to_string(),
            self_hosted_base_url: "http://vllm-host:8000/v1/chat/completions".to_string(),
            self_hosted_api_key: Some("hunter2".into()),
            self_hosted_model: "llama3".to_string(),
            ..Default::default()
        };
        store.set_ai_assistant_provider(&config).await.unwrap();

        let fetched = store
            .get_ai_assistant_provider()
            .await
            .unwrap()
            .expect("just written");
        assert_eq!(
            fetched, config,
            "decrypted read must equal the plaintext originally written"
        );
        assert!(
            fetched.client_secret.is_none(),
            "unrelated GigaChat secret field must stay untouched"
        );
        assert!(
            fetched.openrouter_api_key.is_none(),
            "unrelated OpenRouter secret field must stay untouched"
        );
    }
}
