//! `notification_channels` — one row per user-owned contact point
//! (`discovery_core::NotificationChannel` / `discovery_config_store::NotificationChannelStore`).
//! Self-service resource, not gated by `discovery_core::Domain::Notifications` — see that
//! domain variant's docs. Added 2026-09-10 alongside the notification matrix
//! (`notification_rules`, see that entity's docs).
//!
//! No FK to `users` at the sea-orm level for the same cross-domain reasoning
//! `maintenance_windows`/`alerts` already document: `users` lives alongside `Settings`
//! (auth tables), while this table could in principle live in a different physical
//! database if `Notifications`-adjacent data ever got its own routing target — a real FK
//! would fail the moment the two are split across connections. Ownership is enforced in
//! application code (`discovery-web`'s self-service handlers check `channel.user_id ==
//! current_user.id`), the same boundary `journal_entries.username` already draws.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "notification_channels")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub user_id: Uuid,
    /// `discovery_core::NotificationChannelKind::as_str()` — "email"/"telegram"/"webhook".
    pub kind: String,
    pub target: String,
    /// Webhook HMAC-signing secret, encrypted at rest
    /// (`discovery_core::secret::encrypt_secret`/`decrypt_secret`) by
    /// `discovery-config-store`'s implementation before/after this column is touched.
    /// `None` for `Email`/`Telegram` channels, or a `Webhook` channel with no signing
    /// configured.
    pub secret: Option<String>,
    pub enabled: bool,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
