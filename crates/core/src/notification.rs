//! Notification channels + the provider-side config they're delivered through — direct
//! user request 2026-09-10: "Реализуй каналы нотификации + матрицу нотификации", following
//! up on `docs/Roadmap.md`'s "Нотификации — на будущее" section, which deliberately splits
//! the concept in two: **channels** (this file — a user's own contact points, plus the
//! system-wide provider credentials that actually deliver to them) and the **matrix** (a
//! separate resource, `discovery_config_store::NotificationRule` — "who gets notified for
//! which alert"). See that type's docs for why the matrix itself lives one crate up instead
//! of here.
//!
//! **Why these four types live in `discovery-core` and not `discovery-config-store`**
//! (where the analogous `MaintenanceWindow` lives): [`NotificationChannel`]/
//! [`NotificationChannelKind`]/[`NotificationTrigger`]/[`NotificationProviderConfig`] all
//! need to be visible to `discovery-notify` — the low-level crate that actually places the
//! SMTP/Telegram/webhook call, deliberately dependency-free of `discovery-config-store` the
//! same way `discovery-ssh`/`discovery-servicecheck` only depend on this crate, not on
//! `discovery-config-store` (see those crates' `Cargo.toml`s). `NotificationRule` (the
//! matrix row) never crosses into `discovery-notify` at all — only `AlertEvalHandler`
//! (which already depends on `discovery-config-store`) needs it, to decide *which* channels
//! to notify — so it stays where `MaintenanceWindow` already established the pattern for a
//! CRUD resource with a device selector. Mirrors exactly how `SshCredentials`/`SshAuth`
//! live here (needed by both the low-level `discovery-ssh` and the higher-level
//! `discovery-config-store`/`discovery-devices`) while a higher-level SSH *policy* resource
//! would not.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Which protocol a [`NotificationChannel`] delivers through. SMS is deliberately not a
/// variant here (direct user decision 2026-09-10, in the planning round for this feature):
/// unlike email/Telegram/webhook, it requires picking a specific paid provider (Twilio/
/// SMS.ru/...) up front — a business decision, not an engineering one — so it's left for a
/// later, separate addition rather than guessed at now.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum NotificationChannelKind {
    Email,
    Telegram,
    Webhook,
}

impl NotificationChannelKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            NotificationChannelKind::Email => "email",
            NotificationChannelKind::Telegram => "telegram",
            NotificationChannelKind::Webhook => "webhook",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "email" => NotificationChannelKind::Email,
            "telegram" => NotificationChannelKind::Telegram,
            "webhook" => NotificationChannelKind::Webhook,
            _ => return None,
        })
    }
}

/// One user's own contact point — "каналы нотификации за юзерами" (direct user request,
/// elaborating `docs/Roadmap.md`'s original one-liner): each user configures their own
/// email/Telegram/webhook, not one global webhook for the whole system. Self-service
/// resource (`discovery-web`'s `/api/notifications/channels` requires no RBAC domain grant
/// beyond being logged in, same tier as `PUT /api/auth/password`) — an admin can also
/// manage another user's channels for support purposes via `/api/users/:id/
/// notification-channels`, same relationship `AuthStore::set_password` already has between
/// self-service and admin-on-behalf-of.
///
/// `target`'s meaning depends on `kind`: an email address, a Telegram numeric `chat_id` (as
/// a string — Telegram's own API takes it that way), or a webhook URL. A single type
/// covering all three (rather than one struct per kind) mirrors `discovery_dsl::MetricSpec`'s
/// "form distinguishes the variant" convention loosely, but here the tag is explicit
/// (`kind`) rather than inferred from shape, since there's no natural structural difference
/// between "a string that happens to be an email" and "a string that happens to be a URL".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NotificationChannel {
    pub id: Uuid,
    pub user_id: Uuid,
    pub kind: NotificationChannelKind,
    pub target: String,
    /// Webhook-only: an optional signing secret. When set, `discovery-notify`'s webhook
    /// sender adds an `X-Discovery-Signature` header (`hex(HMAC-SHA256(secret, raw_body))`)
    /// so the receiving endpoint can verify the request genuinely came from this system —
    /// the same convention GitHub/Stripe webhooks use. Meaningless for `Email`/`Telegram`
    /// (left `None` there) — not split into a separate `Option<WebhookConfig>` field
    /// because that's the only kind-specific field this type has; not worth a third shape
    /// for one optional string. Plaintext in memory; `discovery-config-store`'s
    /// implementation encrypts it at rest via `crate::secret::encrypt_secret`/
    /// `decrypt_secret` before/after touching the DB, same boundary-only-encryption
    /// convention as `SnmpV3AuthCreds`/`SshAuth`.
    #[serde(default)]
    pub secret: Option<String>,
    /// Independent kill-switch — a user can pause a channel without losing its
    /// configuration (e.g. muting Telegram while on vacation without re-entering the
    /// chat_id later). `false` means the dispatcher never resolves this channel as a
    /// recipient, regardless of which [`crate::NotificationRule`]s (matrix rows) target its
    /// owner.
    pub enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Which alert transition caused a notification. `Repeated` is explicit opt-in through a
/// notification rule's recurrence policy; ordinary `StillActive` observations remain silent.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum NotificationTrigger {
    Activated,
    Cleared,
    Repeated,
    Escalated,
    Deescalated,
}

impl NotificationTrigger {
    pub fn as_str(&self) -> &'static str {
        match self {
            NotificationTrigger::Activated => "activated",
            NotificationTrigger::Cleared => "cleared",
            NotificationTrigger::Repeated => "repeated",
            NotificationTrigger::Escalated => "escalated",
            NotificationTrigger::Deescalated => "deescalated",
        }
    }
}

/// System-wide delivery credentials — one SMTP relay, one Telegram bot, shared by every
/// user's [`NotificationChannel`] of the matching kind. Deliberately **not** per-channel:
/// unlike a webhook URL (which is inherently per-recipient — there is no "the one webhook
/// server"), an SMTP relay and a Telegram bot are shared infrastructure an operator
/// provisions once, the same way `docs/CLAUDE.md`'s AggreGate reference architecture has
/// one Jira instance's credentials rather than per-user Jira logins. Stored as a
/// `discovery_core::SettingsStore` category (fourth one, after `PollIntervalsConfig`/
/// `AlertRetentionConfig`/`PingConfig`) — see that trait's docs for why a new category is a
/// new typed method over the existing generic `settings` table, not a new migration/table.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NotificationProviderConfig {
    #[serde(default)]
    pub smtp_host: Option<String>,
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    #[serde(default)]
    pub smtp_username: Option<String>,
    /// Encrypted at rest by `discovery-config-store`'s `SettingsStore` implementation via
    /// `crate::secret::encrypt_secret`/`decrypt_secret`, same as
    /// [`NotificationChannel::secret`] — plaintext here in memory only.
    #[serde(default)]
    pub smtp_password: Option<String>,
    #[serde(default)]
    pub smtp_from_address: Option<String>,
    /// Encrypted at rest, same as `smtp_password` — a bot token is a bearer credential for
    /// the whole bot, not a "not really a secret" value the way an SNMP v1/v2c community
    /// string is.
    #[serde(default)]
    pub telegram_bot_token: Option<String>,
}

fn default_smtp_port() -> u16 {
    587
}

/// `#[derive(Default)]` would give `smtp_port: 0` (per-field `Default::default()`, blind to
/// the `#[serde(default = "...")]` attribute above, which only governs deserialization) —
/// implemented by hand instead so `NotificationProviderConfig::default()` (the
/// `SettingsStore::notification_provider()` convenience fallback for "nothing configured
/// yet") lands on the same 587 a freshly-deserialized empty JSON object would.
impl Default for NotificationProviderConfig {
    fn default() -> Self {
        Self {
            smtp_host: None,
            smtp_port: default_smtp_port(),
            smtp_username: None,
            smtp_password: None,
            smtp_from_address: None,
            telegram_bot_token: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_kind_str_roundtrip() {
        for kind in [
            NotificationChannelKind::Email,
            NotificationChannelKind::Telegram,
            NotificationChannelKind::Webhook,
        ] {
            assert_eq!(NotificationChannelKind::from_str(kind.as_str()), Some(kind));
        }
    }

    #[test]
    fn channel_kind_from_str_rejects_unknown() {
        assert_eq!(NotificationChannelKind::from_str("sms"), None);
    }

    #[test]
    fn provider_config_default_has_standard_smtp_submission_port() {
        assert_eq!(NotificationProviderConfig::default().smtp_port, 587);
    }

    #[test]
    fn channel_missing_secret_field_deserializes_to_none() {
        let json = r#"{"id":"5b1a6b8e-6b7a-4f7a-9f0a-000000000000","user_id":"5b1a6b8e-6b7a-4f7a-9f0a-000000000001","kind":"email","target":"a@b.com","enabled":true,"created_at":"2026-09-10T00:00:00Z"}"#;
        let channel: NotificationChannel = serde_json::from_str(json).unwrap();
        assert_eq!(channel.secret, None);
    }
}
