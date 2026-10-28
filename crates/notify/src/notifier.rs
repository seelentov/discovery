use async_trait::async_trait;
use discovery_core::{Alert, NotificationChannel, NotificationProviderConfig, NotificationTrigger};

/// Abstraction over "deliver one notification to one channel" — mirrors
/// `discovery_ping::Pinger`/`discovery_servicecheck::ServiceChecker`'s real/fake split
/// exactly, so `discovery_agent`'s `NotificationDispatchHandler` can run against
/// [`crate::FakeNotifier`] in tests without any real network/SMTP traffic, same as every
/// other pipeline stage in this project.
///
/// One method covering all three channel kinds — same "protocol dispatched inside the
/// implementation, not a separate trait per protocol" shape `ServiceChecker::check` already
/// uses for TCP/HTTP(S)/SSH. `provider` is passed on every call rather than baked into the
/// `Notifier` at construction time: unlike `channel` (identified by
/// `NotificationDispatchHandler`'s job payload), the provider config can change between
/// calls (an operator editing SMTP/Telegram settings) and should apply on the very next
/// delivery attempt, not require restarting whatever holds the `Notifier`.
#[async_trait]
pub trait Notifier: Send + Sync {
    async fn send(
        &self,
        channel: &NotificationChannel,
        provider: &NotificationProviderConfig,
        alert: &Alert,
        trigger: NotificationTrigger,
    ) -> anyhow::Result<()>;
}
