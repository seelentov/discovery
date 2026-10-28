use async_trait::async_trait;
use discovery_core::{Alert, NotificationChannel, NotificationProviderConfig, NotificationTrigger};
use std::collections::HashSet;
use std::sync::RwLock;
use uuid::Uuid;

use crate::Notifier;

/// One recorded call to [`FakeNotifier::send`] — every call is logged here regardless of
/// whether it then succeeded or (simulated-)failed, so a test can assert "channel A was
/// attempted exactly once" even across a retry of a *different* channel's job — the
/// scenario `docs/Architecture/Notifications.md`'s "no duplicate resend on partial retry"
/// guarantee depends on (see `discovery_agent::handlers::AlertEvalHandler::dispatch_notifications`'s
/// docs for why dispatch is one job per channel in the first place).
#[derive(Debug, Clone, PartialEq)]
pub struct NotifyAttempt {
    pub channel_id: Uuid,
    pub alert_id: Uuid,
    pub message: String,
    pub state: discovery_core::AlertState,
    pub trigger: NotificationTrigger,
}

/// In-memory notifier for tests — mirrors `discovery_servicecheck::FakeServiceChecker`'s
/// "seed responses / configure failures, then run the pipeline against it" shape. Unlike
/// `FakeServiceChecker`'s un-seeded-defaults-to-failure convention, an un-configured
/// channel here defaults to **success** — there's no meaningful "unseeded" case for a
/// notification send the way there is for "is this host up" (every channel this fake ever
/// sees is one `AlertEvalHandler` actually resolved as a match, not an arbitrary probe
/// target), so failure has to be opted into explicitly via [`Self::fail_channel`].
#[derive(Default)]
pub struct FakeNotifier {
    attempts: RwLock<Vec<NotifyAttempt>>,
    failing_channels: RwLock<HashSet<Uuid>>,
}

impl FakeNotifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every subsequent [`Notifier::send`] call for `channel_id` returns `Err` — for
    /// exercising `NotificationDispatchHandler`'s error propagation (and, one level up, the
    /// queue's own retry/backoff picking it up) without any real network failure.
    pub fn fail_channel(&self, channel_id: Uuid) {
        self.failing_channels.write().unwrap().insert(channel_id);
    }

    /// Stop simulating failure for `channel_id` — e.g. to model "the endpoint came back up"
    /// between a job's retry attempts.
    pub fn recover_channel(&self, channel_id: Uuid) {
        self.failing_channels.write().unwrap().remove(&channel_id);
    }

    /// Snapshot of every attempt so far, in call order.
    pub fn attempts(&self) -> Vec<NotifyAttempt> {
        self.attempts.read().unwrap().clone()
    }

    pub fn attempt_count_for(&self, channel_id: Uuid) -> usize {
        self.attempts
            .read()
            .unwrap()
            .iter()
            .filter(|a| a.channel_id == channel_id)
            .count()
    }
}

#[async_trait]
impl Notifier for FakeNotifier {
    async fn send(
        &self,
        channel: &NotificationChannel,
        _provider: &NotificationProviderConfig,
        alert: &Alert,
        trigger: NotificationTrigger,
    ) -> anyhow::Result<()> {
        self.attempts.write().unwrap().push(NotifyAttempt {
            channel_id: channel.id,
            alert_id: alert.id,
            message: alert.message.clone(),
            state: alert.state.clone(),
            trigger,
        });
        if self.failing_channels.read().unwrap().contains(&channel.id) {
            anyhow::bail!("simulated delivery failure for channel {}", channel.id);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use discovery_core::{AlertLevel, AlertState, NotificationChannelKind};

    fn channel(id: Uuid) -> NotificationChannel {
        NotificationChannel {
            id,
            user_id: Uuid::new_v4(),
            kind: NotificationChannelKind::Webhook,
            target: "https://example.com".to_string(),
            secret: None,
            enabled: true,
            created_at: chrono::Utc::now(),
        }
    }

    fn alert() -> Alert {
        Alert {
            details: Default::default(),
            id: Uuid::new_v4(),
            device_id: Uuid::new_v4(),
            device_ip: "10.0.0.5".to_string(),
            name: "test".to_string(),
            row_key: None,
            level: AlertLevel::Critical,
            message: "boom".to_string(),
            state: AlertState::Active,
            facts: None,
            first_seen: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            cleared_at: None,
            closed_by: None,
            acknowledged_by: None,
            acknowledged_at: None,
            snoozed_until: None,
            snoozed_by: None,
            auto_clear_reason: None,
            repeat_count: 0,
            escalation_level: 0,
            repeated_at: None,
            escalation_reason: None,
            flapping: false,
            suppression_reason: None,
            comment_count: 0,
            suppressed_by_alert_id: None,
            reopened_from_alert_id: None,
        }
    }

    #[tokio::test]
    async fn unconfigured_channel_succeeds_and_is_recorded() {
        let notifier = FakeNotifier::new();
        let c = channel(Uuid::new_v4());
        notifier
            .send(
                &c,
                &NotificationProviderConfig::default(),
                &alert(),
                NotificationTrigger::Activated,
            )
            .await
            .unwrap();
        assert_eq!(notifier.attempt_count_for(c.id), 1);
    }

    #[tokio::test]
    async fn failing_channel_returns_err_but_still_records_the_attempt() {
        let notifier = FakeNotifier::new();
        let c = channel(Uuid::new_v4());
        notifier.fail_channel(c.id);
        let result = notifier
            .send(
                &c,
                &NotificationProviderConfig::default(),
                &alert(),
                NotificationTrigger::Activated,
            )
            .await;
        assert!(result.is_err());
        assert_eq!(
            notifier.attempt_count_for(c.id),
            1,
            "a failed attempt is still an attempt"
        );
    }

    #[tokio::test]
    async fn recover_channel_lets_a_later_attempt_succeed() {
        let notifier = FakeNotifier::new();
        let c = channel(Uuid::new_v4());
        notifier.fail_channel(c.id);
        assert!(notifier
            .send(
                &c,
                &NotificationProviderConfig::default(),
                &alert(),
                NotificationTrigger::Activated
            )
            .await
            .is_err());
        notifier.recover_channel(c.id);
        assert!(notifier
            .send(
                &c,
                &NotificationProviderConfig::default(),
                &alert(),
                NotificationTrigger::Activated
            )
            .await
            .is_ok());
        assert_eq!(notifier.attempt_count_for(c.id), 2);
    }

    #[tokio::test]
    async fn other_channels_are_unaffected_by_one_channel_failing() {
        let notifier = FakeNotifier::new();
        let failing = channel(Uuid::new_v4());
        let healthy = channel(Uuid::new_v4());
        notifier.fail_channel(failing.id);
        assert!(notifier
            .send(
                &failing,
                &NotificationProviderConfig::default(),
                &alert(),
                NotificationTrigger::Activated
            )
            .await
            .is_err());
        assert!(notifier
            .send(
                &healthy,
                &NotificationProviderConfig::default(),
                &alert(),
                NotificationTrigger::Activated
            )
            .await
            .is_ok());
    }
}
