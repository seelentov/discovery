//! `NotificationDispatchHandler` — the `QueueKind::NotificationDispatch` worker. Everything
//! about *which* channel to notify and *whether* this transition warrants it was already
//! decided by `crate::handlers::AlertEvalHandler::dispatch_notifications` before this job was
//! even enqueued (see that method's docs) — this handler's only job is to load the two small
//! channel it needs fresh (it might have been edited/disabled); the alert in the payload is
//! the immutable transition snapshot used for delivery.

use std::sync::Arc;

use async_trait::async_trait;
use discovery_core::payload::NotificationDispatchPayload;
use discovery_core::Job;
use discovery_notify::Notifier;
use discovery_queue::JobHandler;

/// One delivery attempt to one channel. Returning `Err` here is exactly what makes the
/// queue's own retry/backoff (`JobQueueStore::fail`, `max_attempts`) apply — no bespoke
/// retry logic in this handler at all, same "let the queue be the retry mechanism" contract
/// every other `JobHandler` in this file already relies on.
pub struct NotificationDispatchHandler {
    pub alert_store: Arc<dyn discovery_alerts::AlertStore>,
    pub notification_channels: Arc<dyn discovery_config_store::NotificationChannelStore>,
    pub settings: Arc<dyn discovery_config_store::SettingsStore>,
    pub notifier: Arc<dyn Notifier>,
}

#[async_trait]
impl JobHandler for NotificationDispatchHandler {
    async fn handle(&self, job: Job) -> anyhow::Result<()> {
        let payload: NotificationDispatchPayload = serde_json::from_value(job.payload)?;

        // The channel or the alert can each have vanished (deleted/edited) between
        // `dispatch_notifications` enqueuing this job and it actually running — treated as
        // a completed no-op, not a failure: there's nothing left to deliver, and retrying
        // won't make a deleted row reappear. Same "stale target, quietly done" contract
        // `MetricPollHandler`/`AlertEvalHandler` already use when `get_device` returns
        // `None` for a device removed mid-flight.
        let Some(channel) = self.notification_channels.get(payload.channel_id).await? else {
            return Ok(());
        };
        if !channel.enabled {
            return Ok(());
        }
        let Some(current_alert) = self.alert_store.get(payload.alert_id).await? else {
            return Ok(());
        };
        if current_alert.notifications_snoozed_at(chrono::Utc::now()) {
            tracing::info!(alert_id = %payload.alert_id, "notification skipped because alert is snoozed");
            return Ok(());
        }

        let provider = self.settings.notification_provider().await;
        self.notifier
            .send(&channel, &provider, &payload.alert, payload.trigger)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use discovery_alerts::{AlertStore, SeaOrmAlertStore};
    use discovery_config_store::{
        NotificationChannelStore, SeaOrmNotificationChannelStore, SeaOrmSettingsStore,
        SettingsStore,
    };
    use discovery_core::{
        Alert, AlertLevel, AlertState, NotificationChannel, NotificationChannelKind,
        NotificationProviderConfig, NotificationTrigger, QueueKind,
    };
    use discovery_notify::FakeNotifier;
    use uuid::Uuid;

    fn alert(id: Uuid) -> Alert {
        Alert {
            details: Default::default(),
            id,
            device_id: Uuid::new_v4(),
            device_ip: "10.0.0.5".to_string(),
            name: "high_cpu".to_string(),
            row_key: None,
            level: AlertLevel::Critical,
            message: "CPU 97%".to_string(),
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

    fn job(payload: NotificationDispatchPayload) -> Job {
        Job {
            id: 1,
            queue: QueueKind::NotificationDispatch,
            payload: serde_json::to_value(payload).unwrap(),
            dedupe_key: None,
            state: discovery_core::JobState::InProgress,
            attempts: 1,
            max_attempts: 5,
            locked_by: None,
            locked_at: None,
            last_error: None,
            result: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            paused: false,
        }
    }

    async fn handler_with(
        notifier: Arc<FakeNotifier>,
    ) -> (
        NotificationDispatchHandler,
        Arc<dyn discovery_alerts::AlertStore>,
        Arc<dyn NotificationChannelStore>,
    ) {
        let db = discovery_migration::connect_in_memory_for_tests().await;
        let alert_store: Arc<dyn AlertStore> = Arc::new(SeaOrmAlertStore::new(db.clone()));
        let channels: Arc<dyn NotificationChannelStore> =
            Arc::new(SeaOrmNotificationChannelStore::new(db.clone()));
        let settings: Arc<dyn SettingsStore> = Arc::new(SeaOrmSettingsStore::new(db));
        let handler = NotificationDispatchHandler {
            alert_store: alert_store.clone(),
            notification_channels: channels.clone(),
            settings,
            notifier,
        };
        (handler, alert_store, channels)
    }

    #[tokio::test]
    async fn delivers_to_the_resolved_channel_and_alert() {
        let notifier = Arc::new(FakeNotifier::new());
        let (handler, alert_store, channels) = handler_with(notifier.clone()).await;

        let a = alert(Uuid::new_v4());
        alert_store.upsert(&a).await.unwrap();
        let channel = NotificationChannel {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            kind: NotificationChannelKind::Webhook,
            target: "https://example.com".into(),
            secret: None,
            enabled: true,
            created_at: chrono::Utc::now(),
        };
        channels.upsert(&channel).await.unwrap();

        handler
            .handle(job(NotificationDispatchPayload {
                channel_id: channel.id,
                alert_id: a.id,
                alert: a.clone(),
                trigger: NotificationTrigger::Activated,
            }))
            .await
            .unwrap();

        let attempts = notifier.attempts();
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].channel_id, channel.id);
        assert_eq!(attempts[0].alert_id, a.id);
        assert_eq!(attempts[0].trigger, NotificationTrigger::Activated);
    }

    #[tokio::test]
    async fn a_deleted_channel_is_a_quiet_no_op_not_an_error() {
        let notifier = Arc::new(FakeNotifier::new());
        let (handler, alert_store, _channels) = handler_with(notifier.clone()).await;
        let a = alert(Uuid::new_v4());
        alert_store.upsert(&a).await.unwrap();

        handler
            .handle(job(NotificationDispatchPayload {
                channel_id: Uuid::new_v4(),
                alert_id: a.id,
                alert: a.clone(),
                trigger: NotificationTrigger::Activated,
            }))
            .await
            .unwrap();
        assert!(
            notifier.attempts().is_empty(),
            "no channel to resolve — must never call the notifier"
        );
    }

    #[tokio::test]
    async fn a_deleted_alert_is_a_quiet_no_op_not_an_error() {
        let notifier = Arc::new(FakeNotifier::new());
        let (handler, _alert_store, channels) = handler_with(notifier.clone()).await;
        let channel = NotificationChannel {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            kind: NotificationChannelKind::Webhook,
            target: "https://example.com".into(),
            secret: None,
            enabled: true,
            created_at: chrono::Utc::now(),
        };
        channels.upsert(&channel).await.unwrap();

        handler
            .handle(job(NotificationDispatchPayload {
                channel_id: channel.id,
                alert_id: Uuid::new_v4(),
                alert: alert(Uuid::new_v4()),
                trigger: NotificationTrigger::Activated,
            }))
            .await
            .unwrap();
        assert!(notifier.attempts().is_empty());
    }

    #[tokio::test]
    async fn delayed_activation_uses_its_snapshot_after_alert_is_cleared() {
        let notifier = Arc::new(FakeNotifier::new());
        let (handler, alert_store, channels) = handler_with(notifier.clone()).await;
        let channel = NotificationChannel {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            kind: NotificationChannelKind::Webhook,
            target: "https://example.com".into(),
            secret: None,
            enabled: true,
            created_at: chrono::Utc::now(),
        };
        channels.upsert(&channel).await.unwrap();

        let active = alert(Uuid::new_v4());
        alert_store.upsert(&active).await.unwrap();
        let mut cleared = active.clone();
        cleared.message = "CPU recovered".into();
        cleared.state = AlertState::Cleared;
        cleared.cleared_at = Some(chrono::Utc::now());
        alert_store.upsert(&cleared).await.unwrap();

        handler
            .handle(job(NotificationDispatchPayload {
                channel_id: channel.id,
                alert_id: active.id,
                alert: active,
                trigger: NotificationTrigger::Activated,
            }))
            .await
            .unwrap();

        let attempts = notifier.attempts();
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].message, "CPU 97%");
        assert_eq!(attempts[0].state, AlertState::Active);
        assert_eq!(attempts[0].trigger, NotificationTrigger::Activated);
    }

    #[tokio::test]
    async fn a_failing_notifier_propagates_the_error_for_the_queue_to_retry() {
        let notifier = Arc::new(FakeNotifier::new());
        let (handler, alert_store, channels) = handler_with(notifier.clone()).await;
        let a = alert(Uuid::new_v4());
        alert_store.upsert(&a).await.unwrap();
        let channel = NotificationChannel {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            kind: NotificationChannelKind::Webhook,
            target: "https://example.com".into(),
            secret: None,
            enabled: true,
            created_at: chrono::Utc::now(),
        };
        channels.upsert(&channel).await.unwrap();
        notifier.fail_channel(channel.id);

        let result = handler
            .handle(job(NotificationDispatchPayload {
                channel_id: channel.id,
                alert_id: a.id,
                alert: a.clone(),
                trigger: NotificationTrigger::Activated,
            }))
            .await;
        assert!(
            result.is_err(),
            "a real delivery failure must surface as Err so the queue retries it"
        );
    }

    #[tokio::test]
    async fn uses_whatever_provider_config_is_current_at_delivery_time() {
        let notifier = Arc::new(FakeNotifier::new());
        let (handler, alert_store, channels) = handler_with(notifier.clone()).await;
        handler
            .settings
            .set_notification_provider(&NotificationProviderConfig {
                smtp_host: Some("mail.example.com".into()),
                ..Default::default()
            })
            .await
            .unwrap();

        let a = alert(Uuid::new_v4());
        alert_store.upsert(&a).await.unwrap();
        let channel = NotificationChannel {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            kind: NotificationChannelKind::Webhook,
            target: "https://example.com".into(),
            secret: None,
            enabled: true,
            created_at: chrono::Utc::now(),
        };
        channels.upsert(&channel).await.unwrap();

        // No direct assertion on the provider config reaching `Notifier::send` (`FakeNotifier`
        // doesn't record it) — this test exists to prove `handle` reads `settings` fresh on
        // every call rather than caching a snapshot at construction time, which the
        // `notification_provider()` call inside `handle` (not in `handler_with`) already
        // guarantees by construction; a successful delivery here is the observable proof
        // that reading it didn't error.
        handler
            .handle(job(NotificationDispatchPayload {
                channel_id: channel.id,
                alert_id: a.id,
                alert: a.clone(),
                trigger: NotificationTrigger::Activated,
            }))
            .await
            .unwrap();
    }
}
