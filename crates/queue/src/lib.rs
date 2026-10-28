mod sea_orm_store;
mod store;
mod worker;

pub use sea_orm_store::*;
pub use store::*;
pub use worker::*;

pub async fn enqueue_alert_action(
    queue: &dyn JobQueueStore,
    alert: &discovery_core::Alert,
    action: discovery_core::payload::OperatorAction,
    username: &str,
    phase: discovery_core::AlertLifecycle,
) -> anyhow::Result<i64> {
    let payload = discovery_core::payload::OperatorActionPayload {
        alert_id: Some(alert.id),
        device_id: alert.device_id,
        action,
        username: username.into(),
    };
    let dedupe_key = format!("alert:{}:{phase:?}:{action:?}", alert.id);
    queue
        .enqueue(
            discovery_core::QueueKind::OperatorAction,
            serde_json::to_value(payload)?,
            Some(&dedupe_key),
        )
        .await
}
