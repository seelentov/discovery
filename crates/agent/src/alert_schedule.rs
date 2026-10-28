use discovery_core::{payload::AlertEvalPayload, AlertStateTracker, QueueKind};
use discovery_queue::JobQueueStore;
use std::sync::Arc;

pub async fn run_alert_schedule_loop(
    alerts: Arc<AlertStateTracker>,
    queue: Arc<dyn JobQueueStore>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        interval.tick().await;
        for id in alerts.due_devices(chrono::Utc::now()) {
            let payload = serde_json::to_value(AlertEvalPayload {
                device_id: id,
                event: None,
            })
            .expect("serializable evaluation payload");
            if let Err(error) = queue
                .enqueue(QueueKind::AlertEval, payload, Some(&id.to_string()))
                .await
            {
                tracing::warn!(%error, device_id = %id, "failed to schedule alert deadline");
            }
        }
    }
}
