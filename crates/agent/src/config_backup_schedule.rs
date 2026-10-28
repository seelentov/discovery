use std::sync::Arc;
use std::time::Duration;

use chrono::{Local, NaiveDate, Timelike};
use discovery_config_store::SettingsStore;
use discovery_core::payload::{OperatorAction, OperatorActionPayload};
use discovery_core::{ConfigBackupSettings, JobState, QueueKind, Schedule};
use discovery_devices::DeviceStore;
use discovery_queue::{JobListQuery, JobQueueStore};
use tracing::warn;

/// Runs opt-in scheduled SSH backups and removes only expired backup records. Manual
/// requests share the same queue dedupe key, so a scheduled tick cannot duplicate one.
pub async fn run_config_backup_schedule_loop(
    devices: Arc<dyn DeviceStore>,
    queue: Arc<dyn JobQueueStore>,
    settings: Arc<dyn SettingsStore>,
) {
    let mut last_periodic: Option<tokio::time::Instant> = None;
    let mut last_calendar: Option<NaiveDate> = None;
    let mut last_cleanup: Option<tokio::time::Instant> = None;
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let config = settings.config_backup().await;
        let now = tokio::time::Instant::now();
        if last_cleanup.map_or(true, |last| now.duration_since(last).as_secs() >= 300) {
            prune_expired_backups(queue.as_ref(), config.retention_secs).await;
            last_cleanup = Some(now);
        }
        if !config.enabled {
            continue;
        }
        let due = schedule_due(&config, &mut last_periodic, &mut last_calendar);
        if !due {
            continue;
        }
        let Ok(known_devices) = devices.all().await else {
            continue;
        };
        for device in known_devices
            .into_iter()
            .filter(|d| d.enabled && d.profile.is_some() && d.ssh_credentials.is_some())
        {
            let payload = serde_json::json!(OperatorActionPayload {
                alert_id: None,
                device_id: device.id,
                action: OperatorAction::Backup,
                username: "scheduler".to_string(),
            });
            let _ = queue
                .enqueue(
                    QueueKind::OperatorAction,
                    payload,
                    Some(&device.id.to_string()),
                )
                .await;
        }
    }
}

async fn prune_expired_backups(queue: &dyn JobQueueStore, retention_secs: u64) {
    let cutoff =
        chrono::Utc::now() - chrono::Duration::seconds(retention_secs.min(i64::MAX as u64) as i64);
    for state in [JobState::Done, JobState::Failed] {
        let page = match queue
            .list_jobs(
                QueueKind::OperatorAction,
                &JobListQuery {
                    state: Some(state),
                    limit: 500,
                    ..Default::default()
                },
            )
            .await
        {
            Ok(page) => page,
            Err(error) => {
                warn!(%error, "configuration backup retention sweep failed");
                continue;
            }
        };
        for job in page.jobs.into_iter().filter(|job| job.updated_at < cutoff) {
            let Ok(payload) = serde_json::from_value::<OperatorActionPayload>(job.payload.clone())
            else {
                continue;
            };
            if payload.action == OperatorAction::Backup {
                let _ = queue.delete_job(job.id).await;
            }
        }
    }
}

fn schedule_due(
    config: &ConfigBackupSettings,
    last_periodic: &mut Option<tokio::time::Instant>,
    last_calendar: &mut Option<NaiveDate>,
) -> bool {
    let Some(schedule) = &config.schedule else {
        return false;
    };
    match schedule {
        Schedule::Periodic { interval_secs } => {
            let now = tokio::time::Instant::now();
            let due = last_periodic.map_or(true, |last| {
                now.duration_since(last).as_secs() >= *interval_secs
            });
            if due {
                *last_periodic = Some(now);
            }
            due
        }
        Schedule::Calendar { .. } => {
            let now = Local::now();
            let date = now.date_naive();
            let due = *last_calendar != Some(date)
                && schedule.matches_calendar(date, now.hour(), now.minute());
            if due {
                *last_calendar = Some(date);
            }
            due
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disabled_or_missing_schedule_never_fires() {
        let config = ConfigBackupSettings::default();
        let mut periodic = None;
        let mut calendar = None;
        assert!(!schedule_due(&config, &mut periodic, &mut calendar));
    }
}
