use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::Serialize;

use crate::QueueKind;

/// Live "what is running where right now" snapshot — the data behind the dashboard's
/// "Воркеры" view. Deliberately ephemeral (in-memory only, not persisted): it answers
/// "what is happening right now", not "what happened historically", so losing it on
/// restart is fine — the workers just repopulate it as soon as they start claiming jobs.
#[derive(Debug, Clone, Serialize)]
pub struct WorkerActivity {
    pub worker_id: String,
    pub queue: QueueKind,
    pub current_job_summary: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
}

#[derive(Default)]
pub struct WorkerRegistry {
    workers: DashMap<String, WorkerActivity>,
}

impl WorkerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_idle(&self, worker_id: &str, queue: QueueKind) {
        self.workers.insert(
            worker_id.to_string(),
            WorkerActivity {
                worker_id: worker_id.to_string(),
                queue,
                current_job_summary: None,
                started_at: None,
            },
        );
    }

    pub fn set_busy(&self, worker_id: &str, queue: QueueKind, job_summary: String) {
        self.workers.insert(
            worker_id.to_string(),
            WorkerActivity {
                worker_id: worker_id.to_string(),
                queue,
                current_job_summary: Some(job_summary),
                started_at: Some(Utc::now()),
            },
        );
    }

    pub fn snapshot(&self) -> Vec<WorkerActivity> {
        self.workers.iter().map(|e| e.value().clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn busy_then_idle_transitions_are_visible_in_snapshot() {
        let registry = WorkerRegistry::new();
        registry.set_idle("snmp_poll-0", QueueKind::SnmpPoll);
        registry.set_busy("snmp_poll-0", QueueKind::SnmpPoll, "job#42".to_string());

        let snap = registry.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].current_job_summary.as_deref(), Some("job#42"));

        registry.set_idle("snmp_poll-0", QueueKind::SnmpPoll);
        let snap2 = registry.snapshot();
        assert_eq!(snap2[0].current_job_summary, None);
    }
}
