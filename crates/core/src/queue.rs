use serde::{Deserialize, Serialize};

/// One pipeline stage = one queue = one independently-configurable worker pool. This is
/// the "ограничение на кол-во одновременных потоков для каждого процесса" requirement:
/// each variant gets its own concurrency setting (see `discovery-agent`'s config) so a
/// slow SNMP-heavy stage can't starve a cheap one and vice versa.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum QueueKind {
    /// Candidate IP arrives (from a subnet sweep or seed list) — cheap reachability check.
    Discovery,
    /// Recurring SNMP identity probe (sysObjectID/sysDescr/sysName + whatever extra OIDs
    /// the dedup config declares). Recurring, not one-shot: a device's identity can
    /// change over time (firmware swap, RMA, re-IP) and that has to get picked up.
    SnmpPoll,
    /// Resolve device identity and (re)match a profile against the fresh facts. Identity
    /// resolution is per-IP only for now (2026-08-16, direct user request — the custom
    /// dedup-key fingerprinting that used to live here, `discovery-dsl::dedup`, is pulled
    /// out entirely pending a redesign; see `discovery_devices::DeviceStore::resolve`'s
    /// docs). The name stays `Dedup` since it's still the same pipeline stage, not a
    /// rename pending that redesign.
    Dedup,
    /// Compare the freshly-matched profile against what's on record; reapply config and
    /// restart metric polling only if it actually changed.
    ProfileApply,
    /// Recurring metric collection per the matched profile.
    MetricPoll,
    /// Evaluate the matched profile's alert rules against the latest metrics.
    AlertEval,
    /// Recurring ping+SNMP reachability check (added 2026-08-16/17, direct user request —
    /// live device status separate from profile metrics). Independent of profile matching
    /// — its chain starts right after `Dedup::resolve()`, so even a device that never
    /// matches any profile still gets checked. See `discovery_core::Device`'s
    /// `ping_ok`/`snmp_ok` docs.
    ReachabilityPoll,
    /// Recurring L4/L7 service checks (TCP-connect / HTTP(S) status+body / SSH banner —
    /// added 2026-09-07, third protocol collection sibling of `SnmpPoll`/`ReachabilityPoll`,
    /// see `discovery_dsl::ServiceChecksSection`'s docs). Unlike `ReachabilityPoll`, this
    /// **is** profile-scoped — which checks (if any) to run comes from the matched
    /// profile's `service_checks.checks`, so its chain starts/restarts alongside
    /// `MetricPoll`'s (`ProfileApplyHandler`, same `generation` guard).
    ServiceCheckPoll,
    /// One notification delivery attempt to **one** channel — added 2026-09-10 alongside
    /// notification channels/matrix (`discovery_core::NotificationChannel`/
    /// `discovery_config_store::NotificationRule`). Deliberately one job per *channel*, not
    /// one job per alert-transition covering every matched recipient's channels in a loop:
    /// if a job covered several channels and one delivery failed, retrying the whole job
    /// (`JobQueueStore`'s `max_attempts` backoff) would re-send to the channels that already
    /// succeeded — silent duplicate notifications, not just wasted work. One job per channel
    /// makes each delivery independently retriable, no different from any other unit of
    /// work this queue already models. Enqueued by `AlertEvalHandler::dispatch_notifications`
    /// (`discovery-agent`), handled by `NotificationDispatchHandler`.
    NotificationDispatch,
    /// Recompute one device's `my_key`/`claimed_neighbors` under every enabled
    /// `discovery_config_store::TopologyRule` — added 2026-09-16 alongside the
    /// rule-based topology rebuild (`discovery_core::Domain::Topology`'s docs). Enqueued
    /// by `MetricPollHandler` right after `record_metric_polls`, exactly the same hook
    /// point `AlertEval` already uses, whenever this tick freshly polled (successfully) a
    /// metric referenced by at least one enabled rule's `my_key_expression`/
    /// `claimed_neighbors_expression` (`discovery_dsl::topology::referenced_metrics`).
    /// Deliberately reactive, not on a separate timer — a device's topology signal only
    /// ever needs recomputing when its own relevant metric actually refreshed, and
    /// recomputing it never requires touching any other device (see
    /// `discovery_topology::TopologyStore::neighbors_of`'s docs on why the other side of
    /// an edge is resolved at *read* time instead).
    TopologyRecompute,
    /// Explicit, bounded actions requested by an authenticated operator.
    OperatorAction,
}

impl QueueKind {
    pub const ALL: [QueueKind; 11] = [
        QueueKind::Discovery,
        QueueKind::SnmpPoll,
        QueueKind::Dedup,
        QueueKind::ProfileApply,
        QueueKind::MetricPoll,
        QueueKind::AlertEval,
        QueueKind::ReachabilityPoll,
        QueueKind::ServiceCheckPoll,
        QueueKind::NotificationDispatch,
        QueueKind::TopologyRecompute,
        QueueKind::OperatorAction,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            QueueKind::Discovery => "discovery",
            QueueKind::SnmpPoll => "snmp_poll",
            QueueKind::Dedup => "dedup",
            QueueKind::ProfileApply => "profile_apply",
            QueueKind::MetricPoll => "metric_poll",
            QueueKind::AlertEval => "alert_eval",
            QueueKind::ReachabilityPoll => "reachability_poll",
            QueueKind::ServiceCheckPoll => "service_check_poll",
            QueueKind::NotificationDispatch => "notification_dispatch",
            QueueKind::TopologyRecompute => "topology_recompute",
            QueueKind::OperatorAction => "operator_action",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "discovery" => QueueKind::Discovery,
            "snmp_poll" => QueueKind::SnmpPoll,
            "dedup" => QueueKind::Dedup,
            "profile_apply" => QueueKind::ProfileApply,
            "metric_poll" => QueueKind::MetricPoll,
            "alert_eval" => QueueKind::AlertEval,
            "reachability_poll" => QueueKind::ReachabilityPoll,
            "service_check_poll" => QueueKind::ServiceCheckPoll,
            "notification_dispatch" => QueueKind::NotificationDispatch,
            "topology_recompute" => QueueKind::TopologyRecompute,
            "operator_action" => QueueKind::OperatorAction,
            _ => return None,
        })
    }
}

/// Recurring pipeline jobs are deleted on success. Only explicit operator actions
/// retain terminal states so an operator can inspect the outcome or cancellation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum JobState {
    Pending,
    InProgress,
    Failed,
    /// Retained only for the low-volume operator-action queue so its result can be read.
    Done,
    /// Operator cancelled a job before any worker claimed it.
    Cancelled,
}

/// A unit of work sitting in a queue. `payload` is a JSON blob whose shape depends on
/// `queue` — see `crate::payload` for the typed structs each stage (de)serializes it as.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: i64,
    pub queue: QueueKind,
    pub payload: serde_json::Value,
    /// Optional key used to avoid queuing duplicate pending work for the same logical
    /// target (e.g. two `SnmpPoll` jobs for the same IP). `None` means "always enqueue".
    pub dedupe_key: Option<String>,
    pub state: JobState,
    pub attempts: i32,
    pub max_attempts: i32,
    pub locked_by: Option<String>,
    pub locked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_error: Option<String>,
    /// Terminal operator-action result; never contains unencrypted configuration or credentials.
    pub result: Option<serde_json::Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// Per-job pause (2026-08-21) — the job stays in the queue, in whatever `state` it was
    /// in, but is skipped by `JobQueueStore::claim` until resumed. See
    /// `JobQueueStore::pause_job`'s docs.
    pub paused: bool,
}

/// No `done` counter: these stats describe actionable work; operator-action history
/// is available through its job records.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueueStats {
    pub pending: i64,
    pub in_progress: i64,
    pub failed: i64,
    /// How many jobs currently have `paused = true` (a subset of `pending`, almost always
    /// — see `Job::paused`'s docs; nothing stops pausing an `in_progress` job too, it just
    /// only takes effect the *next* time it would be claimed, e.g. after `reclaim_stale`
    /// or a retry via `fail`).
    pub paused: i64,
    /// Whether the *whole queue* is paused (`JobQueueStore::set_queue_paused`) — distinct
    /// from `paused` above, which counts individually-paused jobs. When this is `true`,
    /// `claim` returns nothing for this queue regardless of any job's own `paused` flag.
    pub queue_paused: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_kind_str_roundtrip() {
        for kind in QueueKind::ALL {
            let s = kind.as_str();
            assert_eq!(
                QueueKind::from_str(s),
                Some(kind),
                "roundtrip failed for {:?}",
                kind
            );
        }
    }

    #[test]
    fn from_str_rejects_unknown_queue_names() {
        assert_eq!(QueueKind::from_str("bogus"), None);
    }
}
