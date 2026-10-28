use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleEvaluationState {
    True,
    False,
    Error,
    Missing,
    Disabled,
    Maintenance,
    Waiting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRuleStatus {
    pub name: String,
    pub row_key: Option<String>,
    pub checked_at: DateTime<Utc>,
    pub next_check_at: Option<DateTime<Utc>>,
    pub state: RuleEvaluationState,
    pub activation: Option<bool>,
    pub recovery: Option<bool>,
    pub error: Option<String>,
    pub activation_since: Option<DateTime<Utc>>,
    pub recovery_since: Option<DateTime<Utc>>,
    pub activate_after_seconds: u64,
    pub clear_after_seconds: u64,
    pub active_alert_id: Option<Uuid>,
    pub flapping: bool,
    pub value: Option<serde_json::Value>,
    pub previous_value: Option<serde_json::Value>,
    pub lower_bound: Option<f64>,
    pub upper_bound: Option<f64>,
    pub event_count: u32,
    pub events_required: u32,
    pub window_seconds: u64,
    /// Changes to a rule reset its observation state rather than reuse an old baseline.
    pub signature: String,
    #[serde(default)]
    pub event_times: Vec<DateTime<Utc>>,
    #[serde(default)]
    pub processed_events: Vec<Uuid>,
    #[serde(default)]
    pub event_since: Option<DateTime<Utc>>,
}

impl AlertRuleStatus {
    pub fn new(name: &str, row_key: Option<&str>, now: DateTime<Utc>) -> Self {
        Self {
            name: name.into(),
            row_key: row_key.map(str::to_string),
            checked_at: now,
            next_check_at: None,
            state: RuleEvaluationState::Waiting,
            activation: None,
            recovery: None,
            error: None,
            activation_since: None,
            recovery_since: None,
            activate_after_seconds: 0,
            clear_after_seconds: 0,
            active_alert_id: None,
            flapping: false,
            value: None,
            previous_value: None,
            lower_bound: None,
            upper_bound: None,
            event_count: 0,
            events_required: 0,
            window_seconds: 0,
            signature: String::new(),
            event_times: Vec::new(),
            processed_events: Vec::new(),
            event_since: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedRuleState {
    pub name: String,
    pub row_key: Option<String>,
    pub active_alert_id: Option<Uuid>,
    pub activation_since: Option<DateTime<Utc>>,
    pub recovery_since: Option<DateTime<Utc>>,
    pub last_zone: Option<bool>,
    pub switches: Vec<DateTime<Utc>>,
    pub flapping: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AlertRuntimeSnapshot {
    #[serde(default)]
    pub response_deadline: Option<DateTime<Utc>>,
    pub states: Vec<PersistedRuleState>,
    pub statuses: Vec<AlertRuleStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAlertRuntime {
    pub device_id: Uuid,
    pub snapshot: AlertRuntimeSnapshot,
}

/// Each accepted packet travels in a durable evaluation job. Keeping packets
/// separate from the latest metric value prevents burst coalescing from losing events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertSourceEvent {
    pub id: Uuid,
    pub device_id: Uuid,
    pub metric: String,
    pub received_at: DateTime<Utc>,
    pub data: serde_json::Value,
}
