use crate::payload::OperatorAction;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertMode {
    #[default]
    State,
    Change,
    Baseline,
    Event,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertLifecycle {
    Raised,
    Activated,
    Cleared,
    Acknowledged,
    Escalated,
    Deescalated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlertAction {
    pub on: AlertLifecycle,
    pub action: OperatorAction,
    #[serde(default)]
    pub condition: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventTrigger {
    /// A profile binding, e.g. `trap_link` or `syslog_authentication`.
    pub metric: String,
    #[serde(default = "one")]
    pub count: u32,
    #[serde(default = "minute")]
    pub window_seconds: u64,
    #[serde(default)]
    pub recovery_expression: Option<String>,
    #[serde(default)]
    pub key_expression: Option<String>,
}
fn one() -> u32 {
    1
}
fn minute() -> u64 {
    60
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct AlertPolicy {
    pub mode: AlertMode,
    pub period_seconds: Option<u64>,
    pub lower_expression: Option<String>,
    pub upper_expression: Option<String>,
    pub history_metrics: Vec<String>,
    pub history_seconds: Option<u64>,
    pub event: Option<EventTrigger>,
    pub shared_rule: Option<String>,
    pub flap_clear_threshold: Option<u32>,
    pub flap_incident: bool,
    pub acknowledge_required: bool,
    pub escalate_after_seconds: Option<u64>,
    pub pending_count_threshold: Option<u32>,
    pub actions: Vec<AlertAction>,
    pub interactive_actions: Vec<OperatorAction>,
    pub viewer_roles: Vec<Uuid>,
    pub operator_roles: Vec<Uuid>,
    pub screen_notification: bool,
    pub notification_sound: bool,
    pub notification_lifetime_seconds: Option<u64>,
}

impl AlertPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.period_seconds == Some(0) || self.period_seconds.is_some_and(|v| v > 86400) {
            return Err("period_seconds must be between 1 and 86400".into());
        }
        if self.mode == AlertMode::Baseline
            && self.lower_expression.is_none()
            && self.upper_expression.is_none()
        {
            return Err("baseline requires lower_expression or upper_expression".into());
        }
        if self.mode == AlertMode::Event {
            let event = self
                .event
                .as_ref()
                .ok_or("event mode requires event settings")?;
            if !(event.metric.starts_with("trap_") || event.metric.starts_with("syslog_")) {
                return Err("event.metric must identify a trap_ or syslog_ binding".into());
            }
            if event.count == 0
                || event.count > 10000
                || event.window_seconds == 0
                || event.window_seconds > 86400
            {
                return Err("event count must be 1..10000 and window_seconds 1..86400".into());
            }
        } else if self.event.is_some() {
            return Err("event settings require event mode".into());
        }
        if self.history_metrics.len() > 16
            || self.history_seconds.is_some_and(|v| v == 0 || v > 86400)
        {
            return Err("history supports at most 16 metrics and a 1..86400 second window".into());
        }
        if self.actions.len() > 16 || self.interactive_actions.len() > 4 {
            return Err("too many alert actions".into());
        }
        if self
            .escalate_after_seconds
            .is_some_and(|n| n == 0 || n > 86400)
            || self
                .pending_count_threshold
                .is_some_and(|n| n == 0 || n > 10000)
        {
            return Err("escalation age must be 1..86400 and pending count 1..10000".into());
        }
        if !self.acknowledge_required
            && (self.escalate_after_seconds.is_some() || self.pending_count_threshold.is_some())
        {
            return Err("response escalation requires acknowledge_required".into());
        }
        if self
            .notification_lifetime_seconds
            .is_some_and(|v| v == 0 || v > 86400)
        {
            return Err("notification lifetime must be between 1 and 86400 seconds".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertDetails {
    pub policy: AlertPolicy,
    pub observed_value: Option<serde_json::Value>,
    pub previous_value: Option<serde_json::Value>,
    pub lower_bound: Option<f64>,
    pub upper_bound: Option<f64>,
    pub source_event: Option<serde_json::Value>,
    pub recovery_data: Option<serde_json::Value>,
    pub raised_count: u32,
    pub response_escalated: bool,
    pub response_escalation_reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_modes_and_bounds() {
        let mut p = AlertPolicy::default();
        assert!(p.validate().is_ok());
        p.mode = AlertMode::Baseline;
        assert!(p.validate().is_err());
        p.upper_expression = Some("90".into());
        assert!(p.validate().is_ok());
        p.mode = AlertMode::Event;
        p.event = Some(EventTrigger {
            metric: "trap_link".into(),
            count: 2,
            window_seconds: 60,
            recovery_expression: None,
            key_expression: None,
        });
        assert!(p.validate().is_ok());
        p.event.as_mut().unwrap().count = 0;
        assert!(p.validate().is_err());
        p.event.as_mut().unwrap().count = 10001;
        assert!(p.validate().is_err());
        p.event.as_mut().unwrap().count = 1;
        p.event.as_mut().unwrap().metric = "cpu".into();
        assert!(p.validate().is_err());
    }
    #[test]
    fn rejects_invalid_limits_and_accepts_exact_boundaries() {
        use serde_json::json;
        for value in [
            json!({"period_seconds":0}), json!({"period_seconds":86401}),
            json!({"history_seconds":0}), json!({"history_seconds":86401}),
            json!({"history_metrics":vec!["cpu";17]}),
            json!({"notification_lifetime_seconds":0}), json!({"notification_lifetime_seconds":86401}),
            json!({"escalate_after_seconds":1}),
            json!({"acknowledge_required":true,"escalate_after_seconds":0}),
            json!({"acknowledge_required":true,"escalate_after_seconds":86401}),
            json!({"acknowledge_required":true,"pending_count_threshold":0}),
            json!({"acknowledge_required":true,"pending_count_threshold":10001}),
            json!({"mode":"event","event":{"metric":"syslog_link","window_seconds":0}}),
            json!({"mode":"event","event":{"metric":"trap_link","window_seconds":86401}}),
            json!({"event":{"metric":"trap_link"}}),
        ] {
            let policy: AlertPolicy = serde_json::from_value(value.clone()).unwrap();
            assert!(policy.validate().is_err(), "accepted {value}");
        }
        for value in [
            json!({"period_seconds":1}), json!({"period_seconds":86400}),
            json!({"history_seconds":1,"history_metrics":vec!["cpu";16]}),
            json!({"history_seconds":86400}),
            json!({"notification_lifetime_seconds":1}), json!({"notification_lifetime_seconds":86400}),
            json!({"acknowledge_required":true,"escalate_after_seconds":86400,"pending_count_threshold":10000}),
            json!({"mode":"event","event":{"metric":"syslog_link","count":10000,"window_seconds":86400}}),
        ] {
            let policy: AlertPolicy = serde_json::from_value(value.clone()).unwrap();
            assert!(policy.validate().is_ok(), "rejected {value}");
        }
        assert!(serde_json::from_value::<AlertPolicy>(json!({"actions":[{"on":"raised","action":"shell"}]})).is_err());
        assert!(serde_json::from_value::<AlertPolicy>(json!({"sms":true})).is_err());
    }

}
