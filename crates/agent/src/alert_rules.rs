use crate::handlers::{alert_hysteresis_config, AlertEvalHandler};
use chrono::{DateTime, Utc};
use discovery_core::{
    Alert, AlertDetails, AlertLifecycle, AlertMode, AlertRuleStatus, AlertTransition,
    AutoClearReason, Device, MetricTableRow, Metrics, RuleEvaluationState,
};
use discovery_dsl::AlertRule;
use serde_json::{json, Value};
use std::hash::{Hash, Hasher};
use tracing::warn;

fn signature(rule: &AlertRule) -> String {
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    serde_json::to_string(rule)
        .unwrap_or_default()
        .hash(&mut hash);
    format!("{:x}", hash.finish())
}

impl AlertEvalHandler {
    pub(crate) fn resolve_rule(&self, declared: &AlertRule) -> anyhow::Result<AlertRule> {
        let Some(name) = declared.policy.shared_rule.as_deref() else {
            return Ok(declared.clone());
        };
        let value = self
            .alerts
            .shared_rule(name)
            .ok_or_else(|| anyhow::anyhow!("shared alert rule '{name}' is missing"))?;
        let mut rule: AlertRule = serde_json::from_value(value)?;
        rule.name = declared.name.clone();
        rule.enabled &= declared.enabled;
        rule.policy.shared_rule = Some(name.into());
        Ok(rule)
    }

    pub(crate) async fn save_runtime(&self, device: &Device) -> anyhow::Result<()> {
        self.alert_store
            .save_runtime(device.id, &self.alerts.snapshot_for_device(device.id))
            .await
    }

    pub(crate) fn record_skipped(
        &self,
        rule: &AlertRule,
        device: &Device,
        state: RuleEvaluationState,
        now: DateTime<Utc>,
    ) {
        let mut statuses = self
            .alerts
            .rule_statuses(device.id)
            .into_iter()
            .filter(|s| s.name == rule.name)
            .collect::<Vec<_>>();
        if statuses.is_empty() {
            statuses.push(AlertRuleStatus::new(&rule.name, None, now));
        }
        for mut status in statuses {
            status.checked_at = now;
            status.state = state;
            status.error = None;
            status.activation = None;
            status.recovery = None;
            status.next_check_at = None;
            status.event_since = Some(now);
            status.event_times.clear();
            status.event_count = 0;
            self.alerts
                .interrupt_observation(device.id, &rule.name, status.row_key.as_deref());
            self.alerts.record_rule_status(device.id, status);
        }
    }

    pub(crate) fn record_error(
        &self,
        rule: &AlertRule,
        device: &Device,
        row_key: Option<&str>,
        error: String,
        now: DateTime<Utc>,
    ) {
        let mut status = self
            .alerts
            .rule_status(device.id, &rule.name, row_key)
            .unwrap_or_else(|| AlertRuleStatus::new(&rule.name, row_key, now));
        status.state = RuleEvaluationState::Error;
        status.error = Some(error.clone());
        status.checked_at = now;
        status.activation = None;
        status.recovery = None;
        status.next_check_at = None;
        self.alerts
            .interrupt_observation(device.id, &rule.name, row_key);
        self.alerts.record_rule_status(device.id, status);
        warn!(alert = %rule.name, ip = %device.facts.ip, %error, "alert rule evaluation failed");
    }

    pub(crate) async fn observe_rule(
        &self,
        rule: &AlertRule,
        device: &Device,
        metrics: &Metrics,
        row: Option<&MetricTableRow>,
        row_key: Option<&str>,
        missing: bool,
        now: DateTime<Utc>,
    ) {
        if missing && rule.policy.mode != AlertMode::State {
            let mut status = self
                .alerts
                .rule_status(device.id, &rule.name, row_key)
                .unwrap_or_else(|| AlertRuleStatus::new(&rule.name, row_key, now));
            status.checked_at = now;
            status.state = RuleEvaluationState::Missing;
            status.error = None;
            status.activation = None;
            status.recovery = None;
            status.next_check_at = rule
                .policy
                .period_seconds
                .map(|n| now + chrono::Duration::seconds(n as i64));
            self.alerts
                .interrupt_observation(device.id, &rule.name, row_key);
            self.alerts.record_rule_status(device.id, status);
            return;
        }
        let hash = signature(rule);
        let previous = self
            .alerts
            .rule_status(device.id, &rule.name, row_key)
            .filter(|s| s.signature == hash);
        if !missing
            && previous
                .as_ref()
                .and_then(|s| s.next_check_at)
                .is_some_and(|at| at > now)
        {
            return;
        }
        let mut status = previous
            .clone()
            .unwrap_or_else(|| AlertRuleStatus::new(&rule.name, row_key, now));
        if previous.is_none() {
            self.alerts
                .interrupt_observation(device.id, &rule.name, row_key);
        }
        status.signature = hash;
        status.checked_at = now;
        status.activate_after_seconds = rule.activate_after_seconds.unwrap_or(0);
        status.clear_after_seconds = rule.clear_after_seconds.unwrap_or(0);
        status.next_check_at = rule
            .policy
            .period_seconds
            .map(|n| now + chrono::Duration::seconds(n as i64));
        let mut extra = json!({ "previous": status.value, "history": {} });
        for name in &rule.policy.history_metrics {
            let since = now
                - chrono::Duration::seconds(rule.policy.history_seconds.unwrap_or(86400) as i64);
            match self
                .device_metrics
                .metric_history(device.id, name, 128, 0, Some(since), Some(now))
                .await
            {
                Ok(page) => {
                    extra["history"][name] = json!(page
                        .records
                        .iter()
                        .filter_map(|r| r.value.as_ref().and_then(|v| v.as_f64()))
                        .collect::<Vec<_>>());
                }
                Err(error) => {
                    self.record_error(rule, device, row_key, error.to_string(), now);
                    return;
                }
            }
        }
        let evaluated = if missing && rule.policy.mode == AlertMode::State {
            Ok((
                false,
                true,
                AlertDetails {
                    policy: rule.policy.clone(),
                    ..Default::default()
                },
            ))
        } else {
            self.evaluate_observation(rule, device, metrics, row, &extra, &mut status)
        };
        let (activation, recovery, mut details) = match evaluated {
            Ok(v) => v,
            Err(error) => {
                self.record_error(rule, device, row_key, error.to_string(), now);
                return;
            }
        };
        status.state = if missing {
            RuleEvaluationState::Missing
        } else if activation {
            RuleEvaluationState::True
        } else {
            RuleEvaluationState::False
        };
        status.activation = Some(activation);
        status.recovery = Some(recovery);
        status.error = None;
        let facts = if missing {
            self.alerts
                .active_alerts_for_device(device.id)
                .into_iter()
                .find(|a| a.name == rule.name && a.row_key.as_deref() == row_key)
                .and_then(|a| a.facts)
        } else {
            match rule.facts_expression.as_deref().filter(|expr| !expr.trim().is_empty()) {
                Some(expr) => match self.alert_engine.evaluate_context(
                    expr,
                    &device.facts,
                    device.ping_ok,
                    device.snmp_ok,
                    metrics,
                    row,
                    &extra,
                ) {
                    Ok(v) => Some(v),
                    Err(e) => {
                        self.record_error(rule, device, row_key, e.to_string(), now);
                        return;
                    }
                },
                None => None,
            }
        };
        let message =
            self.alert_engine
                .render_context_message(rule, &device.facts, metrics, row, &extra);
        if rule.policy.mode == AlertMode::Change {
            if activation {
                details.policy.acknowledge_required = true;
                self.raise_occurrence(rule, device, row_key, message, facts, details, now)
                    .await;
            }
            self.alerts.record_rule_status(device.id, status);
            return;
        }
        let transition = self.alerts.observe_with_config(
            device.id,
            &device.facts.ip,
            &rule.name,
            row_key,
            parse_level(&rule.level),
            message,
            facts,
            activation,
            recovery,
            missing.then_some(AutoClearReason::RowMissing),
            alert_hysteresis_config(
                rule,
                chrono::Duration::seconds(rule.clear_after_seconds.unwrap_or(0) as i64),
            ),
            now,
        );
        self.finish_rule_transition(transition, device, row_key, details, now)
            .await;
        self.alerts.record_rule_status(device.id, status);
        self.eval_flapping_incident(rule, device, row_key, now)
            .await;
    }

    pub(crate) async fn eval_flapping_incident(
        &self,
        rule: &AlertRule,
        device: &Device,
        key: Option<&str>,
        now: DateTime<Utc>,
    ) {
        let flapping = rule.policy.flap_incident
            && self
                .alerts
                .rule_status(device.id, &rule.name, key)
                .is_some_and(|s| s.flapping);
        let name = format!("{}.flapping", rule.name);
        if !flapping
            && !self
                .alerts
                .active_alerts_for_device(device.id)
                .iter()
                .any(|a| a.name == name && a.row_key.as_deref() == key)
        {
            return;
        }
        let transition = self.alerts.observe(
            device.id,
            &device.facts.ip,
            &name,
            key,
            parse_level(&rule.level),
            format!("Нестабильное состояние правила '{}'", rule.name),
            Some(json!({"rule":rule.name})),
            flapping,
            !flapping,
            None,
            chrono::Duration::zero(),
            now,
        );
        let mut policy = rule.policy.clone();
        policy.mode = AlertMode::State;
        policy.event = None;
        policy.actions.clear();
        policy.flap_incident = false;
        self.finish_rule_transition(
            transition,
            device,
            key,
            AlertDetails {
                policy,
                ..Default::default()
            },
            now,
        )
        .await;
    }

    pub(crate) fn evaluate_observation(
        &self,
        rule: &AlertRule,
        device: &Device,
        metrics: &Metrics,
        row: Option<&MetricTableRow>,
        extra: &Value,
        status: &mut AlertRuleStatus,
    ) -> anyhow::Result<(bool, bool, AlertDetails)> {
        let eval = |expr: &str| {
            self.alert_engine.evaluate_context(
                expr,
                &device.facts,
                device.ping_ok,
                device.snmp_ok,
                metrics,
                row,
                extra,
            )
        };
        let value = eval(&rule.expression)?;
        let mut details = AlertDetails {
            policy: rule.policy.clone(),
            observed_value: Some(value.clone()),
            ..Default::default()
        };
        let activation = match rule.policy.mode {
            AlertMode::State => value
                .as_bool()
                .ok_or_else(|| anyhow::anyhow!("activation expression must return a boolean"))?,
            AlertMode::Change => {
                if value.is_null() {
                    anyhow::bail!("observed value is missing");
                }
                status.previous_value = status.value.clone();
                details.previous_value = status.value.clone();
                let changed = status.value.as_ref().is_some_and(|old| old != &value);
                status.value = Some(value.clone());
                changed
            }
            AlertMode::Baseline => {
                let numeric = finite_number(&value)?;
                let lower = rule
                    .policy
                    .lower_expression
                    .as_deref()
                    .map(|expr| eval(expr).and_then(|v| finite_number(&v)))
                    .transpose()?;
                let upper = rule
                    .policy
                    .upper_expression
                    .as_deref()
                    .map(|expr| eval(expr).and_then(|v| finite_number(&v)))
                    .transpose()?;
                if matches!((lower, upper), (Some(l),Some(u)) if l >= u) {
                    anyhow::bail!("lower bound must be less than upper bound");
                }
                status.lower_bound = lower;
                status.upper_bound = upper;
                details.lower_bound = lower;
                details.upper_bound = upper;
                status.value = Some(value.clone());
                lower.is_some_and(|l| numeric < l) || upper.is_some_and(|u| numeric > u)
            }
            AlertMode::Event => anyhow::bail!("event rule requires source event evaluation"),
        };
        if rule.policy.mode == AlertMode::State {
            status.value = Some(value);
        }
        let recovery = match rule.deactivation_expression.as_deref().filter(|expr| !expr.trim().is_empty()) {
            Some(expr) => eval(expr)?
                .as_bool()
                .ok_or_else(|| anyhow::anyhow!("recovery expression must return a boolean"))?,
            None => !activation,
        };
        Ok((activation, recovery, details))
    }

    #[cfg(test)]
    pub(crate) fn evaluate_observation_for_test(
        &self,
        rule: &AlertRule,
        device: &Device,
        metrics: &Metrics,
        extra: &Value,
        status: &mut AlertRuleStatus,
    ) -> anyhow::Result<(bool, bool, AlertDetails)> {
        self.evaluate_observation(rule, device, metrics, None, extra, status)
    }

    async fn raise_occurrence(
        &self,
        rule: &AlertRule,
        device: &Device,
        key: Option<&str>,
        message: String,
        facts: Option<Value>,
        mut details: AlertDetails,
        now: DateTime<Utc>,
    ) {
        let occurrence_key = format!("{}@{}", key.unwrap_or("event"), uuid::Uuid::new_v4());
        details.raised_count = details.raised_count.max(1);
        let transition = self.alerts.observe(
            device.id,
            &device.facts.ip,
            &rule.name,
            Some(&occurrence_key),
            parse_level(&rule.level),
            message,
            facts,
            true,
            false,
            None,
            chrono::Duration::zero(),
            now,
        );
        self.finish_rule_transition(transition, device, Some(&occurrence_key), details, now)
            .await;
    }

    pub(crate) async fn finish_rule_transition(
        &self,
        mut transition: AlertTransition,
        device: &Device,
        key: Option<&str>,
        details: AlertDetails,
        now: DateTime<Utc>,
    ) {
        match &mut transition {
            AlertTransition::Activated(alert) => {
                alert.details = details;
                alert.details.raised_count = alert.details.raised_count.max(1);
                self.alerts
                    .set_details(device.id, &alert.name, key, alert.details.clone());
            }
            AlertTransition::Cleared(alert) => {
                alert.details.recovery_data = details.source_event.or(details.observed_value);
            }
            _ => {}
        }
        let action_alert = match &transition {
            AlertTransition::Activated(a) => Some((a.clone(), AlertLifecycle::Activated)),
            AlertTransition::Cleared(a) => Some((a.clone(), AlertLifecycle::Cleared)),
            _ => None,
        };
        let name = match &transition {
            AlertTransition::Activated(a)
            | AlertTransition::Cleared(a)
            | AlertTransition::StillActive(a) => a.name.clone(),
            _ => return,
        };
        self.persist_transition(
            transition,
            (device.id, name, key.map(str::to_string)),
            device.profile.clone(),
            now,
        )
        .await;
        if let Some((alert, phase)) = action_alert {
            // Only execute actions for an incident which actually reached durable storage.
            if self
                .alert_store
                .get(alert.id)
                .await
                .ok()
                .flatten()
                .is_some_and(|stored| stored.state == alert.state)
            {
                self.enqueue_actions(&alert, phase).await;
                if phase == AlertLifecycle::Activated {
                    self.enqueue_actions(&alert, AlertLifecycle::Raised).await;
                }
            }
        }
    }

    pub(crate) async fn enqueue_actions(&self, alert: &Alert, phase: AlertLifecycle) {
        match self.alert_engine.applicable_actions(alert, phase) {
            Ok(actions) => {
                for action in actions {
                    if let Err(error) = discovery_queue::enqueue_alert_action(
                        self.queue.as_ref(),
                        alert,
                        action,
                        "alert policy",
                        phase,
                    )
                    .await
                    {
                        warn!(%error, alert_id = %alert.id, "failed to enqueue corrective action");
                    }
                }
            }
            Err(error) => warn!(%error, alert_id = %alert.id, "corrective action condition failed"),
        }
    }

    pub(crate) async fn eval_event_rule(
        &self,
        rule: &AlertRule,
        device: &Device,
        metrics: &Metrics,
        now: DateTime<Utc>,
    ) {
        let Some(spec) = &rule.policy.event else {
            self.record_error(rule, device, None, "event settings are missing".into(), now);
            return;
        };
        let events = match self
            .alert_store
            .source_events(
                device.id,
                now - chrono::Duration::seconds(spec.window_seconds as i64),
            )
            .await
        {
            Ok(events) if events.len() <= 10000 => events,
            Ok(_) => {
                self.record_error(
                    rule,
                    device,
                    None,
                    "event window exceeded 10000 packets".into(),
                    now,
                );
                return;
            }
            Err(e) => {
                self.record_error(rule, device, None, e.to_string(), now);
                return;
            }
        };
        let hash = signature(rule);
        let event_since = self
            .alerts
            .rule_statuses(device.id)
            .iter()
            .filter(|s| s.name == rule.name)
            .filter_map(|s| s.event_since)
            .max();
        for event in events.into_iter().filter(|e| {
            e.metric == spec.metric && event_since.is_none_or(|since| e.received_at > since)
        }) {
            let mut event_data = event
                .data
                .get("fields")
                .cloned()
                .unwrap_or(event.data.clone());
            event_data["index"] = event.data.get("index").cloned().unwrap_or(Value::Null);
            let extra = json!({ "event": event_data });
            let eval = |expr: &str| {
                self.alert_engine.evaluate_context(
                    expr,
                    &device.facts,
                    device.ping_ok,
                    device.snmp_ok,
                    metrics,
                    None,
                    &extra,
                )
            };
            let key = match spec
                .key_expression
                .as_deref()
                .map(|expr| eval(expr))
                .transpose()
            {
                Ok(Some(v)) if v.is_string() || v.is_number() => Some(
                    v.as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| v.to_string()),
                ),
                Ok(None) => event
                    .data
                    .get("index")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                Ok(_) => {
                    self.record_error(
                        rule,
                        device,
                        None,
                        "event key must be a string or number".into(),
                        now,
                    );
                    continue;
                }
                Err(e) => {
                    self.record_error(rule, device, None, e.to_string(), now);
                    continue;
                }
            };
            let mut status = self
                .alerts
                .rule_status(device.id, &rule.name, key.as_deref())
                .filter(|s| s.signature == hash)
                .unwrap_or_else(|| AlertRuleStatus::new(&rule.name, key.as_deref(), now));
            if status.processed_events.contains(&event.id) {
                continue;
            }
            let result = (|| -> anyhow::Result<_> {
                let recovery = spec
                    .recovery_expression
                    .as_deref()
                    .map(|expr| {
                        eval(expr).and_then(|v| {
                            v.as_bool().ok_or_else(|| {
                                anyhow::anyhow!("event recovery must return a boolean")
                            })
                        })
                    })
                    .transpose()?
                    .unwrap_or(false);
                let matches = eval(&rule.expression)?
                    .as_bool()
                    .ok_or_else(|| anyhow::anyhow!("event filter must return a boolean"))?;
                let facts = rule.facts_expression.as_deref().map(eval).transpose()?;
                Ok((matches, recovery, facts))
            })();
            let (matches, recovery, facts) = match result {
                Ok(v) => v,
                Err(e) => {
                    self.record_error(rule, device, key.as_deref(), e.to_string(), now);
                    continue;
                }
            };
            status.signature = hash.clone();
            status.checked_at = now;
            status.error = None;
            status
                .event_times
                .retain(|at| *at >= now - chrono::Duration::seconds(spec.window_seconds as i64));
            status.processed_events.push(event.id);
            // The durable source table keeps a bounded horizon. Only ids inside that
            // horizon need to be remembered to make repeated ticks idempotent.
            if status.processed_events.len() > 10000 {
                status
                    .processed_events
                    .drain(..status.processed_events.len() - 10000);
            }
            if recovery {
                status.event_times.clear();
            } else if matches {
                status.event_times.push(event.received_at);
            }
            status.event_count = status.event_times.len() as u32;
            status.events_required = spec.count;
            status.window_seconds = spec.window_seconds;
            let activation = matches && !recovery && status.event_count >= spec.count;
            status.state = if activation {
                RuleEvaluationState::True
            } else {
                RuleEvaluationState::Waiting
            };
            status.activation = Some(activation);
            status.recovery = Some(recovery);
            let mut details = AlertDetails {
                policy: rule.policy.clone(),
                source_event: Some(
                    json!({"id":event.id,"metric":event.metric,"received_at":event.received_at,"data":event_data}),
                ),
                raised_count: status.event_count,
                ..Default::default()
            };
            let message = self.alert_engine.render_context_message(
                rule,
                &device.facts,
                metrics,
                None,
                &extra,
            );
            status.activate_after_seconds = rule.activate_after_seconds.unwrap_or(0);
            status.clear_after_seconds = rule.clear_after_seconds.unwrap_or(0);
            status.event_since = event_since;
            status.value = Some(json!({"details":details,"facts":facts,"message":message}));
            if spec.recovery_expression.is_none() {
                if activation {
                    let since = *status.activation_since.get_or_insert(now);
                    if now - since < chrono::Duration::seconds(status.activate_after_seconds as i64)
                    {
                        self.alerts.record_rule_status(device.id, status);
                        continue;
                    }
                    status.activation_since = None;
                    details.policy.acknowledge_required = true;
                    self.raise_occurrence(
                        rule,
                        device,
                        key.as_deref(),
                        message,
                        facts,
                        details,
                        now,
                    )
                    .await;
                    status.event_times.clear();
                    status.event_count = 0;
                }
            } else {
                if activation {
                    if let Some(mut active) = self
                        .alerts
                        .active_alerts_for_device(device.id)
                        .into_iter()
                        .find(|a| a.name == rule.name && a.row_key == key)
                    {
                        active.details.raised_count = active.details.raised_count.saturating_add(1);
                        if self.alert_store.upsert(&active).await.is_ok() {
                            self.alerts.set_details(
                                device.id,
                                &rule.name,
                                key.as_deref(),
                                active.details.clone(),
                            );
                            self.enqueue_actions(&active, AlertLifecycle::Raised).await;
                        }
                    }
                }
                let transition = self.alerts.observe_with_config(
                    device.id,
                    &device.facts.ip,
                    &rule.name,
                    key.as_deref(),
                    parse_level(&rule.level),
                    message,
                    facts,
                    activation,
                    recovery,
                    None,
                    alert_hysteresis_config(
                        rule,
                        chrono::Duration::seconds(rule.clear_after_seconds.unwrap_or(0) as i64),
                    ),
                    now,
                );
                self.finish_rule_transition(transition, device, key.as_deref(), details, now)
                    .await;
            }
            self.alerts.record_rule_status(device.id, status);
        }
        // Expire counts even if no packet has arrived. Correlated active incidents stay
        // active until an explicit recovery packet or operator action.
        let mut found = false;
        for mut status in self
            .alerts
            .rule_statuses(device.id)
            .into_iter()
            .filter(|s| s.name == rule.name && s.signature == hash)
        {
            found = true;
            status.next_check_at = rule
                .policy
                .period_seconds
                .map(|seconds| now + chrono::Duration::seconds(seconds as i64));
            status
                .event_times
                .retain(|at| *at >= now - chrono::Duration::seconds(spec.window_seconds as i64));
            status.event_count = status.event_times.len() as u32;
            if let Some(value) = &status.value {
                let details: AlertDetails =
                    serde_json::from_value(value["details"].clone()).unwrap_or_default();
                let message = value["message"]
                    .as_str()
                    .unwrap_or(&rule.message)
                    .to_string();
                let facts = value.get("facts").filter(|v| !v.is_null()).cloned();
                if spec.recovery_expression.is_none() {
                    if status.event_count < spec.count {
                        status.activation_since = None;
                    } else if status.activation_since.is_some_and(|at| {
                        now - at >= chrono::Duration::seconds(status.activate_after_seconds as i64)
                    }) {
                        let mut details = details;
                        details.policy.acknowledge_required = true;
                        self.raise_occurrence(
                            rule,
                            device,
                            status.row_key.as_deref(),
                            message,
                            facts,
                            details,
                            now,
                        )
                        .await;
                        status.activation_since = None;
                        status.event_times.clear();
                        status.event_count = 0;
                    }
                } else if status.activation_since.is_some() || status.recovery_since.is_some() {
                    let activation =
                        status.activation == Some(true) && status.event_count >= spec.count;
                    let recovery = status.recovery == Some(true);
                    let transition = self.alerts.observe_with_config(
                        device.id,
                        &device.facts.ip,
                        &rule.name,
                        status.row_key.as_deref(),
                        parse_level(&rule.level),
                        message,
                        facts,
                        activation,
                        recovery,
                        None,
                        alert_hysteresis_config(
                            rule,
                            chrono::Duration::seconds(status.clear_after_seconds as i64),
                        ),
                        now,
                    );
                    self.finish_rule_transition(
                        transition,
                        device,
                        status.row_key.as_deref(),
                        details,
                        now,
                    )
                    .await;
                }
            }
            let key = status.row_key.clone();
            self.alerts.record_rule_status(device.id, status);
            self.eval_flapping_incident(rule, device, key.as_deref(), now)
                .await;
        }
        if !found {
            let mut status = AlertRuleStatus::new(&rule.name, None, now);
            status.signature = hash;
            status.next_check_at = rule
                .policy
                .period_seconds
                .map(|seconds| now + chrono::Duration::seconds(seconds as i64));
            status.events_required = spec.count;
            status.window_seconds = spec.window_seconds;
            self.alerts.record_rule_status(device.id, status);
        }
    }

    pub(crate) async fn eval_response_escalation(&self, device: &Device, now: DateTime<Utc>) {
        let current_profile = match &device.profile {
            Some(name) => self.matcher.profile_by_name(name).await,
            None => None,
        };
        let mut items = Vec::new();
        let mut query = discovery_alerts::AlertListQuery {
            device_id: Some(device.id),
            response_pending: true,
            limit: 500,
            ..Default::default()
        };
        loop {
            let page = match self.alert_store.list(&query).await {
                Ok(page) => page,
                Err(error) => {
                    warn!(%error,"response escalation lookup failed");
                    return;
                }
            };
            let count = page.items.len() as i64;
            items.extend(page.items);
            query.offset += count;
            if count == 0 || query.offset >= page.total {
                break;
            }
        }
        items.retain(|alert| {
            current_profile
                .as_ref()
                .and_then(|p| p.alerts.iter().find(|r| r.name == alert.name))
                .and_then(|r| self.resolve_rule(r).ok())
                .is_none_or(|r| r.enabled)
        });
        let next_deadline = items
            .iter()
            .filter(|a| {
                a.acknowledged_at.is_none()
                    && a.details.policy.acknowledge_required
                    && !a.details.response_escalated
            })
            .filter_map(|a| {
                a.details
                    .policy
                    .escalate_after_seconds
                    .map(|seconds| a.first_seen + chrono::Duration::seconds(seconds as i64))
            })
            .filter(|at| *at > now)
            .min();
        self.alerts.set_response_deadline(device.id, next_deadline);
        let mut pending = std::collections::HashMap::<String, u32>::new();
        for alert in &items {
            if alert.acknowledged_at.is_none() && alert.details.policy.acknowledge_required {
                *pending.entry(alert.name.clone()).or_default() +=
                    alert.details.raised_count.max(1);
            }
        }
        for mut alert in items {
            let policy = &alert.details.policy;
            let needs_response = alert.acknowledged_at.is_none() && policy.acknowledge_required;
            let reason = if needs_response
                && policy
                    .escalate_after_seconds
                    .is_some_and(|n| now - alert.first_seen >= chrono::Duration::seconds(n as i64))
            {
                Some("Истёк срок подтверждения тревоги".to_string())
            } else if needs_response
                && policy
                    .pending_count_threshold
                    .is_some_and(|n| pending.get(&alert.name).copied().unwrap_or(0) >= n)
            {
                Some("Превышено число неподтверждённых событий".to_string())
            } else {
                None
            };
            let escalated = reason.is_some();
            if alert.details.response_escalated == escalated {
                continue;
            }
            alert.details.response_escalated = escalated;
            alert.details.response_escalation_reason = reason;
            if self.alert_store.upsert(&alert).await.is_ok() {
                self.alerts.set_details(
                    device.id,
                    &alert.name,
                    alert.row_key.as_deref(),
                    alert.details.clone(),
                );
                crate::handlers::dispatch_alert_notifications(
                    &self.notification_rules,
                    &self.notification_channels,
                    &self.auth,
                    &self.queue,
                    &alert,
                    device.profile.as_deref(),
                    if escalated {
                        discovery_core::NotificationTrigger::Escalated
                    } else {
                        discovery_core::NotificationTrigger::Deescalated
                    },
                    now,
                )
                .await;
                self.enqueue_actions(
                    &alert,
                    if escalated {
                        AlertLifecycle::Escalated
                    } else {
                        AlertLifecycle::Deescalated
                    },
                )
                .await;
            }
        }
    }
}
fn finite_number(value: &Value) -> anyhow::Result<f64> {
    value
        .as_f64()
        .filter(|n| n.is_finite())
        .ok_or_else(|| anyhow::anyhow!("observed value and bounds must be finite numbers"))
}
fn parse_level(level: &str) -> discovery_core::AlertLevel {
    discovery_core::AlertLevel::from_str(level).unwrap_or(discovery_core::AlertLevel::Info)
}
