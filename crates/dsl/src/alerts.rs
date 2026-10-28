use chrono::{DateTime, Utc};
use discovery_core::{DeviceFacts, MetricRecord, MetricTableRow, MetricValue, Metrics, Schedule};
use rhai::{Dynamic, Engine, Scope};

use crate::util::{
    dynamic_to_json, facts_to_map, metric_reference_regex, metrics_to_map, table_row_to_map,
};
use crate::{AlertRule, ProfileFile};

/// Returns profile metrics whose polling attempt has fallen behind its expected cadence.
///
/// This deliberately uses `last_attempt_at`, not `polled_at`: a metric that is answering
/// with errors is unhealthy, but it is not stale if the poller is still making attempts.
/// Calendar schedules are excluded because their next due time cannot be inferred from a
/// fixed interval. A two-interval grace window prevents normal queue jitter from opening a
/// stale incident while still making a stopped poll chain observable.
pub fn stale_metric_names(
    profile: &ProfileFile,
    records: &[MetricRecord],
    now: DateTime<Utc>,
    default_interval_secs: u64,
) -> Vec<String> {
    profile
        .metrics
        .poll
        .iter()
        .filter_map(|(name, spec)| {
            if !spec.enabled() || matches!(spec.schedule(), Some(Schedule::Calendar { .. })) {
                return None;
            }
            let record = records.iter().find(|record| record.name == *name)?;
            if record.enabled_override == Some(false) {
                return None;
            }
            let interval = spec.interval_secs().unwrap_or(default_interval_secs).max(1);
            let threshold = chrono::Duration::seconds(interval.saturating_mul(2) as i64);
            (now.signed_duration_since(record.last_attempt_at) > threshold).then(|| name.clone())
        })
        .collect()
}

/// Evaluates a profile's alert `expression`/`deactivation_expression`/`facts_expression`
/// against a device's facts and polled metrics. Whether an alert should currently be
/// *open* (debounced against flapping) is not this crate's job — see
/// `discovery_core::AlertStateTracker`, which consumes this evaluator's boolean/JSON
/// output.
pub struct AlertEvaluator {
    engine: Engine,
}

impl Default for AlertEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertEvaluator {
    pub fn applicable_actions(
        &self,
        alert: &discovery_core::Alert,
        on: discovery_core::AlertLifecycle,
    ) -> anyhow::Result<Vec<discovery_core::payload::OperatorAction>> {
        let facts = discovery_core::DeviceFacts {
            ip: alert.device_ip.clone(),
        };
        let extra = serde_json::json!({"alert":alert});
        let mut actions = Vec::new();
        for configured in alert.details.policy.actions.iter().filter(|a| a.on == on) {
            let passes = match &configured.condition {
                Some(expr) => self
                    .evaluate_context(expr, &facts, None, None, &Metrics::default(), None, &extra)?
                    .as_bool()
                    .ok_or_else(|| anyhow::anyhow!("action condition must return a boolean"))?,
                None => true,
            };
            if passes {
                actions.push(configured.action);
            }
        }
        Ok(actions)
    }

    pub fn evaluate_context(
        &self,
        expression: &str,
        facts: &DeviceFacts,
        ping_ok: Option<bool>,
        snmp_ok: Option<bool>,
        metrics: &Metrics,
        row: Option<&MetricTableRow>,
        extra: &serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let mut scope = Scope::new();
        scope.push("facts", facts_to_map(facts, ping_ok, snmp_ok));
        scope.push("metrics", metrics_to_map(metrics));
        if let Some(row) = row {
            scope.push("row", table_row_to_map(row));
        }
        if let Some(extra) = extra.as_object() {
            for (name, value) in extra {
                scope.push_dynamic(name, crate::util::json_to_dynamic(value));
            }
        }
        let result: Dynamic = self
            .engine
            .eval_with_scope(&mut scope, expression)
            .map_err(|e| anyhow::anyhow!("expression error: {e}"))?;
        Ok(dynamic_to_json(&result))
    }

    pub fn validate_rule(&self, rule: &AlertRule) -> anyhow::Result<()> {
        rule.policy.validate().map_err(anyhow::Error::msg)?;
        if rule.name.trim().is_empty() || rule.name.len() > 128 || rule.name.ends_with(".flapping")
        {
            anyhow::bail!("rule requires a name up to 128 bytes; .flapping is reserved");
        }
        for seconds in [
            rule.activate_after_seconds,
            rule.clear_after_seconds,
            rule.flap_window_seconds,
        ]
        .into_iter()
        .flatten()
        {
            if seconds > 86400 {
                anyhow::bail!("rule delays and flapping window must not exceed 86400 seconds");
            }
        }
        if !matches!(rule.level.as_str(), "info" | "warning" | "critical") {
            anyhow::bail!("unknown alert level");
        }
        if rule
            .policy
            .flap_clear_threshold
            .is_some_and(|n| n == 0 || n >= rule.flap_threshold.unwrap_or(0))
        {
            anyhow::bail!("flap_clear_threshold must be positive and less than flap_threshold");
        }
        if rule.policy.mode == discovery_core::AlertMode::Event && rule.row_metric.is_some() {
            anyhow::bail!("event rules use event.key_expression instead of row_metric");
        }
        for expression in std::iter::once(rule.expression.as_str())
            .chain(rule.deactivation_expression.as_deref())
            .chain(rule.facts_expression.as_deref())
            .chain(rule.row_key_expression.as_deref())
            .chain(rule.policy.lower_expression.as_deref())
            .chain(rule.policy.upper_expression.as_deref())
            .chain(
                rule.policy
                    .event
                    .as_ref()
                    .and_then(|e| e.recovery_expression.as_deref()),
            )
            .chain(
                rule.policy
                    .event
                    .as_ref()
                    .and_then(|e| e.key_expression.as_deref()),
            )
            .chain(
                rule.policy
                    .actions
                    .iter()
                    .filter_map(|a| a.condition.as_deref()),
            )
        {
            self.validate_expression(expression)?;
        }
        Ok(())
    }

    pub fn new() -> Self {
        let mut engine = Engine::new();
        engine.set_max_operations(50_000);
        engine.register_fn("avg", |values: rhai::Array| -> f64 {
            let numbers: Vec<f64> = values
                .iter()
                .filter_map(|v| {
                    v.as_float()
                        .ok()
                        .or_else(|| v.as_int().ok().map(|n| n as f64))
                })
                .collect();
            if numbers.is_empty() {
                f64::NAN
            } else {
                numbers.iter().sum::<f64>() / numbers.len() as f64
            }
        });
        crate::util::register_missing_field_safety(&mut engine);
        Self { engine }
    }

    /// Builds the metric bag used by alert expressions from the durable metric state.
    ///
    /// `device_metrics.value` deliberately keeps the last successful value after a
    /// failed poll, so it remains available to historical/dashboard consumers. Alerts
    /// have a stricter contract: a value is usable only when the most recent attempt
    /// succeeded. This prevents a failed metric from holding an alert open on an
    /// indefinitely old last-known value; a later successful poll naturally puts it back
    /// into the bag on the next evaluation.
    pub fn metrics_for_alerts(records: &[MetricRecord]) -> Metrics {
        let mut metrics = Metrics::default();
        for record in records {
            if record.error.is_none() {
                if let Some(value) = &record.value {
                    metrics.insert(record.name.clone(), value.clone());
                }
            }
        }
        metrics
    }

    /// Evaluates a single boolean Rhai expression — used for both `rule.expression`
    /// (activation) and `rule.deactivation_expression` (deactivation), same `facts`/
    /// `metrics` scope either way. If the expression references a metric that isn't in
    /// `metrics` (e.g. its poll failed this cycle), Rhai evaluates the comparison as
    /// `false` rather than erroring — a metric referencing missing data is treated as
    /// "condition not met", not a hard failure. `Err` is reserved for actually malformed
    /// expressions (syntax errors, etc.) — callers are expected to fail safe on `Err`, see
    /// `discovery_agent::handlers::AlertEvalHandler`'s docs for which direction "safe"
    /// means for each of the two conditions.
    ///
    /// `row` (added 2026-08-29 — `AlertRule::row_metric`) puts a third scope variable,
    /// `row`, in scope when `Some` — one row of the rule's declared table metric. `None`
    /// for an ordinary device-level rule, exactly today's behavior/scope.
    ///
    /// `ping_ok`/`snmp_ok` (2026-09-14, `docs/Roadmap.md` "До релиза" item 6) — the
    /// device's *current* live reachability, passed straight through to `facts_to_map`
    /// (`facts.ping_ok`/`facts.snmp_ok` in scope) — see that function's docs for why this
    /// isn't sourced from the `facts: &DeviceFacts` parameter itself.
    pub fn evaluate_condition(
        &self,
        expression: &str,
        facts: &DeviceFacts,
        ping_ok: Option<bool>,
        snmp_ok: Option<bool>,
        metrics: &Metrics,
        row: Option<&MetricTableRow>,
    ) -> anyhow::Result<bool> {
        let mut scope = Scope::new();
        scope.push("facts", facts_to_map(facts, ping_ok, snmp_ok));
        scope.push("metrics", metrics_to_map(metrics));
        if let Some(row) = row {
            scope.push("row", table_row_to_map(row));
        }
        self.engine
            .eval_with_scope::<bool>(&mut scope, expression)
            .map_err(|e| anyhow::anyhow!("expression error: {}", e))
    }

    /// `true` if `expression` references at least one `metrics.<name>` whose name is not a
    /// key in `metrics` at all — i.e. that metric has never been polled, or was pruned
    /// entirely (`DeviceMetricsStore::prune_metrics` — a profile edit drops it, or the
    /// device moves to a profile that no longer declares it), as opposed to merely holding
    /// a value that happens to make the expression evaluate `false`.
    ///
    /// `evaluate_condition` can't distinguish these two cases on its own by design: Rhai
    /// treats a missing map key as `()`, and `() > 85` (etc.) quietly evaluates `false`
    /// rather than erroring — the right fail-safe behavior when the metric legitimately
    /// doesn't clear the threshold, but wrong when the metric doesn't exist at all (see
    /// `missing_metric_does_not_panic_and_is_treated_as_condition_false` below for the
    /// former case, which this method must not flag). Only checks key existence, never the
    /// value/type — a metric present with a stale value from an earlier successful poll is
    /// not "missing". See `discovery_core::AutoClearReason::RowMissing`'s docs and
    /// `discovery_agent::handlers::AlertEvalHandler::eval_device_level_rule`'s docs for the
    /// device-level bug this closes (2026-09-06) — the row-scoped equivalent
    /// (`eval_row_scoped_rule`) already had its own way to detect a metric's row vanishing
    /// from a table entirely; this is the device-level (scalar) counterpart.
    pub fn references_missing_metric(&self, expression: &str, metrics: &Metrics) -> bool {
        metric_reference_regex()
            .captures_iter(expression)
            .any(|caps| metrics.get(&caps[1]).is_none())
    }

    /// Evaluates `rule.facts_expression` and converts the result to JSON for storage —
    /// see `discovery_dsl::AlertRule::facts_expression`'s docs. Same `facts`/`metrics`
    /// (and, when row-scoped, `row`) scope as [`Self::evaluate_condition`]. Typically
    /// returns a Rhai object map; see `crate::util::dynamic_to_json`'s docs for exactly
    /// how the result is converted.
    ///
    /// `ping_ok`/`snmp_ok` — same live-reachability pass-through as
    /// [`Self::evaluate_condition`]'s docs.
    pub fn evaluate_facts(
        &self,
        expression: &str,
        facts: &DeviceFacts,
        ping_ok: Option<bool>,
        snmp_ok: Option<bool>,
        metrics: &Metrics,
        row: Option<&MetricTableRow>,
    ) -> anyhow::Result<serde_json::Value> {
        let mut scope = Scope::new();
        scope.push("facts", facts_to_map(facts, ping_ok, snmp_ok));
        scope.push("metrics", metrics_to_map(metrics));
        if let Some(row) = row {
            scope.push("row", table_row_to_map(row));
        }
        let result: Dynamic = self
            .engine
            .eval_with_scope(&mut scope, expression)
            .map_err(|e| anyhow::anyhow!("facts expression error: {}", e))?;
        Ok(dynamic_to_json(&result))
    }

    /// Computes one row's tracking identity for a row-scoped rule
    /// (`AlertRule::row_key_expression`'s docs have the full contract). `expression =
    /// None` (the rule never set one) defaults to the row's own SNMP index verbatim —
    /// no Rhai evaluation needed for the common case. `Some(expr)` evaluates it with
    /// scope `{facts, metrics, row}` (same as a row-scoped `expression`/
    /// `deactivation_expression`) and stringifies the result via Rhai's own `to_string`
    /// — works for any scalar `row.<field>` (`row.ifDescr`, `row.ifIndex`, ...), which
    /// covers every realistic case without needing a narrower return-type contract.
    pub fn evaluate_row_key(
        &self,
        expression: Option<&str>,
        facts: &DeviceFacts,
        metrics: &Metrics,
        row: &MetricTableRow,
    ) -> anyhow::Result<String> {
        let Some(expression) = expression else {
            return Ok(row.index.clone());
        };
        let mut scope = Scope::new();
        scope.push("facts", facts_to_map(facts, None, None));
        scope.push("metrics", metrics_to_map(metrics));
        scope.push("row", table_row_to_map(row));
        let result: Dynamic = self
            .engine
            .eval_with_scope(&mut scope, expression)
            .map_err(|e| anyhow::anyhow!("row_key_expression error: {}", e))?;
        Ok(result.to_string())
    }

    /// Computes a trap-derived row's identity from `discovery_dsl::TrapEventSpec::key_expression`
    /// — SNMP Trap ingestion, 2026-08-30 (`discovery-agent`'s trap listener is the only
    /// caller). Scope is `{facts, varbinds}`, deliberately *not* `{facts, metrics, row}` —
    /// there is no `row`/`metrics` yet at this point, `varbinds` (already extracted OID ->
    /// friendly-field-name -> `MetricValue`, same shape as any other metrics bag) is all
    /// there is to compute an identity from, per that field's docs. `None` — including a
    /// blank/whitespace-only expression, see `TrapEventSpec::key_expression()`'s
    /// normalization — means this binding has no per-entity identity at all (a
    /// device-level singleton fact), not an error.
    pub fn evaluate_trap_key(
        &self,
        expression: Option<&str>,
        facts: &DeviceFacts,
        varbinds: &Metrics,
    ) -> anyhow::Result<Option<String>> {
        let Some(expression) = expression else {
            return Ok(None);
        };
        let mut scope = Scope::new();
        scope.push("facts", facts_to_map(facts, None, None));
        scope.push("varbinds", metrics_to_map(varbinds));
        let result: Dynamic = self
            .engine
            .eval_with_scope(&mut scope, expression)
            .map_err(|e| anyhow::anyhow!("key_expression error: {}", e))?;
        Ok(Some(result.to_string()))
    }

    /// Computes a syslog-derived row's identity from
    /// `discovery_dsl::SyslogEventSpec::key_expression` — Syslog ingestion, 2026-09-06
    /// (`discovery-agent`'s syslog listener is the only caller). Direct sibling of
    /// [`Self::evaluate_trap_key`]: scope is `{facts, fields}` instead of `{facts,
    /// varbinds}` — `fields` is the matched variant's named regex capture groups plus the
    /// automatic `severity`/`facility`/`hostname` entries every syslog row always carries
    /// (see `SyslogEventSpec`'s docs), same `Metrics` shape either way. `None` — including
    /// blank/whitespace-only, see `SyslogEventSpec::key_expression()`'s normalization —
    /// means singleton, not an error.
    pub fn evaluate_syslog_key(
        &self,
        expression: Option<&str>,
        facts: &DeviceFacts,
        fields: &Metrics,
    ) -> anyhow::Result<Option<String>> {
        let Some(expression) = expression else {
            return Ok(None);
        };
        let mut scope = Scope::new();
        scope.push("facts", facts_to_map(facts, None, None));
        scope.push("fields", metrics_to_map(fields));
        let result: Dynamic = self
            .engine
            .eval_with_scope(&mut scope, expression)
            .map_err(|e| anyhow::anyhow!("key_expression error: {}", e))?;
        Ok(Some(result.to_string()))
    }

    /// Renders `rule.message`, substituting `{metrics.<name>}`/`{facts.<name>}` tokens
    /// with the current value (`{facts.<name>}` support added 2026-08-17, alongside
    /// `expression` gaining `facts` scope access). Plain string substitution on purpose —
    /// the `expression` field is where conditional logic belongs, the message is just for
    /// a human to read.
    ///
    /// `row` (added 2026-08-29) additionally enables `{row.<field>}` tokens
    /// (`{row.ifDescr}`, `{row.index}`, ...) for a row-scoped rule's message — `None` for
    /// an ordinary device-level rule, same behavior as before this field existed.
    pub fn render_message(
        &self,
        rule: &AlertRule,
        facts: &DeviceFacts,
        metrics: &Metrics,
        row: Option<&MetricTableRow>,
    ) -> String {
        let mut out = rule.message.clone();
        for (key, value) in &metrics.0 {
            let token = format!("{{metrics.{}}}", key);
            if out.contains(&token) {
                out = out.replace(&token, &metric_value_to_string(value));
            }
        }
        if let Some(row) = row {
            for (key, value) in &row.fields {
                let token = format!("{{row.{}}}", key);
                if out.contains(&token) {
                    out = out.replace(&token, &metric_value_to_string(value));
                }
            }
            let index_token = "{row.index}";
            if out.contains(index_token) {
                out = out.replace(index_token, &row.index);
            }
        }
        let ip_token = "{facts.ip}";
        if out.contains(ip_token) {
            out = out.replace(ip_token, &facts.ip);
        }
        out
    }

    pub fn render_context_message(
        &self,
        rule: &AlertRule,
        facts: &DeviceFacts,
        metrics: &Metrics,
        row: Option<&MetricTableRow>,
        extra: &serde_json::Value,
    ) -> String {
        let mut message = self.render_message(rule, facts, metrics, row);
        if let Some(extra) = extra.as_object() {
            for (scope, value) in extra {
                if let Some(fields) = value.as_object() {
                    for (field, value) in fields {
                        let rendered = value
                            .as_str()
                            .map(str::to_string)
                            .unwrap_or_else(|| value.to_string());
                        message = message.replace(&format!("{{{scope}.{field}}}"), &rendered);
                    }
                } else {
                    let rendered = value
                        .as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| value.to_string());
                    message = message.replace(&format!("{{{scope}}}"), &rendered);
                }
            }
        }
        message
    }

    /// Syntax-only check — compiles `expression` without evaluating it. Added 2026-09-17
    /// (audit finding #3, see `discovery_dsl::matcher::ProfileMatcher::validate_expression`'s
    /// docs for the full story) so `discovery-web`'s `upsert_profile` can reject a broken
    /// `expression`/`deactivation_expression`/`facts_expression`/`row_key_expression` at
    /// save time instead of only discovering it later as a silent per-tick `AlertEvalHandler`
    /// failure. Same signature/behavior as `TopologyEvaluator::validate_expression`/
    /// `GroupAlertEvaluator::validate_expression`.
    pub fn validate_expression(&self, expression: &str) -> anyhow::Result<()> {
        self.engine
            .compile(expression)
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("{e}"))
    }
}

fn metric_value_to_string(value: &MetricValue) -> String {
    match value {
        MetricValue::Int(v) => v.to_string(),
        MetricValue::Float(v) => format!("{:.2}", v),
        MetricValue::Str(v) => v.clone(),
        MetricValue::Bool(v) => v.to_string(),
        // A whole table doesn't fit a `{metrics.<name>}` text token — a rule that wants to
        // call out specific rows should do so in `expression` (Rhai has the full row data
        // via `metric_value_to_dynamic`) and put the result in a `facts_expression`/its own
        // computed value, not rely on this plain substitution. This is just a
        // never-crashes-the-render fallback, not something a real profile should lean on.
        MetricValue::Table(rows) => format!("<{} rows>", rows.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MatchSection, MetricSpec, MetricsSection, ProfileMeta};
    use discovery_core::MetricTableRow;
    use std::collections::BTreeMap;

    fn facts() -> DeviceFacts {
        DeviceFacts {
            ip: "10.0.0.1".into(),
        }
    }

    #[test]
    fn metrics_for_alerts_drops_failed_last_attempt_but_restores_value_on_recovery() {
        let now = chrono::Utc::now();
        let failed = MetricRecord {
            name: "cpu".into(),
            value: Some(MetricValue::Int(95)),
            error: Some("timeout".into()),
            polled_at: Some(now - chrono::Duration::minutes(10)),
            last_attempt_at: now,
            enabled_override: None,
        };
        assert!(AlertEvaluator::metrics_for_alerts(&[failed])
            .get("cpu")
            .is_none());

        let recovered = MetricRecord {
            error: None,
            value: Some(MetricValue::Int(42)),
            ..failed_record(now)
        };
        assert_eq!(
            AlertEvaluator::metrics_for_alerts(&[recovered]).get("cpu"),
            Some(&MetricValue::Int(42))
        );
    }

    #[test]
    fn stale_metric_names_use_attempt_time_and_two_interval_grace() {
        let now = chrono::Utc::now();
        let mut poll = BTreeMap::new();
        poll.insert("cpu".into(), MetricSpec::Oid("1.3.6.1.2.1.1.3.0".into()));
        let profile = ProfileFile {
            profile: ProfileMeta {
                name: "test".into(),
                priority: 0,
            },
            match_expr: MatchSection {
                expression: "true".into(),
            },
            metrics: MetricsSection { poll },
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            alerts: Vec::new(),
            version: String::new(),
        };
        let record = MetricRecord {
            name: "cpu".into(),
            value: Some(MetricValue::Int(1)),
            error: Some("timeout".into()),
            polled_at: Some(now - chrono::Duration::minutes(10)),
            last_attempt_at: now - chrono::Duration::seconds(29),
            enabled_override: None,
        };
        assert!(stale_metric_names(&profile, &[record], now, 15).is_empty());

        let stale = MetricRecord {
            last_attempt_at: now - chrono::Duration::seconds(31),
            ..failed_record(now - chrono::Duration::seconds(31))
        };
        assert_eq!(stale_metric_names(&profile, &[stale], now, 15), vec!["cpu"]);
    }

    fn failed_record(now: chrono::DateTime<chrono::Utc>) -> MetricRecord {
        MetricRecord {
            name: "cpu".into(),
            value: None,
            error: None,
            polled_at: Some(now),
            last_attempt_at: now,
            enabled_override: None,
        }
    }

    fn rule(expr: &str) -> AlertRule {
        AlertRule {
            policy: Default::default(),
            name: "test_alert".into(),
            level: "warning".into(),
            row_metric: None,
            row_key_expression: None,
            expression: expr.into(),
            deactivation_expression: None,
            facts_expression: None,
            message: "cpu at {metrics.cpu}%".into(),
            clear_after_seconds: Some(60),
            activate_after_seconds: None,
            flap_window_seconds: None,
            flap_threshold: None,
            enabled: true,
        }
    }

    #[test]
    fn evaluates_numeric_threshold() {
        let evaluator = AlertEvaluator::new();

        let mut metrics_high = Metrics::default();
        metrics_high.insert("cpu", MetricValue::Int(92));
        assert!(evaluator
            .evaluate_condition(
                &rule("metrics.cpu > 85").expression,
                &facts(),
                None,
                None,
                &metrics_high,
                None
            )
            .unwrap());

        let mut metrics_ok = Metrics::default();
        metrics_ok.insert("cpu", MetricValue::Int(10));
        assert!(!evaluator
            .evaluate_condition(
                &rule("metrics.cpu > 85").expression,
                &facts(),
                None,
                None,
                &metrics_ok,
                None
            )
            .unwrap());
    }

    fn if_table_row(index: &str, if_index: i64, oper_status: i64) -> MetricTableRow {
        let mut fields = BTreeMap::new();
        fields.insert("ifIndex".to_string(), MetricValue::Int(if_index));
        fields.insert("ifOperStatus".to_string(), MetricValue::Int(oper_status));
        MetricTableRow {
            index: index.to_string(),
            fields,
        }
    }

    /// The whole point of `metric_value_to_dynamic`'s `Table` arm — a table metric must be
    /// usable from an activation/deactivation expression via Rhai's own array functions,
    /// with no bespoke DSL surface needed. `2` = down, `1` = up (mirroring real `ifOperStatus`).
    #[test]
    fn table_metric_is_queryable_from_an_expression_via_rhais_array_functions() {
        let evaluator = AlertEvaluator::new();
        let mut metrics = Metrics::default();
        metrics.insert(
            "if_table",
            MetricValue::Table(vec![
                if_table_row("1", 1, 1),
                if_table_row("2", 2, 2),
                if_table_row("3", 3, 1),
            ]),
        );

        assert!(
            evaluator
                .evaluate_condition(
                    "metrics.if_table.some(|row| row.ifOperStatus == 2)",
                    &facts(),
                    None,
                    None,
                    &metrics,
                    None
                )
                .unwrap(),
            "port 2 is down (ifOperStatus == 2) — `.some()` over the row array must see it"
        );
        assert_eq!(
            evaluator
                .evaluate_facts(
                    "metrics.if_table.filter(|row| row.ifOperStatus == 2).len()",
                    &facts(),
                    None,
                    None,
                    &metrics,
                    None
                )
                .unwrap(),
            serde_json::json!(1),
            "exactly one row is down"
        );

        let mut all_up = Metrics::default();
        all_up.insert(
            "if_table",
            MetricValue::Table(vec![if_table_row("1", 1, 1), if_table_row("2", 2, 1)]),
        );
        assert!(
            !evaluator
                .evaluate_condition(
                    "metrics.if_table.some(|row| row.ifOperStatus == 2)",
                    &facts(),
                    None,
                    None,
                    &all_up,
                    None
                )
                .unwrap(),
            "no row is down — must be false"
        );
    }

    #[test]
    fn renders_message_template() {
        let evaluator = AlertEvaluator::new();
        let mut metrics = Metrics::default();
        metrics.insert("cpu", MetricValue::Int(92));
        let msg = evaluator.render_message(&rule("metrics.cpu > 85"), &facts(), &metrics, None);
        assert_eq!(msg, "cpu at 92%");
    }

    #[test]
    fn renders_facts_ip_token() {
        let evaluator = AlertEvaluator::new();
        let mut r = rule("metrics.cpu > 85");
        r.message = "{facts.ip} cpu at {metrics.cpu}%".into();
        let mut metrics = Metrics::default();
        metrics.insert("cpu", MetricValue::Int(92));
        assert_eq!(
            evaluator.render_message(&r, &facts(), &metrics, None),
            "10.0.0.1 cpu at 92%"
        );
    }

    #[test]
    fn missing_metric_does_not_panic_and_is_treated_as_condition_false() {
        // Rhai returns `()` for a missing map key rather than erroring, and `() > 85`
        // is `false` (Rhai never errors on a type-mismatched comparison, it just says
        // "not equal / not ordered"). Net effect: if a metric failed to poll this cycle,
        // any alert depending on it is treated as *not* firing rather than raising an
        // evaluation error — a deliberately fail-safe default, confirmed here rather
        // than just asserted in a docstring.
        let evaluator = AlertEvaluator::new();
        let metrics = Metrics::default();
        let result = evaluator.evaluate_condition(
            &rule("metrics.cpu > 85").expression,
            &facts(),
            None,
            None,
            &metrics,
            None,
        );
        assert_eq!(result.unwrap(), false);
    }

    /// Contrast with `missing_metric_does_not_panic_and_is_treated_as_condition_false`
    /// above: a metric that's *present* with a value making the expression false is not
    /// "missing" — `references_missing_metric` must say `false` here even though
    /// `evaluate_condition` also says `false`, for the same expression, for a different
    /// reason. Direct fix for the 2026-08-30 device-level "Утеряна" bug — see
    /// `AlertEvaluator::references_missing_metric`'s docs.
    #[test]
    fn present_but_false_metric_is_not_reported_as_missing() {
        let evaluator = AlertEvaluator::new();
        let mut metrics = Metrics::default();
        metrics.insert("cpu", MetricValue::Int(10));
        assert!(!evaluator.references_missing_metric("metrics.cpu > 85", &metrics));
    }

    #[test]
    fn absent_metric_key_is_reported_as_missing() {
        let evaluator = AlertEvaluator::new();
        let metrics = Metrics::default();
        assert!(evaluator.references_missing_metric("metrics.cpu > 85", &metrics));
    }

    /// At least one missing reference among several is enough to flag the whole
    /// expression — matches the roadmap wording ("если хотя бы одна метрика... отсутствует").
    #[test]
    fn one_missing_metric_among_several_is_enough_to_flag_the_expression() {
        let evaluator = AlertEvaluator::new();
        let mut metrics = Metrics::default();
        metrics.insert("cpu", MetricValue::Int(10));
        assert!(
            evaluator.references_missing_metric("metrics.cpu > 85 && metrics.mem > 90", &metrics)
        );
    }

    #[test]
    fn expression_with_no_metric_reference_is_never_missing() {
        let evaluator = AlertEvaluator::new();
        let metrics = Metrics::default();
        assert!(!evaluator.references_missing_metric("facts.ip == \"10.0.0.1\"", &metrics));
    }

    /// Direct user request 2026-08-17: activation/deactivation expressions both see
    /// `facts`, not just `metrics` — needed for e.g. `facts.ip.starts_with("10.")`-style
    /// conditions, and required for `facts_expression` to make sense at all.
    #[test]
    fn condition_expressions_can_reference_facts() {
        let evaluator = AlertEvaluator::new();
        let metrics = Metrics::default();
        assert!(evaluator
            .evaluate_condition(
                "facts.ip == \"10.0.0.1\"",
                &facts(),
                None,
                None,
                &metrics,
                None
            )
            .unwrap());
        assert!(!evaluator
            .evaluate_condition(
                "facts.ip == \"9.9.9.9\"",
                &facts(),
                None,
                None,
                &metrics,
                None
            )
            .unwrap());
    }

    /// `docs/Roadmap.md` "До релиза" item 6 (2026-09-14): a profile's `AlertRule` can now
    /// see the device's *live* reachability inside its own Rhai scope, not just polled
    /// metrics — e.g. suppressing a metric-threshold alert while SNMP itself is down, or
    /// building a distinct alert off `!facts.ping_ok`. Covers all three states each flag
    /// can carry: `Some(true)`, `Some(false)`, and `None` (never checked yet — must read
    /// as Rhai `()`, the same "absent key" contract as an unpolled `metrics.<name>`, not a
    /// hard error).
    #[test]
    fn condition_expressions_can_reference_live_ping_and_snmp_status() {
        let evaluator = AlertEvaluator::new();
        let metrics = Metrics::default();
        assert!(evaluator
            .evaluate_condition(
                "facts.ping_ok == true",
                &facts(),
                Some(true),
                Some(true),
                &metrics,
                None
            )
            .unwrap());
        assert!(evaluator
            .evaluate_condition(
                "facts.ping_ok == false",
                &facts(),
                Some(false),
                Some(true),
                &metrics,
                None
            )
            .unwrap());
        assert!(evaluator
            .evaluate_condition(
                "facts.snmp_ok == false",
                &facts(),
                Some(true),
                Some(false),
                &metrics,
                None
            )
            .unwrap());
        // Never checked yet — reads as `()`, so an equality comparison is simply `false`
        // (Rhai's documented "mismatched operand types compare unequal" behavior for
        // operators, same as an unpolled `metrics.<name>` — see `register_missing_field_safety`'s
        // docs for the narrower case that still needs an explicit guard, method calls).
        assert!(!evaluator
            .evaluate_condition(
                "facts.ping_ok == true",
                &facts(),
                None,
                None,
                &metrics,
                None
            )
            .unwrap());
    }

    /// Direct user request 2026-08-17: "какие facts доставать в момент создания тревоги —
    /// лучше в виде rhai выражения".
    #[test]
    fn facts_expression_captures_a_structured_snapshot() {
        let evaluator = AlertEvaluator::new();
        let mut metrics = Metrics::default();
        metrics.insert("cpu", MetricValue::Int(92));
        let captured = evaluator
            .evaluate_facts(
                r#"#{ip: facts.ip, cpu: metrics.cpu}"#,
                &facts(),
                None,
                None,
                &metrics,
                None,
            )
            .unwrap();
        assert_eq!(captured, serde_json::json!({"ip": "10.0.0.1", "cpu": 92}));
    }

    #[test]
    fn facts_expression_syntax_error_is_an_err_not_a_panic() {
        let evaluator = AlertEvaluator::new();
        let metrics = Metrics::default();
        assert!(evaluator
            .evaluate_facts(
                "this is not valid rhai {{{",
                &facts(),
                None,
                None,
                &metrics,
                None
            )
            .is_err());
    }

    /// Direct user request 2026-08-29 ("тревога по порту"): a row-scoped rule's
    /// `expression`/`deactivation_expression` see a third scope variable, `row`, bound to
    /// one specific row — not the whole table array the way `metrics.if_table` still is.
    #[test]
    fn condition_expressions_can_reference_a_single_row_when_row_scoped() {
        let evaluator = AlertEvaluator::new();
        let metrics = Metrics::default(); // row-scoped rules don't need the row present in `metrics` too
        let down = if_table_row("3", 3, 2);
        let up = if_table_row("3", 3, 1);

        assert!(evaluator
            .evaluate_condition(
                "row.ifOperStatus == 2",
                &facts(),
                None,
                None,
                &metrics,
                Some(&down)
            )
            .unwrap());
        assert!(!evaluator
            .evaluate_condition(
                "row.ifOperStatus == 2",
                &facts(),
                None,
                None,
                &metrics,
                Some(&up)
            )
            .unwrap());
    }

    #[test]
    fn facts_expression_can_capture_row_fields_when_row_scoped() {
        let evaluator = AlertEvaluator::new();
        let metrics = Metrics::default();
        let row = if_table_row("3", 3, 2);
        let captured = evaluator
            .evaluate_facts(
                "#{ifIndex: row.ifIndex, index: row.index}",
                &facts(),
                None,
                None,
                &metrics,
                Some(&row),
            )
            .unwrap();
        assert_eq!(captured, serde_json::json!({"ifIndex": 3, "index": "3"}));
    }

    #[test]
    fn message_supports_row_field_tokens_when_row_scoped() {
        let evaluator = AlertEvaluator::new();
        let mut r = rule("row.ifOperStatus == 2");
        r.row_metric = Some("if_table".into());
        r.message = "Порт ifIndex={row.ifIndex} (строка {row.index}) недоступен".into();
        let metrics = Metrics::default();
        let row = if_table_row("3", 3, 2);
        assert_eq!(
            evaluator.render_message(&r, &facts(), &metrics, Some(&row)),
            "Порт ifIndex=3 (строка 3) недоступен"
        );
    }

    /// `evaluate_row_key`'s default (no `row_key_expression` set) — the row's own SNMP
    /// index, no Rhai evaluation needed.
    #[test]
    fn row_key_defaults_to_the_rows_own_index() {
        let evaluator = AlertEvaluator::new();
        let metrics = Metrics::default();
        let row = if_table_row("7", 7, 1);
        assert_eq!(
            evaluator
                .evaluate_row_key(None, &facts(), &metrics, &row)
                .unwrap(),
            "7"
        );
    }

    /// Direct user request 2026-08-29: identity should be able to survive a port being
    /// renumbered — key by `ifDescr` instead of the default `row.index`/`ifIndex`.
    #[test]
    fn row_key_expression_can_key_by_a_field_other_than_index() {
        let evaluator = AlertEvaluator::new();
        let metrics = Metrics::default();
        let mut fields = BTreeMap::new();
        fields.insert("ifDescr".to_string(), MetricValue::Str("Gi0/3".into()));
        let row = MetricTableRow {
            index: "3".to_string(),
            fields,
        };
        assert_eq!(
            evaluator
                .evaluate_row_key(Some("row.ifDescr"), &facts(), &metrics, &row)
                .unwrap(),
            "Gi0/3"
        );
    }

    #[test]
    fn row_key_bare_scalar_expression_is_stringified_without_string_function() {
        let evaluator = AlertEvaluator::new();
        let metrics = Metrics::default();
        let row = if_table_row("7", 7, 1);
        assert_eq!(
            evaluator
                .evaluate_row_key(Some("row.ifIndex"), &facts(), &metrics, &row)
                .unwrap(),
            "7"
        );
    }

    #[test]
    fn row_key_expression_syntax_error_is_an_err_not_a_panic() {
        let evaluator = AlertEvaluator::new();
        let metrics = Metrics::default();
        let row = if_table_row("3", 3, 1);
        assert!(evaluator
            .evaluate_row_key(Some("this is not valid rhai {{{"), &facts(), &metrics, &row)
            .is_err());
    }

    #[test]
    fn trap_key_none_expression_means_singleton_not_an_error() {
        let evaluator = AlertEvaluator::new();
        let varbinds = Metrics::default();
        assert_eq!(
            evaluator
                .evaluate_trap_key(None, &facts(), &varbinds)
                .unwrap(),
            None
        );
    }

    /// No `string(...)`/`to_string(...)` wrapper needed in the expression itself — same as
    /// `evaluate_row_key`, the *Rust* side stringifies whatever `Dynamic` the expression
    /// produces, so a bare field reference already works for any scalar type. (Caught live
    /// while writing this test: `string(varbinds.if_index)`, the form used throughout this
    /// feature's design discussion, is not actually valid Rhai here — `Function not found:
    /// string (i64)` — every profile example needs the bare form instead.)
    #[test]
    fn trap_key_computes_from_varbinds_not_metrics_or_row() {
        let evaluator = AlertEvaluator::new();
        let mut fields = BTreeMap::new();
        fields.insert("if_index".to_string(), MetricValue::Int(3));
        let varbinds = Metrics(fields);
        assert_eq!(
            evaluator
                .evaluate_trap_key(Some("varbinds.if_index"), &facts(), &varbinds)
                .unwrap(),
            Some("3".to_string())
        );
        assert!(evaluator
            .evaluate_trap_key(Some("string(varbinds.if_index)"), &facts(), &varbinds)
            .is_err());
    }

    #[test]
    fn trap_key_expression_syntax_error_is_an_err_not_a_panic() {
        let evaluator = AlertEvaluator::new();
        let varbinds = Metrics::default();
        assert!(evaluator
            .evaluate_trap_key(Some("this is not valid rhai {{{"), &facts(), &varbinds)
            .is_err());
    }

    #[test]
    fn syslog_key_none_expression_means_singleton_not_an_error() {
        let evaluator = AlertEvaluator::new();
        let fields = Metrics::default();
        assert_eq!(
            evaluator
                .evaluate_syslog_key(None, &facts(), &fields)
                .unwrap(),
            None
        );
    }

    #[test]
    fn syslog_key_computes_from_fields_not_metrics_or_row() {
        let evaluator = AlertEvaluator::new();
        let mut fields = BTreeMap::new();
        fields.insert("hostname".to_string(), MetricValue::Str("sw-vrn-01".into()));
        fields.insert("severity".to_string(), MetricValue::Int(3));
        let fields = Metrics(fields);
        assert_eq!(
            evaluator
                .evaluate_syslog_key(Some("fields.hostname"), &facts(), &fields)
                .unwrap(),
            Some("sw-vrn-01".to_string())
        );
        assert_eq!(
            evaluator
                .evaluate_syslog_key(Some("fields.severity"), &facts(), &fields)
                .unwrap(),
            Some("3".to_string())
        );
    }

    #[test]
    fn syslog_key_expression_syntax_error_is_an_err_not_a_panic() {
        let evaluator = AlertEvaluator::new();
        let fields = Metrics::default();
        assert!(evaluator
            .evaluate_syslog_key(Some("this is not valid rhai {{{"), &facts(), &fields)
            .is_err());
    }

    /// 2026-09-17 audit finding #3 — same fix as `matcher::tests::
    /// validate_expression_accepts_well_formed_syntax_and_rejects_broken_syntax`, for the
    /// alert-rule side of the same gap.
    #[test]
    fn validate_expression_accepts_well_formed_syntax_and_rejects_broken_syntax() {
        let evaluator = AlertEvaluator::new();
        assert!(evaluator.validate_expression("metrics.cpu > 90").is_ok());
        assert!(evaluator
            .validate_expression("metrics.cpu > ((( broken rhai")
            .is_err());
    }
    #[test]
    fn capability_action_conditions_are_typed_scoped_and_lifecycle_specific() {
        let evaluator = AlertEvaluator::new();
        let tracker = discovery_core::AlertStateTracker::new();
        let discovery_core::AlertTransition::Activated(mut a) = tracker.observe(
            uuid::Uuid::new_v4(),
            "127.0.0.1",
            "rule",
            None,
            discovery_core::AlertLevel::Warning,
            "test".into(),
            None,
            true,
            false,
            None,
            chrono::Duration::zero(),
            Utc::now(),
        ) else {
            panic!()
        };
        a.details.policy.actions = vec![discovery_core::AlertAction {
            on: discovery_core::AlertLifecycle::Acknowledged,
            action: discovery_core::payload::OperatorAction::Test,
            condition: Some("alert.acknowledged_at != ()".into()),
        }];
        assert!(evaluator
            .applicable_actions(&a, discovery_core::AlertLifecycle::Activated)
            .unwrap()
            .is_empty());
        assert!(evaluator
            .applicable_actions(&a, discovery_core::AlertLifecycle::Acknowledged)
            .unwrap()
            .is_empty());
        a.acknowledged_at = Some(Utc::now());
        assert_eq!(
            evaluator
                .applicable_actions(&a, discovery_core::AlertLifecycle::Acknowledged)
                .unwrap(),
            vec![discovery_core::payload::OperatorAction::Test]
        );
        a.details.policy.actions[0].condition = Some("7".into());
        assert!(evaluator
            .applicable_actions(&a, discovery_core::AlertLifecycle::Acknowledged)
            .is_err());
        let mut r = rule("true");
        r.message = "{facts.ip} {event.port} {previous}".into();
        assert_eq!(
            evaluator.render_context_message(
                &r,
                &facts(),
                &Metrics::default(),
                None,
                &serde_json::json!({"event":{"port":"eth0"},"previous":"down"})
            ),
            format!("{} eth0 down", facts().ip)
        );
    }
}
