//! Evaluates a `discovery_config_store::GroupAlertRule`'s two Rhai expressions against one
//! `discovery_core::Alert`'s `{name, level, facts}` — the DSL half of group-alert
//! suppression (2026-09-16, `docs/Roadmap.md`'s "Топология → групповые тревоги → RADIUS"
//! item 3). Same shape as `crate::topology::TopologyEvaluator` (that's why this lives here,
//! namespaced but not re-exported, rather than its own crate — see that module's docs for
//! the reasoning, which applies identically here).
//!
//! **Why two separate expressions, not one "participates in group suppression" flag**:
//! direct user requirement — an active-but-unrelated alert on an upstream device (e.g. High
//! CPU) must not suppress an independent alert on a downstream device (e.g. Port Down) just
//! because they coincide in time and topology direction. `cause_expression` is evaluated
//! against the upstream candidate, `effect_expression` against the downstream candidate,
//! independently — `discovery_agent::group_alert::compute_suppression` only treats a pair
//! as cause/effect when *both* match under the same rule.

use discovery_core::Alert;
use rhai::{Dynamic, Engine, Map, Scope};

use crate::util::register_missing_field_safety;

/// Evaluates one rule's `cause_expression`/`effect_expression` against an `Alert`.
/// Stateless beyond the compiled `Engine` — safe to share one instance across every rule
/// and every alert (`discovery_agent::group_alert`'s sweep loop holds one).
pub struct GroupAlertEvaluator {
    engine: Engine,
}

impl Default for GroupAlertEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

impl GroupAlertEvaluator {
    pub fn new() -> Self {
        let mut engine = Engine::new();
        engine.set_max_operations(50_000); // same bound as `AlertEvaluator`/`TopologyEvaluator`
        register_missing_field_safety(&mut engine); // discovery-rhai-dsl-safety
        Self { engine }
    }

    /// `name`/`level` are always present strings (an `Alert` always has both); `facts` is
    /// whatever `Alert::facts` currently holds. **Deliberately an empty `Map`, not bare
    /// `Dynamic::UNIT`, when absent** — real bug found by this module's own tests: unlike a
    /// missing *key inside* a `Map` (which Rhai itself reads as `()`, the convention every
    /// other DSL scope in this crate relies on — see `crate::util::facts_to_map`, which
    /// always returns a `Map`, never a bare unit, for exactly this reason), a property
    /// access on a bare `()` — `facts.role` when `facts` itself is unit — is a hard
    /// `EvalAltResult` before `register_missing_field_safety`'s `contains`/`starts_with`/
    /// `ends_with` no-op guards even get a chance to run. An empty `Map` makes `facts.role`
    /// degrade to `()` the normal way, restoring the "absent field never hard-errors"
    /// invariant for an alert whose rule never declared a `facts_expression` at all (not
    /// just one where a specific field is missing from an otherwise-present facts object).
    fn scope_for(alert: &Alert) -> Scope<'static> {
        let mut scope = Scope::new();
        scope.push("name", alert.name.clone());
        scope.push("level", alert.level.as_str().to_string());
        scope.push(
            "facts",
            alert
                .facts
                .as_ref()
                .map(json_to_dynamic)
                .unwrap_or_else(|| Dynamic::from(Map::new())),
        );
        scope
    }

    /// `None` on a genuine Rhai error (bad syntax, a non-bool result) — logged and skipped
    /// by the caller, same "one broken rule must not block every other enabled rule" posture
    /// `TopologyRecomputeHandler`/`AlertEvalHandler` already take. Not `anyhow::Result`,
    /// unlike `TopologyEvaluator::evaluate_my_key`: there is no legitimate "field absent"
    /// case here worth distinguishing from "authoring mistake" — `name`/`level` always
    /// exist, so a non-bool result only ever means the expression itself is wrong.
    ///
    /// Takes the raw expression string, not a `discovery_config_store::GroupAlertRule` —
    /// this crate has no dependency on `discovery-config-store` (that crate depends on
    /// *this* one, for `discovery_dsl::AlertRule`/`ProfileFile`), same reason
    /// `TopologyEvaluator::evaluate_my_key` takes `expression: &str` rather than a
    /// `TopologyRule`.
    pub fn evaluate_cause(&self, expression: &str, alert: &Alert) -> Option<bool> {
        self.eval_bool(expression, alert)
    }

    pub fn evaluate_effect(&self, expression: &str, alert: &Alert) -> Option<bool> {
        self.eval_bool(expression, alert)
    }

    fn eval_bool(&self, expression: &str, alert: &Alert) -> Option<bool> {
        let mut scope = Self::scope_for(alert);
        self.engine
            .eval_with_scope::<bool>(&mut scope, expression)
            .ok()
    }

    /// Syntax-only check — same `engine.compile(...)` pattern as
    /// `TopologyEvaluator::validate_expression`, used by `discovery-web`'s rule editor
    /// endpoint to reject a broken expression at save time.
    pub fn validate_expression(&self, expression: &str) -> anyhow::Result<()> {
        self.engine
            .compile(expression)
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("{e}"))
    }
}

/// The inverse of `crate::util::dynamic_to_json` — needed here because `Alert::facts` is
/// already-persisted `serde_json::Value`, not a live Rhai `Dynamic` the way `metrics`/
/// `facts` are for `AlertEvaluator`/`TopologyEvaluator`. Deliberately narrow (mirrors
/// exactly the shapes `dynamic_to_json` itself produces — null/bool/number/string/array/
/// object), not a general `serde_json`-feature-powered conversion — same reasoning that
/// function's own docs give.
fn json_to_dynamic(value: &serde_json::Value) -> Dynamic {
    match value {
        serde_json::Value::Null => Dynamic::UNIT,
        serde_json::Value::Bool(b) => Dynamic::from(*b),
        serde_json::Value::Number(n) => n
            .as_i64()
            .map(Dynamic::from)
            .or_else(|| n.as_f64().map(Dynamic::from))
            .unwrap_or(Dynamic::UNIT),
        serde_json::Value::String(s) => Dynamic::from(s.clone()),
        serde_json::Value::Array(arr) => {
            Dynamic::from(arr.iter().map(json_to_dynamic).collect::<rhai::Array>())
        }
        serde_json::Value::Object(obj) => {
            let mut map = Map::new();
            for (k, v) in obj {
                map.insert(k.as_str().into(), json_to_dynamic(v));
            }
            Dynamic::from(map)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use discovery_core::{AlertLevel, AlertState};

    fn alert(name: &str, level: AlertLevel, facts: Option<serde_json::Value>) -> Alert {
        let now = chrono::Utc::now();
        Alert {
            details: Default::default(),
            id: uuid::Uuid::new_v4(),
            device_id: uuid::Uuid::new_v4(),
            device_ip: "10.0.0.1".to_string(),
            name: name.to_string(),
            row_key: None,
            level,
            message: "test".to_string(),
            state: AlertState::Active,
            facts,
            first_seen: now,
            last_seen: now,
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

    #[test]
    fn matches_by_name() {
        let evaluator = GroupAlertEvaluator::new();
        let expr = r#"name == "device_unreachable""#;
        assert_eq!(
            evaluator.evaluate_cause(
                expr,
                &alert("device_unreachable", AlertLevel::Critical, None)
            ),
            Some(true)
        );
        assert_eq!(
            evaluator.evaluate_cause(expr, &alert("high_cpu", AlertLevel::Critical, None)),
            Some(false)
        );
    }

    #[test]
    fn high_cpu_cause_does_not_match_an_unrelated_port_down_effect_rule() {
        // The exact scenario that motivated separate cause/effect expressions — see this
        // module's top docs.
        let evaluator = GroupAlertEvaluator::new();
        let cause_expr = r#"name == "device_unreachable""#;
        let effect_expr = r#"name == "device_unreachable""#;
        let high_cpu = alert("high_cpu", AlertLevel::Warning, None);
        let port_down = alert("port_down", AlertLevel::Critical, None);
        assert_eq!(evaluator.evaluate_cause(cause_expr, &high_cpu), Some(false));
        assert_eq!(
            evaluator.evaluate_effect(effect_expr, &port_down),
            Some(false)
        );
    }

    #[test]
    fn level_is_available_in_scope() {
        let evaluator = GroupAlertEvaluator::new();
        let expr = r#"level == "critical""#;
        assert_eq!(
            evaluator.evaluate_cause(expr, &alert("x", AlertLevel::Critical, None)),
            Some(true)
        );
        assert_eq!(
            evaluator.evaluate_cause(expr, &alert("x", AlertLevel::Warning, None)),
            Some(false)
        );
    }

    #[test]
    fn facts_are_available_in_scope_when_present() {
        let evaluator = GroupAlertEvaluator::new();
        let a = alert(
            "x",
            AlertLevel::Info,
            Some(serde_json::json!({"role": "core"})),
        );
        assert_eq!(
            evaluator.evaluate_cause(r#"facts.role == "core""#, &a),
            Some(true)
        );
    }

    #[test]
    fn missing_facts_degrades_to_false_not_an_error_via_missing_field_safety() {
        let evaluator = GroupAlertEvaluator::new();
        let a = alert("x", AlertLevel::Info, None);
        assert_eq!(
            evaluator.evaluate_cause(r#"facts.role.contains("core")"#, &a),
            Some(false)
        );
    }

    #[test]
    fn a_genuine_syntax_error_evaluates_to_none() {
        let evaluator = GroupAlertEvaluator::new();
        assert_eq!(
            evaluator.evaluate_cause("name == (((", &alert("x", AlertLevel::Info, None)),
            None
        );
    }

    #[test]
    fn a_non_bool_result_evaluates_to_none() {
        let evaluator = GroupAlertEvaluator::new();
        assert_eq!(
            evaluator.evaluate_cause(r#""not a bool""#, &alert("x", AlertLevel::Info, None)),
            None
        );
    }

    #[test]
    fn validate_expression_accepts_well_formed_syntax_and_rejects_broken_syntax() {
        let evaluator = GroupAlertEvaluator::new();
        assert!(evaluator
            .validate_expression(r#"name == "device_unreachable""#)
            .is_ok());
        assert!(evaluator.validate_expression("name == (((").is_err());
    }
}
