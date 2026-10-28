//! Evaluates a `discovery_config_store::TopologyRule`'s two Rhai expressions against one
//! device's facts/metrics — the DSL half of the configurable-topology mechanism (direct
//! user request 2026-09-16: this product is sold to many providers with very different
//! network gear, so topology has to be provider-authored rules, not a hardcoded protocol
//! like LLDP/CDP). Same `{facts, metrics}` scope convention as `AlertEvaluator`/
//! `ProfileMatcher`, reusing `crate::util`'s shared helpers directly (this lives inside
//! `discovery-dsl` rather than its own crate specifically so it can see those
//! `pub(crate)` helpers without re-exporting them).
//!
//! The resulting `my_key`/`claimed_neighbors` values are only ever compared for
//! *equality* against other devices' own values (`discovery_topology::TopologyStore`'s
//! join) — never interpreted semantically — so a device-agnostic Rhai `Dynamic` ->
//! `String` conversion here is enough; no protocol-specific decoding belongs in this
//! crate.

use std::collections::BTreeSet;

use discovery_core::{DeviceFacts, Metrics};
use rhai::{Dynamic, Engine, Scope};

use crate::util::{
    facts_to_map, metric_reference_regex, metrics_to_map, register_missing_field_safety,
};

/// Evaluates one rule's `my_key_expression`/`claimed_neighbors_expression`. Stateless
/// beyond the compiled `Engine` — safe to share one instance across every rule and every
/// device (`discovery_agent::handlers::TopologyRecomputeHandler` holds one `Arc` of it).
pub struct TopologyEvaluator {
    engine: Engine,
}

impl Default for TopologyEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

impl TopologyEvaluator {
    pub fn new() -> Self {
        let mut engine = Engine::new();
        engine.set_max_operations(50_000); // same bound as `AlertEvaluator::new` — a
                                           // malformed/malicious rule can't hang a worker
        register_missing_field_safety(&mut engine); // discovery-rhai-dsl-safety
                                                    // `register_missing_field_safety` only covers `contains`/`starts_with`/`ends_with`
                                                    // — real gap found live while writing this evaluator's own tests: a
                                                    // `claimed_neighbors_expression` of the documented shape
                                                    // (`metrics.some_table.map(|row| ...)`) hard-errors with "Function not found: map"
                                                    // the moment the referenced table metric is entirely absent (`()`), not just
                                                    // empty, since `.map` is a method call on `()` same as `.contains` is — Rhai's
                                                    // "missing map key is unit" leniency covers operators, never method dispatch (see
                                                    // `register_missing_field_safety`'s own docs on this same distinction). Scoped to
                                                    // *this* engine only, not the shared helper: `AlertEvaluator`/`ProfileMatcher`'s
                                                    // existing `.filter`/`.some`/`.all` idioms on `()` have their own, different
                                                    // "vacuous truth" tradeoffs (see discovery-rhai-dsl-safety's "guard makes it safe,
                                                    // not meaningful" caution) that are out of scope to change here — `map` is the
                                                    // only array method this crate's topology expressions are documented to use.
        engine.register_fn("map", |_: (), _: rhai::FnPtr| -> rhai::Array {
            rhai::Array::new()
        });
        Self { engine }
    }

    fn scope_for(facts: &DeviceFacts, metrics: &Metrics) -> Scope<'static> {
        let mut scope = Scope::new();
        scope.push("facts", facts_to_map(facts, None, None));
        scope.push("metrics", metrics_to_map(metrics));
        scope
    }

    /// `()` — the metric(s) `my_key_expression` references are absent for this device
    /// (never polled, or this device's profile doesn't declare them at all) — means this
    /// device simply doesn't participate in this rule, returned as `None`, not an error.
    /// A genuine Rhai error (bad syntax, etc.) is still a hard `Err` — same "fail safe on
    /// a legitimately-absent field, fail loud on a broken expression" split
    /// `AlertEvaluator::evaluate_condition` already draws.
    pub fn evaluate_my_key(
        &self,
        expression: &str,
        facts: &DeviceFacts,
        metrics: &Metrics,
    ) -> anyhow::Result<Option<String>> {
        let mut scope = Self::scope_for(facts, metrics);
        let result: Dynamic = self
            .engine
            .eval_with_scope(&mut scope, expression)
            .map_err(|e| anyhow::anyhow!("my_key expression error: {e}"))?;
        Ok(dynamic_to_key(result))
    }

    /// `None` (`rank_expression` not configured) or `()` (the metric(s) it references are
    /// absent for this device) both mean "this device's direction under this rule is
    /// undetermined" — `None`, not an error. A successfully-evaluated non-numeric result
    /// (a rule-authoring mistake — a string, bool, map, ...) also degrades to `None` rather
    /// than erroring: unlike `dynamic_to_key`'s join-key case, a wrong rank can only
    /// mislabel which side of an *already-confirmed* edge is upstream (`resolve_edges`'s
    /// join is untouched by this), never fabricate an edge between two devices that aren't
    /// otherwise connected — and erroring here would otherwise abort this whole rule's
    /// `apply_recompute` for the tick via the caller's existing warn-and-skip loop
    /// (`discovery_agent::topology_recompute::TopologyRecomputeHandler`), silently
    /// regressing that rule's already-working `my_key`/`claimed_neighbors` data too because
    /// of an unrelated, optional field. A genuine Rhai syntax/runtime error is still a hard
    /// `Err`, same split `evaluate_my_key` draws (caught the same way by
    /// `validate_expression` at save time).
    pub fn evaluate_rank(
        &self,
        expression: Option<&str>,
        facts: &DeviceFacts,
        metrics: &Metrics,
    ) -> anyhow::Result<Option<f64>> {
        let Some(expression) = expression else {
            return Ok(None);
        };
        let mut scope = Self::scope_for(facts, metrics);
        let result: Dynamic = self
            .engine
            .eval_with_scope(&mut scope, expression)
            .map_err(|e| anyhow::anyhow!("rank expression error: {e}"))?;
        Ok(dynamic_to_rank(result))
    }

    /// Syntax-only check — compiles `expression` without evaluating it against any
    /// device's data. Used by `discovery-web`'s rule editor endpoint to reject a broken
    /// expression at save time, rather than let it silently warn-and-skip on every
    /// recompute tick forever (see `discovery_agent::topology_recompute`'s "a malformed
    /// expression in *this* rule must not block every other enabled rule" handling — that
    /// posture is the right runtime behavior, but it also means a typo could otherwise go
    /// unnoticed indefinitely without this earlier check).
    pub fn validate_expression(&self, expression: &str) -> anyhow::Result<()> {
        self.engine
            .compile(expression)
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// `None` (`claimed_neighbors_expression` not configured) or `()` (the metric(s) it
    /// references are absent for this device) both mean "this device claims no
    /// neighbors under this rule right now" — an empty list, not an error. A non-array,
    /// non-unit result (a rule authoring mistake — e.g. forgetting `.map(...)`) is
    /// likewise treated as "no claims" rather than erroring the whole recompute: one
    /// malformed rule must not block every other enabled rule from recomputing this
    /// device, same "don't let one bad thing take down everything else" posture
    /// `SnmpClient::get_multi`'s per-OID fallback already takes for a batched poll.
    pub fn evaluate_claimed_neighbors(
        &self,
        expression: Option<&str>,
        facts: &DeviceFacts,
        metrics: &Metrics,
    ) -> anyhow::Result<Vec<String>> {
        let Some(expression) = expression else {
            return Ok(Vec::new());
        };
        let mut scope = Self::scope_for(facts, metrics);
        let result: Dynamic = self
            .engine
            .eval_with_scope(&mut scope, expression)
            .map_err(|e| anyhow::anyhow!("claimed_neighbors expression error: {e}"))?;
        if result.is_unit() {
            return Ok(Vec::new());
        }
        let Ok(array) = result.into_array() else {
            return Ok(Vec::new());
        };
        Ok(array.into_iter().filter_map(dynamic_to_key).collect())
    }
}

/// `()` -> `None`; a string -> itself; anything else -> `None` (see
/// `evaluate_claimed_neighbors`'s docs on why a malformed element degrades rather than
/// erroring) rather than falling back to Rhai's own `to_string()` rendering — unlike
/// `crate::util::dynamic_to_json`'s "stringify anything odd" fallback (used for a facts
/// expression's *display* value), a key that quietly stringifies a non-string `Dynamic`
/// (e.g. a `Map`'s debug rendering) risks becoming a key that never legitimately matches
/// anything else, which is a worse failure mode here than "no key at all".
fn dynamic_to_key(value: Dynamic) -> Option<String> {
    if value.is_unit() {
        return None;
    }
    value.into_string().ok()
}

/// `()` -> `None`; an int or float -> itself as `f64`; anything else -> `None` (see
/// `evaluate_rank`'s docs on why degrading here, unlike `dynamic_to_key`, is the safe
/// choice — a wrong rank can only mislabel direction on an edge that's already otherwise
/// confirmed, never fabricate one). Same `as_int()`-then-`as_float()` coercion order
/// `crate::util::dynamic_to_json` already uses for the analogous "render whatever numeric
/// type Rhai produced" case.
fn dynamic_to_rank(value: Dynamic) -> Option<f64> {
    if value.is_unit() {
        return None;
    }
    if let Ok(i) = value.as_int() {
        return Some(i as f64);
    }
    value.as_float().ok()
}

/// Auto-detects the `metrics.<name>` references in a rule's expressions — what
/// `discovery_agent::handlers::MetricPollHandler` watches to decide whether a fresh
/// metric poll should trigger a `QueueKind::TopologyRecompute` for that device. Used
/// when `TopologyRule::watched_metrics` is `None`; see that field's docs for the
/// explicit-override escape hatch. Shares `crate::util::metric_reference_regex` with
/// `AlertEvaluator::references_missing_metric` — same scan, different purpose.
pub fn referenced_metrics(expressions: &[&str]) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for expression in expressions {
        for caps in metric_reference_regex().captures_iter(expression) {
            set.insert(caps[1].to_string());
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;
    use discovery_core::MetricValue;

    fn facts() -> DeviceFacts {
        DeviceFacts {
            ip: "10.0.0.1".to_string(),
        }
    }

    fn metrics_with(pairs: &[(&str, MetricValue)]) -> Metrics {
        let mut metrics = Metrics::default();
        for (name, value) in pairs {
            metrics.insert(*name, value.clone());
        }
        metrics
    }

    #[test]
    fn my_key_resolves_a_present_scalar_metric() {
        let evaluator = TopologyEvaluator::new();
        let metrics = metrics_with(&[(
            "lldp_chassis_id",
            MetricValue::Str("aa:bb:cc:dd:ee:ff".to_string()),
        )]);
        let key = evaluator
            .evaluate_my_key("metrics.lldp_chassis_id", &facts(), &metrics)
            .unwrap();
        assert_eq!(key, Some("aa:bb:cc:dd:ee:ff".to_string()));
    }

    #[test]
    fn my_key_is_none_when_the_referenced_metric_is_absent_not_an_error() {
        let evaluator = TopologyEvaluator::new();
        let key = evaluator
            .evaluate_my_key("metrics.lldp_chassis_id", &facts(), &Metrics::default())
            .unwrap();
        assert_eq!(
            key, None,
            "a device whose profile never polls this metric simply doesn't participate in the rule"
        );
    }

    #[test]
    fn claimed_neighbors_extracts_a_list_from_a_table_metric() {
        use discovery_core::MetricTableRow;
        use std::collections::BTreeMap;

        let evaluator = TopologyEvaluator::new();
        let mut fields_b = BTreeMap::new();
        fields_b.insert(
            "chassis_id".to_string(),
            MetricValue::Str("bb:bb:bb:bb:bb:bb".to_string()),
        );
        let mut fields_c = BTreeMap::new();
        fields_c.insert(
            "chassis_id".to_string(),
            MetricValue::Str("cc:cc:cc:cc:cc:cc".to_string()),
        );
        let rows = vec![
            MetricTableRow {
                index: "0.1.1".to_string(),
                fields: fields_b,
            },
            MetricTableRow {
                index: "0.2.1".to_string(),
                fields: fields_c,
            },
        ];
        let metrics = metrics_with(&[("lldp_rem_table", MetricValue::Table(rows))]);

        let claimed = evaluator
            .evaluate_claimed_neighbors(
                Some("metrics.lldp_rem_table.map(|row| row.chassis_id)"),
                &facts(),
                &metrics,
            )
            .unwrap();
        assert_eq!(
            claimed,
            vec![
                "bb:bb:bb:bb:bb:bb".to_string(),
                "cc:cc:cc:cc:cc:cc".to_string()
            ]
        );
    }

    #[test]
    fn claimed_neighbors_is_empty_when_expression_absent() {
        let evaluator = TopologyEvaluator::new();
        let claimed = evaluator
            .evaluate_claimed_neighbors(None, &facts(), &Metrics::default())
            .unwrap();
        assert!(claimed.is_empty());
    }

    #[test]
    fn claimed_neighbors_is_empty_when_the_referenced_table_metric_is_absent() {
        let evaluator = TopologyEvaluator::new();
        let claimed = evaluator
            .evaluate_claimed_neighbors(
                Some("metrics.lldp_rem_table.map(|row| row.chassis_id)"),
                &facts(),
                &Metrics::default(),
            )
            .unwrap();
        assert!(
            claimed.is_empty(),
            "missing table metric must degrade to an empty claim list, not a hard error"
        );
    }

    #[test]
    fn claimed_neighbors_on_an_empty_table_is_an_empty_list_not_missing() {
        let evaluator = TopologyEvaluator::new();
        let metrics = metrics_with(&[("lldp_rem_table", MetricValue::Table(vec![]))]);
        let claimed = evaluator
            .evaluate_claimed_neighbors(
                Some("metrics.lldp_rem_table.map(|row| row.chassis_id)"),
                &facts(),
                &metrics,
            )
            .unwrap();
        assert!(claimed.is_empty());
    }

    #[test]
    fn rank_resolves_a_present_numeric_metric() {
        let evaluator = TopologyEvaluator::new();
        let metrics = metrics_with(&[("role_value", MetricValue::Int(0))]);
        let rank = evaluator
            .evaluate_rank(Some("metrics.role_value"), &facts(), &metrics)
            .unwrap();
        assert_eq!(rank, Some(0.0));
    }

    #[test]
    fn rank_is_none_when_expression_is_absent() {
        let evaluator = TopologyEvaluator::new();
        let rank = evaluator
            .evaluate_rank(None, &facts(), &Metrics::default())
            .unwrap();
        assert_eq!(rank, None);
    }

    #[test]
    fn rank_is_none_when_the_referenced_metric_is_absent_not_an_error() {
        let evaluator = TopologyEvaluator::new();
        let rank = evaluator
            .evaluate_rank(Some("metrics.role_value"), &facts(), &Metrics::default())
            .unwrap();
        assert_eq!(
            rank, None,
            "a device whose profile never polls this metric simply has no rank under this rule"
        );
    }

    #[test]
    fn rank_degrades_to_none_on_a_non_numeric_successful_result_rather_than_erroring() {
        let evaluator = TopologyEvaluator::new();
        let metrics = metrics_with(&[("role_value", MetricValue::Str("core".to_string()))]);
        let rank = evaluator
            .evaluate_rank(Some("metrics.role_value"), &facts(), &metrics)
            .unwrap();
        assert_eq!(rank, None, "a rank-authoring mistake must not error the whole recompute — it just leaves direction undetermined");
    }

    #[test]
    fn a_genuine_rank_syntax_error_is_still_a_hard_error() {
        let evaluator = TopologyEvaluator::new();
        assert!(evaluator
            .evaluate_rank(Some("metrics.((("), &facts(), &Metrics::default())
            .is_err());
    }

    #[test]
    fn a_genuine_syntax_error_is_a_hard_error_not_a_silent_none() {
        let evaluator = TopologyEvaluator::new();
        assert!(evaluator
            .evaluate_my_key("metrics.(((", &facts(), &Metrics::default())
            .is_err());
    }

    #[test]
    fn validate_expression_accepts_well_formed_syntax_and_rejects_broken_syntax() {
        let evaluator = TopologyEvaluator::new();
        assert!(evaluator
            .validate_expression("metrics.lldp_chassis_id")
            .is_ok());
        assert!(evaluator
            .validate_expression("metrics.lldp_rem_table.map(|row| row.chassis_id)")
            .is_ok());
        assert!(evaluator.validate_expression("metrics.(((").is_err());
    }

    #[test]
    fn referenced_metrics_scans_both_expressions_and_dedupes() {
        let found = referenced_metrics(&[
            "metrics.lldp_chassis_id",
            "metrics.lldp_rem_table.map(|row| row.chassis_id) + metrics.lldp_chassis_id",
        ]);
        assert_eq!(
            found,
            BTreeSet::from(["lldp_chassis_id".to_string(), "lldp_rem_table".to_string()])
        );
    }
}
