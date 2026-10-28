use std::sync::OnceLock;

use discovery_core::{DeviceFacts, MetricTableRow, MetricValue, Metrics};
use regex::Regex;
use rhai::{Dynamic, Engine, Map};

/// Matches a `metrics.<name>` reference inside a Rhai expression string — compiled once
/// (not per call) via `std::sync::OnceLock` rather than pulling in a new `once_cell`/
/// `lazy_static` dependency this workspace doesn't otherwise use. Shared by
/// `alerts::AlertEvaluator::references_missing_metric` and
/// `topology::referenced_metrics` — both need the same "which `metrics.<name>` does this
/// expression's text mention" scan, one for "is this metric missing" (a per-evaluation
/// hot-path check), the other for "which metrics should trigger a recompute of this rule"
/// (evaluated once per rule edit, not hot at all, but no reason to duplicate the pattern).
pub(crate) fn metric_reference_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"metrics\.([A-Za-z_][A-Za-z0-9_]*)").unwrap())
}

/// Registers `()`-typed fallbacks for the handful of `ImmutableString` methods this
/// project's expressions actually call on a bag lookup that might be missing.
///
/// **Real bug, found live 2026-08-16** (during the refactor that made `sys_descr`/
/// `sys_object_id`/etc. genuinely-optional `Metrics` entries instead of always-present
/// `DeviceFacts` fields): Rhai's documented "missing map key evaluates to `()`, not an
/// error" behavior only actually holds for *operators* (`+`, `>`, `==`, ...), which Rhai
/// special-cases to tolerate mismatched/unit operands. **Method calls are not special-
/// cased** — `().contains("x")` is a hard `EvalAltResult::ErrorFunctionNotFound`, not a
/// silent `false`, because Rhai dispatches method syntax as an ordinary function call on
/// the receiver's concrete type, and no such function exists for `()`. This was invisible
/// before this refactor because `device.sys_descr`-style fields were always at least `""`
/// (`SnmpPollHandler`'s old unconditional fetch defaulted failures to an empty string),
/// never actually `()`. Once identity fields became optional bag entries, any
/// `match.expression`/dedup/alert expression calling `.contains()`/`.starts_with()`/
/// `.ends_with()` on a field a given subnet simply never configured would hard-error the
/// *entire* evaluation — for `ProfileMatcher::match_profile` specifically, that means
/// erroring out of the whole priority-ordered scan, never even reaching a lower-priority
/// catch-all profile. Registering these as safe no-ops on `()` restores the "absent field
/// degrades gracefully" invariant this project has always documented and relied on.
pub(crate) fn register_missing_field_safety(engine: &mut Engine) {
    engine.register_fn("contains", |_: (), _: &str| false);
    engine.register_fn("starts_with", |_: (), _: &str| false);
    engine.register_fn("ends_with", |_: (), _: &str| false);
}

/// Shared by `matcher.rs` and `alerts.rs` — both need to expose a `Metrics` map to a Rhai
/// expression under the same `metrics` scope-variable convention. (Previously also shared
/// with `dedup.rs`, removed 2026-08-16 — see `discovery_devices::DeviceStore::resolve`'s
/// docs.)
pub(crate) fn metrics_to_map(metrics: &Metrics) -> Map {
    let mut m = Map::new();
    for (key, value) in &metrics.0 {
        m.insert(key.clone().into(), metric_value_to_dynamic(value));
    }
    m
}

pub(crate) fn metric_value_to_dynamic(value: &MetricValue) -> Dynamic {
    match value {
        MetricValue::Int(v) => Dynamic::from(*v),
        MetricValue::Float(v) => Dynamic::from(*v),
        MetricValue::Str(v) => Dynamic::from(v.clone()),
        MetricValue::Bool(v) => Dynamic::from(*v),
        // A table-shaped metric becomes a plain Rhai array of maps — one map per row, each
        // row's `index` alongside its columns (spread flat, not nested under a `fields`
        // key, so an expression reads `row.ifDescr` rather than `row.fields.ifDescr`).
        // This is what lets `match.expression`/`facts_expression`/alert
        // activation-deactivation conditions use Rhai's built-in array functions directly:
        // `metrics.if_table.some(|row| row.ifOperStatus != row.ifAdminStatus)`,
        // `metrics.if_table.filter(|row| row.ifOperStatus == 2).len()`, etc. — no bespoke
        // DSL surface needed beyond this conversion, Rhai's own `Array`/`Map` support
        // (`.filter`/`.some`/`.all`/`.map`/`for` loops) carries the rest.
        MetricValue::Table(rows) => {
            let array: rhai::Array = rows
                .iter()
                .map(|row| Dynamic::from(table_row_to_map(row)))
                .collect();
            Dynamic::from(array)
        }
    }
}

/// One `MetricTableRow` as a Rhai `Map` — column values spread flat alongside `index`
/// (`row.ifDescr`, `row.index`, …), not nested under a `fields` key. Shared by two call
/// sites: `metric_value_to_dynamic`'s `Table` arm (turns a whole table metric into an
/// array of these, for `metrics.if_table.some(|row| ...)`-style expressions) and
/// `AlertEvaluator`'s row-scoped evaluation (added 2026-08-29, `AlertRule::row_metric` —
/// binds a *single* row as the `row` scope variable, one Rhai evaluation per matching
/// row instead of one evaluation over the whole array). Same conversion either way — a
/// row scoped into `row` and an element of the `metrics.<name>` array must look
/// identical to an expression, or `row.ifDescr` and `metrics.if_table[0].ifDescr` could
/// silently disagree.
pub(crate) fn table_row_to_map(row: &MetricTableRow) -> Map {
    let mut m = Map::new();
    for (col, val) in &row.fields {
        m.insert(col.clone().into(), metric_value_to_dynamic(val));
    }
    // Inserted last so the row's own identity always wins over a column that happens to
    // be named "index" too — a same-named column shadowing the row index silently would
    // be a worse surprise than a same-named column's own value being shadowed instead.
    m.insert("index".into(), Dynamic::from(row.index.clone()));
    m
}

/// Shared by `matcher.rs` and `alerts.rs` (moved here from `matcher.rs` 2026-08-17, once
/// `AlertEvaluator` also needed the same `facts` scope-variable convention as
/// `ProfileMatcher::match_profile` — direct user request that alert expressions have
/// access to device facts, not just metrics).
///
/// `ping_ok`/`snmp_ok` (2026-09-14, `docs/Roadmap.md` "До релиза" item 6) — **not** read
/// from `DeviceFacts` itself (that struct stays the persisted, IP-only identity anchor its
/// own docs describe — see that struct's docs on why `sys_descr`/etc. moved *out* to
/// `metrics` rather than living there). Instead, the caller passes the device's *current*
/// top-level `Device::ping_ok`/`Device::snmp_ok` (live reachability, refreshed on its own
/// cadence by `ReachabilityPollHandler` — see that handler's docs) in fresh at every
/// evaluation, exactly the "ephemeral, not persisted alongside facts" shape the Roadmap
/// item calls for. `None` (never checked yet) omits the key entirely rather than inserting
/// a `()` — same "absent key reads as unit in Rhai, no explicit sentinel needed" convention
/// [`metrics_to_map`] already uses for a metric that's never polled.
pub(crate) fn facts_to_map(
    facts: &DeviceFacts,
    ping_ok: Option<bool>,
    snmp_ok: Option<bool>,
) -> Map {
    let mut m = Map::new();
    m.insert("ip".into(), Dynamic::from(facts.ip.clone()));
    if let Some(ping_ok) = ping_ok {
        m.insert("ping_ok".into(), Dynamic::from(ping_ok));
    }
    if let Some(snmp_ok) = snmp_ok {
        m.insert("snmp_ok".into(), Dynamic::from(snmp_ok));
    }
    m
}

/// Converts a Rhai evaluation result into `serde_json::Value` for durable storage —
/// `discovery_dsl::AlertRule::facts_expression`'s return value, captured once at alert
/// activation (`discovery_core::Alert::facts`). Deliberately a narrow, hand-written
/// mapping over the handful of `Dynamic` shapes this project's expressions actually
/// produce (unit, bool, int, float, string, array, map — the same set
/// `metric_value_to_dynamic` produces plus the two container types), rather than pulling
/// in `rhai`'s `serde` cargo feature for a fully general `Dynamic -> Value` conversion:
/// keeps the conversion's behavior fully specified and testable without depending on an
/// external crate's exact serialization of internal/exotic `Dynamic` variants (function
/// pointers, `Instant`, etc.) that a facts expression should never plausibly produce
/// anyway. Anything outside this set falls back to its Rhai `to_string()` representation
/// wrapped in a JSON string — never an error, since a facts expression producing something
/// odd shouldn't crash alert evaluation, just record something less structured than usual.
pub(crate) fn dynamic_to_json(value: &Dynamic) -> serde_json::Value {
    if value.is_unit() {
        return serde_json::Value::Null;
    }
    if let Ok(b) = value.as_bool() {
        return serde_json::Value::Bool(b);
    }
    if let Ok(i) = value.as_int() {
        return serde_json::Value::Number(i.into());
    }
    if let Ok(f) = value.as_float() {
        return serde_json::Number::from_f64(f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null);
    }
    if value.is_array() {
        let arr = value
            .clone()
            .into_typed_array::<Dynamic>()
            .unwrap_or_default();
        return serde_json::Value::Array(arr.iter().map(dynamic_to_json).collect());
    }
    if value.is_map() {
        if let Some(map) = value.clone().try_cast::<Map>() {
            let mut obj = serde_json::Map::new();
            for (k, v) in map.iter() {
                obj.insert(k.to_string(), dynamic_to_json(v));
            }
            return serde_json::Value::Object(obj);
        }
    }
    // String, or anything else we don't specifically handle — stringify rather than error.
    serde_json::Value::String(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rhai::Engine;

    fn eval(expr: &str) -> Dynamic {
        Engine::new().eval::<Dynamic>(expr).unwrap()
    }

    #[test]
    fn converts_scalars() {
        assert_eq!(dynamic_to_json(&eval("()")), serde_json::Value::Null);
        assert_eq!(
            dynamic_to_json(&eval("true")),
            serde_json::Value::Bool(true)
        );
        assert_eq!(dynamic_to_json(&eval("42")), serde_json::json!(42));
        assert_eq!(dynamic_to_json(&eval("3.5")), serde_json::json!(3.5));
        assert_eq!(
            dynamic_to_json(&eval("\"hi\"")),
            serde_json::Value::String("hi".into())
        );
    }

    #[test]
    fn converts_maps_and_arrays_recursively() {
        let json = dynamic_to_json(&eval(r#"#{ip: "10.0.0.1", cpu: 92, tags: [1, 2]}"#));
        assert_eq!(
            json,
            serde_json::json!({"ip": "10.0.0.1", "cpu": 92, "tags": [1, 2]})
        );
    }
}

pub(crate) fn json_to_dynamic(value: &serde_json::Value) -> Dynamic {
    match value {
        serde_json::Value::Null => Dynamic::UNIT,
        serde_json::Value::Bool(v) => Dynamic::from(*v),
        serde_json::Value::Number(v) => v
            .as_i64()
            .map(Dynamic::from)
            .unwrap_or_else(|| Dynamic::from(v.as_f64().unwrap_or_default())),
        serde_json::Value::String(v) => Dynamic::from(v.clone()),
        serde_json::Value::Array(v) => {
            Dynamic::from(v.iter().map(json_to_dynamic).collect::<rhai::Array>())
        }
        serde_json::Value::Object(v) => Dynamic::from(
            v.iter()
                .map(|(k, v)| (k.clone().into(), json_to_dynamic(v)))
                .collect::<Map>(),
        ),
    }
}
