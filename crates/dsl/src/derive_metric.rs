//! Derived metrics from raw SNMP counters (rate/delta) — Roadmap item "Производные
//! метрики от счётчиков (rate/delta поверх сырых SNMP-counter'ов)", added 2026-09-07.
//!
//! SNMP counters (`ifInOctets`, `ifOutOctets`, error/discard counters, ...) are
//! monotonically increasing — a profile's `match.expression`/`AlertRule.expression` can't
//! threshold meaningfully against the raw cumulative value, only against how fast it's
//! growing. This module is the pure computation half of turning a raw counter sample into
//! a rate/delta value; [`crate::MetricSpec::Detailed::derive`] is the profile-config half
//! (opting a metric in, and which kind), and `discovery-agent::handlers::MetricPollHandler`
//! is the only caller — it feeds this function the previous cached `(value, polled_at)` for
//! the metric (from `discovery_devices::DeviceMetricsStore::get_metric_records`, read once
//! per tick, before the fresh sample overwrites it) and the value/timestamp of the sample
//! it just polled.
//!
//! **Naming/storage convention:** the result is stored under a synthetic name
//! (`{base_name}_rate` / `{base_name}_delta`, see [`derived_metric_name`]) through the
//! exact same [`discovery_devices::DeviceMetricsStore::record_metric_polls`] write path the
//! raw metric itself uses — an ordinary [`discovery_core::MetricValue`] landing in the same
//! `metrics` bag, so existing Rhai expressions reference it with zero new DSL surface
//! (`metrics.ifInOctets_rate > 1000000`), per this project's stated philosophy of reusing
//! Rhai's own facilities rather than inventing expression syntax.
use discovery_core::MetricValue;
use serde::{Deserialize, Serialize};

/// What kind of derived value to compute — see [`crate::MetricSpec::Detailed::derive`]'s
/// docs for the full field-level design.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeriveKind {
    /// `(new - old) / elapsed_seconds` — average rate of change per second. Computed from
    /// actual `polled_at` deltas, never an assumed fixed interval: a metric's own
    /// [`discovery_core::Schedule`] may be calendar-based, or a tick can simply be late.
    Rate,
    /// `new - old` — raw difference, no time normalization.
    Delta,
}

impl DeriveKind {
    /// The suffix [`derived_metric_name`] appends — pulled out purely so the two stay in
    /// sync by construction if a third kind is ever added.
    fn suffix(self) -> &'static str {
        match self {
            DeriveKind::Rate => "_rate",
            DeriveKind::Delta => "_delta",
        }
    }
}

/// The synthetic metric name a derived value is stored/referenced under — e.g.
/// `derived_metric_name("ifInOctets", DeriveKind::Rate) == "ifInOctets_rate"`. Single source
/// of truth for this naming, used both by `MetricPollHandler` (writing the value) and
/// `MetricsSection::validate` (catching a name collision with another declared metric at
/// profile-save time).
pub fn derived_metric_name(base_name: &str, kind: DeriveKind) -> String {
    format!("{base_name}{}", kind.suffix())
}

/// Computes a derived value from two consecutive raw samples of the same counter metric, or
/// `None` if it's not computable this tick — **never an error**, same graceful-degradation
/// posture as every other "hasn't polled yet" state in this pipeline (a `None` here simply
/// means `MetricPollHandler` records nothing for the derived name this tick, leaving
/// whatever was cached from a previous tick, if any, untouched). Every one of these is
/// deliberately treated identically, not distinguished in the return type, because the
/// caller's response to all of them is the same ("skip, try again next tick"):
///
/// - **First-ever sample** — `previous_value`/`previous_polled_at` are `None` (this
///   metric — or its derive config — has never successfully polled before). Not an error,
///   just "not computable yet".
/// - **Non-integer sample** — either value isn't [`MetricValue::Int`]. Only SNMP counters
///   (which always decode to `Int` — see `discovery_snmp::snmp_value_to_metric`'s docs,
///   `Counter`/`Gauge`/`TimeTicks` all land there) support a derived value; a metric with
///   `derive` set that happens to resolve to a string/float/table/bool simply never
///   produces one, rather than panicking on a type it can't do arithmetic on.
/// - **Non-positive elapsed time** — `new_polled_at <= previous_polled_at` (clock skew, or
///   two samples landing at the same instant). Guards the division in [`DeriveKind::Rate`]
///   against a divide-by-zero and against a meaningless negative-duration rate.
/// - **Counter wrap or device reset** — `new_value < previous_value`. This project's
///   fail-safe convention: **don't guess/estimate across a wrap, skip this tick.**
///   `discovery-snmp` collapses `Counter32`/`Counter64` into the same
///   `SnmpValue::Counter(u64)` / `MetricValue::Int(i64)` shape before this ever runs (no
///   SNMP type tag survives that far — see `discovery_snmp::snmp_value_to_metric`'s docs),
///   so there's no way to size-aware-unwrap a `Counter32` rollover (`2^32`) from a
///   `Counter64` one (`2^64`, and *that* one can itself already have been miscast to a
///   negative `i64` by the pre-existing `as i64` conversion once it crosses
///   `i64::MAX` — which this same `<` check happens to also catch and skip, rather than
///   silently producing a wildly wrong negative rate) — "any decrease = skip" is the
///   correct and only available fallback here, not a shortcut taken for convenience.
pub fn compute_derived(
    kind: DeriveKind,
    previous_value: Option<&MetricValue>,
    previous_polled_at: Option<chrono::DateTime<chrono::Utc>>,
    new_value: &MetricValue,
    new_polled_at: chrono::DateTime<chrono::Utc>,
) -> Option<MetricValue> {
    let previous_value = previous_value?;
    let previous_polled_at = previous_polled_at?;

    let MetricValue::Int(old) = previous_value else {
        return None;
    };
    let MetricValue::Int(new) = new_value else {
        return None;
    };

    if *new < *old {
        return None; // wrap or reset — skip, don't guess (see this function's docs)
    }

    let elapsed_secs = (new_polled_at - previous_polled_at).num_milliseconds() as f64 / 1000.0;
    if elapsed_secs <= 0.0 {
        return None;
    }

    // Safe: `new >= old` is already established above, and both come from `i64`, so the
    // difference can never overflow `i64` either — `checked_sub` here purely as a defensive
    // belt-and-suspenders against ever panicking on this hot path, not because overflow is
    // actually reachable given the check above.
    let diff = new.checked_sub(*old)?;

    Some(match kind {
        DeriveKind::Delta => MetricValue::Int(diff),
        DeriveKind::Rate => MetricValue::Float(diff as f64 / elapsed_secs),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    fn t(secs_from_epoch: i64) -> chrono::DateTime<Utc> {
        chrono::DateTime::from_timestamp(secs_from_epoch, 0).unwrap()
    }

    #[test]
    fn derived_metric_name_appends_kind_suffix() {
        assert_eq!(
            derived_metric_name("ifInOctets", DeriveKind::Rate),
            "ifInOctets_rate"
        );
        assert_eq!(
            derived_metric_name("ifInOctets", DeriveKind::Delta),
            "ifInOctets_delta"
        );
    }

    #[test]
    fn first_sample_is_not_computable() {
        let result = compute_derived(DeriveKind::Rate, None, None, &MetricValue::Int(100), t(10));
        assert_eq!(
            result, None,
            "no previous sample at all -> not computable yet, not an error"
        );
    }

    #[test]
    fn missing_previous_polled_at_is_not_computable_even_with_a_value() {
        // Shouldn't happen in practice (the store always sets both together), but this
        // function must not panic/misbehave if it ever does.
        let result = compute_derived(
            DeriveKind::Rate,
            Some(&MetricValue::Int(50)),
            None,
            &MetricValue::Int(100),
            t(10),
        );
        assert_eq!(result, None);
    }

    #[test]
    fn rate_is_diff_over_elapsed_seconds() {
        let previous = MetricValue::Int(1_000);
        let new = MetricValue::Int(1_100);
        let result = compute_derived(DeriveKind::Rate, Some(&previous), Some(t(0)), &new, t(10));
        assert_eq!(
            result,
            Some(MetricValue::Float(10.0)),
            "(1100-1000)/10s = 10/s"
        );
    }

    #[test]
    fn rate_uses_actual_elapsed_time_not_an_assumed_fixed_interval() {
        // Same raw delta, a much longer actual gap (e.g. a late/skipped tick, or a
        // calendar-scheduled metric) -> a correspondingly smaller rate, not the same one.
        let previous = MetricValue::Int(1_000);
        let new = MetricValue::Int(1_100);
        let result = compute_derived(DeriveKind::Rate, Some(&previous), Some(t(0)), &new, t(100));
        assert_eq!(
            result,
            Some(MetricValue::Float(1.0)),
            "(1100-1000)/100s = 1/s"
        );
    }

    #[test]
    fn delta_is_raw_difference_with_no_time_normalization() {
        let previous = MetricValue::Int(1_000);
        let new = MetricValue::Int(1_100);
        // A huge elapsed gap must not affect delta at all, unlike rate.
        let result = compute_derived(
            DeriveKind::Delta,
            Some(&previous),
            Some(t(0)),
            &new,
            t(999_999),
        );
        assert_eq!(result, Some(MetricValue::Int(100)));
    }

    #[test]
    fn no_change_yields_a_zero_rate_not_a_skip() {
        let previous = MetricValue::Int(500);
        let new = MetricValue::Int(500);
        let result = compute_derived(DeriveKind::Rate, Some(&previous), Some(t(0)), &new, t(10));
        assert_eq!(result, Some(MetricValue::Float(0.0)), "a counter that genuinely didn't move this tick is a real rate of 0, not 'not computable'");
    }

    #[test]
    fn a_decrease_is_treated_as_a_wrap_or_reset_and_skipped() {
        let previous = MetricValue::Int(4_294_967_290); // near the top of a Counter32's range
        let new = MetricValue::Int(5); // wrapped around, or the device rebooted and reset to ~0
        let result = compute_derived(DeriveKind::Rate, Some(&previous), Some(t(0)), &new, t(10));
        assert_eq!(
            result, None,
            "don't guess/estimate across a wrap — skip this tick entirely"
        );
    }

    #[test]
    fn a_decrease_is_skipped_for_delta_too() {
        let previous = MetricValue::Int(1_000);
        let new = MetricValue::Int(1);
        let result = compute_derived(DeriveKind::Delta, Some(&previous), Some(t(0)), &new, t(10));
        assert_eq!(result, None);
    }

    #[test]
    fn a_counter64_scale_decrease_is_also_just_skipped() {
        // Nothing downstream of `discovery-snmp::snmp_value_to_metric` can tell a Counter32
        // wrap from a Counter64 one apart — both are plain `MetricValue::Int` by the time
        // this runs. A huge previous value followed by a much smaller new one must be
        // skipped exactly the same way regardless of which counter width it came from.
        let previous = MetricValue::Int(i64::MAX - 1000);
        let new = MetricValue::Int(42);
        let result = compute_derived(DeriveKind::Rate, Some(&previous), Some(t(0)), &new, t(10));
        assert_eq!(result, None);
    }

    #[test]
    fn zero_elapsed_time_is_not_computable() {
        let previous = MetricValue::Int(100);
        let new = MetricValue::Int(200);
        let result = compute_derived(DeriveKind::Rate, Some(&previous), Some(t(10)), &new, t(10));
        assert_eq!(
            result, None,
            "division by zero elapsed time must never be attempted"
        );
    }

    #[test]
    fn negative_elapsed_time_is_not_computable() {
        // Clock skew / an out-of-order sample — `new_polled_at` before `previous_polled_at`.
        let previous = MetricValue::Int(100);
        let new = MetricValue::Int(200);
        let result = compute_derived(DeriveKind::Rate, Some(&previous), Some(t(10)), &new, t(0));
        assert_eq!(result, None);
    }

    #[test]
    fn non_integer_previous_value_is_not_computable() {
        let previous = MetricValue::Str("not a counter".into());
        let new = MetricValue::Int(200);
        let result = compute_derived(DeriveKind::Rate, Some(&previous), Some(t(0)), &new, t(10));
        assert_eq!(result, None);
    }

    #[test]
    fn non_integer_new_value_is_not_computable() {
        let previous = MetricValue::Int(100);
        let new = MetricValue::Float(200.5);
        let result = compute_derived(DeriveKind::Rate, Some(&previous), Some(t(0)), &new, t(10));
        assert_eq!(result, None);
    }

    #[test]
    fn sub_second_elapsed_time_still_computes_using_millisecond_precision() {
        let previous = MetricValue::Int(0);
        let new = MetricValue::Int(50);
        let result = compute_derived(
            DeriveKind::Rate,
            Some(&previous),
            Some(t(0)),
            &new,
            t(0) + Duration::milliseconds(500),
        );
        assert_eq!(result, Some(MetricValue::Float(100.0)), "50 / 0.5s = 100/s");
    }
}
