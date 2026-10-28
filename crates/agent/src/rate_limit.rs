//! Shared by the two push-based ingestion pipelines (`trap_ingest`, `syslog_ingest`) —
//! neither the per-source-IP rate limiter nor the "how long has this row gone untouched"
//! staleness check is protocol-specific, so both pipelines share one implementation
//! instead of carrying their own copy (extracted 2026-09-06 while building Syslog
//! ingestion, when the second near-identical copy would have been a straight duplication —
//! see `docs/Changelog/2026-09-06 - Syslog Ingestion.md`).
//!
//! `TokenBucket` itself moved to `discovery_core` (2026-09-12) so `discovery-web`'s login
//! endpoint could reuse it too — `discovery-web` can't depend on this crate (the dependency
//! runs the other way). Re-exported here so `trap_ingest.rs`/`syslog_ingest.rs`'s existing
//! `use crate::rate_limit::{is_stale, TokenBucket, TOUCHED_AT_FIELD};` keeps working
//! unchanged. See `discovery_core::rate_limit`'s docs for the bucket itself.
pub(crate) use discovery_core::TokenBucket;
use discovery_core::{MetricTableRow, MetricValue};

/// Row field both pipelines manage themselves, on every write, regardless of which
/// binding/variant touched the row — the only thing that gives a push-derived table any
/// notion of "staleness" at all, since (unlike a polled table) nothing rebuilds it wholesale
/// on a cadence. Not part of `discovery-dsl`'s public row-shape contract — deliberately a
/// plain field in `MetricTableRow::fields`, not a new column on the shared type, so ordinary
/// polled tables (`ifTable` and friends) are entirely unaffected.
pub(crate) const TOUCHED_AT_FIELD: &str = "_touched_at";

/// `true` if `row` hasn't been touched (see `TOUCHED_AT_FIELD`) within `ttl_secs` of `now`.
/// A row missing/unable to parse `TOUCHED_AT_FIELD` is treated as stale rather than pinned
/// forever — it isn't one this check can judge the age of.
pub(crate) fn is_stale(
    row: &MetricTableRow,
    ttl_secs: u64,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    match row.fields.get(TOUCHED_AT_FIELD) {
        Some(MetricValue::Str(ts)) => match chrono::DateTime::parse_from_rfc3339(ts) {
            Ok(touched_at) => {
                (now - touched_at.with_timezone(&chrono::Utc)).num_seconds() > ttl_secs as i64
            }
            Err(_) => true,
        },
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_stale_true_when_touched_at_missing_or_expired_false_when_fresh() {
        let now = chrono::Utc::now();
        let no_timestamp = MetricTableRow {
            index: "1".to_string(),
            fields: Default::default(),
        };
        assert!(is_stale(&no_timestamp, 3600, now));

        let mut fresh_fields = std::collections::BTreeMap::new();
        fresh_fields.insert(
            TOUCHED_AT_FIELD.to_string(),
            MetricValue::Str(now.to_rfc3339()),
        );
        let fresh = MetricTableRow {
            index: "1".to_string(),
            fields: fresh_fields,
        };
        assert!(!is_stale(&fresh, 3600, now));

        let mut old_fields = std::collections::BTreeMap::new();
        old_fields.insert(
            TOUCHED_AT_FIELD.to_string(),
            MetricValue::Str((now - chrono::Duration::seconds(7200)).to_rfc3339()),
        );
        let old = MetricTableRow {
            index: "1".to_string(),
            fields: old_fields,
        };
        assert!(is_stale(&old, 3600, now));
    }
}
