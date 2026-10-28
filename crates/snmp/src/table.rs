//! Turning raw SNMP `walk()` results into [`MetricValue::Table`] rows — the SNMP-specific
//! half of table metrics (`discovery_dsl::MetricSpec::Detailed::columns`'s docs cover the
//! profile-config half). Deliberately lives here, not in `discovery-agent`, so the exact
//! same slicing code can be reused later by discovery-time OID polling
//! (`discovery-config-store::SubnetSpec::oids`) without duplicating it — see the design
//! discussion this came out of.
//!
//! # Why per-column `walk()`, not one `walk()` on the whole entry OID
//!
//! A real MIB table is often much wider than any one profile cares about (`ifTable` alone
//! has ~22 columns; a profile might want 3). Walking the whole entry OID pulls every
//! column across the wire only to discard most of it. [`poll_table_metric`] instead walks
//! one column at a time (`"{entry_oid}.{subid}"`) when curated columns are declared — see
//! [`build_metric_table`] — and falls back to a single whole-entry walk only in "collect
//! everything" mode (`columns` present but empty), where there's no column list to walk
//! individually in the first place — see [`build_metric_table_auto`].
use std::collections::BTreeMap;

use discovery_core::{DeviceTarget, MetricTableRow, MetricValue};

use crate::{SnmpClient, SnmpValue};

/// The scalar-conversion half of turning an SNMP response into a [`MetricValue`] — used
/// both for a plain scalar metric's single `get()` result (`discovery-agent`'s
/// `MetricPollHandler`) and for one cell inside a table row (`build_metric_table`/
/// `build_metric_table_auto` below). Single source of truth for this mapping — previously
/// duplicated as a private `snmp_value_to_metric` in `discovery-agent::handlers`; moved
/// here and made public so both call sites share it instead of drifting apart.
pub fn snmp_value_to_metric(value: &SnmpValue) -> MetricValue {
    match value {
        SnmpValue::Integer(v) => MetricValue::Int(*v),
        SnmpValue::Counter(v) | SnmpValue::Gauge(v) | SnmpValue::TimeTicks(v) => {
            MetricValue::Int(*v as i64)
        }
        SnmpValue::OctetString(v) | SnmpValue::ObjectId(v) => MetricValue::Str(v.clone()),
        SnmpValue::Null => MetricValue::Bool(false),
    }
}

/// Polls one table metric end to end: decides curated-vs-auto from whether `columns` is
/// empty (see `MetricSpec::Detailed::columns`'s docs for what each mode means) and issues
/// the `walk()` call(s), then slices the result into rows.
///
/// **Whole-metric failure, not partial rows:** if any one column's `walk()` errors (network/
/// timeout — the same failure mode a scalar `get()` already has), the whole call errors —
/// callers should record the metric's `MetricPollOutcome::Err` for this poll, same
/// contract as a scalar OID's own `get()` failing. A table with only some of its declared
/// columns populated (because one column's walk quietly failed) would be a more confusing
/// state to store/display than "this metric didn't poll this cycle, try again next tick" —
/// see the design discussion this came out of.
pub async fn poll_table_metric(
    snmp: &dyn SnmpClient,
    target: &DeviceTarget,
    entry_oid: &str,
    columns: &BTreeMap<String, String>,
) -> anyhow::Result<Vec<MetricTableRow>> {
    if columns.is_empty() {
        let walked = snmp.walk(target, entry_oid).await?;
        return Ok(build_metric_table_auto(entry_oid, walked));
    }

    // Sequential, not concurrent — table metrics declare a handful of columns in practice
    // (single digits), and each `walk()` already batches its own rows via GetBulk under
    // the hood, so the extra round-trips this costs are small. Simpler to reason about
    // than a join-all, and easy to revisit if profiling ever says otherwise.
    let mut walks: Vec<(String, String, Vec<(String, SnmpValue)>)> =
        Vec::with_capacity(columns.len());
    for (col_name, subid) in columns {
        let column_oid = format!("{entry_oid}.{subid}");
        let walked = snmp.walk(target, &column_oid).await?;
        walks.push((col_name.clone(), column_oid, walked));
    }
    Ok(build_metric_table(&walks))
}

/// Curated-columns slicing — merges one `walk()` result per declared column
/// (`(column_name, column_oid, walked_pairs)`, `column_oid` being the exact OID that was
/// walked) into rows keyed by SNMP row index. Every returned OID is expected to start with
/// `"{column_oid}."` — the remainder is the row index (a composite/multi-part index is
/// kept as one opaque dotted string, not decomposed, same as [`MetricTableRow::index`]'s
/// docs explain).
///
/// **Union of indices across columns, not intersection.** Not every column is guaranteed
/// to return a value for every index some other column has (a partially-implemented MIB
/// on the device side) — a row simply lacks that one field, rather than the whole row
/// being dropped. See [`MetricTableRow::fields`]'s docs.
pub fn build_metric_table(
    walks: &[(String, String, Vec<(String, SnmpValue)>)],
) -> Vec<MetricTableRow> {
    let mut rows: BTreeMap<String, BTreeMap<String, MetricValue>> = BTreeMap::new();
    for (col_name, column_oid, walked) in walks {
        let prefix = format!("{column_oid}.");
        for (oid, value) in walked {
            let Some(index) = oid.strip_prefix(prefix.as_str()) else {
                continue; // defensive — a well-behaved walk() only returns OIDs in its own subtree
            };
            if index.is_empty() {
                continue; // no index left to attach this value to — can't be a valid row
            }
            rows.entry(index.to_string())
                .or_default()
                .insert(col_name.clone(), snmp_value_to_metric(value));
        }
    }
    rows_from_map(rows)
}

/// "Collect everything" slicing — a single whole-entry `walk()` result, columns auto-named
/// by their raw subid string (no MIB to look up friendly names from). SNMP's own table
/// syntax (SMIv2 `Entry ::= SEQUENCE { col1 Type1, ... }`) guarantees the subid
/// immediately after the entry OID is always exactly the column number — one subid, not a
/// composite — regardless of whether the caller happens to know what that column means, so
/// this splits unambiguously even without a declared column list.
pub fn build_metric_table_auto(
    entry_oid: &str,
    walked: Vec<(String, SnmpValue)>,
) -> Vec<MetricTableRow> {
    let prefix = format!("{entry_oid}.");
    let mut rows: BTreeMap<String, BTreeMap<String, MetricValue>> = BTreeMap::new();
    for (oid, value) in walked {
        let Some(rest) = oid.strip_prefix(prefix.as_str()) else {
            continue;
        };
        let Some((col_subid, index)) = rest.split_once('.') else {
            continue;
        };
        if index.is_empty() {
            continue;
        }
        rows.entry(index.to_string())
            .or_default()
            .insert(col_subid.to_string(), snmp_value_to_metric(&value));
    }
    rows_from_map(rows)
}

/// Turns the intermediate `index -> fields` map into the final row list, sorted by index —
/// stable ordering across polls is what keeps a dashboard table from reshuffling every
/// refresh. Numeric sort (`"2"` before `"10"`) when every index in this table happens to be
/// a plain non-negative integer (the common case — `ifIndex`-style single-integer indices);
/// falls back to the `BTreeMap`'s own lexical order (already correct as-is) for anything
/// else, e.g. composite/IP-address-shaped indices.
fn rows_from_map(rows: BTreeMap<String, BTreeMap<String, MetricValue>>) -> Vec<MetricTableRow> {
    let mut result: Vec<MetricTableRow> = rows
        .into_iter()
        .map(|(index, fields)| MetricTableRow { index, fields })
        .collect();
    if result.iter().all(|r| r.index.parse::<u64>().is_ok()) {
        result.sort_by_key(|r| r.index.parse::<u64>().unwrap());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn int(v: i64) -> SnmpValue {
        SnmpValue::Integer(v)
    }
    fn s(v: &str) -> SnmpValue {
        SnmpValue::OctetString(v.to_string())
    }

    #[test]
    fn build_metric_table_merges_columns_by_row_index() {
        let walks = vec![
            (
                "ifIndex".to_string(),
                "1.3.6.1.2.1.2.2.1.1".to_string(),
                vec![
                    ("1.3.6.1.2.1.2.2.1.1.1".to_string(), int(1)),
                    ("1.3.6.1.2.1.2.2.1.1.2".to_string(), int(2)),
                ],
            ),
            (
                "ifDescr".to_string(),
                "1.3.6.1.2.1.2.2.1.2".to_string(),
                vec![
                    ("1.3.6.1.2.1.2.2.1.2.1".to_string(), s("Gi0/1")),
                    ("1.3.6.1.2.1.2.2.1.2.2".to_string(), s("Gi0/2")),
                ],
            ),
        ];

        let rows = build_metric_table(&walks);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].index, "1");
        assert_eq!(rows[0].fields.get("ifIndex"), Some(&MetricValue::Int(1)));
        assert_eq!(
            rows[0].fields.get("ifDescr"),
            Some(&MetricValue::Str("Gi0/1".into()))
        );
        assert_eq!(rows[1].index, "2");
        assert_eq!(
            rows[1].fields.get("ifDescr"),
            Some(&MetricValue::Str("Gi0/2".into()))
        );
    }

    #[test]
    fn rows_sort_numerically_not_lexically() {
        let walks = vec![(
            "ifIndex".to_string(),
            "1.3.6.1.2.1.2.2.1.1".to_string(),
            vec![
                ("1.3.6.1.2.1.2.2.1.1.10".to_string(), int(10)),
                ("1.3.6.1.2.1.2.2.1.1.2".to_string(), int(2)),
                ("1.3.6.1.2.1.2.2.1.1.9".to_string(), int(9)),
            ],
        )];

        let rows = build_metric_table(&walks);
        let indices: Vec<&str> = rows.iter().map(|r| r.index.as_str()).collect();
        assert_eq!(
            indices,
            vec!["2", "9", "10"],
            "numeric sort — lexical would put \"10\" before \"2\""
        );
    }

    /// A device that only partially implements the MIB (e.g. `ifDescr` missing for one
    /// index that `ifIndex` still reports) must not lose the whole row — just that field.
    #[test]
    fn a_row_missing_one_column_keeps_its_other_fields_instead_of_being_dropped() {
        let walks = vec![
            (
                "ifIndex".to_string(),
                "1.3.6.1.2.1.2.2.1.1".to_string(),
                vec![
                    ("1.3.6.1.2.1.2.2.1.1.1".to_string(), int(1)),
                    ("1.3.6.1.2.1.2.2.1.1.2".to_string(), int(2)),
                ],
            ),
            (
                "ifDescr".to_string(),
                "1.3.6.1.2.1.2.2.1.2".to_string(),
                vec![("1.3.6.1.2.1.2.2.1.2.1".to_string(), s("Gi0/1"))],
            ),
        ];

        let rows = build_metric_table(&walks);
        assert_eq!(
            rows.len(),
            2,
            "both indices must produce a row, even though only one has ifDescr"
        );
        assert_eq!(rows[1].index, "2");
        assert_eq!(rows[1].fields.get("ifIndex"), Some(&MetricValue::Int(2)));
        assert!(
            !rows[1].fields.contains_key("ifDescr"),
            "missing column must be absent, not a null/empty placeholder"
        );
    }

    #[test]
    fn empty_walk_result_is_an_empty_table_not_an_error() {
        let walks = vec![(
            "lag".to_string(),
            "1.3.6.1.2.1.31.1.2.1.2".to_string(),
            vec![],
        )];
        assert!(build_metric_table(&walks).is_empty());
    }

    #[test]
    fn build_metric_table_auto_names_columns_by_raw_subid() {
        let walked = vec![
            ("1.3.6.1.2.1.2.2.1.1.1".to_string(), int(1)),
            ("1.3.6.1.2.1.2.2.1.2.1".to_string(), s("Gi0/1")),
            ("1.3.6.1.2.1.2.2.1.1.2".to_string(), int(2)),
            ("1.3.6.1.2.1.2.2.1.2.2".to_string(), s("Gi0/2")),
        ];

        let rows = build_metric_table_auto("1.3.6.1.2.1.2.2.1", walked);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0].fields.get("1"),
            Some(&MetricValue::Int(1)),
            "column subid \"1\" (ifIndex) auto-named literally \"1\""
        );
        assert_eq!(
            rows[0].fields.get("2"),
            Some(&MetricValue::Str("Gi0/1".into()))
        );
    }

    #[test]
    fn build_metric_table_auto_ignores_varbinds_outside_the_entry_subtree() {
        // Defensive: a well-behaved walk() only ever returns OIDs under the OID it was
        // asked for, but a malformed/mocked response outside that subtree must not corrupt
        // the table rather than just being dropped.
        let walked = vec![
            ("1.3.6.1.2.1.99.1.1.1".to_string(), int(1)),
            ("1.3.6.1.2.1.2.2.1.1.1".to_string(), int(1)),
        ];
        let rows = build_metric_table_auto("1.3.6.1.2.1.2.2.1", walked);
        assert_eq!(rows.len(), 1);
    }
}
