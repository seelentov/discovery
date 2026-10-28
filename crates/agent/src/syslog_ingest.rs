//! Syslog ingestion — the agent-side half of `discovery-agent::syslog_decode`. Turns a
//! [`DecodedSyslogMessage`] into a row/value inside `metrics.syslog_<binding name>` (via
//! the exact same `DeviceMetricsStore::record_metric_polls` path `MetricPollHandler`/
//! `trap_ingest` already use), then triggers an out-of-band `AlertEval` for the device —
//! never writes to `alerts` directly, same governing principle as SNMP Trap ingestion (see
//! `docs/Architecture/Syslog Ingestion.md`).
//!
//! Direct sibling of [`crate::trap_ingest`], with the one structural difference the
//! protocol forces: **syslog has no authentication at all** — no community string, no USM,
//! nothing. Device resolution is purely by source IP, exactly as trustworthy (or not) as
//! any other UDP source-IP check (spoofable without a return-path handshake). This is an
//! accepted limitation, not an oversight — documented explicitly here the same way
//! `discovery-snmp::TrapUsmUser`'s "last one wins" caveat is, rather than silently having
//! weaker security than trap ingestion for no stated reason.
//!
//! Three independent pieces live here, mirroring `trap_ingest`'s shape:
//! - [`SyslogIngestState::check_rate_limit`] — same per-source-IP token bucket as trap
//!   ingestion (`crate::rate_limit::TokenBucket`), checked before any decode/DB work.
//! - [`ingest_one`] — resolve device -> resolve profile -> prefilter (severity/facility)
//!   -> regex-match (compiled-pattern cache) -> upsert row -> enqueue `AlertEval`. Same
//!   small bounded in-memory worker pool as trap ingestion, not the SQL `jobs` queue, same
//!   reasoning.
//! - [`sweep_ttl_once`] — the *only* path that can evict a syslog-derived row/singleton and
//!   thereby produce `AutoClearReason::RowMissing`/"Утеряна" for it, mirroring
//!   `trap_ingest::sweep_ttl_once` exactly (own `"syslog_"` prefix, own
//!   `SyslogSpec::ttl_secs`).
use crate::rate_limit::{is_stale, TokenBucket, TOUCHED_AT_FIELD};
use dashmap::DashMap;
use discovery_core::{MetricPollOutcome, MetricTableRow, MetricValue, Metrics, QueueKind};
use discovery_devices::{DeviceMetricsStore, DeviceStore};
use discovery_dsl::{AlertEvaluator, ProfileMatcher, SyslogEventSpec, SyslogSection};
use discovery_queue::JobQueueStore;
use regex::Regex;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::ingest_retry::retry_sqlite_busy;
use crate::syslog_decode::DecodedSyslogMessage;

/// Fixed row identity for a singleton (non-keyed) binding — mirrors
/// `trap_ingest::SINGLETON_KEY`.
const SINGLETON_KEY: &str = "0";

pub(crate) fn syslog_metric_name(binding_name: &str) -> String {
    format!("syslog_{binding_name}")
}

/// Shared state for syslog ingestion — one instance for the process, `Arc`-cloned into the
/// UDP listener's worker pool and the ttl-sweep loop. Direct sibling of
/// `trap_ingest::TrapIngestState`.
pub struct SyslogIngestState {
    pub devices: Arc<dyn DeviceStore>,
    pub device_metrics: Arc<dyn DeviceMetricsStore>,
    pub matcher: Arc<ProfileMatcher>,
    pub alert_engine: Arc<AlertEvaluator>,
    pub queue: Arc<dyn JobQueueStore>,
    pub rate_limit_per_source_per_sec: u32,
    rate_buckets: DashMap<IpAddr, TokenBucket>,
    /// Compiled `SyslogEventSpec::pattern` cache, keyed by the raw pattern string —
    /// `SyslogSection::validate()` already guarantees every pattern reaching here compiles
    /// (enforced at `POST /api/profiles` time), so a cache miss here should never actually
    /// fail; the `Result` is still handled gracefully (log + skip that variant) rather than
    /// unwrapped, in case a row ever reaches this path via a store written outside REST.
    /// Grows unboundedly with the number of *distinct pattern strings ever seen*, not with
    /// message volume — bounded in practice by how many syslog bindings a deployment
    /// actually authors, small enough that no eviction policy is warranted.
    pattern_cache: DashMap<String, Arc<Regex>>,
    write_locks: DashMap<uuid::Uuid, Arc<tokio::sync::Mutex<()>>>,
}

impl SyslogIngestState {
    const MAX_RATE_BUCKETS: usize = 65_536;
    const RATE_BUCKET_IDLE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

    pub fn new(
        devices: Arc<dyn DeviceStore>,
        device_metrics: Arc<dyn DeviceMetricsStore>,
        matcher: Arc<ProfileMatcher>,
        alert_engine: Arc<AlertEvaluator>,
        queue: Arc<dyn JobQueueStore>,
        rate_limit_per_source_per_sec: u32,
    ) -> Self {
        Self {
            devices,
            device_metrics,
            matcher,
            alert_engine,
            queue,
            rate_limit_per_source_per_sec,
            rate_buckets: DashMap::new(),
            pattern_cache: DashMap::new(),
            write_locks: DashMap::new(),
        }
    }

    /// `true` = under the limit, proceed. Same semantics as
    /// `trap_ingest::TrapIngestState::check_rate_limit`.
    pub fn check_rate_limit(&self, source: IpAddr) -> bool {
        if !self.rate_buckets.contains_key(&source)
            && self.rate_buckets.len() >= Self::MAX_RATE_BUCKETS
        {
            let cutoff = std::time::Instant::now() - Self::RATE_BUCKET_IDLE_TTL;
            self.rate_buckets
                .retain(|_, bucket| bucket.last_refill() >= cutoff);
            if self.rate_buckets.len() >= Self::MAX_RATE_BUCKETS {
                return false;
            }
        }
        self.rate_buckets
            .entry(source)
            .or_insert_with(|| TokenBucket::new(self.rate_limit_per_source_per_sec))
            .try_consume(self.rate_limit_per_source_per_sec as f64)
    }
}

fn get_or_compile(cache: &DashMap<String, Arc<Regex>>, pattern: &str) -> Option<Arc<Regex>> {
    if let Some(re) = cache.get(pattern) {
        return Some(re.clone());
    }
    match Regex::new(pattern) {
        Ok(re) => {
            let re = Arc::new(re);
            cache.insert(pattern.to_string(), re.clone());
            Some(re)
        }
        Err(e) => {
            warn!(pattern, error = %e, "syslog: pattern failed to compile — should have been caught by profile validation, skipping this variant");
            None
        }
    }
}

/// Runs `pattern` against `message`, returning named capture groups as fields — `None` if
/// the pattern doesn't match at all. A pattern with zero named groups that still matches
/// returns `Some(empty map)`, not `None`: a match with no captures is still a match (a
/// binding can rely purely on the automatic `severity`/`facility`/`hostname` fields, see
/// this module's docs on [`with_auto_fields`]).
fn extract_fields(pattern: &Regex, message: &str) -> Option<BTreeMap<String, MetricValue>> {
    let captures = pattern.captures(message)?;
    let mut fields = BTreeMap::new();
    for name in pattern.capture_names().flatten() {
        if let Some(m) = captures.name(name) {
            fields.insert(name.to_string(), MetricValue::Str(m.as_str().to_string()));
        }
    }
    Some(fields)
}

/// Adds the three fields every syslog row always carries, regardless of what (if anything)
/// `pattern` captured — direct user request 2026-09-06. Inserted **after** the captured
/// fields so they always win on a name collision, same "identity always wins" convention
/// `discovery_dsl::util::table_row_to_map` uses for a row's own `index`.
fn with_auto_fields(
    mut fields: BTreeMap<String, MetricValue>,
    decoded: &DecodedSyslogMessage,
) -> BTreeMap<String, MetricValue> {
    fields.insert(
        "severity".to_string(),
        MetricValue::Int(decoded.severity as i64),
    );
    fields.insert(
        "facility".to_string(),
        MetricValue::Int(decoded.facility as i64),
    );
    fields.insert(
        "hostname".to_string(),
        MetricValue::Str(decoded.hostname.clone()),
    );
    fields
}

/// Which `SyslogEventSpec` (if any) in this profile's `syslog.bindings` matches `decoded` —
/// linear scan, same reasoning as `trap_ingest::find_matching_variant` for why no cached
/// index is needed at this scale. Unlike trap (where OID equality decides the match and
/// varbind extraction is a separate, unconditional step), matching and extraction are the
/// same regex operation here, so this function does both at once: severity/facility
/// prefilter first (cheapest, already-decoded data), then the compiled pattern against the
/// message body.
fn find_matching_variant<'a>(
    syslog: &'a SyslogSection,
    cache: &DashMap<String, Arc<Regex>>,
    decoded: &DecodedSyslogMessage,
) -> Option<(&'a str, &'a SyslogEventSpec, BTreeMap<String, MetricValue>)> {
    for (binding_name, spec) in &syslog.bindings {
        for variant in &spec.variants {
            if variant
                .max_severity
                .is_some_and(|max| decoded.severity > max)
            {
                continue;
            }
            if variant.facility.is_some_and(|f| f != decoded.facility) {
                continue;
            }
            let Some(re) = get_or_compile(cache, &variant.pattern) else {
                continue;
            };
            if let Some(fields) = extract_fields(&re, &decoded.message) {
                return Some((binding_name.as_str(), variant, fields));
            }
        }
    }
    None
}

/// Upserts one row (or the one singleton value) into `table`, merging `new_fields` on top
/// of whatever's already there for this key — same merge-not-clobber contract as
/// `trap_ingest::upsert_row`. No `trap_oid`-equivalent auto field: a syslog row already
/// always carries `severity`/`facility`/`hostname` (see [`with_auto_fields`]), so there's
/// no case here analogous to trap's "varbinds may be entirely empty, stamp *something*
/// distinguishing".
fn upsert_row(
    table: &mut Vec<MetricTableRow>,
    key: &str,
    new_fields: BTreeMap<String, MetricValue>,
    now: chrono::DateTime<chrono::Utc>,
) {
    let touched_at = MetricValue::Str(now.to_rfc3339());
    match table.iter_mut().find(|row| row.index == key) {
        Some(row) => {
            for (k, v) in new_fields {
                row.fields.insert(k, v);
            }
            row.fields.insert(TOUCHED_AT_FIELD.to_string(), touched_at);
        }
        None => {
            let mut fields = new_fields;
            fields.insert(TOUCHED_AT_FIELD.to_string(), touched_at);
            table.push(MetricTableRow {
                index: key.to_string(),
                fields,
            });
        }
    }
}

/// The full per-packet pipeline: resolve -> prefilter/match -> upsert -> trigger
/// evaluation. Every early return is a deliberate, silent drop (logged at `debug`, not
/// `warn` — an unknown source IP or a message no binding recognizes is normal background
/// noise, not an operational problem) except genuine store/queue failures, which propagate
/// as `Err` for the caller to log. **No auth step** — see this module's docs.
pub async fn ingest_one(
    state: &SyslogIngestState,
    decoded: DecodedSyslogMessage,
) -> anyhow::Result<()> {
    let source_ip = decoded.source.ip();

    let Some(device_id) = state.devices.id_by_ip(&source_ip.to_string()).await? else {
        debug!(source = %source_ip, "syslog message from an unknown source IP — dropped");
        return Ok(());
    };
    let Some(device) = state.devices.get_device(device_id).await? else {
        debug!(%device_id, "syslog message resolved to a device that no longer exists — dropped");
        return Ok(());
    };
    let Some(profile_name) = &device.profile else {
        debug!(%device_id, "device has no matched profile yet — dropped");
        return Ok(());
    };
    let Some(profile) = state.matcher.profile_by_name(profile_name).await else {
        debug!(%device_id, profile = %profile_name, "device's profile no longer exists — dropped");
        return Ok(());
    };
    let Some((binding_name, variant, captured)) =
        find_matching_variant(&profile.syslog, &state.pattern_cache, &decoded)
    else {
        debug!(%device_id, "syslog message matched no binding in this device's profile — dropped");
        return Ok(());
    };

    let extracted = with_auto_fields(captured, &decoded);
    let key = state
        .alert_engine
        .evaluate_syslog_key(
            variant.key_expression(),
            &device.facts,
            &Metrics(extracted.clone()),
        )?
        .unwrap_or_else(|| SINGLETON_KEY.to_string());

    let metric_name = syslog_metric_name(binding_name);
    let write_lock = state
        .write_locks
        .entry(device_id)
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _write_guard = write_lock.lock().await;
    retry_sqlite_busy("syslog metric write", || async {
        let current = state.device_metrics.get_metrics(device_id).await?;
        let mut table = match current.get(&metric_name) {
            Some(MetricValue::Table(rows)) => rows.clone(),
            _ => Vec::new(),
        };
        upsert_row(&mut table, &key, extracted.clone(), chrono::Utc::now());
        let outcome = BTreeMap::from([(
            metric_name.clone(),
            MetricPollOutcome::Ok(MetricValue::Table(table)),
        )]);
        state
            .device_metrics
            .record_metric_polls(device_id, &outcome)
            .await
    })
    .await?;

    let source_event = discovery_core::AlertSourceEvent {
        id: uuid::Uuid::new_v4(),
        device_id,
        metric: metric_name.clone(),
        received_at: chrono::Utc::now(),
        data: serde_json::json!({"index": key, "fields": extracted}),
    };
    let payload = serde_json::to_value(discovery_core::payload::AlertEvalPayload {
        device_id,
        event: Some(source_event),
    })?;
    retry_sqlite_busy("syslog alert enqueue", || async {
        state
            .queue
            .enqueue(QueueKind::AlertEval, payload.clone(), None)
            .await
            .map(|_| ())
    })
    .await?;
    Ok(())
}

/// One pass of the ttl-sweep — direct sibling of `trap_ingest::sweep_ttl_once`, own
/// `"syslog_"` prefix and own `SyslogSpec::ttl_secs`. See that function's docs for the full
/// reasoning (identical here).
pub async fn sweep_ttl_once(state: &SyslogIngestState) -> anyhow::Result<()> {
    let rows = state
        .device_metrics
        .list_metrics_by_name_prefix("syslog_")
        .await?;
    let now = chrono::Utc::now();
    let mut touched_devices: std::collections::HashSet<uuid::Uuid> =
        std::collections::HashSet::new();

    for (device_id, metric_name, value) in rows {
        let MetricValue::Table(table) = value else {
            continue;
        };
        let Some(binding_name) = metric_name.strip_prefix("syslog_") else {
            continue;
        };

        let ttl_secs = resolve_ttl_secs(state, device_id, binding_name).await?;
        let Some(ttl_secs) = ttl_secs else {
            continue;
        };

        let original_len = table.len();
        let kept: Vec<MetricTableRow> = table
            .into_iter()
            .filter(|row| !is_stale(row, ttl_secs, now))
            .collect();
        if kept.len() == original_len {
            continue;
        }

        state
            .device_metrics
            .record_metric_polls(
                device_id,
                &BTreeMap::from([(metric_name, MetricPollOutcome::Ok(MetricValue::Table(kept)))]),
            )
            .await?;
        touched_devices.insert(device_id);
    }

    for device_id in touched_devices {
        state
            .queue
            .enqueue(
                QueueKind::AlertEval,
                serde_json::to_value(discovery_core::payload::AlertEvalPayload {
                    device_id,
                    event: None,
                })?,
                Some(&device_id.to_string()),
            )
            .await?;
    }
    Ok(())
}

/// `None` = never expire by staleness. `Some(0)` = expire immediately (binding/profile/
/// device no longer resolves). Direct sibling of `trap_ingest::resolve_ttl_secs`.
async fn resolve_ttl_secs(
    state: &SyslogIngestState,
    device_id: uuid::Uuid,
    binding_name: &str,
) -> anyhow::Result<Option<u64>> {
    let Some(device) = state.devices.get_device(device_id).await? else {
        return Ok(Some(0));
    };
    let Some(profile_name) = &device.profile else {
        return Ok(Some(0));
    };
    let Some(profile) = state.matcher.profile_by_name(profile_name).await else {
        return Ok(Some(0));
    };
    match profile.syslog.bindings.get(binding_name) {
        Some(spec) => Ok(spec.ttl_secs),
        None => Ok(Some(0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use discovery_dsl::SyslogSpec;
    use std::net::SocketAddr;

    fn a_message(severity: u8, facility: u8, message: &str) -> DecodedSyslogMessage {
        DecodedSyslogMessage {
            source: "10.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            severity,
            facility,
            hostname: "sw-vrn-01".to_string(),
            message: message.to_string(),
        }
    }

    #[test]
    fn extract_fields_returns_named_groups_and_none_on_no_match() {
        let re = Regex::new(r"(?P<ifName>\S+) is down").unwrap();
        let fields = extract_fields(&re, "Gi0/1 is down").unwrap();
        assert_eq!(
            fields.get("ifName"),
            Some(&MetricValue::Str("Gi0/1".to_string()))
        );

        assert!(extract_fields(&re, "totally unrelated text").is_none());
    }

    #[test]
    fn extract_fields_matches_with_zero_named_groups_returns_empty_map_not_none() {
        let re = Regex::new(r"reboot").unwrap();
        let fields = extract_fields(&re, "system reboot initiated").unwrap();
        assert!(
            fields.is_empty(),
            "a match with no capture groups is still a match, relying purely on auto-fields"
        );
    }

    #[test]
    fn with_auto_fields_wins_over_a_same_named_capture_group() {
        let mut captured = BTreeMap::new();
        captured.insert(
            "hostname".to_string(),
            MetricValue::Str("attacker-controlled".to_string()),
        );
        let decoded = a_message(3, 23, "irrelevant");
        let merged = with_auto_fields(captured, &decoded);
        assert_eq!(
            merged.get("hostname"),
            Some(&MetricValue::Str("sw-vrn-01".to_string())),
            "the automatic hostname field must win over a same-named capture group"
        );
        assert_eq!(merged.get("severity"), Some(&MetricValue::Int(3)));
        assert_eq!(merged.get("facility"), Some(&MetricValue::Int(23)));
    }

    #[test]
    fn find_matching_variant_applies_severity_prefilter() {
        let mut syslog = SyslogSection::default();
        let variant = SyslogEventSpec {
            pattern: r".*down.*".into(),
            max_severity: Some(4),
            facility: None,
            key_expression: None,
        };
        syslog.bindings.insert(
            "iface_down".to_string(),
            SyslogSpec {
                variants: vec![variant],
                ttl_secs: None,
                history_retention_secs: None,
            },
        );
        let cache = DashMap::new();

        let too_mild = a_message(6, 23, "interface down"); // severity 6 > max 4 — filtered out
        assert!(find_matching_variant(&syslog, &cache, &too_mild).is_none());

        let severe_enough = a_message(3, 23, "interface down");
        assert!(find_matching_variant(&syslog, &cache, &severe_enough).is_some());
    }

    #[test]
    fn find_matching_variant_applies_facility_prefilter() {
        let mut syslog = SyslogSection::default();
        let variant = SyslogEventSpec {
            pattern: r".*down.*".into(),
            max_severity: None,
            facility: Some(23),
            key_expression: None,
        };
        syslog.bindings.insert(
            "iface_down".to_string(),
            SyslogSpec {
                variants: vec![variant],
                ttl_secs: None,
                history_retention_secs: None,
            },
        );
        let cache = DashMap::new();

        let wrong_facility = a_message(3, 4, "interface down");
        assert!(find_matching_variant(&syslog, &cache, &wrong_facility).is_none());

        let right_facility = a_message(3, 23, "interface down");
        assert!(find_matching_variant(&syslog, &cache, &right_facility).is_some());
    }

    #[test]
    fn find_matching_variant_returns_the_matched_binding_name_and_captured_fields() {
        let mut syslog = SyslogSection::default();
        let variant = SyslogEventSpec {
            pattern: r"(?P<ifName>\S+) is down".into(),
            max_severity: None,
            facility: None,
            key_expression: None,
        };
        syslog.bindings.insert(
            "iface_down".to_string(),
            SyslogSpec {
                variants: vec![variant],
                ttl_secs: None,
                history_retention_secs: None,
            },
        );
        let cache = DashMap::new();

        let msg = a_message(3, 23, "Gi0/1 is down");
        let (name, _variant, fields) = find_matching_variant(&syslog, &cache, &msg).unwrap();
        assert_eq!(name, "iface_down");
        assert_eq!(
            fields.get("ifName"),
            Some(&MetricValue::Str("Gi0/1".to_string()))
        );
    }

    #[test]
    fn upsert_row_creates_then_merges_without_clobbering_fields_from_a_different_variant() {
        let mut table = Vec::new();
        let now = chrono::Utc::now();

        let mut open_fields = BTreeMap::new();
        open_fields.insert("state".to_string(), MetricValue::Str("down".into()));
        upsert_row(&mut table, "Gi0/1", open_fields, now);
        assert_eq!(table.len(), 1);
        assert_eq!(
            table[0].fields.get("state"),
            Some(&MetricValue::Str("down".into()))
        );

        let mut close_fields = BTreeMap::new();
        close_fields.insert("state".to_string(), MetricValue::Str("up".into()));
        close_fields.insert("reason".to_string(), MetricValue::Str("manual".into()));
        upsert_row(&mut table, "Gi0/1", close_fields, now);

        assert_eq!(
            table.len(),
            1,
            "same key — must update in place, not append a second row"
        );
        assert_eq!(
            table[0].fields.get("state"),
            Some(&MetricValue::Str("up".into())),
            "second write must win for a field both touched"
        );
        assert_eq!(
            table[0].fields.get("reason"),
            Some(&MetricValue::Str("manual".into())),
            "field only the second write set must be present"
        );
    }
}
