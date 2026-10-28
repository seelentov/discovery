//! SNMP Trap ingestion — the agent-side half of `discovery-snmp::trap`. Turns a
//! [`DecodedTrap`] into a row/value inside `metrics.trap_<binding name>` (via the exact
//! same `DeviceMetricsStore::record_metric_polls` path `MetricPollHandler` already uses),
//! then triggers an out-of-band `AlertEval` for the device — never writes to `alerts`
//! directly, see `docs/Changelog/2026-08-30 - SNMP Trap.md` for why that boundary is load
//! bearing (reusing the entire existing `AlertRule`/`AlertStateTracker` engine unmodified,
//! not a second, parallel path for opening/closing incidents).
//!
//! Three independent pieces live here:
//! - [`TrapIngestState::check_rate_limit`] — an in-memory per-source-IP token bucket,
//!   checked before any decode/DB work, the cheapest possible defense against a trap
//!   storm.
//! - [`ingest_one`] — validate (device known + auth matches) -> resolve binding -> upsert
//!   row -> enqueue `AlertEval`. Called by a small bounded worker pool
//!   (`[snmp_trap].ingest_concurrency`) fed by the UDP listener, deliberately **not** the
//!   SQL `jobs` queue — see this crate's `main.rs` wiring for the reasoning.
//! - [`sweep_ttl_once`] — the *only* path that can evict a trap-derived row/singleton and
//!   thereby produce `AutoClearReason::RowMissing`/"Утеряна" for it, since nothing else
//!   ever re-confirms a trap-derived table the way a poll's fresh `walk()` does. Run by
//!   `run_trap_ttl_sweep` on `poll_intervals.trap_ttl_sweep_secs`.
use crate::ingest_retry::retry_sqlite_busy;
use crate::rate_limit::{is_stale, TokenBucket, TOUCHED_AT_FIELD};
use dashmap::DashMap;
use discovery_core::{
    MetricPollOutcome, MetricTableRow, MetricValue, Metrics, QueueKind, SnmpAuth,
};
use discovery_devices::{DeviceMetricsStore, DeviceStore};
use discovery_dsl::{AlertEvaluator, ProfileMatcher, TrapEventSpec, TrapsSection};
use discovery_queue::JobQueueStore;
use discovery_snmp::{DecodedTrap, TrapAuth, TrapSecurityLevel};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{debug, warn};

/// Automatically exposed on every trap-derived row (2026-08-30 design pass) — the OID that
/// actually matched, for the rare trap whose varbinds carry no data distinguishing it from
/// a sibling variant at all (see `TrapEventSpec::varbinds`'s docs).
const TRAP_OID_FIELD: &str = "trap_oid";
/// Fixed row identity for a singleton (non-keyed) binding — there is exactly one row/value
/// possible, so any constant works; `"0"` matches the SNMP-index convention a keyed row's
/// `index` field otherwise carries.
const SINGLETON_KEY: &str = "0";

pub(crate) fn trap_metric_name(binding_name: &str) -> String {
    format!("trap_{binding_name}")
}

/// Shared state for trap ingestion — one instance for the process, `Arc`-cloned into the
/// UDP listener's worker pool and the ttl-sweep loop.
pub struct TrapIngestState {
    pub devices: Arc<dyn DeviceStore>,
    pub device_metrics: Arc<dyn DeviceMetricsStore>,
    pub matcher: Arc<ProfileMatcher>,
    pub alert_engine: Arc<AlertEvaluator>,
    pub queue: Arc<dyn JobQueueStore>,
    pub rate_limit_per_source_per_sec: u32,
    rate_buckets: DashMap<IpAddr, TokenBucket>,
    write_locks: DashMap<uuid::Uuid, Arc<tokio::sync::Mutex<()>>>,
}

impl TrapIngestState {
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
            write_locks: DashMap::new(),
        }
    }

    /// `true` = under the limit, proceed. Checked by the UDP listener before a packet is
    /// even handed to the ingest worker pool — the cheapest possible line of defense
    /// against a trap storm, entirely in memory, no DB/decode cost paid at all for a
    /// dropped packet.
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

/// Which `TrapEventSpec` (if any) in this profile's `traps.bindings` recognizes `trap_oid`
/// — linear scan over what's normally a handful of bindings/variants per profile, cheap
/// enough not to need a cached index (see the design changelog for why that optimization
/// was deliberately skipped for v1).
fn find_matching_variant<'a>(
    traps: &'a TrapsSection,
    trap_oid: &str,
) -> Option<(&'a str, &'a TrapEventSpec)> {
    for (binding_name, spec) in &traps.bindings {
        for variant in &spec.variants {
            if variant.trap_oid == trap_oid {
                return Some((binding_name.as_str(), variant));
            }
        }
    }
    None
}

/// Extracts this variant's declared fields from the packet's varbinds, by OID — a varbind
/// the packet carries but no `TrapEventSpec::varbinds` entry names is simply not looked at
/// (see that field's docs); a declared OID absent from *this particular* packet is simply
/// not set on the row, not an error (same graceful-degradation philosophy as the rest of
/// this pipeline).
fn extract_fields(
    variant: &TrapEventSpec,
    decoded_varbinds: &BTreeMap<String, MetricValue>,
) -> BTreeMap<String, MetricValue> {
    let mut extracted = BTreeMap::new();
    for (field_name, oid) in &variant.varbinds {
        if let Some(value) = decoded_varbinds.get(oid) {
            extracted.insert(field_name.clone(), value.clone());
        }
    }
    extracted
}

/// Upserts one row (or the one singleton value) into `table`, merging `new_fields` on top
/// of whatever's already there for this key — a variant's write never blanks out fields a
/// *different* variant previously set on the same key, see `TrapEventSpec`'s docs.
fn upsert_row(
    table: &mut Vec<MetricTableRow>,
    key: &str,
    new_fields: BTreeMap<String, MetricValue>,
    trap_oid: &str,
    now: chrono::DateTime<chrono::Utc>,
) {
    let touched_at = MetricValue::Str(now.to_rfc3339());
    match table.iter_mut().find(|row| row.index == key) {
        Some(row) => {
            for (k, v) in new_fields {
                row.fields.insert(k, v);
            }
            row.fields.insert(
                TRAP_OID_FIELD.to_string(),
                MetricValue::Str(trap_oid.to_string()),
            );
            row.fields.insert(TOUCHED_AT_FIELD.to_string(), touched_at);
        }
        None => {
            let mut fields = new_fields;
            fields.insert(
                TRAP_OID_FIELD.to_string(),
                MetricValue::Str(trap_oid.to_string()),
            );
            fields.insert(TOUCHED_AT_FIELD.to_string(), touched_at);
            table.push(MetricTableRow {
                index: key.to_string(),
                fields,
            });
        }
    }
}

/// `TrapAuth` (what the packet claims) against the resolved device's own configured
/// `SnmpAuth` (what it's actually supposed to be) — the check that makes source-IP
/// resolution meaningful instead of "anyone who knows/guesses a community string for any
/// device can forge traps for it". `NoAuthNoPriv` v3 is rejected even for a matching
/// username — spoofable at that level, see `discovery-snmp::TrapAuth`'s docs.
fn auth_matches(claimed: &TrapAuth, configured: &SnmpAuth) -> bool {
    match (claimed, configured) {
        (TrapAuth::Community(claimed_community), SnmpAuth::Community { community, .. }) => {
            claimed_community == community
        }
        (
            TrapAuth::UsmV3 {
                username,
                security_level,
            },
            SnmpAuth::UsmV3(creds),
        ) => *username == creds.user && *security_level >= TrapSecurityLevel::AuthNoPriv,
        _ => false,
    }
}

/// The full per-packet pipeline: validate -> resolve -> upsert -> trigger evaluation. Every
/// early return is a deliberate, silent drop (logged at `debug`, not `warn` — an unknown
/// device or unrecognized `trap_oid` is normal background noise on a shared network, not
/// an operational problem) except genuine store/queue failures, which propagate as `Err`
/// for the caller to log.
pub async fn ingest_one(state: &TrapIngestState, trap: DecodedTrap) -> anyhow::Result<()> {
    let source_ip = trap.source.ip();

    let Some(device_id) = state.devices.id_by_ip(&source_ip.to_string()).await? else {
        debug!(source = %source_ip, "trap from an unknown source IP — dropped");
        return Ok(());
    };
    let Some(device) = state.devices.get_device(device_id).await? else {
        debug!(%device_id, "trap resolved to a device that no longer exists — dropped");
        return Ok(());
    };
    let Some(credentials) = &device.snmp_credentials else {
        debug!(%device_id, "device has no negotiated SNMP credentials yet — cannot validate trap auth, dropped");
        return Ok(());
    };
    if !auth_matches(&trap.auth, &credentials.auth) {
        warn!(%device_id, source = %source_ip, "trap auth does not match this device's configured SNMP credentials — dropped");
        return Ok(());
    }

    let Some(profile_name) = &device.profile else {
        debug!(%device_id, "device has no matched profile yet — dropped");
        return Ok(());
    };
    let Some(profile) = state.matcher.profile_by_name(profile_name).await else {
        debug!(%device_id, profile = %profile_name, "device's profile no longer exists — dropped");
        return Ok(());
    };
    let Some((binding_name, variant)) = find_matching_variant(&profile.traps, &trap.trap_oid)
    else {
        debug!(%device_id, trap_oid = %trap.trap_oid, "trap_oid not declared by any binding in this device's profile — dropped");
        return Ok(());
    };

    let extracted = extract_fields(variant, &trap.varbinds);
    let key = state
        .alert_engine
        .evaluate_trap_key(
            variant.key_expression(),
            &device.facts,
            &Metrics(extracted.clone()),
        )?
        .unwrap_or_else(|| SINGLETON_KEY.to_string());

    let metric_name = trap_metric_name(binding_name);
    let write_lock = state
        .write_locks
        .entry(device_id)
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _write_guard = write_lock.lock().await;
    retry_sqlite_busy("trap metric write", || async {
        let current = state.device_metrics.get_metrics(device_id).await?;
        let mut table = match current.get(&metric_name) {
            Some(MetricValue::Table(rows)) => rows.clone(),
            _ => Vec::new(),
        };
        // Singleton bindings (`key_expression() == None`) only ever have the one row.
        upsert_row(
            &mut table,
            &key,
            extracted.clone(),
            &trap.trap_oid,
            chrono::Utc::now(),
        );
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
    retry_sqlite_busy("trap alert enqueue", || async {
        state
            .queue
            .enqueue(QueueKind::AlertEval, payload.clone(), None)
            .await
            .map(|_| ())
    })
    .await?;
    Ok(())
}

/// One pass of the ttl-sweep — evicts rows/singletons no `TrapEventSpec` variant has
/// touched in longer than that binding's own `TrapSpec::ttl_secs`, then triggers
/// `AlertEval` for every device actually touched so the resulting `RowMissing` closure (or
/// a device-level rule losing its singleton fact) is visible promptly rather than waiting
/// for some unrelated trigger. A binding with `ttl_secs: None`, or a row whose device/
/// profile/binding no longer resolves at all (profile edited, device deleted) is handled
/// as documented on `TrapSpec::ttl_secs`: `None` never expires by staleness; a binding that
/// no longer exists in the device's *current* profile is treated as already expired (there
/// is no live config left to ever refresh it) and evicted immediately.
pub async fn sweep_ttl_once(state: &TrapIngestState) -> anyhow::Result<()> {
    let rows = state
        .device_metrics
        .list_metrics_by_name_prefix("trap_")
        .await?;
    let now = chrono::Utc::now();
    let mut touched_devices: std::collections::HashSet<uuid::Uuid> =
        std::collections::HashSet::new();

    for (device_id, metric_name, value) in rows {
        let MetricValue::Table(table) = value else {
            continue;
        };
        let Some(binding_name) = metric_name.strip_prefix("trap_") else {
            continue;
        };

        let ttl_secs = resolve_ttl_secs(state, device_id, binding_name).await?;
        let Some(ttl_secs) = ttl_secs else {
            continue; // None = never expire by staleness, or binding still None-ttl'd
        };

        let original_len = table.len();
        let kept: Vec<MetricTableRow> = table
            .into_iter()
            .filter(|row| !is_stale(row, ttl_secs, now))
            .collect();
        if kept.len() == original_len {
            continue; // nothing evicted this pass — no write, no AlertEval nudge needed
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

/// `None` = never expire by staleness (`ttl_secs: None`, or the binding/profile/device no
/// longer resolves in a way that changes that — see `sweep_ttl_once`'s docs). `Some(0)` is
/// used as "expire immediately" for the case where the binding itself is simply gone from
/// the device's current profile.
async fn resolve_ttl_secs(
    state: &TrapIngestState,
    device_id: uuid::Uuid,
    binding_name: &str,
) -> anyhow::Result<Option<u64>> {
    let Some(device) = state.devices.get_device(device_id).await? else {
        return Ok(Some(0)); // device gone — nothing will ever refresh this row again
    };
    let Some(profile_name) = &device.profile else {
        return Ok(Some(0));
    };
    let Some(profile) = state.matcher.profile_by_name(profile_name).await else {
        return Ok(Some(0));
    };
    match profile.traps.bindings.get(binding_name) {
        Some(spec) => Ok(spec.ttl_secs),
        None => Ok(Some(0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_matching_variant_returns_the_right_binding_and_none_for_unknown_oid() {
        let mut traps = TrapsSection::default();
        let variant = TrapEventSpec {
            trap_oid: "1.2.3".to_string(),
            varbinds: BTreeMap::new(),
            key_expression: None,
        };
        traps.bindings.insert(
            "cold_start".to_string(),
            discovery_dsl::TrapSpec {
                variants: vec![variant],
                ttl_secs: None,
                history_retention_secs: None,
            },
        );

        let found = find_matching_variant(&traps, "1.2.3");
        assert_eq!(found.map(|(name, _)| name), Some("cold_start"));
        assert!(find_matching_variant(&traps, "9.9.9").is_none());
    }

    #[test]
    fn extract_fields_only_pulls_declared_oids_and_skips_missing_ones() {
        let mut varbinds_spec = BTreeMap::new();
        varbinds_spec.insert("if_index".to_string(), "1.3.6.1.2.1.2.2.1.1".to_string());
        varbinds_spec.insert(
            "if_oper_status".to_string(),
            "1.3.6.1.2.1.2.2.1.8".to_string(),
        );
        let variant = TrapEventSpec {
            trap_oid: "1.2.3".to_string(),
            varbinds: varbinds_spec,
            key_expression: None,
        };

        let mut decoded = BTreeMap::new();
        decoded.insert("1.3.6.1.2.1.2.2.1.1".to_string(), MetricValue::Int(3));
        decoded.insert(
            "1.3.6.1.2.1.1.1.0".to_string(),
            MetricValue::Str("unrelated".into()),
        );

        let extracted = extract_fields(&variant, &decoded);
        assert_eq!(extracted.get("if_index"), Some(&MetricValue::Int(3)));
        assert_eq!(
            extracted.get("if_oper_status"),
            None,
            "declared but absent from this packet — simply not set, not an error"
        );
        assert_eq!(extracted.len(), 1);
    }

    #[test]
    fn upsert_row_creates_then_merges_without_clobbering_fields_from_a_different_variant() {
        let mut table = Vec::new();
        let now = chrono::Utc::now();

        let mut open_fields = BTreeMap::new();
        open_fields.insert("if_oper_status".to_string(), MetricValue::Int(2));
        upsert_row(&mut table, "3", open_fields, "1.3.6.1.6.3.1.1.5.3", now);
        assert_eq!(table.len(), 1);
        assert_eq!(
            table[0].fields.get("if_oper_status"),
            Some(&MetricValue::Int(2))
        );
        assert_eq!(
            table[0].fields.get(TRAP_OID_FIELD),
            Some(&MetricValue::Str("1.3.6.1.6.3.1.1.5.3".to_string()))
        );

        let mut close_fields = BTreeMap::new();
        close_fields.insert("if_oper_status".to_string(), MetricValue::Int(1));
        close_fields.insert("duration_secs".to_string(), MetricValue::Int(42));
        upsert_row(&mut table, "3", close_fields, "1.3.6.1.6.3.1.1.5.4", now);

        assert_eq!(
            table.len(),
            1,
            "same key — must update in place, not append a second row"
        );
        assert_eq!(
            table[0].fields.get("if_oper_status"),
            Some(&MetricValue::Int(1)),
            "second variant's write must win for a field both touched"
        );
        assert_eq!(
            table[0].fields.get("duration_secs"),
            Some(&MetricValue::Int(42)),
            "field only the second variant set must be present"
        );
        assert_eq!(
            table[0].fields.get(TRAP_OID_FIELD),
            Some(&MetricValue::Str("1.3.6.1.6.3.1.1.5.4".to_string())),
            "trap_oid must reflect whichever variant fired most recently"
        );
    }

    #[test]
    fn auth_matches_community_requires_an_exact_match() {
        let claimed = TrapAuth::Community("public".to_string());
        assert!(auth_matches(
            &claimed,
            &SnmpAuth::Community {
                version: discovery_core::SnmpVersion::V2c,
                community: "public".to_string()
            }
        ));
        assert!(!auth_matches(
            &claimed,
            &SnmpAuth::Community {
                version: discovery_core::SnmpVersion::V2c,
                community: "private".to_string()
            }
        ));
    }

    #[test]
    fn auth_matches_v3_requires_matching_username_and_at_least_auth_no_priv() {
        let creds = discovery_core::SnmpV3Credentials {
            user: "trapuser".to_string(),
            auth: None,
            priv_: None,
        };
        let configured = SnmpAuth::UsmV3(creds);

        let matching_authed = TrapAuth::UsmV3 {
            username: "trapuser".to_string(),
            security_level: TrapSecurityLevel::AuthPriv,
        };
        assert!(auth_matches(&matching_authed, &configured));

        let matching_unauthed = TrapAuth::UsmV3 {
            username: "trapuser".to_string(),
            security_level: TrapSecurityLevel::NoAuthNoPriv,
        };
        assert!(
            !auth_matches(&matching_unauthed, &configured),
            "NoAuthNoPriv must be rejected even for a matching username — spoofable at that level"
        );

        let wrong_user = TrapAuth::UsmV3 {
            username: "someoneelse".to_string(),
            security_level: TrapSecurityLevel::AuthPriv,
        };
        assert!(!auth_matches(&wrong_user, &configured));
    }

    #[test]
    fn auth_matches_rejects_mismatched_auth_kinds() {
        let community_claim = TrapAuth::Community("public".to_string());
        let v3_configured = SnmpAuth::UsmV3(discovery_core::SnmpV3Credentials {
            user: "trapuser".to_string(),
            auth: None,
            priv_: None,
        });
        assert!(!auth_matches(&community_claim, &v3_configured));
    }
}
