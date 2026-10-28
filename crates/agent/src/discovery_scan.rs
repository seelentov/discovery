use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{Local, NaiveDate, Timelike};
use discovery_config_store::{enqueue_scan, DiscoveryConfig, DiscoveryConfigStore, SettingsStore};
use discovery_core::{
    default_snmp_retries, default_snmp_timeout_ms, DeviceTarget, Schedule, SnmpCredentials,
};
use discovery_queue::JobQueueStore;
use discovery_snmp::SnmpClient;
use tracing::{info, warn};

// CIDR/netmask math and `find_subnet_spec_for_ip` moved to `discovery-config-store::scan`
// (2026-08-15) so the dashboard's manual "run now" button (`discovery-web`) can enqueue
// the exact same scan this schedule loop does, without `discovery-web` having to depend
// on `discovery-agent` (circular — `discovery-agent` already depends on `discovery-web`
// to serve the dashboard). Re-exported here as `pub use` so existing call sites
// (`handlers::SnmpPollHandler` does `use crate::discovery_scan::find_subnet_spec_for_ip`)
// don't need to change their import path.
pub use discovery_config_store::find_subnet_spec_for_ip;

/// SNMPv2-MIB sysObjectID — used as the "does anything answer at all" probe when
/// negotiating SNMP version/community candidates. Same OID `handlers::SnmpPollHandler`
/// fetches for real identification right after; duplicated here (not imported) since it's
/// a one-line well-known constant and importing it would mean exposing it from `handlers`
/// just for this.
const OID_SYS_OBJECT_ID: &str = "1.3.6.1.2.1.1.2.0";

// ---------------------------------------------------------------------------------------
// SNMP credential negotiation
// ---------------------------------------------------------------------------------------

/// Tries every [`discovery_core::SnmpAuth`] candidate from the subnet `ip` belongs to, in
/// order — community and USM v3 candidates mixed freely, stopping at the first one that
/// answers a plain `sysObjectID` GET. **Flattened from a nested version×community loop to
/// this single loop 2026-08-29** (SNMPv3 support): v3 has no community string to
/// cross-product over, so `SubnetSpec::credentials` is now a flat ordered list of complete
/// candidates rather than two separate lists combined at negotiation time. Returns `None`
/// if `ip` doesn't fall inside any configured subnet, or if none of its candidates
/// answered — callers should fall back to `DeviceTarget::default()` in that case (today's
/// demo-mode behavior, unaffected when nothing is configured).
pub async fn negotiate_snmp_credentials(
    snmp: &Arc<dyn SnmpClient>,
    ip: &str,
    configs: &[DiscoveryConfig],
) -> Option<(DeviceTarget, SnmpCredentials)> {
    let subnet = find_subnet_spec_for_ip(configs, ip)?;
    if subnet.credentials.is_empty() {
        return None; // nothing configured to try
    }
    let timeout_ms = subnet
        .snmp_timeout_ms
        .unwrap_or_else(default_snmp_timeout_ms);
    let retries = subnet.snmp_retries.unwrap_or_else(default_snmp_retries);
    for auth in &subnet.credentials {
        let target = DeviceTarget {
            ip: ip.to_string(),
            port: subnet.port,
            auth: auth.clone(),
            timeout_ms,
            retries,
        };
        if snmp.get(&target, OID_SYS_OBJECT_ID).await.is_ok() {
            return Some((
                target,
                SnmpCredentials {
                    auth: auth.clone(),
                    port: subnet.port,
                },
            ));
        }
    }
    None
}

// ---------------------------------------------------------------------------------------
// Schedule evaluation + the scan loop
// ---------------------------------------------------------------------------------------

/// Periodically (every `check_interval`, which must be well under 60s to reliably catch
/// every scheduled minute) checks every enabled [`DiscoveryConfig`]'s schedule and, when
/// due, enumerates its subnets and enqueues a `Discovery` job for every host address
/// (`discovery_config_store::enqueue_scan` — shared with the dashboard's manual "run now"
/// button, see its docs). Two independent due-checks, one per [`Schedule`] variant —
/// direct user request 2026-08-16 adding [`Schedule::Periodic`] as an alternative to the
/// original calendar-only design:
///
/// - [`Schedule::Calendar`] — matched against the **server's own local time**
///   (`chrono::Local` — replacing a per-config `utc_offset_minutes` field that used to
///   exist here). `last_fired_date` (per config name -> the local date it last fired on)
///   guards against firing more than once for the same scheduled minute.
/// - [`Schedule::Periodic`] — fires when `interval_secs` have elapsed since
///   `last_fired_at`; `None` (never fired yet this process) counts as due immediately,
///   same "first tick after (re)start just runs" convention every other recurring chain in
///   this project uses (`MetricPollHandler`'s `last_polled`, `ActiveChains`, ...).
///
/// Both maps are in-memory and reset on restart — acceptable: worst case a `Calendar`
/// schedule refires once on the day of a restart (idempotent, re-scanning already-known
/// IPs is cheap, see `DiscoveryHandler`'s `ActiveChains` gate), and a `Periodic` schedule
/// just fires once immediately after restart instead of waiting out whatever was left of
/// its previous interval.
///
/// Re-reads `config_store` on every check — there's no separate hot-reload mechanism for
/// discovery configs because this loop already re-reads them constantly; an edit (file or
/// Postgres row) just takes effect on the next check, for free.
///
/// A manual "run now" click doesn't touch either map at all — it's a separate, one-off
/// action (see `discovery-web`'s `run_discovery_config_now`), so it can't suppress or get
/// suppressed by the schedule.
///
/// `check_interval` read fresh from `settings` every iteration (2026-08-16), not fixed at
/// spawn time — same DB-backed, immediately-applying settings requirement as every other
/// `discovery_core::PollIntervalsConfig` field.
pub async fn run_discovery_schedule_loop(
    config_store: Arc<dyn DiscoveryConfigStore>,
    store: Arc<dyn JobQueueStore>,
    settings: Arc<dyn SettingsStore>,
) {
    let mut last_fired_date: HashMap<String, NaiveDate> = HashMap::new();
    let mut last_fired_at: HashMap<String, tokio::time::Instant> = HashMap::new();

    loop {
        tokio::time::sleep(Duration::from_secs(
            settings
                .poll_intervals()
                .await
                .discovery_schedule_check_secs,
        ))
        .await;

        let configs = match config_store.load_all().await {
            Ok(configs) => configs,
            Err(e) => {
                warn!(error = %e, "failed to load discovery configs — skipping this check");
                continue;
            }
        };

        for config in &configs {
            if !config.enabled {
                continue;
            }

            let due = match &config.schedule {
                Schedule::Calendar { .. } => {
                    let local_now = Local::now();
                    let local_date = local_now.date_naive();
                    if last_fired_date.get(&config.name) == Some(&local_date) {
                        false // already ran today (server local time) — don't refire every tick for the rest of the matching minute
                    } else if config.schedule.matches_calendar(
                        local_date,
                        local_now.hour(),
                        local_now.minute(),
                    ) {
                        last_fired_date.insert(config.name.clone(), local_date);
                        true
                    } else {
                        false
                    }
                }
                Schedule::Periodic { interval_secs } => {
                    let now = tokio::time::Instant::now();
                    let due = match last_fired_at.get(&config.name) {
                        Some(last) => {
                            now.duration_since(*last) >= Duration::from_secs(*interval_secs)
                        }
                        None => true,
                    };
                    if due {
                        last_fired_at.insert(config.name.clone(), now);
                    }
                    due
                }
            };

            if due {
                info!(config = %config.name, "discovery schedule fired");
                enqueue_scan(config, &store).await;
            }
        }
    }
}

// Calendar-matching tests (empty months/days = every month/day, specific months/days,
// a day that never occurs in its configured months) moved to
// `discovery_core::schedule::tests` 2026-08-16, alongside the `Schedule::matches_calendar`
// logic itself once it moved out of this file's own `schedule_matches` free function (see
// `Schedule`'s docs for why: the same periodic-vs-calendar switch is now shared with
// `discovery_dsl::MetricSpec`, so the type and its pure matching logic live in
// `discovery-core`, the one crate both depend on). Nothing left here worth a dedicated
// unit test in isolation — `run_discovery_schedule_loop`'s own due-checks (both the
// `Calendar` and new `Periodic` branches) are exercised by this project's live/e2e
// verification instead, same as `MetricPollHandler`'s structurally-identical
// `last_polled`-based due check never had its own isolated unit test either.

#[cfg(test)]
mod tests {
    use super::*;
    use discovery_core::{SnmpAuth, SnmpVersion};
    use discovery_snmp::{FakeSnmpClient, SnmpValue};
    use std::collections::BTreeMap;

    /// `negotiate_snmp_credentials` had zero direct test coverage until now (found during
    /// a project-wide coverage audit, direct user request 2026-08-18: "займись покрытием
    /// тестами... возможно где-то ещё есть такое упущение") — the only place it was ever
    /// exercised was indirectly, through one `SnmpPollHandler` test that wasn't actually
    /// about credential negotiation and only ever configured a single (version,
    /// community) pair, so the version/community *iteration order* and the two early-exit
    /// cases below were never actually checked by anything.
    ///
    /// Builds `credentials` as the full version×community cross-product (same shape the
    /// old separate `snmp_versions`/`read_communities` fields implicitly produced before
    /// 2026-08-29's flattening to a single `Vec<SnmpAuth>`) so these pre-existing tests
    /// keep exercising the same iteration-order/early-exit behavior without rewriting
    /// each one's intent.
    fn subnet(versions: Vec<SnmpVersion>, communities: Vec<&str>) -> DiscoveryConfig {
        let mut credentials = Vec::new();
        for version in &versions {
            for community in &communities {
                credentials.push(SnmpAuth::Community {
                    version: *version,
                    community: community.to_string(),
                });
            }
        }
        DiscoveryConfig {
            name: "test".into(),
            enabled: true,
            schedule: Schedule::Periodic {
                interval_secs: 3600,
            },
            subnets: vec![discovery_config_store::SubnetSpec {
                ip: "10.0.0.0".into(),
                mask: "255.255.255.0".into(),
                port: 161,
                credentials,
                oids: BTreeMap::new(),
                labels: BTreeMap::new(),
                snmp_timeout_ms: None,
                snmp_retries: None,
                create_dead_devices: true,
            }],
        }
    }

    #[tokio::test]
    async fn returns_none_for_an_ip_outside_every_configured_subnet() {
        let snmp: Arc<dyn SnmpClient> = Arc::new(FakeSnmpClient::new());
        let configs = vec![subnet(vec![SnmpVersion::V2c], vec!["public"])];
        assert!(negotiate_snmp_credentials(&snmp, "192.168.1.5", &configs)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn returns_none_immediately_when_the_subnet_has_no_communities_configured() {
        let fake = FakeSnmpClient::new();
        // Seed a value that *would* succeed if negotiation ever actually tried it — proves
        // the empty-communities early return fires before any network attempt, not that
        // every attempt just happened to fail.
        fake.seed_get(
            "10.0.0.5",
            OID_SYS_OBJECT_ID,
            SnmpValue::ObjectId("1.3.6.1.4.1.1".into()),
        );
        let snmp: Arc<dyn SnmpClient> = Arc::new(fake);
        let configs = vec![subnet(vec![SnmpVersion::V2c], vec![])];
        assert!(negotiate_snmp_credentials(&snmp, "10.0.0.5", &configs)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn returns_none_when_nothing_answers_any_candidate() {
        let snmp: Arc<dyn SnmpClient> = Arc::new(FakeSnmpClient::new());
        let configs = vec![subnet(
            vec![SnmpVersion::V2c, SnmpVersion::V1],
            vec!["public", "private"],
        )];
        // Nothing seeded on the fake client at all — every one of the 4 candidates fails.
        assert!(negotiate_snmp_credentials(&snmp, "10.0.0.5", &configs)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn tries_version_outer_community_inner_and_stops_at_the_first_success() {
        let fake = FakeSnmpClient::new();
        fake.seed_get(
            "10.0.0.5",
            OID_SYS_OBJECT_ID,
            SnmpValue::ObjectId("1.3.6.1.4.1.1".into()),
        );
        let snmp: Arc<dyn SnmpClient> = Arc::new(fake);
        // `FakeSnmpClient::get` only keys on (ip, oid) — it can't distinguish which
        // community/version was actually passed in the target, so this seeded value makes
        // *every* candidate "succeed" from the fake's point of view. What this test
        // actually pins down is which one negotiation *reports* as the winner — that has
        // to be the very first entry in `credentials`' iteration order (`subnet`'s helper
        // builds it as the version×community cross-product), proving the loop is exactly
        // "first win keeps it".
        let configs = vec![subnet(
            vec![SnmpVersion::V2c, SnmpVersion::V1],
            vec!["first", "second"],
        )];
        let (_, creds) = negotiate_snmp_credentials(&snmp, "10.0.0.5", &configs)
            .await
            .unwrap();
        assert_eq!(
            creds.auth,
            SnmpAuth::Community {
                version: SnmpVersion::V2c,
                community: "first".to_string()
            }
        );
    }

    #[tokio::test]
    async fn returned_target_carries_the_subnets_port_timeout_and_retries() {
        let fake = FakeSnmpClient::new();
        fake.seed_get(
            "10.0.0.5",
            OID_SYS_OBJECT_ID,
            SnmpValue::ObjectId("1.3.6.1.4.1.1".into()),
        );
        let snmp: Arc<dyn SnmpClient> = Arc::new(fake);
        let mut config = subnet(vec![SnmpVersion::V2c], vec!["public"]);
        config.subnets[0].port = 1161;
        config.subnets[0].snmp_timeout_ms = Some(1234);
        config.subnets[0].snmp_retries = Some(3);
        let (target, creds) = negotiate_snmp_credentials(&snmp, "10.0.0.5", &[config])
            .await
            .unwrap();
        assert_eq!(target.port, 1161);
        assert_eq!(target.timeout_ms, 1234);
        assert_eq!(target.retries, 3);
        assert_eq!(creds.port, 1161);
    }

    #[tokio::test]
    async fn unset_timeout_and_retries_fall_back_to_the_project_wide_snmp_defaults() {
        let fake = FakeSnmpClient::new();
        fake.seed_get(
            "10.0.0.5",
            OID_SYS_OBJECT_ID,
            SnmpValue::ObjectId("1.3.6.1.4.1.1".into()),
        );
        let snmp: Arc<dyn SnmpClient> = Arc::new(fake);
        let configs = vec![subnet(vec![SnmpVersion::V2c], vec!["public"])]; // snmp_timeout_ms/snmp_retries left None
        let (target, _) = negotiate_snmp_credentials(&snmp, "10.0.0.5", &configs)
            .await
            .unwrap();
        assert_eq!(target.timeout_ms, default_snmp_timeout_ms());
        assert_eq!(target.retries, default_snmp_retries());
    }
}
