use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use discovery_config_store::{ProfileStore, SettingsStore};
use discovery_devices::DeviceMetricsStore;
use discovery_dsl::ProfileFile;
use tracing::{info, warn};

/// Periodically enforces each metric's `history_retention_secs`
/// (`profile_metrics.history_retention_secs`, `MetricSpec::Detailed`'s field) by deleting
/// `device_metric_history` rows older than the cutoff — direct user request 2026-08-16
/// ("время хранения истории метрики так же настраивать в профиле"). Pure housekeeping, on
/// `poll_intervals.metric_history_cleanup_secs` (default: once an hour, see
/// `discovery_core::PollIntervalsConfig`'s docs) — read fresh from `settings` every
/// iteration, not fixed at spawn time, same as every other poll interval.
///
/// **Global by metric name, not scoped to a single profile or device** — same convention
/// `oid`/`interval_secs` already follow when more than one profile declares a
/// metric of the same name (see `MetricSpec::history_retention_secs`'s docs). This loop
/// reads every currently-active profile's `[metrics.poll]`, and for each *name* it sees,
/// remembers whichever [`RetentionPolicy`] it saw last while iterating — not a new
/// inconsistency, the exact same last-one-wins rule `DeviceMetricsStore::prune_metric_history_older_than`
/// already documents.
///
/// A metric with `history_retention_secs = None` (the default — "keep forever") is simply
/// never swept; nothing to delete for it, ever, regardless of how long it's been running.
pub async fn run_metric_history_cleanup_loop(
    profile_store: Arc<dyn ProfileStore>,
    device_metrics: Arc<dyn DeviceMetricsStore>,
    settings: Arc<dyn SettingsStore>,
) {
    loop {
        tokio::time::sleep(Duration::from_secs(
            settings.poll_intervals().await.metric_history_cleanup_secs,
        ))
        .await;

        let profiles = match profile_store.load_all().await {
            Ok(profiles) => profiles,
            Err(e) => {
                warn!(error = %e, "metric history cleanup: failed to load profiles — skipping this tick");
                continue;
            }
        };

        for (name, policy) in collapse_retention_by_name(&profiles) {
            let cutoff =
                chrono::Utc::now() - chrono::Duration::seconds(policy.retention_secs as i64);
            match device_metrics
                .prune_metric_history_older_than(
                    &name,
                    cutoff,
                    policy.keep_last_attempt,
                    policy.keep_last_success,
                )
                .await
            {
                Ok(deleted) if deleted > 0 => {
                    info!(metric = %name, deleted, retention_secs = policy.retention_secs, "metric history cleanup: pruned expired history rows");
                }
                Ok(_) => {} // nothing to delete this tick — the common case, not worth logging
                Err(e) => warn!(metric = %name, error = %e, "metric history cleanup: prune failed"),
            }
        }
    }
}

/// One metric name's collapsed retention policy — `retention_secs` (the cutoff) plus the
/// two exemption flags added 2026-08-16 (direct user request — see
/// `discovery_dsl::MetricSpec`'s docs for the full rationale), all three carried together
/// as a unit since they always come from the same `MetricSpec::Detailed` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RetentionPolicy {
    retention_secs: u64,
    keep_last_success: bool,
    keep_last_attempt: bool,
}

/// Collapses every active profile's `[metrics.poll]` down to one [`RetentionPolicy`] per
/// metric *name* — pulled out of the loop above purely so this (the only part with any
/// real logic in it) is unit-testable without a fake `ProfileStore`/`DeviceStore` pair.
/// Absent from the result means "keep forever" (either `history_retention_secs` was never
/// set for this name, or the profile processed last for it explicitly set `None`) —
/// nothing for the caller to prune. See [`run_metric_history_cleanup_loop`]'s docs for the
/// last-one-wins convention this follows.
fn collapse_retention_by_name(profiles: &[ProfileFile]) -> BTreeMap<String, RetentionPolicy> {
    let mut policy_by_name: BTreeMap<String, RetentionPolicy> = BTreeMap::new();
    for profile in profiles {
        for (name, spec) in &profile.metrics.poll {
            match spec.history_retention_secs() {
                Some(secs) => {
                    policy_by_name.insert(
                        name.clone(),
                        RetentionPolicy {
                            retention_secs: secs,
                            keep_last_success: spec.history_keep_last_success(),
                            keep_last_attempt: spec.history_keep_last_attempt(),
                        },
                    );
                }
                None => {
                    // Explicit "keep forever" for this occurrence of the name — remove any
                    // retention a differently-configured profile might have set for the
                    // same name earlier in this same pass, so "keep forever" from whichever
                    // profile is processed last also wins, consistent with every other
                    // last-wins field.
                    policy_by_name.remove(name);
                }
            }
        }
    }
    policy_by_name
}

#[cfg(test)]
mod tests {
    use super::*;
    use discovery_dsl::{MatchSection, MetricSpec, MetricsSection, ProfileMeta};

    fn profile(name: &str, poll: BTreeMap<String, MetricSpec>) -> ProfileFile {
        ProfileFile {
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            profile: ProfileMeta {
                name: name.to_string(),
                priority: 0,
            },
            match_expr: MatchSection {
                expression: "true".into(),
            },
            metrics: MetricsSection { poll },
            alerts: vec![],
            version: "v1".into(),
        }
    }

    fn detailed(retention: Option<u64>) -> MetricSpec {
        MetricSpec::Detailed {
            oid: "1.2.3".into(),
            columns: None,
            schedule: None,
            history_retention_secs: retention,
            enabled: true,
            history_keep_last_success: true,
            history_keep_last_attempt: true,
            derive: None,
        }
    }

    fn detailed_with_keep_flags(
        retention: Option<u64>,
        keep_success: bool,
        keep_attempt: bool,
    ) -> MetricSpec {
        MetricSpec::Detailed {
            oid: "1.2.3".into(),
            columns: None,
            schedule: None,
            history_retention_secs: retention,
            enabled: true,
            history_keep_last_success: keep_success,
            history_keep_last_attempt: keep_attempt,
            derive: None,
        }
    }

    #[test]
    fn a_metric_with_no_retention_set_anywhere_is_absent_from_the_result() {
        let mut poll = BTreeMap::new();
        poll.insert("uptime".to_string(), MetricSpec::Oid("1.2.3".into()));
        let profiles = vec![profile("p", poll)];

        assert!(
            collapse_retention_by_name(&profiles).is_empty(),
            "keep-forever metrics must not be scheduled for pruning at all"
        );
    }

    #[test]
    fn a_metrics_own_retention_is_picked_up() {
        let mut poll = BTreeMap::new();
        poll.insert("cpu".to_string(), detailed(Some(2592000)));
        let profiles = vec![profile("p", poll)];

        let policy = collapse_retention_by_name(&profiles).remove("cpu").unwrap();
        assert_eq!(policy.retention_secs, 2592000);
        assert!(policy.keep_last_success, "default (unset in test helper's Detailed literal, but here explicitly true) must round-trip");
        assert!(policy.keep_last_attempt);
    }

    #[test]
    fn the_same_metric_name_across_profiles_lets_the_last_one_processed_win() {
        let mut poll_a = BTreeMap::new();
        poll_a.insert("serial_number".to_string(), detailed(Some(100)));
        let mut poll_b = BTreeMap::new();
        poll_b.insert("serial_number".to_string(), detailed(Some(200)));

        let profiles = vec![profile("a", poll_a), profile("b", poll_b)];
        assert_eq!(
            collapse_retention_by_name(&profiles)
                .get("serial_number")
                .map(|p| p.retention_secs),
            Some(200),
            "the second profile processed must win, same last-wins convention as oid/interval_secs"
        );
    }

    #[test]
    fn a_later_keep_forever_wins_over_an_earlier_explicit_retention() {
        let mut poll_a = BTreeMap::new();
        poll_a.insert("mac_address".to_string(), detailed(Some(100)));
        let mut poll_b = BTreeMap::new();
        poll_b.insert("mac_address".to_string(), detailed(None));

        let profiles = vec![profile("a", poll_a), profile("b", poll_b)];
        assert_eq!(
            collapse_retention_by_name(&profiles).get("mac_address"),
            None,
            "keep-forever from the profile processed last must win too, not just explicit values"
        );
    }

    /// Direct user request 2026-08-16: "Добавь флаги сохранять ли крайнюю удачную запись
    /// или нет и сохранять ли просто крайнюю запись." The keep-flags travel with
    /// `retention_secs` as one unit from whichever profile is processed last for a given
    /// metric name — same last-wins convention as everything else here, not a separately
    /// tracked field.
    #[test]
    fn keep_flags_travel_with_retention_and_follow_the_same_last_wins_rule() {
        let mut poll_a = BTreeMap::new();
        poll_a.insert(
            "errors_seen".to_string(),
            detailed_with_keep_flags(Some(100), true, true),
        );
        let mut poll_b = BTreeMap::new();
        poll_b.insert(
            "errors_seen".to_string(),
            detailed_with_keep_flags(Some(100), false, false),
        );

        let profiles = vec![profile("a", poll_a), profile("b", poll_b)];
        let policy = collapse_retention_by_name(&profiles)
            .remove("errors_seen")
            .unwrap();
        assert!(
            !policy.keep_last_success,
            "the last-processed profile's keep flags must win, same as its retention_secs"
        );
        assert!(!policy.keep_last_attempt);
    }
}
