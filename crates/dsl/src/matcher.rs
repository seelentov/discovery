use discovery_core::{DeviceFacts, Metrics};
use rhai::{Engine, Scope};
use tokio::sync::RwLock;

use crate::util::{facts_to_map, metrics_to_map};
use crate::{profiles_signature, ProfileFile};

/// Picks a profile for a device by evaluating each profile's `match.expression` in
/// priority order (highest first) and returning the first one that evaluates to `true`.
///
/// The active profile set lives behind a lock so it can be **hot-reloaded**: editing a
/// `profiles/*.toml` file doesn't require restarting the agent — see
/// `discovery_agent::profile_reload`, which periodically calls [`Self::reload`] and, when
/// the set actually changed, nudges every known device back through the pipeline so the
/// change takes effect within one reload cycle instead of waiting for each device's next
/// scheduled identity re-check.
///
/// `match_profile`/`profile_by_name` return an owned `ProfileFile` (cloned out from
/// behind the lock) rather than a borrow, specifically so a reload can't be blocked
/// waiting for callers to finish using a reference into the old set.
pub struct ProfileMatcher {
    engine: Engine,
    profiles: RwLock<Vec<ProfileFile>>,
}

impl ProfileMatcher {
    pub fn new(profiles: Vec<ProfileFile>) -> Self {
        let mut engine = Engine::new();
        // Match expressions are short and side-effect-free by construction (there's no
        // way to mutate anything from this scope) — these limits just guard against a
        // pathological profile file, not against anything the DSL is meant to allow.
        engine.set_max_operations(50_000);
        engine.set_max_expr_depths(32, 32);
        crate::util::register_missing_field_safety(&mut engine);

        Self {
            engine,
            profiles: RwLock::new(sorted_by_priority(profiles)),
        }
    }

    /// Replaces the active profile set (e.g. `profiles/*.toml` changed on disk).
    pub async fn reload(&self, profiles: Vec<ProfileFile>) {
        *self.profiles.write().await = sorted_by_priority(profiles);
    }

    /// A fingerprint of the active set (names + content versions) — changes iff a
    /// profile was added, removed, renamed, or edited. Used by the reload loop to decide
    /// whether a reload actually needs to propagate to known devices.
    pub async fn signature(&self) -> String {
        profiles_signature(&self.profiles.read().await)
    }

    /// `metrics` (2026-08-16, direct user request) is the device's current `Metrics` bag —
    /// the same one-shot discovery-time `subnet.oids`/`subnet.labels` values and
    /// profile-polled values that `DedupResolver::compute_key` reads, under the same
    /// `facts`/`metrics` scope convention. `sys_descr`/`sys_object_id`/whatever else used
    /// to live on `DeviceFacts` directly are now just ordinary entries here — a profile's
    /// `match.expression` reads them as `metrics.sys_descr`, not `device.sys_descr`.
    ///
    /// `ping_ok`/`snmp_ok` (2026-09-14, `docs/Roadmap.md` "До релиза" item 6) — the
    /// device's live reachability, `facts.ping_ok`/`facts.snmp_ok` in scope — see
    /// `crate::util::facts_to_map`'s docs for why these come in as plain parameters here
    /// rather than living on `DeviceFacts` itself. Lets a profile's `match.expression`
    /// re-route a device that's stopped answering SNMP to a lower-fidelity fallback
    /// profile, something no expression could express before this existed.
    pub async fn match_profile(
        &self,
        facts: &DeviceFacts,
        ping_ok: Option<bool>,
        snmp_ok: Option<bool>,
        metrics: &Metrics,
    ) -> anyhow::Result<Option<ProfileFile>> {
        let profiles = self.profiles.read().await;
        for profile in profiles.iter() {
            let mut scope = Scope::new();
            scope.push("facts", facts_to_map(facts, ping_ok, snmp_ok));
            scope.push("metrics", metrics_to_map(metrics));
            let matched: bool = self
                .engine
                .eval_with_scope::<bool>(&mut scope, &profile.match_expr.expression)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "profile '{}': match expression error: {}",
                        profile.profile.name,
                        e
                    )
                })?;
            if matched {
                return Ok(Some(profile.clone()));
            }
        }
        Ok(None)
    }

    pub async fn profile_by_name(&self, name: &str) -> Option<ProfileFile> {
        self.profiles
            .read()
            .await
            .iter()
            .find(|p| p.profile.name == name)
            .cloned()
    }

    /// Syntax-only check — compiles `expression` without evaluating it against any
    /// device's data. Added 2026-09-17 (audit finding #3 — see
    /// `docs/Changelog/2026-09-17 - Аудит глазами оператора...md`): before this,
    /// `discovery-web`'s `upsert_profile` validated a profile's trap/syslog/metrics
    /// sections at save time but not `match.expression` itself, despite it being the one
    /// piece of Rhai every profile has and the one every device's config ultimately
    /// depends on — a typo here saved silently and only ever surfaced later as an opaque
    /// `WARN "job failed"` on an unrelated queue (`dedup`'s `DedupResolver`, the first
    /// thing to actually evaluate the broken expression), with nothing in the UI
    /// connecting that failure back to the profile edit that caused it. Same
    /// `engine.compile(...)`-based pattern `discovery_dsl::topology::TopologyEvaluator::
    /// validate_expression`/`discovery_dsl::group_alerts::GroupAlertEvaluator::
    /// validate_expression` already established for the newer Rhai entry points — this
    /// brings the oldest one in the system up to the same standard.
    pub fn validate_expression(&self, expression: &str) -> anyhow::Result<()> {
        self.engine
            .compile(expression)
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("{e}"))
    }
}

fn sorted_by_priority(mut profiles: Vec<ProfileFile>) -> Vec<ProfileFile> {
    profiles.sort_by(|a, b| b.profile.priority.cmp(&a.profile.priority));
    profiles
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MatchSection, MetricsSection, ProfileMeta};
    use discovery_core::MetricValue;

    fn profile(name: &str, priority: i32, expr: &str) -> ProfileFile {
        ProfileFile {
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            profile: ProfileMeta {
                name: name.into(),
                priority,
            },
            match_expr: MatchSection {
                expression: expr.into(),
            },
            metrics: MetricsSection::default(),
            alerts: vec![],
            version: "test-version".into(),
        }
    }

    fn metrics_with_sys_descr(sys_descr: &str) -> Metrics {
        let mut m = Metrics::default();
        m.insert("sys_descr", MetricValue::Str(sys_descr.to_string()));
        m
    }

    #[tokio::test]
    async fn picks_highest_priority_matching_profile_regardless_of_input_order() {
        // Deliberately given in the "wrong" order — the matcher must sort by priority
        // itself, not trust the caller's ordering.
        let profiles = vec![
            profile("catchall", 0, "true"),
            profile("cisco", 100, r#"metrics.sys_descr.contains("Cisco")"#),
        ];
        let matcher = ProfileMatcher::new(profiles);
        let facts = DeviceFacts {
            ip: "10.0.0.1".into(),
        };
        let metrics = metrics_with_sys_descr("Cisco IOS");
        let matched = matcher
            .match_profile(&facts, None, None, &metrics)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(matched.profile.name, "cisco");
    }

    #[tokio::test]
    async fn falls_back_to_catchall_when_nothing_specific_matches() {
        let profiles = vec![
            profile("cisco", 100, r#"metrics.sys_descr.contains("Cisco")"#),
            profile("catchall", 0, "true"),
        ];
        let matcher = ProfileMatcher::new(profiles);
        let facts = DeviceFacts {
            ip: "10.0.0.2".into(),
        };
        let metrics = metrics_with_sys_descr("Generic Host");
        let matched = matcher
            .match_profile(&facts, None, None, &metrics)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(matched.profile.name, "catchall");
    }

    #[tokio::test]
    async fn returns_none_when_nothing_matches_and_there_is_no_catchall() {
        let profiles = vec![profile(
            "cisco",
            100,
            r#"metrics.sys_descr.contains("Cisco")"#,
        )];
        let matcher = ProfileMatcher::new(profiles);
        let facts = DeviceFacts {
            ip: "10.0.0.3".into(),
        };
        let metrics = metrics_with_sys_descr("Generic Host");
        assert!(matcher
            .match_profile(&facts, None, None, &metrics)
            .await
            .unwrap()
            .is_none());
    }

    /// `docs/Roadmap.md` "До релиза" item 6 (2026-09-14) — a `match.expression` can route
    /// a device whose SNMP has stopped answering to a lower-fidelity fallback profile,
    /// something no expression could reference before `facts.snmp_ok` existed.
    #[tokio::test]
    async fn match_expression_can_route_on_live_snmp_status() {
        let profiles = vec![
            profile("snmp-down-fallback", 100, "facts.snmp_ok == false"),
            profile("catchall", 0, "true"),
        ];
        let matcher = ProfileMatcher::new(profiles);
        let facts = DeviceFacts {
            ip: "10.0.0.4".into(),
        };

        let matched = matcher
            .match_profile(&facts, Some(true), Some(false), &Metrics::default())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            matched.profile.name, "snmp-down-fallback",
            "SNMP genuinely down must route to the fallback profile"
        );

        let matched = matcher
            .match_profile(&facts, Some(true), Some(true), &Metrics::default())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            matched.profile.name, "catchall",
            "SNMP up must not trigger the fallback"
        );
    }

    #[tokio::test]
    async fn a_missing_metric_in_match_expression_is_treated_as_no_match_not_an_error() {
        // Consequence of moving identity data off `DeviceFacts` and into the flexible
        // `Metrics` bag: a subnet that never configured `sys_descr` in its `oids` means
        // `metrics.sys_descr` evaluates to `()` (Rhai's documented behavior for a missing
        // map key), and `().contains(...)` — confirm this fails the match cleanly rather
        // than erroring the whole match_profile call.
        let profiles = vec![
            profile("cisco", 100, r#"metrics.sys_descr.contains("Cisco")"#),
            profile("catchall", 0, "true"),
        ];
        let matcher = ProfileMatcher::new(profiles);
        let facts = DeviceFacts {
            ip: "10.0.0.4".into(),
        };
        let matched = matcher
            .match_profile(&facts, None, None, &Metrics::default())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(matched.profile.name, "catchall", "a profile referencing an absent metric must simply not match, falling through to the catch-all");
    }

    #[tokio::test]
    async fn reload_replaces_the_active_set_and_changes_the_signature() {
        let matcher = ProfileMatcher::new(vec![profile("a", 0, "true")]);
        let sig_before = matcher.signature().await;

        matcher.reload(vec![profile("b", 0, "true")]).await;
        let sig_after = matcher.signature().await;

        assert_ne!(sig_before, sig_after);
        assert!(matcher.profile_by_name("a").await.is_none());
        assert!(matcher.profile_by_name("b").await.is_some());
    }

    #[tokio::test]
    async fn reloading_with_identical_content_does_not_change_the_signature() {
        let matcher = ProfileMatcher::new(vec![profile("a", 0, "true")]);
        let sig_before = matcher.signature().await;
        matcher.reload(vec![profile("a", 0, "true")]).await;
        assert_eq!(sig_before, matcher.signature().await);
    }

    /// 2026-09-17 audit finding #3 — pins down the exact fix: a broken match expression
    /// must be rejected here, not silently accepted the way it was before this method
    /// existed.
    #[test]
    fn validate_expression_accepts_well_formed_syntax_and_rejects_broken_syntax() {
        let matcher = ProfileMatcher::new(vec![]);
        assert!(matcher
            .validate_expression(r#"metrics.sys_object_id == "1.2.3""#)
            .is_ok());
        assert!(matcher
            .validate_expression("metrics.sys_object_id == ((( broken rhai")
            .is_err());
    }
}
