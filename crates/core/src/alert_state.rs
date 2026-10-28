use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use chrono::{DateTime, Utc};

use crate::{Alert, AlertLevel, AlertState, AutoClearReason};

/// Tracks per-(device, alert name) flap state so a condition has to stay in its
/// "deactivate" zone for `clear_after` before we actually clear the alert. The DSL layer
/// only ever answers "is the activation/deactivation condition true right now" for a
/// single poll — debouncing that into "is this incident still open" is a deliberately
/// separate, non-DSL concern.
///
/// This exists because of a very concrete failure mode: a single missed/late poll flipping
/// a threshold condition false for one cycle is enough to close and immediately reopen an
/// incident, spamming the ticketing system with duplicates — this tracker is the direct
/// answer to that class of bug.
///
/// **Rewritten 2026-08-17 (direct user request — full alert-history feature):**
///
/// 1. **Separate activation/deactivation conditions**, not just a single boolean's
///    negation — direct request: "нужно что бы были условия активации, деактивации".
///    `observe` now takes `activation_true`/`deactivation_true` independently
///    (`discovery_agent::handlers::AlertEvalHandler` computes `deactivation_true` as
///    `!activation_true` when a rule doesn't declare its own
///    `AlertRule::deactivation_expression` — that's the only place the old "just negate
///    it" behavior survives, this tracker itself no longer assumes it). This is what
///    makes hysteresis possible (e.g. activate at `cpu > 90`, only deactivate at
///    `cpu < 70`, staying open through the dead zone in between) — something a single
///    condition structurally can't express.
/// 2. **Each activation-to-clear cycle is now a genuinely new [`Alert`]** (fresh `id`,
///    fresh `first_seen`), not the old behavior of reusing the same entry/id across
///    repeated activate→clear→activate cycles for the same (device, rule). The active
///    incident is removed on clear, while a bounded switch history may remain until its
///    flapping window expires. This lets the tracker suppress notification storms without
///    changing durable incident history: each occurrence is still its own row.
///
/// **Row-scoped keying (2026-08-29, direct user request — "тревога по порту"):** the
/// tracking key grew a third component, `row_key: Option<String>`. `None` is every alert
/// that existed before this feature — one incident per `(device_id, rule_name)`, unchanged
/// behavior. `Some(key)` is a row-scoped rule (`discovery_dsl::AlertRule::row_metric` is
/// set) — `discovery_agent::handlers::AlertEvalHandler` calls `observe` once per matching
/// row of the declared table metric, each with its own `row_key` (e.g. a port's `ifDescr`),
/// giving each row fully independent activation/deactivation/grace-period tracking under
/// the same rule name. See [`AutoClearReason`] for the other row-scoped addition — a
/// distinct "why" for a `Cleared` transition caused by the row disappearing from the table
/// entirely, rather than its own condition resolving.
#[derive(Default)]
pub struct AlertStateTracker {
    state: Mutex<HashMap<(uuid::Uuid, String, Option<String>), TrackedState>>,
    statuses: Mutex<HashMap<(uuid::Uuid, String, Option<String>), crate::AlertRuleStatus>>,
    response_deadlines: Mutex<HashMap<uuid::Uuid, DateTime<Utc>>>,
    shared_rules: Mutex<std::collections::BTreeMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AlertHysteresisConfig {
    pub activate_after: chrono::Duration,
    pub clear_after: chrono::Duration,
    pub flap_window: chrono::Duration,
    pub flap_threshold: usize,
    pub flap_clear_threshold: Option<usize>,
}

const FLAPPING_REASON: &str = "Подавлено: слишком много переключений за заданное окно";

#[derive(Clone, Copy, PartialEq, Eq)]
enum FlapZone {
    Activation,
    Deactivation,
}

struct TrackedState {
    active: Option<TrackedAlert>,
    activation_true_since: Option<DateTime<Utc>>,
    last_zone: Option<FlapZone>,
    switches: VecDeque<DateTime<Utc>>,
    flapping: bool,
}

struct TrackedAlert {
    alert: Alert,
    /// `Some(t)` once `deactivation_true` first turned true for the currently-open
    /// incident — reset to `None` any time it flips back to false before `clear_after`
    /// elapses (the flapping-reset behavior the whole tracker exists for).
    condition_false_since: Option<DateTime<Utc>>,
}

impl TrackedState {
    fn new() -> Self {
        Self {
            active: None,
            activation_true_since: None,
            last_zone: None,
            switches: VecDeque::new(),
            flapping: false,
        }
    }

    fn is_flapping(&mut self, config: AlertHysteresisConfig, now: DateTime<Utc>) -> bool {
        if config.flap_window <= chrono::Duration::zero() || config.flap_threshold == 0 {
            self.switches.clear();
            self.flapping = false;
            return false;
        }
        while self
            .switches
            .front()
            .is_some_and(|at| now - *at > config.flap_window)
        {
            self.switches.pop_front();
        }
        let threshold = if self.flapping {
            config.flap_clear_threshold.unwrap_or(config.flap_threshold)
        } else {
            config.flap_threshold
        };
        self.flapping = self.switches.len() >= threshold;
        self.flapping
    }
}

#[derive(Debug)]
pub enum AlertTransition {
    /// Not currently active, and `activation_true` was false — nothing changed, nothing
    /// to persist.
    None,
    /// Was not active (or had just cleared) and `activation_true` just turned true — a
    /// new incident, with a freshly generated `id`.
    Activated(Alert),
    /// Was active, `deactivation_true` has held for at least `clear_after` — incident
    /// closed. This is the last time this specific `Alert.id` is ever seen — a later
    /// re-activation gets a brand new one.
    Cleared(Alert),
    /// Was active and stays active (`deactivation_true` is false, or hasn't held long
    /// enough yet) — same `id`, just an updated `message`/`last_seen` snapshot.
    StillActive(Alert),
}

impl AlertStateTracker {
    pub fn replace_shared_rules(
        &self,
        rules: std::collections::BTreeMap<String, serde_json::Value>,
    ) {
        *self.shared_rules.lock().unwrap() = rules;
    }
    pub fn shared_rule(&self, name: &str) -> Option<serde_json::Value> {
        self.shared_rules.lock().unwrap().get(name).cloned()
    }
    pub fn update_operator_state(&self, alert: &Alert) {
        let key = (alert.device_id, alert.name.clone(), alert.row_key.clone());
        if let Some(active) = self
            .state
            .lock()
            .unwrap()
            .get_mut(&key)
            .and_then(|s| s.active.as_mut())
        {
            if active.alert.id == alert.id {
                active.alert.acknowledged_at = alert.acknowledged_at;
                active.alert.acknowledged_by = alert.acknowledged_by.clone();
                active.alert.snoozed_until = alert.snoozed_until;
                active.alert.snoozed_by = alert.snoozed_by.clone();
                active.alert.details = alert.details.clone();
            }
        }
    }

    pub fn set_response_deadline(&self, device_id: uuid::Uuid, deadline: Option<DateTime<Utc>>) {
        let mut deadlines = self.response_deadlines.lock().unwrap();
        if let Some(at) = deadline {
            deadlines.insert(device_id, at);
        } else {
            deadlines.remove(&device_id);
        }
    }

    pub fn due_devices(&self, now: DateTime<Utc>) -> Vec<uuid::Uuid> {
        let mut devices = std::collections::HashSet::new();
        for (id, at) in self.response_deadlines.lock().unwrap().iter() {
            if *at <= now {
                devices.insert(*id);
            }
        }
        for ((id, _, _), status) in self.statuses.lock().unwrap().iter() {
            let due = status.next_check_at.is_some_and(|at| at <= now)
                || status.activation_since.is_some_and(|at| {
                    now >= at + chrono::Duration::seconds(status.activate_after_seconds as i64)
                })
                || status.recovery_since.is_some_and(|at| {
                    now >= at + chrono::Duration::seconds(status.clear_after_seconds as i64)
                });
            if due {
                devices.insert(*id);
            }
        }
        devices.into_iter().collect()
    }

    pub fn rule_status(
        &self,
        device_id: uuid::Uuid,
        name: &str,
        row_key: Option<&str>,
    ) -> Option<crate::AlertRuleStatus> {
        self.statuses
            .lock()
            .unwrap()
            .get(&(device_id, name.into(), row_key.map(str::to_string)))
            .cloned()
    }
    pub fn record_rule_status(&self, device_id: uuid::Uuid, mut status: crate::AlertRuleStatus) {
        let key = (device_id, status.name.clone(), status.row_key.clone());
        if let Some(tracked) = self.state.lock().unwrap().get(&key) {
            status.activation_since = tracked.activation_true_since;
            status.recovery_since = tracked
                .active
                .as_ref()
                .and_then(|a| a.condition_false_since);
            status.active_alert_id = tracked.active.as_ref().map(|a| a.alert.id);
            status.flapping = tracked.flapping;
        }
        self.statuses.lock().unwrap().insert(key, status);
    }
    pub fn rule_statuses(&self, device_id: uuid::Uuid) -> Vec<crate::AlertRuleStatus> {
        let mut statuses: Vec<_> = self
            .statuses
            .lock()
            .unwrap()
            .iter()
            .filter(|((id, _, _), _)| *id == device_id)
            .map(|(_, status)| status.clone())
            .collect();
        statuses.sort_by(|a, b| (&a.name, &a.row_key).cmp(&(&b.name, &b.row_key)));
        statuses
    }
    /// Failed observations break continuity; an error cannot count as recovery time.
    pub fn interrupt_observation(&self, device_id: uuid::Uuid, name: &str, row_key: Option<&str>) {
        if let Some(t) = self.state.lock().unwrap().get_mut(&(
            device_id,
            name.into(),
            row_key.map(str::to_string),
        )) {
            t.activation_true_since = None;
            if let Some(a) = &mut t.active {
                a.condition_false_since = None;
            }
        }
    }
    pub fn set_details(
        &self,
        device_id: uuid::Uuid,
        name: &str,
        row_key: Option<&str>,
        details: crate::AlertDetails,
    ) {
        if let Some(a) = self
            .state
            .lock()
            .unwrap()
            .get_mut(&(device_id, name.into(), row_key.map(str::to_string)))
            .and_then(|t| t.active.as_mut())
        {
            a.alert.details = details;
        }
    }
    pub fn retain_rule_statuses(&self, device_id: uuid::Uuid, names: &[String]) {
        self.statuses
            .lock()
            .unwrap()
            .retain(|(id, name, _), _| *id != device_id || names.contains(name));
        self.state.lock().unwrap().retain(|(id, name, _), t| {
            *id != device_id || names.contains(name) || t.active.is_some()
        });
    }
    pub fn snapshot_for_device(&self, device_id: uuid::Uuid) -> crate::AlertRuntimeSnapshot {
        let states = self
            .state
            .lock()
            .unwrap()
            .iter()
            .filter(|((id, _, _), _)| *id == device_id)
            .map(|((_, name, key), t)| crate::PersistedRuleState {
                name: name.clone(),
                row_key: key.clone(),
                active_alert_id: t.active.as_ref().map(|a| a.alert.id),
                activation_since: t.activation_true_since,
                recovery_since: t.active.as_ref().and_then(|a| a.condition_false_since),
                last_zone: t.last_zone.map(|z| z == FlapZone::Activation),
                switches: t.switches.iter().copied().collect(),
                flapping: t.flapping,
            })
            .collect();
        crate::AlertRuntimeSnapshot {
            response_deadline: self
                .response_deadlines
                .lock()
                .unwrap()
                .get(&device_id)
                .copied(),
            states,
            statuses: self.rule_statuses(device_id),
        }
    }
    /// Authoritative incidents are hydrated first. A stale snapshot must never resurrect
    /// an incident closed or deleted by an operator after the snapshot was written.
    pub fn restore_snapshot(&self, device_id: uuid::Uuid, snapshot: crate::AlertRuntimeSnapshot) {
        self.set_response_deadline(device_id, snapshot.response_deadline);
        {
            let mut state = self.state.lock().unwrap();
            for s in snapshot.states {
                let key = (device_id, s.name, s.row_key);
                let tracked = state.entry(key).or_insert_with(TrackedState::new);
                if s.active_alert_id != tracked.active.as_ref().map(|a| a.alert.id) {
                    continue;
                }
                tracked.activation_true_since = s.activation_since;
                if let Some(a) = &mut tracked.active {
                    a.condition_false_since = s.recovery_since;
                }
                tracked.last_zone = s.last_zone.map(|v| {
                    if v {
                        FlapZone::Activation
                    } else {
                        FlapZone::Deactivation
                    }
                });
                tracked.switches = s.switches.into();
                tracked.flapping = s.flapping;
            }
        }
        for status in snapshot.statuses {
            self.record_rule_status(device_id, status);
        }
    }

    pub fn new() -> Self {
        Self::default()
    }

    /// Restores an active incident loaded from the durable alert store after a process
    /// restart. The debounce timer deliberately starts unset: the first post-restart
    /// observation must treat the persisted incident as continuously active, not as a
    /// deactivation that began while the process was down.
    pub fn restore_active(&self, alert: Alert) {
        if alert.state != AlertState::Active {
            return;
        }
        let key = (alert.device_id, alert.name.clone(), alert.row_key.clone());
        let mut tracked = TrackedState::new();
        tracked.active = Some(TrackedAlert {
            alert,
            condition_false_since: None,
        });
        self.state.lock().unwrap().insert(key, tracked);
    }

    /// `row_key` (added 2026-08-29 — see this type's docs) is part of the tracking
    /// identity, alongside `device_id`/`name` — `None` for an ordinary device-level alert,
    /// `Some(key)` for one row of a row-scoped rule.
    ///
    /// `auto_clear_reason` is only consulted if this call's `deactivation_true` ends up
    /// actually completing a `Cleared` transition (grace period already elapsed, or
    /// `clear_after` is zero) — it's stamped onto that specific `Alert`, not accumulated or
    /// remembered across calls. Pass `None` for an ordinary condition-based deactivation;
    /// see [`AutoClearReason`]'s docs for the one case that isn't.
    #[allow(clippy::too_many_arguments)]
    pub fn observe(
        &self,
        device_id: uuid::Uuid,
        device_ip: &str,
        name: &str,
        row_key: Option<&str>,
        level: AlertLevel,
        message: String,
        facts: Option<serde_json::Value>,
        activation_true: bool,
        deactivation_true: bool,
        auto_clear_reason: Option<AutoClearReason>,
        clear_after: chrono::Duration,
        now: DateTime<Utc>,
    ) -> AlertTransition {
        self.observe_with_config(
            device_id,
            device_ip,
            name,
            row_key,
            level,
            message,
            facts,
            activation_true,
            deactivation_true,
            auto_clear_reason,
            AlertHysteresisConfig {
                clear_after,
                ..AlertHysteresisConfig::default()
            },
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn observe_with_config(
        &self,
        device_id: uuid::Uuid,
        device_ip: &str,
        name: &str,
        row_key: Option<&str>,
        level: AlertLevel,
        message: String,
        facts: Option<serde_json::Value>,
        activation_true: bool,
        deactivation_true: bool,
        auto_clear_reason: Option<AutoClearReason>,
        config: AlertHysteresisConfig,
        now: DateTime<Utc>,
    ) -> AlertTransition {
        let mut state = self.state.lock().unwrap();
        let key = (device_id, name.to_string(), row_key.map(str::to_string));
        let tracked = state.entry(key.clone()).or_insert_with(TrackedState::new);

        let zone = if activation_true {
            Some(FlapZone::Activation)
        } else if deactivation_true {
            Some(FlapZone::Deactivation)
        } else {
            None
        };
        if let Some(zone) = zone {
            if tracked.last_zone.is_some_and(|previous| previous != zone) {
                tracked.switches.push_back(now);
            }
            tracked.last_zone = Some(zone);
        }
        let flapping = tracked.is_flapping(config, now);
        let suppression_reason = flapping.then(|| FLAPPING_REASON.to_string());

        if let Some(entry) = tracked.active.as_mut() {
            // Currently active — only `deactivation_true` decides anything from here.
            // `activation_true` is irrelevant while already open (see this type's docs).
            entry.alert.last_seen = now;
            entry.alert.message = message;
            entry.alert.flapping = flapping;
            entry.alert.suppression_reason = suppression_reason;

            if deactivation_true {
                let since = *entry.condition_false_since.get_or_insert(now);
                if now - since >= config.clear_after {
                    let mut cleared = entry.alert.clone();
                    cleared.state = AlertState::Cleared;
                    cleared.cleared_at = Some(now);
                    cleared.auto_clear_reason = auto_clear_reason;
                    tracked.active = None;
                    return AlertTransition::Cleared(cleared);
                }
                return AlertTransition::StillActive(entry.alert.clone());
            }

            // Deactivation condition receded before the grace period elapsed — reset the
            // timer, same anti-flapping behavior as before the activation/deactivation
            // split.
            entry.condition_false_since = None;
            return AlertTransition::StillActive(entry.alert.clone());
        }

        // Not currently tracked as active — only `activation_true` matters for opening a
        // brand new incident.
        if activation_true {
            let activation_since = *tracked.activation_true_since.get_or_insert(now);
            if now - activation_since < config.activate_after {
                return AlertTransition::None;
            }
            tracked.activation_true_since = None;
            let alert = Alert {
                details: Default::default(),
                id: uuid::Uuid::new_v4(),
                device_id,
                device_ip: device_ip.to_string(),
                name: name.to_string(),
                row_key: row_key.map(str::to_string),
                level,
                message,
                state: AlertState::Active,
                facts,
                first_seen: now,
                last_seen: now,
                cleared_at: None,
                closed_by: None,
                acknowledged_by: None,
                acknowledged_at: None,
                snoozed_until: None,
                snoozed_by: None,
                auto_clear_reason: None,
                repeat_count: 0,
                escalation_level: 0,
                repeated_at: None,
                escalation_reason: None,
                flapping,
                suppression_reason,
                comment_count: 0,
                suppressed_by_alert_id: None,
                // Filled in by `discovery_agent::handlers::persist_alert_transition`
                // right before the initial persist, if applicable — this tracker is
                // purely in-memory and has no store access to look up a recent manual
                // close itself, same split `suppressed_by_alert_id` already draws.
                reopened_from_alert_id: None,
            };
            tracked.active = Some(TrackedAlert {
                alert: alert.clone(),
                condition_false_since: None,
            });
            return AlertTransition::Activated(alert);
        }

        tracked.activation_true_since = None;
        AlertTransition::None
    }

    /// All alerts currently considered open — the in-memory live view. The durable,
    /// paginated/filterable history (including cleared alerts) lives in
    /// `discovery_alerts::AlertStore` instead; this method is a cheap, no-DB-round-trip
    /// snapshot still used wherever only "what's open right now" matters.
    pub fn active_alerts(&self) -> Vec<Alert> {
        self.state
            .lock()
            .unwrap()
            .values()
            .filter_map(|t| t.active.as_ref().map(|a| a.alert.clone()))
            .collect()
    }

    /// Currently open incidents for one device. The alert evaluator uses this snapshot
    /// to close keys whose rule disappeared from the device's profile.
    pub fn active_alerts_for_device(&self, device_id: uuid::Uuid) -> Vec<Alert> {
        self.state
            .lock()
            .unwrap()
            .iter()
            .filter(|((id, _, _), _)| *id == device_id)
            .filter_map(|(_, tracked)| tracked.active.as_ref().map(|a| a.alert.clone()))
            .collect()
    }

    /// Drops every live incident for a device that was deleted from durable storage.
    /// Device deletion removes the durable alert rows in a separate store, so leaving
    /// these entries here would keep deleted incidents visible to the in-memory
    /// incidents endpoint and group-alert correlation for the rest of the process.
    pub fn remove_for_device(&self, device_id: uuid::Uuid) {
        self.set_response_deadline(device_id, None);
        self.statuses
            .lock()
            .unwrap()
            .retain(|(id, _, _), _| *id != device_id);
        self.state
            .lock()
            .unwrap()
            .retain(|(id, _, _), _| *id != device_id);
    }

    /// Severs live tracking for `(device_id, name)` without writing anything — added
    /// 2026-08-18 for manual close/delete from the dashboard (direct user request: "нужна
    /// возможность вручную закрыть тревогу и отдельно — удалить тревогу"). A no-op if
    /// nothing's currently tracked for this key (already cleared, or never was active).
    ///
    /// **Why this has to exist at all, not just an `UPDATE alerts SET state = 'cleared'`
    /// in `discovery-web`:** if the underlying condition is still genuinely true and this
    /// entry is left in the tracker, the *very next* `AlertEvalHandler` tick would
    /// re-observe it as `StillActive` and write `state = 'active'` right back over
    /// whatever the dashboard just set — a manual close needs to sever tracking here, not
    /// just edit the durable row, or it wouldn't stick past one poll cycle. Deliberately
    /// does **not** try to suppress re-activation forever — if the condition is still true,
    /// the next tick opens a genuinely *new* incident (fresh `id`/`first_seen`), same as
    /// any other reactivation-after-clear. This project has no acknowledge/snooze
    /// workflow (see `discovery/CLAUDE.md`'s AggreGate gap analysis) — manual close means
    /// "I've dealt with this occurrence", not "stop telling me about this forever".
    pub fn remove(&self, device_id: uuid::Uuid, name: &str, row_key: Option<&str>) {
        let key = (device_id, name.to_string(), row_key.map(str::to_string));
        self.state.lock().unwrap().remove(&key);
        if let Some(status) = self.statuses.lock().unwrap().get_mut(&key) {
            status.active_alert_id = None;
            status.activation_since = None;
            status.recovery_since = None;
        }
    }

    /// Every currently-open row-scoped alert (`row_key.is_some()`) for one
    /// `(device_id, rule_name)` pair — used by `AlertEvalHandler`'s row-scoped loop to
    /// find rows that were open on a previous tick but didn't show up among this tick's
    /// freshly-evaluated rows at all (the row vanished from the source table metric —
    /// see [`AutoClearReason::RowMissing`]'s docs). Returns full `Alert` snapshots, not
    /// just the keys, so the caller can reuse the last-known `message`/`level` for the
    /// synthetic "still missing" `observe()` call it makes for each one (there's no row
    /// left to re-render a message from).
    ///
    /// Filters the map directly by key rather than going through [`Self::active_alerts`]
    /// (which clones *every* currently-open alert system-wide) — this runs once per
    /// row-scoped rule per device per `AlertEval` tick, so an O(total open alerts) scan
    /// here would scale badly once row-scoped rules are common (see
    /// `docs/Architecture/Scale и Performance.md`). Still an O(n) scan of the whole map
    /// today (no secondary index by `(device_id, name)`) — acceptable for a brand-new,
    /// opt-in feature; revisit if it's ever actually measured as a bottleneck, same
    /// "don't guess, measure" discipline the rest of this project's scale work follows.
    pub fn open_row_alerts(&self, device_id: uuid::Uuid, rule_name: &str) -> Vec<Alert> {
        self.state
            .lock()
            .unwrap()
            .iter()
            .filter(|((d, n, row_key), _)| *d == device_id && n == rule_name && row_key.is_some())
            .filter_map(|(_, tracked)| tracked.active.as_ref().map(|a| a.alert.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors the pre-2026-08-17 single-condition behavior exactly: a rule with no
    /// separate `deactivation_expression` has the caller pass `deactivation_true =
    /// !activation_true`, reproducing the old "clears once the same condition goes false
    /// for long enough" semantics.
    fn observe_single_condition(
        tracker: &AlertStateTracker,
        device_id: uuid::Uuid,
        ip: &str,
        name: &str,
        message: &str,
        condition_true: bool,
        clear_after: chrono::Duration,
        now: DateTime<Utc>,
    ) -> AlertTransition {
        tracker.observe(
            device_id,
            ip,
            name,
            None,
            AlertLevel::Warning,
            message.into(),
            None,
            condition_true,
            !condition_true,
            None,
            clear_after,
            now,
        )
    }

    #[test]
    fn activates_immediately_but_clears_only_after_grace_period() {
        let tracker = AlertStateTracker::new();
        let device_id = uuid::Uuid::new_v4();
        let t0 = Utc::now();

        let r1 = observe_single_condition(
            &tracker,
            device_id,
            "1.2.3.4",
            "high_cpu",
            "cpu high",
            true,
            chrono::Duration::seconds(60),
            t0,
        );
        assert!(matches!(r1, AlertTransition::Activated(_)));

        // Condition flips false but the grace period hasn't elapsed yet -> still active.
        let r2 = observe_single_condition(
            &tracker,
            device_id,
            "1.2.3.4",
            "high_cpu",
            "cpu ok",
            false,
            chrono::Duration::seconds(60),
            t0 + chrono::Duration::seconds(10),
        );
        assert!(matches!(r2, AlertTransition::StillActive(_)));

        // Past the grace period -> clears.
        let r3 = observe_single_condition(
            &tracker,
            device_id,
            "1.2.3.4",
            "high_cpu",
            "cpu ok",
            false,
            chrono::Duration::seconds(60),
            t0 + chrono::Duration::seconds(70),
        );
        assert!(matches!(r3, AlertTransition::Cleared(_)));
    }

    #[test]
    fn flapping_condition_resets_the_grace_timer() {
        let tracker = AlertStateTracker::new();
        let device_id = uuid::Uuid::new_v4();
        let t0 = Utc::now();

        observe_single_condition(
            &tracker,
            device_id,
            "1.2.3.4",
            "high_cpu",
            "cpu high",
            true,
            chrono::Duration::seconds(60),
            t0,
        );
        observe_single_condition(
            &tracker,
            device_id,
            "1.2.3.4",
            "high_cpu",
            "cpu ok",
            false,
            chrono::Duration::seconds(60),
            t0 + chrono::Duration::seconds(10),
        );
        // Condition true again before the grace period elapsed -> stays active, timer resets.
        let r = observe_single_condition(
            &tracker,
            device_id,
            "1.2.3.4",
            "high_cpu",
            "cpu high",
            true,
            chrono::Duration::seconds(60),
            t0 + chrono::Duration::seconds(20),
        );
        assert!(matches!(r, AlertTransition::StillActive(_)));

        // 60s after the *second* activation, not the first -> should not have cleared yet.
        let r2 = observe_single_condition(
            &tracker,
            device_id,
            "1.2.3.4",
            "high_cpu",
            "cpu ok",
            false,
            chrono::Duration::seconds(60),
            t0 + chrono::Duration::seconds(30),
        );
        assert!(matches!(r2, AlertTransition::StillActive(_)));
    }

    #[test]
    fn unrelated_device_or_alert_name_does_not_clear_a_still_active_one() {
        let tracker = AlertStateTracker::new();
        let device_a = uuid::Uuid::new_v4();
        let device_b = uuid::Uuid::new_v4();
        let t0 = Utc::now();

        observe_single_condition(
            &tracker,
            device_a,
            "1.2.3.4",
            "high_cpu",
            "x",
            true,
            chrono::Duration::seconds(60),
            t0,
        );
        observe_single_condition(
            &tracker,
            device_b,
            "5.6.7.8",
            "high_cpu",
            "y",
            false,
            chrono::Duration::seconds(60),
            t0,
        );

        let active: Vec<_> = tracker.active_alerts();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].device_id, device_a);
    }

    /// Direct user request 2026-08-17: separate activation/deactivation conditions enable
    /// hysteresis — an incident that stays open through a "dead zone" where neither
    /// condition holds, only clearing once the deactivation condition specifically fires.
    #[test]
    fn separate_deactivation_condition_keeps_the_incident_open_through_the_dead_zone() {
        let tracker = AlertStateTracker::new();
        let device_id = uuid::Uuid::new_v4();
        let t0 = Utc::now();

        // Activates at cpu > 90.
        let r1 = tracker.observe(
            device_id,
            "1.2.3.4",
            "high_cpu",
            None,
            AlertLevel::Warning,
            "cpu 95".into(),
            None,
            true,
            false,
            None,
            chrono::Duration::seconds(0),
            t0,
        );
        assert!(matches!(r1, AlertTransition::Activated(_)));

        // cpu drops to 80 — neither activation (>90) nor deactivation (<70) holds. Must
        // stay active: a plain single-condition design (deactivate = !activate) would
        // have started clearing here; this must not.
        let r2 = tracker.observe(
            device_id,
            "1.2.3.4",
            "high_cpu",
            None,
            AlertLevel::Warning,
            "cpu 80".into(),
            None,
            false, // activation_true
            false, // deactivation_true — dead zone, neither condition holds
            None,
            chrono::Duration::seconds(0),
            t0 + chrono::Duration::seconds(10),
        );
        assert!(
            matches!(r2, AlertTransition::StillActive(_)),
            "must stay open through the dead zone between activation and deactivation thresholds"
        );

        // cpu finally drops below the deactivation threshold (70) — now it clears
        // (clear_after=0 here, so immediately).
        let r3 = tracker.observe(
            device_id,
            "1.2.3.4",
            "high_cpu",
            None,
            AlertLevel::Warning,
            "cpu 65".into(),
            None,
            false,
            true, // deactivation_true
            None,
            chrono::Duration::seconds(0),
            t0 + chrono::Duration::seconds(20),
        );
        assert!(matches!(r3, AlertTransition::Cleared(_)));
    }

    /// Direct user request 2026-08-17: "какие facts доставать в момент создания тревоги".
    #[test]
    fn facts_are_captured_only_at_activation_and_frozen_thereafter() {
        let tracker = AlertStateTracker::new();
        let device_id = uuid::Uuid::new_v4();
        let t0 = Utc::now();

        let facts_at_activation = serde_json::json!({"cpu": 95, "model": "switch-x"});
        let r1 = tracker.observe(
            device_id,
            "1.2.3.4",
            "high_cpu",
            None,
            AlertLevel::Warning,
            "cpu 95".into(),
            Some(facts_at_activation.clone()),
            true,
            false,
            None,
            chrono::Duration::seconds(60),
            t0,
        );
        let AlertTransition::Activated(a) = r1 else {
            panic!("expected Activated")
        };
        assert_eq!(a.facts, Some(facts_at_activation.clone()));

        // A later StillActive observation passes DIFFERENT facts (as
        // AlertEvalHandler always would, re-evaluating facts_expression every tick) —
        // must NOT overwrite what was captured at activation.
        let different_facts = serde_json::json!({"cpu": 91, "model": "switch-x"});
        let r2 = tracker.observe(
            device_id,
            "1.2.3.4",
            "high_cpu",
            None,
            AlertLevel::Warning,
            "cpu 91".into(),
            Some(different_facts),
            true,
            false,
            None,
            chrono::Duration::seconds(60),
            t0 + chrono::Duration::seconds(5),
        );
        let AlertTransition::StillActive(a2) = r2 else {
            panic!("expected StillActive")
        };
        assert_eq!(a2.facts, Some(facts_at_activation), "facts must stay frozen at whatever was captured on activation, not re-captured on every tick");
    }

    /// Direct user request 2026-08-17: each activate→clear cycle is a distinct incident
    /// in history, not the same row/id reused forever.
    #[test]
    fn reactivation_after_a_clear_gets_a_brand_new_alert_id() {
        let tracker = AlertStateTracker::new();
        let device_id = uuid::Uuid::new_v4();
        let t0 = Utc::now();

        let r1 = tracker.observe(
            device_id,
            "1.2.3.4",
            "high_cpu",
            None,
            AlertLevel::Warning,
            "up".into(),
            None,
            true,
            false,
            None,
            chrono::Duration::seconds(0),
            t0,
        );
        let AlertTransition::Activated(first) = r1 else {
            panic!("expected Activated")
        };

        let r2 = tracker.observe(
            device_id,
            "1.2.3.4",
            "high_cpu",
            None,
            AlertLevel::Warning,
            "down".into(),
            None,
            false,
            true,
            None,
            chrono::Duration::seconds(0),
            t0 + chrono::Duration::seconds(1),
        );
        assert!(matches!(r2, AlertTransition::Cleared(_)));

        let r3 = tracker.observe(
            device_id,
            "1.2.3.4",
            "high_cpu",
            None,
            AlertLevel::Warning,
            "up again".into(),
            None,
            true,
            false,
            None,
            chrono::Duration::seconds(0),
            t0 + chrono::Duration::seconds(2),
        );
        let AlertTransition::Activated(second) = r3 else {
            panic!("expected a fresh Activated")
        };
        assert_ne!(
            first.id, second.id,
            "a reactivation after clearing must be a distinct incident, not the same id reused"
        );
    }

    /// Direct user request 2026-08-18: manual close needs to sever live tracking, or the
    /// very next tick would just reassert `Active` right back (see `remove`'s docs).
    #[test]
    fn remove_severs_tracking_so_a_still_true_condition_opens_a_fresh_incident_not_still_active() {
        let tracker = AlertStateTracker::new();
        let device_id = uuid::Uuid::new_v4();
        let t0 = Utc::now();

        let r1 = observe_single_condition(
            &tracker,
            device_id,
            "1.2.3.4",
            "high_cpu",
            "cpu high",
            true,
            chrono::Duration::seconds(60),
            t0,
        );
        let AlertTransition::Activated(first) = r1 else {
            panic!("expected Activated")
        };
        assert_eq!(tracker.active_alerts().len(), 1);

        tracker.remove(device_id, "high_cpu", None);
        assert!(
            tracker.active_alerts().is_empty(),
            "remove must drop it from the live view immediately"
        );

        // Condition is still true (nothing about the underlying metric changed) — the
        // next observation must open a brand new incident, not resurrect the old one.
        let r2 = observe_single_condition(
            &tracker,
            device_id,
            "1.2.3.4",
            "high_cpu",
            "still high",
            true,
            chrono::Duration::seconds(60),
            t0 + chrono::Duration::seconds(5),
        );
        let AlertTransition::Activated(second) = r2 else {
            panic!("expected a fresh Activated, not StillActive — tracking was severed")
        };
        assert_ne!(first.id, second.id);
    }

    #[test]
    fn remove_is_a_noop_for_a_key_that_was_never_tracked() {
        let tracker = AlertStateTracker::new();
        tracker.remove(uuid::Uuid::new_v4(), "nonexistent", None); // must not panic
        assert!(tracker.active_alerts().is_empty());
    }

    #[test]
    fn remove_for_device_drops_all_live_alerts_but_keeps_other_devices() {
        let tracker = AlertStateTracker::new();
        let device = uuid::Uuid::new_v4();
        let other = uuid::Uuid::new_v4();
        let now = Utc::now();
        for (id, name, row) in [
            (device, "device-alert", None),
            (device, "row-alert", Some("Gi0/1")),
            (other, "other-alert", None),
        ] {
            assert!(matches!(
                tracker.observe(
                    id,
                    "10.0.0.1",
                    name,
                    row,
                    AlertLevel::Critical,
                    "test".to_string(),
                    None,
                    true,
                    false,
                    None,
                    chrono::Duration::zero(),
                    now,
                ),
                AlertTransition::Activated(_)
            ));
        }

        tracker.remove_for_device(device);

        let remaining = tracker.active_alerts();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].device_id, other);
    }

    /// Direct user request 2026-08-29 ("тревога по порту"): two different `row_key`s
    /// under the same `(device_id, rule_name)` must be fully independent incidents — one
    /// port recovering must not affect another still-down port's own tracking.
    #[test]
    fn different_row_keys_under_the_same_rule_are_independent_incidents() {
        let tracker = AlertStateTracker::new();
        let device_id = uuid::Uuid::new_v4();
        let t0 = Utc::now();

        let r1 = tracker.observe(
            device_id,
            "1.2.3.4",
            "port_down",
            Some("3"),
            AlertLevel::Warning,
            "port 3 down".into(),
            None,
            true,
            false,
            None,
            chrono::Duration::seconds(0),
            t0,
        );
        let AlertTransition::Activated(port3) = r1 else {
            panic!("expected Activated")
        };
        let r2 = tracker.observe(
            device_id,
            "1.2.3.4",
            "port_down",
            Some("5"),
            AlertLevel::Warning,
            "port 5 down".into(),
            None,
            true,
            false,
            None,
            chrono::Duration::seconds(0),
            t0,
        );
        let AlertTransition::Activated(port5) = r2 else {
            panic!("expected Activated")
        };
        assert_ne!(
            port3.id, port5.id,
            "different row_keys must be genuinely separate incidents"
        );
        assert_eq!(tracker.active_alerts().len(), 2);

        // Port 3 recovers — must clear WITHOUT touching port 5's still-open incident.
        let r3 = tracker.observe(
            device_id,
            "1.2.3.4",
            "port_down",
            Some("3"),
            AlertLevel::Warning,
            "port 3 up".into(),
            None,
            false,
            true,
            None,
            chrono::Duration::seconds(0),
            t0 + chrono::Duration::seconds(1),
        );
        assert!(matches!(r3, AlertTransition::Cleared(_)));
        let active = tracker.active_alerts();
        assert_eq!(active.len(), 1, "clearing port 3 must not touch port 5");
        assert_eq!(active[0].row_key.as_deref(), Some("5"));
    }

    /// A row-scoped alert's `Alert.row_key` must actually be set on the returned
    /// `Alert` (not just used internally as a tracking key) — the dashboard/API need it
    /// to tell two same-named incidents on the same device apart.
    #[test]
    fn activated_alert_carries_its_row_key() {
        let tracker = AlertStateTracker::new();
        let device_id = uuid::Uuid::new_v4();
        let r = tracker.observe(
            device_id,
            "1.2.3.4",
            "port_down",
            Some("Gi0/3"),
            AlertLevel::Warning,
            "down".into(),
            None,
            true,
            false,
            None,
            chrono::Duration::seconds(0),
            Utc::now(),
        );
        let AlertTransition::Activated(a) = r else {
            panic!("expected Activated")
        };
        assert_eq!(a.row_key.as_deref(), Some("Gi0/3"));
    }

    #[test]
    fn restored_active_alert_is_cleared_as_the_same_incident() {
        let original = AlertStateTracker::new();
        let device_id = uuid::Uuid::new_v4();
        let t0 = Utc::now();
        let AlertTransition::Activated(alert) = original.observe(
            device_id,
            "1.2.3.4",
            "high_cpu",
            None,
            AlertLevel::Critical,
            "high".into(),
            None,
            true,
            false,
            None,
            chrono::Duration::zero(),
            t0,
        ) else {
            panic!("expected Activated")
        };

        let restored = AlertStateTracker::new();
        restored.restore_active(alert.clone());
        let AlertTransition::Cleared(cleared) = restored.observe(
            device_id,
            "1.2.3.4",
            "high_cpu",
            None,
            AlertLevel::Critical,
            "recovered".into(),
            None,
            false,
            true,
            None,
            chrono::Duration::zero(),
            t0 + chrono::Duration::seconds(1),
        ) else {
            panic!("expected restored incident to clear")
        };
        assert_eq!(cleared.id, alert.id);
        assert!(restored.active_alerts().is_empty());
    }

    /// `open_row_alerts` must return only row-scoped entries for the exact
    /// `(device_id, rule_name)` asked about — not device-level alerts (row_key `None`),
    /// not a different rule's rows, not another device's rows.
    #[test]
    fn open_row_alerts_scopes_to_exactly_one_device_and_rule() {
        let tracker = AlertStateTracker::new();
        let device_a = uuid::Uuid::new_v4();
        let device_b = uuid::Uuid::new_v4();
        let t0 = Utc::now();

        tracker.observe(
            device_a,
            "1.2.3.4",
            "port_down",
            Some("3"),
            AlertLevel::Warning,
            "m".into(),
            None,
            true,
            false,
            None,
            chrono::Duration::seconds(0),
            t0,
        );
        tracker.observe(
            device_a,
            "1.2.3.4",
            "port_down",
            Some("5"),
            AlertLevel::Warning,
            "m".into(),
            None,
            true,
            false,
            None,
            chrono::Duration::seconds(0),
            t0,
        );
        // Different rule, same device — must not show up.
        tracker.observe(
            device_a,
            "1.2.3.4",
            "high_cpu",
            None,
            AlertLevel::Warning,
            "m".into(),
            None,
            true,
            false,
            None,
            chrono::Duration::seconds(0),
            t0,
        );
        // Same rule, different device — must not show up.
        tracker.observe(
            device_b,
            "5.6.7.8",
            "port_down",
            Some("3"),
            AlertLevel::Warning,
            "m".into(),
            None,
            true,
            false,
            None,
            chrono::Duration::seconds(0),
            t0,
        );

        let open = tracker.open_row_alerts(device_a, "port_down");
        let mut keys: Vec<&str> = open.iter().map(|a| a.row_key.as_deref().unwrap()).collect();
        keys.sort();
        assert_eq!(keys, vec!["3", "5"]);
    }

    /// Direct user request 2026-08-29: a row disappearing entirely (not just its condition
    /// resolving) clears through the exact same mechanism/timing as any other
    /// deactivation — `auto_clear_reason` is just a label on the resulting `Cleared`
    /// alert, not a different code path or a bypass of `clear_after`.
    #[test]
    fn auto_clear_reason_is_stamped_only_on_the_alert_that_actually_clears() {
        let tracker = AlertStateTracker::new();
        let device_id = uuid::Uuid::new_v4();
        let t0 = Utc::now();

        tracker.observe(
            device_id,
            "1.2.3.4",
            "port_down",
            Some("3"),
            AlertLevel::Warning,
            "down".into(),
            None,
            true,
            false,
            None,
            chrono::Duration::seconds(60),
            t0,
        );

        // Row missing this tick, but grace period hasn't elapsed — still active, and the
        // in-flight `Alert` (StillActive) must NOT carry the reason yet, only a genuinely
        // `Cleared` transition does.
        let r2 = tracker.observe(
            device_id,
            "1.2.3.4",
            "port_down",
            Some("3"),
            AlertLevel::Warning,
            "down".into(),
            None,
            false,
            true,
            Some(AutoClearReason::RowMissing),
            chrono::Duration::seconds(60),
            t0 + chrono::Duration::seconds(10),
        );
        let AlertTransition::StillActive(a2) = r2 else {
            panic!("expected StillActive")
        };
        assert_eq!(
            a2.auto_clear_reason, None,
            "reason must not appear before the incident actually clears"
        );

        // Grace period elapses — now it clears, carrying the reason from this final call.
        let r3 = tracker.observe(
            device_id,
            "1.2.3.4",
            "port_down",
            Some("3"),
            AlertLevel::Warning,
            "down".into(),
            None,
            false,
            true,
            Some(AutoClearReason::RowMissing),
            chrono::Duration::seconds(60),
            t0 + chrono::Duration::seconds(70),
        );
        let AlertTransition::Cleared(a3) = r3 else {
            panic!("expected Cleared")
        };
        assert_eq!(a3.auto_clear_reason, Some(AutoClearReason::RowMissing));
    }

    #[test]
    fn activation_delay_ignores_a_short_spike() {
        let tracker = AlertStateTracker::new();
        let id = uuid::Uuid::new_v4();
        let t0 = Utc::now();
        let config = AlertHysteresisConfig {
            activate_after: chrono::Duration::seconds(30),
            ..AlertHysteresisConfig::default()
        };
        assert!(matches!(
            tracker.observe_with_config(
                id,
                "1.2.3.4",
                "cpu",
                None,
                AlertLevel::Warning,
                "high".into(),
                None,
                true,
                false,
                None,
                config,
                t0
            ),
            AlertTransition::None
        ));
        assert!(matches!(
            tracker.observe_with_config(
                id,
                "1.2.3.4",
                "cpu",
                None,
                AlertLevel::Warning,
                "ok".into(),
                None,
                false,
                true,
                None,
                config,
                t0 + chrono::Duration::seconds(5)
            ),
            AlertTransition::None
        ));
        assert!(tracker.active_alerts().is_empty());
    }

    #[test]
    fn sustained_activation_opens_after_delay() {
        let tracker = AlertStateTracker::new();
        let id = uuid::Uuid::new_v4();
        let t0 = Utc::now();
        let config = AlertHysteresisConfig {
            activate_after: chrono::Duration::seconds(30),
            ..AlertHysteresisConfig::default()
        };
        assert!(matches!(
            tracker.observe_with_config(
                id,
                "1.2.3.4",
                "cpu",
                None,
                AlertLevel::Warning,
                "high".into(),
                None,
                true,
                false,
                None,
                config,
                t0
            ),
            AlertTransition::None
        ));
        assert!(matches!(
            tracker.observe_with_config(
                id,
                "1.2.3.4",
                "cpu",
                None,
                AlertLevel::Warning,
                "high".into(),
                None,
                true,
                false,
                None,
                config,
                t0 + chrono::Duration::seconds(31)
            ),
            AlertTransition::Activated(_)
        ));
    }

    #[test]
    fn flapping_marks_incident_and_preserves_the_reason() {
        let tracker = AlertStateTracker::new();
        let id = uuid::Uuid::new_v4();
        let t0 = Utc::now();
        let config = AlertHysteresisConfig {
            clear_after: chrono::Duration::seconds(60),
            flap_window: chrono::Duration::seconds(60),
            flap_threshold: 2,
            flap_clear_threshold: None,
            ..AlertHysteresisConfig::default()
        };
        assert!(matches!(
            tracker.observe_with_config(
                id,
                "1.2.3.4",
                "cpu",
                None,
                AlertLevel::Warning,
                "high".into(),
                None,
                true,
                false,
                None,
                config,
                t0
            ),
            AlertTransition::Activated(_)
        ));
        assert!(matches!(
            tracker.observe_with_config(
                id,
                "1.2.3.4",
                "cpu",
                None,
                AlertLevel::Warning,
                "ok".into(),
                None,
                false,
                true,
                None,
                config,
                t0 + chrono::Duration::seconds(1)
            ),
            AlertTransition::StillActive(_)
        ));
        let AlertTransition::StillActive(alert) = tracker.observe_with_config(
            id,
            "1.2.3.4",
            "cpu",
            None,
            AlertLevel::Warning,
            "high".into(),
            None,
            true,
            false,
            None,
            config,
            t0 + chrono::Duration::seconds(2),
        ) else {
            panic!("expected StillActive")
        };
        assert!(alert.flapping);
        assert_eq!(alert.suppression_reason.as_deref(), Some(FLAPPING_REASON));
    }
}

#[cfg(test)]
mod capability_tests {
    use super::*;
    fn observe(
        t: &AlertStateTracker,
        id: uuid::Uuid,
        activation: bool,
        recovery: bool,
        config: AlertHysteresisConfig,
        at: DateTime<Utc>,
    ) -> AlertTransition {
        t.observe_with_config(
            id,
            "127.0.0.1",
            "rule",
            None,
            AlertLevel::Warning,
            "message".into(),
            None,
            activation,
            recovery,
            None,
            config,
            at,
        )
    }
    #[test]
    fn runtime_restores_pending_activation_and_recovery_without_resurrecting_closed_incident() {
        let id = uuid::Uuid::new_v4();
        let now = Utc::now();
        let config = AlertHysteresisConfig {
            activate_after: chrono::Duration::seconds(10),
            clear_after: chrono::Duration::seconds(10),
            ..Default::default()
        };
        let t = AlertStateTracker::new();
        assert!(matches!(
            observe(&t, id, true, false, config, now),
            AlertTransition::None
        ));
        let restored = AlertStateTracker::new();
        restored.restore_snapshot(id, t.snapshot_for_device(id));
        let AlertTransition::Activated(alert) = observe(
            &restored,
            id,
            true,
            false,
            config,
            now + chrono::Duration::seconds(10),
        ) else {
            panic!("activation timer lost")
        };
        observe(
            &restored,
            id,
            false,
            true,
            config,
            now + chrono::Duration::seconds(11),
        );
        let snapshot = restored.snapshot_for_device(id);
        let recovery = AlertStateTracker::new();
        recovery.restore_active(alert.clone());
        recovery.restore_snapshot(id, snapshot.clone());
        assert!(matches!(
            observe(
                &recovery,
                id,
                false,
                true,
                config,
                now + chrono::Duration::seconds(21)
            ),
            AlertTransition::Cleared(_)
        ));
        let closed = AlertStateTracker::new();
        closed.restore_snapshot(id, snapshot);
        assert!(closed.active_alerts().is_empty());
    }
    #[test]
    fn errors_interrupt_both_timers_and_deadlines_schedule_independently() {
        let id = uuid::Uuid::new_v4();
        let now = Utc::now();
        let t = AlertStateTracker::new();
        let config = AlertHysteresisConfig {
            activate_after: chrono::Duration::seconds(5),
            clear_after: chrono::Duration::seconds(5),
            ..Default::default()
        };
        observe(&t, id, true, false, config, now);
        t.interrupt_observation(id, "rule", None);
        assert!(matches!(
            observe(
                &t,
                id,
                true,
                false,
                config,
                now + chrono::Duration::seconds(6)
            ),
            AlertTransition::None
        ));
        assert!(matches!(
            observe(
                &t,
                id,
                true,
                false,
                config,
                now + chrono::Duration::seconds(11)
            ),
            AlertTransition::Activated(_)
        ));
        observe(
            &t,
            id,
            false,
            true,
            config,
            now + chrono::Duration::seconds(12),
        );
        t.interrupt_observation(id, "rule", None);
        assert!(matches!(
            observe(
                &t,
                id,
                false,
                true,
                config,
                now + chrono::Duration::seconds(18)
            ),
            AlertTransition::StillActive(_)
        ));
        let mut s = crate::AlertRuleStatus::new("rule", None, now);
        s.next_check_at = Some(now + chrono::Duration::seconds(2));
        t.record_rule_status(id, s);
        assert!(t.due_devices(now).is_empty());
        assert_eq!(t.due_devices(now + chrono::Duration::seconds(2)), vec![id]);
        t.remove(id, "rule", None);
        assert!(t
            .rule_status(id, "rule", None)
            .unwrap()
            .active_alert_id
            .is_none());
    }
    #[test]
    fn flapping_uses_separate_exit_threshold_and_disable_resets_latch() {
        let now = Utc::now();
        let mut s = TrackedState::new();
        let config = AlertHysteresisConfig {
            flap_window: chrono::Duration::seconds(10),
            flap_threshold: 3,
            flap_clear_threshold: Some(1),
            ..Default::default()
        };
        s.switches.extend([
            now,
            now + chrono::Duration::seconds(1),
            now + chrono::Duration::seconds(2),
        ]);
        assert!(s.is_flapping(config, now + chrono::Duration::seconds(2)));
        assert!(s.is_flapping(config, now + chrono::Duration::seconds(11)));
        assert!(!s.is_flapping(config, now + chrono::Duration::seconds(13)));
        s.flapping = true;
        assert!(!s.is_flapping(Default::default(), now));
        assert!(!s.flapping);
    }
}
