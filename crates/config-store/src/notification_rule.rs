//! The notification matrix — "кого извещать по какой тревоге" (direct user request
//! 2026-09-10), the second half of `docs/Roadmap.md`'s "Нотификации" section, alongside
//! `crate::notification_channel` (the per-user contact points this matrix resolves
//! recipients into). See [`NotificationRule::matches_device`]'s docs for why this type
//! lives here (mirroring `crate::MaintenanceWindow`'s placement) rather than in
//! `discovery-core` alongside `NotificationChannel`.

use async_trait::async_trait;
use chrono::{DateTime, Datelike, NaiveTime, Utc};
use discovery_core::{AlertLevel, NotificationTrigger};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::scan::ipv4_in_subnet;
use crate::SubnetTarget;

/// One row of the notification matrix: which alerts (by severity/device selector/time of
/// day) page which users, and on which transitions.
///
/// Recurrence is opt-in: zero values preserve the original activate/clear-only behaviour.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NotificationRule {
    #[serde(default)]
    pub selection: NotificationSelection,
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    /// Notify when the alert's level is this or higher (`AlertLevel`'s derived `Ord`: Info
    /// < Warning < Critical) — e.g. `Critical` means "only the most severe alerts page
    /// this rule's recipients".
    pub min_level: AlertLevel,
    /// Device selector — same dimensions, same per-dimension "empty = don't filter by this
    /// dimension" meaning, and the same unconditional `device_ids` override as
    /// `crate::MaintenanceWindow`. **The zero-dimensions-populated case is the one
    /// deliberate difference — see [`Self::matches_device`]'s docs.**
    #[serde(default)]
    pub subnets: Vec<SubnetTarget>,
    #[serde(default)]
    pub profiles: Vec<String>,
    #[serde(default)]
    pub device_ids: Vec<Uuid>,
    /// Time-of-day window, UTC — both `Some` or both `None` (enforced at the REST layer,
    /// not here; see [`Self::matches_time`]'s docs on what a mixed pair means at the type
    /// level). `None`/`None` = no time-of-day restriction, all day.
    #[serde(default)]
    pub active_from: Option<NaiveTime>,
    #[serde(default)]
    pub active_to: Option<NaiveTime>,
    /// `chrono::Weekday::to_string()`-shaped short names ("Mon".."Sun") — empty means
    /// "every day of the week", same "empty = don't filter" convention as `profiles`.
    /// Plain `Vec<String>`, not `Vec<chrono::Weekday>`: chrono's `Weekday` has no `serde`
    /// impl at all (only under its unrelated `rkyv` feature) — found while implementing
    /// this type, not a stylistic choice.
    #[serde(default)]
    pub days_of_week: Vec<String>,
    pub notify_on_activate: bool,
    pub notify_on_clear: bool,
    /// Who gets notified when this rule matches — a mix of individual users and/or RBAC
    /// roles as proxy-groups (2026-09-18, direct user request during demo-park manual
    /// testing: "нет группового выбора получателей"). See [`RecipientRef`]'s docs for why
    /// roles are reused here instead of a new "recipient group" entity, and
    /// `discovery_agent::handlers::dispatch_alert_notifications`'s docs for the resolve
    /// step — a `Role` entry expands to its *current* members before the same per-user
    /// "enabled channels" lookup [`RecipientRef::User`] already goes through
    /// (`crate::NotificationChannelStore::list_for_users`), not a separate path.
    #[serde(default)]
    pub recipients: Vec<RecipientRef>,
    #[serde(default)]
    pub repeat_after_seconds: u64,
    #[serde(default)]
    pub repeat_interval_seconds: u64,
    #[serde(default)]
    pub max_repeats: u32,
    #[serde(default)]
    pub escalation_levels: Vec<EscalationLevel>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EscalationLevel {
    pub after_repeats: u32,
    #[serde(default)]
    pub recipients: Vec<RecipientRef>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// One entry of [`NotificationRule::recipients`] — either a specific `users.id`, or every
/// *current* member of a `discovery_auth::Role` (by its id), resolved fresh at dispatch
/// time rather than snapshotted.
///
/// **Role-as-proxy-group, not a new "recipient group" entity** — direct architecture
/// decision 2026-09-18 (see `docs/Roadmap.md`'s "Матрица нотификаций" finding this closes):
/// the project already has exactly one place a set of users is named and given a stable
/// identity — `discovery_auth::Role` — and reusing it here keeps "one concept per domain
/// need" (this crate's own `.claude/rules/engineering-patterns.md` convention) instead of
/// introducing a second, overlapping notion of "group of users" that would inevitably
/// drift from role membership over time. Storing a bare `Uuid` here (not the whole `Role`
/// type) deliberately keeps `discovery-config-store` from depending on `discovery-auth` —
/// same cross-domain-FK-by-id-only posture `device_ids`/individual `User` entries on this
/// same field already use for `devices`/`users`; resolving the id to actual members is the
/// caller's job (`discovery-agent`, which already depends on both crates), not this
/// store's.
///
/// `#[serde(untagged)]`, not an externally-tagged `{"type": "user", "id": "..."}` shape —
/// deliberately so a bare UUID string (the old `Vec<Uuid>` wire/storage shape this field
/// had before roles existed) still deserializes as `User` unchanged: no migration of
/// already-stored `notification_rules.recipients` JSON was needed to ship this, since a
/// plain string parses as the first variant and a `{"role": "..."}` object parses as the
/// second — see `discovery-db-patterns` skill on preferring the lightest change that
/// actually works over a heavier migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RecipientRef {
    /// `users.id` — every `enabled` channel belonging to this one user is notified.
    User(Uuid),
    /// `discovery_auth::Role.id` — every *current* member of this role is notified,
    /// individually, through the exact same "enabled channels" resolution [`User`] gets.
    ///
    /// [`User`]: RecipientRef::User
    Role { role: Uuid },
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NotificationSelection {
    pub alert_names: Vec<String>,
    pub row_keys: Vec<String>,
    pub source_metrics: Vec<String>,
    pub recipient_expression: Option<String>,
    pub notify_on_escalation: bool,
    pub notify_on_deescalation: bool,
}

impl NotificationRule {
    pub fn matches_alert(&self, alert: &discovery_core::Alert) -> bool {
        (self.selection.alert_names.is_empty() || self.selection.alert_names.contains(&alert.name))
            && (self.selection.row_keys.is_empty()
                || alert
                    .row_key
                    .as_ref()
                    .is_some_and(|key| self.selection.row_keys.contains(key)))
            && (self.selection.source_metrics.is_empty()
                || alert
                    .details
                    .source_event
                    .as_ref()
                    .and_then(|e| e.get("metric"))
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|m| self.selection.source_metrics.iter().any(|v| v == m)))
    }

    /// Does this rule apply to `trigger` at all? A rule with `notify_on_activate = false`
    /// never fires for an `Activated` transition, independent of every other field.
    pub fn wants_trigger(&self, trigger: NotificationTrigger) -> bool {
        match trigger {
            NotificationTrigger::Activated => self.notify_on_activate,
            NotificationTrigger::Cleared => self.notify_on_clear,
            NotificationTrigger::Escalated => self.selection.notify_on_escalation,
            NotificationTrigger::Deescalated => self.selection.notify_on_deescalation,
            NotificationTrigger::Repeated => {
                self.repeat_after_seconds > 0
                    && self.repeat_interval_seconds > 0
                    && self.max_repeats > 0
            }
        }
    }

    pub fn repeat_due(&self, alert: &discovery_core::Alert, now: DateTime<Utc>) -> bool {
        self.enabled
            && self.wants_trigger(NotificationTrigger::Repeated)
            && matches!(alert.state, discovery_core::AlertState::Active)
            && alert.acknowledged_at.is_none()
            && !alert.notifications_snoozed_at(now)
            && alert.repeat_count < self.max_repeats
            && (now - alert.first_seen).num_seconds() >= self.repeat_after_seconds as i64
            && alert.repeated_at.map_or(true, |at| {
                (now - at).num_seconds() >= self.repeat_interval_seconds as i64
            })
    }

    pub fn recipients_for_repeat(&self, repeat_count: u32) -> &[RecipientRef] {
        self.escalation_levels
            .iter()
            .filter(|level| repeat_count >= level.after_repeats)
            .max_by_key(|level| level.after_repeats)
            .map_or(&self.recipients, |level| &level.recipients)
    }

    /// Does `device_id` (at `ip`, currently on profile `profile`) fall under this rule's
    /// device selector? Same AND-across-populated-dimensions/unconditional-`device_ids`
    /// logic as `crate::MaintenanceWindow::matches` — with **one deliberate inversion**:
    ///
    /// **A selector with zero populated dimensions (`subnets`, `profiles`, `device_ids`
    /// all empty) matches every device, not none.** Direct user decision 2026-09-10,
    /// explicitly the opposite of `MaintenanceWindow`'s safety-default: there, an
    /// accidentally-empty selector silently freezing the *entire* fleet's alerting is the
    /// failure mode to guard against, so "matches nothing" is the safe default. Here, the
    /// typical first rule an operator writes is "notify me about every critical alert,
    /// anywhere" — an empty selector reading as "matches nothing" would make that rule a
    /// silent no-op instead of the useful catch-all it's meant to be. Both defaults are
    /// documented side by side deliberately, so a future reader isn't left wondering why
    /// two structurally similar selectors disagree — see `crate::MaintenanceWindow::matches`'s
    /// docs for the mirror-image reasoning.
    pub fn matches_device(&self, ip: &str, profile: Option<&str>, device_id: Uuid) -> bool {
        if self.device_ids.contains(&device_id) {
            return true;
        }

        if self.subnets.is_empty() && self.profiles.is_empty() && self.device_ids.is_empty() {
            return true;
        }

        if !self.subnets.is_empty() {
            let in_any_subnet = match ip.parse::<std::net::Ipv4Addr>() {
                Ok(candidate) => self
                    .subnets
                    .iter()
                    .any(|s| ipv4_in_subnet(candidate, &s.ip, &s.mask).unwrap_or(false)),
                Err(_) => false,
            };
            if !in_any_subnet {
                return false;
            }
        }

        if !self.profiles.is_empty() {
            let matches_profile = profile.is_some_and(|p| self.profiles.iter().any(|w| w == p));
            if !matches_profile {
                return false;
            }
        }

        true
    }

    /// Does `now` fall inside this rule's day-of-week + time-of-day restriction? Both
    /// unset dimensions independently mean "don't filter by this", same convention as
    /// `matches_device`'s per-dimension emptiness — **not** the zero-dimensions inversion
    /// above, which only applies to the device selector.
    ///
    /// A mixed pair (`active_from` set, `active_to` unset, or vice versa) is not a state
    /// the REST layer is meant to ever persist (validated as "both or neither" on upsert)
    /// — treated here as "no time-of-day restriction" rather than panicking or guessing
    /// which bound was intended, the same fail-safe-open spirit
    /// `discovery_dsl`'s missing-field Rhai guards use for unexpected shapes.
    pub fn matches_time(&self, now: DateTime<Utc>) -> bool {
        if !self.days_of_week.is_empty() {
            let today = now.weekday().to_string();
            if !self.days_of_week.iter().any(|d| d == &today) {
                return false;
            }
        }

        match (self.active_from, self.active_to) {
            (Some(from), Some(to)) => {
                let t = now.time();
                if from <= to {
                    from <= t && t <= to
                } else {
                    // Window wraps past midnight (e.g. 22:00-06:00 night shift).
                    t >= from || t <= to
                }
            }
            _ => true,
        }
    }

    /// The full match — level threshold, device selector, time-of-day, all combined. Does
    /// **not** check `enabled` or `wants_trigger` — callers (`AlertEvalHandler::
    /// dispatch_notifications`) check those separately since they're cheaper short-circuits
    /// that don't need `ip`/`profile`/`device_id`/`now` at all.
    pub fn matches(
        &self,
        ip: &str,
        profile: Option<&str>,
        device_id: Uuid,
        level: AlertLevel,
        now: DateTime<Utc>,
    ) -> bool {
        level >= self.min_level
            && self.matches_device(ip, profile, device_id)
            && self.matches_time(now)
    }
}

/// Where notification matrix rules live. One implementation — [`SeaOrmNotificationRuleStore`]
/// — same "one trait, one sea-orm implementation" shape as [`crate::MaintenanceWindowStore`].
#[async_trait]
pub trait NotificationRuleStore: Send + Sync {
    async fn list_all(&self) -> anyhow::Result<Vec<NotificationRule>>;

    async fn get(&self, id: Uuid) -> anyhow::Result<Option<NotificationRule>>;

    /// Insert-or-replace-by-id — same "id decides create vs edit" contract as
    /// `crate::MaintenanceWindowStore::upsert`.
    async fn upsert(&self, rule: &NotificationRule) -> anyhow::Result<()>;

    /// No-op (not an error) if `id` doesn't exist.
    async fn delete(&self, id: Uuid) -> anyhow::Result<()>;
}

pub struct SeaOrmNotificationRuleStore {
    db: sea_orm::DatabaseConnection,
}

impl SeaOrmNotificationRuleStore {
    pub fn new(db: sea_orm::DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn new_in_memory_for_tests() -> Self {
        Self::new(discovery_migration::connect_in_memory_for_tests().await)
    }
}

const TIME_FMT: &str = "%H:%M:%S";

fn format_time(t: NaiveTime) -> String {
    t.format(TIME_FMT).to_string()
}

fn parse_time(s: &str) -> anyhow::Result<NaiveTime> {
    NaiveTime::parse_from_str(s, TIME_FMT)
        .map_err(|e| anyhow::anyhow!("invalid stored time '{s}': {e}"))
}

fn model_to_rule(
    m: discovery_entities::notification_rules::Model,
) -> anyhow::Result<NotificationRule> {
    Ok(NotificationRule {
        selection: m
            .selection
            .map(serde_json::from_value)
            .transpose()?
            .unwrap_or_default(),
        id: m.id,
        name: m.name,
        enabled: m.enabled,
        min_level: AlertLevel::from_str(&m.min_level)
            .ok_or_else(|| anyhow::anyhow!("unknown alert level '{}'", m.min_level))?,
        subnets: serde_json::from_value(m.subnets)?,
        profiles: serde_json::from_value(m.profiles)?,
        device_ids: serde_json::from_value(m.device_ids)?,
        active_from: m.active_from.map(|s| parse_time(&s)).transpose()?,
        active_to: m.active_to.map(|s| parse_time(&s)).transpose()?,
        days_of_week: serde_json::from_value(m.days_of_week)?,
        notify_on_activate: m.notify_on_activate,
        notify_on_clear: m.notify_on_clear,
        recipients: serde_json::from_value(m.recipients)?,
        repeat_after_seconds: m.repeat_after_seconds.max(0) as u64,
        repeat_interval_seconds: m.repeat_interval_seconds.max(0) as u64,
        max_repeats: m.max_repeats.max(0) as u32,
        escalation_levels: m
            .escalation_levels
            .map(serde_json::from_value)
            .transpose()?
            .unwrap_or_default(),
    })
}

#[async_trait]
impl NotificationRuleStore for SeaOrmNotificationRuleStore {
    async fn list_all(&self) -> anyhow::Result<Vec<NotificationRule>> {
        use discovery_entities::notification_rules::Entity;
        use sea_orm::EntityTrait;
        Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(model_to_rule)
            .collect()
    }

    async fn get(&self, id: Uuid) -> anyhow::Result<Option<NotificationRule>> {
        use discovery_entities::notification_rules::Entity;
        use sea_orm::EntityTrait;
        Entity::find_by_id(id)
            .one(&self.db)
            .await?
            .map(model_to_rule)
            .transpose()
    }

    async fn upsert(&self, rule: &NotificationRule) -> anyhow::Result<()> {
        use discovery_entities::notification_rules::{ActiveModel, Column, Entity};
        use sea_orm::sea_query::OnConflict;
        use sea_orm::{ActiveValue::Set, EntityTrait};

        let now = chrono::Utc::now();
        let am = ActiveModel {
            selection: Set(Some(serde_json::to_value(&rule.selection)?)),
            id: Set(rule.id),
            name: Set(rule.name.clone()),
            enabled: Set(rule.enabled),
            min_level: Set(rule.min_level.as_str().to_string()),
            subnets: Set(serde_json::to_value(&rule.subnets)?),
            profiles: Set(serde_json::to_value(&rule.profiles)?),
            device_ids: Set(serde_json::to_value(&rule.device_ids)?),
            active_from: Set(rule.active_from.map(format_time)),
            active_to: Set(rule.active_to.map(format_time)),
            days_of_week: Set(serde_json::to_value(&rule.days_of_week)?),
            notify_on_activate: Set(rule.notify_on_activate),
            notify_on_clear: Set(rule.notify_on_clear),
            recipients: Set(serde_json::to_value(&rule.recipients)?),
            repeat_after_seconds: Set(rule.repeat_after_seconds as i64),
            repeat_interval_seconds: Set(rule.repeat_interval_seconds as i64),
            max_repeats: Set(rule.max_repeats as i32),
            escalation_levels: Set(Some(serde_json::to_value(&rule.escalation_levels)?)),
            created_at: Set(now),
            updated_at: Set(now),
        };
        Entity::insert(am)
            .on_conflict(
                OnConflict::column(Column::Id)
                    .update_columns([
                        Column::Name,
                        Column::Enabled,
                        Column::MinLevel,
                        Column::Subnets,
                        Column::Profiles,
                        Column::DeviceIds,
                        Column::ActiveFrom,
                        Column::ActiveTo,
                        Column::DaysOfWeek,
                        Column::NotifyOnActivate,
                        Column::NotifyOnClear,
                        Column::Selection,
                        Column::RepeatAfterSeconds,
                        Column::RepeatIntervalSeconds,
                        Column::MaxRepeats,
                        Column::EscalationLevels,
                        Column::Recipients,
                        Column::UpdatedAt,
                    ])
                    .to_owned(),
            )
            .exec(&self.db)
            .await?;
        Ok(())
    }

    async fn delete(&self, id: Uuid) -> anyhow::Result<()> {
        use discovery_entities::notification_rules::Entity;
        use sea_orm::EntityTrait;
        Entity::delete_by_id(id).exec(&self.db).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_rule() -> NotificationRule {
        NotificationRule {
            selection: Default::default(),
            id: Uuid::new_v4(),
            name: "test rule".into(),
            enabled: true,
            min_level: AlertLevel::Warning,
            subnets: vec![],
            profiles: vec![],
            device_ids: vec![],
            active_from: None,
            active_to: None,
            days_of_week: vec![],
            notify_on_activate: true,
            notify_on_clear: true,
            recipients: vec![RecipientRef::User(Uuid::new_v4())],
            repeat_after_seconds: 0,
            repeat_interval_seconds: 0,
            max_repeats: 0,
            escalation_levels: vec![],
        }
    }

    fn subnet(ip: &str, mask: &str) -> SubnetTarget {
        SubnetTarget {
            ip: ip.to_string(),
            mask: mask.to_string(),
        }
    }

    // ---- the inverted empty-selector default (vs MaintenanceWindow) ----

    #[test]
    fn empty_selector_matches_everything_not_nothing() {
        let rule = base_rule();
        assert!(
            rule.matches_device("10.0.0.5", Some("asw"), Uuid::new_v4()),
            "an empty selector must be a useful catch-all, not a silent no-op"
        );
        assert!(rule.matches_device("192.168.99.1", None, Uuid::new_v4()));
    }

    #[test]
    fn subnet_and_profile_and_device_ids_behave_like_maintenance_window_once_populated() {
        let mut rule = base_rule();
        rule.subnets = vec![subnet("10.0.0.0", "255.255.255.0")];
        rule.profiles = vec!["asw".to_string()];
        assert!(rule.matches_device("10.0.0.5", Some("asw"), Uuid::new_v4()));
        assert!(
            !rule.matches_device("10.0.0.5", Some("olt_xpon"), Uuid::new_v4()),
            "wrong profile"
        );
        assert!(
            !rule.matches_device("192.168.1.5", Some("asw"), Uuid::new_v4()),
            "outside subnet"
        );

        let target = Uuid::new_v4();
        rule.device_ids = vec![target];
        assert!(
            rule.matches_device("192.168.1.5", Some("olt_xpon"), target),
            "explicit device_ids override every other dimension"
        );
    }

    // ---- min_level threshold ----

    #[test]
    fn min_level_gates_lower_severities() {
        let rule = base_rule(); // min_level = Warning
        assert!(!rule.matches(
            "10.0.0.5",
            None,
            Uuid::new_v4(),
            AlertLevel::Info,
            Utc::now()
        ));
        assert!(rule.matches(
            "10.0.0.5",
            None,
            Uuid::new_v4(),
            AlertLevel::Warning,
            Utc::now()
        ));
        assert!(rule.matches(
            "10.0.0.5",
            None,
            Uuid::new_v4(),
            AlertLevel::Critical,
            Utc::now()
        ));
    }

    // ---- time-of-day ----

    #[test]
    fn no_time_restriction_matches_any_time() {
        let rule = base_rule();
        assert!(rule.matches_time(Utc::now()));
    }

    #[test]
    fn simple_daytime_window_excludes_outside_hours() {
        let mut rule = base_rule();
        rule.active_from = Some(NaiveTime::from_hms_opt(9, 0, 0).unwrap());
        rule.active_to = Some(NaiveTime::from_hms_opt(18, 0, 0).unwrap());
        let inside = "2026-09-10T12:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let outside = "2026-09-10T22:00:00Z".parse::<DateTime<Utc>>().unwrap();
        assert!(rule.matches_time(inside));
        assert!(!rule.matches_time(outside));
    }

    #[test]
    fn window_boundaries_are_inclusive() {
        let mut rule = base_rule();
        rule.active_from = Some(NaiveTime::from_hms_opt(9, 0, 0).unwrap());
        rule.active_to = Some(NaiveTime::from_hms_opt(18, 0, 0).unwrap());
        assert!(rule.matches_time("2026-09-10T09:00:00Z".parse().unwrap()));
        assert!(rule.matches_time("2026-09-10T18:00:00Z".parse().unwrap()));
        assert!(!rule.matches_time("2026-09-10T08:59:59Z".parse().unwrap()));
        assert!(!rule.matches_time("2026-09-10T18:00:01Z".parse().unwrap()));
    }

    #[test]
    fn window_wrapping_past_midnight() {
        let mut rule = base_rule();
        rule.active_from = Some(NaiveTime::from_hms_opt(22, 0, 0).unwrap());
        rule.active_to = Some(NaiveTime::from_hms_opt(6, 0, 0).unwrap());
        assert!(
            rule.matches_time("2026-09-10T23:30:00Z".parse().unwrap()),
            "before midnight, inside window"
        );
        assert!(
            rule.matches_time("2026-09-10T02:00:00Z".parse().unwrap()),
            "after midnight, inside window"
        );
        assert!(
            !rule.matches_time("2026-09-10T12:00:00Z".parse().unwrap()),
            "midday, outside an overnight window"
        );
    }

    #[test]
    fn days_of_week_restricts_to_configured_days() {
        let mut rule = base_rule();
        rule.days_of_week = vec![
            "Mon".to_string(),
            "Tue".to_string(),
            "Wed".to_string(),
            "Thu".to_string(),
            "Fri".to_string(),
        ];
        // 2026-09-10 is a Thursday, 2026-09-12 is a Saturday.
        assert!(rule.matches_time("2026-09-10T12:00:00Z".parse().unwrap()));
        assert!(!rule.matches_time("2026-09-12T12:00:00Z".parse().unwrap()));
    }

    // ---- trigger gating ----

    #[test]
    fn wants_trigger_respects_independent_flags() {
        let mut rule = base_rule();
        rule.notify_on_activate = true;
        rule.notify_on_clear = false;
        assert!(rule.wants_trigger(NotificationTrigger::Activated));
        assert!(!rule.wants_trigger(NotificationTrigger::Cleared));
    }

    // ---- store CRUD round trip ----

    #[tokio::test]
    async fn store_round_trips_create_edit_and_delete() {
        let store = SeaOrmNotificationRuleStore::new_in_memory_for_tests().await;
        let mut rule = base_rule();
        rule.subnets = vec![subnet("10.0.0.0", "255.255.255.0")];
        rule.active_from = Some(NaiveTime::from_hms_opt(9, 0, 0).unwrap());
        rule.active_to = Some(NaiveTime::from_hms_opt(18, 0, 0).unwrap());
        rule.days_of_week = vec!["Mon".to_string()];
        store.upsert(&rule).await.unwrap();

        let all = store.list_all().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0], rule);

        let mut edited = rule.clone();
        edited.name = "renamed".to_string();
        edited.min_level = AlertLevel::Critical;
        store.upsert(&edited).await.unwrap();
        let all = store.list_all().await.unwrap();
        assert_eq!(all.len(), 1, "same id — must update in place");
        assert_eq!(all[0].name, "renamed");
        assert_eq!(all[0].min_level, AlertLevel::Critical);

        store.delete(rule.id).await.unwrap();
        assert!(store.list_all().await.unwrap().is_empty());
        store.delete(Uuid::new_v4()).await.unwrap(); // no-op
    }

    #[tokio::test]
    async fn get_returns_none_for_an_unknown_id() {
        let store = SeaOrmNotificationRuleStore::new_in_memory_for_tests().await;
        assert!(store.get(Uuid::new_v4()).await.unwrap().is_none());
    }

    // ---- RecipientRef (2026-09-18, role-as-proxy-group) ----

    #[test]
    fn recipient_ref_round_trips_through_json() {
        let user_id = Uuid::new_v4();
        let role_id = Uuid::new_v4();
        let recipients = vec![
            RecipientRef::User(user_id),
            RecipientRef::Role { role: role_id },
        ];
        let json = serde_json::to_value(&recipients).unwrap();
        let back: Vec<RecipientRef> = serde_json::from_value(json).unwrap();
        assert_eq!(back, recipients);
    }

    /// The load-bearing backward-compat test: `notification_rules.recipients` already held
    /// plain `Vec<Uuid>` JSON (a bare array of UUID strings) before roles existed here — a
    /// row written before this change must keep deserializing without a migration, see
    /// [`RecipientRef`]'s docs on why `#[serde(untagged)]` was chosen specifically for this.
    #[test]
    fn recipient_ref_deserializes_pre_existing_bare_uuid_array_as_users() {
        let user_a = Uuid::new_v4();
        let user_b = Uuid::new_v4();
        let stored = serde_json::json!([user_a.to_string(), user_b.to_string()]);
        let recipients: Vec<RecipientRef> = serde_json::from_value(stored).unwrap();
        assert_eq!(
            recipients,
            vec![RecipientRef::User(user_a), RecipientRef::User(user_b)]
        );
    }

    #[test]
    fn recipient_ref_role_serializes_as_a_tagged_object_distinct_from_a_bare_uuid() {
        let role_id = Uuid::new_v4();
        let json = serde_json::to_value(RecipientRef::Role { role: role_id }).unwrap();
        assert_eq!(json, serde_json::json!({"role": role_id.to_string()}));
    }

    #[tokio::test]
    async fn store_round_trips_a_mixed_user_and_role_recipient_list() {
        let store = SeaOrmNotificationRuleStore::new_in_memory_for_tests().await;
        let mut rule = base_rule();
        let role_id = Uuid::new_v4();
        rule.recipients = vec![
            RecipientRef::User(Uuid::new_v4()),
            RecipientRef::Role { role: role_id },
        ];
        store.upsert(&rule).await.unwrap();

        let fetched = store.get(rule.id).await.unwrap().unwrap();
        assert_eq!(fetched.recipients, rule.recipients);
        assert!(fetched
            .recipients
            .contains(&RecipientRef::Role { role: role_id }));
    }
    #[tokio::test]
    async fn capability_selection_and_recurrence_edits_roundtrip_and_match_all_filters() {
        let store = SeaOrmNotificationRuleStore::new_in_memory_for_tests().await;
        let mut rule = base_rule();
        rule.selection = NotificationSelection {
            alert_names: vec!["link".into()],
            row_keys: vec!["eth0".into()],
            source_metrics: vec!["syslog_link".into()],
            recipient_expression: Some(r#"user.username == "noc""#.into()),
            notify_on_escalation: true,
            notify_on_deescalation: true,
        };
        rule.repeat_after_seconds = 5;
        rule.repeat_interval_seconds = 10;
        rule.max_repeats = 2;
        store.upsert(&rule).await.unwrap();
        rule.repeat_interval_seconds = 20;
        store.upsert(&rule).await.unwrap();
        assert_eq!(store.get(rule.id).await.unwrap().unwrap(), rule);
        let tracker = discovery_core::AlertStateTracker::new();
        let discovery_core::AlertTransition::Activated(mut a) = tracker.observe(
            Uuid::new_v4(),
            "127.0.0.1",
            "link",
            Some("eth0"),
            AlertLevel::Warning,
            "test".into(),
            None,
            true,
            false,
            None,
            chrono::Duration::zero(),
            chrono::Utc::now(),
        ) else {
            panic!()
        };
        a.details.source_event = Some(serde_json::json!({"metric":"syslog_link"}));
        assert!(rule.matches_alert(&a));
        a.row_key = Some("eth1".into());
        assert!(!rule.matches_alert(&a));
        a.row_key = Some("eth0".into());
        a.name = "other".into();
        assert!(!rule.matches_alert(&a));
        a.name = "link".into();
        a.details.source_event = None;
        assert!(!rule.matches_alert(&a));
        assert!(rule.wants_trigger(NotificationTrigger::Escalated));
        assert!(rule.wants_trigger(NotificationTrigger::Deescalated));
    }
}
