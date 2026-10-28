//! Provider-authored Rhai cause/effect rules for group-alert suppression — pункт 3 of
//! `docs/Roadmap.md`'s "Топология → групповые тревоги → RADIUS" section, built 2026-09-16
//! on top of the already-directional topology mechanism (`discovery_config_store::TopologyRule`/
//! `discovery_topology::ResolvedEdge::upstream_device_id`).
//!
//! Direct user requirement, raised while designing this: an active-but-unrelated alert on
//! an upstream device (e.g. High CPU) must **not** suppress an independent alert on a
//! downstream device (e.g. Port Down) just because they happen to coincide in time and
//! direction. A single "participates in group suppression" boolean flag can't express that
//! — hence two separate Rhai predicates per rule, one evaluated against the *candidate
//! cause* (the upstream device's alert) and one against the *candidate effect* (the
//! downstream device's alert). See `discovery_dsl::group_alerts::GroupAlertEvaluator`'s
//! docs for how these are actually evaluated, and `discovery_agent::group_alert`'s docs
//! for how the result feeds into `Alert::suppressed_by_alert_id`.
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One group-alert rule: "which alert on an upstream device counts as a cause, and which
/// alert on a downstream device counts as an effect it may suppress". Both expressions run
/// in the same `{name, level, facts}` Rhai scope — see `GroupAlertEvaluator::scope_for`.
///
/// Unlike `TopologyRule::name`, this isn't a join key any other table references — no
/// database-enforced uniqueness (a display label only, same posture `NotificationRule::name`
/// already takes).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroupAlertRule {
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    /// Rhai expression, evaluated against the candidate upstream (root-cause) alert's
    /// `{name, level, facts}` — must produce a bool. `true` means this alert, if active on
    /// a topological upstream neighbor, is eligible to be treated as a root cause under
    /// this rule.
    pub cause_expression: String,
    /// Rhai expression, same scope, evaluated against the candidate downstream (to-be-
    /// suppressed) alert. `true` means this alert is eligible to be suppressed by a
    /// matching cause under this rule.
    pub effect_expression: String,
}

/// Where group-alert rules live. One implementation — [`SeaOrmGroupAlertRuleStore`] — same
/// "one trait, one sea-orm implementation" shape as [`crate::TopologyRuleStore`].
#[async_trait]
pub trait GroupAlertRuleStore: Send + Sync {
    async fn list_all(&self) -> anyhow::Result<Vec<GroupAlertRule>>;

    async fn get(&self, id: Uuid) -> anyhow::Result<Option<GroupAlertRule>>;

    /// Insert-or-replace-by-id — same "id decides create vs edit" contract as
    /// `crate::TopologyRuleStore::upsert`.
    async fn upsert(&self, rule: &GroupAlertRule) -> anyhow::Result<()>;

    /// No-op (not an error) if `id` doesn't exist.
    async fn delete(&self, id: Uuid) -> anyhow::Result<()>;
}

pub struct SeaOrmGroupAlertRuleStore {
    db: sea_orm::DatabaseConnection,
}

impl SeaOrmGroupAlertRuleStore {
    pub fn new(db: sea_orm::DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn new_in_memory_for_tests() -> Self {
        Self::new(discovery_migration::connect_in_memory_for_tests().await)
    }
}

fn model_to_rule(m: discovery_entities::group_alert_rules::Model) -> GroupAlertRule {
    GroupAlertRule {
        id: m.id,
        name: m.name,
        enabled: m.enabled,
        cause_expression: m.cause_expression,
        effect_expression: m.effect_expression,
    }
}

#[async_trait]
impl GroupAlertRuleStore for SeaOrmGroupAlertRuleStore {
    async fn list_all(&self) -> anyhow::Result<Vec<GroupAlertRule>> {
        use discovery_entities::group_alert_rules::Entity;
        use sea_orm::EntityTrait;
        Ok(Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(model_to_rule)
            .collect())
    }

    async fn get(&self, id: Uuid) -> anyhow::Result<Option<GroupAlertRule>> {
        use discovery_entities::group_alert_rules::Entity;
        use sea_orm::EntityTrait;
        Ok(Entity::find_by_id(id)
            .one(&self.db)
            .await?
            .map(model_to_rule))
    }

    async fn upsert(&self, rule: &GroupAlertRule) -> anyhow::Result<()> {
        use discovery_entities::group_alert_rules::{ActiveModel, Column, Entity};
        use sea_orm::sea_query::OnConflict;
        use sea_orm::{ActiveValue::Set, EntityTrait};

        let now = chrono::Utc::now();
        let am = ActiveModel {
            id: Set(rule.id),
            name: Set(rule.name.clone()),
            enabled: Set(rule.enabled),
            cause_expression: Set(rule.cause_expression.clone()),
            effect_expression: Set(rule.effect_expression.clone()),
            created_at: Set(now),
            updated_at: Set(now),
        };
        Entity::insert(am)
            .on_conflict(
                OnConflict::column(Column::Id)
                    .update_columns([
                        Column::Name,
                        Column::Enabled,
                        Column::CauseExpression,
                        Column::EffectExpression,
                        Column::UpdatedAt,
                    ])
                    .to_owned(),
            )
            .exec(&self.db)
            .await?;
        Ok(())
    }

    async fn delete(&self, id: Uuid) -> anyhow::Result<()> {
        use discovery_entities::group_alert_rules::Entity;
        use sea_orm::EntityTrait;
        Entity::delete_by_id(id).exec(&self.db).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_rule() -> GroupAlertRule {
        GroupAlertRule {
            id: Uuid::new_v4(),
            name: "unreachable-cascade".to_string(),
            enabled: true,
            cause_expression: r#"name == "device_unreachable""#.to_string(),
            effect_expression: r#"name == "device_unreachable""#.to_string(),
        }
    }

    #[tokio::test]
    async fn store_round_trips_create_edit_and_delete() {
        let store = SeaOrmGroupAlertRuleStore::new_in_memory_for_tests().await;
        let rule = base_rule();
        store.upsert(&rule).await.unwrap();

        let all = store.list_all().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0], rule);

        let mut edited = rule.clone();
        edited.name = "unreachable-cascade-renamed".to_string();
        edited.enabled = false;
        store.upsert(&edited).await.unwrap();
        let all = store.list_all().await.unwrap();
        assert_eq!(all.len(), 1, "same id — must update in place");
        assert_eq!(all[0].name, "unreachable-cascade-renamed");
        assert!(!all[0].enabled);

        store.delete(rule.id).await.unwrap();
        assert!(store.list_all().await.unwrap().is_empty());
        store.delete(Uuid::new_v4()).await.unwrap(); // no-op
    }

    #[tokio::test]
    async fn get_returns_none_for_an_unknown_id() {
        let store = SeaOrmGroupAlertRuleStore::new_in_memory_for_tests().await;
        assert!(store.get(Uuid::new_v4()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn two_rules_may_share_the_same_name_unlike_topology_rules() {
        // Deliberately different from `TopologyRuleStore` — `name` here is a display label,
        // not a join key any other table references, so no unique index is enforced.
        let store = SeaOrmGroupAlertRuleStore::new_in_memory_for_tests().await;
        store.upsert(&base_rule()).await.unwrap();
        let mut other = base_rule();
        other.id = Uuid::new_v4();
        store.upsert(&other).await.unwrap();
        assert_eq!(store.list_all().await.unwrap().len(), 2);
    }
}
