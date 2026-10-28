//! Provider-authored Rhai extraction rules for building the device topology — the
//! second half of `docs/Roadmap.md`'s "Топология → групповые тревоги → RADIUS" section,
//! rebuilt 2026-09-16 around a configurable mechanism instead of a hardcoded protocol
//! (LLDP/CDP/...) after direct user request: this product is sold to many providers with
//! very different network gear/conventions, so no single protocol fits all of them. See
//! `discovery_dsl::topology::TopologyEvaluator`'s docs for how the two expressions below
//! are actually evaluated, and `discovery_topology::TopologyStore`'s docs for how the
//! resulting per-device data is turned into resolved neighbor pairs.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One topology rule: "how does a device identify itself, and who does it claim as
/// neighbors, under this signal". Both expressions run in the same `{facts, metrics}`
/// Rhai scope every other DSL entry point in this project uses (`AlertEvaluator`'s
/// `evaluate_condition`/`evaluate_facts`, `ProfileMatcher::match_profile`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TopologyRule {
    pub id: Uuid,
    /// Unique — this is the join key `discovery_topology::TopologyStore` uses to scope
    /// `topology_device_keys`/`topology_claims` rows, not `id` (see
    /// `discovery_entities::topology_rules`'s module docs on why the DB-enforced
    /// uniqueness lives on this column).
    pub name: String,
    pub enabled: bool,
    /// A single Rhai expression producing this device's own identifier under this rule
    /// (e.g. `metrics.lldp_chassis_id`). Evaluating to `()` (the metric it references is
    /// absent for this device) means the device doesn't participate in this rule at all —
    /// not an error.
    pub my_key_expression: String,
    /// A Rhai expression producing an array of neighbor-key strings this device claims to
    /// see (e.g. `metrics.lldp_rem_table.map(|row| row.chassis_id)`). `None` = this rule
    /// only computes `my_key` (a pure clustering signal — no directed claims); evaluates
    /// as an empty claim list, never an error.
    #[serde(default)]
    pub claimed_neighbors_expression: Option<String>,
    /// A single Rhai expression producing this device's numeric hierarchy level under this
    /// rule (e.g. `facts.role == "core" ? 0 : 1`) — lower value = closer to the core/more
    /// upstream. `None` = this rule doesn't participate in hierarchy at all; a `()` or
    /// non-numeric per-device result is likewise not an error, it just leaves that device's
    /// direction undetermined (`discovery_dsl::topology::TopologyEvaluator::evaluate_rank`,
    /// `discovery_topology::apply_hierarchy`).
    #[serde(default)]
    pub rank_expression: Option<String>,
    /// `None` = auto-detect by scanning all three expressions above for `metrics.<name>`
    /// references (`discovery_dsl::topology::referenced_metrics`) — the metric names this
    /// rule needs polled before `MetricPollHandler` will trigger a recompute for a
    /// device. `Some(list)` is an explicit override for a metric name referenced
    /// dynamically (computed, not a literal `metrics.foo` the regex scan can see). Same
    /// `Option<T>` "`None` = default behavior" idiom used everywhere else in this project.
    #[serde(default)]
    pub watched_metrics: Option<Vec<String>>,
}

/// Where topology rules live. One implementation — [`SeaOrmTopologyRuleStore`] — same
/// "one trait, one sea-orm implementation" shape as [`crate::NotificationRuleStore`].
#[async_trait]
pub trait TopologyRuleStore: Send + Sync {
    async fn list_all(&self) -> anyhow::Result<Vec<TopologyRule>>;

    async fn get(&self, id: Uuid) -> anyhow::Result<Option<TopologyRule>>;

    /// Insert-or-replace-by-id — same "id decides create vs edit" contract as
    /// `crate::NotificationRuleStore::upsert`. A `name` collision with a *different* id
    /// surfaces as the underlying unique-constraint error (`idx_topology_rules_name`),
    /// not a bespoke pre-check — same "trust the DB constraint" posture the rest of this
    /// store takes.
    async fn upsert(&self, rule: &TopologyRule) -> anyhow::Result<()>;

    /// No-op (not an error) if `id` doesn't exist.
    async fn delete(&self, id: Uuid) -> anyhow::Result<()>;
}

pub struct SeaOrmTopologyRuleStore {
    db: sea_orm::DatabaseConnection,
}

impl SeaOrmTopologyRuleStore {
    pub fn new(db: sea_orm::DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn new_in_memory_for_tests() -> Self {
        Self::new(discovery_migration::connect_in_memory_for_tests().await)
    }
}

fn model_to_rule(m: discovery_entities::topology_rules::Model) -> anyhow::Result<TopologyRule> {
    Ok(TopologyRule {
        id: m.id,
        name: m.name,
        enabled: m.enabled,
        my_key_expression: m.my_key_expression,
        claimed_neighbors_expression: m.claimed_neighbors_expression,
        rank_expression: m.rank_expression,
        watched_metrics: m.watched_metrics.map(serde_json::from_value).transpose()?,
    })
}

#[async_trait]
impl TopologyRuleStore for SeaOrmTopologyRuleStore {
    async fn list_all(&self) -> anyhow::Result<Vec<TopologyRule>> {
        use discovery_entities::topology_rules::Entity;
        use sea_orm::EntityTrait;
        Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(model_to_rule)
            .collect()
    }

    async fn get(&self, id: Uuid) -> anyhow::Result<Option<TopologyRule>> {
        use discovery_entities::topology_rules::Entity;
        use sea_orm::EntityTrait;
        Entity::find_by_id(id)
            .one(&self.db)
            .await?
            .map(model_to_rule)
            .transpose()
    }

    async fn upsert(&self, rule: &TopologyRule) -> anyhow::Result<()> {
        use discovery_entities::topology_rules::{ActiveModel, Column, Entity};
        use sea_orm::sea_query::OnConflict;
        use sea_orm::{ActiveValue::Set, EntityTrait};

        let now = chrono::Utc::now();
        let am = ActiveModel {
            id: Set(rule.id),
            name: Set(rule.name.clone()),
            enabled: Set(rule.enabled),
            my_key_expression: Set(rule.my_key_expression.clone()),
            claimed_neighbors_expression: Set(rule.claimed_neighbors_expression.clone()),
            rank_expression: Set(rule.rank_expression.clone()),
            watched_metrics: Set(rule
                .watched_metrics
                .as_ref()
                .map(serde_json::to_value)
                .transpose()?),
            created_at: Set(now),
            updated_at: Set(now),
        };
        Entity::insert(am)
            .on_conflict(
                OnConflict::column(Column::Id)
                    .update_columns([
                        Column::Name,
                        Column::Enabled,
                        Column::MyKeyExpression,
                        Column::ClaimedNeighborsExpression,
                        Column::RankExpression,
                        Column::WatchedMetrics,
                        Column::UpdatedAt,
                    ])
                    .to_owned(),
            )
            .exec(&self.db)
            .await?;
        Ok(())
    }

    async fn delete(&self, id: Uuid) -> anyhow::Result<()> {
        use discovery_entities::topology_rules::Entity;
        use sea_orm::EntityTrait;
        Entity::delete_by_id(id).exec(&self.db).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_rule() -> TopologyRule {
        TopologyRule {
            id: Uuid::new_v4(),
            name: "lldp".to_string(),
            enabled: true,
            my_key_expression: "metrics.lldp_chassis_id".to_string(),
            claimed_neighbors_expression: Some(
                "metrics.lldp_rem_table.map(|row| row.chassis_id)".to_string(),
            ),
            rank_expression: None,
            watched_metrics: None,
        }
    }

    #[tokio::test]
    async fn store_round_trips_create_edit_and_delete() {
        let store = SeaOrmTopologyRuleStore::new_in_memory_for_tests().await;
        let rule = base_rule();
        store.upsert(&rule).await.unwrap();

        let all = store.list_all().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0], rule);

        let mut edited = rule.clone();
        edited.name = "lldp-renamed".to_string();
        edited.enabled = false;
        store.upsert(&edited).await.unwrap();
        let all = store.list_all().await.unwrap();
        assert_eq!(all.len(), 1, "same id — must update in place");
        assert_eq!(all[0].name, "lldp-renamed");
        assert!(!all[0].enabled);

        store.delete(rule.id).await.unwrap();
        assert!(store.list_all().await.unwrap().is_empty());
        store.delete(Uuid::new_v4()).await.unwrap(); // no-op
    }

    #[tokio::test]
    async fn get_returns_none_for_an_unknown_id() {
        let store = SeaOrmTopologyRuleStore::new_in_memory_for_tests().await;
        assert!(store.get(Uuid::new_v4()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn watched_metrics_override_round_trips() {
        let store = SeaOrmTopologyRuleStore::new_in_memory_for_tests().await;
        let mut rule = base_rule();
        rule.watched_metrics = Some(vec![
            "lldp_chassis_id".to_string(),
            "lldp_rem_table".to_string(),
        ]);
        store.upsert(&rule).await.unwrap();
        assert_eq!(
            store.get(rule.id).await.unwrap().unwrap().watched_metrics,
            rule.watched_metrics
        );
    }

    #[tokio::test]
    async fn rank_expression_round_trips_present_and_absent() {
        let store = SeaOrmTopologyRuleStore::new_in_memory_for_tests().await;
        let mut rule = base_rule();
        rule.rank_expression = Some(r#"facts.role == "core" ? 0 : 1"#.to_string());
        store.upsert(&rule).await.unwrap();
        assert_eq!(
            store.get(rule.id).await.unwrap().unwrap().rank_expression,
            rule.rank_expression
        );

        let mut edited = rule.clone();
        edited.rank_expression = None;
        store.upsert(&edited).await.unwrap();
        assert_eq!(
            store.get(rule.id).await.unwrap().unwrap().rank_expression,
            None
        );
    }

    #[tokio::test]
    async fn claimed_neighbors_expression_can_be_absent() {
        let store = SeaOrmTopologyRuleStore::new_in_memory_for_tests().await;
        let mut rule = base_rule();
        rule.claimed_neighbors_expression = None;
        store.upsert(&rule).await.unwrap();
        assert_eq!(
            store
                .get(rule.id)
                .await
                .unwrap()
                .unwrap()
                .claimed_neighbors_expression,
            None
        );
    }

    #[tokio::test]
    async fn duplicate_name_on_a_different_id_is_rejected_by_the_unique_index() {
        let store = SeaOrmTopologyRuleStore::new_in_memory_for_tests().await;
        store.upsert(&base_rule()).await.unwrap();
        let mut other = base_rule();
        other.id = Uuid::new_v4(); // same `name`, different `id`
        assert!(
            store.upsert(&other).await.is_err(),
            "idx_topology_rules_name must reject a second rule with the same name"
        );
    }
}
