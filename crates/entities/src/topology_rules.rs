//! `topology_rules` — provider-authored Rhai extraction rules for building the device
//! topology (`discovery_config_store::TopologyRule`/`TopologyRuleStore`). Domain
//! `discovery_core::Domain::Topology`, added 2026-09-16.
//!
//! `name` (not `id`) is what `topology_device_keys.rule_name`/`topology_claims.rule_name`
//! reference — a rule is renamed by editing this column, never by changing its stable
//! `id`, same "human-facing name is the join key other tables use" precedent as
//! `profiles.name`/`profile_metrics.profile_name`.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "topology_rules")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Unique (enforced by `idx_topology_rules_name` in the migration, application-checked
    /// on upsert too — same "unique name, not just unique id" shape as `profiles.name`).
    pub name: String,
    /// A single Rhai expression producing this device's own identifier under this rule
    /// (e.g. `metrics.lldp_chassis_id`) — `discovery_dsl::topology::TopologyEvaluator::evaluate_my_key`.
    /// `()` (missing referenced metric) means this device doesn't participate in this rule.
    pub my_key_expression: String,
    /// A Rhai expression producing an array of neighbor-key strings this device claims to
    /// see (e.g. `metrics.lldp_rem_table.map(|row| row.chassis_id)`) —
    /// `TopologyEvaluator::evaluate_claimed_neighbors`. `NULL` = this rule only computes
    /// `my_key` (a pure clustering signal, no directed claims) — evaluates to an empty
    /// claim list, not an error.
    pub claimed_neighbors_expression: Option<String>,
    /// A Rhai expression producing this device's numeric hierarchy level under this rule
    /// (e.g. `facts.role == "core" ? 0 : 1`) — `TopologyEvaluator::evaluate_rank`. Lower
    /// value = closer to the core/more upstream. `NULL` = this rule doesn't participate in
    /// hierarchy at all; same for a per-device `()` or non-numeric evaluation result — none
    /// of those are errors, they just leave direction undetermined for that device
    /// (`discovery_topology::apply_hierarchy`).
    pub rank_expression: Option<String>,
    /// `Vec<String>` metric names as JSON, or `NULL` — `NULL` means "auto-detect by
    /// scanning both expressions above for `metrics.<name>` references"
    /// (`discovery_dsl::topology::referenced_metrics`, the same regex-based mechanism
    /// `discovery_dsl::alerts::references_missing_metric` already uses for a similar
    /// purpose). `Some(list)` is an explicit override for the rare case a rule references
    /// a metric name computed dynamically, which the regex scan can't see. Same
    /// `Option<T>` "`None` = default behavior, not a sentinel value" idiom this project
    /// uses everywhere else (`.claude/rules/engineering-patterns.md`).
    #[sea_orm(column_type = "Json", nullable)]
    pub watched_metrics: Option<Json>,
    pub enabled: bool,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
