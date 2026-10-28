//! `group_alert_rules` — provider-authored Rhai cause/effect rules for group-alert
//! suppression (`discovery_config_store::GroupAlertRule`/`GroupAlertRuleStore`). Domain
//! `discovery_core::Domain::GroupAlerts`, added 2026-09-16.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "group_alert_rules")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Display label only — unlike `topology_rules.name`, nothing joins against this
    /// column, so it carries no uniqueness constraint.
    pub name: String,
    /// Rhai expression, evaluated against the candidate upstream (root-cause) alert's
    /// `{name, level, facts}` — `discovery_dsl::group_alerts::GroupAlertEvaluator::evaluate_cause`.
    pub cause_expression: String,
    /// Rhai expression, same scope, evaluated against the candidate downstream (to-be-
    /// suppressed) alert — `GroupAlertEvaluator::evaluate_effect`.
    pub effect_expression: String,
    pub enabled: bool,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
