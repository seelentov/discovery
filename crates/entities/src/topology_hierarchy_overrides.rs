//! `topology_hierarchy_overrides` — a manual pin of which side of an edge is upstream,
//! overriding whatever `topology_rules.rank_expression` would otherwise compute (or filling
//! in direction when it can't — a tie, or no rank expression configured at all). See
//! `discovery_topology::apply_hierarchy` for how this table is combined with rank data.
//!
//! Scoped per `rule_name`, same as `topology_device_keys`/`topology_claims` — there is no
//! cross-rule merged graph anywhere in this feature, so an override only makes sense in the
//! context of one specific rule's resolved edges.
//!
//! `device_a`/`device_b` are canonicalized `(min, max)` by the store layer, same convention
//! `discovery_topology::ResolvedEdge` already uses — neither is an FK, same cross-domain
//! reasoning as `topology_device_keys.device_id` (`Devices` may be a different physical
//! database than `Topology`). `upstream_device_id` must equal `device_a` or `device_b` —
//! enforced in application code (REST handler + `TopologyStore::set_hierarchy_override`),
//! not a DB `CHECK` constraint (this project doesn't use those anywhere, cross-backend).
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "topology_hierarchy_overrides")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub rule_name: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub device_a: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub device_b: Uuid,
    pub upstream_device_id: Uuid,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::topology_rules::Entity",
        from = "Column::RuleName",
        to = "super::topology_rules::Column::Name",
        on_delete = "Cascade"
    )]
    Rule,
}

impl ActiveModelBehavior for ActiveModel {}
