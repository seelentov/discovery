//! `topology_claims` — one row per (rule, claiming device, claimed neighbor key): "this
//! device says it sees a neighbor with this key, under this rule"
//! (`discovery_topology::TopologyStore`). Fully replaced (`DELETE` old rows for
//! `(rule_name, claimer_device_id)` + fresh `INSERT`) every time that one device gets
//! recomputed — never appended to, never edited in place — so a stale claim (the
//! neighbor moved away, the port went down) disappears as soon as the claiming device's
//! own topology-relevant metric is next polled, not before.
//!
//! `rule_name` is a real FK (`ON DELETE CASCADE` to `topology_rules.name`) — same
//! same-domain reasoning as `topology_device_keys`'s docs. `claimer_device_id` is
//! deliberately not an FK, same cross-domain reasoning, cleaned up explicitly via
//! `TopologyStore::delete_for_device`.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "topology_claims")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub rule_name: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub claimer_device_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub claimed_key: String,
    pub observed_at: DateTimeUtc,
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
