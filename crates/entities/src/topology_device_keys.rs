//! `topology_device_keys` — one row per (rule, device) holding that device's own
//! `my_key` under that rule (`discovery_topology::TopologyStore`). This is the
//! fleet-wide index a `topology_claims.claimed_key` resolves against — see
//! `TopologyStore::neighbors_of`'s docs for the forward/reverse resolution this table
//! makes possible without ever re-touching the device that isn't currently being
//! recomputed.
//!
//! `rule_name` is a real, DB-enforced `FOREIGN KEY ... ON DELETE CASCADE` to
//! `topology_rules.name` — same "same domain, same physical database by construction"
//! reasoning as `profile_metrics.profile_name -> profiles.name` (see
//! `discovery_entities::profile_metrics`'s docs): deleting a rule should drop every
//! device's key/claims under it, and both tables always live in `Domain::Topology`.
//!
//! `device_id` is deliberately **not** an FK — `Devices` can be routed to a different
//! physical database than `Topology` (`docs/Architecture/Domains и модель данных.md`),
//! so cleanup on device deletion is explicit application code
//! (`TopologyStore::delete_for_device`, called from `DeviceStore::delete`), the same
//! cross-domain pattern `device_metrics`/`alerts` already use for their own `device_id`.
use sea_orm::entity::prelude::*;

// No `Eq` (unlike most entities in this crate) — `rank: Option<f64>` below isn't `Eq`,
// same reasoning as `discovery_entities::devices`'s `ping_loss_pct`.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "topology_device_keys")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub rule_name: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub device_id: Uuid,
    pub my_key: String,
    /// This device's hierarchy level under this rule, per `topology_rules.rank_expression`
    /// — `NULL` if the rule has no rank expression, or it evaluated to `()`/non-numeric for
    /// this device. Computed and cleared in the same `apply_recompute` write as `my_key`.
    pub rank: Option<f64>,
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
