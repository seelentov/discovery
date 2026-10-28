//! `queue_control` — whole-queue pause flag, domain "Очередь заданий" (2026-08-21, see
//! `discovery_queue::JobQueueStore::is_queue_paused`'s docs). One row per *paused* queue;
//! a queue with no row here is simply not paused — see that trait method's docs for why
//! "row absent" is the steady-state representation instead of seeding one row per
//! `QueueKind` up front.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "queue_control")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub queue_type: String,
    pub paused: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
