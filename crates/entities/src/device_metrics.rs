//! `device_metrics` — the derived "latest state" cache per `(device_id, name)`
//! (`migrations/0003_device_metrics.sql`'s final shape). Domain "Метрики устройств" —
//! see `discovery_bootstrap::DomainRouting::device_metrics`'s docs. `device_id` is a
//! **soft** reference to `devices.device_id`, not an enforced `FOREIGN KEY` — those two
//! domains can resolve to different physical databases (see `devices.rs`'s docs), so
//! `DeviceStore::delete`/`delete_unreachable_since` must explicitly delete this table's
//! matching rows in application code instead of relying on `ON DELETE CASCADE`.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "device_metrics")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub device_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub name: String,
    #[sea_orm(column_type = "Json", nullable)]
    pub value: Option<Json>,
    pub error: Option<String>,
    pub polled_at: Option<DateTimeUtc>,
    pub last_attempt_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
