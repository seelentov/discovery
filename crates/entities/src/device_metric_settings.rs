//! `device_metric_settings` — per-device, per-metric manual on/off overrides
//! (`migrations/0018_device_metric_settings.sql`). Same routing domain as `devices`
//! ("Устройства" — see `discovery_bootstrap::DomainRouting::devices`'s docs), not
//! `device_metrics` — this table is about which metrics a device *should* poll, not the
//! polled values themselves, and the user's own domain list keeps it with the device row
//! it overrides.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "device_metric_settings")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub device_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub name: String,
    pub enabled: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
