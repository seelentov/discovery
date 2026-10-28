//! `device_metric_history` — append-only "state run" change history
//! (`migrations/0012_device_metric_history.sql`). Same routing domain as
//! `device_metrics` ("Метрики устройств"). `device_id` is a **soft** reference to
//! `devices.device_id` — see `device_metrics.rs`'s docs for why there's no enforced FK.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "device_metric_history")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub device_id: Uuid,
    pub name: String,
    #[sea_orm(column_type = "Json", nullable)]
    pub value: Option<Json>,
    pub error: Option<String>,
    pub first_observed_at: DateTimeUtc,
    pub last_observed_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
