//! `maintenance_windows` — one row per named, independently CRUD-able maintenance window
//! (`discovery_config_store::MaintenanceWindowStore`). Domain "Maintenance windows"
//! (`discovery_core::Domain::MaintenanceWindows`), added 2026-09-07.
//!
//! `subnets`/`profiles`/`device_ids` are each the *whole* selector dimension as JSON, not
//! normalized into their own child tables — same precedent as `profile_traps.variants`/
//! `profile_syslog.variants` (see those modules' docs): nested structured data that's
//! small and always read/written as a single unit gets a JSON column; only genuine
//! one-row-per-X collections that need independent querying get a real child table. A
//! maintenance window's selector is always read/written whole (there is no "list every
//! window targeting subnet X" query — matching happens in application code, once per
//! device per `AlertEval` tick, against the small in-memory list every enabled window
//! resolves to), so a child table here would only add join/cascade ceremony for no
//! querying benefit.
//!
//! No FK to `devices` for the ids inside `device_ids` — same cross-domain reasoning as
//! `alerts.device_id`/`device_metrics.device_id` (see those modules' docs):
//! "Maintenance windows" and "Устройства" can independently route to different physical
//! databases, and a device id living inside a JSON array couldn't be a column-level FK
//! target anyway.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "maintenance_windows")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub starts_at: DateTimeUtc,
    pub ends_at: DateTimeUtc,
    /// `Vec<discovery_config_store::SubnetTarget>` (`{ip, mask}` pairs) as JSON — empty
    /// array means "don't filter by subnet" (see `MaintenanceWindow::matches`'s docs).
    #[sea_orm(column_type = "Json")]
    pub subnets: Json,
    /// `Vec<String>` (profile names) as JSON.
    #[sea_orm(column_type = "Json")]
    pub profiles: Json,
    /// `Vec<Uuid>` (explicit device allow-list) as JSON.
    #[sea_orm(column_type = "Json")]
    pub device_ids: Json,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
