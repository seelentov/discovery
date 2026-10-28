//! `devices` — the device inventory (`migrations/0002_devices.sql` plus every later
//! `ALTER` folded into its final shape: reachability, `enabled`, `ping_failing_since`).
//! Domain "Устройства" — see `discovery_bootstrap::DomainRouting::devices`'s docs.
//!
//! **Deliberately carries no relation to `device_metrics`/`device_metric_history`/
//! `alerts`** even though those tables' rows logically belong to a device — those three
//! live in *different* routing domains (`device_metrics`/`alerts`) that may resolve to a
//! different physical database than this one, so a sea-orm `Relation`/join across that
//! boundary would silently break the moment someone actually routes them apart. Any
//! store needing "this device's metrics" does two independent queries against two
//! independently-resolved connections, not a join — see `discovery-devices`'s
//! `DeviceStore`/`DeviceMetricsStore` split docs.
use sea_orm::entity::prelude::*;

// No `Eq` (unlike every other entity in this crate) — `ping_loss_pct: Option<f64>` below
// is the first floating-point column any entity here has ever had, and `f64` has no `Eq`
// impl (NaN isn't reflexively equal to itself). Nothing in this codebase relies on
// `devices::Model: Eq` (no `HashSet`/`BTreeSet` of rows, no `Eq`-bound generic) — `PartialEq`
// alone covers every actual use (test `assert_eq!`, etc.).
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "devices")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub device_id: Uuid,
    pub ip: String,
    pub profile: Option<String>,
    pub profile_version: Option<String>,
    pub poll_generation: i64,
    /// Serialized `discovery_core::SnmpAuth` (community or USM v3) — see
    /// `discovery-migration`'s `Devices::SnmpAuth` docs for why this replaced the former
    /// `snmp_version`/`snmp_community` pair. Any `SnmpV3Credentials` passphrase inside is
    /// ciphertext at rest (`SeaOrmDeviceStore` encrypts/decrypts at the read/write
    /// boundary, see `discovery_core::secret`) — never plaintext in this column.
    pub snmp_auth: Option<Json>,
    pub snmp_port: i32,
    /// Serialized `discovery_core::SshAuth` — see `discovery-migration`'s
    /// `Devices::SshAuth` docs. `NULL` = no SSH credentials configured yet.
    pub ssh_auth: Option<Json>,
    pub ssh_username: String,
    pub ssh_port: i32,
    /// SHA256 fingerprint of this device's pinned SSH host key — see
    /// `discovery-migration`'s `Devices::SshHostKeyFingerprint` docs and
    /// `discovery_core::SshCredentials::known_host_key`'s docs for the trust-on-first-use
    /// contract. `NULL` = not yet pinned.
    pub ssh_host_key_fingerprint: Option<String>,
    pub discovered_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
    pub ping_ok: Option<bool>,
    pub ping_checked_at: Option<DateTimeUtc>,
    /// The share of the most recent reachability tick's `1 + retries` ICMP attempts that
    /// got no reply, `0.0`-`100.0` — see `discovery-migration`'s `Devices::PingLossPct`
    /// docs. `NULL` until the first reachability tick after this column existed.
    pub ping_loss_pct: Option<f64>,
    pub snmp_ok: Option<bool>,
    pub snmp_checked_at: Option<DateTimeUtc>,
    pub enabled: bool,
    pub ping_failing_since: Option<DateTimeUtc>,
    /// Precomputed `discovery_core::ipv4_to_sort_key(ip)` — added 2026-08-21, scale audit.
    /// See that function's docs and `discovery-migration`'s `up()` for why this exists
    /// instead of sorting `ip` as a plain string.
    pub ip_sort_key: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
