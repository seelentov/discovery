//! `discovery_subnets` — one row per subnet within a discovery config
//! (`migrations/0008_discovery_subnets.sql` plus 0022's `create_dead_devices`). Same
//! routing domain as `discovery_configs` — real, DB-enforced FK.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "discovery_subnets")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub subnet_id: i64,
    pub discovery_config_name: String,
    pub ip: String,
    pub mask: String,
    pub port: i32,
    /// Serialized `Vec<discovery_core::SnmpAuth>` — replaces the former separate
    /// `snmp_versions`/`read_communities` columns (2026-08-29, SNMPv3 support; see
    /// `discovery-migration`'s `DiscoverySubnets::Credentials` docs for why). Any
    /// `SnmpV3Credentials` passphrase inside is ciphertext at rest
    /// (`SeaOrmDiscoveryConfigStore` encrypts/decrypts at the read/write boundary, see
    /// `discovery_core::secret`) — never plaintext in this column. Nullable so an
    /// already-deployed row that predates this column (`NULL`, not `[]`) doesn't need a
    /// cross-backend JSON column default; `None` and `[]` mean the same thing to the
    /// store (no candidates configured).
    #[sea_orm(column_type = "Json")]
    pub credentials: Option<Json>,
    pub snmp_timeout_ms: Option<i64>,
    pub snmp_retries: Option<i32>,
    pub create_dead_devices: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::discovery_configs::Entity",
        from = "Column::DiscoveryConfigName",
        to = "super::discovery_configs::Column::Name",
        on_delete = "Cascade"
    )]
    DiscoveryConfig,
}

impl ActiveModelBehavior for ActiveModel {}
