use std::collections::BTreeMap;

use async_trait::async_trait;
use discovery_core::SnmpAuth;
use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

fn default_snmp_port() -> u16 {
    161
}

/// One entry in [`SubnetSpec::oids`] — a discovery-time OID fetched once during a
/// subnet's identity probe (`SnmpPollHandler`), scalar or table-shaped. Same
/// three-state `columns` encoding as `discovery_dsl::MetricSpec::Detailed::columns`
/// (see its docs for the full reasoning — untagged JSON shape as the discriminant,
/// not a separate tag, for the same "no ambiguous-parse trap" reason): `columns`
/// absent/`null` = scalar (`get()`), `Some({})` = table "collect everything" (one
/// `walk()` on the whole entry OID), `Some({"name": "subid", ...})` = table with
/// curated columns (one `walk()` per column). **Deliberately no `schedule`/`enabled`/
/// `history_retention_secs`/etc. fields** the way `MetricSpec` has — those don't apply
/// here: a `SubnetSpec::oids` entry is one-shot by definition (fetched exactly once,
/// on a device's very first identity cycle, never re-polled — see `SubnetSpec::oids`'s
/// own docs), so there's no cadence or retention to configure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DiscoveryOidSpec {
    Oid(String),
    Detailed {
        /// Scalar: the OID's own full path. Table (`columns` is `Some`): the MIB
        /// **entry** OID columns hang off, same convention as `MetricSpec::Detailed::oid`.
        oid: String,
        #[serde(default)]
        columns: Option<BTreeMap<String, String>>,
    },
}

impl DiscoveryOidSpec {
    pub fn oid(&self) -> &str {
        match self {
            DiscoveryOidSpec::Oid(oid) => oid,
            DiscoveryOidSpec::Detailed { oid, .. } => oid,
        }
    }

    pub fn columns(&self) -> Option<&BTreeMap<String, String>> {
        match self {
            DiscoveryOidSpec::Oid(_) => None,
            DiscoveryOidSpec::Detailed { columns, .. } => columns.as_ref(),
        }
    }

    pub fn is_table(&self) -> bool {
        self.columns().is_some()
    }
}

impl From<String> for DiscoveryOidSpec {
    fn from(oid: String) -> Self {
        DiscoveryOidSpec::Oid(oid)
    }
}

impl From<&str> for DiscoveryOidSpec {
    fn from(oid: &str) -> Self {
        DiscoveryOidSpec::Oid(oid.to_string())
    }
}

/// When a [`DiscoveryConfig`]'s scan actually fires — calendar (months/days/time-of-day)
/// or a plain periodic interval. **Moved to `discovery_core::Schedule` 2026-08-16**
/// (direct user request: "впиши такую же логику в метрики в профиле" — the same
/// periodic-vs-calendar switch is now also used by `discovery_dsl::MetricSpec`, and
/// `discovery-dsl` can't depend on this crate — `discovery-config-store` already depends
/// on `discovery-dsl` — so the shared type lives in `discovery-core`, which both depend
/// on). Re-exported here under its original name so existing call sites
/// (`discovery-agent`'s `use discovery_config_store::Schedule`) don't need to change their
/// import path. See `discovery_core::Schedule`'s docs for the full contract.
///
/// Stored as one JSON blob on `discovery_configs` (not normalized further) — it's a small
/// fixed-shape record, not an open-ended list that grows or needs its own FK lifecycle the
/// way `subnets`/`oids`/`labels` do (see [`SubnetSpec`]'s docs for the ones that did get
/// normalized, 2026-08-16).
pub use discovery_core::Schedule;

/// One subnet within a [`DiscoveryConfig`]: the range to scan, which SNMP
/// version/community candidates to try against hosts in it (tried nested — each version
/// in order, each community within that version in order — until one combination
/// responds), and which extra named OIDs/constant labels to collect once during
/// discovery's identity probe.
///
/// **Changed 2026-08-16 (direct user request, DB normalization):** `oids`/`labels` used
/// to be JSONB maps inline on this record. Storage backends now keep them as their own
/// FK/cascade child tables (`discovery_subnet_oids`/`discovery_subnet_labels`, off
/// `discovery_subnets`) — deleting a subnet (or its parent config) cleans them up
/// automatically, no dead rows left behind. This Rust struct's shape is unchanged; only
/// how [`SeaOrmDiscoveryConfigStore`] persists it changed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetSpec {
    /// Network address, e.g. `"10.0.0.0"`.
    pub ip: String,
    /// Dotted-decimal subnet mask, e.g. `"255.255.255.0"` — not a CIDR prefix length,
    /// deliberately: this is the representation most network engineers reach for first.
    pub mask: String,
    /// UDP port to talk SNMP on for hosts in this subnet. Defaults to the standard 161 —
    /// only real-world reason to override is a non-standard device, but it's also what
    /// makes local testing against a non-root SNMP simulator possible (`snmpd` bound to a
    /// high port like 1161 needs no root; 161 does).
    #[serde(default = "default_snmp_port")]
    pub port: u16,
    /// Candidates to try against hosts in this subnet, in order, stopping at the first
    /// that answers — see `discovery_agent::discovery_scan::negotiate_snmp_credentials`.
    /// **Replaces the former `snmp_versions: Vec<SnmpVersion>` + `read_communities:
    /// Vec<String>` pair (2026-08-29, SNMPv3 support)**: that shape only worked because
    /// v1/v2c share one community-string space to cross-product over; v3 has no
    /// community at all (USM user/auth/priv instead), so it couldn't be added as a third
    /// `snmp_versions` entry without `read_communities` becoming meaningless for it. A
    /// flat list of [`discovery_core::SnmpAuth`] candidates (community *or* USM v3, mixed
    /// freely) replaces the nested "version outer loop, community inner loop" with a
    /// single loop over this list.
    #[serde(default)]
    pub credentials: Vec<SnmpAuth>,
    /// name -> [`DiscoveryOidSpec`] (scalar or table), fetched once during the identity
    /// probe for hosts in this subnet. **Changed 2026-08-29** (direct user request —
    /// table-shaped discovery-time OIDs, e.g. `ifTable`, not just scalars): value type
    /// was a plain `String` (the OID itself); a bare-string JSON value still
    /// deserializes into `DiscoveryOidSpec::Oid` unchanged, so this is backward-
    /// compatible with every config written before this field existed.
    #[serde(default)]
    pub oids: BTreeMap<String, DiscoveryOidSpec>,
    /// name -> constant value, written into a device's metrics bag once during the
    /// identity probe — same one-shot timing/gate as `oids` above (only on a device's
    /// very first identity cycle), but **no SNMP round trip**: the value is whatever's
    /// configured here, verbatim, not fetched from the device. Use case: tag every device
    /// found through this subnet with something the subnet itself implies but no OID on
    /// the device would ever report — e.g. `area_name = "Воронеж"` to record which branch
    /// a subnet belongs to.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// Per-SNMP-request timeout in milliseconds for hosts in this subnet — used both
    /// during the identity probe (`SnmpPoll`) and for every metric poll
    /// (`MetricPoll`) against devices discovered through it. `None` = use the
    /// process-wide default (`discovery_core::default_snmp_timeout_ms`, 2s).
    #[serde(default)]
    pub snmp_timeout_ms: Option<u64>,
    /// Additional attempts after the first failure (total attempts = `1 + retries`) for
    /// hosts in this subnet — same `None` = process-wide default
    /// (`discovery_core::default_snmp_retries`, 1) convention as `snmp_timeout_ms`.
    #[serde(default)]
    pub snmp_retries: Option<u32>,
    /// Direct user request 2026-08-18: "если ping мертвый, не создавать устройство".
    /// **Defaults to `false`** (deliberately not `default_true` like `DiscoveryConfig`'s
    /// own `enabled` — this one is opt-*in*, both for new configs and for any config
    /// already stored before this field existed, which get `false` here the same as any
    /// other missing-field default) — meaning by default a candidate address that doesn't
    /// even answer ICMP never gets a `Device` row or a permanent recurring `SnmpPoll`
    /// chain at all. See `discovery_agent::handlers::DiscoveryHandler`'s docs for exactly
    /// where this is checked (before `ActiveChains::mark`, specifically so a skipped IP
    /// isn't permanently blocked from being re-checked by a *later* discovery run — only
    /// this one candidacy is skipped, not the IP forever). `true` restores the old
    /// unconditional "every candidate becomes a device" behavior for subnets that want it.
    #[serde(default)]
    pub create_dead_devices: bool,
}

/// A named, independently schedulable and enable/disable-able discovery job. Multiple can
/// exist at once (`DiscoveryConfigStore::load_all`) and all of the enabled ones run on
/// their own schedules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub schedule: Schedule,
    #[serde(default)]
    pub subnets: Vec<SubnetSpec>,
}

/// Where the list of discovery configs lives. One implementation —
/// [`SeaOrmDiscoveryConfigStore`], works against Postgres/MySQL/SQLite (and, for
/// tests/zero-config, `sqlite::memory:`) through the same sea-orm entity/query code path
/// (2026-08-18 multi-DB rewrite, replacing the old `PostgresDiscoveryConfigStore`/
/// `SqliteDiscoveryConfigStore`/`InMemoryDiscoveryConfigStore` trio — see
/// `discovery_config_store::SeaOrmSettingsStore`'s docs for the full rationale). Configs
/// are rows in `discovery_configs`; each one's subnets are rows in `discovery_subnets`,
/// and each subnet's OIDs/labels are rows in `discovery_subnet_oids`/
/// `discovery_subnet_labels` — same-domain FK/cascade children, see those entities' docs.
///
/// Unlike profiles, there's no hot-reload loop dedicated to this (the schedule-check loop
/// in `discovery-agent` already re-reads it on every check tick, so an edit just takes
/// effect on the next tick for free — see its docs).
///
/// **No file-backed store anymore** — `FileDiscoveryConfigStore`/`scans/*.toml` removed
/// 2026-08-16 (direct user request, same as `ProfileStore`'s docs) in favor of writing
/// configs directly (dashboard/API, or a direct `INSERT` for tests).
#[async_trait]
pub trait DiscoveryConfigStore: Send + Sync {
    async fn load_all(&self) -> anyhow::Result<Vec<DiscoveryConfig>>;
    async fn upsert(&self, config: &DiscoveryConfig) -> anyhow::Result<()>;
    async fn delete(&self, name: &str) -> anyhow::Result<()>;
}

/// The sea-orm-backed implementation — see [`DiscoveryConfigStore`]'s docs.
pub struct SeaOrmDiscoveryConfigStore {
    db: sea_orm::DatabaseConnection,
    /// `None` unless [`Self::with_secret_key`] was called — see that method's docs.
    secret_key: Option<std::sync::Arc<discovery_core::secret::SecretKey>>,
}

impl SeaOrmDiscoveryConfigStore {
    pub fn new(db: sea_orm::DatabaseConnection) -> Self {
        Self {
            db,
            secret_key: None,
        }
    }

    /// Opts this store into encrypting/decrypting `SnmpAuth::UsmV3` passphrases inside
    /// `SubnetSpec::credentials` at the read/write boundary (`discovery_core::secret`) —
    /// a builder method, not a constructor parameter, so every existing `new`/
    /// `new_in_memory_for_tests` call site (none of which exercise SNMPv3) doesn't need
    /// to change. Only `discovery-agent`'s real bootstrap wiring needs to call this.
    /// Without it, writing or reading a `UsmV3` credential fails loudly
    /// (`SecretError::KeyRequired`) instead of silently storing/returning plaintext.
    pub fn with_secret_key(
        mut self,
        key: std::sync::Arc<discovery_core::secret::SecretKey>,
    ) -> Self {
        self.secret_key = Some(key);
        self
    }

    /// Convenience for tests — see `SeaOrmSettingsStore::new_in_memory_for_tests`'s docs
    /// for why this exists and why it's async. `discovery_migration::connect_in_memory_for_tests`
    /// also turns on `PRAGMA foreign_keys = ON` — load-bearing here, same reason as
    /// `SeaOrmProfileStore`'s docs: `delete`/`upsert` both rely entirely on
    /// `discovery_subnets`/`discovery_subnet_oids`/`discovery_subnet_labels`'s `ON DELETE
    /// CASCADE` to clean up.
    pub async fn new_in_memory_for_tests() -> Self {
        Self::new(discovery_migration::connect_in_memory_for_tests().await)
    }
}

mod queries {
    use super::{DiscoveryConfig, DiscoveryOidSpec, Schedule, SubnetSpec};
    use discovery_core::secret::{decrypt_auth_secrets, encrypt_auth_secrets, SecretKey};
    use discovery_entities::{
        discovery_configs, discovery_subnet_labels, discovery_subnet_oids, discovery_subnets,
    };
    use sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseConnection,
        EntityTrait, QueryFilter, TransactionTrait,
    };
    use std::collections::{BTreeMap, HashMap};

    pub async fn load_all(
        db: &DatabaseConnection,
        secret_key: Option<&SecretKey>,
    ) -> anyhow::Result<Vec<DiscoveryConfig>> {
        let config_rows = discovery_configs::Entity::find().all(db).await?;
        let subnet_rows = discovery_subnets::Entity::find().all(db).await?;
        let oid_rows = discovery_subnet_oids::Entity::find().all(db).await?;
        let label_rows = discovery_subnet_labels::Entity::find().all(db).await?;

        let mut oids_by_subnet: HashMap<i64, BTreeMap<String, DiscoveryOidSpec>> = HashMap::new();
        for row in oid_rows {
            let columns = row.columns.map(serde_json::from_value).transpose()?;
            let spec = match columns {
                None => DiscoveryOidSpec::Oid(row.oid),
                Some(columns) => DiscoveryOidSpec::Detailed {
                    oid: row.oid,
                    columns: Some(columns),
                },
            };
            oids_by_subnet
                .entry(row.subnet_id)
                .or_default()
                .insert(row.name, spec);
        }
        let mut labels_by_subnet: HashMap<i64, BTreeMap<String, String>> = HashMap::new();
        for row in label_rows {
            labels_by_subnet
                .entry(row.subnet_id)
                .or_default()
                .insert(row.name, row.value);
        }

        let mut subnets_by_config: HashMap<String, Vec<SubnetSpec>> = HashMap::new();
        for row in subnet_rows {
            let raw_credentials: Vec<discovery_core::SnmpAuth> = match row.credentials {
                Some(json) => serde_json::from_value(json)?,
                None => Vec::new(), // pre-2026-08-29 row (or a subnet saved with none configured) — same as an empty list
            };
            let credentials = raw_credentials
                .into_iter()
                .map(|auth| decrypt_auth_secrets(auth, secret_key))
                .collect::<Result<Vec<_>, _>>()?;
            subnets_by_config
                .entry(row.discovery_config_name)
                .or_default()
                .push(SubnetSpec {
                    ip: row.ip,
                    mask: row.mask,
                    port: row.port as u16,
                    credentials,
                    oids: oids_by_subnet.remove(&row.subnet_id).unwrap_or_default(),
                    labels: labels_by_subnet.remove(&row.subnet_id).unwrap_or_default(),
                    snmp_timeout_ms: row.snmp_timeout_ms.map(|v| v as u64),
                    snmp_retries: row.snmp_retries.map(|v| v as u32),
                    create_dead_devices: row.create_dead_devices,
                });
        }

        config_rows
            .into_iter()
            .map(|row| {
                let schedule: Schedule = serde_json::from_value(row.schedule)?;
                let subnets = subnets_by_config.remove(&row.name).unwrap_or_default();
                Ok(DiscoveryConfig {
                    name: row.name,
                    enabled: row.enabled,
                    schedule,
                    subnets,
                })
            })
            .collect()
    }

    async fn insert_subnets<C: ConnectionTrait>(
        txn: &C,
        config_name: &str,
        subnets: &[SubnetSpec],
        secret_key: Option<&SecretKey>,
    ) -> anyhow::Result<()> {
        for subnet in subnets {
            let encrypted_credentials: Vec<discovery_core::SnmpAuth> = subnet
                .credentials
                .iter()
                .cloned()
                .map(|auth| encrypt_auth_secrets(auth, secret_key))
                .collect::<Result<Vec<_>, _>>()?;
            let credentials =
                serde_json::to_value(&encrypted_credentials).expect("SnmpAuth always serializes");
            let am = discovery_subnets::ActiveModel {
                subnet_id: sea_orm::ActiveValue::NotSet,
                discovery_config_name: Set(config_name.to_string()),
                ip: Set(subnet.ip.clone()),
                mask: Set(subnet.mask.clone()),
                port: Set(subnet.port as i32),
                credentials: Set(Some(credentials)),
                snmp_timeout_ms: Set(subnet.snmp_timeout_ms.map(|v| v as i64)),
                snmp_retries: Set(subnet.snmp_retries.map(|v| v as i32)),
                create_dead_devices: Set(subnet.create_dead_devices),
            };
            let inserted = am.insert(txn).await?;

            for (name, spec) in &subnet.oids {
                let columns = spec
                    .columns()
                    .map(|c| serde_json::to_value(c).expect("a column map always serializes"));
                discovery_subnet_oids::ActiveModel {
                    subnet_id: Set(inserted.subnet_id),
                    name: Set(name.clone()),
                    oid: Set(spec.oid().to_string()),
                    columns: Set(columns),
                }
                .insert(txn)
                .await?;
            }
            for (name, value) in &subnet.labels {
                discovery_subnet_labels::ActiveModel {
                    subnet_id: Set(inserted.subnet_id),
                    name: Set(name.clone()),
                    value: Set(value.clone()),
                }
                .insert(txn)
                .await?;
            }
        }
        Ok(())
    }

    pub async fn upsert(
        db: &DatabaseConnection,
        config: &DiscoveryConfig,
        secret_key: Option<&SecretKey>,
    ) -> anyhow::Result<()> {
        use sea_orm::sea_query::OnConflict;

        let schedule = serde_json::to_value(&config.schedule)?;
        let txn = db.begin().await?;
        let now = chrono::Utc::now();
        let am = discovery_configs::ActiveModel {
            name: Set(config.name.clone()),
            enabled: Set(config.enabled),
            schedule: Set(schedule),
            created_at: Set(now),
            updated_at: Set(now),
        };
        discovery_configs::Entity::insert(am)
            .on_conflict(
                OnConflict::column(discovery_configs::Column::Name)
                    .update_columns([
                        discovery_configs::Column::Enabled,
                        discovery_configs::Column::Schedule,
                        discovery_configs::Column::UpdatedAt,
                    ])
                    .to_owned(),
            )
            .exec(&txn)
            .await?;
        // Cascades into discovery_subnet_oids/discovery_subnet_labels automatically (needs
        // `PRAGMA foreign_keys = ON` on SQLite specifically, see this store's docs).
        discovery_subnets::Entity::delete_many()
            .filter(discovery_subnets::Column::DiscoveryConfigName.eq(config.name.clone()))
            .exec(&txn)
            .await?;
        insert_subnets(&txn, &config.name, &config.subnets, secret_key).await?;
        txn.commit().await?;
        Ok(())
    }

    pub async fn delete(db: &DatabaseConnection, name: &str) -> anyhow::Result<()> {
        discovery_configs::Entity::delete_by_id(name.to_string())
            .exec(db)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl DiscoveryConfigStore for SeaOrmDiscoveryConfigStore {
    async fn load_all(&self) -> anyhow::Result<Vec<DiscoveryConfig>> {
        queries::load_all(&self.db, self.secret_key.as_deref()).await
    }

    async fn upsert(&self, config: &DiscoveryConfig) -> anyhow::Result<()> {
        queries::upsert(&self.db, config, self.secret_key.as_deref()).await
    }

    async fn delete(&self, name: &str) -> anyhow::Result<()> {
        queries::delete(&self.db, name).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use discovery_core::SnmpVersion;

    fn sample_config(name: &str) -> DiscoveryConfig {
        DiscoveryConfig {
            name: name.to_string(),
            enabled: true,
            schedule: Schedule::Calendar {
                months: vec![],
                days_of_month: vec![],
                time: chrono::NaiveTime::from_hms_opt(3, 0, 0).unwrap(),
            },
            subnets: vec![SubnetSpec {
                ip: "10.0.0.0".into(),
                mask: "255.255.255.0".into(),
                port: 161,
                credentials: vec![SnmpAuth::Community {
                    version: SnmpVersion::V2c,
                    community: "public".into(),
                }],
                oids: BTreeMap::from([(
                    "sys_descr".to_string(),
                    DiscoveryOidSpec::Oid("1.3.6.1.2.1.1.1.0".to_string()),
                )]),
                labels: BTreeMap::from([("area_name".to_string(), "Воронеж".to_string())]),
                snmp_timeout_ms: Some(1500),
                snmp_retries: Some(2),
                create_dead_devices: true,
            }],
        }
    }

    #[tokio::test]
    async fn round_trips_upsert_and_delete_including_subnets_oids_and_labels() {
        let store = SeaOrmDiscoveryConfigStore::new_in_memory_for_tests().await;
        store.upsert(&sample_config("office")).await.unwrap();

        let loaded = store.load_all().await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "office");
        assert_eq!(loaded[0].subnets.len(), 1);
        assert_eq!(
            loaded[0].subnets[0].credentials,
            vec![SnmpAuth::Community {
                version: SnmpVersion::V2c,
                community: "public".into()
            }]
        );
        assert_eq!(
            loaded[0].subnets[0].oids.get("sys_descr").unwrap().oid(),
            "1.3.6.1.2.1.1.1.0"
        );
        assert_eq!(
            loaded[0].subnets[0].labels.get("area_name").unwrap(),
            "Воронеж"
        );
        assert_eq!(loaded[0].subnets[0].snmp_timeout_ms, Some(1500));

        store.delete("office").await.unwrap();
        assert!(store.load_all().await.unwrap().is_empty());
    }

    /// The point of `discovery_core::secret`'s encrypt-at-rest boundary: a `UsmV3`
    /// passphrase must round-trip correctly through a store configured with a key
    /// (`load_all` after `upsert` returns the original plaintext) **and** the actual row
    /// sitting in the DB must not contain that plaintext anywhere — checked by reading
    /// the raw `discovery_subnets.credentials` JSON directly, not just trusting the
    /// store's own decrypt path to prove itself. This is the test the plan called
    /// "the most important — not just that the code compiles."
    #[tokio::test]
    async fn usm_v3_passphrases_are_ciphertext_in_the_db_and_round_trip_through_the_store() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        use discovery_core::secret::SecretKey;
        use discovery_core::{SnmpV3AuthCreds, SnmpV3Credentials, SnmpV3PrivCreds};
        use sea_orm::EntityTrait;

        let db = discovery_migration::connect_in_memory_for_tests().await;
        let key = std::sync::Arc::new(SecretKey::from_base64(&STANDARD.encode([9u8; 32])).unwrap());
        let store = SeaOrmDiscoveryConfigStore::new(db.clone()).with_secret_key(key);

        let mut config = sample_config("v3-office");
        config.subnets[0].credentials = vec![SnmpAuth::UsmV3(SnmpV3Credentials {
            user: "monitor".to_string(),
            auth: Some(SnmpV3AuthCreds {
                protocol: discovery_core::SnmpAuthProtocol::Sha1,
                passphrase: "authpass123".to_string(),
            }),
            priv_: Some(SnmpV3PrivCreds {
                protocol: discovery_core::SnmpPrivProtocol::Aes128,
                passphrase: "privpass123".to_string(),
            }),
        })];
        store.upsert(&config).await.unwrap();

        // Raw row, bypassing the store's own decrypt path entirely.
        let raw_row = discovery_entities::discovery_subnets::Entity::find()
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        let raw_json = raw_row.credentials.unwrap().to_string();
        assert!(
            !raw_json.contains("authpass123"),
            "auth passphrase must not be readable in the raw DB row: {raw_json}"
        );
        assert!(
            !raw_json.contains("privpass123"),
            "priv passphrase must not be readable in the raw DB row: {raw_json}"
        );

        let loaded = store.load_all().await.unwrap();
        assert_eq!(
            loaded[0].subnets[0].credentials, config.subnets[0].credentials,
            "the store must still hand back the original plaintext"
        );
    }

    /// The three `columns` states (see `DiscoveryOidSpec`'s docs) round-trip through the
    /// DB distinctly, same guarantee `profile_store`'s equivalent test proves for
    /// `MetricSpec` — a scalar entry in the same subnet as a table entry must not bleed
    /// into each other.
    #[tokio::test]
    async fn round_trips_a_table_shaped_discovery_oid_distinctly_from_a_scalar() {
        let store = SeaOrmDiscoveryConfigStore::new_in_memory_for_tests().await;
        let mut config = sample_config("office");
        let mut columns = BTreeMap::new();
        columns.insert("ifIndex".to_string(), "1".to_string());
        columns.insert("ifDescr".to_string(), "2".to_string());
        config.subnets[0].oids.insert(
            "if_table".to_string(),
            DiscoveryOidSpec::Detailed {
                oid: "1.3.6.1.2.1.2.2.1".to_string(),
                columns: Some(columns),
            },
        );
        store.upsert(&config).await.unwrap();

        let loaded = store.load_all().await.unwrap();
        let oids = &loaded[0].subnets[0].oids;

        let sys_descr = oids.get("sys_descr").unwrap();
        assert!(
            !sys_descr.is_table(),
            "a plain scalar entry must not pick up a stray columns value"
        );

        let if_table = oids.get("if_table").unwrap();
        assert!(if_table.is_table());
        let loaded_columns = if_table.columns().unwrap();
        assert_eq!(loaded_columns.len(), 2);
        assert_eq!(loaded_columns.get("ifDescr"), Some(&"2".to_string()));
    }

    #[tokio::test]
    async fn upsert_on_an_existing_name_replaces_subnets_not_appends() {
        let store = SeaOrmDiscoveryConfigStore::new_in_memory_for_tests().await;
        store.upsert(&sample_config("office")).await.unwrap();

        let mut second = sample_config("office");
        second.subnets = vec![SubnetSpec {
            ip: "192.168.1.0".into(),
            mask: "255.255.255.0".into(),
            port: 161,
            credentials: vec![SnmpAuth::Community {
                version: SnmpVersion::V1,
                community: "private".into(),
            }],
            oids: BTreeMap::new(),
            labels: BTreeMap::new(),
            snmp_timeout_ms: None,
            snmp_retries: None,
            create_dead_devices: false,
        }];
        store.upsert(&second).await.unwrap();

        let loaded = store.load_all().await.unwrap();
        assert_eq!(
            loaded.len(),
            1,
            "same name — must update in place, not create a second config"
        );
        assert_eq!(
            loaded[0].subnets.len(),
            1,
            "old subnet must be fully replaced, not appended to"
        );
        assert_eq!(loaded[0].subnets[0].ip, "192.168.1.0");
    }

    #[tokio::test]
    async fn delete_cascades_all_the_way_down_to_oids_and_labels() {
        use sea_orm::EntityTrait;

        let store = SeaOrmDiscoveryConfigStore::new_in_memory_for_tests().await;
        store.upsert(&sample_config("office")).await.unwrap();
        assert_eq!(
            discovery_entities::discovery_subnets::Entity::find()
                .all(&store.db)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            discovery_entities::discovery_subnet_oids::Entity::find()
                .all(&store.db)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            discovery_entities::discovery_subnet_labels::Entity::find()
                .all(&store.db)
                .await
                .unwrap()
                .len(),
            1
        );

        store.delete("office").await.unwrap();

        // The real proof this is a DB-enforced `ON DELETE CASCADE` two levels deep actually
        // firing (needs `PRAGMA foreign_keys = ON` on SQLite specifically) — not just
        // `load_all` returning nothing, which it would either way.
        assert!(discovery_entities::discovery_subnets::Entity::find()
            .all(&store.db)
            .await
            .unwrap()
            .is_empty());
        assert!(discovery_entities::discovery_subnet_oids::Entity::find()
            .all(&store.db)
            .await
            .unwrap()
            .is_empty());
        assert!(discovery_entities::discovery_subnet_labels::Entity::find()
            .all(&store.db)
            .await
            .unwrap()
            .is_empty());
    }
}
