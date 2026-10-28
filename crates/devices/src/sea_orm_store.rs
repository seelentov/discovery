use async_trait::async_trait;
use discovery_core::secret::{
    decrypt_auth_secrets, decrypt_ssh_auth_secrets, encrypt_auth_secrets, encrypt_ssh_auth_secrets,
    SecretKey,
};
use discovery_core::{
    Device, DeviceFacts, SnmpAuth, SnmpCredentials, SortDir, SshAuth, SshCredentials,
};
use discovery_entities::{device_metric_settings, devices};
use sea_orm::sea_query::{Expr, Func, LockType, OnConflict};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, Condition, DatabaseConnection, EntityTrait,
    Order, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, TransactionTrait,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    DeviceListPage, DeviceListQuery, DeviceMetricsStore, DeviceSortBy, DeviceStore, ProfileDecision,
};

/// `m.snmp_auth` is `None` for a device that has never negotiated working SNMP
/// credentials yet — same meaning as before this column existed. A `Some` value that
/// fails to parse/decrypt (corrupt JSON, or a `UsmV3` row with no `secret_key`
/// configured — see [`SeaOrmDeviceStore::secret_key`]'s docs) surfaces as a device with no
/// credentials rather than failing the whole read: the next `SnmpPoll` identity cycle
/// renegotiates it, same recovery path as "never had credentials" already has.
fn model_to_device(m: devices::Model, secret_key: Option<&SecretKey>) -> Device {
    let snmp_credentials = m.snmp_auth.as_ref().and_then(|json| {
        let auth: SnmpAuth = serde_json::from_value(json.clone()).ok()?;
        let auth = decrypt_auth_secrets(auth, secret_key).ok()?;
        Some(SnmpCredentials {
            auth,
            port: m.snmp_port as u16,
        })
    });
    // Same "a value that fails to parse/decrypt surfaces as no credentials, not a failed
    // read" contract as `snmp_credentials` above — see its docs. A `UsmV3`-style
    // `KeyRequired` failure here (no `DISCOVERY_SECRET_KEY` configured) is the realistic
    // cause, unlike SNMP where `Community` never needs a key at all.
    let ssh_credentials = m.ssh_auth.as_ref().and_then(|json| {
        let auth: SshAuth = serde_json::from_value(json.clone()).ok()?;
        let auth = decrypt_ssh_auth_secrets(auth, secret_key).ok()?;
        Some(SshCredentials {
            username: m.ssh_username.clone(),
            auth,
            port: m.ssh_port as u16,
            known_host_key: m.ssh_host_key_fingerprint.clone(),
        })
    });
    Device {
        id: m.device_id,
        facts: DeviceFacts { ip: m.ip },
        profile: m.profile,
        discovered_at: m.discovered_at,
        snmp_credentials,
        ping_ok: m.ping_ok,
        ping_checked_at: m.ping_checked_at,
        ping_loss_pct: m.ping_loss_pct,
        snmp_ok: m.snmp_ok,
        snmp_checked_at: m.snmp_checked_at,
        ping_failing_since: m.ping_failing_since,
        enabled: m.enabled,
        ssh_credentials,
    }
}

fn new_device_active_model(
    id: Uuid,
    ip: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> devices::ActiveModel {
    devices::ActiveModel {
        device_id: Set(id),
        ip: Set(ip.to_string()),
        profile: Set(None),
        profile_version: Set(None),
        poll_generation: Set(0),
        snmp_auth: Set(None),
        snmp_port: Set(161),
        ssh_auth: Set(None),
        ssh_username: Set(String::new()),
        ssh_port: Set(discovery_core::default_ssh_port() as i32),
        ssh_host_key_fingerprint: Set(None),
        discovered_at: Set(now),
        updated_at: Set(now),
        ping_ok: Set(None),
        ping_checked_at: Set(None),
        ping_loss_pct: Set(None),
        snmp_ok: Set(None),
        snmp_checked_at: Set(None),
        enabled: Set(true),
        ping_failing_since: Set(None),
        ip_sort_key: Set(discovery_core::ipv4_to_sort_key(ip)),
    }
}

/// The sea-orm-backed implementation of [`DeviceStore`] — see that trait's docs, in
/// particular for why [`Self::delete`]/[`Self::delete_unreachable_since`] hold references
/// to a [`DeviceMetricsStore`] and an `discovery_alerts::AlertStore`: those two domains'
/// `ON DELETE CASCADE` isn't DB-enforceable anymore once they can route to a different
/// physical database than `devices` itself, so this store calls into them explicitly.
pub struct SeaOrmDeviceStore {
    db: DatabaseConnection,
    device_metrics: Arc<dyn DeviceMetricsStore>,
    alerts: Arc<dyn discovery_alerts::AlertStore>,
    /// `None` unless [`Self::with_secret_key`] was called — see that method's docs.
    secret_key: Option<Arc<SecretKey>>,
    /// `None` unless [`Self::with_topology`] was called — same "builder method, not a
    /// constructor parameter" reasoning as `secret_key`: added 2026-09-16 alongside the
    /// rule-based topology mechanism, well after every existing `new`/
    /// `new_in_memory_for_tests` call site in this codebase was written, none of which
    /// exercise topology. `None` simply skips the cross-domain cleanup below (nothing to
    /// clean up — a deployment/test that never configured topology never wrote any).
    topology: Option<Arc<dyn discovery_topology::TopologyStore>>,
}

impl SeaOrmDeviceStore {
    pub fn new(
        db: DatabaseConnection,
        device_metrics: Arc<dyn DeviceMetricsStore>,
        alerts: Arc<dyn discovery_alerts::AlertStore>,
    ) -> Self {
        Self {
            db,
            device_metrics,
            alerts,
            secret_key: None,
            topology: None,
        }
    }

    /// Opts this store into cascading device deletion into `discovery-topology`'s
    /// `topology_device_keys`/`topology_claims` (`TopologyStore::delete_for_device`) — see
    /// this struct's `topology` field docs. Only `discovery-agent`'s real bootstrap wiring
    /// needs to call this.
    pub fn with_topology(mut self, topology: Arc<dyn discovery_topology::TopologyStore>) -> Self {
        self.topology = Some(topology);
        self
    }

    /// Opts this store into encrypting/decrypting `SnmpAuth::UsmV3` passphrases at the
    /// read/write boundary (`discovery_core::secret`) — a builder method, not a
    /// constructor parameter, so every existing `new`/`new_in_memory_for_tests` call site
    /// (none of which exercise SNMPv3) doesn't need to change. Only
    /// `discovery-agent`'s real bootstrap wiring needs to call this. Without it, writing
    /// or reading a `UsmV3` credential fails loudly (`SecretError::KeyRequired`) instead
    /// of silently storing/returning plaintext.
    pub fn with_secret_key(mut self, key: Arc<SecretKey>) -> Self {
        self.secret_key = Some(key);
        self
    }

    /// Convenience for tests — see `discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests`'s
    /// docs for why this exists and why it's async. Shares the *same* in-memory connection
    /// across all three stores (devices/device_metrics/alerts) — in this fixture there's
    /// only one database, so "which physical connection" is moot; production wiring
    /// (`main.rs`'s `build_stores`, via `discovery-db::ConnectionRegistry`) passes whichever
    /// connection each domain actually resolved to, possibly three different ones.
    pub async fn new_in_memory_for_tests() -> Self {
        let db = discovery_migration::connect_in_memory_for_tests().await;
        let device_metrics: Arc<dyn DeviceMetricsStore> =
            Arc::new(crate::SeaOrmDeviceMetricsStore::new(db.clone()));
        let alerts: Arc<dyn discovery_alerts::AlertStore> =
            Arc::new(discovery_alerts::SeaOrmAlertStore::new(db.clone()));
        Self::new(db, device_metrics, alerts)
    }
}

#[async_trait]
impl DeviceStore for SeaOrmDeviceStore {
    async fn resolve(&self, facts: DeviceFacts) -> anyhow::Result<(Uuid, bool)> {
        if let Some(existing) = devices::Entity::find()
            .filter(devices::Column::Ip.eq(facts.ip.clone()))
            .one(&self.db)
            .await?
        {
            let id = existing.device_id;
            let mut am: devices::ActiveModel = existing.into();
            am.updated_at = Set(chrono::Utc::now());
            am.update(&self.db).await?;
            return Ok((id, false));
        }

        // Not found — insert a brand-new device. Two concurrent first-sightings of the
        // same new IP can race here (both pass the `find` above before either commits);
        // resolved by catching the resulting unique-constraint error and falling back to
        // re-reading whichever insert actually won, rather than a Postgres-specific
        // advisory lock (no portable equivalent across MySQL/SQLite).
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        match new_device_active_model(id, &facts.ip, now)
            .insert(&self.db)
            .await
        {
            Ok(model) => Ok((model.device_id, true)),
            Err(insert_err) => match devices::Entity::find()
                .filter(devices::Column::Ip.eq(facts.ip.clone()))
                .one(&self.db)
                .await?
            {
                Some(winner) => Ok((winner.device_id, false)),
                None => Err(insert_err.into()),
            },
        }
    }

    async fn apply_profile_if_changed(
        &self,
        id: Uuid,
        new_profile: &str,
        new_profile_version: &str,
    ) -> anyhow::Result<Option<ProfileDecision>> {
        let txn = self.db.begin().await?;
        let Some(existing) = devices::Entity::find_by_id(id)
            .lock(LockType::Update)
            .one(&txn)
            .await?
        else {
            txn.commit().await?;
            return Ok(None);
        };

        let unchanged = existing.profile.as_deref() == Some(new_profile)
            && existing.profile_version.as_deref() == Some(new_profile_version);
        if unchanged {
            let generation = existing.poll_generation as u64;
            txn.commit().await?;
            return Ok(Some(ProfileDecision::Unchanged { generation }));
        }

        let new_generation = existing.poll_generation + 1;
        let mut am: devices::ActiveModel = existing.into();
        am.profile = Set(Some(new_profile.to_string()));
        am.profile_version = Set(Some(new_profile_version.to_string()));
        am.poll_generation = Set(new_generation);
        am.updated_at = Set(chrono::Utc::now());
        am.update(&txn).await?;
        txn.commit().await?;
        Ok(Some(ProfileDecision::Changed {
            generation: new_generation as u64,
        }))
    }

    async fn current_poll_generation(&self, id: Uuid) -> anyhow::Result<Option<u64>> {
        Ok(devices::Entity::find_by_id(id)
            .one(&self.db)
            .await?
            .map(|m| m.poll_generation as u64))
    }

    async fn set_snmp_credentials(
        &self,
        id: Uuid,
        credentials: SnmpCredentials,
    ) -> anyhow::Result<()> {
        let auth = encrypt_auth_secrets(credentials.auth, self.secret_key.as_deref())?;
        let auth_json = serde_json::to_value(&auth)?;
        devices::Entity::update_many()
            .filter(devices::Column::DeviceId.eq(id))
            .col_expr(devices::Column::SnmpAuth, Expr::value(auth_json))
            .col_expr(
                devices::Column::SnmpPort,
                Expr::value(credentials.port as i32),
            )
            .col_expr(devices::Column::UpdatedAt, Expr::value(chrono::Utc::now()))
            .exec(&self.db)
            .await?;
        Ok(())
    }

    async fn set_ssh_credentials(
        &self,
        id: Uuid,
        credentials: SshCredentials,
    ) -> anyhow::Result<()> {
        let auth = encrypt_ssh_auth_secrets(credentials.auth, self.secret_key.as_deref())?;
        let auth_json = serde_json::to_value(&auth)?;
        // `known_host_key` is always whatever the caller passed — the manual `PUT`
        // endpoint never populates it (see `discovery_core::SshCredentials::known_host_key`'s
        // docs), so a credentials update always resets this device's pin back to `NULL`
        // and the next successful connection re-learns it via trust-on-first-use.
        devices::Entity::update_many()
            .filter(devices::Column::DeviceId.eq(id))
            .col_expr(devices::Column::SshAuth, Expr::value(auth_json))
            .col_expr(
                devices::Column::SshUsername,
                Expr::value(credentials.username),
            )
            .col_expr(
                devices::Column::SshPort,
                Expr::value(credentials.port as i32),
            )
            .col_expr(
                devices::Column::SshHostKeyFingerprint,
                Expr::value(credentials.known_host_key),
            )
            .col_expr(devices::Column::UpdatedAt, Expr::value(chrono::Utc::now()))
            .exec(&self.db)
            .await?;
        Ok(())
    }

    async fn pin_ssh_host_key(&self, id: Uuid, fingerprint: String) -> anyhow::Result<()> {
        devices::Entity::update_many()
            .filter(devices::Column::DeviceId.eq(id))
            .filter(devices::Column::SshHostKeyFingerprint.is_null())
            .col_expr(
                devices::Column::SshHostKeyFingerprint,
                Expr::value(fingerprint),
            )
            .exec(&self.db)
            .await?;
        Ok(())
    }

    async fn set_reachability(
        &self,
        id: Uuid,
        ping_ok: bool,
        ping_loss_pct: f64,
        snmp_ok: bool,
    ) -> anyhow::Result<()> {
        let txn = self.db.begin().await?;
        let Some(existing) = devices::Entity::find_by_id(id)
            .lock(LockType::Update)
            .one(&txn)
            .await?
        else {
            txn.commit().await?;
            return Ok(());
        };

        let now = chrono::Utc::now();
        // Three-way transition, computed against the row's *current* ping_ok — see
        // `DeviceStore::set_reachability`'s docs for the exact cases.
        let ping_failing_since = if !ping_ok {
            if existing.ping_ok != Some(false) {
                Some(now)
            } else {
                existing.ping_failing_since
            }
        } else {
            None
        };

        let mut am: devices::ActiveModel = existing.into();
        am.ping_ok = Set(Some(ping_ok));
        am.ping_checked_at = Set(Some(now));
        am.ping_loss_pct = Set(Some(ping_loss_pct));
        am.snmp_ok = Set(Some(snmp_ok));
        am.snmp_checked_at = Set(Some(now));
        am.ping_failing_since = Set(ping_failing_since);
        am.update(&txn).await?;
        txn.commit().await?;
        Ok(())
    }

    async fn delete_unreachable_since(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<Vec<(Uuid, String)>> {
        let matching = devices::Entity::find()
            .filter(devices::Column::Enabled.eq(true))
            .filter(devices::Column::PingFailingSince.is_not_null())
            .filter(devices::Column::PingFailingSince.lte(cutoff))
            .all(&self.db)
            .await?;
        if matching.is_empty() {
            return Ok(vec![]);
        }
        let deleted: Vec<(Uuid, String)> =
            matching.into_iter().map(|m| (m.device_id, m.ip)).collect();
        let ids: Vec<Uuid> = deleted.iter().map(|(id, _)| *id).collect();
        // One statement for the `devices` row itself (found on the 2026-08-21 scale
        // audit: this used to be N sequential `DeviceStore::delete` calls, each its own
        // `DELETE ... WHERE device_id = ?` round trip — the exact "not in a loop" principle
        // `set_enabled_all`'s docs, a few methods up in this same file, already state).
        // The cross-domain cascade below still has to stay per-id: `device_metrics`/
        // `alerts` only expose a single-device `delete_for_device`, and giving them a
        // batch variant too (including their Cassandra-backed implementations) was judged
        // disproportionate to what this specific finding needed — the `devices` table
        // delete was the part actually flagged as N sequential round trips.
        devices::Entity::delete_many()
            .filter(devices::Column::DeviceId.is_in(ids.clone()))
            .exec(&self.db)
            .await?;
        for id in &ids {
            self.device_metrics.delete_for_device(*id).await?;
            self.alerts.delete_for_device(*id).await?;
            if let Some(topology) = &self.topology {
                topology.delete_for_device(*id).await?;
            }
        }
        Ok(deleted)
    }

    async fn set_enabled(&self, id: Uuid, enabled: bool) -> anyhow::Result<()> {
        devices::Entity::update_many()
            .filter(devices::Column::DeviceId.eq(id))
            .col_expr(devices::Column::Enabled, Expr::value(enabled))
            .col_expr(devices::Column::UpdatedAt, Expr::value(chrono::Utc::now()))
            .exec(&self.db)
            .await?;
        Ok(())
    }

    async fn set_enabled_all(&self, enabled: bool) -> anyhow::Result<u64> {
        let result = devices::Entity::update_many()
            .col_expr(devices::Column::Enabled, Expr::value(enabled))
            .col_expr(devices::Column::UpdatedAt, Expr::value(chrono::Utc::now()))
            .exec(&self.db)
            .await?;
        Ok(result.rows_affected)
    }

    async fn set_enabled_for_ids(&self, ids: &[Uuid], enabled: bool) -> anyhow::Result<u64> {
        if ids.is_empty() {
            return Ok(0);
        }
        let result = devices::Entity::update_many()
            .filter(devices::Column::DeviceId.is_in(ids.iter().copied()))
            .col_expr(devices::Column::Enabled, Expr::value(enabled))
            .col_expr(devices::Column::UpdatedAt, Expr::value(chrono::Utc::now()))
            .exec(&self.db)
            .await?;
        Ok(result.rows_affected)
    }

    async fn get_metric_overrides(&self, id: Uuid) -> anyhow::Result<BTreeMap<String, bool>> {
        let rows = device_metric_settings::Entity::find()
            .filter(device_metric_settings::Column::DeviceId.eq(id))
            .all(&self.db)
            .await?;
        Ok(rows.into_iter().map(|r| (r.name, r.enabled)).collect())
    }

    async fn get_metric_overrides_for_many(
        &self,
        ids: &[Uuid],
    ) -> anyhow::Result<BTreeMap<Uuid, BTreeMap<String, bool>>> {
        if ids.is_empty() {
            return Ok(BTreeMap::new());
        }
        let rows = device_metric_settings::Entity::find()
            .filter(device_metric_settings::Column::DeviceId.is_in(ids.to_vec()))
            .all(&self.db)
            .await?;
        let mut out: BTreeMap<Uuid, BTreeMap<String, bool>> = BTreeMap::new();
        for row in rows {
            out.entry(row.device_id)
                .or_default()
                .insert(row.name, row.enabled);
        }
        Ok(out)
    }

    async fn set_metric_override(&self, id: Uuid, name: &str, enabled: bool) -> anyhow::Result<()> {
        let am = device_metric_settings::ActiveModel {
            device_id: Set(id),
            name: Set(name.to_string()),
            enabled: Set(enabled),
        };
        device_metric_settings::Entity::insert(am)
            .on_conflict(
                OnConflict::columns([
                    device_metric_settings::Column::DeviceId,
                    device_metric_settings::Column::Name,
                ])
                .update_column(device_metric_settings::Column::Enabled)
                .to_owned(),
            )
            .exec(&self.db)
            .await?;
        Ok(())
    }

    async fn clear_metric_override(&self, id: Uuid, name: &str) -> anyhow::Result<()> {
        device_metric_settings::Entity::delete_many()
            .filter(device_metric_settings::Column::DeviceId.eq(id))
            .filter(device_metric_settings::Column::Name.eq(name))
            .exec(&self.db)
            .await?;
        Ok(())
    }

    async fn clear_metric_overrides(&self, id: Uuid, names: &[String]) -> anyhow::Result<()> {
        if names.is_empty() {
            return Ok(());
        }
        device_metric_settings::Entity::delete_many()
            .filter(device_metric_settings::Column::DeviceId.eq(id))
            .filter(device_metric_settings::Column::Name.is_in(names.to_vec()))
            .exec(&self.db)
            .await?;
        Ok(())
    }

    async fn clear_metric_overrides_for_devices(
        &self,
        ids: &[Uuid],
        names: &[String],
    ) -> anyhow::Result<()> {
        if ids.is_empty() || names.is_empty() {
            return Ok(());
        }
        device_metric_settings::Entity::delete_many()
            .filter(device_metric_settings::Column::DeviceId.is_in(ids.to_vec()))
            .filter(device_metric_settings::Column::Name.is_in(names.to_vec()))
            .exec(&self.db)
            .await?;
        Ok(())
    }

    async fn prune_metric_overrides(&self, id: Uuid, keep: &[String]) -> anyhow::Result<()> {
        let mut query = device_metric_settings::Entity::delete_many()
            .filter(device_metric_settings::Column::DeviceId.eq(id));
        if !keep.is_empty() {
            query = query.filter(device_metric_settings::Column::Name.is_not_in(keep.to_vec()));
        }
        query.exec(&self.db).await?;
        Ok(())
    }

    async fn delete(&self, id: Uuid) -> anyhow::Result<()> {
        // Same-domain cascade (device_metric_settings, real ON DELETE CASCADE) happens for
        // free; the other two domains need an explicit call — see this store's docs.
        devices::Entity::delete_by_id(id).exec(&self.db).await?;
        self.device_metrics.delete_for_device(id).await?;
        self.alerts.delete_for_device(id).await?;
        if let Some(topology) = &self.topology {
            topology.delete_for_device(id).await?;
        }
        Ok(())
    }

    async fn get_device(&self, id: Uuid) -> anyhow::Result<Option<Device>> {
        Ok(devices::Entity::find_by_id(id)
            .one(&self.db)
            .await?
            .map(|m| model_to_device(m, self.secret_key.as_deref())))
    }

    async fn id_by_ip(&self, ip: &str) -> anyhow::Result<Option<Uuid>> {
        Ok(devices::Entity::find()
            .filter(devices::Column::Ip.eq(ip))
            .one(&self.db)
            .await?
            .map(|m| m.device_id))
    }

    async fn all(&self) -> anyhow::Result<Vec<Device>> {
        Ok(devices::Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(|m| model_to_device(m, self.secret_key.as_deref()))
            .collect())
    }

    async fn list_devices(&self, query: &DeviceListQuery) -> anyhow::Result<DeviceListPage> {
        let mut cond = Condition::all();
        if let Some(profile) = query.profile.as_deref().filter(|s| !s.is_empty()) {
            cond = cond.add(devices::Column::Profile.eq(profile));
        }
        // Not escaping literal `%`/`_` in `search` on purpose — same call
        // `discovery_queue::SeaOrmJobQueueStore::list_jobs`'s docs make: a dashboard search
        // box, not a security boundary.
        if let Some(search) = query
            .search
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let needle = format!("%{}%", search.to_lowercase());
            cond = cond.add(
                Condition::any()
                    .add(
                        Expr::expr(Func::lower(Expr::col(devices::Column::Ip)))
                            .like(needle.clone()),
                    )
                    .add(
                        Expr::expr(Func::lower(Func::coalesce([
                            Expr::col(devices::Column::Profile).into(),
                            Expr::val("").into(),
                        ])))
                        .like(needle),
                    ),
            );
        }

        let total = devices::Entity::find()
            .filter(cond.clone())
            .count(&self.db)
            .await? as i64;

        // `Ip` sorts by the precomputed `ip_sort_key` (see `discovery_core::ipv4_to_sort_key`'s
        // docs), not the `ip` text column itself — a plain string `ORDER BY` would put
        // "10.0.0.10" before "10.0.0.2".
        let sort_column = match query.sort_by {
            Some(DeviceSortBy::Profile) => devices::Column::Profile,
            Some(DeviceSortBy::DiscoveredAt) => devices::Column::DiscoveredAt,
            _ => devices::Column::IpSortKey,
        };
        let order = if query.sort_dir == Some(SortDir::Desc) {
            Order::Desc
        } else {
            Order::Asc
        };

        let models = devices::Entity::find()
            .filter(cond)
            .order_by(sort_column, order)
            .order_by(devices::Column::DeviceId, Order::Asc) // stable tiebreaker, same convention as every other list() in this project
            .limit(query.limit.max(0) as u64)
            .offset(query.offset.max(0) as u64)
            .all(&self.db)
            .await?;

        Ok(DeviceListPage {
            items: models
                .into_iter()
                .map(|m| model_to_device(m, self.secret_key.as_deref()))
                .collect(),
            total,
        })
    }

    async fn device_ids_by_profile(&self, profile_name: &str) -> anyhow::Result<Vec<Uuid>> {
        use sea_orm::QuerySelect;
        Ok(devices::Entity::find()
            .filter(devices::Column::Profile.eq(profile_name))
            .select_only()
            .column(devices::Column::DeviceId)
            .into_tuple::<Uuid>()
            .all(&self.db)
            .await?)
    }

    async fn count(&self) -> anyhow::Result<u64> {
        Ok(devices::Entity::find().count(&self.db).await?)
    }
}
