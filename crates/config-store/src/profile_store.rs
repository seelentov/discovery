use async_trait::async_trait;
use discovery_dsl::ProfileFile;

/// Where the active profile set lives. One implementation — [`SeaOrmProfileStore`], works
/// against Postgres/MySQL/SQLite (and, for tests/zero-config, `sqlite::memory:`) through
/// the same sea-orm entity/query code path (2026-08-18 multi-DB rewrite, replacing the old
/// `PostgresProfileStore`/`SqliteProfileStore`/`InMemoryProfileStore` trio — see
/// `discovery_config_store::SeaOrmSettingsStore`'s docs for the full rationale). Profiles
/// are rows in `profiles` (`discovery_entities::profiles`), each profile's `[metrics.poll]`
/// list a real, DB-enforced FK/cascade child table (`profile_metrics`), its trap bindings
/// another (`profile_traps`, 2026-08-30), its syslog bindings another (`profile_syslog`,
/// 2026-09-06), its service checks another (`profile_service_checks`, 2026-09-07), its
/// alert list another (`profile_alerts`) — same-domain references, safe to keep as real
/// `ON DELETE CASCADE` FKs (unlike the device-related cross-domain tables) because
/// "Профили" is a single routing domain, so every child table always shares one physical
/// connection with their parent by construction.
///
/// **No file-backed store anymore.** Profiles used to also be loadable from
/// `profiles/*.toml` (`FileProfileStore`) as a one-time seed source into the DB backends.
/// Removed entirely, same date, same request: "убери в целом логику которая подгружает
/// сиды из файлов" — this project's stores are all directly writable now (via the
/// dashboard/API or a direct `INSERT`), so a file-loading path serves no purpose anymore.
#[async_trait]
pub trait ProfileStore: Send + Sync {
    /// Loads the full active profile set. Called at startup and on every hot-reload tick
    /// (`discovery_agent::profile_reload`).
    async fn load_all(&self) -> anyhow::Result<Vec<ProfileFile>>;

    /// Inserts a new profile or replaces the existing one with the same name.
    async fn upsert(&self, profile: &ProfileFile) -> anyhow::Result<()>;

    async fn delete(&self, name: &str) -> anyhow::Result<()>;
}

/// The sea-orm-backed implementation — see [`ProfileStore`]'s docs.
pub struct SeaOrmProfileStore {
    db: sea_orm::DatabaseConnection,
}

impl SeaOrmProfileStore {
    pub fn new(db: sea_orm::DatabaseConnection) -> Self {
        Self { db }
    }

    /// Convenience for tests — see `SeaOrmSettingsStore::new_in_memory_for_tests`'s docs
    /// for why this exists and why it's async. `discovery_migration::connect_in_memory_for_tests`
    /// (not a hand-rolled connect+migrate here) also turns on `PRAGMA foreign_keys = ON` —
    /// load-bearing for this store specifically, since `delete()` relies entirely on
    /// `profile_metrics`/`profile_alerts`' `ON DELETE CASCADE` to clean up, unlike every
    /// other store rewritten so far.
    pub async fn new_in_memory_for_tests() -> Self {
        Self::new(discovery_migration::connect_in_memory_for_tests().await)
    }
}

mod queries {
    use discovery_dsl::{
        compute_version, AlertRule, MatchSection, MetricSpec, MetricsSection, ProfileFile,
        ProfileMeta, ServiceChecksSection, SyslogSection, SyslogSpec, TrapSpec, TrapsSection,
    };
    use discovery_entities::{
        profile_alerts, profile_metrics, profile_service_checks, profile_syslog, profile_traps,
        profiles,
    };
    use sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseConnection,
        DbErr, EntityTrait, QueryFilter, TransactionTrait,
    };
    use std::collections::BTreeMap;

    pub async fn load_all(db: &DatabaseConnection) -> anyhow::Result<Vec<ProfileFile>> {
        let profile_rows = profiles::Entity::find().all(db).await?;
        let metric_rows = profile_metrics::Entity::find().all(db).await?;
        let trap_rows = profile_traps::Entity::find().all(db).await?;
        let syslog_rows = profile_syslog::Entity::find().all(db).await?;
        let service_check_rows = profile_service_checks::Entity::find().all(db).await?;
        let alert_rows = profile_alerts::Entity::find().all(db).await?;

        let mut metrics_by_profile: BTreeMap<String, BTreeMap<String, MetricSpec>> =
            BTreeMap::new();
        for row in metric_rows {
            let schedule = row.schedule.map(serde_json::from_value).transpose()?;
            // `command` is `Some` iff this row is an SSH CLI-pull metric
            // (`MetricSpec::SshCommand`) — see `discovery_entities::profile_metrics`'s
            // `Command` field docs. Checked first since it fully determines which variant
            // to reconstruct; `row.oid`/`row.columns`/`row.derive` are simply unused (always
            // `""`/`NULL`/`NULL` respectively) on an `SshCommand` row.
            let spec = match row.command {
                Some(command) => MetricSpec::SshCommand {
                    command,
                    schedule,
                    history_retention_secs: row.history_retention_secs.map(|s| s as u64),
                    enabled: row.enabled,
                    history_keep_last_success: row.history_keep_last_success,
                    history_keep_last_attempt: row.history_keep_last_attempt,
                },
                None => {
                    let columns = row.columns.map(serde_json::from_value).transpose()?;
                    let derive = row.derive.map(serde_json::from_value).transpose()?;
                    MetricSpec::Detailed {
                        oid: row.oid,
                        columns,
                        schedule,
                        history_retention_secs: row.history_retention_secs.map(|s| s as u64),
                        enabled: row.enabled,
                        history_keep_last_success: row.history_keep_last_success,
                        history_keep_last_attempt: row.history_keep_last_attempt,
                        derive,
                    }
                }
            };
            metrics_by_profile
                .entry(row.profile_name)
                .or_default()
                .insert(row.name, spec);
        }

        let mut traps_by_profile: BTreeMap<String, TrapsSection> = BTreeMap::new();
        for row in trap_rows {
            let variants = serde_json::from_value(row.variants)?;
            traps_by_profile
                .entry(row.profile_name)
                .or_default()
                .bindings
                .insert(
                    row.name,
                    TrapSpec {
                        variants,
                        ttl_secs: row.ttl_secs.map(|s| s as u64),
                        history_retention_secs: row.history_retention_secs.map(|s| s as u64),
                    },
                );
        }

        let mut syslog_by_profile: BTreeMap<String, SyslogSection> = BTreeMap::new();
        for row in syslog_rows {
            let variants = serde_json::from_value(row.variants)?;
            syslog_by_profile
                .entry(row.profile_name)
                .or_default()
                .bindings
                .insert(
                    row.name,
                    SyslogSpec {
                        variants,
                        ttl_secs: row.ttl_secs.map(|s| s as u64),
                        history_retention_secs: row.history_retention_secs.map(|s| s as u64),
                    },
                );
        }

        // One row per profile (not per check, see `discovery_entities::profile_service_checks`'s
        // docs) — a plain map to the whole deserialized section, not a nested insert like
        // the three maps above.
        let mut service_checks_by_profile: BTreeMap<String, ServiceChecksSection> = BTreeMap::new();
        for row in service_check_rows {
            let checks = serde_json::from_value(row.checks)?;
            let schedule = row.schedule.map(serde_json::from_value).transpose()?;
            service_checks_by_profile.insert(
                row.profile_name,
                ServiceChecksSection {
                    checks,
                    schedule,
                    history_retention_secs: row.history_retention_secs.map(|s| s as u64),
                },
            );
        }

        let mut alerts_by_profile: BTreeMap<String, Vec<AlertRule>> = BTreeMap::new();
        for row in alert_rows {
            alerts_by_profile
                .entry(row.profile_name)
                .or_default()
                .push(AlertRule {
                    policy: row
                        .policy
                        .map(serde_json::from_value)
                        .transpose()
                        .map_err(|e| DbErr::Custom(e.to_string()))?
                        .unwrap_or_default(),
                    name: row.name,
                    level: row.level,
                    row_metric: row.row_metric,
                    row_key_expression: row.row_key_expression,
                    expression: row.expression,
                    deactivation_expression: row.deactivation_expression,
                    facts_expression: row.facts_expression,
                    message: row.message,
                    clear_after_seconds: row.clear_after_seconds.map(|s| s as u64),
                    activate_after_seconds: row.activate_after_seconds.map(|s| s as u64),
                    flap_window_seconds: row.flap_window_seconds.map(|s| s as u64),
                    flap_threshold: row.flap_threshold.map(|s| s as u32),
                    enabled: row.enabled,
                });
        }

        Ok(profile_rows
            .into_iter()
            .map(|row| {
                let metrics_poll = metrics_by_profile
                    .get(&row.name)
                    .cloned()
                    .unwrap_or_default();
                let traps = traps_by_profile.get(&row.name).cloned().unwrap_or_default();
                let syslog = syslog_by_profile
                    .get(&row.name)
                    .cloned()
                    .unwrap_or_default();
                let service_checks = service_checks_by_profile
                    .get(&row.name)
                    .cloned()
                    .unwrap_or_default();
                let alerts = alerts_by_profile
                    .get(&row.name)
                    .cloned()
                    .unwrap_or_default();
                let version = compute_version(
                    &row.match_expression,
                    &metrics_poll,
                    &traps,
                    &syslog,
                    &service_checks,
                    &alerts,
                );
                ProfileFile {
                    profile: ProfileMeta {
                        name: row.name,
                        priority: row.priority,
                    },
                    match_expr: MatchSection {
                        expression: row.match_expression,
                    },
                    metrics: MetricsSection { poll: metrics_poll },
                    traps,
                    syslog,
                    service_checks,
                    alerts,
                    version,
                }
            })
            .collect())
    }

    /// Delete-then-reinsert the whole child set, same strategy the pre-2026-08-18
    /// hand-written backends used — a profile's metric/alert lists are small and rewritten
    /// as a whole on every save, no need for row-level diffing.
    async fn replace_metrics<C: ConnectionTrait>(
        txn: &C,
        profile_name: &str,
        metrics_poll: &BTreeMap<String, MetricSpec>,
    ) -> Result<(), DbErr> {
        profile_metrics::Entity::delete_many()
            .filter(profile_metrics::Column::ProfileName.eq(profile_name))
            .exec(txn)
            .await?;
        for (name, spec) in metrics_poll {
            let schedule = spec
                .schedule()
                .map(|s| serde_json::to_value(s).expect("Schedule always serializes"));
            let columns = spec
                .columns()
                .map(|c| serde_json::to_value(c).expect("a column map always serializes"));
            let derive = spec
                .derive()
                .map(|d| serde_json::to_value(d).expect("DeriveKind always serializes"));
            let am = profile_metrics::ActiveModel {
                profile_name: Set(profile_name.to_string()),
                name: Set(name.clone()),
                oid: Set(spec.oid().to_string()),
                columns: Set(columns),
                command: Set(spec.command().map(|c| c.to_string())),
                history_retention_secs: Set(spec.history_retention_secs().map(|s| s as i64)),
                schedule: Set(schedule),
                enabled: Set(spec.enabled()),
                history_keep_last_success: Set(spec.history_keep_last_success()),
                history_keep_last_attempt: Set(spec.history_keep_last_attempt()),
                derive: Set(derive),
            };
            am.insert(txn).await?;
        }
        Ok(())
    }

    async fn replace_traps<C: ConnectionTrait>(
        txn: &C,
        profile_name: &str,
        traps: &TrapsSection,
    ) -> Result<(), DbErr> {
        profile_traps::Entity::delete_many()
            .filter(profile_traps::Column::ProfileName.eq(profile_name))
            .exec(txn)
            .await?;
        for (name, spec) in &traps.bindings {
            let am = profile_traps::ActiveModel {
                profile_name: Set(profile_name.to_string()),
                name: Set(name.clone()),
                variants: Set(serde_json::to_value(&spec.variants)
                    .expect("Vec<TrapEventSpec> always serializes")),
                ttl_secs: Set(spec.ttl_secs.map(|s| s as i64)),
                history_retention_secs: Set(spec.history_retention_secs.map(|s| s as i64)),
            };
            am.insert(txn).await?;
        }
        Ok(())
    }

    async fn replace_syslog<C: ConnectionTrait>(
        txn: &C,
        profile_name: &str,
        syslog: &SyslogSection,
    ) -> Result<(), DbErr> {
        profile_syslog::Entity::delete_many()
            .filter(profile_syslog::Column::ProfileName.eq(profile_name))
            .exec(txn)
            .await?;
        for (name, spec) in &syslog.bindings {
            let am = profile_syslog::ActiveModel {
                profile_name: Set(profile_name.to_string()),
                name: Set(name.clone()),
                variants: Set(serde_json::to_value(&spec.variants)
                    .expect("Vec<SyslogEventSpec> always serializes")),
                ttl_secs: Set(spec.ttl_secs.map(|s| s as i64)),
                history_retention_secs: Set(spec.history_retention_secs.map(|s| s as i64)),
            };
            am.insert(txn).await?;
        }
        Ok(())
    }

    /// Delete-then-reinsert, same strategy as `replace_metrics`/`replace_traps`/
    /// `replace_syslog` — but at most **one** row per profile (see
    /// `discovery_entities::profile_service_checks`'s docs), not one per named entry.
    /// `checks` being empty is a perfectly normal state (a profile that just doesn't
    /// declare any) — no row gets inserted at all in that case, so `load_all`'s
    /// `unwrap_or_default()` correctly falls back to an empty `ServiceChecksSection`.
    async fn replace_service_checks<C: ConnectionTrait>(
        txn: &C,
        profile_name: &str,
        service_checks: &discovery_dsl::ServiceChecksSection,
    ) -> Result<(), DbErr> {
        profile_service_checks::Entity::delete_many()
            .filter(profile_service_checks::Column::ProfileName.eq(profile_name))
            .exec(txn)
            .await?;
        if service_checks.checks.is_empty()
            && service_checks.schedule.is_none()
            && service_checks.history_retention_secs.is_none()
        {
            return Ok(());
        }
        let checks = serde_json::to_value(&service_checks.checks)
            .expect("Vec<ServiceCheckSpec> always serializes");
        let schedule = service_checks
            .schedule
            .as_ref()
            .map(|s| serde_json::to_value(s).expect("Schedule always serializes"));
        let am = profile_service_checks::ActiveModel {
            profile_name: Set(profile_name.to_string()),
            checks: Set(checks),
            schedule: Set(schedule),
            history_retention_secs: Set(service_checks.history_retention_secs.map(|s| s as i64)),
        };
        am.insert(txn).await?;
        Ok(())
    }

    async fn replace_alerts<C: ConnectionTrait>(
        txn: &C,
        profile_name: &str,
        alerts: &[AlertRule],
    ) -> Result<(), DbErr> {
        profile_alerts::Entity::delete_many()
            .filter(profile_alerts::Column::ProfileName.eq(profile_name))
            .exec(txn)
            .await?;
        for alert in alerts {
            let am = profile_alerts::ActiveModel {
                policy: Set(Some(
                    serde_json::to_value(&alert.policy)
                        .map_err(|e| DbErr::Custom(e.to_string()))?,
                )),
                profile_name: Set(profile_name.to_string()),
                name: Set(alert.name.clone()),
                level: Set(alert.level.clone()),
                row_metric: Set(alert.row_metric.clone()),
                row_key_expression: Set(alert.row_key_expression.clone()),
                expression: Set(alert.expression.clone()),
                deactivation_expression: Set(alert.deactivation_expression.clone()),
                facts_expression: Set(alert.facts_expression.clone()),
                message: Set(alert.message.clone()),
                clear_after_seconds: Set(alert.clear_after_seconds.map(|s| s as i64)),
                activate_after_seconds: Set(alert.activate_after_seconds.map(|s| s as i64)),
                flap_window_seconds: Set(alert.flap_window_seconds.map(|s| s as i64)),
                flap_threshold: Set(alert.flap_threshold.map(|s| s as i64)),
                enabled: Set(alert.enabled),
            };
            am.insert(txn).await?;
        }
        Ok(())
    }

    pub async fn upsert(db: &DatabaseConnection, profile: &ProfileFile) -> anyhow::Result<()> {
        use sea_orm::sea_query::OnConflict;

        let txn = db.begin().await?;
        let now = chrono::Utc::now();
        let am = profiles::ActiveModel {
            name: Set(profile.profile.name.clone()),
            priority: Set(profile.profile.priority),
            match_expression: Set(profile.match_expr.expression.clone()),
            created_at: Set(now),
            updated_at: Set(now),
        };
        profiles::Entity::insert(am)
            .on_conflict(
                OnConflict::column(profiles::Column::Name)
                    .update_columns([
                        profiles::Column::Priority,
                        profiles::Column::MatchExpression,
                        profiles::Column::UpdatedAt,
                    ])
                    .to_owned(),
            )
            .exec(&txn)
            .await?;
        replace_metrics(&txn, &profile.profile.name, &profile.metrics.poll).await?;
        replace_traps(&txn, &profile.profile.name, &profile.traps).await?;
        replace_syslog(&txn, &profile.profile.name, &profile.syslog).await?;
        replace_service_checks(&txn, &profile.profile.name, &profile.service_checks).await?;
        replace_alerts(&txn, &profile.profile.name, &profile.alerts).await?;
        txn.commit().await?;
        Ok(())
    }

    pub async fn delete(db: &DatabaseConnection, name: &str) -> anyhow::Result<()> {
        // `ON DELETE CASCADE` on profile_metrics.profile_name/profile_alerts.profile_name
        // cleans up the metric/alert lists automatically — no dead rows left behind. Needs
        // `PRAGMA foreign_keys = ON` on SQLite specifically, see this module's docs.
        profiles::Entity::delete_by_id(name.to_string())
            .exec(db)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl ProfileStore for SeaOrmProfileStore {
    async fn load_all(&self) -> anyhow::Result<Vec<ProfileFile>> {
        queries::load_all(&self.db).await
    }

    async fn upsert(&self, profile: &ProfileFile) -> anyhow::Result<()> {
        queries::upsert(&self.db, profile).await
    }

    async fn delete(&self, name: &str) -> anyhow::Result<()> {
        queries::delete(&self.db, name).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use discovery_dsl::{AlertRule, MatchSection, MetricSpec, MetricsSection, ProfileMeta};
    use std::collections::BTreeMap;

    fn a_profile(name: &str) -> ProfileFile {
        let mut poll = BTreeMap::new();
        poll.insert("cpu".to_string(), MetricSpec::Oid("1.2.3".to_string()));
        ProfileFile {
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            profile: ProfileMeta {
                name: name.to_string(),
                priority: 5,
            },
            match_expr: MatchSection {
                expression: "true".into(),
            },
            metrics: MetricsSection { poll },
            alerts: vec![AlertRule {
                policy: Default::default(),
                name: "high_cpu".into(),
                level: "warning".into(),
                row_metric: None,
                row_key_expression: None,
                expression: "metrics.cpu > 90".into(),
                deactivation_expression: None,
                facts_expression: None,
                message: "cpu high".into(),
                clear_after_seconds: Some(60),
                activate_after_seconds: Some(30),
                flap_window_seconds: Some(300),
                flap_threshold: Some(4),
                enabled: true,
            }],
            version: "ignored-on-write".into(),
        }
    }

    #[tokio::test]
    async fn round_trips_upsert_and_delete_including_metrics_and_alerts() {
        let store = SeaOrmProfileStore::new_in_memory_for_tests().await;
        store.upsert(&a_profile("a")).await.unwrap();

        let loaded = store.load_all().await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].profile.name, "a");
        assert_eq!(loaded[0].profile.priority, 5);
        assert_eq!(loaded[0].metrics.poll.get("cpu").unwrap().oid(), "1.2.3");
        assert_eq!(loaded[0].alerts.len(), 1);
        assert_eq!(loaded[0].alerts[0].name, "high_cpu");
        assert_eq!(loaded[0].alerts[0].activate_after_seconds, Some(30));
        assert_eq!(loaded[0].alerts[0].flap_window_seconds, Some(300));
        assert_eq!(loaded[0].alerts[0].flap_threshold, Some(4));

        store.delete("a").await.unwrap();
        assert!(store.load_all().await.unwrap().is_empty());
    }

    /// SNMP Trap ingestion (2026-08-30) — `traps.bindings` must round-trip through the DB
    /// including the multi-variant list and both optional `ttl_secs`/
    /// `history_retention_secs`, and an `upsert` on the same profile name must fully
    /// replace the trap set (not append), same contract `replace_metrics`/`replace_alerts`
    /// already give.
    #[tokio::test]
    async fn round_trips_trap_bindings_and_replaces_on_upsert() {
        use discovery_dsl::{TrapEventSpec, TrapSpec, TrapsSection};

        let store = SeaOrmProfileStore::new_in_memory_for_tests().await;
        let mut profile = a_profile("with_traps");
        let mut varbinds = BTreeMap::new();
        varbinds.insert("if_index".to_string(), "1.3.6.1.2.1.2.2.1.1".to_string());
        varbinds.insert(
            "if_oper_status".to_string(),
            "1.3.6.1.2.1.2.2.1.8".to_string(),
        );
        profile.traps.bindings.insert(
            "port_link_state".to_string(),
            TrapSpec {
                variants: vec![
                    TrapEventSpec {
                        trap_oid: "1.3.6.1.6.3.1.1.5.3".into(),
                        varbinds: varbinds.clone(),
                        key_expression: Some("varbinds.if_index".into()),
                    },
                    TrapEventSpec {
                        trap_oid: "1.3.6.1.6.3.1.1.5.4".into(),
                        varbinds,
                        key_expression: Some("varbinds.if_index".into()),
                    },
                ],
                ttl_secs: Some(3600),
                history_retention_secs: Some(604800),
            },
        );
        store.upsert(&profile).await.unwrap();

        let loaded = store.load_all().await.unwrap();
        assert_eq!(loaded.len(), 1);
        let traps = &loaded[0].traps;
        assert_eq!(traps.bindings.len(), 1);
        let spec = traps.bindings.get("port_link_state").unwrap();
        assert_eq!(spec.variants.len(), 2);
        assert_eq!(spec.variants[0].trap_oid, "1.3.6.1.6.3.1.1.5.3");
        assert_eq!(
            spec.variants[0].varbinds.get("if_oper_status").unwrap(),
            "1.3.6.1.2.1.2.2.1.8"
        );
        assert_eq!(
            spec.variants[0].key_expression.as_deref(),
            Some("varbinds.if_index")
        );
        assert_eq!(spec.ttl_secs, Some(3600));
        assert_eq!(spec.history_retention_secs, Some(604800));

        // Re-upsert with no traps at all — the old binding must be gone, not left orphaned.
        let mut replaced = profile.clone();
        replaced.traps = TrapsSection::default();
        store.upsert(&replaced).await.unwrap();
        let loaded = store.load_all().await.unwrap();
        assert!(
            loaded[0].traps.bindings.is_empty(),
            "old trap binding must be fully replaced, not merged with the empty new set"
        );
    }

    /// Syslog ingestion (2026-09-06) — `syslog.bindings` must round-trip through the DB
    /// including the multi-variant list, the severity/facility prefilters, and both
    /// optional `ttl_secs`/`history_retention_secs`, same contract
    /// `round_trips_trap_bindings_and_replaces_on_upsert` already established for traps.
    #[tokio::test]
    async fn round_trips_syslog_bindings_and_replaces_on_upsert() {
        use discovery_dsl::{SyslogEventSpec, SyslogSection, SyslogSpec};

        let store = SeaOrmProfileStore::new_in_memory_for_tests().await;
        let mut profile = a_profile("with_syslog");
        profile.syslog.bindings.insert(
            "iface_down".to_string(),
            SyslogSpec {
                variants: vec![
                    SyslogEventSpec {
                        pattern: r"(?P<ifName>\S+) is down".into(),
                        max_severity: Some(4),
                        facility: Some(23),
                        key_expression: Some("fields.ifName".into()),
                    },
                    SyslogEventSpec {
                        pattern: r"(?P<ifName>\S+) down".into(),
                        max_severity: Some(4),
                        facility: Some(23),
                        key_expression: Some("fields.ifName".into()),
                    },
                ],
                ttl_secs: Some(3600),
                history_retention_secs: Some(604800),
            },
        );
        store.upsert(&profile).await.unwrap();

        let loaded = store.load_all().await.unwrap();
        assert_eq!(loaded.len(), 1);
        let syslog = &loaded[0].syslog;
        assert_eq!(syslog.bindings.len(), 1);
        let spec = syslog.bindings.get("iface_down").unwrap();
        assert_eq!(spec.variants.len(), 2);
        assert_eq!(spec.variants[0].pattern, r"(?P<ifName>\S+) is down");
        assert_eq!(spec.variants[0].max_severity, Some(4));
        assert_eq!(spec.variants[0].facility, Some(23));
        assert_eq!(
            spec.variants[0].key_expression.as_deref(),
            Some("fields.ifName")
        );
        assert_eq!(spec.ttl_secs, Some(3600));
        assert_eq!(spec.history_retention_secs, Some(604800));

        // Re-upsert with no syslog bindings at all — the old binding must be gone, not left orphaned.
        let mut replaced = profile.clone();
        replaced.syslog = SyslogSection::default();
        store.upsert(&replaced).await.unwrap();
        let loaded = store.load_all().await.unwrap();
        assert!(
            loaded[0].syslog.bindings.is_empty(),
            "old syslog binding must be fully replaced, not merged with the empty new set"
        );
    }

    /// L4/L7 service checks (2026-09-07) — `service_checks.checks`/`.schedule` must
    /// round-trip through the DB, and an `upsert` on the same profile name must fully
    /// replace the list (not append/merge), same contract the trap/syslog tests already
    /// established — but here it's a **single row per profile**, not one per named entry
    /// (see `discovery_entities::profile_service_checks`'s docs), so this also checks that
    /// re-upserting down to an empty list actually removes that one row rather than leaving
    /// a stale empty-`checks`-array row behind.
    #[tokio::test]
    async fn round_trips_service_checks_and_replaces_on_upsert() {
        use discovery_core::Schedule;
        use discovery_dsl::{ServiceCheckProtocol, ServiceCheckSpec, ServiceChecksSection};
        use sea_orm::EntityTrait;

        let store = SeaOrmProfileStore::new_in_memory_for_tests().await;
        let mut profile = a_profile("with_service_checks");
        profile.service_checks = ServiceChecksSection {
            checks: vec![
                ServiceCheckSpec {
                    name: "ssh".to_string(),
                    protocol: ServiceCheckProtocol::Ssh,
                    target: None,
                    port: 22,
                    path: None,
                    expected_status: None,
                    body_contains: None,
                    timeout_ms: Some(2000),
                    enabled: true,
                },
                ServiceCheckSpec {
                    name: "web".to_string(),
                    protocol: ServiceCheckProtocol::Https,
                    target: Some("10.0.0.99".to_string()),
                    port: 443,
                    path: Some("/health".to_string()),
                    expected_status: Some(200),
                    body_contains: Some("ok".to_string()),
                    timeout_ms: Some(3000),
                    enabled: true,
                },
            ],
            schedule: Some(Schedule::Periodic { interval_secs: 45 }),
            history_retention_secs: Some(604800),
        };
        store.upsert(&profile).await.unwrap();

        let loaded = store.load_all().await.unwrap();
        assert_eq!(loaded.len(), 1);
        let sc = &loaded[0].service_checks;
        assert_eq!(sc.checks.len(), 2);
        assert_eq!(sc.checks[0].name, "ssh");
        assert_eq!(sc.checks[0].protocol, ServiceCheckProtocol::Ssh);
        assert_eq!(sc.checks[1].target.as_deref(), Some("10.0.0.99"));
        assert_eq!(sc.checks[1].expected_status, Some(200));
        assert_eq!(sc.checks[1].body_contains.as_deref(), Some("ok"));
        assert!(matches!(
            sc.schedule,
            Some(Schedule::Periodic { interval_secs: 45 })
        ));
        assert_eq!(sc.history_retention_secs, Some(604800));

        // Re-upsert with an empty list — the old row must be gone entirely, not left as a
        // stale `checks: []` row (`replace_service_checks` skips inserting a fresh one when
        // the whole section is empty — this is the one behavior that would silently regress
        // if that guard were ever removed).
        let mut replaced = profile.clone();
        replaced.service_checks = ServiceChecksSection::default();
        store.upsert(&replaced).await.unwrap();
        let loaded = store.load_all().await.unwrap();
        assert!(
            loaded[0].service_checks.checks.is_empty(),
            "old service checks must be fully replaced, not merged with the empty new set"
        );
        assert!(
            discovery_entities::profile_service_checks::Entity::find().all(&store.db).await.unwrap().is_empty(),
            "an empty ServiceChecksSection must leave zero rows in profile_service_checks, not one row with an empty checks array"
        );
    }

    /// Direct user request 2026-08-29 ("тревога по порту") — `row_metric`/
    /// `row_key_expression` must round-trip through the DB, distinctly from an ordinary
    /// device-level rule in the same profile.
    #[tokio::test]
    async fn round_trips_a_row_scoped_alert_rule_distinctly_from_a_device_level_one() {
        let store = SeaOrmProfileStore::new_in_memory_for_tests().await;
        let mut profile = a_profile("with_row_alert");
        profile.alerts.push(AlertRule {
            policy: Default::default(),
            name: "port_down".into(),
            level: "warning".into(),
            row_metric: Some("if_table".into()),
            row_key_expression: Some("row.ifDescr".into()),
            expression: "row.ifOperStatus == 2".into(),
            deactivation_expression: Some("row.ifOperStatus == 1".into()),
            facts_expression: Some("#{ifIndex: row.ifIndex}".into()),
            message: "Порт {row.ifDescr} недоступен".into(),
            clear_after_seconds: Some(300),
            activate_after_seconds: None,
            flap_window_seconds: None,
            flap_threshold: None,
            enabled: true,
        });
        store.upsert(&profile).await.unwrap();

        let loaded = store.load_all().await.unwrap();
        let alerts = &loaded[0].alerts;
        assert_eq!(alerts.len(), 2);

        let device_level = alerts.iter().find(|a| a.name == "high_cpu").unwrap();
        assert_eq!(
            device_level.row_metric, None,
            "an ordinary rule must not pick up a stray row_metric"
        );

        let row_scoped = alerts.iter().find(|a| a.name == "port_down").unwrap();
        assert_eq!(row_scoped.row_metric.as_deref(), Some("if_table"));
        assert_eq!(
            row_scoped.row_key_expression.as_deref(),
            Some("row.ifDescr")
        );
        assert_eq!(row_scoped.expression, "row.ifOperStatus == 2");
    }

    /// The three `columns` states (see `MetricSpec::Detailed::columns`'s docs) must
    /// round-trip through the DB distinctly — a scalar staying `None`/absent, and a table's
    /// curated column map surviving the JSON column intact, not silently collapsing into
    /// one of the other states.
    #[tokio::test]
    async fn round_trips_a_table_metrics_columns_distinctly_from_a_scalar() {
        let store = SeaOrmProfileStore::new_in_memory_for_tests().await;

        let mut poll = BTreeMap::new();
        poll.insert(
            "uptime".to_string(),
            MetricSpec::Oid("1.3.6.1.2.1.1.3.0".to_string()),
        );
        let mut columns = BTreeMap::new();
        columns.insert("ifIndex".to_string(), "1".to_string());
        columns.insert("ifDescr".to_string(), "2".to_string());
        poll.insert(
            "if_table".to_string(),
            MetricSpec::Detailed {
                oid: "1.3.6.1.2.1.2.2.1".to_string(),
                columns: Some(columns),
                schedule: None,
                history_retention_secs: None,
                enabled: true,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
                derive: None,
            },
        );

        let profile = ProfileFile {
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            profile: ProfileMeta {
                name: "with_table".to_string(),
                priority: 0,
            },
            match_expr: MatchSection {
                expression: "true".into(),
            },
            metrics: MetricsSection { poll },
            alerts: vec![],
            version: "ignored-on-write".into(),
        };
        store.upsert(&profile).await.unwrap();

        let loaded = store.load_all().await.unwrap();
        assert_eq!(loaded.len(), 1);
        let loaded_poll = &loaded[0].metrics.poll;

        let uptime = loaded_poll.get("uptime").unwrap();
        assert!(
            !uptime.is_table(),
            "a plain-string metric must round-trip as a scalar, not pick up a stray columns value"
        );

        let if_table = loaded_poll.get("if_table").unwrap();
        assert!(if_table.is_table());
        let loaded_columns = if_table.columns().unwrap();
        assert_eq!(loaded_columns.len(), 2);
        assert_eq!(loaded_columns.get("ifDescr"), Some(&"2".to_string()));
    }

    /// SSH CLI-pull metrics (2026-09-07) — a `MetricSpec::SshCommand` row must round-trip
    /// through `profile_metrics` distinctly from an SNMP `Oid`/`Detailed` row in the same
    /// profile, same contract `round_trips_a_table_metrics_columns_distinctly_from_a_scalar`
    /// already established for table-vs-scalar.
    #[tokio::test]
    async fn round_trips_an_ssh_command_metric_distinctly_from_an_snmp_metric() {
        let store = SeaOrmProfileStore::new_in_memory_for_tests().await;

        let mut poll = BTreeMap::new();
        poll.insert(
            "uptime".to_string(),
            MetricSpec::Oid("1.3.6.1.2.1.1.3.0".to_string()),
        );
        poll.insert(
            "running_config".to_string(),
            MetricSpec::SshCommand {
                command: "show running-config".to_string(),
                schedule: None,
                history_retention_secs: Some(2592000),
                enabled: true,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
            },
        );

        let profile = ProfileFile {
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            profile: ProfileMeta {
                name: "with_ssh".to_string(),
                priority: 0,
            },
            match_expr: MatchSection {
                expression: "true".into(),
            },
            metrics: MetricsSection { poll },
            alerts: vec![],
            version: "ignored-on-write".into(),
        };
        store.upsert(&profile).await.unwrap();

        let loaded = store.load_all().await.unwrap();
        assert_eq!(loaded.len(), 1);
        let loaded_poll = &loaded[0].metrics.poll;

        let uptime = loaded_poll.get("uptime").unwrap();
        assert!(
            !uptime.is_ssh_command(),
            "an SNMP metric must round-trip as SNMP, not pick up a stray command"
        );
        assert_eq!(uptime.oid(), "1.3.6.1.2.1.1.3.0");

        let running_config = loaded_poll.get("running_config").unwrap();
        assert!(running_config.is_ssh_command());
        assert_eq!(running_config.command(), Some("show running-config"));
        assert_eq!(running_config.history_retention_secs(), Some(2592000));
        assert!(!running_config.is_table());
    }

    #[tokio::test]
    async fn upsert_on_an_existing_name_replaces_metrics_and_alerts_not_appends() {
        let store = SeaOrmProfileStore::new_in_memory_for_tests().await;
        store.upsert(&a_profile("a")).await.unwrap();

        let mut second = a_profile("a");
        second.metrics.poll.clear();
        second
            .metrics
            .poll
            .insert("mem".to_string(), MetricSpec::Oid("9.9.9".to_string()));
        second.alerts.clear();
        second.profile.priority = 99;
        store.upsert(&second).await.unwrap();

        let loaded = store.load_all().await.unwrap();
        assert_eq!(
            loaded.len(),
            1,
            "same name — must update in place, not create a second profile"
        );
        assert_eq!(loaded[0].profile.priority, 99);
        assert_eq!(
            loaded[0].metrics.poll.len(),
            1,
            "old metric list must be fully replaced"
        );
        assert!(loaded[0].metrics.poll.contains_key("mem"));
        assert!(!loaded[0].metrics.poll.contains_key("cpu"));
        assert!(
            loaded[0].alerts.is_empty(),
            "old alert list must be fully replaced"
        );
    }

    #[tokio::test]
    async fn delete_cascades_to_profile_metrics_and_profile_alerts() {
        use sea_orm::EntityTrait;

        let store = SeaOrmProfileStore::new_in_memory_for_tests().await;
        store.upsert(&a_profile("a")).await.unwrap();
        assert_eq!(
            discovery_entities::profile_metrics::Entity::find()
                .all(&store.db)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            discovery_entities::profile_alerts::Entity::find()
                .all(&store.db)
                .await
                .unwrap()
                .len(),
            1
        );

        store.delete("a").await.unwrap();

        // The real proof this is a DB-enforced `ON DELETE CASCADE` actually firing (needs
        // `PRAGMA foreign_keys = ON` on SQLite specifically, see this store's docs) — not
        // just `load_all` returning nothing, which it would do either way since it only
        // ever looks up children by names still present in `profiles`, cascade or not.
        assert!(
            discovery_entities::profile_metrics::Entity::find()
                .all(&store.db)
                .await
                .unwrap()
                .is_empty(),
            "profile_metrics row must be gone, not merely orphaned"
        );
        assert!(
            discovery_entities::profile_alerts::Entity::find()
                .all(&store.db)
                .await
                .unwrap()
                .is_empty(),
            "profile_alerts row must be gone, not merely orphaned"
        );
    }

    #[tokio::test]
    async fn load_all_computes_a_version_deterministically_from_content() {
        let store = SeaOrmProfileStore::new_in_memory_for_tests().await;
        store.upsert(&a_profile("a")).await.unwrap();
        let first = store.load_all().await.unwrap();
        let second = store.load_all().await.unwrap();
        assert_eq!(
            first[0].version, second[0].version,
            "version must be a pure function of content, not random/time-based"
        );
        assert_ne!(first[0].version, "ignored-on-write", "the version written on the struct must never be trusted back — it's recomputed on read");
    }
}
