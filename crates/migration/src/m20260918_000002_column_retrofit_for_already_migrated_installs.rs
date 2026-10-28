//! Retrofits every column that `m20260818_000001_initial_schema` added to an existing
//! table's `up()` body *after* that migration had already shipped and run somewhere — a
//! `has_column`-guarded `ADD COLUMN` block living inside an already-applied migration.
//!
//! **Why this has to be a separate, new migration — found live, 2026-09-18, not
//! guessed.** `sea_orm_migration::MigratorTrait::up()` only calls `up()` on migrations
//! *not yet* recorded in `seaql_migrations` (`get_pending_migrations`, this crate's own
//! `migrator.rs`) — a `has_column` guard *inside* an already-applied migration's `up()`
//! body never runs again, no matter how many new guarded blocks get appended to that body
//! later, because `up()` for that migration simply never gets called again at all. Every
//! prior "add a column to an existing table" retrofit in this project followed the
//! documented `has_column` pattern (`.claude/rules/engineering-patterns.md`), correctly
//! avoiding a duplicate-column crash on a **fresh** install (where the column already
//! exists via the `CREATE TABLE` above it, in the same `up()` call) — but every one of
//! them, as originally written, was silently inert for the one case they were actually
//! meant to cover: a database that had already run
//! `m20260818_000001_initial_schema` *before* that particular column's guarded block was
//! added to it. Verified by simulating exactly that (a real file-backed SQLite,
//! `assistant_conversations` present, `auto_approve_writes` column dropped, `seaql_migrations`
//! still recording the migration as applied) — restarting `discovery-agent` against it
//! immediately threw `no such column: assistant_conversations.auto_approve_writes`, not a
//! clean retrofit. See `docs/Changelog/2026-09-18 - Column retrofit migration
//! bug.md`.
//!
//! Every column below is copied verbatim from its guarded block in
//! `m20260818_000001_initial_schema` — same type/nullability/default, same order where
//! order is load-bearing (the `devices` block: every column the entity's `SELECT *`-style
//! `Entity::find()` in the `ip_sort_key` backfill touches must exist first). This
//! migration's `up()` is idempotent in both directions:
//! - A fresh install already has every one of these columns from the original migration's
//!   own `CREATE TABLE` — every `has_column` check here is `true`, this whole `up()` is a
//!   sequence of no-ops.
//! - An install that already ran `m20260818_000001_initial_schema` before some of these
//!   columns existed in it gets exactly the ones it's missing — this is the case that
//!   never actually worked before this file existed.
//!
//! **Going forward: a schema change to a table this project has already shipped must be a
//! new migration file like this one** (registered in `Migrator::migrations()`), never
//! another edit to `m20260818_000001_initial_schema`'s `up()` body — editing that file only
//! ever affects a database that has never run any migration at all.
//!
//! Local `#[derive(DeriveIden)]` enums below are deliberately separate from
//! `m20260818_000001_initial_schema`'s own (rather than importing/making those `pub`) —
//! `DeriveIden`'s generated identifier string depends only on the enum/variant name, not
//! which module defines it, so a same-named local enum here produces the exact same SQL
//! identifier with zero coupling between the two migration files.

use sea_orm_migration::prelude::*;

const KEY_LEN: u32 = 255;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // ---------------------------------------------------------------- jobs
        if !manager.has_column("jobs", "paused").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Jobs::Table)
                        .add_column(
                            ColumnDef::new(Jobs::Paused)
                                .boolean()
                                .not_null()
                                .default(false),
                        )
                        .to_owned(),
                )
                .await?;
        }

        // ------------------------------------------------------------- devices
        // Order matters: the `ip_sort_key` backfill below does a full
        // `discovery_entities::devices::Entity::find()`, which selects every column the
        // *current* entity struct declares — it fails outright against a table still
        // missing any of them. Every other `devices` column here must be added first.
        if !manager.has_column("devices", "snmp_auth").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Devices::Table)
                        .add_column(ColumnDef::new(Devices::SnmpAuth).json())
                        .to_owned(),
                )
                .await?;
        }
        if !manager.has_column("devices", "ssh_auth").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Devices::Table)
                        .add_column(ColumnDef::new(Devices::SshAuth).json())
                        .to_owned(),
                )
                .await?;
        }
        if !manager.has_column("devices", "ssh_username").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Devices::Table)
                        .add_column(
                            ColumnDef::new(Devices::SshUsername)
                                // MySQL rejects DEFAULT on TEXT; keep the retrofit schema
                                // identical to the fresh-install definition.
                                .string_len(KEY_LEN)
                                .not_null()
                                .default(""),
                        )
                        .to_owned(),
                )
                .await?;
        }
        if !manager.has_column("devices", "ssh_port").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Devices::Table)
                        .add_column(
                            ColumnDef::new(Devices::SshPort)
                                .integer()
                                .not_null()
                                .default(22),
                        )
                        .to_owned(),
                )
                .await?;
        }
        if !manager
            .has_column("devices", "ssh_host_key_fingerprint")
            .await?
        {
            manager
                .alter_table(
                    Table::alter()
                        .table(Devices::Table)
                        .add_column(ColumnDef::new(Devices::SshHostKeyFingerprint).text())
                        .to_owned(),
                )
                .await?;
        }
        if !manager.has_column("devices", "ping_loss_pct").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Devices::Table)
                        .add_column(ColumnDef::new(Devices::PingLossPct).double())
                        .to_owned(),
                )
                .await?;
        }
        if !manager.has_column("devices", "ip_sort_key").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Devices::Table)
                        .add_column(
                            ColumnDef::new(Devices::IpSortKey)
                                .big_integer()
                                .not_null()
                                .default(0),
                        )
                        .to_owned(),
                )
                .await?;
            // Same portable typed-query backfill as the original block — bounded by
            // however many devices existed before this migration first ran here.
            use discovery_entities::devices::{
                ActiveModel as DeviceActiveModel, Entity as DeviceEntity,
            };
            use sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait};
            let db = manager.get_connection();
            for row in DeviceEntity::find().all(db).await? {
                let sort_key = discovery_core::ipv4_to_sort_key(&row.ip);
                let mut am: DeviceActiveModel = row.into();
                am.ip_sort_key = Set(sort_key);
                am.update(db).await?;
            }
        }

        // ---------------------------------------------------------- profile_metrics
        if !manager.has_column("profile_metrics", "columns").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(ProfileMetrics::Table)
                        .add_column(ColumnDef::new(ProfileMetrics::Columns).json())
                        .to_owned(),
                )
                .await?;
        }
        if !manager.has_column("profile_metrics", "command").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(ProfileMetrics::Table)
                        .add_column(ColumnDef::new(ProfileMetrics::Command).text())
                        .to_owned(),
                )
                .await?;
        }
        if !manager.has_column("profile_metrics", "derive").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(ProfileMetrics::Table)
                        .add_column(ColumnDef::new(ProfileMetrics::Derive).json())
                        .to_owned(),
                )
                .await?;
        }

        // ----------------------------------------------------------- profile_alerts
        if !manager.has_column("profile_alerts", "row_metric").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(ProfileAlerts::Table)
                        .add_column(ColumnDef::new(ProfileAlerts::RowMetric).text())
                        .to_owned(),
                )
                .await?;
        }
        if !manager
            .has_column("profile_alerts", "row_key_expression")
            .await?
        {
            manager
                .alter_table(
                    Table::alter()
                        .table(ProfileAlerts::Table)
                        .add_column(ColumnDef::new(ProfileAlerts::RowKeyExpression).text())
                        .to_owned(),
                )
                .await?;
        }

        // -------------------------------------------------------- discovery_subnets
        if !manager
            .has_column("discovery_subnets", "credentials")
            .await?
        {
            manager
                .alter_table(
                    Table::alter()
                        .table(DiscoverySubnets::Table)
                        .add_column(ColumnDef::new(DiscoverySubnets::Credentials).json())
                        .to_owned(),
                )
                .await?;
        }

        // --------------------------------------------------- discovery_subnet_oids
        if !manager
            .has_column("discovery_subnet_oids", "columns")
            .await?
        {
            manager
                .alter_table(
                    Table::alter()
                        .table(DiscoverySubnetOids::Table)
                        .add_column(ColumnDef::new(DiscoverySubnetOids::Columns).json())
                        .to_owned(),
                )
                .await?;
        }

        // -------------------------------------------------------------------- alerts
        if !manager.has_column("alerts", "row_key").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alerts::Table)
                        .add_column(ColumnDef::new(Alerts::RowKey).text())
                        .to_owned(),
                )
                .await?;
        }
        if !manager.has_column("alerts", "auto_clear_reason").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alerts::Table)
                        .add_column(ColumnDef::new(Alerts::AutoClearReason).text())
                        .to_owned(),
                )
                .await?;
        }
        if !manager
            .has_column("alerts", "suppressed_by_alert_id")
            .await?
        {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alerts::Table)
                        .add_column(ColumnDef::new(Alerts::SuppressedByAlertId).uuid())
                        .to_owned(),
                )
                .await?;
        }
        if !manager
            .has_column("alerts", "reopened_from_alert_id")
            .await?
        {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alerts::Table)
                        .add_column(ColumnDef::new(Alerts::ReopenedFromAlertId).uuid())
                        .to_owned(),
                )
                .await?;
        }

        // ------------------------------------------------ assistant_conversations
        if !manager
            .has_column("assistant_conversations", "auto_approve_writes")
            .await?
        {
            manager
                .alter_table(
                    Table::alter()
                        .table(AssistantConversations::Table)
                        .add_column(
                            ColumnDef::new(AssistantConversations::AutoApproveWrites)
                                .boolean()
                                .not_null()
                                .default(false),
                        )
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // No-op — same convention every other guarded retrofit in this project already
        // takes (see `m20260818_000001_initial_schema::down`): rolling back means wiping
        // the whole schema, which that migration's own `down()` already does by dropping
        // every table outright (columns included). Nothing here to separately reverse.
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Jobs {
    Table,
    Paused,
}

#[derive(DeriveIden)]
enum Devices {
    Table,
    SnmpAuth,
    SshAuth,
    SshUsername,
    SshPort,
    SshHostKeyFingerprint,
    PingLossPct,
    IpSortKey,
}

#[derive(DeriveIden)]
enum ProfileMetrics {
    Table,
    Columns,
    Command,
    Derive,
}

#[derive(DeriveIden)]
enum ProfileAlerts {
    Table,
    RowMetric,
    RowKeyExpression,
}

#[derive(DeriveIden)]
enum DiscoverySubnets {
    Table,
    Credentials,
}

#[derive(DeriveIden)]
enum DiscoverySubnetOids {
    Table,
    Columns,
}

#[derive(DeriveIden)]
enum Alerts {
    Table,
    RowKey,
    AutoClearReason,
    SuppressedByAlertId,
    ReopenedFromAlertId,
}

#[derive(DeriveIden)]
enum AssistantConversations {
    Table,
    AutoApproveWrites,
}
