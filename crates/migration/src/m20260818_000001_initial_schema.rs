use sea_orm_migration::prelude::*;

/// A bounded length for every text column that participates in a primary key, a plain
/// index, or a foreign key — found live, not guessed: MySQL rejected the first version of
/// this migration with "BLOB/TEXT column ... used in key specification without a key
/// length" (`.text()` has no fixed length MySQL can build a key on; Postgres/SQLite don't
/// have this restriction, which is exactly why this only ever showed up running against a
/// real MySQL server). 255 is generous for every column this applies to here (queue
/// names, ids/names/keys, IPs) — not a hard schema limit elsewhere, just what MySQL needs
/// declared for indexing purposes.
const KEY_LEN: u32 = 255;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // ---------------------------------------------------------------- jobs
        manager
            .create_table(
                Table::create()
                    .table(Jobs::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Jobs::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Jobs::QueueType)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(ColumnDef::new(Jobs::Payload).json().not_null())
                    .col(ColumnDef::new(Jobs::DedupeKey).string_len(KEY_LEN))
                    // No DB-level default (unlike the old Postgres-only migration) — MySQL
                    // rejects a literal `DEFAULT` on TEXT/BLOB/JSON columns ("BLOB, TEXT,
                    // GEOMETRY or JSON column 'state' can't have a default value", found
                    // live running this exact migration against MySQL 9.7). Every store's
                    // `enqueue` always sets `state` explicitly on insert anyway (same
                    // discipline already used here for `created_at`/`updated_at` instead of
                    // a DB-level `now()`, to sidestep function-default dialect differences
                    // too), so the column-level default was never load-bearing.
                    .col(ColumnDef::new(Jobs::State).string_len(KEY_LEN).not_null())
                    .col(
                        ColumnDef::new(Jobs::Attempts)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(Jobs::MaxAttempts)
                            .integer()
                            .not_null()
                            .default(5),
                    )
                    .col(ColumnDef::new(Jobs::LockedBy).text())
                    .col(ColumnDef::new(Jobs::LockedAt).timestamp_with_time_zone())
                    .col(ColumnDef::new(Jobs::LastError).text())
                    .col(
                        ColumnDef::new(Jobs::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Jobs::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    // `not_null().default(false)` here only takes effect for a brand-new
                    // table — see the `alter_table` call right below for why a *second*,
                    // separate statement is needed to reach this column on a database that
                    // already had a `jobs` table before this field existed.
                    .col(
                        ColumnDef::new(Jobs::Paused)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;
        // `create_table(...).if_not_exists()` above is a complete no-op against a database
        // that already has a `jobs` table (this project's already-running dev stand among
        // them — see this module's docs on why `.if_not_exists()` has to keep working
        // against it) — it will never add a column an existing table is missing. This
        // `alter_table` is the one part of this migration that's a real incremental `ALTER
        // TABLE`, not "rewrite the CREATE TABLE and call it done": added 2026-08-21 for
        // per-job pause (`discovery_queue::JobQueueStore::pause_job`), after the `paused`
        // column already existed in the `Jobs` enum/CREATE TABLE above for fresh installs
        // only.
        //
        // **`has_column` gate, not `add_column_if_not_exists`'s own SQL-level guard** —
        // found live, not guessed: `add_column_if_not_exists` emits real `IF NOT EXISTS` on
        // Postgres/MySQL, but sea-query 0.31's SQLite backend drops that clause entirely
        // (`sea-query`'s own `backend/sqlite/table.rs`, verified by reading it, not
        // assumed) — so against a *fresh* SQLite database (which already got `paused` from
        // the `CREATE TABLE` above), this would otherwise re-run as a bare `ALTER TABLE
        // jobs ADD COLUMN paused ...` and fail with "duplicate column name: paused" — which
        // is exactly what every SQLite-backed test in this workspace hit the first time
        // this migration shipped. Querying `has_column` explicitly first works identically
        // on all three backends.
        //
        // **This guard only protects a *fresh* install, within this one `up()` call — it
        // does *not* retrofit a database that already ran this migration before this block
        // existed** (found live 2026-09-18, see `crate`'s own module docs and
        // `m20260918_000002_column_retrofit_for_already_migrated_installs`, which is what
        // actually does that; every "same `has_column` gate as `jobs.paused` above" comment
        // elsewhere in this file carries the same correction, not repeated at each site).
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
        // `idx_jobs_dequeue` (queue_type, id) replaced by `idx_jobs_claim` below — found on
        // the 2026-08-21 scale audit: `claim()`'s actual filter is `queue_type = X AND
        // state = 'pending' AND paused = false ORDER BY id`, and a `(queue_type, id)`
        // index can't satisfy `state`/`paused` without a row-by-row recheck once a
        // meaningful fraction of a queue's rows are `failed`/`in_progress`/paused (which
        // grows over time under normal operation, not just under failure). Dropped, not
        // just superseded-and-left-in-place — an unused index still costs a write on every
        // `INSERT`/`UPDATE` to `jobs` for no benefit once `idx_jobs_claim` covers every
        // query this one did.
        // MySQL does not support `DROP INDEX IF EXISTS`; probe first so the
        // fresh-install path remains portable across all supported backends.
        if manager.has_index("jobs", "idx_jobs_dequeue").await? {
            manager
                .drop_index(
                    Index::drop()
                        .name("idx_jobs_dequeue")
                        .table(Jobs::Table)
                        .to_owned(),
                )
                .await?;
        }
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_jobs_claim")
                    .table(Jobs::Table)
                    .col(Jobs::QueueType)
                    .col(Jobs::State)
                    .col(Jobs::Paused)
                    .col(Jobs::Id)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_jobs_dedupe")
                    .table(Jobs::Table)
                    .col(Jobs::QueueType)
                    .col(Jobs::DedupeKey)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_jobs_stale")
                    .table(Jobs::Table)
                    .col(Jobs::State)
                    .col(Jobs::LockedAt)
                    .to_owned(),
            )
            .await?;

        // ------------------------------------------------------------- devices
        manager
            .create_table(
                Table::create()
                    .table(Devices::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Devices::DeviceId)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Devices::Ip).string_len(KEY_LEN).not_null())
                    .col(ColumnDef::new(Devices::Profile).text())
                    .col(ColumnDef::new(Devices::ProfileVersion).text())
                    .col(
                        ColumnDef::new(Devices::PollGeneration)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(ColumnDef::new(Devices::SnmpAuth).json())
                    .col(
                        ColumnDef::new(Devices::SnmpPort)
                            .integer()
                            .not_null()
                            .default(161),
                    )
                    .col(
                        ColumnDef::new(Devices::DiscoveredAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Devices::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Devices::PingOk).boolean())
                    .col(ColumnDef::new(Devices::PingCheckedAt).timestamp_with_time_zone())
                    .col(ColumnDef::new(Devices::PingLossPct).double())
                    .col(ColumnDef::new(Devices::SnmpOk).boolean())
                    .col(ColumnDef::new(Devices::SnmpCheckedAt).timestamp_with_time_zone())
                    .col(
                        ColumnDef::new(Devices::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(ColumnDef::new(Devices::PingFailingSince).timestamp_with_time_zone())
                    // Precomputed numeric sort key for `ip` (the dotted-quad string as a
                    // big-endian u32, widened to fit a portable signed `BIGINT`) — added
                    // 2026-08-21, scale audit: `GET /api/devices`'s default sort ("by ip")
                    // used to require loading every row and sorting in Rust, because a
                    // plain string `ORDER BY ip` sorts lexicographically ("10.0.0.10"
                    // before "10.0.0.2"), not numerically — see
                    // `discovery_devices::ipv4_to_sort_key`'s docs. Computed once, at
                    // insert time only (`ip` is immutable after a device is first
                    // resolved — see `SeaOrmDeviceStore::resolve`'s docs), never
                    // recomputed.
                    .col(
                        ColumnDef::new(Devices::IpSortKey)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_devices_ip")
                    .table(Devices::Table)
                    .col(Devices::Ip)
                    .unique()
                    .to_owned(),
            )
            .await?;
        // Same `has_column` gate as `ip_sort_key` below — an already-deployed stand (not a
        // fresh install) still has the pre-2026-08-29 shape (`snmp_version`/`snmp_community`
        // text columns, no `snmp_auth`); this `ADD COLUMN` gives it the new one without
        // touching the old ones. No backfill needed — `NULL` here means exactly what it
        // meant before this column existed (no negotiated SNMP credentials yet), and the
        // next `SnmpPoll` identity cycle renegotiates it the same way it would for any
        // device that has never had working credentials.
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
        // `ssh_auth`/`ssh_username`/`ssh_port` — SSH CLI-pull metrics (added 2026-09-07,
        // see `docs/Roadmap.md`'s "Сделано" entry). Same `has_column` retrofit pattern as
        // `snmp_auth` above, on a table that already existed on deployed stands. `NULL`
        // `ssh_auth` means exactly what "no `snmp_credentials` yet" already means for SNMP
        // — nothing configured, `MetricPollHandler` fails any due `SshCommand` metric on
        // this device with an explanatory error. Unlike `snmp_auth`, this is **never**
        // populated by any automatic pipeline code — see `discovery_core::SshCredentials`'s
        // docs for why SSH credentials are manual-entry-only.
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
                                // MySQL rejects DEFAULT on TEXT; this value is a bounded
                                // username and needs a portable VARCHAR-like type.
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
        // `ssh_host_key_fingerprint` — SSH host-key pinning (added 2026-09-17, fixing a
        // CWE-295 finding: `discovery_ssh::client::Handler::check_server_key` used to
        // accept every server key unconditionally). Same `has_column` retrofit pattern as
        // `ssh_auth`/`ssh_username`/`ssh_port` above. `NULL` = not yet pinned
        // (trust-on-first-use — see `discovery_core::SshCredentials::known_host_key`'s
        // docs); populated automatically by `MetricPollHandler` via
        // `DeviceStore::pin_ssh_host_key` the first time `discovery_ssh::CliClient::exec`
        // succeeds against this device, never by any manual/REST write directly.
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
        // Same `has_column` retrofit pattern as `snmp_auth`/`ssh_auth` above — an
        // already-deployed stand still has the pre-2026-09-14 shape (no packet-loss
        // column at all). `NULL` here means exactly what it means before this column
        // existed for `ping_ok`/`ping_checked_at`: nothing checked yet — the next
        // `ReachabilityPollHandler` tick populates a real value the same way it would for
        // a freshly-resolved device.
        //
        // **Must run before the `ip_sort_key` backfill below**, not after — that backfill
        // does a full `DeviceEntity::find()` (every column `discovery_entities::devices::
        // Model` declares, `ping_loss_pct` included since 2026-09-14), which fails outright
        // against a pre-existing table that doesn't have this column yet. Found live by
        // this exact migration test failing the moment the column was added after that
        // backfill block instead of before it.
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
            // Backfill devices that predate this column — a fresh install never has any
            // pre-existing rows to backfill (this branch only runs once, guarded by
            // `has_column` above), and every row inserted from now on already gets a real
            // value from `SeaOrmDeviceStore::resolve` at insert time. A typed sea-orm
            // query/update (not raw SQL) — portable across all three backends without
            // hand-rolling per-dialect string parsing, and the row count here is bounded
            // by however many devices existed *before* this migration first ran on this
            // installation, not an ongoing cost.
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
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_devices_ip_sort_key")
                    .table(Devices::Table)
                    .col(Devices::IpSortKey)
                    .to_owned(),
            )
            .await?;
        // Found on the 2026-08-21 scale audit: `DeviceStore::delete_unreachable_since`
        // filters `enabled = true AND ping_failing_since IS NOT NULL AND <= cutoff` with no
        // supporting index — `dead_device_cleanup`'s periodic sweep (hourly by default) was
        // a full `devices` table scan every single run.
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_devices_ping_failing")
                    .table(Devices::Table)
                    .col(Devices::Enabled)
                    .col(Devices::PingFailingSince)
                    .to_owned(),
            )
            .await?;

        // ------------------------------------------------------ device_metric_settings
        manager
            .create_table(
                Table::create()
                    .table(DeviceMetricSettings::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(DeviceMetricSettings::DeviceId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DeviceMetricSettings::Name)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DeviceMetricSettings::Enabled)
                            .boolean()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(DeviceMetricSettings::DeviceId)
                            .col(DeviceMetricSettings::Name),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(DeviceMetricSettings::Table, DeviceMetricSettings::DeviceId)
                            .to(Devices::Table, Devices::DeviceId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // ------------------------------------------------------------- device_metrics
        // No FK to `devices` — cross-domain soft reference, see this crate's docs.
        manager
            .create_table(
                Table::create()
                    .table(DeviceMetrics::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(DeviceMetrics::DeviceId).uuid().not_null())
                    .col(
                        ColumnDef::new(DeviceMetrics::Name)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(ColumnDef::new(DeviceMetrics::Value).json())
                    .col(ColumnDef::new(DeviceMetrics::Error).text())
                    .col(ColumnDef::new(DeviceMetrics::PolledAt).timestamp_with_time_zone())
                    .col(
                        ColumnDef::new(DeviceMetrics::LastAttemptAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(DeviceMetrics::DeviceId)
                            .col(DeviceMetrics::Name),
                    )
                    .to_owned(),
            )
            .await?;

        // ------------------------------------------------------ device_metric_history
        // No FK to `devices` either — same cross-domain reasoning.
        manager
            .create_table(
                Table::create()
                    .table(DeviceMetricHistory::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(DeviceMetricHistory::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(DeviceMetricHistory::DeviceId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DeviceMetricHistory::Name)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(ColumnDef::new(DeviceMetricHistory::Value).json())
                    .col(ColumnDef::new(DeviceMetricHistory::Error).text())
                    .col(
                        ColumnDef::new(DeviceMetricHistory::FirstObservedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DeviceMetricHistory::LastObservedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_device_metric_history_latest")
                    .table(DeviceMetricHistory::Table)
                    .col(DeviceMetricHistory::DeviceId)
                    .col(DeviceMetricHistory::Name)
                    .col(DeviceMetricHistory::LastObservedAt)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_device_metric_history_retention")
                    .table(DeviceMetricHistory::Table)
                    .col(DeviceMetricHistory::Name)
                    .col(DeviceMetricHistory::LastObservedAt)
                    .to_owned(),
            )
            .await?;

        // ------------------------------------------------------------------ profiles
        manager
            .create_table(
                Table::create()
                    .table(Profiles::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Profiles::Name)
                            .string_len(KEY_LEN)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Profiles::Priority)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(ColumnDef::new(Profiles::MatchExpression).text().not_null())
                    .col(
                        ColumnDef::new(Profiles::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Profiles::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // ---------------------------------------------------------- profile_metrics
        manager
            .create_table(
                Table::create()
                    .table(ProfileMetrics::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ProfileMetrics::ProfileName)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProfileMetrics::Name)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(ColumnDef::new(ProfileMetrics::Oid).text().not_null())
                    .col(ColumnDef::new(ProfileMetrics::Columns).json())
                    .col(ColumnDef::new(ProfileMetrics::HistoryRetentionSecs).big_integer())
                    .col(ColumnDef::new(ProfileMetrics::Schedule).json())
                    .col(
                        ColumnDef::new(ProfileMetrics::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(ProfileMetrics::HistoryKeepLastSuccess)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(ProfileMetrics::HistoryKeepLastAttempt)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(ColumnDef::new(ProfileMetrics::Derive).json())
                    .primary_key(
                        Index::create()
                            .col(ProfileMetrics::ProfileName)
                            .col(ProfileMetrics::Name),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(ProfileMetrics::Table, ProfileMetrics::ProfileName)
                            .to(Profiles::Table, Profiles::Name)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        // `columns` added after this table already existed on deployed stands — same
        // `has_column` gate as `jobs.paused` above, for the same reason (bare CREATE TABLE
        // IF NOT EXISTS never retrofits a column onto an existing table).
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
        // `command` — SSH CLI-pull metrics (added 2026-09-07, see `docs/Roadmap.md`'s
        // "Сделано" entry). Nullable, same "one more optional column, not a schema
        // rewrite" treatment `columns` got above: `NULL` = this row is an SNMP-sourced
        // metric (`oid` is what to read, same as before this column existed), non-`NULL`
        // = an SSH-sourced `discovery_dsl::MetricSpec::SshCommand` (this row's `oid` is
        // simply `""`, unused — see that variant's `oid()` docs for why the column stays
        // `NOT NULL` rather than loosening a constraint on an already-deployed column).
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
        // `derive` (2026-09-07, derived rate/delta metrics) — same `has_column` gate, same
        // reasoning: a deployed stand that already created `profile_metrics` before this
        // column existed never gets it from the `if_not_exists()` CREATE TABLE above.
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
        manager
            .create_table(
                Table::create()
                    .table(ProfileAlerts::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ProfileAlerts::ProfileName)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProfileAlerts::Name)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(ColumnDef::new(ProfileAlerts::Level).text().not_null())
                    .col(ColumnDef::new(ProfileAlerts::RowMetric).text())
                    .col(ColumnDef::new(ProfileAlerts::RowKeyExpression).text())
                    .col(ColumnDef::new(ProfileAlerts::Expression).text().not_null())
                    .col(ColumnDef::new(ProfileAlerts::DeactivationExpression).text())
                    .col(ColumnDef::new(ProfileAlerts::FactsExpression).text())
                    .col(ColumnDef::new(ProfileAlerts::Message).text().not_null())
                    .col(ColumnDef::new(ProfileAlerts::ClearAfterSeconds).big_integer())
                    .col(ColumnDef::new(ProfileAlerts::ActivateAfterSeconds).big_integer())
                    .col(ColumnDef::new(ProfileAlerts::FlapWindowSeconds).big_integer())
                    .col(ColumnDef::new(ProfileAlerts::FlapThreshold).big_integer())
                    .col(
                        ColumnDef::new(ProfileAlerts::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .primary_key(
                        Index::create()
                            .col(ProfileAlerts::ProfileName)
                            .col(ProfileAlerts::Name),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(ProfileAlerts::Table, ProfileAlerts::ProfileName)
                            .to(Profiles::Table, Profiles::Name)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        // `row_metric`/`row_key_expression` added after this table already existed on
        // deployed stands — same `has_column` gate as `jobs.paused` above.
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

        // ------------------------------------------------------------ profile_traps
        manager
            .create_table(
                Table::create()
                    .table(ProfileTraps::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ProfileTraps::ProfileName)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProfileTraps::Name)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(ColumnDef::new(ProfileTraps::Variants).json().not_null())
                    .col(ColumnDef::new(ProfileTraps::TtlSecs).big_integer())
                    .col(ColumnDef::new(ProfileTraps::HistoryRetentionSecs).big_integer())
                    .primary_key(
                        Index::create()
                            .col(ProfileTraps::ProfileName)
                            .col(ProfileTraps::Name),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(ProfileTraps::Table, ProfileTraps::ProfileName)
                            .to(Profiles::Table, Profiles::Name)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // ----------------------------------------------------------- profile_syslog
        // Brand-new table (2026-09-06, Syslog ingestion) — no `has_column` guard needed,
        // same reasoning as `profile_traps` above: this is a table that never existed on
        // any previously-deployed stand, not a column retrofit onto one that did.
        manager
            .create_table(
                Table::create()
                    .table(ProfileSyslog::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ProfileSyslog::ProfileName)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProfileSyslog::Name)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(ColumnDef::new(ProfileSyslog::Variants).json().not_null())
                    .col(ColumnDef::new(ProfileSyslog::TtlSecs).big_integer())
                    .col(ColumnDef::new(ProfileSyslog::HistoryRetentionSecs).big_integer())
                    .primary_key(
                        Index::create()
                            .col(ProfileSyslog::ProfileName)
                            .col(ProfileSyslog::Name),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(ProfileSyslog::Table, ProfileSyslog::ProfileName)
                            .to(Profiles::Table, Profiles::Name)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // ----------------------------------------------------- profile_service_checks
        // Brand-new table (2026-09-07, L4/L7 service checks) — no `has_column` guard
        // needed, same reasoning as `profile_traps`/`profile_syslog` above. One row per
        // *profile* (not per check) — see `discovery_entities::profile_service_checks`'s
        // module docs for why this shape differs from those two.
        manager
            .create_table(
                Table::create()
                    .table(ProfileServiceChecks::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ProfileServiceChecks::ProfileName)
                            .string_len(KEY_LEN)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(ProfileServiceChecks::Checks)
                            .json()
                            .not_null(),
                    )
                    .col(ColumnDef::new(ProfileServiceChecks::Schedule).json())
                    .col(ColumnDef::new(ProfileServiceChecks::HistoryRetentionSecs).big_integer())
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                ProfileServiceChecks::Table,
                                ProfileServiceChecks::ProfileName,
                            )
                            .to(Profiles::Table, Profiles::Name)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // ------------------------------------------------------- discovery_configs
        manager
            .create_table(
                Table::create()
                    .table(DiscoveryConfigs::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(DiscoveryConfigs::Name)
                            .string_len(KEY_LEN)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(DiscoveryConfigs::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(ColumnDef::new(DiscoveryConfigs::Schedule).json().not_null())
                    .col(
                        ColumnDef::new(DiscoveryConfigs::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DiscoveryConfigs::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // ------------------------------------------------------- discovery_subnets
        manager
            .create_table(
                Table::create()
                    .table(DiscoverySubnets::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(DiscoverySubnets::SubnetId)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(DiscoverySubnets::DiscoveryConfigName)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(ColumnDef::new(DiscoverySubnets::Ip).text().not_null())
                    .col(ColumnDef::new(DiscoverySubnets::Mask).text().not_null())
                    .col(
                        ColumnDef::new(DiscoverySubnets::Port)
                            .integer()
                            .not_null()
                            .default(161),
                    )
                    .col(ColumnDef::new(DiscoverySubnets::Credentials).json())
                    .col(ColumnDef::new(DiscoverySubnets::SnmpTimeoutMs).big_integer())
                    .col(ColumnDef::new(DiscoverySubnets::SnmpRetries).integer())
                    .col(
                        ColumnDef::new(DiscoverySubnets::CreateDeadDevices)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                DiscoverySubnets::Table,
                                DiscoverySubnets::DiscoveryConfigName,
                            )
                            .to(DiscoveryConfigs::Table, DiscoveryConfigs::Name)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        // Same `has_column` gate as `devices.snmp_auth` above — an already-deployed stand
        // still has the pre-2026-08-29 shape (`snmp_versions`/`read_communities` json
        // columns, no `credentials`).
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
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_discovery_subnets_config")
                    .table(DiscoverySubnets::Table)
                    .col(DiscoverySubnets::DiscoveryConfigName)
                    .to_owned(),
            )
            .await?;

        // --------------------------------------------------- discovery_subnet_oids
        manager
            .create_table(
                Table::create()
                    .table(DiscoverySubnetOids::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(DiscoverySubnetOids::SubnetId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DiscoverySubnetOids::Name)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(ColumnDef::new(DiscoverySubnetOids::Oid).text().not_null())
                    .col(ColumnDef::new(DiscoverySubnetOids::Columns).json())
                    .primary_key(
                        Index::create()
                            .col(DiscoverySubnetOids::SubnetId)
                            .col(DiscoverySubnetOids::Name),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(DiscoverySubnetOids::Table, DiscoverySubnetOids::SubnetId)
                            .to(DiscoverySubnets::Table, DiscoverySubnets::SubnetId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        // `columns` added after this table already existed on deployed stands — same
        // `has_column` gate as `jobs.paused` above.
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

        // ------------------------------------------------- discovery_subnet_labels
        manager
            .create_table(
                Table::create()
                    .table(DiscoverySubnetLabels::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(DiscoverySubnetLabels::SubnetId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DiscoverySubnetLabels::Name)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DiscoverySubnetLabels::Value)
                            .text()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(DiscoverySubnetLabels::SubnetId)
                            .col(DiscoverySubnetLabels::Name),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                DiscoverySubnetLabels::Table,
                                DiscoverySubnetLabels::SubnetId,
                            )
                            .to(DiscoverySubnets::Table, DiscoverySubnets::SubnetId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // ----------------------------------------------------------------------- logs
        manager
            .create_table(
                Table::create()
                    .table(Logs::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Logs::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Logs::Ts)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Logs::Level).text().not_null())
                    .col(ColumnDef::new(Logs::Target).text().not_null())
                    .col(ColumnDef::new(Logs::Message).text().not_null())
                    .col(ColumnDef::new(Logs::Fields).json().not_null())
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_logs_ts")
                    .table(Logs::Table)
                    .col(Logs::Ts)
                    .to_owned(),
            )
            .await?;

        // ------------------------------------------------------------------- settings
        manager
            .create_table(
                Table::create()
                    .table(Settings::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Settings::Key)
                            .string_len(KEY_LEN)
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Settings::Value).json().not_null())
                    .col(
                        ColumnDef::new(Settings::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // -------------------------------------------------------------------- alerts
        // No FK to `devices` — cross-domain soft reference, see this crate's docs.
        manager
            .create_table(
                Table::create()
                    .table(Alerts::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Alerts::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Alerts::DeviceId).uuid().not_null())
                    .col(ColumnDef::new(Alerts::DeviceIp).text().not_null())
                    .col(ColumnDef::new(Alerts::Name).text().not_null())
                    .col(ColumnDef::new(Alerts::RowKey).text())
                    .col(ColumnDef::new(Alerts::Level).text().not_null())
                    .col(ColumnDef::new(Alerts::Message).text().not_null())
                    .col(ColumnDef::new(Alerts::State).string_len(KEY_LEN).not_null())
                    .col(ColumnDef::new(Alerts::Facts).json())
                    .col(
                        ColumnDef::new(Alerts::FirstSeen)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alerts::LastSeen)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Alerts::ClearedAt).timestamp_with_time_zone())
                    .col(ColumnDef::new(Alerts::ClosedBy).text())
                    .col(ColumnDef::new(Alerts::AcknowledgedBy).text())
                    .col(ColumnDef::new(Alerts::AcknowledgedAt).timestamp_with_time_zone())
                    .col(ColumnDef::new(Alerts::SnoozedUntil).timestamp_with_time_zone())
                    .col(ColumnDef::new(Alerts::SnoozedBy).text())
                    .col(ColumnDef::new(Alerts::AutoClearReason).text())
                    .col(
                        ColumnDef::new(Alerts::Flapping)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(Alerts::SuppressionReason).text())
                    .to_owned(),
            )
            .await?;
        // `row_key`/`auto_clear_reason` added after this table already existed on deployed
        // stands — same `has_column` gate as `jobs.paused` above.
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
        // Group-alert suppression (2026-09-16) — see `discovery_agent::group_alert`'s docs.
        // Soft reference, no FK (same reasoning as `device_id`'s docs on this entity): the
        // alert it points to is a row in this very table, but a `FOREIGN KEY` onto the same
        // table's own `id` would reject the common insert order (the upstream alert's row
        // and the downstream alert's row are written independently, by different sweep-tick
        // iterations, not in a single transaction that could satisfy a self-referential
        // constraint atomically).
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
        // Reopen linking (2026-09-17, audit finding #4 — see
        // `docs/Changelog/2026-09-17 - Аудит глазами оператора...md`): when a manually
        // closed alert's underlying condition is still true and it re-activates within
        // `discovery_agent::handlers::REOPEN_LINK_WINDOW`, this points the *new* row at the
        // one it effectively reopened, instead of leaving two unconnected rows with the
        // comment thread stranded on the old one — see `Alert::reopened_from_alert_id`'s
        // docs for the full mechanism. Same soft-reference reasoning (and same self-
        // referential-FK-can't-work argument) as `suppressed_by_alert_id` just above.
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
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_alerts_device")
                    .table(Alerts::Table)
                    .col(Alerts::DeviceId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_alerts_state")
                    .table(Alerts::Table)
                    .col(Alerts::State)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_alerts_last_seen")
                    .table(Alerts::Table)
                    .col(Alerts::LastSeen)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_alerts_cleared_at")
                    .table(Alerts::Table)
                    .col(Alerts::State)
                    .col(Alerts::ClearedAt)
                    .to_owned(),
            )
            .await?;

        // ---------------------------------------------------------- alert_comments
        // Threaded, multi-author comments (2026-08-28, direct user request — supersedes
        // the earlier 2026-08-18 single free-form `alerts.comment` field: "Мы в дизайне
        // делали комментариями от пользователей" — the design artifact's original
        // round-4 intent, reinstated after living as a single shared textarea for a
        // while). Same-domain FK to `alerts` (both "Тревоги"), so a real
        // `ON DELETE CASCADE` applies here, unlike `alerts.device_id`'s cross-domain
        // soft reference to "Устройства".
        manager
            .create_table(
                Table::create()
                    .table(AlertComments::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AlertComments::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(AlertComments::AlertId).uuid().not_null())
                    .col(ColumnDef::new(AlertComments::Author).text().not_null())
                    .col(
                        ColumnDef::new(AlertComments::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(ColumnDef::new(AlertComments::Text).text().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .from(AlertComments::Table, AlertComments::AlertId)
                            .to(Alerts::Table, Alerts::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_alert_comments_alert")
                    .table(AlertComments::Table)
                    .col(AlertComments::AlertId)
                    .to_owned(),
            )
            .await?;

        // ------------------------------------------------------ alert_comment_attachments
        // Files attached to a comment (2026-08-29, direct user request: "вложения к
        // комментариям тревог: файл/изображение/видео") — "Blob в БД", not a filesystem
        // path, so an attachment lives wherever the `alerts` domain is already routed
        // to, no extra storage location to configure/back up. Same-domain FK to
        // `alert_comments`, so `ON DELETE CASCADE` applies here too.
        manager
            .create_table(
                Table::create()
                    .table(AlertCommentAttachments::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AlertCommentAttachments::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(AlertCommentAttachments::CommentId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AlertCommentAttachments::Filename)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AlertCommentAttachments::ContentType)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AlertCommentAttachments::Size)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AlertCommentAttachments::Data)
                            .blob()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                AlertCommentAttachments::Table,
                                AlertCommentAttachments::CommentId,
                            )
                            .to(AlertComments::Table, AlertComments::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_alert_comment_attachments_comment")
                    .table(AlertCommentAttachments::Table)
                    .col(AlertCommentAttachments::CommentId)
                    .to_owned(),
            )
            .await?;

        // ------------------------------------------------------------------- roles
        // Named, reusable per-domain permission bundles (2026-08-27, design-artifact
        // parity pass, round 5: "система не имеет фиксированной роли, только именованные
        // списки доступа" — a proper Roles model, a user just picks one, doesn't set
        // per-domain permissions directly). Replaces the earlier flat `user_permissions`
        // table entirely (not layered on top of it) — one way to grant domain access, not
        // two overlapping ones. `name` unique, same discipline as `Users::Username`.
        manager
            .create_table(
                Table::create()
                    .table(Roles::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Roles::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Roles::Name).string_len(KEY_LEN).not_null())
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_roles_name")
                    .table(Roles::Table)
                    .col(Roles::Name)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // ------------------------------------------------------------------- users
        // Local authentication (2026-08-21, direct user request — "логика авторизации и
        // аутентификации... для rest, так и для webui... permissions... чтение, запись,
        // для различных доменов"). External providers (LDAP/Kerberos/OAuth/cloud, see
        // AggreGate's own plugin family — `discovery/CLAUDE.md`'s "Обзор механизмов
        // аутентификации...") are explicitly deferred; only local password auth ships
        // here, but the shape (one `authenticate` outcome -> one internal user, permissions
        // keyed by user id, not by auth method) is the same one those plugins would slot
        // into later without a redesign.
        //
        // `role_id` (2026-08-27, see `Roles::Table` above) — `SET NULL` on the role's own
        // deletion, not `CASCADE`: removing a role should unassign the users who had it
        // (back to "no domain access", same "absence = no access" convention as before),
        // never delete the accounts themselves.
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Users::Id).uuid().not_null().primary_key())
                    .col(
                        ColumnDef::new(Users::Username)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(ColumnDef::new(Users::PasswordHash).text().not_null())
                    .col(
                        ColumnDef::new(Users::IsAdmin)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(Users::MustChangePassword)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(Users::RoleId).uuid())
                    .col(
                        ColumnDef::new(Users::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Users::Table, Users::RoleId)
                            .to(Roles::Table, Roles::Id)
                            .on_delete(ForeignKeyAction::SetNull),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_users_username")
                    .table(Users::Table)
                    .col(Users::Username)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // ----------------------------------------------------------------- sessions
        // Opaque bearer/cookie session tokens — `token_hash` (SHA-256 of the token the
        // client actually holds) is the primary key, never the raw token itself, so a
        // database read (backup, dump, `SELECT *`) can't be turned directly into a valid
        // session the way storing the raw token would allow.
        manager
            .create_table(
                Table::create()
                    .table(Sessions::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Sessions::TokenHash)
                            .string_len(KEY_LEN)
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Sessions::UserId).uuid().not_null())
                    .col(
                        ColumnDef::new(Sessions::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Sessions::ExpiresAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Sessions::Table, Sessions::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_sessions_user")
                    .table(Sessions::Table)
                    .col(Sessions::UserId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_sessions_expires")
                    .table(Sessions::Table)
                    .col(Sessions::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        // --------------------------------------------------------- role_permissions
        // Classic per-domain read/write, flat `(role, domain) -> level` — same shape the
        // superseded `user_permissions` table had, just keyed by role instead of by user
        // (see `Roles::Table`'s docs above for why). `discovery` has exactly 8 fixed
        // domains, not an arbitrarily deep context tree, so this flat table (not
        // AggreGate's context-path-pattern ACL — `discovery/CLAUDE.md`'s auth survey) is
        // still the right shape. Missing row for a `(role, domain)` pair means no access
        // at all for that role (same "absence = default" convention as `queue_control`).
        manager
            .create_table(
                Table::create()
                    .table(RolePermissions::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(RolePermissions::RoleId).uuid().not_null())
                    .col(
                        ColumnDef::new(RolePermissions::Domain)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(RolePermissions::Level)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(RolePermissions::RoleId)
                            .col(RolePermissions::Domain),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(RolePermissions::Table, RolePermissions::RoleId)
                            .to(Roles::Table, Roles::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // ---------------------------------------------------------- journal_entries
        // Audit trail for the "Журнал" feature — who did what, in which functional area,
        // when. Written by `discovery-web`'s `require_domain_permission`/`require_admin`
        // middleware, not tied to any single routed `Domain` (an audit log about every
        // domain doesn't belong to one of them) — lives wherever `Settings` resolves to,
        // same treatment as `users`/`sessions`/`roles` above.
        manager
            .create_table(
                Table::create()
                    .table(JournalEntries::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(JournalEntries::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(JournalEntries::Ts)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(JournalEntries::Username)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(JournalEntries::Domain)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(ColumnDef::new(JournalEntries::Action).text().not_null())
                    .col(
                        ColumnDef::new(JournalEntries::Method)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(ColumnDef::new(JournalEntries::Path).text().not_null())
                    // Short identifier of the specific thing acted on (a profile/discovery
                    // config name, a device IP, a role name, ...) — nullable, `None` for
                    // fleet-wide/singleton actions (bulk device toggle, poll-interval
                    // settings) that have no single object. Plain text, not folded into
                    // `details`, specifically so it's cheaply searchable (`idx`-free LIKE,
                    // same `JournalListQuery::search` OR-clause as username/domain/action).
                    .col(ColumnDef::new(JournalEntries::Object).text())
                    // Optional small JSON payload — a before/after diff for an edit, or a
                    // few named counters for an action that isn't a diff (e.g. "N jobs
                    // deleted"). Deliberately NOT a copy of the whole edited entity — see
                    // `discovery_web::json_diff`'s docs for the size-capping/redaction
                    // discipline that keeps this column proportional to what changed, not
                    // to the size of the entity, and never containing a password/SNMP
                    // community.
                    .col(ColumnDef::new(JournalEntries::Details).json())
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_journal_entries_ts")
                    .table(JournalEntries::Table)
                    .col(JournalEntries::Ts)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_journal_entries_domain")
                    .table(JournalEntries::Table)
                    .col(JournalEntries::Domain)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_journal_entries_username")
                    .table(JournalEntries::Table)
                    .col(JournalEntries::Username)
                    .to_owned(),
            )
            .await?;

        // ------------------------------------------------------------ queue_control
        // Whole-queue pause flag (2026-08-21, direct user request — "приостанавливать
        // задачи... очищать очередь целиком или приостанавливать" — pausing an entire
        // `QueueKind`, not just one job). One row per paused queue; an unpaused queue (the
        // default/common case) simply has no row at all — see
        // `discovery_queue::JobQueueStore::is_queue_paused`'s docs for why "no row" reads as
        // `false` rather than every queue needing to be seeded up front.
        manager
            .create_table(
                Table::create()
                    .table(QueueControl::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(QueueControl::QueueType)
                            .string_len(KEY_LEN)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(QueueControl::Paused)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;

        // ------------------------------------------------------ maintenance_windows
        // Brand-new table (2026-09-07, Maintenance windows) — no `has_column` guard
        // needed, same reasoning as `profile_syslog` above: never existed on any
        // previously-deployed stand. No FK on `device_ids` — see
        // `discovery_entities::maintenance_windows`'s module docs.
        manager
            .create_table(
                Table::create()
                    .table(MaintenanceWindows::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(MaintenanceWindows::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(MaintenanceWindows::Name).text().not_null())
                    .col(
                        ColumnDef::new(MaintenanceWindows::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(MaintenanceWindows::StartsAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(MaintenanceWindows::EndsAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(MaintenanceWindows::Subnets)
                            .json()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(MaintenanceWindows::Profiles)
                            .json()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(MaintenanceWindows::DeviceIds)
                            .json()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(MaintenanceWindows::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(MaintenanceWindows::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;
        // `AlertEvalHandler` loads every window once per device per `AlertEval` tick and
        // filters `enabled`/time-range in application code (see
        // `discovery_config_store::is_device_under_maintenance`'s docs on why matching
        // can't be pushed into SQL — subnet/profile matching isn't a portable predicate
        // across Postgres/MySQL/SQLite) — this index just makes that "load every
        // currently-enabled window" scan cheap on a large table instead of a full scan.
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_maintenance_windows_enabled")
                    .table(MaintenanceWindows::Table)
                    .col(MaintenanceWindows::Enabled)
                    .to_owned(),
            )
            .await?;

        // ------------------------------------------------------ notification_channels
        // Brand-new table (2026-09-10, notification channels + matrix) — no `has_column`
        // guard needed, never existed on any previously-deployed stand. No FK on `user_id`
        // — see `discovery_entities::notification_channels`'s module docs (cross-domain
        // reasoning, same as `alerts.device_id`).
        manager
            .create_table(
                Table::create()
                    .table(NotificationChannels::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(NotificationChannels::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(NotificationChannels::UserId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(NotificationChannels::Kind)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(NotificationChannels::Target)
                            .text()
                            .not_null(),
                    )
                    .col(ColumnDef::new(NotificationChannels::Secret).text().null())
                    .col(
                        ColumnDef::new(NotificationChannels::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(NotificationChannels::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(NotificationChannels::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;
        // Self-service "list my channels" (`GET /api/notifications/channels`) is the only
        // read pattern this table gets — one index makes that a lookup, not a full scan.
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_notification_channels_user_id")
                    .table(NotificationChannels::Table)
                    .col(NotificationChannels::UserId)
                    .to_owned(),
            )
            .await?;

        // ------------------------------------------------------ notification_rules
        // Brand-new table (2026-09-10) — the notification matrix. No FK on
        // `device_ids`/`recipients` — see `discovery_entities::notification_rules`'s
        // module docs.
        manager
            .create_table(
                Table::create()
                    .table(NotificationRules::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(NotificationRules::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(NotificationRules::Name).text().not_null())
                    .col(
                        ColumnDef::new(NotificationRules::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(NotificationRules::MinLevel)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(ColumnDef::new(NotificationRules::Subnets).json().not_null())
                    .col(
                        ColumnDef::new(NotificationRules::Profiles)
                            .json()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(NotificationRules::DeviceIds)
                            .json()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(NotificationRules::ActiveFrom)
                            .string_len(8)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(NotificationRules::ActiveTo)
                            .string_len(8)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(NotificationRules::DaysOfWeek)
                            .json()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(NotificationRules::NotifyOnActivate)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(NotificationRules::NotifyOnClear)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(NotificationRules::Recipients)
                            .json()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(NotificationRules::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(NotificationRules::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;
        // Same reasoning as `idx_maintenance_windows_enabled` — `AlertEvalHandler::
        // dispatch_notifications` loads every rule once per Activated/Cleared transition
        // and matches in application code.
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_notification_rules_enabled")
                    .table(NotificationRules::Table)
                    .col(NotificationRules::Enabled)
                    .to_owned(),
            )
            .await?;

        // ------------------------------------------------------ topology_rules
        // Brand-new table (2026-09-16) — provider-authored Rhai extraction rules, see
        // `discovery_entities::topology_rules`'s module docs. `name` (not `id`) is what
        // `topology_device_keys`/`topology_claims` FK against — needs its own unique index
        // since (unlike `profiles.name`) it isn't the primary key here.
        manager
            .create_table(
                Table::create()
                    .table(TopologyRules::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(TopologyRules::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(TopologyRules::Name)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TopologyRules::MyKeyExpression)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TopologyRules::ClaimedNeighborsExpression)
                            .text()
                            .null(),
                    )
                    .col(ColumnDef::new(TopologyRules::RankExpression).text().null())
                    .col(ColumnDef::new(TopologyRules::WatchedMetrics).json().null())
                    .col(
                        ColumnDef::new(TopologyRules::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(TopologyRules::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TopologyRules::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_topology_rules_name")
                    .table(TopologyRules::Table)
                    .col(TopologyRules::Name)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // ------------------------------------------------------ topology_device_keys
        // `rule_name` is a real FK (`ON DELETE CASCADE`) — same domain/DB as
        // `topology_rules` by construction, same reasoning as `profile_metrics.profile_name
        // -> profiles.name`. `device_id` is deliberately not an FK — `Devices` can be
        // routed to a different physical database, see
        // `discovery_entities::topology_device_keys`'s module docs.
        manager
            .create_table(
                Table::create()
                    .table(TopologyDeviceKeys::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(TopologyDeviceKeys::RuleName)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TopologyDeviceKeys::DeviceId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TopologyDeviceKeys::MyKey)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(ColumnDef::new(TopologyDeviceKeys::Rank).double().null())
                    .col(
                        ColumnDef::new(TopologyDeviceKeys::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(TopologyDeviceKeys::RuleName)
                            .col(TopologyDeviceKeys::DeviceId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(TopologyDeviceKeys::Table, TopologyDeviceKeys::RuleName)
                            .to(TopologyRules::Table, TopologyRules::Name)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // ------------------------------------------------------ topology_claims
        // "This device claims to see a neighbor with this key" — fully replaced (delete +
        // insert) per `(rule_name, claimer_device_id)` on every recompute, never appended
        // to. `idx_topology_claims_claimed_key` is the index the *reverse* half of
        // `TopologyStore::neighbors_of`'s resolution ("who claims my own key") relies on.
        manager
            .create_table(
                Table::create()
                    .table(TopologyClaims::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(TopologyClaims::RuleName)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TopologyClaims::ClaimerDeviceId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TopologyClaims::ClaimedKey)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TopologyClaims::ObservedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(TopologyClaims::RuleName)
                            .col(TopologyClaims::ClaimerDeviceId)
                            .col(TopologyClaims::ClaimedKey),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(TopologyClaims::Table, TopologyClaims::RuleName)
                            .to(TopologyRules::Table, TopologyRules::Name)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_topology_claims_claimed_key")
                    .table(TopologyClaims::Table)
                    .col(TopologyClaims::RuleName)
                    .col(TopologyClaims::ClaimedKey)
                    .to_owned(),
            )
            .await?;

        // ------------------------------------------------------ topology_hierarchy_overrides
        // Manual pin of which side of an edge is upstream — the escape hatch for when
        // `topology_rules.rank_expression` can't determine direction on its own (tie, or a
        // customer without disciplined role/profile data at all). Scoped per `rule_name`,
        // same as every other topology table: there is no cross-rule merged graph anywhere
        // in this feature, so a rule-agnostic override table would be the first such concept
        // and would also allow the meaningless state "override for a pair with no edge under
        // this rule". `device_a`/`device_b` are canonicalized (min, max) by the store layer,
        // same convention `discovery_topology::ResolvedEdge` already uses. `upstream_device_id`
        // must equal `device_a` or `device_b` — enforced in application code (REST + store),
        // not a DB `CHECK` (this project doesn't use those anywhere, cross-backend).
        manager
            .create_table(
                Table::create()
                    .table(TopologyHierarchyOverrides::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(TopologyHierarchyOverrides::RuleName)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TopologyHierarchyOverrides::DeviceA)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TopologyHierarchyOverrides::DeviceB)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TopologyHierarchyOverrides::UpstreamDeviceId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TopologyHierarchyOverrides::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(TopologyHierarchyOverrides::RuleName)
                            .col(TopologyHierarchyOverrides::DeviceA)
                            .col(TopologyHierarchyOverrides::DeviceB),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                TopologyHierarchyOverrides::Table,
                                TopologyHierarchyOverrides::RuleName,
                            )
                            .to(TopologyRules::Table, TopologyRules::Name)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // ------------------------------------------------------ group_alert_rules
        // Brand-new table (2026-09-16) — provider-authored Rhai cause/effect rules for
        // group-alert suppression, see `discovery_entities::group_alert_rules`'s module
        // docs. Unlike `topology_rules`, `name` here is a display label only — nothing
        // joins against it, so no unique index.
        manager
            .create_table(
                Table::create()
                    .table(GroupAlertRules::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(GroupAlertRules::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(GroupAlertRules::Name)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GroupAlertRules::CauseExpression)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GroupAlertRules::EffectExpression)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GroupAlertRules::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(GroupAlertRules::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GroupAlertRules::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // ------------------------------------------------------ assistant_conversations
        // Brand-new table (2026-09-18) — AI assistant chat conversations, see
        // `discovery_entities::assistant_conversations`'s module docs. Not one of the 12
        // routed domains — self-service, scoped by `owner_user_id`, no FK to `users`
        // (outside the independently-routable domain set).
        manager
            .create_table(
                Table::create()
                    .table(AssistantConversations::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AssistantConversations::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(AssistantConversations::OwnerUserId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AssistantConversations::Title)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AssistantConversations::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AssistantConversations::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AssistantConversations::AutoApproveWrites)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;

        // Retrofit for a stand that already ran this migration before `AutoApproveWrites`
        // existed here (2026-09-18, direct user request — a per-conversation opt-in
        // bypass of confirm-before-write, Claude-Code-style) — same `has_column` gate as
        // `jobs.paused` above, not `add_column_if_not_exists`'s own (SQLite-inert) guard.
        // On a genuinely fresh install this is a no-op: `create_table` above already
        // included the column.
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

        // ------------------------------------------------------ assistant_messages
        // Brand-new table (2026-09-18) — one row per turn in an AI assistant conversation,
        // see `discovery_entities::assistant_messages`'s module docs. `sequence` (not
        // `created_at`) is the stable ordering key within a `conversation_id`.
        manager
            .create_table(
                Table::create()
                    .table(AssistantMessages::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AssistantMessages::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(AssistantMessages::ConversationId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AssistantMessages::Sequence)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AssistantMessages::Role)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(ColumnDef::new(AssistantMessages::Content).text())
                    .col(ColumnDef::new(AssistantMessages::ToolCall).json())
                    .col(
                        ColumnDef::new(AssistantMessages::ToolCallStatus)
                            .string_len(KEY_LEN)
                            .not_null(),
                    )
                    .col(ColumnDef::new(AssistantMessages::ToolResult).json())
                    .col(
                        ColumnDef::new(AssistantMessages::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Reverse dependency order — children (FK-holding tables) before parents.
        for table in [
            Sessions::Table.into_iden(),
            Users::Table.into_iden(),
            RolePermissions::Table.into_iden(),
            Roles::Table.into_iden(),
            JournalEntries::Table.into_iden(),
            QueueControl::Table.into_iden(),
            MaintenanceWindows::Table.into_iden(),
            NotificationChannels::Table.into_iden(),
            NotificationRules::Table.into_iden(),
            AssistantMessages::Table.into_iden(),
            AssistantConversations::Table.into_iden(),
            GroupAlertRules::Table.into_iden(),
            TopologyHierarchyOverrides::Table.into_iden(),
            TopologyDeviceKeys::Table.into_iden(),
            TopologyClaims::Table.into_iden(),
            TopologyRules::Table.into_iden(),
            AlertCommentAttachments::Table.into_iden(),
            AlertComments::Table.into_iden(),
            Alerts::Table.into_iden(),
            Settings::Table.into_iden(),
            Logs::Table.into_iden(),
            DiscoverySubnetLabels::Table.into_iden(),
            DiscoverySubnetOids::Table.into_iden(),
            DiscoverySubnets::Table.into_iden(),
            DiscoveryConfigs::Table.into_iden(),
            ProfileServiceChecks::Table.into_iden(),
            ProfileSyslog::Table.into_iden(),
            ProfileTraps::Table.into_iden(),
            ProfileAlerts::Table.into_iden(),
            ProfileMetrics::Table.into_iden(),
            Profiles::Table.into_iden(),
            DeviceMetricHistory::Table.into_iden(),
            DeviceMetrics::Table.into_iden(),
            DeviceMetricSettings::Table.into_iden(),
            Devices::Table.into_iden(),
            Jobs::Table.into_iden(),
        ] {
            manager
                .drop_table(Table::drop().table(table).if_exists().to_owned())
                .await?;
        }
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Jobs {
    Table,
    Id,
    QueueType,
    Payload,
    DedupeKey,
    State,
    Attempts,
    MaxAttempts,
    LockedBy,
    LockedAt,
    LastError,
    CreatedAt,
    UpdatedAt,
    Paused,
}

#[derive(DeriveIden)]
enum QueueControl {
    Table,
    QueueType,
    Paused,
}

#[derive(DeriveIden)]
enum MaintenanceWindows {
    Table,
    Id,
    Name,
    Enabled,
    StartsAt,
    EndsAt,
    /// `Vec<discovery_config_store::SubnetTarget>` as JSON — see
    /// `discovery_entities::maintenance_windows`'s module docs.
    Subnets,
    /// `Vec<String>` (profile names) as JSON.
    Profiles,
    /// `Vec<Uuid>` as JSON.
    DeviceIds,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum NotificationChannels {
    Table,
    Id,
    UserId,
    /// `discovery_core::NotificationChannelKind::as_str()`.
    Kind,
    Target,
    Secret,
    Enabled,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum NotificationRules {
    Table,
    Id,
    Name,
    Enabled,
    /// `discovery_core::AlertLevel::as_str()`.
    MinLevel,
    /// `Vec<discovery_config_store::SubnetTarget>` as JSON.
    Subnets,
    /// `Vec<String>` (profile names) as JSON.
    Profiles,
    /// `Vec<Uuid>` as JSON.
    DeviceIds,
    /// `"HH:MM:SS"` text — see `discovery_entities::notification_rules`'s module docs.
    ActiveFrom,
    ActiveTo,
    /// `Vec<String>` (`chrono::Weekday` short names) as JSON.
    DaysOfWeek,
    NotifyOnActivate,
    NotifyOnClear,
    /// `Vec<Uuid>` (`users.id`) as JSON.
    Recipients,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum TopologyRules {
    Table,
    Id,
    /// Unique (`idx_topology_rules_name`) — what `TopologyDeviceKeys`/`TopologyClaims`
    /// FK against, not `Id`. See `discovery_entities::topology_rules`'s module docs.
    Name,
    MyKeyExpression,
    ClaimedNeighborsExpression,
    /// `None` = this rule doesn't participate in hierarchy at all. Lower value = closer to
    /// the core/more upstream — see `discovery_dsl::topology::TopologyEvaluator::evaluate_rank`.
    RankExpression,
    /// `Vec<String>` as JSON, or `NULL` = auto-detect from both expressions above.
    WatchedMetrics,
    Enabled,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum TopologyDeviceKeys {
    Table,
    RuleName,
    DeviceId,
    MyKey,
    /// `NULL` = this rule has no `RankExpression`, or it evaluated to `()`/a non-numeric
    /// result for this device. See `discovery_topology::apply_hierarchy`.
    Rank,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum TopologyClaims {
    Table,
    RuleName,
    ClaimerDeviceId,
    ClaimedKey,
    ObservedAt,
}

#[derive(DeriveIden)]
enum TopologyHierarchyOverrides {
    Table,
    RuleName,
    DeviceA,
    DeviceB,
    UpstreamDeviceId,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum GroupAlertRules {
    Table,
    Id,
    /// Display label only — unlike `TopologyRules::Name`, nothing joins against this
    /// column, so no unique index.
    Name,
    CauseExpression,
    EffectExpression,
    Enabled,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum AssistantConversations {
    Table,
    Id,
    OwnerUserId,
    Title,
    CreatedAt,
    UpdatedAt,
    AutoApproveWrites,
}

#[derive(DeriveIden)]
enum AssistantMessages {
    Table,
    Id,
    ConversationId,
    Sequence,
    Role,
    Content,
    ToolCall,
    ToolCallStatus,
    ToolResult,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
    Username,
    PasswordHash,
    IsAdmin,
    MustChangePassword,
    RoleId,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Sessions {
    Table,
    TokenHash,
    UserId,
    CreatedAt,
    ExpiresAt,
}

#[derive(DeriveIden)]
enum Roles {
    Table,
    Id,
    Name,
}

#[derive(DeriveIden)]
enum RolePermissions {
    Table,
    RoleId,
    Domain,
    Level,
}

#[derive(DeriveIden)]
enum JournalEntries {
    Table,
    Id,
    Ts,
    Username,
    Domain,
    Action,
    Method,
    Path,
    Object,
    Details,
}

#[derive(DeriveIden)]
enum Devices {
    Table,
    DeviceId,
    Ip,
    Profile,
    ProfileVersion,
    PollGeneration,
    /// Replaces the former separate `SnmpVersion`/`SnmpCommunity` text columns
    /// (2026-08-29, SNMPv3 support) — one JSON blob holding a serialized
    /// `discovery_core::SnmpAuth` (community *or* USM v3), since v3 has no community
    /// string at all and needed a materially different shape, not just a third
    /// `SnmpVersion` value. `SeaOrmDeviceStore` encrypts `SnmpV3Credentials`'
    /// passphrases in place before this blob is written, decrypts after reading it back
    /// — see `discovery_core::secret`'s docs. On an already-deployed stand (not a fresh
    /// install) the old `snmp_version`/`snmp_community` columns physically remain,
    /// unused — no code references them anymore, dropping them isn't worth a
    /// cross-backend `DROP COLUMN` (SQLite's support for it is version-dependent).
    SnmpAuth,
    SnmpPort,
    /// Serialized `discovery_core::SshAuth` (password or private key) — the SSH
    /// counterpart of `SnmpAuth`, added 2026-09-07 for SSH CLI-pull metrics (see
    /// `docs/Roadmap.md`'s "Сделано" entry). `NULL` = no SSH credentials configured for
    /// this device yet. Always ciphertext at rest (`SeaOrmDeviceStore` encrypts/decrypts
    /// at the read/write boundary via `discovery_core::secret::encrypt_ssh_auth_secrets`/
    /// `decrypt_ssh_auth_secrets`) — unlike `SnmpAuth`, there is no plaintext-ok branch
    /// here at all, see `discovery_core::SshAuth`'s docs.
    SshAuth,
    /// The username `SshAuth` authenticates as — kept as its own column rather than
    /// folded into the `SshAuth` JSON blob, since it isn't itself secret (mirrors why
    /// `SnmpPort` is a plain column instead of living inside the `SnmpAuth` blob).
    SshUsername,
    SshPort,
    /// SHA256 fingerprint of this device's pinned SSH host key — see the `has_column`
    /// retrofit block in `up()` above for the CWE-295 fix this exists for.
    SshHostKeyFingerprint,
    DiscoveredAt,
    UpdatedAt,
    PingOk,
    PingCheckedAt,
    /// The share of the `1 + retries` ICMP attempts in the most recent
    /// `ReachabilityPollHandler` tick that got **no** reply, `0.0`-`100.0` — added
    /// 2026-09-14, `docs/Roadmap.md` "До релиза" item 5 ("Packet loss % не собирается
    /// вообще"), a direct honest-porting prerequisite for AggreGate's ICMP-packet-loss
    /// alert. `NULL` until the first reachability tick after this column exists, same
    /// "nothing checked yet" convention as `PingOk`/`PingCheckedAt` themselves. See
    /// `discovery_ping::PingOutcome`'s docs for why this needs every attempt to actually
    /// run (no more stopping at the first success).
    PingLossPct,
    SnmpOk,
    SnmpCheckedAt,
    Enabled,
    PingFailingSince,
    IpSortKey,
}

#[derive(DeriveIden)]
enum DeviceMetricSettings {
    Table,
    DeviceId,
    Name,
    Enabled,
}

#[derive(DeriveIden)]
enum DeviceMetrics {
    Table,
    DeviceId,
    Name,
    Value,
    Error,
    PolledAt,
    LastAttemptAt,
}

#[derive(DeriveIden)]
enum DeviceMetricHistory {
    Table,
    Id,
    DeviceId,
    Name,
    Value,
    Error,
    FirstObservedAt,
    LastObservedAt,
}

#[derive(DeriveIden)]
enum Profiles {
    Table,
    Name,
    Priority,
    MatchExpression,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum ProfileMetrics {
    Table,
    ProfileName,
    Name,
    Oid,
    /// Table-metric column map (`discovery_dsl::MetricSpec::Detailed::columns`) — `NULL`
    /// = scalar, `{}` = table in "collect everything" mode, `{"name": "subid", ...}` =
    /// table with curated columns. See that field's docs for the full three-state
    /// contract this column stores verbatim as JSON.
    Columns,
    HistoryRetentionSecs,
    Schedule,
    Enabled,
    HistoryKeepLastSuccess,
    HistoryKeepLastAttempt,
    /// SSH CLI-pull metrics (2026-09-07) — `NULL` = an SNMP-sourced row (`Oid`/`Detailed`,
    /// `oid` holds the real value), non-`NULL` = a `discovery_dsl::MetricSpec::SshCommand`
    /// row (`oid` is unused, always `""`). See `Devices::SshAuth`'s docs above for the
    /// analogous device-credentials side of this same feature.
    Command,
    /// Serialized `discovery_dsl::DeriveKind` (`"rate"`/`"delta"`) — `NULL` = no derived
    /// value for this metric. See `MetricSpec::Detailed::derive`'s docs.
    Derive,
}

#[derive(DeriveIden)]
enum ProfileAlerts {
    Table,
    ProfileName,
    Name,
    Level,
    RowMetric,
    RowKeyExpression,
    Expression,
    DeactivationExpression,
    FactsExpression,
    Message,
    ClearAfterSeconds,
    ActivateAfterSeconds,
    FlapWindowSeconds,
    FlapThreshold,
    Enabled,
}

#[derive(DeriveIden)]
enum ProfileTraps {
    Table,
    ProfileName,
    Name,
    /// `Vec<discovery_dsl::TrapEventSpec>` as JSON — see `discovery_entities::profile_traps`'s
    /// module docs for why this one nested collection stays a JSON column instead of its
    /// own child table.
    Variants,
    TtlSecs,
    HistoryRetentionSecs,
}

#[derive(DeriveIden)]
enum ProfileSyslog {
    Table,
    ProfileName,
    Name,
    /// `Vec<discovery_dsl::SyslogEventSpec>` as JSON — see
    /// `discovery_entities::profile_syslog`'s module docs.
    Variants,
    TtlSecs,
    HistoryRetentionSecs,
}

#[derive(DeriveIden)]
enum ProfileServiceChecks {
    Table,
    ProfileName,
    /// `Vec<discovery_dsl::ServiceCheckSpec>` as JSON — see
    /// `discovery_entities::profile_service_checks`'s module docs for why this table is
    /// one row per *profile*, unlike `ProfileTraps`/`ProfileSyslog`'s one row per binding.
    Checks,
    /// Serialized `discovery_core::Schedule` — `NULL` = use the process-wide default
    /// (`poll_intervals.service_check_secs`).
    Schedule,
    HistoryRetentionSecs,
}

#[derive(DeriveIden)]
enum DiscoveryConfigs {
    Table,
    Name,
    Enabled,
    Schedule,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum DiscoverySubnets {
    Table,
    SubnetId,
    DiscoveryConfigName,
    Ip,
    Mask,
    Port,
    /// Replaces the former separate `SnmpVersions`/`ReadCommunities` json columns
    /// (2026-08-29, SNMPv3 support) — see `Devices::SnmpAuth`'s docs above for the same
    /// reasoning, applied here to the subnet-level candidate list instead of a single
    /// negotiated device credential.
    Credentials,
    SnmpTimeoutMs,
    SnmpRetries,
    CreateDeadDevices,
}

#[derive(DeriveIden)]
enum DiscoverySubnetOids {
    Table,
    SubnetId,
    Name,
    Oid,
    Columns,
}

#[derive(DeriveIden)]
enum DiscoverySubnetLabels {
    Table,
    SubnetId,
    Name,
    Value,
}

#[derive(DeriveIden)]
enum Logs {
    Table,
    Id,
    Ts,
    Level,
    Target,
    Message,
    Fields,
}

#[derive(DeriveIden)]
enum Settings {
    Table,
    Key,
    Value,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Alerts {
    Table,
    Id,
    DeviceId,
    DeviceIp,
    Name,
    RowKey,
    Level,
    Message,
    State,
    Facts,
    FirstSeen,
    LastSeen,
    ClearedAt,
    ClosedBy,
    AcknowledgedBy,
    AcknowledgedAt,
    SnoozedUntil,
    SnoozedBy,
    AutoClearReason,
    Flapping,
    SuppressionReason,
    /// Soft reference to another row in this same table — see the `has_column` block
    /// above for why this isn't a real `FOREIGN KEY`.
    SuppressedByAlertId,
    /// Soft reference to another row in this same table — see the `has_column` block
    /// above for why this isn't a real `FOREIGN KEY`.
    ReopenedFromAlertId,
}

#[derive(DeriveIden)]
enum AlertComments {
    Table,
    Id,
    AlertId,
    Author,
    CreatedAt,
    Text,
}

#[derive(DeriveIden)]
enum AlertCommentAttachments {
    Table,
    Id,
    CommentId,
    Filename,
    ContentType,
    Size,
    Data,
}
