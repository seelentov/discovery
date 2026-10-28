//! `ConnectionRegistry` — resolves the 8-domain [`discovery_bootstrap::DomainRouting`]
//! against [`discovery_bootstrap::StorageConfig::default_database`], dedupes to the set
//! of physically distinct named connections actually needed, and opens exactly one
//! `sea_orm::DatabaseConnection` per used name — direct user request 2026-08-18: "если
//! несколько блоков будут настроены на один конфиг БД, то это будет один коннект. Не
//! поднимать коннект, если он не используется, просто лежит в настройках, но ни один
//! блок его не использует."
//!
//! Runs `discovery_migration::Migrator::up` once per unique connection it actually opens
//! — same "migrate right after the pool is created, before any store touches the
//! database" discipline `discovery-agent::main::build_stores` already followed pre-2026-
//! 08-18 (see that function's docs for the exact bug this avoids: independently-embedded
//! migration sets going out of sync with each other).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context;
use discovery_bootstrap::{DatabaseConnConfig, DbKind, DomainRouting, StorageConfig};
use sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseConnection, Statement};
use sea_orm_migration::MigratorTrait;

/// A domain's physical connection — **not always a `sea_orm::DatabaseConnection`** as of
/// 2026-08-18 (direct user request: "Может сразу добавить поддержку timescale и
/// clickhouse?", following the multi-DB rewrite's original single-backend-type design).
/// TimescaleDB needed no new variant here — it's a Postgres extension, reached through the
/// ordinary [`DomainConnection::SeaOrm`] path (see [`maybe_enable_timescale`]'s docs).
/// ClickHouse and Cassandra genuinely do need one each: sea-orm/sea-query have no driver
/// for either, so they connect via their own native clients instead (`clickhouse`'s HTTP
/// client, `scylla`'s CQL client).
///
/// Each non-`SeaOrm` variant is restricted to exactly one domain by
/// `discovery_bootstrap::Config::validate` — `ClickHouse` to `Domain::Logs`, `Cassandra` to
/// `Domain::DeviceMetrics` — see `discovery_bootstrap::DbKind::ClickHouse`/`DbKind::Cassandra`'s
/// docs for why each was chosen and why every *other* domain doesn't fit that particular
/// backend.
#[derive(Clone)]
pub enum DomainConnection {
    SeaOrm(DatabaseConnection),
    ClickHouse(clickhouse::Client),
    /// `scylla::Session` isn't `Clone` itself (unlike `DatabaseConnection`/`clickhouse::Client`,
    /// which wrap their pools in an `Arc` internally) — wrapped here so this whole enum
    /// stays cheaply `Clone`, consistent with the other variants and with
    /// `ConnectionRegistry::for_domain`'s "cheap to call repeatedly" contract. The `String`
    /// is the keyspace name — unlike `clickhouse::Client` (which bakes its database into
    /// the client at connect time via `with_database`), the session deliberately does
    /// **not** have a keyspace selected yet at this point (it may not exist on a fresh
    /// cluster — see `connect`'s Cassandra branch), so the caller needs the name
    /// separately to create it and switch in (`CassandraDeviceMetricsStore::ensure_schema`).
    Cassandra(std::sync::Arc<scylla::Session>, String),
}

impl DomainConnection {
    /// Unwraps the `SeaOrm` variant — for the seven domains that, per
    /// `discovery_bootstrap::Config::validate`, can *only* ever resolve to one (everything
    /// except `Domain::Logs`/`Domain::DeviceMetrics`). Panics if that invariant somehow
    /// doesn't hold: the same "should have been caught by `Config::validate`" contract this
    /// module already uses elsewhere (see e.g. `ConnectionRegistry::build`'s `.expect(...)`
    /// calls) — not a runtime possibility a caller needs to handle gracefully, a config bug
    /// validation already guards against.
    pub fn expect_sea_orm(self, domain: Domain) -> DatabaseConnection {
        match self {
            DomainConnection::SeaOrm(conn) => conn,
            other => panic!(
                "domain {domain:?} resolved to a {} connection — Config::validate should already have rejected this configuration",
                other.kind_name()
            ),
        }
    }

    fn kind_name(&self) -> &'static str {
        match self {
            DomainConnection::SeaOrm(_) => "SeaOrm",
            DomainConnection::ClickHouse(_) => "ClickHouse",
            DomainConnection::Cassandra(_, _) => "Cassandra",
        }
    }
}

/// The eight independently-routable data domains — direct user request 2026-08-18, see
/// `discovery_bootstrap::DomainRouting`'s docs for the full rationale (in particular why
/// `Devices` and `DeviceMetrics` are separate despite both concerning "a device"). Moved to
/// `discovery-core` 2026-08-21 (see that module's docs) and re-exported here so every
/// existing `discovery_db::Domain` call site keeps working unchanged.
pub use discovery_core::Domain;

fn routing_field<'a>(domain: Domain, routing: &'a DomainRouting) -> &'a Option<String> {
    match domain {
        Domain::Settings => &routing.settings,
        Domain::Alerts => &routing.alerts,
        Domain::Devices => &routing.devices,
        Domain::DiscoveryConfigs => &routing.discovery_configs,
        Domain::DeviceMetrics => &routing.device_metrics,
        Domain::Profiles => &routing.profiles,
        Domain::Logs => &routing.logs,
        Domain::Jobs => &routing.jobs,
        Domain::MaintenanceWindows => &routing.maintenance_windows,
        Domain::Notifications => &routing.notifications,
        Domain::Topology => &routing.topology,
        Domain::GroupAlerts => &routing.group_alerts,
    }
}

/// Sentinel name for the implicit, zero-configuration in-process connection — used when
/// `StorageConfig::databases` is empty (no `config.toml` `[storage]` section at all, or
/// an explicitly empty one). Never a name a user can type themselves (`DatabaseConnConfig`
/// names come only from `storage.databases`, which is empty in this case) — see
/// `Config::validate`'s docs for why a non-empty `databases` always has a real default.
const IMPLICIT_MEMORY: &str = "__implicit_memory__";

pub struct ConnectionRegistry {
    /// One entry per physically distinct connection actually opened — keyed by config
    /// name (or [`IMPLICIT_MEMORY`] in the zero-config case).
    connections: HashMap<String, DomainConnection>,
    /// Domain -> which key in `connections` serves it. Precomputed once in [`Self::build`]
    /// so [`Self::for_domain`] is a plain lookup, not a re-resolution.
    resolved: HashMap<Domain, String>,
}

impl ConnectionRegistry {
    /// Connects to every named database at least one domain resolves to — and *only*
    /// those; a `storage.databases` entry nothing routes to (directly or via the default)
    /// is left completely untouched, per the user's explicit requirement quoted in this
    /// module's docs.
    pub async fn build(storage: &StorageConfig) -> anyhow::Result<Self> {
        // Zero-config: no databases configured at all — every domain gets the same one
        // implicit in-process connection, the direct successor of the old `InMemory*`
        // stores' "just works" default (see `discovery_bootstrap::DbKind::Memory`'s docs).
        if storage.databases.is_empty() {
            let conn = connect_memory().await?;
            discovery_migration::Migrator::up(&conn, None).await?;
            let mut connections = HashMap::new();
            connections.insert(IMPLICIT_MEMORY.to_string(), DomainConnection::SeaOrm(conn));
            let resolved = Domain::ALL
                .iter()
                .map(|d| (*d, IMPLICIT_MEMORY.to_string()))
                .collect();
            return Ok(Self {
                connections,
                resolved,
            });
        }

        let by_name: HashMap<&str, &DatabaseConnConfig> = storage
            .databases
            .iter()
            .map(|db| (db.name.as_str(), db))
            .collect();
        // `Config::validate` already guarantees this is `Some` whenever `databases` is
        // non-empty — see its docs.
        let default_name = storage
            .default_database
            .as_deref()
            .expect("validated by discovery_bootstrap::Config::load");

        let mut resolved: HashMap<Domain, String> = HashMap::new();
        for domain in Domain::ALL {
            let name = routing_field(domain, &storage.routing)
                .as_deref()
                .unwrap_or(default_name);
            resolved.insert(domain, name.to_string());
        }

        // The whole point of this function: only the *distinct* names actually resolved
        // to above get connected — a configured-but-unreferenced entry in
        // `storage.databases` never causes a connection attempt.
        let mut connections = HashMap::new();
        for name in resolved.values().collect::<std::collections::HashSet<_>>() {
            let config = by_name.get(name.as_str()).expect(
                "routing/default already validated against storage.databases by Config::validate",
            );
            let conn = connect(config).await?;
            match &conn {
                DomainConnection::SeaOrm(db) => {
                    discovery_migration::Migrator::up(db, None).await?;
                    // Best-effort, never fatal — see `maybe_enable_timescale`'s docs.
                    // Only meaningful for Postgres; a no-op for MySQL/SQLite/Memory.
                    maybe_enable_timescale(db).await;
                }
                // `Config::validate` guarantees only `Domain::Logs`/`Domain::DeviceMetrics`
                // can resolve here respectively — each domain's schema is ensured by the
                // caller after construction, mirroring how every sea-orm store already gets
                // its schema from a shared migration rather than from `ConnectionRegistry`
                // reaching into a specific domain crate (see `DomainConnection`'s docs).
                DomainConnection::ClickHouse(_) | DomainConnection::Cassandra(_, _) => {}
            }
            connections.insert(name.clone(), conn);
        }

        Ok(Self {
            connections,
            resolved,
        })
    }

    /// The connection this domain resolves to. Cheap to call repeatedly/cheap to clone —
    /// both `DomainConnection` variants wrap an internally-`Arc`'d client, so two domains
    /// sharing one named config end up holding clones of the exact same pool/client, not
    /// two separate ones (this is *how* "one physical connection, shared" is satisfied —
    /// no extra bookkeeping needed beyond the plain `HashMap` lookup here).
    pub fn for_domain(&self, domain: Domain) -> DomainConnection {
        let name = &self.resolved[&domain];
        self.connections[name].clone()
    }

    /// Convenience for the seven domains that, per `discovery_bootstrap::Config::validate`,
    /// can only ever resolve to a sea-orm connection — see [`DomainConnection::expect_sea_orm`].
    pub fn for_domain_sea_orm(&self, domain: Domain) -> DatabaseConnection {
        self.for_domain(domain).expect_sea_orm(domain)
    }

    /// Which named `storage.databases` entry `domain` resolved to — `None` for the
    /// zero-config implicit in-process connection (never a name a user could have typed).
    /// Added 2026-08-21 so `main.rs` can look up that config's `pool_max_connections` and
    /// warn if it's smaller than the configured worker concurrency needs (see that
    /// module's docs) — the registry already did this resolution once in [`Self::build`],
    /// no reason to make every caller redo `routing_field`/`default_database` lookups
    /// themselves.
    pub fn resolved_database_name(&self, domain: Domain) -> Option<&str> {
        self.resolved
            .get(&domain)
            .map(|s| s.as_str())
            .filter(|&name| name != IMPLICIT_MEMORY)
    }
}

static MEMORY_DB_SEQ: AtomicU64 = AtomicU64::new(0);

/// Builds a URL for a fresh, uniquely-named, shared-cache in-memory SQLite database —
/// deliberately not the bare `sqlite::memory:` shorthand, which mints its own random,
/// process-internal name each time it's *parsed*
/// (`sqlx_sqlite::options::parse::from_db_and_params`), not once per logical database.
/// sea-orm parses a pool's URL exactly once per `Database::connect` call and reuses that
/// one `SqliteConnectOptions` for every connection the resulting pool ever opens, so
/// `sqlite::memory:` already behaves correctly *within* one pool — but [`open_memory_guard`]
/// needs the identical name reachable from a second, independent connection outside that
/// pool, which isn't possible without generating and threading the name ourselves. Every
/// call gets its own unique name, matching `sqlite::memory:`'s existing "fresh separate
/// database per logical connect" behavior (needed since `connect()`, below, opens one of
/// these per distinct `kind = "memory"` entry in `storage.databases`, and they must not
/// collide into a single shared database).
fn fresh_memory_db_url() -> String {
    let n = MEMORY_DB_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("sqlite:file:discovery-memory-db-{n}?mode=memory&cache=shared")
}

/// Opens one extra raw sqlx connection to `url` (a shared-cache in-memory database built
/// by [`fresh_memory_db_url`]) and leaks it for the lifetime of the process.
///
/// Belt-and-suspenders against sqlx ever *reactively* closing and reopening a pool's sole
/// physical connection — a failed `test_before_acquire` ping, a query future dropped
/// mid-flight, or any other reason sqlx decides a connection is unhealthy. `max_connections(1)`
/// plus a huge `idle_timeout`/`max_lifetime` (see [`connect_memory`]) only ever protects
/// against *proactive*, time-based closing of that connection — not this reactive path,
/// where the pool can (however rarely, and regardless of how recently it was last used)
/// close its one connection and open a fresh one to replace it. SQLite deallocates a
/// shared-cache in-memory database the instant its open-connection refcount reaches zero;
/// if the replacement is the *only* connection holding the name open at that instant, the
/// entire database — schema and all — is already gone, and the replacement silently
/// attaches to a brand-new, empty database of the same name instead of erroring. That is
/// exactly the `no such table: users` failure found live during a full e2e run under heavy
/// concurrent load (see `docs/Changelog/2026-09-20 - Аудит перед релизом...md`, finding 1).
/// A second connection that the pool itself never manages, and therefore can never decide
/// to close, keeps the refcount at >= 1 permanently, so this can no longer happen no
/// matter what ends up triggering the pool's own connection to be replaced.
async fn open_memory_guard(url: &str) -> anyhow::Result<()> {
    let opts: sea_orm::sqlx::sqlite::SqliteConnectOptions = url
        .parse()
        .map_err(|e| anyhow::anyhow!("parsing keep-alive guard URL {url:?}: {e}"))?;
    let guard =
        <sea_orm::sqlx::sqlite::SqliteConnection as sea_orm::sqlx::Connection>::connect_with(&opts)
            .await
            .with_context(|| {
                format!("opening keep-alive guard connection for in-memory database {url:?}")
            })?;
    // Leaked on purpose — this connection has no close-triggering event to react to; it
    // must simply stay open, unused, until the process exits.
    Box::leak(Box::new(guard));
    Ok(())
}

async fn connect_memory() -> anyhow::Result<DatabaseConnection> {
    // `sqlite::memory:` is a fresh, separate, empty database *per connection* unless the
    // pool is held to exactly one — see `discovery-devices`/`discovery-queue`/
    // `discovery-alerts`'s `tests/sqlite_integration.rs` docs for the same constraint
    // hit (and worked around identically) while testing the old hand-written SQLite
    // backends. Every domain sharing this single connection is exactly the point: it's
    // the one implicit in-process database, not eight independent ones.
    //
    // **The huge `idle_timeout`/`max_lifetime` below are load-bearing, not defensive
    // paranoia** — found live: sea-orm leaves both unset by default, which means
    // `sqlx::pool::PoolOptions`'s own default (`idle_timeout: Some(10 minutes)`) applies
    // underneath. Past that mark with no traffic, sqlx closes the one physical
    // connection this whole process depends on; the next query then opens a *replacement*
    // connection to `sqlite::memory:`, which is a brand-new, schema-less database —
    // observed as `no such table: users` (and every other table) after a demo instance
    // sat idle for a while, not a migration bug. `ConnectOptions::idle_timeout`/
    // `max_lifetime` only accept a `Duration`, not `Option<Duration>` — there's no
    // direct "disable" call — so a Duration far past any real process uptime is the
    // actual way to express "never" here.
    //
    // That pair only ever covered *proactive* (idle-timer-driven) closing, though — see
    // [`open_memory_guard`]'s docs for the *reactive* half of this same failure class
    // (found live again, under load rather than idleness, in the 2026-09-20 pre-release
    // audit) and why a named `cache=shared` database plus a permanent guard connection is
    // what actually closes that gap.
    const EFFECTIVELY_NEVER: std::time::Duration =
        std::time::Duration::from_secs(60 * 60 * 24 * 365 * 10); // 10 years
    let url = fresh_memory_db_url();
    open_memory_guard(&url).await?;
    let mut opt = ConnectOptions::new(url);
    opt.max_connections(1)
        .idle_timeout(EFFECTIVELY_NEVER)
        .max_lifetime(EFFECTIVELY_NEVER);
    let conn = Database::connect(opt).await?;
    enable_sqlite_foreign_keys(&conn).await?;
    Ok(conn)
}

/// `sea_orm::Database::connect` does **not** turn on SQLite foreign-key enforcement by
/// default (unlike this project's pre-2026-08-18 hand-written `SqliteConnectOptions::foreign_keys(true)`,
/// which every `main.rs` storage branch set explicitly) — found while wiring up the first
/// store whose cascade-delete correctness actually depends on it
/// (`discovery_config_store::SeaOrmProfileStore`, `profile_metrics`/`profile_alerts` ->
/// `profiles`). Without this, every same-domain `ON DELETE CASCADE` the migration declares
/// silently never fires against a SQLite connection — a parent-row delete leaves orphaned
/// child rows instead of cascading. Postgres/MySQL always enforce their FKs regardless, so
/// this is a SQLite-only gap, but both `DbKind::Sqlite` and `DbKind::Memory` need it.
async fn enable_sqlite_foreign_keys(conn: &DatabaseConnection) -> anyhow::Result<()> {
    if conn.get_database_backend() == sea_orm::DatabaseBackend::Sqlite {
        conn.execute_unprepared("PRAGMA foreign_keys = ON;").await?;
    }
    Ok(())
}

/// TimescaleDB needs **no new `DbKind`** — it's a Postgres extension, reached through the
/// ordinary `postgres://` connection `DbKind::Postgres` already builds (see
/// `discovery_bootstrap::DbKind::ClickHouse`'s docs for why ClickHouse, unlike Timescale,
/// *does* need a dedicated variant). Direct user request 2026-08-18: "Может сразу добавить
/// поддержку timescale и clickhouse?".
///
/// Best-effort and **never fatal** — the extension isn't bundled with stock Postgres, so
/// "not installed" is the overwhelmingly common case and must behave exactly like plain
/// Postgres always has (a `discovery_dev`-style local install, this project's own primary
/// dev stand, has no `timescaledb` available — confirmed live). Every failure path here is
/// logged as a `warn!` and swallowed, never propagated — a hypertable conversion is a
/// value-add on top of a working plain-Postgres setup, not a requirement for one.
///
/// **Not domain-aware** — every Postgres connection gets the same full schema regardless
/// of which domain(s) actually route to it (`discovery_migration`'s one migration,
/// `.if_not_exists()` on all 15 tables), so this targets the two genuinely
/// time-series-shaped, append-heavy tables by name wherever they happen to exist:
/// `device_metric_history` and `logs`. Converting an unused, empty one costs nothing.
/// `settings`/`profiles`/`discovery_configs`/`jobs`/etc. are deliberately not candidates —
/// small, point-CRUD, not time-partitioned, nothing to gain from a hypertable.
async fn maybe_enable_timescale(conn: &DatabaseConnection) {
    if conn.get_database_backend() != sea_orm::DatabaseBackend::Postgres {
        return;
    }

    if !timescale_extension_active(conn).await {
        // Try to activate it — succeeds only if the extension's shared library is already
        // installed on the Postgres server (e.g. via `CREATE EXTENSION` being permitted)
        // but not yet enabled on this particular database. A failure here (the extension
        // isn't available on the server at all — the common case) is expected and silent;
        // `timescale_extension_active`'s re-check right after is what actually decides
        // whether to proceed.
        let _ = conn
            .execute_unprepared("CREATE EXTENSION IF NOT EXISTS timescaledb")
            .await;
    }
    if !timescale_extension_active(conn).await {
        return;
    }

    for (table, time_column) in [
        ("device_metric_history", "last_observed_at"),
        ("logs", "ts"),
    ] {
        if let Err(e) = convert_to_hypertable(conn, table, time_column).await {
            tracing::warn!(table, error = %e, "timescaledb: could not convert table into a hypertable, continuing as plain Postgres");
        } else {
            tracing::info!(table, "timescaledb: table is now a compressed hypertable");
        }
    }
}

async fn timescale_extension_active(conn: &DatabaseConnection) -> bool {
    conn.query_one(Statement::from_string(
        sea_orm::DatabaseBackend::Postgres,
        "SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'",
    ))
    .await
    .ok()
    .flatten()
    .is_some()
}

async fn convert_to_hypertable(
    conn: &DatabaseConnection,
    table: &str,
    time_column: &str,
) -> anyhow::Result<()> {
    // `create_hypertable` requires the partitioning column to be part of every
    // UNIQUE/PRIMARY KEY constraint on the table — neither `device_metric_history.id` nor
    // `logs.id` (both plain auto-increment integer PKs, Postgres's default constraint name
    // `"{table}_pkey"`, never explicitly renamed by the migration) satisfy that, so the PK
    // is dropped first. Safe specifically because neither table's Rust-side code ever does
    // a single-column `find_by_id` lookup: `device_metric_history` is only ever read via
    // `filter(...).is_in(...)`/aggregate queries (`discovery-devices::metrics_store`'s
    // batched `record_metric_polls`) and `logs` is insert-only
    // (`discovery_logging::LogStore` has no read/update/delete method at all) — `id`
    // remains a perfectly good de-facto-unique row identifier, just no longer a *declared*
    // constraint. `IF EXISTS` makes this safe to also run against a table whose PK was
    // already dropped by an earlier call (idempotent, matching this whole function's
    // `if_not_exists => true` conventions below).
    conn.execute_unprepared(&format!(
        "ALTER TABLE \"{table}\" DROP CONSTRAINT IF EXISTS \"{table}_pkey\""
    ))
    .await?;
    conn.execute_unprepared(&format!("SELECT create_hypertable('{table}', '{time_column}', if_not_exists => true, migrate_data => true)")).await?;

    // Compression + retention are optional value-adds layered on top of "just a
    // hypertable" — best-effort *within* this already-best-effort function; a failure here
    // must not undo (or be reported as undoing) the hypertable conversion that already
    // succeeded above, so these two don't propagate `?`.
    let _ = conn.execute_unprepared(&format!("ALTER TABLE \"{table}\" SET (timescaledb.compress, timescaledb.compress_orderby = '{time_column} DESC')")).await;
    let _ = conn
        .execute_unprepared(&format!(
            "SELECT add_compression_policy('{table}', INTERVAL '7 days', if_not_exists => true)"
        ))
        .await;
    Ok(())
}

async fn connect(config: &DatabaseConnConfig) -> anyhow::Result<DomainConnection> {
    if config.kind == DbKind::ClickHouse {
        let base_url = config.clickhouse_http_url()?;
        let mut client = clickhouse::Client::default().with_url(base_url);
        if let Some(database) = config.database.as_deref().filter(|s| !s.is_empty()) {
            client = client.with_database(database);
        }
        if let Some(username) = config.username.as_deref().filter(|s| !s.is_empty()) {
            client = client.with_user(username);
        }
        if let Some(password) = config.password.as_deref().filter(|s| !s.is_empty()) {
            client = client.with_password(password);
        }
        return Ok(DomainConnection::ClickHouse(client));
    }

    if config.kind == DbKind::Cassandra {
        let (node_addr, keyspace) = config.cassandra_config()?;
        // No keyspace selected here on purpose — it may not exist yet on a fresh cluster.
        // `discovery-devices::CassandraDeviceMetricsStore::ensure_schema` creates it (and
        // the two tables) and only then calls `Session::use_keyspace`, mirroring where
        // ClickHouse's schema is ensured (see this file's `ConnectionRegistry::build` docs
        // for why that isn't done here, in the domain-agnostic connection layer).
        let mut builder = scylla::SessionBuilder::new().known_node(node_addr);
        if let (Some(username), Some(password)) = (
            config.username.as_deref().filter(|s| !s.is_empty()),
            config.password.as_deref().filter(|s| !s.is_empty()),
        ) {
            builder = builder.user(username, password);
        }
        let session = builder.build().await.with_context(|| {
            format!(
                "storage.databases[\"{}\"]: connecting to Cassandra",
                config.name
            )
        })?;
        return Ok(DomainConnection::Cassandra(
            std::sync::Arc::new(session),
            keyspace,
        ));
    }

    if config.kind == DbKind::Sqlite {
        return Ok(DomainConnection::SeaOrm(connect_sqlite_file(config).await?));
    }

    let url = match config.kind {
        DbKind::Postgres | DbKind::MySql => config.connection_url()?,
        DbKind::Memory => fresh_memory_db_url(),
        DbKind::Sqlite | DbKind::ClickHouse | DbKind::Cassandra => unreachable!("handled above"),
    };

    if config.kind == DbKind::Memory {
        // See `open_memory_guard`'s docs — without this, the pool's one connection can be
        // reactively closed and replaced under load, silently losing everything routed to
        // this named `kind = "memory"` database, not just the zero-config implicit case.
        open_memory_guard(&url).await?;
    }

    let mut opt = ConnectOptions::new(url);
    if config.kind == DbKind::Memory {
        // Always exactly one connection — see `connect_memory`'s docs for why (a second
        // connection to this database is a brand-new, separate, empty database, not a
        // second handle onto the same one, unless it shares the same `cache=shared` name
        // `fresh_memory_db_url` just built — which `open_memory_guard`'s permanent
        // connection, above, now does).
        opt.max_connections(1);
        // Same fix, same reason as `connect_memory`'s docs: without this, sqlx's own
        // 10-minute `idle_timeout` default reaps the one connection this named
        // `kind = "memory"` database depends on, and the replacement connection sqlx
        // opens next is a brand-new, empty database — silently losing everything routed
        // to it, not just the zero-config implicit case.
        const EFFECTIVELY_NEVER: std::time::Duration =
            std::time::Duration::from_secs(60 * 60 * 24 * 365 * 10); // 10 years
        opt.idle_timeout(EFFECTIVELY_NEVER)
            .max_lifetime(EFFECTIVELY_NEVER);
    } else {
        // 64, not the old 10 — found live during a 2026-08-21 scale audit: the *default*
        // `concurrency.*` sum was already 40 then. Still just a default: `main.rs`
        // additionally warns at startup if this ends up smaller than `concurrency.*`'s sum
        // for whichever config the `jobs` domain resolves to (see that module's docs),
        // since raising this default doesn't make an operator's own *custom*
        // `pool_max_connections` + raised `concurrency.*` combination safe.
        opt.max_connections(config.pool_max_connections.unwrap_or(64));
    }

    let conn = Database::connect(opt).await?;
    enable_sqlite_foreign_keys(&conn).await?;
    Ok(DomainConnection::SeaOrm(conn))
}

/// Every `concurrency.*` queue's worker pool draws from one pool of this many physical
/// SQLite connections in the common zero-config case (`main.rs`'s startup warning covers
/// a custom override) — sized to the current `ConcurrencyConfig::default().sum()` (64) so a
/// fresh install never starts out already undersized, rather than a hand-picked literal
/// that silently drifts stale as queues get added (see `ConcurrencyConfig::sum`'s docs for
/// the exact 2026-09-17 audit finding this replaces: the old hardcoded `16` here was less
/// than half the *already-current* concurrency sum of 64, not just the 40 it was picked
/// against back in 2026-08-21).
pub fn default_sqlite_pool_max_connections() -> u32 {
    discovery_bootstrap::ConcurrencyConfig::default().sum() as u32
}

/// Opens a file-backed SQLite database directly through `sqlx`'s own
/// `SqliteConnectOptions` builder (wrapped back into a `sea_orm::DatabaseConnection` via
/// `SqlxSqliteConnector::from_sqlx_sqlite_pool`), not sea-orm's generic URL-string
/// `ConnectOptions::new` path `Database::connect` otherwise uses — **the only way to reach
/// `journal_mode`/`busy_timeout`/`synchronous`, none of which sea-orm's own `ConnectOptions`
/// exposes for SQLite at all.**
///
/// Fixes two real bugs found in the 2026-09-17 audit
/// (`docs/Changelog/2026-09-17 - Аудит глазами оператора...md`, finding #2 — "SQLite-бэкенд
/// по умолчанию заливает логи ERROR-шумом, жрёт CPU в простое"):
///
/// 1. **`journal_mode` was never set to WAL.** The old generic connect path left every
///    SQLite connection on the on-disk default (`DELETE`/rollback-journal) — under that
///    mode a writer takes an exclusive lock that blocks *every* concurrent reader too, not
///    just other writers, which is what actually produced the observed flood of `database
///    is locked` at ERROR under completely ordinary concurrent load (two devices, minimal
///    traffic). WAL lets readers proceed while a single writer commits, which is the
///    standard fix for this exact symptom class and by far the largest lever here —
///    `pool_max_connections` sizing (below) only ever addressed the pool-exhaustion half of
///    the problem, not this file-locking half.
/// 2. **`config.sqlite_busy_timeout_secs` was dead configuration.** `DatabaseConnConfig`'s
///    field docs claimed it was "passed straight to `SqliteConnectOptions::busy_timeout`",
///    but the old code never actually read the field — every connection silently ran on
///    whatever `sqlx`'s own hardcoded default happened to be (also 5s, which is why this
///    went unnoticed operationally: the default coincidentally matched), so an operator
///    raising it in `config.toml`/the dashboard to ride out worse contention had that change
///    quietly do nothing.
///
/// `synchronous = NORMAL` is the standard pairing with WAL (safe against an application
/// crash — every *committed* transaction survives — trades away only durability against an
/// OS crash/power loss between a WAL commit and its checkpoint, an accepted tradeoff this
/// project's own data, monitoring/alerting state, already leans toward: see
/// `docs/Architecture/Testing и Live-проверка.md`'s "durable but not paranoid" framing for
/// the rest of the schema). `foreign_keys(true)` is made explicit here rather than relying
/// on it being `sqlx`'s own default (it is, but a future `sqlx` upgrade changing that
/// default would otherwise silently regress `ON DELETE CASCADE` enforcement — see
/// `enable_sqlite_foreign_keys`'s docs for why this project depends on it).
async fn connect_sqlite_file(config: &DatabaseConnConfig) -> anyhow::Result<DatabaseConnection> {
    use sea_orm::sqlx::sqlite::{
        SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous,
    };

    let path = config
        .file_path
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("storage.databases[\"{}\"]: missing file_path — should have been caught by Config::validate", config.name))?;

    let connect_opts = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(std::time::Duration::from_secs(
            config.sqlite_busy_timeout_secs,
        ))
        .foreign_keys(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(
            config
                .pool_max_connections
                .unwrap_or_else(default_sqlite_pool_max_connections),
        )
        .connect_with(connect_opts)
        .await
        .with_context(|| {
            format!(
                "storage.databases[\"{}\"]: connecting to sqlite {}",
                config.name,
                path.display()
            )
        })?;

    Ok(sea_orm::SqlxSqliteConnector::from_sqlx_sqlite_pool(pool))
}

#[cfg(test)]
mod tests {
    use super::*;
    use discovery_bootstrap::DatabaseConnConfig;

    fn sqlite_config(name: &str, path: &str) -> DatabaseConnConfig {
        DatabaseConnConfig {
            name: name.to_string(),
            kind: DbKind::Sqlite,
            host: None,
            port: None,
            database: None,
            username: None,
            password: None,
            file_path: Some(std::path::PathBuf::from(path)),
            pool_max_connections: None,
            sqlite_busy_timeout_secs: 5,
        }
    }

    fn temp_sqlite_path(label: &str) -> String {
        std::env::temp_dir()
            .join(format!(
                "discovery-db-test-{label}-{}.sqlite3",
                std::process::id()
            ))
            .display()
            .to_string()
    }

    #[tokio::test]
    async fn zero_config_gives_every_domain_the_same_implicit_memory_connection() {
        let storage = StorageConfig::default();
        let registry = ConnectionRegistry::build(&storage).await.unwrap();
        assert_eq!(
            registry.connections.len(),
            1,
            "must be exactly one physical connection for the whole zero-config default"
        );
        for domain in Domain::ALL {
            assert_eq!(registry.resolved[&domain], IMPLICIT_MEMORY);
        }
    }

    #[tokio::test]
    async fn two_domains_sharing_one_named_config_share_one_physical_connection() {
        let path = temp_sqlite_path("shared");
        let storage = StorageConfig {
            databases: vec![sqlite_config("main", &path)],
            default_database: Some("main".to_string()),
            routing: DomainRouting::default(), // every domain unset -> falls back to "main"
        };
        let registry = ConnectionRegistry::build(&storage).await.unwrap();
        assert_eq!(
            registry.connections.len(),
            1,
            "eight domains, one config referenced -> exactly one connection opened"
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn a_database_no_domain_references_is_never_connected_to() {
        let used_path = temp_sqlite_path("used");
        let unused_path = temp_sqlite_path("unused-does-not-exist-and-must-stay-that-way");
        let storage = StorageConfig {
            databases: vec![
                sqlite_config("used", &used_path),
                sqlite_config("unused", &unused_path),
            ],
            default_database: Some("used".to_string()),
            routing: DomainRouting::default(),
        };
        let registry = ConnectionRegistry::build(&storage).await.unwrap();
        assert_eq!(
            registry.connections.len(),
            1,
            "the unreferenced \"unused\" config must never be connected to"
        );
        assert!(registry.connections.contains_key("used"));
        assert!(!registry.connections.contains_key("unused"));
        // The strongest possible proof it was never opened: SQLite would have created the
        // file on connect (`mode=rwc`) — it must not exist.
        assert!(
            !std::path::Path::new(&unused_path).exists(),
            "connecting would have created this file"
        );
        std::fs::remove_file(&used_path).ok();
    }

    #[tokio::test]
    async fn two_databases_routed_to_different_domains_open_two_connections() {
        let path_a = temp_sqlite_path("a");
        let path_b = temp_sqlite_path("b");
        let storage = StorageConfig {
            databases: vec![sqlite_config("a", &path_a), sqlite_config("b", &path_b)],
            default_database: Some("a".to_string()),
            routing: DomainRouting {
                alerts: Some("b".to_string()),
                ..Default::default()
            },
        };
        let registry = ConnectionRegistry::build(&storage).await.unwrap();
        assert_eq!(registry.connections.len(), 2);
        assert_eq!(registry.resolved[&Domain::Alerts], "b");
        assert_eq!(
            registry.resolved[&Domain::Devices],
            "a",
            "unset — falls back to default_database"
        );
        std::fs::remove_file(&path_a).ok();
        std::fs::remove_file(&path_b).ok();
    }

    #[tokio::test]
    async fn for_domain_returns_a_usable_connection() {
        let path = temp_sqlite_path("usable");
        let storage = StorageConfig {
            databases: vec![sqlite_config("main", &path)],
            default_database: Some("main".to_string()),
            routing: DomainRouting::default(),
        };
        let registry = ConnectionRegistry::build(&storage).await.unwrap();
        let conn = registry.for_domain_sea_orm(Domain::Settings);
        conn.execute(Statement::from_string(
            conn.get_database_backend(),
            "SELECT 1",
        ))
        .await
        .unwrap();
        std::fs::remove_file(&path).ok();
    }

    /// 2026-09-17 audit finding #2's root cause, pinned down directly: the old generic
    /// `sea_orm::ConnectOptions::new(url)` path never actually set `journal_mode` (silently
    /// left on the on-disk default, `DELETE`) and never read `sqlite_busy_timeout_secs` at
    /// all despite that field's docs claiming otherwise. `connect_sqlite_file` must both
    /// switch the file to WAL and apply the *configured* busy timeout, not just whatever
    /// `sqlx`'s own built-in default happens to be.
    #[tokio::test]
    async fn connect_sqlite_file_enables_wal_and_applies_the_configured_busy_timeout() {
        let path = temp_sqlite_path("wal-pragma");
        let mut config = sqlite_config("main", &path);
        config.sqlite_busy_timeout_secs = 17;

        let conn = connect_sqlite_file(&config).await.unwrap();

        let journal_mode: String = conn
            .query_one(Statement::from_string(
                conn.get_database_backend(),
                "PRAGMA journal_mode",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index::<String>(0)
            .unwrap();
        assert_eq!(
            journal_mode.to_lowercase(),
            "wal",
            "connect_sqlite_file must switch the database to WAL journal mode"
        );

        let busy_timeout_ms: i32 = conn
            .query_one(Statement::from_string(
                conn.get_database_backend(),
                "PRAGMA busy_timeout",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index::<i32>(0)
            .unwrap();
        assert_eq!(busy_timeout_ms, 17_000, "connect_sqlite_file must apply the configured sqlite_busy_timeout_secs, not sqlx's own built-in default");

        drop(conn);
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(format!("{path}-wal")).ok();
        std::fs::remove_file(format!("{path}-shm")).ok();
    }

    /// Direct reproduction of the 2026-09-17 audit's finding #2 scenario: many workers
    /// concurrently reading and writing the same real file-backed SQLite database (not
    /// `:memory:` — WAL's whole benefit is a real on-disk `-wal` file). Before this fix
    /// (rollback-journal mode, the on-disk default `connect_sqlite_file` now overrides),
    /// a writer takes an exclusive lock that blocks every concurrent reader too, which is
    /// what produced the audit's observed flood of `database is locked` under nothing more
    /// than two devices' worth of ordinary traffic. Not deterministic proof the old code
    /// *would* fail here (timing-dependent), but this concurrency level reliably reproduced
    /// the symptom live during the audit, and every task below must now complete with zero
    /// errors under WAL.
    #[tokio::test]
    async fn many_concurrent_readers_and_writers_against_one_real_sqlite_file_never_error() {
        let path = temp_sqlite_path("concurrency");
        let config = sqlite_config("main", &path);
        let conn = connect_sqlite_file(&config).await.unwrap();
        conn.execute(Statement::from_string(
            conn.get_database_backend(),
            "CREATE TABLE t (id INTEGER PRIMARY KEY, v INTEGER)",
        ))
        .await
        .unwrap();
        let conn = std::sync::Arc::new(conn);

        const TASKS: usize = 40;
        const ITERATIONS: usize = 25;
        let mut set = tokio::task::JoinSet::new();
        for i in 0..TASKS {
            let conn = conn.clone();
            set.spawn(async move {
                for j in 0..ITERATIONS {
                    conn.execute(Statement::from_string(
                        conn.get_database_backend(),
                        format!("INSERT INTO t (v) VALUES ({})", i * ITERATIONS + j),
                    ))
                    .await?;
                    conn.query_one(Statement::from_string(
                        conn.get_database_backend(),
                        "SELECT COUNT(*) FROM t",
                    ))
                    .await?;
                }
                anyhow::Ok(())
            });
        }
        let mut failures = Vec::new();
        while let Some(res) = set.join_next().await {
            if let Err(e) = res.unwrap() {
                failures.push(e.to_string());
            }
        }
        assert!(failures.is_empty(), "expected zero errors under concurrent read/write load with WAL enabled, got: {failures:?}");

        let total: i64 = conn
            .query_one(Statement::from_string(
                conn.get_database_backend(),
                "SELECT COUNT(*) FROM t",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index::<i64>(0)
            .unwrap();
        assert_eq!(
            total,
            (TASKS * ITERATIONS) as i64,
            "every concurrent insert must have actually committed, not just avoided erroring"
        );

        drop(conn);
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(format!("{path}-wal")).ok();
        std::fs::remove_file(format!("{path}-shm")).ok();
    }

    /// Direct reproduction of the 2026-09-20 pre-release audit's finding #1: schema
    /// surviving the *reactive* half of the connection-recycling problem, not just the
    /// proactive/idle-timeout half `connect_sqlite_file`'s sibling test already covers.
    /// `DatabaseConnection::close` deterministically tears down every connection a pool
    /// holds (unlike a bare `drop`, which only schedules an async close) — standing in here
    /// for "sqlx decided the sole connection was unhealthy and replaced it", since from the
    /// shared-cache database's point of view the two are indistinguishable: what matters is
    /// only whether the open-connection refcount against its name ever reaches zero.
    /// Without `open_memory_guard` keeping a permanent connection alive, a brand-new pool
    /// reopened against the exact same name after this point gets a fresh, empty database
    /// instead of the one just populated — this test would fail with `no such table: t` if
    /// the guard connection were removed.
    #[tokio::test]
    async fn a_reactively_recreated_memory_connection_still_sees_the_same_schema_and_data() {
        let url = fresh_memory_db_url();
        open_memory_guard(&url).await.unwrap();

        let first = Database::connect(
            ConnectOptions::new(url.clone())
                .max_connections(1)
                .to_owned(),
        )
        .await
        .unwrap();
        first
            .execute(Statement::from_string(
                first.get_database_backend(),
                "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)",
            ))
            .await
            .unwrap();
        first
            .execute(Statement::from_string(
                first.get_database_backend(),
                "INSERT INTO t (v) VALUES ('before-reconnect')",
            ))
            .await
            .unwrap();
        first.close().await.unwrap();

        // A brand-new pool against the identical name, opened after the first pool (and
        // its sole connection) is fully gone — exactly the shape of sqlx reactively
        // replacing a connection it decided was unhealthy.
        let second = Database::connect(ConnectOptions::new(url).max_connections(1).to_owned())
            .await
            .unwrap();
        let value: String = second
            .query_one(Statement::from_string(
                second.get_database_backend(),
                "SELECT v FROM t WHERE id = 1",
            ))
            .await
            .unwrap()
            .expect(
                "row must still exist — the shared-cache database must not have been deallocated",
            )
            .try_get_by_index::<String>(0)
            .unwrap();
        assert_eq!(value, "before-reconnect");
        second.close().await.unwrap();
    }

    /// Negative control for the test above: proves the rig itself actually exercises the
    /// bug (rather than passing for some unrelated reason) — the exact same sequence
    /// *without* `open_memory_guard` must lose the table, confirming the guard connection
    /// is what makes the previous test pass, not incidental sqlite/sqlx behavior.
    #[tokio::test]
    async fn without_the_guard_a_recreated_memory_connection_loses_the_schema() {
        let url = fresh_memory_db_url();
        // Deliberately no `open_memory_guard` call here.

        let first = Database::connect(
            ConnectOptions::new(url.clone())
                .max_connections(1)
                .to_owned(),
        )
        .await
        .unwrap();
        first
            .execute(Statement::from_string(
                first.get_database_backend(),
                "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)",
            ))
            .await
            .unwrap();
        first.close().await.unwrap();

        let second = Database::connect(ConnectOptions::new(url).max_connections(1).to_owned())
            .await
            .unwrap();
        let result = second
            .query_one(Statement::from_string(
                second.get_database_backend(),
                "SELECT v FROM t WHERE id = 1",
            ))
            .await;
        assert!(result.is_err(), "without the guard connection, the shared-cache database must have been deallocated once the first pool fully closed");
        second.close().await.unwrap();
    }

    #[tokio::test]
    async fn a_domain_other_than_logs_never_resolves_to_a_clickhouse_connection() {
        // Structural guard, not a `Config::validate` retest — proves `ConnectionRegistry`
        // itself never hands a ClickHouse connection to a caller asking via
        // `for_domain_sea_orm` for one of the eight domains that can't use it, even though
        // nothing in this crate's own types stop a `StorageConfig` built by hand (as here,
        // bypassing `Config::validate` entirely) from routing one there.
        let storage = StorageConfig {
            databases: vec![DatabaseConnConfig {
                name: "ch".to_string(),
                kind: DbKind::ClickHouse,
                host: Some("127.0.0.1".to_string()),
                port: Some(8123),
                database: None,
                username: None,
                password: None,
                file_path: None,
                pool_max_connections: None,
                sqlite_busy_timeout_secs: 5,
            }],
            default_database: Some("ch".to_string()),
            routing: DomainRouting::default(),
        };
        let registry = ConnectionRegistry::build(&storage).await.unwrap();
        assert!(matches!(
            registry.for_domain(Domain::Logs),
            DomainConnection::ClickHouse(_)
        ));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            registry.for_domain_sea_orm(Domain::Settings)
        }));
        assert!(result.is_err(), "for_domain_sea_orm must panic rather than silently return a ClickHouse connection for a domain that can't use one");
    }

    /// Live verification against a real TimescaleDB-enabled Postgres — same `#[ignore]`d
    /// convention as `discovery-migration`'s `tests/live_multi_backend.rs` (needs a real
    /// server reachable, not run by plain `cargo test --workspace`). Run explicitly with
    /// `cargo test -p discovery-db -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn maybe_enable_timescale_converts_the_two_candidate_tables_into_compressed_hypertables()
    {
        let db = Database::connect("postgres://vladislav@127.0.0.1:5433/ts_probe")
            .await
            .expect("connect to the local Timescale-enabled Postgres");
        discovery_migration::Migrator::up(&db, None)
            .await
            .expect("run the schema migration first, same order ConnectionRegistry::build uses");
        maybe_enable_timescale(&db).await;

        let hypertables: Vec<String> = db
            .query_all(Statement::from_string(sea_orm::DatabaseBackend::Postgres, "SELECT hypertable_name FROM timescaledb_information.hypertables ORDER BY hypertable_name"))
            .await
            .unwrap()
            .iter()
            .map(|r| r.try_get::<String>("", "hypertable_name").unwrap())
            .collect();
        assert_eq!(
            hypertables,
            vec!["device_metric_history".to_string(), "logs".to_string()],
            "exactly these two tables, not the other 13"
        );

        let compressed: Vec<String> = db
            .query_all(Statement::from_string(
                sea_orm::DatabaseBackend::Postgres,
                "SELECT hypertable_name FROM timescaledb_information.hypertables WHERE compression_enabled ORDER BY hypertable_name",
            ))
            .await
            .unwrap()
            .iter()
            .map(|r| r.try_get::<String>("", "hypertable_name").unwrap())
            .collect();
        assert_eq!(
            compressed,
            vec!["device_metric_history".to_string(), "logs".to_string()],
            "compression policy must actually be attached, not just the conversion"
        );

        // Idempotent — calling it again on already-converted tables must not error.
        maybe_enable_timescale(&db).await;
    }

    /// A Postgres connection *without* the extension available must behave exactly like
    /// plain Postgres — no error, nothing converted. Uses the project's other local
    /// Postgres install (port 5432, `discovery_dev` — no `timescaledb` extension
    /// available there, confirmed live) specifically *because* it lacks the extension —
    /// this is the overwhelmingly common case this function must degrade safely for.
    #[tokio::test]
    #[ignore]
    async fn maybe_enable_timescale_is_a_silent_no_op_without_the_extension_available() {
        let db = Database::connect("postgres://vladislav@127.0.0.1:5432/discovery_dev")
            .await
            .expect("connect to the project's ordinary dev Postgres");
        maybe_enable_timescale(&db).await; // must not panic or return an error to propagate
        let rows = db
            .query_all(Statement::from_string(
                sea_orm::DatabaseBackend::Postgres,
                "SELECT extname FROM pg_extension WHERE extname = 'timescaledb'",
            ))
            .await
            .unwrap();
        assert!(rows.is_empty(), "this database must genuinely not have timescaledb active — that's the scenario this test exists to cover");
    }
}
