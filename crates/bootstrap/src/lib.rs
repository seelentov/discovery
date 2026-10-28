//! Bootstrap configuration: the handful of settings that can never live in the database,
//! because they're needed *before* the process can reach a database at all — which
//! storage backend to use, where to find it, which port to listen on, how to log, how many
//! workers per queue. Read from `config.toml` (path from the `CONFIG_FILE` env var, default
//! `./config.toml`); every field has a sane default, so a missing file — or a file that
//! only overrides one or two settings — is not an error, it just means "use the defaults
//! for the rest".
//!
//! **`poll_intervals` moved out 2026-08-16** (direct user request: "конфигурацию мы храним
//! в БД! И должна быть возможность для webui для изменения настроек + они должны сразу
//! применяться") — unlike `storage`/`server`/`logging`/`concurrency`, there's no
//! chicken-and-egg reason poll cadences can't live in the database (they're only ever read
//! *after* a store already exists). `PollIntervalsConfig` itself now lives in
//! `discovery_core` (re-exported here) and is DB-backed via
//! `discovery_config_store::SettingsStore` — this crate's [`PollIntervalsConfig`] field on
//! [`Config`] survives only as the **first-run seed default**, written into the settings
//! store once if it has nothing yet (see `discovery-agent::main::build_stores`'s docs), then
//! inert — the database is the live source of truth from then on.
//!
//! Everything else (device profiles, discovery/subnet-scan schedules, poll intervals) lives
//! in whichever storage backend this file points at — see
//! `discovery-config-store`/`discovery-devices`/`discovery-queue`'s Postgres/Sqlite/Memory
//! implementations. This crate only decides *how to reach* that storage, never what's in it
//! (with the one now-vestigial exception of `poll_intervals`'s seed default, above).

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::Context;
use serde::{Deserialize, Serialize};

pub use discovery_core::PollIntervalsConfig;

/// Which database engine a single named [`DatabaseConnConfig`] talks to — direct user
/// request 2026-08-18, following an AggreGate source-code review for reference (see
/// `discovery/README.md`'s "Мульти-БД поддержка" section for the full comparison):
/// "discovery должен уметь подключаться к разным СУБД". `Postgres`/`Sqlite` already
/// existed (as the old `StorageKind::Database`/`File`); `MySql` is new. Oracle/MS SQL
/// Server were explicitly ruled out — no viable async Rust driver for either exists,
/// confirmed before committing to this design.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DbKind {
    Postgres,
    MySql,
    /// Embedded, file-backed — single file on disk, no external server,
    /// single-process-oriented (SQLite serializes writers at the connection level).
    Sqlite,
    /// Pure in-process, nothing survives a restart — implemented as a sea-orm connection
    /// over `sqlite::memory:` (not a bespoke Rust-native store), so it's just another
    /// `DbKind` rather than a separate code path — the zero-configuration default:
    /// `cargo run` with no `config.toml` at all just works.
    Memory,
    /// **2026-08-18, second pass** — direct user request after the scale-target
    /// discussion ("Может сразу добавить поддержку timescale и clickhouse?"). Not a
    /// sea-orm backend (sea-orm/sea-query have no ClickHouse driver) — connects via the
    /// `clickhouse` crate's own HTTP client instead (`discovery_db::DomainConnection`'s
    /// docs). Column-oriented, append-optimized, weak at point `UPDATE`/`DELETE` — a
    /// structural mismatch for domains that update/delete rows in place
    /// (`device_metric_history`'s "same state" in-place update, `alerts`'s `StillActive`
    /// update, either domain's `delete_for_device`). **`Config::validate` therefore
    /// restricts this kind to the `logs` routing domain only** — pure-append, no
    /// updates, no per-device delete, see `discovery_logging::LogStore`'s single
    /// `append` method. TimescaleDB, the other database discussed in that request,
    /// needs no new `DbKind` at all — it's a Postgres extension, `DbKind::Postgres`
    /// already reaches it unchanged (see `discovery-db::ConnectionRegistry`'s
    /// Timescale-detection docs).
    ClickHouse,
    /// **2026-08-18, third pass** — direct user request "переходи на реализацию
    /// подключения к cassandra. Пускай этот вариант тоже будет". Connects via the
    /// `scylla` crate's CQL client (wire-compatible with real Apache Cassandra, not
    /// Cassandra-specific — sea-orm/sea-query have no CQL driver either). Unlike
    /// ClickHouse, Cassandra's `INSERT`/`UPDATE` are the same upsert operation and both
    /// are fast/synchronous — it genuinely tolerates the update-in-place and
    /// per-device-delete patterns ClickHouse structurally can't. **Restricted by
    /// `Config::validate` to `device_metrics` and `alerts`** — both direct user choices
    /// after being asked which domain fits, both sharing the same partition-by-`device_id`/
    /// cluster-by-time shape Cassandra is built for. `device_metrics` (2026-08-18, third
    /// pass) was the domain that originally motivated the whole scale conversation;
    /// `alerts` (2026-08-18, fourth pass — "Сделай для alerts cassandra") is the second,
    /// asked for explicitly once `logs`/`devices`/`jobs`/`profiles`/etc. were ruled out as
    /// poor fits (see the discussion this decision came out of — `devices` needs ad-hoc
    /// cross-partition dashboard queries, `jobs` needs a cheap atomic claim, neither of
    /// which Cassandra does well). Not opened up to every domain — only
    /// `discovery-devices::CassandraDeviceMetricsStore`/`discovery-alerts::CassandraAlertStore`
    /// exist; `settings`/`profiles`/etc. have no Cassandra implementation to route to even
    /// if validation allowed it.
    Cassandra,
}

impl Default for DbKind {
    fn default() -> Self {
        DbKind::Memory
    }
}

fn default_sqlite_busy_timeout_secs() -> u64 {
    5
}

/// One named, independently connectable database — direct user request 2026-08-18: "в
/// настройке был список конфигов БД - один из них будет по умолчанию, можно переключать
/// по умолчанию БД". `name` is how [`DomainRouting`] and the UI refer to this entry;
/// unique among its siblings in [`StorageConfig::databases`] (`Config::validate` checks
/// this — a duplicate name would make routing ambiguous).
///
/// Nothing here says *which domains* use this config — that's [`DomainRouting`]'s job,
/// deliberately kept separate: a database connection's own shape (kind/host/pool tuning)
/// doesn't change depending on who references it, and keeping the two concerns apart is
/// what makes "two domains pointing at the same name share one physical connection, not
/// two" a simple lookup rather than something this type has to know about.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConnConfig {
    pub name: String,
    pub kind: DbKind,
    /// Required for `kind = "postgres"`/`"mysql"`. Unused for `sqlite`/`memory`.
    #[serde(default)]
    pub host: Option<String>,
    /// `kind = "postgres"`/`"mysql"` only. `None` = the engine's own standard port
    /// (5432/3306).
    #[serde(default)]
    pub port: Option<u16>,
    /// Required for `kind = "postgres"`/`"mysql"` — the database/schema name to connect
    /// to. Unused for `sqlite` (`file_path` serves that role there) / `memory`.
    #[serde(default)]
    pub database: Option<String>,
    /// Required for `kind = "postgres"`/`"mysql"`.
    #[serde(default)]
    pub username: Option<String>,
    /// `kind = "postgres"`/`"mysql"` only. `None` (not `Some("")`) means the connection
    /// string carries no password segment at all — the common case for local trust-auth
    /// setups (e.g. this project's own dev Postgres, connected as the OS user with no
    /// password prompt).
    #[serde(default)]
    pub password: Option<String>,
    /// Required for `kind = "sqlite"`. A relative path is resolved against the process's
    /// current directory, same convention as `profiles/`/`scans/` used before this.
    /// Unused for `postgres`/`mysql`/`memory`.
    #[serde(default)]
    pub file_path: Option<PathBuf>,
    /// Max size of this config's own connection pool. `None` = the backend-specific
    /// built-in default (`10` for Postgres/MySQL, `5` for SQLite — kept modest on purpose
    /// even though it's adjustable, see `Sqlite*Store`'s docs: SQLite serializes writers
    /// regardless of pool size, a larger pool there only buys concurrent *readers*).
    /// Unused for `kind = "memory"`.
    #[serde(default)]
    pub pool_max_connections: Option<u32>,
    /// `kind = "sqlite"` only — how long a connection waits on `SQLITE_BUSY` before
    /// giving up, passed straight to `SqliteConnectOptions::busy_timeout`. Complements
    /// (does not replace) `SqliteDeviceStore`'s own `retry_on_locked` transaction-restart
    /// logic for `SQLITE_BUSY_SNAPSHOT`, which this timeout doesn't cover — see that
    /// module's docs.
    #[serde(default = "default_sqlite_busy_timeout_secs")]
    pub sqlite_busy_timeout_secs: u64,
}

impl DatabaseConnConfig {
    /// Builds the `postgres://`/`mysql://` connection string sea-orm/sqlx actually connect
    /// with, from the structured `host`/`port`/`database`/`username`/`password` fields —
    /// direct user request 2026-08-18, after seeing the first version of this UI/schema
    /// (a single free-text `url` box): "куда вводить пароль к бд, саму бд, просто url
    /// недостаточно" — a bare URL field pushes hand-assembling (and correctly
    /// percent-encoding) a connection string onto whoever fills in the form. Uses
    /// `url::Url`'s own setters, not string concatenation, specifically so a password or
    /// database name containing `@`/`:`/`/`/`#`/etc. round-trips correctly instead of
    /// silently corrupting the connection string. Only meaningful for `kind = "postgres"`/
    /// `"mysql"` — `sqlite`/`memory` never call this, they connect via `file_path`/
    /// `sqlite::memory:` instead.
    pub fn connection_url(&self) -> anyhow::Result<String> {
        let scheme = match self.kind {
            DbKind::Postgres => "postgres",
            DbKind::MySql => "mysql",
            DbKind::Sqlite | DbKind::Memory | DbKind::ClickHouse | DbKind::Cassandra => {
                anyhow::bail!("storage.databases[\"{}\"]: connection_url is only meaningful for postgres/mysql, not {:?}", self.name, self.kind)
            }
        };
        let host = non_empty(&self.host).ok_or_else(|| {
            anyhow::anyhow!(
                "storage.databases[\"{}\"]: \"host\" is required for kind = \"{:?}\"",
                self.name,
                self.kind
            )
        })?;
        let database = non_empty(&self.database).ok_or_else(|| {
            anyhow::anyhow!(
                "storage.databases[\"{}\"]: \"database\" is required for kind = \"{:?}\"",
                self.name,
                self.kind
            )
        })?;
        let username = non_empty(&self.username).ok_or_else(|| {
            anyhow::anyhow!(
                "storage.databases[\"{}\"]: \"username\" is required for kind = \"{:?}\"",
                self.name,
                self.kind
            )
        })?;

        let mut url = url::Url::parse(&format!("{scheme}://{host}"))
            .with_context(|| format!("storage.databases[\"{}\"]: invalid host", self.name))?;
        url.set_username(username).map_err(|_| {
            anyhow::anyhow!("storage.databases[\"{}\"]: invalid username", self.name)
        })?;
        if let Some(password) = non_empty(&self.password) {
            url.set_password(Some(password)).map_err(|_| {
                anyhow::anyhow!("storage.databases[\"{}\"]: invalid password", self.name)
            })?;
        }
        if let Some(port) = self.port {
            url.set_port(Some(port)).map_err(|_| {
                anyhow::anyhow!("storage.databases[\"{}\"]: invalid port", self.name)
            })?;
        }
        url.set_path(&format!("/{database}"));
        Ok(url.to_string())
    }

    /// The ClickHouse HTTP interface's base URL (`http://host:port`) — unlike
    /// `connection_url`, credentials/database aren't folded into this string; the
    /// `clickhouse` crate's `Client` builder takes them as separate calls
    /// (`with_user`/`with_password`/`with_database`), so `discovery-db::connect` reads
    /// this config's `username`/`password`/`database` fields directly rather than
    /// through a parsed URL. Only `host` is required — ClickHouse always has a `default`
    /// database and an anonymous `default` user with no password, so `database`/
    /// `username`/`password` are genuinely optional here (unlike postgres/mysql).
    pub fn clickhouse_http_url(&self) -> anyhow::Result<String> {
        if self.kind != DbKind::ClickHouse {
            anyhow::bail!("storage.databases[\"{}\"]: clickhouse_http_url is only meaningful for kind = \"clickhouse\", not {:?}", self.name, self.kind);
        }
        let host = non_empty(&self.host).ok_or_else(|| {
            anyhow::anyhow!(
                "storage.databases[\"{}\"]: \"host\" is required for kind = \"clickhouse\"",
                self.name
            )
        })?;
        let port = self.port.unwrap_or(8123);
        Ok(format!("http://{host}:{port}"))
    }

    /// `(host:port, keyspace)` for the `scylla` crate's `SessionBuilder::known_node`/
    /// `Session::use_keyspace` — unlike `connection_url`, there's no single connection
    /// string; a CQL client connects to a node address, then separately switches into a
    /// keyspace (this config's `database` field doubles as the keyspace name — same
    /// field, same meaning as postgres/mysql's "which database", just Cassandra's own
    /// term for it). Both `host` and `database` (keyspace) are required — unlike
    /// ClickHouse, Cassandra has no anonymous default keyspace to fall back to.
    pub fn cassandra_config(&self) -> anyhow::Result<(String, String)> {
        if self.kind != DbKind::Cassandra {
            anyhow::bail!("storage.databases[\"{}\"]: cassandra_config is only meaningful for kind = \"cassandra\", not {:?}", self.name, self.kind);
        }
        let host = non_empty(&self.host).ok_or_else(|| {
            anyhow::anyhow!(
                "storage.databases[\"{}\"]: \"host\" is required for kind = \"cassandra\"",
                self.name
            )
        })?;
        let keyspace =
            non_empty(&self.database).ok_or_else(|| anyhow::anyhow!("storage.databases[\"{}\"]: \"database\" (keyspace) is required for kind = \"cassandra\"", self.name))?;
        let port = self.port.unwrap_or(9042);
        Ok((format!("{host}:{port}"), keyspace.to_string()))
    }
}

fn non_empty(field: &Option<String>) -> Option<&str> {
    field.as_deref().filter(|s| !s.is_empty())
}

/// Which named [`DatabaseConnConfig`] each data domain's store uses — direct user
/// request 2026-08-18: "разделение хранение данных на различных БД... конфиг
/// (Настройки) - одна БД, тревоги - другая бд, устройства - третья бд...". `None` for any
/// field means "use [`StorageConfig::default_database`]" — "Изначально у всех блоков
/// хранение идет в БД по умолчанию" (every field starts `None`, i.e. every domain
/// defaults to the default database, until the user explicitly routes one elsewhere).
///
/// **Eight domains, not one per table** — `devices` deliberately does *not* include
/// device metrics/history (a separate `device_metrics` field): the user explicitly named
/// "устройства" and "метрики устройств (история)" as two different blocks. This is why
/// `discovery-devices`'s `DeviceStore` trait is split into `DeviceStore` (identity +
/// per-device metric on/off overrides) and a new `DeviceMetricsStore` (current values +
/// history) — see that crate's docs for the full consequence (in particular: cross-DB
/// cascade delete can no longer be a database-level `ON DELETE CASCADE` when these two
/// domains point at different physical databases, so `DeviceStore::delete` now cleans up
/// the other domains' rows explicitly in application code).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DomainRouting {
    pub settings: Option<String>,
    pub alerts: Option<String>,
    pub devices: Option<String>,
    pub discovery_configs: Option<String>,
    pub device_metrics: Option<String>,
    pub profiles: Option<String>,
    pub logs: Option<String>,
    pub jobs: Option<String>,
    /// 9th domain, added 2026-09-07 for Maintenance windows — see
    /// `discovery_core::Domain::MaintenanceWindows`'s docs. A plain sea-orm-only domain,
    /// same as `profiles`/`discovery_configs` — never allowed to resolve to ClickHouse/
    /// Cassandra (see the `label != "logs"`/`"device_metrics"`/`"alerts"` checks in
    /// `Config::validate` below, which `all_with_labels` feeds).
    pub maintenance_windows: Option<String>,
    /// 10th domain, added 2026-09-10 for notification matrix rules
    /// (`discovery_config_store::NotificationRuleStore`) — see
    /// `discovery_core::Domain::Notifications`'s docs. Per-user notification *channels*
    /// (`discovery_core::NotificationChannel`) aren't a routed domain of their own — they
    /// live alongside `users`/`sessions` on whichever connection `Settings` resolves to,
    /// same "not a business domain, an administrative one" reasoning `journal_entries`
    /// already follows (see `docs/Architecture/Domains и модель данных.md`). A plain
    /// sea-orm-only domain, same as `maintenance_windows` — never allowed to resolve to
    /// ClickHouse/Cassandra.
    pub notifications: Option<String>,
    /// 11th domain, added 2026-09-16 for the rule-based topology mechanism
    /// (`discovery_config_store::TopologyRuleStore` + `discovery_topology::TopologyStore`)
    /// — see `discovery_core::Domain::Topology`'s docs. A plain sea-orm-only domain, same
    /// as `maintenance_windows`/`notifications` — never allowed to resolve to ClickHouse/
    /// Cassandra.
    pub topology: Option<String>,
    /// 12th domain, added 2026-09-16 for group-alert suppression rules
    /// (`discovery_config_store::GroupAlertRuleStore`) — see
    /// `discovery_core::Domain::GroupAlerts`'s docs. A plain sea-orm-only domain, same as
    /// `topology`/`maintenance_windows`/`notifications` — never allowed to resolve to
    /// ClickHouse/Cassandra.
    pub group_alerts: Option<String>,
}

impl DomainRouting {
    /// Every non-`None` entry, for validation (each must name a real
    /// [`StorageConfig::databases`] entry) — see `Config::validate`.
    fn referenced_names(&self) -> impl Iterator<Item = &str> {
        [
            &self.settings,
            &self.alerts,
            &self.devices,
            &self.discovery_configs,
            &self.device_metrics,
            &self.profiles,
            &self.logs,
            &self.jobs,
            &self.maintenance_windows,
            &self.notifications,
            &self.topology,
            &self.group_alerts,
        ]
        .into_iter()
        .filter_map(|o| o.as_deref())
    }

    /// `(domain label, routing field)` for all twelve domains — used by `Config::validate`'s
    /// "only `logs` may resolve to a ClickHouse-kind config" check. Deliberately a plain
    /// label string, not `discovery_db::Domain`: this crate is a dependency *of*
    /// `discovery-db` (`DatabaseConnConfig`/`StorageConfig` live here), so depending back
    /// on it for its `Domain` enum would be a cycle.
    fn all_with_labels(&self) -> [(&'static str, &Option<String>); 12] {
        [
            ("settings", &self.settings),
            ("alerts", &self.alerts),
            ("devices", &self.devices),
            ("discovery_configs", &self.discovery_configs),
            ("device_metrics", &self.device_metrics),
            ("profiles", &self.profiles),
            ("logs", &self.logs),
            ("jobs", &self.jobs),
            ("maintenance_windows", &self.maintenance_windows),
            ("notifications", &self.notifications),
            ("topology", &self.topology),
            ("group_alerts", &self.group_alerts),
        ]
    }
}

/// Replaces the old single-engine `[storage]` section (`kind`/`database_url`/`file_path`)
/// — direct user request 2026-08-18, by way of an AggreGate design comparison (see
/// `DbKind`'s docs): a **list** of named database connections, one marked default, plus
/// per-domain routing ([`DomainRouting`]) that falls back to the default when unset.
///
/// **Still config.toml-only, not DB-backed** — same chicken-and-egg reason every field in
/// this crate is (`build_stores` needs this before any store, hence any database, exists).
/// What's new is that it's no longer *hand*-edited-only: `discovery-web`'s
/// `PUT /api/settings/databases`/`PUT /api/settings/routing` endpoints serialize an
/// updated `StorageConfig` straight back into `config.toml` — the UI is a structured
/// editor for this file, not a separate source of truth. Every such write requires a
/// restart to take effect (a live database swap mid-process is out of scope — see
/// `discovery-web`'s restart-warning docs), which those endpoints' callers must surface.
///
/// Zero-configuration default (`databases` empty, `default_database: None`) resolves to
/// a single implicit in-process `memory` connection for every domain — the same
/// `cargo run` with no `config.toml` at all "just works" guarantee the old `StorageKind::
/// Memory` default gave.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    pub databases: Vec<DatabaseConnConfig>,
    /// Name of the entry in `databases` every domain falls back to when its own
    /// `DomainRouting` field is `None`. `None` here (with `databases` empty) means the
    /// implicit zero-config `memory` connection — see this type's docs.
    pub default_database: Option<String>,
    pub routing: DomainRouting,
}

fn default_addr() -> String {
    "127.0.0.1:8088".to_string()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    #[serde(default = "default_addr")]
    pub addr: String,
    /// Toggle for the `/api/*` REST surface — direct user request 2026-08-29: "возможность
    /// через config.toml выключить rest и/или webui". `false` unmounts every `/api/*` route
    /// entirely (a real 404, not an auth rejection) — see `discovery_web::router_with_flags`.
    /// Read once at startup like every other `[server]` field; toggling requires a restart.
    /// Since the bundled webui is itself nothing but a REST client (see
    /// `router_with_flags`'s docs for the audit backing that claim), turning this off also
    /// makes `enable_webui` non-functional even if left `true` — expected, not validated
    /// against here, since `discovery-agent::main::run` already warns loudly for the one
    /// combination (both `false`) that leaves *nothing* reachable at all.
    #[serde(default = "default_true")]
    pub enable_rest: bool,
    /// Toggle for serving the bundled React dashboard (the static-asset fallback,
    /// `discovery_web::serve_embedded`). `false` means only `/api/*` responds (or nothing at
    /// all, if `enable_rest` is also `false`) — useful for a REST-only/headless deployment
    /// that doesn't want to expose the dashboard's static assets.
    #[serde(default = "default_true")]
    pub enable_webui: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            addr: default_addr(),
            enable_rest: true,
            enable_webui: true,
        }
    }
}

/// `sqlx=warn` on top of the blanket `info` — added 2026-08-26 after a live incident
/// ("запускал ненадолго и у меня быстро собирались 100гб логов"): a bare `"info"` lets
/// through `sqlx`'s own per-statement completion event (sqlx logs a *successful* query at
/// INFO, only a slow one at WARN — confirmed live, not assumed), and this project's own
/// `LogStore::append` (persisting a captured log entry) is itself a SQL `INSERT` traced by
/// sqlx. With every sink defaulting to a plain `info`, persisting *any* event — including
/// one produced by idle worker-pool polling (~40 workers × 500ms-1s claim ticks by
/// default, no real devices needed) — re-enters the log pipeline as a fresh `sqlx::query`
/// event, which gets persisted, producing another, forever: an unthrottled feedback loop
/// (the persist channel is intentionally unbounded, see `PersistingLayer`'s docs) bounded
/// only by disk/DB throughput, not by anything resembling real application activity. This
/// default keeps the common case (no explicit `level`/`level_file`/etc. override) quiet;
/// an operator who explicitly sets `level = "debug"` (or similar) still gets exactly what
/// they asked for globally — this only changes what an *unconfigured* install falls back
/// to. See `logging_setup::init`'s docs for the second half of the fix: `PersistingLayer`/
/// `BufferLayer` now hardcode `sqlx=off` unconditionally, regardless of this or any other
/// configured level, since persisting/displaying the log store's own internal SQL has no
/// legitimate use and is structurally unsafe to ever allow.
fn default_log_level() -> String {
    "info,sqlx=warn".to_string()
}
fn default_log_file() -> String {
    "logs/discovery.log".to_string()
}
fn default_log_rotation() -> String {
    "daily".to_string()
}
fn default_buffer_size() -> usize {
    1000
}

/// Three independently filterable sinks (console/file/dashboard-buffer) — same design as
/// before this moved out of env vars, see `discovery/README.md`'s "Логирование" section.
/// `level_console`/`level_file`/`level_dashboard` empty means "fall back to `level`".
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub level_console: String,
    #[serde(default)]
    pub level_file: String,
    #[serde(default)]
    pub level_dashboard: String,
    /// Empty string disables the file sink entirely.
    #[serde(default = "default_log_file")]
    pub file: String,
    /// `"daily" | "hourly" | "never"`.
    #[serde(default = "default_log_rotation")]
    pub file_rotation: String,
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            level_console: String::new(),
            level_file: String::new(),
            level_dashboard: String::new(),
            file: default_log_file(),
            file_rotation: default_log_rotation(),
            buffer_size: default_buffer_size(),
        }
    }
}

impl LoggingConfig {
    pub fn console_filter(&self) -> String {
        if self.level_console.is_empty() {
            self.level.clone()
        } else {
            self.level_console.clone()
        }
    }
    pub fn file_filter(&self) -> String {
        if self.level_file.is_empty() {
            self.level.clone()
        } else {
            self.level_file.clone()
        }
    }
    pub fn dashboard_filter(&self) -> String {
        if self.level_dashboard.is_empty() {
            self.level.clone()
        } else {
            self.level_dashboard.clone()
        }
    }
}

macro_rules! default_fn {
    ($name:ident, $ty:ty, $val:expr) => {
        fn $name() -> $ty {
            $val
        }
    };
}

default_fn!(default_c_discovery, usize, 4);
default_fn!(default_c_snmp_poll, usize, 8);
default_fn!(default_c_dedup, usize, 4);
default_fn!(default_c_profile_apply, usize, 4);
default_fn!(default_c_metric_poll, usize, 8);
default_fn!(default_c_alert_eval, usize, 4);
// Same cost class as `snmp_poll`/`metric_poll` (network I/O-bound, one check per device
// per tick) — reachability polling added 2026-08-16/17, see `QueueKind::ReachabilityPoll`.
default_fn!(default_c_reachability_poll, usize, 8);
// Same cost class again — L4/L7 service checks, 2026-09-07, see
// `QueueKind::ServiceCheckPoll`.
default_fn!(default_c_service_check_poll, usize, 8);
// Notification dispatch (2026-09-10) — one job per (alert transition, channel), an
// outbound network call (SMTP/Telegram/webhook) rather than a device poll, but the same
// "network I/O-bound, don't starve it" cost class as the queues above.
default_fn!(default_c_notification_dispatch, usize, 8);
// Topology recompute (2026-09-16) — one small transaction per device, triggered
// reactively off a fresh metric poll rather than its own timer (see
// `QueueKind::TopologyRecompute`'s docs). Cheap DB-bound work, same cost class as the
// queues above.
default_fn!(default_c_topology_recompute, usize, 8);

/// Per-queue worker concurrency — "ограничение на кол-во одновременных потоков для
/// каждого процесса", one independent knob per pipeline stage.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ConcurrencyConfig {
    #[serde(default = "default_c_discovery")]
    pub discovery: usize,
    #[serde(default = "default_c_snmp_poll")]
    pub snmp_poll: usize,
    #[serde(default = "default_c_dedup")]
    pub dedup: usize,
    #[serde(default = "default_c_profile_apply")]
    pub profile_apply: usize,
    #[serde(default = "default_c_metric_poll")]
    pub metric_poll: usize,
    #[serde(default = "default_c_alert_eval")]
    pub alert_eval: usize,
    #[serde(default = "default_c_reachability_poll")]
    pub reachability_poll: usize,
    #[serde(default = "default_c_service_check_poll")]
    pub service_check_poll: usize,
    #[serde(default = "default_c_notification_dispatch")]
    pub notification_dispatch: usize,
    #[serde(default = "default_c_topology_recompute")]
    pub topology_recompute: usize,
}

impl Default for ConcurrencyConfig {
    fn default() -> Self {
        Self {
            discovery: default_c_discovery(),
            snmp_poll: default_c_snmp_poll(),
            dedup: default_c_dedup(),
            profile_apply: default_c_profile_apply(),
            metric_poll: default_c_metric_poll(),
            alert_eval: default_c_alert_eval(),
            reachability_poll: default_c_reachability_poll(),
            service_check_poll: default_c_service_check_poll(),
            notification_dispatch: default_c_notification_dispatch(),
            topology_recompute: default_c_topology_recompute(),
        }
    }
}

impl ConcurrencyConfig {
    /// Total worker slots across every queue — the number of DB-touching tasks a
    /// zero-config deployment runs concurrently against whichever connection the `jobs`
    /// domain resolves to. Factored out 2026-09-17 (audit finding #2, see
    /// `docs/Changelog/2026-09-17 - Аудит глазами оператора...md`) after this sum was
    /// found hand-duplicated as a field-by-field literal in `discovery-agent::main`'s
    /// startup warning *and* baked into `discovery_db::connect`'s SQLite default
    /// `pool_max_connections` as a separate hardcoded number — the two had already drifted
    /// apart once (`topology_recompute` added a 10th queue, bumping the true sum from 40 to
    /// 64, without the SQLite pool default following). A single method both call now means
    /// adding an 11th queue only has one place to update, not two silently-stale ones.
    pub fn sum(&self) -> usize {
        self.discovery
            + self.snmp_poll
            + self.dedup
            + self.profile_apply
            + self.metric_poll
            + self.alert_eval
            + self.reachability_poll
            + self.service_check_poll
            + self.notification_dispatch
            + self.topology_recompute
    }
}

/// Parses one `allowed_sources` entry — either a bare IP (`"10.0.0.5"`, matched as an
/// exact host) or a CIDR network (`"10.0.0.0/24"`). `ipnet::IpNet::from_str` alone rejects
/// the bare-IP form (it requires a `/prefix`), which would be a surprising papercut for
/// the overwhelmingly common case of allowlisting one specific device.
fn parse_allowed_source(entry: &str) -> anyhow::Result<ipnet::IpNet> {
    if let Ok(net) = entry.parse::<ipnet::IpNet>() {
        return Ok(net);
    }
    let ip: std::net::IpAddr = entry.parse().map_err(|_| anyhow::anyhow!("'{entry}' is not a valid IP address or CIDR network (e.g. \"10.0.0.5\" or \"10.0.0.0/24\")"))?;
    Ok(ipnet::IpNet::from(ip))
}

/// A [`SyslogConfig`]/[`SnmpTrapConfig::allowed_sources`] list, parsed once at listener
/// startup — SEC-19 (2026-09-22, ingress isolation). Kept opaque (not a bare
/// `Vec<ipnet::IpNet>`) so `discovery-agent`'s receive loops, which call [`Self::contains`]
/// once per incoming UDP packet, never need `ipnet` as a dependency of their own just to
/// call it. **Neither listener has any cryptographic source authentication of its own** —
/// syslog UDP carries none at all, and SNMP v1/v2c "auth" is a plaintext community string
/// anyone who can reach the bind address can read off the wire or simply guess (only
/// SNMPv3/USM, already supported for traps, actually authenticates the sender). This
/// allowlist is the network-layer mitigation for that gap — an empty list (the default)
/// preserves the pre-SEC-19 behavior of accepting from anywhere reachable, so upgrading
/// doesn't silently start dropping traffic from devices an operator hasn't listed yet.
pub struct AllowedSources(Vec<ipnet::IpNet>);

impl AllowedSources {
    fn parse(entries: &[String]) -> anyhow::Result<Self> {
        Ok(Self(
            entries
                .iter()
                .map(|e| parse_allowed_source(e))
                .collect::<anyhow::Result<Vec<_>>>()?,
        ))
    }

    /// `true` when `entries` was empty (no restriction configured) or `ip` matches one of
    /// the configured hosts/networks.
    pub fn contains(&self, ip: std::net::IpAddr) -> bool {
        self.0.is_empty() || self.0.iter().any(|net| net.contains(&ip))
    }
}

default_fn!(default_trap_bind_addr, String, "0.0.0.0:1162".to_string());
// In-memory bounded worker pool for decode+validate+upsert, deliberately NOT the SQL
// `jobs` queue — see `docs/Changelog/2026-08-30 - SNMP Trap.md` for why paying a ~5
// round-trip `claim()` per incoming UDP packet (a potentially bursty, best-effort event
// stream, unlike every other recurring queue here) doesn't pay for itself, and why
// pre-auth enqueueing would be a `jobs`-table DoS vector. Same cost class as
// `snmp_poll`/`metric_poll`.
default_fn!(default_trap_ingest_concurrency, usize, 8);
// Per-source-IP token bucket, checked before decode — the first, cheapest line of defense
// against a trap storm (a real network-wide event, not just malice) before anything costs
// CPU/DB time. 20/s comfortably covers a genuinely flapping port without needing tuning
// for the common case; a deployment with a much larger fleet behind one collector IP
// (unusual — traps are normally per-device source IPs, not proxied) can raise it.
default_fn!(default_trap_rate_limit_per_source_per_sec, u32, 20);

/// SNMP Trap ingestion (push-based, complementing the poll-based pipeline everything else
/// here uses) — 2026-08-30, see `docs/Changelog/2026-08-30 - SNMP Trap.md` for the full
/// design discussion and `docs/Architecture/Alerts и Metrics Pipeline.md` for how a
/// trap-derived row ends up feeding the exact same `AlertRule`/`AlertStateTracker` engine
/// as any polled table metric.
///
/// **`enabled` defaults to `false`** — unlike every other section in this file, turning
/// this on opens a UDP listening port, a real change in attack surface an existing
/// deployment shouldn't acquire silently on upgrade.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SnmpTrapConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Deliberately not the SNMP-standard port 162 by default — binding it needs root/
    /// `CAP_NET_BIND_SERVICE` on most systems, the same "avoid needing root for local
    /// testing" reasoning `SnmpCredentials::port`'s docs give for polling against `snmpd`
    /// on a high port. A real deployment wanting the standard port sets this explicitly
    /// (and grants the capability) rather than the process defaulting to needing root.
    #[serde(default = "default_trap_bind_addr")]
    pub bind_addr: String,
    #[serde(default = "default_trap_ingest_concurrency")]
    pub ingest_concurrency: usize,
    #[serde(default = "default_trap_rate_limit_per_source_per_sec")]
    pub rate_limit_per_source_per_sec: u32,
    /// Ingress ACL (SEC-19, 2026-09-22) — see [`AllowedSources`]'s docs for why this
    /// exists (v1/v2c has no cryptographic sender authentication) and why empty means
    /// "unrestricted", not "reject everything". Each entry is a bare IP or a CIDR network.
    #[serde(default)]
    pub allowed_sources: Vec<String>,
}

impl SnmpTrapConfig {
    /// Parses [`Self::allowed_sources`] once — call at listener startup, not per packet.
    /// Already validated by [`Config::validate`] at load time, so a parse failure here
    /// only happens if a config was mutated after loading without re-validating.
    pub fn compiled_allowed_sources(&self) -> anyhow::Result<AllowedSources> {
        AllowedSources::parse(&self.allowed_sources)
    }
}

impl Default for SnmpTrapConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_addr: default_trap_bind_addr(),
            ingest_concurrency: default_trap_ingest_concurrency(),
            rate_limit_per_source_per_sec: default_trap_rate_limit_per_source_per_sec(),
            allowed_sources: Vec::new(),
        }
    }
}

// Non-privileged mirror of syslog's standard UDP/514, same "don't need root for local
// testing" reasoning as `default_trap_bind_addr`'s 1162-mirrors-162.
default_fn!(default_syslog_bind_addr, String, "0.0.0.0:1514".to_string());
default_fn!(default_syslog_ingest_concurrency, usize, 8);
default_fn!(default_syslog_rate_limit_per_source_per_sec, u32, 20);

/// Syslog ingestion (push-based, direct sibling of [`SnmpTrapConfig`]) — 2026-09-06, see
/// `docs/Architecture/Syslog Ingestion.md`. **`enabled` defaults to `false`** for the same
/// reason as `SnmpTrapConfig::enabled` — turning this on opens a UDP listening port.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SyslogConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_syslog_bind_addr")]
    pub bind_addr: String,
    #[serde(default = "default_syslog_ingest_concurrency")]
    pub ingest_concurrency: usize,
    #[serde(default = "default_syslog_rate_limit_per_source_per_sec")]
    pub rate_limit_per_source_per_sec: u32,
    /// Ingress ACL (SEC-19, 2026-09-22) — see [`AllowedSources`]'s docs (syslog UDP has no
    /// sender authentication at all, cryptographic or otherwise) and why empty means
    /// "unrestricted", not "reject everything". Each entry is a bare IP or a CIDR network.
    #[serde(default)]
    pub allowed_sources: Vec<String>,
}

impl SyslogConfig {
    /// Parses [`Self::allowed_sources`] once — call at listener startup, not per packet.
    /// Already validated by [`Config::validate`] at load time, so a parse failure here
    /// only happens if a config was mutated after loading without re-validating.
    pub fn compiled_allowed_sources(&self) -> anyhow::Result<AllowedSources> {
        AllowedSources::parse(&self.allowed_sources)
    }
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_addr: default_syslog_bind_addr(),
            ingest_concurrency: default_syslog_ingest_concurrency(),
            rate_limit_per_source_per_sec: default_syslog_rate_limit_per_source_per_sec(),
            allowed_sources: Vec::new(),
        }
    }
}

default_fn!(default_poll_discovery_ms, u64, 500);
default_fn!(default_poll_snmp_poll_ms, u64, 500);
default_fn!(default_poll_dedup_ms, u64, 500);
default_fn!(default_poll_profile_apply_ms, u64, 500);
// Deliberately longer than the rest — `MetricPollHandler` self-throttles per (device,
// metric) via its own `last_polled` cadence already, so this pool's claim loop doesn't
// need to check as often as the network-I/O-bound queues above.
default_fn!(default_poll_metric_poll_ms, u64, 1000);
default_fn!(default_poll_alert_eval_ms, u64, 500);
default_fn!(default_poll_reachability_poll_ms, u64, 500);
default_fn!(default_poll_service_check_poll_ms, u64, 500);
default_fn!(default_poll_notification_dispatch_ms, u64, 500);
default_fn!(default_poll_topology_recompute_ms, u64, 500);

/// How often each queue's worker pool tries to claim a fresh batch of jobs — **not** how
/// often the underlying domain data gets re-polled (that's `PollIntervalsConfig`,
/// DB-backed and hot-reloadable). This is a spawn-time parameter baked into each
/// `discovery_queue::WorkerPoolConfig` when the pool starts — same "read once at process
/// start, needs a restart to change" bucket as [`ConcurrencyConfig`], not the
/// live-editable-via-dashboard bucket, since a running worker pool's claim loop isn't
/// re-consulting this value on every tick (unlike `PollIntervalsConfig`, which is).
/// Extracted from hardcoded `Duration::from_millis(...)` literals at every
/// `run_worker_pool` call site — direct user request 2026-08-18 (see [`StorageConfig`]'s
/// `pool_max_connections` docs for the full quote).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct WorkerPollIntervalConfig {
    #[serde(default = "default_poll_discovery_ms")]
    pub discovery_ms: u64,
    #[serde(default = "default_poll_snmp_poll_ms")]
    pub snmp_poll_ms: u64,
    #[serde(default = "default_poll_dedup_ms")]
    pub dedup_ms: u64,
    #[serde(default = "default_poll_profile_apply_ms")]
    pub profile_apply_ms: u64,
    #[serde(default = "default_poll_metric_poll_ms")]
    pub metric_poll_ms: u64,
    #[serde(default = "default_poll_alert_eval_ms")]
    pub alert_eval_ms: u64,
    #[serde(default = "default_poll_reachability_poll_ms")]
    pub reachability_poll_ms: u64,
    #[serde(default = "default_poll_service_check_poll_ms")]
    pub service_check_poll_ms: u64,
    #[serde(default = "default_poll_notification_dispatch_ms")]
    pub notification_dispatch_ms: u64,
    #[serde(default = "default_poll_topology_recompute_ms")]
    pub topology_recompute_ms: u64,
}

impl Default for WorkerPollIntervalConfig {
    fn default() -> Self {
        Self {
            discovery_ms: default_poll_discovery_ms(),
            snmp_poll_ms: default_poll_snmp_poll_ms(),
            dedup_ms: default_poll_dedup_ms(),
            profile_apply_ms: default_poll_profile_apply_ms(),
            metric_poll_ms: default_poll_metric_poll_ms(),
            alert_eval_ms: default_poll_alert_eval_ms(),
            reachability_poll_ms: default_poll_reachability_poll_ms(),
            service_check_poll_ms: default_poll_service_check_poll_ms(),
            notification_dispatch_ms: default_poll_notification_dispatch_ms(),
            topology_recompute_ms: default_poll_topology_recompute_ms(),
        }
    }
}

fn default_reclaim_check_interval_secs() -> u64 {
    30
}
fn default_reclaim_stale_after_secs() -> u64 {
    300
}

/// Parameters for the crash-recovery sweep (`discovery_queue::spawn_reclaim_loop`) that
/// requeues jobs stuck `in_progress` because the worker that claimed them died mid-job.
/// Same "spawn-time only, restart to change" bucket as [`WorkerPollIntervalConfig`] — the
/// loop captures both values once when it's spawned in `main`, it doesn't re-read them.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ReclaimConfig {
    /// How often the sweep runs.
    #[serde(default = "default_reclaim_check_interval_secs")]
    pub check_interval_secs: u64,
    /// How long a job may sit `in_progress` before it's considered abandoned and returned
    /// to `pending`. Must comfortably exceed the slowest real job's normal runtime, or a
    /// merely-slow-but-alive worker's job would get reclaimed and picked up twice.
    #[serde(default = "default_reclaim_stale_after_secs")]
    pub stale_after_secs: u64,
}

impl Default for ReclaimConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: default_reclaim_check_interval_secs(),
            stale_after_secs: default_reclaim_stale_after_secs(),
        }
    }
}

/// `/api/auth/login` brute-force protection (2026-09-12) — see
/// `discovery_web::LoginRateLimiter`'s docs. No `enabled` flag, unlike
/// `SnmpTrapConfig`: this can't be meaningfully turned off without reopening
/// the exact vulnerability it exists to close, so every deployment gets it whether this
/// section is present in `config.toml` or not — only the tuning is configurable.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LoginRateLimitConfig {
    /// Immediate attempts allowed before the trickle kicks in — default 5, matches the
    /// hardcoded value this replaces. Enough that a legitimate user fumbling a password a
    /// couple of times never notices anything.
    #[serde(default = "default_login_burst_capacity")]
    pub burst_capacity: u32,
    /// Sustained recovery rate once the burst is spent, in attempts/sec — default `1/60`
    /// (one recovered attempt roughly every minute), matches the hardcoded value this
    /// replaces. Still lets a real user in on their next honest try but reduces an online
    /// guesser to ~60 attempts/hour per (username, ip) pair.
    #[serde(default = "default_login_refill_per_sec")]
    pub refill_per_sec: f64,
    /// How often the stale-entry sweep runs — see `stale_after_secs`'s docs for what it
    /// removes and why this is safe. Default 15 minutes: frequent enough that a long-lived
    /// process serving many distinct attackers/typo-prone users doesn't accumulate entries
    /// unboundedly, infrequent enough to be a non-event on any deployment's resource budget.
    #[serde(default = "default_login_rate_limit_sweep_interval_secs")]
    pub sweep_interval_secs: u64,
    /// A (username, ip) bucket untouched for longer than this is evicted — default 1 hour.
    /// Safe by construction, not just "probably fine": `TokenBucket` refills continuously
    /// up to its own capacity, so a bucket idle this long is already back at full capacity
    /// — evicting it and letting the next attempt recreate it fresh is behaviorally
    /// identical to leaving it in place, just without holding the memory. Must comfortably
    /// exceed `1.0 / refill_per_sec` (how long a fully-drained bucket takes to refill one
    /// token) or a slow-but-genuine retry could get evicted (and thus reset) mid-throttle —
    /// harmless for a real user (they just get to try again sooner), but worth keeping in
    /// mind if these are ever tuned independently.
    #[serde(default = "default_login_rate_limit_stale_after_secs")]
    pub stale_after_secs: u64,
    /// Proxy addresses allowed to supply an `X-Forwarded-For` chain. Empty by default:
    /// deployments that do not explicitly list their reverse proxy trust only the direct
    /// transport peer and ignore forwarded headers.
    #[serde(default)]
    pub trusted_proxy_ips: Vec<IpAddr>,
}

impl Default for LoginRateLimitConfig {
    fn default() -> Self {
        Self {
            burst_capacity: default_login_burst_capacity(),
            refill_per_sec: default_login_refill_per_sec(),
            sweep_interval_secs: default_login_rate_limit_sweep_interval_secs(),
            stale_after_secs: default_login_rate_limit_stale_after_secs(),
            trusted_proxy_ips: Vec::new(),
        }
    }
}

fn default_login_burst_capacity() -> u32 {
    5
}
fn default_login_refill_per_sec() -> f64 {
    1.0 / 60.0
}
fn default_login_rate_limit_sweep_interval_secs() -> u64 {
    900
}
fn default_login_rate_limit_stale_after_secs() -> u64 {
    3600
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub storage: StorageConfig,
    pub server: ServerConfig,
    pub logging: LoggingConfig,
    pub concurrency: ConcurrencyConfig,
    pub poll_intervals: PollIntervalsConfig,
    pub worker_poll_interval: WorkerPollIntervalConfig,
    pub reclaim: ReclaimConfig,
    pub snmp_trap: SnmpTrapConfig,
    pub syslog: SyslogConfig,
    pub login_rate_limit: LoginRateLimitConfig,
}

impl Config {
    /// Reads `CONFIG_FILE` (default `config.toml`, resolved against the current
    /// directory). A missing file is not an error — it's `Config::default()`, i.e. memory
    /// storage, nothing external required, exactly today's zero-setup `cargo run`. A
    /// *present but invalid* file (bad TOML, unknown `kind`, ...) is an error — silently
    /// falling back to defaults there would hide a typo as "storage quietly reset to
    /// memory", which is a much worse failure mode than refusing to start.
    pub fn load() -> anyhow::Result<Self> {
        Self::load_from_path(&Self::config_file_path())
    }

    /// The path `load()` reads/`write_storage` writes — `CONFIG_FILE` env var, default
    /// `./config.toml`. Exposed separately so `discovery-web`'s settings endpoints target
    /// the exact same file `load()` will read on the next restart, without duplicating the
    /// env-var-with-default logic.
    pub fn config_file_path() -> PathBuf {
        PathBuf::from(std::env::var("CONFIG_FILE").unwrap_or_else(|_| "config.toml".to_string()))
    }

    /// Split out from [`Config::load`] so tests can exercise loading without mutating the
    /// process-wide `CONFIG_FILE` env var — `cargo test` runs tests in the same process
    /// concurrently, so racing on shared env state would make them flaky.
    pub fn load_from_path(path: &std::path::Path) -> anyhow::Result<Self> {
        let config = match std::fs::read_to_string(path) {
            Ok(text) => {
                toml::from_str(&text).map_err(|e| anyhow::anyhow!("{}: {}", path.display(), e))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Config::default(),
            Err(e) => return Err(anyhow::anyhow!("reading {}: {}", path.display(), e)),
        };
        Self::validate(&config)?;
        Ok(config)
    }

    fn validate(config: &Config) -> anyhow::Result<()> {
        let storage = &config.storage;

        let mut seen = HashSet::new();
        for db in &storage.databases {
            if db.name.is_empty() {
                anyhow::bail!("storage.databases: every entry needs a non-empty \"name\"");
            }
            if !seen.insert(db.name.as_str()) {
                anyhow::bail!(
                    "storage.databases: duplicate name \"{}\" — names must be unique",
                    db.name
                );
            }
            match db.kind {
                // Reuses `connection_url`'s own field checks (host/database/username)
                // rather than duplicating "which fields are required" here — one place
                // decides that, this just propagates whatever it says.
                DbKind::Postgres | DbKind::MySql => {
                    db.connection_url()?;
                }
                DbKind::Sqlite if db.file_path.is_none() => {
                    anyhow::bail!("storage.databases[\"{}\"]: kind = \"sqlite\" requires \"file_path\" to be set", db.name);
                }
                // Reuses `clickhouse_http_url`'s own field check (host), same reasoning
                // as the postgres/mysql branch above.
                DbKind::ClickHouse => {
                    db.clickhouse_http_url()?;
                }
                // Reuses `cassandra_config`'s own field checks (host/database), same
                // reasoning as the branches above.
                DbKind::Cassandra => {
                    db.cassandra_config()?;
                }
                _ => {}
            }
        }

        let known: HashSet<&str> = storage
            .databases
            .iter()
            .map(|db| db.name.as_str())
            .collect();
        match storage.default_database.as_deref() {
            Some(default) if !known.contains(default) => {
                anyhow::bail!("storage.default_database = \"{default}\" does not match any entry in storage.databases");
            }
            None if !storage.databases.is_empty() => {
                // Every `DomainRouting` field that's left `None` falls back to this — with
                // one or more databases configured but no default, an unrouted domain
                // would have nothing to resolve to. Caught here, at config-load time, not
                // as a confusing failure deep inside `ConnectionRegistry::build`.
                anyhow::bail!("storage.databases is non-empty but storage.default_database is not set — every domain needs somewhere to fall back to");
            }
            _ => {}
        }
        for referenced in storage.routing.referenced_names() {
            if !known.contains(referenced) {
                anyhow::bail!("storage.routing references unknown database \"{referenced}\" — not present in storage.databases");
            }
        }

        // ClickHouse is column-oriented and weak at point UPDATE/DELETE — a structural
        // mismatch for every domain except `logs` (pure `append`, see
        // `discovery_logging::LogStore`'s docs): `device_metrics`/`device_metric_history`
        // update rows in place on an unchanged poll, `alerts` updates in place on
        // `StillActive`, both explicitly delete a device's rows on removal. Direct user
        // question 2026-08-18 confirmed this restriction is intentional, not an oversight:
        // "будут доступны для хранения метрик, тревог или для настроек... Просто в этом
        // нет необходимости" — caught here, at config-load time, with a clear message,
        // rather than as a confusing failure (or worse, silent data-quality issue) deep
        // inside whichever store first tries an UPDATE/DELETE against ClickHouse.
        let by_name: std::collections::HashMap<&str, &DatabaseConnConfig> = storage
            .databases
            .iter()
            .map(|db| (db.name.as_str(), db))
            .collect();
        for (label, field) in storage.routing.all_with_labels() {
            let resolved_name = field.as_deref().or(storage.default_database.as_deref());
            if let Some(name) = resolved_name {
                if let Some(db) = by_name.get(name) {
                    if db.kind == DbKind::ClickHouse && label != "logs" {
                        anyhow::bail!(
                            "storage.routing.{label} resolves to \"{name}\" (kind = \"clickhouse\") — only the \"logs\" domain may use a ClickHouse-backed database"
                        );
                    }
                    // Cassandra tolerates update-in-place/delete fine (unlike ClickHouse
                    // above) — this restriction isn't about a structural mismatch, it's
                    // simply that `discovery-devices::CassandraDeviceMetricsStore`/
                    // `discovery-alerts::CassandraAlertStore` are the only store
                    // implementations this kind has today. Direct user choices 2026-08-18,
                    // after being asked which domain: "device_metrics/device_metric_history"
                    // (third pass), then "alerts" (fourth pass) — see `DbKind::Cassandra`'s
                    // docs.
                    if db.kind == DbKind::Cassandra
                        && label != "device_metrics"
                        && label != "alerts"
                    {
                        anyhow::bail!(
                            "storage.routing.{label} resolves to \"{name}\" (kind = \"cassandra\") — only the \"device_metrics\"/\"alerts\" domains may use a Cassandra-backed database"
                        );
                    }
                }
            }
        }

        // Fail at load time, not on the first incoming packet — same "loudly reject a bad
        // config up front" posture as every other check in this function.
        for entry in &config.snmp_trap.allowed_sources {
            parse_allowed_source(entry)
                .map_err(|e| anyhow::anyhow!("snmp_trap.allowed_sources: {e}"))?;
        }
        for entry in &config.syslog.allowed_sources {
            parse_allowed_source(entry)
                .map_err(|e| anyhow::anyhow!("syslog.allowed_sources: {e}"))?;
        }

        Ok(())
    }

    /// Rewrites just the `[storage]` table of the config file at `path` (format-preserving
    /// via `toml_edit` — every other section's comments/formatting/key order survive
    /// untouched, load-bearing since `config.toml` is a hand-maintained reference document,
    /// see its own header). Validates the *resulting* full config before writing anything —
    /// a bad update must never land on disk half-applied, and never past a config a fresh
    /// process couldn't actually `load()` again.
    ///
    /// Callers (`discovery-web`'s `PUT /api/settings/databases`/`PUT /api/settings/routing`)
    /// each read-modify-write one piece of `StorageConfig` (databases+default, or routing)
    /// against whatever's on disk *right now* — see those handlers' docs for why a fresh
    /// `load()` first, not a cached `Config`, is what "modify" starts from.
    pub fn write_storage(path: &std::path::Path, storage: &StorageConfig) -> anyhow::Result<()> {
        let mut candidate = Self::load_from_path(path).unwrap_or_default();
        candidate.storage = storage.clone();
        Self::validate(&candidate).context("the resulting config would be invalid")?;

        let existing_text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let mut doc: toml_edit::DocumentMut = if existing_text.trim().is_empty() {
            toml_edit::DocumentMut::new()
        } else {
            existing_text.parse().with_context(|| {
                format!("parsing existing {} to merge the update in", path.display())
            })?
        };

        let storage_doc = toml_edit::ser::to_document(storage)
            .context("serializing the updated storage config")?;
        doc["storage"] = storage_doc.as_table().clone().into();

        std::fs::write(path, doc.to_string())
            .with_context(|| format!("writing {}", path.display()))?;

        // `StorageConfig` may contain plaintext database passwords.  The dashboard is
        // allowed to create/update this file, so keep the resulting file private even
        // when the process umask is permissive or the file already existed with broader
        // permissions.  The checked-in example configs remain ordinary documentation;
        // this applies to the runtime config actually written by the API.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = std::fs::metadata(path)
                .with_context(|| format!("reading permissions for {}", path.display()))?
                .permissions();
            permissions.set_mode(0o600);
            std::fs::set_permissions(path, permissions)
                .with_context(|| format!("restricting permissions for {}", path.display()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_is_default_memory_storage_not_an_error() {
        let dir = std::env::temp_dir().join(format!(
            "discovery-bootstrap-test-missing-{}",
            std::process::id()
        ));
        let config = Config::load_from_path(&dir.join("does-not-exist.toml")).unwrap();
        assert!(
            config.storage.databases.is_empty(),
            "zero-config default must be the implicit memory connection"
        );
        assert_eq!(config.storage.default_database, None);
        assert_eq!(config.server.addr, "127.0.0.1:8088");
    }

    #[test]
    fn partial_override_keeps_other_defaults() {
        let path = std::env::temp_dir().join(format!(
            "discovery-bootstrap-test-partial-{}.toml",
            std::process::id()
        ));
        std::fs::write(&path, "[server]\naddr = \"0.0.0.0:9000\"\n").unwrap();
        let config = Config::load_from_path(&path).unwrap();
        assert_eq!(config.server.addr, "0.0.0.0:9000");
        assert!(
            config.server.enable_rest,
            "untouched field must keep its default"
        );
        assert!(
            config.server.enable_webui,
            "untouched field must keep its default"
        );
        assert!(
            config.storage.databases.is_empty(),
            "untouched section must keep its default"
        );
        assert_eq!(
            config.concurrency.snmp_poll, 8,
            "untouched section must keep its default"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn enable_rest_and_enable_webui_default_to_true_and_can_be_overridden_independently() {
        let config = Config::default();
        assert!(config.server.enable_rest);
        assert!(config.server.enable_webui);

        let path = write_config("[server]\nenable_rest = false\n");
        let config = Config::load_from_path(&path).unwrap();
        assert!(!config.server.enable_rest);
        assert!(
            config.server.enable_webui,
            "untouched field must keep its default"
        );
        std::fs::remove_file(&path).ok();

        let path = write_config("[server]\nenable_webui = false\n");
        let config = Config::load_from_path(&path).unwrap();
        assert!(
            config.server.enable_rest,
            "untouched field must keep its default"
        );
        assert!(!config.server.enable_webui);
        std::fs::remove_file(&path).ok();
    }

    fn write_config(text: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "discovery-bootstrap-test-{}-{}.toml",
            std::process::id(),
            rand_suffix()
        ));
        std::fs::write(&path, text).unwrap();
        path
    }

    // A cheap, dependency-free "unique enough for a temp filename" source — several tests
    // in this module run in parallel and each needs its own file.
    fn rand_suffix() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    #[test]
    fn pool_max_connections_defaults_to_none_and_busy_timeout_has_a_sane_default() {
        let db = DatabaseConnConfig {
            name: "main".into(),
            kind: DbKind::Sqlite,
            host: None,
            port: None,
            database: None,
            username: None,
            password: None,
            file_path: Some(PathBuf::from("x.sqlite3")),
            pool_max_connections: None,
            sqlite_busy_timeout_secs: default_sqlite_busy_timeout_secs(),
        };
        assert_eq!(
            db.pool_max_connections, None,
            "None must mean \"use the backend-specific built-in default\""
        );
        assert_eq!(db.sqlite_busy_timeout_secs, 5);
    }

    #[test]
    fn pool_max_connections_can_be_overridden() {
        let path = write_config(
            "[[storage.databases]]\nname = \"main\"\nkind = \"sqlite\"\nfile_path = \"x.sqlite3\"\npool_max_connections = 25\nsqlite_busy_timeout_secs = 10\n\n[storage]\ndefault_database = \"main\"\n",
        );
        let config = Config::load_from_path(&path).unwrap();
        assert_eq!(config.storage.databases[0].pool_max_connections, Some(25));
        assert_eq!(config.storage.databases[0].sqlite_busy_timeout_secs, 10);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn worker_poll_interval_and_reclaim_default_to_the_previously_hardcoded_values() {
        let config = Config::default();
        assert_eq!(config.worker_poll_interval.discovery_ms, 500);
        assert_eq!(config.worker_poll_interval.snmp_poll_ms, 500);
        assert_eq!(config.worker_poll_interval.dedup_ms, 500);
        assert_eq!(config.worker_poll_interval.profile_apply_ms, 500);
        assert_eq!(
            config.worker_poll_interval.metric_poll_ms, 1000,
            "MetricPoll was always the one deliberately slower queue"
        );
        assert_eq!(config.worker_poll_interval.alert_eval_ms, 500);
        assert_eq!(config.worker_poll_interval.reachability_poll_ms, 500);
        assert_eq!(config.reclaim.check_interval_secs, 30);
        assert_eq!(config.reclaim.stale_after_secs, 300);
    }

    #[test]
    fn worker_poll_interval_partial_override_keeps_the_rest_default() {
        let path = std::env::temp_dir().join(format!(
            "discovery-bootstrap-test-wpi-{}.toml",
            std::process::id()
        ));
        std::fs::write(
            &path,
            "[worker_poll_interval]\nmetric_poll_ms = 2500\n\n[reclaim]\nstale_after_secs = 600\n",
        )
        .unwrap();
        let config = Config::load_from_path(&path).unwrap();
        assert_eq!(config.worker_poll_interval.metric_poll_ms, 2500);
        assert_eq!(
            config.worker_poll_interval.discovery_ms, 500,
            "untouched field must keep its default"
        );
        assert_eq!(config.reclaim.stale_after_secs, 600);
        assert_eq!(
            config.reclaim.check_interval_secs, 30,
            "untouched field must keep its default"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn postgres_or_mysql_database_without_required_fields_is_rejected() {
        let path = write_config("[[storage.databases]]\nname = \"main\"\nkind = \"postgres\"\n");
        assert!(
            Config::load_from_path(&path).is_err(),
            "no host/database/username at all"
        );
        std::fs::remove_file(&path).ok();

        let path = write_config(
            "[[storage.databases]]\nname = \"main\"\nkind = \"mysql\"\nhost = \"localhost\"\n",
        );
        assert!(
            Config::load_from_path(&path).is_err(),
            "host alone isn't enough — database/username still missing"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn sqlite_database_without_file_path_is_rejected() {
        let path = write_config("[[storage.databases]]\nname = \"main\"\nkind = \"sqlite\"\n");
        assert!(Config::load_from_path(&path).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn postgres_database_with_full_connection_details_loads_fine_and_builds_the_expected_url() {
        let path = write_config(
            "[[storage.databases]]\nname = \"main\"\nkind = \"postgres\"\nhost = \"localhost\"\nport = 5433\ndatabase = \"discovery\"\nusername = \"app\"\npassword = \"s3cr3t\"\n\n[storage]\ndefault_database = \"main\"\n",
        );
        let config = Config::load_from_path(&path).unwrap();
        assert_eq!(config.storage.databases.len(), 1);
        let db = &config.storage.databases[0];
        assert_eq!(db.kind, DbKind::Postgres);
        assert_eq!(db.host.as_deref(), Some("localhost"));
        assert_eq!(db.port, Some(5433));
        assert_eq!(db.database.as_deref(), Some("discovery"));
        assert_eq!(db.username.as_deref(), Some("app"));
        assert_eq!(
            db.connection_url().unwrap(),
            "postgres://app:s3cr3t@localhost:5433/discovery"
        );
        assert_eq!(config.storage.default_database.as_deref(), Some("main"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn connection_url_omits_the_password_segment_entirely_when_unset() {
        let db = DatabaseConnConfig {
            name: "main".into(),
            kind: DbKind::Postgres,
            host: Some("127.0.0.1".into()),
            port: None,
            database: Some("discovery_dev".into()),
            username: Some("vladislav".into()),
            password: None,
            file_path: None,
            pool_max_connections: None,
            sqlite_busy_timeout_secs: 5,
        };
        // No explicit port either — must fall back to whatever `url::Url` considers the
        // default for the scheme is irrelevant here (postgres isn't a "special" scheme to
        // the URL spec, so there's no built-in default port); what matters is that the
        // password segment (`user:pass@`) is entirely absent, not an empty `user:@`.
        assert_eq!(
            db.connection_url().unwrap(),
            "postgres://vladislav@127.0.0.1/discovery_dev"
        );
    }

    #[test]
    fn connection_url_correctly_encodes_special_characters_in_the_password() {
        let db = DatabaseConnConfig {
            name: "main".into(),
            kind: DbKind::MySql,
            host: Some("db.internal".into()),
            port: Some(3306),
            database: Some("app".into()),
            username: Some("root".into()),
            password: Some("p@ss:w/ord#1".into()),
            file_path: None,
            pool_max_connections: None,
            sqlite_busy_timeout_secs: 5,
        };
        let url = db.connection_url().unwrap();
        // Doesn't assert the exact percent-encoded password string (which characters get
        // encoded is `url::Url`'s implementation detail) — what actually matters is that a
        // password containing `@`/`:`/`/`/`#` didn't corrupt the *other* parts of the URL
        // a naive string-concatenation approach would be at real risk of doing (the `@`
        // could be mistaken for the userinfo/host separator, `/` for a path boundary, `#`
        // for a fragment start). Parsing the built URL back out must still see the correct
        // host/path/username.
        let parsed = url::Url::parse(&url).unwrap();
        assert_eq!(parsed.host_str(), Some("db.internal"));
        assert_eq!(parsed.port(), Some(3306));
        assert_eq!(parsed.path(), "/app");
        assert_eq!(parsed.username(), "root");
        assert!(
            parsed.password().is_some(),
            "a password was set and must still be present in some (percent-encoded) form"
        );
    }

    #[test]
    fn non_empty_databases_without_a_default_is_rejected() {
        let path = write_config("[[storage.databases]]\nname = \"main\"\nkind = \"sqlite\"\nfile_path = \"x.sqlite3\"\n");
        assert!(
            Config::load_from_path(&path).is_err(),
            "an unrouted domain would have nothing to fall back to"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn default_database_referencing_an_unknown_name_is_rejected() {
        let path = write_config("[storage]\ndefault_database = \"nope\"\n");
        assert!(Config::load_from_path(&path).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn routing_referencing_an_unknown_name_is_rejected() {
        let path = write_config(
            "[[storage.databases]]\nname = \"main\"\nkind = \"sqlite\"\nfile_path = \"x.sqlite3\"\n\n[storage.routing]\nalerts = \"nope\"\n",
        );
        assert!(Config::load_from_path(&path).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_clickhouse_database_routed_to_a_domain_other_than_logs_is_rejected() {
        let path = write_config(
            "[[storage.databases]]\nname = \"ch\"\nkind = \"clickhouse\"\nhost = \"127.0.0.1\"\n\n\
             [storage]\ndefault_database = \"ch\"\n",
        );
        let err = Config::load_from_path(&path).unwrap_err();
        assert!(
            err.to_string().contains("clickhouse"),
            "expected a clickhouse-specific rejection, got: {err}"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_clickhouse_database_routed_only_to_logs_loads_fine() {
        let path = write_config(
            "[[storage.databases]]\nname = \"main\"\nkind = \"sqlite\"\nfile_path = \"a.sqlite3\"\n\n\
             [[storage.databases]]\nname = \"ch\"\nkind = \"clickhouse\"\nhost = \"127.0.0.1\"\n\n\
             [storage]\ndefault_database = \"main\"\n\n\
             [storage.routing]\nlogs = \"ch\"\n",
        );
        assert!(Config::load_from_path(&path).is_ok());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_cassandra_database_routed_to_a_domain_other_than_device_metrics_is_rejected() {
        let path = write_config(
            "[[storage.databases]]\nname = \"cass\"\nkind = \"cassandra\"\nhost = \"127.0.0.1\"\ndatabase = \"ks\"\n\n\
             [storage]\ndefault_database = \"cass\"\n",
        );
        let err = Config::load_from_path(&path).unwrap_err();
        assert!(
            err.to_string().contains("cassandra"),
            "expected a cassandra-specific rejection, got: {err}"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_cassandra_database_routed_only_to_device_metrics_loads_fine() {
        let path = write_config(
            "[[storage.databases]]\nname = \"main\"\nkind = \"sqlite\"\nfile_path = \"a.sqlite3\"\n\n\
             [[storage.databases]]\nname = \"cass\"\nkind = \"cassandra\"\nhost = \"127.0.0.1\"\ndatabase = \"ks\"\n\n\
             [storage]\ndefault_database = \"main\"\n\n\
             [storage.routing]\ndevice_metrics = \"cass\"\n",
        );
        assert!(Config::load_from_path(&path).is_ok());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_cassandra_database_routed_only_to_alerts_loads_fine() {
        let path = write_config(
            "[[storage.databases]]\nname = \"main\"\nkind = \"sqlite\"\nfile_path = \"a.sqlite3\"\n\n\
             [[storage.databases]]\nname = \"cass\"\nkind = \"cassandra\"\nhost = \"127.0.0.1\"\ndatabase = \"ks\"\n\n\
             [storage]\ndefault_database = \"main\"\n\n\
             [storage.routing]\nalerts = \"cass\"\n",
        );
        assert!(Config::load_from_path(&path).is_ok());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_cassandra_database_routed_to_both_device_metrics_and_alerts_loads_fine() {
        let path = write_config(
            "[[storage.databases]]\nname = \"main\"\nkind = \"sqlite\"\nfile_path = \"a.sqlite3\"\n\n\
             [[storage.databases]]\nname = \"cass\"\nkind = \"cassandra\"\nhost = \"127.0.0.1\"\ndatabase = \"ks\"\n\n\
             [storage]\ndefault_database = \"main\"\n\n\
             [storage.routing]\ndevice_metrics = \"cass\"\nalerts = \"cass\"\n",
        );
        assert!(Config::load_from_path(&path).is_ok());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn cassandra_database_without_a_keyspace_is_rejected() {
        let path = write_config(
            "[[storage.databases]]\nname = \"cass\"\nkind = \"cassandra\"\nhost = \"127.0.0.1\"\n",
        );
        assert!(Config::load_from_path(&path).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn duplicate_database_names_are_rejected() {
        let path = write_config(
            "[[storage.databases]]\nname = \"main\"\nkind = \"sqlite\"\nfile_path = \"a.sqlite3\"\n\n\
             [[storage.databases]]\nname = \"main\"\nkind = \"sqlite\"\nfile_path = \"b.sqlite3\"\n",
        );
        assert!(Config::load_from_path(&path).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn multiple_named_databases_with_per_domain_routing_load_fine() {
        let path = write_config(
            "[[storage.databases]]\nname = \"main\"\nkind = \"postgres\"\nhost = \"localhost\"\ndatabase = \"main\"\nusername = \"app\"\n\n\
             [[storage.databases]]\nname = \"alerts_db\"\nkind = \"sqlite\"\nfile_path = \"alerts.sqlite3\"\n\n\
             [[storage.databases]]\nname = \"unused\"\nkind = \"mysql\"\nhost = \"localhost\"\ndatabase = \"unused\"\nusername = \"app\"\n\n\
             [storage]\ndefault_database = \"main\"\n\n\
             [storage.routing]\nalerts = \"alerts_db\"\n",
        );
        let config = Config::load_from_path(&path).unwrap();
        assert_eq!(
            config.storage.databases.len(),
            3,
            "an unreferenced database is still a valid, loadable entry"
        );
        assert_eq!(config.storage.routing.alerts.as_deref(), Some("alerts_db"));
        assert_eq!(
            config.storage.routing.devices, None,
            "unset — falls back to default_database at resolve time"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn logging_filter_falls_back_to_the_shared_level_when_unset() {
        let logging = LoggingConfig {
            level: "warn".into(),
            ..Default::default()
        };
        assert_eq!(logging.console_filter(), "warn");
        assert_eq!(logging.file_filter(), "warn");
        let logging = LoggingConfig {
            level: "warn".into(),
            level_file: "debug".into(),
            ..Default::default()
        };
        assert_eq!(logging.file_filter(), "debug");
        assert_eq!(logging.console_filter(), "warn");
    }

    #[test]
    fn write_storage_on_a_missing_file_creates_it_with_just_the_storage_table() {
        let path = std::env::temp_dir().join(format!(
            "discovery-bootstrap-test-write-missing-{}-{}.toml",
            std::process::id(),
            rand_suffix()
        ));
        let storage = StorageConfig {
            databases: vec![DatabaseConnConfig {
                name: "main".into(),
                kind: DbKind::Sqlite,
                host: None,
                port: None,
                database: None,
                username: None,
                password: None,
                file_path: Some("x.sqlite3".into()),
                pool_max_connections: None,
                sqlite_busy_timeout_secs: 5,
            }],
            default_database: Some("main".into()),
            routing: DomainRouting::default(),
        };
        Config::write_storage(&path, &storage).unwrap();

        let reloaded = Config::load_from_path(&path).unwrap();
        assert_eq!(reloaded.storage.databases.len(), 1);
        assert_eq!(reloaded.storage.databases[0].name, "main");
        assert_eq!(reloaded.storage.default_database.as_deref(), Some("main"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600,
                "new runtime config must not be world/group-readable"
            );
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn write_storage_preserves_unrelated_sections_and_their_comments() {
        let path = write_config(
            "# a hand-written comment that must survive\n[server]\naddr = \"0.0.0.0:9000\"\n\n[storage]\ndefault_database = \"old\"\n\n[[storage.databases]]\nname = \"old\"\nkind = \"sqlite\"\nfile_path = \"old.sqlite3\"\n",
        );

        let new_storage = StorageConfig {
            databases: vec![DatabaseConnConfig {
                name: "new".into(),
                kind: DbKind::Sqlite,
                host: None,
                port: None,
                database: None,
                username: None,
                password: None,
                file_path: Some("new.sqlite3".into()),
                pool_max_connections: None,
                sqlite_busy_timeout_secs: 5,
            }],
            default_database: Some("new".into()),
            routing: DomainRouting::default(),
        };
        Config::write_storage(&path, &new_storage).unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(
            written.contains("a hand-written comment that must survive"),
            "comments outside [storage] must survive:\n{written}"
        );
        assert!(
            written.contains("0.0.0.0:9000"),
            "unrelated [server] section must survive untouched:\n{written}"
        );

        let reloaded = Config::load_from_path(&path).unwrap();
        assert_eq!(reloaded.server.addr, "0.0.0.0:9000");
        assert_eq!(reloaded.storage.databases.len(), 1);
        assert_eq!(
            reloaded.storage.databases[0].name, "new",
            "the storage table itself must be fully replaced, not merged field-by-field"
        );
        assert_eq!(reloaded.storage.default_database.as_deref(), Some("new"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn write_storage_rejects_an_invalid_update_without_touching_the_file() {
        let path = write_config("[server]\naddr = \"0.0.0.0:9000\"\n");
        let before = std::fs::read_to_string(&path).unwrap();

        let invalid = StorageConfig {
            databases: vec![DatabaseConnConfig {
                name: "main".into(),
                kind: DbKind::Postgres,
                host: None,
                port: None,
                database: None,
                username: None,
                password: None,
                file_path: None,
                pool_max_connections: None,
                sqlite_busy_timeout_secs: 5,
            }],
            default_database: Some("main".into()),
            routing: DomainRouting::default(),
        };
        assert!(
            Config::write_storage(&path, &invalid).is_err(),
            "postgres without a url must be rejected before writing"
        );

        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            before, after,
            "a rejected update must never touch the file on disk"
        );
        std::fs::remove_file(&path).ok();
    }

    #[cfg(unix)]
    #[test]
    fn write_storage_restricts_runtime_config_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = write_config("[server]\naddr = \"127.0.0.1:8088\"\n");
        let mut broad = std::fs::metadata(&path).unwrap().permissions();
        broad.set_mode(0o644);
        std::fs::set_permissions(&path, broad).unwrap();

        Config::write_storage(&path, &StorageConfig::default()).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "runtime config must not be world/group-readable"
        );
        std::fs::remove_file(&path).ok();
    }

    // ---------------------------------------------------- SEC-19 ingress ACL

    #[test]
    fn allowed_sources_empty_list_permits_everything() {
        let allowed = AllowedSources::parse(&[]).unwrap();
        assert!(
            allowed.contains("203.0.113.7".parse().unwrap()),
            "empty allowed_sources must preserve pre-SEC-19 behavior: accept from anywhere"
        );
    }

    #[test]
    fn allowed_sources_matches_bare_ip_as_exact_host_and_cidr_as_a_range() {
        let allowed =
            AllowedSources::parse(&["10.0.0.5".to_string(), "192.168.1.0/24".to_string()]).unwrap();
        assert!(allowed.contains("10.0.0.5".parse().unwrap()));
        assert!(
            !allowed.contains("10.0.0.6".parse().unwrap()),
            "a bare IP entry must match only that exact host"
        );
        assert!(allowed.contains("192.168.1.42".parse().unwrap()));
        assert!(!allowed.contains("192.168.2.1".parse().unwrap()));
        assert!(
            !allowed.contains("203.0.113.7".parse().unwrap()),
            "an address matching neither entry must be rejected once the list is non-empty"
        );
    }

    #[test]
    fn allowed_sources_rejects_garbage_at_config_load_time() {
        let path = write_config("[snmp_trap]\nallowed_sources = [\"not-an-ip\"]\n");
        let err = Config::load_from_path(&path).unwrap_err();
        assert!(
            err.to_string().contains("snmp_trap.allowed_sources"),
            "error must name which section: {err}"
        );
        std::fs::remove_file(&path).ok();

        let path = write_config("[syslog]\nallowed_sources = [\"10.0.0.0/99\"]\n");
        let err = Config::load_from_path(&path).unwrap_err();
        assert!(
            err.to_string().contains("syslog.allowed_sources"),
            "error must name which section: {err}"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn allowed_sources_default_to_empty_for_both_listeners() {
        let config = Config::default();
        assert!(config.snmp_trap.allowed_sources.is_empty());
        assert!(config.syslog.allowed_sources.is_empty());
    }
}
