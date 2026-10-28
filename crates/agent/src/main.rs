mod bootstrap_admin;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use discovery_agent::handlers::{
    AlertEvalHandler, DedupHandler, DiscoveryHandler, MetricPollHandler, ProfileApplyHandler,
    ReachabilityPollHandler, ServiceCheckPollHandler, SnmpPollHandler,
};
use discovery_agent::notification_dispatch::NotificationDispatchHandler;
use discovery_agent::operator_actions::OperatorActionHandler;
use discovery_agent::topology_recompute::TopologyRecomputeHandler;
use discovery_alerts::{AlertListQuery, AlertSortBy, AlertStore};
use discovery_auth::AuthStore;
use discovery_bootstrap::Config;
use discovery_config_store::{
    DiscoveryConfigStore, GroupAlertRuleStore, MaintenanceWindowStore, NotificationChannelStore,
    NotificationRuleStore, ProfileStore, SettingsStore, TopologyRuleStore,
};
use discovery_core::{
    ActiveChains, AlertState, AlertStateTracker, QueueKind, SortDir, WorkerRegistry,
};
use discovery_db::{ConnectionRegistry, Domain, DomainConnection};
use discovery_devices::{DeviceMetricsStore, DeviceStore};
use discovery_dsl::{AlertEvaluator, ProfileMatcher};
use discovery_journal::JournalStore;
use discovery_logging::LogStore;
use discovery_notify::{Notifier, RealNotifier};
use discovery_ping::{IcmpPinger, Pinger};
use discovery_queue::{run_worker_pool, spawn_reclaim_loop, JobQueueStore, WorkerPoolConfig};
use discovery_servicecheck::{RealServiceChecker, ServiceChecker};
use discovery_snmp::{RealSnmpClient, SnmpClient};
use discovery_ssh::{CliClient, RealCliClient};
use tracing::{info, warn};

type Stores = (
    Arc<dyn JobQueueStore>,
    Arc<dyn DeviceStore>,
    Arc<dyn DeviceMetricsStore>,
    Arc<dyn ProfileStore>,
    Arc<dyn DiscoveryConfigStore>,
    Arc<dyn LogStore>,
    Arc<dyn SettingsStore>,
    Arc<dyn AlertStore>,
    Arc<dyn AuthStore>,
    Arc<dyn JournalStore>,
    Arc<dyn MaintenanceWindowStore>,
    Arc<dyn NotificationRuleStore>,
    Arc<dyn NotificationChannelStore>,
    Arc<dyn TopologyRuleStore>,
    Arc<dyn discovery_topology::TopologyStore>,
    Arc<dyn GroupAlertRuleStore>,
    Arc<dyn discovery_assistant::AssistantStore>,
);

const ALERT_HYDRATION_PAGE_SIZE: i64 = 500;

async fn hydrate_alert_state(
    alert_store: &Arc<dyn AlertStore>,
    alerts: &AlertStateTracker,
) -> anyhow::Result<usize> {
    let mut offset = 0;
    let mut restored = 0;
    loop {
        let page = alert_store
            .list(&AlertListQuery {
                state: Some(AlertState::Active),
                sort_by: AlertSortBy::FirstSeen,
                sort_dir: SortDir::Asc,
                limit: ALERT_HYDRATION_PAGE_SIZE,
                offset,
                ..AlertListQuery::default()
            })
            .await
            .context("loading active alerts for runtime-state hydration")?;
        let page_len = page.items.len() as i64;
        for alert in page.items {
            alerts.restore_active(alert);
            restored += 1;
        }
        offset += page_len;
        if page_len == 0 || offset >= page.total {
            break;
        }
    }
    let mut runtime_offset = 0;
    loop {
        let page = alert_store
            .runtime_page(500, runtime_offset)
            .await
            .context("loading alert runtime snapshots")?;
        let count = page.len();
        for runtime in page {
            alerts.restore_snapshot(runtime.device_id, runtime.snapshot);
        }
        if count < 500 {
            break;
        }
        runtime_offset += count as u64;
    }
    alerts.replace_shared_rules(alert_store.shared_rules().await?);
    Ok(restored)
}

/// Builds every store — job queue, device inventory, device metrics, profiles, discovery
/// (subnet scan) configs, durable logs, settings, alerts, maintenance windows — via
/// [`discovery_db::ConnectionRegistry`], which resolves `config.storage`'s per-domain
/// routing (direct user request 2026-08-18: "по аналогии с aggregate discovery должен
/// поддерживать множества различных БД... сделай настраиваемым разделение хранение
/// данных на различных БД") down to the distinct physical connections actually needed —
/// two domains routed to the same named config share one connection, an unreferenced
/// config is never connected to at all. Replaces the old single-`storage.kind` switch
/// (`memory`/`file`/`database`, one backend for everything) entirely.
///
/// **No dedup config store here anymore (2026-08-16)** — the custom dedup-key mechanism
/// (`discovery-dsl::dedup`, `DedupConfigStore`) is pulled out entirely for now, direct
/// user request, see `discovery_devices::DeviceStore::resolve`'s docs. Will come back,
/// redesigned, as separate work.
async fn build_stores(config: &Config) -> anyhow::Result<Stores> {
    let registry = ConnectionRegistry::build(&config.storage)
        .await
        .context("connecting to configured databases")?;
    info!("storage: connected via ConnectionRegistry (per-domain routing, see config.toml's [storage] section)");

    // `None` unless `DISCOVERY_SECRET_KEY` is actually set — a deployment with no SNMPv3
    // credentials configured never needs it. Only logged at startup (not propagated as a
    // hard failure here): the two stores below fail loudly on their own, but only if/when
    // something actually tries to persist a `SnmpAuth::UsmV3` value — see
    // `discovery_core::secret::SecretKey`'s docs.
    //
    // `KeyNotSet` is the common, silent case above. Anything else means the var *is* set
    // but malformed (e.g. hex instead of base64 — see docs/Changelog 2026-09-12) — that
    // deserves a loud startup warning, not the same silence as "not configured at all",
    // since it'll otherwise surface much later as a confusing failure on first credential save.
    let secret_key = match discovery_core::secret::SecretKey::from_env() {
        Ok(key) => {
            info!("DISCOVERY_SECRET_KEY configured — SNMPv3 credentials can be stored");
            Some(Arc::new(key))
        }
        Err(discovery_core::secret::SecretError::KeyNotSet) => None,
        Err(err) => {
            warn!("DISCOVERY_SECRET_KEY is set but invalid ({err}) — SNMPv3/SSH credentials and other encrypted secrets will be rejected until this is fixed");
            None
        }
    };

    // Scale-audit finding, 2026-08-21: every worker pool's `claim()` (and every other
    // store sharing the same connection, in the common case where every domain routes to
    // one default database) draws from one pool of `pool_max_connections` — a pool smaller
    // than the sum of `concurrency.*` doesn't error, it just silently caps real throughput
    // below whatever `concurrency.*` promises (workers block waiting for a free
    // connection, indistinguishable from "queues are just slow" in the logs otherwise).
    // This only checks the `jobs` domain's own connection, since that's the one every
    // queue's `claim()`/`complete`/`fail` hits every tick — not a full audit of every
    // store sharing it, just the actionable, cheap-to-compute warning.
    if let Some(name) = registry.resolved_database_name(Domain::Jobs) {
        let concurrency_sum = config.concurrency.sum();
        if let Some(db_config) = config.storage.databases.iter().find(|d| d.name == name) {
            let pool_size = db_config.pool_max_connections.unwrap_or(
                if db_config.kind == discovery_bootstrap::DbKind::Sqlite {
                    discovery_db::default_sqlite_pool_max_connections()
                } else {
                    64
                },
            );
            if (pool_size as usize) < concurrency_sum {
                warn!(
                    database = name,
                    pool_max_connections = pool_size,
                    concurrency_sum,
                    "storage.databases[\"{name}\"].pool_max_connections ({pool_size}) is smaller than the sum of concurrency.* ({concurrency_sum}) — worker pools will silently block waiting for a free connection instead of hitting the throughput concurrency.* implies; raise pool_max_connections to at least the concurrency sum"
                );
            }
        }
    }

    // `device_metrics`/`alert_store` are built first — `SeaOrmDeviceStore` holds
    // references to both so `DeviceStore::delete`/`delete_unreachable_since` can cascade
    // into them explicitly (a cross-database `FOREIGN KEY` isn't physically possible once
    // "Устройства"/"Метрики устройств"/"Тревоги" can each route to a different physical
    // database — see `discovery_devices::DeviceStore`'s docs).
    //
    // `device_metrics` can also resolve to a non-sea-orm backend (2026-08-18, third pass:
    // "переходи на реализацию подключения к cassandra") — see
    // `discovery_bootstrap::DbKind::Cassandra`'s docs for why this specific domain.
    // Cassandra's schema, like ClickHouse's below, isn't part of the shared
    // `discovery-migration` crate, so it's ensured here, right after construction.
    let device_metrics: Arc<dyn DeviceMetricsStore> =
        match registry.for_domain(Domain::DeviceMetrics) {
            DomainConnection::SeaOrm(conn) => {
                Arc::new(discovery_devices::SeaOrmDeviceMetricsStore::new(conn))
            }
            DomainConnection::Cassandra(session, keyspace) => {
                discovery_devices::CassandraDeviceMetricsStore::ensure_schema(&session, &keyspace)
                    .await
                    .context("ensuring Cassandra schema for the device_metrics domain")?;
                Arc::new(discovery_devices::CassandraDeviceMetricsStore::new(session))
            }
            DomainConnection::ClickHouse(_) => unreachable!(
                "Config::validate only allows device_metrics to resolve to SeaOrm or Cassandra"
            ),
        };
    // `alerts` can also resolve to a non-sea-orm backend (2026-08-18, fourth pass:
    // "Сделай для alerts cassandra") — see `discovery_bootstrap::DbKind::Cassandra`'s
    // docs for why this domain, alongside `device_metrics`, is the second one to allow
    // Cassandra. Same "ensure schema right after construction" pattern.
    let alert_store: Arc<dyn AlertStore> = match registry.for_domain(Domain::Alerts) {
        DomainConnection::SeaOrm(conn) => Arc::new(discovery_alerts::SeaOrmAlertStore::new(conn)),
        DomainConnection::Cassandra(session, keyspace) => {
            discovery_alerts::CassandraAlertStore::ensure_schema(&session, &keyspace)
                .await
                .context("ensuring Cassandra schema for the alerts domain")?;
            Arc::new(discovery_alerts::CassandraAlertStore::new(session))
        }
        DomainConnection::ClickHouse(_) => {
            unreachable!("Config::validate only allows alerts to resolve to SeaOrm or Cassandra")
        }
    };
    let mut device_store = discovery_devices::SeaOrmDeviceStore::new(
        registry.for_domain_sea_orm(Domain::Devices),
        device_metrics.clone(),
        alert_store.clone(),
    );
    if let Some(key) = &secret_key {
        device_store = device_store.with_secret_key(key.clone());
    }

    // The `logs` domain can also resolve to a non-sea-orm backend (ClickHouse) — see
    // `discovery_db::DomainConnection`'s docs. Same "ensure schema right after
    // construction" pattern as `device_metrics` above.
    let log_store: Arc<dyn LogStore> = match registry.for_domain(Domain::Logs) {
        DomainConnection::SeaOrm(conn) => Arc::new(discovery_logging::SeaOrmLogStore::new(conn)),
        DomainConnection::ClickHouse(client) => {
            discovery_logging::ClickHouseLogStore::ensure_schema(&client)
                .await
                .context("ensuring ClickHouse schema for the logs domain")?;
            Arc::new(discovery_logging::ClickHouseLogStore::new(client))
        }
        DomainConnection::Cassandra(_, _) => {
            unreachable!("Config::validate only allows logs to resolve to SeaOrm or ClickHouse")
        }
    };

    let mut discovery_configs_store = discovery_config_store::SeaOrmDiscoveryConfigStore::new(
        registry.for_domain_sea_orm(Domain::DiscoveryConfigs),
    );
    if let Some(key) = &secret_key {
        discovery_configs_store = discovery_configs_store.with_secret_key(key.clone());
    }

    // 9th domain, added 2026-09-07 for Maintenance windows — see
    // `discovery_core::Domain::MaintenanceWindows`'s docs. A plain sea-orm-only domain,
    // same as `profiles`/`discovery_configs` — never resolves to ClickHouse/Cassandra
    // (`Config::validate` rejects that combination before this ever runs).
    let maintenance_windows: Arc<dyn MaintenanceWindowStore> =
        Arc::new(discovery_config_store::SeaOrmMaintenanceWindowStore::new(
            registry.for_domain_sea_orm(Domain::MaintenanceWindows),
        ));

    // 10th domain, added 2026-09-10 for the notification matrix — see
    // `discovery_core::Domain::Notifications`'s docs. Plain sea-orm-only, same as
    // `maintenance_windows` above.
    let notification_rules: Arc<dyn NotificationRuleStore> =
        Arc::new(discovery_config_store::SeaOrmNotificationRuleStore::new(
            registry.for_domain_sea_orm(Domain::Notifications),
        ));
    // Notification channels aren't a routed domain of their own (see
    // `discovery_core::Domain::Notifications`'s docs) — they live alongside `users`/
    // `sessions`/`journal_entries` on whichever connection `Settings` resolves to.
    let mut notification_channels_store =
        discovery_config_store::SeaOrmNotificationChannelStore::new(
            registry.for_domain_sea_orm(Domain::Settings),
        );
    if let Some(key) = &secret_key {
        notification_channels_store = notification_channels_store.with_secret_key(key.clone());
    }
    let notification_channels: Arc<dyn NotificationChannelStore> =
        Arc::new(notification_channels_store);

    let mut settings_store = discovery_config_store::SeaOrmSettingsStore::new(
        registry.for_domain_sea_orm(Domain::Settings),
    );
    if let Some(key) = &secret_key {
        settings_store = settings_store.with_secret_key(key.clone());
    }

    // 11th domain, added 2026-09-16 for the rule-based topology mechanism — see
    // `discovery_core::Domain::Topology`'s docs. Plain sea-orm-only, same as
    // `maintenance_windows`/`notification_rules` above. Two stores share this one domain
    // (rule config vs. derived per-device data) — same "one domain, two stores" shape
    // `Notifications` already has for `notification_rules`/`notification_channels`,
    // except here *both* halves are gated by the same domain (channels deliberately
    // aren't, see that domain's docs — topology data has no per-user-self-service analog).
    let topology_rules: Arc<dyn TopologyRuleStore> =
        Arc::new(discovery_config_store::SeaOrmTopologyRuleStore::new(
            registry.for_domain_sea_orm(Domain::Topology),
        ));
    let topology: Arc<dyn discovery_topology::TopologyStore> = Arc::new(
        discovery_topology::SeaOrmTopologyStore::new(registry.for_domain_sea_orm(Domain::Topology)),
    );
    // Cross-domain cascade on device deletion (`TopologyStore::delete_for_device`) — see
    // `SeaOrmDeviceStore::with_topology`'s docs. Applied here, after `topology` exists,
    // rather than where `device_store` was originally built above.
    let devices: Arc<dyn DeviceStore> = Arc::new(device_store.with_topology(topology.clone()));

    // 12th domain, added 2026-09-16 for group-alert suppression rules — see
    // `discovery_core::Domain::GroupAlerts`'s docs. Config-only: the correlation result
    // (`Alert::suppressed_by_alert_id`) lives on the `alerts` table under `Domain::Alerts`,
    // not a second store here.
    let group_alert_rules: Arc<dyn GroupAlertRuleStore> =
        Arc::new(discovery_config_store::SeaOrmGroupAlertRuleStore::new(
            registry.for_domain_sea_orm(Domain::GroupAlerts),
        ));

    // AI-assistant conversation/message history (2026-09-18) — not a routed domain either,
    // same reasoning as `users`/`sessions`/`journal_entries` above: self-service data with
    // no `discovery_core::Domain` gate of its own (see `discovery_assistant::AssistantStore`'s
    // docs), so it lives wherever `Settings` resolves to rather than adding a 13th
    // `DomainRouting` field for it.
    let assistant: Arc<dyn discovery_assistant::AssistantStore> =
        Arc::new(discovery_assistant::SeaOrmAssistantStore::new(
            registry.for_domain_sea_orm(Domain::Settings),
        ));

    Ok((
        Arc::new(discovery_queue::SeaOrmJobQueueStore::new(
            registry.for_domain_sea_orm(Domain::Jobs),
        )),
        devices,
        device_metrics,
        Arc::new(discovery_config_store::SeaOrmProfileStore::new(
            registry.for_domain_sea_orm(Domain::Profiles),
        )),
        Arc::new(discovery_configs_store),
        log_store,
        Arc::new(settings_store) as Arc<dyn SettingsStore>,
        alert_store,
        // `users`/`sessions`/`user_permissions` aren't one of the 8 routed domains (auth
        // isn't a *business* domain the way Alerts/Devices/etc. are — see
        // `discovery_auth`'s crate docs) — they live wherever `Settings` resolves to, the
        // closest existing "administrative" connection, rather than adding a 9th
        // `DomainRouting` field for three tables nobody asked to route independently.
        Arc::new(discovery_auth::SeaOrmAuthStore::new(
            registry.for_domain_sea_orm(Domain::Settings),
        )),
        // `journal_entries` (the "Журнал" audit trail) isn't one of the 8 routed domains
        // either, same reasoning as `users`/`sessions` above — an audit log about every
        // domain doesn't belong to any single one of them, so it lives alongside auth on
        // the `Settings` connection rather than adding a 9th `DomainRouting` field.
        Arc::new(discovery_journal::SeaOrmJournalStore::new(
            registry.for_domain_sea_orm(Domain::Settings),
        )),
        maintenance_windows,
        notification_rules,
        notification_channels,
        topology_rules,
        topology,
        group_alert_rules,
        assistant,
    ))
}

/// Synchronous entrypoint. Unlike `#[tokio::main] async fn main() -> anyhow::Result<()>`
/// (whose default error path bypasses our logging entirely — it prints the error's
/// `Debug` straight to stderr via `std::process::Termination`), this catches whatever
/// `run()` returns and routes it through `fatal!` first, so a startup failure is visible
/// in the file/dashboard sinks too, not just the console. `discovery_logging::fatal!` is
/// how "fatal" (a level this project has that plain `tracing` doesn't — see its docs)
/// actually gets produced: an ERROR-level event tagged so it's relabeled "FATAL" and
/// terminates the process, exactly like FATAL/CRITICAL in most logging frameworks.
fn main() -> std::process::ExitCode {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("FATAL: could not start the async runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            // Also eprintln: if `run()` failed before `logging_setup::init()` reached its
            // first line (only realistically possible if that call itself panics, since
            // it's the very first statement), `fatal!` would otherwise go nowhere — no
            // subscriber means tracing events are silently dropped.
            discovery_logging::fatal!(error = %e, "fatal error during startup, exiting");
            eprintln!("FATAL: {e:?}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Runs the whole pipeline (discovery -> recurring SNMP identification -> dedup ->
/// profile match/apply -> recurring metric poll -> alert eval) and serves the dashboard.
///
/// There is no more "demo mode" as a separate code path — `storage.kind = "memory"` in
/// `config.toml` (or its absence, since that's the default) gives the same zero-setup
/// experience the old demo binary did, through the exact same code every other storage
/// kind runs. The three hardcoded virtual devices and the always-on `FakeSnmpClient` are
/// gone from here entirely — they're still used by tests/`e2e.rs` (`discovery_agent::demo`),
/// just no longer wired into the running process. SNMP identification/polling talks to
/// real devices via [`RealSnmpClient`] unconditionally; a fresh `memory`/`file`/`database`
/// instance with no discovery configs configured simply does nothing until you add one
/// (`scans/*.toml` seeded in, or a row written directly / via the dashboard).
async fn run() -> anyhow::Result<()> {
    let config = Config::load().context("loading config.toml")?;

    // `_file_guard` must stay alive for the whole process — dropping it early stops the
    // background thread that flushes buffered writes to the log file.
    let (log_buffer, log_persist_rx, _file_guard) =
        discovery_agent::logging_setup::init(&config.logging);

    // Direct user request 2026-08-29: "возможность через config.toml выключить rest и/или
    // webui... Если выключены оба, то мы не сможем взаимодействовать с системой - выкидывай
    // warn об этом в логи". Preceded by an audit (see `discovery_web::router_with_flags`'s
    // docs) confirming the webui has no capability of its own beyond being a REST client —
    // so this really is "no way to interact with the system at all" once both are off, not
    // just "no UI left". A soft warning, not a hard startup failure: an operator might
    // legitimately want this (e.g. staging both off ahead of fronting the process with
    // something else entirely) and the process otherwise starts and runs its pipeline fine
    // with no HTTP surface at all.
    if !config.server.enable_rest && !config.server.enable_webui {
        warn!(
            "server.enable_rest and server.enable_webui are both false — the HTTP server will start but respond to nothing (no REST API, no dashboard); there is no way to interact with this discovery-agent process until at least one is re-enabled in config.toml and the process is restarted"
        );
    }

    let (
        store,
        devices,
        device_metrics,
        profile_store,
        discovery_config_store,
        log_store,
        settings_store,
        alert_store,
        auth_store,
        journal_store,
        maintenance_windows,
        notification_rules,
        notification_channels,
        topology_rules,
        topology,
        group_alert_rules,
        assistant_store,
    ) = build_stores(&config).await.context("initializing stores")?;

    // Now that we know which backend logs persist to, start draining the channel
    // `logging_setup::init` already wired every tracing event into — anything logged
    // before this point (including a `build_stores` failure) gets the same bounded,
    // best-effort treatment as the rest of the process lifetime.
    discovery_logging::spawn_log_persister(log_persist_rx, log_store.clone());

    // First-run seed: `config.toml`'s `[poll_intervals]` only ever matters if the settings
    // store has nothing yet — see `discovery_core::PollIntervalsConfig`'s docs. After this
    // point `config.toml`'s section is inert; the database is the live source of truth,
    // read fresh by every consumer below (not captured once here).
    if settings_store
        .get_poll_intervals()
        .await
        .context("reading poll_intervals settings")?
        .is_none()
    {
        settings_store
            .set_poll_intervals(&config.poll_intervals)
            .await
            .context("seeding poll_intervals settings from config.toml")?;
        info!("seeded poll_intervals settings from config.toml (first run — nothing in the settings store yet)");
    }

    // First-run bootstrap admin (2026-08-21) — an empty `users` table means nobody could
    // ever log in to create the first account through the API itself (chicken-and-egg,
    // `/api/users` is admin-only). Same "seed something sane on a genuinely empty store,
    // loudly, so the operator notices" discipline as `poll_intervals` above.
    //
    // First-run provisioning is deliberately explicit.  There is no public default
    // password and the value is never logged; the process fails before starting its HTTP
    // listener when an empty store has not been provisioned.
    if auth_store
        .user_count()
        .await
        .context("checking whether any local user exists yet")?
        == 0
    {
        let password = bootstrap_admin::bootstrap_admin_password()
            .context("provisioning the first-run administrator")?;
        auth_store
            .create_user("admin", &password, true, true, None)
            .await
            .context("creating the first-run bootstrap admin user")?;
        warn!(username = "admin", "created the provisioned first-run administrator; it must change its password before normal operation");
    }

    let profiles = profile_store.load_all().await.context("loading profiles")?;
    info!(count = profiles.len(), "loaded profiles");
    let matcher = Arc::new(ProfileMatcher::new(profiles));
    let alert_engine = Arc::new(AlertEvaluator::new());

    let registry = Arc::new(WorkerRegistry::new());
    let alerts = Arc::new(AlertStateTracker::new());
    let restored_alerts = hydrate_alert_state(&alert_store, &alerts).await?;
    info!(
        count = restored_alerts,
        "hydrated active alerts into runtime state"
    );
    let active_chains: Arc<ActiveChains<uuid::Uuid>> = Arc::new(ActiveChains::new());
    let identity_chains: Arc<ActiveChains<String>> = Arc::new(ActiveChains::new());
    // Gates "start a ReachabilityPoll chain for this device" to once per process — see
    // DedupHandler's docs. Separate from `active_chains` (MetricPoll's, keyed the same way
    // but started from a different place, on a different condition).
    let reachability_chains: Arc<ActiveChains<uuid::Uuid>> = Arc::new(ActiveChains::new());
    // Per-(device, metric) last-poll timestamps for MetricPollHandler's per-metric poll
    // cadence — in-process only, empty on every fresh start (same reasoning as
    // ActiveChains: every metric just looks "due" on the first tick after a restart).
    let metric_last_polled: Arc<dashmap::DashMap<(uuid::Uuid, String), tokio::time::Instant>> =
        Arc::new(dashmap::DashMap::new());
    // The `Schedule::Calendar` counterpart — see `MetricPollHandler`'s docs. Same
    // in-process/never-persisted reasoning as `metric_last_polled`.
    let metric_last_polled_date: Arc<dashmap::DashMap<(uuid::Uuid, String), chrono::NaiveDate>> =
        Arc::new(dashmap::DashMap::new());
    // `ServiceCheckPollHandler`'s own per-device (not per-(device,metric)) pair — see that
    // handler's docs for why its schedule is section-wide, one entry per device.
    let service_check_last_polled: Arc<dashmap::DashMap<uuid::Uuid, tokio::time::Instant>> =
        Arc::new(dashmap::DashMap::new());
    let service_check_last_polled_date: Arc<dashmap::DashMap<uuid::Uuid, chrono::NaiveDate>> =
        Arc::new(dashmap::DashMap::new());
    let snmp: Arc<dyn SnmpClient> = Arc::new(RealSnmpClient::new());
    // SSH CLI-pull metrics (2026-09-07) — see `discovery_dsl::MetricSpec::SshCommand`'s
    // docs. `RealCliClient::new()` never fails (no persistent socket/session to set up at
    // construction time — see its docs on the reconnect-per-`exec()` lifecycle), unlike
    // `IcmpPinger::new()` below.
    let cli: Arc<dyn CliClient> = Arc::new(RealCliClient::new());
    // Fails only if the platform can't create an unprivileged ICMP socket at all — a
    // startup-time failure, same treatment as every other fatal-if-missing dependency here
    // (routed through `run()`'s single `?`-propagation path to `main`'s `fatal!` catch).
    let pinger: Arc<dyn Pinger> = Arc::new(
        IcmpPinger::new()
            .context("creating the ICMP pinger (unprivileged SOCK_DGRAM/IPPROTO_ICMP socket)")?,
    );
    // L4/L7 service checks (2026-09-07) — fails only if the TLS backend can't initialize
    // (see `RealServiceChecker::new`'s docs), same fatal-at-startup treatment as the ICMP
    // pinger above.
    let service_checker: Arc<dyn ServiceChecker> = Arc::new(
        RealServiceChecker::new().context("creating the HTTP(S) client for service checks")?,
    );
    // Notification channels + matrix (2026-09-10) — fails only if the HTTP client can't
    // initialize (webhook/Telegram delivery share it), same fatal-at-startup treatment as
    // the ICMP pinger/service-check HTTP client above. Email (SMTP) needs no client built
    // up front — a fresh connection per send, see `RealNotifier`'s docs.
    let notifier: Arc<dyn Notifier> = Arc::new(
        RealNotifier::new()
            .context("creating the HTTP client for webhook/Telegram notification delivery")?,
    );

    // Crash-recovery loop: requeues any job stuck `in_progress` longer than
    // `reclaim.stale_after_secs`, checked every `reclaim.check_interval_secs` —
    // `config.toml`-only, read once at spawn (see `ReclaimConfig`'s docs).
    spawn_reclaim_loop(
        store.clone(),
        chrono::Duration::seconds(config.reclaim.stale_after_secs as i64),
        Duration::from_secs(config.reclaim.check_interval_secs),
    );

    let concurrency = &config.concurrency;

    // Hot-reload: picks up profile changes (file edit, SQLite/Postgres row edit) without
    // a restart, see its docs.
    tokio::spawn(discovery_agent::profile_reload::run_profile_reload_loop(
        profile_store.clone(),
        matcher.clone(),
        devices.clone(),
        store.clone(),
        settings_store.clone(),
    ));

    // Configure subnets for discovery (scans/*.toml or the discovery_configs table) and
    // this is what actually feeds them into the pipeline — checks every enabled config's
    // schedule and enqueues its subnets' host addresses when it fires. Empty/no configs =
    // this loop just idles; nothing is auto-seeded anymore.
    tokio::spawn(
        discovery_agent::discovery_scan::run_discovery_schedule_loop(
            discovery_config_store.clone(),
            store.clone(),
            settings_store.clone(),
        ),
    );
    tokio::spawn(discovery_agent::config_backup_schedule::run_config_backup_schedule_loop(
        devices.clone(), store.clone(), settings_store.clone(),
    ));

    // Metric change history retention sweep — direct user request 2026-08-16, see its
    // docs. Idles harmlessly if no profile sets `history_retention_secs` on any metric.
    tokio::spawn(
        discovery_agent::metric_history_cleanup::run_metric_history_cleanup_loop(
            profile_store.clone(),
            device_metrics.clone(),
            settings_store.clone(),
        ),
    );

    // SNMP Trap ingestion (2026-08-30) — push-based, complementing the poll-based pipeline
    // everything else here uses. Both loops idle harmlessly when `config.snmp_trap.enabled
    // = false` (the default): `run_trap_listener` returns immediately, and the ttl-sweep
    // finds nothing to evict since nothing was ever ingested. `TrapIngestState` is shared
    // between the two so the sweep's evictions and the listener's writes go through the
    // exact same row-upsert/AlertEval-trigger code path.
    let trap_ingest_state = Arc::new(discovery_agent::trap_ingest::TrapIngestState::new(
        devices.clone(),
        device_metrics.clone(),
        matcher.clone(),
        alert_engine.clone(),
        store.clone(),
        config.snmp_trap.rate_limit_per_source_per_sec,
    ));
    tokio::spawn(discovery_agent::trap_listener::run_trap_listener(
        config.snmp_trap.clone(),
        settings_store.clone(),
        trap_ingest_state.clone(),
    ));
    tokio::spawn(discovery_agent::trap_ttl_sweep::run_trap_ttl_sweep_loop(
        trap_ingest_state.clone(),
        settings_store.clone(),
    ));

    // Syslog ingestion (2026-09-06) — push-based sibling of SNMP Trap ingestion, direct
    // user request. Same "idles harmlessly when disabled" wiring as the trap loops above.
    let syslog_ingest_state = Arc::new(discovery_agent::syslog_ingest::SyslogIngestState::new(
        devices.clone(),
        device_metrics.clone(),
        matcher.clone(),
        alert_engine.clone(),
        store.clone(),
        config.syslog.rate_limit_per_source_per_sec,
    ));
    tokio::spawn(discovery_agent::syslog_listener::run_syslog_listener(
        config.syslog.clone(),
        syslog_ingest_state.clone(),
    ));
    tokio::spawn(
        discovery_agent::syslog_ttl_sweep::run_syslog_ttl_sweep_loop(
            syslog_ingest_state.clone(),
            settings_store.clone(),
        ),
    );

    // Alert history retention sweep — direct user request 2026-08-17: "добавь
    // конфигурацию на время хранения тревог". Idles harmlessly (0 rows deleted) if
    // `AlertRetentionConfig.retention_secs` is never set (default `None` = keep forever).
    tokio::spawn(
        discovery_agent::alert_history_cleanup::run_alert_history_cleanup_loop(
            alert_store.clone(),
            settings_store.clone(),
        ),
    );
    tokio::spawn(discovery_agent::log_cleanup::run_log_cleanup_loop(
        log_store.clone(),
        settings_store.clone(),
    ));
    tokio::spawn(discovery_agent::journal_cleanup::run_journal_cleanup_loop(
        journal_store.clone(),
        settings_store.clone(),
    ));
    tokio::spawn(discovery_agent::session_cleanup::run_session_cleanup_loop(
        auth_store.clone(),
    ));

    // Dead-device auto-cleanup — direct user request 2026-08-18: "настраиваемый через
    // конфиг период времени после которого устройство с ping=false удаляется... По
    // умолчанию 0 - если 0 никогда не удалять". Idles harmlessly (0 rows deleted, no query
    // even run) unless `DeadDeviceRetentionConfig.unreachable_for_secs` is explicitly set.
    tokio::spawn(
        discovery_agent::dead_device_cleanup::run_dead_device_cleanup_loop(
            devices.clone(),
            settings_store.clone(),
            identity_chains.clone(),
            active_chains.clone(),
            reachability_chains.clone(),
            alerts.clone(),
        ),
    );

    tokio::spawn(discovery_agent::alert_schedule::run_alert_schedule_loop(
        alerts.clone(),
        store.clone(),
    ));

    // Group-alert suppression (2026-09-16) — item 3 of `docs/Roadmap.md`'s "Топология →
    // групповые тревоги → RADIUS" chain. Global periodic sweep, same shape as
    // `alert_history_cleanup`'s loop (cadence read fresh from `settings` every iteration) —
    // see `discovery_agent::group_alert`'s docs for why this can't be a per-device
    // reactive chain the way `TopologyRecomputeHandler` is (correlation is inherently
    // cross-device, comparing one device's alert against a topological neighbor's).
    //
    // The same `Arc<GroupAlertCorrelator>` also feeds `AlertEvalHandler`'s reactive
    // fast-path (`notification_held_for_suppression`, 2026-09-20), so the periodic sweep
    // and the activate-moment suppression consensus ride one shared snapshot + evaluator —
    // they cannot disagree about a classification.
    let group_alert_correlator = Arc::new(
        discovery_agent::group_alert::GroupAlertCorrelator::with_refresh(
            discovery_agent::group_alert::CorrelationRefreshSources {
                topology_rules: topology_rules.clone(),
                topology: topology.clone(),
                group_alert_rules: group_alert_rules.clone(),
            },
        ),
    );
    tokio::spawn(discovery_agent::group_alert::run_group_alert_loop(
        alert_store.clone(),
        group_alert_correlator.clone(),
        settings_store.clone(),
        notification_rules.clone(),
        notification_channels.clone(),
        auth_store.clone(),
        store.clone(),
    ));

    // Login brute-force protection (2026-09-12) — see `discovery_web::LoginRateLimiter`'s
    // docs. The sweep loop evicts stale (username, ip) buckets so a remote attacker rotating
    // usernames can't grow this map unboundedly (found in the 2026-09-11 audit).
    let login_rate_limiter = Arc::new(discovery_web::LoginRateLimiter::new(
        config.login_rate_limit.clone(),
    ));
    tokio::spawn(
        discovery_agent::login_rate_limit_sweep::run_login_rate_limiter_sweep_loop(
            login_rate_limiter.clone(),
            config.login_rate_limit.sweep_interval_secs,
            config.login_rate_limit.stale_after_secs,
        ),
    );

    tokio::spawn(run_worker_pool(
        store.clone(),
        registry.clone(),
        WorkerPoolConfig {
            queue: QueueKind::Discovery,
            concurrency: concurrency.discovery,
            poll_interval: Duration::from_millis(config.worker_poll_interval.discovery_ms),
        },
        Arc::new(DiscoveryHandler {
            store: store.clone(),
            identity_chains: identity_chains.clone(),
            discovery_configs: discovery_config_store.clone(),
            pinger: pinger.clone(),
            settings: settings_store.clone(),
        }),
    ));
    let snmp_poll_handler = Arc::new(SnmpPollHandler {
        store: store.clone(),
        snmp: snmp.clone(),
        devices: devices.clone(),
        discovery_configs: discovery_config_store.clone(),
        settings: settings_store.clone(),
    });
    tokio::spawn(run_worker_pool(
        store.clone(),
        registry.clone(),
        WorkerPoolConfig {
            queue: QueueKind::SnmpPoll,
            concurrency: concurrency.snmp_poll,
            poll_interval: Duration::from_millis(config.worker_poll_interval.snmp_poll_ms),
        },
        snmp_poll_handler.clone(),
    ));
    tokio::spawn(run_worker_pool(
        store.clone(),
        registry.clone(),
        WorkerPoolConfig {
            queue: QueueKind::Dedup,
            concurrency: concurrency.dedup,
            poll_interval: Duration::from_millis(config.worker_poll_interval.dedup_ms),
        },
        Arc::new(DedupHandler {
            store: store.clone(),
            devices: devices.clone(),
            device_metrics: device_metrics.clone(),
            matcher: matcher.clone(),
            reachability_chains: reachability_chains.clone(),
        }),
    ));
    tokio::spawn(run_worker_pool(
        store.clone(),
        registry.clone(),
        WorkerPoolConfig {
            queue: QueueKind::ProfileApply,
            concurrency: concurrency.profile_apply,
            poll_interval: Duration::from_millis(config.worker_poll_interval.profile_apply_ms),
        },
        Arc::new(ProfileApplyHandler {
            store: store.clone(),
            devices: devices.clone(),
            active_chains: active_chains.clone(),
            last_polled: metric_last_polled.clone(),
            last_polled_date: metric_last_polled_date.clone(),
            service_check_last_polled: service_check_last_polled.clone(),
            service_check_last_polled_date: service_check_last_polled_date.clone(),
        }),
    ));
    let metric_poll_handler = Arc::new(MetricPollHandler {
        store: store.clone(),
        snmp: snmp.clone(),
        cli: cli.clone(),
        devices: devices.clone(),
        device_metrics: device_metrics.clone(),
        matcher: matcher.clone(),
        settings: settings_store.clone(),
        last_polled: metric_last_polled.clone(),
        last_polled_date: metric_last_polled_date.clone(),
        discovery_configs: discovery_config_store.clone(),
        pruned_generations: Arc::new(dashmap::DashMap::new()),
        topology_rules: topology_rules.clone(),
    });
    tokio::spawn(run_worker_pool(
        store.clone(),
        registry.clone(),
        WorkerPoolConfig {
            queue: QueueKind::MetricPoll,
            concurrency: concurrency.metric_poll,
            poll_interval: Duration::from_millis(config.worker_poll_interval.metric_poll_ms),
        },
        metric_poll_handler.clone(),
    ));
    tokio::spawn(run_worker_pool(
        store.clone(),
        registry.clone(),
        WorkerPoolConfig {
            queue: QueueKind::OperatorAction,
            concurrency: 1,
            poll_interval: Duration::from_millis(250),
        },
        Arc::new(OperatorActionHandler {
            queue: store.clone(),
            devices: devices.clone(),
            matcher: matcher.clone(),
            settings: settings_store.clone(),
            pinger: pinger.clone(),
            checker: service_checker.clone(),
            cli: cli.clone(),
            snmp_poll: snmp_poll_handler.clone(),
            metric_poll: metric_poll_handler.clone(),
            journal: journal_store.clone(),
            secret_key: discovery_core::secret::SecretKey::from_env()
                .ok()
                .map(Arc::new),
        }),
    ));
    tokio::spawn(run_worker_pool(
        store.clone(),
        registry.clone(),
        WorkerPoolConfig {
            queue: QueueKind::ReachabilityPoll,
            concurrency: concurrency.reachability_poll,
            poll_interval: Duration::from_millis(config.worker_poll_interval.reachability_poll_ms),
        },
        Arc::new(ReachabilityPollHandler {
            store: store.clone(),
            devices: devices.clone(),
            snmp: snmp.clone(),
            pinger: pinger.clone(),
            discovery_configs: discovery_config_store.clone(),
            settings: settings_store.clone(),
        }),
    ));
    // L4/L7 service checks (2026-09-07) — profile-scoped, started/restarted by
    // ProfileApplyHandler above, see `ServiceCheckPollHandler`'s docs.
    tokio::spawn(run_worker_pool(
        store.clone(),
        registry.clone(),
        WorkerPoolConfig {
            queue: QueueKind::ServiceCheckPoll,
            concurrency: concurrency.service_check_poll,
            poll_interval: Duration::from_millis(config.worker_poll_interval.service_check_poll_ms),
        },
        Arc::new(ServiceCheckPollHandler {
            store: store.clone(),
            devices: devices.clone(),
            device_metrics: device_metrics.clone(),
            matcher: matcher.clone(),
            checker: service_checker.clone(),
            settings: settings_store.clone(),
            last_polled: service_check_last_polled.clone(),
            last_polled_date: service_check_last_polled_date.clone(),
        }),
    ));
    // AlertEval — re-enabled 2026-08-17 (direct user request, full alert-history feature).
    // Was paused since 2026-08-15 ("удали пока логику связанную с Инциденты, мы сделаем
    // её позже"); nothing had been deleted, just unplugged, so this is the one-line
    // uncomment the comment above used to promise — now also persisting every transition
    // via `alert_store`, see `AlertEvalHandler`'s docs.
    tokio::spawn(run_worker_pool(
        store.clone(),
        registry.clone(),
        WorkerPoolConfig {
            queue: QueueKind::AlertEval,
            concurrency: concurrency.alert_eval,
            poll_interval: Duration::from_millis(config.worker_poll_interval.alert_eval_ms),
        },
        Arc::new(AlertEvalHandler {
            evaluation_locks: Default::default(),
            alert_engine: alert_engine.clone(),
            alerts: alerts.clone(),
            alert_store: alert_store.clone(),
            devices: devices.clone(),
            device_metrics: device_metrics.clone(),
            matcher: matcher.clone(),
            maintenance_windows: maintenance_windows.clone(),
            notification_rules: notification_rules.clone(),
            notification_channels: notification_channels.clone(),
            auth: auth_store.clone(),
            queue: store.clone(),
            still_active_last_persisted: Arc::new(dashmap::DashMap::new()),
            correlator: group_alert_correlator.clone(),
        }),
    ));
    // Notification dispatch (2026-09-10) — one job per (alert transition, channel),
    // enqueued by `AlertEvalHandler::dispatch_notifications` above, see
    // `QueueKind::NotificationDispatch`'s docs for why it's scoped that way.
    tokio::spawn(run_worker_pool(
        store.clone(),
        registry.clone(),
        WorkerPoolConfig {
            queue: QueueKind::NotificationDispatch,
            concurrency: concurrency.notification_dispatch,
            poll_interval: Duration::from_millis(
                config.worker_poll_interval.notification_dispatch_ms,
            ),
        },
        Arc::new(NotificationDispatchHandler {
            alert_store: alert_store.clone(),
            notification_channels: notification_channels.clone(),
            settings: settings_store.clone(),
            notifier: notifier.clone(),
        }),
    ));
    // Topology recompute (2026-09-16) — reactive, enqueued by `MetricPollHandler` right
    // after a device's watched metric is freshly polled, see `QueueKind::TopologyRecompute`'s
    // docs. Own worker pool/concurrency setting, same "each pipeline stage gets its own
    // pool" contract as every other queue here.
    tokio::spawn(run_worker_pool(
        store.clone(),
        registry.clone(),
        WorkerPoolConfig {
            queue: QueueKind::TopologyRecompute,
            concurrency: concurrency.topology_recompute,
            poll_interval: Duration::from_millis(config.worker_poll_interval.topology_recompute_ms),
        },
        Arc::new(TopologyRecomputeHandler {
            rules: topology_rules.clone(),
            topology: topology.clone(),
            devices: devices.clone(),
            device_metrics: device_metrics.clone(),
            evaluator: Arc::new(discovery_dsl::topology::TopologyEvaluator::new()),
        }),
    ));

    let dashboard_state = discovery_web::DashboardState {
        store: store.clone(),
        alerts: alerts.clone(),
        alert_store: alert_store.clone(),
        workers: registry.clone(),
        logs: log_buffer.clone(),
        profiles: profile_store.clone(),
        matcher: matcher.clone(),
        discovery_configs: discovery_config_store.clone(),
        devices: devices.clone(),
        device_metrics: device_metrics.clone(),
        settings: settings_store.clone(),
        auth: auth_store.clone(),
        journal: journal_store.clone(),
        maintenance_windows: maintenance_windows.clone(),
        notification_rules: notification_rules.clone(),
        notification_channels: notification_channels.clone(),
        topology_rules: topology_rules.clone(),
        topology: topology.clone(),
        group_alert_rules: group_alert_rules.clone(),
        assistant: assistant_store.clone(),
        identity_chains: identity_chains.clone(),
        active_chains: active_chains.clone(),
        reachability_chains: reachability_chains.clone(),
        login_rate_limiter: login_rate_limiter.clone(),
        action_enqueue_lock: Arc::new(tokio::sync::Mutex::new(())),
    };
    let app = discovery_web::router_with_flags(
        dashboard_state,
        config.server.enable_rest,
        config.server.enable_webui,
    );
    info!(addr = %config.server.addr, enable_rest = config.server.enable_rest, enable_webui = config.server.enable_webui, "dashboard listening");
    let listener = tokio::net::TcpListener::bind(&config.server.addr)
        .await
        .with_context(|| format!("binding dashboard address {}", config.server.addr))?;
    // `with_connect_info` (not plain `into_make_service`) so `login`'s `ConnectInfo<SocketAddr>`
    // extractor can see the real peer address (2026-09-12, login rate-limiting is keyed on it).
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("dashboard server")?;

    Ok(())
}
