use async_trait::async_trait;
use discovery_core::{
    Device, DeviceFacts, MetricHistoryPage, MetricPollOutcome, MetricRecord, MetricValue, Metrics,
    SnmpCredentials, SortDir, SshCredentials,
};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Which column to sort [`DeviceStore::list_devices`] results by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceSortBy {
    /// Numeric, not lexicographic — see `discovery_core::ipv4_to_sort_key`'s docs.
    Ip,
    Profile,
    DiscoveredAt,
}

/// Search + filter + sort + paginate parameters for [`DeviceStore::list_devices`] — added
/// 2026-08-21, scale audit finding, same shape/reasoning as `discovery_queue::JobListQuery`/
/// `discovery_alerts::AlertListQuery`. Pushed down to SQL for the same reason those two
/// were: `GET /api/devices` used to load the *entire* device table (every column, every
/// row) on every dashboard poll (every 1.5s) and filter/sort/paginate a `Vec` in Rust — a
/// design the pre-existing doc comment on that handler explicitly justified as "device
/// counts in this project don't approach the scale `list_jobs` has to worry about", an
/// assumption that stopped holding the moment this project was asked to be ready for
/// 500k-1M devices.
///
/// **Does not cover the `has_error` filter** ("only devices with a metric currently in an
/// error state") — that depends on `device_metrics`, a separate routing domain that can
/// resolve to a *different physical database* than `devices` (see this trait's own docs on
/// why `Devices`/`DeviceMetrics` are split domains). A single SQL query can't join across
/// two arbitrary physical connections, so `has_error` remains an application-level filter,
/// applied by `discovery-web` over `DeviceStore::all()`'s full result — a known, deliberate
/// scope limit, not an oversight (see that handler's docs).
#[derive(Debug, Clone)]
pub struct DeviceListQuery {
    /// Free-text, case-insensitive, matched against `ip` and `profile`.
    pub search: Option<String>,
    /// Exact profile-name filter.
    pub profile: Option<String>,
    pub sort_by: Option<DeviceSortBy>,
    pub sort_dir: Option<SortDir>,
    pub limit: i64,
    pub offset: i64,
}

/// Hand-written, not derived — `#[derive(Default)]` would give `limit: 0`, which passed
/// straight to SQL's `LIMIT 0` returns *zero* rows, not "no limit" (found by a failing
/// test the first time this shipped, not guessed). Same 50-row default as
/// `discovery_queue::JobListQuery`/`discovery_alerts::AlertListQuery`.
impl Default for DeviceListQuery {
    fn default() -> Self {
        Self {
            search: None,
            profile: None,
            sort_by: None,
            sort_dir: None,
            limit: 50,
            offset: 0,
        }
    }
}

/// One page of devices plus the total count matching the filter (ignoring
/// `limit`/`offset`) — same "page N of M, K total" contract as `JobListPage`/`AlertListPage`.
#[derive(Debug, Clone)]
pub struct DeviceListPage {
    pub items: Vec<Device>,
    pub total: i64,
}

/// What [`DeviceStore::apply_profile_if_changed`] decided. Both variants carry the
/// device's current `generation` — even `Unchanged`, because the caller needs it to
/// (re)start a metric-poll chain when *nothing else* proves one is already running (the
/// restart case: a fresh process has no memory of any chain a previous process had going,
/// even though the on-record profile is unchanged — see `discovery-agent`'s
/// `ProfileApplyHandler` / `ActiveChains`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileDecision {
    /// The device already has this exact profile — nothing to reconfigure.
    Unchanged { generation: u64 },
    /// The profile is new or different from what was on record. `generation` is what the
    /// freshly (re)started `MetricPoll` chain must be tagged with.
    Changed { generation: u64 },
}

/// Device inventory: identity (currently just IP — see [`Self::resolve`]'s docs for the
/// dedup fingerprint mechanism that used to also live here, pulled out 2026-08-16), matched
/// profile, poll generation, SNMP credentials/reachability, master on/off switch, and
/// per-device metric overrides (`device_metric_settings`).
///
/// **Split from a single `DeviceStore` into this + [`crate::DeviceMetricsStore`] (2026-08-18
/// multi-DB rewrite, direct user request).** Domain "Устройства" — device identity and
/// `device_metric_settings` always live together (both routed by
/// `discovery_bootstrap::DomainRouting::devices`); actual metric readings
/// (`device_metrics`/`device_metric_history`) are a *separate* routing domain
/// ("Метрики устройств") that can resolve to a different physical database, so they moved
/// to their own trait with their own store. See [`crate::DeviceMetricsStore`]'s docs and
/// [`crate::all_with_metrics`]/[`crate::get`] for how the two are composed back together
/// where the dashboard/pipeline still needs both at once.
///
/// **[`Self::delete`]/[`Self::delete_unreachable_since`] now explicitly cascade into the
/// other two domains that used to be `ON DELETE CASCADE`** (`device_metrics`/
/// `device_metric_history` via [`crate::DeviceMetricsStore::delete_for_device`],
/// `alerts` via `discovery_alerts::AlertStore::delete_for_device`) — a cross-database
/// `FOREIGN KEY` isn't physically possible once those domains can route independently, so
/// [`SeaOrmDeviceStore`] holds references to both of the other stores specifically to make
/// these two calls itself, application-code cascade instead of a DB-enforced one. See
/// `discovery_entities::devices`'s module docs for the same point made from the schema
/// side.
///
/// One implementation — [`SeaOrmDeviceStore`], works against Postgres/MySQL/SQLite (and,
/// for tests/zero-config, `sqlite::memory:`) through the same sea-orm entity/query code
/// path (replacing the old `PostgresDeviceStore`/`SqliteDeviceStore`/`InMemoryDeviceStore`
/// trio — see `discovery_config_store::SeaOrmSettingsStore`'s docs for the full rewrite
/// rationale).
#[async_trait]
pub trait DeviceStore: Send + Sync {
    /// Resolves a device identity purely by IP:
    ///
    /// - This exact IP already maps to a device -> that device, facts refreshed.
    /// - Otherwise -> a brand-new device.
    ///
    /// **Changed 2026-08-16 (direct user request — metric change history):** this used to
    /// also take an `identity_extra: Option<Metrics>` parameter and write it into
    /// `device_metrics` as part of the same transaction. That responsibility moved out
    /// entirely — `resolve()` is now purely about identity/IP resolution. Callers that have
    /// one-shot discovery-time poll outcomes to record (only `DedupHandler`, only on a
    /// device's first-ever identity cycle) call [`crate::DeviceMetricsStore::record_metric_polls`]
    /// themselves, separately, with the `device_id` this method returns — the exact same
    /// single write path [`crate::DeviceMetricsStore::record_metric_polls`]'s other caller
    /// (`MetricPollHandler`) already uses for regular profile-polled metrics. Trade-off,
    /// accepted and documented: this is now two transactions instead of one (device row
    /// insert, then metrics record) rather than one atomic unit, and — since 2026-08-18 —
    /// potentially against two entirely different physical databases. In the vanishingly
    /// rare case of a crash exactly between them, a brand-new device's one-shot discovery
    /// data would be lost forever (no retry for one-shot fields, by design) — an acceptable
    /// cost for having exactly one metrics-writing code path in the whole system, never two.
    ///
    /// Returns `(device_id, is_new)`.
    async fn resolve(&self, facts: DeviceFacts) -> anyhow::Result<(Uuid, bool)>;

    /// Compares `(new_profile, new_profile_version)` against what's on record for `id`.
    /// Comparing the version alongside the name is what catches an edit to an
    /// *existing* profile's content (match expression, metric list, alert thresholds) —
    /// comparing the name alone would treat "profile X, edited" as indistinguishable
    /// from "profile X, unchanged", since the name is the same either way. Returns
    /// `Ok(None)` if the device no longer exists, `Ok(Some(Unchanged{generation}))` if
    /// both match what's on record, or `Ok(Some(Changed{generation}))` if either differs.
    /// Note that `Unchanged` does *not* by itself mean "nothing to do" — see
    /// [`ProfileDecision`]'s docs.
    async fn apply_profile_if_changed(
        &self,
        id: Uuid,
        new_profile: &str,
        new_profile_version: &str,
    ) -> anyhow::Result<Option<ProfileDecision>>;

    async fn current_poll_generation(&self, id: Uuid) -> anyhow::Result<Option<u64>>;

    /// Records SNMP credentials that were just successfully negotiated for this device —
    /// see [`discovery_core::SnmpCredentials`]'s docs. A no-op if `id` doesn't exist.
    async fn set_snmp_credentials(
        &self,
        id: Uuid,
        credentials: SnmpCredentials,
    ) -> anyhow::Result<()>;

    /// Sets (or replaces) this device's SSH credentials — see
    /// [`discovery_core::SshCredentials`]'s docs for why this is the SSH counterpart of
    /// [`Self::set_snmp_credentials`] but, unlike it, is **never** called by any automatic
    /// pipeline code: the only caller is a manual REST/dashboard action (`POST
    /// /api/devices`'s `ssh_auth` field, or a dedicated `PUT` credentials endpoint — see
    /// `discovery-web`'s device handlers). A no-op if `id` doesn't exist, same contract as
    /// [`Self::set_snmp_credentials`].
    async fn set_ssh_credentials(
        &self,
        id: Uuid,
        credentials: SshCredentials,
    ) -> anyhow::Result<()>;

    /// Pins `fingerprint` as this device's trusted SSH host key — see
    /// [`discovery_core::SshCredentials::known_host_key`]'s docs for the
    /// trust-on-first-use contract this exists for, closing a CWE-295 finding
    /// (`discovery_ssh::client::Handler::check_server_key` used to accept every server
    /// key unconditionally). Unlike [`Self::set_ssh_credentials`] (manual-entry-only, a
    /// blind full overwrite), this is called automatically by `MetricPollHandler` right
    /// after `discovery_ssh::CliClient::exec` reports a freshly-learned fingerprint on an
    /// until-now-unpinned device — the same "automatic pipeline write" category as
    /// [`Self::set_snmp_credentials`].
    ///
    /// **Only writes if the column is currently `NULL`** — never overwrites an
    /// already-pinned fingerprint. `CliClient::exec` itself already refuses to connect at
    /// all once a fingerprint is pinned and the server presents a different one, so this
    /// guard is not the security boundary; it exists purely to make two concurrent
    /// first-ever connections for the same device race-safe. A no-op if `id` doesn't
    /// exist or already has a pinned fingerprint, same "silently do nothing rather than
    /// error" contract as [`Self::set_snmp_credentials`].
    async fn pin_ssh_host_key(&self, id: Uuid, fingerprint: String) -> anyhow::Result<()>;

    /// Records the outcome of one reachability check — see
    /// [`discovery_core::Device`]'s `ping_ok`/`snmp_ok` docs. Writes both statuses plus
    /// `now()` into both `*_checked_at` columns in one call: `ReachabilityPollHandler`
    /// always checks ping and SNMP together on the same tick, there's no scenario where one
    /// half updates without the other. A no-op if `id` doesn't exist — same contract as
    /// [`Self::set_snmp_credentials`] (the device may have been deleted between the poll
    /// starting and this write landing).
    ///
    /// **Also maintains `ping_failing_since`, atomically, in the same statement — not
    /// read-then-written from the caller** (`ReachabilityPollHandler` only ever has this
    /// single check's outcome in hand, no memory of the previous one): if the new `ping_ok`
    /// is `false` and the row's *current* `ping_ok` is anything else (`true`, or never
    /// checked), this is the start of a new down-streak — set to `now()`. If the new
    /// `ping_ok` is `false` and the row is *already* `false`, the streak is still running —
    /// leave the existing `ping_failing_since` untouched (it must keep pointing at when the
    /// streak actually began, not slide forward on every tick, or
    /// [`Self::delete_unreachable_since`]'s threshold would never be reached). If the new
    /// `ping_ok` is `true`, the streak is over — clear it back to `None`.
    ///
    /// `ping_loss_pct` (2026-09-14, `docs/Roadmap.md` "До релиза" item 5) — the share of
    /// the `1 + retries` ICMP attempts behind this tick's `ping_ok` that got no reply, see
    /// [`discovery_core::Device::ping_loss_pct`]'s docs. Written unconditionally alongside
    /// `ping_ok`/`ping_checked_at`, same "one call, one tick" contract as everything else
    /// here — there's no scenario where reachability updates without it.
    async fn set_reachability(
        &self,
        id: Uuid,
        ping_ok: bool,
        ping_loss_pct: f64,
        snmp_ok: bool,
    ) -> anyhow::Result<()>;

    /// Auto-cleanup sweep — direct user request 2026-08-18: "настраиваемый через конфиг
    /// период времени после которого устройство с ping=false удаляется". Deletes every
    /// **enabled** device whose `ping_failing_since` is non-`None` and at or before
    /// `cutoff` (i.e. it's been continuously unreachable for at least the caller's
    /// configured `DeadDeviceRetentionConfig::unreachable_for_secs`, computed by the caller
    /// as `now() - unreachable_for_secs`). Each matching device is deleted exactly like
    /// [`Self::delete`] (same cross-domain cascade into metrics/alerts) — this just selects
    /// the set in bulk by a condition instead of by a single id.
    ///
    /// **Skips `enabled = false` devices** — same "freeze, don't force" contract every
    /// other `Device::enabled` gate in this project follows (`MetricPollHandler`/
    /// `ReachabilityPollHandler` both skip *work* while disabled rather than reacting to
    /// the frozen last-known state, see `discovery_core::Device::enabled`'s docs): a device
    /// a human explicitly parked shouldn't quietly vanish out from under them just because
    /// its last observed state, before being parked, happened to be unreachable.
    ///
    /// Returns the `(device_id, ip)` of every deleted row — not just a count (changed
    /// 2026-08-21, scale/correctness audit): the caller needs each deleted device's id and
    /// ip to also clear it out of `discovery_core::ActiveChains` (`active_chains`/
    /// `reachability_chains` keyed by id, `identity_chains` keyed by ip) — see that type's
    /// `remove` docs for why skipping this permanently blocks re-discovering the ip later.
    async fn delete_unreachable_since(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<Vec<(Uuid, String)>>;

    /// Device-level master on/off switch — direct user request 2026-08-16: "мне нужна
    /// возможность выключать устройства (выключить все)". A no-op if `id` doesn't exist,
    /// same contract as [`Self::set_snmp_credentials`]/[`Self::set_reachability`]. See
    /// [`discovery_core::Device::enabled`]'s docs for what turning this off actually does
    /// (skips `MetricPoll`/`ReachabilityPoll` work, doesn't stop the chains themselves).
    async fn set_enabled(&self, id: Uuid, enabled: bool) -> anyhow::Result<()>;

    /// Bulk counterpart of [`Self::set_enabled`] — "выключить все". A single statement in
    /// the DB-backed implementation, not a loop of per-device calls — the whole point is
    /// this stays cheap regardless of device count. Returns the number of devices touched.
    async fn set_enabled_all(&self, enabled: bool) -> anyhow::Result<u64>;

    /// Bulk counterpart scoped to an already selected set of device ids. The update is one
    /// database statement, so a filtered dashboard action cannot fall back to N per-device
    /// writes or accidentally widen its scope between selection and update.
    async fn set_enabled_for_ids(&self, ids: &[Uuid], enabled: bool) -> anyhow::Result<u64>;

    /// All manual per-device metric overrides on record for `id`, name -> forced on/off —
    /// see [`discovery_core::MetricRecord::enabled_override`]'s docs for the full contract
    /// this and the two methods below exist to guarantee. Empty for a device with no
    /// overrides (never an error) or an unknown device id.
    async fn get_metric_overrides(&self, id: Uuid) -> anyhow::Result<BTreeMap<String, bool>>;

    /// Batch form of [`Self::get_metric_overrides`] — one round trip for many devices at
    /// once, keyed by device id. Added alongside [`crate::all_with_metrics`] specifically:
    /// composing "every device with its metrics and overrides" now means two independently-
    /// resolved stores instead of one SQL `JOIN`, and doing that with N+1 per-device calls
    /// would defeat the whole point of `all_with_metrics` existing (see that free
    /// function's docs). A device with no overrides is simply absent from the returned map
    /// (not an empty entry).
    async fn get_metric_overrides_for_many(
        &self,
        ids: &[Uuid],
    ) -> anyhow::Result<BTreeMap<Uuid, BTreeMap<String, bool>>>;

    /// Sets (inserts or replaces) an explicit override for one metric on one device — the
    /// *only* way `device_metric_settings` is ever written by a real user action (a
    /// per-metric toggle in the dashboard). **Never called by any automatic pipeline
    /// handler** (`DedupHandler`/`ProfileApplyHandler`/`MetricPollHandler`) — that
    /// invariant is what makes a manual override survive automatic profile
    /// (re)application, including a device re-matching to a *different* profile that
    /// happens to declare a same-named metric (the scenario the user described directly).
    async fn set_metric_override(&self, id: Uuid, name: &str, enabled: bool) -> anyhow::Result<()>;

    /// Clears one metric's override for one device, reverting it to follow the profile's
    /// own default (`MetricSpec::Detailed::enabled`) again. Not an error if no override
    /// existed for that name.
    async fn clear_metric_override(&self, id: Uuid, name: &str) -> anyhow::Result<()>;

    /// Clears every override in `names` for one device — the "sync with profile" action
    /// (`discovery-web`'s device- and profile-scoped sync endpoints), called with the
    /// current profile's declared metric names. **Deliberately implemented as delete, not
    /// as "write an override copying the profile's current value"** — the latter would
    /// look identical right after syncing but would then *stop* following future profile
    /// edits (an explicit override, even one that happens to match the default, always
    /// wins over the profile going forward). Clearing is what actually means "go back to
    /// following the profile" as new edits to it keep happening.
    async fn clear_metric_overrides(&self, id: Uuid, names: &[String]) -> anyhow::Result<()>;

    /// Batch counterpart of [`Self::clear_metric_overrides`] for many devices at once — one
    /// statement instead of N. Added 2026-08-21, scale audit finding:
    /// `discovery-web::sync_profile_devices_metrics` used to call the single-device version
    /// in a sequential loop over every device matching a profile, which at a large device
    /// count (a popular profile easily matches tens/hundreds of thousands of devices) meant
    /// that many round trips on one HTTP request.
    async fn clear_metric_overrides_for_devices(
        &self,
        ids: &[Uuid],
        names: &[String],
    ) -> anyhow::Result<()>;

    /// Deletes every `device_metric_settings` row for `id` whose name is not in `keep` —
    /// used when a profile edit removes a metric from `[metrics.poll]`, so a stale manual
    /// override doesn't linger forever once the metric it applied to no longer exists
    /// anywhere. Purely additive safety, not a correctness requirement — an override for a
    /// name that never reappears in `keep` is simply never consulted again either way.
    /// Always called together with [`crate::DeviceMetricsStore::prune_metrics`] (the
    /// `device_metrics` cache-row half of what a single `prune_metrics` used to do before
    /// this domain split) — see `discovery-agent::handlers::MetricPollHandler`'s call site.
    async fn prune_metric_overrides(&self, id: Uuid, keep: &[String]) -> anyhow::Result<()>;

    /// Deletes a device and cascades into everything that references it —
    /// `device_metric_settings` (same domain, real `ON DELETE CASCADE`), plus
    /// `device_metrics`/`device_metric_history` (via
    /// [`crate::DeviceMetricsStore::delete_for_device`]) and `alerts` (via
    /// `discovery_alerts::AlertStore::delete_for_device`) — both explicit application-code
    /// calls now, not DB-enforced, since those two domains can route to different physical
    /// databases (see this trait's docs). Not an error if `id` doesn't exist.
    async fn delete(&self, id: Uuid) -> anyhow::Result<()>;

    async fn get_device(&self, id: Uuid) -> anyhow::Result<Option<Device>>;

    async fn id_by_ip(&self, ip: &str) -> anyhow::Result<Option<Uuid>>;

    async fn all(&self) -> anyhow::Result<Vec<Device>>;

    /// Search + filter + sort + paginate at the SQL level — see [`DeviceListQuery`]'s docs
    /// for why this exists alongside [`Self::all`] rather than replacing it ([`Self::all`]
    /// still backs the `has_error`-filtered path and anything else that genuinely needs
    /// every device).
    async fn list_devices(&self, query: &DeviceListQuery) -> anyhow::Result<DeviceListPage>;

    /// Just the ids of every device currently matched to `profile_name` — added 2026-08-21,
    /// scale audit finding: `discovery-web::sync_profile_devices_metrics` used to call
    /// [`Self::all`] (every device, every column) and filter by profile in Rust, to answer
    /// a question the database can filter directly and far more cheaply (a single indexed
    /// column, only the id projected out — not the whole `Device` row for every device in
    /// the fleet).
    async fn device_ids_by_profile(&self, profile_name: &str) -> anyhow::Result<Vec<Uuid>>;

    /// Total device count — a plain `SELECT COUNT(*)` for callers that need "how many
    /// devices exist" without also wanting a page of them back, rather than piggybacking on
    /// `list()`'s pagination total.
    async fn count(&self) -> anyhow::Result<u64>;
}

/// Device metric readings: current state (`device_metrics`, a derived cache) plus full
/// change history (`device_metric_history`, the source of truth). Domain "Метрики
/// устройств" — split out of [`DeviceStore`] in the 2026-08-18 multi-DB rewrite, see that
/// trait's docs for why. `device_id` throughout this trait is a **soft** reference to a
/// [`DeviceStore`]-owned device (see `discovery_entities::device_metrics`'s docs) — never
/// validated against `devices` by this store itself, since the two may not even share a
/// connection.
///
/// **[`Self::record_metric_polls`] is the single write path for device metrics — the only
/// method in this whole system that ever touches `device_metrics`/`device_metric_history`.**
/// For each `(name, outcome)` in `results`, in one transaction:
/// 1. Compare `outcome` against the latest `device_metric_history` row for
///    `(id, name)`. Same state (same value, or the same error text) -> just bump that
///    row's `last_observed_at` — no new row, this is what keeps a metric that never
///    changes (or a device that keeps failing with the identical error) from growing
///    an unbounded history. Different state -> insert a new history row.
/// 2. Unconditionally upsert `device_metrics` (the derived cache) to match: `value`/
///    `polled_at` updated only on `Ok`, `error`/`last_attempt_at` updated regardless.
///
/// A metric name not present in `results` is left completely untouched — a device with
/// several metrics on different cadences (`MetricSpec::Detailed::interval_secs`) must
/// not have an unrelated metric's `last_attempt_at` dragged forward just because a
/// faster sibling was due this tick.
///
/// One implementation — [`SeaOrmDeviceMetricsStore`], same Postgres/MySQL/SQLite-from-one-
/// code-path rewrite as [`DeviceStore`].
#[async_trait]
pub trait DeviceMetricsStore: Send + Sync {
    async fn record_metric_polls(
        &self,
        id: Uuid,
        results: &BTreeMap<String, MetricPollOutcome>,
    ) -> anyhow::Result<()>;

    /// Deletes every `device_metrics` (cache) row for `id` whose name is not in `keep` —
    /// used when a profile edit removes a metric from `[metrics.poll]`, so a stale value
    /// doesn't linger in the *current* view forever. Deliberately does **not** touch
    /// `device_metric_history` — the metric's past history remains as an archival record
    /// (ages out via the normal retention cleanup, or lives forever if no retention is
    /// configured for it) even after it stops being polled. An empty `keep` clears every
    /// current metric for the device (its history is unaffected either way). See
    /// [`DeviceStore::prune_metric_overrides`]'s docs for the other half of what a single
    /// `prune_metrics` used to do before the domain split.
    async fn prune_metrics(&self, id: Uuid, keep: &[String]) -> anyhow::Result<()>;

    /// Deletes `device_metric_history` rows for metric `name` (across every device) whose
    /// `last_observed_at` is older than `cutoff` — **except** rows exempted by
    /// `keep_last_attempt`/`keep_last_success`, direct user request 2026-08-16: "Мне нужно
    /// хранить всегда крайнюю удачную и самую крайнюю, потому что в ней может быть
    /// ошибка." Global by metric *name*, not scoped to a particular profile — same
    /// convention `oid`/`interval_secs` already follow when the same metric name is
    /// declared by more than one profile (see `profile_metrics.history_retention_secs`'s
    /// docs) — but the two exemptions below **are** scoped per **device** within that
    /// name, computed independently for each device that has history for this metric:
    ///
    /// - `keep_last_attempt`: the single most recent row overall (by `last_observed_at`,
    ///   success or error) for each device is never deleted, regardless of age.
    /// - `keep_last_success`: the single most recent row with a non-`None` `value` (a
    ///   successful poll) for each device is never deleted, regardless of age.
    ///
    /// If both are `true` and a device's latest row happens to be a success, both
    /// exemptions point at the *same* row — one protected row survives, not two (only
    /// diverges into two when the latest state is an error preceded by an older,
    /// otherwise-expired success) — see `discovery_dsl::MetricSpec`'s docs for the direct
    /// user framing this implements.
    ///
    /// Returns the number of rows actually deleted, purely for logging by the caller
    /// (`discovery-agent::metric_history_cleanup`).
    async fn prune_metric_history_older_than(
        &self,
        name: &str,
        cutoff: chrono::DateTime<chrono::Utc>,
        keep_last_attempt: bool,
        keep_last_success: bool,
    ) -> anyhow::Result<u64>;

    /// Paginated read of `device_metric_history` for one device+metric, newest run first
    /// (`ORDER BY last_observed_at DESC`) — the dashboard's metric-history view. No sort
    /// parameter — recency is the only order that makes sense for a change history.
    /// `limit`/`offset` behave like every other paginated read in this project: the
    /// returned [`MetricHistoryPage::total`] reflects every run on record for this
    /// device+metric, not just this page's size (after `since`/`until` narrow it, if set).
    ///
    /// `since`/`until` filter on `last_observed_at` (the same column the result is ordered
    /// by) — a run is included if its most recent observation falls in `[since, until]`,
    /// same one-sided-optional-bounds contract as `AlertListQuery::since`/`until`.
    async fn metric_history(
        &self,
        id: Uuid,
        name: &str,
        limit: i64,
        offset: i64,
        since: Option<chrono::DateTime<chrono::Utc>>,
        until: Option<chrono::DateTime<chrono::Utc>>,
    ) -> anyhow::Result<MetricHistoryPage>;

    /// The device's current metrics as a flat name -> value bag, with no timestamps/errors
    /// — exactly the shape the DSL layer (`ProfileMatcher`/`DedupResolver`/
    /// `AlertEvaluator`) consumes. Metrics whose cache row has no successful value yet
    /// (`value IS NULL` — only errors so far) are simply absent from the returned bag, same
    /// as a metric that's never been polled at all (both look like `()` to a Rhai
    /// expression referencing them — no special-casing needed there). Returns an *empty*
    /// bag, not an error, for an unknown device id — several callers (`DedupHandler` in
    /// particular, on a device's very first-ever contact) depend on this defaulting
    /// behavior rather than having to special-case "device doesn't exist yet".
    async fn get_metrics(&self, id: Uuid) -> anyhow::Result<Metrics>;

    /// Full [`MetricRecord`]s (value/error/timestamps, **no** `enabled_override` —
    /// that field lives entirely in [`DeviceStore`]'s domain, filled in by
    /// [`crate::all_with_metrics`]) for one device. An empty `Vec`, not an error, for an
    /// unknown device id — same defaulting contract as [`Self::get_metrics`].
    async fn get_metric_records(&self, id: Uuid) -> anyhow::Result<Vec<MetricRecord>>;

    /// Batch form of [`Self::get_metric_records`] — see
    /// [`DeviceStore::get_metric_overrides_for_many`]'s docs for why this exists (the same
    /// N+1-avoidance reasoning, the other half of the same composition). A device with no
    /// metrics at all is simply absent from the returned map (not an empty entry).
    async fn get_metric_records_for_many(
        &self,
        ids: &[Uuid],
    ) -> anyhow::Result<BTreeMap<Uuid, Vec<MetricRecord>>>;

    /// Deletes every `device_metrics`/`device_metric_history` row for one device — the
    /// cascade target [`DeviceStore::delete`]/[`DeviceStore::delete_unreachable_since`]
    /// call explicitly (see those methods' docs for why this can no longer be a DB-enforced
    /// `ON DELETE CASCADE`). A no-op, not an error, if the device has no metrics on record.
    async fn delete_for_device(&self, id: Uuid) -> anyhow::Result<()>;

    /// Every current `device_metrics` row (across every device) whose metric name starts
    /// with `prefix` — SNMP Trap ingestion's ttl-sweep (2026-08-30) is the only caller,
    /// with `prefix = "trap_"`: it needs every trap-derived table/singleton across the
    /// whole fleet to check for per-row staleness (see `discovery-agent::trap_ttl_sweep`),
    /// and a targeted `WHERE name LIKE 'trap_%'` query is the difference between that and
    /// loading every device's every metric just to throw almost all of it away. Rows with
    /// a `NULL` value (never successfully written) are skipped, same as `get_metrics`.
    async fn list_metrics_by_name_prefix(
        &self,
        prefix: &str,
    ) -> anyhow::Result<Vec<(Uuid, String, MetricValue)>>;
}

/// Composes [`DeviceStore::all`] with batched metric/override lookups into the same
/// `(Device, Vec<MetricRecord>)` shape a single-store `all_with_metrics` used to produce
/// via one SQL `JOIN` — now necessarily two-to-three independent round trips (one per
/// physically distinct store `devices`/`device_metrics` resolve to) instead of one query,
/// since "Устройства" and "Метрики устройств" can route to different databases (see
/// [`DeviceStore`]'s docs). What the dashboard's `GET /api/devices` renders.
///
/// Reads only the `device_metrics` cache, never `device_metric_history` — that keeps this
/// (called on every dashboard poll) on the fast path; full history is a separate,
/// per-metric read (`DeviceMetricsStore::metric_history`).
pub async fn all_with_metrics(
    devices: &dyn DeviceStore,
    device_metrics: &dyn DeviceMetricsStore,
) -> anyhow::Result<Vec<(Device, Vec<MetricRecord>)>> {
    with_metrics(devices.all().await?, devices, device_metrics).await
}

/// The composition half of [`all_with_metrics`], split out 2026-08-21 (scale audit) so
/// `discovery-web`'s paginated `GET /api/devices` can attach metrics/overrides to just
/// *one page* of devices (from [`DeviceStore::list_devices`]) instead of always the whole
/// fleet — the two batched lookups below are the expensive part `all_with_metrics` used to
/// force onto the full device list even when a caller only ever wanted a page of it.
pub async fn with_metrics(
    devices_page: Vec<Device>,
    devices: &dyn DeviceStore,
    device_metrics: &dyn DeviceMetricsStore,
) -> anyhow::Result<Vec<(Device, Vec<MetricRecord>)>> {
    let ids: Vec<Uuid> = devices_page.iter().map(|d| d.id).collect();
    let mut records_by_device = device_metrics.get_metric_records_for_many(&ids).await?;
    let mut overrides_by_device = devices.get_metric_overrides_for_many(&ids).await?;

    Ok(devices_page
        .into_iter()
        .map(|d| {
            let mut records = records_by_device.remove(&d.id).unwrap_or_default();
            if let Some(mut overrides) = overrides_by_device.remove(&d.id) {
                for record in &mut records {
                    record.enabled_override = overrides.remove(&record.name);
                }
            }
            (d, records)
        })
        .collect())
}

/// Convenience pairing of [`DeviceStore::get_device`] + [`DeviceMetricsStore::get_metrics`]
/// for callers that need both together (`AlertEvalHandler`, `MetricPollHandler`) — pure
/// composition of the two stores, same reasoning as [`all_with_metrics`]. `None` if the
/// device doesn't exist; a device that exists but has no metrics yet gets an empty
/// [`Metrics`] bag, not an error.
pub async fn get(
    devices: &dyn DeviceStore,
    device_metrics: &dyn DeviceMetricsStore,
    id: Uuid,
) -> anyhow::Result<Option<(Device, Metrics)>> {
    match devices.get_device(id).await? {
        Some(device) => {
            let metrics = device_metrics.get_metrics(id).await?;
            Ok(Some((device, metrics)))
        }
        None => Ok(None),
    }
}
