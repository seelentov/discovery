use crate::derive_metric::{derived_metric_name, DeriveKind};
use discovery_core::Schedule;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};

/// One profile — a row in `profiles`/`profile_metrics` via
/// `discovery-config-store::ProfileStore` (Postgres/SQLite), or an in-process entry
/// (`storage.kind = "memory"`). Also what `POST /api/profiles` deserializes its JSON body
/// into. This type itself doesn't know or care which backend it came from — it's the
/// shared shape they all produce. Layout is deliberately flat — no nested profile
/// inheritance in the MVP.
///
/// **No more TOML.** Until 2026-08-16 this was also loadable from `profiles/*.toml` via
/// `ProfileFile::parse`/`load_profiles_from_dir`, used both directly (file-backed storage)
/// and as a one-time seed source into the DB backends. Removed entirely — direct user
/// request ("убери в целом логику которая подгружает сиды из файлов"): every store is
/// directly writable now (dashboard/API, or a direct `INSERT`), so file-loading serves no
/// purpose. `Deserialize` is still real and exercised — via JSON, through the web API and
/// this crate's own tests — just never via TOML anymore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileFile {
    pub profile: ProfileMeta,
    #[serde(rename = "match")]
    pub match_expr: MatchSection,
    #[serde(default)]
    pub metrics: MetricsSection,
    /// SNMP Trap ingestion — added 2026-08-30. Declares which incoming trap OIDs this
    /// profile's devices are expected to send and how to turn their varbinds into rows of
    /// a synthetic table-shaped metric (`metrics.trap_<binding name>`), consumed by
    /// ordinary `AlertRule`s in `alerts` below exactly like any polled table metric — see
    /// [`TrapsSection`]'s docs for the full design.
    #[serde(default)]
    pub traps: TrapsSection,
    /// Syslog ingestion — added 2026-09-06. Sibling of `traps`: same terminal shape
    /// (`metrics.syslog_<binding name>`), see [`SyslogSection`]'s docs for the full design.
    #[serde(default)]
    pub syslog: SyslogSection,
    /// L4/L7 service checks (TCP/HTTP(S)/SSH reachability) — added 2026-09-07, third
    /// protocol collection sibling of `metrics.poll` (SNMP) and the device-level
    /// ping/SNMP reachability pair (`Device::ping_ok`/`snmp_ok`,
    /// `discovery_agent::handlers::ReachabilityPollHandler`). Unlike that fixed pair,
    /// which check(s) to run varies per profile and there can be more than one, so this is
    /// shaped like `metrics.poll` (a declared list with its own poll cadence), not a fixed
    /// column — see [`ServiceChecksSection`]'s docs for the full design.
    #[serde(default)]
    pub service_checks: ServiceChecksSection,
    #[serde(default, rename = "alerts")]
    pub alerts: Vec<AlertRule>,
    /// Content fingerprint — computed by [`compute_version`] from `match_expr`,
    /// `metrics.poll`, and `alerts` (**not** `priority`, see its docs). Not a field you
    /// write by hand — every store's row-to-`ProfileFile` conversion (`load_all`) fills it
    /// in via `compute_version`; a value deserialized straight from JSON (e.g. a web API
    /// request body) simply has it default-empty, which is fine since no store's `upsert`
    /// reads this field back. This exists so `ProfileApply` can tell "the profile named X
    /// got edited" apart from "nothing changed" even though the *name* X is identical
    /// either way — comparing only the name would silently ignore edits to an existing
    /// profile's match expression, metric list, or alert thresholds. See
    /// `discovery_devices::ProfileDecision`.
    #[serde(skip, default)]
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileMeta {
    pub name: String,
    /// Higher priority is tried first. Use this for a catch-all profile at priority 0 and
    /// more specific vendor/model profiles above it.
    ///
    /// Deliberately **excluded** from `version`: priority affects which profile *wins* a
    /// match against other profiles, not what a device already on *this* profile is
    /// configured with. A priority-only edit shouldn't force every device currently on
    /// this profile to reconfigure — see `priority_alone_does_not_affect_version` below.
    #[serde(default)]
    pub priority: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchSection {
    /// A Rhai boolean expression. Two variables in scope: `facts` (currently just `ip`)
    /// and `metrics` (the device's data bag — one-shot discovery-time `subnet.oids`/
    /// `subnet.labels` values and profile-polled values live together here, see
    /// `discovery-core::DeviceFacts`'s docs). Example:
    /// `metrics.sys_descr.contains("Cisco") && metrics.sys_object_id.starts_with("1.3.6.1.4.1.9")`
    pub expression: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetricsSection {
    /// metric name -> what to poll for it and how often.
    #[serde(default)]
    pub poll: BTreeMap<String, MetricSpec>,
}

impl MetricsSection {
    /// Catches one profile-authoring mistake at save time: a metric declaring `derive`
    /// (see [`MetricSpec::Detailed::derive`]'s docs) whose computed synthetic name
    /// (`derived_metric_name`) collides with another metric already declared under that
    /// exact name in the same profile. Without this check the two would silently fight
    /// over the same `device_metrics` row on every poll tick — whichever
    /// `MetricPollHandler` happens to write last that tick wins, with nothing anywhere
    /// indicating this is even happening. Same "catch it at save time, not on live
    /// traffic" posture as `TrapsSection::validate`/`SyslogSection::validate`.
    pub fn validate(&self) -> Result<(), String> {
        for (name, spec) in &self.poll {
            if let Some(kind) = spec.derive() {
                let derived_name = derived_metric_name(name, kind);
                if self.poll.contains_key(&derived_name) {
                    return Err(format!(
                        "metrics.poll.{name}: derive={kind:?} would compute a derived metric named \"{derived_name}\", which collides with another metric already declared under that name"
                    ));
                }
            }
        }
        Ok(())
    }
}

/// A single metric's OID plus (optionally) its own poll [`Schedule`] — direct request
/// from the user: "частота опроса метрик должна настраиваться через профиль" (poll
/// frequency should be configurable per profile, per metric, not one global interval for
/// everything). `#[serde(untagged)]` keeps the plain-string form
/// (`cpu = "1.3.6.1.4.1.9.9.109.1.1.1.1.3.1"`) working unchanged — it just means "use the
/// process-wide default interval" (`poll_intervals.metric_secs` in `config.toml`); the
/// table form (`cpu = { oid = "...", schedule = {...} }`) opts a specific metric into its
/// own cadence.
///
/// **`schedule` (was a plain `interval_secs: Option<u64>` field until 2026-08-16, direct
/// user follow-up: "впиши такую же логику в метрики в профиле — опрашивать либо
/// периодично либо по времени/месяцу/дате, аналогично тому как щас в дискаверинге").** Now
/// a full [`discovery_core::Schedule`] — the same periodic-vs-calendar switch discovery
/// configs use. `Schedule::Periodic { interval_secs }` is the direct successor of the old
/// plain field (same meaning, just wrapped); `Schedule::Calendar { months, days_of_month,
/// time }` is new — a metric can now be polled on a fixed calendar schedule (e.g. once a
/// day at 03:00) instead of a running interval. `None` (the field omitted entirely) still
/// means "use the process-wide default periodic interval", same as before. See
/// `discovery_agent::handlers::MetricPollHandler`'s docs for how each mode's "is it due"
/// check differs.
///
/// `history_retention_secs` (added 2026-08-16, direct user request — metric change
/// history): how long `device_metric_history` rows for this metric name are kept before
/// `discovery-agent`'s cleanup loop prunes them (`DeviceStore::prune_metric_history_older_than`).
/// `None` means keep forever. Global by metric *name*, not scoped to a particular device
/// or even this one profile — same convention `oid`/`schedule` already follow when
/// more than one profile declares a metric of the same name (last one the cleanup loop
/// processes on a given tick wins for that name; not a new inconsistency, see
/// `discovery_devices::DeviceStore::prune_metric_history_older_than`'s docs). A metric's
/// *current* (most recently touched) history row is never at real risk from this **while
/// still being actively polled** — `last_observed_at` on it advances on every poll that
/// repeats the same state, so it only becomes "old" once the device/metric genuinely stops
/// being polled at all (including, since 2026-08-16, a device or metric turned off via
/// `Device::enabled`/`device_metric_settings` — see those docs).
///
/// **`history_keep_last_success`/`history_keep_last_attempt` (added 2026-08-16, direct
/// user request following the on/off-toggle feature): "Сейчас БД может просто
/// переполниться со временем. Мне нужно хранить всегда крайнюю удачную и самую крайнюю,
/// потому что в ней может быть ошибка."** The gap these close: once a device/metric can be
/// turned off, its history's "current" row stops being refreshed and *will* eventually age
/// past `history_retention_secs` and get deleted like any other stale row — silently
/// losing "what was the last known value" and "what was the last attempt's outcome" for
/// something the user explicitly paused rather than abandoned. Two independent exemptions
/// from the retention cutoff, each keyed per **device**, not globally:
///
/// - `history_keep_last_success` — the single most recent history row with a non-`None`
///   `value` (the equivalent of `device_metrics.value`/`polled_at`) is never pruned,
///   regardless of age, as long as this is `true`.
/// - `history_keep_last_attempt` — the single most recent history row overall, success or
///   error (the equivalent of `device_metrics.error`/`last_attempt_at`), is never pruned,
///   regardless of age, as long as this is `true`.
///
/// Both default `true` — this is a no-op for the common case (an actively-polled metric's
/// latest row is never actually stale anyway, as explained above), and closes the
/// data-loss gap by default rather than requiring an opt-in edit to every existing
/// profile. **If the very latest row happens to be a success, both flags exempt the exact
/// same row — one protected row, not two** (the user's own framing: "Если же самая
/// крайняя удачная то будет только одна запись"); they only diverge into two protected
/// rows when the latest state is an error preceded by an older, otherwise-expired success.
/// See [`discovery_devices::DeviceStore::prune_metric_history_older_than`]'s docs for the
/// exact ranking this implements.
///
/// **`reidentify`/`reidentify_debounce_secs` removed 2026-08-16** (direct user request,
/// same change that removed `discovery-dsl::dedup` entirely — see
/// `discovery_devices::DeviceStore::resolve`'s docs): these existed purely to trigger a
/// reactive dedup-key re-check on a metric value change. With custom dedup-key
/// deduplication pulled out (only the plain per-IP fallback remains for now), there was
/// nothing left for them to trigger. Will come back, redesigned, alongside whatever
/// replaces the dedup module.
fn default_metric_enabled() -> bool {
    true
}

fn default_history_keep() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MetricSpec {
    Oid(String),
    Detailed {
        /// A scalar metric's full OID, or — when `columns` is `Some` — a table metric's
        /// **entry** OID (the `not-accessible` MIB node columns hang off, e.g. `ifEntry`
        /// = `1.3.6.1.2.1.2.2.1` for `ifTable`), not a scalar value's own OID.
        oid: String,
        /// Whether this metric is a scalar or a table, and — for a table — which columns
        /// to keep. Three states, distinguished by JSON shape (deliberately *not* a
        /// separate `kind`/`type` tag — this mirrors how `schedule: None` already means
        /// "use the default" elsewhere in this struct):
        ///
        /// - absent / `null` (`None`) — **scalar**. `oid` is `get()`-ed directly, exactly
        ///   as before this field existed. This is every existing profile's behavior,
        ///   unchanged.
        /// - present, non-empty (`Some({"ifIndex": "1", "ifDescr": "2", ...})`) —
        ///   **table, curated columns**. Each entry maps a friendly column name to that
        ///   column's subid *relative to `oid`* (i.e. the full column OID is
        ///   `"{oid}.{subid}"`, straight out of the MIB — `ifDescr` is `ifEntry.2`, so
        ///   `"2"`). Polled via one `walk()` per declared column (not one walk on the
        ///   whole entry) — see `discovery-snmp`'s `build_metric_table` — so only the
        ///   columns actually asked for cross the wire, not every column a wide table
        ///   happens to have.
        /// - present, empty (`Some({})`) — **table, collect everything**. A single
        ///   `walk()` on the whole entry OID; columns are auto-named by their raw subid
        ///   string (`"1"`, `"2"`, `"8"`, ...) since there's no MIB to look up friendly
        ///   names from. Useful for a first exploratory look at an unfamiliar table
        ///   before narrowing to a curated list — not the recommended steady-state
        ///   config for a wide table, since it pulls every column across the wire. See
        ///   `discovery-snmp`'s `build_metric_table_auto`.
        #[serde(default)]
        columns: Option<BTreeMap<String, String>>,
        #[serde(default)]
        schedule: Option<Schedule>,
        #[serde(default)]
        history_retention_secs: Option<u64>,
        /// See this type's docs. `true` = the latest *successful* history row for this
        /// metric is never pruned by retention, regardless of age.
        #[serde(default = "default_history_keep")]
        history_keep_last_success: bool,
        /// See this type's docs. `true` = the latest history row overall (success or
        /// error) is never pruned by retention, regardless of age.
        #[serde(default = "default_history_keep")]
        history_keep_last_attempt: bool,
        /// Profile-level default for this metric's on/off state — direct user request
        /// 2026-08-16, alongside the per-device override (`device_metric_settings`,
        /// `discovery_devices::DeviceStore`'s docs): a profile can declare a metric
        /// disabled by default for every device on it, not just the shorthand "declared =
        /// always polled". Only the *default*: a device-level override always wins over
        /// this, and automatic profile (re)application never overrides an existing
        /// device-level override — only this profile default. `true` (the plain-string
        /// `MetricSpec::Oid` form's implicit meaning) unless explicitly set `false`.
        #[serde(default = "default_metric_enabled")]
        enabled: bool,
        /// Opts this metric into a derived rate/delta value — added 2026-09-07, Roadmap
        /// item "Производные метрики от счётчиков (rate/delta поверх сырых
        /// SNMP-counter'ов)". `None` (the default) means no derived value, this metric's
        /// behavior is unchanged from before this field existed. `Some(kind)` means
        /// `discovery-agent::handlers::MetricPollHandler` computes a derived value
        /// (`discovery_dsl::compute_derived`) right after each fresh successful poll of
        /// this metric and stores it as its own synthetic metric —
        /// `discovery_dsl::derived_metric_name(name, kind)`, e.g. `ifInOctets` with
        /// `derive: Rate` produces `ifInOctets_rate` — through the exact same
        /// `DeviceMetricsStore::record_metric_polls` write path as any polled metric, so
        /// it's referenceable from `match.expression`/`AlertRule.expression`/`message`
        /// with zero new DSL surface (`metrics.ifInOctets_rate > 1000000`).
        ///
        /// Only meaningful for a **scalar** metric whose polled value is
        /// [`discovery_core::MetricValue::Int`] (every SNMP counter decodes to that — see
        /// `discovery_snmp::snmp_value_to_metric`'s docs). Setting it on a table metric
        /// or one that resolves to a non-integer value isn't rejected — it simply never
        /// produces a derived value, same graceful-degradation posture as
        /// `compute_derived`'s other "not computable this tick" cases (first-ever sample,
        /// non-positive elapsed time, a decrease treated as a counter wrap/device reset —
        /// see that function's docs for the full list and the reasoning for each).
        #[serde(default)]
        derive: Option<DeriveKind>,
    },
    /// SSH CLI-pull (added 2026-09-07, direct user decision — "Config backup/compliance →
    /// метрики через SSH CLI pull", see `docs/Roadmap.md`'s "Сделано" entry for the full
    /// scoping discussion). A metric whose value is the captured stdout of running
    /// `command` over SSH on the device, instead of an SNMP `get`/`walk` — everything
    /// downstream (`device_metrics`/`device_metric_history` versioning, `AlertRule`
    /// expressions) is completely unaware this metric didn't come from SNMP. See
    /// `discovery_agent::handlers::MetricPollHandler`'s docs for how it routes a due metric
    /// to `discovery_ssh::CliClient::exec` instead of `discovery_snmp::SnmpClient` based on
    /// this variant, and `discovery_core::Device::ssh_credentials`'s docs for where the
    /// SSH login this executes under comes from (always manual-entry, never negotiated).
    ///
    /// Disambiguated from `Detailed` by JSON shape, same untagged-enum convention this
    /// whole type already uses (table-metric `columns`, scalar-vs-table): `command` is a
    /// field `Detailed` never has, and `Detailed`'s own `oid` is mandatory, so a JSON
    /// object carrying `command` but no `oid` can never be mistaken for a `Detailed` entry
    /// (and vice versa) — no separate `kind`/`type` tag needed, matching this type's
    /// existing "shape *is* the discriminant" style.
    ///
    /// **Always a scalar `MetricValue::Str`.** There is no SSH-command equivalent of
    /// `Detailed::columns` in this design — a profile author who wants structured,
    /// multi-row data out of a CLI command's output is expected to parse it inside a
    /// downstream Rhai `AlertRule` expression (e.g. `metrics.running_config.contains(...)`),
    /// not something this variant itself attempts. This is deliberate, not a v1 gap to
    /// close later — see the Roadmap decision this shipped from: the whole point is reusing
    /// the *existing* metric/alert pipeline unchanged, not growing a second table-shaped
    /// metric encoding just for this source.
    SshCommand {
        /// The command run verbatim over the SSH session's exec channel — no shell
        /// expansion/escaping performed by this codebase beyond what the SSH server itself
        /// does with a bare exec request (RFC 4254 §6.5: most servers run it through the
        /// user's login shell). A profile author who needs a fixed, injection-safe command
        /// controls this string directly (it comes from profile authoring, not
        /// runtime/user-supplied input), same trust boundary `match.expression`/
        /// `AlertRule.expression` already have for Rhai code.
        command: String,
        #[serde(default)]
        schedule: Option<Schedule>,
        #[serde(default)]
        history_retention_secs: Option<u64>,
        /// See [`Detailed::history_keep_last_success`]'s docs — identical meaning, applied
        /// to this metric's history runs.
        #[serde(default = "default_history_keep")]
        history_keep_last_success: bool,
        /// See [`Detailed::history_keep_last_attempt`]'s docs — identical meaning.
        #[serde(default = "default_history_keep")]
        history_keep_last_attempt: bool,
        /// See [`Detailed::enabled`]'s docs — identical meaning.
        #[serde(default = "default_metric_enabled")]
        enabled: bool,
    },
}

impl MetricSpec {
    /// The OID to poll over SNMP — meaningless for [`MetricSpec::SshCommand`], which has
    /// none; returns `""` for that variant rather than `Option<&str>`, since every
    /// pre-existing call site (`compute_version`, `discovery-config-store`'s
    /// `profile_metrics.oid` column, `MetricPollHandler`'s SNMP batch) predates
    /// `SshCommand` and expects a plain `&str`. Safe in practice: every caller routes an
    /// `SshCommand` metric through [`Self::is_ssh_command`]/[`Self::command`] before ever
    /// needing an OID, the same way a table metric is routed through [`Self::is_table`]
    /// before its `oid` is read as an *entry* OID rather than a scalar one.
    pub fn oid(&self) -> &str {
        match self {
            MetricSpec::Oid(oid) => oid,
            MetricSpec::Detailed { oid, .. } => oid,
            MetricSpec::SshCommand { .. } => "",
        }
    }

    /// The command to run over SSH — `Some` only for [`MetricSpec::SshCommand`], `None`
    /// for every SNMP-sourced variant (the mirror image of [`Self::oid`]).
    pub fn command(&self) -> Option<&str> {
        match self {
            MetricSpec::Oid(_) | MetricSpec::Detailed { .. } => None,
            MetricSpec::SshCommand { command, .. } => Some(command),
        }
    }

    /// `true` iff this metric's value comes from `discovery_ssh::CliClient::exec` instead
    /// of SNMP — what `MetricPollHandler` checks first to route a due metric to the right
    /// client, before ever consulting [`Self::is_table`] (which only makes sense for the
    /// two SNMP-sourced variants).
    pub fn is_ssh_command(&self) -> bool {
        matches!(self, MetricSpec::SshCommand { .. })
    }

    /// `columns` as documented on the `Detailed::columns` field — `None` for the
    /// plain-string form (always a scalar, no way to declare a table via the shorthand),
    /// a `Detailed` entry that never set it, or [`MetricSpec::SshCommand`] (always a
    /// scalar — see its docs for why there's no SSH-command table shape).
    pub fn columns(&self) -> Option<&BTreeMap<String, String>> {
        match self {
            MetricSpec::Oid(_) | MetricSpec::SshCommand { .. } => None,
            MetricSpec::Detailed { columns, .. } => columns.as_ref(),
        }
    }

    /// `true` iff this metric is table-shaped (`columns` is `Some`, curated or
    /// "collect everything" — see `Detailed::columns`'s docs for the distinction between
    /// the two). `MetricPollHandler` uses this to route a due metric to a `walk()`-based
    /// poll instead of the scalar `get()`/`get_multi()` path.
    pub fn is_table(&self) -> bool {
        self.columns().is_some()
    }

    /// The profile's own default for this metric — `true` for the plain-string form
    /// (`MetricSpec::Oid`, no way to disable via the shorthand) or a `Detailed` entry that
    /// never set `enabled`. A device-level override (if any) always takes precedence over
    /// this — see [`crate`] module docs / `discovery_devices::DeviceStore`'s for the full
    /// resolution order callers must follow.
    pub fn enabled(&self) -> bool {
        match self {
            MetricSpec::Oid(_) => true,
            MetricSpec::Detailed { enabled, .. } => *enabled,
            MetricSpec::SshCommand { enabled, .. } => *enabled,
        }
    }

    /// `None` means "use the caller's default periodic interval" — either because no
    /// schedule was set at all, or because the set schedule is [`Schedule::Calendar`]
    /// (which has no fixed interval — see [`Self::schedule`] for that case instead).
    pub fn interval_secs(&self) -> Option<u64> {
        match self {
            MetricSpec::Oid(_) => None,
            MetricSpec::Detailed { schedule, .. } => {
                schedule.as_ref().and_then(Schedule::interval_secs)
            }
            MetricSpec::SshCommand { schedule, .. } => {
                schedule.as_ref().and_then(Schedule::interval_secs)
            }
        }
    }

    /// The full schedule, when one is set — `None` for the plain-string form or a
    /// `Detailed`/`SshCommand` entry that never set one (both mean "use the process-wide
    /// default periodic interval", see [`Self::interval_secs`]). `Some(Schedule::Calendar{..})`
    /// is what [`discovery_agent::handlers::MetricPollHandler`] checks to decide whether
    /// this metric is due right now instead of consulting a running interval.
    pub fn schedule(&self) -> Option<&Schedule> {
        match self {
            MetricSpec::Oid(_) => None,
            MetricSpec::Detailed { schedule, .. } => schedule.as_ref(),
            MetricSpec::SshCommand { schedule, .. } => schedule.as_ref(),
        }
    }

    /// `None` means keep this metric's history forever — see this type's docs.
    pub fn history_retention_secs(&self) -> Option<u64> {
        match self {
            MetricSpec::Oid(_) => None,
            MetricSpec::Detailed {
                history_retention_secs,
                ..
            } => *history_retention_secs,
            MetricSpec::SshCommand {
                history_retention_secs,
                ..
            } => *history_retention_secs,
        }
    }

    /// `true` (including for the plain-string form, which has no way to turn this off) =
    /// exempt the latest successful history row from retention pruning — see this type's
    /// docs.
    pub fn history_keep_last_success(&self) -> bool {
        match self {
            MetricSpec::Oid(_) => true,
            MetricSpec::Detailed {
                history_keep_last_success,
                ..
            } => *history_keep_last_success,
            MetricSpec::SshCommand {
                history_keep_last_success,
                ..
            } => *history_keep_last_success,
        }
    }

    /// `true` (including for the plain-string form) = exempt the latest history row
    /// overall (success or error) from retention pruning — see this type's docs.
    pub fn history_keep_last_attempt(&self) -> bool {
        match self {
            MetricSpec::Oid(_) => true,
            MetricSpec::Detailed {
                history_keep_last_attempt,
                ..
            } => *history_keep_last_attempt,
            MetricSpec::SshCommand {
                history_keep_last_attempt,
                ..
            } => *history_keep_last_attempt,
        }
    }

    /// `None` for the plain-string form (no way to opt in via the shorthand) or a
    /// `Detailed` entry that never set it — see this field's docs for the full contract.
    pub fn derive(&self) -> Option<DeriveKind> {
        match self {
            MetricSpec::Oid(_) | MetricSpec::SshCommand { .. } => None,
            MetricSpec::Detailed { derive, .. } => *derive,
        }
    }
}

/// SNMP Trap ingestion (2026-08-30) — `traps.bindings.<name>` in `ProfileFile`'s JSON.
/// Sibling of [`MetricsSection`]: `metrics` says what to *poll*, `traps` says what
/// *pushed* events to expect and how to turn them into the same shape a polled table
/// metric produces (`MetricValue::Table`), so downstream — `AlertRule`, `AlertEvaluator`,
/// `AlertStateTracker`'s `RowMissing` auto-clear — never needs to know or care whether a
/// row came from a `walk()` or a trap packet. `discovery-agent`'s trap listener is the
/// only thing that reads this section; it never writes to `alerts` directly, only to
/// `metrics.trap_<binding name>` via the same `DeviceMetricsStore::record_metric_polls`
/// path `MetricPollHandler` already uses.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrapsSection {
    #[serde(default)]
    pub bindings: BTreeMap<String, TrapSpec>,
}

impl TrapsSection {
    /// Catches profile-authoring mistakes at save time instead of letting them fail
    /// silently on live traffic: (1) `key_expression` set but `varbinds` empty — nothing
    /// for the expression to read a per-entity identity from, since 2026-08-30's design
    /// pass deliberately has no `constants` field to fall back on (synthesized data was
    /// rejected in favor of requiring the device's own varbinds); (2) `variants` empty —
    /// a binding with no way to ever match an incoming `trap_oid` can never do anything;
    /// (3) a `varbinds` **key** that itself looks like a dotted OID — `varbinds` maps
    /// field name -> OID, not the reverse (see that field's docs); a dotted-numeric key
    /// is a strong signal the map was authored backwards — exactly the mistake found live
    /// 2026-09-19 (silent zero-field extraction, not an error, on a profile written the
    /// wrong way around — see that field's docs for the full story). This check catches
    /// it at save time now instead of relying on the doc comment alone.
    pub fn validate(&self) -> Result<(), String> {
        for (name, spec) in &self.bindings {
            if spec.variants.is_empty() {
                return Err(format!("traps.bindings.{name}: variants must not be empty"));
            }
            for (i, variant) in spec.variants.iter().enumerate() {
                let has_key_expr = variant
                    .key_expression
                    .as_deref()
                    .is_some_and(|e| !e.trim().is_empty());
                if has_key_expr && variant.varbinds.is_empty() {
                    return Err(format!(
                        "traps.bindings.{name}.variants[{i}]: key_expression is set but varbinds is empty — a per-entity key can only be computed from the device's own varbinds, not invented"
                    ));
                }
                if let Some(oid_looking_key) = variant.varbinds.keys().find(|k| looks_like_oid(k)) {
                    return Err(format!(
                        "traps.bindings.{name}.variants[{i}]: varbinds key \"{oid_looking_key}\" looks like an OID — varbinds maps field name -> OID (e.g. {{\"if_index\": \"1.3.6.1.2.1.2.2.1.1\"}}), not the reverse; this looks like the map was written backwards"
                    ));
                }
            }
        }
        Ok(())
    }
}

/// `true` for a string shaped like a dotted-numeric SNMP OID (`^\d+(\.\d+)+$`, e.g.
/// `"1.3.6.1.2.1.2.2.1.1"` — requires **at least one dot**, so a plain numeric field name
/// like `"1"` is not flagged) — used only as a heuristic red flag for a `varbinds` map
/// authored in the wrong direction (see `TrapsSection::validate`'s docs), not a real OID
/// parser/validator. A real field name essentially never matches this shape in practice.
fn looks_like_oid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() >= 2
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
}

/// One trap-derived fact — a row (or, for a singleton binding, the one value) of
/// `metrics.trap_<binding name>`. `variants` (2026-08-30, replacing an earlier
/// open/close-role design after direct user pushback: "давай ты сейчас сам продумаешь
/// логику" → "какой смысл в open и close, если это просто значения в обычной метрике") —
/// a flat list, not two named roles: each variant independently upserts the same
/// key-addressed row whenever its own `trap_oid` matches, merging its `varbinds` into
/// whatever's already there. Two vendors' `linkDown`/`linkUp` for the same logical event,
/// or a standard trap plus an enterprise-specific extended one, are just more entries in
/// this list — nothing about "open" vs "close" is baked into the schema; a device-level
/// value like `ifOperStatus` (present in real `linkDown`/`linkUp` varbinds per RFC1215) is
/// what an `AlertRule.expression` actually branches on.
#[derive(Debug, Clone, Hash, Serialize, Deserialize)]
pub struct TrapSpec {
    pub variants: Vec<TrapEventSpec>,
    /// How long a row may go untouched by *any* variant before the ttl-sweep evicts it —
    /// not "waiting for a specific closing trap" (that concept doesn't exist here), just
    /// general staleness. This is the **only** path that can ever produce
    /// `AutoClearReason::RowMissing`/"Утеряна" for trap-derived data: unlike a polled
    /// table, nothing ever re-walks and rebuilds this table from scratch on a cadence, so
    /// a row that stops being touched would otherwise sit at its last value forever — see
    /// [`crate`] module docs / the trap design changelog for the full reasoning. `None` =
    /// never evicted by staleness (rows only ever change if a matching variant fires
    /// again); day-to-day this is rarely what you want for a keyed binding, since it means
    /// a row for a device that's gone permanently silent never resolves to "Утеряна" at
    /// all.
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    /// Same meaning as `MetricSpec::Detailed::history_retention_secs` — how long
    /// `device_metric_history` runs for `trap_<binding name>` are kept. Trap-derived
    /// tables can churn through history "runs" far more often than a polled metric on a
    /// fixed interval (a flapping port fires on every trap, not once per poll cycle), so
    /// this is worth tuning tighter than a comparable poll metric, not copy-pasted.
    #[serde(default)]
    pub history_retention_secs: Option<u64>,
}

/// One OID this binding recognizes, plus how to extract a row's fields and (optionally)
/// identity from it. `trap_oid` is matched against `snmpTrapOID.0` (v2c/v3) or the
/// v1-Trap-PDU's enterprise+generic+specific fields normalized to the same dotted form by
/// the ingestion layer — see `discovery-snmp`'s trap decode module.
#[derive(Debug, Clone, Hash, Serialize, Deserialize)]
pub struct TrapEventSpec {
    pub trap_oid: String,
    /// field name on the resulting row -> the varbind OID (as it actually appears in the
    /// packet) to pull that field's value from, e.g. `{"if_index":
    /// "1.3.6.1.2.1.2.2.1.1"}` — confirmed against the actual reader,
    /// `discovery_agent::trap_ingest::extract_fields`, which destructures each entry as
    /// `(field_name, oid)`; found live 2026-09-19 (silent zero-field extraction on a
    /// profile written the other way around) after this doc comment itself had the
    /// direction backwards — copied verbatim into the dashboard's `TrapEventSpec` JSDoc
    /// mirror and its trap-editor hint text, so all three said the same wrong thing
    /// consistently, which is exactly why it went unnoticed until live use. Only real
    /// data the device sent — deliberately no way to inject a literal constant here
    /// (removed during design: "если значение не будет попадать под активацию и
    /// деактивацию то тревога либо не взведется, либо не закроется, но тут проблема
    /// конкретно выражения ... и/или данных которые возвращает устройство" — a trap type
    /// with no genuinely distinguishing varbind is an honest limitation of that trap, not
    /// something to paper over with invented data). The ingestion layer always
    /// additionally exposes the matched `trap_oid` itself as an automatic `trap_oid` field
    /// on the row, for the rare case where the OID match is the only signal available.
    #[serde(default)]
    pub varbinds: BTreeMap<String, String>,
    /// Rhai expression, scope `{facts, varbinds}`, computing this row's stable identity —
    /// its result becomes the row's `index` field, the same convention a real SNMP table's
    /// own index already populates, so `AlertRule.row_key_expression`'s existing default
    /// (bare `row.index`, no wrapper — see that field's docs and
    /// `AlertEvaluator::evaluate_row_key`'s implementation; `string(...)` is **not** a
    /// registered Rhai function in this engine and errors with "Function not found" if an
    /// expression actually calls it, see `docs/Roadmap.md`'s 2026-09-20 audit finding #2)
    /// works unchanged for trap-derived tables too. `None` **or an
    /// empty/blank string** (2026-08-30 — "пустой key_expression" normalizes the same as
    /// absent, same "отсутствие = дефолт" convention used elsewhere in this project, e.g.
    /// `queue_control`) means this binding has no per-entity identity at all: a
    /// device-level singleton fact, at most one row, not a per-key table.
    #[serde(default)]
    pub key_expression: Option<String>,
}

impl TrapEventSpec {
    /// Normalizes `Some("")`/`Some("   ")` to `None` — see this field's docs. Every reader
    /// (validation, the ingestion layer deciding singleton-vs-keyed) must go through this,
    /// never the raw field, so the two spellings of "no key" can never silently diverge.
    pub fn key_expression(&self) -> Option<&str> {
        self.key_expression
            .as_deref()
            .map(str::trim)
            .filter(|e| !e.is_empty())
    }
}

/// Syslog ingestion (2026-09-06) — `syslog.bindings.<name>` in `ProfileFile`'s JSON.
/// Sibling of [`TrapsSection`]: same terminal shape (a matched push event becomes a row of
/// a synthetic table-shaped metric, `metrics.syslog_<binding name>`, consumed by ordinary
/// `AlertRule`s exactly like any polled table metric), same "never writes to `alerts`
/// directly" governing principle. The one structural difference is forced by the medium:
/// a trap's `varbinds` maps OID -> field name because an OID isn't human-readable on its
/// own; a syslog message body is unstructured text, so extraction and naming happen in one
/// place — regex **named capture groups** (`(?P<fieldName>...)`) directly become row
/// fields, no separate field-name map needed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyslogSection {
    #[serde(default)]
    pub bindings: BTreeMap<String, SyslogSpec>,
}

impl SyslogSection {
    /// Catches profile-authoring mistakes at save time instead of letting them fail
    /// silently (or not at all — a bad `pattern` would otherwise just never match) on live
    /// traffic: (1) `variants` empty — a binding that can never match anything; (2)
    /// `pattern` doesn't compile as a regex; (3) `max_severity`/`facility` out of their
    /// protocol-defined ranges. Deliberately **does not** repeat `TrapsSection::validate`'s
    /// "key_expression set but nothing to read it from" check — a syslog row always carries
    /// at least `severity`/`facility`/`hostname` (see `discovery-agent`'s ingestion layer),
    /// so `key_expression` never lacks data to read the way a trap's `varbinds` can be an
    /// empty map.
    pub fn validate(&self) -> Result<(), String> {
        for (name, spec) in &self.bindings {
            if spec.variants.is_empty() {
                return Err(format!(
                    "syslog.bindings.{name}: variants must not be empty"
                ));
            }
            for (i, variant) in spec.variants.iter().enumerate() {
                if let Err(e) = regex::Regex::new(&variant.pattern) {
                    return Err(format!(
                        "syslog.bindings.{name}.variants[{i}]: invalid pattern: {e}"
                    ));
                }
                if variant.max_severity.is_some_and(|s| s > 7) {
                    return Err(format!(
                        "syslog.bindings.{name}.variants[{i}]: max_severity must be 0..=7"
                    ));
                }
                if variant.facility.is_some_and(|f| f > 23) {
                    return Err(format!(
                        "syslog.bindings.{name}.variants[{i}]: facility must be 0..=23"
                    ));
                }
            }
        }
        Ok(())
    }
}

/// One matched-message-shape config — a row (or, for a singleton binding, the one value) of
/// `metrics.syslog_<binding name>`. `variants` is a flat list for the same reason as
/// `TrapSpec::variants`: two vendors phrasing the same logical event differently, or an
/// old/new firmware message format, are just more entries — nothing about "open"/"close" is
/// baked into the schema.
#[derive(Debug, Clone, Hash, Serialize, Deserialize)]
pub struct SyslogSpec {
    pub variants: Vec<SyslogEventSpec>,
    /// Same meaning as `TrapSpec::ttl_secs` — how long a row may go untouched by *any*
    /// variant before the ttl-sweep evicts it as `AutoClearReason::RowMissing`. `None` =
    /// never evicted by staleness (fine for a one-off event with no implicit "still
    /// ongoing" state; a persistent-state binding — e.g. a syslog-only "interface down" —
    /// should set this, same as a trap-derived link-state binding would).
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    /// Same meaning as `TrapSpec::history_retention_secs`.
    #[serde(default)]
    pub history_retention_secs: Option<u64>,
}

/// One message shape this binding recognizes. `pattern` is matched against the syslog
/// **message body only** — `facility`/`severity`/`hostname` are already parsed for free
/// from the RFC 3164/5424 header before any binding is even looked up, and are always
/// exposed automatically on the resulting row's fields (direct user request 2026-09-06),
/// not something a pattern needs to re-extract.
#[derive(Debug, Clone, Hash, Serialize, Deserialize)]
pub struct SyslogEventSpec {
    /// Regex tested against the message body. Named capture groups (`(?P<ifName>...)`)
    /// become row fields directly — no separate field-name map, unlike
    /// `TrapEventSpec::varbinds`: a capture group's name already is a real, human field
    /// name, so there's nothing a map would add. The automatic `severity`/`facility`/
    /// `hostname` fields (see this type's docs) win over a same-named capture group, same
    /// "identity always wins" convention `discovery_dsl::util::table_row_to_map` uses for
    /// `index`.
    pub pattern: String,
    /// Optional pre-filter — only consider this variant for messages at or below this
    /// syslog severity (0=emerg .. 7=debug, lower is more severe). `None` = any severity.
    /// Checked (it's already decoded from the header) before `pattern` runs at all.
    #[serde(default)]
    pub max_severity: Option<u8>,
    /// Optional pre-filter on facility (0=kernel, 3=daemon, 16-23=local0-7, ...). `None` =
    /// any facility.
    #[serde(default)]
    pub facility: Option<u8>,
    /// Rhai expression, scope `{facts, fields}` (`fields` = this variant's named capture
    /// groups plus the automatic `severity`/`facility`/`hostname` row fields), computing
    /// this row's stable identity — same convention as `TrapEventSpec::key_expression`.
    /// `None`/blank = singleton, no per-entity identity.
    #[serde(default)]
    pub key_expression: Option<String>,
}

impl SyslogEventSpec {
    /// Same normalizer as `TrapEventSpec::key_expression`.
    pub fn key_expression(&self) -> Option<&str> {
        self.key_expression
            .as_deref()
            .map(str::trim)
            .filter(|e| !e.is_empty())
    }
}

/// L4/L7 service checks (2026-09-07) — `service_checks.checks`/`service_checks.schedule`
/// in `ProfileFile`'s JSON. Sibling of [`MetricsSection`], not of [`TrapsSection`]/
/// [`SyslogSection`]: those two are *push* ingestion (a device sends a trap/syslog message
/// and a binding matches it), this is *poll* — `discovery_agent::handlers::
/// ServiceCheckPollHandler` actively connects out to each declared check on its own
/// schedule, the same way `MetricPollHandler` walks/gets SNMP OIDs.
///
/// **One synthetic table-shaped metric for the whole list, not one metric per check**
/// (`metrics.service_checks`, `MetricValue::Table` with one row per [`ServiceCheckSpec`],
/// keyed by its `name`) — this is what lets an ordinary `AlertRule` alert on "any service
/// check failed" or "check X failed" with **zero new alert-engine code**: `row_metric =
/// "service_checks"`, `expression = "row.ok == false"`, exactly the same row-scoped
/// mechanism `alerts` already gives any table metric (`docs/Architecture/Alerts и Metrics
/// Pipeline.md`'s "Тревоги по строке"). A row disappearing (the check was removed from the
/// profile) is picked up for free too, via the same `AutoClearReason::RowMissing` path any
/// other table metric's shrinking row set already produces — no ttl-sweep needed here
/// (unlike trap/syslog-derived tables), since this table *is* rebuilt from scratch on every
/// poll tick, same as a real SNMP table walk.
///
/// **One schedule for the whole list, not one per check** (unlike `MetricSpec::Detailed`,
/// where every metric gets its own `schedule`) — deliberate scope reduction: every check in
/// the list already lands in the same one metric name and gets rewritten as a whole on
/// every tick (see above), so a per-check cadence would mean either running some checks
/// more often than they're actually used for (the whole row set is only ever consumed
/// together) or complicating the single table write into a partial-update merge for no
/// asked-for benefit. `None` = use the process-wide default, `poll_intervals.
/// service_check_secs`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceChecksSection {
    #[serde(default)]
    pub checks: Vec<ServiceCheckSpec>,
    #[serde(default)]
    pub schedule: Option<Schedule>,
    /// Same meaning as `MetricSpec::Detailed::history_retention_secs`, applied to the
    /// single `service_checks` metric name as a whole.
    #[serde(default)]
    pub history_retention_secs: Option<u64>,
}

impl ServiceChecksSection {
    /// Catches profile-authoring mistakes at save time rather than letting them fail
    /// silently (or confusingly) at poll time: (1) a blank check name — would collide with
    /// every other blank-named check as the same row key; (2) a duplicate name within the
    /// same list — two checks would silently overwrite the same row every tick, "last one
    /// wins" with no indication either existed; (3) `timeout_ms = Some(0)` — a check that
    /// can never possibly succeed, since even a loopback connect takes non-zero time.
    pub fn validate(&self) -> Result<(), String> {
        let mut seen = std::collections::HashSet::new();
        for (i, check) in self.checks.iter().enumerate() {
            if check.name.trim().is_empty() {
                return Err(format!(
                    "service_checks.checks[{i}]: name must not be empty"
                ));
            }
            if !seen.insert(check.name.as_str()) {
                return Err(format!(
                    "service_checks.checks[{i}]: duplicate check name '{}'",
                    check.name
                ));
            }
            if check.timeout_ms == Some(0) {
                return Err(format!(
                    "service_checks.checks[{i}] '{}': timeout_ms must be greater than 0",
                    check.name
                ));
            }
        }
        Ok(())
    }
}

fn default_service_check_enabled() -> bool {
    true
}

/// One check within a profile's `service_checks.checks` — a row of `metrics.service_checks`
/// once polled (see [`ServiceChecksSection`]'s docs). `name` is this row's stable identity
/// (its `MetricTableRow::index`) — deliberately author-chosen and validated unique at save
/// time (`ServiceChecksSection::validate`), unlike a real SNMP table's index or a trap/
/// syslog binding's `key_expression`: there's no device-reported identity to key off here
/// (a TCP port number alone isn't a great row key — a profile can declare more than one
/// check against the *same* port with different `protocol`/`path`, e.g. plain `tcp` on 443
/// *and* an `https` status check on the same port).
#[derive(Debug, Clone, Hash, Serialize, Deserialize)]
pub struct ServiceCheckSpec {
    pub name: String,
    pub protocol: ServiceCheckProtocol,
    /// Host/IP to check — `None` (the common case) means the device's own IP
    /// (`facts.ip`). Only worth overriding for the rare device that fronts a check-worthy
    /// endpoint on a different address than its own management IP.
    #[serde(default)]
    pub target: Option<String>,
    pub port: u16,
    /// HTTP(S) only, ignored for `tcp`/`ssh`. `None`/empty defaults to `"/"`.
    #[serde(default)]
    pub path: Option<String>,
    /// HTTP(S) only. `None` = any 2xx status counts as ok.
    #[serde(default)]
    pub expected_status: Option<u16>,
    /// HTTP(S) only. `None` = response body is not even fetched, let alone checked — see
    /// `discovery_servicecheck::RealServiceChecker::check_http`'s docs for why that's a
    /// deliberate bandwidth saving, not just "not implemented".
    #[serde(default)]
    pub body_contains: Option<String>,
    /// `None` = use the process-wide default (`discovery_core::PingConfig`-adjacent
    /// concept, but service checks don't share `PingConfig` since TCP/HTTP/SSH timeouts
    /// are a materially different knob than ICMP's) — `discovery_agent::handlers::
    /// ServiceCheckPollHandler` falls back to a fixed 2s default when both this and no
    /// override exist, see that handler's docs.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Same on/off convention as `MetricSpec::Detailed::enabled` — `false` means this
    /// check is declared but skipped every tick (and its row consequently disappears from
    /// `metrics.service_checks`, going through the same `AutoClearReason::RowMissing` path
    /// removing it from the list entirely would). No per-device override exists for this
    /// (unlike metrics' `device_metric_settings`) — not asked for, and the profile-level
    /// switch alone already covers "temporarily stop checking this without deleting the
    /// config".
    #[serde(default = "default_service_check_enabled")]
    pub enabled: bool,
}

impl ServiceCheckSpec {
    /// `path` defaulted to `"/"` — see this field's docs.
    pub fn path_or_default(&self) -> &str {
        match &self.path {
            Some(p) if !p.is_empty() => p,
            _ => "/",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceCheckProtocol {
    Tcp,
    Http,
    Https,
    Ssh,
}

fn default_alert_enabled() -> bool {
    true
}

/// One alert rule within a profile — a row in `profile_alerts`
/// (`migrations/0020_profile_alerts.sql`), normalized out of what used to be a single
/// `profiles.alerts` JSONB column (direct user request 2026-08-17: "сделай хранение
/// тревог профиля так же в отдельной таблице БД" — same reasoning as the earlier
/// `profile_metrics` normalization: deleting a profile cleans up its alert rules
/// automatically via `ON DELETE CASCADE`, no dead rows left behind).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    #[serde(default)]
    pub policy: discovery_core::AlertPolicy,
    pub name: String,
    /// "info" | "warning" | "critical" — anything else is treated as "info".
    pub level: String,
    /// The name of a table-shaped metric (`MetricSpec::Detailed::columns` is `Some` — see
    /// its docs) this rule iterates, one independent incident per matching row instead of
    /// one incident for the whole device (2026-08-29, direct user request — "тревога по
    /// порту"). `None` (the default, and the only behavior that existed before this field)
    /// means an ordinary device-level rule: `expression`/`deactivation_expression`/
    /// `facts_expression` evaluate once per device per tick, exactly as before.
    ///
    /// When set, those same three expressions instead evaluate **once per row** of
    /// `metrics.<row_metric>` (must actually be a `MetricValue::Table` — if the metric
    /// hasn't polled yet, or isn't table-shaped, this rule simply has zero rows to
    /// evaluate this tick, not an error), with a third scope variable, `row`, bound to
    /// that row's fields (same shape as an element of the array `MetricValue::Table`
    /// already converts to for Rhai — `row.ifDescr`, `row.ifOperStatus`, `row.index`, …).
    /// See [`Self::row_key_expression`] for how each row gets its own tracking identity,
    /// and `discovery_core::AlertStateTracker`'s docs for the independent-lifecycle
    /// mechanics this enables.
    #[serde(default)]
    pub row_metric: Option<String>,
    /// Only meaningful when [`Self::row_metric`] is set. A Rhai expression, scope `{facts,
    /// metrics, row}`, that computes this row's stable identity for tracking purposes —
    /// e.g. `row.ifDescr` (survives the port being renumbered, not just moved) instead of
    /// the default. `None` (the default) means bare `row.index` — the row's own SNMP
    /// index, always present, usually stable, but tied to whatever index the device
    /// happens to report rather than something a human would recognize if it changes.
    /// **Not `string(row.index)`** — `string(...)` is not a registered Rhai function in
    /// this engine (see `AlertEvaluator::evaluate_row_key`'s implementation, which
    /// short-circuits to `row.index.clone()` directly rather than evaluating Rhai at all
    /// for the `None` case); an expression that actually calls `string(...)` itself would
    /// hard-error with "Function not found: string" — see `docs/Roadmap.md`'s 2026-09-20
    /// audit finding #2.
    /// **Choose a field that uniquely identifies the row for as long as you want its
    /// alert's identity to persist** — two rows this expression maps to the same value
    /// are, as far as tracking is concerned, the same incident.
    #[serde(default)]
    pub row_key_expression: Option<String>,
    /// **Activation** condition — a Rhai boolean expression with two variables in scope:
    /// `facts` (device identity, currently just `ip`) and `metrics` (the device's data
    /// bag), same scope convention as `match.expression` (added 2026-08-17 — this
    /// expression previously only saw `metrics`; `facts` access was a direct user
    /// request). Example: `metrics.cpu > 90`. When [`Self::row_metric`] is set, a third
    /// variable `row` is also in scope — see that field's docs. Example:
    /// `row.ifOperStatus == 2`.
    pub expression: String,
    /// **Deactivation** condition (added 2026-08-17, direct user request: "нужно что бы
    /// были условия активации, деактивации") — a separate Rhai boolean expression, same
    /// `facts`/`metrics` scope as `expression`. `None` (the default, and the only
    /// behavior that existed before this field) means "the negation of `expression`" —
    /// computed by the caller (`discovery_agent::handlers::AlertEvalHandler`), not this
    /// type. A genuinely separate expression is what makes hysteresis possible: e.g.
    /// activate at `metrics.cpu > 90`, only deactivate at `metrics.cpu < 70`, staying
    /// open through the dead zone in between instead of flapping right at one threshold
    /// — see `discovery_core::AlertStateTracker`'s docs for exactly how this is debounced.
    #[serde(default)]
    pub deactivation_expression: Option<String>,
    /// Evaluated **once**, only at the moment a brand-new incident activates (added
    /// 2026-08-17, direct user request: "какие facts доставать в момент создания
    /// тревоги — лучше в виде rhai выражения") — same `facts`/`metrics` scope as
    /// `expression`. Typically returns a Rhai object map, e.g. `#{ip: facts.ip, cpu:
    /// metrics.cpu, model: metrics.sys_descr}`, converted to JSON and stored as
    /// `discovery_core::Alert::facts`. `None` = no snapshot captured for this rule's
    /// incidents. Never re-evaluated for an already-open incident — see `Alert::facts`'s
    /// docs for why it stays frozen at whatever was true when the incident opened.
    #[serde(default)]
    pub facts_expression: Option<String>,
    /// Human-readable message. Supports `{metrics.<name>}`/`{facts.<name>}` substitution
    /// (plain string replacement, not another expression — see
    /// `AlertEvaluator::render_message`).
    pub message: String,
    /// How long the deactivation condition must hold before the alert is actually
    /// cleared. Guards against a single noisy poll flapping an incident open/closed —
    /// see `discovery_core::AlertStateTracker`. Defaults to 0 (clear immediately once the
    /// deactivation condition first holds).
    #[serde(default)]
    pub clear_after_seconds: Option<u64>,
    /// Minimum continuous activation duration before opening an incident.
    #[serde(default)]
    pub activate_after_seconds: Option<u64>,
    /// Time window used to detect repeated activation/deactivation switches.
    #[serde(default)]
    pub flap_window_seconds: Option<u64>,
    /// Number of switches in the window at which notifications are suppressed.
    #[serde(default)]
    pub flap_threshold: Option<u32>,
    /// Profile-level on/off switch (added 2026-08-17, direct user request: "добавь
    /// возможность выключения тревоги и включения"). `false` = `AlertEvalHandler` skips
    /// this rule entirely — never activates a new incident, and deliberately leaves any
    /// *already-open* incident for it completely alone (frozen at its last observed
    /// state, not force-cleared) rather than silently closing something a human might
    /// still care about. Re-enabling picks evaluation back up on the very next tick, same
    /// "freeze, don't force-close" contract as `Device::enabled`/
    /// `device_metric_settings`. Defaults to `true` — an existing/omitted rule keeps
    /// working exactly as before this field existed.
    #[serde(default = "default_alert_enabled")]
    pub enabled: bool,
}

/// Content fingerprint of a profile's *behavioral* fields — match expression, metrics to
/// poll, trap bindings, alert rules. Any storage backend producing a `ProfileFile` (file,
/// Postgres row, ...) should compute `version` this same way, so "same content" always
/// means "same version" regardless of where the profile came from.
pub fn compute_version(
    match_expression: &str,
    metrics_poll: &BTreeMap<String, MetricSpec>,
    traps: &TrapsSection,
    syslog: &SyslogSection,
    service_checks: &ServiceChecksSection,
    alerts: &[AlertRule],
) -> String {
    let mut hasher = DefaultHasher::new();
    match_expression.hash(&mut hasher);
    // BTreeMap iterates in sorted key order — deterministic regardless of insertion order.
    // `schedule`/`history_retention_secs`/`history_keep_last_success`/
    // `history_keep_last_attempt`/`enabled`/`derive` are all part of the hash too — all
    // behavioral, not cosmetic (a device already polling this metric needs its chain
    // restarted to pick up a new interval, calendar schedule, default on/off state, or
    // derive kind, same as it would for a new OID; a retention/keep-flag edit changes how
    // long history for it survives going forward). Note `enabled` here is only the
    // profile's *default* — a device-level override (`device_metric_settings`) is a
    // separate mechanism this version fingerprint doesn't and shouldn't cover, see
    // `discovery_devices::DeviceStore`'s docs.
    for (key, spec) in metrics_poll {
        key.hash(&mut hasher);
        spec.oid().hash(&mut hasher);
        // Added alongside `MetricSpec::SshCommand` (2026-09-07) — `None` for every
        // pre-existing SNMP-sourced variant, so this is a purely additive hash input: it
        // never changes what an existing SNMP-only profile's version was computed from
        // relative to before, beyond the usual one-time bump every past addition to this
        // hashed set already caused (see this function's own history for precedent).
        spec.command().hash(&mut hasher);
        spec.columns().hash(&mut hasher);
        spec.schedule().hash(&mut hasher);
        spec.history_retention_secs().hash(&mut hasher);
        spec.history_keep_last_success().hash(&mut hasher);
        spec.history_keep_last_attempt().hash(&mut hasher);
        spec.enabled().hash(&mut hasher);
        spec.derive().hash(&mut hasher);
    }
    for (name, spec) in &traps.bindings {
        name.hash(&mut hasher);
        spec.hash(&mut hasher);
    }
    for (name, spec) in &syslog.bindings {
        name.hash(&mut hasher);
        spec.hash(&mut hasher);
    }
    service_checks.checks.hash(&mut hasher);
    service_checks.schedule.hash(&mut hasher);
    service_checks.history_retention_secs.hash(&mut hasher);
    for alert in alerts {
        serde_json::to_string(&alert.policy)
            .unwrap_or_default()
            .hash(&mut hasher);
        alert.name.hash(&mut hasher);
        alert.level.hash(&mut hasher);
        alert.row_metric.hash(&mut hasher);
        alert.row_key_expression.hash(&mut hasher);
        alert.expression.hash(&mut hasher);
        alert.deactivation_expression.hash(&mut hasher);
        alert.facts_expression.hash(&mut hasher);
        alert.message.hash(&mut hasher);
        alert.clear_after_seconds.hash(&mut hasher);
        alert.activate_after_seconds.hash(&mut hasher);
        alert.flap_window_seconds.hash(&mut hasher);
        alert.flap_threshold.hash(&mut hasher);
        alert.enabled.hash(&mut hasher);
    }
    format!("{:016x}", hasher.finish())
}

/// A fingerprint of a profile set (name + content version of each, order-independent) —
/// changes iff a profile was added, removed, renamed, or edited. Used by
/// `ProfileMatcher::signature` and the hot-reload loop in `discovery-agent` to decide
/// whether a reload actually needs to propagate anywhere.
pub fn profiles_signature(profiles: &[ProfileFile]) -> String {
    let mut parts: Vec<String> = profiles
        .iter()
        .map(|p| format!("{}:{}", p.profile.name, p.version))
        .collect();
    parts.sort();
    parts.join(",")
}

#[cfg(test)]
mod traps_tests {
    use super::*;

    fn a_variant(trap_oid: &str, key_expression: Option<&str>) -> TrapEventSpec {
        let mut varbinds = BTreeMap::new();
        varbinds.insert("if_index".to_string(), "1.3.6.1.2.1.2.2.1.1".to_string());
        TrapEventSpec {
            trap_oid: trap_oid.to_string(),
            varbinds,
            key_expression: key_expression.map(str::to_string),
        }
    }

    #[test]
    fn key_expression_none_is_none() {
        let v = TrapEventSpec {
            trap_oid: "1.2.3".into(),
            varbinds: BTreeMap::new(),
            key_expression: None,
        };
        assert_eq!(v.key_expression(), None);
    }

    #[test]
    fn key_expression_blank_string_normalizes_to_none() {
        let v = TrapEventSpec {
            trap_oid: "1.2.3".into(),
            varbinds: BTreeMap::new(),
            key_expression: Some("   ".to_string()),
        };
        assert_eq!(v.key_expression(), None, "blank key_expression must behave exactly like absent — same 'отсутствие = дефолт' convention as elsewhere");
    }

    #[test]
    fn key_expression_real_value_is_trimmed_and_kept() {
        let v = TrapEventSpec {
            trap_oid: "1.2.3".into(),
            varbinds: BTreeMap::new(),
            key_expression: Some("  varbinds.if_index  ".to_string()),
        };
        assert_eq!(v.key_expression(), Some("varbinds.if_index"));
    }

    #[test]
    fn validate_rejects_a_binding_with_no_variants() {
        let mut section = TrapsSection::default();
        section.bindings.insert(
            "empty".to_string(),
            TrapSpec {
                variants: vec![],
                ttl_secs: None,
                history_retention_secs: None,
            },
        );
        let err = section
            .validate()
            .expect_err("a binding with zero variants can never match anything");
        assert!(err.contains("empty"));
        assert!(err.contains("variants"));
    }

    #[test]
    fn validate_rejects_key_expression_with_no_varbinds_to_read_it_from() {
        let mut section = TrapsSection::default();
        let broken = TrapEventSpec {
            trap_oid: "1.2.3".into(),
            varbinds: BTreeMap::new(),
            key_expression: Some("varbinds.if_index".into()),
        };
        section.bindings.insert(
            "broken".to_string(),
            TrapSpec {
                variants: vec![broken],
                ttl_secs: None,
                history_retention_secs: None,
            },
        );
        let err = section.validate().expect_err("key_expression referencing varbinds that were never declared must be caught at save time");
        assert!(err.contains("broken"));
        assert!(err.contains("varbinds"));
    }

    #[test]
    fn validate_rejects_a_varbinds_key_that_looks_like_an_oid() {
        let mut section = TrapsSection::default();
        let mut backwards = BTreeMap::new();
        backwards.insert("1.3.6.1.2.1.2.2.1.1".to_string(), "if_index".to_string()); // OID -> field name, i.e. reversed
        let broken = TrapEventSpec {
            trap_oid: "1.2.3".into(),
            varbinds: backwards,
            key_expression: None,
        };
        section.bindings.insert(
            "backwards".to_string(),
            TrapSpec {
                variants: vec![broken],
                ttl_secs: None,
                history_retention_secs: None,
            },
        );
        let err = section.validate().expect_err("a varbinds key shaped like a dotted OID is a strong signal the map was authored field_name/OID-reversed");
        assert!(err.contains("backwards"));
        assert!(err.contains("1.3.6.1.2.1.2.2.1.1"));
    }

    #[test]
    fn validate_accepts_a_field_name_that_happens_to_contain_a_dot_free_number() {
        // A plain numeric-looking field name (no dot) must NOT be flagged — only a
        // multi-part dotted-numeric shape is a meaningful OID signal.
        let mut section = TrapsSection::default();
        let mut varbinds = BTreeMap::new();
        varbinds.insert("1".to_string(), "1.3.6.1.2.1.2.2.1.1".to_string());
        let variant = TrapEventSpec {
            trap_oid: "1.2.3".into(),
            varbinds,
            key_expression: None,
        };
        section.bindings.insert(
            "ok".to_string(),
            TrapSpec {
                variants: vec![variant],
                ttl_secs: None,
                history_retention_secs: None,
            },
        );
        section
            .validate()
            .expect("a single numeric field name with no dot must not be flagged as OID-shaped");
    }

    #[test]
    fn validate_accepts_a_singleton_variant_with_no_varbinds_and_no_key_expression() {
        let mut section = TrapsSection::default();
        let cold_start = TrapEventSpec {
            trap_oid: "1.3.6.1.6.3.1.1.5.1".into(),
            varbinds: BTreeMap::new(),
            key_expression: None,
        };
        section.bindings.insert(
            "cold_start".to_string(),
            TrapSpec {
                variants: vec![cold_start],
                ttl_secs: None,
                history_retention_secs: None,
            },
        );
        section
            .validate()
            .expect("a singleton binding with no key_expression needs no varbinds");
    }

    #[test]
    fn validate_accepts_a_well_formed_keyed_binding() {
        let mut section = TrapsSection::default();
        section.bindings.insert(
            "port_link_state".to_string(),
            TrapSpec {
                variants: vec![
                    a_variant("1.3.6.1.6.3.1.1.5.3", Some("varbinds.if_index")),
                    a_variant("1.3.6.1.6.3.1.1.5.4", Some("varbinds.if_index")),
                ],
                ttl_secs: Some(3600),
                history_retention_secs: Some(604800),
            },
        );
        section.validate().expect(
            "a keyed binding with matching varbinds/key_expression on every variant is valid",
        );
    }

    /// `variants` is a flat list now, not two named roles — see this type's docs for the
    /// 2026-08-30 design change. Multiple OIDs mapping to the same binding (e.g. a
    /// standard trap plus a vendor-specific extended one) must round-trip through JSON.
    #[test]
    fn deserializes_multiple_variants_for_one_binding() {
        let json = r#"{
            "variants": [
                {"trap_oid": "1.3.6.1.6.3.1.1.5.3", "varbinds": {"if_index": "1.3.6.1.2.1.2.2.1.1"}, "key_expression": "varbinds.if_index"},
                {"trap_oid": "1.3.6.1.6.3.1.1.5.4", "varbinds": {"if_index": "1.3.6.1.2.1.2.2.1.1"}, "key_expression": "varbinds.if_index"}
            ],
            "ttl_secs": 3600,
            "history_retention_secs": 604800
        }"#;
        let spec: TrapSpec = serde_json::from_str(json).unwrap();
        assert_eq!(spec.variants.len(), 2);
        assert_eq!(spec.ttl_secs, Some(3600));
    }

    /// `compute_version` must be sensitive to trap bindings — a profile edited only in its
    /// `traps` section still needs to bump `version` so `ProfileApply` picks it up, same
    /// reasoning `version_changes_when_columns_change` already established for metrics.
    #[test]
    fn compute_version_changes_when_traps_change() {
        let empty = TrapsSection::default();
        let mut with_binding = TrapsSection::default();
        with_binding.bindings.insert(
            "port_link_state".to_string(),
            TrapSpec {
                variants: vec![a_variant("1.3.6.1.6.3.1.1.5.3", None)],
                ttl_secs: None,
                history_retention_secs: None,
            },
        );

        let v1 = compute_version(
            "true",
            &BTreeMap::new(),
            &empty,
            &SyslogSection::default(),
            &ServiceChecksSection::default(),
            &[],
        );
        let v2 = compute_version(
            "true",
            &BTreeMap::new(),
            &with_binding,
            &SyslogSection::default(),
            &ServiceChecksSection::default(),
            &[],
        );
        assert_ne!(v1, v2);
    }
}

#[cfg(test)]
mod syslog_tests {
    use super::*;

    fn a_variant(pattern: &str) -> SyslogEventSpec {
        SyslogEventSpec {
            pattern: pattern.to_string(),
            max_severity: None,
            facility: None,
            key_expression: None,
        }
    }

    #[test]
    fn key_expression_none_is_none() {
        let v = SyslogEventSpec {
            pattern: ".*".into(),
            max_severity: None,
            facility: None,
            key_expression: None,
        };
        assert_eq!(v.key_expression(), None);
    }

    #[test]
    fn key_expression_blank_string_normalizes_to_none() {
        let v = SyslogEventSpec {
            pattern: ".*".into(),
            max_severity: None,
            facility: None,
            key_expression: Some("   ".to_string()),
        };
        assert_eq!(v.key_expression(), None, "blank key_expression must behave exactly like absent — same 'отсутствие = дефолт' convention as elsewhere");
    }

    #[test]
    fn key_expression_real_value_is_trimmed_and_kept() {
        let v = SyslogEventSpec {
            pattern: ".*".into(),
            max_severity: None,
            facility: None,
            key_expression: Some("  fields.hostname  ".to_string()),
        };
        assert_eq!(v.key_expression(), Some("fields.hostname"));
    }

    #[test]
    fn validate_rejects_a_binding_with_no_variants() {
        let mut section = SyslogSection::default();
        section.bindings.insert(
            "empty".to_string(),
            SyslogSpec {
                variants: vec![],
                ttl_secs: None,
                history_retention_secs: None,
            },
        );
        let err = section
            .validate()
            .expect_err("a binding with zero variants can never match anything");
        assert!(err.contains("empty"));
        assert!(err.contains("variants"));
    }

    #[test]
    fn validate_rejects_an_invalid_regex_pattern() {
        let mut section = SyslogSection::default();
        let broken = a_variant("(unclosed");
        section.bindings.insert(
            "broken".to_string(),
            SyslogSpec {
                variants: vec![broken],
                ttl_secs: None,
                history_retention_secs: None,
            },
        );
        let err = section.validate().expect_err(
            "an unparseable regex must be caught at save time, not silently never match",
        );
        assert!(err.contains("broken"));
        assert!(err.contains("pattern"));
    }

    #[test]
    fn validate_rejects_max_severity_out_of_range() {
        let mut section = SyslogSection::default();
        let variant = SyslogEventSpec {
            pattern: ".*".into(),
            max_severity: Some(8),
            facility: None,
            key_expression: None,
        };
        section.bindings.insert(
            "bad_severity".to_string(),
            SyslogSpec {
                variants: vec![variant],
                ttl_secs: None,
                history_retention_secs: None,
            },
        );
        let err = section
            .validate()
            .expect_err("severity is 0..=7, 8 is out of range");
        assert!(err.contains("max_severity"));
    }

    #[test]
    fn validate_rejects_facility_out_of_range() {
        let mut section = SyslogSection::default();
        let variant = SyslogEventSpec {
            pattern: ".*".into(),
            max_severity: None,
            facility: Some(24),
            key_expression: None,
        };
        section.bindings.insert(
            "bad_facility".to_string(),
            SyslogSpec {
                variants: vec![variant],
                ttl_secs: None,
                history_retention_secs: None,
            },
        );
        let err = section
            .validate()
            .expect_err("facility is 0..=23, 24 is out of range");
        assert!(err.contains("facility"));
    }

    #[test]
    fn validate_accepts_a_well_formed_binding_with_key_expression_and_no_named_groups() {
        // Deliberately no named capture group here — unlike traps, a syslog row always
        // carries severity/facility/hostname automatically, so key_expression never lacks
        // data to read even when `pattern` itself captures nothing.
        let mut section = SyslogSection::default();
        let variant = SyslogEventSpec {
            pattern: r".*[Ii]nterface.*down.*".into(),
            max_severity: Some(4),
            facility: Some(23),
            key_expression: Some("fields.hostname".into()),
        };
        section.bindings.insert(
            "iface_down".to_string(),
            SyslogSpec {
                variants: vec![variant],
                ttl_secs: Some(3600),
                history_retention_secs: Some(604800),
            },
        );
        section.validate().expect("a well-formed binding with severity/facility prefilters and a key_expression over auto-fields is valid");
    }

    /// `variants` is a flat list, same reasoning as `TrapSpec::variants` — two vendors
    /// phrasing the same logical event differently are just more entries.
    #[test]
    fn deserializes_multiple_variants_for_one_binding() {
        let json = r#"{
            "variants": [
                {"pattern": "(?P<ifName>\\S+) down", "max_severity": 4, "facility": 23, "key_expression": "fields.ifName"},
                {"pattern": "(?P<ifName>\\S+) is down", "max_severity": 4, "facility": 23, "key_expression": "fields.ifName"}
            ],
            "ttl_secs": 3600,
            "history_retention_secs": 604800
        }"#;
        let spec: SyslogSpec = serde_json::from_str(json).unwrap();
        assert_eq!(spec.variants.len(), 2);
        assert_eq!(spec.ttl_secs, Some(3600));
        assert_eq!(spec.variants[0].max_severity, Some(4));
        assert_eq!(spec.variants[0].facility, Some(23));
    }

    /// `compute_version` must be sensitive to syslog bindings — a profile edited only in
    /// its `syslog` section still needs to bump `version` so `ProfileApply` picks it up,
    /// same reasoning `compute_version_changes_when_traps_change` established for traps.
    #[test]
    fn compute_version_changes_when_syslog_changes() {
        let empty = SyslogSection::default();
        let mut with_binding = SyslogSection::default();
        with_binding.bindings.insert(
            "iface_down".to_string(),
            SyslogSpec {
                variants: vec![a_variant(".*down.*")],
                ttl_secs: None,
                history_retention_secs: None,
            },
        );

        let v1 = compute_version(
            "true",
            &BTreeMap::new(),
            &TrapsSection::default(),
            &empty,
            &ServiceChecksSection::default(),
            &[],
        );
        let v2 = compute_version(
            "true",
            &BTreeMap::new(),
            &TrapsSection::default(),
            &with_binding,
            &ServiceChecksSection::default(),
            &[],
        );
        assert_ne!(v1, v2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ProfileFile`'s `Deserialize` is still real production code — `POST
    /// /api/profiles`'s JSON body goes through exactly this — just no longer reachable
    /// via TOML (`ProfileFile::parse`/`load_profiles_from_dir` removed 2026-08-16, direct
    /// user request: no more file-based seeding anywhere in this project).
    #[test]
    fn deserializes_a_minimal_profile_from_json() {
        let json = r#"{
            "profile": {"name": "test_profile", "priority": 10},
            "match": {"expression": "true"},
            "metrics": {"poll": {"uptime": "1.3.6.1.2.1.1.3.0"}},
            "alerts": [{"name": "always_on", "level": "info", "expression": "true", "message": "hi"}]
        }"#;
        let parsed: ProfileFile = serde_json::from_str(json).expect("should deserialize");
        assert_eq!(parsed.profile.name, "test_profile");
        assert_eq!(parsed.profile.priority, 10);
        assert_eq!(
            parsed.metrics.poll.get("uptime"),
            Some(&MetricSpec::Oid("1.3.6.1.2.1.1.3.0".to_string()))
        );
        assert_eq!(parsed.alerts.len(), 1);
        // `version` is `#[serde(skip)]` — a plain deserialize (e.g. a web request body)
        // never carries one; only a store's `load_all` (via `compute_version`) fills it.
        assert!(parsed.version.is_empty());
    }

    /// The three states `Detailed::columns` distinguishes (see its own docs) — the whole
    /// point of encoding scalar-vs-table this way instead of a separate `kind`/`type` tag
    /// is that these three JSON shapes round-trip unambiguously through `#[serde(untagged)]`.
    #[test]
    fn columns_absent_is_a_scalar() {
        let spec: MetricSpec = serde_json::from_str(r#"{"oid": "1.2.3"}"#).unwrap();
        assert!(!spec.is_table());
        assert_eq!(spec.columns(), None);
    }

    #[test]
    fn columns_explicit_null_is_also_a_scalar() {
        // A dashboard/API client that always writes the key (rather than omitting it) must
        // get the same scalar behavior as omitting it entirely.
        let spec: MetricSpec =
            serde_json::from_str(r#"{"oid": "1.2.3", "columns": null}"#).unwrap();
        assert!(!spec.is_table());
        assert_eq!(spec.columns(), None);
    }

    #[test]
    fn columns_empty_object_is_a_table_in_collect_everything_mode() {
        let spec: MetricSpec =
            serde_json::from_str(r#"{"oid": "1.3.6.1.2.1.2.2.1", "columns": {}}"#).unwrap();
        assert!(spec.is_table());
        assert_eq!(spec.columns(), Some(&BTreeMap::new()));
    }

    #[test]
    fn columns_populated_is_a_table_with_curated_columns() {
        let spec: MetricSpec = serde_json::from_str(
            r#"{"oid": "1.3.6.1.2.1.2.2.1", "columns": {"ifIndex": "1", "ifDescr": "2", "ifOperStatus": "8"}}"#,
        )
        .unwrap();
        assert!(spec.is_table());
        let columns = spec.columns().unwrap();
        assert_eq!(columns.len(), 3);
        assert_eq!(columns.get("ifDescr"), Some(&"2".to_string()));
    }

    #[test]
    fn the_bare_string_shorthand_is_always_a_scalar_never_a_table() {
        let spec: MetricSpec = serde_json::from_str(r#""1.2.3""#).unwrap();
        assert!(!spec.is_table());
        assert_eq!(spec.columns(), None);
    }

    #[test]
    fn version_changes_when_columns_change() {
        let mut scalar = BTreeMap::new();
        scalar.insert(
            "if_table".to_string(),
            MetricSpec::Detailed {
                oid: "1.3.6.1.2.1.2.2.1".to_string(),
                columns: None,
                schedule: None,
                history_retention_secs: None,
                enabled: true,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
                derive: None,
            },
        );

        let mut table = BTreeMap::new();
        let mut columns = BTreeMap::new();
        columns.insert("ifDescr".to_string(), "2".to_string());
        table.insert(
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

        assert_ne!(
            compute_version("true", &scalar, &TrapsSection::default(), &SyslogSection::default(), &ServiceChecksSection::default(), &[]),
            compute_version("true", &table, &TrapsSection::default(), &SyslogSection::default(), &ServiceChecksSection::default(), &[]),
            "turning a metric from scalar into a table (or changing which columns it declares) must restart a device's poll chain, same as any other behavioral edit"
        );
    }

    #[test]
    fn version_changes_when_the_match_expression_changes() {
        let a = compute_version(
            "true",
            &BTreeMap::new(),
            &TrapsSection::default(),
            &SyslogSection::default(),
            &ServiceChecksSection::default(),
            &[],
        );
        let b = compute_version(
            "false",
            &BTreeMap::new(),
            &TrapsSection::default(),
            &SyslogSection::default(),
            &ServiceChecksSection::default(),
            &[],
        );
        assert_ne!(
            a, b,
            "editing a profile's match expression must change its version"
        );
    }

    #[test]
    fn identical_content_always_produces_the_same_version() {
        let a = compute_version(
            "true",
            &BTreeMap::new(),
            &TrapsSection::default(),
            &SyslogSection::default(),
            &ServiceChecksSection::default(),
            &[],
        );
        let b = compute_version(
            "true",
            &BTreeMap::new(),
            &TrapsSection::default(),
            &SyslogSection::default(),
            &ServiceChecksSection::default(),
            &[],
        );
        assert_eq!(a, b);
    }

    #[test]
    fn compute_version_is_order_independent_over_metrics_poll() {
        // BTreeMap already guarantees sorted iteration, but assert it explicitly since
        // this is exactly what makes "same profile, loaded from a DB row vs a file"
        // produce the same version regardless of column/insertion order.
        let mut a = BTreeMap::new();
        a.insert("cpu".to_string(), MetricSpec::Oid("1.2.3".to_string()));
        a.insert("uptime".to_string(), MetricSpec::Oid("1.2.4".to_string()));

        let mut b = BTreeMap::new();
        b.insert("uptime".to_string(), MetricSpec::Oid("1.2.4".to_string()));
        b.insert("cpu".to_string(), MetricSpec::Oid("1.2.3".to_string()));

        assert_eq!(
            compute_version(
                "true",
                &a,
                &TrapsSection::default(),
                &SyslogSection::default(),
                &ServiceChecksSection::default(),
                &[]
            ),
            compute_version(
                "true",
                &b,
                &TrapsSection::default(),
                &SyslogSection::default(),
                &ServiceChecksSection::default(),
                &[]
            )
        );
    }

    #[test]
    fn compute_version_changes_when_only_a_metrics_interval_changes() {
        // A poll-cadence-only edit is a behavioral change (see compute_version's docs) —
        // must bump the version just like an OID edit would, so a device already on this
        // profile gets its MetricPoll chain restarted with the new interval.
        let mut a = BTreeMap::new();
        a.insert(
            "cpu".to_string(),
            MetricSpec::Detailed {
                columns: None,
                oid: "1.2.3".to_string(),
                schedule: Some(Schedule::Periodic { interval_secs: 10 }),
                history_retention_secs: None,
                enabled: true,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
                derive: None,
            },
        );

        let mut b = BTreeMap::new();
        b.insert(
            "cpu".to_string(),
            MetricSpec::Detailed {
                columns: None,
                oid: "1.2.3".to_string(),
                schedule: Some(Schedule::Periodic { interval_secs: 30 }),
                history_retention_secs: None,
                enabled: true,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
                derive: None,
            },
        );

        assert_ne!(
            compute_version(
                "true",
                &a,
                &TrapsSection::default(),
                &SyslogSection::default(),
                &ServiceChecksSection::default(),
                &[]
            ),
            compute_version(
                "true",
                &b,
                &TrapsSection::default(),
                &SyslogSection::default(),
                &ServiceChecksSection::default(),
                &[]
            )
        );
    }

    #[test]
    fn compute_version_changes_when_switching_from_periodic_to_calendar_schedule() {
        // Direct user request 2026-08-16: a metric can now be polled on a calendar
        // schedule instead of a running interval — switching modes is just as behavioral
        // as changing the interval itself, must bump the version too.
        let mut periodic = BTreeMap::new();
        periodic.insert(
            "cpu".to_string(),
            MetricSpec::Detailed {
                columns: None,
                oid: "1.2.3".to_string(),
                schedule: Some(Schedule::Periodic { interval_secs: 10 }),
                history_retention_secs: None,
                enabled: true,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
                derive: None,
            },
        );

        let mut calendar = BTreeMap::new();
        calendar.insert(
            "cpu".to_string(),
            MetricSpec::Detailed {
                oid: "1.2.3".to_string(),
                columns: None,
                schedule: Some(Schedule::Calendar {
                    months: vec![],
                    days_of_month: vec![],
                    time: chrono::NaiveTime::from_hms_opt(3, 0, 0).unwrap(),
                }),
                history_retention_secs: None,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
                enabled: true,
                derive: None,
            },
        );

        assert_ne!(
            compute_version(
                "true",
                &periodic,
                &TrapsSection::default(),
                &SyslogSection::default(),
                &ServiceChecksSection::default(),
                &[]
            ),
            compute_version(
                "true",
                &calendar,
                &TrapsSection::default(),
                &SyslogSection::default(),
                &ServiceChecksSection::default(),
                &[]
            )
        );
    }

    #[test]
    fn compute_version_changes_when_history_retention_changes() {
        // Direct user request 2026-08-16: retention is behavioral (changes how long a
        // metric's history survives going forward), so editing it must bump the version
        // just like `interval_secs` does.
        let mut forever = BTreeMap::new();
        forever.insert(
            "cpu".to_string(),
            MetricSpec::Detailed {
                columns: None,
                oid: "1.2.3".to_string(),
                schedule: None,
                history_retention_secs: None,
                enabled: true,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
                derive: None,
            },
        );

        let mut thirty_days = BTreeMap::new();
        thirty_days.insert(
            "cpu".to_string(),
            MetricSpec::Detailed {
                columns: None,
                oid: "1.2.3".to_string(),
                schedule: None,
                history_retention_secs: Some(30 * 86400),
                enabled: true,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
                derive: None,
            },
        );

        assert_ne!(
            compute_version(
                "true",
                &forever,
                &TrapsSection::default(),
                &SyslogSection::default(),
                &ServiceChecksSection::default(),
                &[]
            ),
            compute_version(
                "true",
                &thirty_days,
                &TrapsSection::default(),
                &SyslogSection::default(),
                &ServiceChecksSection::default(),
                &[]
            )
        );
    }

    #[test]
    fn metric_spec_history_retention_secs_deserializes_and_defaults_to_forever() {
        let with_retention: MetricSpec =
            serde_json::from_str(r#"{"oid": "1.2.3", "history_retention_secs": 2592000}"#).unwrap();
        assert_eq!(with_retention.history_retention_secs(), Some(2592000));

        let plain: MetricSpec = serde_json::from_str(r#"{"oid": "1.2.3"}"#).unwrap();
        assert_eq!(
            plain.history_retention_secs(),
            None,
            "omitted means keep forever"
        );

        let bare: MetricSpec = serde_json::from_str(r#""1.2.3""#).unwrap();
        assert_eq!(
            bare.history_retention_secs(),
            None,
            "the plain-string form has no way to set a retention"
        );
    }

    #[test]
    fn metric_spec_plain_string_form_still_deserializes_and_uses_the_default_interval() {
        // `MetricSpec`'s `#[serde(untagged)]` — plain string ("just an OID") vs. table
        // form ("OID + its own cadence") — is generic serde behavior, not TOML-specific,
        // so it's still exercised via JSON (the shape `POST /api/profiles` actually
        // receives) even with TOML parsing gone entirely.
        let json = r#"{"poll": {
            "uptime": "1.3.6.1.2.1.1.3.0",
            "cpu": {"oid": "1.3.6.1.4.1.9.9.109.1.1.1.1.3.1", "schedule": {"interval_secs": 10}}
        }}"#;
        let parsed: MetricsSection = serde_json::from_str(json).expect("should deserialize");
        assert_eq!(
            parsed.poll.get("uptime"),
            Some(&MetricSpec::Oid("1.3.6.1.2.1.1.3.0".to_string()))
        );
        assert_eq!(parsed.poll.get("uptime").unwrap().interval_secs(), None);
        assert_eq!(
            parsed.poll.get("cpu").unwrap().oid(),
            "1.3.6.1.4.1.9.9.109.1.1.1.1.3.1"
        );
        assert_eq!(parsed.poll.get("cpu").unwrap().interval_secs(), Some(10));
    }

    #[test]
    fn metric_spec_calendar_schedule_deserializes_and_has_no_interval() {
        // Direct user request 2026-08-16: a metric can be polled on a calendar schedule
        // instead of a running interval — same shape `Schedule::Calendar` uses elsewhere
        // (discovery configs), nested under this metric's own `schedule` field.
        let json = r#"{"oid": "1.3.6.1.2.1.1.3.0", "schedule": {"months": [1,6], "days_of_month": [], "time": "03:00:00"}}"#;
        let parsed: MetricSpec = serde_json::from_str(json).expect("should deserialize");
        assert_eq!(
            parsed.interval_secs(),
            None,
            "a calendar schedule has no fixed interval"
        );
        assert!(matches!(parsed.schedule(), Some(Schedule::Calendar { .. })));
    }

    #[test]
    fn metric_spec_enabled_defaults_to_true_for_both_forms() {
        // Direct user request 2026-08-16: a profile can declare a metric disabled by
        // default. The plain-string form has no way to say that — it must always mean
        // enabled — and a `Detailed` entry that never sets `enabled` must default to the
        // same thing, so this feature can't silently flip existing profiles' behavior.
        let plain: MetricSpec = serde_json::from_str(r#""1.2.3""#).unwrap();
        assert!(plain.enabled());

        let detailed_no_enabled: MetricSpec = serde_json::from_str(r#"{"oid": "1.2.3"}"#).unwrap();
        assert!(
            detailed_no_enabled.enabled(),
            "omitting `enabled` must default to true, not silently disable existing profiles"
        );

        let explicitly_disabled: MetricSpec =
            serde_json::from_str(r#"{"oid": "1.2.3", "enabled": false}"#).unwrap();
        assert!(!explicitly_disabled.enabled());
    }

    #[test]
    fn compute_version_changes_when_only_the_enabled_default_changes() {
        // Same behavioral-edit reasoning as interval/schedule/retention above — a profile
        // author flipping a metric's default on/off state must force affected devices
        // (the ones with no device-level override) to pick it up promptly.
        let mut on = BTreeMap::new();
        on.insert(
            "cpu".to_string(),
            MetricSpec::Detailed {
                columns: None,
                oid: "1.2.3".to_string(),
                schedule: None,
                history_retention_secs: None,
                enabled: true,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
                derive: None,
            },
        );

        let mut off = BTreeMap::new();
        off.insert(
            "cpu".to_string(),
            MetricSpec::Detailed {
                columns: None,
                oid: "1.2.3".to_string(),
                schedule: None,
                history_retention_secs: None,
                enabled: false,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
                derive: None,
            },
        );

        assert_ne!(
            compute_version(
                "true",
                &on,
                &TrapsSection::default(),
                &SyslogSection::default(),
                &ServiceChecksSection::default(),
                &[]
            ),
            compute_version(
                "true",
                &off,
                &TrapsSection::default(),
                &SyslogSection::default(),
                &ServiceChecksSection::default(),
                &[]
            )
        );
    }

    /// Direct user request 2026-08-16: "Мне нужно хранить всегда крайнюю удачную и самую
    /// крайнюю... Добавь флаги сохранять ли крайнюю удачную запись или нет и сохранять ли
    /// просто крайнюю запись." Both default `true` without an explicit value — must not
    /// silently start dropping history on existing profiles the moment this feature ships.
    /// SSH CLI-pull (2026-09-07) — `command` is the field that disambiguates this variant
    /// from `Detailed` in the untagged encoding; a plain `{"command": "..."}` object with
    /// no `oid` must deserialize as `SshCommand`, not fail or get mistaken for `Detailed`.
    #[test]
    fn ssh_command_deserializes_and_is_distinct_from_oid_and_table() {
        let spec: MetricSpec =
            serde_json::from_str(r#"{"command": "show running-config"}"#).unwrap();
        assert!(spec.is_ssh_command());
        assert_eq!(spec.command(), Some("show running-config"));
        assert_eq!(spec.oid(), "", "an SSH-command metric has no OID");
        assert!(
            !spec.is_table(),
            "an SSH-command metric is always a scalar, never table-shaped"
        );
        assert_eq!(spec.columns(), None);
    }

    /// An existing `Oid`/`Detailed` profile must keep deserializing exactly as before —
    /// adding the third untagged variant must not perturb the first two's matching.
    #[test]
    fn existing_oid_and_detailed_forms_still_deserialize_unchanged_after_adding_ssh_command() {
        let plain: MetricSpec = serde_json::from_str(r#""1.2.3""#).unwrap();
        assert!(!plain.is_ssh_command());
        assert_eq!(plain.command(), None);
        assert_eq!(plain.oid(), "1.2.3");

        let detailed: MetricSpec =
            serde_json::from_str(r#"{"oid": "1.2.3", "columns": {"a": "1"}}"#).unwrap();
        assert!(!detailed.is_ssh_command());
        assert_eq!(detailed.command(), None);
        assert!(detailed.is_table());
    }

    #[test]
    fn ssh_command_enabled_and_history_flags_default_the_same_as_detailed() {
        let bare: MetricSpec = serde_json::from_str(r#"{"command": "show version"}"#).unwrap();
        assert!(bare.enabled());
        assert!(bare.history_keep_last_success());
        assert!(bare.history_keep_last_attempt());
        assert_eq!(bare.history_retention_secs(), None);
        assert_eq!(bare.interval_secs(), None);

        let explicit: MetricSpec = serde_json::from_str(
            r#"{"command": "show version", "enabled": false, "history_keep_last_success": false, "history_keep_last_attempt": false, "history_retention_secs": 86400}"#,
        )
        .unwrap();
        assert!(!explicit.enabled());
        assert!(!explicit.history_keep_last_success());
        assert!(!explicit.history_keep_last_attempt());
        assert_eq!(explicit.history_retention_secs(), Some(86400));
    }

    #[test]
    fn ssh_command_with_a_calendar_schedule_deserializes_and_has_no_interval() {
        let json = r#"{"command": "show running-config", "schedule": {"months": [], "days_of_month": [1], "time": "03:00:00"}}"#;
        let spec: MetricSpec = serde_json::from_str(json).unwrap();
        assert_eq!(
            spec.interval_secs(),
            None,
            "a calendar schedule has no fixed interval"
        );
        assert!(matches!(spec.schedule(), Some(Schedule::Calendar { .. })));
    }

    /// `compute_version` must be sensitive to an SSH-command metric's `command` text — a
    /// profile edited only in the CLI command a metric runs still needs to bump `version`
    /// so a device already on this profile restarts its poll chain and picks up the edit
    /// on the very next tick, same reasoning `version_changes_when_columns_change`
    /// established for SNMP table columns.
    #[test]
    fn compute_version_changes_when_an_ssh_command_metric_changes() {
        let mut a = BTreeMap::new();
        a.insert(
            "running_config".to_string(),
            MetricSpec::SshCommand {
                command: "show running-config".to_string(),
                schedule: None,
                history_retention_secs: None,
                enabled: true,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
            },
        );

        let mut b = BTreeMap::new();
        b.insert(
            "running_config".to_string(),
            MetricSpec::SshCommand {
                command: "show running-config all".to_string(),
                schedule: None,
                history_retention_secs: None,
                enabled: true,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
            },
        );

        assert_ne!(
            compute_version(
                "true",
                &a,
                &TrapsSection::default(),
                &SyslogSection::default(),
                &ServiceChecksSection::default(),
                &[]
            ),
            compute_version(
                "true",
                &b,
                &TrapsSection::default(),
                &SyslogSection::default(),
                &ServiceChecksSection::default(),
                &[]
            ),
            "editing an SSH-command metric's command text must bump the profile version"
        );
    }

    /// Adding `MetricSpec::SshCommand` support to `compute_version` must not change the
    /// version an SNMP-only profile computes relative to what it computed before this
    /// variant existed — `command()` returns `None` uniformly for `Oid`/`Detailed`, which
    /// hashes identically to "this hash input doesn't exist" would have.
    #[test]
    fn compute_version_of_an_snmp_only_profile_is_unaffected_by_ssh_command_support_existing() {
        let mut poll = BTreeMap::new();
        poll.insert(
            "uptime".to_string(),
            MetricSpec::Oid("1.3.6.1.2.1.1.3.0".to_string()),
        );
        let v1 = compute_version(
            "true",
            &poll,
            &TrapsSection::default(),
            &SyslogSection::default(),
            &ServiceChecksSection::default(),
            &[],
        );
        let v2 = compute_version(
            "true",
            &poll,
            &TrapsSection::default(),
            &SyslogSection::default(),
            &ServiceChecksSection::default(),
            &[],
        );
        assert_eq!(
            v1, v2,
            "must remain a pure, deterministic function of content"
        );
    }

    #[test]
    fn history_keep_flags_default_to_true_for_both_forms() {
        let plain: MetricSpec = serde_json::from_str(r#""1.2.3""#).unwrap();
        assert!(plain.history_keep_last_success());
        assert!(plain.history_keep_last_attempt());

        let detailed_no_flags: MetricSpec = serde_json::from_str(r#"{"oid": "1.2.3"}"#).unwrap();
        assert!(
            detailed_no_flags.history_keep_last_success(),
            "omitting the flag must default to true"
        );
        assert!(
            detailed_no_flags.history_keep_last_attempt(),
            "omitting the flag must default to true"
        );

        let explicitly_off: MetricSpec = serde_json::from_str(r#"{"oid": "1.2.3", "history_keep_last_success": false, "history_keep_last_attempt": false}"#).unwrap();
        assert!(!explicitly_off.history_keep_last_success());
        assert!(!explicitly_off.history_keep_last_attempt());
    }

    #[test]
    fn compute_version_changes_when_either_history_keep_flag_changes() {
        fn spec(keep_success: bool, keep_attempt: bool) -> MetricSpec {
            MetricSpec::Detailed {
                oid: "1.2.3".to_string(),
                columns: None,
                schedule: None,
                history_retention_secs: Some(86400),
                enabled: true,
                history_keep_last_success: keep_success,
                history_keep_last_attempt: keep_attempt,
                derive: None,
            }
        }

        let mut default_flags = BTreeMap::new();
        default_flags.insert("cpu".to_string(), spec(true, true));

        let mut success_off = BTreeMap::new();
        success_off.insert("cpu".to_string(), spec(false, true));
        assert_ne!(
            compute_version(
                "true",
                &default_flags,
                &TrapsSection::default(),
                &SyslogSection::default(),
                &ServiceChecksSection::default(),
                &[]
            ),
            compute_version(
                "true",
                &success_off,
                &TrapsSection::default(),
                &SyslogSection::default(),
                &ServiceChecksSection::default(),
                &[]
            ),
            "toggling history_keep_last_success must bump the version"
        );

        let mut attempt_off = BTreeMap::new();
        attempt_off.insert("cpu".to_string(), spec(true, false));
        assert_ne!(
            compute_version(
                "true",
                &default_flags,
                &TrapsSection::default(),
                &SyslogSection::default(),
                &ServiceChecksSection::default(),
                &[]
            ),
            compute_version(
                "true",
                &attempt_off,
                &TrapsSection::default(),
                &SyslogSection::default(),
                &ServiceChecksSection::default(),
                &[]
            ),
            "toggling history_keep_last_attempt must bump the version"
        );
    }
}

#[cfg(test)]
mod service_checks_tests {
    use super::*;

    fn a_check(name: &str) -> ServiceCheckSpec {
        ServiceCheckSpec {
            name: name.to_string(),
            protocol: ServiceCheckProtocol::Tcp,
            target: None,
            port: 22,
            path: None,
            expected_status: None,
            body_contains: None,
            timeout_ms: None,
            enabled: true,
        }
    }

    #[test]
    fn validate_rejects_a_blank_name() {
        let section = ServiceChecksSection {
            checks: vec![ServiceCheckSpec {
                name: "  ".to_string(),
                ..a_check("x")
            }],
            schedule: None,
            history_retention_secs: None,
        };
        let err = section
            .validate()
            .expect_err("a blank name can never be a usable row key");
        assert!(err.contains("name must not be empty"));
    }

    #[test]
    fn validate_rejects_duplicate_names() {
        let section = ServiceChecksSection {
            checks: vec![a_check("ssh"), a_check("ssh")],
            schedule: None,
            history_retention_secs: None,
        };
        let err = section
            .validate()
            .expect_err("two checks with the same name would silently overwrite the same row");
        assert!(err.contains("duplicate"));
        assert!(err.contains("ssh"));
    }

    #[test]
    fn validate_rejects_a_zero_timeout() {
        let section = ServiceChecksSection {
            checks: vec![ServiceCheckSpec {
                timeout_ms: Some(0),
                ..a_check("ssh")
            }],
            schedule: None,
            history_retention_secs: None,
        };
        let err = section
            .validate()
            .expect_err("a zero timeout can never succeed");
        assert!(err.contains("timeout_ms"));
    }

    #[test]
    fn validate_accepts_a_well_formed_list() {
        let section = ServiceChecksSection {
            checks: vec![
                a_check("ssh"),
                ServiceCheckSpec {
                    name: "web".to_string(),
                    protocol: ServiceCheckProtocol::Https,
                    port: 443,
                    path: Some("/health".to_string()),
                    expected_status: Some(200),
                    body_contains: Some("ok".to_string()),
                    ..a_check("web")
                },
            ],
            schedule: None,
            history_retention_secs: None,
        };
        section
            .validate()
            .expect("two distinct, non-blank names must be accepted");
    }

    #[test]
    fn path_or_default_falls_back_to_root() {
        assert_eq!(a_check("x").path_or_default(), "/");
        let with_path = ServiceCheckSpec {
            path: Some("/health".to_string()),
            ..a_check("x")
        };
        assert_eq!(with_path.path_or_default(), "/health");
        let empty_path = ServiceCheckSpec {
            path: Some("".to_string()),
            ..a_check("x")
        };
        assert_eq!(
            empty_path.path_or_default(),
            "/",
            "an explicitly empty path must fall back to root, same as absent"
        );
    }

    #[test]
    fn protocol_round_trips_as_lowercase_json() {
        let spec: ServiceCheckSpec =
            serde_json::from_str(r#"{"name":"ssh","protocol":"ssh","port":22}"#).unwrap();
        assert_eq!(spec.protocol, ServiceCheckProtocol::Ssh);
        assert!(spec.enabled, "omitting enabled must default to true");
        let json = serde_json::to_string(&spec).unwrap();
        assert!(json.contains("\"ssh\""));
    }

    #[test]
    fn compute_version_changes_when_service_checks_change() {
        let empty = ServiceChecksSection::default();
        let with_check = ServiceChecksSection {
            checks: vec![a_check("ssh")],
            schedule: None,
            history_retention_secs: None,
        };

        let v1 = compute_version(
            "true",
            &BTreeMap::new(),
            &TrapsSection::default(),
            &SyslogSection::default(),
            &empty,
            &[],
        );
        let v2 = compute_version(
            "true",
            &BTreeMap::new(),
            &TrapsSection::default(),
            &SyslogSection::default(),
            &with_check,
            &[],
        );
        assert_ne!(v1, v2, "a profile edited only in its service_checks section must still bump version so ProfileApply picks it up");
    }

    #[test]
    fn compute_version_changes_when_only_the_schedule_changes() {
        let a = ServiceChecksSection {
            checks: vec![a_check("ssh")],
            schedule: Some(Schedule::Periodic { interval_secs: 30 }),
            history_retention_secs: None,
        };
        let b = ServiceChecksSection {
            checks: vec![a_check("ssh")],
            schedule: Some(Schedule::Periodic { interval_secs: 60 }),
            history_retention_secs: None,
        };

        let v1 = compute_version(
            "true",
            &BTreeMap::new(),
            &TrapsSection::default(),
            &SyslogSection::default(),
            &a,
            &[],
        );
        let v2 = compute_version(
            "true",
            &BTreeMap::new(),
            &TrapsSection::default(),
            &SyslogSection::default(),
            &b,
            &[],
        );
        assert_ne!(
            v1, v2,
            "a cadence-only edit is behavioral, same reasoning as MetricSpec's own schedule"
        );
    }

    /// `ProfileFile`'s `Deserialize` must accept a real `service_checks` payload — the
    /// shape `POST /api/profiles` actually receives.
    #[test]
    fn deserializes_a_profile_with_service_checks() {
        let json = r#"{
            "profile": {"name": "switch", "priority": 0},
            "match": {"expression": "true"},
            "service_checks": {
                "checks": [
                    {"name": "ssh", "protocol": "ssh", "port": 22},
                    {"name": "web", "protocol": "https", "port": 443, "path": "/health", "expected_status": 200, "body_contains": "ok", "timeout_ms": 3000}
                ],
                "schedule": {"interval_secs": 30}
            }
        }"#;
        let parsed: ProfileFile = serde_json::from_str(json).expect("should deserialize");
        assert_eq!(parsed.service_checks.checks.len(), 2);
        assert_eq!(parsed.service_checks.checks[0].name, "ssh");
        assert_eq!(parsed.service_checks.checks[1].expected_status, Some(200));
        assert!(matches!(
            parsed.service_checks.schedule,
            Some(Schedule::Periodic { interval_secs: 30 })
        ));
    }

    /// A profile with no `service_checks` key at all (every existing profile, before this
    /// field existed) must still deserialize — same additive-field contract `traps`/
    /// `syslog` established.
    #[test]
    fn missing_service_checks_section_defaults_to_empty() {
        let json = r#"{
            "profile": {"name": "legacy", "priority": 0},
            "match": {"expression": "true"}
        }"#;
        let parsed: ProfileFile = serde_json::from_str(json).expect("should deserialize");
        assert!(parsed.service_checks.checks.is_empty());
        assert!(parsed.service_checks.schedule.is_none());
    }

    /// Derived rate/delta metrics (2026-09-07) — `derive` must default to `None` for both
    /// the plain-string shorthand and a `Detailed` entry that never set it, same "opt-in,
    /// zero behavioral change for existing profiles" contract as every other field added to
    /// `Detailed` after it first shipped.
    #[test]
    fn derive_defaults_to_none_for_both_forms() {
        let plain: MetricSpec = serde_json::from_str(r#""1.2.3""#).unwrap();
        assert_eq!(plain.derive(), None);

        let detailed_no_derive: MetricSpec = serde_json::from_str(r#"{"oid": "1.2.3"}"#).unwrap();
        assert_eq!(detailed_no_derive.derive(), None);
    }

    #[test]
    fn derive_parses_rate_and_delta_from_json() {
        let rate: MetricSpec =
            serde_json::from_str(r#"{"oid": "1.2.3", "derive": "rate"}"#).unwrap();
        assert_eq!(rate.derive(), Some(DeriveKind::Rate));

        let delta: MetricSpec =
            serde_json::from_str(r#"{"oid": "1.2.3", "derive": "delta"}"#).unwrap();
        assert_eq!(delta.derive(), Some(DeriveKind::Delta));
    }

    #[test]
    fn compute_version_changes_when_derive_changes() {
        // Same behavioral-edit reasoning as every other flag above — a device already
        // polling this metric needs its MetricPoll chain restarted to start (or stop)
        // computing the derived value.
        let mut none = BTreeMap::new();
        none.insert(
            "ifInOctets".to_string(),
            MetricSpec::Detailed {
                columns: None,
                oid: "1.2.3".to_string(),
                schedule: None,
                history_retention_secs: None,
                enabled: true,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
                derive: None,
            },
        );

        let mut rate = BTreeMap::new();
        rate.insert(
            "ifInOctets".to_string(),
            MetricSpec::Detailed {
                columns: None,
                oid: "1.2.3".to_string(),
                schedule: None,
                history_retention_secs: None,
                enabled: true,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
                derive: Some(DeriveKind::Rate),
            },
        );

        let mut delta = BTreeMap::new();
        delta.insert(
            "ifInOctets".to_string(),
            MetricSpec::Detailed {
                columns: None,
                oid: "1.2.3".to_string(),
                schedule: None,
                history_retention_secs: None,
                enabled: true,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
                derive: Some(DeriveKind::Delta),
            },
        );

        let v_none = compute_version(
            "true",
            &none,
            &TrapsSection::default(),
            &SyslogSection::default(),
            &ServiceChecksSection::default(),
            &[],
        );
        let v_rate = compute_version(
            "true",
            &rate,
            &TrapsSection::default(),
            &SyslogSection::default(),
            &ServiceChecksSection::default(),
            &[],
        );
        let v_delta = compute_version(
            "true",
            &delta,
            &TrapsSection::default(),
            &SyslogSection::default(),
            &ServiceChecksSection::default(),
            &[],
        );
        assert_ne!(v_none, v_rate, "turning on derive must bump the version");
        assert_ne!(
            v_rate, v_delta,
            "switching rate <-> delta must bump the version too"
        );
    }

    /// See `MetricsSection::validate`'s docs — this is the save-time guard against a
    /// `derive`d metric silently fighting another declared metric for the same storage
    /// slot.
    #[test]
    fn metrics_section_validate_rejects_a_name_collision_with_a_derived_metric() {
        let mut poll = BTreeMap::new();
        poll.insert(
            "ifInOctets".to_string(),
            MetricSpec::Detailed {
                columns: None,
                oid: "1.2.3".to_string(),
                schedule: None,
                history_retention_secs: None,
                enabled: true,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
                derive: Some(DeriveKind::Rate),
            },
        );
        // A second, unrelated metric that just happens to already be named exactly what
        // `derive` on the first one would compute.
        poll.insert(
            "ifInOctets_rate".to_string(),
            MetricSpec::Oid("9.9.9".to_string()),
        );

        let section = MetricsSection { poll };
        let err = section.validate().expect_err("a manually-declared metric colliding with a derived name must be rejected at save time");
        assert!(err.contains("ifInOctets"));
        assert!(err.contains("ifInOctets_rate"));
    }

    #[test]
    fn metrics_section_validate_accepts_a_profile_with_no_collisions() {
        let mut poll = BTreeMap::new();
        poll.insert(
            "ifInOctets".to_string(),
            MetricSpec::Detailed {
                columns: None,
                oid: "1.2.3".to_string(),
                schedule: None,
                history_retention_secs: None,
                enabled: true,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
                derive: Some(DeriveKind::Rate),
            },
        );
        poll.insert(
            "uptime".to_string(),
            MetricSpec::Oid("1.3.6.1.2.1.1.3.0".to_string()),
        );

        MetricsSection { poll }
            .validate()
            .expect("no collision here — must be accepted");
    }
}
