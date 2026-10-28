use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{Local, Timelike};
use dashmap::DashMap;
use discovery_config_store::{DiscoveryConfigStore, DiscoveryOidSpec, SettingsStore};
use discovery_core::payload::{
    AlertEvalPayload, DedupPayload, DiscoveryPayload, MetricPollPayload,
    NotificationDispatchPayload, ProfileApplyPayload, ReachabilityPollPayload,
    ServiceCheckPollPayload, SnmpPollPayload, TopologyRecomputePayload,
};
use discovery_core::{
    default_snmp_retries, default_snmp_timeout_ms, ActiveChains, Alert, AlertHysteresisConfig,
    AlertLevel, AlertTransition, Device, DeviceFacts, DeviceTarget, Job, MetricPollOutcome,
    MetricRecord, MetricTableRow, MetricValue, Metrics, NotificationTrigger, QueueKind, Schedule,
    SshTarget,
};
use discovery_devices::{DeviceMetricsStore, DeviceStore, ProfileDecision};
use discovery_dsl::{
    compute_derived, derived_metric_name, stale_metric_names, topology::referenced_metrics,
    AlertEvaluator, AlertRule, MetricSpec, ProfileMatcher,
};
use discovery_queue::{JobHandler, JobQueueStore};
use discovery_snmp::{poll_table_metric, snmp_value_to_metric, SnmpClient};
use tracing::{info, warn};

use crate::discovery_scan::{find_subnet_spec_for_ip, negotiate_snmp_credentials};
use crate::group_alert::GroupAlertCorrelator;

/// Adds up to +10% random jitter to a recurring chain's reschedule delay — found on the
/// 2026-08-21 scale audit: `SnmpPollHandler`/`MetricPollHandler`/`ReachabilityPollHandler`
/// all self-reschedule via a plain `tokio::time::sleep(interval)`, so a batch of devices
/// that all started their chain around the same moment (a large subnet scan, or a cold
/// restart with an already-large device inventory) stays in lockstep forever — every one
/// of them lands back in its queue within the same instant on every cycle, not spread out.
/// Applied on *every* reschedule, not just the first, so the spread compounds instead of
/// resyncing back to lockstep. `rand::thread_rng()` per call (not a shared `Rng`) — these
/// closures run on independent spawned tasks, contending over one `Rng` would be its own
/// small bottleneck for no benefit here.
fn jittered(interval: Duration) -> Duration {
    use rand::Rng;
    let jitter_ms = rand::thread_rng().gen_range(0..=(interval.as_millis() / 10).max(1) as u64);
    interval + Duration::from_millis(jitter_ms)
}

/// Stage 1: a candidate IP arrives (from a subnet scan or a seed list — possibly the
/// *same* IP many times over, once per scan cycle, since a scan re-enqueues every address
/// in its configured ranges every time).
///
/// **Cheap reachability gate before anything else (added 2026-08-18, direct user
/// request):** unless the matching subnet opts in via `SubnetSpec::create_dead_devices`
/// (default `false`), a candidate that doesn't answer ICMP within `PingConfig.timeout_ms`
/// (`1 + PingConfig.retries` attempts, read fresh from `SettingsStore` on every candidate —
/// same live-editable convention as `snmp_timeout_ms`/`snmp_retries` below) never
/// gets a `Device` row or a permanent recurring `SnmpPoll` chain at all — a subnet scan
/// used to unconditionally turn *every* candidate address into a `Device`, live or not
/// (a `10.0.0.0/24` sweep with 3 real hosts created 251 devices that would never answer
/// anything, each with its own forever-recurring identity/metric-poll chain, real load
/// found live: "снмп воркер не справляется" — see `discovery/CLAUDE.md`).
///
/// Checked **before** `identity_chains.mark`, not after — marking first would mean a
/// skipped IP is permanently blocked from ever being reconsidered by this process again;
/// checked first, a dead candidate this cycle is simply not marked at all, so the *next*
/// discovery run (not an internal retry — a real device that later shows up on this IP
/// gets picked up the next time a scan enqueues it, exactly the "следующий дискаверинг
/// его создаст" behavior asked for) re-pings it fresh. `identity_chains.contains` (a
/// non-mutating peek) is checked first as a fast path — an IP that already has an active
/// chain skips the ping entirely, same cost as before this gate existed.
pub struct DiscoveryHandler {
    pub store: Arc<dyn JobQueueStore>,
    /// Gates "start a new recurring `SnmpPoll` chain for this IP" to at most once per IP
    /// per process — see `ActiveChains`'s docs. Without this, a continuous subnet scan
    /// re-discovering an already-known IP every cycle would leak a fresh, permanently
    /// self-perpetuating identity-poll chain each time.
    pub identity_chains: Arc<ActiveChains<String>>,
    /// Looked up fresh every candidate (by IP) purely for `create_dead_devices` — same
    /// "read the subnet config fresh, not cached" convention `SnmpPollHandler`/
    /// `MetricPollHandler` already use for `snmp_timeout_ms`/`snmp_retries`.
    pub discovery_configs: Arc<dyn DiscoveryConfigStore>,
    pub pinger: Arc<dyn discovery_ping::Pinger>,
    /// `ping_config()` (timeout/retries), read fresh right before each candidate's gate
    /// check — same "no caching, dashboard edit applies on the very next use" convention as
    /// `discovery_configs` above.
    pub settings: Arc<dyn SettingsStore>,
}

#[async_trait]
impl JobHandler for DiscoveryHandler {
    async fn handle(&self, job: Job) -> anyhow::Result<()> {
        let payload: DiscoveryPayload = serde_json::from_value(job.payload)?;

        if self.identity_chains.contains(&payload.ip) {
            return Ok(()); // already has an active identity-poll chain — nothing to do
        }

        let configs = self.discovery_configs.load_all().await.unwrap_or_default();
        // No matching subnet (e.g. a manually seeded IP outside any configured range) —
        // there's no policy to consult, so this candidate is unaffected by the gate,
        // exactly like before it existed.
        let create_dead_devices = find_subnet_spec_for_ip(&configs, &payload.ip)
            .map(|s| s.create_dead_devices)
            .unwrap_or(true);
        if !create_dead_devices {
            let ping_config = self.settings.ping_config().await;
            let outcome = self
                .pinger
                .ping(
                    &payload.ip,
                    Duration::from_millis(ping_config.timeout_ms),
                    ping_config.retries,
                )
                .await;
            if !outcome.reachable {
                info!(ip = %payload.ip, "discovery: candidate did not answer ping — skipping, not creating a device (create_dead_devices=false)");
                return Ok(());
            }
        }

        if !self.identity_chains.mark(payload.ip.clone()) {
            return Ok(()); // lost a race with another concurrent Discovery job for the same IP
        }

        self.store
            .enqueue(
                QueueKind::SnmpPoll,
                serde_json::to_value(SnmpPollPayload {
                    ip: payload.ip.clone(),
                    recurring: true,
                })?,
                Some(&payload.ip),
            )
            .await?;
        Ok(())
    }
}

/// Stage 2: recurring SNMP identity probe. **No hardcoded OID fetch of its own** as of
/// 2026-08-16 (direct user request — see `discovery_core::DeviceFacts`'s docs for why): if
/// this IP falls inside a configured subnet, fetches that subnet's `oids`/`labels` — but
/// only on this device's very first-ever cycle, never again afterwards (see the `extra`
/// block in `handle` below — discovery-time OIDs are one-shot, not recurring monitoring
/// data; anything that should be re-polled belongs in the profile's `[metrics.poll]`
/// instead). On every *later* recurring cycle this handler does no SNMP I/O at all — it
/// just hands the device's IP through to `Dedup`, which re-evaluates dedup/profile
/// matching against whatever's *currently* in the device's `Metrics` bag (which may have
/// moved on since, if a profile is regularly re-polling the relevant field). Which device
/// this is (new or already-known) is not this handler's call to make. **Does not fetch
/// dedup fields either** — `DedupHandler` below is identity resolution by IP only for now
/// (see its docs).
///
/// Also where SNMP credentials get negotiated: if the device has none on record yet, tries
/// every (version, community) candidate from the matching subnet (see
/// `discovery_scan::negotiate_snmp_credentials`) until one answers, then hands the result
/// to `Dedup` to persist (`DedupPayload::snmp_credentials`) — every later poll (including
/// this chain's own next tick) reuses whatever's on record instead of re-negotiating.
///
/// Recurring on purpose: even though this handler itself no longer re-fetches anything for
/// an already-known device, re-running dedup/match on a schedule still matters — a
/// profile-refreshed metric that happens to share a name with an identity-relevant field
/// (see `discovery_core::DeviceFacts`'s docs) can change what profile a device *should*
/// match without anyone manually re-running discovery. Only re-enqueues itself when
/// `payload.recurring` — see [`discovery_core::payload::SnmpPollPayload`]'s docs for why
/// that flag exists (it's what lets `profile_reload`'s one-off "re-check this device now"
/// nudge share this same handler without leaking a second permanent chain).
pub struct SnmpPollHandler {
    pub store: Arc<dyn JobQueueStore>,
    pub snmp: Arc<dyn SnmpClient>,
    pub devices: Arc<dyn DeviceStore>,
    pub discovery_configs: Arc<dyn DiscoveryConfigStore>,
    /// `poll_intervals.identity_secs`, read fresh (not cached) right before each
    /// self-reschedule — direct user request 2026-08-16: settings live in the database and
    /// an edit must apply without a restart, see `SettingsStore`'s docs.
    pub settings: Arc<dyn SettingsStore>,
}

#[async_trait]
impl JobHandler for SnmpPollHandler {
    async fn handle(&self, job: Job) -> anyhow::Result<()> {
        let manual = job.payload.get("manual").and_then(|v| v.as_bool()) == Some(true);
        let payload: SnmpPollPayload = serde_json::from_value(job.payload)?;

        let configs = self.discovery_configs.load_all().await.unwrap_or_else(|e| {
            warn!(error = %e, "failed to load discovery configs — proceeding without subnet-specific credentials/enrichment OIDs");
            Vec::new()
        });
        let subnet_spec = find_subnet_spec_for_ip(&configs, &payload.ip);

        // Whether this device already exists is also the gate for "have we already
        // fetched this subnet's enrichment OIDs once" (see the `extra` block below) — a
        // brand-new IP means both "negotiate credentials" and "fetch subnet.oids" are
        // still to do; an already-known IP means neither is, regardless of `recurring`.
        let existing_device_id = self.devices.id_by_ip(&payload.ip).await?;
        let existing_credentials = match existing_device_id {
            Some(id) => self
                .devices
                .get_device(id)
                .await?
                .and_then(|d| d.snmp_credentials),
            None => None,
        };

        // Timeout/retries always come from whichever subnet the IP currently belongs to
        // (not frozen at negotiation time like the port/auth are) — a config
        // edit to `snmp_timeout_ms`/`snmp_retries` takes effect on the very next identity
        // cycle, same as any other subnet-config change.
        let timeout_ms = subnet_spec
            .as_ref()
            .and_then(|s| s.snmp_timeout_ms)
            .unwrap_or_else(default_snmp_timeout_ms);
        let retries = subnet_spec
            .as_ref()
            .and_then(|s| s.snmp_retries)
            .unwrap_or_else(default_snmp_retries);

        let (target, newly_negotiated_credentials) = match existing_credentials {
            Some(creds) => (
                DeviceTarget {
                    ip: payload.ip.clone(),
                    port: creds.port,
                    auth: creds.auth,
                    timeout_ms,
                    retries,
                },
                None,
            ),
            None => match negotiate_snmp_credentials(&self.snmp, &payload.ip, &configs).await {
                Some((target, creds)) => (target, Some(creds)),
                // No configured subnet matched, or none of its candidates answered — fall
                // back to the same single default this handler always used before subnet
                // configs existed (keeps demo mode and never-configured IPs unaffected).
                None => (
                    DeviceTarget {
                        ip: payload.ip.clone(),
                        timeout_ms,
                        retries,
                        ..Default::default()
                    },
                    None,
                ),
            },
        };

        // No hardcoded sys_descr/sys_object_id/sys_name fetch here anymore (2026-08-16,
        // direct user request) — `ip` is the only genuinely universal fact. Anything
        // identity-relevant is an ordinary named entry in `subnet.oids` (below), fetched
        // once, same as any other discovery-time enrichment data — a given deployment
        // isn't obligated to configure exactly those three names, or any at all.
        let facts = DeviceFacts {
            ip: payload.ip.clone(),
        };

        // Discovery-time enrichment OIDs are fetched exactly once — only on a device's
        // very first-ever identity cycle (`existing_device_id.is_none()`), never again on
        // subsequent recurring cycles. Direct user requirement: "метрики из дискаверинга
        // опрашиваем один раз и не переопрашиваем" — anything that should be re-polled
        // belongs in the profile's `[metrics.poll]` instead, with its own cadence (see
        // `MetricPollHandler`). `None` here tells `DedupHandler` there is nothing new this
        // cycle to record — leave whatever's already on record untouched, not overwrite it
        // with `{}`.
        //
        // **Changed 2026-08-16 (direct user request — metric change history):** a failed
        // fetch is recorded too (`MetricPollOutcome::Err`), not just logged and dropped —
        // there's no retry for one-shot fields by design, so this `Err` is permanent unless
        // a future identity cycle for a *different* IP happens to carry the same field
        // again.
        let extra: Option<BTreeMap<String, MetricPollOutcome>> = if existing_device_id.is_none()
            || manual
        {
            let mut extra: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
            if let Some(subnet) = &subnet_spec {
                // Table-shaped entries (`spec.is_table()` — a `DiscoveryOidSpec` declaring
                // `columns`, see its docs) split off here, same reasoning as
                // `MetricPollHandler`'s `scalar_due`/`table_due` split: `walk()` is a
                // different SNMP primitive from a batched `GetRequest`, so a table entry
                // can never join the scalar `get_multi` batch below.
                let (table_entries, scalar_entries): (
                    Vec<(&String, &DiscoveryOidSpec)>,
                    Vec<(&String, &DiscoveryOidSpec)>,
                ) = subnet.oids.iter().partition(|(_, spec)| spec.is_table());

                // Batched (2026-08-18, direct user request — SNMP batching, same reasoning
                // as `MetricPollHandler`'s due-metrics fetch): one packet for every scalar
                // `subnet.oids` entry instead of one sequential `get()` per name. Built from
                // one `.iter()` pass (not separate `.keys()`/`.values()` calls) so a name
                // can never end up paired with the wrong OID's result.
                let oids: Vec<String> = scalar_entries
                    .iter()
                    .map(|(_, spec)| spec.oid().to_string())
                    .collect();
                let results = self.snmp.get_multi(&target, &oids).await;
                for ((name, _), result) in scalar_entries.into_iter().zip(results) {
                    match result {
                        Ok(value) => {
                            extra.insert(
                                name.clone(),
                                MetricPollOutcome::Ok(snmp_value_to_metric(&value)),
                            );
                        }
                        Err(e) => {
                            warn!(ip = %payload.ip, field = %name, error = %e, "subnet enrichment OID fetch failed");
                            extra.insert(name.clone(), MetricPollOutcome::Err(e.to_string()));
                        }
                    }
                }

                // Sequential — same "table entries are the uncommon case, keep it simple"
                // reasoning as `MetricPollHandler`'s table-metric loop.
                for (name, spec) in table_entries {
                    let columns = spec.columns().expect("table_entries filtered by is_table() above, which is exactly columns().is_some()");
                    match poll_table_metric(self.snmp.as_ref(), &target, spec.oid(), columns).await
                    {
                        Ok(rows) => {
                            extra.insert(
                                name.clone(),
                                MetricPollOutcome::Ok(MetricValue::Table(rows)),
                            );
                        }
                        Err(e) => {
                            warn!(ip = %payload.ip, field = %name, error = %e, "subnet enrichment table OID fetch failed");
                            extra.insert(name.clone(), MetricPollOutcome::Err(e.to_string()));
                        }
                    }
                }

                // Labels: same one-shot gate/bag as `oids` above, but no SNMP round trip —
                // these are constant values declared directly in the subnet config (e.g.
                // `area_name = "Воронеж"`), written verbatim, always a success. Direct user
                // request 2026-08-16: "вместо единоразового опроса и записью метрики — эти
                // метрики просто сразу запишутся такие, какие мы укажем".
                for (name, value) in &subnet.labels {
                    extra.insert(
                        name.clone(),
                        MetricPollOutcome::Ok(MetricValue::Str(value.clone())),
                    );
                }
            }
            Some(extra)
        } else {
            None
        };

        self.store
            .enqueue(
                QueueKind::Dedup,
                serde_json::to_value(DedupPayload {
                    ip: payload.ip.clone(),
                    facts,
                    extra,
                    snmp_credentials: newly_negotiated_credentials,
                })?,
                None, // each identity re-check is a fresh event, not something to collapse
            )
            .await?;

        if payload.recurring {
            // Schedule the next identity re-check for this IP, carrying `recurring`
            // forward so the chain keeps going.
            let store = self.store.clone();
            let ip = payload.ip.clone();
            let settings = self.settings.clone();
            tokio::spawn(async move {
                let poll_interval =
                    Duration::from_secs(settings.poll_intervals().await.identity_secs);
                tokio::time::sleep(jittered(poll_interval)).await;
                if let Ok(payload) = serde_json::to_value(SnmpPollPayload {
                    ip: ip.clone(),
                    recurring: true,
                }) {
                    let _ = store.enqueue(QueueKind::SnmpPoll, payload, Some(&ip)).await;
                }
            });
        }

        Ok(())
    }
}

/// Stage 3: identity resolution + profile matching. Resolves the canonical device identity
/// purely by IP (see [`discovery_devices::DeviceStore::resolve`]'s docs), then (re)matches
/// a profile against the fresh facts and hands off to `ProfileApply`, which decides whether
/// anything actually needs to change.
///
/// **Custom dedup-key fingerprinting removed 2026-08-16** (direct user request: "Давай
/// пока вовсе исключим дедубликацию... удали все связанное с дедубликацией"). This handler
/// used to compute a fingerprint via `DedupResolver`/`discovery-dsl::dedup` from the
/// device's currently-known metrics and use it to recognize "the same physical device,
/// moved to a new IP" — pulled out entirely after finding a real, unhandled failure mode
/// (see `DeviceStore::resolve`'s docs). Only the plain per-IP fallback remains — same IP
/// always means the same device, a new IP always means a new device, full stop. The
/// custom-key mechanism will come back, redesigned, as separate work; the queue/handler
/// name stays `Dedup` for now since it's still the same pipeline stage
/// (`SnmpPoll` -> **Dedup** -> `ProfileApply`).
pub struct DedupHandler {
    pub store: Arc<dyn JobQueueStore>,
    pub devices: Arc<dyn DeviceStore>,
    /// Added 2026-08-18's `DeviceStore`/`DeviceMetricsStore` domain split — this handler
    /// reads a device's known metrics (for profile matching) and writes one-shot discovery
    /// outcomes, both of which now live in this separate store. See
    /// `discovery_devices::DeviceMetricsStore`'s docs.
    pub device_metrics: Arc<dyn DeviceMetricsStore>,
    pub matcher: Arc<ProfileMatcher>,
    /// Gates "start a new recurring `ReachabilityPoll` chain for this device" to at most
    /// once per device per process — same `ActiveChains` pattern `DiscoveryHandler` uses
    /// for `identity_chains`. Started here, not from `ProfileApplyHandler` like
    /// `MetricPoll`'s chain — reachability checking doesn't depend on a profile ever
    /// matching, see `ReachabilityPollHandler`'s docs.
    pub reachability_chains: Arc<ActiveChains<uuid::Uuid>>,
}

#[async_trait]
impl JobHandler for DedupHandler {
    async fn handle(&self, job: Job) -> anyhow::Result<()> {
        let payload: DedupPayload = serde_json::from_value(job.payload)?;

        info!(ip = %payload.ip, "identity/dedup cycle running");

        // What this device (if it already exists at this IP) has already collected via
        // its profile's `[metrics.poll]` (MetricPoll) — needed for profile *matching*
        // below, not for identity resolution (that's IP-only now, see this handler's
        // docs). A device seen for the very first time has no prior row, so
        // `known_metrics` is empty.
        let existing_device_id = self.devices.id_by_ip(&payload.ip).await?;
        let known_metrics = match existing_device_id {
            Some(id) => self.device_metrics.get_metrics(id).await?,
            None => Metrics::default(),
        };

        // Merge in this cycle's one-shot discovery data (if any) BEFORE matching a profile
        // — load-bearing for a device's very first-ever contact: at that point
        // `known_metrics` is empty (`resolve` hasn't persisted anything yet), so without
        // this merge profile matching wouldn't see the `subnet.oids`/`subnet.labels`
        // values `SnmpPollHandler` just fetched this exact cycle — the device would
        // wrongly fall through to a catch-all profile until its *next* identity cycle.
        // Only the `Ok` outcomes participate — match expressions only ever see successful
        // values (see `DedupPayload::extra`'s docs); a failed one-shot fetch still gets
        // recorded below, just not used for matching.
        let mut effective_metrics = known_metrics;
        if let Some(extra) = &payload.extra {
            for (k, outcome) in extra {
                if let MetricPollOutcome::Ok(v) = outcome {
                    effective_metrics.0.insert(k.clone(), v.clone());
                }
            }
        }

        let (device_id, is_new) = self.devices.resolve(payload.facts.clone()).await?;
        if is_new {
            info!(ip = %payload.ip, device_id = %device_id, "new device registered");
        }

        // The single write path for this cycle's one-shot discovery outcomes (successes
        // AND failures) — same method `MetricPollHandler` uses for regular profile-polled
        // metrics, see `DeviceStore::record_metric_polls`'s docs. `resolve()` itself no
        // longer writes metrics at all (2026-08-16, direct user request — metric change
        // history); this is the only place a device's one-shot discovery data ever lands.
        if let Some(extra) = &payload.extra {
            self.device_metrics
                .record_metric_polls(device_id, extra)
                .await?;
        }

        // Persist credentials `SnmpPoll` just negotiated for the first time — see
        // `DedupPayload::snmp_credentials`'s docs for why this is where it happens (this
        // is the stage that actually resolves/creates the device row).
        if let Some(credentials) = payload.snmp_credentials {
            self.devices
                .set_snmp_credentials(device_id, credentials)
                .await?;
        }

        // Start the reachability chain right here, independent of profile matching below
        // — a device that never matches any profile must still get checked. `mark`
        // returns `true` only the first time this process sees this device_id, so a
        // recurring `Dedup` cycle for an already-chained device is a no-op here.
        if self.reachability_chains.mark(device_id) {
            self.store
                .enqueue(
                    QueueKind::ReachabilityPoll,
                    serde_json::to_value(ReachabilityPollPayload { device_id })?,
                    None,
                )
                .await?;
        }

        // Live reachability for `match.expression`'s `facts.ping_ok`/`facts.snmp_ok`
        // (2026-09-14, `docs/Roadmap.md` "До релиза" item 6) — read fresh here, not carried
        // over from anywhere cached: for a brand-new device this is always `None` (nothing
        // checked yet, same as any other never-polled field), but for a device re-running
        // this cycle (identity re-check, a later `Dedup` after `ReachabilityPollHandler`
        // has already ticked at least once) it reflects the device's actual current
        // up/down status — see `ProfileMatcher::match_profile`'s docs for why this isn't
        // just `payload.facts` itself.
        let (ping_ok, snmp_ok) = match self.devices.get_device(device_id).await? {
            Some(d) => (d.ping_ok, d.snmp_ok),
            None => (None, None),
        };
        match self
            .matcher
            .match_profile(&payload.facts, ping_ok, snmp_ok, &effective_metrics)
            .await?
        {
            Some(profile) => {
                self.store
                    .enqueue(
                        QueueKind::ProfileApply,
                        serde_json::to_value(ProfileApplyPayload {
                            device_id,
                            profile_name: profile.profile.name.clone(),
                            profile_version: profile.version.clone(),
                        })?,
                        Some(&format!(
                            "{}:{}:{}",
                            device_id, profile.profile.name, profile.version
                        )),
                    )
                    .await?;
            }
            None => {
                warn!(ip = %payload.ip, "no matching profile found — device will not be (re)configured this cycle")
            }
        }

        Ok(())
    }
}

/// Stage 4: compares the freshly-matched profile against what's on record
/// ([`DeviceStore::apply_profile_if_changed`]) and reconfigures only if it actually
/// changed. Also (re)starts the metric-poll chain — either because the profile just
/// changed (a fresh generation always needs one), or because this is the first time
/// *this process* has seen the device at all, even with an unchanged profile.
///
/// That second condition is the fix for a real bug found by actually restarting the
/// agent against a live Postgres (not by inspection): a metric-poll chain is just an
/// in-process `tokio::spawn` loop, never persisted. After a restart, the device's profile
/// on record is unchanged, so without this check `apply_profile_if_changed` would report
/// `Unchanged` and the handler would (correctly, by the old logic) do nothing — leaving
/// every already-known device with zero active pollers until its profile happens to
/// change again, which for a stable device might be never. `ActiveChains` tracks "has
/// this process started a chain for this device yet" and is empty on every fresh start,
/// so the first `ProfileApply` per device always gets to start one.
pub struct ProfileApplyHandler {
    pub store: Arc<dyn JobQueueStore>,
    pub devices: Arc<dyn DeviceStore>,
    pub active_chains: Arc<ActiveChains<uuid::Uuid>>,
    /// Same `Arc` `MetricPollHandler` schedules against — cleared for this device on a
    /// real profile change (see `handle` below). Direct user request 2026-08-16: "при
    /// смене профиля нужно будет опросить весь профиль сразу, что бы собрать актуальные
    /// метрики". Without this, a metric *name* reused between the old and new profile
    /// (even under a different OID) would keep its stale `last_polled` timestamp from the
    /// old profile and look "not due yet" on the new generation's very first tick —
    /// silently skipping part of the freshly-applied profile instead of collecting it
    /// immediately.
    pub last_polled: Arc<DashMap<(uuid::Uuid, String), tokio::time::Instant>>,
    /// Same idea as `last_polled`, but for [`discovery_core::Schedule::Calendar`]-mode
    /// metrics (added 2026-08-16) — see `MetricPollHandler`'s docs for why calendar mode
    /// needs its own "already fired today" guard instead of an elapsed-time one. Cleared
    /// alongside `last_polled` on a real profile change, same reasoning: a metric name
    /// reused from the old profile under a new calendar schedule shouldn't inherit "already
    /// fired today" from before the profile even changed.
    pub last_polled_date: Arc<DashMap<(uuid::Uuid, String), chrono::NaiveDate>>,
    /// Same "clear on real profile change" idea as `last_polled`, but for
    /// `ServiceCheckPollHandler`'s chain (added 2026-09-07) — its own dedicated map, keyed
    /// by device only (not (device, name), see that handler's docs for why its schedule is
    /// section-wide, not per-check).
    pub service_check_last_polled: Arc<DashMap<uuid::Uuid, tokio::time::Instant>>,
    /// See `service_check_last_polled`'s docs — the `Schedule::Calendar` counterpart.
    pub service_check_last_polled_date: Arc<DashMap<uuid::Uuid, chrono::NaiveDate>>,
}

#[async_trait]
impl JobHandler for ProfileApplyHandler {
    async fn handle(&self, job: Job) -> anyhow::Result<()> {
        let payload: ProfileApplyPayload = serde_json::from_value(job.payload)?;

        let Some(decision) = self
            .devices
            .apply_profile_if_changed(
                payload.device_id,
                &payload.profile_name,
                &payload.profile_version,
            )
            .await?
        else {
            return Ok(()); // device vanished between Dedup and here
        };

        let (generation, is_reconfigure) = match decision {
            ProfileDecision::Changed { generation } => (generation, true),
            ProfileDecision::Unchanged { generation } => (generation, false),
        };

        if is_reconfigure {
            info!(device_id = %payload.device_id, profile = %payload.profile_name, generation, "profile (re)applied");
            // Real implementation: push profile-defined SNMP SET commands / config here.

            // Force every metric in the freshly-applied profile to be treated as due on
            // its very first tick — see this field's docs for why a plain "leave
            // last_polled alone" would silently under-poll a metric name reused from the
            // old profile.
            self.last_polled
                .retain(|(id, _), _| *id != payload.device_id);
            self.last_polled_date
                .retain(|(id, _), _| *id != payload.device_id);
            self.service_check_last_polled.remove(&payload.device_id);
            self.service_check_last_polled_date
                .remove(&payload.device_id);
        }

        // `mark` is called unconditionally so it's always up to date, but only its
        // *return value* decides anything on the unchanged-profile path.
        let first_time_this_process = self.active_chains.mark(payload.device_id);
        if is_reconfigure || first_time_this_process {
            self.store
                .enqueue(
                    QueueKind::MetricPoll,
                    serde_json::to_value(MetricPollPayload {
                        device_id: payload.device_id,
                        generation,
                    })?,
                    None,
                )
                .await?;
            // Started alongside `MetricPoll`, same generation guard — see
            // `ServiceCheckPollHandler`'s docs. Harmless to enqueue even for a profile with
            // an empty `service_checks.checks` list: that first tick just returns
            // immediately without rescheduling itself (no dangling chain left behind).
            self.store
                .enqueue(
                    QueueKind::ServiceCheckPoll,
                    serde_json::to_value(ServiceCheckPollPayload {
                        device_id: payload.device_id,
                        generation,
                    })?,
                    None,
                )
                .await?;
        }
        Ok(())
    }
}

/// Stage 5: recurring metric collection per the matched profile's `[metrics.poll]` list.
/// Re-enqueues itself after `next_tick` (see below) — but only while `generation` still
/// matches what's on record; a profile change bumps the generation and starts a fresh
/// chain, and this is what makes the *old* chain notice and quietly stop instead of
/// racing the new one (see `DeviceStore::apply_profile_if_changed`).
///
/// **Per-metric poll cadence (direct user request: "частота опроса метрик должна
/// настраиваться через профиль").** Each metric in `[metrics.poll]` can declare its own
/// [`Schedule`] (`MetricSpec::Detailed`) or fall back to `default_poll_interval`
/// (`MetricSpec::Oid`, the plain-string form, or a `Detailed` entry that never set one —
/// see its docs). One chain per *device* still, not one per metric: it wakes up every
/// `next_tick` (the shortest interval among the profile's metrics — a `Calendar`-scheduled
/// metric contributes `default_poll_interval` to that computation, same as an unscheduled
/// one, so the chain wakes up often enough to actually catch its target minute) and on
/// each wake only actually polls whichever metrics are actually due.
///
/// **Two independent due-checks, one per [`Schedule`] variant (added 2026-08-16, direct
/// user follow-up to discovery's own periodic-vs-calendar switch: "впиши такую же логику в
/// метрики в профиле")** — same split `discovery_agent::discovery_scan::run_discovery_schedule_loop`
/// uses, just per (device, metric) instead of per discovery-config name:
///
/// - No schedule, or [`Schedule::Periodic`] — `last_polled` (an elapsed-time check against
///   `interval_secs()`, deliberately not persisted, same reasoning as `ActiveChains`: empty
///   on every fresh process start just means every metric looks "due" on the first tick
///   after a restart, which is correct, not a bug — the same one-time catch-up the old
///   always-poll-everything design did on every single tick).
/// - [`Schedule::Calendar`] — `last_polled_date` (per (device, metric) -> the local date it
///   last fired on, mirroring discovery's own `last_fired_date`) guards against firing more
///   than once for the same matching minute, then `Schedule::matches_calendar` against the
///   **server's local time** decides the rest.
///
/// **On/off gating (added 2026-08-16, direct user request — "выключать устройства...
/// выключать временно метрики").** Two independent switches, both consulted every tick,
/// neither ever written by this handler (or any other automatic pipeline code):
///
/// - Per-metric: `DeviceStore::get_metric_overrides` (a manual override, if one exists,
///   always wins over the profile's own default, `MetricSpec::enabled()`) — checked inside
///   the `due` filter, so a disabled metric simply never becomes due.
/// - Per-device: `Device::enabled`, the master switch — gates the whole polling action for
///   this tick (`due.is_empty()` check below), but **not** the reschedule at the end, and
///   **not** `last_polled`/`last_polled_date` (left untouched while disabled) — so
///   re-enabling a device picks up immediately on its very next tick, already "due" for
///   whatever it missed, no restart or re-discovery needed.
/// Fixed per-call timeout for `discovery_ssh::CliClient::exec` — deliberately **not** a
/// dashboard-editable setting in v1, unlike `snmp_timeout_ms`/`snmp_retries` (looked up
/// fresh from subnet config every tick, see this struct's `discovery_configs` field docs).
/// SSH's connect + key-exchange + authenticate + exec round trip is inherently slower than
/// a UDP SNMP `get` (see `discovery-ssh::RealCliClient`'s docs on the reconnect-per-call
/// lifecycle this implies), so this is set generously rather than tuned. Revisit as a real
/// settings-store field if an actual deployment's device/network latency needs something
/// different — not added preemptively for a knob nobody has asked to turn yet.
const SSH_COMMAND_TIMEOUT: Duration = Duration::from_secs(15);

pub struct MetricPollHandler {
    pub store: Arc<dyn JobQueueStore>,
    pub snmp: Arc<dyn SnmpClient>,
    /// SSH CLI-pull metrics (added 2026-09-07, see `discovery_dsl::MetricSpec::SshCommand`'s
    /// docs) — routed to this instead of `snmp` for any due metric where
    /// `MetricSpec::is_ssh_command()` is true. `Arc<dyn CliClient>` for the same
    /// test-without-real-I/O reasoning `snmp`/`Pinger` fields already follow throughout
    /// this handler set.
    pub cli: Arc<dyn discovery_ssh::CliClient>,
    pub devices: Arc<dyn DeviceStore>,
    /// Added 2026-08-18's `DeviceStore`/`DeviceMetricsStore` domain split — see
    /// `DedupHandler::device_metrics`'s docs.
    pub device_metrics: Arc<dyn DeviceMetricsStore>,
    pub matcher: Arc<ProfileMatcher>,
    /// `poll_intervals.metric_secs`, read fresh (not cached) once at the top of every
    /// `handle()` call — direct user request 2026-08-16: settings live in the database and
    /// an edit must apply without a restart, see `SettingsStore`'s docs.
    pub settings: Arc<dyn SettingsStore>,
    pub last_polled: Arc<DashMap<(uuid::Uuid, String), tokio::time::Instant>>,
    /// See this struct's docs — the `Schedule::Calendar` counterpart to `last_polled`.
    pub last_polled_date: Arc<DashMap<(uuid::Uuid, String), chrono::NaiveDate>>,
    /// Looked up fresh every poll (by the device's current IP) purely for
    /// `snmp_timeout_ms`/`snmp_retries` — a config edit there takes effect on the very
    /// next metric-poll cycle, same as `SnmpPollHandler`. Direct user requirement
    /// 2026-08-16, following the SNMP-hang bug found live (see
    /// `discovery-snmp::RealSnmpClient`'s docs).
    pub discovery_configs: Arc<dyn DiscoveryConfigStore>,
    /// Last generation this device was actually pruned for — added 2026-08-21, scale
    /// audit finding: `prune_metrics`/`prune_metric_overrides` used to run unconditionally
    /// on *every* tick (see the call site's docs for why that was originally judged fine —
    /// "a single DELETE" — and why it stopped being fine once the fixed per-tick overhead
    /// across every queue, not just this one DELETE, was measured at scale). What those
    /// two calls actually clean up (a stale metric a profile edit dropped) only changes
    /// when the profile does — i.e. on a fresh `generation`, the same event that already
    /// resets `last_polled`/`last_polled_date` (see `ProfileApplyHandler`'s docs) — so
    /// pruning once per generation instead of once per tick loses nothing for the case
    /// this was built for. Absent from this map means "never pruned yet in this process",
    /// same convention as `discovery_core::ActiveChains`.
    pub pruned_generations: Arc<DashMap<uuid::Uuid, u64>>,
    /// Loaded fresh at the same point every tick already loads other small config (same
    /// convention as `AlertEvalHandler.maintenance_windows`) — used only to decide whether
    /// this tick's freshly-polled metrics warrant enqueuing a `QueueKind::TopologyRecompute`
    /// for this device (2026-09-16, see that call site's docs), never to do any topology
    /// evaluation itself (that's `TopologyRecomputeHandler`'s job, in its own worker pool).
    pub topology_rules: Arc<dyn discovery_config_store::TopologyRuleStore>,
}

#[async_trait]
impl JobHandler for MetricPollHandler {
    async fn handle(&self, job: Job) -> anyhow::Result<()> {
        let manual = job.payload.get("manual").and_then(|v| v.as_bool()) == Some(true);
        let payload: MetricPollPayload = serde_json::from_value(job.payload)?;

        if self
            .devices
            .current_poll_generation(payload.device_id)
            .await?
            != Some(payload.generation)
        {
            return Ok(()); // stale chain (device gone, or superseded by a newer generation)
        }

        let Some(device) = self.devices.get_device(payload.device_id).await? else {
            return Ok(());
        };
        let Some(profile_name) = device.profile.clone() else {
            return Ok(());
        };
        let Some(profile) = self.matcher.profile_by_name(&profile_name).await else {
            warn!(profile = %profile_name, "device references a profile that no longer exists");
            return Ok(());
        };

        if profile.metrics.poll.is_empty() {
            return Ok(()); // nothing to poll; a future profile change restarts the chain via the generation guard
        }

        // Looked up once per tick and reused below both for the prune "keep" list and for
        // SNMP timeout/retries — same "read fresh, not cached" convention as the rest of
        // this handler.
        let configs = self.discovery_configs.load_all().await.unwrap_or_default();
        let subnet_spec = find_subnet_spec_for_ip(&configs, &device.facts.ip);

        // Drop any device_metrics row no longer declared by the current profile (e.g.
        // removed in an edit) — without this, a stale value from a previous profile would
        // linger in storage forever, since polling below only ever upserts due keys, never
        // deletes any. **Only needs to run once per `generation`, not every tick** (see
        // `pruned_generations`'s docs — changed 2026-08-21, this used to run
        // unconditionally on every tick on the reasoning that a single DELETE is cheap in
        // isolation, which stopped being the right call once it was counted as one of
        // several fixed per-tick round trips multiplied across every device at scale).
        //
        // **Also keeps the device's own one-shot discovery-time fields** (`subnet.oids`/
        // `subnet.labels` — see `discovery_core::DeviceFacts`'s docs) — a real bug found
        // live 2026-08-18 ("спустя некоторое время у всех стал профиль unknown_device"):
        // those fields are never declared in any profile's `[metrics.poll]` by design
        // (they're one-shot, not recurring), so without this exemption a profile's very
        // first metric-poll tick wiped them from `device_metrics` — including
        // `sys_descr`/`sys_object_id`/whatever else `match.expression` reads. The device's
        // *next* identity cycle then saw an empty `metrics.sys_descr`, no specific profile
        // matched, and it fell through to the lowest-priority catch-all — permanently,
        // since `SnmpPollHandler` only ever fetches `subnet.oids` on a device's very
        // first-ever identity cycle (see its docs), never again afterwards.
        if self.pruned_generations.get(&payload.device_id).map(|g| *g) != Some(payload.generation) {
            let mut keep: Vec<String> = profile.metrics.poll.keys().cloned().collect();
            if let Some(subnet) = &subnet_spec {
                keep.extend(subnet.oids.keys().cloned());
                keep.extend(subnet.labels.keys().cloned());
            }
            // Also exempt synthetic table-metrics produced by sibling ingestion/poll
            // features that never go through `[metrics.poll]` at all (SNMP Trap/Syslog
            // ingestion, L4/L7 service checks) — found live while adding service checks
            // 2026-09-07: without this, a device with BOTH ordinary metrics AND one of
            // these bindings would have `metrics.trap_<binding>`/`metrics.syslog_<binding>`/
            // `metrics.service_checks` silently deleted the very first time its generation's
            // prune ran, since none of those names were ever in `keep`. Neither ingestion
            // path nor `ServiceCheckPollHandler` ever *recreates* a row from nothing on its
            // own schedule the way a fresh SNMP walk would — trap/syslog only upsert on a
            // matching event, and even service checks (rebuilt every tick) would just
            // silently reappear one tick later, briefly and spuriously auto-clearing any
            // open row-scoped alert via `AutoClearReason::RowMissing` in the meantime.
            keep.extend(
                profile
                    .traps
                    .bindings
                    .keys()
                    .map(|name| crate::trap_ingest::trap_metric_name(name)),
            );
            keep.extend(
                profile
                    .syslog
                    .bindings
                    .keys()
                    .map(|name| crate::syslog_ingest::syslog_metric_name(name)),
            );
            if !profile.service_checks.checks.is_empty() {
                keep.push(SERVICE_CHECKS_METRIC_NAME.to_string());
            }
            let prune_metrics_ok = match self
                .device_metrics
                .prune_metrics(payload.device_id, &keep)
                .await
            {
                Ok(()) => true,
                Err(e) => {
                    warn!(device_id = %payload.device_id, error = %e, "failed to prune stale metrics — will retry on the next tick");
                    false
                }
            };
            if prune_metrics_ok {
                if let Err(e) = self
                    .devices
                    .prune_metric_overrides(payload.device_id, &keep)
                    .await
                {
                    warn!(device_id = %payload.device_id, error = %e, "failed to prune metric overrides — will retry on the next tick");
                } else {
                    self.pruned_generations
                        .insert(payload.device_id, payload.generation);
                }
            }
        }

        // Read fresh once per tick, not cached across ticks — see this struct's
        // `settings` field docs.
        let default_poll_interval =
            Duration::from_secs(self.settings.poll_intervals().await.metric_secs);

        // Manual per-device overrides (direct user request 2026-08-16: "за определенными
        // устройствами выключать временно метрики"). Read once per tick — see
        // `discovery_core::MetricRecord::enabled_override`'s docs for the resolution order
        // this implements: an override, if one exists, always wins over the profile's own
        // default (`spec.enabled()`). **Never written by this handler or anything else in
        // the automatic pipeline** — that's what makes a manual override survive a profile
        // (re)application untouched, including a device re-matching to an entirely
        // different profile that happens to declare a same-named metric.
        let overrides = self
            .devices
            .get_metric_overrides(payload.device_id)
            .await
            .unwrap_or_default();

        let now = tokio::time::Instant::now();
        let local_now = Local::now();
        let today = local_now.date_naive();
        let due: Vec<(&String, &MetricSpec)> = profile
            .metrics
            .poll
            .iter()
            .filter(|(name, spec)| {
                let effectively_enabled = overrides
                    .get(*name)
                    .copied()
                    .unwrap_or_else(|| spec.enabled());
                if !effectively_enabled {
                    return false;
                }
                // Manual poll never runs profile-authored SSH commands. Those can be
                // arbitrary CLI text; explicit operator actions only allow SNMP reads.
                if manual && spec.is_ssh_command() {
                    return false;
                }
                if manual {
                    return true;
                }
                match spec.schedule() {
                    Some(Schedule::Calendar { .. }) => {
                        let key = (payload.device_id, (*name).clone());
                        if self.last_polled_date.get(&key).map(|d| *d) == Some(today) {
                            false // already fired today — don't refire every tick for the rest of the matching minute
                        } else {
                            spec.schedule().unwrap().matches_calendar(
                                today,
                                local_now.hour(),
                                local_now.minute(),
                            )
                        }
                    }
                    _ => {
                        let interval = Duration::from_secs(
                            spec.interval_secs()
                                .unwrap_or(default_poll_interval.as_secs()),
                        );
                        match self.last_polled.get(&(payload.device_id, (*name).clone())) {
                            Some(last) => now.duration_since(*last) >= interval,
                            None => true, // never polled by this process yet — due immediately
                        }
                    }
                }
            })
            .collect();

        // Device-level master switch (direct user request 2026-08-16: "мне нужна
        // возможность выключать устройства"). Skips all actual polling below, but — since
        // `last_polled`/`last_polled_date` are simply never updated while disabled — the
        // `due` computation above still reflects reality: the moment the device is
        // re-enabled, whatever was already overdue fires on the very next tick, no restart
        // or re-discovery needed. The chain itself (the reschedule below) keeps running
        // either way, so re-enabling is picked up automatically.
        if device.enabled && !due.is_empty() {
            // Reuse whatever credentials `SnmpPoll` negotiated (see `SnmpPollHandler`'s
            // docs) rather than re-negotiating every metric-poll cycle — falls back to
            // the default (v2c/public) only if the device somehow has none on record yet.
            // Timeout/retries, unlike port/version/community, are looked up fresh from
            // the subnet config every cycle (see this struct's docs) — not persisted.
            // `subnet_spec` was already looked up above, for the prune "keep" list.
            let timeout_ms = subnet_spec
                .as_ref()
                .and_then(|s| s.snmp_timeout_ms)
                .unwrap_or_else(default_snmp_timeout_ms);
            let retries = subnet_spec
                .as_ref()
                .and_then(|s| s.snmp_retries)
                .unwrap_or_else(default_snmp_retries);

            let target = match &device.snmp_credentials {
                Some(creds) => DeviceTarget {
                    ip: device.facts.ip.clone(),
                    port: creds.port,
                    auth: creds.auth.clone(),
                    timeout_ms,
                    retries,
                },
                None => DeviceTarget {
                    ip: device.facts.ip.clone(),
                    timeout_ms,
                    retries,
                    ..Default::default()
                },
            };

            // **Changed 2026-08-16 (direct user request — metric change history):** builds
            // the full outcome map (successes *and* failures), not just a `Metrics` bag of
            // successes — a failed poll attempt used to be logged via `warn!` and then
            // silently dropped, with no record anywhere that it was even attempted. Now
            // every `due` metric gets an entry either way.
            //
            // **Changed 2026-08-18 (direct user request — SNMP batching):** all due OIDs
            // for this device go out in one `get_multi` call instead of one sequential
            // `get()` per metric — one packet/timeout for the whole job instead of N. See
            // `discovery_snmp::SnmpClient::get_multi`'s docs for why this can never lose a
            // metric a device *does* support just because another one in the same batch
            // isn't (the all-or-nothing `csnmp::get_multiple` failure mode is handled
            // there, not here).
            for (name, _) in &due {
                // Both bookkeeping maps are updated unconditionally per due metric,
                // regardless of which one its own due-check actually consults — harmless
                // for the map it doesn't use, and keeps this one write site simple rather
                // than branching on `spec.schedule()` a second time here. Updated on
                // failure too — a metric that's currently failing should retry on *its
                // own* cadence, not on every base tick (which could be much shorter than
                // its configured interval).
                self.last_polled
                    .insert((payload.device_id, (*name).clone()), now);
                self.last_polled_date
                    .insert((payload.device_id, (*name).clone()), today);
            }
            // SSH-command metrics (`spec.is_ssh_command()`, added 2026-09-07 — see
            // `discovery_dsl::MetricSpec::SshCommand`'s docs) split off first: they never
            // touch SNMP at all, routed to `discovery_ssh::CliClient::exec` further below
            // instead of the batch/table SNMP paths that handle everything else.
            let (ssh_due, snmp_due): (Vec<(&String, &MetricSpec)>, Vec<(&String, &MetricSpec)>) =
                due.iter()
                    .copied()
                    .partition(|(_, spec)| spec.is_ssh_command());

            // Table metrics (`spec.is_table()` — an OID that's a MIB table entry, declaring
            // `columns`, see `discovery_dsl::MetricSpec::Detailed::columns`'s docs) split
            // off from the scalar batch here: `walk()` is a fundamentally different SNMP
            // operation from a batched `GetRequest` (GetBulk-driven subtree iteration, not
            // a fixed set of named scalar OIDs — see `SnmpClient::get_multi`'s docs on why
            // `get_multiple` specifically targets the latter), so a table metric can never
            // join the scalar `get_multi` batch below; it gets its own
            // `discovery_snmp::poll_table_metric` call instead, entirely independent of
            // whether the batch below succeeds or fails.
            let (table_due, scalar_due): (
                Vec<(&String, &MetricSpec)>,
                Vec<(&String, &MetricSpec)>,
            ) = snmp_due.into_iter().partition(|(_, spec)| spec.is_table());

            let mut outcomes: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();

            // Derived rate/delta metrics (2026-09-07) — one batched read of this device's
            // *current* cached metric records (value + `polled_at`, from before this tick's
            // fresh values overwrite them below), only when at least one due metric
            // actually opts into `derive` (`MetricSpec::Detailed::derive`). Skipping this
            // read entirely for the common case (no profile on this device uses the
            // feature) keeps this tick's round-trip count identical to before the feature
            // existed. One read for the whole tick, not one per derived metric — O(1) per
            // device per tick, not N+1 — see `discovery_dsl::compute_derived`'s docs for
            // what this feeds into.
            //
            let needs_previous_records = due.iter().any(|(_, spec)| spec.derive().is_some());
            let mut previous_records: BTreeMap<String, MetricRecord> = BTreeMap::new();
            if needs_previous_records {
                for record in self
                    .device_metrics
                    .get_metric_records(payload.device_id)
                    .await
                    .unwrap_or_default()
                {
                    previous_records.insert(record.name.clone(), record);
                }
            }
            // Captured once, right before the batch actually goes out — used as the "new
            // sample" timestamp for every derived value computed from this tick's results,
            // approximating (within the same tick, sub-second) the `polled_at` `record_metric_polls`
            // itself will stamp a moment later. See `compute_derived`'s docs: elapsed time
            // is always computed from actual timestamps, never an assumed fixed interval.
            let poll_time = chrono::Utc::now();

            let due_oids: Vec<String> = scalar_due
                .iter()
                .map(|(_, spec)| spec.oid().to_string())
                .collect();
            let results = self.snmp.get_multi(&target, &due_oids).await;
            for ((name, spec), result) in scalar_due.iter().zip(results) {
                match result {
                    Ok(value) => {
                        let metric_value = snmp_value_to_metric(&value);
                        if let Some(kind) = spec.derive() {
                            let derived = previous_records.get(name.as_str()).and_then(|prev| {
                                compute_derived(
                                    kind,
                                    prev.value.as_ref(),
                                    prev.polled_at,
                                    &metric_value,
                                    poll_time,
                                )
                            });
                            // `None` here covers every "not computable this tick" case
                            // uniformly (first-ever sample, wrap/reset, non-positive
                            // elapsed time — see `compute_derived`'s docs) — nothing is
                            // written for the derived name, leaving whatever was cached
                            // from a previous tick (if any) untouched, exactly like a
                            // metric that simply hasn't polled yet.
                            if let Some(derived_value) = derived {
                                outcomes.insert(
                                    derived_metric_name(name, kind),
                                    MetricPollOutcome::Ok(derived_value),
                                );
                            }
                        }
                        outcomes.insert((*name).clone(), MetricPollOutcome::Ok(metric_value));
                    }
                    Err(e) => {
                        warn!(ip = %device.facts.ip, metric = %name, error = %e, "metric poll failed");
                        outcomes.insert((*name).clone(), MetricPollOutcome::Err(e.to_string()));
                    }
                }
            }

            // Sequential, not batched/concurrent — table metrics are the uncommon case
            // (most profiles' `[metrics.poll]` entries are scalars) and each one's own
            // `poll_table_metric` call already does its own per-column `walk()`s. Simple to
            // reason about; revisit with a `join_all` if profiling ever says a device with
            // many table metrics needs it.
            for (name, spec) in &table_due {
                // `table_due` was filtered by `is_table()`, which is exactly `columns().is_some()`.
                let columns = spec
                    .columns()
                    .expect("table_due entries always have columns — filtered by is_table() above");
                match poll_table_metric(self.snmp.as_ref(), &target, spec.oid(), columns).await {
                    Ok(rows) => {
                        outcomes.insert(
                            (*name).clone(),
                            MetricPollOutcome::Ok(MetricValue::Table(rows)),
                        );
                    }
                    Err(e) => {
                        warn!(ip = %device.facts.ip, metric = %name, error = %e, "table metric poll failed");
                        outcomes.insert((*name).clone(), MetricPollOutcome::Err(e.to_string()));
                    }
                }
            }

            // SSH-command metrics (2026-09-07) — entirely independent of the SNMP batch/
            // table polling above, and of each other: one `exec()` call per due metric,
            // not batched (unlike the SNMP scalar batch, there's no protocol-level way to
            // run several commands in one SSH round trip, and — per
            // `discovery-ssh::RealCliClient`'s docs — each call is already its own full
            // connect/auth/exec/disconnect cycle regardless). A device with no SSH
            // credentials configured at all fails every due SSH metric with one explanatory
            // error each, the same "nothing to poll with yet" treatment a metric poll gets
            // before a device's first successful `SnmpPoll` negotiation, rather than
            // silently skipping them (which would leave no record anywhere that they were
            // ever attempted — see this handler's `MetricPollOutcome` docs for why every
            // due metric always gets an outcome, success or failure).
            if !ssh_due.is_empty() {
                match &device.ssh_credentials {
                    Some(creds) => {
                        // Mutable, not just a one-shot literal — see the `newly_pinned_host_key`
                        // handling below for why: pinning as soon as the *first* due command
                        // this tick learns a fingerprint means every subsequent command in the
                        // same tick already verifies against it, instead of every one of them
                        // independently trusting-on-first-use against a device with no prior
                        // pin (see `discovery_core::SshCredentials::known_host_key`'s docs).
                        let mut ssh_target = SshTarget {
                            ip: device.facts.ip.clone(),
                            port: creds.port,
                            username: creds.username.clone(),
                            auth: creds.auth.clone(),
                            known_host_key: creds.known_host_key.clone(),
                        };
                        for (name, spec) in &ssh_due {
                            let command = spec.command().expect("ssh_due entries always have a command — filtered by is_ssh_command() above");
                            match self
                                .cli
                                .exec(&ssh_target, command, SSH_COMMAND_TIMEOUT)
                                .await
                            {
                                Ok(outcome) => {
                                    outcomes.insert(
                                        (*name).clone(),
                                        MetricPollOutcome::Ok(MetricValue::Str(outcome.output)),
                                    );
                                    if let Some(fingerprint) = outcome.newly_pinned_host_key {
                                        if let Err(e) = self
                                            .devices
                                            .pin_ssh_host_key(
                                                payload.device_id,
                                                fingerprint.clone(),
                                            )
                                            .await
                                        {
                                            warn!(ip = %device.facts.ip, error = %e, "failed to persist newly-learned SSH host key fingerprint");
                                        }
                                        ssh_target.known_host_key = Some(fingerprint);
                                    }
                                }
                                Err(e) => {
                                    warn!(ip = %device.facts.ip, metric = %name, error = %e, "SSH command metric poll failed");
                                    outcomes.insert(
                                        (*name).clone(),
                                        MetricPollOutcome::Err(e.to_string()),
                                    );
                                }
                            }
                        }
                    }
                    None => {
                        for (name, _) in &ssh_due {
                            warn!(ip = %device.facts.ip, metric = %name, "SSH command metric is due but this device has no SSH credentials configured");
                            outcomes.insert(
                                (*name).clone(),
                                MetricPollOutcome::Err(
                                    "no SSH credentials configured for this device".to_string(),
                                ),
                            );
                        }
                    }
                }
            }

            // Records only the keys that were actually due/polled this tick — a metric on
            // a slower cadence must not have its `last_attempt_at` dragged forward just
            // because a faster sibling happened to be due (see
            // `DeviceStore::record_metric_polls`'s docs). Called even when every attempt
            // this tick failed — that's exactly what gives a fully-unreachable device an
            // accurate "time of last attempt" instead of a frozen one (see this struct's
            // docs / `MetricRecord::last_attempt_at`).
            // A recurring metric chain must survive a transient write/enqueue failure.
            // The reschedule is below this block; propagating either error here would
            // return before reaching it and freeze this device until a new profile apply
            // or process restart (the same failure mode fixed for reachability polling).
            if let Err(e) = self
                .device_metrics
                .record_metric_polls(payload.device_id, &outcomes)
                .await
            {
                warn!(device_id = %payload.device_id, error = %e, "failed to persist metric poll — will retry on the next tick");
            }

            if let Err(e) = self
                .store
                .enqueue(
                    QueueKind::AlertEval,
                    serde_json::to_value(AlertEvalPayload {
                        event: None,
                        device_id: payload.device_id,
                    })?,
                    None,
                )
                .await
            {
                warn!(device_id = %payload.device_id, error = %e, "failed to enqueue alert evaluation after metric poll — will retry on the next tick");
            }

            // Reactive topology recompute (2026-09-16) — deliberately not a separate
            // timer: a device's `my_key`/claimed-neighbors only ever need recomputing
            // when a metric a topology rule actually watches was just freshly (and
            // successfully) polled. Same "read the whole small config table fresh, not
            // cached" convention as `AlertEvalHandler.maintenance_windows` — a rule can be
            // edited/enabled between ticks and must take effect immediately. Triggers on
            // "this metric was due and polled successfully this tick", not a strict
            // value-diff against the previous sample — same posture `AlertEval` above
            // already takes (re-evaluated every tick with due metrics, unconditionally),
            // and cheap enough to match: `TopologyRecomputeHandler` does one small
            // transaction per device, not a fleet-wide scan.
            let topology_rules = self.topology_rules.list_all().await.unwrap_or_else(|e| {
                warn!(error = %e, "failed to load topology rules — skipping topology recompute trigger this tick");
                Vec::new()
            });
            if !topology_rules.is_empty() {
                let watched_metrics: BTreeSet<String> = topology_rules
                    .iter()
                    .filter(|rule| rule.enabled)
                    .flat_map(|rule| match &rule.watched_metrics {
                        Some(explicit) => explicit.iter().cloned().collect::<BTreeSet<_>>(),
                        None => referenced_metrics(&[
                            &rule.my_key_expression,
                            rule.claimed_neighbors_expression.as_deref().unwrap_or(""),
                            rule.rank_expression.as_deref().unwrap_or(""),
                        ]),
                    })
                    .collect();
                let topology_relevant = outcomes.iter().any(|(name, outcome)| {
                    matches!(outcome, MetricPollOutcome::Ok(_)) && watched_metrics.contains(name)
                });
                if topology_relevant {
                    if let Err(e) = self
                        .store
                        .enqueue(
                            QueueKind::TopologyRecompute,
                            serde_json::to_value(TopologyRecomputePayload {
                                device_id: payload.device_id,
                            })?,
                            None,
                        )
                        .await
                    {
                        warn!(device_id = %payload.device_id, error = %e, "failed to enqueue topology recompute after metric poll — will retry on the next tick");
                    }
                }
            }
        }

        // Wake up again at the shortest interval among this profile's metrics — that's
        // the only cadence fine-grained enough to catch every metric's own due time.
        let next_tick = profile
            .metrics
            .poll
            .values()
            .map(|spec| {
                Duration::from_secs(
                    spec.interval_secs()
                        .unwrap_or(default_poll_interval.as_secs()),
                )
            })
            .min()
            .unwrap_or(default_poll_interval);

        let store = self.store.clone();
        let device_id = payload.device_id;
        let generation = payload.generation;
        if !manual {
            tokio::spawn(async move {
                tokio::time::sleep(jittered(next_tick)).await;
                if let Ok(payload) = serde_json::to_value(MetricPollPayload {
                    device_id,
                    generation,
                }) {
                    let _ = store.enqueue(QueueKind::MetricPoll, payload, None).await;
                }
            });
        }

        Ok(())
    }
}

/// Stage 6: evaluate the matched profile's alert rules against the latest metrics and
/// feed the result through the anti-flapping debounce in `AlertStateTracker`, persisting
/// every non-`None` transition to [`discovery_alerts::AlertStore`] — direct user request
/// 2026-08-17: "сделай хранение тревог в БД".
pub struct AlertEvalHandler {
    pub evaluation_locks: Arc<DashMap<uuid::Uuid, std::sync::Weak<tokio::sync::Mutex<()>>>>,
    pub alert_engine: Arc<AlertEvaluator>,
    pub alerts: Arc<discovery_core::AlertStateTracker>,
    pub alert_store: Arc<dyn discovery_alerts::AlertStore>,
    pub devices: Arc<dyn DeviceStore>,
    /// Added 2026-08-18's `DeviceStore`/`DeviceMetricsStore` domain split — see
    /// `DedupHandler::device_metrics`'s docs.
    pub device_metrics: Arc<dyn DeviceMetricsStore>,
    pub matcher: Arc<ProfileMatcher>,
    /// Maintenance windows (2026-09-07) — see `handle`'s docs for the suppression gate
    /// this feeds. Loaded fresh once per `handle()` call (once per device per tick), same
    /// "read the whole small config table fresh, not cached" convention
    /// `discovery_configs`/`SettingsStore` already use elsewhere in this file.
    pub maintenance_windows: Arc<dyn discovery_config_store::MaintenanceWindowStore>,
    /// Notification matrix (2026-09-10) — see [`Self::dispatch_notifications`]'s docs for
    /// the enqueue-one-job-per-channel logic these two feed, right after a successful
    /// `Activated`/`Cleared` persist.
    pub notification_rules: Arc<dyn discovery_config_store::NotificationRuleStore>,
    pub notification_channels: Arc<dyn discovery_config_store::NotificationChannelStore>,
    /// Resolves `discovery_config_store::RecipientRef::Role` entries to their *current*
    /// members (2026-09-18) — see [`dispatch_alert_notifications`]'s docs for the exact
    /// resolve step. Not used for anything else in this handler; `AuthStore` is already a
    /// `discovery-agent` dependency (session/user administration), so this just reuses the
    /// existing store rather than adding a narrower "list users by role" trait.
    pub auth: Arc<dyn discovery_auth::AuthStore>,
    /// Where [`Self::dispatch_notifications`] enqueues `QueueKind::NotificationDispatch`
    /// jobs — the same queue every other recurring/reactive stage in this file already
    /// enqueues its own follow-up work onto (see e.g. `DedupHandler`'s `ReachabilityPoll`
    /// enqueue).
    pub queue: Arc<dyn JobQueueStore>,
    /// When each (device, rule) `StillActive` transition was last actually persisted, and
    /// what message it carried — added 2026-08-21, scale audit finding: without this,
    /// every already-open alert got a real `alert_store.upsert()` on *every* `AlertEval`
    /// tick (same cadence as `MetricPoll`, default 15s) purely to refresh `last_seen`, even
    /// though nothing about the incident changed. At even a modest 5% of a large device
    /// fleet holding an open alert, that's tens of thousands of otherwise-pointless writes
    /// per cycle. See [`STILL_ACTIVE_PERSIST_INTERVAL`]'s docs for the throttle itself.
    /// Key grew a third component, `row_key: Option<String>`, 2026-08-29 (row-scoped
    /// alerts — "тревога по порту") — `None` for an ordinary device-level rule, matching
    /// `AlertStateTracker`'s own key exactly, so the throttle stays independent per row.
    pub still_active_last_persisted: Arc<StillActivePersistMap>,
    /// Shared group-correlation fast path (2026-09-20) — see
    /// [`Self::persist_transition`]'s docs for how `notification_held_for_suppression`
    /// consults it (via `GroupAlertCorrelator::react_to_activation`) *before* an
    /// `Activated` notification is dispatched, so a group-suppressed effect never spams.
    /// The periodic sweep (`crate::group_alert::run_group_alert_loop`) owns the *same*
    /// `Arc`, so both paths ride one snapshot and one evaluator.
    pub correlator: Arc<GroupAlertCorrelator>,
}

/// How stale a persisted `StillActive.last_seen` is allowed to get before the next tick
/// writes it again, regardless of whether the message changed — bounds "how out of date
/// can the dashboard's last-seen-time be for an alert that's been open a long time" to
/// something no human would notice, while cutting the write rate for a long-lived alert
/// from "every AlertEval tick" to "at most once a minute". A message *change* always
/// persists immediately regardless of this interval (see the call site) — this only
/// throttles the redundant "nothing changed, just bump the timestamp" case.
const STILL_ACTIVE_PERSIST_INTERVAL: chrono::Duration = chrono::Duration::seconds(60);

/// How far back a fresh `Activated` transition looks for a *manually* closed alert on the
/// same `(device_id, name, row_key)` to link as `Alert::reopened_from_alert_id` — 2026-09-17,
/// audit finding #4. Deliberately generous (minutes, not seconds) since the scenario this
/// exists for is exactly "operator clicked Закрыть, condition was still true" — that
/// re-activation can land on the very next `AlertEval` tick (seconds) or take a few minutes
/// if the pipeline was mid-cycle — but bounded, so a genuinely new incident days later never
/// gets spuriously linked to old, unrelated history.
const REOPEN_LINK_WINDOW: chrono::Duration = chrono::Duration::minutes(10);

/// `still_active_last_persisted`'s map type — factored out (2026-09-12) once a second
/// handler (`ReachabilityPollHandler`) needed the identical shape, purely to satisfy
/// `clippy::type_complexity` at all three now-existing sites (`AlertEvalHandler`'s own
/// field, `ReachabilityPollHandler`'s, and `persist_alert_transition`'s parameter) — no
/// behavior change, this is the exact same type spelled once instead of three times.
type StillActivePersistMap = DashMap<
    (uuid::Uuid, String, Option<String>),
    (chrono::DateTime<chrono::Utc>, String, bool, Option<String>),
>;

const SYSTEM_DEVICE_DOWN: &str = "system.device_down";
const SYSTEM_SNMP_DOWN: &str = "system.snmp_down";
const SYSTEM_STALE_METRIC: &str = "system.stale_metric";

fn is_system_alert(name: &str) -> bool {
    matches!(
        name,
        SYSTEM_DEVICE_DOWN | SYSTEM_SNMP_DOWN | SYSTEM_STALE_METRIC
    )
}

pub(crate) fn alert_hysteresis_config(
    rule: &AlertRule,
    clear_after: chrono::Duration,
) -> AlertHysteresisConfig {
    AlertHysteresisConfig {
        activate_after: chrono::Duration::seconds(rule.activate_after_seconds.unwrap_or(0) as i64),
        clear_after,
        flap_window: chrono::Duration::seconds(rule.flap_window_seconds.unwrap_or(0) as i64),
        flap_threshold: rule.flap_threshold.unwrap_or(0) as usize,
        flap_clear_threshold: rule.policy.flap_clear_threshold.map(|n| n as usize),
    }
}

#[async_trait]
impl JobHandler for AlertEvalHandler {
    async fn handle(&self, job: Job) -> anyhow::Result<()> {
        let payload: AlertEvalPayload = serde_json::from_value(job.payload)?;
        // Weak entries serialize concurrent packets without retaining deleted devices.
        self.evaluation_locks
            .retain(|_, lock| lock.strong_count() > 0);
        let lock = {
            let mut entry = self.evaluation_locks.entry(payload.device_id).or_default();
            match entry.upgrade() {
                Some(lock) => lock,
                None => {
                    let lock = Arc::new(tokio::sync::Mutex::new(()));
                    *entry = Arc::downgrade(&lock);
                    lock
                }
            }
        };
        let _guard = lock.lock().await;

        let Some(device) = self.devices.get_device(payload.device_id).await? else {
            return Ok(());
        };
        if let Some(event) = &payload.event {
            if event.device_id != payload.device_id {
                anyhow::bail!("source event belongs to another device");
            }
            self.alert_store.record_source_event(event).await?;
        }
        // Keep last-known values in storage for dashboard/history consumers, but do not
        // feed them to alert expressions after a failed poll. `metrics_for_alerts` uses
        // the current attempt status from the full records, so a repeated outage remains
        // observable to the alert pipeline instead of evaluating against old data.
        let records = self
            .device_metrics
            .get_metric_records(payload.device_id)
            .await?;
        let metrics = AlertEvaluator::metrics_for_alerts(&records);
        let now = chrono::Utc::now();

        let profile = match device.profile.as_deref() {
            Some(name) => self.matcher.profile_by_name(name).await,
            None => None,
        };
        if !device.enabled {
            if let Some(profile) = &profile {
                for rule in &profile.alerts {
                    self.record_skipped(
                        rule,
                        &device,
                        discovery_core::RuleEvaluationState::Disabled,
                        now,
                    );
                }
            }
            self.alerts.set_response_deadline(device.id, None);
            self.save_runtime(&device).await?;
            return Ok(());
        }

        // Maintenance window suppression gate (2026-09-07, direct user request —
        // "Maintenance windows — подавление тревог на время работ") — checked **once per
        // device per tick, before the rule loop**, not once per rule (batch-not-loop
        // discipline: this is the `AlertEval` hot path). Same "freeze, don't force-close"
        // contract as `rule.enabled = false`/`Device::enabled`: while an enabled window's
        // `[starts_at, ends_at]` contains `now` and its selector matches this device, the
        // rest of this tick is skipped entirely for every rule — no new activations, no
        // `StillActive` persistence churn, no clears. `AlertStateTracker` isn't touched at
        // all in that case, so an already-open incident simply stops getting fresher
        // `last_seen` bumps until the window ends (or is disabled), it does not get
        // force-cleared.
        let windows = self.maintenance_windows.list_all().await.unwrap_or_else(|e| {
            warn!(error = %e, "failed to load maintenance windows — proceeding without suppression this tick");
            Vec::new()
        });
        if discovery_config_store::is_device_under_maintenance(
            &windows,
            &device.facts.ip,
            device.profile.as_deref(),
            device.id,
            now,
        ) {
            if let Some(profile) = &profile {
                for rule in &profile.alerts {
                    self.record_skipped(
                        rule,
                        &device,
                        discovery_core::RuleEvaluationState::Maintenance,
                        now,
                    );
                }
            }
            self.alerts.set_response_deadline(device.id, None);
            self.save_runtime(&device).await?;
            return Ok(());
        }

        self.eval_system_alerts(&device, profile.as_ref(), &records, now)
            .await;
        let active_rules = profile.as_ref().map(|p| p.alerts.as_slice()).unwrap_or(&[]);
        self.clear_removed_rules(&device, active_rules, now).await;

        let Some(profile) = profile else {
            self.save_runtime(&device).await?;
            return Ok(());
        };

        self.alerts.retain_rule_statuses(
            device.id,
            &profile
                .alerts
                .iter()
                .map(|r| r.name.clone())
                .collect::<Vec<_>>(),
        );
        for declared in &profile.alerts {
            let rule = match self.resolve_rule(declared) {
                Ok(rule) => rule,
                Err(e) => {
                    self.record_error(declared, &device, None, e.to_string(), now);
                    continue;
                }
            };
            let rule = &rule;
            // Profile-level on/off switch (direct user request 2026-08-17: "добавь
            // возможность выключения тревоги и включения") — a disabled rule is skipped
            // entirely, freezing any already-open incident at its last state rather than
            // force-clearing it, same "freeze, don't force-close" contract already used
            // for `Device::enabled`/metric overrides.
            if !rule.enabled {
                self.record_skipped(
                    rule,
                    &device,
                    discovery_core::RuleEvaluationState::Disabled,
                    now,
                );
                continue;
            }
            if rule.policy.mode == discovery_core::AlertMode::Event {
                self.eval_event_rule(rule, &device, &metrics, now).await;
                continue;
            }

            let level = parse_level(&rule.level);
            let clear_after =
                chrono::Duration::seconds(rule.clear_after_seconds.unwrap_or(0) as i64);

            // `row_metric` (2026-08-29, direct user request — "тревога по порту") splits
            // evaluation in two: `None` is every rule that existed before this field, one
            // evaluation/incident for the whole device; `Some` evaluates the same
            // expressions once per row of the declared table metric instead, each row its
            // own independent incident. See `AlertRule::row_metric`'s docs.
            match &rule.row_metric {
                None => {
                    self.eval_device_level_rule(rule, &device, &metrics, level, clear_after, now)
                        .await
                }
                Some(row_metric) => {
                    self.eval_row_scoped_rule(
                        rule,
                        row_metric,
                        &device,
                        &metrics,
                        level,
                        clear_after,
                        now,
                    )
                    .await
                }
            }
        }
        self.eval_response_escalation(&device, now).await;
        self.save_runtime(&device).await?;
        Ok(())
    }
}

impl AlertEvalHandler {
    /// Evaluates health dimensions independent of profile-authored alert rules. Reserved
    /// names keep device reachability, SNMP reachability, and each stale metric separate,
    /// while reusing the normal persistence and notification lifecycle.
    async fn eval_system_alerts(
        &self,
        device: &Device,
        profile: Option<&discovery_dsl::ProfileFile>,
        records: &[MetricRecord],
        now: chrono::DateTime<chrono::Utc>,
    ) {
        self.eval_system_alert(
            device,
            SYSTEM_DEVICE_DOWN,
            None,
            device.ping_ok == Some(false),
            device.ping_ok == Some(true),
            AlertLevel::Critical,
            "Устройство не отвечает на ping",
            now,
        )
        .await;
        self.eval_system_alert(
            device,
            SYSTEM_SNMP_DOWN,
            None,
            device.snmp_ok == Some(false),
            device.snmp_ok == Some(true),
            AlertLevel::Critical,
            "SNMP недоступен",
            now,
        )
        .await;

        let stale = profile
            .map(|p| stale_metric_names(p, records, now, 15))
            .unwrap_or_default();
        for name in &stale {
            self.eval_system_alert(
                device,
                SYSTEM_STALE_METRIC,
                Some(name),
                true,
                false,
                AlertLevel::Warning,
                &format!("Метрика '{name}' не обновляется вовремя"),
                now,
            )
            .await;
        }

        // Recovery, disabling, or profile removal removes a metric from `stale`; close its
        // previously-open row explicitly because it is not visited by the activation loop.
        for alert in self.alerts.active_alerts_for_device(device.id) {
            if alert.name == SYSTEM_STALE_METRIC
                && alert
                    .row_key
                    .as_ref()
                    .is_some_and(|key| !stale.contains(key))
            {
                let metric = alert.row_key.as_deref().unwrap_or("?");
                self.eval_system_alert(
                    device,
                    SYSTEM_STALE_METRIC,
                    Some(metric),
                    false,
                    true,
                    alert.level,
                    &format!("Метрика '{metric}' снова обновляется"),
                    now,
                )
                .await;
            }
        }
    }

    async fn eval_system_alert(
        &self,
        device: &Device,
        name: &str,
        row_key: Option<&str>,
        activation_true: bool,
        deactivation_true: bool,
        level: AlertLevel,
        message: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        let transition = self.alerts.observe(
            device.id,
            &device.facts.ip,
            name,
            row_key,
            level,
            message.to_string(),
            Some(serde_json::json!({
                "system_alert": name,
                "metric": row_key,
            })),
            activation_true,
            deactivation_true,
            None,
            chrono::Duration::zero(),
            now,
        );
        self.persist_transition(
            transition,
            (device.id, name.to_string(), row_key.map(str::to_string)),
            device.profile.clone(),
            now,
        )
        .await;
    }

    /// Closes incidents whose rule no longer exists in the current profile. Disabled rules
    /// remain intentionally frozen, including their old row scope; maintenance is checked
    /// by the caller before this method, so it also preserves the global freeze contract.
    async fn clear_removed_rules(
        &self,
        device: &Device,
        rules: &[AlertRule],
        now: chrono::DateTime<chrono::Utc>,
    ) {
        let open = self.alerts.active_alerts_for_device(device.id);
        for alert in open {
            let Some(rule) = rules.iter().find(|rule| {
                rule.name == alert.name
                    || alert.name.strip_suffix(".flapping") == Some(rule.name.as_str())
            }) else {
                if is_system_alert(&alert.name) {
                    continue;
                }
                self.clear_removed_alert(device, alert, now).await;
                continue;
            };
            if !rule.enabled {
                continue;
            }
            let Ok(rule) = self.resolve_rule(rule) else {
                continue;
            };
            if !matches!(
                rule.policy.mode,
                discovery_core::AlertMode::Change | discovery_core::AlertMode::Event
            ) && rule.row_metric.is_some() != alert.row_key.is_some()
            {
                self.clear_removed_alert(device, alert, now).await;
            }
        }
    }

    async fn clear_removed_alert(
        &self,
        device: &Device,
        alert: Alert,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        let details = alert.details.clone();
        let transition = self.alerts.observe(
            device.id,
            &device.facts.ip,
            &alert.name,
            alert.row_key.as_deref(),
            alert.level,
            format!("Правило '{}' удалено из активного профиля", alert.name),
            alert.facts.clone(),
            false,
            true,
            None,
            chrono::Duration::zero(),
            now,
        );
        self.finish_rule_transition(transition, device, alert.row_key.as_deref(), details, now)
            .await;
    }

    /// The device-level path — unchanged behavior from before row-scoped alerts existed,
    /// just factored out so [`Self::eval_row_scoped_rule`] can share the exact same
    /// activation/deactivation/facts/message/persist logic instead of a parallel copy.
    ///
    /// Activation condition failing to evaluate (syntax error, etc.) fails safe as "not
    /// activating". Deactivation, when the rule declares its own expression, fails safe
    /// the *other* direction — "not clearing" — so a broken expression can't silently
    /// close an open incident; when the rule has no `deactivation_expression` at all,
    /// deactivation is simply the negation of activation (the only behavior that existed
    /// before that field, see `AlertRule::deactivation_expression`'s docs).
    async fn eval_device_level_rule(
        &self,
        rule: &AlertRule,
        device: &Device,
        metrics: &Metrics,
        _level: AlertLevel,
        _clear_after: chrono::Duration,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        let missing = self
            .alert_engine
            .references_missing_metric(&rule.expression, metrics)
            || rule
                .deactivation_expression
                .as_deref()
                .is_some_and(|expr| self.alert_engine.references_missing_metric(expr, metrics));
        self.observe_rule(rule, device, metrics, None, None, missing, now)
            .await;
    }

    /// The row-scoped path (2026-08-29, direct user request — "тревога по порту"):
    /// `rule.expression`/`deactivation_expression`/`facts_expression`/`message` evaluate
    /// once per row of `metrics.<row_metric>`, each with `row` bound in scope (see
    /// `AlertEvaluator::evaluate_condition`'s docs) — same logic
    /// [`Self::eval_device_level_rule`] uses, just per-row instead of once. Each row's own
    /// tracking identity comes from `AlertEvaluator::evaluate_row_key`
    /// (`rule.row_key_expression`, or the row's own SNMP index by default).
    ///
    /// `metrics.get(row_metric)` not being a `MetricValue::Table` at all (metric hasn't
    /// polled yet, misconfigured to point at a scalar, ...) is treated as "zero rows this
    /// tick", not an error — same graceful-degradation philosophy every other missing-data
    /// case in this pipeline already follows.
    ///
    /// After evaluating every row actually present, also checks for rows that were open
    /// on a *previous* tick but are missing from this one entirely (not just failing their
    /// own deactivation condition) — the underlying row vanished from the table (e.g. a
    /// port disappearing from `ifTable`, not just going down). Those clear through the
    /// exact same `observe`/`clear_after`/persist path as any other deactivation, tagged
    /// `AutoClearReason::RowMissing` so the dashboard can label them "Утеряна" instead of
    /// "Закрыта" — see that type's docs for why this is a label, not a different lifecycle.
    #[allow(clippy::too_many_arguments)]
    async fn eval_row_scoped_rule(
        &self,
        rule: &AlertRule,
        row_metric: &str,
        device: &Device,
        metrics: &Metrics,
        _level: AlertLevel,
        _clear_after: chrono::Duration,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        let rows: &[MetricTableRow] = match metrics.get(row_metric) {
            Some(MetricValue::Table(rows)) => rows.as_slice(),
            _ => &[],
        };

        let mut seen_row_keys: std::collections::HashSet<String> = std::collections::HashSet::new();

        for row in rows {
            let row_key = match self.alert_engine.evaluate_row_key(
                rule.row_key_expression.as_deref(),
                &device.facts,
                metrics,
                row,
            ) {
                Ok(k) => k,
                Err(e) => {
                    self.record_error(rule, device, Some(&row.index), e.to_string(), now);
                    return;
                }
            };
            seen_row_keys.insert(row_key.clone());

            self.observe_rule(rule, device, metrics, Some(row), Some(&row_key), false, now)
                .await;
        }

        for missing in self.alerts.open_row_alerts(device.id, &rule.name) {
            // `open_row_alerts` already filters to `row_key.is_some()` — `unwrap_or`
            // here is defensive, not load-bearing.
            let row_key = missing.row_key.clone().unwrap_or_default();
            if seen_row_keys.contains(&row_key) {
                continue; // still there this tick — handled by the loop above already
            }
            self.observe_rule(rule, device, metrics, None, Some(&row_key), true, now)
                .await;
        }
    }

    /// Single write path for an `AlertStateTracker::observe` result — shared by
    /// [`Self::eval_device_level_rule`] and [`Self::eval_row_scoped_rule`]'s per-row loop
    /// and its missing-row loop. Thin wrapper over [`persist_alert_transition`].
    pub(crate) async fn persist_transition(
        &self,
        transition: AlertTransition,
        key: (uuid::Uuid, String, Option<String>),
        profile: Option<String>,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        persist_alert_transition(
            &self.alert_store,
            &self.still_active_last_persisted,
            &self.notification_rules,
            &self.notification_channels,
            &self.auth,
            &self.queue,
            &self.correlator,
            transition,
            key,
            profile,
            now,
        )
        .await;
    }
}

/// Single write path for an `AlertStateTracker::observe` result: persists a genuine
/// `Activated`/`Cleared` transition (or a `StillActive` one that's due per
/// `STILL_ACTIVE_PERSIST_INTERVAL`'s throttle) via `AlertStore::upsert`, then dispatches
/// notifications for `Activated`/`Cleared` only.
async fn persist_alert_transition(
    alert_store: &Arc<dyn discovery_alerts::AlertStore>,
    still_active_last_persisted: &StillActivePersistMap,
    notification_rules: &Arc<dyn discovery_config_store::NotificationRuleStore>,
    notification_channels: &Arc<dyn discovery_config_store::NotificationChannelStore>,
    auth: &Arc<dyn discovery_auth::AuthStore>,
    queue: &Arc<dyn JobQueueStore>,
    correlator: &Arc<GroupAlertCorrelator>,
    transition: AlertTransition,
    key: (uuid::Uuid, String, Option<String>),
    profile: Option<String>,
    now: chrono::DateTime<chrono::Utc>,
) {
    // `NotificationTrigger` alongside the alert itself — `None` for `StillActive` (never
    // dispatches, see `dispatch_alert_notifications`'s docs) and the throttled-away branch
    // of `StillActive`, `Some` for a genuine `Activated`/`Cleared`.
    let persisted: Option<(Alert, Option<NotificationTrigger>)> = match transition {
        AlertTransition::Activated(mut a) => {
            // Reopen linking (2026-09-17, audit finding #4) — see
            // `Alert::reopened_from_alert_id`'s docs and `AlertStore::find_recent_manual_close`'s
            // for the full mechanism. `AlertStateTracker` is purely in-memory and has no
            // store access to decide this itself (same split as `suppressed_by_alert_id`),
            // so it's resolved here, right before the first persist of a brand-new incident.
            match alert_store
                .find_recent_manual_close(key.0, &key.1, key.2.as_deref(), now - REOPEN_LINK_WINDOW)
                .await
            {
                Ok(Some(previous)) => {
                    info!(ip = %a.device_ip, alert = %a.name, row_key = ?a.row_key, previous_alert_id = %previous.id, "alert reopened — linking to the manually closed alert it followed");
                    a.reopened_from_alert_id = Some(previous.id);
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(ip = %a.device_ip, alert = %a.name, error = %e, "failed to check for a recent manual close — persisting without a reopened_from_alert_id link")
                }
            }
            still_active_last_persisted.insert(
                key,
                (
                    now,
                    a.message.clone(),
                    a.flapping,
                    a.suppression_reason.clone(),
                ),
            );
            warn!(ip = %a.device_ip, alert = %a.name, row_key = ?a.row_key, "alert activated");
            let trigger = (!a.flapping).then_some(NotificationTrigger::Activated);
            Some((a, trigger))
        }
        AlertTransition::Cleared(a) => {
            still_active_last_persisted.remove(&key);
            info!(ip = %a.device_ip, alert = %a.name, row_key = ?a.row_key, auto_clear_reason = ?a.auto_clear_reason, "alert cleared");
            let trigger = (!a.flapping).then_some(NotificationTrigger::Cleared);
            Some((a, trigger))
        }
        AlertTransition::StillActive(a) => {
            // Throttled: skip the write if the message hasn't changed since the last one
            // *and* it's still within `STILL_ACTIVE_PERSIST_INTERVAL` — see
            // `still_active_last_persisted`'s docs.
            let due = match still_active_last_persisted.get(&key) {
                Some(entry) => {
                    entry.1 != a.message
                        || entry.2 != a.flapping
                        || entry.3 != a.suppression_reason
                        || now - entry.0 >= STILL_ACTIVE_PERSIST_INTERVAL
                }
                None => true,
            };
            if due {
                still_active_last_persisted.insert(
                    key,
                    (
                        now,
                        a.message.clone(),
                        a.flapping,
                        a.suppression_reason.clone(),
                    ),
                );
                Some((a, None))
            } else {
                None
            }
        }
        AlertTransition::None => None,
    };
    if let Some((alert, trigger)) = persisted {
        if let Err(e) = alert_store.upsert(&alert).await {
            warn!(ip = %alert.device_ip, alert = %alert.name, error = %e, "failed to persist alert transition");
        } else if let Some(trigger) = trigger {
            // Group-correlation suppression gate (2026-09-20) — decided here, between the
            // persist and the dispatch, so a group-suppressed effect's *notification* is
            // held back the moment it activates, not up to a sweep-interval later. See
            // `notification_held_for_suppression`'s docs for the per-trigger logic (and
            // the deliberate safe direction: every failure path dispatches).
            if notification_held_for_suppression(correlator, alert_store, &alert, trigger).await {
                if trigger == NotificationTrigger::Activated {
                    info!(ip = %alert.device_ip, alert = %alert.name, alert_id = %alert.id, "notification dispatch held — activation is group-suppressed");
                } else {
                    info!(ip = %alert.device_ip, alert = %alert.name, alert_id = %alert.id, "notification dispatch held — clearing a group-suppressed incident that was never announced");
                }
            } else {
                dispatch_alert_notifications(
                    notification_rules,
                    notification_channels,
                    auth,
                    queue,
                    &alert,
                    profile.as_deref(),
                    trigger,
                    now,
                )
                .await;
            }
        } else {
            maybe_dispatch_repeated_alert(
                alert_store,
                notification_rules,
                notification_channels,
                auth,
                queue,
                &alert,
                profile.as_deref(),
                now,
            )
            .await;
        }
    }
}

async fn maybe_dispatch_repeated_alert(
    alert_store: &Arc<dyn discovery_alerts::AlertStore>,
    notification_rules: &Arc<dyn discovery_config_store::NotificationRuleStore>,
    notification_channels: &Arc<dyn discovery_config_store::NotificationChannelStore>,
    auth: &Arc<dyn discovery_auth::AuthStore>,
    queue: &Arc<dyn JobQueueStore>,
    alert: &Alert,
    profile: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
) {
    let Some(mut current) = (match alert_store.get(alert.id).await {
        Ok(value) => value,
        Err(error) => {
            warn!(alert = %alert.name, error = %error, "failed to load alert for repeat notification");
            return;
        }
    }) else {
        return;
    };
    let Ok(rules) = notification_rules.list_all().await else {
        return;
    };
    let due = rules.iter().any(|rule| {
        rule.matches(
            &current.device_ip,
            profile,
            current.device_id,
            current.level,
            now,
        ) && rule.matches_alert(&current)
            && rule.repeat_due(&current, now)
    });
    if !due {
        return;
    }

    current.repeat_count = current.repeat_count.saturating_add(1);
    current.escalation_level = rules
        .iter()
        .flat_map(|rule| rule.escalation_levels.iter())
        .filter(|level| current.repeat_count >= level.after_repeats)
        .map(|level| level.after_repeats)
        .max()
        .unwrap_or(0);
    current.escalation_reason = rules
        .iter()
        .flat_map(|rule| rule.escalation_levels.iter())
        .filter(|level| current.repeat_count >= level.after_repeats)
        .max_by_key(|level| level.after_repeats)
        .and_then(|level| level.reason.clone());
    current.repeated_at = Some(now);
    if alert_store.upsert(&current).await.is_ok() {
        dispatch_alert_notifications(
            notification_rules,
            notification_channels,
            auth,
            queue,
            &current,
            profile,
            NotificationTrigger::Repeated,
            now,
        )
        .await;
    }
}

/// Reactive group-correlation suppression gate, called between a successful `Activated`/
/// `Cleared` persist and `dispatch_alert_notifications`. Returns `true` when the
/// transition's notification must be **held** (skipped), `false` when it may dispatch.
///
/// * **`Activated`** — `GroupAlertCorrelator::react_to_activation` persists
///   `suppressed_by_alert_id` via `AlertStore::set_suppression` (the single writer of that
///   column, see its docs) and returns the root cause's id; `Some` → hold. Runs on the
///   notification hot path, but its fast path is a pure in-memory snapshot lookup
///   (`CorrelationSnapshot` with no directed upstream for this device → `Ok(None)` without
///   a single store round trip), one small bounded `list()` per direct upstream otherwise.
/// * **`Cleared`** — reads the *persisted* row right after the upsert and holds when
///   `suppressed_by_alert_id` is set: an incident that was never announced (its activation
///   notification was held) must not announce its recovery either — that would reveal the
///   incident through the backdoor. Best-effort: if the sweep already cleared suppression
///   in the gap, it notifies as it always used to — acceptable, a recovery notice for an
///   independently-subsequent incident.
///
/// **Safe direction on every failure path is `false` (dispatch).** A notification for a
/// suppressed alert is recoverable noise; *suppressing* one that a rule decided should go
/// out is a missed incident. The reactive path also never errors in a way that leaves a
/// half-persisted suppression: `react_to_activation` completes its `set_suppression`
/// before returning, so `true` here always means the DB already carries the suppression.
async fn notification_held_for_suppression(
    correlator: &Arc<GroupAlertCorrelator>,
    alert_store: &Arc<dyn discovery_alerts::AlertStore>,
    alert: &Alert,
    trigger: NotificationTrigger,
) -> bool {
    match trigger {
        NotificationTrigger::Activated => {
            match correlator.react_to_activation(alert_store, alert).await {
                Ok(Some(_root_alert_id)) => true,
                Ok(None) => false,
                Err(e) => {
                    warn!(error = %e, ip = %alert.device_ip, alert = %alert.name, alert_id = %alert.id, "group correlation failed on activation — notifying anyway (safe default)");
                    false
                }
            }
        }
        NotificationTrigger::Cleared => match alert_store.get(alert.id).await {
            Ok(Some(row)) => row.suppressed_by_alert_id.is_some(),
            Ok(None) => false,
            Err(e) => {
                warn!(error = %e, ip = %alert.device_ip, alert = %alert.name, alert_id = %alert.id, "failed to read the persisted alert for the clear-side suppression check — notifying anyway");
                false
            }
        },
        NotificationTrigger::Repeated => false,
        NotificationTrigger::Escalated | NotificationTrigger::Deescalated => {
            alert.suppressed_by_alert_id.is_some()
        }
    }
}

/// Notification matrix dispatch (2026-09-10, direct user request: "Реализуй каналы
/// нотификации + матрицу нотификации") — called from [`persist_alert_transition`] right
/// after a *successful* `Activated`/`Cleared` persist, never for `StillActive`:
/// re-notifying an already-open incident on every tick would be alert spam/escalation, a
/// distinct future feature `docs/Roadmap.md` tracks separately from the matrix itself (see
/// `discovery_core::NotificationTrigger`'s docs).
///
/// **One `QueueKind::NotificationDispatch` job per matched, `enabled` channel — not one job
/// covering the whole transition's recipient list.** See
/// `discovery_core::QueueKind::NotificationDispatch`'s docs for why: a job covering several
/// channels would risk re-sending to channels that already succeeded if the queue's own
/// retry/backoff (`JobQueueStore`) ever kicks in for a *different* channel's transient
/// failure. Recipients/channels are resolved here, synchronously with the persist that
/// triggered them, specifically so each resulting job is scoped to exactly one
/// already-resolved channel — `NotificationDispatchHandler` never needs to re-run the
/// matching logic itself.
pub(crate) async fn dispatch_alert_notifications(
    notification_rules: &Arc<dyn discovery_config_store::NotificationRuleStore>,
    notification_channels: &Arc<dyn discovery_config_store::NotificationChannelStore>,
    auth: &Arc<dyn discovery_auth::AuthStore>,
    queue: &Arc<dyn JobQueueStore>,
    alert: &Alert,
    profile: Option<&str>,
    trigger: NotificationTrigger,
    now: chrono::DateTime<chrono::Utc>,
) {
    let rules = match retry_notification_store("notification rules", || {
        notification_rules.list_all()
    })
    .await
    {
        Ok(rules) => rules,
        Err(e) => {
            warn!(alert = %alert.name, error = %e, "failed to load notification rules after retries — skipping notification dispatch for this transition");
            return;
        }
    };

    let matched_rules: Vec<_> = rules
        .iter()
        .filter(|rule| {
            rule.enabled
                && rule.wants_trigger(trigger)
                && rule.matches_alert(alert)
                && rule.matches(&alert.device_ip, profile, alert.device_id, alert.level, now)
        })
        .collect();
    if matched_rules.is_empty() {
        return;
    }

    // `RecipientRef::Role` entries resolve to their *current* members here, not a
    // snapshot taken when the rule was saved (2026-09-18, "Матрица нотификаций — роль как
    // группа получателей" — see `discovery_config_store::RecipientRef`'s docs for why a
    // role is reused as a proxy-group instead of a new entity). One batch `list_users()`
    // call regardless of how many matched rules/role-recipients there are — same "батч
    // вместо цикла на hot path" posture as the `list_for_users` call below, not a
    // per-role round trip.
    let users =
        match retry_notification_store("notification recipients", || auth.list_users()).await {
            Ok(users) => users,
            Err(error) => {
                warn!(%error,"failed to resolve notification recipients");
                return;
            }
        };
    let evaluator = discovery_dsl::AlertEvaluator::new();
    let mut recipients = std::collections::HashSet::<uuid::Uuid>::new();
    for rule in matched_rules {
        for user in &users {
            let selected = rule
                .recipients_for_repeat(alert.repeat_count)
                .iter()
                .any(|r| match r {
                    discovery_config_store::RecipientRef::User(id) => *id == user.id,
                    discovery_config_store::RecipientRef::Role { role } => {
                        user.role_id == Some(*role)
                    }
                });
            if !selected {
                continue;
            }
            if !user.is_admin
                && !alert.details.policy.viewer_roles.is_empty()
                && !user
                    .role_id
                    .is_some_and(|id| alert.details.policy.viewer_roles.contains(&id))
            {
                continue;
            }
            if let Some(expr) = &rule.selection.recipient_expression {
                let facts = discovery_core::DeviceFacts {
                    ip: alert.device_ip.clone(),
                };
                let extra = serde_json::json!({"alert":alert,"user":{"id":user.id,"username":user.username,"role_id":user.role_id}});
                match evaluator.evaluate_context(
                    expr,
                    &facts,
                    None,
                    None,
                    &Metrics::default(),
                    None,
                    &extra,
                ) {
                    Ok(value) if value.as_bool() == Some(true) => {}
                    Ok(_) => continue,
                    Err(error) => {
                        warn!(%error,rule=%rule.name,"notification recipient expression failed");
                        continue;
                    }
                }
            }
            recipients.insert(user.id);
        }
    }
    if recipients.is_empty() {
        return;
    }
    let recipients: Vec<uuid::Uuid> = recipients.into_iter().collect();

    // Batch, not a `list_for_user` call per recipient — see
    // `discovery_config_store::NotificationChannelStore::list_for_users`'s docs.
    let channels = match retry_notification_store("notification channels", || {
        notification_channels.list_for_users(&recipients)
    })
    .await
    {
        Ok(channels) => channels,
        Err(e) => {
            warn!(alert = %alert.name, error = %e, "failed to load notification channels — skipping notification dispatch for this transition");
            return;
        }
    };

    for channel in channels.iter().filter(|c| c.enabled) {
        let payload = match serde_json::to_value(NotificationDispatchPayload {
            channel_id: channel.id,
            alert_id: alert.id,
            alert: alert.clone(),
            trigger,
        }) {
            Ok(p) => p,
            Err(e) => {
                warn!(alert = %alert.name, channel_id = %channel.id, error = %e, "failed to serialize notification dispatch payload");
                continue;
            }
        };
        // A dedupe key defends against this somehow running twice for the exact same
        // (alert, channel, trigger) — not expected in normal operation (this only runs
        // once per successful `alert_store.upsert()` call), but cheap insurance against
        // ever double-sending the same event to the same channel, same spirit as
        // `SnmpPoll`'s ip-keyed dedupe.
        let dedupe_key = format!("notify:{}:{}:{}", alert.id, channel.id, trigger.as_str());
        if let Err(e) = queue
            .enqueue(QueueKind::NotificationDispatch, payload, Some(&dedupe_key))
            .await
        {
            warn!(alert = %alert.name, channel_id = %channel.id, error = %e, "failed to enqueue notification dispatch job");
        }
    }
}

/// Notification fan-out runs after the alert transition has already been persisted, so a
/// transient store failure here must not turn into a permanent lost notification. Keep the
/// retry deliberately short and bounded: the delivery queue still owns provider retries, while
/// this covers brief DB contention/connection failures before the fan-out jobs exist.
async fn retry_notification_store<T, F, Fut>(label: &str, mut operation: F) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    const MAX_ATTEMPTS: usize = 3;
    for attempt in 0..MAX_ATTEMPTS {
        match operation().await {
            Ok(value) => return Ok(value),
            Err(error) if attempt + 1 < MAX_ATTEMPTS => {
                let delay_ms = 50_u64 << attempt;
                warn!(label, attempt = attempt + 1, delay_ms, error = %error, "notification fan-out store read failed; retrying");
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }
            Err(error) => {
                return Err(
                    error.context(format!("{label} read failed after {MAX_ATTEMPTS} attempts"))
                )
            }
        }
    }
    unreachable!("the bounded retry loop always returns")
}

fn parse_level(s: &str) -> AlertLevel {
    match s {
        "critical" => AlertLevel::Critical,
        "warning" => AlertLevel::Warning,
        _ => AlertLevel::Info,
    }
}

/// `sysUpTime.0` — a lightweight probe every SNMP agent implements, used purely to answer
/// "does SNMP itself answer right now", not to read anything meaningful from the value.
const SYS_UPTIME_OID: &str = "1.3.6.1.2.1.1.3.0";

/// Recurring ping+SNMP reachability check — **independent of the profile pipeline above**
/// (`SnmpPoll` -> `Dedup` -> `ProfileApply` -> `MetricPoll` -> `AlertEval`). Its chain is
/// started by [`DedupHandler`] right after `resolve()`, not by `ProfileApplyHandler` like
/// `MetricPoll` — a device that never matches any profile still gets checked, since "is it
/// even answering" doesn't depend on which (if any) profile applies to it. Writes straight
/// to [`discovery_core::Device`]'s `ping_ok`/`snmp_ok`/`*_checked_at` fields via
/// [`DeviceStore::set_reachability`] — deliberately not a `device_metrics` row, see that
/// struct's docs (direct user request, 2026-08-16/17: "это будет ещё одна колонка на
/// дашборд... но эта колонка будет в отдельном поле").
///
/// SNMP status is a lightweight [`SYS_UPTIME_OID`] `GET` using whatever credentials
/// `SnmpPoll` already negotiated (`device.snmp_credentials`) — never a full profile
/// re-poll. `Some(false)` immediately, with no network I/O, if no credentials exist yet
/// (nothing to poll with).
///
/// No `generation` guard (unlike `MetricPoll`) — there's no profile epoch to be scoped to,
/// see [`discovery_core::payload::ReachabilityPollPayload`]'s docs. The chain just keeps
/// ticking at `poll_interval` until `get_device` returns `None` (device deleted), at which
/// point it silently stops — same stale-chain stop condition as `MetricPoll`, minus the
/// generation check that doesn't apply here.
///
/// **Device-level master switch (added 2026-08-16, direct user request — "мне нужна
/// возможность выключать устройства").** `Device::enabled = false` skips the actual
/// ping/SNMP work for a tick — `ping_ok`/`snmp_ok` are simply left at their last values,
/// not reset — but the chain keeps ticking regardless, so re-enabling takes effect on the
/// very next tick with no restart.
pub struct ReachabilityPollHandler {
    pub store: Arc<dyn JobQueueStore>,
    pub devices: Arc<dyn DeviceStore>,
    pub snmp: Arc<dyn SnmpClient>,
    pub pinger: Arc<dyn discovery_ping::Pinger>,
    pub discovery_configs: Arc<dyn DiscoveryConfigStore>,
    /// `poll_intervals.reachability_secs`, read fresh (not cached) right before each
    /// self-reschedule — direct user request 2026-08-16: settings live in the database and
    /// an edit must apply without a restart, see `SettingsStore`'s docs.
    pub settings: Arc<dyn SettingsStore>,
}

#[async_trait]
impl JobHandler for ReachabilityPollHandler {
    async fn handle(&self, job: Job) -> anyhow::Result<()> {
        let payload: ReachabilityPollPayload = serde_json::from_value(job.payload)?;

        let Some(device) = self.devices.get_device(payload.device_id).await? else {
            return Ok(()); // device deleted — chain stops silently, same as MetricPoll
        };

        // Device-level master switch (direct user request 2026-08-16: "мне нужна
        // возможность выключать устройства") — skip the actual ping/SNMP work while
        // disabled, but keep the chain alive (reschedule below runs unconditionally), so
        // re-enabling picks up automatically on the very next tick. `ping_ok`/`snmp_ok`
        // are simply left at whatever they last were — frozen, not reset.
        if device.enabled {
            // Timeout/retries read fresh from `SettingsStore` every tick — direct user
            // correction 2026-08-18, see `discovery_core::PingConfig`'s docs.
            let ping_config = self.settings.ping_config().await;
            let ping_outcome = self
                .pinger
                .ping(
                    &device.facts.ip,
                    Duration::from_millis(ping_config.timeout_ms),
                    ping_config.retries,
                )
                .await;
            let ping_ok = ping_outcome.reachable;

            let snmp_ok = match &device.snmp_credentials {
                Some(creds) => {
                    // Timeout/retries looked up fresh from the subnet config every cycle,
                    // same as `SnmpPollHandler`/`MetricPollHandler` — a config edit takes
                    // effect on this chain's very next tick, not just at negotiation time.
                    let configs = self.discovery_configs.load_all().await.unwrap_or_default();
                    let subnet_spec = find_subnet_spec_for_ip(&configs, &device.facts.ip);
                    let timeout_ms = subnet_spec
                        .as_ref()
                        .and_then(|s| s.snmp_timeout_ms)
                        .unwrap_or_else(default_snmp_timeout_ms);
                    let retries = subnet_spec
                        .as_ref()
                        .and_then(|s| s.snmp_retries)
                        .unwrap_or_else(default_snmp_retries);
                    let target = DeviceTarget {
                        ip: device.facts.ip.clone(),
                        port: creds.port,
                        auth: creds.auth.clone(),
                        timeout_ms,
                        retries,
                    };
                    self.snmp.get(&target, SYS_UPTIME_OID).await.is_ok()
                }
                None => false, // nothing negotiated yet — nothing to poll with
            };

            // **Not `?`** — deliberately caught and logged here rather than propagated,
            // unlike the lookups above this block. A transient DB error on this single
            // write (e.g. `SQLITE_BUSY` under concurrent discoverer/worker load — found
            // live 2026-09-18 while preparing the demo park, see
            // `docs/Changelog/2026-09-18 - Fix ReachabilityPollHandler умирает после
            // SQLITE_BUSY.md`) must never stop this tick's self-reschedule below: this is
            // a recurring self-reenqueuing chain (see `.claude/rules/engineering-patterns.md`'s
            // "Generation guard + ActiveChains" section), and the *only* thing that keeps
            // it alive is reaching the `tokio::spawn` below on every single tick, success
            // or failure — a `?` here would propagate out of `handle()` before that point
            // and, once the queue's own retry/backoff for *this* job is exhausted, freeze
            // `ping_ok`/`snmp_ok` for this device forever (no self-heal short of a full
            // process restart re-seeding `reachability_chains`). Worth retrying on its own
            // per-tick cadence exactly like `MetricPollHandler` treats a failed metric poll
            // (see that handler's `last_polled`/`last_polled_date` docs) rather than
            // treated as fatal to the chain itself.
            match self
                .devices
                .set_reachability(payload.device_id, ping_ok, ping_outcome.loss_pct, snmp_ok)
                .await
            {
                Ok(()) => {
                    // Reachability is an independent source of truth, so wake the alert
                    // evaluator here instead of waiting for the next metric poll. This
                    // keeps device_down/snmp_down transitions close to the probe result.
                    if let Ok(alert_payload) = serde_json::to_value(AlertEvalPayload {
                        event: None,
                        device_id: payload.device_id,
                    }) {
                        let _ = self
                            .store
                            .enqueue(QueueKind::AlertEval, alert_payload, None)
                            .await;
                    }
                }
                Err(e) => {
                    warn!(device_id = %payload.device_id, error = %e, "failed to persist reachability this tick — will retry next tick");
                }
            }
        }

        let store = self.store.clone();
        let device_id = payload.device_id;
        let settings = self.settings.clone();
        tokio::spawn(async move {
            let poll_interval =
                Duration::from_secs(settings.poll_intervals().await.reachability_secs);
            tokio::time::sleep(jittered(poll_interval)).await;
            if let Ok(payload) = serde_json::to_value(ReachabilityPollPayload { device_id }) {
                let _ = store
                    .enqueue(QueueKind::ReachabilityPoll, payload, None)
                    .await;
            }
        });

        Ok(())
    }
}

/// The one synthetic table-metric name every profile's `service_checks.checks` list lands
/// in, whole (rewritten every tick, not merged) — see
/// `discovery_dsl::ServiceChecksSection`'s docs.
const SERVICE_CHECKS_METRIC_NAME: &str = "service_checks";

pub(crate) fn resolve_service_check_host(
    target: Option<&str>,
    device_ip: &str,
) -> Result<String, String> {
    match target {
        None => Ok(device_ip.to_string()),
        Some(target) if target == device_ip => Ok(target.to_string()),
        Some(_) => Err("service-check target must equal the device management IP".to_string()),
    }
}

/// Fallback per-check timeout when a `ServiceCheckSpec` doesn't set its own `timeout_ms` —
/// see that field's docs. Distinct from `discovery_core::PingConfig`'s timeout (ICMP is a
/// materially different, much cheaper probe than a TCP handshake/HTTP round trip/SSH
/// banner read), so this isn't read from `SettingsStore` — a fixed, generous-enough
/// default, same "not every knob needs a dashboard setting" judgment call as several other
/// constants in this file (e.g. `SYS_UPTIME_OID`'s use above).
const DEFAULT_SERVICE_CHECK_TIMEOUT_MS: u64 = 2000;

fn to_check_protocol(
    p: discovery_dsl::ServiceCheckProtocol,
) -> discovery_servicecheck::CheckProtocol {
    match p {
        discovery_dsl::ServiceCheckProtocol::Tcp => discovery_servicecheck::CheckProtocol::Tcp,
        discovery_dsl::ServiceCheckProtocol::Http => discovery_servicecheck::CheckProtocol::Http,
        discovery_dsl::ServiceCheckProtocol::Https => discovery_servicecheck::CheckProtocol::Https,
        discovery_dsl::ServiceCheckProtocol::Ssh => discovery_servicecheck::CheckProtocol::Ssh,
    }
}

fn service_check_protocol_str(p: discovery_dsl::ServiceCheckProtocol) -> &'static str {
    match p {
        discovery_dsl::ServiceCheckProtocol::Tcp => "tcp",
        discovery_dsl::ServiceCheckProtocol::Http => "http",
        discovery_dsl::ServiceCheckProtocol::Https => "https",
        discovery_dsl::ServiceCheckProtocol::Ssh => "ssh",
    }
}

/// One `metrics.service_checks` row for `check`'s outcome this tick — `index` is the
/// check's own author-chosen `name` (see `ServiceCheckSpec`'s docs for why, unlike a real
/// SNMP table, there's no device-reported identity to key off instead). `latency_ms`/
/// `error` are only present when meaningful (`Option` -> absent field, same "not every
/// column guaranteed present" convention `build_metric_table` uses for real SNMP tables),
/// not forced to a sentinel value like `0`/`""`.
fn service_check_row(
    check: &discovery_dsl::ServiceCheckSpec,
    host: &str,
    outcome: &discovery_servicecheck::CheckOutcome,
) -> MetricTableRow {
    let mut fields = BTreeMap::new();
    fields.insert("name".to_string(), MetricValue::Str(check.name.clone()));
    fields.insert(
        "protocol".to_string(),
        MetricValue::Str(service_check_protocol_str(check.protocol).to_string()),
    );
    fields.insert(
        "target".to_string(),
        MetricValue::Str(format!("{host}:{}", check.port)),
    );
    fields.insert("ok".to_string(), MetricValue::Bool(outcome.ok));
    if let Some(latency) = outcome.latency_ms {
        fields.insert("latency_ms".to_string(), MetricValue::Int(latency as i64));
    }
    if let Some(err) = &outcome.error {
        fields.insert("error".to_string(), MetricValue::Str(err.clone()));
    }
    MetricTableRow {
        index: check.name.clone(),
        fields,
    }
}

/// Stage 6 (a third, independent collection protocol alongside SNMP metric polling and
/// ping/SNMP reachability): recurring L4/L7 service checks (TCP-connect / HTTP(S)
/// status+body / SSH banner) per the matched profile's `service_checks.checks` list —
/// added 2026-09-07, direct roadmap item ("Сервис-чеки L4/L7 — третий протокол сбора рядом
/// с ping/SNMP").
///
/// **Profile-scoped, unlike `ReachabilityPollHandler`** — which checks (if any) to run
/// varies per profile, so this chain is started/restarted exactly like `MetricPoll`'s: by
/// `ProfileApplyHandler`, on the same `generation` guard, alongside (not instead of)
/// `MetricPoll`'s own chain. A device with an empty `service_checks.checks` list (the
/// common case for most profiles today) simply never gets this chain going anywhere —
/// `handle` returns immediately, no reschedule, same "a future profile change restarts the
/// chain via the generation guard" contract `MetricPollHandler` already uses for an empty
/// `[metrics.poll]`.
///
/// **One schedule for the whole check list, one synthetic table-metric write per tick** —
/// see `discovery_dsl::ServiceChecksSection`'s docs for why this is deliberately coarser
/// than `MetricSpec`'s per-metric schedule. Supports both `Schedule::Periodic` (elapsed-time
/// check against `last_polled`) and `Schedule::Calendar` (calendar-position check against
/// `last_polled_date`), exactly the same two-mode split `MetricPollHandler` already
/// implements per metric — here applied once per device instead of once per (device,
/// metric), since there's only one schedule to track. `None` falls back to the
/// process-wide default, `poll_intervals.service_check_secs`, read fresh every tick (same
/// "an edit applies without a restart" convention every other `SettingsStore` consumer in
/// this file follows).
///
/// **Disabled checks (`ServiceCheckSpec::enabled == false`) are skipped entirely** — no
/// row for them this tick, same as if they'd been removed from the profile outright (any
/// already-open row-scoped alert for that check name auto-clears via
/// `AutoClearReason::RowMissing`, exactly the mechanism a real removed SNMP table row would
/// trigger).
///
/// **Device-level master switch** (`Device::enabled`) gates the actual probing+recording
/// for a tick, never the reschedule — same "freeze, don't force-close" contract
/// `MetricPollHandler`/`ReachabilityPollHandler` already give it.
pub struct ServiceCheckPollHandler {
    pub store: Arc<dyn JobQueueStore>,
    pub devices: Arc<dyn DeviceStore>,
    pub device_metrics: Arc<dyn DeviceMetricsStore>,
    pub matcher: Arc<ProfileMatcher>,
    pub checker: Arc<dyn discovery_servicecheck::ServiceChecker>,
    /// `poll_intervals.service_check_secs`, read fresh (not cached) every tick — see this
    /// struct's docs.
    pub settings: Arc<dyn SettingsStore>,
    /// Same `Arc` sharing convention as `MetricPollHandler`'s `last_polled`/
    /// `last_polled_date` — a dedicated pair here (keyed by device only, not (device,
    /// metric name), since there's exactly one schedule per device for this feature), not
    /// a reuse of `MetricPollHandler`'s own maps (different key shape, and this handler's
    /// chain has its own independent lifecycle).
    pub last_polled: Arc<DashMap<uuid::Uuid, tokio::time::Instant>>,
    /// See this struct's docs — the `Schedule::Calendar` counterpart to `last_polled`.
    pub last_polled_date: Arc<DashMap<uuid::Uuid, chrono::NaiveDate>>,
}

#[async_trait]
impl JobHandler for ServiceCheckPollHandler {
    async fn handle(&self, job: Job) -> anyhow::Result<()> {
        let payload: ServiceCheckPollPayload = serde_json::from_value(job.payload)?;

        if self
            .devices
            .current_poll_generation(payload.device_id)
            .await?
            != Some(payload.generation)
        {
            return Ok(()); // stale chain (device gone, or superseded by a newer generation)
        }

        let Some(device) = self.devices.get_device(payload.device_id).await? else {
            return Ok(());
        };
        let Some(profile_name) = device.profile.clone() else {
            return Ok(());
        };
        let Some(profile) = self.matcher.profile_by_name(&profile_name).await else {
            warn!(profile = %profile_name, "device references a profile that no longer exists");
            return Ok(());
        };

        if profile.service_checks.checks.is_empty() {
            return Ok(()); // nothing to check; a future profile change restarts the chain via the generation guard
        }

        // Read fresh once per tick, not cached across ticks — see this struct's `settings`
        // field docs.
        let default_interval =
            Duration::from_secs(self.settings.poll_intervals().await.service_check_secs);
        let interval = Duration::from_secs(
            profile
                .service_checks
                .schedule
                .as_ref()
                .and_then(Schedule::interval_secs)
                .unwrap_or(default_interval.as_secs()),
        );

        let now = tokio::time::Instant::now();
        let local_now = Local::now();
        let today = local_now.date_naive();
        let due = match &profile.service_checks.schedule {
            Some(Schedule::Calendar { .. }) => {
                if self.last_polled_date.get(&payload.device_id).map(|d| *d) == Some(today) {
                    false // already fired today — don't refire every tick for the rest of the matching minute
                } else {
                    profile
                        .service_checks
                        .schedule
                        .as_ref()
                        .unwrap()
                        .matches_calendar(today, local_now.hour(), local_now.minute())
                }
            }
            _ => match self.last_polled.get(&payload.device_id) {
                Some(last) => now.duration_since(*last) >= interval,
                None => true, // never polled by this process yet — due immediately
            },
        };

        // Device-level master switch — see this struct's docs. `last_polled`/
        // `last_polled_date` are simply never updated while disabled, so re-enabling picks
        // back up as "due" on the very next tick, no restart needed.
        if device.enabled && due {
            self.last_polled.insert(payload.device_id, now);
            self.last_polled_date.insert(payload.device_id, today);

            // Sequential, not concurrent — same "simple to reason about; revisit if
            // profiling ever says a device with many checks needs it" judgment call
            // `MetricPollHandler` makes for its (rarer) table metrics. A profile's check
            // list is expected to be a handful of entries, not dozens.
            let mut rows = Vec::with_capacity(profile.service_checks.checks.len());
            for check in &profile.service_checks.checks {
                if !check.enabled {
                    continue; // disabled — no row this tick, see this struct's docs
                }
                let host = match resolve_service_check_host(
                    check.target.as_deref(),
                    &device.facts.ip,
                ) {
                    Ok(host) => host,
                    Err(error) => {
                        warn!(ip = %device.facts.ip, check = %check.name, %error, "service check target rejected");
                        rows.push(service_check_row(
                            check,
                            check.target.as_deref().unwrap_or_default(),
                            &discovery_servicecheck::CheckOutcome {
                                ok: false,
                                latency_ms: None,
                                error: Some(error),
                            },
                        ));
                        continue;
                    }
                };
                let target = discovery_servicecheck::CheckTarget {
                    protocol: to_check_protocol(check.protocol),
                    host: host.clone(),
                    port: check.port,
                    path: check.path_or_default().to_string(),
                    expected_status: check.expected_status,
                    body_contains: check.body_contains.clone(),
                    timeout: Duration::from_millis(
                        check.timeout_ms.unwrap_or(DEFAULT_SERVICE_CHECK_TIMEOUT_MS),
                    ),
                };
                let outcome = self.checker.check(&target).await;
                if !outcome.ok {
                    warn!(ip = %device.facts.ip, check = %check.name, error = ?outcome.error, "service check failed");
                }
                rows.push(service_check_row(check, &host, &outcome));
            }

            let mut outcomes: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
            outcomes.insert(
                SERVICE_CHECKS_METRIC_NAME.to_string(),
                MetricPollOutcome::Ok(MetricValue::Table(rows)),
            );
            self.device_metrics
                .record_metric_polls(payload.device_id, &outcomes)
                .await?;

            self.store
                .enqueue(
                    QueueKind::AlertEval,
                    serde_json::to_value(AlertEvalPayload {
                        event: None,
                        device_id: payload.device_id,
                    })?,
                    None,
                )
                .await?;
        }

        let store = self.store.clone();
        let device_id = payload.device_id;
        let generation = payload.generation;
        tokio::spawn(async move {
            tokio::time::sleep(jittered(interval)).await;
            if let Ok(payload) = serde_json::to_value(ServiceCheckPollPayload {
                device_id,
                generation,
            }) {
                let _ = store
                    .enqueue(QueueKind::ServiceCheckPoll, payload, None)
                    .await;
            }
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group_alert::CorrelationSnapshot;
    use discovery_core::JobState;
    use discovery_core::{AlertState, AutoClearReason};
    use discovery_devices::{SeaOrmDeviceMetricsStore, SeaOrmDeviceStore};
    use discovery_queue::SeaOrmJobQueueStore;
    use discovery_snmp::FakeSnmpClient;

    /// Builds a `DeviceStore` + `DeviceMetricsStore` pair sharing one in-memory connection
    /// — the 2026-08-18 domain split means the old `InMemoryDeviceStore::new()` one-liner
    /// isn't enough on its own for any test that also needs metrics/overrides; this is the
    /// paired replacement, used wherever both are needed (see
    /// `discovery_devices::SeaOrmDeviceStore::new_in_memory_for_tests`'s docs for why
    /// sharing one connection here mirrors production's common case).
    async fn device_stores() -> (Arc<dyn DeviceStore>, Arc<dyn DeviceMetricsStore>) {
        let db = discovery_migration::connect_in_memory_for_tests().await;
        let device_metrics: Arc<dyn DeviceMetricsStore> =
            Arc::new(SeaOrmDeviceMetricsStore::new(db.clone()));
        let alerts: Arc<dyn discovery_alerts::AlertStore> =
            Arc::new(discovery_alerts::SeaOrmAlertStore::new(db.clone()));
        let devices: Arc<dyn DeviceStore> =
            Arc::new(SeaOrmDeviceStore::new(db, device_metrics.clone(), alerts));
        (devices, device_metrics)
    }

    /// Same idea as `device_stores`, plus the `AlertStore` handle exposed to the caller
    /// (needed by `AlertEvalHandler` tests, which read it back to assert what actually got
    /// persisted — `device_stores`'s own internal one is only wired for `DeviceStore`'s
    /// cascade-delete, not reachable from outside it).
    async fn device_and_alert_stores() -> (
        Arc<dyn DeviceStore>,
        Arc<dyn DeviceMetricsStore>,
        Arc<dyn discovery_alerts::AlertStore>,
    ) {
        let db = discovery_migration::connect_in_memory_for_tests().await;
        let device_metrics: Arc<dyn DeviceMetricsStore> =
            Arc::new(SeaOrmDeviceMetricsStore::new(db.clone()));
        let alert_store: Arc<dyn discovery_alerts::AlertStore> =
            Arc::new(discovery_alerts::SeaOrmAlertStore::new(db.clone()));
        let devices: Arc<dyn DeviceStore> = Arc::new(SeaOrmDeviceStore::new(
            db,
            device_metrics.clone(),
            alert_store.clone(),
        ));
        (devices, device_metrics, alert_store)
    }

    /// Builds a real `Job` for `AlertEvalHandler::handle` — that handler has no `store`
    /// field of its own (see its docs), so this exists purely to mint a well-formed `Job`
    /// via a throwaway queue, same convention every other handler test in this module uses.
    async fn alert_eval_job(device_id: uuid::Uuid) -> Job {
        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
        store
            .enqueue(
                QueueKind::AlertEval,
                serde_json::to_value(AlertEvalPayload {
                    device_id,
                    event: None,
                })
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        store
            .claim(QueueKind::AlertEval, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
    }

    fn if_row(index: &str, oper_status: i64) -> MetricTableRow {
        let mut fields = BTreeMap::new();
        fields.insert("ifOperStatus".to_string(), MetricValue::Int(oper_status));
        MetricTableRow {
            index: index.to_string(),
            fields,
        }
    }

    fn port_down_rule(row_key_expression: Option<&str>) -> AlertRule {
        AlertRule {
            policy: Default::default(),
            name: "port_down".into(),
            level: "warning".into(),
            row_metric: Some("if_table".into()),
            row_key_expression: row_key_expression.map(str::to_string),
            expression: "row.ifOperStatus == 2".into(),
            deactivation_expression: Some("row.ifOperStatus == 1".into()),
            facts_expression: None,
            message: "Порт {row.index} недоступен".into(),
            clear_after_seconds: Some(0),
            activate_after_seconds: None,
            flap_window_seconds: None,
            flap_threshold: None,
            enabled: true,
        }
    }

    /// No maintenance windows configured at all — `load_all()` always returns empty, so
    /// [`discovery_config_store::is_device_under_maintenance`] always reads `false`. The
    /// default `maintenance_windows` for every pre-existing `AlertEvalHandler` test in
    /// this module, none of which are about this feature — keeps their setup unchanged
    /// rather than threading a real (async-constructed) store through every call site.
    struct NoMaintenanceWindows;

    #[async_trait]
    impl discovery_config_store::MaintenanceWindowStore for NoMaintenanceWindows {
        async fn list_all(&self) -> anyhow::Result<Vec<discovery_config_store::MaintenanceWindow>> {
            Ok(vec![])
        }
        async fn get(
            &self,
            _id: uuid::Uuid,
        ) -> anyhow::Result<Option<discovery_config_store::MaintenanceWindow>> {
            Ok(None)
        }
        async fn upsert(
            &self,
            _window: &discovery_config_store::MaintenanceWindow,
        ) -> anyhow::Result<()> {
            Ok(())
        }
        async fn delete(&self, _id: uuid::Uuid) -> anyhow::Result<()> {
            Ok(())
        }
    }

    /// No notification rules configured at all — `list_all()` always returns empty, so
    /// `AlertEvalHandler::dispatch_notifications` always finds nothing to notify and
    /// returns before ever touching `notification_channels`/`queue`. The default for every
    /// pre-existing `AlertEvalHandler` test in this module, none of which are about
    /// notifications — same "keep unrelated tests' setup unchanged" reasoning as
    /// `NoMaintenanceWindows` above.
    struct NoNotificationRules;

    #[async_trait]
    impl discovery_config_store::NotificationRuleStore for NoNotificationRules {
        async fn list_all(&self) -> anyhow::Result<Vec<discovery_config_store::NotificationRule>> {
            Ok(vec![])
        }
        async fn get(
            &self,
            _id: uuid::Uuid,
        ) -> anyhow::Result<Option<discovery_config_store::NotificationRule>> {
            Ok(None)
        }
        async fn upsert(
            &self,
            _rule: &discovery_config_store::NotificationRule,
        ) -> anyhow::Result<()> {
            Ok(())
        }
        async fn delete(&self, _id: uuid::Uuid) -> anyhow::Result<()> {
            Ok(())
        }
    }

    /// Paired with [`NoNotificationRules`] — never actually called (dispatch returns
    /// before resolving channels once the rule list is empty), but the field still needs a
    /// concrete value.
    struct NoNotificationChannels;

    #[async_trait]
    impl discovery_config_store::NotificationChannelStore for NoNotificationChannels {
        async fn list_for_user(
            &self,
            _user_id: uuid::Uuid,
        ) -> anyhow::Result<Vec<discovery_core::NotificationChannel>> {
            Ok(vec![])
        }
        async fn list_for_users(
            &self,
            _user_ids: &[uuid::Uuid],
        ) -> anyhow::Result<Vec<discovery_core::NotificationChannel>> {
            Ok(vec![])
        }
        async fn list_all(&self) -> anyhow::Result<Vec<discovery_core::NotificationChannel>> {
            Ok(vec![])
        }
        async fn get(
            &self,
            _id: uuid::Uuid,
        ) -> anyhow::Result<Option<discovery_core::NotificationChannel>> {
            Ok(None)
        }
        async fn upsert(
            &self,
            _channel: &discovery_core::NotificationChannel,
        ) -> anyhow::Result<()> {
            Ok(())
        }
        async fn delete(&self, _id: uuid::Uuid) -> anyhow::Result<()> {
            Ok(())
        }
    }

    /// Paired with [`NoNotificationRules`] — `dispatch_alert_notifications` only ever
    /// calls `list_users` when a matched rule has a `RecipientRef::Role` entry, which none
    /// of the pre-existing (non-notification) tests' rules do; every other method here
    /// being `unimplemented!()` is safe for the same reason `NoNotificationChannels`'s
    /// methods are.
    struct NoAuth;

    #[async_trait]
    impl discovery_auth::AuthStore for NoAuth {
        async fn create_user(
            &self,
            _username: &str,
            _password: &str,
            _is_admin: bool,
            _must_change_password: bool,
            _role_id: Option<uuid::Uuid>,
        ) -> anyhow::Result<discovery_auth::User> {
            unimplemented!()
        }
        async fn get_user_by_id(
            &self,
            _id: uuid::Uuid,
        ) -> anyhow::Result<Option<discovery_auth::User>> {
            unimplemented!()
        }
        async fn list_users(&self) -> anyhow::Result<Vec<discovery_auth::User>> {
            Ok(vec![])
        }
        async fn delete_user(&self, _id: uuid::Uuid) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn set_password(&self, _id: uuid::Uuid, _new_password: &str) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn set_admin(&self, _id: uuid::Uuid, _is_admin: bool) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn verify_password(
            &self,
            _username: &str,
            _password: &str,
        ) -> anyhow::Result<Option<discovery_auth::User>> {
            unimplemented!()
        }
        async fn user_count(&self) -> anyhow::Result<u64> {
            unimplemented!()
        }
        async fn set_user_role(
            &self,
            _user_id: uuid::Uuid,
            _role_id: Option<uuid::Uuid>,
        ) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn create_role(
            &self,
            _name: &str,
            _permissions: std::collections::HashMap<
                discovery_core::Domain,
                discovery_auth::AccessLevel,
            >,
        ) -> anyhow::Result<discovery_auth::Role> {
            unimplemented!()
        }
        async fn list_roles(&self) -> anyhow::Result<Vec<discovery_auth::Role>> {
            unimplemented!()
        }
        async fn get_role(&self, _id: uuid::Uuid) -> anyhow::Result<Option<discovery_auth::Role>> {
            unimplemented!()
        }
        async fn update_role(
            &self,
            _id: uuid::Uuid,
            _name: &str,
            _permissions: std::collections::HashMap<
                discovery_core::Domain,
                discovery_auth::AccessLevel,
            >,
        ) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn delete_role(&self, _id: uuid::Uuid) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn create_session(
            &self,
            _user_id: uuid::Uuid,
            _ttl: chrono::Duration,
        ) -> anyhow::Result<String> {
            unimplemented!()
        }
        async fn authenticate_session(
            &self,
            _raw_token: &str,
        ) -> anyhow::Result<Option<discovery_auth::AuthenticatedUser>> {
            unimplemented!()
        }
        async fn delete_session(&self, _raw_token: &str) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn delete_sessions_for_user(&self, _user_id: uuid::Uuid) -> anyhow::Result<u64> {
            unimplemented!()
        }
        async fn delete_expired_sessions(&self) -> anyhow::Result<u64> {
            unimplemented!()
        }
    }

    /// Paired with [`NoNotificationRules`] — `dispatch_notifications` never reaches
    /// `queue.enqueue` when there are zero rules to match, so every method here being
    /// `unimplemented!()` is safe for every pre-existing (non-notification) test.
    struct NoQueue;

    #[async_trait]
    impl JobQueueStore for NoQueue {
        async fn enqueue(
            &self,
            _queue: QueueKind,
            _payload: serde_json::Value,
            _dedupe_key: Option<&str>,
        ) -> anyhow::Result<i64> {
            unimplemented!(
                "NoQueue is only a placeholder for tests unrelated to notification dispatch"
            )
        }
        async fn claim(
            &self,
            _queue: QueueKind,
            _worker_id: &str,
            _limit: i64,
        ) -> anyhow::Result<Vec<Job>> {
            unimplemented!()
        }
        async fn complete(&self, _job_id: i64) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn fail(&self, _job_id: i64, _error: &str) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn reclaim_stale(&self, _older_than: chrono::Duration) -> anyhow::Result<u64> {
            unimplemented!()
        }
        async fn stats(&self, _queue: QueueKind) -> anyhow::Result<discovery_core::QueueStats> {
            unimplemented!()
        }
        async fn state_of(&self, _job_id: i64) -> anyhow::Result<Option<discovery_core::JobState>> {
            unimplemented!()
        }
        async fn delete_job(&self, _job_id: i64) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn pause_job(&self, _job_id: i64) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn resume_job(&self, _job_id: i64) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn clear_queue(
            &self,
            _queue: QueueKind,
            _state: Option<discovery_core::JobState>,
        ) -> anyhow::Result<u64> {
            unimplemented!()
        }
        async fn is_queue_paused(&self, _queue: QueueKind) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn set_queue_paused(&self, _queue: QueueKind, _paused: bool) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn list_jobs(
            &self,
            _queue: QueueKind,
            _query: &discovery_queue::JobListQuery,
        ) -> anyhow::Result<discovery_queue::JobListPage> {
            unimplemented!()
        }
    }

    fn alert_eval_handler(
        devices: Arc<dyn DeviceStore>,
        device_metrics: Arc<dyn DeviceMetricsStore>,
        alert_store: Arc<dyn discovery_alerts::AlertStore>,
        alerts: Arc<discovery_core::AlertStateTracker>,
        rule: AlertRule,
    ) -> AlertEvalHandler {
        let profile = discovery_dsl::ProfileFile {
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            profile: discovery_dsl::ProfileMeta {
                name: "port_monitor".into(),
                priority: 0,
            },
            match_expr: discovery_dsl::MatchSection {
                expression: "true".into(),
            },
            metrics: discovery_dsl::MetricsSection::default(),
            alerts: vec![rule],
            version: "v1".into(),
        };
        AlertEvalHandler {
            evaluation_locks: Default::default(),
            alert_engine: Arc::new(AlertEvaluator::new()),
            alerts,
            alert_store,
            devices,
            device_metrics,
            matcher: Arc::new(ProfileMatcher::new(vec![profile])),
            maintenance_windows: Arc::new(NoMaintenanceWindows),
            notification_rules: Arc::new(NoNotificationRules),
            notification_channels: Arc::new(NoNotificationChannels),
            auth: Arc::new(NoAuth),
            queue: Arc::new(NoQueue),
            still_active_last_persisted: Arc::new(DashMap::new()),
            correlator: Arc::new(GroupAlertCorrelator::new()),
        }
    }

    /// Direct user request 2026-08-29 ("тревога по порту") — end-to-end through the real
    /// `AlertEvalHandler`, not just the `AlertStateTracker` unit it delegates to: only the
    /// row whose condition actually holds gets an incident, keyed by that row's own index
    /// by default, and it clears normally (no `auto_clear_reason`) once its own
    /// `deactivation_expression` holds — a genuinely recovered port, not a vanished one.
    #[tokio::test]
    async fn alert_eval_handler_activates_one_incident_per_down_row_and_clears_on_recovery() {
        let (devices, device_metrics, alert_store) = device_and_alert_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "port_monitor", "v1")
            .await
            .unwrap();

        let mut outcomes = BTreeMap::new();
        outcomes.insert(
            "if_table".to_string(),
            MetricPollOutcome::Ok(MetricValue::Table(vec![if_row("1", 1), if_row("3", 2)])),
        );
        device_metrics
            .record_metric_polls(device_id, &outcomes)
            .await
            .unwrap();

        let handler = alert_eval_handler(
            devices.clone(),
            device_metrics.clone(),
            alert_store.clone(),
            Arc::new(discovery_core::AlertStateTracker::new()),
            port_down_rule(None),
        );
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();

        let page = alert_store
            .list(&discovery_alerts::AlertListQuery::default())
            .await
            .unwrap();
        assert_eq!(
            page.total, 1,
            "only row \"3\" is down — exactly one incident must exist, not one per row"
        );
        assert_eq!(page.items[0].row_key.as_deref(), Some("3"));
        assert_eq!(page.items[0].state, discovery_core::AlertState::Active);
        assert_eq!(
            page.items[0].message, "Порт 3 недоступен",
            "message must render the row.index token"
        );

        // Row "3" recovers.
        let mut outcomes2 = BTreeMap::new();
        outcomes2.insert(
            "if_table".to_string(),
            MetricPollOutcome::Ok(MetricValue::Table(vec![if_row("1", 1), if_row("3", 1)])),
        );
        device_metrics
            .record_metric_polls(device_id, &outcomes2)
            .await
            .unwrap();
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();

        let page2 = alert_store
            .list(&discovery_alerts::AlertListQuery::default())
            .await
            .unwrap();
        assert_eq!(page2.items[0].state, discovery_core::AlertState::Cleared);
        assert_eq!(page2.items[0].auto_clear_reason, None, "recovered via its own condition, not because the row vanished — must not be RowMissing");
    }

    /// Direct user request 2026-08-29: two independently-down rows under the same rule
    /// must be two independent incidents, and clearing one must not touch the other.
    #[tokio::test]
    async fn alert_eval_handler_tracks_multiple_down_rows_independently() {
        let (devices, device_metrics, alert_store) = device_and_alert_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "port_monitor", "v1")
            .await
            .unwrap();

        let mut outcomes = BTreeMap::new();
        outcomes.insert(
            "if_table".to_string(),
            MetricPollOutcome::Ok(MetricValue::Table(vec![
                if_row("1", 2),
                if_row("2", 1),
                if_row("3", 2),
            ])),
        );
        device_metrics
            .record_metric_polls(device_id, &outcomes)
            .await
            .unwrap();

        let handler = alert_eval_handler(
            devices.clone(),
            device_metrics.clone(),
            alert_store.clone(),
            Arc::new(discovery_core::AlertStateTracker::new()),
            port_down_rule(None),
        );
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();

        let page = alert_store
            .list(&discovery_alerts::AlertListQuery::default())
            .await
            .unwrap();
        assert_eq!(
            page.total, 2,
            "ports 1 and 3 are both down — two independent incidents"
        );
        let mut keys: Vec<&str> = page
            .items
            .iter()
            .map(|a| a.row_key.as_deref().unwrap())
            .collect();
        keys.sort();
        assert_eq!(keys, vec!["1", "3"]);

        // Port 1 recovers, port 3 stays down.
        let mut outcomes2 = BTreeMap::new();
        outcomes2.insert(
            "if_table".to_string(),
            MetricPollOutcome::Ok(MetricValue::Table(vec![
                if_row("1", 1),
                if_row("2", 1),
                if_row("3", 2),
            ])),
        );
        device_metrics
            .record_metric_polls(device_id, &outcomes2)
            .await
            .unwrap();
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();

        let active = alert_store
            .list(&discovery_alerts::AlertListQuery {
                state: Some(discovery_core::AlertState::Active),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            active.total, 1,
            "clearing port 1's incident must not touch port 3's"
        );
        assert_eq!(active.items[0].row_key.as_deref(), Some("3"));
    }

    /// Direct user request 2026-08-29: a row disappearing from the table entirely (not
    /// just failing its own deactivation condition) must still clear — through the exact
    /// same `AlertEvalHandler` tick, tagged `AutoClearReason::RowMissing` — rather than
    /// being stuck open forever because there's no row left to re-evaluate.
    #[tokio::test]
    async fn alert_eval_handler_clears_a_row_that_vanished_from_the_table_as_row_missing() {
        let (devices, device_metrics, alert_store) = device_and_alert_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "port_monitor", "v1")
            .await
            .unwrap();

        let mut outcomes = BTreeMap::new();
        outcomes.insert(
            "if_table".to_string(),
            MetricPollOutcome::Ok(MetricValue::Table(vec![if_row("1", 1), if_row("3", 2)])),
        );
        device_metrics
            .record_metric_polls(device_id, &outcomes)
            .await
            .unwrap();

        let handler = alert_eval_handler(
            devices.clone(),
            device_metrics.clone(),
            alert_store.clone(),
            Arc::new(discovery_core::AlertStateTracker::new()),
            port_down_rule(None),
        );
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();
        assert_eq!(
            alert_store
                .list(&discovery_alerts::AlertListQuery::default())
                .await
                .unwrap()
                .total,
            1
        );

        // Port 3 vanishes entirely from if_table (e.g. removed from the device) — not
        // present with any ifOperStatus at all this tick.
        let mut outcomes2 = BTreeMap::new();
        outcomes2.insert(
            "if_table".to_string(),
            MetricPollOutcome::Ok(MetricValue::Table(vec![if_row("1", 1)])),
        );
        device_metrics
            .record_metric_polls(device_id, &outcomes2)
            .await
            .unwrap();
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();

        let page = alert_store
            .list(&discovery_alerts::AlertListQuery::default())
            .await
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].state, discovery_core::AlertState::Cleared);
        assert_eq!(page.items[0].row_key.as_deref(), Some("3"));
        assert_eq!(
            page.items[0].auto_clear_reason,
            Some(AutoClearReason::RowMissing),
            "must be tagged as lost, not an ordinary condition-based clear"
        );
    }

    /// Same scenario as above, but the metric hasn't polled at all this tick (`if_table`
    /// entirely absent from `metrics`, not present-with-zero-rows) — must be treated the
    /// same as "row missing" — must not crash and must not leave the incident frozen
    /// forever just because there's no `MetricValue::Table` at all to iterate.
    ///
    /// **Not simulated via a failed poll** (`MetricPollOutcome::Err`) — this system
    /// deliberately keeps a metric's *last successful* value in `Metrics` across a failed
    /// re-poll (`discovery_core::MetricRecord`'s docs: "value... describes the last
    /// success specifically", independent of the most recent attempt's outcome), so a
    /// transient timeout does *not* make `metrics.get(row_metric)` return `None` — that
    /// would be the wrong scenario to test here. Instead this seeds the tracker directly,
    /// the same way a stale incident could exist after a profile edit that renamed/removed
    /// the rule's `row_metric` out from under an already-open row-scoped incident.
    #[tokio::test]
    async fn alert_eval_handler_clears_as_row_missing_when_the_whole_metric_is_absent() {
        let (devices, device_metrics, alert_store) = device_and_alert_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "port_monitor", "v1")
            .await
            .unwrap();

        // `if_table` is never polled for this device at all — only an unrelated metric is.
        let mut outcomes = BTreeMap::new();
        outcomes.insert(
            "cpu".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(10)),
        );
        device_metrics
            .record_metric_polls(device_id, &outcomes)
            .await
            .unwrap();

        let alerts = Arc::new(discovery_core::AlertStateTracker::new());
        // Seed a pre-existing open incident directly, as if it had activated on an
        // earlier tick before `if_table` stopped being declared/available.
        alerts.observe(
            device_id,
            "10.0.0.1",
            "port_down",
            Some("3"),
            AlertLevel::Warning,
            "Порт 3 недоступен".into(),
            None,
            true,
            false,
            None,
            chrono::Duration::seconds(0),
            chrono::Utc::now(),
        );

        let handler = alert_eval_handler(
            devices.clone(),
            device_metrics.clone(),
            alert_store.clone(),
            alerts,
            port_down_rule(None),
        );
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();

        let page = alert_store
            .list(&discovery_alerts::AlertListQuery::default())
            .await
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].state, discovery_core::AlertState::Cleared);
        assert_eq!(
            page.items[0].auto_clear_reason,
            Some(AutoClearReason::RowMissing)
        );
    }

    /// Direct user request 2026-08-29: identity should be able to survive a port being
    /// renumbered — `row_key_expression` keys by a field other than the default
    /// `row.index`.
    #[tokio::test]
    async fn alert_eval_handler_uses_row_key_expression_when_the_rule_declares_one() {
        let (devices, device_metrics, alert_store) = device_and_alert_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "port_monitor", "v1")
            .await
            .unwrap();

        let mut fields = BTreeMap::new();
        fields.insert("ifOperStatus".to_string(), MetricValue::Int(2));
        fields.insert("ifDescr".to_string(), MetricValue::Str("Gi0/3".into()));
        let row = MetricTableRow {
            index: "3".to_string(),
            fields,
        };
        let mut outcomes = BTreeMap::new();
        outcomes.insert(
            "if_table".to_string(),
            MetricPollOutcome::Ok(MetricValue::Table(vec![row])),
        );
        device_metrics
            .record_metric_polls(device_id, &outcomes)
            .await
            .unwrap();

        let handler = alert_eval_handler(
            devices.clone(),
            device_metrics.clone(),
            alert_store.clone(),
            Arc::new(discovery_core::AlertStateTracker::new()),
            port_down_rule(Some("row.ifDescr")),
        );
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();

        let page = alert_store
            .list(&discovery_alerts::AlertListQuery::default())
            .await
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(
            page.items[0].row_key.as_deref(),
            Some("Gi0/3"),
            "must key by ifDescr, not the default row.index"
        );
    }

    /// Regression net for the device-level/row-scoped refactor
    /// (`eval_device_level_rule`/`eval_row_scoped_rule` split) — an ordinary rule with no
    /// `row_metric` must behave exactly as it did before row-scoped alerts existed: one
    /// incident for the whole device, `row_key` absent.
    #[tokio::test]
    async fn alert_eval_handler_device_level_rule_is_unaffected_by_the_row_scoped_split() {
        let (devices, device_metrics, alert_store) = device_and_alert_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "port_monitor", "v1")
            .await
            .unwrap();

        let mut outcomes = BTreeMap::new();
        outcomes.insert(
            "cpu".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(95)),
        );
        device_metrics
            .record_metric_polls(device_id, &outcomes)
            .await
            .unwrap();

        let rule = AlertRule {
            policy: Default::default(),
            name: "high_cpu".into(),
            level: "warning".into(),
            row_metric: None,
            row_key_expression: None,
            expression: "metrics.cpu > 90".into(),
            deactivation_expression: None,
            facts_expression: None,
            message: "cpu high".into(),
            clear_after_seconds: Some(0),
            activate_after_seconds: None,
            flap_window_seconds: None,
            flap_threshold: None,
            enabled: true,
        };
        let handler = alert_eval_handler(
            devices.clone(),
            device_metrics.clone(),
            alert_store.clone(),
            Arc::new(discovery_core::AlertStateTracker::new()),
            rule,
        );
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();

        let page = alert_store
            .list(&discovery_alerts::AlertListQuery::default())
            .await
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].row_key, None);
        assert_eq!(page.items[0].state, discovery_core::AlertState::Active);
    }

    fn high_cpu_rule(deactivation_expression: Option<&str>) -> AlertRule {
        AlertRule {
            policy: Default::default(),
            name: "high_cpu".into(),
            level: "warning".into(),
            row_metric: None,
            row_key_expression: None,
            expression: "metrics.cpu > 90".into(),
            deactivation_expression: deactivation_expression.map(str::to_string),
            facts_expression: None,
            message: "cpu high".into(),
            clear_after_seconds: Some(0),
            activate_after_seconds: None,
            flap_window_seconds: None,
            flap_threshold: None,
            enabled: true,
        }
    }

    #[tokio::test]
    async fn alert_eval_does_not_use_last_known_value_after_poll_failure() {
        let (devices, device_metrics, alert_store) = device_and_alert_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "port_monitor", "v1")
            .await
            .unwrap();

        let handler = alert_eval_handler(
            devices.clone(),
            device_metrics.clone(),
            alert_store.clone(),
            Arc::new(discovery_core::AlertStateTracker::new()),
            high_cpu_rule(None),
        );
        let mut success = BTreeMap::new();
        success.insert("cpu".into(), MetricPollOutcome::Ok(MetricValue::Int(95)));
        device_metrics
            .record_metric_polls(device_id, &success)
            .await
            .unwrap();
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();

        let mut failure = BTreeMap::new();
        failure.insert("cpu".into(), MetricPollOutcome::Err("timeout".into()));
        device_metrics
            .record_metric_polls(device_id, &failure)
            .await
            .unwrap();
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();
        let active = alert_store
            .list(&discovery_alerts::AlertListQuery {
                state: Some(discovery_core::AlertState::Active),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            active.total, 0,
            "failed poll must not keep the old alert active"
        );

        // A successful poll restores the value to the alert DSL and opens a new incident.
        device_metrics
            .record_metric_polls(device_id, &success)
            .await
            .unwrap();
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();
        let active = alert_store
            .list(&discovery_alerts::AlertListQuery {
                state: Some(discovery_core::AlertState::Active),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(active.total, 1);
    }

    /// Fix for the 2026-08-30 bug ("Скалярные (device-level) тревоги не получают статус
    /// «Утеряна»"): a rule with its own explicit `deactivation_expression` referencing a
    /// metric that then gets pruned entirely (`DeviceMetricsStore::prune_metrics` — e.g. a
    /// profile edit drops it) used to leave the incident stuck `Active` forever, because
    /// both `activation_true` and `deactivation_true` evaluated `false` against a missing
    /// metric. Must now clear as `RowMissing`, same `clear_after` mechanics as any other
    /// deactivation.
    #[tokio::test]
    async fn alert_eval_handler_clears_device_level_alert_as_row_missing_when_metric_pruned_with_explicit_deactivation(
    ) {
        let (devices, device_metrics, alert_store) = device_and_alert_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "port_monitor", "v1")
            .await
            .unwrap();

        let mut outcomes = BTreeMap::new();
        outcomes.insert(
            "cpu".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(95)),
        );
        device_metrics
            .record_metric_polls(device_id, &outcomes)
            .await
            .unwrap();

        let handler = alert_eval_handler(
            devices.clone(),
            device_metrics.clone(),
            alert_store.clone(),
            Arc::new(discovery_core::AlertStateTracker::new()),
            high_cpu_rule(Some("metrics.cpu < 70")),
        );
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();
        assert_eq!(
            alert_store
                .list(&discovery_alerts::AlertListQuery::default())
                .await
                .unwrap()
                .items[0]
                .state,
            discovery_core::AlertState::Active
        );

        // Profile edit drops `cpu` — it's now entirely absent from `metrics`, not merely
        // holding a value the condition reads as false.
        device_metrics.prune_metrics(device_id, &[]).await.unwrap();
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();

        let page = alert_store
            .list(&discovery_alerts::AlertListQuery::default())
            .await
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(
            page.items[0].state,
            discovery_core::AlertState::Cleared,
            "must not hang open forever with the metric gone"
        );
        assert_eq!(
            page.items[0].auto_clear_reason,
            Some(AutoClearReason::RowMissing)
        );
    }

    /// 2026-09-17 audit finding #4, end to end through the real `AlertEvalHandler`: an
    /// operator manually closes an alert (`discovery-web::close_alert`'s exact sequence —
    /// sever live tracking, then persist `Cleared`/`closed_by`) while the condition is
    /// still true. The very next real `AlertEval` tick must activate a brand-new incident
    /// (expected — see `Alert::closed_by`'s docs) but that new row must carry
    /// `reopened_from_alert_id` pointing back at the one just closed, so the operator's
    /// comment thread on the old row isn't silently stranded.
    #[tokio::test]
    async fn alert_eval_handler_links_a_reactivated_alert_to_the_one_manually_closed_moments_earlier(
    ) {
        let (devices, device_metrics, alert_store) = device_and_alert_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "port_monitor", "v1")
            .await
            .unwrap();

        let mut outcomes = BTreeMap::new();
        outcomes.insert(
            "cpu".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(95)),
        );
        device_metrics
            .record_metric_polls(device_id, &outcomes)
            .await
            .unwrap();

        let tracker = Arc::new(discovery_core::AlertStateTracker::new());
        let handler = alert_eval_handler(
            devices.clone(),
            device_metrics.clone(),
            alert_store.clone(),
            tracker.clone(),
            high_cpu_rule(None),
        );
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();

        let first = alert_store
            .list(&discovery_alerts::AlertListQuery::default())
            .await
            .unwrap();
        assert_eq!(first.total, 1);
        let original_id = first.items[0].id;
        assert_eq!(
            first.items[0].reopened_from_alert_id, None,
            "a genuinely first activation must not link to anything"
        );

        // Exactly what `discovery-web::close_alert` does: sever live tracking, then persist
        // Cleared/closed_by — the condition (`metrics.cpu > 90`) never actually changed.
        tracker.remove(device_id, "high_cpu", None);
        let mut closed = alert_store.get(original_id).await.unwrap().unwrap();
        closed.state = discovery_core::AlertState::Cleared;
        closed.cleared_at = Some(chrono::Utc::now());
        closed.closed_by = Some("noc-operator".to_string());
        alert_store.upsert(&closed).await.unwrap();

        // Next real tick — condition still holds, must reactivate as a *new* incident.
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();

        let active = alert_store
            .list(&discovery_alerts::AlertListQuery {
                state: Some(discovery_core::AlertState::Active),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(active.total, 1);
        assert_ne!(
            active.items[0].id, original_id,
            "a reactivation is a genuinely new incident row, not an overwrite of the old one"
        );
        assert_eq!(
            active.items[0].reopened_from_alert_id,
            Some(original_id),
            "the new incident must be linked back to the one just manually closed"
        );
    }

    /// Same bug, the other broken outcome: a rule with **no** explicit
    /// `deactivation_expression` (default = negation of `expression`) used to silently
    /// clear as an ordinary "Закрыта" the instant its referenced metric was pruned
    /// (`activation_true` reads `false` against a missing metric, so the default negation
    /// reads `true`) — misleading, since the condition never actually resolved. Must also
    /// clear as `RowMissing`.
    #[tokio::test]
    async fn alert_eval_handler_clears_device_level_alert_as_row_missing_when_metric_pruned_with_default_deactivation(
    ) {
        let (devices, device_metrics, alert_store) = device_and_alert_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "port_monitor", "v1")
            .await
            .unwrap();

        let mut outcomes = BTreeMap::new();
        outcomes.insert(
            "cpu".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(95)),
        );
        device_metrics
            .record_metric_polls(device_id, &outcomes)
            .await
            .unwrap();

        let handler = alert_eval_handler(
            devices.clone(),
            device_metrics.clone(),
            alert_store.clone(),
            Arc::new(discovery_core::AlertStateTracker::new()),
            high_cpu_rule(None),
        );
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();

        device_metrics.prune_metrics(device_id, &[]).await.unwrap();
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();

        let page = alert_store
            .list(&discovery_alerts::AlertListQuery::default())
            .await
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].state, discovery_core::AlertState::Cleared);
        assert_eq!(
            page.items[0].auto_clear_reason,
            Some(AutoClearReason::RowMissing),
            "must be tagged as lost, not a silent ordinary clear"
        );
    }

    /// Regression guard for the fix above: a metric that's still present but has genuinely
    /// dropped below the deactivation threshold must keep clearing exactly as before —
    /// an ordinary `Cleared`, no `RowMissing` tag, since nothing actually went missing.
    #[tokio::test]
    async fn alert_eval_handler_device_level_alert_still_clears_normally_when_condition_genuinely_resolves(
    ) {
        let (devices, device_metrics, alert_store) = device_and_alert_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "port_monitor", "v1")
            .await
            .unwrap();

        let mut outcomes = BTreeMap::new();
        outcomes.insert(
            "cpu".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(95)),
        );
        device_metrics
            .record_metric_polls(device_id, &outcomes)
            .await
            .unwrap();

        let handler = alert_eval_handler(
            devices.clone(),
            device_metrics.clone(),
            alert_store.clone(),
            Arc::new(discovery_core::AlertStateTracker::new()),
            high_cpu_rule(None),
        );
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();

        let mut outcomes2 = BTreeMap::new();
        outcomes2.insert(
            "cpu".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(10)),
        );
        device_metrics
            .record_metric_polls(device_id, &outcomes2)
            .await
            .unwrap();
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();

        let page = alert_store
            .list(&discovery_alerts::AlertListQuery::default())
            .await
            .unwrap();
        assert_eq!(page.items[0].state, discovery_core::AlertState::Cleared);
        assert_eq!(
            page.items[0].auto_clear_reason, None,
            "condition genuinely resolved — must not be mislabeled RowMissing"
        );
    }

    /// Maintenance windows (2026-09-07) — an active, matching window must suppress a
    /// brand-new activation entirely (no `Activated` transition, no row in `AlertStore`
    /// at all), while a device the window doesn't target keeps alerting normally through
    /// the exact same tick/handler.
    #[tokio::test]
    async fn alert_eval_handler_suppresses_new_activation_for_a_targeted_device_but_leaves_others_unaffected(
    ) {
        let (devices, device_metrics, alert_store) = device_and_alert_stores().await;
        let (device_a, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        let (device_b, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.2".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_a, "port_monitor", "v1")
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_b, "port_monitor", "v1")
            .await
            .unwrap();

        let mut outcomes = BTreeMap::new();
        outcomes.insert(
            "cpu".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(95)),
        );
        device_metrics
            .record_metric_polls(device_a, &outcomes)
            .await
            .unwrap();
        device_metrics
            .record_metric_polls(device_b, &outcomes)
            .await
            .unwrap();

        let maintenance_windows: Arc<dyn discovery_config_store::MaintenanceWindowStore> = Arc::new(
            discovery_config_store::SeaOrmMaintenanceWindowStore::new_in_memory_for_tests().await,
        );
        let now = chrono::Utc::now();
        maintenance_windows
            .upsert(&discovery_config_store::MaintenanceWindow {
                id: uuid::Uuid::new_v4(),
                name: "planned reboot".into(),
                enabled: true,
                starts_at: now - chrono::Duration::hours(1),
                ends_at: now + chrono::Duration::hours(1),
                subnets: vec![],
                profiles: vec![],
                device_ids: vec![device_a],
            })
            .await
            .unwrap();

        let profile = discovery_dsl::ProfileFile {
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            profile: discovery_dsl::ProfileMeta {
                name: "port_monitor".into(),
                priority: 0,
            },
            match_expr: discovery_dsl::MatchSection {
                expression: "true".into(),
            },
            metrics: discovery_dsl::MetricsSection::default(),
            alerts: vec![high_cpu_rule(None)],
            version: "v1".into(),
        };
        let handler = AlertEvalHandler {
            evaluation_locks: Default::default(),
            alert_engine: Arc::new(AlertEvaluator::new()),
            alerts: Arc::new(discovery_core::AlertStateTracker::new()),
            alert_store: alert_store.clone(),
            devices: devices.clone(),
            device_metrics: device_metrics.clone(),
            matcher: Arc::new(ProfileMatcher::new(vec![profile])),
            maintenance_windows,
            notification_rules: Arc::new(NoNotificationRules),
            notification_channels: Arc::new(NoNotificationChannels),
            auth: Arc::new(NoAuth),
            queue: Arc::new(NoQueue),
            still_active_last_persisted: Arc::new(DashMap::new()),
            correlator: Arc::new(GroupAlertCorrelator::new()),
        };

        handler
            .handle(alert_eval_job(device_a).await)
            .await
            .unwrap();
        handler
            .handle(alert_eval_job(device_b).await)
            .await
            .unwrap();

        let page = alert_store
            .list(&discovery_alerts::AlertListQuery::default())
            .await
            .unwrap();
        assert_eq!(
            page.total, 1,
            "device_a is under an active maintenance window — its alert must never activate"
        );
        assert_eq!(
            page.items[0].device_id, device_b,
            "device_b isn't targeted by the window and must alert normally"
        );
    }

    /// Maintenance windows (2026-09-07) — an already-active incident must freeze exactly
    /// in place (no `StillActive` persistence, message/state untouched) for as long as a
    /// matching window is active, then resume normal evaluation (re-render/persist,
    /// eventually clear) the instant the window is disabled — "freeze, don't force-close",
    /// same contract as `Device::enabled`/`AlertRule::enabled`.
    #[tokio::test]
    async fn alert_eval_handler_freezes_an_already_active_alert_during_a_maintenance_window_and_resumes_after(
    ) {
        let (devices, device_metrics, alert_store) = device_and_alert_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "port_monitor", "v1")
            .await
            .unwrap();

        let mut outcomes = BTreeMap::new();
        outcomes.insert(
            "cpu".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(95)),
        );
        device_metrics
            .record_metric_polls(device_id, &outcomes)
            .await
            .unwrap();

        // Message interpolates `{metrics.cpu}` (see `AlertEvaluator::render_message`'s
        // docs) purely so a later tick that *isn't* suppressed would visibly re-render it
        // with a new value — makes "the message did not change" a decisive proof that the
        // tick was a true no-op, not just coincidentally unchanged.
        let rule = AlertRule {
            policy: Default::default(),
            name: "high_cpu".into(),
            level: "warning".into(),
            row_metric: None,
            row_key_expression: None,
            expression: "metrics.cpu > 90".into(),
            deactivation_expression: None,
            facts_expression: None,
            message: "cpu high: {metrics.cpu}".into(),
            clear_after_seconds: Some(0),
            activate_after_seconds: None,
            flap_window_seconds: None,
            flap_threshold: None,
            enabled: true,
        };
        let profile = discovery_dsl::ProfileFile {
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            profile: discovery_dsl::ProfileMeta {
                name: "port_monitor".into(),
                priority: 0,
            },
            match_expr: discovery_dsl::MatchSection {
                expression: "true".into(),
            },
            metrics: discovery_dsl::MetricsSection::default(),
            alerts: vec![rule],
            version: "v1".into(),
        };
        let maintenance_windows: Arc<dyn discovery_config_store::MaintenanceWindowStore> = Arc::new(
            discovery_config_store::SeaOrmMaintenanceWindowStore::new_in_memory_for_tests().await,
        );
        let handler = AlertEvalHandler {
            evaluation_locks: Default::default(),
            alert_engine: Arc::new(AlertEvaluator::new()),
            alerts: Arc::new(discovery_core::AlertStateTracker::new()),
            alert_store: alert_store.clone(),
            devices: devices.clone(),
            device_metrics: device_metrics.clone(),
            matcher: Arc::new(ProfileMatcher::new(vec![profile])),
            maintenance_windows: maintenance_windows.clone(),
            notification_rules: Arc::new(NoNotificationRules),
            notification_channels: Arc::new(NoNotificationChannels),
            auth: Arc::new(NoAuth),
            queue: Arc::new(NoQueue),
            still_active_last_persisted: Arc::new(DashMap::new()),
            correlator: Arc::new(GroupAlertCorrelator::new()),
        };

        // No window yet — activates normally.
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();
        let page = alert_store
            .list(&discovery_alerts::AlertListQuery::default())
            .await
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].message, "cpu high: 95");
        assert_eq!(page.items[0].state, discovery_core::AlertState::Active);

        // A maintenance window now covers this device, and the underlying metric changes
        // too — a non-suppressed tick would re-render the message and persist a fresh
        // StillActive. Must be a complete no-op instead.
        let now = chrono::Utc::now();
        let window_id = uuid::Uuid::new_v4();
        maintenance_windows
            .upsert(&discovery_config_store::MaintenanceWindow {
                id: window_id,
                name: "emergency ppr".into(),
                enabled: true,
                starts_at: now - chrono::Duration::minutes(5),
                ends_at: now + chrono::Duration::hours(2),
                subnets: vec![],
                profiles: vec![],
                device_ids: vec![device_id],
            })
            .await
            .unwrap();
        let mut outcomes2 = BTreeMap::new();
        outcomes2.insert(
            "cpu".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(99)),
        );
        device_metrics
            .record_metric_polls(device_id, &outcomes2)
            .await
            .unwrap();

        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();

        let page_during = alert_store
            .list(&discovery_alerts::AlertListQuery::default())
            .await
            .unwrap();
        assert_eq!(
            page_during.total, 1,
            "still just the one incident — no duplicate row"
        );
        assert_eq!(
            page_during.items[0].message, "cpu high: 95",
            "must not be re-rendered/persisted with the new cpu value while under maintenance"
        );
        assert_eq!(
            page_during.items[0].state,
            discovery_core::AlertState::Active,
            "must stay open, not force-cleared, by the maintenance window"
        );

        // The window is disabled (operator cancels it) — evaluation must resume
        // immediately on the very next tick, no restart needed.
        let mut disabled = maintenance_windows.get(window_id).await.unwrap().unwrap();
        disabled.enabled = false;
        maintenance_windows.upsert(&disabled).await.unwrap();

        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();
        let page_after = alert_store
            .list(&discovery_alerts::AlertListQuery::default())
            .await
            .unwrap();
        assert_eq!(
            page_after.items[0].message, "cpu high: 99",
            "once the window is disabled, the very next tick must resume normal evaluation"
        );
    }

    // ---- notification dispatch (2026-09-10) ----

    /// Real `notification_rules`/`notification_channels`/`queue` (unlike [`alert_eval_handler`]'s
    /// `NoNotificationRules`/`NoNotificationChannels`/`NoQueue` defaults) — for the tests
    /// below, which are specifically about `AlertEvalHandler::dispatch_notifications`. The
    /// caller supplies the correlator explicitly so a test can pre-publish a hand-built
    /// snapshot (see the group-suppression gate tests below); the ordinary notification
    /// tests pass a blank `GroupAlertCorrelator::new()`.
    async fn alert_eval_handler_with_notifications(
        devices: Arc<dyn DeviceStore>,
        device_metrics: Arc<dyn DeviceMetricsStore>,
        alert_store: Arc<dyn discovery_alerts::AlertStore>,
        rule: AlertRule,
        correlator: Arc<GroupAlertCorrelator>,
    ) -> (
        AlertEvalHandler,
        Arc<dyn discovery_config_store::NotificationRuleStore>,
        Arc<dyn discovery_config_store::NotificationChannelStore>,
        Arc<dyn discovery_auth::AuthStore>,
        Arc<dyn JobQueueStore>,
    ) {
        let profile = discovery_dsl::ProfileFile {
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            profile: discovery_dsl::ProfileMeta {
                name: "port_monitor".into(),
                priority: 0,
            },
            match_expr: discovery_dsl::MatchSection {
                expression: "true".into(),
            },
            metrics: discovery_dsl::MetricsSection::default(),
            alerts: vec![rule],
            version: "v1".into(),
        };
        let notification_rules: Arc<dyn discovery_config_store::NotificationRuleStore> = Arc::new(
            discovery_config_store::SeaOrmNotificationRuleStore::new_in_memory_for_tests().await,
        );
        let notification_channels: Arc<dyn discovery_config_store::NotificationChannelStore> =
            Arc::new(
                discovery_config_store::SeaOrmNotificationChannelStore::new_in_memory_for_tests()
                    .await,
            );
        // Real (not `NoAuth`) — several tests below exercise `RecipientRef::Role`
        // resolution, which genuinely calls `list_users()`.
        let auth: Arc<dyn discovery_auth::AuthStore> =
            Arc::new(discovery_auth::SeaOrmAuthStore::new(
                discovery_migration::connect_in_memory_for_tests().await,
            ));
        let queue: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
        let handler = AlertEvalHandler {
            evaluation_locks: Default::default(),
            alert_engine: Arc::new(AlertEvaluator::new()),
            alerts: Arc::new(discovery_core::AlertStateTracker::new()),
            alert_store,
            devices,
            device_metrics,
            matcher: Arc::new(ProfileMatcher::new(vec![profile])),
            maintenance_windows: Arc::new(NoMaintenanceWindows),
            notification_rules: notification_rules.clone(),
            notification_channels: notification_channels.clone(),
            auth: auth.clone(),
            queue: queue.clone(),
            still_active_last_persisted: Arc::new(DashMap::new()),
            correlator,
        };
        (
            handler,
            notification_rules,
            notification_channels,
            auth,
            queue,
        )
    }

    fn notification_channel(user_id: uuid::Uuid) -> discovery_core::NotificationChannel {
        discovery_core::NotificationChannel {
            id: uuid::Uuid::new_v4(),
            user_id,
            kind: discovery_core::NotificationChannelKind::Webhook,
            target: "https://example.com/hook".into(),
            secret: None,
            enabled: true,
            created_at: chrono::Utc::now(),
        }
    }

    fn notification_rule(
        recipients: Vec<discovery_config_store::RecipientRef>,
    ) -> discovery_config_store::NotificationRule {
        discovery_config_store::NotificationRule {
            selection: Default::default(),
            id: uuid::Uuid::new_v4(),
            name: "test rule".into(),
            enabled: true,
            min_level: AlertLevel::Info,
            subnets: vec![],
            profiles: vec![],
            device_ids: vec![],
            active_from: None,
            active_to: None,
            days_of_week: vec![],
            notify_on_activate: true,
            notify_on_clear: true,
            recipients,
            repeat_after_seconds: 0,
            repeat_interval_seconds: 0,
            max_repeats: 0,
            escalation_levels: vec![],
        }
    }

    async fn claim_notification_dispatch_jobs(
        queue: &Arc<dyn JobQueueStore>,
    ) -> Vec<discovery_core::payload::NotificationDispatchPayload> {
        queue
            .claim(QueueKind::NotificationDispatch, "test-worker", 10)
            .await
            .unwrap()
            .into_iter()
            .map(|j| serde_json::from_value(j.payload).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn alert_eval_handler_closes_deleted_rule_and_notifies_on_clear() {
        let (devices, device_metrics, alert_store) = device_and_alert_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "port_monitor", "v1")
            .await
            .unwrap();
        let mut outcomes = BTreeMap::new();
        outcomes.insert(
            "cpu".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(95)),
        );
        device_metrics
            .record_metric_polls(device_id, &outcomes)
            .await
            .unwrap();

        let (handler, notification_rules, notification_channels, _auth, queue) =
            alert_eval_handler_with_notifications(
                devices.clone(),
                device_metrics.clone(),
                alert_store.clone(),
                high_cpu_rule(None),
                Arc::new(GroupAlertCorrelator::new()),
            )
            .await;
        let user_id = handler
            .auth
            .create_user(
                "recipient",
                "notification-test-password-123",
                true,
                false,
                None,
            )
            .await
            .unwrap()
            .id;
        notification_channels
            .upsert(&notification_channel(user_id))
            .await
            .unwrap();
        let mut notification_rule =
            notification_rule(vec![discovery_config_store::RecipientRef::User(user_id)]);
        notification_rule.notify_on_clear = true;
        notification_rules.upsert(&notification_rule).await.unwrap();

        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();
        assert_eq!(claim_notification_dispatch_jobs(&queue).await.len(), 1);

        // The same profile remains selected, but the old rule has been deleted.
        handler
            .matcher
            .reload(vec![discovery_dsl::ProfileFile {
                traps: Default::default(),
                syslog: Default::default(),
                service_checks: Default::default(),
                profile: discovery_dsl::ProfileMeta {
                    name: "replacement_profile".into(),
                    priority: 0,
                },
                match_expr: discovery_dsl::MatchSection {
                    expression: "true".into(),
                },
                metrics: discovery_dsl::MetricsSection::default(),
                alerts: vec![],
                version: "v2".into(),
            }])
            .await;
        devices
            .apply_profile_if_changed(device_id, "replacement_profile", "v2")
            .await
            .unwrap();
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();

        let page = alert_store
            .list(&discovery_alerts::AlertListQuery::default())
            .await
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].state, discovery_core::AlertState::Cleared);
        assert_eq!(page.items[0].auto_clear_reason, None);
        let clear_jobs = claim_notification_dispatch_jobs(&queue).await;
        assert_eq!(clear_jobs.len(), 1);
        assert_eq!(
            clear_jobs[0].trigger,
            discovery_core::NotificationTrigger::Cleared
        );
    }

    #[tokio::test]
    async fn alert_eval_handler_closes_active_rules_when_profile_disappears() {
        let (devices, device_metrics, alert_store) = device_and_alert_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "port_monitor", "v1")
            .await
            .unwrap();
        let mut outcomes = BTreeMap::new();
        outcomes.insert(
            "cpu".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(95)),
        );
        device_metrics
            .record_metric_polls(device_id, &outcomes)
            .await
            .unwrap();
        let handler = alert_eval_handler(
            devices,
            device_metrics,
            alert_store.clone(),
            Arc::new(discovery_core::AlertStateTracker::new()),
            high_cpu_rule(None),
        );
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();
        handler.matcher.reload(vec![]).await;
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();

        let page = alert_store
            .list(&discovery_alerts::AlertListQuery::default())
            .await
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].state, discovery_core::AlertState::Cleared);
    }

    #[tokio::test]
    async fn alert_eval_handler_enqueues_one_notification_dispatch_job_per_matching_channel_on_activation(
    ) {
        let (devices, device_metrics, alert_store) = device_and_alert_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "port_monitor", "v1")
            .await
            .unwrap();
        let mut outcomes = BTreeMap::new();
        outcomes.insert(
            "cpu".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(95)),
        );
        device_metrics
            .record_metric_polls(device_id, &outcomes)
            .await
            .unwrap();

        let (handler, notification_rules, notification_channels, _auth, queue) =
            alert_eval_handler_with_notifications(
                devices.clone(),
                device_metrics.clone(),
                alert_store.clone(),
                high_cpu_rule(None),
                Arc::new(GroupAlertCorrelator::new()),
            )
            .await;

        let user_id = handler
            .auth
            .create_user(
                "recipient",
                "notification-test-password-123",
                true,
                false,
                None,
            )
            .await
            .unwrap()
            .id;
        let channel = notification_channel(user_id);
        notification_channels.upsert(&channel).await.unwrap();
        notification_rules
            .upsert(&notification_rule(vec![
                discovery_config_store::RecipientRef::User(user_id),
            ]))
            .await
            .unwrap();

        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();

        let jobs = claim_notification_dispatch_jobs(&queue).await;
        assert_eq!(
            jobs.len(),
            1,
            "exactly one matching, enabled channel — exactly one job"
        );
        assert_eq!(jobs[0].channel_id, channel.id);
        assert_eq!(
            jobs[0].trigger,
            discovery_core::NotificationTrigger::Activated
        );
    }

    #[tokio::test]
    async fn alert_eval_handler_disabled_channel_and_disabled_rule_are_never_dispatched_to() {
        let (devices, device_metrics, alert_store) = device_and_alert_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "port_monitor", "v1")
            .await
            .unwrap();
        let mut outcomes = BTreeMap::new();
        outcomes.insert(
            "cpu".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(95)),
        );
        device_metrics
            .record_metric_polls(device_id, &outcomes)
            .await
            .unwrap();

        let (handler, notification_rules, notification_channels, _auth, queue) =
            alert_eval_handler_with_notifications(
                devices.clone(),
                device_metrics.clone(),
                alert_store.clone(),
                high_cpu_rule(None),
                Arc::new(GroupAlertCorrelator::new()),
            )
            .await;

        let user_id = handler
            .auth
            .create_user(
                "recipient",
                "notification-test-password-123",
                true,
                false,
                None,
            )
            .await
            .unwrap()
            .id;
        let mut disabled_channel = notification_channel(user_id);
        disabled_channel.enabled = false;
        notification_channels
            .upsert(&disabled_channel)
            .await
            .unwrap();
        let mut disabled_rule =
            notification_rule(vec![discovery_config_store::RecipientRef::User(user_id)]);
        disabled_rule.enabled = false;
        notification_rules.upsert(&disabled_rule).await.unwrap();

        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();

        assert!(
            claim_notification_dispatch_jobs(&queue).await.is_empty(),
            "a disabled rule matching zero enabled channels must dispatch nothing"
        );
    }

    #[tokio::test]
    async fn alert_eval_handler_dispatches_on_clear_only_when_notify_on_clear_is_true() {
        let (devices, device_metrics, alert_store) = device_and_alert_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "port_monitor", "v1")
            .await
            .unwrap();
        let mut outcomes = BTreeMap::new();
        outcomes.insert(
            "cpu".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(95)),
        );
        device_metrics
            .record_metric_polls(device_id, &outcomes)
            .await
            .unwrap();

        let (handler, notification_rules, notification_channels, _auth, queue) =
            alert_eval_handler_with_notifications(
                devices.clone(),
                device_metrics.clone(),
                alert_store.clone(),
                high_cpu_rule(None),
                Arc::new(GroupAlertCorrelator::new()),
            )
            .await;

        let user_id = handler
            .auth
            .create_user(
                "recipient",
                "notification-test-password-123",
                true,
                false,
                None,
            )
            .await
            .unwrap()
            .id;
        notification_channels
            .upsert(&notification_channel(user_id))
            .await
            .unwrap();
        let mut rule = notification_rule(vec![discovery_config_store::RecipientRef::User(user_id)]);
        rule.notify_on_clear = false;
        notification_rules.upsert(&rule).await.unwrap();

        // Activation — dispatches (notify_on_activate is still true).
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();
        assert_eq!(claim_notification_dispatch_jobs(&queue).await.len(), 1);

        // Recovery — condition genuinely resolves, alert clears, but notify_on_clear=false
        // must suppress the dispatch entirely.
        let mut recovered = BTreeMap::new();
        recovered.insert(
            "cpu".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(10)),
        );
        device_metrics
            .record_metric_polls(device_id, &recovered)
            .await
            .unwrap();
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();
        let page = alert_store
            .list(&discovery_alerts::AlertListQuery::default())
            .await
            .unwrap();
        assert_eq!(
            page.items[0].state,
            discovery_core::AlertState::Cleared,
            "the alert itself must still clear normally"
        );
        assert!(
            claim_notification_dispatch_jobs(&queue).await.is_empty(),
            "notify_on_clear=false must suppress the Cleared dispatch"
        );
    }

    #[tokio::test]
    async fn alert_eval_handler_never_dispatches_for_still_active_transitions() {
        let (devices, device_metrics, alert_store) = device_and_alert_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "port_monitor", "v1")
            .await
            .unwrap();
        let mut outcomes = BTreeMap::new();
        outcomes.insert(
            "cpu".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(95)),
        );
        device_metrics
            .record_metric_polls(device_id, &outcomes)
            .await
            .unwrap();

        let (handler, notification_rules, notification_channels, _auth, queue) =
            alert_eval_handler_with_notifications(
                devices.clone(),
                device_metrics.clone(),
                alert_store.clone(),
                high_cpu_rule(None),
                Arc::new(GroupAlertCorrelator::new()),
            )
            .await;
        let user_id = handler
            .auth
            .create_user(
                "recipient",
                "notification-test-password-123",
                true,
                false,
                None,
            )
            .await
            .unwrap()
            .id;
        notification_channels
            .upsert(&notification_channel(user_id))
            .await
            .unwrap();
        notification_rules
            .upsert(&notification_rule(vec![
                discovery_config_store::RecipientRef::User(user_id),
            ]))
            .await
            .unwrap();

        // First tick: Activated — dispatches once.
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();
        assert_eq!(claim_notification_dispatch_jobs(&queue).await.len(), 1);

        // Second tick, condition still true (unchanged metrics): StillActive — must not
        // enqueue a second job, regardless of `still_active_last_persisted`'s own persist
        // throttle (this is a stronger guarantee: never, not just "not every tick").
        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();
        assert!(
            claim_notification_dispatch_jobs(&queue).await.is_empty(),
            "StillActive must never dispatch"
        );
    }

    async fn seeded_upstream_cause(
        alert_store: &Arc<dyn discovery_alerts::AlertStore>,
        upstream: uuid::Uuid,
    ) -> Alert {
        let now = chrono::Utc::now();
        let cause = Alert {
            details: Default::default(),
            id: uuid::Uuid::new_v4(),
            device_id: upstream,
            device_ip: "10.0.0.2".into(),
            name: "high_cpu".into(),
            row_key: None,
            level: AlertLevel::Warning,
            message: "cpu high".into(),
            state: discovery_core::AlertState::Active,
            facts: None,
            first_seen: now - chrono::Duration::seconds(120),
            last_seen: now,
            cleared_at: None,
            closed_by: None,
            acknowledged_by: None,
            acknowledged_at: None,
            snoozed_until: None,
            snoozed_by: None,
            auto_clear_reason: None,
            repeat_count: 0,
            escalation_level: 0,
            repeated_at: None,
            escalation_reason: None,
            flapping: false,
            suppression_reason: None,
            comment_count: 0,
            suppressed_by_alert_id: None,
            reopened_from_alert_id: None,
        };
        alert_store.upsert(&cause).await.unwrap();
        cause
    }

    fn suppression_snapshot(downstream: uuid::Uuid, upstream: uuid::Uuid) -> CorrelationSnapshot {
        // Both cause and effect carry the `high_cpu` name (matches `high_cpu_rule`), so
        // one rule whose expressions gate on that name qualifies the C->E pair.
        CorrelationSnapshot {
            upstream_of: std::collections::HashMap::from([(downstream, vec![upstream])]),
            group_rules: vec![discovery_config_store::GroupAlertRule {
                id: uuid::Uuid::new_v4(),
                name: "cpu-cascade".into(),
                enabled: true,
                cause_expression: r#"name == "high_cpu""#.into(),
                effect_expression: r#"name == "high_cpu""#.into(),
            }],
            ..CorrelationSnapshot::default()
        }
    }

    #[tokio::test]
    async fn alert_eval_handler_holds_activation_notification_for_a_group_suppressed_effect() {
        let (devices, device_metrics, alert_store) = device_and_alert_stores().await;
        let (downstream, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(downstream, "port_monitor", "v1")
            .await
            .unwrap();
        let (upstream, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.2".into(),
            })
            .await
            .unwrap();
        let mut outcomes = BTreeMap::new();
        outcomes.insert(
            "cpu".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(95)),
        );
        device_metrics
            .record_metric_polls(downstream, &outcomes)
            .await
            .unwrap();

        let cause = seeded_upstream_cause(&alert_store, upstream).await;
        let correlator = Arc::new(GroupAlertCorrelator::new());
        correlator.publish(suppression_snapshot(downstream, upstream));

        let (handler, notification_rules, notification_channels, _auth, queue) =
            alert_eval_handler_with_notifications(
                devices.clone(),
                device_metrics.clone(),
                alert_store.clone(),
                high_cpu_rule(None),
                correlator,
            )
            .await;
        let user_id = handler
            .auth
            .create_user(
                "recipient",
                "notification-test-password-123",
                true,
                false,
                None,
            )
            .await
            .unwrap()
            .id;
        notification_channels
            .upsert(&notification_channel(user_id))
            .await
            .unwrap();
        notification_rules
            .upsert(&notification_rule(vec![
                discovery_config_store::RecipientRef::User(user_id),
            ]))
            .await
            .unwrap();

        handler
            .handle(alert_eval_job(downstream).await)
            .await
            .unwrap();

        let page = alert_store
            .list(&discovery_alerts::AlertListQuery::default())
            .await
            .unwrap();
        let effect = page
            .items
            .iter()
            .find(|a| a.device_id == downstream)
            .expect("the downstream effect must have been persisted");
        assert_eq!(
            effect.state,
            discovery_core::AlertState::Active,
            "suppression gates the notification, not the alert itself"
        );
        assert_eq!(
            effect.suppressed_by_alert_id,
            Some(cause.id),
            "the reactive gate must persist the suppression alongside the activation"
        );
        assert!(
            claim_notification_dispatch_jobs(&queue).await.is_empty(),
            "a group-suppressed activation's notification must be held"
        );
    }

    #[tokio::test]
    async fn alert_eval_handler_holds_clear_notification_too_when_the_incident_was_never_announced()
    {
        let (devices, device_metrics, alert_store) = device_and_alert_stores().await;
        let (downstream, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(downstream, "port_monitor", "v1")
            .await
            .unwrap();
        let (upstream, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.2".into(),
            })
            .await
            .unwrap();
        let mut outcomes = BTreeMap::new();
        outcomes.insert(
            "cpu".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(95)),
        );
        device_metrics
            .record_metric_polls(downstream, &outcomes)
            .await
            .unwrap();

        let _cause = seeded_upstream_cause(&alert_store, upstream).await;
        let correlator = Arc::new(GroupAlertCorrelator::new());
        correlator.publish(suppression_snapshot(downstream, upstream));

        let (handler, notification_rules, notification_channels, _auth, queue) =
            alert_eval_handler_with_notifications(
                devices.clone(),
                device_metrics.clone(),
                alert_store.clone(),
                high_cpu_rule(None),
                correlator,
            )
            .await;
        let user_id = handler
            .auth
            .create_user(
                "recipient",
                "notification-test-password-123",
                true,
                false,
                None,
            )
            .await
            .unwrap()
            .id;
        notification_channels
            .upsert(&notification_channel(user_id))
            .await
            .unwrap();
        notification_rules
            .upsert(&notification_rule(vec![
                discovery_config_store::RecipientRef::User(user_id),
            ]))
            .await
            .unwrap();

        // Activation: suppressed, notification held.
        handler
            .handle(alert_eval_job(downstream).await)
            .await
            .unwrap();
        assert!(
            claim_notification_dispatch_jobs(&queue).await.is_empty(),
            "suppressed activation must not announce"
        );

        // Recovery: the incident genuinely resolves — the alert must clear normally, but
        // the recovery must stay silent too (it was never announced).
        let mut recovered = BTreeMap::new();
        recovered.insert(
            "cpu".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(10)),
        );
        device_metrics
            .record_metric_polls(downstream, &recovered)
            .await
            .unwrap();
        handler
            .handle(alert_eval_job(downstream).await)
            .await
            .unwrap();

        let page = alert_store
            .list(&discovery_alerts::AlertListQuery::default())
            .await
            .unwrap();
        let effect = page
            .items
            .iter()
            .find(|a| a.device_id == downstream)
            .expect("the downstream effect must be present");
        assert_eq!(
            effect.state,
            discovery_core::AlertState::Cleared,
            "the alert itself must still clear normally"
        );
        assert!(
            claim_notification_dispatch_jobs(&queue).await.is_empty(),
            "recovery of an incident that was never announced must not dispatch a notice"
        );
    }

    #[tokio::test]
    async fn alert_eval_handler_dispatches_normally_when_the_effect_has_no_directed_upstream() {
        // Negative control: an upstream *cause alert exists in the store*, but the snapshot
        // has no topology link for the device — an unlinked active alert is not a cause.
        let (devices, device_metrics, alert_store) = device_and_alert_stores().await;
        let (downstream, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(downstream, "port_monitor", "v1")
            .await
            .unwrap();
        let (upstream, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.2".into(),
            })
            .await
            .unwrap();
        let mut outcomes = BTreeMap::new();
        outcomes.insert(
            "cpu".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(95)),
        );
        device_metrics
            .record_metric_polls(downstream, &outcomes)
            .await
            .unwrap();

        let _cause = seeded_upstream_cause(&alert_store, upstream).await;
        let correlator = Arc::new(GroupAlertCorrelator::new()); // blank snapshot — no topology
        correlator.publish(CorrelationSnapshot::default());

        let (handler, notification_rules, notification_channels, _auth, queue) =
            alert_eval_handler_with_notifications(
                devices.clone(),
                device_metrics.clone(),
                alert_store.clone(),
                high_cpu_rule(None),
                correlator,
            )
            .await;
        let user_id = handler
            .auth
            .create_user(
                "recipient",
                "notification-test-password-123",
                true,
                false,
                None,
            )
            .await
            .unwrap()
            .id;
        notification_channels
            .upsert(&notification_channel(user_id))
            .await
            .unwrap();
        notification_rules
            .upsert(&notification_rule(vec![
                discovery_config_store::RecipientRef::User(user_id),
            ]))
            .await
            .unwrap();

        handler
            .handle(alert_eval_job(downstream).await)
            .await
            .unwrap();

        let jobs = claim_notification_dispatch_jobs(&queue).await;
        assert_eq!(
            jobs.len(),
            1,
            "without a topology link to the upstream cause, the activation must dispatch normally"
        );
        assert_eq!(
            jobs[0].trigger,
            discovery_core::NotificationTrigger::Activated
        );
    }

    #[tokio::test]
    async fn alert_eval_handler_skips_dispatch_when_no_rule_matches_level_or_time_window() {
        let (devices, device_metrics, alert_store) = device_and_alert_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "port_monitor", "v1")
            .await
            .unwrap();
        let mut outcomes = BTreeMap::new();
        outcomes.insert(
            "cpu".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(95)),
        );
        device_metrics
            .record_metric_polls(device_id, &outcomes)
            .await
            .unwrap();

        // `high_cpu_rule` fires at `AlertLevel::Warning` (see its own definition) — a rule
        // requiring `Critical` must never match it.
        let (handler, notification_rules, notification_channels, _auth, queue) =
            alert_eval_handler_with_notifications(
                devices.clone(),
                device_metrics.clone(),
                alert_store.clone(),
                high_cpu_rule(None),
                Arc::new(GroupAlertCorrelator::new()),
            )
            .await;

        let user_id = handler
            .auth
            .create_user(
                "recipient",
                "notification-test-password-123",
                true,
                false,
                None,
            )
            .await
            .unwrap()
            .id;
        notification_channels
            .upsert(&notification_channel(user_id))
            .await
            .unwrap();

        let mut too_severe =
            notification_rule(vec![discovery_config_store::RecipientRef::User(user_id)]);
        too_severe.min_level = AlertLevel::Critical;
        notification_rules.upsert(&too_severe).await.unwrap();

        // A one-minute window exactly one hour from now, computed via wrapping time
        // arithmetic — guaranteed to exclude "now" regardless of when this test actually
        // runs (unlike a fixed wall-clock window, which would be flaky around that time of
        // day), same "don't hardcode a real clock into a test" discipline the rest of this
        // project's time-sensitive tests already follow.
        let now = chrono::Utc::now();
        let (active_from, _) = now
            .time()
            .overflowing_add_signed(chrono::Duration::hours(1));
        let (active_to, _) = active_from.overflowing_add_signed(chrono::Duration::minutes(1));
        let mut wrong_time =
            notification_rule(vec![discovery_config_store::RecipientRef::User(user_id)]);
        wrong_time.active_from = Some(active_from);
        wrong_time.active_to = Some(active_to);
        notification_rules.upsert(&wrong_time).await.unwrap();

        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();
        assert!(
            claim_notification_dispatch_jobs(&queue).await.is_empty(),
            "neither rule's level/time-window matches — nothing must dispatch"
        );
    }

    /// 2026-09-18, "Матрица нотификаций — роль как группа получателей" —
    /// `RecipientRef::Role` must resolve to every *current* member of that role, each
    /// getting the same per-user "enabled channels" treatment a `RecipientRef::User` entry
    /// already gets, through one real `AuthStore::list_users()` call (not per-role).
    #[tokio::test]
    async fn alert_eval_handler_dispatches_to_every_current_member_of_a_role_recipient() {
        let (devices, device_metrics, alert_store) = device_and_alert_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "port_monitor", "v1")
            .await
            .unwrap();
        let mut outcomes = BTreeMap::new();
        outcomes.insert(
            "cpu".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(95)),
        );
        device_metrics
            .record_metric_polls(device_id, &outcomes)
            .await
            .unwrap();

        let (handler, notification_rules, notification_channels, auth, queue) =
            alert_eval_handler_with_notifications(
                devices.clone(),
                device_metrics.clone(),
                alert_store.clone(),
                high_cpu_rule(None),
                Arc::new(GroupAlertCorrelator::new()),
            )
            .await;

        let role = auth
            .create_role("On-call", std::collections::HashMap::new())
            .await
            .unwrap();
        let member_a = auth
            .create_user("oncall-a", "password123", false, false, Some(role.id))
            .await
            .unwrap();
        let member_b = auth
            .create_user("oncall-b", "password123", false, false, Some(role.id))
            .await
            .unwrap();
        // Not in the role — must never receive a dispatch job for this rule.
        let outsider = auth
            .create_user("outsider", "password123", false, false, None)
            .await
            .unwrap();

        let channel_a = notification_channel(member_a.id);
        let channel_b = notification_channel(member_b.id);
        let channel_outsider = notification_channel(outsider.id);
        notification_channels.upsert(&channel_a).await.unwrap();
        notification_channels.upsert(&channel_b).await.unwrap();
        notification_channels
            .upsert(&channel_outsider)
            .await
            .unwrap();
        notification_rules
            .upsert(&notification_rule(vec![
                discovery_config_store::RecipientRef::Role { role: role.id },
            ]))
            .await
            .unwrap();

        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();

        let jobs = claim_notification_dispatch_jobs(&queue).await;
        let dispatched_channel_ids: std::collections::HashSet<_> =
            jobs.iter().map(|j| j.channel_id).collect();
        assert_eq!(
            dispatched_channel_ids.len(),
            2,
            "exactly the role's two current members, each via their own channel — not the outsider"
        );
        assert!(dispatched_channel_ids.contains(&channel_a.id));
        assert!(dispatched_channel_ids.contains(&channel_b.id));
        assert!(!dispatched_channel_ids.contains(&channel_outsider.id));
    }

    /// A role with zero current members must not error — it's an empty resolve, not a
    /// missing-recipient failure — and, mixed with a real `RecipientRef::User` in the same
    /// rule, must not stop that user's own dispatch either.
    #[tokio::test]
    async fn alert_eval_handler_role_recipient_with_no_members_dispatches_nothing_for_that_entry_but_others_still_work(
    ) {
        let (devices, device_metrics, alert_store) = device_and_alert_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "port_monitor", "v1")
            .await
            .unwrap();
        let mut outcomes = BTreeMap::new();
        outcomes.insert(
            "cpu".to_string(),
            MetricPollOutcome::Ok(MetricValue::Int(95)),
        );
        device_metrics
            .record_metric_polls(device_id, &outcomes)
            .await
            .unwrap();

        let (handler, notification_rules, notification_channels, auth, queue) =
            alert_eval_handler_with_notifications(
                devices.clone(),
                device_metrics.clone(),
                alert_store.clone(),
                high_cpu_rule(None),
                Arc::new(GroupAlertCorrelator::new()),
            )
            .await;

        let empty_role = auth
            .create_role("Empty Role", std::collections::HashMap::new())
            .await
            .unwrap();
        let user_id = handler
            .auth
            .create_user(
                "recipient",
                "notification-test-password-123",
                true,
                false,
                None,
            )
            .await
            .unwrap()
            .id;
        let channel = notification_channel(user_id);
        notification_channels.upsert(&channel).await.unwrap();
        notification_rules
            .upsert(&notification_rule(vec![
                discovery_config_store::RecipientRef::Role {
                    role: empty_role.id,
                },
                discovery_config_store::RecipientRef::User(user_id),
            ]))
            .await
            .unwrap();

        handler
            .handle(alert_eval_job(device_id).await)
            .await
            .unwrap();

        let jobs = claim_notification_dispatch_jobs(&queue).await;
        assert_eq!(jobs.len(), 1, "the empty role contributes nothing, but the plain User recipient in the same rule must still dispatch");
        assert_eq!(jobs[0].channel_id, channel.id);
    }

    /// The load-bearing test for the generation guard: without it, a profile change
    /// would leave the *old* metric-poll chain running alongside the new one, silently
    /// doubling up polling for that device forever.
    #[tokio::test]
    async fn stale_generation_metric_poll_does_not_touch_device_state() {
        let (devices, device_metrics) = device_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();

        devices
            .apply_profile_if_changed(device_id, "generic_host", "v1")
            .await
            .unwrap(); // generation 1
        devices
            .apply_profile_if_changed(device_id, "generic_switch", "v1")
            .await
            .unwrap(); // generation 2 — supersedes it
        assert_eq!(
            devices.current_poll_generation(device_id).await.unwrap(),
            Some(2)
        );

        // Built as a literal, not loaded from a file — file-based profile loading
        // (`load_profiles_from_dir`/`profiles/*.toml`) was removed 2026-08-16, direct
        // user request (no more file-based seeding anywhere in this project). Content
        // doesn't matter much here: the stale-generation check inside `handle` short-
        // circuits before this profile is ever read — only its *name* needs to match
        // what `apply_profile_if_changed` above put on the device.
        let profiles = vec![discovery_dsl::ProfileFile {
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            profile: discovery_dsl::ProfileMeta {
                name: "generic_switch".into(),
                priority: 10,
            },
            match_expr: discovery_dsl::MatchSection {
                expression: r#"metrics.sys_descr.contains("Switch")"#.into(),
            },
            metrics: discovery_dsl::MetricsSection::default(),
            alerts: vec![],
            version: "test-version".into(),
        }];
        let matcher = Arc::new(ProfileMatcher::new(profiles));
        // Nothing is seeded on this client — if the guard didn't fire, `handle` would
        // try to fetch OIDs and error out (or panic in a stricter fake), which would
        // also fail this test, just less directly.
        let snmp: Arc<dyn SnmpClient> = Arc::new(FakeSnmpClient::new());
        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);

        let handler = MetricPollHandler {
            store: store.clone(),
            snmp,
            cli: Arc::new(discovery_ssh::FakeCliClient::new()),
            devices: devices.clone(),
            device_metrics: device_metrics.clone(),
            matcher,
            settings: Arc::new(
                discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests().await,
            ),
            last_polled: Arc::new(DashMap::new()),
            last_polled_date: Arc::new(DashMap::new()),
            discovery_configs: Arc::new(
                discovery_config_store::SeaOrmDiscoveryConfigStore::new_in_memory_for_tests().await,
            ),
            pruned_generations: Arc::new(dashmap::DashMap::new()),
            topology_rules: Arc::new(
                discovery_config_store::SeaOrmTopologyRuleStore::new_in_memory_for_tests().await,
            ),
        };

        store
            .enqueue(
                QueueKind::MetricPoll,
                serde_json::to_value(MetricPollPayload {
                    device_id,
                    generation: 1,
                })
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let job = store
            .claim(QueueKind::MetricPoll, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();

        handler.handle(job).await.unwrap();

        let (_, metrics) =
            discovery_devices::get(devices.as_ref(), device_metrics.as_ref(), device_id)
                .await
                .unwrap()
                .unwrap();
        assert!(
            metrics.0.is_empty(),
            "a stale-generation poll must not record metrics"
        );
    }

    /// Direct user request 2026-08-16 (metric change history): a poll attempt that fails
    /// must still be recorded — `last_attempt_at` advances and the error is visible, even
    /// though there is (and never was) a successful value. Before this change, a failed
    /// poll was only `warn!`-logged and left no trace in storage at all.
    #[tokio::test]
    async fn metric_poll_records_a_failure_even_though_nothing_ever_succeeded() {
        let (devices, device_metrics) = device_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "generic_switch", "v1")
            .await
            .unwrap();

        let mut poll = std::collections::BTreeMap::new();
        poll.insert(
            "uptime".to_string(),
            MetricSpec::Oid("1.3.6.1.2.1.1.3.0".to_string()),
        );
        let profiles = vec![discovery_dsl::ProfileFile {
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            profile: discovery_dsl::ProfileMeta {
                name: "generic_switch".into(),
                priority: 0,
            },
            match_expr: discovery_dsl::MatchSection {
                expression: "true".into(),
            },
            metrics: discovery_dsl::MetricsSection { poll },
            alerts: vec![],
            version: "v1".into(),
        }];
        let matcher = Arc::new(ProfileMatcher::new(profiles));
        // Nothing seeded for this OID on this IP — `FakeSnmpClient` returns an error for
        // any unseeded (target, oid) pair, simulating an unreachable device.
        let snmp: Arc<dyn SnmpClient> = Arc::new(FakeSnmpClient::new());
        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);

        let handler = MetricPollHandler {
            store: store.clone(),
            snmp,
            cli: Arc::new(discovery_ssh::FakeCliClient::new()),
            devices: devices.clone(),
            device_metrics: device_metrics.clone(),
            matcher,
            settings: Arc::new(
                discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests().await,
            ),
            last_polled: Arc::new(DashMap::new()),
            last_polled_date: Arc::new(DashMap::new()),
            discovery_configs: Arc::new(
                discovery_config_store::SeaOrmDiscoveryConfigStore::new_in_memory_for_tests().await,
            ),
            pruned_generations: Arc::new(dashmap::DashMap::new()),
            topology_rules: Arc::new(
                discovery_config_store::SeaOrmTopologyRuleStore::new_in_memory_for_tests().await,
            ),
        };

        store
            .enqueue(
                QueueKind::MetricPoll,
                serde_json::to_value(MetricPollPayload {
                    device_id,
                    generation: 1,
                })
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let job = store
            .claim(QueueKind::MetricPoll, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        handler.handle(job).await.unwrap();

        // The DSL-facing bag stays empty — a metric that's never succeeded is simply
        // absent, same as one that's never been polled at all.
        let (_, metrics) =
            discovery_devices::get(devices.as_ref(), device_metrics.as_ref(), device_id)
                .await
                .unwrap()
                .unwrap();
        assert!(
            metrics.0.is_empty(),
            "a metric with no successful poll ever must be absent from the plain Metrics bag"
        );

        // But the richer per-metric record shows the attempt actually happened.
        let (_, records) =
            discovery_devices::all_with_metrics(devices.as_ref(), device_metrics.as_ref())
                .await
                .unwrap()
                .into_iter()
                .find(|(d, _)| d.id == device_id)
                .unwrap();
        let record = records
            .iter()
            .find(|r| r.name == "uptime")
            .expect("a record must exist even though every attempt failed");
        assert_eq!(record.value, None, "no value was ever obtained");
        assert!(
            record.error.is_some(),
            "the most recent failure's error must be visible"
        );
    }

    /// A profile with both a scalar and a table metric — the two must poll independently
    /// (table metrics split off `get_multi`'s scalar batch into their own `walk()`-based
    /// `poll_table_metric` calls, see `MetricPollHandler::handle`'s docs) and both end up
    /// correctly recorded.
    #[tokio::test]
    async fn metric_poll_handles_a_table_metric_alongside_a_scalar_one() {
        let (devices, device_metrics) = device_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "generic_switch", "v1")
            .await
            .unwrap();

        let mut poll = std::collections::BTreeMap::new();
        poll.insert(
            "uptime".to_string(),
            MetricSpec::Oid("1.3.6.1.2.1.1.3.0".to_string()),
        );
        let mut columns = std::collections::BTreeMap::new();
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
        let profiles = vec![discovery_dsl::ProfileFile {
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            profile: discovery_dsl::ProfileMeta {
                name: "generic_switch".into(),
                priority: 0,
            },
            match_expr: discovery_dsl::MatchSection {
                expression: "true".into(),
            },
            metrics: discovery_dsl::MetricsSection { poll },
            alerts: vec![],
            version: "v1".into(),
        }];
        let matcher = Arc::new(ProfileMatcher::new(profiles));

        let snmp = FakeSnmpClient::new();
        snmp.seed_get(
            "10.0.0.1",
            "1.3.6.1.2.1.1.3.0",
            discovery_snmp::SnmpValue::TimeTicks(12345),
        );
        snmp.seed_walk(
            "10.0.0.1",
            "1.3.6.1.2.1.2.2.1.1",
            vec![
                (
                    "1.3.6.1.2.1.2.2.1.1.1".to_string(),
                    discovery_snmp::SnmpValue::Integer(1),
                ),
                (
                    "1.3.6.1.2.1.2.2.1.1.2".to_string(),
                    discovery_snmp::SnmpValue::Integer(2),
                ),
            ],
        );
        snmp.seed_walk(
            "10.0.0.1",
            "1.3.6.1.2.1.2.2.1.2",
            vec![
                (
                    "1.3.6.1.2.1.2.2.1.2.1".to_string(),
                    discovery_snmp::SnmpValue::OctetString("Gi0/1".into()),
                ),
                (
                    "1.3.6.1.2.1.2.2.1.2.2".to_string(),
                    discovery_snmp::SnmpValue::OctetString("Gi0/2".into()),
                ),
            ],
        );
        let snmp: Arc<dyn SnmpClient> = Arc::new(snmp);
        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);

        let handler = MetricPollHandler {
            store: store.clone(),
            snmp,
            cli: Arc::new(discovery_ssh::FakeCliClient::new()),
            devices: devices.clone(),
            device_metrics: device_metrics.clone(),
            matcher,
            settings: Arc::new(
                discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests().await,
            ),
            last_polled: Arc::new(DashMap::new()),
            last_polled_date: Arc::new(DashMap::new()),
            discovery_configs: Arc::new(
                discovery_config_store::SeaOrmDiscoveryConfigStore::new_in_memory_for_tests().await,
            ),
            pruned_generations: Arc::new(dashmap::DashMap::new()),
            topology_rules: Arc::new(
                discovery_config_store::SeaOrmTopologyRuleStore::new_in_memory_for_tests().await,
            ),
        };

        store
            .enqueue(
                QueueKind::MetricPoll,
                serde_json::to_value(MetricPollPayload {
                    device_id,
                    generation: 1,
                })
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let job = store
            .claim(QueueKind::MetricPoll, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        handler.handle(job).await.unwrap();

        let (_, metrics) =
            discovery_devices::get(devices.as_ref(), device_metrics.as_ref(), device_id)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            metrics.get("uptime"),
            Some(&MetricValue::Int(12345)),
            "the scalar metric in the same profile must still poll normally"
        );

        let Some(MetricValue::Table(rows)) = metrics.get("if_table") else {
            panic!(
                "expected if_table to be a MetricValue::Table, got {:?}",
                metrics.get("if_table")
            )
        };
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].index, "1");
        assert_eq!(rows[0].fields.get("ifIndex"), Some(&MetricValue::Int(1)));
        assert_eq!(
            rows[0].fields.get("ifDescr"),
            Some(&MetricValue::Str("Gi0/1".into()))
        );
        assert_eq!(
            rows[1].fields.get("ifDescr"),
            Some(&MetricValue::Str("Gi0/2".into()))
        );
    }

    /// If even one of a table metric's declared columns fails to walk (network/timeout —
    /// the same failure mode a scalar `get()` already has), the whole metric must record as
    /// `Err`, not a partially-populated table — see `poll_table_metric`'s docs on why a
    /// half-built table would be a more confusing stored state than "didn't poll this tick".
    #[tokio::test]
    async fn metric_poll_records_a_table_metric_as_failed_if_any_one_column_walk_fails() {
        let (devices, device_metrics) = device_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "generic_switch", "v1")
            .await
            .unwrap();

        let mut columns = std::collections::BTreeMap::new();
        columns.insert("ifIndex".to_string(), "1".to_string());
        columns.insert("ifDescr".to_string(), "2".to_string());
        let mut poll = std::collections::BTreeMap::new();
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
        let profiles = vec![discovery_dsl::ProfileFile {
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            profile: discovery_dsl::ProfileMeta {
                name: "generic_switch".into(),
                priority: 0,
            },
            match_expr: discovery_dsl::MatchSection {
                expression: "true".into(),
            },
            metrics: discovery_dsl::MetricsSection { poll },
            alerts: vec![],
            version: "v1".into(),
        }];
        let matcher = Arc::new(ProfileMatcher::new(profiles));

        // ifIndex's column walk succeeds; ifDescr's is seeded to genuinely fail
        // (`seed_walk_error`, not just left unseeded — an unseeded walk means "empty
        // table", a different, non-error case already covered by
        // `build_metric_table`'s own `a_row_missing_one_column_keeps_its_other_fields`
        // unit test in `discovery-snmp`).
        let snmp = FakeSnmpClient::new();
        snmp.seed_walk(
            "10.0.0.1",
            "1.3.6.1.2.1.2.2.1.1",
            vec![(
                "1.3.6.1.2.1.2.2.1.1.1".to_string(),
                discovery_snmp::SnmpValue::Integer(1),
            )],
        );
        snmp.seed_walk_error("10.0.0.1", "1.3.6.1.2.1.2.2.1.2", "simulated timeout");
        let snmp: Arc<dyn SnmpClient> = Arc::new(snmp);
        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);

        let handler = MetricPollHandler {
            store: store.clone(),
            snmp,
            cli: Arc::new(discovery_ssh::FakeCliClient::new()),
            devices: devices.clone(),
            device_metrics: device_metrics.clone(),
            matcher,
            settings: Arc::new(
                discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests().await,
            ),
            last_polled: Arc::new(DashMap::new()),
            last_polled_date: Arc::new(DashMap::new()),
            discovery_configs: Arc::new(
                discovery_config_store::SeaOrmDiscoveryConfigStore::new_in_memory_for_tests().await,
            ),
            pruned_generations: Arc::new(dashmap::DashMap::new()),
            topology_rules: Arc::new(
                discovery_config_store::SeaOrmTopologyRuleStore::new_in_memory_for_tests().await,
            ),
        };

        store
            .enqueue(
                QueueKind::MetricPoll,
                serde_json::to_value(MetricPollPayload {
                    device_id,
                    generation: 1,
                })
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let job = store
            .claim(QueueKind::MetricPoll, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        handler.handle(job).await.unwrap();

        let (_, metrics) =
            discovery_devices::get(devices.as_ref(), device_metrics.as_ref(), device_id)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(metrics.get("if_table"), None, "a metric that never succeeded is absent from the plain Metrics bag, same as a scalar would be");

        let (_, records) =
            discovery_devices::all_with_metrics(devices.as_ref(), device_metrics.as_ref())
                .await
                .unwrap()
                .into_iter()
                .find(|(d, _)| d.id == device_id)
                .unwrap();
        let record = records
            .iter()
            .find(|r| r.name == "if_table")
            .expect("a record must exist even though the poll failed");
        assert_eq!(record.value, None);
        assert!(
            record.error.is_some(),
            "the whole table metric must be recorded as an error, not a partial table"
        );
    }

    /// SSH-command metrics (2026-09-07, see `discovery_dsl::MetricSpec::SshCommand`'s
    /// docs) route to `discovery_ssh::CliClient::exec` instead of SNMP, entirely
    /// independent of the scalar/table batches above. Every other `MetricPollHandler` test
    /// in this file only ever wires up `FakeCliClient::new()` unseeded (to satisfy the
    /// struct's field type) without ever exercising this branch — this is the first test
    /// that actually seeds it and drives a real poll through it.
    #[tokio::test]
    async fn metric_poll_ssh_command_uses_configured_credentials_and_records_the_captured_output() {
        // `set_ssh_credentials` always encrypts (see `discovery_core::secret::
        // encrypt_ssh_auth_secrets`'s docs — no plaintext-ok branch the way
        // `SnmpAuth::Community` gets), so this test needs a real secret key configured,
        // unlike `device_stores()`'s plain setup every other test in this file uses.
        let db = discovery_migration::connect_in_memory_for_tests().await;
        let device_metrics: Arc<dyn DeviceMetricsStore> =
            Arc::new(SeaOrmDeviceMetricsStore::new(db.clone()));
        let alerts: Arc<dyn discovery_alerts::AlertStore> =
            Arc::new(discovery_alerts::SeaOrmAlertStore::new(db.clone()));
        // Base64 of 32 `0x07` bytes — any valid 32-byte key works, this one's arbitrary.
        let secret_key =
            discovery_core::SecretKey::from_base64("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=")
                .unwrap();
        let devices: Arc<dyn DeviceStore> = Arc::new(
            SeaOrmDeviceStore::new(db, device_metrics.clone(), alerts)
                .with_secret_key(Arc::new(secret_key)),
        );

        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .set_ssh_credentials(
                device_id,
                discovery_core::SshCredentials {
                    username: "admin".into(),
                    auth: discovery_core::SshAuth::Password {
                        password: "hunter2".into(),
                    },
                    port: 22,
                    known_host_key: None,
                },
            )
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "generic_switch", "v1")
            .await
            .unwrap();

        let mut poll = std::collections::BTreeMap::new();
        poll.insert(
            "running_config".to_string(),
            MetricSpec::SshCommand {
                command: "show running-config".to_string(),
                schedule: None,
                history_retention_secs: None,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
                enabled: true,
            },
        );
        let profiles = vec![discovery_dsl::ProfileFile {
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            profile: discovery_dsl::ProfileMeta {
                name: "generic_switch".into(),
                priority: 0,
            },
            match_expr: discovery_dsl::MatchSection {
                expression: "true".into(),
            },
            metrics: discovery_dsl::MetricsSection { poll },
            alerts: vec![],
            version: "v1".into(),
        }];
        let matcher = Arc::new(ProfileMatcher::new(profiles));

        let cli = discovery_ssh::FakeCliClient::new();
        cli.seed("10.0.0.1", "show running-config", "hostname sw1\n");
        let snmp: Arc<dyn SnmpClient> = Arc::new(FakeSnmpClient::new());
        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);

        let handler = MetricPollHandler {
            store: store.clone(),
            snmp,
            cli: Arc::new(cli),
            devices: devices.clone(),
            device_metrics: device_metrics.clone(),
            matcher,
            settings: Arc::new(
                discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests().await,
            ),
            last_polled: Arc::new(DashMap::new()),
            last_polled_date: Arc::new(DashMap::new()),
            discovery_configs: Arc::new(
                discovery_config_store::SeaOrmDiscoveryConfigStore::new_in_memory_for_tests().await,
            ),
            pruned_generations: Arc::new(dashmap::DashMap::new()),
            topology_rules: Arc::new(
                discovery_config_store::SeaOrmTopologyRuleStore::new_in_memory_for_tests().await,
            ),
        };

        store
            .enqueue(
                QueueKind::MetricPoll,
                serde_json::to_value(MetricPollPayload {
                    device_id,
                    generation: 1,
                })
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let job = store
            .claim(QueueKind::MetricPoll, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        handler.handle(job).await.unwrap();

        let (_, metrics) =
            discovery_devices::get(devices.as_ref(), device_metrics.as_ref(), device_id)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            metrics.get("running_config"),
            Some(&MetricValue::Str("hostname sw1\n".to_string())),
            "the SSH command's captured stdout must be recorded verbatim as a scalar Str metric"
        );
    }

    /// CWE-295 fix, `MetricPollHandler`-side plumbing: when a device has no pinned SSH host
    /// key yet (`known_host_key: None`, the state every device starts in) and
    /// `discovery_ssh::CliClient::exec` reports it just learned one
    /// (`SshExecOutcome::newly_pinned_host_key`, simulated here via
    /// `FakeCliClient::seed_newly_pinned_host_key` — see that method's docs for why this is
    /// the only way to exercise this path without a real network), the handler must persist
    /// it via `DeviceStore::pin_ssh_host_key` so every future poll connects with it pinned.
    #[tokio::test]
    async fn metric_poll_ssh_command_persists_a_newly_learned_host_key_fingerprint() {
        let db = discovery_migration::connect_in_memory_for_tests().await;
        let device_metrics: Arc<dyn DeviceMetricsStore> =
            Arc::new(SeaOrmDeviceMetricsStore::new(db.clone()));
        let alerts: Arc<dyn discovery_alerts::AlertStore> =
            Arc::new(discovery_alerts::SeaOrmAlertStore::new(db.clone()));
        let secret_key =
            discovery_core::SecretKey::from_base64("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=")
                .unwrap();
        let devices: Arc<dyn DeviceStore> = Arc::new(
            SeaOrmDeviceStore::new(db, device_metrics.clone(), alerts)
                .with_secret_key(Arc::new(secret_key)),
        );

        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .set_ssh_credentials(
                device_id,
                discovery_core::SshCredentials {
                    username: "admin".into(),
                    auth: discovery_core::SshAuth::Password {
                        password: "hunter2".into(),
                    },
                    port: 22,
                    known_host_key: None,
                },
            )
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "generic_switch", "v1")
            .await
            .unwrap();

        let mut poll = std::collections::BTreeMap::new();
        poll.insert(
            "running_config".to_string(),
            MetricSpec::SshCommand {
                command: "show running-config".to_string(),
                schedule: None,
                history_retention_secs: None,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
                enabled: true,
            },
        );
        let profiles = vec![discovery_dsl::ProfileFile {
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            profile: discovery_dsl::ProfileMeta {
                name: "generic_switch".into(),
                priority: 0,
            },
            match_expr: discovery_dsl::MatchSection {
                expression: "true".into(),
            },
            metrics: discovery_dsl::MetricsSection { poll },
            alerts: vec![],
            version: "v1".into(),
        }];
        let matcher = Arc::new(ProfileMatcher::new(profiles));

        let cli = discovery_ssh::FakeCliClient::new();
        cli.seed("10.0.0.1", "show running-config", "hostname sw1\n");
        cli.seed_newly_pinned_host_key("10.0.0.1", "show running-config", "SHA256:fakefingerprint");
        let snmp: Arc<dyn SnmpClient> = Arc::new(FakeSnmpClient::new());
        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);

        let handler = MetricPollHandler {
            store: store.clone(),
            snmp,
            cli: Arc::new(cli),
            devices: devices.clone(),
            device_metrics: device_metrics.clone(),
            matcher,
            settings: Arc::new(
                discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests().await,
            ),
            last_polled: Arc::new(DashMap::new()),
            last_polled_date: Arc::new(DashMap::new()),
            discovery_configs: Arc::new(
                discovery_config_store::SeaOrmDiscoveryConfigStore::new_in_memory_for_tests().await,
            ),
            pruned_generations: Arc::new(dashmap::DashMap::new()),
            topology_rules: Arc::new(
                discovery_config_store::SeaOrmTopologyRuleStore::new_in_memory_for_tests().await,
            ),
        };

        store
            .enqueue(
                QueueKind::MetricPoll,
                serde_json::to_value(MetricPollPayload {
                    device_id,
                    generation: 1,
                })
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let job = store
            .claim(QueueKind::MetricPoll, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        handler.handle(job).await.unwrap();

        let device = devices
            .get_device(device_id)
            .await
            .unwrap()
            .expect("device must still exist");
        let creds = device
            .ssh_credentials
            .expect("SSH credentials must still be configured");
        assert_eq!(creds.known_host_key.as_deref(), Some("SHA256:fakefingerprint"), "a freshly-learned host key fingerprint must be persisted, not just returned and dropped");
    }

    /// A device with no SSH credentials configured at all must fail every due SSH-command
    /// metric with an explanatory error, not silently skip it or panic — the same "nothing
    /// to poll with yet" treatment a metric gets before a device's first successful
    /// `SnmpPoll` (see `metric_poll_records_a_failure_even_though_nothing_ever_succeeded`
    /// above for the SNMP-side equivalent of this same shape).
    #[tokio::test]
    async fn metric_poll_ssh_command_without_credentials_records_a_clear_failure() {
        let (devices, device_metrics) = device_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "generic_switch", "v1")
            .await
            .unwrap();

        let mut poll = std::collections::BTreeMap::new();
        poll.insert(
            "running_config".to_string(),
            MetricSpec::SshCommand {
                command: "show running-config".to_string(),
                schedule: None,
                history_retention_secs: None,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
                enabled: true,
            },
        );
        let profiles = vec![discovery_dsl::ProfileFile {
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            profile: discovery_dsl::ProfileMeta {
                name: "generic_switch".into(),
                priority: 0,
            },
            match_expr: discovery_dsl::MatchSection {
                expression: "true".into(),
            },
            metrics: discovery_dsl::MetricsSection { poll },
            alerts: vec![],
            version: "v1".into(),
        }];
        let matcher = Arc::new(ProfileMatcher::new(profiles));

        let snmp: Arc<dyn SnmpClient> = Arc::new(FakeSnmpClient::new());
        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);

        let handler = MetricPollHandler {
            store: store.clone(),
            snmp,
            cli: Arc::new(discovery_ssh::FakeCliClient::new()),
            devices: devices.clone(),
            device_metrics: device_metrics.clone(),
            matcher,
            settings: Arc::new(
                discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests().await,
            ),
            last_polled: Arc::new(DashMap::new()),
            last_polled_date: Arc::new(DashMap::new()),
            discovery_configs: Arc::new(
                discovery_config_store::SeaOrmDiscoveryConfigStore::new_in_memory_for_tests().await,
            ),
            pruned_generations: Arc::new(dashmap::DashMap::new()),
            topology_rules: Arc::new(
                discovery_config_store::SeaOrmTopologyRuleStore::new_in_memory_for_tests().await,
            ),
        };

        store
            .enqueue(
                QueueKind::MetricPoll,
                serde_json::to_value(MetricPollPayload {
                    device_id,
                    generation: 1,
                })
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let job = store
            .claim(QueueKind::MetricPoll, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        handler.handle(job).await.unwrap();

        let (_, metrics) =
            discovery_devices::get(devices.as_ref(), device_metrics.as_ref(), device_id)
                .await
                .unwrap()
                .unwrap();
        assert!(
            metrics.0.is_empty(),
            "a metric with no successful poll ever must be absent from the plain Metrics bag"
        );

        let (_, records) =
            discovery_devices::all_with_metrics(devices.as_ref(), device_metrics.as_ref())
                .await
                .unwrap()
                .into_iter()
                .find(|(d, _)| d.id == device_id)
                .unwrap();
        let record = records
            .iter()
            .find(|r| r.name == "running_config")
            .expect("a record must exist even though the device has no SSH credentials");
        assert_eq!(record.value, None);
        assert_eq!(
            record.error.as_deref(),
            Some("no SSH credentials configured for this device")
        );
    }

    /// Regression test for a real bug found live 2026-08-18 ("спустя некоторое время у
    /// всех стал профиль unknown_device"): `sys_descr` (and anything else populated by
    /// `subnet.oids`/`subnet.labels`) must survive a metric-poll tick even though no
    /// profile's `[metrics.poll]` declares it — a genuinely stale leftover metric (neither
    /// polled by the profile nor declared by the subnet) must still be pruned as before.
    #[tokio::test]
    async fn metric_poll_never_prunes_the_devices_own_subnet_discovery_fields() {
        use discovery_config_store::{
            DiscoveryConfig, Schedule, SeaOrmDiscoveryConfigStore, SubnetSpec,
        };
        use discovery_core::{SnmpAuth, SnmpVersion};

        let (devices, device_metrics) = device_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "generic_switch", "v1")
            .await
            .unwrap();

        // What `DedupHandler` would have written on the device's very first identity
        // cycle: the subnet's one-shot discovery fields, plus one genuinely stale metric
        // left over from some earlier, differently-configured profile/subnet.
        let mut discovered = std::collections::BTreeMap::new();
        discovered.insert(
            "sys_descr".to_string(),
            MetricPollOutcome::Ok(MetricValue::Str("Cisco Catalyst Switch 2960X".into())),
        );
        discovered.insert(
            "stale_leftover".to_string(),
            MetricPollOutcome::Ok(MetricValue::Str("should be pruned".into())),
        );
        device_metrics
            .record_metric_polls(device_id, &discovered)
            .await
            .unwrap();

        let discovery_configs: Arc<dyn DiscoveryConfigStore> =
            Arc::new(SeaOrmDiscoveryConfigStore::new_in_memory_for_tests().await);
        let mut oids = std::collections::BTreeMap::new();
        oids.insert(
            "sys_descr".to_string(),
            DiscoveryOidSpec::Oid("1.3.6.1.2.1.1.1.0".to_string()),
        );
        discovery_configs
            .upsert(&DiscoveryConfig {
                name: "test".into(),
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
                    oids,
                    labels: Default::default(),
                    snmp_timeout_ms: None,
                    snmp_retries: None,
                    create_dead_devices: true,
                }],
            })
            .await
            .unwrap();

        // Profile declares only `uptime` — deliberately does NOT declare `sys_descr`,
        // mirroring the real profiles that triggered the live bug (identity fields belong
        // to the subnet, not the profile).
        let mut poll = std::collections::BTreeMap::new();
        poll.insert(
            "uptime".to_string(),
            MetricSpec::Oid("1.3.6.1.2.1.1.3.0".to_string()),
        );
        let profiles = vec![discovery_dsl::ProfileFile {
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            profile: discovery_dsl::ProfileMeta {
                name: "generic_switch".into(),
                priority: 0,
            },
            match_expr: discovery_dsl::MatchSection {
                expression: r#"metrics.sys_descr.contains("Switch")"#.into(),
            },
            metrics: discovery_dsl::MetricsSection { poll },
            alerts: vec![],
            version: "v1".into(),
        }];
        let matcher = Arc::new(ProfileMatcher::new(profiles));
        let snmp: Arc<dyn SnmpClient> = Arc::new(FakeSnmpClient::new()); // uptime poll will fail — irrelevant to this test
        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);

        let handler = MetricPollHandler {
            store: store.clone(),
            snmp,
            cli: Arc::new(discovery_ssh::FakeCliClient::new()),
            devices: devices.clone(),
            device_metrics: device_metrics.clone(),
            matcher,
            settings: Arc::new(
                discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests().await,
            ),
            last_polled: Arc::new(DashMap::new()),
            last_polled_date: Arc::new(DashMap::new()),
            discovery_configs,
            pruned_generations: Arc::new(DashMap::new()),
            topology_rules: Arc::new(
                discovery_config_store::SeaOrmTopologyRuleStore::new_in_memory_for_tests().await,
            ),
        };

        store
            .enqueue(
                QueueKind::MetricPoll,
                serde_json::to_value(MetricPollPayload {
                    device_id,
                    generation: 1,
                })
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let job = store
            .claim(QueueKind::MetricPoll, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        handler.handle(job).await.unwrap();

        let metrics = device_metrics.get_metrics(device_id).await.unwrap();
        assert!(
            metrics.0.contains_key("sys_descr"),
            "the subnet's own discovery field must survive a metric-poll prune"
        );
        assert!(
            !metrics.0.contains_key("stale_leftover"),
            "a metric declared by neither the profile nor the subnet must still be pruned"
        );
    }

    /// Direct user request 2026-08-16: "мне нужна возможность выключать устройства". A
    /// disabled device must not be polled at all — but the chain itself must keep ticking
    /// (not stop), so re-enabling takes effect on its very next tick with no restart.
    #[tokio::test]
    async fn a_disabled_device_is_not_polled_but_resumes_immediately_once_re_enabled() {
        let (devices, device_metrics) = device_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "generic_switch", "v1")
            .await
            .unwrap();
        devices.set_enabled(device_id, false).await.unwrap();

        let mut poll = std::collections::BTreeMap::new();
        poll.insert(
            "uptime".to_string(),
            MetricSpec::Oid("1.3.6.1.2.1.1.3.0".to_string()),
        );
        let profiles = vec![discovery_dsl::ProfileFile {
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            profile: discovery_dsl::ProfileMeta {
                name: "generic_switch".into(),
                priority: 0,
            },
            match_expr: discovery_dsl::MatchSection {
                expression: "true".into(),
            },
            metrics: discovery_dsl::MetricsSection { poll },
            alerts: vec![],
            version: "v1".into(),
        }];
        let matcher = Arc::new(ProfileMatcher::new(profiles));
        let snmp = Arc::new(FakeSnmpClient::new());
        snmp.seed_get(
            "10.0.0.1",
            "1.3.6.1.2.1.1.3.0",
            discovery_snmp::SnmpValue::Integer(42),
        );
        let snmp: Arc<dyn SnmpClient> = snmp;
        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);

        let handler = MetricPollHandler {
            store: store.clone(),
            snmp,
            cli: Arc::new(discovery_ssh::FakeCliClient::new()),
            devices: devices.clone(),
            device_metrics: device_metrics.clone(),
            matcher,
            settings: Arc::new(
                discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests().await,
            ),
            last_polled: Arc::new(DashMap::new()),
            last_polled_date: Arc::new(DashMap::new()),
            discovery_configs: Arc::new(
                discovery_config_store::SeaOrmDiscoveryConfigStore::new_in_memory_for_tests().await,
            ),
            pruned_generations: Arc::new(dashmap::DashMap::new()),
            topology_rules: Arc::new(
                discovery_config_store::SeaOrmTopologyRuleStore::new_in_memory_for_tests().await,
            ),
        };

        store
            .enqueue(
                QueueKind::MetricPoll,
                serde_json::to_value(MetricPollPayload {
                    device_id,
                    generation: 1,
                })
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let job = store
            .claim(QueueKind::MetricPoll, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        handler.handle(job).await.unwrap();

        let (_, records) =
            discovery_devices::all_with_metrics(devices.as_ref(), device_metrics.as_ref())
                .await
                .unwrap()
                .into_iter()
                .find(|(d, _)| d.id == device_id)
                .unwrap();
        assert!(
            records.is_empty(),
            "a disabled device must not be polled at all, not even to record a failure"
        );

        // Re-enable, then feed the chain's own self-rescheduled next job (it kept ticking
        // even while disabled) back through the handler.
        devices.set_enabled(device_id, true).await.unwrap();
        store
            .enqueue(
                QueueKind::MetricPoll,
                serde_json::to_value(MetricPollPayload {
                    device_id,
                    generation: 1,
                })
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let job2 = store
            .claim(QueueKind::MetricPoll, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        handler.handle(job2).await.unwrap();

        let (_, metrics) =
            discovery_devices::get(devices.as_ref(), device_metrics.as_ref(), device_id)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            metrics.get("uptime"),
            Some(&MetricValue::Int(42)),
            "re-enabling must resume polling on the very next tick, no restart needed"
        );
    }

    /// Direct user question 2026-08-16: "при изменении профиля, изменении периодичности в
    /// профиле — это изменит сразу периодичность опроса метрики?" End-to-end proof that it
    /// does, driving the real production handlers (not a background loop/real sleeps —
    /// `#[tokio::test(start_paused = true)]` + `tokio::time::advance` for deterministic
    /// virtual time) through exactly the sequence a real profile edit triggers:
    /// `ProfileMatcher::reload` (what `profile_reload.rs`'s hot-reload loop calls once it
    /// notices a signature change) -> `apply_profile_if_changed` sees a new version (same
    /// name) -> `Changed` -> `ProfileApplyHandler` clears `last_polled`/`last_polled_date`
    /// for this device and starts a fresh `MetricPoll` generation.
    ///
    /// The real proof isn't just "the new chain's first tick polls immediately" — a
    /// brand-new generation's first tick is *always* due regardless of interval size (see
    /// `last_polled`'s "never polled yet" branch). The proof is the **second** tick: 2
    /// virtual seconds after the edit — nowhere near the *old* 3600s interval, but past
    /// the *new* 1s one — polls again. If the handler were reading a stale cached
    /// schedule instead of asking `ProfileMatcher` fresh every tick, this would stay
    /// silent for another hour.
    #[tokio::test]
    async fn editing_a_metrics_schedule_in_the_profile_changes_the_actual_poll_cadence() {
        let (devices, device_metrics) = device_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();

        let mut old_poll = BTreeMap::new();
        old_poll.insert(
            "x".to_string(),
            MetricSpec::Detailed {
                oid: "1.2.3".into(),
                columns: None,
                schedule: Some(Schedule::Periodic {
                    interval_secs: 3600,
                }),
                history_retention_secs: None,
                enabled: true,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
                derive: None,
            },
        );
        let old_version = discovery_dsl::compute_version(
            "true",
            &old_poll,
            &discovery_dsl::TrapsSection::default(),
            &discovery_dsl::SyslogSection::default(),
            &discovery_dsl::ServiceChecksSection::default(),
            &[],
        );
        let profile =
            |poll: BTreeMap<String, MetricSpec>, version: String| discovery_dsl::ProfileFile {
                traps: Default::default(),
                syslog: Default::default(),
                service_checks: Default::default(),
                profile: discovery_dsl::ProfileMeta {
                    name: "p".into(),
                    priority: 0,
                },
                match_expr: discovery_dsl::MatchSection {
                    expression: "true".into(),
                },
                metrics: discovery_dsl::MetricsSection { poll },
                alerts: vec![],
                version,
            };
        let matcher = Arc::new(ProfileMatcher::new(vec![profile(
            old_poll,
            old_version.clone(),
        )]));
        devices
            .apply_profile_if_changed(device_id, "p", &old_version)
            .await
            .unwrap();

        let snmp: Arc<dyn SnmpClient> = Arc::new(FakeSnmpClient::new());
        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
        let last_polled = Arc::new(DashMap::new());
        let last_polled_date = Arc::new(DashMap::new());
        let handler = MetricPollHandler {
            store: store.clone(),
            snmp,
            cli: Arc::new(discovery_ssh::FakeCliClient::new()),
            devices: devices.clone(),
            device_metrics: device_metrics.clone(),
            matcher: matcher.clone(),
            settings: Arc::new(
                discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests().await,
            ),
            last_polled: last_polled.clone(),
            last_polled_date: last_polled_date.clone(),
            discovery_configs: Arc::new(
                discovery_config_store::SeaOrmDiscoveryConfigStore::new_in_memory_for_tests().await,
            ),
            pruned_generations: Arc::new(dashmap::DashMap::new()),
            topology_rules: Arc::new(
                discovery_config_store::SeaOrmTopologyRuleStore::new_in_memory_for_tests().await,
            ),
        };

        async fn tick(
            store: &Arc<dyn JobQueueStore>,
            handler: &MetricPollHandler,
            device_id: uuid::Uuid,
            generation: u64,
        ) {
            store
                .enqueue(
                    QueueKind::MetricPoll,
                    serde_json::to_value(MetricPollPayload {
                        device_id,
                        generation,
                    })
                    .unwrap(),
                    None,
                )
                .await
                .unwrap();
            let job = store
                .claim(QueueKind::MetricPoll, "test-worker", 1)
                .await
                .unwrap()
                .into_iter()
                .next()
                .unwrap();
            handler.handle(job).await.unwrap();
        }

        async fn last_attempt_at(
            devices: &Arc<dyn DeviceStore>,
            device_metrics: &Arc<dyn DeviceMetricsStore>,
            device_id: uuid::Uuid,
        ) -> chrono::DateTime<chrono::Utc> {
            discovery_devices::all_with_metrics(devices.as_ref(), device_metrics.as_ref())
                .await
                .unwrap()
                .into_iter()
                .find(|(d, _)| d.id == device_id)
                .unwrap()
                .1
                .into_iter()
                .find(|r| r.name == "x")
                .unwrap()
                .last_attempt_at
        }

        // Generation 1, first tick — due immediately (never polled before), regardless of
        // the 3600s interval.
        tick(&store, &handler, device_id, 1).await;
        let after_first = last_attempt_at(&devices, &device_metrics, device_id).await;

        // "5 seconds later, same generation — nowhere near due under 3600s": backdating
        // `last_polled`'s stored `tokio::time::Instant` directly, rather than
        // `tokio::time::pause()` + `tokio::time::advance()`, on purpose — `handle()` reads
        // real, if brief, I/O through two sea-orm/SQLite pools (`store`, `settings`), and
        // every one of those is a genuine `spawn_blocking` hop for the synchronous SQLite
        // driver; racing that against a paused, auto-advancing virtual clock was flaky
        // (`PoolTimedOut`, found live under full-suite parallel load, not guessed — the old
        // `InMemoryJobQueueStore`/`InMemorySettingsStore` had no connection/blocking-thread
        // setup at all, so this interaction never showed up before both stores' sea-orm
        // rewrites). `handle()`'s due-check only ever compares `tokio::time::Instant::now()`
        // (unpaused, real) against this map's stored value — moving the stored value
        // backward is observably identical to advancing the clock forward, without ever
        // touching the runtime's time source at all.
        if let Some(mut entry) = last_polled.get_mut(&(device_id, "x".to_string())) {
            *entry -= Duration::from_secs(5);
        }
        tick(&store, &handler, device_id, 1).await;
        assert_eq!(
            last_attempt_at(&devices, &device_metrics, device_id).await,
            after_first,
            "under the old 3600s interval, 5s later must not re-poll"
        );

        // The edit: same profile name, same match expression, only the metric's schedule
        // changes (3600s -> 1s). This must bump the version — the same mechanism already
        // covered `interval_secs` edits before `schedule` replaced it.
        let mut new_poll = BTreeMap::new();
        new_poll.insert(
            "x".to_string(),
            MetricSpec::Detailed {
                oid: "1.2.3".into(),
                columns: None,
                schedule: Some(Schedule::Periodic { interval_secs: 1 }),
                history_retention_secs: None,
                enabled: true,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
                derive: None,
            },
        );
        let new_version = discovery_dsl::compute_version(
            "true",
            &new_poll,
            &discovery_dsl::TrapsSection::default(),
            &discovery_dsl::SyslogSection::default(),
            &discovery_dsl::ServiceChecksSection::default(),
            &[],
        );
        assert_ne!(
            new_version, old_version,
            "editing a metric's schedule must bump the profile version"
        );

        // What `profile_reload.rs`'s hot-reload loop does once it notices the signature
        // changed: swap the matcher's active set, then re-run identity/dedup/apply for
        // every known device (reproduced directly here — `Dedup`/`ProfileApply`'s own
        // mechanics are already covered by their own tests elsewhere in this module; what's
        // new and under test here is specifically what `MetricPollHandler` does with it).
        matcher
            .reload(vec![profile(new_poll, new_version.clone())])
            .await;
        let decision = devices
            .apply_profile_if_changed(device_id, "p", &new_version)
            .await
            .unwrap()
            .unwrap();
        let ProfileDecision::Changed {
            generation: new_generation,
        } = decision
        else {
            panic!("a real schedule edit must be a Changed decision")
        };
        last_polled.retain(|(id, _), _| *id != device_id);
        last_polled_date.retain(|(id, _), _| *id != device_id);

        // Fresh generation's first tick — due immediately, same as generation 1's was;
        // not yet proof of the *new* interval specifically.
        tick(&store, &handler, device_id, new_generation).await;
        let after_edit = last_attempt_at(&devices, &device_metrics, device_id).await;
        assert_ne!(
            after_edit, after_first,
            "the new generation's first tick must poll immediately"
        );

        // The real proof: only 2 seconds later (same backdating technique as above) — past
        // the *new* 1s interval, but nowhere near the *old* 3600s one.
        if let Some(mut entry) = last_polled.get_mut(&(device_id, "x".to_string())) {
            *entry -= Duration::from_secs(2);
        }
        tick(&store, &handler, device_id, new_generation).await;
        assert_ne!(
            last_attempt_at(&devices, &device_metrics, device_id).await,
            after_edit,
            "2s after the edit, the NEW 1s interval must already be due again — proves the edit actually took effect, not a stale cached 3600s one"
        );
    }

    /// Full poll -> derive -> store round trip against sqlite `:memory:` (2026-09-07,
    /// derived rate/delta metrics) — the integration-level counterpart to
    /// `discovery_dsl::derive_metric`'s pure-logic unit tests: proves `MetricPollHandler`
    /// actually wires `compute_derived` up to a real `DeviceMetricsStore` round trip (read
    /// the previous cached sample, compute, write the derived value back through the exact
    /// same `record_metric_polls` call as the raw metric), not just that the pure function
    /// itself is correct in isolation.
    #[tokio::test]
    async fn metric_poll_computes_and_stores_a_derived_rate_across_two_real_ticks() {
        let (devices, device_metrics) = device_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();

        let mut poll = BTreeMap::new();
        poll.insert(
            "if_in_octets".to_string(),
            MetricSpec::Detailed {
                oid: "1.3.6.1.2.1.2.2.1.10.1".into(),
                columns: None,
                schedule: None,
                history_retention_secs: None,
                enabled: true,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
                derive: Some(discovery_dsl::DeriveKind::Rate),
            },
        );
        let profile = discovery_dsl::ProfileFile {
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            profile: discovery_dsl::ProfileMeta {
                name: "counters".into(),
                priority: 0,
            },
            match_expr: discovery_dsl::MatchSection {
                expression: "true".into(),
            },
            metrics: discovery_dsl::MetricsSection { poll },
            alerts: vec![],
            version: "v1".into(),
        };
        let matcher = Arc::new(ProfileMatcher::new(vec![profile]));
        devices
            .apply_profile_if_changed(device_id, "counters", "v1")
            .await
            .unwrap();

        let fake_snmp = Arc::new(FakeSnmpClient::new());
        fake_snmp.seed_get(
            "10.0.0.1",
            "1.3.6.1.2.1.2.2.1.10.1",
            discovery_snmp::SnmpValue::Counter(1_000),
        );
        let snmp: Arc<dyn SnmpClient> = fake_snmp.clone();
        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
        let last_polled = Arc::new(DashMap::new());
        let last_polled_date = Arc::new(DashMap::new());
        let handler = MetricPollHandler {
            store: store.clone(),
            snmp: snmp.clone(),
            cli: Arc::new(discovery_ssh::FakeCliClient::new()),
            devices: devices.clone(),
            device_metrics: device_metrics.clone(),
            matcher,
            settings: Arc::new(
                discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests().await,
            ),
            last_polled: last_polled.clone(),
            last_polled_date: last_polled_date.clone(),
            discovery_configs: Arc::new(
                discovery_config_store::SeaOrmDiscoveryConfigStore::new_in_memory_for_tests().await,
            ),
            pruned_generations: Arc::new(dashmap::DashMap::new()),
            topology_rules: Arc::new(
                discovery_config_store::SeaOrmTopologyRuleStore::new_in_memory_for_tests().await,
            ),
        };

        async fn tick(
            store: &Arc<dyn JobQueueStore>,
            handler: &MetricPollHandler,
            device_id: uuid::Uuid,
        ) {
            store
                .enqueue(
                    QueueKind::MetricPoll,
                    serde_json::to_value(MetricPollPayload {
                        device_id,
                        generation: 1,
                    })
                    .unwrap(),
                    None,
                )
                .await
                .unwrap();
            let job = store
                .claim(QueueKind::MetricPoll, "test-worker", 1)
                .await
                .unwrap()
                .into_iter()
                .next()
                .unwrap();
            handler.handle(job).await.unwrap();
        }
        fn force_due_now(
            last_polled: &DashMap<(uuid::Uuid, String), tokio::time::Instant>,
            device_id: uuid::Uuid,
        ) {
            last_polled.insert(
                (device_id, "if_in_octets".to_string()),
                tokio::time::Instant::now() - Duration::from_secs(3600),
            );
        }

        // ---- Tick 1: first-ever sample — no derived value yet, just the raw counter ----
        tick(&store, &handler, device_id).await;
        let metrics = device_metrics.get_metrics(device_id).await.unwrap();
        assert_eq!(metrics.get("if_in_octets"), Some(&MetricValue::Int(1_000)));
        assert_eq!(
            metrics.get("if_in_octets_rate"),
            None,
            "first-ever sample must not produce a derived value, not an error"
        );

        // ---- Counter genuinely increases; real wall-clock time passes between ticks ----
        fake_snmp.seed_get(
            "10.0.0.1",
            "1.3.6.1.2.1.2.2.1.10.1",
            discovery_snmp::SnmpValue::Counter(2_000),
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        force_due_now(&last_polled, device_id);
        tick(&store, &handler, device_id).await;

        let metrics = device_metrics.get_metrics(device_id).await.unwrap();
        assert_eq!(metrics.get("if_in_octets"), Some(&MetricValue::Int(2_000)));
        let rate = match metrics.get("if_in_octets_rate") {
            Some(MetricValue::Float(v)) => *v,
            other => {
                panic!("expected a computed Float rate after a genuine increase, got {other:?}")
            }
        };
        assert!(
            rate > 0.0,
            "counter increased by 1000 — rate must be positive, got {rate}"
        );

        // The derived value is a real, independently-readable stored metric — same
        // `record_metric_polls` write path as any polled metric, so it shows up in
        // `get_metric_records` with its own `polled_at`, not just in the flat bag.
        let records = device_metrics.get_metric_records(device_id).await.unwrap();
        let derived_record = records
            .iter()
            .find(|r| r.name == "if_in_octets_rate")
            .expect("derived metric must be a real device_metrics row");
        assert!(derived_record.polled_at.is_some());

        // ---- Counter genuinely decreases (device reboot resetting to ~0) — must be skipped ----
        fake_snmp.seed_get(
            "10.0.0.1",
            "1.3.6.1.2.1.2.2.1.10.1",
            discovery_snmp::SnmpValue::Counter(50),
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        force_due_now(&last_polled, device_id);
        tick(&store, &handler, device_id).await;

        let metrics = device_metrics.get_metrics(device_id).await.unwrap();
        assert_eq!(metrics.get("if_in_octets"), Some(&MetricValue::Int(50)), "raw counter must still reflect the (decreased) polled value — only the derived one skips");
        assert_eq!(metrics.get("if_in_octets_rate"), Some(&MetricValue::Float(rate)), "a wrap/reset must be skipped entirely, not guessed — the derived value stays frozen at its last real computation, never goes negative");
    }

    /// **The single most important guarantee of the whole on/off-override feature (direct
    /// user emphasis 2026-08-16): "Тут даже важнее, что бы вновь не включались метрики,
    /// которые были выключены руками".** Exact scenario the user described: a device is
    /// manually told to stop polling metric "x", then it re-matches to a *different*
    /// profile that also happens to declare "x" (enabled by default) — the manual
    /// disable must survive that reconfigure completely untouched. Drives the real
    /// `ProfileApplyHandler`/`MetricPollHandler` pipeline end to end, not just the store
    /// layer, so this actually proves the invariant nothing in that pipeline ever writes
    /// to `device_metric_settings`.
    #[tokio::test]
    async fn a_manual_metric_override_survives_reconfiguring_to_a_different_profile_with_the_same_metric_name(
    ) {
        let (devices, device_metrics) = device_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();

        // Two unrelated profiles that both happen to declare a metric named "x".
        let mut poll_a = BTreeMap::new();
        poll_a.insert(
            "x".to_string(),
            MetricSpec::Detailed {
                oid: "1.1.1".into(),
                columns: None,
                schedule: None,
                history_retention_secs: None,
                enabled: true,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
                derive: None,
            },
        );
        let mut poll_b = BTreeMap::new();
        poll_b.insert(
            "x".to_string(),
            MetricSpec::Detailed {
                oid: "2.2.2".into(),
                columns: None,
                schedule: None,
                history_retention_secs: None,
                enabled: true,
                history_keep_last_success: true,
                history_keep_last_attempt: true,
                derive: None,
            },
        );
        let profile_a = discovery_dsl::ProfileFile {
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            profile: discovery_dsl::ProfileMeta {
                name: "profile_a".into(),
                priority: 0,
            },
            match_expr: discovery_dsl::MatchSection {
                expression: "true".into(),
            },
            metrics: discovery_dsl::MetricsSection {
                poll: poll_a.clone(),
            },
            alerts: vec![],
            version: discovery_dsl::compute_version(
                "true",
                &poll_a,
                &discovery_dsl::TrapsSection::default(),
                &discovery_dsl::SyslogSection::default(),
                &discovery_dsl::ServiceChecksSection::default(),
                &[],
            ),
        };
        let profile_b = discovery_dsl::ProfileFile {
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            profile: discovery_dsl::ProfileMeta {
                name: "profile_b".into(),
                priority: 0,
            },
            match_expr: discovery_dsl::MatchSection {
                expression: "true".into(),
            },
            metrics: discovery_dsl::MetricsSection {
                poll: poll_b.clone(),
            },
            alerts: vec![],
            version: discovery_dsl::compute_version(
                "true",
                &poll_b,
                &discovery_dsl::TrapsSection::default(),
                &discovery_dsl::SyslogSection::default(),
                &discovery_dsl::ServiceChecksSection::default(),
                &[],
            ),
        };

        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
        let last_polled = Arc::new(DashMap::new());
        let last_polled_date = Arc::new(DashMap::new());
        let profile_apply_handler = ProfileApplyHandler {
            store: store.clone(),
            devices: devices.clone(),
            active_chains: Arc::new(ActiveChains::new()),
            last_polled: last_polled.clone(),
            last_polled_date: last_polled_date.clone(),
            service_check_last_polled: Arc::new(DashMap::new()),
            service_check_last_polled_date: Arc::new(DashMap::new()),
        };

        // 1. Device starts on profile_a.
        let job1 =
            enqueue_and_claim_profile_apply(&store, device_id, "profile_a", &profile_a.version)
                .await;
        profile_apply_handler.handle(job1).await.unwrap();
        assert_eq!(
            devices
                .get_device(device_id)
                .await
                .unwrap()
                .unwrap()
                .profile
                .as_deref(),
            Some("profile_a")
        );

        // 2. A human explicitly turns metric "x" off on this device — the only way this
        // table is ever written outside this test's assertions, mirroring the dashboard's
        // per-metric toggle.
        devices
            .set_metric_override(device_id, "x", false)
            .await
            .unwrap();
        assert_eq!(
            devices
                .get_metric_overrides(device_id)
                .await
                .unwrap()
                .get("x"),
            Some(&false)
        );

        // 3. The device re-matches to a completely different profile that also declares
        // "x" — e.g. its identity changed, or the match expression picked a different
        // profile this cycle. This IS a real `Changed` decision (different name).
        let job2 =
            enqueue_and_claim_profile_apply(&store, device_id, "profile_b", &profile_b.version)
                .await;
        profile_apply_handler.handle(job2).await.unwrap();
        let device = devices.get_device(device_id).await.unwrap().unwrap();
        assert_eq!(
            device.profile.as_deref(),
            Some("profile_b"),
            "the profile really did change"
        );

        // 4. THE ASSERTION THAT MATTERS: the override must be completely untouched — not
        // reset, not flipped, not deleted — despite the entire reconfigure pipeline (new
        // generation, cleared last_polled/last_polled_date, restarted MetricPoll chain)
        // having just run for real.
        assert_eq!(
            devices.get_metric_overrides(device_id).await.unwrap().get("x"),
            Some(&false),
            "a manually-disabled metric must survive reconfiguring to a different profile that happens to declare the same metric name"
        );

        // 5. And the proof that actually matters in practice: MetricPollHandler must
        // genuinely skip polling "x" on profile_b's very first tick, even though
        // profile_b's own default for "x" is `enabled: true`.
        let matcher = Arc::new(ProfileMatcher::new(vec![profile_a, profile_b]));
        let snmp: Arc<dyn SnmpClient> = Arc::new(FakeSnmpClient::new());
        let metric_poll_handler = MetricPollHandler {
            store: store.clone(),
            snmp,
            cli: Arc::new(discovery_ssh::FakeCliClient::new()),
            devices: devices.clone(),
            device_metrics: device_metrics.clone(),
            matcher,
            settings: Arc::new(
                discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests().await,
            ),
            last_polled: last_polled.clone(),
            last_polled_date: last_polled_date.clone(),
            discovery_configs: Arc::new(
                discovery_config_store::SeaOrmDiscoveryConfigStore::new_in_memory_for_tests().await,
            ),
            pruned_generations: Arc::new(dashmap::DashMap::new()),
            topology_rules: Arc::new(
                discovery_config_store::SeaOrmTopologyRuleStore::new_in_memory_for_tests().await,
            ),
        };
        let generation = devices
            .current_poll_generation(device_id)
            .await
            .unwrap()
            .unwrap();
        store
            .enqueue(
                QueueKind::MetricPoll,
                serde_json::to_value(MetricPollPayload {
                    device_id,
                    generation,
                })
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let job3 = store
            .claim(QueueKind::MetricPoll, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        metric_poll_handler.handle(job3).await.unwrap();

        let (_, records) =
            discovery_devices::all_with_metrics(devices.as_ref(), device_metrics.as_ref())
                .await
                .unwrap()
                .into_iter()
                .find(|(d, _)| d.id == device_id)
                .unwrap();
        assert!(
            records.iter().find(|r| r.name == "x").is_none(),
            "a metric forced off by a manual override must never actually be polled, even under a brand-new profile that defaults it to enabled"
        );
    }

    /// Direct user request 2026-08-16 (metric change history): `Dedup` is the single place
    /// a device's one-shot discovery-time outcomes (`SnmpPoll`'s `subnet.oids`) get
    /// persisted, via the same `record_metric_polls` write path `MetricPoll` uses — and a
    /// failed one-shot fetch must be recorded too, not just successes.
    #[tokio::test]
    async fn dedup_handler_records_one_shot_discovery_outcomes_including_failures() {
        let (devices, device_metrics) = device_stores().await;
        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
        let profiles = vec![discovery_dsl::ProfileFile {
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: Default::default(),
            profile: discovery_dsl::ProfileMeta {
                name: "generic_host".into(),
                priority: 0,
            },
            match_expr: discovery_dsl::MatchSection {
                expression: "true".into(),
            },
            metrics: discovery_dsl::MetricsSection::default(),
            alerts: vec![],
            version: "v1".into(),
        }];
        let matcher = Arc::new(ProfileMatcher::new(profiles));

        let handler = DedupHandler {
            store: store.clone(),
            devices: devices.clone(),
            device_metrics: device_metrics.clone(),
            matcher,
            reachability_chains: Arc::new(ActiveChains::default()),
        };

        let mut extra: BTreeMap<String, MetricPollOutcome> = BTreeMap::new();
        extra.insert(
            "serial_number".to_string(),
            MetricPollOutcome::Ok(MetricValue::Str("SN-1".into())),
        );
        extra.insert(
            "mgmt_ip".to_string(),
            MetricPollOutcome::Err("timeout".to_string()),
        );

        store
            .enqueue(
                QueueKind::Dedup,
                serde_json::to_value(DedupPayload {
                    ip: "10.0.0.1".into(),
                    facts: DeviceFacts {
                        ip: "10.0.0.1".into(),
                    },
                    extra: Some(extra),
                    snmp_credentials: None,
                })
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let job = store
            .claim(QueueKind::Dedup, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        handler.handle(job).await.unwrap();

        let device_id = devices
            .id_by_ip("10.0.0.1")
            .await
            .unwrap()
            .expect("Dedup must have resolved/created the device");
        let (_, records) =
            discovery_devices::all_with_metrics(devices.as_ref(), device_metrics.as_ref())
                .await
                .unwrap()
                .into_iter()
                .find(|(d, _)| d.id == device_id)
                .unwrap();

        let serial = records
            .iter()
            .find(|r| r.name == "serial_number")
            .expect("the successful one-shot outcome must be recorded");
        assert_eq!(serial.value, Some(MetricValue::Str("SN-1".into())));
        assert_eq!(serial.error, None);

        let mgmt_ip = records
            .iter()
            .find(|r| r.name == "mgmt_ip")
            .expect("the failed one-shot outcome must be recorded too, not dropped");
        assert_eq!(mgmt_ip.value, None);
        assert_eq!(mgmt_ip.error, Some("timeout".to_string()));
    }

    async fn enqueue_and_claim_profile_apply(
        store: &Arc<dyn JobQueueStore>,
        device_id: uuid::Uuid,
        profile_name: &str,
        profile_version: &str,
    ) -> Job {
        store
            .enqueue(
                QueueKind::ProfileApply,
                serde_json::to_value(ProfileApplyPayload {
                    device_id,
                    profile_name: profile_name.to_string(),
                    profile_version: profile_version.to_string(),
                })
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        store
            .claim(QueueKind::ProfileApply, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
    }

    #[tokio::test]
    async fn profile_apply_starts_a_metric_poll_chain_even_when_unchanged_the_first_time_this_process_sees_it(
    ) {
        // This is the restart-recovery scenario, found by actually restarting the agent
        // against a live Postgres and watching metric polling silently stop: the device's
        // profile is already on record (as if written by a *previous* process before a
        // restart), but no `MetricPoll` chain is running in *this* process — a fresh
        // `ActiveChains` doesn't know that, so the first `ProfileApply` for this device
        // must start one regardless of the Unchanged/Changed decision.
        let devices: Arc<dyn DeviceStore> =
            Arc::new(discovery_devices::SeaOrmDeviceStore::new_in_memory_for_tests().await);
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(device_id, "generic_switch", "v1")
            .await
            .unwrap();

        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
        let handler = ProfileApplyHandler {
            store: store.clone(),
            devices: devices.clone(),
            active_chains: Arc::new(ActiveChains::new()),
            last_polled: Arc::new(DashMap::new()),
            last_polled_date: Arc::new(DashMap::new()),
            service_check_last_polled: Arc::new(DashMap::new()),
            service_check_last_polled_date: Arc::new(DashMap::new()),
        };

        let job = enqueue_and_claim_profile_apply(&store, device_id, "generic_switch", "v1").await;
        handler.handle(job).await.unwrap();

        let stats = store.stats(QueueKind::MetricPoll).await.unwrap();
        assert_eq!(stats.pending, 1, "first sight of an already-profiled device in this process must (re)start its metric-poll chain");
        assert_eq!(
            devices.current_poll_generation(device_id).await.unwrap(),
            Some(1),
            "generation must not bump — the profile itself didn't change"
        );
    }

    #[tokio::test]
    async fn profile_apply_does_not_start_a_second_chain_for_an_unchanged_profile_in_the_same_process(
    ) {
        let devices: Arc<dyn DeviceStore> =
            Arc::new(discovery_devices::SeaOrmDeviceStore::new_in_memory_for_tests().await);
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();

        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
        let active_chains = Arc::new(ActiveChains::new());
        let handler = ProfileApplyHandler {
            store: store.clone(),
            devices: devices.clone(),
            active_chains: active_chains.clone(),
            last_polled: Arc::new(DashMap::new()),
            last_polled_date: Arc::new(DashMap::new()),
            service_check_last_polled: Arc::new(DashMap::new()),
            service_check_last_polled_date: Arc::new(DashMap::new()),
        };

        // First ProfileApply for this device in this process — starts the chain (profile
        // is new, so this is a `Changed` decision regardless of the ActiveChains check).
        let job1 = enqueue_and_claim_profile_apply(&store, device_id, "generic_switch", "v1").await;
        handler.handle(job1).await.unwrap();
        assert_eq!(store.stats(QueueKind::MetricPoll).await.unwrap().pending, 1);

        // Second ProfileApply, same process, same profile+version — must be a true no-op.
        let job2 = enqueue_and_claim_profile_apply(&store, device_id, "generic_switch", "v1").await;
        handler.handle(job2).await.unwrap();
        assert_eq!(
            store.stats(QueueKind::MetricPoll).await.unwrap().pending,
            1,
            "an unchanged profile re-seen by the same process must not start a second chain"
        );
    }

    #[tokio::test]
    async fn profile_apply_enqueues_metric_poll_when_profile_actually_changes() {
        let devices: Arc<dyn DeviceStore> =
            Arc::new(discovery_devices::SeaOrmDeviceStore::new_in_memory_for_tests().await);
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();

        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
        let handler = ProfileApplyHandler {
            store: store.clone(),
            devices: devices.clone(),
            active_chains: Arc::new(ActiveChains::new()),
            last_polled: Arc::new(DashMap::new()),
            last_polled_date: Arc::new(DashMap::new()),
            service_check_last_polled: Arc::new(DashMap::new()),
            service_check_last_polled_date: Arc::new(DashMap::new()),
        };

        let job = enqueue_and_claim_profile_apply(&store, device_id, "generic_switch", "v1").await;
        handler.handle(job).await.unwrap();

        let stats = store.stats(QueueKind::MetricPoll).await.unwrap();
        assert_eq!(stats.pending, 1);

        let queued = store
            .claim(QueueKind::MetricPoll, "test-worker", 1)
            .await
            .unwrap();
        let payload: MetricPollPayload = serde_json::from_value(queued[0].payload.clone()).unwrap();
        assert_eq!(payload.generation, 1);
        assert_eq!(queued[0].state, JobState::InProgress);
    }

    #[tokio::test]
    async fn profile_apply_reconfigures_when_only_the_profile_content_changed() {
        // Same profile *name*, different *version* (as if profiles/generic_switch.toml
        // was edited) — must still be treated as a real change.
        let devices: Arc<dyn DeviceStore> =
            Arc::new(discovery_devices::SeaOrmDeviceStore::new_in_memory_for_tests().await);
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();

        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
        let active_chains = Arc::new(ActiveChains::new());
        let handler = ProfileApplyHandler {
            store: store.clone(),
            devices: devices.clone(),
            active_chains: active_chains.clone(),
            last_polled: Arc::new(DashMap::new()),
            last_polled_date: Arc::new(DashMap::new()),
            service_check_last_polled: Arc::new(DashMap::new()),
            service_check_last_polled_date: Arc::new(DashMap::new()),
        };

        let job1 = enqueue_and_claim_profile_apply(&store, device_id, "generic_switch", "v1").await;
        handler.handle(job1).await.unwrap();
        assert_eq!(
            devices.current_poll_generation(device_id).await.unwrap(),
            Some(1)
        );

        let job2 =
            enqueue_and_claim_profile_apply(&store, device_id, "generic_switch", "v2-edited").await;
        handler.handle(job2).await.unwrap();
        assert_eq!(
            devices.current_poll_generation(device_id).await.unwrap(),
            Some(2),
            "a content-only edit (same name, different version) must still bump the generation"
        );
        assert_eq!(
            store.stats(QueueKind::MetricPoll).await.unwrap().pending,
            2,
            "each real change starts its own fresh chain"
        );
    }

    /// Direct user request 2026-08-16 ("при смене профиля нужно будет опросить весь
    /// профиль сразу"): a real profile change must clear this device's `last_polled`
    /// entries so a metric *name* reused between the old and new profile doesn't look
    /// "not due yet" on the new generation's first tick.
    #[tokio::test]
    async fn a_real_profile_change_clears_last_polled_for_that_device_but_not_others() {
        let devices: Arc<dyn DeviceStore> =
            Arc::new(discovery_devices::SeaOrmDeviceStore::new_in_memory_for_tests().await);
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        let (other_device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.2".into(),
            })
            .await
            .unwrap();

        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
        let last_polled = Arc::new(DashMap::new());
        let last_polled_date = Arc::new(DashMap::new());
        let now = tokio::time::Instant::now();
        let today = chrono::Local::now().date_naive();
        last_polled.insert((device_id, "sys_uptime".to_string()), now);
        last_polled.insert((other_device_id, "sys_uptime".to_string()), now);
        // Same-idea calendar-mode counterpart (added 2026-08-16, direct user follow-up):
        // must clear alongside `last_polled` for the same reason.
        last_polled_date.insert((device_id, "daily_report".to_string()), today);
        last_polled_date.insert((other_device_id, "daily_report".to_string()), today);

        let handler = ProfileApplyHandler {
            store: store.clone(),
            devices: devices.clone(),
            active_chains: Arc::new(ActiveChains::new()),
            last_polled: last_polled.clone(),
            last_polled_date: last_polled_date.clone(),
            service_check_last_polled: Arc::new(DashMap::new()),
            service_check_last_polled_date: Arc::new(DashMap::new()),
        };

        let job = enqueue_and_claim_profile_apply(&store, device_id, "generic_switch", "v1").await;
        handler.handle(job).await.unwrap();

        assert!(
            !last_polled.contains_key(&(device_id, "sys_uptime".to_string())),
            "the reconfigured device's stale last_polled entry must be gone, forcing an immediate re-poll of the new profile"
        );
        assert!(
            last_polled.contains_key(&(other_device_id, "sys_uptime".to_string())),
            "an unrelated device's last_polled entries must not be touched"
        );
        assert!(
            !last_polled_date.contains_key(&(device_id, "daily_report".to_string())),
            "the reconfigured device's stale last_polled_date entry must be gone too"
        );
        assert!(
            last_polled_date.contains_key(&(other_device_id, "daily_report".to_string())),
            "an unrelated device's last_polled_date entries must not be touched"
        );
    }

    /// The mirror case: an `Unchanged` decision must not clear anything — otherwise every
    /// unremarkable identity re-check would force a full re-poll of the profile for no
    /// reason.
    #[tokio::test]
    async fn an_unchanged_profile_decision_does_not_clear_last_polled() {
        let devices: Arc<dyn DeviceStore> =
            Arc::new(discovery_devices::SeaOrmDeviceStore::new_in_memory_for_tests().await);
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();

        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
        let last_polled = Arc::new(DashMap::new());
        let last_polled_date = Arc::new(DashMap::new());
        let handler = ProfileApplyHandler {
            store: store.clone(),
            devices: devices.clone(),
            active_chains: Arc::new(ActiveChains::new()),
            last_polled: last_polled.clone(),
            last_polled_date: last_polled_date.clone(),
            service_check_last_polled: Arc::new(DashMap::new()),
            service_check_last_polled_date: Arc::new(DashMap::new()),
        };

        // First apply — a real Changed, establishes the profile on record.
        let job1 = enqueue_and_claim_profile_apply(&store, device_id, "generic_switch", "v1").await;
        handler.handle(job1).await.unwrap();

        let now = tokio::time::Instant::now();
        let today = chrono::Local::now().date_naive();
        last_polled.insert((device_id, "sys_uptime".to_string()), now);
        last_polled_date.insert((device_id, "daily_report".to_string()), today);

        // Second apply — same (name, version): Unchanged.
        let job2 = enqueue_and_claim_profile_apply(&store, device_id, "generic_switch", "v1").await;
        handler.handle(job2).await.unwrap();

        assert!(
            last_polled.contains_key(&(device_id, "sys_uptime".to_string())),
            "an Unchanged decision must not clear last_polled"
        );
        assert!(
            last_polled_date.contains_key(&(device_id, "daily_report".to_string())),
            "an Unchanged decision must not clear last_polled_date either"
        );
    }

    #[tokio::test]
    async fn subnet_labels_are_written_once_and_never_overwritten() {
        use discovery_config_store::{
            DiscoveryConfig, Schedule, SeaOrmDiscoveryConfigStore, SubnetSpec,
        };
        use discovery_core::{SnmpAuth, SnmpVersion};

        let discovery_configs: Arc<dyn DiscoveryConfigStore> =
            Arc::new(SeaOrmDiscoveryConfigStore::new_in_memory_for_tests().await);
        let mut labels = std::collections::BTreeMap::new();
        labels.insert("area_name".to_string(), "Воронеж".to_string());
        discovery_configs
            .upsert(&DiscoveryConfig {
                name: "test".into(),
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
                    oids: Default::default(),
                    labels,
                    snmp_timeout_ms: None,
                    snmp_retries: None,
                    create_dead_devices: true,
                }],
            })
            .await
            .unwrap();

        // No sys_object_id/sys_descr/sys_name seeding needed — `SnmpPollHandler` no
        // longer fetches those unconditionally (2026-08-16), only whatever `subnet.oids`
        // declares (`area_name` here is a label, not an OID fetch at all).
        let snmp: Arc<dyn SnmpClient> = Arc::new(FakeSnmpClient::new());

        let (devices, device_metrics) = device_stores().await;
        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
        let handler = SnmpPollHandler {
            store: store.clone(),
            snmp,
            devices: devices.clone(),
            discovery_configs,
            settings: Arc::new(
                discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests().await,
            ),
        };

        // Cycle 1: brand-new IP — `existing_device_id` is None, so the label must be written.
        store
            .enqueue(
                QueueKind::SnmpPoll,
                serde_json::to_value(SnmpPollPayload {
                    ip: "10.0.0.1".into(),
                    recurring: false,
                })
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let job1 = store
            .claim(QueueKind::SnmpPoll, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        handler.handle(job1).await.unwrap();

        let dedup_job1 = store
            .claim(QueueKind::Dedup, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let payload1: DedupPayload = serde_json::from_value(dedup_job1.payload).unwrap();
        let extra1 = payload1
            .extra
            .expect("first identity cycle must write identity_extra");
        assert_eq!(
            extra1.get("area_name"),
            Some(&MetricPollOutcome::Ok(MetricValue::Str("Воронеж".into())))
        );

        // Now actually create the device on record, as `DedupHandler` would downstream —
        // this is what flips `existing_device_id` to `Some` on the next cycle.
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.0.0.1".into(),
            })
            .await
            .unwrap();
        device_metrics
            .record_metric_polls(device_id, &extra1)
            .await
            .unwrap();

        // Cycle 2: same IP, device already exists — label must NOT be rewritten (extra
        // must be None, telling `DeviceStore::resolve` to leave what's on record alone).
        store
            .enqueue(
                QueueKind::SnmpPoll,
                serde_json::to_value(SnmpPollPayload {
                    ip: "10.0.0.1".into(),
                    recurring: false,
                })
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let job2 = store
            .claim(QueueKind::SnmpPoll, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        handler.handle(job2).await.unwrap();

        let dedup_job2 = store
            .claim(QueueKind::Dedup, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let payload2: DedupPayload = serde_json::from_value(dedup_job2.payload).unwrap();
        assert!(
            payload2.extra.is_none(),
            "second identity cycle must not rewrite identity_extra, even for free constant labels"
        );
    }

    /// Direct user request 2026-08-29: discovery-time OIDs can be table-shaped too, not
    /// just scalar — `SnmpPollHandler` must poll a `DiscoveryOidSpec::Detailed` entry
    /// declaring `columns` via `walk()`, same as `MetricPollHandler` already does for
    /// profile metrics, and produce a `MetricValue::Table` in `identity_extra`.
    #[tokio::test]
    async fn subnet_oid_can_be_table_shaped_and_is_polled_via_walk() {
        use discovery_config_store::{
            DiscoveryConfig, DiscoveryOidSpec, Schedule, SeaOrmDiscoveryConfigStore, SubnetSpec,
        };
        use discovery_core::{SnmpAuth, SnmpVersion};

        let discovery_configs: Arc<dyn DiscoveryConfigStore> =
            Arc::new(SeaOrmDiscoveryConfigStore::new_in_memory_for_tests().await);
        let mut columns = std::collections::BTreeMap::new();
        columns.insert("ifIndex".to_string(), "1".to_string());
        columns.insert("ifDescr".to_string(), "2".to_string());
        let mut oids = std::collections::BTreeMap::new();
        oids.insert(
            "if_table".to_string(),
            DiscoveryOidSpec::Detailed {
                oid: "1.3.6.1.2.1.2.2.1".to_string(),
                columns: Some(columns),
            },
        );
        discovery_configs
            .upsert(&DiscoveryConfig {
                name: "test".into(),
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
                    oids,
                    labels: Default::default(),
                    snmp_timeout_ms: None,
                    snmp_retries: None,
                    create_dead_devices: true,
                }],
            })
            .await
            .unwrap();

        let snmp = FakeSnmpClient::new();
        snmp.seed_walk(
            "10.0.0.1",
            "1.3.6.1.2.1.2.2.1.1",
            vec![(
                "1.3.6.1.2.1.2.2.1.1.1".to_string(),
                discovery_snmp::SnmpValue::Integer(1),
            )],
        );
        snmp.seed_walk(
            "10.0.0.1",
            "1.3.6.1.2.1.2.2.1.2",
            vec![(
                "1.3.6.1.2.1.2.2.1.2.1".to_string(),
                discovery_snmp::SnmpValue::OctetString("Gi0/1".into()),
            )],
        );
        let snmp: Arc<dyn SnmpClient> = Arc::new(snmp);

        let (devices, _device_metrics) = device_stores().await;
        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
        let handler = SnmpPollHandler {
            store: store.clone(),
            snmp,
            devices,
            discovery_configs,
            settings: Arc::new(
                discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests().await,
            ),
        };

        store
            .enqueue(
                QueueKind::SnmpPoll,
                serde_json::to_value(SnmpPollPayload {
                    ip: "10.0.0.1".into(),
                    recurring: false,
                })
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let job = store
            .claim(QueueKind::SnmpPoll, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        handler.handle(job).await.unwrap();

        let dedup_job = store
            .claim(QueueKind::Dedup, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let payload: DedupPayload = serde_json::from_value(dedup_job.payload).unwrap();
        let extra = payload
            .extra
            .expect("first identity cycle must write identity_extra");
        let MetricPollOutcome::Ok(MetricValue::Table(rows)) =
            extra.get("if_table").expect("if_table must be present")
        else {
            panic!(
                "expected if_table to be Ok(MetricValue::Table(_)), got {:?}",
                extra.get("if_table")
            );
        };
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].fields.get("ifIndex"), Some(&MetricValue::Int(1)));
        assert_eq!(
            rows[0].fields.get("ifDescr"),
            Some(&MetricValue::Str("Gi0/1".into()))
        );
    }

    /// Direct user request 2026-08-18: "если ping мертвый, не создавать устройство" —
    /// `create_dead_devices: false` (the default) plus a dead ping must not enqueue
    /// `SnmpPoll` at all, and must not mark `identity_chains` either (see
    /// `DiscoveryHandler`'s docs for why the latter matters: marking it would permanently
    /// block a *later* discovery run from ever reconsidering this same IP).
    async fn discovery_config_with_create_dead_devices(
        create_dead_devices: bool,
    ) -> Arc<dyn DiscoveryConfigStore> {
        use discovery_config_store::{
            DiscoveryConfig, Schedule, SeaOrmDiscoveryConfigStore, SubnetSpec,
        };
        use discovery_core::{SnmpAuth, SnmpVersion};

        let discovery_configs: Arc<dyn DiscoveryConfigStore> =
            Arc::new(SeaOrmDiscoveryConfigStore::new_in_memory_for_tests().await);
        discovery_configs
            .upsert(&DiscoveryConfig {
                name: "test".into(),
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
                    oids: Default::default(),
                    labels: Default::default(),
                    snmp_timeout_ms: None,
                    snmp_retries: None,
                    create_dead_devices,
                }],
            })
            .await
            .unwrap();
        discovery_configs
    }

    #[tokio::test]
    async fn dead_candidate_is_skipped_entirely_when_create_dead_devices_is_false() {
        let discovery_configs = discovery_config_with_create_dead_devices(false).await;
        let pinger = discovery_ping::FakePinger::new();
        // "10.0.0.5" deliberately never seeded — FakePinger defaults an unseeded IP to
        // unreachable, exactly like a genuinely dead address.
        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
        let identity_chains = Arc::new(ActiveChains::new());
        let handler = DiscoveryHandler {
            store: store.clone(),
            identity_chains: identity_chains.clone(),
            discovery_configs,
            pinger: Arc::new(pinger),
            settings: Arc::new(
                discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests().await,
            ),
        };

        store
            .enqueue(
                QueueKind::Discovery,
                serde_json::to_value(DiscoveryPayload {
                    ip: "10.0.0.5".into(),
                })
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let job = store
            .claim(QueueKind::Discovery, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        handler.handle(job).await.unwrap();

        let stats = store.stats(QueueKind::SnmpPoll).await.unwrap();
        assert_eq!(
            stats.pending, 0,
            "a dead candidate must never get an SnmpPoll job — no Device, no permanent chain"
        );
        assert!(
            !identity_chains.contains(&"10.0.0.5".to_string()),
            "must not be marked either — a later discovery run has to be free to re-check it"
        );
    }

    #[tokio::test]
    async fn live_candidate_still_proceeds_normally_when_create_dead_devices_is_false() {
        let discovery_configs = discovery_config_with_create_dead_devices(false).await;
        let pinger = discovery_ping::FakePinger::new();
        pinger.seed("10.0.0.6", true);
        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
        let identity_chains = Arc::new(ActiveChains::new());
        let handler = DiscoveryHandler {
            store: store.clone(),
            identity_chains: identity_chains.clone(),
            discovery_configs,
            pinger: Arc::new(pinger),
            settings: Arc::new(
                discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests().await,
            ),
        };

        store
            .enqueue(
                QueueKind::Discovery,
                serde_json::to_value(DiscoveryPayload {
                    ip: "10.0.0.6".into(),
                })
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let job = store
            .claim(QueueKind::Discovery, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        handler.handle(job).await.unwrap();

        let stats = store.stats(QueueKind::SnmpPoll).await.unwrap();
        assert_eq!(
            stats.pending, 1,
            "a live candidate must still start its identity chain as before"
        );
        assert!(identity_chains.contains(&"10.0.0.6".to_string()));
    }

    #[tokio::test]
    async fn create_dead_devices_true_bypasses_the_ping_gate_entirely() {
        let discovery_configs = discovery_config_with_create_dead_devices(true).await;
        // Not seeded — would be "dead" under the false-default policy, but this subnet
        // opted back into the old unconditional behavior.
        let pinger = discovery_ping::FakePinger::new();
        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
        let handler = DiscoveryHandler {
            store: store.clone(),
            identity_chains: Arc::new(ActiveChains::new()),
            discovery_configs,
            pinger: Arc::new(pinger),
            settings: Arc::new(
                discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests().await,
            ),
        };

        store
            .enqueue(
                QueueKind::Discovery,
                serde_json::to_value(DiscoveryPayload {
                    ip: "10.0.0.7".into(),
                })
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let job = store
            .claim(QueueKind::Discovery, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        handler.handle(job).await.unwrap();

        let stats = store.stats(QueueKind::SnmpPoll).await.unwrap();
        assert_eq!(stats.pending, 1, "create_dead_devices=true must skip the ping check and proceed exactly like before this gate existed");
    }

    // ---------------------------------------------------------------------------------
    // ServiceCheckPollHandler — L4/L7 service checks (2026-09-07)
    // ---------------------------------------------------------------------------------

    fn a_service_check(
        name: &str,
        protocol: discovery_dsl::ServiceCheckProtocol,
        port: u16,
    ) -> discovery_dsl::ServiceCheckSpec {
        discovery_dsl::ServiceCheckSpec {
            name: name.to_string(),
            protocol,
            target: None,
            port,
            path: None,
            expected_status: None,
            body_contains: None,
            timeout_ms: None,
            enabled: true,
        }
    }

    #[test]
    fn service_check_target_is_limited_to_the_device_management_ip() {
        assert_eq!(
            resolve_service_check_host(None, "10.0.0.5").unwrap(),
            "10.0.0.5"
        );
        assert_eq!(
            resolve_service_check_host(Some("10.0.0.5"), "10.0.0.5").unwrap(),
            "10.0.0.5"
        );
        assert!(resolve_service_check_host(Some("127.0.0.1"), "10.0.0.5").is_err());
        assert!(resolve_service_check_host(Some("metadata.internal"), "10.0.0.5").is_err());
    }

    fn service_check_profile(
        name: &str,
        checks: Vec<discovery_dsl::ServiceCheckSpec>,
        version: &str,
    ) -> discovery_dsl::ProfileFile {
        discovery_dsl::ProfileFile {
            profile: discovery_dsl::ProfileMeta {
                name: name.to_string(),
                priority: 0,
            },
            match_expr: discovery_dsl::MatchSection {
                expression: "true".into(),
            },
            metrics: discovery_dsl::MetricsSection::default(),
            traps: Default::default(),
            syslog: Default::default(),
            service_checks: discovery_dsl::ServiceChecksSection {
                checks,
                schedule: None,
                history_retention_secs: None,
            },
            alerts: vec![],
            version: version.to_string(),
        }
    }

    async fn service_check_handler(
        devices: Arc<dyn DeviceStore>,
        device_metrics: Arc<dyn DeviceMetricsStore>,
        matcher: Arc<ProfileMatcher>,
        checker: Arc<dyn discovery_servicecheck::ServiceChecker>,
        store: Arc<dyn JobQueueStore>,
    ) -> ServiceCheckPollHandler {
        ServiceCheckPollHandler {
            store,
            devices,
            device_metrics,
            matcher,
            checker,
            settings: Arc::new(
                discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests().await,
            ),
            last_polled: Arc::new(DashMap::new()),
            last_polled_date: Arc::new(DashMap::new()),
        }
    }

    /// The core contract: one row per *enabled* check, `ok`/`latency_ms`/`error` populated
    /// per `discovery_servicecheck::CheckOutcome`, a disabled check contributing no row at
    /// all (same "disappears, doesn't zero out" convention documented on the handler).
    #[tokio::test]
    async fn service_check_poll_writes_one_row_per_enabled_check_and_skips_disabled_ones() {
        let (devices, device_metrics) = device_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.5.5.5".into(),
            })
            .await
            .unwrap();

        let checks = vec![
            a_service_check("ssh", discovery_dsl::ServiceCheckProtocol::Tcp, 22),
            a_service_check("web", discovery_dsl::ServiceCheckProtocol::Tcp, 80),
            discovery_dsl::ServiceCheckSpec {
                enabled: false,
                ..a_service_check(
                    "disabled_one",
                    discovery_dsl::ServiceCheckProtocol::Tcp,
                    8080,
                )
            },
        ];
        let profile = service_check_profile("svc", checks, "v1");
        let matcher = Arc::new(ProfileMatcher::new(vec![profile]));
        let generation = devices
            .apply_profile_if_changed(device_id, "svc", "v1")
            .await
            .unwrap()
            .unwrap();
        let generation = match generation {
            ProfileDecision::Changed { generation } => generation,
            ProfileDecision::Unchanged { generation } => generation,
        };

        let checker = Arc::new(discovery_servicecheck::FakeServiceChecker::new());
        checker.seed_ok("10.5.5.5", 22, 3);
        checker.seed_err("10.5.5.5", 80, "connection refused");
        let checker: Arc<dyn discovery_servicecheck::ServiceChecker> = checker;

        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
        let handler = service_check_handler(
            devices.clone(),
            device_metrics.clone(),
            matcher,
            checker,
            store.clone(),
        )
        .await;

        store
            .enqueue(
                QueueKind::ServiceCheckPoll,
                serde_json::to_value(ServiceCheckPollPayload {
                    device_id,
                    generation,
                })
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let job = store
            .claim(QueueKind::ServiceCheckPoll, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        handler.handle(job).await.unwrap();

        let (_, metrics) =
            discovery_devices::get(devices.as_ref(), device_metrics.as_ref(), device_id)
                .await
                .unwrap()
                .unwrap();
        let MetricValue::Table(rows) = metrics
            .get(SERVICE_CHECKS_METRIC_NAME)
            .expect("service_checks metric must be recorded")
        else {
            panic!("service_checks must be table-shaped");
        };
        assert_eq!(
            rows.len(),
            2,
            "the disabled check must contribute no row at all"
        );

        let ssh = rows.iter().find(|r| r.index == "ssh").unwrap();
        assert_eq!(ssh.fields.get("ok"), Some(&MetricValue::Bool(true)));
        assert_eq!(ssh.fields.get("latency_ms"), Some(&MetricValue::Int(3)));
        assert_eq!(
            ssh.fields.get("protocol"),
            Some(&MetricValue::Str("tcp".to_string()))
        );
        assert_eq!(
            ssh.fields.get("target"),
            Some(&MetricValue::Str("10.5.5.5:22".to_string()))
        );
        assert!(
            ssh.fields.get("error").is_none(),
            "a successful check must not carry an error field"
        );

        let web = rows.iter().find(|r| r.index == "web").unwrap();
        assert_eq!(web.fields.get("ok"), Some(&MetricValue::Bool(false)));
        assert_eq!(
            web.fields.get("error"),
            Some(&MetricValue::Str("connection refused".to_string()))
        );

        assert!(
            rows.iter().all(|r| r.index != "disabled_one"),
            "a disabled check must never appear as a row"
        );

        // Enqueues AlertEval too, same convention every other write path in this file uses.
        let stats = store.stats(QueueKind::AlertEval).await.unwrap();
        assert_eq!(stats.pending, 1);
    }

    /// Same generation-guard contract `MetricPollHandler`'s own stale-generation test
    /// proves — a profile change bumps the generation, and the *old* chain's already
    /// in-flight tick must be a no-op, not a race against the new one.
    #[tokio::test]
    async fn service_check_poll_stale_generation_does_not_touch_device_state() {
        let (devices, device_metrics) = device_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.5.5.6".into(),
            })
            .await
            .unwrap();

        let checks = vec![a_service_check(
            "ssh",
            discovery_dsl::ServiceCheckProtocol::Tcp,
            22,
        )];
        let matcher = Arc::new(ProfileMatcher::new(vec![
            service_check_profile("svc_a", checks.clone(), "v1"),
            service_check_profile("svc_b", checks, "v1"),
        ]));

        devices
            .apply_profile_if_changed(device_id, "svc_a", "v1")
            .await
            .unwrap(); // generation 1
        devices
            .apply_profile_if_changed(device_id, "svc_b", "v1")
            .await
            .unwrap(); // generation 2 — supersedes it
        assert_eq!(
            devices.current_poll_generation(device_id).await.unwrap(),
            Some(2)
        );

        let checker: Arc<dyn discovery_servicecheck::ServiceChecker> =
            Arc::new(discovery_servicecheck::FakeServiceChecker::new());
        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
        let handler = service_check_handler(
            devices.clone(),
            device_metrics.clone(),
            matcher,
            checker,
            store.clone(),
        )
        .await;

        // A stale job still carrying generation 1.
        store
            .enqueue(
                QueueKind::ServiceCheckPoll,
                serde_json::to_value(ServiceCheckPollPayload {
                    device_id,
                    generation: 1,
                })
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let job = store
            .claim(QueueKind::ServiceCheckPoll, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        handler.handle(job).await.unwrap();

        let (_, metrics) =
            discovery_devices::get(devices.as_ref(), device_metrics.as_ref(), device_id)
                .await
                .unwrap()
                .unwrap();
        assert!(
            metrics.0.is_empty(),
            "a stale-generation poll must not record metrics"
        );
    }

    /// Same "freeze, don't force-close" contract `MetricPollHandler`'s own disabled-device
    /// test proves — the actual probing is skipped while `Device::enabled == false`, but
    /// the chain keeps ticking, so re-enabling resumes on the very next tick with no
    /// restart.
    #[tokio::test]
    async fn service_check_poll_disabled_device_is_not_probed_but_resumes_once_re_enabled() {
        let (devices, device_metrics) = device_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.5.5.7".into(),
            })
            .await
            .unwrap();
        devices.set_enabled(device_id, false).await.unwrap();

        let checks = vec![a_service_check(
            "ssh",
            discovery_dsl::ServiceCheckProtocol::Tcp,
            22,
        )];
        let generation = match devices
            .apply_profile_if_changed(device_id, "svc", "v1")
            .await
            .unwrap()
            .unwrap()
        {
            ProfileDecision::Changed { generation } => generation,
            ProfileDecision::Unchanged { generation } => generation,
        };
        let matcher = Arc::new(ProfileMatcher::new(vec![service_check_profile(
            "svc", checks, "v1",
        )]));

        let checker = Arc::new(discovery_servicecheck::FakeServiceChecker::new());
        checker.seed_ok("10.5.5.7", 22, 1);
        let checker: Arc<dyn discovery_servicecheck::ServiceChecker> = checker;
        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
        let handler = service_check_handler(
            devices.clone(),
            device_metrics.clone(),
            matcher,
            checker,
            store.clone(),
        )
        .await;

        store
            .enqueue(
                QueueKind::ServiceCheckPoll,
                serde_json::to_value(ServiceCheckPollPayload {
                    device_id,
                    generation,
                })
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let job = store
            .claim(QueueKind::ServiceCheckPoll, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        handler.handle(job).await.unwrap();

        let (_, metrics) =
            discovery_devices::get(devices.as_ref(), device_metrics.as_ref(), device_id)
                .await
                .unwrap()
                .unwrap();
        assert!(
            metrics.0.is_empty(),
            "a disabled device must not be probed at all"
        );

        devices.set_enabled(device_id, true).await.unwrap();
        store
            .enqueue(
                QueueKind::ServiceCheckPoll,
                serde_json::to_value(ServiceCheckPollPayload {
                    device_id,
                    generation,
                })
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let job2 = store
            .claim(QueueKind::ServiceCheckPoll, "test-worker", 1)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        handler.handle(job2).await.unwrap();

        let (_, metrics) =
            discovery_devices::get(devices.as_ref(), device_metrics.as_ref(), device_id)
                .await
                .unwrap()
                .unwrap();
        assert!(
            metrics.get(SERVICE_CHECKS_METRIC_NAME).is_some(),
            "re-enabling must resume probing on the very next tick, no restart needed"
        );
    }

    /// Own interval respected — same backdating technique
    /// `editing_a_metrics_schedule_in_the_profile_changes_the_actual_poll_cadence` uses
    /// (moving the stored `Instant` back rather than pausing the runtime clock, for the
    /// same real-I/O-vs-paused-clock flakiness reason documented there).
    #[tokio::test]
    async fn service_check_poll_respects_its_own_interval_not_every_tick() {
        let (devices, device_metrics) = device_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.5.5.8".into(),
            })
            .await
            .unwrap();

        let checks = vec![a_service_check(
            "ssh",
            discovery_dsl::ServiceCheckProtocol::Tcp,
            22,
        )];
        let mut profile = service_check_profile("svc", checks, "v1");
        profile.service_checks.schedule = Some(Schedule::Periodic {
            interval_secs: 3600,
        });
        let matcher = Arc::new(ProfileMatcher::new(vec![profile]));
        let generation = match devices
            .apply_profile_if_changed(device_id, "svc", "v1")
            .await
            .unwrap()
            .unwrap()
        {
            ProfileDecision::Changed { generation } => generation,
            ProfileDecision::Unchanged { generation } => generation,
        };

        let checker = Arc::new(discovery_servicecheck::FakeServiceChecker::new());
        checker.seed_ok("10.5.5.8", 22, 1);
        let checker: Arc<dyn discovery_servicecheck::ServiceChecker> = checker;
        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
        let last_polled = Arc::new(DashMap::new());
        let handler = ServiceCheckPollHandler {
            store: store.clone(),
            devices: devices.clone(),
            device_metrics: device_metrics.clone(),
            matcher,
            checker,
            settings: Arc::new(
                discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests().await,
            ),
            last_polled: last_polled.clone(),
            last_polled_date: Arc::new(DashMap::new()),
        };

        async fn tick(
            store: &Arc<dyn JobQueueStore>,
            handler: &ServiceCheckPollHandler,
            device_id: uuid::Uuid,
            generation: u64,
        ) {
            store
                .enqueue(
                    QueueKind::ServiceCheckPoll,
                    serde_json::to_value(ServiceCheckPollPayload {
                        device_id,
                        generation,
                    })
                    .unwrap(),
                    None,
                )
                .await
                .unwrap();
            let job = store
                .claim(QueueKind::ServiceCheckPoll, "test-worker", 1)
                .await
                .unwrap()
                .into_iter()
                .next()
                .unwrap();
            handler.handle(job).await.unwrap();
        }
        async fn last_attempt_at(
            devices: &Arc<dyn DeviceStore>,
            device_metrics: &Arc<dyn DeviceMetricsStore>,
            device_id: uuid::Uuid,
        ) -> chrono::DateTime<chrono::Utc> {
            discovery_devices::all_with_metrics(devices.as_ref(), device_metrics.as_ref())
                .await
                .unwrap()
                .into_iter()
                .find(|(d, _)| d.id == device_id)
                .unwrap()
                .1
                .into_iter()
                .find(|r| r.name == SERVICE_CHECKS_METRIC_NAME)
                .unwrap()
                .last_attempt_at
        }

        tick(&store, &handler, device_id, generation).await;
        let after_first = last_attempt_at(&devices, &device_metrics, device_id).await;

        // 5 virtual seconds "later" (backdated) — nowhere near due under the 3600s interval.
        if let Some(mut entry) = last_polled.get_mut(&device_id) {
            *entry -= Duration::from_secs(5);
        }
        tick(&store, &handler, device_id, generation).await;
        assert_eq!(
            last_attempt_at(&devices, &device_metrics, device_id).await,
            after_first,
            "under a 3600s interval, 5s later must not re-probe"
        );

        // Far enough back to be due again.
        if let Some(mut entry) = last_polled.get_mut(&device_id) {
            *entry -= Duration::from_secs(3601);
        }
        tick(&store, &handler, device_id, generation).await;
        assert_ne!(
            last_attempt_at(&devices, &device_metrics, device_id).await,
            after_first,
            "past the 3600s interval, the chain must probe again"
        );
    }

    /// `ProfileApplyHandler` must start both `MetricPoll` and `ServiceCheckPoll` together —
    /// same generation, same "reconfigure or first-time-this-process" trigger — proving the
    /// new chain isn't left behind as an oversight alongside the pre-existing one.
    #[tokio::test]
    async fn profile_apply_starts_the_service_check_chain_alongside_metric_poll() {
        let (devices, _device_metrics) = device_stores().await;
        let (device_id, _) = devices
            .resolve(DeviceFacts {
                ip: "10.5.5.9".into(),
            })
            .await
            .unwrap();
        let store: Arc<dyn JobQueueStore> =
            Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);

        let handler = ProfileApplyHandler {
            store: store.clone(),
            devices: devices.clone(),
            active_chains: Arc::new(ActiveChains::new()),
            last_polled: Arc::new(DashMap::new()),
            last_polled_date: Arc::new(DashMap::new()),
            service_check_last_polled: Arc::new(DashMap::new()),
            service_check_last_polled_date: Arc::new(DashMap::new()),
        };

        let job = enqueue_and_claim_profile_apply(&store, device_id, "svc", "v1").await;
        handler.handle(job).await.unwrap();

        assert_eq!(store.stats(QueueKind::MetricPoll).await.unwrap().pending, 1);
        assert_eq!(store.stats(QueueKind::ServiceCheckPoll).await.unwrap().pending, 1, "ServiceCheckPoll must be started alongside MetricPoll on the very first ProfileApply for a device");
    }
    async fn capability_handler(mut rule: AlertRule) -> (AlertEvalHandler, Device, AlertRule) {
        let (devices, metrics, store) = device_and_alert_stores().await;
        let (id, _) = devices
            .resolve(DeviceFacts {
                ip: "127.0.0.1".into(),
            })
            .await
            .unwrap();
        devices
            .apply_profile_if_changed(id, "port_monitor", "v1")
            .await
            .unwrap();
        rule.row_metric = None;
        rule.row_key_expression = None;
        let handler = alert_eval_handler(
            devices.clone(),
            metrics,
            store,
            Arc::new(discovery_core::AlertStateTracker::new()),
            rule.clone(),
        );
        (
            handler,
            devices.get_device(id).await.unwrap().unwrap(),
            rule,
        )
    }
    #[tokio::test]
    async fn capability_expression_errors_never_close_incident_or_advance_recovery_timer() {
        let (h, d, mut r) = capability_handler(high_cpu_rule(None)).await;
        let now = chrono::Utc::now();
        let mut metrics = Metrics::default();
        metrics.insert("cpu", MetricValue::Int(99));
        h.observe_rule(&r, &d, &metrics, None, None, false, now)
            .await;
        let first = h.alert_store.list(&Default::default()).await.unwrap().items[0].clone();
        r.expression = "1 / 0 > 2".into();
        h.observe_rule(
            &r,
            &d,
            &metrics,
            None,
            None,
            false,
            now + chrono::Duration::seconds(1),
        )
        .await;
        assert_eq!(
            h.alert_store.get(first.id).await.unwrap().unwrap().state,
            discovery_core::AlertState::Active
        );
        assert_eq!(
            h.alerts.rule_status(d.id, &r.name, None).unwrap().state,
            discovery_core::RuleEvaluationState::Error
        );
        r.expression = "7".into();
        h.observe_rule(
            &r,
            &d,
            &metrics,
            None,
            None,
            false,
            now + chrono::Duration::seconds(2),
        )
        .await;
        assert!(h
            .alerts
            .rule_status(d.id, &r.name, None)
            .unwrap()
            .error
            .unwrap()
            .contains("boolean"));
        r.expression = "false".into();
        r.clear_after_seconds = Some(5);
        h.observe_rule(
            &r,
            &d,
            &metrics,
            None,
            None,
            false,
            now + chrono::Duration::seconds(3),
        )
        .await;
        r.expression = "1 / 0 > 2".into();
        h.observe_rule(
            &r,
            &d,
            &metrics,
            None,
            None,
            false,
            now + chrono::Duration::seconds(4),
        )
        .await;
        assert!(h
            .alerts
            .rule_status(d.id, &r.name, None)
            .unwrap()
            .recovery_since
            .is_none());
    }
    #[tokio::test]
    async fn capability_blank_optional_expressions_preserve_default_recovery() {
        let (h, d, mut r) = capability_handler(high_cpu_rule(None)).await;
        r.expression = "true".into();
        r.deactivation_expression = Some("  ".into());
        r.facts_expression = Some("".into());
        let now = chrono::Utc::now();
        h.observe_rule(&r, &d, &Metrics::default(), None, None, false, now).await;
        assert_eq!(h.alerts.active_alerts_for_device(d.id).len(), 1);
        r.expression = "false".into();
        h.observe_rule(&r, &d, &Metrics::default(), None, None, false, now + chrono::Duration::seconds(1)).await;
        assert!(h.alerts.active_alerts_for_device(d.id).is_empty());
    }

    #[tokio::test]
    async fn capability_change_first_sample_is_silent_and_captures_old_new_values() {
        let (h, d, mut r) = capability_handler(high_cpu_rule(None)).await;
        r.policy.mode = discovery_core::AlertMode::Change;
        r.expression = "metrics.cpu".into();
        let now = chrono::Utc::now();
        let mut metrics = Metrics::default();
        metrics.insert("cpu", MetricValue::Int(1));
        h.observe_rule(&r, &d, &metrics, None, None, false, now)
            .await;
        assert_eq!(
            h.alert_store.list(&Default::default()).await.unwrap().total,
            0
        );
        h.observe_rule(&r, &d, &metrics, None, None, false, now)
            .await;
        metrics.insert("cpu", MetricValue::Int(2));
        h.observe_rule(&r, &d, &metrics, None, None, false, now)
            .await;
        let a = h.alert_store.list(&Default::default()).await.unwrap().items[0].clone();
        assert_eq!(a.details.previous_value, Some(serde_json::json!(1)));
        assert_eq!(a.details.observed_value, Some(serde_json::json!(2)));
        assert!(a.details.policy.acknowledge_required);
        let snapshot = h.alerts.snapshot_for_device(d.id);
        let restored = discovery_core::AlertStateTracker::new();
        restored.restore_active(a);
        restored.restore_snapshot(d.id, snapshot);
        assert_eq!(
            restored.rule_status(d.id, &r.name, None).unwrap().value,
            Some(serde_json::json!(2))
        );
    }
    #[tokio::test]
    async fn capability_dynamic_bounds_accept_boundary_and_reject_invalid_ranges() {
        let (h, d, mut r) = capability_handler(high_cpu_rule(None)).await;
        let now = chrono::Utc::now();
        r.policy.mode = discovery_core::AlertMode::Baseline;
        r.expression = "metrics.cpu".into();
        r.policy.lower_expression = Some("10".into());
        r.policy.upper_expression = Some("avg(history.cpu) + 10.0".into());
        let mut status = discovery_core::AlertRuleStatus::new(&r.name, None, now);
        let mut metrics = Metrics::default();
        metrics.insert("cpu", MetricValue::Int(40));
        let extra = serde_json::json!({"history":{"cpu":[10,30]}});
        let (activation, _, details) = h
            .evaluate_observation_for_test(&r, &d, &metrics, &extra, &mut status)
            .unwrap();
        assert!(activation);
        assert_eq!(details.upper_bound, Some(30.0));
        metrics.insert("cpu", MetricValue::Int(30));
        assert!(
            !h.evaluate_observation_for_test(&r, &d, &metrics, &extra, &mut status)
                .unwrap()
                .0
        );
        r.policy.lower_expression = Some("50".into());
        assert!(h
            .evaluate_observation_for_test(&r, &d, &metrics, &extra, &mut status)
            .is_err());
        r.policy.lower_expression = None;
        assert!(h
            .evaluate_observation_for_test(
                &r,
                &d,
                &metrics,
                &serde_json::json!({"history":{"cpu":[]}}),
                &mut status
            )
            .is_err());
    }
    #[tokio::test]
    async fn capability_event_bursts_count_packets_once_and_recover_after_quiet_delay() {
        let (h, d, mut r) = capability_handler(high_cpu_rule(None)).await;
        let now = chrono::Utc::now();
        r.policy.mode = discovery_core::AlertMode::Event;
        r.expression = "event.status == 2".into();
        r.clear_after_seconds = Some(3);
        r.activate_after_seconds = Some(2);
        r.policy.event = Some(discovery_core::EventTrigger {
            metric: "syslog_link".into(),
            count: 2,
            window_seconds: 30,
            key_expression: Some("event.port".into()),
            recovery_expression: Some("event.status == 1".into()),
        });
        for n in 0..2 {
            h.alert_store
                .record_source_event(&discovery_core::AlertSourceEvent {
                    id: uuid::Uuid::new_v4(),
                    device_id: d.id,
                    metric: "syslog_link".into(),
                    received_at: now + chrono::Duration::milliseconds(n),
                    data: serde_json::json!({"fields":{"status":2,"port":"eth0"}}),
                })
                .await
                .unwrap();
        }
        h.eval_event_rule(
            &r,
            &d,
            &Metrics::default(),
            now + chrono::Duration::seconds(1),
        )
        .await;
        assert!(h.alerts.active_alerts().is_empty());
        assert_eq!(
            h.alerts
                .rule_status(d.id, &r.name, Some("eth0"))
                .unwrap()
                .event_count,
            2
        );
        h.eval_event_rule(
            &r,
            &d,
            &Metrics::default(),
            now + chrono::Duration::seconds(3),
        )
        .await;
        let a = h.alerts.active_alerts()[0].clone();
        assert_eq!(a.row_key.as_deref(), Some("eth0"));
        assert_eq!(a.details.raised_count, 2);
        h.alert_store
            .record_source_event(&discovery_core::AlertSourceEvent {
                id: uuid::Uuid::new_v4(),
                device_id: d.id,
                metric: "syslog_link".into(),
                received_at: now + chrono::Duration::seconds(4),
                data: serde_json::json!({"fields":{"status":1,"port":"eth0"}}),
            })
            .await
            .unwrap();
        h.eval_event_rule(
            &r,
            &d,
            &Metrics::default(),
            now + chrono::Duration::seconds(4),
        )
        .await;
        assert_eq!(h.alerts.active_alerts().len(), 1);
        h.eval_event_rule(
            &r,
            &d,
            &Metrics::default(),
            now + chrono::Duration::seconds(7),
        )
        .await;
        let a = h.alert_store.get(a.id).await.unwrap().unwrap();
        assert_eq!(a.state, AlertState::Cleared);
        assert_eq!(a.details.recovery_data.unwrap()["data"]["status"], 1);
        h.eval_event_rule(
            &r,
            &d,
            &Metrics::default(),
            now + chrono::Duration::seconds(8),
        )
        .await;
        assert_eq!(
            h.alert_store.list(&Default::default()).await.unwrap().total,
            1
        );
    }
    #[tokio::test]
    async fn capability_event_pulses_require_ack_and_maintenance_discards_backlog() {
        let (h, d, mut r) = capability_handler(high_cpu_rule(None)).await;
        let now = chrono::Utc::now();
        r.policy.mode = discovery_core::AlertMode::Event;
        r.expression = "true".into();
        r.policy.event = Some(discovery_core::EventTrigger {
            metric: "trap_link".into(),
            count: 1,
            window_seconds: 30,
            key_expression: None,
            recovery_expression: None,
        });
        let event = discovery_core::AlertSourceEvent {
            id: uuid::Uuid::new_v4(),
            device_id: d.id,
            metric: "trap_link".into(),
            received_at: now,
            data: serde_json::json!({"index":"1","fields":{"status":2}}),
        };
        h.alert_store.record_source_event(&event).await.unwrap();
        h.eval_event_rule(&r, &d, &Metrics::default(), now).await;
        h.eval_event_rule(&r, &d, &Metrics::default(), now).await;
        let p = h.alert_store.list(&Default::default()).await.unwrap();
        assert_eq!(p.total, 1);
        assert!(p.items[0].details.policy.acknowledge_required);
        h.record_skipped(
            &r,
            &d,
            discovery_core::RuleEvaluationState::Maintenance,
            now + chrono::Duration::seconds(1),
        );
        h.eval_event_rule(
            &r,
            &d,
            &Metrics::default(),
            now + chrono::Duration::seconds(2),
        )
        .await;
        assert_eq!(
            h.alert_store.list(&Default::default()).await.unwrap().total,
            1
        );
    }
    #[tokio::test]
    async fn capability_response_escalation_is_idempotent_and_acknowledgment_deescalates() {
        let (mut h, d, mut r) = capability_handler(high_cpu_rule(None)).await;
        h.queue = Arc::new(SeaOrmJobQueueStore::new_in_memory_for_tests().await);
        h.auth = Arc::new(discovery_auth::SeaOrmAuthStore::new(
            discovery_migration::connect_in_memory_for_tests().await,
        ));
        h.notification_rules = Arc::new(
            discovery_config_store::SeaOrmNotificationRuleStore::new_in_memory_for_tests().await,
        );
        h.notification_channels = Arc::new(
            discovery_config_store::SeaOrmNotificationChannelStore::new_in_memory_for_tests().await,
        );
        let user = h
            .auth
            .create_user("recipient", "test-password-123456", true, false, None)
            .await
            .unwrap();
        h.notification_channels
            .upsert(&notification_channel(user.id))
            .await
            .unwrap();
        let mut notify =
            notification_rule(vec![discovery_config_store::RecipientRef::User(user.id)]);
        notify.notify_on_activate = false;
        notify.notify_on_clear = false;
        notify.selection.notify_on_escalation = true;
        notify.selection.notify_on_deescalation = true;
        notify.selection.alert_names = vec![r.name.clone()];
        notify.selection.recipient_expression = Some("user.username == \"recipient\"".into());
        h.notification_rules.upsert(&notify).await.unwrap();
        r.expression = "true".into();
        r.policy.acknowledge_required = true;
        r.policy.escalate_after_seconds = Some(2);
        r.policy.actions = vec![discovery_core::AlertAction {
            on: discovery_core::AlertLifecycle::Escalated,
            action: discovery_core::payload::OperatorAction::PollNow,
            condition: Some("alert.details.response_escalated".into()),
        }];
        let now = chrono::Utc::now();
        h.observe_rule(&r, &d, &Metrics::default(), None, None, false, now)
            .await;
        let id = h.alerts.active_alerts()[0].id;
        h.eval_response_escalation(&d, now + chrono::Duration::seconds(2))
            .await;
        h.eval_response_escalation(&d, now + chrono::Duration::seconds(3))
            .await;
        assert!(
            h.alert_store
                .get(id)
                .await
                .unwrap()
                .unwrap()
                .details
                .response_escalated
        );
        let actions = h
            .queue
            .claim(QueueKind::OperatorAction, "test", 10)
            .await
            .unwrap();
        assert_eq!(actions.len(), 1);
        let action: discovery_core::payload::OperatorActionPayload =
            serde_json::from_value(actions[0].payload.clone()).unwrap();
        assert_eq!(action.alert_id, Some(id));
        let jobs = claim_notification_dispatch_jobs(&h.queue).await;
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].trigger, NotificationTrigger::Escalated);
        h.alert_store
            .set_acknowledgement(id, Some("recipient".into()), Some(now))
            .await
            .unwrap();
        h.eval_response_escalation(&d, now + chrono::Duration::seconds(4))
            .await;
        assert!(
            !h.alert_store
                .get(id)
                .await
                .unwrap()
                .unwrap()
                .details
                .response_escalated
        );
        let jobs = claim_notification_dispatch_jobs(&h.queue).await;
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].trigger, NotificationTrigger::Deescalated);
    }
    #[tokio::test]
    async fn capability_count_escalation_counts_unacknowledged_occurrences_after_recovery() {
        let (h, d, mut r) = capability_handler(high_cpu_rule(None)).await;
        let now = chrono::Utc::now();
        r.expression = "true".into();
        r.policy.acknowledge_required = true;
        r.policy.pending_count_threshold = Some(2);
        for _ in 0..2 {
            let mut a = match h.alerts.observe(
                d.id,
                &d.facts.ip,
                &r.name,
                Some(&uuid::Uuid::new_v4().to_string()),
                AlertLevel::Warning,
                "event".into(),
                None,
                true,
                false,
                None,
                chrono::Duration::zero(),
                now,
            ) {
                AlertTransition::Activated(a) => a,
                _ => panic!(),
            };
            a.state = AlertState::Cleared;
            a.details.policy = r.policy.clone();
            h.alert_store.upsert(&a).await.unwrap();
        }
        h.eval_response_escalation(&d, now).await;
        let page = h.alert_store.list(&Default::default()).await.unwrap();
        assert!(page.items.iter().all(|a| a.details.response_escalated));
        h.alert_store
            .set_acknowledgement(page.items[0].id, Some("operator".into()), Some(now))
            .await
            .unwrap();
        h.eval_response_escalation(&d, now).await;
        assert!(h
            .alert_store
            .list(&Default::default())
            .await
            .unwrap()
            .items
            .iter()
            .all(|a| !a.details.response_escalated));
    }
}
