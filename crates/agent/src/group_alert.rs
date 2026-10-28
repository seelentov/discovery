use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration as StdDuration, Instant};

use discovery_alerts::{AlertListQuery, AlertSortBy, AlertStore};
use discovery_auth::AuthStore;
use discovery_config_store::{
    GroupAlertRule, GroupAlertRuleStore, NotificationChannelStore, NotificationRuleStore,
    SettingsStore, TopologyRuleStore,
};
use discovery_core::{Alert, AlertState, NotificationTrigger, SortDir};
use discovery_dsl::group_alerts::GroupAlertEvaluator;
use discovery_queue::JobQueueStore;
use discovery_topology::{ResolvedEdge, TopologyStore};
use tracing::{info, warn};
use uuid::Uuid;

/// `AlertListQuery` has no `name` filter and correlation needs every active alert. This is
/// only the page size: callers continue until the store reports that all matching rows were
/// read, so the former fleet/upstream hard limits cannot silently change correlation.
const CORRELATION_PAGE_SIZE: i64 = 1000;
/// Give a concurrently evaluated upstream alert a short chance to become visible before
/// the downstream notification gate makes its one-way decision. This is intentionally
/// bounded: failed correlation still falls back to notifying.
const ACTIVATION_CORRELATION_RETRIES: usize = 5;
const ACTIVATION_CORRELATION_RETRY_DELAY: StdDuration = StdDuration::from_millis(20);

fn is_active_unsuppression(alert: &Alert, new_value: Option<Uuid>) -> bool {
    alert.state == AlertState::Active
        && alert.suppressed_by_alert_id.is_some()
        && new_value.is_none()
}

async fn fetch_active_alerts(alert_store: &Arc<dyn AlertStore>) -> anyhow::Result<Vec<Alert>> {
    fetch_active_alert_pages(alert_store, None).await
}

async fn fetch_active_alert_pages(
    alert_store: &Arc<dyn AlertStore>,
    device_id: Option<Uuid>,
) -> anyhow::Result<Vec<Alert>> {
    let mut alerts = Vec::new();
    let mut offset = 0;
    loop {
        let page = alert_store
            .list(&AlertListQuery {
                response_pending: false,
                screen_only: false,
                search: None,
                level: None,
                state: Some(AlertState::Active),
                device_id,
                since: None,
                until: None,
                sort_by: AlertSortBy::FirstSeen,
                sort_dir: SortDir::Asc,
                limit: CORRELATION_PAGE_SIZE,
                offset,
            })
            .await?;
        let item_count = page.items.len() as i64;
        alerts.extend(page.items);
        offset += item_count;
        if offset >= page.total {
            break;
        }
        if item_count == 0 {
            warn!(device_id = ?device_id, total = page.total, fetched = offset, "group-alert pagination: store returned an empty page before total was reached; correlation may be incomplete");
            break;
        }
        if item_count < CORRELATION_PAGE_SIZE {
            warn!(total = page.total, fetched = offset, "group-alert pagination: store returned a short page before total was reached; correlation may be incomplete");
            break;
        }
    }
    Ok(alerts)
}

/// Pure — unions every enabled topology rule's resolved edges into one fleet-wide
/// `downstream_device_id -> upstream neighbor ids` map (direct user decision: correlation
/// considers *any* enabled `TopologyRule`, not one designated rule). Deduplicates an
/// upstream neighbor claimed identically by more than one rule. Edges with
/// `upstream_device_id: None` (direction undetermined) contribute nothing — an undirected
/// edge can't tell a downstream device from an upstream one, so it's simply not a candidate
/// for this feature (unlike topology's own adjacency views, which show it regardless).
pub fn merge_upstream_map(rule_edges: Vec<Vec<ResolvedEdge>>) -> HashMap<Uuid, Vec<Uuid>> {
    let mut upstream_of: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    for edges in rule_edges {
        for edge in edges {
            let Some(upstream) = edge.upstream_device_id else {
                continue;
            };
            let downstream = if upstream == edge.device_a {
                edge.device_b
            } else {
                edge.device_a
            };
            let list = upstream_of.entry(downstream).or_default();
            if !list.contains(&upstream) {
                list.push(upstream);
            }
        }
    }
    upstream_of
}

/// For every alert in `alerts`, decides its new `suppressed_by_alert_id`: `None` if it
/// should be treated as an independent root cause, `Some(root_alert_id)` if a qualifying
/// upstream cause was found.
///
/// **Direction replaces the old symmetric time-window heuristic** (pre-2026-09-15: no
/// topology direction existed yet, so correlation could only lean on "roughly the same
/// time" as a proxy for causality). Now that `upstream_of` already encodes real physical
/// direction, the only timing requirement left is causal ordering — a cause cannot have
/// started *after* its effect: `cause.first_seen <= effect.first_seen`. No
/// `correlation_window` — an upstream outage that has been active for an hour is still the
/// real cause of a downstream device losing reachability just now, regardless of how long
/// ago it started.
///
/// **cause/effect rules, not a single "participates" flag** (direct user requirement,
/// motivated by a concrete scenario: an unrelated active alert on the upstream device, e.g.
/// High CPU, must not suppress an independent alert on the downstream device, e.g. Port
/// Down, just because they coincide in time and direction) — a pair only qualifies when
/// some enabled [`GroupAlertRule`]'s `cause_expression` matches the upstream candidate
/// *and* that same rule's `effect_expression` matches the downstream candidate.
///
/// **Direct-neighbors-only** — deliberately does not expand transitively: if A ends up
/// suppressed by B, and B would independently be suppressed by some other device C, that
/// doesn't chain. Multi-hop correlation is an explicitly deferred, harder problem (same
/// scope boundary the pre-rollback implementation drew — see `docs/Roadmap.md`).
///
/// **Deterministic tie-break**: candidates with the same `first_seen` are ordered by
/// `alert_id`, so a result doesn't depend on iteration order.
///
/// **Pure, no I/O, full recompute every call** — this is what makes un-suppression fall out
/// for free: an alert that *was* suppressed by a neighbor whose own alert has since cleared
/// simply doesn't find that neighbor's alert in `alerts` on the next call (a cleared alert
/// is no longer `Active`, so the caller never includes it), so this function naturally
/// returns `None` for it — no separate "was my root cause cleared" check needed anywhere.
///
/// `group_rules` is assumed already filtered to enabled rules — this function doesn't check
/// `.enabled` itself, same "caller decides what's active, this just computes" split
/// `resolve_edges`/`TopologyRecomputeHandler` already draw.
pub fn compute_suppression(
    alerts: &[Alert],
    upstream_of: &HashMap<Uuid, Vec<Uuid>>,
    group_rules: &[GroupAlertRule],
    evaluator: &GroupAlertEvaluator,
) -> HashMap<Uuid, Option<Uuid>> {
    let mut by_device: HashMap<Uuid, Vec<&Alert>> = HashMap::new();
    for a in alerts {
        by_device.entry(a.device_id).or_default().push(a);
    }
    let empty: Vec<Uuid> = Vec::new();

    alerts
        .iter()
        .map(|effect_alert| {
            let root = resolve_cause(
                effect_alert,
                upstream_of.get(&effect_alert.device_id).unwrap_or(&empty),
                &by_device,
                group_rules,
                evaluator,
            );
            (effect_alert.id, root)
        })
        .collect()
}

/// The single-alert half of [`compute_suppression`], factored out so the reactive activation
/// path (`GroupAlertCorrelator::react_to_activation`'s `react_from_snapshot`) can use the
/// *exact same* cause/effect logic instead of a parallel copy — the two paths must agree on
/// what counts as a suppression, or the notification gate would diverge from the badge.
///
/// Decides whether `effect_alert` should be suppressed by any of `upstream_device_ids`'
/// active alerts (passed in `alerts_by_device`), and which one. Same rules that
/// [`compute_suppression`]'s docs spell out: direct neighbors only, a cause cannot start
/// after its effect (`cause.first_seen <= effect.first_seen`), a pair qualifies only under
/// a rule whose `cause_expression` matches the candidate *and* whose `effect_expression`
/// matches the effect, and the earliest qualifying candidate (tie-broken by `alert_id`) wins.
///
/// At-activation the `<=` check is vacuously satisfied (the just-activated effect is the
/// newest alert in existence), but it stays here so this function is identical to the sweep
/// semantics rather than relying on the caller having guaranteed it externally.
fn resolve_cause(
    effect_alert: &Alert,
    upstream_device_ids: &[Uuid],
    alerts_by_device: &HashMap<Uuid, Vec<&Alert>>,
    group_rules: &[GroupAlertRule],
    evaluator: &GroupAlertEvaluator,
) -> Option<Uuid> {
    let order_key = |a: &Alert| (a.first_seen, a.id);
    let mut root: Option<&Alert> = None;
    for upstream_device_id in upstream_device_ids {
        for cause_alert in alerts_by_device
            .get(upstream_device_id)
            .into_iter()
            .flatten()
        {
            if order_key(cause_alert) > order_key(effect_alert) {
                continue; // a cause cannot start after its effect
            }
            let qualifies = group_rules.iter().any(|rule| {
                evaluator.evaluate_cause(&rule.cause_expression, cause_alert) == Some(true)
                    && evaluator.evaluate_effect(&rule.effect_expression, effect_alert)
                        == Some(true)
            });
            if !qualifies {
                continue;
            }
            if root.is_none_or(|r| order_key(cause_alert) < order_key(r)) {
                root = Some(cause_alert);
            }
        }
    }
    root.map(|r| r.id)
}

/// A point-in-time, read-only snapshot of everything correlation depends on except the
/// alert population itself: the merged directed topology map (`upstream_of`) and the
/// currently-enabled [`GroupAlertRule`]s. Produced by [`GroupAlertCorrelator`]'s
/// `refresh_snapshot` (the periodic sweep) or its `ensure_fresh_snapshot` (the reactive
/// activation path) and consumed by both [`compute_suppression`] and
/// `react_to_activation`'s `react_from_snapshot`.
#[derive(Default, Clone)]
pub struct CorrelationSnapshot {
    pub upstream_of: HashMap<Uuid, Vec<Uuid>>,
    /// Enabled rules only — the caller decides what's active, this just carries it.
    pub group_rules: Vec<GroupAlertRule>,
    /// When this snapshot was last `publish`ed (an immediate refresh never happens before
    /// the first publish, so `None` reads as "stale"), `Instant` rather than a UTC
    /// `DateTime` because staleness here is pure elapsed-time bookkeeping, not something a
    /// human ever reads back. `pub(crate)` so the crate's own handler tests can build a
    /// hand-rolled snapshot via functional-update syntax; external callers must use
    /// `CorrelationSnapshot::default()` as the base (publishing is the correlator's job).
    pub(crate) published_at: Option<Instant>,
}

/// The three stores a fresh snapshot is built from — the real `discovery-agent::main`
/// wiring. How the reactive path refreshes itself when the sweep has been idle: see
/// `GroupAlertCorrelator::ensure_fresh_snapshot`'s docs for why "idle sweep" is exactly the
/// case its on-demand rebuild exists for.
pub struct CorrelationRefreshSources {
    pub topology_rules: Arc<dyn TopologyRuleStore>,
    pub topology: Arc<dyn TopologyStore>,
    pub group_alert_rules: Arc<dyn GroupAlertRuleStore>,
}

/// Shared correlation state: the current [`CorrelationSnapshot`] plus the evaluator and,
/// in production, the refresh sources an on-demand rebuild can use. Two consumers, one
/// writer discipline:
///
/// * the **periodic sweep** (`run_group_alert_loop`) calls `refresh_snapshot` — an
///   unconditional rebuild from the stores — every tick that has anything to correlate, and
///   publishes the result (including an empty one, which clears stale config on this path);
/// * the **reactive activation path** (`react_to_activation`, driven by `AlertEvalHandler`
///   right before a notification decision) reads the current snapshot, refreshing it
///   on-demand only when it's grown stale — a quiet system that hasn't correlated anything
///   in a while still gets a correct, fresh-enough answer on the very first alert of a
///   storm, instead of relying on whatever the last active-alert-bearing tick published.
///
/// The evaluator is stateless (`GroupAlertEvaluator`'s docs) so one instance shared between
/// the two paths is exactly the "the two paths must compute the same answer" guarantee
/// `resolve_cause`'s docs call for.
pub struct GroupAlertCorrelator {
    state: RwLock<CorrelationSnapshot>,
    evaluator: GroupAlertEvaluator,
    refresh: Option<CorrelationRefreshSources>,
    /// A snapshot older than this is rebuilt on-demand by the reactive path (when refresh
    /// sources exist). [`STALE_SNAPSHOT_AFTER`] by default; tests shrink it to zero to
    /// force deterministic rebuilds without sleeping.
    stale_after: StdDuration,
}

/// A snapshot is "stale" once this old. Comfortably above the sweep's own 30s default
/// cadence (so a serving sweep republishing every tick *never* triggers an on-demand
/// rebuild — the reactive path rides the sweep's publications), yet short enough that a
/// system whose sweep has been idle for a minute or more rebuilds once rather than trusting
/// pre-storm topology.
const STALE_SNAPSHOT_AFTER: StdDuration = StdDuration::from_secs(60);

impl Default for GroupAlertCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

impl GroupAlertCorrelator {
    /// No refresh sources — used by unit tests that publish a hand-built snapshot directly
    /// and by the periodic sweep when none are configured (a deployment without any
    /// `TopologyRule` simply never correlates, same as `run_group_alert_loop`'s
    /// `upstream_of.is_empty()` short-circuit).
    pub fn new() -> Self {
        Self {
            state: RwLock::new(CorrelationSnapshot::default()),
            evaluator: GroupAlertEvaluator::new(),
            refresh: None,
            stale_after: STALE_SNAPSHOT_AFTER,
        }
    }

    /// Production wiring — `discovery-agent::main` passes the three real stores so the
    /// reactive path can rebuild a stale snapshot on its own (see [`Self::ensure_fresh_snapshot`]).
    pub fn with_refresh(sources: CorrelationRefreshSources) -> Self {
        Self {
            refresh: Some(sources),
            ..Self::new()
        }
    }

    /// Test-only shorthand for a deterministic staleness test without sleeping: a
    /// `stale_after` of `Duration::ZERO` makes every `ensure_fresh_snapshot` rebuild.
    #[cfg(test)]
    pub fn with_refresh_stale(
        sources: CorrelationRefreshSources,
        stale_after: StdDuration,
    ) -> Self {
        Self {
            refresh: Some(sources),
            stale_after,
            ..Self::new()
        }
    }

    pub fn evaluator(&self) -> &GroupAlertEvaluator {
        &self.evaluator
    }

    pub fn current(&self) -> CorrelationSnapshot {
        self.state
            .read()
            .expect("group-alert correlator lock poisoned")
            .clone()
    }

    /// Replaces the current snapshot (timestamping it as freshly published) — the only
    /// write path. `run_group_alert_loop` calls it via `refresh_snapshot`; nothing else
    /// writes, so the "single writer" discipline the sweep and the reactive path share
    /// stays intact (same reasoning `AlertStore::set_suppression` is the single writer of
    /// `suppressed_by_alert_id`).
    pub fn publish(&self, snapshot: CorrelationSnapshot) {
        let mut s = snapshot;
        s.published_at = Some(Instant::now());
        *self
            .state
            .write()
            .expect("group-alert correlator lock poisoned") = s;
    }

    /// Unconditional rebuild from the configured stores + publish. Errors surface to the
    /// caller (the sweep skips the tick; `ensure_fresh_snapshot` warns and keeps the old
    /// snapshot). No refresh sources configured → returns current without touching anything
    /// (pure-unit-test mode).
    pub async fn refresh_snapshot(&self) -> anyhow::Result<CorrelationSnapshot> {
        let Some(sources) = &self.refresh else {
            return Ok(self.current());
        };
        let snapshot = build_snapshot(
            &sources.topology_rules,
            &sources.topology,
            &sources.group_alert_rules,
        )
        .await?;
        self.publish(snapshot.clone());
        Ok(snapshot)
    }

    /// The reactive path's view: the current snapshot if it's fresh enough, else a rebuild
    /// from the stores (best-effort — a failed rebuild returns an empty snapshot, the safe
    /// direction: an alert we can't positively identify as a group effect must notify, never
    /// silently vanish). Never errors.
    async fn ensure_fresh_snapshot(&self) -> CorrelationSnapshot {
        let fresh_enough = {
            let cur = self
                .state
                .read()
                .expect("group-alert correlator lock poisoned");
            match &self.refresh {
                None => true,
                Some(_) => cur
                    .published_at
                    .is_some_and(|t| t.elapsed() < self.stale_after),
            }
        };
        if fresh_enough {
            return self.current();
        }
        match self.refresh_snapshot().await {
            Ok(snapshot) => snapshot,
            Err(e) => {
                warn!(error = %e, "group correlation: on-demand snapshot refresh failed — disabling suppression for this activation");
                // A stale non-empty snapshot can hide an alert using topology or rules that
                // have since been removed. An empty snapshot is the safe fallback: without a
                // successful refresh we cannot positively identify a group effect, so notify.
                CorrelationSnapshot::default()
            }
        }
    }

    /// The reactive fast-path (2026-09-20): decides — *before* `AlertEvalHandler` makes its
    /// notification decision — whether a freshly-activated `effect` is suppressed by a
    /// qualifying active alert on a direct topology upstream neighbor, and persists that
    /// (`set_suppression`, the single writer — a concurrent `upsert` from a `StillActive`
    /// persist can never clobber it, see `AlertStore::set_suppression`'s docs).
    ///
    /// Returns the suppressing root alert's id (`Some`) or `None`. Overloads the meaning of
    /// `Ok(None)` intentionally: it is the caller's signal that this activation is an
    /// independent root cause (or nothing qualifies) and its notification must fire. All
    /// `Err` paths leave the alert unsuppressed and let the caller notify — failing to
    /// suppress a notification is recoverable noise, failing to *send* one is a missed
    /// incident.
    pub async fn react_to_activation(
        &self,
        alert_store: &Arc<dyn AlertStore>,
        effect: &Alert,
    ) -> anyhow::Result<Option<Uuid>> {
        let snapshot = self.ensure_fresh_snapshot().await;
        self.react_from_snapshot(alert_store, effect, &snapshot)
            .await
    }

    /// The pure-ish core of `react_to_activation`, given an already-resolved snapshot —
    /// `pub` (rather than private) so it's directly testable and so a caller that already
    /// holds a snapshot doesn't pay another freshness check.
    pub async fn react_from_snapshot(
        &self,
        alert_store: &Arc<dyn AlertStore>,
        effect: &Alert,
        snapshot: &CorrelationSnapshot,
    ) -> anyhow::Result<Option<Uuid>> {
        let Some(upstream_device_ids) = snapshot.upstream_of.get(&effect.device_id) else {
            return Ok(None); // no directed upstream — this device is a potential root cause itself
        };
        if upstream_device_ids.is_empty() || snapshot.group_rules.is_empty() {
            return Ok(None);
        }

        // Fresh per-device reads, not a cached copy: the whole point is that the upstream
        // *root cause just activated moments ago*, so a snapshot of "who was active" that is
        // up to `poll_intervals.group_alert_sweep_secs` old would systematically miss the
        // very alert this feature exists to correlate against. Direct upstreams are usually
        // 1-2 devices, so a tiny bounded loop here is cheap on the hot path (and the
        // batch-not-loop discipline only demands a batch when the loop grows with a fleet,
        // which this one never does).
        let mut root_id = None;
        for attempt in 0..=ACTIVATION_CORRELATION_RETRIES {
            let mut upstream_alerts: HashMap<Uuid, Vec<Alert>> = HashMap::new();
            for upstream_device_id in upstream_device_ids {
                let alerts =
                    fetch_active_alert_pages(alert_store, Some(*upstream_device_id)).await?;
                upstream_alerts.insert(*upstream_device_id, alerts);
            }
            // Owned vecs above (the pages die at the `for` iteration boundary), refs here for
            // `resolve_cause` — the owned `upstream_alerts` outlives this use, so the borrow is
            // sound, same shape `compute_suppression`'s `by_device` builds internally.
            let upstream_alerts_by_device: HashMap<Uuid, Vec<&Alert>> = upstream_alerts
                .iter()
                .map(|(k, v)| (*k, v.iter().collect()))
                .collect();

            root_id = resolve_cause(
                effect,
                upstream_device_ids,
                &upstream_alerts_by_device,
                &snapshot.group_rules,
                &self.evaluator,
            );
            if root_id.is_some() || attempt == ACTIVATION_CORRELATION_RETRIES {
                break;
            }
            // AlertEval workers can finish the upstream transition just after this read.
            tokio::time::sleep(ACTIVATION_CORRELATION_RETRY_DELAY).await;
        }
        if let Some(root_id) = root_id {
            alert_store
                .set_suppression(effect.id, Some(root_id))
                .await?;
            info!(ip = %effect.device_ip, alert = %effect.name, effect_alert_id = %effect.id, %root_id, "reactive group correlation: activation suppressed by an upstream cause — notification dispatch held");
        }
        Ok(root_id)
    }
}

/// One sweep-tick's (or on-demand refresh's) input assembly — the shared body behind both
/// [`GroupAlertCorrelator::refresh_snapshot`] and the pre-2026-09-20 inline loop logic:
/// enabled topology rules' resolved edges merged into `upstream_of`, enabled group rules
/// collected. No alert-store access; warn-and-skip posture for a single broken rule,
/// same as `TopologyRecomputeHandler`.
async fn build_snapshot(
    topology_rules: &Arc<dyn TopologyRuleStore>,
    topology: &Arc<dyn TopologyStore>,
    group_alert_rules: &Arc<dyn GroupAlertRuleStore>,
) -> anyhow::Result<CorrelationSnapshot> {
    let rules = topology_rules.list_all().await?;
    let mut rule_edges = Vec::new();
    for rule in rules.into_iter().filter(|r| r.enabled) {
        match topology.resolved_edges(&rule.name).await {
            Ok(edges) => rule_edges.push(edges),
            // One broken rule's edges must not block correlation under every other enabled
            // rule — same "warn and skip" posture `TopologyRecomputeHandler` already takes
            // for a single misbehaving rule.
            Err(e) => {
                warn!(error = %e, rule = %rule.name, "group correlation: failed to load resolved edges for a topology rule, skipping it")
            }
        }
    }
    let group_rules: Vec<GroupAlertRule> = group_alert_rules
        .list_all()
        .await?
        .into_iter()
        .filter(|r| r.enabled)
        .collect();
    Ok(CorrelationSnapshot {
        upstream_of: merge_upstream_map(rule_edges),
        group_rules,
        published_at: None,
    })
}

/// Item 3 of "Топология → групповые тревоги → RADIUS" (`docs/Roadmap.md`), 2026-09-16:
/// periodically correlates currently-active alerts against the topology graph
/// (`discovery_topology::TopologyStore`, items 1-2) plus provider-authored
/// [`GroupAlertRule`]s so a downstream device's alert gets `suppressed_by_alert_id` set
/// when a direct topology upstream neighbor has a qualifying active alert — see
/// [`compute_suppression`]'s docs for the actual rule.
///
/// Singleton, process-wide loop: correlation is inherently
/// cross-device (comparing device A's alert against device B's), so there's no per-device
/// key an `ActiveChains` duplicate-chain guard could be keyed on. Cadence is
/// `poll_intervals.group_alert_sweep_secs` (default 30s) — read fresh from `settings` every
/// iteration, same pattern `alert_history_cleanup`/`dead_device_cleanup` already use.
///
/// **Only one of two correlators by 2026-09-20** — `AlertEvalHandler`'s reactive path
/// (`GroupAlertCorrelator::react_to_activation`) is now the fast lane that decides
/// suppression at the moment an effect activates, *before* its notification is dispatched;
/// this sweep remains the authoritative full recompute and the reconcile net. Both go
/// through the same `GroupAlertCorrelator` snapshot and the same `resolve_cause`, so they
/// can't disagree about a classification.
pub async fn run_group_alert_loop(
    alert_store: Arc<dyn AlertStore>,
    correlator: Arc<GroupAlertCorrelator>,
    settings: Arc<dyn SettingsStore>,
    notification_rules: Arc<dyn NotificationRuleStore>,
    notification_channels: Arc<dyn NotificationChannelStore>,
    auth: Arc<dyn AuthStore>,
    queue: Arc<dyn JobQueueStore>,
) {
    loop {
        let intervals = settings.poll_intervals().await;
        tokio::time::sleep(StdDuration::from_secs(
            intervals.group_alert_sweep_secs.max(1),
        ))
        .await;

        let active = match fetch_active_alerts(&alert_store).await {
            Ok(a) => a,
            Err(e) => {
                warn!(error = %e, "group-alert sweep: failed to list active alerts, skipping this tick");
                continue;
            }
        };
        // Refresh even while idle. Configuration changes must invalidate the snapshot before
        // the first alert after a quiet period; otherwise that activation can use old topology
        // or group-alert rules.
        let snapshot = match correlator.refresh_snapshot().await {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "group-alert sweep: failed to refresh correlation snapshot, skipping this tick");
                continue;
            }
        };
        if active.is_empty() {
            continue; // the snapshot was still refreshed during the idle tick
        }

        // The authoritative rebuild publishes even an empty result, so a disabled rule /
        // vanished topology clears the snapshot rather than poisoning the reactive path.
        if snapshot.upstream_of.is_empty() {
            continue; // no directed topology anywhere -- nothing can be correlated this tick
        }
        if snapshot.group_rules.is_empty() {
            continue; // no configured rules -- nothing to correlate
        }

        let assignments = compute_suppression(
            &active,
            &snapshot.upstream_of,
            &snapshot.group_rules,
            correlator.evaluator(),
        );

        // Concurrent, not sequential — the scenario this sweep exists for (an uplink dies,
        // N downstream devices all need `suppressed_by_alert_id` set in the same tick) is
        // exactly when a `for ... .await` loop here would serialize what could be hundreds
        // of round trips into one long tail. `AlertStore` has no batch-update, so per-alert
        // calls are unavoidable — firing them concurrently via `JoinSet` at least avoids
        // paying for them one at a time. The number of tasks is bounded by the active rows
        // returned for this tick, while pagination ensures the correlation input is complete.
        //
        // `AlertStore::set_suppression` — a targeted single-column write, not a full
        // `upsert(&alert)` of a mutated copy. See that method's docs: `upsert` no longer
        // touches this column at all, specifically so a concurrent `StillActive` persist
        // from `AlertEvalHandler` (which calls `upsert` with its own stale in-memory
        // `AlertStateTracker` copy) can never clobber what this sweep writes here.
        let mut to_update: Vec<(Uuid, Option<Uuid>)> = Vec::new();
        for alert in &active {
            let new_value = assignments.get(&alert.id).copied().flatten();
            if alert.suppressed_by_alert_id != new_value {
                to_update.push((alert.id, new_value));
            }
        }

        let mut updated = 0usize;
        if !to_update.is_empty() {
            let mut set = tokio::task::JoinSet::new();
            for (alert_id, new_value) in to_update {
                let alert_store = alert_store.clone();
                let notification_rules = notification_rules.clone();
                let notification_channels = notification_channels.clone();
                let auth = auth.clone();
                let queue = queue.clone();
                let alert = active.iter().find(|alert| alert.id == alert_id).cloned();
                set.spawn(async move {
                    let should_notify = alert
                        .as_ref()
                        .map(|alert| is_active_unsuppression(alert, new_value))
                        .unwrap_or(false);
                    let result = alert_store.set_suppression(alert_id, new_value).await;
                    if result.is_ok() && should_notify {
                        if let Some(alert) = alert {
                            crate::handlers::dispatch_alert_notifications(
                                &notification_rules,
                                &notification_channels,
                                &auth,
                                &queue,
                                &alert,
                                None,
                                NotificationTrigger::Activated,
                                chrono::Utc::now(),
                            )
                            .await;
                        }
                    }
                    (alert_id, result)
                });
            }
            while let Some(res) = set.join_next().await {
                match res {
                    Ok((_alert_id, Ok(()))) => updated += 1,
                    Ok((alert_id, Err(e))) => {
                        warn!(error = %e, %alert_id, "group-alert sweep: failed to persist a suppression change")
                    }
                    Err(e) => warn!(error = %e, "group-alert sweep: a persist task panicked"),
                }
            }
        }
        if updated > 0 {
            info!(updated, "group-alert sweep: tick complete");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use discovery_core::AlertLevel;

    fn alert(device_id: Uuid, name: &str, seconds_ago: i64) -> Alert {
        let now = chrono::Utc::now();
        Alert {
            details: Default::default(),
            id: Uuid::new_v4(),
            device_id,
            device_ip: "10.0.0.1".to_string(),
            name: name.to_string(),
            row_key: None,
            level: AlertLevel::Critical,
            message: "test".to_string(),
            state: AlertState::Active,
            facts: None,
            first_seen: now - chrono::Duration::seconds(seconds_ago),
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
        }
    }

    fn rule(cause: &str, effect: &str) -> GroupAlertRule {
        GroupAlertRule {
            id: Uuid::new_v4(),
            name: "test-rule".to_string(),
            enabled: true,
            cause_expression: cause.to_string(),
            effect_expression: effect.to_string(),
        }
    }

    fn edge(a: Uuid, b: Uuid, upstream: Uuid) -> ResolvedEdge {
        ResolvedEdge {
            device_a: a,
            device_b: b,
            confirmed: true,
            upstream_device_id: Some(upstream),
            direction_overridden: false,
        }
    }

    fn same_name_rule() -> Vec<GroupAlertRule> {
        vec![rule(
            r#"name == "device_unreachable""#,
            r#"name == "device_unreachable""#,
        )]
    }

    #[tokio::test]
    async fn correlation_paginates_past_the_former_upstream_limit() {
        let db = discovery_migration::connect_in_memory_for_tests().await;
        let store: Arc<dyn AlertStore> = Arc::new(discovery_alerts::SeaOrmAlertStore::new(db));
        let device_id = Uuid::new_v4();

        for _ in 0..=CORRELATION_PAGE_SIZE {
            store
                .upsert(&alert(device_id, "device_unreachable", 120))
                .await
                .unwrap();
        }

        let fetched = fetch_active_alert_pages(&store, Some(device_id))
            .await
            .unwrap();
        assert_eq!(fetched.len(), (CORRELATION_PAGE_SIZE + 1) as usize);
    }

    #[test]
    fn merge_upstream_map_unions_edges_from_multiple_rules() {
        let (a, b, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let merged = merge_upstream_map(vec![vec![edge(a, b, a)], vec![edge(b, c, b)]]);
        assert_eq!(merged.get(&b), Some(&vec![a]));
        assert_eq!(merged.get(&c), Some(&vec![b]));
    }

    #[test]
    fn merge_upstream_map_dedupes_the_same_upstream_claimed_by_two_rules() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let merged = merge_upstream_map(vec![vec![edge(a, b, a)], vec![edge(a, b, a)]]);
        assert_eq!(merged.get(&b), Some(&vec![a]));
    }

    #[test]
    fn merge_upstream_map_skips_edges_with_undetermined_direction() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let undirected = ResolvedEdge {
            device_a: a,
            device_b: b,
            confirmed: true,
            upstream_device_id: None,
            direction_overridden: false,
        };
        assert!(merge_upstream_map(vec![vec![undirected]]).is_empty());
    }

    #[test]
    fn independent_alert_with_no_upstream_neighbor_is_never_suppressed() {
        let evaluator = GroupAlertEvaluator::new();
        let alerts = vec![alert(Uuid::new_v4(), "device_unreachable", 10)];
        let result = compute_suppression(&alerts, &HashMap::new(), &same_name_rule(), &evaluator);
        assert_eq!(result[&alerts[0].id], None);
    }

    #[test]
    fn later_neighbor_alert_is_suppressed_by_the_earlier_matching_cause() {
        let evaluator = GroupAlertEvaluator::new();
        let (device_a, device_b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut upstream_of = HashMap::new();
        upstream_of.insert(device_b, vec![device_a]);

        // A (upstream) went unreachable 90s ago; B (downstream), 30s ago.
        let alert_a = alert(device_a, "device_unreachable", 90);
        let alert_b = alert(device_b, "device_unreachable", 30);
        let alerts = vec![alert_a.clone(), alert_b.clone()];
        let result = compute_suppression(&alerts, &upstream_of, &same_name_rule(), &evaluator);

        assert_eq!(
            result[&alert_a.id], None,
            "the upstream root cause must remain unsuppressed"
        );
        assert_eq!(result[&alert_b.id], Some(alert_a.id));
    }

    #[test]
    fn an_upstream_alert_starting_after_the_downstream_alert_is_not_a_cause() {
        let evaluator = GroupAlertEvaluator::new();
        let (device_a, device_b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut upstream_of = HashMap::new();
        upstream_of.insert(device_b, vec![device_a]);

        // B (downstream) went unreachable first; A (upstream) only started after — B's
        // alert cannot have been *caused* by something that hadn't happened yet.
        let alert_a = alert(device_a, "device_unreachable", 10);
        let alert_b = alert(device_b, "device_unreachable", 90);
        let alerts = vec![alert_a.clone(), alert_b.clone()];
        let result = compute_suppression(&alerts, &upstream_of, &same_name_rule(), &evaluator);

        assert_eq!(
            result[&alert_b.id], None,
            "a cause cannot start after its effect"
        );
    }

    #[test]
    fn an_unrelated_upstream_cause_does_not_suppress_an_independent_downstream_effect() {
        // The exact scenario that motivated separate cause/effect rules over a single
        // "participates in group suppression" flag: High CPU on the upstream device must
        // not suppress an independent Port Down on the downstream device.
        let evaluator = GroupAlertEvaluator::new();
        let (device_a, device_b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut upstream_of = HashMap::new();
        upstream_of.insert(device_b, vec![device_a]);

        let rules = vec![rule(
            r#"name == "device_unreachable""#,
            r#"name == "device_unreachable""#,
        )];
        let high_cpu = alert(device_a, "high_cpu", 90);
        let port_down = alert(device_b, "port_down", 30);
        let alerts = vec![high_cpu.clone(), port_down.clone()];
        let result = compute_suppression(&alerts, &upstream_of, &rules, &evaluator);

        assert_eq!(result[&port_down.id], None, "cause/effect expressions don't match — must not be correlated just because they coincide in time and direction");
    }

    #[test]
    fn non_neighbors_are_never_correlated_regardless_of_timing() {
        let evaluator = GroupAlertEvaluator::new();
        let (device_a, device_b) = (Uuid::new_v4(), Uuid::new_v4());
        let alert_a = alert(device_a, "device_unreachable", 60);
        let alert_b = alert(device_b, "device_unreachable", 30);
        let alerts = vec![alert_a.clone(), alert_b.clone()];
        let result = compute_suppression(&alerts, &HashMap::new(), &same_name_rule(), &evaluator);

        assert_eq!(result[&alert_a.id], None);
        assert_eq!(
            result[&alert_b.id], None,
            "topologically unrelated devices must never suppress each other"
        );
    }

    #[test]
    fn direct_neighbors_only_no_transitive_chain() {
        // A - B - C, a simple path. A and C are not direct neighbors.
        let (device_a, device_b, device_c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let mut upstream_of = HashMap::new();
        upstream_of.insert(device_b, vec![device_a]);
        upstream_of.insert(device_c, vec![device_b]);

        let alert_a = alert(device_a, "device_unreachable", 90);
        let alert_b = alert(device_b, "device_unreachable", 60);
        let alert_c = alert(device_c, "device_unreachable", 30);
        let alerts = vec![alert_a.clone(), alert_b.clone(), alert_c.clone()];
        let evaluator = GroupAlertEvaluator::new();
        let result = compute_suppression(&alerts, &upstream_of, &same_name_rule(), &evaluator);

        assert_eq!(result[&alert_a.id], None);
        assert_eq!(result[&alert_b.id], Some(alert_a.id));
        assert_eq!(result[&alert_c.id], Some(alert_b.id), "C must correlate against its own direct upstream neighbor B, not transitively against A");
    }

    #[test]
    fn a_neighbor_without_its_own_active_alert_does_not_affect_correlation() {
        let (device_a, device_b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut upstream_of = HashMap::new();
        upstream_of.insert(device_b, vec![device_a]); // A is upstream but has no active alert

        let alert_b = alert(device_b, "device_unreachable", 10);
        let alerts = vec![alert_b.clone()];
        let evaluator = GroupAlertEvaluator::new();
        let result = compute_suppression(&alerts, &upstream_of, &same_name_rule(), &evaluator);
        assert_eq!(result[&alert_b.id], None);
    }

    #[test]
    fn root_cause_clearing_un_suppresses_on_the_next_tick() {
        // Simulates two successive sweep ticks: tick 1, A (root) and B (dependent) are both
        // active -- B gets suppressed by A. Tick 2, A's alert has cleared and is therefore
        // no longer part of the `alerts` slice the caller passes in.
        let (device_a, device_b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut upstream_of = HashMap::new();
        upstream_of.insert(device_b, vec![device_a]);
        let evaluator = GroupAlertEvaluator::new();

        let alert_a = alert(device_a, "device_unreachable", 90);
        let alert_b = alert(device_b, "device_unreachable", 30);
        let tick1 = vec![alert_a.clone(), alert_b.clone()];
        let result1 = compute_suppression(&tick1, &upstream_of, &same_name_rule(), &evaluator);
        assert_eq!(result1[&alert_b.id], Some(alert_a.id));

        // Tick 2: A is gone from the active set (its device recovered).
        let tick2 = vec![alert_b.clone()];
        let result2 = compute_suppression(&tick2, &upstream_of, &same_name_rule(), &evaluator);
        assert_eq!(
            result2[&alert_b.id], None,
            "must un-suppress once the claimed root cause is no longer active"
        );
    }

    #[test]
    fn active_unsuppression_is_only_emitted_for_some_to_none() {
        let mut downstream = alert(Uuid::new_v4(), "device_unreachable", 30);
        let root = Uuid::new_v4();
        downstream.suppressed_by_alert_id = Some(root);

        assert!(is_active_unsuppression(&downstream, None));
        assert!(!is_active_unsuppression(&downstream, Some(root)));

        downstream.suppressed_by_alert_id = None;
        assert!(!is_active_unsuppression(&downstream, None));

        downstream.state = AlertState::Cleared;
        downstream.suppressed_by_alert_id = Some(root);
        assert!(!is_active_unsuppression(&downstream, None));
    }

    #[test]
    fn multiple_candidate_causes_the_earliest_wins() {
        let (device_a1, device_a2, device_b) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let mut upstream_of = HashMap::new();
        upstream_of.insert(device_b, vec![device_a1, device_a2]);
        let evaluator = GroupAlertEvaluator::new();

        let earlier = alert(device_a1, "device_unreachable", 120);
        let later = alert(device_a2, "device_unreachable", 60);
        let effect = alert(device_b, "device_unreachable", 30);
        let alerts = vec![earlier.clone(), later.clone(), effect.clone()];
        let result = compute_suppression(&alerts, &upstream_of, &same_name_rule(), &evaluator);
        assert_eq!(
            result[&effect.id],
            Some(earlier.id),
            "the earliest qualifying candidate must win"
        );
    }

    #[test]
    fn exact_tie_in_first_seen_between_two_candidates_is_broken_deterministically_by_alert_id() {
        // Two candidate causes on two different upstream neighbors, both with the exact
        // same `first_seen` -- the smaller `alert_id` must win regardless of which order
        // they appear in the input slice.
        let (device_a1, device_a2, device_b) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let mut upstream_of = HashMap::new();
        upstream_of.insert(device_b, vec![device_a1, device_a2]);
        let evaluator = GroupAlertEvaluator::new();

        let cand1 = alert(device_a1, "device_unreachable", 60);
        let mut cand2 = alert(device_a2, "device_unreachable", 60);
        cand2.first_seen = cand1.first_seen; // exact tie
        let expected_winner = std::cmp::min(cand1.id, cand2.id);

        let effect = alert(device_b, "device_unreachable", 30);
        let alerts = vec![cand1.clone(), cand2.clone(), effect.clone()];
        let result = compute_suppression(&alerts, &upstream_of, &same_name_rule(), &evaluator);
        assert_eq!(result[&effect.id], Some(expected_winner));
    }

    // ---- Reactive fast-path (2026-09-20): `GroupAlertCorrelator` ----

    /// The stores a real `react_to_activation` call needs: an alert store (the source the
    /// reactive path reads upstream candidates from and writes suppression into) and the
    /// three refresh-source stores. Topology is pre-wired so "lldp" resolves a confirmed
    /// edge with `upstream` rank 0.0 (`key-a`) upstream of `downstream` rank 1.0 (`key-b`,
    /// claims `key-a`) — the same direction the topology crate's own
    /// `lower_rank_wins_as_upstream` proves.
    async fn reactive_stores() -> (
        Arc<dyn AlertStore>,
        Arc<dyn TopologyRuleStore>,
        Arc<dyn TopologyStore>,
        Arc<dyn GroupAlertRuleStore>,
        Uuid,
        Uuid,
    ) {
        let alert_db = discovery_migration::connect_in_memory_for_tests().await;
        let alert_store: Arc<dyn AlertStore> =
            Arc::new(discovery_alerts::SeaOrmAlertStore::new(alert_db));

        let topology_db = discovery_migration::connect_in_memory_for_tests().await;
        let topology_rules: Arc<dyn TopologyRuleStore> = Arc::new(
            discovery_config_store::SeaOrmTopologyRuleStore::new(topology_db.clone()),
        );
        let topology: Arc<dyn TopologyStore> =
            Arc::new(discovery_topology::SeaOrmTopologyStore::new(topology_db));
        topology_rules
            .upsert(&discovery_config_store::TopologyRule {
                id: Uuid::new_v4(),
                name: "lldp".to_string(),
                enabled: true,
                my_key_expression: "metrics.lldp_chassis_id".to_string(),
                claimed_neighbors_expression: Some("metrics.lldp_rem_table".to_string()),
                rank_expression: Some("metrics.role_value".to_string()),
                watched_metrics: None,
            })
            .await
            .unwrap();

        let group_alert_rules: Arc<dyn GroupAlertRuleStore> = Arc::new(
            discovery_config_store::SeaOrmGroupAlertRuleStore::new_in_memory_for_tests().await,
        );
        group_alert_rules
            .upsert(&rule(r#"name == "snafu""#, r#"name == "snafu""#))
            .await
            .unwrap();

        let upstream = Uuid::new_v4();
        let downstream = Uuid::new_v4();
        topology
            .apply_recompute(
                "lldp",
                upstream,
                Some("key-a".to_string()),
                vec![],
                Some(0.0),
            )
            .await
            .unwrap();
        topology
            .apply_recompute(
                "lldp",
                downstream,
                Some("key-b".to_string()),
                vec!["key-a".to_string()],
                Some(1.0),
            )
            .await
            .unwrap();

        (
            alert_store,
            topology_rules,
            topology,
            group_alert_rules,
            upstream,
            downstream,
        )
    }

    fn refresh_sources(
        topology_rules: Arc<dyn TopologyRuleStore>,
        topology: Arc<dyn TopologyStore>,
        group_alert_rules: Arc<dyn GroupAlertRuleStore>,
    ) -> CorrelationRefreshSources {
        CorrelationRefreshSources {
            topology_rules,
            topology,
            group_alert_rules,
        }
    }

    #[tokio::test]
    async fn react_to_activation_suppresses_a_downstream_activation_and_persists_it() {
        let (alert_store, topology_rules, topology, group_alert_rules, upstream, downstream) =
            reactive_stores().await;
        let correlator = Arc::new(GroupAlertCorrelator::with_refresh(refresh_sources(
            topology_rules,
            topology,
            group_alert_rules,
        )));

        let cause = alert(upstream, "snafu", 120);
        alert_store.upsert(&cause).await.unwrap();
        let effect = alert(downstream, "snafu", 0);
        alert_store.upsert(&effect).await.unwrap();

        let root = correlator
            .react_to_activation(&alert_store, &effect)
            .await
            .unwrap();
        assert_eq!(root, Some(cause.id));

        let persisted = alert_store.get(effect.id).await.unwrap().unwrap();
        assert_eq!(
            persisted.suppressed_by_alert_id,
            Some(cause.id),
            "the reactive path must persist the suppression, not just decide in memory"
        );
    }

    #[tokio::test]
    async fn concurrent_activation_retries_until_late_upstream_persist_is_visible() {
        let (alert_store, topology_rules, topology, group_alert_rules, upstream, downstream) =
            reactive_stores().await;
        let correlator = Arc::new(GroupAlertCorrelator::with_refresh(refresh_sources(
            topology_rules,
            topology,
            group_alert_rules,
        )));

        let cause = alert(upstream, "snafu", 120);
        let effect = alert(downstream, "snafu", 0);
        // The downstream transition completes first; the upstream AlertEval persists its
        // transition shortly afterwards, reproducing the production worker race.
        alert_store.upsert(&effect).await.unwrap();
        let delayed_store = Arc::clone(&alert_store);
        let delayed_cause = cause.clone();
        let upstream_persist = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            delayed_store.upsert(&delayed_cause).await.unwrap();
        });

        let root = correlator
            .react_to_activation(&alert_store, &effect)
            .await
            .unwrap();
        upstream_persist.await.unwrap();

        assert_eq!(root, Some(cause.id));
        assert_eq!(
            alert_store
                .get(effect.id)
                .await
                .unwrap()
                .unwrap()
                .suppressed_by_alert_id,
            Some(cause.id)
        );
    }

    #[tokio::test]
    async fn react_to_activation_leaves_a_device_without_an_upstream_alone() {
        let (alert_store, topology_rules, topology, group_alert_rules, _, _) =
            reactive_stores().await;
        let correlator = Arc::new(GroupAlertCorrelator::with_refresh(refresh_sources(
            topology_rules,
            topology,
            group_alert_rules,
        )));

        let stranger = alert(Uuid::new_v4(), "snafu", 0); // not in the topology graph at all
        alert_store.upsert(&stranger).await.unwrap();

        let root = correlator
            .react_to_activation(&alert_store, &stranger)
            .await
            .unwrap();
        assert_eq!(
            root, None,
            "a device with no directed upstream is a potential root cause itself"
        );

        let persisted = alert_store.get(stranger.id).await.unwrap().unwrap();
        assert_eq!(persisted.suppressed_by_alert_id, None);
    }

    #[tokio::test]
    async fn react_to_activation_does_not_suppress_when_the_upstream_alert_does_not_qualify() {
        let (alert_store, topology_rules, topology, group_alert_rules, upstream, downstream) =
            reactive_stores().await;
        let correlator = Arc::new(GroupAlertCorrelator::with_refresh(refresh_sources(
            topology_rules,
            topology,
            group_alert_rules,
        )));

        // Upstream's alert is a *different* name — the rule gates on `name == "snafu"`, so
        // this must not qualify (same scenario as `an_unrelated_upstream_cause...` above).
        let unrelated = alert(upstream, "high_cpu", 120);
        alert_store.upsert(&unrelated).await.unwrap();
        let effect = alert(downstream, "snafu", 0);
        alert_store.upsert(&effect).await.unwrap();

        let root = correlator
            .react_to_activation(&alert_store, &effect)
            .await
            .unwrap();
        assert_eq!(
            root, None,
            "a non-qualifying upstream alert must not suppress"
        );

        let persisted = alert_store.get(effect.id).await.unwrap().unwrap();
        assert_eq!(persisted.suppressed_by_alert_id, None);
    }

    #[tokio::test]
    async fn a_stale_snapshot_triggers_an_on_demand_rebuild_and_suppresses() {
        let (alert_store, topology_rules, topology, group_alert_rules, upstream, downstream) =
            reactive_stores().await;
        // `stale_after = ZERO` — every `ensure_fresh_snapshot` is deterministically stale,
        // no sleeping, so this exercises the silent-system → sudden-storm rebuild path.
        let correlator = Arc::new(GroupAlertCorrelator::with_refresh_stale(
            refresh_sources(topology_rules, topology, group_alert_rules),
            StdDuration::ZERO,
        ));
        correlator.publish(CorrelationSnapshot::default()); // a "published, long idle" snapshot

        let cause = alert(upstream, "snafu", 120);
        alert_store.upsert(&cause).await.unwrap();
        let effect = alert(downstream, "snafu", 0);
        alert_store.upsert(&effect).await.unwrap();

        let root = correlator
            .react_to_activation(&alert_store, &effect)
            .await
            .unwrap();
        assert_eq!(
            root,
            Some(cause.id),
            "a stale snapshot must be rebuilt on demand from the refresh sources"
        );
    }

    #[tokio::test]
    async fn an_idle_refresh_picks_up_group_alert_config_changes_before_activation() {
        let (alert_store, topology_rules, topology, group_alert_rules, upstream, downstream) =
            reactive_stores().await;
        let correlator = Arc::new(GroupAlertCorrelator::with_refresh(refresh_sources(
            topology_rules.clone(),
            topology.clone(),
            group_alert_rules.clone(),
        )));

        // The first idle tick publishes the original configuration.
        correlator.refresh_snapshot().await.unwrap();

        // Configuration changes while there are no active alerts. The next idle tick must
        // still refresh, otherwise the first activation would use the removed rules.
        let topology_rule = topology_rules.list_all().await.unwrap().pop().unwrap();
        let group_rule = group_alert_rules.list_all().await.unwrap().pop().unwrap();
        topology_rules.delete(topology_rule.id).await.unwrap();
        group_alert_rules.delete(group_rule.id).await.unwrap();
        correlator.refresh_snapshot().await.unwrap();
        assert!(correlator.current().upstream_of.is_empty());
        assert!(correlator.current().group_rules.is_empty());

        // The configuration is enabled again during the same quiet period. A refresh before
        // activation must publish it even though the active-alert list is still empty.
        topology_rules.upsert(&topology_rule).await.unwrap();
        group_alert_rules.upsert(&group_rule).await.unwrap();
        topology
            .apply_recompute(
                "lldp",
                upstream,
                Some("key-a".to_string()),
                vec![],
                Some(0.0),
            )
            .await
            .unwrap();
        topology
            .apply_recompute(
                "lldp",
                downstream,
                Some("key-b".to_string()),
                vec!["key-a".to_string()],
                Some(1.0),
            )
            .await
            .unwrap();
        correlator.refresh_snapshot().await.unwrap();
        assert_eq!(
            correlator.current().upstream_of.get(&downstream),
            Some(&vec![upstream])
        );
        assert_eq!(correlator.current().group_rules.len(), 1);

        let cause = alert(upstream, "snafu", 120);
        alert_store.upsert(&cause).await.unwrap();
        let effect = alert(downstream, "snafu", 0);
        alert_store.upsert(&effect).await.unwrap();

        assert_eq!(
            correlator
                .react_to_activation(&alert_store, &effect)
                .await
                .unwrap(),
            Some(cause.id),
            "the first activation after idle must use the refreshed configuration"
        );
    }

    #[tokio::test]
    async fn a_fresh_snapshot_is_used_without_an_on_demand_rebuild() {
        // Proof that the reactive path *trusts* a fresh snapshot rather than always
        // rebuilding: the refresh happens while the world is empty (no topology, no rule);
        // then the world changes in the stores; the never-again-refreshed snapshot (fresh,
        // empty) must win — the activation must NOT be suppressed.
        let alert_db = discovery_migration::connect_in_memory_for_tests().await;
        let alert_store: Arc<dyn AlertStore> =
            Arc::new(discovery_alerts::SeaOrmAlertStore::new(alert_db));
        let topology_db = discovery_migration::connect_in_memory_for_tests().await;
        let topology_rules: Arc<dyn TopologyRuleStore> = Arc::new(
            discovery_config_store::SeaOrmTopologyRuleStore::new(topology_db.clone()),
        );
        let topology: Arc<dyn TopologyStore> =
            Arc::new(discovery_topology::SeaOrmTopologyStore::new(topology_db));
        let group_alert_rules: Arc<dyn GroupAlertRuleStore> = Arc::new(
            discovery_config_store::SeaOrmGroupAlertRuleStore::new_in_memory_for_tests().await,
        );

        let correlator = Arc::new(GroupAlertCorrelator::with_refresh(refresh_sources(
            topology_rules.clone(),
            topology.clone(),
            group_alert_rules.clone(),
        )));
        correlator.refresh_snapshot().await.unwrap(); // publishes the empty-but-fresh snapshot

        // The world changes after the snapshot was published.
        topology_rules
            .upsert(&discovery_config_store::TopologyRule {
                id: Uuid::new_v4(),
                name: "lldp".to_string(),
                enabled: true,
                my_key_expression: "metrics.lldp_chassis_id".to_string(),
                claimed_neighbors_expression: Some("metrics.lldp_rem_table".to_string()),
                rank_expression: Some("metrics.role_value".to_string()),
                watched_metrics: None,
            })
            .await
            .unwrap();
        group_alert_rules
            .upsert(&rule(r#"name == "snafu""#, r#"name == "snafu""#))
            .await
            .unwrap();
        let upstream = Uuid::new_v4();
        let downstream = Uuid::new_v4();
        topology
            .apply_recompute(
                "lldp",
                upstream,
                Some("key-a".to_string()),
                vec![],
                Some(0.0),
            )
            .await
            .unwrap();
        topology
            .apply_recompute(
                "lldp",
                downstream,
                Some("key-b".to_string()),
                vec!["key-a".to_string()],
                Some(1.0),
            )
            .await
            .unwrap();
        let cause = alert(upstream, "snafu", 120);
        alert_store.upsert(&cause).await.unwrap();
        let effect = alert(downstream, "snafu", 0);
        alert_store.upsert(&effect).await.unwrap();

        let root = correlator
            .react_to_activation(&alert_store, &effect)
            .await
            .unwrap();
        assert_eq!(
            root, None,
            "a fresh snapshot is trusted — this activation must not trigger a rebuild"
        );

        let persisted = alert_store.get(effect.id).await.unwrap().unwrap();
        assert_eq!(persisted.suppressed_by_alert_id, None);
    }

    #[test]
    fn resolve_cause_picks_the_earliest_qualifying_cause_directly() {
        let evaluator = GroupAlertEvaluator::new();
        let (upstream, downstream) = (Uuid::new_v4(), Uuid::new_v4());
        let earlier = alert(upstream, "snafu", 120);
        let later = alert(upstream, "snafu", 60);
        let effect = alert(downstream, "snafu", 30);
        let by_device: HashMap<Uuid, Vec<&Alert>> =
            HashMap::from([(upstream, vec![&earlier, &later])]);
        let root = resolve_cause(
            &effect,
            &[upstream],
            &by_device,
            &[rule(r#"name == "snafu""#, r#"name == "snafu""#)],
            &evaluator,
        );
        assert_eq!(
            root,
            Some(earlier.id),
            "the earliest qualifying candidate must win"
        );
    }

    #[test]
    fn resolve_cause_skips_a_cause_that_starts_after_the_effect() {
        let evaluator = GroupAlertEvaluator::new();
        let (upstream, downstream) = (Uuid::new_v4(), Uuid::new_v4());
        let too_late = alert(upstream, "snafu", 5); // 5s ago — the effect at 30s ago predates it
        let effect = alert(downstream, "snafu", 30);
        let by_device: HashMap<Uuid, Vec<&Alert>> = HashMap::from([(upstream, vec![&too_late])]);
        let root = resolve_cause(
            &effect,
            &[upstream],
            &by_device,
            &[rule(r#"name == "snafu""#, r#"name == "snafu""#)],
            &evaluator,
        );
        assert_eq!(
            root, None,
            "a cause cannot start after its effect, even on the reactive path"
        );
    }
}
