//! Typed job payloads, one per [`crate::QueueKind`] variant. Kept as plain structs
//! (de)serialized to/from `Job::payload` (a `serde_json::Value`) rather than a single
//! enum, so each queue's handler only ever has to know about its own shape.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{Alert, DeviceFacts, MetricPollOutcome, NotificationTrigger, SnmpCredentials};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperatorAction {
    Test,
    PollNow,
    Rediscover,
    Backup,
}

impl OperatorAction {
    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "test" => Self::Test,
            "poll-now" => Self::PollNow,
            "rediscover" => Self::Rediscover,
            "backup" => Self::Backup,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorActionPayload {
    #[serde(default)]
    pub alert_id: Option<uuid::Uuid>,
    pub device_id: uuid::Uuid,
    pub action: OperatorAction,
    /// Audit provenance only. Credentials and commands never enter the queue payload.
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryPayload {
    pub ip: String,
}

/// `recurring = true` marks the self-perpetuating identity-poll chain for `ip` — started
/// exactly once per IP per process (`DiscoveryHandler` gates this via `ActiveChains`) and
/// re-enqueuing itself forever afterwards. `recurring = false` is a one-off out-of-band
/// re-check (e.g. `profile_reload`'s "a profile changed, re-verify this device sooner than
/// its next scheduled tick" nudge) that must **not** spawn a chain of its own — otherwise
/// every such nudge would leak a second, permanently-running identity-poll loop for a
/// device that already has one. See `discovery_agent::handlers::SnmpPollHandler`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnmpPollPayload {
    pub ip: String,
    pub recurring: bool,
}

/// What the identity probe (`SnmpPoll`) hands to `Dedup`: standard facts plus (only on a
/// device's very first-ever identity cycle) the outcome of the subnet's discovery-time
/// enrichment OIDs — one entry per name, success or failure.
///
/// `extra` is `Some` only on first contact — a direct user requirement: discovery-time
/// OIDs (`SubnetSpec::oids`) are fetched exactly once, never re-polled on subsequent
/// recurring identity cycles ("метрики из дискаверинга... опрашиваем один раз и не
/// переопрашиваем"; anything that *should* be re-polled belongs in the profile's
/// `[metrics.poll]` instead, with its own cadence). `None` on every later cycle means
/// nothing new was fetched this time — `DedupHandler` must leave whatever's already on
/// record untouched, not overwrite it.
///
/// **Changed 2026-08-16 (direct user request — metric change history):** used to be
/// `Option<Metrics>` (successes only; a failed one-shot fetch was logged and silently
/// dropped). Now `Option<BTreeMap<String, MetricPollOutcome>>` — a failed one-shot fetch is
/// recorded too (`value=null, error="..."`, permanently, since there's no retry for
/// one-shot fields by design). `DedupHandler` derives the plain `Metrics` view (successes
/// only) for profile-match purposes, and separately writes the full outcome map (successes
/// and failures) via `DeviceStore::record_metric_polls` — the same single writer
/// `MetricPollHandler` uses for regular profile-polled metrics, see its docs.
///
/// `snmp_credentials` is `Some` only when `SnmpPoll` had to *newly* negotiate working SNMP
/// credentials this cycle (no device was on record with them yet) — `Dedup` is where the
/// device row actually gets created/resolved, so it's also where credentials get persisted
/// onto it (`DeviceStore::set_snmp_credentials`). `None` means either the device already
/// had credentials on record (nothing new to persist) or negotiation didn't apply (no
/// configured subnet matched this IP).
///
/// **`trigger` (the `DedupTrigger` provenance field) removed 2026-08-16, same day it was
/// added** (direct user request, same change that pulled `discovery-dsl::dedup` out
/// entirely — see `discovery_devices::DeviceStore::resolve`'s docs): it only ever
/// distinguished the plain scheduled cycle from a reactive re-check triggered by a
/// `reidentify`-flagged metric changing value. With that mechanism gone, every `Dedup`
/// cycle is the same plain scheduled kind again — nothing left to record provenance about.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedupPayload {
    pub ip: String,
    pub facts: DeviceFacts,
    pub extra: Option<BTreeMap<String, MetricPollOutcome>>,
    pub snmp_credentials: Option<SnmpCredentials>,
}

/// `profile_name`/`profile_version` are what `Dedup`'s matching step just picked for this
/// device — `ProfileApply` compares *both* against what's on record and only reconfigures
/// if either is different (see `discovery_devices::ProfileDecision`). Comparing the
/// version alongside the name is what catches "the profile named X got edited", not just
/// "the device now matches a differently-named profile".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileApplyPayload {
    pub device_id: uuid::Uuid,
    pub profile_name: String,
    pub profile_version: String,
}

/// `generation` ties this poll to the profile "epoch" it was started under — see
/// `discovery_agent::devices::DeviceRegistry::apply_profile_if_changed` for why: a
/// profile change bumps the generation and starts a fresh chain, and any older chain's
/// self-rescheduled job quietly stops once it notices its generation is stale, instead
/// of racing the new one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricPollPayload {
    pub device_id: uuid::Uuid,
    pub generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEvalPayload {
    #[serde(default)]
    pub event: Option<crate::AlertSourceEvent>,
    pub device_id: uuid::Uuid,
}

/// No `generation` (unlike [`MetricPollPayload`]) — reachability checking is independent
/// of profile matching entirely (see `QueueKind::ReachabilityPoll`'s docs), so there's no
/// profile "epoch" for it to be scoped to. The chain simply stops on its own once
/// `get_device` returns `None` (device deleted) — same as `MetricPoll`'s stale-chain
/// stop condition, just without a generation check being the trigger for it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachabilityPollPayload {
    pub device_id: uuid::Uuid,
}

/// `generation` ties this poll to the profile "epoch" it was started under — same
/// mechanism, same reasoning as [`MetricPollPayload::generation`]: service checks are
/// profile-declared (`discovery_dsl::ServiceChecksSection`), so a profile change must
/// restart this chain too, and an older chain's self-rescheduled job quietly stops once it
/// notices its generation is stale.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceCheckPollPayload {
    pub device_id: uuid::Uuid,
    pub generation: u64,
}

/// One delivery attempt to one channel — see `QueueKind::NotificationDispatch`'s docs for
/// why this is scoped to a single `channel_id` rather than a whole alert transition's full
/// recipient list. `alert` is the immutable transition snapshot: delivery may be delayed or
/// retried after the persisted alert has changed, but the notification must retain the state
/// and message that caused this transition. `alert_id` remains the target-existence guard used
/// by the worker when an alert is deleted before delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationDispatchPayload {
    pub channel_id: uuid::Uuid,
    pub alert_id: uuid::Uuid,
    pub alert: Alert,
    pub trigger: NotificationTrigger,
}

/// No `generation` — same reasoning as [`AlertEvalPayload`]: this is a one-shot
/// re-evaluation triggered by a fresh metric poll, not a self-rescheduling chain of its
/// own, so there's no "epoch" for it to be scoped to. `TopologyRecomputeHandler` re-reads
/// every enabled `discovery_config_store::TopologyRule` fresh on each invocation rather
/// than the payload naming a specific rule — see `QueueKind::TopologyRecompute`'s docs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyRecomputePayload {
    pub device_id: uuid::Uuid,
}
