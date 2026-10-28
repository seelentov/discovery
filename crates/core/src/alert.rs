use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertLevel {
    Info,
    Warning,
    Critical,
}

impl AlertLevel {
    /// Lowercase string form — the same three values `discovery_dsl::AlertRule.level`
    /// already stores as plain strings (parsed ad hoc by `discovery_agent::handlers::
    /// parse_level`, which defaults unknown/missing to `Info` since a rule always has
    /// *some* level). Added 2026-09-10 for `discovery_config_store::NotificationRule::
    /// min_level`, which needs the same lowercase-string column convention as every other
    /// enum this codebase persists (`Domain`/`QueueKind`/`NotificationChannelKind`), but
    /// as `Option`-returning `from_str` — a rule's stored level should never silently
    /// coerce a corrupted value to `Info`, unlike `parse_level`'s permissive default.
    pub fn as_str(&self) -> &'static str {
        match self {
            AlertLevel::Info => "info",
            AlertLevel::Warning => "warning",
            AlertLevel::Critical => "critical",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "info" => AlertLevel::Info,
            "warning" => AlertLevel::Warning,
            "critical" => AlertLevel::Critical,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertState {
    Active,
    Cleared,
}

/// Why a `Cleared` transition happened automatically (i.e. **not** a manual close — see
/// [`Alert::closed_by`], which is `Some` for those and makes this field irrelevant).
/// `None` on `Alert` = ordinary automatic clear, the condition's own
/// `deactivation_expression` (or its default negation) genuinely evaluated true — the only
/// kind of automatic clear that existed before row-scoped alerts (2026-08-29, direct user
/// request — "тревога по порту"). `Some(RowMissing)` is the new case: a row-scoped rule's
/// row (e.g. a specific `ifTable` port) vanished from the source table metric entirely,
/// rather than the rule's own condition evaluating the deactivation side true for a row
/// that's still there. Same terminal `Cleared` state, same `clear_after` grace period, same
/// history/retention treatment either way — this is purely a *why*, for the dashboard to
/// label distinctly ("Утеряна" vs "Закрыта"), not a different lifecycle. See
/// `discovery_core::AlertStateTracker::observe`'s docs for exactly how a caller supplies
/// this. Two independent detection sites as of 2026-09-06:
/// `discovery_agent::handlers::AlertEvalHandler::eval_row_scoped_rule`'s missing-row loop
/// (a row-scoped rule's row vanishes from its table metric entirely — the original case
/// this variant was added for), and `eval_device_level_rule` (an ordinary, non-row-scoped
/// rule's referenced *scalar* metric vanishes from `metrics` entirely — no row/table
/// involved at all, see `AlertEvaluator::references_missing_metric`'s docs).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AutoClearReason {
    RowMissing,
}

/// A live incident. Created and mutated by [`crate::AlertStateTracker`] — nothing else
/// should construct these directly, since the tracker is what applies the anti-flapping
/// debounce (see its module docs). Persisted by `discovery_alerts::AlertStore` (added
/// 2026-08-17, direct user request — alert history now lives in the DB, not just this
/// crate's in-memory tracker) on every transition; `discovery-web`'s Тревоги page reads
/// it back from there, paginated/filtered/sorted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    #[serde(default)]
    pub details: crate::AlertDetails,
    pub id: uuid::Uuid,
    pub device_id: uuid::Uuid,
    pub device_ip: String,
    pub name: String,
    /// `Some(key)` for a row-scoped alert (`discovery_dsl::AlertRule::row_metric` is set) —
    /// this incident's identity within the rule, e.g. a specific port's `ifDescr` or
    /// `ifIndex` (whatever `row_key_expression` produced, or the row's own SNMP `index` by
    /// default). `None` for an ordinary device-level alert (today's only kind before
    /// 2026-08-29, direct user request — "тревога по порту"). Together with `device_id` +
    /// `name`, this is the full identity `AlertStateTracker` tracks independently — two
    /// alerts with the same `name` on the same device but different `row_key` are
    /// genuinely separate incidents with their own lifecycle (one port recovering doesn't
    /// affect another still-down port under the same rule).
    #[serde(default)]
    pub row_key: Option<String>,
    pub level: AlertLevel,
    pub message: String,
    pub state: AlertState,
    /// A snapshot of whatever `discovery_dsl::AlertRule::facts_expression` (a Rhai
    /// expression, evaluated against `facts`/`metrics` — same scope convention as
    /// `match.expression`) produced, captured **only at the moment this specific incident
    /// activated** — direct user request: "какие facts доставать в момент создания
    /// тревоги". `None` if the rule doesn't declare a `facts_expression`, or if it failed
    /// to evaluate (logged, not fatal — see `AlertEvalHandler`'s docs). Frozen for this
    /// incident's whole lifetime; a later `StillActive`/`Cleared` observation never
    /// re-evaluates or overwrites it, even though `message`/`last_seen` do update.
    #[serde(default)]
    pub facts: Option<serde_json::Value>,
    pub first_seen: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub cleared_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Username of whoever clicked "Закрыть тревогу" (`discovery-web::close_alert`) —
    /// direct user request 2026-08-28: "указывать кто закрыл тревогу, если пользователь
    /// закрыл руками". `None` for an alert that's still active, or one that cleared
    /// automatically (its own condition became false — `AlertEvalHandler`'s `Cleared`
    /// transition, which never touches this field). A text snapshot of the username at
    /// close time, same "who said what when" reasoning as [`AlertComment::author`] — not a
    /// live `users` join, so it survives that user account later being renamed/deleted.
    /// Reset to `None` on the alert's *next* activation: a re-activation after a manual
    /// close gets a brand-new id (`AlertStateTracker::observe` — closing removes the live
    /// tracked entry, so the next `Activated` transition doesn't reuse the old id), so this
    /// is naturally a fresh row starting from `None`, never an overwrite of history.
    #[serde(default)]
    pub closed_by: Option<String>,
    /// Username and time of the operator acknowledgement. Acknowledgement is an
    /// operator state only; it never changes `state` or the incident lifecycle.
    #[serde(default)]
    pub acknowledged_by: Option<String>,
    #[serde(default)]
    pub acknowledged_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Notification snooze deadline. The deadline is evaluated at dispatch time, so
    /// expiry automatically restores notifications without a cleanup job.
    #[serde(default)]
    pub snoozed_until: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub snoozed_by: Option<String>,
    /// `Some(reason)` when this alert cleared automatically for a reason worth labeling
    /// distinctly from "the condition genuinely resolved" — see [`AutoClearReason`]'s docs.
    /// Always `None` while `state == Active`, and always `None` when `closed_by` is `Some`
    /// (a manual close is never also an auto-clear reason). Frozen once set, same
    /// "written once at the terminal transition, never touched again" convention as
    /// `cleared_at`/`closed_by`.
    #[serde(default)]
    pub auto_clear_reason: Option<AutoClearReason>,
    /// True while the incident is inside the configured flapping window/threshold.
    #[serde(default)]
    pub flapping: bool,
    /// Human-readable reason why activation/recovery notifications are suppressed.
    #[serde(default)]
    pub suppression_reason: Option<String>,
    /// Denormalized count of this alert's [`AlertComment`]s — cheap to show in a list
    /// row (a "💬 N" badge) without fetching the full thread. `0` when there are none.
    /// Never written by the automatic pipeline, same as the thread itself — see
    /// `AlertStore::add_comment`'s docs.
    #[serde(default)]
    pub comment_count: i64,
    /// `Some(root_alert_id)` when `discovery_agent::group_alert`'s sweep has determined
    /// this alert is a downstream consequence of `root_alert_id` (an active alert on a
    /// direct topological upstream neighbor that a `discovery_config_store::GroupAlertRule`
    /// matched as cause/effect) — direct user request, 2026-09-16: "при падении общего
    /// аплинка показывать одну причинную тревогу + N подавленных, не штормить NOC
    /// одинаковыми алертами". `None` means this alert is either its own root cause, or
    /// group-alert correlation hasn't found a qualifying upstream cause for it (yet, or at
    /// all). Recomputed fresh every sweep tick from current state, not incrementally — see
    /// `discovery_agent::group_alert::compute_suppression`'s docs for why that's what makes
    /// un-suppression (the root cause clearing) fall out for free with no separate check
    /// needed anywhere.
    #[serde(default)]
    pub suppressed_by_alert_id: Option<uuid::Uuid>,
    /// `Some(previous_alert_id)` when this alert's `Activated` transition landed within
    /// `discovery_agent::handlers::REOPEN_LINK_WINDOW` of a *manually* closed alert for the
    /// same `(device_id, name, row_key)` — 2026-09-17, audit finding #4 (see
    /// `docs/Changelog/2026-09-17 - Аудит глазами оператора...md`): "Закрыть тревогу"
    /// creates a brand-new incident (see `closed_by`'s docs above) whenever the underlying
    /// condition is still true, which used to silently strand the closed alert's comment
    /// thread with no link forward to whatever the operator sees next. Set once, at
    /// activation, never touched again — same "frozen at the terminal/initial transition"
    /// convention as `closed_by`/`auto_clear_reason`. `None` for the overwhelming majority
    /// of activations (no recent manual close to link back to) — this is not a general
    /// "previous incident for this alert type" pointer, only the narrow reopen case.
    #[serde(default)]
    pub reopened_from_alert_id: Option<uuid::Uuid>,
    #[serde(default)]
    pub repeat_count: u32,
    #[serde(default)]
    pub escalation_level: u32,
    #[serde(default)]
    pub repeated_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub escalation_reason: Option<String>,
}

impl Alert {
    /// Whether an activation/recovery notification must currently be held. This is
    /// intentionally independent from maintenance and group-alert suppression.
    pub fn notifications_snoozed_at(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        self.snoozed_until.is_some_and(|until| until > now)
    }
}

/// Metadata for one file attached to an [`AlertComment`] (2026-08-29, direct user
/// request: "вложения к комментариям тревог: файл/изображение/видео"). The binary
/// content itself is deliberately **not** part of this struct — it lives in the store's
/// own blob column and is fetched separately via `AlertStore::get_attachment`/the
/// `GET /api/alerts/:id/comments/:comment_id/attachments/:attachment_id` route — so
/// listing a comment thread stays cheap even when one comment carries a multi-MB video.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertCommentAttachment {
    pub id: uuid::Uuid,
    pub comment_id: uuid::Uuid,
    pub filename: String,
    pub content_type: String,
    pub size: i64,
}

/// One file to attach when posting a new [`AlertComment`] — `AlertStore::add_comment`'s
/// input shape, not a persisted type itself (that's [`AlertCommentAttachment`] plus a
/// separately-stored blob). `discovery-web`'s `add_alert_comment` builds these from a
/// JSON body where each attachment's bytes travel as base64 — same "JSON in, JSON out"
/// convention the rest of this API already uses, no multipart/form-data plumbing needed.
#[derive(Debug, Clone)]
pub struct NewAttachment {
    pub filename: String,
    pub content_type: String,
    pub data: Vec<u8>,
}

/// One entry in an alert's comment thread (2026-08-28, direct user request — supersedes
/// the earlier 2026-08-18 single free-form `Alert::comment` field: "Мы в дизайне делали
/// комментариями от пользователей", the design artifact's original round-4 intent,
/// reinstated). Append-only — no edit/delete, same "who said what when" audit-trail
/// shape `Alert::facts`'s "frozen snapshot, never touched again" convention takes one
/// step further. Never written by the automatic pipeline (`AlertStateTracker`/
/// `AlertStore::upsert`) — only `AlertStore::add_comment` writes these, same
/// "never touched by automatic code" contract `Device::enabled`/metric overrides use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertComment {
    pub id: uuid::Uuid,
    pub alert_id: uuid::Uuid,
    /// Username at post time — a text snapshot, not a live `users` join. See this
    /// struct's docs on why (an append-only audit trail should keep reading as who
    /// actually wrote it even if that account is later renamed or deleted).
    pub author: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub text: String,
    /// Files attached to this comment (2026-08-29, direct user request) — metadata
    /// only, see [`AlertCommentAttachment`]'s docs for why the bytes live elsewhere.
    /// Empty for the overwhelming majority of comments, which carry no attachment at all.
    #[serde(default)]
    pub attachments: Vec<AlertCommentAttachment>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_str_roundtrip() {
        for level in [AlertLevel::Info, AlertLevel::Warning, AlertLevel::Critical] {
            assert_eq!(AlertLevel::from_str(level.as_str()), Some(level));
        }
    }

    #[test]
    fn level_from_str_rejects_unknown() {
        assert_eq!(AlertLevel::from_str("bogus"), None);
    }

    #[test]
    fn level_ordering_is_info_lt_warning_lt_critical() {
        // Load-bearing for `discovery_config_store::NotificationRule::min_level` —
        // "notify at this level and above" relies on this exact ranking.
        assert!(AlertLevel::Info < AlertLevel::Warning);
        assert!(AlertLevel::Warning < AlertLevel::Critical);
    }
}
