/**
 * Types mirroring the real Rust API shapes (`crates/web/src/lib.rs`, `crates/core/src/
 * device.rs`, `crates/core/src/metrics.rs`). Kept 1:1 with `#[derive(Serialize)]`/
 * `#[derive(Deserialize)]` structs on the backend — when a backend struct changes, this
 * file needs the matching edit, not the other way around. See docs/Architecture/REST API
 * Reference.md for the endpoint list these types belong to.
 */

// ---- Auth ----

export interface UserView {
  id: string
  username: string
  is_admin: boolean
  /** `true` for the fixed `admin`/`admin` bootstrap account until it calls
   * `PUT /api/auth/password` — every domain/admin-gated route 403s server-side while
   * this is set (see `require_domain_permission`/`require_admin` in `crates/web/src/
   * lib.rs`), so the client-side gate in `App.tsx` is UX, not the actual boundary. */
  must_change_password: boolean
  /** `null` = no role assigned, i.e. no domain access at all. */
  role_id: string | null
  /** Denormalized alongside `role_id` purely for display. */
  role_name: string | null
  /** Effective per-domain permissions. Admins bypass these entries server-side. */
  permissions: Record<string, PermissionLevel>
}

export type PermissionLevel = 'read' | 'write'

export interface LoginRequest {
  username: string
  password: string
}

export interface LoginResponse {
  token: string
  user: UserView
}

export interface ChangePasswordRequest {
  current_password: string
  new_password: string
}

// ---- Devices ----

export interface DeviceFacts {
  ip: string
}

/** `discovery_core::Device` — flattened into `DeviceView` on the wire. */
export interface Device {
  id: string
  facts: DeviceFacts
  profile: string | null
  discovered_at: string
  snmp_credentials: SnmpCredentials | null
  /** `discovery_core::SshCredentials` (2026-09-07, SSH CLI-pull metrics) —
   * manual-entry-only, never auto-negotiated (unlike `snmp_credentials`), set via a
   * dedicated `PUT /api/devices/:id/ssh_credentials`. Secrets (`auth.password`/
   * `auth.private_key`/`auth.passphrase`) come back from `GET` **redacted** to an empty
   * string, never the real value (fixed 2026-09-17, audit finding #5 — before this, `GET`
   * genuinely returned the decrypted secret; see `redact_ssh_credentials`'s Rust docs).
   * `username`/`port`/`auth.kind` are real and safe to read back — a form must never
   * resubmit the blanked secret fields as-is; always start them blank and require the
   * operator to re-enter real credentials to change them (unlike notification channels'
   * `secret`, `PUT .../ssh_credentials` always replaces the whole credential — there is no
   * "leave unchanged" partial-update path here). */
  ssh_credentials: SshCredentials | null
  ping_ok: boolean | null
  ping_checked_at: string | null
  /** Share of the most recent reachability tick's `1 + retries` ICMP attempts that got no
   * reply, `0.0`-`100.0` (2026-09-14, `docs/Roadmap.md` "До релиза" item 5). `null` until
   * the first reachability tick after this field existed, same convention as `ping_ok`. */
  ping_loss_pct: number | null
  snmp_ok: boolean | null
  snmp_checked_at: string | null
  ping_failing_since: string | null
  enabled: boolean
}

export interface SnmpCredentials {
  version: string
  community: string
  port: number
}

/** `discovery_core::SshAuth` — `#[serde(tag = "kind", rename_all = "snake_case")]`, same
 * internally-tagged convention as `SnmpAuth`. **No plaintext-ok variant**, unlike
 * `SnmpAuth::Community` — a password and a private key are both always sensitive, both
 * always encrypted at rest server-side (`discovery_core::secret::encrypt_ssh_auth_secrets`). */
export type SshAuth =
  | { kind: 'password'; password: string }
  | { kind: 'private_key'; private_key: string; passphrase?: string | null }

/** `discovery_core::SshCredentials` — the SSH counterpart of `SnmpCredentials`, with one
 * load-bearing difference: manual-entry-only, never auto-negotiated (see that Rust type's
 * docs for why probing a subnet for SSH creds isn't a thing this project does). Set via
 * `PUT /api/devices/:id/ssh_credentials` (`SetSshCredentialsBody`), read back (redacted)
 * as `Device.ssh_credentials`. */
export interface SshCredentials {
  username: string
  auth: SshAuth
  port: number
  /** SHA256 fingerprint of this device's pinned SSH host key (CWE-295 fix, 2026-09-17) —
   * `null` until the first successful connection pins one via trust-on-first-use
   * (`discovery_core::SshCredentials::known_host_key`'s docs). Never a secret (it's the
   * public key the device already presents to anyone who connects), so unlike `auth`'s
   * fields this comes back from `GET` as the real value, not blanked. Read-only from this
   * UI's point of view — there is no form field for it; `PUT .../ssh_credentials` always
   * resets it back to `null` server-side (rotating credentials forces a fresh pin). */
  known_host_key: string | null
}

/** Body for `PUT /api/devices/:id/ssh_credentials` — deliberately **not** the same shape
 * as `SshCredentials`: the Rust side's `SetSshCredentialsBody` has no `known_host_key`
 * field at all (manual pinning isn't a thing this project does — see that field's docs on
 * `SshCredentials` above), so this omits it rather than requiring callers to pass `null`. */
export type SetSshCredentialsBody = Omit<SshCredentials, 'known_host_key'>

/** `discovery_core::MetricTableRow` — one row of a table-shaped metric. `index` is the raw
 * SNMP row index (opaque string, e.g. `"1"`, `"24"`); `fields` maps column name (from
 * `MetricSpec::Detailed::columns`, or the raw subid in "collect everything" mode) to that
 * column's value for this row — not every declared column is guaranteed present in every
 * row (see the Rust type's docs). A cell is itself `MetricValue`-typed but never actually
 * `Table` — SNMP's own MIB syntax forbids a table column from being another table. */
export interface MetricTableRow {
  index: string
  fields: Record<string, MetricValue>
}

/** `MetricValue` is `#[serde(untagged)]` — a plain JSON number/string/bool/array on the
 * wire, never `{"Int": 5}`. `number | string | boolean` covers Int/Float/Str/Bool exactly;
 * `MetricTableRow[]` covers `MetricValue::Table` (a table-shaped SNMP metric — see
 * `discovery_dsl::MetricSpec::Detailed::columns`'s Rust docs for how a metric ends up
 * table-shaped). */
export type MetricValue = number | string | boolean | MetricTableRow[]

export function isTableMetricValue(value: MetricValue): value is MetricTableRow[] {
  return Array.isArray(value)
}

/** One `device_metrics` row — the metric's current cached state. `value`/`polled_at`
 * describe the last *success*; `error`/`last_attempt_at` describe the most recent
 * *attempt*, which may be more recent than the last success if currently failing. */
export interface MetricRecord {
  name: string
  value: MetricValue | null
  error: string | null
  polled_at: string | null
  last_attempt_at: string
  /** `null` = no manual override, this device follows the profile's own default. */
  enabled_override: boolean | null
}

/** `MetricRecord` plus the *resolved* on/off state (override if set, else the profile's
 * current default) — the dashboard should always read `effective_enabled`, not try to
 * recompute it from `enabled_override` + a separately-fetched profile. */
export interface MetricView extends MetricRecord {
  effective_enabled: boolean
}

/** `DeviceView` — `Device` flattened plus its metrics. */
export interface DeviceView extends Device {
  metrics: MetricView[]
  /** Currently-active alert count for this device — batched server-side, see
   * `discovery-web::attach_active_alert_counts`'s Rust docs. */
  active_alert_count: number
  /** Is this device currently under an active maintenance window? Computed fresh on
   * every read, never stored — see `discovery-web::attach_maintenance_status`'s Rust
   * docs. */
  under_maintenance: boolean
}

export interface DevicesQuery {
  search?: string
  profile?: string
  has_error?: boolean
  /** Dotted-quad CIDR, e.g. `"10.121.0.0/16"` — matched in Rust on the backend, not a
   * generic SQL predicate (see `DevicesQuery::cidr`'s Rust docs). */
  cidr?: string
  sort_by?: 'ip' | 'profile' | 'discovered_at'
  sort_dir?: 'asc' | 'desc'
  page?: number
  page_size?: number
}

export interface DevicesPage {
  items: DeviceView[]
  total: number
}

export interface EnabledBody {
  enabled: boolean
}

/** Body for `POST /api/devices` — the one bypass of the discovery pipeline, direct user
 * request 2026-08-28: "ручное создание устройств - указание ip, профиля, ручное
 * добавление метрик". `metrics` is string-only (same shape as a discovery subnet's own
 * one-shot `labels`) — a later real profile poll overwriting one is expected and fine. */
export interface CreateDeviceBody {
  ip: string
  profile?: string
  metrics?: Record<string, string>
  /** Added 2026-08-30 alongside SNMP Trap ingestion — a manually-created device has no
   * `snmp_credentials` otherwise (only a real `SnmpPoll` negotiation sets it), which the
   * trap listener needs to validate an incoming trap's claimed auth against. Optional;
   * omitted leaves the device exactly as before. */
  snmp_auth?: SnmpAuth
  snmp_port?: number
}

export interface SetEnabledAllResponse {
  touched: number
}

// ---- Metric history ----

export interface MetricHistoryRecord {
  /** `null` if this run's state was an error, not a value. */
  value: MetricValue | null
  /** `null` if this run's state was a successful value, not an error. */
  error: string | null
  first_observed_at: string
  last_observed_at: string
}

export interface MetricHistoryPage {
  records: MetricHistoryRecord[]
  total: number
}

export interface HistoryPageQuery {
  page?: number
  page_size?: number
  /** RFC3339 — filters on `last_observed_at`, same one-sided-optional-bounds contract as
   * `AlertsQuery.since`/`.until`. */
  since?: string
  until?: string
}

// ---- Alerts ----

/** `AlertLevel`/`AlertState` have no `#[serde(rename_all)]` — response bodies carry the
 * Rust variant name verbatim (PascalCase). Query-string filter *values* are a different,
 * separate lowercase convention (`parse_alert_level`/`parse_alert_state` in
 * `crates/web/src/lib.rs`) — see `AlertLevelParam`/`AlertStateParam` below. Don't confuse
 * the two: a value read from `Alert.level` can't be sent back as an `AlertsQuery.level`
 * without going through `alertLevelParam()`. */
export type AlertLevel = 'Info' | 'Warning' | 'Critical'
export type AlertState = 'Active' | 'Cleared'

/** `discovery_core::AutoClearReason` — why a `Cleared` alert closed automatically, when
 * that's worth labeling distinctly from "the condition genuinely resolved" (2026-08-29,
 * row-scoped alerts — "тревога по порту"). Currently one value: the row-scoped alert's
 * row (e.g. a specific port) vanished from its source table metric entirely, rather than
 * its own deactivation condition evaluating true for a row still there. Same `Cleared`
 * state/lifecycle either way — this only changes the label the dashboard shows
 * ("Утеряна" instead of "Закрыта"). */
export type AutoClearReason = 'RowMissing'

export type AlertLevelParam = 'info' | 'warning' | 'critical'
export type AlertStateParam = 'active' | 'cleared'

export function alertLevelParam(level: AlertLevel): AlertLevelParam {
  return level.toLowerCase() as AlertLevelParam
}

export interface Alert {
  details?: AlertDetails
  id: string
  device_id: string
  device_ip: string
  name: string
  /** `null` for an ordinary device-level alert. Set for a row-scoped alert
   * (`AlertRule.row_metric` — 2026-08-29, row-scoped alerts) — this incident's
   * identity within the rule, e.g. a specific port's `ifDescr`/index. Two alerts with
   * the same `name` on the same device but different `row_key` are independent
   * incidents (one port recovering doesn't affect another still-down port under the
   * same rule). */
  row_key: string | null
  level: AlertLevel
  message: string
  state: AlertState
  /** Snapshot from `AlertRule::facts_expression`, frozen at activation — see the Rust
   * struct's docs. Arbitrary JSON (whatever the Rhai expression produced), or `null`. */
  facts: unknown
  first_seen: string
  last_seen: string
  cleared_at: string | null
  /** Username of whoever manually clicked "Закрыть тревогу" — `null` if still active or
   * cleared automatically (its own condition became false on its own). */
  closed_by: string | null
  acknowledged_by: string | null
  acknowledged_at: string | null
  snoozed_until: string | null
  snoozed_by: string | null
  /** `null` for a manual close or an ordinary condition-based clear — see
   * `AutoClearReason`'s docs. Only ever set alongside `state === 'Cleared'`. */
  auto_clear_reason: AutoClearReason | null
  flapping: boolean
  suppression_reason: string | null
  /** Denormalized count of this alert's `AlertComment`s — see that type's docs. */
  comment_count: number
  /** Set by `discovery_agent::group_alert`'s sweep when this alert is a downstream
   * consequence of an active alert on a direct topology upstream neighbor — see
   * `discovery_core::Alert.suppressed_by_alert_id`'s Rust docs. `null` means this alert is
   * either its own root cause, or group-alert correlation hasn't found a qualifying
   * upstream cause for it. */
  suppressed_by_alert_id: string | null
  /** Set once, at activation, when this alert reactivated within
   * `discovery_agent::handlers::REOPEN_LINK_WINDOW` of a *manually* closed alert for the
   * same device+name+row — see `discovery_core::Alert.reopened_from_alert_id`'s Rust docs.
   * `null` for the overwhelming majority of alerts (no recent manual close to link to). */
  reopened_from_alert_id: string | null
}

/** Metadata for one file attached to an `AlertComment` (2026-08-29) — bytes are never
 * part of this shape, see `AlertComment.attachments`' docs. */
export interface AlertCommentAttachment {
  id: string
  comment_id: string
  filename: string
  content_type: string
  size: number
}

/** One entry in an alert's comment thread (2026-08-28, design-artifact parity —
 * supersedes the earlier single free-form `Alert.comment` field). Append-only: no edit,
 * no delete. */
export interface AlertComment {
  id: string
  alert_id: string
  author: string
  created_at: string
  text: string
  /** Files attached to this comment (2026-08-29) — metadata only; fetch the actual
   * bytes from `alertCommentAttachmentUrl(alertId, comment.id, attachment.id)`. */
  attachments: AlertCommentAttachment[]
}

export interface AlertsQuery {
  search?: string
  level?: AlertLevelParam
  state?: AlertStateParam
  device_id?: string
  /** Inclusive lower/upper bound on `Alert.first_seen`, ISO-8601. */
  since?: string
  until?: string
  sort_by?: 'first_seen' | 'last_seen' | 'level' | 'name' | 'device_ip'
  sort_dir?: 'asc' | 'desc'
  page?: number
  page_size?: number
}

export interface AlertListPage {
  items: Alert[]
  total: number
}

/** One attachment as it travels to `POST .../comments` — bytes as base64 in the same
 * JSON body as `text` (2026-08-29, direct user request: "вложения к комментариям
 * тревог: файл/изображение/видео"). */
export interface AttachmentUploadBody {
  filename: string
  content_type: string
  data_base64: string
}

export interface AddAlertCommentBody {
  text: string
  attachments?: AttachmentUploadBody[]
}

// ---- Queues / Jobs ----

/** Path-segment / `QueueStatsView.queue` form — `QueueKind::as_str()`, snake_case.
 * Distinct from `Job.queue`/`WorkerActivity.queue` below, which serialize the Rust variant
 * name verbatim (PascalCase) since `QueueKind` itself has no `#[serde(rename_all)]`. */
export type QueueKindParam =
  | 'discovery'
  | 'snmp_poll'
  | 'dedup'
  | 'profile_apply'
  | 'metric_poll'
  | 'alert_eval'
  | 'reachability_poll'
  | 'service_check_poll'
  | 'notification_dispatch'
  | 'topology_recompute'
  | 'operator_action'

export const QUEUE_KINDS: QueueKindParam[] = [
  'discovery',
  'snmp_poll',
  'dedup',
  'profile_apply',
  'metric_poll',
  'alert_eval',
  'reachability_poll',
  'service_check_poll',
  'notification_dispatch',
  'topology_recompute',
  'operator_action',
]

export type QueueKind = 'Discovery' | 'SnmpPoll' | 'Dedup' | 'ProfileApply' | 'MetricPoll' | 'AlertEval' | 'ReachabilityPoll' | 'ServiceCheckPoll' | 'NotificationDispatch' | 'TopologyRecompute' | 'OperatorAction'

export interface QueueStats {
  pending: number
  in_progress: number
  failed: number
  paused: number
  queue_paused: boolean
}

export interface QueueStatsView {
  queue: QueueKindParam
  stats: QueueStats
}

export type JobState = 'Pending' | 'InProgress' | 'Failed' | 'Done' | 'Cancelled'
export type JobStateParam = 'pending' | 'in_progress' | 'failed' | 'done' | 'cancelled'

export interface Job {
  id: number
  queue: QueueKind
  payload: unknown
  dedupe_key: string | null
  state: JobState
  attempts: number
  max_attempts: number
  locked_by: string | null
  locked_at: string | null
  last_error: string | null
  result: unknown | null
  created_at: string
  updated_at: string
  paused: boolean
}

export interface QueueJobsQuery {
  state?: JobStateParam
  search?: string
  sort_by?: 'id' | 'created_at' | 'updated_at' | 'attempts'
  sort_dir?: 'asc' | 'desc'
  page?: number
  page_size?: number
}

/** Field is `jobs`, not `items` — unlike every other paginated list in this API. */
export interface JobListPage {
  jobs: Job[]
  total: number
}

export interface QueuePausedBody {
  paused: boolean
}

export interface ClearQueueResponse {
  deleted: number
}

export interface WorkerActivity {
  worker_id: string
  queue: QueueKind
  current_job_summary: string | null
  started_at: string | null
}

// ---- Logs ----

export interface LogEntry {
  timestamp: string
  /** "TRACE" | "DEBUG" | "INFO" | "WARN" | "ERROR" */
  level: string
  target: string
  message: string
  fields: Record<string, string>
}

export interface LogsQuery {
  level?: string
  target?: string
  search?: string
  /** Inclusive lower/upper bound on `LogEntry.timestamp`, ISO-8601. */
  since?: string
  until?: string
  sort_dir?: 'asc' | 'desc'
  page?: number
  page_size?: number
}

export interface LogsPage {
  items: LogEntry[]
  total: number
}

// ---- Journal (audit trail) ----

/** One recorded user action — `discovery_journal::JournalEntry` on the wire. Written
 * server-side by `require_domain_permission`/`require_admin` after every successful
 * (2xx) mutating request; read-only from the dashboard's own perspective. */
export interface JournalEntry {
  id: string
  ts: string
  username: string
  /** One of the routing-domain names (`DOMAINS` above), plus `"users"`/`"roles"` for
   * the two admin-only route groups that aren't a routed domain. 2026-09-17 audit finding
   * #8: this comment used to name a specific domain count ("11") that had already drifted
   * from `DOMAINS`'s real length — deliberately not repeating a number here at all, so it
   * can't go stale again the next time a domain is added; `DOMAINS.length` is the one
   * source of truth. */
  domain: string
  /** Human-readable (Russian), e.g. "Удалено устройство" — see `describe_action` in
   * `crates/web/src/lib.rs`. */
  action: string
  method: string
  path: string
  /** Short identifier of the specific thing acted on (a profile/discovery config name, a
   * device IP, a role name, ...) — `null` for fleet-wide/singleton actions with no single
   * object (e.g. a bulk device toggle, poll-interval settings). */
  object: string | null
  /** A small before/after diff (edit) or a few named counters (e.g. "N задач удалено") —
   * never a full copy of the edited entity, never a password/SNMP community — see
   * `discovery_web::json_diff`/`redact_sensitive`'s Rust docs. `null` when there's
   * nothing beyond `action`/`object` worth recording (most creates/deletes). Render via
   * `renderJsonAsTable` — same JSON-as-a-table treatment as `Alert.facts`. */
  details: unknown
}

export interface JournalQuery {
  search?: string
  domain?: string
  username?: string
  /** Inclusive lower/upper bound on `JournalEntry.ts`, ISO-8601. */
  since?: string
  until?: string
  sort_by?: 'ts' | 'username' | 'domain' | 'action'
  sort_dir?: 'asc' | 'desc'
  page?: number
  page_size?: number
}

export interface JournalListPage {
  items: JournalEntry[]
  total: number
}

// ---- Profiles ----

/** `discovery_core::Schedule` — `#[serde(untagged)]`, distinguished by shape:
 * `Periodic` always has `interval_secs`, `Calendar` always has `time`. */
export type Schedule = { interval_secs: number } | { months: number[]; days_of_month: number[]; time: string }

export function isPeriodicSchedule(s: Schedule): s is { interval_secs: number } {
  return (s as { interval_secs?: number }).interval_secs !== undefined
}

/** `discovery_dsl::MetricSpec` — `#[serde(untagged)]`. A bare string is "just an OID,
 * everything else defaults" (always enabled, no custom schedule, keep-forever history).
 *
 * `columns` (added 2026-08-29, table metrics) distinguishes scalar vs. table by JSON
 * shape, not a separate tag — same convention `schedule: null` already uses elsewhere in
 * this type:
 * - absent / `null` — scalar. `oid` is polled directly, exactly as before this field
 *   existed.
 * - `{}` (present, empty) — table, "collect everything": one whole-entry `walk()`,
 *   columns auto-named by raw SNMP subid.
 * - `{"name": "subid", ...}` (present, populated) — table, curated columns: `oid` is the
 *   MIB entry OID, each value is that column's subid relative to it (e.g. `ifDescr` =
 *   `"2"` under `ifEntry` = `1.3.6.1.2.1.2.2.1`).
 */
/** `discovery_dsl::DeriveKind` — see `MetricSpec.derive`'s docs. */
export type DeriveKind = 'rate' | 'delta'

export type MetricSpec =
  | string
  | {
      oid: string
      columns?: Record<string, string> | null
      schedule?: Schedule | null
      history_retention_secs?: number | null
      history_keep_last_success?: boolean
      history_keep_last_attempt?: boolean
      enabled?: boolean
      /** Opts this metric into a derived rate/delta value, computed from consecutive raw
       * counter samples and stored as its own synthetic metric (`<name>_rate`/
       * `<name>_delta`) — see `discovery_dsl::MetricSpec::Detailed::derive`'s Rust docs
       * for the full design. `null`/absent = no derived value (unchanged behavior). */
      derive?: DeriveKind | null
    }
  | {
      /** `discovery_dsl::MetricSpec::SshCommand` (2026-09-07) — the metric's value is the
       * captured stdout of running this command over SSH on the device (using
       * `Device.ssh_credentials`), instead of an SNMP get/walk. Disambiguated from the
       * `oid`-based variant above purely by JSON shape (`command` present, `oid` absent)
       * — same untagged-enum convention this whole type follows. Always a scalar
       * (`MetricValue::Str`) — no table/`columns`/`derive` equivalent, see the Rust docs
       * for why that's a deliberate scope cut, not a v1 gap. */
      command: string
      schedule?: Schedule | null
      history_retention_secs?: number | null
      history_keep_last_success?: boolean
      history_keep_last_attempt?: boolean
      enabled?: boolean
    }

export function metricSpecIsTable(spec: MetricSpec): boolean {
  return typeof spec !== 'string' && 'columns' in spec && spec.columns != null
}

export function metricSpecIsSshCommand(spec: MetricSpec): boolean {
  return typeof spec !== 'string' && 'command' in spec
}

export function metricSpecOid(spec: MetricSpec): string {
  if (typeof spec === 'string') return spec
  return 'oid' in spec ? spec.oid : ''
}

export function metricSpecCommand(spec: MetricSpec): string {
  return typeof spec !== 'string' && 'command' in spec ? spec.command : ''
}

export function metricSpecEnabled(spec: MetricSpec): boolean {
  return typeof spec === 'string' ? true : (spec.enabled ?? true)
}

export interface AlertRule {
  policy?: AlertPolicy
  name: string
  /** "info" | "warning" | "critical" (free string on the wire — anything else is
   * treated as "info" by the evaluator). */
  level: string
  /** Name of a table-shaped metric (`MetricSpec` with `columns` set) this rule iterates
   * — one independent incident per matching row instead of one for the whole device
   * (2026-08-29, row-scoped alerts). `null`/absent (the default) — an ordinary
   * device-level rule, `expression`/etc. evaluate once per device per tick, unchanged
   * from before this field existed. When set, those same expressions instead gain a
   * third scope variable, `row`, evaluated once per row of `metrics.<row_metric>`. */
  row_metric?: string | null
  /** Only meaningful when `row_metric` is set. A Rhai expression, scope `{facts,
   * metrics, row}`, computing this row's stable tracking identity — e.g. `row.ifDescr`
   * (survives the row being renumbered). `null`/absent (the default) means
   * `row.index` — the row's own SNMP index. */
  row_key_expression?: string | null
  expression: string
  deactivation_expression?: string | null
  facts_expression?: string | null
  message: string
  clear_after_seconds?: number | null
  activate_after_seconds?: number | null
  flap_window_seconds?: number | null
  flap_threshold?: number | null
  enabled: boolean
}

export interface ProfileMeta {
  name: string
  priority: number
}

export interface MatchSection {
  expression: string
}

export interface MetricsSection {
  poll: Record<string, MetricSpec>
}

/** `discovery_dsl::TrapEventSpec` — one OID this trap binding recognizes. `varbinds` maps
 * a field name on the resulting row to the varbind OID (as it appears on the wire) to
 * pull that field's value from, e.g. `{if_index: "1.3.6.1.2.1.2.2.1.1"}` — only real
 * device data, no way to inject a literal. Direction confirmed against
 * `discovery_agent::trap_ingest::extract_fields` (found live 2026-09-19 — the Rust type's
 * own doc comment had this backwards, copied here and into the trap editor's hint text;
 * all three fixed together). `key_expression` (Rhai, scope `{facts, varbinds}`) computes
 * the row's identity; `null`/empty/blank all mean "no per-entity identity" (a
 * device-level singleton fact, not a per-key table) — see the Rust docs for why blank
 * normalizes the same as absent. */
export interface TrapEventSpec {
  trap_oid: string
  varbinds: Record<string, string>
  key_expression?: string | null
}

/** `discovery_dsl::TrapSpec` — one trap-derived fact (`metrics.trap_<binding name>`).
 * `variants` is a flat list, not "open"/"close" roles — each variant independently
 * upserts the same key-addressed row whenever its own `trap_oid` matches (2026-08-30
 * design pass — see `docs/Changelog` for why the earlier open/close-role shape was
 * dropped). `ttl_secs` is staleness since the row was last touched by *any* variant, not
 * "waiting for a specific closer" — the only path that can produce
 * `AutoClearReason.RowMissing`/"Утеряна" for trap-derived rows, since nothing re-walks
 * this table on a cadence the way a polled metric does. */
export interface TrapSpec {
  variants: TrapEventSpec[]
  ttl_secs?: number | null
  history_retention_secs?: number | null
}

export interface TrapsSection {
  bindings: Record<string, TrapSpec>
}

/** `discovery_dsl::SyslogEventSpec` — one message shape this syslog binding recognizes.
 * `pattern` is a regex tested against the message body only (facility/severity/hostname
 * are parsed for free from the RFC 3164/5424 header and always exposed as automatic row
 * fields regardless of what `pattern` captures) — named capture groups (`(?P<name>...)`)
 * become row fields directly, no separate field-name map like `TrapEventSpec.varbinds`
 * needs, since a capture group's name already is a real field name. `max_severity`/
 * `facility` are optional pre-filters, checked before `pattern` runs at all.
 * `key_expression` (Rhai, scope `{facts, fields}`) computes the row's identity; `null`/
 * empty/blank all mean "no per-entity identity", same convention as
 * `TrapEventSpec.key_expression`. */
export interface SyslogEventSpec {
  pattern: string
  max_severity?: number | null
  facility?: number | null
  key_expression?: string | null
}

/** `discovery_dsl::SyslogSpec` — one syslog-derived fact (`metrics.syslog_<binding
 * name>`). Same flat-`variants`-list shape as `TrapSpec`, same `ttl_secs` staleness
 * semantics. */
export interface SyslogSpec {
  variants: SyslogEventSpec[]
  ttl_secs?: number | null
  history_retention_secs?: number | null
}

export interface SyslogSection {
  bindings: Record<string, SyslogSpec>
}

/** `discovery_dsl::ServiceCheckProtocol` — lowercase on the wire (`#[serde(rename_all =
 * "lowercase")]`). */
export type ServiceCheckProtocol = 'tcp' | 'http' | 'https' | 'ssh'

/** `discovery_dsl::ServiceCheckSpec` — one L4/L7 check, becoming one row of
 * `metrics.service_checks` (index = `name`) once polled. `target` is `null`/absent for the
 * common case (the device's own IP); `path`/`expected_status`/`body_contains` only apply to
 * `http`/`https`. */
export interface ServiceCheckSpec {
  name: string
  protocol: ServiceCheckProtocol
  target?: string | null
  port: number
  path?: string | null
  expected_status?: number | null
  body_contains?: string | null
  timeout_ms?: number | null
  enabled: boolean
}

/** `discovery_dsl::ServiceChecksSection` — L4/L7 service checks (TCP/HTTP(S)/SSH
 * reachability, 2026-09-07). One schedule for the whole `checks` list (unlike
 * `MetricSpec`'s per-metric schedule) — every check lands in the single synthetic
 * `metrics.service_checks` table metric, rewritten as a whole on every poll tick. `null`
 * schedule = use the process-wide default, `poll_intervals.service_check_secs`. */
export interface ServiceChecksSection {
  checks: ServiceCheckSpec[]
  schedule?: Schedule | null
  history_retention_secs?: number | null
}

export interface ProfileFile {
  profile: ProfileMeta
  match: MatchSection
  metrics: MetricsSection
  traps: TrapsSection
  syslog: SyslogSection
  service_checks: ServiceChecksSection
  alerts: AlertRule[]
}

export interface ProfilesQuery {
  search?: string
  sort_by?: 'name' | 'priority'
  sort_dir?: 'asc' | 'desc'
  page?: number
  page_size?: number
}

export interface ProfilesPage {
  items: ProfileFile[]
  total: number
}

export interface SyncProfileDevicesResponse {
  devices_synced: number
}

// ---- Discovery configs ----

/** `#[serde(rename_all = "lowercase")]` on `discovery_core::SnmpVersion` — wire values are
 * lowercase, unlike most other enums in this API (which have no rename and serialize
 * PascalCase). Verified against a live `POST /api/discovery-configs` round trip: sending
 * `"V2c"` 422s with "unknown variant `V2c`, expected `v1` or `v2c`". */
export type SnmpVersion = 'v1' | 'v2c'

/** `#[serde(rename_all = "lowercase")]` on `discovery_core::SnmpAuthProtocol`. */
export type SnmpAuthProtocol = 'md5' | 'sha1' | 'sha224' | 'sha256' | 'sha384' | 'sha512'

/** `#[serde(rename_all = "snake_case")]` on `discovery_core::SnmpPrivProtocol` —
 * `aes192_blumenthal`/`aes192_reeder` (and the 256-bit equivalents) exist because there's
 * no single standard for extending a too-short localized key up to 192/256 bits; Cisco
 * gear conventionally uses "Reeder", most other vendors (and net-snmp) use "Blumenthal". */
export type SnmpPrivProtocol = 'des' | 'des3' | 'aes128' | 'aes192_blumenthal' | 'aes192_reeder' | 'aes256_blumenthal' | 'aes256_reeder'

export interface SnmpV3AuthCreds {
  protocol: SnmpAuthProtocol
  /** Plaintext over the wire (HTTPS is the transport protection); encrypted at rest by
   * the backend (`discovery_core::secret`) before it ever reaches the database. */
  passphrase: string
}

export interface SnmpV3PrivCreds {
  protocol: SnmpPrivProtocol
  passphrase: string
}

/** `discovery_core::SnmpAuth` — replaced the former `snmp_versions`/`read_communities`
 * pair on `SubnetSpec` (2026-08-29, SNMPv3 support): v3 has no community string at all
 * (USM instead), so a flat per-candidate union replaces two separate lists that used to
 * be combined as a version×community cross-product at negotiation time.
 * `#[serde(tag = "kind", rename_all = "snake_case")]`, `UsmV3` is a tuple variant wrapping
 * `SnmpV3Credentials` — internally tagged, so its fields flatten alongside `kind` on the
 * wire (verified: `SnmpAuth::UsmV3(SnmpV3Credentials{user:"monitor",auth:None,priv_:None})`
 * serializes to `{"kind":"usm_v3","user":"monitor","auth":null,"priv_":null}`, not nested
 * under a `usm_v3` key). `auth: null` = noAuthNoPriv, `auth` set + `priv_: null` =
 * authNoPriv, both set = authPriv; `priv_` set without `auth` is rejected server-side
 * (privNoAuth isn't a real SNMPv3 security level). */
export type SnmpAuth =
  | { kind: 'community'; version: SnmpVersion; community: string }
  | { kind: 'usm_v3'; user: string; auth?: SnmpV3AuthCreds | null; priv_?: SnmpV3PrivCreds | null }

/** `discovery_config_store::DiscoveryOidSpec` — same three-state `columns` encoding as
 * `MetricSpec` (see its own docs), minus the scheduling/retention fields `MetricSpec` has:
 * a `SubnetSpec.oids` entry is fetched exactly once (a device's very first identity
 * cycle), never re-polled, so there's no cadence to configure. `columns` absent/`null` =
 * scalar; `{}` = table "collect everything"; `{"name": "subid", ...}` = table with
 * curated columns. */
export type DiscoveryOidSpec = string | { oid: string; columns?: Record<string, string> | null }

export function discoveryOidSpecOid(spec: DiscoveryOidSpec): string {
  return typeof spec === 'string' ? spec : spec.oid
}

export function discoveryOidSpecIsTable(spec: DiscoveryOidSpec): boolean {
  return typeof spec !== 'string' && spec.columns != null
}

export interface SubnetSpec {
  ip: string
  mask: string
  port: number
  /** Candidates tried in order, stopping at the first that answers — community and USM
   * v3 entries mixed freely. See `SnmpAuth`'s docs. */
  credentials: SnmpAuth[]
  oids: Record<string, DiscoveryOidSpec>
  labels: Record<string, string>
  snmp_timeout_ms?: number | null
  snmp_retries?: number | null
  create_dead_devices: boolean
}

export interface DiscoveryConfig {
  name: string
  enabled: boolean
  schedule: Schedule
  subnets: SubnetSpec[]
}

export interface DiscoveryConfigsQuery {
  search?: string
  enabled?: boolean
  sort_by?: 'name' | 'enabled'
  sort_dir?: 'asc' | 'desc'
  page?: number
  page_size?: number
}

export interface DiscoveryConfigsPage {
  items: DiscoveryConfig[]
  total: number
}

export interface RunDiscoveryConfigResponse {
  enqueued: number
}

// ---- Maintenance windows ----

/** Same dotted-decimal ip+mask shape as `SubnetSpec` above — see
 * `discovery_config_store::SubnetTarget`'s Rust docs for why a maintenance window's
 * targeting has its own, smaller type rather than reusing `SubnetSpec` itself. */
export interface SubnetTarget {
  ip: string
  mask: string
}

/** A one-off, time-boxed alert-suppression window. See
 * `discovery_config_store::MaintenanceWindow`'s Rust docs for the full selector
 * semantics (AND across populated dimensions, `device_ids` as an unconditional
 * override, empty selector matches nothing). */
export interface MaintenanceWindow {
  id: string
  name: string
  enabled: boolean
  starts_at: string
  ends_at: string
  subnets: SubnetTarget[]
  profiles: string[]
  device_ids: string[]
}

/** `POST /api/maintenance-windows` body — `id: null`/omitted creates a new window
 * (server generates the id); `id` set to an existing window's id edits it in place. */
export interface MaintenanceWindowBody {
  id?: string | null
  name: string
  enabled: boolean
  starts_at: string
  ends_at: string
  subnets: SubnetTarget[]
  profiles: string[]
  device_ids: string[]
}

// ---- Notification channels + matrix (2026-09-10) ----

export type NotificationChannelKind = 'email' | 'telegram' | 'webhook'

/** A user's own contact point — self-service (`/api/notifications/channels*`, no domain
 * gate) or admin-on-behalf-of (`/api/users/:id/notification-channels*`). See
 * `discovery_core::NotificationChannel`'s Rust docs. `secret` is webhook-only (HMAC
 * signing) — always `null` for `email`/`telegram`.
 *
 * 2026-09-17 audit finding #5's side-check: a GET response never carries the real value —
 * `""` means one is configured, `null` means it isn't (see `redact_notification_channel`'s
 * Rust docs). Submitting an edit with a blank `secret` therefore means "leave the existing
 * one unchanged", not "clear it" (see `upsert_notification_channel_for`'s Rust docs). */
export interface NotificationChannel {
  id: string
  user_id: string
  kind: NotificationChannelKind
  target: string
  secret: string | null
  enabled: boolean
  created_at: string
}

/** `id: null`/omitted creates a new channel; `id` set edits it in place. */
export interface NotificationChannelBody {
  id?: string | null
  kind: NotificationChannelKind
  target: string
  secret?: string | null
  enabled: boolean
}

export type NotificationTrigger = 'activated' | 'cleared'

/** One row of the notification matrix — "кого извещать по какой тревоге". See
 * `discovery_config_store::NotificationRule`'s Rust docs, in particular why an empty
 * device selector (`subnets`/`profiles`/`device_ids` all empty) matches **every**
 * device here — the opposite default from `MaintenanceWindow`. `active_from`/
 * `active_to` are `"HH:MM:SS"` in UTC (not the browser's local time — this project has
 * no timezone handling anywhere else either), always both set or both `null` together. */
/** One entry of `NotificationRule.recipients` — either a specific user (`users.id`, a
 * bare UUID string) or every *current* member of an RBAC role (2026-09-18, "Матрица
 * нотификаций — роль как группа получателей"). Mirrors
 * `discovery_config_store::RecipientRef`'s `#[serde(untagged)]` wire shape exactly: a
 * plain string is a user id (the pre-existing shape, unchanged), `{role: "..."}` is a
 * role id — never a third, tagged shape. */
export type RecipientRef = string | { role: string }

export function isRoleRecipient(r: RecipientRef): r is { role: string } {
  return typeof r === 'object' && r !== null && 'role' in r
}

export interface NotificationRule {
  selection?: NotificationSelection
  id: string
  name: string
  enabled: boolean
  min_level: AlertLevel
  subnets: SubnetTarget[]
  profiles: string[]
  device_ids: string[]
  active_from: string | null
  active_to: string | null
  days_of_week: string[]
  notify_on_activate: boolean
  notify_on_clear: boolean
  recipients: RecipientRef[]
}

export interface NotificationRuleBody {
  selection?: NotificationSelection
  id?: string | null
  name: string
  enabled: boolean
  min_level: AlertLevel
  subnets: SubnetTarget[]
  profiles: string[]
  device_ids: string[]
  active_from?: string | null
  active_to?: string | null
  days_of_week: string[]
  notify_on_activate: boolean
  notify_on_clear: boolean
  recipients: RecipientRef[]
}

/** Minimal `{id, username}` projection for the matrix editor's recipient picker — not
 * the full admin-only `/api/users` payload, see `list_notification_recipients`'s Rust
 * docs for why. */
export interface NotificationRecipient {
  id: string
  username: string
}

/** Sibling of `NotificationRecipient` for the role-as-proxy-group recipient option — see
 * `list_notification_recipient_roles`'s Rust docs. */
export interface NotificationRecipientRole {
  id: string
  name: string
}

/** A provider-authored Rhai extraction rule for the configurable topology mechanism —
 * see `discovery_config_store::TopologyRule`'s Rust docs. `claimed_neighbors_expression:
 * null` means this rule only computes `my_key_expression` (a pure clustering signal, no
 * directed neighbor claims). `rank_expression: null` means this rule doesn't participate
 * in hierarchy at all — lower value = closer to the core/more upstream. `watched_metrics:
 * null` means "auto-detect from all three expressions' `metrics.<name>` references"
 * rather than an explicit override list. */
export interface TopologyRule {
  id: string
  name: string
  enabled: boolean
  my_key_expression: string
  claimed_neighbors_expression: string | null
  rank_expression: string | null
  watched_metrics: string[] | null
}

export interface TopologyRuleBody {
  id?: string | null
  name: string
  enabled: boolean
  my_key_expression: string
  claimed_neighbors_expression?: string | null
  rank_expression?: string | null
  watched_metrics?: string[] | null
}

/** One resolved neighbor of a specific device under one rule — see
 * `discovery_topology::ResolvedNeighbor`'s Rust docs on what `confirmed: false` means
 * (only one side currently claims the other; still a real edge, not an error state).
 * `upstream_device_id: null` means direction is undetermined (no override, and either
 * side lacks a rank or both ranks tie) — never fabricated. */
export interface ResolvedNeighbor {
  neighbor_device_id: string
  confirmed: boolean
  upstream_device_id: string | null
  direction_overridden: boolean
}

/** One resolved edge in the whole fleet-wide graph for a rule — `device_a`/`device_b`
 * canonically ordered, an edge is undirected (see `discovery_topology::ResolvedEdge`'s
 * Rust docs). `upstream_device_id`, when set, is always one of `device_a`/`device_b`. */
export interface ResolvedEdge {
  device_a: string
  device_b: string
  confirmed: boolean
  upstream_device_id: string | null
  direction_overridden: boolean
}

/** `ResolvedEdge` plus both devices' IPs, resolved server-side — what `GET
 * /api/topology/rules/:name/edges` actually returns (2026-09-18, manual-test-audit
 * finding #5). `device_a_ip`/`device_b_ip` are `null` if that device has since been
 * deleted — the page falls back to the raw id in that case, same as before this endpoint
 * resolved IPs itself. */
export interface TopologyEdgeView extends ResolvedEdge {
  device_a_ip: string | null
  device_b_ip: string | null
}

/** Search + filter + sort + paginate parameters for `GET
 * /api/topology/rules/:name/edges` — same shape/conventions as `AlertsQuery`/
 * `DevicesQuery`. `search` matches either device's IP; `status`/`direction` are select
 * filters, not free text (a fixed small set of states, same reasoning `DevicesQuery.profile`
 * already documents for using a dropdown over a text box). */
export interface TopologyEdgesQuery {
  search?: string
  status?: 'confirmed' | 'unconfirmed'
  direction?: 'determined' | 'undetermined'
  sort_by?: 'device_a' | 'device_b' | 'status' | 'direction'
  sort_dir?: 'asc' | 'desc'
  page?: number
  page_size?: number
}

export interface TopologyEdgesPage {
  items: TopologyEdgeView[]
  total: number
}

/** A provider-authored Rhai cause/effect rule for group-alert suppression — see
 * `discovery_config_store::GroupAlertRule`'s Rust docs. Both expressions run against
 * `{name, level, facts}` of a candidate alert: `cause_expression` against the upstream
 * (root-cause) candidate, `effect_expression` against the downstream (to-be-suppressed)
 * candidate — kept separate so an unrelated active alert on the upstream device (e.g. High
 * CPU) can't suppress an independent alert downstream (e.g. Port Down) just because they
 * coincide in time and topology direction. Unlike `TopologyRule.name`, `name` here is a
 * display label only — no uniqueness constraint. */
export interface GroupAlertRule {
  id: string
  name: string
  enabled: boolean
  cause_expression: string
  effect_expression: string
}

export interface GroupAlertRuleBody {
  id?: string | null
  name: string
  enabled: boolean
  cause_expression: string
  effect_expression: string
}

/** System-wide SMTP/Telegram delivery credentials — one relay, one bot, shared by every
 * user's channel of the matching kind. `smtp_password`/`telegram_bot_token` come back
 * from `GET` redacted to an empty string when configured, `null` when not (fixed
 * 2026-09-17, audit finding #5's side-check — before this, `GET` genuinely returned the
 * decrypted secret; see `get_notification_provider_settings`'s Rust docs). Submitting an
 * edit with a blank field therefore means "leave the existing value unchanged", not
 * "clear it" (see `put_notification_provider_settings`'s Rust docs) — same contract as
 * `NotificationChannel.secret`. */
export interface NotificationProviderConfig {
  smtp_host: string | null
  smtp_port: number
  smtp_username: string | null
  smtp_password: string | null
  smtp_from_address: string | null
  telegram_bot_token: string | null
}

// ---- Settings ----

export interface PollIntervalsConfig {
  identity_secs: number
  metric_secs: number
  profiles_reload_secs: number
  discovery_schedule_check_secs: number
  metric_history_cleanup_secs: number
  reachability_secs: number
  alert_cleanup_secs: number
  dead_device_cleanup_secs: number
  logs_cleanup_secs: number
  journal_cleanup_secs: number
  service_check_secs: number
  group_alert_sweep_secs: number
}

/** `null` = keep cleared alerts forever. */
export interface AlertRetentionConfig {
  retention_secs: number | null
}

/** `null` = keep logs forever. */
export interface LogRetentionConfig {
  retention_secs: number | null
}

/** `null` = keep journal entries forever. */
export interface JournalRetentionConfig {
  retention_secs: number | null
}

export interface PingConfig {
  timeout_ms: number
  retries: number
}


/** `0` = never auto-delete (not `null` — a different nullable-vs-zero convention than
 * `AlertRetentionConfig`/`LogRetentionConfig` above, see the Rust struct's docs). */
export interface DeadDeviceRetentionConfig {
  unreachable_for_secs: number
}

export type DbKind = 'postgres' | 'mysql' | 'sqlite' | 'memory' | 'clickhouse' | 'cassandra'

export interface DatabaseConnConfig {
  name: string
  kind: DbKind
  host?: string | null
  port?: number | null
  database?: string | null
  username?: string | null
  password?: string | null
  file_path?: string | null
  pool_max_connections?: number | null
  sqlite_busy_timeout_secs: number
}

export interface StorageDatabasesView {
  databases: DatabaseConnConfig[]
  default_database: string | null
}

export interface StorageDatabasesUpdate {
  databases: DatabaseConnConfig[]
  default_database: string | null
}

export interface StorageWriteResponse {
  needs_restart: boolean
}

/** One entry per `Domain` — `null` means "use the default database". */
export interface DomainRouting {
  settings: string | null
  alerts: string | null
  devices: string | null
  discovery_configs: string | null
  device_metrics: string | null
  profiles: string | null
  logs: string | null
  jobs: string | null
  maintenance_windows: string | null
  notifications: string | null
  topology: string | null
  group_alerts: string | null
}

/** The keys of `DomainRouting`, in the order the dashboard shows them — also the exact
 * strings `Role.permissions`/`RoleRequest.permissions` use. */
export const DOMAINS: (keyof DomainRouting)[] = [
  'settings',
  'alerts',
  'devices',
  'discovery_configs',
  'device_metrics',
  'profiles',
  'logs',
  'jobs',
  'maintenance_windows',
  'notifications',
  'topology',
  'group_alerts',
]

export const DOMAIN_LABELS: Record<keyof DomainRouting, string> = {
  settings: 'Настройки',
  alerts: 'Тревоги',
  devices: 'Устройства',
  discovery_configs: 'Дискаверинг',
  device_metrics: 'Метрики устройств',
  profiles: 'Профили',
  logs: 'Логи',
  jobs: 'Очередь заданий',
  maintenance_windows: 'Окна обслуживания',
  notifications: 'Уведомления',
  topology: 'Топология',
  group_alerts: 'Групповые тревоги',
}

/** `JournalEntry.domain`'s full value set — the routed domains above plus `users`/
 * `roles`, which aren't routed domains but do get their own admin-only write actions
 * recorded (`require_admin` in `crates/web/src/lib.rs`). Used for the Журнал page's
 * domain filter dropdown. */
export const JOURNAL_DOMAINS = [...DOMAINS, 'users', 'roles'] as const

export const JOURNAL_DOMAIN_LABELS: Record<(typeof JOURNAL_DOMAINS)[number], string> = {
  ...DOMAIN_LABELS,
  users: 'Пользователи',
  roles: 'Роли',
}

// ---- Users ----

export interface UserListItem {
  id: string
  username: string
  is_admin: boolean
  /** See `UserView.must_change_password`'s docs. Surfaced here so an admin can see which
   * accounts (e.g. a bootstrap `admin`/`admin` left unchanged) are still stuck on a
   * default/temporary password. */
  must_change_password: boolean
  created_at: string
  role_id: string | null
  role_name: string | null
}

export interface CreateUserRequest {
  username: string
  password: string
  is_admin?: boolean
  /** Opts this account into the same forced-change-on-first-login flow the bootstrap
   * account uses — e.g. for handing out a temporary password. Defaults to `false`. */
  must_change_password?: boolean
  role_id?: string | null
}

export interface SetPasswordRequest {
  password: string
}

export interface SetAdminRequest {
  is_admin: boolean
}

export interface SetUserRoleRequest {
  role_id: string | null
}

// ---- Roles ----

/** A named, reusable per-domain permission bundle — a user just picks one, doesn't set
 * per-domain permissions directly (2026-08-27, design-artifact parity pass, round 5).
 * `permissions`: domain name -> "read" | "write" (`Domain`/`AccessLevel::as_str()`), same
 * shape the old per-user `UserView.permissions` map used, just keyed by role now. */
export interface Role {
  id: string
  name: string
  permissions: Record<string, string>
}

export interface RoleRequest {
  name: string
  permissions: Record<string, string>
}

// ---- AI Assistant (2026-09-18) ----

/** `discovery_assistant::Conversation` — one chat conversation, scoped to its owning
 * user. Self-service (`/api/assistant/conversations*`, no domain gate) — see
 * `docs/Architecture/AI Assistant.md`. */
export interface Conversation {
  id: string
  owner_user_id: string
  title: string
  created_at: string
  updated_at: string
  /** Per-conversation opt-in bypass of confirm-before-write (2026-09-18, direct user
   * request — "bypass permission... как в Claude Code"). Default `false`. Toggled via
   * `PUT /api/assistant/conversations/:id`. Does not change what the assistant is allowed
   * to do — only whether a write-level tool call stops for a manual Confirm click. */
  auto_approve_writes: boolean
}

/** `discovery_assistant::MessageRole` — `#[serde(rename_all = "lowercase")]`. */
export type MessageRole = 'user' | 'assistant' | 'tool'

/** `discovery_assistant::ToolCallStatus` — `#[serde(rename_all = "snake_case")]`.
 * `pending_confirmation` is the confirm-before-write gate a write-level tool call stops
 * at until the user calls `.../confirm` or `.../reject`. */
export type ToolCallStatus = 'none' | 'pending_confirmation' | 'confirmed' | 'rejected' | 'executed' | 'failed'

/** `discovery_assistant::Message` — one turn in a conversation. `tool_call` is set on an
 * assistant message that proposed calling a tool (`{name, arguments}`); `tool_result` is
 * set on the `'tool'`-role message carrying that call's outcome (`{status_code, body}`,
 * or `{declined_by_user: true}` after a reject). */
export interface Message {
  id: string
  conversation_id: string
  sequence: number
  role: MessageRole
  content: string | null
  tool_call: { name: string; arguments: unknown } | null
  tool_call_status: ToolCallStatus
  tool_result: { status_code: number; body: unknown } | { declined_by_user: true } | { error: string } | null
  created_at: string
}

/** Response shape of `POST .../messages`, `.../confirm`, `.../reject` — `status` says
 * whether the turn produced a final reply or stopped on a pending write action needing
 * confirmation; `message` is the newest assistant-role message either way. */
export interface TurnResponse {
  status: 'final' | 'awaiting_confirmation'
  message: Message
}

/** `discovery_core::AiAssistantProviderConfig` — system-wide LLM provider credentials,
 * admin-only to read/write (`/api/settings/ai-assistant`, `admin_guard!`, not a
 * `Domain`-gated route — see that Rust type's docs for why). `client_secret`/
 * `openrouter_api_key`/`self_hosted_api_key` come back from `GET` redacted to `""` when
 * set, `null` when not — same "blank on write means leave unchanged" contract as
 * `NotificationProviderConfig`'s secrets. `provider` picks which field group below is
 * actually used — `client_*` for `"gigachat"`, `openrouter_*` for `"openrouter"`
 * (2026-09-18, second provider), `self_hosted_*` for `"self_hosted"` (2026-09-19, third
 * provider — vLLM/Ollama/etc., customer's own server; `self_hosted_api_key` is genuinely
 * optional, unlike the other two providers' secrets — many self-hosted deployments run
 * with no auth at all). */
export interface AiAssistantProviderConfig {
  enabled: boolean
  provider: string
  client_id: string
  client_secret: string | null
  client_scope: string
  openrouter_api_key: string | null
  openrouter_model: string
  self_hosted_base_url: string
  self_hosted_api_key: string | null
  self_hosted_model: string
}

export type AlertMode = 'state' | 'change' | 'baseline' | 'event'
export type AlertLifecycle = 'raised' | 'activated' | 'cleared' | 'acknowledged' | 'escalated' | 'deescalated'
export interface AlertPolicy {
  mode?: AlertMode
  period_seconds?: number | null
  lower_expression?: string | null
  upper_expression?: string | null
  history_metrics?: string[]
  history_seconds?: number | null
  event?: { metric: string; count: number; window_seconds: number; recovery_expression?: string | null; key_expression?: string | null } | null
  shared_rule?: string | null
  flap_clear_threshold?: number | null
  flap_incident?: boolean
  acknowledge_required?: boolean
  escalate_after_seconds?: number | null
  pending_count_threshold?: number | null
  actions?: { on: AlertLifecycle; action: OperatorAction; condition?: string | null }[]
  interactive_actions?: OperatorAction[]
  viewer_roles?: string[]
  operator_roles?: string[]
  screen_notification?: boolean
  notification_sound?: boolean
  notification_lifetime_seconds?: number | null
}
export interface AlertDetails {
  policy: AlertPolicy
  observed_value?: unknown
  previous_value?: unknown
  lower_bound?: number | null
  upper_bound?: number | null
  source_event?: unknown
  recovery_data?: unknown
  raised_count: number
  response_escalated: boolean
  response_escalation_reason?: string | null
}
export interface AlertRuleStatus {
  name: string; row_key: string | null
  state: 'true' | 'false' | 'error' | 'missing' | 'disabled' | 'maintenance' | 'waiting'
  checked_at: string; next_check_at: string | null; error: string | null
  activation_since: string | null; recovery_since: string | null
  activate_after_seconds: number; clear_after_seconds: number
  active_alert_id: string | null; flapping: boolean
  value: unknown; previous_value: unknown
  lower_bound: number | null; upper_bound: number | null
  event_count: number; events_required: number; window_seconds: number
}
export interface NotificationSelection {
  alert_names?: string[]; row_keys?: string[]; source_metrics?: string[]
  recipient_expression?: string | null
  notify_on_escalation?: boolean; notify_on_deescalation?: boolean
}

export type OperatorAction = 'test' | 'poll_now' | 'rediscover' | 'backup'
