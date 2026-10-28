import { SharedAlertRules } from '../components/SharedAlertRules'
import { AlertPolicyEditor } from '../components/AlertPolicyEditor'
import { useCallback, useEffect, useRef, useState } from 'react'
import { profilesApi } from '../api/profiles'
import { ApiHttpError } from '../api/http'
import type { AlertRule, DeriveKind, MetricSpec, ProfileFile, ServiceCheckProtocol, ServiceCheckSpec, ServiceChecksSection, SyslogEventSpec, SyslogSpec, TrapEventSpec, TrapSpec } from '../api/types'
import { Button } from '../components/Button'
import { EmptyStateBlock } from '../components/EmptyState'
import { Field } from '../components/Field'
import { Icon } from '../components/Icon'
import { KvEditor } from '../components/KvEditor'
import { Modal } from '../components/Modal'
import { OidTypeAndValueFields, TableColumnsFields, validManualColumns, type ColumnsMode, type OidKind } from '../components/OidFields'
import { Pagination } from '../components/Pagination'
import { Switch } from '../components/Switch'
import { useConfirm } from '../hooks/useConfirm'
import { useAuth } from '../hooks/useAuth'
import { useToast } from '../hooks/useToast'
import { downloadJsonValue, readJsonFile } from '../utils/export'

type SortBy = 'name' | 'priority'

const PAGE_SIZE = 24

function useDebouncedValue<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const id = setTimeout(() => setDebounced(value), delayMs)
    return () => clearTimeout(id)
  }, [value, delayMs])
  return debounced
}

type ScheduleMode = 'default' | 'periodic' | 'calendar'

/** `OidKind`/`ColumnsMode` — shared with `DiscoveryPage`'s subnet-OID editor, see
 * `components/OidFields.tsx`'s docs. Scalar = a single OID, `get()`-ed directly. Table =
 * `oid` is a MIB table entry, walked column by column (`columnsMode: 'auto'` -> `columns:
 * {}`, `'manual'` -> the curated map) — see `discovery_dsl::MetricSpec::Detailed`'s
 * `columns` field docs for the three-state wire encoding this UI produces. Aliased to
 * `MetricKind` here purely for this file's own naming (`EditingMetric.metricKind`) —
 * same type either name. */
type MetricKind = OidKind

/** `'snmp'` -> the existing `oid`/`columns`/`derive` form (`MetricSpec.oid`/`Detailed`).
 * `'ssh'` -> `MetricSpec::SshCommand` (2026-09-07) — the metric's value is a command's
 * captured stdout over SSH instead of an SNMP get/walk. Always scalar, no table/derive
 * equivalent — see that variant's Rust docs for why. */
type MetricSource = 'snmp' | 'ssh'

interface EditingMetric {
  name: string
  source: MetricSource
  oid: string
  /** Only meaningful when `source === 'ssh'` — the command run verbatim over the
   * device's SSH session. */
  command: string
  metricKind: MetricKind
  columnsMode: ColumnsMode
  /** [column name, SNMP subid relative to `oid`][] — only used when `metricKind ===
   * 'table' && columnsMode === 'manual'`. */
  columns: [string, string][]
  scheduleMode: ScheduleMode
  intervalSecs: string
  months: string
  days: string
  time: string
  enabled: boolean
  retentionSecs: string
  keepSuccess: boolean
  keepAttempt: boolean
  /** `'none'` -> `derive: null`/omitted on save. See `MetricSpec.derive`'s docs — only
   * meaningful for a scalar SNMP metric, hidden in the form otherwise. */
  deriveMode: 'none' | DeriveKind
}

/** One `SyslogEventSpec` in editing form — string fields throughout (same convention as
 * `EditingMetric`'s `retentionSecs` etc.), parsed back to number/null on save. */
interface EditingSyslogVariant {
  pattern: string
  maxSeverity: string
  facility: string
  keyExpression: string
}

/** One `syslog.bindings` entry, name pulled out of the map key into the row itself — same
 * "array of rows with an embedded name" shape `EditingMetric[]` uses for `metrics.poll`. */
interface EditingSyslogBinding {
  name: string
  variants: EditingSyslogVariant[]
  ttlSecs: string
  historyRetentionSecs: string
}

/** One `TrapEventSpec` in editing form. `varbinds` — field name -> varbind OID (see
 * `KvEditor`'s `keyPlaceholder`/`valuePlaceholder` below, and `api/types.ts`'s
 * `TrapEventSpec` docs for the direction bug found live 2026-09-19) — edited as a plain
 * key/value list via the shared `KvEditor` (same component `TableColumnsFields` uses for
 * a metric's curated column map), since it's exactly that shape. */
interface EditingTrapVariant {
  trapOid: string
  varbinds: [string, string][]
  keyExpression: string
}

/** One `traps.bindings` entry — direct structural sibling of `EditingSyslogBinding`. */
interface EditingTrapBinding {
  name: string
  variants: EditingTrapVariant[]
  ttlSecs: string
  historyRetentionSecs: string
}

/** One `ServiceCheckSpec` in editing form — string fields throughout, same convention as
 * `EditingMetric`. `path`/`expectedStatus`/`bodyContains` only meaningful for
 * `http`/`https` (form hides them for `tcp`/`ssh`, mirroring how `MetricRow` hides the
 * columns editor for a scalar metric). */
interface EditingServiceCheck {
  name: string
  protocol: ServiceCheckProtocol
  target: string
  port: string
  path: string
  expectedStatus: string
  bodyContains: string
  timeoutMs: string
  enabled: boolean
}

/** `discovery_dsl::ServiceChecksSection` in editing form. Unlike `EditingSyslogBinding`/
 * `EditingTrapBinding` (a map of named bindings, each with its own `ttl_secs`), this
 * section is a flat `checks` list sharing **one** schedule/retention for the whole
 * synthetic `metrics.service_checks` table — so the schedule fields live here, at the
 * section level, not per-row. */
interface EditingServiceChecksSection {
  checks: EditingServiceCheck[]
  scheduleMode: ScheduleMode
  intervalSecs: string
  months: string
  days: string
  time: string
  retentionSecs: string
}

interface EditingProfile {
  name: string
  priority: number
  matchExpression: string
  metrics: EditingMetric[]
  alerts: AlertRule[]
  syslog: EditingSyslogBinding[]
  traps: EditingTrapBinding[]
  serviceChecks: EditingServiceChecksSection
}

function emptyMetric(): EditingMetric {
  return {
    name: '',
    source: 'snmp',
    oid: '',
    command: '',
    metricKind: 'scalar',
    columnsMode: 'auto',
    columns: [],
    scheduleMode: 'default',
    intervalSecs: '',
    months: '',
    days: '',
    time: '',
    enabled: true,
    retentionSecs: '',
    keepSuccess: true,
    keepAttempt: true,
    deriveMode: 'none',
  }
}

function emptyAlert(): AlertRule {
  return { name: '', level: 'warning', row_metric: null, row_key_expression: null, expression: '', deactivation_expression: '', facts_expression: '', message: '', clear_after_seconds: 0, activate_after_seconds: 0, flap_window_seconds: 0, flap_threshold: 0, enabled: true }
}

function emptySyslogVariant(): EditingSyslogVariant {
  return { pattern: '', maxSeverity: '', facility: '', keyExpression: '' }
}

function emptySyslogBinding(): EditingSyslogBinding {
  return { name: '', variants: [emptySyslogVariant()], ttlSecs: '', historyRetentionSecs: '' }
}

function specToEditingSyslogVariant(v: SyslogEventSpec): EditingSyslogVariant {
  return { pattern: v.pattern, maxSeverity: v.max_severity != null ? String(v.max_severity) : '', facility: v.facility != null ? String(v.facility) : '', keyExpression: v.key_expression ?? '' }
}

function specToEditingSyslogBinding(name: string, spec: SyslogSpec): EditingSyslogBinding {
  return {
    name,
    variants: spec.variants.length > 0 ? spec.variants.map(specToEditingSyslogVariant) : [emptySyslogVariant()],
    ttlSecs: spec.ttl_secs != null ? String(spec.ttl_secs) : '',
    historyRetentionSecs: spec.history_retention_secs != null ? String(spec.history_retention_secs) : '',
  }
}

function editingSyslogVariantToSpec(v: EditingSyslogVariant): SyslogEventSpec {
  return {
    pattern: v.pattern.trim(),
    max_severity: v.maxSeverity.trim() ? Number(v.maxSeverity) : null,
    facility: v.facility.trim() ? Number(v.facility) : null,
    key_expression: v.keyExpression.trim() || null,
  }
}

function editingSyslogBindingToSpec(b: EditingSyslogBinding): SyslogSpec {
  return {
    variants: b.variants.filter((v) => v.pattern.trim()).map(editingSyslogVariantToSpec),
    ttl_secs: b.ttlSecs.trim() ? Number(b.ttlSecs) : null,
    history_retention_secs: b.historyRetentionSecs.trim() ? Number(b.historyRetentionSecs) : null,
  }
}

function emptyTrapVariant(): EditingTrapVariant {
  return { trapOid: '', varbinds: [], keyExpression: '' }
}

function emptyTrapBinding(): EditingTrapBinding {
  return { name: '', variants: [emptyTrapVariant()], ttlSecs: '', historyRetentionSecs: '' }
}

function specToEditingTrapVariant(v: TrapEventSpec): EditingTrapVariant {
  return { trapOid: v.trap_oid, varbinds: Object.entries(v.varbinds ?? {}), keyExpression: v.key_expression ?? '' }
}

function specToEditingTrapBinding(name: string, spec: TrapSpec): EditingTrapBinding {
  return {
    name,
    variants: spec.variants.length > 0 ? spec.variants.map(specToEditingTrapVariant) : [emptyTrapVariant()],
    ttlSecs: spec.ttl_secs != null ? String(spec.ttl_secs) : '',
    historyRetentionSecs: spec.history_retention_secs != null ? String(spec.history_retention_secs) : '',
  }
}

function editingTrapVariantToSpec(v: EditingTrapVariant): TrapEventSpec {
  return {
    trap_oid: v.trapOid.trim(),
    varbinds: Object.fromEntries(v.varbinds.map(([k, val]) => [k.trim(), val.trim()] as [string, string]).filter(([k, val]) => k && val)),
    key_expression: v.keyExpression.trim() || null,
  }
}

function editingTrapBindingToSpec(b: EditingTrapBinding): TrapSpec {
  return {
    variants: b.variants.filter((v) => v.trapOid.trim()).map(editingTrapVariantToSpec),
    ttl_secs: b.ttlSecs.trim() ? Number(b.ttlSecs) : null,
    history_retention_secs: b.historyRetentionSecs.trim() ? Number(b.historyRetentionSecs) : null,
  }
}

function emptyServiceCheck(): EditingServiceCheck {
  return { name: '', protocol: 'tcp', target: '', port: '', path: '', expectedStatus: '', bodyContains: '', timeoutMs: '', enabled: true }
}

function emptyServiceChecksSection(): EditingServiceChecksSection {
  return { checks: [], scheduleMode: 'default', intervalSecs: '', months: '', days: '', time: '', retentionSecs: '' }
}

function specToEditingServiceCheck(spec: ServiceCheckSpec): EditingServiceCheck {
  return {
    name: spec.name,
    protocol: spec.protocol,
    target: spec.target ?? '',
    port: String(spec.port),
    path: spec.path ?? '',
    expectedStatus: spec.expected_status != null ? String(spec.expected_status) : '',
    bodyContains: spec.body_contains ?? '',
    timeoutMs: spec.timeout_ms != null ? String(spec.timeout_ms) : '',
    enabled: spec.enabled,
  }
}

function sectionToEditingServiceChecksSection(section: ServiceChecksSection): EditingServiceChecksSection {
  const schedule = section.schedule ?? null
  const mode: ScheduleMode = !schedule ? 'default' : 'interval_secs' in schedule ? 'periodic' : 'calendar'
  return {
    checks: (section.checks ?? []).map(specToEditingServiceCheck),
    scheduleMode: mode,
    intervalSecs: mode === 'periodic' && schedule && 'interval_secs' in schedule ? String(schedule.interval_secs) : '',
    months: mode === 'calendar' && schedule && 'months' in schedule ? schedule.months.join(', ') : '',
    days: mode === 'calendar' && schedule && 'days_of_month' in schedule ? schedule.days_of_month.join(', ') : '',
    time: mode === 'calendar' && schedule && 'time' in schedule ? schedule.time : '',
    retentionSecs: section.history_retention_secs != null ? String(section.history_retention_secs) : '',
  }
}

function editingServiceCheckToSpec(c: EditingServiceCheck): ServiceCheckSpec {
  return {
    name: c.name.trim(),
    protocol: c.protocol,
    target: c.target.trim() || null,
    port: Number(c.port) || 0,
    path: c.path.trim() || null,
    expected_status: c.expectedStatus.trim() ? Number(c.expectedStatus) : null,
    body_contains: c.bodyContains.trim() || null,
    timeout_ms: c.timeoutMs.trim() ? Number(c.timeoutMs) : null,
    enabled: c.enabled,
  }
}

function editingServiceChecksSectionToSection(e: EditingServiceChecksSection): ServiceChecksSection {
  let schedule = null
  if (e.scheduleMode === 'periodic' && e.intervalSecs.trim()) {
    schedule = { interval_secs: Number(e.intervalSecs) }
  } else if (e.scheduleMode === 'calendar') {
    schedule = { months: parseNumberList(e.months), days_of_month: parseNumberList(e.days), time: e.time.trim() }
  }
  return {
    checks: e.checks.filter((c) => c.name.trim()).map(editingServiceCheckToSpec),
    schedule,
    history_retention_secs: e.retentionSecs.trim() ? Number(e.retentionSecs) : null,
  }
}

function specToEditingMetric(name: string, spec: MetricSpec): EditingMetric {
  if (typeof spec === 'string') {
    return { ...emptyMetric(), name, oid: spec }
  }
  const schedule = spec.schedule ?? null
  const mode: ScheduleMode = !schedule ? 'default' : 'interval_secs' in schedule ? 'periodic' : 'calendar'
  const scheduleFields = {
    scheduleMode: mode,
    intervalSecs: mode === 'periodic' && schedule && 'interval_secs' in schedule ? String(schedule.interval_secs) : '',
    months: mode === 'calendar' && schedule && 'months' in schedule ? schedule.months.join(', ') : '',
    days: mode === 'calendar' && schedule && 'days_of_month' in schedule ? schedule.days_of_month.join(', ') : '',
    time: mode === 'calendar' && schedule && 'time' in schedule ? schedule.time : '',
    enabled: spec.enabled ?? true,
    retentionSecs: spec.history_retention_secs != null ? String(spec.history_retention_secs) : '',
    keepSuccess: spec.history_keep_last_success ?? true,
    keepAttempt: spec.history_keep_last_attempt ?? true,
  }
  if ('command' in spec) {
    return { ...emptyMetric(), name, source: 'ssh', command: spec.command, ...scheduleFields }
  }
  // Three states, mirroring `discovery_dsl::MetricSpec::Detailed::columns`'s docs exactly:
  // absent/null -> scalar; present+empty -> table/auto; present+populated -> table/manual.
  const metricKind: MetricKind = spec.columns != null ? 'table' : 'scalar'
  const columnsEntries = spec.columns != null ? Object.entries(spec.columns) : []
  return {
    name,
    source: 'snmp',
    oid: spec.oid,
    command: '',
    metricKind,
    columnsMode: columnsEntries.length > 0 ? 'manual' : 'auto',
    columns: columnsEntries,
    ...scheduleFields,
    deriveMode: spec.derive ?? 'none',
  }
}

function parseNumberList(text: string): number[] {
  return text
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map(Number)
    .filter((n) => !Number.isNaN(n))
}

function editingMetricToSpec(m: EditingMetric): MetricSpec {
  let schedule = null
  if (m.scheduleMode === 'periodic' && m.intervalSecs.trim()) {
    schedule = { interval_secs: Number(m.intervalSecs) }
  } else if (m.scheduleMode === 'calendar') {
    schedule = { months: parseNumberList(m.months), days_of_month: parseNumberList(m.days), time: m.time.trim() }
  }
  const retentionSecs = m.retentionSecs.trim() ? Number(m.retentionSecs) : null

  if (m.source === 'ssh') {
    return {
      command: m.command.trim(),
      schedule,
      enabled: m.enabled,
      history_retention_secs: retentionSecs,
      history_keep_last_success: m.keepSuccess,
      history_keep_last_attempt: m.keepAttempt,
    }
  }

  // `columns` is the scalar/table discriminant itself (see `MetricSpec`'s docs) — a table
  // metric always needs the detailed object form, regardless of whether any of the other
  // "needs the detailed form" flags below are also set. `derive` is deliberately omitted
  // here (not even `null`) — it's only meaningful for a scalar metric (see
  // `MetricSpec.derive`'s docs), the form hides the control entirely for a table metric.
  if (m.metricKind === 'table') {
    const columns = m.columnsMode === 'auto' ? {} : Object.fromEntries(validManualColumns(m.columns))
    return {
      oid: m.oid,
      columns,
      schedule,
      enabled: m.enabled,
      history_retention_secs: retentionSecs,
      history_keep_last_success: m.keepSuccess,
      history_keep_last_attempt: m.keepAttempt,
    }
  }

  const derive: DeriveKind | null = m.deriveMode === 'none' ? null : m.deriveMode
  const needsTableForm = schedule !== null || !m.enabled || retentionSecs !== null || !m.keepSuccess || !m.keepAttempt || derive !== null
  if (!needsTableForm) return m.oid
  return {
    oid: m.oid,
    schedule,
    enabled: m.enabled,
    history_retention_secs: retentionSecs,
    history_keep_last_success: m.keepSuccess,
    history_keep_last_attempt: m.keepAttempt,
    derive,
  }
}

/** A table metric in manual-columns mode with nothing actually filled in is a dead-end
 * config — it would poll every tick and always produce an empty table, with no way for the
 * user to tell that apart from "a real table that happens to have zero rows right now"
 * from the profile list. Caught at save time rather than left to fail silently at poll
 * time. */
function metricNeedsAtLeastOneColumn(m: EditingMetric): boolean {
  return m.source === 'snmp' && m.metricKind === 'table' && m.columnsMode === 'manual' && validManualColumns(m.columns).length === 0
}

function fileToEditing(p: ProfileFile): EditingProfile {
  return {
    name: p.profile.name,
    priority: p.profile.priority,
    matchExpression: p.match.expression,
    metrics: Object.entries(p.metrics?.poll ?? {}).map(([name, spec]) => specToEditingMetric(name, spec)),
    alerts: (p.alerts ?? []).map((a) => ({ ...a })),
    syslog: Object.entries(p.syslog?.bindings ?? {}).map(([name, spec]) => specToEditingSyslogBinding(name, spec)),
    traps: Object.entries(p.traps?.bindings ?? {}).map(([name, spec]) => specToEditingTrapBinding(name, spec)),
    serviceChecks: sectionToEditingServiceChecksSection(p.service_checks ?? { checks: [] }),
  }
}

function editingToFile(e: EditingProfile): ProfileFile {
  const poll: Record<string, MetricSpec> = {}
  for (const m of e.metrics) {
    if (!m.name.trim()) continue
    if (m.source === 'ssh' ? !m.command.trim() : !m.oid.trim()) continue
    poll[m.name.trim()] = editingMetricToSpec(m)
  }
  const syslogBindings: Record<string, SyslogSpec> = {}
  for (const b of e.syslog) {
    if (!b.name.trim() || b.variants.every((v) => !v.pattern.trim())) continue
    syslogBindings[b.name.trim()] = editingSyslogBindingToSpec(b)
  }
  const trapBindings: Record<string, TrapSpec> = {}
  for (const b of e.traps) {
    if (!b.name.trim() || b.variants.every((v) => !v.trapOid.trim())) continue
    trapBindings[b.name.trim()] = editingTrapBindingToSpec(b)
  }
  return {
    profile: { name: e.name.trim(), priority: e.priority || 0 },
    match: { expression: e.matchExpression },
    metrics: { poll },
    traps: { bindings: trapBindings },
    syslog: { bindings: syslogBindings },
    service_checks: editingServiceChecksSectionToSection(e.serviceChecks),
    alerts: e.alerts,
  }
}

function emptyEditing(): EditingProfile {
  return { name: '', priority: 0, matchExpression: '', metrics: [], alerts: [], syslog: [], traps: [], serviceChecks: emptyServiceChecksSection() }
}

export function ProfilesPage({
  openProfile: openProfileDeepLink,
  onOpenProfileHandled,
}: {
  /** Set by Alerts' "правило: X →" link (`tab: 'alerts'`) or Devices' profile-name link
   * (`tab: 'main'`, direct user request 2026-08-28 — "хочу проваливаться не в тревоги а
   * основное") — which tab the profile edit modal opens on depends on where the click
   * came from, not a single hardcoded choice. */
  openProfile?: { name: string; tab: 'main' | 'alerts' } | null
  onOpenProfileHandled?: () => void
}) {
  const toast = useToast()
  const confirm = useConfirm()
  const { canWrite } = useAuth()
  const canWriteProfiles = canWrite('profiles')
  const [searchInput, setSearchInput] = useState('')
  const search = useDebouncedValue(searchInput, 300)
  const [sortBy, setSortBy] = useState<SortBy>('name')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')
  const [page, setPage] = useState(1)
  const [data, setData] = useState<{ items: ProfileFile[]; total: number } | null>(null)
  const [editing, setEditing] = useState<EditingProfile | null>(null)
  const [isNew, setIsNew] = useState(false)
  const [error, setError] = useState('')
  const [tab, setTab] = useState<'main' | 'metrics' | 'alerts' | 'syslog' | 'traps' | 'serviceChecks'>('main')
  const [syncStatus, setSyncStatus] = useState<Record<string, string>>({})
  // Direct user request 2026-08-28: клонирование профилей. Only cosmetic (the modal
  // title) — `handleSave` always upserts by name regardless of `isNew`, so a cloned
  // profile with a new name is already a distinct row with no special-casing needed.
  const [cloneSource, setCloneSource] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const res = await profilesApi.list({ search: search || undefined, sort_by: sortBy, sort_dir: sortDir, page, page_size: PAGE_SIZE })
      setData(res)
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось загрузить профили', true)
    }
  }, [search, sortBy, sortDir, page, toast])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    setPage(1)
  }, [search, sortBy, sortDir])

  // Deep-link from Alerts' "правило: X →" or Devices' profile-name link — fetched
  // directly by name (not read off the current paginated/filtered `profiles` list, which
  // may not even contain it) so the link works regardless of what filter/page this page
  // happens to be showing.
  useEffect(() => {
    if (!openProfileDeepLink) return
    const { name, tab: targetTab } = openProfileDeepLink
    profilesApi
      .get(name)
      .then((p) => {
        setError('')
        setTab(targetTab)
        setIsNew(false)
        setEditing(fileToEditing(p))
      })
      .catch((e) => toast(e instanceof ApiHttpError ? e.message : 'Не удалось открыть профиль', true))
      .finally(() => onOpenProfileHandled?.())
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [openProfileDeepLink])

  const profiles = data?.items ?? null

  function openCreate() {
    setError('')
    setTab('main')
    setIsNew(true)
    setCloneSource(null)
    setEditing(emptyEditing())
  }

  function openEdit(p: ProfileFile) {
    setError('')
    setTab('main')
    setIsNew(false)
    setCloneSource(null)
    setEditing(fileToEditing(p))
  }

  function openClone(p: ProfileFile) {
    setError('')
    setTab('main')
    setIsNew(true)
    setCloneSource(p.profile.name)
    setEditing({ ...fileToEditing(p), name: '' })
  }

  async function handleDelete(p: ProfileFile) {
    const ok = await confirm(`Удалить профиль «${p.profile.name}»?`, { label: 'Удалить', icon: 'trash' })
    if (!ok) return
    try {
      await profilesApi.delete(p.profile.name)
      toast('Профиль удалён')
      load()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось удалить профиль', true)
    }
  }

  async function handleSyncDevices(p: ProfileFile) {
    setSyncStatus((prev) => ({ ...prev, [p.profile.name]: 'синхронизация…' }))
    try {
      const res = await profilesApi.syncDevices(p.profile.name)
      setSyncStatus((prev) => ({ ...prev, [p.profile.name]: `синхронизировано устройств: ${res.devices_synced}` }))
    } catch (e) {
      setSyncStatus((prev) => ({ ...prev, [p.profile.name]: `ошибка: ${e instanceof ApiHttpError ? e.message : 'не удалось'}` }))
    }
  }

  async function handleSave() {
    if (!editing) return
    const brokenTableMetric = editing.metrics.find(metricNeedsAtLeastOneColumn)
    if (brokenTableMetric) {
      toast(`Метрика «${brokenTableMetric.name || '(без имени)'}»: таблица без столбцов — добавьте хотя бы один столбец или включите «собрать всё»`, true)
      return
    }
    setError('')
    try {
      await profilesApi.upsert(editingToFile(editing))
      setEditing(null)
      toast(`Профиль «${editing.name}» сохранён`)
      load()
    } catch (e) {
      setError(e instanceof ApiHttpError ? e.message : 'Не удалось сохранить профиль')
    }
  }

  function updateMetric(idx: number, patch: Partial<EditingMetric>) {
    setEditing((prev) => {
      if (!prev) return prev
      const metrics = prev.metrics.slice()
      metrics[idx] = { ...metrics[idx], ...patch }
      return { ...prev, metrics }
    })
  }

  function updateAlert(idx: number, patch: Partial<AlertRule>) {
    setEditing((prev) => {
      if (!prev) return prev
      const alerts = prev.alerts.slice()
      alerts[idx] = { ...alerts[idx], ...patch }
      return { ...prev, alerts }
    })
  }

  function updateSyslogBinding(idx: number, patch: Partial<EditingSyslogBinding>) {
    setEditing((prev) => {
      if (!prev) return prev
      const syslog = prev.syslog.slice()
      syslog[idx] = { ...syslog[idx], ...patch }
      return { ...prev, syslog }
    })
  }

  function updateTrapBinding(idx: number, patch: Partial<EditingTrapBinding>) {
    setEditing((prev) => {
      if (!prev) return prev
      const traps = prev.traps.slice()
      traps[idx] = { ...traps[idx], ...patch }
      return { ...prev, traps }
    })
  }

  function updateServiceCheck(idx: number, patch: Partial<EditingServiceCheck>) {
    setEditing((prev) => {
      if (!prev) return prev
      const checks = prev.serviceChecks.checks.slice()
      checks[idx] = { ...checks[idx], ...patch }
      return { ...prev, serviceChecks: { ...prev.serviceChecks, checks } }
    })
  }

  // Direct user request 2026-08-28: "экспортировать... список метрик для импорта в
  // другой профиль" — export/import the metrics/alerts *lists* (not the whole profile,
  // that's `openClone` above) as JSON, for copying a subset from one profile into
  // another. Import merges by name — an imported entry overwrites a same-named local
  // draft row rather than appending a duplicate.
  const metricsFileInputRef = useRef<HTMLInputElement>(null)
  const alertsFileInputRef = useRef<HTMLInputElement>(null)
  const syslogFileInputRef = useRef<HTMLInputElement>(null)
  const trapsFileInputRef = useRef<HTMLInputElement>(null)
  const serviceChecksFileInputRef = useRef<HTMLInputElement>(null)

  function exportMetrics() {
    if (!editing) return
    downloadJsonValue(`${editing.name || 'profile'}-metrics.json`, editing.metrics)
  }

  function exportAlerts() {
    if (!editing) return
    downloadJsonValue(`${editing.name || 'profile'}-alerts.json`, editing.alerts)
  }

  function exportSyslog() {
    if (!editing) return
    downloadJsonValue(`${editing.name || 'profile'}-syslog.json`, editing.syslog)
  }

  function exportTraps() {
    if (!editing) return
    downloadJsonValue(`${editing.name || 'profile'}-traps.json`, editing.traps)
  }

  function exportServiceChecks() {
    if (!editing) return
    downloadJsonValue(`${editing.name || 'profile'}-service-checks.json`, editing.serviceChecks.checks)
  }

  async function handleImportMetrics(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file || !editing) return
    try {
      const data = await readJsonFile(file)
      if (!Array.isArray(data)) throw new Error('expected an array')
      const byName = new Map(editing.metrics.map((m) => [m.name, m]))
      for (const m of data as EditingMetric[]) byName.set(m.name, m)
      setEditing({ ...editing, metrics: Array.from(byName.values()) })
      toast(`Импортировано метрик: ${data.length}`)
    } catch {
      toast('Не удалось импортировать метрики — проверьте формат файла (JSON-список из экспорта)', true)
    }
  }

  async function handleImportAlerts(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file || !editing) return
    try {
      const data = await readJsonFile(file)
      if (!Array.isArray(data)) throw new Error('expected an array')
      const byName = new Map(editing.alerts.map((a) => [a.name, a]))
      for (const a of data as AlertRule[]) byName.set(a.name, a)
      setEditing({ ...editing, alerts: Array.from(byName.values()) })
      toast(`Импортировано тревог: ${data.length}`)
    } catch {
      toast('Не удалось импортировать тревоги — проверьте формат файла (JSON-список из экспорта)', true)
    }
  }

  async function handleImportSyslog(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file || !editing) return
    try {
      const data = await readJsonFile(file)
      if (!Array.isArray(data)) throw new Error('expected an array')
      const byName = new Map(editing.syslog.map((b) => [b.name, b]))
      for (const b of data as EditingSyslogBinding[]) byName.set(b.name, b)
      setEditing({ ...editing, syslog: Array.from(byName.values()) })
      toast(`Импортировано syslog-биндингов: ${data.length}`)
    } catch {
      toast('Не удалось импортировать syslog-биндинги — проверьте формат файла (JSON-список из экспорта)', true)
    }
  }

  async function handleImportTraps(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file || !editing) return
    try {
      const data = await readJsonFile(file)
      if (!Array.isArray(data)) throw new Error('expected an array')
      const byName = new Map(editing.traps.map((b) => [b.name, b]))
      for (const b of data as EditingTrapBinding[]) byName.set(b.name, b)
      setEditing({ ...editing, traps: Array.from(byName.values()) })
      toast(`Импортировано trap-биндингов: ${data.length}`)
    } catch {
      toast('Не удалось импортировать trap-биндинги — проверьте формат файла (JSON-список из экспорта)', true)
    }
  }

  async function handleImportServiceChecks(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file || !editing) return
    try {
      const data = await readJsonFile(file)
      if (!Array.isArray(data)) throw new Error('expected an array')
      const byName = new Map(editing.serviceChecks.checks.map((c) => [c.name, c]))
      for (const c of data as EditingServiceCheck[]) byName.set(c.name, c)
      setEditing({ ...editing, serviceChecks: { ...editing.serviceChecks, checks: Array.from(byName.values()) } })
      toast(`Импортировано service-чеков: ${data.length}`)
    } catch {
      toast('Не удалось импортировать service-чеки — проверьте формат файла (JSON-список из экспорта)', true)
    }
  }

  return (
    <div className="util-col gap-4">
      <div className="card-header">
        <div className="card-title">Профили</div>
        {canWriteProfiles && (
          <Button variant="primary" title="Создать новый профиль с нуля" onClick={openCreate}>
            <Icon name="plus" />
            Создать
          </Button>
        )}
      </div>

      <SharedAlertRules />
      <div className="filter-bar">
        <div className="filter-bar__row">
          <div className="input-icon">
            <Icon name="search" />
            <input className="input" placeholder="Имя, метрика…" title="Поиск по имени профиля и именам его метрик" value={searchInput} onChange={(e) => setSearchInput(e.target.value)} />
          </div>
          <select className="select" title="Сортировка списка профилей" value={sortBy} onChange={(e) => setSortBy(e.target.value as SortBy)}>
            <option value="name">сорт.: имя</option>
            <option value="priority">сорт.: приоритет</option>
          </select>
          <button className="btn btn-ghost btn-sm" title={sortDir === 'asc' ? 'По возрастанию — нажмите для сортировки по убыванию' : 'По убыванию — нажмите для сортировки по возрастанию'} onClick={() => setSortDir(sortDir === 'asc' ? 'desc' : 'asc')}>
            <Icon name={sortDir === 'asc' ? 'arrow-up' : 'arrow-down'} />
          </button>
        </div>
      </div>

      {profiles === null ? (
        <p className="stamp">Загрузка…</p>
      ) : profiles.length === 0 ? (
        <EmptyStateBlock icon="sliders" text="Профилей не найдено — измените фильтры или сбросьте их" />
      ) : (
        <div className="grid-cards">
          {profiles.map((p) => (
            <div className="card card-pad" key={p.profile.name}>
              <div className="config-card__title">{p.profile.name}</div>
              <div className="config-card__sub">
                приоритет {p.profile.priority} · метрик: {Object.keys(p.metrics?.poll ?? {}).length} · тревог: {(p.alerts ?? []).length}
              </div>
              {syncStatus[p.profile.name] && <div className="config-card__row">{syncStatus[p.profile.name]}</div>}
              <div className="config-card__actions">
                {canWriteProfiles && (
                  <>
                    <Button variant="ghost" iconOnly small title="Изменить" onClick={() => openEdit(p)}>
                      <Icon name="pencil" />
                    </Button>
                    <Button variant="ghost" iconOnly small title="Клонировать — создать новый профиль с этими же настройками под другим именем" onClick={() => openClone(p)}>
                      <Icon name="copy" />
                    </Button>
                    <Button
                      variant="ghost"
                      iconOnly
                      small
                      title="Синхр. устройства — сбросить ручные override метрик у всех устройств на этом профиле к настройкам профиля"
                      onClick={() => handleSyncDevices(p)}
                    >
                      <Icon name="refresh" />
                    </Button>
                    <Button variant="danger" iconOnly small title="Удалить" onClick={() => handleDelete(p)}>
                      <Icon name="trash" />
                    </Button>
                  </>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
      {data && <Pagination page={page} pageSize={PAGE_SIZE} total={data.total} itemCount={profiles?.length ?? 0} onPageChange={setPage} />}

      {canWriteProfiles && <Modal
        open={editing !== null}
        wide
        title={isNew ? (cloneSource ? `Новый профиль (копия «${cloneSource}»)` : 'Новый профиль') : `Редактировать профиль: ${editing?.name ?? ''}`}
        onClose={() => setEditing(null)}
        footer={
          <>
            <Button variant="ghost" title="Закрыть без сохранения изменений" onClick={() => setEditing(null)}>
              Отмена
            </Button>
            <Button variant="primary" title="Сохранить профиль — upsert по имени, применяется на следующем hot-reload" onClick={handleSave}>
              Сохранить профиль
            </Button>
          </>
        }
      >
        {editing && (
          <div className="util-col gap-4">
            {error && <div className="form-error">{error}</div>}
            <div className="tabs">
              <button className={tab === 'main' ? 'active' : ''} title="Имя, приоритет и match-выражение профиля" onClick={() => setTab('main')}>
                Основное
              </button>
              <button className={tab === 'metrics' ? 'active' : ''} title="Метрики, которые опрашиваются у устройств на этом профиле" onClick={() => setTab('metrics')}>
                Метрики ({editing.metrics.length})
              </button>
              <button className={tab === 'alerts' ? 'active' : ''} title="Правила тревог, привязанные к этому профилю" onClick={() => setTab('alerts')}>
                Тревоги ({editing.alerts.length})
              </button>
              <button className={tab === 'syslog' ? 'active' : ''} title="Syslog-биндинги — какие push-сообщения от устройств этот профиль распознаёт" onClick={() => setTab('syslog')}>
                Syslog ({editing.syslog.length})
              </button>
              <button className={tab === 'traps' ? 'active' : ''} title="SNMP Trap-биндинги — какие push-трапы от устройств этот профиль распознаёт" onClick={() => setTab('traps')}>
                Trap ({editing.traps.length})
              </button>
              <button className={tab === 'serviceChecks' ? 'active' : ''} title="Service-чеки — TCP/HTTP(S)/SSH reachability, опрашиваются по расписанию" onClick={() => setTab('serviceChecks')}>
                Service Check ({editing.serviceChecks.checks.length})
              </button>
            </div>

            {tab === 'main' && (
              <div className="util-col gap-2">
                <Field label="Имя профиля" hint={isNew ? 'уникальное имя — используется в маршрутизации и ссылках на профиль' : 'нельзя изменить у существующего профиля — создайте клон, если нужно другое имя'}>
                  <input className="input" value={editing.name} onChange={(e) => setEditing({ ...editing, name: e.target.value })} disabled={!isNew} />
                </Field>
                <Field label="Приоритет" hint="выше — проверяется раньше">
                  <input className="input" type="number" value={editing.priority} onChange={(e) => setEditing({ ...editing, priority: Number(e.target.value) || 0 })} />
                </Field>
                <Field label="Match-выражение (Rhai)" hint="область видимости facts/metrics, например: metrics.vendor.contains(&quot;Cisco&quot;)">
                  <textarea
                    className="input textarea mono"
                    style={{ width: '100%' }}
                    rows={4}
                    value={editing.matchExpression}
                    onChange={(e) => setEditing({ ...editing, matchExpression: e.target.value })}
                  />
                </Field>
              </div>
            )}

            {tab === 'metrics' && (
              <div className="util-col gap-3">
                <p className="stamp">
                  Имя, OID и (опционально) своя частота опроса; если интервал не задан — используется общий по умолчанию (Настройки — периодичность опроса).
                </p>
                {editing.metrics.map((m, idx) => (
                  <MetricRow key={idx} metric={m} onChange={(patch) => updateMetric(idx, patch)} onRemove={() => setEditing({ ...editing, metrics: editing.metrics.filter((_, i) => i !== idx) })} />
                ))}
                <div className="filter-bar__row">
                  <Button variant="ghost" small title="Добавить ещё одну метрику к профилю" onClick={() => setEditing({ ...editing, metrics: [...editing.metrics, emptyMetric()] })}>
                    <Icon name="plus" />
                    Метрика
                  </Button>
                  <span className="spacer" />
                  <Button variant="ghost" small title="Экспортировать список метрик в JSON" onClick={exportMetrics} disabled={editing.metrics.length === 0}>
                    <Icon name="download" />
                    Экспорт
                  </Button>
                  <Button variant="ghost" small title="Импортировать метрики из JSON — по имени перезапишет уже заданные" onClick={() => metricsFileInputRef.current?.click()}>
                    <Icon name="external" />
                    Импорт
                  </Button>
                  <input ref={metricsFileInputRef} type="file" accept="application/json" style={{ display: 'none' }} onChange={handleImportMetrics} />
                </div>
              </div>
            )}

            {tab === 'alerts' && (
              <div className="util-col gap-3">
                {editing.alerts.map((a, idx) => (
                  <AlertRow
                    key={idx}
                    alert={a}
                    tableMetricNames={editing.metrics.filter((m) => m.metricKind === 'table').map((m) => m.name)}
                    onChange={(patch) => updateAlert(idx, patch)}
                    onRemove={() => setEditing({ ...editing, alerts: editing.alerts.filter((_, i) => i !== idx) })}
                  />
                ))}
                <div className="filter-bar__row">
                  <Button variant="ghost" small title="Добавить ещё одно правило тревоги к профилю" onClick={() => setEditing({ ...editing, alerts: [...editing.alerts, emptyAlert()] })}>
                    <Icon name="plus" />
                    Тревога
                  </Button>
                  <span className="spacer" />
                  <Button variant="ghost" small title="Экспортировать список тревог в JSON" onClick={exportAlerts} disabled={editing.alerts.length === 0}>
                    <Icon name="download" />
                    Экспорт
                  </Button>
                  <Button variant="ghost" small title="Импортировать тревоги из JSON — по имени перезапишет уже заданные" onClick={() => alertsFileInputRef.current?.click()}>
                    <Icon name="external" />
                    Импорт
                  </Button>
                  <input ref={alertsFileInputRef} type="file" accept="application/json" style={{ display: 'none' }} onChange={handleImportAlerts} />
                </div>
              </div>
            )}

            {tab === 'syslog' && (
              <div className="util-col gap-3">
                <p className="stamp">
                  Каждый биндинг — один или несколько форматов syslog-сообщения (regex по телу сообщения, без заголовка). Именованные capture-группы
                  (<code>(?P&lt;имя&gt;...)</code>) становятся полями строки <code>metrics.syslog_&lt;имя биндинга&gt;</code>; severity/facility/hostname добавляются
                  на строку автоматически, независимо от паттерна.
                </p>
                {editing.syslog.map((b, idx) => (
                  <SyslogBindingRow key={idx} binding={b} onChange={(patch) => updateSyslogBinding(idx, patch)} onRemove={() => setEditing({ ...editing, syslog: editing.syslog.filter((_, i) => i !== idx) })} />
                ))}
                <div className="filter-bar__row">
                  <Button variant="ghost" small title="Добавить ещё один syslog-биндинг к профилю" onClick={() => setEditing({ ...editing, syslog: [...editing.syslog, emptySyslogBinding()] })}>
                    <Icon name="plus" />
                    Биндинг
                  </Button>
                  <span className="spacer" />
                  <Button variant="ghost" small title="Экспортировать список syslog-биндингов в JSON" onClick={exportSyslog} disabled={editing.syslog.length === 0}>
                    <Icon name="download" />
                    Экспорт
                  </Button>
                  <Button variant="ghost" small title="Импортировать syslog-биндинги из JSON — по имени перезапишет уже заданные" onClick={() => syslogFileInputRef.current?.click()}>
                    <Icon name="external" />
                    Импорт
                  </Button>
                  <input ref={syslogFileInputRef} type="file" accept="application/json" style={{ display: 'none' }} onChange={handleImportSyslog} />
                </div>
              </div>
            )}

            {tab === 'traps' && (
              <div className="util-col gap-3">
                <p className="stamp">
                  Каждый биндинг — один или несколько OID SNMP-трапов, которые устройства на этом профиле должны присылать. Варбинды (varbind OID → имя поля)
                  становятся полями строки <code>metrics.trap_&lt;имя биндинга&gt;</code> — только реальные данные из пакета, без синтетических значений.
                </p>
                {editing.traps.map((b, idx) => (
                  <TrapBindingRow key={idx} binding={b} onChange={(patch) => updateTrapBinding(idx, patch)} onRemove={() => setEditing({ ...editing, traps: editing.traps.filter((_, i) => i !== idx) })} />
                ))}
                <div className="filter-bar__row">
                  <Button variant="ghost" small title="Добавить ещё один trap-биндинг к профилю" onClick={() => setEditing({ ...editing, traps: [...editing.traps, emptyTrapBinding()] })}>
                    <Icon name="plus" />
                    Биндинг
                  </Button>
                  <span className="spacer" />
                  <Button variant="ghost" small title="Экспортировать список trap-биндингов в JSON" onClick={exportTraps} disabled={editing.traps.length === 0}>
                    <Icon name="download" />
                    Экспорт
                  </Button>
                  <Button variant="ghost" small title="Импортировать trap-биндинги из JSON — по имени перезапишет уже заданные" onClick={() => trapsFileInputRef.current?.click()}>
                    <Icon name="external" />
                    Импорт
                  </Button>
                  <input ref={trapsFileInputRef} type="file" accept="application/json" style={{ display: 'none' }} onChange={handleImportTraps} />
                </div>
              </div>
            )}

            {tab === 'serviceChecks' && (
              <div className="util-col gap-3">
                <p className="stamp">
                  TCP/HTTP(S)/SSH reachability-проверки — одно общее расписание на весь список, результат — одна синтетическая табличная метрика
                  <code> metrics.service_checks</code> (строка на чек, индекс — имя чека).
                </p>
                <div className="form-grid">
                  <Field label="Частота опроса" hint="по умолчанию — poll_intervals.service_check_secs; период/календарь — своё расписание для всех чеков этого профиля">
                    <select className="select" value={editing.serviceChecks.scheduleMode} onChange={(e) => setEditing({ ...editing, serviceChecks: { ...editing.serviceChecks, scheduleMode: e.target.value as ScheduleMode } })}>
                      <option value="default">по умолчанию</option>
                      <option value="periodic">период</option>
                      <option value="calendar">по календарю</option>
                    </select>
                  </Field>
                  <Field label="Хранить историю, сек" hint="пусто = навсегда">
                    <input className="input" type="number" min={1} value={editing.serviceChecks.retentionSecs} onChange={(e) => setEditing({ ...editing, serviceChecks: { ...editing.serviceChecks, retentionSecs: e.target.value } })} />
                  </Field>
                </div>
                {editing.serviceChecks.scheduleMode === 'periodic' && (
                  <Field label="Интервал, сек" hint="как часто опрашивается весь список чеков">
                    <input className="input" type="number" min={1} value={editing.serviceChecks.intervalSecs} onChange={(e) => setEditing({ ...editing, serviceChecks: { ...editing.serviceChecks, intervalSecs: e.target.value } })} />
                  </Field>
                )}
                {editing.serviceChecks.scheduleMode === 'calendar' && (
                  <div className="form-grid">
                    <Field label="Месяцы" hint="пусто = каждый">
                      <input className="input" placeholder="1, 6" value={editing.serviceChecks.months} onChange={(e) => setEditing({ ...editing, serviceChecks: { ...editing.serviceChecks, months: e.target.value } })} />
                    </Field>
                    <Field label="Даты" hint="пусто = каждый день">
                      <input className="input" placeholder="1, 15" value={editing.serviceChecks.days} onChange={(e) => setEditing({ ...editing, serviceChecks: { ...editing.serviceChecks, days: e.target.value } })} />
                    </Field>
                    <Field label="Время" hint="ЧЧ:ММ:СС">
                      <input className="input" placeholder="03:00:00" value={editing.serviceChecks.time} onChange={(e) => setEditing({ ...editing, serviceChecks: { ...editing.serviceChecks, time: e.target.value } })} />
                    </Field>
                  </div>
                )}

                {editing.serviceChecks.checks.map((c, idx) => (
                  <ServiceCheckRow key={idx} check={c} onChange={(patch) => updateServiceCheck(idx, patch)} onRemove={() => setEditing({ ...editing, serviceChecks: { ...editing.serviceChecks, checks: editing.serviceChecks.checks.filter((_, i) => i !== idx) } })} />
                ))}
                <div className="filter-bar__row">
                  <Button variant="ghost" small title="Добавить ещё один service-чек к профилю" onClick={() => setEditing({ ...editing, serviceChecks: { ...editing.serviceChecks, checks: [...editing.serviceChecks.checks, emptyServiceCheck()] } })}>
                    <Icon name="plus" />
                    Чек
                  </Button>
                  <span className="spacer" />
                  <Button variant="ghost" small title="Экспортировать список service-чеков в JSON" onClick={exportServiceChecks} disabled={editing.serviceChecks.checks.length === 0}>
                    <Icon name="download" />
                    Экспорт
                  </Button>
                  <Button variant="ghost" small title="Импортировать service-чеки из JSON — по имени перезапишет уже заданные" onClick={() => serviceChecksFileInputRef.current?.click()}>
                    <Icon name="external" />
                    Импорт
                  </Button>
                  <input ref={serviceChecksFileInputRef} type="file" accept="application/json" style={{ display: 'none' }} onChange={handleImportServiceChecks} />
                </div>
              </div>
            )}
          </div>
        )}
      </Modal>}
    </div>
  )
}

function MetricRow({ metric, onChange, onRemove }: { metric: EditingMetric; onChange: (patch: Partial<EditingMetric>) => void; onRemove: () => void }) {
  return (
    <div className="card card-pad">
      <div className="card-header">
        <strong>Метрика</strong>
        <div style={{ display: 'flex', alignItems: 'center', gap: '.75rem' }}>
          <Switch
            checked={metric.enabled}
            onChange={(v) => onChange({ enabled: v })}
            title="Отключает опрос этой метрики для всего профиля — устройства без ручного override подхватят это сразу; устройства с override нужно синхронизировать (кнопка «Синхр.») отдельно"
            label={['метрика активна', 'метрика выключена']}
          />
          <Button variant="ghost" iconOnly small title="Удалить" onClick={onRemove}>
            <Icon name="x" />
          </Button>
        </div>
      </div>
      <div className="form-grid">
        <Field label="Имя метрики" hint="ключ метрики — на него ссылаются {metrics.имя} в сообщениях тревог и Rhai-выражениях профиля">
          <input className="input mono" value={metric.name} onChange={(e) => onChange({ name: e.target.value })} />
        </Field>
        <Field label="Источник" hint="snmp — get/walk по OID (как раньше); ssh — значение метрики это stdout команды, выполненной по SSH-сессии устройства (Device.ssh_credentials). Всегда скаляр, без табличной формы и производных метрик">
          <select className="select" value={metric.source} onChange={(e) => onChange({ source: e.target.value as MetricSource })}>
            <option value="snmp">snmp</option>
            <option value="ssh">ssh (команда)</option>
          </select>
        </Field>
      </div>
      <div className="form-grid">
        {metric.source === 'snmp' ? (
          <OidTypeAndValueFields oid={metric.oid} kind={metric.metricKind} onChange={(next) => onChange({ oid: next.oid, metricKind: next.kind })} />
        ) : (
          <Field label="Команда" hint="выполняется как есть в exec-сессии SSH, без экранирования этим кодом сверх того, что делает сам SSH-сервер (обычно — через логин-шелл пользователя)">
            <textarea className="input textarea mono" style={{ width: '100%' }} rows={2} value={metric.command} onChange={(e) => onChange({ command: e.target.value })} />
          </Field>
        )}
        <Field label="Частота опроса" hint="по умолчанию — общий интервал из Настроек; период/календарь — своё расписание для этой метрики">
          <select className="select" value={metric.scheduleMode} onChange={(e) => onChange({ scheduleMode: e.target.value as ScheduleMode })}>
            <option value="default">по умолчанию</option>
            <option value="periodic">период</option>
            <option value="calendar">по календарю</option>
          </select>
        </Field>
        <Field label="Хранить историю, сек" hint="пусто = навсегда">
          <input className="input" type="number" min={1} value={metric.retentionSecs} onChange={(e) => onChange({ retentionSecs: e.target.value })} />
        </Field>
        {metric.source === 'snmp' && metric.metricKind === 'scalar' && (
          <Field
            label="Производная метрика"
            hint="из сырого счётчика вычисляется rate (изменение/сек) или delta (изменение за тик) и сохраняется как отдельная метрика «имя_rate»/«имя_delta» — доступна в Rhai-выражениях так же, как любая обычная метрика"
          >
            <select className="select" value={metric.deriveMode} onChange={(e) => onChange({ deriveMode: e.target.value as EditingMetric['deriveMode'] })}>
              <option value="none">нет</option>
              <option value="rate">rate — изменение в секунду</option>
              <option value="delta">delta — изменение за тик, без нормализации по времени</option>
            </select>
          </Field>
        )}
      </div>
      {metric.source === 'snmp' && metric.metricKind === 'table' && (
        <TableColumnsFields columnsMode={metric.columnsMode} columns={metric.columns} onChange={(next) => onChange({ columnsMode: next.columnsMode, columns: next.columns })} />
      )}
      {metric.scheduleMode === 'periodic' && (
        <Field label="Интервал, сек" hint="как часто опрашивается именно эта метрика, вместо общего интервала по умолчанию">
          <input className="input" type="number" min={1} value={metric.intervalSecs} onChange={(e) => onChange({ intervalSecs: e.target.value })} />
        </Field>
      )}
      {metric.scheduleMode === 'calendar' && (
        <div className="form-grid">
          <Field label="Месяцы" hint="пусто = каждый">
            <input className="input" placeholder="1, 6" value={metric.months} onChange={(e) => onChange({ months: e.target.value })} />
          </Field>
          <Field label="Даты" hint="пусто = каждый день">
            <input className="input" placeholder="1, 15" value={metric.days} onChange={(e) => onChange({ days: e.target.value })} />
          </Field>
          <Field label="Время" hint="ЧЧ:ММ:СС">
            <input className="input" placeholder="03:00:00" value={metric.time} onChange={(e) => onChange({ time: e.target.value })} />
          </Field>
        </div>
      )}
      <div className="wrap-row" style={{ marginTop: '.5rem' }}>
        <label className="checkbox-row" title="Последнее успешное значение не удаляется при очистке истории, даже если срок хранения истёк">
          <input type="checkbox" checked={metric.keepSuccess} onChange={(e) => onChange({ keepSuccess: e.target.checked })} /> хранить крайнюю удачную всегда
        </label>
        <label className="checkbox-row" title="Самая последняя запись (даже неуспешная попытка) не удаляется при очистке истории">
          <input type="checkbox" checked={metric.keepAttempt} onChange={(e) => onChange({ keepAttempt: e.target.checked })} /> хранить самую крайнюю запись всегда
        </label>
      </div>
    </div>
  )
}

export function AlertRow({
  alert,
  shared = false,
  tableMetricNames,
  onChange,
  onRemove,
}: {
  alert: AlertRule
  shared?: boolean
  tableMetricNames: string[]
  onChange: (patch: Partial<AlertRule>) => void
  onRemove: () => void
}) {
  return (
    <div className="card card-pad">
      <AlertPolicyEditor shared={shared} value={alert.policy} onChange={policy => onChange({ policy })} />
      <div className="card-header">
        <strong>Тревога</strong>
        <div style={{ display: 'flex', alignItems: 'center', gap: '.75rem' }}>
          <Switch
            checked={alert.enabled}
            onChange={(v) => onChange({ enabled: v })}
            title="Выключено — правило не участвует в обработке тревог, но остаётся в профиле для последующего включения"
            label={['правило активно', 'правило выключено']}
          />
          <Button variant="ghost" iconOnly small title="Удалить" onClick={onRemove}>
            <Icon name="x" />
          </Button>
        </div>
      </div>
      <div className="form-grid">
        <Field label="Имя" hint="уникальное в рамках профиля имя правила — отображается в списке тревог">
          <input className="input" value={alert.name} onChange={(e) => onChange({ name: e.target.value })} />
        </Field>
        <Field label="Уровень" hint="серьёзность: info — информационно, warning — требует внимания, critical — требует немедленной реакции">
          <select className="select" value={alert.level} onChange={(e) => onChange({ level: e.target.value })}>
            <option value="info">info</option>
            <option value="warning">warning</option>
            <option value="critical">critical</option>
          </select>
        </Field>
      </div>
      <div className="form-grid">
        <Field
          label="Табличная метрика (тревога по строке)"
          hint="имя табличной метрики профиля (см. вкладку «Метрики»). Если указано — тревога создаётся отдельно для каждой строки этой таблицы, и во всех выражениях ниже и в сообщении становится доступна переменная row. Пусто — одно правило на устройство целиком, без переменной row"
        >
          <select
            className="select mono"
            value={alert.row_metric ?? ''}
            onChange={(e) => onChange({ row_metric: e.target.value || null })}
          >
            <option value="">— обычное правило на устройство —</option>
            {tableMetricNames.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
            {alert.row_metric && !tableMetricNames.includes(alert.row_metric) && (
              <option value={alert.row_metric}>{alert.row_metric} (метрики с таким именем и табличным типом сейчас нет в профиле)</option>
            )}
          </select>
        </Field>
        {!!alert.row_metric && (
          <Field
            label="Ключ идентичности строки (Rhai)"
            hint="выражение над row (и facts/metrics), определяющее, какие строки считать одной и той же тревогой между опросами. Пусто = row.index — собственный SNMP-индекс строки"
          >
            <input
              className="input mono"
              placeholder="пусто = row.index"
              value={alert.row_key_expression ?? ''}
              onChange={(e) => onChange({ row_key_expression: e.target.value || null })}
            />
          </Field>
        )}
      </div>
      <Field
        label="Условие активации (Rhai)"
        hint={alert.row_metric ? 'область видимости facts/metrics/row (одна строка табличной метрики), например: row.ifOperStatus == 2' : 'область видимости facts/metrics, например: metrics.cpu_load > 90'}
      >
        <textarea className="input textarea mono" style={{ width: '100%' }} rows={2} value={alert.expression} onChange={(e) => onChange({ expression: e.target.value })} />
      </Field>
      <Field label="Условие деактивации (Rhai)" hint="пусто = отрицание условия активации — гистерезис недоступен">
        <textarea className="input textarea mono" style={{ width: '100%' }} rows={2} value={alert.deactivation_expression ?? ''} onChange={(e) => onChange({ deactivation_expression: e.target.value })} />
      </Field>
      <Field label="Facts-выражение (Rhai)" hint='снимок данных на момент активации, например: #{ip: facts.ip, cpu: metrics.cpu_load}; пусто = не сохранять'>
        <textarea className="input textarea mono" style={{ width: '100%' }} rows={2} value={alert.facts_expression ?? ''} onChange={(e) => onChange({ facts_expression: e.target.value })} />
      </Field>
      <Field label="Сообщение" hint={alert.row_metric ? 'поддерживает {metrics.имя}, {facts.ip} и {row.имя} (например {row.ifDescr})' : 'поддерживает {metrics.имя} и {facts.ip}'}>
        <input className="input" value={alert.message} onChange={(e) => onChange({ message: e.target.value })} />
      </Field>
      <Field label="Держать условие деактивации истинным столько секунд перед снятием" hint="анти-флаппинг: тревога снимается только после того, как условие деактивации остаётся истинным непрерывно это время. Действует и для тревог по строке, включая закрытие по причине «строка пропала» (см. статус «Утеряна» в списке тревог)">
        <input className="input" type="number" min={0} value={alert.clear_after_seconds ?? 0} onChange={(e) => onChange({ clear_after_seconds: Number(e.target.value) || 0 })} />
      </Field>
      <Field label="Задержка активации, секунд" hint="краткий выброс не открывает тревогу">
        <input className="input" type="number" min={0} value={alert.activate_after_seconds ?? 0} onChange={(e) => onChange({ activate_after_seconds: Number(e.target.value) || 0 })} />
      </Field>
      <Field label="Окно flapping, секунд" hint="окно для подсчёта переходов между зонами">
        <input className="input" type="number" min={0} value={alert.flap_window_seconds ?? 0} onChange={(e) => onChange({ flap_window_seconds: Number(e.target.value) || 0 })} />
      </Field>
      <Field label="Порог flapping, переключений" hint="при достижении уведомления подавляются">
        <input className="input" type="number" min={0} value={alert.flap_threshold ?? 0} onChange={(e) => onChange({ flap_threshold: Number(e.target.value) || 0 })} />
      </Field>
    </div>
  )
}

function SyslogBindingRow({ binding, onChange, onRemove }: { binding: EditingSyslogBinding; onChange: (patch: Partial<EditingSyslogBinding>) => void; onRemove: () => void }) {
  function updateVariant(idx: number, patch: Partial<EditingSyslogVariant>) {
    const variants = binding.variants.slice()
    variants[idx] = { ...variants[idx], ...patch }
    onChange({ variants })
  }

  return (
    <div className="card card-pad">
      <div className="card-header">
        <strong>Syslog-биндинг</strong>
        <Button variant="ghost" iconOnly small title="Удалить" onClick={onRemove}>
          <Icon name="x" />
        </Button>
      </div>
      <div className="form-grid">
        <Field label="Имя биндинга" hint="ключ биндинга — метрика на устройстве появится как metrics.syslog_<имя>">
          <input className="input mono" value={binding.name} onChange={(e) => onChange({ name: e.target.value })} />
        </Field>
        <Field label="TTL строки, сек" hint="сколько строка может не обновляться ни одним вариантом, прежде чем считается «Утеряна». Пусто = никогда не устаревает по этой причине">
          <input className="input" type="number" min={0} value={binding.ttlSecs} onChange={(e) => onChange({ ttlSecs: e.target.value })} />
        </Field>
        <Field label="Хранить историю, сек" hint="пусто = навсегда">
          <input className="input" type="number" min={1} value={binding.historyRetentionSecs} onChange={(e) => onChange({ historyRetentionSecs: e.target.value })} />
        </Field>
      </div>

      <div className="util-col gap-2" style={{ marginTop: '.5rem' }}>
        {binding.variants.map((v, idx) => (
          <div key={idx} className="card card-pad" style={{ background: 'var(--surface-2, transparent)' }}>
            <div className="card-header">
              <strong>Вариант</strong>
              <Button
                variant="ghost"
                iconOnly
                small
                title="Удалить вариант"
                onClick={() => onChange({ variants: binding.variants.filter((_, i) => i !== idx) })}
                disabled={binding.variants.length <= 1}
              >
                <Icon name="x" />
              </Button>
            </div>
            <Field label="Regex-паттерн" hint="проверяется против тела сообщения (без заголовка). Именованные группы (?P<имя>...) становятся полями строки">
              <input className="input mono" value={v.pattern} onChange={(e) => updateVariant(idx, { pattern: e.target.value })} />
            </Field>
            <div className="form-grid">
              <Field label="Severity ≤" hint="0=emerg .. 7=debug, меньше — серьёзнее. Пусто = любой">
                <input className="input" type="number" min={0} max={7} value={v.maxSeverity} onChange={(e) => updateVariant(idx, { maxSeverity: e.target.value })} />
              </Field>
              <Field label="Facility =" hint="0=kernel, 3=daemon, 16-23=local0-7 и т.п. Пусто = любой">
                <input className="input" type="number" min={0} max={23} value={v.facility} onChange={(e) => updateVariant(idx, { facility: e.target.value })} />
              </Field>
            </div>
            <Field label="Ключ идентичности строки (Rhai)" hint="область видимости {facts, fields} — fields это capture-группы этого варианта плюс автополя severity/facility/hostname. Пусто = singleton, без per-entity identity">
              <input className="input mono" placeholder="например: fields.ifName" value={v.keyExpression} onChange={(e) => updateVariant(idx, { keyExpression: e.target.value })} />
            </Field>
          </div>
        ))}
        <Button variant="ghost" small title="Добавить ещё один вариант формата сообщения к этому биндингу" onClick={() => onChange({ variants: [...binding.variants, emptySyslogVariant()] })}>
          <Icon name="plus" />
          Вариант
        </Button>
      </div>
    </div>
  )
}

function TrapBindingRow({ binding, onChange, onRemove }: { binding: EditingTrapBinding; onChange: (patch: Partial<EditingTrapBinding>) => void; onRemove: () => void }) {
  function updateVariant(idx: number, patch: Partial<EditingTrapVariant>) {
    const variants = binding.variants.slice()
    variants[idx] = { ...variants[idx], ...patch }
    onChange({ variants })
  }

  return (
    <div className="card card-pad">
      <div className="card-header">
        <strong>Trap-биндинг</strong>
        <Button variant="ghost" iconOnly small title="Удалить" onClick={onRemove}>
          <Icon name="x" />
        </Button>
      </div>
      <div className="form-grid">
        <Field label="Имя биндинга" hint="ключ биндинга — метрика на устройстве появится как metrics.trap_<имя>">
          <input className="input mono" value={binding.name} onChange={(e) => onChange({ name: e.target.value })} />
        </Field>
        <Field label="TTL строки, сек" hint="сколько строка может не обновляться ни одним вариантом, прежде чем считается «Утеряна». Пусто = никогда не устаревает по этой причине">
          <input className="input" type="number" min={0} value={binding.ttlSecs} onChange={(e) => onChange({ ttlSecs: e.target.value })} />
        </Field>
        <Field label="Хранить историю, сек" hint="пусто = навсегда">
          <input className="input" type="number" min={1} value={binding.historyRetentionSecs} onChange={(e) => onChange({ historyRetentionSecs: e.target.value })} />
        </Field>
      </div>

      <div className="util-col gap-2" style={{ marginTop: '.5rem' }}>
        {binding.variants.map((v, idx) => (
          <div key={idx} className="card card-pad" style={{ background: 'var(--surface-2, transparent)' }}>
            <div className="card-header">
              <strong>Вариант</strong>
              <Button
                variant="ghost"
                iconOnly
                small
                title="Удалить вариант"
                onClick={() => onChange({ variants: binding.variants.filter((_, i) => i !== idx) })}
                disabled={binding.variants.length <= 1}
              >
                <Icon name="x" />
              </Button>
            </div>
            <Field label="Trap OID" hint="сравнивается с snmpTrapOID.0 (v2c/v3) или нормализованным enterprise+generic+specific (v1)">
              <input className="input mono" value={v.trapOid} onChange={(e) => updateVariant(idx, { trapOid: e.target.value })} />
            </Field>
            <KvEditor
              label="Варбинды"
              hint="имя поля на строке → varbind OID (как в пакете), откуда брать значение — только реальные данные устройства, без синтетических значений"
              keyPlaceholder="имя поля, напр. if_index"
              valuePlaceholder="OID варбинда, напр. 1.3.6.1.2.1.2.2.1.1"
              entries={v.varbinds}
              onChange={(entries) => updateVariant(idx, { varbinds: entries })}
            />
            <Field label="Ключ идентичности строки (Rhai)" hint="область видимости {facts, varbinds}. Пусто = singleton, без per-entity identity">
              <input className="input mono" placeholder="например: varbinds.if_index" value={v.keyExpression} onChange={(e) => updateVariant(idx, { keyExpression: e.target.value })} />
            </Field>
          </div>
        ))}
        <Button variant="ghost" small title="Добавить ещё один вариант (OID) к этому биндингу" onClick={() => onChange({ variants: [...binding.variants, emptyTrapVariant()] })}>
          <Icon name="plus" />
          Вариант
        </Button>
      </div>
    </div>
  )
}

function ServiceCheckRow({ check, onChange, onRemove }: { check: EditingServiceCheck; onChange: (patch: Partial<EditingServiceCheck>) => void; onRemove: () => void }) {
  const isHttp = check.protocol === 'http' || check.protocol === 'https'
  return (
    <div className="card card-pad">
      <div className="card-header">
        <strong>Service-чек</strong>
        <div style={{ display: 'flex', alignItems: 'center', gap: '.75rem' }}>
          <Switch checked={check.enabled} onChange={(v) => onChange({ enabled: v })} title="Отключает этот чек — он выпадает из общей табличной метрики, но остаётся в профиле" label={['чек активен', 'чек выключен']} />
          <Button variant="ghost" iconOnly small title="Удалить" onClick={onRemove}>
            <Icon name="x" />
          </Button>
        </div>
      </div>
      <div className="form-grid">
        <Field label="Имя" hint="ключ чека — индекс строки в metrics.service_checks, должен быть уникален в профиле">
          <input className="input mono" value={check.name} onChange={(e) => onChange({ name: e.target.value })} />
        </Field>
        <Field label="Протокол" hint="tcp — просто connect; http(s) — запрос с опциональной проверкой статуса/тела; ssh — connect+auth (без выполнения команды)">
          <select className="select" value={check.protocol} onChange={(e) => onChange({ protocol: e.target.value as ServiceCheckProtocol })}>
            <option value="tcp">tcp</option>
            <option value="http">http</option>
            <option value="https">https</option>
            <option value="ssh">ssh</option>
          </select>
        </Field>
      </div>
      <div className="form-grid">
        <Field label="Target" hint="хост/IP для проверки — пусто = собственный IP устройства (facts.ip)">
          <input className="input mono" placeholder="пусто = IP устройства" value={check.target} onChange={(e) => onChange({ target: e.target.value })} />
        </Field>
        <Field label="Порт" hint="TCP-порт, на который идёт проверка">
          <input className="input" type="number" min={1} max={65535} value={check.port} onChange={(e) => onChange({ port: e.target.value })} />
        </Field>
        <Field label="Таймаут, мс" hint="пусто = дефолт хендлера (2с)">
          <input className="input" type="number" min={1} value={check.timeoutMs} onChange={(e) => onChange({ timeoutMs: e.target.value })} />
        </Field>
      </div>
      {isHttp && (
        <div className="form-grid">
          <Field label="Path" hint="пусто = &quot;/&quot;">
            <input className="input mono" placeholder="/" value={check.path} onChange={(e) => onChange({ path: e.target.value })} />
          </Field>
          <Field label="Ожидаемый статус" hint="пусто = любой 2xx считается успехом">
            <input className="input" type="number" min={100} max={599} value={check.expectedStatus} onChange={(e) => onChange({ expectedStatus: e.target.value })} />
          </Field>
          <Field label="Тело содержит" hint="пусто = тело ответа вообще не запрашивается">
            <input className="input" value={check.bodyContains} onChange={(e) => onChange({ bodyContains: e.target.value })} />
          </Field>
        </div>
      )}
    </div>
  )
}
