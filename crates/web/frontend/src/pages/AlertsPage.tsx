import { AlertDiagnostics } from '../components/AlertDiagnostics'
import { useCallback, useEffect, useRef, useState } from 'react'
import { alertCommentAttachmentUrl, alertsApi } from '../api/alerts'
import { profilesApi } from '../api/profiles'
import { ApiHttpError } from '../api/http'
import type { Alert, AlertComment, AlertLevelParam, AlertsQuery, AlertStateParam } from '../api/types'
import { Badge, type Severity } from '../components/Badge'
import { Button } from '../components/Button'
import { EmptyStateRow } from '../components/EmptyState'
import { ExportMenu } from '../components/ExportMenu'
import { Icon } from '../components/Icon'
import { renderJsonAsTable } from '../components/JsonTable'
import { Modal } from '../components/Modal'
import { Pagination } from '../components/Pagination'
import { useConfirm } from '../hooks/useConfirm'
import { useAuth } from '../hooks/useAuth'
import { useToast } from '../hooks/useToast'
import type { ExportRow } from '../utils/export'
import { fileToBase64 } from '../utils/export'
import { localToIso } from '../utils/datetime'

type SortBy = 'first_seen' | 'last_seen' | 'level' | 'name' | 'device_ip'
type SortDir = 'asc' | 'desc'

const EXPORT_PAGE_SIZE = 500
const EXPORT_MAX_PAGES = 50

async function fetchAllAlerts(query: Omit<AlertsQuery, 'page' | 'page_size'>): Promise<Alert[]> {
  const all: Alert[] = []
  for (let page = 1; page <= EXPORT_MAX_PAGES; page++) {
    const res = await alertsApi.list({ ...query, page, page_size: EXPORT_PAGE_SIZE })
    all.push(...res.items)
    if (all.length >= res.total || res.items.length === 0) break
  }
  return all
}

function alertToExportRow(a: Alert): ExportRow {
  return {
    level: a.level,
    state: a.state,
    device_ip: a.device_ip,
    name: a.name,
    row_key: a.row_key ?? '',
    message: a.message,
    first_seen: a.first_seen,
    last_seen: a.last_seen,
    cleared_at: a.cleared_at ?? '',
    closed_by: a.closed_by ?? '',
    auto_clear_reason: a.auto_clear_reason ?? '',
    flapping: a.flapping,
    suppression_reason: a.suppression_reason ?? '',
    comment_count: a.comment_count,
  }
}

const PAGE_SIZE = 50

function fmtDate(iso: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} Б`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} КБ`
  return `${(n / (1024 * 1024)).toFixed(1)} МБ`
}

function levelSeverity(level: string): Severity {
  switch (level) {
    case 'Critical':
      return 'critical'
    case 'Warning':
      return 'warning'
    default:
      return 'info'
  }
}

function useDebouncedValue<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const id = setTimeout(() => setDebounced(value), delayMs)
    return () => clearTimeout(id)
  }, [value, delayMs])
  return debounced
}

export function AlertsPage({
  onOpenProfile,
  onOpenDevice,
  openFilter,
  onOpenFilterHandled,
}: {
  onOpenProfile: (profileName: string) => void
  onOpenDevice: (ip: string) => void
  /** Set by Devices' "активные тревоги" count link (`deviceIp`) or Overview's "активные
   * тревоги" tile/panel (`onlyActive`) — pre-fills the search box and/or state filter,
   * same deep-link shape Alerts→Devices/Alerts→Profiles already use, just in the opposite
   * direction. Read via lazy initial state below (not a post-mount effect that calls
   * `setSearchInput`/`setState`) — a post-mount effect would let the very first `load()`
   * fire once with no filter before the effect applies it (an extra, briefly-visible
   * unfiltered request each time this deep-link fires; direct user report 2026-08-28).
   * Since navigating here always freshly mounts this component (different page branches
   * in `App.tsx`'s `AuthedApp`), lazy initial state already sees the correct prop value
   * on the very first render — no race. */
  openFilter?: { deviceIp?: string; onlyActive?: boolean } | null
  onOpenFilterHandled?: () => void
}) {
  const toast = useToast()
  const confirm = useConfirm()
  const { canWrite } = useAuth()
  const canWriteAlerts = canWrite('alerts')

  const [searchInput, setSearchInput] = useState(() => openFilter?.deviceIp ?? '')
  const search = useDebouncedValue(searchInput, 300)
  const [level, setLevel] = useState<AlertLevelParam | ''>('')
  const [state, setState] = useState<AlertStateParam | ''>(() => (openFilter?.onlyActive ? 'active' : ''))
  // Unbounded by default (both blank) — this filters an existing record list, not a
  // query/tail view, so defaulting to a recent window would hide older alerts
  // unexpectedly on page load. See the artifact's round-13 note (`discovery-design-
  // artifact` memory) — Logs' own date filter defaults to last-24h instead, precisely
  // because it's the opposite kind of view.
  const [sinceInput, setSinceInput] = useState('')
  const [untilInput, setUntilInput] = useState('')
  const since = localToIso(sinceInput)
  const until = localToIso(untilInput)
  const [sortBy, setSortBy] = useState<SortBy>('last_seen')
  const [sortDir, setSortDir] = useState<SortDir>('desc')
  const [page, setPage] = useState(1)
  const [data, setData] = useState<{ items: Alert[]; total: number } | null>(null)
  const [loading, setLoading] = useState(true)
  const [commentTarget, setCommentTarget] = useState<Alert | null>(null)
  // Direct user request 2026-08-28: click Facts to see it fully, auto-formatted as a
  // table when the content is recognizable (JSON/CSV/XML) — see `renderFacts`'s docs.
  const [diagnosticTarget, setDiagnosticTarget] = useState<Alert | null>(null)
  const [factsTarget, setFactsTarget] = useState<Alert | null>(null)
  // Demo-park manual-test finding #4 (2026-09-18): the "подавлена" badge had no way to see
  // *which* upstream alert caused the suppression short of looking up
  // `suppressed_by_alert_id` by hand via the API. `causeTarget` is the suppressed row the
  // operator clicked (only needed for the modal's summary line); `causeAlert` is the
  // fetched causal alert itself, `null` while loading or if it errored.
  const [causeTarget, setCauseTarget] = useState<Alert | null>(null)
  const [causeAlert, setCauseAlert] = useState<Alert | null>(null)
  const [causeLoading, setCauseLoading] = useState(false)
  const [causeError, setCauseError] = useState('')
  const [commentThread, setCommentThread] = useState<AlertComment[] | null>(null)
  const [commentDraft, setCommentDraft] = useState('')
  const [commentSending, setCommentSending] = useState(false)
  // Files staged for the next comment, before it's actually sent — 2026-08-29, direct
  // user request: "вложения к комментариям тревог: файл/изображение/видео".
  const [commentFiles, setCommentFiles] = useState<File[]>([])
  const commentFileInputRef = useRef<HTMLInputElement>(null)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [profileByRuleName, setProfileByRuleName] = useState<Map<string, string>>(new Map())
  // Auto-refresh — direct user request: this page had no live-update at all before (unlike
  // Logs/Overview, which already poll), and no way to see "how fresh is this" or force a
  // refresh. `0` = off. Defaulted to 1s originally; changed to off (audit finding 9,
  // 2026-09-20, direct user request) — auto-refresh anywhere should be something an
  // operator opts into, not a surprise background poll running from the first page load.
  const [refreshSecs, setRefreshSecs] = useState(0)

  useEffect(() => {
    profilesApi
      .list({ page_size: 1000 })
      .then((res) => {
        const map = new Map<string, string>()
        for (const p of res.items) {
          for (const rule of p.alerts ?? []) {
            map.set(rule.name, p.profile.name)
          }
        }
        setProfileByRuleName(map)
      })
      .catch(() => {})
  }, [])

  useEffect(() => {
    if (openFilter) onOpenFilterHandled?.()
    // Runs once on mount only — see `openFilter`'s docs on why the actual filter values
    // are applied via lazy initial state, not here.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Guards against an out-of-order response — same real bug (not hypothetical, found live
  // via `DevicesPage`'s identical pattern, see that page's docs) as auto-refresh polling
  // *alongside* filter/sort/page changes: an older in-flight request can resolve after a
  // newer one and overwrite fresh, correctly-filtered data with a stale result.
  const requestIdRef = useRef(0)

  const load = useCallback(async () => {
    const requestId = ++requestIdRef.current
    setLoading(true)
    try {
      const res = await alertsApi.list({
        search: search || undefined,
        level: level || undefined,
        state: state || undefined,
        since,
        until,
        sort_by: sortBy,
        sort_dir: sortDir,
        page,
        page_size: PAGE_SIZE,
      })
      if (requestId !== requestIdRef.current) return
      setData(res)
    } catch (e) {
      if (requestId !== requestIdRef.current) return
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось загрузить тревоги', true)
    } finally {
      if (requestId === requestIdRef.current) setLoading(false)
    }
  }, [search, level, state, since, until, sortBy, sortDir, page, toast])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    if (refreshSecs <= 0) return
    const id = setInterval(load, refreshSecs * 1000)
    return () => clearInterval(id)
  }, [load, refreshSecs])

  useEffect(() => {
    setPage(1)
  }, [search, level, state, since, until, sortBy, sortDir])

  useEffect(() => {
    setSelected(new Set())
  }, [data])

  function toggleSort(field: SortBy) {
    if (sortBy !== field) {
      setSortBy(field)
      setSortDir('asc')
    } else if (sortDir === 'asc') {
      setSortDir('desc')
    } else {
      setSortBy('last_seen')
      setSortDir('desc')
    }
  }

  function sortIndicator(field: SortBy) {
    if (sortBy !== field) return null
    return (
      <span className="sort-ind active">
        <Icon name={sortDir === 'asc' ? 'arrow-up' : 'arrow-down'} />
      </span>
    )
  }

  function toggleSelected(id: string) {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const activeRows = (data?.items ?? []).filter((a) => a.state === 'Active')
  const allActiveSelected = activeRows.length > 0 && activeRows.every((a) => selected.has(a.id))

  function toggleSelectAll() {
    setSelected(allActiveSelected ? new Set() : new Set(activeRows.map((a) => a.id)))
  }

  async function handleBulkClose() {
    const ids = [...selected]
    if (ids.length === 0) return
    const ok = await confirm(`Закрыть ${ids.length} тревог(и)?`, { label: 'Закрыть', icon: 'check' })
    if (!ok) return
    const results = await Promise.allSettled(ids.map((id) => alertsApi.close(id)))
    const failed = results.filter((r) => r.status === 'rejected').length
    toast(failed > 0 ? `Закрыто ${ids.length - failed} из ${ids.length}, ${failed} с ошибкой` : `Закрыто тревог: ${ids.length}`, failed > 0)
    setSelected(new Set())
    load()
  }

  async function handleClose(alert: Alert) {
    // 2026-09-17 audit finding #4: closing does not verify the underlying condition —
    // if it's still true, the very next re-evaluation tick reactivates it as a brand-new
    // incident (new id), leaving this alert's comment thread behind on the now-closed row.
    // Say that explicitly before acting, same as the bulk-close confirm above — this
    // single-alert path used to have no confirmation at all.
    const ok = await confirm(`Закрыть тревогу «${alert.name}» (${alert.device_ip})? Если условие всё ещё истинно, она тут же появится снова — уже новой записью, без связи с текущими комментариями.`, {
      label: 'Закрыть',
      icon: 'check',
      danger: false,
    })
    if (!ok) return
    try {
      await alertsApi.close(alert.id)
      toast(`Тревога «${alert.name}» закрыта`)
      load()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось закрыть тревогу', true)
    }
  }

  async function handleAcknowledge(alert: Alert) {
    try {
      if (alert.acknowledged_at) await alertsApi.unacknowledge(alert.id)
      else await alertsApi.acknowledge(alert.id)
      toast(alert.acknowledged_at ? 'Подтверждение снято' : 'Тревога подтверждена')
      load()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось изменить подтверждение', true)
    }
  }

  async function handleSnooze(alert: Alert) {
    const minutes = window.prompt('Подавлять уведомления (минут):', '60')
    if (minutes == null) return
    const duration = Number(minutes)
    if (!Number.isFinite(duration) || duration <= 0) {
      toast('Укажите положительное число минут', true)
      return
    }
    try {
      if (alert.snoozed_until && new Date(alert.snoozed_until) > new Date()) {
        await alertsApi.unsnooze(alert.id)
        toast('Временное подавление снято')
      } else {
        await alertsApi.snooze(alert.id, new Date(Date.now() + duration * 60_000).toISOString())
        toast(`Уведомления подавлены на ${duration} мин.`)
      }
      load()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось изменить подавление', true)
    }
  }

  async function handleDelete(alert: Alert) {
    const ok = await confirm(`Удалить тревогу «${alert.name}» (${alert.device_ip})? История будет потеряна безвозвратно.`, {
      label: 'Удалить',
      icon: 'trash',
    })
    if (!ok) return
    try {
      await alertsApi.delete(alert.id)
      toast('Тревога удалена')
      load()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось удалить тревогу', true)
    }
  }

  function openCause(alert: Alert) {
    if (!alert.suppressed_by_alert_id) return
    setCauseTarget(alert)
    setCauseAlert(null)
    setCauseError('')
    setCauseLoading(true)
    alertsApi
      .get(alert.suppressed_by_alert_id)
      .then((a) => setCauseAlert(a))
      .catch((e) => setCauseError(e instanceof ApiHttpError ? e.message : 'Не удалось загрузить причинную тревогу'))
      .finally(() => setCauseLoading(false))
  }

  function openComment(alert: Alert) {
    setCommentTarget(alert)
    setCommentThread(null)
    setCommentDraft('')
    setCommentFiles([])
    alertsApi
      .listComments(alert.id)
      .then(setCommentThread)
      .catch((e) => toast(e instanceof ApiHttpError ? e.message : 'Не удалось загрузить комментарии', true))
  }

  async function sendComment() {
    if (!commentTarget || !commentDraft.trim()) return
    setCommentSending(true)
    try {
      const attachments = await Promise.all(
        commentFiles.map(async (f) => ({
          filename: f.name,
          content_type: f.type || 'application/octet-stream',
          data_base64: await fileToBase64(f),
        })),
      )
      const comment = await alertsApi.addComment(commentTarget.id, commentDraft.trim(), attachments)
      setCommentThread((prev) => [...(prev ?? []), comment])
      setCommentDraft('')
      setCommentFiles([])
      load() // refreshes the table's comment-count badge
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось отправить комментарий', true)
    } finally {
      setCommentSending(false)
    }
  }

  const rows = data?.items ?? []

  return (
    <div className="util-col gap-4">
      <p className="stamp">
        Полная история тревог (устойчивое хранение в БД) — каждый цикл активации/снятия отдельная запись. Включение/выключение самого правила тревоги — в редакторе профиля.
      </p>
      <div className="filter-bar">
        <div className="filter-bar__row">
          <div className="input-icon">
            <Icon name="search" />
            <input className="input" placeholder="IP, имя, сообщение, строка…" value={searchInput} onChange={(e) => setSearchInput(e.target.value)} />
          </div>
          <select className="select" value={level} onChange={(e) => setLevel(e.target.value as AlertLevelParam | '')}>
            <option value="">все уровни</option>
            <option value="info">info</option>
            <option value="warning">warning</option>
            <option value="critical">critical</option>
          </select>
          <select className="select" value={state} onChange={(e) => setState(e.target.value as AlertStateParam | '')}>
            <option value="">все состояния</option>
            <option value="active">активные</option>
            <option value="cleared">снятые</option>
          </select>
          <span className="spacer" />
          <Button variant="ghost" iconOnly small title="Обновить сейчас" onClick={() => load()}>
            <Icon name="refresh" />
          </Button>
          <select className="select" title="Период автообновления" value={refreshSecs} onChange={(e) => setRefreshSecs(Number(e.target.value))}>
            <option value={0}>без автообновления</option>
            <option value={1}>каждую 1с</option>
            <option value={3}>каждые 3с</option>
            <option value={5}>каждые 5с</option>
            <option value={10}>каждые 10с</option>
            <option value={30}>каждые 30с</option>
          </select>
          <ExportMenu
            filenameBase="alerts"
            getRows={async () => {
              const alerts = await fetchAllAlerts({ search: search || undefined, level: level || undefined, state: state || undefined, since, until })
              return alerts.map(alertToExportRow)
            }}
          />
        </div>
        <div className="filter-bar__row">
          <label className="row-sub" htmlFor="alerts-since">
            Начало
          </label>
          <input id="alerts-since" className="input" type="datetime-local" value={sinceInput} onChange={(e) => setSinceInput(e.target.value)} />
          <span className="row-sub">—</span>
          <input className="input" type="datetime-local" value={untilInput} onChange={(e) => setUntilInput(e.target.value)} />
          {(sinceInput || untilInput) && (
            <button
              className="btn btn-ghost btn-sm"
              onClick={() => {
                setSinceInput('')
                setUntilInput('')
              }}
            >
              <Icon name="x" />
              Сбросить период
            </button>
          )}
        </div>
      </div>

      <AlertDiagnostics alert={diagnosticTarget} onClose={() => setDiagnosticTarget(null)} />
      {selected.size > 0 && (
        <div className="alert-bulk-bar" style={{ display: 'flex' }}>
          <span>Выбрано: {selected.size}</span>
          <span className="spacer" />
          <Button variant="ghost" small title="Снять выделение со всех строк" onClick={() => setSelected(new Set())}>
            Отменить выбор
          </Button>
          {canWriteAlerts && (
            <Button variant="primary" small title="Закрыть все выбранные активные тревоги" onClick={handleBulkClose}>
              <Icon name="check" />
              Закрыть выбранные
            </Button>
          )}
        </div>
      )}

      <div className="table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th style={{ width: '2rem' }}>
                <input type="checkbox" title="Выбрать все активные" checked={allActiveSelected} onChange={toggleSelectAll} disabled={activeRows.length === 0} />
              </th>
              <th className="th-sortable" onClick={() => toggleSort('level')}>
                Уровень {sortIndicator('level')}
              </th>
              <th>Состояние</th>
              <th className="th-sortable" onClick={() => toggleSort('device_ip')}>
                IP {sortIndicator('device_ip')}
              </th>
              <th className="th-sortable" onClick={() => toggleSort('name')}>
                Имя {sortIndicator('name')}
              </th>
              <th>Сообщение</th>
              <th className="th-sortable" onClick={() => toggleSort('first_seen')}>
                Начало {sortIndicator('first_seen')}
              </th>
              <th className="th-sortable" onClick={() => toggleSort('last_seen')}>
                Последнее наблюдение {sortIndicator('last_seen')}
              </th>
              <th>Закрыта</th>
              <th>Facts</th>
              <th>Комментарий</th>
              <th>Действия</th>
            </tr>
          </thead>
          <tbody>
            {loading && rows.length === 0 ? (
              <EmptyStateRow colSpan={12} icon="bell" text="Загрузка…" />
            ) : rows.length === 0 ? (
              <EmptyStateRow colSpan={12} icon="bell" text="Тревог не найдено" />
            ) : (
              rows.map((a) => {
                const isActive = a.state === 'Active'
                const ruleProfile = profileByRuleName.get(a.name)
                return (
                  <tr key={a.id}>
                    <td>{isActive && <input type="checkbox" checked={selected.has(a.id)} onChange={() => toggleSelected(a.id)} />}</td>
                    <td>
                      <Badge severity={levelSeverity(a.level)} label={a.level} />
                    </td>
                    <td>
                      {isActive ? (
                        <Badge severity="critical" label="активна" />
                      ) : a.auto_clear_reason === 'RowMissing' ? (
                        <span title="Снята автоматически — то, к чему была привязана эта тревога (строка, например порт, или метрика устройства), пропало из данных целиком, а не просто перестало соответствовать условию активации">
                          <Badge severity="warning" label="утеряна" />
                        </span>
                      ) : (
                        <Badge severity="ok" label="снята" />
                      )}
                      {a.suppressed_by_alert_id && (
                        <>
                          {' '}
                          <button
                            className="metric-name-btn"
                            title="Подавлена групповым правилом — нажмите, чтобы увидеть причинную тревогу на upstream-соседе"
                            onClick={() => openCause(a)}
                          >
                            <Badge severity="info" label="подавлена" />
                          </button>
                        </>
                      )}
                      {a.flapping && <Badge severity="warning" label="flapping — уведомление подавлено" />}
                      {a.reopened_from_alert_id && (
                        <span title={`Повторная активация — условие снова стало истинным после ручного закрытия. Комментарии к предыдущему инциденту: id ${a.reopened_from_alert_id}`}>
                          {' '}
                          <Badge severity="warning" label="повторная" />
                        </span>
                      )}
                      {a.acknowledged_at && <Badge severity="ok" label={`подтверждена${a.acknowledged_by ? `: ${a.acknowledged_by}` : ''}`} />}
                      {a.snoozed_until && new Date(a.snoozed_until) > new Date() && (
                        <Badge severity="warning" label={`уведомления до ${fmtDate(a.snoozed_until)}`} />
                      )}
                    </td>
                    <td className="mono">
                      <button className="metric-name-btn" title={`Открыть устройство ${a.device_ip}`} onClick={() => onOpenDevice(a.device_ip)}>
                        {a.device_ip}
                      </button>
                    </td>
                    <td>
                      {ruleProfile ? (
                        <button className="metric-name-btn" title={`Открыть правило в профиле «${ruleProfile}»`} onClick={() => onOpenProfile(ruleProfile)}>
                          {a.name}
                        </button>
                      ) : (
                        a.name
                      )}
                      {a.row_key != null && (
                        <span className="row-sub" title="Идентичность строки, к которой привязана эта тревога (row_key) — тревога по этому же правилу для другой строки является независимым инцидентом">
                          {' '}
                          ({a.row_key})
                        </span>
                      )}
                    </td>
                    <td>{a.message}<br /><button className="link-more" onClick={() => setDiagnosticTarget(a)}>Диагностика</button>{a.details?.response_escalated && <Badge severity="critical" label="эскалация" />}</td>
                    <td className="row-sub">{fmtDate(a.first_seen)}</td>
                    <td className="row-sub">{fmtDate(a.last_seen)}</td>
                    <td className="row-sub">
                      {fmtDate(a.cleared_at)}
                      {a.closed_by && ` — ${a.closed_by}`}
                    </td>
                    <td className="row-sub">
                      {a.facts != null ? (
                        <button className="link-more" title="Открыть facts полностью" onClick={() => setFactsTarget(a)}>
                          <Icon name="external" />
                          facts
                        </button>
                      ) : (
                        '—'
                      )}
                    </td>
                    <td className="row-sub">
                      {a.comment_count > 0 ? (
                        <button className="link-more" title="Открыть обсуждение" onClick={() => openComment(a)}>
                          <Icon name="comment" />
                          {a.comment_count}
                        </button>
                      ) : (
                        '—'
                      )}
                    </td>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      {(isActive || a.details?.policy.acknowledge_required) && canWriteAlerts && (
                        <>
                          <Button variant="ghost" iconOnly small title={a.acknowledged_at ? 'Снять подтверждение' : 'Подтвердить тревогу'} onClick={() => handleAcknowledge(a)}>
                            <Icon name="check" />
                          </Button>
                          <Button variant="ghost" iconOnly small title={a.snoozed_until && new Date(a.snoozed_until) > new Date() ? 'Снять временное подавление' : 'Временно подавить уведомления'} onClick={() => handleSnooze(a)}>
                            <Icon name="pause" />
                          </Button>
                        </>
                      )}
                      {isActive && canWriteAlerts && (
                        <Button variant="ghost" iconOnly small title="Закрыть тревогу" onClick={() => handleClose(a)}>
                          <Icon name="check" />
                        </Button>
                      )}
                      <Button variant="ghost" iconOnly small title="Комментарии" onClick={() => openComment(a)}>
                        <Icon name="comment" />
                      </Button>
                      {canWriteAlerts && (
                        <Button variant="ghost" iconOnly small title="Удалить" onClick={() => handleDelete(a)}>
                          <Icon name="trash" />
                        </Button>
                      )}
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>
      {data && <Pagination page={page} pageSize={PAGE_SIZE} total={data.total} itemCount={rows.length} onPageChange={setPage} />}

      <Modal
        open={commentTarget !== null}
        title={`Обсуждение тревоги${commentTarget ? `: ${commentTarget.name}` : ''}`}
        onClose={() => setCommentTarget(null)}
        wide
        footer={
          <Button variant="ghost" title="Закрыть окно обсуждения" onClick={() => setCommentTarget(null)}>
            Закрыть
          </Button>
        }
      >
        <div className="util-col gap-3">
          {commentThread === null ? (
            <p className="stamp">Загрузка…</p>
          ) : commentThread.length === 0 ? (
            <p className="stamp">Пока нет ни одного комментария.</p>
          ) : (
            <div className="comment-list">
              {commentThread.map((c) => (
                <div className="comment-item" key={c.id}>
                  <div className="comment-item__head">
                    <span className="comment-item__author">{c.author}</span>
                    <span className="row-sub">{fmtDate(c.created_at)}</span>
                  </div>
                  <div className="comment-item__text">{c.text}</div>
                  {c.attachments.length > 0 && (
                    <div className="comment-item__attachments">
                      {c.attachments.map((att) => {
                        const url = alertCommentAttachmentUrl(c.alert_id, c.id, att.id)
                        if (att.content_type.startsWith('image/')) {
                          return (
                            <a key={att.id} href={url} target="_blank" rel="noreferrer" title={`${att.filename} (${fmtBytes(att.size)})`}>
                              <img className="comment-attachment__thumb" src={url} alt={att.filename} />
                            </a>
                          )
                        }
                        if (att.content_type.startsWith('video/')) {
                          return <video key={att.id} className="comment-attachment__thumb" src={url} controls />
                        }
                        return (
                          <a key={att.id} className="comment-attachment__file" href={url} target="_blank" rel="noreferrer" title={`Скачать: ${att.filename} (${fmtBytes(att.size)})`}>
                            <Icon name="download" />
                            {att.filename}
                            <span className="row-sub">{fmtBytes(att.size)}</span>
                          </a>
                        )
                      })}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
          {canWriteAlerts && <div className="util-col gap-2">
            <textarea
              className="input textarea"
              style={{ width: '100%' }}
              rows={3}
              value={commentDraft}
              onChange={(e) => setCommentDraft(e.target.value)}
              placeholder="Написать комментарий…"
            />
            {commentFiles.length > 0 && (
              <div className="comment-item__attachments">
                {commentFiles.map((f, i) => (
                  <span key={`${f.name}-${i}`} className="comment-attachment__file">
                    <Icon name="paperclip" />
                    {f.name}
                    <span className="row-sub">{fmtBytes(f.size)}</span>
                    <button
                      className="btn btn-ghost btn-icon btn-sm"
                      title="Убрать вложение"
                      onClick={() => setCommentFiles((prev) => prev.filter((_, idx) => idx !== i))}
                    >
                      <Icon name="x" />
                    </button>
                  </span>
                ))}
              </div>
            )}
            <div className="filter-bar__row">
              <input
                ref={commentFileInputRef}
                type="file"
                multiple
                style={{ display: 'none' }}
                onChange={async (e) => {
                  const picked = Array.from(e.target.files ?? [])
                  e.target.value = ''
                  // A microtask hop before the state update — matches the same shape
                  // `ProfilesPage`'s (proven-reliable) import handlers naturally have via
                  // their own `await readJsonFile(file)`. A same-tick `setState` called
                  // directly inside a CDP-driven (rather than a real OS-level) file-input
                  // `change` event was observed, live, to sometimes never commit a
                  // re-render within a normal assertion window — this sidesteps that.
                  await Promise.resolve()
                  setCommentFiles((prev) => [...prev, ...picked])
                }}
              />
              <Button variant="ghost" small title="Прикрепить файл, изображение или видео" onClick={() => commentFileInputRef.current?.click()}>
                <Icon name="paperclip" />
                Прикрепить
              </Button>
              <span className="spacer" />
              <Button variant="primary" title="Отправить комментарий вместе с прикреплёнными файлами" disabled={!commentDraft.trim() || commentSending} onClick={sendComment}>
                Отправить
              </Button>
            </div>
          </div>}
        </div>
      </Modal>

      <Modal
        open={factsTarget !== null}
        title={`Facts${factsTarget ? `: ${factsTarget.name}` : ''}`}
        onClose={() => setFactsTarget(null)}
        wide
        footer={
          <Button variant="ghost" title="Закрыть окно facts" onClick={() => setFactsTarget(null)}>
            Закрыть
          </Button>
        }
      >
        {factsTarget && renderJsonAsTable(factsTarget.facts, 'Facts не заданы для этой тревоги.')}
      </Modal>

      <Modal
        open={causeTarget !== null}
        title="Причина подавления"
        onClose={() => setCauseTarget(null)}
        footer={
          <Button variant="ghost" title="Закрыть" onClick={() => setCauseTarget(null)}>
            Закрыть
          </Button>
        }
      >
        <div className="util-col gap-3">
          {causeTarget && (
            <p className="stamp">
              Тревога «{causeTarget.name}» ({causeTarget.device_ip}) подавлена групповым правилом — она является следствием тревоги, активной на upstream-соседе:
            </p>
          )}
          {causeLoading ? (
            <p className="stamp">Загрузка…</p>
          ) : causeError ? (
            <p className="stamp" style={{ color: 'var(--status-critical)' }}>
              {causeError}
            </p>
          ) : causeAlert ? (
            <div className="util-col gap-2">
              <div className="filter-bar__row">
                <Badge severity={levelSeverity(causeAlert.level)} label={causeAlert.level} />
                {causeAlert.state === 'Active' ? <Badge severity="critical" label="активна" /> : <Badge severity="ok" label="снята" />}
                <button
                  className="metric-name-btn"
                  title={`Открыть устройство ${causeAlert.device_ip}`}
                  onClick={() => {
                    setCauseTarget(null)
                    onOpenDevice(causeAlert.device_ip)
                  }}
                >
                  {causeAlert.device_ip}
                </button>
                <strong>{causeAlert.name}</strong>
              </div>
              <p>{causeAlert.message}</p>
              <p className="row-sub">
                Начало: {fmtDate(causeAlert.first_seen)} · Последнее наблюдение: {fmtDate(causeAlert.last_seen)}
              </p>
            </div>
          ) : null}
        </div>
      </Modal>
    </div>
  )
}
