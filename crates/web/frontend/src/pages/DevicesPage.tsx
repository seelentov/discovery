import { DeviceRuleDiagnostics } from '../components/DeviceRuleDiagnostics'
import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { devicesApi, type OperatorAction, type OperatorActionJob } from '../api/devices'
import { profilesApi } from '../api/profiles'
import { topologyRulesApi } from '../api/topology'
import { ApiHttpError } from '../api/http'
import { isTableMetricValue, type DeviceView, type DevicesQuery, type MetricHistoryRecord, type MetricView, type ResolvedNeighbor, type SshAuth, type TopologyRule } from '../api/types'
import { Badge } from '../components/Badge'
import { Button } from '../components/Button'
import { EmptyStateRow } from '../components/EmptyState'
import { ExportMenu } from '../components/ExportMenu'
import { Field } from '../components/Field'
import { Icon } from '../components/Icon'
import { renderJsonAsTable } from '../components/JsonTable'
import { Modal } from '../components/Modal'
import { Pagination } from '../components/Pagination'
import { Switch } from '../components/Switch'
import { useConfirm } from '../hooks/useConfirm'
import { useAuth } from '../hooks/useAuth'
import { useToast } from '../hooks/useToast'
import { localToIso } from '../utils/datetime'
import type { ExportRow } from '../utils/export'

const EXPORT_PAGE_SIZE = 500
const EXPORT_MAX_PAGES = 50

/** Fetches every page matching `query` (up to `EXPORT_MAX_PAGES` × `EXPORT_PAGE_SIZE`
 * rows — a generous cap against a runaway loop, not a realistic ceiling for what an
 * export button should pull down in one click) — "export respecting current filters"
 * means the whole filtered result set, not just whatever page happens to be on screen. */
async function fetchAllDevices(query: Omit<DevicesQuery, 'page' | 'page_size'>): Promise<DeviceView[]> {
  const all: DeviceView[] = []
  for (let page = 1; page <= EXPORT_MAX_PAGES; page++) {
    const res = await devicesApi.list({ ...query, page, page_size: EXPORT_PAGE_SIZE })
    all.push(...res.items)
    if (all.length >= res.total || res.items.length === 0) break
  }
  return all
}

function deviceToExportRow(d: DeviceView): ExportRow {
  return {
    ip: d.facts.ip,
    profile: d.profile ?? '',
    enabled: d.enabled,
    ping_ok: d.ping_ok === null ? '' : d.ping_ok,
    ping_loss_pct: d.ping_loss_pct === null ? '' : d.ping_loss_pct,
    snmp_ok: d.snmp_ok === null ? '' : d.snmp_ok,
    active_alert_count: d.active_alert_count,
    under_maintenance: d.under_maintenance,
    discovered_at: d.discovered_at,
    metrics: JSON.stringify(Object.fromEntries(d.metrics.map((m) => [m.name, m.error ?? m.value]))),
  }
}

type SortBy = 'ip' | 'profile' | 'discovered_at'
type SortDir = 'asc' | 'desc'

const PAGE_SIZE = 25

function fmtDate(iso: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

/** `useDebounce`-style: only fires `onChange` `delayMs` after the last keystroke — the
 * mockup filtered a fully-loaded client-side array on every keystroke; the real backend
 * does the filtering in SQL per request, so hammering it on every keystroke would be
 * needless load for no benefit (see the discovery-sort-filter-backend memory note this
 * whole page exists to satisfy). */
function useDebouncedValue<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const id = setTimeout(() => setDebounced(value), delayMs)
    return () => clearTimeout(id)
  }, [value, delayMs])
  return debounced
}

export function DevicesPage({
  openDeviceIp,
  onOpenDeviceHandled,
  onOpenProfile,
  onOpenAlertsForDevice,
}: {
  /** Set by Alerts' IP link — pre-fills the search filter with that IP. Read via lazy
   * initial state below (not a post-mount effect calling `setSearchInput`), same fix as
   * `AlertsPage`'s own `openFilter` — a post-mount effect would let the very first
   * `load()` fire once with no filter before the effect applies it. */
  openDeviceIp?: string | null
  onOpenDeviceHandled?: () => void
  /** Direct user request 2026-08-28, mirrors Alerts' own name→profile link: clicking a
   * device's profile name jumps to that profile's edit modal. */
  onOpenProfile?: (profileName: string) => void
  /** Direct user request 2026-08-28: clicking a device's active-alert count jumps to
   * Alerts pre-filtered to this device's IP — the reverse of Alerts' own IP→Devices link. */
  onOpenAlertsForDevice?: (ip: string) => void
} = {}) {
  const toast = useToast()
  const confirm = useConfirm()
  const { canWrite } = useAuth()
  const canWriteDevices = canWrite('devices')
  const canWriteMetrics = canWrite('device_metrics')

  const [searchInput, setSearchInput] = useState(() => openDeviceIp ?? '')
  const search = useDebouncedValue(searchInput, 300)
  const [hasError, setHasError] = useState(false)
  const [profileFilter, setProfileFilter] = useState('')
  const [profileNames, setProfileNames] = useState<string[]>([])
  const [cidrInput, setCidrInput] = useState('')
  const cidr = useDebouncedValue(cidrInput, 300)
  const [sortBy, setSortBy] = useState<SortBy>('ip')
  const [sortDir, setSortDir] = useState<SortDir>('asc')
  const [page, setPage] = useState(1)

  const [data, setData] = useState<{ items: DeviceView[]; total: number } | null>(null)
  const [loading, setLoading] = useState(true)
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [historyTarget, setHistoryTarget] = useState<{ device: DeviceView; metric: string } | null>(null)
  // Direct user request 2026-08-28: manual device creation (the one bypass of the
  // discovery pipeline) — see `devicesApi.create`'s Rust-side docs.
  const [createOpen, setCreateOpen] = useState(false)
  const [createIp, setCreateIp] = useState('')
  const [createProfile, setCreateProfile] = useState('')
  const [createMetrics, setCreateMetrics] = useState<[string, string][]>([])
  const [createSaving, setCreateSaving] = useState(false)
  // SSH credentials (2026-09-07, SSH CLI-pull metrics) — manual-entry-only, set via a
  // dedicated `PUT /api/devices/:id/ssh_credentials` (works on any existing device, not
  // just at creation, unlike `snmp_auth`). Secret fields (`sshPassword`/`sshPrivateKey`/
  // `sshPassphrase`) always start blank on open — `GET` returns them redacted
  // (`"<скрыто>"`), which must never be resubmitted as though it were real.
  const [sshModalDevice, setSshModalDevice] = useState<DeviceView | null>(null)
  const [sshUsername, setSshUsername] = useState('')
  const [sshAuthKind, setSshAuthKind] = useState<SshAuth['kind']>('password')
  const [sshPassword, setSshPassword] = useState('')
  const [sshPrivateKey, setSshPrivateKey] = useState('')
  const [sshPassphrase, setSshPassphrase] = useState('')
  const [sshPort, setSshPort] = useState('22')
  const [sshSaving, setSshSaving] = useState(false)
  // Roadmap 2026-09-18 finding #3: "Show topological neighbors" from the Devices page —
  // previously only reachable from the Topology page or the raw REST endpoint. Self-
  // contained here (no dependency on `TopologyPage.tsx`): the modal fetches the rule list
  // and this device's neighbors under *every* configured rule itself.
  const [neighborsDevice, setNeighborsDevice] = useState<DeviceView | null>(null)
  // `0` = off — defaulted to off (audit finding 9, 2026-09-20, direct user request), not
  // 1s: auto-refresh anywhere should be opt-in, not a surprise background poll from the
  // first page load.
  const [refreshSecs, setRefreshSecs] = useState(0)
  // Guards against an out-of-order response: with auto-refresh now polling this same
  // `load()` on a timer *alongside* every filter/sort/page change also triggering it, an
  // older in-flight request (issued just before a filter changed) can resolve *after* a
  // newer one and overwrite fresh, correctly-filtered data with a stale result — found
  // live via a genuinely flaky "фильтр по профилю" E2E run, not a hypothetical. Only the
  // response matching the most recently *issued* call is ever applied.
  const requestIdRef = useRef(0)

  const load = useCallback(async () => {
    const requestId = ++requestIdRef.current
    setLoading(true)
    try {
      const res = await devicesApi.list({
        search: search || undefined,
        has_error: hasError || undefined,
        profile: profileFilter || undefined,
        cidr: cidr || undefined,
        sort_by: sortBy,
        sort_dir: sortDir,
        page,
        page_size: PAGE_SIZE,
      })
      if (requestId !== requestIdRef.current) return // a newer request has since started
      setData(res)
    } catch (e) {
      if (requestId !== requestIdRef.current) return
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось загрузить устройства', true)
    } finally {
      if (requestId === requestIdRef.current) setLoading(false)
    }
  }, [search, hasError, profileFilter, cidr, sortBy, sortDir, page, toast])

  useEffect(() => {
    load()
  }, [load])

  // Direct user request 2026-08-28: configurable auto-refresh (same button+period pattern
  // as `AlertsPage`), but deliberately paused while any row's metrics table is expanded —
  // "когда открыт список метрик то не обновлять список, но обновлять список метрик"
  // (`DeviceMetricsTable` below owns its own independent refresh for that case instead).
  // Re-fetching the whole page here while a row is expanded would also risk reordering/
  // resizing rows out from under whatever the user is currently looking at.
  useEffect(() => {
    if (refreshSecs <= 0 || expanded.size > 0) return
    const id = setInterval(load, refreshSecs * 1000)
    return () => clearInterval(id)
  }, [load, refreshSecs, expanded.size])

  // The profile dropdown's option list is fetched once, independent of the devices list
  // itself — a profile with zero matching devices right now should still be selectable.
  useEffect(() => {
    profilesApi
      .list({ page_size: 1000, sort_by: 'name', sort_dir: 'asc' })
      .then((res) => setProfileNames(res.items.map((p) => p.profile.name)))
      .catch(() => {})
  }, [])

  // Filters changing should reset to page 1 — a lingering "page 4" from a broader search
  // would silently show an empty page under a narrower one.
  useEffect(() => {
    setPage(1)
  }, [search, hasError, profileFilter, cidr, sortBy, sortDir])

  // Deep-link from Alerts' IP link — the search value itself is set via lazy initial
  // state above; this just clears the pending flag once on mount. profile/CIDR filters
  // are already blank by default, so there's nothing left for this effect to reset.
  useEffect(() => {
    if (openDeviceIp) onOpenDeviceHandled?.()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  function toggleSort(field: SortBy) {
    if (sortBy !== field) {
      setSortBy(field)
      setSortDir('asc')
    } else if (sortDir === 'asc') {
      setSortDir('desc')
    } else {
      // third click: back to the default column/direction rather than a "no sort" state
      // — the API always needs *some* sort_by, unlike the mockup's client-side sort which
      // could fall back to insertion order.
      setSortBy('ip')
      setSortDir('asc')
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

  async function toggleExpanded(id: string) {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  async function handleSetEnabled(device: DeviceView, enabled: boolean) {
    try {
      await devicesApi.setEnabled(device.id, enabled)
      toast(enabled ? `Устройство ${device.facts.ip} включено` : `Устройство ${device.facts.ip} выключено — опрос остановлен`)
      load()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось изменить устройство', true)
    }
  }

  async function handleServiceDiscovery() {
    const ip = window.prompt('IP устройства для проверки сервисов')?.trim()
    if (!ip) return
    try {
      const result = await devicesApi.discoverServices(ip)
      const passed = result.results.filter((item) => item.ok).length
      if (result.device_id) load()
      toast(result.device_id
        ? `Найдено проверок: ${passed}; устройство ${result.created ? 'создано' : 'уже существует'}, профиль: ${result.profile ?? 'не выбран'}`
        : `Сервисы на ${ip} не обнаружены`, !result.device_id)
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось выполнить discovery сервисов', true)
    }
  }

  function openCreate() {
    setCreateIp('')
    setCreateProfile('')
    setCreateMetrics([])
    setCreateOpen(true)
  }

  async function handleCreate() {
    const ip = createIp.trim()
    if (!ip) return
    setCreateSaving(true)
    try {
      const metrics = Object.fromEntries(createMetrics.filter(([k]) => k.trim() !== ''))
      await devicesApi.create({ ip, profile: createProfile || undefined, metrics: Object.keys(metrics).length > 0 ? metrics : undefined })
      toast(`Устройство ${ip} создано`)
      setCreateOpen(false)
      load()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось создать устройство', true)
    } finally {
      setCreateSaving(false)
    }
  }

  async function handleSetAllEnabled(enabled: boolean) {
    const filters = [
      search && `поиск «${search}»`,
      profileFilter && `профиль «${profileFilter}»`,
      cidr && `подсеть ${cidr}`,
      hasError && 'с ошибками',
    ].filter(Boolean).join(', ')
    const scope = filters ? `текущую выборку (${filters})` : 'все устройства'
    const count = data?.total ?? 0
    const ok = await confirm(`${enabled ? 'Включить' : 'Выключить'} мониторинг для ${scope}? Затронуто устройств: ${count}.`, {
      label: enabled ? 'Включить' : 'Выключить',
      icon: enabled ? 'check' : 'pause',
      danger: !enabled,
    })
    if (!ok) return
    try {
      const res = await devicesApi.setAllEnabled(enabled, {
        search: search || undefined,
        has_error: hasError || undefined,
        profile: profileFilter || undefined,
        cidr: cidr || undefined,
      })
      toast(`${enabled ? 'Включено' : 'Выключено'} устройств: ${res.touched}`)
      load()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось изменить устройства', true)
    }
  }

  async function handleDelete(device: DeviceView) {
    const ok = await confirm(`Удалить устройство «${device.facts.ip}»? Каскадно удалятся его метрики, история и тревоги.`, {
      label: 'Удалить',
      icon: 'trash',
    })
    if (!ok) return
    try {
      await devicesApi.delete(device.id)
      toast(`Устройство ${device.facts.ip} удалено`)
      load()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось удалить устройство', true)
    }
  }

  function openSshModal(device: DeviceView) {
    setSshModalDevice(device)
    // Username/port aren't secrets — safe to prefill from the (unredacted) existing
    // value. Auth fields always start blank, see this state's docs above.
    setSshUsername(device.ssh_credentials?.username ?? '')
    setSshAuthKind(device.ssh_credentials?.auth.kind ?? 'password')
    setSshPassword('')
    setSshPrivateKey('')
    setSshPassphrase('')
    setSshPort(device.ssh_credentials ? String(device.ssh_credentials.port) : '22')
  }

  async function handleSaveSsh() {
    if (!sshModalDevice) return
    setSshSaving(true)
    try {
      const auth: SshAuth =
        sshAuthKind === 'password' ? { kind: 'password', password: sshPassword } : { kind: 'private_key', private_key: sshPrivateKey, passphrase: sshPassphrase.trim() || null }
      await devicesApi.setSshCredentials(sshModalDevice.id, { username: sshUsername.trim(), auth, port: Number(sshPort) || 22 })
      toast(`SSH-креды устройства ${sshModalDevice.facts.ip} обновлены`)
      setSshModalDevice(null)
      load()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось сохранить SSH-креды', true)
    } finally {
      setSshSaving(false)
    }
  }

  async function handleSync(device: DeviceView) {
    const hasOverrides = device.metrics.some((m) => m.enabled_override !== null)
    const doSync = async () => {
      try {
        await devicesApi.syncWithProfile(device.id)
        toast(`Устройство ${device.facts.ip} синхронизировано с профилем`)
        load()
      } catch (e) {
        toast(e instanceof ApiHttpError ? e.message : 'Не удалось синхронизировать устройство', true)
      }
    }
    if (hasOverrides) {
      const ok = await confirm(
        `У устройства «${device.facts.ip}» есть ручные override метрик — синхронизация с профилем их сбросит, устройство вернётся на настройки профиля по умолчанию. Продолжить?`,
        { label: 'Синхронизировать', icon: 'refresh' },
      )
      if (!ok) return
    }
    await doSync()
  }

  // Neither of these calls the page's own `load()` anymore — `DeviceMetricsTable` owns
  // its metrics independently now (its own refresh button/period, see task docs there)
  // and re-fetches itself right after a successful toggle/reset instead. They re-throw on
  // failure so the sub-table knows *not* to refresh over a change that never actually
  // happened.
  async function handleToggleMetric(device: DeviceView, metric: MetricView) {
    try {
      await devicesApi.setMetricOverride(device.id, metric.name, !metric.effective_enabled)
      toast(`Метрика «${metric.name}» ${!metric.effective_enabled ? 'включена' : 'выключена'} (ручной override)`)
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось изменить метрику', true)
      throw e
    }
  }

  async function handleResetMetricOverride(device: DeviceView, metric: MetricView) {
    try {
      await devicesApi.clearMetricOverride(device.id, metric.name)
      toast('Override снят — используется дефолт профиля')
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось снять override', true)
      throw e
    }
  }

  const rows = useMemo(() => data?.items ?? [], [data])

  return (
    <div className="util-col gap-4">
      <div className="filter-bar">
        <div className="filter-bar__row">
          <div className="input-icon">
            <Icon name="search" />
            <input
              className="input"
              placeholder="IP, профиль, значение метрики…"
              title="Поиск по IP устройства, имени профиля и значениям опрошенных метрик"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
            />
          </div>
          <select className="select" title="Показать только устройства на выбранном профиле" value={profileFilter} onChange={(e) => setProfileFilter(e.target.value)}>
            <option value="">все профили</option>
            {profileNames.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
          <input
            className="input"
            style={{ width: '11rem' }}
            placeholder="Подсеть (CIDR)…"
            title="Например, 10.121.0.0/16"
            value={cidrInput}
            onChange={(e) => setCidrInput(e.target.value)}
          />
          <div className="segmented">
            <button className={hasError ? '' : 'active'} title="Показать все устройства" onClick={() => setHasError(false)}>
              Все
            </button>
            <button className={hasError ? 'active' : ''} title="Показать только устройства с ошибкой опроса ping или SNMP" onClick={() => setHasError(true)}>
              С ошибками
            </button>
          </div>
        </div>
        <div className="filter-bar__row">
          {canWriteDevices && (
            <Button variant="primary" small title="Создать устройство вручную, без дискаверинга — по IP" onClick={openCreate}>
              <Icon name="plus" />
              Создать
            </Button>
          )}
          {canWriteDevices && (
            <Button variant="ghost" small title="Проверить SNMP, SSH, HTTP, HTTPS и TCP на одном IP" onClick={handleServiceDiscovery}>
              Обнаружить сервисы
            </Button>
          )}
          <ExportMenu
            filenameBase="devices"
            getRows={async () => {
              const devices = await fetchAllDevices({ search: search || undefined, has_error: hasError || undefined, profile: profileFilter || undefined, cidr: cidr || undefined })
              return devices.map(deviceToExportRow)
            }}
          />
          {canWriteDevices && (
            <>
              <Button variant="ghost" small title="Включить мониторинг для всех устройств в текущей выборке" onClick={() => handleSetAllEnabled(true)}>
                Включить все
              </Button>
              <Button variant="danger" small title="Выключить мониторинг для всех устройств в текущей выборке" onClick={() => handleSetAllEnabled(false)}>
                Выключить все
              </Button>
            </>
          )}
          <span className="spacer" />
          <Button variant="ghost" iconOnly small title="Обновить сейчас" onClick={() => load()}>
            <Icon name="refresh" />
          </Button>
          <select
            className="select"
            title={expanded.size > 0 ? 'Автообновление списка приостановлено, пока раскрыта таблица метрик' : 'Период автообновления'}
            value={refreshSecs}
            onChange={(e) => setRefreshSecs(Number(e.target.value))}
          >
            <option value={0}>без автообновления</option>
            <option value={1}>каждую 1с</option>
            <option value={3}>каждые 3с</option>
            <option value={5}>каждые 5с</option>
            <option value={10}>каждые 10с</option>
            <option value={30}>каждые 30с</option>
          </select>
        </div>
      </div>

      <div className="table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th></th>
              <th className="th-sortable" onClick={() => toggleSort('ip')}>
                IP {sortIndicator('ip')}
              </th>
              <th className="th-sortable" onClick={() => toggleSort('profile')}>
                Профиль {sortIndicator('profile')}
              </th>
              <th>Ping</th>
              <th>SNMP</th>
              <th>Активные тревоги</th>
              <th className="th-sortable" onClick={() => toggleSort('discovered_at')}>
                Обнаружено {sortIndicator('discovered_at')}
              </th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {loading && rows.length === 0 ? (
              <EmptyStateRow colSpan={8} icon="router" text="Загрузка…" />
            ) : rows.length === 0 ? (
              <EmptyStateRow colSpan={8} icon="router" text="Измените фильтры или сбросьте их" />
            ) : (
              rows.map((d) => {
                const isExpanded = expanded.has(d.id)
                const vendor = d.metrics.find((m) => m.name === 'vendor')?.value
                return (
                  <Fragment key={d.id}>
                    <tr data-sev={d.enabled && (d.ping_ok === false || d.snmp_ok === false) ? 'critical' : 'none'}>
                      <td>
                        <button className={isExpanded ? 'expand-btn row-expanded' : 'expand-btn'} onClick={() => toggleExpanded(d.id)}>
                          <Icon name="chevron-right" />
                        </button>
                      </td>
                      <td>
                        <div className="row-ip">
                          {d.facts.ip} {!d.enabled && <span className="badge badge-neutral">выключено</span>}
                          {d.under_maintenance && <Badge severity="warning" label="под ТО" />}
                        </div>
                        {vendor != null && <div className="row-sub">{String(vendor)}</div>}
                      </td>
                      <td>
                        {d.profile ? (
                          <button className="metric-name-btn" title={`Открыть профиль «${d.profile}»`} onClick={() => onOpenProfile?.(d.profile as string)}>
                            {d.profile}
                          </button>
                        ) : (
                          <span className="row-sub">без профиля</span>
                        )}
                      </td>
                      <td>
                        {!d.enabled ? (
                          <span className="badge badge-neutral">
                            <Icon name="dot" />
                            не опрашивается
                          </span>
                        ) : d.ping_ok === null ? (
                          <span className="badge badge-neutral">н/д</span>
                        ) : (
                          <div className="util-col gap-1">
                            {d.ping_ok ? <Badge severity="ok" label="ok" /> : <Badge severity="critical" label="недоступен" />}
                            {/* Packet loss % (2026-09-14, `docs/Roadmap.md` item 5) — only worth a
                             * line when it's actually informative: a device can be `ping_ok=true`
                             * (at least one of `1 + retries` attempts got through) while still
                             * dropping a meaningful share of them, a distinction the plain badge
                             * above can't show on its own. Silent at 0% — the common case
                             * shouldn't grow a redundant "потери: 0%" on every healthy row. */}
                            {d.ping_ok && typeof d.ping_loss_pct === 'number' && d.ping_loss_pct > 0 && (
                              <span className="row-sub" title="Доля ICMP-попыток без ответа за последнюю проверку">
                                потери: {d.ping_loss_pct.toFixed(0)}%
                              </span>
                            )}
                          </div>
                        )}
                      </td>
                      <td>
                        {!d.enabled ? (
                          <span className="badge badge-neutral">
                            <Icon name="dot" />
                            не опрашивается
                          </span>
                        ) : d.snmp_ok === null ? (
                          <span className="badge badge-neutral">н/д</span>
                        ) : d.snmp_ok ? (
                          <Badge severity="ok" label="ok" />
                        ) : (
                          <Badge severity="critical" label="недоступен" />
                        )}
                      </td>
                      <td>
                        {d.active_alert_count > 0 ? (
                          <button className="link-more" title="Открыть активные тревоги этого устройства" onClick={() => onOpenAlertsForDevice?.(d.facts.ip)}>
                            <Icon name="bell" />
                            {d.active_alert_count}
                          </button>
                        ) : (
                          <span className="row-sub">—</span>
                        )}
                      </td>
                      <td className="row-sub">{fmtDate(d.discovered_at)}</td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        {canWriteDevices && (
                          <>
                            <Switch checked={d.enabled} onChange={(v) => handleSetEnabled(d, v)} title={d.enabled ? 'Выключить мониторинг' : 'Включить мониторинг'} />
                            <Button
                              variant="ghost"
                              iconOnly
                              small
                              title="Синхронизировать с профилем (сбросит ручные override метрик, если они есть)"
                              onClick={() => handleSync(d)}
                            >
                              <Icon name="refresh" />
                            </Button>
                            <Button
                              variant="ghost"
                              iconOnly
                              small
                              title={d.ssh_credentials ? `SSH-креды заданы (${d.ssh_credentials.username}) — изменить` : 'SSH-креды не заданы — нужны для metric-source=ssh (SSH CLI-pull)'}
                              onClick={() => openSshModal(d)}
                            >
                              <Icon name="key" />
                            </Button>
                          </>
                        )}
                        <Button variant="ghost" iconOnly small title="Показать топологических соседей" onClick={() => setNeighborsDevice(d)}>
                          <Icon name="stack" />
                        </Button>
                        {canWriteDevices && (
                          <Button variant="ghost" iconOnly small title="Удалить" onClick={() => handleDelete(d)}>
                            <Icon name="trash" />
                          </Button>
                        )}
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr className="detail-row">
                        <td colSpan={8}>
                          <div className="util-col gap-4">
                            {canWriteDevices && <DeviceActions device={d} />}
                            <DeviceRuleDiagnostics deviceId={d.id} />
                            <DeviceMetricsTable
                              device={d}
                              onToggleMetric={handleToggleMetric}
                              onResetOverride={handleResetMetricOverride}
                              canWrite={canWriteMetrics}
                              onOpenHistory={(metric) => setHistoryTarget({ device: d, metric })}
                            />
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })
            )}
          </tbody>
        </table>
      </div>
      {data && <Pagination page={page} pageSize={PAGE_SIZE} total={data.total} itemCount={rows.length} onPageChange={setPage} />}

      {historyTarget && <MetricHistoryModal device={historyTarget.device} metricName={historyTarget.metric} onClose={() => setHistoryTarget(null)} />}

      {neighborsDevice && <DeviceNeighborsModal device={neighborsDevice} onClose={() => setNeighborsDevice(null)} onOpenAlertsForDevice={onOpenAlertsForDevice} />}

      {canWriteDevices && <Modal
        open={createOpen}
        title="Создать устройство"
        onClose={() => setCreateOpen(false)}
        footer={
          <>
            <Button variant="ghost" title="Закрыть без создания устройства" onClick={() => setCreateOpen(false)}>
              Отмена
            </Button>
            <Button variant="primary" title="Создать устройство сразу с указанными IP/профилем/метриками, в обход дискаверинга" disabled={!createIp.trim() || createSaving} onClick={handleCreate}>
              Создать
            </Button>
          </>
        }
      >
        <div className="util-col gap-3">
          <p className="stamp" style={{ maxWidth: 'none' }}>
            Единственный путь в обход дискаверинга — устройство появится сразу, без SNMP-опроса. Профиль (если указан) назначается напрямую, минуя match-выражение; реальный
            опрос по профилю подхватит его на своём обычном расписании и может переопросить заданные ниже метрики поверх — это ожидаемо.
          </p>
          <Field label="IP" hint="обязательное поле">
            <input className="input" placeholder="10.0.0.5" value={createIp} onChange={(e) => setCreateIp(e.target.value)} />
          </Field>
          <Field label="Профиль" hint="необязательно — можно оставить без профиля">
            <select className="select" value={createProfile} onChange={(e) => setCreateProfile(e.target.value)}>
              <option value="">без профиля</option>
              {profileNames.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
          </Field>
          <KvEditor
            label="Начальные метрики"
            hint="имя → значение, записывается один раз без SNMP-опроса — например area_name; последующий реальный опрос по профилю может переопределить"
            keyPlaceholder="имя"
            valuePlaceholder="значение"
            entries={createMetrics}
            onChange={setCreateMetrics}
          />
        </div>
      </Modal>}

      {canWriteDevices && <Modal
        open={sshModalDevice !== null}
        title={`SSH-креды: ${sshModalDevice?.facts.ip ?? ''}`}
        onClose={() => setSshModalDevice(null)}
        footer={
          <>
            <Button variant="ghost" title="Закрыть без сохранения" onClick={() => setSshModalDevice(null)}>
              Отмена
            </Button>
            <Button
              variant="primary"
              title="Сохранить SSH-креды устройства"
              disabled={!sshUsername.trim() || (sshAuthKind === 'password' ? !sshPassword : !sshPrivateKey.trim()) || sshSaving}
              onClick={handleSaveSsh}
            >
              Сохранить
            </Button>
          </>
        }
      >
        <div className="util-col gap-3">
          <p className="stamp" style={{ maxWidth: 'none' }}>
            Ручной ввод — SSH-креды, в отличие от SNMP, никогда не подбираются автоматически. Нужны, чтобы у этого устройства заработали метрики с источником «ssh (команда)»
            (см. вкладку «Метрики» в профиле). Пароль/приватный ключ никогда не приходят обратно с сервера — поля всегда пустые при открытии, ввод обязателен только если хотите
            их поменять.
          </p>
          <p className="stamp" style={{ maxWidth: 'none' }} title="Защита от MITM (CWE-295): при первом успешном подключении discovery-agent запоминает SHA256-отпечаток ключа устройства и сверяет его на каждом следующем подключении — несовпадение обрывает соединение до отправки логина/пароля. Смена SSH-кредов сбрасывает отпечаток — следующее подключение запомнит его заново.">
            Host key: {sshModalDevice?.ssh_credentials?.known_host_key ? <code className="mono">{sshModalDevice.ssh_credentials.known_host_key}</code> : 'не закреплён — будет закреплён при первом подключении'}
          </p>
          <div className="form-grid">
            <Field label="Username" hint="обязательное поле">
              <input className="input" value={sshUsername} onChange={(e) => setSshUsername(e.target.value)} />
            </Field>
            <Field label="Порт" hint="по умолчанию 22">
              <input className="input" type="number" min={1} max={65535} value={sshPort} onChange={(e) => setSshPort(e.target.value)} />
            </Field>
          </div>
          <Field label="Тип аутентификации" hint="пароль или приватный ключ (опционально с passphrase)">
            <select className="select" value={sshAuthKind} onChange={(e) => setSshAuthKind(e.target.value as SshAuth['kind'])}>
              <option value="password">пароль</option>
              <option value="private_key">приватный ключ</option>
            </select>
          </Field>
          {sshAuthKind === 'password' ? (
            <Field label="Пароль" hint="обязательное поле — вводится заново при каждом изменении">
              <input className="input" type="password" autoComplete="new-password" value={sshPassword} onChange={(e) => setSshPassword(e.target.value)} />
            </Field>
          ) : (
            <>
              <Field label="Приватный ключ" hint="полный текст ключа (PEM/OpenSSH), не путь к файлу — этот проект не хранит ссылок на файлы на хосте агента">
                <textarea className="input textarea mono" style={{ width: '100%' }} rows={4} value={sshPrivateKey} onChange={(e) => setSshPrivateKey(e.target.value)} />
              </Field>
              <Field label="Passphrase" hint="пусто — ключ не зашифрован">
                <input className="input" type="password" autoComplete="new-password" value={sshPassphrase} onChange={(e) => setSshPassphrase(e.target.value)} />
              </Field>
            </>
          )}
        </div>
      </Modal>}
    </div>
  )
}

function DeviceActions({ device }: { device: DeviceView }) {
  const [job, setJob] = useState<OperatorActionJob | null>(null)
  const [history, setHistory] = useState<OperatorActionJob[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    devicesApi.listActions(device.id).then((items) => {
      setHistory(items)
      if (items[0]) devicesApi.getAction(device.id, items[0].job_id).then(setJob).catch(() => {})
    }).catch(() => {})
  }, [device.id])

  useEffect(() => {
    if (!job || (job.status !== 'pending' && job.status !== 'in_progress')) return
    const timer = window.setInterval(() => {
      devicesApi.getAction(device.id, job.job_id).then((updated) => {
        setJob(updated)
        setHistory((items) => items.map((item) => item.job_id === updated.job_id ? updated : item))
      }).catch((e) => {
        setError(e instanceof ApiHttpError ? e.message : 'Не удалось прочитать статус действия')
      })
    }, 1000)
    return () => window.clearInterval(timer)
  }, [device.id, job?.job_id, job?.status])

  async function run(action: OperatorAction) {
    setBusy(true)
    setError('')
    try {
      const created = await devicesApi.runAction(device.id, action)
      setJob(created)
      setHistory((items) => [created, ...items].slice(0, 20))
    } catch (e) {
      setError(e instanceof ApiHttpError ? e.message : 'Не удалось запустить действие')
    } finally {
      setBusy(false)
    }
  }

  async function cancel() {
    if (!job) return
    try {
      await devicesApi.cancelAction(device.id, job.job_id)
      const cancelled = await devicesApi.getAction(device.id, job.job_id)
      setJob(cancelled)
      setHistory((items) => items.map((item) => item.job_id === cancelled.job_id ? cancelled : item))
    } catch (e) {
      setError(e instanceof ApiHttpError ? e.message : 'Не удалось отменить действие')
    }
  }

  const actions: [OperatorAction, string][] = [
    ['test', 'Проверить'], ['poll-now', 'Опросить сейчас'],
    ['rediscover', 'Повторить discovery'], ['backup', 'Получить конфигурацию'],
  ]
  return <section className="util-col gap-2" aria-label={`Действия устройства ${device.facts.ip}`}>
    <div className="util-row gap-2">
      {actions.map(([action, label]) => <Button key={action} small disabled={busy || !device.enabled || job?.status === 'pending' || job?.status === 'in_progress'} onClick={() => run(action)}>{label}</Button>)}
    </div>
    {job && <div role="status">
      Задача #{job.job_id}: {job.status}
      {job.error && <> — {job.error}</>}
      {job.status === 'pending' && <Button small onClick={cancel}>Отменить</Button>}
      {job.result && job.action === 'test' && <> — ping: {job.result.ping_ok ? 'ok' : 'недоступен'}, сервисы: {Array.isArray(job.result.services) ? job.result.services.length : 0}
        {typeof job.result.reason === 'string' && <> — {job.result.reason}</>}
      </>}
      {job.result && job.action === 'poll_now' && <> — опрошено метрик: {String(job.result.metric_count ?? 0)}
        {Array.isArray(job.result.failed_metrics) && job.result.failed_metrics.length > 0 && <>; ошибки: {job.result.failed_metrics.join(', ')}</>}
      </>}
      {job.result && job.action === 'rediscover' && <> — проверка идентичности передана следующему этапу</>}
      {job.result && job.action === 'backup' && typeof job.result.configuration === 'string' &&
        <pre style={{ maxHeight: 320, overflow: 'auto' }}>{job.result.configuration}</pre>}
    </div>}
    {history.length > 0 && <div className="util-row gap-2" aria-label="История действий">
      {history.slice(0, 5).map((item) => <Button key={item.job_id} small variant="ghost" onClick={() => {
        devicesApi.getAction(device.id, item.job_id).then(setJob).catch((e) => setError(e instanceof ApiHttpError ? e.message : 'Не удалось прочитать задачу'))
      }}>#{item.job_id} {item.action} — {item.status}</Button>)}
    </div>}
    {error && <div role="alert">{error}</div>}
  </section>
}

function KvEditor({
  label,
  hint,
  keyPlaceholder,
  valuePlaceholder,
  entries,
  onChange,
}: {
  label: string
  hint: string
  keyPlaceholder: string
  valuePlaceholder: string
  entries: [string, string][]
  onChange: (entries: [string, string][]) => void
}) {
  function update(idx: number, key: string, value: string) {
    const next = entries.slice()
    next[idx] = [key, value]
    onChange(next)
  }
  function remove(idx: number) {
    onChange(entries.filter((_, i) => i !== idx))
  }
  function add() {
    onChange([...entries, ['', '']])
  }
  return (
    <Field label={label} hint={hint}>
      <div className="util-col gap-2">
        {entries.map(([k, v], idx) => (
          <div className="filter-bar__row" key={idx}>
            <input className="input" placeholder={keyPlaceholder} value={k} onChange={(e) => update(idx, e.target.value, v)} />
            <input className="input mono" placeholder={valuePlaceholder} value={v} onChange={(e) => update(idx, k, e.target.value)} />
            <Button variant="ghost" iconOnly small title="Удалить" onClick={() => remove(idx)}>
              <Icon name="x" />
            </Button>
          </div>
        ))}
        <Button variant="ghost" small title={`Добавить ещё одну пару для «${label}»`} onClick={add} style={{ alignSelf: 'flex-start' }}>
          <Icon name="plus" />
          Добавить
        </Button>
      </div>
    </Field>
  )
}

/** Russian plural for "строка" (table row count) — the standard one/few/many rule
 * (11-14 are always "many" regardless of the last digit, e.g. "11 строк" not "11 строка"). */
function rowsWord(n: number): string {
  const mod10 = n % 10
  const mod100 = n % 100
  if (mod10 === 1 && mod100 !== 11) return 'строка'
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return 'строки'
  return 'строк'
}

function sortMetrics(metrics: MetricView[]): MetricView[] {
  // Stable, deterministic order across refreshes — whatever order the backend happens to
  // return metrics in isn't guaranteed consistent, so sorting client-side is what actually
  // keeps rows from jumping around on every auto-refresh tick.
  return [...metrics].sort((a, b) => a.name.localeCompare(b.name))
}

/** Direct user request 2026-08-28: this sub-table refreshes independently of the parent
 * device list — its own list auto-refresh is deliberately paused while any row is
 * expanded (see `DevicesPage`'s own auto-refresh effect), replaced by this component's
 * own "Обновить" button + period select instead, so the metrics underneath stay live
 * without the whole page's rows reflowing/reordering around the user. */
function DeviceMetricsTable({
  device,
  onToggleMetric,
  onResetOverride,
  canWrite,
  onOpenHistory,
}: {
  device: DeviceView
  onToggleMetric: (device: DeviceView, metric: MetricView) => Promise<void>
  onResetOverride: (device: DeviceView, metric: MetricView) => Promise<void>
  canWrite: boolean
  onOpenHistory: (metricName: string) => void
}) {
  const [metrics, setMetrics] = useState<MetricView[]>(() => sortMetrics(device.metrics))
  // Which table-shaped metrics (by name) are currently expanded in-row — collapsed by
  // default, same reasoning as `refreshSecs` starting at 0: a wide table (e.g. `if_table`
  // on a many-port switch) shouldn't dominate the row list the moment this sub-table
  // opens; the user opts in per metric.
  const [expandedTables, setExpandedTables] = useState<Set<string>>(new Set())
  function toggleTable(name: string) {
    setExpandedTables((prev) => {
      const next = new Set(prev)
      if (next.has(name)) next.delete(name)
      else next.add(name)
      return next
    })
  }
  // Off by default, unlike the top-level list pages — opening this sub-table means the
  // user is typically about to interact with a specific row (click a metric's history,
  // toggle its override), and a re-render mid-interaction is a real, found-live
  // (`fill`/`click` racing a 1s repaint) source of E2E flakiness that a real person could
  // hit too, not just a test. Still available on request via the same select.
  const [refreshSecs, setRefreshSecs] = useState(0)
  // Same "ignore a response older than the most recently issued request" guard as
  // `DevicesPage.load` — a manual "Обновить" click and a periodic tick (or two ticks in a
  // row) can otherwise resolve out of order.
  const requestIdRef = useRef(0)

  const load = useCallback(async () => {
    const requestId = ++requestIdRef.current
    try {
      const fresh = await devicesApi.get(device.id)
      if (requestId !== requestIdRef.current) return
      setMetrics(sortMetrics(fresh.metrics))
    } catch {
      // A transient failure here just leaves the last-known metrics on screen — this is a
      // background refresh, not a user-initiated action, so no toast for it.
    }
  }, [device.id])

  useEffect(() => {
    if (refreshSecs <= 0) return
    const id = setInterval(load, refreshSecs * 1000)
    return () => clearInterval(id)
  }, [load, refreshSecs])

  async function handleToggle(m: MetricView) {
    try {
      await onToggleMetric(device, m)
      load()
    } catch {
      // `onToggleMetric` already toasted the error — don't refresh over a change that
      // never actually happened.
    }
  }

  async function handleReset(m: MetricView) {
    try {
      await onResetOverride(device, m)
      load()
    } catch {
      // same as handleToggle
    }
  }

  return (
    <div className="util-col gap-2">
      <div className="filter-bar__row">
        <span className="spacer" />
        <Button variant="ghost" iconOnly small title="Обновить метрики сейчас" onClick={() => load()}>
          <Icon name="refresh" />
        </Button>
        <select className="select" title="Период автообновления метрик" value={refreshSecs} onChange={(e) => setRefreshSecs(Number(e.target.value))}>
          <option value={0}>без автообновления</option>
          <option value={1}>каждую 1с</option>
          <option value={3}>каждые 3с</option>
          <option value={5}>каждые 5с</option>
          <option value={10}>каждые 10с</option>
          <option value={30}>каждые 30с</option>
        </select>
      </div>
      {metrics.length === 0 ? (
        <p className="stamp" style={{ maxWidth: 'none' }}>
          У устройства пока нет ни одной метрики.
        </p>
      ) : (
        <table className="data-table metrics-table">
          <thead>
            <tr>
              <th>Метрика</th>
              <th className="num">Значение</th>
              <th title="Вкл/выкл опроса именно на этом устройстве — независимо от профиля, если стоит ручной override">Опрос</th>
            </tr>
          </thead>
          <tbody>
            {metrics.map((m) => {
              const isTable = m.value !== null && isTableMetricValue(m.value)
              return (
              <tr key={m.name} style={!m.effective_enabled ? { opacity: 0.55 } : undefined}>
                <td className="mono">
                  <button className="metric-name-btn" title="История значений этой метрики" onClick={() => onOpenHistory(m.name)}>
                    <Icon name="history" />
                    {m.name}
                  </button>
                </td>
                <td className={isTable ? undefined : 'num tnum'}>
                  {!m.effective_enabled ? (
                    <span className="row-sub">не опрашивается (выключено)</span>
                  ) : m.error ? (
                    <div className="metric-error-msg">
                      <span className="badge badge-critical">
                        <Icon name="x-circle" />
                        {m.error}
                      </span>
                    </div>
                  ) : m.value !== null && isTableMetricValue(m.value) ? (
                    <div className="util-col gap-1">
                      {m.value.length === 0 ? (
                        <span className="metric-table-empty">
                          <Icon name="layout" />
                          Таблица пуста
                        </span>
                      ) : (
                        <>
                          <button
                            className="metric-name-btn"
                            title={expandedTables.has(m.name) ? 'Свернуть таблицу' : 'Таблица свёрнута — нажмите для просмотра'}
                            aria-expanded={expandedTables.has(m.name)}
                            onClick={() => toggleTable(m.name)}
                          >
                            <Icon name={expandedTables.has(m.name) ? 'chevron-down' : 'chevron-right'} />
                            {m.value.length} {rowsWord(m.value.length)} · таблица {expandedTables.has(m.name) ? 'раскрыта — нажмите, чтобы свернуть' : 'свёрнута — нажмите для просмотра'}
                          </button>
                          {expandedTables.has(m.name) && (
                            <div style={{ textAlign: 'left' }}>{renderJsonAsTable(m.value.map((row) => ({ index: row.index, ...row.fields })), 'Таблица пуста.')}</div>
                          )}
                        </>
                      )}
                    </div>
                  ) : m.value !== null ? (
                    String(m.value)
                  ) : (
                    <span className="row-sub">ещё не опрошено</span>
                  )}
                </td>
                <td style={{ whiteSpace: 'nowrap', display: 'flex', alignItems: 'center', gap: '.35rem' }}>
                  {canWrite && (
                    <>
                      <Switch
                        checked={m.effective_enabled}
                        onChange={() => handleToggle(m)}
                        title={m.effective_enabled ? 'Выключить опрос этой метрики на этом устройстве' : 'Включить опрос этой метрики на этом устройстве'}
                      />
                      {m.enabled_override !== null && (
                        <Button
                          variant="ghost"
                          iconOnly
                          small
                          title="Опрос этой метрики настроен вручную, а не профилем — нажмите, чтобы снять override и вернуть дефолт профиля"
                          onClick={() => handleReset(m)}
                        >
                          <Icon name="x-circle" />
                        </Button>
                      )}
                    </>
                  )}
                </td>
              </tr>
              )
            })}
          </tbody>
        </table>
      )}
    </div>
  )
}

/** One rule's resolved neighbors for the device the modal is open on — fetched together
 * with every other configured rule when the modal opens (see `DeviceNeighborsModal`
 * below), not lazily per rule-selection: with a handful of rules this is cheap, and it
 * avoids a second click just to discover a rule has zero neighbors under it. */
interface NeighborsByRule {
  rule: TopologyRule
  neighbors: ResolvedNeighbor[] | null // null = still loading or failed
  error: string
}

/** Roadmap 2026-09-18 finding #3: reachable only from the Topology page or the raw REST
 * endpoint before this — no widget existed on `DevicesPage.tsx` at all. Deliberately
 * self-contained (doesn't import or navigate into `TopologyPage.tsx`, per task scope):
 * calls the same `GET /api/topology/rules/:name/neighbors/:device_id` that page already
 * uses (`topologyRulesApi.neighbors`, `crates/web/src/lib.rs::get_topology_neighbors`).
 *
 * A device can be evaluated against multiple configured `TopologyRule`s at once (each
 * rule is an independent extraction/clustering signal, see `Topology.md`) — minimal UX
 * chosen here is "stack all rules", not a rule-picker: with a handful of rules in
 * practice, fetching all of them up front avoids an extra click just to find out a given
 * rule resolved zero neighbors for this device. */
function DeviceNeighborsModal({
  device,
  onClose,
  onOpenAlertsForDevice,
}: {
  device: DeviceView
  onClose: () => void
  onOpenAlertsForDevice?: (ip: string) => void
}) {
  const [byRule, setByRule] = useState<NeighborsByRule[] | null>(null)
  const [deviceById, setDeviceById] = useState<Record<string, DeviceView>>({})
  const [listError, setListError] = useState('')

  useEffect(() => {
    let cancelled = false
    async function load() {
      let rules: TopologyRule[]
      try {
        // Fetched alongside the rule list, same as `TopologyPage`'s own `deviceIpById` —
        // resolving a neighbor's raw id to something a person recognizes (IP/profile)
        // needs the full device list, not just this one row.
        const [ruleList, page] = await Promise.all([topologyRulesApi.list(), devicesApi.list({ page_size: 1000 })])
        if (cancelled) return
        rules = ruleList
        setDeviceById(Object.fromEntries(page.items.map((d) => [d.id, d])))
      } catch (e) {
        if (!cancelled) setListError(e instanceof ApiHttpError ? e.message : 'Не удалось загрузить правила топологии')
        return
      }
      if (cancelled) return
      if (rules.length === 0) {
        setByRule([])
        return
      }
      const initial: NeighborsByRule[] = rules.map((rule) => ({ rule, neighbors: null, error: '' }))
      setByRule(initial)
      await Promise.all(
        rules.map(async (rule, idx) => {
          try {
            const neighbors = await topologyRulesApi.neighbors(rule.name, device.id)
            if (cancelled) return
            setByRule((prev) => prev?.map((entry, i) => (i === idx ? { ...entry, neighbors } : entry)) ?? prev)
          } catch (e) {
            if (cancelled) return
            const message = e instanceof ApiHttpError ? e.message : 'Не удалось загрузить соседей'
            setByRule((prev) => prev?.map((entry, i) => (i === idx ? { ...entry, neighbors: [], error: message } : entry)) ?? prev)
          }
        }),
      )
    }
    load()
    return () => {
      cancelled = true
    }
  }, [device.id])

  function deviceLabel(id: string): string {
    const dv = deviceById[id]
    return dv ? dv.facts.ip : id
  }

  return (
    <Modal open title={`Топологические соседи: ${device.facts.ip}`} onClose={onClose} wide>
      {listError && (
        <p className="stamp" style={{ color: 'var(--status-critical)' }}>
          {listError}
        </p>
      )}
      {byRule === null ? (
        <p className="stamp">Загрузка…</p>
      ) : byRule.length === 0 ? (
        <p className="stamp" style={{ maxWidth: 'none' }}>
          Правил топологии пока не настроено — соседей показывать неоткуда. Настройте правило на странице «Топология».
        </p>
      ) : (
        <div className="util-col gap-4">
          {byRule.map(({ rule, neighbors, error }) => (
            <div className="util-col gap-2" key={rule.id}>
              <div className="card-header">
                <div className="card-title" style={{ fontSize: '0.95rem' }}>
                  {rule.name} {!rule.enabled && <span className="badge badge-neutral">отключено</span>}
                </div>
              </div>
              {error && (
                <p className="stamp" style={{ color: 'var(--status-critical)' }}>
                  {error}
                </p>
              )}
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Сосед</th>
                      <th>Статус</th>
                      <th>Направление</th>
                    </tr>
                  </thead>
                  <tbody>
                    {neighbors === null ? (
                      <EmptyStateRow colSpan={3} icon="layout" text="Загрузка…" />
                    ) : neighbors.length === 0 ? (
                      <EmptyStateRow colSpan={3} icon="layout" text="По этому правилу соседей не найдено" />
                    ) : (
                      neighbors.map((n) => {
                        const neighborDevice = deviceById[n.neighbor_device_id]
                        return (
                          <tr key={n.neighbor_device_id}>
                            <td>
                              {neighborDevice && onOpenAlertsForDevice ? (
                                <button className="metric-name-btn" title="Открыть тревоги этого соседа" onClick={() => onOpenAlertsForDevice(neighborDevice.facts.ip)}>
                                  {deviceLabel(n.neighbor_device_id)}
                                </button>
                              ) : (
                                deviceLabel(n.neighbor_device_id)
                              )}
                            </td>
                            <td>{n.confirmed ? <Badge severity="info" label="подтверждено" /> : <span className="badge badge-neutral">одностороннее</span>}</td>
                            <td>
                              {n.upstream_device_id ? (
                                <>
                                  {n.upstream_device_id === device.id ? 'это устройство →' : `${deviceLabel(n.upstream_device_id)} →`}{' '}
                                  {n.upstream_device_id === device.id ? deviceLabel(n.neighbor_device_id) : 'это устройство'}
                                  {n.direction_overridden && <Badge severity="warning" label="вручную" />}
                                </>
                              ) : (
                                <span className="row-sub">—</span>
                              )}
                            </td>
                          </tr>
                        )
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          ))}
        </div>
      )}
    </Modal>
  )
}

function toNum(value: MetricHistoryRecord['value']): number | null {
  if (typeof value === 'number') return value
  if (typeof value === 'boolean') return value ? 1 : 0
  return null
}

/** Click-to-open history for one device+metric — added 2026-08-27, the backend endpoint
 * (`GET /api/devices/:id/metrics/:name/history`) already existed and was already in the
 * typed API client, but nothing in this page ever called it. Only metrics whose every
 * *successful* record is numeric/boolean get the chart (matches the design artifact's own
 * rule — string-valued metrics render as a plain table instead, see `numeric` below);
 * error records still plot (at y=0, dashed/red) regardless, since a run can fail either
 * way. */
function MetricHistoryModal({ device, metricName, onClose }: { device: DeviceView; metricName: string; onClose: () => void }) {
  const toast = useToast()
  const [records, setRecords] = useState<MetricHistoryRecord[] | null>(null)
  const [loading, setLoading] = useState(true)
  // Direct user request 2026-08-28: date-range inputs — same `datetime-local` +
  // `localToIso` pattern as Alerts'/Logs' own period filters.
  const [sinceInput, setSinceInput] = useState('')
  const [untilInput, setUntilInput] = useState('')
  const since = localToIso(sinceInput)
  const until = localToIso(untilInput)
  // Direct user request 2026-08-28: auto-refresh here too, but only while the selected
  // window actually includes "now" (blank `until`, or an explicit `until` that isn't
  // already in the past) — a window fixed strictly in the past can never gain new data,
  // so refreshing it on a timer would just be a no-op poll. Off by default, same
  // "interacting with a specific open detail view, not passively watching an overview"
  // reasoning as `DeviceMetricsTable`'s own default.
  const [refreshSecs, setRefreshSecs] = useState(0)
  const includesNow = !untilInput || new Date(untilInput).getTime() >= Date.now()
  // Same "ignore a response older than the most recently issued request" guard as
  // `DevicesPage.load` — editing the date range *and* a periodic tick both call this.
  const requestIdRef = useRef(0)
  // Fix (2026-09-14, direct user request): a table-shaped metric's history (e.g.
  // `if_table`) used to render each row's `value` via plain `String(r.value)` — for an
  // array of row objects that's JS's default `Array.prototype.toString()`, which stringifies
  // each element with `[object Object]` and joins with commas, not useful output. Same
  // collapsed-by-default / expand-per-row treatment as `DeviceMetricsTable`'s own
  // `expandedTables` (`toggleTable` above), just keyed by this record's index instead of
  // metric name — a history list can hold up to 200 records, so auto-expanding every table
  // value at once would be as unreadable as the bug it replaces.
  const [expandedRows, setExpandedRows] = useState<Set<number>>(new Set())
  function toggleRow(i: number) {
    setExpandedRows((prev) => {
      const next = new Set(prev)
      if (next.has(i)) next.delete(i)
      else next.add(i)
      return next
    })
  }

  const fetchHistory = useCallback(async () => {
    const requestId = ++requestIdRef.current
    try {
      const res = await devicesApi.metricHistory(device.id, metricName, { page_size: 200, since, until })
      if (requestId !== requestIdRef.current) return
      setRecords(res.records)
    } catch (e) {
      if (requestId !== requestIdRef.current) return
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось загрузить историю метрики', true)
      setRecords([])
    }
  }, [device.id, metricName, since, until, toast])

  useEffect(() => {
    setLoading(true)
    fetchHistory().finally(() => setLoading(false))
  }, [fetchHistory])

  useEffect(() => {
    if (refreshSecs <= 0 || !includesNow) return
    // No `setLoading(true)` here, unlike the effect above — a background refresh tick
    // shouldn't flash the whole chart to "Загрузка…" every time.
    const id = setInterval(fetchHistory, refreshSecs * 1000)
    return () => clearInterval(id)
  }, [fetchHistory, refreshSecs, includesNow])

  // The store returns newest-first (`ORDER BY last_observed_at DESC`) — a chart reads
  // left-to-right oldest-to-newest.
  const chronological = useMemo(() => (records ? [...records].reverse() : []), [records])
  const numeric = useMemo(
    () => chronological.some((r) => r.error === null && toNum(r.value) !== null) && chronological.every((r) => r.error !== null || toNum(r.value) !== null),
    [chronological],
  )

  return (
    <Modal open title={`История метрики: ${metricName}`} onClose={onClose} wide>
      <p className="stamp" style={{ maxWidth: 'none' }}>
        Устройство {device.facts.ip}. Каждая запись — непрерывный период с одним и тем же значением (или ошибкой); последние {chronological.length} записей.
      </p>
      <div className="filter-bar__row" style={{ marginBottom: 'var(--space-3)' }}>
        <label className="row-sub" htmlFor="metric-history-since">
          Начало
        </label>
        <input id="metric-history-since" className="input" type="datetime-local" title="Нижняя граница периода — пусто, если не задано" value={sinceInput} onChange={(e) => setSinceInput(e.target.value)} />
        <span className="row-sub">—</span>
        <input className="input" type="datetime-local" title="Верхняя граница периода — пусто, если не задано" value={untilInput} onChange={(e) => setUntilInput(e.target.value)} />
        {(sinceInput || untilInput) && (
          <button
            className="btn btn-ghost btn-sm"
            title="Сбросить обе границы периода — показать всю историю"
            onClick={() => {
              setSinceInput('')
              setUntilInput('')
            }}
          >
            <Icon name="x" />
            Сбросить период
          </button>
        )}
        <span className="spacer" />
        <Button variant="ghost" iconOnly small title="Обновить сейчас" onClick={() => fetchHistory()}>
          <Icon name="refresh" />
        </Button>
        <select
          className="select"
          title={includesNow ? 'Период автообновления' : 'Автообновление недоступно — выбранный период целиком в прошлом, новых данных в нём не появится'}
          value={refreshSecs}
          disabled={!includesNow}
          onChange={(e) => setRefreshSecs(Number(e.target.value))}
        >
          <option value={0}>без автообновления</option>
          <option value={1}>каждую 1с</option>
          <option value={3}>каждые 3с</option>
          <option value={5}>каждые 5с</option>
          <option value={10}>каждые 10с</option>
          <option value={30}>каждые 30с</option>
        </select>
      </div>
      {loading ? (
        <p className="stamp">Загрузка…</p>
      ) : chronological.length === 0 ? (
        <p className="stamp">
          {since || until ? 'За выбранный период записей нет.' : 'История ещё не накоплена — метрика пока не опрашивалась достаточно долго.'}
        </p>
      ) : numeric ? (
        <MetricHistoryChart records={chronological} />
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>С</th>
                <th>По</th>
                <th>Значение</th>
              </tr>
            </thead>
            <tbody>
              {chronological
                .slice()
                .reverse()
                .map((r, i) => (
                  <tr key={i}>
                    <td className="row-sub">{fmtDate(r.first_observed_at)}</td>
                    <td className="row-sub">{fmtDate(r.last_observed_at)}</td>
                    <td>
                      {r.error ? (
                        <span className="badge badge-critical">{r.error}</span>
                      ) : r.value !== null && isTableMetricValue(r.value) ? (
                        <div className="util-col gap-1">
                          <button className="metric-name-btn" title="Развернуть/свернуть таблицу" onClick={() => toggleRow(i)}>
                            <Icon name={expandedRows.has(i) ? 'chevron-down' : 'chevron-right'} />
                            {r.value.length} {rowsWord(r.value.length)}
                          </button>
                          {expandedRows.has(i) && (
                            <div style={{ textAlign: 'left' }}>{renderJsonAsTable(r.value.map((row) => ({ index: row.index, ...row.fields })), 'Таблица пуста.')}</div>
                          )}
                        </div>
                      ) : (
                        String(r.value)
                      )}
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      )}
    </Modal>
  )
}

const CHART_W = 680
const CHART_H = 220
const CHART_PAD = { left: 44, right: 12, top: 12, bottom: 28 }

function MetricHistoryChart({ records }: { records: MetricHistoryRecord[] }) {
  const svgRef = useRef<SVGSVGElement>(null)
  const [hover, setHover] = useState<number | null>(null)

  const points = useMemo(() => {
    const times = records.map((r) => new Date(r.last_observed_at).getTime())
    const minT = Math.min(...times)
    const maxT = Math.max(...times)
    const spanT = maxT - minT || 1

    const numericValues = records.map((r) => (r.error === null ? toNum(r.value) : null)).filter((v): v is number => v !== null)
    let minV = numericValues.length > 0 ? Math.min(...numericValues) : 0
    let maxV = numericValues.length > 0 ? Math.max(...numericValues) : 1
    if (records.some((r) => r.error !== null)) minV = Math.min(minV, 0) // error dips plot at 0
    if (minV === maxV) {
      minV -= 1
      maxV += 1
    }
    const spanV = maxV - minV

    const plotW = CHART_W - CHART_PAD.left - CHART_PAD.right
    const plotH = CHART_H - CHART_PAD.top - CHART_PAD.bottom

    return records.map((r, i) => {
      const t = times[i]
      const x = CHART_PAD.left + ((t - minT) / spanT) * plotW
      const v = r.error !== null ? 0 : (toNum(r.value) ?? 0)
      const y = CHART_PAD.top + plotH - ((v - minV) / spanV) * plotH
      return { x, y, record: r, isError: r.error !== null, minV, maxV }
    })
  }, [records])

  function handleMove(e: React.MouseEvent<SVGSVGElement>) {
    const svg = svgRef.current
    if (!svg) return
    const rect = svg.getBoundingClientRect()
    const relX = ((e.clientX - rect.left) / rect.width) * CHART_W
    let closest = 0
    let bestDist = Infinity
    points.forEach((p, i) => {
      const d = Math.abs(p.x - relX)
      if (d < bestDist) {
        bestDist = d
        closest = i
      }
    })
    setHover(closest)
  }

  const minV = points[0]?.minV ?? 0
  const maxV = points[0]?.maxV ?? 1
  const midV = (minV + maxV) / 2
  const first = records[0]
  const last = records[records.length - 1]
  const mid = records[Math.floor(records.length / 2)]

  // One polyline per unbroken run of successful points — an error point breaks the line
  // (drawn separately as a red dot below) rather than being connected through, so a gap
  // in the data reads as a gap, not a false straight-line interpolation across it.
  let linePath = ''
  let penDown = false
  for (const p of points) {
    if (p.isError) {
      penDown = false
      continue
    }
    linePath += `${penDown ? 'L' : 'M'} ${p.x.toFixed(1)} ${p.y.toFixed(1)} `
    penDown = true
  }

  const hoverPoint = hover !== null ? points[hover] : null

  return (
    <div className="mh-chart-wrap">
      <svg ref={svgRef} viewBox={`0 0 ${CHART_W} ${CHART_H}`} onMouseMove={handleMove} onMouseLeave={() => setHover(null)}>
        {/* Y gridlines + labels: max/mid/min */}
        {[
          { v: maxV, y: CHART_PAD.top },
          { v: midV, y: CHART_PAD.top + (CHART_H - CHART_PAD.top - CHART_PAD.bottom) / 2 },
          { v: minV, y: CHART_H - CHART_PAD.bottom },
        ].map((tick, i) => (
          <g key={i}>
            <line className="mh-grid" x1={CHART_PAD.left} y1={tick.y} x2={CHART_W - CHART_PAD.right} y2={tick.y} />
            <text className="mh-axis-label" x={CHART_PAD.left - 6} y={tick.y + 3} textAnchor="end">
              {Number.isInteger(tick.v) ? tick.v : tick.v.toFixed(1)}
            </text>
          </g>
        ))}
        {/* X labels: start/mid/end date */}
        <text className="mh-axis-label" x={CHART_PAD.left} y={CHART_H - 6} textAnchor="start">
          {fmtDate(first.last_observed_at)}
        </text>
        <text className="mh-axis-label" x={(CHART_W + CHART_PAD.left - CHART_PAD.right) / 2} y={CHART_H - 6} textAnchor="middle">
          {fmtDate(mid.last_observed_at)}
        </text>
        <text className="mh-axis-label" x={CHART_W - CHART_PAD.right} y={CHART_H - 6} textAnchor="end">
          {fmtDate(last.last_observed_at)}
        </text>

        <path d={linePath} fill="none" stroke="var(--accent)" strokeWidth={1.75} />
        {points.map((p, i) =>
          p.isError ? (
            <circle key={i} cx={p.x} cy={p.y} r={3} fill="var(--danger)" stroke="var(--danger)" />
          ) : (
            <circle key={i} cx={p.x} cy={p.y} r={2} fill="var(--accent)" />
          ),
        )}

        {hoverPoint && (
          <>
            <line className="mh-cursor" x1={hoverPoint.x} y1={CHART_PAD.top} x2={hoverPoint.x} y2={CHART_H - CHART_PAD.bottom} />
            <circle className="mh-cursor-dot" cx={hoverPoint.x} cy={hoverPoint.y} r={4} fill={hoverPoint.isError ? 'var(--danger)' : 'var(--accent)'} />
            {(() => {
              const label = hoverPoint.isError ? (hoverPoint.record.error ?? '') : String(hoverPoint.record.value)
              const dateLabel = fmtDate(hoverPoint.record.last_observed_at)
              const tipW = Math.max(label.length, dateLabel.length) * 5.4 + 12
              const tipX = Math.min(Math.max(hoverPoint.x - tipW / 2, 2), CHART_W - tipW - 2)
              const tipY = Math.max(hoverPoint.y - 34, 2)
              return (
                <g>
                  <rect className="mh-tip-bg" x={tipX} y={tipY} width={tipW} height={28} rx={3} />
                  <text className="mh-tip-text" x={tipX + 6} y={tipY + 11}>
                    {label}
                  </text>
                  <text className="mh-tip-text" x={tipX + 6} y={tipY + 23} opacity={0.75}>
                    {dateLabel}
                  </text>
                </g>
              )
            })()}
          </>
        )}
      </svg>
    </div>
  )
}
