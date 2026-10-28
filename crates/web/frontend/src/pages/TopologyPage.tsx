import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiHttpError } from '../api/http'
import { topologyRulesApi } from '../api/topology'
import type { TopologyEdgeView, TopologyRule, TopologyRuleBody } from '../api/types'
import { Badge } from '../components/Badge'
import { Button } from '../components/Button'
import { EmptyStateRow } from '../components/EmptyState'
import { Field } from '../components/Field'
import { Icon } from '../components/Icon'
import { Modal } from '../components/Modal'
import { Pagination } from '../components/Pagination'
import { Switch } from '../components/Switch'
import { useConfirm } from '../hooks/useConfirm'
import { useAuth } from '../hooks/useAuth'
import { useToast } from '../hooks/useToast'

function emptyDraft(): TopologyRuleBody {
  return { id: null, name: '', enabled: true, my_key_expression: '', claimed_neighbors_expression: null, rank_expression: null, watched_metrics: null }
}

/** `watched_metrics` is edited as comma-separated free text, empty = `null` ("auto-detect
 * from both expressions" — see `TopologyRule.watched_metrics`'s docs), same
 * plain-functional editing surface `MaintenanceWindowsPage`'s `profiles`/`device_ids`
 * comma-separated fields already use for a list-of-strings field. */
function parseCsv(s: string): string[] {
  return s
    .split(',')
    .map((v) => v.trim())
    .filter((v) => v.length > 0)
}

type SortBy = 'device_a' | 'device_b' | 'status' | 'direction'
type SortDir = 'asc' | 'desc'
type StatusFilter = 'confirmed' | 'unconfirmed' | ''
type DirectionFilter = 'determined' | 'undetermined' | ''

const PAGE_SIZE = 50

/** Same debounce shape `DevicesPage`/`AlertsPage` each already have their own copy of —
 * search filtering runs server-side per request, so it shouldn't fire on every keystroke. */
function useDebouncedValue<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const id = setTimeout(() => setDebounced(value), delayMs)
    return () => clearTimeout(id)
  }, [value, delayMs])
  return debounced
}

export function TopologyPage() {
  const toast = useToast()
  const confirm = useConfirm()
  const { canWrite } = useAuth()
  const canWriteTopology = canWrite('topology')

  const [rules, setRules] = useState<TopologyRule[] | null>(null)
  const [error, setError] = useState('')
  const [editing, setEditing] = useState<TopologyRuleBody | null>(null)
  const [saving, setSaving] = useState(false)

  const [selectedRule, setSelectedRule] = useState<string>('')

  // Search/filter/sort/pagination for the resolved-edges table (2026-09-18,
  // manual-test-audit finding #5) — same server-side pattern DevicesPage/AlertsPage
  // already use, with the rule selector folded into the same filter panel rather than
  // standing alone as its own widget.
  const [searchInput, setSearchInput] = useState('')
  const search = useDebouncedValue(searchInput, 300)
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('')
  const [directionFilter, setDirectionFilter] = useState<DirectionFilter>('')
  const [sortBy, setSortBy] = useState<SortBy>('device_a')
  const [sortDir, setSortDir] = useState<SortDir>('asc')
  const [page, setPage] = useState(1)

  const [edgesData, setEdgesData] = useState<{ items: TopologyEdgeView[]; total: number } | null>(null)
  const [edgesLoading, setEdgesLoading] = useState(false)
  const [edgesError, setEdgesError] = useState('')

  // Auto-refresh (2026-09-18, manual-test-audit finding #9) — same configurable-period +
  // button pattern DevicesPage/AlertsPage already use. No expandable-row (or similar
  // "currently inspecting a sub-view") state exists on this page to pause it for, unlike
  // DevicesPage's metrics sub-table — a plain periodic reload is enough here. `0` = off —
  // defaulted to off (pre-release audit finding 9, 2026-09-20, direct user request), not
  // 1s: auto-refresh anywhere should be opt-in.
  const [refreshSecs, setRefreshSecs] = useState(0)

  const load = useCallback(async () => {
    try {
      const list = await topologyRulesApi.list()
      setRules(list)
      setError('')
      if (!selectedRule && list.length > 0) setSelectedRule(list[0].name)
    } catch (e) {
      setError(e instanceof ApiHttpError ? e.message : 'Не удалось загрузить правила топологии')
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    load()
  }, [load])

  // Guards against an out-of-order response — same real bug (not hypothetical, see
  // `AlertsPage`'s identical guard's docs) as a slower in-flight request resolving after a
  // newer, differently-filtered one and overwriting fresh data with stale results.
  const requestIdRef = useRef(0)

  const loadEdges = useCallback(async () => {
    if (!selectedRule) {
      setEdgesData(null)
      return
    }
    const requestId = ++requestIdRef.current
    setEdgesLoading(true)
    try {
      const res = await topologyRulesApi.edges(selectedRule, {
        search: search || undefined,
        status: statusFilter || undefined,
        direction: directionFilter || undefined,
        sort_by: sortBy,
        sort_dir: sortDir,
        page,
        page_size: PAGE_SIZE,
      })
      if (requestId !== requestIdRef.current) return
      setEdgesData(res)
      setEdgesError('')
    } catch (e) {
      if (requestId !== requestIdRef.current) return
      setEdgesError(e instanceof ApiHttpError ? e.message : 'Не удалось загрузить связи')
    } finally {
      if (requestId === requestIdRef.current) setEdgesLoading(false)
    }
  }, [selectedRule, search, statusFilter, directionFilter, sortBy, sortDir, page])

  useEffect(() => {
    loadEdges()
  }, [loadEdges])

  useEffect(() => {
    setPage(1)
  }, [selectedRule, search, statusFilter, directionFilter, sortBy, sortDir])

  useEffect(() => {
    if (refreshSecs <= 0) return
    const id = setInterval(() => {
      load()
      loadEdges()
    }, refreshSecs * 1000)
    return () => clearInterval(id)
  }, [load, loadEdges, refreshSecs])

  function toggleSort(field: SortBy) {
    if (sortBy !== field) {
      setSortBy(field)
      setSortDir('asc')
    } else if (sortDir === 'asc') {
      setSortDir('desc')
    } else {
      setSortBy('device_a')
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

  function openCreate() {
    setEditing(emptyDraft())
  }

  function openEdit(r: TopologyRule) {
    setEditing({
      id: r.id,
      name: r.name,
      enabled: r.enabled,
      my_key_expression: r.my_key_expression,
      claimed_neighbors_expression: r.claimed_neighbors_expression,
      rank_expression: r.rank_expression,
      watched_metrics: r.watched_metrics,
    })
  }

  async function handleSave() {
    if (!editing) return
    if (!editing.name.trim()) {
      toast('Укажите название правила', true)
      return
    }
    if (!editing.my_key_expression.trim()) {
      toast('Укажите my_key_expression', true)
      return
    }
    setSaving(true)
    try {
      await topologyRulesApi.upsert({
        ...editing,
        claimed_neighbors_expression: editing.claimed_neighbors_expression?.trim() || null,
        rank_expression: editing.rank_expression?.trim() || null,
      })
      toast(editing.id ? 'Правило топологии сохранено' : 'Правило топологии создано')
      setEditing(null)
      await load()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось сохранить правило', true)
    } finally {
      setSaving(false)
    }
  }

  async function handleDelete(r: TopologyRule) {
    const ok = await confirm(`Удалить правило топологии «${r.name}»?`, { label: 'Удалить', icon: 'trash', danger: true })
    if (!ok) return
    try {
      await topologyRulesApi.delete(r.id)
      toast(`Правило «${r.name}» удалено`)
      if (selectedRule === r.name) setSelectedRule('')
      await load()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось удалить правило', true)
    }
  }

  function deviceLabel(id: string, ip: string | null): string {
    return ip ?? id
  }

  /** `direction` is `''` (clear override — fall back to `rank_expression`, or "—" if that
   * also can't determine it) or one of the two device ids (pin it as upstream). */
  async function handleSetDirection(e: TopologyEdgeView, direction: string) {
    try {
      if (direction === '') {
        await topologyRulesApi.clearHierarchyOverride(selectedRule, e.device_a, e.device_b)
      } else {
        await topologyRulesApi.setHierarchyOverride(selectedRule, e.device_a, e.device_b, direction)
      }
      await loadEdges()
    } catch (err) {
      toast(err instanceof ApiHttpError ? err.message : 'Не удалось изменить направление связи', true)
    }
  }

  const edgeRows = edgesData?.items ?? []

  return (
    <div className="util-col gap-4">
      <div className="card-header">
        <div className="card-title">Правила топологии</div>
        {canWriteTopology && (
          <Button variant="primary" title="Создать новое правило" onClick={openCreate}>
            <Icon name="plus" />
            Создать правило
          </Button>
        )}
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
              <th>Название</th>
              <th>Статус</th>
              <th>my_key_expression</th>
              <th>claimed_neighbors_expression</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {rules === null ? (
              <EmptyStateRow colSpan={5} icon="layout" text="Загрузка…" />
            ) : rules.length === 0 ? (
              <EmptyStateRow colSpan={5} icon="layout" text="Правил топологии пока нет — создайте первое" />
            ) : (
              rules.map((r) => (
                <tr key={r.id}>
                  <td>{r.name}</td>
                  <td>{r.enabled ? <Badge severity="info" label="включено" /> : <span className="badge badge-neutral">отключено</span>}</td>
                  <td className="row-sub" style={{ fontFamily: 'monospace', maxWidth: '20rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {r.my_key_expression}
                  </td>
                  <td className="row-sub" style={{ fontFamily: 'monospace', maxWidth: '20rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {r.claimed_neighbors_expression ?? '—'}
                  </td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    {canWriteTopology && (
                      <>
                        <Button variant="ghost" iconOnly small title="Редактировать" onClick={() => openEdit(r)}>
                          <Icon name="pencil" />
                        </Button>
                        <Button variant="ghost" iconOnly small title="Удалить" onClick={() => handleDelete(r)}>
                          <Icon name="trash" />
                        </Button>
                      </>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="card-header">
        <div className="card-title">Подтверждённые связи</div>
      </div>

      <div className="filter-bar">
        <div className="filter-bar__row">
          <select className="select" title="Правило топологии" value={selectedRule} onChange={(e) => setSelectedRule(e.target.value)} disabled={!rules || rules.length === 0}>
            {(rules ?? []).map((r) => (
              <option key={r.name} value={r.name}>
                {r.name}
              </option>
            ))}
          </select>
          <div className="input-icon">
            <Icon name="search" />
            <input className="input" placeholder="IP устройства A или B…" title="Поиск по IP любой из сторон связи" value={searchInput} onChange={(e) => setSearchInput(e.target.value)} />
          </div>
          <select className="select" title="Показать только связи с этим статусом" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value as StatusFilter)}>
            <option value="">все статусы</option>
            <option value="confirmed">подтверждено</option>
            <option value="unconfirmed">одностороннее</option>
          </select>
          <select className="select" title="Показать только связи с этим направлением" value={directionFilter} onChange={(e) => setDirectionFilter(e.target.value as DirectionFilter)}>
            <option value="">все направления</option>
            <option value="determined">направление определено</option>
            <option value="undetermined">направление не определено</option>
          </select>
          <span className="spacer" />
          <Button
            variant="ghost"
            iconOnly
            small
            title="Обновить сейчас"
            onClick={() => {
              load()
              loadEdges()
            }}
          >
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
        </div>
      </div>

      {edgesError && (
        <p className="stamp" style={{ color: 'var(--status-critical)' }}>
          {edgesError}
        </p>
      )}

      <div className="table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th className="th-sortable" onClick={() => toggleSort('device_a')}>
                Устройство A {sortIndicator('device_a')}
              </th>
              <th className="th-sortable" onClick={() => toggleSort('device_b')}>
                Устройство B {sortIndicator('device_b')}
              </th>
              <th className="th-sortable" onClick={() => toggleSort('status')}>
                Статус {sortIndicator('status')}
              </th>
              <th className="th-sortable" onClick={() => toggleSort('direction')}>
                Направление {sortIndicator('direction')}
              </th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {!selectedRule ? (
              <EmptyStateRow colSpan={5} icon="layout" text="Выберите правило" />
            ) : edgesLoading && edgeRows.length === 0 ? (
              <EmptyStateRow colSpan={5} icon="layout" text="Загрузка…" />
            ) : edgeRows.length === 0 ? (
              <EmptyStateRow colSpan={5} icon="layout" text="По этому фильтру не найдено ни одной связи" />
            ) : (
              edgeRows.map((e, idx) => (
                <tr key={idx}>
                  <td>{deviceLabel(e.device_a, e.device_a_ip)}</td>
                  <td>{deviceLabel(e.device_b, e.device_b_ip)}</td>
                  <td>{e.confirmed ? <Badge severity="info" label="подтверждено" /> : <span className="badge badge-neutral">одностороннее</span>}</td>
                  <td>
                    {e.upstream_device_id ? (
                      <>
                        {deviceLabel(e.upstream_device_id, e.upstream_device_id === e.device_a ? e.device_a_ip : e.device_b_ip)} →{' '}
                        {deviceLabel(e.upstream_device_id === e.device_a ? e.device_b : e.device_a, e.upstream_device_id === e.device_a ? e.device_b_ip : e.device_a_ip)}
                        {e.direction_overridden && <Badge severity="warning" label="вручную" />}
                      </>
                    ) : (
                      <span className="row-sub">—</span>
                    )}
                  </td>
                  <td>
                    {canWriteTopology && (
                      <select className="input" value={e.direction_overridden ? (e.upstream_device_id ?? '') : ''} onChange={(ev) => handleSetDirection(e, ev.target.value)} title="Задать направление вручную">
                        <option value="">Авто (по рангу)</option>
                        <option value={e.device_a}>
                          {deviceLabel(e.device_a, e.device_a_ip)} → {deviceLabel(e.device_b, e.device_b_ip)}
                        </option>
                        <option value={e.device_b}>
                          {deviceLabel(e.device_b, e.device_b_ip)} → {deviceLabel(e.device_a, e.device_a_ip)}
                        </option>
                      </select>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
      {edgesData && <Pagination page={page} pageSize={PAGE_SIZE} total={edgesData.total} itemCount={edgeRows.length} onPageChange={setPage} />}

      {canWriteTopology && <Modal
        open={editing !== null}
        title={editing?.id ? 'Редактировать правило топологии' : 'Новое правило топологии'}
        wide
        onClose={() => setEditing(null)}
        footer={
          <>
            <Button variant="ghost" onClick={() => setEditing(null)}>
              Отмена
            </Button>
            <Button variant="primary" onClick={handleSave} disabled={saving}>
              {saving ? 'Сохранение…' : 'Сохранить'}
            </Button>
          </>
        }
      >
        {editing && (
          <div className="form-grid">
            <Field label="Название" wide>
              <input className="input" value={editing.name} onChange={(e) => setEditing({ ...editing, name: e.target.value })} placeholder="lldp" />
            </Field>
            <Field label="Включено">
              <Switch checked={editing.enabled} onChange={(v) => setEditing({ ...editing, enabled: v })} title="Включено" />
            </Field>

            <Field label="my_key_expression" wide hint="Rhai-выражение: как устройству называть себя под этим правилом (например metrics.lldp_chassis_id)">
              <textarea
                className="input"
                rows={2}
                style={{ fontFamily: 'monospace' }}
                value={editing.my_key_expression}
                onChange={(e) => setEditing({ ...editing, my_key_expression: e.target.value })}
                placeholder="metrics.lldp_chassis_id"
              />
            </Field>

            <Field label="claimed_neighbors_expression" wide hint="Rhai-выражение: список ключей соседей, которых устройство заявляет (пусто = правило только кластеризует по my_key)">
              <textarea
                className="input"
                rows={2}
                style={{ fontFamily: 'monospace' }}
                value={editing.claimed_neighbors_expression ?? ''}
                onChange={(e) => setEditing({ ...editing, claimed_neighbors_expression: e.target.value })}
                placeholder="metrics.lldp_rem_table.map(|row| row.chassis_id)"
              />
            </Field>

            <Field
              label="rank_expression"
              wide
              hint="Rhai-выражение: числовой уровень иерархии устройства под этим правилом. Меньше = ближе к ядру/аплинк. Пусто = правило не участвует в иерархии — направление связи останется неопределённым, если не задано вручную"
            >
              <textarea
                className="input"
                rows={2}
                style={{ fontFamily: 'monospace' }}
                value={editing.rank_expression ?? ''}
                onChange={(e) => setEditing({ ...editing, rank_expression: e.target.value })}
                placeholder='facts.role == "core" ? 0 : 1'
              />
            </Field>

            <Field label="Отслеживаемые метрики" wide hint="Через запятую — какие метрики триггерят пересбор при опросе. Пусто = определить автоматически из выражений выше">
              <input
                className="input"
                value={(editing.watched_metrics ?? []).join(', ')}
                onChange={(e) => {
                  const parsed = parseCsv(e.target.value)
                  setEditing({ ...editing, watched_metrics: parsed.length > 0 ? parsed : null })
                }}
                placeholder="lldp_chassis_id, lldp_rem_table"
              />
            </Field>
          </div>
        )}
      </Modal>}
    </div>
  )
}
