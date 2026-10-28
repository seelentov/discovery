import { useCallback, useEffect, useState } from 'react'
import { logsApi } from '../api/logs'
import { ApiHttpError } from '../api/http'
import type { LogEntry } from '../api/types'
import { Badge, type Severity } from '../components/Badge'
import { EmptyStateRow } from '../components/EmptyState'
import { Icon } from '../components/Icon'
import { Pagination } from '../components/Pagination'
import { useToast } from '../hooks/useToast'
import { localToIso, toLocalInputValue } from '../utils/datetime'

const PAGE_SIZE = 50

const LEVEL_OPTIONS = [
  { value: '', label: 'все' },
  { value: 'error', label: 'error+' },
  { value: 'warn', label: 'warn+' },
  { value: 'info', label: 'info+' },
  { value: 'debug', label: 'debug+' },
  { value: 'trace', label: 'trace+' },
]

function levelSeverity(level: string): Severity {
  switch (level.toUpperCase()) {
    case 'ERROR':
      return 'critical'
    case 'WARN':
      return 'warning'
    case 'INFO':
      return 'info'
    default:
      return 'neutral'
  }
}

function fmtTime(iso: string): string {
  const d = new Date(iso)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(d.getDate())}.${pad(d.getMonth() + 1)} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

function last24hRange(): { since: string; until: string } {
  const now = new Date()
  const yesterday = new Date(now.getTime() - 24 * 3600 * 1000)
  return { since: toLocalInputValue(yesterday), until: toLocalInputValue(now) }
}

export function LogsPage() {
  const toast = useToast()

  const [level, setLevel] = useState('info')
  const [target, setTarget] = useState('')
  const [search, setSearch] = useState('')
  // Bounded-by-default (last 24h) — this is a query/tail-style view, not a record list;
  // see the artifact's round-13 note (`discovery-design-artifact` memory) on why that's
  // the right default here, unlike Devices/Alerts' own unbounded-by-default date filters.
  const [{ since: sinceInput, until: untilInput }, setRange] = useState(last24hRange)
  const [liveTail, setLiveTail] = useState(true)
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')
  const [page, setPage] = useState(1)
  const [data, setData] = useState<{ items: LogEntry[]; total: number } | null>(null)
  const [loading, setLoading] = useState(true)

  const since = localToIso(sinceInput)
  const until = liveTail ? undefined : localToIso(untilInput)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await logsApi.list({
        level: level || undefined,
        target: target || undefined,
        search: search || undefined,
        since,
        until,
        sort_dir: sortDir,
        page,
        page_size: PAGE_SIZE,
      })
      setData(res)
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось загрузить логи', true)
    } finally {
      setLoading(false)
    }
  }, [level, target, search, since, until, sortDir, page, toast])

  useEffect(() => {
    load()
    // Живой хвост — обновляем раз в 3с, пока страница открыта (в памяти агента, не
    // персистентно — см. LogBuffer). Не 1.5с как в старом дашборде: пагинация/фильтры
    // на этой странице обычно листаются руками, слишком частый автообновление сбивало
    // бы прокрутку.
    const id = setInterval(load, 3000)
    return () => clearInterval(id)
  }, [load])

  useEffect(() => {
    setPage(1)
  }, [level, target, search, since, until, sortDir])

  function resetFilters() {
    setLevel('info')
    setTarget('')
    setSearch('')
    setRange(last24hRange())
    setLiveTail(true)
  }

  const rows = data?.items ?? []

  return (
    <div className="util-col gap-4">
      <div className="filter-bar">
        <div className="filter-bar__row">
          <select className="select" value={level} onChange={(e) => setLevel(e.target.value)}>
            {LEVEL_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
          <input className="input" style={{ maxWidth: '14rem' }} placeholder="цель (discovery_agent...)" value={target} onChange={(e) => setTarget(e.target.value)} />
          <div className="input-icon">
            <Icon name="search" />
            <input className="input" placeholder="поиск по сообщению" value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
          <span className="spacer" />
          <button className="btn btn-ghost btn-sm" onClick={() => setSortDir(sortDir === 'asc' ? 'desc' : 'asc')}>
            <Icon name={sortDir === 'asc' ? 'arrow-up' : 'arrow-down'} />
            {sortDir === 'asc' ? 'старые сверху' : 'новые сверху'}
          </button>
        </div>
        <div className="filter-bar__row">
          <label className="row-sub" htmlFor="logs-since">
            Период
          </label>
          <input id="logs-since" className="input" type="datetime-local" value={sinceInput} onChange={(e) => setRange({ since: e.target.value, until: untilInput })} />
          <span className="row-sub">—</span>
          <input
            className="input"
            type="datetime-local"
            value={untilInput}
            onChange={(e) => {
              setRange({ since: sinceInput, until: e.target.value })
              setLiveTail(false)
            }}
          />
          <button className="btn btn-ghost btn-sm" onClick={resetFilters}>
            <Icon name="refresh" />
            Сбросить фильтры
          </button>
        </div>
      </div>

      <p className="stamp">Живой хвост записей в памяти агента — обнуляется при рестарте. Полная история пишется в лог-файл процесса.</p>

      <div className="table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th style={{ whiteSpace: 'nowrap' }}>Время</th>
              <th>Уровень</th>
              <th>Цель</th>
              <th>Сообщение</th>
            </tr>
          </thead>
          <tbody>
            {loading && rows.length === 0 ? (
              <EmptyStateRow colSpan={4} icon="terminal" text="Загрузка…" />
            ) : rows.length === 0 ? (
              <EmptyStateRow colSpan={4} icon="terminal" text="Нет записей под текущий фильтр" />
            ) : (
              rows.map((l, i) => (
                <tr key={i}>
                  <td className="row-sub mono" style={{ whiteSpace: 'nowrap' }}>
                    {fmtTime(l.timestamp)}
                  </td>
                  <td>
                    <Badge severity={levelSeverity(l.level)} label={l.level} />
                  </td>
                  <td className="mono row-sub">{l.target}</td>
                  <td>
                    {l.message}
                    {Object.keys(l.fields).length > 0 && (
                      <div className="row-sub mono" style={{ fontSize: '.7rem' }}>
                        {Object.entries(l.fields)
                          .map(([k, v]) => `${k}=${v}`)
                          .join(' ')}
                      </div>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
      {data && <Pagination page={page} pageSize={PAGE_SIZE} total={data.total} itemCount={rows.length} onPageChange={setPage} />}
    </div>
  )
}
