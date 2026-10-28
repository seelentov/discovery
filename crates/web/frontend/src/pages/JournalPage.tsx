import { useCallback, useEffect, useState } from 'react'
import { journalApi } from '../api/journal'
import { ApiHttpError } from '../api/http'
import { JOURNAL_DOMAIN_LABELS, JOURNAL_DOMAINS, type JournalEntry } from '../api/types'
import { Badge } from '../components/Badge'
import { Button } from '../components/Button'
import { EmptyStateRow } from '../components/EmptyState'
import { Icon } from '../components/Icon'
import { renderJsonAsTable } from '../components/JsonTable'
import { Modal } from '../components/Modal'
import { Pagination } from '../components/Pagination'
import { useToast } from '../hooks/useToast'
import { localToIso } from '../utils/datetime'

type SortBy = 'ts' | 'username' | 'domain' | 'action'
type SortDir = 'asc' | 'desc'

const PAGE_SIZE = 50

function fmtDate(iso: string): string {
  const d = new Date(iso)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

function domainLabel(domain: string): string {
  return (JOURNAL_DOMAIN_LABELS as Record<string, string>)[domain] ?? domain
}

function useDebouncedValue<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const id = setTimeout(() => setDebounced(value), delayMs)
    return () => clearTimeout(id)
  }, [value, delayMs])
  return debounced
}

/** The "Журнал" audit trail page — direct user request: показывает "что за пользователь,
 * в каком домене и что за действие" для каждого сохранённого/удалённого/переключённого
 * ресурса, с фильтрацией/пагинацией/сортировкой/поиском/периодом, аналогично Тревогам/
 * Устройствам/Метрикам. Admin-only (server-enforced — see `require_admin` in
 * `crates/web/src/lib.rs`; `App.tsx`/`Sidebar.tsx` also gate it client-side, same
 * treatment as the Users page). Read-only — there is nothing to create/edit/delete here,
 * every row is written automatically by the server itself. */
export function JournalPage() {
  const toast = useToast()

  const [searchInput, setSearchInput] = useState('')
  const search = useDebouncedValue(searchInput, 300)
  const [domain, setDomain] = useState('')
  const [usernameInput, setUsernameInput] = useState('')
  const username = useDebouncedValue(usernameInput, 300)
  // Unbounded by default (both blank) — this filters an existing record list (the audit
  // trail), not a live tail, same "record list" default `AlertsPage`/`DevicesPage` use —
  // see the `discovery-design-artifact` memory's round-13 note on why that differs from
  // Logs' own bounded-by-default date filter.
  const [sinceInput, setSinceInput] = useState('')
  const [untilInput, setUntilInput] = useState('')
  const since = localToIso(sinceInput)
  const until = localToIso(untilInput)
  const [sortBy, setSortBy] = useState<SortBy>('ts')
  const [sortDir, setSortDir] = useState<SortDir>('desc')
  const [page, setPage] = useState(1)
  const [data, setData] = useState<{ items: JournalEntry[]; total: number } | null>(null)
  const [loading, setLoading] = useState(true)
  // Direct user follow-up request: показывать что было отредактировано (JSON-diff) —
  // same "click to open a modal, JSON rendered as a table" UX as Alerts' Facts column.
  const [detailsTarget, setDetailsTarget] = useState<JournalEntry | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await journalApi.list({
        search: search || undefined,
        domain: domain || undefined,
        username: username || undefined,
        since,
        until,
        sort_by: sortBy,
        sort_dir: sortDir,
        page,
        page_size: PAGE_SIZE,
      })
      setData(res)
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось загрузить журнал', true)
    } finally {
      setLoading(false)
    }
  }, [search, domain, username, since, until, sortBy, sortDir, page, toast])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    setPage(1)
  }, [search, domain, username, since, until, sortBy, sortDir])

  function toggleSort(field: SortBy) {
    if (sortBy !== field) {
      setSortBy(field)
      setSortDir('asc')
    } else if (sortDir === 'asc') {
      setSortDir('desc')
    } else {
      setSortBy('ts')
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

  function resetFilters() {
    setSearchInput('')
    setDomain('')
    setUsernameInput('')
    setSinceInput('')
    setUntilInput('')
  }

  const rows = data?.items ?? []
  const hasFilters = searchInput || domain || usernameInput || sinceInput || untilInput

  return (
    <div className="util-col gap-4">
      <p className="stamp">
        Кто, в каком разделе и что сделал — запись создаётся автоматически при каждом успешном сохранении/удалении/переключении через дашборд или REST API. Только для чтения.
      </p>
      <div className="filter-bar">
        <div className="filter-bar__row">
          <div className="input-icon">
            <Icon name="search" />
            <input className="input" placeholder="пользователь, действие, объект, путь…" value={searchInput} onChange={(e) => setSearchInput(e.target.value)} />
          </div>
          <select className="select" value={domain} onChange={(e) => setDomain(e.target.value)}>
            <option value="">все домены</option>
            {JOURNAL_DOMAINS.map((d) => (
              <option key={d} value={d}>
                {domainLabel(d)}
              </option>
            ))}
          </select>
          <input className="input" style={{ maxWidth: '12rem' }} placeholder="пользователь" value={usernameInput} onChange={(e) => setUsernameInput(e.target.value)} />
          <span className="spacer" />
          <Button variant="ghost" iconOnly small title="Обновить сейчас" onClick={() => load()}>
            <Icon name="refresh" />
          </Button>
        </div>
        <div className="filter-bar__row">
          <label className="row-sub" htmlFor="journal-since">
            Период
          </label>
          <input id="journal-since" className="input" type="datetime-local" value={sinceInput} onChange={(e) => setSinceInput(e.target.value)} />
          <span className="row-sub">—</span>
          <input className="input" type="datetime-local" value={untilInput} onChange={(e) => setUntilInput(e.target.value)} />
          {hasFilters && (
            <button className="btn btn-ghost btn-sm" onClick={resetFilters}>
              <Icon name="x" />
              Сбросить фильтры
            </button>
          )}
        </div>
      </div>

      <div className="table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th className="th-sortable" onClick={() => toggleSort('ts')}>
                Время {sortIndicator('ts')}
              </th>
              <th className="th-sortable" onClick={() => toggleSort('username')}>
                Пользователь {sortIndicator('username')}
              </th>
              <th className="th-sortable" onClick={() => toggleSort('domain')}>
                Домен {sortIndicator('domain')}
              </th>
              <th className="th-sortable" onClick={() => toggleSort('action')}>
                Действие {sortIndicator('action')}
              </th>
              <th>Объект</th>
              <th>Детали</th>
            </tr>
          </thead>
          <tbody>
            {loading && rows.length === 0 ? (
              <EmptyStateRow colSpan={6} icon="history" text="Загрузка…" />
            ) : rows.length === 0 ? (
              <EmptyStateRow colSpan={6} icon="history" text="Записей не найдено" />
            ) : (
              rows.map((e) => (
                <tr key={e.id}>
                  <td className="row-sub mono" style={{ whiteSpace: 'nowrap' }}>
                    {fmtDate(e.ts)}
                  </td>
                  <td>{e.username}</td>
                  <td>
                    <Badge severity="neutral" label={domainLabel(e.domain)} />
                  </td>
                  <td title={`${e.method} ${e.path}`}>{e.action}</td>
                  <td className="mono row-sub">{e.object ?? '—'}</td>
                  <td className="row-sub">
                    {e.details != null ? (
                      <button className="link-more" title="Открыть детали изменения" onClick={() => setDetailsTarget(e)}>
                        <Icon name="external" />
                        детали
                      </button>
                    ) : (
                      '—'
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
      {data && <Pagination page={page} pageSize={PAGE_SIZE} total={data.total} itemCount={rows.length} onPageChange={setPage} />}

      <Modal
        open={detailsTarget !== null}
        title={`Детали${detailsTarget?.object ? `: ${detailsTarget.object}` : ''}`}
        onClose={() => setDetailsTarget(null)}
        wide
        footer={
          <Button variant="ghost" title="Закрыть окно деталей" onClick={() => setDetailsTarget(null)}>
            Закрыть
          </Button>
        }
      >
        {detailsTarget && (
          <div className="util-col gap-3">
            <p className="stamp">{detailsTarget.action}</p>
            {renderJsonAsTable(detailsTarget.details, 'Для этого действия нет дополнительных деталей.')}
          </div>
        )}
      </Modal>
    </div>
  )
}
