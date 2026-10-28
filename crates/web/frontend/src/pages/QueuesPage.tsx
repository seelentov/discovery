import { Fragment, useCallback, useEffect, useState } from 'react'
import { queuesApi } from '../api/queues'
import { ApiHttpError } from '../api/http'
import type { Job, JobStateParam, QueueStatsView, WorkerActivity } from '../api/types'
import { Badge, type Severity } from '../components/Badge'
import { Button } from '../components/Button'
import { EmptyStateBlock, EmptyStateRow } from '../components/EmptyState'
import { Icon } from '../components/Icon'
import { Pagination } from '../components/Pagination'
import { useConfirm } from '../hooks/useConfirm'
import { useAuth } from '../hooks/useAuth'
import { useToast } from '../hooks/useToast'

const PAGE_SIZE = 20

function fmtDate(iso: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(d.getDate())}.${pad(d.getMonth() + 1)} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

function jobStateSeverity(state: string): Severity {
  switch (state) {
    case 'Failed':
      return 'critical'
    case 'InProgress':
      return 'info'
    default:
      return 'neutral'
  }
}

export function QueuesPage() {
  const toast = useToast()
  const confirm = useConfirm()
  const { canWrite } = useAuth()
  const canWriteJobs = canWrite('jobs')
  const [queues, setQueues] = useState<QueueStatsView[] | null>(null)
  const [workers, setWorkers] = useState<WorkerActivity[]>([])
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  // Direct user request 2026-08-28: this page always auto-refreshed, but on a hardcoded
  // 3s interval with no manual "Обновить" button and no way to change the period — same
  // configurable pattern `AlertsPage` already has. Defaulted to off (`0`, pre-release
  // audit finding 9, 2026-09-20, direct user request) — auto-refresh anywhere should be
  // opt-in, not a surprise background poll from the first page load.
  const [refreshSecs, setRefreshSecs] = useState(0)

  const load = useCallback(async () => {
    try {
      const [q, w] = await Promise.all([queuesApi.list(), queuesApi.workers()])
      setQueues(q)
      setWorkers(w)
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось загрузить очереди', true)
    }
  }, [toast])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    if (refreshSecs <= 0) return
    const id = setInterval(load, refreshSecs * 1000)
    return () => clearInterval(id)
  }, [load, refreshSecs])

  function toggleExpanded(kind: string) {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(kind)) next.delete(kind)
      else next.add(kind)
      return next
    })
  }

  async function handleTogglePaused(kind: string, paused: boolean) {
    try {
      await queuesApi.setPaused(kind, paused)
      toast(paused ? `Очередь «${kind}» приостановлена` : `Очередь «${kind}» возобновлена`)
      load()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось изменить очередь', true)
    }
  }

  async function handleClearQueue(kind: string) {
    const ok = await confirm(`Удалить ВСЕ задачи из очереди «${kind}»? Действие необратимо.`, { label: 'Очистить', icon: 'trash' })
    if (!ok) return
    try {
      const res = await queuesApi.clear(kind)
      toast(`Удалено задач: ${res.deleted}`)
      load()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось очистить очередь', true)
    }
  }

  return (
    <div className="util-col gap-4">
      <div className="filter-bar">
        <div className="filter-bar__row">
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
        </div>
      </div>
      <div className="table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th></th>
              <th>Очередь</th>
              <th className="num">Pending</th>
              <th className="num">In progress</th>
              <th className="num">Failed</th>
              <th className="num">Paused</th>
              <th>Управление</th>
            </tr>
          </thead>
          <tbody>
            {queues === null ? (
              <EmptyStateRow colSpan={7} icon="stack" text="Загрузка…" />
            ) : (
              queues.map((q) => {
                const isExpanded = expanded.has(q.queue)
                return (
                  <Fragment key={q.queue}>
                    <tr>
                      <td>
                        <button className={isExpanded ? 'expand-btn row-expanded' : 'expand-btn'} onClick={() => toggleExpanded(q.queue)}>
                          <Icon name="chevron-right" />
                        </button>
                      </td>
                      <td>
                        <span className="mono">{q.queue}</span>{' '}
                        {q.stats.queue_paused && <span className="badge badge-neutral">на паузе</span>}
                      </td>
                      <td className="num tnum">{q.stats.pending}</td>
                      <td className="num tnum">{q.stats.in_progress}</td>
                      <td className="num tnum">{q.stats.failed > 0 ? <Badge severity="critical" label={String(q.stats.failed)} /> : q.stats.failed}</td>
                      <td className="num tnum">{q.stats.paused}</td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        {canWriteJobs && (
                          <>
                            <Button variant="ghost" iconOnly small title={q.stats.queue_paused ? 'Возобновить очередь' : 'Приостановить очередь'} onClick={() => handleTogglePaused(q.queue, !q.stats.queue_paused)}>
                              <Icon name={q.stats.queue_paused ? 'play' : 'pause'} />
                            </Button>
                            {q.queue !== 'operator_action' && <Button variant="danger" iconOnly small title="Удалить все задачи из очереди" onClick={() => handleClearQueue(q.queue)}>
                              <Icon name="trash" />
                            </Button>}
                          </>
                        )}
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr className="queue-detail-row">
                        <td colSpan={7}>
                          <QueueJobsPanel kind={q.queue} onChanged={load} canWrite={canWriteJobs} />
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

      <h3 className="section-title">Воркеры — что сейчас выполняется</h3>
      <div className="table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th>Worker</th>
              <th>Очередь</th>
              <th>Задача</th>
              <th>С какого момента</th>
            </tr>
          </thead>
          <tbody>
            {workers.length === 0 ? (
              <EmptyStateRow colSpan={4} icon="stack" text="Нет активных воркеров" />
            ) : (
              workers.map((w, i) => (
                <tr key={i}>
                  <td className="mono">{w.worker_id}</td>
                  <td className="mono row-sub">{w.queue}</td>
                  <td>{w.current_job_summary ?? <span className="row-sub">простаивает</span>}</td>
                  <td className="row-sub">{fmtDate(w.started_at)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function QueueJobsPanel({ kind, onChanged, canWrite }: { kind: string; onChanged: () => void; canWrite: boolean }) {
  const toast = useToast()
  const confirm = useConfirm()
  const [search, setSearch] = useState('')
  const [state, setState] = useState<JobStateParam | ''>('')
  const [sortBy, setSortBy] = useState<'updated_at' | 'created_at' | 'id' | 'attempts'>('updated_at')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')
  const [page, setPage] = useState(1)
  const [data, setData] = useState<{ jobs: Job[]; total: number } | null>(null)

  const load = useCallback(async () => {
    try {
      const res = await queuesApi.jobs(kind, {
        search: search || undefined,
        state: state || undefined,
        sort_by: sortBy,
        sort_dir: sortDir,
        page,
        page_size: PAGE_SIZE,
      })
      setData(res)
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось загрузить задачи', true)
    }
  }, [kind, search, state, sortBy, sortDir, page, toast])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    setPage(1)
  }, [search, state, sortBy, sortDir])

  async function handleTogglePaused(job: Job) {
    try {
      if (job.paused) await queuesApi.resumeJob(kind, job.id)
      else await queuesApi.pauseJob(kind, job.id)
      load()
      onChanged()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось изменить задачу', true)
    }
  }

  async function handleDelete(job: Job) {
    const ok = await confirm(`Удалить задачу #${job.id}?`, { label: 'Удалить', icon: 'trash' })
    if (!ok) return
    try {
      await queuesApi.deleteJob(kind, job.id)
      load()
      onChanged()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось удалить задачу', true)
    }
  }

  const rows = data?.jobs ?? []

  return (
    <div className="util-col gap-2">
      <div className="filter-bar__row">
        <div className="input-icon">
          <Icon name="search" />
          <input className="input" placeholder="поиск (id/данные/ошибка)" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
        <select className="select" value={state} onChange={(e) => setState(e.target.value as JobStateParam | '')}>
          <option value="">все состояния</option>
          <option value="pending">pending</option>
          <option value="in_progress">in_progress</option>
          <option value="failed">failed</option>
          {kind === 'operator_action' && <option value="done">done</option>}
          {kind === 'operator_action' && <option value="cancelled">cancelled</option>}
        </select>
        <select className="select" value={sortBy} onChange={(e) => setSortBy(e.target.value as typeof sortBy)}>
          <option value="updated_at">сорт.: обновлено</option>
          <option value="created_at">сорт.: создано</option>
          <option value="id">сорт.: ID</option>
          <option value="attempts">сорт.: попытки</option>
        </select>
        <button className="btn btn-ghost btn-sm" onClick={() => setSortDir(sortDir === 'asc' ? 'desc' : 'asc')}>
          <Icon name={sortDir === 'asc' ? 'arrow-up' : 'arrow-down'} />
        </button>
      </div>
      {rows.length === 0 ? (
        <div className="job-empty">
          <EmptyStateBlock icon="stack" text="Записей нет" />
        </div>
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Состояние</th>
                <th>Данные</th>
                <th>Попытки</th>
                <th>Ошибка</th>
                <th>Обновлено</th>
                <th>Действия</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((j) => (
                <tr key={j.id} style={j.paused ? { opacity: 0.6 } : undefined}>
                  <td className="mono">{j.id}</td>
                  <td>
                    <Badge severity={jobStateSeverity(j.state)} label={j.state} />
                    {j.paused && <span className="badge badge-neutral">пауза</span>}
                  </td>
                  <td className="mono row-sub" style={{ maxWidth: '22rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={JSON.stringify(j.payload)}>
                    {JSON.stringify(j.payload)}
                  </td>
                  <td className="num tnum">
                    {j.attempts}/{j.max_attempts}
                  </td>
                  <td className="row-sub" style={{ maxWidth: '16rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={j.last_error ?? ''}>
                    {j.last_error ?? '—'}
                  </td>
                  <td className="row-sub">{fmtDate(j.updated_at)}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    {canWrite && kind !== 'operator_action' && (
                      <>
                        <Button variant="ghost" iconOnly small title={j.paused ? 'Возобновить' : 'Приостановить'} onClick={() => handleTogglePaused(j)}>
                          <Icon name={j.paused ? 'play' : 'pause'} />
                        </Button>
                        <Button variant="ghost" iconOnly small title="Удалить" onClick={() => handleDelete(j)}>
                          <Icon name="trash" />
                        </Button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {data && <Pagination page={page} pageSize={PAGE_SIZE} total={data.total} itemCount={rows.length} onPageChange={setPage} />}
    </div>
  )
}
