import { useCallback, useEffect, useState } from 'react'
import { alertsApi } from '../api/alerts'
import { devicesApi } from '../api/devices'
import { ApiHttpError } from '../api/http'
import { queuesApi } from '../api/queues'
import type { Alert, QueueStatsView, WorkerActivity } from '../api/types'
import { Badge } from '../components/Badge'
import { EmptyStateBlock } from '../components/EmptyState'
import { Icon, type IconName } from '../components/Icon'
import type { PageId } from '../layout/pages'
import { useToast } from '../hooks/useToast'

function fmtDate(iso: string): string {
  const d = new Date(iso)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(d.getDate())}.${pad(d.getMonth() + 1)} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

function StatTile({ icon, label, value, meta, onClick }: { icon: IconName; label: string; value: string | number; meta?: string; onClick?: () => void }) {
  return (
    <div className={onClick ? 'stat-tile clickable' : 'stat-tile'} onClick={onClick} role={onClick ? 'button' : undefined} tabIndex={onClick ? 0 : undefined}>
      <div className="stat-tile__top">
        <span className="stat-tile__label">{label}</span>
        <span className="stat-tile__icon">
          <Icon name={icon} />
        </span>
      </div>
      <span className="stat-tile__value">{value}</span>
      {meta && <span className="stat-tile__meta">{meta}</span>}
    </div>
  )
}

export function OverviewPage({
  onNavigate,
  onOpenActiveAlerts,
}: {
  onNavigate: (page: PageId) => void
  /** Direct user request 2026-08-28: "при нажатии на обзоре на активные тревоги видеть
   * только активные а не все" — this tile/panel's own data is already active-only
   * (`alertsApi.incidents()`, the live in-memory active set), but a plain `onNavigate`
   * used to land on Alerts completely unfiltered. */
  onOpenActiveAlerts: () => void
}) {
  const toast = useToast()
  const [incidents, setIncidents] = useState<Alert[] | null>(null)
  const [deviceTotal, setDeviceTotal] = useState<number | null>(null)
  const [deviceErrors, setDeviceErrors] = useState<number | null>(null)
  const [queues, setQueues] = useState<QueueStatsView[] | null>(null)
  const [workers, setWorkers] = useState<WorkerActivity[]>([])

  const load = useCallback(async () => {
    try {
      const [inc, devPage, errPage, q, w] = await Promise.all([
        alertsApi.incidents(),
        devicesApi.list({ page: 1, page_size: 1 }),
        devicesApi.list({ page: 1, page_size: 1, has_error: true }),
        queuesApi.list(),
        queuesApi.workers(),
      ])
      setIncidents(inc)
      setDeviceTotal(devPage.total)
      setDeviceErrors(errPage.total)
      setQueues(q)
      setWorkers(w)
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось загрузить обзор', true)
    }
  }, [toast])

  useEffect(() => {
    load()
    // 1000ms, not the old 5000ms — 2026-09-17 audit finding #9: Обзор is the most likely
    // first place an operator looks when something might be wrong, but its 5s poll
    // (unlike every other live page in this app — Тревоги/Устройства default to 1s,
    // user-adjustable) meant a just-activated alert could still show a false "всё чисто"
    // for up to 5 real seconds after `/api/alerts`/a device's `active_alert_count` had
    // already picked it up. Matches the rest of the app's own established default instead
    // of a bespoke slower one — no backend change needed, `GET /api/incidents` itself was
    // always current the instant it was actually fetched (see that handler's docs).
    const id = setInterval(load, 1000)
    return () => clearInterval(id)
  }, [load])

  const critical = incidents?.filter((a) => a.level === 'Critical').length ?? 0
  const warning = incidents?.filter((a) => a.level === 'Warning').length ?? 0
  const pendingTotal = queues?.reduce((sum, q) => sum + q.stats.pending + q.stats.in_progress, 0) ?? 0
  const failedTotal = queues?.reduce((sum, q) => sum + q.stats.failed, 0) ?? 0

  return (
    <div className="util-col gap-4">
      <div className="stat-grid">
        <StatTile icon="bell" label="Активные тревоги" value={incidents?.length ?? '—'} meta={`критических: ${critical} · warning: ${warning}`} onClick={onOpenActiveAlerts} />
        <StatTile
          icon="router"
          label="Устройств под мониторингом"
          value={deviceTotal ?? '—'}
          meta={deviceErrors ? `с ошибками: ${deviceErrors}` : 'ошибок нет'}
          onClick={() => onNavigate('devices')}
        />
        <StatTile icon="stack" label="Задач в очередях" value={pendingTotal} meta={failedTotal > 0 ? `failed: ${failedTotal}` : 'failed: 0'} onClick={() => onNavigate('queues')} />
        <StatTile icon="command" label="Активных воркеров" value={workers.length} meta={workers.length > 0 ? 'выполняют задачи' : 'простаивают'} onClick={() => onNavigate('queues')} />
      </div>

      <div className="two-col">
        <div className="card card-pad">
          <div className="card-header">
            <div className="card-title">Активные тревоги</div>
            <button className="link-more" onClick={onOpenActiveAlerts}>
              Все тревоги
              <Icon name="arrow-right" />
            </button>
          </div>
          {incidents === null ? (
            <p className="stamp">Загрузка…</p>
          ) : incidents.length === 0 ? (
            <EmptyStateBlock icon="check-circle" text="Активных тревог нет" />
          ) : (
            <div className="mini-list">
              {incidents.slice(0, 10).map((a) => (
                <div className="mini-list__row clickable" key={a.id} onClick={onOpenActiveAlerts}>
                  <Badge severity={a.level === 'Critical' ? 'critical' : a.level === 'Warning' ? 'warning' : 'info'} label={a.level} />
                  <div className="txt">
                    <div className="t1">
                      {a.name} · {a.device_ip}
                    </div>
                    <div className="t2">{a.message}</div>
                  </div>
                  <span className="row-sub">{fmtDate(a.last_seen)}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="card card-pad">
          <div className="card-header">
            <div className="card-title">Очереди</div>
            <button className="link-more" onClick={() => onNavigate('queues')}>
              Все очереди
              <Icon name="arrow-right" />
            </button>
          </div>
          {queues === null ? (
            <p className="stamp">Загрузка…</p>
          ) : (
            <div className="mini-list">
              {queues.map((q) => (
                <div className="mini-list__row clickable" key={q.queue} onClick={() => onNavigate('queues')}>
                  <div className="txt">
                    <div className="t1 mono">{q.queue}</div>
                    <div className="t2">
                      pending {q.stats.pending} · in progress {q.stats.in_progress}
                    </div>
                  </div>
                  {q.stats.failed > 0 ? <Badge severity="critical" label={`failed ${q.stats.failed}`} /> : <span className="row-sub">ok</span>}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
