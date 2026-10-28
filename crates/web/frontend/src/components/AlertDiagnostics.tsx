import { useEffect, useState } from 'react'
import type { Alert, AlertRuleStatus } from '../api/types'
import { alertsApi } from '../api/alerts'
import { devicesApi, type OperatorActionJob } from '../api/devices'
import { Button } from './Button'
import { Modal } from './Modal'
import { useAuth } from '../hooks/useAuth'

export function AlertDiagnostics({ alert, onClose }: { alert: Alert | null; onClose: () => void }) {
  const [statuses, setStatuses] = useState<AlertRuleStatus[]>([])
  const [jobs, setJobs] = useState<OperatorActionJob[]>([])
  const [error, setError] = useState('')
  const { canRead, canWrite } = useAuth()
  const deviceRead = canRead('devices')
  useEffect(() => {
    if (!alert) return
    let cancelled = false
    const load = async () => {
      try {
        const statuses = await alertsApi.ruleStatuses(alert.device_id)
        const jobs = deviceRead ? await devicesApi.listActions(alert.device_id) : []
        if (!cancelled) { setError(''); setStatuses(statuses.filter(s => s.name === alert.name)); setJobs(jobs.filter(j => j.alert_id === alert.id)) }
      } catch (e) { if (!cancelled) setError(String(e)) }
    }
    void load()
    const timer = setInterval(() => void load(), 3000)
    return () => { cancelled = true; clearInterval(timer) }
  }, [alert, deviceRead])
  return <Modal open={!!alert} title="Диагностика тревоги" wide onClose={onClose}>
    {error && <p role="alert">{error}</p>}
    {alert && <>
      <h4>{alert.name} · {alert.device_ip}</h4>
      {alert.details?.response_escalated && <p role="status">Эскалация: {alert.details.response_escalation_reason}</p>}
      <h4>Причина и восстановление</h4><pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(alert.details, null, 2)}</pre>
      <h4>Состояние правила</h4>
      {statuses.map(s => <div key={s.row_key ?? ''} className="card card-pad">
        <strong>{s.row_key ?? 'Устройство'}: {s.state}</strong>
        {s.error && <p role="alert">{s.error}</p>}
        <p>Проверено: {s.checked_at}. Следующая проверка: {s.next_check_at ?? 'при обновлении данных'}.</p>
        <p>Активация: {s.activation_since ?? 'нет таймера'} / {s.activate_after_seconds} с. Восстановление: {s.recovery_since ?? 'нет таймера'} / {s.clear_after_seconds} с.</p>
        {s.events_required > 0 && <p>События: {s.event_count} / {s.events_required} за {s.window_seconds} с.</p>}
        <pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify({ value: s.value, previous: s.previous_value, lower: s.lower_bound, upper: s.upper_bound, flapping: s.flapping }, null, 2)}</pre>
      </div>)}
      {canWrite('alerts') && canWrite('devices') && (alert.details?.policy.interactive_actions ?? []).map(action => <Button key={action} onClick={() => { void alertsApi.action(alert.id, action).then(() => devicesApi.listActions(alert.device_id)).then(j => setJobs(j.filter(job => job.alert_id === alert.id))).catch(e => setError(String(e))) }}>{action}</Button>)}
      <h4>Выполнение действий</h4>{jobs.map(job => <div key={job.job_id}><strong>{job.action}: {job.status}</strong>{job.error && <p role="alert">{job.error}</p>}<pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(job.result, null, 2)}</pre></div>)}
    </>}
  </Modal>
}
