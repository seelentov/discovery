import { useEffect, useState } from 'react'
import { alertsApi } from '../api/alerts'
import type { AlertRuleStatus } from '../api/types'
import { Button } from './Button'
import { Modal } from './Modal'
import { useAuth } from '../hooks/useAuth'

export function DeviceRuleDiagnostics({ deviceId }: { deviceId: string }) {
  const { canRead } = useAuth()
  const [open, setOpen] = useState(false)
  const [statuses, setStatuses] = useState<AlertRuleStatus[]>([])
  const [error, setError] = useState('')
  useEffect(() => {
    if (!open) return
    let cancelled = false
    const load = () => alertsApi.ruleStatuses(deviceId).then(statuses => { if (!cancelled) { setStatuses(statuses); setError('') } }).catch(e => { if (!cancelled) setError(String(e)) })
    void load()
    const interval = setInterval(() => void load(), 3000)
    return () => { cancelled = true; clearInterval(interval) }
  }, [open, deviceId])
  if (!canRead('alerts')) return null
  return <>
    <Button small variant="ghost" onClick={() => setOpen(true)}>Диагностика правил</Button>
    <Modal open={open} title="Диагностика правил устройства" wide onClose={() => setOpen(false)}>
      {error && <p role="alert">{error}</p>}
      {!statuses.length && !error && <p>Правила ещё не проверены или недоступны для вашей роли.</p>}
      {statuses.map(status => <div key={`${status.name}:${status.row_key ?? ''}`} className="card card-pad"><strong>{status.name} · {status.row_key ?? 'Устройство'} · {status.state}</strong>{status.error && <p role="alert">{status.error}</p>}<pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(status, null, 2)}</pre></div>)}
    </Modal>
  </>
}
