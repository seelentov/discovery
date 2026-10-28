import { useEffect, useRef, useState } from 'react'
import { alertsApi } from '../api/alerts'
import type { Alert } from '../api/types'
import { screenNoticeVisible } from '../utils/alertScreen'
import { Button } from './Button'
import { useAuth } from '../hooks/useAuth'

export function AlertScreenNotifications() {
  const { canRead, canWrite, user } = useAuth()
  const allowed = canRead('alerts')
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [dismissed, setDismissed] = useState<Set<string>>(new Set())
  const [error, setError] = useState('')
  const [sound, setSound] = useState(false)
  const [now, setNow] = useState(() => Date.now())
  const audio = useRef<AudioContext | null>(null)
  const sounded = useRef(new Set<string>())
  useEffect(() => {
    if (!allowed) return
    let cancelled = false
    const load = () => alertsApi.screen().then(a => { if (!cancelled) { setAlerts(a); setNow(Date.now()); setError('') } }).catch(e => { if (!cancelled) setError(String(e)) })
    void load()
    const timer = setInterval(() => void load(), 3000)
    return () => { cancelled = true; clearInterval(timer) }
  }, [allowed, user?.id])
  useEffect(() => {
    if (!sound || !audio.current) return
    const fresh = alerts.filter(a => a.details?.policy.notification_sound && screenNoticeVisible(a, now, dismissed) && !sounded.current.has(a.id))
    if (!fresh.length) return
    for (const a of fresh) sounded.current.add(a.id)
    const ctx = audio.current
    const oscillator = ctx.createOscillator(), gain = ctx.createGain()
    oscillator.frequency.value = 880; gain.gain.value = 0.08
    oscillator.connect(gain); gain.connect(ctx.destination)
    oscillator.start(); oscillator.stop(ctx.currentTime + 0.2)
  }, [alerts, sound, dismissed, now])
  useEffect(() => () => { void audio.current?.close() }, [])
  const visible = alerts.filter(a => screenNoticeVisible(a, now, dismissed))
  if (!allowed || (!visible.length && !error)) return null
  return <aside aria-label="Экранные уведомления тревог" style={{ position: 'fixed', bottom: 16, right: 16, zIndex: 950, width: 360, maxHeight: '65vh', overflow: 'auto' }}>
    <div className="card card-pad">
      <strong>Тревоги: {visible.length}</strong>
      <Button small variant="ghost" onClick={() => {
        if (!audio.current) audio.current = new AudioContext()
        void audio.current.resume(); setSound(v => !v)
      }}>{sound ? 'Выключить звук' : 'Включить звук'}</Button>
      {error && <p role="alert">{error}</p>}
      {visible.map(a => <div key={a.id} role="status" className="card card-pad">
        <strong>{a.device_ip} · {a.name}</strong><p>{a.message}</p>
        {a.details?.response_escalated && <p>{a.details.response_escalation_reason}</p>}
        {canWrite('alerts') && <Button small onClick={() => { void alertsApi.acknowledge(a.id).then(() => setAlerts(v => v.filter(item => item.id !== a.id))).catch(e => setError(String(e))) }}>Подтвердить</Button>}
        {!a.details?.policy.acknowledge_required && <Button small variant="ghost" onClick={() => setDismissed(v => new Set([...v, a.id]))}>Скрыть</Button>}
      </div>)}
    </div>
  </aside>
}
