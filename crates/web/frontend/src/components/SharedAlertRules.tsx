import { useEffect, useState } from 'react'
import { alertsApi } from '../api/alerts'
import type { AlertRule } from '../api/types'
import { AlertRow } from '../pages/ProfilesPage'
import { Button } from './Button'
import { Modal } from './Modal'
import { useAuth } from '../hooks/useAuth'

export function SharedAlertRules() {
  const { canRead, canWrite } = useAuth()
  const [open, setOpen] = useState(false)
  const [rules, setRules] = useState<AlertRule[]>([])
  const [draft, setDraft] = useState<AlertRule | null>(null)
  const [error, setError] = useState('')
  const load = () => alertsApi.sharedRules().then(setRules).catch(e => setError(String(e)))
  useEffect(() => { if (open) void load() }, [open])
  if (!canRead('alerts')) return null
  return <>
    <Button variant="ghost" onClick={() => setOpen(true)}>Библиотека правил тревог</Button>
    <Modal open={open} title="Общие правила тревог" wide onClose={() => { setOpen(false); setDraft(null) }}>
      {error && <p role="alert">{error}</p>}
      <p className="row-sub">В профиле укажите имя в поле «Общее правило». Изменение библиотеки применяется ко всем ссылкам.</p>
      {rules.map(rule => <div className="form-grid" key={rule.name}><strong>{rule.name}</strong><span>{rule.policy?.mode ?? 'state'}</span>{canWrite('alerts') && <>
        <Button small onClick={() => { setDraft(structuredClone(rule)); setError('') }}>Изменить</Button>
        <Button small variant="ghost" onClick={() => { void alertsApi.deleteSharedRule(rule.name).then(load).catch(e => setError(String(e))) }}>Удалить</Button>
      </>}</div>)}
      {canWrite('alerts') && <Button onClick={() => { setDraft({ name: '', enabled: true, level: 'warning', expression: 'false', message: '' }); setError('') }}>Создать общее правило</Button>}
      {draft && <>
        <AlertRow alert={draft} tableMetricNames={[]} shared onChange={patch => setDraft({ ...draft, ...patch })} onRemove={() => setDraft(null)} />
        <Button variant="primary" onClick={() => { void alertsApi.saveSharedRule(draft).then(() => { setDraft(null); return load() }).catch(e => setError(String(e))) }}>Сохранить общее правило</Button>
      </>}
    </Modal>
  </>
}
