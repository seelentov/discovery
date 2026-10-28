import { useEffect, useState } from 'react'
import { rolesApi } from '../api/roles'
import type { Role } from '../api/types'
import type { AlertPolicy, AlertLifecycle, OperatorAction } from '../api/types'
import { Field } from './Field'
import { Button } from './Button'
import { useAuth } from '../hooks/useAuth'

const actions: OperatorAction[] = ['test', 'poll_now', 'rediscover', 'backup']
const phases: AlertLifecycle[] = ['raised', 'activated', 'cleared', 'acknowledged', 'escalated', 'deescalated']
const split = (v: string) => v.split(',').map(s => s.trim()).filter(Boolean)
const number = (v: string) => v === '' ? null : Number(v)

export function AlertPolicyEditor({ value = {}, onChange, shared = false }: { value?: AlertPolicy; onChange: (policy: AlertPolicy) => void; shared?: boolean }) {
  const { user } = useAuth()
  const [roles, setRoles] = useState<Role[]>([])
  useEffect(() => { if (user?.is_admin) void rolesApi.list().then(setRoles) }, [user?.is_admin])
  const patch = (v: Partial<AlertPolicy>) => onChange({ ...value, ...v })
  const event = value.event ?? { metric: '', count: 1, window_seconds: 60 }
  return <details className="card card-pad" open>
    <summary>Расширенные настройки тревоги</summary>
    <div className="form-grid">
      {!shared && <Field label="Общее правило" hint="Имя правила библиотеки. Его настройки применяются ко всем профилям, которые на него ссылаются; здесь сохраняются имя и включение.">
        <input className="input" value={value.shared_rule ?? ''} onChange={e => patch({ shared_rule: e.target.value || null })} />
      </Field>}
      <Field label="Режим">
        <select className="select" value={value.mode ?? 'state'} onChange={e => patch({ mode: e.target.value as AlertPolicy['mode'], event: e.target.value === 'event' ? event : null })}>
          <option value="state">Условие</option><option value="change">Изменение значения</option><option value="baseline">Динамические границы</option><option value="event">Trap / Syslog</option>
        </select>
      </Field>
      <Field label="Период проверки, секунд"><input className="input" type="number" min={1} max={86400} value={value.period_seconds ?? ''} onChange={e => patch({ period_seconds: number(e.target.value) })} /></Field>
      {(value.mode === 'baseline') && <>
        <Field label="Нижняя граница (Rhai)"><input className="input mono" value={value.lower_expression ?? ''} onChange={e => patch({ lower_expression: e.target.value || null })} /></Field>
        <Field label="Верхняя граница (Rhai)"><input className="input mono" value={value.upper_expression ?? ''} onChange={e => patch({ upper_expression: e.target.value || null })} /></Field>
      </>}
      <Field label="История метрик" hint="Имена через запятую. В выражениях доступны history.<имя> (массив чисел) и avg(history.<имя>).">
        <input className="input" value={(value.history_metrics ?? []).join(', ')} onChange={e => patch({ history_metrics: split(e.target.value) })} />
      </Field>
      <Field label="Окно истории, секунд"><input className="input" type="number" min={1} max={86400} value={value.history_seconds ?? ''} onChange={e => patch({ history_seconds: number(e.target.value) })} /></Field>
      {value.mode === 'event' && <>
        <Field label="Биндинг события" hint="Имя метрики trap_<имя> или syslog_<имя>. Условие проверяется на каждом принятом пакете; поля доступны как event.<поле>."><input className="input mono" value={event.metric} onChange={e => patch({ event: { ...event, metric: e.target.value } })} /></Field>
        <Field label="Число событий"><input className="input" type="number" min={1} max={10000} value={event.count} onChange={e => patch({ event: { ...event, count: Number(e.target.value) } })} /></Field>
        <Field label="Окно событий, секунд"><input className="input" type="number" min={1} max={86400} value={event.window_seconds} onChange={e => patch({ event: { ...event, window_seconds: Number(e.target.value) } })} /></Field>
        <Field label="Ключ события (Rhai)"><input className="input mono" value={event.key_expression ?? ''} onChange={e => patch({ event: { ...event, key_expression: e.target.value || null } })} /></Field>
        <Field label="Восстановление по событию (Rhai)" hint="Пусто — каждое достижение порога создаёт отдельное событие, которое оператор подтверждает."><input className="input mono" value={event.recovery_expression ?? ''} onChange={e => patch({ event: { ...event, recovery_expression: e.target.value || null } })} /></Field>
      </>}
      <Field label="Порог выхода из flapping"><input className="input" type="number" min={1} value={value.flap_clear_threshold ?? ''} onChange={e => patch({ flap_clear_threshold: number(e.target.value) })} /></Field>
      <Field label="Эскалация после, секунд"><input className="input" type="number" min={1} value={value.escalate_after_seconds ?? ''} onChange={e => patch({ escalate_after_seconds: number(e.target.value) })} /></Field>
      <Field label="Порог неподтверждённых событий"><input className="input" type="number" min={1} value={value.pending_count_threshold ?? ''} onChange={e => patch({ pending_count_threshold: number(e.target.value) })} /></Field>
      <Field label="Время показа уведомления, секунд" hint="Пусто — до закрытия оператором. При обязательном подтверждении уведомление не исчезает до подтверждения."><input className="input" type="number" min={1} max={86400} value={value.notification_lifetime_seconds ?? ''} onChange={e => patch({ notification_lifetime_seconds: number(e.target.value) })} /></Field>
      {user?.is_admin && (['viewer_roles', 'operator_roles'] as const).map((key, i) => <Field key={key} label={['Роли просмотра', 'Роли управления'][i]} hint="Пустой выбор — все пользователи с соответствующим правом на раздел тревог. Администраторы имеют доступ всегда.">
        {roles.map(role => <label key={role.id} className="checkbox-row"><input type="checkbox" checked={value[key]?.includes(role.id) ?? false} onChange={e => patch({ [key]: e.target.checked ? [...(value[key] ?? []), role.id] : (value[key] ?? []).filter(id => id !== role.id) })} />{role.name}</label>)}
      </Field>)}
    </div>
    {(['acknowledge_required', 'screen_notification', 'notification_sound', 'flap_incident'] as const).map((key, i) => <label key={key} className="checkbox-row"><input type="checkbox" checked={!!value[key]} onChange={e => patch({ [key]: e.target.checked })} />{['Обязательное подтверждение', 'Экранное уведомление', 'Звук уведомления', 'Отдельная тревога о нестабильности'][i]}</label>)}
    <Field label="Действия оператора из тревоги">{actions.map(action => <label key={action} className="checkbox-row"><input type="checkbox" checked={value.interactive_actions?.includes(action) ?? false} onChange={e => patch({ interactive_actions: e.target.checked ? [...(value.interactive_actions ?? []), action] : value.interactive_actions?.filter(a => a !== action) })} />{action}</label>)}</Field>
    <Field label="Автоматические действия">
      {(value.actions ?? []).map((action, i) => <div className="form-grid" key={i}>
        <select className="select" value={action.on} onChange={e => patch({ actions: value.actions?.map((a, n) => n === i ? { ...a, on: e.target.value as AlertLifecycle } : a) })}>{phases.map(p => <option key={p}>{p}</option>)}</select>
        <select className="select" value={action.action} onChange={e => patch({ actions: value.actions?.map((a, n) => n === i ? { ...a, action: e.target.value as OperatorAction } : a) })}>{actions.map(a => <option key={a}>{a}</option>)}</select>
        <input className="input mono" placeholder="Условие (Rhai), необязательно" value={action.condition ?? ''} onChange={e => patch({ actions: value.actions?.map((a, n) => n === i ? { ...a, condition: e.target.value || null } : a) })} />
        <Button small variant="ghost" onClick={() => patch({ actions: value.actions?.filter((_, n) => n !== i) })}>Удалить</Button>
      </div>)}
      <Button small variant="ghost" onClick={() => patch({ actions: [...(value.actions ?? []), { on: 'activated', action: 'poll_now' }] })}>Добавить действие</Button>
    </Field>
  </details>
}
