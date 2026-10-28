import { useCallback, useEffect, useState } from 'react'
import { groupAlertRulesApi } from '../api/group_alerts'
import { ApiHttpError } from '../api/http'
import type { GroupAlertRule, GroupAlertRuleBody } from '../api/types'
import { Badge } from '../components/Badge'
import { Button } from '../components/Button'
import { EmptyStateRow } from '../components/EmptyState'
import { Field } from '../components/Field'
import { Icon } from '../components/Icon'
import { Modal } from '../components/Modal'
import { Switch } from '../components/Switch'
import { useConfirm } from '../hooks/useConfirm'
import { useAuth } from '../hooks/useAuth'
import { useToast } from '../hooks/useToast'

function emptyDraft(): GroupAlertRuleBody {
  return { id: null, name: '', enabled: true, cause_expression: '', effect_expression: '' }
}

export function GroupAlertsPage() {
  const toast = useToast()
  const confirm = useConfirm()
  const { canWrite } = useAuth()
  const canWriteGroupAlerts = canWrite('group_alerts')

  const [rules, setRules] = useState<GroupAlertRule[] | null>(null)
  const [error, setError] = useState('')
  const [editing, setEditing] = useState<GroupAlertRuleBody | null>(null)
  const [saving, setSaving] = useState(false)

  const load = useCallback(async () => {
    try {
      setRules(await groupAlertRulesApi.list())
      setError('')
    } catch (e) {
      setError(e instanceof ApiHttpError ? e.message : 'Не удалось загрузить правила группового подавления')
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  function openCreate() {
    setEditing(emptyDraft())
  }

  function openEdit(r: GroupAlertRule) {
    setEditing({ id: r.id, name: r.name, enabled: r.enabled, cause_expression: r.cause_expression, effect_expression: r.effect_expression })
  }

  async function handleSave() {
    if (!editing) return
    if (!editing.name.trim()) {
      toast('Укажите название правила', true)
      return
    }
    if (!editing.cause_expression.trim() || !editing.effect_expression.trim()) {
      toast('Укажите оба выражения — cause_expression и effect_expression', true)
      return
    }
    setSaving(true)
    try {
      await groupAlertRulesApi.upsert(editing)
      toast(editing.id ? 'Правило сохранено' : 'Правило создано')
      setEditing(null)
      await load()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось сохранить правило', true)
    } finally {
      setSaving(false)
    }
  }

  async function handleDelete(r: GroupAlertRule) {
    const ok = await confirm(`Удалить правило «${r.name}»?`, { label: 'Удалить', icon: 'trash', danger: true })
    if (!ok) return
    try {
      await groupAlertRulesApi.delete(r.id)
      toast(`Правило «${r.name}» удалено`)
      await load()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось удалить правило', true)
    }
  }

  return (
    <div className="util-col gap-4">
      <div className="card-header">
        <div className="card-title">Правила группового подавления тревог</div>
        {canWriteGroupAlerts && (
          <Button variant="primary" title="Создать новое правило" onClick={openCreate}>
            <Icon name="plus" />
            Создать правило
          </Button>
        )}
      </div>

      <p className="row-sub">
        При падении общего аплинка — одна причинная тревога вместо шторма одинаковых алертов по всем зависимым устройствам. Тревога на устройстве подавляется, если у его topology-соседа выше по иерархии (аплинка) есть активная тревога,
        начавшаяся не позже, и хотя бы одно включённое правило ниже считает эту пару причиной/следствием.
      </p>

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
              <th>cause_expression</th>
              <th>effect_expression</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {rules === null ? (
              <EmptyStateRow colSpan={5} icon="filter" text="Загрузка…" />
            ) : rules.length === 0 ? (
              <EmptyStateRow colSpan={5} icon="filter" text="Правил пока нет — создайте первое" />
            ) : (
              rules.map((r) => (
                <tr key={r.id}>
                  <td>{r.name}</td>
                  <td>{r.enabled ? <Badge severity="info" label="включено" /> : <span className="badge badge-neutral">отключено</span>}</td>
                  <td className="row-sub" style={{ fontFamily: 'monospace', maxWidth: '20rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {r.cause_expression}
                  </td>
                  <td className="row-sub" style={{ fontFamily: 'monospace', maxWidth: '20rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {r.effect_expression}
                  </td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    {canWriteGroupAlerts && (
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

      {canWriteGroupAlerts && <Modal
        open={editing !== null}
        title={editing?.id ? 'Редактировать правило' : 'Новое правило группового подавления'}
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
              <input className="input" value={editing.name} onChange={(e) => setEditing({ ...editing, name: e.target.value })} placeholder="unreachable-cascade" />
            </Field>
            <Field label="Включено">
              <Switch checked={editing.enabled} onChange={(v) => setEditing({ ...editing, enabled: v })} title="Включено" />
            </Field>

            <Field label="cause_expression" wide hint="Rhai-выражение → bool, вычисляется над тревогой-кандидатом на upstream-соседе (поля: name, level, facts)">
              <textarea
                className="input"
                rows={2}
                style={{ fontFamily: 'monospace' }}
                value={editing.cause_expression}
                onChange={(e) => setEditing({ ...editing, cause_expression: e.target.value })}
                placeholder='name == "device_unreachable"'
              />
            </Field>

            <Field label="effect_expression" wide hint="Rhai-выражение → bool, тот же scope, вычисляется над тревогой-кандидатом на даунстрим-устройстве — подавляется, только если совпало и cause, и effect">
              <textarea
                className="input"
                rows={2}
                style={{ fontFamily: 'monospace' }}
                value={editing.effect_expression}
                onChange={(e) => setEditing({ ...editing, effect_expression: e.target.value })}
                placeholder='name == "device_unreachable"'
              />
            </Field>
          </div>
        )}
      </Modal>}
    </div>
  )
}
