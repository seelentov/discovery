import { useCallback, useEffect, useState } from 'react'
import { maintenanceWindowsApi } from '../api/maintenanceWindows'
import { ApiHttpError } from '../api/http'
import type { MaintenanceWindow, MaintenanceWindowBody, SubnetTarget } from '../api/types'
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
import { localToIso, toLocalInputValue } from '../utils/datetime'

function emptySubnet(): SubnetTarget {
  return { ip: '', mask: '255.255.255.0' }
}

function emptyDraft(): MaintenanceWindowBody {
  const now = new Date()
  const in2h = new Date(now.getTime() + 2 * 60 * 60 * 1000)
  return { id: null, name: '', enabled: true, starts_at: toLocalInputValue(now), ends_at: toLocalInputValue(in2h), subnets: [], profiles: [], device_ids: [] }
}

/** `profiles` is edited as comma-separated free text, not a multiselect — this feature's
 * UI is deliberately functional-but-plain (see the originating request's scope note); the
 * REST API is the precise/scriptable surface, this is a usable, not elaborate,
 * hand-editing surface for it. `device_ids` has no editor at all (audit finding 8,
 * 2026-09-20, direct user request) — raw device UUIDs typed by hand were unusable (an
 * operator has nowhere to look one up), and the CIDR subnet field above already covers
 * point-targeting a single device via a `/32`. Still read/displayed (a window created
 * before this fix, or via the API directly, may still have some set) — just no longer
 * settable from this form. */
function parseCsv(s: string): string[] {
  return s
    .split(',')
    .map((v) => v.trim())
    .filter((v) => v.length > 0)
}

function fmtDate(iso: string): string {
  const d = new Date(iso)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

/** Client-side mirror of `MaintenanceWindow::is_active` — purely for the list's "сейчас
 * активно" badge, not used for any enforcement (that only ever happens server-side, in
 * `AlertEvalHandler`). */
function isActiveNow(w: MaintenanceWindow): boolean {
  if (!w.enabled) return false
  const now = Date.now()
  return new Date(w.starts_at).getTime() <= now && now <= new Date(w.ends_at).getTime()
}

export function MaintenanceWindowsPage() {
  const toast = useToast()
  const confirm = useConfirm()
  const { canWrite } = useAuth()
  const canWriteMaintenance = canWrite('maintenance_windows')

  const [windows, setWindows] = useState<MaintenanceWindow[] | null>(null)
  const [error, setError] = useState('')
  const [editing, setEditing] = useState<MaintenanceWindowBody | null>(null)
  const [saving, setSaving] = useState(false)

  const load = useCallback(async () => {
    try {
      const list = await maintenanceWindowsApi.list()
      setWindows(list)
      setError('')
    } catch (e) {
      setError(e instanceof ApiHttpError ? e.message : 'Не удалось загрузить окна обслуживания')
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  function openCreate() {
    setEditing(emptyDraft())
  }

  function openEdit(w: MaintenanceWindow) {
    setEditing({
      id: w.id,
      name: w.name,
      enabled: w.enabled,
      starts_at: toLocalInputValue(new Date(w.starts_at)),
      ends_at: toLocalInputValue(new Date(w.ends_at)),
      subnets: w.subnets,
      profiles: w.profiles,
      device_ids: w.device_ids,
    })
  }

  async function handleSave() {
    if (!editing) return
    const startsIso = localToIso(editing.starts_at)
    const endsIso = localToIso(editing.ends_at)
    if (!editing.name.trim()) {
      toast('Укажите название окна', true)
      return
    }
    if (!startsIso || !endsIso) {
      toast('Укажите корректные дату/время начала и окончания', true)
      return
    }
    setSaving(true)
    try {
      await maintenanceWindowsApi.upsert({ ...editing, starts_at: startsIso, ends_at: endsIso, subnets: editing.subnets.filter((s) => s.ip && s.mask) })
      toast(editing.id ? 'Окно обслуживания сохранено' : 'Окно обслуживания создано')
      setEditing(null)
      await load()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось сохранить окно', true)
    } finally {
      setSaving(false)
    }
  }

  async function handleDelete(w: MaintenanceWindow) {
    const ok = await confirm(`Удалить окно обслуживания «${w.name}»?`, { label: 'Удалить', icon: 'trash', danger: true })
    if (!ok) return
    try {
      await maintenanceWindowsApi.delete(w.id)
      toast(`Окно «${w.name}» удалено`)
      await load()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось удалить окно', true)
    }
  }

  function patchSubnet(idx: number, patch: Partial<SubnetTarget>) {
    setEditing((prev) => {
      if (!prev) return prev
      const subnets = prev.subnets.slice()
      subnets[idx] = { ...subnets[idx], ...patch }
      return { ...prev, subnets }
    })
  }

  return (
    <div className="util-col gap-4">
      <div className="card-header">
        <div className="card-title">Окна обслуживания</div>
        {canWriteMaintenance && (
          <Button variant="primary" title="Создать новое окно обслуживания" onClick={openCreate}>
            <Icon name="plus" />
            Создать окно
          </Button>
        )}
      </div>

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
              <th>Начало</th>
              <th>Окончание</th>
              <th>Цель</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {windows === null ? (
              <EmptyStateRow colSpan={6} icon="clock" text="Загрузка…" />
            ) : windows.length === 0 ? (
              <EmptyStateRow colSpan={6} icon="clock" text="Окон обслуживания пока нет — создайте первое" />
            ) : (
              windows.map((w) => (
                <tr key={w.id}>
                  <td>{w.name}</td>
                  <td>
                    {!w.enabled ? (
                      <span className="badge badge-neutral">
                        <Icon name="dot" />
                        отключено
                      </span>
                    ) : isActiveNow(w) ? (
                      <Badge severity="warning" label="активно" />
                    ) : (
                      <span className="badge badge-neutral">запланировано</span>
                    )}
                  </td>
                  <td className="row-sub">{fmtDate(w.starts_at)}</td>
                  <td className="row-sub">{fmtDate(w.ends_at)}</td>
                  <td className="row-sub">
                    {w.subnets.length === 0 && w.profiles.length === 0 && w.device_ids.length === 0
                      ? '— (не выбрано ни одного устройства)'
                      : [
                          w.subnets.length > 0 ? `подсетей: ${w.subnets.length}` : null,
                          w.profiles.length > 0 ? `профилей: ${w.profiles.length}` : null,
                          w.device_ids.length > 0 ? `устройств: ${w.device_ids.length}` : null,
                        ]
                          .filter(Boolean)
                          .join(' · ')}
                  </td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    {canWriteMaintenance && (
                      <>
                        <Button variant="ghost" iconOnly small title="Редактировать" onClick={() => openEdit(w)}>
                          <Icon name="pencil" />
                        </Button>
                        <Button variant="ghost" iconOnly small title="Удалить" onClick={() => handleDelete(w)}>
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

      {canWriteMaintenance && <Modal
        open={editing !== null}
        title={editing?.id ? 'Редактировать окно обслуживания' : 'Новое окно обслуживания'}
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
              <input className="input" value={editing.name} onChange={(e) => setEditing({ ...editing, name: e.target.value })} placeholder="Плановые работы на узле…" />
            </Field>
            <Field label="Включено" hint="Независимый выключатель — можно отменить запланированное окно, не удаляя его">
              <Switch checked={editing.enabled} onChange={(v) => setEditing({ ...editing, enabled: v })} title="Включено" />
            </Field>
            <Field label="Начало">
              <input className="input" type="datetime-local" value={editing.starts_at} onChange={(e) => setEditing({ ...editing, starts_at: e.target.value })} />
            </Field>
            <Field label="Окончание">
              <input className="input" type="datetime-local" value={editing.ends_at} onChange={(e) => setEditing({ ...editing, ends_at: e.target.value })} />
            </Field>

            <div className="field field-wide">
              <label>
                Подсети (CIDR-диапазоны) <span className="row-sub">— устройство должно попадать хотя бы в одну</span>
              </label>
              {editing.subnets.map((s, idx) => (
                <div key={idx} style={{ display: 'flex', gap: '.5rem', marginBottom: '.4rem' }}>
                  <input className="input" placeholder="10.0.0.0" value={s.ip} onChange={(e) => patchSubnet(idx, { ip: e.target.value })} />
                  <input className="input" placeholder="255.255.255.0" value={s.mask} onChange={(e) => patchSubnet(idx, { mask: e.target.value })} />
                  <Button variant="ghost" iconOnly small title="Удалить подсеть" onClick={() => setEditing({ ...editing, subnets: editing.subnets.filter((_, i) => i !== idx) })}>
                    <Icon name="trash" />
                  </Button>
                </div>
              ))}
              <Button variant="ghost" small onClick={() => setEditing({ ...editing, subnets: [...editing.subnets, emptySubnet()] })}>
                <Icon name="plus" />
                Добавить подсеть
              </Button>
            </div>

            <Field label="Профили" wide hint="Через запятую — устройство должно быть на одном из перечисленных профилей">
              <input className="input" value={editing.profiles.join(', ')} onChange={(e) => setEditing({ ...editing, profiles: parseCsv(e.target.value) })} placeholder="asw, olt_xpon" />
            </Field>

            {editing.subnets.length === 0 && editing.profiles.length === 0 && editing.device_ids.length === 0 && (
              <p className="stamp field-wide" style={{ color: 'var(--status-warning)' }}>
                Ни одна цель не выбрана — такое окно не подавит тревоги ни для одного устройства (пустой селектор намеренно не значит «все устройства»).
              </p>
            )}
          </div>
        )}
      </Modal>}
    </div>
  )
}
