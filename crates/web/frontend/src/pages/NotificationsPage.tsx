import { useCallback, useEffect, useState } from 'react'
import { notificationChannelsApi, notificationProviderApi, notificationRulesApi } from '../api/notifications'
import { ApiHttpError } from '../api/http'
import {
  isRoleRecipient,
  type AlertLevel,
  type NotificationChannel,
  type NotificationChannelBody,
  type NotificationChannelKind,
  type NotificationProviderConfig,
  type NotificationRecipient,
  type NotificationRecipientRole,
  type NotificationRule,
  type NotificationRuleBody,
  type SubnetTarget,
} from '../api/types'
import { Button } from '../components/Button'
import { EmptyStateRow } from '../components/EmptyState'
import { Field } from '../components/Field'
import { Icon } from '../components/Icon'
import { Modal } from '../components/Modal'
import { Switch } from '../components/Switch'
import { useConfirm } from '../hooks/useConfirm'
import { useAuth } from '../hooks/useAuth'
import { useToast } from '../hooks/useToast'

type Tab = 'channels' | 'matrix' | 'provider'

const CHANNEL_KIND_LABEL: Record<NotificationChannelKind, string> = { email: 'Email', telegram: 'Telegram', webhook: 'Webhook' }
const LEVELS: AlertLevel[] = ['Info', 'Warning', 'Critical']
const LEVEL_LABEL: Record<AlertLevel, string> = { Info: 'Инфо', Warning: 'Внимание', Critical: 'Критично' }
const WEEKDAYS: { key: string; label: string }[] = [
  { key: 'Mon', label: 'Пн' },
  { key: 'Tue', label: 'Вт' },
  { key: 'Wed', label: 'Ср' },
  { key: 'Thu', label: 'Чт' },
  { key: 'Fri', label: 'Пт' },
  { key: 'Sat', label: 'Сб' },
  { key: 'Sun', label: 'Вс' },
]

function parseCsv(s: string): string[] {
  return s
    .split(',')
    .map((v) => v.trim())
    .filter((v) => v.length > 0)
}

function emptySubnet(): SubnetTarget {
  return { ip: '', mask: '255.255.255.0' }
}

function emptyChannelDraft(): NotificationChannelBody {
  return { id: null, kind: 'webhook', target: '', secret: '', enabled: true }
}

function emptyRuleDraft(): NotificationRuleBody {
  return {
    id: null,
    name: '',
    enabled: true,
    min_level: 'Warning',
    subnets: [],
    profiles: [],
    device_ids: [],
    active_from: null,
    active_to: null,
    days_of_week: [],
    notify_on_activate: true,
    notify_on_clear: true,
    recipients: [],
  }
}

/** `<input type="time">` gives/accepts `"HH:MM"` — the API stores `"HH:MM:SS"` (UTC, see
 * `NotificationRule.active_from`'s docs). Seconds are always `":00"`, never edited. */
function timeToInputValue(t: string | null): string {
  return t ? t.slice(0, 5) : ''
}
function inputValueToTime(v: string): string | null {
  return v ? `${v}:00` : null
}

function channelTargetLabel(kind: NotificationChannelKind): string {
  if (kind === 'email') return 'Email-адрес'
  if (kind === 'telegram') return 'Telegram chat_id'
  return 'Webhook URL'
}

export function NotificationsPage() {
  const toast = useToast()
  const confirm = useConfirm()
  const { canWrite } = useAuth()
  const canWriteNotifications = canWrite('notifications')
  const [tab, setTab] = useState<Tab>('channels')

  // ---- Мои каналы ----
  const [channels, setChannels] = useState<NotificationChannel[] | null>(null)
  const [channelError, setChannelError] = useState('')
  const [editingChannel, setEditingChannel] = useState<NotificationChannelBody | null>(null)
  const [savingChannel, setSavingChannel] = useState(false)

  const loadChannels = useCallback(async () => {
    try {
      setChannels(await notificationChannelsApi.listMine())
      setChannelError('')
    } catch (e) {
      setChannelError(e instanceof ApiHttpError ? e.message : 'Не удалось загрузить каналы')
    }
  }, [])

  useEffect(() => {
    loadChannels()
  }, [loadChannels])

  function openCreateChannel() {
    setEditingChannel(emptyChannelDraft())
  }

  function openEditChannel(c: NotificationChannel) {
    setEditingChannel({ id: c.id, kind: c.kind, target: c.target, secret: c.secret ?? '', enabled: c.enabled })
  }

  async function handleSaveChannel() {
    if (!editingChannel) return
    if (!editingChannel.target.trim()) {
      toast(`Укажите ${channelTargetLabel(editingChannel.kind).toLowerCase()}`, true)
      return
    }
    setSavingChannel(true)
    try {
      await notificationChannelsApi.upsertMine({ ...editingChannel, secret: editingChannel.secret || null })
      toast(editingChannel.id ? 'Канал сохранён' : 'Канал добавлен')
      setEditingChannel(null)
      await loadChannels()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось сохранить канал', true)
    } finally {
      setSavingChannel(false)
    }
  }

  async function handleDeleteChannel(c: NotificationChannel) {
    const ok = await confirm(`Удалить канал «${CHANNEL_KIND_LABEL[c.kind]}: ${c.target}»?`, { label: 'Удалить', icon: 'trash', danger: true })
    if (!ok) return
    try {
      await notificationChannelsApi.deleteMine(c.id)
      toast('Канал удалён')
      await loadChannels()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось удалить канал', true)
    }
  }

  // ---- Матрица ----
  const [rules, setRules] = useState<NotificationRule[] | null>(null)
  const [ruleError, setRuleError] = useState('')
  const [recipients, setRecipients] = useState<NotificationRecipient[]>([])
  const [recipientRoles, setRecipientRoles] = useState<NotificationRecipientRole[]>([])
  const [editingRule, setEditingRule] = useState<NotificationRuleBody | null>(null)
  const [savingRule, setSavingRule] = useState(false)

  const loadMatrix = useCallback(async () => {
    try {
      const [r, rec, roles] = await Promise.all([notificationRulesApi.list(), notificationRulesApi.recipients(), notificationRulesApi.recipientRoles()])
      setRules(r)
      setRecipients(rec)
      setRecipientRoles(roles)
      setRuleError('')
    } catch (e) {
      setRuleError(e instanceof ApiHttpError ? e.message : 'Не удалось загрузить матрицу нотификации')
    }
  }, [])

  useEffect(() => {
    loadMatrix()
  }, [loadMatrix])

  /** `recipients` is a mix of individual users and roles (2026-09-18) — see
   * `RecipientRef`'s docs. A role's name is rendered with a "роль:" prefix so the two
   * kinds are never visually ambiguous in the summary column/checkbox lists. */
  function recipientName(r: import('../api/types').RecipientRef): string {
    if (isRoleRecipient(r)) {
      return `роль: ${recipientRoles.find((role) => role.id === r.role)?.name ?? r.role.slice(0, 8)}`
    }
    return recipients.find((u) => u.id === r)?.username ?? r.slice(0, 8)
  }

  function openCreateRule() {
    setEditingRule(emptyRuleDraft())
  }

  function openEditRule(r: NotificationRule) {
    setEditingRule({
      ...r,
      id: r.id,
      name: r.name,
      enabled: r.enabled,
      min_level: r.min_level,
      subnets: r.subnets,
      profiles: r.profiles,
      device_ids: r.device_ids,
      active_from: r.active_from,
      active_to: r.active_to,
      days_of_week: r.days_of_week,
      notify_on_activate: r.notify_on_activate,
      notify_on_clear: r.notify_on_clear,
      recipients: r.recipients,
    })
  }

  function patchSubnet(idx: number, patch: Partial<SubnetTarget>) {
    setEditingRule((prev) => {
      if (!prev) return prev
      const subnets = prev.subnets.slice()
      subnets[idx] = { ...subnets[idx], ...patch }
      return { ...prev, subnets }
    })
  }

  function toggleDay(day: string) {
    setEditingRule((prev) => {
      if (!prev) return prev
      const has = prev.days_of_week.includes(day)
      return { ...prev, days_of_week: has ? prev.days_of_week.filter((d) => d !== day) : [...prev.days_of_week, day] }
    })
  }

  function toggleRecipient(id: string) {
    setEditingRule((prev) => {
      if (!prev) return prev
      const has = prev.recipients.includes(id)
      return { ...prev, recipients: has ? prev.recipients.filter((r) => r !== id) : [...prev.recipients, id] }
    })
  }

  function toggleRoleRecipient(roleId: string) {
    setEditingRule((prev) => {
      if (!prev) return prev
      const has = prev.recipients.some((r) => isRoleRecipient(r) && r.role === roleId)
      return { ...prev, recipients: has ? prev.recipients.filter((r) => !(isRoleRecipient(r) && r.role === roleId)) : [...prev.recipients, { role: roleId }] }
    })
  }

  async function handleSaveRule() {
    if (!editingRule) return
    if (!editingRule.name.trim()) {
      toast('Укажите название правила', true)
      return
    }
    if ((editingRule.active_from == null) !== (editingRule.active_to == null)) {
      toast('Укажите обе границы времени (от и до) или не указывайте ни одной', true)
      return
    }
    setSavingRule(true)
    try {
      await notificationRulesApi.upsert({ ...editingRule, subnets: editingRule.subnets.filter((s) => s.ip && s.mask) })
      toast(editingRule.id ? 'Правило сохранено' : 'Правило создано')
      setEditingRule(null)
      await loadMatrix()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось сохранить правило', true)
    } finally {
      setSavingRule(false)
    }
  }

  async function handleDeleteRule(r: NotificationRule) {
    const ok = await confirm(`Удалить правило «${r.name}»?`, { label: 'Удалить', icon: 'trash', danger: true })
    if (!ok) return
    try {
      await notificationRulesApi.delete(r.id)
      toast(`Правило «${r.name}» удалено`)
      await loadMatrix()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось удалить правило', true)
    }
  }

  // ---- Провайдер (SMTP/Telegram) ----
  const [provider, setProvider] = useState<NotificationProviderConfig | null>(null)
  const [providerError, setProviderError] = useState('')
  const [savingProvider, setSavingProvider] = useState(false)

  const loadProvider = useCallback(async () => {
    try {
      setProvider(await notificationProviderApi.get())
      setProviderError('')
    } catch (e) {
      setProviderError(e instanceof ApiHttpError ? e.message : 'Не удалось загрузить настройки провайдера')
    }
  }, [])

  useEffect(() => {
    loadProvider()
  }, [loadProvider])

  async function handleSaveProvider() {
    if (!provider) return
    setSavingProvider(true)
    try {
      await notificationProviderApi.set(provider)
      toast('Настройки провайдера сохранены')
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось сохранить настройки провайдера', true)
    } finally {
      setSavingProvider(false)
    }
  }

  return (
    <div className="util-col gap-4">
      <div className="tabs">
        <button className={tab === 'channels' ? 'active' : ''} title="Свои способы связи — email/Telegram/webhook" onClick={() => setTab('channels')}>
          Мои каналы
        </button>
        <button className={tab === 'matrix' ? 'active' : ''} title="Кого извещать по какой тревоге" onClick={() => setTab('matrix')}>
          Матрица ({rules?.length ?? 0})
        </button>
        <button className={tab === 'provider' ? 'active' : ''} title="Общие настройки доставки SMTP/Telegram" onClick={() => setTab('provider')}>
          Провайдер
        </button>
      </div>

      {tab === 'channels' && (
        <div className="util-col gap-4">
          <div className="card-header">
            <div className="card-title">Мои каналы связи</div>
            <Button variant="primary" title="Добавить канал" onClick={openCreateChannel}>
              <Icon name="plus" />
              Добавить канал
            </Button>
          </div>
          <p className="stamp">Свои личные способы связи — их видите и редактируете только вы (и администратор, при необходимости поддержки).</p>

          {channelError && (
            <p className="stamp" style={{ color: 'var(--status-critical)' }}>
              {channelError}
            </p>
          )}

          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Тип</th>
                  <th>Адрес / ID / URL</th>
                  <th>Статус</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {channels === null ? (
                  <EmptyStateRow colSpan={4} icon="mail" text="Загрузка…" />
                ) : channels.length === 0 ? (
                  <EmptyStateRow colSpan={4} icon="mail" text="Каналов пока нет — добавьте первый" />
                ) : (
                  channels.map((c) => (
                    <tr key={c.id}>
                      <td>{CHANNEL_KIND_LABEL[c.kind]}</td>
                      <td className="row-sub">{c.target}</td>
                      <td>
                        {c.enabled ? <span className="badge badge-ok">включён</span> : <span className="badge badge-neutral">выключен</span>}
                      </td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        <Button variant="ghost" iconOnly small title="Редактировать" onClick={() => openEditChannel(c)}>
                          <Icon name="pencil" />
                        </Button>
                        <Button variant="ghost" iconOnly small title="Удалить" onClick={() => handleDeleteChannel(c)}>
                          <Icon name="trash" />
                        </Button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === 'matrix' && (
        <div className="util-col gap-4">
          <div className="card-header">
            <div className="card-title">Матрица нотификации</div>
            {canWriteNotifications && (
              <Button variant="primary" title="Создать правило" onClick={openCreateRule}>
                <Icon name="plus" />
                Создать правило
              </Button>
            )}
          </div>

          {ruleError && (
            <p className="stamp" style={{ color: 'var(--status-critical)' }}>
              {ruleError}
            </p>
          )}

          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Название</th>
                  <th>Статус</th>
                  <th>Уровень</th>
                  <th>Цель</th>
                  <th>Время</th>
                  <th>Получатели</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {rules === null ? (
                  <EmptyStateRow colSpan={7} icon="mail" text="Загрузка…" />
                ) : rules.length === 0 ? (
                  <EmptyStateRow colSpan={7} icon="mail" text="Правил пока нет — создайте первое" />
                ) : (
                  rules.map((r) => (
                    <tr key={r.id}>
                      <td>{r.name}</td>
                      <td>{r.enabled ? <span className="badge badge-ok">включено</span> : <span className="badge badge-neutral">выключено</span>}</td>
                      <td className="row-sub">{LEVEL_LABEL[r.min_level]}+</td>
                      <td className="row-sub">
                        {r.subnets.length === 0 && r.profiles.length === 0 && r.device_ids.length === 0
                          ? 'все устройства'
                          : [
                              r.subnets.length > 0 ? `подсетей: ${r.subnets.length}` : null,
                              r.profiles.length > 0 ? `профилей: ${r.profiles.length}` : null,
                              r.device_ids.length > 0 ? `устройств: ${r.device_ids.length}` : null,
                            ]
                              .filter(Boolean)
                              .join(' · ')}
                      </td>
                      <td className="row-sub">
                        {r.active_from && r.active_to ? `${r.active_from.slice(0, 5)}–${r.active_to.slice(0, 5)} UTC` : 'весь день'}
                        {r.days_of_week.length > 0 ? `, ${r.days_of_week.join('/')}` : ''}
                      </td>
                      <td className="row-sub">{r.recipients.length === 0 ? '—' : r.recipients.map(recipientName).join(', ')}</td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        {canWriteNotifications && (
                          <>
                            <Button variant="ghost" iconOnly small title="Редактировать" onClick={() => openEditRule(r)}>
                              <Icon name="pencil" />
                            </Button>
                            <Button variant="ghost" iconOnly small title="Удалить" onClick={() => handleDeleteRule(r)}>
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
        </div>
      )}

      {tab === 'provider' && (
        <div className="util-col gap-4">
          <div className="card-title">Настройки провайдера доставки</div>
          <p className="stamp">Один SMTP-релей и один Telegram-бот на всю систему — общая инфраструктура, которую каждый канал использует для своего типа доставки.</p>

          {providerError && (
            <p className="stamp" style={{ color: 'var(--status-critical)' }}>
              {providerError}
            </p>
          )}

          {provider && (
            <div className="card card-pad util-col gap-3">
              <div className="form-grid">
                <Field label="SMTP-хост">
                  <input
                    className="input"
                    disabled={!canWriteNotifications}
                    value={provider.smtp_host ?? ''}
                    onChange={(e) => setProvider({ ...provider, smtp_host: e.target.value || null })}
                    placeholder="smtp.example.com"
                  />
                </Field>
                <Field label="SMTP-порт">
                  <input className="input" type="number" disabled={!canWriteNotifications} value={provider.smtp_port} onChange={(e) => setProvider({ ...provider, smtp_port: Number(e.target.value) || 587 })} />
                </Field>
                <Field label="SMTP-логин">
                  <input
                    className="input"
                    disabled={!canWriteNotifications}
                    value={provider.smtp_username ?? ''}
                    onChange={(e) => setProvider({ ...provider, smtp_username: e.target.value || null })}
                  />
                </Field>
                <Field
                  label="SMTP-пароль"
                  hint="Хранится зашифрованным (требует настроенный DISCOVERY_SECRET_KEY на сервере). Никогда не приходит обратно с сервера — поле всегда пустое при открытии; оставьте пустым, чтобы сохранить текущий пароль, введите новый, чтобы заменить его"
                >
                  <input
                    className="input"
                    disabled={!canWriteNotifications}
                    type="password"
                    value={provider.smtp_password ?? ''}
                    onChange={(e) => setProvider({ ...provider, smtp_password: e.target.value || null })}
                  />
                </Field>
                <Field label="Адрес отправителя" wide>
                  <input
                    className="input"
                    disabled={!canWriteNotifications}
                    value={provider.smtp_from_address ?? ''}
                    onChange={(e) => setProvider({ ...provider, smtp_from_address: e.target.value || null })}
                    placeholder="alerts@example.com"
                  />
                </Field>
                <Field
                  label="Telegram bot token"
                  wide
                  hint="Хранится зашифрованным (требует настроенный DISCOVERY_SECRET_KEY на сервере). Никогда не приходит обратно с сервера — поле всегда пустое при открытии; оставьте пустым, чтобы сохранить текущий токен, введите новый, чтобы заменить его"
                >
                  <input
                    className="input"
                    disabled={!canWriteNotifications}
                    type="password"
                    value={provider.telegram_bot_token ?? ''}
                    onChange={(e) => setProvider({ ...provider, telegram_bot_token: e.target.value || null })}
                    placeholder="123456:ABC-DEF..."
                  />
                </Field>
              </div>
              {canWriteNotifications && <div className="form-actions">
                <Button variant="primary" onClick={handleSaveProvider} disabled={savingProvider}>
                  {savingProvider ? 'Сохранение…' : 'Сохранить'}
                </Button>
              </div>}
            </div>
          )}
        </div>
      )}

      <Modal
        open={editingChannel !== null}
        title={editingChannel?.id ? 'Редактировать канал' : 'Новый канал'}
        onClose={() => setEditingChannel(null)}
        footer={
          <>
            <Button variant="ghost" onClick={() => setEditingChannel(null)}>
              Отмена
            </Button>
            <Button variant="primary" onClick={handleSaveChannel} disabled={savingChannel}>
              {savingChannel ? 'Сохранение…' : 'Сохранить'}
            </Button>
          </>
        }
      >
        {editingChannel && (
          <div className="form-grid">
            <Field label="Тип канала">
              <select
                className="select"
                value={editingChannel.kind}
                onChange={(e) => setEditingChannel({ ...editingChannel, kind: e.target.value as NotificationChannelKind })}
              >
                <option value="email">Email</option>
                <option value="telegram">Telegram</option>
                <option value="webhook">Webhook</option>
              </select>
            </Field>
            <Field label="Включён">
              <Switch checked={editingChannel.enabled} onChange={(v) => setEditingChannel({ ...editingChannel, enabled: v })} title="Включён" />
            </Field>
            <Field label={channelTargetLabel(editingChannel.kind)} wide>
              <input
                className="input"
                value={editingChannel.target}
                onChange={(e) => setEditingChannel({ ...editingChannel, target: e.target.value })}
                placeholder={editingChannel.kind === 'email' ? 'you@example.com' : editingChannel.kind === 'telegram' ? '123456789' : 'https://example.com/hook'}
              />
            </Field>
            {editingChannel.kind === 'webhook' && (
              <Field
                label="Секрет подписи (опционально)"
                wide
                hint={
                  editingChannel.id
                    ? 'Если задан — запросы подписываются HMAC-SHA256 в заголовке X-Discovery-Signature. Никогда не приходит обратно с сервера — поле всегда пустое при открытии; оставьте пустым, чтобы сохранить текущий секрет, введите новый, чтобы заменить его'
                    : 'Если задан — запросы подписываются HMAC-SHA256 в заголовке X-Discovery-Signature'
                }
              >
                <input className="input" value={editingChannel.secret ?? ''} onChange={(e) => setEditingChannel({ ...editingChannel, secret: e.target.value })} />
              </Field>
            )}
          </div>
        )}
      </Modal>

      {canWriteNotifications && <Modal
        open={editingRule !== null}
        title={editingRule?.id ? 'Редактировать правило' : 'Новое правило'}
        wide
        onClose={() => setEditingRule(null)}
        footer={
          <>
            <Button variant="ghost" onClick={() => setEditingRule(null)}>
              Отмена
            </Button>
            <Button variant="primary" onClick={handleSaveRule} disabled={savingRule}>
              {savingRule ? 'Сохранение…' : 'Сохранить'}
            </Button>
          </>
        }
      >
        {editingRule && (
          <div className="form-grid">
            <Field label="Название" wide>
              <input className="input" value={editingRule.name} onChange={(e) => setEditingRule({ ...editingRule, name: e.target.value })} placeholder="Дежурный на критичные" />
            </Field>
            <Field label="Включено">
              <Switch checked={editingRule.enabled} onChange={(v) => setEditingRule({ ...editingRule, enabled: v })} title="Включено" />
            </Field>
            <Field label="Минимальный уровень" hint="Уведомлять при этом уровне и выше">
              <select className="select" value={editingRule.min_level} onChange={(e) => setEditingRule({ ...editingRule, min_level: e.target.value as AlertLevel })}>
                {LEVELS.map((l) => (
                  <option key={l} value={l}>
                    {LEVEL_LABEL[l]}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="При активации тревоги">
              <Switch checked={editingRule.notify_on_activate} onChange={(v) => setEditingRule({ ...editingRule, notify_on_activate: v })} title="При активации" />
            </Field>
            <Field label="При закрытии тревоги">
              <Switch checked={editingRule.notify_on_clear} onChange={(v) => setEditingRule({ ...editingRule, notify_on_clear: v })} title="При закрытии" />
              <label className="checkbox-row"><input type="checkbox" checked={!!editingRule.selection?.notify_on_escalation} onChange={e => setEditingRule({ ...editingRule, selection: { ...editingRule.selection, notify_on_escalation: e.target.checked } })} />При эскалации</label>
              <label className="checkbox-row"><input type="checkbox" checked={!!editingRule.selection?.notify_on_deescalation} onChange={e => setEditingRule({ ...editingRule, selection: { ...editingRule.selection, notify_on_deescalation: e.target.checked } })} />При деэскалации</label>

            </Field>

            <div className="field field-wide">
              <label>
                Подсети (CIDR-диапазоны) <span className="row-sub">— устройство должно попадать хотя бы в одну</span>
              </label>
              {editingRule.subnets.map((s, idx) => (
                <div key={idx} style={{ display: 'flex', gap: '.5rem', marginBottom: '.4rem' }}>
                  <input className="input" placeholder="10.0.0.0" value={s.ip} onChange={(e) => patchSubnet(idx, { ip: e.target.value })} />
                  <input className="input" placeholder="255.255.255.0" value={s.mask} onChange={(e) => patchSubnet(idx, { mask: e.target.value })} />
                  <Button
                    variant="ghost"
                    iconOnly
                    small
                    title="Удалить подсеть"
                    onClick={() => setEditingRule({ ...editingRule, subnets: editingRule.subnets.filter((_, i) => i !== idx) })}
                  >
                    <Icon name="trash" />
                  </Button>
                </div>
              ))}
              <Button variant="ghost" small onClick={() => setEditingRule({ ...editingRule, subnets: [...editingRule.subnets, emptySubnet()] })}>
                <Icon name="plus" />
                Добавить подсеть
              </Button>
            </div>

            <Field label="Профили" wide hint="Через запятую — устройство должно быть на одном из перечисленных профилей">
              <input className="input" value={editingRule.profiles.join(', ')} onChange={(e) => setEditingRule({ ...editingRule, profiles: parseCsv(e.target.value) })} placeholder="asw, olt_xpon" />
            </Field>

            {editingRule.subnets.length === 0 && editingRule.profiles.length === 0 && editingRule.device_ids.length === 0 && (
              <p className="stamp field-wide">Селектор устройств пуст — правило сработает для всех устройств (в отличие от окон обслуживания, пустой селектор здесь значит «все», не «ни одного»).</p>
            )}

            <Field label="Время суток, от (UTC)" hint="Оставьте пустым для «весь день»">
              <input
                className="input"
                type="time"
                value={timeToInputValue(editingRule.active_from ?? null)}
                onChange={(e) => setEditingRule({ ...editingRule, active_from: inputValueToTime(e.target.value) })}
              />
            </Field>
            <Field label="Время суток, до (UTC)">
              <input
                className="input"
                type="time"
                value={timeToInputValue(editingRule.active_to ?? null)}
                onChange={(e) => setEditingRule({ ...editingRule, active_to: inputValueToTime(e.target.value) })}
              />
            </Field>

            <div className="field field-wide">
              <label>Дни недели — пусто значит «каждый день»</label>
              <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
                {WEEKDAYS.map((d) => (
                  <label key={d.key} className="checkbox-row">
                    <input type="checkbox" checked={editingRule.days_of_week.includes(d.key)} onChange={() => toggleDay(d.key)} />
                    {d.label}
                  </label>
                ))}
              </div>
            </div>

              {(['alert_names', 'row_keys', 'source_metrics'] as const).map((key, i) => <Field key={key} label={['Имена тревог', 'Ключи строк', 'Биндинги источников'][i]} hint="Через запятую. Пусто — любые."><input className="input" value={(editingRule.selection?.[key] ?? []).join(', ')} onChange={e => setEditingRule({ ...editingRule, selection: { ...editingRule.selection, [key]: parseCsv(e.target.value) } })} /></Field>)}
              <Field label="Условие получателя (Rhai)" hint="Область user (id, username, role_id), alert и facts.ip. Получатель включается только если выражение возвращает true."><input className="input mono" value={editingRule.selection?.recipient_expression ?? ''} onChange={e => setEditingRule({ ...editingRule, selection: { ...editingRule.selection, recipient_expression: e.target.value || null } })} /></Field>

            <div className="field field-wide">
              <label>Получатели — уведомляются все включённые каналы каждого выбранного пользователя</label>

              {recipients.length === 0 ? (
                <p className="stamp">Нет других пользователей — получателей выбрать не из кого.</p>
              ) : (
                <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
                  {recipients.map((r) => (
                    <label key={r.id} className="checkbox-row">
                      <input type="checkbox" checked={editingRule.recipients.includes(r.id)} onChange={() => toggleRecipient(r.id)} />
                      {r.username}
                    </label>
                  ))}
                </div>
              )}
            </div>

            <div className="field field-wide">
              <label>Получатели-роли — уведомляются все текущие участники выбранной роли</label>
              {recipientRoles.length === 0 ? (
                <p className="stamp">Ролей пока не создано — см. вкладку «Пользователи».</p>
              ) : (
                <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
                  {recipientRoles.map((role) => (
                    <label key={role.id} className="checkbox-row">
                      <input
                        type="checkbox"
                        checked={editingRule.recipients.some((r) => isRoleRecipient(r) && r.role === role.id)}
                        onChange={() => toggleRoleRecipient(role.id)}
                      />
                      {role.name}
                    </label>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </Modal>}
    </div>
  )
}
