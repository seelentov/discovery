import { useCallback, useEffect, useState } from 'react'
import { alertsApi } from '../api/alerts'
import { assistantSettingsApi } from '../api/assistant'
import { journalApi } from '../api/journal'
import { logsApi } from '../api/logs'
import { settingsApi } from '../api/settings'
import { ApiHttpError } from '../api/http'
import { DOMAIN_LABELS, DOMAINS, type AiAssistantProviderConfig, type DatabaseConnConfig, type DbKind, type DomainRouting, type PingConfig, type PollIntervalsConfig } from '../api/types'
import { Button } from '../components/Button'
import { Field } from '../components/Field'
import { Icon } from '../components/Icon'
import { Switch } from '../components/Switch'
import { useAuth } from '../hooks/useAuth'
import { useToast } from '../hooks/useToast'

// GigaChat Studio's "Authorization key" is exactly base64(client_id:client_secret) — see
// `gigachatAuthKey`'s docs above for why this is decoded here rather than sent as-is.
function decodeGigachatAuthKey(raw: string): { clientId: string; clientSecret: string } | null {
  let decoded: string
  try {
    decoded = atob(raw.trim())
  } catch {
    return null
  }
  const sep = decoded.indexOf(':')
  if (sep <= 0 || sep === decoded.length - 1) return null
  return { clientId: decoded.slice(0, sep), clientSecret: decoded.slice(sep + 1) }
}

const GIGACHAT_SCOPES: { value: string; label: string }[] = [
  { value: 'GIGACHAT_API_PERS', label: 'Personal (физлицо)' },
  { value: 'GIGACHAT_API_B2B', label: 'B2B (пост-оплата)' },
  { value: 'GIGACHAT_API_CORP', label: 'Corporate (по договору)' },
]

function positiveRetentionSeconds(raw: string): number | null {
  const value = raw.trim()
  if (!/^[1-9]\d*$/.test(value)) return null
  const seconds = Number(value)
  return Number.isSafeInteger(seconds) && seconds > 0 ? seconds : null
}

type Section = 'intervals' | 'retention' | 'ping' | 'databases' | 'ai-assistant'

const SECTIONS: { id: Section; label: string }[] = [
  { id: 'intervals', label: 'Периодичность опроса' },
  // Direct user request 2026-08-28: these three used to be separate nav entries — same
  // "forever checkbox + numeric seconds field" shape, all about "when does old data get
  // cleaned up", grouped into one tab. Each card keeps its own independent Save button —
  // they're still three separate settings hitting three separate API endpoints
  // (`saveAlertRetention`/`saveLogRetention`/`saveDeadDeviceRetention`), just no longer
  // requiring three separate nav clicks to see/edit them all.
  { id: 'retention', label: 'Хранение и очистка' },
  { id: 'ping', label: 'Ping' },
  { id: 'databases', label: 'Базы данных' },
]

// `/api/settings/ai-assistant` is `admin_guard!`-gated, not `domain_guard!` — a non-admin
// user with `Domain::Settings` write permission can open this whole page for its other
// tabs, but must never see (let alone be able to fetch, and 403 on) this one — see
// `docs/Architecture/AI Assistant.md` for why the AI provider config is admin-only rather
// than domain-gated. Kept out of the static `SECTIONS` array above and appended
// conditionally at render time instead.
const AI_ASSISTANT_SECTION: { id: Section; label: string } = { id: 'ai-assistant', label: 'ИИ-ассистент' }

const INTERVAL_FIELDS: { key: keyof PollIntervalsConfig; label: string; hint: string }[] = [
  { key: 'identity_secs', label: 'Идентификация устройства (SnmpPoll), сек', hint: 'как часто определяется модель/vendor устройства по SNMP' },
  { key: 'metric_secs', label: 'Опрос метрик профиля по умолчанию (MetricPoll), сек', hint: 'базовый период опроса метрик — конкретная метрика профиля может переопределить своим собственным расписанием' },
  { key: 'reachability_secs', label: 'Ping/SNMP статус доступности (ReachabilityPoll), сек', hint: 'проверка живости устройства отдельно от опроса метрик' },
  { key: 'service_check_secs', label: 'Сервис-чеки L4/L7 (ServiceCheckPoll), сек', hint: 'период опроса по умолчанию для profile.service_checks — конкретный профиль может задать своё расписание' },
  { key: 'discovery_schedule_check_secs', label: 'Проверка расписания дискаверинга, сек', hint: 'как часто проверяется, не пора ли запустить конфигурацию дискаверинга по её расписанию — не периодичность самого сканирования' },
  { key: 'profiles_reload_secs', label: 'Hot-reload профилей, сек', hint: 'как часто перечитываются файлы профилей с диска без перезапуска процесса' },
  { key: 'metric_history_cleanup_secs', label: 'Очистка истории метрик, сек', hint: 'как часто запускается удаление истории метрик старше срока хранения профиля' },
  { key: 'alert_cleanup_secs', label: 'Очистка истории тревог, сек', hint: 'как часто удаляются снятые тревоги старше срока хранения (раздел «Хранение и очистка»)' },
  { key: 'dead_device_cleanup_secs', label: 'Проверка недоступных устройств на удаление, сек', hint: 'как часто проверяется условие автоудаления недоступных устройств' },
  { key: 'logs_cleanup_secs', label: 'Очистка логов, сек', hint: 'как часто удаляются логи старше срока хранения (раздел «Хранение и очистка»)' },
  { key: 'journal_cleanup_secs', label: 'Очистка журнала, сек', hint: 'как часто удаляются записи журнала действий старше срока хранения (раздел «Хранение и очистка»)' },
  { key: 'group_alert_sweep_secs', label: 'Корреляция групповых тревог, сек', hint: 'как часто активные тревоги сверяются с топологией и правилами группового подавления (раздел «Групповые тревоги»)' },
]

export function SettingsPage() {
  const toast = useToast()
  const { user, canWrite } = useAuth()
  const canWriteSettings = canWrite('settings')
  const [section, setSection] = useState<Section>('intervals')
  const sections = user?.is_admin ? [...SECTIONS, AI_ASSISTANT_SECTION] : SECTIONS

  const [aiConfig, setAiConfig] = useState<AiAssistantProviderConfig | null>(null)
  const [aiConfigError, setAiConfigError] = useState('')
  const [savingAiConfig, setSavingAiConfig] = useState(false)
  // GigaChat Studio issues one combined "Authorization key" (base64(client_id:client_secret)),
  // not the separate client_id/client_secret the backend payload still wants — audit finding 4
  // (2026-09-20): a first-time setup attempt with real credentials failed with "Can't decode
  // 'Authorization' header" because the user had to guess how to split it themselves. Kept as
  // its own local field (not part of `aiConfig`) since it's write-only like a password field —
  // decoded and split into client_id/client_secret client-side right before sending, same
  // existing backend payload shape, unchanged.
  const [gigachatAuthKey, setGigachatAuthKey] = useState('')

  const loadAiConfig = useCallback(async () => {
    try {
      setAiConfig(await assistantSettingsApi.get())
      setAiConfigError('')
    } catch (e) {
      setAiConfigError(e instanceof ApiHttpError ? e.message : 'Не удалось загрузить настройки ИИ-ассистента')
    }
  }, [])

  useEffect(() => {
    if (user?.is_admin) loadAiConfig()
  }, [user?.is_admin, loadAiConfig])

  async function saveAiConfig() {
    if (!aiConfig) return
    let payload = { ...aiConfig, client_secret: aiConfig.client_secret || null, openrouter_api_key: aiConfig.openrouter_api_key || null, self_hosted_api_key: aiConfig.self_hosted_api_key || null }
    if (aiConfig.provider === 'gigachat' && gigachatAuthKey.trim()) {
      const decoded = decodeGigachatAuthKey(gigachatAuthKey)
      if (!decoded) {
        toast('Не удалось разобрать Authorization key', true)
        return
      }
      payload = { ...payload, client_id: decoded.clientId, client_secret: decoded.clientSecret }
    }
    setSavingAiConfig(true)
    try {
      await assistantSettingsApi.set(payload)
      toast('Настройки ИИ-ассистента сохранены')
      setGigachatAuthKey('')
      await loadAiConfig()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось сохранить настройки ИИ-ассистента', true)
    } finally {
      setSavingAiConfig(false)
    }
  }

  const [intervals, setIntervals] = useState<PollIntervalsConfig | null>(null)
  const [alertForever, setAlertForever] = useState(true)
  const [alertSecs, setAlertSecs] = useState('')
  const [logForever, setLogForever] = useState(true)
  const [logSecs, setLogSecs] = useState('')
  const [journalForever, setJournalForever] = useState(true)
  const [journalSecs, setJournalSecs] = useState('')
  const [ping, setPing] = useState<PingConfig | null>(null)
  const [deadNever, setDeadNever] = useState(true)
  const [deadSecs, setDeadSecs] = useState('')

  const [databases, setDatabases] = useState<DatabaseConnConfig[]>([])
  const [defaultDb, setDefaultDb] = useState<string | null>(null)
  const [routing, setRouting] = useState<DomainRouting | null>(null)
  const [restartBanner, setRestartBanner] = useState(false)
  const [dbError, setDbError] = useState('')

  /** `alertForever`/`logForever`/`deadNever` above default to `true` before the real
   * fetch resolves — a real bug this exposed (caught 2026-08-25 by an E2E test that
   * unchecked one of them right after navigating to this page): without a "has the real
   * value actually arrived yet" gate, a fast interaction during that window gets
   * silently clobbered the moment `loadAll()`'s response *does* arrive and overwrites
   * local state back to the optimistic default. `intervals`/`ping`/`routing` below
   * already avoid this by gating their section's render on the fetched object being
   * non-`null`; these three don't have an equivalent single object to gate on (their
   * state is decomposed into primitives), so this flag does the same job explicitly.
   */
  const [loaded, setLoaded] = useState(false)

  const loadAll = useCallback(async () => {
    try {
      const [pi, ar, lr, jr, pc, ddr, dbs, rt] = await Promise.all([
        settingsApi.getPollIntervals(),
        alertsApi.getRetention(),
        logsApi.getRetention(),
        journalApi.getRetention(),
        settingsApi.getPing(),
        settingsApi.getDeadDeviceRetention(),
        settingsApi.getDatabases(),
        settingsApi.getRouting(),
      ])
      setIntervals(pi)
      setAlertForever(ar.retention_secs == null)
      setAlertSecs(ar.retention_secs != null ? String(ar.retention_secs) : '')
      setLogForever(lr.retention_secs == null)
      setLogSecs(lr.retention_secs != null ? String(lr.retention_secs) : '')
      setJournalForever(jr.retention_secs == null)
      setJournalSecs(jr.retention_secs != null ? String(jr.retention_secs) : '')
      setPing(pc)
      setDeadNever(!ddr.unreachable_for_secs)
      setDeadSecs(ddr.unreachable_for_secs ? String(ddr.unreachable_for_secs) : '')
      setDatabases(dbs.databases)
      setDefaultDb(dbs.default_database)
      setRouting(rt)
      setLoaded(true)
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось загрузить настройки', true)
    }
  }, [toast])

  useEffect(() => {
    loadAll()
  }, [loadAll])

  async function saveIntervals() {
    if (!intervals) return
    try {
      await settingsApi.setPollIntervals(intervals)
      toast('Сохранено — применится на следующем тике соответствующего цикла')
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось сохранить', true)
    }
  }

  async function saveAlertRetention() {
    const retention_secs = alertForever ? null : positiveRetentionSeconds(alertSecs)
    if (!alertForever && retention_secs == null) {
      toast('Укажите целое число секунд больше нуля', true)
      return
    }
    try {
      await alertsApi.setRetention({ retention_secs })
      toast('Сохранено — применится на следующем цикле очистки')
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось сохранить', true)
    }
  }

  async function saveLogRetention() {
    const retention_secs = logForever ? null : positiveRetentionSeconds(logSecs)
    if (!logForever && retention_secs == null) {
      toast('Укажите целое число секунд больше нуля', true)
      return
    }
    try {
      await logsApi.setRetention({ retention_secs })
      toast('Сохранено — применится на следующем цикле очистки')
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось сохранить', true)
    }
  }

  async function saveJournalRetention() {
    const retention_secs = journalForever ? null : positiveRetentionSeconds(journalSecs)
    if (!journalForever && retention_secs == null) {
      toast('Укажите целое число секунд больше нуля', true)
      return
    }
    try {
      await journalApi.setRetention({ retention_secs })
      toast('Сохранено — применится на следующем цикле очистки')
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось сохранить', true)
    }
  }

  async function savePing() {
    if (!ping) return
    try {
      await settingsApi.setPing(ping)
      toast('Сохранено — применится на следующей пробе')
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось сохранить', true)
    }
  }

  async function saveDeadDeviceRetention() {
    try {
      await settingsApi.setDeadDeviceRetention({ unreachable_for_secs: deadNever ? 0 : Number(deadSecs) })
      toast('Сохранено — применится на следующем цикле очистки')
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось сохранить', true)
    }
  }

  function updateDb(idx: number, patch: Partial<DatabaseConnConfig>) {
    setDatabases((prev) => {
      const next = prev.slice()
      next[idx] = { ...next[idx], ...patch }
      return next
    })
  }

  function addDb() {
    setDatabases((prev) => [...prev, { name: '', kind: 'sqlite', sqlite_busy_timeout_secs: 5 }])
  }

  function removeDb(idx: number) {
    setDatabases((prev) => prev.filter((_, i) => i !== idx))
  }

  // Direct user request 2026-08-28: клонирование конфигов БД — appends a copy with a
  // blank name (must be filled in before saving, same "duplicate name rejected" guard
  // `saveDatabases` already enforces for any two non-blank entries).
  function cloneDb(idx: number) {
    setDatabases((prev) => [...prev, { ...prev[idx], name: '' }])
  }

  async function saveDatabases() {
    setDbError('')
    const names = databases.map((d) => d.name.trim())
    const seen = new Set<string>()
    for (const n of names) {
      if (!n) continue
      if (seen.has(n)) {
        setDbError(`дублирующееся имя БД: "${n}"`)
        return
      }
      seen.add(n)
    }
    try {
      const res = await settingsApi.setDatabases({ databases, default_database: defaultDb })
      setRestartBanner(res.needs_restart)
      toast('Список БД сохранён в config.toml')
      loadAll()
    } catch (e) {
      setDbError(e instanceof ApiHttpError ? e.message : 'Не удалось сохранить')
    }
  }

  async function saveRouting() {
    if (!routing) return
    try {
      const res = await settingsApi.setRouting(routing)
      setRestartBanner(res.needs_restart)
      toast('Маршрутизация сохранена')
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось сохранить маршрутизацию', true)
    }
  }

  async function restartNow() {
    try {
      await settingsApi.restart()
    } catch {
      // Connection reset because the process actually exited — expected, not a failure.
    }
    toast('Перезапуск запрошен — процесс завершает работу')
  }

  // Mirrors `Config::validate`'s own routing restriction exactly (`crates/bootstrap/src/
  // lib.rs`) — ClickHouse only fits `logs` (append-only), Cassandra only fits
  // `device_metrics`/`alerts` (the only two domains with a Cassandra store
  // implementation). Filtered here so picking an invalid combination isn't even possible
  // from the dropdown, rather than only surfacing as a save-time error.
  function dbNamesForDomain(domain: (typeof DOMAINS)[number]): string[] {
    return databases
      .filter((db) => {
        if (db.kind === 'clickhouse') return domain === 'logs'
        if (db.kind === 'cassandra') return domain === 'device_metrics' || domain === 'alerts'
        return true
      })
      .map((d) => d.name.trim())
      .filter(Boolean)
  }

  return (
    <div className="settings-layout">
      <nav className="settings-nav">
        {sections.map((s) => (
          <button key={s.id} className={section === s.id ? 'active' : ''} title={`Раздел настроек: ${s.label}`} onClick={() => setSection(s.id)}>
            {s.label}
          </button>
        ))}
      </nav>

      <fieldset disabled={!canWriteSettings} style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }}>
      <div className="util-col gap-4">
        {restartBanner && (
          <div className="form-ok" style={{ display: 'flex', gap: '.75rem', alignItems: 'center' }}>
            Настройки БД сохранены в config.toml. Изменения вступят в силу только после перезапуска процесса.
            <Button variant="primary" small title="Перезапустить процесс discovery-agent сейчас, чтобы новые настройки БД вступили в силу" onClick={restartNow}>
              Перезапустить сейчас
            </Button>
            <Button variant="ghost" small title="Скрыть баннер — изменения всё равно не применятся до следующего перезапуска" onClick={() => setRestartBanner(false)}>
              Позже
            </Button>
          </div>
        )}

        {section === 'intervals' && intervals && (
          <div className="card card-pad util-col gap-3">
            <div className="card-title">Настройки — периодичность опроса</div>
            <p className="stamp">Хранится в БД (не в config.toml) — сохранение применяется на следующем тике соответствующего цикла, без перезапуска процесса.</p>
            <div className="form-grid">
              {INTERVAL_FIELDS.map((f) => (
                <Field key={f.key} label={f.label} hint={f.hint}>
                  <input
                    className="input"
                    type="number"
                    min={1}
                    value={intervals[f.key]}
                    onChange={(e) => setIntervals({ ...intervals, [f.key]: Number(e.target.value) || 1 })}
                  />
                </Field>
              ))}
            </div>
            <div className="form-actions">
              <Button variant="primary" title="Сохранить периодичность опроса — применится на следующем тике каждого цикла" onClick={saveIntervals}>
                Сохранить
              </Button>
            </div>
          </div>
        )}

        {section === 'retention' && loaded && (
          <div className="util-col gap-4">
            <div className="card card-pad util-col gap-3">
              <div className="card-title">Хранение тревог</div>
              <p className="stamp">Сколько хранить снятые (cleared) тревоги в БД после снятия; активные тревоги не удаляются никогда.</p>
              <label className="checkbox-row" title="Включено — снятые тревоги никогда не удаляются автоматически, поле ниже заблокировано">
                <input type="checkbox" checked={alertForever} onChange={(e) => setAlertForever(e.target.checked)} /> Хранить снятые тревоги вечно
              </label>
              <Field label="Хранить снятые тревоги, сек" hint="через сколько секунд после снятия тревога удаляется из БД">
                <input className="input" type="number" min={1} disabled={alertForever} value={alertSecs} onChange={(e) => setAlertSecs(e.target.value)} />
              </Field>
              <div className="form-actions">
                <Button variant="primary" title="Сохранить срок хранения снятых тревог" onClick={saveAlertRetention}>
                  Сохранить
                </Button>
              </div>
            </div>

            <div className="card card-pad util-col gap-3">
              <div className="card-title">Хранение логов</div>
              <p className="stamp">Сколько хранить записи логов агента после их появления; старые записи удаляются автоматически.</p>
              <label className="checkbox-row" title="Включено — логи никогда не удаляются автоматически, поле ниже заблокировано">
                <input type="checkbox" checked={logForever} onChange={(e) => setLogForever(e.target.checked)} /> Хранить логи вечно
              </label>
              <Field label="Хранить логи, сек" hint="через сколько секунд после записи лог удаляется из буфера/БД">
                <input className="input" type="number" min={1} disabled={logForever} value={logSecs} onChange={(e) => setLogSecs(e.target.value)} />
              </Field>
              <div className="form-actions">
                <Button variant="primary" title="Сохранить срок хранения логов" onClick={saveLogRetention}>
                  Сохранить
                </Button>
              </div>
            </div>

            <div className="card card-pad util-col gap-3">
              <div className="card-title">Хранение журнала</div>
              <p className="stamp">Сколько хранить записи журнала действий пользователей (раздел «Журнал») после их появления; старые записи удаляются автоматически.</p>
              <label className="checkbox-row" title="Включено — записи журнала никогда не удаляются автоматически, поле ниже заблокировано">
                <input type="checkbox" checked={journalForever} onChange={(e) => setJournalForever(e.target.checked)} /> Хранить журнал вечно
              </label>
              <Field label="Хранить записи журнала, сек" hint="через сколько секунд после записи действие удаляется из журнала">
                <input className="input" type="number" min={1} disabled={journalForever} value={journalSecs} onChange={(e) => setJournalSecs(e.target.value)} />
              </Field>
              <div className="form-actions">
                <Button variant="primary" title="Сохранить срок хранения журнала" onClick={saveJournalRetention}>
                  Сохранить
                </Button>
              </div>
            </div>

            <div className="card card-pad util-col gap-3">
              <div className="card-title">Удаление недоступных устройств</div>
              <p className="stamp">
                Устройство, у которого ping непрерывно "false" дольше указанного времени, будет удалено вместе со всей своей историей. Устройства, выключенные вручную, никогда не
                удаляются автоматически.
              </p>
              <label className="checkbox-row" title="Включено — недоступные устройства никогда не удаляются автоматически, поле ниже заблокировано">
                <input type="checkbox" checked={deadNever} onChange={(e) => setDeadNever(e.target.checked)} /> Никогда не удалять (по умолчанию)
              </label>
              <Field label="Удалять после недоступности дольше, сек" hint="сколько секунд подряд ping должен быть недоступен, прежде чем устройство удалят вместе с историей">
                <input className="input" type="number" min={1} disabled={deadNever} value={deadSecs} onChange={(e) => setDeadSecs(e.target.value)} />
              </Field>
              <div className="form-actions">
                <Button variant="primary" title="Сохранить правило удаления недоступных устройств" onClick={saveDeadDeviceRetention}>
                  Сохранить
                </Button>
              </div>
            </div>
          </div>
        )}

        {section === 'ping' && ping && (
          <div className="card card-pad util-col gap-3">
            <div className="card-title">Настройки — ping</div>
            <p className="stamp">Периодичность проверки доступности задаётся в разделе «Периодичность опроса». Здесь — таймаут и число повторов одной пробы.</p>
            <div className="form-grid">
              <Field label="Таймаут пробы, мс" hint="сколько ждать ответа на один ICMP-запрос, прежде чем считать эту пробу неудачной">
                <input className="input" type="number" min={1} value={ping.timeout_ms} onChange={(e) => setPing({ ...ping, timeout_ms: Number(e.target.value) || 1 })} />
              </Field>
              <Field label="Повторов после первой неудачи" hint="сколько раз повторить пробу, прежде чем считать устройство недоступным">
                <input className="input" type="number" min={0} value={ping.retries} onChange={(e) => setPing({ ...ping, retries: Number(e.target.value) || 0 })} />
              </Field>
            </div>
            <div className="form-actions">
              <Button variant="primary" title="Сохранить настройки ping" onClick={savePing}>
                Сохранить
              </Button>
            </div>
          </div>
        )}

        {section === 'databases' && routing && (
          <div className="util-col gap-4">
            <div className="card card-pad util-col gap-3">
              <div className="card-title">Настройки — БД</div>
              <p className="stamp">
                Список именованных подключений к БД и маршрутизация {DOMAINS.length} доменов данных по ним. Хранится в config.toml, не в самой БД. Любое изменение здесь требует
                перезапуска процесса — сохранение не перезапускает само по себе.
              </p>
              {dbError && <div className="form-error">{dbError}</div>}
              {databases.length === 0 && (
                <p className="stamp">
                  Список пуст — ни одной именованной БД не настроено. Это не ошибка: все {DOMAINS.length} доменов данных в этом случае работают на неявном
                  внутрипроцессном <code>sqlite::memory:</code> — ничего не переживает перезапуск процесса и ничего внешнего не требуется («просто
                  запусти» режим). Чтобы подключить настоящую БД (Postgres/MySQL/SQLite-файл/ClickHouse/Cassandra) — добавьте запись кнопкой ниже.
                </p>
              )}
              <div className="util-col gap-3">
                {databases.map((db, idx) => (
                  <DbRow
                    key={idx}
                    db={db}
                    isDefault={defaultDb === db.name && db.name.trim() !== ''}
                    onMakeDefault={() => setDefaultDb(db.name)}
                    onChange={(patch) => updateDb(idx, patch)}
                    onRemove={() => removeDb(idx)}
                    onClone={() => cloneDb(idx)}
                  />
                ))}
              </div>
              <div className="form-actions">
                <Button variant="ghost" title="Добавить новую пустую запись подключения к БД" onClick={addDb}>
                  <Icon name="plus" />
                  Добавить БД
                </Button>
                <Button variant="primary" title="Сохранить список БД в config.toml — требует перезапуска процесса" onClick={saveDatabases}>
                  Сохранить список БД
                </Button>
              </div>
            </div>

            <div className="card card-pad util-col gap-3">
              <div className="card-title">Маршрутизация доменов</div>
              <p className="stamp">Домен, для которого не выбрана конкретная БД, использует «БД по умолчанию».</p>
              <div className="form-grid">
                {DOMAINS.map((domain) => (
                  <Field key={domain} label={DOMAIN_LABELS[domain]} hint="(по умолчанию) — использовать «БД по умолчанию» из списка выше">
                    <select className="select" value={routing[domain] ?? ''} onChange={(e) => setRouting({ ...routing, [domain]: e.target.value || null })}>
                      <option value="">(по умолчанию)</option>
                      {dbNamesForDomain(domain).map((n) => (
                        <option key={n} value={n}>
                          {n}
                        </option>
                      ))}
                    </select>
                  </Field>
                ))}
              </div>
              <div className="form-actions">
                <Button variant="primary" title="Сохранить маршрутизацию доменов по БД — требует перезапуска процесса" onClick={saveRouting}>
                  Сохранить маршрутизацию
                </Button>
              </div>
            </div>
          </div>
        )}

        {section === 'ai-assistant' && user?.is_admin && (
          <div className="card card-pad util-col gap-3">
            <div className="card-title">Настройки — ИИ-ассистент</div>
            <p className="stamp">
              Учётные данные провайдера ИИ (GigaChat) — общие на всю систему, использует каждый пользователь при работе с чатом ассистента. Что именно ассистент может
              прочитать или изменить в конкретном чате определяется правами того пользователя, который с ним общается, а не этими настройками.
            </p>
            {aiConfigError && <p className="form-error">{aiConfigError}</p>}
            {aiConfig && (
              <>
                <div className="form-grid">
                  <Field label="Включён">
                    <Switch checked={aiConfig.enabled} onChange={(v) => setAiConfig({ ...aiConfig, enabled: v })} title="Включён" />
                  </Field>
                  <Field label="Провайдер">
                    <select className="select" value={aiConfig.provider} onChange={(e) => setAiConfig({ ...aiConfig, provider: e.target.value })}>
                      <option value="gigachat">GigaChat</option>
                      <option value="openrouter">OpenRouter</option>
                      <option value="self_hosted">Self-hosted (vLLM/Ollama/...)</option>
                    </select>
                  </Field>
                  {aiConfig.provider === 'gigachat' && (
                    <>
                      <Field
                        label="Authorization key"
                        wide
                        hint="Единый ключ из личного кабинета GigaChat Studio — сам является base64(Client ID:Client Secret), разбирается на составляющие на этой странице автоматически, Client ID/Secret по отдельности вводить не нужно. Хранится зашифрованным (требует настроенный DISCOVERY_SECRET_KEY на сервере). Никогда не приходит обратно с сервера — поле всегда пустое при открытии; оставьте пустым, чтобы сохранить текущий секрет, введите новый, чтобы заменить его"
                      >
                        <input className="input" type="password" value={gigachatAuthKey} onChange={(e) => setGigachatAuthKey(e.target.value)} />
                      </Field>
                      <Field label="Тариф (scope)" hint="Определяет OAuth-scope, с которым получается токен — должен совпадать с реально подключённым в GigaChat Studio тарифом">
                        <select className="select" value={aiConfig.client_scope} onChange={(e) => setAiConfig({ ...aiConfig, client_scope: e.target.value })}>
                          {GIGACHAT_SCOPES.map((s) => (
                            <option key={s.value} value={s.value}>
                              {s.label}
                            </option>
                          ))}
                        </select>
                      </Field>
                    </>
                  )}
                  {aiConfig.provider === 'openrouter' && (
                    <>
                      <Field
                        label="API Key"
                        wide
                        hint="Хранится зашифрованным (требует настроенный DISCOVERY_SECRET_KEY на сервере). Никогда не приходит обратно с сервера — поле всегда пустое при открытии; оставьте пустым, чтобы сохранить текущий ключ, введите новый, чтобы заменить его. Бесплатный ключ можно завести на openrouter.ai без привязки карты"
                      >
                        <input className="input" type="password" value={aiConfig.openrouter_api_key ?? ''} onChange={(e) => setAiConfig({ ...aiConfig, openrouter_api_key: e.target.value })} />
                      </Field>
                      <Field label="Model" wide hint="Например openai/gpt-4o-mini, или модель с суффиксом :free — полный список на openrouter.ai/models (не все :free-модели поддерживают вызов инструментов)">
                        <input className="input" value={aiConfig.openrouter_model} onChange={(e) => setAiConfig({ ...aiConfig, openrouter_model: e.target.value })} />
                      </Field>
                    </>
                  )}
                  {aiConfig.provider === 'self_hosted' && (
                    <>
                      <Field label="Base URL" wide hint="Полный адрес chat-completions эндпоинта собственного сервера, например http://localhost:11434/v1/chat/completions (Ollama) или http://vllm-host:8000/v1/chat/completions (vLLM)">
                        <input className="input" value={aiConfig.self_hosted_base_url} onChange={(e) => setAiConfig({ ...aiConfig, self_hosted_base_url: e.target.value })} />
                      </Field>
                      <Field
                        label="API Key"
                        wide
                        hint="Опционально — многие self-hosted серверы работают без авторизации вообще. Хранится зашифрованным (требует настроенный DISCOVERY_SECRET_KEY на сервере), если указан. Никогда не приходит обратно с сервера — поле всегда пустое при открытии; оставьте пустым, чтобы сохранить текущий ключ или оставить без ключа, введите новый, чтобы заменить его"
                      >
                        <input className="input" type="password" value={aiConfig.self_hosted_api_key ?? ''} onChange={(e) => setAiConfig({ ...aiConfig, self_hosted_api_key: e.target.value })} />
                      </Field>
                      <Field label="Model" wide hint="Имя модели, под которым её знает сам сервер (например llama3 для Ollama)">
                        <input className="input" value={aiConfig.self_hosted_model} onChange={(e) => setAiConfig({ ...aiConfig, self_hosted_model: e.target.value })} />
                      </Field>
                    </>
                  )}
                </div>
                <div className="form-actions">
                  <Button variant="primary" onClick={saveAiConfig} disabled={savingAiConfig}>
                    {savingAiConfig ? 'Сохранение…' : 'Сохранить'}
                  </Button>
                </div>
              </>
            )}
          </div>
        )}
      </div>
      </fieldset>
    </div>
  )
}

const DB_KINDS: DbKind[] = ['postgres', 'mysql', 'sqlite', 'memory', 'clickhouse', 'cassandra']

const DB_KIND_LABELS: Record<DbKind, string> = {
  postgres: 'postgres',
  mysql: 'mysql',
  sqlite: 'sqlite',
  memory: 'memory',
  clickhouse: 'clickhouse (только домен «Логи»)',
  cassandra: 'cassandra (только «Метрики устройств»/«Тревоги»)',
}

function DbRow({
  db,
  isDefault,
  onMakeDefault,
  onChange,
  onRemove,
  onClone,
}: {
  db: DatabaseConnConfig
  isDefault: boolean
  onMakeDefault: () => void
  onChange: (patch: Partial<DatabaseConnConfig>) => void
  onRemove: () => void
  onClone: () => void
}) {
  const isServer = db.kind === 'postgres' || db.kind === 'mysql' || db.kind === 'clickhouse' || db.kind === 'cassandra'
  const portHint =
    db.kind === 'clickhouse' ? 'пусто — 8123 по умолчанию' : db.kind === 'cassandra' ? 'пусто — 9042 по умолчанию' : 'пусто — 5432/3306 по умолчанию'
  const databaseLabel = db.kind === 'cassandra' ? 'Keyspace' : 'База данных'
  const databaseHint = db.kind === 'clickhouse' ? 'пусто — «default»' : undefined
  const credentialsHint = db.kind === 'clickhouse' || db.kind === 'cassandra' ? 'пусто — без аутентификации' : 'пусто — без пароля'
  return (
    <div className="card card-pad">
      <div className="filter-bar__row">
        <label className="checkbox-row" title="Использовать эту БД для любого домена, для которого не выбрана конкретная БД в разделе «Маршрутизация доменов»">
          <input type="radio" name="db-default" checked={isDefault} onChange={onMakeDefault} /> по умолчанию
        </label>
        <input
          className="input"
          placeholder="имя (уникальное)"
          title="Уникальное имя подключения — используется в маршрутизации доменов ниже, не влияет на реальное имя БД"
          value={db.name}
          onChange={(e) => onChange({ name: e.target.value })}
        />
        <select className="select" title="Тип БД — определяет, какие поля подключения ниже показываются, и в какие домены эту БД можно маршрутизировать" value={db.kind} onChange={(e) => onChange({ kind: e.target.value as DbKind })}>
          {DB_KINDS.map((k) => (
            <option key={k} value={k}>
              {DB_KIND_LABELS[k]}
            </option>
          ))}
        </select>
        <Button variant="ghost" iconOnly small title="Клонировать — добавить копию этой записи под другим именем" onClick={onClone}>
          <Icon name="copy" />
        </Button>
        <Button variant="danger" iconOnly small title="Удалить" onClick={onRemove}>
          <Icon name="trash" />
        </Button>
      </div>
      {isServer && (
        <div className="form-grid" style={{ marginTop: '.5rem' }}>
          <Field label="Хост" hint="адрес сервера БД, без порта">
            <input className="input" placeholder="127.0.0.1" value={db.host ?? ''} onChange={(e) => onChange({ host: e.target.value || null })} />
          </Field>
          <Field label="Порт" hint={portHint}>
            <input className="input" type="number" min={1} max={65535} value={db.port ?? ''} onChange={(e) => onChange({ port: e.target.value ? Number(e.target.value) : null })} />
          </Field>
          <Field label={databaseLabel} hint={databaseHint}>
            <input className="input" placeholder="discovery" value={db.database ?? ''} onChange={(e) => onChange({ database: e.target.value || null })} />
          </Field>
          <Field label="Пользователь" hint={credentialsHint}>
            <input className="input" placeholder="postgres" value={db.username ?? ''} onChange={(e) => onChange({ username: e.target.value || null })} />
          </Field>
          <Field label="Пароль" hint={credentialsHint}>
            <input className="input" type="password" autoComplete="new-password" value={db.password ?? ''} onChange={(e) => onChange({ password: e.target.value || null })} />
          </Field>
        </div>
      )}
      {db.kind === 'sqlite' && (
        <div className="form-grid" style={{ marginTop: '.5rem' }}>
          <Field label="Путь к файлу" hint="относительный или абсолютный путь к файлу SQLite; пусто — sqlite::memory: (ничего не сохраняется между перезапусками)">
            <input className="input" placeholder="storage.sqlite3" value={db.file_path ?? ''} onChange={(e) => onChange({ file_path: e.target.value || null })} />
          </Field>
          <Field label="SQLITE_BUSY таймаут, сек" hint="сколько ждать освобождения файла БД при конкурентной записи, прежде чем вернуть ошибку">
            <input className="input" type="number" min={1} value={db.sqlite_busy_timeout_secs} onChange={(e) => onChange({ sqlite_busy_timeout_secs: Number(e.target.value) || 5 })} />
          </Field>
        </div>
      )}
      {db.kind !== 'memory' && (
        <Field label="Размер пула соединений" hint="пусто — дефолт бэкенда">
          <input
            className="input"
            type="number"
            min={1}
            value={db.pool_max_connections ?? ''}
            onChange={(e) => onChange({ pool_max_connections: e.target.value ? Number(e.target.value) : null })}
          />
        </Field>
      )}
    </div>
  )
}
