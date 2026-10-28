import { useCallback, useEffect, useRef, useState } from 'react'
import { discoveryConfigsApi } from '../api/discoveryConfigs'
import { ApiHttpError } from '../api/http'
import { isPeriodicSchedule, type DiscoveryConfig, type DiscoveryOidSpec, type Schedule, type SnmpAuth, type SnmpAuthProtocol, type SnmpPrivProtocol, type SubnetSpec } from '../api/types'
import { Button } from '../components/Button'
import { EmptyStateBlock } from '../components/EmptyState'
import { Field } from '../components/Field'
import { Icon } from '../components/Icon'
import { KvEditor } from '../components/KvEditor'
import { Modal } from '../components/Modal'
import { OidTypeAndValueFields, TableColumnsFields, type ColumnsMode, type OidKind } from '../components/OidFields'
import { Switch } from '../components/Switch'
import { useConfirm } from '../hooks/useConfirm'
import { useAuth } from '../hooks/useAuth'
import { useToast } from '../hooks/useToast'
import { downloadJsonValue, readJsonFile } from '../utils/export'

function parseNumberList(text: string): number[] {
  return text
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map(Number)
    .filter((n) => !Number.isNaN(n))
}

function scheduleSummary(s: Schedule): string {
  if (isPeriodicSchedule(s)) return `период: ${s.interval_secs}с`
  const months = s.months.length ? s.months.join(',') : 'любой месяц'
  const days = s.days_of_month.length ? s.days_of_month.join(',') : 'любой день'
  return `время: ${s.time} (${months}, ${days})`
}

/** Editing-time shape of a subnet — identical to the wire `SubnetSpec` except `oids`,
 * which is `OidRow[]` (see that interface's docs) instead of the wire's
 * `Record<string, DiscoveryOidSpec>`, for exactly the same reason `ProfilesPage`'s
 * `EditingMetric.columnsMode` exists as a first-class field of its own editing-only
 * shape rather than being re-derived from `MetricSpec` on every render (audit finding
 * 10, 2026-09-20 — see `specToOidRow`'s docs for the bug this replaces: `columnsMode:
 * 'manual'` with zero columns entered so far and `columnsMode: 'auto'` are literally the
 * same wire value (`columns: {}`), so re-deriving `columnsMode` from the wire shape after
 * every keystroke — as this editor used to — couldn't tell them apart, and a fresh
 * "curated columns" selection instantly reverted itself before an operator could type a
 * single column pair in). Converted from/to `SubnetSpec` only at the two boundaries this
 * editing session actually crosses: `subnetToEditing` when a config is loaded into
 * `editing` (create/edit/clone/import), `editingToSubnet` when `editing` is saved/
 * exported — never in between, so `oids` stays lossless (and `DiscoveryOidsEditor` stays
 * a plain, fully-controlled-by-`editing`, no-internal-state component, same convention
 * `CredentialsEditor`/`KvEditor` already use) for the whole time an operator is actively
 * editing one config. */
interface EditingSubnet extends Omit<SubnetSpec, 'oids'> {
  oids: OidRow[]
}

interface EditingDiscoveryConfig extends Omit<DiscoveryConfig, 'subnets'> {
  subnets: EditingSubnet[]
}

function subnetToEditing(s: SubnetSpec): EditingSubnet {
  return { ...s, oids: Object.entries(s.oids).map(([name, spec]) => specToOidRow(name, spec)) }
}

function editingToSubnet(s: EditingSubnet): SubnetSpec {
  return { ...s, oids: Object.fromEntries(s.oids.map(oidRowToEntry)) }
}

function configToEditing(c: DiscoveryConfig): EditingDiscoveryConfig {
  return { ...c, subnets: c.subnets.map(subnetToEditing) }
}

function editingToConfig(c: EditingDiscoveryConfig): DiscoveryConfig {
  return { ...c, subnets: c.subnets.map(editingToSubnet) }
}

function emptySubnet(): EditingSubnet {
  return {
    ip: '',
    mask: '255.255.255.0',
    port: 161,
    credentials: [{ kind: 'community', version: 'v2c', community: 'public' }],
    oids: [],
    labels: {},
    snmp_timeout_ms: null,
    snmp_retries: null,
    create_dead_devices: false,
  }
}

function emptyConfig(): EditingDiscoveryConfig {
  return {
    name: '',
    enabled: true,
    schedule: { months: [], days_of_month: [], time: '03:00:00' },
    subnets: [],
  }
}

/** `useDebounce`-style: only fires `onChange` `delayMs` after the last keystroke — same
 * pattern Devices/Alerts/Profiles already each define locally (no shared hooks module in
 * this codebase yet). */
function useDebouncedValue<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const id = setTimeout(() => setDebounced(value), delayMs)
    return () => clearTimeout(id)
  }, [value, delayMs])
  return debounced
}

export function DiscoveryPage({
  openConfig,
  onOpenConfigHandled,
}: {
  /** Set by the global command palette (⌘K) — opens that config's edit modal on mount,
   * same "fetch by name directly, don't wait for the list" pattern `ProfilesPage`'s own
   * `openProfile` deep-link uses. */
  openConfig?: string | null
  onOpenConfigHandled?: () => void
} = {}) {
  const toast = useToast()
  const confirm = useConfirm()
  const { canWrite } = useAuth()
  const canWriteDiscovery = canWrite('discovery_configs')
  const [configs, setConfigs] = useState<DiscoveryConfig[] | null>(null)
  const [editing, setEditing] = useState<EditingDiscoveryConfig | null>(null)
  const [isNew, setIsNew] = useState(false)
  const [cloneSource, setCloneSource] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [runStatus, setRunStatus] = useState<Record<string, string>>({})
  // Direct user request 2026-08-28: "В дискаверинг добавить поиск. Поиск читает подсети и
  // название и ищет по ним." — matches the config's own name and its subnets' ip/mask/
  // label values (`list_discovery_configs`'s Rust docs).
  const [searchInput, setSearchInput] = useState('')
  const search = useDebouncedValue(searchInput, 300)

  const load = useCallback(async () => {
    try {
      const res = await discoveryConfigsApi.list({ search: search || undefined, page_size: 1000 })
      setConfigs(res.items)
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось загрузить конфигурации дискаверинга', true)
    }
  }, [search, toast])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    if (!openConfig) return
    discoveryConfigsApi
      .get(openConfig)
      .then((c) => {
        setError('')
        setIsNew(false)
        setCloneSource(null)
        setEditing(configToEditing(structuredClone(c)))
      })
      .catch((e) => toast(e instanceof ApiHttpError ? e.message : 'Не удалось открыть конфигурацию', true))
      .finally(() => onOpenConfigHandled?.())
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [openConfig])

  function openCreate() {
    setError('')
    setIsNew(true)
    setCloneSource(null)
    setEditing(emptyConfig())
  }

  function openEdit(c: DiscoveryConfig) {
    setError('')
    setIsNew(false)
    setCloneSource(null)
    setEditing(configToEditing(structuredClone(c)))
  }

  // Direct user request 2026-08-28: клонирование конфигов дискаверинга — same "blank the
  // name, save always upserts by name" pattern as `ProfilesPage`'s own `openClone`.
  function openClone(c: DiscoveryConfig) {
    setError('')
    setIsNew(true)
    setCloneSource(c.name)
    setEditing({ ...configToEditing(structuredClone(c)), name: '' })
  }

  async function handleDelete(c: DiscoveryConfig) {
    const ok = await confirm(`Удалить конфигурацию «${c.name}»?`, { label: 'Удалить', icon: 'trash' })
    if (!ok) return
    try {
      await discoveryConfigsApi.delete(c.name)
      toast('Конфигурация удалена')
      load()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось удалить конфигурацию', true)
    }
  }

  async function handleRunNow(c: DiscoveryConfig) {
    setRunStatus((prev) => ({ ...prev, [c.name]: 'запуск…' }))
    try {
      const res = await discoveryConfigsApi.runNow(c.name)
      setRunStatus((prev) => ({ ...prev, [c.name]: `поставлено в очередь: ${res.enqueued}` }))
    } catch (e) {
      setRunStatus((prev) => ({ ...prev, [c.name]: `ошибка: ${e instanceof ApiHttpError ? e.message : 'не удалось запустить'}` }))
    }
  }

  async function handleSave() {
    if (!editing) return
    setError('')
    try {
      await discoveryConfigsApi.upsert(editingToConfig(editing))
      setEditing(null)
      toast(`Конфигурация «${editing.name}» сохранена`)
      load()
    } catch (e) {
      setError(e instanceof ApiHttpError ? e.message : 'Не удалось сохранить конфигурацию')
    }
  }

  function updateEditing(patch: Partial<EditingDiscoveryConfig>) {
    setEditing((prev) => (prev ? { ...prev, ...patch } : prev))
  }

  function updateSubnet(idx: number, patch: Partial<EditingSubnet>) {
    setEditing((prev) => {
      if (!prev) return prev
      const subnets = prev.subnets.slice()
      subnets[idx] = { ...subnets[idx], ...patch }
      return { ...prev, subnets }
    })
  }

  function addSubnet() {
    setEditing((prev) => (prev ? { ...prev, subnets: [...prev.subnets, emptySubnet()] } : prev))
  }

  function removeSubnet(idx: number) {
    setEditing((prev) => (prev ? { ...prev, subnets: prev.subnets.filter((_, i) => i !== idx) } : prev))
  }

  // Direct user request 2026-08-28: "импорт экспорт подсетей в дискаверинге" — export/
  // import the subnets *list* as JSON, for copying a subset from one config into another.
  // Merges by `ip` (a subnet's natural identity) — an imported entry overwrites a
  // same-`ip` local draft row rather than appending a duplicate.
  const subnetsFileInputRef = useRef<HTMLInputElement>(null)

  function exportSubnets() {
    if (!editing) return
    downloadJsonValue(`${editing.name || 'discovery-config'}-subnets.json`, editing.subnets.map(editingToSubnet))
  }

  async function handleImportSubnets(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file || !editing) return
    try {
      const data = await readJsonFile(file)
      if (!Array.isArray(data)) throw new Error('expected an array')
      const byIp = new Map(editing.subnets.map(editingToSubnet).map((s) => [s.ip, s]))
      for (const s of data as SubnetSpec[]) byIp.set(s.ip, s)
      setEditing({ ...editing, subnets: Array.from(byIp.values()).map(subnetToEditing) })
      toast(`Импортировано подсетей: ${data.length}`)
    } catch {
      toast('Не удалось импортировать подсети — проверьте формат файла (JSON-список из экспорта)', true)
    }
  }

  const isPeriodic = editing ? isPeriodicSchedule(editing.schedule) : false

  return (
    <div className="util-col gap-4">
      <div className="card-header">
        <div className="card-title">Дискаверинг подсетей</div>
        {canWriteDiscovery && (
          <Button variant="primary" title="Создать новую конфигурацию дискаверинга с нуля" onClick={openCreate}>
            <Icon name="plus" />
            Создать
          </Button>
        )}
      </div>

      <div className="filter-bar">
        <div className="filter-bar__row">
          <div className="input-icon">
            <Icon name="search" />
            <input
              className="input"
              placeholder="Название, подсеть, метка…"
              title="Поиск по названию конфигурации и по её подсетям — IP, маска, метки"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
            />
          </div>
        </div>
      </div>

      {configs === null ? (
        <p className="stamp">Загрузка…</p>
      ) : configs.length === 0 ? (
        <EmptyStateBlock icon="radar" text={search ? 'Конфигураций не найдено — измените поиск или сбросьте его' : 'Конфигураций дискаверинга нет'} />
      ) : (
        <div className="grid-cards">
          {configs.map((c) => (
            <div className="card card-pad" key={c.name}>
              <div className="config-card__title">{c.name}</div>
              <div className="config-card__sub">
                {c.enabled ? 'включена' : 'выключена'} · подсетей: {c.subnets.length} · {scheduleSummary(c.schedule)}
              </div>
              {runStatus[c.name] && <div className="config-card__row">{runStatus[c.name]}</div>}
              <div className="config-card__actions">
                {canWriteDiscovery && (
                  <>
                    <Button variant="primary" iconOnly small title="Запустить" onClick={() => handleRunNow(c)}>
                      <Icon name="play" />
                    </Button>
                    <Button variant="ghost" iconOnly small title="Изменить" onClick={() => openEdit(c)}>
                      <Icon name="pencil" />
                    </Button>
                    <Button variant="ghost" iconOnly small title="Клонировать — создать новую конфигурацию с этими же подсетями под другим именем" onClick={() => openClone(c)}>
                      <Icon name="copy" />
                    </Button>
                    <Button variant="danger" iconOnly small title="Удалить" onClick={() => handleDelete(c)}>
                      <Icon name="trash" />
                    </Button>
                  </>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {canWriteDiscovery && <Modal
        open={editing !== null}
        wide
        title={isNew ? (cloneSource ? `Новая конфигурация (копия «${cloneSource}»)` : 'Новая конфигурация дискаверинга') : `Редактировать конфигурацию: ${editing?.name ?? ''}`}
        onClose={() => setEditing(null)}
        footer={
          <>
            <Button variant="ghost" title="Закрыть без сохранения изменений" onClick={() => setEditing(null)}>
              Отмена
            </Button>
            <Button variant="primary" title="Сохранить конфигурацию — upsert по имени" onClick={handleSave}>
              Сохранить конфигурацию
            </Button>
          </>
        }
      >
        {editing && (
          <div className="util-col gap-4">
            {error && <div className="form-error">{error}</div>}
            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <Switch
                checked={editing.enabled}
                onChange={(v) => updateEditing({ enabled: v })}
                title="Выключено — конфигурация не запускается по расписанию, но её можно запустить вручную кнопкой «Запустить»"
                label={['конфигурация активна', 'конфигурация выключена']}
              />
            </div>
            <Field label="Имя конфигурации" hint={isNew ? 'уникальное имя конфигурации' : 'нельзя изменить у существующей конфигурации — создайте клон, если нужно другое имя'}>
              <input className="input" value={editing.name} onChange={(e) => updateEditing({ name: e.target.value })} disabled={!isNew} />
            </Field>

            <Field label="Режим расписания" hint="по календарю — запуск в заданное время в заданные дни; по периоду — запуск каждые N секунд">
              <select
                className="select"
                value={isPeriodic ? 'periodic' : 'calendar'}
                onChange={(e) =>
                  updateEditing({
                    schedule: e.target.value === 'periodic' ? { interval_secs: 3600 } : { months: [], days_of_month: [], time: '03:00:00' },
                  })
                }
              >
                <option value="calendar">по календарю (месяц/дата/время)</option>
                <option value="periodic">по периоду (каждые N секунд)</option>
              </select>
            </Field>
            {isPeriodic ? (
              <Field label="Период, сек" hint="как часто автоматически запускать сканирование этих подсетей">
                <input
                  className="input"
                  type="number"
                  min={1}
                  value={isPeriodicSchedule(editing.schedule) ? editing.schedule.interval_secs : 3600}
                  onChange={(e) => updateEditing({ schedule: { interval_secs: Number(e.target.value) || 1 } })}
                />
              </Field>
            ) : (
              <div className="form-grid">
                <Field label="Месяцы (1-12)" hint="пусто = каждый месяц">
                  <input
                    className="input"
                    placeholder="1, 6"
                    value={!isPeriodicSchedule(editing.schedule) ? editing.schedule.months.join(', ') : ''}
                    onChange={(e) =>
                      updateEditing({
                        schedule: { months: parseNumberList(e.target.value), days_of_month: !isPeriodicSchedule(editing.schedule) ? editing.schedule.days_of_month : [], time: !isPeriodicSchedule(editing.schedule) ? editing.schedule.time : '03:00:00' },
                      })
                    }
                  />
                </Field>
                <Field label="Даты месяца (1-31)" hint="пусто = каждый день">
                  <input
                    className="input"
                    placeholder="1, 15"
                    value={!isPeriodicSchedule(editing.schedule) ? editing.schedule.days_of_month.join(', ') : ''}
                    onChange={(e) =>
                      updateEditing({
                        schedule: { months: !isPeriodicSchedule(editing.schedule) ? editing.schedule.months : [], days_of_month: parseNumberList(e.target.value), time: !isPeriodicSchedule(editing.schedule) ? editing.schedule.time : '03:00:00' },
                      })
                    }
                  />
                </Field>
                <Field label="Время запуска" hint="ЧЧ:ММ:СС, время сервера">
                  <input
                    className="input"
                    placeholder="03:00:00"
                    value={!isPeriodicSchedule(editing.schedule) ? editing.schedule.time : ''}
                    onChange={(e) =>
                      updateEditing({
                        schedule: { months: !isPeriodicSchedule(editing.schedule) ? editing.schedule.months : [], days_of_month: !isPeriodicSchedule(editing.schedule) ? editing.schedule.days_of_month : [], time: e.target.value },
                      })
                    }
                  />
                </Field>
              </div>
            )}

            <div className="card-header">
              <div className="card-title">Подсети</div>
              <div className="filter-bar__row">
                <Button variant="ghost" small title="Добавить ещё одну подсеть для сканирования" onClick={addSubnet}>
                  <Icon name="plus" />
                  Подсеть
                </Button>
                <Button variant="ghost" small title="Экспортировать список подсетей в JSON" onClick={exportSubnets} disabled={editing.subnets.length === 0}>
                  <Icon name="download" />
                  Экспорт
                </Button>
                <Button variant="ghost" small title="Импортировать подсети из JSON — по IP перезапишет уже заданные" onClick={() => subnetsFileInputRef.current?.click()}>
                  <Icon name="external" />
                  Импорт
                </Button>
                <input ref={subnetsFileInputRef} type="file" accept="application/json" style={{ display: 'none' }} onChange={handleImportSubnets} />
              </div>
            </div>
            {editing.subnets.map((subnet, idx) => (
              <SubnetBlock key={idx} subnet={subnet} onChange={(patch) => updateSubnet(idx, patch)} onRemove={() => removeSubnet(idx)} />
            ))}
          </div>
        )}
      </Modal>}
    </div>
  )
}

function SubnetBlock({ subnet, onChange, onRemove }: { subnet: EditingSubnet; onChange: (patch: Partial<EditingSubnet>) => void; onRemove: () => void }) {
  function setKv(field: 'labels', entries: [string, string][]) {
    onChange({ [field]: Object.fromEntries(entries) } as Partial<EditingSubnet>)
  }

  return (
    <div className="card card-pad">
      <div className="card-header">
        <strong>Подсеть</strong>
        <Button variant="ghost" iconOnly small title="Удалить подсеть" onClick={onRemove}>
          <Icon name="x" />
        </Button>
      </div>
      <div className="form-grid">
        <Field label="IP сети" hint="сетевой адрес сканируемого диапазона">
          <input className="input" placeholder="10.0.0.0" value={subnet.ip} onChange={(e) => onChange({ ip: e.target.value })} />
        </Field>
        <Field label="Маска" hint="маска подсети — вместе с IP сети определяет диапазон сканируемых адресов">
          <input className="input" placeholder="255.255.255.0" value={subnet.mask} onChange={(e) => onChange({ mask: e.target.value })} />
        </Field>
        <Field label="UDP-порт SNMP" hint="стандартный порт — 161">
          <input className="input" type="number" min={1} max={65535} value={subnet.port} onChange={(e) => onChange({ port: Number(e.target.value) || 161 })} />
        </Field>
        <Field label="Таймаут SNMP, мс" hint="пусто = по умолчанию (2000)">
          <input
            className="input"
            type="number"
            min={1}
            placeholder="2000"
            value={subnet.snmp_timeout_ms ?? ''}
            onChange={(e) => onChange({ snmp_timeout_ms: e.target.value ? Number(e.target.value) : null })}
          />
        </Field>
        <Field label="Повторы при неответе" hint="пусто = по умолчанию (1)">
          <input
            className="input"
            type="number"
            min={0}
            placeholder="1"
            value={subnet.snmp_retries ?? ''}
            onChange={(e) => onChange({ snmp_retries: e.target.value ? Number(e.target.value) : null })}
          />
        </Field>
      </div>
      <label className="checkbox-row" style={{ marginTop: '.5rem' }} title="Включено — даже адрес, не ответивший на ping, становится устройством (полезно для мониторинга самого факта недоступности); выключено — молчащие адреса пропускаются">
        <input type="checkbox" checked={subnet.create_dead_devices} onChange={(e) => onChange({ create_dead_devices: e.target.checked })} />
        Создавать устройства для не отвечающих на ping адресов
      </label>

      <CredentialsEditor credentials={subnet.credentials} onChange={(credentials) => onChange({ credentials })} />
      <DiscoveryOidsEditor rows={subnet.oids} onChange={(oids) => onChange({ oids })} />
      <KvEditor label="Метки (константы)" hint="имя → значение, записывается один раз без SNMP-опроса" keyPlaceholder="имя" valuePlaceholder="значение" entries={Object.entries(subnet.labels)} onChange={(e) => setKv('labels', e)} />
    </div>
  )
}

const AUTH_PROTOCOL_OPTIONS: { value: SnmpAuthProtocol; label: string }[] = [
  { value: 'md5', label: 'MD5' },
  { value: 'sha1', label: 'SHA-1' },
  { value: 'sha224', label: 'SHA-224' },
  { value: 'sha256', label: 'SHA-256' },
  { value: 'sha384', label: 'SHA-384' },
  { value: 'sha512', label: 'SHA-512' },
]

const PRIV_PROTOCOL_OPTIONS: { value: SnmpPrivProtocol; label: string }[] = [
  { value: 'des', label: 'DES' },
  { value: 'des3', label: '3DES' },
  { value: 'aes128', label: 'AES-128' },
  { value: 'aes192_blumenthal', label: 'AES-192 (Blumenthal)' },
  { value: 'aes192_reeder', label: 'AES-192 (Reeder/Cisco)' },
  { value: 'aes256_blumenthal', label: 'AES-256 (Blumenthal)' },
  { value: 'aes256_reeder', label: 'AES-256 (Reeder/Cisco)' },
]

const MIN_V3_PASSPHRASE_LEN = 8

function defaultCommunityCredential(): SnmpAuth {
  return { kind: 'community', version: 'v2c', community: '' }
}

function defaultUsmV3Credential(): SnmpAuth {
  return { kind: 'usm_v3', user: '', auth: { protocol: 'sha1', passphrase: '' } }
}

/** Kандидаты SNMP-аутентификации для подсети, перебираемые по порядку до первого
 * ответившего — community (v1/v2c) и SNMPv3 USM вперемешку. Заменил отдельные поля
 * "Версии SNMP"/"Read community" 2026-08-29 (поддержка SNMPv3): у v3 нет community-строки
 * вовсе, так что общий плоский список кандидатов лучше отражает реальную модель, чем два
 * списка, перемножаемые на бэкенде. */
function CredentialsEditor({ credentials, onChange }: { credentials: SnmpAuth[]; onChange: (credentials: SnmpAuth[]) => void }) {
  function update(idx: number, next: SnmpAuth) {
    const copy = credentials.slice()
    copy[idx] = next
    onChange(copy)
  }
  function remove(idx: number) {
    onChange(credentials.filter((_, i) => i !== idx))
  }
  function changeKind(idx: number, kind: SnmpAuth['kind']) {
    update(idx, kind === 'community' ? defaultCommunityCredential() : defaultUsmV3Credential())
  }

  return (
    <div style={{ marginTop: '.75rem' }}>
      <Field label="SNMP-доступ" hint="кандидаты для опроса адресов этой подсети, перебираются по порядку до первого ответившего">
        <div className="util-col gap-2">
          {credentials.map((cred, idx) => (
            <CredentialRow key={idx} credential={cred} onChange={(c) => update(idx, c)} onChangeKind={(k) => changeKind(idx, k)} onRemove={() => remove(idx)} />
          ))}
          <div className="wrap-row" style={{ gap: '.5rem' }}>
            <Button variant="ghost" small title="Добавить community-кандидата (v1/v2c)" onClick={() => onChange([...credentials, defaultCommunityCredential()])}>
              <Icon name="plus" />
              Community (v1/v2c)
            </Button>
            <Button variant="ghost" small title="Добавить кандидата SNMPv3" onClick={() => onChange([...credentials, defaultUsmV3Credential()])}>
              <Icon name="plus" />
              SNMPv3
            </Button>
          </div>
        </div>
      </Field>
    </div>
  )
}

function CredentialRow({
  credential,
  onChange,
  onChangeKind,
  onRemove,
}: {
  credential: SnmpAuth
  onChange: (c: SnmpAuth) => void
  onChangeKind: (kind: SnmpAuth['kind']) => void
  onRemove: () => void
}) {
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '.6rem', display: 'flex', flexDirection: 'column', gap: '.4rem' }}>
      <div className="filter-bar__row">
        <select className="input" value={credential.kind} onChange={(e) => onChangeKind(e.target.value as SnmpAuth['kind'])} style={{ maxWidth: '10rem' }}>
          <option value="community">Community (v1/v2c)</option>
          <option value="usm_v3">SNMPv3 (USM)</option>
        </select>
        <Button variant="ghost" iconOnly small title="Удалить кандидата" onClick={onRemove}>
          <Icon name="x" />
        </Button>
      </div>

      {credential.kind === 'community' ? (
        <div className="filter-bar__row">
          <select className="input" value={credential.version} onChange={(e) => onChange({ ...credential, version: e.target.value as 'v1' | 'v2c' })} style={{ maxWidth: '7rem' }}>
            <option value="v2c">v2c</option>
            <option value="v1">v1</option>
          </select>
          <input className="input mono" placeholder="community, например public" value={credential.community} onChange={(e) => onChange({ ...credential, community: e.target.value })} />
        </div>
      ) : (
        <UsmV3Fields credential={credential} onChange={onChange} />
      )}
    </div>
  )
}

function UsmV3Fields({ credential, onChange }: { credential: Extract<SnmpAuth, { kind: 'usm_v3' }>; onChange: (c: SnmpAuth) => void }) {
  const auth = credential.auth ?? null
  const priv = credential.priv_ ?? null

  function setAuthEnabled(enabled: boolean) {
    // Privacy without authentication (privNoAuth) isn't a valid SNMPv3 security level —
    // turning auth off must also clear priv, mirroring the backend's own rejection of
    // that combination (see `discovery_web::validate_subnet_credentials`'s docs) instead
    // of letting the UI reach a state the server will just 400 on submit.
    onChange({ ...credential, auth: enabled ? { protocol: 'sha1', passphrase: '' } : null, priv_: enabled ? credential.priv_ : null })
  }
  function setPrivEnabled(enabled: boolean) {
    onChange({ ...credential, priv_: enabled ? { protocol: 'aes128', passphrase: '' } : null })
  }

  const authTooShort = auth != null && auth.passphrase.length > 0 && auth.passphrase.length < MIN_V3_PASSPHRASE_LEN
  const privTooShort = priv != null && priv.passphrase.length > 0 && priv.passphrase.length < MIN_V3_PASSPHRASE_LEN

  return (
    <div className="util-col gap-2">
      <Field label="Имя пользователя (securityName)">
        <input className="input mono" placeholder="monitor" value={credential.user} onChange={(e) => onChange({ ...credential, user: e.target.value })} />
      </Field>

      <label className="checkbox-row">
        <input type="checkbox" checked={auth != null} onChange={(e) => setAuthEnabled(e.target.checked)} />
        Аутентификация (authNoPriv/authPriv) — выключено значит noAuthNoPriv
      </label>
      {auth != null && (
        <div className="filter-bar__row">
          <select className="input" value={auth.protocol} onChange={(e) => onChange({ ...credential, auth: { ...auth, protocol: e.target.value as SnmpAuthProtocol } })} style={{ maxWidth: '8rem' }}>
            {AUTH_PROTOCOL_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
          <input
            className="input mono"
            type="password"
            placeholder="пароль аутентификации, ≥ 8 символов"
            value={auth.passphrase}
            onChange={(e) => onChange({ ...credential, auth: { ...auth, passphrase: e.target.value } })}
          />
        </div>
      )}
      {authTooShort && <span className="row-sub" style={{ color: 'var(--status-critical)' }}>пароль аутентификации должен быть не короче {MIN_V3_PASSPHRASE_LEN} символов</span>}

      <label className="checkbox-row" title={auth == null ? 'сначала включите аутентификацию — приватность без неё (privNoAuth) не поддерживается SNMPv3' : undefined}>
        <input type="checkbox" checked={priv != null} disabled={auth == null} onChange={(e) => setPrivEnabled(e.target.checked)} />
        Приватность/шифрование (authPriv)
      </label>
      {priv != null && (
        <div className="filter-bar__row">
          <select className="input" value={priv.protocol} onChange={(e) => onChange({ ...credential, priv_: { ...priv, protocol: e.target.value as SnmpPrivProtocol } })} style={{ maxWidth: '12rem' }}>
            {PRIV_PROTOCOL_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
          <input
            className="input mono"
            type="password"
            placeholder="пароль приватности, ≥ 8 символов"
            value={priv.passphrase}
            onChange={(e) => onChange({ ...credential, priv_: { ...priv, passphrase: e.target.value } })}
          />
        </div>
      )}
      {privTooShort && <span className="row-sub" style={{ color: 'var(--status-critical)' }}>пароль приватности должен быть не короче {MIN_V3_PASSPHRASE_LEN} символов</span>}
    </div>
  )
}

interface OidRow {
  name: string
  oid: string
  kind: OidKind
  columnsMode: ColumnsMode
  columns: [string, string][]
}

/** Wire (`SubnetSpec.oids`) <-> editing (`EditingSubnet.oids`) boundary conversions — see
 * `EditingSubnet`'s docs for why `columnsMode` only lives losslessly on the editing side.
 * Called exactly at the two points an editing session starts/ends (`subnetToEditing`/
 * `editingToSubnet`), never per-keystroke. */
function specToOidRow(name: string, spec: DiscoveryOidSpec): OidRow {
  if (typeof spec === 'string') return { name, oid: spec, kind: 'scalar', columnsMode: 'auto', columns: [] }
  const entries = spec.columns != null ? Object.entries(spec.columns) : []
  return { name, oid: spec.oid, kind: spec.columns != null ? 'table' : 'scalar', columnsMode: entries.length > 0 ? 'manual' : 'auto', columns: entries }
}

function oidRowToEntry(row: OidRow): [string, DiscoveryOidSpec] {
  if (row.kind === 'scalar') return [row.name, row.oid]
  const columns = row.columnsMode === 'auto' ? {} : Object.fromEntries(row.columns)
  return [row.name, { oid: row.oid, columns }]
}

/** Editor for `EditingSubnet.oids` — one row per discovery-time OID, each independently
 * scalar or table-shaped (`OidTypeAndValueFields`/`TableColumnsFields`, shared with
 * `ProfilesPage`'s metric editor — same widget, same underlying `discovery_snmp::table`
 * walk logic on the Rust side, see `discovery-snmp::table`'s docs). Fully controlled by
 * the `rows` prop, no internal state — same convention `CredentialsEditor`/`KvEditor`
 * already use one level up. **Not** `Record<string, DiscoveryOidSpec>` (the wire shape,
 * as it was until the 2026-09-20 pre-release audit, finding 10) — see `EditingSubnet`'s
 * docs for why re-deriving `OidRow[]` from that lossy shape on every render made a fresh
 * "curated columns" selection with zero columns typed in yet indistinguishable from
 * "auto", so the select instantly reverted itself. */
function DiscoveryOidsEditor({ rows, onChange }: { rows: OidRow[]; onChange: (rows: OidRow[]) => void }) {
  function commit(nextRows: OidRow[]) {
    onChange(nextRows)
  }
  function updateRow(idx: number, patch: Partial<OidRow>) {
    const next = rows.slice()
    next[idx] = { ...next[idx], ...patch }
    commit(next)
  }
  function removeRow(idx: number) {
    commit(rows.filter((_, i) => i !== idx))
  }
  function addRow() {
    commit([...rows, { name: '', oid: '', kind: 'scalar', columnsMode: 'auto', columns: [] }])
  }

  return (
    <div style={{ marginTop: '.75rem' }}>
      <Field label="Доп. OID для обогащения" hint="опрашивается один раз при первом обнаружении устройства — скаляр или таблица (SNMP walk), как метрики профиля">
        <div className="util-col gap-2">
          {rows.map((row, idx) => (
            <div key={idx} className="card card-pad">
              <div className="filter-bar__row">
                <input className="input" placeholder="имя, напр. sys_descr" value={row.name} onChange={(e) => updateRow(idx, { name: e.target.value })} />
                <Button variant="ghost" iconOnly small title="Удалить" onClick={() => removeRow(idx)}>
                  <Icon name="x" />
                </Button>
              </div>
              <div className="form-grid">
                <OidTypeAndValueFields oid={row.oid} kind={row.kind} onChange={(next) => updateRow(idx, { oid: next.oid, kind: next.kind })} />
              </div>
              {row.kind === 'table' && (
                <TableColumnsFields columnsMode={row.columnsMode} columns={row.columns} onChange={(next) => updateRow(idx, { columnsMode: next.columnsMode, columns: next.columns })} />
              )}
            </div>
          ))}
          <Button variant="ghost" small title="Добавить ещё один OID" onClick={addRow} style={{ alignSelf: 'flex-start' }}>
            <Icon name="plus" />
            Добавить
          </Button>
        </div>
      </Field>
    </div>
  )
}
