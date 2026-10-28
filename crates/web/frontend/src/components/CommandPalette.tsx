import { useEffect, useState } from 'react'
import { alertsApi } from '../api/alerts'
import { devicesApi } from '../api/devices'
import { discoveryConfigsApi } from '../api/discoveryConfigs'
import { profilesApi } from '../api/profiles'
import { usersApi } from '../api/users'
import type { Alert, DeviceView, DiscoveryConfig, ProfileFile, UserListItem } from '../api/types'
import { Icon } from './Icon'

function useDebouncedValue<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const id = setTimeout(() => setDebounced(value), delayMs)
    return () => clearTimeout(id)
  }, [value, delayMs])
  return debounced
}

interface PaletteResults {
  devices: DeviceView[]
  alerts: Alert[]
  profiles: ProfileFile[]
  discoveryConfigs: DiscoveryConfig[]
  users: UserListItem[]
}

const RESULT_LIMIT = 5

/**
 * Global search / command palette (⌘K or the sidebar's search button) — direct user
 * request 2026-08-28: "Была отличная фича в дизайне - поиск по ВСЕМУ", matching the
 * design artifact's own round-8 feature ("searching devices, alerts, profiles, discovery
 * configs and users at once, clicking a result navigates straight to it"). No dedicated
 * backend endpoint — fans out to each domain's own already-existing, already-paginated
 * `list` endpoint with the same `search` term (users has no server-side search, so its
 * small full list is filtered client-side), same "reuse the existing REST surface"
 * approach the rest of this app's cross-page deep-links already use.
 */
export function CommandPalette({
  open,
  onClose,
  onOpenDevice,
  onOpenAlert,
  onOpenProfile,
  onOpenDiscoveryConfig,
  onOpenUsers,
}: {
  open: boolean
  onClose: () => void
  onOpenDevice: (ip: string) => void
  onOpenAlert: (deviceIp: string) => void
  onOpenProfile: (name: string) => void
  onOpenDiscoveryConfig: (name: string) => void
  onOpenUsers: () => void
}) {
  const [query, setQuery] = useState('')
  const search = useDebouncedValue(query, 250)
  const [results, setResults] = useState<PaletteResults | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!open) {
      setQuery('')
      setResults(null)
    }
  }, [open])

  useEffect(() => {
    if (!open || !search.trim()) {
      setResults(null)
      return
    }
    let cancelled = false
    setLoading(true)
    Promise.all([
      devicesApi.list({ search, page: 1, page_size: RESULT_LIMIT }).catch(() => ({ items: [], total: 0 })),
      alertsApi.list({ search, page: 1, page_size: RESULT_LIMIT }).catch(() => ({ items: [], total: 0 })),
      profilesApi.list({ search, page: 1, page_size: RESULT_LIMIT }).catch(() => ({ items: [], total: 0 })),
      discoveryConfigsApi.list({ search, page: 1, page_size: RESULT_LIMIT }).catch(() => ({ items: [], total: 0 })),
      usersApi.list().catch(() => [] as UserListItem[]),
    ]).then(([devicesRes, alertsRes, profilesRes, discoveryRes, usersRes]) => {
      if (cancelled) return
      const needle = search.toLowerCase()
      setResults({
        devices: devicesRes.items,
        alerts: alertsRes.items,
        profiles: profilesRes.items,
        discoveryConfigs: discoveryRes.items,
        users: usersRes.filter((u) => u.username.toLowerCase().includes(needle)).slice(0, RESULT_LIMIT),
      })
      setLoading(false)
    })
    return () => {
      cancelled = true
    }
  }, [open, search])

  useEffect(() => {
    if (!open) return
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [open, onClose])

  if (!open) return null

  const total = results ? results.devices.length + results.alerts.length + results.profiles.length + results.discoveryConfigs.length + results.users.length : 0

  return (
    <div className="modal-backdrop" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal command-palette">
        <div className="command-palette__input-row">
          <Icon name="search" />
          <input
            autoFocus
            className="command-palette__input"
            placeholder="Поиск по устройствам, тревогам, профилям, дискаверингу, пользователям…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <span className="row-sub">Esc</span>
        </div>
        <div className="command-palette__body">
          {!search.trim() ? (
            <p className="stamp">Начните вводить, чтобы найти устройство, тревогу, профиль, конфигурацию дискаверинга или пользователя.</p>
          ) : loading && !results ? (
            <p className="stamp">Поиск…</p>
          ) : !results || total === 0 ? (
            <p className="stamp">Ничего не найдено.</p>
          ) : (
            <>
              {results.devices.length > 0 && (
                <div className="command-palette__group">
                  <div className="command-palette__group-title">
                    <Icon name="router" /> Устройства
                  </div>
                  {results.devices.map((d) => (
                    <button
                      key={d.id}
                      className="command-palette__item"
                      onClick={() => {
                        onOpenDevice(d.facts.ip)
                        onClose()
                      }}
                    >
                      <span className="mono">{d.facts.ip}</span>
                      {d.profile && <span className="row-sub">профиль: {d.profile}</span>}
                    </button>
                  ))}
                </div>
              )}
              {results.alerts.length > 0 && (
                <div className="command-palette__group">
                  <div className="command-palette__group-title">
                    <Icon name="bell" /> Тревоги
                  </div>
                  {results.alerts.map((a) => (
                    <button
                      key={a.id}
                      className="command-palette__item"
                      onClick={() => {
                        onOpenAlert(a.device_ip)
                        onClose()
                      }}
                    >
                      <span>{a.name}</span>
                      <span className="row-sub mono">{a.device_ip}</span>
                    </button>
                  ))}
                </div>
              )}
              {results.profiles.length > 0 && (
                <div className="command-palette__group">
                  <div className="command-palette__group-title">
                    <Icon name="sliders" /> Профили
                  </div>
                  {results.profiles.map((p) => (
                    <button
                      key={p.profile.name}
                      className="command-palette__item"
                      onClick={() => {
                        onOpenProfile(p.profile.name)
                        onClose()
                      }}
                    >
                      <span>{p.profile.name}</span>
                    </button>
                  ))}
                </div>
              )}
              {results.discoveryConfigs.length > 0 && (
                <div className="command-palette__group">
                  <div className="command-palette__group-title">
                    <Icon name="radar" /> Дискаверинг
                  </div>
                  {results.discoveryConfigs.map((c) => (
                    <button
                      key={c.name}
                      className="command-palette__item"
                      onClick={() => {
                        onOpenDiscoveryConfig(c.name)
                        onClose()
                      }}
                    >
                      <span>{c.name}</span>
                    </button>
                  ))}
                </div>
              )}
              {results.users.length > 0 && (
                <div className="command-palette__group">
                  <div className="command-palette__group-title">
                    <Icon name="users" /> Пользователи
                  </div>
                  {results.users.map((u) => (
                    <button
                      key={u.id}
                      className="command-palette__item"
                      onClick={() => {
                        onOpenUsers()
                        onClose()
                      }}
                    >
                      <span>{u.username}</span>
                      {u.is_admin && <span className="row-sub">админ</span>}
                    </button>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
