import type { IconName } from '../components/Icon'

export type PageId = 'overview' | 'devices' | 'alerts' | 'queues' | 'logs' | 'profiles' | 'discovery' | 'maintenance' | 'notifications' | 'topology' | 'group-alerts' | 'assistant' | 'settings' | 'users' | 'journal'

/** Domain whose Read permission is needed to show a page in the navigation. Pages
 * without an entry are either cross-domain/read-only shells or self-service surfaces. */
export const PAGE_DOMAINS: Partial<Record<PageId, string>> = {
  devices: 'devices',
  alerts: 'alerts',
  queues: 'jobs',
  logs: 'logs',
  profiles: 'profiles',
  discovery: 'discovery_configs',
  maintenance: 'maintenance_windows',
  // Notifications has a self-service "Мои каналы" surface available to every
  // authenticated user; the page itself gates the admin-only matrix/provider tabs.
  topology: 'topology',
  'group-alerts': 'group_alerts',
  settings: 'settings',
}

export interface PageMeta {
  id: PageId
  label: string
  icon: IconName
  title: string
  subtitle: string
  /** `false` for pages not built yet — shown in the nav (so the chrome/IA is complete
   * from the start) but routed to a "not built yet" placeholder instead of a real page. */
  implemented: boolean
}

export const NAV_GROUPS: { label: string; pages: PageMeta[] }[] = [
  {
    label: 'Мониторинг',
    pages: [
      { id: 'overview', label: 'Обзор', icon: 'grid', title: 'Обзор', subtitle: 'Состояние сети прямо сейчас', implemented: true },
      { id: 'devices', label: 'Устройства', icon: 'router', title: 'Устройства', subtitle: 'Список устройств под мониторингом', implemented: true },
      { id: 'alerts', label: 'Тревоги', icon: 'bell', title: 'Тревоги', subtitle: 'Полная история активаций и снятий', implemented: true },
      // 2026-09-17 audit finding #8: this subtitle used to name a specific queue count
      // ("9") that had already drifted from reality (`topology_recompute` added a 10th
      // queue without this text ever being updated) — deliberately not repeating a count
      // here at all now, since this static nav-metadata module has no live queue list to
      // derive one from and a hardcoded number can only go stale again. The Queues page
      // body itself lists every queue with live, always-accurate stats.
      { id: 'queues', label: 'Очереди', icon: 'stack', title: 'Очереди', subtitle: 'Очереди обработки + активные воркеры', implemented: true },
      { id: 'logs', label: 'Логи', icon: 'terminal', title: 'Логи', subtitle: 'Живой хвост буфера логов агента', implemented: true },
      {
        id: 'assistant',
        label: 'Ассистент',
        icon: 'comment',
        title: 'Ассистент',
        subtitle: 'Чат с ИИ — доступ к данным и действиям в пределах ваших прав',
        implemented: true,
      },
    ],
  },
  {
    label: 'Конфигурация',
    pages: [
      { id: 'profiles', label: 'Профили', icon: 'sliders', title: 'Профили', subtitle: 'Правила сопоставления, метрики, тревоги', implemented: true },
      { id: 'discovery', label: 'Дискаверинг', icon: 'radar', title: 'Дискаверинг', subtitle: 'Конфигурации сканирования подсетей', implemented: true },
      {
        id: 'maintenance',
        label: 'Окна обслуживания',
        icon: 'clock',
        title: 'Окна обслуживания',
        subtitle: 'Подавление тревог на время плановых работ',
        implemented: true,
      },
      {
        id: 'notifications',
        label: 'Уведомления',
        icon: 'mail',
        title: 'Уведомления',
        subtitle: 'Каналы связи и матрица «кого извещать по какой тревоге»',
        implemented: true,
      },
      {
        id: 'topology',
        label: 'Топология',
        icon: 'layout',
        title: 'Топология',
        subtitle: 'Provider-настраиваемые правила построения топологии и подтверждённые связи',
        implemented: true,
      },
      {
        id: 'group-alerts',
        label: 'Групповые тревоги',
        icon: 'filter',
        title: 'Групповые тревоги',
        subtitle: 'Правила подавления тревог по топологической причинности',
        implemented: true,
      },
      { id: 'settings', label: 'Настройки', icon: 'gear', title: 'Настройки', subtitle: 'Периодичность опроса, retention, БД', implemented: true },
      { id: 'users', label: 'Пользователи', icon: 'users', title: 'Пользователи', subtitle: 'Учётные записи и права по доменам', implemented: true },
      // Admin-only, same as 'users' above — see `Sidebar.tsx`'s filter and `App.tsx`'s
      // gate. Grouped with "Конфигурация"/administrative pages, not "Мониторинг" — this
      // is an administrative audit surface, not a live operational view.
      { id: 'journal', label: 'Журнал', icon: 'history', title: 'Журнал', subtitle: 'Кто, где и что изменил — аудит действий пользователей', implemented: true },
    ],
  },
]

export const ALL_PAGES: PageMeta[] = NAV_GROUPS.flatMap((g) => g.pages)

export function pageMeta(id: PageId): PageMeta {
  const meta = ALL_PAGES.find((p) => p.id === id)
  if (!meta) throw new Error(`unknown page id: ${id}`)
  return meta
}

// Audit finding 6 (2026-09-20): `App.tsx` used to track the current page purely as
// in-memory `useState`, never reading `window.location.pathname` or calling
// `history.pushState` — direct URL navigation, F5 on any non-Overview page, and the
// browser's back/forward buttons all silently landed back on Overview instead. `overview`
// lives at `/` (the dashboard's natural landing route); every other page is `/<id>`. The
// server's SPA fallback (`serve_embedded`) already answers any unknown path with
// `index.html`, so this is purely a client-side concern.
export function pathForPage(id: PageId): string {
  return id === 'overview' ? '/' : `/${id}`
}

export function pageFromPathname(pathname: string): PageId {
  const id = pathname.replace(/^\/+|\/+$/g, '')
  if (id === '') return 'overview'
  return (ALL_PAGES.find((p) => p.id === id)?.id as PageId | undefined) ?? 'overview'
}
