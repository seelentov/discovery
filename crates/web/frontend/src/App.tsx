import { AlertScreenNotifications } from './components/AlertScreenNotifications'
import { useEffect, useState } from 'react'
import { CommandPalette } from './components/CommandPalette'
import { IconSprite } from './components/Icon'
import { AuthProvider, useAuth } from './hooks/useAuth'
import { ConfirmProvider } from './hooks/useConfirm'
import { ToastProvider } from './hooks/useToast'
import { Shell } from './layout/Shell'
import { pageFromPathname, pathForPage, type PageId } from './layout/pages'
import { AiAssistantPage } from './pages/AiAssistantPage'
import { AlertsPage } from './pages/AlertsPage'
import { ChangePasswordPage } from './pages/ChangePasswordPage'
import { DevicesPage } from './pages/DevicesPage'
import { DiscoveryPage } from './pages/DiscoveryPage'
import { GroupAlertsPage } from './pages/GroupAlertsPage'
import { JournalPage } from './pages/JournalPage'
import { LoginPage } from './pages/LoginPage'
import { LogsPage } from './pages/LogsPage'
import { MaintenanceWindowsPage } from './pages/MaintenanceWindowsPage'
import { NotificationsPage } from './pages/NotificationsPage'
import { OverviewPage } from './pages/OverviewPage'
import { ProfilesPage } from './pages/ProfilesPage'
import { QueuesPage } from './pages/QueuesPage'
import { SettingsPage } from './pages/SettingsPage'
import { TopologyPage } from './pages/TopologyPage'
import { UsersPage } from './pages/UsersPage'

const PAGE_COMPONENTS: Record<Exclude<PageId, 'overview' | 'alerts' | 'profiles' | 'devices' | 'discovery'>, () => React.JSX.Element> = {
  queues: QueuesPage,
  logs: LogsPage,
  assistant: AiAssistantPage,
  maintenance: MaintenanceWindowsPage,
  notifications: NotificationsPage,
  topology: TopologyPage,
  'group-alerts': GroupAlertsPage,
  settings: SettingsPage,
  users: UsersPage,
  journal: JournalPage,
}

function AuthedApp() {
  // Audit finding 6 (2026-09-20, see `layout/pages.ts`'s `pathForPage`/`pageFromPathname`
  // docs) — initialized from the real URL, not a hardcoded `'overview'`, so a direct
  // navigation/bookmark/F5 on any page lands on that page instead of always bouncing back
  // to Overview. `setPage` below (not this raw setter) is what every navigation call site
  // in this file actually uses — it also pushes the matching URL.
  const [page, setPageState] = useState<PageId>(() => pageFromPathname(window.location.pathname))
  const { user } = useAuth()

  function setPage(id: PageId) {
    setPageState(id)
    if (window.location.pathname !== pathForPage(id)) {
      window.history.pushState(null, '', pathForPage(id))
    }
  }

  // Browser back/forward — `popstate` fires with the URL already changed, so this only
  // needs to resync React state to it, never push a new entry itself (that would turn
  // "back" into a no-op loop).
  useEffect(() => {
    function onPopState() {
      setPageState(pageFromPathname(window.location.pathname))
    }
    window.addEventListener('popstate', onPopState)
    return () => window.removeEventListener('popstate', onPopState)
  }, [])
  // Set by Alerts' "правило: X →" link (tab: 'alerts') or Devices' profile-name link
  // (tab: 'main') — Profiles reads this once on mount to auto-open that profile's edit
  // modal on the right tab, then clears it via `onOpenProfileHandled` so navigating to
  // Profiles normally afterward doesn't re-trigger it.
  const [pendingProfile, setPendingProfile] = useState<{ name: string; tab: 'main' | 'alerts' } | null>(null)
  // Set by Alerts' IP link — Devices reads this once on mount to pre-fill its search
  // filter with that IP, then clears it via `onOpenDeviceHandled` the same way.
  const [pendingDeviceIp, setPendingDeviceIp] = useState<string | null>(null)
  // Set by Devices' "активные тревоги" count link (deviceIp) or Overview's "активные
  // тревоги" tile/panel (onlyActive) — same deep-link shape, reverse direction: Alerts
  // reads this once on mount to pre-fill its own search box and/or state filter.
  const [pendingAlertFilter, setPendingAlertFilter] = useState<{ deviceIp?: string; onlyActive?: boolean } | null>(null)
  // Set by the global command palette — Discovery reads this once on mount to open that
  // config's edit modal directly, same "fetch by name, don't wait for the list" pattern
  // `pendingProfile`/`ProfilesPage.openProfile` already uses.
  const [pendingDiscoveryConfig, setPendingDiscoveryConfig] = useState<string | null>(null)
  // Global search / command palette (⌘K or the sidebar button) — direct user request
  // 2026-08-28: "Была отличная фича в дизайне - поиск по ВСЕМУ".
  const [paletteOpen, setPaletteOpen] = useState(false)

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setPaletteOpen(true)
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [])

  function openProfile(name: string, tab: 'main' | 'alerts' = 'main') {
    setPendingProfile({ name, tab })
    setPage('profiles')
  }

  function openDevice(ip: string) {
    setPendingDeviceIp(ip)
    setPage('devices')
  }

  function openAlertsForDevice(ip: string) {
    setPendingAlertFilter({ deviceIp: ip })
    setPage('alerts')
  }

  function openActiveAlerts() {
    setPendingAlertFilter({ onlyActive: true })
    setPage('alerts')
  }

  function openDiscoveryConfig(name: string) {
    setPendingDiscoveryConfig(name)
    setPage('discovery')
  }

  let content: React.JSX.Element
  if (page === 'overview') {
    content = <OverviewPage onNavigate={setPage} onOpenActiveAlerts={openActiveAlerts} />
  } else if (page === 'alerts') {
    content = (
      <AlertsPage
        onOpenProfile={(name) => openProfile(name, 'alerts')}
        onOpenDevice={openDevice}
        openFilter={pendingAlertFilter}
        onOpenFilterHandled={() => setPendingAlertFilter(null)}
      />
    )
  } else if (page === 'profiles') {
    content = <ProfilesPage openProfile={pendingProfile} onOpenProfileHandled={() => setPendingProfile(null)} />
  } else if (page === 'devices') {
    content = (
      <DevicesPage
        openDeviceIp={pendingDeviceIp}
        onOpenDeviceHandled={() => setPendingDeviceIp(null)}
        onOpenProfile={(name) => openProfile(name, 'main')}
        onOpenAlertsForDevice={openAlertsForDevice}
      />
    )
  } else if (page === 'discovery') {
    content = <DiscoveryPage openConfig={pendingDiscoveryConfig} onOpenConfigHandled={() => setPendingDiscoveryConfig(null)} />
  } else if ((page === 'users' || page === 'journal') && !user?.is_admin) {
    content = <div className="stamp">Раздел доступен только администраторам.</div>
  } else {
    const PageComponent = PAGE_COMPONENTS[page]
    content = <PageComponent />
  }

  return (
    <Shell current={page} onNavigate={setPage} onOpenSearch={() => setPaletteOpen(true)}>
      {content}
      <AlertScreenNotifications />
      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        onOpenDevice={openDevice}
        onOpenAlert={openAlertsForDevice}
        onOpenProfile={(name) => openProfile(name, 'main')}
        onOpenDiscoveryConfig={openDiscoveryConfig}
        onOpenUsers={() => setPage('users')}
      />
    </Shell>
  )
}

function Root() {
  const { user } = useAuth()
  if (user === undefined) return null // still checking the session — avoid a login flash
  if (user === null) return <LoginPage />
  // Blocking gate — see `ChangePasswordPage`'s docs. Checked before `AuthedApp` renders
  // anything (sidebar, page content) that would just fail server-side anyway.
  if (user.must_change_password) return <ChangePasswordPage />
  return <AuthedApp />
}

export default function App() {
  return (
    <AuthProvider>
      <ToastProvider>
        <ConfirmProvider>
          <IconSprite />
          <Root />
        </ConfirmProvider>
      </ToastProvider>
    </AuthProvider>
  )
}
