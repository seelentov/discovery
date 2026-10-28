import { Icon } from '../components/Icon'
import { useAuth } from '../hooks/useAuth'
import { NAV_GROUPS, PAGE_DOMAINS, type PageId } from './pages'

export function Sidebar({ current, onNavigate, onOpenSearch, onClose, open }: { current: PageId; onNavigate: (page: PageId) => void; onOpenSearch: () => void; onClose: () => void; open: boolean }) {
  const { user, logout, canRead } = useAuth()
  const initials = user
    ? user.username
        .split(/\s+/)
        .map((p) => p.charAt(0))
        .join('')
        .toUpperCase()
        .slice(0, 2)
    : '?'

  return (
    <aside id="main-navigation" className={open ? 'sidebar open' : 'sidebar'}>
      <div className="sidebar__brand">
        <Icon name="radar" className="brand-icon" />
        <div>
          <div className="wordmark">Discovery</div>
          <div className="tagline">Network Ops</div>
        </div>
      </div>

      <button className="sidebar__search-btn" title="Поиск по всему" onClick={onOpenSearch}>
        <Icon name="search" />
        Поиск
      </button>

      {NAV_GROUPS.map((group) => {
        // "Пользователи"/"Журнал" are admin-only — hidden here purely for UI cleanliness
        // (same as the old dashboard's `nav-users` display toggle); the server
        // independently rejects `/api/users*`/`/api/journal` for a non-admin regardless
        // of what this sidebar shows.
        const pages = group.pages.filter((page) => {
          if ((page.id === 'users' || page.id === 'journal') && !user?.is_admin) return false
          const domain = PAGE_DOMAINS[page.id]
          return !domain || canRead(domain)
        })
        if (pages.length === 0) return null
        return (
          <div key={group.label}>
            <div className="nav-section-label">{group.label}</div>
            <div className="nav-list">
              {pages.map((page) => (
                <button
                  key={page.id}
                  className={page.id === current ? 'nav-item active' : 'nav-item'}
                  onClick={() => onNavigate(page.id)}
                >
                  <Icon name={page.icon} />
                  {page.label}
                </button>
              ))}
            </div>
          </div>
        )
      })}

      <div className="sidebar__footer">
        <div className="user-row">
          <div className="avatar">{initials}</div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="user-row__name">{user?.username}</div>
            <div className="user-row__role">{user?.is_admin ? 'Администратор' : 'Пользователь'}</div>
          </div>
          <button className="btn btn-ghost btn-icon btn-sm" title="Выйти" onClick={() => { onClose(); logout() }}>
            <Icon name="logout" />
          </button>
        </div>
      </div>
    </aside>
  )
}
