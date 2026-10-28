import type { ReactNode } from 'react'
import { Icon } from '../components/Icon'
import type { PageMeta } from './pages'

/** `actions` is the page-specific button(s) that used to live in the mockup's
 * `#page-actions` div (e.g. "+ Профиль" on the Profiles page) — each page passes its own. */
export function Topbar({ page, actions, onMenuToggle, menuOpen }: { page: PageMeta; actions?: ReactNode; onMenuToggle: () => void; menuOpen: boolean }) {
  return (
    <div className="topbar">
      <button
        className="btn btn-ghost btn-icon topbar__menu-btn"
        type="button"
        aria-label={menuOpen ? 'Закрыть меню' : 'Открыть меню'}
        aria-expanded={menuOpen}
        aria-controls="main-navigation"
        onClick={onMenuToggle}
      >
        <Icon name={menuOpen ? 'x' : 'menu'} />
      </button>
      <div>
        <div className="topbar__title">{page.title}</div>
        <div className="topbar__subtitle">{page.subtitle}</div>
      </div>
      <div className="topbar__actions">{actions}</div>
    </div>
  )
}
