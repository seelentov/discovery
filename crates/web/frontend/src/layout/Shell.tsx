import { useEffect, useState, type ReactNode } from 'react'
import { Sidebar } from './Sidebar'
import { Topbar } from './Topbar'
import { pageMeta, type PageId } from './pages'

export function Shell({
  current,
  onNavigate,
  onOpenSearch,
  actions,
  children,
}: {
  current: PageId
  onNavigate: (page: PageId) => void
  onOpenSearch: () => void
  actions?: ReactNode
  children: ReactNode
}) {
  const [menuOpen, setMenuOpen] = useState(false)
  const meta = pageMeta(current)

  useEffect(() => {
    if (!menuOpen) return
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') setMenuOpen(false)
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [menuOpen])

  function closeMenu() {
    setMenuOpen(false)
  }

  return (
    <div className="app-shell">
      <Sidebar
        current={current}
        onNavigate={(page) => {
          closeMenu()
          onNavigate(page)
        }}
        onOpenSearch={() => {
          closeMenu()
          onOpenSearch()
        }}
        onClose={closeMenu}
        open={menuOpen}
      />
      <button className={menuOpen ? 'sidebar-backdrop open' : 'sidebar-backdrop'} type="button" aria-label="Закрыть меню" onClick={closeMenu} />
      <div className="content">
        <Topbar page={meta} actions={actions} menuOpen={menuOpen} onMenuToggle={() => setMenuOpen((open) => !open)} />
        <section className="page active">{children}</section>
      </div>
    </div>
  )
}
