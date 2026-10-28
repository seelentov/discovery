import { useEffect, type ReactNode } from 'react'
import { Icon } from './Icon'

/**
 * Generic modal shell — unlike the design mockup's single global `#app-modal` + a
 * `MODAL_TEMPLATES` registry keyed by string (a pattern that only made sense for a
 * no-build vanilla-JS artifact), each call site here owns its own `open` boolean and
 * renders its own `<Modal>` — the idiomatic React shape for the same generic-shell idea.
 *
 * Every modal in the app (Facts-viewer, comments, SSH-креды, `useConfirm`'s confirmation
 * dialog, ...) goes through this one shell, so the 2026-09-17 audit finding #7 fix
 * (Escape didn't close any modal — only an explicit click on «Закрыть»/the X icon did,
 * unlike the standard web expectation) lands here once for all of them.
 */
export function Modal({
  open,
  title,
  wide,
  onClose,
  footer,
  children,
}: {
  open: boolean
  title: string
  wide?: boolean
  onClose: () => void
  footer?: ReactNode
  children: ReactNode
}) {
  // Only listens while actually open, and re-subscribes if `onClose` itself changes
  // (call sites commonly pass an inline closure) — a stale closure here would close the
  // *previous* modal's state instead of the one currently on screen.
  useEffect(() => {
    if (!open) return;
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose();
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [open, onClose]);

  if (!open) return null
  return (
    <div className="modal-backdrop" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className={wide ? 'modal modal-lg' : 'modal'}>
        <div className="modal-header">
          <h3>{title}</h3>
          <button className="btn btn-ghost btn-icon btn-sm" title="Закрыть" onClick={onClose}>
            <Icon name="x" />
          </button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-footer">{footer}</div>}
      </div>
    </div>
  )
}
