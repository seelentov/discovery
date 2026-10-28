import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from 'react'
import { Button } from '../components/Button'
import { Icon, type IconName } from '../components/Icon'
import { Modal } from '../components/Modal'

interface ConfirmOptions {
  /** Button label — round-11 design audit fixed the mockup's confirm dialog always
   * saying "Удалить" regardless of the actual action; keep passing an accurate verb per
   * call site ("Синхронизировать", "Выключить", "Закрыть", ...), don't default this to
   * "Удалить" and let call sites forget to override it. */
  label: string
  icon?: IconName
  /** Whether the confirm button reads as destructive (`.btn-danger`) or as the app's
   * neutral action style (`.btn-primary`) — defaults to `true` since most confirms in
   * this app guard a deletion. */
  danger?: boolean
}

type ConfirmFn = (message: string, options: ConfirmOptions) => Promise<boolean>

const ConfirmContext = createContext<ConfirmFn | null>(null)

interface PendingConfirm {
  message: string
  options: ConfirmOptions
  resolve: (value: boolean) => void
}

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<PendingConfirm | null>(null)
  const resolveRef = useRef<((value: boolean) => void) | null>(null)

  const confirm = useCallback<ConfirmFn>((message, options) => {
    return new Promise<boolean>((resolve) => {
      resolveRef.current = resolve
      setPending({ message, options, resolve })
    })
  }, [])

  const settle = (value: boolean) => {
    resolveRef.current?.(value)
    resolveRef.current = null
    setPending(null)
  }

  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      <Modal
        open={pending !== null}
        title="Подтверждение"
        onClose={() => settle(false)}
        footer={
          <>
            <Button variant="ghost" onClick={() => settle(false)}>
              Отмена
            </Button>
            <Button variant={pending?.options.danger === false ? 'primary' : 'danger'} onClick={() => settle(true)}>
              {pending?.options.icon && <Icon name={pending.options.icon} />}
              {pending?.options.label}
            </Button>
          </>
        }
      >
        <p className="stamp" style={{ maxWidth: 'none' }}>
          {pending?.message}
        </p>
      </Modal>
    </ConfirmContext.Provider>
  )
}

/** `const confirm = useConfirm(); if (await confirm('Удалить устройство «10.0.0.1»?', {
 * label: 'Удалить', icon: 'trash' })) { ... }` */
export function useConfirm(): ConfirmFn {
  const ctx = useContext(ConfirmContext)
  if (!ctx) throw new Error('useConfirm must be used inside <ConfirmProvider>')
  return ctx
}
