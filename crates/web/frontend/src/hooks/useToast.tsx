import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from 'react'
import { Icon } from '../components/Icon'

interface ToastEntry {
  id: number
  message: string
  isError: boolean
}

const ToastContext = createContext<((message: string, isError?: boolean) => void) | null>(null)

const TOAST_LIFETIME_MS = 2800

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastEntry[]>([])
  const nextId = useRef(0)

  const toast = useCallback((message: string, isError = false) => {
    const id = nextId.current++
    setToasts((prev) => [...prev, { id, message, isError }])
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), TOAST_LIFETIME_MS)
  }, [])

  return (
    <ToastContext.Provider value={toast}>
      {children}
      <div className="toast-stack">
        {toasts.map((t) => (
          <div key={t.id} className={t.isError ? 'toast toast-error' : 'toast'}>
            <Icon name={t.isError ? 'x-circle' : 'check-circle'} />
            {t.message}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

/** `const toast = useToast(); toast('Профиль сохранён'); toast('Не удалось сохранить', true)`. */
export function useToast() {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast must be used inside <ToastProvider>')
  return ctx
}
