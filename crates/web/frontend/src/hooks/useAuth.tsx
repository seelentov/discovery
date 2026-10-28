import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
import { authApi } from '../api/auth'
import { ApiHttpError } from '../api/http'
import type { LoginRequest, PermissionLevel, UserView } from '../api/types'

interface AuthState {
  /** `undefined` = still checking `GET /api/auth/me` on startup, `null` = confirmed
   * logged out — kept distinct so the shell can show a loading state instead of
   * flashing the login screen for a moment on every page load. */
  user: UserView | null | undefined
  login: (body: LoginRequest) => Promise<void>
  logout: () => Promise<void>
  loginError: string | null
  canRead: (domain: string) => boolean
  canWrite: (domain: string) => boolean
  /** Re-fetches `GET /api/auth/me` and updates `user` — exposed for `ChangePasswordPage`:
   * after a successful `PUT /api/auth/password`, `user.must_change_password` needs to
   * flip to `false` on the *same* session so `App.tsx`'s `Root` re-renders into the real
   * dashboard, without forcing a full page reload or a fresh login. */
  refreshUser: () => Promise<void>
}

const AuthContext = createContext<AuthState | null>(null)

/** Mirrors the old dashboard's `checkAuth()` pattern (Dashboard (Web UI).md): call
 * `GET /api/auth/me` on start and periodically, treat 401 as "logged out" rather than an
 * error to surface. Re-checks every 60s so an admin revoking a session (or the cookie
 * expiring) is noticed without a manual refresh. */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserView | null | undefined>(undefined)
  const [loginError, setLoginError] = useState<string | null>(null)

  const checkAuth = useCallback(async () => {
    try {
      const result = await authApi.me()
      if (result.kind === 'authenticated') {
        setUser(result.user)
      } else {
        // Both states are expected during normal session lifecycle. In particular,
        // the anonymous first load must not become a console error; an expired
        // session still transitions to the logged-out shell immediately.
        setUser(null)
      }
    } catch (e) {
      // Network/server error — don't force a logged-out flash on a transient blip;
      // next 60s tick tries again. This remains visible because it is not one of
      // the two expected 401 auth states.
      console.error('auth check failed', e)
    }
  }, [])

  useEffect(() => {
    checkAuth()
    const id = setInterval(checkAuth, 60_000)
    return () => clearInterval(id)
  }, [checkAuth])

  const login = useCallback(async (body: LoginRequest) => {
    setLoginError(null)
    try {
      const res = await authApi.login(body)
      setUser(res.user)
    } catch (e) {
      setLoginError(e instanceof ApiHttpError ? e.message : 'Не удалось войти')
      throw e
    }
  }, [])

  const logout = useCallback(async () => {
    await authApi.logout().catch(() => undefined)
    setUser(null)
  }, [])

  const can = useCallback(
    (domain: string, required: PermissionLevel) => {
      if (!user) return false
      if (user.is_admin) return true
      const granted = user.permissions[domain]
      return granted === 'write' || (required === 'read' && granted === 'read')
    },
    [user],
  )

  return (
    <AuthContext.Provider
      value={{
        user,
        login,
        logout,
        loginError,
        canRead: (domain) => can(domain, 'read'),
        canWrite: (domain) => can(domain, 'write'),
        refreshUser: checkAuth,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}
