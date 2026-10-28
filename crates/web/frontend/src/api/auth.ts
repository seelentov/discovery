import { ApiHttpError, http } from './http'
import type { ChangePasswordRequest, LoginRequest, LoginResponse, UserView } from './types'

export type AuthMeResult =
  | { kind: 'authenticated'; user: UserView }
  | { kind: 'anonymous' }
  | { kind: 'expired-session' }

export const authApi = {
  login: (body: LoginRequest) => http.post<LoginResponse>('/api/auth/login', body),
  logout: () => http.post<void>('/api/auth/logout'),
  /** Converts the two expected 401 responses into explicit auth states. */
  me: async (): Promise<AuthMeResult> => {
    try {
      return { kind: 'authenticated', user: await http.get<UserView>('/api/auth/me') }
    } catch (error) {
      if (error instanceof ApiHttpError && error.hasStatus(401)) {
        if (error.message === 'not logged in') return { kind: 'anonymous' }
        if (error.message === 'invalid or expired session') return { kind: 'expired-session' }
      }
      throw error
    }
  },
  /** Not domain/admin-gated — reachable even while `must_change_password` is set (that's
   * the whole point, see `ChangePasswordPage`). Throws `ApiHttpError` (401) if
   * `current_password` is wrong. */
  changePassword: (body: ChangePasswordRequest) => http.put<void>('/api/auth/password', body),
}
