import { http } from './http'
import type { CreateUserRequest, SetAdminRequest, SetPasswordRequest, SetUserRoleRequest, UserListItem } from './types'

export const usersApi = {
  list: () => http.get<UserListItem[]>('/api/users'),
  create: (body: CreateUserRequest) => http.post<void>('/api/users', body),
  delete: (id: string) => http.delete<void>(`/api/users/${id}`),
  setPassword: (id: string, password: string) => http.put<void>(`/api/users/${id}/password`, { password } satisfies SetPasswordRequest),
  setAdmin: (id: string, is_admin: boolean) => http.put<void>(`/api/users/${id}/admin`, { is_admin } satisfies SetAdminRequest),
  setRole: (id: string, role_id: string | null) => http.put<void>(`/api/users/${id}/role`, { role_id } satisfies SetUserRoleRequest),
}
