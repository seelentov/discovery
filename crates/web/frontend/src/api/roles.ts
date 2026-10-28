import { http } from './http'
import type { Role, RoleRequest } from './types'

export const rolesApi = {
  list: () => http.get<Role[]>('/api/roles'),
  get: (id: string) => http.get<Role>(`/api/roles/${id}`),
  create: (body: RoleRequest) => http.post<Role>('/api/roles', body),
  update: (id: string, body: RoleRequest) => http.put<void>(`/api/roles/${id}`, body),
  delete: (id: string) => http.delete<void>(`/api/roles/${id}`),
}
