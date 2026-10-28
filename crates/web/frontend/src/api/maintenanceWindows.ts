import { http } from './http'
import type { MaintenanceWindow, MaintenanceWindowBody } from './types'

export const maintenanceWindowsApi = {
  list: () => http.get<MaintenanceWindow[]>('/api/maintenance-windows'),
  get: (id: string) => http.get<MaintenanceWindow>(`/api/maintenance-windows/${encodeURIComponent(id)}`),
  upsert: (body: MaintenanceWindowBody) => http.post<MaintenanceWindow>('/api/maintenance-windows', body),
  delete: (id: string) => http.delete<void>(`/api/maintenance-windows/${encodeURIComponent(id)}`),
}
