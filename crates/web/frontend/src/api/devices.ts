import { http } from './http'
import type {
  DevicesPage,
  DevicesQuery,
  DeviceView,
  EnabledBody,
  SetEnabledAllResponse,
  MetricHistoryPage,
  HistoryPageQuery,
  CreateDeviceBody,
  SetSshCredentialsBody,
} from './types'

export type ServiceDiscoveryResult = {
  protocol: string
  profile: string | null
  service: string | null
  ok: boolean
  latency_ms: number | null
  error: string | null
}

export type ServiceDiscoveryResponse = {
  ip: string
  device_id: string | null
  profile: string | null
  created: boolean
  results: ServiceDiscoveryResult[]
}

export type OperatorAction = 'test' | 'poll-now' | 'rediscover' | 'backup'

export type OperatorActionJob = {
  alert_id?: string | null
  job_id: number
  device_id: string
  action: 'test' | 'poll_now' | 'rediscover' | 'backup'
  status: 'pending' | 'in_progress' | 'done' | 'failed' | 'cancelled'
  result: Record<string, unknown> | null
  error: string | null
  created_at: string
  updated_at: string
}

export const devicesApi = {
  list: (query: DevicesQuery) =>
    http.get<DevicesPage>('/api/devices', query),
  create: (body: CreateDeviceBody) => http.post<DeviceView>('/api/devices', body),
  discoverServices: (ip: string, protocols?: string[]) =>
    http.post<ServiceDiscoveryResponse>('/api/service-discovery', { ip, protocols }),
  get: (id: string) => http.get<DeviceView>(`/api/devices/${id}`),
  runAction: (id: string, action: OperatorAction) =>
    http.post<OperatorActionJob>(`/api/devices/${id}/actions/${action}`),
  listActions: (id: string) =>
    http.get<OperatorActionJob[]>(`/api/devices/${id}/actions`),
  getAction: (id: string, jobId: number) =>
    http.get<OperatorActionJob>(`/api/devices/${id}/actions/jobs/${jobId}`),
  cancelAction: (id: string, jobId: number) =>
    http.delete<void>(`/api/devices/${id}/actions/jobs/${jobId}`),
  delete: (id: string) => http.delete<void>(`/api/devices/${id}`),
  setEnabled: (id: string, enabled: boolean) =>
    http.put<void>(`/api/devices/${id}/enabled`, { enabled } satisfies EnabledBody),
  setAllEnabled: (enabled: boolean, query?: DevicesQuery) => {
    const params = new URLSearchParams()
    for (const [key, value] of Object.entries(query ?? {})) {
      if (value !== undefined && value !== '') params.set(key, String(value))
    }
    const suffix = params.toString()
    return http.put<SetEnabledAllResponse>(`/api/devices/enabled${suffix ? `?${suffix}` : ''}`, { enabled } satisfies EnabledBody)
  },
  syncWithProfile: (id: string) => http.post<void>(`/api/devices/${id}/sync-profile`),
  setSshCredentials: (id: string, body: SetSshCredentialsBody) => http.put<void>(`/api/devices/${id}/ssh_credentials`, body),
  setMetricOverride: (id: string, name: string, enabled: boolean) =>
    http.put<void>(`/api/devices/${id}/metrics/${encodeURIComponent(name)}/enabled`, { enabled } satisfies EnabledBody),
  clearMetricOverride: (id: string, name: string) =>
    http.delete<void>(`/api/devices/${id}/metrics/${encodeURIComponent(name)}/enabled`),
  metricHistory: (id: string, name: string, query?: HistoryPageQuery) =>
    http.get<MetricHistoryPage>(`/api/devices/${id}/metrics/${encodeURIComponent(name)}/history`, query),
}
