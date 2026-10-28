import { http } from './http'
import type { DiscoveryConfig, DiscoveryConfigsPage, DiscoveryConfigsQuery, RunDiscoveryConfigResponse } from './types'

export const discoveryConfigsApi = {
  list: (query: DiscoveryConfigsQuery) => http.get<DiscoveryConfigsPage>('/api/discovery-configs', query),
  get: (name: string) => http.get<DiscoveryConfig>(`/api/discovery-configs/${encodeURIComponent(name)}`),
  upsert: (config: DiscoveryConfig) => http.post<void>('/api/discovery-configs', config),
  delete: (name: string) => http.delete<void>(`/api/discovery-configs/${encodeURIComponent(name)}`),
  runNow: (name: string) => http.post<RunDiscoveryConfigResponse>(`/api/discovery-configs/${encodeURIComponent(name)}/run`),
}
