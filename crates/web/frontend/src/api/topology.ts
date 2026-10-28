import { http } from './http'
import type { ResolvedNeighbor, TopologyEdgesPage, TopologyEdgesQuery, TopologyRule, TopologyRuleBody } from './types'

export const topologyRulesApi = {
  list: () => http.get<TopologyRule[]>('/api/topology/rules'),
  get: (id: string) => http.get<TopologyRule>(`/api/topology/rules/${encodeURIComponent(id)}`),
  upsert: (body: TopologyRuleBody) => http.post<TopologyRule>('/api/topology/rules', body),
  delete: (id: string) => http.delete<void>(`/api/topology/rules/${encodeURIComponent(id)}`),
  neighbors: (ruleName: string, deviceId: string) => http.get<ResolvedNeighbor[]>(`/api/topology/rules/${encodeURIComponent(ruleName)}/neighbors/${encodeURIComponent(deviceId)}`),
  edges: (ruleName: string, query: TopologyEdgesQuery = {}) => http.get<TopologyEdgesPage>(`/api/topology/rules/${encodeURIComponent(ruleName)}/edges`, query),
  setHierarchyOverride: (ruleName: string, deviceA: string, deviceB: string, upstreamDeviceId: string) =>
    http.put<void>(`/api/topology/rules/${encodeURIComponent(ruleName)}/hierarchy/${encodeURIComponent(deviceA)}/${encodeURIComponent(deviceB)}`, { upstream_device_id: upstreamDeviceId }),
  clearHierarchyOverride: (ruleName: string, deviceA: string, deviceB: string) =>
    http.delete<void>(`/api/topology/rules/${encodeURIComponent(ruleName)}/hierarchy/${encodeURIComponent(deviceA)}/${encodeURIComponent(deviceB)}`),
}
