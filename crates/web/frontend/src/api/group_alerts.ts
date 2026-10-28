import { http } from './http'
import type { GroupAlertRule, GroupAlertRuleBody } from './types'

export const groupAlertRulesApi = {
  list: () => http.get<GroupAlertRule[]>('/api/group-alerts/rules'),
  get: (id: string) => http.get<GroupAlertRule>(`/api/group-alerts/rules/${encodeURIComponent(id)}`),
  upsert: (body: GroupAlertRuleBody) => http.post<GroupAlertRule>('/api/group-alerts/rules', body),
  delete: (id: string) => http.delete<void>(`/api/group-alerts/rules/${encodeURIComponent(id)}`),
}
