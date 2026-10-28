import { http } from './http'
import type { AddAlertCommentBody, Alert, AlertRule, AlertRuleStatus, AlertComment, AlertListPage, AlertRetentionConfig, AlertsQuery, AttachmentUploadBody } from './types'

/** Direct, browser-fetchable URL for one attachment's bytes — no JS fetch/blob dance
 * needed for `<img src>`/`<video src>`/a plain download link: the session is an
 * `HttpOnly` cookie (see `api/http.ts`'s docs), which the browser attaches to this GET
 * on its own, same as any other same-origin request. */
export function alertCommentAttachmentUrl(alertId: string, commentId: string, attachmentId: string): string {
  return `/api/alerts/${alertId}/comments/${commentId}/attachments/${attachmentId}`
}

export const alertsApi = {
  screen: () => http.get<Alert[]>('/api/alerts/screen'),
  sharedRules: () => http.get<AlertRule[]>('/api/alert-rules/shared'),
  saveSharedRule: (rule: AlertRule) => http.post<void>('/api/alert-rules/shared', rule),
  deleteSharedRule: (name: string) => http.delete<void>(`/api/alert-rules/shared/${encodeURIComponent(name)}`),
  ruleStatuses: (deviceId: string) => http.get<AlertRuleStatus[]>(`/api/devices/${deviceId}/alert-rules`),
  action: (id: string, action: string) => http.post<{ job_id: number }>(`/api/alerts/${id}/actions/${action.replace('_', '-')}`),
  /** Live, in-memory snapshot of currently-active incidents (`AlertStateTracker`) — cheap,
   * no DB round-trip, unlike `list()` below. What the Overview page's "active alerts"
   * count/list comes from. */
  incidents: () => http.get<Alert[]>('/api/incidents'),
  list: (query: AlertsQuery) => http.get<AlertListPage>('/api/alerts', query),
  get: (id: string) => http.get<Alert>(`/api/alerts/${id}`),
  delete: (id: string) => http.delete<void>(`/api/alerts/${id}`),
  close: (id: string) => http.post<void>(`/api/alerts/${id}/close`),
  acknowledge: (id: string) => http.post<Alert>(`/api/alerts/${id}/acknowledge`),
  unacknowledge: (id: string) => http.post<Alert>(`/api/alerts/${id}/unacknowledge`),
  snooze: (id: string, until: string) => http.post<Alert>(`/api/alerts/${id}/snooze`, { until }),
  unsnooze: (id: string) => http.post<Alert>(`/api/alerts/${id}/unsnooze`),
  listComments: (id: string) => http.get<AlertComment[]>(`/api/alerts/${id}/comments`),
  addComment: (id: string, text: string, attachments?: AttachmentUploadBody[]) =>
    http.post<AlertComment>(`/api/alerts/${id}/comments`, { text, attachments } satisfies AddAlertCommentBody),
  getRetention: () => http.get<AlertRetentionConfig>('/api/settings/alert-retention'),
  setRetention: (retention: AlertRetentionConfig) => http.put<void>('/api/settings/alert-retention', retention),
}
