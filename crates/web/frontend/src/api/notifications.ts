import { http } from './http'
import type { NotificationChannel, NotificationChannelBody, NotificationProviderConfig, NotificationRecipient, NotificationRecipientRole, NotificationRule, NotificationRuleBody } from './types'

export const notificationChannelsApi = {
  listMine: () => http.get<NotificationChannel[]>('/api/notifications/channels'),
  upsertMine: (body: NotificationChannelBody) => http.post<NotificationChannel>('/api/notifications/channels', body),
  deleteMine: (id: string) => http.delete<void>(`/api/notifications/channels/${encodeURIComponent(id)}`),
  listForUser: (userId: string) => http.get<NotificationChannel[]>(`/api/users/${encodeURIComponent(userId)}/notification-channels`),
  upsertForUser: (userId: string, body: NotificationChannelBody) => http.post<NotificationChannel>(`/api/users/${encodeURIComponent(userId)}/notification-channels`, body),
  deleteForUser: (userId: string, id: string) => http.delete<void>(`/api/users/${encodeURIComponent(userId)}/notification-channels/${encodeURIComponent(id)}`),
}

export const notificationRulesApi = {
  list: () => http.get<NotificationRule[]>('/api/notifications/rules'),
  get: (id: string) => http.get<NotificationRule>(`/api/notifications/rules/${encodeURIComponent(id)}`),
  upsert: (body: NotificationRuleBody) => http.post<NotificationRule>('/api/notifications/rules', body),
  delete: (id: string) => http.delete<void>(`/api/notifications/rules/${encodeURIComponent(id)}`),
  recipients: () => http.get<NotificationRecipient[]>('/api/notifications/recipients'),
  recipientRoles: () => http.get<NotificationRecipientRole[]>('/api/notifications/recipient-roles'),
}

export const notificationProviderApi = {
  get: () => http.get<NotificationProviderConfig>('/api/settings/notifications'),
  set: (body: NotificationProviderConfig) => http.put<void>('/api/settings/notifications', body),
}
