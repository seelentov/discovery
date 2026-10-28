import { http } from './http'
import type { LogRetentionConfig, LogsPage, LogsQuery } from './types'

export const logsApi = {
  list: (query: LogsQuery) => http.get<LogsPage>('/api/logs', query),
  getRetention: () => http.get<LogRetentionConfig>('/api/settings/log-retention'),
  setRetention: (retention: LogRetentionConfig) => http.put<void>('/api/settings/log-retention', retention),
}
