import { http } from './http'
import type { JournalListPage, JournalQuery, JournalRetentionConfig } from './types'

export const journalApi = {
  list: (query: JournalQuery) => http.get<JournalListPage>('/api/journal', query),
  getRetention: () => http.get<JournalRetentionConfig>('/api/settings/journal-retention'),
  setRetention: (retention: JournalRetentionConfig) => http.put<void>('/api/settings/journal-retention', retention),
}
