import { http } from './http'
import type {
  DeadDeviceRetentionConfig,
  DomainRouting,
  PingConfig,
  PollIntervalsConfig,
  StorageDatabasesUpdate,
  StorageDatabasesView,
  StorageWriteResponse,
} from './types'

export const settingsApi = {
  getPollIntervals: () => http.get<PollIntervalsConfig>('/api/settings/poll-intervals'),
  setPollIntervals: (body: PollIntervalsConfig) => http.put<void>('/api/settings/poll-intervals', body),
  getPing: () => http.get<PingConfig>('/api/settings/ping'),
  setPing: (body: PingConfig) => http.put<void>('/api/settings/ping', body),
  getDeadDeviceRetention: () => http.get<DeadDeviceRetentionConfig>('/api/settings/dead-device-retention'),
  setDeadDeviceRetention: (body: DeadDeviceRetentionConfig) => http.put<void>('/api/settings/dead-device-retention', body),
  getDatabases: () => http.get<StorageDatabasesView>('/api/settings/databases'),
  setDatabases: (body: StorageDatabasesUpdate) => http.put<StorageWriteResponse>('/api/settings/databases', body),
  getRouting: () => http.get<DomainRouting>('/api/settings/routing'),
  setRouting: (body: DomainRouting) => http.put<StorageWriteResponse>('/api/settings/routing', body),
  restart: () => http.post<void>('/api/system/restart'),
}
