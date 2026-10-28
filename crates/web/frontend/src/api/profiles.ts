import { http } from './http'
import type { ProfileFile, ProfilesPage, ProfilesQuery, SyncProfileDevicesResponse } from './types'

export const profilesApi = {
  list: (query: ProfilesQuery) => http.get<ProfilesPage>('/api/profiles', query),
  get: (name: string) => http.get<ProfileFile>(`/api/profiles/${encodeURIComponent(name)}`),
  upsert: (profile: ProfileFile) => http.post<void>('/api/profiles', profile),
  delete: (name: string) => http.delete<void>(`/api/profiles/${encodeURIComponent(name)}`),
  syncDevices: (name: string) => http.post<SyncProfileDevicesResponse>(`/api/profiles/${encodeURIComponent(name)}/sync-devices`),
}
