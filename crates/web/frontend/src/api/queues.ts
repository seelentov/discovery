import { http } from './http'
import type {
  ClearQueueResponse,
  JobListPage,
  JobStateParam,
  QueueJobsQuery,
  QueuePausedBody,
  QueueStatsView,
  WorkerActivity,
} from './types'

export const queuesApi = {
  list: () => http.get<QueueStatsView[]>('/api/queues'),
  workers: () => http.get<WorkerActivity[]>('/api/workers'),
  jobs: (kind: string, query: QueueJobsQuery) => http.get<JobListPage>(`/api/queues/${kind}/jobs`, query),
  setPaused: (kind: string, paused: boolean) =>
    http.put<void>(`/api/queues/${kind}/paused`, { paused } satisfies QueuePausedBody),
  deleteJob: (kind: string, id: number) => http.delete<void>(`/api/queues/${kind}/jobs/${id}`),
  pauseJob: (kind: string, id: number) => http.post<void>(`/api/queues/${kind}/jobs/${id}/pause`),
  resumeJob: (kind: string, id: number) => http.post<void>(`/api/queues/${kind}/jobs/${id}/resume`),
  clear: (kind: string, state?: JobStateParam) =>
    http.delete<ClearQueueResponse>(`/api/queues/${kind}/jobs${state ? `?state=${state}` : ''}`),
}
