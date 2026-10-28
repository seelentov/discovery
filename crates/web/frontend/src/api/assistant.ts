import { http } from './http'
import type { AiAssistantProviderConfig, Conversation, Message, TurnResponse } from './types'

export const assistantApi = {
  listConversations: () => http.get<Conversation[]>('/api/assistant/conversations'),
  createConversation: (title?: string) => http.post<Conversation>('/api/assistant/conversations', { title }),
  setAutoApproveWrites: (conversationId: string, enabled: boolean) =>
    http.put<Conversation>(`/api/assistant/conversations/${encodeURIComponent(conversationId)}`, { auto_approve_writes: enabled }),
  listMessages: (conversationId: string) => http.get<Message[]>(`/api/assistant/conversations/${encodeURIComponent(conversationId)}/messages`),
  sendMessage: (conversationId: string, content: string) => http.post<TurnResponse>(`/api/assistant/conversations/${encodeURIComponent(conversationId)}/messages`, { content }),
  confirmAction: (conversationId: string, messageId: string) =>
    http.post<TurnResponse>(`/api/assistant/conversations/${encodeURIComponent(conversationId)}/messages/${encodeURIComponent(messageId)}/confirm`, {}),
  rejectAction: (conversationId: string, messageId: string) =>
    http.post<TurnResponse>(`/api/assistant/conversations/${encodeURIComponent(conversationId)}/messages/${encodeURIComponent(messageId)}/reject`, {}),
}

export const assistantSettingsApi = {
  get: () => http.get<AiAssistantProviderConfig>('/api/settings/ai-assistant'),
  set: (body: AiAssistantProviderConfig) => http.put<void>('/api/settings/ai-assistant', body),
}
