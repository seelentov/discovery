import { useCallback, useEffect, useRef, useState } from 'react'
import { assistantApi } from '../api/assistant'
import { ApiHttpError } from '../api/http'
import type { Conversation, Message } from '../api/types'
import { Button } from '../components/Button'
import { Icon } from '../components/Icon'
import { Switch } from '../components/Switch'
import { useToast } from '../hooks/useToast'

const STATUS_BADGE: Record<string, { label: string; className: string }> = {
  executed: { label: 'выполнено', className: 'badge-ok' },
  confirmed: { label: 'подтверждено', className: 'badge-ok' },
  failed: { label: 'ошибка', className: 'badge-critical' },
  rejected: { label: 'отклонено', className: 'badge-neutral' },
}

function relativeTime(iso: string): string {
  const diffMs = Date.now() - new Date(iso).getTime()
  const mins = Math.round(diffMs / 60000)
  if (mins < 1) return 'только что'
  if (mins < 60) return `${mins} мин назад`
  const hours = Math.round(mins / 60)
  if (hours < 24) return `${hours} ч назад`
  return new Date(iso).toLocaleDateString('ru-RU')
}

function toolResultSummary(result: Message['tool_result']): string {
  if (result == null) return ''
  if (typeof result === 'object' && 'declined_by_user' in result) return 'отклонено пользователем'
  if (typeof result === 'object' && 'status_code' in result) return `код ${(result as { status_code: number }).status_code}`
  if (typeof result === 'object' && 'error' in result) return `ошибка: ${(result as { error: string }).error}`
  return ''
}

export function AiAssistantPage() {
  const toast = useToast()
  const [conversations, setConversations] = useState<Conversation[] | null>(null)
  const [listError, setListError] = useState('')
  const [activeId, setActiveId] = useState<string | null>(null)
  const [messages, setMessages] = useState<Message[] | null>(null)
  const [messagesError, setMessagesError] = useState('')
  const [providerUnavailable, setProviderUnavailable] = useState<string | null>(null)
  const [input, setInput] = useState('')
  const [sending, setSending] = useState(false)
  const [actingOn, setActingOn] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const transcriptRef = useRef<HTMLDivElement>(null)

  const loadConversations = useCallback(async () => {
    try {
      const list = await assistantApi.listConversations()
      setConversations(list)
      setListError('')
    } catch (e) {
      setListError(e instanceof ApiHttpError ? e.message : 'Не удалось загрузить список чатов')
    }
  }, [])

  useEffect(() => {
    loadConversations()
  }, [loadConversations])

  const loadMessages = useCallback(async (conversationId: string) => {
    try {
      const list = await assistantApi.listMessages(conversationId)
      setMessages(list)
      setMessagesError('')
    } catch (e) {
      setMessagesError(e instanceof ApiHttpError ? e.message : 'Не удалось загрузить историю')
    }
  }, [])

  useEffect(() => {
    if (activeId) {
      setMessages(null)
      setProviderUnavailable(null)
      loadMessages(activeId)
    }
  }, [activeId, loadMessages])

  useEffect(() => {
    transcriptRef.current?.scrollTo({ top: transcriptRef.current.scrollHeight })
  }, [messages, sending])

  async function handleCreateConversation() {
    setCreating(true)
    try {
      const conv = await assistantApi.createConversation()
      setConversations((prev) => [conv, ...(prev ?? [])])
      setActiveId(conv.id)
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось создать чат', true)
    } finally {
      setCreating(false)
    }
  }

  function handleApiError(e: unknown, fallback: string) {
    if (e instanceof ApiHttpError && e.status === 503) {
      setProviderUnavailable(e.message)
      return
    }
    toast(e instanceof ApiHttpError ? e.message : fallback, true)
  }

  async function handleSend() {
    if (!activeId || !input.trim() || sending) return
    setSending(true)
    setProviderUnavailable(null)
    const content = input
    setInput('')
    try {
      await assistantApi.sendMessage(activeId, content)
      await loadMessages(activeId)
    } catch (e) {
      setInput(content)
      handleApiError(e, 'Не удалось отправить сообщение')
    } finally {
      setSending(false)
    }
  }

  async function handleConfirm(messageId: string) {
    if (!activeId) return
    setActingOn(messageId)
    try {
      await assistantApi.confirmAction(activeId, messageId)
      await loadMessages(activeId)
    } catch (e) {
      handleApiError(e, 'Не удалось выполнить действие')
    } finally {
      setActingOn(null)
    }
  }

  async function handleReject(messageId: string) {
    if (!activeId) return
    setActingOn(messageId)
    try {
      await assistantApi.rejectAction(activeId, messageId)
      await loadMessages(activeId)
    } catch (e) {
      handleApiError(e, 'Не удалось отклонить действие')
    } finally {
      setActingOn(null)
    }
  }

  async function handleToggleAutoApprove(next: boolean) {
    if (!activeId) return
    try {
      const updated = await assistantApi.setAutoApproveWrites(activeId, next)
      setConversations((prev) => prev?.map((c) => (c.id === updated.id ? updated : c)) ?? prev)
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось изменить режим подтверждения', true)
    }
  }

  const activeConversation = conversations?.find((c) => c.id === activeId) ?? null
  const lastMessage = messages && messages.length > 0 ? messages[messages.length - 1] : null
  const hasPendingAction = lastMessage?.role === 'assistant' && lastMessage.tool_call_status === 'pending_confirmation'
  const inputDisabled = !activeId || sending || hasPendingAction

  return (
    <div className="assistant-layout">
      <aside className="assistant-sidebar">
        <div className="assistant-sidebar__header">
          <Button variant="primary" small onClick={handleCreateConversation} disabled={creating} title="Начать новый чат с ИИ-ассистентом">
            <Icon name="plus" />
            Новый чат
          </Button>
        </div>
        {listError && <p className="form-error">{listError}</p>}
        {conversations === null ? (
          <p className="stamp">Загрузка…</p>
        ) : conversations.length === 0 ? (
          <p className="stamp">Чатов пока нет — начните первый.</p>
        ) : (
          <ul className="assistant-conv-list">
            {conversations.map((c) => (
              <li key={c.id}>
                <button className={`assistant-conv-item${c.id === activeId ? ' active' : ''}`} onClick={() => setActiveId(c.id)} title={c.title}>
                  <span className="assistant-conv-item__title">{c.title}</span>
                  <span className="assistant-conv-item__time">{relativeTime(c.updated_at)}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </aside>

      <div className="assistant-main">
        {!activeId ? (
          <div className="assistant-empty stamp">Выберите чат слева или начните новый.</div>
        ) : (
          <>
            <div className="assistant-mode-row">
              <Switch
                checked={activeConversation?.auto_approve_writes ?? false}
                onChange={handleToggleAutoApprove}
                title="Выполнять действия ИИ сразу, без ручного подтверждения — как bypass-режим в Claude Code"
                label={['без подтверждения', 'с подтверждением']}
              />
              {activeConversation?.auto_approve_writes && (
                <span className="assistant-mode-row__warning">Действия выполняются сразу, без подтверждения — только для этого чата.</span>
              )}
            </div>
            <div className="assistant-transcript" ref={transcriptRef}>
              {messagesError && <p className="form-error">{messagesError}</p>}
              {messages === null ? (
                <p className="stamp">Загрузка…</p>
              ) : messages.length === 0 ? (
                <p className="stamp">Напишите что-нибудь, чтобы начать разговор.</p>
              ) : (
                messages.map((m) => <MessageItem key={m.id} message={m} acting={actingOn === m.id} onConfirm={() => handleConfirm(m.id)} onReject={() => handleReject(m.id)} />)
              )}
              {sending && (
                // Roadmap 2026-09-18 finding #1: the "hangs" perception was a missing
                // sending-state indicator, not an actual stall — a multi-iteration tool-
                // calling turn against a real LLM provider genuinely can take several
                // seconds to tens of seconds, and until now nothing on screen changed
                // during that whole window besides the input/button silently disabling.
                <div className="assistant-bubble assistant-bubble--assistant assistant-bubble--pending">
                  <div className="assistant-bubble__content">Ассистент обрабатывает запрос…</div>
                </div>
              )}
            </div>

            {providerUnavailable && (
              <div className="assistant-banner">
                {providerUnavailable} — ИИ-ассистент не настроен. Обратитесь к администратору (вкладка «ИИ-ассистент» в Настройках).
              </div>
            )}

            <div className="assistant-input-row">
              <textarea
                className="input assistant-input"
                placeholder={hasPendingAction ? 'Сначала подтвердите или отклоните предложенное действие выше' : 'Спросите что-нибудь или попросите выполнить действие…'}
                value={input}
                disabled={inputDisabled}
                rows={2}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault()
                    handleSend()
                  }
                }}
              />
              <Button variant="primary" onClick={handleSend} disabled={inputDisabled || !input.trim()} title="Отправить (Enter)">
                {sending ? 'Отправляем…' : 'Отправить'}
              </Button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

function MessageItem({ message, acting, onConfirm, onReject }: { message: Message; acting: boolean; onConfirm: () => void; onReject: () => void }) {
  if (message.role === 'user') {
    return (
      <div className="assistant-bubble assistant-bubble--user">
        <div className="assistant-bubble__content">{message.content}</div>
      </div>
    )
  }

  if (message.role === 'tool') {
    const summary = toolResultSummary(message.tool_result)
    return (
      <details className="assistant-tool-line">
        <summary>→ результат{summary ? `: ${summary}` : ''}</summary>
        <pre>{JSON.stringify(message.tool_result, null, 2)}</pre>
      </details>
    )
  }

  // role === 'assistant'
  if (message.tool_call) {
    const badge = STATUS_BADGE[message.tool_call_status]
    return (
      <div className="assistant-action-card">
        <div className="assistant-action-card__header">
          Хочет выполнить: <code>{message.tool_call.name}</code>
          {badge && <span className={`badge ${badge.className}`}>{badge.label}</span>}
        </div>
        <pre className="assistant-action-card__args">{JSON.stringify(message.tool_call.arguments, null, 2)}</pre>
        {message.tool_call_status === 'pending_confirmation' && (
          <div className="assistant-action-card__actions">
            <Button variant="primary" small onClick={onConfirm} disabled={acting} title="Выполнить предложенное действие">
              Подтвердить
            </Button>
            <Button variant="ghost" small onClick={onReject} disabled={acting} title="Отклонить предложенное действие">
              Отклонить
            </Button>
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="assistant-bubble assistant-bubble--assistant">
      <div className="assistant-bubble__content">{message.content}</div>
    </div>
  )
}
