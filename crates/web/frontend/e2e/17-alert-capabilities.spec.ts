import { test, expect, fieldInput, login } from './fixtures'
import type { Page } from '@playwright/test'
import { createSocket } from 'node:dgram'

async function api(page: Page, method: string, path: string, body?: unknown) {
  return page.evaluate(async ({ method, path, body }) => {
    const response = await fetch(path, { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })
    const text = await response.text()
    return { status: response.status, data: text ? (() => { try { return JSON.parse(text) } catch { return text } })() : null }
  }, { method, path, body })
}
const rule = (name: string, expression: string, policy = {}) => ({ name, expression, message: name, level: 'warning', enabled: true, clear_after_seconds: 0, policy: { period_seconds: 1, ...policy } })
const profile = (name: string, alerts: unknown[], extra = {}) => ({ profile: { name, priority: -100 }, match: { expression: 'false' }, metrics: { poll: {} }, alerts, ...extra })
async function device(page: Page, ip: string, profile: string) {
  const prior = await api(page, 'GET', `/api/devices?search=${ip}`)
  const owned = prior.data.items?.find((d: { facts: { ip: string }; profile?: string }) => d.facts.ip === ip && d.profile?.startsWith('e2e-cap-'))
  if (owned) await api(page, 'DELETE', `/api/devices/${owned.id}`)
  const r = await api(page, 'POST', '/api/devices', { ip, profile })
  expect(r.status).toBe(200)
  return r.data.id as string
}
async function poke(page: Page, id: string) {
  // Real operator action reaches the normal evaluation pipeline; no test-only API.
  const r = await api(page, 'POST', `/api/devices/${id}/actions/poll-now`)
  expect([202, 409, 429]).toContain(r.status)
}
async function sendSyslog(message: string) {
  const socket = createSocket('udp4')
  try {
    await new Promise<void>((resolve, reject) => socket.send(Buffer.from(`<30>Oct  3 12:00:00 router ${message}`), Number(process.env.E2E_PORT ?? 8088) + 1, '127.0.0.1', e => e ? reject(e) : resolve()))
  } finally { socket.close() }
}

test('shared library UI, linked rule, diagnostic errors and independent response deadlines', async ({ adminPage: page }) => {
  test.setTimeout(60_000)
  const name = 'e2e-cap-shared'
  await page.locator('.nav-item', { hasText: 'Профили' }).click()
  await page.getByRole('button', { name: 'Библиотека правил тревог' }).click()
  await page.getByRole('button', { name: 'Создать общее правило', exact: true }).click()
  const editor = page.locator('.modal-body > .card')
  await fieldInput(editor, 'Имя').fill(name)
  await fieldInput(editor, 'Условие активации').fill('true')
  await fieldInput(editor, 'Сообщение').fill('shared alarm')
  await fieldInput(editor, 'Эскалация после').fill('2')
  await editor.getByText('Обязательное подтверждение', { exact: true }).locator('input').check()
  await editor.getByText('Экранное уведомление', { exact: true }).locator('input').check()
  await editor.getByText('Звук уведомления', { exact: true }).locator('input').check()
  await page.getByRole('button', { name: 'Сохранить общее правило', exact: true }).click()
  await expect(page.locator('.modal-body')).toContainText(name)
  await page.locator('.modal-header button[title="Закрыть"]').click()
  expect((await api(page, 'POST', '/api/profiles', profile('e2e-cap-profile', [rule('shared-alias', 'false', { shared_rule: name })]))).status).toBe(204)
  const id = await device(page, '192.0.2.181', 'e2e-cap-profile')
  await poke(page, id)
  let alertId = ''
  await expect.poll(async () => { const r = await api(page, 'GET', `/api/alerts?device_id=${id}`); alertId = r.data.items[0]?.id ?? ''; return r.data.items.some((a: { name: string; details: { response_escalated: boolean } }) => a.name === 'shared-alias' && a.details.response_escalated) }, { timeout: 25_000 }).toBe(true)
  const notices = page.getByRole('complementary', { name: 'Экранные уведомления тревог' })
  await expect(notices).toContainText('shared-alias')
  await expect(notices.getByRole('button', { name: 'Скрыть', exact: true })).toHaveCount(0)
  await notices.getByRole('button', { name: 'Включить звук', exact: true }).click()
  await expect(notices.getByRole('button', { name: 'Выключить звук', exact: true })).toBeVisible()
  expect((await api(page, 'DELETE', `/api/alert-rules/shared/${name}`)).status).toBe(409)
  const shared = rule(name, '1 / 0 > 2', { period_seconds: 1, acknowledge_required: true, screen_notification: true })
  expect((await api(page, 'POST', '/api/alert-rules/shared', shared)).status).toBe(204)
  await expect.poll(async () => (await api(page, 'GET', `/api/devices/${id}/alert-rules`)).data.some((s: { state: string }) => s.state === 'error'), { timeout: 10_000 }).toBe(true)
  expect((await api(page, 'GET', `/api/alerts/${alertId}`)).data.state).toBe('Active')
  expect((await api(page, 'POST', `/api/alerts/${alertId}/acknowledge`)).status).toBe(200)
  expect((await api(page, 'GET', '/api/alerts/screen')).data.some((a: { id: string }) => a.id === alertId)).toBe(false)
  await api(page, 'DELETE', `/api/devices/${id}`)
  await api(page, 'DELETE', '/api/profiles/e2e-cap-profile')
  expect((await api(page, 'DELETE', `/api/alert-rules/shared/${name}`)).status).toBe(204)
})

test('real syslog burst, keyed recovery, quiet timers, occurrence acknowledgment and action provenance', async ({ adminPage: page }) => {
  test.setTimeout(60_000)
  const spec = { metric: 'syslog_link', count: 2, window_seconds: 30, key_expression: 'event.port', recovery_expression: 'event.status == "up"' }
  const state = { ...rule('e2e-cap-link', 'event.status == "down"', { mode: 'event', event: spec, actions: [{ on: 'cleared', action: 'test', condition: 'alert.name == "e2e-cap-link"' }], interactive_actions: ['test'], acknowledge_required: true, screen_notification: true }), activate_after_seconds: 1, clear_after_seconds: 1 }
  const pulse = rule('e2e-cap-pulse', 'event.status == "pulse"', { mode: 'event', event: { metric: 'syslog_link', count: 1, window_seconds: 30 } })
  const prof = profile('e2e-cap-syslog', [state, pulse], { syslog: { bindings: { link: { variants: [{ pattern: '^port=(?P<port>\\w+) status=(?P<status>\\w+)$', key_expression: 'fields.port' }] } } } })
  expect((await api(page, 'POST', '/api/profiles', prof)).status).toBe(204)
  const id = await device(page, '127.0.0.1', 'e2e-cap-syslog')
  await sendSyslog('port=eth0 status=down'); await sendSyslog('port=eth0 status=down')
  let alertId = ''
  await expect.poll(async () => { const p = await api(page, 'GET', `/api/alerts?device_id=${id}&search=e2e-cap-link`); alertId = p.data.items[0]?.id ?? ''; return p.data.items.length }, { timeout: 20_000 }).toBe(1)
  const a = (await api(page, 'GET', `/api/alerts/${alertId}`)).data
  expect(a.row_key).toBe('eth0'); expect(a.details.raised_count).toBe(2); expect(a.details.source_event.metric).toBe('syslog_link')
  const action = await api(page, 'POST', `/api/alerts/${alertId}/actions/test`); expect(action.status).toBe(202)
  await expect.poll(async () => { const j = await api(page, 'GET', `/api/devices/${id}/actions/jobs/${action.data.job_id}`); expect(j.data.alert_id).toBe(alertId); return j.data.status }, { timeout: 10_000 }).toBe('done')
  expect((await api(page, 'POST', `/api/alerts/${alertId}/actions/backup`)).status).toBe(403)
  await sendSyslog('port=eth0 status=up')
  await expect.poll(async () => (await api(page, 'GET', `/api/alerts/${alertId}`)).data.state, { timeout: 10_000 }).toBe('Cleared')
  expect((await api(page, 'GET', `/api/alerts/${alertId}`)).data.details.recovery_data.data.status).toBe('up')
  await expect.poll(async () => (await api(page, 'GET', `/api/devices/${id}/actions`)).data.some((j: { alert_id: string; job_id: number; status: string }) => j.alert_id === alertId && j.job_id !== action.data.job_id && j.status === 'done'), { timeout: 15_000 }).toBe(true)
  expect((await api(page, 'GET', '/api/alerts/screen')).data.some((a: { id: string }) => a.id === alertId)).toBe(true)
  expect((await api(page, 'POST', `/api/alerts/${alertId}/acknowledge`)).status).toBe(200)
  await sendSyslog('port=eth1 status=pulse')
  let pulseId = ''
  await expect.poll(async () => { const p = await api(page, 'GET', `/api/alerts?device_id=${id}&search=e2e-cap-pulse`); pulseId = p.data.items[0]?.id ?? ''; return p.data.total }, { timeout: 10_000 }).toBe(1)
  await api(page, 'POST', `/api/alerts/${pulseId}/acknowledge`)
  expect((await api(page, 'GET', `/api/alerts/${pulseId}`)).data.state).toBe('Cleared')
  await api(page, 'DELETE', `/api/devices/${id}`); await api(page, 'DELETE', '/api/profiles/e2e-cap-syslog')
})

test('change snapshots, dynamic numeric boundaries, flapping entry and exit', async ({ adminPage: page }) => {
  test.setTimeout(60_000)
  const alerts = [
    rule('e2e-cap-change', 'metrics.syslog_link[0].status', { mode: 'change' }),
    rule('e2e-cap-bound', 'metrics.syslog_link[0].severity', { mode: 'baseline', lower_expression: '2', upper_expression: '5' }),
    { ...rule('e2e-cap-flap', 'metrics.syslog_link[0].status == "down"', { flap_incident: true, flap_clear_threshold: 1 }), flap_window_seconds: 5, flap_threshold: 2 },
  ]
  expect((await api(page, 'POST', '/api/profiles', profile('e2e-cap-modes', alerts, { syslog: { bindings: { link: { variants: [{ pattern: '^port=(?P<port>\\w+) status=(?P<status>\\w+)$', key_expression: 'fields.port' }] } } } }))).status).toBe(204)
  const id = await device(page, '127.0.0.1', 'e2e-cap-modes')
  await sendSyslog('port=eth0 status=down')
  await expect.poll(async () => (await api(page, 'GET', `/api/devices/${id}/alert-rules`)).data.find((s: { name: string }) => s.name === 'e2e-cap-change')?.value, { timeout: 15_000 }).toBe('down')
  expect((await api(page, 'GET', `/api/alerts?device_id=${id}&search=e2e-cap-change`)).data.total).toBe(0)
  const bounds = (await api(page, 'GET', `/api/alerts?device_id=${id}&search=e2e-cap-bound`)).data.items
  expect(bounds).toHaveLength(1); expect(bounds[0].details.upper_bound).toBe(5); expect(bounds[0].details.observed_value).toBe(6)
  await sendSyslog('port=eth0 status=up')
  await expect.poll(async () => (await api(page, 'GET', `/api/alerts?device_id=${id}&search=e2e-cap-change`)).data.total, { timeout: 10_000 }).toBe(1)
  const change = (await api(page, 'GET', `/api/alerts?device_id=${id}&search=e2e-cap-change`)).data.items[0]
  expect(change.details.previous_value).toBe('down'); expect(change.details.observed_value).toBe('up')
  await api(page, 'POST', `/api/alerts/${change.id}/acknowledge`)
  for (const status of ['down', 'up', 'down']) {
    await sendSyslog(`port=eth0 status=${status}`)
    await expect.poll(async () => (await api(page, 'GET', `/api/devices/${id}/alert-rules`)).data.find((s: { name: string }) => s.name === 'e2e-cap-change')?.value, { timeout: 10_000 }).toBe(status)
  }
  await expect.poll(async () => (await api(page, 'GET', `/api/alerts?device_id=${id}&search=e2e-cap-flap.flapping&state=active`)).data.total, { timeout: 10_000 }).toBe(1)
  await expect.poll(async () => (await api(page, 'GET', `/api/alerts?device_id=${id}&search=e2e-cap-flap.flapping&state=active`)).data.total, { timeout: 15_000 }).toBe(0)
  await api(page, 'DELETE', `/api/devices/${id}`); await api(page, 'DELETE', '/api/profiles/e2e-cap-modes')
})

test('rule role permissions apply to reads, notices, comments and mutations', async ({ adminPage: page, browser }) => {
  test.setTimeout(60_000)
  const role = await api(page, 'POST', '/api/roles', { name: 'e2e-cap-hidden-role', permissions: { alerts: 'write', devices: 'write', profiles: 'write' } })
  expect(role.status).toBe(200)
  const owner = await api(page, 'POST', '/api/roles', { name: 'e2e-cap-owner-role', permissions: { alerts: 'write' } })
  expect(owner.status).toBe(200)
  const user = await api(page, 'POST', '/api/users', { username: 'e2e-cap-hidden-user', password: 'e2e-cap-password-123', role_id: role.data.id })
  expect(user.status).toBe(200)
  expect((await api(page, 'POST', '/api/profiles', profile('e2e-cap-permissions', [rule('e2e-cap-protected', 'true', { viewer_roles: [owner.data.id], operator_roles: [owner.data.id], screen_notification: true })]))).status).toBe(204)
  const id = await device(page, '192.0.2.182', 'e2e-cap-permissions')
  await poke(page, id)
  let alertId = ''
  await expect.poll(async () => { const a = await api(page, 'GET', `/api/alerts?device_id=${id}&search=e2e-cap-protected`); alertId = a.data.items[0]?.id ?? ''; return a.data.total }, { timeout: 20_000 }).toBe(1)
  const context = await browser.newContext(), restricted = await context.newPage()
  try {
    await login(restricted, { username: 'e2e-cap-hidden-user', password: 'e2e-cap-password-123' })
    expect((await api(restricted, 'GET', `/api/alerts?device_id=${id}`)).data.total).toBe(0)
    expect((await api(restricted, 'GET', `/api/alerts/${alertId}`)).status).toBe(403)
    expect((await api(restricted, 'POST', `/api/alerts/${alertId}/acknowledge`)).status).toBe(403)
    expect((await api(restricted, 'GET', `/api/alerts/${alertId}/comments`)).status).toBe(403)
    expect((await api(restricted, 'DELETE', `/api/alerts/${alertId}`)).status).toBe(403)
    expect((await api(restricted, 'DELETE', '/api/profiles/e2e-cap-permissions')).status).toBe(403)
    expect((await api(restricted, 'POST', '/api/profiles', profile('e2e-cap-permissions', []))).status).toBe(403)
    expect((await api(restricted, 'GET', '/api/alerts/screen')).data.some((a: { id: string }) => a.id === alertId)).toBe(false)
    expect((await api(restricted, 'GET', `/api/devices/${id}/alert-rules`)).data).toEqual([])
  } finally { await context.close() }
  await api(page, 'DELETE', `/api/devices/${id}`); await api(page, 'DELETE', '/api/profiles/e2e-cap-permissions')
  await api(page, 'DELETE', `/api/users/${user.data.id}`); await api(page, 'DELETE', `/api/roles/${role.data.id}`); await api(page, 'DELETE', `/api/roles/${owner.data.id}`)
})

test('notification selection editor roundtrips and rejects invalid recipient expressions', async ({ adminPage: page }) => {
  const rule = { name: 'e2e-cap-notifications', enabled: true, min_level: 'Warning', subnets: [], profiles: [], device_ids: [], active_from: null, active_to: null, days_of_week: [], notify_on_activate: true, notify_on_clear: true, recipients: [], selection: { alert_names: ['link'], row_keys: ['eth0'], source_metrics: ['syslog_link'], recipient_expression: 'user.username == "admin"', notify_on_escalation: true, notify_on_deescalation: true } }
  const saved = await api(page, 'POST', '/api/notifications/rules', rule); expect(saved.status).toBe(200)
  const id = saved.data.id
  await page.goto('/notifications')
  await page.getByRole('button', { name: /Матрица/ }).click()
  const row = page.locator('.data-table tbody tr', { hasText: rule.name })
  await row.getByTitle('Редактировать').click()
  await expect(fieldInput(page.locator('.modal-body'), 'Имена тревог')).toHaveValue('link')
  await expect(fieldInput(page.locator('.modal-body'), 'Условие получателя')).toHaveValue('user.username == "admin"')
  await fieldInput(page.locator('.modal-body'), 'Ключи строк').fill('eth1')
  await page.getByRole('button', { name: 'Сохранить', exact: true }).click()
  await expect.poll(async () => (await api(page, 'GET', `/api/notifications/rules/${id}`)).data.selection.row_keys).toEqual(['eth1'])
  expect((await api(page, 'POST', '/api/notifications/rules', { ...rule, id, selection: { recipient_expression: 'invalid {{{' } })).status).toBe(400)
  await api(page, 'DELETE', `/api/notifications/rules/${id}`)
})


test('policy validation rejects invalid modes, limits and unsafe actions at the real API', async ({ adminPage: page }) => {
  for (const policy of [
    { mode: 'baseline' }, { mode: 'event' }, { period_seconds: 0 }, { period_seconds: 86401 },
    { history_seconds: 0 }, { history_seconds: 86401 }, { history_metrics: Array(17).fill('cpu') },
    { notification_lifetime_seconds: 0 }, { notification_lifetime_seconds: 86401 },
    { escalate_after_seconds: 1 }, { acknowledge_required: true, escalate_after_seconds: 0 },
    { acknowledge_required: true, escalate_after_seconds: 86401 },
    { acknowledge_required: true, pending_count_threshold: 0 }, { acknowledge_required: true, pending_count_threshold: 10001 },
    { mode: 'event', event: { metric: 'cpu', count: 1, window_seconds: 60 } },
    { mode: 'event', event: { metric: 'syslog_link', count: 0, window_seconds: 60 } },
    { mode: 'event', event: { metric: 'trap_link', count: 10001, window_seconds: 60 } },
    { mode: 'event', event: { metric: 'syslog_link', count: 1, window_seconds: 0 } },
    { mode: 'event', event: { metric: 'trap_link', count: 1, window_seconds: 86401 } },
    { event: { metric: 'trap_link' } },
  ]) {
    const response = await api(page, 'POST', '/api/profiles', profile('e2e-cap-invalid', [rule('invalid', 'true', policy)]))
    expect(response.status, JSON.stringify(policy)).toBe(400)
  }
  const unsafe = await api(page, 'POST', '/api/profiles', profile('e2e-cap-invalid', [rule('invalid', 'true', { actions: [{ on: 'raised', action: 'shell' }] })]))
  expect([400, 422]).toContain(unsafe.status)
})
