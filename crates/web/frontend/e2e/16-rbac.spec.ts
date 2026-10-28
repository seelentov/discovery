import { test, expect, login, type Credentials } from './fixtures'

const DOMAINS = ['settings', 'alerts', 'devices', 'discovery_configs', 'device_metrics', 'profiles', 'logs', 'jobs', 'maintenance_windows', 'notifications', 'topology', 'group_alerts']
const suffix = Date.now().toString()
const READ_USER = `e2e-rbac-read-${suffix}`
const WRITE_USER = `e2e-rbac-write-${suffix}`
const PASSWORD = 'e2e-rbac-password-123'

async function apiRequest(page: Parameters<typeof login>[0], method: string, path: string, body?: unknown) {
  return page.evaluate(
    async ({ method, path, body }) => {
      const response = await fetch(path, {
        method,
        credentials: 'include',
        headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
      })
      return { status: response.status, body: await response.text() }
    },
    { method, path, body },
  )
}

async function createRole(page: Parameters<typeof login>[0], name: string, level: 'read' | 'write') {
  const response = await apiRequest(page, 'POST', '/api/roles', { name, permissions: Object.fromEntries(DOMAINS.map((domain) => [domain, level])) })
  expect(response.status, `create role failed: ${response.status} ${response.body}`).toBe(200)
  return JSON.parse(response.body) as { id: string }
}

async function createUser(page: Parameters<typeof login>[0], username: string, roleId: string) {
  const response = await apiRequest(page, 'POST', '/api/users', { username, password: PASSWORD, role_id: roleId })
  expect(response.status, `create user failed: ${response.status} ${response.body}`).toBe(200)
  return JSON.parse(response.body) as { id: string }
}

async function deleteById(page: Parameters<typeof login>[0], path: string, id: string) {
  const response = await apiRequest(page, 'DELETE', `${path}/${id}`)
  expect(response.status, `delete failed: ${response.status} ${response.body}`).toBe(204)
}

test.describe('RBAC frontend: read/write controls', () => {
  test('admin, write и read роли получают соответствующую матрицу controls; REST write остаётся 403', async ({ adminPage: page, browser }) => {
    const readRole = await createRole(page, `e2e-rbac-read-role-${suffix}`, 'read')
    const writeRole = await createRole(page, `e2e-rbac-write-role-${suffix}`, 'write')
    const readUser = await createUser(page, READ_USER, readRole.id)
    const writeUser = await createUser(page, WRITE_USER, writeRole.id)

    try {
      await page.goto('/devices')
      await expect(page.getByRole('button', { name: 'Создать', exact: true })).toBeVisible()

      const writeContext = await browser.newContext()
      const writePage = await writeContext.newPage()
      await login(writePage, { username: WRITE_USER, password: PASSWORD } satisfies Credentials)
      await writePage.goto('/devices')
      await expect(writePage.getByRole('button', { name: 'Создать', exact: true })).toBeVisible()
      await writePage.goto('/profiles')
      await expect(writePage.getByRole('button', { name: 'Создать', exact: true })).toBeVisible()
      await writePage.goto('/discovery')
      await expect(writePage.getByRole('button', { name: 'Создать', exact: true })).toBeVisible()
      await writePage.goto('/maintenance')
      await expect(writePage.getByRole('button', { name: 'Создать окно' })).toBeVisible()
      await writePage.goto('/topology')
      await expect(writePage.getByRole('button', { name: 'Создать правило' })).toBeVisible()
      await writePage.goto('/group-alerts')
      await expect(writePage.getByRole('button', { name: 'Создать правило' })).toBeVisible()
      await writePage.goto('/notifications')
      await writePage.getByRole('button', { name: /Матрица/ }).click()
      await expect(writePage.getByRole('button', { name: 'Создать правило' })).toBeVisible()
      await writePage.goto('/settings')
      await expect(writePage.getByRole('button', { name: 'Сохранить' }).first()).toBeEnabled()

      const readContext = await browser.newContext()
      const readPage = await readContext.newPage()
      await login(readPage, { username: READ_USER, password: PASSWORD } satisfies Credentials)
      await readPage.goto('/devices')
      await expect(readPage.getByRole('button', { name: 'Создать', exact: true })).toHaveCount(0)
      await expect(readPage.getByRole('button', { name: 'Включить все' })).toHaveCount(0)
      await readPage.goto('/profiles')
      await expect(readPage.getByRole('button', { name: 'Создать', exact: true })).toHaveCount(0)
      await readPage.goto('/discovery')
      await expect(readPage.getByRole('button', { name: 'Создать', exact: true })).toHaveCount(0)
      await readPage.goto('/maintenance')
      await expect(readPage.getByRole('button', { name: 'Создать окно' })).toHaveCount(0)
      await readPage.goto('/topology')
      await expect(readPage.getByRole('button', { name: 'Создать правило' })).toHaveCount(0)
      await readPage.goto('/group-alerts')
      await expect(readPage.getByRole('button', { name: 'Создать правило' })).toHaveCount(0)
      await readPage.goto('/notifications')
      await readPage.getByRole('button', { name: /Матрица/ }).click()
      await expect(readPage.getByRole('button', { name: 'Создать правило' })).toHaveCount(0)
      await readPage.goto('/settings')
      await expect(readPage.getByRole('button', { name: 'Сохранить' }).first()).toBeDisabled()

      const writeResponse = await apiRequest(readPage, 'POST', '/api/devices', { ip: '203.0.113.250' })
      expect(writeResponse.status).toBe(403)

      await writeContext.close()
      await readContext.close()
    } finally {
      await deleteById(page, '/api/users', readUser.id)
      await deleteById(page, '/api/users', writeUser.id)
      await deleteById(page, '/api/roles', readRole.id)
      await deleteById(page, '/api/roles', writeRole.id)
    }
  })
})
