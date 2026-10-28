import { bootstrapCredentials, expect, fieldInput, login, test } from './fixtures'

test.describe('Аутентификация', () => {
  test('гостевая первичная загрузка не пишет ожидаемый 401 в console', async ({ page }) => {
    const consoleErrors: string[] = []
    page.on('console', (message) => {
      if (message.type() === 'error' && !message.text().includes('401 (Unauthorized)')) consoleErrors.push(message.text())
    })

    await page.goto('/')
    await expect(page.locator('.login-screen')).toBeVisible()
    await expect.poll(() => consoleErrors).toEqual([])
  })

  test('неверный пароль показывает ошибку и не пускает в дашборд', async ({ page }) => {
    const { username } = bootstrapCredentials()
    await page.goto('/')
    await page.locator('input[autocomplete="username"]').fill(username)
    await page.locator('input[autocomplete="current-password"]').fill('definitely-wrong-password')
    await page.getByRole('button', { name: /Войти/ }).click()
    // The error text is the raw backend body (`ApiHttpError.message`, plain text, not
    // JSON) surfaced verbatim — "invalid username or password", in English, unlike the
    // rest of this page's Russian copy. Same pattern every other error surface in this
    // app uses (toasts, form-level errors) — not translated client-side anywhere.
    await expect(page.getByText(/invalid username or password/i)).toBeVisible()
    await expect(page.locator('.sidebar')).not.toBeVisible()
  })

  test('успешный логин показывает дашборд, /api/auth/me переживает reload, logout возвращает на экран логина', async ({ page }) => {
    await login(page)
    await expect(page.locator('.sidebar__brand')).toContainText('Discovery')

    // Session cookie is HttpOnly + persists across a full reload without re-submitting
    // the login form — this is the whole point of `useAuth`'s `GET /api/auth/me` check.
    await page.reload()
    await expect(page.locator('.sidebar')).toBeVisible()

    await page.locator('.sidebar__footer button[title="Выйти"]').click()
    await expect(page.locator('.login-screen')).toBeVisible()
    await expect(page.locator('.sidebar')).not.toBeVisible()
  })

  /**
   * Direct user request 2026-08-26: the fixed `admin`/`admin` bootstrap login must force
   * a real password on first use. `global-setup.ts` already unblocks the *shared*
   * `adminPage` session this way (or every other spec in this suite would fail against
   * the gate) — this test is what actually exercises that forced-change flow end to end,
   * against a disposable account created for exactly this, in its own browser context so
   * it doesn't disturb the shared session.
   */
  test('учётка с must_change_password видит блокирующий экран смены пароля вместо дашборда', async ({ adminPage, browser }) => {
    await adminPage.locator('.nav-item', { hasText: 'Пользователи' }).click()
    await adminPage.getByRole('button', { name: /Добавить пользователя/ }).click()
    await fieldInput(adminPage, 'Имя пользователя').fill('e2e-must-change')
    await fieldInput(adminPage, 'Пароль').fill('temp-password-1')
    await adminPage.locator('.checkbox-row', { hasText: 'Потребовать смену пароля' }).locator('input').check()
    await adminPage.getByRole('button', { name: 'Создать' }).click()
    const row = adminPage.locator('.data-table tbody tr', { hasText: 'e2e-must-change' })
    await expect(row).toBeVisible()
    await expect(row.locator('.badge', { hasText: 'смена пароля' })).toBeVisible()

    const ctx = await browser.newContext()
    const page = await ctx.newPage()
    await page.goto('/')
    await page.locator('input[autocomplete="username"]').fill('e2e-must-change')
    await page.locator('input[autocomplete="current-password"]').fill('temp-password-1')
    await page.getByRole('button', { name: /Войти/ }).click()

    // Blocked, not the real dashboard — no sidebar, no nav, just the change-password
    // gate. `.wordmark` is a plain `<div>`, not a heading role — same non-semantic markup
    // `LoginPage`'s own "Discovery" wordmark uses, so a role-based locator won't match.
    await expect(page.locator('.wordmark')).toHaveText('Смена пароля')
    await expect(page.locator('.sidebar')).toHaveCount(0)

    // Wrong current password — rejected, still gated.
    await fieldInput(page, 'Текущий пароль').fill('wrong-password')
    await fieldInput(page, 'Новый пароль').fill('a-real-password-1')
    await fieldInput(page, 'Повторите новый пароль').fill('a-real-password-1')
    await page.getByRole('button', { name: 'Сменить пароль' }).click()
    await expect(page.getByText(/current password is incorrect/i)).toBeVisible()
    await expect(page.locator('.sidebar')).toHaveCount(0)

    // Mismatched confirmation — caught client-side, no request even needed.
    await fieldInput(page, 'Текущий пароль').fill('temp-password-1')
    await fieldInput(page, 'Новый пароль').fill('a-real-password-1')
    await fieldInput(page, 'Повторите новый пароль').fill('a-different-password')
    await page.getByRole('button', { name: 'Сменить пароль' }).click()
    await expect(page.getByText('Новый пароль и подтверждение не совпадают')).toBeVisible()

    // Correct current password + matching confirmation clears the forced-change gate.
    await fieldInput(page, 'Повторите новый пароль').fill('a-real-password-1')
    await page.getByRole('button', { name: 'Сменить пароль' }).click()
    // The endpoint invalidates the current session by design, so this context lands on
    // the login gate. The persistence and new-password verification are covered by the
    // auth-store integration tests; the browser test proves the forced-change UX path.
    await expect(page.getByText(/current password is incorrect/i)).toHaveCount(0)

    await ctx.close()
  })
})
