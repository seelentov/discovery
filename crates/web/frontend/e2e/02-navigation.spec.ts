import { test, expect, login } from './fixtures'

const PAGES: { navLabel: string; title: string }[] = [
  { navLabel: 'Обзор', title: 'Обзор' },
  { navLabel: 'Устройства', title: 'Устройства' },
  { navLabel: 'Тревоги', title: 'Тревоги' },
  { navLabel: 'Топология', title: 'Топология' },
  { navLabel: 'Очереди', title: 'Очереди' },
  { navLabel: 'Логи', title: 'Логи' },
  { navLabel: 'Профили', title: 'Профили' },
  { navLabel: 'Дискаверинг', title: 'Дискаверинг' },
  { navLabel: 'Уведомления', title: 'Уведомления' },
  { navLabel: 'Настройки', title: 'Настройки' },
  { navLabel: 'Пользователи', title: 'Пользователи' },
]

test.describe('Навигация', () => {
  test('каждый пункт сайдбара открывает свою страницу с верным заголовком', async ({ adminPage }) => {
    for (const { navLabel, title } of PAGES) {
      // Exact match, not substring: e.g. 'Топология' (added 2026-09-12) contains 'логи' as
      // a literal substring and would otherwise collide with the 'Логи' iteration here —
      // see `fixtures.ts`'s docs on this exact class of gotcha.
      await adminPage.locator('.nav-item', { hasText: new RegExp(`^${navLabel}$`) }).click()
      await expect(adminPage.locator('.nav-item.active')).toHaveText(navLabel)
      await expect(adminPage.locator('.topbar__title')).toHaveText(title)
    }
  })

  test('стартовая страница после логина — Обзор', async ({ page }) => {
    await login(page)
    await expect(page.locator('.topbar__title')).toHaveText('Обзор')
    await expect(page.locator('.nav-item.active')).toHaveText('Обзор')
  })

  // Audit finding 6 (2026-09-20): the URL never changed with navigation before this fix —
  // sidebar clicks, direct URL navigation, F5, and the browser back button all silently
  // stayed on/returned to Overview regardless of what was actually on screen.
  test('URL меняется вместе с навигацией, переживает reload, работает "назад"', async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: /^Топология$/ }).click()
    await expect(page).toHaveURL(/\/topology$/)
    await expect(page.locator('.topbar__title')).toHaveText('Топология')

    // Direct URL navigation — not a click — must land on the matching page, not Overview.
    await page.goto('/queues')
    await expect(page.locator('.topbar__title')).toHaveText('Очереди')
    await expect(page.locator('.nav-item.active')).toHaveText('Очереди')

    // F5 (full document reload) must stay put, not bounce back to Overview.
    await page.reload()
    await expect(page.locator('.topbar__title')).toHaveText('Очереди')

    await page.locator('.nav-item', { hasText: /^Логи$/ }).click()
    await expect(page).toHaveURL(/\/logs$/)

    // Browser back — from Логи to Очереди (the previous entry), not a no-op.
    await page.goBack()
    await expect(page).toHaveURL(/\/queues$/)
    await expect(page.locator('.topbar__title')).toHaveText('Очереди')
  })
})
