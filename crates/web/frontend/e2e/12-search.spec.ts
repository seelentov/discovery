import { test, expect } from './fixtures'
import { DEVICE_KEEP_IP, DISCOVERY_CONFIG_NAME, E2E_PROFILE_NAME } from './shared'

// Deliberately last (after every other spec has seeded its own fixtures) — the global
// palette fans out to devices/alerts/profiles/discovery-configs/users all at once, so it
// needs all of those to actually exist first (2026-08-28, direct user request: "Была
// отличная фича в дизайне - поиск по ВСЕМУ").
test.describe('Глобальный поиск (⌘K)', () => {
  test('Ctrl+K открывает палитру, поиск находит устройство и переходит к нему', async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Обзор' }).click()
    await expect(page.locator('.command-palette')).toHaveCount(0)

    await page.keyboard.press('Control+k')
    const palette = page.locator('.command-palette')
    await expect(palette).toBeVisible()
    await expect(palette).toContainText('Начните вводить')

    await palette.locator('.command-palette__input').fill(DEVICE_KEEP_IP)
    const deviceGroup = palette.locator('.command-palette__group', { hasText: 'Устройства' })
    await expect(deviceGroup).toBeVisible()
    await deviceGroup.locator('.command-palette__item', { hasText: DEVICE_KEEP_IP }).click()

    await expect(page.locator('.command-palette')).toHaveCount(0)
    await expect(page.locator('.topbar__title')).toHaveText('Устройства')
    await expect(page.locator('.data-table tbody tr', { hasText: DEVICE_KEEP_IP })).toBeVisible()
  })

  test('поиск находит профиль и открывает его на редактировании', async ({ adminPage: page }) => {
    await page.locator('.sidebar__search-btn').click()
    const palette = page.locator('.command-palette')
    await expect(palette).toBeVisible()

    await palette.locator('.command-palette__input').fill(E2E_PROFILE_NAME)
    const profileGroup = palette.locator('.command-palette__group', { hasText: 'Профили' })
    await expect(profileGroup).toBeVisible()
    await profileGroup.locator('.command-palette__item', { hasText: E2E_PROFILE_NAME }).click()

    await expect(page.getByRole('heading', { name: `Редактировать профиль: ${E2E_PROFILE_NAME}` })).toBeVisible()
    await page.locator('.modal-footer').getByRole('button', { name: 'Отмена' }).click()
  })

  test('поиск находит конфигурацию дискаверинга и открывает её на редактировании', async ({ adminPage: page }) => {
    await page.keyboard.press('Control+k')
    const palette = page.locator('.command-palette')
    await palette.locator('.command-palette__input').fill(DISCOVERY_CONFIG_NAME)
    const discoveryGroup = palette.locator('.command-palette__group', { hasText: 'Дискаверинг' })
    await expect(discoveryGroup).toBeVisible()
    await discoveryGroup.locator('.command-palette__item', { hasText: DISCOVERY_CONFIG_NAME }).first().click()

    await expect(page.locator('.topbar__title')).toHaveText('Дискаверинг')
    await expect(page.getByRole('heading', { name: /Редактировать конфигурацию/ })).toBeVisible()
    await page.locator('.modal-footer').getByRole('button', { name: 'Отмена' }).click()
  })

  test('Escape закрывает палитру, пустой запрос ничего не ищет', async ({ adminPage: page }) => {
    await page.keyboard.press('Control+k')
    const palette = page.locator('.command-palette')
    await expect(palette).toBeVisible()
    await expect(palette).toContainText('Начните вводить')

    await page.keyboard.press('Escape')
    await expect(page.locator('.command-palette')).toHaveCount(0)
  })

  test('несуществующий запрос — "ничего не найдено"', async ({ adminPage: page }) => {
    await page.keyboard.press('Control+k')
    const palette = page.locator('.command-palette')
    await palette.locator('.command-palette__input').fill('no-such-thing-xyz-12345')
    await expect(palette).toContainText('Ничего не найдено')
    await page.keyboard.press('Escape')
  })
})
