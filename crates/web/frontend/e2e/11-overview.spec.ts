import { test, expect } from './fixtures'

test.describe('Обзор', () => {
  test.beforeEach(async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Обзор' }).click()
  })

  test('плитки статистики и обе панели показывают реальные данные, накопленные всей сюитой', async ({ adminPage: page }) => {
    const tiles = page.locator('.stat-tile')
    await expect(tiles).toHaveCount(4)

    // Tiles show "—" until `load()`'s first response arrives (a real, correct loading
    // state, not a bug) — wait for the panels to finish their own "Загрузка…" before
    // reading tile values, otherwise this races the fetch and reads the placeholder.
    const alertsPanel = page.locator('.card', { hasText: 'Активные тревоги' })
    await expect(alertsPanel).not.toContainText('Загрузка…')
    await expect(tiles.nth(0)).toContainText('Активные тревоги')
    await expect(tiles.nth(1)).toContainText('Устройств под мониторингом')
    await expect(tiles.nth(2)).toContainText('Задач в очередях')
    await expect(tiles.nth(3)).toContainText('Активных воркеров')

    // At least one real device exists (`06`'s keeper) and at least one real alert
    // (`09`'s "закрытие" test leaves it re-activatable, `06`'s other two devices still
    // have theirs) — device count tile should read a real, non-zero number.
    const deviceCountText = await tiles.nth(1).locator('.stat-tile__value').innerText()
    expect(Number(deviceCountText)).toBeGreaterThan(0)

    // Not asserting on a *specific* seeded device IP here: the panel only previews the
    // 10 most recent active alerts (`OverviewPage`'s `incidents.slice(0, 10)`) and by
    // this point in the suite `06`/`08` together have created more than 10 matching
    // devices — which 10 make the cut isn't something this test should depend on. The
    // shared alert *name* every seeded alert uses is a stable thing to assert on instead.
    await expect(alertsPanel).toContainText('e2e-alert')

    const queuesPanel = page.locator('.card', { hasText: 'Очереди' }).last()
    await expect(queuesPanel).toContainText('discovery')
    await expect(queuesPanel).toContainText('reachability_poll')
  })

  test('плитки и ссылки "Все..." кликабельны и ведут на нужную страницу', async ({ adminPage: page }) => {
    const tiles = page.locator('.stat-tile')

    await tiles.nth(0).click() // "Активные тревоги"
    await expect(page.locator('.topbar__title')).toHaveText('Тревоги')
    await expect(page.locator('.nav-item.active')).toHaveText('Тревоги')
    // Direct user request 2026-08-28: this link must land pre-filtered to active alerts
    // only, not the full unfiltered list.
    await expect(page.locator('select', { hasText: 'все состояния' })).toHaveValue('active')
    await page.locator('.nav-item', { hasText: 'Обзор' }).click()

    await tiles.nth(1).click() // "Устройств под мониторингом"
    await expect(page.locator('.topbar__title')).toHaveText('Устройства')
    await page.locator('.nav-item', { hasText: 'Обзор' }).click()

    await tiles.nth(2).click() // "Задач в очередях"
    await expect(page.locator('.topbar__title')).toHaveText('Очереди')
    await page.locator('.nav-item', { hasText: 'Обзор' }).click()

    await tiles.nth(3).click() // "Активных воркеров" — also routes to Очереди
    await expect(page.locator('.topbar__title')).toHaveText('Очереди')
    await page.locator('.nav-item', { hasText: 'Обзор' }).click()

    await page.locator('.card', { hasText: 'Активные тревоги' }).locator('.link-more').click()
    await expect(page.locator('.topbar__title')).toHaveText('Тревоги')
    await expect(page.locator('select', { hasText: 'все состояния' })).toHaveValue('active')
    await page.locator('.nav-item', { hasText: 'Обзор' }).click()

    await page.locator('.card', { hasText: 'Очереди' }).last().locator('.link-more').click()
    await expect(page.locator('.topbar__title')).toHaveText('Очереди')

    // A mini-list row itself is also clickable, same destination as its parent panel.
    await page.locator('.nav-item', { hasText: 'Обзор' }).click()
    await page.locator('.mini-list__row').first().click()
    await expect(page.locator('.topbar__title')).toHaveText('Тревоги')
    await expect(page.locator('select', { hasText: 'все состояния' })).toHaveValue('active')
  })
})
