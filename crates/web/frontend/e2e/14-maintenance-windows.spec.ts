import { test, expect, fieldInput } from './fixtures'

const WINDOW_NAME = 'e2e-maintenance-window'
const WINDOW_RENAMED = 'e2e-maintenance-window-renamed'
const WINDOW_FUTURE = 'e2e-maintenance-window-future'

test.describe('Окна обслуживания', () => {
  test.beforeEach(async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Окна обслуживания' }).click()
    await expect(page.locator('.topbar__title')).toHaveText('Окна обслуживания')
  })

  test('создание (сразу активно, цель по подсети+профилю), редактирование (переименование, выключение), удаление', async ({ adminPage: page }) => {
    await page.getByRole('button', { name: 'Создать окно' }).click()
    await expect(page.getByRole('heading', { name: 'Новое окно обслуживания' })).toBeVisible()

    await fieldInput(page, 'Название').fill(WINDOW_NAME)
    // Начало/окончание prefilled by the form itself to "now" .. "+2h" — left as-is, which
    // is exactly what makes the freshly created window immediately "активно" below.
    await page.getByRole('button', { name: 'Добавить подсеть' }).click()
    await page.locator('input[placeholder="10.0.0.0"]').fill('203.0.113.0')
    await page.locator('input[placeholder="255.255.255.0"]').fill('255.255.255.0')
    await fieldInput(page, 'Профили').fill('e2e-test-profile')

    await page.getByRole('button', { name: 'Сохранить' }).click()
    await expect(page.locator('.toast-stack')).toContainText('создано')

    const row = page.locator('.data-table tbody tr', { hasText: WINDOW_NAME })
    await expect(row).toBeVisible()
    await expect(row).toContainText('активно') // starts_at=now <= now <= ends_at=+2h
    await expect(row).toContainText('подсетей: 1')
    await expect(row).toContainText('профилей: 1')

    // --- Edit: rename + disable. Disabling must flip the badge to "отключено" regardless
    // of the active time window — it's an independent override (see isActiveNow's own
    // !w.enabled short-circuit), not derived from the schedule. ---
    await row.getByRole('button', { name: 'Редактировать' }).click()
    await expect(page.getByRole('heading', { name: 'Редактировать окно обслуживания' })).toBeVisible()
    await expect(fieldInput(page, 'Название')).toHaveValue(WINDOW_NAME)
    await fieldInput(page, 'Название').fill(WINDOW_RENAMED)
    await page.locator('.switch').click()
    await page.getByRole('button', { name: 'Сохранить' }).click()
    await expect(page.locator('.toast-stack')).toContainText('сохранено')

    const renamedRow = page.locator('.data-table tbody tr', { hasText: WINDOW_RENAMED })
    await expect(renamedRow).toBeVisible()
    await expect(renamedRow).toContainText('отключено')

    // --- Reopen: subnet/profile round-tripped through the backend unchanged. ---
    await renamedRow.getByRole('button', { name: 'Редактировать' }).click()
    await expect(page.locator('input[placeholder="10.0.0.0"]')).toHaveValue('203.0.113.0')
    await expect(page.locator('input[placeholder="255.255.255.0"]')).toHaveValue('255.255.255.0')
    await expect(fieldInput(page, 'Профили')).toHaveValue('e2e-test-profile')
    await page.locator('.modal-footer').getByRole('button', { name: 'Отмена' }).click()

    // --- Delete: cancel then confirm, same two-step pattern as Devices' delete test. ---
    await renamedRow.getByRole('button', { name: 'Удалить' }).click()
    await expect(page.getByRole('heading', { name: 'Подтверждение' })).toBeVisible()
    await page.getByRole('button', { name: 'Отмена' }).click()
    await expect(renamedRow).toBeVisible()

    await renamedRow.getByRole('button', { name: 'Удалить' }).click()
    await page.locator('.modal-footer').getByRole('button', { name: 'Удалить' }).click()
    await expect(page.locator('.toast-stack')).toContainText('удалено')
    await expect(page.locator('.data-table tbody tr', { hasText: WINDOW_RENAMED })).toHaveCount(0)
  })

  test('запланированное окно (будущее) и предупреждение о пустой цели', async ({ adminPage: page }) => {
    await page.getByRole('button', { name: 'Создать окно' }).click()
    // No subnet/profile/device selected yet — must warn, not silently mean "all devices".
    await expect(page.getByText('Ни одна цель не выбрана')).toBeVisible()

    await fieldInput(page, 'Название').fill(WINDOW_FUTURE)
    const dateInputs = page.locator('.modal-body input[type="datetime-local"]')
    await dateInputs.nth(0).fill('2099-01-01T00:00')
    await dateInputs.nth(1).fill('2099-01-01T02:00')

    await page.getByRole('button', { name: 'Сохранить' }).click()
    await expect(page.locator('.toast-stack')).toContainText('создано')

    const row = page.locator('.data-table tbody tr', { hasText: WINDOW_FUTURE })
    await expect(row).toBeVisible()
    await expect(row).toContainText('запланировано')
    await expect(row).toContainText('не выбрано ни одного устройства')

    // Cleanup.
    await row.getByRole('button', { name: 'Удалить' }).click()
    await page.locator('.modal-footer').getByRole('button', { name: 'Удалить' }).click()
    await expect(row).toHaveCount(0)
  })
})
